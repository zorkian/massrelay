//! Experimental, unpublished private relay mailbox protocol.
//!
//! A private relay serves this protocol on its own Iroh ALPN, [`ALPN`], next to an Iroh relay
//! transport that admits any endpoint. The relay endpoint's key is pinned by clients, so Iroh's
//! handshake authenticates the relay; the relay learns the client's transport identity but uses
//! it for nothing. There is no roster, member table or membership check here. The protocol is
//! labeled experimental and is not frozen: [`VERSION`], the ALPN and the layout below may change
//! before the private discovery wire format is settled.
//!
//! # Framing
//!
//! Each request uses one bidirectional stream. Control messages are fixed-width binary, so the
//! relay never allocates by a size the peer chose. A request is an operation byte, a big-endian
//! `u32` version and that operation's fixed fields; a write is followed by exactly the body
//! length it declares. A reply is a code byte and that code's fixed fields; [`Reply::Present`]
//! is followed by exactly the body length it declares. Both sides finish their stream right
//! after their message: the relay answers only once the request is complete, and refuses
//! trailing bytes as malformed; the client finishes before waiting, refuses a reply code its
//! request cannot receive before reading any field or body, and refuses trailing bytes after
//! the reply. Bodies move through bounded working
//! buffers of [`CHUNK`] bytes with normal stream backpressure. That size is an implementation
//! choice: there is no object, request, session or traffic limit beyond the `u64` length field.
//!
//! # Admission
//!
//! Storage is operator-admitted, not open. A connection presents one operator access credential
//! with [`Request::Admit`] (the [`AccessKey`] in the relay's [`Locator`]); the relay compares
//! only its [`AccessKey::verifier`] with its operator's current grants and admits the
//! connection, or refuses it with [`Rejection::NotAdmitted`]. Every storage operation, reads
//! included, on a connection that is not admitted is refused with [`Rejection::NotAdmitted`]
//! before any field is checked or any body byte read; only [`Request::Incarnation`] is served
//! without admission. A grant is an operator's storage tenancy, never a member, device or
//! network: the relay keeps no roster, and the credential authorizes no slot, queue or service.
//! [`Client::connect`] admits before it returns. Grants are fixed while a relay runs; a revoked
//! grant stops admitting at the relay's next start. See `docs/private-relay-operations.md`.
//!
//! # Operations
//!
//! - [`Request::Incarnation`] returns the store's incarnation over the pinned channel.
//! - [`Request::Read`] returns a slot's exact bytes, absence, a wrong incarnation or
//!   unavailability. Failures are never reported as absence. The relay sends the committed
//!   length and digest first and checks the stored bytes as it streams them; if they fail, the
//!   stream is reset rather than completed. The client checks the length and digest too. A
//!   client streams the body to a sink with [`Client::read_into`], or materializes it with
//!   [`Client::read`], which reserves the buffer fallibly only after the reply's type and length
//!   have been parsed.
//! - [`Request::Write`] publishes an immutable slot. The slot address is the hash of the write
//!   public key ([`slot_address`]), and the proof is that key's Ed25519 signature over
//!   [`write_statement`]: the protocol version, opaque purpose label, pinned relay endpoint key,
//!   expected incarnation, write key, slot address, body length and SHA-256 body digest. The
//!   relay checks the purpose, that the relay key is its own, the incarnation, key, slot binding
//!   and proof from the header alone, before staging any body
//!   byte; a refused write's body is never read. It then streams the body into staging while
//!   hashing it, refuses a body that does not match the signed digest, and only then commits.
//!   The store decides between created, exact retry and occupied. A write result is not
//!   publication evidence; only a read returning the exact bytes is.
//!
//! - [`Request::Write`] also carries immutable invite replies, under their own purpose: the
//!   issuer's per-invite reply key is the only key whose slot is the reply's address.
//! - [`Request::Append`] adds an immutable item to an opaque queue whose handle binds an append
//!   key and an acknowledgement key ([`crate::slot_wire::queue_handle`]). The append key signs
//!   the version, purpose, relay key, incarnation, queue and both keys, the body length and the
//!   body digest, which is the item's identity; an exact retry is the same item and distinct
//!   items coexist.
//! - [`Request::Next`] returns the first item after a cursor, and [`Request::Ack`] records an
//!   item's terminal acknowledgement. Both need the acknowledgement key's proof over the relay
//!   key and incarnation too, so holders of the append key cannot read, acknowledge or remove
//!   anything. Queue order is the store's and carries no authority. The relay reads an item's
//!   row and verifies its whole body in one read view before answering: a success header is
//!   sent only for a body that verified, and an item whose body is definitively damaged gets
//!   [`Reply::DamagedEntry`], its order and identity without a body, so a reader can record it
//!   and move past it. Storage that cannot answer is unavailability, never damage.
//!
//! Every signed request names the relay endpoint key it is for, and the relay refuses one
//! naming another ([`Rejection::WrongRelay`]), so a request signed for one relay cannot be
//! replayed to another that shares its storage incarnation, such as one serving a copy.
//!
//! Bodies are opaque ciphertext. Membership data and credentials travel only inside them; each
//! key is per slot or per queue and authorizes nothing else.
//!
//! # Lifecycle
//!
//! Acknowledged queue items, and replies whose joiner has finished, stay stored: nothing expires
//! or is deleted automatically, for the life of the store's incarnation. There is no purge; any
//! future explicit operator purge must keep each object's occupied marker.

use std::fmt;

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayUrl, SecretKey, endpoint::Connection};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(test)]
use crate::slot_wire::WRITE_DOMAIN;
use crate::slot_wire::WRITE_FIELDS_LEN;
use crate::slot_wire::{
    ACK_FIELDS_LEN, APPEND_FIELDS_LEN, AckHeader, AppendHeader, QueueKeys,
    READ_FIELDS_LEN as QUEUE_READ_FIELDS_LEN, ReadHeader, unsigned_header,
};
pub use crate::slot_wire::{
    CHUNK, Incarnation, MEMBERSHIP_SLOT, SlotAddress, VERSION, WriteHeader, WriteRefusal,
    write_statement,
};
use crate::wire::ServerAddr;

pub(crate) const LOCATOR_PREFIX: &str = "mrprivx1_";
const ACCESS_DOMAIN: &[u8] = b"massrelay private relay access\0";

/// What a client pins for a private relay: its identity, addresses and storage incarnation,
/// and the operator access credential it presents. Experimental.
///
/// The access credential makes a locator a bearer secret for the relay's storage: anyone holding
/// it can store objects there until the operator revokes it. It grants nothing in any network.
#[derive(Clone, Serialize, Deserialize)]
pub struct Locator {
    pub server: ServerAddr,
    pub incarnation: Bytes<32>,
    pub access: AccessKey,
}

/// An operator-issued relay access credential: a random bearer secret that admits one
/// connection to the relay's storage operations ([`Request::Admit`]). The relay keeps only its
/// [`AccessKey::verifier`], never the secret. Its `Debug` form never shows the secret.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccessKey(pub Bytes<32>);

impl AccessKey {
    pub fn random() -> Result<Self> {
        let mut secret = [0; 32];
        getrandom::fill(&mut secret).map_err(|error| anyhow::anyhow!("random: {error}"))?;
        Ok(Self(Bytes(secret)))
    }

    /// What the relay stores and compares: a domain-separated hash of the secret.
    pub fn verifier(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(ACCESS_DOMAIN);
        digest.update(self.0.0);
        digest.finalize().into()
    }
}

impl fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessKey(..)")
    }
}

impl Locator {
    pub fn encode(&self) -> Result<String> {
        refuse_userinfo(&self.server.relay)?;
        Ok(format!(
            "{LOCATOR_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?)
        ))
    }

    pub fn decode(text: &str) -> Result<Self> {
        let encoded = text
            .trim()
            .strip_prefix(LOCATOR_PREFIX)
            .context("expected an experimental private relay locator")?;
        let locator: Self =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded)?).context("invalid locator")?;
        refuse_userinfo(&locator.server.relay)?;
        Ok(locator)
    }

    pub fn incarnation(&self) -> Incarnation {
        Incarnation::from_bytes(self.incarnation.0)
    }
}

/// A locator is shared freely, so its relay URL must never carry credentials.
pub fn refuse_userinfo(relay: &RelayUrl) -> Result<()> {
    ensure!(
        relay.username().is_empty() && relay.password().is_none(),
        "the relay URL must not contain a user name or password"
    );
    Ok(())
}

/// Iroh ALPN of the experimental mailbox protocol. Distinct from every legacy ALPN.
pub const ALPN: &[u8] = b"massrelay/mailbox/experimental-2";

const OP_INCARNATION: u8 = 1;
const OP_READ: u8 = 2;
const OP_WRITE: u8 = 3;
const OP_APPEND: u8 = 4;
const OP_NEXT: u8 = 5;
const OP_ACK: u8 = 6;
const OP_ADMIT: u8 = 7;
const READ_FIELDS_LEN: usize = 32 + 32;

/// Fixed-length bytes carried as unpadded base64url in JSON profiles and locators.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Bytes<const N: usize>(pub [u8; N]);

impl<const N: usize> fmt::Debug for Bytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<const N: usize> Serialize for Bytes<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Bytes<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD.decode(text).map_err(de::Error::custom)?;
        let bytes = bytes
            .try_into()
            .map_err(|_| de::Error::custom(format!("expected {N} bytes")))?;
        Ok(Self(bytes))
    }
}

impl From<Incarnation> for Bytes<32> {
    fn from(incarnation: Incarnation) -> Self {
        Self(incarnation.to_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Incarnation,
    Read {
        incarnation: Incarnation,
        slot: SlotAddress,
    },
    /// Followed by exactly `len` body bytes.
    Write(WriteHeader),
    /// Followed by exactly `len` body bytes.
    Append(AppendHeader),
    Next(ReadHeader),
    Ack(AckHeader),
    /// Present an operator access credential for this connection.
    Admit(AccessKey),
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        self.encode_version(VERSION)
    }

    pub(crate) fn encode_version(&self, version: u32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(5 + WRITE_FIELDS_LEN);
        let op = match self {
            Self::Incarnation => OP_INCARNATION,
            Self::Read { .. } => OP_READ,
            Self::Write(_) => OP_WRITE,
            Self::Append(_) => OP_APPEND,
            Self::Next(_) => OP_NEXT,
            Self::Ack(_) => OP_ACK,
            Self::Admit(_) => OP_ADMIT,
        };
        bytes.push(op);
        bytes.extend_from_slice(&version.to_be_bytes());
        match self {
            Self::Incarnation => {}
            Self::Read { incarnation, slot } => {
                bytes.extend_from_slice(&incarnation.to_bytes());
                bytes.extend_from_slice(&slot.to_bytes());
            }
            Self::Write(header) => {
                bytes.extend_from_slice(&header.purpose);
                bytes.extend_from_slice(&header.relay_key);
                bytes.extend_from_slice(&header.incarnation.to_bytes());
                bytes.extend_from_slice(&header.write_key);
                bytes.extend_from_slice(&header.slot.to_bytes());
                bytes.extend_from_slice(&header.len.to_be_bytes());
                bytes.extend_from_slice(&header.digest);
                bytes.extend_from_slice(&header.proof);
            }
            Self::Append(h) => {
                bytes.extend_from_slice(&h.purpose);
                bytes.extend_from_slice(&h.relay_key);
                bytes.extend_from_slice(&h.incarnation.to_bytes());
                encode_keys(&mut bytes, &h.keys);
                bytes.extend_from_slice(&h.len.to_be_bytes());
                bytes.extend_from_slice(&h.digest);
                bytes.extend_from_slice(&h.proof);
            }
            Self::Next(h) => {
                bytes.extend_from_slice(&h.relay_key);
                bytes.extend_from_slice(&h.incarnation.to_bytes());
                encode_keys(&mut bytes, &h.keys);
                bytes.extend_from_slice(&h.after.to_be_bytes());
                bytes.extend_from_slice(&h.proof);
            }
            Self::Ack(h) => {
                bytes.extend_from_slice(&h.relay_key);
                bytes.extend_from_slice(&h.incarnation.to_bytes());
                encode_keys(&mut bytes, &h.keys);
                bytes.extend_from_slice(&h.item);
                bytes.extend_from_slice(&h.proof);
            }
            Self::Admit(access) => bytes.extend_from_slice(&access.0.0),
        }
        bytes
    }
}

fn encode_keys(bytes: &mut Vec<u8>, keys: &QueueKeys) {
    bytes.extend_from_slice(&keys.queue);
    bytes.extend_from_slice(&keys.append_key);
    bytes.extend_from_slice(&keys.ack_key);
}

fn decode_keys(fields: &[u8]) -> QueueKeys {
    QueueKeys {
        queue: fields[..32].try_into().unwrap(),
        append_key: fields[32..64].try_into().unwrap(),
        ack_key: fields[64..96].try_into().unwrap(),
    }
}

/// A request header read from a stream, or the reply refusing it unread. Short-lived, so the
/// size difference between variants does not matter.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Incoming {
    Request(Request),
    Refused(Reply),
}

pub(crate) async fn read_request(recv: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Incoming> {
    let op = recv.read_u8().await?;
    if recv.read_u32().await? != VERSION {
        return Ok(Incoming::Refused(Reply::Rejected(Rejection::Version)));
    }
    let take32 = |bytes: &[u8]| -> [u8; 32] { bytes.try_into().unwrap() };
    Ok(Incoming::Request(match op {
        OP_INCARNATION => Request::Incarnation,
        OP_READ => {
            let mut fields = [0; READ_FIELDS_LEN];
            recv.read_exact(&mut fields).await?;
            Request::Read {
                incarnation: Incarnation::from_bytes(take32(&fields[..32])),
                slot: SlotAddress::from_bytes(take32(&fields[32..])),
            }
        }
        OP_WRITE => {
            let mut fields = [0; WRITE_FIELDS_LEN];
            recv.read_exact(&mut fields).await?;
            Request::Write(WriteHeader {
                purpose: take32(&fields[..32]),
                relay_key: take32(&fields[32..64]),
                incarnation: Incarnation::from_bytes(take32(&fields[64..96])),
                write_key: take32(&fields[96..128]),
                slot: SlotAddress::from_bytes(take32(&fields[128..160])),
                len: u64::from_be_bytes(fields[160..168].try_into().unwrap()),
                digest: take32(&fields[168..200]),
                proof: fields[200..].try_into().unwrap(),
            })
        }
        OP_APPEND => {
            let mut f = [0; APPEND_FIELDS_LEN];
            recv.read_exact(&mut f).await?;
            Request::Append(AppendHeader {
                purpose: take32(&f[..32]),
                relay_key: take32(&f[32..64]),
                incarnation: Incarnation::from_bytes(take32(&f[64..96])),
                keys: decode_keys(&f[96..192]),
                len: u64::from_be_bytes(f[192..200].try_into().unwrap()),
                digest: take32(&f[200..232]),
                proof: f[232..].try_into().unwrap(),
            })
        }
        OP_NEXT => {
            let mut f = [0; QUEUE_READ_FIELDS_LEN];
            recv.read_exact(&mut f).await?;
            Request::Next(ReadHeader {
                relay_key: take32(&f[..32]),
                incarnation: Incarnation::from_bytes(take32(&f[32..64])),
                keys: decode_keys(&f[64..160]),
                after: u64::from_be_bytes(f[160..168].try_into().unwrap()),
                proof: f[168..].try_into().unwrap(),
            })
        }
        OP_ACK => {
            let mut f = [0; ACK_FIELDS_LEN];
            recv.read_exact(&mut f).await?;
            Request::Ack(AckHeader {
                relay_key: take32(&f[..32]),
                incarnation: Incarnation::from_bytes(take32(&f[32..64])),
                keys: decode_keys(&f[64..160]),
                item: take32(&f[160..192]),
                proof: f[192..].try_into().unwrap(),
            })
        }
        OP_ADMIT => {
            let mut secret = [0; 32];
            recv.read_exact(&mut secret).await?;
            Request::Admit(AccessKey(Bytes(secret)))
        }
        _ => return Ok(Incoming::Refused(Reply::Rejected(Rejection::Malformed))),
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    Incarnation(Incarnation),
    /// Followed by exactly `len` bytes hashing to `digest`.
    Present {
        len: u64,
        digest: [u8; 32],
    },
    Absent,
    Created,
    ExactRetry,
    Occupied,
    WrongIncarnation,
    /// The write may or may not be durable. It is never known to be absent.
    Unconfirmed,
    /// The write failed before anything was committed. Publication did not happen.
    WriteFailed,
    /// Storage could not answer. This never means the slot is absent or that a write happened.
    Unavailable(Unavailable),
    /// The request was refused before reaching storage. Nothing was written.
    Rejected(Rejection),
    /// A queue item: followed by exactly `len` bytes hashing to `digest`, its identity.
    Entry {
        seq: u64,
        acked: bool,
        len: u64,
        digest: [u8; 32],
    },
    /// A queue item the relay verified is damaged in its own storage. Its order and identity are
    /// trustworthy, its body is not, and no body follows.
    DamagedEntry {
        seq: u64,
        acked: bool,
        item: [u8; 32],
    },
    /// The connection's access credential is current; its storage operations are admitted.
    Admitted,
}

impl Reply {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(41);
        match self {
            Self::Incarnation(incarnation) => {
                bytes.push(1);
                bytes.extend_from_slice(&incarnation.to_bytes());
            }
            Self::Present { len, digest } => {
                bytes.push(2);
                bytes.extend_from_slice(&len.to_be_bytes());
                bytes.extend_from_slice(digest);
            }
            Self::Absent => bytes.push(3),
            Self::Created => bytes.push(4),
            Self::ExactRetry => bytes.push(5),
            Self::Occupied => bytes.push(6),
            Self::WrongIncarnation => bytes.push(7),
            Self::Unconfirmed => bytes.push(8),
            Self::WriteFailed => bytes.push(9),
            Self::Unavailable(why) => bytes.extend_from_slice(&[10, *why as u8]),
            Self::Rejected(why) => bytes.extend_from_slice(&[11, *why as u8]),
            Self::Entry {
                seq,
                acked,
                len,
                digest,
            } => {
                bytes.push(12);
                bytes.extend_from_slice(&seq.to_be_bytes());
                bytes.push(u8::from(*acked));
                bytes.extend_from_slice(&len.to_be_bytes());
                bytes.extend_from_slice(digest);
            }
            Self::DamagedEntry { seq, acked, item } => {
                bytes.push(13);
                bytes.extend_from_slice(&seq.to_be_bytes());
                bytes.push(u8::from(*acked));
                bytes.extend_from_slice(item);
            }
            Self::Admitted => bytes.push(14),
        }
        bytes
    }

    /// The body that follows this reply, as (length, digest).
    fn body(&self) -> Option<(u64, [u8; 32])> {
        match *self {
            Self::Present { len, digest } | Self::Entry { len, digest, .. } => Some((len, digest)),
            _ => None,
        }
    }

    /// Read a reply to `request`. A code that request cannot receive is refused before any of
    /// its fields, let alone a body, is read.
    pub async fn read_for(request: &Request, recv: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
        let code = recv.read_u8().await?;
        let expected = match request {
            Request::Incarnation => matches!(code, 1 | 11),
            Request::Read { .. } => matches!(code, 2 | 3 | 7 | 10 | 11),
            Request::Write(_) => matches!(code, 4..=11),
            Request::Append(_) => matches!(code, 4 | 5 | 7..=11),
            Request::Next(_) => matches!(code, 3 | 7 | 10..=13),
            Request::Ack(_) => matches!(code, 3 | 4 | 5 | 7..=11),
            Request::Admit(_) => matches!(code, 11 | 14),
        };
        ensure!(
            expected,
            "unexpected mailbox reply code {code} for {request:?}"
        );
        Self::read_fields(code, recv).await
    }

    pub(crate) async fn read_fields(code: u8, recv: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
        Ok(match code {
            1 => {
                let mut incarnation = [0; 32];
                recv.read_exact(&mut incarnation).await?;
                Self::Incarnation(Incarnation::from_bytes(incarnation))
            }
            2 => {
                let len = recv.read_u64().await?;
                let mut digest = [0; 32];
                recv.read_exact(&mut digest).await?;
                Self::Present { len, digest }
            }
            3 => Self::Absent,
            4 => Self::Created,
            5 => Self::ExactRetry,
            6 => Self::Occupied,
            7 => Self::WrongIncarnation,
            8 => Self::Unconfirmed,
            9 => Self::WriteFailed,
            10 => Self::Unavailable(Unavailable::from_code(recv.read_u8().await?)?),
            11 => Self::Rejected(Rejection::from_code(recv.read_u8().await?)?),
            12 => {
                let seq = recv.read_u64().await?;
                let acked = match recv.read_u8().await? {
                    0 => false,
                    1 => true,
                    other => bail!("invalid acknowledgement flag {other}"),
                };
                let len = recv.read_u64().await?;
                let mut digest = [0; 32];
                recv.read_exact(&mut digest).await?;
                Self::Entry {
                    seq,
                    acked,
                    len,
                    digest,
                }
            }
            13 => {
                let seq = recv.read_u64().await?;
                let acked = match recv.read_u8().await? {
                    0 => false,
                    1 => true,
                    other => bail!("invalid acknowledgement flag {other}"),
                };
                let mut item = [0; 32];
                recv.read_exact(&mut item).await?;
                Self::DamagedEntry { seq, acked, item }
            }
            14 => Self::Admitted,
            code => bail!("unknown mailbox reply code {code}"),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Unavailable {
    /// An earlier write is unconfirmed; the relay must reopen its store to answer.
    Suspended = 1,
    /// The slot is occupied, but its stored bytes are damaged.
    Damaged = 2,
    /// Any other storage failure.
    Storage = 3,
}

impl Unavailable {
    fn from_code(code: u8) -> Result<Self> {
        Ok(match code {
            1 => Self::Suspended,
            2 => Self::Damaged,
            3 => Self::Storage,
            _ => bail!("unknown unavailability code {code}"),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rejection {
    Version = 1,
    Purpose = 2,
    InvalidKey = 3,
    SlotKeyMismatch = 4,
    InvalidProof = 5,
    Malformed = 6,
    /// The body did not match the digest its writer signed.
    BodyMismatch = 7,
    /// The request was signed for another relay endpoint than the one serving it.
    WrongRelay = 8,
    /// The connection presented no current operator access credential. Nothing was read,
    /// written or stored; the same request on an admitted connection may succeed.
    NotAdmitted = 9,
}

impl Rejection {
    fn from_code(code: u8) -> Result<Self> {
        Ok(match code {
            1 => Self::Version,
            2 => Self::Purpose,
            3 => Self::InvalidKey,
            4 => Self::SlotKeyMismatch,
            5 => Self::InvalidProof,
            6 => Self::Malformed,
            7 => Self::BodyMismatch,
            8 => Self::WrongRelay,
            9 => Self::NotAdmitted,
            _ => bail!("unknown rejection code {code}"),
        })
    }
}

/// The slot a write key may publish to (see [`crate::slot_wire::slot_address`]).
pub fn slot_address(write_key: &PublicKey) -> SlotAddress {
    crate::slot_wire::slot_address(write_key.as_bytes())
}

/// A signed membership slot write header for `payload`, for tests and local tools. Devices
/// prepare and sign their own headers; the transport never holds their keys.
pub fn write_header(
    relay_key: &PublicKey,
    incarnation: &Incarnation,
    write_key: &SecretKey,
    payload: &[u8],
) -> WriteHeader {
    let mut header = unsigned_header(
        MEMBERSHIP_SLOT,
        *relay_key.as_bytes(),
        *incarnation,
        *write_key.public().as_bytes(),
        payload,
    );
    header.proof = write_key
        .sign(&write_statement(VERSION, &header))
        .to_bytes();
    header
}

/// Whether the peer has finished its stream, with no bytes left.
pub(crate) async fn at_end(recv: &mut (impl AsyncRead + Unpin)) -> Result<bool> {
    let mut byte = [0; 1];
    Ok(recv.read(&mut byte).await? == 0)
}

/// Send one request and any body, then finish the stream so the relay knows the request is
/// complete. The relay may refuse a write before reading its body; its reply still arrives.
pub async fn send_request(
    send: &mut (impl AsyncWrite + Unpin),
    request: &Request,
    body: Option<&[u8]>,
) -> std::io::Result<()> {
    send.write_all(&request.encode()).await?;
    for chunk in body.unwrap_or_default().chunks(CHUNK) {
        send.write_all(chunk).await?;
    }
    send.shutdown().await
}

/// Stream a `Present` reply's body into `sink` through a bounded buffer, checking its exact
/// length and digest, then require the relay to finish its stream with no trailing bytes.
/// `sink` may hold unverified bytes if this fails; the caller must then discard them.
pub async fn receive_body_into(
    recv: &mut (impl AsyncRead + Unpin),
    len: u64,
    digest: &[u8; 32],
    sink: &mut (impl AsyncWrite + Unpin),
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0; CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let want = usize::try_from(remaining).map_or(CHUNK, |remaining| remaining.min(CHUNK));
        let read = recv.read(&mut buf[..want]).await?;
        ensure!(read > 0, "the slot body ended before its declared length");
        hasher.update(&buf[..read]);
        sink.write_all(&buf[..read]).await?;
        remaining -= read as u64;
    }
    sink.flush().await?;
    ensure!(
        *hasher.finalize() == *digest,
        "the slot body does not match its digest"
    );
    ensure!(
        at_end(recv).await?,
        "trailing bytes after the mailbox reply"
    );
    Ok(())
}

#[derive(Default)]
struct ReceivedBody(Vec<u8>);

impl AsyncWrite for ReceivedBody {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let output = &mut self.0;
        output
            .try_reserve(bytes.len())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::OutOfMemory, error))?;
        output.extend_from_slice(bytes);
        std::task::Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// One whole exchange, materializing verified bodies for device processing.
/// Allocation grows fallibly with bytes actually received, rather than the declared length.
pub async fn exchange(
    send: &mut (impl AsyncWrite + Unpin),
    recv: &mut (impl AsyncRead + Unpin),
    request: &Request,
    body: Option<&[u8]>,
) -> Result<(Reply, Option<Vec<u8>>)> {
    let sent = send_request(send, request, body).await;
    let reply = match Reply::read_for(request, recv).await {
        Ok(reply) => reply,
        Err(error) => {
            sent?;
            return Err(error);
        }
    };
    let early_refusal = matches!(request, Request::Write(_) | Request::Append(_))
        && matches!(
            reply,
            Reply::Rejected(_)
                | Reply::WrongIncarnation
                | Reply::WriteFailed
                | Reply::Unavailable(_)
        );
    if !early_refusal {
        sent?;
    }
    let Some((len, digest)) = reply.body() else {
        ensure!(
            at_end(recv).await?,
            "trailing bytes after the mailbox reply"
        );
        return Ok((reply, None));
    };
    let mut stored = ReceivedBody::default();
    receive_body_into(recv, len, &digest, &mut stored).await?;
    Ok((reply, Some(stored.0)))
}

/// What a streaming read established. `Present` is returned only after every byte reached the
/// sink and matched the committed length and digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadInto {
    Present { len: u64, digest: [u8; 32] },
    Absent,
    WrongIncarnation,
    Unavailable(Unavailable),
}

/// What a read established. A transport or protocol failure is an error, never absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadResult {
    Present(Vec<u8>),
    Absent,
    WrongIncarnation,
    Unavailable(Unavailable),
}

/// What a queue read established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NextResult {
    Item {
        seq: u64,
        acked: bool,
        bytes: Vec<u8>,
    },
    /// The relay verified this item is damaged. Its order and identity remain trustworthy, so a
    /// reader can move past it; its body is gone.
    Damaged {
        seq: u64,
        acked: bool,
        item: [u8; 32],
    },
    /// No item after the cursor in the store's current view.
    Empty,
    WrongIncarnation,
    Unavailable(Unavailable),
    Rejected(Rejection),
}

/// What an acknowledgement established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckResult {
    Recorded,
    AlreadyRecorded,
    NoSuchItem,
    WrongIncarnation,
    Unconfirmed,
    WriteFailed,
    Unavailable(Unavailable),
    Rejected(Rejection),
}

/// What a write established. Only a later matching read is publication evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteResult {
    Created,
    ExactRetry,
    Occupied,
    WrongIncarnation,
    Unconfirmed,
    WriteFailed,
    Unavailable(Unavailable),
    Rejected(Rejection),
}

/// The pinned relay refused the connection's access credential: unknown, or revoked by its
/// operator. Nothing was sent beyond the credential.
#[derive(Debug)]
pub struct NotAdmitted;

impl fmt::Display for NotAdmitted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "the private relay refused this access credential (unknown or revoked); ask its \
             operator for a current locator",
        )
    }
}

impl std::error::Error for NotAdmitted {}

/// The client side, over a connection to a pinned relay.
pub struct Client {
    connection: Connection,
}

impl Client {
    /// Connect to the relay at `relay` and present `access`. Iroh authenticates the relay's
    /// key, and the connection is refused unless the remote is exactly that key; the credential
    /// is sent only after that. The connection is returned only once the relay admitted it.
    pub async fn connect(
        endpoint: &Endpoint,
        relay: EndpointAddr,
        access: &AccessKey,
    ) -> Result<Self> {
        let client = Self::connect_unadmitted(endpoint, relay).await?;
        match client.call(&Request::Admit(*access), None).await? {
            (Reply::Admitted, _) => Ok(client),
            (Reply::Rejected(Rejection::NotAdmitted), _) => {
                client.connection.close(0u32.into(), b"not admitted");
                Err(NotAdmitted.into())
            }
            (reply, _) => bail!("unexpected mailbox reply {reply:?}"),
        }
    }

    /// Connect to the pinned relay without presenting a credential. Only
    /// [`Request::Incarnation`] is served on such a connection.
    pub async fn connect_unadmitted(endpoint: &Endpoint, relay: EndpointAddr) -> Result<Self> {
        let pinned = relay.id;
        let connection = endpoint
            .connect(relay, ALPN)
            .await
            .context("connect to the private relay")?;
        ensure!(
            connection.remote_id() == pinned,
            "the relay is not the pinned identity"
        );
        Ok(Self { connection })
    }

    /// Whether the connection has closed, so a new one is needed.
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    async fn call(
        &self,
        request: &Request,
        body: Option<&[u8]>,
    ) -> Result<(Reply, Option<Vec<u8>>)> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        exchange(&mut send, &mut recv, request, body).await
    }

    pub async fn incarnation(&self) -> Result<Incarnation> {
        match self.call(&Request::Incarnation, None).await? {
            (Reply::Incarnation(incarnation), _) => Ok(incarnation),
            (reply, _) => bail!("unexpected mailbox reply {reply:?}"),
        }
    }

    pub async fn read(&self, incarnation: &Incarnation, slot: &SlotAddress) -> Result<ReadResult> {
        let request = Request::Read {
            incarnation: *incarnation,
            slot: *slot,
        };
        Ok(match self.call(&request, None).await? {
            (Reply::Present { .. }, Some(body)) => ReadResult::Present(body),
            (Reply::Absent, _) => ReadResult::Absent,
            (Reply::WrongIncarnation, _) => ReadResult::WrongIncarnation,
            (Reply::Unavailable(why), _) => ReadResult::Unavailable(why),
            (reply, _) => bail!("unexpected mailbox reply {reply:?}"),
        })
    }

    /// Stream a slot's body into `sink` through a bounded buffer instead of materializing it.
    /// On an error, `sink` may hold unverified bytes and must be discarded.
    pub async fn read_into(
        &self,
        incarnation: &Incarnation,
        slot: &SlotAddress,
        sink: &mut (impl AsyncWrite + Unpin),
    ) -> Result<ReadInto> {
        let request = Request::Read {
            incarnation: *incarnation,
            slot: *slot,
        };
        let (mut send, mut recv) = self.connection.open_bi().await?;
        send_request(&mut send, &request, None).await?;
        let reply = Reply::read_for(&request, &mut recv).await?;
        if let Reply::Present { len, digest } = reply {
            receive_body_into(&mut recv, len, &digest, sink).await?;
            return Ok(ReadInto::Present { len, digest });
        }
        ensure!(
            at_end(&mut recv).await?,
            "trailing bytes after the mailbox reply"
        );
        Ok(match reply {
            Reply::Absent => ReadInto::Absent,
            Reply::WrongIncarnation => ReadInto::WrongIncarnation,
            Reply::Unavailable(why) => ReadInto::Unavailable(why),
            reply => bail!("unexpected mailbox reply {reply:?}"),
        })
    }

    /// Sign and write `payload`, for tests and local tools that hold the write key.
    pub async fn write(
        &self,
        incarnation: &Incarnation,
        write_key: &SecretKey,
        payload: &[u8],
    ) -> Result<WriteResult> {
        let relay = self.connection.remote_id();
        self.write_prepared(
            &write_header(&relay, incarnation, write_key, payload),
            payload,
        )
        .await
    }

    /// Write a body with the exact header its writer prepared and signed. The header's length
    /// and digest must describe `payload`; a mismatch is refused here and nothing is sent.
    pub async fn write_prepared(
        &self,
        header: &WriteHeader,
        payload: &[u8],
    ) -> Result<WriteResult> {
        if crate::slot_wire::verify_body(header, payload).is_err() {
            return Ok(WriteResult::Rejected(Rejection::BodyMismatch));
        }
        self.write_result(&Request::Write(*header), payload).await
    }

    /// Append an item with the exact header its writer prepared and signed. The header's length
    /// and digest must describe `payload`; a mismatch is refused here and nothing is sent.
    pub async fn append_prepared(
        &self,
        header: &AppendHeader,
        payload: &[u8],
    ) -> Result<WriteResult> {
        if payload.len() as u64 != header.len || *Sha256::digest(payload) != header.digest {
            return Ok(WriteResult::Rejected(Rejection::BodyMismatch));
        }
        self.write_result(&Request::Append(*header), payload).await
    }

    /// The first item after `header.after`, with its verified bytes.
    pub async fn next_item(&self, header: &ReadHeader) -> Result<NextResult> {
        Ok(match self.call(&Request::Next(*header), None).await? {
            (Reply::Entry { seq, acked, .. }, Some(bytes)) => {
                NextResult::Item { seq, acked, bytes }
            }
            (Reply::DamagedEntry { seq, acked, item }, _) => {
                NextResult::Damaged { seq, acked, item }
            }
            (Reply::Absent, _) => NextResult::Empty,
            (Reply::WrongIncarnation, _) => NextResult::WrongIncarnation,
            (Reply::Unavailable(why), _) => NextResult::Unavailable(why),
            (Reply::Rejected(why), _) => NextResult::Rejected(why),
            (reply, _) => bail!("unexpected mailbox reply {reply:?}"),
        })
    }

    /// Record the terminal acknowledgement of one item.
    pub async fn ack(&self, header: &AckHeader) -> Result<AckResult> {
        Ok(match self.call(&Request::Ack(*header), None).await? {
            (Reply::Created, _) => AckResult::Recorded,
            (Reply::ExactRetry, _) => AckResult::AlreadyRecorded,
            (Reply::Absent, _) => AckResult::NoSuchItem,
            (Reply::WrongIncarnation, _) => AckResult::WrongIncarnation,
            (Reply::Unconfirmed, _) => AckResult::Unconfirmed,
            (Reply::WriteFailed, _) => AckResult::WriteFailed,
            (Reply::Unavailable(why), _) => AckResult::Unavailable(why),
            (Reply::Rejected(why), _) => AckResult::Rejected(why),
            (reply, _) => bail!("unexpected mailbox reply {reply:?}"),
        })
    }

    async fn write_result(&self, request: &Request, payload: &[u8]) -> Result<WriteResult> {
        Ok(match self.call(request, Some(payload)).await? {
            (Reply::Created, _) => WriteResult::Created,
            (Reply::ExactRetry, _) => WriteResult::ExactRetry,
            (Reply::Occupied, _) => WriteResult::Occupied,
            (Reply::WrongIncarnation, _) => WriteResult::WrongIncarnation,
            (Reply::Unconfirmed, _) => WriteResult::Unconfirmed,
            (Reply::WriteFailed, _) => WriteResult::WriteFailed,
            (Reply::Unavailable(why), _) => WriteResult::Unavailable(why),
            (Reply::Rejected(why), _) => WriteResult::Rejected(why),
            (reply, _) => bail!("unexpected mailbox reply {reply:?}"),
        })
    }

    /// Whether the relay now serves exactly `payload` in `slot`: the only publication evidence.
    pub async fn is_published(
        &self,
        incarnation: &Incarnation,
        slot: &SlotAddress,
        payload: &[u8],
    ) -> Result<bool> {
        match self.read(incarnation, slot).await? {
            ReadResult::Present(stored) => Ok(stored == payload),
            ReadResult::Absent => Ok(false),
            other => bail!("publication could not be checked: {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::wire;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn the_experimental_format_is_fixed_width_and_disjoint() {
        assert_ne!(ALPN, wire::CONTROL);
        assert_ne!(ALPN, wire::SERVICE);
        assert_eq!(Request::Incarnation.encode(), [1, 0, 0, 0, 1]);
        let incarnation = Incarnation::from_bytes([1; 32]);
        let read = Request::Read {
            incarnation,
            slot: SlotAddress::from_bytes([2; 32]),
        };
        assert_eq!(
            read.encode(),
            [&[2u8, 0, 0, 0, 1][..], &[1; 32], &[2; 32]].concat()
        );
        let header = WriteHeader {
            purpose: MEMBERSHIP_SLOT,
            relay_key: [8; 32],
            incarnation,
            write_key: [3; 32],
            slot: SlotAddress::from_bytes([4; 32]),
            len: 0x0102,
            digest: [5; 32],
            proof: [6; 64],
        };
        let encoded = Request::Write(header).encode();
        assert_eq!(encoded.len(), 5 + WRITE_FIELDS_LEN);
        assert_eq!(
            encoded,
            [
                &[3u8, 0, 0, 0, 1][..],
                &MEMBERSHIP_SLOT,
                &[8; 32],
                &[1; 32],
                &[3; 32],
                &[4; 32],
                &[0, 0, 0, 0, 0, 0, 1, 2],
                &[5; 32],
                &[6; 64],
            ]
            .concat()
        );
        assert_eq!(
            write_statement(VERSION, &header),
            [
                WRITE_DOMAIN,
                &[0, 0, 0, 1],
                &encoded[5..5 + WRITE_FIELDS_LEN - 64]
            ]
            .concat()
        );
        let replies = [
            (
                Reply::Incarnation(incarnation),
                [&[1u8][..], &[1; 32]].concat(),
            ),
            (
                Reply::Present {
                    len: 3,
                    digest: [7; 32],
                },
                [&[2u8, 0, 0, 0, 0, 0, 0, 0, 3][..], &[7; 32]].concat(),
            ),
            (Reply::Absent, vec![3]),
            (Reply::WriteFailed, vec![9]),
            (Reply::Unavailable(Unavailable::Suspended), vec![10, 1]),
            (Reply::Rejected(Rejection::BodyMismatch), vec![11, 7]),
            (Reply::Rejected(Rejection::WrongRelay), vec![11, 8]),
            (
                Reply::DamagedEntry {
                    seq: 0x0304,
                    acked: true,
                    item: [9; 32],
                },
                [&[13u8, 0, 0, 0, 0, 0, 0, 3, 4, 1][..], &[9; 32]].concat(),
            ),
        ];
        for (reply, bytes) in replies {
            assert_eq!(reply.encode(), bytes);
        }
    }

    /// Every signed request names the relay it is for, and each frame decodes to exactly the
    /// request that was encoded.
    #[tokio::test]
    async fn signed_frames_carry_the_relay_and_round_trip() {
        let keys = QueueKeys::new([3; 32], [4; 32]);
        let incarnation = Incarnation::from_bytes([1; 32]);
        let write = WriteHeader {
            purpose: MEMBERSHIP_SLOT,
            relay_key: [8; 32],
            incarnation,
            write_key: [3; 32],
            slot: SlotAddress::from_bytes([4; 32]),
            len: 7,
            digest: [5; 32],
            proof: [6; 64],
        };
        let append = AppendHeader {
            purpose: crate::slot_wire::INVITE_REQUEST,
            relay_key: [8; 32],
            incarnation,
            keys,
            len: 7,
            digest: [5; 32],
            proof: [6; 64],
        };
        let next = ReadHeader {
            relay_key: [8; 32],
            incarnation,
            keys,
            after: 9,
            proof: [6; 64],
        };
        let ack = AckHeader {
            relay_key: [8; 32],
            incarnation,
            keys,
            item: [5; 32],
            proof: [6; 64],
        };
        for (request, fields, relay_at) in [
            (Request::Write(write), WRITE_FIELDS_LEN, 32),
            (Request::Append(append), APPEND_FIELDS_LEN, 32),
            (Request::Next(next), QUEUE_READ_FIELDS_LEN, 0),
            (Request::Ack(ack), ACK_FIELDS_LEN, 0),
        ] {
            let encoded = request.encode();
            assert_eq!(encoded.len(), 5 + fields, "{request:?}");
            assert_eq!(&encoded[5 + relay_at..5 + relay_at + 32], &[8; 32]);
            match read_request(&mut encoded.as_slice()).await.unwrap() {
                Incoming::Request(decoded) => assert_eq!(decoded, request),
                Incoming::Refused(reply) => panic!("{request:?} refused: {reply:?}"),
            }
        }
    }

    type FakeRelay = (
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<()>,
    );

    /// A relay that sends `reply` and then either finishes or holds its stream open.
    fn fake_relay(reply: Vec<u8>, finish: bool) -> FakeRelay {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let task = tokio::spawn(async move {
            let (mut server_recv, mut server_send) = tokio::io::split(server);
            let mut request = Vec::new();
            let _ = server_recv.read_to_end(&mut request).await;
            server_send.write_all(&reply).await.unwrap();
            if finish {
                server_send.shutdown().await.unwrap();
            } else {
                std::future::pending::<()>().await;
            }
        });
        let (recv, send) = tokio::io::split(client);
        (recv, send, task)
    }

    /// The client checks reply types, reads exact bodies and refuses trailing bytes.
    #[tokio::test]
    async fn clients_refuse_unexpected_or_trailing_replies() {
        let incarnation = Incarnation::from_bytes([1; 32]);
        let owner = key(1);
        let write = Request::Write(write_header(
            &key(50).public(),
            &incarnation,
            &owner,
            b"body",
        ));
        let read = Request::Read {
            incarnation,
            slot: slot_address(&owner.public()),
        };
        let present = |len: u64, body: &[u8]| {
            Reply::Present {
                len,
                digest: Sha256::digest(body).into(),
            }
            .encode()
        };
        let enormous = present(u64::MAX, b"");
        let next = Request::Next(ReadHeader {
            relay_key: [8; 32],
            incarnation,
            keys: QueueKeys::new([3; 32], [4; 32]),
            after: 0,
            proof: [0; 64],
        });
        let damaged = Reply::DamagedEntry {
            seq: 1,
            acked: false,
            item: [9; 32],
        }
        .encode();
        let cases: Vec<(Request, Vec<u8>, bool)> = vec![
            // Replies a request cannot receive, held open: refused from the code alone,
            // without waiting for fields or a body.
            (write, enormous.clone(), false),
            (Request::Incarnation, enormous.clone(), false),
            (read, Reply::Created.encode(), false),
            // A large size claim without any body: rejected at EOF without sizing a buffer to it.
            (read, enormous, true),
            // Trailing bytes after a complete reply or body.
            (write, [&Reply::Created.encode()[..], &[0]].concat(), true),
            (read, [&present(2, b"ok")[..], b"ok!"].concat(), true),
            // A body that ends early or does not match its digest.
            (read, [&present(3, b"abc")[..], b"ab"].concat(), true),
            (read, [&present(3, b"abc")[..], b"abd"].concat(), true),
            // A damaged-entry verdict is only a queue read's, and carries no body.
            (read, damaged.clone(), true),
            (next, [&damaged[..], &[0]].concat(), true),
        ];
        for (request, reply, finish) in cases {
            let (mut recv, mut send, relay) = fake_relay(reply, finish);
            let body = matches!(request, Request::Write(_)).then_some(&b"body"[..]);
            let result = timeout(
                Duration::from_secs(5),
                exchange(&mut send, &mut recv, &request, body),
            )
            .await
            .expect("the client must not wait for more");
            assert!(result.is_err(), "{request:?} accepted {result:?}");
            relay.abort();
        }

        // The exact damaged-entry verdict, finished, is accepted without a body.
        let (mut recv, mut send, _relay) = fake_relay(damaged.clone(), true);
        assert_eq!(
            exchange(&mut send, &mut recv, &next, None).await.unwrap(),
            (
                Reply::DamagedEntry {
                    seq: 1,
                    acked: false,
                    item: [9; 32]
                },
                None
            )
        );

        // The exact reply, finished, is accepted.
        let (mut recv, mut send, _relay) =
            fake_relay([&present(2, b"ok")[..], b"ok"].concat(), true);
        assert_eq!(
            exchange(&mut send, &mut recv, &read, None).await.unwrap().1,
            Some(b"ok".to_vec())
        );
    }

    #[tokio::test]
    async fn failed_request_send_allows_only_early_write_refusal() {
        let incarnation = Incarnation::from_bytes([1; 32]);
        let owner = key(1);
        let write = Request::Write(write_header(
            &key(50).public(),
            &incarnation,
            &owner,
            b"body",
        ));
        let read = Request::Read {
            incarnation,
            slot: slot_address(&owner.public()),
        };
        for (request, reply, allowed) in [
            (write, Reply::Created, false),
            (write, Reply::ExactRetry, false),
            (write, Reply::Rejected(Rejection::Malformed), true),
            (write, Reply::WrongIncarnation, true),
            (read, Reply::Absent, false),
        ] {
            let (mut send, disconnected) = tokio::io::duplex(128);
            drop(disconnected);
            let bytes = reply.encode();
            let mut recv = bytes.as_slice();
            let result = exchange(&mut send, &mut recv, &request, Some(b"body")).await;
            assert_eq!(result.is_ok(), allowed, "{request:?}: {result:?}");
        }
    }
}
