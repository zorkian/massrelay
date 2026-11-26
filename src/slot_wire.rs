//! Portable slot write primitives shared by the private relay's verifier, the device-side
//! membership adapter and its test fakes. Experimental and unpublished; not a frozen format.
//!
//! This module has no storage, networking or platform dependency, so device code can use it
//! wherever it builds. One slot address and one signed statement are defined here and nowhere
//! else:
//!
//! - The slot address is the SHA-256 of a domain label and the 32-byte Ed25519 write public key.
//! - The write proof is that key's Ed25519 signature over [`write_statement`]: a domain label,
//!   the protocol version, the opaque 32-byte purpose, the pinned relay endpoint key, the
//!   expected 32-byte storage incarnation, the write key, the slot address, the body length and
//!   the body's SHA-256. Queue statements bind the relay endpoint key the same way.
//!
//! A writer prepares the whole [`WriteHeader`], proof included, before handing it to a
//! transport; the transport never signs.

use std::fmt;

use iroh::{PublicKey, Signature};
use sha2::{Digest, Sha256};

/// Size of the working buffer used to stream bodies. An implementation choice, not a limit.
pub const CHUNK: usize = 64 * 1024;

/// The only protocol version.
pub const VERSION: u32 = 1;
/// The membership slot purpose. The relay compares it and gives it no meaning.
pub const MEMBERSHIP_SLOT: [u8; 32] = *b"massrelay/membership-slot/exp-1\0";
/// The immutable invite reply purpose, written only with the issuer's per-invite reply key.
pub const INVITE_REPLY: [u8; 32] = *b"massrelay/invite-reply/exp-1\0\0\0\0";
/// The invite request queue purpose.
pub const INVITE_REQUEST: [u8; 32] = *b"massrelay/invite-request/exp-1\0\0";

const SLOT_DOMAIN: &[u8] = b"massrelay mailbox slot address experimental-1\0";
pub(crate) const WRITE_DOMAIN: &[u8] = b"massrelay mailbox slot write experimental-1\0";
/// Bytes of a write header after the operation byte and version.
pub(crate) const WRITE_FIELDS_LEN: usize = 32 + 32 + 32 + 32 + 32 + 8 + 32 + 64;

/// Random identity of one store's backing data, always 32 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Incarnation(pub(crate) [u8; 32]);

impl Incarnation {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exactly 32 bytes, or `None`.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for Incarnation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Incarnation({})", hex(&self.0))
    }
}

/// Opaque address of one immutable slot.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotAddress(pub(crate) [u8; 32]);

impl SlotAddress {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for SlotAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlotAddress({})", hex(&self.0))
    }
}

/// Everything a write binds, sent before its body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteHeader {
    pub purpose: [u8; 32],
    /// The endpoint key of the relay the writer pinned; any other relay refuses the write.
    pub relay_key: [u8; 32],
    pub incarnation: Incarnation,
    pub write_key: [u8; 32],
    pub slot: SlotAddress,
    pub len: u64,
    pub digest: [u8; 32],
    pub proof: [u8; 64],
}

/// Why a write header or body is refused. Each is definitive for those exact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteRefusal {
    InvalidKey,
    SlotKeyMismatch,
    InvalidProof,
    /// The body's length or digest differs from the signed header.
    BodyMismatch,
}

/// The slot a write public key may publish to.
pub fn slot_address(write_key: &[u8; 32]) -> SlotAddress {
    let mut digest = Sha256::new();
    digest.update(SLOT_DOMAIN);
    digest.update(write_key);
    SlotAddress(digest.finalize().into())
}

/// The header for writing `body` with `write_key`, still unsigned.
pub fn unsigned_header(
    purpose: [u8; 32],
    relay_key: [u8; 32],
    incarnation: Incarnation,
    write_key: [u8; 32],
    body: &[u8],
) -> WriteHeader {
    WriteHeader {
        purpose,
        relay_key,
        incarnation,
        write_key,
        slot: slot_address(&write_key),
        len: body.len() as u64,
        digest: Sha256::digest(body).into(),
        proof: [0; 64],
    }
}

/// The exact bytes a write key signs for `header`; the proof field is not included.
pub fn write_statement(version: u32, header: &WriteHeader) -> Vec<u8> {
    let mut statement = Vec::with_capacity(WRITE_DOMAIN.len() + 4 + WRITE_FIELDS_LEN);
    statement.extend_from_slice(WRITE_DOMAIN);
    statement.extend_from_slice(&version.to_be_bytes());
    statement.extend_from_slice(&header.purpose);
    statement.extend_from_slice(&header.relay_key);
    statement.extend_from_slice(&header.incarnation.0);
    statement.extend_from_slice(&header.write_key);
    statement.extend_from_slice(&header.slot.0);
    statement.extend_from_slice(&header.len.to_be_bytes());
    statement.extend_from_slice(&header.digest);
    statement
}

/// Check the write key, its slot binding and the proof over this version's statement.
pub fn verify_proof(header: &WriteHeader) -> Result<(), WriteRefusal> {
    let key = PublicKey::from_bytes(&header.write_key).map_err(|_| WriteRefusal::InvalidKey)?;
    if slot_address(&header.write_key) != header.slot {
        return Err(WriteRefusal::SlotKeyMismatch);
    }
    key.verify(
        &write_statement(VERSION, header),
        &Signature::from_bytes(&header.proof),
    )
    .map_err(|_| WriteRefusal::InvalidProof)
}

/// Check that `body` is exactly the body `header` signs.
pub fn verify_body(header: &WriteHeader, body: &[u8]) -> Result<(), WriteRefusal> {
    if body.len() as u64 != header.len || *Sha256::digest(body) != header.digest {
        return Err(WriteRefusal::BodyMismatch);
    }
    Ok(())
}

// ------------------------------------------------------------------ queues
//
// A queue is an append-only set of immutable opaque items. Its handle is the hash of two
// Ed25519 keys: an append key, whose holders may add items, and an acknowledgement key, whose
// holder alone may read the queue and record a terminal acknowledgement of an item. An item's
// identity is the SHA-256 of its exact bytes, so an exact retry is the same item and distinct
// requests coexist; nothing can overwrite or remove one.

const QUEUE_DOMAIN: &[u8] = b"massrelay mailbox queue handle experimental-1\0";
pub(crate) const APPEND_DOMAIN: &[u8] = b"massrelay mailbox queue append experimental-1\0";
pub(crate) const READ_DOMAIN: &[u8] = b"massrelay mailbox queue read experimental-1\0";
pub(crate) const ACK_DOMAIN: &[u8] = b"massrelay mailbox queue ack experimental-1\0";
pub(crate) const QUEUE_KEYS_LEN: usize = 32 * 3;
pub(crate) const APPEND_FIELDS_LEN: usize = 32 + 32 + 32 + QUEUE_KEYS_LEN + 8 + 32 + 64;
pub(crate) const READ_FIELDS_LEN: usize = 32 + 32 + QUEUE_KEYS_LEN + 8 + 64;
pub(crate) const ACK_FIELDS_LEN: usize = 32 + 32 + QUEUE_KEYS_LEN + 32 + 64;

/// The handle of the queue bound to these two keys.
pub fn queue_handle(append_key: &[u8; 32], ack_key: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(QUEUE_DOMAIN);
    digest.update(append_key);
    digest.update(ack_key);
    digest.finalize().into()
}

/// A queue handle with the two keys it binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueKeys {
    pub queue: [u8; 32],
    pub append_key: [u8; 32],
    pub ack_key: [u8; 32],
}

impl QueueKeys {
    pub fn new(append_key: [u8; 32], ack_key: [u8; 32]) -> Self {
        Self {
            queue: queue_handle(&append_key, &ack_key),
            append_key,
            ack_key,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.queue);
        out.extend_from_slice(&self.append_key);
        out.extend_from_slice(&self.ack_key);
    }

    /// The key that signs for `role`, after checking the handle binds both keys.
    fn signer(&self, role: &[u8; 32]) -> Result<PublicKey, WriteRefusal> {
        if queue_handle(&self.append_key, &self.ack_key) != self.queue {
            return Err(WriteRefusal::SlotKeyMismatch);
        }
        PublicKey::from_bytes(role).map_err(|_| WriteRefusal::InvalidKey)
    }
}

/// An item appended to a queue, sent before its body. The item's identity is `digest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppendHeader {
    pub purpose: [u8; 32],
    pub relay_key: [u8; 32],
    pub incarnation: Incarnation,
    pub keys: QueueKeys,
    pub len: u64,
    pub digest: [u8; 32],
    pub proof: [u8; 64],
}

/// A request for the first item after sequence number `after`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadHeader {
    pub relay_key: [u8; 32],
    pub incarnation: Incarnation,
    pub keys: QueueKeys,
    pub after: u64,
    pub proof: [u8; 64],
}

/// A terminal acknowledgement of one item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckHeader {
    pub relay_key: [u8; 32],
    pub incarnation: Incarnation,
    pub keys: QueueKeys,
    pub item: [u8; 32],
    pub proof: [u8; 64],
}

/// The unsigned append header for `body`.
pub fn unsigned_append(
    purpose: [u8; 32],
    relay_key: [u8; 32],
    incarnation: Incarnation,
    keys: QueueKeys,
    body: &[u8],
) -> AppendHeader {
    AppendHeader {
        purpose,
        relay_key,
        incarnation,
        keys,
        len: body.len() as u64,
        digest: Sha256::digest(body).into(),
        proof: [0; 64],
    }
}

/// The bytes the append key signs; the proof is not included.
pub fn append_statement(version: u32, h: &AppendHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(APPEND_DOMAIN.len() + 4 + APPEND_FIELDS_LEN);
    out.extend_from_slice(APPEND_DOMAIN);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&h.purpose);
    out.extend_from_slice(&h.relay_key);
    out.extend_from_slice(&h.incarnation.0);
    h.keys.encode(&mut out);
    out.extend_from_slice(&h.len.to_be_bytes());
    out.extend_from_slice(&h.digest);
    out
}

/// The bytes the acknowledgement key signs to read; the proof is not included.
pub fn read_statement(version: u32, h: &ReadHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(READ_DOMAIN.len() + 4 + READ_FIELDS_LEN);
    out.extend_from_slice(READ_DOMAIN);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&h.relay_key);
    out.extend_from_slice(&h.incarnation.0);
    h.keys.encode(&mut out);
    out.extend_from_slice(&h.after.to_be_bytes());
    out
}

/// The bytes the acknowledgement key signs to acknowledge; the proof is not included.
pub fn ack_statement(version: u32, h: &AckHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(ACK_DOMAIN.len() + 4 + ACK_FIELDS_LEN);
    out.extend_from_slice(ACK_DOMAIN);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&h.relay_key);
    out.extend_from_slice(&h.incarnation.0);
    h.keys.encode(&mut out);
    out.extend_from_slice(&h.item);
    out
}

fn verify_with(key: PublicKey, statement: &[u8], proof: &[u8; 64]) -> Result<(), WriteRefusal> {
    key.verify(statement, &Signature::from_bytes(proof))
        .map_err(|_| WriteRefusal::InvalidProof)
}

/// Check the queue binding and the append key's proof.
pub fn verify_append(h: &AppendHeader) -> Result<(), WriteRefusal> {
    let key = h.keys.signer(&h.keys.append_key)?;
    verify_with(key, &append_statement(VERSION, h), &h.proof)
}

/// Check the queue binding and the acknowledgement key's read proof.
pub fn verify_read(h: &ReadHeader) -> Result<(), WriteRefusal> {
    let key = h.keys.signer(&h.keys.ack_key)?;
    verify_with(key, &read_statement(VERSION, h), &h.proof)
}

/// Check the queue binding and the acknowledgement key's proof.
pub fn verify_ack(h: &AckHeader) -> Result<(), WriteRefusal> {
    let key = h.keys.signer(&h.keys.ack_key)?;
    verify_with(key, &ack_statement(VERSION, h), &h.proof)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The statement and address are pinned byte for byte, and every bound field matters.
    #[test]
    fn statements_bind_every_field() {
        let secret = iroh::SecretKey::from_bytes(&[3; 32]);
        let write_key = *secret.public().as_bytes();
        let incarnation = Incarnation::from_bytes([1; 32]);
        let mut header = unsigned_header(MEMBERSHIP_SLOT, [8; 32], incarnation, write_key, b"body");
        header.proof = secret.sign(&write_statement(VERSION, &header)).to_bytes();
        assert_eq!(verify_proof(&header), Ok(()));
        assert_eq!(verify_body(&header, b"body"), Ok(()));
        assert_eq!(
            verify_body(&header, b"bodY"),
            Err(WriteRefusal::BodyMismatch)
        );
        assert_eq!(
            verify_body(&header, b"bod"),
            Err(WriteRefusal::BodyMismatch)
        );
        assert_eq!(
            write_statement(VERSION, &header),
            [
                WRITE_DOMAIN,
                &1u32.to_be_bytes(),
                &MEMBERSHIP_SLOT,
                &[8; 32],
                &[1; 32],
                &write_key,
                &header.slot.0,
                &4u64.to_be_bytes(),
                &header.digest,
            ]
            .concat()
        );
        let mut digest = Sha256::new();
        digest.update(SLOT_DOMAIN);
        digest.update(write_key);
        assert_eq!(header.slot.0, <[u8; 32]>::from(digest.finalize()));

        let changes: [fn(&mut WriteHeader); 7] = [
            |h| h.purpose[0] ^= 1,
            |h| h.relay_key[0] ^= 1,
            |h| h.incarnation.0[0] ^= 1,
            |h| h.len += 1,
            |h| h.digest[0] ^= 1,
            |h| h.proof[0] ^= 1,
            |h| h.slot.0[0] ^= 1,
        ];
        for change in changes {
            let mut altered = header;
            change(&mut altered);
            assert!(verify_proof(&altered).is_err());
        }
        assert!(Incarnation::from_slice(&[0; 16]).is_none());
    }
}
