//! Experimental records carried by the opaque mailbox: encrypted membership
//! slots, signed transitions, invite tokens, encrypted join requests and
//! encrypted invite replies with the issuer's signed admission receipt.
//!
//! Every record is versioned and labelled. Each key has its own purpose:
//!
//! | Key | Derived from | Purpose |
//! | --- | --- | --- |
//! | slot write key | MLS exporter, accepted head as context | proof of slot possession |
//! | slot wrap root | MLS exporter, accepted head as context | root of per-candidate wrap keys |
//! | candidate wrap key | HKDF(wrap root, fresh 32-byte candidate salt) | AEAD of one candidate |
//! | request / reply key | HKDF(invite secret) | AEAD of join requests / replies |
//!
//! Every candidate (winning or losing) uses a fresh salt, so no two writers
//! ever share an AEAD key, and its exact ciphertext is persisted before the
//! first write so a retry never re-encrypts. Nonces are random as well.

use ed25519_dalek::{Signer as _, SigningKey};
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::{GroupContext, MlsGroup};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::types::{AeadType, HashType};

use super::PROTOCOL;
use super::binding::{EndpointKey, JoinTranscript, SigReject, verify_ed25519};
use super::codec::{Dec, DecodeError, Enc, Hash, hash, random, sha256};
use super::mailbox::Pin;
use crate::slot_wire::{
    AckHeader, AppendHeader, INVITE_REPLY, INVITE_REQUEST, Incarnation, MEMBERSHIP_SLOT, QueueKeys,
    ReadHeader, VERSION, WriteHeader, ack_statement, append_statement, read_statement,
    unsigned_append, unsigned_header, write_statement,
};

pub const RECORD_VERSION: u8 = 1;

const SLOT_WRITE_LABEL: &str = "massrelay-private/experimental-1 slot-write";
const SLOT_WRAP_LABEL: &str = "massrelay-private/experimental-1 slot-wrap";
const SLOT_KEY_INFO: &[u8] = b"massrelay-private slot candidate key";
const SLOT_AAD: &[u8] = b"massrelay-private slot aad";
const TRANSITION: &[u8] = b"massrelay-private transition";
const TRANSITION_SIG: &[u8] = b"massrelay-private transition-signature";
const STATE_DIGEST: &[u8] = b"massrelay-private state-digest";
const GENESIS: &[u8] = b"massrelay-private genesis";
const HEAD: &[u8] = b"massrelay-private head";
const RECEIPT: &[u8] = b"massrelay-private admission-receipt";
const RECEIPT_SIG: &[u8] = b"massrelay-private admission-receipt-signature";
const INVITE: &[u8] = b"massrelay-private invite";
const INVITE_REQUEST_KEY: &[u8] = b"massrelay-private invite request key";
const INVITE_REPLY_KEY: &[u8] = b"massrelay-private invite reply key";
const INVITE_REQUEST_APPEND_KEY: &[u8] = b"massrelay-private invite request append key";
const REQUEST_AAD: &[u8] = b"massrelay-private join-request aad";
const REPLY_AAD: &[u8] = b"massrelay-private invite-reply aad";

const AEAD: AeadType = AeadType::Aes128Gcm;
const AEAD_KEY: usize = 16;
const NONCE: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    Malformed(String),
    /// AEAD open failed: wrong key, wrong binding or modified bytes.
    Undecryptable,
    Signature(SigReject),
}

impl From<DecodeError> for RecordError {
    fn from(e: DecodeError) -> Self {
        RecordError::Malformed(e.0)
    }
}

pub fn crypto() -> RustCrypto {
    RustCrypto::default()
}

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let c = crypto();
    let prk = c
        .hkdf_extract(HashType::Sha2_256, salt, ikm)
        .expect("hkdf extract");
    c.hkdf_expand(HashType::Sha2_256, prk.as_slice(), info, len)
        .expect("hkdf expand")
        .as_slice()
        .to_vec()
}

fn seal_raw(key: &[u8], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; NONCE]) {
    let nonce = random::<NONCE>();
    let ct = crypto()
        .aead_encrypt(AEAD, key, plaintext, &nonce, aad)
        .expect("aead encrypt");
    (ct, nonce)
}

fn open_raw(key: &[u8], aad: &[u8], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>, RecordError> {
    crypto()
        .aead_decrypt(AEAD, key, ct, nonce, aad)
        .map_err(|_| RecordError::Undecryptable)
}

// ------------------------------------------------------------------ slots

pub type SlotId = Hash;

/// The slot a write key may publish to: the relay's own address function.
pub fn slot_address(write_pub: &[u8; 32]) -> SlotId {
    crate::slot_wire::slot_address(write_pub).to_bytes()
}

/// The prepared header for writing `ciphertext` to `slot` with `write_pub`, unsigned, for the
/// pinned relay endpoint and its 32-byte storage incarnation.
pub fn slot_write_header(
    pin: &Pin,
    write_pub: &[u8; 32],
    ciphertext: &[u8],
) -> Result<WriteHeader, SigReject> {
    Ok(unsigned_header(
        MEMBERSHIP_SLOT,
        pin.relay_key,
        pinned(&pin.incarnation)?,
        *write_pub,
        ciphertext,
    ))
}

/// Verify a prepared slot write exactly as the relay does: the pinned relay, incarnation and
/// purpose, the shared statement over version, purpose, relay, incarnation, write key, slot,
/// length and digest, and the exact body.
pub fn verify_slot_write(
    pin: &Pin,
    header: &WriteHeader,
    ciphertext: &[u8],
) -> Result<(), SigReject> {
    verify_object_write(MEMBERSHIP_SLOT, pin, header, ciphertext)
}

/// Verify an immutable object write of `purpose` exactly as the relay does.
pub fn verify_object_write(
    purpose: [u8; 32],
    pin: &Pin,
    header: &WriteHeader,
    ciphertext: &[u8],
) -> Result<(), SigReject> {
    if header.relay_key != pin.relay_key {
        return Err(SigReject("write is for another relay".into()));
    }
    if header.incarnation.to_bytes().as_slice() != pin.incarnation.as_slice() {
        return Err(SigReject("write is for another storage incarnation".into()));
    }
    if header.purpose != purpose {
        return Err(SigReject("write is for another purpose".into()));
    }
    crate::slot_wire::verify_proof(header)
        .and_then(|()| crate::slot_wire::verify_body(header, ciphertext))
        .map_err(|refusal| SigReject(format!("write proof: {refusal:?}")))
}

/// Keys for the successor slot of one accepted (epoch, head).
pub struct SlotKeys {
    pub slot: SlotId,
    pub write_pub: [u8; 32],
    write_sk: SigningKey,
    wrap_root: Vec<u8>,
}

impl SlotKeys {
    pub fn derive(group: &MlsGroup, head: &Hash) -> Result<Self, String> {
        let c = crypto();
        let seed = group
            .export_secret(&c, SLOT_WRITE_LABEL, head, 32)
            .map_err(|e| format!("export slot write seed: {e:?}"))?;
        let wrap_root = group
            .export_secret(&c, SLOT_WRAP_LABEL, head, 32)
            .map_err(|e| format!("export slot wrap root: {e:?}"))?;
        let seed: [u8; 32] = seed
            .as_ref()
            .try_into()
            .map_err(|_| "seed length".to_string())?;
        let write_sk = SigningKey::from_bytes(&seed);
        let write_pub = write_sk.verifying_key().to_bytes();
        Ok(Self {
            slot: slot_address(&write_pub),
            write_pub,
            write_sk,
            wrap_root: wrap_root.as_ref().to_vec(),
        })
    }

    /// The signed relay header for writing `ciphertext`. Only the device holds this key; the
    /// header is persisted with the candidate and handed to the transport as is.
    pub fn prepare(&self, pin: &Pin, ciphertext: &[u8]) -> Result<WriteHeader, SigReject> {
        let mut header = slot_write_header(pin, &self.write_pub, ciphertext)?;
        header.proof = self
            .write_sk
            .sign(&write_statement(VERSION, &header))
            .to_bytes();
        Ok(header)
    }

    fn candidate_key(&self, incarnation: &[u8], salt: &[u8; 32]) -> Vec<u8> {
        let info = Enc::new()
            .bytes(SLOT_KEY_INFO)
            .bytes(PROTOCOL)
            .bytes(incarnation)
            .fixed(&self.slot)
            .finish();
        hkdf(&self.wrap_root, salt, &info, AEAD_KEY)
    }

    fn aad(&self, incarnation: &[u8], salt: &[u8; 32]) -> Hash {
        hash(
            SLOT_AAD,
            &[PROTOCOL, &[RECORD_VERSION], incarnation, &self.slot, salt],
        )
    }

    /// Encrypt one candidate with a fresh salt and nonce.
    pub fn seal(&self, incarnation: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let salt = random::<32>();
        let key = self.candidate_key(incarnation, &salt);
        let (ct, nonce) = seal_raw(&key, &self.aad(incarnation, &salt), plaintext);
        Enc::new()
            .u8(RECORD_VERSION)
            .fixed(&salt)
            .fixed(&nonce)
            .fixed(&ct)
            .finish()
    }

    pub fn open(&self, incarnation: &[u8], bytes: &[u8]) -> Result<Vec<u8>, RecordError> {
        let mut d = Dec::new(bytes);
        if d.u8()? != RECORD_VERSION {
            return Err(RecordError::Malformed("slot record version".into()));
        }
        let salt = d.fixed::<32>()?;
        let nonce = d.fixed::<NONCE>()?;
        let ct = d.take(bytes.len() - 1 - 32 - NONCE)?;
        let key = self.candidate_key(incarnation, &salt);
        open_raw(&key, &self.aad(incarnation, &salt), &nonce, ct)
    }
}

/// Candidate salt and nonce of a slot record (test evidence for nonce and
/// key freshness). `None` if the record is malformed.
pub fn slot_record_salt_nonce(bytes: &[u8]) -> Option<([u8; 32], [u8; NONCE])> {
    let mut d = Dec::new(bytes);
    if d.u8().ok()? != RECORD_VERSION {
        return None;
    }
    Some((d.fixed().ok()?, d.fixed().ok()?))
}

// ------------------------------------------------------------ state digest

/// One roster entry: bound endpoint key and pinned MLS signature key.
pub type RosterEntry = (EndpointKey, Vec<u8>);

pub fn state_digest(gc: &GroupContext, roster: &[RosterEntry], revoked: &[EndpointKey]) -> Hash {
    let gc_bytes = gc.tls_serialize_detached().expect("group context encodes");
    let mut roster = roster.to_vec();
    roster.sort();
    let mut revoked = revoked.to_vec();
    revoked.sort();
    let body = Enc::new()
        .bytes(PROTOCOL)
        .bytes(&gc_bytes)
        .list(&roster, |e, (ep, sk)| {
            e.fixed(ep).bytes(sk);
        })
        .list(&revoked, |e, r| {
            e.fixed(r);
        })
        .finish();
    hash(STATE_DIGEST, &[&body])
}

pub fn genesis_head(
    group_tag: &Hash,
    relay_key: &[u8; 32],
    incarnation: &[u8],
    gc: &GroupContext,
) -> Hash {
    let gc_bytes = gc.tls_serialize_detached().expect("group context encodes");
    hash(
        GENESIS,
        &[PROTOCOL, group_tag, relay_key, incarnation, &gc_bytes],
    )
}

pub fn next_head(parent: &Hash, slot: &SlotId, slot_bytes: &[u8], digest: &Hash) -> Hash {
    hash(HEAD, &[parent, slot, &sha256(slot_bytes), digest])
}

// -------------------------------------------------------------- transition

// Transitions are decoded one at a time and never stored in bulk.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Exactly one inline Add. `transcript` and `proof` are the joiner's
    /// detached endpoint-key proof; the invite times and `reserved_at` are
    /// the issuer's signed assertions, replicated for deterministic checks.
    Add {
        joiner: EndpointKey,
        invite_not_before: u64,
        invite_expires_at: u64,
        reserved_at: u64,
        transcript: JoinTranscript,
        proof: Vec<u8>,
    },
    /// Exactly one inline Remove of `subject` at `leaf`, signed by the
    /// author as its Remove intent.
    Remove { subject: EndpointKey, leaf: u32 },
}

/// Author-signed transition carried inside the encrypted slot record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub group_tag: Hash,
    pub relay_key: [u8; 32],
    pub incarnation: Vec<u8>,
    pub parent_head: Hash,
    pub slot: SlotId,
    pub author_leaf: u32,
    pub author_endpoint: EndpointKey,
    /// Author clock when the commit was built. Recipients validate Add
    /// KeyPackage lifetimes at exactly this time, never at their own clock.
    pub issued_at: u64,
    pub op: Op,
    /// Exact MLS commit (PublicMessage, TLS-encoded `MlsMessageOut`).
    pub commit: Vec<u8>,
    pub resulting_digest: Hash,
}

impl Transition {
    pub fn body(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u8(RECORD_VERSION)
            .bytes(TRANSITION)
            .bytes(PROTOCOL)
            .fixed(&self.group_tag)
            .fixed(&self.relay_key)
            .bytes(&self.incarnation)
            .fixed(&self.parent_head)
            .fixed(&self.slot)
            .u32(self.author_leaf)
            .fixed(&self.author_endpoint)
            .u64(self.issued_at);
        match &self.op {
            Op::Add {
                joiner,
                invite_not_before,
                invite_expires_at,
                reserved_at,
                transcript,
                proof,
            } => {
                e.u8(1)
                    .fixed(joiner)
                    .u64(*invite_not_before)
                    .u64(*invite_expires_at)
                    .u64(*reserved_at)
                    .bytes(&transcript.encode())
                    .bytes(proof);
            }
            Op::Remove { subject, leaf } => {
                e.u8(2).fixed(subject).u32(*leaf);
            }
        }
        e.bytes(&self.commit).fixed(&self.resulting_digest);
        e.finish()
    }

    fn decode_body(b: &[u8]) -> Result<Self, RecordError> {
        let mut d = Dec::new(b);
        if d.u8()? != RECORD_VERSION {
            return Err(RecordError::Malformed("transition version".into()));
        }
        d.expect_label(TRANSITION)?;
        d.expect_label(PROTOCOL)?;
        let group_tag = d.fixed()?;
        let relay_key = d.fixed()?;
        let incarnation = d.bytes()?;
        let parent_head = d.fixed()?;
        let slot = d.fixed()?;
        let author_leaf = d.u32()?;
        let author_endpoint = d.fixed()?;
        let issued_at = d.u64()?;
        let op = match d.u8()? {
            1 => {
                let joiner = d.fixed()?;
                let invite_not_before = d.u64()?;
                let invite_expires_at = d.u64()?;
                let reserved_at = d.u64()?;
                let tb = d.bytes()?;
                let mut td = Dec::new(&tb);
                let transcript = JoinTranscript::decode(&mut td)?;
                td.end()?;
                let proof = d.bytes()?;
                Op::Add {
                    joiner,
                    invite_not_before,
                    invite_expires_at,
                    reserved_at,
                    transcript,
                    proof,
                }
            }
            2 => Op::Remove {
                subject: d.fixed()?,
                leaf: d.u32()?,
            },
            k => {
                return Err(RecordError::Malformed(format!(
                    "unsupported operation kind {k}"
                )));
            }
        };
        let commit = d.bytes()?;
        let resulting_digest = d.fixed()?;
        d.end()?;
        Ok(Self {
            group_tag,
            relay_key,
            incarnation,
            parent_head,
            slot,
            author_leaf,
            author_endpoint,
            issued_at,
            op,
            commit,
            resulting_digest,
        })
    }

    /// Sign with the author's pinned MLS signature key.
    pub fn sign(&self, signer: &impl Signer) -> Vec<u8> {
        let body = self.body();
        let sig = signer
            .sign(&hash(TRANSITION_SIG, &[&body]))
            .expect("sign transition");
        Enc::new().bytes(&body).bytes(&sig).finish()
    }

    /// Decode a signed transition. The signature is checked separately with
    /// `verify`, against a key taken from the accepted parent roster.
    pub fn decode_signed(b: &[u8]) -> Result<SignedTransition, RecordError> {
        let mut d = Dec::new(b);
        let body = d.bytes()?;
        let signature = d.bytes()?;
        d.end()?;
        Ok(SignedTransition {
            transition: Self::decode_body(&body)?,
            body,
            signature,
        })
    }
}

pub struct SignedTransition {
    pub transition: Transition,
    body: Vec<u8>,
    signature: Vec<u8>,
}

impl SignedTransition {
    pub fn verify(&self, author_mls_key: &[u8]) -> Result<(), SigReject> {
        verify_ed25519(
            author_mls_key,
            &hash(TRANSITION_SIG, &[&self.body]),
            &self.signature,
        )
    }
}

// ------------------------------------------------------------------ invite

/// Bearer invite. Pins the protocol, group, relay identity and incarnation,
/// issuer's endpoint and MLS keys, and an invite-specific id and secret. It
/// carries no membership slot key or roster key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteToken {
    pub group_tag: Hash,
    pub relay_key: [u8; 32],
    pub incarnation: Vec<u8>,
    pub issuer_endpoint: EndpointKey,
    pub issuer_mls_key: Vec<u8>,
    pub invite_id: [u8; 16],
    pub secret: [u8; 32],
    /// The issuer's per-invite queue acknowledgement key: it alone reads the request queue.
    pub queue_ack_key: [u8; 32],
    /// The issuer's per-invite reply writer key: it alone writes the reply object.
    pub reply_key: [u8; 32],
}

/// The issuer-only keys of one invite, from seeds never derived from the shared secret.
pub struct InviteKeys {
    ack: SigningKey,
    reply: SigningKey,
}

impl InviteKeys {
    pub fn from_seeds(ack_seed: &[u8; 32], reply_seed: &[u8; 32]) -> Self {
        Self {
            ack: SigningKey::from_bytes(ack_seed),
            reply: SigningKey::from_bytes(reply_seed),
        }
    }

    pub fn ack_pub(&self) -> [u8; 32] {
        self.ack.verifying_key().to_bytes()
    }

    pub fn reply_pub(&self) -> [u8; 32] {
        self.reply.verifying_key().to_bytes()
    }

    /// A read of the request queue for the first item after `after`.
    pub fn read(&self, pin: &Pin, queue: QueueKeys, after: u64) -> Result<ReadHeader, SigReject> {
        let mut h = ReadHeader {
            relay_key: pin.relay_key,
            incarnation: pinned(&pin.incarnation)?,
            keys: queue,
            after,
            proof: [0; 64],
        };
        h.proof = self.ack.sign(&read_statement(VERSION, &h)).to_bytes();
        Ok(h)
    }

    /// The terminal acknowledgement of one request item.
    pub fn ack(&self, pin: &Pin, queue: QueueKeys, item: [u8; 32]) -> Result<AckHeader, SigReject> {
        let mut h = AckHeader {
            relay_key: pin.relay_key,
            incarnation: pinned(&pin.incarnation)?,
            keys: queue,
            item,
            proof: [0; 64],
        };
        h.proof = self.ack.sign(&ack_statement(VERSION, &h)).to_bytes();
        Ok(h)
    }
}

/// The signed header of an invite reply object, by the issuer's per-invite reply key.
pub fn reply_header(
    reply_seed: &[u8; 32],
    pin: &Pin,
    sealed: &[u8],
) -> Result<WriteHeader, SigReject> {
    let key = SigningKey::from_bytes(reply_seed);
    let mut h = unsigned_header(
        INVITE_REPLY,
        pin.relay_key,
        pinned(&pin.incarnation)?,
        key.verifying_key().to_bytes(),
        sealed,
    );
    h.proof = key.sign(&write_statement(VERSION, &h)).to_bytes();
    Ok(h)
}

fn pinned(incarnation: &[u8]) -> Result<Incarnation, SigReject> {
    Incarnation::from_slice(incarnation)
        .ok_or_else(|| SigReject("storage incarnation is not 32 bytes".into()))
}

impl InviteToken {
    /// The relay identity and storage incarnation this invite pins together.
    pub fn pin(&self) -> Pin {
        Pin {
            relay_key: self.relay_key,
            incarnation: self.incarnation.clone(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        Enc::new()
            .u8(RECORD_VERSION)
            .bytes(INVITE)
            .bytes(PROTOCOL)
            .fixed(&self.group_tag)
            .fixed(&self.relay_key)
            .bytes(&self.incarnation)
            .fixed(&self.issuer_endpoint)
            .bytes(&self.issuer_mls_key)
            .fixed(&self.invite_id)
            .fixed(&self.secret)
            .fixed(&self.queue_ack_key)
            .fixed(&self.reply_key)
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, RecordError> {
        let mut d = Dec::new(b);
        if d.u8()? != RECORD_VERSION {
            return Err(RecordError::Malformed("invite version".into()));
        }
        d.expect_label(INVITE)?;
        d.expect_label(PROTOCOL)?;
        let t = Self {
            group_tag: d.fixed()?,
            relay_key: d.fixed()?,
            incarnation: d.bytes()?,
            issuer_endpoint: d.fixed()?,
            issuer_mls_key: d.bytes()?,
            invite_id: d.fixed()?,
            secret: d.fixed()?,
            queue_ack_key: d.fixed()?,
            reply_key: d.fixed()?,
        };
        d.end()?;
        Ok(t)
    }

    fn key(&self, purpose: &[u8]) -> Vec<u8> {
        hkdf(
            &self.secret,
            &self.invite_id,
            &Enc::new().bytes(purpose).bytes(PROTOCOL).finish(),
            AEAD_KEY,
        )
    }

    /// Opaque mailbox handles for the request queue and the reply.
    /// The append key every holder of this invite derives from its secret. It may add request
    /// items to the invite's queue and nothing else.
    fn append_key(&self) -> SigningKey {
        let seed = hkdf(
            &self.secret,
            &self.invite_id,
            &Enc::new()
                .bytes(INVITE_REQUEST_APPEND_KEY)
                .bytes(PROTOCOL)
                .finish(),
            32,
        );
        SigningKey::from_bytes(&seed.try_into().expect("32-byte seed"))
    }

    /// The invite's request queue: bound to the shared append key and the issuer's
    /// acknowledgement key.
    pub fn request_queue(&self) -> QueueKeys {
        QueueKeys::new(
            self.append_key().verifying_key().to_bytes(),
            self.queue_ack_key,
        )
    }

    /// The signed append of an exact sealed request to this invite's queue.
    pub fn prepare_request(&self, sealed: &[u8]) -> Result<AppendHeader, SigReject> {
        let mut h = unsigned_append(
            INVITE_REQUEST,
            self.relay_key,
            pinned(&self.incarnation)?,
            self.request_queue(),
            sealed,
        );
        h.proof = self
            .append_key()
            .sign(&append_statement(VERSION, &h))
            .to_bytes();
        Ok(h)
    }

    /// The immutable reply object's address: the issuer's reply key's slot.
    pub fn reply_box(&self) -> Hash {
        crate::slot_wire::slot_address(&self.reply_key).to_bytes()
    }

    fn aad(&self, label: &[u8]) -> Hash {
        hash(label, &[PROTOCOL, &[RECORD_VERSION], &self.invite_id])
    }

    fn seal(&self, key_purpose: &[u8], aad_label: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let (ct, nonce) = seal_raw(&self.key(key_purpose), &self.aad(aad_label), plaintext);
        Enc::new()
            .u8(RECORD_VERSION)
            .fixed(&nonce)
            .fixed(&ct)
            .finish()
    }

    fn open(
        &self,
        key_purpose: &[u8],
        aad_label: &[u8],
        bytes: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        let mut d = Dec::new(bytes);
        if d.u8()? != RECORD_VERSION {
            return Err(RecordError::Malformed("invite record version".into()));
        }
        let nonce = d.fixed::<NONCE>()?;
        let ct = d.take(bytes.len() - 1 - NONCE)?;
        open_raw(&self.key(key_purpose), &self.aad(aad_label), &nonce, ct)
    }

    pub fn seal_request(&self, r: &JoinRequest) -> Vec<u8> {
        self.seal(INVITE_REQUEST_KEY, REQUEST_AAD, &r.encode())
    }

    pub fn open_request(&self, bytes: &[u8]) -> Result<JoinRequest, RecordError> {
        JoinRequest::decode(&self.open(INVITE_REQUEST_KEY, REQUEST_AAD, bytes)?)
    }

    pub fn seal_reply(&self, reply: &[u8]) -> Vec<u8> {
        self.seal(INVITE_REPLY_KEY, REPLY_AAD, reply)
    }

    pub fn open_reply(&self, bytes: &[u8]) -> Result<Vec<u8>, RecordError> {
        self.open(INVITE_REPLY_KEY, REPLY_AAD, bytes)
    }
}

/// Plaintext of a join request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    pub transcript: JoinTranscript,
    pub proof: Vec<u8>,
    /// Exact KeyPackage (TLS-encoded `KeyPackage`).
    pub key_package: Vec<u8>,
}

impl JoinRequest {
    pub fn encode(&self) -> Vec<u8> {
        Enc::new()
            .u8(RECORD_VERSION)
            .bytes(&self.transcript.encode())
            .bytes(&self.proof)
            .bytes(&self.key_package)
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, RecordError> {
        let mut d = Dec::new(b);
        if d.u8()? != RECORD_VERSION {
            return Err(RecordError::Malformed("join request version".into()));
        }
        let tb = d.bytes()?;
        let mut td = Dec::new(&tb);
        let transcript = JoinTranscript::decode(&mut td)?;
        td.end()?;
        let r = Self {
            transcript,
            proof: d.bytes()?,
            key_package: d.bytes()?,
        };
        d.end()?;
        Ok(r)
    }
}

// ----------------------------------------------------------------- receipt

/// Issuer-signed admission receipt, delivered with the Welcome inside the
/// encrypted invite reply. It binds the exact slot record, resulting group
/// context, roster and revoked set, the pending request and selected
/// KeyPackage, the exact Welcome bytes and the accepted epoch's key
/// confirmation (epoch authenticator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub relay_key: [u8; 32],
    pub incarnation: Vec<u8>,
    pub group_tag: Hash,
    pub issuer_endpoint: EndpointKey,
    pub issuer_mls_key: Vec<u8>,
    pub invite_id: [u8; 16],
    pub request_digest: Hash,
    pub joiner_endpoint: EndpointKey,
    pub key_package_ref: Vec<u8>,
    pub parent_head: Hash,
    pub slot: SlotId,
    pub ct_hash: Hash,
    pub head: Hash,
    pub resulting_digest: Hash,
    pub group_context: Vec<u8>,
    pub roster: Vec<RosterEntry>,
    pub revoked: Vec<EndpointKey>,
    pub welcome_hash: Hash,
    pub epoch_authenticator: Vec<u8>,
    pub issued_at: u64,
}

impl Receipt {
    pub fn body(&self) -> Vec<u8> {
        Enc::new()
            .u8(RECORD_VERSION)
            .bytes(RECEIPT)
            .bytes(PROTOCOL)
            .fixed(&self.relay_key)
            .bytes(&self.incarnation)
            .fixed(&self.group_tag)
            .fixed(&self.issuer_endpoint)
            .bytes(&self.issuer_mls_key)
            .fixed(&self.invite_id)
            .fixed(&self.request_digest)
            .fixed(&self.joiner_endpoint)
            .bytes(&self.key_package_ref)
            .fixed(&self.parent_head)
            .fixed(&self.slot)
            .fixed(&self.ct_hash)
            .fixed(&self.head)
            .fixed(&self.resulting_digest)
            .bytes(&self.group_context)
            .list(&self.roster, |e, (ep, sk)| {
                e.fixed(ep).bytes(sk);
            })
            .list(&self.revoked, |e, r| {
                e.fixed(r);
            })
            .fixed(&self.welcome_hash)
            .bytes(&self.epoch_authenticator)
            .u64(self.issued_at)
            .finish()
    }

    fn decode(b: &[u8]) -> Result<Self, RecordError> {
        let mut d = Dec::new(b);
        if d.u8()? != RECORD_VERSION {
            return Err(RecordError::Malformed("receipt version".into()));
        }
        d.expect_label(RECEIPT)?;
        d.expect_label(PROTOCOL)?;
        let r = Self {
            relay_key: d.fixed()?,
            incarnation: d.bytes()?,
            group_tag: d.fixed()?,
            issuer_endpoint: d.fixed()?,
            issuer_mls_key: d.bytes()?,
            invite_id: d.fixed()?,
            request_digest: d.fixed()?,
            joiner_endpoint: d.fixed()?,
            key_package_ref: d.bytes()?,
            parent_head: d.fixed()?,
            slot: d.fixed()?,
            ct_hash: d.fixed()?,
            head: d.fixed()?,
            resulting_digest: d.fixed()?,
            group_context: d.bytes()?,
            roster: d.list(|d| Ok((d.fixed()?, d.bytes()?)))?,
            revoked: d.list(|d| d.fixed())?,
            welcome_hash: d.fixed()?,
            epoch_authenticator: d.bytes()?,
            issued_at: d.u64()?,
        };
        d.end()?;
        Ok(r)
    }
}

/// Plaintext of an invite reply: exact Welcome bytes plus signed receipt.
pub struct Reply {
    pub welcome: Vec<u8>,
    pub receipt: Receipt,
    receipt_body: Vec<u8>,
    signature: Vec<u8>,
}

impl Reply {
    pub fn build(welcome: Vec<u8>, receipt: Receipt, signer: &impl Signer) -> Vec<u8> {
        let body = receipt.body();
        let sig = signer
            .sign(&hash(RECEIPT_SIG, &[&body]))
            .expect("sign receipt");
        Enc::new()
            .u8(RECORD_VERSION)
            .bytes(&welcome)
            .bytes(&body)
            .bytes(&sig)
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, RecordError> {
        let mut d = Dec::new(b);
        if d.u8()? != RECORD_VERSION {
            return Err(RecordError::Malformed("reply version".into()));
        }
        let welcome = d.bytes()?;
        let receipt_body = d.bytes()?;
        let signature = d.bytes()?;
        d.end()?;
        Ok(Self {
            welcome,
            receipt: Receipt::decode(&receipt_body)?,
            receipt_body,
            signature,
        })
    }

    /// Verify the receipt signature against the invite-pinned issuer key.
    pub fn verify(&self, issuer_mls_key: &[u8]) -> Result<(), SigReject> {
        verify_ed25519(
            issuer_mls_key,
            &hash(RECEIPT_SIG, &[&self.receipt_body]),
            &self.signature,
        )
    }
}
