//! Device-side private membership and admission state machine.
//!
//! One `Device` handle owns one profile directory. The profile lock
//! (`store::Guard`) makes the profile a single local writer across threads
//! and processes. It is never held while waiting for the relay:
//!
//! - A read snapshots its target (pinned incarnation, accepted head and
//!   file, journal or pending-join identity) under the lock, reads without
//!   it, then retakes the lock and applies the result only if that identity
//!   is unchanged. A stale result is discarded, never applied to a newer
//!   parent.
//! - A write takes the lock, rechecks eligibility, durably records the
//!   attempt and hands the exact persisted bytes to the transport
//!   (`Mailbox::start_*`, nonblocking), then releases the lock and waits.
//!   Linearization: a cutoff, removal or halt recorded before the handoff
//!   prevents it; after the handoff, delivery may be unknown and a sent
//!   reply cannot be recalled. Recovery rechecks eligibility before handing
//!   the same bytes off again.
//!
//! Durable decisions, in order:
//!
//! | Step | Durable before any external effect |
//! | --- | --- |
//! | join request | pending transcript, KeyPackage (+ private keys), exact request ciphertext |
//! | reservation | clock observation (own transaction), then the selected request and KeyPackage |
//! | stage | candidate MLS file holding the fully merged and verified successor, then the journal (exact slot bytes, sealed reply) |
//! | publish | candidate rechecked, `publish_attempted` and attempt id, then the handoff |
//! | accept own | matching slot read, then one promotion transaction |
//! | adopt winner | validation copy, then one promotion transaction that drops the journal |
//! | dispatch | eligibility and `Dispatching` attempt, then the handoff; `Sent` after the outcome |

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use openmls_traits::types::SignatureScheme;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::binding::{CredentialBinding, EndpointKey, EndpointSecret, JoinTranscript, signed_name};
use super::codec::{Dec, Hash, hex, random, sha256};
use super::envelope::{
    InviteKeys, InviteToken, JoinRequest, Op, Receipt, RecordError, Reply, RosterEntry, SlotId,
    SlotKeys, Transition, crypto, genesis_head, next_head, reply_header, slot_record_salt_nonce,
    state_digest,
};
use super::fault;
use super::mailbox::{
    AckOutcome, CreateOutcome, Mailbox, MailboxError, Pin, QueueAppend, QueueBody, ReadOutcome,
    SlotWrite,
};
use super::policy::{ParentView, Violation};
use super::store::{Guard, MlsProvider, Store, StoreError, write_marker};
use super::{
    CIPHERSUITE, CLOCK_ROLLBACK_TOLERANCE_SECS, INVITE_WINDOW_SECS, KEY_PACKAGE_LIFETIME_SECS,
    KEY_PACKAGE_MAX_LIFETIME_SECS, versions,
};
use crate::slot_wire::{
    INVITE_REPLY, Incarnation, MEMBERSHIP_SLOT, QueueKeys, SlotAddress, WriteHeader,
};

// ------------------------------------------------------------------ clock

/// Clock for issuer-side live decisions and new KeyPackages. Historical
/// validation never reads it.
#[derive(Clone, Debug)]
pub enum Clock {
    System,
    Manual(Arc<AtomicU64>),
}

impl Clock {
    pub fn manual(t: u64) -> Self {
        Clock::Manual(Arc::new(AtomicU64::new(t)))
    }

    pub fn now(&self) -> u64 {
        match self {
            Clock::System => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            Clock::Manual(a) => a.load(Ordering::SeqCst),
        }
    }

    pub fn set(&self, t: u64) {
        if let Clock::Manual(a) = self {
            a.store(t, Ordering::SeqCst);
        }
    }
}

// ------------------------------------------------------------------ state

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AcceptedSlot {
    pub slot: SlotId,
    pub ct_hash: Hash,
    pub head: Hash,
    pub epoch: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Network {
    pub group_tag: Hash,
    pub group_id: Vec<u8>,
    pub relay_key: [u8; 32],
    pub incarnation: Vec<u8>,
    /// MLS file of the accepted epoch.
    pub mls_file: String,
    /// This device's pinned MLS signature public key.
    pub mls_key: Vec<u8>,
    pub head: Hash,
    pub epoch: u64,
    /// Every accepted (slot, ciphertext hash, head), oldest first.
    pub accepted: Vec<AcceptedSlot>,
    /// Revoked endpoint keys in the authenticated group state.
    pub revoked: Vec<EndpointKey>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectClass {
    /// Confirmed invalid: framing, policy, MLS validation, structural path
    /// errors such as a parent-hash mismatch.
    Invalid,
    /// Authenticated in the parent epoch, but this device cannot decrypt the
    /// update path.
    Undecryptable,
    /// A signature check rejected. Not confirmed: verification itself may be
    /// faulty. The parent is kept and advancement suspended either way.
    VerificationFault,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Halt {
    Rejected {
        class: RejectClass,
        slot: SlotId,
        ct_hash: Hash,
        reason: String,
    },
    /// The relay holds this device's exact candidate, but the successor
    /// state is gone. OpenMLS cannot process an own commit with a path.
    CandidateLost {
        slot: SlotId,
        reason: String,
    },
    Quarantined {
        evidence: String,
    },
    IncarnationMismatch {
        detail: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum JournalOp {
    Add {
        invite_id: [u8; 16],
        joiner: EndpointKey,
    },
    Remove {
        subject: EndpointKey,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PendingReply {
    pub invite_id: [u8; 16],
    pub joiner: EndpointKey,
    /// The immutable reply object: the slot of the issuer's per-invite reply key.
    pub reply_box: Hash,
    /// Exact encrypted reply (Welcome + signed receipt).
    pub bytes: Vec<u8>,
    /// The reply key, and the length, digest and proof it signed for `bytes`.
    pub reply_key: [u8; 32],
    pub reply_len: u64,
    pub reply_digest: Hash,
    pub reply_proof: Vec<u8>,
}

impl PendingReply {
    /// The signed reply header persisted with these bytes, assembled without rehashing.
    pub fn write_header(&self, pin: &Pin) -> Result<WriteHeader, String> {
        Ok(WriteHeader {
            purpose: INVITE_REPLY,
            relay_key: pin.relay_key,
            incarnation: Incarnation::from_slice(&pin.incarnation)
                .ok_or("storage incarnation is not 32 bytes")?,
            write_key: self.reply_key,
            slot: SlotAddress::from_bytes(self.reply_box),
            len: self.reply_len,
            digest: self.reply_digest,
            proof: self
                .reply_proof
                .as_slice()
                .try_into()
                .map_err(|_| "reply proof is not 64 bytes")?,
        })
    }

    fn checked_header(&self, pin: &Pin) -> Result<WriteHeader, String> {
        let header = self.write_header(pin)?;
        crate::slot_wire::verify_proof(&header).map_err(|error| format!("{error:?}"))?;
        crate::slot_wire::verify_body(&header, &self.bytes)
            .map_err(|error| format!("{error:?}"))?;
        Ok(header)
    }
}

/// An own staged transition. Lives only in `membership.db`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub id: [u8; 16],
    pub parent_head: Hash,
    pub parent_epoch: u64,
    pub parent_mls_file: String,
    /// Holds the fully merged, verified successor state.
    pub candidate_mls_file: String,
    pub slot: SlotId,
    pub write_pub: [u8; 32],
    pub write_proof: Vec<u8>,
    /// Length and digest the write proof signs, persisted so a handoff never rehashes.
    pub write_len: u64,
    pub write_digest: Hash,
    pub slot_bytes: Vec<u8>,
    pub new_head: Hash,
    pub resulting_digest: Hash,
    pub op: JournalOp,
    pub publish_attempted: bool,
    /// Identity of the latest handoff.
    pub attempt: Option<[u8; 16]>,
    pub last_outcome: Option<String>,
    pub reply: Option<PendingReply>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub request_digest: Hash,
    pub joiner: EndpointKey,
    pub transcript: Vec<u8>,
    pub proof: Vec<u8>,
    pub key_package: Vec<u8>,
    pub key_package_ref: Vec<u8>,
    /// Effective issuer time of the first valid reservation.
    pub reserved_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct IssuedInvite {
    pub invite_id: [u8; 16],
    pub secret: [u8; 32],
    pub not_before: u64,
    pub expires_at: u64,
    pub reservation: Option<Reservation>,
    /// Slot of the accepted Add that admitted the reserved request.
    pub admitted_slot: Option<SlotId>,
    /// Issuer-only seeds of the queue acknowledgement key and the reply writer key, never
    /// derived from the shared invite secret.
    pub ack_seed: [u8; 32],
    pub reply_seed: [u8; 32],
    /// The last request queue item whose verdict is durable here.
    pub queue_cursor: u64,
    /// Items at or before the cursor whose terminal acknowledgement is not yet confirmed.
    pub unacked: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum OutboxStatus {
    Ready,
    /// Handed to the transport; delivery may be unknown.
    Dispatching {
        attempt: [u8; 16],
    },
    Sent,
    Withheld {
        reason: String,
        possibly_sent: bool,
    },
    /// The reply box holds a different value. Isolated to this entry.
    Conflicted,
    /// The reply box is occupied but its body was purged; the store cannot
    /// tell whose value it holds. Isolated to this entry; not resent.
    Unavailable,
    /// The store definitively refused this exact reply. Nothing was stored
    /// by it. Isolated to this entry; not resent.
    Refused {
        reason: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OutboxEntry {
    pub reply: PendingReply,
    pub admitted_slot: SlotId,
    pub status: OutboxStatus,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PendingJoin {
    pub token: Vec<u8>,
    pub mls_file: String,
    pub mls_key: Vec<u8>,
    pub transcript: Vec<u8>,
    pub proof: Vec<u8>,
    pub key_package: Vec<u8>,
    pub key_package_ref: Vec<u8>,
    /// Exact request ciphertext; retransmits send these bytes.
    pub request: Vec<u8>,
    pub last_failure: Option<String>,
    /// Persistent stop, e.g. an authenticated incarnation mismatch.
    pub halted: Option<String>,
}

impl PendingJoin {
    /// Same pending join: every identity field, ignoring diagnostics and the
    /// halt marker.
    fn same(&self, other: &PendingJoin) -> bool {
        self.token == other.token
            && self.mls_file == other.mls_file
            && self.mls_key == other.mls_key
            && self.transcript == other.transcript
            && self.proof == other.proof
            && self.key_package == other.key_package
            && self.key_package_ref == other.key_package_ref
            && self.request == other.request
    }
}

/// Why the exact pending join `pj` may not be installed now, if anything.
fn join_install_blocked(st: &State, pj: &PendingJoin) -> Option<Error> {
    match &st.pending_join {
        Some(p) if !p.same(pj) => Some(Error::Busy("pending join changed".into())),
        Some(p) => p
            .halted
            .as_ref()
            .map(|h| JoinError::Halted(h.clone()).into()),
        None => Some(Error::Busy("pending join changed".into())),
    }
    .or_else(|| {
        st.net
            .is_some()
            .then(|| Error::Busy("already a member".into()))
    })
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Terminal {
    pub author_leaf: u32,
    pub slot: SlotId,
    pub ct_hash: Hash,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub own_merges: u64,
    pub remote_merges: u64,
    /// Hashes of discarded own candidates.
    pub discarded: Vec<Hash>,
    /// Read results discarded because the profile moved meanwhile.
    pub stale_reads: u64,
}

/// The whole application state row (experimental format).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct State {
    pub endpoint: EndpointKey,
    pub net: Option<Network>,
    pub local_cutoffs: Vec<EndpointKey>,
    pub halt: Option<Halt>,
    pub journal: Option<Journal>,
    pub invites: Vec<IssuedInvite>,
    pub clock_high_water: u64,
    pub outbox: Vec<OutboxEntry>,
    pub pending_join: Option<PendingJoin>,
    pub terminal: Option<Terminal>,
    pub stats: Stats,
}

impl State {
    fn new(endpoint: EndpointKey) -> Self {
        Self {
            endpoint,
            net: None,
            local_cutoffs: vec![],
            halt: None,
            journal: None,
            invites: vec![],
            clock_high_water: 0,
            outbox: vec![],
            pending_join: None,
            terminal: None,
            stats: Stats::default(),
        }
    }

    fn net(&self) -> Result<&Network, Error> {
        if self.terminal.is_some() {
            return Err(Error::Terminal);
        }
        self.net.as_ref().ok_or(Error::NotMember)
    }

    fn writable(&self) -> Result<&Network, Error> {
        let net = self.net()?;
        if let Some(h) = &self.halt {
            return Err(Error::Halted(h.clone()));
        }
        Ok(net)
    }

    /// Whether this exact relay and incarnation are still pinned by a
    /// live (non-terminal) membership. An authenticated mismatch from that
    /// relay is processed whatever else changed meanwhile.
    fn pins(&self, relay_key: &[u8; 32], incarnation: &[u8]) -> bool {
        self.terminal.is_none()
            && self
                .net
                .as_ref()
                .is_some_and(|n| &n.relay_key == relay_key && n.incarnation == incarnation)
    }

    /// Exact identity slot bytes are applied against.
    fn anchor(&self) -> Option<Anchor> {
        if self.terminal.is_some() || self.halt.is_some() {
            return None;
        }
        let n = self.net.as_ref()?;
        Some(Anchor {
            relay_key: n.relay_key,
            head: n.head,
            mls_file: n.mls_file.clone(),
            incarnation: n.incarnation.clone(),
            journal: self.journal.as_ref().map(|j| j.id),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Anchor {
    relay_key: [u8; 32],
    head: Hash,
    mls_file: String,
    incarnation: Vec<u8>,
    journal: Option<[u8; 16]>,
}

impl Anchor {
    fn pin(&self) -> Pin {
        Pin {
            relay_key: self.relay_key,
            incarnation: self.incarnation.clone(),
        }
    }
}

impl Network {
    /// The relay identity and storage incarnation this network pinned together.
    pub fn pin(&self) -> Pin {
        Pin {
            relay_key: self.relay_key,
            incarnation: self.incarnation.clone(),
        }
    }
}

impl Journal {
    /// The signed relay header persisted with this candidate. Assembled from stored fields; the
    /// ciphertext is neither copied nor hashed.
    pub fn write_header(&self, pin: &Pin) -> Result<WriteHeader, String> {
        Ok(WriteHeader {
            purpose: MEMBERSHIP_SLOT,
            relay_key: pin.relay_key,
            incarnation: Incarnation::from_slice(&pin.incarnation)
                .ok_or("storage incarnation is not 32 bytes")?,
            write_key: self.write_pub,
            slot: SlotAddress::from_bytes(self.slot),
            len: self.write_len,
            digest: self.write_digest,
            proof: self
                .write_proof
                .as_slice()
                .try_into()
                .map_err(|_| "write proof is not 64 bytes")?,
        })
    }
}

// ----------------------------------------------------------------- errors

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    UnknownInvite,
    MalformedRequest(String),
    NotYetValid {
        now: u64,
        not_before: u64,
    },
    Expired {
        now: u64,
        expires_at: u64,
    },
    /// A different request already holds this invite.
    AlreadyUsed,
    ClockRollback {
        now: u64,
        high_water: u64,
    },
    IssuerNotAuthorized(String),
    InviteMismatch(String),
    ProofInvalid(String),
    KeyPackageInvalid(String),
    KeyPackageExpired(String),
    KeyPackageLifetimeTooLong,
    BindingInvalid(String),
    Ineligible(String),
    NoReservation,
    AlreadyAdmitted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinError {
    NoPendingJoin,
    Waiting,
    InviteUsed,
    ReplyUndecryptable,
    Malformed(String),
    /// Receipt, binding or Welcome signature rejected (unconfirmed fault).
    VerificationFault(String),
    Mismatch(String),
    SlotUnavailable(String),
    Welcome(String),
    Halted(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub class: RejectClass,
    pub slot: SlotId,
    pub ct_hash: Hash,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Local storage failure. Never a verdict on a slot.
    Storage(String),
    Halted(Halt),
    Terminal,
    NotMember,
    Busy(String),
    Admission(AdmissionError),
    Join(JoinError),
    Mailbox(MailboxError),
    Slot(Rejection),
    Unavailable(String),
    /// The own candidate cannot be used; nothing was written.
    CandidateUnusable(String),
    /// Local library or programming fault. Never a verdict on a slot.
    Internal(String),
    /// The gate closed (runtime stopping); nothing further was done.
    Cancelled,
}

impl From<StoreError> for Error {
    fn from(e: StoreError) -> Self {
        Error::Storage(e.0)
    }
}

impl From<AdmissionError> for Error {
    fn from(e: AdmissionError) -> Self {
        Error::Admission(e)
    }
}

impl From<JoinError> for Error {
    fn from(e: JoinError) -> Self {
        Error::Join(e)
    }
}

fn internal<E: std::fmt::Debug>(ctx: &'static str) -> impl FnOnce(E) -> Error {
    move |e| Error::Internal(format!("{ctx}: {e:?}"))
}

/// Why validating a slot did not produce a successor.
enum Invalid {
    /// The slot itself was rejected; halt on it.
    Rejected(Rejection),
    /// A local storage or library fault; the slot was not judged.
    Local(Error),
}

// ---------------------------------------------------------------- outcomes

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveOutcome {
    Reserved {
        reserved_at: u64,
    },
    /// Exact retransmit of the reserved request. Renews nothing.
    ExactRetry {
        reserved_at: u64,
    },
    /// Exact retransmit after admission. Mints nothing.
    AlreadyAdmitted {
        reserved_at: u64,
    },
}

/// One request queue item an issuer processed, or why it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polled {
    pub invite_id: [u8; 16],
    pub seq: Option<u64>,
    pub verdict: Verdict,
    pub ack: AckState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Reserved(ReserveOutcome),
    /// A definitive local rejection of this item; the invite is untouched by it.
    Rejected(AdmissionError),
    /// This issuer cannot judge the item now; it stays unprocessed.
    Deferred(AdmissionError),
    /// The issuer already acknowledged this item.
    AlreadyAcknowledged,
    /// The relay verified this item's body is damaged. Its identity and order are intact, so it
    /// is recorded and acknowledged without touching the invite; its content is gone.
    Damaged,
    /// The queue could not be read; nothing was processed.
    Unavailable(MailboxError),
    /// An earlier poll already made this item's verdict durable; this reports only the retry
    /// of its pending acknowledgement.
    Retried {
        item: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckState {
    /// The relay recorded the terminal acknowledgement, now or earlier.
    Confirmed(AckOutcome),
    /// The relay's current view holds no such item, so nothing is acknowledged. The item stays
    /// unresolved and is retried by the next poll.
    NoSuchItem,
    /// Unknown; retried by the next poll, without holding up other items.
    Unconfirmed(MailboxError),
    NotNeeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpSummary {
    Add { joiner: EndpointKey },
    Remove { subject: EndpointKey },
}

/// `Advance::Advanced::author_leaf` of this device's own accepted commit,
/// reported to the gate at promotion.
pub const OWN_COMMIT: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advance {
    Advanced {
        epoch: u64,
        /// The author's leaf, or `OWN_COMMIT`.
        author_leaf: u32,
        op: OpSummary,
    },
    SelfRemoved {
        author_leaf: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settle {
    NoCandidate,
    /// Journaled, never handed off.
    NotPublished,
    /// Handed off at least once; the slot is still absent.
    Pending,
    Accepted,
    Lost {
        winner: Advance,
    },
    /// The candidate became unusable before any handoff and was dropped.
    Discarded {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The next slot is absent in the configured relay's current view.
    UpToDate,
    OwnCandidatePending,
    Terminal,
    Halted(Halt),
    Unavailable(String),
    Failed(Error),
    /// The gate closed (runtime stopping) before the next read or apply.
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dispatch {
    Sent {
        invite_id: [u8; 16],
    },
    Withheld {
        invite_id: [u8; 16],
        reason: String,
        possibly_sent: bool,
    },
    Conflicted {
        invite_id: [u8; 16],
    },
    /// Occupied, body purged; not resent.
    Unavailable {
        invite_id: [u8; 16],
    },
    /// Definitively refused; nothing stored; not resent.
    Refused {
        invite_id: [u8; 16],
        reason: String,
    },
    /// Handed off, outcome unknown; stays `Dispatching`.
    Unconfirmed {
        invite_id: [u8; 16],
        error: MailboxError,
    },
    /// Not handed off: the mailbox cannot serve the network's pin. The entry's status is
    /// unchanged, so an earlier attempt's uncertainty is kept.
    NotAttempted {
        invite_id: [u8; 16],
        error: MailboxError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    /// The cutoff is durably saved locally.
    pub local_cutoff: bool,
    /// Staged removal slot, or why no removal was staged.
    pub removal: Result<SlotId, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Recovered {
    pub swept: Vec<String>,
}

// ------------------------------------------------------- test adversaries

/// Test-only deviations an adversarial author can apply when staging. They
/// bypass the author's own policy and successor checks, so tests can prove
/// that recipients reject on their own. Outside tests the type is empty and
/// every bypass branch is compiled out.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub struct Adversary {
    pub no_path: bool,
    pub tamper_digest: bool,
    pub extra_remove: Option<u32>,
    pub forge_proof: bool,
    pub signed_issued_at: Option<u64>,
    pub signed_reserved_at: Option<u64>,
    pub skip_issuer_checks: bool,
}

#[cfg(not(test))]
pub enum Adversary {}

// The test-only raw variant carries a whole invite; values live only for one staging call.
#[allow(clippy::large_enum_variant)]
enum StageKind<'a> {
    Add {
        invite_id: [u8; 16],
    },
    Remove {
        subject: EndpointKey,
    },
    /// Test-only: an issuer committing an unreserved request directly.
    #[cfg(test)]
    RawAdd {
        request: &'a JoinRequest,
        reply_to: Option<InviteToken>,
    },
    #[cfg(not(test))]
    #[allow(dead_code)]
    Never(std::marker::PhantomData<&'a ()>),
}

/// Admission material for an Add, checked live on the issuer clock.
struct AddMaterial {
    kp: Vec<u8>,
    transcript: JoinTranscript,
    proof: Vec<u8>,
    not_before: u64,
    expires_at: u64,
    reserved_at: u64,
    reply_to: Option<InviteToken>,
    /// The issuer-only seed of the reply writer key for `reply_to`.
    reply_seed: Option<[u8; 32]>,
}

// ------------------------------------------------------------- MLS helpers

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(0)
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(0)
        .build()
}

fn load_group(p: &MlsProvider<'_>, group_id: &[u8]) -> Result<MlsGroup, Error> {
    MlsGroup::load(p.storage(), &GroupId::from_slice(group_id))
        .map_err(internal("load group"))?
        .ok_or_else(|| Error::Internal("group missing from MLS file".into()))
}

fn signer(p: &MlsProvider<'_>, public: &[u8]) -> Result<SignatureKeyPair, Error> {
    SignatureKeyPair::read(p.storage(), public, SignatureScheme::ED25519)
        .ok_or_else(|| Error::Internal("signer missing from MLS file".into()))
}

fn violation(v: Violation) -> (RejectClass, String) {
    match v {
        Violation::Policy(s) => (RejectClass::Invalid, s),
        Violation::Signature(s) => (RejectClass::VerificationFault, s),
    }
}

/// Classify an OpenMLS processing error. Storage and library faults are
/// local and never judge the slot.
fn classify<E: std::fmt::Debug>(
    e: &ProcessMessageError<E>,
) -> Result<(RejectClass, String), Error> {
    use openmls::treesync::errors::ApplyUpdatePathError as P;
    let s = format!("{e:?}");
    match e {
        ProcessMessageError::StorageError(_) => Err(Error::Storage(s)),
        _ if s.contains("LibraryError") => Err(Error::Internal(s)),
        // Only an actual decryption failure of the path is "authenticated
        // but undecryptable". `MissingSender` is how OpenMLS reports missing
        // own path keys (treesync/treekem.rs); the sender itself was already
        // matched to the envelope author's parent leaf.
        ProcessMessageError::InvalidCommit(StageCommitError::UpdatePathError(
            P::UnableToDecrypt | P::MissingSender,
        ))
        | ProcessMessageError::InvalidCommit(StageCommitError::MissingDecryptionKey) => {
            Ok((RejectClass::Undecryptable, s))
        }
        // Any signature-class rejection inside OpenMLS (message, leaf node,
        // KeyPackage) is an unconfirmed fault, never a confirmed verdict.
        _ if s.contains("Signature") => Ok((RejectClass::VerificationFault, s)),
        // Everything else, including structural path errors such as a
        // parent-hash mismatch, is a confirmed invalid slot.
        _ => Ok((RejectClass::Invalid, s)),
    }
}

fn kp_error(e: impl std::fmt::Debug) -> AdmissionError {
    let s = format!("{e:?}");
    if s.contains("Lifetime") {
        AdmissionError::KeyPackageExpired(s)
    } else {
        AdmissionError::KeyPackageInvalid(s)
    }
}

fn roster_endpoints(g: &MlsGroup) -> Vec<RosterEntry> {
    g.members()
        .filter_map(|m| {
            CredentialBinding::claimed_endpoint(&m.credential).map(|e| (e, m.signature_key.clone()))
        })
        .collect()
}

fn revoked_after(revoked: &[EndpointKey], op: &JournalOp) -> Vec<EndpointKey> {
    let mut r = revoked.to_vec();
    if let JournalOp::Remove { subject } = op
        && !r.contains(subject)
    {
        r.push(*subject);
    }
    r.sort();
    r
}

/// Recompute the resulting-state digest of a merged group from its own
/// members, verifying every binding.
fn merged_digest(
    grp: &MlsGroup,
    group_tag: &Hash,
    revoked: &[EndpointKey],
) -> Result<Hash, String> {
    let mut roster = vec![];
    for m in grp.members() {
        let ep = CredentialBinding::verify_credential(&m.credential, &m.signature_key, group_tag)
            .map_err(|e| format!("successor binding: {e:?}"))?;
        roster.push((ep, m.signature_key.clone()));
    }
    roster.sort();
    Ok(state_digest(
        grp.public_group().group_context(),
        &roster,
        revoked,
    ))
}

/// Outcome of validating a remote slot in a copy of the accepted file.
enum Validated {
    Advance {
        file: String,
        head: Hash,
        epoch: u64,
        revoked: Vec<EndpointKey>,
        author_leaf: u32,
        op: OpSummary,
    },
    SelfRemoved {
        file: String,
        author_leaf: u32,
    },
}

enum Step {
    Advanced(Advance),
    Removed(Advance),
    Stale,
    Stop(Stop),
}

/// Ordering point for applying membership changes. `run` executes `f` (the
/// short, local validation and promotion of one slot; never a mailbox wait)
/// while holding whatever orders service starts, and must end the sessions
/// for every advance `f` reports as durably applied before returning, even
/// if `f` then fails.
///
/// A gate can close (its runtime is stopping). A closed gate runs nothing:
/// `run` returns `None` without calling `f`, so no slot is applied, no
/// write is handed off and no outcome is recorded after it closed, and
/// `admits` turns false so no new mailbox read starts.
pub trait Gate {
    fn run<R>(&self, f: impl FnOnce(&mut Vec<Advance>) -> R) -> Option<R>;
    /// Whether new mailbox work may start. Checked before every read; every
    /// handoff and apply also happens inside `run`.
    fn admits(&self) -> bool;
}

/// No ordering: plain membership use without live sessions.
pub struct NoGate;

impl Gate for NoGate {
    fn run<R>(&self, f: impl FnOnce(&mut Vec<Advance>) -> R) -> Option<R> {
        Some(f(&mut Vec::new()))
    }

    fn admits(&self) -> bool {
        true
    }
}

/// See `Device::member_view`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberView {
    pub endpoint: EndpointKey,
    /// `None` before joining and after own removal.
    pub group_tag: Option<Hash>,
    pub terminal: bool,
    /// Bound endpoint keys of the accepted roster (verified at admission).
    pub roster: Vec<EndpointKey>,
    /// Removed endpoints in the authenticated group state.
    pub revoked: Vec<EndpointKey>,
    /// Local cutoffs recorded by `revoke`.
    pub local_cutoffs: Vec<EndpointKey>,
}

impl MemberView {
    /// Why `peer` is not a current, uncut member, if anything.
    pub fn ineligible(&self, peer: &EndpointKey) -> Option<&'static str> {
        if self.terminal || self.group_tag.is_none() {
            return Some("this device is not a current member");
        }
        if peer == &self.endpoint {
            return Some("this device itself");
        }
        if self.local_cutoffs.contains(peer) {
            return Some("locally cut off");
        }
        if self.revoked.contains(peer) {
            return Some("removed from the network");
        }
        if !self.roster.contains(peer) {
            return Some("not in the accepted roster");
        }
        None
    }
}

// ------------------------------------------------------------------ device

pub struct Device<M: Mailbox> {
    store: Store,
    mailbox: M,
    clock: Clock,
}

impl<M: Mailbox> Device<M> {
    // ------------------------------------------------------ construction

    pub fn open(dir: &Path, mailbox: M, clock: Clock) -> Result<Self, Error> {
        let store = Store::open(dir)?;
        let d = Self {
            store,
            mailbox,
            clock,
        };
        let g = d.store.lock()?;
        let _: State = d.store.load(&g)?;
        Ok(d)
    }

    /// First device: initialize the group and pin its checkpoint.
    pub fn create_network(
        dir: &Path,
        endpoint: &EndpointSecret,
        relay_key: [u8; 32],
        incarnation: Vec<u8>,
        mailbox: M,
        clock: Clock,
    ) -> Result<Self, Error> {
        Self::create_network_named(dir, endpoint, relay_key, incarnation, mailbox, clock, None)
    }

    /// `create_network`, with this device's display name (see
    /// `binding::check_device_name`) signed into its credential, up to
    /// `binding::SIGNED_NAME_BYTES`.
    pub fn create_network_named(
        dir: &Path,
        endpoint: &EndpointSecret,
        relay_key: [u8; 32],
        incarnation: Vec<u8>,
        mailbox: M,
        clock: Clock,
        name: Option<&str>,
    ) -> Result<Self, Error> {
        check_name_arg(name)?;
        if incarnation.len() != 32 {
            return Err(Error::Internal(
                "the relay storage incarnation must be 32 bytes".into(),
            ));
        }
        let (store, g) = Store::create(dir, &State::new(endpoint.public()))?;
        versions::enroll_name(store.dir(), name).map_err(internal("device name"))?;
        let file = store.new_mls_file(&g, "epoch")?;
        let group_tag: Hash = random();
        let group_id = random::<16>().to_vec();
        let (mls_key, head) = store.with_mls(&g, &file, true, |p, _| {
            let s = SignatureKeyPair::new(SignatureScheme::ED25519)
                .map_err(internal("signature key"))?;
            s.store(p.storage())
                .map_err(internal("store signature key"))?;
            let binding = CredentialBinding::create_named(
                endpoint,
                &group_tag,
                s.public(),
                name.map(signed_name),
            )
            .map_err(internal("binding"))?;
            let cred = CredentialWithKey {
                credential: binding.credential(),
                signature_key: s.public().into(),
            };
            let grp = MlsGroup::new_with_group_id(
                p,
                &s,
                &create_config(),
                GroupId::from_slice(&group_id),
                cred,
            )
            .map_err(internal("create group"))?;
            let head = genesis_head(
                &group_tag,
                &relay_key,
                &incarnation,
                grp.public_group().group_context(),
            );
            Ok::<_, Error>((s.public().to_vec(), head))
        })?;
        store.update(&g, |st: &mut State| {
            st.net = Some(Network {
                group_tag,
                group_id,
                relay_key,
                incarnation,
                mls_file: file,
                mls_key,
                head,
                epoch: 0,
                accepted: vec![],
                revoked: vec![],
            });
            Ok::<_, Error>(())
        })?;
        drop(g);
        Ok(Self {
            store,
            mailbox,
            clock,
        })
    }

    /// Joiner: persist the pending endpoint, exact KeyPackage, its private
    /// state and the exact encrypted request before returning the request.
    pub fn begin_join(
        dir: &Path,
        endpoint: &EndpointSecret,
        invite: &[u8],
        mailbox: M,
        clock: Clock,
    ) -> Result<(Self, Vec<u8>), Error> {
        Self::begin_join_named(dir, endpoint, invite, mailbox, clock, None)
    }

    /// `begin_join`, with this device's display name signed into the
    /// credential of its KeyPackage. The name travels only inside the
    /// encrypted request and MLS state.
    pub fn begin_join_named(
        dir: &Path,
        endpoint: &EndpointSecret,
        invite: &[u8],
        mailbox: M,
        clock: Clock,
        name: Option<&str>,
    ) -> Result<(Self, Vec<u8>), Error> {
        check_name_arg(name)?;
        let token = InviteToken::decode(invite)
            .map_err(|e| Error::Join(JoinError::Malformed(format!("invite: {e:?}"))))?;
        let (store, g) = if super::store::initialized(dir) {
            let store = Store::open(dir)?;
            let guard = store.lock()?;
            let state: State = store.load(&guard)?;
            if state.endpoint != endpoint.public()
                || state.net.is_some()
                || state.terminal.is_some()
                || state.halt.is_some()
                || state.pending_join.is_some()
            {
                return Err(Error::Busy("profile already initialized".into()));
            }
            (store, guard)
        } else {
            Store::create(dir, &State::new(endpoint.public()))?
        };
        // Saved before the pending join, which a restart resumes without the name.
        versions::enroll_name(store.dir(), name).map_err(internal("device name"))?;
        let file = store.new_mls_file(&g, "join")?;
        let now = clock.now();
        let (mls_key, kp_bytes, kp_ref) = store.with_mls(&g, &file, true, |p, _| {
            let s = SignatureKeyPair::new(SignatureScheme::ED25519)
                .map_err(internal("signature key"))?;
            s.store(p.storage())
                .map_err(internal("store signature key"))?;
            let binding = CredentialBinding::create_named(
                endpoint,
                &token.group_tag,
                s.public(),
                name.map(signed_name),
            )
            .map_err(internal("binding"))?;
            let cred = CredentialWithKey {
                credential: binding.credential(),
                signature_key: s.public().into(),
            };
            let bundle = KeyPackage::builder()
                .key_package_lifetime(Lifetime::init(
                    now.saturating_sub(60),
                    now + KEY_PACKAGE_LIFETIME_SECS,
                ))
                .build(CIPHERSUITE, p, &s, cred)
                .map_err(internal("key package"))?;
            let kp = bundle.key_package();
            let kp_bytes = kp
                .tls_serialize_detached()
                .map_err(internal("encode key package"))?;
            let kp_ref = kp
                .hash_ref(p.crypto())
                .map_err(internal("key package ref"))?
                .as_slice()
                .to_vec();
            Ok::<_, Error>((s.public().to_vec(), kp_bytes, kp_ref))
        })?;
        let transcript = JoinTranscript {
            group_tag: token.group_tag,
            relay_key: token.relay_key,
            incarnation: token.incarnation.clone(),
            issuer_endpoint: token.issuer_endpoint,
            issuer_mls_key: token.issuer_mls_key.clone(),
            invite_id: token.invite_id,
            joiner_endpoint: endpoint.public(),
            key_package_ref: kp_ref.clone(),
            request_nonce: random(),
        };
        let proof = transcript.sign(endpoint);
        let request = token.seal_request(&JoinRequest {
            transcript: transcript.clone(),
            proof: proof.clone(),
            key_package: kp_bytes.clone(),
        });
        store.update(&g, |st: &mut State| {
            st.pending_join = Some(PendingJoin {
                token: invite.to_vec(),
                mls_file: file,
                mls_key,
                transcript: transcript.encode(),
                proof,
                key_package: kp_bytes,
                key_package_ref: kp_ref,
                request: request.clone(),
                last_failure: None,
                halted: None,
            });
            Ok::<_, Error>(())
        })?;
        drop(g);
        Ok((
            Self {
                store,
                mailbox,
                clock,
            },
            request,
        ))
    }

    pub fn state(&self) -> Result<State, Error> {
        let g = self.store.lock()?;
        Ok(self.store.load(&g)?)
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn mailbox(&self) -> &M {
        &self.mailbox
    }

    /// Exact bytes of the pending join request, for retransmission.
    pub fn join_request(&self) -> Result<Vec<u8>, Error> {
        let st = self.state()?;
        Ok(st
            .pending_join
            .ok_or(Error::Join(JoinError::NoPendingJoin))?
            .request)
    }

    fn halt(&self, g: &Guard, h: Halt) -> Result<(), Error> {
        self.store.update(g, |st: &mut State| {
            if st.halt.is_none() {
                st.halt = Some(h);
            }
            Ok::<_, Error>(())
        })
    }

    /// Process an authenticated `WrongIncarnation` from the relay pinned as
    /// `pin` (relay key, incarnation). The halt is persisted whenever that
    /// relay and incarnation are still pinned, independent of any head,
    /// journal or halt change since the request started. Returns the halt in
    /// force, or `None` if the pin itself changed (nothing to apply).
    fn authenticated_mismatch(
        &self,
        g: &Guard,
        pin: &Pin,
        detail: &str,
    ) -> Result<Option<Halt>, Error> {
        let st: State = self.store.load(g)?;
        if !st.pins(&pin.relay_key, &pin.incarnation) {
            return Ok(None);
        }
        self.halt(
            g,
            Halt::IncarnationMismatch {
                detail: detail.into(),
            },
        )?;
        let st: State = self.store.load(g)?;
        Ok(st.halt)
    }

    fn stale(&self, g: &Guard) -> Result<(), Error> {
        self.store.update(g, |st: &mut State| {
            st.stats.stale_reads += 1;
            Ok::<_, Error>(())
        })
    }

    // ------------------------------------------------------------- clock

    /// Record the issuer clock in its own transaction (kept even if the
    /// operation that observed it fails) and return the nondecreasing
    /// effective time. A step back beyond the tolerance refuses new live
    /// decisions; a tolerated step back uses the high-water mark, so it can
    /// never reopen a window.
    fn observe_clock(&self, g: &Guard) -> Result<u64, Error> {
        let raw = self.clock.now();
        let hw = self.store.update(g, |st: &mut State| {
            if raw > st.clock_high_water {
                st.clock_high_water = raw;
            }
            Ok::<_, Error>(st.clock_high_water)
        })?;
        if raw.saturating_add(CLOCK_ROLLBACK_TOLERANCE_SECS) < hw {
            return Err(AdmissionError::ClockRollback {
                now: raw,
                high_water: hw,
            }
            .into());
        }
        Ok(hw.max(raw))
    }

    // ------------------------------------------------------------ issuer

    fn token_for(st: &State, inv: &IssuedInvite) -> Result<InviteToken, Error> {
        let net = st.net()?;
        let keys = InviteKeys::from_seeds(&inv.ack_seed, &inv.reply_seed);
        Ok(InviteToken {
            group_tag: net.group_tag,
            relay_key: net.relay_key,
            incarnation: net.incarnation.clone(),
            issuer_endpoint: st.endpoint,
            issuer_mls_key: net.mls_key.clone(),
            invite_id: inv.invite_id,
            secret: inv.secret,
            queue_ack_key: keys.ack_pub(),
            reply_key: keys.reply_pub(),
        })
    }

    /// The issuer's own current authority: an active, unhalted member whose
    /// leaf binding names this endpoint and MLS key.
    fn check_own_authority(&self, g: &Guard, st: &State) -> Result<(), Error> {
        let net = st.writable().map_err(|e| match e {
            Error::Halted(h) => {
                AdmissionError::IssuerNotAuthorized(format!("halted: {h:?}")).into()
            }
            other => other,
        })?;
        self.store.with_mls(g, &net.mls_file, false, |p, _| {
            let grp = load_group(p, &net.group_id)?;
            let own = grp.own_leaf_node().ok_or_else(|| {
                Error::from(AdmissionError::IssuerNotAuthorized("no own leaf".into()))
            })?;
            let ep = CredentialBinding::verify_credential(
                own.credential(),
                own.signature_key().as_slice(),
                &net.group_tag,
            )
            .map_err(|e| AdmissionError::IssuerNotAuthorized(format!("own binding: {e:?}")))?;
            if ep != st.endpoint || own.signature_key().as_slice() != net.mls_key.as_slice() {
                return Err(AdmissionError::IssuerNotAuthorized(
                    "own leaf names another key".into(),
                )
                .into());
            }
            Ok(())
        })
    }

    fn members(&self, g: &Guard, net: &Network) -> Result<Vec<RosterEntry>, Error> {
        self.store.with_mls(g, &net.mls_file, false, |p, _| {
            Ok::<_, Error>(roster_endpoints(&load_group(p, &net.group_id)?))
        })
    }

    /// Why `joiner` may not be admitted now, if anything.
    fn joiner_ineligible(
        &self,
        g: &Guard,
        st: &State,
        joiner: &EndpointKey,
    ) -> Result<Option<String>, Error> {
        let net = st.net()?;
        if net.revoked.contains(joiner) {
            return Ok(Some("endpoint is revoked".into()));
        }
        if st.local_cutoffs.contains(joiner) {
            return Ok(Some("endpoint is locally cut off".into()));
        }
        if self.members(g, net)?.iter().any(|(e, _)| e == joiner) {
            return Ok(Some("endpoint is already a member".into()));
        }
        Ok(None)
    }

    /// Durably pre-issue a ten-minute invite and return the bearer token.
    pub fn issue_invite(&self) -> Result<Vec<u8>, Error> {
        let g = self.store.lock()?;
        let now = self.observe_clock(&g)?;
        let st: State = self.store.load(&g)?;
        self.check_own_authority(&g, &st)?;
        let inv = IssuedInvite {
            invite_id: random(),
            secret: random(),
            not_before: now,
            expires_at: now + INVITE_WINDOW_SECS,
            reservation: None,
            admitted_slot: None,
            ack_seed: random(),
            reply_seed: random(),
            queue_cursor: 0,
            unacked: vec![],
        };
        let token = Self::token_for(&st, &inv)?;
        self.store.update(&g, |st: &mut State| {
            st.invites.push(inv);
            Ok::<_, Error>(())
        })?;
        Ok(token.encode())
    }

    /// Joiner: append the exact persisted sealed request to the invite's request queue, signed
    /// with the invite's append key. An exact retry is the same item; only the issuer's reply
    /// settles anything. No lock is held while the relay answers.
    pub fn send_join_request(&self) -> Result<CreateOutcome, Error> {
        let (pj, token) = self.pending_join()?;
        let pin = token.pin();
        let header = token
            .prepare_request(&pj.request)
            .map_err(|e| Error::Internal(format!("request append proof: {}", e.0)))?;
        let r = self
            .mailbox
            .start_append(
                &pin,
                QueueAppend {
                    header,
                    bytes: pj.request.clone(),
                },
            )
            .wait();
        if r == Err(MailboxError::WrongIncarnation) {
            self.halt_join(&pj, &token, "request append: wrong incarnation")?;
        }
        r.map_err(Error::Mailbox)
    }

    /// Issuer: process every invite's request queue incrementally. Each item is judged by the
    /// same local rules as any request (verified content, this issuer's clock and window, the
    /// one-use reservation); relay order never establishes authority. The verdict's progress is
    /// made durable before the item is terminally acknowledged, and an acknowledgement whose
    /// outcome is unknown is retried later without holding up other items.
    pub fn poll_join_requests(&self) -> Result<Vec<Polled>, Error> {
        self.poll_join_requests_gated(&NoGate)
    }

    /// `poll_join_requests` through `gate`: no queue read or acknowledgement starts once the
    /// gate stops admitting, and every verdict, cursor and acknowledgement is recorded inside
    /// `run`. An acknowledgement whose outcome arrives after the gate closed stays pending.
    pub fn poll_join_requests_gated<G: Gate>(&self, gate: &G) -> Result<Vec<Polled>, Error> {
        let invites: Vec<[u8; 16]> = self.state()?.invites.iter().map(|i| i.invite_id).collect();
        let mut out = vec![];
        for invite_id in invites {
            if !gate.admits() {
                break;
            }
            self.poll_invite(gate, &invite_id, &mut out)?;
        }
        Ok(out)
    }

    fn poll_invite<G: Gate>(
        &self,
        gate: &G,
        invite_id: &[u8; 16],
        out: &mut Vec<Polled>,
    ) -> Result<(), Error> {
        // Acknowledgements an earlier poll left pending are retried once, and reported.
        let st = self.state()?;
        let pin = st.net()?.pin();
        let inv = st
            .invites
            .iter()
            .find(|i| &i.invite_id == invite_id)
            .ok_or(AdmissionError::UnknownInvite)?;
        let keys = InviteKeys::from_seeds(&inv.ack_seed, &inv.reply_seed);
        let queue = Self::token_for(&st, inv)?.request_queue();
        for item in inv.unacked.clone() {
            let ack = self.ack_request(gate, invite_id, &pin, &keys, queue, item)?;
            out.push(Polled {
                invite_id: *invite_id,
                seq: None,
                verdict: Verdict::Retried { item },
                ack,
            });
        }
        loop {
            let st = self.state()?;
            let pin = st.net()?.pin();
            let inv = st
                .invites
                .iter()
                .find(|i| &i.invite_id == invite_id)
                .cloned()
                .ok_or(AdmissionError::UnknownInvite)?;
            let read = keys
                .read(&pin, queue, inv.queue_cursor)
                .map_err(|e| Error::Internal(format!("queue read proof: {}", e.0)))?;
            if !gate.admits() {
                return Ok(());
            }
            let item = match self.mailbox.next_item(&pin, read) {
                Ok(Some(item)) => item,
                Ok(None) => return Ok(()),
                Err(MailboxError::WrongIncarnation) => {
                    let halted = gate.run(|_| -> Result<Option<Halt>, Error> {
                        let g = self.store.lock()?;
                        self.authenticated_mismatch(&g, &pin, "queue read")
                    });
                    return match halted.ok_or(Error::Cancelled)?? {
                        Some(h) => Err(Error::Halted(h)),
                        None => Err(Error::Busy("relay pin changed during the read".into())),
                    };
                }
                Err(error) => {
                    out.push(Polled {
                        invite_id: *invite_id,
                        seq: None,
                        verdict: Verdict::Unavailable(error),
                        ack: AckState::NotNeeded,
                    });
                    return Ok(());
                }
            };
            let (id, bytes) = match &item.body {
                QueueBody::Bytes(bytes) => (sha256(bytes), Some(bytes.as_slice())),
                QueueBody::Damaged { item } => (*item, None),
            };
            // Judged and recorded inside the gate: nothing is recorded once it has closed.
            let judged = gate.run(|_| -> Result<Option<Verdict>, Error> {
                let verdict = if item.acked {
                    Verdict::AlreadyAcknowledged
                } else if let Some(bytes) = bytes {
                    match self.receive_join_request(invite_id, bytes) {
                        Ok(r) => Verdict::Reserved(r),
                        // These depend on this issuer's own state, not the item: try again later.
                        Err(Error::Admission(
                            a @ (AdmissionError::ClockRollback { .. }
                            | AdmissionError::NotYetValid { .. }
                            | AdmissionError::IssuerNotAuthorized(_)),
                        )) => {
                            out.push(Polled {
                                invite_id: *invite_id,
                                seq: Some(item.seq),
                                verdict: Verdict::Deferred(a),
                                ack: AckState::NotNeeded,
                            });
                            return Ok(None);
                        }
                        Err(Error::Admission(a)) => Verdict::Rejected(a),
                        Err(e) => return Err(e),
                    }
                } else {
                    // Nothing can be judged from a damaged body, so the invite is not consumed;
                    // the item is recorded past and acknowledged like any other terminal verdict.
                    Verdict::Damaged
                };
                // The verdict is durable (a reservation, or nothing to keep); record the cursor
                // and the pending acknowledgement together before acknowledging.
                let g = self.store.lock()?;
                self.store.update(&g, |st: &mut State| {
                    let i = st
                        .invites
                        .iter_mut()
                        .find(|i| &i.invite_id == invite_id)
                        .ok_or(Error::Internal("invite vanished".into()))?;
                    i.queue_cursor = i.queue_cursor.max(item.seq);
                    if !item.acked && !i.unacked.contains(&id) {
                        i.unacked.push(id);
                    }
                    Ok::<_, Error>(())
                })?;
                Ok(Some(verdict))
            });
            let verdict = match judged {
                None => return Ok(()),
                Some(judged) => match judged? {
                    None => return Ok(()),
                    Some(verdict) => verdict,
                },
            };
            let ack = if item.acked {
                AckState::NotNeeded
            } else {
                self.ack_request(gate, invite_id, &pin, &keys, queue, id)?
            };
            out.push(Polled {
                invite_id: *invite_id,
                seq: Some(item.seq),
                verdict,
                ack,
            });
        }
    }

    /// Terminally acknowledge one request item, forgetting it once the relay confirms.
    fn ack_request<G: Gate>(
        &self,
        gate: &G,
        invite_id: &[u8; 16],
        pin: &Pin,
        keys: &InviteKeys,
        queue: QueueKeys,
        item: [u8; 32],
    ) -> Result<AckState, Error> {
        let header = keys
            .ack(pin, queue, item)
            .map_err(|e| Error::Internal(format!("queue ack proof: {}", e.0)))?;
        let Some(started) = gate.run(|_| self.mailbox.start_ack(pin, header)) else {
            return Ok(AckState::Unconfirmed(MailboxError::NotStored(
                "the runtime is stopping; nothing was sent".into(),
            )));
        };
        let outcome = match started.wait() {
            Ok(outcome) => outcome,
            Err(MailboxError::WrongIncarnation) => {
                let halted = gate.run(|_| -> Result<Option<Halt>, Error> {
                    let g = self.store.lock()?;
                    self.authenticated_mismatch(&g, pin, "queue ack")
                });
                return match halted.ok_or(Error::Cancelled)?? {
                    Some(h) => Err(Error::Halted(h)),
                    None => Err(Error::Busy("relay pin changed during the ack".into())),
                };
            }
            Err(error) => return Ok(AckState::Unconfirmed(error)),
        };
        if outcome == AckOutcome::NoSuchItem {
            // Absent from this view is not acknowledged: keep it pending.
            return Ok(AckState::NoSuchItem);
        }
        let recorded = gate.run(|_| -> Result<(), Error> {
            let g = self.store.lock()?;
            self.store.update(&g, |st: &mut State| {
                if let Some(i) = st.invites.iter_mut().find(|i| &i.invite_id == invite_id) {
                    i.unacked.retain(|u| *u != item);
                }
                Ok::<_, Error>(())
            })
        });
        match recorded {
            Some(recorded) => recorded?,
            // Recorded by the relay, not here: it stays pending and is retried (an exact retry).
            None => {
                return Ok(AckState::Unconfirmed(MailboxError::Uncertain(format!(
                    "the runtime stopped before recording {outcome:?}"
                ))));
            }
        }
        Ok(AckState::Confirmed(outcome))
    }

    /// Validate an encrypted join request and durably reserve the invite for
    /// the first valid one. Purely local; never touches the mailbox.
    pub fn receive_join_request(
        &self,
        invite_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<ReserveOutcome, Error> {
        let g = self.store.lock()?;
        let st: State = self.store.load(&g)?;
        let inv = st
            .invites
            .iter()
            .find(|i| &i.invite_id == invite_id)
            .cloned()
            .ok_or(AdmissionError::UnknownInvite)?;
        let token = Self::token_for(&st, &inv)?;
        let req = token
            .open_request(bytes)
            .map_err(|e| AdmissionError::MalformedRequest(format!("{e:?}")))?;
        let digest = req.transcript.digest();
        // Exact retransmit: answered from the durable reservation, before any
        // clock or window check, and without renewing anything.
        if let Some(r) = &inv.reservation {
            if r.request_digest == digest
                && r.key_package == req.key_package
                && r.proof == req.proof
            {
                return Ok(if inv.admitted_slot.is_some() {
                    ReserveOutcome::AlreadyAdmitted {
                        reserved_at: r.reserved_at,
                    }
                } else {
                    ReserveOutcome::ExactRetry {
                        reserved_at: r.reserved_at,
                    }
                });
            }
            return Err(AdmissionError::AlreadyUsed.into());
        }
        let now = self.observe_clock(&g)?;
        self.check_own_authority(&g, &st)?;
        if now < inv.not_before {
            return Err(AdmissionError::NotYetValid {
                now,
                not_before: inv.not_before,
            }
            .into());
        }
        if now >= inv.expires_at {
            return Err(AdmissionError::Expired {
                now,
                expires_at: inv.expires_at,
            }
            .into());
        }
        let net = st.net()?;
        let t = &req.transcript;
        if t.group_tag != net.group_tag
            || t.relay_key != net.relay_key
            || t.incarnation != net.incarnation
            || t.issuer_endpoint != st.endpoint
            || t.issuer_mls_key != net.mls_key
            || &t.invite_id != invite_id
        {
            return Err(AdmissionError::InviteMismatch(
                "request transcript names another invite".into(),
            )
            .into());
        }
        t.verify(&req.proof)
            .map_err(|e| AdmissionError::ProofInvalid(e.0))?;
        let kp = KeyPackageIn::tls_deserialize_exact(&req.key_package)
            .map_err(|e| AdmissionError::KeyPackageInvalid(format!("{e:?}")))?
            .validate_with_lifetime_policy(
                &crypto(),
                ProtocolVersion::Mls10,
                LeafNodeLifetimePolicy::VerifyAt(now),
            )
            .map_err(kp_error)?;
        if kp.ciphersuite() != CIPHERSUITE {
            return Err(AdmissionError::KeyPackageInvalid("ciphersuite".into()).into());
        }
        let lt = kp.life_time();
        if lt.not_after() < lt.not_before()
            || lt.not_after() - lt.not_before() > KEY_PACKAGE_MAX_LIFETIME_SECS
            || !lt.has_acceptable_range()
        {
            return Err(AdmissionError::KeyPackageLifetimeTooLong.into());
        }
        let ln = kp.leaf_node();
        let ep = CredentialBinding::verify_credential(
            ln.credential(),
            ln.signature_key().as_slice(),
            &net.group_tag,
        )
        .map_err(|e| AdmissionError::BindingInvalid(format!("{e:?}")))?;
        if ep != t.joiner_endpoint {
            return Err(AdmissionError::BindingInvalid(
                "KeyPackage is bound to another endpoint".into(),
            )
            .into());
        }
        let kp_ref = kp
            .hash_ref(&crypto())
            .map_err(internal("key package ref"))?;
        if kp_ref.as_slice() != t.key_package_ref.as_slice() {
            return Err(AdmissionError::InviteMismatch(
                "transcript names another KeyPackage".into(),
            )
            .into());
        }
        if let Some(why) = self.joiner_ineligible(&g, &st, &t.joiner_endpoint)? {
            return Err(AdmissionError::Ineligible(why).into());
        }
        let reservation = Reservation {
            request_digest: digest,
            joiner: t.joiner_endpoint,
            transcript: t.encode(),
            proof: req.proof.clone(),
            key_package: req.key_package.clone(),
            key_package_ref: t.key_package_ref.clone(),
            reserved_at: now,
        };
        self.store.update(&g, |st: &mut State| {
            let i = st
                .invites
                .iter_mut()
                .find(|i| &i.invite_id == invite_id)
                .ok_or(Error::Internal("invite vanished".into()))?;
            if i.reservation.is_some() {
                return Err(AdmissionError::AlreadyUsed.into());
            }
            i.reservation = Some(reservation);
            Ok::<_, Error>(())
        })?;
        Ok(ReserveOutcome::Reserved { reserved_at: now })
    }

    // ------------------------------------------------------------- stage

    /// Stage the Add for a reserved invite: requires the reserved KeyPackage
    /// to still be valid at the issuer's effective time.
    pub fn stage_add(&self, invite_id: &[u8; 16]) -> Result<SlotId, Error> {
        let g = self.store.lock()?;
        self.stage_locked(
            &g,
            StageKind::Add {
                invite_id: *invite_id,
            },
            None,
        )
    }

    pub fn stage_remove(&self, subject: &EndpointKey) -> Result<SlotId, Error> {
        let g = self.store.lock()?;
        self.stage_locked(&g, StageKind::Remove { subject: *subject }, None)
    }

    /// Stage a local cutoff that the accepted history has not applied yet.
    pub fn stage_pending_removal(&self) -> Result<Option<SlotId>, Error> {
        let g = self.store.lock()?;
        let st: State = self.store.load(&g)?;
        if st.journal.is_some() || st.local_cutoffs.is_empty() {
            return Ok(None);
        }
        let net = st.writable()?;
        let roster = self.members(&g, net)?;
        let subject = st
            .local_cutoffs
            .iter()
            .find(|key| roster.iter().any(|(member, _)| member == *key) && **key != st.endpoint);
        subject
            .map(|subject| self.stage_locked(&g, StageKind::Remove { subject: *subject }, None))
            .transpose()
    }

    #[cfg(test)]
    pub(crate) fn stage_adversarial(
        &self,
        invite_id: Option<[u8; 16]>,
        remove: Option<EndpointKey>,
        adv: Adversary,
    ) -> Result<SlotId, Error> {
        let g = self.store.lock()?;
        let kind = match (invite_id, remove) {
            (Some(i), _) => StageKind::Add { invite_id: i },
            (None, Some(s)) => StageKind::Remove { subject: s },
            _ => panic!("nothing to stage"),
        };
        self.stage_locked(&g, kind, Some(&adv))
    }

    /// Test-only: an issuer that commits an unreserved request directly,
    /// optionally sealing its own reply under `reply_to`.
    #[cfg(test)]
    pub(crate) fn stage_raw_add(
        &self,
        request: &JoinRequest,
        adv: Adversary,
        reply_to: Option<&[u8]>,
    ) -> Result<SlotId, Error> {
        let g = self.store.lock()?;
        let reply_to = reply_to.map(|t| InviteToken::decode(t).expect("token"));
        self.stage_locked(&g, StageKind::RawAdd { request, reply_to }, Some(&adv))
    }

    #[cfg_attr(not(test), allow(unused_variables))]
    fn stage_locked(
        &self,
        g: &Guard,
        kind: StageKind<'_>,
        adv: Option<&Adversary>,
    ) -> Result<SlotId, Error> {
        let st: State = self.store.load(g)?;
        st.writable()?;
        if st.journal.is_some() {
            return Err(Error::Busy("a candidate is already journaled".into()));
        }
        // Admission decisions need a trustworthy clock. A removal does not
        // depend on time, so a rolled-back clock never blocks revocation; it
        // signs the nondecreasing effective time instead.
        let now = match (&kind, self.observe_clock(g)) {
            (_, Ok(t)) => t,
            (
                StageKind::Remove { .. },
                Err(Error::Admission(AdmissionError::ClockRollback { high_water, .. })),
            ) => high_water,
            (_, Err(e)) => return Err(e),
        };
        let st: State = self.store.load(g)?;
        #[cfg(test)]
        let skip_issuer = adv.map(|a| a.skip_issuer_checks).unwrap_or(false);
        #[cfg(not(test))]
        let skip_issuer = false;
        if !skip_issuer {
            self.check_own_authority(g, &st)?;
        }
        let net = st.net()?.clone();

        let add: Option<AddMaterial> = match &kind {
            StageKind::Add { invite_id } => {
                let inv = st
                    .invites
                    .iter()
                    .find(|i| &i.invite_id == invite_id)
                    .ok_or(AdmissionError::UnknownInvite)?;
                if inv.admitted_slot.is_some() {
                    return Err(AdmissionError::AlreadyAdmitted.into());
                }
                let r = inv
                    .reservation
                    .as_ref()
                    .ok_or(AdmissionError::NoReservation)?;
                if !skip_issuer && let Some(why) = self.joiner_ineligible(g, &st, &r.joiner)? {
                    return Err(AdmissionError::Ineligible(why).into());
                }
                let mut d = Dec::new(&r.transcript);
                let transcript =
                    JoinTranscript::decode(&mut d).map_err(internal("stored transcript"))?;
                Some(AddMaterial {
                    kp: r.key_package.clone(),
                    transcript,
                    proof: r.proof.clone(),
                    not_before: inv.not_before,
                    expires_at: inv.expires_at,
                    reserved_at: r.reserved_at,
                    reply_to: Some(Self::token_for(&st, inv)?),
                    reply_seed: Some(inv.reply_seed),
                })
            }
            #[cfg(test)]
            StageKind::RawAdd { request, reply_to } => Some(AddMaterial {
                kp: request.key_package.clone(),
                transcript: request.transcript.clone(),
                proof: request.proof.clone(),
                not_before: now,
                expires_at: now + INVITE_WINDOW_SECS,
                reserved_at: now,
                reply_to: reply_to.clone(),
                // Test path: an invite this issuer did not issue gets a throwaway reply key.
                reply_seed: reply_to.as_ref().map(|t| {
                    st.invites
                        .iter()
                        .find(|i| i.invite_id == t.invite_id)
                        .map_or_else(random, |i| i.reply_seed)
                }),
            }),
            StageKind::Remove { .. } => None,
            #[cfg(not(test))]
            StageKind::Never(_) => None,
        };
        let subject = match &kind {
            StageKind::Remove { subject } => Some(*subject),
            _ => None,
        };

        let journal_id: [u8; 16] = random();
        let cand = self.store.copy_mls(g, &net.mls_file, "cand")?;
        let built = self.store.with_mls(g, &cand, true, |p, conn| {
            self.build_candidate(
                p,
                conn,
                &st,
                &net,
                add.as_ref(),
                subject,
                now,
                &journal_id,
                &cand,
                adv,
            )
        });
        let journal = match built {
            Ok(j) => j,
            Err(e) => {
                self.store.delete_mls(g, &cand)?;
                return Err(e);
            }
        };
        fault::crash("after_candidate_written");
        let slot = journal.slot;
        let r = self.store.update(g, |st: &mut State| {
            let head = st.net()?.head;
            if st.journal.is_some() || head != journal.parent_head {
                return Err(Error::Busy(
                    "state changed while staging; candidate discarded".into(),
                ));
            }
            st.journal = Some(journal);
            Ok(())
        });
        if let Err(e) = r {
            self.store.delete_mls(g, &cand)?;
            return Err(e);
        }
        fault::crash("after_journal");
        Ok(slot)
    }

    /// Build, sign, seal, merge and verify the successor in the candidate
    /// file. The journal is returned only once the merged successor matches
    /// the exact parent, the signed digest and (for a reserved Add) a
    /// complete encrypted reply exists.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(test), allow(unused_variables))]
    fn build_candidate(
        &self,
        p: &MlsProvider<'_>,
        conn: &Connection,
        st: &State,
        net: &Network,
        add: Option<&AddMaterial>,
        subject: Option<EndpointKey>,
        now: u64,
        journal_id: &[u8; 16],
        cand: &str,
        adv: Option<&Adversary>,
    ) -> Result<Journal, Error> {
        #[cfg(test)]
        let dev = adv.cloned().unwrap_or_default();
        let mut grp = load_group(p, &net.group_id)?;
        let s = signer(p, &net.mls_key)?;
        let keys = SlotKeys::derive(&grp, &net.head).map_err(Error::Internal)?;
        let parent_epoch = grp.epoch().as_u64();
        let own_leaf = grp.own_leaf_index().u32();
        let mut adds = vec![];
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut removals = vec![];
        let op = match (add, subject) {
            (Some(a), _) => {
                // Live check at commit time on the issuer clock, distinct from
                // the reservation-time check.
                let kp = KeyPackageIn::tls_deserialize_exact(&a.kp)
                    .map_err(|e| AdmissionError::KeyPackageInvalid(format!("{e:?}")))?
                    .validate_with_lifetime_policy(
                        p.crypto(),
                        ProtocolVersion::Mls10,
                        LeafNodeLifetimePolicy::VerifyAt(now),
                    )
                    .map_err(kp_error)?;
                adds.push(kp);
                #[cfg_attr(not(test), allow(unused_mut))]
                let mut proof = a.proof.clone();
                #[cfg_attr(not(test), allow(unused_mut))]
                let mut reserved_at = a.reserved_at;
                #[cfg(test)]
                {
                    if dev.forge_proof {
                        proof[0] ^= 1;
                    }
                    reserved_at = dev.signed_reserved_at.unwrap_or(reserved_at);
                }
                Op::Add {
                    joiner: a.transcript.joiner_endpoint,
                    invite_not_before: a.not_before,
                    invite_expires_at: a.expires_at,
                    reserved_at,
                    transcript: a.transcript.clone(),
                    proof,
                }
            }
            (None, Some(subject)) => {
                let m = grp
                    .members()
                    .find(|m| {
                        CredentialBinding::claimed_endpoint(&m.credential).as_ref()
                            == Some(&subject)
                    })
                    .ok_or_else(|| Error::Busy("endpoint is not a member".into()))?;
                removals.push(m.index);
                Op::Remove {
                    subject,
                    leaf: m.index.u32(),
                }
            }
            (None, None) => return Err(Error::Internal("stage without material".into())),
        };
        #[cfg(test)]
        if let Some(l) = dev.extra_remove {
            removals.push(LeafNodeIndex::new(l));
        }
        #[cfg(test)]
        let force_path = !dev.no_path;
        #[cfg(not(test))]
        let force_path = true;
        #[cfg(test)]
        let issued_at = dev.signed_issued_at.unwrap_or(now);
        #[cfg(not(test))]
        let issued_at = now;
        let bundle = grp
            .commit_builder()
            .leaf_node_lifetime_policy(LeafNodeLifetimePolicy::VerifyAt(now))
            .force_self_update(force_path)
            .propose_adds(adds)
            .propose_removals(removals)
            .load_psks(p.storage())
            .map_err(internal("psks"))?
            .build(p.rand(), p.crypto(), &s, |_| true)
            .map_err(|e| {
                let s = format!("{e:?}");
                if s.contains("Lifetime") {
                    AdmissionError::KeyPackageExpired(s).into()
                } else {
                    Error::Internal(format!("build commit: {s}"))
                }
            })?
            .stage_commit(p)
            .map_err(internal("stage commit"))?;
        let (commit_out, welcome, _group_info) = bundle.into_contents();
        let commit = commit_out
            .tls_serialize_detached()
            .map_err(internal("encode commit"))?;
        let staged = grp
            .pending_commit()
            .ok_or_else(|| Error::Internal("no pending commit".into()))?;
        let mut t = Transition {
            group_tag: net.group_tag,
            relay_key: net.relay_key,
            incarnation: net.incarnation.clone(),
            parent_head: net.head,
            slot: keys.slot,
            author_leaf: own_leaf,
            author_endpoint: st.endpoint,
            issued_at,
            op,
            commit,
            resulting_digest: [0; 32],
        };
        // The same parent-scoped policy recipients run.
        let view = parent_view(&grp, net);
        let checked = view
            .check_envelope(&t, &keys.slot)
            .and_then(|_| view.check_staged(&t, staged));
        #[cfg(test)]
        let checked = match checked {
            Err(_) if adv.is_some() => Ok(adversarial_checked(&grp, staged, &t, net)),
            c => c,
        };
        let checked = checked
            .map_err(|v| Error::Internal(format!("own candidate violates policy: {v:?}")))?;
        let revoked = checked.revoked.clone();
        t.resulting_digest = checked
            .digest
            .ok_or_else(|| Error::Internal("author self-removal".into()))?;
        #[cfg(test)]
        if dev.tamper_digest {
            t.resulting_digest[0] ^= 1;
        }
        let staged_gc = staged
            .group_context()
            .tls_serialize_detached()
            .map_err(internal("encode context"))?;
        let staged_auth = staged
            .epoch_authenticator()
            .ok_or_else(|| Error::Internal("no staged epoch authenticator".into()))?
            .as_slice()
            .to_vec();
        let signed = t.sign(&s);
        let slot_bytes = keys.seal(&net.incarnation, &signed);
        let new_head = next_head(&net.head, &keys.slot, &slot_bytes, &t.resulting_digest);

        // Detached successor: merge now, in the candidate file only, and
        // check it against the exact parent and signed digest.
        grp.merge_pending_commit(p)
            .map_err(internal("merge candidate"))?;
        #[cfg(test)]
        let verify_successor = adv.is_none();
        #[cfg(not(test))]
        let verify_successor = true;
        if verify_successor {
            if grp.epoch().as_u64() != parent_epoch + 1
                || grp
                    .public_group()
                    .group_context()
                    .tls_serialize_detached()
                    .map_err(internal("gc"))?
                    != staged_gc
                || grp.epoch_authenticator().as_slice() != staged_auth.as_slice()
            {
                return Err(Error::Internal(
                    "merged successor differs from the staged commit".into(),
                ));
            }
            let d = merged_digest(&grp, &net.group_tag, &revoked).map_err(Error::Internal)?;
            if d != t.resulting_digest {
                return Err(Error::Internal(
                    "merged successor differs from the signed digest".into(),
                ));
            }
        }

        let (journal_op, reply) = match (&t.op, add) {
            (
                Op::Add {
                    joiner, transcript, ..
                },
                Some(a),
            ) => {
                let reply = match (&a.reply_to, welcome) {
                    (Some(token), Some(w)) => {
                        let welcome = MlsMessageOut::from_welcome(w, ProtocolVersion::Mls10)
                            .tls_serialize_detached()
                            .map_err(internal("encode welcome"))?;
                        let receipt = Receipt {
                            relay_key: net.relay_key,
                            incarnation: net.incarnation.clone(),
                            group_tag: net.group_tag,
                            issuer_endpoint: st.endpoint,
                            issuer_mls_key: net.mls_key.clone(),
                            invite_id: token.invite_id,
                            request_digest: transcript.digest(),
                            joiner_endpoint: *joiner,
                            key_package_ref: transcript.key_package_ref.clone(),
                            parent_head: net.head,
                            slot: keys.slot,
                            ct_hash: sha256(&slot_bytes),
                            head: new_head,
                            resulting_digest: t.resulting_digest,
                            group_context: staged_gc.clone(),
                            roster: checked.roster.clone(),
                            revoked: revoked.clone(),
                            welcome_hash: sha256(&welcome),
                            epoch_authenticator: grp.epoch_authenticator().as_slice().to_vec(),
                            issued_at: t.issued_at,
                        };
                        let plain = Reply::build(welcome, receipt, &s);
                        let sealed = token.seal_reply(&plain);
                        let seed = add
                            .and_then(|m| m.reply_seed)
                            .ok_or(Error::Internal("no reply key for this invite".into()))?;
                        let header = reply_header(&seed, &net.pin(), &sealed)
                            .map_err(|e| Error::Internal(format!("reply proof: {}", e.0)))?;
                        Some(PendingReply {
                            invite_id: token.invite_id,
                            joiner: *joiner,
                            reply_box: header.slot.to_bytes(),
                            bytes: sealed,
                            reply_key: header.write_key,
                            reply_len: header.len,
                            reply_digest: header.digest,
                            reply_proof: header.proof.to_vec(),
                        })
                    }
                    (Some(_), None) => {
                        return Err(Error::Internal("reserved Add without a Welcome".into()));
                    }
                    (None, _) => None,
                };
                (
                    JournalOp::Add {
                        invite_id: transcript.invite_id,
                        joiner: *joiner,
                    },
                    reply,
                )
            }
            (Op::Remove { subject, .. }, _) => (JournalOp::Remove { subject: *subject }, None),
            _ => return Err(Error::Internal("op without material".into())),
        };
        write_marker(conn, journal_id, true)?;
        let header = keys
            .prepare(&net.pin(), &slot_bytes)
            .map_err(|e| Error::Internal(format!("slot write proof: {}", e.0)))?;
        Ok(Journal {
            id: *journal_id,
            parent_head: net.head,
            parent_epoch,
            parent_mls_file: net.mls_file.clone(),
            candidate_mls_file: cand.to_string(),
            slot: keys.slot,
            write_pub: header.write_key,
            write_proof: header.proof.to_vec(),
            write_len: header.len,
            write_digest: header.digest,
            slot_bytes,
            new_head,
            resulting_digest: t.resulting_digest,
            op: journal_op,
            publish_attempted: false,
            attempt: None,
            last_outcome: None,
            reply,
        })
    }

    /// The journaled candidate holds a usable successor: present, marked for
    /// this journal, merged to parent + 1, matching the signed digest, and a
    /// reserved Add carries its complete encrypted reply.
    fn candidate_ready(&self, g: &Guard, st: &State, j: &Journal) -> Result<(), String> {
        if !self.store.mls_exists(&j.candidate_mls_file) {
            return Err("candidate file missing".into());
        }
        match self.store.candidate_marker(g, &j.candidate_mls_file) {
            Ok(Some((id, true))) if id == j.id => {}
            other => return Err(format!("candidate marker {other:?}")),
        }
        let net = st.net().map_err(|e| format!("{e:?}"))?;
        if let JournalOp::Add { invite_id, .. } = &j.op {
            let reserved = st
                .invites
                .iter()
                .any(|i| &i.invite_id == invite_id && i.reservation.is_some());
            if reserved && j.reply.is_none() {
                return Err("reserved Add without its encrypted reply".into());
            }
        }
        let revoked = revoked_after(&net.revoked, &j.op);
        let r = self
            .store
            .with_mls(g, &j.candidate_mls_file, false, |p, _| {
                let grp = load_group(p, &net.group_id).map_err(|e| StoreError(format!("{e:?}")))?;
                Ok::<_, StoreError>((
                    grp.epoch().as_u64(),
                    merged_digest(&grp, &net.group_tag, &revoked),
                ))
            });
        match r {
            Ok((epoch, Ok(d))) if epoch == j.parent_epoch + 1 && d == j.resulting_digest => Ok(()),
            Ok((epoch, d)) => Err(format!(
                "candidate successor mismatch (epoch {epoch}, digest {d:?})"
            )),
            Err(e) => Err(format!("candidate unreadable: {e}")),
        }
    }

    /// Drop a journaled candidate that was never handed off. Refused once a
    /// handoff happened, because the slot may hold it.
    pub fn abandon_unpublished(&self) -> Result<(), Error> {
        let g = self.store.lock()?;
        let st: State = self.store.load(&g)?;
        let j = st.journal.ok_or(Error::Busy("no candidate".into()))?;
        if j.publish_attempted {
            return Err(Error::Busy(
                "publication was attempted; settle instead".into(),
            ));
        }
        self.drop_journal(&g, &j)
    }

    fn drop_journal(&self, g: &Guard, j: &Journal) -> Result<(), Error> {
        self.store.update(g, |st: &mut State| {
            if st.journal.as_ref().map(|x| x.id) != Some(j.id) {
                return Err(Error::Busy("journal changed".into()));
            }
            st.journal = None;
            st.stats.discarded.push(sha256(&j.slot_bytes));
            Ok(())
        })?;
        self.store.delete_mls(g, &j.candidate_mls_file)?;
        Ok(())
    }

    // ----------------------------------------------------------- publish

    /// Hand the exact journaled bytes to the transport, then wait for the
    /// outcome without the lock. The prepared successor and eligibility are
    /// rechecked first; a refused publication writes nothing.
    pub fn publish(&self) -> Result<CreateOutcome, Error> {
        self.publish_gated(&NoGate)
    }

    /// `publish` through `gate`: the handoff happens inside `run`, so a
    /// closed gate hands nothing off. An outcome that arrives after the gate
    /// closed is returned but not recorded; the journal keeps
    /// `publish_attempted`, so the write still counts as possibly delivered.
    pub fn publish_gated<G: Gate>(&self, gate: &G) -> Result<CreateOutcome, Error> {
        let handoff = gate.run(|_| -> Result<_, Error> {
            let g = self.store.lock()?;
            let mut st: State = self.store.load(&g)?;
            let net = st.writable()?.clone();
            let pin = net.pin();
            self.mailbox.validate_pin(&pin).map_err(Error::Mailbox)?;
            // Taken from this loaded copy, so the ciphertext is moved, never cloned.
            let j = st
                .journal
                .take()
                .ok_or(Error::Busy("no candidate".into()))?;
            if net.head != j.parent_head || net.mls_file != j.parent_mls_file {
                return Err(Error::Busy(
                    "accepted parent moved; settle the candidate".into(),
                ));
            }
            if let Err(why) = self.candidate_ready(&g, &st, &j) {
                if !j.publish_attempted {
                    self.drop_journal(&g, &j)?;
                    return Err(Error::CandidateUnusable(format!(
                        "{why}; dropped before any write"
                    )));
                }
                return Err(Error::CandidateUnusable(format!(
                    "{why}; not written again"
                )));
            }
            if let JournalOp::Add { invite_id, joiner } = &j.op {
                let inv = st.invites.iter().find(|i| &i.invite_id == invite_id);
                if inv.and_then(|i| i.reservation.as_ref()).map(|r| &r.joiner) != Some(joiner) {
                    return Err(AdmissionError::NoReservation.into());
                }
                if let Some(why) = self.joiner_ineligible(&g, &st, joiner)? {
                    return Err(AdmissionError::Ineligible(why).into());
                }
            }
            let header = j
                .write_header(&pin)
                .map_err(|why| Error::CandidateUnusable(format!("{why}; not written")))?;
            let attempt: [u8; 16] = random();
            self.store.update(&g, |st: &mut State| {
                let jj = st
                    .journal
                    .as_mut()
                    .filter(|x| x.id == j.id)
                    .ok_or(Error::Busy("journal changed".into()))?;
                jj.publish_attempted = true;
                jj.attempt = Some(attempt);
                Ok::<_, Error>(())
            })?;
            fault::crash("after_publish_marked");
            let jid = j.id;
            let started = self.mailbox.start_create_slot(
                &pin,
                SlotWrite {
                    header,
                    bytes: j.slot_bytes,
                },
            );
            Ok((started, jid, attempt, pin))
        });
        let (started, jid, attempt, pin) = handoff.ok_or(Error::Cancelled)??;
        let r = started.wait();
        fault::crash("after_slot_write");
        let note = format!("{r:?}");
        let recorded = gate.run(|_| -> Result<(), Error> {
            let g = self.store.lock()?;
            if r == Err(MailboxError::WrongIncarnation) {
                self.authenticated_mismatch(&g, &pin, "slot write")?;
            }
            self.store.update(&g, |st: &mut State| {
                if let Some(j) = st
                    .journal
                    .as_mut()
                    .filter(|j| j.id == jid && j.attempt == Some(attempt))
                {
                    j.last_outcome = Some(note);
                }
                Ok::<_, Error>(())
            })
        });
        if let Some(recorded) = recorded {
            recorded?;
        }
        r.map_err(Error::Mailbox)
    }

    // ------------------------------------------------------------ settle

    /// Decide an own candidate from the configured relay's slot read.
    pub fn settle(&self) -> Result<Settle, Error> {
        self.settle_gated(&NoGate)
    }

    /// `settle`, applying any accepted promotion inside `gate` (see `Gate`).
    pub fn settle_gated<G: Gate>(&self, gate: &G) -> Result<Settle, Error> {
        loop {
            let (anchor, j) = {
                let g = self.store.lock()?;
                let st: State = self.store.load(&g)?;
                let Some(j) = st.journal.clone() else {
                    return Ok(Settle::NoCandidate);
                };
                st.writable()?;
                if !j.publish_attempted
                    && let Err(why) = self.candidate_ready(&g, &st, &j)
                {
                    self.drop_journal(&g, &j)?;
                    return Ok(Settle::Discarded { reason: why });
                }
                (st.anchor().expect("writable member"), j)
            };
            if !gate.admits() {
                return Err(Error::Cancelled);
            }
            let pin = anchor.pin();
            let r = self.mailbox.read_slot(&pin, &j.slot);
            let step = gate.run(|applied| -> Result<Option<Settle>, Error> {
                let g = self.store.lock()?;
                // An authenticated mismatch only needs the same pinned relay and
                // incarnation; slot bytes need the exact parent and journal.
                if r == Err(MailboxError::WrongIncarnation) {
                    return match self.authenticated_mismatch(&g, &pin, "slot read")? {
                        Some(h) => Err(Error::Halted(h)),
                        None => Err(Error::Busy("relay pin changed during the read".into())),
                    };
                }
                let st: State = self.store.load(&g)?;
                if st.anchor().as_ref() != Some(&anchor) {
                    st.writable()?;
                    if st.journal.is_none() {
                        return Ok(Some(Settle::NoCandidate));
                    }
                    self.stale(&g)?;
                    return Ok(None);
                }
                match r {
                    Ok(ReadOutcome::Present(b)) if b == j.slot_bytes => {
                        match self.candidate_ready(&g, &st, &j) {
                            Ok(()) => {
                                self.promote_own(&g, &j, applied)?;
                                Ok(Some(Settle::Accepted))
                            }
                            Err(why) => {
                                let h = Halt::CandidateLost {
                                    slot: j.slot,
                                    reason: why,
                                };
                                self.halt(&g, h.clone())?;
                                Err(Error::Halted(h))
                            }
                        }
                    }
                    Ok(ReadOutcome::Present(b)) => match self.validate_slot(&g, &st, &j.slot, &b) {
                        Ok(v) => {
                            let winner = self.promote_remote(
                                &g,
                                &anchor,
                                Some(&j),
                                &j.slot,
                                &b,
                                v,
                                applied,
                            )?;
                            Ok(Some(Settle::Lost { winner }))
                        }
                        Err(Invalid::Rejected(rej)) => {
                            self.record_rejection(&g, &rej)?;
                            // The slot holds another value: this candidate can
                            // never be accepted. The reservation stays.
                            self.drop_journal(&g, &j)?;
                            Err(Error::Slot(rej))
                        }
                        Err(Invalid::Local(e)) => Err(e),
                    },
                    Ok(ReadOutcome::Absent) => Ok(Some(if j.publish_attempted {
                        Settle::Pending
                    } else {
                        Settle::NotPublished
                    })),
                    Ok(ReadOutcome::Unavailable) => {
                        Err(Error::Unavailable("slot body unavailable".into()))
                    }
                    Err(e) => Err(Error::Mailbox(e)),
                }
            });
            match step.ok_or(Error::Cancelled)?? {
                Some(s) => return Ok(s),
                None => continue,
            }
        }
    }

    /// One transaction: compare exact parent head, file and journal
    /// identity, then switch to the prepared successor file.
    fn promote_own(&self, g: &Guard, j: &Journal, applied: &mut Vec<Advance>) -> Result<(), Error> {
        let epoch = j.parent_epoch + 1;
        self.store.update(g, |st: &mut State| {
            fault::fail("promote")?;
            if st.journal.as_ref().map(|x| x.id) != Some(j.id) {
                return Err(Error::Busy("journal changed; promotion refused".into()));
            }
            if let Some(h) = &st.halt {
                return Err(Error::Halted(h.clone()));
            }
            let net = st.net.as_mut().ok_or(Error::NotMember)?;
            if net.head != j.parent_head || net.mls_file != j.parent_mls_file {
                return Err(Error::Busy(
                    "accepted parent changed; promotion refused".into(),
                ));
            }
            net.mls_file = j.candidate_mls_file.clone();
            net.head = j.new_head;
            net.epoch = epoch;
            net.accepted.push(AcceptedSlot {
                slot: j.slot,
                ct_hash: sha256(&j.slot_bytes),
                head: j.new_head,
                epoch,
            });
            net.revoked = revoked_after(&net.revoked, &j.op);
            if let JournalOp::Add { invite_id, .. } = &j.op {
                if let Some(i) = st.invites.iter_mut().find(|i| &i.invite_id == invite_id) {
                    i.admitted_slot = Some(j.slot);
                }
                if let Some(r) = &j.reply {
                    st.outbox.push(OutboxEntry {
                        reply: r.clone(),
                        admitted_slot: j.slot,
                        status: OutboxStatus::Ready,
                    });
                }
            }
            st.journal = None;
            st.stats.own_merges += 1;
            Ok(())
        })?;
        // Durable now: an own accepted removal is reported to the gate at
        // commit, before cleanup and before any start can poll again.
        if let JournalOp::Remove { subject } = &j.op {
            applied.push(Advance::Advanced {
                epoch,
                author_leaf: OWN_COMMIT,
                op: OpSummary::Remove { subject: *subject },
            });
        }
        fault::crash("after_promote");
        self.store.delete_mls(g, &j.parent_mls_file)?;
        Ok(())
    }

    // ---------------------------------------------------------- validate

    fn record_rejection(&self, g: &Guard, rej: &Rejection) -> Result<(), Error> {
        self.halt(
            g,
            Halt::Rejected {
                class: rej.class,
                slot: rej.slot,
                ct_hash: rej.ct_hash,
                reason: rej.reason.clone(),
            },
        )
    }

    /// Validate a slot against the accepted parent in a fresh copy of the
    /// accepted MLS file. The accepted file and state are never touched.
    fn validate_slot(
        &self,
        g: &Guard,
        st: &State,
        slot: &SlotId,
        bytes: &[u8],
    ) -> Result<Validated, Invalid> {
        let net = st.net().map_err(Invalid::Local)?;
        let copy = self
            .store
            .copy_mls(g, &net.mls_file, "val")
            .map_err(|e| Invalid::Local(e.into()))?;
        let res = self.store.with_mls(
            g,
            &copy,
            true,
            |p, _| -> Result<Result<Validated, Invalid>, StoreError> {
                Ok(self.validate_in(p, st, net, slot, bytes, &copy))
            },
        );
        let out = match res {
            Ok(r) => r,
            Err(e) => Err(Invalid::Local(e.into())),
        };
        if !matches!(out, Ok(Validated::Advance { .. }))
            && let Err(e) = self.store.delete_mls(g, &copy)
        {
            return Err(Invalid::Local(e.into()));
        }
        out
    }

    fn validate_in(
        &self,
        p: &MlsProvider<'_>,
        st: &State,
        net: &Network,
        slot: &SlotId,
        bytes: &[u8],
        copy: &str,
    ) -> Result<Validated, Invalid> {
        let reject = |class, reason: String| {
            Invalid::Rejected(Rejection {
                class,
                slot: *slot,
                ct_hash: sha256(bytes),
                reason,
            })
        };
        let invalid = |reason: String| reject(RejectClass::Invalid, reason);
        let from_violation = |v: Violation| {
            let (c, s) = violation(v);
            reject(c, s)
        };
        let mut grp = load_group(p, &net.group_id).map_err(Invalid::Local)?;
        let keys =
            SlotKeys::derive(&grp, &net.head).map_err(|e| Invalid::Local(Error::Internal(e)))?;
        if &keys.slot != slot {
            return Err(Invalid::Local(Error::Internal(
                "slot is not the accepted head's successor".into(),
            )));
        }
        let plain = keys
            .open(&net.incarnation, bytes)
            .map_err(|e| invalid(format!("envelope: {e:?}")))?;
        let signed =
            Transition::decode_signed(&plain).map_err(|e| invalid(format!("transition: {e:?}")))?;
        let t = signed.transition.clone();
        let author_key = parent_view(&grp, net)
            .check_envelope(&t, slot)
            .map_err(from_violation)?;
        signed.verify(&author_key).map_err(|e| {
            reject(
                RejectClass::VerificationFault,
                format!("author signature: {}", e.0),
            )
        })?;
        let msg = MlsMessageIn::tls_deserialize_exact(&t.commit)
            .map_err(|e| invalid(format!("commit decode: {e:?}")))?;
        let pm = msg
            .try_into_protocol_message()
            .map_err(|e| invalid(format!("commit: {e:?}")))?;
        if !matches!(pm, ProtocolMessage::PublicMessage(_)) {
            return Err(invalid(
                "handshake must be a PublicMessage inside the envelope".into(),
            ));
        }
        if pm.content_type() != ContentType::Commit {
            return Err(invalid("not a commit".into()));
        }
        if pm.group_id().as_slice() != net.group_id.as_slice() || pm.epoch() != grp.epoch() {
            return Err(invalid(
                "MLS group or epoch differs from the accepted parent".into(),
            ));
        }
        // Deterministic historical validation: Add KeyPackage lifetimes are
        // checked at the author's signed commit time.
        let processed = match grp.process_message_with_lifetime_policy(
            p,
            pm,
            LeafNodeLifetimePolicy::VerifyAt(t.issued_at),
        ) {
            Ok(m) => m,
            Err(e) => {
                return Err(match classify(&e) {
                    Ok((c, s)) => reject(c, s),
                    Err(local) => Invalid::Local(local),
                });
            }
        };
        if processed.sender() != &Sender::Member(LeafNodeIndex::new(t.author_leaf)) {
            return Err(invalid(
                "MLS sender differs from the envelope author".into(),
            ));
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(invalid("not a staged commit".into()));
        };
        let checked = parent_view(&grp, net)
            .check_staged(&t, &staged)
            .map_err(from_violation)?;
        if checked.self_removed {
            // Own removal: parent-epoch facts only. OpenMLS cannot verify the
            // resulting confirmation tag for a removed member.
            match &t.op {
                Op::Remove { subject, leaf }
                    if subject == &st.endpoint && *leaf == grp.own_leaf_index().u32() => {}
                _ => {
                    return Err(invalid(
                        "self-removal without a matching signed Remove intent".into(),
                    ));
                }
            }
            return Ok(Validated::SelfRemoved {
                file: copy.to_string(),
                author_leaf: t.author_leaf,
            });
        }
        let digest = checked
            .digest
            .ok_or_else(|| invalid("no resulting digest".into()))?;
        if digest != t.resulting_digest {
            return Err(invalid("resulting state digest mismatch".into()));
        }
        grp.merge_staged_commit(p, *staged)
            .map_err(|e| Invalid::Local(Error::Internal(format!("merge: {e:?}"))))?;
        let op = match &t.op {
            Op::Add { joiner, .. } => OpSummary::Add { joiner: *joiner },
            Op::Remove { subject, .. } => OpSummary::Remove { subject: *subject },
        };
        Ok(Validated::Advance {
            file: copy.to_string(),
            head: next_head(&net.head, slot, bytes, &digest),
            epoch: grp.epoch().as_u64(),
            revoked: checked.revoked,
            author_leaf: t.author_leaf,
            op,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn promote_remote(
        &self,
        g: &Guard,
        anchor: &Anchor,
        discard: Option<&Journal>,
        slot: &SlotId,
        bytes: &[u8],
        v: Validated,
        applied: &mut Vec<Advance>,
    ) -> Result<Advance, Error> {
        let ct_hash = sha256(bytes);
        let (advance, new_file) = match &v {
            Validated::Advance {
                file,
                author_leaf,
                op,
                epoch,
                ..
            } => (
                Advance::Advanced {
                    epoch: *epoch,
                    author_leaf: *author_leaf,
                    op: op.clone(),
                },
                Some(file.clone()),
            ),
            Validated::SelfRemoved { author_leaf, .. } => (
                Advance::SelfRemoved {
                    author_leaf: *author_leaf,
                },
                None,
            ),
        };
        let r = self.store.update(g, |st: &mut State| {
            fault::fail("promote")?;
            if st.anchor().as_ref() != Some(anchor)
                || st.journal.as_ref().map(|j| j.id) != discard.map(|j| j.id)
            {
                return Err(Error::Busy(
                    "accepted parent or journal changed; promotion refused".into(),
                ));
            }
            if let Some(j) = discard {
                st.stats.discarded.push(sha256(&j.slot_bytes));
            }
            st.journal = None;
            let net = st.net.as_mut().expect("anchored");
            match &v {
                Validated::Advance {
                    file,
                    head,
                    epoch,
                    revoked,
                    ..
                } => {
                    net.mls_file = file.clone();
                    net.head = *head;
                    net.epoch = *epoch;
                    net.revoked = revoked.clone();
                    net.accepted.push(AcceptedSlot {
                        slot: *slot,
                        ct_hash,
                        head: *head,
                        epoch: *epoch,
                    });
                    st.stats.remote_merges += 1;
                }
                Validated::SelfRemoved { author_leaf, .. } => {
                    st.terminal = Some(Terminal {
                        author_leaf: *author_leaf,
                        slot: *slot,
                        ct_hash,
                    });
                    for o in st.outbox.iter_mut() {
                        let possibly_sent = matches!(o.status, OutboxStatus::Dispatching { .. });
                        if possibly_sent || o.status == OutboxStatus::Ready {
                            o.status = OutboxStatus::Withheld {
                                reason: "this device was removed".into(),
                                possibly_sent,
                            };
                        }
                    }
                }
            }
            Ok(())
        });
        if let Err(e) = r {
            if let Some(f) = new_file {
                self.store.delete_mls(g, &f)?;
            }
            return Err(e);
        }
        // Durable now: report it to the gate before any cleanup can fail.
        applied.push(advance.clone());
        fault::pause("after_remote_commit");
        fault::crash("after_remote_promote");
        fault::fail("remote_cleanup")?;
        if let Some(j) = discard {
            self.store.delete_mls(g, &j.candidate_mls_file)?;
        }
        if let Validated::SelfRemoved { file, .. } = &v {
            self.store.delete_mls(g, file)?;
        }
        // Erase the superseded epoch (or, on own removal, all group state).
        self.store.delete_mls(g, &anchor.mls_file)?;
        Ok(advance)
    }

    // ---------------------------------------------------------- catch up

    /// Walk forward from the durable accepted head through successor slots.
    /// Each read happens without the lock and is applied only to the exact
    /// parent it was taken for. A stale read is discarded and the walk
    /// continues from the current head.
    pub fn catch_up(&self) -> (Vec<Advance>, Stop) {
        self.catch_up_gated(&NoGate)
    }

    /// `catch_up`, applying each slot's short local validation and promotion
    /// inside `gate`, so the gate can order it against service starts and end
    /// affected sessions before releasing. Mailbox reads stay outside.
    pub fn catch_up_gated<G: Gate>(&self, gate: &G) -> (Vec<Advance>, Stop) {
        let mut out = vec![];
        loop {
            match self.catch_up_step(gate) {
                Ok(Step::Advanced(a)) => out.push(a),
                Ok(Step::Stale) => {}
                Ok(Step::Stop(s)) => return (out, s),
                Ok(Step::Removed(a)) => {
                    out.push(a);
                    return (out, Stop::Terminal);
                }
                Err(e) => return (out, Stop::Failed(e)),
            }
        }
    }

    fn catch_up_step<G: Gate>(&self, gate: &G) -> Result<Step, Error> {
        let (anchor, slot) = {
            let g = self.store.lock()?;
            let st: State = self.store.load(&g)?;
            if st.terminal.is_some() {
                return Ok(Step::Stop(Stop::Terminal));
            }
            if let Some(h) = &st.halt {
                return Ok(Step::Stop(Stop::Halted(h.clone())));
            }
            let net = st.net.clone().ok_or(Error::NotMember)?;
            if st.journal.is_some() {
                drop(g);
                return Ok(match self.settle_gated(gate) {
                    Ok(Settle::Accepted)
                    | Ok(Settle::Discarded { .. })
                    | Ok(Settle::NoCandidate) => Step::Stale,
                    Ok(Settle::Lost { winner }) => Step::Advanced(winner),
                    Ok(_) => Step::Stop(Stop::OwnCandidatePending),
                    Err(Error::Halted(h)) => Step::Stop(Stop::Halted(h)),
                    Err(Error::Slot(r)) => Step::Stop(Stop::Halted(Halt::Rejected {
                        class: r.class,
                        slot: r.slot,
                        ct_hash: r.ct_hash,
                        reason: r.reason,
                    })),
                    Err(Error::Unavailable(s)) => Step::Stop(Stop::Unavailable(s)),
                    Err(Error::Mailbox(e)) => Step::Stop(Stop::Unavailable(format!("{e:?}"))),
                    Err(Error::Cancelled) => Step::Stop(Stop::Cancelled),
                    Err(e) => return Err(e),
                });
            }
            let keys = self.store.with_mls(&g, &net.mls_file, false, |p, _| {
                SlotKeys::derive(&load_group(p, &net.group_id)?, &net.head).map_err(Error::Internal)
            })?;
            (st.anchor().expect("unhalted member"), keys.slot)
        };
        if !gate.admits() {
            return Ok(Step::Stop(Stop::Cancelled));
        }
        let pin = anchor.pin();
        let r = self.mailbox.read_slot(&pin, &slot);
        let applied = gate.run(|applied| {
            let g = self.store.lock()?;
            if r == Err(MailboxError::WrongIncarnation) {
                return Ok(match self.authenticated_mismatch(&g, &pin, "slot read")? {
                    Some(h) => Step::Stop(Stop::Halted(h)),
                    None => Step::Stale,
                });
            }
            let st: State = self.store.load(&g)?;
            if st.anchor().as_ref() != Some(&anchor) {
                self.stale(&g)?;
                return Ok(Step::Stale);
            }
            match r {
                Ok(ReadOutcome::Present(b)) => match self.validate_slot(&g, &st, &slot, &b) {
                    Ok(v) => match self.promote_remote(&g, &anchor, None, &slot, &b, v, applied)? {
                        a @ Advance::SelfRemoved { .. } => Ok(Step::Removed(a)),
                        a => Ok(Step::Advanced(a)),
                    },
                    Err(Invalid::Rejected(rej)) => {
                        self.record_rejection(&g, &rej)?;
                        let st: State = self.store.load(&g)?;
                        Ok(Step::Stop(Stop::Halted(st.halt.expect("recorded halt"))))
                    }
                    Err(Invalid::Local(e)) => Err(e),
                },
                Ok(ReadOutcome::Absent) => Ok(Step::Stop(Stop::UpToDate)),
                Ok(ReadOutcome::Unavailable) => Ok(Step::Stop(Stop::Unavailable(
                    "slot body unavailable".into(),
                ))),
                Err(e) => Ok(Step::Stop(Stop::Unavailable(format!("{e:?}")))),
            }
        });
        applied.unwrap_or(Ok(Step::Stop(Stop::Cancelled)))
    }

    // ---------------------------------------------------------- dispatch

    /// Send accepted-Add replies whose joiner is still eligible. Each entry
    /// is decided and handed off under the lock, then awaited without it.
    /// One entry's conflict or transport failure never blocks the others.
    pub fn dispatch_replies(&self) -> Result<Vec<Dispatch>, Error> {
        self.dispatch_replies_gated(&NoGate)
    }

    /// `dispatch_replies` through `gate`: each decision and handoff happens
    /// inside `run`, and so does recording its outcome. Once the gate is
    /// closed nothing more is handed off; an outcome that arrives afterwards
    /// is not recorded, so its entry stays `Dispatching` (possibly sent) and
    /// is reported as `Unconfirmed`.
    pub fn dispatch_replies_gated<G: Gate>(&self, gate: &G) -> Result<Vec<Dispatch>, Error> {
        enum Next {
            Done,
            Withheld,
            Started(
                [u8; 16],
                [u8; 16],
                super::mailbox::Started<CreateOutcome>,
                Pin,
            ),
        }
        let mut out = vec![];
        let mut seen: Vec<[u8; 16]> = vec![];
        loop {
            let next = gate.run(|_| -> Result<Next, Error> {
                let g = self.store.lock()?;
                let st: State = self.store.load(&g)?;
                let Some(entry) = st
                    .outbox
                    .iter()
                    .find(|o| {
                        matches!(
                            o.status,
                            OutboxStatus::Ready | OutboxStatus::Dispatching { .. }
                        ) && !seen.contains(&o.reply.invite_id)
                    })
                    .cloned()
                else {
                    return Ok(Next::Done);
                };
                let invite_id = entry.reply.invite_id;
                seen.push(invite_id);
                let possibly_sent = matches!(entry.status, OutboxStatus::Dispatching { .. });
                if let Some(reason) = self.dispatch_ineligible(&g, &st, &entry)? {
                    self.set_outbox(
                        &g,
                        &invite_id,
                        None,
                        OutboxStatus::Withheld {
                            reason: reason.clone(),
                            possibly_sent,
                        },
                    )?;
                    out.push(Dispatch::Withheld {
                        invite_id,
                        reason,
                        possibly_sent,
                    });
                    return Ok(Next::Withheld);
                }
                // Local preflight, before anything is marked: an adapter that cannot serve this
                // pin sends nothing, and the entry keeps whatever it already established.
                let pin = st.net()?.pin();
                if let Err(error) = self.mailbox.validate_pin(&pin) {
                    out.push(Dispatch::NotAttempted { invite_id, error });
                    return Ok(Next::Withheld);
                }
                let header = match entry.reply.checked_header(&pin) {
                    Ok(header) => header,
                    Err(why) => {
                        // This record can never be sent as stored; the others still can.
                        let reason = format!("malformed local reply record: {why}");
                        self.set_outbox(
                            &g,
                            &invite_id,
                            None,
                            OutboxStatus::Withheld {
                                reason: reason.clone(),
                                possibly_sent,
                            },
                        )?;
                        out.push(Dispatch::Withheld {
                            invite_id,
                            reason,
                            possibly_sent,
                        });
                        return Ok(Next::Withheld);
                    }
                };
                let attempt: [u8; 16] = random();
                self.set_outbox(&g, &invite_id, None, OutboxStatus::Dispatching { attempt })?;
                fault::crash("after_dispatch_marked");
                let started = self.mailbox.start_put_reply(
                    &pin,
                    SlotWrite {
                        header,
                        bytes: entry.reply.bytes,
                    },
                );
                Ok(Next::Started(invite_id, attempt, started, pin))
            });
            let (invite_id, attempt, started, pin) = match next {
                None => return Ok(out),
                Some(next) => match next? {
                    Next::Done => return Ok(out),
                    Next::Withheld => continue,
                    Next::Started(i, a, s, p) => (i, a, s, p),
                },
            };
            let r = started.wait();
            let note = format!("{r:?}");
            let recorded = gate.run(|_| -> Result<(), Error> {
                let g = self.store.lock()?;
                // Each outcome is scoped to this entry and this attempt.
                match r {
                    Ok(CreateOutcome::Created | CreateOutcome::ExactRetry) => {
                        fault::crash("after_reply_put");
                        // Handed off before any later cutoff: it counts as sent.
                        self.set_outbox(&g, &invite_id, Some(attempt), OutboxStatus::Sent)?;
                        out.push(Dispatch::Sent { invite_id });
                    }
                    Ok(CreateOutcome::Conflict) => {
                        self.set_outbox(&g, &invite_id, Some(attempt), OutboxStatus::Conflicted)?;
                        out.push(Dispatch::Conflicted { invite_id });
                    }
                    Ok(CreateOutcome::Unavailable) => {
                        self.set_outbox(&g, &invite_id, Some(attempt), OutboxStatus::Unavailable)?;
                        out.push(Dispatch::Unavailable { invite_id });
                    }
                    Err(MailboxError::Refused(reason)) => {
                        let status = OutboxStatus::Refused {
                            reason: reason.clone(),
                        };
                        self.set_outbox(&g, &invite_id, Some(attempt), status)?;
                        out.push(Dispatch::Refused { invite_id, reason });
                    }
                    Err(MailboxError::WrongIncarnation) => {
                        // The entry stays `Dispatching`: the handoff happened.
                        if let Some(h) = self.authenticated_mismatch(&g, &pin, "reply write")? {
                            return Err(Error::Halted(h));
                        }
                    }
                    // Unknown delivery: stays `Dispatching`. A later dispatch
                    // rechecks eligibility and resends the exact bytes.
                    // Known not stored, or storage could not answer: equally unresolved here, and
                    // kept distinct in the reported error.
                    Err(
                        error @ (MailboxError::Uncertain(_)
                        | MailboxError::NotStored(_)
                        | MailboxError::StorageUnavailable(_)
                        | MailboxError::Mispinned(_)),
                    ) => out.push(Dispatch::Unconfirmed { invite_id, error }),
                }
                Ok(())
            });
            match recorded {
                Some(recorded) => recorded?,
                None => {
                    // Stopping: the handoff happened, its outcome is not
                    // recorded, and the entry stays `Dispatching`.
                    out.push(Dispatch::Unconfirmed {
                        invite_id,
                        error: MailboxError::Uncertain(format!(
                            "runtime stopped before recording {note}"
                        )),
                    });
                    return Ok(out);
                }
            }
        }
    }

    fn dispatch_ineligible(
        &self,
        g: &Guard,
        st: &State,
        entry: &OutboxEntry,
    ) -> Result<Option<String>, Error> {
        if st.terminal.is_some() {
            return Ok(Some("this device was removed".into()));
        }
        if let Some(h) = &st.halt {
            return Ok(Some(format!("membership halted: {h:?}")));
        }
        let net = st.net()?;
        if !net.accepted.iter().any(|a| a.slot == entry.admitted_slot) {
            return Ok(Some("admitting slot is not in the accepted chain".into()));
        }
        let joiner = &entry.reply.joiner;
        if net.revoked.contains(joiner) {
            return Ok(Some("joiner was removed".into()));
        }
        if st.local_cutoffs.contains(joiner) {
            return Ok(Some("joiner is locally cut off".into()));
        }
        if !self.members(g, net)?.iter().any(|(e, _)| e == joiner) {
            return Ok(Some("joiner is no longer a member".into()));
        }
        Ok(None)
    }

    /// Set an entry's status; with `attempt`, only while that attempt is
    /// still the entry's current one.
    fn set_outbox(
        &self,
        g: &Guard,
        invite_id: &[u8; 16],
        attempt: Option<[u8; 16]>,
        status: OutboxStatus,
    ) -> Result<(), Error> {
        self.store.update(g, |st: &mut State| {
            for o in st
                .outbox
                .iter_mut()
                .filter(|o| &o.reply.invite_id == invite_id)
            {
                match attempt {
                    Some(a) if o.status != (OutboxStatus::Dispatching { attempt: a }) => {}
                    _ => o.status = status.clone(),
                }
            }
            Ok::<_, Error>(())
        })
    }

    // ------------------------------------------------------------ revoke

    /// Durably record a local cutoff only (no MLS staging). Purely local.
    pub fn record_cutoff(&self, endpoint: &EndpointKey) -> Result<(), Error> {
        let g = self.store.lock()?;
        self.store.update(&g, |st: &mut State| {
            if !st.local_cutoffs.contains(endpoint) {
                st.local_cutoffs.push(*endpoint);
            }
            Ok::<_, Error>(())
        })
    }

    /// Persist the local cutoff first, then stage the network removal if
    /// this device can. Purely local; never waits for the mailbox.
    pub fn revoke(&self, endpoint: &EndpointKey) -> Result<RevokeOutcome, Error> {
        let g = self.store.lock()?;
        self.store.update(&g, |st: &mut State| {
            if !st.local_cutoffs.contains(endpoint) {
                st.local_cutoffs.push(*endpoint);
            }
            Ok::<_, Error>(())
        })?;
        let removal = match self.stage_locked(&g, StageKind::Remove { subject: *endpoint }, None) {
            Ok(slot) => Ok(slot),
            Err(e) => Err(format!("{e:?}")),
        };
        Ok(RevokeOutcome {
            local_cutoff: true,
            removal,
        })
    }

    // ----------------------------------------------------------- recover

    /// Restart entry point: delete unreferenced MLS copies. Copies other
    /// than the journaled candidate and the accepted epoch exist only while
    /// the lock is held, so nothing deleted here belongs to a live
    /// operation. A terminal profile keeps no group MLS state at all.
    /// Welcome dispatch is not resumed here; `dispatch_replies` rechecks
    /// eligibility first.
    pub fn recover(&self) -> Result<Recovered, Error> {
        let g = self.store.lock()?;
        let st: State = self.store.load(&g)?;
        let mut keep = vec![];
        if st.terminal.is_none() {
            if let Some(n) = &st.net {
                keep.push(n.mls_file.clone());
            }
            if let Some(j) = &st.journal {
                keep.push(j.candidate_mls_file.clone());
            }
        }
        if let Some(p) = &st.pending_join {
            keep.push(p.mls_file.clone());
        }
        let mut rep = Recovered::default();
        for f in self.store.mls_files(&g)? {
            if !keep.contains(&f) {
                self.store.delete_mls(&g, &f)?;
                rep.swept.push(f);
            }
        }
        Ok(rep)
    }

    // ------------------------------------------------------------- audit

    /// Re-read every accepted slot (without the lock) and compare with its
    /// stored hash. Needs no MLS keys. A different value quarantines; an
    /// authenticated incarnation mismatch halts.
    pub fn audit_accepted(&self) -> Result<(), Error> {
        let (pin, accepted) = {
            let st = self.state()?;
            let net = st.net()?;
            (net.pin(), net.accepted.clone())
        };
        for a in &accepted {
            let r = self.mailbox.read_slot(&pin, &a.slot);
            let g = self.store.lock()?;
            if r == Err(MailboxError::WrongIncarnation) {
                return match self.authenticated_mismatch(&g, &pin, "audit read")? {
                    Some(h) => Err(Error::Halted(h)),
                    None => Err(Error::Busy("relay pin changed during audit".into())),
                };
            }
            let st: State = self.store.load(&g)?;
            let net = st.net()?;
            if net.pin() != pin || !net.accepted.contains(a) {
                return Err(Error::Busy("profile changed during audit".into()));
            }
            match r {
                Ok(ReadOutcome::Present(b)) if sha256(&b) == a.ct_hash => {}
                Ok(ReadOutcome::Present(b)) => {
                    let evidence = format!(
                        "slot {} accepted with hash {} now served with hash {}",
                        hex(&a.slot),
                        hex(&a.ct_hash),
                        hex(&sha256(&b))
                    );
                    let h = Halt::Quarantined { evidence };
                    self.store.update(&g, |st: &mut State| {
                        // Quarantine takes precedence over a weaker halt.
                        st.halt = Some(h.clone());
                        Ok::<_, Error>(())
                    })?;
                    return Err(Error::Halted(h));
                }
                Ok(other) => {
                    return Err(Error::Unavailable(format!(
                        "accepted slot {}: {other:?}",
                        hex(&a.slot)
                    )));
                }
                Err(e) => return Err(Error::Mailbox(e)),
            }
        }
        Ok(())
    }

    // -------------------------------------------------------------- join

    /// Joiner: fetch the encrypted reply and the attested slot without the
    /// lock, then accept the Welcome only after checking the issuer receipt,
    /// the exact pending request and KeyPackage, the published slot, the
    /// actual Welcome signer, the selected KeyPackage, every tree binding
    /// and the epoch key confirmation.
    pub fn complete_join(&self) -> Result<(), Error> {
        let (pj, token) = self.pending_join()?;
        let bytes = match self.mailbox.get_reply(&token.pin(), &token.reply_box()) {
            Ok(Some(b)) => b,
            Ok(None) => return Err(JoinError::Waiting.into()),
            Err(MailboxError::WrongIncarnation) => {
                return self.halt_join(&pj, &token, "reply read: wrong incarnation");
            }
            Err(e) => return Err(Error::Mailbox(e)),
        };
        self.join_with(&pj, &token, &bytes)
    }

    /// Test hook: accept specific reply bytes instead of the mailbox copy.
    #[cfg(test)]
    pub(crate) fn complete_join_with(&self, bytes: &[u8]) -> Result<(), Error> {
        let (pj, token) = self.pending_join()?;
        self.join_with(&pj, &token, bytes)
    }

    fn pending_join(&self) -> Result<(PendingJoin, InviteToken), Error> {
        let st = self.state()?;
        let pj = st.pending_join.ok_or(JoinError::NoPendingJoin)?;
        if let Some(h) = &pj.halted {
            return Err(JoinError::Halted(h.clone()).into());
        }
        let token =
            InviteToken::decode(&pj.token).map_err(|e| JoinError::Malformed(format!("{e:?}")))?;
        Ok((pj, token))
    }

    fn halt_join(&self, pj: &PendingJoin, token: &InviteToken, why: &str) -> Result<(), Error> {
        let g = self.store.lock()?;
        self.store.update(&g, |st: &mut State| {
            if let Some(p) = st.pending_join.as_mut().filter(|p| p.same(pj)) {
                p.halted = Some(why.to_string());
            } else if st.pins(&token.relay_key, &token.incarnation) && st.halt.is_none() {
                // Another completion can install the join while this read is in flight.
                st.halt = Some(Halt::IncarnationMismatch { detail: why.into() });
            }
            Ok::<_, Error>(())
        })?;
        Err(JoinError::Halted(why.to_string()).into())
    }

    fn join_with(&self, pj: &PendingJoin, token: &InviteToken, bytes: &[u8]) -> Result<(), Error> {
        let (reply, _slot_bytes) = match self.check_reply(pj, token, bytes) {
            Ok(c) => c,
            Err(Error::Join(JoinError::Halted(why))) => return self.halt_join(pj, token, &why),
            Err(Error::Join(JoinError::InviteUsed)) => return self.discard_used_invite(pj),
            Err(e) => return self.join_failed(pj, e),
        };
        let g = self.store.lock()?;
        let st: State = self.store.load(&g)?;
        // A halt recorded by a concurrent completion (for example an
        // authenticated incarnation mismatch) wins over this result.
        if let Some(e) = join_install_blocked(&st, pj) {
            return Err(e);
        }
        match self.install_join(&g, pj, token, &reply) {
            Ok(()) => Ok(()),
            Err(e) => {
                drop(g);
                self.join_failed(pj, e)
            }
        }
    }

    fn join_failed(&self, pj: &PendingJoin, e: Error) -> Result<(), Error> {
        let g = self.store.lock()?;
        let msg = format!("{e:?}");
        self.store.update(&g, |st: &mut State| {
            if let Some(p) = st.pending_join.as_mut().filter(|p| p.same(pj)) {
                p.last_failure = Some(msg);
            }
            Ok::<_, Error>(())
        })?;
        Err(e)
    }

    fn discard_used_invite(&self, pj: &PendingJoin) -> Result<(), Error> {
        let g = self.store.lock()?;
        // Clear only the exact pending attempt that read the verified receipt.
        self.store.update(&g, |st: &mut State| {
            if let Some(e) = join_install_blocked(st, pj) {
                return Err(e);
            }
            st.pending_join = None;
            Ok(())
        })?;
        self.store.delete_mls(&g, &pj.mls_file)?;
        Err(JoinError::InviteUsed.into())
    }

    /// Checks that need no profile state: reply, receipt bindings and the
    /// attested slot (read without the lock).
    fn check_reply(
        &self,
        pj: &PendingJoin,
        token: &InviteToken,
        bytes: &[u8],
    ) -> Result<(Reply, Vec<u8>), Error> {
        let mismatch = |s: &str| Error::Join(JoinError::Mismatch(s.into()));
        let plain = token.open_reply(bytes).map_err(|e| match e {
            RecordError::Undecryptable => JoinError::ReplyUndecryptable,
            e => JoinError::Malformed(format!("{e:?}")),
        })?;
        let reply = Reply::decode(&plain).map_err(|e| JoinError::Malformed(format!("{e:?}")))?;
        reply
            .verify(&token.issuer_mls_key)
            .map_err(|e| JoinError::VerificationFault(format!("receipt: {}", e.0)))?;
        let r = &reply.receipt;
        let mut d = Dec::new(&pj.transcript);
        let transcript = JoinTranscript::decode(&mut d).map_err(internal("pending transcript"))?;
        if r.relay_key != token.relay_key
            || r.incarnation != token.incarnation
            || r.group_tag != token.group_tag
        {
            return Err(mismatch(
                "receipt names another relay, incarnation or group",
            ));
        }
        if r.issuer_endpoint != token.issuer_endpoint
            || r.issuer_mls_key != token.issuer_mls_key
            || r.invite_id != token.invite_id
        {
            return Err(mismatch("receipt names another issuer or invite"));
        }
        let same_request = r.request_digest == transcript.digest();
        let same_joiner = r.joiner_endpoint == transcript.joiner_endpoint;
        if !same_request && !same_joiner {
            return Err(JoinError::InviteUsed.into());
        }
        if !same_request || !same_joiner {
            return Err(mismatch("receipt is for another request"));
        }
        if r.key_package_ref != pj.key_package_ref {
            return Err(mismatch("receipt selects another KeyPackage"));
        }
        if r.welcome_hash != sha256(&reply.welcome) {
            return Err(mismatch("receipt binds other Welcome bytes"));
        }
        if r.revoked.contains(&transcript.joiner_endpoint) {
            return Err(mismatch("receipt revokes the joiner"));
        }
        // Publication evidence: the configured relay's slot read.
        let slot_bytes = match self.mailbox.read_slot(&token.pin(), &r.slot) {
            Ok(ReadOutcome::Present(b)) => b,
            Ok(other) => return Err(JoinError::SlotUnavailable(format!("{other:?}")).into()),
            Err(MailboxError::WrongIncarnation) => {
                return Err(JoinError::Halted("slot read: wrong incarnation".into()).into());
            }
            Err(e) => return Err(JoinError::SlotUnavailable(format!("{e:?}")).into()),
        };
        if sha256(&slot_bytes) != r.ct_hash {
            return Err(mismatch("published slot differs from the receipt"));
        }
        if next_head(&r.parent_head, &r.slot, &slot_bytes, &r.resulting_digest) != r.head {
            return Err(mismatch("receipt head does not commit to the slot"));
        }
        Ok((reply, slot_bytes))
    }

    fn install_join(
        &self,
        g: &Guard,
        pj: &PendingJoin,
        token: &InviteToken,
        reply: &Reply,
    ) -> Result<(), Error> {
        let mismatch = |s: &str| Error::Join(JoinError::Mismatch(s.into()));
        let r = &reply.receipt;
        let welcome = match MlsMessageIn::tls_deserialize_exact(&reply.welcome)
            .map_err(|e| JoinError::Malformed(format!("welcome: {e:?}")))?
            .extract()
        {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(JoinError::Malformed("not a Welcome".into()).into()),
        };
        if welcome.ciphersuite() != CIPHERSUITE {
            return Err(mismatch("Welcome ciphersuite"));
        }
        if !welcome
            .secrets()
            .iter()
            .any(|s| s.new_member().as_slice() == pj.key_package_ref.as_slice())
        {
            return Err(mismatch(
                "Welcome is not encrypted to the pending KeyPackage",
            ));
        }
        let file = self.store.copy_mls(g, &pj.mls_file, "epoch")?;
        let res = self
            .store
            .with_mls(g, &file, true, |p, _| -> Result<(Vec<u8>, u64), Error> {
                let jb = StagedWelcome::build_from_welcome(p, &join_config(), welcome)
                    .map_err(|e| welcome_err(&e))?;
                let selected = jb
                    .processed_welcome()
                    .own_key_package()
                    .ok_or_else(|| mismatch("no KeyPackage selected"))?;
                if selected
                    .hash_ref(p.crypto())
                    .map_err(internal("kp ref"))?
                    .as_slice()
                    != pj.key_package_ref.as_slice()
                {
                    return Err(mismatch("OpenMLS selected another KeyPackage"));
                }
                let own_kp_leaf = selected.leaf_node().clone();
                // `Skip` applies only to tree-leaf lifetimes in the Welcome. Tree
                // signatures, key uniqueness, GroupInfo, tree hash and the
                // confirmation tag are still verified by OpenMLS.
                let staged = jb
                    .leaf_node_lifetime_policy(LeafNodeLifetimePolicy::Skip)
                    .build()
                    .map_err(|e| welcome_err(&e))?;
                let sender = staged
                    .welcome_sender()
                    .map_err(internal("welcome sender"))?;
                let sender_ep = CredentialBinding::verify_credential(
                    sender.credential(),
                    sender.signature_key().as_slice(),
                    &token.group_tag,
                )
                .map_err(|e| binding_err(&e))?;
                if sender_ep != token.issuer_endpoint
                    || sender.signature_key().as_slice() != token.issuer_mls_key.as_slice()
                {
                    return Err(mismatch(
                        "Welcome signed by another member than the invite issuer",
                    ));
                }
                let own = staged
                    .own_leaf_node()
                    .ok_or_else(|| mismatch("no own leaf"))?;
                if own != &own_kp_leaf || own.signature_key().as_slice() != pj.mls_key.as_slice() {
                    return Err(mismatch("own leaf differs from the pending KeyPackage"));
                }
                let mut roster: Vec<RosterEntry> = vec![];
                for m in staged.members() {
                    let ep = CredentialBinding::verify_credential(
                        &m.credential,
                        &m.signature_key,
                        &token.group_tag,
                    )
                    .map_err(|e| binding_err(&e))?;
                    if roster.iter().any(|(e, _)| e == &ep) {
                        return Err(mismatch("duplicate endpoint in Welcome tree"));
                    }
                    if r.revoked.contains(&ep) {
                        return Err(mismatch("revoked endpoint in Welcome tree"));
                    }
                    roster.push((ep, m.signature_key.clone()));
                }
                roster.sort();
                let mut rr = r.roster.clone();
                rr.sort();
                if roster != rr {
                    return Err(mismatch("Welcome roster differs from the receipt"));
                }
                let gc = staged.group_context();
                if gc.tls_serialize_detached().map_err(internal("gc"))? != r.group_context {
                    return Err(mismatch("Welcome group context differs from the receipt"));
                }
                if state_digest(gc, &roster, &r.revoked) != r.resulting_digest {
                    return Err(mismatch("checkpoint digest mismatch"));
                }
                let group_id = gc.group_id().as_slice().to_vec();
                let epoch = gc.epoch().as_u64();
                let grp = staged.into_group(p).map_err(|e| welcome_err(&e))?;
                if grp.epoch_authenticator().as_slice() != r.epoch_authenticator.as_slice() {
                    return Err(mismatch("epoch key confirmation differs from the receipt"));
                }
                Ok((group_id, epoch))
            });
        let (group_id, epoch) = match res {
            Ok(v) => v,
            Err(e) => {
                self.store.delete_mls(g, &file)?;
                return Err(e);
            }
        };
        let mut revoked = r.revoked.clone();
        revoked.sort();
        let pending_file = pj.mls_file.clone();
        self.store.update(g, |st: &mut State| {
            if let Some(e) = join_install_blocked(st, pj) {
                return Err(e);
            }
            st.pending_join = None;
            st.net = Some(Network {
                group_tag: token.group_tag,
                group_id,
                relay_key: token.relay_key,
                incarnation: token.incarnation.clone(),
                mls_file: file.clone(),
                mls_key: pj.mls_key.clone(),
                head: r.head,
                epoch,
                accepted: vec![AcceptedSlot {
                    slot: r.slot,
                    ct_hash: r.ct_hash,
                    head: r.head,
                    epoch,
                }],
                revoked,
            });
            Ok(())
        })?;
        self.store.delete_mls(g, &pending_file)?;
        Ok(())
    }

    // ------------------------------------------------------- inspection

    /// (group context bytes, epoch authenticator) of the accepted epoch.
    pub fn group_fingerprint(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let g = self.store.lock()?;
        let st: State = self.store.load(&g)?;
        let net = st.net()?;
        self.store.with_mls(&g, &net.mls_file, false, |p, _| {
            let grp = load_group(p, &net.group_id)?;
            Ok((
                grp.public_group()
                    .group_context()
                    .tls_serialize_detached()
                    .map_err(internal("gc"))?,
                grp.epoch_authenticator().as_slice().to_vec(),
            ))
        })
    }

    /// The accepted membership facts peer authorization depends on, read under
    /// the caller's profile lock. Roster names are not part of it: they carry
    /// no authority.
    pub fn member_view(&self, g: &Guard) -> Result<MemberView, Error> {
        let st: State = self.store.load(g)?;
        let mut view = MemberView {
            endpoint: st.endpoint,
            group_tag: None,
            terminal: st.terminal.is_some(),
            roster: vec![],
            revoked: vec![],
            local_cutoffs: st.local_cutoffs.clone(),
        };
        if let (Some(net), None) = (&st.net, &st.terminal) {
            view.group_tag = Some(net.group_tag);
            view.revoked = net.revoked.clone();
            view.roster = self.members(g, net)?.into_iter().map(|(e, _)| e).collect();
            view.roster.sort();
        }
        Ok(view)
    }

    pub fn roster(&self) -> Result<Vec<EndpointKey>, Error> {
        let g = self.store.lock()?;
        let st: State = self.store.load(&g)?;
        let net = st.net()?;
        let mut r: Vec<EndpointKey> = self.members(&g, net)?.into_iter().map(|(e, _)| e).collect();
        r.sort();
        Ok(r)
    }

    /// The accepted roster with each member's signed display name, sorted by
    /// endpoint key. Names are cosmetic: select by `select_peer`, never
    /// authorize by name.
    pub fn named_roster(&self) -> Result<Vec<RosterMember>, Error> {
        let g = self.store.lock()?;
        let st: State = self.store.load(&g)?;
        let net = st.net()?;
        let mut r = self.store.with_mls(&g, &net.mls_file, false, |p, _| {
            Ok::<_, Error>(
                load_group(p, &net.group_id)?
                    .members()
                    .filter_map(|m| CredentialBinding::claimed(&m.credential))
                    .map(|(endpoint, name)| RosterMember { endpoint, name })
                    .collect::<Vec<_>>(),
            )
        })?;
        r.sort_by_key(|m| m.endpoint);
        Ok(r)
    }

    /// Test hook: slot keys of the accepted head (what any current member,
    /// or a removed member at its removal slot, can derive).
    #[cfg(test)]
    pub(crate) fn slot_keys(&self) -> Result<(SlotKeys, Vec<u8>), Error> {
        let g = self.store.lock()?;
        let st: State = self.store.load(&g)?;
        let net = st.net()?;
        let k = self.store.with_mls(&g, &net.mls_file, false, |p, _| {
            SlotKeys::derive(&load_group(p, &net.group_id)?, &net.head).map_err(Error::Internal)
        })?;
        Ok((k, net.incarnation.clone()))
    }
}

/// A display name passed to a named constructor.
fn check_name_arg(name: Option<&str>) -> Result<(), Error> {
    match name.map(super::binding::check_device_name) {
        Some(Err(e)) => Err(Error::Internal(e)),
        _ => Ok(()),
    }
}

// ------------------------------------------------------- display names

/// One accepted member and the display name its own binding signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterMember {
    pub endpoint: EndpointKey,
    pub name: Option<String>,
}

/// How a selector picked a peer. Only `Key` and `Alias` are pinned by this
/// device; a `Name` match is a self-asserted label, so approving by it needs
/// the user to confirm the key's fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerMatch {
    Key(EndpointKey),
    Alias(EndpointKey),
    Name(EndpointKey),
}

impl PeerMatch {
    pub fn endpoint(&self) -> EndpointKey {
        match self {
            PeerMatch::Key(k) | PeerMatch::Alias(k) | PeerMatch::Name(k) => *k,
        }
    }

    /// Whether this device pinned the key (exact key or local alias).
    pub fn pinned(&self) -> bool {
        !matches!(self, PeerMatch::Name(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectError {
    /// No key, local alias or roster name matches.
    NoMatch,
    /// More than one local alias matches (should not happen).
    AmbiguousAlias(Vec<EndpointKey>),
    /// Several roster members carry this name (case-insensitively); name one
    /// by exact key or local alias.
    AmbiguousName(Vec<EndpointKey>),
}

/// Resolve a peer selector, in order of authority: an exact endpoint key
/// (`parsed_key`, parsed by the caller), then a local alias this device
/// pinned, then a display name carried by exactly one accepted roster
/// member. Names compare ASCII case-insensitively, so look-alike case
/// variants count as duplicates. A name never overrides a key or alias.
pub fn select_peer(
    selector: &str,
    parsed_key: Option<EndpointKey>,
    aliases: &[(String, EndpointKey)],
    roster: &[RosterMember],
) -> Result<PeerMatch, SelectError> {
    if let Some(k) = parsed_key {
        return Ok(PeerMatch::Key(k));
    }
    let mut hits: Vec<EndpointKey> = aliases
        .iter()
        .filter(|(a, _)| a == selector)
        .map(|(_, k)| *k)
        .collect();
    hits.sort();
    hits.dedup();
    match hits.as_slice() {
        [k] => return Ok(PeerMatch::Alias(*k)),
        [] => {}
        _ => return Err(SelectError::AmbiguousAlias(hits)),
    }
    let mut hits: Vec<EndpointKey> = roster
        .iter()
        .filter(|m| {
            m.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(selector))
        })
        .map(|m| m.endpoint)
        .collect();
    hits.sort();
    hits.dedup();
    match hits.as_slice() {
        [k] => Ok(PeerMatch::Name(*k)),
        [] => Err(SelectError::NoMatch),
        _ => Err(SelectError::AmbiguousName(hits)),
    }
}

/// Test-only: an adversarial author's own view of its result when it
/// deliberately violates the policy.
#[cfg(test)]
fn adversarial_checked(
    grp: &MlsGroup,
    staged: &StagedCommit,
    t: &Transition,
    net: &Network,
) -> super::policy::Checked {
    let mut r = roster_endpoints(grp);
    if let Op::Add { joiner, .. } = &t.op
        && let Some(kp) = staged.add_proposals().next()
    {
        r.push((
            *joiner,
            kp.add_proposal()
                .key_package()
                .leaf_node()
                .signature_key()
                .as_slice()
                .to_vec(),
        ));
    }
    r.sort();
    let d = state_digest(staged.group_context(), &r, &net.revoked);
    super::policy::Checked {
        roster: r,
        revoked: net.revoked.clone(),
        digest: Some(d),
        self_removed: false,
    }
}

fn parent_view<'a>(grp: &'a MlsGroup, net: &'a Network) -> ParentView<'a> {
    ParentView {
        group: grp,
        group_id: &net.group_id,
        group_tag: &net.group_tag,
        relay_key: &net.relay_key,
        incarnation: &net.incarnation,
        head: &net.head,
        revoked: &net.revoked,
    }
}

fn welcome_err<E: std::fmt::Debug>(e: &E) -> Error {
    let s = format!("{e:?}");
    if s.contains("StorageError") {
        Error::Storage(s)
    } else if s.contains("LibraryError") {
        Error::Internal(s)
    } else if s.contains("Signature") {
        JoinError::VerificationFault(s).into()
    } else {
        JoinError::Welcome(s).into()
    }
}

fn binding_err(e: &super::binding::BindingError) -> Error {
    match e {
        super::binding::BindingError::Signature(s) => {
            JoinError::VerificationFault(format!("binding: {}", s.0)).into()
        }
        other => JoinError::Mismatch(format!("binding: {other:?}")).into(),
    }
}

/// (salt, nonce) of a slot record, for nonce-safety evidence.
pub fn record_salt_nonce(bytes: &[u8]) -> Option<([u8; 32], [u8; 12])> {
    slot_record_salt_nonce(bytes)
}
