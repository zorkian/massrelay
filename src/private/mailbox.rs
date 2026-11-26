//! Boundary to the opaque relay mailbox.
//!
//! This is the only interface the membership state machine uses to reach the
//! relay. It is not an RPC definition. The slot address and write-proof
//! statement are the relay's own (`crate::slot_wire`), shared by the device,
//! the relay verifier and the test fake; there is no second codec.
//!
//! # Outcome contract (what an adapter must report)
//!
//! Every call names the relay identity and storage incarnation the device
//! pinned together (`Pin`). Results are
//! kept distinct, because the device acts on each differently:
//!
//! | Result | Meaning | Device action |
//! | --- | --- | --- |
//! | `Created` / `ExactRetry` | the store durably holds exactly these bytes | slot: **not** publication, acceptance needs an exact read; reply: `Sent` |
//! | `Conflict` | occupied by a different value | slot: settle reads the winner; reply: that entry only becomes `Conflicted` |
//! | `Unavailable` | occupied, body purged; the store cannot compare | slot: unresolved until a read; reply: that entry only becomes `Unavailable` |
//! | `Err(WrongIncarnation)` | authenticated: the store has another incarnation | persisted halt (or join stop) while that relay and incarnation are still pinned, whatever else changed meanwhile |
//! | `Err(Refused)` | definitive protocol refusal of this exact request; nothing was stored by it | slot: recorded, nothing accepted; reply: that entry only becomes `Refused` and is not resent |
//! | `Err(NotStored)` | the store definitely committed nothing for this request, which may succeed if resent | as `Uncertain`, but known not stored: a later attempt rechecks eligibility and resends the exact bytes |
//! | `Err(StorageUnavailable)` | the store could not answer a read | the read is not absence; retry later |
//! | `Err(Mispinned)` | this mailbox is configured for another relay or incarnation; nothing was sent | no relay verdict: nothing halts and nothing is recorded as refused |
//! | `Err(Uncertain)` | delivery unknown (transport failure, lost receipt, timeout chosen by the transport) | slot: may later read as ours; reply: stays `Dispatching`, a later dispatch rechecks eligibility and resends the exact bytes |
//!
//! An adapter must never report `Refused` for a request whose outcome it
//! does not know; that is `Uncertain`. Reads return the exact stored bytes,
//! `Absent` in the store's current view, or `Unavailable` for a purged body;
//! a read failure never implies the slot is unoccupied.
//!
//! # Prepared write and receipt boundary
//!
//! The device prepares every write completely before handoff: the slot id,
//! write public key, write proof and exact ciphertext (`SlotWrite`), or the
//! reply box and exact sealed reply. The adapter never signs, re-encrypts or
//! re-encodes. `start_*` is called under the profile lock, right after the
//! device durably recorded its eligibility decision and attempt id, so it
//! must only enqueue the prepared bytes and return: no network, disk or lock
//! wait. Once it returns, the transport owns the bytes. The receipt arrives
//! through `Started::wait`, which the device calls without the lock and
//! reconciles by attempt id. After handoff, delivery may be unknown and
//! cannot be recalled.
//!
//! Reads (`read_slot`, `get_reply`) may block and are only called without
//! the lock. The device rechecks its exact parent and journal or pending-join
//! identity before applying slot bytes. An authenticated incarnation
//! mismatch is processed whenever the same relay and incarnation are still
//! pinned. No timeout or retry limit is imposed here.

use std::sync::mpsc;

use super::codec::Hash;
use super::envelope::SlotId;
use crate::slot_wire::{AckHeader, AppendHeader, ReadHeader, WriteHeader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    Created,
    ExactRetry,
    /// Occupied by a different value.
    Conflict,
    /// Occupied, body purged: the store cannot tell whose value it was.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    Present(Vec<u8>),
    /// Absent in the configured store's current view.
    Absent,
    /// Body purged by the operator; the slot stays occupied.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxError {
    /// The store authenticated a different incarnation from the pinned one.
    WrongIncarnation,
    /// Definitive protocol refusal of this exact request (bad proof,
    /// framing). Nothing was stored by it; resending the same bytes cannot
    /// succeed.
    Refused(String),
    /// Delivery or outcome unknown.
    Uncertain(String),
    /// The store committed nothing for this exact request; resending may succeed.
    NotStored(String),
    /// The store could not answer a read. Never absence.
    StorageUnavailable(String),
    /// This mailbox is configured for another relay or incarnation than the call's pin, so
    /// nothing was sent. Not a verdict from any relay.
    Mispinned(String),
}

/// The relay identity and storage incarnation a device pinned together. Every call names
/// both; an adapter configured for any other pair sends nothing and reports `Mispinned`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub relay_key: [u8; 32],
    pub incarnation: Vec<u8>,
}

/// One slot write, owned by the transport after handoff: the header the device signed when it
/// staged the candidate (slot, write key, length, digest, proof) and the exact ciphertext.
#[derive(Debug, Clone)]
pub struct SlotWrite {
    pub header: WriteHeader,
    pub bytes: Vec<u8>,
}

impl SlotWrite {
    pub fn slot(&self) -> SlotId {
        self.header.slot.to_bytes()
    }
}

/// A write already handed to the transport.
pub struct Started<T> {
    rx: mpsc::Receiver<Result<T, MailboxError>>,
}

impl<T> Started<T> {
    /// Channel the transport reports on exactly once.
    pub fn channel() -> (mpsc::Sender<Result<T, MailboxError>>, Self) {
        let (tx, rx) = mpsc::channel();
        (tx, Self { rx })
    }

    pub fn done(r: Result<T, MailboxError>) -> Self {
        let (tx, s) = Self::channel();
        let _ = tx.send(r);
        s
    }

    /// Block until the transport reports. Never call with the profile lock.
    /// A transport that ends without reporting is `Uncertain`.
    pub fn wait(self) -> Result<T, MailboxError> {
        self.rx.recv().unwrap_or_else(|_| {
            Err(MailboxError::Uncertain(
                "transport ended without an outcome".into(),
            ))
        })
    }
}

/// One request item for an invite queue, owned by the transport after handoff.
#[derive(Debug, Clone)]
pub struct QueueAppend {
    pub header: AppendHeader,
    pub bytes: Vec<u8>,
}

/// One queue item read back: its relay-assigned order, whether the issuer already recorded its
/// terminal acknowledgement, and its body. Relay order never establishes authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueItem {
    pub seq: u64,
    pub acked: bool,
    pub body: QueueBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueBody {
    /// The exact bytes, verified against the item's identity.
    Bytes(Vec<u8>),
    /// The relay verified that this item's stored body is damaged. Its order and identity are
    /// intact, so a reader can record it and move on; its content is gone.
    Damaged { item: [u8; 32] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    Recorded,
    AlreadyRecorded,
    /// The relay's current view holds no such item. This is not a terminal acknowledgement.
    NoSuchItem,
}

pub trait Mailbox {
    /// Check local adapter configuration without contacting the relay or accessing storage.
    fn validate_pin(&self, pin: &Pin) -> Result<(), MailboxError>;

    /// Nonblocking handoff of a fully prepared immutable slot write.
    /// Moves the prepared header and owned bytes; must not copy or hash the body.
    fn start_create_slot(&self, pin: &Pin, write: SlotWrite) -> Started<CreateOutcome>;
    /// Nonblocking handoff of the issuer's signed immutable reply object.
    fn start_put_reply(&self, pin: &Pin, reply: SlotWrite) -> Started<CreateOutcome>;
    /// Nonblocking handoff of a signed request item for an invite queue.
    fn start_append(&self, pin: &Pin, append: QueueAppend) -> Started<CreateOutcome>;
    /// May block. Never called with the profile lock held.
    fn read_slot(&self, pin: &Pin, slot: &SlotId) -> Result<ReadOutcome, MailboxError>;
    /// May block. Never called with the profile lock held.
    fn get_reply(&self, pin: &Pin, reply_box: &Hash) -> Result<Option<Vec<u8>>, MailboxError>;
    /// The first queue item after the read's cursor. May block; never with the profile lock.
    fn next_item(&self, pin: &Pin, read: ReadHeader) -> Result<Option<QueueItem>, MailboxError>;
    /// Nonblocking handoff of a signed terminal acknowledgement.
    fn start_ack(&self, pin: &Pin, ack: AckHeader) -> Started<AckOutcome>;
    /// Graceful stop seam, called once when the runtime stops (after it has
    /// closed its membership gate, so the device starts nothing new). A
    /// transport should make in-flight and later calls return promptly. A
    /// cancelled read is `Uncertain`. A cancelled write is `Uncertain`, never
    /// `Refused`: once handed off it may have been delivered, and the device
    /// keeps treating it as possibly sent. The default does nothing; calls
    /// already in flight then finish on their own, and the runtime owner is
    /// held until they return.
    fn shutdown(&self) {}
}
