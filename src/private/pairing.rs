//! EXPERIMENTAL private peer authorization: pairing, grants and local cutoff
//! on top of the accepted private membership.
//!
//! # What authorizes a service start
//!
//! All of the following, evaluated by the destination:
//!
//! 1. This device is a current member (removal ends everything; halts do
//!    not: cached verified pairs keep working during relay trouble).
//! 2. The peer's exact endpoint key is in the accepted roster, not removed
//!    from the network and not locally cut off. Roster names, relay replies,
//!    reachability and legacy grants confer nothing.
//! 3. This device approved that exact key under a verified local alias, and
//!    that approval (random value and decision order) is still current.
//! 4. Mutual consent on this completed, authenticated private-ALPN Iroh
//!    connection: both sides exchanged their current decision, approval
//!    value, decision order and a fresh nonce over the connection, then each
//!    confirmed a transcript hash covering the group, both endpoint keys,
//!    the connection's TLS exporter (channel binding), both nonces, both
//!    decisions and both orders. The connection itself authenticates the
//!    sender, so no detached signature is used; nothing proven on one
//!    connection is usable on another. The peer's decision is accepted only
//!    if its order is newer than the last one learned, and the pairing
//!    (both approval values) must still be the recorded one.
//! 5. An explicit grant for this peer, pairing generation and exact service
//!    (protocol and port), or an enabled service default the peer is not
//!    excluded from. The destination chooses the target.
//!
//! Every step is local. A stalled or absent relay never blocks a start,
//! decline or cutoff, and paired peers keep access with no imposed lease.
//!
//! # One owner, one registry, one ordering point
//!
//! `Owner` holds an exclusive runtime lock on the profile for the daemon's
//! lifetime and owns the only `Sessions` registry; `Peers` can only be built
//! from it. Short profile transactions (`membership.lock`) are unaffected.
//!
//! The registry lock is the ordering point between authority and side
//! effects. Every transition (decline, re-approval, cutoff, grant, default
//! and exclusion changes, re-pair, learned removal) takes it, persists, and
//! flags the affected sessions before releasing it. `SessionHandle::start`
//! polls the caller's local initiation future (spawn, connect, bind and
//! first send) only while holding that lock and after re-checking the flag
//! and the connection, releasing it between polls. A start therefore either
//! completes its local initiation step before a transition, or never runs
//! it after. Waiting for remote I/O never happens under the lock. Nothing
//! already started can be recalled.
//!
//! An `Authorization` is itself registered, in the same critical section
//! that commits its exchange, until it is dropped: a peer-level ending
//! (decline, cutoff, removal, re-pair, owner stop) ends it before any
//! request, and `Peers::open` refuses an ended one. `SessionHandle::guard`
//! extends the start rule to every later native write of a session.
//!
//! `Owner::retire` permanently moves the registry to stopping, under its
//! lock: afterwards every transition, cutoff, reconciliation, exchange and
//! open is refused with `Refusal::Stopping`, and the membership gate is
//! closed (no read, handoff, apply or record).
//!
//! A cutoff persists the local cutoff first (only its failure fails the
//! call), flags every session under the registry lock, then saves the
//! declined pairing and finally stages the network removal; `Cutoff`
//! reports the later two separately. An own accepted removal ends its
//! subject's sessions at promotion, before cleanup and reconciliation.
//!
//! # Grants
//!
//! Per-peer grants and service defaults reuse `crate::grants` (`Grants`,
//! `ServiceDefaults`) and `crate::wire::Service`. Grants are keyed by this
//! device's local pairing generation, so a re-pair, decline or re-approval
//! never revives one. Named exclusions are private to this module and
//! persist whether or not the default is enabled.
//!
//! # Exposures
//!
//! `Peers::expose` registers a temporary grant for one approved peer and one
//! exact port. It becomes usable after pairing, optionally with a target this
//! device's owner chose (`wire::check_target`). It reuses
//! `crate::grants::Grants`, but held in the owner's registry, never in the
//! persisted pairing row, so an exposure cannot outlive the runtime owner.
//! A peer holds at most one of a persistent grant or an exposure per service,
//! and an exposure is refused where an enabled default already covers the
//! peer. The returned `Exposure` is the grant: dropping it withdraws exactly
//! that exposure and ends only the sessions opened under it, under the
//! registry lock. Decline, re-approval, re-pair, removal, cutoff, disabling
//! that service for that peer and owner stop withdraw it the same way and
//! wake its holder (`Exposure::ended`).
//!
//! # Daemon responsibilities
//!
//! `service::Node` and `runtime::Runtime` carry these out:
//!
//! - Accept `PAIRING_ALPN` on the private listener and call
//!   `Peers::authorize` with the completed `Connection`; dial peers with the
//!   same ALPN and call it as the dialer. Keep the `Authorization` with that
//!   connection until its final teardown.
//! - Per service request: `Peers::open`, then run the privileged local
//!   initiation inside `SessionHandle::start` (shell spawn; TCP connect; UDP
//!   resolve, then bind, connect and first send for each association), and
//!   end the session when `done` resolves.
//! - Advance membership only through `Peers::advance_membership` and
//!   `Peers::settle`, so each applied removal flags sessions before the next
//!   mailbox wait. Route every local decline, cutoff and grant change through
//!   the owner's `Peers`; a CLI must send them to the runtime, not open the
//!   profile itself.

use std::collections::BTreeMap;
use std::fs::File;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};
use std::sync::{Arc, Condvar, Mutex};
use std::task::Poll;

use fs2::FileExt;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::grants::{GrantInstance, Grants, ServiceDefaults};
use crate::wire::{self, Service};

use super::PROTOCOL;
use super::binding::EndpointKey;
use super::codec::{Dec, DecodeError, Enc, Hash, hash, hex, random, unhex};
use super::mailbox::Mailbox;
use super::membership::{Advance, Device, Gate, MemberView, OpSummary, Settle, Stop};
use super::store::Guard;

pub const PAIRING_FORMAT: &str = "massrelay-private-pairing/experimental-2";
const AUX_NAME: &str = "pairing";
pub const PAIRING_VERSION: u8 = 2;
/// ALPN of the pairing stream on the private service listener.
pub const PAIRING_ALPN: &[u8] = b"massrelay/private-pairing/experimental-2";
/// RFC 5705 exporter label for the 32-byte channel binding.
pub const CHANNEL_BINDING_LABEL: &[u8] = b"EXPORTER-massrelay-private-pairing-experimental-2";
const OFFER: &[u8] = b"massrelay-private pairing-offer";
const CONFIRM: &[u8] = b"massrelay-private pairing-confirm";
const TRANSCRIPT: &[u8] = b"massrelay-private pairing-transcript";
const OWNER_LOCK: &str = "runtime-owner.lock";
const MAX_ALIAS: usize = 64;

// ------------------------------------------------------------------ links

mod sealed {
    pub trait Sealed {}
}

/// The only transports an authorization can come from. Sealed: outside
/// this module it is implemented for a completed Iroh connection only, so
/// no caller can supply an identity, channel binding or liveness of its
/// own. An outgoing 0-RTT connection is a different type and is excluded;
/// an accepted connection is used only after its handshake completed.
pub trait Link: sealed::Sealed + Send + Sync {
    /// The remote endpoint key the transport authenticated.
    fn remote_key(&self) -> EndpointKey;
    /// Channel binding both ends derive identically for this connection.
    fn channel_binding(&self) -> Result<[u8; 32], PairError>;
    fn is_open(&self) -> bool;
    /// Negotiated application protocol.
    fn alpn(&self) -> Vec<u8>;
    /// Resolves when the transport closes (async; no thread parked).
    fn closed(&self) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

impl sealed::Sealed for iroh::endpoint::Connection {}

impl Link for iroh::endpoint::Connection {
    fn remote_key(&self) -> EndpointKey {
        *self.remote_id().as_bytes()
    }

    fn channel_binding(&self) -> Result<[u8; 32], PairError> {
        let mut out = [0u8; 32];
        self.export_keying_material(&mut out, CHANNEL_BINDING_LABEL, b"")
            .map_err(|e| PairError::Local(format!("channel binding: {e:?}")))?;
        Ok(out)
    }

    fn is_open(&self) -> bool {
        self.close_reason().is_none()
    }

    fn alpn(&self) -> Vec<u8> {
        iroh::endpoint::Connection::<iroh::endpoint::HandshakeCompleted>::alpn(self).to_vec()
    }

    fn closed(&self) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let c = self.clone();
        Box::pin(async move {
            let _ = c.closed().await;
        })
    }
}

/// Test-only in-memory link standing in for an authenticated connection.
#[cfg(test)]
pub(crate) struct TestLink {
    pub remote: EndpointKey,
    pub binding: [u8; 32],
    pub open: Arc<std::sync::atomic::AtomicBool>,
    closing: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
impl TestLink {
    pub(crate) fn new(remote: EndpointKey, binding: [u8; 32]) -> Arc<Self> {
        Arc::new(Self {
            remote,
            binding,
            open: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            closing: Arc::default(),
        })
    }

    pub(crate) fn close(&self) {
        self.open.store(false, std::sync::atomic::Ordering::SeqCst);
        self.closing.notify_waiters();
    }
}

#[cfg(test)]
impl sealed::Sealed for TestLink {}

#[cfg(test)]
impl Link for TestLink {
    fn remote_key(&self) -> EndpointKey {
        self.remote
    }
    fn channel_binding(&self) -> Result<[u8; 32], PairError> {
        Ok(self.binding)
    }
    fn is_open(&self) -> bool {
        self.open.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn alpn(&self) -> Vec<u8> {
        PAIRING_ALPN.to_vec()
    }
    fn closed(&self) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let (open, closing) = (self.open.clone(), self.closing.clone());
        Box::pin(async move {
            loop {
                let n = closing.notified();
                let mut n = pin!(n);
                n.as_mut().enable();
                if !open.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                n.await;
            }
        })
    }
}

// ------------------------------------------------------------------ state

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Approved with this fresh random value.
    Approve {
        approval: [u8; 32],
    },
    Decline,
    /// Nothing learned yet (remote side only).
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pairing {
    pub ours: [u8; 32],
    pub theirs: [u8; 32],
    /// Local generation that grants for this pairing are keyed by.
    pub generation: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    pub endpoint: EndpointKey,
    /// Verified local alias. Only a selector; never authority.
    pub alias: String,
    pub local: Decision,
    /// Increases with every local approve or decline of this peer.
    pub local_order: u64,
    /// Newest decision the peer proved on an authenticated connection.
    pub remote: Decision,
    pub remote_order: u64,
    pub pairing: Option<Pairing>,
}

/// Pairing state row of the private profile (experimental format).
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct PairingState {
    /// Group the decisions are scoped to.
    pub group_tag: Option<Hash>,
    /// Last pairing generation handed out; generations are never reused.
    pub last_generation: u64,
    pub peers: Vec<PeerRecord>,
    pub grants: Grants,
    /// Locally granted services waiting for the peer's first confirmed pairing.
    #[serde(default)]
    pub pending_grants: Vec<(EndpointKey, Service)>,
    /// Default enablement only; exclusions live in `exclusions`.
    pub defaults: ServiceDefaults,
    /// Named exclusions from defaults, kept whether or not the default is on.
    pub exclusions: Vec<(EndpointKey, Service)>,
}

impl PairingState {
    pub(super) fn peer(&self, ep: &EndpointKey) -> Option<&PeerRecord> {
        self.peers.iter().find(|p| &p.endpoint == ep)
    }

    fn peer_mut(&mut self, ep: &EndpointKey) -> Option<&mut PeerRecord> {
        self.peers.iter_mut().find(|p| &p.endpoint == ep)
    }

    /// Resolve an exact endpoint key or a locally pinned alias.
    pub(super) fn resolve_selector(&self, selector: &str) -> Result<EndpointKey, String> {
        if let Some(key) = parse_key(selector) {
            return Ok(key);
        }
        let mut hits = self.peers.iter().filter(|p| p.alias == selector);
        match (hits.next(), hits.next()) {
            (Some(p), None) => Ok(p.endpoint),
            (None, _) => Err(format!(
                "no peer pinned as {selector:?} on this device; name it by endpoint key"
            )),
            _ => Err(format!("{selector:?} names more than one pinned peer")),
        }
    }

    fn check_alias_binding(&self, alias: &str, peer: &EndpointKey) -> Result<(), PairError> {
        if let Some(other) = self
            .peers
            .iter()
            .find(|p| p.alias == alias && &p.endpoint != peer)
        {
            return Err(PairError::Alias(format!(
                "alias {alias:?} is bound to {}",
                hex(&other.endpoint)
            )));
        }
        Ok(())
    }

    fn excluded(&self, ep: &EndpointKey, service: Service) -> bool {
        self.exclusions
            .iter()
            .any(|(e, s)| e == ep && *s == service)
    }

    /// Drop every grant whose peer and generation is no longer current.
    fn prune_grants(&mut self) {
        let current: BTreeMap<EndpointId, u64> = self
            .peers
            .iter()
            .filter_map(|p| Some((endpoint_id(&p.endpoint).ok()?, p.pairing?.generation)))
            .collect();
        self.grants
            .retain(|id, generation| current.get(&id) == Some(&generation));
    }
}

fn endpoint_id(ep: &EndpointKey) -> Result<EndpointId, PairError> {
    EndpointId::from_bytes(ep).map_err(|e| PairError::Local(format!("endpoint key: {e}")))
}

// ----------------------------------------------------------------- errors

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// This device was removed from the network.
    Terminal,
    /// The peer is not a current, uncut member (reason attached).
    NotMember(&'static str),
    /// This device has not approved the peer, or declined it.
    NotApproved,
    /// The peer's newest decision is a decline.
    RemoteDeclined,
    /// No current reciprocal pairing for this authorization.
    NotPaired,
    /// The peer presented an older decision than one already learned.
    StaleDecision,
    /// The peer presented a different decision with an order already used.
    ConflictingDecision,
    /// A message does not belong to this exact exchange or connection, or
    /// the local decision changed during it.
    StaleExchange(&'static str),
    WrongGroup,
    WrongProtocol,
    ConnectionClosed,
    ServiceNotGranted,
    /// The runtime owner is stopping; nothing new is authorized or applied.
    Stopping,
    /// The session's authority ended.
    Invalidated(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairError {
    Refused(Refusal),
    Malformed(String),
    Alias(String),
    /// Another runtime owner holds this profile.
    OwnedElsewhere,
    /// Local storage, transport or programming fault; nothing authorized.
    Local(String),
}

impl From<Refusal> for PairError {
    fn from(r: Refusal) -> Self {
        PairError::Refused(r)
    }
}

impl From<super::store::StoreError> for PairError {
    fn from(e: super::store::StoreError) -> Self {
        PairError::Local(e.0)
    }
}

impl From<super::membership::Error> for PairError {
    fn from(e: super::membership::Error) -> Self {
        PairError::Local(format!("membership: {e:?}"))
    }
}

impl From<DecodeError> for PairError {
    fn from(e: DecodeError) -> Self {
        PairError::Malformed(e.0)
    }
}

// ------------------------------------------------------------------ owner

/// Exclusive runtime owner of one private profile, for the daemon's
/// lifetime. It owns the only session registry. A second owner (another
/// process, or a second acquisition in this process) is refused until the
/// first is dropped or its process exits.
pub struct Owner {
    _lock: File,
    dir: PathBuf,
    sessions: Arc<Sessions>,
    /// Distinguishes this owner instance; authorizations are bound to it.
    instance: [u8; 16],
}

impl Owner {
    pub fn acquire(profile_dir: &Path) -> Result<Self, PairError> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(profile_dir.join(OWNER_LOCK))
            .map_err(|e| PairError::Local(format!("owner lock: {e}")))?;
        match f.try_lock_exclusive() {
            Ok(()) => Ok(Self {
                _lock: f,
                dir: profile_dir.to_path_buf(),
                sessions: Arc::default(),
                instance: random(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(PairError::OwnedElsewhere),
            Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
                Err(PairError::OwnedElsewhere)
            }
            Err(e) => Err(PairError::Local(format!("owner lock: {e}"))),
        }
    }

    /// Permanently move this owner to stopping, then retire every session
    /// and negotiation (runtime stop). Both happen under the registry lock,
    /// so this is the linearization point: afterwards no exchange commits,
    /// no service opens or starts, no decision, grant or cutoff is applied
    /// and no gated membership step runs. Idempotent; never undone.
    pub fn retire(&self, why: &str) {
        self.retire_all(why);
    }

    /// Whether `retire` (or drop) has begun. Lock-free.
    pub fn stopping(&self) -> bool {
        self.sessions
            .stopping
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn retire_all(&self, why: &str) {
        let mut reg = match self.sessions.inner.lock() {
            Ok(reg) => reg,
            Err(poisoned) => poisoned.into_inner(),
        };
        if reg.stopping.is_none() {
            reg.stopping = Some(why.into());
        }
        self.sessions
            .stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        reg.flag(&Ending::All(why.into()));
        drop(reg);
        self.sessions.changed.notify_waiters();
    }

    pub fn live_sessions(&self) -> usize {
        self.sessions
            .inner
            .lock()
            .expect("sessions lock")
            .entries
            .len()
    }
}

impl Drop for Owner {
    /// Every session and negotiation ends before the owner lock (a field) is
    /// released, so no session can outlive its owner's authority.
    fn drop(&mut self) {
        self.retire_all("runtime owner stopped");
    }
}

// --------------------------------------------------------------- sessions

#[derive(Default)]
struct Flag {
    reason: Mutex<Option<String>>,
    cv: Condvar,
    /// Wakes async waiters without parking a thread per session.
    notify: tokio::sync::Notify,
}

impl Flag {
    fn set(&self, why: &str) -> bool {
        let mut r = self.reason.lock().expect("flag lock");
        let fresh = r.is_none();
        if fresh {
            *r = Some(why.to_string());
        }
        self.cv.notify_all();
        self.notify.notify_waiters();
        fresh
    }

    fn get(&self) -> Option<String> {
        self.reason.lock().expect("flag lock").clone()
    }
}

struct Entry {
    peer: EndpointKey,
    /// `None` for an authorization's own entry (before or without a
    /// request); `Some` for an opened service session.
    service: Option<Service>,
    generation: u64,
    via_default: bool,
    /// The exposure instance this session was opened under.
    exposure: Option<u64>,
    flag: Arc<Flag>,
}

/// The holder side of one registered exposure.
struct Holder {
    peer: EndpointKey,
    id: EndpointId,
    service: Service,
    generation: u64,
    flag: Arc<Flag>,
}

#[derive(Default)]
struct Registry {
    next: u64,
    entries: BTreeMap<u64, Entry>,
    /// Bumped whenever a peer's local decision, eligibility or pairing ends,
    /// so in-flight negotiations can tell their offer went stale.
    epochs: BTreeMap<EndpointKey, u64>,
    global: u64,
    /// Set once by `Owner::retire`; never cleared.
    stopping: Option<String>,
    /// Live exposures only (never persisted), and their holders by instance.
    exposed: Grants,
    holders: BTreeMap<u64, Holder>,
}

impl Registry {
    fn snapshot(&self, peer: &EndpointKey) -> (u64, u64) {
        (self.epochs.get(peer).copied().unwrap_or(0), self.global)
    }

    fn flag(&mut self, end: &Ending) -> usize {
        match end {
            Ending::Peer(p, _) | Ending::PeerGeneration(p, _, _) => {
                *self.epochs.entry(*p).or_default() += 1
            }
            Ending::All(_) => self.global += 1,
            Ending::PeerService(..)
            | Ending::PeerDefault(..)
            | Ending::Default(..)
            | Ending::Exposure(..) => {}
        }
        let mut n = 0;
        for e in self.entries.values() {
            let hit = match end {
                Ending::Peer(p, _) => &e.peer == p,
                Ending::PeerGeneration(p, g, _) => &e.peer == p && e.generation == *g,
                Ending::PeerService(p, s, _) => &e.peer == p && e.service == Some(*s),
                Ending::PeerDefault(p, s, _) => {
                    e.via_default && &e.peer == p && e.service == Some(*s)
                }
                Ending::Default(s, _) => e.via_default && e.service == Some(*s),
                Ending::Exposure(i, _) => e.exposure == Some(*i),
                Ending::All(_) => true,
            };
            if hit && e.flag.set(end.reason()) {
                n += 1;
            }
        }
        // Exposures the same ending withdraws (their sessions are hit above).
        let ended: Vec<u64> = self
            .holders
            .iter()
            .filter(|(_, h)| match end {
                Ending::Peer(p, _) => &h.peer == p,
                Ending::PeerGeneration(p, g, _) => &h.peer == p && h.generation == *g,
                Ending::PeerService(p, s, _) => &h.peer == p && h.service == *s,
                Ending::All(_) => true,
                Ending::PeerDefault(..) | Ending::Default(..) | Ending::Exposure(..) => false,
            })
            .map(|(i, _)| *i)
            .collect();
        for i in ended {
            self.withdraw(i, end.reason());
        }
        n
    }

    fn bind_exposures(&mut self, peer: &EndpointKey, generation: u64) {
        for (&instance, holder) in &mut self.holders {
            if &holder.peer == peer && holder.generation == 0 {
                self.exposed
                    .bind_exposure(holder.id, holder.service, instance, generation);
                holder.generation = generation;
            }
        }
    }

    /// Withdraw exactly one exposure, wake its holder and end the sessions
    /// opened under it.
    fn withdraw(&mut self, instance: u64, why: &str) {
        if let Some(h) = self.holders.remove(&instance) {
            self.exposed.withdraw(h.id, h.service, instance);
            h.flag.set(why);
            self.flag(&Ending::Exposure(instance, why.into()));
        }
    }

    fn is_exposed(&self, peer: &EndpointKey, service: Service) -> bool {
        self.holders
            .values()
            .any(|h| &h.peer == peer && h.service == service)
    }
}

/// The owner's in-process session registry. Its lock orders transitions
/// against session starts.
#[derive(Default)]
struct Sessions {
    inner: Mutex<Registry>,
    /// Wakes negotiations when any epoch changes.
    changed: tokio::sync::Notify,
    /// Lock-free mirror of `Registry::stopping` (for `Gate::admits`).
    stopping: std::sync::atomic::AtomicBool,
}

/// One authorized session on one connection. Dropping it unregisters it.
pub struct SessionHandle {
    id: u64,
    sessions: Arc<Sessions>,
    flag: Arc<Flag>,
    link: Arc<dyn Link>,
    pub peer: EndpointKey,
    pub service: Service,
    /// Destination-chosen target (`None`: loopback on the service port).
    pub target: Option<String>,
}

impl SessionHandle {
    fn check(&self) -> Result<(), Refusal> {
        if let Some(r) = self.flag.get() {
            return Err(Refusal::Invalidated(r));
        }
        if !self.link.is_open() {
            return Err(Refusal::ConnectionClosed);
        }
        Ok(())
    }

    /// Run the privileged local initiation (spawn, connect, bind, first
    /// send). Each poll happens under the registry lock after re-checking
    /// the session; the lock is released between polls, so a transition
    /// waits at most for one poll and a start never resumes after it.
    /// `start` must not block inside a poll.
    pub async fn start<T>(&self, start: impl Future<Output = T>) -> Result<T, Refusal> {
        let mut start = pin!(start);
        let guarded = std::future::poll_fn(|cx| {
            let reg = self.sessions.inner.lock().expect("sessions lock");
            if let Err(r) = self.check() {
                return Poll::Ready(Err(r));
            }
            let r = start.as_mut().poll(cx).map(Ok);
            drop(reg);
            r
        });
        // A pending start is woken (and dropped) as soon as its authority
        // ends or its connection closes.
        tokio::select! {
            biased;
            r = self.done() => Err(r),
            r = guarded => r,
        }
    }

    /// Resolve when the session ends for any reason: its authority (flag)
    /// or its connection.
    pub async fn done(&self) -> Refusal {
        tokio::select! {
            biased;
            why = self.ended() => Refusal::Invalidated(why),
            _ = self.link.closed() => Refusal::ConnectionClosed,
        }
    }

    /// Synchronous variant for a local step that completes at once.
    pub fn start_now<T>(&self, start: impl FnOnce() -> T) -> Result<T, Refusal> {
        let _reg = self.sessions.inner.lock().expect("sessions lock");
        self.check()?;
        Ok(start())
    }

    /// Current verdict without starting anything.
    pub fn status(&self) -> Result<(), Refusal> {
        self.check()
    }

    /// Wrap a native target so that every write (and the final shutdown) is
    /// handed to the OS only from a poll that holds the registry lock after
    /// re-checking this session. Bytes already handed to the OS cannot be
    /// withdrawn; nothing is handed over after a transition returns.
    pub fn guard<T>(&self, inner: T) -> Guarded<'_, T> {
        Guarded {
            inner,
            session: self,
        }
    }

    pub fn cancelled(&self) -> Option<String> {
        self.flag.get()
    }

    /// Block until the session's authority ends.
    pub fn wait_cancelled(&self) -> String {
        self.wait_blocking()
    }

    /// Resolve when the session's authority ends (async; no thread parked).
    pub async fn ended(&self) -> String {
        loop {
            let notified = self.flag.notify.notified();
            let mut notified = pin!(notified);
            notified.as_mut().enable();
            if let Some(r) = self.flag.get() {
                return r;
            }
            notified.await;
        }
    }

    fn wait_blocking(&self) -> String {
        let mut r = self.flag.reason.lock().expect("flag lock");
        loop {
            if let Some(reason) = r.clone() {
                return reason;
            }
            r = self.flag.cv.wait(r).expect("flag lock");
        }
    }
}

/// See `SessionHandle::guard`.
pub struct Guarded<'s, T> {
    inner: T,
    session: &'s SessionHandle,
}

impl<T> Guarded<'_, T> {
    fn guarded<R>(
        &mut self,
        f: impl FnOnce(Pin<&mut T>) -> Poll<std::io::Result<R>>,
    ) -> Poll<std::io::Result<R>>
    where
        T: Unpin,
    {
        let _reg = self.session.sessions.inner.lock().expect("sessions lock");
        if let Err(r) = self.session.check() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{r:?}"),
            )));
        }
        f(Pin::new(&mut self.inner))
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Guarded<'_, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Guarded<'_, T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.guarded(|t| t.poll_write(cx, buf))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.guarded(|t| t.poll_shutdown(cx))
    }
}

impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHandle")
            .field("id", &self.id)
            .field("peer", &hex(&self.peer))
            .field("service", &self.service)
            .field("cancelled", &self.cancelled())
            .finish()
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        if let Ok(mut reg) = self.sessions.inner.lock() {
            reg.entries.remove(&self.id);
        }
    }
}

// -------------------------------------------------------------- exposures

/// One live exposure (see the module docs). Dropping it withdraws exactly
/// this exposure and ends the sessions opened under it.
pub struct Exposure {
    sessions: Arc<Sessions>,
    instance: u64,
    flag: Arc<Flag>,
    pub peer: EndpointKey,
    /// The alias this device pinned to `peer`.
    pub alias: String,
    pub service: Service,
    /// Owner-chosen target (`None`: loopback on the service port).
    pub target: Option<String>,
}

impl Exposure {
    /// Resolve when this device withdraws the exposure for any reason other
    /// than this handle's drop.
    pub async fn ended(&self) -> String {
        loop {
            let notified = self.flag.notify.notified();
            let mut notified = pin!(notified);
            notified.as_mut().enable();
            if let Some(r) = self.flag.get() {
                return r;
            }
            notified.await;
        }
    }

    pub fn cancelled(&self) -> Option<String> {
        self.flag.get()
    }
}

impl Drop for Exposure {
    fn drop(&mut self) {
        let mut reg = match self.sessions.inner.lock() {
            Ok(reg) => reg,
            Err(poisoned) => poisoned.into_inner(),
        };
        reg.withdraw(self.instance, "the exposure ended");
        drop(reg);
        self.sessions.changed.notify_waiters();
    }
}

impl std::fmt::Debug for Exposure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exposure")
            .field("peer", &hex(&self.peer))
            .field("service", &self.service)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

// --------------------------------------------------------------- messages

/// One side's current decision for one exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Offer {
    group_tag: Hash,
    sender: EndpointKey,
    receiver: EndpointKey,
    nonce: [u8; 32],
    decision: Decision,
    order: u64,
}

impl Offer {
    fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u8(PAIRING_VERSION)
            .bytes(OFFER)
            .bytes(PROTOCOL)
            .fixed(&self.group_tag)
            .fixed(&self.sender)
            .fixed(&self.receiver)
            .fixed(&self.nonce)
            .u64(self.order);
        match &self.decision {
            Decision::Approve { approval } => e.u8(1).fixed(approval),
            Decision::Decline | Decision::Unknown => e.u8(2),
        };
        e.finish()
    }

    fn decode(b: &[u8]) -> Result<Self, PairError> {
        let mut d = Dec::new(b);
        if d.u8()? != PAIRING_VERSION {
            return Err(PairError::Malformed("offer version".into()));
        }
        d.expect_label(OFFER)?;
        d.expect_label(PROTOCOL)?;
        let (group_tag, sender, receiver, nonce, order) =
            (d.fixed()?, d.fixed()?, d.fixed()?, d.fixed()?, d.u64()?);
        let decision = match d.u8()? {
            1 => Decision::Approve {
                approval: d.fixed()?,
            },
            2 => Decision::Decline,
            k => return Err(PairError::Malformed(format!("offer decision {k}"))),
        };
        d.end()?;
        Ok(Self {
            group_tag,
            sender,
            receiver,
            nonce,
            decision,
            order,
        })
    }
}

/// Transcript both sides confirm: everything either side relied on.
fn transcript(group_tag: &Hash, binding: &[u8; 32], a: &Offer, b: &Offer) -> Hash {
    let (first, second) = if a.sender <= b.sender { (a, b) } else { (b, a) };
    hash(
        TRANSCRIPT,
        &[
            PROTOCOL,
            &[PAIRING_VERSION],
            group_tag,
            binding,
            &first.encode(),
            &second.encode(),
        ],
    )
}

fn encode_confirm(t: &Hash) -> Vec<u8> {
    Enc::new()
        .u8(PAIRING_VERSION)
        .bytes(CONFIRM)
        .fixed(t)
        .finish()
}

fn decode_confirm(b: &[u8]) -> Result<Hash, PairError> {
    let mut d = Dec::new(b);
    if d.u8()? != PAIRING_VERSION {
        return Err(PairError::Malformed("confirm version".into()));
    }
    d.expect_label(CONFIRM)?;
    let t = d.fixed()?;
    d.end()?;
    Ok(t)
}

/// Completed mutual consent on one live connection. Not constructible,
/// cloneable or transferable outside this module; valid only while that
/// connection is open and the recorded decisions and pairing still match.
pub struct Authorization {
    owner: [u8; 16],
    /// Registry entry from exchange commit until drop: a decline, cutoff,
    /// removal or owner shutdown ends it even before any request arrives.
    id: u64,
    flag: Arc<Flag>,
    sessions: Arc<Sessions>,
    link: Arc<dyn Link>,
    remote: EndpointKey,
    binding: [u8; 32],
    ours: [u8; 32],
    our_order: u64,
    theirs: [u8; 32],
    their_order: u64,
    generation: u64,
}

impl Drop for Authorization {
    fn drop(&mut self) {
        if let Ok(mut reg) = self.sessions.inner.lock() {
            reg.entries.remove(&self.id);
        }
    }
}

impl Authorization {
    /// Queue one datagram while peer authority is current.
    pub(super) fn while_authorized<T>(&self, send: impl FnOnce() -> T) -> Result<T, Refusal> {
        let _registry = self.sessions.inner.lock().expect("sessions lock");
        self.status()?;
        Ok(send())
    }

    /// Ok while this authorization's authority and connection last.
    pub fn status(&self) -> Result<(), Refusal> {
        if let Some(r) = self.flag.get() {
            return Err(Refusal::Invalidated(r));
        }
        if !self.link.is_open() {
            return Err(Refusal::ConnectionClosed);
        }
        Ok(())
    }

    /// Resolve when the authority ends or the connection closes.
    pub async fn done(&self) -> Refusal {
        self.watch_end().await
    }

    /// Observe cancellation without keeping the registered authorization alive.
    pub(super) fn watch_end(&self) -> impl Future<Output = Refusal> + Send + 'static + use<> {
        let (flag, link) = (self.flag.clone(), self.link.clone());
        async move {
            let ended = async {
                loop {
                    let n = flag.notify.notified();
                    let mut n = pin!(n);
                    n.as_mut().enable();
                    if let Some(r) = flag.get() {
                        return r;
                    }
                    n.await;
                }
            };
            tokio::select! {
                biased;
                why = ended => Refusal::Invalidated(why),
                _ = link.closed() => Refusal::ConnectionClosed,
            }
        }
    }

    pub fn remote(&self) -> EndpointKey {
        self.remote
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    pub(crate) fn approvals(&self) -> ([u8; 32], [u8; 32]) {
        (self.ours, self.theirs)
    }
}

impl std::fmt::Debug for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorization")
            .field("remote", &hex(&self.remote))
            .field("generation", &self.generation)
            .finish()
    }
}

/// One side of the exchange on one link. Each step consumes it, so an
/// exchange completes at most once. Order: send `offer()`, call
/// `on_offer` with the peer's offer and send the returned confirm, then
/// `finish` with the peer's confirm.
pub(in crate::private) struct Exchange<'p, 'd, 'o, M: Mailbox> {
    peers: &'p Peers<'d, 'o, M>,
    link: Arc<dyn Link>,
    binding: [u8; 32],
    mine: Offer,
    /// Registry epochs when the offer was taken.
    snapshot: (u64, u64),
}

/// After the peer's offer was checked.
pub(in crate::private) struct Confirming<'p, 'd, 'o, M: Mailbox> {
    ex: Exchange<'p, 'd, 'o, M>,
    theirs: Offer,
    transcript: Hash,
}

impl<'p, 'd, 'o, M: Mailbox> Exchange<'p, 'd, 'o, M> {
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> (EndpointKey, (u64, u64)) {
        (self.link.remote_key(), self.snapshot)
    }

    pub(in crate::private) fn offer(&self) -> Vec<u8> {
        self.mine.encode()
    }

    pub(in crate::private) fn on_offer(
        self,
        bytes: &[u8],
    ) -> Result<(Confirming<'p, 'd, 'o, M>, Vec<u8>), PairError> {
        let theirs = Offer::decode(bytes)?;
        if theirs.sender != self.link.remote_key() || theirs.receiver != self.mine.sender {
            return Err(Refusal::StaleExchange("offer names another pair").into());
        }
        if theirs.group_tag != self.mine.group_tag {
            return Err(Refusal::WrongGroup.into());
        }
        if theirs.nonce == self.mine.nonce {
            return Err(Refusal::StaleExchange("reflected nonce").into());
        }
        let t = transcript(&self.mine.group_tag, &self.binding, &self.mine, &theirs);
        Ok((
            Confirming {
                ex: self,
                theirs,
                transcript: t,
            },
            encode_confirm(&t),
        ))
    }
}

impl<M: Mailbox> Confirming<'_, '_, '_, M> {
    /// Check the peer's confirmation of the same transcript and record the
    /// result. Consumes the exchange.
    pub(in crate::private) fn finish(self, bytes: &[u8]) -> Result<Authorization, PairError> {
        if decode_confirm(bytes)? != self.transcript {
            return Err(Refusal::StaleExchange("peer confirmed another exchange").into());
        }
        if !self.ex.link.is_open() {
            return Err(Refusal::ConnectionClosed.into());
        }
        self.ex
            .peers
            .commit_exchange(self.ex.link, self.ex.binding, &self.ex.mine, &self.theirs)
    }
}

// ------------------------------------------------------------------ peers

/// Result of `Peers::cutoff`: the durable local cutoff (always applied when
/// this is returned), reported separately from later, independent steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cutoff {
    pub local_cutoff: bool,
    pub pairing_saved: Result<(), String>,
    pub removal: Result<super::envelope::SlotId, String>,
}

/// Result of `Peers::approve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    /// A new approval value was chosen (any earlier pairing ended).
    pub fresh: bool,
}

/// Peer authorization boundary over one private membership profile,
/// usable only through the profile's runtime owner.
pub struct Peers<'d, 'o, M: Mailbox> {
    device: &'d Device<M>,
    owner: &'o Owner,
}

impl<'d, 'o, M: Mailbox> Peers<'d, 'o, M> {
    pub fn new(device: &'d Device<M>, owner: &'o Owner) -> Result<Self, PairError> {
        let same = std::fs::canonicalize(device.store().dir()).ok()
            == std::fs::canonicalize(&owner.dir).ok();
        if !same {
            return Err(PairError::Local("owner holds another profile".into()));
        }
        Ok(Self { device, owner })
    }

    /// Flag the sessions `e` ends and wake negotiations, under the registry
    /// lock the caller holds.
    fn end(&self, reg: &mut Registry, e: &Ending) -> usize {
        let n = reg.flag(e);
        self.owner.sessions.changed.notify_waiters();
        n
    }

    fn registry(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.owner.sessions.inner.lock().expect("sessions lock")
    }

    /// The registry lock, refused once the owner is stopping. Every
    /// transition, cutoff, reconciliation, exchange and open takes it.
    fn running(&self) -> Result<std::sync::MutexGuard<'_, Registry>, PairError> {
        let reg = self.registry();
        if reg.stopping.is_some() {
            return Err(Refusal::Stopping.into());
        }
        Ok(reg)
    }

    /// Run a short local device step (invite issue) only while the owner is
    /// not stopping, ordered against `Owner::retire` by the registry lock.
    pub fn while_running<T>(&self, f: impl FnOnce() -> T) -> Result<T, PairError> {
        let _reg = self.running()?;
        Ok(f())
    }

    fn group_scope(view: &MemberView, st: &PairingState) -> Result<Hash, PairError> {
        if view.terminal {
            return Err(Refusal::Terminal.into());
        }
        let tag = view
            .group_tag
            .ok_or(Refusal::NotMember("this device is not a current member"))?;
        if st.group_tag.is_some_and(|current| current != tag) {
            return Err(Refusal::WrongGroup.into());
        }
        Ok(tag)
    }

    fn scoped(view: &MemberView, st: &mut PairingState) -> Result<(), PairError> {
        st.group_tag = Some(Self::group_scope(view, st)?);
        st.pending_grants
            .retain(|(peer, _)| view.ineligible(peer).is_none());
        Ok(())
    }

    fn read_locked<R>(
        &self,
        g: &Guard,
        f: impl FnOnce(&MemberView, &PairingState) -> Result<R, PairError>,
    ) -> Result<R, PairError> {
        let view = self.device.member_view(g)?;
        let mut st: PairingState = self
            .device
            .store()
            .load_aux(g, AUX_NAME, PAIRING_FORMAT)?
            .unwrap_or_default();
        Self::scoped(&view, &mut st)?;
        f(&view, &st)
    }

    /// Persist under the registry and profile locks, then flag the ended
    /// sessions before releasing the registry lock.
    fn transition<R>(
        &self,
        f: impl FnOnce(&MemberView, &mut PairingState) -> Result<(R, Vec<Ending>), PairError>,
    ) -> Result<R, PairError> {
        self.transition_then(f, |_, r| r)
    }

    /// `transition`, then `then` under the same registry lock (after the
    /// endings are flagged), to register what the transition created.
    fn transition_then<R, T>(
        &self,
        f: impl FnOnce(&MemberView, &mut PairingState) -> Result<(R, Vec<Ending>), PairError>,
        then: impl FnOnce(&mut Registry, R) -> T,
    ) -> Result<T, PairError> {
        self.transition_reg(|_, view, st| f(view, st), then)
    }

    /// `transition_then`, with `f` also reading the registry (held).
    fn transition_reg<R, T>(
        &self,
        f: impl FnOnce(&Registry, &MemberView, &mut PairingState) -> Result<(R, Vec<Ending>), PairError>,
        then: impl FnOnce(&mut Registry, R) -> T,
    ) -> Result<T, PairError> {
        let mut reg = self.running()?;
        let (out, endings) = {
            let g = self.device.store().lock()?;
            let view = self.device.member_view(&g)?;
            self.device.store().update_aux(
                &g,
                AUX_NAME,
                PAIRING_FORMAT,
                |st: &mut PairingState| {
                    Self::scoped(&view, st)?;
                    let r = f(&reg, &view, st)?;
                    st.prune_grants();
                    super::fault::fail("pairing_save")?;
                    Ok::<_, PairError>(r)
                },
            )?
        };
        for e in &endings {
            self.end(&mut reg, e);
        }
        Ok(then(&mut reg, out))
    }

    // ---------------------------------------------------------- decisions

    /// Approve the exact endpoint key the operator verified, under a local
    /// alias. With `reapprove`, or after a decline, a fresh approval value
    /// and a newer decision order end any earlier pairing.
    pub fn approve(
        &self,
        alias: &str,
        peer: &EndpointKey,
        reapprove: bool,
    ) -> Result<Approved, PairError> {
        check_alias(alias)?;
        self.transition(|view, st| {
            if reapprove {
                st.pending_grants.retain(|(key, _)| key != peer);
            }
            if let Some(why) = view.ineligible(peer) {
                return Err(Refusal::NotMember(why).into());
            }
            st.check_alias_binding(alias, peer)?;
            let fresh = Decision::Approve { approval: random() };
            match st.peer_mut(peer) {
                None => {
                    st.peers.push(PeerRecord {
                        endpoint: *peer,
                        alias: alias.to_string(),
                        local: fresh,
                        local_order: 1,
                        remote: Decision::Unknown,
                        remote_order: 0,
                        pairing: None,
                    });
                    Ok((Approved { fresh: true }, vec![]))
                }
                Some(p) if p.alias != alias => Err(PairError::Alias(format!(
                    "this key is already approved as {:?}",
                    p.alias
                ))),
                Some(p) if matches!(p.local, Decision::Approve { .. }) && !reapprove => {
                    Ok((Approved { fresh: false }, vec![]))
                }
                Some(p) => {
                    p.local = fresh;
                    p.local_order += 1;
                    p.pairing = None;
                    Ok((
                        Approved { fresh: true },
                        vec![Ending::Peer(*peer, "re-approved".into())],
                    ))
                }
            }
        })
    }

    /// Change an existing pin under the owner gate. Resolve the selector
    /// under the same locks as the write so concurrent renames cannot
    /// redirect a selector between lookup and update.
    pub fn rename(&self, selector: &str, alias: &str) -> Result<bool, PairError> {
        check_alias(alias)?;
        let _reg = self.running()?;
        let store = self.device.store();
        let g = store.lock()?;
        let view = self.device.member_view(&g)?;
        // This change only updates the label, so it skips the decision
        // transition's grant pruning and session invalidation.
        store.update_aux(&g, AUX_NAME, PAIRING_FORMAT, |st: &mut PairingState| {
            Self::group_scope(&view, st)?;
            let key = st.resolve_selector(selector).map_err(PairError::Alias)?;
            if let Some(why) = view.ineligible(&key) {
                return Err(Refusal::NotMember(why).into());
            }
            st.check_alias_binding(alias, &key)?;
            let peer = st.peer_mut(&key).ok_or_else(|| {
                PairError::Alias("this endpoint has no local alias to rename".into())
            })?;
            if peer.alias == alias {
                return Ok(false);
            }
            peer.alias = alias.to_owned();
            super::fault::fail("pairing_save")?;
            Ok(true)
        })
    }

    /// Locally decline a peer. Immediate and relay-independent.
    pub fn decline(&self, peer: &EndpointKey) -> Result<(), PairError> {
        self.transition(|_, st| {
            Self::decline_in(st, peer);
            Ok(((), vec![Ending::Peer(*peer, "declined locally".into())]))
        })
    }

    fn decline_in(st: &mut PairingState, peer: &EndpointKey) {
        st.pending_grants.retain(|(key, _)| key != peer);
        match st.peer_mut(peer) {
            Some(p) => {
                if p.local != Decision::Decline {
                    p.local = Decision::Decline;
                    p.local_order += 1;
                }
                p.pairing = None;
            }
            None => st.peers.push(PeerRecord {
                endpoint: *peer,
                alias: format!("declined-{}", hex(&peer[..8])),
                local: Decision::Decline,
                local_order: 1,
                remote: Decision::Unknown,
                remote_order: 0,
                pairing: None,
            }),
        }
    }

    /// Local cutoff. Under the registry lock: durably record the membership
    /// cutoff, flag the peer's sessions, then decline the pairing. Stage
    /// the network removal under a fresh gate, so shutdown can leave the
    /// already durable local cutoff in effect without staging a removal.
    pub fn cutoff(&self, peer: &EndpointKey) -> Result<Cutoff, PairError> {
        let mut reg = self.running()?;
        // 1. The durable local cutoff; only its failure fails the call.
        self.device.record_cutoff(peer)?;
        // 2. Signal it to every session and negotiation, still under the
        //    registry lock, before anything else can fail.
        self.end(&mut reg, &Ending::Peer(*peer, "cut off".into()));
        // 3. Decline the pairing (a failure here is reported, not fatal).
        let pairing_saved = (|| {
            let g = self.device.store().lock()?;
            let view = self.device.member_view(&g)?;
            self.device
                .store()
                .update_aux(&g, AUX_NAME, PAIRING_FORMAT, |st: &mut PairingState| {
                    Self::scoped(&view, st)?;
                    Self::decline_in(st, peer);
                    st.prune_grants();
                    super::fault::fail("pairing_save")?;
                    Ok::<_, PairError>(())
                })
        })();
        drop(reg);
        let pairing_saved = match pairing_saved {
            Ok(()) | Err(PairError::Refused(Refusal::Terminal)) => Ok(()),
            Err(e) => Err(format!("{e:?}")),
        };
        // 4. Only then stage the network removal (local MLS work; its
        //    publication is separate and may never be confirmed).
        let removal = self
            .run(|_| self.device.stage_remove(peer))
            .unwrap_or(Err(super::membership::Error::Cancelled))
            .map_err(|e| format!("{e:?}"));
        Ok(Cutoff {
            local_cutoff: true,
            pairing_saved,
            removal,
        })
    }

    // ------------------------------------------------------------- grants

    /// Grant an exact service to a member. A grant for an unpaired member
    /// becomes usable when both devices establish the pairing.
    pub fn grant(&self, peer: &EndpointKey, service: Service) -> Result<bool, PairError> {
        self.transition_reg(|reg, view, st| {
            if reg.is_exposed(peer, service) {
                return Err(PairError::Local(format!("{service} is temporarily exposed; stop the exposure before making it persistent")));
            }
            if let Some(why) = view.ineligible(peer) {
                return Err(Refusal::NotMember(why).into());
            }
            let added = match st
                .peer(peer)
                .and_then(|rec| rec.pairing.map(|p| (rec.alias.clone(), p)))
            {
                Some((alias, pairing)) => st
                    .grants
                    .enable(endpoint_id(peer)?, &alias, service, pairing.generation)
                    .map_err(|e| PairError::Local(format!("{e:#}")))?,
                None if st.pending_grants.contains(&(*peer, service)) => false,
                None => {
                    st.pending_grants.push((*peer, service));
                    true
                }
            };
            let before = st.exclusions.len();
            st.exclusions.retain(|(e, s)| !(e == peer && *s == service));
            Ok((added || st.exclusions.len() != before, vec![]))
        }, |_, r| r)
    }

    /// Remove a peer's grant for one service and exclude it from that
    /// service's default.
    /// Also withdraws a live exposure of that service to that peer.
    pub fn revoke_grant(&self, peer: &EndpointKey, service: Service) -> Result<bool, PairError> {
        self.transition_reg(
            |reg, _, st| {
                let exposed = reg.is_exposed(peer, service);
                let removed = st.grants.disable(endpoint_id(peer)?, service).is_some();
                let before = st.pending_grants.len();
                st.pending_grants.retain(|grant| *grant != (*peer, service));
                let removed = removed || st.pending_grants.len() != before;
                let excluded = Self::exclude_in(st, peer, service);
                Ok((
                    removed || excluded || exposed,
                    vec![Ending::PeerService(*peer, service, "grant removed".into())],
                ))
            },
            |_, r| r,
        )
    }

    /// Offer a port to an approved peer while the handle lives. Access
    /// starts only after both sides confirm the pairing.
    pub fn expose(
        &self,
        peer: &EndpointKey,
        service: Service,
        target: Option<String>,
    ) -> Result<Exposure, PairError> {
        if service == Service::Shell {
            return Err(PairError::Local("only a port can be exposed".into()));
        }
        if let Some(t) = &target {
            wire::check_target(t).map_err(|e| PairError::Local(format!("{e:#}")))?;
        }
        let mut reg = self.running()?;
        let g = self.device.store().lock()?;
        let (alias, generation) = self.read_locked(&g, |view, st| {
            if let Some(why) = view.ineligible(peer) {
                return Err(Refusal::NotMember(why).into());
            }
            let rec = st.peer(peer).ok_or(Refusal::NotApproved)?;
            if !matches!(rec.local, Decision::Approve { .. }) {
                return Err(Refusal::NotApproved.into());
            }
            let generation = rec.pairing.map_or(0, |pairing| pairing.generation);
            let (alias, id) = (rec.alias.clone(), endpoint_id(peer)?);
            if reg.is_exposed(peer, service) {
                return Err(PairError::Local(format!(
                    "{service} is already exposed to {alias}; stop that command first"
                )));
            }
            if st.pending_grants.contains(&(*peer, service))
                || st.grants.access(id, service, generation).is_some()
            {
                return Err(PairError::Local(format!(
                    "{service} is already enabled for {alias}; disable it first"
                )));
            }
            if !st.excluded(peer, service) && st.defaults.access(id, service).is_some() {
                return Err(PairError::Local(format!(
                    "{service} is enabled by default for {alias}; \
                     disable it for {alias} before exposing a different target"
                )));
            }
            Ok((alias, generation))
        })?;
        drop(g);
        let id = endpoint_id(peer)?;
        let instance = reg
            .exposed
            .expose(id, &alias, service, generation, target.clone())
            .map_err(|e| PairError::Local(format!("{e:#}")))?;
        let flag = Arc::new(Flag::default());
        reg.holders.insert(
            instance,
            Holder {
                peer: *peer,
                id,
                service,
                generation,
                flag: flag.clone(),
            },
        );
        Ok(Exposure {
            sessions: self.owner.sessions.clone(),
            instance,
            flag,
            peer: *peer,
            alias,
            service,
            target,
        })
    }

    /// Live exposures: (peer, service, owner-chosen target).
    pub fn exposures(&self) -> Vec<(EndpointKey, Service, Option<String>)> {
        self.registry()
            .exposed
            .list(|_| None)
            .into_iter()
            .filter_map(|g| Some((*g.id?.as_bytes(), g.service, g.target)))
            .collect()
    }

    pub fn set_default(&self, service: Service, enabled: bool) -> Result<bool, PairError> {
        self.transition(|_, st| {
            let changed = st.defaults.set(service, enabled);
            let end = if enabled {
                vec![]
            } else {
                vec![Ending::Default(service, "default disabled".into())]
            };
            Ok((changed, end))
        })
    }

    /// Exclude a peer from a service default. Persists whether or not the
    /// default is currently enabled.
    pub fn exclude(&self, peer: &EndpointKey, service: Service) -> Result<bool, PairError> {
        self.transition(|_, st| {
            let changed = Self::exclude_in(st, peer, service);
            Ok((
                changed,
                vec![Ending::PeerDefault(*peer, service, "excluded".into())],
            ))
        })
    }

    fn exclude_in(st: &mut PairingState, peer: &EndpointKey, service: Service) -> bool {
        if st.excluded(peer, service) {
            return false;
        }
        st.exclusions.push((*peer, service));
        true
    }

    pub fn clear_exclusion(&self, peer: &EndpointKey, service: Service) -> Result<bool, PairError> {
        self.transition(|_, st| {
            let before = st.exclusions.len();
            st.exclusions.retain(|(e, s)| !(e == peer && *s == service));
            Ok((st.exclusions.len() != before, vec![]))
        })
    }

    // ---------------------------------------------------------- membership

    /// End the sessions (and negotiations) an applied membership advance
    /// ends, under the registry lock the gate holds.
    fn end_advance(&self, reg: &mut Registry, a: &Advance) {
        match a {
            Advance::Advanced {
                op: OpSummary::Remove { subject },
                ..
            } => {
                self.end(
                    reg,
                    &Ending::Peer(*subject, "removed from the network".into()),
                );
            }
            Advance::SelfRemoved { .. } => {
                self.end(reg, &Ending::All("this device was removed".into()));
            }
            Advance::Advanced { .. } => {}
        }
    }

    /// Apply the current membership view to sessions and pairings: flag
    /// first (under the registry lock), then prune the pairing row. A save
    /// failure leaves the flags in place.
    pub fn reconcile(&self) -> Result<usize, PairError> {
        let mut reg = self.running()?;
        let g = self.device.store().lock()?;
        let view = self.device.member_view(&g)?;
        if view.terminal {
            return Ok(self.end(&mut reg, &Ending::All("this device was removed".into())));
        }
        // Peers with a live exposure count even with no session open.
        let mut peers: Vec<EndpointKey> = reg.entries.values().map(|e| e.peer).collect();
        peers.extend(reg.holders.values().map(|h| h.peer));
        peers.sort_unstable();
        peers.dedup();
        let mut n = 0;
        for p in peers {
            if let Some(why) = view.ineligible(&p) {
                n += self.end(&mut reg, &Ending::Peer(p, why.into()));
            }
        }
        self.device
            .store()
            .update_aux(&g, AUX_NAME, PAIRING_FORMAT, |st: &mut PairingState| {
                Self::scoped(&view, st)?;
                for p in st.peers.iter_mut() {
                    if view.ineligible(&p.endpoint).is_some() {
                        p.pairing = None;
                    }
                }
                st.prune_grants();
                super::fault::fail("pairing_save")?;
                Ok::<_, PairError>(())
            })?;
        Ok(n)
    }

    /// Catch up membership. Each slot's local promotion runs inside this
    /// boundary's gate (registry lock held, no mailbox wait), so a removal
    /// and the end of its sessions are one step for every service start.
    pub fn advance_membership(&self) -> Result<(Vec<Advance>, Stop), PairError> {
        let r = self.device.catch_up_gated(self);
        self.reconcile()?;
        Ok(r)
    }

    /// Settle an own candidate inside the same gate; a lost race may adopt
    /// another member's removal.
    pub fn settle(&self) -> Result<Settle, PairError> {
        let r = self.device.settle_gated(self);
        // Test point: an accepted own removal has already ended its
        // subject's sessions here, before reconciliation.
        super::fault::pause("settled_before_reconcile");
        self.reconcile()?;
        Ok(r?)
    }

    // ------------------------------------------------------------ exchange

    /// Start the exchange on a completed authenticated link. Identity,
    /// channel binding and liveness come from the link only. A key outside
    /// the accepted roster (or removed, or cut off) is refused here, before
    /// anything (the group tag included) is sent to it.
    pub(in crate::private) fn exchange<'p>(
        &'p self,
        link: Arc<dyn Link>,
    ) -> Result<Exchange<'p, 'd, 'o, M>, PairError> {
        if link.alpn() != PAIRING_ALPN {
            return Err(Refusal::WrongProtocol.into());
        }
        if !link.is_open() {
            return Err(Refusal::ConnectionClosed.into());
        }
        let binding = link.channel_binding()?;
        let remote = link.remote_key();
        let reg = self.running()?;
        let snapshot = reg.snapshot(&remote);
        let g = self.device.store().lock()?;
        let mine = self.read_locked(&g, |view, st| {
            if let Some(why) = view.ineligible(&remote) {
                return Err(Refusal::NotMember(why).into());
            }
            let (decision, order) = match st.peer(&remote) {
                Some(r) if matches!(r.local, Decision::Approve { .. }) => {
                    (r.local.clone(), r.local_order)
                }
                Some(r) => (Decision::Decline, r.local_order),
                None => (Decision::Decline, 0),
            };
            Ok(Offer {
                group_tag: st.group_tag.expect("scoped"),
                sender: view.endpoint,
                receiver: remote,
                nonce: random(),
                decision,
                order,
            })
        })?;
        drop(g);
        drop(reg);
        Ok(Exchange {
            peers: self,
            link,
            binding,
            mine,
            snapshot,
        })
    }

    /// Send (or do any short step) only while the exchange's offer is still
    /// this device's current decision: each poll runs under the registry
    /// lock after comparing the peer's decision epoch with the snapshot taken
    /// with the offer; the lock is released between polls.
    pub(in crate::private) async fn guarded<T>(
        &self,
        peer: &EndpointKey,
        snapshot: (u64, u64),
        link: &dyn Link,
        step: impl Future<Output = T>,
    ) -> Result<T, PairError> {
        let mut step = pin!(step);
        std::future::poll_fn(|cx| {
            let reg = self.registry();
            if reg.snapshot(peer) != snapshot {
                return Poll::Ready(Err(Refusal::StaleExchange(
                    "local decision changed during the exchange",
                )
                .into()));
            }
            if !link.is_open() {
                return Poll::Ready(Err(Refusal::ConnectionClosed.into()));
            }
            let r = step.as_mut().poll(cx).map(Ok);
            drop(reg);
            r
        })
        .await
    }

    /// Resolve once the peer's decision epoch differs from `snapshot`.
    pub(in crate::private) async fn retired(&self, peer: &EndpointKey, snapshot: (u64, u64)) {
        loop {
            let n = self.owner.sessions.changed.notified();
            let mut n = pin!(n);
            n.as_mut().enable();
            if self.registry().snapshot(peer) != snapshot {
                return;
            }
            n.await;
        }
    }

    /// Production acquisition on a completed private-ALPN Iroh connection:
    /// the dialer opens one bi-stream, both sides exchange offers and
    /// confirmations on it (each send guarded, each read bounded by the
    /// record's exact encoded size), and the same stream is returned for the
    /// one service request and its payload. A local decline, cutoff or
    /// removal retires the negotiation at once; so does the connection
    /// closing.
    pub(in crate::private) async fn authorize(
        &self,
        conn: &iroh::endpoint::Connection,
        dialer: bool,
    ) -> Result<
        (
            Authorization,
            iroh::endpoint::SendStream,
            iroh::endpoint::RecvStream,
        ),
        PairError,
    > {
        let link: Arc<dyn Link> = Arc::new(conn.clone());
        let ex = self.exchange(link.clone())?;
        let (peer, snapshot) = (ex.link.remote_key(), ex.snapshot);
        let io = async {
            let local =
                |e: &dyn std::fmt::Display| PairError::Local(format!("pairing stream: {e}"));
            let (mut tx, mut rx) = if dialer {
                conn.open_bi().await.map_err(|e| local(&e))?
            } else {
                conn.accept_bi().await.map_err(|e| local(&e))?
            };
            // Defence in depth only: replay safety comes from reading the
            // request only after this device's fresh nonce is confirmed.
            if rx.is_0rtt() {
                return Err(Refusal::StaleExchange("stream opened in early data").into());
            }
            let offer = ex.offer();
            self.guarded(&peer, snapshot, &*link, crate::wire::frame(&mut tx, &offer))
                .await?
                .map_err(|e| local(&e))?;
            let their_offer = read_bounded(&mut rx, &offer_lens()).await?;
            let (confirming, confirm) = ex.on_offer(&their_offer)?;
            self.guarded(
                &peer,
                snapshot,
                &*link,
                crate::wire::frame(&mut tx, &confirm),
            )
            .await?
            .map_err(|e| local(&e))?;
            let their_confirm = read_bounded(&mut rx, &[confirm_len()]).await?;
            let auth = confirming.finish(&their_confirm)?;
            Ok((auth, tx, rx))
        };
        tokio::select! {
            biased;
            _ = self.retired(&peer, snapshot) => {
                Err(Refusal::StaleExchange("local decision changed during the exchange").into())
            }
            _ = link.closed() => Err(Refusal::ConnectionClosed.into()),
            r = io => r,
        }
    }

    fn commit_exchange(
        &self,
        link: Arc<dyn Link>,
        binding: [u8; 32],
        mine: &Offer,
        theirs: &Offer,
    ) -> Result<Authorization, PairError> {
        let remote = link.remote_key();
        let sessions = self.owner.sessions.clone();
        let owner = self.owner.instance;
        self.transition_then(
            |view, st| {
                if let Some(why) = view.ineligible(&remote) {
                    if let Some(p) = st.peer_mut(&remote) {
                        p.pairing = None;
                    }
                    return Ok((
                        Err(Refusal::NotMember(why)),
                        vec![Ending::Peer(remote, why.into())],
                    ));
                }
                let rec = st.peer_mut(&remote).ok_or(Refusal::NotApproved)?;
                // Our side: we offered an approval, and it is still current.
                let ours = match &mine.decision {
                    Decision::Approve { approval } => *approval,
                    _ => return Err(Refusal::NotApproved.into()),
                };
                if rec.local != mine.decision || rec.local_order != mine.order {
                    return Err(Refusal::StaleExchange(
                        "local decision changed during the exchange",
                    )
                    .into());
                }
                // Their side: only a newer decision changes what we know.
                if theirs.order < rec.remote_order {
                    return Err(Refusal::StaleDecision.into());
                }
                if theirs.order == rec.remote_order && rec.remote != theirs.decision {
                    return Err(Refusal::ConflictingDecision.into());
                }
                rec.remote = theirs.decision.clone();
                rec.remote_order = theirs.order;
                let theirs_value = match &theirs.decision {
                    Decision::Approve { approval } => *approval,
                    _ => {
                        rec.pairing = None;
                        // Order zero says the peer has never approved.
                        let endings = if theirs.order == 0 {
                            vec![]
                        } else {
                            st.pending_grants.retain(|(key, _)| *key != remote);
                            vec![Ending::Peer(remote, "peer declined".into())]
                        };
                        return Ok((Err(Refusal::RemoteDeclined), endings));
                    }
                };
                let mut endings = vec![];
                let generation = match rec.pairing {
                    Some(p) if p.ours == ours && p.theirs == theirs_value => p.generation,
                    old => {
                        if let Some(old) = old {
                            endings.push(Ending::PeerGeneration(
                                remote,
                                old.generation,
                                "re-paired".into(),
                            ));
                        }
                        st.last_generation += 1;
                        let generation = st.last_generation;
                        let rec = st.peer_mut(&remote).expect("record");
                        rec.pairing = Some(Pairing {
                            ours,
                            theirs: theirs_value,
                            generation,
                        });
                        generation
                    }
                };
                let alias = st.peer(&remote).expect("record").alias.clone();
                for service in st
                    .pending_grants
                    .iter()
                    .filter_map(|(key, service)| (*key == remote).then_some(*service))
                {
                    st.grants
                        .enable(endpoint_id(&remote)?, &alias, service, generation)
                        .map_err(|e| PairError::Local(format!("{e:#}")))?;
                }
                st.pending_grants.retain(|(key, _)| *key != remote);
                Ok((Ok((ours, theirs_value, generation)), endings))
            },
            |reg, r| {
                r.map(|(ours, theirs_value, generation)| {
                    // Registered in the same critical section as the commit.
                    reg.bind_exposures(&remote, generation);
                    reg.next += 1;
                    let id = reg.next;
                    let flag = Arc::new(Flag::default());
                    reg.entries.insert(
                        id,
                        Entry {
                            peer: remote,
                            service: None,
                            generation,
                            via_default: false,
                            exposure: None,
                            flag: flag.clone(),
                        },
                    );
                    Authorization {
                        owner,
                        id,
                        flag,
                        sessions: sessions.clone(),
                        link: link.clone(),
                        remote,
                        binding,
                        ours,
                        our_order: mine.order,
                        theirs: theirs_value,
                        their_order: theirs.order,
                        generation,
                    }
                })
            },
        )?
        .map_err(PairError::Refused)
    }

    // --------------------------------------------------------------- open

    /// Authorize one service request on an authorized connection. Evaluates
    /// the durable state and registers the session under the registry lock.
    pub(in crate::private) fn open(
        &self,
        auth: &Authorization,
        service: Service,
    ) -> Result<SessionHandle, PairError> {
        let mut reg = self.running()?;
        if auth.owner != self.owner.instance {
            return Err(Refusal::StaleExchange("authorization from another runtime owner").into());
        }
        // The authorization's own entry has been registered since commit;
        // anything that ended it ends this open too.
        if let Some(r) = auth.flag.get() {
            return Err(Refusal::Invalidated(r).into());
        }
        if !auth.link.is_open() {
            return Err(Refusal::ConnectionClosed.into());
        }
        if auth.link.remote_key() != auth.remote || auth.link.channel_binding()? != auth.binding {
            return Err(Refusal::StaleExchange("authorization is for another connection").into());
        }
        let g = self.device.store().lock()?;
        let (target, via_default, exposure) = self.read_locked(&g, |view, st| {
            if let Some(why) = view.ineligible(&auth.remote) {
                return Err(Refusal::NotMember(why).into());
            }
            let rec = st.peer(&auth.remote).ok_or(Refusal::NotApproved)?;
            if rec.local
                != (Decision::Approve {
                    approval: auth.ours,
                })
                || rec.local_order != auth.our_order
            {
                return Err(match rec.local {
                    Decision::Approve { .. } => Refusal::NotPaired,
                    _ => Refusal::NotApproved,
                }
                .into());
            }
            if rec.remote
                != (Decision::Approve {
                    approval: auth.theirs,
                })
                || rec.remote_order != auth.their_order
            {
                return Err(match rec.remote {
                    Decision::Decline => Refusal::RemoteDeclined,
                    _ => Refusal::NotPaired,
                }
                .into());
            }
            if rec.pairing
                != Some(Pairing {
                    ours: auth.ours,
                    theirs: auth.theirs,
                    generation: auth.generation,
                })
            {
                return Err(Refusal::NotPaired.into());
            }
            let id = endpoint_id(&auth.remote)?;
            if let Some(a) = reg.exposed.access(id, service, auth.generation)
                && let GrantInstance::Peer(instance) = a.instance
            {
                return Ok((a.target, false, Some(instance)));
            }
            if let Some(a) = st.grants.access(id, service, auth.generation) {
                return Ok((a.target, false, None));
            }
            if !st.excluded(&auth.remote, service)
                && let Some(a) = st.defaults.access(id, service)
            {
                return Ok((a.target, true, None));
            }
            Err(Refusal::ServiceNotGranted.into())
        })?;
        drop(g);
        #[cfg(test)]
        open_pause(&auth.remote);
        reg.next += 1;
        let id = reg.next;
        let flag = Arc::new(Flag::default());
        reg.entries.insert(
            id,
            Entry {
                peer: auth.remote,
                service: Some(service),
                generation: auth.generation,
                via_default,
                exposure,
                flag: flag.clone(),
            },
        );
        Ok(SessionHandle {
            id,
            sessions: self.owner.sessions.clone(),
            flag,
            link: auth.link.clone(),
            peer: auth.remote,
            service,
            target,
        })
    }

    // ---------------------------------------------------------- inspection

    pub fn state(&self) -> Result<PairingState, PairError> {
        let g = self.device.store().lock()?;
        self.read_locked(&g, |_, st| Ok(st.clone()))
    }

    /// The endpoint bound to a verified local alias.
    pub fn resolve(&self, alias: &str) -> Result<Option<EndpointKey>, PairError> {
        let g = self.device.store().lock()?;
        self.read_locked(&g, |_, st| {
            Ok(st
                .peers
                .iter()
                .find(|p| p.alias == alias)
                .map(|p| p.endpoint))
        })
    }
}

/// Read the pairing row without a runtime owner (safe status for another
/// process). Never writes; mutations require the owner's `Peers`.
pub fn read_state<M: Mailbox>(device: &Device<M>) -> Result<PairingState, PairError> {
    let g = device.store().lock()?;
    Ok(device
        .store()
        .load_aux(&g, AUX_NAME, PAIRING_FORMAT)?
        .unwrap_or_default())
}

/// Test-only: pause one peer's next open between evaluation and
/// registration, to make the open/transition ordering observable.
#[cfg(test)]
pub(crate) static OPEN_PAUSE: Mutex<Option<(EndpointKey, std::sync::mpsc::Sender<()>)>> =
    Mutex::new(None);

#[cfg(test)]
fn open_pause(peer: &EndpointKey) {
    let hook = OPEN_PAUSE
        .lock()
        .expect("pause lock")
        .take_if(|(p, _)| p == peer);
    if let Some((_, tx)) = hook {
        let _ = tx.send(());
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

impl<M: Mailbox> Gate for Peers<'_, '_, M> {
    /// Hold the registry lock (the startup ordering point) across one short
    /// local promotion and end the sessions of everything it applied, even
    /// if the promotion then failed in cleanup. Lock order: registry, then
    /// the profile lock taken inside `f`.
    /// Closed (returns `None` without running `f`) once the owner is
    /// stopping, checked under the same lock `Owner::retire` takes.
    fn run<R>(&self, f: impl FnOnce(&mut Vec<Advance>) -> R) -> Option<R> {
        let mut reg = self.running().ok()?;
        let mut applied = vec![];
        let r = f(&mut applied);
        for a in &applied {
            self.end_advance(&mut reg, a);
        }
        Some(r)
    }

    fn admits(&self) -> bool {
        !self.owner.stopping()
    }
}

/// Exact encoded sizes of an offer (approve, decline).
fn offer_lens() -> [usize; 2] {
    let o = |decision| {
        Offer {
            group_tag: [0; 32],
            sender: [0; 32],
            receiver: [0; 32],
            nonce: [0; 32],
            decision,
            order: 0,
        }
        .encode()
        .len()
    };
    [
        o(Decision::Approve { approval: [0; 32] }),
        o(Decision::Decline),
    ]
}

fn confirm_len() -> usize {
    encode_confirm(&[0; 32]).len()
}

/// Read one length-prefixed record whose length must be one of `allowed`
/// (its exact valid encodings); anything else fails before reading the body.
pub(in crate::private) async fn read_bounded(
    rx: &mut (impl tokio::io::AsyncRead + Unpin),
    allowed: &[usize],
) -> Result<Vec<u8>, PairError> {
    use tokio::io::AsyncReadExt;
    let io = |e: std::io::Error| PairError::Local(format!("pairing stream: {e}"));
    let len = rx.read_u32().await.map_err(io)? as usize;
    if !allowed.contains(&len) {
        return Err(PairError::Malformed(format!("record length {len}")));
    }
    let mut buf = vec![0; len];
    rx.read_exact(&mut buf).await.map_err(io)?;
    Ok(buf)
}

enum Ending {
    Peer(EndpointKey, String),
    PeerGeneration(EndpointKey, u64, String),
    PeerService(EndpointKey, Service, String),
    /// Sessions of this peer and service that rely on the default only.
    PeerDefault(EndpointKey, Service, String),
    Default(Service, String),
    /// Sessions opened under one exposure instance.
    Exposure(u64, String),
    All(String),
}

impl Ending {
    fn reason(&self) -> &str {
        match self {
            Ending::Peer(_, r)
            | Ending::PeerGeneration(_, _, r)
            | Ending::PeerService(_, _, r)
            | Ending::PeerDefault(_, _, r)
            | Ending::Default(_, r)
            | Ending::Exposure(_, r)
            | Ending::All(r) => r,
        }
    }
}

/// An endpoint key written as 64 hex digits or in Iroh's own form.
pub(super) fn parse_key(s: &str) -> Option<EndpointKey> {
    if s.len() == 64
        && let Some(b) = unhex(s)
    {
        return b.try_into().ok();
    }
    s.parse::<EndpointId>().ok().map(|id| *id.as_bytes())
}

fn check_alias(alias: &str) -> Result<(), PairError> {
    if alias.is_empty()
        || alias.len() > MAX_ALIAS
        || alias.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(PairError::Alias(
            "alias must be 1 to 64 characters without spaces or controls".into(),
        ));
    }
    if parse_key(alias).is_some() {
        return Err(PairError::Alias(
            "an alias must not look like an endpoint key".into(),
        ));
    }
    Ok(())
}
