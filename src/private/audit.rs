//! Device event log of the private runtime, over the shared `ConnectionLog`
//! JSONL format.
//!
//! The private runtime appends to `connections.jsonl` in its profile
//! directory (or the file its caller chose) with the same record shape and,
//! where an event means the same thing, the same event names and reasons as
//! the legacy daemon:
//!
//! - `device_started` and `device_stopped` around the runtime;
//! - one session per inbound or outbound service connection
//!   (`connected`, then `disconnected`, or `connection_failed`), with its
//!   direction, peer, service and a fixed reason (`shell_exit` carries the
//!   exit code);
//! - `local_control` audits for each control command (`requested`, then
//!   `allowed`, `denied` or `failed`), and for a client that failed to
//!   authenticate or send a command;
//! - `peer_transport` audits for failed inbound handshakes;
//! - `membership_sync` audits when the membership pass starts or stops
//!   reaching the relay;
//! - state changes observed in the pairing state and the accepted roster:
//!   `peer_joined`, `peer_removed`, `approval_granted`, `approval_declined`,
//!   `peer_approved`, `peer_declined`, `pairing_established`,
//!   `pairing_ended`, `service_enabled`, `service_disabled`,
//!   `service_default_enabled`, `service_default_disabled`,
//!   `service_default_excluded`, `service_default_exclusion_cleared`,
//!   `membership_halted` and `device_revoked`.
//!
//! # What is never logged
//!
//! Peers appear by endpoint ID and, when this device pinned one, by the
//! local alias; roster names are not consulted. Every reason is a fixed
//! code chosen here. No record carries a request, reply, payload byte,
//! invite, approval value, pairing secret, local control key, raw error or
//! halt text.
//!
//! # State changes
//!
//! The runtime records state events by diffing snapshots of the pairing
//! state (and, after control commands and membership passes, the roster
//! and halt) against the previous snapshot. The first snapshot is the
//! baseline and logs nothing. Each snapshot is read while the tracker is
//! held, so concurrent observers never apply an older view after a newer
//! one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use anyhow::Result;
use iroh::EndpointId;

use crate::connection_log::{Audit, ConnectionLog, Direction, Session};
use crate::wire::{GrantRule, Service};

use super::binding::EndpointKey;
use super::mailbox::Mailbox;
use super::membership::{Advance, Stop};
use super::pairing::{Decision, PairError, PairingState, Refusal};
use super::runtime::{ControlReply, ControlRequest};
use super::service::{Ended, Node, Synced};

/// Default event file name in the private profile directory (as legacy).
pub const EVENT_FILE: &str = "connections.jsonl";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn id(key: &EndpointKey) -> Option<EndpointId> {
    EndpointId::from_bytes(key).ok()
}

/// The private runtime's event log.
pub struct DeviceLog {
    log: ConnectionLog,
    path: Option<PathBuf>,
    own: OnceLock<EndpointKey>,
    seen: Mutex<Option<Snapshot>>,
    reachable: Mutex<Option<bool>>,
    revoked: AtomicBool,
}

impl DeviceLog {
    /// Append to `path` (created with owner-only permissions), mirrored to
    /// standard error.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self::with(
            ConnectionLog::open(Some(path))?,
            Some(path.into()),
        ))
    }

    /// Record nothing.
    pub fn disabled() -> Self {
        Self::with(ConnectionLog::disabled(), None)
    }

    fn with(log: ConnectionLog, path: Option<PathBuf>) -> Self {
        Self {
            log,
            path,
            own: OnceLock::new(),
            seen: Mutex::new(None),
            reachable: Mutex::new(None),
            revoked: AtomicBool::new(false),
        }
    }

    /// The event file, when there is one.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Whether anything is recorded.
    pub fn enabled(&self) -> bool {
        self.path.is_some()
    }

    /// Set this device's endpoint key (the actor of local audits).
    pub fn set_own(&self, key: EndpointKey) {
        let _ = self.own.set(key);
    }

    fn actor(&self) -> Option<EndpointId> {
        self.own.get().and_then(id)
    }

    pub fn started(&self) {
        self.log.state("device_started", None, None);
    }

    pub fn stopped(&self) {
        self.log.state("device_stopped", None, None);
    }

    /// An inbound connection whose handshake did not complete.
    pub fn handshake_failed(&self) {
        self.log.audit(
            "peer_transport",
            Audit {
                operation: "handshake",
                outcome: "failed",
                reason: Some("handshake_failed"),
                ..Audit::default()
            },
            None,
        );
    }

    /// A local control client that failed to authenticate (or, once
    /// authenticated, to send a complete command in time).
    pub fn control_unreadable(&self, authenticated: bool) {
        self.log.audit(
            "local_control",
            Audit {
                operation: if authenticated {
                    "read_request"
                } else {
                    "authenticate"
                },
                outcome: "denied",
                actor_id: authenticated.then(|| self.actor()).flatten(),
                reason: Some(if authenticated {
                    "invalid_or_incomplete_request"
                } else {
                    "authentication_failed"
                }),
                ..Audit::default()
            },
            None,
        );
    }

    /// One audit of a local control command.
    pub fn control(
        &self,
        operation: &'static str,
        outcome: &'static str,
        target: Option<EndpointKey>,
        service: Option<Service>,
        reason: Option<&'static str>,
    ) {
        self.log.audit(
            "local_control",
            Audit {
                operation,
                outcome,
                actor_id: self.actor(),
                target_id: target.as_ref().and_then(id),
                reason,
                ..Audit::default()
            },
            service,
        );
    }

    pub fn exposure(&self, event: &'static str, key: &EndpointKey, alias: &str, service: Service) {
        self.log.peer(event, id(key), Some(alias), Some(service));
    }

    /// The outcome of one membership pass: reachability changes and this
    /// device's own removal.
    pub fn membership_pass(&self, synced: &Synced) {
        if matches!(synced.stop, Stop::Terminal)
            || synced
                .advanced
                .iter()
                .any(|a| matches!(a, Advance::SelfRemoved { .. }))
        {
            self.device_revoked();
        }
        let reached = match synced.stop {
            Stop::Cancelled => return,
            Stop::Unavailable(_) | Stop::Failed(_) => false,
            _ => true,
        };
        {
            let mut last = lock(&self.reachable);
            if *last == Some(reached) {
                return;
            }
            *last = Some(reached);
        }
        self.log.audit(
            "membership_sync",
            Audit {
                operation: "membership_pass",
                outcome: if reached { "allowed" } else { "failed" },
                actor_id: self.actor(),
                reason: (!reached).then_some("could_not_sync_membership"),
                ..Audit::default()
            },
            None,
        );
    }

    fn device_revoked(&self) {
        if !self.revoked.swap(true, Ordering::Relaxed) {
            self.log.state("device_revoked", None, None);
        }
    }

    /// The local alias pinned to `key`, from the last snapshot.
    fn alias(&self, key: &EndpointKey) -> Option<String> {
        lock(&self.seen)
            .as_ref()
            .and_then(|s| s.peers.get(key))
            .map(|p| p.alias.clone())
    }

    /// The key a pinned alias selects, from the last snapshot (for audits
    /// only; commands resolve against the current state).
    pub fn alias_key(&self, alias: &str) -> Option<EndpointKey> {
        let seen = lock(&self.seen);
        let mut hits = seen
            .as_ref()?
            .peers
            .iter()
            .filter(|(_, p)| p.alias == alias);
        match (hits.next(), hits.next()) {
            (Some((k, _)), None) => Some(*k),
            _ => None,
        }
    }

    /// A session for a connection a peer opened to this device.
    pub fn inbound(&self, peer: EndpointId) -> Tracked<'_> {
        let name = self.alias(peer.as_bytes());
        Tracked::new(self.log.session(Direction::Inbound, Some(peer), name))
    }

    /// A session for a connection a local command opens to a peer.
    pub fn outbound(&self, service: Service) -> Tracked<'_> {
        let mut session = self.log.session(Direction::Outbound, None, None);
        session.set_service(service);
        Tracked::new(session)
    }

    /// Diff a fresh snapshot against the last one and log the changes.
    /// `read` runs while the tracker is held; `None` skips this round.
    pub fn observe(&self, read: impl FnOnce() -> Option<Observed>) {
        let mut seen = lock(&self.seen);
        let Some(observed) = read() else { return };
        let next = Snapshot::new(observed, seen.as_ref());
        if let Some(before) = seen.as_ref() {
            for change in changes(self.own.get(), before, &next) {
                if change.event == "device_revoked" {
                    self.device_revoked();
                    continue;
                }
                let name = change
                    .peer
                    .and_then(|k| next.peers.get(&k).or_else(|| before.peers.get(&k)))
                    .map(|p| p.alias.as_str());
                let peer = change.peer.as_ref().and_then(id);
                self.log.peer(change.event, peer, name, change.service);
            }
        }
        *seen = Some(next);
    }
}

/// Observe `node`'s pairing state and, with `membership`, its roster and
/// halt (local reads only; no mailbox wait).
pub fn observe<M: Mailbox + Send + Sync + 'static>(node: &Node<M>, membership: bool) {
    if !node.log().enabled() {
        return;
    }
    node.log().observe(|| {
        let pairing = node.pairing_state().ok()?;
        let (roster, halted) = if membership {
            (node.roster().ok(), node.halt().ok().map(|h| h.is_some()))
        } else {
            (None, None)
        };
        Some(Observed {
            pairing,
            roster,
            halted,
        })
    });
}

/// One read of the state the log tracks. `None` keeps the previous value.
pub struct Observed {
    pub pairing: PairingState,
    pub roster: Option<Vec<EndpointKey>>,
    pub halted: Option<bool>,
}

// ---------------------------------------------------------------- snapshots

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Approve,
    Decline,
    Unknown,
}

impl From<&Decision> for Kind {
    fn from(d: &Decision) -> Self {
        match d {
            Decision::Approve { .. } => Kind::Approve,
            Decision::Decline => Kind::Decline,
            Decision::Unknown => Kind::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PeerSnap {
    alias: String,
    local: Kind,
    local_order: u64,
    remote: Kind,
    remote_order: u64,
    /// Generation of the current pairing.
    pairing: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Snapshot {
    peers: BTreeMap<EndpointKey, PeerSnap>,
    grants: BTreeSet<(EndpointKey, Service)>,
    defaults: BTreeSet<Service>,
    exclusions: BTreeSet<(EndpointKey, Service)>,
    roster: Option<BTreeSet<EndpointKey>>,
    halted: bool,
}

impl Snapshot {
    fn new(o: Observed, previous: Option<&Snapshot>) -> Self {
        let st = o.pairing;
        let peers = st
            .peers
            .iter()
            .map(|p| {
                let snap = PeerSnap {
                    alias: p.alias.clone(),
                    local: (&p.local).into(),
                    local_order: p.local_order,
                    remote: (&p.remote).into(),
                    remote_order: p.remote_order,
                    pairing: p.pairing.map(|x| x.generation),
                };
                (p.endpoint, snap)
            })
            .collect();
        let grants = st
            .grants
            .list(|_| None)
            .into_iter()
            .filter(|g| !g.temporary)
            .filter_map(|g| Some((*g.id?.as_bytes(), g.service)))
            .chain(st.pending_grants)
            .collect();
        let defaults = st
            .defaults
            .list(|_| None)
            .into_iter()
            .filter(|g| matches!(g.rule, Some(GrantRule::Default)))
            .map(|g| g.service)
            .collect();
        let exclusions = st.exclusions.iter().copied().collect();
        Self {
            peers,
            grants,
            defaults,
            exclusions,
            roster: o
                .roster
                .map(|r| r.into_iter().collect())
                .or_else(|| previous.and_then(|p| p.roster.clone())),
            halted: o.halted.or(previous.map(|p| p.halted)).unwrap_or(false),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Change {
    event: &'static str,
    peer: Option<EndpointKey>,
    service: Option<Service>,
}

fn change(event: &'static str, peer: Option<EndpointKey>, service: Option<Service>) -> Change {
    Change {
        event,
        peer,
        service,
    }
}

/// The events between two snapshots, in a stable order.
fn changes(own: Option<&EndpointKey>, before: &Snapshot, after: &Snapshot) -> Vec<Change> {
    let mut out = vec![];
    let rosters = before.roster.as_ref().zip(after.roster.as_ref());
    if let (Some((b, a)), Some(own)) = (rosters, own)
        && b.contains(own)
        && !a.contains(own)
    {
        out.push(change("device_revoked", None, None));
    }
    let mut keys: BTreeSet<EndpointKey> = before.peers.keys().copied().collect();
    keys.extend(after.peers.keys().copied());
    if let Some((b, a)) = rosters {
        keys.extend(b.iter().copied());
        keys.extend(a.iter().copied());
    }
    for key in keys {
        if Some(&key) == own {
            continue;
        }
        let peer = Some(key);
        let membership = rosters.map(|(b, a)| (b.contains(&key), a.contains(&key)));
        if membership == Some((false, true)) {
            out.push(change("peer_joined", peer, None));
        }
        let (b, a) = (before.peers.get(&key), after.peers.get(&key));
        if let Some(a) = a {
            let local_changed =
                b.is_none_or(|b| (b.local, b.local_order) != (a.local, a.local_order));
            if local_changed {
                match a.local {
                    Kind::Approve => out.push(change("approval_granted", peer, None)),
                    Kind::Decline => out.push(change("approval_declined", peer, None)),
                    Kind::Unknown => {}
                }
            }
            let remote_changed =
                b.is_none_or(|b| (b.remote, b.remote_order) != (a.remote, a.remote_order));
            if remote_changed {
                match a.remote {
                    Kind::Approve => out.push(change("peer_approved", peer, None)),
                    Kind::Decline => out.push(change("peer_declined", peer, None)),
                    Kind::Unknown => {}
                }
            }
        }
        match (b.and_then(|b| b.pairing), a.and_then(|a| a.pairing)) {
            (None, Some(_)) => out.push(change("pairing_established", peer, None)),
            (Some(_), None) => out.push(change("pairing_ended", peer, None)),
            (Some(x), Some(y)) if x != y => {
                out.push(change("pairing_ended", peer, None));
                out.push(change("pairing_established", peer, None));
            }
            _ => {}
        }
        if membership == Some((true, false)) {
            out.push(change("peer_removed", peer, None));
        }
    }
    for (k, s) in before.grants.difference(&after.grants) {
        out.push(change("service_disabled", Some(*k), Some(*s)));
    }
    for (k, s) in after.grants.difference(&before.grants) {
        out.push(change("service_enabled", Some(*k), Some(*s)));
    }
    for (k, s) in after.exclusions.difference(&before.exclusions) {
        out.push(change("service_default_excluded", Some(*k), Some(*s)));
    }
    for (k, s) in before.exclusions.difference(&after.exclusions) {
        out.push(change(
            "service_default_exclusion_cleared",
            Some(*k),
            Some(*s),
        ));
    }
    for s in after.defaults.difference(&before.defaults) {
        out.push(change("service_default_enabled", None, Some(*s)));
    }
    for s in before.defaults.difference(&after.defaults) {
        out.push(change("service_default_disabled", None, Some(*s)));
    }
    if after.halted && !before.halted {
        out.push(change("membership_halted", None, None));
    }
    out
}

// ----------------------------------------------------------------- sessions

/// One logged connection. Shared by reference across the connection's
/// futures; the first `end` is recorded, and a session dropped without one
/// ends as `interrupted`.
pub struct Tracked<'a> {
    inner: Mutex<TrackedInner<'a>>,
}

struct TrackedInner<'a> {
    session: Session<'a>,
    ended: bool,
    /// Why authority ended, when this device saw it end.
    authority: Option<&'static str>,
}

impl<'a> Tracked<'a> {
    fn new(session: Session<'a>) -> Self {
        Self {
            inner: Mutex::new(TrackedInner {
                session,
                ended: false,
                authority: None,
            }),
        }
    }

    /// Set the peer (with its pinned alias, if any).
    pub fn peer(&self, log: &DeviceLog, key: &EndpointKey) {
        if let Some(peer) = id(key) {
            let name = log.alias(key);
            lock(&self.inner).session.identify(peer, name);
        }
    }

    pub fn service(&self, service: Service) {
        lock(&self.inner).session.set_service(service);
    }

    /// The service is running.
    pub fn connected(&self) {
        let mut t = lock(&self.inner);
        if !t.ended {
            t.session.connected();
        }
    }

    /// Remember why this device ended the authority (for `end_served`).
    pub fn authority_ended(&self, why: &Refusal) {
        lock(&self.inner).authority = Some(authority_end_reason(why));
    }

    pub fn end(&self, reason: &'static str, exit_code: Option<i32>) {
        let mut t = lock(&self.inner);
        if !t.ended {
            t.ended = true;
            t.session.end(reason, exit_code);
        }
    }

    /// End with the reason for how a served connection ended.
    pub fn end_served(&self, ended: &Ended) {
        let authority = lock(&self.inner).authority;
        let (reason, code) = match ended {
            Ended::AuthorityEnd(_) => (authority.unwrap_or("authorization_ended"), None),
            other => ended_reason(other),
        };
        self.end(reason, code);
    }
}

// ------------------------------------------------------------------ reasons

/// Fixed reason for a refusal before or at authorization.
pub fn refusal_reason(r: &Refusal) -> &'static str {
    match r {
        Refusal::Terminal => "device_revoked",
        Refusal::NotMember(_) => "not_member",
        Refusal::NotApproved | Refusal::NotPaired => "pairing_required",
        Refusal::RemoteDeclined => "peer_declined",
        Refusal::StaleDecision | Refusal::ConflictingDecision => "stale_decision",
        Refusal::StaleExchange(_) => "stale_exchange",
        Refusal::WrongGroup => "wrong_network",
        Refusal::WrongProtocol => "wrong_protocol",
        Refusal::ConnectionClosed => "peer_disconnected",
        Refusal::ServiceNotGranted => "service_not_enabled",
        Refusal::Stopping => "device_stopping",
        Refusal::Invalidated(_) => "pairing_ended",
    }
}

/// Fixed reason for an authorization or dial failure.
pub fn pair_error_reason(e: &PairError) -> &'static str {
    match e {
        PairError::Refused(r) => refusal_reason(r),
        PairError::Malformed(_) => "malformed_exchange",
        PairError::Alias(_) => "invalid_alias",
        PairError::OwnedElsewhere => "owned_elsewhere",
        PairError::Local(_) => "setup_failed",
    }
}

/// Fixed reason for authority ending during a session.
pub fn authority_end_reason(r: &Refusal) -> &'static str {
    match r {
        Refusal::ServiceNotGranted => "grant_removed",
        Refusal::NotMember(_) => "peer_removed",
        Refusal::NotApproved
        | Refusal::NotPaired
        | Refusal::RemoteDeclined
        | Refusal::Invalidated(_) => "pairing_ended",
        other => refusal_reason(other),
    }
}

/// Fixed reason (and shell exit code) for how a served connection ended.
pub fn ended_reason(e: &Ended) -> (&'static str, Option<i32>) {
    match e {
        Ended::WrongProtocol => ("wrong_protocol", None),
        Ended::NotAuthorized(_) => ("pairing_required", None),
        Ended::BadRequest => ("service_request_failed", None),
        Ended::Refused(r) => (r.reason(), None),
        Ended::AuthorityEnd(_) => ("authorization_ended", None),
        Ended::PeerDisconnected => ("peer_disconnected", None),
        Ended::ShellExit(code) => ("shell_exit", Some(*code)),
        Ended::ShellError => ("shell_io_error", None),
        Ended::StreamClosed => ("stream_closed", None),
        Ended::TargetError => ("target_io_error", None),
    }
}

/// Operation name, peer selector and service of a control command.
pub fn operation(r: &ControlRequest) -> (&'static str, Option<&str>, Option<Service>) {
    match r {
        ControlRequest::Status => ("status", None, None),
        ControlRequest::Peers => ("list_peers", None, None),
        ControlRequest::Invite => ("issue_invite", None, None),
        ControlRequest::Approve { peer, .. } => ("approve", Some(peer), None),
        ControlRequest::Decline { peer } => ("decline", Some(peer), None),
        ControlRequest::Revoke { peer } => ("revoke", Some(peer), None),
        ControlRequest::Enable { peer, service } => ("enable", Some(peer), Some(*service)),
        ControlRequest::Disable { peer, service } => ("disable", Some(peer), Some(*service)),
        ControlRequest::SetDefault { service, enabled } => (
            if *enabled {
                "enable_default"
            } else {
                "disable_default"
            },
            None,
            Some(*service),
        ),
        ControlRequest::Exclude { peer, service } => ("exclude", Some(peer), Some(*service)),
        ControlRequest::ClearExclusion { peer, service } => {
            ("clear_exclusion", Some(peer), Some(*service))
        }
        ControlRequest::Shell { peer, .. } => ("shell", Some(peer), Some(Service::Shell)),
        ControlRequest::Connect { peer, service, .. } => ("connect", Some(peer), Some(*service)),
        ControlRequest::Expose { peer, service, .. } => ("expose", Some(peer), Some(*service)),
    }
}

/// Audit outcome and reason of a management reply.
pub fn reply_outcome(r: &ControlReply) -> (&'static str, Option<&'static str>) {
    match r {
        ControlReply::Error(_) => ("denied", Some("command_rejected")),
        ControlReply::CutOff {
            pairing_error,
            removal_error,
        } => (
            "allowed",
            if pairing_error.is_some() {
                Some("pairing_save_failed")
            } else if removal_error.is_some() {
                Some("network_removal_not_staged")
            } else {
                None
            },
        ),
        _ => ("allowed", None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Refusal as WireRefusal;
    use std::num::NonZeroU16;

    const OWN: EndpointKey = [1; 32];
    const BOB: EndpointKey = [2; 32];
    const CAROL: EndpointKey = [3; 32];

    fn tcp(p: u16) -> Service {
        Service::Tcp(NonZeroU16::new(p).unwrap())
    }

    fn peer(alias: &str, local: Kind, order: u64, remote: Kind, pairing: Option<u64>) -> PeerSnap {
        PeerSnap {
            alias: alias.into(),
            local,
            local_order: order,
            remote,
            remote_order: 0,
            pairing,
        }
    }

    fn events(before: &Snapshot, after: &Snapshot) -> Vec<(&'static str, Option<u8>)> {
        changes(Some(&OWN), before, after)
            .into_iter()
            .map(|c| (c.event, c.peer.map(|k| k[0])))
            .collect()
    }

    #[test]
    fn membership_decisions_and_pairing_changes_map_to_legacy_events() {
        let before = Snapshot {
            roster: Some([OWN, BOB].into()),
            ..Snapshot::default()
        };
        let mut after = before.clone();
        after.roster = Some([OWN, BOB, CAROL].into());
        after
            .peers
            .insert(BOB, peer("bob", Kind::Approve, 1, Kind::Unknown, None));
        assert_eq!(
            events(&before, &after),
            vec![("approval_granted", Some(2)), ("peer_joined", Some(3))]
        );

        // The peer's approval arrives on an exchange, which pairs.
        let mut paired = after.clone();
        paired.peers.get_mut(&BOB).unwrap().remote = Kind::Approve;
        paired.peers.get_mut(&BOB).unwrap().pairing = Some(1);
        assert_eq!(
            events(&after, &paired),
            vec![("peer_approved", Some(2)), ("pairing_established", Some(2))]
        );
        // Unchanged state logs nothing.
        assert!(events(&paired, &paired.clone()).is_empty());

        // A re-pair ends the old pairing and establishes the new one.
        let mut repaired = paired.clone();
        repaired.peers.get_mut(&BOB).unwrap().pairing = Some(2);
        assert_eq!(
            events(&paired, &repaired),
            vec![("pairing_ended", Some(2)), ("pairing_established", Some(2))]
        );

        // A decline (new local order) ends the pairing; removal follows.
        let mut declined = repaired.clone();
        let b = declined.peers.get_mut(&BOB).unwrap();
        (b.local, b.local_order, b.pairing) = (Kind::Decline, 2, None);
        declined.roster = Some([OWN, CAROL].into());
        assert_eq!(
            events(&repaired, &declined),
            vec![
                ("approval_declined", Some(2)),
                ("pairing_ended", Some(2)),
                ("peer_removed", Some(2)),
            ]
        );

        // Re-approving with a new order is logged even with the same kind.
        let mut again = paired.clone();
        again.peers.get_mut(&BOB).unwrap().local_order = 3;
        assert_eq!(events(&paired, &again), vec![("approval_granted", Some(2))]);
    }

    #[test]
    fn own_removal_halts_and_unknown_rosters() {
        let before = Snapshot {
            roster: Some([OWN, BOB].into()),
            ..Snapshot::default()
        };
        let after = Snapshot {
            roster: Some([BOB].into()),
            halted: true,
            ..Snapshot::default()
        };
        assert_eq!(
            events(&before, &after),
            vec![("device_revoked", None), ("membership_halted", None)]
        );
        // Without a roster on either side, membership is not compared.
        let unknown = Snapshot::default();
        assert!(events(&before, &unknown).is_empty());
        assert!(
            events(&unknown, &after)
                .iter()
                .all(|e| e.0 != "peer_joined")
        );
    }

    #[test]
    fn grants_defaults_and_exclusions() {
        let before = Snapshot {
            grants: [(BOB, Service::Shell)].into(),
            defaults: [tcp(80)].into(),
            ..Snapshot::default()
        };
        let after = Snapshot {
            grants: [(BOB, tcp(22))].into(),
            defaults: [Service::Shell].into(),
            exclusions: [(BOB, Service::Shell)].into(),
            ..Snapshot::default()
        };
        let got: Vec<_> = changes(Some(&OWN), &before, &after)
            .into_iter()
            .map(|c| (c.event, c.service))
            .collect();
        assert_eq!(
            got,
            vec![
                ("service_disabled", Some(Service::Shell)),
                ("service_enabled", Some(tcp(22))),
                ("service_default_excluded", Some(Service::Shell)),
                ("service_default_enabled", Some(Service::Shell)),
                ("service_default_disabled", Some(tcp(80))),
            ]
        );
        let got: Vec<_> = changes(Some(&OWN), &after, &before)
            .into_iter()
            .map(|c| c.event)
            .collect();
        assert!(got.contains(&"service_default_exclusion_cleared"));
    }

    #[test]
    fn reasons_are_fixed_codes() {
        assert_eq!(
            ended_reason(&Ended::NotAuthorized(
                "Refused(NotApproved) with detail".into()
            )),
            ("pairing_required", None)
        );
        assert_eq!(ended_reason(&Ended::ShellExit(5)), ("shell_exit", Some(5)));
        assert_eq!(
            ended_reason(&Ended::Refused(WireRefusal::ServiceNotEnabled)).0,
            "service_not_enabled"
        );
        assert_eq!(
            authority_end_reason(&Refusal::Invalidated("secret detail".into())),
            "pairing_ended"
        );
        assert_eq!(
            authority_end_reason(&Refusal::ServiceNotGranted),
            "grant_removed"
        );
        assert_eq!(
            pair_error_reason(&PairError::Local("raw io error".into())),
            "setup_failed"
        );
    }

    fn lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn sessions_record_one_end_and_the_pinned_alias() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(EVENT_FILE);
        let log = DeviceLog::open(&path).unwrap();
        log.set_own(OWN);
        let bob = *iroh::SecretKey::from_bytes(&[9; 32]).public().as_bytes();
        let mut st = PairingState::default();
        st.peers.push(super::super::pairing::PeerRecord {
            endpoint: bob,
            alias: "bob".into(),
            local: Decision::Decline,
            local_order: 1,
            remote: Decision::Unknown,
            remote_order: 0,
            pairing: None,
        });
        let obs = |st: &PairingState| {
            Some(Observed {
                pairing: st.clone(),
                roster: None,
                halted: None,
            })
        };
        log.observe(|| obs(&st)); // baseline: nothing logged
        {
            let t = log.inbound(EndpointId::from_bytes(&bob).unwrap());
            t.service(Service::Shell);
            t.connected();
            t.end_served(&Ended::ShellExit(3));
            t.end("interrupted", None);
            t.connected();
        }
        {
            let t = log.outbound(tcp(22));
            t.peer(&log, &bob);
        } // dropped without an end
        log.control("approve", "allowed", Some(bob), None, None);
        st.peers[0].local = Decision::Approve { approval: [7; 32] };
        st.peers[0].local_order = 2;
        log.observe(|| obs(&st));

        let got = lines(&path);
        let ev: Vec<&str> = got.iter().map(|v| v["event"].as_str().unwrap()).collect();
        assert_eq!(
            ev,
            vec![
                "connected",
                "disconnected",
                "connection_failed",
                "local_control",
                "approval_granted",
            ]
        );
        assert_eq!(got[0]["direction"], "inbound");
        assert_eq!(got[0]["peer_name"], "bob");
        assert_eq!(got[1]["reason"], "shell_exit");
        assert_eq!(got[1]["exit_code"], 3);
        assert_eq!(got[2]["direction"], "outbound");
        assert_eq!(got[2]["reason"], "interrupted");
        assert_eq!(got[2]["peer_name"], "bob");
        assert_eq!(got[2]["service"], "tcp:22");
        let bob_id = EndpointId::from_bytes(&bob).unwrap().to_string();
        assert_eq!(got[3]["target_id"], bob_id.as_str());
        assert_eq!(got[4]["peer_id"], bob_id.as_str());
        // The approval value never reaches the log.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("[7,7") && !raw.contains("0707"), "{raw}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn reachability_is_logged_on_change_and_revocation_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(EVENT_FILE);
        let log = DeviceLog::open(&path).unwrap();
        let synced = |stop| Synced {
            requests: Ok(vec![]),
            staged: None,
            settle: Ok(super::super::membership::Settle::NoCandidate),
            published: None,
            advanced: vec![],
            stop,
            replies: Ok(vec![]),
        };
        log.membership_pass(&synced(Stop::UpToDate));
        log.membership_pass(&synced(Stop::UpToDate));
        log.membership_pass(&synced(Stop::Unavailable("relay down".into())));
        log.membership_pass(&synced(Stop::Unavailable("relay down".into())));
        log.membership_pass(&synced(Stop::Cancelled));
        log.membership_pass(&synced(Stop::Terminal));
        log.membership_pass(&synced(Stop::Terminal));
        let got = lines(&path);
        let ev: Vec<_> = got
            .iter()
            .map(|v| (v["event"].as_str().unwrap(), v["outcome"].as_str()))
            .collect();
        assert_eq!(
            ev,
            vec![
                ("membership_sync", Some("allowed")),
                ("membership_sync", Some("failed")),
                ("device_revoked", None),
                ("membership_sync", Some("allowed")),
            ]
        );
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("relay down")
        );
        // A disabled log writes nothing anywhere.
        DeviceLog::disabled().started();
    }
}
