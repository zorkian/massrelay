//! EXPERIMENTAL private service dispatch: the narrow daemon layer between
//! completed private-ALPN Iroh connections, the pairing registry and the
//! existing `terminal`, `tcp`, `udp` and `tunnel` payload code.
//!
//! # One connection, one stream, one registered lifetime
//!
//! 1. The destination serves a connection only if its handshake completed on
//!    `SERVICE_ALPN`; anything else (the legacy `massrelay/service/1`
//!    included) is closed before a stream is read.
//! 2. The dialer opens exactly one bi-stream. On it, in order: the roster
//!    gate (a key outside the accepted roster gets nothing, not even the
//!    group tag), the fresh mutual-consent offer and confirmation (each send
//!    guarded against a concurrent local decline, each record read bounded
//!    by its exact encoded size), then one fixed-size request and its reply.
//!    A ping request echoes fixed-size QUIC datagrams while pairing authority
//!    lasts. Service requests carry their payload on the stream.
//! 3. The authorization is registered with the owner's session registry in
//!    the same critical section that commits the exchange, and stays
//!    registered until the connection's final teardown. A decline, cutoff,
//!    learned or own removal, re-pair or owner shutdown therefore ends the
//!    connection at any point: while the request is partial, while a reply
//!    is in flight, while serving, and while the last frames drain.
//! 4. `Peers::open` evaluates current policy for that authorization; then
//!    the privileged local step runs inside `SessionHandle::start`: shell
//!    spawn; TCP connect to the offering side's target; UDP resolve, then
//!    bind, connect and first send of every association. A refusal is sent
//!    before any of them.
//! 5. While serving, every native handoff is guarded: each TCP write and
//!    the half-close (`SessionHandle::guard`) and each later UDP datagram
//!    (`SessionHandle::start`) is handed to the OS only from a poll that
//!    holds the registry lock after re-checking the session, so nothing is
//!    handed over after a cutoff transition returns. Shell input takes the
//!    same path: the private shell runs on `pty`'s native PTY (a
//!    nonblocking PTY master on Unix, a ConPTY whose input pipe is in
//!    nonblocking mode on Windows), each input chunk is one guarded
//!    nonblocking write straight from the peer's frame (no writer thread,
//!    nothing queued in between). Unix resizes with one guarded ioctl.
//!    Windows keeps the dimensions set when the session opens. Bytes already
//!    handed to the OS cannot be withdrawn. Other platforms refuse private
//!    shells.
//! 6. On the session's end the serving future is dropped (copy stopped, TCP
//!    and UDP sockets closed, PTY input closed), the connection is closed
//!    with `CLOSE_AUTHORITY_ENDED`, and the PTY reaper (woken by the drop)
//!    kills and reaps the shell before the connection's task ends. The
//!    runtime's stop bounds that wait and reports a surviving reaper.
//! 7. After a finished reply or payload, the destination waits at most
//!    `wire::RPC_TIMEOUT` for the dialer to read the final frames and close,
//!    then closes itself. The authorization and the exact service session
//!    stay registered through that drain: any end of authority, including a
//!    grant or default change for that service, closes at once.
//!
//! # SSH
//!
//! An SSH request is admitted under the shell grant. Its tunnel (`super::ssh`) reaches only
//! the installed system SSH server on `127.0.0.1`: the connect and every write run under the
//! guard, the client's key is authorized only while the session is, and it is withdrawn
//! before the connection closes. The system server decides who may log in.
//!
//! # Early data
//!
//! Safety against replayed 0-RTT data does not rest on the stream's early
//! data flag (which is checked too, as defence in depth). The destination
//! only accepts connections whose handshake completed, and reads the request
//! only after this device's fresh nonce was confirmed by the peer on that
//! connection's channel binding: a replayed or early request cannot carry
//! that confirmation.
//!
//! # Bounds
//!
//! Every peer frame is read with the largest length its format allows: the
//! request and exchange records by their exact size, the reply by the
//! largest private reply (`max_reply_len`), shell input by the terminal
//! chunk, TCP by `tcp::MAX_FRAME` (a destination's failure text is cut to
//! fit) and UDP by `udp::MAX_FRAME`.
//!
//! Replies reuse `wire::ServiceReply`; shell, TCP and UDP payload frames are
//! the existing ones. The request record and ALPN are experimental.
//!
//! # Control entry points
//!
//! `Node` exposes the local operations the private runtime's authenticated
//! control channel calls. It owns the profile's runtime `Owner`, so control,
//! service dispatch and membership advancement share one session registry,
//! and it never hands out the raw `Device`: every mutation goes through the
//! registry. It does not manage OS services, installation or user state.
//!
//! # Parity gaps against the legacy daemon
//!
//! Persistent grants and defaults forward to loopback. Temporary exposures
//! can choose a local target. Connections are logged through `super::audit` with
//! fixed event reasons.

use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};

use crate::tunnel::{self, Broken};
use crate::wire::{self, Refusal as WireRefusal, Service, ServiceReply};
use crate::{tcp, terminal, udp};

use super::audit::{self, DeviceLog, Tracked};
use super::pty;
use super::routes::Routes;
use super::ssh;
use super::versions::{self, Exchange, Observations, PeerVersions};

use super::binding::EndpointKey;
use super::codec::{Dec, Enc, hex};
use super::mailbox::Mailbox;
use super::membership::{
    Advance, Device, Dispatch, Error as MembershipError, Gate, MemberView, Polled, Settle, Stop,
};
use super::pairing::{
    Activity, AdmissionHold, Approved, Authorization, Cutoff, Exposure, Owner, PAIRING_ALPN,
    PairError, PairingState, Peers, Refusal, SessionHandle, read_bounded,
};

/// ALPN of the private service listener.
pub const SERVICE_ALPN: &[u8] = PAIRING_ALPN;
/// Connection close reasons.
pub const CLOSE_NOT_AUTHORIZED: &[u8] = b"private pairing required";
pub const CLOSE_WRONG_PROTOCOL: &[u8] = b"private service protocol required";
pub const CLOSE_AUTHORITY_ENDED: &[u8] = b"authorization ended";
pub const CLOSE_DONE: &[u8] = b"done";

const REQUEST_VERSION: u8 = 1;
const REQUEST_LEN: usize = 8;
const PING_REQUEST: [u8; REQUEST_LEN] = [REQUEST_VERSION, 6, 0, 0, 0, 0, 0, 0];
const PING_BYTES: usize = 16;

// Every refusal text a private destination sends. The reply bound is the
// largest encoding of any of them, so it is a property of the format.
const MSG_NOT_AUTHORIZED: &str = "not authorized on this device";
const MSG_SHELL: &str = "could not start the shell";
const MSG_SHELL_UNSUPPORTED: &str = "private shells are not supported on this platform";
const MSG_ELEVATED_UNSUPPORTED: &str = "elevated shells are only available on Windows";
#[cfg(windows)]
const MSG_ELEVATED_UNAVAILABLE: &str = "this device cannot start an administrator shell";
const MSG_CONNECT: &str = "could not connect to the target";
const MSG_RESOLVE: &str = "could not resolve the target";
const MSG_ENDED: &str = "authorization ended";
const MSG_SSH_SETUP: &str = "system SSH is not set up; run massrelay install there";
const MSG_SSH_SERVER: &str = "no SSH server answers on 127.0.0.1 on that device";
const MSG_SSH_KEY: &str = "could not authorize the SSH key on that device";
const MSG_SSH_CUSTOM_SHELL: &str = "this device uses a custom shell; SSH access is disabled";
const REPLY_MESSAGES: &[&str] = &[
    MSG_NOT_AUTHORIZED,
    MSG_SHELL,
    MSG_SHELL_UNSUPPORTED,
    MSG_ELEVATED_UNSUPPORTED,
    #[cfg(windows)]
    MSG_ELEVATED_UNAVAILABLE,
    MSG_CONNECT,
    MSG_RESOLVE,
    MSG_ENDED,
    MSG_SSH_SETUP,
    MSG_SSH_SERVER,
    MSG_SSH_KEY,
    MSG_SSH_CUSTOM_SHELL,
];

/// Largest encoded private service reply.
pub fn max_reply_len() -> usize {
    let mut replies = vec![ServiceReply::Ready];
    for refusal in [
        WireRefusal::PairingRequired,
        WireRefusal::ServiceNotEnabled,
        WireRefusal::TargetUnavailable,
    ] {
        for message in REPLY_MESSAGES {
            replies.push(ServiceReply::Refused {
                refusal,
                message: (*message).into(),
            });
        }
    }
    replies
        .iter()
        .map(|r| serde_json::to_vec(r).expect("reply encodes").len())
        .max()
        .expect("non-empty")
}

/// Largest payload frame a private destination sends for `service`.
pub fn max_payload_frame(service: Service) -> usize {
    match service {
        Service::Shell => terminal::MAX_OUTPUT_FRAME,
        Service::Tcp(_) => tcp::MAX_FRAME,
        Service::Udp(_) => udp::MAX_FRAME,
    }
}

/// The one service request on a private connection (experimental record):
/// the service only, never a target, network or pairing value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateRequest {
    pub service: Service,
    /// Initial shell columns and rows.
    pub terminal: Option<(u16, u16)>,
    pub elevated: bool,
}

impl PrivateRequest {
    fn encode(&self) -> Vec<u8> {
        let (kind, port) = match self.service {
            // Kind 1 was allowed to inherit the runtime's privileges. Keep
            // it receive-only so old hosts cannot misread either request.
            Service::Shell if self.elevated => (5, 0),
            Service::Shell => (4, 0),
            Service::Tcp(p) => (2, p.get()),
            Service::Udp(p) => (3, p.get()),
        };
        let (cols, rows) = self.terminal.unwrap_or((0, 0));
        let mut e = Enc::new();
        e.u8(REQUEST_VERSION)
            .u8(kind)
            .fixed(&port.to_be_bytes())
            .fixed(&cols.to_be_bytes())
            .fixed(&rows.to_be_bytes());
        e.finish()
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut d = Dec::new(b);
        if d.u8().ok()? != REQUEST_VERSION {
            return None;
        }
        let kind = d.u8().ok()?;
        let port = u16::from_be_bytes(d.fixed().ok()?);
        let cols = u16::from_be_bytes(d.fixed().ok()?);
        let rows = u16::from_be_bytes(d.fixed().ok()?);
        d.end().ok()?;
        let service = match kind {
            1 | 4 | 5 if port == 0 => Service::Shell,
            2 => Service::Tcp(std::num::NonZeroU16::new(port)?),
            3 => Service::Udp(std::num::NonZeroU16::new(port)?),
            _ => return None,
        };
        let terminal = (service == Service::Shell && cols > 0 && rows > 0).then_some((cols, rows));
        Some(Self {
            service,
            terminal,
            elevated: kind == 5,
        })
    }
}

#[cfg(test)]
#[test]
fn shell_privilege_survives_framing_and_legacy_means_regular() {
    let regular = PrivateRequest {
        service: Service::Shell,
        terminal: Some((80, 24)),
        elevated: false,
    };
    let elevated = PrivateRequest {
        elevated: true,
        ..regular
    };
    // Deployed peers accept only 1 (shell), 2 (TCP), or 3 (UDP).
    assert!(regular.encode()[1] > 3);
    assert!(elevated.encode()[1] > 3);
    assert_eq!(PrivateRequest::decode(&regular.encode()), Some(regular));
    assert_eq!(PrivateRequest::decode(&elevated.encode()), Some(elevated));
    let legacy = [1, 1, 0, 0, 0, 80, 0, 24];
    assert_eq!(PrivateRequest::decode(&legacy), Some(regular));
}

/// Why a served connection ended (for logs and tests).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ended {
    WrongProtocol,
    NotAuthorized(String),
    BadRequest,
    Refused(WireRefusal),
    AuthorityEnd(String),
    PeerDisconnected,
    ShellExit(i32),
    ShellError,
    StreamClosed,
    TargetError,
}

impl Ended {
    /// Whether the destination finished its side and should let the final
    /// frames drain before closing.
    fn drains(&self) -> bool {
        matches!(
            self,
            Ended::Refused(_) | Ended::ShellExit(_) | Ended::StreamClosed | Ended::TargetError
        )
    }
}

fn wire_refusal(e: &PairError) -> WireRefusal {
    match e {
        PairError::Refused(Refusal::ServiceNotGranted) => WireRefusal::ServiceNotEnabled,
        _ => WireRefusal::PairingRequired,
    }
}

async fn refuse(tx: &mut SendStream, refusal: WireRefusal, message: &'static str) {
    debug_assert!(REPLY_MESSAGES.contains(&message));
    let reply = ServiceReply::Refused {
        refusal,
        message: message.into(),
    };
    if wire::send(tx, reply).await.is_ok() {
        let _ = tx.finish();
    }
}

/// Invite requests processed, and the Add staged for one reserved invite.
type Admitted = (
    Result<Vec<Polled>, PairError>,
    Option<Result<(), PairError>>,
);

/// One membership maintenance pass (see `Node::sync_membership`).
#[derive(Debug)]
pub struct Synced {
    /// Invite request queues processed (reservations, rejections, acknowledgements).
    pub requests: Result<Vec<Polled>, PairError>,
    /// A pending removal or reserved admission staged when the journal was free.
    pub staged: Option<Result<(), PairError>>,
    pub settle: Result<Settle, PairError>,
    pub published: Option<Result<(), String>>,
    pub advanced: Vec<Advance>,
    pub stop: Stop,
    pub replies: Result<Vec<Dispatch>, PairError>,
}

/// The private daemon layer for one profile.
pub struct Node<M: Mailbox> {
    device: Device<M>,
    owner: Owner,
    /// This profile's endpoint key; every endpoint used with it must match.
    endpoint: EndpointKey,
    /// Shell executable offered to peers (`None`: the platform default).
    shell: Option<PathBuf>,
    /// Held by every native PTY worker until its shell is reaped.
    workers: Arc<()>,
    log: Arc<DeviceLog>,
    routes: Routes,
    versions: Arc<PeerVersions>,
    /// Tunnels into this device's system SSH server.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    ssh: ssh::Destination,
}

impl<M: Mailbox + Send + Sync + 'static> Node<M> {
    pub fn new(
        device: Device<M>,
        owner: Owner,
        shell: Option<PathBuf>,
    ) -> Result<Arc<Self>, PairError> {
        Self::with_log(device, owner, shell, Arc::new(DeviceLog::disabled()))
    }

    /// `new`, recording connections and state changes to `log`.
    pub fn with_log(
        device: Device<M>,
        owner: Owner,
        shell: Option<PathBuf>,
        log: Arc<DeviceLog>,
    ) -> Result<Arc<Self>, PairError> {
        Peers::new(&device, &owner)?;
        let endpoint = device.state()?.endpoint;
        log.set_own(endpoint);
        let routes = Routes::open(device.store().dir());
        let versions = Arc::new(PeerVersions::open(device.store().dir()));
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        let ssh = ssh::Destination::new(&endpoint, device.store().dir());
        Ok(Arc::new(Self {
            device,
            owner,
            endpoint,
            shell,
            workers: Arc::new(()),
            log,
            routes,
            versions,
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            ssh,
        }))
    }

    pub fn log(&self) -> &DeviceLog {
        &self.log
    }

    pub(super) fn version_observations(&self) -> Observations {
        self.versions.observations()
    }

    /// Set how long a tunnel's client key stays authorized, and withdraw the keys an
    /// earlier run of this profile left behind. Only before anything is served, within the
    /// async runtime.
    pub(super) fn prepare_ssh(&self, lease: Duration) {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        {
            self.ssh.set_lifetime(lease);
            self.ssh.purge();
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        let _ = lease;
    }

    /// Give keys of ended tunnels still being withdrawn at most `grace`.
    pub(super) async fn close_ssh(&self, grace: Duration) {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        self.ssh.close(grace).await;
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        let _ = grace;
    }

    /// Whether the connection with exactly these ends, from this device to its own SSH
    /// server, is one of this runtime's open tunnels.
    pub(super) fn has_ssh_tunnel(&self, client: SocketAddrV4, server: SocketAddrV4) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        return self.ssh.owns(client, server);
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = (client, server);
            false
        }
    }

    pub async fn watch_routes(&self, conn: &Connection) {
        self.routes.watch(conn).await;
    }

    fn peers(&self) -> Peers<'_, '_, M> {
        Peers::new(&self.device, &self.owner).expect("checked in Node::new")
    }

    pub fn endpoint_key(&self) -> EndpointKey {
        self.endpoint
    }

    /// Refuse an Iroh endpoint whose identity is not this profile's.
    pub fn check_endpoint(&self, endpoint: &Endpoint) -> Result<(), PairError> {
        if endpoint.id().as_bytes() != &self.endpoint {
            return Err(PairError::Local(format!(
                "endpoint {} is not this profile's endpoint {}",
                hex(endpoint.id().as_bytes()),
                hex(&self.endpoint)
            )));
        }
        Ok(())
    }

    pub fn live_sessions(&self) -> usize {
        self.owner.live_sessions()
    }

    /// Permanently stop: under the registry lock the owner moves to
    /// stopping and every session and negotiation ends; from then on no
    /// exchange commits, no service starts, no control mutation applies and
    /// no gated membership step runs (see `Owner::retire`). Then the
    /// mailbox's graceful stop seam is asked to end in-flight calls.
    pub fn retire_all(&self, why: &str) {
        self.owner.retire(why);
        self.device.mailbox().shutdown();
    }

    pub fn stopping(&self) -> bool {
        self.owner.stopping()
    }

    /// Close admission if nothing is live (see `Owner::hold_if_idle`).
    pub fn hold_if_idle(&self) -> Result<AdmissionHold, Activity> {
        self.owner.hold_if_idle()
    }

    pub fn update_hold_state(&self) -> Option<bool> {
        self.owner.update_hold_state()
    }

    /// Permanently stop through a hold that is still in force (see
    /// `AdmissionHold::retire`), then ask the mailbox to end calls in flight.
    /// Returns whether this call retired the owner.
    pub fn retire_held(&self, hold: &AdmissionHold, why: &str) -> bool {
        let retired = hold.retire(why);
        if retired {
            self.device.mailbox().shutdown();
        }
        retired
    }

    /// Native PTY workers (reapers) still running, including any whose
    /// session already ended.
    pub fn native_workers(&self) -> usize {
        Arc::strong_count(&self.workers) - 1
    }

    // ---------------------------------------------------- control entry points

    pub(super) fn rename_self(&self, name: &str) -> anyhow::Result<()> {
        self.peers()
            .while_running(|| versions::rename_self(&self.device, name))
            .map_err(|error| anyhow::anyhow!("{error:?}"))?
    }

    pub fn approve(
        &self,
        alias: &str,
        peer: &EndpointKey,
        reapprove: bool,
    ) -> Result<Approved, PairError> {
        self.peers().approve(alias, peer, reapprove)
    }

    pub fn rename(&self, selector: &str, alias: &str) -> Result<bool, PairError> {
        self.peers().rename(selector, alias)
    }

    pub fn decline(&self, peer: &EndpointKey) -> Result<(), PairError> {
        self.peers().decline(peer)
    }

    /// Durable local cutoff first (only its failure fails this), signalled
    /// to every session before the pairing save and network removal, which
    /// are reported separately.
    pub fn cutoff(&self, peer: &EndpointKey) -> Result<Cutoff, PairError> {
        self.peers().cutoff(peer)
    }

    pub fn grant(&self, peer: &EndpointKey, service: Service) -> Result<bool, PairError> {
        self.peers().grant(peer, service)
    }

    pub fn revoke_grant(&self, peer: &EndpointKey, service: Service) -> Result<bool, PairError> {
        self.peers().revoke_grant(peer, service)
    }

    pub fn set_default(&self, service: Service, enabled: bool) -> Result<bool, PairError> {
        self.peers().set_default(service, enabled)
    }

    /// Expose one port to one paired peer until the handle drops.
    pub fn expose(
        &self,
        peer: &EndpointKey,
        service: Service,
        target: Option<String>,
    ) -> Result<Exposure, PairError> {
        self.peers().expose(peer, service, target)
    }

    /// Live exposures: (peer, service, owner-chosen target).
    pub fn exposures(&self) -> Vec<(EndpointKey, Service, Option<String>)> {
        self.peers().exposures()
    }

    pub fn exclude(&self, peer: &EndpointKey, service: Service) -> Result<bool, PairError> {
        self.peers().exclude(peer, service)
    }

    pub fn clear_exclusion(&self, peer: &EndpointKey, service: Service) -> Result<bool, PairError> {
        self.peers().clear_exclusion(peer, service)
    }

    pub fn pairing_state(&self) -> Result<PairingState, PairError> {
        self.peers().state()
    }

    /// Accepted roster (endpoint keys only; names carry no authority).
    pub fn roster(&self) -> Result<Vec<EndpointKey>, PairError> {
        Ok(self.device.roster()?)
    }

    pub fn member_view(&self) -> Result<MemberView, PairError> {
        let guard = self.device.store().lock()?;
        Ok(self.device.member_view(&guard)?)
    }

    /// Issue a membership invite. The membership pass admits its joiner.
    pub fn issue_invite(&self) -> Result<Vec<u8>, PairError> {
        Ok(self
            .peers()
            .while_running(|| self.device.issue_invite())??)
    }

    /// Catch up membership; each removal and its sessions' end are one step.
    pub fn advance_membership(&self) -> Result<(Vec<Advance>, Stop), PairError> {
        self.peers().advance_membership()
    }

    pub fn settle(&self) -> Result<Settle, PairError> {
        self.peers().settle()
    }

    /// The recorded membership halt, if any.
    pub fn halt(&self) -> Result<Option<String>, PairError> {
        Ok(self.device.state()?.halt.map(|h| format!("{h:?}")))
    }

    /// Process invite request queues, then stage the Add for one reserved
    /// invite that is not yet admitted, when no other candidate is journaled.
    /// The reservation is the issuer's durable verdict on the request; the
    /// Add is published and settled by the rest of the pass, and the sealed
    /// reply is dispatched only after it is accepted.
    ///
    /// Queue reads and acknowledgements, the verdicts and the staging all go
    /// through the owner's gate, so none of them starts or is recorded once
    /// the runtime is stopping.
    fn admit(&self, peers: &Peers<'_, '_, M>) -> Admitted {
        if self.stopping() {
            return (Err(PairError::Refused(Refusal::Stopping)), None);
        }
        let requests = self
            .device
            .poll_join_requests_gated(peers)
            .map_err(PairError::from);
        let st = match self.device.state() {
            Ok(st) => st,
            Err(e) => return (requests, Some(Err(e.into()))),
        };
        if st.journal.is_some() || st.halt.is_some() || st.terminal.is_some() {
            return (requests, None);
        }
        match peers.run(|_| self.device.stage_pending_removal()) {
            Some(Ok(None)) => {}
            Some(Ok(Some(_))) => return (requests, Some(Ok(()))),
            Some(Err(e)) => return (requests, Some(Err(e.into()))),
            None => return (requests, Some(Err(Refusal::Stopping.into()))),
        }
        let due = st
            .invites
            .iter()
            .find(|i| i.reservation.is_some() && i.admitted_slot.is_none())
            .map(|i| i.invite_id);
        let staged = due.map(|id| match peers.run(|_| self.device.stage_add(&id)) {
            None => Err(PairError::Refused(Refusal::Stopping)),
            Some(Ok(_)) => Ok(()),
            // Another candidate was journaled meanwhile: the next pass retries.
            Some(Err(MembershipError::Busy(_))) => Ok(()),
            Some(Err(e)) => Err(e.into()),
        });
        (requests, staged)
    }

    /// One blocking membership pass, for a blocking worker: process invite
    /// requests and stage a due Add, settle an own candidate (publishing an
    /// unpublished one first), catch up, then send due admission replies.
    /// Mailbox waits happen without the profile or registry lock, so a
    /// stalled relay never holds up local control.
    ///
    /// Every read, handoff and apply goes through the owner's gate: once
    /// the runtime is stopping, a call that was blocked in the mailbox may
    /// return, but nothing after it reads, hands off, applies or records.
    pub fn sync_membership(&self) -> Synced {
        let peers = self.peers();
        let (requests, staged) = self.admit(&peers);
        let mut published = None;
        let mut settle = self.settle();
        // Both outcomes follow an authenticated absent read. A previous
        // uncertain send is retried with the same durable bytes and eligibility checks.
        if matches!(settle, Ok(Settle::NotPublished | Settle::Pending)) && !self.stopping() {
            published = Some(
                self.device
                    .publish_gated(&peers)
                    .map(|_| ())
                    .map_err(|e| format!("{e:?}")),
            );
            settle = self.settle();
        }
        let (advanced, stop) = if self.stopping() {
            (vec![], Stop::Cancelled)
        } else {
            match self.advance_membership() {
                Ok(x) => x,
                Err(e) => (vec![], Stop::Unavailable(format!("{e:?}"))),
            }
        };
        let replies = if self.stopping() {
            Err(PairError::Refused(Refusal::Stopping))
        } else {
            self.device
                .dispatch_replies_gated(&peers)
                .map_err(PairError::from)
        };
        Synced {
            requests,
            staged,
            settle,
            published,
            advanced,
            stop,
            replies,
        }
    }

    // ------------------------------------------------------------ destination

    /// Accept private connections until the endpoint closes; each is served
    /// on its own task.
    pub async fn accept_loop(self: Arc<Self>, endpoint: Endpoint) {
        self.accept_until(endpoint, std::future::pending()).await
    }

    /// Accept until `stop` resolves or the endpoint closes, then accept
    /// nothing more and wait for the connections already accepted (which
    /// end with their sessions once the owner retires them).
    pub async fn accept_until(
        self: Arc<Self>,
        endpoint: Endpoint,
        stop: impl std::future::Future<Output = ()>,
    ) {
        let mut tasks = tokio::task::JoinSet::new();
        tokio::pin!(stop);
        loop {
            tokio::select! {
                biased;
                _ = &mut stop => break,
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let node = self.clone();
                    tasks.spawn(async move {
                        match incoming.await {
                            Ok(conn) => {
                                node.serve_connection(conn).await;
                            }
                            Err(_) => node.log.handshake_failed(),
                        }
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        while tasks.join_next().await.is_some() {}
    }

    /// Serve one completed connection through its whole registered lifetime:
    /// exchange, one request, its reply and payload, and the final drain.
    pub async fn serve_connection(&self, conn: Connection) -> Ended {
        let track = self.log.inbound(conn.remote_id());
        if conn.alpn() != SERVICE_ALPN {
            conn.close(0u32.into(), CLOSE_WRONG_PROTOCOL);
            track.end("wrong_protocol", None);
            return Ended::WrongProtocol;
        }
        let authorized = self.peers().authorize(&conn, false).await;
        // The exchange may have learned a decision or paired.
        audit::observe(self, false);
        let (auth, mut tx, mut rx) = match authorized {
            Ok(x) => x,
            Err(e) => {
                conn.close(0u32.into(), CLOSE_NOT_AUTHORIZED);
                track.end(audit::pair_error_reason(&e), None);
                return Ended::NotAuthorized(format!("{e:?}"));
            }
        };
        let _versions = self.versions.exchange(&conn, &auth);
        let (ended, session) = tokio::select! {
            biased;
            _ = self.watch_routes(&conn) => unreachable!("route watcher stays pending"),
            result = self.serve_authorized(&conn, &auth, &mut tx, &mut rx, &track) => result,
        };
        track.end_served(&ended);
        if ended.drains() {
            // The final frames are finished on the stream. Let the dialer
            // read them and close, for at most `RPC_TIMEOUT`. The exact
            // service session (when there is one) stays registered: a grant
            // or default change, like any end of authority, closes at once.
            let service_done = async {
                match &session {
                    Some(s) => s.done().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                biased;
                why = auth.done() => {
                    if why != Refusal::ConnectionClosed {
                        conn.close(0u32.into(), CLOSE_AUTHORITY_ENDED);
                    }
                }
                why = service_done => {
                    if why != Refusal::ConnectionClosed {
                        conn.close(0u32.into(), CLOSE_AUTHORITY_ENDED);
                    }
                }
                _ = tokio::time::timeout(wire::RPC_TIMEOUT, conn.closed()) => {}
            }
            conn.close(0u32.into(), CLOSE_DONE);
        }
        drop(session);
        drop(auth);
        ended
    }

    async fn serve_authorized(
        &self,
        conn: &Connection,
        auth: &Authorization,
        tx: &mut SendStream,
        rx: &mut RecvStream,
        track: &Tracked<'_>,
    ) -> (Ended, Option<SessionHandle>) {
        let over = |why: Refusal| match why {
            Refusal::ConnectionClosed => Ended::PeerDisconnected,
            why => {
                conn.close(0u32.into(), CLOSE_AUTHORITY_ENDED);
                track.authority_ended(&why);
                Ended::AuthorityEnd(format!("{why:?}"))
            }
        };
        // A partial request is cancelled by any end of authority.
        let read = tokio::select! {
            biased;
            why = auth.done() => return (over(why), None),
            r = read_bounded(rx, &[REQUEST_LEN]) => r,
        };
        if read.as_deref().is_ok_and(|bytes| bytes == PING_REQUEST) {
            let ended = tokio::select! {
                biased;
                why = auth.done() => over(why),
                result = echo_ping(conn, auth, tx, rx) => match result {
                    Ok(ended) => {
                        conn.close(0u32.into(), CLOSE_DONE);
                        ended
                    }
                    Err(why) => over(why),
                },
            };
            return (ended, None);
        }
        let Ok(header) = read else {
            conn.close(0u32.into(), CLOSE_DONE);
            return (Ended::BadRequest, None);
        };
        let ssh_info = ssh::is_info(&header);
        let ssh_tunnel = ssh::is_tunnel(&header);
        let req = PrivateRequest::decode(&header);
        let grant = match req {
            Some(req) => req.service,
            None if ssh_info || ssh_tunnel => Service::Shell,
            None => {
                conn.close(0u32.into(), CLOSE_DONE);
                return (Ended::BadRequest, None);
            }
        };
        track.service(grant);
        let session = match self.peers().open(auth, grant) {
            Ok(s) => s,
            Err(e) => {
                let refusal = wire_refusal(&e);
                tokio::select! {
                    biased;
                    why = auth.done() => return (over(why), None),
                    _ = refuse(tx, refusal, MSG_NOT_AUTHORIZED) => {}
                }
                return (Ended::Refused(refusal), None);
            }
        };
        enum Outcome {
            Served(Ended),
            Over(Refusal),
        }
        let mut teardown = None;
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        let mut tunnel = None;
        let serve = async {
            let connected = || track.connected(Some(conn));
            match req {
                Some(req) => {
                    self.serve_service(&session, &req, rx, tx, &mut teardown, connected)
                        .await
                }
                #[cfg(any(target_os = "linux", target_os = "macos", windows))]
                None => {
                    self.serve_ssh(&session, ssh_info, rx, tx, &mut tunnel, connected)
                        .await
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
                None => {
                    refuse(tx, WireRefusal::TargetUnavailable, MSG_SSH_SETUP).await;
                    Ended::Refused(WireRefusal::TargetUnavailable)
                }
            }
        };
        let outcome = tokio::select! {
            biased;
            why = session.done() => Outcome::Over(why),
            ended = serve => Outcome::Served(ended),
        };
        // The serving future is dropped here: copies stop, sockets close and
        // a shell's PTY is dropped (its reaper wakes, kills and reaps). An SSH
        // tunnel's key is withdrawn before the dialer sees the connection close.
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        drop(tunnel);
        let ended = match outcome {
            Outcome::Served(e) => e,
            Outcome::Over(why) => over(why),
        };
        if let Some(t) = teardown {
            t.wait().await;
        }
        (ended, Some(session))
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    async fn serve_ssh(
        &self,
        session: &SessionHandle,
        info: bool,
        rx: &mut RecvStream,
        tx: &mut SendStream,
        tunnel: &mut Option<ssh::Tunnel>,
        connected: impl FnOnce(),
    ) -> Ended {
        async fn unavailable(tx: &mut SendStream, message: &'static str) -> Ended {
            refuse(tx, WireRefusal::TargetUnavailable, message).await;
            Ended::Refused(WireRefusal::TargetUnavailable)
        }
        let custom_shell = self.shell.as_deref().is_some_and(|shell| {
            #[cfg(windows)]
            {
                !crate::windows_service::is_default_shell(shell)
            }
            #[cfg(not(windows))]
            {
                let _ = shell;
                true
            }
        });
        // The system server would give the account's own shell instead.
        if custom_shell {
            return unavailable(tx, MSG_SSH_CUSTOM_SHELL).await;
        }
        let profile = self.device.store().dir();
        let target = match ssh::Target::load(profile).await {
            Ok(target) => target,
            Err(error) => {
                // A device without an install has nothing to report.
                if ssh::Target::described(profile) {
                    ssh::warn("system SSH is unavailable", &error);
                }
                return unavailable(tx, MSG_SSH_SETUP).await;
            }
        };
        if info {
            let mut guarded = session.guard(&mut *tx);
            if wire::send(&mut guarded, ServiceReply::Ready).await.is_err()
                || wire::send(&mut guarded, target.host()).await.is_err()
            {
                return Ended::PeerDisconnected;
            }
            let _ = tx.finish();
            return Ended::StreamClosed;
        }

        let key = tokio::time::timeout(wire::RPC_TIMEOUT, read_bounded(rx, &[32])).await;
        let Ok(Ok(key)) = key else {
            return Ended::BadRequest;
        };
        let key = key.try_into().expect("bounded to 32 bytes");
        // Connect first: no key is authorized for a server that does not answer.
        let connect = tokio::time::timeout(wire::RPC_TIMEOUT, target.connect());
        let stream = match session.start(connect).await {
            Ok(Ok(Ok(stream))) => stream,
            Ok(_) => return unavailable(tx, MSG_SSH_SERVER).await,
            Err(_) => return denied(tx).await,
        };
        let authorized = match self.ssh.register(&stream) {
            Ok(registered) => {
                let tunnel = tunnel.insert(registered);
                self.ssh
                    .authorize(tunnel, session, profile, &target, &key)
                    .await
            }
            Err(error) => Ok(Err(error)),
        };
        match authorized {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                ssh::warn("could not authorize an SSH tunnel's key", &error);
                return unavailable(tx, MSG_SSH_KEY).await;
            }
            Err(_) => return denied(tx).await,
        }
        let mut target = session.guard(stream);
        let mut guarded = session.guard(&mut *tx);
        if wire::send(&mut guarded, ServiceReply::Ready).await.is_err() {
            return Ended::PeerDisconnected;
        }
        connected();
        let result = {
            let bridge = tcp::bridge_with(rx, &mut guarded, &mut target, tcp::MAX_FRAME);
            tokio::pin!(bridge);
            tokio::select! {
                result = &mut bridge => result,
                _ = tokio::time::sleep(self.ssh.lifetime()) => {
                    // Authentication has had its time; the connection stays.
                    if let Some(tunnel) = tunnel.as_mut() {
                        tunnel.expire();
                    }
                    bridge.await
                }
            }
        };
        // The key is withdrawn before the dialer learns that the tunnel ended.
        *tunnel = None;
        finish_tunnel(result, tx, tcp::MAX_FRAME).await
    }

    async fn serve_service(
        &self,
        session: &SessionHandle,
        req: &PrivateRequest,
        rx: &mut RecvStream,
        tx: &mut SendStream,
        teardown: &mut Option<pty::Teardown>,
        connected: impl FnOnce(),
    ) -> Ended {
        let target = session.target.as_deref();
        match req.service {
            Service::Shell => {
                #[cfg(not(windows))]
                if req.elevated {
                    refuse(tx, WireRefusal::TargetUnavailable, MSG_ELEVATED_UNSUPPORTED).await;
                    return Ended::Refused(WireRefusal::TargetUnavailable);
                }
                let (cols, rows) = req.terminal.unwrap_or((80, 24));
                let shell = self.shell.as_deref();
                let token = self.workers.clone();
                #[cfg(windows)]
                let spawn = async {
                    pty::Pty::spawn_with_privilege(cols, rows, shell, token, req.elevated)
                };
                #[cfg(not(windows))]
                let spawn = async { pty::spawn(cols, rows, shell, token) };
                match session.start(spawn).await {
                    Ok(Ok(mut pty)) => {
                        *teardown = Some(pty.teardown());
                        connected();
                        match serve_shell(session, &mut pty, rx, tx).await {
                            Ok(code) => {
                                let _ = tx.finish();
                                Ended::ShellExit(code)
                            }
                            Err(_) => Ended::ShellError,
                        }
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::Unsupported => {
                        refuse(tx, WireRefusal::TargetUnavailable, MSG_SHELL_UNSUPPORTED).await;
                        Ended::Refused(WireRefusal::TargetUnavailable)
                    }
                    Ok(Err(_error)) => {
                        #[cfg(all(test, windows))]
                        eprintln!("Windows shell startup: {_error}");
                        #[cfg(windows)]
                        let message = if req.elevated {
                            MSG_ELEVATED_UNAVAILABLE
                        } else {
                            MSG_SHELL
                        };
                        #[cfg(not(windows))]
                        let message = MSG_SHELL;
                        refuse(tx, WireRefusal::TargetUnavailable, message).await;
                        Ended::Refused(WireRefusal::TargetUnavailable)
                    }
                    Err(_) => denied(tx).await,
                }
            }
            Service::Tcp(port) => {
                let stream = match session.start(tcp::dial(port, target)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(_)) => {
                        refuse(tx, WireRefusal::TargetUnavailable, MSG_CONNECT).await;
                        return Ended::Refused(WireRefusal::TargetUnavailable);
                    }
                    Err(_) => return denied(tx).await,
                };
                // Authority may have ended while the connect completed.
                if session.status().is_err() {
                    return denied(tx).await;
                }
                if wire::send(&mut *tx, ServiceReply::Ready).await.is_err() {
                    return Ended::PeerDisconnected;
                }
                connected();
                let mut target = session.guard(stream);
                let result = tcp::bridge_with(rx, tx, &mut target, tcp::MAX_FRAME).await;
                finish_tunnel(result, tx, tcp::MAX_FRAME).await
            }
            Service::Udp(port) => {
                let addr = match session.start(udp::resolve(port, target)).await {
                    Ok(Ok(a)) => a,
                    Ok(Err(_)) => {
                        refuse(tx, WireRefusal::TargetUnavailable, MSG_RESOLVE).await;
                        return Ended::Refused(WireRefusal::TargetUnavailable);
                    }
                    Err(_) => return denied(tx).await,
                };
                if wire::send(&mut *tx, ServiceReply::Ready).await.is_err() {
                    return Ended::PeerDisconnected;
                }
                connected();
                let ended = || Broken::Denied(WireRefusal::PairingRequired);
                // Each association's bind, connect and first send, and every
                // later datagram, are handed to the OS under the guard.
                let result = udp::bridge_with(
                    rx,
                    tx,
                    |first| async move {
                        session
                            .start(udp::associate(addr, &first))
                            .await
                            .map_err(|_| ended())?
                            .map_err(Broken::Target)
                    },
                    |socket, payload| async move {
                        session
                            .start(udp::send(&socket, &payload))
                            .await
                            .map_err(|_| ended())
                    },
                    udp::MAX_FRAME,
                )
                .await;
                finish_tunnel(result, tx, udp::MAX_FRAME).await
            }
        }
    }

    // -------------------------------------------------------------- initiator

    /// Dial a peer for one service: connect on the private ALPN from this
    /// profile's endpoint, complete the exchange as the dialer, send the
    /// request on the same stream and return that stream with the
    /// destination's reply. Any end of authority before the reply cancels
    /// the dial and closes the connection.
    pub async fn open_service(
        &self,
        endpoint: &Endpoint,
        addr: EndpointAddr,
        req: PrivateRequest,
    ) -> Result<ServiceStream, PairError> {
        self.open_request(endpoint, addr, &req.encode(), None).await
    }

    pub(super) async fn open_ssh(
        &self,
        endpoint: &Endpoint,
        addr: EndpointAddr,
        req: ssh::Request,
    ) -> Result<ServiceStream, PairError> {
        self.open_request(endpoint, addr, req.header(), Some(req))
            .await
    }

    pub(super) async fn open_ping(
        &self,
        endpoint: &Endpoint,
        addr: EndpointAddr,
    ) -> Result<ServiceStream, PairError> {
        self.open_request(endpoint, addr, &PING_REQUEST, None).await
    }

    async fn open_request(
        &self,
        endpoint: &Endpoint,
        mut addr: EndpointAddr,
        request: &[u8],
        ssh: Option<ssh::Request>,
    ) -> Result<ServiceStream, PairError> {
        self.check_endpoint(endpoint)?;
        let local = |e: &dyn std::fmt::Display| PairError::Local(format!("service: {e}"));
        if let Some(address) = self.routes.get(addr.id) {
            addr = addr.with_ip_addr(address);
        }
        // Preserve the pinned identity and relay while offering direct paths
        // learned by Iroh during earlier connections to this peer.
        if let Some(remote) = endpoint.remote_info(addr.id).await {
            addr.addrs.extend(
                remote
                    .into_addrs()
                    .map(|info| info.into_addr())
                    .filter(|candidate| matches!(candidate, iroh::TransportAddr::Ip(_))),
            );
        }
        let conn = endpoint
            .connect(addr, SERVICE_ALPN)
            .await
            .map_err(|e| local(&e))?;
        let (auth, mut tx, mut rx) = self.peers().authorize(&conn, true).await?;
        let versions = self.versions.exchange(&conn, &auth);
        let io = async {
            crate::wire::frame(&mut tx, request)
                .await
                .map_err(|e| local(&e))?;
            if let Some(ssh::Request::Tunnel(key)) = ssh {
                wire::frame(&mut tx, &key.0).await.map_err(|e| local(&e))?;
            }
            let bytes = wire::read_frame_max(&mut rx, max_reply_len())
                .await
                .map_err(|e| local(&e))?;
            let reply = serde_json::from_slice::<ServiceReply>(&bytes)
                .map_err(|e| PairError::Malformed(format!("service reply: {e}")))?;
            let host = if matches!(ssh, Some(ssh::Request::Info))
                && matches!(reply, ServiceReply::Ready)
            {
                let bytes = wire::read_frame_max(&mut rx, ssh::Host::MAX_REPLY)
                    .await
                    .map_err(|e| local(&e))?;
                let host: ssh::Host = serde_json::from_slice(&bytes)
                    .map_err(|_| PairError::Malformed("invalid SSH host record".into()))?;
                if !ssh::Host::valid_user(&host.user) {
                    return Err(PairError::Malformed("invalid SSH account".into()));
                }
                Some(host)
            } else {
                None
            };
            Ok((reply, host))
        };
        let reply = tokio::select! {
            biased;
            why = auth.done() => {
                conn.close(0u32.into(), CLOSE_AUTHORITY_ENDED);
                return Err(why.into());
            }
            r = io => r,
        };
        let (reply, ssh_host) = match reply {
            Ok(r) => r,
            Err(e) => {
                conn.close(0u32.into(), CLOSE_DONE);
                return Err(e);
            }
        };
        Ok(ServiceStream {
            conn,
            auth,
            tx,
            rx,
            reply,
            ssh_host,
            _versions: versions,
        })
    }
}

/// Echo only fixed-size datagrams on this already-paired connection.
async fn echo_ping(
    conn: &Connection,
    auth: &Authorization,
    tx: &mut SendStream,
    rx: &mut RecvStream,
) -> Result<Ended, Refusal> {
    if wire::send(tx, ServiceReply::Ready).await.is_err() {
        return Ok(Ended::PeerDisconnected);
    }
    let mut byte = [0];
    loop {
        let datagram = tokio::select! {
            biased;
            _ = rx.read(&mut byte) => return Ok(Ended::StreamClosed),
            result = tokio::time::timeout(wire::RPC_TIMEOUT, conn.read_datagram()) => result,
        };
        let Ok(Ok(datagram)) = datagram else {
            return Ok(Ended::StreamClosed);
        };
        if datagram.len() != PING_BYTES {
            return Ok(Ended::BadRequest);
        }
        if auth
            .while_authorized(|| conn.send_datagram(datagram))?
            .is_err()
        {
            return Ok(Ended::StreamClosed);
        }
        // Keep the ungranted echo workload bounded even for a paired flooder.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Serve one shell over the native PTY: the existing shell frames (DATA,
/// RESIZE in; DATA, EXIT out), input bounded by `terminal::MAX_INPUT_FRAME`.
/// Input bytes go straight from the peer's frame to a guarded nonblocking
/// PTY write (nothing queued in between). Unix resizes under the guard.
/// Windows keeps the initial dimensions because its resize call can block.
/// After the shell exits, output is drained for 500 ms as the legacy
/// server does, never cutting a frame.
async fn serve_shell(
    session: &SessionHandle,
    pty: &mut pty::Pty,
    rx: &mut RecvStream,
    tx: &mut SendStream,
) -> anyhow::Result<i32> {
    use terminal::{CHUNK, DATA, EXIT, RESIZE};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut exited = pty.take_exit();
    let pty = &*pty;
    wire::send(&mut *tx, ServiceReply::Ready).await?;
    let mut input = session.guard(pty.writer());
    let mut output = pty.reader();
    let read_inputs = async {
        loop {
            let data = wire::read_frame_max(rx, terminal::MAX_INPUT_FRAME).await?;
            match data.as_slice() {
                #[cfg(windows)]
                [RESIZE, _, _, _, _] => {}
                #[cfg(not(windows))]
                [RESIZE, c0, c1, r0, r1] => {
                    let (cols, rows) = (
                        u16::from_be_bytes([*c0, *c1]),
                        u16::from_be_bytes([*r0, *r1]),
                    );
                    session
                        .start_now(|| pty.resize(cols, rows))
                        .map_err(|r| anyhow::anyhow!("{r:?}"))??;
                }
                [DATA, bytes @ ..] => input.write_all(bytes).await?,
                _ => anyhow::bail!("invalid shell input frame"),
            }
        }
    };
    let write_outputs = async {
        let mut buf = [0u8; CHUNK];
        buf[0] = DATA;
        let code = loop {
            tokio::select! {
                code = &mut exited => break code??,
                n = output.read(&mut buf[1..]) => match n? {
                    0 => break (&mut exited).await??,
                    n => wire::frame(&mut *tx, &buf[..n + 1]).await?,
                },
            }
        };
        // A descendant may keep the output open after the shell exits. Time
        // out waiting for a chunk, never in the middle of writing a frame.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, output.read(&mut buf[1..])).await {
            if n == 0 {
                break;
            }
            wire::frame(&mut *tx, &buf[..n + 1]).await?;
        }
        Ok::<_, anyhow::Error>(code)
    };
    let code = tokio::select! {
        r = write_outputs => r?,
        r = read_inputs => return r,
    };
    let [a, b, c, d] = code.to_be_bytes();
    wire::frame(&mut *tx, &[EXIT, a, b, c, d]).await?;
    Ok(code)
}

async fn denied(tx: &mut SendStream) -> Ended {
    refuse(tx, WireRefusal::PairingRequired, MSG_ENDED).await;
    Ended::Refused(WireRefusal::PairingRequired)
}

async fn finish_tunnel(result: Result<(), Broken>, tx: &mut SendStream, max_frame: usize) -> Ended {
    match result {
        Ok(()) => {
            let _ = tunnel::done(tx).await;
            let _ = tx.finish();
            Ended::StreamClosed
        }
        Err(Broken::Target(e)) => {
            let mut message = format!("forwarding failed on the destination: {e}");
            // The failure frame (kind byte + text) must fit the format bound.
            let mut cut = max_frame.saturating_sub(1).min(message.len());
            while !message.is_char_boundary(cut) {
                cut -= 1;
            }
            message.truncate(cut);
            let _ = tunnel::fail(tx, &message).await;
            let _ = tx.finish();
            Ended::TargetError
        }
        Err(Broken::Peer) => Ended::PeerDisconnected,
        Err(Broken::Denied(r)) => Ended::Refused(r),
    }
}

/// The initiator's end of one private service connection. It keeps its
/// authorization registered: a local decline, cutoff or removal resolves
/// `done`, and the caller closes the connection.
pub struct ServiceStream {
    pub conn: Connection,
    /// Disjoint from the streams, so `auth.done()` can be awaited while
    /// they are copied.
    pub auth: Authorization,
    pub tx: SendStream,
    pub rx: RecvStream,
    pub reply: ServiceReply,
    pub ssh_host: Option<ssh::Host>,
    _versions: Exchange,
}

impl ServiceStream {
    /// Time a single UDP-style probe. A reply arriving after the deadline
    /// can never match the next probe's random payload.
    pub(super) async fn probe(&self) -> anyhow::Result<Option<Duration>> {
        let payload = super::codec::random::<PING_BYTES>();
        let start = tokio::time::Instant::now();
        self.auth
            .while_authorized(|| self.conn.send_datagram(payload.to_vec().into()))
            .map_err(|why| anyhow::anyhow!("ping authorization ended: {why:?}"))??;
        let deadline = tokio::time::sleep_until(start + Duration::from_secs(1));
        tokio::pin!(deadline);
        loop {
            let reply = tokio::select! {
                biased;
                why = self.auth.done() => anyhow::bail!("ping connection ended: {why:?}"),
                _ = &mut deadline => return Ok(None),
                result = self.conn.read_datagram() => result?,
            };
            if reply.as_ref() == payload {
                return Ok(Some(start.elapsed()));
            }
            tokio::task::consume_budget().await;
        }
    }

    /// Resolve when this connection's authority ends or it closes.
    pub async fn done(&self) -> Refusal {
        self.auth.done().await
    }

    pub fn status(&self) -> Result<(), Refusal> {
        self.auth.status()
    }
}
