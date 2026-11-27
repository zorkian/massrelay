//! EXPERIMENTAL thin foreground runtime for one private profile: the
//! profile's runtime `Owner`, the private-ALPN listener, an authenticated
//! local control channel, outbound shell and port attach, and a background
//! membership pass, with one ordered stop.
//!
//! # One owner, one registry
//!
//! `Runtime::start` acquires the profile's exclusive `Owner` before it opens
//! the profile, and checks that the Iroh endpoint it was given is the
//! profile's endpoint. Every live mutation (decisions, cutoffs, grants,
//! defaults, exclusions), every membership promotion and every service
//! session goes through the one `Node` and its session registry. A second
//! runtime on the same profile is refused (`PairError::OwnedElsewhere`); a
//! second process can still read status with `offline_status`, which takes
//! no owner and never writes.
//!
//! # Local control
//!
//! The control channel reuses the legacy loopback socket, two-way HMAC
//! proof and JSON framing (`local::listen_on`, `authenticate_on`,
//! `connect_on`) on its own channel: a separate marker
//! (`private-runtime.json`) and separate role labels, so legacy commands
//! never reach the private runtime and neither side can authenticate to the
//! other. A command is read only after authentication, within
//! `wire::RPC_TIMEOUT`.
//!
//! Peers are named by endpoint key (64 hex digits, or Iroh's own form) or by
//! the alias this device pinned when it approved that key. Roster names are
//! never consulted, so they cannot redirect an approval or a connection.
//! Remote decisions shown in status are only those the peer proved on an
//! authenticated exchange with this device; grants shown are this device's.
//!
//! # Outbound
//!
//! Shell and port connect resolve the peer, look up its address, require
//! the address's endpoint id to be that exact key, and dial from the
//! profile's endpoint. The outbound connection's authorization stays
//! registered for its whole life: a local decline, cutoff, removal or stop
//! closes it at once. Port forwards reuse `tunnel::forward` and the
//! command's lifetime socket (a TCP stdin half-close keeps the other
//! direction; the command leaving ends the session) with the format's frame
//! bound; shell bytes are copied as a stream.
//!
//! # Exposures
//!
//! `Expose` holds a temporary grant (`Node::expose`) for one port to one
//! paired peer, optionally forwarding to a target this device's owner chose,
//! for as long as the command's lifetime socket stays open. The command
//! leaving, a disable of that service for that peer, a decline, cutoff,
//! re-pair, removal or stop withdraws exactly that exposure and ends only
//! the sessions opened under it; the control socket then gets `Done` (the
//! command left) or the reason. Exposures are never persisted; `Status`
//! lists them (with targets) apart from persistent grants.
//!
//! # Membership pass
//!
//! A background task runs `Node::sync_membership` on a blocking worker: it
//! processes invite request queues (reservation and acknowledgement under
//! the established durable rules), stages the Add of a reserved invite,
//! publishes and settles the own candidate, catches up, and dispatches due
//! sealed replies. Mailbox waits there hold neither the profile lock nor the
//! registry lock, so a stalled relay never delays a local cutoff, decline or
//! stop.
//!
//! # Updates
//!
//! `massrelay update` (`crate::update`) replaces the installed program only
//! while nothing is using this device. `Update(Identify)` tells it which
//! process, program and version answers for the profile now. The rest is two
//! steps on one authenticated control connection:
//!
//! 1. `Update(Hold)` asks the owner's registry, in one step under its lock,
//!    whether any authorization, session or exposure is live and, if none
//!    is, closes admission (`Owner::hold_if_idle`). The reply is `Busy` with
//!    what is live, or `Held` with this runtime's identity, so the updater
//!    knows on the hold's own connection exactly which process it holds. A
//!    hold lasts while its connection stays open, for at most the lease. When
//!    it lapses, admission reopens and the device serves as before. A hold
//!    alone never stops anything. One hold at a time; a second is answered
//!    `Busy`.
//! 2. `Commit`, sent on that connection, retires this runtime: under the same
//!    lock, only if that hold is still in force and the registry still
//!    empty, the owner moves to stopping (`AdmissionHold::retire`), and the
//!    reply is `Retired`. A commit that arrives after the hold lapsed finds
//!    its connection closed and retires nothing.
//!
//! `Identify` never shows a runtime that may be ending as one that serves:
//! while a hold is in force the identity says so (`held`), and from the
//! moment the runtime retires, which is before it answers the commit, the
//! answer is `Retired`.
//!
//! A retired runtime then ends itself through its ordinary stop
//! (`Runtime::retired`). Nothing outside it is asked to stop it, so what
//! ends is exactly the runtime that was idle when it retired, and never a
//! process that took its place. On Unix it ends as a failure, so that a
//! service manager which restarts failed services starts the program that is
//! installed by then; under the Windows service manager it ends cleanly, and
//! the updater starts the service.
//!
//! # Stop
//!
//! `stop` first moves the owner to stopping (`Node::retire_all`, under the
//! registry lock): from that point no connection already accepted can
//! commit an exchange or start a service, no control command already read
//! can apply a mutation, and no membership step can read, hand off, apply
//! or record (the gate is closed). Every session and negotiation ends in
//! the same step, and the mailbox's stop seam (`Mailbox::shutdown`) is
//! asked to end calls in flight. Then it stops admission (control listener,
//! peer accepts, the next membership pass), removes the marker, closes the
//! endpoint while joining the control, peer and membership tasks (bounded
//! by `STOP_WAIT`, then aborted), waits (same bound) for native PTY
//! workers to reap their shells, and only then drops the `Node` and its
//! `Owner`.
//!
//! What can still hold the owner: a membership call blocked in a transport
//! without a working stop seam (it returns, then does nothing more), or a
//! PTY reaper that cannot reap its shell. In either case the `Node` is
//! kept until it finishes (or the process exits) and `Stopped` says so.
//!
//! # OpenSSH client entries
//!
//! While the profile holds `ssh-client.conf`, a background task keeps OpenSSH
//! entries there for the paired peers this device confirmed (`ssh::managed`).
//! Control mutations and membership passes wake it.
//!
//! # Event log
//!
//! The runtime appends device events (start and stop, every inbound and
//! outbound service session, every control command, membership
//! reachability and observed state changes) to `Config::log_file`, by
//! default `connections.jsonl` in the profile directory, with the legacy
//! record format and event names. See `super::audit` for what is recorded
//! and what never is.
//!
//! # Not here
//!
//! No OS service manager, installer, roles or additional capabilities.
//! Non-loopback targets exist only on exposures. The experimental
//! CLI over this runtime is `super::cli`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::local::{self, Channel};
use crate::wire::{self, GrantRule, Service, ServiceReply};
use crate::{terminal, tunnel};

use super::audit::{self, DeviceLog};
use super::binding::EndpointKey;
use super::codec::hex;
use super::mailbox::Mailbox;
use super::membership::{Clock, Device, MemberView};
use super::pairing::{self, Decision, Owner, PairError, PairingState, Refusal, parse_key};
use super::service::{
    CLOSE_AUTHORITY_ENDED, CLOSE_DONE, Node, PrivateRequest, ServiceStream, max_payload_frame,
};
use super::ssh;
use super::versions::{Observation, Observations, PeerVersions};

/// The private runtime's local control channel.
pub const CONTROL: Channel = Channel {
    marker: "private-runtime.json",
    daemon_role: b"massrelay private runtime experimental-1",
    client_role: b"massrelay private client experimental-1",
    unavailable: "private runtime unavailable; start it in the foreground first",
};

/// Bound on joining each task group during `stop`.
const STOP_WAIT: Duration = Duration::from_secs(10);
pub const MAX_PING_COUNT: u16 = 1000;

// ------------------------------------------------------------------ protocol

/// One local control command (experimental; JSON over the control socket).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlRequest {
    Status,
    Peers,
    Invite,
    Ping {
        peer: String,
        count: u16,
        /// Older clients omit this and expect only `PingSample` replies.
        #[serde(default)]
        include_route: bool,
    },
    RenameSelf {
        name: String,
    },
    /// Approve `peer` (endpoint key, or an alias already pinned to one) and
    /// pin `alias` to it.
    Approve {
        peer: String,
        alias: String,
        reapprove: bool,
    },
    Rename {
        peer: String,
        alias: String,
    },
    Decline {
        peer: String,
    },
    /// Local cutoff (and network removal where this device can stage one).
    Revoke {
        peer: String,
    },
    Enable {
        peer: String,
        service: Service,
    },
    Disable {
        peer: String,
        service: Service,
    },
    SetDefault {
        service: Service,
        enabled: bool,
    },
    Exclude {
        peer: String,
        service: Service,
    },
    ClearExclusion {
        peer: String,
        service: Service,
    },
    /// Interactive shell. The lifetime socket tells the runtime the command
    /// left even while setup is pending or the data socket is backed up.
    // Older runtimes must reject new requests instead of discarding the
    // privilege choice and sending a legacy shell request.
    #[serde(rename = "ShellWithPrivilege", alias = "Shell")]
    Shell {
        peer: String,
        #[serde(default)]
        elevated: bool,
        cols: u16,
        rows: u16,
        lifetime_port: u16,
        lifetime_key: [u8; 32],
    },
    Connect {
        peer: String,
        service: Service,
        lifetime_port: u16,
        lifetime_key: [u8; 32],
    },
    Ssh {
        peer: String,
        client_key: Option<crate::mailbox::Bytes<32>>,
        lifetime_port: u16,
        lifetime_key: [u8; 32],
    },
    /// Grant `service` (a port) to `peer` while the lifetime socket stays
    /// open, forwarding to `target` (`None`: loopback on the same port).
    Expose {
        peer: String,
        service: Service,
        target: Option<String>,
        lifetime_port: u16,
        lifetime_key: [u8; 32],
    },
    /// Coordination with `massrelay update`. A runtime that predates it drops the connection.
    Update(UpdateRequest),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateRequest {
    /// Which process, program and version serves this profile.
    Identify,
    /// Close admission if nothing is live, until this connection ends.
    Hold,
    /// The second step on a `Hold` connection: retire the runtime that granted the hold.
    Commit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateReply {
    Identity(Identity),
    /// Something is live, another update holds admission, or the runtime is stopping.
    Busy {
        connections: usize,
        exposures: usize,
        held: bool,
    },
    /// Admission is closed and nothing is live, for at most `lease_secs`.
    Held {
        lease_secs: u64,
        /// The runtime that holds: the one a commit on this connection retires.
        identity: Identity,
    },
    /// This runtime is permanently stopping, having ended nothing. The answer to a commit,
    /// and to any later `Identify` until the process is gone.
    Retired,
}

/// The process serving a profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub pid: u32,
    /// The program this process was started from, when the system reports it as text.
    pub executable: Option<String>,
    pub version: String,
    pub endpoint: String,
    /// An update's hold is in force on this runtime: it admits nothing, and a commit on the
    /// hold's connection retires it. Such a runtime may be about to end, so it is not to be
    /// taken for a settled, serving one.
    #[serde(default)]
    pub held: bool,
}

/// How long an update's admission hold lasts without its commit.
pub const HOLD_LEASE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlReply {
    Status(StatusView),
    Peers(Vec<PeerView>),
    /// Hex encoding of the invite token.
    Invite(String),
    Approved {
        key: String,
        fresh: bool,
    },
    Done,
    /// Whether the setting changed.
    Changed(bool),
    /// The durable local cutoff is applied; later steps reported apart.
    CutOff {
        pairing_error: Option<String>,
        removal_error: Option<String>,
    },
    Shell,
    Connected,
    SshHost(ssh::Host),
    PingStarted,
    PingSample(Option<u64>),
    PingSampleWithRoute {
        micros: u64,
        route: PingRoute,
    },
    /// The exposure is live; a final `Done` or `Error` follows when it ends.
    Exposed {
        key: String,
        alias: String,
    },
    Update(UpdateReply),
    Error(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PingRoute {
    Direct(SocketAddr),
    Relayed,
    Unknown,
}

impl PingRoute {
    fn selected(conn: &Connection) -> Self {
        let paths = conn.paths();
        match paths.iter().find(|path| path.is_selected()) {
            Some(path) => match path.remote_addr() {
                TransportAddr::Ip(addr) => Self::Direct(*addr),
                TransportAddr::Relay(_) => Self::Relayed,
                _ => Self::Unknown,
            },
            None => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    pub endpoint: String,
    /// Version of the executable that produced this view.
    #[serde(default)]
    pub version: Option<String>,
    /// Read from the running owner (`true`) or without one (`false`).
    pub running: bool,
    /// Established service connections (running owner only).
    #[serde(default)]
    pub connections: Vec<audit::ConnectionView>,
    pub peers: Vec<PeerView>,
    /// Services enabled by default for every paired peer.
    pub defaults: Vec<Service>,
    /// Per-peer grants on this device: (endpoint key, service).
    pub grants: Vec<(String, Service)>,
    pub exclusions: Vec<(String, Service)>,
    /// Live temporary exposures (running owner only; never persisted).
    #[serde(default)]
    pub exposures: Vec<ExposureView>,
    /// Outcome of the last membership pass (running owner only).
    pub last_sync: Option<String>,
    /// The recorded membership halt, if any.
    pub halt: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureView {
    pub key: String,
    pub service: Service,
    /// Owner-chosen target (`None`: loopback on the service port).
    pub target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerView {
    pub key: String,
    /// Alias this device pinned on approval.
    pub alias: Option<String>,
    /// In the accepted roster.
    pub member: bool,
    /// "approved", "declined" or "none".
    pub local: String,
    /// The peer's newest decision proved on an authenticated exchange.
    pub remote: String,
    pub paired: bool,
    #[serde(default)]
    pub version: Option<Observation>,
}

impl PeerView {
    pub fn reported_name(&self) -> Option<&str> {
        self.version.as_ref()?.name()
    }
}

fn decision(d: &Decision) -> String {
    match d {
        Decision::Approve { .. } => "approved",
        Decision::Decline => "declined",
        Decision::Unknown => "none",
    }
    .into()
}

fn view(
    members: &MemberView,
    st: &PairingState,
    running: bool,
    last_sync: Option<String>,
    halt: Option<String>,
    versions: &Observations,
) -> StatusView {
    let report = |key: &EndpointKey| {
        EndpointId::from_bytes(key)
            .ok()
            .and_then(|id| versions.get(&id).cloned())
    };
    let peers = members
        .roster
        .iter()
        .filter(|key| members.ineligible(key).is_none())
        .map(|key| {
            let record = st.peer(key);
            PeerView {
                key: hex(key),
                alias: record.map(|p| p.alias.clone()),
                member: true,
                local: record.map_or_else(|| "none".into(), |p| decision(&p.local)),
                remote: record.map_or_else(|| "none".into(), |p| decision(&p.remote)),
                paired: record.is_some_and(|p| p.pairing.is_some()),
                version: report(key),
            }
        })
        .collect();
    let defaults = st
        .defaults
        .list(|_| None)
        .into_iter()
        .filter(|g| matches!(g.rule, Some(GrantRule::Default)))
        .map(|g| g.service)
        .collect();
    let grants = st
        .grants
        .list(|_| None)
        .into_iter()
        .filter(|g| !g.temporary)
        .filter_map(|g| Some((hex(g.id?.as_bytes()), g.service)))
        .chain(
            st.pending_grants
                .iter()
                .map(|(key, service)| (hex(key), *service)),
        )
        .collect();
    let exclusions = st.exclusions.iter().map(|(k, s)| (hex(k), *s)).collect();
    StatusView {
        endpoint: hex(&members.endpoint),
        version: Some(env!("CARGO_PKG_VERSION").into()),
        running,
        connections: vec![],
        peers,
        defaults,
        grants,
        exclusions,
        exposures: vec![],
        last_sync,
        halt,
    }
}

/// Status read without the runtime owner (for a second process). Never
/// writes and offers no mutation.
pub fn offline_status<M: Mailbox>(device: &Device<M>) -> Result<StatusView, PairError> {
    let state = device.state()?;
    let st = pairing::read_state(device)?;
    let members = {
        let guard = device.store().lock()?;
        device.member_view(&guard)?
    };
    let halt = state.halt.map(|h| format!("{h:?}"));
    Ok(view(
        &members,
        &st,
        false,
        None,
        halt,
        &PeerVersions::read(device.store().dir()),
    ))
}

// ------------------------------------------------------------------- runtime

/// Address lookup for outbound dials. The runtime requires the returned
/// address's endpoint id to equal the selected key.
pub type Addresses = Arc<dyn Fn(&EndpointKey) -> Option<EndpointAddr> + Send + Sync>;

pub struct Config {
    /// The private profile directory (owner lock, state, control marker).
    pub dir: PathBuf,
    /// Shell offered to peers (`None`: the platform default).
    pub shell: Option<PathBuf>,
    /// Interval of the background membership pass (`None`: no pass).
    pub sync_every: Option<Duration>,
    pub addresses: Addresses,
    /// Event log file (`None`: `connections.jsonl` in `dir`).
    pub log_file: Option<PathBuf>,
    /// How long an update's admission hold lasts without its commit.
    pub hold_lease: Duration,
    /// Upkeep of the opt-in OpenSSH client entries.
    pub ssh: ssh::Settings,
}

impl Config {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            shell: None,
            sync_every: Some(Duration::from_secs(30)),
            addresses: Arc::new(|key| EndpointId::from_bytes(key).ok().map(EndpointAddr::new)),
            log_file: None,
            hold_lease: HOLD_LEASE,
            ssh: ssh::Settings::default(),
        }
    }
}

struct Shared<M: Mailbox> {
    node: Arc<Node<M>>,
    endpoint: Endpoint,
    addresses: Addresses,
    last_sync: Mutex<Option<String>>,
    hold_lease: Duration,
    /// Signalled when an update retired this runtime.
    retired: Arc<tokio::sync::Notify>,
    /// Signalled when this device's peers may have changed.
    peers_changed: Arc<tokio::sync::Notify>,
}

/// A running private profile. Drop stops admission and retires sessions
/// but cannot wait; call `stop` to join everything.
pub struct Runtime<M: Mailbox + Send + Sync + 'static> {
    shared: Option<Arc<Shared<M>>>,
    dir: PathBuf,
    stop: watch::Sender<bool>,
    tasks: Vec<(&'static str, JoinHandle<()>)>,
    log: Arc<DeviceLog>,
    retired: Arc<tokio::sync::Notify>,
}

/// What `stop` achieved.
#[derive(Debug, PartialEq, Eq)]
pub struct Stopped {
    /// Task groups that had to be aborted after `STOP_WAIT`.
    pub aborted: Vec<&'static str>,
    /// Native PTY workers still alive (a shell not yet reaped).
    pub native_workers: usize,
    /// The `Owner` (and its lock) was released. `false` while a membership
    /// call is still blocked in the mailbox or a PTY worker survives; the
    /// owner is then released once they finish (or the process exits).
    pub owner_released: bool,
}

impl<M: Mailbox + Send + Sync + 'static> Runtime<M> {
    /// Start with a fixture's already-bound endpoint.
    #[cfg(test)]
    pub async fn start(
        config: Config,
        mailbox: M,
        clock: Clock,
        endpoint: Endpoint,
    ) -> Result<Self, PairError> {
        let owner = Owner::acquire(&config.dir)?;
        Self::start_owned(config, mailbox, clock, endpoint, owner).await
    }

    /// Start serving with the profile owner acquired before transport setup.
    pub async fn start_owned(
        config: Config,
        mailbox: M,
        clock: Clock,
        endpoint: Endpoint,
        owner: Owner,
    ) -> Result<Self, PairError> {
        let local = |e: &dyn std::fmt::Display| PairError::Local(format!("runtime: {e:#}"));
        let device = Device::open(&config.dir, mailbox, clock)?;
        let log_file = config
            .log_file
            .clone()
            .unwrap_or_else(|| config.dir.join(audit::EVENT_FILE));
        let log = Arc::new(DeviceLog::open(&log_file).map_err(|e| local(&e))?);
        let node = Node::with_log(device, owner, config.shell, log.clone())?;
        node.check_endpoint(&endpoint)?;
        let (listener, marker) = local::listen_on(&config.dir, &CONTROL)
            .await
            .map_err(|e| local(&e))?;
        // The baseline later state events are diffed against.
        audit::observe(&node, true);
        let (stop, stopping) = watch::channel(false);
        let retired = Arc::new(tokio::sync::Notify::new());
        let shared = Arc::new(Shared {
            node,
            endpoint,
            addresses: config.addresses,
            last_sync: Mutex::new(None),
            hold_lease: config.hold_lease,
            retired: retired.clone(),
            peers_changed: Arc::default(),
        });
        let mut tasks = vec![];

        let accept = shared
            .node
            .clone()
            .accept_until(shared.endpoint.clone(), stopped(stopping.clone()));
        tasks.push(("peers", tokio::spawn(accept)));

        let control = {
            let (shared, stopping) = (shared.clone(), stopping.clone());
            let marker = Arc::new(marker);
            async move {
                let mut clients = JoinSet::new();
                let stop = stopped(stopping);
                tokio::pin!(stop);
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut stop => break,
                        accepted = listener.accept() => {
                            let Ok((socket, _)) = accepted else { continue };
                            let (shared, marker) = (shared.clone(), marker.clone());
                            clients.spawn(async move {
                                let _ = serve_control(shared, socket, &marker).await;
                            });
                        }
                        Some(_) = clients.join_next(), if !clients.is_empty() => {}
                    }
                }
                drop(listener);
                // In-flight commands end with their sessions (retired by
                // `stop`); a command still running at the bound is aborted.
                let drain = async { while clients.join_next().await.is_some() {} };
                if timeout(STOP_WAIT, drain).await.is_err() {
                    clients.shutdown().await;
                }
            }
        };
        tasks.push(("control", tokio::spawn(control)));

        if let Some(every) = config.sync_every {
            let (shared, stopping) = (shared.clone(), stopping.clone());
            let sync = async move {
                let stop = stopped(stopping);
                tokio::pin!(stop);
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut stop => break,
                        _ = tokio::time::sleep(every) => {}
                    }
                    let node = shared.node.clone();
                    let pass = tokio::task::spawn_blocking(move || {
                        let synced = node.sync_membership();
                        audit::observe(&node, true);
                        synced
                    });
                    tokio::select! {
                        biased;
                        // A pass blocked in the mailbox is left to finish on
                        // its worker; it holds no lock meanwhile.
                        _ = &mut stop => break,
                        r = pass => {
                            let note = match r {
                                Ok(s) => {
                                    shared.node.log().membership_pass(&s);
                                    format!("{s:?}")
                                }
                                Err(e) => format!("membership pass failed: {e}"),
                            };
                            *shared.last_sync.lock().expect("sync note") = Some(note);
                            shared.peers_changed.notify_one();
                        }
                    }
                }
            };
            tasks.push(("membership", tokio::spawn(sync)));
        }

        #[cfg(any(unix, windows))]
        {
            let entries = ssh::maintain(
                shared.node.clone(),
                shared.endpoint.clone(),
                shared.addresses.clone(),
                config.dir.clone(),
                config.ssh,
                shared.peers_changed.clone(),
                stopped(stopping.clone()),
            );
            tasks.push(("ssh", tokio::spawn(entries)));
        }

        log.started();
        Ok(Self {
            shared: Some(shared),
            dir: config.dir,
            stop,
            tasks,
            log,
            retired,
        })
    }

    /// Notified when an update retired this runtime. It serves nothing from then on, and
    /// nothing else will stop it: stop it and end the process.
    pub fn retired(&self) -> Arc<tokio::sync::Notify> {
        self.retired.clone()
    }

    /// The event log file.
    pub fn log_file(&self) -> Option<&Path> {
        self.log.path()
    }

    pub fn live_sessions(&self) -> usize {
        self.shared.as_ref().map_or(0, |s| s.node.live_sessions())
    }

    /// Native PTY workers (shell reapers) still running.
    pub fn native_workers(&self) -> usize {
        self.shared.as_ref().map_or(0, |s| s.node.native_workers())
    }

    /// Stop in order (see the module docs) and release the owner.
    pub async fn stop(mut self) -> Stopped {
        let shared = self.shared.take().expect("running");
        // 1. The linearization point: permanently stopping. Nothing already
        //    accepted or read can authorize, start or mutate after this, and
        //    every session, authorization and negotiation ends now.
        shared.node.retire_all("private runtime stopped");
        // 2. No new control commands, peer connections or membership pass.
        let _ = self.stop.send(true);
        // 3. Clients now see the runtime as unavailable.
        let _ = std::fs::remove_file(self.dir.join(CONTROL.marker));
        // 4. Close the endpoint while draining the task groups. A peer
        //    still handshaking has no registered session for retire_all
        //    to wake.
        let tasks = std::mem::take(&mut self.tasks);
        let drain = async {
            let mut aborted = vec![];
            for (name, mut task) in tasks {
                if timeout(STOP_WAIT, &mut task).await.is_err() {
                    task.abort();
                    let _ = task.await;
                    aborted.push(name);
                }
            }
            aborted
        };
        let (aborted, _) = tokio::join!(drain, timeout(STOP_WAIT, shared.endpoint.close()));
        let node = match Arc::try_unwrap(shared) {
            Ok(shared) => shared.node,
            Err(shared) => shared.node.clone(),
        };
        // 5. Native PTY workers reap their (already killed) shells, and a
        //    membership call in flight returns (its gate is closed, so it does
        //    nothing more).
        let quiet = async {
            while node.native_workers() > 0 || Arc::strong_count(&node) > 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        let _ = timeout(STOP_WAIT, quiet).await;
        let native_workers = node.native_workers();
        // 6. Only now drop the node, and with it the owner. A node still
        //    needed by a blocked membership call is dropped by that call; one
        //    whose PTY worker survives is kept until the worker exits.
        let owner_released = if native_workers > 0 {
            std::thread::spawn(move || {
                while node.native_workers() > 0 {
                    std::thread::sleep(Duration::from_millis(50));
                }
                drop(node);
            });
            false
        } else {
            match Arc::try_unwrap(node) {
                Ok(node) => {
                    drop(node);
                    true
                }
                Err(_) => false,
            }
        };
        self.log.stopped();
        Stopped {
            aborted,
            native_workers,
            owner_released,
        }
    }
}

impl<M: Mailbox + Send + Sync + 'static> Drop for Runtime<M> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            shared.node.retire_all("private runtime dropped");
            let _ = self.stop.send(true);
            let _ = std::fs::remove_file(self.dir.join(CONTROL.marker));
            for (_, task) in &self.tasks {
                task.abort();
            }
        }
    }
}

/// Resolve once `stop` is signalled.
async fn stopped(mut stopping: watch::Receiver<bool>) {
    let _ = stopping.wait_for(|stop| *stop).await;
}

// ------------------------------------------------------------ control side

async fn serve_control<M: Mailbox + Send + Sync + 'static>(
    shared: Arc<Shared<M>>,
    mut socket: TcpStream,
    marker: &local::Runtime,
) -> Result<()> {
    let log = shared.node.log();
    let mut authenticated = false;
    let request = timeout(wire::RPC_TIMEOUT, async {
        local::authenticate_on(&mut socket, marker, &CONTROL).await?;
        authenticated = true;
        wire::recv(&mut socket).await
    })
    .await
    .context("local request timed out")
    .and_then(|r| r);
    let request: ControlRequest = match request {
        Ok(request) => request,
        Err(e) => {
            log.control_unreadable(authenticated);
            return Err(e);
        }
    };
    // Audited by operation, peer and service only; never the request.
    let (operation, selector, service) = audit::operation(&request);
    let target = selector.and_then(|s| parse_key(s).or_else(|| log.alias_key(s)));
    let audit = |outcome, reason| log.control(operation, outcome, target, service, reason);
    audit("requested", None);
    socket.set_nodelay(true)?;
    // A command read after stop linearized is refused (status may still be
    // read). `Peers` refuses every mutation then as well.
    if shared.node.stopping() && !matches!(request, ControlRequest::Status | ControlRequest::Peers)
    {
        audit("denied", Some("device_stopping"));
        // A runtime that is ending never identifies itself as one that serves: from the
        // moment it retires, and so before it can say that it has, the answer is this.
        let reply = match request {
            ControlRequest::Update(UpdateRequest::Identify) => {
                ControlReply::Update(UpdateReply::Retired)
            }
            _ => ControlReply::Error("the private runtime is stopping".into()),
        };
        return wire::send(&mut socket, reply).await;
    }
    match request {
        ControlRequest::Ping {
            peer,
            count,
            include_route,
        } => {
            let (mut rx, mut tx) = socket.into_split();
            let mut byte = [0];
            let result = tokio::select! {
                biased;
                _ = rx.read(&mut byte) => {
                    audit("failed", Some("local_client_closed"));
                    return Ok(());
                }
                result = ping_peer(&shared, &peer, count, include_route, &mut tx) => result,
            };
            match result {
                Ok(()) => {
                    audit("allowed", None);
                    wire::send(&mut tx, ControlReply::Done).await
                }
                Err(e) => {
                    audit("failed", Some("ping_failed"));
                    wire::send(&mut tx, ControlReply::Error(e.to_string())).await
                }
            }
        }
        ControlRequest::Shell {
            peer,
            elevated,
            cols,
            rows,
            lifetime_port,
            lifetime_key,
        } => {
            let lifetime = local::lifetime_connect(lifetime_port, &lifetime_key).await;
            if lifetime.is_err() {
                audit("failed", Some("lifetime_channel_failed"));
            }
            let lifetime = lifetime?;
            outbound(
                &shared,
                socket,
                &peer,
                OutboundRequest::Service(PrivateRequest {
                    service: Service::Shell,
                    terminal: Some((cols, rows)),
                    elevated,
                }),
                lifetime,
            )
            .await
        }
        ControlRequest::Ssh {
            peer,
            client_key,
            lifetime_port,
            lifetime_key,
        } => {
            let lifetime = local::lifetime_connect(lifetime_port, &lifetime_key).await;
            if lifetime.is_err() {
                audit("failed", Some("lifetime_channel_failed"));
            }
            let request = client_key.map_or(ssh::Request::Info, ssh::Request::Tunnel);
            outbound(
                &shared,
                socket,
                &peer,
                OutboundRequest::Ssh(request),
                lifetime?,
            )
            .await
        }
        ControlRequest::Connect {
            service: Service::Shell,
            ..
        } => {
            audit("denied", Some("command_rejected"));
            let reply = ControlReply::Error("connect forwards a port".into());
            wire::send(&mut socket, reply).await
        }
        ControlRequest::Connect {
            peer,
            service,
            lifetime_port,
            lifetime_key,
        } => {
            let lifetime = local::lifetime_connect(lifetime_port, &lifetime_key).await;
            if lifetime.is_err() {
                audit("failed", Some("lifetime_channel_failed"));
            }
            let lifetime = lifetime?;
            outbound(
                &shared,
                socket,
                &peer,
                OutboundRequest::Service(PrivateRequest {
                    service,
                    terminal: None,
                    elevated: false,
                }),
                lifetime,
            )
            .await
        }
        ControlRequest::Expose {
            peer,
            service,
            target,
            lifetime_port,
            lifetime_key,
        } => {
            let lifetime = local::lifetime_connect(lifetime_port, &lifetime_key).await;
            if lifetime.is_err() {
                audit("failed", Some("lifetime_channel_failed"));
            }
            hold_exposure(shared, socket, peer, service, target, lifetime?).await
        }
        ControlRequest::Update(UpdateRequest::Identify) => {
            audit("allowed", None);
            let reply = identity(&shared).map_or(UpdateReply::Retired, UpdateReply::Identity);
            let reply = ControlReply::Update(reply);
            wire::send(&mut socket, reply).await
        }
        ControlRequest::Update(UpdateRequest::Hold) => hold_admission(&shared, socket).await,
        ControlRequest::Update(UpdateRequest::Commit) => {
            audit("denied", Some("command_rejected"));
            let reply = ControlReply::Error("a commit follows a hold on its connection".into());
            wire::send(&mut socket, reply).await
        }
        request => {
            let changes = !matches!(
                request,
                ControlRequest::Status | ControlRequest::Peers | ControlRequest::Invite
            );
            // Local store and MLS work only; no mailbox wait.
            let shared2 = shared.clone();
            let reply = tokio::task::spawn_blocking(move || {
                let reply = manage(&shared2, request);
                if changes {
                    audit::observe(&shared2.node, true);
                    shared2.peers_changed.notify_one();
                }
                reply
            })
            .await
            .unwrap_or_else(|e| ControlReply::Error(format!("command failed: {e}")));
            // The reply (an invite token included) is never logged.
            let (outcome, reason) = audit::reply_outcome(&reply);
            audit(outcome, reason);
            wire::send(&mut socket, reply).await
        }
    }
}

fn manage<M: Mailbox + Send + Sync + 'static>(
    shared: &Shared<M>,
    request: ControlRequest,
) -> ControlReply {
    let node = &shared.node;
    let err = |e: PairError| format!("{e:?}");
    let run = || -> Result<ControlReply, String> {
        if let ControlRequest::Rename { peer, alias } = &request {
            return Ok(ControlReply::Changed(node.rename(peer, alias).map_err(
                |e| match e {
                    PairError::Alias(message) => message,
                    other => err(other),
                },
            )?));
        }
        let st = node.pairing_state().map_err(err)?;
        let peer = |s: &str| st.resolve_selector(s);
        Ok(match request {
            ControlRequest::Status | ControlRequest::Peers => {
                let members = node.member_view().map_err(err)?;
                let last = shared.last_sync.lock().expect("sync note").clone();
                let mut v = view(
                    &members,
                    &st,
                    true,
                    last,
                    node.halt().map_err(err)?,
                    &node.version_observations(),
                );
                v.connections = node.log().connections();
                v.exposures = node
                    .exposures()
                    .into_iter()
                    .map(|(k, service, target)| ExposureView {
                        key: hex(&k),
                        service,
                        target,
                    })
                    .collect();
                match request {
                    ControlRequest::Peers => ControlReply::Peers(v.peers),
                    _ => ControlReply::Status(v),
                }
            }
            ControlRequest::Invite => {
                ControlReply::Invite(hex(&node.issue_invite().map_err(err)?))
            }
            ControlRequest::RenameSelf { name } => {
                node.rename_self(&name).map_err(|error| error.to_string())?;
                ControlReply::Done
            }
            ControlRequest::Approve {
                peer: p,
                alias,
                reapprove,
            } => {
                let key = peer(&p)?;
                let a = node.approve(&alias, &key, reapprove).map_err(err)?;
                ControlReply::Approved {
                    key: hex(&key),
                    fresh: a.fresh,
                }
            }
            ControlRequest::Decline { peer: p } => {
                node.decline(&peer(&p)?).map_err(err)?;
                ControlReply::Done
            }
            ControlRequest::Revoke { peer: p } => {
                let c = node.cutoff(&peer(&p)?).map_err(err)?;
                ControlReply::CutOff {
                    pairing_error: c.pairing_saved.err(),
                    removal_error: c.removal.err(),
                }
            }
            ControlRequest::Enable { peer: p, service } => {
                ControlReply::Changed(node.grant(&peer(&p)?, service).map_err(err)?)
            }
            ControlRequest::Disable { peer: p, service } => {
                ControlReply::Changed(node.revoke_grant(&peer(&p)?, service).map_err(err)?)
            }
            ControlRequest::SetDefault { service, enabled } => {
                ControlReply::Changed(node.set_default(service, enabled).map_err(err)?)
            }
            ControlRequest::Exclude { peer: p, service } => {
                ControlReply::Changed(node.exclude(&peer(&p)?, service).map_err(err)?)
            }
            ControlRequest::ClearExclusion { peer: p, service } => {
                ControlReply::Changed(node.clear_exclusion(&peer(&p)?, service).map_err(err)?)
            }
            ControlRequest::Ping { .. }
            | ControlRequest::Rename { .. }
            | ControlRequest::Shell { .. }
            | ControlRequest::Ssh { .. }
            | ControlRequest::Connect { .. }
            | ControlRequest::Expose { .. }
            | ControlRequest::Update(_) => {
                return Err("not a management command".into());
            }
        })
    };
    run().unwrap_or_else(ControlReply::Error)
}

/// The two steps of an update on one connection (see the module docs). Close admission if
/// nothing is live and keep it closed while the connection stays open, within the lease.
/// Then, only if the updater commits while that hold is in force, retire this runtime under
/// the registry lock and have it end itself. A hold that lapses, is released or is never
/// committed reopens admission and stops nothing.
async fn hold_admission<M: Mailbox + Send + Sync + 'static>(
    shared: &Shared<M>,
    mut socket: TcpStream,
) -> Result<()> {
    let log = shared.node.log();
    let record = |operation, outcome, reason| log.control(operation, outcome, None, None, reason);
    let hold = match shared.node.hold_if_idle() {
        Ok(hold) => hold,
        Err(activity) => {
            record("update_hold", "denied", Some("device_busy"));
            let reply = UpdateReply::Busy {
                connections: activity.connections,
                exposures: activity.exposures,
                held: activity.held,
            };
            return wire::send(&mut socket, ControlReply::Update(reply)).await;
        }
    };
    let Some(identity) = identity(shared) else {
        return wire::send(&mut socket, ControlReply::Update(UpdateReply::Retired)).await;
    };
    record("update_hold", "allowed", None);
    let held = UpdateReply::Held {
        lease_secs: shared.hold_lease.as_secs(),
        identity,
    };
    // The only thing the updater may say next is `Commit`. Anything else, its end or an
    // error releases the hold.
    let commit = async {
        wire::send(&mut socket, ControlReply::Update(held))
            .await
            .ok()?;
        let frame = wire::read_frame_max(&mut socket, 64).await.ok()?;
        matches!(
            serde_json::from_slice::<UpdateRequest>(&frame),
            Ok(UpdateRequest::Commit)
        )
        .then_some(())
    };
    let lapsed = tokio::select! {
        biased;
        _ = hold.retired() => Some("device_stopping"),
        committed = commit => committed.is_none().then_some("hold_released"),
        _ = tokio::time::sleep(shared.hold_lease) => Some("hold_expired"),
    };
    if let Some(reason) = lapsed {
        drop(hold);
        record("update_hold", "failed", Some(reason));
        return Ok(());
    }
    // The linearization point: stopping only if this hold still stands on an empty registry.
    if !shared.node.retire_held(&hold, "retired for an update") {
        drop(hold);
        record("update_retire", "denied", Some("hold_lost"));
        return Ok(());
    }
    record("update_retire", "allowed", None);
    // Whether or not the updater hears of it, this runtime now ends itself: nothing else is
    // asked to stop it, so nothing that might have taken its place can be stopped instead.
    let _ = wire::send(&mut socket, ControlReply::Update(UpdateReply::Retired)).await;
    shared.retired.notify_one();
    Ok(())
}

/// This process as the runtime of its profile.
fn identity<M: Mailbox + Send + Sync + 'static>(shared: &Shared<M>) -> Option<Identity> {
    let mut identity = Identity {
        pid: std::process::id(),
        executable: std::env::current_exe()
            .ok()
            .and_then(|path| path.to_str().map(str::to_owned)),
        version: env!("CARGO_PKG_VERSION").into(),
        endpoint: hex(&shared.node.endpoint_key()),
        held: false,
    };
    identity.held = shared.node.update_hold_state()?;
    Some(identity)
}

/// Hold one exposure for as long as the command's lifetime socket stays
/// open; then withdraw exactly it and tell the command why it ended.
async fn hold_exposure<M: Mailbox + Send + Sync + 'static>(
    shared: Arc<Shared<M>>,
    mut socket: TcpStream,
    selector: String,
    service: Service,
    target: Option<String>,
    mut lifetime: TcpStream,
) -> Result<()> {
    // Local store work only; no mailbox wait.
    let node = shared.node.clone();
    let made = tokio::task::spawn_blocking(move || {
        let st = node.pairing_state().map_err(|e| format!("{e:?}"))?;
        let key = st.resolve_selector(&selector)?;
        node.expose(&key, service, target)
            .map_err(|e| format!("{e:?}"))
    })
    .await
    .unwrap_or_else(|e| Err(format!("command failed: {e}")));
    let log = shared.node.log();
    let exposure = match made {
        Ok(exposure) => exposure,
        Err(e) => {
            log.control(
                "expose",
                "denied",
                None,
                Some(service),
                Some("command_rejected"),
            );
            return wire::send(&mut socket, ControlReply::Error(e)).await;
        }
    };
    let peer = exposure.peer;
    let alias = log.alias(&peer).unwrap_or_else(|| exposure.alias.clone());
    let ready = ControlReply::Exposed {
        key: hex(&peer),
        alias: alias.clone(),
    };
    log.control("expose", "allowed", Some(peer), Some(service), None);
    log.exposure("exposure_started", &peer, &alias, service);
    let mut byte = [0u8; 1];
    let ended: Result<Option<String>> = tokio::select! {
        biased;
        why = exposure.ended() => Ok(Some(why)),
        _ = lifetime.read(&mut byte) => Ok(None),
        r = async {
            wire::send(&mut socket, ready).await?;
            std::future::pending::<Result<Option<String>>>().await
        } => r,
    };
    // Withdraws exactly this exposure and ends its sessions.
    drop(exposure);
    let alias = log.alias(&peer).unwrap_or(alias);
    log.exposure("exposure_ended", &peer, &alias, service);
    let ended = ended?;

    let reply = match ended {
        None => ControlReply::Done,
        Some(why) => ControlReply::Error(format!("the {service} exposure to {alias} ended: {why}")),
    };
    // The command may already be gone.
    let _ = timeout(wire::RPC_TIMEOUT, wire::send(&mut socket, reply)).await;
    Ok(())
}

/// The address to dial for `key`, which must name exactly that endpoint.
pub(super) fn peer_address(addresses: &Addresses, key: &EndpointKey) -> Result<EndpointAddr> {
    let addr = addresses(key).context("no address is known for this peer")?;
    ensure!(
        addr.id.as_bytes() == key,
        "the peer's address names a different endpoint"
    );
    Ok(addr)
}

async fn ping_peer<M: Mailbox + Send + Sync + 'static>(
    shared: &Shared<M>,
    peer: &str,
    count: u16,
    include_route: bool,
    tx: &mut (impl AsyncWrite + Unpin),
) -> Result<()> {
    ensure!(
        (1..=MAX_PING_COUNT).contains(&count),
        "ping count must be between 1 and {MAX_PING_COUNT}"
    );
    let state = shared
        .node
        .pairing_state()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let key = state.resolve_selector(peer).map_err(anyhow::Error::msg)?;
    let addr = peer_address(&shared.addresses, &key)?;
    let opened = timeout(
        wire::RPC_TIMEOUT * 2,
        shared.node.open_ping(&shared.endpoint, addr),
    )
    .await
    .context("the peer did not answer in time")?;
    audit::observe(&shared.node, false);
    let stream = opened.map_err(|e| match e {
        PairError::Refused(Refusal::ConnectionClosed) | PairError::Local(_) => anyhow::anyhow!(
            "could not start ping: {e:?}. Check that the peer is online and both daemons support ping"
        ),
        _ => anyhow::anyhow!("could not start ping: {e:?}"),
    })?;
    let samples = async {
        if let ServiceReply::Refused { message, .. } = &stream.reply {
            bail!("the peer refused: {message}");
        }
        wire::send(tx, ControlReply::PingStarted).await?;
        let mut ticks = tokio::time::interval(Duration::from_secs(1));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        for _ in 0..count {
            ticks.tick().await;
            let elapsed = stream.probe().await?.map(|rtt| rtt.as_micros() as u64);
            let sample = match elapsed {
                Some(micros) if include_route => ControlReply::PingSampleWithRoute {
                    micros,
                    // Sample the selected transmission path at receipt. Iroh's
                    // datagram API does not identify the path the reply took.
                    route: PingRoute::selected(&stream.conn),
                },
                _ => ControlReply::PingSample(elapsed),
            };
            wire::send(tx, sample).await?;
        }
        Ok(())
    };
    let (result, reason) = tokio::select! {
        biased;
        why = stream.done() => (
            Err(anyhow::anyhow!("ping connection ended: {why:?}")),
            CLOSE_AUTHORITY_ENDED,
        ),
        result = samples => (result, CLOSE_DONE),
    };
    stream.conn.close(0u32.into(), reason);
    result
}

enum OutboundRequest {
    Service(PrivateRequest),
    Ssh(ssh::Request),
}

/// Open a service on a peer for a local command and attach it. The
/// command's lifetime socket ends the session at once, at any point: during
/// setup, while a reply or data write is backed up, and during the final
/// local drain. A TCP upload's half-close is a frame, not the lifetime, so
/// the other direction stays open.
async fn outbound<M: Mailbox + Send + Sync + 'static>(
    shared: &Shared<M>,
    mut socket: TcpStream,
    selector: &str,
    req: OutboundRequest,
    mut lifetime: TcpStream,
) -> Result<()> {
    // Resolves (and stays resolved when polled again) once the command's
    // lifetime socket yields anything: EOF, an error or a byte.
    let mut left = false;
    let mut local_closed = std::future::poll_fn(|cx| {
        if !left {
            let mut byte = [0u8; 1];
            let mut buf = tokio::io::ReadBuf::new(&mut byte);
            if std::pin::Pin::new(&mut lifetime)
                .poll_read(cx, &mut buf)
                .is_pending()
            {
                return std::task::Poll::Pending;
            }
            left = true;
        }
        std::task::Poll::Ready(())
    });
    let log = shared.node.log();
    let service = match req {
        OutboundRequest::Service(req) => req.service,
        OutboundRequest::Ssh(_) => Service::Shell,
    };
    let track = log.outbound(service);
    // Each failure carries its fixed log reason and the text for the command.
    let setup = async {
        let st = shared
            .node
            .pairing_state()
            .map_err(|e| ("setup_failed", format!("{e:?}")))?;
        let key = st
            .resolve_selector(selector)
            .map_err(|e| ("unknown_peer", e))?;
        track.peer(log, &key);
        let addr =
            peer_address(&shared.addresses, &key).map_err(|e| ("setup_failed", e.to_string()))?;
        let opened = match req {
            OutboundRequest::Service(req) => {
                shared.node.open_service(&shared.endpoint, addr, req).await
            }
            OutboundRequest::Ssh(req) => shared.node.open_ssh(&shared.endpoint, addr, req).await,
        };
        // The exchange may have learned a decision or paired.
        audit::observe(&shared.node, false);
        opened.map_err(|e| (audit::pair_error_reason(&e), format!("{e:?}")))
    };
    let opened = tokio::select! {
        biased;
        _ = &mut local_closed => {
            track.end("local_client_closed", None);
            return Ok(());
        }
        r = timeout(wire::RPC_TIMEOUT * 2, setup) => r,
    };
    let error = match opened {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e),
        Err(_) => Err((
            "deadline_elapsed",
            "the peer did not answer in time".to_string(),
        )),
    };
    let error = error.and_then(|s| match &s.reply {
        ServiceReply::Refused { refusal, message } => {
            s.conn.close(0u32.into(), CLOSE_DONE);
            Err((refusal.reason(), format!("the peer refused: {message}")))
        }
        ServiceReply::Ready => Ok(s),
    });
    let stream = match error {
        Ok(s) => s,
        Err((reason, e)) => {
            track.end(reason, None);
            tokio::select! {
                biased;
                _ = &mut local_closed => {}
                r = wire::send(&mut socket, ControlReply::Error(e)) => r?,
            }
            return Ok(());
        }
    };
    let is_shell = matches!(
        req,
        OutboundRequest::Service(PrivateRequest {
            service: Service::Shell,
            ..
        })
    );
    let ready = match stream.ssh_host {
        Some(host) => ControlReply::SshHost(host),
        None if is_shell => ControlReply::Shell,
        None => ControlReply::Connected,
    };
    let info_only = matches!(ready, ControlReply::SshHost(_));
    track.connected(Some(&stream.conn));
    let max_frame = match req {
        OutboundRequest::Service(_) => max_payload_frame(service),
        OutboundRequest::Ssh(_) => crate::tcp::MAX_FRAME,
    };
    let ServiceStream {
        conn,
        auth,
        mut tx,
        mut rx,
        ..
    } = stream;
    let sent = tokio::select! {
        biased;
        _ = &mut local_closed => Ok(false),
        why = auth.done(), if matches!(req, OutboundRequest::Ssh(_)) => {
            conn.close(0u32.into(), CLOSE_AUTHORITY_ENDED);
            track.end(if why == Refusal::ConnectionClosed { "peer_disconnected" } else { "authorization_ended" }, None);
            return Ok(());
        }
        r = wire::send(&mut socket, ready) => r.map(|()| true),
    };
    match sent {
        Ok(true) => {}
        Ok(false) => {
            conn.close(0u32.into(), CLOSE_DONE);
            track.end("local_client_closed", None);
            return Ok(());
        }
        Err(e) => {
            conn.close(0u32.into(), CLOSE_DONE);
            track.end("local_client_closed", None);
            return Err(e);
        }
    }
    if info_only {
        conn.close(0u32.into(), CLOSE_DONE);
        track.end("stream_closed", None);
        return Ok(());
    }
    // Resolves only when this device ends the authorization (the
    // connection's own end is reported by the copy or delivery).
    let stopped = async {
        if auth.done().await == Refusal::ConnectionClosed {
            std::future::pending::<()>().await;
        }
        conn.close(0u32.into(), CLOSE_AUTHORITY_ENDED);
    };
    let (mut local_rx, mut local_tx) = socket.into_split();
    if is_shell {
        let reason = tokio::select! {
            biased;
            _ = shared.node.watch_routes(&conn) => unreachable!("route watcher stays pending"),
            _ = stopped => "authorization_ended",
            _ = &mut local_closed => "local_client_closed",
            copied = async {
                tokio::try_join!(
                    async {
                        tokio::io::copy(&mut local_rx, &mut tx).await?;
                        tx.shutdown().await
                    },
                    async {
                        tokio::io::copy(&mut rx, &mut local_tx).await?;
                        local_tx.shutdown().await
                    },
                )
            } => match copied {
                Ok(_) => "stream_closed",
                Err(_) if conn.close_reason().is_some() => peer_cut_reason(&conn),
                Err(_) => "shell_io_error",
            },
        };
        conn.close(0u32.into(), CLOSE_DONE);
        track.end(reason, None);
        return Ok(());
    }
    let mut writing = false;
    let ended = tokio::select! {
        biased;
        _ = shared.node.watch_routes(&conn) => unreachable!("route watcher stays pending"),
        result = tunnel::forward(
        &mut rx,
        &mut tx,
        &mut local_rx,
        &mut local_tx,
        &mut writing,
        &mut local_closed,
        stopped,
        max_frame,
        ) => result,
    };
    track.end(
        match ended {
            tunnel::Forwarded::Stopped => "authorization_ended",
            tunnel::Forwarded::Done => "stream_closed",
            tunnel::Forwarded::Failed => "service_failed",
            tunnel::Forwarded::LocalClosed => "local_client_closed",
            tunnel::Forwarded::PeerCut => peer_cut_reason(&conn),
        },
        None,
    );
    let message = match ended {
        tunnel::Forwarded::Stopped => Some("the authorization ended on this device"),
        tunnel::Forwarded::Done | tunnel::Forwarded::Failed | tunnel::Forwarded::LocalClosed => {
            None
        }
        tunnel::Forwarded::PeerCut => Some(match conn.close_reason() {
            Some(iroh::endpoint::ConnectionError::ApplicationClosed(c))
                if c.reason.as_ref() == CLOSE_AUTHORITY_ENDED =>
            {
                "the destination ended this authorization"
            }
            _ => "the connection to the destination was lost",
        }),
    };
    conn.close(0u32.into(), CLOSE_DONE);
    drop(auth);
    if matches!(ended, tunnel::Forwarded::LocalClosed) {
        // The command is gone: there is no final frame to protect.
        return Ok(());
    }
    // The final local drain lasts only while the command is still there.
    tokio::select! {
        biased;
        _ = &mut local_closed => Ok(()),
        r = tunnel::finish_local(&mut local_rx, &mut local_tx, writing, message) => r,
    }
}

/// Log reason for a connection the destination (or the path) closed.
fn peer_cut_reason(conn: &iroh::endpoint::Connection) -> &'static str {
    match conn.close_reason() {
        Some(iroh::endpoint::ConnectionError::ApplicationClosed(c))
            if c.reason.as_ref() == CLOSE_AUTHORITY_ENDED =>
        {
            "authorization_ended"
        }
        _ => "peer_disconnected",
    }
}

// ------------------------------------------------------------- client side

/// Send one command to the private runtime of `dir`; the socket is
/// returned for shell, connect, and ping.
pub async fn request(dir: &Path, request: ControlRequest) -> Result<(TcpStream, ControlReply)> {
    timeout(wire::RPC_TIMEOUT * 3, async {
        let mut socket = local::connect_on(dir, &CONTROL).await?;
        wire::send(&mut socket, request).await?;
        let reply: ControlReply = wire::recv(&mut socket).await?;
        Ok((socket, reply))
    })
    .await
    .context("local request timed out")?
}

/// `request`, with an `Error` reply as an error.
pub async fn command(dir: &Path, request: ControlRequest) -> Result<ControlReply> {
    match self::request(dir, request).await?.1 {
        ControlReply::Error(e) => bail!("{e}"),
        reply => Ok(reply),
    }
}

/// Interactive shell on a peer through the private runtime. Output frames
/// longer than the shell format allows end the session.
pub async fn shell(dir: &Path, peer: String, elevated: bool) -> Result<i32> {
    let (cols, rows) = terminal::size()?;
    let lifetime = local::Lifetime::bind().await?;
    let req = ControlRequest::Shell {
        peer,
        elevated,
        cols,
        rows,
        lifetime_port: lifetime.port,
        lifetime_key: lifetime.key,
    };
    // The runtime connects the lifetime socket before it replies (a
    // connect completes on the listen backlog), so the reply comes first.
    let (socket, reply) = self::request(dir, req).await?;
    if let ControlReply::Error(e) = reply {
        bail!("{e}");
    }
    let _lifetime = timeout(wire::RPC_TIMEOUT, lifetime.accept())
        .await
        .context("the runtime did not open the lifetime channel")??;
    match reply {
        ControlReply::Shell => {}
        ControlReply::Error(e) => bail!("{e}"),
        _ => bail!("unexpected shell reply"),
    }
    let (rx, tx) = socket.into_split();
    terminal::attach_max(rx, tx, (cols, rows), terminal::MAX_OUTPUT_FRAME).await
}

/// Forward a peer's port through the private runtime (TCP over stdin and
/// stdout, UDP through a loopback socket), like `massrelay connect`.
pub async fn connect(
    dir: &Path,
    peer: String,
    service: Service,
    listen: Option<u16>,
) -> Result<()> {
    let datagrams = local::claim_forward(service, listen).await?;
    let lifetime = local::Lifetime::bind().await?;
    let req = ControlRequest::Connect {
        peer: peer.clone(),
        service,
        lifetime_port: lifetime.port,
        lifetime_key: lifetime.key,
    };
    let (socket, reply) = self::request(dir, req).await?;
    if let ControlReply::Error(e) = reply {
        bail!("{e}");
    }
    let _lifetime = timeout(wire::RPC_TIMEOUT, lifetime.accept())
        .await
        .context("the runtime did not open the lifetime channel")??;
    match reply {
        ControlReply::Connected => {}
        ControlReply::Error(e) => bail!("{e}"),
        _ => bail!("unexpected connection reply"),
    }
    ensure!(
        socket.peer_addr()?.ip().is_loopback(),
        "invalid runtime address"
    );
    local::attach_forward(socket, datagrams, &peer, service).await
}

/// Expose a port to one peer through the private runtime until this command
/// is interrupted or the runtime withdraws the exposure (like
/// `massrelay expose`).
pub async fn expose(
    dir: &Path,
    service: Service,
    peer: String,
    target: Option<String>,
) -> Result<()> {
    let forwarding = match (&target, service) {
        (Some(target), _) => {
            wire::check_target(target)?;
            target.clone()
        }
        (None, Service::Tcp(port) | Service::Udp(port)) => format!("loopback port {port}"),
        (None, Service::Shell) => bail!("only a port can be exposed"),
    };
    let lifetime = local::Lifetime::bind().await?;
    let req = ControlRequest::Expose {
        peer,
        service,
        target,
        lifetime_port: lifetime.port,
        lifetime_key: lifetime.key,
    };
    let (socket, reply) = self::request(dir, req).await?;
    if let ControlReply::Error(e) = reply {
        bail!("{e}");
    }
    let keep = timeout(wire::RPC_TIMEOUT, lifetime.accept())
        .await
        .context("the runtime did not open the lifetime channel")??;
    let ControlReply::Exposed { key, alias } = reply else {
        bail!("unexpected exposure reply");
    };
    let (mut rx, _tx) = socket.into_split();
    let ended = wire::recv::<ControlReply>(&mut rx);
    let interrupted = crate::shutdown();
    tokio::pin!(ended, interrupted);
    eprintln!(
        "massrelay: exposing {service} to {alias} ({key}), forwarding to {forwarding}, \
         until this command exits. Press Ctrl-C to stop."
    );
    tokio::select! {
        biased;
        signal = &mut interrupted => {
            signal.context("wait for shutdown")?;
            // Closing the lifetime withdraws the exposure; wait for the
            // runtime to confirm it is gone.
            drop(keep);
            let reply = timeout(wire::RPC_TIMEOUT, ended)
                .await
                .context("the runtime did not confirm that the exposure ended")??;
            ensure!(
                matches!(reply, ControlReply::Done | ControlReply::Error(_)),
                "unexpected exposure reply"
            );
            Ok(())
        }
        reply = &mut ended => match reply {
            Ok(ControlReply::Error(e)) => bail!("{e}"),
            _ => bail!("the private runtime stopped, which ended the exposure"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_resolve_to_keys_or_locally_pinned_aliases_only() {
        let key = [7u8; 32];
        let mut st = PairingState::default();
        // A bare key always resolves, pinned or not.
        assert_eq!(st.resolve_selector(&hex(&key)), Ok(key));
        assert!(
            st.resolve_selector("bob").is_err(),
            "unknown names never resolve"
        );
        st.peers.push(pairing::PeerRecord {
            endpoint: key,
            alias: "bob".into(),
            local: Decision::Decline,
            local_order: 1,
            remote: Decision::Unknown,
            remote_order: 0,
            pairing: None,
        });
        assert_eq!(st.resolve_selector("bob"), Ok(key));
        assert!(st.resolve_selector(&"z".repeat(64)).is_err());
        assert!(parse_key(&hex(&[1; 31])).is_none());
    }
}
