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
//! # Not here
//!
//! No OS service manager, installer, temporary exposures, destination-chosen
//! non-loopback targets, roles or additional capabilities. The experimental
//! CLI over this runtime is `super::cli`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::local::{self, Channel};
use crate::wire::{self, GrantRule, Service, ServiceReply};
use crate::{terminal, tunnel};

use super::binding::EndpointKey;
use super::codec::{hex, unhex};
use super::mailbox::Mailbox;
use super::membership::{Clock, Device};
use super::pairing::{self, Decision, Owner, PairError, PairingState, Refusal};
use super::service::{CLOSE_AUTHORITY_ENDED, CLOSE_DONE, Node, PrivateRequest, ServiceStream};

/// The private runtime's local control channel.
pub const CONTROL: Channel = Channel {
    marker: "private-runtime.json",
    daemon_role: b"massrelay private runtime experimental-1",
    client_role: b"massrelay private client experimental-1",
    unavailable: "private runtime unavailable; start it in the foreground first",
};

/// Bound on joining each task group during `stop`.
const STOP_WAIT: Duration = Duration::from_secs(10);

// ------------------------------------------------------------------ protocol

/// One local control command (experimental; JSON over the control socket).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlRequest {
    Status,
    Peers,
    Invite,
    /// Approve `peer` (endpoint key, or an alias already pinned to one) and
    /// pin `alias` to it.
    Approve {
        peer: String,
        alias: String,
        reapprove: bool,
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
    Shell {
        peer: String,
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
}

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
    Error(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    pub endpoint: String,
    /// Read from the running owner (`true`) or without one (`false`).
    pub running: bool,
    /// Registered authorizations and sessions (running owner only).
    pub live_sessions: Option<usize>,
    pub peers: Vec<PeerView>,
    /// Services enabled by default for every paired peer.
    pub defaults: Vec<Service>,
    /// Per-peer grants on this device: (endpoint key, service).
    pub grants: Vec<(String, Service)>,
    pub exclusions: Vec<(String, Service)>,
    /// Outcome of the last membership pass (running owner only).
    pub last_sync: Option<String>,
    /// The recorded membership halt, if any.
    pub halt: Option<String>,
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
    endpoint: &EndpointKey,
    roster: &[EndpointKey],
    st: &PairingState,
    running: bool,
    live_sessions: Option<usize>,
    last_sync: Option<String>,
    halt: Option<String>,
) -> StatusView {
    let mut peers: Vec<PeerView> = st
        .peers
        .iter()
        .map(|p| PeerView {
            key: hex(&p.endpoint),
            alias: Some(p.alias.clone()),
            member: roster.contains(&p.endpoint),
            local: decision(&p.local),
            remote: decision(&p.remote),
            paired: p.pairing.is_some(),
        })
        .collect();
    for key in roster {
        if key != endpoint && !st.peers.iter().any(|p| &p.endpoint == key) {
            peers.push(PeerView {
                key: hex(key),
                alias: None,
                member: true,
                local: "none".into(),
                remote: "none".into(),
                paired: false,
            });
        }
    }
    peers.sort_by(|a, b| a.key.cmp(&b.key));
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
        .collect();
    let exclusions = st.exclusions.iter().map(|(k, s)| (hex(k), *s)).collect();
    StatusView {
        endpoint: hex(endpoint),
        running,
        live_sessions,
        peers,
        defaults,
        grants,
        exclusions,
        last_sync,
        halt,
    }
}

/// Status read without the runtime owner (for a second process). Never
/// writes and offers no mutation.
pub fn offline_status<M: Mailbox>(device: &Device<M>) -> Result<StatusView, PairError> {
    let state = device.state()?;
    let st = pairing::read_state(device)?;
    let roster = device.roster().unwrap_or_default();
    let halt = state.halt.map(|h| format!("{h:?}"));
    Ok(view(&state.endpoint, &roster, &st, false, None, None, halt))
}

/// An endpoint key written as 64 hex digits or in Iroh's own form.
fn parse_key(s: &str) -> Option<EndpointKey> {
    if s.len() == 64
        && let Some(b) = unhex(s)
    {
        return b.try_into().ok();
    }
    s.parse::<EndpointId>().ok().map(|id| *id.as_bytes())
}

/// Resolve a selector to a key: an endpoint key, or an alias this device
/// pinned. Roster names are never consulted.
fn resolve(st: &PairingState, selector: &str) -> Result<EndpointKey, String> {
    if let Some(key) = parse_key(selector) {
        return Ok(key);
    }
    let mut hits = st.peers.iter().filter(|p| p.alias == selector);
    match (hits.next(), hits.next()) {
        (Some(p), None) => Ok(p.endpoint),
        (None, _) => Err(format!(
            "no peer pinned as {selector:?} on this device; name it by endpoint key"
        )),
        _ => Err(format!("{selector:?} names more than one pinned peer")),
    }
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
}

impl Config {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            shell: None,
            sync_every: Some(Duration::from_secs(30)),
            addresses: Arc::new(|key| EndpointId::from_bytes(key).ok().map(EndpointAddr::new)),
        }
    }
}

struct Shared<M: Mailbox> {
    node: Arc<Node<M>>,
    endpoint: Endpoint,
    addresses: Addresses,
    last_sync: Mutex<Option<String>>,
}

/// A running private profile. Drop stops admission and retires sessions
/// but cannot wait; call `stop` to join everything.
pub struct Runtime<M: Mailbox + Send + Sync + 'static> {
    shared: Option<Arc<Shared<M>>>,
    dir: PathBuf,
    stop: watch::Sender<bool>,
    tasks: Vec<(&'static str, JoinHandle<()>)>,
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
        let node = Node::new(device, owner, config.shell)?;
        node.check_endpoint(&endpoint)?;
        let (listener, marker) = local::listen_on(&config.dir, &CONTROL)
            .await
            .map_err(|e| local(&e))?;
        let shared = Arc::new(Shared {
            node,
            endpoint,
            addresses: config.addresses,
            last_sync: Mutex::new(None),
        });
        let (stop, stopping) = watch::channel(false);
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
                    let pass = tokio::task::spawn_blocking(move || node.sync_membership());
                    tokio::select! {
                        biased;
                        // A pass blocked in the mailbox is left to finish on
                        // its worker; it holds no lock meanwhile.
                        _ = &mut stop => break,
                        r = pass => {
                            let note = match r {
                                Ok(s) => format!("{s:?}"),
                                Err(e) => format!("membership pass failed: {e}"),
                            };
                            *shared.last_sync.lock().expect("sync note") = Some(note);
                        }
                    }
                }
            };
            tasks.push(("membership", tokio::spawn(sync)));
        }

        Ok(Self {
            shared: Some(shared),
            dir: config.dir,
            stop,
            tasks,
        })
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
    let request: ControlRequest = timeout(wire::RPC_TIMEOUT, async {
        local::authenticate_on(&mut socket, marker, &CONTROL).await?;
        wire::recv(&mut socket).await
    })
    .await
    .context("local request timed out")??;
    socket.set_nodelay(true)?;
    // A command read after stop linearized is refused (status may still be
    // read). `Peers` refuses every mutation then as well.
    if shared.node.stopping() && !matches!(request, ControlRequest::Status | ControlRequest::Peers)
    {
        let reply = ControlReply::Error("the private runtime is stopping".into());
        return wire::send(&mut socket, reply).await;
    }
    match request {
        ControlRequest::Shell {
            peer,
            cols,
            rows,
            lifetime_port,
            lifetime_key,
        } => {
            let lifetime = local::lifetime_connect(lifetime_port, &lifetime_key).await?;
            outbound(
                &shared,
                socket,
                &peer,
                Service::Shell,
                Some((cols, rows)),
                lifetime,
            )
            .await
        }
        ControlRequest::Connect {
            service: Service::Shell,
            ..
        } => {
            let reply = ControlReply::Error("connect forwards a port".into());
            wire::send(&mut socket, reply).await
        }
        ControlRequest::Connect {
            peer,
            service,
            lifetime_port,
            lifetime_key,
        } => {
            let lifetime = local::lifetime_connect(lifetime_port, &lifetime_key).await?;
            outbound(&shared, socket, &peer, service, None, lifetime).await
        }
        request => {
            // Local store and MLS work only; no mailbox wait.
            let shared2 = shared.clone();
            let reply = tokio::task::spawn_blocking(move || manage(&shared2, request))
                .await
                .unwrap_or_else(|e| ControlReply::Error(format!("command failed: {e}")));
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
        let st = node.pairing_state().map_err(err)?;
        let peer = |s: &str| resolve(&st, s);
        Ok(match request {
            ControlRequest::Status | ControlRequest::Peers => {
                let roster = node.roster().unwrap_or_default();
                let last = shared.last_sync.lock().expect("sync note").clone();
                let v = view(
                    &node.endpoint_key(),
                    &roster,
                    &st,
                    true,
                    Some(node.live_sessions()),
                    last,
                    node.halt().map_err(err)?,
                );
                match request {
                    ControlRequest::Peers => ControlReply::Peers(v.peers),
                    _ => ControlReply::Status(v),
                }
            }
            ControlRequest::Invite => {
                ControlReply::Invite(hex(&node.issue_invite().map_err(err)?))
            }
            ControlRequest::Approve {
                peer: p,
                alias,
                reapprove,
            } => {
                if parse_key(&alias).is_some() {
                    return Err("an alias must not look like an endpoint key".into());
                }
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
            ControlRequest::Shell { .. } | ControlRequest::Connect { .. } => {
                return Err("not a management command".into());
            }
        })
    };
    run().unwrap_or_else(ControlReply::Error)
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
    service: Service,
    terminal: Option<(u16, u16)>,
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
    let setup = async {
        let st = shared.node.pairing_state().map_err(|e| format!("{e:?}"))?;
        let key = resolve(&st, selector)?;
        let addr = (shared.addresses)(&key).ok_or("no address is known for this peer")?;
        if addr.id.as_bytes() != &key {
            return Err("the peer's address names a different endpoint".to_string());
        }
        let req = PrivateRequest { service, terminal };
        shared
            .node
            .open_service(&shared.endpoint, addr, req)
            .await
            .map_err(|e| format!("{e:?}"))
    };
    let opened = tokio::select! {
        biased;
        _ = &mut local_closed => return Ok(()),
        r = timeout(wire::RPC_TIMEOUT * 2, setup) => r,
    };
    let error = match opened {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("the peer did not answer in time".to_string()),
    };
    let error = error.and_then(|s| match &s.reply {
        ServiceReply::Refused { message, .. } => {
            s.conn.close(0u32.into(), CLOSE_DONE);
            Err(format!("the peer refused: {message}"))
        }
        ServiceReply::Ready => Ok(s),
    });
    let stream = match error {
        Ok(s) => s,
        Err(e) => {
            tokio::select! {
                biased;
                _ = &mut local_closed => {}
                r = wire::send(&mut socket, ControlReply::Error(e)) => r?,
            }
            return Ok(());
        }
    };
    let ready = match service {
        Service::Shell => ControlReply::Shell,
        _ => ControlReply::Connected,
    };
    let max_frame = stream.max_frame();
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
        r = wire::send(&mut socket, ready) => r.map(|()| true),
    };
    match sent {
        Ok(true) => {}
        Ok(false) => {
            conn.close(0u32.into(), CLOSE_DONE);
            return Ok(());
        }
        Err(e) => {
            conn.close(0u32.into(), CLOSE_DONE);
            return Err(e);
        }
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
    if service == Service::Shell {
        tokio::select! {
            _ = stopped => {}
            _ = &mut local_closed => {}
            _ = async {
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
            } => {}
        }
        conn.close(0u32.into(), CLOSE_DONE);
        return Ok(());
    }
    let mut writing = false;
    let ended = tunnel::forward(
        &mut rx,
        &mut tx,
        &mut local_rx,
        &mut local_tx,
        &mut writing,
        &mut local_closed,
        stopped,
        max_frame,
    )
    .await;
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

// ------------------------------------------------------------- client side

/// Send one command to the private runtime of `dir`; the socket is
/// returned for shell and connect.
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
pub async fn shell(dir: &Path, peer: String) -> Result<i32> {
    let (cols, rows) = terminal::size()?;
    let lifetime = local::Lifetime::bind().await?;
    let req = ControlRequest::Shell {
        peer,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_resolve_to_keys_or_locally_pinned_aliases_only() {
        let key = [7u8; 32];
        let mut st = PairingState::default();
        // A bare key always resolves, pinned or not.
        assert_eq!(resolve(&st, &hex(&key)), Ok(key));
        assert!(resolve(&st, "bob").is_err(), "unknown names never resolve");
        st.peers.push(pairing::PeerRecord {
            endpoint: key,
            alias: "bob".into(),
            local: Decision::Decline,
            local_order: 1,
            remote: Decision::Unknown,
            remote_order: 0,
            pairing: None,
        });
        assert_eq!(resolve(&st, "bob"), Ok(key));
        assert!(resolve(&st, &"z".repeat(64)).is_err());
        assert!(parse_key(&hex(&[1; 31])).is_none());
    }
}
