use std::{
    collections::BTreeMap,
    fs::File,
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    task::{Poll, ready},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey,
    endpoint::{Connection, ConnectionError, RecvStream, SendStream},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, watch},
    task::JoinSet,
    time::{MissedTickBehavior, timeout},
};

use crate::{
    bind_endpoint,
    connection_log::{ConnectionLog, Direction, Session},
    grants::{Access, Grants, RemovedGrant},
    local, storage, tcp, terminal, tunnel, udp,
    wire::{
        self, Decision, LocalReply, LocalRequest, Member, Peer, Refusal, Reply, Request, Roster,
        ServerAddr, Service, ServiceReply, ServiceRequest, Ticket,
    },
};

const FILE: &str = "device.json";
const PENDING: &str = "pending-device.json";
const SYNC_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Clone, Serialize, Deserialize)]
struct Identity {
    key: [u8; 32],
    server: ServerAddr,
}

impl Identity {
    fn public(&self) -> EndpointId {
        SecretKey::from_bytes(&self.key).public()
    }
}

/// A device name from the host's name, falling back to a label from the device key.
fn default_name(id: EndpointId) -> String {
    ["HOSTNAME", "COMPUTERNAME"]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok())
        .chain(
            std::iter::once_with(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
                .flatten(),
        )
        .chain(std::iter::once_with(hostname_command).flatten())
        .find_map(|host| host_label(&host))
        .unwrap_or_else(|| format!("device-{}", id.fmt_short()))
}

fn hostname_command() -> Option<String> {
    let output = std::process::Command::new("hostname").output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The first label of a hostname, restricted to characters allowed in device names.
fn host_label(host: &str) -> Option<String> {
    let label: String = host
        .trim()
        .split('.')
        .next()?
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let label = label.trim_matches('-');
    (!label.eq_ignore_ascii_case("localhost") && wire::check_name(label).is_ok())
        .then(|| label.to_owned())
}

#[derive(Serialize, Deserialize)]
struct PendingEnrollment {
    #[serde(flatten)]
    identity: Identity,
    operation: Option<Enrollment>,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
enum Enrollment {
    SharedCreate,
    OperatorTicket([u8; 32]),
    JoinInvite([u8; 32]),
}

#[derive(Clone, Serialize, Deserialize)]
struct Device {
    identity: Identity,
    roster: Roster,
    approvals: BTreeMap<EndpointId, u64>,
    #[serde(default)]
    pending_declines: BTreeMap<EndpointId, u64>,
    #[serde(default)]
    grants: Grants,
    #[serde(default)]
    udp_port: Option<u16>,
    #[serde(skip)]
    dirty: bool,
    revoked: bool,
}

impl Device {
    /// Whether both devices currently approve this pairing generation.
    fn paired(&self, id: EndpointId, network: &str, generation: u64) -> bool {
        self.roster.network == network
            && self.roster.peers.iter().any(|peer| {
                peer.member.id == id
                    && peer.pair.generation == generation
                    && self.peer_is_paired(peer)
            })
    }

    fn peer_is_paired(&self, peer: &Peer) -> bool {
        !self.revoked
            && self.approvals.get(&peer.member.id) == Some(&peer.pair.generation)
            && peer.pair.ours == Some(Decision::Approve)
            && peer.pair.theirs == Some(Decision::Approve)
    }

    /// Both mutual pairing and a grant for this peer and service are required.
    fn access(&self, id: EndpointId, request: &ServiceRequest) -> Result<Access, Refusal> {
        if !self.paired(id, &request.network, request.generation) {
            return Err(Refusal::PairingRequired);
        }
        self.grants
            .access(id, request.service, request.generation)
            .ok_or(Refusal::ServiceNotEnabled)
    }

    fn check_grant(
        &self,
        id: EndpointId,
        request: &ServiceRequest,
        instance: u64,
    ) -> Result<(), Refusal> {
        if self.access(id, request)?.instance == instance {
            Ok(())
        } else {
            Err(Refusal::ServiceNotEnabled)
        }
    }

    /// The pairing generation that a new grant for a known peer belongs to.
    fn grant_generation(&self, peer: &Member) -> Result<u64> {
        ensure!(!self.revoked, "this device has been revoked");
        ensure!(
            !self.pending_declines.contains_key(&peer.id),
            "the decline of {} has not reached the relay yet; try again after it does",
            peer.name
        );
        self.roster
            .peers
            .iter()
            .find(|known| known.member.id == peer.id)
            .map(|known| known.pair.generation)
            .with_context(|| format!("unknown peer {}", peer.name))
    }

    /// Forget grants made under a pairing that has since ended.
    fn prune_grants(&mut self) -> Vec<(EndpointId, Service, RemovedGrant)> {
        let (revoked, declines, peers) = (self.revoked, &self.pending_declines, &self.roster.peers);
        self.grants.retain(|id, generation| {
            !revoked
                && !declines.contains_key(&id)
                && peers
                    .iter()
                    .any(|peer| peer.member.id == id && peer.pair.generation == generation)
        })
    }
}

struct Node {
    state: Mutex<Device>,
    operations: Mutex<()>,
    endpoint: Endpoint,
    dir: PathBuf,
    shell: Option<PathBuf>,
    connection_log: ConnectionLog,
    changed: watch::Sender<()>,
}

/// Redeem an operator creation ticket (`create`) or a join invite.
pub async fn enroll(dir: &Path, ticket: Ticket, name: Option<String>, create: bool) -> Result<()> {
    let fingerprint = Sha256::digest(ticket.secret.as_bytes()).into();
    let operation = if create {
        Enrollment::OperatorTicket(fingerprint)
    } else {
        Enrollment::JoinInvite(fingerprint)
    };
    let (_lock, identity) = prepare(dir, ticket.server, operation)?;
    let defaulted = name.is_none();
    let name = name.unwrap_or_else(|| {
        let name = default_name(identity.public());
        eprintln!("massrelay: joining as {name}, from this machine's hostname");
        name
    });
    let request = Request::Enroll {
        secret: ticket.secret,
        name: name.clone(),
        create,
    };
    match register(&identity, request).await? {
        Reply::Roster(roster) => commit(dir, identity, roster),
        Reply::Revoked => bail!("this device was revoked; use a new state directory"),
        Reply::Error(error) => {
            // The relay checks for existing enrollment before rejecting these credentials.
            // A transport failure leaves the pending identity intact for an exact retry.
            if (create && error == wire::INVALID_CREATE_TICKET)
                || (!create
                    && matches!(
                        error.as_str(),
                        wire::INVALID_JOIN_INVITE | wire::EXPIRED_INVITE
                    ))
            {
                std::fs::remove_file(dir.join(PENDING)).context("clear the rejected enrollment")?;
            }
            if defaulted && error == wire::NAME_IN_USE {
                bail!("name {name} is already in use; choose another with --name");
            }
            bail!("{error}");
        }
        _ => bail!("unexpected enrollment reply"),
    }
}

/// Create a pocket network on a shared relay. Returns this device's name and the first invite.
pub async fn create(
    dir: &Path,
    server: ServerAddr,
    name: Option<String>,
) -> Result<(String, String)> {
    let (_lock, identity) = prepare(dir, server, Enrollment::SharedCreate)?;
    let name = name.unwrap_or_else(|| default_name(identity.public()));
    match register(&identity, Request::Create { name }).await? {
        Reply::Created {
            name,
            roster,
            invite,
        } => {
            let invite = Ticket {
                server: identity.server.clone(),
                secret: invite,
            }
            .encode()?;
            commit(dir, identity, roster)?;
            Ok((name, invite))
        }
        Reply::Revoked => bail!("this device was revoked; use a new state directory"),
        Reply::Error(error) => bail!("{error}"),
        _ => bail!("unexpected creation reply"),
    }
}

/// Persist the key and operation together before sending a request. An authenticated retry
/// may return a prior enrollment, so reuse the key only for the same operation.
fn prepare(dir: &Path, server: ServerAddr, operation: Enrollment) -> Result<(File, Identity)> {
    let lock = storage::lock(dir)?;
    ensure!(
        !dir.join(FILE).try_exists()?,
        "this device already belongs to a network; use a new state directory"
    );
    let mut pending = if dir.join(PENDING).try_exists()? {
        let mut pending: PendingEnrollment = storage::load(dir, PENDING)?;
        ensure!(
            pending.identity.server.id == server.id,
            "pending enrollment uses another relay; use a new state directory"
        );
        match &pending.operation {
            Some(previous) => ensure!(
                previous == &operation,
                "another enrollment is pending; retry the original command or use a new state directory"
            ),
            None => bail!(
                "enrollment began with an earlier version; finish it with the original client and ticket, \
                 or use a new state directory"
            ),
        }
        pending.identity.server = server;
        pending
    } else {
        PendingEnrollment {
            identity: Identity {
                key: wire::random()?,
                server,
            },
            operation: None,
        }
    };
    if pending.operation.is_none() {
        pending.operation = Some(operation);
        storage::save(dir, PENDING, &pending)?;
    }
    Ok((lock, pending.identity))
}

async fn register(identity: &Identity, request: Request) -> Result<Reply> {
    let bind = if identity.server.udp.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let endpoint = bind_endpoint(
        SecretKey::from_bytes(&identity.key),
        bind.parse()?,
        None,
        wire::SERVICE,
        false,
    )
    .await?;
    let reply = exchange(&endpoint, &identity.server, false, request).await;
    endpoint.close().await;
    reply
}

fn commit(dir: &Path, identity: Identity, roster: Roster) -> Result<()> {
    let device = Device {
        identity,
        roster,
        approvals: BTreeMap::new(),
        pending_declines: BTreeMap::new(),
        grants: Grants::default(),
        udp_port: None,
        dirty: false,
        revoked: false,
    };
    storage::save(dir, FILE, &device)?;
    std::fs::remove_file(dir.join(PENDING))?;
    Ok(())
}

pub async fn run(
    dir: PathBuf,
    shell: Option<PathBuf>,
    bind: SocketAddr,
    log_file: Option<PathBuf>,
) -> Result<()> {
    let _lock = storage::lock(&dir)?;
    let mut device = load_device(&dir)?;
    let log_file = log_file.unwrap_or_else(|| dir.join("connections.jsonl"));
    let connection_log = ConnectionLog::open(Some(&log_file))?;
    let bind_device = |addr| {
        bind_endpoint(
            SecretKey::from_bytes(&device.identity.key),
            addr,
            Some(device.identity.server.relay.clone()),
            wire::SERVICE,
            true,
        )
    };
    let mut preferred = bind;
    if bind.port() == 0 {
        preferred.set_port(device.udp_port.unwrap_or(0));
    }
    let endpoint = match bind_device(preferred).await {
        Err(error) if preferred != bind => {
            eprintln!(
                "massrelay: could not reuse UDP port {}: {error}",
                preferred.port()
            );
            bind_device(bind).await?
        }
        result => result?,
    };
    device.udp_port = endpoint.bound_sockets().first().map(SocketAddr::port);
    storage::save(&dir, FILE, &device)?;
    let (listener, runtime) = local::listen(&dir).await?;
    let node = Arc::new(Node {
        state: Mutex::new(device),
        operations: Mutex::new(()),
        endpoint,
        dir,
        shell,
        connection_log,
        changed: watch::channel(()).0,
    });
    eprintln!("MassRelay running as {}", node.endpoint.id());
    eprintln!("MassRelay event log at {}", log_file.display());
    node.connection_log.state("device_started", None, None);
    let mut tasks = JoinSet::new();
    let sync_node = node.clone();
    tasks.spawn(async move {
        let mut timer = tokio::time::interval(SYNC_INTERVAL);
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            let _ = sync_node.refresh().await;
            if sync_node.state.lock().await.revoked {
                sync_node.endpoint.close().await;
                return;
            }
        }
    });
    let shutdown = crate::shutdown();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            signal = &mut shutdown => break signal.context("wait for shutdown"),
            Some(_) = tasks.join_next() => {},
            incoming = node.endpoint.accept() => {
                let Some(incoming) = incoming else { break Ok(()); };
                let node = node.clone();
                tasks.spawn(async move {
                    let Ok(Ok(connection)) = timeout(wire::RPC_TIMEOUT, incoming).await else { return };
                    node.serve_peer(connection).await;
                });
            }
            connection = listener.accept() => {
                let (socket, _) = match connection {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        eprintln!("massrelay: local command listener: {error}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let (node, runtime) = (node.clone(), runtime.clone());
                tasks.spawn(async move {
                    let _ = node.serve_local(socket, &runtime).await;
                });
            }
        }
    };
    node.endpoint.close().await;
    tasks.shutdown().await;
    node.connection_log.state("device_stopped", None, None);
    result
}

fn load_device(dir: &Path) -> Result<Device> {
    let device: Device =
        storage::load(dir, FILE).context("use create or join to enroll this device")?;
    ensure!(!device.revoked, "this device has been revoked");
    Ok(device)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn check_enrolled(dir: &Path) -> Result<()> {
    load_device(dir).map(drop)
}

async fn rpc(
    endpoint: &Endpoint,
    server: &ServerAddr,
    via_relay: bool,
    request: Request,
) -> Result<Reply> {
    match exchange(endpoint, server, via_relay, request).await? {
        Reply::Error(error) => bail!("{error}"),
        reply => Ok(reply),
    }
}

async fn exchange(
    endpoint: &Endpoint,
    server: &ServerAddr,
    via_relay: bool,
    request: Request,
) -> Result<Reply> {
    timeout(wire::RPC_TIMEOUT, async {
        let connection = endpoint
            .connect(server.dial(via_relay), wire::CONTROL)
            .await?;
        let (mut tx, mut rx) = connection.open_bi().await?;
        wire::send(&mut tx, request).await?;
        tx.finish()?;
        wire::recv(&mut rx).await
    })
    .await
    .context("membership service timed out")?
}

impl Node {
    async fn rpc(&self, request: Request) -> Result<Reply> {
        let server = self.state.lock().await.identity.server.clone();
        rpc(&self.endpoint, &server, true, request).await
    }

    async fn refresh(&self) -> Result<()> {
        let _permit = self.operations.lock().await;
        self.update_roster().await
    }

    async fn update_roster(&self) -> Result<()> {
        let reply = self
            .rpc(Request::Sync {
                addr: self.endpoint.addr(),
            })
            .await?;
        self.apply_reply(reply, None).await?;
        let pending = self.state.lock().await.pending_declines.clone();
        for (id, previous) in pending {
            let pair = self
                .state
                .lock()
                .await
                .roster
                .peers
                .iter()
                .find(|peer| peer.member.id == id)
                .map(|peer| peer.pair);
            if let Some(pair) = pair
                && (pair.generation <= previous || pair.ours != Some(Decision::Decline))
            {
                let reply = self
                    .rpc(Request::Pair {
                        peer: id,
                        generation: pair.generation,
                        decision: Decision::Decline,
                    })
                    .await?;
                self.apply_reply(reply, None).await?;
            }
            let mut state = self.state.lock().await;
            if state.pending_declines.get(&id) == Some(&previous) {
                state.pending_declines.remove(&id);
                self.save_restrictions(&mut state)?;
            }
        }
        Ok(())
    }

    fn save_restrictions(&self, state: &mut Device) -> Result<()> {
        let saved = storage::save(&self.dir, FILE, state);
        state.dirty = saved.is_err();
        if let Err(error) = &saved {
            eprintln!("massrelay: could not save updated device restrictions: {error:#}");
        }
        saved
    }

    async fn apply_reply(&self, reply: Reply, approval: Option<(EndpointId, u64)>) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut next = state.clone();
        match reply {
            Reply::Roster(roster) => {
                ensure!(
                    roster.network == state.roster.network,
                    "membership service returned another network"
                );
                next.roster = roster;
                next.approvals.retain(|id, generation| {
                    next.roster.peers.iter().any(|peer| {
                        peer.member.id == *id
                            && peer.pair.generation == *generation
                            && peer.pair.ours == Some(Decision::Approve)
                    })
                });
                if let Some((id, generation)) = approval
                    && !next.pending_declines.contains_key(&id)
                    && next.roster.peers.iter().any(|peer| {
                        peer.member.id == id
                            && peer.pair.generation == generation
                            && peer.pair.ours == Some(Decision::Approve)
                    })
                {
                    next.approvals.insert(id, generation);
                }
            }
            Reply::Revoked => {
                next.revoked = true;
                next.approvals.clear();
            }
            _ => bail!("unexpected membership reply"),
        }
        let removed = next.prune_grants();
        let changed = !same_membership(&state, &next)?;
        let saved = if changed || state.dirty {
            self.save_restrictions(&mut next)
        } else {
            Ok(())
        };
        if saved.is_err() {
            // Keep access closed if we cannot persist changes that removed authorization.
            next.approvals
                .retain(|id, generation| state.approvals.get(id) == Some(generation));
        }
        if changed || !removed.is_empty() {
            self.log_membership_changes(&state, &next);
            self.log_pruned_grants(&state, removed);
        }
        *state = next;
        if changed {
            self.changed.send_replace(());
        }
        saved?;
        ensure!(!state.revoked, "this device has been revoked");
        Ok(())
    }

    fn log_membership_changes(&self, before: &Device, after: &Device) {
        if after.revoked && !before.revoked {
            self.connection_log.state("device_revoked", None, None);
        }
        let mut previous: BTreeMap<_, _> = before
            .roster
            .peers
            .iter()
            .map(|peer| (peer.member.id, peer))
            .collect();
        for peer in &after.roster.peers {
            let id = peer.member.id;
            let member = Some(&peer.member);
            let old = previous.remove(&id);
            if old.is_none() {
                self.connection_log.state("peer_joined", member, None);
            }
            if let Some(decision) = peer.pair.theirs
                && old.and_then(|peer| peer.pair.theirs) != Some(decision)
            {
                let event = match decision {
                    Decision::Approve => "peer_approved",
                    Decision::Decline => "peer_declined",
                };
                self.connection_log.state(event, member, None);
            }
            if after.approvals.get(&id) != before.approvals.get(&id)
                && after.approvals.contains_key(&id)
            {
                self.connection_log.state("approval_granted", member, None);
            }
            match (
                old.is_some_and(|peer| before.peer_is_paired(peer)),
                after.peer_is_paired(peer),
            ) {
                (false, true) => self
                    .connection_log
                    .state("pairing_established", member, None),
                (true, false) => self.connection_log.state("pairing_ended", member, None),
                _ => {}
            }
        }
        for peer in previous.into_values() {
            let member = Some(&peer.member);
            if before.peer_is_paired(peer) {
                self.connection_log.state("pairing_ended", member, None);
            }
            self.connection_log.state("peer_removed", member, None);
        }
    }

    fn log_removed_grant(&self, member: &Member, service: Service, grant: RemovedGrant) {
        let event = match grant {
            RemovedGrant::Persistent => "service_disabled",
            RemovedGrant::Exposure => "exposure_ended",
        };
        self.connection_log
            .state(event, Some(member), Some(service));
    }

    fn log_pruned_grants(&self, state: &Device, removed: Vec<(EndpointId, Service, RemovedGrant)>) {
        for (id, service, grant) in removed {
            if let Some(peer) = state.roster.peers.iter().find(|peer| peer.member.id == id) {
                self.log_removed_grant(&peer.member, service, grant);
            }
        }
    }

    async fn lookup(&self, name: &str) -> Result<Peer> {
        let state = self.state.lock().await;
        ensure!(!state.revoked, "this device has been revoked");
        let id: Option<EndpointId> = name.parse().ok();
        let mut matches = state.roster.peers.iter().filter(|peer| match id {
            Some(id) => peer.member.id == id,
            None => peer.member.name.eq_ignore_ascii_case(name),
        });
        let peer = matches
            .next()
            .with_context(|| format!("unknown peer {name}"))?;
        ensure!(
            matches.next().is_none(),
            "several peers are named {name}; use an endpoint ID"
        );
        Ok(peer.clone())
    }

    async fn manage(&self, request: LocalRequest) -> Result<LocalReply> {
        if matches!(request, LocalRequest::Peers) {
            let state = self.state.lock().await;
            ensure!(!state.revoked, "this device has been revoked");
            let mut peers = state.roster.peers.clone();
            for peer in &mut peers {
                if state.pending_declines.contains_key(&peer.member.id) {
                    peer.pair.ours = Some(Decision::Decline);
                } else if peer.pair.ours == Some(Decision::Approve)
                    && state.approvals.get(&peer.member.id) != Some(&peer.pair.generation)
                {
                    peer.pair.ours = None;
                }
            }
            return Ok(LocalReply::Peers(peers));
        }
        if matches!(request, LocalRequest::Grants) {
            let state = self.state.lock().await;
            ensure!(!state.revoked, "this device has been revoked");
            return Ok(LocalReply::Grants(state.grants.list(|id| {
                state
                    .roster
                    .peers
                    .iter()
                    .find(|peer| peer.member.id == id)
                    .map(|peer| peer.member.name.clone())
            })));
        }
        // Grants are local decisions, which work and take effect without the relay.
        if let LocalRequest::Enable { service, peer } = &request {
            let member = self.lookup(peer).await?.member;
            let mut state = self.state.lock().await;
            let generation = state.grant_generation(&member)?;
            let mut next = state.clone();
            let added = next
                .grants
                .enable(member.id, &member.name, *service, generation)?;
            if added || next.dirty {
                // Access opens only after the grant is saved.
                self.save_restrictions(&mut next)?;
                *state = next;
            }
            if added {
                self.connection_log
                    .state("service_enabled", Some(&member), Some(*service));
            }
            return Ok(LocalReply::Done);
        }
        if let LocalRequest::Disable { service, peer } = &request {
            let member = self.lookup(peer).await?.member;
            let mut state = self.state.lock().await;
            // Access closes now, even if saving fails.
            let removed = state.grants.disable(member.id, *service);
            if let Some(grant) = removed {
                self.log_removed_grant(&member, *service, grant);
            }
            self.changed.send_replace(());
            if removed == Some(RemovedGrant::Persistent) || state.dirty {
                self.save_restrictions(&mut state)?;
            }
            return Ok(LocalReply::Done);
        }
        if let LocalRequest::Pair {
            peer,
            decision: Decision::Decline,
        } = &request
        {
            let peer = self.lookup(peer).await?;
            let id = peer.member.id;
            let mut state = self.state.lock().await;
            let was_paired = state.paired(id, &state.roster.network, peer.pair.generation);
            state.approvals.remove(&id);
            if !state.pending_declines.contains_key(&id)
                && peer.pair.ours != Some(Decision::Decline)
            {
                self.connection_log
                    .state("approval_declined", Some(&peer.member), None);
            }
            if was_paired {
                self.connection_log
                    .state("pairing_ended", Some(&peer.member), None);
            }
            state
                .pending_declines
                .entry(id)
                .or_insert(peer.pair.generation);
            let removed = state.prune_grants();
            self.log_pruned_grants(&state, removed);
            self.changed.send_replace(());
            self.save_restrictions(&mut state)?;
            return Ok(LocalReply::Done);
        }

        let _permit = self.operations.lock().await;
        match request {
            LocalRequest::Invite => match self.rpc(Request::Invite).await? {
                Reply::Invite(secret) => {
                    let server = self.state.lock().await.identity.server.clone();
                    Ok(LocalReply::Invite(Ticket { server, secret }.encode()?))
                }
                Reply::Revoked => {
                    self.apply_reply(Reply::Revoked, None).await?;
                    bail!("this device has been revoked");
                }
                _ => bail!("unexpected invite reply"),
            },
            LocalRequest::Pair { peer, decision } => {
                let Peer { member, .. } = self.lookup(&peer).await?;
                let id = member.id;
                self.update_roster().await?;
                let current = self.lookup(&id.to_string()).await?;
                let generation = current.pair.generation;
                let reply = self
                    .rpc(Request::Pair {
                        peer: id,
                        decision,
                        generation,
                    })
                    .await?;
                self.apply_reply(reply, Some((id, generation))).await?;
                ensure!(
                    self.state.lock().await.approvals.get(&id) == Some(&generation),
                    "pairing changed before approval completed"
                );
                Ok(LocalReply::Done)
            }
            LocalRequest::Revoke { peer } => {
                let id = self.lookup(&peer).await?.member.id;
                let reply = self.rpc(Request::Revoke { peer: id }).await?;
                self.apply_reply(reply, None).await?;
                Ok(LocalReply::Done)
            }
            LocalRequest::Peers
            | LocalRequest::Grants
            | LocalRequest::Enable { .. }
            | LocalRequest::Disable { .. }
            | LocalRequest::Shell { .. }
            | LocalRequest::Connect { .. }
            | LocalRequest::Expose { .. } => unreachable!(),
        }
    }

    async fn paired(&self, id: EndpointId, network: &str, generation: u64) -> bool {
        self.state.lock().await.paired(id, network, generation)
    }

    async fn until_unpaired(&self, id: EndpointId, request: &ServiceRequest) {
        let mut changed = self.changed.subscribe();
        while self.paired(id, &request.network, request.generation).await {
            if changed.changed().await.is_err() {
                break;
            }
        }
    }

    /// Serialize authorized side effects with grant changes without holding the lock across a wait.
    async fn start_if_allowed<T>(
        &self,
        id: EndpointId,
        request: &ServiceRequest,
        instance: u64,
        start: impl Future<Output = T>,
    ) -> Result<T, Refusal> {
        let lock = self.state.lock();
        tokio::pin!(lock, start);
        poll_fn(|cx| {
            let state = ready!(lock.as_mut().poll(cx));
            let result = match state.check_grant(id, request, instance) {
                Ok(()) => start.as_mut().poll(cx).map(Ok),
                Err(refusal) => Poll::Ready(Err(refusal)),
            };
            drop(state);
            if result.is_pending() {
                lock.set(self.state.lock());
            }
            result
        })
        .await
    }

    async fn until_denied(
        &self,
        id: EndpointId,
        request: &ServiceRequest,
        instance: u64,
    ) -> Refusal {
        // Subscribing before the first check means no change can be missed.
        let mut changed = self.changed.subscribe();
        loop {
            if let Err(refusal) = self.state.lock().await.check_grant(id, request, instance) {
                return refusal;
            }
            if changed.changed().await.is_err() {
                return Refusal::PairingRequired;
            }
        }
    }

    async fn until_withdrawn(&self, id: EndpointId, service: Service, instance: u64) {
        let mut changed = self.changed.subscribe();
        while self
            .state
            .lock()
            .await
            .grants
            .is_exposed(id, service, instance)
        {
            if changed.changed().await.is_err() {
                break;
            }
        }
    }

    async fn serve_local(&self, mut socket: TcpStream, runtime: &local::Runtime) -> Result<()> {
        let request =
            timeout(wire::RPC_TIMEOUT, local::authenticate(&mut socket, runtime)).await??;
        socket.set_nodelay(true)?;
        let response = match request {
            LocalRequest::Shell { peer, cols, rows } => {
                let size = Some((cols, rows));
                return self
                    .open_service(socket, peer, Service::Shell, size, None)
                    .await;
            }
            LocalRequest::Connect {
                peer,
                service,
                lifetime_port,
                lifetime_key,
            } if service != Service::Shell => {
                let mut lifetime = TcpStream::connect((Ipv4Addr::LOCALHOST, lifetime_port)).await?;
                lifetime.write_all(&lifetime_key).await?;
                return self
                    .open_service(socket, peer, service, None, Some(lifetime))
                    .await;
            }
            LocalRequest::Connect { .. } => Err(anyhow::anyhow!("connect forwards a port")),
            LocalRequest::Expose {
                service,
                peer,
                target,
            } => return self.expose(socket, service, peer, target).await,
            request => self.manage(request).await,
        };
        let response = response.unwrap_or_else(|error| LocalReply::Error(format!("{error:#}")));
        wire::send(&mut socket, response).await
    }

    async fn add_exposure(
        &self,
        service: Service,
        peer: &str,
        target: Option<String>,
    ) -> Result<(Member, u64)> {
        ensure!(service != Service::Shell, "only a port can be exposed");
        if let Some(target) = &target {
            wire::check_target(target)?;
        }
        let member = self.lookup(peer).await?.member;
        let mut state = self.state.lock().await;
        let generation = state.grant_generation(&member)?;
        let instance = state
            .grants
            .expose(member.id, &member.name, service, generation, target)?;
        self.connection_log
            .state("exposure_started", Some(&member), Some(service));
        Ok((member, instance))
    }

    /// Hold a temporary grant for as long as the local command stays connected.
    async fn expose(
        &self,
        mut socket: TcpStream,
        service: Service,
        peer: String,
        target: Option<String>,
    ) -> Result<()> {
        let (member, instance) = match self.add_exposure(service, &peer, target).await {
            Ok(added) => added,
            Err(error) => {
                return wire::send(&mut socket, LocalReply::Error(format!("{error:#}"))).await;
            }
        };
        let (mut rx, mut tx) = socket.split();
        let stopped = async {
            let reply = LocalReply::Exposed {
                peer: member.name.clone(),
                id: member.id,
            };
            wire::send(&mut tx, reply).await?;
            let mut stop = [0];
            Ok::<_, anyhow::Error>(tokio::select! {
                biased;
                _ = self.until_withdrawn(member.id, service, instance) => false,
                // The command closes its side to stop. A lost command ends the read too.
                _ = rx.read(&mut stop) => true,
            })
        }
        .await;
        // Every way out of the wait removes this grant and closes its sessions.
        {
            let mut state = self.state.lock().await;
            if state.grants.withdraw(member.id, service, instance) {
                self.log_removed_grant(&member, service, RemovedGrant::Exposure);
            }
        }
        self.changed.send_replace(());
        let reply = if stopped? {
            LocalReply::Done
        } else {
            LocalReply::Error(format!(
                "the {service} exposure to {} ended because it was disabled or the pairing changed",
                member.name
            ))
        };
        wire::send(&mut tx, reply).await
    }

    /// Open a service on a peer and connect it to the local command.
    async fn open_service(
        &self,
        mut socket: TcpStream,
        name: String,
        service: Service,
        terminal: Option<(u16, u16)>,
        mut lifetime: Option<TcpStream>,
    ) -> Result<()> {
        let mut session =
            self.connection_log
                .session(Direction::Outbound, None, Some(name.clone()));
        session.set_service(service);
        let mut failure = "setup_failed";
        let local_closed = async {
            match lifetime.as_mut() {
                Some(socket) => {
                    let _ = socket.read_u8().await;
                }
                None => std::future::pending().await,
            }
        };
        tokio::pin!(local_closed);
        let setup = timeout(wire::RPC_TIMEOUT * 2, async {
            let peer = self.lookup(&name).await?;
            let (network, relay) = {
                let state = self.state.lock().await;
                (
                    state.roster.network.clone(),
                    state.identity.server.relay.clone(),
                )
            };
            let generation = peer.pair.generation;
            let id = peer.member.id;
            session.set_peer(id, peer.member.name);
            if !self.paired(id, &network, generation).await {
                failure = Refusal::PairingRequired.reason();
                bail!(wire::PAIRING_REQUIRED);
            }
            let addr = peer.member.addr.unwrap_or_else(|| EndpointAddr::new(id));
            ensure!(addr.id == id, "membership address identity mismatch");
            let connection = self
                .endpoint
                .connect(addr.with_relay_url(relay), wire::SERVICE)
                .await
                .map_err(|error| {
                    // The error already describes its causes.
                    anyhow::anyhow!(
                        "could not reach the peer; \
                         check that it is running an up-to-date MassRelay: {error}"
                    )
                })?;
            let request = ServiceRequest {
                network,
                generation,
                service,
                terminal,
            };
            let opened = async {
                let (mut tx, mut rx) = connection.open_bi().await?;
                wire::send(&mut tx, &request).await?;
                let reply: ServiceReply = wire::recv(&mut rx).await?;
                Ok::<_, anyhow::Error>((tx, rx, reply))
            }
            .await;
            match opened {
                Ok((tx, rx, ServiceReply::Ready)) => Ok((connection, tx, rx, request)),
                Ok((_, _, ServiceReply::Refused { refusal, message })) => {
                    failure = refusal.reason();
                    bail!("{message}")
                }
                Err(error) => match closed_by_peer(&connection, service) {
                    Some((reason, message)) => {
                        failure = reason;
                        bail!("{message}")
                    }
                    None => Err(error),
                },
            }
        });
        let setup = tokio::select! {
            biased;
            _ = &mut local_closed => {
                session.end("local_client_closed", None);
                return Ok(());
            }
            result = setup => result.context("service connection timed out").and_then(|result| result),
        };

        let (connection, mut tx, mut rx, request) = match setup {
            Ok(result) => result,
            Err(error) => {
                session.end(failure, None);
                return wire::send(&mut socket, LocalReply::Error(format!("{error:#}"))).await;
            }
        };
        let id = connection.remote_id();
        session.connected();
        let ready = match service {
            Service::Shell => LocalReply::Shell,
            _ => LocalReply::Connected,
        };
        if let Err(error) = wire::send(&mut socket, ready).await {
            session.end("local_client_closed", None);
            return Err(error);
        }
        let (mut local_rx, mut local_tx) = socket.into_split();
        if service == Service::Shell {
            tokio::select! {
                _ = self.until_unpaired(id, &request) => {
                    connection.close(0u32.into(), wire::CLOSE_PAIRING_ENDED);
                    session.end("pairing_ended", None);
                }
                result = async {
                    tokio::try_join!(
                        async {
                            io::copy(&mut local_rx, &mut tx).await?;
                            tx.shutdown().await
                        },
                        async {
                            io::copy(&mut rx, &mut local_tx).await?;
                            local_tx.shutdown().await
                        },
                    )
                } => {
                    let reason = match (&result, closed_by_peer(&connection, service)) {
                        (Ok(_), _) => "stream_closed",
                        (Err(_), Some((reason, _))) => reason,
                        (Err(_), None) => "shell_io_error",
                    };
                    session.end(reason, None);
                    result?;
                }
            }
            return Ok(());
        }

        let mut writing = false;
        // A message is what to tell the local command when the destination cannot.
        // Polling order varies, so that a busy download cannot hold back the upload.
        let (reason, message) = tokio::select! {
            _ = self.until_unpaired(id, &request) => {
                connection.close(0u32.into(), wire::CLOSE_PAIRING_ENDED);
                ("pairing_ended", Some("this pairing ended".to_owned()))
            }
            delivered = tunnel::deliver(&mut rx, &mut local_tx, &mut writing) => match delivered {
                Ok(true) => ("stream_closed", None),
                Ok(false) => ("service_failed", None),
                Err(tunnel::Cut::Local) => ("local_client_closed", None),
                Err(tunnel::Cut::Peer) => match closed_by_peer(&connection, service) {
                    Some((reason, message)) => (reason, Some(message)),
                    None => (
                        "peer_disconnected",
                        Some("the connection to the destination was lost".to_owned()),
                    ),
                },
            },
            _ = &mut local_closed => ("local_client_closed", None),
            _ = tunnel::pump(&mut local_rx, &mut tx) => ("local_client_closed", None),
        };
        connection.close(0u32.into(), b"done");
        session.end(reason, None);
        if reason == "local_client_closed" {
            return Ok(());
        }
        if let Some(message) = message {
            // After part of a frame, only closing the socket can report the failure.
            if writing {
                return Ok(());
            }
            tunnel::fail(&mut local_tx, &message).await?;
        }
        // Closing with unread input could discard the final frame before the command reads it.
        io::copy(&mut local_rx, &mut io::sink()).await?;
        Ok(())
    }

    async fn serve_peer(&self, connection: Connection) {
        let id = connection.remote_id();
        let (profile_approved, name) = {
            let state = self.state.lock().await;
            let name = state
                .roster
                .peers
                .iter()
                .find(|peer| peer.member.id == id)
                .map(|peer| peer.member.name.clone());
            (state.approvals.contains_key(&id), name)
        };
        let mut session = self
            .connection_log
            .session(Direction::Inbound, Some(id), name.clone());
        if !profile_approved {
            session.end("pairing_required", None);
            connection.close(0u32.into(), wire::CLOSE_PAIRING_REQUIRED);
            return;
        }
        let setup = async {
            let (tx, mut rx) = timeout(wire::RPC_TIMEOUT, connection.accept_bi()).await??;
            let request: ServiceRequest = timeout(wire::RPC_TIMEOUT, wire::recv(&mut rx)).await??;
            Ok::<_, anyhow::Error>((tx, rx, request))
        };
        let Ok((mut tx, mut rx, request)) = setup.await else {
            session.end("service_request_failed", None);
            return;
        };
        session.set_service(request.service);
        let access = self.state.lock().await.access(id, &request);
        let access = match access {
            Ok(access) => access,
            Err(refusal) => {
                session.end(refusal.reason(), None);
                let message = match refusal {
                    Refusal::ServiceNotEnabled => {
                        not_enabled(request.service, &name.unwrap_or_default())
                    }
                    _ => wire::PAIRING_REQUIRED.into(),
                };
                refuse(&connection, &mut tx, refusal, message).await;
                return;
            }
        };
        let (reason, exit_code) = tokio::select! {
            // Check authorization first, so nothing more is forwarded once it has been removed.
            biased;
            refusal = self.until_denied(id, &request, access.instance) => {
                (close_denied(&connection, refusal), None)
            }
            outcome = async {
                if request.service == Service::Shell {
                    let (cols, rows) = request.terminal.unwrap_or((80, 24));
                    let opened = self.start_if_allowed(id, &request, access.instance, async {
                        terminal::start(cols, rows, self.shell.as_deref())
                    }).await;
                    return match opened {
                        Ok(Ok(terminal)) => self.serve_shell(terminal, &mut rx, &mut tx, &mut session).await,
                        Ok(Err(_)) => ("shell_io_error", None),
                        Err(refusal) => (close_denied(&connection, refusal), None),
                    };
                }
                tokio::select! {
                    biased;
                    reason = self.serve_port(
                        &request, &access, &connection, &mut rx, &mut tx, &mut session,
                    ) => (reason, None),
                    _ = connection.closed() => ("peer_disconnected", None),
                }
            } => outcome,
        };
        session.end(reason, exit_code);
    }

    /// Returns the reason the session ended, and the shell's exit code if it exited.
    async fn serve_shell(
        &self,
        terminal: terminal::Terminal,
        rx: &mut RecvStream,
        tx: &mut SendStream,
        session: &mut Session<'_>,
    ) -> (&'static str, Option<i32>) {
        match terminal.serve(rx, tx, || session.connected()).await {
            Ok(code) => {
                if tx.finish().is_ok() {
                    let _ = timeout(wire::RPC_TIMEOUT, tx.stopped()).await;
                }
                ("shell_exit", Some(code))
            }
            Err(_) => ("shell_io_error", None),
        }
    }

    /// Forward a TCP or UDP service, and return the reason the session ended.
    async fn serve_port(
        &self,
        request: &ServiceRequest,
        access: &Access,
        connection: &Connection,
        rx: &mut RecvStream,
        tx: &mut SendStream,
        session: &mut Session<'_>,
    ) -> &'static str {
        enum Target {
            Tcp(TcpStream),
            Udp(SocketAddr),
        }
        let (service, target) = (request.service, access.target.as_deref());
        let id = connection.remote_id();
        let opened = self
            .start_if_allowed(id, request, access.instance, async {
                match service {
                    Service::Tcp(port) => tcp::dial(port, target).await.map(Target::Tcp),
                    Service::Udp(port) => udp::resolve(port, target).await.map(Target::Udp),
                    Service::Shell => unreachable!("shells do not forward ports"),
                }
            })
            .await;
        let opened = match opened {
            Ok(Ok(opened)) => opened,
            Err(refusal) => return close_denied(connection, refusal),
            Ok(Err(error)) => {
                // The owner's chosen address is not disclosed to the peer.
                let place = match target {
                    Some(_) => format!("the {service} target"),
                    None => match service {
                        Service::Tcp(port) | Service::Udp(port) => format!("loopback port {port}"),
                        Service::Shell => unreachable!("shells do not forward ports"),
                    },
                };
                let message = format!("could not connect to {place} on the destination: {error}");
                refuse(connection, tx, Refusal::TargetUnavailable, message).await;
                return Refusal::TargetUnavailable.reason();
            }
        };
        // Authorization may have been removed while the target was opening.
        if let Err(refusal) = self
            .state
            .lock()
            .await
            .check_grant(id, request, access.instance)
        {
            return close_denied(connection, refusal);
        }
        if wire::send(tx, ServiceReply::Ready).await.is_err() {
            return "peer_disconnected";
        }
        session.connected();
        let result = match opened {
            Target::Tcp(mut stream) => tcp::bridge(rx, tx, &mut stream).await,
            Target::Udp(addr) => {
                udp::bridge(rx, tx, |first| async move {
                    self.start_if_allowed(
                        id,
                        request,
                        access.instance,
                        udp::associate(addr, &first),
                    )
                    .await
                    .map_err(tunnel::Broken::Denied)?
                    .map_err(tunnel::Broken::Target)
                })
                .await
            }
        };
        let (reason, sent) = match result {
            Ok(()) => ("stream_closed", tunnel::done(tx).await),
            Err(tunnel::Broken::Target(error)) => {
                let message = format!("forwarding {service} failed on the destination: {error}");
                ("target_io_error", tunnel::fail(tx, &message).await)
            }
            Err(tunnel::Broken::Peer) => return "peer_disconnected",
            Err(tunnel::Broken::Denied(refusal)) => return close_denied(connection, refusal),
        };
        if sent.is_ok() && tx.finish().is_ok() {
            // The peer closes the connection once it has received everything.
            connection.closed().await;
        }
        reason
    }
}

/// Tell a paired peer how this device's owner can grant the service it asked for.
fn not_enabled(service: Service, peer: &str) -> String {
    let remedy = match service {
        Service::Udp(port) => format!("massrelay expose --udp {port} --to {peer}"),
        _ => format!("massrelay enable {service} {peer}"),
    };
    format!("{service} is not enabled for this device; on the destination, run {remedy}")
}

async fn refuse(connection: &Connection, tx: &mut SendStream, refusal: Refusal, message: String) {
    let reply = ServiceReply::Refused { refusal, message };
    if wire::send(tx, reply).await.is_ok() && tx.finish().is_ok() {
        // Closing first could discard the reply, so wait for the peer to close.
        let _ = timeout(wire::RPC_TIMEOUT, connection.closed()).await;
    }
}

/// Close an active session whose authorization was removed, and return the reason to log.
fn close_denied(connection: &Connection, refusal: Refusal) -> &'static str {
    let (close, reason) = match refusal {
        Refusal::PairingRequired => (wire::CLOSE_PAIRING_ENDED, "pairing_ended"),
        _ => (wire::CLOSE_GRANT_REMOVED, "grant_removed"),
    };
    connection.close(0u32.into(), close);
    reason
}

/// The destination's reason for closing a connection, as a log reason and an explanation.
fn closed_by_peer(connection: &Connection, service: Service) -> Option<(&'static str, String)> {
    let Some(ConnectionError::ApplicationClosed(close)) = connection.close_reason() else {
        return None;
    };
    match close.reason.as_ref() {
        wire::CLOSE_PAIRING_REQUIRED => Some((
            Refusal::PairingRequired.reason(),
            wire::PAIRING_REQUIRED.into(),
        )),
        wire::CLOSE_PAIRING_ENDED => {
            Some(("pairing_ended", "the destination ended this pairing".into()))
        }
        wire::CLOSE_GRANT_REMOVED => Some((
            "grant_removed",
            format!("access to {service} was removed on the destination"),
        )),
        _ => None,
    }
}

fn same_membership(a: &Device, b: &Device) -> Result<bool> {
    // Presence is a heartbeat and does not need to rewrite the device state file on each poll.
    let canonical = |device: &Device| {
        let mut device = device.clone();
        device
            .roster
            .peers
            .iter_mut()
            .for_each(|p| p.member.last_seen = None);
        serde_json::to_vec(&device)
    };
    Ok(canonical(a)? == canonical(b)?)
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn hostnames_become_acceptable_device_names_or_fall_back() {
        for (host, name) in [
            ("laptop\n", "laptop"),
            ("Build Box.example.test", "Build-Box"),
            ("zoë's_pc", "zo--s_pc"),
        ] {
            assert_eq!(host_label(host).as_deref(), Some(name));
        }
        let endpoint_id = SecretKey::from_bytes(&[1; 32]).public().to_string();
        for unusable in ["", "...", "日本", "LocalHost.localdomain", &endpoint_id] {
            assert_eq!(host_label(unusable), None);
        }
    }
}

#[cfg(test)]
mod grant_tests {
    use super::*;
    use crate::wire::PairView;

    fn paired_peer(seed: u8, name: &str, generation: u64) -> Peer {
        Peer {
            member: Member {
                id: SecretKey::from_bytes(&[seed; 32]).public(),
                name: name.into(),
                addr: None,
                last_seen: None,
            },
            pair: PairView {
                generation,
                ours: Some(Decision::Approve),
                theirs: Some(Decision::Approve),
            },
        }
    }

    /// A destination on loopback, paired with each peer, whose profile predates service grants.
    async fn destination(dir: &Path, peers: &[Peer]) -> Result<Node> {
        let key = SecretKey::from_bytes(&[9; 32]);
        let approvals: BTreeMap<_, _> = peers
            .iter()
            .map(|peer| (peer.member.id, peer.pair.generation))
            .collect();
        let profile = serde_json::json!({
            "identity": {
                "key": key.to_bytes(),
                "server": {
                    "id": key.public(),
                    "udp": "127.0.0.1:1",
                    "relay": "http://127.0.0.1:1",
                },
            },
            "roster": Roster { network: "test".into(), peers: peers.to_vec() },
            "approvals": approvals,
            "revoked": false,
        });
        storage::save(dir, FILE, &profile)?;
        let bind = "127.0.0.1:0".parse()?;
        Ok(Node {
            state: Mutex::new(storage::load(dir, FILE)?),
            operations: Mutex::new(()),
            endpoint: bind_endpoint(key, bind, None, wire::SERVICE, false).await?,
            dir: dir.into(),
            shell: None,
            connection_log: ConnectionLog::open(None)?,
            changed: watch::channel(()).0,
        })
    }

    impl Node {
        async fn allowed(&self, peer: &Peer, service: &str) -> Result<u64, Refusal> {
            let request = ServiceRequest {
                network: "test".into(),
                generation: peer.pair.generation,
                service: service.parse().expect("test service"),
                terminal: None,
            };
            let state = self.state.lock().await;
            state
                .access(peer.member.id, &request)
                .map(|access| access.instance)
        }

        async fn change(&self, enable: bool, service: &str, peer: &str) -> Result<()> {
            let (service, peer) = (service.parse().expect("test service"), peer.into());
            self.manage(if enable {
                LocalRequest::Enable { service, peer }
            } else {
                LocalRequest::Disable { service, peer }
            })
            .await
            .map(drop)
        }

        async fn roster(&self, peers: &[Peer]) -> Result<()> {
            let roster = Roster {
                network: "test".into(),
                peers: peers.to_vec(),
            };
            self.apply_reply(Reply::Roster(roster), None).await
        }
    }

    #[tokio::test]
    async fn grants_belong_to_one_peer_service_and_pairing() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (first, second) = (paired_peer(1, "first", 0), paired_peer(2, "second", 0));
        let node = destination(dir.path(), &[first.clone(), second.clone()]).await?;
        let denied = Err(Refusal::ServiceNotEnabled);

        assert_eq!(node.allowed(&first, "shell").await, denied);
        node.change(true, "tcp:80", "FIRST").await?;
        let instance = node.allowed(&first, "tcp:80").await.expect("granted");
        node.change(true, "tcp:80", &first.member.id.to_string())
            .await?;
        assert_eq!(node.allowed(&first, "tcp:80").await, Ok(instance));
        for service in ["shell", "tcp:81", "udp:80"] {
            assert_eq!(node.allowed(&first, service).await, denied);
        }
        assert_eq!(node.allowed(&second, "tcp:80").await, denied);

        // Temporary grants are not saved, and never replace a persistent one.
        assert!(
            node.add_exposure("tcp:80".parse().unwrap(), "first", None)
                .await
                .is_err()
        );
        let udp = "udp:53".parse().unwrap();
        node.add_exposure(udp, "second", Some("localhost:5353".into()))
            .await?;
        assert!(node.change(true, "udp:53", "second").await.is_err());
        assert!(node.allowed(&second, "udp:53").await.is_ok());
        let saved: Device = storage::load(dir.path(), FILE)?;
        let saved = saved.grants.list(|_| None);
        assert!(saved.len() == 1 && !saved[0].temporary);

        // Removing and restoring a grant never revives the instance that sessions hold.
        node.change(false, "tcp:80", "first").await?;
        node.change(false, "tcp:80", "first").await?;
        assert_eq!(node.allowed(&first, "tcp:80").await, denied);
        node.change(true, "tcp:80", "first").await?;
        assert_ne!(node.allowed(&first, "tcp:80").await, Ok(instance));

        // A new pairing generation ends both kinds of grant.
        let repaired = paired_peer(2, "second", 1);
        let first_again = paired_peer(1, "first", 1);
        node.roster(&[first_again.clone(), repaired.clone()])
            .await?;
        // A grant made before both approvals waits for them.
        node.change(true, "tcp:90", "second").await?;
        assert_eq!(
            node.allowed(&repaired, "tcp:90").await,
            Err(Refusal::PairingRequired)
        );
        node.state.lock().await.approvals = [(first.member.id, 1), (second.member.id, 1)].into();
        assert!(node.allowed(&repaired, "tcp:90").await.is_ok());
        assert_eq!(node.allowed(&first_again, "tcp:80").await, denied);
        assert_eq!(node.allowed(&repaired, "udp:53").await, denied);

        // A grant stays with the device, not its name.
        node.change(true, "shell", "first").await?;
        let namesake = paired_peer(3, "first", 1);
        node.roster(std::slice::from_ref(&namesake)).await?;
        node.state
            .lock()
            .await
            .approvals
            .insert(namesake.member.id, 1);
        assert_eq!(node.allowed(&namesake, "shell").await, denied);
        let saved: Device = storage::load(dir.path(), FILE)?;
        assert!(saved.grants.list(|_| None).is_empty());
        node.endpoint.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn startup_waits_for_grant_changes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let peer = paired_peer(1, "peer", 0);
        let node = destination(dir.path(), std::slice::from_ref(&peer)).await?;
        node.change(true, "tcp:80", "peer").await?;
        let instance = node.allowed(&peer, "tcp:80").await.expect("granted");
        let request = ServiceRequest {
            network: "test".into(),
            generation: peer.pair.generation,
            service: "tcp:80".parse().unwrap(),
            terminal: None,
        };
        let id = peer.member.id;

        let mut state = node.state.lock().await;
        let startup = node.start_if_allowed(id, &request, instance, async {
            panic!("a removed grant must never start a service");
        });
        tokio::pin!(startup);
        assert!(poll_fn(|cx| Poll::Ready(startup.as_mut().poll(cx).is_pending())).await);
        assert_eq!(
            state.grants.disable(id, request.service),
            Some(RemovedGrant::Persistent)
        );
        drop(state);
        assert_eq!(startup.await, Err(Refusal::ServiceNotEnabled));
        node.endpoint.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn unsaved_changes_never_widen_access() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let peer = paired_peer(1, "peer", 0);
        let node = destination(dir.path(), std::slice::from_ref(&peer)).await?;
        node.change(true, "shell", "peer").await?;

        // A directory in place of the state file makes every save fail.
        let file = dir.path().join(FILE);
        std::fs::remove_file(&file)?;
        std::fs::create_dir_all(file.join("occupied"))?;
        assert!(node.change(true, "tcp:80", "peer").await.is_err());
        assert_eq!(
            node.allowed(&peer, "tcp:80").await,
            Err(Refusal::ServiceNotEnabled)
        );
        assert!(node.change(false, "shell", "peer").await.is_err());
        assert_eq!(
            node.allowed(&peer, "shell").await,
            Err(Refusal::ServiceNotEnabled)
        );

        // Retrying saves the removal once storage recovers.
        std::fs::remove_dir_all(&file)?;
        node.change(false, "shell", "peer").await?;
        let saved: Device = storage::load(dir.path(), FILE)?;
        assert!(saved.grants.list(|_| None).is_empty());
        node.endpoint.close().await;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "opens loopback sockets and a native PTY"]
    async fn shell_works_with_only_a_tcp_relay_path() -> Result<()> {
        use crate::wire::{Member, PairView};
        use iroh::endpoint::{RelayMode, presets};
        use iroh_relay::server::{RelayConfig, Server, ServerConfig};

        let mut config = ServerConfig::default();
        config.relay = Some(RelayConfig::new("127.0.0.1:0".parse::<SocketAddr>()?));
        let relay = Server::spawn(config).await?;
        let addr = relay.http_addr().context("relay address missing")?;
        let url: iroh::RelayUrl = format!("http://{addr}").parse()?;
        let endpoint = || {
            Endpoint::builder(presets::Minimal)
                .clear_ip_transports()
                .relay_mode(RelayMode::custom([url.clone()]))
                .alpns(vec![wire::SERVICE.to_vec()])
                .bind()
        };
        let (source, destination) = tokio::try_join!(endpoint(), endpoint())?;
        assert!(source.bound_sockets().is_empty());
        assert!(destination.bound_sockets().is_empty());

        let device = Device {
            identity: Identity {
                key: destination.secret_key().to_bytes(),
                server: ServerAddr {
                    id: destination.id(),
                    udp: "127.0.0.1:1".parse()?,
                    relay: url.clone(),
                },
            },
            roster: Roster {
                network: "test".into(),
                peers: vec![Peer {
                    member: Member {
                        id: source.id(),
                        name: "source".into(),
                        addr: None,
                        last_seen: None,
                    },
                    pair: PairView {
                        generation: 0,
                        ours: Some(Decision::Approve),
                        theirs: Some(Decision::Approve),
                    },
                }],
            },
            approvals: BTreeMap::from([(source.id(), 0)]),
            pending_declines: BTreeMap::new(),
            grants: Grants::default(),
            udp_port: None,
            dirty: false,
            revoked: false,
        };
        let scratch = tempfile::tempdir()?;
        let node = Node {
            state: Mutex::new(device),
            operations: Mutex::new(()),
            endpoint: destination,
            dir: scratch.path().into(),
            shell: Some("/bin/sh".into()),
            connection_log: ConnectionLog::open(None)?,
            changed: watch::channel(()).0,
        };
        node.manage(LocalRequest::Enable {
            service: Service::Shell,
            peer: "source".into(),
        })
        .await?;
        timeout(Duration::from_secs(20), async {
            node.endpoint.online().await;
            let server = async {
                let incoming = node.endpoint.accept().await.context("endpoint closed")?;
                node.serve_peer(incoming.await?).await;
                Ok(())
            };
            let client = async {
                let addr = EndpointAddr::new(node.endpoint.id()).with_relay_url(url);
                let connection = source.connect(addr, wire::SERVICE).await?;
                let (mut tx, mut rx) = connection.open_bi().await?;
                wire::send(
                    &mut tx,
                    ServiceRequest {
                        network: "test".into(),
                        generation: 0,
                        service: Service::Shell,
                        terminal: Some((80, 24)),
                    },
                )
                .await?;
                assert!(matches!(wire::recv(&mut rx).await?, ServiceReply::Ready));
                wire::frame(&mut tx, b"\x01printf '%s%s\\n' relay_ only; exit 17\r").await?;
                let mut output = Vec::new();
                loop {
                    let frame = wire::read_frame(&mut rx).await?;
                    match frame.split_first() {
                        Some((&1, data)) => output.extend_from_slice(data),
                        Some((&3, status)) => {
                            assert_eq!(status, 17_i32.to_be_bytes());
                            assert!(
                                output
                                    .windows(b"relay_only".len())
                                    .any(|w| w == b"relay_only")
                            );
                            break Ok::<_, anyhow::Error>(());
                        }
                        _ => bail!("unexpected terminal frame"),
                    }
                }
            };
            tokio::try_join!(server, client)
        })
        .await??;
        source.close().await;
        node.endpoint.close().await;
        relay.shutdown().await?;
        Ok(())
    }
}
