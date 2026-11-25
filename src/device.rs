use std::{
    collections::BTreeMap,
    fs::File,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, endpoint::Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, watch},
    task::JoinSet,
    time::{MissedTickBehavior, timeout},
};

use crate::{
    bind_endpoint,
    connection_log::{ConnectionLog, Direction},
    local, storage, terminal,
    wire::{
        self, Decision, LocalReply, LocalRequest, Peer, Reply, Request, Roster, ServerAddr,
        ShellRequest, Ticket,
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
    udp_port: Option<u16>,
    #[serde(skip)]
    dirty: bool,
    revoked: bool,
}

struct Node {
    state: Mutex<Device>,
    operations: Mutex<()>,
    endpoint: Endpoint,
    dir: PathBuf,
    allow_shell: bool,
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
        wire::SHELL,
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
    allow_shell: bool,
    shell: Option<PathBuf>,
    bind: SocketAddr,
    log_file: Option<PathBuf>,
) -> Result<()> {
    let _lock = storage::lock(&dir)?;
    let mut device: Device =
        storage::load(&dir, FILE).context("use create or join to enroll this device")?;
    ensure!(!device.revoked, "this device has been revoked");
    let connection_log = ConnectionLog::open(log_file.as_deref())?;
    let bind_device = |addr| {
        bind_endpoint(
            SecretKey::from_bytes(&device.identity.key),
            addr,
            Some(device.identity.server.relay.clone()),
            wire::SHELL,
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
        allow_shell,
        shell,
        connection_log,
        changed: watch::channel(()).0,
    });
    eprintln!("MassRelay running as {}", node.endpoint.id());
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
                    let _ = node.serve_shell(connection).await;
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
    result
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
        *state = next;
        if changed {
            self.changed.send_replace(());
        }
        saved?;
        ensure!(!state.revoked, "this device has been revoked");
        Ok(())
    }

    async fn lookup(&self, name: &str) -> Result<Peer> {
        let state = self.state.lock().await;
        ensure!(!state.revoked, "this device has been revoked");
        let id: Option<EndpointId> = name.parse().ok();
        state
            .roster
            .peers
            .iter()
            .find(|peer| match id {
                Some(id) => peer.member.id == id,
                None => peer.member.name.eq_ignore_ascii_case(name),
            })
            .cloned()
            .with_context(|| format!("unknown peer {name}"))
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
        if let LocalRequest::Pair {
            peer,
            decision: Decision::Decline,
        } = &request
        {
            let peer = self.lookup(peer).await?;
            let id = peer.member.id;
            let mut state = self.state.lock().await;
            state.approvals.remove(&id);
            state
                .pending_declines
                .entry(id)
                .or_insert(peer.pair.generation);
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
            LocalRequest::Peers | LocalRequest::Shell { .. } => unreachable!(),
        }
    }

    async fn authorized(&self, id: EndpointId, network: &str, generation: u64) -> bool {
        let state = self.state.lock().await;
        !state.revoked
            && state.roster.network == network
            && state.approvals.get(&id) == Some(&generation)
            && state.roster.peers.iter().any(|peer| {
                peer.member.id == id
                    && peer.pair.generation == generation
                    && peer.pair.ours == Some(Decision::Approve)
                    && peer.pair.theirs == Some(Decision::Approve)
            })
    }

    async fn until_unpaired(&self, id: EndpointId, request: &ShellRequest) {
        let mut changed = self.changed.subscribe();
        while self
            .authorized(id, &request.network, request.generation)
            .await
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
        if let LocalRequest::Shell { peer, cols, rows } = request {
            return self.open_shell(socket, peer, cols, rows).await;
        }
        let response = self
            .manage(request)
            .await
            .unwrap_or_else(|error| LocalReply::Error(format!("{error:#}")));
        wire::send(&mut socket, response).await
    }

    async fn open_shell(
        &self,
        mut socket: TcpStream,
        name: String,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        let mut session =
            self.connection_log
                .session(Direction::Outbound, None, Some(name.clone()));
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
            ensure!(
                self.authorized(id, &network, generation).await,
                "both devices must approve this pairing"
            );
            let addr = peer.member.addr.unwrap_or_else(|| EndpointAddr::new(id));
            ensure!(addr.id == id, "membership address identity mismatch");
            let connection = self
                .endpoint
                .connect(addr.with_relay_url(relay), wire::SHELL)
                .await?;
            let (mut tx, mut rx) = connection.open_bi().await?;
            let request = ShellRequest {
                network,
                generation,
                cols,
                rows,
            };
            wire::send(&mut tx, &request).await?;
            let response: LocalReply = wire::recv(&mut rx).await?;
            match response {
                LocalReply::Shell => Ok((connection, tx, rx, request)),
                LocalReply::Error(error) => bail!("{error}"),
                _ => bail!("unexpected shell reply"),
            }
        })
        .await
        .context("shell connection timed out")
        .and_then(|result| result);

        let (connection, mut tx, mut rx, request) = match setup {
            Ok(result) => result,
            Err(error) => {
                session.end("shell_setup_failed", None);
                return wire::send(&mut socket, LocalReply::Error(format!("{error:#}"))).await;
            }
        };
        let id = connection.remote_id();
        session.connected();
        if let Err(error) = wire::send(&mut socket, LocalReply::Shell).await {
            session.end("local_client_closed", None);
            return Err(error);
        }
        let (mut local_rx, mut local_tx) = socket.into_split();
        tokio::select! {
            _ = self.until_unpaired(id, &request) => {
                connection.close(0u32.into(), b"pairing ended");
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
                session.end(if result.is_ok() { "stream_closed" } else { "shell_io_error" }, None);
                result?;
            }
        }
        Ok(())
    }

    async fn serve_shell(&self, connection: Connection) -> Result<()> {
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
            .session(Direction::Inbound, Some(id), name);
        if !profile_approved {
            session.end("pairing_required", None);
            connection.close(0u32.into(), b"pairing required");
            return Ok(());
        }
        let setup = async {
            let (tx, mut rx) = timeout(wire::RPC_TIMEOUT, connection.accept_bi()).await??;
            let request: ShellRequest = timeout(wire::RPC_TIMEOUT, wire::recv(&mut rx)).await??;
            Ok::<_, anyhow::Error>((tx, rx, request))
        };
        let (mut tx, mut rx, request) = match setup.await {
            Ok(value) => value,
            Err(error) => {
                session.end("shell_request_failed", None);
                return Err(error);
            }
        };
        if !self.allow_shell
            || !self
                .authorized(id, &request.network, request.generation)
                .await
        {
            session.end("shell_unavailable", None);
            wire::send(
                &mut tx,
                LocalReply::Error("shell access is unavailable on this device".into()),
            )
            .await?;
            tx.finish()?;
            let _ = timeout(wire::RPC_TIMEOUT, tx.stopped()).await;
            return Ok(());
        }
        let outcome = tokio::select! {
            _ = self.until_unpaired(id, &request) => {
                connection.close(0u32.into(), b"pairing ended");
                Ok(None)
            }
            result = terminal::serve(&mut rx, &mut tx, request.cols, request.rows, self.shell.as_deref(), || session.connected()) => result.map(Some),
        };
        match outcome {
            Ok(None) => session.end("pairing_ended", None),
            Ok(Some(code)) => {
                session.end("shell_exit", Some(code));
                tx.finish()?;
                let _ = timeout(wire::RPC_TIMEOUT, tx.stopped()).await;
            }
            Err(error) => {
                session.end("shell_io_error", None);
                return Err(error);
            }
        }
        Ok(())
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
                .alpns(vec![wire::SHELL.to_vec()])
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
            allow_shell: true,
            shell: Some("/bin/sh".into()),
            connection_log: ConnectionLog::open(None)?,
            changed: watch::channel(()).0,
        };
        timeout(Duration::from_secs(20), async {
            node.endpoint.online().await;
            let server = async {
                let incoming = node.endpoint.accept().await.context("endpoint closed")?;
                node.serve_shell(incoming.await?).await
            };
            let client = async {
                let addr = EndpointAddr::new(node.endpoint.id()).with_relay_url(url);
                let connection = source.connect(addr, wire::SHELL).await?;
                let (mut tx, mut rx) = connection.open_bi().await?;
                wire::send(
                    &mut tx,
                    ShellRequest {
                        network: "test".into(),
                        generation: 0,
                        cols: 80,
                        rows: 24,
                    },
                )
                .await?;
                assert!(matches!(wire::recv(&mut rx).await?, LocalReply::Shell));
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
