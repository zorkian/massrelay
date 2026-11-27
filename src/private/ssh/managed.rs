//! OpenSSH client entries for approved peers, kept by the running runtime.
//!
//! The profile opts in by holding `ssh-client.conf`, a regular file the installer creates
//! and includes from the user's OpenSSH configuration. While it exists, this task writes one
//! `Host massrelay-<peer> mr-<peer>` block there for each peer this device confirmed. It
//! never writes outside the private profile.
//!
//! `ssh-client-published.sha256` beside it records what was last published there: the
//! SHA-256 in lowercase hexadecimal and a newline. An uninstall removes a configuration
//! only while it matches, so one a person changed is kept. The record is removed before the
//! configuration changes and written after, so an interruption leaves none.
//!
//! Confirmed means the peer, locally approved and eligible, answered the authenticated SSH
//! host-record request. An entry is removed when the peer's authenticated answer denies
//! access, when this device ends the approval it was confirmed under (decline, cutoff,
//! removal or a new approval), or after `KEEP_OFFLINE` without another confirmation.
//! Failing to reach a peer, and replies that this device's state has overtaken, change
//! nothing.
//!
//! Each peer gets a persistent client key (`ssh-client-key-<endpoint>`) and shares the host
//! pin of `massrelay ssh`. `ssh-client.json` records the confirmed entries and every alias
//! ever given out, so an alias never moves to another endpoint.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use iroh::Endpoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use tokio::sync::Notify;
use tokio::task::{Id, JoinSet};
use tokio::time::{Instant, timeout};

use crate::mailbox::Bytes;
use crate::wire::{Refusal as WireRefusal, ServiceReply};

use super::super::audit;
use super::super::binding::EndpointKey;
use super::super::codec::hex;
use super::super::diagnostics::{self, Level};
use super::super::mailbox::Mailbox;
use super::super::pairing::{Decision, PairError, Refusal, parse_key};
use super::super::runtime::{self, Addresses};
use super::super::service::{CLOSE_DONE, Node};
use super::{Host, Request, Settings, client, keys};

/// Its presence opts the profile in. The installer creates it.
const CONFIG_FILE: &str = "ssh-client.conf";
/// The record of what was last published as `CONFIG_FILE`.
const RECORD_FILE: &str = "ssh-client-published.sha256";
const STATE_FILE: &str = "ssh-client.json";
const KEY_PREFIX: &str = "ssh-client-key-";
const HOSTS_PREFIX: &str = "ssh-client-hosts-";
/// How long an entry outlives its last confirmation while the peer cannot confirm again.
const KEEP_OFFLINE: Duration = Duration::from_secs(7 * 24 * 3600);
/// Host-record requests in flight at once.
const MAX_PROBES: usize = 4;

/// A locally approved, eligible peer as this device's state has it now.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Peer {
    /// The local alias pinned to the endpoint.
    alias: String,
    /// The order of the local approval. A confirmation belongs to exactly one.
    approval: u64,
    /// The order of the newest decision the peer proved to this device.
    decision: u64,
    /// That newest decision is not an approval.
    declined: bool,
}

type Peers = BTreeMap<EndpointKey, Peer>;

/// What one host-record request established.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Probe {
    /// The peer authorized this device and sent its SSH host record.
    Confirmed {
        user: String,
        client_key: Bytes<32>,
        /// When the record arrived, in seconds since the Unix epoch.
        at: u64,
    },
    /// The authenticated peer denied this device access.
    Denied,
    /// The authenticated peer did not deny access but cannot serve SSH now.
    Unavailable,
    /// Transport failure: no authenticated answer.
    Unreachable,
    /// This device's state moved on, or the reply is older than what it already knows.
    Stale,
    /// This device could not accept the record (changed host key, local key failure).
    Rejected(String),
}

impl Probe {
    /// An exchange or request that returned no service reply.
    fn failed(error: &PairError) -> Self {
        let PairError::Refused(refusal) = error else {
            return Self::Unreachable;
        };
        match refusal {
            // The peer proved its decision on this connection.
            Refusal::RemoteDeclined => Self::Denied,
            Refusal::Terminal
            | Refusal::NotMember(_)
            | Refusal::NotApproved
            | Refusal::NotPaired
            | Refusal::StaleDecision
            | Refusal::ConflictingDecision
            | Refusal::StaleExchange(_)
            | Refusal::Invalidated(_)
            | Refusal::Stopping => Self::Stale,
            Refusal::WrongGroup
            | Refusal::WrongProtocol
            | Refusal::ConnectionClosed
            | Refusal::ServiceNotGranted => Self::Unreachable,
        }
    }

    /// A refusal the destination sent on the authorized connection.
    fn refused(refusal: WireRefusal) -> Self {
        match refusal {
            WireRefusal::PairingRequired | WireRefusal::ServiceNotEnabled => Self::Denied,
            WireRefusal::TargetUnavailable => Self::Unavailable,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SavedHost {
    /// The `<peer>` of the entry's aliases.
    name: String,
    user: String,
    client_key: Bytes<32>,
    /// `Peer::approval` at confirmation.
    approval: u64,
    /// Seconds since the Unix epoch.
    confirmed: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Saved {
    /// The number reserved for this profile in the user's SSH configuration.
    namespace: u64,
    /// Every `<peer>` ever given out, to the endpoint (hex) that keeps it. Never removed.
    names: BTreeMap<String, String>,
    /// Confirmed entries by endpoint (hex).
    hosts: BTreeMap<String, SavedHost>,
}

impl Saved {
    /// Apply new answers, then keep only what this device's present state still supports.
    fn apply(&mut self, peers: &Peers, answers: &BTreeMap<EndpointKey, (u64, Probe)>, now: u64) {
        for (key, (approval, probe)) in answers {
            if peers.get(key).is_none_or(|peer| peer.approval != *approval) {
                continue;
            }
            match probe {
                Probe::Confirmed {
                    user,
                    client_key,
                    at,
                } => {
                    let host = SavedHost {
                        name: String::new(),
                        user: user.clone(),
                        client_key: *client_key,
                        approval: *approval,
                        confirmed: *at,
                    };
                    self.hosts.insert(hex(key), host);
                }
                Probe::Denied => {
                    self.hosts.remove(&hex(key));
                }
                Probe::Unavailable | Probe::Unreachable | Probe::Stale | Probe::Rejected(_) => {}
            }
        }
        let mut kept = BTreeMap::new();
        for (key, peer) in peers {
            let id = hex(key);
            let Some(mut host) = self.hosts.remove(&id) else {
                continue;
            };
            // A clock set back must not extend an entry's life indefinitely.
            host.confirmed = host.confirmed.min(now);
            if peer.declined
                || host.approval != peer.approval
                || now - host.confirmed >= KEEP_OFFLINE.as_secs()
            {
                continue;
            }
            host.name = reserve(&mut self.names, &peer.alias, &id);
            kept.insert(id, host);
        }
        self.hosts = kept;
    }
}

/// The `<peer>` part of an endpoint's aliases: its local alias reduced to characters that are
/// literal in an OpenSSH `Host` pattern. A name another endpoint holds gets a suffix from
/// this endpoint's key, so the result stays the same from then on.
fn reserve(names: &mut BTreeMap<String, String>, alias: &str, endpoint: &str) -> String {
    let cleaned: String = alias
        .chars()
        .map(|c| match c.to_ascii_lowercase() {
            c if c.is_ascii_alphanumeric() || "._-".contains(c) => c,
            _ => '-',
        })
        .collect();
    // Double dashes are reserved for profile suffixes.
    let cleaned = cleaned
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let base = match cleaned.trim_matches(['-', '.']) {
        "" => &endpoint[..8],
        base => base,
    };
    let suffixed = [8, 16, 32, 64]
        .into_iter()
        .map(|len| format!("{base}-{}", &endpoint[..len]));
    let numbered = (2u64..).map(|n| format!("{base}-{endpoint}-{n}"));
    let name = std::iter::once(base.to_owned())
        .chain(suffixed)
        .chain(numbered)
        .find(|name| names.get(name).is_none_or(|holder| holder == endpoint))
        .expect("unbounded candidates");
    names.insert(name.clone(), endpoint.to_owned());
    name
}

fn eligible<M: Mailbox + Send + Sync + 'static>(node: &Node<M>) -> Result<Peers> {
    let failed = |error: PairError| anyhow::anyhow!("read peer state: {error:?}");
    let view = node.member_view().map_err(failed)?;
    // After this device's own removal there is no pairing state to read.
    if view.terminal || view.group_tag.is_none() {
        return Ok(Peers::new());
    }
    let state = node.pairing_state().map_err(failed)?;
    Ok(state
        .peers
        .into_iter()
        .filter(|peer| matches!(peer.local, Decision::Approve { .. }))
        .filter(|peer| view.ineligible(&peer.endpoint).is_none())
        .map(|peer| {
            let record = Peer {
                alias: peer.alias,
                approval: peer.local_order,
                decision: peer.remote_order,
                declined: peer.remote == Decision::Decline,
            };
            (peer.endpoint, record)
        })
        .collect())
}

/// `present`, first replacing on Windows a configuration whose access list is not private.
fn opted_in(dir: &Path) -> Result<bool> {
    let present = present(dir)?;
    #[cfg(windows)]
    if present
        && crate::windows_service::ssh_files::check_managed_file(&dir.join(CONFIG_FILE)).is_err()
    {
        write_config(dir, staged(dir, b"")?, b"")?;
    }
    Ok(present)
}

/// Whether the profile holds a configuration file that is safe to replace. Writes nothing.
fn present(dir: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(dir.join(CONFIG_FILE)) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("inspect ssh-client.conf"),
    };
    ensure!(metadata.is_file(), "ssh-client.conf is not a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == fs::metadata(dir)?.uid()
                && metadata.mode() & 0o022 == 0
                && metadata.nlink() == 1,
            "ssh-client.conf must be writable only by the profile's owner"
        );
    }
    #[cfg(windows)]
    crate::windows_service::ssh_private_dir(dir)?;
    Ok(true)
}

/// A new private file in the profile, to be renamed over its destination.
fn staged(dir: &Path, content: &[u8]) -> Result<NamedTempFile> {
    #[cfg(windows)]
    let mut file = crate::windows_service::private_marker(dir)?;
    #[cfg(not(windows))]
    let mut file = NamedTempFile::new_in(dir)?;
    file.write_all(content)?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn unchanged(path: &Path, content: &[u8]) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
        && fs::read(path).is_ok_and(|old| old == content)
}

fn publish_file(dir: &Path, file: NamedTempFile, name: &str) -> Result<()> {
    file.persist(dir.join(name))
        .with_context(|| format!("replace {name}"))?;
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn replace(dir: &Path, name: &str, content: &[u8]) -> Result<()> {
    let path = dir.join(name);
    if unchanged(&path, content) {
        #[cfg(windows)]
        if crate::windows_service::ssh_files::check_managed_file(&path).is_err() {
            return publish_file(dir, staged(dir, content)?, name);
        }
        return Ok(());
    }
    publish_file(dir, staged(dir, content)?, name)
}

/// Publish `content` as the configuration and record it, unless the file was removed.
fn publish_config(dir: &Path, content: &[u8]) -> Result<()> {
    if unchanged(&dir.join(CONFIG_FILE), content) {
        #[cfg(windows)]
        if crate::windows_service::ssh_files::check_managed_file(&dir.join(CONFIG_FILE)).is_err() {
            return write_config(dir, staged(dir, content)?, content);
        }
        // Also without a change: an interrupted publication left no record.
        return record(dir, content);
    }
    let file = staged(dir, content)?;
    // Never bring back a file that was removed to opt out.
    if present(dir)? {
        write_config(dir, file, content)?;
    }
    Ok(())
}

/// Replace the configuration with `file`, which holds `content`. Between the two records
/// there is none, so none ever describes anything but the last bytes published.
fn write_config(dir: &Path, file: NamedTempFile, content: &[u8]) -> Result<()> {
    match fs::remove_file(dir.join(RECORD_FILE)) {
        Ok(()) => {
            #[cfg(unix)]
            fs::File::open(dir)?.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("remove the SSH configuration record"),
    }
    publish_file(dir, file, CONFIG_FILE)?;
    record(dir, content)
}

fn record(dir: &Path, content: &[u8]) -> Result<()> {
    let digest = format!("{:x}\n", Sha256::digest(content));
    replace(dir, RECORD_FILE, digest.as_bytes())
}

/// The absolute paths the generated entries name.
#[derive(Clone)]
struct Paths {
    profile: PathBuf,
    state: PathBuf,
    program: PathBuf,
}

impl Paths {
    fn resolve(dir: &Path, program: Option<&Path>) -> Result<Self> {
        let program = match program {
            Some(program) => program.to_owned(),
            None => std::env::current_exe()?,
        };
        Ok(Self {
            profile: dir.canonicalize().context("resolve the private profile")?,
            state: dir
                .parent()
                .context("missing runtime state directory")?
                .canonicalize()
                .context("resolve the state directory")?,
            program: program
                .canonicalize()
                .context("resolve the MassRelay program")?,
        })
    }
}

fn namespaced(name: &str, namespace: u64) -> String {
    if namespace == 1 {
        name.to_owned()
    } else {
        format!("{name}--{namespace}")
    }
}

/// Write one endpoint's host file and render its block. `None` until it has both a pinned
/// host key and a client key.
fn block(
    dir: &Path,
    paths: &Paths,
    id: &str,
    host: &SavedHost,
    namespace: u64,
) -> Result<Option<String>> {
    let endpoint = parse_key(id).context("invalid saved endpoint")?;
    let identity = format!("{KEY_PREFIX}{id}");
    let Some(host_key) = client::pinned(dir, &endpoint)? else {
        return Ok(None);
    };
    let identity = paths.profile.join(identity);
    if !fs::symlink_metadata(&identity).is_ok_and(|metadata| metadata.is_file()) {
        return Ok(None);
    }
    #[cfg(windows)]
    crate::windows_service::ssh_files::check_managed_file(&identity)?;
    ensure!(Host::valid_user(&host.user), "invalid saved SSH account");
    let name = namespaced(&host.name, namespace);
    let alias = format!("massrelay-{name}");
    let hosts = format!("{HOSTS_PREFIX}{id}");
    let known = client::known_host(&alias, &host_key);
    replace(dir, &hosts, known.as_bytes())?;
    client::render(&client::Entry {
        managed: true,
        patterns: &format!("{alias} mr-{name}"),
        alias: &alias,
        user: &host.user,
        identity: &identity,
        known_hosts: &paths.profile.join(hosts),
        program: &paths.program,
        state: &paths.state,
        peer: id,
        client_key: &host.client_key.0,
    })
    .map(Some)
}

/// Bring the profile's state, host files and configuration up to date. Does nothing unless
/// the configuration file is still there. An entry that cannot be written is left out, so it
/// never holds back another's removal; the first such failure is returned.
fn publish(
    dir: &Path,
    paths: &Paths,
    peers: &Peers,
    answers: &BTreeMap<EndpointKey, (u64, Probe)>,
    now: u64,
) -> Result<Option<String>> {
    if !opted_in(dir)? {
        return Ok(None);
    }
    // Refuse to reuse names if the installer-created reservation state was lost.
    let read = || -> Result<Saved> {
        let path = dir.join(STATE_FILE);
        #[cfg(windows)]
        crate::windows_service::ssh_files::check_managed_file(&path)?;
        let saved: Saved =
            serde_json::from_slice(&fs::read(path)?).context("read ssh-client.json")?;
        ensure!(saved.namespace > 0, "invalid SSH alias namespace");
        ensure!(
            saved
                .hosts
                .iter()
                .all(|(id, host)| saved.names.get(&host.name) == Some(id)),
            "an SSH alias is missing its original reservation"
        );
        Ok(saved)
    };
    let mut saved = match read() {
        Ok(saved) => saved,
        Err(error) => {
            publish_config(dir, b"")?;
            return Err(error.context("SSH alias reservations unavailable"));
        }
    };
    saved.apply(peers, answers, now);
    // Reservations are durable before any configuration names them.
    replace(dir, STATE_FILE, &serde_json::to_vec(&saved)?)?;

    let mut blocks = BTreeMap::new();
    let mut omitted = None;
    for (id, host) in &saved.hosts {
        match block(dir, paths, id, host, saved.namespace) {
            Ok(Some(block)) => {
                blocks.insert(&host.name, block);
            }
            Ok(None) => {}
            Err(error) => {
                omitted.get_or_insert_with(|| format!("{}: {error:#}", host.name));
            }
        }
    }
    let mut config = String::new();
    if !blocks.is_empty() {
        config.push_str("# Written by MassRelay. Changes to this file are replaced.\n");
        for block in blocks.values() {
            config.push('\n');
            config.push_str(block);
        }
    }
    publish_config(dir, config.as_bytes())?;
    Ok(omitted)
}

/// Ask one peer for its SSH host record on a freshly authorized connection.
async fn probe<M: Mailbox + Send + Sync + 'static>(
    node: Arc<Node<M>>,
    endpoint: Endpoint,
    addresses: Addresses,
    dir: PathBuf,
    key: EndpointKey,
    deadline: Duration,
) -> Probe {
    let Ok(address) = runtime::peer_address(&addresses, &key) else {
        return Probe::Unreachable;
    };
    let opened = timeout(deadline, node.open_ssh(&endpoint, address, Request::Info)).await;
    // The exchange may have learned a decision or paired.
    audit::observe(&node, false);
    let stream = match opened {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Probe::failed(&error),
        Err(_) => return Probe::Unreachable,
    };
    let answer = match (&stream.reply, &stream.ssh_host) {
        _ if matches!(stream.status(), Err(Refusal::Invalidated(_))) => Err(Probe::Stale),
        (ServiceReply::Refused { refusal, .. }, _) => Err(Probe::refused(*refusal)),
        (ServiceReply::Ready, Some(host)) => Ok(host.clone()),
        (ServiceReply::Ready, None) => Err(Probe::Unreachable),
    };
    // Release the authorization before any local work.
    stream.conn.close(0u32.into(), CLOSE_DONE);
    drop(stream);
    let host = match answer {
        Ok(host) => host,
        Err(probe) => return probe,
    };
    let at = crate::storage::now();
    match timeout(deadline, accept(dir, key, host, at)).await {
        Ok(Ok(confirmed)) => confirmed,
        Ok(Err(error)) => Probe::Rejected(format!("{error:#}")),
        Err(_) => Probe::Rejected("preparing the SSH client key timed out".into()),
    }
}

/// Pin the confirmed host key and make sure this device has the peer's client key.
async fn accept(dir: PathBuf, key: EndpointKey, host: Host, at: u64) -> Result<Probe> {
    ensure!(Host::valid_user(&host.user), "invalid SSH account");
    #[cfg(windows)]
    crate::windows_service::ssh_private_dir(&dir)?;
    let id = hex(&key);
    let (path, peer) = (dir.clone(), id.clone());
    let (user, record) = (host.user.clone(), host);
    let migrated =
        tokio::task::spawn_blocking(move || client::pin(&path, &peer, &record, None)).await??;
    if migrated {
        diagnostics::event(
            Level::Info,
            "a peer's system SSH host key replaced the one pinned for its former SSH server",
        );
    }
    let client_key = keys::persistent(&dir, &format!("{KEY_PREFIX}{id}")).await?;
    Ok(Probe::Confirmed {
        user,
        client_key: Bytes(client_key),
        at,
    })
}

/// When a peer is asked next.
struct Due {
    /// `Peer::approval` the schedule was made under.
    approval: u64,
    /// `Peer::decision` likewise; `None` right after an answer, whose own exchange may have
    /// changed it.
    decision: Option<u64>,
    next: Instant,
    failures: u32,
    /// The rejection last reported.
    rejected: Option<String>,
}

impl Due {
    fn now(peer: &Peer) -> Self {
        Self {
            approval: peer.approval,
            decision: Some(peer.decision),
            next: Instant::now(),
            failures: 0,
            rejected: None,
        }
    }

    /// Schedule the next request. Returns a rejection not reported before.
    fn answered(&mut self, probe: &Probe, settings: &Settings) -> Option<&str> {
        let rejected = match probe {
            Probe::Rejected(detail) => Some(detail.clone()),
            _ => None,
        };
        let new = rejected != self.rejected;
        self.rejected = rejected;
        let wait = if matches!(probe, Probe::Confirmed { .. }) {
            self.failures = 0;
            settings.refresh_every
        } else {
            self.failures = self.failures.saturating_add(1);
            let doubled = 1u32 << (self.failures - 1).min(16);
            settings
                .retry_after
                .saturating_mul(doubled)
                .min(settings.refresh_every)
        };
        self.decision = None;
        self.next = Instant::now() + wait;
        self.rejected.as_deref().filter(|_| new)
    }
}

fn warn(detail: &str) {
    diagnostics::quiet(
        Level::Warning,
        "could not update the managed SSH configuration",
    );
    if diagnostics::console() {
        eprintln!("massrelay: could not update the managed SSH configuration: {detail}");
    }
}

/// Keep the configuration current until `stop` resolves. `wake` reports that this device's
/// state may have changed; otherwise the profile is checked every `check_every`.
#[allow(clippy::too_many_arguments)]
pub(in crate::private) async fn maintain<M: Mailbox + Send + Sync + 'static>(
    node: Arc<Node<M>>,
    endpoint: Endpoint,
    addresses: Addresses,
    dir: PathBuf,
    settings: Settings,
    wake: Arc<Notify>,
    stop: impl std::future::Future<Output = ()>,
) {
    // Resolved at start: an update may later replace the running program's file.
    let paths = Paths::resolve(&dir, settings.program.as_deref()).map_err(|e| format!("{e:#}"));
    let mut schedule = BTreeMap::<EndpointKey, Due>::new();
    let mut running = BTreeMap::<EndpointKey, (Id, u64)>::new();
    let mut probes = JoinSet::<Probe>::new();
    let mut answers = BTreeMap::<EndpointKey, (u64, Probe)>::new();
    let mut reported = None;
    tokio::pin!(stop);
    while !node.stopping() {
        let pass = async {
            let path = dir.clone();
            if !tokio::task::spawn_blocking(move || present(&path)).await?? {
                return Ok(None);
            }
            let paths = paths.clone().map_err(anyhow::Error::msg)?;
            let current = node.clone();
            let peers = tokio::task::spawn_blocking(move || eligible(&current)).await??;
            let (path, view, new) = (dir.clone(), peers.clone(), answers.clone());
            let now = crate::storage::now();
            // The profile stays owned while it is written, even if a stop gives up
            // waiting: an uninstall changes these files only once it owns the profile.
            let owner = node.clone();
            let omitted = tokio::task::spawn_blocking(move || {
                let _owner = owner;
                publish(&path, &paths, &view, &new, now)
            })
            .await??;
            Ok::<_, anyhow::Error>(Some((peers, omitted)))
        }
        .await;
        let failed = pass.is_err();
        let (peers, problem) = match pass {
            Ok(Some((peers, omitted))) => (Some(peers), omitted),
            Ok(None) => (None, None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
        if problem != reported {
            if let Some(detail) = &problem {
                warn(detail);
            }
            reported = problem;
        }
        match peers {
            Some(peers) => {
                answers.clear();
                schedule.retain(|key, _| peers.contains_key(key));
                for (key, peer) in &peers {
                    let due = schedule.entry(*key).or_insert_with(|| Due::now(peer));
                    // A new approval or a newly proved decision is worth asking about now.
                    if due.approval != peer.approval
                        || due.decision.is_some_and(|old| old != peer.decision)
                    {
                        *due = Due::now(peer);
                    } else {
                        due.decision = Some(peer.decision);
                    }
                }
                let now = Instant::now();
                let mut ready: Vec<_> = schedule
                    .iter()
                    .filter(|(key, due)| due.next <= now && !running.contains_key(*key))
                    .map(|(key, due)| (due.failures, due.next, *key))
                    .collect();
                // Peers not yet failing go first, so offline ones cannot starve them.
                ready.sort_unstable();
                for (_, _, key) in ready
                    .into_iter()
                    .take(MAX_PROBES.saturating_sub(probes.len()))
                {
                    let task = probes.spawn(probe(
                        node.clone(),
                        endpoint.clone(),
                        addresses.clone(),
                        dir.clone(),
                        key,
                        settings.probe_deadline,
                    ));
                    running.insert(key, (task.id(), peers[&key].approval));
                }
            }
            // Opted out: ask nobody. After an error keep the answers for the next pass.
            None if !failed => {
                probes.shutdown().await;
                running.clear();
                schedule.clear();
                answers.clear();
            }
            None => {}
        }
        tokio::select! {
            biased;
            _ = &mut stop => break,
            Some(done) = probes.join_next_with_id() => {
                let (id, probe) = match done {
                    Ok((id, probe)) => (id, Some(probe)),
                    Err(error) => (error.id(), None),
                };
                let finished = running
                    .iter()
                    .find(|(_, (task, _))| *task == id)
                    .map(|(key, (_, approval))| (*key, *approval));
                if let Some((key, approval)) = finished {
                    running.remove(&key);
                    let probe = probe.unwrap_or(Probe::Rejected("the SSH check failed".into()));
                    // An answer for a replaced approval leaves the new one due.
                    let due = schedule.get_mut(&key);
                    if let Some(due) = due.filter(|due| due.approval == approval)
                        && let Some(rejected) = due.answered(&probe, &settings)
                    {
                        warn(rejected);
                    }
                    answers.insert(key, (approval, probe));
                }
            }
            _ = wake.notified() => {}
            _ = tokio::time::sleep(settings.check_every) => {}
        }
    }
    probes.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: EndpointKey = [0x11; 32];
    const TWO: EndpointKey = [0x22; 32];
    const DAY: u64 = 24 * 3600;

    fn peer(alias: &str, approval: u64) -> Peer {
        Peer {
            alias: alias.into(),
            approval,
            decision: 1,
            declined: false,
        }
    }

    fn answer(
        key: EndpointKey,
        approval: u64,
        probe: Probe,
    ) -> BTreeMap<EndpointKey, (u64, Probe)> {
        BTreeMap::from([(key, (approval, probe))])
    }

    fn confirmed(at: u64) -> Probe {
        Probe::Confirmed {
            user: "user".into(),
            client_key: Bytes([7; 32]),
            at,
        }
    }

    #[test]
    fn only_authenticated_denials_count_as_denials() {
        let failed = |refusal| Probe::failed(&PairError::Refused(refusal));
        assert_eq!(failed(Refusal::RemoteDeclined), Probe::Denied);
        assert_eq!(failed(Refusal::ConnectionClosed), Probe::Unreachable);
        assert_eq!(
            Probe::failed(&PairError::Local("no route".into())),
            Probe::Unreachable
        );
        for overtaken in [
            Refusal::StaleDecision,
            Refusal::ConflictingDecision,
            Refusal::StaleExchange("changed"),
            Refusal::Invalidated("re-paired".into()),
            Refusal::NotApproved,
            Refusal::Stopping,
        ] {
            assert_eq!(failed(overtaken), Probe::Stale);
        }
        assert_eq!(
            Probe::refused(WireRefusal::ServiceNotEnabled),
            Probe::Denied
        );
        assert_eq!(Probe::refused(WireRefusal::PairingRequired), Probe::Denied);
        assert_eq!(
            Probe::refused(WireRefusal::TargetUnavailable),
            Probe::Unavailable
        );
    }

    #[test]
    fn entries_follow_answers_the_local_approval_and_age() {
        let mut peers = Peers::from([(ONE, peer("one", 1))]);
        let mut saved = Saved::default();
        let none = BTreeMap::new();
        let start = 100 * DAY;

        // Only a confirmation under the present approval adds an entry.
        for probe in [Probe::Unreachable, Probe::Unavailable, Probe::Stale] {
            saved.apply(&peers, &answer(ONE, 1, probe), start);
        }
        saved.apply(&peers, &answer(ONE, 0, confirmed(start)), start);
        saved.apply(&peers, &answer(TWO, 1, confirmed(start)), start);
        assert!(saved.hosts.is_empty());
        // Its seven days start when the record arrived, even if saved later.
        saved.apply(&peers, &answer(ONE, 1, confirmed(start)), start + DAY);
        let entry = saved.clone();
        assert_eq!(entry.hosts.len(), 1);

        // Nothing short of a current denial touches it for seven days.
        for probe in [
            Probe::Unreachable,
            Probe::Unavailable,
            Probe::Stale,
            Probe::Rejected("changed".into()),
        ] {
            saved.apply(&peers, &answer(ONE, 1, probe), start + DAY);
        }
        saved.apply(&peers, &answer(ONE, 0, Probe::Denied), start + DAY);
        saved.apply(&peers, &none, start + 7 * DAY - 1);
        assert_eq!(saved, entry);
        saved.apply(&peers, &none, start + 7 * DAY);
        assert!(saved.hosts.is_empty());

        // A clock set back restarts the seven days from the earlier time.
        let mut saved = entry.clone();
        saved.apply(&peers, &none, start - 20 * DAY);
        saved.apply(&peers, &none, start - 13 * DAY);
        assert!(saved.hosts.is_empty());

        let mut saved = entry.clone();
        saved.apply(&peers, &answer(ONE, 1, Probe::Denied), start);
        assert!(saved.hosts.is_empty());

        // A declining peer, a new local approval and a lost eligibility each end it,
        // even against a confirmation that arrives at the same time.
        peers.get_mut(&ONE).unwrap().declined = true;
        let mut saved = entry.clone();
        saved.apply(&peers, &answer(ONE, 1, confirmed(start)), start);
        assert!(saved.hosts.is_empty());
        let mut saved = entry.clone();
        saved.apply(&Peers::from([(ONE, peer("one", 2))]), &none, start);
        assert!(saved.hosts.is_empty());
        let mut saved = entry;
        saved.apply(&Peers::new(), &answer(ONE, 1, confirmed(start)), start);
        assert!(saved.hosts.is_empty());
    }

    #[test]
    fn an_alias_never_moves_to_another_endpoint() {
        let (one, two) = (hex(&ONE), hex(&TWO));
        let mut names = BTreeMap::new();
        assert_eq!(reserve(&mut names, "Lab*", &one), "lab");
        // Patterns and case cannot make two endpoints share a name.
        let suffixed = format!("lab-{}", &two[..8]);
        assert_eq!(reserve(&mut names, "LAB?", &two), suffixed);
        assert_eq!(reserve(&mut names, "LAB?", &two), suffixed);
        // A renamed endpoint keeps its old name reserved, even after it is gone.
        assert_eq!(reserve(&mut names, "desk", &one), "desk");
        assert_eq!(reserve(&mut names, "lab", &two), suffixed);
        assert_eq!(reserve(&mut names, "lab", &one), "lab");
        // A name chosen to equal another endpoint's suffixed one does not take it.
        let three = "3".repeat(64);
        assert_eq!(
            reserve(&mut names, &suffixed, &three),
            format!("{suffixed}-33333333")
        );
        assert_eq!(reserve(&mut names, "!\"*", &three), "33333333");
    }

    #[test]
    fn profile_suffixes_cannot_collide_with_literal_peer_names() {
        let mut names = BTreeMap::new();
        let name = reserve(&mut names, "lab--2", &hex(&ONE));
        assert_eq!(name, "lab-2");
        assert_eq!(namespaced("lab", 1), "lab");
        assert_eq!(namespaced("lab", 2), "lab--2");
        assert_ne!(name, namespaced("lab", 2));
    }

    #[cfg(unix)]
    #[test]
    fn publication_replaces_only_a_protected_file_and_survives_a_damaged_entry() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("private");
        fs::create_dir(&dir).unwrap();
        let paths = Paths::resolve(&dir, Some(&std::env::current_exe().unwrap())).unwrap();
        for (key, pin) in [(ONE, vec![1; 32]), (TWO, vec![2; 31])] {
            fs::write(dir.join(format!("ssh-pin-{}", hex(&key))), pin).unwrap();
            fs::write(dir.join(format!("{KEY_PREFIX}{}", hex(&key))), "key").unwrap();
        }
        let peers = Peers::from([(ONE, peer("one", 1)), (TWO, peer("two", 1))]);
        let mut answers = answer(ONE, 1, confirmed(100));
        answers.extend(answer(TWO, 1, confirmed(100)));
        let config = dir.join(CONFIG_FILE);
        let publish = |answers: &_| publish(&dir, &paths, &peers, answers, 100);
        let mode = |mode| fs::set_permissions(&config, fs::Permissions::from_mode(mode)).unwrap();

        publish(&answers).unwrap();
        assert!(!config.exists() && !dir.join(STATE_FILE).exists());
        assert!(!dir.join(RECORD_FILE).exists());

        let target = root.path().join("elsewhere");
        fs::write(&target, "keep").unwrap();
        symlink(&target, &config).unwrap();
        assert!(publish(&answers).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        fs::remove_file(&config).unwrap();
        fs::write(&config, "keep").unwrap();
        mode(0o620);
        assert!(publish(&answers).is_err());
        assert_eq!(fs::read(&config).unwrap(), b"keep");

        mode(0o600);
        fs::write(
            dir.join(STATE_FILE),
            br#"{"namespace":1,"names":{},"hosts":{}}"#,
        )
        .unwrap();
        assert!(
            publish(&answers)
                .unwrap()
                .is_some_and(|omitted| omitted.starts_with("two:"))
        );
        let text = fs::read_to_string(&config).unwrap();
        assert!(text.contains("Host massrelay-one mr-one\n"));
        assert!(!text.contains("mr-two"));

        // The record is of exactly what was published, and is private.
        let record = dir.join(RECORD_FILE);
        let recorded = || {
            let expected = format!("{:x}\n", Sha256::digest(fs::read(&config).unwrap()));
            assert_eq!(fs::read_to_string(&record).unwrap(), expected);
            let metadata = fs::metadata(&record).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        };
        recorded();
        // One that is missing or stale is renewed although the configuration is current.
        fs::remove_file(&record).unwrap();
        publish(&answers).unwrap();
        recorded();
        fs::write(&record, "stale\n").unwrap();
        publish(&answers).unwrap();
        recorded();
        // A change someone made is replaced, as before, and the record follows.
        fs::write(&config, "Host mine\n").unwrap();
        publish(&answers).unwrap();
        assert_eq!(fs::read_to_string(&config).unwrap(), text);
        recorded();
        // Without a way to withdraw the old record, the configuration is not changed.
        fs::remove_file(&record).unwrap();
        fs::create_dir(&record).unwrap();
        assert!(publish(&answer(ONE, 1, Probe::Denied)).is_err());
        assert_eq!(fs::read_to_string(&config).unwrap(), text);
        fs::remove_dir(&record).unwrap();

        publish(&answer(ONE, 1, Probe::Denied)).unwrap();
        assert_eq!(fs::read(&config).unwrap(), b"");
        recorded();

        // Bad or lost reservations withdraw entries without assigning their names again.
        publish(&answers).unwrap();
        let state = dir.join(STATE_FILE);
        let record = fs::read(&state).unwrap();
        let mut partial: Saved = serde_json::from_slice(&record).unwrap();
        partial.names.clear();
        let partial = serde_json::to_vec(&partial).unwrap();
        fs::write(&state, &partial).unwrap();
        assert!(publish(&answers).is_err());
        assert_eq!(fs::read(&state).unwrap(), partial);
        assert_eq!(fs::read(&config).unwrap(), b"");
        fs::write(dir.join(STATE_FILE), "damaged").unwrap();
        assert!(publish(&answers).is_err());
        assert_eq!(fs::read(dir.join(STATE_FILE)).unwrap(), b"damaged");
        assert_eq!(fs::read(&config).unwrap(), b"");
        fs::remove_file(dir.join(STATE_FILE)).unwrap();
        assert!(publish(&answers).is_err());
        assert!(!dir.join(STATE_FILE).exists());
        assert_eq!(fs::read(&config).unwrap(), b"");
    }
}
