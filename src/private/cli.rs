//! Top-level device commands, using the encrypted membership store.
//!
//! The profile directory holds the endpoint key, pinned relay locator,
//! membership state, and local runtime marker. Mailbox exchanges use
//! separate random transport identities.
//!
//! - `create` pins a relay from its locator after checking, over the relay's
//!   authenticated identity, that it serves the locator's storage incarnation and admits the
//!   locator's operator access credential.
//! - `relay-access` replaces that credential with the one in a newer locator for the exact same
//!   relay, addresses and incarnation, after the relay admits it; nothing else changes. The
//!   relay operator issues credentials and revokes them (`docs/private-relay-operations.md`).
//! - `invite` asks the running runtime for a one-use invite and prints one envelope carrying
//!   the relay locator and the invite bytes. The envelope is a bearer secret. It is never logged.
//! - `join` reads that envelope (argument or standard input), refuses it unless the locator's
//!   relay key and incarnation equal the ones inside the invite and the relay authenticates that
//!   incarnation, persists the exact request, appends it, and waits for the issuer's reply. Run
//!   again, it resumes the same pending join with the exact persisted request.
//! - `run` is the foreground runtime. Its membership pass processes invite requests, stages and
//!   settles the Add of a reserved invite, catches up and dispatches sealed replies, all through
//!   the runtime's owner.
//!   Its diagnostics go to the host's native log (`super::diagnostics`), in the foreground and
//!   under a service manager alike; the connection audit stays in its own JSONL file.
//! - `logs` reads both native diagnostics and the profile's local connection audit.
//! - `rename NEW_NAME` sets the profile's display name through the running owner or under the
//!   offline owner lock. `rename PEER NEW_NAME` changes a local alias through the running owner.
//! - Every other command talks to the running runtime over its authenticated local control
//!   channel; `status` and `peers` fall back to a read-only view when it is not running.
//!
//! The device's endpoint identity serves peers only; every mailbox exchange uses a separate
//! random transport identity.
//!
use std::io::{self, IsTerminal, Write as _};
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Subcommand;
use iroh::{EndpointAddr, EndpointId, SecretKey};
use serde::{Deserialize, Serialize};

use crate::mailbox::{self, Bytes, Client, Locator};
use crate::wire::{self, Service};

use super::binding::{EndpointSecret, check_device_name};
use super::codec::{Hash, hex, unhex};
use super::diagnostics::{self, Level};
use super::envelope::{InviteToken, SlotId};
use super::mailbox::{
    AckOutcome, CreateOutcome, Mailbox, MailboxError, Pin, QueueAppend, QueueItem, ReadOutcome,
    SlotWrite, Started,
};
use super::membership::{
    Clock, Device, Error as MembershipError, JoinError, PeerMatch, RosterMember, SelectError,
    select_peer,
};
use super::pairing::{Owner, PairError};
use super::relay_mailbox::RelayMailbox;
use super::runtime::{
    self, CONTROL, Config, ControlReply, ControlRequest, PeerView, PingRoute, Runtime,
};
use super::service::SERVICE_ALPN;
use super::store;
use super::versions;
use crate::slot_wire::{AckHeader, ReadHeader};

/// The private profile's directory under the state directory.
pub const DIR_NAME: &str = "private-experimental-0";
const PROFILE_FILE: &str = "private-device.json";
const PROFILE_FORMAT: &str = "massrelay-private-device/experimental-0";
const INVITE_PREFIX: &str = "mrprivinv0_";
const INVITE_FORMAT: &str = "massrelay-private-invite/experimental-0";
/// Transport ALPN of the throwaway endpoint that checks a relay's incarnation.
const CHECK_ALPN: &[u8] = b"massrelay/mailbox-check/experimental-1";
/// The exit status of a runtime that an update retired, outside Windows (`EX_TEMPFAIL`).
const RETIRED_EXIT: i32 = 75;
/// How often a waiting join looks for its reply.
const JOIN_POLL: Duration = Duration::from_secs(2);

#[derive(Subcommand)]
pub enum Command {
    /// Create a network and print its first one-use invite.
    Create {
        /// Relay locator. Omit to read it from standard input.
        #[arg(
            long,
            value_name = "LOCATOR",
            env = "MASSRELAY_RELAY",
            hide_env_values = true
        )]
        relay: Option<String>,
        /// Device name. Defaults to this machine’s hostname.
        #[arg(long)]
        name: Option<String>,
        /// Copy the invite to the clipboard.
        #[arg(long)]
        copy: bool,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
    },
    /// Create a one-use invite valid for ten minutes.
    Invite {
        /// Copy the invite to the clipboard.
        #[arg(long)]
        copy: bool,
    },
    /// Replace the relay access credential with the one in a new locator for the same relay.
    RelayAccess {
        /// Current locator for the pinned relay. Omit to read it from standard input.
        #[arg(value_name = "LOCATOR")]
        locator: Option<String>,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
    },
    /// Join with an invite, or resume a pending join.
    Join {
        /// The invite envelope (mrprivinv0_...). Omit to read it from stdin or to resume.
        #[arg(value_name = "INVITE")]
        invite: Option<String>,
        /// Device name. Defaults to this machine’s hostname.
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
    },
    /// Run this device in the foreground.
    Run {
        /// Use this shell executable instead of the account's default.
        #[arg(long)]
        shell: Option<PathBuf>,
        /// Append connection events here.
        #[arg(long)]
        log_file: Option<PathBuf>,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
        /// Seconds between membership passes.
        #[arg(long, value_name = "SECONDS", default_value_t = 30)]
        sync_every: u64,
    },
    /// Show this device’s enrollment and runtime.
    Status,
    /// Rename this device or change a peer's local alias.
    #[command(
        after_help = "  massrelay rename NEW_NAME       Change this device's display name\n  massrelay rename PEER NEW_NAME  Change a peer's alias on this device"
    )]
    Rename {
        /// This device's new name, or the peer's current local alias or exact endpoint ID.
        #[arg(value_name = "NEW_NAME|PEER")]
        name_or_peer: String,
        /// The peer's new local alias when PEER is supplied.
        #[arg(value_name = "NEW_NAME")]
        new_name: Option<String>,
    },
    /// Show this device’s recent diagnostics and connection audit.
    Logs {
        /// Keep printing new events as they are written.
        #[arg(long, short)]
        follow: bool,
        /// Read the connection audit from this file instead of the profile defaults.
        #[arg(long, value_name = "PATH")]
        log_file: Option<PathBuf>,
    },
    /// List members and pairing decisions, by endpoint key and local alias.
    Peers {
        /// Show full endpoint IDs in the terminal.
        #[arg(long)]
        full: bool,
    },
    /// Measure datagram round-trip time and loss to a paired peer.
    Ping {
        /// Endpoint ID, alias, or device name.
        peer: String,
        /// Number of probes to send.
        #[arg(short = 'c', long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=i64::from(runtime::MAX_PING_COUNT)))]
        count: u16,
    },
    /// Approve a member's exact endpoint key under a local alias.
    Approve {
        /// Verified endpoint ID, local alias, or a display name to confirm.
        peer: String,
        /// Local alias to pin to the verified key.
        #[arg(long = "as", value_name = "ALIAS")]
        alias: Option<String>,
        /// Replace an earlier decision for this key with a fresh approval.
        #[arg(long)]
        reapprove: bool,
    },
    /// Decline a peer, ending any pairing with it.
    Decline { peer: String },
    /// Cut a peer off locally now, then remove it from the network.
    Revoke { peer: String },
    /// Grant a paired peer a service, or enable it by default.
    Enable {
        /// shell, tcp:PORT, or udp:PORT. Ports forward to loopback on this device.
        service: Service,
        /// Endpoint key or alias. Omit to enable the default for every paired peer.
        peer: Option<String>,
    },
    /// Remove a peer's grant (excluding it from the default), or disable the default.
    Disable {
        service: Service,
        peer: Option<String>,
    },
    /// List persistent grants, temporary exposures, defaults, and exclusions.
    List {
        /// Show full endpoint IDs.
        #[arg(long)]
        full: bool,
    },
    /// Offer a port to one peer for as long as this command runs.
    Expose {
        #[arg(long, conflicts_with = "udp", required_unless_present = "udp")]
        tcp: Option<NonZeroU16>,
        #[arg(long, conflicts_with = "tcp", required_unless_present = "tcp")]
        udp: Option<NonZeroU16>,
        #[arg(long)]
        to: String,
        /// Forward to this HOST:PORT instead of loopback on the exposed port.
        #[arg(value_name = "HOST:PORT", value_parser = exposure_target)]
        target: Option<String>,
    },
    /// Open an interactive shell on a paired peer.
    Shell {
        peer: String,
        /// Request an administrator shell on Windows.
        #[arg(long)]
        elevated: bool,
    },
    /// Open stock SSH to a paired peer using its existing shell grant.
    #[cfg(any(unix, windows))]
    Ssh {
        #[arg(long)]
        replace_host_key: Option<String>,
        peer: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Replace this device's SSH host key and print its new fingerprint.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    SshRotateHostKey,
    #[cfg(any(unix, windows))]
    #[command(hide = true)]
    SshProxy { peer: String, client_key: String },
    /// Connect to a peer's shell or forwarded port.
    Connect {
        peer: Option<String>,
        /// shell, tcp:PORT, or udp:PORT. Defaults to shell.
        service: Option<Service>,
        /// Local UDP port to listen on. Defaults to the service's port.
        #[arg(long, value_name = "PORT", requires = "service")]
        listen: Option<u16>,
    },
}

pub async fn execute(state_dir: &Path, command: Command) -> Result<i32> {
    let dir = state_dir.join(DIR_NAME);
    match command {
        Command::Create {
            relay,
            bind,
            copy,
            name,
        } => {
            let (locator, token) = create(&dir, &relay_locator_input(relay)?, bind, name).await?;
            deliver_invite(&encode_invite(locator, &token)?, copy)?;
        }
        Command::Invite { copy } => invite(&dir, copy).await?,
        Command::RelayAccess { locator, bind } => {
            relay_access(&dir, &relay_locator_input(locator)?, bind).await?;
        }
        Command::Join { invite, name, bind } => {
            let (invite, name) = match (invite, name) {
                (Some(label), None)
                    if check_device_name(&label).is_ok() && !label.starts_with(INVITE_PREFIX) =>
                {
                    (None, Some(label))
                }
                (invite, name) => (invite, name),
            };
            join(&dir, invite, bind, name).await?;
        }
        Command::Run {
            shell,
            log_file,
            bind,
            sync_every,
        } => {
            diagnostics::start(state_dir);
            let ran = run(
                &dir,
                shell,
                log_file.unwrap_or_else(|| state_dir.join(super::audit::EVENT_FILE)),
                bind,
                sync_every,
            )
            .await;
            if ran.is_err() {
                // The caller prints the error on the console.
                diagnostics::quiet(
                    Level::Error,
                    "the runtime failed; run it in a terminal for details",
                );
            }
            return ran;
        }
        Command::Status => status(&dir).await?,
        Command::Rename {
            name_or_peer,
            new_name: None,
        } => rename_self(&dir, name_or_peer).await?,
        Command::Logs { follow, log_file } => {
            return diagnostics::show(state_dir, follow, log_file.as_deref()).await;
        }
        Command::Peers { full } => peers(&dir, full).await?,
        Command::Ping { peer, count } => return ping(&dir, &peer, count).await,
        Command::Approve {
            peer,
            alias,
            reapprove,
        } => {
            let (peer, suggested_alias) = approve_peer(&dir, &peer).await?;
            let alias = alias.unwrap_or(suggested_alias);
            let request = ControlRequest::Approve {
                peer,
                alias: alias.clone(),
                reapprove,
            };
            let ControlReply::Approved { key, fresh } = control(&dir, request).await? else {
                bail!("unexpected approval reply");
            };
            let note = if fresh { "" } else { " (unchanged)" };
            println!("Approved {key} as {}{note}", crate::visible(&alias));
            eprintln!("Pairing completes on the next connection with that device.");
        }
        Command::Rename {
            name_or_peer: peer,
            new_name: Some(new_name),
        } => {
            let request = ControlRequest::Rename {
                peer,
                alias: new_name.clone(),
            };
            let ControlReply::Changed(changed) = control(&dir, request).await? else {
                bail!("unexpected rename reply");
            };
            let alias = crate::visible(&new_name);
            if changed {
                println!("Renamed peer to {alias} on this device.");
            } else {
                println!("Peer is already named {alias} on this device.");
            }
        }
        Command::Decline { peer } => {
            let peer = peer_key(&dir, &peer).await?;
            control(&dir, ControlRequest::Decline { peer }).await?;
            println!("Declined locally.");
        }
        Command::Revoke { peer } => {
            let peer = peer_key(&dir, &peer).await?;
            let ControlReply::CutOff {
                pairing_error,
                removal_error,
            } = control(&dir, ControlRequest::Revoke { peer }).await?
            else {
                bail!("unexpected cutoff reply");
            };
            println!("Cut off locally; its sessions on this device have ended.");
            if let Some(e) = pairing_error {
                eprintln!("massrelay: the declined pairing was not saved: {e}");
            }
            match removal_error {
                None => eprintln!("The network removal is staged; the runtime publishes it."),
                Some(e) => eprintln!("massrelay: the network removal was not staged: {e}"),
            }
        }
        Command::Enable { service, peer } => change(&dir, service, peer, true).await?,
        Command::Disable { service, peer } => change(&dir, service, peer, false).await?,
        Command::List { full } => list(&dir, full).await?,
        Command::Expose {
            tcp,
            udp,
            to,
            target,
        } => {
            let service = match (tcp, udp) {
                (Some(port), None) => Service::Tcp(port),
                (None, Some(port)) => Service::Udp(port),
                _ => bail!("choose one of --tcp or --udp"),
            };
            runtime::expose(&dir, service, peer_key(&dir, &to).await?, target).await?;
        }
        Command::Shell { peer, elevated } => {
            return runtime::shell(&dir, peer_key(&dir, &peer).await?, elevated).await;
        }
        #[cfg(any(unix, windows))]
        Command::Ssh {
            peer,
            replace_host_key,
            command,
        } => {
            return super::ssh::launch_ssh(
                &dir,
                peer_key(&dir, &peer).await?,
                replace_host_key.as_deref(),
                command,
            )
            .await;
        }
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        Command::SshRotateHostKey => {
            ensure!(profile_exists(state_dir), "no private MassRelay profile");
            println!("{}", super::ssh::rotate_host_key(&dir).await?);
        }
        #[cfg(any(unix, windows))]
        Command::SshProxy { peer, client_key } => {
            super::ssh::proxy(&dir, peer, &client_key).await?;
        }
        Command::Connect {
            peer,
            service,
            listen,
        } => {
            let peer = match peer {
                Some(peer) => peer_key(&dir, &peer).await?,
                None => match pick_peer(&dir).await? {
                    Some(peer) => peer,
                    None => return Ok(0),
                },
            };
            match service.unwrap_or(Service::Shell) {
                Service::Shell => {
                    ensure!(listen.is_none(), "--listen applies to udp services");
                    return runtime::shell(&dir, peer, false).await;
                }
                service => runtime::connect(&dir, peer, service, listen).await?,
            }
        }
    }
    Ok(0)
}

// ------------------------------------------------------------------ profile

#[derive(Clone, Serialize, Deserialize)]
struct Profile {
    format: String,
    /// This device's endpoint secret key.
    key: Bytes<32>,
    locator: Locator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    udp_port: Option<u16>,
}

impl Profile {
    fn secret(&self) -> SecretKey {
        SecretKey::from_bytes(&self.key.0)
    }

    fn mailbox(&self, bind: SocketAddr) -> Result<RelayMailbox> {
        let server = &self.locator.server;
        RelayMailbox::start(
            server.dial(true),
            self.locator.incarnation(),
            self.locator.access,
            SocketAddr::new(bind.ip(), 0),
            Some(server.relay.clone()),
        )
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub fn check_enrolled(state_dir: &Path) -> Result<()> {
    let dir = state_dir.join(DIR_NAME);
    load(&dir)?;
    let state = Device::open(&dir, Offline, Clock::System)
        .and_then(|device| device.state())
        .map_err(membership)?;
    ensure!(
        state.net.is_some() && state.terminal.is_none(),
        "join a network before installing the device service"
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub fn claim_owner(state_dir: &Path) -> Result<Owner> {
    Owner::acquire(&state_dir.join(DIR_NAME)).map_err(|error| anyhow!("{error:?}"))
}

/// The candidate's side of an update's preflight: read this profile the way `status` does,
/// writing nothing, and check the pinned relay from a throwaway identity on a temporary
/// endpoint. Returns the device's endpoint ID. Never listens with the device's identity.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub async fn check_profile_for_update(state_dir: &Path) -> Result<String> {
    let dir = state_dir.join(DIR_NAME);
    let profile = load(&dir)?;
    let path = dir.clone();
    let view = blocking(move || {
        let device = Device::open(&path, Offline, Clock::System).map_err(membership)?;
        let state = device.state().map_err(membership)?;
        ensure!(
            state.net.is_some() && state.terminal.is_none(),
            "this device is not an enrolled member"
        );
        runtime::offline_status(&device).map_err(|e| anyhow!("{e:?}"))
    })
    .await??;
    let endpoint = hex(profile.secret().public().as_bytes());
    ensure!(
        view.endpoint == endpoint,
        "the profile's key and its membership state name different devices"
    );
    let bind = SocketAddr::from(([0, 0, 0, 0], 0));
    tokio::time::timeout(Duration::from_secs(40), check_relay(&profile.locator, bind))
        .await
        .context("the pinned relay did not answer in time")??;
    Ok(endpoint)
}

pub fn profile_exists(state_dir: &Path) -> bool {
    state_dir.join(DIR_NAME).join(PROFILE_FILE).is_file()
}

fn load(dir: &Path) -> Result<Profile> {
    ensure!(
        dir.join(PROFILE_FILE).try_exists()?,
        "no device profile in {}; run 'massrelay create' or 'massrelay join'",
        dir.display()
    );
    let profile: Profile = crate::storage::load(dir, PROFILE_FILE)?;
    ensure!(
        profile.format == PROFILE_FORMAT,
        "unsupported device profile format {:?}",
        profile.format
    );
    Ok(profile)
}

/// Create the private directory (owner-only) and take its runtime owner, so no runtime or
/// other setup command runs on it meanwhile.
fn claim(dir: &Path) -> Result<Owner> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    Owner::acquire(dir).map_err(|e| match e {
        PairError::OwnedElsewhere => {
            anyhow!("the runtime or another command is using this profile")
        }
        e => anyhow!("{e:?}"),
    })
}

/// A profile being set up: either a new one, or the saved one of an interrupted setup with the
/// same locator (its store not yet created).
fn setup_profile(dir: &Path, locator: &Locator) -> Result<(Profile, bool)> {
    if dir.join(PROFILE_FILE).try_exists()? {
        let saved = load(dir)?;
        ensure!(
            saved.locator.encode()? == locator.encode()?,
            "{} already holds a device profile for another relay; it was not changed",
            dir.display()
        );
        return Ok((saved, false));
    }
    Ok((
        Profile {
            format: PROFILE_FORMAT.into(),
            key: Bytes(wire::random()?),
            locator: locator.clone(),
            udp_port: None,
        },
        true,
    ))
}

/// Check over the relay's authenticated identity that it admits the locator's access credential
/// and serves its incarnation, from a throwaway transport identity.
async fn check_relay(locator: &Locator, bind: SocketAddr) -> Result<()> {
    let endpoint = crate::bind_endpoint(
        SecretKey::from_bytes(&wire::random()?),
        SocketAddr::new(bind.ip(), 0),
        Some(locator.server.relay.clone()),
        CHECK_ALPN,
        false,
    )
    .await?;
    let checked = async {
        let client = Client::connect(&endpoint, locator.server.dial(true), &locator.access)
            .await
            .map_err(|error| match error.downcast::<mailbox::NotAdmitted>() {
                Ok(refused) => anyhow!("{refused}; nothing was changed"),
                Err(error) => error.context("could not reach the relay"),
            })?;
        let served = client.incarnation().await?;
        ensure!(
            served == locator.incarnation(),
            "the relay now serves another storage incarnation than its locator; \
             nothing was changed"
        );
        Ok(())
    }
    .await;
    endpoint.close().await;
    checked
}

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .context("background task failed")
}

fn membership(e: MembershipError) -> anyhow::Error {
    anyhow!("{e:?}")
}

// ------------------------------------------------------------------- create

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
    let label = &label[..label.len().min(63)];
    (!label.eq_ignore_ascii_case("localhost") && check_device_name(label).is_ok())
        .then(|| label.to_owned())
}

fn relay_locator_input(argument: Option<String>) -> Result<String> {
    if let Some(argument) = argument {
        return Ok(argument);
    }
    if io::stdin().is_terminal() {
        eprintln!("Paste the relay locator:");
    }
    let mut locator = String::new();
    io::stdin().read_line(&mut locator)?;
    ensure!(!locator.trim().is_empty(), "a relay locator is required");
    Ok(locator)
}

async fn create(
    dir: &Path,
    relay: &str,
    bind: SocketAddr,
    name: Option<String>,
) -> Result<(Locator, Vec<u8>)> {
    if let Some(name) = &name {
        check_device_name(name).map_err(|error| anyhow!("{error}"))?;
    }
    let locator = Locator::decode(relay)?;
    let owner = claim(dir)?;
    ensure!(
        !store::initialized(dir),
        "{} already holds a device profile; it was not changed",
        dir.display()
    );
    let (profile, fresh) = setup_profile(dir, &locator)?;
    let name = name.unwrap_or_else(|| default_name(profile.secret().public()));
    check_relay(&locator, bind).await?;
    if fresh {
        // Saved before the store, so an interrupted create resumes with the same identity.
        crate::storage::save(dir, PROFILE_FILE, &profile)?;
    }
    let (path, key) = (dir.to_path_buf(), profile.key.0);
    let relay_key = *locator.server.id.as_bytes();
    let incarnation = locator.incarnation.0.to_vec();
    let token = blocking(move || {
        Device::create_network_named(
            &path,
            &EndpointSecret::from_bytes(&key),
            relay_key,
            incarnation,
            Offline,
            Clock::System,
            Some(&name),
        )
        .and_then(|device| device.issue_invite())
    })
    .await?
    .map_err(membership)?;
    drop(owner);
    eprintln!("Created the network. Run 'massrelay run' to accept the invite.");
    Ok((locator, token))
}

// ------------------------------------------------------------- relay access

/// Whether two locators pin the same relay identity, addresses and storage incarnation; only
/// the access credential may differ.
fn same_relay(a: &Locator, b: &Locator) -> bool {
    a.server.id == b.server.id
        && a.server.udp == b.server.udp
        && a.server.relay == b.server.relay
        && a.incarnation == b.incarnation
}

async fn relay_access(dir: &Path, text: &str, bind: SocketAddr) -> Result<()> {
    let locator = Locator::decode(text)?;
    load(dir)?;
    let owner = claim(dir)?;
    let mut profile = load(dir)?;
    ensure!(
        same_relay(&profile.locator, &locator),
        "that locator names another relay, address or storage incarnation than this profile \
         pins; only the access credential can be replaced, and nothing was changed"
    );
    check_relay(&locator, bind).await?;
    profile.locator = locator;
    crate::storage::save(dir, PROFILE_FILE, &profile)?;
    drop(owner);
    eprintln!("Relay access credential replaced. Start 'massrelay run' again to use it.");
    Ok(())
}

// ------------------------------------------------------------------- invite

/// The copy/paste join envelope: the relay locator and the exact invite bytes.
#[derive(Serialize, Deserialize)]
struct InviteEnvelope {
    format: String,
    locator: Locator,
    invite: String,
}

impl InviteEnvelope {
    fn encode(&self) -> Result<String> {
        Ok(format!(
            "{INVITE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?)
        ))
    }

    /// Decode and check that the locator pins exactly the relay and incarnation the invite
    /// names. Returns the locator and the exact invite bytes.
    fn open(text: &str) -> Result<(Locator, Vec<u8>)> {
        let encoded = text
            .trim()
            .strip_prefix(INVITE_PREFIX)
            .context("expected an invite starting with mrprivinv0_")?;
        let envelope: Self =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).context("invalid invite")?)
                .context("invalid invite")?;
        ensure!(
            envelope.format == INVITE_FORMAT,
            "unsupported invite format {:?}",
            envelope.format
        );
        mailbox::refuse_userinfo(&envelope.locator.server.relay)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&envelope.invite)
            .context("invalid invite")?;
        matches(&envelope.locator, &bytes)?;
        Ok((envelope.locator, bytes))
    }
}

/// The invite inside must name the locator's relay key and storage incarnation.
fn matches(locator: &Locator, invite: &[u8]) -> Result<()> {
    let token = InviteToken::decode(invite).map_err(|e| anyhow!("invalid invite: {e:?}"))?;
    ensure!(
        token.relay_key == *locator.server.id.as_bytes(),
        "the invite names another relay than its locator; nothing was sent"
    );
    ensure!(
        token.incarnation == locator.incarnation.0,
        "the invite names another storage incarnation than its locator; nothing was sent"
    );
    Ok(())
}

fn encode_invite(locator: Locator, bytes: &[u8]) -> Result<String> {
    matches(&locator, bytes)?;
    InviteEnvelope {
        format: INVITE_FORMAT.into(),
        locator,
        invite: URL_SAFE_NO_PAD.encode(bytes),
    }
    .encode()
}

async fn invite(dir: &Path, copy: bool) -> Result<()> {
    let profile = load(dir)?;
    let ControlReply::Invite(token) = control(dir, ControlRequest::Invite).await? else {
        bail!("unexpected invite reply");
    };
    let bytes = unhex(&token).context("invalid invite from the runtime")?;
    deliver_invite(&encode_invite(profile.locator, &bytes)?, copy)
}

fn deliver_invite(invite: &str, copy: bool) -> Result<()> {
    if copy {
        let mut command = clipboard_command()?;
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context(
                "open the clipboard helper; use the command without --copy to print the invite",
            )?;
        let written = child
            .stdin
            .take()
            .expect("piped clipboard input")
            .write_all(invite.as_bytes());
        let result = child.wait()?;
        written.context("write the invite to the clipboard")?;
        anyhow::ensure!(result.success(), "clipboard helper failed ({result})");
        eprintln!("Invite copied. Run 'massrelay join' on the other device and paste it there.");
    } else if io::stdout().is_terminal() {
        eprintln!("On the other device, run 'massrelay join' and paste the invite below.");
        println!("{invite}");
    } else {
        println!("{invite}");
        return Ok(());
    }
    eprintln!("The invite works once and expires in ten minutes.");
    Ok(())
}

fn clipboard_command() -> Result<Process> {
    #[cfg(target_os = "macos")]
    return Ok(Process::new("/usr/bin/pbcopy"));
    #[cfg(windows)]
    return Ok(Process::new("clip.exe"));
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            return Ok(Process::new("wl-copy"));
        }
        if std::env::var_os("DISPLAY").is_some() {
            let mut command = Process::new("xclip");
            command.args(["-selection", "clipboard"]);
            return Ok(command);
        }
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    bail!("clipboard copy needs a desktop session; run 'massrelay invite' to print the invite");
}

// --------------------------------------------------------------------- join

async fn join(
    dir: &Path,
    argument: Option<String>,
    bind: SocketAddr,
    name: Option<String>,
) -> Result<()> {
    if let Some(name) = &name {
        check_device_name(name).map_err(|error| anyhow!("{error}"))?;
    }
    let owner = claim(dir)?;
    let saved = if store::initialized(dir) {
        let path = dir.to_path_buf();
        let st = blocking(move || Device::open(&path, Offline, Clock::System)?.state())
            .await?
            .map_err(membership)?;
        ensure!(
            st.net.is_none(),
            "this device is already a member; run 'massrelay run'"
        );
        ensure!(
            st.terminal.is_none() && st.halt.is_none(),
            "this device already has a membership profile; run 'massrelay status'"
        );
        Some((load(dir)?, st.pending_join))
    } else {
        None
    };
    let profile = if let Some((profile, Some(pending))) = saved {
        if let Some(text) = argument {
            let (_, bytes) = InviteEnvelope::open(&text)?;
            ensure!(
                bytes == pending.token,
                "another join is pending on this profile; run 'massrelay join' without \
                 an invite to resume it"
            );
        }
        profile
    } else {
        let text = match argument {
            Some(text) => text,
            None => read_invite()?,
        };
        let (locator, bytes) = InviteEnvelope::open(&text)?;
        let (profile, save) = if let Some((mut profile, None)) = saved {
            profile.locator = locator.clone();
            (profile, true)
        } else {
            setup_profile(dir, &locator)?
        };
        let name = name.unwrap_or_else(|| default_name(profile.secret().public()));
        check_relay(&locator, bind).await?;
        if save {
            crate::storage::save(dir, PROFILE_FILE, &profile)?;
        }
        let (path, key) = (dir.to_path_buf(), profile.key.0);
        // Persists the exact request before anything is sent.
        blocking(move || {
            Device::begin_join_named(
                &path,
                &EndpointSecret::from_bytes(&key),
                &bytes,
                Offline,
                Clock::System,
                Some(&name),
            )
            .map(drop)
        })
        .await?
        .map_err(membership)?;
        profile
    };
    let mailbox = {
        let p = profile.clone();
        blocking(move || p.mailbox(bind)).await??
    };
    let path = dir.to_path_buf();
    let device = Arc::new(
        blocking(move || Device::open(&path, mailbox, Clock::System))
            .await?
            .map_err(membership)?,
    );
    let waiting = wait_for_reply(device);
    tokio::select! {
        r = waiting => r?,
        r = crate::shutdown() => {
            r?;
            bail!("stopped waiting; run 'massrelay join' to resume this join");
        }
    }
    drop(owner);
    eprintln!("Joined the network. Run 'massrelay run' next.");
    println!("{}", hex(profile.secret().public().as_bytes()));
    Ok(())
}

fn read_invite() -> Result<String> {
    if io::stdin().is_terminal() {
        eprint!("Paste the invite: ");
        io::stderr().flush()?;
    }
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line)
}

/// Append the exact persisted request until the relay holds it, then read the issuer's reply
/// until it arrives. Unknown delivery is retried with the same bytes; nothing is retried that
/// the relay definitively refused.
async fn wait_for_reply(device: Arc<Device<RelayMailbox>>) -> Result<()> {
    let mut sent = false;
    let mut last_note = String::new();
    let mut note = |text: String| {
        if text != last_note {
            eprintln!("massrelay: {text}");
            last_note = text;
        }
    };
    loop {
        if !sent {
            let d = device.clone();
            match blocking(move || d.send_join_request()).await? {
                Ok(CreateOutcome::Created | CreateOutcome::ExactRetry) => {
                    sent = true;
                    eprintln!(
                        "Join request sent. Waiting for the inviting device's runtime to \
                         admit this device; Ctrl-C stops waiting and 'massrelay join' \
                         resumes."
                    );
                }
                Ok(other) => note(format!(
                    "the relay could not take the request ({other:?}); retrying"
                )),
                Err(MembershipError::Mailbox(MailboxError::Refused(why))) => {
                    bail!("the relay refused the join request: {why}")
                }
                Err(MembershipError::Mailbox(e)) => note(format!(
                    "the join request is not confirmed ({e:?}); retrying the same request"
                )),
                Err(e) => return Err(membership(e)),
            }
        }
        if sent {
            let d = device.clone();
            match blocking(move || d.complete_join()).await? {
                Ok(()) => return Ok(()),
                Err(MembershipError::Join(JoinError::Waiting)) => {}
                Err(MembershipError::Join(JoinError::InviteUsed)) => bail!(
                    "this invite was used by another device; run 'massrelay join' with a fresh invite"
                ),
                Err(MembershipError::Mailbox(e)) => {
                    note(format!("the reply could not be read ({e:?}); retrying"))
                }
                Err(e) => return Err(membership(e)),
            }
        }
        tokio::time::sleep(JOIN_POLL).await;
    }
}

// ---------------------------------------------------------------------- run

async fn run(
    dir: &Path,
    shell: Option<PathBuf>,
    log_file: PathBuf,
    bind: SocketAddr,
    sync_every: u64,
) -> Result<i32> {
    let mut profile = load(dir)?;
    ensure!(sync_every > 0, "--sync-every must be at least one second");
    // A duplicate must not use this profile's key to register at the relay.
    let owner = Owner::acquire(dir).map_err(|e| match e {
        PairError::OwnedElsewhere => {
            anyhow!("a runtime is already running on this profile")
        }
        e => anyhow!("{e:?}"),
    })?;
    {
        let path = dir.to_path_buf();
        let st = blocking(move || Device::open(&path, Offline, Clock::System)?.state())
            .await?
            .map_err(membership)?;
        ensure!(
            st.net.is_some(),
            "this device has not finished joining; run 'massrelay join' first"
        );
    }
    let relay = profile.locator.server.relay.clone();
    let bind_device = |addr| {
        crate::bind_endpoint(
            profile.secret(),
            addr,
            Some(relay.clone()),
            SERVICE_ALPN,
            true,
        )
    };
    let mut preferred = bind;
    if bind.port() == 0 {
        preferred.set_port(profile.udp_port.unwrap_or(0));
    }
    let endpoint = match bind_device(preferred).await {
        Err(error) if preferred != bind => {
            diagnostics::quiet(Level::Warning, "could not reuse the previous UDP port");
            if diagnostics::console() {
                eprintln!(
                    "massrelay: could not reuse UDP port {}: {error}",
                    preferred.port()
                );
            }
            bind_device(bind).await?
        }
        result => result?,
    };
    let actual = endpoint.bound_sockets().first().map(SocketAddr::port);
    if profile.udp_port != actual {
        profile.udp_port = actual;
        crate::storage::save(dir, PROFILE_FILE, &profile)?;
    }
    let mailbox = {
        let p = profile.clone();
        blocking(move || p.mailbox(bind)).await??
    };
    let mut config = Config::new(dir);
    config.shell = shell;
    config.log_file = Some(log_file);
    config.sync_every = Some(Duration::from_secs(sync_every));
    config.addresses = Arc::new(move |key| {
        EndpointId::from_bytes(key)
            .ok()
            .map(|id| EndpointAddr::new(id).with_relay_url(relay.clone()))
    });
    let runtime = Runtime::start_owned(config, mailbox, Clock::System, endpoint.clone(), owner)
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    diagnostics::quiet(
        Level::Info,
        format!(
            "the runtime started (massrelay {})",
            env!("CARGO_PKG_VERSION")
        ),
    );
    // The console names this device and its audit file; the system log, which other accounts
    // can read, does not.
    if diagnostics::console() {
        if let Some(log_file) = runtime.log_file() {
            eprintln!("MassRelay event log at {}", log_file.display());
        }
        eprintln!(
            "MassRelay runtime running as {}",
            hex(endpoint.id().as_bytes())
        );
        eprintln!("Press Ctrl-C to stop.");
    }
    // A runtime that an update retired serves nothing and ends itself here, by the same
    // ordered stop. Nothing outside it is asked to stop it.
    let retired = runtime.retired();
    let signal = tokio::select! {
        signal = crate::shutdown() => Some(signal),
        _ = retired.notified() => None,
    };
    let stopped = runtime.stop().await;
    if !stopped.aborted.is_empty() {
        diagnostics::event(
            Level::Warning,
            format!("stopped without waiting for: {:?}", stopped.aborted),
        );
    }
    if stopped.native_workers > 0 {
        diagnostics::event(
            Level::Warning,
            format!(
                "{} shell cleanup worker(s) still running",
                stopped.native_workers
            ),
        );
    }
    if !stopped.owner_released {
        diagnostics::event(
            Level::Warning,
            "a membership call or shell cleanup is still running; the profile stays owned \
             until it finishes or this process exits",
        );
    } else if diagnostics::console() {
        eprintln!("Stopped; the profile is released.");
    }
    diagnostics::quiet(Level::Info, "the runtime stopped");
    match signal {
        Some(signal) => {
            signal?;
            Ok(0)
        }
        // Under the Windows service manager a clean stop is never started again, and the
        // updater starts the service once the program is replaced.
        None if cfg!(windows) => Ok(0),
        // Elsewhere the program is already replaced under this process. Ending with a
        // failure status makes a service manager that restarts failed services (systemd's
        // `Restart=on-failure`, launchd's `KeepAlive`) start it, even if the updater is gone.
        None => {
            diagnostics::quiet(
                Level::Info,
                "retired for an update; ending so that the installed program takes over",
            );
            Ok(RETIRED_EXIT)
        }
    }
}

// ------------------------------------------------------------ status, peers

async fn control(dir: &Path, request: ControlRequest) -> Result<ControlReply> {
    load(dir)?;
    runtime::command(dir, request).await
}

async fn rename_self(dir: &Path, name: String) -> Result<()> {
    load(dir)?;
    check_device_name(&name).map_err(anyhow::Error::msg)?;
    let path = dir.to_path_buf();
    let new_name = name.clone();
    let saved_offline = blocking(move || {
        let _owner = match Owner::acquire(&path) {
            Ok(owner) => owner,
            Err(PairError::OwnedElsewhere) => return Ok(false),
            Err(error) => return Err(anyhow!("{error:?}")),
        };
        let device = Device::open(&path, Offline, Clock::System).map_err(membership)?;
        versions::rename_self(&device, &new_name)?;
        Ok::<_, anyhow::Error>(true)
    })
    .await??;
    if !saved_offline {
        let reply =
            runtime::command(dir, ControlRequest::RenameSelf { name: name.clone() }).await?;
        ensure!(reply == ControlReply::Done, "unexpected rename reply");
    }
    println!("Renamed this device to {}", crate::visible(&name));
    Ok(())
}

/// The running runtime's view, or a read-only one when it is not running.
async fn current_view(dir: &Path) -> Result<runtime::StatusView> {
    if dir.join(CONTROL.marker).try_exists()? {
        let ControlReply::Status(view) = runtime::command(dir, ControlRequest::Status).await?
        else {
            bail!("unexpected status reply");
        };
        return Ok(view);
    }
    let path = dir.to_path_buf();
    blocking(move || {
        let device = Device::open(&path, Offline, Clock::System).map_err(membership)?;
        runtime::offline_status(&device).map_err(|e| anyhow!("{e:?}"))
    })
    .await?
}

async fn status(dir: &Path) -> Result<()> {
    let profile = load(dir)?;
    let path = dir.to_path_buf();
    let st = blocking(move || Device::open(&path, Offline, Clock::System)?.state())
        .await?
        .map_err(membership)?;
    let endpoint = hex(profile.secret().public().as_bytes());
    if st.net.is_some() {
        let name = match versions::local_display_name(dir).ok().flatten() {
            Some(name) => Some(name),
            None => roster_name(&named_roster(dir).await?, &endpoint).map(str::to_owned),
        };
        if let Some(name) = name {
            println!("Name: {}", crate::visible(&name));
        }
    }
    println!("Endpoint: {endpoint}");
    println!("Client version: {}", env!("CARGO_PKG_VERSION"));
    println!(
        "Relay: {} incarnation {}",
        profile.locator.server.id,
        hex(&profile.locator.incarnation.0)
    );
    if let Some(pending) = &st.pending_join {
        match &pending.halted {
            Some(h) => println!("Membership: join halted: {}", crate::visible(h)),
            None => println!("Membership: join pending; run 'massrelay join' to resume"),
        }
        return Ok(());
    }
    if st.terminal.is_some() {
        // A removed device keeps no peers or services; its runtime refuses every command.
        let running = dir.join(CONTROL.marker).try_exists()?;
        println!(
            "Runtime: {}",
            if running { "running" } else { "not running" }
        );
        println!("Membership: this device was removed");
        return Ok(());
    }
    if st.net.is_none() {
        println!("Membership: not joined; run 'massrelay join' with a fresh invite");
        return Ok(());
    }
    let view = current_view(dir).await?;
    if view.running {
        println!(
            "Runtime: running (version {})",
            view.version.as_deref().unwrap_or("unknown")
        );
    } else {
        println!("Runtime: not running");
    }
    let members = view.peers.iter().filter(|p| p.member).count() + 1;
    match &view.halt {
        Some(h) => println!("Membership: halted: {}", crate::visible(h)),
        None => println!(
            "Membership: {members} members, epoch {}",
            st.net.map_or(0, |n| n.epoch)
        ),
    }
    let mut versions = vec![["PEER", "VERSION", "REPORTED (UTC)"].map(String::from)];
    for peer in view.peers.iter().filter(|peer| peer.member) {
        let label = peer.alias.as_deref().unwrap_or(&peer.key);
        let (version, observed) = match &peer.version {
            Some(report) => (
                report.version.as_str(),
                i64::try_from(report.observed_at)
                    .ok()
                    .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
                    .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "-".into()),
            ),
            None => ("unknown", "-".into()),
        };
        versions.push([crate::visible(label), crate::visible(version), observed]);
    }
    if versions.len() > 1 {
        crate::print_table(&versions, io::stdout().is_terminal());
    }
    let list = |services: &[Service]| {
        if services.is_empty() {
            "none".to_string()
        } else {
            services
                .iter()
                .map(Service::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    println!("Defaults: {}", list(&view.defaults));
    for (key, service) in &view.grants {
        println!("Grant: {service} to {key}");
    }
    for (key, service) in &view.exclusions {
        println!("Excluded from default: {service} for {key}");
    }
    if view.running {
        println!("Active connections: {}", view.connections.len());
        if !view.connections.is_empty() {
            use super::audit::Route;
            use crate::connection_log::Direction;

            let mut rows = vec![["DIRECTION", "PEER", "SERVICE", "ROUTE"].map(String::from)];
            rows.extend(view.connections.iter().map(|connection| {
                let peer = view
                    .peers
                    .iter()
                    .find(|peer| peer.key == connection.key)
                    .and_then(|peer| peer.alias.as_deref())
                    .unwrap_or(&connection.key);
                [
                    match connection.direction {
                        Direction::Inbound => "inbound",
                        Direction::Outbound => "outbound",
                    }
                    .into(),
                    crate::visible(peer),
                    connection.service.to_string(),
                    match connection.route {
                        Route::Direct => "direct",
                        Route::Relayed => "via relay",
                        Route::Unknown => "unknown",
                    }
                    .into(),
                ]
            }));
            crate::print_table(&rows, io::stdout().is_terminal());
        }
        println!(
            "Temporary exposures: {} (see 'massrelay list')",
            view.exposures.len()
        );
    }
    if let Some(last) = &view.last_sync {
        println!("Last membership pass: {}", crate::visible(last));
    }
    Ok(())
}

async fn named_roster(dir: &Path) -> Result<Vec<RosterMember>> {
    let path = dir.to_path_buf();
    blocking(
        move || match Device::open(&path, Offline, Clock::System)?.named_roster() {
            Err(MembershipError::NotMember | MembershipError::Terminal) => Ok(Vec::new()),
            result => result,
        },
    )
    .await?
    .map_err(membership)
}

fn parse_endpoint(selector: &str) -> Option<EndpointId> {
    selector.parse().ok()
}

async fn selected_peer(dir: &Path, selector: &str) -> Result<(PeerMatch, Option<String>)> {
    let view = current_view(dir).await?;
    let aliases: Vec<_> = view
        .peers
        .iter()
        .filter_map(|p| Some((p.alias.clone()?, *parse_endpoint(&p.key)?.as_bytes())))
        .collect();
    let roster = named_roster(dir).await?;
    let mut names: Vec<_> = roster
        .iter()
        .filter(|member| {
            let key = hex(&member.endpoint);
            key == view.endpoint || view.peers.iter().any(|p| p.member && p.key == key)
        })
        .cloned()
        .collect();
    // An authenticated report adds a name for its sender. Keep signed names
    // reserved so a reported name cannot silently move a selector to another peer.
    names.extend(
        view.peers
            .iter()
            .filter(|peer| peer.member)
            .filter_map(|peer| {
                Some(RosterMember {
                    endpoint: *parse_endpoint(&peer.key)?.as_bytes(),
                    name: Some(peer.reported_name()?.to_owned()),
                })
            }),
    );
    if let (Some(endpoint), Ok(Some(name))) = (
        parse_endpoint(&view.endpoint),
        versions::local_display_name(dir),
    ) {
        names.push(RosterMember {
            endpoint: *endpoint.as_bytes(),
            name: Some(name),
        });
    }
    let selected = select_peer(
        selector,
        parse_endpoint(selector).map(|key| *key.as_bytes()),
        &aliases,
        &names,
    )
    .map_err(|error| match error {
        SelectError::NoMatch => anyhow!("no peer pinned or named {selector:?}"),
        SelectError::AmbiguousName(keys) | SelectError::AmbiguousAlias(keys) => {
            let keys = keys
                .iter()
                .map(|key| hex(key))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow!("{selector:?} names multiple devices; use an endpoint ID: {keys}")
        }
    })?;
    let key = selected.endpoint();
    let label = aliases
        .into_iter()
        .find_map(|(alias, endpoint)| (endpoint == key).then_some(alias))
        .or_else(|| {
            let peer = view.peers.iter().find(|peer| peer.key == hex(&key))?;
            peer_name(peer, &roster).map(str::to_owned)
        });
    Ok((selected, label))
}

async fn peer_key(dir: &Path, selector: &str) -> Result<String> {
    if let Some(key) = parse_endpoint(selector) {
        return Ok(hex(key.as_bytes()));
    }
    Ok(hex(&selected_peer(dir, selector).await?.0.endpoint()))
}

async fn ping(dir: &Path, peer: &str, count: u16) -> Result<i32> {
    let key = peer_key(dir, peer).await?;
    let (mut socket, reply) = runtime::request(
        dir,
        ControlRequest::Ping {
            peer: key,
            count,
            include_route: true,
        },
    )
    .await?;
    match reply {
        ControlReply::PingStarted => {}
        ControlReply::Error(e) => bail!("{e}"),
        _ => bail!("unexpected ping reply"),
    }
    let peer = crate::visible(peer);
    println!("PING {peer}");
    let mut sent = 0;
    let mut received = 0;
    let mut min = f64::INFINITY;
    let mut max = 0.0_f64;
    let mut sum = 0.0;
    let interrupt = crate::shutdown();
    tokio::pin!(interrupt);
    loop {
        let reply = tokio::select! {
            r = &mut interrupt => { r?; break; }
            r = wire::recv(&mut socket) => r?,
        };
        let (micros, route) = match reply {
            ControlReply::PingSampleWithRoute { micros, route } => (micros, route),
            ControlReply::PingSample(Some(micros)) => (micros, PingRoute::Unknown),
            ControlReply::PingSample(None) => {
                sent += 1;
                println!("request timed out: seq={sent}");
                continue;
            }
            ControlReply::Done => break,
            ControlReply::Error(e) => bail!("{e}"),
            _ => bail!("unexpected ping reply"),
        };
        sent += 1;
        received += 1;
        let ms = micros as f64 / 1000.0;
        min = min.min(ms);
        max = max.max(ms);
        sum += ms;
        let route = match route {
            PingRoute::Direct(addr) => format!("direct {addr}"),
            PingRoute::Relayed => "via relay".into(),
            PingRoute::Unknown => "unknown".into(),
        };
        println!("reply from {peer}: seq={sent} time={ms:.3} ms {route}");
    }
    println!("--- {peer} ping statistics ---");
    let loss = if sent > 0 {
        100.0 * f64::from(sent - received) / f64::from(sent)
    } else {
        0.0
    };
    println!("{sent} packets transmitted, {received} received, {loss:.1}% packet loss");
    if received > 0 {
        println!(
            "rtt min/avg/max = {min:.3}/{:.3}/{max:.3} ms",
            sum / f64::from(received)
        );
    }
    Ok(i32::from(received == 0))
}

async fn approve_peer(dir: &Path, selector: &str) -> Result<(String, String)> {
    let (selected, label) = selected_peer(dir, selector).await?;
    let key = hex(&selected.endpoint());
    if !selected.pinned() {
        ensure!(
            io::stdin().is_terminal(),
            "approve using the verified endpoint ID {key}"
        );
        eprintln!(
            "Run 'massrelay status' on {} and compare its endpoint ID:",
            crate::visible(selector)
        );
        eprintln!("{key}");
        eprint!("Approve this device? [y/N] ");
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        ensure!(
            answer.trim().eq_ignore_ascii_case("y"),
            "approval cancelled"
        );
    }
    Ok((
        key.clone(),
        label.unwrap_or_else(|| format!("device-{}", &key[..8])),
    ))
}

async fn pick_peer(dir: &Path) -> Result<Option<String>> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "use 'massrelay connect PEER [SERVICE]'"
    );
    let roster = named_roster(dir).await?;
    let mut peers: Vec<PeerView> = current_view(dir)
        .await?
        .peers
        .into_iter()
        .filter(|p| p.member && p.local == "approved")
        .collect();
    peers.sort_by_cached_key(|p| p.alias.as_deref().unwrap_or(&p.key).to_ascii_lowercase());
    if peers.is_empty() {
        eprintln!("No approved devices. Run 'massrelay peers' to check approvals.");
        return Ok(None);
    }
    for (index, peer) in peers.iter().enumerate() {
        let alias = peer
            .alias
            .as_deref()
            .or_else(|| peer_name(peer, &roster))
            .unwrap_or(&peer.key);
        eprintln!("  {}  {}", index + 1, crate::visible(alias));
    }
    eprint!("Choose a device number, or press Enter to cancel: ");
    io::stderr().flush()?;
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();
    if choice.is_empty() {
        return Ok(None);
    }
    let peer = choice
        .parse::<usize>()
        .ok()
        .and_then(|number| number.checked_sub(1))
        .and_then(|index| peers.get(index))
        .context("choose a device number from the list")?;
    Ok(Some(peer.key.clone()))
}

async fn peers(dir: &Path, full: bool) -> Result<()> {
    load(dir)?;
    let view = current_view(dir).await?;
    let roster = named_roster(dir).await?;
    let terminal = io::stdout().is_terminal();
    let mut rows = vec![
        [
            "ENDPOINT", "NAME", "ALIAS", "MEMBER", "LOCAL", "REMOTE", "PAIRED",
        ]
        .map(String::from),
    ];
    rows.extend(view.peers.into_iter().map(|mut p: PeerView| {
        let name = peer_name(&p, &roster).unwrap_or("-").to_owned();
        if terminal && !full {
            p.key.truncate(8);
        }
        [
            p.key,
            name,
            p.alias.map_or_else(|| "-".into(), |a| crate::visible(&a)),
            yes(p.member),
            p.local,
            p.remote,
            yes(p.paired),
        ]
    }));
    crate::print_table(&rows, terminal);
    Ok(())
}

fn peer_name<'a>(peer: &'a PeerView, roster: &'a [RosterMember]) -> Option<&'a str> {
    peer.reported_name()
        .or_else(|| roster_name(roster, &peer.key))
}

fn roster_name<'a>(roster: &'a [RosterMember], key: &str) -> Option<&'a str> {
    let endpoint = parse_endpoint(key)?;
    roster
        .iter()
        .find(|member| &member.endpoint == endpoint.as_bytes())?
        .name
        .as_deref()
}

fn yes(b: bool) -> String {
    if b { "yes" } else { "no" }.into()
}

fn exposure_target(target: &str) -> Result<String, String> {
    wire::check_target(target).map_err(|error| error.to_string())?;
    Ok(target.to_owned())
}

async fn list(dir: &Path, full: bool) -> Result<()> {
    let view = current_view(dir).await?;
    let terminal = io::stdout().is_terminal();
    let mut rows = vec![["SERVICE", "PEER", "ENDPOINT", "MODE", "TARGET"].map(String::from)];
    let mut append = |service: Service, key: Option<&str>, mode: &str, target: Option<&str>| {
        let peer = key
            .and_then(|key| view.peers.iter().find(|peer| peer.key == key))
            .and_then(|peer| peer.alias.as_deref())
            .or(key)
            .unwrap_or("all paired peers");
        let key = key.unwrap_or("-");
        let endpoint = if terminal && !full && key.len() > 8 {
            &key[..8]
        } else {
            key
        };
        let target = match (target, service, mode) {
            (Some(target), _, _) => crate::visible(target),
            (_, Service::Shell, _) | (_, _, "excluded") => "-".into(),
            (_, Service::Tcp(port), _) => format!("loopback:{port}"),
            (_, Service::Udp(port), _) => format!("127.0.0.1:{port}"),
        };
        rows.push([
            service.to_string(),
            crate::visible(peer),
            endpoint.into(),
            mode.into(),
            target,
        ]);
    };
    for (key, service) in &view.grants {
        append(*service, Some(key), "persistent", None);
    }
    for exposure in &view.exposures {
        append(
            exposure.service,
            Some(&exposure.key),
            "temporary",
            exposure.target.as_deref(),
        );
    }
    for service in &view.defaults {
        append(*service, None, "default", None);
    }
    for (key, service) in &view.exclusions {
        append(*service, Some(key), "excluded", None);
    }
    if terminal && rows.len() == 1 {
        println!("No services enabled or exposed on this device.");
        return Ok(());
    }
    crate::print_table(&rows, terminal);
    Ok(())
}

async fn change(dir: &Path, service: Service, peer: Option<String>, enable: bool) -> Result<()> {
    let action = if enable { "Enabled" } else { "Disabled" };
    let request = match (&peer, enable) {
        (Some(p), true) => ControlRequest::Enable {
            peer: peer_key(dir, p).await?,
            service,
        },
        (Some(p), false) => ControlRequest::Disable {
            peer: peer_key(dir, p).await?,
            service,
        },
        (None, enabled) => ControlRequest::SetDefault { service, enabled },
    };
    let ControlReply::Changed(changed) = control(dir, request).await? else {
        bail!("unexpected reply");
    };
    let note = if changed { "" } else { " (unchanged)" };
    match peer {
        Some(p) => println!("{action} {service} for {}{note}", crate::visible(&p)),
        None if enable => println!("Enabled {service} by default for paired peers{note}"),
        None => println!("Disabled the default for {service}{note}; individual grants still apply"),
    }
    Ok(())
}

// ----------------------------------------------------------- offline mailbox

/// A mailbox that sends nothing, for profile setup and read-only views.
struct Offline;

const OFFLINE: &str = "no relay is contacted by this command";

impl Mailbox for Offline {
    fn validate_pin(&self, _: &Pin) -> Result<(), MailboxError> {
        Err(MailboxError::Mispinned(OFFLINE.into()))
    }
    fn start_create_slot(&self, _: &Pin, _: SlotWrite) -> Started<CreateOutcome> {
        Started::done(Err(MailboxError::Mispinned(OFFLINE.into())))
    }
    fn start_put_reply(&self, _: &Pin, _: SlotWrite) -> Started<CreateOutcome> {
        Started::done(Err(MailboxError::Mispinned(OFFLINE.into())))
    }
    fn start_append(&self, _: &Pin, _: QueueAppend) -> Started<CreateOutcome> {
        Started::done(Err(MailboxError::Mispinned(OFFLINE.into())))
    }
    fn read_slot(&self, _: &Pin, _: &SlotId) -> Result<ReadOutcome, MailboxError> {
        Err(MailboxError::Mispinned(OFFLINE.into()))
    }
    fn get_reply(&self, _: &Pin, _: &Hash) -> Result<Option<Vec<u8>>, MailboxError> {
        Err(MailboxError::Mispinned(OFFLINE.into()))
    }
    fn next_item(&self, _: &Pin, _: ReadHeader) -> Result<Option<QueueItem>, MailboxError> {
        Err(MailboxError::Mispinned(OFFLINE.into()))
    }
    fn start_ack(&self, _: &Pin, _: AckHeader) -> Started<AckOutcome> {
        Started::done(Err(MailboxError::Mispinned(OFFLINE.into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locator(id: u8, incarnation: u8) -> Locator {
        Locator {
            server: wire::ServerAddr {
                id: SecretKey::from_bytes(&[id; 32]).public(),
                udp: "127.0.0.1:1".parse().unwrap(),
                relay: "http://127.0.0.1:2".parse().unwrap(),
            },
            incarnation: Bytes([incarnation; 32]),
            access: mailbox::AccessKey(Bytes([5; 32])),
        }
    }

    /// An envelope opens only when its locator pins exactly the relay and incarnation inside
    /// the invite; a swapped locator is refused before anything could be sent.
    #[test]
    fn invite_envelopes_must_pin_the_invites_relay() {
        let root = tempfile::tempdir().unwrap();
        let good = locator(1, 2);
        let device = Device::create_network(
            &root.path().join("issuer"),
            &EndpointSecret::generate(),
            *good.server.id.as_bytes(),
            good.incarnation.0.to_vec(),
            Offline,
            Clock::System,
        )
        .unwrap();
        let token = device.issue_invite().unwrap();
        let envelope = |locator: Locator| {
            InviteEnvelope {
                format: INVITE_FORMAT.into(),
                locator,
                invite: URL_SAFE_NO_PAD.encode(&token),
            }
            .encode()
            .unwrap()
        };
        let (opened, bytes) = InviteEnvelope::open(&envelope(good.clone())).unwrap();
        assert_eq!(bytes, token);
        assert_eq!(opened.encode().unwrap(), good.encode().unwrap());
        for wrong in [locator(3, 2), locator(1, 4)] {
            assert!(InviteEnvelope::open(&envelope(wrong)).is_err());
        }
        assert!(InviteEnvelope::open(&format!("{INVITE_PREFIX}AAAA")).is_err());
        assert!(InviteEnvelope::open(&good.encode().unwrap()).is_err());
    }

    /// Not a check: writes an enrolled profile into the state directory named by
    /// MASSRELAY_FIXTURE_STATE_DIR, for native fixtures that need a real profile where no
    /// relay can be hosted (`tests/service-windows.ps1`). Its relay is an unused loopback
    /// port, so the runtime starts, serves local commands and stays offline.
    #[test]
    #[ignore = "writes a profile for a native service fixture"]
    fn write_an_offline_fixture_profile() {
        let Some(state_dir) = std::env::var_os("MASSRELAY_FIXTURE_STATE_DIR") else {
            return;
        };
        let dir = Path::new(&state_dir).join(DIR_NAME);
        let locator = locator(1, 2);
        let _owner = claim(&dir).unwrap();
        let (profile, fresh) = setup_profile(&dir, &locator).unwrap();
        assert!(fresh, "the fixture directory already holds a profile");
        crate::storage::save(&dir, PROFILE_FILE, &profile).unwrap();
        Device::create_network_named(
            &dir,
            &EndpointSecret::from_bytes(&profile.key.0),
            *locator.server.id.as_bytes(),
            locator.incarnation.0.to_vec(),
            Offline,
            Clock::System,
            Some("service-fixture"),
        )
        .unwrap();
    }
}
