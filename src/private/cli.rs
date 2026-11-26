//! Private network commands and their isolated device profiles.
//!
//! A private profile lives in its own directory, `<state dir>/private-experimental-0/`, beside
//! (never inside or instead of) a legacy profile. Its marker, `private-device.json`, names an
//! experimental format and holds this device's endpoint key and the private relay locator it
//! pinned; the membership store, pairing state, runtime owner lock and local control marker sit
//! next to it. No legacy profile, credential, default relay or command mode is read, changed or
//! used as a fallback, and none of these formats is frozen.
//!
//! - `create` pins a private relay from its locator after checking, over the relay's
//!   authenticated identity, that it serves the locator's storage incarnation and admits the
//!   locator's operator access credential.
//! - `relay-access` replaces that credential with the one in a newer locator for the exact same
//!   relay, addresses and incarnation, after the relay admits it; nothing else changes. The
//!   relay operator issues credentials and revokes them (`docs/private-relay-operations.md`).
//! - `invite` asks the running runtime for a one-use invite and prints one envelope carrying
//!   the relay locator and the invite bytes. The envelope is a bearer secret: it is printed only
//!   to standard output and never logged.
//! - `join` reads that envelope (argument or standard input), refuses it unless the locator's
//!   relay key and incarnation equal the ones inside the invite and the relay authenticates that
//!   incarnation, persists the exact request, appends it, and waits for the issuer's reply. Run
//!   again, it resumes the same pending join with the exact persisted request.
//! - `run` is the foreground runtime. Its membership pass processes invite requests, stages and
//!   settles the Add of a reserved invite, catches up and dispatches sealed replies, all through
//!   the runtime's owner.
//! - Every other command talks to the running runtime over its authenticated local control
//!   channel; `status` and `peers` fall back to a read-only view when it is not running.
//!
//! The device's endpoint identity serves peers only; every mailbox exchange uses a separate
//! random transport identity.
//!
//! # Not offered (parity gaps)
//!
//! Background services (`install`, `start`, `restart`, `stop`), temporary exposures (`expose`),
//! destination-chosen targets, clipboard copy, the interactive peer picker, roster names as
//! selectors and the connection log are legacy features with no private equivalent yet.

use std::io::{self, IsTerminal, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Subcommand;
use iroh::{EndpointAddr, EndpointId, SecretKey};
use serde::{Deserialize, Serialize};

use crate::mailbox::{self, Bytes, Client, Locator};
use crate::wire::{self, Service};

use super::binding::EndpointSecret;
use super::codec::{Hash, hex, unhex};
use super::envelope::{InviteToken, SlotId};
use super::mailbox::{
    AckOutcome, CreateOutcome, Mailbox, MailboxError, Pin, QueueAppend, QueueItem, ReadOutcome,
    SlotWrite, Started,
};
use super::membership::{Clock, Device, Error as MembershipError, JoinError};
use super::pairing::{Owner, PairError};
use super::relay_mailbox::RelayMailbox;
use super::runtime::{self, CONTROL, Config, ControlReply, ControlRequest, PeerView, Runtime};
use super::service::SERVICE_ALPN;
use super::store;
use crate::slot_wire::{AckHeader, ReadHeader};

/// The private profile's directory under the state directory.
pub const DIR_NAME: &str = "private-experimental-0";
const PROFILE_FILE: &str = "private-device.json";
const PROFILE_FORMAT: &str = "massrelay-private-device/experimental-0";
const INVITE_PREFIX: &str = "mrprivinv0_";
const INVITE_FORMAT: &str = "massrelay-private-invite/experimental-0";
/// Transport ALPN of the throwaway endpoint that checks a relay's incarnation.
const CHECK_ALPN: &[u8] = b"massrelay/mailbox-check/experimental-1";
/// How often a waiting join looks for its reply.
const JOIN_POLL: Duration = Duration::from_secs(2);

#[derive(Subcommand)]
pub enum Command {
    /// Create a private network pinned to a private relay locator.
    Create {
        /// Private relay locator. Omit to read it from standard input.
        #[arg(long, value_name = "LOCATOR")]
        relay: Option<String>,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
    },
    /// Print a one-use private invite (valid ten minutes) from the running runtime.
    Invite,
    /// Replace the relay access credential with the one in a new locator for the same relay.
    RelayAccess {
        /// Current locator for the pinned relay. Omit to read it from standard input.
        #[arg(value_name = "LOCATOR")]
        locator: Option<String>,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
    },
    /// Join with a private invite, or resume a pending join.
    Join {
        /// The invite envelope (mrprivinv0_...). Omit to read it from stdin or to resume.
        #[arg(value_name = "INVITE")]
        invite: Option<String>,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
    },
    /// Run the private runtime in the foreground.
    Run {
        /// Use this shell executable instead of the account's default.
        #[arg(long)]
        shell: Option<PathBuf>,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
        /// Seconds between membership passes.
        #[arg(long, value_name = "SECONDS", default_value_t = 30)]
        sync_every: u64,
    },
    /// Show this private profile and its runtime.
    Status,
    /// List members and pairing decisions, by endpoint key and local alias.
    Peers,
    /// Approve a member's exact endpoint key under a local alias.
    Approve {
        /// Endpoint key (64 hex digits or Iroh form), or an alias already pinned.
        peer: String,
        /// Alias this device pins to the key. Never taken from the roster.
        #[arg(long = "as", value_name = "ALIAS")]
        alias: String,
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
    /// Open an interactive shell on a paired peer.
    Shell { peer: String },
    /// Connect to a peer's shell or forwarded port.
    Connect {
        peer: String,
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
        Command::Create { relay, bind } => create(&dir, &relay_locator_input(relay)?, bind).await?,
        Command::Invite => invite(&dir).await?,
        Command::RelayAccess { locator, bind } => {
            relay_access(&dir, &relay_locator_input(locator)?, bind).await?;
        }
        Command::Join { invite, bind } => join(&dir, invite, bind).await?,
        Command::Run {
            shell,
            bind,
            sync_every,
        } => run(&dir, shell, bind, sync_every).await?,
        Command::Status => status(&dir).await?,
        Command::Peers => peers(&dir).await?,
        Command::Approve {
            peer,
            alias,
            reapprove,
        } => {
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
        Command::Decline { peer } => {
            control(&dir, ControlRequest::Decline { peer }).await?;
            println!("Declined locally.");
        }
        Command::Revoke { peer } => {
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
        Command::Shell { peer } => return runtime::shell(&dir, peer).await,
        Command::Connect {
            peer,
            service,
            listen,
        } => match service.unwrap_or(Service::Shell) {
            Service::Shell => {
                ensure!(listen.is_none(), "--listen applies to udp services");
                return runtime::shell(&dir, peer).await;
            }
            service => runtime::connect(&dir, peer, service, listen).await?,
        },
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

pub fn profile_exists(state_dir: &Path) -> bool {
    state_dir.join(DIR_NAME).join(PROFILE_FILE).is_file()
}

fn load(dir: &Path) -> Result<Profile> {
    ensure!(
        dir.join(PROFILE_FILE).try_exists()?,
        "no private profile in {}; run 'massrelay private create' or 'massrelay private join'",
        dir.display()
    );
    let profile: Profile = crate::storage::load(dir, PROFILE_FILE)?;
    ensure!(
        profile.format == PROFILE_FORMAT,
        "unsupported private profile format {:?}",
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
            anyhow!("the private runtime or another command is using this profile")
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
            "{} already holds a private profile for another relay; it was not changed",
            dir.display()
        );
        return Ok((saved, false));
    }
    Ok((
        Profile {
            format: PROFILE_FORMAT.into(),
            key: Bytes(wire::random()?),
            locator: locator.clone(),
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
                Err(error) => error.context("could not reach the private relay"),
            })?;
        let served = client.incarnation().await?;
        ensure!(
            served == locator.incarnation(),
            "the private relay now serves another storage incarnation than its locator; \
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

fn relay_locator_input(argument: Option<String>) -> Result<String> {
    if let Some(argument) = argument {
        return Ok(argument);
    }
    if io::stdin().is_terminal() {
        eprintln!("Paste the private relay locator:");
    }
    let mut locator = String::new();
    io::stdin().read_line(&mut locator)?;
    ensure!(
        !locator.trim().is_empty(),
        "a private relay locator is required"
    );
    Ok(locator)
}

async fn create(dir: &Path, relay: &str, bind: SocketAddr) -> Result<()> {
    let locator = Locator::decode(relay)?;
    let owner = claim(dir)?;
    ensure!(
        !store::initialized(dir),
        "{} already holds a private profile; it was not changed",
        dir.display()
    );
    let (profile, fresh) = setup_profile(dir, &locator)?;
    check_relay(&locator, bind).await?;
    if fresh {
        // Saved before the store, so an interrupted create resumes with the same identity.
        crate::storage::save(dir, PROFILE_FILE, &profile)?;
    }
    let (path, key) = (dir.to_path_buf(), profile.key.0);
    let relay_key = *locator.server.id.as_bytes();
    let incarnation = locator.incarnation.0.to_vec();
    blocking(move || {
        Device::create_network(
            &path,
            &EndpointSecret::from_bytes(&key),
            relay_key,
            incarnation,
            Offline,
            Clock::System,
        )
        .map(drop)
    })
    .await?
    .map_err(membership)?;
    drop(owner);
    eprintln!("Created a private network. Run 'massrelay private run' next.");
    println!("{}", hex(profile.secret().public().as_bytes()));
    Ok(())
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
    eprintln!("Relay access credential replaced. Start 'massrelay private run' again to use it.");
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
            .context("expected a private invite starting with mrprivinv0_")?;
        let envelope: Self = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded)
                .context("invalid private invite")?,
        )
        .context("invalid private invite")?;
        ensure!(
            envelope.format == INVITE_FORMAT,
            "unsupported private invite format {:?}",
            envelope.format
        );
        mailbox::refuse_userinfo(&envelope.locator.server.relay)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&envelope.invite)
            .context("invalid private invite")?;
        matches(&envelope.locator, &bytes)?;
        Ok((envelope.locator, bytes))
    }
}

/// The invite inside must name the locator's relay key and storage incarnation.
fn matches(locator: &Locator, invite: &[u8]) -> Result<()> {
    let token =
        InviteToken::decode(invite).map_err(|e| anyhow!("invalid private invite: {e:?}"))?;
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

async fn invite(dir: &Path) -> Result<()> {
    let profile = load(dir)?;
    let ControlReply::Invite(token) = control(dir, ControlRequest::Invite).await? else {
        bail!("unexpected invite reply");
    };
    let bytes = unhex(&token).context("invalid invite from the runtime")?;
    matches(&profile.locator, &bytes)?;
    let envelope = InviteEnvelope {
        format: INVITE_FORMAT.into(),
        locator: profile.locator,
        invite: URL_SAFE_NO_PAD.encode(bytes),
    }
    .encode()?;
    if io::stdout().is_terminal() {
        eprintln!(
            "Private invite. On the other device run 'massrelay private join' and \
             paste it there. It works once and expires in ten minutes; keep it secret."
        );
    }
    println!("{envelope}");
    Ok(())
}

// --------------------------------------------------------------------- join

async fn join(dir: &Path, argument: Option<String>, bind: SocketAddr) -> Result<()> {
    let owner = claim(dir)?;
    let profile = if store::initialized(dir) {
        let path = dir.to_path_buf();
        let st = blocking(move || Device::open(&path, Offline, Clock::System)?.state())
            .await?
            .map_err(membership)?;
        let Some(pending) = st.pending_join else {
            bail!("this private profile is already a member; run 'massrelay private run'");
        };
        if let Some(text) = argument {
            let (_, bytes) = InviteEnvelope::open(&text)?;
            ensure!(
                bytes == pending.token,
                "another join is pending on this profile; run 'massrelay private join' without \
                 an invite to resume it"
            );
        }
        load(dir)?
    } else {
        let text = match argument {
            Some(text) => text,
            None => read_invite()?,
        };
        let (locator, bytes) = InviteEnvelope::open(&text)?;
        let (profile, fresh) = setup_profile(dir, &locator)?;
        check_relay(&locator, bind).await?;
        if fresh {
            crate::storage::save(dir, PROFILE_FILE, &profile)?;
        }
        let (path, key) = (dir.to_path_buf(), profile.key.0);
        // Persists the exact request before anything is sent.
        blocking(move || {
            Device::begin_join(
                &path,
                &EndpointSecret::from_bytes(&key),
                &bytes,
                Offline,
                Clock::System,
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
            bail!("stopped waiting; run 'massrelay private join' to resume this join");
        }
    }
    drop(owner);
    eprintln!("Joined the private network. Run 'massrelay private run' next.");
    println!("{}", hex(profile.secret().public().as_bytes()));
    Ok(())
}

fn read_invite() -> Result<String> {
    if io::stdin().is_terminal() {
        eprint!("Paste the private invite: ");
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
                        "Join request sent. Waiting for the inviting device's private runtime to \
                         admit this device; Ctrl-C stops waiting and 'massrelay private join' \
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
                Err(MembershipError::Join(JoinError::Mismatch(why))) => bail!(
                    "this invite's reply admits another request ({why}): the invite was used by \
                     another device; ask for a new one"
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

async fn run(dir: &Path, shell: Option<PathBuf>, bind: SocketAddr, sync_every: u64) -> Result<()> {
    let profile = load(dir)?;
    ensure!(sync_every > 0, "--sync-every must be at least one second");
    // A duplicate must not use this profile's key to register at the relay.
    let owner = Owner::acquire(dir).map_err(|e| match e {
        PairError::OwnedElsewhere => {
            anyhow!("a private runtime is already running on this profile")
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
            "this device has not finished joining; run 'massrelay private join' first"
        );
    }
    let relay = profile.locator.server.relay.clone();
    let endpoint = crate::bind_endpoint(
        profile.secret(),
        bind,
        Some(relay.clone()),
        SERVICE_ALPN,
        true,
    )
    .await?;
    let mailbox = {
        let p = profile.clone();
        blocking(move || p.mailbox(bind)).await??
    };
    let mut config = Config::new(dir);
    config.shell = shell;
    config.sync_every = Some(Duration::from_secs(sync_every));
    config.addresses = Arc::new(move |key| {
        EndpointId::from_bytes(key)
            .ok()
            .map(|id| EndpointAddr::new(id).with_relay_url(relay.clone()))
    });
    let runtime = Runtime::start_owned(config, mailbox, Clock::System, endpoint.clone(), owner)
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    eprintln!(
        "MassRelay private runtime running as {}",
        hex(endpoint.id().as_bytes())
    );
    eprintln!("Press Ctrl-C to stop.");
    let signal = crate::shutdown().await;
    let stopped = runtime.stop().await;
    if !stopped.aborted.is_empty() {
        eprintln!(
            "massrelay: stopped without waiting for: {:?}",
            stopped.aborted
        );
    }
    if stopped.native_workers > 0 {
        eprintln!(
            "massrelay: {} shell cleanup worker(s) still running",
            stopped.native_workers
        );
    }
    if !stopped.owner_released {
        eprintln!(
            "massrelay: a membership call or shell cleanup is still running; the profile stays \
             owned until it finishes or this process exits"
        );
    } else {
        eprintln!("Stopped; the profile is released.");
    }
    signal?;
    Ok(())
}

// ------------------------------------------------------------ status, peers

async fn control(dir: &Path, request: ControlRequest) -> Result<ControlReply> {
    load(dir)?;
    runtime::command(dir, request).await
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
    println!("Profile: private");
    println!("Endpoint: {}", hex(profile.secret().public().as_bytes()));
    println!(
        "Relay: {} incarnation {}",
        profile.locator.server.id,
        hex(&profile.locator.incarnation.0)
    );
    if let Some(pending) = &st.pending_join {
        match &pending.halted {
            Some(h) => println!("Membership: join halted: {}", crate::visible(h)),
            None => println!("Membership: join pending; run 'massrelay private join' to resume"),
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
    let view = current_view(dir).await?;
    match view.live_sessions {
        Some(live) => println!("Runtime: running, {live} live authorizations and sessions"),
        None => println!("Runtime: not running"),
    }
    let members = view.peers.iter().filter(|p| p.member).count() + 1;
    match &view.halt {
        Some(h) => println!("Membership: halted: {}", crate::visible(h)),
        None => println!(
            "Membership: {members} members, epoch {}",
            st.net.map_or(0, |n| n.epoch)
        ),
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
    if let Some(last) = &view.last_sync {
        println!("Last membership pass: {}", crate::visible(last));
    }
    Ok(())
}

async fn peers(dir: &Path) -> Result<()> {
    load(dir)?;
    let view = current_view(dir).await?;
    let mut rows =
        vec![["ENDPOINT", "ALIAS", "MEMBER", "LOCAL", "REMOTE", "PAIRED"].map(String::from)];
    rows.extend(view.peers.into_iter().map(|p: PeerView| {
        [
            p.key,
            p.alias.map_or_else(|| "-".into(), |a| crate::visible(&a)),
            yes(p.member),
            p.local,
            p.remote,
            yes(p.paired),
        ]
    }));
    crate::print_table(&rows, io::stdout().is_terminal());
    Ok(())
}

fn yes(b: bool) -> String {
    if b { "yes" } else { "no" }.into()
}

async fn change(dir: &Path, service: Service, peer: Option<String>, enable: bool) -> Result<()> {
    let action = if enable { "Enabled" } else { "Disabled" };
    let request = match (&peer, enable) {
        (Some(p), true) => ControlRequest::Enable {
            peer: p.clone(),
            service,
        },
        (Some(p), false) => ControlRequest::Disable {
            peer: p.clone(),
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
}
