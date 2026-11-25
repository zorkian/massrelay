mod device;
mod local;
mod relay;
mod storage;
mod terminal;
mod wire;

use std::{
    io::{self, IsTerminal, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use iroh::{
    Endpoint, EndpointId, RelayUrl, SecretKey,
    endpoint::{RelayMode, presets},
};
use iroh_mdns_address_lookup::MdnsAddressLookup;

use wire::{Decision, LocalReply, LocalRequest, ServerAddr, Ticket};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Override the per-user state directory (use a separate directory for the relay).
    #[arg(long, global = true, env = "MASSRELAY_STATE_DIR")]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a ticket-only relay and print a one-use network creation ticket.
    RelayInit {
        #[arg(long)]
        public_udp: SocketAddr,
        #[arg(long)]
        url: RelayUrl,
    },
    /// Run the public relay and membership service in the foreground.
    Relay {
        #[arg(long, default_value = "0.0.0.0:4433")]
        udp_bind: SocketAddr,
        #[arg(long, default_value = "0.0.0.0:3340")]
        relay_bind: SocketAddr,
        /// Start a shared relay, open to new pocket networks, advertising this UDP address.
        #[arg(long, requires = "url")]
        public_udp: Option<SocketAddr>,
        /// Relay URL advertised by a shared relay.
        #[arg(long, requires = "public_udp")]
        url: Option<RelayUrl>,
    },
    /// Print a shared relay's public locator.
    RelayInfo,
    /// Print the relay's current one-use network creation ticket.
    RelayTicket,
    /// Create a pocket network on a shared relay and print an invite for the next device.
    Create {
        /// Device name for an operator creation ticket, which is read from stdin.
        #[arg(value_name = "NAME", conflicts_with_all = ["relay", "name"])]
        ticket_name: Option<String>,
        /// Public locator of a shared relay. Defaults to MASSRELAY_RELAY.
        #[arg(long, value_name = "LOCATOR")]
        relay: Option<String>,
        /// Device name on a shared relay. Defaults to this machine's hostname.
        #[arg(long)]
        name: Option<String>,
    },
    /// Enroll in a pocket network using an invite.
    Join {
        /// Invite token. Anything else is a device name, with the invite read from stdin.
        /// Omit to read the invite from stdin.
        #[arg(value_name = "INVITE|NAME")]
        invite_or_name: Option<String>,
        /// Device name. Defaults to this machine's hostname.
        #[arg(long)]
        name: Option<String>,
    },
    /// Make this device reachable while the foreground process runs.
    Run {
        /// Let paired devices open a shell under this OS account.
        #[arg(long)]
        allow_shell: bool,
        /// Use this shell executable instead of the account's default.
        #[arg(long, requires = "allow_shell")]
        shell: Option<PathBuf>,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
    },
    /// List devices, recent presence, and pairing status.
    Peers,
    /// Issue a one-use invite valid for ten minutes.
    Invite,
    /// Approve a pairing by device name or endpoint ID.
    Approve { peer: String },
    /// Decline or remove a pairing. Both devices must reapprove to pair again.
    Decline { peer: String },
    /// Remove another device from the entire network.
    Revoke { peer: String },
    /// Open an interactive shell on a paired device.
    Shell { peer: String },
}

#[tokio::main]
async fn main() {
    match execute(Cli::parse()).await {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("massrelay: {}", visible(&format!("{error:#}")));
            std::process::exit(1);
        }
    }
}

async fn execute(cli: Cli) -> Result<i32> {
    let dir = match cli.state_dir {
        Some(dir) => dir,
        None => ProjectDirs::from("", "", "MassRelay")
            .context("cannot find the user state directory; specify --state-dir")?
            .data_local_dir()
            .to_path_buf(),
    };

    match cli.command {
        Command::RelayInit { public_udp, url } => relay::init(&dir, public_udp, url)?,
        Command::Relay {
            udp_bind,
            relay_bind,
            public_udp,
            url,
        } => relay::run(dir, udp_bind, relay_bind, public_udp.zip(url)).await?,
        Command::RelayInfo => relay::info(&dir)?,
        Command::RelayTicket => relay::create_ticket(&dir)?,
        Command::Create {
            ticket_name: Some(name),
            ..
        } => {
            if io::stdin().is_terminal() && env_relay().is_some() {
                eprintln!(
                    "massrelay: reading an operator creation ticket from stdin. \
                     To use MASSRELAY_RELAY instead, run massrelay create --name NAME."
                );
            }
            device::enroll(&dir, read_ticket()?, Some(name), true).await?
        }
        Command::Create { relay, name, .. } => {
            let locator = relay.or_else(env_relay).context(
                "pass --relay LOCATOR or set MASSRELAY_RELAY; \
                 with an operator creation ticket, use massrelay create NAME",
            )?;
            let server = ServerAddr::from_locator(&locator)?;
            let (name, invite) = device::create(&dir, server, name).await?;
            eprintln!(
                "Created a pocket network. This device is {}. \
                 The invite works once and expires ten minutes after issue.",
                visible(&name)
            );
            println!("{invite}");
        }
        Command::Join {
            invite_or_name,
            name,
        } => {
            let (ticket, name) = join_input(invite_or_name, name)?;
            device::enroll(&dir, ticket, name, false).await?
        }
        Command::Run {
            allow_shell,
            shell,
            bind,
        } => device::run(dir, allow_shell, shell, bind).await?,
        Command::Peers => {
            let LocalReply::Peers(peers) = local::command(&dir, LocalRequest::Peers).await? else {
                bail!("unexpected roster reply");
            };
            println!("NAME\tPRESENCE\tPAIRING\tENDPOINT");
            for peer in peers {
                let online = peer
                    .member
                    .last_seen
                    .is_some_and(|t| storage::now().saturating_sub(t) < 12);
                let presence = if online { "recent" } else { "unknown" };
                let pairing = match (peer.pair.ours, peer.pair.theirs) {
                    (Some(Decision::Approve), Some(Decision::Approve)) => "paired",
                    (Some(Decision::Decline), _) => "declined",
                    (_, Some(Decision::Decline)) => "declined by peer",
                    (Some(Decision::Approve), _) => "awaiting peer",
                    (_, Some(Decision::Approve)) => "approval requested",
                    _ => "unpaired",
                };
                println!(
                    "{}\t{presence}\t{pairing}\t{}",
                    visible(&peer.member.name),
                    peer.member.id
                );
            }
        }
        Command::Invite => {
            let LocalReply::Invite(ticket) = local::command(&dir, LocalRequest::Invite).await?
            else {
                bail!("unexpected invite reply");
            };
            println!("{ticket}");
        }
        Command::Approve { peer } => {
            let peer = confirm_peer(&dir, &peer).await?;
            local::command(
                &dir,
                LocalRequest::Pair {
                    peer: peer.to_string(),
                    decision: Decision::Approve,
                },
            )
            .await?;
            println!("Approved {peer}");
        }
        Command::Decline { peer } => {
            local::command(
                &dir,
                LocalRequest::Pair {
                    peer,
                    decision: Decision::Decline,
                },
            )
            .await?;
            println!("Declined locally. The relay will update when reachable.");
        }
        Command::Revoke { peer } => {
            local::command(&dir, LocalRequest::Revoke { peer }).await?;
        }
        Command::Shell { peer } => return local::shell(&dir, peer).await,
    }
    Ok(0)
}

fn visible(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

async fn confirm_peer(dir: &Path, name: &str) -> Result<EndpointId> {
    if let Ok(id) = name.parse() {
        return Ok(id);
    }
    let LocalReply::Peers(peers) = local::command(dir, LocalRequest::Peers).await? else {
        bail!("unexpected roster reply");
    };
    let peer = peers
        .into_iter()
        .find(|peer| peer.member.name.eq_ignore_ascii_case(name))
        .with_context(|| format!("unknown peer {name}"))?
        .member;
    if !io::stdin().is_terminal() {
        bail!("approve using the verified endpoint ID {}", peer.id);
    }
    eprintln!(
        "Compare this endpoint ID with the one shown by massrelay run on {}:",
        visible(&peer.name)
    );
    eprintln!("{}", peer.id);
    eprint!("Approve this device? [y/N] ");
    io::stderr().flush()?;
    let mut reply = String::new();
    io::stdin().read_line(&mut reply)?;
    if !reply.trim().eq_ignore_ascii_case("y") {
        bail!("approval cancelled");
    }
    Ok(peer.id)
}

async fn shutdown() -> io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

fn env_relay() -> Option<String> {
    std::env::var("MASSRELAY_RELAY")
        .ok()
        .filter(|locator| !locator.trim().is_empty())
}

/// Resolve `join`'s arguments into an invite and an optional device name.
fn join_input(argument: Option<String>, name: Option<String>) -> Result<(Ticket, Option<String>)> {
    let Some(argument) = argument else {
        return Ok((read_ticket()?, name));
    };
    match Ticket::decode(&argument) {
        Ok(ticket) => Ok((ticket, name)),
        Err(_) if ServerAddr::from_locator(&argument).is_ok() => {
            bail!("that is a relay locator; join needs an invite from an enrolled device")
        }
        Err(error) if name.is_some() => {
            Err(error).context("with --name, the argument must be an invite token")
        }
        // A name may begin like a token, so only a complete token is treated as one.
        Err(_) => {
            if argument.starts_with("mr1_") {
                eprintln!(
                    "massrelay: the argument is not a complete invite, so it is used as the \
                     device name; reading the invite from stdin"
                );
            }
            Ok((read_ticket()?, Some(argument)))
        }
    }
}

fn read_ticket() -> Result<Ticket> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ticket::decode(&line)
}

async fn bind_endpoint(
    key: SecretKey,
    bind: SocketAddr,
    relay: Option<RelayUrl>,
    alpn: &[u8],
    mdns: bool,
) -> Result<Endpoint> {
    let mode = relay.map_or(RelayMode::Disabled, |url| RelayMode::custom([url]));
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .clear_ip_transports()
        .bind_addr(bind)?
        .relay_mode(mode)
        .alpns(vec![alpn.to_vec()])
        .bind()
        .await?;
    if mdns && !bind.ip().is_loopback() {
        match MdnsAddressLookup::builder()
            .service_name("massrelay")
            .build(endpoint.id())
        {
            Ok(lookup) => endpoint.address_lookup()?.add(lookup),
            Err(error) => eprintln!("massrelay: LAN discovery unavailable: {error}"),
        }
    }
    Ok(endpoint)
}
