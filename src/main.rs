#[cfg(target_os = "macos")]
#[path = "launch_agent.rs"]
mod background_service;
#[cfg(target_os = "linux")]
#[path = "systemd_user.rs"]
mod background_service;
mod connection_log;
mod device;
mod grants;
mod local;
mod relay;
mod storage;
mod tcp;
mod terminal;
mod tunnel;
mod udp;
mod wire;

use std::{
    fmt::Write as _,
    io::{self, IsTerminal, Write},
    net::SocketAddr,
    num::NonZeroU16,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use directories::ProjectDirs;
use iroh::{
    Endpoint, EndpointId, RelayUrl, SecretKey,
    endpoint::{RelayMode, presets},
};
use iroh_mdns_address_lookup::MdnsAddressLookup;

use wire::{Decision, LocalReply, LocalRequest, ServerAddr, Service, Ticket};

#[derive(Parser)]
#[command(
    version,
    about = "Connect your own machines for shells and port forwarding."
)]
struct Cli {
    /// Override the per-user state directory (use a separate directory for the relay).
    #[arg(long, global = true, env = "MASSRELAY_STATE_DIR")]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a ticket-only relay and print its creation ticket.
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
    /// Create a network on a shared relay and print its first invite.
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
    /// Run this device in the foreground.
    Run {
        /// Use this shell executable instead of the account's default.
        #[arg(long)]
        shell: Option<PathBuf>,
        /// Append events to this file. Defaults to connections.jsonl in the device state directory.
        #[arg(long)]
        log_file: Option<PathBuf>,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
    },
    /// Set up and start this device's background service.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Install,
    /// Start this device's installed background service.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Start,
    /// Restart this device's installed background service.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Restart,
    /// Stop this device's installed background service for this login.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Stop,
    /// Show this device's enrollment, service state, and endpoint ID.
    Status,
    /// List peers and see which devices have approved access.
    Peers {
        /// Show full endpoint IDs in the terminal.
        #[arg(long)]
        full: bool,
    },
    /// Issue a one-use invite valid for ten minutes.
    Invite,
    /// Approve a pairing by device name or endpoint ID.
    Approve { peer: String },
    /// Decline an approval request or end an existing pairing.
    Decline { peer: String },
    /// Remove another device from the entire network.
    Revoke { peer: String },
    /// Open an interactive shell on a paired device that has enabled it.
    Shell { peer: String },
    /// Grant a peer persistent access to a service on this device.
    Enable {
        /// shell, tcp:PORT, or udp:PORT. Ports forward to loopback on this device.
        service: Service,
        /// Peer name or endpoint ID.
        peer: String,
    },
    /// Revoke a peer's access to a service and close its sessions.
    Disable {
        /// shell, tcp:PORT, or udp:PORT.
        service: Service,
        /// Peer name or endpoint ID.
        peer: String,
    },
    /// List the services this device grants, and who may use them.
    List {
        /// Show full endpoint IDs.
        #[arg(long)]
        full: bool,
    },
    /// Expose a port to one peer for as long as this command runs.
    Expose {
        #[command(flatten)]
        port: ExposedPort,
        /// The only peer allowed to connect, by device name or endpoint ID.
        #[arg(long, value_name = "PEER")]
        to: String,
        /// Where this device forwards to. Defaults to loopback on the same port.
        #[arg(value_name = "HOST:PORT", value_parser = target)]
        target: Option<String>,
    },
    /// Use a port that a paired device has enabled or exposed.
    ///
    /// A TCP service is connected to standard input and output. A UDP service is
    /// offered on a loopback port until this command is interrupted.
    Connect {
        /// Peer name or endpoint ID.
        peer: String,
        /// tcp:PORT or udp:PORT.
        service: Service,
        /// Local UDP port to listen on. Defaults to the service's port.
        #[arg(long, value_name = "PORT")]
        listen: Option<u16>,
    },
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct ExposedPort {
    /// Expose this TCP port.
    #[arg(long, value_name = "PORT")]
    tcp: Option<NonZeroU16>,
    /// Expose this UDP port.
    #[arg(long, value_name = "PORT")]
    udp: Option<NonZeroU16>,
}

fn target(text: &str) -> Result<String, String> {
    wire::check_target(text)
        .map(|()| text.to_owned())
        .map_err(|error| error.to_string())
}

#[tokio::main]
async fn main() {
    let cli =
        Cli::from_arg_matches(&grouped_cli().get_matches()).unwrap_or_else(|error| error.exit());
    match execute(cli).await {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("massrelay: {}", visible(&format!("{error:#}")));
            std::process::exit(1);
        }
    }
}

fn grouped_cli() -> clap::Command {
    let command = Cli::command();
    let groups: &[(&str, &[&str])] = &[
        ("Set up a network", &["create", "join", "invite"]),
        (
            "Manage this device",
            &["status", "install", "start", "restart", "stop", "run"],
        ),
        (
            "Find and pair devices",
            &["peers", "approve", "decline", "revoke"],
        ),
        ("Connect to a peer", &["shell", "connect"]),
        (
            "Share services from this device",
            &["list", "enable", "disable", "expose"],
        ),
        (
            "Operate a relay",
            &["relay", "relay-info", "relay-init", "relay-ticket"],
        ),
    ];
    let mut help = String::from("{about-with-newline}\n{usage-heading} {usage}\n");
    for &(heading, names) in groups {
        writeln!(help, "\n{heading}:").expect("write to string");
        for &name in names {
            if let Some(subcommand) = command.find_subcommand(name) {
                let description = subcommand.get_about().expect("command description");
                writeln!(help, "  {name:12}  {description}").expect("write to string");
            }
        }
    }
    help.push_str("\nOptions:\n{options}\n\nRun 'massrelay help <command>' for details.\n");
    command.help_template(help)
}

async fn execute(cli: Cli) -> Result<i32> {
    let dir = match cli.state_dir {
        Some(dir) => dir,
        None => default_state_dir()?,
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
            device::enroll(
                &dir,
                read_ticket("Paste the operator creation ticket: ")?,
                Some(name),
                true,
            )
            .await?;
            eprintln!("Created a pocket network. Run 'massrelay status' for the next step.");
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
                 Use the invite with 'massrelay join' on another device. It works once and expires in ten minutes. \
                 Run 'massrelay status' for this device's next step.",
                visible(&name)
            );
            println!("{invite}");
        }
        Command::Join {
            invite_or_name,
            name,
        } => {
            let (ticket, name) = join_input(invite_or_name, name)?;
            device::enroll(&dir, ticket, name, false).await?;
            eprintln!("Joined the pocket network. Run 'massrelay status' for the next step.");
        }
        Command::Run {
            shell,
            log_file,
            bind,
        } => device::run(dir, shell, bind, log_file).await?,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::Install => background_service::install(&dir)?,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::Start => background_service::control(&dir, ServiceAction::Start)?,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::Restart => background_service::control(&dir, ServiceAction::Restart)?,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::Stop => background_service::control(&dir, ServiceAction::Stop)?,
        Command::Status => device::status(&dir).await?,
        Command::Peers { full } => {
            let LocalReply::Peers(peers) = local::command(&dir, LocalRequest::Peers).await? else {
                bail!("unexpected roster reply");
            };
            let terminal = io::stdout().is_terminal();
            let mut rows = vec![["NAME", "PRESENCE", "PAIRING", "ENDPOINT"].map(String::from)];
            rows.extend(peers.into_iter().map(|peer| {
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
                [
                    visible(&peer.member.name),
                    presence.into(),
                    pairing.into(),
                    endpoint_display(peer.member.id, full || !terminal),
                ]
            }));
            print_table(&rows, terminal);
        }
        Command::Invite => {
            let LocalReply::Invite(ticket) = local::command(&dir, LocalRequest::Invite).await?
            else {
                bail!("unexpected invite reply");
            };
            if io::stderr().is_terminal() {
                eprintln!(
                    "Use this invite with 'massrelay join' on another device within ten minutes."
                );
            }
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
        Command::Enable { service, peer } => {
            let request = LocalRequest::Enable {
                service,
                peer: peer.clone(),
            };
            local::command(&dir, request).await?;
            println!("Enabled {service} for {}", visible(&peer));
        }
        Command::Disable { service, peer } => {
            let request = LocalRequest::Disable {
                service,
                peer: peer.clone(),
            };
            local::command(&dir, request).await?;
            println!("Disabled {service} for {}", visible(&peer));
        }
        Command::List { full } => {
            let LocalReply::Grants(grants) = local::command(&dir, LocalRequest::Grants).await?
            else {
                bail!("unexpected grant list reply");
            };
            let mut rows =
                vec![["SERVICE", "PEER", "ENDPOINT", "MODE", "TARGET"].map(String::from)];
            rows.extend(grants.into_iter().map(|grant| {
                let peer = grant.peer.as_deref().unwrap_or("(unknown)");
                let mode = if grant.temporary {
                    "temporary".into()
                } else {
                    "persistent".into()
                };
                let endpoint = endpoint_display(grant.id, full);
                let target = grant.target.unwrap_or_else(|| match grant.service {
                    Service::Shell => "-".into(),
                    Service::Tcp(port) => format!("loopback:{port}"),
                    Service::Udp(port) => format!("127.0.0.1:{port}"),
                });
                [
                    grant.service.to_string(),
                    visible(peer),
                    endpoint,
                    mode,
                    visible(&target),
                ]
            }));
            print_table(&rows, io::stdout().is_terminal());
        }
        Command::Expose { port, to, target } => {
            let service = match (port.tcp, port.udp) {
                (Some(port), None) => Service::Tcp(port),
                (None, Some(port)) => Service::Udp(port),
                _ => bail!("pass one of --tcp or --udp"),
            };
            local::expose(&dir, service, to, target).await?
        }
        Command::Connect {
            peer,
            service,
            listen,
        } => local::connect(&dir, peer, service, listen).await?,
    }
    Ok(0)
}

fn default_state_dir() -> Result<PathBuf> {
    Ok(ProjectDirs::from("", "", "MassRelay")
        .context("cannot find the user state directory; specify --state-dir")?
        .data_local_dir()
        .to_path_buf())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy)]
enum ServiceAction {
    Start,
    Restart,
    Stop,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ServiceAction {
    fn name(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Restart => "restart",
            Self::Stop => "stop",
        }
    }

    fn completed(self) -> &'static str {
        match self {
            Self::Start => "Started",
            Self::Restart => "Restarted",
            Self::Stop => "Stopped",
        }
    }

    fn record(self, path: &Path, result: &Result<()>) {
        use connection_log::{Audit, ConnectionLog};
        let log = ConnectionLog::open(Some(path)).or_else(|error| {
            eprintln!("massrelay: could not open service audit log: {error:#}");
            ConnectionLog::open(None)
        });
        if let Ok(log) = log {
            log.audit(
                "service_control",
                Audit {
                    operation: self.name(),
                    outcome: if result.is_ok() { "allowed" } else { "failed" },
                    reason: result.is_err().then_some("service_manager_failed"),
                    ..Audit::default()
                },
                None,
            );
        }
    }
}

fn visible(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

fn endpoint_display(id: EndpointId, full: bool) -> String {
    let mut endpoint = id.to_string();
    if !full {
        endpoint.truncate(8);
    }
    endpoint
}

fn print_table<const N: usize>(rows: &[[String; N]], terminal: bool) {
    if !terminal {
        for row in rows {
            println!("{}", row.join("\t"));
        }
        return;
    }

    let widths: [usize; N] = std::array::from_fn(|index| {
        rows.iter()
            .map(|row| row[index].chars().count())
            .max()
            .unwrap_or(0)
    });
    for row in rows {
        let (last, columns) = row.split_last().expect("table columns");
        let mut line = String::new();
        for (cell, width) in columns.iter().zip(widths) {
            write!(line, "{cell:<width$}  ").expect("write to string");
        }
        println!("{line}{last}");
    }
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
        "Run 'massrelay status' on {} and compare its endpoint ID:",
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
        return Ok((read_ticket("Paste the join invite: ")?, name));
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
            Ok((read_ticket("Paste the join invite: ")?, Some(argument)))
        }
    }
}

fn read_ticket(prompt: &str) -> Result<Ticket> {
    if io::stdin().is_terminal() {
        eprint!("{prompt}");
        io::stderr().flush()?;
    }
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
