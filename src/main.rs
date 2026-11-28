#[cfg(target_os = "macos")]
#[path = "launch_agent.rs"]
mod background_service;
#[cfg(target_os = "linux")]
#[path = "systemd_user.rs"]
mod background_service;
mod connection_log;
mod grants;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod host_ssh;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod installer;
// Linux has no launchd; this builds the macOS service code there and tests its portable part.
#[cfg(all(test, target_os = "linux"))]
#[allow(dead_code)]
mod launch_agent;
mod local;
#[allow(dead_code)]
mod mailbox;
#[cfg(unix)]
#[allow(dead_code)]
mod mailbox_server;
#[allow(dead_code)]
mod private;
#[cfg(unix)]
mod private_relay;
#[cfg(unix)]
#[allow(dead_code)]
mod slot_store;
#[allow(dead_code)]
mod slot_wire;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod ssh_install;
mod storage;
mod tcp;
mod terminal;
mod tunnel;
mod udp;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod update;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_service;
mod wire;

use std::{
    fmt::Write as _,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use directories::ProjectDirs;
#[cfg(unix)]
use iroh::EndpointId;
use iroh::{
    Endpoint, RelayUrl, SecretKey,
    endpoint::{RelayMode, presets},
};
use iroh_mdns_address_lookup::MdnsAddressLookup;
#[cfg(windows)]
use windows_service as background_service;

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
    command: Option<Command>,
}

#[cfg(unix)]
#[derive(Subcommand)]
enum RelayGrants {
    /// Issue an access grant and print a locator carrying its secret.
    Issue {
        /// The operator's own note for this grant, such as whose network uses it.
        #[arg(long, default_value = "")]
        label: String,
    },
    /// List every access grant, revoked ones included.
    List,
    /// Revoke an access grant. It stops admitting at the relay's next start.
    Revoke {
        /// The grant identifier shown by 'list'.
        id: String,
    },
}

#[cfg(unix)]
#[derive(Subcommand)]
enum RelayStore {
    /// Verify the whole store: integrity, exact schema, links and every body.
    Check,
    /// Write a verified, signed snapshot into a new directory.
    Backup {
        #[arg(long, value_name = "DIR")]
        to: PathBuf,
        /// Seal the store first: the snapshot becomes the incarnation's final state, and this
        /// relay will not serve again.
        #[arg(long = "final")]
        final_: bool,
    },
    /// Restore a backup into an empty state directory.
    Restore {
        #[arg(long, value_name = "DIR")]
        from: PathBuf,
        /// The relay endpoint identity the backup must be signed by, from a locator you trust.
        #[arg(long, value_name = "ENDPOINT_ID")]
        relay: String,
        /// Keep the incarnation. Only a complete (final) backup, restored once.
        #[arg(long)]
        keep_incarnation: bool,
    },
    /// Set the store aside and start a new, empty incarnation. Every network on the old one
    /// must be created again.
    Rotate {
        /// Required: confirms that networks on the current incarnation end here.
        #[arg(long, required = true)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a private relay in its own state directory.
    #[cfg(unix)]
    RelayInit {
        #[arg(long)]
        public_udp: SocketAddr,
        #[arg(long)]
        url: RelayUrl,
    },
    /// Run an initialized private relay in the foreground.
    #[cfg(unix)]
    Relay {
        #[arg(long, default_value = "0.0.0.0:4433")]
        udp_bind: SocketAddr,
        #[arg(long, default_value = "0.0.0.0:3340")]
        relay_bind: SocketAddr,
    },
    /// Show the relay’s identity, addresses, and store incarnation.
    #[cfg(unix)]
    RelayInfo,
    /// Manage a stopped private relay's operator access grants.
    #[cfg(unix)]
    #[command(subcommand)]
    RelayGrants(RelayGrants),
    /// Verify, back up, restore or rotate a stopped private
    /// relay's store.
    #[cfg(unix)]
    #[command(subcommand)]
    RelayStore(RelayStore),
    /// Set up and start this device's background service and its SSH access.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Install(installer::Confirmation),
    /// Set up this device's SSH access and its background service, which starts before sign-in.
    #[cfg(windows)]
    Install {
        #[command(flatten)]
        service: windows_service::InstallOptions,
        #[command(flatten)]
        confirmation: installer::Confirmation,
    },
    /// Remove this device's background service and SSH setup, keeping its enrollment.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    Uninstall(installer::Confirmation),
    /// Start this device's installed background service.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    Start,
    /// Restart this device's installed background service.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    Restart,
    #[cfg_attr(
        not(windows),
        doc = "Stop this device's installed background service for this login."
    )]
    #[cfg_attr(
        windows,
        doc = "Stop this device's installed background service until it is started or Windows restarts."
    )]
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    Stop,
    /// Update this device's installed background service to the latest release, once it is idle.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[command(
        after_help = "Downloads the latest public release, checks it, waits until no connection or \
                      temporary exposure is live, then restarts the service on the new version. \
                      If the new version does not start, the previous one is restored."
    )]
    Update,
    /// Check that this program can serve this profile. Run by 'massrelay update' on a download.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[command(hide = true)]
    UpdateSelfCheck,
    /// Finish a prepared update. Run by 'massrelay update' on Windows.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[command(hide = true)]
    UpdateApply {
        /// Finish or undo an interrupted update instead.
        #[arg(long)]
        recover: bool,
    },
    /// Run as the installed background service. Only the Windows service manager starts this.
    #[cfg(windows)]
    #[command(hide = true)]
    Service {
        /// The registered service name.
        name: String,
        #[arg(long)]
        shell: Option<PathBuf>,
    },
    #[command(flatten)]
    Device(private::cli::Command),
}

fn main() {
    let cli =
        Cli::from_arg_matches(&grouped_cli().get_matches()).unwrap_or_else(|error| error.exit());
    #[cfg(windows)]
    let result = match cli.command {
        Some(Command::Service { name, shell }) => serve(cli.state_dir, &name, shell),
        _ => run(cli),
    };
    #[cfg(not(windows))]
    let result = run(cli);
    match result {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(error) => {
            // A runtime failure was already sent to the system log by `run`.
            if private::diagnostics::console() {
                eprintln!("massrelay: {}", visible(&format!("{error:#}")));
            }
            std::process::exit(1);
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("start the async runtime")?
        .block_on(execute(cli))
}

/// Run the device as its Windows service: the ordinary `run` command, started and stopped by
/// the service manager.
#[cfg(windows)]
fn serve(state_dir: Option<PathBuf>, name: &str, shell: Option<PathBuf>) -> Result<i32> {
    let dir = match state_dir {
        Some(dir) => dir,
        None => default_state_dir()?,
    };
    let mut arguments: Vec<std::ffi::OsString> = Vec::new();
    arguments.extend(["massrelay".into(), "--state-dir".into()]);
    arguments.extend([dir.clone().into(), "run".into()]);
    if let Some(shell) = shell {
        arguments.extend(["--shell".into(), shell.into()]);
    }
    let cli = Cli::try_parse_from(arguments)?;
    windows_service::serve(name, dir, move || run(cli))
}

fn grouped_cli() -> clap::Command {
    let command = Cli::command();
    let groups: &[(&str, &[&str])] = &[
        (
            "Set up a network",
            &["create", "join", "invite", "relay-access"],
        ),
        (
            "Manage this device",
            &[
                "status",
                "rename",
                "logs",
                "install",
                "start",
                "restart",
                "stop",
                "update",
                "uninstall",
                "run",
            ],
        ),
        (
            "Find and pair devices",
            &["peers", "approve", "decline", "revoke"],
        ),
        ("Connect to a peer", &["shell", "ssh", "connect", "ping"]),
        (
            "Share services from this device",
            &["enable", "disable", "list", "expose", "ssh-rotate-host-key"],
        ),
        (
            "Operate a relay",
            &[
                "relay",
                "relay-init",
                "relay-info",
                "relay-grants",
                "relay-store",
            ],
        ),
    ];
    let mut help = String::from("{about-with-newline}\n{usage-heading} {usage}\n");
    for &(heading, names) in groups {
        // The relay can only be hosted on Unix.
        if !names
            .iter()
            .any(|name| command.find_subcommand(name).is_some())
        {
            continue;
        }
        writeln!(help, "\n{heading}:").expect("write to string");
        let width = names
            .iter()
            .map(|name| name.len())
            .max()
            .unwrap_or(0)
            .max(12);
        for &name in names {
            if let Some(subcommand) = command.find_subcommand(name) {
                let description = subcommand.get_about().expect("command description");
                writeln!(help, "  {name:width$}  {description}").expect("write to string");
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

    let Some(command) = cli.command else {
        if private::cli::profile_exists(&dir) {
            return private::cli::execute(&dir, private::cli::Command::Status).await;
        }
        grouped_cli().print_help()?;
        println!("\nStart with 'massrelay create' or 'massrelay join'.");
        return Ok(0);
    };
    match command {
        // Only these two change SSH configuration, and each asks first.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::Install(confirmation) => installer::install(&dir, confirmation).await?,
        #[cfg(windows)]
        Command::Install {
            service,
            confirmation,
        } => installer::install(&dir, confirmation, service).await?,
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        Command::Uninstall(confirmation) => installer::uninstall(&dir, confirmation).await?,
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        Command::Start => background_service::control(&dir, ServiceAction::Start)?,
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        Command::Restart => background_service::control(&dir, ServiceAction::Restart)?,
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        Command::Stop => background_service::control(&dir, ServiceAction::Stop)?,
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        Command::Update => return update::run(&dir).await,
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        Command::UpdateSelfCheck => return update::self_check(&dir).await,
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        Command::UpdateApply { recover } => return update::apply_prepared(&dir, recover).await,
        // `main` hands this to the service manager before any runtime exists.
        #[cfg(windows)]
        Command::Service { .. } => anyhow::bail!("the service command cannot be run here"),

        Command::Device(command) => return private::cli::execute(&dir, command).await,
        #[cfg(unix)]
        Command::RelayInit { public_udp, url } => private_relay::init(&dir, public_udp, url)?,
        #[cfg(unix)]
        Command::Relay {
            udp_bind,
            relay_bind,
        } => private_relay::run(dir, udp_bind, relay_bind).await?,
        #[cfg(unix)]
        Command::RelayInfo => private_relay::info(&dir)?,
        #[cfg(unix)]
        Command::RelayGrants(command) => match command {
            RelayGrants::Issue { label } => private_relay::access_issue(&dir, &label)?,
            RelayGrants::List => private_relay::access_list(&dir)?,
            RelayGrants::Revoke { id } => private_relay::access_revoke(&dir, &id)?,
        },
        #[cfg(unix)]
        Command::RelayStore(command) => match command {
            RelayStore::Check => private_relay::store_check(&dir)?,
            RelayStore::Backup { to, final_ } => private_relay::store_backup(&dir, &to, final_)?,
            RelayStore::Restore {
                from,
                relay,
                keep_incarnation,
            } => {
                let relay: EndpointId = relay
                    .trim()
                    .parse()
                    .context("expected the relay's endpoint identity")?;
                private_relay::store_restore(&dir, &from, &relay, keep_incarnation)?
            }
            RelayStore::Rotate { confirm } => {
                anyhow::ensure!(confirm, "pass --confirm to start a new incarnation");
                private_relay::store_rotate(&dir)?
            }
        },
    }
    Ok(0)
}

fn default_state_dir() -> Result<PathBuf> {
    Ok(ProjectDirs::from("", "", "MassRelay")
        .context("cannot find the user state directory; specify --state-dir")?
        .data_local_dir()
        .to_path_buf())
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[derive(Clone, Copy)]
enum ServiceAction {
    Start,
    Restart,
    Stop,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
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
        match ConnectionLog::open(Some(path)) {
            Ok(log) => log.audit(
                "service_control",
                Audit {
                    operation: self.name(),
                    outcome: if result.is_ok() { "allowed" } else { "failed" },
                    reason: result.is_err().then_some("service_manager_failed"),
                    ..Audit::default()
                },
                None,
            ),
            Err(error) => eprintln!("massrelay: could not open service audit log: {error:#}"),
        }
    }
}

fn visible(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
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
            // Pad by hand: a format width panics beyond `u16::MAX`, and names have no limit.
            line.push_str(cell);
            line.extend(std::iter::repeat_n(' ', width - cell.chars().count() + 2));
        }
        println!("{line}{last}");
    }
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
    #[cfg(windows)]
    {
        // Under the Windows service manager there is no console. Waiting here is the point
        // at which the runtime is up, so it reports the service as running, and the service
        // manager's stop request ends the wait.
        if windows_service::serving() {
            windows_service::until_stopped().await;
            return Ok(());
        }
        tokio::signal::ctrl_c().await
    }
    #[cfg(not(any(unix, windows)))]
    tokio::signal::ctrl_c().await
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
