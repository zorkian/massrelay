//! `massrelay install` and `massrelay uninstall`.
//!
//! Each first reads what it would change and prints it, and changes nothing until that is
//! confirmed. Every step leaves alone what is already as it should be, so a command that
//! failed partway can be run again. The steps belong to `background_service`, `ssh_install`
//! (this account's OpenSSH client) and `host_ssh` (the system's SSH server).
//!
//! An install can be asked for in a session that depends on MassRelay: its shell, or an SSH
//! login it carries. A service that is already exactly as the install would make it is then
//! left running. Otherwise the steps that can end the session go to a separate process of the
//! platform's own kind, as `update` uses, which makes only what was confirmed ([`Handoff`]).
//! Steps that need this terminal stay in the session: a password, and outside Windows the
//! system SSH server, since `sudo` asks there and reloading that server ends no login.

use std::io::{self, BufRead, IsTerminal as _, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

#[cfg(windows)]
use crate::windows_service::InstallOptions;
use crate::{
    private::{cli, pairing::Owner},
    ssh_install,
};

use crate::{
    background_service as service, host_ssh,
    private::runtime::{self, Identity},
    update::{self, say},
};

/// Set for the process that finishes an install alone. Outside Windows its value is the
/// approval; Windows hands that over, with any password, on the process's input.
pub(crate) const QUEUED: &str = "MASSRELAY_QUEUED_INSTALL";

/// How long the finishing process leaves the command that queued it to say so, before it may
/// cut the session carrying those words.
const HANDOFF_GRACE: Duration = Duration::from_secs(3);

/// How a service manager's registration shows that what it started serves: `serves`, given
/// the program when it has to be that one. Only a finishing process, which no one watches,
/// asks this; another command has `None`.
pub(crate) type Verify<'a> = Option<&'a dyn Fn(Option<&Path>) -> Result<()>>;

/// What the process finishing a confirmed install is given.
pub(crate) struct Handoff {
    /// `Plan::approval` of what was confirmed.
    pub approval: String,
    /// The account's password, when Windows is to register the service. It passes through
    /// the pipe between the two processes only.
    #[cfg(windows)]
    pub password: Option<crate::windows_service::Secret>,
}

#[derive(clap::Args)]
pub struct Confirmation {
    /// Make the listed changes without MassRelay asking. Password and operating system
    /// prompts still apply.
    #[arg(short, long)]
    pub yes: bool,
}

impl Confirmation {
    /// Show `changes` and return only if they are to be made.
    fn ask(&self, changes: &str) -> Result<()> {
        // An answer counts only from someone who can have read the question.
        let terminal = io::stdin().is_terminal() && io::stdout().is_terminal();
        confirm(
            changes,
            self.yes,
            terminal,
            &mut io::stdin().lock(),
            &mut io::stdout().lock(),
        )
    }
}

/// Input is read only to answer the question: otherwise it belongs to what follows, such as
/// `--password-stdin`.
fn confirm(
    changes: &str,
    yes: bool,
    terminal: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    writeln!(output, "{changes}").context("show the changes")?;
    output.flush().context("show the changes")?;
    if yes {
        return Ok(());
    }
    ensure!(
        terminal,
        "nothing was changed: there is no terminal to confirm on. To make these changes, run \
         the command again with --yes"
    );
    write!(output, "Proceed? [y/N] ")?;
    output.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer).context("read the answer")?;
    let answer = answer.trim();
    ensure!(
        answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"),
        "cancelled; nothing was changed"
    );
    Ok(())
}

/// The changes under their headings, one to a line.
fn listing(introduction: &str, sections: &[(&str, String)]) -> String {
    let mut text = format!("{}\n", crate::visible(introduction));
    for (heading, changes) in sections {
        text.push_str(&format!("\n{heading}\n"));
        for line in changes.lines() {
            // Nothing in a path may restyle the terminal or overwrite what is shown.
            text.push_str(&format!("  {}\n", crate::visible(line)));
        }
    }
    text
}

/// Everything an install would do.
struct Plan {
    daemon: service::InstallPlan,
    client: String,
    /// Or why system SSH cannot be set up here.
    host: Result<host_ssh::InstallPlan, String>,
}

impl Plan {
    /// Look, changing nothing. With `host_done`, system SSH was dealt with before a handoff
    /// and is not looked at again.
    fn read(dir: &Path, host_done: bool, #[cfg(windows)] options: InstallOptions) -> Result<Self> {
        let daemon = service::plan_install(
            dir,
            #[cfg(windows)]
            options,
        )?;
        let client = ssh_install::describe_register(dir)?;
        // A device without a usable system SSH server still gets the rest. Any other refusal,
        // such as a configuration that is unsafe or unclear, stops the install here.
        let host = if host_done {
            Err(String::new())
        } else {
            match host_ssh::plan_install(dir) {
                Ok(plan) => Ok(plan),
                Err(error) if error.is::<host_ssh::Unavailable>() => Err(format!("{error:#}")),
                Err(error) => return Err(error),
            }
        };
        Ok(Self {
            daemon,
            client,
            host,
        })
    }

    /// What ties a finishing process to a confirmation: a digest of what it is left to do.
    /// Outside Windows system SSH is not part of that, being set up before the handoff.
    fn approval(&self) -> String {
        let host = cfg!(windows).then(|| match &self.host {
            Ok(plan) => plan.approval(),
            Err(reason) => reason.clone(),
        });
        let daemon = self.daemon.approval();
        digest(
            [env!("CARGO_PKG_VERSION"), &daemon, &self.client]
                .into_iter()
                .chain(host.as_deref()),
        )
    }
}

fn digest<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        // Lengths keep one part from passing for the start of the next.
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    format!("{:x}", digest.finalize())
}

/// Whether an install from a session that depends on MassRelay must be finished by another
/// process: when the service is to be restarted, and for an SSH login on Windows, where
/// restarting the system's server can end it.
fn handed_over(kept: bool, ssh: bool, windows: bool) -> bool {
    !kept || (windows && ssh)
}

pub async fn install(
    dir: &Path,
    confirmation: Confirmation,
    #[cfg(windows)] options: InstallOptions,
) -> Result<()> {
    // Before anything else reads standard input: a process an install queued waits there.
    let handoff = handoff()?;
    ensure!(
        cli::profile_exists(dir),
        "no device profile in {}; run 'massrelay create' or 'massrelay join' first",
        dir.display()
    );
    let dir = ssh_install::canonical(dir)?;
    if handoff.is_some() {
        ensure!(
            carried(&dir, "install").await?.is_none(),
            "the process that was to finish the install still depends on MassRelay; it \
             changed nothing"
        );
        tokio::time::sleep(HANDOFF_GRACE).await;
    }
    let plan = Plan::read(
        &dir,
        cfg!(unix) && handoff.is_some(),
        #[cfg(windows)]
        options,
    )?;
    match handoff {
        Some(handoff) => finish(&dir, plan, handoff).await,
        None => confirmed(&dir, plan, confirmation).await,
    }
}

#[cfg(windows)]
fn handoff() -> Result<Option<Handoff>> {
    service::handoff()
}

#[cfg(unix)]
fn handoff() -> Result<Option<Handoff>> {
    match std::env::var(QUEUED) {
        Ok(approval) => Ok(Some(Handoff { approval })),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error).context(QUEUED),
    }
}

/// Show the plan, and once it is confirmed carry it out or hand it over.
async fn confirmed(dir: &Path, mut plan: Plan, confirmation: Confirmation) -> Result<()> {
    let session = carried(dir, "install").await?;
    if let Some(session) = &session {
        plan.daemon.carried_by(&session.runtime)?;
    }
    let separate = session
        .as_ref()
        .is_some_and(|session| handed_over(plan.daemon.keeps(), session.ssh, cfg!(windows)));
    let approval = plan.approval();
    let host_changes = match &plan.host {
        Ok(plan) => plan.to_string(),
        Err(reason) => format!(
            "unavailable, so nothing is changed here: {reason}\n\
             run 'massrelay install' again once that is corrected"
        ),
    };
    let mut sections = vec![
        ("Background service", plan.daemon.to_string()),
        (
            "OpenSSH aliases for this account's connections to peers",
            plan.client.clone(),
        ),
        (
            "Inbound SSH to this device through the system server",
            host_changes,
        ),
    ];
    if separate {
        let order = if cfg!(windows) {
            "After you confirm, and give any password asked for, a separate process makes all \
             of these changes"
        } else {
            "Inbound SSH is set up first, here. Then a separate process installs the service \
             and the aliases"
        };
        sections.push((
            "This session depends on MassRelay, and may end during these changes",
            format!(
                "{order}, whether or not this session is still open\n\
                 Reconnect afterwards. Its log: {}",
                plan.daemon.log()
            ),
        ));
    }
    confirmation.ask(&listing(
        &format!("Installing MassRelay for {} will:", dir.display()),
        &sections,
    ))?;

    ensure!(
        carried(dir, "install").await? == session,
        "what this session depends on changed after the changes were shown; nothing was \
         changed. Run 'massrelay install' again"
    );
    // A session that goes away must not stop a change to the system's server half way.
    #[cfg(unix)]
    if session.is_some() {
        // SAFETY: ignoring a signal installs no handler.
        unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
    }
    if !separate {
        let installed = plan.daemon.apply()?;
        return connect(dir, &installed, plan.host);
    }
    #[cfg(unix)]
    set_up_host(plan.host).context(
        "system SSH access to this device is not set up, so the service and aliases were left \
         as they were. Correct this and run 'massrelay install' again",
    )?;
    let log = plan.daemon.queue(&approval).context(
        "the install was not handed over, so the service and aliases were left as they were",
    )?;
    say(format!(
        "Queued. A separate process is finishing the install; this session may now end.\n\
         Reconnect afterwards.\n\
         Install log     {}",
        crate::visible(&log)
    ));
    Ok(())
}

/// In the process an install queued: make what was confirmed, if it is still what an install
/// would do.
async fn finish(dir: &Path, plan: Plan, handoff: Handoff) -> Result<()> {
    let mut plan = plan;
    // On Unix this rechecks the registration we would have to restart on rollback.
    // On Windows a passwordless handoff must still resolve to the same keep plan.
    #[cfg(unix)]
    let check_running = true;
    #[cfg(windows)]
    let check_running = handoff.password.is_none();
    if check_running {
        let runtime = tokio::time::timeout(
            crate::wire::RPC_TIMEOUT,
            update::identify(&dir.join(cli::DIR_NAME)),
        )
        .await
        .context("identify the running MassRelay service")??;
        plan.daemon.carried_by(&runtime)?;
    }
    ensure!(
        plan.approval() == handoff.approval,
        "what this install would do is no longer what was confirmed, so nothing was changed. \
         Run 'massrelay install' again"
    );
    // Waiting for the runtime to answer blocks.
    let installed = tokio::task::block_in_place(|| {
        plan.daemon.finish(
            #[cfg(windows)]
            handoff,
            &|program: Option<&Path>| {
                let host = update::installed_service(dir)?;
                serves(host.as_ref(), program, update::Timing::default())
            },
        )
    })?;
    #[cfg(unix)]
    register(dir, &installed)?;
    #[cfg(windows)]
    connect(dir, &installed, plan.host)?;
    say("MassRelay installation finished.");
    Ok(())
}

/// What follows the service: this account's aliases, then system SSH.
fn connect(
    dir: &Path,
    installed: &Path,
    host: Result<host_ssh::InstallPlan, String>,
) -> Result<()> {
    register(dir, installed)?;
    set_up_host(host).context(
        "the background service is installed, but system SSH access to this device is not \
         set up. Correct this and run 'massrelay install' again",
    )
}

fn register(dir: &Path, installed: &Path) -> Result<()> {
    ensure!(
        installed == dir,
        "{} was replaced while it was being installed",
        dir.display()
    );
    ssh_install::register(installed)
}

fn set_up_host(host: Result<host_ssh::InstallPlan, String>) -> Result<()> {
    match host {
        Ok(plan) => plan.apply(),
        Err(reason) => {
            say(format!(
                "Inbound SSH setup is unavailable: {}",
                crate::visible(&reason)
            ));
            Ok(())
        }
    }
}

pub async fn uninstall(dir: &Path, confirmation: Confirmation) -> Result<()> {
    let dir = ssh_install::canonical(dir)?;
    let daemon = service::plan_uninstall(&dir)?;
    let host = host_ssh::plan_uninstall(&dir)?;
    let client = ssh_install::plan_uninstall(&dir)?;
    confirmation.ask(&listing(
        &format!(
            "Uninstalling MassRelay for {} keeps its enrollment, device keys, logs and \
             program. It will:",
            dir.display()
        ),
        &[
            ("Background service", daemon.to_string()),
            (
                "Inbound SSH to this device through the system server",
                host.to_string(),
            ),
            (
                "OpenSSH aliases for this account's connections to peers",
                client.to_string(),
            ),
        ],
    ))?;

    ensure!(
        carried(&dir, "uninstall").await?.is_none(),
        "this session is carried by MassRelay and would end during this command. Run \
         'massrelay uninstall' from a local terminal or another kind of remote session"
    );
    // First, so that no service is left running to write what is removed next.
    daemon.apply().context(
        "the background service was not removed, so its SSH setup was left in place. Correct \
         this and run 'massrelay uninstall' again",
    )?;
    let _stopped = stopped_runtime(&dir)?;
    // Neither removal depends on the other, so one failing does not strand the other.
    both(
        host.apply()
            .context("system SSH access to this device was not removed completely"),
        client
            .apply()
            .context("this account's OpenSSH aliases were not removed completely"),
    )
    .context("run 'massrelay uninstall' again to finish")?;
    Ok(())
}

/// A session that depends on the profile's runtime, which replacing its service ends.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Carried {
    runtime: Identity,
    /// An SSH login the runtime carries to the system's server, which also ends with that
    /// server. Otherwise the runtime's own shell.
    ssh: bool,
}

/// How this command's session depends on the profile in `state_dir`, if it does.
async fn carried(state_dir: &Path, action: &str) -> Result<Option<Carried>> {
    let profile = state_dir.join(cli::DIR_NAME);
    let shell = std::env::var(crate::private::HOST_ENV)
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    async {
        if let Some(runtime) = runtime::local_ssh_tunnel(&profile).await? {
            return Ok(Some(Carried { runtime, ssh: true }));
        }
        if let Some(pid) = shell
            && profile.join(runtime::CONTROL.marker).try_exists()?
        {
            let identity =
                tokio::time::timeout(crate::wire::RPC_TIMEOUT, crate::update::identify(&profile))
                    .await
                    .context("identify the running MassRelay service")??;
            if identity.pid == pid {
                return Ok(Some(Carried {
                    runtime: identity,
                    ssh: false,
                }));
            }
        }
        anyhow::Ok(None)
    }
    .await
    .with_context(|| {
        format!(
            "cannot tell whether this session depends on MassRelay; run 'massrelay {action}' \
             from a local terminal"
        )
    })
}

/// Whether `runtime` is this very program, as `binary`, serving normally.
pub(crate) fn is_this_program(runtime: &Identity, binary: &Path) -> bool {
    let same = || {
        let running = Path::new(runtime.executable.as_deref()?)
            .canonicalize()
            .ok()?;
        Some(running == binary.canonicalize().ok()?)
    };
    !runtime.held && runtime.version == env!("CARGO_PKG_VERSION") && same() == Some(true)
}

/// Wait until the installed service answers: the service manager's process, on the profile's
/// authenticated control channel. With `program`, it has to be running that very program.
pub(crate) fn serves(
    host: &dyn update::Host,
    program: Option<&Path>,
    timing: update::Timing,
) -> Result<()> {
    let runtime = update::await_service(host, timing)?;
    if let Some(program) = program {
        ensure!(
            is_this_program(&runtime, program),
            "the service answers as MassRelay {} from {}, not as {} from {}",
            crate::visible(&runtime.version),
            crate::visible(
                runtime
                    .executable
                    .as_deref()
                    .unwrap_or("an unnamed program")
            ),
            env!("CARGO_PKG_VERSION"),
            program.display()
        );
    }
    Ok(())
}

/// Why an install refuses a session of a runtime that its service does not run.
pub(crate) const NOT_THE_SERVICE: &str = "this session depends on a MassRelay runtime that \
    is not this profile's installed service (such as 'massrelay run'), which an install would \
    have to stop, ending the session. Nothing was changed. Run 'massrelay install' from a \
    local terminal or another kind of remote session";

/// Hold the profile so that no runtime can start while its SSH files are removed.
fn stopped_runtime(state_dir: &Path) -> Result<Option<Owner>> {
    if !state_dir.join(cli::DIR_NAME).is_dir() {
        return Ok(None);
    }
    cli::claim_owner(state_dir).map(Some).context(
        "the service was removed, but this profile is still running. Stop 'massrelay run', \
         then run 'massrelay uninstall' again",
    )
}

/// Report every failure of two independent steps.
fn both(first: Result<()>, second: Result<()>) -> Result<()> {
    match (first, second) {
        (Err(first), Err(second)) => bail!("{first:#}; {second:#}"),
        (first, second) => first.and(second),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether the changes would be made, and how much of the input was left unread.
    fn answered(yes: bool, terminal: bool, input: &str) -> (bool, usize) {
        let mut unread = input.as_bytes();
        let result = confirm("changes", yes, terminal, &mut unread, &mut Vec::new());
        (result.is_ok(), unread.len())
    }

    #[test]
    fn changes_are_made_only_when_confirmed() {
        for accepted in ["y\n", "Y\r\n", " yes \n", "YES"] {
            assert!(answered(false, true, accepted).0, "{accepted:?}");
        }
        for declined in ["", "\n", "n\n", "no\n", "yess\n", "ok\n", "\ny\n"] {
            assert!(!answered(false, true, declined).0, "{declined:?}");
        }
        // Without a terminal nothing piped in counts as an answer, or is consumed.
        assert_eq!(answered(false, false, "y\n"), (false, 2));
        // --yes leaves all of the input, such as a password, for what follows.
        assert_eq!(answered(true, false, "secret\n"), (true, 7));
        assert_eq!(answered(true, true, "secret\n"), (true, 7));
        // One line answers; what was typed after it stays.
        assert_eq!(answered(false, true, "y\nsecret\n"), (true, 7));
    }
}
