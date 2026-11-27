//! `massrelay install` and `massrelay uninstall`.
//!
//! Each first reads what it would change and prints it, and changes nothing until that is
//! confirmed. Every step leaves alone what is already as it should be, so a command that
//! failed partway can be run again. The steps belong to `background_service`, `ssh_install`
//! (this account's OpenSSH client) and `host_ssh` (the system's SSH server).

use std::io::{self, BufRead, IsTerminal as _, Write};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};

#[cfg(windows)]
use crate::windows_service::InstallOptions;
use crate::{
    private::{cli, pairing::Owner},
    ssh_install,
};

use crate::{background_service as service, host_ssh, private::runtime};

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

pub async fn install(
    dir: &Path,
    confirmation: Confirmation,
    #[cfg(windows)] options: InstallOptions,
) -> Result<()> {
    ensure!(
        cli::profile_exists(dir),
        "no device profile in {}; run 'massrelay create' or 'massrelay join' first",
        dir.display()
    );
    let dir = ssh_install::canonical(dir)?;
    let daemon = service::plan_install(
        &dir,
        #[cfg(windows)]
        options,
    )?;
    let client = ssh_install::describe_register(&dir)?;
    // A device without a usable system SSH server still gets the rest. Any other refusal,
    // such as a configuration that is unsafe or unclear, stops the install here.
    let host = match host_ssh::plan_install(&dir) {
        Ok(plan) => Ok(plan),
        Err(error) if error.is::<host_ssh::Unavailable>() => Err(format!("{error:#}")),
        Err(error) => return Err(error),
    };
    let host_changes = match &host {
        Ok(plan) => plan.to_string(),
        Err(reason) => format!(
            "unavailable, so nothing is changed here: {reason}\n\
             run 'massrelay install' again once that is corrected"
        ),
    };
    confirmation.ask(&listing(
        &format!("Installing MassRelay for {} will:", dir.display()),
        &[
            ("Background service", daemon.to_string()),
            (
                "OpenSSH aliases for this account's connections to peers",
                client,
            ),
            (
                "Inbound SSH to this device through the system server",
                host_changes,
            ),
        ],
    ))?;

    refuse_hosted_login(&dir, "install").await?;
    let installed = daemon.apply()?;
    ensure!(
        installed == dir,
        "{} was replaced while it was being installed",
        dir.display()
    );
    ssh_install::register(&installed)?;
    match host {
        Ok(plan) => plan.apply().context(
            "the background service is installed, but system SSH access to this device is not \
             set up. Correct this and run 'massrelay install' again",
        ),
        Err(reason) => {
            println!(
                "Inbound SSH setup is unavailable: {}",
                crate::visible(&reason)
            );
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

    refuse_hosted_login(&dir, "uninstall").await?;
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

/// Restarting or removing the service ends the logins it carries.
async fn refuse_hosted_login(state_dir: &Path, action: &str) -> Result<()> {
    let profile = state_dir.join(cli::DIR_NAME);
    let shell = std::env::var(crate::private::HOST_ENV)
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    let carried = async {
        if let Some(pid) = shell
            && profile.join(runtime::CONTROL.marker).try_exists()?
        {
            let identity =
                tokio::time::timeout(crate::wire::RPC_TIMEOUT, crate::update::identify(&profile))
                    .await
                    .context("identify the running MassRelay service")??;
            if identity.pid == pid {
                return Ok(true);
            }
        }
        runtime::is_local_ssh_tunnel(&profile).await
    }
    .await
    .with_context(|| {
        format!(
            "cannot tell whether this session depends on MassRelay; run 'massrelay {action}' \
             from a local terminal"
        )
    })?;
    ensure!(
        !carried,
        "this session is carried by MassRelay and would end during this command. Run \
         'massrelay {action}' from a local terminal or another kind of remote session"
    );
    Ok(())
}

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
