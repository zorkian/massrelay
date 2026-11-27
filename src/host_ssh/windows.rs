//! The system OpenSSH server on Windows: the OpenSSH Server optional feature's `sshd`
//! service, configured in `ProgramData\ssh\sshd_config`.
//!
//! `massrelay install` already runs elevated on Windows, so nothing here raises its rights.
//! System programs are run by their full paths in the system directory, and a plan bounds
//! the time of each. The configuration, its directory and every directory above must be
//! controlled by the system and administrators alone, without a link or mount point, before
//! anything is staged or replaced there. A new configuration is created in that directory and
//! replaces the old one keeping its access list. A file in that directory which only
//! administrators can open is the machine's lock on these changes.
//!
//! This file holds the decisions, which are compiled and tested on every platform. `native`
//! makes the Win32 calls.

use std::{
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};

use super::{
    Purpose, Unavailable, check_version, scanned_key,
    setup::{Access, Held, Reload, Staged, System},
    valid_user,
};
use crate::update::{Finished, run_within};

#[cfg(windows)]
mod native;
/// Stand-ins that let this file be compiled and tested elsewhere.
#[cfg(not(windows))]
mod native {
    use std::{fs::Metadata, path::Path, path::PathBuf, time::Duration};

    use anyhow::{Result, bail};

    pub fn known_directories() -> Result<(PathBuf, PathBuf)> {
        bail!("not Windows")
    }

    pub fn replace_file(target: &Path, replacement: &Path) -> Result<()> {
        Ok(std::fs::rename(replacement, target)?)
    }

    /// Stands for the access check: anything under a directory named `untrusted` fails.
    pub fn check_system_path(path: &Path, _: bool) -> Result<()> {
        if path
            .components()
            .any(|part| part.as_os_str() == "untrusted")
        {
            bail!("another account can change {}", path.display());
        }
        Ok(())
    }

    pub fn lock_system(path: &Path, _: Duration) -> Result<std::fs::File> {
        check_system_path(path, false)?;
        Ok(std::fs::File::create(path)?)
    }

    pub fn check_managed_file(_: &Path) -> Result<()> {
        Ok(())
    }

    pub fn check_private_directory(_: &Path) -> Result<()> {
        Ok(())
    }

    pub fn plain(path: &Path) -> Result<PathBuf> {
        Ok(path.to_owned())
    }

    pub fn is_reparse(metadata: &Metadata) -> bool {
        metadata.is_symlink()
    }
}

const SERVICE: &str = "sshd";
/// Bound on a question asked while planning.
const LIMIT: Duration = Duration::from_secs(15);
/// How long another change to the server is waited for.
const LOCK_WAIT: Duration = Duration::from_secs(60);
const LOCK_FILE: &str = "massrelay-setup.lock";
/// The Windows error number for a service that does not exist.
const NO_SUCH_SERVICE: &str = "1060";
const PROGRAM_DATA: &str = "__PROGRAMDATA__";
const ELEVATE: &str = "run this in an elevated PowerShell (Run as administrator)";
const HINT: &str = "In an elevated PowerShell run 'Add-WindowsCapability -Online -Name \
                    OpenSSH.Server~~~~0.0.1.0', 'Set-Service sshd -StartupType Automatic' \
                    and 'Start-Service sshd', then run 'massrelay install' again.";

fn absent(server: &Path) -> anyhow::Error {
    Unavailable(format!(
        "there is no OpenSSH server at {}. {HINT}",
        server.display()
    ))
    .into()
}

pub(super) struct Windows {
    user: String,
    /// The system directory, `System32`.
    system: PathBuf,
    /// `ProgramData`.
    data: PathBuf,
    config: PathBuf,
}

impl Windows {
    pub(super) fn native(purpose: Purpose) -> Result<Self> {
        let (system, data) = native::known_directories()?;
        // Said before anything about the account: without a server nothing else matters.
        let server = system.join("OpenSSH").join("sshd.exe");
        if purpose == Purpose::Install && !server.is_file() {
            return Err(absent(&server));
        }
        let said = |program: &str| -> Result<String> {
            let output = run_within(&mut Command::new(system.join(program)), LIMIT)
                .with_context(|| format!("run {program}"))?;
            ensure!(output.success, "{program} failed");
            Ok(output.stdout.trim().to_owned())
        };
        let user = local_user(&said("whoami.exe")?, &said("hostname.exe")?)?;
        let config = data.join("ssh").join("sshd_config");
        Ok(Self {
            user,
            system,
            data,
            config,
        })
    }

    fn openssh(&self, name: &str) -> PathBuf {
        self.system.join("OpenSSH").join(name)
    }

    fn service_control(&self, verb: &str) -> Result<Finished> {
        let mut command = Command::new(self.system.join("sc.exe"));
        command.args([verb, SERVICE]);
        run_within(&mut command, LIMIT).context("ask Windows about the sshd service")
    }

    /// The registered `sshd` service must be the system's server, with no arguments of its
    /// own, and running.
    fn check_service(&self) -> Result<()> {
        let configured = self.service_control("qc")?;
        // `sc.exe` prints the error number whatever the language.
        if !configured.success && configured.stdout.contains(NO_SUCH_SERVICE) {
            return Err(Unavailable(format!(
                "the Windows 'sshd' service is not installed. {}",
                self.enable_hint()
            ))
            .into());
        }
        ensure!(
            configured.success,
            "could not read the sshd service's configuration"
        );
        check_program(&configured.stdout, &self.openssh("sshd.exe"))?;
        let state = self.service_control("query")?;
        ensure!(state.success, "could not query the sshd service");
        if !is_running(&state.stdout)? {
            return Err(Unavailable(format!(
                "the Windows 'sshd' service is not running. {}",
                self.enable_hint()
            ))
            .into());
        }
        Ok(())
    }
}

/// The login name of a local account from `whoami`'s `machine\user`.
fn local_user(account: &str, host: &str) -> Result<String> {
    let (domain, user) = account
        .split_once('\\')
        .context("Windows did not name this account")?;
    // The computer name used in account names holds at most 15 characters.
    let machine: String = host.chars().take(15).collect();
    ensure!(
        domain.eq_ignore_ascii_case(&machine),
        "system SSH setup supports local Windows accounts only, and {account} is not one"
    );
    // The server compares account names in lower case.
    let user = user.to_ascii_lowercase();
    ensure!(valid_user(&user), "unsupported SSH account name {user:?}");
    Ok(user)
}

/// Check the program `sc qc` reports.
fn check_program(configured: &str, expected: &Path) -> Result<()> {
    let program = configured
        .lines()
        .find_map(|line| line.trim().strip_prefix("BINARY_PATH_NAME"))
        .and_then(|rest| rest.trim_start().strip_prefix(':'))
        .context("Windows did not report the sshd service's program")?
        .trim();
    let unquoted = program
        .strip_prefix('"')
        .and_then(|program| program.strip_suffix('"'))
        .unwrap_or(program);
    ensure!(
        expected
            .to_str()
            .is_some_and(|expected| unquoted.eq_ignore_ascii_case(expected)),
        "the sshd service runs {program}. MassRelay only sets up the OpenSSH Server Windows \
         provides, started without arguments: {}",
        expected.display()
    );
    Ok(())
}

fn is_running(state: &str) -> Result<bool> {
    let code = state.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        if label.trim() != "STATE" {
            return None;
        }
        value.split_ascii_whitespace().next()
    });
    match code {
        Some("1") => Ok(false),
        Some("4") => Ok(true),
        _ => bail!("could not establish whether the Windows sshd service is stopped or running"),
    }
}

impl System for Windows {
    fn user(&self) -> &str {
        &self.user
    }

    fn other_user(&self) -> &str {
        if self.user == "administrator" {
            "guest"
        } else {
            "administrator"
        }
    }

    fn config(&self) -> &Path {
        &self.config
    }

    fn canonical(&self, path: &Path) -> Result<PathBuf> {
        let path = path
            .canonicalize()
            .with_context(|| format!("resolve {}", path.display()))?;
        native::plain(&path)
    }

    fn installed(&self) -> Result<()> {
        let server = self.openssh("sshd.exe");
        if !server.is_file() {
            return Err(absent(&server));
        }
        // Some versions exit with an error here, after printing their version.
        let output = run_within(Command::new(server).arg("-V"), LIMIT)
            .context("ask the SSH server its version")?;
        check_version(&format!("{}{}", output.stdout, output.stderr))
    }

    fn check_key_file(&self, path: &Path) -> Result<()> {
        let directory = path.parent().context("the key file has no directory")?;
        native::check_private_directory(directory)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file() && !native::is_reparse(&metadata),
                    "{} is not a regular file",
                    path.display()
                );
                // Owned by the account, and open to it and administrators alone.
                native::check_managed_file(path)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("check {}", path.display()));
            }
        }
        Ok(())
    }

    fn key_file_entry(&self, path: &Path) -> Result<String> {
        let text = path
            .to_str()
            .with_context(|| format!("path is not Unicode: {}", path.display()))?
            .replace('\\', "/");
        ensure!(
            !text
                .chars()
                .any(|c| c.is_control() || "\"'%$#*?[]{}".contains(c)),
            "the SSH server cannot be given the path {text}; use a state directory whose path \
             has none of \" ' % $ # * ? [ ] {{ }}"
        );
        Ok(text)
    }

    fn read_config(&self, access: Access) -> Result<Option<Vec<u8>>> {
        self.read(&self.config, access)
    }

    fn read(&self, path: &Path, _: Access) -> Result<Option<Vec<u8>>> {
        if !trusted_config_path(path, false)? {
            return Ok(None);
        }
        fs::read(path)
            .map(Some)
            .with_context(|| format!("read {}; {ELEVATE}", path.display()))
    }

    fn list(&self, directory: &Path, _: Access) -> Result<Vec<String>> {
        if !trusted_config_path(directory, true)? {
            return Ok(Vec::new());
        }
        fs::read_dir(directory)
            .with_context(|| format!("read {}; {ELEVATE}", directory.display()))?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect()
    }

    fn path(&self, written: &str) -> PathBuf {
        match written.strip_prefix(PROGRAM_DATA) {
            Some(rest) => {
                let mut path = self.data.clone();
                path.extend(rest.split(['/', '\\']).filter(|part| !part.is_empty()));
                path
            }
            None => written.into(),
        }
    }

    fn spellings(&self, value: &str) -> Vec<String> {
        let data = self.data.to_string_lossy();
        vec![
            value.to_owned(),
            value.replace(PROGRAM_DATA, &data),
            value.replace(PROGRAM_DATA, &data.replace('\\', "/")),
        ]
    }

    fn sshd(&self, arguments: &[String], access: Access) -> Result<String> {
        let mut command = Command::new(self.openssh("sshd.exe"));
        command.args(arguments).stdin(Stdio::null());
        let (success, stdout, stderr) = match access {
            Access::User => {
                let output = run_within(&mut command, LIMIT).context("run the SSH server")?;
                (output.success, output.stdout, output.stderr)
            }
            Access::Administrator => {
                let output = command.output().context("run the SSH server's test mode")?;
                (
                    output.status.success(),
                    String::from_utf8(output.stdout)
                        .context("the SSH server printed text that is not UTF-8")?,
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                )
            }
        };
        ensure!(
            success,
            "sshd failed (it can read its host keys only when elevated: {ELEVATE}): {}",
            stderr.trim()
        );
        Ok(stdout)
    }

    fn authorize(&self) -> Result<()> {
        // Only an administrator can create a file in the server's directory.
        self.stage(b"").map(drop)
    }

    fn exclusive(&self) -> Result<Held> {
        let directory = self
            .config
            .parent()
            .context("the configuration has no directory")?;
        Ok(Box::new(native::lock_system(
            &directory.join(LOCK_FILE),
            LOCK_WAIT,
        )?))
    }

    fn stage(&self, contents: &[u8]) -> Result<Staged> {
        let directory = self
            .config
            .parent()
            .context("the configuration has no directory")?;
        // Before anything is written there.
        native::check_system_path(directory, true)?;
        // A new file takes the directory's access list, and an elevated process's files
        // belong to the administrators, as the server requires of its configuration.
        let mut file = tempfile::Builder::new()
            .prefix("sshd_config.massrelay-")
            .tempfile_in(directory)
            .with_context(|| format!("create a file in {}; {ELEVATE}", directory.display()))?;
        file.write_all(contents)?;
        file.as_file().sync_all()?;
        let path = file.into_temp_path();
        native::check_system_path(&path, false)?;
        Ok(Staged::new(path.to_path_buf(), move || drop(path)))
    }

    fn replace(&self, staged: Staged, expected: &[u8]) -> Result<()> {
        ensure!(
            self.read_config(Access::Administrator)?.as_deref() == Some(expected),
            "{} changed while it was being updated; it was not replaced",
            self.config.display()
        );
        native::check_system_path(&staged.path, false)?;
        native::replace_file(&self.config, &staged.path)?;
        staged.consumed();
        Ok(())
    }

    fn running(&self) -> Result<()> {
        self.check_service()
    }

    fn reload_method(&self, _: Access) -> Result<Reload> {
        self.check_service()?;
        Ok(Reload::Service(SERVICE.to_owned()))
    }

    fn reload(&self, reload: &Reload) -> Result<()> {
        let Reload::Service(name) = reload else {
            return Ok(());
        };
        ensure!(name == SERVICE, "unexpected service {name}");
        let output = Command::new(
            self.system
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe"),
        )
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Restart-Service -Name sshd -ErrorAction Stop",
        ])
        .stdin(Stdio::null())
        .output()
        .context("restart the sshd service")?;
        if !output.status.success() {
            bail!(
                "restarting the sshd service failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    fn listener_key(&self, port: u16) -> Result<Option<String>> {
        let output = run_within(
            Command::new(self.openssh("ssh-keyscan.exe"))
                .args(["-T", "5", "-t", "ed25519", "-p", &port.to_string()])
                .arg("127.0.0.1"),
            LIMIT,
        )
        .context("run ssh-keyscan; install the Windows OpenSSH Client")?;
        Ok(scanned_key(&output.stdout))
    }

    fn enable_hint(&self) -> &'static str {
        HINT
    }

    fn rights(&self) -> &'static str {
        "this elevated terminal"
    }

    fn describe(&self, _: &Reload) -> String {
        "restart the Windows sshd service (Restart-Service sshd)".to_owned()
    }
}

/// Validate an existing file or directory before reading it. If it is missing, verify
/// the nearest existing directory so an untrusted account cannot add an include later.
fn trusted_config_path(path: &Path, directory: bool) -> Result<bool> {
    for candidate in path.ancestors() {
        match fs::symlink_metadata(candidate) {
            Ok(_) => {
                let found = candidate == path;
                native::check_system_path(candidate, directory || !found)?;
                return Ok(found);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("check {}; {ELEVATE}", candidate.display()));
            }
        }
    }
    bail!("cannot establish ownership of {}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn nothing_is_staged_or_locked_where_other_accounts_could_change_it() -> Result<()> {
        let temp = tempfile::tempdir()?;
        for (name, trusted) in [("ssh", true), ("untrusted", false)] {
            let data = temp.path().join(name);
            let config = data.join("sshd_config");
            fs::create_dir(&data)?;
            fs::write(&config, "Port 22\n")?;
            let windows = Windows {
                user: "sam".into(),
                system: temp.path().to_owned(),
                data: data.clone(),
                config,
            };
            assert_eq!(windows.stage(b"Port 23\n").is_ok(), trusted);
            assert_eq!(windows.exclusive().is_ok(), trusted);
            assert_eq!(windows.read_config(Access::User).is_ok(), trusted);
            assert_eq!(
                windows
                    .read(&data.join("missing.conf"), Access::User)
                    .is_ok(),
                trusted
            );
            assert_eq!(
                windows.list(&data.join("conf.d"), Access::User).is_ok(),
                trusted
            );
            fs::create_dir(data.join("conf.d"))?;
            assert_eq!(
                windows.list(&data.join("conf.d"), Access::User).is_ok(),
                trusted
            );
            let include = data.join("conf.d/local.conf");
            fs::write(&include, "Port 22\n")?;
            assert_eq!(windows.read(&include, Access::User).is_ok(), trusted);
            // A refused staging leaves nothing behind, and a dropped copy goes.
            let names: Vec<_> = fs::read_dir(&data)?
                .map(|entry| Ok(entry?.file_name()))
                .collect::<io::Result<_>>()?;
            assert!(
                names
                    .iter()
                    .all(|name| !name.to_string_lossy().starts_with("sshd_config.")),
                "{names:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn only_a_local_account_and_the_unmodified_system_service_are_set_up() -> Result<()> {
        assert_eq!(
            local_user("desktop-abcdefg\\Sam.Doe", "DESKTOP-ABCDEFGH")?,
            "sam.doe"
        );
        assert!(local_user("corp\\sam", "desktop-1").is_err());
        assert!(local_user("desktop-1\\sam doe", "desktop-1").is_err());

        let server = Path::new(r"C:\Windows\System32\OpenSSH\sshd.exe");
        let report = |program: &str| {
            format!(
                "SERVICE_NAME: sshd\r\n        TYPE               : 10\r\n        \
                 BINARY_PATH_NAME   : {program}\r\n"
            )
        };
        check_program(&report(r"C:\WINDOWS\System32\OpenSSH\sshd.exe"), server)?;
        check_program(&report(r#""C:\Windows\System32\OpenSSH\sshd.exe""#), server)?;
        for other in [
            r"C:\Program Files\OpenSSH\sshd.exe",
            r"C:\Windows\System32\OpenSSH\sshd.exe -f C:\other",
        ] {
            assert!(check_program(&report(other), server).is_err());
        }
        assert!(is_running(
            "SERVICE_NAME: sshd\r\n        STATE              : 4  RUNNING\r\n"
        )?);
        assert!(!is_running("        STATE              : 1  STOPPED\r\n")?);
        assert!(is_running("        STATE              : 3  STOP_PENDING\r\n").is_err());
        assert!(is_running("        ESTADO             : 4  EN_EJECUCIÓN\r\n").is_err());
        assert!(is_running("SERVICE_NAME: sshd\r\n").is_err());
        Ok(())
    }
}
