//! This device's background service on Windows, registered with the Service Control Manager.
//!
//! `massrelay install` registers one auto-start service per state directory. Windows starts it
//! at boot, before anyone signs in, and logs it on as the account that ran the install: the
//! account that enrolled the device. Windows needs that account's password for the logon. It
//! is read at the console without echo (or from standard input with `--password-stdin`), handed
//! to the service manager in memory, and stored by Windows only.
//!
//! The service manager runs `massrelay --state-dir DIR service NAME --shell SHELL`, which is
//! the ordinary `run` command under the service control protocol: it reports "running" once
//! the runtime waits for shutdown, and a stop request ends that wait, so the runtime stops in
//! its usual order. The service controller performs the stop and start for a restart.
//!
//! An install asked for in a session that depends on the service leaves an unchanged, running
//! one alone. Otherwise it asks for the password there and hands what is left, with that
//! password, to a detached process over the pipe that activates it.
//!
//! What the install refuses, so the service cannot be turned against its account:
//!
//! - a program, shell or state directory that another account can modify or replace (checked
//!   on every directory up to the drive root). It never changes permissions to pass the check;
//! - a state directory owned by a different account than the one running the install;
//! - an administrator account, unless `--allow-administrator` is given. Windows gives a
//!   service logon the full administrator token, so peers granted the shell can request an
//!   elevated shell, unlike `massrelay run` in an ordinary terminal.
//!
//! This file holds the decisions, which are tested on every platform. `native` holds the
//! Win32 calls.

use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::{installer, private::runtime::Identity};

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{
    Managed, control, handoff, is_default_shell, managed, plan_install, plan_uninstall,
    private_audit, private_marker, serve, serving, ssh_files, ssh_private_dir, until_stopped,
    wait_for_activation,
};

#[derive(clap::Args)]
pub struct InstallOptions {
    /// Shell for peers with shell access. Defaults to Windows PowerShell.
    #[arg(long, value_name = "PATH")]
    pub shell: Option<PathBuf>,
    /// Read the account password from standard input instead of asking at the console.
    #[arg(long)]
    pub password_stdin: bool,
    /// Accept that an administrator account's service lets peers with shell access request an
    /// elevated shell.
    #[arg(long)]
    pub allow_administrator: bool,
}

/// The service name for a state directory. Service names are shared by every account on the
/// machine, so each profile gets its own.
fn service_name(dir: &str) -> String {
    let hash = format!("{:x}", Sha256::digest(dir.as_bytes()));
    format!("MassRelay-{}", &hash[..16])
}

/// The command line the service manager starts.
fn command_line(binary: &str, dir: &str, name: &str, shell: &str) -> Result<String> {
    Ok(format!(
        "{} {} --shell {}",
        quote(binary)?,
        profile_arguments(dir, name)?,
        quote(shell)?
    ))
}

/// The log of the last update queued from one of this device's shells, in the state
/// directory.
const UPDATE_LOG: &str = "update.log";
/// The same for an install.
const INSTALL_LOG: &str = "install.log";
/// Held, in the state directory, for as long as a queued update, its helper or a queued
/// install runs.
const UPDATE_LOCK: &str = "update.lock";

/// The command line of an update queued from one of this device's shells.
fn update_command_line(binary: &str, dir: &str) -> Result<String> {
    Ok(format!(
        "{} --state-dir {} update",
        quote(binary)?,
        quote(dir)?
    ))
}

/// The command line of a queued install: the confirmed options, with the shell it settled on.
/// The password is not one of them.
fn install_command_line(
    binary: &str,
    dir: &str,
    shell: &str,
    allow_administrator: bool,
) -> Result<String> {
    Ok(format!(
        "{} --state-dir {} install --yes --shell {}{}",
        quote(binary)?,
        quote(dir)?,
        quote(shell)?,
        if allow_administrator {
            " --allow-administrator"
        } else {
            ""
        }
    ))
}

/// A password, or bytes holding one, wiped when dropped.
pub(crate) struct Secret<T: Copy + Default = u16>(Vec<T>);

impl<T: Copy + Default> Drop for Secret<T> {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

fn wipe<T: Copy + Default>(data: &mut [T]) {
    for item in data {
        // SAFETY: `item` is a valid, exclusive reference. The volatile write keeps the
        // compiler from dropping the wipe as a dead store.
        unsafe { std::ptr::write_volatile(item, T::default()) };
    }
}

/// A line of `input`, its newline included, of at most `limit` bytes. It is read a byte at a
/// time, so that nothing past the line is taken and no buffer but the one returned holds it.
/// `input` must not buffer either.
fn read_secret_line(mut input: impl Read, limit: usize) -> std::io::Result<Secret<u8>> {
    let mut line = Secret(Vec::with_capacity(limit));
    let mut byte = [0];
    while line.0.len() < limit && line.0.last() != Some(&b'\n') {
        match input.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => line.0.push(byte[0]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    wipe(&mut byte);
    Ok(line)
}

/// The length of an approval: a SHA-256 digest in hexadecimal.
const APPROVAL: usize = 64;

/// What a queued install is told once it is activated: the approval, then the number of the
/// password's UTF-16 units and those units, its final NUL among them. No units mean that the
/// running service is to be kept.
fn handoff_message(approval: &str, password: Option<&Secret>) -> Result<Secret<u8>> {
    ensure!(approval.len() == APPROVAL, "not an install approval");
    let units = password.map_or(&[][..], |password| &password.0);
    let count = u32::try_from(units.len()).context("the password is too long to hand over")?;
    // Room for all of it at once, so that no copy is left behind by a reallocation.
    let mut message = Secret(Vec::with_capacity(APPROVAL + 4 + units.len() * 2));
    message.0.extend_from_slice(approval.as_bytes());
    message.0.extend_from_slice(&count.to_le_bytes());
    for unit in units {
        message.0.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(message)
}

/// Read a `handoff_message`, which has to be complete.
fn read_handoff(mut message: impl Read) -> Result<(String, Option<Secret>)> {
    const CUT: &str = "the command that queued this install ended before it had handed it \
        over, so nothing was done";
    let mut approval = vec![0; APPROVAL];
    message.read_exact(&mut approval).context(CUT)?;
    let approval = String::from_utf8(approval).context("not an install approval")?;
    let mut count = [0; 4];
    message.read_exact(&mut count).context(CUT)?;
    let count = u32::from_le_bytes(count) as usize;
    if count == 0 {
        return Ok((approval, None));
    }
    let mut bytes = Secret(vec![0u8; count.checked_mul(2).context(CUT)?]);
    message.read_exact(&mut bytes.0).context(CUT)?;
    let mut password = Secret(Vec::with_capacity(count));
    password.0.extend(
        bytes
            .0
            .as_chunks()
            .0
            .iter()
            .map(|&unit| u16::from_le_bytes(unit)),
    );
    ensure!(
        password.0.last() == Some(&0),
        "the password handed over is not terminated"
    );
    Ok((approval, Some(password)))
}

/// The byte that lets a queued process act.
const ACTIVATE: u8 = b'+';

/// Wait up to `limit` for the activating byte on `gate`, and return the gate. The command
/// that queued this process holds the only other end, so if that command ends first, however
/// it ends, the pipe closes.
fn await_activation<R: Read + Send + 'static>(mut gate: R, limit: Duration) -> Result<R> {
    let (send, received) = mpsc::channel();
    // A pipe read has no time limit. A reader left waiting ends with the process.
    thread::spawn(move || {
        let mut byte = [0];
        let read = gate.read_exact(&mut byte).map(|()| byte[0]);
        let _ = send.send((read, gate));
    });
    match received.recv_timeout(limit) {
        Ok((Ok(ACTIVATE), gate)) => Ok(gate),
        _ => anyhow::bail!("the command that queued this did not activate it, so nothing was done"),
    }
}

/// Start a queued update writing to `log`, a new file of its own, and only once it is
/// activated make that file `latest`. Returns where the log is. A refused start removes the new file and
/// leaves `latest` as it was. If `latest` cannot be replaced (Windows refuses while a program
/// holds it open), the update is already active, so its log stays under its own name.
fn start_logged(
    log: NamedTempFile,
    latest: &Path,
    start: impl FnOnce(&File) -> Result<()>,
) -> Result<PathBuf> {
    start(log.as_file())?;
    Ok(match log.persist(latest) {
        Ok(_) => latest.to_owned(),
        Err(refused) => {
            let mut log = refused.file;
            log.disable_cleanup(true);
            log.path().to_owned()
        }
    })
}

/// The UTF-16 environment block of a queued update: `variables` without those that place it
/// in a session (the runtime serving this shell, the ends of this SSH login), each
/// NUL-terminated and sorted by name ignoring case, then one more NUL.
fn environment_block(
    variables: impl Iterator<Item = (OsString, OsString)>,
    encode: impl Fn(&OsStr) -> Vec<u16>,
) -> Vec<u16> {
    let mut variables: Vec<_> = variables
        .filter(|(name, _)| {
            [crate::private::HOST_ENV, crate::private::SSH_ENV]
                .iter()
                .all(|session| !name.eq_ignore_ascii_case(session))
        })
        .collect();
    variables.sort_by_cached_key(|(name, _)| name.to_string_lossy().to_uppercase());
    let mut block = Vec::new();
    for (name, value) in variables {
        block.extend(encode(&name));
        block.push(u16::from(b'='));
        block.extend(encode(&value));
        block.push(0);
    }
    // An empty block is still two NULs.
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

/// The part of the command line that identifies a profile's service.
fn profile_arguments(dir: &str, name: &str) -> Result<String> {
    Ok(format!("--state-dir {} service {name}", quote(dir)?))
}

/// Whether an existing service's command line was written by `install` for this profile.
fn is_profile_service(command: &str, dir: &str, name: &str) -> bool {
    profile_arguments(dir, name).is_ok_and(|arguments| {
        command.starts_with('"') && command.contains(&format!("\" {arguments} "))
    })
}

/// A registered service, as `uninstall` finds it.
struct Registered<'a> {
    command: &'a str,
    /// Whether it logs on as the account removing it.
    own_account: bool,
    /// Its process, while it has one.
    process: Option<u32>,
}

/// Refuse to remove anything but this profile's own service, from a command that its end would
/// not take along, while no update is working on it. `shell_host` is the runtime serving the
/// MassRelay shell the command says it is in.
fn check_removable(
    service: &Registered,
    dir: &str,
    name: &str,
    shell_host: Option<u32>,
    updating: bool,
) -> Result<()> {
    ensure!(
        is_profile_service(service.command, dir, name),
        "another service uses the name {name}; nothing was changed"
    );
    ensure!(
        service.own_account,
        "the service {name} runs under another account; nothing was changed"
    );
    ensure!(
        service.process.is_none() || service.process != shell_host,
        "this command runs in a MassRelay shell on this device, which ends with the service it \
         would remove. Nothing was changed. Run 'massrelay uninstall' from an elevated \
         PowerShell on this device"
    );
    ensure!(
        !updating,
        "an update or install of this service is queued or running; nothing was changed. Run \
         'massrelay uninstall' once it has finished"
    );
    Ok(())
}

/// What tells one registration of a service from another, as far as the service manager
/// says: not whether or as which process it runs.
#[derive(Debug, PartialEq, Eq)]
struct Registration {
    command: String,
    account: String,
    start: u32,
}

/// A removal as shown for confirmation, which displays as the changes it would make. Only
/// Windows makes one, with `plan_uninstall`, and applies it.
pub struct UninstallPlan {
    /// The canonical state directory, and the service name `install` gives it.
    dir: String,
    name: String,
    shown: Option<Registration>,
}

impl UninstallPlan {
    /// `found` is what is registered under `name` now, inspected for removal, with the means
    /// to remove it. Hands those back only if this is what was shown.
    fn confirm<S>(&self, name: &str, found: Option<(Registration, S)>) -> Result<Option<S>> {
        ensure!(
            name == self.name && found.as_ref().map(|(found, _)| found) == self.shown.as_ref(),
            "the background service is no longer as it was shown, so it was not touched. Run \
             'massrelay uninstall' again"
        );
        Ok(found.map(|(_, service)| service))
    }
}

impl fmt::Display for UninstallPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let Self { dir, name, shown } = self;
        match shown {
            Some(Registration {
                command, account, ..
            }) => write!(
                formatter,
                "Delete the Windows service {name}, which runs as {account}, and stop it\n\
                 Command line: {command}\n\
                 Keep the device profile, keys and logs in {dir}\n\
                 Keep the account's right to log on as a service"
            ),
            None => write!(
                formatter,
                "No Windows service to remove for the profile in {dir}: {name} is not registered"
            ),
        }
    }
}

/// What a confirmation of an install approves: the registration to be made, and what it was
/// found over.
#[derive(Debug, PartialEq, Eq)]
struct Approval {
    /// The canonical state directory, and the service name it gets.
    dir: String,
    name: String,
    account: String,
    command: String,
    /// The registration to be replaced, and whether it was running.
    existing: Option<(Registration, bool)>,
    /// Whether the account has to be allowed to log on as a service.
    grant: bool,
}

/// `SERVICE_AUTO_START`, the start type `install` registers.
const AUTO_START: u32 = 2;

/// An install as shown for confirmation, which displays as the changes it would make. Only
/// Windows makes one, with `plan_install`, and applies it.
pub struct InstallPlan {
    options: InstallOptions,
    shown: Approval,
    /// The runtime the service already runs exactly as this install would register it, which
    /// is therefore left running.
    kept: Option<Identity>,
}

impl InstallPlan {
    const CHANGED: &str = "the background service, or what an install would do, is no longer \
        as it was shown, so nothing was installed. Run 'massrelay install' again";

    /// Require what an install would do now to be what was shown.
    fn confirm(&self, found: &Approval) -> Result<()> {
        ensure!(*found == self.shown, Self::CHANGED);
        Ok(())
    }

    /// Decide what a command in a session that depends on `runtime` does about the service,
    /// which has to be that runtime's. `service` is the registered service's process and
    /// whether it is fully running, and `current` whether the runtime is this program. A
    /// password given to be stored means that the service is registered again.
    fn consider(
        &mut self,
        runtime: &Identity,
        service: Option<(u32, bool)>,
        current: bool,
    ) -> Result<()> {
        ensure!(
            service.is_some_and(|(process, _)| process == runtime.pid),
            installer::NOT_THE_SERVICE
        );
        let registered = matches!(
            &self.shown.existing,
            Some((found, true))
                if found.command == self.shown.command && found.start == AUTO_START
        );
        let exact = registered
            && service.is_some_and(|(_, running)| running)
            && current
            && !self.shown.grant
            && !self.options.password_stdin;
        self.kept = exact.then(|| runtime.clone());
        Ok(())
    }

    /// Whether applying this leaves the running service alone.
    pub fn keeps(&self) -> bool {
        self.kept.is_some()
    }

    /// Everything a confirmation of this approves, to compare across processes.
    pub fn approval(&self) -> String {
        format!("{:?} {:?}", self.shown, self.kept)
    }

    /// Where a queued install says what it did.
    pub fn log(&self) -> String {
        Path::new(&self.shown.dir)
            .join(INSTALL_LOG)
            .display()
            .to_string()
    }

    /// Asked where the right would be granted: whether to grant it, which only a plan that
    /// showed so allows.
    fn grant(&self, needed: bool) -> Result<bool> {
        ensure!(!needed || self.shown.grant, Self::CHANGED);
        Ok(needed)
    }
}

impl fmt::Display for InstallPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let Approval {
            dir,
            name,
            account,
            command,
            existing,
            grant,
        } = &self.shown;
        if self.keeps() {
            return write!(
                formatter,
                "Keep the Windows service {name} running as {account}, without a restart: it is \
                 already registered as this install would register it\n\
                 Command line: {command}\n\
                 The password Windows stored for it is not asked for or checked. To store a new \
                 one, pass --password-stdin\n\
                 It records events in the profile directory, {dir}"
            );
        }
        let register = match existing {
            None => "Register and start",
            Some((_, false)) => "Reconfigure and start",
            Some((_, true)) => "Reconfigure and restart",
        };
        writeln!(
            formatter,
            "{register} the Windows service {name}, which runs as {account} and starts at boot"
        )?;
        if *grant {
            writeln!(formatter, "Allow {account} to log on as a service")?;
        }
        write!(
            formatter,
            "Command line: {command}\n\
             Windows needs that account's password, which MassRelay does not save\n\
             It records events in the profile directory, {dir}"
        )
    }
}

/// What removal asks of the service manager.
trait Unregister {
    /// Mark the service for deletion. One that is marked already is left so.
    fn delete(&self) -> Result<()>;
    /// Stop it, and wait within a limit until it has stopped.
    fn stop(&self) -> Result<()>;
}

/// Delete, then stop. Windows keeps a marked service only until it has stopped, so once the
/// mark is made the removal holds even if this command ends during the stop, as one reaching
/// the device through the service would.
fn unregister(service: &impl Unregister) -> Result<()> {
    service.delete()?;
    service.stop().context(
        "the service is marked for deletion but has not stopped. Windows removes it once it \
         stops, at the latest when Windows restarts",
    )
}

/// Quote one argument for a service command line.
pub(crate) fn quote(text: &str) -> Result<String> {
    ensure!(
        !text.is_empty() && !text.contains('"') && !text.chars().any(char::is_control),
        "this path cannot be written in a service command line: {text:?}"
    );
    // The service manager expands environment variables in the stored command line.
    ensure!(
        !text.contains('%'),
        "a path containing '%' cannot be used for a Windows service: {text}"
    );
    // Backslashes are literal except before a quote, so only the trailing ones are doubled.
    let trailing = text.len() - text.trim_end_matches('\\').len();
    Ok(format!("\"{text}{}\"", "\\".repeat(trailing)))
}

/// A canonical path as the drive-letter path the service manager and the user both read.
pub(crate) fn plain(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .with_context(|| format!("path is not Unicode: {}", path.display()))?;
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    let bytes = text.as_bytes();
    ensure!(
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\',
        "{text} is not on a local drive"
    );
    Ok(text.to_owned())
}

/// What a checked path is to the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// A program the service runs.
    Program,
    /// A directory whose contents the service loads or writes: the program's directory (where
    /// Windows also looks for its DLLs) and the state directory.
    Holder,
    /// A directory whose newly created updater files must inherit safe permissions.
    Staging,
    /// A directory above one of those. It only has to keep the path below it in place.
    Ancestor,
    /// Private profile state. Its contents and inherited permissions must be private.
    Private,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AceKind {
    Allow,
    Deny,
    Other,
}

struct Ace {
    kind: AceKind,
    /// Applies to objects created below, not to this one.
    inherit_only: bool,
    mask: u32,
    sid: String,
}

/// A file or directory's owner and access list, with SIDs in string form.
struct Security {
    owner: String,
    /// `None` is a missing access list, which grants everyone everything.
    dacl: Option<Vec<Ace>>,
}

const FILE_WRITE_DATA: u32 = 0x2; // On a directory: add a file.
const FILE_READ_DATA: u32 = 0x1; // On a directory: list its contents.
const FILE_APPEND_DATA: u32 = 0x4; // On a directory: add a subdirectory.
const FILE_DELETE_CHILD: u32 = 0x40;
const DELETE: u32 = 0x1_0000;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// Placeholders for the owner, who is checked separately.
const CREATOR_OWNER: &str = "S-1-3-0";
const OWNER_RIGHTS: &str = "S-1-3-4";

/// Who can already act as any account: letting them write changes nothing.
fn privileged(sid: &str) -> bool {
    [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER].contains(&sid)
}

/// The SID of an account, other than the service's own and the machine's administrators, that
/// could change what the service runs through this path.
fn untrusted<'a>(security: &'a Security, role: Role, account: &str) -> Option<&'a str> {
    let trusted = |sid: &str| sid == account || privileged(sid);
    if !trusted(&security.owner) {
        return Some(&security.owner);
    }
    let Some(dacl) = &security.dacl else {
        return Some("S-1-1-0");
    };
    // Replacing or removing the path, or taking it over.
    let takeover = DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
    let harmful = takeover
        | match role {
            Role::Program => FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE,
            Role::Holder | Role::Staging => {
                FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | GENERIC_WRITE
            }
            Role::Ancestor => FILE_DELETE_CHILD,
            Role::Private => {
                FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_APPEND_DATA
                    | FILE_DELETE_CHILD
                    | GENERIC_READ
                    | GENERIC_WRITE
            }
        };
    dacl.iter()
        .find(|ace| {
            let grants = match ace.kind {
                AceKind::Allow => ace.mask & harmful != 0,
                AceKind::Deny => false,
                // An entry this check does not understand is not assumed to be harmless.
                AceKind::Other => true,
            };
            grants
                && (!ace.inherit_only || matches!(role, Role::Private | Role::Staging))
                && !trusted(&ace.sid)
                && ![CREATOR_OWNER, OWNER_RIGHTS].contains(&ace.sid.as_str())
        })
        .map(|ace| ace.sid.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";
    const USERS: &str = "S-1-5-32-545";
    const AUTHENTICATED: &str = "S-1-5-11";
    const FULL: u32 = 0x1F_01FF;
    const MODIFY: u32 = 0x13_01BF;
    const READ: u32 = 0x12_00A9;

    fn allow(sid: &str, mask: u32) -> Ace {
        Ace {
            kind: AceKind::Allow,
            inherit_only: false,
            mask,
            sid: sid.into(),
        }
    }

    fn security(owner: &str, dacl: Vec<Ace>) -> Security {
        Security {
            owner: owner.into(),
            dacl: Some(dacl),
        }
    }

    /// What Windows gives a directory under the account's own profile.
    fn profile(owner: &str) -> Security {
        security(
            owner,
            vec![
                allow(SYSTEM, FULL),
                allow(ADMINISTRATORS, FULL),
                allow(ACCOUNT, FULL),
            ],
        )
    }

    #[test]
    fn a_path_only_the_account_and_administrators_control_is_trusted() {
        for role in [Role::Program, Role::Holder, Role::Ancestor] {
            // Windows makes Administrators the owner of what an elevated process creates.
            for owner in [ACCOUNT, ADMINISTRATORS, SYSTEM] {
                assert_eq!(untrusted(&profile(owner), role, ACCOUNT), None);
            }
            // Program Files: readable by everyone, written by the installer service alone.
            let system = security(
                TRUSTED_INSTALLER,
                vec![
                    allow(TRUSTED_INSTALLER, FULL),
                    allow(ADMINISTRATORS, FULL),
                    allow(USERS, READ),
                    allow(CREATOR_OWNER, GENERIC_ALL),
                ],
            );
            assert_eq!(untrusted(&system, role, ACCOUNT), None);
        }
    }

    #[test]
    fn another_accounts_profile_is_not_trusted_for_this_account() {
        for role in [Role::Program, Role::Holder, Role::Ancestor] {
            // Owned by the other account.
            let mut theirs = profile(OTHER);
            assert_eq!(untrusted(&theirs, role, ACCOUNT), Some(OTHER));
            // Created by an elevated process, but still the other account's to write.
            theirs = profile(ADMINISTRATORS);
            theirs.dacl.as_mut().unwrap().push(allow(OTHER, FULL));
            assert_eq!(untrusted(&theirs, role, ACCOUNT), Some(OTHER));
        }
    }

    #[test]
    fn a_shared_writable_directory_is_refused_where_writing_matters() {
        // A new directory at a drive's root: any signed-in account may modify it.
        let mut shared = profile(ADMINISTRATORS);
        shared
            .dacl
            .as_mut()
            .unwrap()
            .push(allow(AUTHENTICATED, MODIFY));
        for role in [Role::Program, Role::Holder, Role::Ancestor] {
            assert_eq!(untrusted(&shared, role, ACCOUNT), Some(AUTHENTICATED));
        }

        // The drive root itself: anyone may add a directory, and what they add is theirs to
        // modify, but nobody can replace what is already there.
        let mut root = profile(TRUSTED_INSTALLER);
        let dacl = root.dacl.as_mut().unwrap();
        dacl.push(allow(USERS, READ));
        dacl.push(allow(AUTHENTICATED, FILE_APPEND_DATA));
        dacl.push(Ace {
            inherit_only: true,
            ..allow(AUTHENTICATED, MODIFY)
        });
        assert_eq!(untrusted(&root, Role::Ancestor, ACCOUNT), None);
        // The same rights on the program's own directory would let them plant a DLL.
        assert_eq!(untrusted(&root, Role::Holder, ACCOUNT), Some(AUTHENTICATED));

        let mut plantable = profile(ACCOUNT);
        plantable
            .dacl
            .as_mut()
            .unwrap()
            .push(allow(USERS, READ | FILE_WRITE_DATA));
        assert_eq!(untrusted(&plantable, Role::Ancestor, ACCOUNT), None);
        assert_eq!(untrusted(&plantable, Role::Holder, ACCOUNT), Some(USERS));
        assert_eq!(untrusted(&plantable, Role::Program, ACCOUNT), Some(USERS));
    }

    #[test]
    fn updater_staging_rejects_write_access_inherited_by_new_files() {
        let directory = security(
            ACCOUNT,
            vec![Ace {
                inherit_only: true,
                ..allow(USERS, FILE_WRITE_DATA)
            }],
        );
        assert_eq!(untrusted(&directory, Role::Holder, ACCOUNT), None);
        assert_eq!(untrusted(&directory, Role::Staging, ACCOUNT), Some(USERS));
    }

    #[test]
    fn access_lists_that_cannot_be_judged_are_refused() {
        let open = Security {
            owner: ACCOUNT.into(),
            dacl: None,
        };
        assert!(untrusted(&open, Role::Ancestor, ACCOUNT).is_some());

        let mut odd = profile(ACCOUNT);
        odd.dacl.as_mut().unwrap().push(Ace {
            kind: AceKind::Other,
            ..allow(USERS, 0)
        });
        assert_eq!(untrusted(&odd, Role::Ancestor, ACCOUNT), Some(USERS));

        // A denial takes nothing away from the check and grants nothing.
        let mut denied = profile(ACCOUNT);
        denied.dacl.as_mut().unwrap().push(Ace {
            kind: AceKind::Deny,
            ..allow(USERS, FULL)
        });
        assert_eq!(untrusted(&denied, Role::Program, ACCOUNT), None);
    }

    #[test]
    fn the_service_command_line_survives_windows_argument_parsing() -> Result<()> {
        let dir = r"C:\Users\A & B\My Profile\";
        let name = service_name(dir);
        assert_ne!(name, service_name(r"C:\Users\A & B\My Profile"));
        assert_eq!(name.len(), "MassRelay-".len() + 16);

        let command = command_line(
            r"C:\Users\A & B\bin\massrelay.exe",
            dir,
            &name,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )?;
        // The doubled backslash keeps the closing quote a quote.
        assert_eq!(
            command,
            format!(
                r#""C:\Users\A & B\bin\massrelay.exe" --state-dir "C:\Users\A & B\My Profile\\" service {name} --shell "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe""#
            )
        );
        assert!(is_profile_service(&command, dir, &name));
        assert!(!is_profile_service(&command, r"C:\Users\A & B", &name));
        assert!(!is_profile_service(
            r"C:\Windows\System32\svchost.exe -k netsvcs",
            dir,
            &name
        ));

        // A queued update names the same program and profile, quoted the same way.
        assert_eq!(
            update_command_line(r"C:\Users\A & B\bin\massrelay.exe", dir)?,
            r#""C:\Users\A & B\bin\massrelay.exe" --state-dir "C:\Users\A & B\My Profile\\" update"#
        );

        // A quote would end the argument; '%' would be expanded by the service manager.
        assert!(quote("C:\\a\" --shell \"C:\\evil.exe").is_err());
        assert!(quote(r"C:\Users\%USERNAME%\bin").is_err());
        assert!(quote("C:\\a\nb").is_err());
        Ok(())
    }

    #[test]
    fn only_this_profiles_idle_service_is_removable() -> Result<()> {
        let dir = r"C:\Users\me\MassRelay";
        let name = service_name(dir);
        let command = command_line(r"C:\bin\massrelay.exe", dir, &name, r"C:\shell.exe")?;
        let ours = || Registered {
            command: &command,
            own_account: true,
            process: Some(40),
        };
        let check = |service: Registered, host, updating| {
            check_removable(&service, dir, &name, host, updating)
        };
        check(ours(), None, false)?;
        // A marker left by another runtime, and a stopped service, which hosts nothing.
        check(ours(), Some(41), false)?;
        let stopped = Registered {
            process: None,
            ..ours()
        };
        check(stopped, None, false)?;

        let foreign = Registered {
            command: r"C:\Windows\System32\svchost.exe -k netsvcs",
            ..ours()
        };
        assert!(check(foreign, None, false).is_err());
        let theirs = Registered {
            own_account: false,
            ..ours()
        };
        assert!(check(theirs, None, false).is_err());
        assert!(check(ours(), Some(40), false).is_err());
        assert!(check(ours(), None, true).is_err());
        Ok(())
    }

    #[test]
    fn an_install_applies_only_what_was_shown() -> Result<()> {
        let approval = |command: &str, running: Option<bool>, grant| Approval {
            dir: r"C:\state".into(),
            name: "MassRelay-1".into(),
            account: r"PC\me".into(),
            command: command.into(),
            existing: running.map(|running| {
                let registration = Registration {
                    command: "massrelay".into(),
                    account: r".\me".into(),
                    start: 2,
                };
                (registration, running)
            }),
            grant,
        };
        let plan = |shown| InstallPlan {
            options: InstallOptions {
                shell: None,
                password_stdin: false,
                allow_administrator: false,
            },
            shown,
            kept: None,
        };

        let over_stopped = plan(approval("massrelay", Some(false), false));
        over_stopped.confirm(&approval("massrelay", Some(false), false))?;
        for changed in [
            approval("other", Some(false), false),
            // Removed, or started so that installing would end its sessions.
            approval("massrelay", None, false),
            approval("massrelay", Some(true), false),
            // The account lost the right.
            approval("massrelay", Some(false), true),
        ] {
            assert!(over_stopped.confirm(&changed).is_err());
        }
        // Lost after that look too: nothing grants what was not shown.
        assert!(!over_stopped.grant(false)?);
        assert!(over_stopped.grant(true).is_err());

        let granting = plan(approval("massrelay", None, true));
        assert!(granting.grant(true)?);
        assert!(!granting.grant(false)?);
        assert!(
            granting
                .confirm(&approval("massrelay", Some(false), true))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn a_carried_install_keeps_only_the_exact_running_registration() -> Result<()> {
        let runtime = Identity {
            pid: 40,
            executable: None,
            version: String::new(),
            endpoint: String::new(),
            held: false,
        };
        let plan = |change: &dyn Fn(&mut Approval, &mut InstallOptions)| {
            let mut options = InstallOptions {
                shell: None,
                password_stdin: false,
                allow_administrator: true,
            };
            let registration = Registration {
                command: "wanted".into(),
                account: r".\me".into(),
                start: AUTO_START,
            };
            let mut shown = Approval {
                dir: r"C:\state".into(),
                name: "MassRelay-1".into(),
                account: r"PC\me".into(),
                command: "wanted".into(),
                existing: Some((registration, true)),
                grant: false,
            };
            change(&mut shown, &mut options);
            InstallPlan {
                options,
                shown,
                kept: None,
            }
        };
        let running = Some((runtime.pid, true));

        let mut exact = plan(&|_, _| {});
        let replacing = exact.approval();
        exact.consider(&runtime, running, true)?;
        assert!(exact.keeps());
        // A finishing process cannot take one for the other.
        assert_ne!(exact.approval(), replacing);

        // Another program or one not serving normally, and a start or stop under way.
        for (service, current) in [(running, false), (Some((runtime.pid, false)), true)] {
            let mut plan = plan(&|_, _| {});
            plan.consider(&runtime, service, current)?;
            assert!(!plan.keeps());
        }
        // Anything the install would change, and a password that is to be stored.
        type Change<'a> = &'a dyn Fn(&mut Approval, &mut InstallOptions);
        let changes: [Change; 4] = [
            &|shown, _| shown.command = "another shell".into(),
            &|shown, _| shown.existing.as_mut().unwrap().0.start = AUTO_START + 1,
            &|shown, _| shown.grant = true,
            &|_, options| options.password_stdin = true,
        ];
        for change in changes {
            let mut plan = plan(change);
            plan.consider(&runtime, running, true)?;
            assert!(!plan.keeps());
        }
        // The session depends on something else than this service.
        for service in [None, Some((41, true))] {
            let mut plan = plan(&|_, _| {});
            assert!(plan.consider(&runtime, service, true).is_err());
            assert!(!plan.keeps());
        }
        Ok(())
    }

    #[test]
    fn a_queued_install_gets_the_whole_confirmation_and_password_or_does_nothing() -> Result<()> {
        use std::io::Write as _;

        let patient = Duration::from_secs(30);
        let approval = "a".repeat(APPROVAL);
        // Beyond ASCII and the basic plane, with the NUL Windows expects.
        let password: Vec<u16> = "p+ss wörd \u{1F511}\0".encode_utf16().collect();
        let sent = |bytes: &[u8]| -> Result<(String, Option<Secret>)> {
            let (gate, mut command) = std::io::pipe()?;
            command.write_all(bytes)?;
            // The command ends, however it ends.
            drop(command);
            read_handoff(await_activation(gate, patient)?)
        };
        // What follows a handoff stays in the pipe.
        let (gate, mut command) = std::io::pipe()?;
        command.write_all(&[ACTIVATE])?;
        command.write_all(&handoff_message(&approval, None)?.0)?;
        command.write_all(b"after")?;
        drop(command);
        let mut gate = await_activation(gate, patient)?;
        read_handoff(&mut gate)?;
        let mut rest = Vec::new();
        gate.read_to_end(&mut rest)?;
        assert_eq!(rest, b"after");
        for given in [Some(Secret(password.clone())), None] {
            let message = handoff_message(&approval, given.as_ref())?;
            let mut bytes = vec![ACTIVATE];
            bytes.extend_from_slice(&message.0);
            let (confirmed, received) = sent(&bytes)?;
            assert_eq!(confirmed, approval);
            assert_eq!(
                received.as_ref().map(|secret| &secret.0),
                given.as_ref().map(|secret| &secret.0)
            );
            // Cut anywhere, a shortened password included.
            for end in 0..bytes.len() {
                assert!(sent(&bytes[..end]).is_err(), "accepted {end} bytes");
            }
            // Without the activating byte nothing is read as a confirmation.
            assert!(sent(&message.0).is_err());
        }
        let unterminated = Secret(vec![u16::from(b'x')]);
        let mut bytes = vec![ACTIVATE];
        bytes.extend_from_slice(&handoff_message(&approval, Some(&unterminated))?.0);
        assert!(sent(&bytes).is_err());

        // The command line carries the confirmed options, and nothing about the password.
        assert_eq!(
            install_command_line(r"C:\a b\massrelay.exe", r"C:\state\", r"C:\sh.exe", true)?,
            r#""C:\a b\massrelay.exe" --state-dir "C:\state\\" install --yes --shell "C:\sh.exe" --allow-administrator"#
        );
        assert!(
            !install_command_line(r"C:\m.exe", r"C:\state", r"C:\sh.exe", false)?
                .contains("--allow-administrator")
        );
        Ok(())
    }

    #[test]
    fn a_password_line_is_read_without_taking_anything_after_it() -> Result<()> {
        /// Gives no more than it is asked for, and records the most that was.
        struct Source<'a>(&'a [u8], usize);
        impl Read for Source<'_> {
            fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
                self.1 = self.1.max(into.len());
                self.0.read(into)
            }
        }
        for (sent, limit, line, rest) in [
            (
                &b"secret\r\nafter"[..],
                64,
                &b"secret\r\n"[..],
                &b"after"[..],
            ),
            (b"secret", 64, b"secret", b""),
            (b"secret", 3, b"sec", b"ret"),
            (b"", 64, b"", b""),
        ] {
            let mut source = Source(sent, 0);
            assert_eq!(read_secret_line(&mut source, limit)?.0, line);
            assert_eq!(source.0, rest);
            // One byte at a time: a pipe is never asked for what follows the line.
            assert!(source.1 <= 1);
        }
        Ok(())
    }

    #[test]
    fn a_removal_applies_only_to_the_registration_that_was_shown() -> Result<()> {
        let registration = |command: &str, account: &str, start| Registration {
            command: command.into(),
            account: account.into(),
            start,
        };
        let installed = || registration("massrelay", r".\me", 2);
        let plan = |shown| UninstallPlan {
            dir: r"C:\state".into(),
            name: "MassRelay-1".into(),
            shown,
        };
        let confirm = |plan: &UninstallPlan, found: Option<Registration>| {
            plan.confirm("MassRelay-1", found.map(|found| (found, ())))
        };
        // Nothing was shown, so a service registered since is not removed.
        assert_eq!(confirm(&plan(None), None)?, None);
        assert!(confirm(&plan(None), Some(installed())).is_err());

        let shown = plan(Some(installed()));
        assert_eq!(confirm(&shown, Some(installed()))?, Some(()));
        for replaced in [
            None,
            Some(registration("other", r".\me", 2)),
            Some(registration("massrelay", r".\other", 2)),
            Some(registration("massrelay", r".\me", 4)),
        ] {
            assert!(confirm(&shown, replaced).is_err());
        }
        assert!(
            shown
                .confirm("MassRelay-2", Some((installed(), ())))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn a_service_is_marked_for_deletion_before_it_is_stopped() {
        struct Manager {
            refuse: &'static str,
            asked: std::cell::RefCell<Vec<&'static str>>,
        }
        impl Manager {
            fn ask(&self, request: &'static str) -> Result<()> {
                self.asked.borrow_mut().push(request);
                ensure!(self.refuse != request, "refused");
                Ok(())
            }
        }
        impl Unregister for Manager {
            fn delete(&self) -> Result<()> {
                self.ask("delete")
            }
            fn stop(&self) -> Result<()> {
                self.ask("stop")
            }
        }
        for (refuse, asked) in [
            ("", &["delete", "stop"][..]),
            // Nothing is stopped that could not be deleted.
            ("delete", &["delete"]),
            ("stop", &["delete", "stop"]),
        ] {
            let manager = Manager {
                refuse,
                asked: Default::default(),
            };
            assert_eq!(unregister(&manager).is_ok(), refuse.is_empty());
            assert_eq!(*manager.asked.borrow(), asked);
        }
    }

    #[test]
    fn only_a_started_update_replaces_the_previous_log() -> Result<()> {
        use std::{fs, io::Write as _};

        let dir = tempfile::tempdir()?;
        let latest = dir.path().join(UPDATE_LOG);
        fs::write(&latest, "previous diagnostics")?;
        let files = || fs::read_dir(dir.path()).map(Iterator::count);
        let write = |mut log: &File, text: &str| log.write_all(text.as_bytes());

        let refused = start_logged(NamedTempFile::new_in(dir.path())?, &latest, |log| {
            write(log, "partial")?;
            anyhow::bail!("refused")
        });
        assert!(refused.is_err());
        assert_eq!(fs::read_to_string(&latest)?, "previous diagnostics");
        assert_eq!(files()?, 1);

        let path = start_logged(NamedTempFile::new_in(dir.path())?, &latest, |log| {
            Ok(write(log, "started")?)
        })?;
        assert_eq!(path, latest);
        assert_eq!(fs::read_to_string(&latest)?, "started");
        assert_eq!(files()?, 1);

        // A directory cannot be replaced by a file: the running update keeps its own log.
        let held = dir.path().join("held");
        fs::create_dir(&held)?;
        let path = start_logged(NamedTempFile::new_in(dir.path())?, &held, |log| {
            Ok(write(log, "running")?)
        })?;
        assert_ne!(path, held);
        assert_eq!(fs::read_to_string(path)?, "running");
        Ok(())
    }

    #[test]
    fn a_queued_update_acts_only_when_its_queuing_command_says_so() -> Result<()> {
        use std::{io::Write as _, time::Instant};

        let patient = Duration::from_secs(30);
        for (said, activated) in [(Some(ACTIVATE), true), (Some(0), false), (None, false)] {
            let (gate, mut command) = std::io::pipe()?;
            if let Some(byte) = said {
                command.write_all(&[byte])?;
            }
            // The command ends, or is ended: its end of the pipe closes.
            drop(command);
            let started = Instant::now();
            assert_eq!(await_activation(gate, patient).is_ok(), activated);
            assert!(started.elapsed() < patient);
        }
        // It neither activates the update nor ends.
        let (gate, _command) = std::io::pipe()?;
        assert!(await_activation(gate, Duration::from_millis(50)).is_err());
        Ok(())
    }

    #[test]
    fn the_queued_environment_drops_the_session_markers_and_ends_with_two_nuls() {
        let block = |variables: &[(&str, &str)]| {
            environment_block(
                variables
                    .iter()
                    .map(|&(name, value)| (name.into(), value.into())),
                |text| text.to_string_lossy().encode_utf16().collect(),
            )
        };
        assert_eq!(block(&[]), [0, 0]);
        assert_eq!(
            block(&[("MassRelay_Shell_Host", "1"), ("Ssh_Connection", "2")]),
            [0, 0]
        );
        let expected: Vec<u16> = "a=1\0B=2\0\0".encode_utf16().collect();
        assert_eq!(
            block(&[("B", "2"), (crate::private::HOST_ENV, "1"), ("a", "1")]),
            expected
        );
    }

    #[test]
    fn only_local_drive_paths_are_used() -> Result<()> {
        assert_eq!(
            plain(Path::new(r"\\?\C:\Users\me\AppData\Local\MassRelay"))?,
            r"C:\Users\me\AppData\Local\MassRelay"
        );
        assert_eq!(plain(Path::new(r"D:\tools"))?, r"D:\tools");
        assert!(plain(Path::new(r"\\?\UNC\server\share\MassRelay")).is_err());
        assert!(plain(Path::new(r"\\server\share\MassRelay")).is_err());
        assert!(plain(Path::new(r"relative\path")).is_err());
        Ok(())
    }
}
