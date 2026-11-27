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

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{
    Managed, control, install, is_default_shell, managed, private_audit, private_marker, serve,
    serving, ssh_files, ssh_private_dir, until_stopped, wait_for_activation,
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
/// Held, in the state directory, for as long as a queued update or its helper runs.
const UPDATE_LOCK: &str = "update.lock";

/// The command line of an update queued from one of this device's shells.
fn update_command_line(binary: &str, dir: &str) -> Result<String> {
    Ok(format!(
        "{} --state-dir {} update",
        quote(binary)?,
        quote(dir)?
    ))
}

/// The byte that lets a queued update act.
const ACTIVATE: u8 = b'+';

/// Wait up to `limit` for the activating byte on `gate`. The command that queued the update
/// holds the only other end, so if that command ends first, however it ends, the pipe closes.
fn await_activation(mut gate: impl Read + Send + 'static, limit: Duration) -> Result<()> {
    let (send, received) = mpsc::channel();
    // A pipe read has no time limit. A reader left waiting ends with the process.
    thread::spawn(move || {
        let mut byte = [0];
        let _ = send.send(gate.read_exact(&mut byte).map(|()| byte[0]));
    });
    ensure!(
        matches!(received.recv_timeout(limit), Ok(Ok(ACTIVATE))),
        "the command that queued this update did not activate it, so the update did nothing"
    );
    Ok(())
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

/// The UTF-16 environment block of a queued update: `variables` without the one that names the
/// runtime serving this shell, each NUL-terminated and sorted by name ignoring case, then one
/// more NUL.
fn environment_block(
    variables: impl Iterator<Item = (OsString, OsString)>,
    encode: impl Fn(&OsStr) -> Vec<u16>,
) -> Vec<u16> {
    let mut variables: Vec<_> = variables
        .filter(|(name, _)| !name.eq_ignore_ascii_case(crate::private::HOST_ENV))
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
    fn the_queued_environment_drops_the_shell_marker_and_ends_with_two_nuls() {
        let block = |variables: &[(&str, &str)]| {
            environment_block(
                variables
                    .iter()
                    .map(|&(name, value)| (name.into(), value.into())),
                |text| text.to_string_lossy().encode_utf16().collect(),
            )
        };
        assert_eq!(block(&[]), [0, 0]);
        assert_eq!(block(&[("MassRelay_Shell_Host", "1")]), [0, 0]);
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
