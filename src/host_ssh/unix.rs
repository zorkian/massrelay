//! The system OpenSSH server on Linux (systemd) and macOS (Remote Login).
//!
//! MassRelay itself never runs with more rights than the account's. A plan runs system
//! programs with those rights only, within a time limit, and creates nothing. Applying a
//! change runs the fixed programs below through `sudo`, which authenticates the account
//! itself: `cat`, `ls` and `test` to read private configuration; a constant `sh` script,
//! using `mkdir`, `sleep` and `rmdir`, to hold the machine's lock; `sshd -t` and `-T` to
//! check a copy; `cp`, `tee`, `sync`, `mv` and `rm` to replace the configuration; and
//! `systemctl reload`. The new file is staged beside the old one, so it is never writable by
//! the account between check and use.

use std::{
    ffi::{CStr, OsStr},
    fs,
    io::{self, BufRead as _, Write as _},
    mem::MaybeUninit,
    os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Output, Stdio},
    ptr::null_mut,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};

use super::{
    Purpose, Unavailable, check_version, scanned_key,
    setup::{Access, Held, NeedsAdministrator, Reload, Staged, System},
    valid_user,
};
use crate::update::{Finished, run_within};

const GROUP_OR_OTHERS_WRITE: u32 = 0o022;
const SERVICES: [&str; 2] = ["ssh.service", "sshd.service"];
const SOCKETS: [&str; 2] = ["ssh.socket", "sshd.socket"];
/// What a socket that starts one server for each connection runs.
const INSTANCES: [&str; 2] = ["ssh@massrelay.service", "sshd@massrelay.service"];
/// Bound on a question asked with this account's own rights.
const LIMIT: Duration = Duration::from_secs(15);
/// The machine's lock: a directory only root can make, gone after a restart.
const LOCK: &str = "/run/massrelay-sshd.lock";
const MAC_LOCK: &str = "/var/run/massrelay-sshd.lock";
/// Run as root with the lock's path. It holds the lock until its input ends, which also
/// happens when the process holding the other end dies, and waits a minute for another
/// holder. Only a holder that is itself killed leaves the directory behind.
const HOLD: &str = r#"n=0
until /bin/mkdir -m 700 "$1" 2>/dev/null; do
    [ -d "$1" ] || exit 1
    n=$((n + 1))
    [ "$n" -lt 60 ] || exit 75
    /bin/sleep 1
done
trap '/bin/rmdir "$1"' 0
trap 'exit 1' 1 2 13 15
echo held
/bin/cat >/dev/null"#;
/// `HOLD`'s exit status when another holder stayed.
const BUSY: i32 = 75;

/// The system programs used, each by a fixed path.
#[derive(Clone)]
pub(super) struct Tools {
    pub sshd: PathBuf,
    pub sudo: PathBuf,
    pub systemctl: PathBuf,
    pub keyscan: PathBuf,
}

impl Default for Tools {
    fn default() -> Self {
        Self {
            sshd: "/usr/sbin/sshd".into(),
            sudo: "/usr/bin/sudo".into(),
            systemctl: "/usr/bin/systemctl".into(),
            keyscan: "/usr/bin/ssh-keyscan".into(),
        }
    }
}

pub(super) struct Unix {
    pub user: String,
    pub uid: u32,
    /// The canonical home directory, where the server's ownership checks stop.
    pub home: PathBuf,
    pub config: PathBuf,
    /// Who must own the configuration: root.
    pub owner: u32,
    pub tools: Tools,
    /// Remote Login rather than a systemd service.
    pub macos: bool,
    /// The machine's lock on configuration changes, in a directory only root can write.
    pub lock: PathBuf,
}

impl Unix {
    pub(super) fn native(purpose: Purpose) -> Result<Self> {
        let tools = Tools::default();
        let macos = cfg!(target_os = "macos");
        // Said before anything about the account: without a server nothing else matters.
        if purpose == Purpose::Install && !tools.sshd.is_file() {
            return Err(absent(&tools.sshd, hint(macos)));
        }
        // SAFETY: these calls have no preconditions and cannot fail.
        let (uid, effective) = unsafe { (libc::getuid(), libc::geteuid()) };
        ensure!(
            uid != 0 && uid == effective,
            "run massrelay as your own account, without sudo; it asks for administrator \
             rights only for the changes that need them"
        );
        let (user, home) = account(uid)?;
        ensure!(valid_user(&user), "unsupported SSH account name {user:?}");
        let home = home
            .canonicalize()
            .context("resolve this account's home directory")?;
        Ok(Self {
            user,
            uid,
            home,
            config: "/etc/ssh/sshd_config".into(),
            owner: 0,
            tools,
            macos,
            lock: if macos { MAC_LOCK } else { LOCK }.into(),
        })
    }

    fn command(&self, access: Access, program: impl AsRef<OsStr>) -> Command {
        let mut command = match access {
            Access::User => Command::new(program),
            Access::Administrator => {
                let mut command = Command::new(&self.tools.sudo);
                command.arg("--").arg(program);
                command
            }
        };
        command.env("LC_ALL", "C");
        command
    }

    /// Run one system program as an administrator, giving it `input`.
    fn administer(
        &self,
        program: &str,
        arguments: &[&OsStr],
        input: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut command = self.command(Access::Administrator, program);
        command.args(arguments);
        let output = match input {
            None => command.stdin(Stdio::null()).output(),
            Some(input) => (|| {
                let mut child = command
                    .stdin(Stdio::piped())
                    // `tee` repeats its input, which nothing here wants.
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()?;
                let written = child
                    .stdin
                    .take()
                    .map_or(Ok(()), |mut stdin| stdin.write_all(input));
                let output = child.wait_with_output()?;
                written.map(|()| output)
            })(),
        }
        .with_context(|| format!("run {program} through sudo"))?;
        succeeded(program, output)
    }

    fn show(&self, unit: &str) -> Result<String> {
        let mut command = self.command(Access::User, &self.tools.systemctl);
        command.args([
            "show",
            "--property=LoadState,ActiveState,MainPID,ExecStart,Environment,EnvironmentFiles",
            unit,
        ]);
        ask(&mut command, "systemctl show")
            .context("ask systemd about the SSH server; system SSH setup supports systemd on Linux")
    }

    /// Refuse a unit that starts another program, or the server with another configuration
    /// or key file list.
    fn check_daemon(&self, shown: &str, access: Access) -> Result<()> {
        let mut arguments = Vec::new();
        for command in values(shown, "ExecStart") {
            let program = field(command, "path=").context("systemd did not name the program")?;
            ensure!(
                Path::new(program).canonicalize().ok() == self.tools.sshd.canonicalize().ok(),
                "the SSH service runs {program}, not {}; MassRelay only sets up the system's \
                 own server",
                self.tools.sshd.display()
            );
            arguments.extend(
                field(command, "argv[]=")
                    .into_iter()
                    .flat_map(str::split_ascii_whitespace)
                    .map(str::to_owned),
            );
        }
        let running = value(shown, "MainPID")
            .filter(|pid| *pid != "0" && pid.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|pid| fs::read(format!("/proc/{pid}/cmdline")).ok())
            .map(|line| String::from_utf8_lossy(&line).replace('\0', " "))
            .filter(|line| !line.trim().is_empty());
        let arguments = match running {
            // The running server's own command line already has the variables expanded.
            Some(line) => line.split_ascii_whitespace().map(str::to_owned).collect(),
            None => self.expand(shown, arguments, access)?,
        };
        let mut arguments = arguments.iter();
        while let Some(argument) = arguments.next() {
            let option = match argument.strip_prefix("-o") {
                Some("") => arguments.next().map(String::as_str),
                other => other,
            };
            let another_file =
                argument.starts_with('-') && !argument.starts_with("-o") && argument.contains('f');
            let other_keys = option.is_some_and(|option| {
                option
                    .trim_start_matches(['"', '\''])
                    .to_ascii_lowercase()
                    .starts_with("authorizedkeysfile")
            });
            ensure!(
                !another_file && !other_keys,
                "the SSH service is started with '{argument}', which replaces the \
                 configuration or its key files. MassRelay does not set up this server"
            );
        }
        Ok(())
    }

    /// The unit's command line with its environment variables filled in.
    fn expand(&self, shown: &str, arguments: Vec<String>, access: Access) -> Result<Vec<String>> {
        if !arguments.iter().any(|argument| argument.contains('$')) {
            return Ok(arguments);
        }
        let mut variables: Vec<(String, String)> = values(shown, "Environment")
            .flat_map(str::split_ascii_whitespace)
            .filter_map(assignment)
            .collect();
        for file in values(shown, "EnvironmentFiles") {
            let file = file.split(" (").next().unwrap_or(file);
            if let Some(contents) = self.read(Path::new(file), access)? {
                variables.extend(
                    String::from_utf8_lossy(&contents)
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.starts_with(['#', ';']))
                        .filter_map(assignment),
                );
            }
        }
        Ok(arguments
            .into_iter()
            .flat_map(|argument| {
                let name = argument
                    .strip_prefix('$')
                    .map(|name| name.trim_start_matches('{').trim_end_matches('}'));
                match name {
                    Some(name) => variables
                        .iter()
                        .rev()
                        .find(|(variable, _)| variable == name)
                        .map(|(_, value)| value.split_ascii_whitespace())
                        .into_iter()
                        .flatten()
                        .map(str::to_owned)
                        .collect(),
                    None => vec![argument],
                }
            })
            .collect())
    }
}

/// What the user can do to make the system's server available.
fn hint(macos: bool) -> &'static str {
    if macos {
        "Turn on Remote Login in System Settings, General, Sharing, then run 'massrelay \
         install' again."
    } else {
        "Install your distribution's OpenSSH server package and enable it (for example \
         'sudo systemctl enable --now ssh', or 'sshd'), then run 'massrelay install' again."
    }
}

fn absent(server: &Path, hint: &str) -> anyhow::Error {
    Unavailable(format!(
        "there is no OpenSSH server at {}. {hint}",
        server.display()
    ))
    .into()
}

/// Run a program with this account's rights, within `LIMIT`, and return its output.
fn ask(command: &mut Command, program: &str) -> Result<String> {
    let Finished {
        success,
        stdout,
        stderr,
    } = run_within(command, LIMIT).with_context(|| format!("run {program}"))?;
    ensure!(success, "{program} failed: {}", stderr.trim());
    Ok(stdout)
}

/// The machine's lock while `HOLD` runs.
struct Lock {
    holder: Child,
    input: Option<ChildStdin>,
}

impl Drop for Lock {
    fn drop(&mut self) {
        // The end of its input releases the lock.
        drop(self.input.take());
        let _ = self.holder.wait();
    }
}

fn succeeded(program: &str, output: Output) -> Result<Vec<u8>> {
    ensure!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

fn values<'a>(shown: &'a str, property: &'a str) -> impl Iterator<Item = &'a str> {
    shown
        .lines()
        .filter_map(move |line| line.strip_prefix(property)?.strip_prefix('='))
}

fn value<'a>(shown: &'a str, property: &'a str) -> Option<&'a str> {
    values(shown, property).next()
}

/// A field of systemd's `{ path=... ; argv[]=... ; ... }`.
fn field<'a>(command: &'a str, name: &str) -> Option<&'a str> {
    command.split_once(name)?.1.split(" ;").next()
}

/// A `NAME=value` line, with the quotes around the value removed.
fn assignment(line: &str) -> Option<(String, String)> {
    let (name, value) = line.split_once('=')?;
    let value = value.trim().trim_matches(['"', '\'']);
    Some((name.trim().to_owned(), value.to_owned()))
}

/// The name and home directory the password database gives `uid`.
pub(super) fn account(uid: u32) -> Result<(String, PathBuf)> {
    let mut buffer = vec![0u8; 1024];
    loop {
        let mut entry = MaybeUninit::<libc::passwd>::uninit();
        let mut found = null_mut();
        // SAFETY: the entry, the buffer of the length given and the result are writable.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE && buffer.len() < 1 << 20 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status)).context("look up this account");
        }
        ensure!(
            !found.is_null(),
            "the password database has no entry for user ID {uid}"
        );
        // SAFETY: a found entry was initialized, and its strings point into the buffer.
        let (name, home) = unsafe {
            let (name, home) = ((*found).pw_name, (*found).pw_dir);
            ensure!(
                !name.is_null() && !home.is_null(),
                "this account has no name or home directory"
            );
            (CStr::from_ptr(name), CStr::from_ptr(home))
        };
        return Ok((
            name.to_str()
                .context("the account name is not UTF-8")?
                .to_owned(),
            Path::new(OsStr::from_bytes(home.to_bytes())).to_owned(),
        ));
    }
}

impl System for Unix {
    fn user(&self) -> &str {
        &self.user
    }

    fn other_user(&self) -> &str {
        "root"
    }

    fn config(&self) -> &Path {
        &self.config
    }

    fn canonical(&self, path: &Path) -> Result<PathBuf> {
        path.canonicalize()
            .with_context(|| format!("resolve {}", path.display()))
    }

    fn installed(&self) -> Result<()> {
        if !self.tools.sshd.is_file() {
            return Err(absent(&self.tools.sshd, self.enable_hint()));
        }
        // Old servers exit with an error here, after printing their version.
        let output = run_within(Command::new(&self.tools.sshd).arg("-V"), LIMIT)
            .context("ask the SSH server its version")?;
        check_version(&format!("{}{}", output.stdout, output.stderr))
    }

    /// The server's ownership rules (`StrictModes`): every directory from the key file up to
    /// the home directory, or the root, belongs to the account or root and nobody else can
    /// write to it.
    fn check_key_file(&self, path: &Path) -> Result<()> {
        let directory = path.parent().context("the key file has no directory")?;
        for part in directory.ancestors() {
            let metadata =
                fs::metadata(part).with_context(|| format!("check {}", part.display()))?;
            ensure!(
                (metadata.uid() == self.uid || metadata.uid() == 0)
                    && metadata.mode() & GROUP_OR_OTHERS_WRITE == 0,
                "the SSH server would refuse keys in {}: {} must belong to this account or \
                 root and not be writable by others",
                directory.display(),
                part.display()
            );
            if part == self.home {
                break;
            }
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) => ensure!(
                metadata.is_file()
                    && metadata.uid() == self.uid
                    && metadata.mode() & 0o7777 == 0o600
                    && metadata.nlink() == 1,
                "{} must be a single file of this account with mode 0600",
                path.display()
            ),
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
            .with_context(|| format!("path is not UTF-8: {}", path.display()))?;
        // OpenSSH expands or ends an argument at these.
        ensure!(
            path.is_absolute()
                && !text
                    .chars()
                    .any(|c| c.is_control() || "\"'\\%$#*?[]{}".contains(c)),
            "the SSH server cannot be given the path {text}; use a state directory whose path \
             has none of \" ' \\ % $ # * ? [ ] {{ }}"
        );
        Ok(text.to_owned())
    }

    fn read_config(&self, access: Access) -> Result<Option<Vec<u8>>> {
        let path = &self.config;
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("check {}", path.display())),
        };
        let directory = path
            .parent()
            .context("the configuration has no directory")?;
        let parent = fs::metadata(directory)?;
        ensure!(
            metadata.is_file(),
            "{} is a link or not a file, so something else manages it; MassRelay does not \
             replace it",
            path.display()
        );
        ensure!(
            metadata.uid() == self.owner
                && parent.uid() == self.owner
                && metadata.mode() & GROUP_OR_OTHERS_WRITE == 0
                && parent.mode() & GROUP_OR_OTHERS_WRITE == 0
                && metadata.nlink() == 1,
            "{} and its directory must belong to root, with one name and no write access for \
             others",
            path.display()
        );
        self.read(path, access)
    }

    fn read(&self, path: &Path, access: Access) -> Result<Option<Vec<u8>>> {
        match fs::read(path) {
            Ok(contents) => Ok(Some(contents)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                if access == Access::User {
                    return Err(NeedsAdministrator(path.to_owned()).into());
                }
                let exists = self
                    .command(access, "/bin/test")
                    .arg("-e")
                    .arg(path)
                    .stdin(Stdio::null())
                    .status()?;
                if !exists.success() {
                    return Ok(None);
                }
                self.administer("/bin/cat", &["--".as_ref(), path.as_os_str()], None)
                    .map(Some)
            }
            Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
        }
    }

    fn list(&self, directory: &Path, access: Access) -> Result<Vec<String>> {
        let read = fs::read_dir(directory).and_then(|entries| {
            entries
                .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
                .collect::<io::Result<Vec<_>>>()
        });
        match read {
            Ok(names) => Ok(names),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(Vec::new())
            }
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                if access == Access::User {
                    return Err(NeedsAdministrator(directory.to_owned()).into());
                }
                let names = self.administer(
                    "/bin/ls",
                    &["-1A".as_ref(), "--".as_ref(), directory.as_os_str()],
                    None,
                )?;
                Ok(String::from_utf8_lossy(&names)
                    .lines()
                    .map(str::to_owned)
                    .collect())
            }
            Err(error) => Err(error).with_context(|| format!("read {}", directory.display())),
        }
    }

    fn path(&self, written: &str) -> PathBuf {
        written.into()
    }

    fn spellings(&self, value: &str) -> Vec<String> {
        vec![value.to_owned()]
    }

    fn sshd(&self, arguments: &[String], access: Access) -> Result<String> {
        let mut command = self.command(access, &self.tools.sshd);
        command.args(arguments);
        match access {
            Access::User => ask(&mut command, "sshd"),
            Access::Administrator => {
                let output = command
                    .stdin(Stdio::null())
                    .output()
                    .context("run the SSH server's test mode through sudo")?;
                String::from_utf8(succeeded("sshd", output)?)
                    .context("the SSH server printed text that is not UTF-8")
            }
        }
    }

    fn stage(&self, contents: &[u8]) -> Result<Staged> {
        // Each copy has its own name: several are compared with one another.
        static COPIES: AtomicU64 = AtomicU64::new(0);
        let mut name = self.config.clone().into_os_string();
        name.push(format!(
            ".massrelay-{}-{}",
            std::process::id(),
            COPIES.fetch_add(1, Ordering::Relaxed)
        ));
        let path = PathBuf::from(name);
        let (sudo, remove) = (self.tools.sudo.clone(), path.clone());
        let staged = Staged::new(path.clone(), move || {
            let _ = Command::new(sudo)
                .args(["--", "/bin/rm", "-f", "--"])
                .arg(remove)
                .stdin(Stdio::null())
                .output();
        });
        // The copy takes the configuration's owner and mode, which writing into it keeps.
        self.administer(
            "/bin/cp",
            &[
                "-p".as_ref(),
                "--".as_ref(),
                self.config.as_os_str(),
                path.as_os_str(),
            ],
            None,
        )?;
        self.administer(
            "/usr/bin/tee",
            &["--".as_ref(), path.as_os_str()],
            Some(contents),
        )?;
        ensure!(
            self.read(&path, Access::Administrator)?.as_deref() == Some(contents),
            "{} was not written as intended",
            path.display()
        );
        Ok(staged)
    }

    fn exclusive(&self) -> Result<Held> {
        let mut holder = self
            .command(Access::Administrator, "/bin/sh")
            .args(["-c", HOLD, "massrelay-lock"])
            .arg(&self.lock)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .context("take the machine's lock on SSH server changes through sudo")?;
        let input = holder.stdin.take();
        let mut said = String::new();
        if let Some(output) = holder.stdout.take() {
            io::BufReader::new(output).read_line(&mut said)?;
        }
        let mut lock = Lock { holder, input };
        if said.trim_end() == "held" {
            return Ok(Box::new(lock));
        }
        drop(lock.input.take());
        if lock.holder.wait()?.code() == Some(BUSY) {
            bail!(
                "another MassRelay change to this machine's SSH server is still running; \
                 nothing was changed. If none is, one was killed: remove the directory {} as \
                 an administrator, or restart the machine",
                self.lock.display()
            );
        }
        bail!(
            "could not take the machine's lock {}; nothing was changed",
            self.lock.display()
        )
    }

    fn authorize(&self) -> Result<()> {
        let cached = Command::new(&self.tools.sudo)
            .args(["-n", "--", "/bin/test", "-e", "/"])
            .stdin(Stdio::null())
            .output()
            .is_ok_and(|output| output.status.success());
        if cached {
            return Ok(());
        }
        // sudo asks on the terminal itself.
        let granted = Command::new(&self.tools.sudo).arg("-v").status();
        if !granted.is_ok_and(|status| status.success()) {
            bail!(
                "changing the SSH server needs administrator rights, and sudo did not grant \
                 them; nothing was changed. Run this in a terminal as an account that may use \
                 sudo"
            );
        }
        Ok(())
    }

    fn replace(&self, staged: Staged, expected: &[u8]) -> Result<()> {
        ensure!(
            self.read_config(Access::Administrator)?.as_deref() == Some(expected),
            "{} changed while it was being updated; it was not replaced",
            self.config.display()
        );
        // The new file reaches the disk before it takes the old one's name.
        self.administer("/bin/sync", &[], None)?;
        self.administer(
            "/bin/mv",
            &[
                "-f".as_ref(),
                "--".as_ref(),
                staged.path.as_os_str(),
                self.config.as_os_str(),
            ],
            None,
        )?;
        staged.consumed();
        self.administer("/bin/sync", &[], None)?;
        Ok(())
    }

    fn running(&self) -> Result<()> {
        let running = if self.macos {
            // Remote Login always listens on the SSH port.
            self.listener_key(22)?.is_some()
        } else {
            let mut active = false;
            for unit in SERVICES.into_iter().chain(SOCKETS) {
                active |= matches!(
                    value(&self.show(unit)?, "ActiveState"),
                    Some("active" | "reloading")
                );
            }
            active
        };
        if !running {
            return Err(Unavailable(format!(
                "the system's SSH server is not running. {}",
                self.enable_hint()
            ))
            .into());
        }
        Ok(())
    }

    fn reload_method(&self, access: Access) -> Result<Reload> {
        if self.macos {
            // launchd starts a server for each connection.
            return Ok(Reload::NextConnection);
        }
        for unit in SERVICES {
            let shown = self.show(unit)?;
            if value(&shown, "LoadState") == Some("loaded")
                && matches!(value(&shown, "ActiveState"), Some("active" | "reloading"))
            {
                self.check_daemon(&shown, access)?;
                return Ok(Reload::Service(unit.to_owned()));
            }
        }
        for socket in SOCKETS {
            if value(&self.show(socket)?, "ActiveState") != Some("active") {
                continue;
            }
            for unit in SERVICES.into_iter().chain(INSTANCES) {
                let shown = self.show(unit)?;
                if value(&shown, "LoadState") == Some("loaded") {
                    self.check_daemon(&shown, access)?;
                }
            }
            return Ok(Reload::NextConnection);
        }
        bail!(
            "an SSH server answers, but neither systemd's ssh or sshd service nor its socket \
             is active. MassRelay only sets up the system's own service"
        )
    }

    fn reload(&self, reload: &Reload) -> Result<()> {
        if let Reload::Service(unit) = reload {
            let systemctl = self.tools.systemctl.to_str().context("systemctl's path")?;
            self.administer(systemctl, &["reload".as_ref(), unit.as_ref()], None)
                .with_context(|| format!("reload {unit}"))?;
        }
        Ok(())
    }

    fn listener_key(&self, port: u16) -> Result<Option<String>> {
        let output = run_within(
            Command::new(&self.tools.keyscan)
                .args(["-T", "5", "-t", "ed25519", "-p", &port.to_string()])
                .arg("127.0.0.1"),
            LIMIT,
        )
        .context("run ssh-keyscan; install the system's OpenSSH client")?;
        Ok(scanned_key(&output.stdout))
    }

    fn enable_hint(&self) -> &'static str {
        hint(self.macos)
    }

    fn rights(&self) -> &'static str {
        "sudo, which may ask for your password, runs cat, ls, test, sh (to hold this \
         machine's\n            lock), sshd, cp, tee, sync, mv, rm and systemctl. An \
         account without sudo\n            cannot do this"
    }

    fn describe(&self, reload: &Reload) -> String {
        match reload {
            Reload::Service(unit) => format!("systemctl reload {unit}"),
            Reload::NextConnection => {
                "none needed; the server reads the file for each new connection".to_owned()
            }
        }
    }
}
