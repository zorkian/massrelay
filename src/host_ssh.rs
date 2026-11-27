//! The system's own OpenSSH server, which a peer granted the tunnel logs in to.
//!
//! `massrelay install` lets that server accept a key file MassRelay owns, for this account
//! and connections between `127.0.0.1` addresses only. It adds one marked `Match` block to
//! `sshd_config`, repeating the key files those logins already use and adding the new one,
//! and records what the runtime needs in `ssh-server.json` in the private profile. It never
//! starts, installs or replaces a server, and never changes listeners, firewalls or any other
//! setting. A plan only reads. `massrelay uninstall` removes what was added, keeping and
//! reporting whatever it cannot show to be its own or safe to remove.
//!
//! The key file is one an install made (`owned`). A configuration that names such a file
//! anywhere but in this account's blocks is refused.
//!
//! The runtime trusts `ssh-server.json` as the opt-in: install writes it only after the
//! server verified the change and reloaded, and uninstall removes it first. It lives in the
//! private profile and is not checked against `sshd_config` again. A later change to the
//! server makes logins fail at the server.
//!
//! The runtime writes keys to `authorized_keys` while holding an exclusive lock on
//! [`AUTHORIZED_KEYS_LOCK`] beside it, and calls [`Server::load`] after taking that lock, so
//! that nothing is added once uninstall has begun. It replaces the file with a new private
//! one (`windows_service::private_marker` on Windows), keeping it private to the account.
//!
//! One limitation follows from `sshd_config` having no way to append a key file: the block
//! repeats the list in force at install. A later `AuthorizedKeysFile` change reaches these
//! loopback logins only after another install.

mod config;
mod owned;
mod setup;
#[cfg(unix)]
mod unix;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows;

use std::{
    fmt, fs,
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, ensure};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::private::cli;

pub(crate) use setup::{InstallPlan, UninstallPlan};

/// The installed server's description, in the private profile.
pub(crate) const SERVER_FILE: &str = "ssh-server.json";
/// The key file the server reads for tunnel logins, in the private profile. It holds only
/// lines MassRelay generates.
pub(crate) const AUTHORIZED_KEYS: &str = "ssh-authorized-keys";
/// Held while the key file or the description changes.
pub(crate) const AUTHORIZED_KEYS_LOCK: &str = "ssh-authorized-keys.lock";
/// What setup has made and still owes, in the private profile.
pub(crate) const SETUP_RECORD: &str = "ssh-setup.json";
/// More than a description holds.
const SERVER_LIMIT: u64 = 16 * 1024;

/// There is no system SSH server to use: it is not installed, not running or not set up.
/// Callers can tell this apart from an unsafe configuration with `error.downcast_ref`.
#[derive(Debug)]
pub(crate) struct Unavailable(String);

impl fmt::Display for Unavailable {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.0)
    }
}

impl std::error::Error for Unavailable {}

/// A system SSH server was found, but MassRelay will not set it up or change it: its
/// configuration is unsafe, ambiguous or unsupported, or rights are missing. Every error of
/// a plan or an apply that is not [`Unavailable`] downcasts to this.
#[derive(Debug)]
pub(crate) struct Refused;

impl fmt::Display for Refused {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("MassRelay will not change the system SSH setup")
    }
}

/// The system SSH server a profile was set up with. The proxy's target is always
/// `127.0.0.1` at `port`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Server {
    /// The account that logs in.
    pub(crate) user: String,
    pub(crate) port: u16,
    /// The installed Ed25519 host key: `ssh-ed25519 BASE64`, no options or comment.
    pub(crate) host_key: String,
    /// The absolute path of [`AUTHORIZED_KEYS`] in this profile.
    pub(crate) authorized_keys: PathBuf,
}

impl Server {
    /// The server described in `profile`, the private profile directory. Fails when system
    /// SSH is not set up ([`Unavailable`]) or either file is not safe to use.
    pub(crate) fn load(profile: &Path) -> Result<Self> {
        let path = profile.join(SERVER_FILE);
        let contents = read_description(&path)?.ok_or_else(|| {
            anyhow!(Unavailable(
                "system SSH is not set up on this device; run 'massrelay install'".into()
            ))
        })?;
        let server: Self = serde_json::from_slice(&contents)
            .with_context(|| format!("read {}", path.display()))?;
        server
            .check(profile)
            .with_context(|| format!("{} is not usable", path.display()))?;
        Ok(server)
    }

    fn check(&self, profile: &Path) -> Result<()> {
        ensure!(valid_user(&self.user), "unsupported SSH account name");
        ensure!(self.port != 0, "the SSH port is zero");
        ensure!(
            ed25519(&self.host_key).as_deref() == Some(self.host_key.as_str()),
            "the host key is not a plain Ed25519 public key"
        );
        let keys = &self.authorized_keys;
        let beside = keys.is_absolute()
            && keys.file_name().is_some_and(|name| name == AUTHORIZED_KEYS)
            && match keys.parent() {
                Some(parent) => parent.canonicalize()? == profile.canonicalize()?,
                None => false,
            };
        ensure!(beside, "the key file is not this profile's");
        ensure!(private_content_exists(keys)?, "the key file is missing");
        Ok(())
    }
}

/// What installing system SSH for the enrolled device in `state_dir` would change. Reads
/// only, with no rights beyond this process's.
pub(crate) fn plan_install(state_dir: &Path) -> Result<InstallPlan> {
    let planned = (|| {
        let system = native(Purpose::Install)?;
        let profile = profile(system.as_ref(), state_dir)?.with_context(|| {
            format!(
                "no device profile in {}; run 'massrelay create' or 'massrelay join'",
                state_dir.display()
            )
        })?;
        InstallPlan::new(system, profile)
    })();
    planned.map_err(setup::refused)
}

/// What removing the system SSH setup of `state_dir` would change. Reads only.
pub(crate) fn plan_uninstall(state_dir: &Path) -> Result<UninstallPlan> {
    let planned = (|| match native(Purpose::Removal) {
        Ok(system) => match profile(system.as_ref(), state_dir)? {
            Some(profile) => UninstallPlan::new(system, profile),
            None => Ok(UninstallPlan::nothing()),
        },
        // Where setup cannot work, there is nothing to remove unless the profile says so.
        Err(_) if !setup::set_up(&state_dir.join(cli::DIR_NAME))? => Ok(UninstallPlan::nothing()),
        Err(error) => Err(error),
    })();
    planned.map_err(setup::refused)
}

/// Installing needs a server before anything else is looked at; removal must not.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Install,
    Removal,
}

#[cfg(unix)]
fn native(purpose: Purpose) -> Result<Box<dyn setup::System>> {
    Ok(Box::new(unix::Unix::native(purpose)?))
}

#[cfg(windows)]
fn native(purpose: Purpose) -> Result<Box<dyn setup::System>> {
    Ok(Box::new(windows::Windows::native(purpose)?))
}

/// The canonical private profile directory, if there is one.
fn profile(system: &dyn setup::System, state_dir: &Path) -> Result<Option<PathBuf>> {
    let path = state_dir.join(cli::DIR_NAME);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir(),
                "{} is not a directory; a link there is not followed",
                path.display()
            );
            let state = system.canonical(state_dir)?;
            Ok(Some(state.join(cli::DIR_NAME)))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("check {}", path.display())),
    }
}

/// An account name that is literal in `sshd_config` and on an `ssh` command line.
fn valid_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && !user.starts_with('-')
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// The oldest server that refuses an expired key (`expiry-time`).
const OLDEST_SERVER: (u32, u32) = (7, 7);

/// Require a new enough server from what `sshd -V` prints. Older servers print their
/// version with a complaint about the option.
fn check_version(printed: &str) -> Result<()> {
    let version = ["OpenSSH_for_Windows_", "OpenSSH_"]
        .into_iter()
        .find_map(|prefix| printed.split_once(prefix))
        .and_then(|(_, version)| version.split_once('.'))
        .and_then(|(major, minor)| {
            let digits = minor.split(|c: char| !c.is_ascii_digit()).next()?;
            Some((major.parse::<u32>().ok()?, digits.parse::<u32>().ok()?))
        })
        .context("cannot tell the SSH server's version")?;
    ensure!(
        version >= OLDEST_SERVER,
        "system SSH needs an OpenSSH 7.7 or later server, which can expire keys"
    );
    Ok(())
}

/// The Ed25519 key in `ssh-keyscan` output.
fn scanned_key(printed: &str) -> Option<String> {
    printed
        .lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| ed25519(line.split_once(' ')?.1))
}

const ED25519_PREFIX: &[u8] = b"\0\0\0\x0bssh-ed25519\0\0\0\x20";

/// The `ssh-ed25519 BASE64` of a public key line, without its comment. A line with options
/// or of another key type is none.
fn ed25519(line: &str) -> Option<String> {
    let mut fields = line.split_ascii_whitespace();
    if fields.next() != Some("ssh-ed25519") {
        return None;
    }
    let encoded = fields.next()?;
    let blob = STANDARD.decode(encoded).ok()?;
    (blob.len() == ED25519_PREFIX.len() + 32 && blob.starts_with(ED25519_PREFIX))
        .then(|| format!("ssh-ed25519 {encoded}"))
}

fn fingerprint(host_key: &str) -> String {
    let blob = host_key
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .unwrap_or_default();
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// A new file in the private profile, which only this account (and on Windows the
/// machine's administrators) can use, even when an elevated process creates it.
#[cfg(windows)]
use crate::windows_service::private_marker as private_file;

#[cfg(unix)]
fn private_file(dir: &Path) -> Result<tempfile::NamedTempFile> {
    tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("create a file in {}", dir.display()))
}

/// Whether the private profile file `path` exists. Fails unless it is a single regular file
/// that only this account (and administrators) can change.
fn private_exists(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("check {}", path.display())),
    };
    ensure!(
        metadata.is_file(),
        "expected a regular file at {}; a link there is not followed",
        path.display()
    );
    let directory = path.parent().context("the file has no directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let parent = fs::metadata(directory)?;
        ensure!(
            metadata.uid() == parent.uid()
                && metadata.mode() & 0o022 == 0
                && parent.mode() & 0o022 == 0
                && metadata.nlink() == 1,
            "{} must be a single file that only the profile's owner can change",
            path.display()
        );
    }
    // The private directory's access list admits only this account and administrators.
    #[cfg(windows)]
    crate::windows_service::ssh_private_dir(directory)?;
    Ok(true)
}

/// [`private_exists`], for a file whose contents are trusted. On Windows the file's own
/// owner and access list are checked as well, which reads it: not for a lock file.
fn private_content_exists(path: &Path) -> Result<bool> {
    let exists = private_exists(path)?;
    #[cfg(windows)]
    if exists {
        crate::windows_service::ssh_files::check_managed_file(path)?;
    }
    Ok(exists)
}

fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("check {}", path.display())),
    }
}

fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(directory) = path.parent() {
                sync_directory(directory);
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

/// The server description's bytes, if there is one.
fn read_description(path: &Path) -> Result<Option<Vec<u8>>> {
    if !private_content_exists(path)? {
        return Ok(None);
    }
    let mut contents = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(SERVER_LIMIT + 1).read_to_end(&mut contents))
        .with_context(|| format!("read {}", path.display()))?;
    ensure!(
        contents.len() as u64 <= SERVER_LIMIT,
        "{} is too large",
        path.display()
    );
    Ok(Some(contents))
}

/// Atomically publish `contents` as a private file of the profile.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let directory = path.parent().context("the file has no directory")?;
    let mut staged = private_file(directory)?;
    staged.write_all(contents)?;
    staged.as_file().sync_all()?;
    staged
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("write {}", path.display()))?;
    sync_directory(directory);
    Ok(())
}

fn sync_directory(directory: &Path) {
    // The rename already took effect. Some filesystems reject directory fsync.
    #[cfg(unix)]
    let _ = fs::File::open(directory).and_then(|directory| directory.sync_all());
    #[cfg(windows)]
    let _ = directory;
}

/// Wait for and hold an exclusive lock on the profile file `name`.
fn lock(profile: &Path, name: &str) -> Result<fs::File> {
    let path = profile.join(name);
    if !private_exists(&path)? {
        let staged = private_file(profile)?;
        if let Err(error) = staged.persist_noclobber(&path) {
            ensure!(
                error.error.kind() == io::ErrorKind::AlreadyExists,
                "create {}: {}",
                path.display(),
                error.error
            );
        }
        ensure!(private_exists(&path)?, "the lock file disappeared");
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    fs2::FileExt::lock_exclusive(&file).with_context(|| format!("lock {}", path.display()))?;
    Ok(file)
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
