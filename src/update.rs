//! `massrelay update`: replace the installed program of this device's background service with
//! the latest public release, without ending anyone's session.
//!
//! # The rule everything follows
//!
//! The updater never asks a service manager to stop anything. A process is only ever named to
//! a service manager by its service, and whatever runs under that name when the request
//! lands is what stops. So the one runtime that may end is asked to end itself, on the
//! authenticated connection on which it proved, in one step under its session lock, that it
//! was idle and had closed admission (`exchange`). That connection also says which process it
//! is. Nothing that takes its place can be hit by mistake, because nothing is aimed at a name.
//!
//! A runtime that does not answer control cannot be asked, and is therefore left alone: the
//! update stays unfinished, with its journal and both program files kept, for a later run.
//!
//! # Order of work
//!
//! 1. **Checks.** The profile's runtime must answer its authenticated local control channel,
//!    and must be the process the service manager runs for this profile's installed service,
//!    started from the program the service's effective definition names.
//! 2. **Download** (`release`): anonymous, HTTPS only, with deadlines, checksum verified.
//! 3. **Stage** (`Staging`). The candidate is written beside the installed program, in a
//!    directory that is this account's alone and that no other account can reach around:
//!    every directory above it is checked before anything is written or run there.
//! 4. **Preflight.** The staged bytes, re-read against the published checksum, run
//!    `update-self-check`, bounded in time including their output.
//! 5. **Hold.** The running service keeps serving until its runtime grants a hold: nothing is
//!    live and admission is closed. Under the staging lock everything is checked again
//!    (`revalidate`) against the identity that came with the hold.
//! 6. **Exchange.** Where a program can be replaced while it runs (Linux, macOS), the
//!    candidate is renamed over the installed program first, and then the held runtime is told
//!    to retire. It ends itself, and whatever the service manager or the updater starts next
//!    is the candidate. So there is no moment at which a start could run the old program
//!    again, whatever the service manager's restart policy. Where it cannot (Windows), the
//!    held runtime retires and ends cleanly, which the Windows service manager never restarts,
//!    and the candidate is renamed into place once nothing runs.
//! 7. **Verify** (`settle`). The service manager's process must answer local control for the
//!    same endpoint with the new version, from the installed bytes. A stopped service is
//!    started; a running one is never restarted.
//! 8. **Revert** on any failure after the exchange began: the previous bytes go back, and if
//!    the new program serves, it leaves the same way, by itself, once idle.
//!
//! A commit whose answer is lost proves nothing either way. The updater then watches what
//! serves, for longer than the hold could have lasted, and acts on what it sees.
//!
//! # What is kept, and until when
//!
//! The journal, the saved previous program and the staged candidate all stay until the
//! intended bytes are read back from the installed path and the intended service is verified
//! healthy. Both programs are installed by linking, never by moving the only copy. A failure
//! to make any of it durable is a failure of the step.
//!
//! # Interruption
//!
//! The next `massrelay update` takes the staging lock, reads the journal under it (`recover`)
//! and decides from the installed bytes, the service's definition and the runtime's
//! authenticated identity: a healthy new version is kept, a previous version that still
//! serves is left serving with its own bytes, a stopped service is started on the previous
//! bytes, and anything else that serves leaves by itself once idle.
//!
//! On Windows the exchange and any recovery run in a copy of this program started from the
//! staging directory after the invoking process has exited, so the installed file is mapped
//! by neither the service nor the command when it is replaced.

mod release;

use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;

use crate::private::cli;
use crate::private::runtime::{
    self, CONTROL, ControlReply, ControlRequest, Identity, UpdateReply, UpdateRequest,
};
use crate::wire;

use release::{Release, Source, Version};

const STAGING: &str = ".massrelay-update";
const JOURNAL: &str = "update-journal.json";
const JOURNAL_FORMAT: &str = "massrelay-update-journal/2";
const SELF_CHECK_FORMAT: &str = "massrelay-update-self-check/1";
const SELF_CHECK_TIMEOUT: Duration = Duration::from_secs(60);
/// The longest any one request to a service manager may take.
pub(crate) const MANAGER_LIMIT: Duration = Duration::from_secs(60);

/// The installed background service of one profile, as its service manager sees it. There is
/// no way to stop it here, on purpose.
pub trait Service: Send + Sync {
    fn label(&self) -> String;
    /// The profile's connection audit file.
    fn events(&self) -> PathBuf;
    /// Whether the service, as the service manager would start it now, runs exactly `program`
    /// for this profile: the definition on disk and the one the manager has loaded.
    fn launches(&self, program: &Path) -> Result<bool>;
    /// Refuse a path the service's account must not run from or stage in. On Windows: no
    /// other account may modify it or any directory above it, and none of them is a reparse
    /// point. Elsewhere `Staging` makes the equivalent checks itself.
    fn trusts(&self, _path: &Path) -> Result<()> {
        Ok(())
    }
    /// Refuse now if this account may not start the service.
    fn controllable(&self) -> Result<()> {
        Ok(())
    }
    /// Whether the installed program can be replaced while the service runs from it.
    fn replaces_running(&self) -> bool {
        !cfg!(windows)
    }
    /// What the service manager says of the service, in its own terms.
    fn state(&self) -> Result<Manager>;
    /// Start a stopped service.
    fn start(&self) -> Result<()>;
}

/// A service as its manager reports it. Only `Stopped` means that nothing runs: a start or a
/// stop under way, or any state this does not know, is `Pending`, and is never taken for
/// stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Manager {
    /// Running, as this process.
    Running(u32),
    /// Not running, and not about to be.
    Stopped,
    /// Anything else. Says what.
    Pending(String),
}

/// The answer to a request to close admission.
pub enum Held {
    /// Admission is closed, and nothing is live, while this is kept and its lease lasts.
    Yes(Box<dyn Hold>),
    Busy {
        connections: usize,
        exposures: usize,
        held: bool,
    },
}

/// Closed admission on one idle runtime, on that runtime's own control connection.
pub trait Hold: Send {
    /// The runtime that granted this hold, as it named itself on this connection.
    fn identity(&self) -> &Identity;
    /// How long the hold lasts without a commit.
    fn lease(&self) -> Duration;
    /// Ask that runtime to retire and end itself. `true`: it confirmed. `false`: no
    /// confirmation was received, which says nothing about whether it retired.
    fn commit(&mut self) -> bool;
}

/// What the update needs from the machine. Called from blocking code only.
pub trait Host: Send + Sync {
    fn service(&self) -> &dyn Service;
    /// What answers the profile's authenticated local control channel now.
    fn identify(&self) -> Result<Identity>;
    /// Ask that runtime to close admission if nothing is live.
    fn hold(&self) -> Result<Held>;
    /// Whether no runtime owns the profile.
    fn released(&self) -> bool;
}

/// A request to give up, honoured only while the update is waiting.
pub(crate) trait Interrupt: Send + Sync {
    fn interrupted(&self) -> bool;
}

struct Live<S> {
    service: S,
    state_dir: PathBuf,
    handle: tokio::runtime::Handle,
}

impl<S: Service> Host for Live<S> {
    fn service(&self) -> &dyn Service {
        &self.service
    }

    fn identify(&self) -> Result<Identity> {
        self.handle
            .block_on(identify(&self.state_dir.join(cli::DIR_NAME)))
    }

    fn hold(&self) -> Result<Held> {
        live_hold(&self.handle, &self.state_dir.join(cli::DIR_NAME))
    }

    fn released(&self) -> bool {
        cli::claim_owner(&self.state_dir).is_ok()
    }
}

/// How long each step may take.
#[derive(Clone, Copy)]
pub(crate) struct Timing {
    /// Between attempts to find the device idle.
    pub poll: Duration,
    /// For a service to settle: to answer correctly once started, or to finish a start or an
    /// end that is under way.
    pub verify: Duration,
    pub retry: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(2),
            verify: Duration::from_secs(60),
            retry: Duration::from_secs(2),
        }
    }
}

impl Timing {
    fn pause(&self) {
        std::thread::sleep(Duration::from_millis(250).min(self.retry));
    }
}

// ----------------------------------------------------------------- control

pub(crate) async fn identify(profile: &Path) -> Result<Identity> {
    let request = ControlRequest::Update(UpdateRequest::Identify);
    match runtime::request(profile, request).await?.1 {
        ControlReply::Update(UpdateReply::Identity(identity)) => Ok(identity),
        ControlReply::Update(UpdateReply::Retired) => bail!("the runtime retired and is ending"),
        ControlReply::Error(error) => bail!("{error}"),
        _ => bail!("unexpected reply from the runtime"),
    }
}

/// The hold's control connection. Both steps of the protocol happen on it.
struct LiveHold {
    socket: TcpStream,
    identity: Identity,
    lease: Duration,
    handle: tokio::runtime::Handle,
}

impl Hold for LiveHold {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn lease(&self) -> Duration {
        self.lease
    }

    fn commit(&mut self) -> bool {
        self.handle.block_on(async {
            if wire::send(&mut self.socket, UpdateRequest::Commit)
                .await
                .is_err()
            {
                return false;
            }
            let reply = tokio::time::timeout(wire::RPC_TIMEOUT, wire::recv(&mut self.socket)).await;
            matches!(reply, Ok(Ok(ControlReply::Update(UpdateReply::Retired))))
        })
    }
}

/// Ask the runtime of `profile` to close admission if nothing is live.
pub(crate) fn live_hold(handle: &tokio::runtime::Handle, profile: &Path) -> Result<Held> {
    let request = ControlRequest::Update(UpdateRequest::Hold);
    let (socket, reply) = handle.block_on(runtime::request(profile, request))?;
    match reply {
        ControlReply::Update(UpdateReply::Held {
            lease_secs,
            identity,
        }) => Ok(Held::Yes(Box::new(LiveHold {
            socket,
            identity,
            lease: Duration::from_secs(lease_secs),
            handle: handle.clone(),
        }))),
        ControlReply::Update(UpdateReply::Busy {
            connections,
            exposures,
            held,
        }) => Ok(Held::Busy {
            connections,
            exposures,
            held,
        }),
        ControlReply::Error(error) => bail!("{error}"),
        _ => bail!("unexpected reply from the runtime"),
    }
}

// ----------------------------------------------------------------- staging

/// The user ID files created by this process get.
#[cfg(unix)]
fn own_uid() -> io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    Ok(tempfile::tempfile()?.metadata()?.uid())
}

/// Refuse a directory through which another account could replace what is below it: it must
/// be a real directory, owned by this account or root, and writable by nobody else unless it
/// is sticky (where only an entry's owner may replace it).
#[cfg(unix)]
fn check_exclusive(dir: &Path, own: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(dir).with_context(|| format!("read {}", dir.display()))?;
    ensure!(
        metadata.is_dir(),
        "{} is not a directory (a symbolic link is not followed)",
        dir.display()
    );
    ensure!(
        metadata.uid() == own || metadata.uid() == 0,
        "{} belongs to another account",
        dir.display()
    );
    let mode = metadata.mode();
    ensure!(
        mode & 0o022 == 0 || mode & 0o1000 != 0,
        "{} can be changed by other accounts (mode {:o}). 'massrelay update' stages and runs \
         the download below it. Remove that access with 'chmod go-w {}' and run it again",
        dir.display(),
        mode & 0o7777,
        dir.display()
    );
    Ok(())
}

/// Refuse a directory that another account could reach around: the path to it must name it
/// directly, with no symbolic link on the way, and it and every directory above it must be
/// exclusive (`check_exclusive`).
#[cfg(unix)]
pub(crate) fn check_ancestry(dir: &Path) -> Result<()> {
    let own = own_uid()?;
    let resolved = dir
        .canonicalize()
        .with_context(|| format!("resolve {}", dir.display()))?;
    ensure!(
        dir.is_absolute() && resolved == dir,
        "{} is reached through a symbolic link; 'massrelay update' does not follow one to the \
         installed program",
        dir.display()
    );
    for ancestor in dir.ancestors() {
        check_exclusive(ancestor, own)?;
    }
    Ok(())
}

/// Refuse an installed program that another account could rewrite in place: it must be a
/// regular file, owned by this account or root, and writable by nobody else. It is checked
/// before it is run for its version, saved for rollback, or replaced.
fn check_program(installed: &Path) -> Result<()> {
    regular(installed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(installed)?;
        let own = own_uid()?;
        ensure!(
            metadata.uid() == own || metadata.uid() == 0,
            "{} belongs to another account",
            installed.display()
        );
        ensure!(
            metadata.mode() & 0o022 == 0,
            "{} can be changed by other accounts (mode {:o}). Remove that access with \
             'chmod go-w {}' and run 'massrelay update' again",
            installed.display(),
            metadata.mode() & 0o7777,
            installed.display()
        );
    }
    Ok(())
}

/// A path that must be a regular file: never a symbolic link or another kind of entry.
fn regular(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("read {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    Ok(())
}

/// Make a file's contents durable. Windows flushes only through a writable handle, which a
/// link to a program in use cannot give; its renames are journaled by the filesystem.
fn sync_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Make a directory's entries durable.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Replace a same-filesystem file, requesting write-through on Windows.
fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let wide = |path: &Path| {
            path.as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>()
        };
        let from = wide(from);
        let to = wide(to);
        // Both NUL-terminated paths remain valid for the duration of the call.
        if unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    fs::rename(from, to)
}

/// The directory beside the installed program where one update at a time stages its files.
/// Nobody but this account can change what is in it, replace it, or replace a directory on
/// the way to it (see `check`), and it belongs to the profile whose update is in progress.
pub(crate) struct Staging {
    dir: PathBuf,
    _lock: File,
}

impl Staging {
    /// Create or reuse the staging directory of `installed` for the profile in `state_dir`,
    /// after checking the installed program and the whole path to it, and take its lock.
    /// `trusts` is the service's own check of a path (`Service::trusts`): it passes the
    /// installed program before anything is created, and the staging directory before
    /// anything in it is opened or written. Refused while another profile that shares the
    /// program has an unfinished update there.
    fn open(
        installed: &Path,
        state_dir: &Path,
        trusts: &dyn Fn(&Path) -> Result<()>,
    ) -> Result<Self> {
        let parent = installed
            .parent()
            .context("the installed program has no directory")?;
        let dir = parent.join(STAGING);
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        let denied = |error: io::Error, what: &str| {
            if error.kind() == io::ErrorKind::PermissionDenied {
                anyhow!(
                    "this account may not {what} in {}. Run 'massrelay update' as the account \
                     that installed {}",
                    parent.display(),
                    installed.display()
                )
            } else {
                anyhow!("{what} in {}: {error}", parent.display())
            }
        };
        // Nothing is created below a directory that other accounts can change or reach around,
        // or beside a program they can rewrite.
        #[cfg(unix)]
        check_ancestry(parent)?;
        check_program(installed)?;
        trusts(installed)?;
        match builder.create(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(denied(error, "create the update's staging directory")),
        }
        Self::check(&dir)?;
        trusts(&dir)?;
        // Nothing in a private directory is a link unless this account made it one.
        let lock = dir.join("lock");
        if lock.try_exists()? || fs::symlink_metadata(&lock).is_ok() {
            regular(&lock)?;
            trusts(&lock)?;
        }
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock)
            .map_err(|error| denied(error, "write the update's lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| {
            anyhow!(
                "another 'massrelay update' is already working on {}",
                installed.display()
            )
        })?;
        let staging = Self { dir, _lock: lock };
        staging.claim(state_dir, trusts)?;
        Ok(staging)
    }

    /// The private boundary: the staging directory is a real directory that only this account
    /// can read or change, and no other account can change any directory on the way to it.
    fn check(dir: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            check_ancestry(dir.parent().context("no directory")?)?;
            let metadata =
                fs::symlink_metadata(dir).with_context(|| format!("read {}", dir.display()))?;
            ensure!(
                metadata.is_dir() && metadata.uid() == own_uid()? && metadata.mode() & 0o077 == 0,
                "{} is not a directory that only this account can use. Remove it and run \
                 'massrelay update' again",
                dir.display()
            );
        }
        // On Windows `Service::trusts` checks the access lists and reparse points of the
        // whole path, before anything is written or run.
        #[cfg(not(unix))]
        ensure!(
            fs::symlink_metadata(dir).is_ok_and(|metadata| metadata.is_dir()),
            "{} is not a directory. Remove it and run 'massrelay update' again",
            dir.display()
        );
        Ok(())
    }

    /// Record which profile's update owns the staged files. Profiles whose services share one
    /// program share this directory, and an unfinished update of one must not be swept away
    /// by another.
    fn claim(&self, state_dir: &Path, trusts: &dyn Fn(&Path) -> Result<()>) -> Result<()> {
        let marker = self.dir.join("profile");
        if marker.try_exists()? || fs::symlink_metadata(&marker).is_ok() {
            regular(&marker)?;
            trusts(&marker)?;
            let owner: PathBuf = serde_json::from_slice(&fs::read(&marker)?)
                .context("read the staging directory's profile")?;
            if owner == state_dir {
                return Ok(());
            }
            ensure!(
                !owner.join(JOURNAL).try_exists()?,
                "an update of this program for the profile in {} is unfinished. Run \
                 'massrelay --state-dir {} update' first",
                owner.display(),
                owner.display()
            );
            // A past unlink may have succeeded without a durable directory sync.
            if self.previous().try_exists()? || self.candidate().try_exists()? {
                sync_dir(&owner).context("verify the previous update was closed durably")?;
            }
        }
        let mut saved = tempfile::NamedTempFile::new_in(&self.dir)?;
        serde_json::to_writer(saved.as_file_mut(), state_dir)?;
        saved.as_file().sync_all()?;
        replace_file(&saved.into_temp_path(), &marker)?;
        sync_dir(&self.dir)?;
        Ok(())
    }

    fn file(&self, name: &str) -> PathBuf {
        let extension = if cfg!(windows) { ".exe" } else { "" };
        self.dir.join(format!("{name}{extension}"))
    }

    fn candidate(&self) -> PathBuf {
        self.file("candidate")
    }

    fn previous(&self) -> PathBuf {
        self.file("previous")
    }

    /// Put the bytes of `source`, which must match `digest`, at `installed`, by one rename of
    /// a second link (or, without links, of a copy). `source` itself stays where it is, so
    /// installing never uses up the only copy of a program. An error before the rename
    /// leaves `installed` as it was; the caller reads it back to know.
    fn place(&self, source: &Path, digest: &str, installed: &Path) -> Result<(), String> {
        let placing = self.file("placing");
        let prepared = (|| {
            let _ = fs::remove_file(&placing);
            ensure!(
                has_digest(source, digest),
                "{} is missing or is not the verified file",
                source.display()
            );
            if fs::hard_link(source, &placing).is_err() {
                fs::copy(source, &placing)?;
            }
            sync_file(&placing)?;
            ensure!(
                has_digest(&placing, digest),
                "the file changed while it was linked"
            );
            sync_dir(&self.dir)?;
            Ok(())
        })();
        prepared.map_err(|error: anyhow::Error| {
            format!("could not prepare {}: {error:#}", installed.display())
        })?;
        replace_file(&placing, installed).map_err(|error| match error.kind() {
            io::ErrorKind::PermissionDenied => format!(
                "this account may not replace {}: {error}",
                installed.display()
            ),
            _ => format!("could not replace {}: {error}", installed.display()),
        })?;
        installed
            .parent()
            .map_or(Ok(()), sync_dir)
            .map_err(|error| {
                format!(
                    "{} was replaced, but that could not be made durable: {error}",
                    installed.display()
                )
            })
    }

    /// Remove what earlier runs left. A Windows helper still exiting keeps its own file.
    fn sweep(&self) {
        for name in ["candidate", "previous", "placing", "helper"] {
            let _ = fs::remove_file(self.file(name));
        }
    }

    fn clear(self) {
        self.sweep();
        // Retain the lock inode. A process that opened it before this one closes
        // must contend on the same inode as a later process opening the path.
    }
}

/// The SHA-256 of a regular file, in hex.
fn sha256_file(path: &Path) -> Result<String> {
    regular(path)?;
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        match file.read(&mut buffer)? {
            0 => break,
            n => hash.update(&buffer[..n]),
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn has_digest(path: &Path, digest: &str) -> bool {
    sha256_file(path).is_ok_and(|found| found == digest)
}

/// Download the release's artifact into the staging directory, verified and durable, with
/// the installed program's permissions. Nothing is left behind when it fails.
async fn stage(
    client: &release::Client<'_>,
    release: &Release,
    staging: &Staging,
    installed: &Path,
) -> Result<String> {
    let asset = release::asset()?;
    let expected = client.checksum(release, asset).await?;
    let candidate = staging.candidate();
    let _ = fs::remove_file(&candidate);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&candidate)
        .with_context(|| format!("create {}", candidate.display()))?;
    let staged = async {
        client
            .download(release, asset, &expected, |chunk| {
                file.write_all(chunk).context("write the staged program")
            })
            .await?;
        #[allow(unused_mut)]
        let mut permissions = fs::metadata(installed)?.permissions();
        #[cfg(unix)]
        {
            // The installed program's access, without write access for others or special bits.
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(permissions.mode() & 0o755);
        }
        file.set_permissions(permissions)
            .context("give the staged program the installed program's permissions")?;
        file.sync_all()?;
        sync_dir(&staging.dir).context("make the staged program durable")?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    drop(file);
    if let Err(error) = staged {
        let _ = fs::remove_file(&candidate);
        return Err(error);
    }
    Ok(expected.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Keep the installed program's exact bytes under a second name for the way back, durably.
fn keep_previous(staging: &Staging, installed: &Path) -> Result<String> {
    regular(installed)?;
    let previous = staging.previous();
    let _ = fs::remove_file(&previous);
    // A hard link keeps the file's owner and protection as they are; a copy is the fallback
    // where the filesystem has no links.
    if fs::hard_link(installed, &previous).is_err() {
        fs::copy(installed, &previous)
            .with_context(|| format!("copy {} for rollback", installed.display()))?;
    }
    sync_file(&previous).context("make the saved program durable")?;
    sync_dir(&staging.dir).context("make the saved program durable")?;
    let digest = sha256_file(&previous)?;
    ensure!(
        has_digest(installed, &digest),
        "{} changed while it was being saved for rollback",
        installed.display()
    );
    Ok(digest)
}

// --------------------------------------------------------------- preflight

/// What a program reports about itself and a profile in `update-self-check`.
#[derive(Serialize, Deserialize)]
struct SelfCheck {
    format: String,
    version: String,
    asset: String,
    endpoint: String,
}

/// The `update-self-check` command: run by a staged candidate before it replaces anything.
pub async fn self_check(state_dir: &Path) -> Result<i32> {
    let endpoint = cli::check_profile_for_update(state_dir).await?;
    let report = SelfCheck {
        format: SELF_CHECK_FORMAT.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        asset: release::asset()?.into(),
        endpoint,
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(0)
}

/// What a program that ran to its end left behind.
pub(crate) struct Finished {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// One of a program's outputs as it arrives. This owns what has arrived, so letting it go
/// frees that at once, even while its reader is blocked on an output that stays open.
struct Output {
    bytes: Arc<Mutex<Vec<u8>>>,
    ended: mpsc::Receiver<io::Result<u64>>,
}

/// Where a reader puts what arrives: in its `Output`, which it does not keep alive.
struct Arrival(Weak<Mutex<Vec<u8>>>);

impl io::Write for Arrival {
    fn write(&mut self, part: &[u8]) -> io::Result<usize> {
        // With nothing waiting for it, the reader ends here and closes the pipe.
        let bytes = self.0.upgrade().ok_or(io::ErrorKind::BrokenPipe)?;
        let mut bytes = bytes.lock().unwrap_or_else(PoisonError::into_inner);
        bytes.try_reserve(part.len())?;
        bytes.extend_from_slice(part);
        Ok(part.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Output {
    /// Read `pipe` to its end on a thread of its own.
    fn collect(pipe: Option<impl io::Read + Send + 'static>) -> Self {
        let bytes = Arc::default();
        let mut arrival = Arrival(Arc::downgrade(&bytes));
        let (done, ended) = mpsc::channel();
        std::thread::spawn(move || {
            let read = pipe.map_or(Ok(0), |mut pipe| io::copy(&mut pipe, &mut arrival));
            // A failed read or allocation is reported, never taken for the end of the output.
            let _ = done.send(read);
        });
        Self { bytes, ended }
    }

    /// All of the output, once everything that has it open closed it. `None` if that takes
    /// longer than `wait`.
    fn finish(self, wait: Duration) -> Option<io::Result<String>> {
        let ended = self.ended.recv_timeout(wait).ok()?;
        Some(ended.map(|_| {
            let mut bytes = self.bytes.lock().unwrap_or_else(PoisonError::into_inner);
            String::from_utf8(std::mem::take(&mut *bytes))
                .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
        }))
    }
}

/// Run a program within `limit`, with no input, and collect all of its output. The limit
/// covers the output too: a program that exits but leaves its output open, in a process it
/// started, does not hold this up. Its readers are left behind, holding none of the output,
/// and each ends when that process closes the output or next writes to it.
pub(crate) fn run_within(command: &mut Command, limit: Duration) -> Result<Finished> {
    let deadline = Instant::now() + limit;
    let late = || anyhow!("it did not finish within {} seconds", limit.as_secs());
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start the program")?;
    let stdout = Output::collect(child.stdout.take());
    let stderr = Output::collect(child.stderr.take());
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(late());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let read = |output: Output| {
        output
            .finish(deadline.saturating_duration_since(Instant::now()))
            .ok_or_else(late)?
            .context("read the program's output")
    };
    Ok(Finished {
        success: status.success(),
        stdout: read(stdout)?,
        stderr: read(stderr)?,
    })
}

/// Run the staged candidate's self-check and require it to be `release` for this platform,
/// reading the same profile. What runs is the file whose bytes match `digest`.
fn preflight(
    candidate: &Path,
    digest: &str,
    state_dir: &Path,
    release: &Release,
    endpoint: &str,
    limit: Duration,
) -> Result<()> {
    ensure!(
        has_digest(candidate, digest),
        "the staged program is not the verified download"
    );
    let mut command = Command::new(candidate);
    command
        .arg("--state-dir")
        .arg(state_dir)
        .arg("update-self-check");
    let Finished {
        success,
        stdout,
        stderr,
    } = run_within(&mut command, limit).context("the downloaded program failed its self-check")?;
    if !success {
        let reason = stderr.lines().last().unwrap_or("it exited with an error");
        bail!(
            "the downloaded program failed its self-check: {}",
            crate::visible(reason)
        );
    }
    let report: SelfCheck = serde_json::from_str(stdout.trim())
        .ok()
        .filter(|report: &SelfCheck| report.format == SELF_CHECK_FORMAT)
        .context("the downloaded program's self-check gave no usable report")?;
    ensure!(
        Version::parse(&report.version) == Some(release.version),
        "the downloaded program reports version {}, not the release's {}",
        crate::visible(&report.version),
        release.version
    );
    ensure!(
        report.asset == release::asset()?,
        "the downloaded program was built for another platform ({})",
        crate::visible(&report.asset)
    );
    ensure!(
        report.endpoint == endpoint,
        "the downloaded program read another device identity from this profile"
    );
    Ok(())
}

/// The version a program file prints for `--version`.
fn program_version(program: &Path) -> Result<String> {
    let mut command = Command::new(program);
    command.arg("--version");
    let finished = run_within(&mut command, Duration::from_secs(20))
        .with_context(|| format!("run {} --version", program.display()))?;
    ensure!(finished.success, "{} --version failed", program.display());
    finished
        .stdout
        .split_whitespace()
        .last()
        .map(str::to_owned)
        .context("no version was printed")
}

// ----------------------------------------------------------------- journal

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    /// Staged and checked; neither the service nor the installed program has been touched.
    Armed,
    /// The exchange began: the installed program may be either one, and either may serve.
    Switching,
}

/// The transaction record of one update. Holds no secret. It exists from the moment the
/// update is staged until the intended program is verified on disk and serving.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Journal {
    format: String,
    phase: Phase,
    installed: PathBuf,
    previous_version: String,
    previous_sha256: String,
    candidate_version: String,
    candidate_sha256: String,
    endpoint: String,
}

impl Journal {
    fn load(state_dir: &Path) -> Result<Option<Self>> {
        if !state_dir.join(JOURNAL).try_exists()? {
            return Ok(None);
        }
        let journal: Self = crate::storage::load(state_dir, JOURNAL)?;
        ensure!(
            journal.format == JOURNAL_FORMAT,
            "{} was written by another version of massrelay",
            state_dir.join(JOURNAL).display()
        );
        Ok(Some(journal))
    }

    /// Write the journal so that it survives a crash, or fail.
    fn record(&mut self, state_dir: &Path, phase: Phase) -> Result<()> {
        self.phase = phase;
        let saved = (|| {
            let mut file = tempfile::NamedTempFile::new_in(state_dir)?;
            serde_json::to_writer(file.as_file_mut(), self)?;
            file.as_file().sync_all()?;
            replace_file(&file.into_temp_path(), &state_dir.join(JOURNAL))?;
            sync_dir(state_dir)?;
            Ok::<_, anyhow::Error>(())
        })();
        saved.context("write the update journal durably")
    }

    /// Take the staging lock that `seen`, a journal read without it, points at, and read the
    /// journal again under the lock. Only that second reading is acted on: `None` if the
    /// update it described was finished meanwhile, an error if it became another one.
    fn lock(
        state_dir: &Path,
        seen: &Self,
        service: &dyn Service,
    ) -> Result<Option<(Staging, Self)>> {
        let staging = Staging::open(&seen.installed, state_dir, &|path| service.trusts(path))?;
        match Self::load(state_dir)? {
            Some(current) if current == *seen => Ok(Some((staging, current))),
            Some(_) => {
                bail!("another 'massrelay update' changed this profile's update; run it again")
            }
            None => Ok(None),
        }
    }

    /// The journal of this profile's unfinished update, read under its staging lock.
    fn locked(state_dir: &Path, service: &dyn Service) -> Result<Option<(Staging, Self)>> {
        match Self::load(state_dir)? {
            Some(seen) => Self::lock(state_dir, &seen, service),
            None => Ok(None),
        }
    }

    fn previous(&self, staging: &Staging) -> Image {
        Image {
            file: staging.previous(),
            sha256: self.previous_sha256.clone(),
            version: self.previous_version.clone(),
        }
    }

    fn candidate(&self, staging: &Staging) -> Image {
        Image {
            file: staging.candidate(),
            sha256: self.candidate_sha256.clone(),
            version: self.candidate_version.clone(),
        }
    }
}

/// One of the update's two programs: its kept file, its bytes and the version it runs as.
struct Image {
    file: PathBuf,
    sha256: String,
    version: String,
}

/// Close the transaction: remove the journal, durably, and only then the staged files. If the
/// journal cannot be removed, or its removal cannot be made durable, both programs stay where
/// they are, because a journal that survives must still find them.
///
/// Called directly only when the update changed nothing. Everything else ends in `complete`.
fn close(state_dir: &Path, staging: Staging) -> Result<(), String> {
    let journal = state_dir.join(JOURNAL);
    let kept = |error: io::Error| {
        format!(
            "the update journal {} could not be removed durably ({error}), so the update's \
             files are kept. Run 'massrelay update' again",
            journal.display()
        )
    };
    #[cfg(windows)]
    let closed = state_dir.join("update-journal.closed");
    #[cfg(windows)]
    let removal = replace_file(&journal, &closed);
    #[cfg(not(windows))]
    let removal = fs::remove_file(&journal);
    match removal {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(kept(error)),
    }
    sync_dir(state_dir).map_err(kept)?;
    staging.clear();
    #[cfg(windows)]
    let _ = fs::remove_file(closed);
    Ok(())
}

/// The one way an update that changed anything ends. `image` must be what is installed,
/// durably, and what the service serves healthily, checked here once more; only then is the
/// transaction closed. On any mismatch nothing is removed.
fn complete(
    host: &dyn Host,
    state_dir: &Path,
    staging: Staging,
    journal: &Journal,
    image: &Image,
) -> Result<(), String> {
    let installed = &journal.installed;
    // An earlier sync of this directory may have failed after its rename had happened.
    installed
        .parent()
        .map_or(Ok(()), sync_dir)
        .map_err(|error| format!("{} could not be made durable: {error}", installed.display()))?;
    if !has_digest(installed, &image.sha256) {
        return Err(format!(
            "{} does not read back as the version {} program",
            installed.display(),
            image.version
        ));
    }
    if !healthy(host, journal, image) {
        return Err(format!(
            "the service is no longer seen serving version {} healthily",
            image.version
        ));
    }
    close(state_dir, staging)
}

// ------------------------------------------------------- service transitions

pub(crate) fn say(text: impl AsRef<str>) {
    // A closed terminal must not stop an exchange half way.
    let _ = writeln!(io::stdout(), "{}", text.as_ref());
}

/// What serves the profile, where the service manager and authenticated control agree.
enum Serving {
    /// The service manager's process answers control as this runtime.
    Managed(Identity),
    /// The service manager runs nothing and nothing owns the profile.
    Stopped,
    /// Neither: a start or an end under way, a process that does not answer, or a runtime
    /// that is not the service manager's. Says which.
    Unsettled(String),
}

fn serving(host: &dyn Host) -> Serving {
    let state = match host.service().state() {
        Ok(state) => state,
        Err(error) => {
            return Serving::Unsettled(format!("the service manager did not answer: {error:#}"));
        }
    };
    match (state, host.identify()) {
        (Manager::Pending(what), _) => {
            Serving::Unsettled(format!("the service manager reports the service {what}"))
        }
        // A hold is in force on it: it may be about to retire and end.
        (Manager::Running(pid), Ok(identity)) if identity.pid == pid && identity.held => {
            Serving::Unsettled("the runtime is held for an update and may be ending".into())
        }
        (Manager::Running(pid), Ok(identity)) if identity.pid == pid => Serving::Managed(identity),
        (_, Ok(_)) => Serving::Unsettled(
            "a runtime that is not the installed service answers for this profile".into(),
        ),
        (Manager::Running(_), Err(error)) => Serving::Unsettled(format!(
            "the service's process does not answer as a serving runtime ({error:#})"
        )),
        (Manager::Stopped, Err(_)) if host.released() => Serving::Stopped,
        (Manager::Stopped, Err(_)) => {
            Serving::Unsettled("the service is stopped, but the profile is still in use".into())
        }
    }
}

/// `serving`, after waiting out a start or an end that is under way, for `timing.verify`.
fn observe(host: &dyn Host, timing: Timing) -> Serving {
    observe_for(host, timing, timing.verify)
}

fn observe_for(host: &dyn Host, timing: Timing, limit: Duration) -> Serving {
    let deadline = Instant::now() + limit;
    loop {
        match serving(host) {
            Serving::Unsettled(_) if Instant::now() < deadline => timing.pause(),
            seen => return seen,
        }
    }
}

/// The installed service of the profile in `state_dir`, for another command to look at. Its
/// questions block, so they are asked off the async runtime.
pub(crate) fn installed_service(state_dir: &Path) -> Result<Arc<dyn Host>> {
    Ok(Arc::new(Live {
        service: crate::background_service::managed(state_dir)?,
        state_dir: state_dir.to_path_buf(),
        handle: tokio::runtime::Handle::current(),
    }))
}

/// Wait, as long as an update waits for a start, until the service manager's process answers
/// the profile's authenticated control channel as a settled runtime.
pub(crate) fn await_service(host: &dyn Host, timing: Timing) -> Result<Identity> {
    match observe(host, timing) {
        Serving::Managed(identity) => Ok(identity),
        Serving::Stopped => bail!("the service is not running"),
        Serving::Unsettled(what) => bail!("{what} after {} seconds", timing.verify.as_secs()),
    }
}

/// Whether the service, as it would be started now, runs the installed program.
fn launches(host: &dyn Host, journal: &Journal) -> Result<(), String> {
    match host.service().launches(&journal.installed) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!(
            "the service is not set up to start {}",
            journal.installed.display()
        )),
        Err(error) => Err(format!("the service's setup cannot be read: {error:#}")),
    }
}

/// Whether the service manager's process serves `image` for this device: its version, from
/// the installed bytes, as the service is set up to start them.
fn healthy(host: &dyn Host, journal: &Journal, image: &Image) -> bool {
    matches!(
        serving(host),
        Serving::Managed(identity)
            if identity.version == image.version && identity.endpoint == journal.endpoint
    ) && has_digest(&journal.installed, &image.sha256)
        && launches(host, journal).is_ok()
}

/// Make sure the service serves `image` for this device: verify one that runs, start one
/// that is stopped, and wait out a start or an end that is under way. Nothing is started
/// unless `image` is what is installed and what the service is set up to start, and a
/// running service is never restarted.
fn settle(host: &dyn Host, journal: &Journal, image: &Image, timing: Timing) -> Result<(), String> {
    let installed = || {
        if has_digest(&journal.installed, &image.sha256) {
            Ok(())
        } else {
            Err(format!(
                "{} is not the version {} program",
                journal.installed.display(),
                image.version
            ))
        }
    };
    let mut deadline = Instant::now() + timing.verify;
    let mut starts = 0;
    loop {
        let problem = match serving(host) {
            Serving::Managed(identity) => {
                if identity.endpoint != journal.endpoint {
                    return Err("the service answered for another device identity".into());
                }
                if identity.version != image.version {
                    return Err(format!(
                        "the service runs version {}, not {}",
                        crate::visible(&identity.version),
                        image.version
                    ));
                }
                installed()?;
                return launches(host, journal);
            }
            Serving::Stopped if starts < 3 => {
                installed()?;
                launches(host, journal)?;
                starts += 1;
                match host.service().start() {
                    Ok(()) => deadline = Instant::now() + timing.verify,
                    Err(error) if starts == 3 => {
                        return Err(format!("the service did not start: {error:#}"));
                    }
                    Err(_) => {}
                }
                "the service is starting".to_owned()
            }
            Serving::Stopped => "the service is not running".to_owned(),
            Serving::Unsettled(what) => what,
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "{problem} after {} seconds",
                timing.verify.as_secs()
            ));
        }
        timing.pause();
    }
}

// ---------------------------------------------------------------- exchange

/// Everything an exchange relies on, checked under the staging lock while the runtime is
/// idle and held, against the identity that came with the hold:
///
/// - the service manager's process is that runtime, started from the installed program, for
///   this device, and (with `from`) of the expected version;
/// - the installed program and the staging directory are still a private boundary;
/// - the service would still start the installed program;
/// - with `from`, the installed bytes are still that program's;
/// - the saved previous program and the program to install are intact.
fn revalidate(
    host: &dyn Host,
    staging: &Staging,
    journal: &Journal,
    identity: &Identity,
    from: Option<&Image>,
    to: &Image,
) -> Result<(), String> {
    let installed = &journal.installed;
    match host.service().state() {
        Ok(Manager::Running(pid)) if pid == identity.pid => {}
        Ok(_) => {
            return Err("the runtime that is idle is not the installed service's process".into());
        }
        Err(error) => return Err(format!("the service manager did not answer: {error:#}")),
    }
    let same = identity.executable.as_deref().map(Path::new) == Some(installed.as_path())
        && identity.endpoint == journal.endpoint
        && from.is_none_or(|from| identity.version == from.version);
    if !same {
        return Err("the running service is not the one that was checked".into());
    }
    let trusted = || {
        check_program(installed)?;
        Staging::check(&staging.dir)?;
        host.service().trusts(installed)?;
        host.service().trusts(&staging.dir)
    };
    trusted().map_err(|error| format!("{error:#}"))?;
    launches(host, journal)?;
    if from.is_some_and(|from| !has_digest(installed, &from.sha256)) {
        return Err(format!(
            "{} was replaced while the update was waiting",
            installed.display()
        ));
    }
    if !has_digest(&staging.previous(), &journal.previous_sha256)
        || !has_digest(&to.file, &to.sha256)
    {
        return Err("the staged files are not the ones that were verified".into());
    }
    Ok(())
}

enum Exchange {
    /// Interrupted while waiting for the device to be idle. Nothing was changed.
    Cancelled,
    /// Nothing was changed, and the runtime serves on. Says why.
    Refused(String),
    /// The exchange was set in motion: the held runtime was told to retire, and the program
    /// was or was to be replaced. With a problem if a step of it failed. What is installed and
    /// what serves now must be read, not assumed.
    Begun(Option<String>),
}

/// Have the idle runtime that serves now leave, with `to` installed in its place.
///
/// The runtime is asked to close admission if idle, as often as needed. Once it has,
/// everything is checked against the identity it gave on that connection (`revalidate`),
/// `ready` runs, and then:
///
/// - where a running program can be replaced, `to` is renamed over the installed program
///   and then that connection is told to commit. Whenever that runtime ends, whatever is
///   started next is `to`;
/// - elsewhere, the connection is told to commit, the runtime ends cleanly and is not
///   started again by its service manager, and `to` is renamed into place once nothing runs.
///
/// Nothing is ever stopped from outside. If the runtime does not confirm, what it did is
/// read from what serves afterwards, once that has settled.
#[allow(clippy::too_many_arguments)]
fn exchange(
    host: &dyn Host,
    staging: &Staging,
    journal: &Journal,
    from: Option<&Image>,
    to: &Image,
    timing: Timing,
    interrupt: &dyn Interrupt,
    what: &str,
    ready: &mut dyn FnMut() -> Result<(), String>,
) -> Exchange {
    let service = host.service();
    let mut reported = None;
    let mut hold = loop {
        match host.hold() {
            Ok(Held::Yes(hold)) => break hold,
            Ok(Held::Busy { held: true, .. }) => {
                return Exchange::Refused(
                    "another update is already waiting on this device".into(),
                );
            }
            Ok(Held::Busy {
                connections,
                exposures,
                ..
            }) => {
                if reported != Some((connections, exposures)) {
                    reported = Some((connections, exposures));
                    say(format!(
                        "Waiting for {} on {what} to end. The service keeps running. Ctrl-C \
                         stops waiting.",
                        describe(connections, exposures)
                    ));
                }
                if interrupt.interrupted() {
                    return Exchange::Cancelled;
                }
                std::thread::sleep(timing.poll);
            }
            Err(error) => {
                return Exchange::Refused(format!("the runtime does not answer: {error:#}"));
            }
        }
    };
    if interrupt.interrupted() {
        return Exchange::Cancelled;
    }
    let (pid, lease) = (hold.identity().pid, hold.lease());
    if let Err(cause) = revalidate(host, staging, journal, hold.identity(), from, to) {
        return Exchange::Refused(cause);
    }
    if let Err(cause) = ready() {
        return Exchange::Refused(cause);
    }
    let installed = &journal.installed;
    let in_place = service.replaces_running();
    if in_place {
        if let Err(cause) = staging.place(&to.file, &to.sha256, installed) {
            // The hold is released by dropping it; the runtime serves on.
            return match from {
                Some(from) if has_digest(installed, &from.sha256) => Exchange::Refused(cause),
                _ => Exchange::Begun(Some(cause)),
            };
        }
        say(format!(
            "{} is idle and ends itself; version {} takes over.",
            service.label(),
            to.version
        ));
    } else {
        say(format!("{} is idle and ends itself.", service.label()));
    }
    let confirmed = hold.commit();
    if in_place && confirmed {
        return Exchange::Begun(None);
    }
    // What the runtime did is read from what the service manager and the runtime say, for
    // at least as long as the hold could still be taken up. A runtime that is held or
    // retiring, and a service that is starting or stopping, are waited out, not guessed at.
    let unconfirmed = "the running service did not confirm that it retired, and serves on";
    let limit = timing.verify.max(lease + timing.retry);
    match observe_for(host, timing, limit) {
        // The very runtime that was held answers again, with no hold on it: it never retired,
        // and that hold can no longer be taken up.
        Serving::Managed(identity) if identity.pid == pid && !confirmed => {
            if in_place {
                Exchange::Begun(Some(unconfirmed.into()))
            } else {
                Exchange::Refused(unconfirmed.into())
            }
        }
        _ if in_place => Exchange::Begun(None),
        // The program can be replaced only once the service manager says that nothing runs.
        Serving::Stopped => Exchange::Begun(staging.place(&to.file, &to.sha256, installed).err()),
        Serving::Managed(_) => Exchange::Begun(Some(
            "the service was started again before its program could be replaced".into(),
        )),
        Serving::Unsettled(state) => {
            Exchange::Begun(Some(format!("the retired runtime has not ended: {state}")))
        }
    }
}

// ------------------------------------------------------------- transaction

/// How an update ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Updated,
    /// The previous version serves as before, from its own bytes. It never stopped.
    Unchanged(String),
    /// The new program was installed, failed, and the previous one is back and running.
    RolledBack(String),
    /// The update failed and is unfinished: its journal and files are kept. Says what is where.
    Stranded(String),
}

enum Reverted {
    /// The previous version was serving all along.
    Untouched,
    /// The previous version was started again.
    Restored,
}

/// Bring back the previous program and its service, from whatever state the update is in,
/// without stopping anything:
///
/// - the previous version serves: only the installed bytes are made its own again;
/// - nothing runs: the previous bytes go back, and the service is started;
/// - another runtime serves: it leaves by itself once idle (`exchange`), then as above;
/// - a process serves that cannot be asked: it is left alone. Where the program can be
///   replaced under it, the previous bytes go back, so that the next start runs them.
///
/// `Err` says what is where; the journal and both programs are kept.
fn revert(
    host: &dyn Host,
    state_dir: &Path,
    staging: &Staging,
    journal: &Journal,
    timing: Timing,
    interrupt: &dyn Interrupt,
) -> Result<Reverted, String> {
    let previous = journal.previous(staging);
    let installed = &journal.installed;
    let kept = format!(
        "The update stays unfinished: the previous program is kept at {} and the journal at \
         {}. Run 'massrelay update' again to finish",
        previous.file.display(),
        state_dir.join(JOURNAL).display()
    );
    let put_back = || {
        if has_digest(installed, &previous.sha256) {
            return Ok(());
        }
        staging
            .place(&previous.file, &previous.sha256, installed)
            .and_then(|()| {
                if has_digest(installed, &previous.sha256) {
                    Ok(())
                } else {
                    Err("the restored program does not read back correctly".into())
                }
            })
            .map_err(|error| format!("Could not restore the previous program: {error}"))
    };
    let started = |()| {
        settle(host, journal, &previous, timing).map_err(|error| {
            format!(
                "Version {} is back at {}, but its service is not up: {error}. {kept}, or run \
                 'massrelay start' and check 'massrelay logs'",
                previous.version,
                installed.display()
            )
        })
    };
    match observe(host, timing) {
        Serving::Managed(identity)
            if identity.version == previous.version && identity.endpoint == journal.endpoint =>
        {
            put_back().map_err(|error| format!("{error}. {kept}"))?;
            launches(host, journal).map_err(|error| format!("{error}. {kept}"))?;
            Ok(Reverted::Untouched)
        }
        Serving::Stopped => {
            put_back()
                .map_err(|error| format!("{error}. {kept}"))
                .and_then(started)?;
            Ok(Reverted::Restored)
        }
        Serving::Managed(_) => {
            let what = format!("the new version ({})", journal.candidate_version);
            let exchanged = exchange(
                host,
                staging,
                journal,
                None,
                &previous,
                timing,
                interrupt,
                &what,
                &mut || Ok(()),
            );
            match exchanged {
                Exchange::Begun(None) => started(()).map(|()| Reverted::Restored),
                Exchange::Cancelled => Err(format!(
                    "The new version still has live sessions and was left running. {kept}"
                )),
                Exchange::Refused(cause) | Exchange::Begun(Some(cause)) => {
                    Err(format!("{cause}. {kept}"))
                }
            }
        }
        Serving::Unsettled(state) => {
            let mut note = "";
            if host.service().replaces_running() && put_back().is_ok() {
                // Whatever starts next is the previous version. If the process that cannot
                // be asked goes away by itself meanwhile, that is all it takes.
                if settle(host, journal, &previous, timing).is_ok() {
                    return Ok(Reverted::Restored);
                }
                note = " The previous program is back on disk and runs when the service \
                        next starts.";
            }
            Err(format!("{state}. It was not stopped.{note} {kept}"))
        }
    }
}

/// Exchange the idle service's program for the candidate and verify it, and bring the
/// previous one back on failure. The journal and both programs outlive every failure that
/// leaves the intended program unverified.
pub(crate) fn transact(
    host: &dyn Host,
    state_dir: &Path,
    staging: Staging,
    mut journal: Journal,
    timing: Timing,
    interrupt: &dyn Interrupt,
) -> Outcome {
    let (previous, candidate) = (journal.previous(&staging), journal.candidate(&staging));
    let begun = {
        let armed = journal.clone();
        let mut ready = || {
            journal
                .record(state_dir, Phase::Switching)
                .map_err(|error| format!("{error:#}"))
        };
        let what = format!("this device (version {})", previous.version);
        exchange(
            host,
            &staging,
            &armed,
            Some(&previous),
            &candidate,
            timing,
            interrupt,
            &what,
            &mut ready,
        )
    };
    let unclosed = |error: String| Outcome::Stranded(error);
    let problem = match begun {
        Exchange::Cancelled => {
            return match close(state_dir, staging) {
                Ok(()) => Outcome::Unchanged("the update was cancelled".into()),
                Err(error) => unclosed(format!("the update was cancelled, but {error}")),
            };
        }
        // Nothing was retired or replaced: the service runs as it did.
        Exchange::Refused(cause) => {
            return match close(state_dir, staging) {
                Ok(()) => Outcome::Unchanged(cause),
                Err(error) => unclosed(format!("{cause}. Nothing was replaced, but {error}")),
            };
        }
        Exchange::Begun(problem) => problem,
    };
    let settled = match problem {
        Some(problem) => Err(problem),
        None => settle(host, &journal, &candidate, timing),
    };
    let cause = match settled {
        Ok(()) => {
            return match complete(host, state_dir, staging, &journal, &candidate) {
                Ok(()) => Outcome::Updated,
                Err(error) => unclosed(format!(
                    "version {} was installed and started, but the update could not be \
                     completed: {error}",
                    candidate.version
                )),
            };
        }
        Err(cause) => cause,
    };
    say(format!(
        "{cause}. Bringing back version {}.",
        previous.version
    ));
    let reverted = match revert(host, state_dir, &staging, &journal, timing, interrupt) {
        Ok(reverted) => reverted,
        Err(stranded) => return Outcome::Stranded(format!("{cause}. {stranded}")),
    };
    match complete(host, state_dir, staging, &journal, &previous) {
        Ok(()) => match reverted {
            Reverted::Untouched => Outcome::Unchanged(cause),
            Reverted::Restored => Outcome::RolledBack(cause),
        },
        Err(error) => Outcome::Stranded(format!(
            "{cause}. Version {} is back, but the update could not be completed: {error}",
            previous.version
        )),
    }
}

/// Finish or undo the update an earlier run left in its journal, read under its staging
/// lock. What is done follows from what is installed and what serves now:
///
/// - the new bytes are installed and serve healthily: the update had finished;
/// - either program is installed otherwise: bring the previous one back (`revert`);
/// - other bytes are installed: someone replaced the program since. Touch nothing.
///
/// `None` if there is nothing to recover. On error the journal and the staged files are kept.
fn recover(
    host: &dyn Host,
    state_dir: &Path,
    timing: Timing,
    interrupt: &dyn Interrupt,
) -> Result<Option<String>> {
    let Some((staging, journal)) = Journal::locked(state_dir, host.service())? else {
        return Ok(None);
    };
    let (previous, candidate) = (journal.previous(&staging), journal.candidate(&staging));
    let unfinished = "an earlier update was interrupted and is still unfinished";
    let closed =
        |closed: Result<(), String>| closed.map_err(|error| anyhow!("{unfinished}: {error}"));
    if journal.phase == Phase::Armed {
        closed(close(state_dir, staging))?;
        return Ok(Some(
            "An earlier update was prepared but never started; it was discarded.".into(),
        ));
    }
    let installed = &journal.installed;
    // The run that was interrupted may have left a runtime that is still ending, or a service
    // that is still starting. Nothing is decided until that has settled.
    let _ = observe(host, timing);
    if has_digest(installed, &candidate.sha256) && healthy(host, &journal, &candidate) {
        closed(complete(host, state_dir, staging, &journal, &candidate))?;
        return Ok(Some(format!(
            "An earlier update to version {} had finished; it is running.",
            candidate.version
        )));
    }
    if has_digest(installed, &candidate.sha256) || has_digest(installed, &previous.sha256) {
        let reverted = revert(host, state_dir, &staging, &journal, timing, interrupt)
            .map_err(|error| anyhow!("{unfinished}. {error}"))?;
        closed(complete(host, state_dir, staging, &journal, &previous))?;
        return Ok(Some(match reverted {
            Reverted::Untouched => format!(
                "An earlier update was interrupted; version {} serves as before.",
                previous.version
            ),
            Reverted::Restored => format!(
                "An earlier update was interrupted; version {} was restored and is running.",
                previous.version
            ),
        }));
    }
    // Whatever was installed since supersedes the update, once it is seen to serve.
    let serves = matches!(
        serving(host),
        Serving::Managed(identity) if identity.endpoint == journal.endpoint
    ) && launches(host, &journal).is_ok();
    ensure!(
        serves,
        "{unfinished}, and {} has since been replaced by another program. Nothing was touched. \
         Start the service with 'massrelay start' and run 'massrelay update' again",
        installed.display()
    );
    closed(close(state_dir, staging))?;
    Ok(Some(
        "An earlier update was interrupted and the program was replaced since; its leftovers \
         were removed."
            .into(),
    ))
}

// ------------------------------------------------------------- the command

/// Signals that would otherwise end the process. Once listening they no longer do, so an
/// exchange cannot be cut off by one; `interrupted` reports them where stopping is safe.
struct Interrupts(Arc<AtomicBool>);

impl Interrupts {
    fn listen() -> io::Result<Arc<Self>> {
        let seen = Arc::new(AtomicBool::new(false));
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            for kind in [
                SignalKind::interrupt(),
                SignalKind::terminate(),
                SignalKind::hangup(),
            ] {
                let (mut signal, seen) = (signal(kind)?, seen.clone());
                tokio::spawn(async move {
                    while signal.recv().await.is_some() {
                        seen.store(true, Ordering::SeqCst);
                    }
                });
            }
        }
        #[cfg(windows)]
        {
            let (mut ctrl_c, flag) = (tokio::signal::windows::ctrl_c()?, seen.clone());
            tokio::spawn(async move {
                while ctrl_c.recv().await.is_some() {
                    flag.store(true, Ordering::SeqCst);
                }
            });
            let (mut ctrl_break, flag) = (tokio::signal::windows::ctrl_break()?, seen.clone());
            tokio::spawn(async move {
                while ctrl_break.recv().await.is_some() {
                    flag.store(true, Ordering::SeqCst);
                }
            });
        }
        Ok(Arc::new(Self(seen)))
    }
}

impl Interrupt for Interrupts {
    fn interrupted(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

fn record(service: &dyn Service, outcome: &'static str, reason: Option<&'static str>) {
    use crate::connection_log::{Audit, ConnectionLog};
    if let Ok(log) = ConnectionLog::open(Some(&service.events())) {
        log.audit(
            "service_control",
            Audit {
                operation: "update",
                outcome,
                reason,
                ..Audit::default()
            },
            None,
        );
    }
}

fn describe(connections: usize, exposures: usize) -> String {
    let count =
        |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    let mut parts = vec![];
    if connections > 0 {
        parts.push(count(connections, "connection", "connections"));
    }
    if exposures > 0 {
        parts.push(count(
            exposures,
            "temporary exposure",
            "temporary exposures",
        ));
    }
    parts.join(" and ")
}

/// Print how the update ended, record it, and choose the exit code.
fn conclude(service: &dyn Service, journal: &Journal, outcome: Outcome) -> i32 {
    let (previous, candidate) = (&journal.previous_version, &journal.candidate_version);
    match outcome {
        Outcome::Updated => {
            record(service, "allowed", None);
            say(format!(
                "Updated {} from version {previous} to {candidate}.",
                service.label()
            ));
            0
        }
        Outcome::Unchanged(cause) => {
            record(service, "failed", Some("not_replaced"));
            say(format!(
                "massrelay: {cause}. Version {previous} is still installed and serving."
            ));
            1
        }
        Outcome::RolledBack(cause) => {
            record(service, "failed", Some("rolled_back"));
            say(format!(
                "massrelay: the update to version {candidate} failed: {cause}. Version \
                 {previous} was restored and is running."
            ));
            1
        }
        Outcome::Stranded(what) => {
            record(service, "failed", Some("recovery_needed"));
            say(format!(
                "massrelay: the update to version {candidate} failed: {what}."
            ));
            1
        }
    }
}

fn live(state_dir: &Path) -> Result<Arc<Live<crate::background_service::Managed>>> {
    let service = crate::background_service::managed(state_dir)
        .context("'massrelay update' updates the installed background service of this profile")?;
    Ok(Arc::new(Live {
        service,
        state_dir: state_dir.to_path_buf(),
        handle: tokio::runtime::Handle::current(),
    }))
}

/// Run the journaled part of an update, or the recovery of one, off the async runtime.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .context("the update task failed")
}

/// The `update` command.
pub async fn run(state_dir: &Path) -> Result<i32> {
    #[cfg(windows)]
    crate::background_service::wait_for_activation()?;
    ensure!(
        cli::profile_exists(state_dir),
        "no device profile in {}; there is no service to update",
        state_dir.display()
    );
    let state_dir = state_dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let profile = state_dir.join(cli::DIR_NAME);
    let host = live(&state_dir)?;
    let timing = Timing::default();

    // A command may run inside a session of the service itself: a MassRelay shell marks its
    // processes, and the runtime knows the ends of an SSH login that it carries.
    let shell = std::env::var(crate::private::HOST_ENV)
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    let login = runtime::local_ssh_tunnel(&profile)
        .await
        .context("check whether this SSH login is carried by the service being updated")?
        .map(|identity| identity.pid);
    if (shell.is_some() || login.is_some())
        && matches!(host.service.state()?, Manager::Running(pid)
            if [shell, login].contains(&Some(pid)))
    {
        // Recovery can wait for idle, too. Leave this session before touching its journal.
        let program = std::env::current_exe().context("find the running MassRelay executable")?;
        let queued = blocking(move || {
            #[cfg(unix)]
            {
                let parent = program
                    .parent()
                    .context("the MassRelay executable has no parent directory")?;
                check_ancestry(parent)?;
                check_program(&program)?;
                ensure!(
                    host.service.launches(&program)?,
                    "run the copy of MassRelay configured for this device's background service"
                );
            }
            host.service.queue_update(&program)
        })
        .await??;
        #[cfg(windows)]
        let queued = format!(
            "Update queued. Exit this shell so sessions can drain.\nUpdate log     {queued}"
        );
        say(queued);
        return Ok(0);
    }

    // An unfinished update comes first. Recovery may replace the installed program, which on
    // Windows this process maps, so there it runs in the helper.
    #[cfg(windows)]
    if let Some((staging, _)) = Journal::locked(&state_dir, host.service())? {
        return hand_over(&state_dir, staging, host.service(), true);
    }
    #[cfg(not(windows))]
    {
        let interrupts = Interrupts::listen().context("listen for interruption")?;
        let (host, dir) = (host.clone(), state_dir.clone());
        let recovered =
            blocking(move || recover(host.as_ref(), &dir, timing, interrupts.as_ref())).await??;
        if let Some(recovered) = recovered {
            say(recovered);
        }
    }

    // 1. The running service is the installed one, from the program its definition names.
    ensure!(
        profile.join(CONTROL.marker).try_exists()?,
        "this profile's service is not running. Run 'massrelay start', then 'massrelay update'"
    );
    runtime::command(&profile, ControlRequest::Status)
        .await
        .context("this profile's runtime does not answer; nothing was changed")?;
    let identity = identify(&profile).await.map_err(|_| {
        anyhow!(
            "the running service predates 'massrelay update' and cannot hand over while idle. \
             Run 'massrelay restart' once (this ends its live sessions), then 'massrelay update'"
        )
    })?;
    let service = host.service();
    service.controllable()?;
    ensure!(
        service.state()? == Manager::Running(identity.pid),
        "the runtime answering for this profile (process {}) is not its installed service {}. \
         'massrelay update' only updates a service set up by 'massrelay install'; stop the \
         foreground 'massrelay run' and start the service first",
        identity.pid,
        service.label()
    );
    let text = identity
        .executable
        .as_deref()
        .context("the running service could not name its program file")?;
    let restart = "Run 'massrelay restart' (this ends live sessions), then 'massrelay update'";
    ensure!(
        !text.ends_with(" (deleted)"),
        "the program file the service was started from has since been replaced. {restart}"
    );
    let installed = PathBuf::from(text);
    ensure!(
        ![shell, login].contains(&Some(identity.pid)),
        "this command is running inside a MassRelay shell or SSH session on this device. The \
         update waits for every session to end, including that one, and ending it ends this \
         command. Run 'massrelay update' from a local terminal or another kind of remote session"
    );

    // The program and the whole path to it are checked before the program is run for its
    // version and before anything is written or run beside it. Everything below happens
    // under the staging lock, and is checked again, under the same lock, at the moment the
    // service is idle and held.
    let staging = Staging::open(&installed, &state_dir, &|path| service.trusts(path))
        .context("the service's program cannot be updated in place")?;
    ensure!(
        Journal::load(&state_dir)?.is_none(),
        "another 'massrelay update' left this profile's update unfinished; run it again"
    );
    // Even if a prior unlink succeeded but its sync failed, the images can
    // now be overwritten only after the journal's absence is durable.
    sync_dir(&state_dir).context("verify that no unfinished update remains")?;
    let prepared = async {
        ensure!(
            service.launches(&installed)?,
            "the service {} is not set up to start {} for this profile. Run 'massrelay install' \
             again, then 'massrelay update'",
            service.label(),
            installed.display()
        );
        let on_disk = program_version(&installed)?;
        ensure!(
            on_disk == identity.version,
            "the service runs version {}, but {} is version {}. {restart}",
            crate::visible(&identity.version),
            installed.display(),
            crate::visible(&on_disk)
        );
        let current = Version::parse(&identity.version).with_context(|| {
            format!(
                "the running version {:?} is not a release; update it the way it was installed",
                crate::visible(&identity.version)
            )
        })?;

        // 2. The latest stable release, only if newer.
        let source = Source::github();
        let client = source.client()?;
        let release = client.latest().await?;
        if release.version <= current {
            say(format!(
                "MassRelay {current} is up to date (latest release: {}).",
                release.version
            ));
            return Ok(None);
        }
        say(format!(
            "Downloading MassRelay {} (installed: {current}).",
            release.version
        ));

        // 3 and 4. Stage and check, with the service untouched.
        staging.sweep();
        let candidate_sha256 = stage(&client, &release, &staging, &installed).await?;
        let candidate = staging.candidate();
        service.trusts(&candidate)?;
        say("Checking the downloaded program.");
        let (dir, checked, endpoint, digest) = (
            state_dir.clone(),
            release.clone(),
            identity.endpoint.clone(),
            candidate_sha256.clone(),
        );
        blocking(move || {
            let limit = SELF_CHECK_TIMEOUT;
            preflight(&candidate, &digest, &dir, &checked, &endpoint, limit)
        })
        .await??;
        let mut journal = Journal {
            format: JOURNAL_FORMAT.into(),
            phase: Phase::Armed,
            installed: installed.clone(),
            previous_version: identity.version.clone(),
            previous_sha256: keep_previous(&staging, &installed)?,
            candidate_version: release.version.to_string(),
            candidate_sha256,
            endpoint: identity.endpoint.clone(),
        };
        journal.record(&state_dir, Phase::Armed)?;
        Ok::<_, anyhow::Error>(Some(journal))
    }
    .await;
    let journal = match prepared {
        Ok(Some(journal)) => journal,
        Ok(None) => {
            staging.clear();
            return Ok(0);
        }
        // Neither the service nor the installed program was touched.
        Err(error) => {
            let closed = close(&state_dir, staging);
            let error = error.context("nothing was changed");
            return Err(match closed {
                Ok(()) => error,
                Err(unclosed) => error.context(unclosed),
            });
        }
    };

    #[cfg(windows)]
    {
        let _ = (timing, &journal);
        hand_over(&state_dir, staging, service, false)
    }
    #[cfg(not(windows))]
    {
        // Until here an interrupt simply ends the command; what it leaves staged is swept by
        // the next run. From here on it is honoured only while waiting.
        let interrupts = Interrupts::listen().context("listen for interruption")?;
        let (applying, dir, record) = (host.clone(), state_dir.clone(), journal.clone());
        let outcome = blocking(move || {
            let host: &dyn Host = applying.as_ref();
            transact(host, &dir, staging, record, timing, interrupts.as_ref())
        })
        .await?;
        Ok(conclude(host.service(), &journal, outcome))
    }
}

/// Continue in a copy of this program started from the staging directory, and leave, so that
/// nothing maps the installed program when it is replaced. With `recovering`, the helper
/// finishes or undoes an interrupted update instead of applying a prepared one.
#[cfg(windows)]
fn hand_over(
    state_dir: &Path,
    staging: Staging,
    service: &dyn Service,
    recovering: bool,
) -> Result<i32> {
    let helper = staging.file("helper");
    let started = (|| {
        let _ = fs::remove_file(&helper);
        fs::copy(std::env::current_exe()?, &helper).context("copy the update helper")?;
        // The helper runs with this account's rights: nobody else may be able to change it.
        service.trusts(&helper)?;
        let mut command = Command::new(&helper);
        command
            .arg("--state-dir")
            .arg(state_dir)
            .arg("update-apply");
        if recovering {
            command.arg("--recover");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .spawn()
            .context("start the update helper")?;
        // The pipe closes when this process exits, which is the helper's signal to begin.
        std::mem::forget(child.stdin.take());
        Ok::<_, anyhow::Error>(child.id())
    })();
    match started {
        Ok(pid) if recovering => {
            say(format!(
                "An earlier update was interrupted. A helper (process {pid}) finishes or undoes \
                 it and reports here. Run 'massrelay update' again afterwards."
            ));
            drop(staging);
            Ok(0)
        }
        Ok(pid) => {
            say(format!(
                "The update continues in a helper (process {pid}) that reports here when it is \
                 done. It waits until this device is idle; Ctrl-C cancels it. Check the result \
                 with 'massrelay status'."
            ));
            // Dropping the staging lock lets the helper take it.
            drop(staging);
            Ok(0)
        }
        // An interrupted update keeps its journal and files.
        Err(error) if recovering => Err(error),
        Err(error) => {
            let closed = close(state_dir, staging);
            let error = error.context("nothing was changed");
            Err(match closed {
                Ok(()) => error,
                Err(unclosed) => error.context(unclosed),
            })
        }
    }
}

/// The `update-apply` command: exchange and verify from a prepared journal and staging
/// directory, or with `recovering` finish or undo an interrupted update. Only
/// `massrelay update` starts it, on Windows, from the staging directory.
pub async fn apply_prepared(state_dir: &Path, recovering: bool) -> Result<i32> {
    // Wait for the process that started this one to exit and release the installed file.
    blocking(|| {
        let _ = io::stdin().read_to_end(&mut Vec::new());
    })
    .await?;
    let state_dir = state_dir
        .canonicalize()
        .context("resolve the device state directory")?;
    let host = live(&state_dir)?;
    let timing = Timing::default();
    let interrupts = Interrupts::listen().context("listen for interruption")?;
    if recovering {
        let (host, dir) = (host.clone(), state_dir.clone());
        let recovered =
            blocking(move || recover(host.as_ref(), &dir, timing, interrupts.as_ref())).await??;
        say(recovered.unwrap_or_else(|| "There was no interrupted update to finish.".into()));
        return Ok(0);
    }
    // The preparing process releases the staging lock as it exits. The journal is read under
    // the lock, and only that reading is applied.
    let deadline = Instant::now() + Duration::from_secs(20);
    let (staging, journal) = loop {
        match Journal::locked(&state_dir, host.service()) {
            Ok(Some(locked)) => break locked,
            Ok(None) => bail!("no update was prepared for this profile"),
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    };
    ensure!(
        journal.phase == Phase::Armed,
        "the prepared update was already started; run 'massrelay update'"
    );
    let (applying, dir, record) = (host.clone(), state_dir.clone(), journal.clone());
    let outcome = blocking(move || {
        let host: &dyn Host = applying.as_ref();
        transact(host, &dir, staging, record, timing, interrupts.as_ref())
    })
    .await?;
    Ok(conclude(host.service(), &journal, outcome))
}

#[cfg(test)]
pub(crate) mod tests;
