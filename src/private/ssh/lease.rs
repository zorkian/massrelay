//! The destination's authorizations in the system SSH server's dedicated key file,
//! `<profile>/ssh-authorized-keys`.
//!
//! Each tunnel adds one line for the connecting device's key, usable only from `127.0.0.1`
//! and only until it expires, and removes exactly that line when the tunnel ends or its
//! lifetime passes, whichever comes first. SSH authenticates as a connection opens, so an
//! established one does not need the line again.
//!
//! The installer creates the file; this module never does, so removing it opts out. A new
//! authorization is refused while the file holds anything but these lines, blank lines and
//! comments: a person's own keys belong elsewhere. The file is replaced atomically, by a
//! writer holding the exclusive lock on `ssh-authorized-keys.lock`. The installer takes
//! the same lock while it changes this file or the server's description, and for the whole of
//! a removal. Nothing here blocks a runtime's thread on it: an authorization waits for it as
//! long as its request lasts, and a withdrawal that cannot have it at once is retried until
//! it is done (`Withdrawals`).
//!
//! Each line is tagged with the profile that wrote it. A runtime removes its profile's
//! lines when it starts, after a crash left them behind.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use chrono::{Local, TimeDelta, TimeZone as _};
use fs2::FileExt;
use tempfile::{NamedTempFile, TempPath};
use tokio::runtime::Handle;
use tokio::task::AbortHandle;

use super::super::codec::{hex, random};
use super::super::pairing::{Refusal, SessionHandle};
use super::keys;

/// The dedicated key file in the private profile.
pub(super) const KEY_FILE: &str = "ssh-authorized-keys";
const LOCK_FILE: &str = "ssh-authorized-keys.lock";
const TAG: &str = "massrelay-lease:";
const OPTIONS: &str = r#"from="127.0.0.1",expiry-time=""#;
/// How long a reader may keep the file from being replaced, and a withdrawal may wait before
/// that is reported.
pub(super) const WAIT: Duration = Duration::from_secs(2);
pub(super) const RETRY: Duration = Duration::from_millis(10);
/// The longest pause between attempts to withdraw a key.
const RETRY_LIMIT: Duration = Duration::from_millis(500);

/// The exclusive lock on the profile's SSH setup, held until dropped. Never hold it across
/// a suspension: it excludes the installer and every other tunnel.
pub(super) struct Lock {
    _file: File,
}

impl Lock {
    /// Wait while another holds the lock, with no deadline of its own: the caller drops the
    /// wait when what it is for ends. Any other failure is returned at once.
    pub(super) async fn acquire(profile: &Path) -> Result<Self> {
        loop {
            match Self::try_acquire(profile) {
                Err(error) if contended(&error) => tokio::time::sleep(RETRY).await,
                lock => return lock,
            }
        }
    }

    fn try_acquire(profile: &Path) -> Result<Self> {
        let file = open_lock(profile)?;
        file.try_lock_exclusive()
            .context("the SSH setup is locked")?;
        Ok(Self { _file: file })
    }
}

/// Whether `error` says only that another holds the lock.
fn contended(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.raw_os_error() == fs2::lock_contended_error().raw_os_error())
}

/// Removes lines from a profile's key file. It is asked where a tunnel ends, which must not
/// wait: it tries at once, and while the setup lock or the file cannot be had, one task
/// keeps trying for as long as a line is there, until `close` or the last owner is gone. A
/// line left behind still expires, and the next start withdraws it.
pub(super) struct Withdrawals {
    profile: PathBuf,
    pending: Mutex<Pending>,
}

#[derive(Default)]
struct Pending {
    /// The tags of the lines still to be removed.
    tags: HashSet<String>,
    retry: Option<AbortHandle>,
    closed: bool,
}

impl Withdrawals {
    pub(super) fn new(profile: &Path) -> Arc<Self> {
        Arc::new(Self {
            profile: profile.to_owned(),
            pending: Mutex::default(),
        })
    }

    fn withdraw(self: &Arc<Self>, tags: impl IntoIterator<Item = String>) {
        let mut pending = self.pending();
        pending.tags.extend(tags);
        let Err(error) = self.attempt(&mut pending.tags) else {
            return;
        };
        if pending.retry.is_some() {
            return;
        }
        match Handle::try_current() {
            Ok(runtime) if !pending.closed => {
                let task = runtime.spawn(retry(Arc::downgrade(self)));
                pending.retry = Some(task.abort_handle());
            }
            _ => super::warn("an SSH tunnel's key was left to expire", &error),
        }
    }

    /// Give what is pending at most `grace`, then stop trying. Whether nothing is left.
    pub(super) async fn close(&self, grace: Duration) -> bool {
        let deadline = Instant::now() + grace;
        loop {
            {
                let mut pending = self.pending();
                let done = self.attempt(&mut pending.tags).is_ok();
                if done || Instant::now() >= deadline {
                    pending.closed = true;
                    if let Some(task) = pending.retry.take() {
                        task.abort();
                    }
                    return done;
                }
            }
            tokio::time::sleep(RETRY).await;
        }
    }

    fn pending(&self) -> MutexGuard<'_, Pending> {
        // A removal repeats safely, whatever an earlier one did before it panicked.
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// One attempt to remove the lines tagged `tags`, which are then forgotten. It never
    /// waits for the lock. Every other byte stays, and a file that is gone stays gone.
    fn attempt(&self, tags: &mut HashSet<String>) -> Result<()> {
        let file = self.profile.join(KEY_FILE);
        if !tags.is_empty() && read(&file)?.is_some() {
            let _lock = Lock::try_acquire(&self.profile)?;
            if let Some(current) = read(&file)? {
                let kept: String = current
                    .content
                    .split_inclusive('\n')
                    .filter(|line| !line_tag(line.trim()).is_some_and(|tag| tags.contains(tag)))
                    .collect();
                if kept != current.content {
                    let staged = stage(&file, &current, kept.as_bytes())?;
                    publish(staged, &file, &current).context("replace the SSH key file")?;
                }
            }
        }
        tags.clear();
        Ok(())
    }
}

async fn retry(withdrawals: Weak<Withdrawals>) {
    let mut pause = RETRY;
    // Tunnels hold the lock for a moment each; only a longer wait is worth reporting.
    let mut report = Some(Instant::now() + WAIT);
    loop {
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(RETRY_LIMIT);
        let Some(withdrawals) = withdrawals.upgrade() else {
            return;
        };
        let mut pending = withdrawals.pending();
        let Err(error) = withdrawals.attempt(&mut pending.tags) else {
            pending.retry = None;
            return;
        };
        if report.take_if(|due| Instant::now() >= *due).is_some() {
            super::warn("an SSH tunnel's key is not yet withdrawn", &error);
        }
    }
}

/// One authorization. Dropping it withdraws its line.
pub(super) struct Lease {
    withdrawals: Arc<Withdrawals>,
    tag: String,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.withdrawals.withdraw([std::mem::take(&mut self.tag)]);
    }
}

pub(super) enum Grant {
    Made(Lease),
    /// The file could not be replaced just now, as while a reader holds it on Windows.
    Blocked(io::Error),
}

/// Authorize `key` in the key file of `withdrawals`' profile, whose lock the caller holds,
/// for the profile `owner`, for as long as `session` lasts and at most `lifetime`. The line
/// is published only while the session is still authorized.
pub(super) fn grant(
    _lock: &Lock,
    session: &SessionHandle,
    withdrawals: &Arc<Withdrawals>,
    owner: &str,
    key: &[u8; 32],
    lifetime: Duration,
) -> Result<Result<Grant>, Refusal> {
    let file = withdrawals.profile.join(KEY_FILE);
    let tag = format!("{TAG}{owner}:{}", hex(&random::<16>()));
    let staged = (|| {
        let current = read(&file)?.context("the dedicated SSH key file is missing")?;
        check_trusted(&file)?;
        let mut content = current.content.clone();
        ensure!(
            content.lines().all(|line| {
                let line = line.trim();
                line.is_empty() || line.starts_with('#') || line_tag(line).is_some()
            }),
            "{} holds lines MassRelay did not write; it was not changed. Keep other keys \
             in another file",
            file.display()
        );
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(&render(key, &expiry(lifetime)?, &tag));
        Ok((stage(&file, &current, content.as_bytes())?, current))
    })();
    let (staged, current) = match staged {
        Ok(staged) => staged,
        Err(error) => return Ok(Err(error)),
    };
    // The authorization itself: nothing is published after a cutoff returns.
    Ok(Ok(
        match session.start_now(|| publish(staged, &file, &current))? {
            Ok(()) => Grant::Made(Lease {
                withdrawals: withdrawals.clone(),
                tag,
            }),
            Err(error) => Grant::Blocked(error),
        },
    ))
}

/// Withdraw every line the profile `owner` wrote. Only before any tunnel: it picks the lines
/// that are there now, so that one granted while the removal still waits is not among them.
pub(super) fn purge(withdrawals: &Arc<Withdrawals>, owner: &str) -> Result<()> {
    let Some(current) = read(&withdrawals.profile.join(KEY_FILE))? else {
        return Ok(());
    };
    let prefix = format!("{TAG}{owner}:");
    let tags = current
        .content
        .lines()
        .filter_map(|line| line_tag(line.trim()))
        .filter(|tag| tag.starts_with(&prefix))
        .map(str::to_owned);
    withdrawals.withdraw(tags);
    Ok(())
}

fn render(key: &[u8; 32], expiry: &str, tag: &str) -> String {
    format!("{OPTIONS}{expiry}\" {} {tag}\n", keys::public_line(key))
}

/// The tag of a line in exactly the form this module writes.
fn line_tag(line: &str) -> Option<&str> {
    let mut fields = line.split(' ');
    let expiry = fields.next()?.strip_prefix(OPTIONS)?.strip_suffix('"')?;
    let kind = fields.next()?;
    keys::parse_blob(fields.next()?).ok()?;
    let tag = fields.next()?;
    let (owner, id) = tag.strip_prefix(TAG)?.split_once(':')?;
    let hex = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit());
    (expiry.len() == 14
        && expiry.bytes().all(|b| b.is_ascii_digit())
        && kind == "ssh-ed25519"
        && hex(owner)
        && hex(id)
        && fields.next().is_none())
    .then_some(tag)
}

/// `lifetime` from now, as `expiry-time` reads it without a zone: in the system time zone.
/// The unambiguous `Z` suffix needs OpenSSH 9.1, which supported systems predate.
fn expiry(lifetime: Duration) -> Result<String> {
    // Whole seconds, rounded up.
    let lifetime = TimeDelta::from_std(lifetime + Duration::from_secs(1))?;
    let mut at = (Local::now() + lifetime).naive_local();
    // A repeated hour can be read as its earlier instance, which would already be past.
    if Local.from_local_datetime(&at).single().is_none() {
        at += TimeDelta::hours(1);
    }
    Ok(at.format("%Y%m%d%H%M%S").to_string())
}

/// The file is this account's alone, and nobody else can replace it. The installer's
/// description and the server's own checks cover the directories above the profile.
#[cfg(unix)]
fn check_trusted(file: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let metadata = fs::symlink_metadata(file)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == uid
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1,
        "{} must be a regular file private to this account",
        file.display()
    );
    let parent = file.parent().context("the SSH key file has no directory")?;
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o022 == 0,
        "{} can be changed by other accounts",
        parent.display()
    );
    Ok(())
}

#[cfg(windows)]
fn check_trusted(file: &Path) -> Result<()> {
    crate::windows_service::ssh_private_dir(
        file.parent().context("the SSH key file has no directory")?,
    )?;
    crate::windows_service::ssh_files::check_managed_file(file)
}

/// The lock file, which stays while the key file is replaced.
fn open_lock(profile: &Path) -> Result<File> {
    let path = profile.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
    }
    // Windows gives a new file its access list as it is created.
    #[cfg(windows)]
    if !path.try_exists()?
        && let Err(error) =
            crate::windows_service::private_marker(profile)?.persist_noclobber(&path)
        && error.error.kind() != io::ErrorKind::AlreadyExists
    {
        return Err(error.error).context("create the SSH setup lock");
    }
    options
        .open(&path)
        .with_context(|| format!("open {}", path.display()))
}

struct Current {
    content: String,
    #[cfg(unix)]
    metadata: fs::Metadata,
}

fn read(file: &Path) -> Result<Option<Current>> {
    let metadata = match fs::symlink_metadata(file) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect the SSH key file"),
    };
    ensure!(
        metadata.is_file(),
        "{} is not a regular SSH key file",
        file.display()
    );
    let content = fs::read_to_string(file).context("read the SSH key file")?;
    Ok(Some(Current {
        content,
        #[cfg(unix)]
        metadata,
    }))
}

/// A new file beside `file` that will keep its permissions.
fn stage(file: &Path, current: &Current, content: &[u8]) -> Result<TempPath> {
    let parent = file.parent().context("the SSH key file has no directory")?;
    #[cfg(unix)]
    let mut staged = {
        use std::os::unix::fs::{MetadataExt, fchown};
        let staged = NamedTempFile::new_in(parent)?;
        if staged.as_file().metadata()?.gid() != current.metadata.gid() {
            fchown(staged.as_file(), None, Some(current.metadata.gid()))
                .context("keep the SSH key file's group")?;
        }
        staged
            .as_file()
            .set_permissions(current.metadata.permissions())?;
        staged
    };
    // `ReplaceFileW` gives it the replaced file's access list; until then it is private.
    #[cfg(windows)]
    let mut staged: NamedTempFile = {
        let _ = current;
        crate::windows_service::private_marker(parent)?
    };
    staged.write_all(content)?;
    staged.as_file().sync_all()?;
    Ok(staged.into_temp_path())
}

/// Replace `file` with `staged`, unless it was removed or replaced since it was read.
#[cfg(unix)]
fn publish(staged: TempPath, file: &Path, current: &Current) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let found = fs::symlink_metadata(file)?;
    if (found.dev(), found.ino()) != (current.metadata.dev(), current.metadata.ino()) {
        return Err(io::Error::other("the SSH key file changed meanwhile"));
    }
    staged.persist(file).map_err(|error| error.error)
}

#[cfg(windows)]
fn publish(staged: TempPath, file: &Path, _: &Current) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    let wide = |path: &Path| -> Vec<u16> { path.as_os_str().encode_wide().chain([0]).collect() };
    let (target, source) = (wide(file), wide(&staged));
    // SAFETY: both paths are NUL-terminated; the optional arguments are null. It fails if
    // the target is gone, and keeps the target's access list.
    let replaced = unsafe {
        ReplaceFileW(
            target.as_ptr(),
            source.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if replaced == 0 {
        return Err(io::Error::last_os_error());
    }
    // The staged name no longer exists.
    let _ = staged.keep();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "00aa";

    fn line(key: u8, id: &str) -> String {
        render(&[key; 32], "20300101000000", &format!("{TAG}{id}"))
    }

    #[test]
    fn only_lines_in_the_generated_form_are_recognized() {
        let generated = line(1, "00aa:11");
        assert_eq!(line_tag(generated.trim()), Some("massrelay-lease:00aa:11"));
        let key = keys::public_line(&[1; 32]);
        for other in [
            key.clone(),
            format!("{key} massrelay-lease:00aa:11"),
            generated.trim().replace("127.0.0.1", "0.0.0.0/0"),
            generated.trim().replace("\",expiry", "\",pty,expiry"),
            generated.trim().replace("20300101000000", "forever"),
            format!("{} trailing", generated.trim()),
            format!("command=\"x\",{}", generated.trim()),
        ] {
            assert_eq!(line_tag(&other), None, "{other}");
        }
    }

    #[test]
    fn removal_keeps_every_other_line_and_never_recreates_the_file() -> Result<()> {
        let profile = tempfile::tempdir()?;
        let file = profile.path().join(KEY_FILE);
        let withdrawals = Withdrawals::new(profile.path());
        purge(&withdrawals, OWNER)?;
        // Nothing is created in a profile that was never set up.
        assert!(fs::read_dir(profile.path())?.next().is_none());

        // Another profile's lease, a comment and a line someone added stay as they were.
        let other = line(2, "00bb:22");
        let foreign = format!("{} someone", keys::public_line(&[3; 32]));
        let before = format!(
            "# header\r\n{}{other}{}{foreign}",
            line(1, "00aa:11"),
            line(4, "00aa:33")
        );
        fs::write(&file, &before)?;
        purge(&withdrawals, OWNER)?;
        assert_eq!(
            fs::read_to_string(&file)?,
            format!("# header\r\n{other}{foreign}")
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_lock_is_waited_for_until_dropped_and_only_while_another_holds_it() -> Result<()> {
        let profile = tempfile::tempdir()?;
        let held = Lock::try_acquire(profile.path())?;
        let mut waiting = std::pin::pin!(Lock::acquire(profile.path()));
        let early = tokio::time::timeout(WAIT + Duration::from_millis(500), &mut waiting).await;
        assert!(early.is_err(), "the wait ended while the lock was held");
        drop(held);
        drop(tokio::time::timeout(WAIT, waiting).await??);
        // Any other failure ends it at once.
        let broken = profile.path().join("broken");
        fs::create_dir_all(broken.join(LOCK_FILE))?;
        let failed = tokio::time::timeout(WAIT, Lock::acquire(&broken)).await?;
        assert!(failed.is_err());
        Ok(())
    }

    #[test]
    fn a_key_file_of_any_size_is_read_and_pruned() -> Result<()> {
        let profile = tempfile::tempdir()?;
        let file = profile.path().join(KEY_FILE);
        let kept = line(2, "00bb:22").repeat(8000);
        fs::write(&file, format!("{kept}{}", line(1, "00aa:11")))?;
        assert!(kept.len() > 1 << 20);
        purge(&Withdrawals::new(profile.path()), OWNER)?;
        assert_eq!(fs::read_to_string(&file)?, kept);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_file_others_could_change_is_not_trusted() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let file = root.path().join(KEY_FILE);
        fs::write(&file, "")?;
        let mode = |path: &Path, mode| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap()
        };
        mode(&file, 0o600);
        check_trusted(&file)?;
        for open in [0o620, 0o604] {
            mode(&file, open);
            assert!(check_trusted(&file).is_err());
        }
        mode(&file, 0o600);
        mode(root.path(), 0o770);
        assert!(check_trusted(&file).is_err());
        mode(root.path(), 0o700);
        let link = root.path().join("link");
        symlink(&file, &link)?;
        assert!(check_trusted(&link).is_err() && read(&link).is_err());
        fs::hard_link(&file, root.path().join("second"))?;
        assert!(check_trusted(&file).is_err());
        Ok(())
    }
}
