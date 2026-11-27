//! The account's files on Linux and macOS.
//!
//! The home directory is the password database's, where OpenSSH looks for `~/.ssh`, whatever
//! `HOME` says. Only this account can create a file it owns, and OpenSSH reads only files
//! owned by the account or root, so ownership is checked on every file used.

use std::{
    ffi::{CStr, OsStr},
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    mem::MaybeUninit,
    os::unix::{
        ffi::OsStrExt as _,
        fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
    ptr::null_mut,
};

use anyhow::{Context, Result, bail, ensure};
use tempfile::NamedTempFile;

/// More than any SSH configuration holds.
const LIMIT: u64 = 16 * 1024 * 1024;
const GROUP_OR_OTHERS_WRITE: u32 = 0o022;
const STICKY: u32 = 0o1000;

/// The account running the install, which is the one its service runs as.
pub struct Account {
    uid: u32,
}

/// A file as it was read. Equal readings are of the same unchanged file.
#[derive(PartialEq, Eq)]
pub struct Found {
    pub contents: Vec<u8>,
    link: bool,
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    names: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

pub fn canonical(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("resolve {}", path.display()))
}

impl Account {
    pub fn current() -> Result<Self> {
        // SAFETY: these calls have no preconditions and cannot fail.
        let (uid, effective) = unsafe { (libc::getuid(), libc::geteuid()) };
        ensure!(
            uid == effective,
            "run massrelay install as the account itself"
        );
        Ok(Self { uid })
    }

    pub fn home(&self) -> Result<PathBuf> {
        let mut buffer = vec![0u8; 1024];
        loop {
            let mut entry = MaybeUninit::<libc::passwd>::uninit();
            let mut found = null_mut();
            // SAFETY: the entry, the buffer of the length given and the result are writable.
            let status = unsafe {
                libc::getpwuid_r(
                    self.uid,
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
                return Err(io::Error::from_raw_os_error(status))
                    .context("look up this account's home directory");
            }
            ensure!(
                !found.is_null(),
                "the password database has no entry for user ID {}",
                self.uid
            );
            // SAFETY: a found entry was initialized, and its strings point into the buffer.
            let home = unsafe {
                let home = (*found).pw_dir;
                ensure!(!home.is_null(), "this account has no home directory");
                CStr::from_ptr(home)
            };
            let home = Path::new(OsStr::from_bytes(home.to_bytes()));
            ensure!(
                home.is_absolute(),
                "this account's home directory is not an absolute path"
            );
            return canonical(home);
        }
    }

    /// Every directory down to `path` must keep what is below it in place.
    pub fn home_directory(&self, path: &Path) -> Result<()> {
        for part in path.ancestors() {
            let metadata =
                fs::metadata(part).with_context(|| format!("check {}", part.display()))?;
            ensure!(
                metadata.uid() == self.uid || metadata.uid() == 0,
                "{} belongs to another account",
                part.display()
            );
            ensure!(
                metadata.mode() & GROUP_OR_OTHERS_WRITE == 0 || metadata.mode() & STICKY != 0,
                "{} is writable by other accounts",
                part.display()
            );
        }
        Ok(())
    }

    /// The private profile, whose path OpenSSH will follow.
    pub fn profile_directory(&self, path: &Path) -> Result<()> {
        self.owned_directory(path, GROUP_OR_OTHERS_WRITE)?;
        self.home_directory(path.parent().context("the profile has no parent")?)
    }

    /// `~/.ssh`, created for this account alone when absent.
    pub fn ssh_directory(&self, path: &Path) -> Result<()> {
        create_directory(path)?;
        self.owned_directory(path, GROUP_OR_OTHERS_WRITE)
    }

    pub fn fragment_directory(&self, path: &Path) -> Result<()> {
        create_directory(path)?;
        self.owned_directory(path, GROUP_OR_OTHERS_WRITE)
    }

    fn owned_directory(&self, path: &Path, forbidden: u32) -> Result<()> {
        let metadata =
            fs::symlink_metadata(path).with_context(|| format!("check {}", path.display()))?;
        ensure!(
            metadata.is_dir(),
            "{} is not a directory; a link there is not followed",
            path.display()
        );
        ensure!(
            metadata.uid() == self.uid,
            "{} belongs to another account",
            path.display()
        );
        ensure!(
            metadata.mode() & forbidden == 0,
            "{} is writable by other accounts",
            path.display()
        );
        Ok(())
    }

    /// Hold off other installs of this account while its SSH files change.
    pub fn lock(&self, path: &Path) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        fs2::FileExt::lock_exclusive(&file).with_context(|| format!("lock {}", path.display()))?;
        Ok(file)
    }

    /// Read a file. A link is followed only to see what it holds; `check` refuses it.
    pub fn read(&self, path: &Path) -> Result<Option<Found>> {
        let link = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata.is_symlink(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("check {}", path.display())),
        };
        // A pipe at the path must not stall the install.
        let flags = libc::O_NONBLOCK | if link { 0 } else { libc::O_NOFOLLOW };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file(),
            "expected a regular file at {}",
            path.display()
        );
        let mut contents = Vec::new();
        file.take(LIMIT + 1)
            .read_to_end(&mut contents)
            .with_context(|| format!("read {}", path.display()))?;
        ensure!(
            contents.len() as u64 <= LIMIT,
            "{} is too large",
            path.display()
        );
        Ok(Some(Found {
            contents,
            link,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
            names: metadata.nlink(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }))
    }

    pub fn check_client(&self, path: &Path, found: &Found) -> Result<()> {
        self.check(path, found, GROUP_OR_OTHERS_WRITE)
    }

    pub fn check_fragment(&self, path: &Path, found: &Found) -> Result<()> {
        self.check(path, found, GROUP_OR_OTHERS_WRITE)
    }

    fn check(&self, path: &Path, found: &Found, forbidden: u32) -> Result<()> {
        if found.link {
            bail!(
                "{} is a link, which massrelay install does not write through",
                path.display()
            );
        }
        ensure!(
            found.uid == self.uid,
            "{} belongs to another account",
            path.display()
        );
        ensure!(
            found.mode & forbidden == 0,
            "{} is writable by other accounts",
            path.display()
        );
        ensure!(
            found.names == 1,
            "{} has more than one name (a hard link)",
            path.display()
        );
        Ok(())
    }

    /// Publish a complete private file where there is none. False if one appeared.
    pub fn create(&self, path: &Path, contents: &[u8]) -> Result<bool> {
        let staged = stage(path, contents, 0o600, None)?;
        match staged.persist_noclobber(path) {
            Ok(_) => {
                sync_parent(path);
                Ok(true)
            }
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error.error).with_context(|| format!("create {}", path.display())),
        }
    }

    /// Replace the file `found` was read from, keeping its owner, group and mode. False if it
    /// is no longer that file with those contents.
    ///
    /// A link or another account's file is never replaced, nor is a configuration every
    /// account can write. An edit saved between the last comparison and the rename, which no
    /// portable call can close, would be lost.
    pub fn replace(&self, path: &Path, found: &Found, contents: &[u8]) -> Result<bool> {
        self.check(path, found, GROUP_OR_OTHERS_WRITE)?;
        let staged = stage(path, contents, found.mode, Some(found.gid))?;
        // Immediately before the rename, so that an edit made meanwhile is read and kept.
        if self.read(path)?.as_ref() != Some(found) {
            return Ok(false);
        }
        staged
            .persist(path)
            .map_err(|error| error.error)
            .with_context(|| format!("replace {}", path.display()))?;
        sync_parent(path);
        Ok(true)
    }
}

fn create_directory(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        // Exactly the owner's access, whatever the umask took away.
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700)),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
    .with_context(|| format!("create {}", path.display()))
}

/// A temporary file beside `path`. Its name matches no `*.conf` include.
fn stage(path: &Path, contents: &[u8], mode: u32, group: Option<u32>) -> Result<NamedTempFile> {
    let directory = path.parent().context("the file has no directory")?;
    let mut staged = NamedTempFile::new_in(directory)
        .with_context(|| format!("create a file in {}", directory.display()))?;
    staged.write_all(contents)?;
    let file = staged.as_file();
    if group.is_some_and(|group| file.metadata().is_ok_and(|now| now.gid() != group)) {
        std::os::unix::fs::fchown(file, None, group)
            .with_context(|| format!("keep the group of {}", path.display()))?;
    }
    // After the group, since changing that can clear mode bits.
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(staged)
}

fn sync_parent(path: &Path) {
    // The rename already took effect. Some filesystems reject directory fsync.
    if let Some(directory) = path.parent() {
        let _ = File::open(directory).and_then(|directory| directory.sync_all());
    }
}
