//! The account's SSH files on Windows, for `massrelay install` and `massrelay uninstall`.
//!
//! Both run elevated, so nothing here trusts the environment or who owns the device's
//! state. The home directory is the profile of the process token's user. Every SSH file used
//! must be owned by exactly that user: an elevated process's files belong to Administrators
//! unless an owner is named, so each file made here names one, in the same call that creates
//! it, with an access list the user's ordinary token can read. Links and mount points are
//! refused. OpenSSH is never run: its configuration can name commands to execute.

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::windows::{
        ffi::OsStringExt as _,
        fs::{MetadataExt as _, OpenOptionsExt as _},
        io::AsRawHandle as _,
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};

use anyhow::{Context, Result, bail, ensure};
use tempfile::NamedTempFile;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_UNABLE_TO_MOVE_REPLACEMENT_2, GENERIC_READ,
        GENERIC_WRITE,
    },
    Security::TOKEN_QUERY,
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, GetFileInformationByHandle, MoveFileExW, OPEN_ALWAYS,
        ReplaceFileW,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
    UI::Shell::GetUserProfileDirectoryW,
};

use super::super::{self as rules, AceKind, Role, Security};
use super::{
    PrivateFile, describe, ensure_trusted, handle_security, last_error, os_error, security,
    ssh_private_dir, wide,
};

/// More than any SSH configuration holds.
const LIMIT: u64 = 16 * 1024 * 1024;

/// The account running the command, which is the one its service runs as.
pub struct Account(super::Account);

/// A file as it was read.
pub struct Found {
    pub contents: Vec<u8>,
    identity: Identity,
    security: Security,
}

#[derive(PartialEq, Eq)]
struct Identity {
    volume: u32,
    file: u64,
    names: u32,
    written: u64,
}

/// A canonical drive-letter path.
pub fn canonical(path: &Path) -> Result<PathBuf> {
    let resolved = path
        .canonicalize()
        .with_context(|| format!("resolve {}", path.display()))?;
    Ok(rules::plain(&resolved)?.into())
}

impl Account {
    pub fn current() -> Result<Self> {
        super::Account::current().map(Self)
    }

    /// The profile directory Windows records for the process token's user, where its OpenSSH
    /// looks for `.ssh`.
    pub fn home(&self) -> Result<PathBuf> {
        let mut token = null_mut();
        // SAFETY: the pseudo-handle of this process is always valid; `token` receives a
        // handle that is closed below.
        ensure!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
            "read this account's identity: {}",
            io::Error::last_os_error()
        );
        let mut buffer = vec![0u16; 32 * 1024];
        let mut len = buffer.len() as u32;
        // SAFETY: the token is open and the buffer is writable for the length given.
        let found = unsafe { GetUserProfileDirectoryW(token, buffer.as_mut_ptr(), &mut len) };
        let error = last_error();
        // SAFETY: `token` was opened above and is not used again.
        unsafe { CloseHandle(token) };
        if found == 0 {
            return Err(os_error(error).context("find this account's profile directory"));
        }
        let end = buffer
            .iter()
            .position(|&unit| unit == 0)
            .context("the profile directory's path is not terminated")?;
        Ok(OsString::from_wide(&buffer[..end]).into())
    }

    /// Every directory down to `path` must keep what is below it in place.
    pub fn home_directory(&self, path: &Path) -> Result<()> {
        no_reparse(path)?;
        ensure_trusted(&rules::plain(path)?, Role::Ancestor, &self.0)
    }

    /// The private profile, whose path OpenSSH will follow.
    pub fn profile_directory(&self, path: &Path) -> Result<()> {
        ssh_private_dir(path)
    }

    pub fn ssh_directory(&self, path: &Path) -> Result<()> {
        self.directory(path)
    }

    pub fn fragment_directory(&self, path: &Path) -> Result<()> {
        self.directory(path)
    }

    /// A directory of this account's own, created private to it when absent.
    fn directory(&self, path: &Path) -> Result<()> {
        let permissions = PrivateFile::inheriting(&self.0, "OICI")?;
        let name = wide(path)?;
        // SAFETY: the path is NUL-terminated and the security descriptor is live.
        if unsafe { CreateDirectoryW(name.as_ptr(), &permissions.0) } == 0 {
            let error = last_error();
            if error != ERROR_ALREADY_EXISTS {
                return Err(os_error(error).context(format!("create {}", path.display())));
            }
        }
        self.existing_directory(path)
    }

    /// Such a directory, which is not created.
    pub fn existing_directory(&self, path: &Path) -> Result<()> {
        no_reparse(path)?;
        ensure!(
            fs::symlink_metadata(path)?.is_dir(),
            "expected a directory at {}",
            path.display()
        );
        self.owned(path, &security(path)?)?;
        ensure_trusted(&rules::plain(path)?, Role::Holder, &self.0)
    }

    /// Hold off other installs and uninstalls of this account while its SSH files change.
    pub fn lock(&self, path: &Path) -> Result<File> {
        let file = PrivateFile::new(&self.0)?
            .open(path, GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS)
            .with_context(|| format!("open {}", path.display()))?;
        regular(path, &file)?;
        fs2::FileExt::lock_exclusive(&file).with_context(|| format!("lock {}", path.display()))?;
        Ok(file)
    }

    pub fn read(&self, path: &Path) -> Result<Option<Found>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
        };
        regular(path, &file)?;
        let identity = identity(path, &file)?;
        let security = handle_security(path, &file)?;
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
            identity,
            security,
        }))
    }

    fn owned(&self, path: &Path, security: &Security) -> Result<()> {
        ensure!(
            security.owner == self.0.sid,
            "{} is owned by {}, not by {}. Make that account its owner",
            path.display(),
            describe(&security.owner),
            self.0.name()
        );
        Ok(())
    }

    fn check(&self, path: &Path, found: &Found, role: Role) -> Result<()> {
        self.owned(path, &found.security)?;
        if let Some(sid) = rules::untrusted(&found.security, role, &self.0.sid) {
            bail!("{} has unsafe access to {}", describe(sid), path.display());
        }
        ensure!(
            found.identity.names == 1,
            "{} has more than one name (a hard link)",
            path.display()
        );
        Ok(())
    }

    /// A configuration or fragment: only this account and administrators may change it.
    pub fn check_fragment(&self, path: &Path, found: &Found) -> Result<()> {
        self.check(path, found, Role::Program)
    }

    /// A profile's SSH configuration: private, and readable by the user's ordinary token,
    /// in which the Administrators group grants nothing.
    pub fn check_client(&self, path: &Path, found: &Found) -> Result<()> {
        self.check(path, found, Role::Private)?;
        let read = rules::FILE_READ_DATA | rules::GENERIC_READ | rules::GENERIC_ALL;
        ensure!(
            found.security.dacl.as_ref().is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.kind == AceKind::Allow
                        && !entry.inherit_only
                        && entry.sid == self.0.sid
                        && entry.mask & read != 0
                })
            }),
            "{} does not let {} read it",
            path.display(),
            self.0.name()
        );
        Ok(())
    }

    /// The runtime's record: private, as the configuration it describes is.
    pub fn check_record(&self, path: &Path, found: &Found) -> Result<()> {
        self.check_client(path, found)
    }

    /// A temporary file beside `path`. Its name matches no `*.conf` include.
    fn stage(&self, path: &Path, contents: &[u8]) -> Result<NamedTempFile> {
        let directory = path.parent().context("the file has no directory")?;
        let permissions = PrivateFile::new(&self.0)?;
        let mut staged = tempfile::Builder::new()
            .make_in(directory, |path| {
                permissions.open(path, GENERIC_READ | GENERIC_WRITE, CREATE_NEW)
            })
            .with_context(|| format!("create a file in {}", directory.display()))?;
        staged.write_all(contents)?;
        staged.as_file().sync_all()?;
        Ok(staged)
    }

    /// Publish a complete private file where there is none. False if one appeared.
    pub fn create(&self, path: &Path, contents: &[u8]) -> Result<bool> {
        match self.stage(path, contents)?.persist_noclobber(path) {
            Ok(_) => Ok(true),
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error.error).with_context(|| format!("create {}", path.display())),
        }
    }

    /// Replace the file `found` was read from, keeping its owner and access list. False if it
    /// is no longer that file with those contents.
    ///
    /// An edit saved between the last comparison and the replacement, which Windows has no
    /// call to close, would be lost.
    pub fn replace(&self, path: &Path, found: &Found, contents: &[u8]) -> Result<bool> {
        self.check_fragment(path, found)?;
        let staged = self.stage(path, contents)?.into_temp_path();
        // As unused a name as the staged file's, and no more of an include.
        let previous = staged.with_extension("previous");
        let (target, replacement, backup) = (
            wide(path)?,
            wide(staged.as_os_str())?,
            wide(previous.as_path())?,
        );
        // Immediately before the replacement, so that an edit made meanwhile is read and kept.
        let unchanged = self
            .read(path)?
            .is_some_and(|now| now.identity == found.identity && now.contents == found.contents);
        if !unchanged {
            return Ok(false);
        }
        // ReplaceFileW gives the replacement the original's access list.
        // SAFETY: all three paths are NUL-terminated; the reserved arguments are null.
        let replaced = unsafe {
            ReplaceFileW(
                target.as_ptr(),
                replacement.as_ptr(),
                backup.as_ptr(),
                0,
                null(),
                null(),
            )
        };
        if replaced == 0 {
            let error = last_error();
            // The one failure that leaves the original under the other name.
            if error == ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 {
                // SAFETY: both paths are NUL-terminated.
                ensure!(
                    unsafe { MoveFileExW(backup.as_ptr(), target.as_ptr(), 0) } != 0,
                    "replacing {} failed; its contents are in {}",
                    path.display(),
                    previous.display()
                );
            }
            return Err(os_error(error).context(format!("replace {}", path.display())));
        }
        // The new file is in place; a leftover copy of the old one harms nothing.
        let _ = fs::remove_file(&previous);
        Ok(true)
    }

    /// Delete the file `found` was read from, under the same limits as `replace`. False if
    /// it is no longer that file with those contents.
    pub fn remove(&self, path: &Path, found: &Found) -> Result<bool> {
        self.check_fragment(path, found)?;
        let unchanged = self
            .read(path)?
            .is_some_and(|now| now.identity == found.identity && now.contents == found.contents);
        if !unchanged {
            return Ok(false);
        }
        fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
        Ok(true)
    }
}

/// Neither `path` nor any directory above it is a link or mount point, so that what is checked
/// is what is used.
fn no_reparse(path: &Path) -> Result<()> {
    // A drive's root has no entry of its own to be a reparse point.
    for part in path.ancestors().filter(|part| part.parent().is_some()) {
        let metadata =
            fs::symlink_metadata(part).with_context(|| format!("check {}", part.display()))?;
        ensure!(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "{} is a link or mount point, which MassRelay does not follow",
            part.display()
        );
    }
    Ok(())
}

fn regular(path: &Path, file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "expected a regular file at {}; a link there is not followed",
        path.display()
    );
    Ok(())
}

fn identity(path: &Path, file: &File) -> Result<Identity> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open and the structure is writable.
    ensure!(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } != 0,
        "identify {}: {}",
        path.display(),
        io::Error::last_os_error()
    );
    let wide = |high: u32, low: u32| u64::from(high) << 32 | u64::from(low);
    Ok(Identity {
        volume: information.dwVolumeSerialNumber,
        file: wide(information.nFileIndexHigh, information.nFileIndexLow),
        names: information.nNumberOfLinks,
        written: wide(
            information.ftLastWriteTime.dwHighDateTime,
            information.ftLastWriteTime.dwLowDateTime,
        ),
    })
}

pub(crate) fn check_managed_file(path: &Path) -> Result<()> {
    let account = Account::current()?;
    let found = account
        .read(path)?
        .context("the private SSH file is missing")?;
    account.check_client(path, &found)
}

/// Refuse `path`, a file or a directory of the system SSH server, unless the system, the
/// machine's administrators and TrustedInstaller alone control it and every directory above
/// it, none of them a link or mount point. No other account counts, the one running this
/// included: its ordinary token must not change what the server reads.
pub(crate) fn check_system_path(path: &Path, directory: bool) -> Result<()> {
    no_reparse(path)?;
    ensure!(
        fs::symlink_metadata(path)?.is_dir() == directory,
        "{} is not the expected kind of file",
        path.display()
    );
    let path = rules::plain(path)?;
    for (depth, part) in Path::new(&path).ancestors().enumerate() {
        // A directory that receives new files must not pass them unsafe permissions.
        let role = match (depth, directory) {
            (0, false) => Role::Program,
            (0, true) | (1, false) => Role::Staging,
            _ => Role::Ancestor,
        };
        // The account named to this rule is trusted besides the privileged ones.
        if let Some(sid) = rules::untrusted(&security(part)?, role, rules::SYSTEM) {
            bail!("{} has unsafe access to {}", describe(sid), part.display());
        }
    }
    Ok(())
}

/// Hold the machine's lock on changes to the system SSH server: the file `path` in the
/// server's own directory, which only the system and administrators can open and one handle
/// at a time holds. Waits `limit` for another holder. Windows releases it when the process
/// ends, however it ends.
pub(crate) fn lock_system(path: &Path, limit: std::time::Duration) -> Result<File> {
    let directory = path.parent().context("the lock has no directory")?;
    check_system_path(directory, true)?;
    // Owned by Administrators, and open to them and the system alone.
    let administrators = super::Account {
        token_user: Vec::new(),
        sid: rules::ADMINISTRATORS.to_owned(),
        user: String::new(),
        domain: String::new(),
    };
    let permissions = PrivateFile::new(&administrators)?;
    let deadline = std::time::Instant::now() + limit;
    let held = windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION as i32;
    let file = loop {
        match permissions.open_sharing(path, GENERIC_READ | GENERIC_WRITE, 0, OPEN_ALWAYS) {
            Ok(file) => break file,
            Err(error)
                if error.raw_os_error() == Some(held) && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("take the lock {} on SSH server changes", path.display())
                });
            }
        }
    };
    regular(path, &file)?;
    // An existing file open to others could be held by one of them.
    let security = handle_security(path, &file)?;
    ensure!(
        rules::untrusted(&security, Role::Private, rules::SYSTEM).is_none(),
        "{} is open to other accounts",
        path.display()
    );
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        private::cli,
        ssh_install::{CLIENT_CONFIG, CLIENT_RECORD, CLIENT_STATE, integrate, survey},
        windows_service::private_marker,
    };

    fn present(account: &Account, path: &Path) -> Result<Found> {
        account.read(path)?.context("the file is missing")
    }

    fn entries(found: &Found) -> Vec<(String, u32)> {
        let mut entries: Vec<_> = found
            .security
            .dacl
            .iter()
            .flatten()
            .map(|entry| (entry.sid.clone(), entry.mask))
            .collect();
        entries.sort();
        entries
    }

    /// Registration with real owners and access lists, from an elevated terminal or an
    /// ordinary one, in a disposable home. The account's own `.ssh` is not touched.
    #[test]
    fn registration_owns_its_files_and_keeps_an_existing_access_list() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = canonical(temp.path())?;
        let account = Account::current()?;
        let home = root.join("home");
        let state = root.join("state with spaces");
        let profile = state.join(cli::DIR_NAME);
        fs::create_dir(&home)?;
        fs::create_dir_all(&profile)?;
        let config = integrate(&account, &home, &state)?;
        let client = profile.join(CLIENT_CONFIG);
        account.check_fragment(&config, &present(&account, &config)?)?;
        account.check_client(&client, &present(&account, &client)?)?;
        let fragments = home.join(".ssh").join("massrelay.d");
        for entry in fs::read_dir(&fragments)? {
            let path = entry?.path();
            account.check_fragment(&path, &present(&account, &path)?)?;
        }

        // The runtime publishes its file this way, and a later install accepts it.
        let settings = b"Host massrelay-fixture\n    User fixture\n    Port 2222\n";
        let mut staged = private_marker(&profile)?;
        staged.write_all(settings)?;
        staged.persist(&client)?;
        // A user's configuration, readable by one more group.
        fs::write(&config, "Host a\r\n")?;
        let granted = Command::new("icacls.exe")
            .arg(&config)
            .args(["/grant", "*S-1-5-32-545:(R)"])
            .output()?;
        ensure!(granted.status.success(), "could not change the access list");
        let before = present(&account, &config)?;
        integrate(&account, &home, &state)?;
        let after = present(&account, &config)?;
        assert_eq!(
            after.contents,
            b"# Added by massrelay install\r\nInclude massrelay.d/*.conf\r\n\r\nHost a\r\n"
        );
        assert_eq!(after.security.owner, before.security.owner);
        assert_eq!(entries(&after), entries(&before));
        assert_eq!(present(&account, &client)?.contents, settings);
        integrate(&account, &home, &state)?;
        assert!(present(&account, &config)?.identity == after.identity);
        // The configuration, the fragments and no staged or previous file.
        assert_eq!(fs::read_dir(home.join(".ssh"))?.count(), 2);

        // An uninstall removes what the runtime recorded writing, and takes back the added
        // lines keeping the access list. The next install adds them again.
        let record = profile.join(CLIENT_RECORD);
        let mut staged = private_marker(&profile)?;
        writeln!(staged, "{:x}", Sha256::digest(settings))?;
        staged.persist(&record)?;
        survey(Account::current()?, &home, &state).apply()?;
        assert!(!record.exists());
        let removed = present(&account, &config)?;
        assert_eq!(removed.contents, b"Host a\r\n");
        assert_eq!(removed.security.owner, before.security.owner);
        assert_eq!(entries(&removed), entries(&before));
        assert!(!client.exists());
        assert!(profile.join(CLIENT_STATE).is_file());
        // The ledger and the lock stay; the profile's fragment is gone.
        assert_eq!(fs::read_dir(&fragments)?.count(), 2);
        integrate(&account, &home, &state)?;
        let mut staged = private_marker(&profile)?;
        staged.write_all(settings)?;
        staged.persist(&client)?;
        let after = present(&account, &config)?;

        // Windows OpenSSH reads the drive path the fragment includes. The copy it parses
        // names the disposable fragments, since a relative include means the real home's.
        let ssh = std::env::var_os("SystemRoot")
            .map(|root| PathBuf::from(root).join(r"System32\OpenSSH\ssh.exe"));
        if let Some(ssh) = ssh.filter(|ssh| ssh.is_file()) {
            let pattern = format!(
                "\"{}/*.conf\"",
                rules::plain(&fragments)?.replace('\\', "/")
            );
            let parsed = config.with_file_name("parsed");
            let text =
                String::from_utf8(after.contents)?.replacen("massrelay.d/*.conf", &pattern, 1);
            ensure!(account.create(&parsed, text.as_bytes())?, "the copy exists");
            let output = Command::new(ssh)
                .arg("-G")
                .arg("-F")
                .arg(&parsed)
                .arg("massrelay-fixture")
                .output()?;
            ensure!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let shown = String::from_utf8_lossy(&output.stdout);
            assert!(shown.lines().any(|line| line == "user fixture"), "{shown}");
            assert!(shown.lines().any(|line| line == "port 2222"), "{shown}");
        }
        Ok(())
    }
}
