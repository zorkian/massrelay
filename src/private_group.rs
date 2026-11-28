//! Linux user private groups: when a group write bit gives nobody but the owner access.
//!
//! Distributions that give each account a group of its own commonly use umask 0002, which
//! leaves directories such as `~/.local/share` group-writable. That is as safe as mode 0755
//! only while the group really is the account's alone, so every doubt is answered no:
//!
//! - The path has no POSIX access ACL. With one, the group bits are its mask and can give
//!   named accounts and groups write access whatever the owning group is.
//! - `/etc/nsswitch.conf` takes accounts and groups from `files` and `systemd` only. A
//!   network directory need not list all of its accounts, so a member could be missed.
//! - The group is the account's primary group and has the account's name. A group such as
//!   `users` that happens to have one member now is still meant to be shared.
//! - No other account listed has it as its primary or a supplementary group, and it names
//!   no other member.
//! - No other account has that group in its running threads' credentials. Processes can
//!   retain a group after removal from the account database, or receive it at service start.
//!
//! This accepts less than the same check in Debian's and Ubuntu's OpenSSH. Upstream OpenSSH
//! has no such check and refuses every group-writable path, so a caller that relies on the
//! SSH server must also know which server it is. macOS answers no.

use std::{fs::Metadata, os::unix::fs::MetadataExt as _, path::Path};

const GROUP_OR_OTHERS_WRITE: u32 = 0o022;
const GROUP_WRITE: u32 = 0o020;
/// The name services whose enumeration lists every account.
const LOCAL: [&str; 2] = ["files", "systemd"];

/// Whether `path`, whose `metadata` the caller read, is writable by its group and that
/// gives no account but `owner` write access: it is `owner`'s, others cannot write it, and
/// its group is provably `owner`'s private group. False for root's, and always off Linux.
///
/// It says nothing about other paths, and a caller decides which may have such a mode.
pub(crate) fn private_group_write(path: &Path, metadata: &Metadata, owner: u32) -> bool {
    PrivateGroups::SYSTEM.allows(path, metadata, owner)
}

/// [`private_group_write`], with where it learns a group's members.
#[derive(Clone, Copy)]
pub(crate) struct PrivateGroups {
    accounts: fn(u32) -> Option<Accounts>,
    credentials: fn(u32, u32) -> bool,
}

impl PrivateGroups {
    /// This machine's account database.
    pub(crate) const SYSTEM: Self = Self {
        accounts: system_accounts,
        credentials: private_credentials,
    };

    /// A database a test describes, asked about one group ID.
    #[cfg(test)]
    pub(crate) const fn fixture(accounts: fn(u32) -> Option<Accounts>) -> Self {
        Self {
            accounts,
            credentials: |_, _| true,
        }
    }

    pub(crate) fn allows(&self, path: &Path, metadata: &Metadata, owner: u32) -> bool {
        let group = metadata.gid();
        owner != 0
            && metadata.uid() == owner
            && metadata.mode() & GROUP_OR_OTHERS_WRITE == GROUP_WRITE
            && without_access_acl(path)
            && (self.accounts)(group).is_some_and(|accounts| accounts.private(owner, group))
            && (self.credentials)(owner, group)
    }
}

/// What the account database says that bears on one group.
pub(crate) struct Accounts {
    /// The contents of `/etc/nsswitch.conf`.
    pub nsswitch: String,
    /// What the group ID resolves to.
    pub group: Option<Group>,
    /// Every account listed.
    pub users: Vec<User>,
}

pub(crate) struct Group {
    pub name: Vec<u8>,
    /// The members it names, which need not include those whose primary group it is.
    pub members: Vec<Vec<u8>>,
}

pub(crate) struct User {
    pub name: Vec<u8>,
    pub uid: u32,
    /// The primary group.
    pub gid: u32,
    /// Every group a login of this account is given.
    pub groups: Vec<u32>,
}

impl Accounts {
    /// Whether group `gid` is `owner`'s private group.
    fn private(&self, owner: u32, gid: u32) -> bool {
        let Some(group) = &self.group else {
            return false;
        };
        // The first entry is the one a lookup by user ID gives. A list without it is not
        // complete.
        let Some(account) = self.users.iter().find(|user| user.uid == owner) else {
            return false;
        };
        local_only(&self.nsswitch)
            && account.gid == gid
            && account.name == group.name
            && matches!(group.members.as_slice(), [] | [_])
            && group.members.iter().all(|member| *member == account.name)
            && self
                .users
                .iter()
                .all(|user| user.uid == owner || (user.gid != gid && !user.groups.contains(&gid)))
    }
}

/// Whether accounts and groups come from local services alone.
fn local_only(nsswitch: &str) -> bool {
    let (mut users, mut groups) = (false, false);
    for line in nsswitch.lines() {
        let line = line.split('#').next().unwrap_or_default().trim_start();
        let end = line
            .find(|c: char| c == ':' || c.is_whitespace())
            .unwrap_or(line.len());
        let (database, sources) = line.split_at(end);
        match database {
            "passwd" => users = true,
            "group" => groups = true,
            // Where a login's supplementary groups come from, when it is not `group`.
            "initgroups" => {}
            _ => continue,
        }
        let sources = sources.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
        let mut action = false;
        let mut named = false;
        for word in sources.split_whitespace() {
            // `[NOTFOUND=return]` says what to do after a source, and can hold spaces.
            action |= word.starts_with('[');
            if !action {
                if !LOCAL.contains(&word) {
                    return false;
                }
                named = true;
            }
            action &= !word.ends_with(']');
        }
        if !named {
            return false;
        }
    }
    users && groups
}

#[cfg(target_os = "linux")]
fn without_access_acl(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: both strings are terminated, and no value is asked for.
    let size = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    // Only "there is no such attribute" shows there is none. A filesystem that cannot say
    // may enforce another kind of access list.
    size < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA)
}

#[cfg(not(target_os = "linux"))]
fn without_access_acl(_: &Path) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn private_credentials(owner: u32, group: u32) -> bool {
    use std::fs;

    // Fixed initial namespace IDs from include/linux/proc_ns.h (now named in
    // include/uapi/linux/nsfs.h). A container's procfs can conceal credentials
    // of processes that still have access to a mounted host directory.
    let initial = |namespace: &str, expected: &Path| {
        fs::read_link(format!("/proc/self/ns/{namespace}")).is_ok_and(|found| found == expected)
    };
    initial("pid", Path::new("pid:[4026531836]"))
        && initial("user", Path::new("user:[4026531837]"))
        && fs::read_to_string("/proc/self/mountinfo").is_ok_and(|mounts| visible_processes(&mounts))
        && private_threads(Path::new("/proc"), owner, group) == Some(true)
}

#[cfg(target_os = "linux")]
fn visible_processes(mounts: &str) -> bool {
    let mut found = false;
    for (mount, fs) in mounts.lines().filter_map(|line| line.split_once(" - ")) {
        if mount.split_ascii_whitespace().nth(4) != Some("/proc") {
            continue;
        }
        let mut fields = fs.split_ascii_whitespace();
        if fields.next() != Some("proc")
            || fields.nth(1).is_none_or(|options| {
                options
                    .split(',')
                    .any(|option| option.starts_with("hidepid=") && option != "hidepid=0")
            })
        {
            return false;
        }
        found = true;
    }
    found
}

#[cfg(target_os = "linux")]
fn private_threads(proc: &Path, owner: u32, group: u32) -> Option<bool> {
    use std::{fs, io::ErrorKind};

    let mut inspected = false;
    for process in fs::read_dir(proc).ok()? {
        let process = process.ok()?;
        if !process
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let pid = process.file_name().to_str()?.parse::<libc::pid_t>().ok()?;
        let mut threads = match fs::read_dir(process.path().join("task")) {
            Ok(threads) => threads.peekable(),
            Err(error) if error.kind() == ErrorKind::NotFound && exited(proc, pid, pid) => continue,
            Err(_) => return None,
        };
        if threads.peek().is_none() {
            if exited(proc, pid, pid) {
                continue;
            }
            return None;
        }
        for thread in threads {
            let thread = thread.ok()?;
            let status = match fs::read(thread.path().join("status")) {
                Ok(status) => status,
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    let tid = thread.file_name().to_str()?.parse::<libc::pid_t>().ok()?;
                    if exited(proc, pid, tid) {
                        continue;
                    }
                    return None;
                }
                Err(_) => return None,
            };
            inspected = true;
            if !private_thread(&status, owner, group)? {
                return Some(false);
            }
        }
    }
    inspected.then_some(true)
}

/// A missing proc entry can be skipped only when the kernel also reports that thread gone.
#[cfg(target_os = "linux")]
fn exited(proc: &Path, process: libc::pid_t, thread: libc::pid_t) -> bool {
    if proc != Path::new("/proc") || process <= 0 || thread <= 0 {
        return false;
    }
    // SAFETY: signal zero only checks for the process or thread; it cannot deliver a signal.
    let missing = unsafe {
        if process == thread {
            libc::kill(process, 0) == -1
        } else {
            libc::syscall(libc::SYS_tgkill, process, thread, 0) == -1
        }
    };
    missing && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(target_os = "linux")]
fn private_thread(status: &[u8], owner: u32, group: u32) -> Option<bool> {
    let ids = |key: &[u8]| {
        let field = status
            .split(|&byte| byte == b'\n')
            .find_map(|line| line.strip_prefix(key))?;
        std::str::from_utf8(field)
            .ok()?
            .split_ascii_whitespace()
            .map(|s| s.parse::<u32>().ok())
            .collect::<Option<Vec<_>>>()
    };
    let (uids, gids, supplementary) = (ids(b"Uid:")?, ids(b"Gid:")?, ids(b"Groups:")?);
    if uids.len() != 4 || gids.len() != 4 {
        return None;
    }
    Some(
        uids.iter().all(|&uid| uid == 0 || uid == owner)
            || (!gids.contains(&group) && !supplementary.contains(&group)),
    )
}

#[cfg(not(target_os = "linux"))]
fn private_credentials(_: u32, _: u32) -> bool {
    false
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn system_accounts(_: u32) -> Option<Accounts> {
    None
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn system_accounts(gid: u32) -> Option<Accounts> {
    let nsswitch = std::fs::read_to_string("/etc/nsswitch.conf").ok()?;
    // Asked first: a network directory is not enumerated at all.
    if !local_only(&nsswitch) {
        return None;
    }
    Some(Accounts {
        group: system::group(gid)?,
        users: system::users()?,
        nsswitch,
    })
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod system {
    use std::{ffi::CStr, mem::MaybeUninit, ptr::null_mut, sync::Mutex};

    use super::{Group, User};

    /// The C library has one position in the account list for the whole process.
    static LISTING: Mutex<()> = Mutex::new(());

    /// Call a reentrant lookup, with as large a buffer as it asks for. `None` if it fails,
    /// and `Some(None)` if there is no entry.
    fn entry<E, T>(
        mut call: impl FnMut(*mut E, &mut [libc::c_char], *mut *mut E) -> libc::c_int,
        read: impl FnOnce(&E) -> Option<T>,
    ) -> Option<Option<T>> {
        let mut buffer = vec![0; 16 * 1024];
        loop {
            let mut entry = MaybeUninit::<E>::uninit();
            let mut found = null_mut();
            match call(entry.as_mut_ptr(), &mut buffer, &mut found) {
                libc::ERANGE => {
                    let more = buffer.len();
                    buffer.try_reserve(more).ok()?;
                    buffer.resize(more * 2, 0);
                }
                // The end of a list, and what a lookup by ID may say for no entry.
                libc::ENOENT => return Some(None),
                0 if found.is_null() => return Some(None),
                // SAFETY: a found entry was initialized, and its strings and lists point
                // into the buffer, which outlives this read.
                0 => return read(unsafe { &*found }).map(Some),
                _ => return None,
            }
        }
    }

    /// # Safety
    /// `text` is null or a terminated string that stays valid for this call.
    unsafe fn bytes(text: *const libc::c_char) -> Option<Vec<u8>> {
        // SAFETY: the caller's promise, and null is excluded.
        (!text.is_null()).then(|| unsafe { CStr::from_ptr(text) }.to_bytes().to_vec())
    }

    pub(super) fn group(gid: u32) -> Option<Option<Group>> {
        entry(
            // SAFETY: the entry, the buffer of the length given and the result are writable.
            |entry, buffer, found| unsafe {
                libc::getgrgid_r(gid, entry, buffer.as_mut_ptr(), buffer.len(), found)
            },
            |group: &libc::group| {
                let mut members = Vec::new();
                let mut next = group.gr_mem;
                // SAFETY: a found group's name is a string, and its members are a list of
                // strings ended by a null pointer.
                unsafe {
                    while !next.is_null() && !(*next).is_null() {
                        members.push(bytes(*next)?);
                        next = next.add(1);
                    }
                    Some(Group {
                        name: bytes(group.gr_name)?,
                        members,
                    })
                }
            },
        )
    }

    /// Every account, with the groups its login is given.
    pub(super) fn users() -> Option<Vec<User>> {
        let _listing = LISTING.lock().ok()?;
        // SAFETY: no other thread uses the list while `LISTING` is held.
        unsafe { libc::setpwent() };
        let users = (|| {
            let mut users = Vec::new();
            loop {
                let next = entry(
                    // SAFETY: the entry, the buffer of the length given and the result are
                    // writable.
                    |entry, buffer, found| unsafe {
                        libc::getpwent_r(entry, buffer.as_mut_ptr(), buffer.len(), found)
                    },
                    |user: &libc::passwd| {
                        // SAFETY: a found account's name is a string.
                        let name = unsafe { bytes(user.pw_name) }?;
                        Some((name, user.pw_uid, user.pw_gid))
                    },
                )?;
                let Some((name, uid, gid)) = next else {
                    return Some(users);
                };
                users.push((name, uid, gid));
            }
        })();
        // SAFETY: as above.
        unsafe { libc::endpwent() };
        users?
            .into_iter()
            .map(|(name, uid, gid)| {
                let groups = memberships(&name, gid)?;
                Some(User {
                    name,
                    uid,
                    gid,
                    groups,
                })
            })
            .collect()
    }

    fn memberships(name: &[u8], primary: u32) -> Option<Vec<u32>> {
        let name = std::ffi::CString::new(name).ok()?;
        let mut groups = vec![0; 32];
        loop {
            let mut count = libc::c_int::try_from(groups.len()).ok()?;
            // SAFETY: the name is a string, and the list holds `count` entries.
            let status = unsafe {
                libc::getgrouplist(name.as_ptr(), primary, groups.as_mut_ptr(), &mut count)
            };
            let count = usize::try_from(count).ok()?;
            if status >= 0 {
                groups.truncate(count);
                return Some(groups);
            }
            // It says how many there are.
            let wanted = count.max(groups.len().checked_mul(2)?);
            groups.try_reserve(wanted - groups.len()).ok()?;
            groups.resize(wanted, 0);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests;
