//! Account databases written as `/etc/passwd` and `/etc/group` are on a distribution with
//! user private groups, and temporary directories. Only the last test reads the machine's
//! own database.

use std::{
    ffi::CString,
    fs,
    os::unix::{ffi::OsStrExt as _, fs::PermissionsExt as _},
};

use anyhow::{Context, Result, ensure};

use super::*;

/// Ubuntu's.
const NSSWITCH: &str = "\
# /etc/nsswitch.conf

passwd:         files systemd
group:          files systemd
shadow:         files systemd

hosts:          files mdns4_minimal [NOTFOUND=return] dns
netgroup:       nis
";

const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
owner:x:{uid}:{gid}:,,,:/home/owner:/bin/bash
guest:x:4000001:4000001:,,,:/home/guest:/bin/bash
";

const GROUP: &str = "\
root:x:0:
daemon:x:1:
owner:x:{gid}:
guest:x:4000001:
sudo:x:4000002:owner
";

/// What a lookup of `gid` finds in these files, for the account `uid`.
fn database(uid: u32, gid: u32, passwd: &str, group: &str) -> Accounts {
    let filled = |text: &str| {
        text.replace("{uid}", &uid.to_string())
            .replace("{gid}", &gid.to_string())
    };
    let (passwd, group) = (filled(passwd), filled(group));
    let groups: Vec<(&str, u32, Vec<&str>)> = group
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            let members = fields[3].split(',').filter(|name| !name.is_empty());
            (fields[0], fields[2].parse().unwrap(), members.collect())
        })
        .collect();
    let users = passwd
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            let (name, primary) = (fields[0], fields[3].parse().unwrap());
            let supplementary = groups
                .iter()
                .filter(|(_, _, members)| members.contains(&name))
                .map(|(_, gid, _)| *gid);
            User {
                name: name.into(),
                uid: fields[2].parse().unwrap(),
                gid: primary,
                groups: std::iter::once(primary).chain(supplementary).collect(),
            }
        })
        .collect();
    Accounts {
        nsswitch: NSSWITCH.into(),
        group: groups
            .iter()
            .find(|(_, id, _)| *id == gid)
            .map(|(name, _, members)| Group {
                name: (*name).into(),
                members: members.iter().map(|member| (*member).into()).collect(),
            }),
        users,
    }
}

fn running_uid() -> u32 {
    // SAFETY: geteuid is infallible and has no preconditions.
    unsafe { libc::geteuid() }
}

/// A machine where `gid`, which the test's files have, is this account's private group.
pub(crate) fn private(gid: u32) -> Option<Accounts> {
    Some(database(running_uid(), gid, PASSWD, GROUP))
}

/// The same machine after another account was added to that group.
pub(crate) fn shared(gid: u32) -> Option<Accounts> {
    let group = GROUP.replace("owner:x:{gid}:", "owner:x:{gid}:guest");
    Some(database(running_uid(), gid, PASSWD, &group))
}

/// Give `path` an access list that lets one more account write it. The group mode bits
/// become the list's mask, so the mode alone still reads as group-writable.
pub(crate) fn grant_by_acl(path: &Path) -> Result<()> {
    const NOBODY: u32 = u32::MAX;
    let mut value = 2u32.to_le_bytes().to_vec();
    // The owner, a named account, the owning group, the mask and others.
    for (tag, permissions, id) in [
        (0x01u16, 7u16, NOBODY),
        (0x02, 7, 4_000_001),
        (0x04, 7, NOBODY),
        (0x10, 7, NOBODY),
        (0x20, 0, NOBODY),
    ] {
        value.extend(tag.to_le_bytes());
        value.extend(permissions.to_le_bytes());
        value.extend(id.to_le_bytes());
    }
    let name = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: both strings are terminated, and the value has the length given.
    let status = unsafe {
        libc::setxattr(
            name.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    ensure!(
        status == 0,
        "give {} an access list: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    Ok(())
}

#[test]
fn only_a_group_with_no_other_member_is_private() {
    const UID: u32 = 1000;
    const GID: u32 = 1000;
    let private = |passwd: &str, group: &str| database(UID, GID, passwd, group).private(UID, GID);
    let own = "owner:x:{gid}:";
    assert!(private(PASSWD, GROUP));
    // Naming the account itself, or a second name for its user ID, adds nobody.
    assert!(private(PASSWD, &GROUP.replace(own, "owner:x:{gid}:owner")));
    let alias = format!("{PASSWD}alias:x:{{uid}}:{{gid}}::/home/owner:/bin/sh\n");
    assert!(private(&alias, GROUP));

    // Another account's primary group.
    let primary = format!("{PASSWD}other:x:4000003:{{gid}}::/home/other:/bin/sh\n");
    assert!(!private(&primary, GROUP));
    // A supplementary member, also through a second line for the same group ID.
    for group in [
        GROUP.replace(own, "owner:x:{gid}:guest"),
        GROUP.replace(own, "owner:x:{gid}:owner,guest"),
        format!("{GROUP}staff:x:{{gid}}:guest\n"),
        // A member the account list does not have.
        GROUP.replace(own, "owner:x:{gid}:elsewhere"),
    ] {
        assert!(!private(PASSWD, &group), "{group}");
    }
    // A group meant to be shared, which has one member only for now.
    assert!(!private(PASSWD, &GROUP.replace(own, "users:x:{gid}:")));
    // Not the account's primary group, though it alone belongs to it.
    let elsewhere = PASSWD.replace("{uid}:{gid}", "{uid}:4000009");
    assert!(!private(
        &elsewhere,
        &GROUP.replace(own, "owner:x:{gid}:owner")
    ));
    // An unknown group, and a list that does not have the account.
    assert!(!private(PASSWD, &GROUP.replace(own, "owner:x:4000009:")));
    assert!(!private(&PASSWD.replace("{uid}", "4000009"), GROUP));
}

#[test]
fn a_network_account_database_is_never_trusted_to_list_every_member() {
    for local in [
        NSSWITCH,
        "passwd:files\ngroup : files [SUCCESS=merge] systemd\ninitgroups: files\n",
        "passwd: files [!UNAVAIL=return NOTFOUND=continue] systemd # sss\ngroup: files\n",
    ] {
        assert!(local_only(local), "{local}");
    }
    for other in [
        "",
        "passwd: files\n",
        "group: files\n",
        "passwd: files\ngroup:\n",
        "passwd: files sss\ngroup: files\n",
        "passwd: files\ngroup: files ldap\n",
        "passwd: compat\ngroup: compat\n",
        "passwd: files\ngroup: files [SUCCESS=merge] winbind\n",
        "passwd: files\ngroup: files\ninitgroups: files nis\n",
        "passwd: files\ngroup: files\npasswd: sss\n",
    ] {
        assert!(!local_only(other), "{other}");
    }
    let mut accounts = database(1000, 1000, PASSWD, GROUP);
    accounts.nsswitch = "passwd: files sss\ngroup: files sss\n".into();
    assert!(!accounts.private(1000, 1000));
}

#[test]
fn only_the_group_bit_of_an_owned_path_without_an_access_list_is_excused() -> Result<()> {
    let uid = running_uid();
    ensure!(uid != 0, "run this test without root");
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("share");
    fs::create_dir(&path)?;
    let groups = PrivateGroups::fixture(private);
    let allows = |groups: PrivateGroups, mode: u32, owner: u32| -> Result<bool> {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        Ok(groups.allows(&path, &fs::metadata(&path)?, owner))
    };
    for mode in [0o770, 0o775, 0o2775] {
        assert!(allows(groups, mode, uid)?, "{mode:o}");
    }
    // Writable by others, or by nobody but the owner, which needs no excuse.
    for mode in [0o777, 0o772, 0o1777, 0o702, 0o755] {
        assert!(!allows(groups, mode, uid)?, "{mode:o}");
    }
    assert!(!allows(groups, 0o775, uid + 1)?);
    assert!(!allows(PrivateGroups::fixture(shared), 0o775, uid)?);
    assert!(!allows(PrivateGroups::fixture(|_| None), 0o775, uid)?);

    grant_by_acl(&path)?;
    let metadata = fs::metadata(&path)?;
    assert_eq!(metadata.mode() & 0o777, 0o770);
    assert!(!groups.allows(&path, &metadata, uid));
    Ok(())
}

/// The calls into the C library, compared with the files they read.
#[test]
#[cfg(target_env = "gnu")]
fn the_system_database_lists_every_local_account_with_its_groups() -> Result<()> {
    let nsswitch = fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default();
    // SAFETY: getegid is infallible and has no preconditions.
    let gid = unsafe { libc::getegid() };
    let found = system_accounts(gid);
    if !local_only(&nsswitch) {
        assert!(found.is_none());
        return Ok(());
    }
    let found = found.context("a local account database")?;
    for line in fs::read_to_string("/etc/passwd")?.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if line.starts_with('#') || fields.len() != 7 {
            continue;
        }
        let (uid, primary) = (fields[2].parse::<u32>()?, fields[3].parse::<u32>()?);
        let user = found
            .users
            .iter()
            .find(|user| user.name == fields[0].as_bytes())
            .with_context(|| format!("{} is not listed", fields[0]))?;
        assert_eq!((user.uid, user.gid), (uid, primary), "{}", fields[0]);
        assert!(user.groups.contains(&primary), "{}", fields[0]);
    }
    let mut named = false;
    for line in fs::read_to_string("/etc/group")?.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if line.starts_with('#') || fields.len() != 4 {
            continue;
        }
        for member in fields[3].split(',') {
            if let Some(user) = found
                .users
                .iter()
                .find(|user| user.name == member.as_bytes())
            {
                assert!(user.groups.contains(&fields[2].parse()?), "{line}");
            }
        }
        // A lookup by ID gives the first line with it.
        if fields[2].parse::<u32>()? == gid && !std::mem::replace(&mut named, true) {
            let group = found.group.as_ref().context("this process's group")?;
            assert_eq!(group.name, fields[0].as_bytes());
        }
    }
    Ok(())
}

#[test]
fn a_running_threads_credentials_can_disprove_group_privacy() -> Result<()> {
    let proc = tempfile::tempdir()?;
    let task = proc.path().join("14/task/15");
    fs::create_dir_all(&task)?;
    let status = task.join("status");
    let owner_and_group = 1000;
    fs::write(
        &status,
        "Uid:\t1001 1001 1001 1001\nGid:\t1001 1001 1001 1001\nGroups:\t1001\n",
    )?;
    assert_eq!(
        private_threads(proc.path(), owner_and_group, owner_and_group),
        Some(true)
    );
    fs::write(
        &status,
        "Uid:\t1001 1001 1001 1001\nGid:\t1001 1001 1001 1001\nGroups:\t1001 1000\n",
    )?;
    assert_eq!(
        private_threads(proc.path(), owner_and_group, owner_and_group),
        Some(false)
    );
    fs::write(
        &status,
        "Uid:\t1001 1001 1001 1001\nGid:\t1001 1001 1001 1000\nGroups:\n",
    )?;
    assert_eq!(
        private_threads(proc.path(), owner_and_group, owner_and_group),
        Some(false)
    );
    fs::write(&status, "Uid:\t1001 1001 1001 1001\n")?;
    assert_eq!(
        private_threads(proc.path(), owner_and_group, owner_and_group),
        None
    );
    fs::write(
        &status,
        "Uid:\t1001 1001 1001 1001\nGid:\t1001 1001 1001 1001\nGroups:\n",
    )?;
    let incomplete = proc.path().join("12");
    fs::create_dir(&incomplete)?;
    assert_eq!(
        private_threads(proc.path(), owner_and_group, owner_and_group),
        None
    );
    fs::create_dir(incomplete.join("task"))?;
    assert_eq!(
        private_threads(proc.path(), owner_and_group, owner_and_group),
        None
    );
    fs::create_dir_all(incomplete.join("task/12"))?;
    assert_eq!(
        private_threads(proc.path(), owner_and_group, owner_and_group),
        None
    );
    assert!(!visible_processes(
        "42 33 0:42 / /proc rw - proc proc rw,hidepid=2"
    ));
    Ok(())
}
