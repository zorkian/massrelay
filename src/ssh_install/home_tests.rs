use std::{
    fs,
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _, symlink},
    process::Command,
};

use tempfile::TempDir;

use super::*;

/// A disposable home directory and profiles. Nothing here reads the real account's files.
struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    home: PathBuf,
    account: Account,
}

impl Fixture {
    fn new() -> Result<Self> {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let root = temp.path().canonicalize()?;
        let home = root.join("home");
        private_dir(&home)?;
        Ok(Self {
            _temp: temp,
            root,
            home,
            account: Account::current()?,
        })
    }

    /// A state directory with the private directory an enrolled profile has.
    fn profile(&self, name: &str) -> Result<PathBuf> {
        let state = self.root.join(name);
        private_dir(&state)?;
        private_dir(&state.join(cli::DIR_NAME))?;
        Ok(state)
    }

    fn install(&self, state: &Path) -> Result<PathBuf> {
        integrate(&self.account, &self.home, state)
    }

    fn ssh(&self) -> PathBuf {
        self.home.join(".ssh")
    }

    fn fragments(&self) -> Result<Vec<PathBuf>> {
        let mut found = Vec::new();
        for entry in fs::read_dir(self.ssh().join(FRAGMENTS))? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "conf") {
                found.push(path);
            }
        }
        found.sort();
        Ok(found)
    }

    /// The uninstall as planned now: what it would show.
    fn removal(&self, state: &Path) -> Result<Removal> {
        let mut account = Account::current()?;
        account.groups = self.account.groups;
        Ok(survey(account, &self.home, state))
    }

    fn uninstall(&self, state: &Path) -> Result<()> {
        self.removal(state)?.apply()
    }

    fn ledger(&self) -> PathBuf {
        self.ssh().join(FRAGMENTS).join(LEDGER)
    }

    /// A user's own file, in a `~/.ssh` made beforehand.
    fn existing(&self, name: &str, contents: &[u8], mode: u32) -> Result<PathBuf> {
        if !self.ssh().exists() {
            private_dir(&self.ssh())?;
        }
        let path = self.ssh().join(name);
        write(&path, contents, mode)?;
        Ok(path)
    }
}

fn private_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

fn write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn client(state: &Path) -> PathBuf {
    state.join(cli::DIR_NAME).join(CLIENT_CONFIG)
}

fn record(state: &Path) -> PathBuf {
    state.join(cli::DIR_NAME).join(CLIENT_RECORD)
}

fn digest(contents: &[u8]) -> Vec<u8> {
    format!("{:x}\n", Sha256::digest(contents)).into_bytes()
}

/// What the runtime leaves once it has written a configuration.
fn publish(state: &Path, contents: &[u8]) -> Result<()> {
    write(&client(state), contents, 0o600)?;
    write(&record(state), &digest(contents), 0o600)
}

fn mode(path: &Path) -> Result<u32> {
    Ok(fs::symlink_metadata(path)?.mode() & 0o7777)
}

/// What changes when a file is written or replaced.
fn stamp(path: &Path) -> Result<(u64, i64, i64, Vec<u8>)> {
    let metadata = fs::metadata(path)?;
    Ok((
        metadata.ino(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        fs::read(path)?,
    ))
}

#[test]
fn profiles_coexist_and_a_second_install_changes_nothing() -> Result<()> {
    let fixture = Fixture::new()?;
    let first = fixture.profile("Application Support")?;
    let config = fixture.install(&first)?;
    assert_eq!(config, fixture.ssh().join("config"));
    assert_eq!(
        fs::read_to_string(&config)?,
        "# Added by massrelay install\nInclude massrelay.d/*.conf\n"
    );
    assert_eq!(mode(&fixture.ssh())?, 0o700);
    assert_eq!(mode(&fixture.ssh().join(FRAGMENTS))?, 0o700);
    assert_eq!(mode(&config)?, 0o600);
    assert_eq!(mode(&client(&first))?, 0o600);
    assert_eq!(fs::read(client(&first))?, b"");
    let fragment = fixture.fragments()?.remove(0);
    assert_eq!(mode(&fragment)?, 0o600);
    assert_eq!(
        fs::read_to_string(&fragment)?,
        format!("{GENERATED}Include \"{}\"\n", client(&first).display())
    );

    // The runtime's file is its own once it exists.
    write(&client(&first), b"Host written-by-the-runtime\n", 0o600)?;
    let before = [stamp(&config)?, stamp(&fragment)?, stamp(&client(&first))?];
    fixture.install(&first)?;
    let after = [stamp(&config)?, stamp(&fragment)?, stamp(&client(&first))?];
    assert_eq!(before, after);

    let ledger = fixture.ssh().join(FRAGMENTS).join(".namespaces.json");
    let old_ledger = fs::read(&ledger)?;
    let second = fixture.profile("second")?;
    fixture.install(&second)?;
    assert_eq!(stamp(&config)?, before[0]);
    assert_eq!(stamp(&fragment)?, before[1]);
    assert_eq!(fixture.fragments()?.len(), 2);
    let read_namespace = |state: &Path| -> Result<u64> {
        let contents = fs::read(state.join(cli::DIR_NAME).join(CLIENT_STATE))?;
        Ok(
            serde_json::from_slice::<serde_json::Value>(&contents)?["namespace"]
                .as_u64()
                .unwrap(),
        )
    };
    assert_eq!(read_namespace(&first)?, 1);
    assert_eq!(read_namespace(&second)?, 2);
    fs::remove_dir_all(&first)?;
    let third = fixture.profile("third")?;
    let current_ledger = fs::read(&ledger)?;
    fs::write(&ledger, &old_ledger)?;
    assert!(fixture.install(&third).is_err());
    assert!(!client(&third).exists());
    assert_eq!(fs::read(&ledger)?, old_ledger);
    fs::write(&ledger, current_ledger)?;
    fixture.install(&third)?;
    assert_eq!(read_namespace(&third)?, 3);
    assert_eq!(read_namespace(&second)?, 2);
    // No staged file is left behind.
    assert_eq!(fs::read_dir(fixture.ssh())?.count(), 2);
    Ok(())
}

#[test]
fn an_existing_configuration_keeps_its_contents_group_and_mode() -> Result<()> {
    let fixture = Fixture::new()?;
    let original = b"ServerAliveInterval 30\r\n\r\nHost a\r\n    User b";
    let config = fixture.existing("config", original, 0o640)?;
    let group = fs::metadata(&config)?.gid();
    fixture.install(&fixture.profile("state")?)?;
    let updated = fs::read(&config)?;
    assert_eq!(
        updated,
        [
            &b"# Added by massrelay install\r\nInclude massrelay.d/*.conf\r\n\r\n"[..],
            original
        ]
        .concat()
    );
    assert_eq!(mode(&config)?, 0o640);
    assert_eq!(fs::metadata(&config)?.gid(), group);
    Ok(())
}

#[test]
fn an_include_inside_a_host_block_does_not_count() -> Result<()> {
    let fixture = Fixture::new()?;
    let original = "Host a\n  Include massrelay.d/*.conf\n";
    let config = fixture.existing("config", original.as_bytes(), 0o600)?;
    let state = fixture.profile("state")?;
    fixture.install(&state)?;
    let updated = fs::read_to_string(&config)?;
    assert!(updated.starts_with("# Added by massrelay install\nInclude massrelay.d/*.conf\n"));
    assert!(updated.ends_with(original));
    fixture.install(&state)?;
    assert_eq!(fs::read_to_string(&config)?, updated);
    Ok(())
}

#[test]
fn a_linked_configuration_is_never_written() -> Result<()> {
    let fixture = Fixture::new()?;
    private_dir(&fixture.ssh())?;
    let target = fixture.root.join("dotfiles-config");
    write(&target, b"Host a\n", 0o600)?;
    symlink(&target, fixture.ssh().join("config"))?;
    let state = fixture.profile("state")?;
    let error = fixture.install(&state).unwrap_err();
    assert!(format!("{error:#}").contains("is a link"), "{error:#}");
    assert_eq!(fs::read(&target)?, b"Host a\n");
    assert!(fixture.fragments()?.is_empty());
    assert!(!client(&state).exists());

    // Once its owner adds the include there, nothing needs writing.
    write(&target, b"Include massrelay.d/*.conf\nHost a\n", 0o600)?;
    let before = stamp(&target)?;
    fixture.install(&state)?;
    assert_eq!(stamp(&target)?, before);
    assert!(fixture.ssh().join("config").is_symlink());
    assert!(client(&state).exists());
    Ok(())
}

#[test]
fn unsafe_files_and_directories_are_refused_unchanged() -> Result<()> {
    // Every account can write the configuration, it has a second name, or it is UTF-16.
    for (contents, permissions, second_name) in [
        (&b"Host a\n"[..], 0o666, false),
        (b"Host a\n", 0o600, true),
        (b"\xff\xfeH\0", 0o600, false),
    ] {
        let fixture = Fixture::new()?;
        let config = fixture.existing("config", contents, permissions)?;
        if second_name {
            fs::hard_link(&config, fixture.root.join("other-name"))?;
        }
        let before = stamp(&config)?;
        let state = fixture.profile("state")?;
        assert!(fixture.install(&state).is_err());
        assert_eq!(stamp(&config)?, before);
        assert!(!client(&state).exists());
    }

    // A linked or shared directory is not written into.
    let fixture = Fixture::new()?;
    let state = fixture.profile("state")?;
    let elsewhere = fixture.root.join("elsewhere");
    private_dir(&elsewhere)?;
    symlink(&elsewhere, fixture.ssh())?;
    assert!(fixture.install(&state).is_err());
    assert_eq!(fs::read_dir(&elsewhere)?.count(), 0);
    fs::remove_file(fixture.ssh())?;
    private_dir(&fixture.ssh())?;
    fs::set_permissions(fixture.ssh(), fs::Permissions::from_mode(0o707))?;
    assert!(fixture.install(&state).is_err());
    assert_eq!(fs::read_dir(fixture.ssh())?.count(), 0);

    // A home directory every account can rearrange.
    fs::set_permissions(fixture.ssh(), fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&fixture.home, fs::Permissions::from_mode(0o707))?;
    assert!(fixture.install(&state).is_err());
    assert_eq!(fs::read_dir(fixture.ssh())?.count(), 0);
    Ok(())
}

/// The default Linux layout under a umask of 0002: the profile is below
/// `~/.local/share/massrelay`, and every directory down to there is group-writable.
#[test]
#[cfg(target_os = "linux")]
fn group_writable_directories_pass_only_for_this_accounts_private_group() -> Result<()> {
    use crate::private_group::{
        PrivateGroups,
        tests::{grant_by_acl, private, shared},
    };

    let mut fixture = Fixture::new()?;
    let share = fixture.home.join(".local/share");
    let state = share.join("massrelay");
    let above = [fixture.home.join(".local"), share.clone(), state.clone()];
    for directory in &above {
        private_dir(directory)?;
    }
    let above: Vec<_> = above.into_iter().chain([fixture.home.clone()]).collect();
    for directory in &above {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o775))?;
    }
    let profile = state.join(cli::DIR_NAME);
    private_dir(&profile)?;
    let refused = |fixture: &Fixture| {
        let error = fixture.install(&state).err().context("not refused")?;
        assert!(
            format!("{error:#}").contains("writable by other accounts"),
            "{error:#}"
        );
        assert!(!client(&state).exists());
        anyhow::Ok(())
    };
    let chmod = |path: &Path, mode| fs::set_permissions(path, fs::Permissions::from_mode(mode));

    for groups in [shared, |_| None] {
        fixture.account.groups = PrivateGroups::fixture(groups);
        refused(&fixture)?;
        assert!(!fixture.ssh().exists());
    }
    fixture.account.groups = PrivateGroups::fixture(private);
    // Others may write nowhere, and the group may not write the private profile.
    for (path, unsafe_mode, safe_mode) in [(&share, 0o777, 0o775), (&profile, 0o770, 0o700)] {
        chmod(path, unsafe_mode)?;
        refused(&fixture)?;
        assert!(!fixture.ssh().exists());
        chmod(path, safe_mode)?;
    }

    fixture.install(&state)?;
    for directory in &above {
        assert_eq!(mode(directory)?, 0o775, "{}", directory.display());
    }
    assert_eq!(mode(&profile)?, 0o700);
    assert_eq!(mode(&client(&state))?, 0o600);
    fixture.uninstall(&state)?;
    assert!(fixture.fragments()?.is_empty());
    assert!(!client(&state).exists());

    // Nor `~/.ssh` and the files, whoever is in the group.
    chmod(&fixture.ssh(), 0o770)?;
    refused(&fixture)?;
    chmod(&fixture.ssh(), 0o700)?;
    write(&client(&state), b"", 0o660)?;
    assert!(fixture.install(&state).is_err());
    assert_eq!(mode(&client(&state))?, 0o660);
    fs::remove_file(client(&state))?;

    // An access list can let another account write through the group bits.
    grant_by_acl(&share)?;
    refused(&fixture)
}

#[test]
fn an_unsafe_client_file_stops_the_install_before_it_writes() -> Result<()> {
    let fixture = Fixture::new()?;
    let state = fixture.profile("state")?;
    let other = fixture.root.join("unrelated");
    write(&other, b"unrelated", 0o600)?;
    symlink(&other, client(&state))?;
    assert!(fixture.install(&state).is_err());
    fs::remove_file(client(&state))?;
    // OpenSSH would refuse every connection over this one.
    write(&client(&state), b"", 0o666)?;
    assert!(fixture.install(&state).is_err());
    assert!(!fixture.ssh().exists());
    assert_eq!(fs::read(&other)?, b"unrelated");
    assert_eq!(mode(&client(&state))?, 0o666);
    Ok(())
}

#[test]
fn only_a_generated_fragment_is_replaced() -> Result<()> {
    let fixture = Fixture::new()?;
    let state = fixture.profile("state")?;
    let config = fixture.install(&state)?;
    let fragment = fixture.fragments()?.remove(0);
    let wanted = fs::read(&fragment)?;

    write(&fragment, format!("{GENERATED}old\n").as_bytes(), 0o600)?;
    fixture.install(&state)?;
    assert_eq!(fs::read(&fragment)?, wanted);

    // Someone else's file at that name stops the install before the configuration changes.
    write(&fragment, b"Host mine\n", 0o600)?;
    write(&config, b"Host a\n", 0o600)?;
    assert!(fixture.install(&state).is_err());
    assert_eq!(fs::read(&fragment)?, b"Host mine\n");
    assert_eq!(fs::read(&config)?, b"Host a\n");

    fs::remove_file(&fragment)?;
    symlink(&config, &fragment)?;
    assert!(fixture.install(&state).is_err());
    assert_eq!(fs::read(&config)?, b"Host a\n");
    Ok(())
}

#[test]
fn a_path_openssh_would_reinterpret_is_refused_before_anything_changes() -> Result<()> {
    let fixture = Fixture::new()?;
    for name in ["100%", "$HOME", "a*b", "[profile]", "quo\"te"] {
        assert!(fixture.install(&fixture.profile(name)?).is_err(), "{name}");
    }
    assert!(!fixture.ssh().exists());

    // A state path that no longer resolves to itself was swapped after the service install.
    let state = fixture.profile("state")?;
    let link = fixture.root.join("link");
    symlink(&state, &link)?;
    assert!(fixture.install(&link).is_err());
    // So was a private directory that became a link.
    let private = state.join(cli::DIR_NAME);
    fs::remove_dir(&private)?;
    symlink(fixture.profile("other")?.join(cli::DIR_NAME), &private)?;
    assert!(fixture.install(&state).is_err());
    assert!(!fixture.ssh().exists());
    Ok(())
}

#[test]
fn a_file_changed_after_it_was_read_is_not_overwritten() -> Result<()> {
    let fixture = Fixture::new()?;
    let account = &fixture.account;
    let config = fixture.existing("config", b"Host a\n", 0o600)?;
    // A file that appeared after it was found missing.
    assert!(!account.create(&config, b"replacement")?);
    assert_eq!(fs::read(&config)?, b"Host a\n");

    // Edited in place.
    let found = account.read(&config)?.context("config")?;
    write(&config, b"Host b\n", 0o600)?;
    assert!(!account.replace(&config, &found, b"replacement")?);
    assert_eq!(fs::read(&config)?, b"Host b\n");

    // Swapped for another file with the same contents.
    let found = account.read(&config)?.context("config")?;
    let swapped = fixture.existing("swapped", b"Host b\n", 0o600)?;
    fs::rename(swapped, &config)?;
    assert!(!account.replace(&config, &found, b"replacement")?);
    assert_eq!(fs::read(&config)?, b"Host b\n");

    // A change during the update is read again and kept.
    let first = std::cell::Cell::new(true);
    update(account, &config, |found| {
        let mut contents = found.context("config")?.contents.clone();
        if first.replace(false) {
            write(&config, b"Host c\n", 0o600)?;
        }
        contents.extend_from_slice(b"added\n");
        Ok(Some(contents))
    })?;
    assert_eq!(fs::read(&config)?, b"Host c\nadded\n");
    assert_eq!(fs::read_dir(fixture.ssh())?.count(), 1);
    Ok(())
}

#[test]
fn the_last_uninstall_takes_back_the_include_and_keeps_everything_else() -> Result<()> {
    let fixture = Fixture::new()?;
    let original = b"ServerAliveInterval 30\r\n\r\nHost a\r\n    User b";
    let config = fixture.existing("config", original, 0o640)?;
    let own_key = fixture.existing("id_ed25519", b"the user's key", 0o600)?;
    let first = fixture.profile("first")?;
    let second = fixture.profile("second")?;
    let mut kept = vec![own_key];
    for state in [&first, &second] {
        fixture.install(state)?;
        let private = state.join(cli::DIR_NAME);
        for name in [CLIENT_STATE, "ssh-client-key-peer", "ssh-pin-peer"] {
            if name != CLIENT_STATE {
                write(&private.join(name), b"runtime", 0o600)?;
            }
            kept.push(private.join(name));
        }
    }
    kept.push(fixture.ledger());
    publish(&first, b"Host written-by-the-runtime\n")?;
    let stamps = |paths: &[PathBuf]| paths.iter().map(|path| stamp(path)).collect();
    let before: Result<Vec<_>> = stamps(&kept);
    let before = before?;
    let installed = stamp(&config)?;
    let [first_fragment, second_fragment] = [&first, &second].map(|state| {
        let (name, _) = fragment(&client(state)).unwrap();
        fixture.ssh().join(FRAGMENTS).join(name)
    });

    // Planning shows the removals and makes none.
    let shown = fixture.removal(&first)?.to_string();
    assert!(shown.contains(&format!("stopped: {}", client(&first).display())));
    assert!(shown.contains(&format!("remove: {}", first_fragment.display())));
    assert!(shown.contains(&format!("keep {}", config.display())));
    assert!(first_fragment.is_file() && client(&first).is_file());

    // Another profile still needs the include.
    fixture.uninstall(&first)?;
    assert!(!client(&first).exists() && !first_fragment.exists());
    assert!(!record(&first).exists());
    assert!(second_fragment.is_file() && client(&second).is_file());
    assert_eq!(stamp(&config)?, installed);

    fixture.uninstall(&second)?;
    assert!(fixture.fragments()?.is_empty());
    assert!(!client(&second).exists());
    assert_eq!(fs::read(&config)?, original);
    assert_eq!(mode(&config)?, 0o640);
    let after: Result<Vec<_>> = stamps(&kept);
    assert_eq!(after?, before);

    // Again finds nothing to do and writes nothing.
    let removed = stamp(&config)?;
    for state in [&first, &second] {
        let again = fixture.removal(state)?;
        assert!(again.to_string().starts_with("nothing to remove"));
        again.apply()?;
    }
    assert_eq!(stamp(&config)?, removed);

    // A later install gives each profile its namespace back, so no alias changes hands.
    let ledger = fs::read(fixture.ledger())?;
    fixture.install(&second)?;
    fixture.install(&first)?;
    assert_eq!(fs::read(fixture.ledger())?, ledger);
    assert_eq!(fixture.fragments()?.len(), 2);
    Ok(())
}

#[test]
fn an_uninstall_that_stopped_partway_can_be_run_again() -> Result<()> {
    let fixture = Fixture::new()?;
    let state = fixture.profile("state")?;
    let config = fixture.install(&state)?;
    let fragment = fixture.fragments()?.remove(0);
    let generated = fs::read(&fragment)?;
    let installed = fs::read(&config)?;

    // A file edited after it was shown stops the removal there.
    let planned = fixture.removal(&state)?;
    let edited = [&generated[..], b"Host mine\n"].concat();
    write(&fragment, &edited, 0o600)?;
    assert!(planned.apply().is_err());
    assert!(client(&state).exists());
    assert_eq!(fs::read(&fragment)?, edited);
    assert_eq!(fs::read(&config)?, installed);

    write(&fragment, &generated, 0o600)?;
    fixture.uninstall(&state)?;
    assert!(!client(&state).exists() && !fragment.exists());
    assert_eq!(fs::read(&config)?, b"");

    // Only the include is left, as after a failure to rewrite the configuration.
    write(&config, &installed, 0o600)?;
    fixture.uninstall(&state)?;
    assert_eq!(fs::read(&config)?, b"");
    Ok(())
}

#[test]
fn an_uninstall_removes_only_what_it_was_shown_to_remove() -> Result<()> {
    let fixture = Fixture::new()?;
    let first = fixture.profile("first")?;
    let config = fixture.install(&first)?;
    let installed = fs::read(&config)?;
    // Another profile is installed between the plan and its application.
    let planned = fixture.removal(&first)?;
    let second = fixture.profile("second")?;
    fixture.install(&second)?;
    planned.apply()?;
    assert_eq!(fs::read(&config)?, installed);
    assert_eq!(fixture.fragments()?.len(), 1);
    assert!(client(&second).exists());
    Ok(())
}

#[test]
fn an_uninstall_keeps_what_it_cannot_show_the_install_made() -> Result<()> {
    // An edited fragment stays, and so does the include that reads it.
    let fixture = Fixture::new()?;
    let state = fixture.profile("state")?;
    let config = fixture.install(&state)?;
    let fragment = fixture.fragments()?.remove(0);
    let edited = [&fs::read(&fragment)?[..], b"Host mine\n"].concat();
    write(&fragment, &edited, 0o600)?;
    let installed = fs::read(&config)?;
    fixture.uninstall(&state)?;
    assert_eq!(fs::read(&fragment)?, edited);
    assert_eq!(fs::read(&config)?, installed);
    assert!(client(&state).exists());

    // The user's own file among the fragments keeps the include too.
    fs::remove_file(&fragment)?;
    let own = fixture.ssh().join(FRAGMENTS).join("mine.conf");
    write(&own, b"Host mine\n", 0o600)?;
    fixture.uninstall(&state)?;
    assert_eq!(fs::read(&config)?, installed);
    assert_eq!(fs::read(&own)?, b"Host mine\n");
    fs::remove_file(&own)?;

    // A configuration that has become a link is left, and so is what it points at.
    let target = fixture.root.join("dotfiles-config");
    fs::rename(&config, &target)?;
    symlink(&target, &config)?;
    let removal = fixture.removal(&state)?;
    assert!(removal.to_string().contains("is a link"), "{removal}");
    removal.apply()?;
    assert!(config.is_symlink());
    assert_eq!(fs::read(&target)?, installed);

    // An include the user wrote is theirs.
    fs::remove_file(&config)?;
    write(&config, b"Include massrelay.d/*.conf\n", 0o600)?;
    fixture.uninstall(&state)?;
    assert_eq!(fs::read(&config)?, b"Include massrelay.d/*.conf\n");

    // A linked fragment directory shows nothing about whose the configuration is, and does
    // not stop the uninstall.
    let moved = fixture.root.join("moved-fragments");
    fs::rename(fixture.ssh().join(FRAGMENTS), &moved)?;
    symlink(&moved, fixture.ssh().join(FRAGMENTS))?;
    fixture.uninstall(&state)?;
    assert!(client(&state).exists());
    fs::remove_file(client(&state))?;
    fs::remove_file(fixture.ssh().join(FRAGMENTS))?;
    fs::rename(&moved, fixture.ssh().join(FRAGMENTS))?;

    // Links in place of the profile's own files are not removed or followed.
    let other = fixture.root.join("unrelated");
    write(&other, b"unrelated", 0o600)?;
    symlink(&other, client(&state))?;
    symlink(&other, &fragment)?;
    fixture.uninstall(&state)?;
    assert!(client(&state).is_symlink() && fragment.is_symlink());
    assert_eq!(fs::read(&other)?, b"unrelated");
    Ok(())
}

#[test]
fn an_uninstall_removes_a_configuration_only_while_massrelay_wrote_all_of_it() -> Result<()> {
    const WRITTEN: &[u8] = b"# Written by MassRelay.\n\nHost massrelay-a mr-a\n    User b\n";
    let edited = [WRITTEN, b"\nHost mine\n    User me\n"].concat();
    // An installed profile whose runtime has written its configuration.
    let published = || -> Result<(Fixture, PathBuf, PathBuf)> {
        let fixture = Fixture::new()?;
        let state = fixture.profile("state")?;
        fixture.install(&state)?;
        publish(&state, WRITTEN)?;
        let fragment = fixture.fragments()?.remove(0);
        Ok((fixture, state, fragment))
    };
    let kept = |removal: &Removal, state: &Path| {
        let shown = removal.to_string();
        shown.contains(&format!("keep {}: ", client(state).display()))
    };

    let (fixture, state, fragment) = published()?;
    let removal = fixture.removal(&state)?;
    assert!(!kept(&removal, &state), "{removal}");
    removal.apply()?;
    assert!(!client(&state).exists() && !record(&state).exists() && !fragment.exists());

    // A stanza added by hand keeps the file, while its aliases go with the fragment.
    let (fixture, state, fragment) = published()?;
    write(&client(&state), &edited, 0o600)?;
    let removal = fixture.removal(&state)?;
    assert!(kept(&removal, &state), "{removal}");
    removal.apply()?;
    assert!(!fragment.exists());
    assert_eq!(fs::read(fixture.ssh().join("config"))?, b"");
    // Nothing shows whose it is any more, so a second run keeps it too.
    fixture.uninstall(&state)?;
    assert_eq!(fs::read(client(&state))?, edited);
    assert_eq!(fs::read(record(&state))?, digest(WRITTEN));

    // Edited after it was shown to be removed.
    let (fixture, state, fragment) = published()?;
    let removal = fixture.removal(&state)?;
    write(&client(&state), &edited, 0o600)?;
    removal.apply()?;
    assert_eq!(fs::read(client(&state))?, edited);
    assert!(record(&state).exists() && !fragment.exists());

    // Seen between the runtime's two writes, and complete once it has stopped.
    let (fixture, state, _) = published()?;
    write(&client(&state), &edited, 0o600)?;
    let removal = fixture.removal(&state)?;
    publish(&state, &edited)?;
    removal.apply()?;
    assert!(!client(&state).exists() && !record(&state).exists());

    // Only a private record of exactly these bytes counts, and any other is left alone.
    let good = digest(WRITTEN);
    let upper = good.to_ascii_uppercase();
    let longer = [&good[..], b"\n"].concat();
    for (bytes, permissions) in [
        (&digest(&edited)[..], 0o600),
        (&upper, 0o600),
        (&good[..64], 0o600),
        (&longer, 0o600),
        (&good, 0o640),
    ] {
        let (fixture, state, fragment) = published()?;
        write(&record(&state), bytes, permissions)?;
        fixture.uninstall(&state)?;
        assert_eq!(fs::read(client(&state))?, WRITTEN);
        assert_eq!(fs::read(record(&state))?, bytes);
        assert!(!fragment.exists());
    }
    for link in [false, true] {
        let (fixture, state, _) = published()?;
        let elsewhere = fixture.root.join("record");
        fs::rename(record(&state), &elsewhere)?;
        if link {
            symlink(&elsewhere, record(&state))?;
        }
        fixture.uninstall(&state)?;
        assert_eq!(fs::read(client(&state))?, WRITTEN);
        assert_eq!(record(&state).is_symlink(), link);
        assert_eq!(fs::read(&elsewhere)?, good);
    }

    // A matching record is not enough without the fragment the install wrote.
    for replacement in [None, Some(&b"Host mine\n"[..])] {
        let (fixture, state, fragment) = published()?;
        match replacement {
            Some(contents) => write(&fragment, contents, 0o600)?,
            None => fs::remove_file(&fragment)?,
        }
        fixture.uninstall(&state)?;
        assert_eq!(fs::read(client(&state))?, WRITTEN);
        assert_eq!(fs::read(record(&state))?, good);
    }

    // An empty configuration holds nothing to lose. A record of other bytes stays.
    for recorded in [&b""[..], WRITTEN] {
        let (fixture, state, _) = published()?;
        write(&client(&state), b"", 0o600)?;
        write(&record(&state), &digest(recorded), 0o600)?;
        fixture.uninstall(&state)?;
        assert!(!client(&state).exists());
        assert_eq!(record(&state).exists(), !recorded.is_empty());
    }
    Ok(())
}

#[test]
fn an_uninstall_with_nothing_installed_creates_nothing() -> Result<()> {
    let fixture = Fixture::new()?;
    let state = fixture.profile("state")?;
    fixture.uninstall(&state)?;
    assert!(!fixture.ssh().exists());
    assert_eq!(fs::read_dir(state.join(cli::DIR_NAME))?.count(), 0);
    Ok(())
}

/// The system's OpenSSH reads the result: the fragments apply to every host, and no block in
/// them or in the user's configuration spills into another.
#[test]
#[ignore = "runs the system OpenSSH client"]
fn openssh_reads_each_profile_without_rescoping_the_users_settings() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.existing(
        "config",
        b"ServerAliveInterval 30\n\nHost plain\n    Port 2200\n\nHost *\n    User fallback\n    Port 22\n    ForwardAgent yes\n",
        0o600,
    )?;
    let first = fixture.profile("Application Support")?;
    let second = fixture.profile("it's #2")?;
    let removed = fixture.profile("removed")?;
    for state in [&first, &second, &removed] {
        fixture.install(state)?;
    }
    for (state, alias, port) in [(&first, "one", 2201), (&second, "two", 2202)] {
        write(
            &client(state),
            format!(
                "Host massrelay-{alias}\n    User {alias}\n    Port {port}\n    ForwardAgent no\n"
            )
            .as_bytes(),
            0o600,
        )?;
    }
    // A removed profile leaves a fragment that includes nothing.
    fs::remove_dir_all(&removed)?;

    // OpenSSH takes the `~/.ssh` a relative include stands for from `HOME`, even with `-F`,
    // so this reads the disposable home and nothing of the real account's.
    let config = fixture.ssh().join("config");
    let settings = |host: &str| -> Result<Vec<String>> {
        let output = Command::new("ssh")
            .env("HOME", &fixture.home)
            .arg("-G")
            .arg("-F")
            .arg(&config)
            .arg(host)
            .output()?;
        ensure!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let all = String::from_utf8(output.stdout)?;
        Ok(all
            .lines()
            .filter(|line| {
                ["user ", "port ", "forwardagent ", "serveraliveinterval "]
                    .iter()
                    .any(|key| line.starts_with(key))
            })
            .map(str::to_owned)
            .collect())
    };
    let expected = |user: &str, port: u16, forward: &str| {
        let mut lines = vec![
            format!("user {user}"),
            format!("port {port}"),
            format!("forwardagent {forward}"),
            "serveraliveinterval 30".to_owned(),
        ];
        lines.sort();
        lines
    };
    for (host, user, port, forward) in [
        ("massrelay-one", "one", 2201, "no"),
        ("massrelay-two", "two", 2202, "no"),
        ("plain", "fallback", 2200, "yes"),
        ("other", "fallback", 22, "yes"),
    ] {
        let mut seen = settings(host)?;
        seen.sort();
        assert_eq!(seen, expected(user, port, forward), "{host}");
    }

    // After an uninstall of each, the user's own hosts connect as they did before.
    for state in [&first, &second, &removed] {
        fixture.uninstall(state)?;
    }
    for (host, user, port, forward) in [
        ("massrelay-one", "fallback", 22, "yes"),
        ("plain", "fallback", 2200, "yes"),
    ] {
        let mut seen = settings(host)?;
        seen.sort();
        assert_eq!(seen, expected(user, port, forward), "{host}");
    }
    Ok(())
}
