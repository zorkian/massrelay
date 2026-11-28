//! Planning, verifying and applying the change to the system SSH server, on every platform.
//! [`System`] is what differs between them.
//!
//! A plan only reads: it creates no file, asks for no rights, and asks the server about its
//! settings only where that needs neither. Applying takes administrator rights and then the
//! machine's lock, so that one change, its rollback included, ends before another account's
//! or profile's begins. It also holds the profile's setup lock, so that an install and a
//! removal of one profile never overlap, also where the removal needs no rights. An install
//! holds the lock the runtime authorizes tunnels under only while it reads or changes the
//! key file or the description, never while it waits for an administrator command or a
//! reload; a removal holds it throughout. Nothing replaces `sshd_config` before the server
//! itself, reading a staged copy, has shown that the only difference is the added key file
//! for this account's loopback logins. A failure after the replacement puts the previous
//! file back, and a reload that may not have happened is recorded for the next run.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Component, Path, PathBuf},
    rc::Rc,
    thread,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};

use super::{
    AUTHORIZED_KEYS, AUTHORIZED_KEYS_LOCK, Refused, SERVER_FILE, SETUP_RECORD, Server, Unavailable,
    config::{self, Block, Token},
    ed25519, fingerprint, lock,
    owned::{self, Disposition, KeyFile, Record},
    present, read_description, remove, write_private,
};
use crate::update::say;

const LOOPBACK: &str = "127.0.0.1";
/// An address reserved for documentation, standing in for logins from elsewhere.
const REMOTE: (&str, &str) = ("192.0.2.1", "192.0.2.2");
/// OpenSSH's own bound on nested includes.
const INCLUDE_DEPTH: usize = 16;
/// Held by an install or a removal of a profile's setup, from start to end. The runtime does
/// not take it.
pub(super) const SETUP_LOCK: &str = "ssh-setup.lock";
/// How long a reloaded server has to answer again.
const ANSWER_ATTEMPTS: usize = 40;
const DEFAULT_KEY_FILES: [&str; 2] = [".ssh/authorized_keys", ".ssh/authorized_keys2"];
const CHANGED: &str = "the SSH server changed after the changes were shown; nothing was \
                       changed. Run the command again";

/// With whose rights a system file is read or the server is asked about a configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Access {
    /// This process's own, which is all a plan uses.
    User,
    /// An administrator's, after [`System::authorize`].
    Administrator,
}

/// A read this process may not make itself.
#[derive(Debug)]
#[cfg_attr(windows, allow(dead_code))]
pub(super) struct NeedsAdministrator(pub PathBuf);

impl fmt::Display for NeedsAdministrator {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "only an administrator can read {}", self.0.display())
    }
}

impl std::error::Error for NeedsAdministrator {}

/// How a running server takes up a changed configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Reload {
    /// The named service has to be told.
    Service(String),
    /// Each new connection reads the file.
    #[cfg_attr(windows, allow(dead_code))]
    NextConnection,
}

/// A held lock, released when dropped.
pub(super) type Held = Box<dyn Send>;

/// A copy of a configuration the server can read. Dropping it removes what is left.
pub(super) struct Staged {
    pub path: PathBuf,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}

impl Staged {
    pub(super) fn new(path: PathBuf, cleanup: impl FnOnce() + Send + 'static) -> Self {
        Self {
            path,
            cleanup: Some(Box::new(cleanup)),
        }
    }

    /// The copy now is the configuration, so nothing is left to remove.
    pub(super) fn consumed(mut self) {
        self.cleanup = None;
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

/// The platform's system SSH server and the rights to change it.
pub(super) trait System: Send {
    /// The account that is installing, which tunnel logins use.
    fn user(&self) -> &str;
    /// An account other than [`Self::user`] whose settings must not change, if the server
    /// can be asked about one.
    fn other_user(&self) -> Option<&str>;
    /// The server's configuration file.
    fn config(&self) -> &Path;
    /// The canonical form of a directory.
    fn canonical(&self, path: &Path) -> Result<PathBuf>;
    /// Fails with [`Unavailable`] without the system's server program, which every change
    /// is checked with.
    fn installed(&self) -> Result<()>;
    /// Refuses a key file the server would not accept or others could read or change.
    fn check_key_file(&self, path: &Path) -> Result<()>;
    /// A key file's path as an `AuthorizedKeysFile` argument.
    fn key_file_entry(&self, path: &Path) -> Result<String>;
    /// The server's configuration, refusing one that should not be replaced.
    fn read_config(&self, access: Access) -> Result<Option<Vec<u8>>>;
    /// A file the server reads. Fails with [`NeedsAdministrator`] when it may not be read.
    fn read(&self, path: &Path, access: Access) -> Result<Option<Vec<u8>>>;
    /// The names in a directory, none if it is absent.
    fn list(&self, directory: &Path, access: Access) -> Result<Vec<String>>;
    /// A path as the server's configuration or output writes it.
    fn path(&self, written: &str) -> PathBuf;
    /// Other spellings under which the server may print a configured value.
    fn spellings(&self, value: &str) -> Vec<String>;
    /// Run the system server in a test mode (`-t` or `-T`) and return its output. This
    /// writes nothing; with [`Access::User`] it also ends within a bounded time.
    fn sshd(&self, arguments: &[String], access: Access) -> Result<String>;
    /// Ask for administrator rights, failing without changing anything.
    fn authorize(&self) -> Result<()>;
    /// Take the machine's lock on changes to the server's configuration, which every account
    /// and profile takes. Needs [`Self::authorize`].
    fn exclusive(&self) -> Result<Held>;
    /// A copy of a configuration beside the real one, where only administrators can write.
    /// Needs [`Self::authorize`].
    fn stage(&self, contents: &[u8]) -> Result<Staged>;
    /// Atomically put `staged` in place of the configuration, if that still is `expected`.
    fn replace(&self, staged: Staged, expected: &[u8]) -> Result<()>;
    /// Fails with [`Unavailable`] if the system server evidently is not running.
    fn running(&self) -> Result<()>;
    /// How the running system server reloads. Refuses one started with another
    /// configuration.
    fn reload_method(&self, access: Access) -> Result<Reload>;
    fn reload(&self, reload: &Reload) -> Result<()>;
    /// The Ed25519 host key of whatever answers SSH on `127.0.0.1` at `port`.
    fn listener_key(&self, port: u16) -> Result<Option<String>>;
    /// What the user can do to make an absent server available.
    fn enable_hint(&self) -> &'static str;
    /// Which administrator rights applying uses.
    fn rights(&self) -> &'static str;
    fn describe(&self, reload: &Reload) -> String;
}

/// A connection the server is asked about.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Connection {
    user: String,
    host: &'static str,
    address: &'static str,
    local_address: &'static str,
    local_port: u16,
}

impl Connection {
    fn argument(&self) -> String {
        format!(
            "user={},host={},addr={},laddr={},lport={}",
            self.user, self.host, self.address, self.local_address, self.local_port
        )
    }

    /// The logins the block covers, as the server may name their host.
    fn covered(user: &str, port: u16) -> [Self; 2] {
        [LOOPBACK, "localhost"].map(|host| Self {
            user: user.to_owned(),
            host,
            address: LOOPBACK,
            local_address: LOOPBACK,
            local_port: port,
        })
    }

    /// Logins whose settings must stay exactly as they are.
    fn untouched(user: &str, other: Option<&str>, port: u16) -> Vec<Self> {
        let [loopback, _] = Self::covered(user, port);
        let other = other.map(|other| Self {
            user: other.to_owned(),
            ..loopback.clone()
        });
        let mut untouched = vec![
            Self {
                host: REMOTE.0,
                address: REMOTE.0,
                local_address: REMOTE.1,
                ..loopback.clone()
            },
            Self {
                host: "::1",
                address: "::1",
                local_address: "::1",
                ..loopback.clone()
            },
            Self {
                local_port: if port == u16::MAX { 1 } else { port + 1 },
                ..loopback
            },
        ];
        untouched.extend(other);
        untouched
    }
}

/// The server's effective settings for one connection.
fn effective(
    system: &dyn System,
    config: &Path,
    connection: &Connection,
    access: Access,
) -> Result<String> {
    let path = config
        .to_str()
        .context("the configuration's path is not Unicode")?;
    let arguments = ["-T", "-f", path, "-C", &connection.argument()].map(str::to_owned);
    Ok(config::effective_output(&system.sshd(&arguments, access)?))
}

/// What the server must say about a staged configuration.
type Expected = Vec<(Connection, String)>;

fn verify(system: &dyn System, staged: &Staged, expected: &Expected) -> Result<()> {
    let path = staged
        .path
        .to_str()
        .context("the configuration's path is not Unicode")?;
    system
        .sshd(
            &["-t".to_owned(), "-f".to_owned(), path.to_owned()],
            Access::Administrator,
        )
        .context("the SSH server rejected the new configuration; nothing was changed")?;
    for (connection, expected) in expected {
        let found = effective(system, &staged.path, connection, Access::Administrator)?;
        if &found == expected {
            continue;
        }
        let about = connection.argument();
        let differs = expected
            .lines()
            .zip(found.lines())
            .find(|(expected, found)| expected != found)
            .map(|(expected, found)| format!("expected '{expected}', found '{found}'"))
            .unwrap_or_else(|| "the number of settings differs".to_owned());
        bail!(
            "the new configuration would not have exactly the intended effect for {about}: \
             {differs}. A Match block read earlier may take precedence, for example in a file \
             included before the first Match line of {}. Nothing was changed",
            system.config().display()
        );
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Change {
    original: Vec<u8>,
    candidate: Vec<u8>,
}

/// The configuration, first, and every file it includes, each path once.
fn configuration(system: &dyn System, main: &[u8], access: Access) -> Result<Vec<Vec<u8>>> {
    let mut files = Vec::new();
    // What each included path holds, and the deepest nesting it is followed at. It is
    // followed again only through a longer chain, which holds every chain to the server's
    // bound and so ends include cycles, however many files there are.
    let mut known = BTreeMap::<PathBuf, (Option<Rc<[u8]>>, usize)>::new();
    let mut listed = BTreeSet::new();
    let mut pending = vec![(None, Rc::<[u8]>::from(main), 0)];
    while let Some((path, contents, depth)) = pending.pop() {
        for arguments in config::arguments(&contents, "include")? {
            for pattern in arguments {
                for path in included(system, &pattern.value, access)? {
                    let contents = match known.get(&path) {
                        Some((_, followed)) if *followed > depth => continue,
                        Some((contents, _)) => contents.clone(),
                        None => system.read(&path, access)?.map(Rc::from),
                    };
                    known.insert(path.clone(), (contents.clone(), depth + 1));
                    if let Some(contents) = contents {
                        ensure!(
                            depth < INCLUDE_DEPTH,
                            "the SSH server configuration nests includes too deeply"
                        );
                        pending.push((Some(path), contents, depth + 1));
                    }
                }
            }
        }
        if listed.insert(path) {
            files.push(contents.to_vec());
        }
    }
    Ok(files)
}

/// The files an `Include` argument names, relative to the configuration's directory.
fn included(system: &dyn System, pattern: &str, access: Access) -> Result<Vec<PathBuf>> {
    // A backslash escapes a pattern character, except where it separates directories.
    ensure!(
        !pattern.starts_with('~')
            && !pattern.contains('[')
            && (cfg!(windows) || !pattern.contains('\\')),
        "MassRelay cannot follow the SSH server's 'Include {pattern}'"
    );
    let path = system.path(pattern);
    let path = if path.has_root() {
        path
    } else {
        system
            .config()
            .parent()
            .context("the configuration has no directory")?
            .join(path)
    };
    let mut found = vec![PathBuf::new()];
    for component in path.components() {
        let wild = match component {
            Component::Normal(name) => name.to_str().filter(|name| name.contains(['*', '?'])),
            _ => None,
        };
        let Some(wild) = wild else {
            found.iter_mut().for_each(|path| path.push(component));
            continue;
        };
        let mut next = Vec::new();
        for directory in found {
            let mut names = system.list(&directory, access)?;
            names.sort();
            next.extend(
                names
                    .into_iter()
                    .filter(|name| config::matches(wild, name))
                    .map(|name| directory.join(name)),
            );
        }
        found = next;
    }
    Ok(found)
}

/// The configured arguments behind a `sshd -T` key file list, which prints them without
/// quotes, and each as it is printed there. Only a list that the default or some directive
/// accounts for in exactly one way is used.
fn key_files(system: &dyn System, files: &[Vec<u8>], shown: &str) -> Result<Vec<(Token, String)>> {
    let mut candidates = vec![DEFAULT_KEY_FILES.map(Token::new).to_vec()];
    for file in files {
        candidates.extend(config::arguments(file, "authorizedkeysfile")?);
    }
    let mut found: Vec<Vec<(Token, String)>> = Vec::new();
    for tokens in candidates {
        let spellings: Vec<_> = tokens
            .iter()
            .map(|token| system.spellings(&token.value))
            .collect();
        let count = spellings.first().map_or(0, Vec::len);
        let Some(which) = (0..count).find(|&which| {
            let printed: Vec<_> = spellings.iter().map(|each| each[which].as_str()).collect();
            printed.join(" ") == shown
        }) else {
            continue;
        };
        let list: Vec<_> = tokens
            .into_iter()
            .zip(spellings)
            .map(|(token, each)| (token, each[which].clone()))
            .collect();
        let values = |list: &[(Token, String)]| -> Vec<String> {
            list.iter().map(|(token, _)| token.value.clone()).collect()
        };
        if found.iter().all(|other| values(other) != values(&list)) {
            found.push(list);
        }
    }
    ensure!(
        found.len() == 1,
        "MassRelay cannot tell exactly which key files '{shown}' names, so it cannot keep \
         them. Write AuthorizedKeysFile with plain paths, without '~'"
    );
    found.pop().context("no key files")
}

/// What the account's loopback logins require of the server's settings.
fn check_policy(settings: &str) -> Result<()> {
    let has = |list: &str, wanted: &str| list.split(',').any(|item| item == wanted);
    ensure!(
        config::setting(settings, "pubkeyauthentication") == Some("yes"),
        "the SSH server has public key authentication off for logins from this device \
         (PubkeyAuthentication). MassRelay does not change that"
    );
    ensure!(
        config::setting(settings, "authenticationmethods").is_none_or(|methods| {
            methods
                .split_ascii_whitespace()
                .any(|list| list == "any" || list == "publickey")
        }),
        "the SSH server requires more than a public key for logins from this device \
         (AuthenticationMethods). MassRelay does not change that"
    );
    ensure!(
        config::setting(settings, "pubkeyacceptedalgorithms")
            .or_else(|| config::setting(settings, "pubkeyacceptedkeytypes"))
            .is_some_and(|list| has(list, "ssh-ed25519")),
        "the SSH server does not accept Ed25519 user keys (PubkeyAcceptedAlgorithms)"
    );
    ensure!(
        config::setting(settings, "hostkeyalgorithms").is_none_or(|list| has(list, "ssh-ed25519")),
        "the SSH server does not offer its Ed25519 host key (HostKeyAlgorithms)"
    );
    Ok(())
}

/// Host policy that stays in force and may still refuse a login.
fn restrictions(settings: &str) -> Vec<String> {
    [
        "allowusers",
        "allowgroups",
        "denyusers",
        "denygroups",
        "forcecommand",
        "chrootdirectory",
    ]
    .into_iter()
    .flat_map(|key| config::settings(settings, key).map(move |value| (key, value)))
    .filter(|(_, value)| *value != "none")
    .map(|(key, value)| format!("{key} {value}"))
    .collect()
}

/// This profile's block in the configuration, which must be unedited.
fn own_block(system: &dyn System, configuration: &[u8], entry: &str) -> Result<Option<Block>> {
    let id = config::id(entry);
    let own = config::blocks(configuration)?
        .into_iter()
        .find(|block| block.id == id);
    ensure!(
        own.as_ref().is_none_or(|block| block.managed.is_some()),
        "MassRelay's block {id} in {} was edited. Remove it, from its BEGIN line through its \
         END line, then run 'massrelay install' again",
        system.config().display()
    );
    Ok(own)
}

/// Whether a configured argument could be the key file: that text, or any path ending in its
/// name, which may be relative to a home directory or written with tokens.
fn names_key_file(argument: &str, entry: &str) -> bool {
    let name = argument.rsplit(['/', '\\']).next().unwrap_or(argument);
    argument == entry || name.eq_ignore_ascii_case(AUTHORIZED_KEYS)
}

/// Refuse a configuration that already names a MassRelay key file anywhere setup did not put
/// it. Asking the server about a few connections cannot prove which accounts and logins such
/// a line gives the file to, so that is not tried. `files` is the configuration and then what
/// it includes.
fn check_references(files: &[Vec<u8>], user: &str, entry: &str) -> Result<()> {
    let Some((main, included)) = files.split_first() else {
        return Ok(());
    };
    let mut owned = Vec::new();
    // An edited block is not MassRelay's, so its lines are looked at like any other.
    for block in config::blocks(main)? {
        let Some(managed) = block.managed else {
            continue;
        };
        ensure!(
            managed.user == user || !managed.keys.iter().any(|key| key.value == entry),
            "another account's MassRelay block already names {entry}. Remove it from that \
             block, then run 'massrelay install' again"
        );
        owned.push((block.span, String::new()));
    }
    let outside = config::splice(main, &owned);
    for file in std::iter::once(&outside).chain(included) {
        for argument in config::arguments(file, "authorizedkeysfile")?
            .into_iter()
            .flatten()
        {
            ensure!(
                !names_key_file(&argument.value, entry),
                "the SSH server's configuration already names a MassRelay key file ('{}') \
                 outside this account's MassRelay blocks. Remove that line, then run \
                 'massrelay install' again",
                argument.value
            );
        }
    }
    Ok(())
}

/// The port in a `ListenAddress` argument, if it names one.
fn address_port(address: &str) -> Option<u16> {
    if let Some(bracketed) = address.strip_prefix('[') {
        return bracketed.split_once("]:")?.1.parse().ok();
    }
    // More than one colon is a bare IPv6 address.
    address.split_once(':')?.1.parse().ok()
}

/// The installed server's answer on `127.0.0.1`: its port, and the Ed25519 host key that
/// the configuration's host key files, or the default one, account for.
fn listener(system: &dyn System, files: &[Vec<u8>]) -> Result<(u16, PathBuf, String)> {
    let directory = system
        .config()
        .parent()
        .context("the configuration has no directory")?;
    let (mut ports, mut paths) = (Vec::new(), Vec::new());
    for file in files {
        let first = |keyword| -> Result<Vec<String>> {
            Ok(config::arguments(file, keyword)?
                .into_iter()
                .filter_map(|arguments| arguments.into_iter().next())
                .map(|argument| argument.value)
                .collect())
        };
        ports.extend(
            first("port")?
                .iter()
                .filter_map(|port| port.parse::<u16>().ok()),
        );
        ports.extend(
            first("listenaddress")?
                .iter()
                .filter_map(|address| address_port(address)),
        );
        paths.extend(first("hostkey")?.iter().map(|path| {
            let path = system.path(path);
            if path.has_root() {
                path
            } else {
                directory.join(path)
            }
        }));
    }
    ports.push(22u16);
    if paths.is_empty() {
        paths.push(directory.join("ssh_host_ed25519_key"));
    }
    let mut installed = Vec::new();
    for path in paths {
        let mut public = path.into_os_string();
        public.push(".pub");
        let public = PathBuf::from(public);
        let key = system
            .read(&public, Access::User)
            .ok()
            .flatten()
            .and_then(|contents| ed25519(std::str::from_utf8(&contents).ok()?));
        if let Some(key) = key {
            installed.push((public, key));
        }
    }
    ensure!(
        !installed.is_empty(),
        "the SSH server has no readable Ed25519 host public key. An administrator can create \
         missing host keys with 'ssh-keygen -A', then restart the server"
    );
    let mut seen = BTreeSet::new();
    let mut other = None;
    for port in ports.into_iter().filter(|port| seen.insert(*port)) {
        let Some(offered) = system.listener_key(port)? else {
            continue;
        };
        match installed.iter().find(|(_, key)| *key == offered) {
            Some((path, key)) => return Ok((port, path.clone(), key.clone())),
            None => other = Some(port),
        }
    }
    if let Some(port) = other {
        bail!(
            "the SSH server answering on 127.0.0.1:{port} does not use this system's host key; \
             MassRelay only sets up the system's own server"
        );
    }
    Err(Unavailable(format!(
        "no SSH server answers on 127.0.0.1 at the configured port. {} MassRelay does not \
         change listeners or firewalls",
        system.enable_hint()
    ))
    .into())
}

/// What a plan and an apply both establish by reading only.
struct Survey {
    /// The configuration, then every file it includes.
    files: Vec<Vec<u8>>,
    port: u16,
    host_key: String,
    host_key_path: PathBuf,
    reload: Reload,
}

impl Survey {
    fn configuration(&self) -> &[u8] {
        self.files.first().map_or(&[], Vec::as_slice)
    }

    fn same_as(&self, other: &Self) -> bool {
        (&self.files, self.port, &self.host_key, &self.reload)
            == (&other.files, other.port, &other.host_key, &other.reload)
    }
}

fn survey(system: &dyn System, profile: &Path, access: Access) -> Result<Survey> {
    system.installed()?;
    let record = Record::load(profile, system.user())?;
    {
        // An apply reads the key file while the runtime may write it; a plan creates no lock.
        let _keys = match access {
            Access::Administrator => Some(lock(profile, AUTHORIZED_KEYS_LOCK)?),
            Access::User => None,
        };
        owned::check_adoptable(system, profile, &record)?;
    }
    let entry = system.key_file_entry(&profile.join(AUTHORIZED_KEYS))?;
    let original = system.read_config(access)?.ok_or_else(|| {
        anyhow!(Unavailable(format!(
            "{} does not exist. {}",
            system.config().display(),
            system.enable_hint()
        )))
    })?;
    let files = configuration(system, &original, access)?;
    own_block(system, &original, &entry)?;
    check_references(&files, system.user(), &entry)?;
    let (port, host_key_path, host_key) = listener(system, &files)?;
    let reload = system.reload_method(access)?;
    Ok(Survey {
        files,
        port,
        host_key,
        host_key_path,
        reload,
    })
}

/// The one key file list the covered logins have, from the server's settings for them.
fn covered_key_files(settings: &[String], files: &[Vec<u8>]) -> Result<String> {
    let shown: Vec<_> = settings
        .iter()
        .map(|settings| config::setting(settings, "authorizedkeysfile"))
        .collect();
    let value = shown
        .first()
        .copied()
        .flatten()
        .context("the SSH server did not report its AuthorizedKeysFile")?;
    ensure!(
        shown.iter().all(|other| *other == Some(value))
            && !(settings
                .iter()
                .any(|settings| config::setting(settings, "usedns") == Some("yes"))
                && matches_by_host(files)?),
        "the key files for logins from this device depend on the name the server gives \
         127.0.0.1 (Match Host with UseDNS). MassRelay does not set up this configuration"
    );
    Ok(value.to_owned())
}

/// The arguments listing the present key files and then ours, and how the server will print
/// each. `none` stands for no file, and ours is listed once.
fn with_key_file(
    system: &dyn System,
    files: &[Vec<u8>],
    shown: &str,
    entry: &str,
) -> Result<(Vec<Token>, Vec<String>)> {
    let (mut keys, mut printed): (Vec<_>, Vec<_>) = key_files(system, files, shown)?
        .into_iter()
        .filter(|(key, printed)| key.value != "none" && printed != entry)
        .unzip();
    keys.push(Token::new(entry));
    printed.push(entry.to_owned());
    Ok((keys, printed))
}

fn matches_by_host(files: &[Vec<u8>]) -> Result<bool> {
    for file in files {
        if config::arguments(file, "match")?.iter().any(|criteria| {
            criteria
                .iter()
                .any(|token| token.value.eq_ignore_ascii_case("host"))
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What the server itself says before anything changes, where asking needs no rights.
struct Preview {
    /// The exact block, when it follows from the present settings.
    block: Option<String>,
    notes: Vec<String>,
}

/// The inner error is why the server could not be asked: as a rule its host keys, without
/// which it does not start even to test, are an administrator's alone.
fn preview(system: &dyn System, profile: &Path, found: &Survey) -> Result<Result<Preview, String>> {
    let entry = system.key_file_entry(&profile.join(AUTHORIZED_KEYS))?;
    let user = system.user();
    let mut settings = Vec::new();
    for connection in Connection::covered(user, found.port) {
        match effective(system, system.config(), &connection, Access::User) {
            Ok(shown) => settings.push(shown),
            Err(error) => return Ok(Err(format!("{error:#}"))),
        }
    }
    check_policy(&settings[0])?;
    let block = match own_block(system, found.configuration(), &entry)? {
        // Refreshing a block takes the settings without it, which only a copy shows.
        Some(_) => None,
        None => {
            let shown = covered_key_files(&settings, &found.files)?;
            let (keys, _) = with_key_file(system, &found.files, &shown, &entry)?;
            Some(config::render(
                &config::id(&entry),
                user,
                found.port,
                &keys,
                config::newline(found.configuration()),
            ))
        }
    };
    Ok(Ok(Preview {
        block,
        notes: restrictions(&settings[0]),
    }))
}

/// The change to make, which the server has verified on staged copies.
struct Install {
    /// `None` when the configuration is already what it should be.
    change: Option<Change>,
    block: String,
    expected: Expected,
    notes: Vec<String>,
}

fn prepare(system: &dyn System, profile: &Path, found: &Survey) -> Result<Install> {
    let access = Access::Administrator;
    let entry = system.key_file_entry(&profile.join(AUTHORIZED_KEYS))?;
    let user = system.user();
    let port = found.port;
    let original = found.configuration();
    let stripped = match own_block(system, original, &entry)? {
        Some(block) => config::splice(original, &[(block.span, String::new())]),
        None => original.to_vec(),
    };
    let files = configuration(system, &stripped, access)?;
    let baseline = system.stage(&stripped)?;
    let covered = Connection::covered(user, port);
    let mut settings = Vec::new();
    for connection in &covered {
        settings.push(effective(system, &baseline.path, connection, access)?);
    }
    let shown = covered_key_files(&settings, &files)?;
    check_policy(&settings[0])?;
    let (keys, printed) = with_key_file(system, &files, &shown, &entry)?;
    let block = config::render(
        &config::id(&entry),
        user,
        port,
        &keys,
        config::newline(original),
    );
    let candidate = config::insert(&stripped, &block)?;
    let wanted = format!("authorizedkeysfile {}", printed.join(" "));
    let mut expected: Expected = Vec::new();
    for (connection, settings) in covered.iter().zip(&settings) {
        let changed = settings
            .lines()
            .map(|line| {
                if line.starts_with("authorizedkeysfile ") {
                    format!("{wanted}\n")
                } else {
                    format!("{line}\n")
                }
            })
            .collect();
        expected.push((connection.clone(), changed));
    }
    for connection in Connection::untouched(user, system.other_user(), port) {
        let settings = effective(system, &baseline.path, &connection, access)?;
        expected.push((connection, settings));
    }
    let staged = system.stage(&candidate)?;
    verify(system, &staged, &expected)?;
    let change = (candidate != original).then(|| Change {
        original: original.to_vec(),
        candidate,
    });
    Ok(Install {
        change,
        block,
        expected,
        notes: restrictions(&settings[0]),
    })
}

fn needs_administrator(error: &anyhow::Error) -> Option<PathBuf> {
    error
        .downcast_ref::<NeedsAdministrator>()
        .map(|needed| needed.0.clone())
}

/// Mark every failure that is not [`Unavailable`] as a refusal.
pub(super) fn refused(error: anyhow::Error) -> anyhow::Error {
    if error.is::<Unavailable>() || error.is::<Refused>() {
        error
    } else {
        error.context(Refused)
    }
}

/// `error`, and what also went wrong while dealing with it.
fn also(error: anyhow::Error, then: Result<()>) -> anyhow::Error {
    match then {
        Ok(()) => error,
        Err(other) => error.context(format!("then also: {other:#}")),
    }
}

enum Planned {
    Known(Box<Survey>, Result<Preview, String>),
    /// Reading the configuration takes administrator rights, which a plan does not use.
    Deferred(PathBuf),
}

/// The system SSH part of `massrelay install`.
pub(crate) struct InstallPlan {
    system: Box<dyn System>,
    profile: PathBuf,
    planned: Planned,
}

impl InstallPlan {
    pub(super) fn new(system: Box<dyn System>, profile: PathBuf) -> Result<Self> {
        let planned = match survey(system.as_ref(), &profile, Access::User) {
            Ok(found) => {
                let preview = preview(system.as_ref(), &profile, &found).map_err(refused)?;
                Planned::Known(Box::new(found), preview)
            }
            Err(error) => match needs_administrator(&error) {
                Some(path) => {
                    system.running().map_err(refused)?;
                    Planned::Deferred(path)
                }
                None => return Err(refused(error)),
            },
        };
        Ok(Self {
            system,
            profile,
            planned,
        })
    }

    /// Make the changes shown. Fails, leaving things as they were, if what was shown no
    /// longer holds.
    pub(crate) fn apply(self) -> Result<()> {
        self.perform().map_err(refused)
    }

    fn perform(self) -> Result<()> {
        let system = self.system.as_ref();
        let profile = &self.profile;
        // Before either lock: a password may be typed here.
        system.authorize()?;
        let _machine = system.exclusive()?;
        let _setup = lock(profile, SETUP_LOCK)?;
        let found = survey(system, profile, Access::Administrator)?;
        if let Planned::Known(shown, _) = &self.planned {
            ensure!(shown.same_as(&found), CHANGED);
        }
        let install = prepare(system, profile, &found)?;
        if let Planned::Known(
            _,
            Ok(Preview {
                block: Some(shown), ..
            }),
        ) = &self.planned
        {
            ensure!(*shown == install.block, CHANGED);
        }

        let mut record = Record::load(profile, system.user())?;
        let created = {
            let _keys = lock(profile, AUTHORIZED_KEYS_LOCK)?;
            owned::make_key_file(profile, &mut record)?
        };
        if let Err(error) = finish(system, profile, &found, &install, &mut record) {
            let undone = if created {
                record.key_file = KeyFile::Unclaimed;
                lock(profile, AUTHORIZED_KEYS_LOCK)
                    .and_then(|_keys| remove(&profile.join(AUTHORIZED_KEYS)))
                    .and_then(|()| record.settle(profile))
            } else {
                Ok(())
            };
            return Err(also(error, undone));
        }
        let shown_before = matches!(
            &self.planned,
            Planned::Known(_, Ok(Preview { block: Some(_), .. }))
        );
        if !shown_before && install.change.is_some() {
            say(format!(
                "Added to {}:\n{}",
                system.config().display(),
                indented(&install.block)
            ));
        }
        for note in &install.notes {
            say(format!(
                "Note: the server's '{note}' stays in force for these logins"
            ));
        }
        say(format!(
            "System SSH      {LOOPBACK}:{} is ready",
            found.port
        ));
        Ok(())
    }

    /// What a confirmation of this plan approves, for a process that is to carry it out
    /// later to compare with its own: what is shown, and what was found.
    pub(crate) fn approval(&self) -> String {
        match &self.planned {
            Planned::Known(found, _) => format!(
                "{self}{:?}",
                (&found.files, found.port, &found.host_key, &found.reload)
            ),
            Planned::Deferred(_) => self.to_string(),
        }
    }
}

/// Change and reload the server, then describe it to the runtime.
fn finish(
    system: &dyn System,
    profile: &Path,
    found: &Survey,
    install: &Install,
    record: &mut Record,
) -> Result<()> {
    let answering = || answers(system, found.port, &found.host_key);
    let owed = record.reload_pending;
    if let Some(change) = &install.change {
        // Recorded first: whatever interrupts this, the next run knows to reload.
        record.reload_pending = true;
        record.save(profile)?;
        if let Err(failed) = commit(
            system,
            change,
            &install.expected,
            Some(&found.reload),
            answering,
        ) {
            record.reload_pending = failed.owes_reload(owed);
            return Err(also(failed.error, record.save(profile)));
        }
    } else if owed {
        system.reload(&found.reload)?;
        answering()?;
    }
    record.reload_pending = false;
    let server = Server {
        user: system.user().to_owned(),
        port: found.port,
        host_key: found.host_key.clone(),
        authorized_keys: profile.join(AUTHORIZED_KEYS),
    };
    let written = record.save(profile).and_then(|()| {
        let contents = serde_json::to_vec(&server)?;
        // The runtime reads the description under this lock.
        let _keys = lock(profile, AUTHORIZED_KEYS_LOCK)?;
        write_private(&profile.join(SERVER_FILE), &contents)
    });
    match (written, &install.change) {
        (Err(error), Some(change)) => {
            let failed = restore(system, change, Some(&found.reload), error);
            record.reload_pending = failed.owes_reload(owed);
            Err(also(failed.error, record.save(profile)))
        }
        (written, _) => written,
    }
}

/// Wait until the server answers with its host key.
fn answers(system: &dyn System, port: u16, host_key: &str) -> Result<()> {
    for attempt in 0..ANSWER_ATTEMPTS {
        if attempt > 0 {
            thread::sleep(Duration::from_millis(250));
        }
        if system.listener_key(port)?.as_deref() == Some(host_key) {
            return Ok(());
        }
    }
    bail!("the SSH server stopped answering on {LOOPBACK}:{port}")
}

/// Where a change that failed left the configuration.
#[derive(Clone, Copy)]
enum LeftAs {
    /// Never replaced.
    Untouched,
    /// Replaced, then put back and reloaded.
    Restored,
    /// Possibly replaced without the server having reloaded what is there.
    Unsettled,
}

struct Failed {
    error: anyhow::Error,
    left: LeftAs,
}

impl Failed {
    fn owes_reload(&self, owed_before: bool) -> bool {
        match self.left {
            LeftAs::Untouched => owed_before,
            LeftAs::Restored => false,
            LeftAs::Unsettled => true,
        }
    }
}

/// Verify a staged copy, put it in place and reload, restoring the previous file on failure.
fn commit(
    system: &dyn System,
    change: &Change,
    expected: &Expected,
    reload: Option<&Reload>,
    healthy: impl FnOnce() -> Result<()>,
) -> Result<(), Failed> {
    // The very file that replaces the configuration is the one verified.
    let staged = system
        .stage(&change.candidate)
        .and_then(|staged| verify(system, &staged, expected).map(|()| staged))
        .map_err(|error| Failed {
            error,
            left: LeftAs::Untouched,
        })?;
    if let Err(error) = system.replace(staged, &change.original) {
        // As a rule nothing happened. See, rather than assume.
        let left = match system.read_config(Access::Administrator) {
            Ok(Some(now)) if now == change.original => LeftAs::Untouched,
            _ => LeftAs::Unsettled,
        };
        return Err(Failed { error, left });
    }
    match reload {
        Some(reload) => system
            .reload(reload)
            .and_then(|()| healthy())
            .map_err(|error| restore(system, change, Some(reload), error)),
        None => Ok(()),
    }
}

/// Put the previous configuration back after `error`, and say what became of it.
fn restore(
    system: &dyn System,
    change: &Change,
    reload: Option<&Reload>,
    error: anyhow::Error,
) -> Failed {
    let restored = system
        .stage(&change.original)
        .and_then(|staged| system.replace(staged, &change.candidate))
        .and_then(|()| reload.map_or(Ok(()), |reload| system.reload(reload)));
    let config = system.config().display();
    match restored {
        Ok(()) => Failed {
            error: error.context(format!("the previous {config} was restored")),
            left: LeftAs::Restored,
        },
        Err(restore) => Failed {
            error: error.context(format!(
                "could not restore and reload the previous {config}: {restore:#}. Check it, \
                 including MassRelay's marked block, before reloading the SSH server"
            )),
            left: LeftAs::Unsettled,
        },
    }
}

fn indented(block: &str) -> String {
    block
        .lines()
        .map(|line| format!("      {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

impl fmt::Display for InstallPlan {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let system = self.system.as_ref();
        let key_file = self.profile.join(AUTHORIZED_KEYS);
        let config = system.config().display();
        let user = system.user();
        writeln!(out, "System SSH server, for logins as {user}")?;
        if let Planned::Known(found, _) = &self.planned {
            writeln!(
                out,
                "  Server    {LOOPBACK}:{} (already listening)",
                found.port
            )?;
            writeln!(
                out,
                "  Host key  {} ({})",
                fingerprint(&found.host_key),
                found.host_key_path.display()
            )?;
        }
        writeln!(
            out,
            "  Keep      {} (MassRelay's temporary keys only; made if absent)",
            key_file.display()
        )?;
        for (file, what) in [
            (SERVER_FILE, "how to reach the server"),
            (SETUP_RECORD, "what setup made, for removal"),
        ] {
            writeln!(
                out,
                "  Write     {} ({what})",
                self.profile.join(file).display()
            )?;
        }
        let (block, reload, preview) = match &self.planned {
            Planned::Known(found, preview) => (
                preview
                    .as_ref()
                    .ok()
                    .and_then(|preview| preview.block.clone()),
                system.describe(&found.reload),
                preview.as_ref().map_err(Some),
            ),
            Planned::Deferred(path) => {
                writeln!(
                    out,
                    "  Only an administrator can read {}. The port and the key files are read \
                     with\n  those rights after you confirm.",
                    path.display()
                )?;
                (
                    None,
                    "reload the system SSH server if it needs it".to_owned(),
                    Err(None),
                )
            }
        };
        writeln!(
            out,
            "  Change    {config}: add or refresh this block before its first Match line, \
             unless it is\n            already right"
        )?;
        let block = block.unwrap_or_else(|| {
            let entry = system
                .key_file_entry(&key_file)
                .unwrap_or_else(|_| key_file.display().to_string());
            let port = match &self.planned {
                Planned::Known(found, _) => found.port.to_string(),
                Planned::Deferred(_) => "<the server's port>".to_owned(),
            };
            format!(
                "Match User {user} Address {LOOPBACK} LocalAddress {LOOPBACK} LocalPort {port}\n\
                 \tAuthorizedKeysFile <the key files these logins use without MassRelay> {}\n\
                 Match all\n",
                Token::new(&entry).raw
            )
        });
        writeln!(out, "{}", indented(&block))?;
        writeln!(
            out,
            "  Check     after you confirm, the server tests a copy beside the file before it \
             replaces\n            it: only these loopback logins may change, by gaining the new \
             key file"
        )?;
        if let Err(why) = &preview {
            writeln!(
                out,
                "  Unchecked the server's effective settings are not known yet; they are read \
                 with\n            administrator rights, and if they do not allow this, nothing \
                 is changed"
            )?;
            if let Some(why) = why {
                writeln!(out, "            ({})", why.replace('\n', " "))?;
            }
        }
        writeln!(
            out,
            "  Reload    {reload}; the previous file is restored if this fails"
        )?;
        writeln!(out, "  Rights    {}", system.rights())?;
        writeln!(
            out,
            "  The block fixes which key files are read for these logins; the files themselves \
             are\n  read at each login. Run 'massrelay install' again after changing \
             AuthorizedKeysFile.\n  No listener, firewall rule or other SSH setting is changed."
        )?;
        for note in preview.ok().iter().flat_map(|preview| &preview.notes) {
            writeln!(
                out,
                "  Note      the server's '{note}' stays in force for these logins"
            )?;
        }
        Ok(())
    }
}

/// What removing a profile's setup does outside the profile.
#[derive(Debug, Default)]
struct Removal {
    /// The configuration without this profile's key file.
    change: Option<Change>,
    /// A port by which to check that change.
    port: u16,
    /// The changed blocks, as shown.
    shown: Vec<String>,
    /// What stays because it cannot be removed safely now.
    left: Vec<String>,
    notes: Vec<String>,
}

impl Removal {
    /// Keep the configuration, which nothing here can check a change to.
    fn keep_configuration(&mut self, system: &dyn System, why: &str) {
        if self.change.take().is_some() {
            self.shown.clear();
            self.left.push(format!(
                "{} keeps MassRelay's block, since a change to it cannot be checked: {why}",
                system.config().display()
            ));
        }
    }

    fn unread(system: &dyn System, why: impl fmt::Display) -> Self {
        Self {
            left: vec![format!(
                "{} may keep MassRelay's block: {why}",
                system.config().display()
            )],
            ..Self::default()
        }
    }
}

/// Work out the removal from the configuration's text alone.
fn scan(system: &dyn System, entry: &str, access: Access) -> Result<Removal> {
    let id = config::id(entry);
    let config = system.config().display();
    let mut removal = Removal::default();
    let original = match system.read_config(access) {
        Ok(Some(original)) => original,
        Ok(None) => return Ok(removal),
        Err(error) if error.is::<NeedsAdministrator>() => return Err(error),
        Err(error) => return Ok(Removal::unread(system, format!("{error:#}"))),
    };
    let blocks = match config::blocks(&original) {
        Ok(blocks) => blocks,
        Err(error) => {
            removal.left.push(format!(
                "{config} is left as it is: {error:#}. Remove MassRelay's block yourself"
            ));
            return Ok(removal);
        }
    };
    let mut changes = Vec::new();
    for Block {
        id: of,
        span,
        managed,
    } in blocks
    {
        let Some(managed) = managed else {
            if of == id {
                removal.left.push(format!(
                    "MassRelay's block {id} in {config} was edited, so it is left for you to \
                     remove"
                ));
            }
            continue;
        };
        if of == id {
            removal.shown.push(format!(
                "remove\n{}",
                indented(&String::from_utf8_lossy(&original[span.clone()]))
            ));
            removal.port = managed.port;
            changes.push((span, String::new()));
        } else if managed.keys.iter().any(|key| key.value == entry) {
            // Another profile's block repeats this profile's file.
            let keys: Vec<_> = managed
                .keys
                .into_iter()
                .filter(|key| key.value != entry)
                .collect();
            let block = config::render(
                &of,
                &managed.user,
                managed.port,
                &keys,
                config::newline(&original),
            );
            removal.shown.push(format!(
                "drop this profile's key file from block {of}, leaving\n{}",
                indented(&block)
            ));
            if removal.port == 0 {
                removal.port = managed.port;
            }
            changes.push((span, block));
        }
    }
    let candidate = config::splice(&original, &changes);
    if String::from_utf8_lossy(&candidate).contains(entry) {
        removal.notes.push(format!(
            "{config} still names {entry} in a line MassRelay does not own, which it leaves"
        ));
    }
    if !changes.is_empty() {
        removal.change = Some(Change {
            original,
            candidate,
        });
    }
    Ok(removal)
}

/// Have the server show that a removal changes nothing but the key files of the covered
/// logins.
fn verify_removal(system: &dyn System, change: &Change, port: u16) -> Result<Expected> {
    let access = Access::Administrator;
    configuration(system, &change.original, access)?;
    let current = system.stage(&change.original)?;
    let staged = system.stage(&change.candidate)?;
    let user = system.user();
    let mut expected: Expected = Vec::new();
    for connection in Connection::untouched(user, system.other_user(), port) {
        let settings = effective(system, &current.path, &connection, access)?;
        expected.push((connection, settings));
    }
    // The covered logins keep every other setting.
    for connection in Connection::covered(user, port) {
        let before = effective(system, &current.path, &connection, access)?;
        let after = effective(system, &staged.path, &connection, access)?;
        let others = |settings: &str| -> Vec<String> {
            settings
                .lines()
                .filter(|line| !line.starts_with("authorizedkeysfile "))
                .map(str::to_owned)
                .collect()
        };
        ensure!(
            others(&before) == others(&after),
            "removing the block would change other settings for these logins"
        );
        expected.push((connection, after));
    }
    verify(system, &staged, &expected)?;
    Ok(expected)
}

/// How to have a running server read the configuration; `None` when none is running, so
/// that whichever starts next reads what is there.
fn reload_for(system: &dyn System, access: Access) -> Result<Option<Reload>> {
    match system.running() {
        Err(error) if error.is::<Unavailable>() => Ok(None),
        _ => system.reload_method(access).map(Some),
    }
}

/// Finish a reload an earlier change still owes. `Ok(Some)` says why it cannot be tried, and
/// an error that it was tried and failed.
fn settle(system: &dyn System) -> Result<Option<String>> {
    let checked = (|| {
        let Some(current) = system.read_config(Access::Administrator)? else {
            return match system.running() {
                Err(error) if error.is::<Unavailable>() => Ok(None),
                Err(error) => Err(error),
                Ok(()) => bail!("{} is missing", system.config().display()),
            };
        };
        let staged = system.stage(&current)?;
        let path = staged
            .path
            .to_str()
            .context("the configuration's path is not Unicode")?;
        system.sshd(
            &["-t".to_owned(), "-f".to_owned(), path.to_owned()],
            Access::Administrator,
        )?;
        reload_for(system, Access::Administrator)
    })();
    match checked {
        Ok(Some(reload)) => system.reload(&reload).map(|()| None),
        Ok(None) => Ok(None),
        Err(error) => Ok(Some(format!(
            "a running SSH server may not have read an earlier change, and cannot safely be \
             reloaded: {error:#}"
        ))),
    }
}

enum PlannedRemoval {
    Known(Removal),
    Deferred(PathBuf),
}

struct ProfileRemoval {
    system: Box<dyn System>,
    profile: PathBuf,
    planned: PlannedRemoval,
    /// What the plan shows becomes of the key file.
    key_file: Disposition,
    /// A reload an earlier change owes, and whether it can be tried.
    owed: bool,
    usable: bool,
}

/// The system SSH part of `massrelay uninstall`.
pub(crate) struct UninstallPlan(
    /// `None` when there is nothing to remove or look at.
    Option<ProfileRemoval>,
);

impl UninstallPlan {
    pub(super) fn nothing() -> Self {
        Self(None)
    }

    /// A missing or unusable server program never stops a removal: the configuration is
    /// then kept, since no change to it can be checked, and the profile is still cleaned.
    pub(super) fn new(system: Box<dyn System>, profile: PathBuf) -> Result<Self> {
        let this = system.as_ref();
        let entry = match this.key_file_entry(&profile.join(AUTHORIZED_KEYS)) {
            Ok(entry) => entry,
            // A path the server cannot be given was never set up.
            Err(_) if !set_up(&profile)? => return Ok(Self::nothing()),
            Err(error) => return Err(refused(error)),
        };
        let planned = (|| {
            let (record, unusable) = Record::load_for_removal(&profile, this.user())?;
            let usable = this.installed().map_err(|error| format!("{error:#}"));
            let mut planned = match scan(this, &entry, Access::User) {
                Ok(removal) => PlannedRemoval::Known(removal),
                Err(error) => match needs_administrator(&error) {
                    // The record and the key file are made before the configuration
                    // changes, so without them there is nothing that has to be looked at.
                    Some(_) if !set_up(&profile)? => PlannedRemoval::Known(Removal::default()),
                    Some(path) if usable.is_ok() => PlannedRemoval::Deferred(path),
                    Some(_) => PlannedRemoval::Known(Removal::unread(this, format!("{error:#}"))),
                    None => return Err(error),
                },
            };
            if let (PlannedRemoval::Known(removal), Err(why)) = (&mut planned, &usable) {
                removal.keep_configuration(this, why);
            }
            let key_file = owned::disposition(this, &profile, &record)?;
            let owed = unusable.is_none() && record.reload_pending;
            Ok((planned, key_file, owed, usable.is_ok()))
        })();
        let (planned, key_file, owed, usable) = planned.map_err(refused)?;
        Ok(Self(Some(ProfileRemoval {
            system,
            profile,
            planned,
            key_file,
            owed,
            usable,
        })))
    }

    /// Remove what was shown. Safe to run again after any failure.
    pub(crate) fn apply(self) -> Result<()> {
        match self.0 {
            Some(removal) => removal.perform().map_err(refused),
            None => Ok(()),
        }
    }
}

impl ProfileRemoval {
    fn perform(self) -> Result<()> {
        let system = self.system.as_ref();
        let profile = &self.profile;
        let config = system.config().display();
        let planned_change = match &self.planned {
            PlannedRemoval::Known(removal) => removal.change.is_some(),
            PlannedRemoval::Deferred(_) => true,
        };
        if !planned_change && !set_up(profile)? {
            return Ok(());
        }
        let usable = system.installed();
        let owed = Record::load_for_removal(profile, system.user())?
            .0
            .reload_pending;
        let usable = usable.map_err(|error| format!("{error:#}"));
        let rights = usable.is_ok() && (planned_change || owed);
        let _machine = if rights {
            system.authorize()?;
            Some(system.exclusive()?)
        } else {
            None
        };
        let _setup = lock(profile, SETUP_LOCK)?;
        // Held to the end: a runtime waiting for it then finds no description and adds no key.
        let _lock = lock(profile, AUTHORIZED_KEYS_LOCK)?;
        let key_file = profile.join(AUTHORIZED_KEYS);
        let entry = system.key_file_entry(&key_file)?;
        let (mut record, unusable) = Record::load_for_removal(profile, system.user())?;
        let access = if rights {
            Access::Administrator
        } else {
            Access::User
        };
        let mut now = match scan(system, &entry, access) {
            Ok(removal) => removal,
            Err(error) if !rights && error.is::<NeedsAdministrator>() => {
                Removal::unread(system, format!("{error:#}"))
            }
            Err(error) => return Err(error),
        };
        if let Err(why) = &usable {
            now.keep_configuration(system, why);
        } else if let PlannedRemoval::Known(shown) = &self.planned {
            ensure!(shown.change == now.change, CHANGED);
        }

        // An unusable description is removed all the same, and then not put back.
        let description = profile.join(SERVER_FILE);
        let previous = read_description(&description).unwrap_or_default();
        remove(&description)?;
        let restore_description = |error: anyhow::Error| {
            let restored = previous
                .as_ref()
                .map_or(Ok(()), |contents| write_private(&description, contents));
            also(error, restored)
        };
        // A reload that was tried and failed, reported once the profile is clean.
        let mut failed_reload = None;
        if let Some(change) = now.change.take() {
            let verified = match &unusable {
                // Without a record, an interrupted change could pass for a finished one.
                Some(why) => Err(anyhow!("{why}")),
                None => verify_removal(system, &change, now.port),
            };
            match verified {
                Err(error) => now.left.push(format!(
                    "{config} keeps MassRelay's block, because its removal cannot be verified: \
                     {error:#}"
                )),
                Ok(expected) => {
                    let reload = reload_for(system, Access::Administrator);
                    let owed = record.reload_pending;
                    record.reload_pending = true;
                    record.save(profile).map_err(&restore_description)?;
                    let how = reload.as_ref().ok().and_then(Option::as_ref);
                    if let Err(failed) = commit(system, &change, &expected, how, || Ok(())) {
                        record.reload_pending = failed.owes_reload(owed);
                        let error = also(failed.error, record.save(profile));
                        return Err(restore_description(error));
                    }
                    match reload {
                        Ok(_) => record.reload_pending = false,
                        Err(error) => now.left.push(format!(
                            "{config} was changed, but MassRelay cannot reload the server, so \
                             reload it yourself: {error:#}"
                        )),
                    }
                }
            }
        } else if record.reload_pending {
            match &usable {
                Err(why) => now.left.push(format!(
                    "a running SSH server may not have read an earlier change, and there is no \
                     usable server program to check a reload with: {why}"
                )),
                Ok(()) if rights => match settle(system) {
                    Ok(None) => record.reload_pending = false,
                    Ok(Some(why)) => now.left.push(why),
                    Err(error) => failed_reload = Some(error),
                },
                Ok(()) => bail!(CHANGED),
            }
        }

        match owned::disposition(system, profile, &record)? {
            Disposition::Absent => {}
            Disposition::Remove => remove(&key_file)?,
            Disposition::Scrub(rest) => {
                write_private(&key_file, rest.as_bytes())?;
                now.notes.push(format!(
                    "{} is kept with the lines MassRelay did not write; its own were removed",
                    key_file.display()
                ));
            }
            Disposition::Keep(why) => now
                .notes
                .push(format!("{} is left as it is: {why}", key_file.display())),
        }
        record.key_file = KeyFile::Unclaimed;
        match &unusable {
            Some(why) => now.left.push(why.clone()),
            // The record stays while anything does, so that a later run looks again.
            None if now.left.is_empty() => record.settle(profile)?,
            None => record.save(profile)?,
        }

        if matches!(self.planned, PlannedRemoval::Deferred(_)) {
            for change in &now.shown {
                println!("In {config}: {change}");
            }
        }
        // What was kept is said even when the removal goes on to fail.
        for note in &now.notes {
            println!("Note: {note}");
        }
        if let Some(error) = failed_reload {
            for left in &now.left {
                println!("Remains: {left}");
            }
            return Err(error.context(
                "the SSH server still has not reloaded an earlier change; run 'massrelay \
                 uninstall' again",
            ));
        }
        if now.left.is_empty() {
            println!("System SSH      MassRelay's setup is removed");
        } else {
            println!("System SSH      not completely removed. What remains:");
            for left in &now.left {
                println!("  {left}");
            }
        }
        Ok(())
    }
}

/// Whether the profile holds anything of a setup.
pub(super) fn set_up(profile: &Path) -> Result<bool> {
    Ok(present(&profile.join(SETUP_RECORD))?
        || present(&profile.join(AUTHORIZED_KEYS))?
        || present(&profile.join(SERVER_FILE))?)
}

impl fmt::Display for UninstallPlan {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(out, "System SSH server")?;
        let Some(ProfileRemoval {
            system,
            profile,
            planned,
            key_file,
            owed,
            usable,
        }) = &self.0
        else {
            return writeln!(out, "  Nothing was set up for this state directory.");
        };
        let config = system.config().display();
        writeln!(
            out,
            "  Remove    {} (if present)",
            profile.join(SERVER_FILE).display()
        )?;
        let keys = profile.join(AUTHORIZED_KEYS);
        let keys = keys.display();
        match key_file {
            Disposition::Absent => {}
            Disposition::Remove => writeln!(out, "  Remove    {keys}")?,
            Disposition::Scrub(_) => writeln!(
                out,
                "  Keep      {keys}, removing only MassRelay's lines: someone else wrote in it"
            )?,
            Disposition::Keep(why) => writeln!(out, "  Keep      {keys} unchanged: {why}")?,
        }
        writeln!(
            out,
            "  Update    {} (kept only while something remains)",
            profile.join(SETUP_RECORD).display()
        )?;
        let reloading = || match reload_for(system.as_ref(), Access::User) {
            Ok(Some(reload)) => system.describe(&reload),
            Ok(None) => "none needed; no server is running".to_owned(),
            Err(_) => "the running server, as found after you confirm".to_owned(),
        };
        match planned {
            PlannedRemoval::Known(removal) => {
                if removal.change.is_none() {
                    writeln!(out, "  Unchanged {config}")?;
                    if *owed && *usable {
                        writeln!(
                            out,
                            "  Reload    {}, which an earlier change still owes\n  Rights    {}",
                            reloading(),
                            system.rights()
                        )?;
                    }
                } else {
                    for change in &removal.shown {
                        writeln!(out, "  Change    {config}: {change}")?;
                    }
                    writeln!(
                        out,
                        "  Check     after you confirm, the server tests a copy beside the \
                         file; the file is\n            kept if the removal cannot be verified"
                    )?;
                    writeln!(
                        out,
                        "  Reload    {}; the previous file is restored if this fails",
                        reloading()
                    )?;
                    writeln!(out, "  Rights    {}", system.rights())?;
                }
                for left in &removal.left {
                    writeln!(out, "  Remains   {left}")?;
                }
                for note in &removal.notes {
                    writeln!(out, "  Note      {note}")?;
                }
            }
            PlannedRemoval::Deferred(path) => {
                writeln!(
                    out,
                    "  Only an administrator can read {}. After you confirm, those rights are \
                     used\n  to remove this profile's MassRelay block from {config}, if there, \
                     check the\n  result with the server's own tests and reload it.",
                    path.display()
                )?;
                writeln!(out, "  Rights    {}", system.rights())?;
            }
        }
        Ok(())
    }
}
