use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::mailbox::Bytes;
use crate::{local, tcp, wire};

use super::super::binding::EndpointKey;
use super::super::pairing::parse_key;
use super::super::runtime::{self, ControlReply, ControlRequest};
use super::{Host, keys};

async fn connect(
    dir: &Path,
    peer: String,
    client_key: Option<Bytes<32>>,
) -> Result<(tokio::net::TcpStream, ControlReply, tokio::net::TcpStream)> {
    let lifetime = local::Lifetime::bind().await?;
    let (socket, reply) = runtime::request(
        dir,
        ControlRequest::Ssh {
            peer,
            client_key,
            lifetime_port: lifetime.port,
            lifetime_key: lifetime.key,
        },
    )
    .await?;
    if let ControlReply::Error(error) = reply {
        bail!("{error}");
    }
    let lifetime = timeout(wire::RPC_TIMEOUT, lifetime.accept())
        .await
        .context("the runtime did not open the SSH lifetime channel")??;
    Ok((socket, reply, lifetime))
}

pub(in crate::private) async fn proxy(dir: &Path, peer: String, key: &str) -> Result<()> {
    let key = super::super::codec::unhex(key)
        .and_then(|bytes| bytes.try_into().ok())
        .context("invalid SSH client key")?;
    let (socket, reply, _lifetime) = connect(dir, peer, Some(Bytes(key))).await?;
    ensure!(
        matches!(reply, ControlReply::Connected),
        "unexpected SSH tunnel reply"
    );
    tcp::attach(socket).await
}

/// The key pinned for a peer's system SSH server.
const SYSTEM_PIN: &str = "ssh-system-pin-";
/// The key pinned for the SSH server of MassRelay's own that a former peer runs.
const FORMER_PIN: &str = "ssh-pin-";

fn pin_path(dir: &Path, kind: &str, endpoint: &EndpointKey) -> std::path::PathBuf {
    dir.join(format!("{kind}{}", super::super::codec::hex(endpoint)))
}

fn read_pin(path: &Path) -> Result<Option<[u8; 32]>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid SSH host pin"))?,
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// The SSH host key trusted for `endpoint`, if one was ever pinned.
pub(super) fn pinned(dir: &Path, endpoint: &EndpointKey) -> Result<Option<[u8; 32]>> {
    match read_pin(&pin_path(dir, SYSTEM_PIN, endpoint))? {
        Some(key) => Ok(Some(key)),
        None => read_pin(&pin_path(dir, FORMER_PIN, endpoint)),
    }
}

/// Trust the host record `host`, which `peer` sent on an authorized connection, if it
/// agrees with what is pinned or `replace` names its fingerprint.
///
/// A peer's move from MassRelay's own SSH server to its system server changes the key once:
/// the first system record replaces a former pin. From then on only the system pin counts,
/// so a record of the former kind has to match it too. Returns whether a former pin of
/// another key was replaced that way.
pub(super) fn pin(dir: &Path, peer: &str, host: &Host, replace: Option<&str>) -> Result<bool> {
    let endpoint = parse_key(peer).context("expected an SSH peer endpoint")?;
    let key = host.key.0;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600);
    let lock = options.open(dir.join("ssh-pins.lock"))?;
    FileExt::lock_exclusive(&lock)?;
    let system_path = pin_path(dir, SYSTEM_PIN, &endpoint);
    let former_path = pin_path(dir, FORMER_PIN, &endpoint);
    let system = read_pin(&system_path)?;
    let former = read_pin(&former_path)?;
    let fingerprint = keys::fingerprint(&key);
    if let Some(expected) = replace {
        ensure!(
            expected == fingerprint,
            "the authenticated SSH host key is {fingerprint}"
        );
    }
    let trusted = system.or(if host.system { None } else { former });
    if let Some(old) = trusted.filter(|old| *old != key && replace.is_none()) {
        bail!(
            "SSH host key changed from {} to {fingerprint}; verify the new fingerprint before using --replace-host-key",
            keys::fingerprint(&old)
        );
    }
    // The pin to write, and the one that must not outlive it.
    let (path, current, other) = if host.system {
        (&system_path, system, &former_path)
    } else if trusted == Some(key) {
        return Ok(false);
    } else {
        (&former_path, former, &system_path)
    };
    if current != Some(key) {
        let mut updated = tempfile::NamedTempFile::new_in(dir)?;
        updated.write_all(&key)?;
        updated.as_file().sync_all()?;
        updated.persist(path)?;
        sync_directory(dir)?;
    }
    match std::fs::remove_file(other) {
        Ok(()) => sync_directory(dir)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("remove the replaced SSH host pin"),
    }
    Ok(host.system && system.is_none() && former.is_some_and(|old| old != key))
}

fn sync_directory(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(unix)]
fn shell_arg(value: &str) -> Result<String> {
    ensure!(
        !value.chars().any(char::is_control),
        "SSH proxy path contains a control character"
    );
    Ok(format!(
        "'{}'",
        value.replace('\'', "'\\''").replace('%', "%%")
    ))
}

#[cfg(windows)]
fn shell_arg(value: &str) -> Result<String> {
    crate::windows_service::quote(value)
}

fn path_text(path: &Path) -> Result<String> {
    #[cfg(unix)]
    {
        path.to_str()
            .map(str::to_owned)
            .context("path is not Unicode")
    }
    #[cfg(windows)]
    crate::windows_service::plain(&std::path::absolute(path)?)
}

fn config_path(path: &Path) -> Result<String> {
    let path = path_text(path)?;
    #[cfg(windows)]
    let path = path.replace('\\', "/");
    ensure!(
        !path
            .chars()
            .any(|c| c.is_control() || "\"\\%$?*[]{}".contains(c)),
        "unsupported path in OpenSSH configuration"
    );
    Ok(path)
}

/// What one `Host` block names.
pub(super) struct Entry<'a> {
    /// The `Host` line's patterns.
    pub managed: bool,
    pub patterns: &'a str,
    /// The name the host key is recorded under.
    pub alias: &'a str,
    pub user: &'a str,
    pub identity: &'a Path,
    pub known_hosts: &'a Path,
    /// The MassRelay program `ProxyCommand` runs, and its state directory.
    pub program: &'a Path,
    pub state: &'a Path,
    /// The destination's endpoint.
    pub peer: &'a str,
    pub client_key: &'a [u8; 32],
}

/// The `UserKnownHostsFile` line that pins `key` for an entry.
pub(super) fn known_host(alias: &str, key: &[u8; 32]) -> String {
    format!("{alias} {}\n", keys::public_line(key))
}

pub(super) fn render(entry: &Entry<'_>) -> Result<String> {
    let Entry {
        patterns,
        alias,
        user,
        ..
    } = entry;
    let exe = shell_arg(&path_text(entry.program)?)?;
    let state = shell_arg(&path_text(entry.state)?)?;
    let peer = shell_arg(entry.peer)?;
    let client_key = super::super::codec::hex(entry.client_key);
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    // Only letters, digits and `_.-@` go unquoted: see `Host::valid_user`.
    let user = if user.contains([' ', '\\']) {
        format!("\"{user}\"")
    } else {
        (*user).to_owned()
    };
    let known_hosts_command = if entry.managed {
        "KnownHostsCommand none\n"
    } else {
        ""
    };
    Ok(format!(
        "Host {patterns}\n\
         HostName {alias}.invalid\n\
         HostKeyAlias {alias}\n\
         User {user}\n\
         BatchMode yes\n\
         IdentitiesOnly yes\n\
         IdentityAgent none\n\
         IdentityFile \"{}\"\n\
         CertificateFile none\n\
         PreferredAuthentications publickey\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         ForwardAgent no\n\
         ForwardX11 no\n\
         ClearAllForwardings yes\n\
         PermitLocalCommand no\n\
         StrictHostKeyChecking yes\n\
         CheckHostIP no\n\
         VerifyHostKeyDNS no\n\
         UpdateHostKeys no\n\
         HostKeyAlgorithms ssh-ed25519\n\
         UserKnownHostsFile \"{}\"\n\
         GlobalKnownHostsFile {null}\n\
         {known_hosts_command}ControlMaster no\n\
         ControlPath none\n\
         ProxyUseFdpass no\n\
         ProxyCommand {exe} --state-dir {state} ssh-proxy {peer} {client_key}\n",
        config_path(entry.identity)?,
        config_path(entry.known_hosts)?,
    ))
}

pub(in crate::private) struct Launch {
    files: tempfile::TempDir,
    pub alias: String,
    pub config: String,
}

impl Launch {
    pub(in crate::private) async fn prepare(
        dir: &Path,
        peer: String,
        replace: Option<&str>,
        proxy_exe: &Path,
    ) -> Result<Self> {
        let (_, reply, _) = connect(dir, peer.clone(), None).await?;
        let ControlReply::SshHost(host) = reply else {
            bail!("unexpected SSH host reply");
        };
        ensure!(Host::valid_user(&host.user), "invalid SSH account");
        #[cfg(windows)]
        crate::windows_service::ssh_private_dir(dir)?;
        if pin(dir, &peer, &host, replace)? {
            eprintln!(
                "massrelay: this peer now uses its system SSH server; its host key {} \
                 replaces the one pinned for MassRelay's former SSH server",
                keys::fingerprint(&host.key.0)
            );
        }
        let Host { user, key, .. } = host;

        // OpenSSH's config parser also expands tokens in path options.
        // The temporary credential paths use only characters safe there.
        #[cfg(unix)]
        let temp_root = Path::new("/tmp");
        #[cfg(windows)]
        let temp_root = dir;
        let mut builder = tempfile::Builder::new();
        builder.prefix("massrelay-ssh-");
        #[cfg(unix)]
        builder.permissions(std::fs::Permissions::from_mode(0o700));
        let files = builder.tempdir_in(temp_root)?;
        let alias = files
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .context("invalid SSH alias")?
            .to_owned();
        let identity = files.path().join("identity");
        let client_key = keys::generate(&identity).await?;
        let known = files.path().join("known_hosts");
        tokio::fs::write(&known, known_host(&alias, &key.0)).await?;
        let state = dir
            .parent()
            .context("missing runtime state directory")?
            .canonicalize()?;
        let config = render(&Entry {
            managed: false,
            patterns: &alias,
            alias: &alias,
            user: &user,
            identity: &identity,
            known_hosts: &known,
            program: proxy_exe,
            state: &state,
            peer: &peer,
            client_key: &client_key,
        })?;
        Ok(Self {
            alias,
            config,
            files,
        })
    }
}

async fn until_interrupted(work: impl std::future::Future<Output = Result<i32>>) -> Result<i32> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut hangup = signal(SignalKind::hangup())?;
        tokio::select! {
            biased;
            _ = hangup.recv() => Ok(129),
            result = crate::shutdown() => { result?; Ok(130) }
            result = work => result,
        }
    }
    #[cfg(windows)]
    tokio::select! {
        biased;
        result = crate::shutdown() => { result?; Ok(130) }
        result = work => result,
    }
}

pub(in crate::private) async fn launch_ssh(
    dir: &Path,
    peer: String,
    replace: Option<&str>,
    remote: Vec<String>,
) -> Result<i32> {
    until_interrupted(async {
        let launch = Launch::prepare(dir, peer, replace, &std::env::current_exe()?).await?;
        let config = launch.files.path().join("config");
        tokio::fs::write(&config, launch.config).await?;
        let status = Command::new(keys::openssh("ssh")?)
            .arg("-F")
            .arg(config)
            .arg("--")
            .arg(launch.alias)
            .args(remote)
            .kill_on_drop(true)
            .status()
            .await
            .context("run OpenSSH client")?;
        Ok(status.code().unwrap_or(1))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private::codec::hex;

    #[test]
    fn a_former_pin_gives_way_once_and_a_system_pin_only_when_told() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let dir = dir.path();
        let endpoint = [7; 32];
        let peer = hex(&endpoint);
        let host = |key, system| Host {
            user: "user".into(),
            key: Bytes([key; 32]),
            system,
        };
        let trusted = || pinned(dir, &endpoint).unwrap().map(|key| key[0]);
        let former = pin_path(dir, FORMER_PIN, &endpoint);
        let system = pin_path(dir, SYSTEM_PIN, &endpoint);

        // A former peer is pinned and held to its key as before.
        assert!(!pin(dir, &peer, &host(1, false), None)?);
        assert!(!pin(dir, &peer, &host(1, false), None)?);
        assert!(pin(dir, &peer, &host(2, false), None).is_err());
        assert_eq!(trusted(), Some(1));
        let wrong = keys::fingerprint(&[9; 32]);
        assert!(pin(dir, &peer, &host(2, true), Some(&wrong)).is_err());
        assert_eq!(trusted(), Some(1));

        // Its system server's key replaces that pin, once.
        assert!(pin(dir, &peer, &host(2, true), None)?);
        assert_eq!(trusted(), Some(2));
        assert!(!former.exists() && system.exists());
        assert!(!pin(dir, &peer, &host(2, true), None)?);
        // Neither another system key nor the former server is believed from then on.
        for changed in [host(3, true), host(1, false)] {
            let error = pin(dir, &peer, &changed, None).unwrap_err().to_string();
            assert!(error.contains("SSH host key changed"), "{error}");
        }
        assert_eq!(trusted(), Some(2));
        let fingerprint = keys::fingerprint(&[3; 32]);
        pin(dir, &peer, &host(3, true), Some(&fingerprint))?;
        assert_eq!(trusted(), Some(3));
        // Going back takes the same deliberate step.
        let fingerprint = keys::fingerprint(&[1; 32]);
        pin(dir, &peer, &host(1, false), Some(&fingerprint))?;
        assert_eq!(trusted(), Some(1));
        assert!(former.exists() && !system.exists());

        // An interrupted replacement leaves both: the system pin counts.
        std::fs::write(&system, [4; 32])?;
        assert_eq!(trusted(), Some(4));
        assert!(!pin(dir, &peer, &host(4, true), None)?);
        assert!(!former.exists());
        Ok(())
    }
}
