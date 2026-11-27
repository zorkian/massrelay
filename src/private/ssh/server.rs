use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
#[cfg(not(target_os = "macos"))]
use std::os::unix::net::UnixStream as StdStream;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use tempfile::{NamedTempFile, TempDir};
#[cfg(target_os = "macos")]
use tokio::net::TcpStream as LocalStream;
#[cfg(not(target_os = "macos"))]
use tokio::net::UnixStream as LocalStream;
use tokio::process::{Child, Command};

use crate::mailbox::Bytes;

use super::{Host, keys};

const SSHD: &str = "/usr/sbin/sshd";
const HOST_FILE: &str = "ssh-host-ed25519";
const TEMP_DIR: &str = "/tmp";

#[cfg(target_os = "linux")]
fn has_user_bus(runtime: &Path, uid: u32) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    std::fs::symlink_metadata(runtime)
        .is_ok_and(|dir| dir.is_dir() && dir.uid() == uid && dir.mode() & 0o077 == 0)
        && std::fs::symlink_metadata(runtime.join("bus"))
            .is_ok_and(|bus| bus.file_type().is_socket() && bus.uid() == uid)
}

fn session_environment() -> String {
    let host = format!("SetEnv={}={}", crate::private::HOST_ENV, std::process::id());
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid is infallible and has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let runtime = format!("/run/user/{uid}");
        if has_user_bus(Path::new(&runtime), uid) {
            return format!(
                "{host} XDG_RUNTIME_DIR={runtime} DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus"
            );
        }
    }
    host
}

async fn account() -> Result<String> {
    unsafe extern "C" {
        fn getuid() -> u32;
        fn geteuid() -> u32;
    }
    // SAFETY: These libc calls have no preconditions and cannot fail.
    let (uid, effective) = unsafe { (getuid(), geteuid()) };
    ensure!(
        uid != 0 && uid == effective,
        "SSH requires a regular runtime user"
    );
    let run_id = |args: &[&str]| {
        let mut cmd = Command::new("/usr/bin/id");
        cmd.args(args).env_clear().kill_on_drop(true);
        cmd
    };
    let name = run_id(&["-un"]).output().await?;
    ensure!(name.status.success(), "could not resolve the runtime user");
    let user = std::str::from_utf8(&name.stdout)?.trim_end_matches('\n');
    ensure!(Host::valid_user(user), "unsupported SSH account name");
    let resolved = run_id(&["-u", user]).output().await?;
    ensure!(
        resolved.status.success()
            && std::str::from_utf8(&resolved.stdout)?
                .trim_end_matches('\n')
                .parse::<u32>()?
                == uid,
        "SSH account does not resolve to the runtime UID"
    );
    Ok(user.to_owned())
}

async fn install_host_key(dir: &Path, rotate: bool) -> Result<[u8; 32]> {
    let staging = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(dir)?;
    let generated = staging.path().join("host");
    let key = keys::generate(&generated).await?;
    let mut replacement = NamedTempFile::new_in(dir)?;
    replacement.write_all(&tokio::fs::read(generated).await?)?;
    replacement.as_file().sync_all()?;
    let path = dir.join(HOST_FILE);
    if rotate {
        replacement.persist(&path)?;
    } else if let Err(err) = replacement.persist_noclobber(&path) {
        if err.error.kind() != io::ErrorKind::AlreadyExists {
            return Err(err.error.into());
        }
        return keys::public_key(&path).await;
    }
    std::fs::File::open(dir)?.sync_all()?;
    Ok(key)
}

pub(in crate::private) async fn rotate_host_key(dir: &Path) -> Result<String> {
    account().await?;
    let key = install_host_key(dir, true).await?;
    Ok(keys::fingerprint(&key))
}

pub(in crate::private) async fn host_info(dir: &Path) -> Result<Host> {
    let user = account().await?;
    ensure!(
        Path::new(SSHD).is_file(),
        "OpenSSH server executable is missing"
    );
    let path = dir.join(HOST_FILE);
    let key = match tokio::fs::try_exists(&path).await? {
        true => keys::public_key(&path).await?,
        false => install_host_key(dir, false).await?,
    };
    Ok(Host {
        user,
        key: Bytes(key),
    })
}

pub(in crate::private) struct Prepared {
    files: TempDir,
    user: String,
    #[cfg(target_os = "macos")]
    pair: (LocalStream, std::net::TcpStream),
}

#[cfg(any(test, target_os = "macos"))]
async fn audit_socket_pair() -> Result<(tokio::net::TcpStream, std::net::TcpStream)> {
    // Apple sshd needs an IP address for its audit session. The listener
    // exists only while we connect our own socket and close it before spawn.
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let local = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
    let (remote, peer) = listener.accept().await?;
    drop(listener);
    ensure!(
        peer == local.local_addr()?,
        "unexpected connection while preparing the OpenSSH audit socket"
    );
    let remote = remote.into_std()?;
    remote.set_nonblocking(false)?;
    Ok((local, remote))
}

impl Prepared {
    pub(in crate::private) async fn new(dir: &Path, key: &[u8; 32]) -> Result<Self> {
        let user = host_info(dir).await?.user;
        let files = tempfile::Builder::new()
            .prefix("massrelay-sshd-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(TEMP_DIR)?;
        tokio::fs::write(
            files.path().join("client.pub"),
            keys::public_line(key) + "\n",
        )
        .await?;
        #[cfg(target_os = "macos")]
        let pair = tokio::time::timeout(Duration::from_secs(2), audit_socket_pair()).await??;
        Ok(Self {
            files,
            user,
            #[cfg(target_os = "macos")]
            pair,
        })
    }

    fn command(&self, dir: &Path) -> Command {
        let mut command = Command::new(SSHD);
        command
            .args(["-e", "-f", "/dev/null"])
            .args([
                "-o",
                "PidFile=none",
                "-o",
                "AuthenticationMethods=publickey",
                "-o",
                "PubkeyAcceptedAlgorithms=ssh-ed25519",
                "-o",
                "AuthorizedKeysCommand=none",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                // PAM requires privileges on both Linux and macOS.
                "UsePAM=no",
                "-o",
                "PermitRootLogin=no",
                "-o",
                "DisableForwarding=yes",
                "-o",
                "PermitTunnel=no",
                "-o",
                "PermitUserRC=no",
                "-o",
                "LoginGraceTime=20",
                "-o",
                // The private configuration supplies SFTP even without the
                // system's external sftp-server subsystem.
                "Subsystem=sftp internal-sftp",
                // The authorized key is in our own mode-0700 directory
                // under /tmp. OpenSSH StrictModes rejects that ancestor.
                "-o",
                "StrictModes=no",
            ])
            .arg("-o")
            .arg(format!("AllowUsers={}", self.user))
            .arg("-o")
            .arg(session_environment())
            .arg("-h")
            .arg(dir.join(HOST_FILE))
            .arg("-o")
            .arg(format!(
                "AuthorizedKeysFile={}/client.pub",
                self.files.path().display()
            ))
            .env_clear()
            .kill_on_drop(true);
        command
    }

    #[cfg(test)]
    pub(in crate::private) async fn check_config(&self, dir: &Path) -> Result<()> {
        let output = self.command(dir).arg("-t").output().await?;
        ensure!(
            output.status.success(),
            "{SSHD} rejected the private configuration: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }

    // This runs under SessionHandle's startup lock. The daemon side is
    // asynchronous. OpenSSH gets blocking descriptors for its own side.
    pub(in crate::private) fn start(self, dir: &Path) -> Result<(LocalStream, Sshd)> {
        #[cfg(not(target_os = "macos"))]
        let (local, remote) = {
            let (local, remote) = StdStream::pair()?;
            local.set_nonblocking(true)?;
            (LocalStream::from_std(local)?, remote)
        };
        let stderr = if cfg!(test) {
            Stdio::inherit()
        } else {
            Stdio::null()
        };
        let mut command = self.command(dir);
        #[cfg(target_os = "macos")]
        let (local, remote) = self.pair;
        let child = command
            .arg("-i")
            .stdin(OwnedFd::from(remote.try_clone()?))
            .stdout(OwnedFd::from(remote))
            .stderr(stderr)
            .spawn()
            .context("start OpenSSH in inetd mode")?;
        Ok((
            local,
            Sshd {
                child,
                _files: self.files,
            },
        ))
    }
}

pub(in crate::private) struct Sshd {
    child: Child,
    _files: TempDir,
}

impl Sshd {
    pub(in crate::private) async fn reap(mut self) {
        // The connected socket has been dropped. Let OpenSSH handle its
        // own channel shutdown. Never signal detached workspace processes.
        if tokio::time::timeout(Duration::from_secs(1), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
        }
    }
}

#[cfg(test)]
#[tokio::test]
async fn ssh_audit_socket_only_accepts_the_connected_peer_after_preparation() {
    let (local, remote) = audit_socket_pair().await.unwrap();
    assert_eq!(remote.peer_addr().unwrap(), local.local_addr().unwrap());
    let address = remote.local_addr().unwrap();
    assert!(address.ip().is_loopback());
    assert_eq!(
        tokio::net::TcpStream::connect(address)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::ConnectionRefused
    );
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn ssh_only_exports_a_bus_in_the_accounts_private_runtime_directory() {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = directory.path();
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let bus = path.join("bus");
    assert!(!has_user_bus(path, uid));
    let listener = UnixListener::bind(&bus).unwrap();
    assert!(has_user_bus(path, uid));
    assert!(!has_user_bus(path, uid ^ 1));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(!has_user_bus(path, uid));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(listener);
    std::fs::rename(&bus, path.join("elsewhere")).unwrap();
    symlink(path.join("elsewhere"), &bus).unwrap();
    assert!(!has_user_bus(path, uid));
}
