use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdStream;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use tempfile::{NamedTempFile, TempDir};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

use crate::mailbox::Bytes;

use super::{Host, keys};

const SSHD: &str = "/usr/sbin/sshd";
const HOST_FILE: &str = "ssh-host-ed25519";
const TEMP_DIR: &str = "/tmp";

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
        Ok(Self { files, user })
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
            .arg(format!(
                "SetEnv={}={}",
                crate::private::HOST_ENV,
                std::process::id()
            ))
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
    pub(in crate::private) fn start(self, dir: &Path) -> Result<(UnixStream, Sshd)> {
        let (local, remote) = StdStream::pair()?;
        local.set_nonblocking(true)?;
        let local = UnixStream::from_std(local)?;
        let stderr = if cfg!(test) {
            Stdio::inherit()
        } else {
            Stdio::null()
        };
        let child = self
            .command(dir)
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
