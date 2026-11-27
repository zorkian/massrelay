//! The destination side: the installed system SSH server, reached only on `127.0.0.1`.
//!
//! The installer describes that server in the profile (`crate::host_ssh`). Without the
//! description this device offers no SSH. It is read for every request, under the lock the
//! installer holds while changing it, so removal takes effect at once. This module starts no
//! server, changes no host configuration and never touches the server's host keys.

use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};
use tokio::net::TcpStream;

use crate::mailbox::Bytes;

use super::super::binding::EndpointKey;
use super::super::codec::hex;
use super::super::pairing::{Refusal, SessionHandle};
use super::{Host, Settings, keys, lease};

/// The installer's description of the server, in the private profile.
const DESCRIPTION: &str = "ssh-server.json";
/// Bound on this device's open tunnels, and so on its lines in the key file.
const MAX_TUNNELS: usize = 256;

/// A validated description of this device's system SSH server.
#[derive(PartialEq, Eq)]
pub(in crate::private) struct Target {
    user: String,
    port: u16,
    host_key: [u8; 32],
}

impl Target {
    /// This device's server, with the lock under which it was read.
    async fn locked(profile: &Path) -> Result<(Self, lease::Lock)> {
        // Nothing is created in a profile that was never set up.
        ensure!(
            profile.join(DESCRIPTION).try_exists()?,
            "no system SSH server is set up for this profile"
        );
        let lock = lease::Lock::acquire(profile).await?;
        let server = crate::host_ssh::Server::load(profile)?;
        ensure!(
            Host::valid_user(&server.user),
            "unsupported SSH account name"
        );
        ensure!(server.port != 0, "invalid SSH server port");
        let file = &server.authorized_keys;
        ensure!(
            file.file_name() == Some(lease::KEY_FILE.as_ref())
                && file.parent().and_then(|dir| dir.canonicalize().ok())
                    == Some(profile.canonicalize()?),
            "the SSH key file must be {} in this profile",
            lease::KEY_FILE
        );
        let target = Self {
            host_key: keys::parse_public_line(&server.host_key)
                .context("read the system SSH host key")?,
            user: server.user,
            port: server.port,
        };
        Ok((target, lock))
    }

    pub(in crate::private) async fn load(profile: &Path) -> Result<Self> {
        Ok(Self::locked(profile).await?.0)
    }

    /// Whether an install described a server to this profile at all.
    pub(in crate::private) fn described(profile: &Path) -> bool {
        profile.join(DESCRIPTION).exists()
    }

    pub(in crate::private) fn host(&self) -> Host {
        Host {
            user: self.user.clone(),
            key: Bytes(self.host_key),
            system: true,
        }
    }

    pub(in crate::private) async fn connect(&self) -> io::Result<TcpStream> {
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port)).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

/// A connection to the SSH server, as both of its ends name it: (our end, the server's).
type Ends = (SocketAddrV4, SocketAddrV4);

/// This runtime's tunnels into the system SSH server.
pub(in crate::private) struct Destination {
    /// Tags this profile's lines in the key file.
    owner: String,
    lifetime: Mutex<Duration>,
    open: Arc<Mutex<HashSet<Ends>>>,
    keys: Arc<lease::Withdrawals>,
}

/// One open tunnel. Dropping it withdraws its key, then forgets its connection.
pub(in crate::private) struct Tunnel {
    // Declared first, so it is withdrawn first.
    lease: Option<lease::Lease>,
    _open: Open,
}

struct Open {
    all: Arc<Mutex<HashSet<Ends>>>,
    ends: Ends,
}

impl Drop for Open {
    fn drop(&mut self) {
        if let Ok(mut all) = self.all.lock() {
            all.remove(&self.ends);
        }
    }
}

impl Tunnel {
    /// Withdraw the key and keep the connection, which has had its time to authenticate.
    pub(in crate::private) fn expire(&mut self) {
        self.lease = None;
    }
}

impl Destination {
    pub(in crate::private) fn new(endpoint: &EndpointKey, profile: &Path) -> Self {
        Self {
            owner: hex(&endpoint[..16]),
            lifetime: Mutex::new(Settings::default().lease),
            open: Arc::default(),
            keys: lease::Withdrawals::new(profile),
        }
    }

    pub(in crate::private) fn set_lifetime(&self, lifetime: Duration) {
        *self.lifetime.lock().expect("SSH lifetime") = lifetime;
    }

    pub(in crate::private) fn lifetime(&self) -> Duration {
        *self.lifetime.lock().expect("SSH lifetime")
    }

    /// Withdraw keys an earlier run of this profile left behind. Only before any tunnel,
    /// within the async runtime. It does not wait for the setup lock.
    pub(in crate::private) fn purge(&self) {
        if let Err(error) = lease::purge(&self.keys, &self.owner) {
            super::warn("could not withdraw earlier SSH tunnel keys", &error);
        }
    }

    /// Give keys still being withdrawn at most `grace`, then stop trying. Only after the
    /// tunnels have ended.
    pub(in crate::private) async fn close(&self, grace: Duration) {
        if !self.keys.close(grace).await {
            super::warn(
                "an SSH tunnel's key was left to expire",
                &anyhow!("it could not be withdrawn before stopping"),
            );
        }
    }

    /// Record `stream`, a connection to the SSH server, as a tunnel of this runtime.
    pub(in crate::private) fn register(&self, stream: &TcpStream) -> Result<Tunnel> {
        let v4 = |address| match address {
            SocketAddr::V4(address) => Ok(address),
            SocketAddr::V6(_) => Err(anyhow::anyhow!("the SSH connection is not IPv4")),
        };
        let ends = (v4(stream.local_addr()?)?, v4(stream.peer_addr()?)?);
        let mut open = self.open.lock().expect("SSH tunnels");
        ensure!(open.len() < MAX_TUNNELS, "too many open SSH tunnels");
        ensure!(open.insert(ends), "the SSH connection is already recorded");
        Ok(Tunnel {
            lease: None,
            _open: Open {
                all: self.open.clone(),
                ends,
            },
        })
    }

    /// Authorize `key` for `tunnel`, which is connected to `target`, while `session` is
    /// authorized. The server must still be described as it was when connected.
    pub(in crate::private) async fn authorize(
        &self,
        tunnel: &mut Tunnel,
        session: &SessionHandle,
        profile: &Path,
        target: &Target,
        key: &[u8; 32],
    ) -> Result<Result<()>, Refusal> {
        let deadline = Instant::now() + lease::WAIT;
        loop {
            let current = Target::locked(profile).await.and_then(|(current, lock)| {
                ensure!(current == *target, "the SSH server setup changed");
                Ok(lock)
            });
            let lock = match current {
                Ok(lock) => lock,
                Err(error) => return Ok(Err(error)),
            };
            let (owner, lifetime) = (&self.owner, self.lifetime());
            let granted = lease::grant(&lock, session, &self.keys, owner, key, lifetime)?;
            // Released first: a lease takes the lock again when dropped.
            drop(lock);
            match granted {
                Ok(lease::Grant::Made(lease)) => {
                    tunnel.lease = Some(lease);
                    return Ok(Ok(()));
                }
                Ok(lease::Grant::Blocked(error)) if Instant::now() >= deadline => {
                    return Ok(Err(anyhow!(error).context("replace the SSH key file")));
                }
                Ok(lease::Grant::Blocked(_)) => tokio::time::sleep(lease::RETRY).await,
                Err(error) => return Ok(Err(error)),
            }
        }
    }

    /// Whether the connection with exactly these ends is one of the open tunnels.
    pub(in crate::private) fn owns(&self, client: SocketAddrV4, server: SocketAddrV4) -> bool {
        self.open
            .lock()
            .is_ok_and(|open| open.contains(&(client, server)))
    }
}
