use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

use crate::{
    storage, tcp, udp, visible,
    wire::{self, Service},
};

type Tag = Hmac<Sha256>;

/// One local control channel: where its runtime marker lives and the role
/// labels its two-way proof binds. Distinct channels cannot authenticate to
/// each other even with the same key.
pub struct Channel {
    pub marker: &'static str,
    pub daemon_role: &'static [u8],
    pub client_role: &'static [u8],
    pub unavailable: &'static str,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Runtime {
    addr: SocketAddr,
    key: [u8; 32],
}

/// Bind the loopback control listener and publish its marker for `channel`.
pub async fn listen_on(dir: &Path, channel: &Channel) -> Result<(TcpListener, Runtime)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let runtime = Runtime {
        addr: listener.local_addr()?,
        key: wire::random()?,
    };
    storage::save_control_marker(dir, channel.marker, &runtime)?;
    Ok((listener, runtime))
}

fn proof(key: &[u8; 32], role: &[u8], challenge: &[u8; 32]) -> [u8; 32] {
    let mut mac = Tag::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(role);
    mac.update(challenge);
    mac.finalize().into_bytes().into()
}

/// Daemon side of the mutual proof on `channel`.
pub async fn authenticate_on(
    socket: &mut TcpStream,
    runtime: &Runtime,
    channel: &Channel,
) -> Result<()> {
    let mut response = [0; 32];
    socket.read_exact(&mut response).await?;
    socket
        .write_all(&proof(&runtime.key, channel.daemon_role, &response))
        .await?;
    let challenge = wire::random()?;
    socket.write_all(&challenge).await?;
    socket.read_exact(&mut response).await?;
    ensure!(
        bool::from(response.ct_eq(&proof(&runtime.key, channel.client_role, &challenge))),
        "local client authentication failed"
    );
    Ok(())
}

/// Client side: connect to the daemon published for `channel` and complete
/// the mutual proof. The caller sends its request next.
pub async fn connect_on(dir: &Path, channel: &Channel) -> Result<TcpStream> {
    let runtime: Runtime = storage::load(dir, channel.marker).context(channel.unavailable)?;
    ensure!(runtime.addr.ip().is_loopback(), "invalid daemon address");
    let mut socket = TcpStream::connect(runtime.addr)
        .await
        .context(channel.unavailable)?;
    socket.set_nodelay(true)?;
    let challenge = wire::random()?;
    socket.write_all(&challenge).await?;
    let mut response = [0; 32];
    socket.read_exact(&mut response).await?;
    ensure!(
        bool::from(response.ct_eq(&proof(&runtime.key, channel.daemon_role, &challenge))),
        "local daemon authentication failed"
    );
    socket.read_exact(&mut response).await?;
    socket
        .write_all(&proof(&runtime.key, channel.client_role, &response))
        .await?;
    Ok(socket)
}

/// The idle loopback socket a forwarding command keeps for its lifetime.
/// Its EOF can be read even if the data socket is backed up, and it stays
/// open through a TCP stdin half-close.
pub struct Lifetime {
    listener: TcpListener,
    pub port: u16,
    pub key: [u8; 32],
}

impl Lifetime {
    pub async fn bind() -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        Ok(Self {
            listener,
            port,
            key: wire::random()?,
        })
    }

    /// Accept the daemon's connection and check its key.
    pub async fn accept(&self) -> Result<TcpStream> {
        let (mut socket, _) = self.listener.accept().await?;
        let mut response = [0; 32];
        socket.read_exact(&mut response).await?;
        ensure!(
            bool::from(response.ct_eq(&self.key)),
            "invalid connection lifetime key"
        );
        Ok(socket)
    }
}

/// Daemon side: connect to a command's lifetime socket and prove the key.
pub async fn lifetime_connect(port: u16, key: &[u8; 32]) -> std::io::Result<TcpStream> {
    let mut lifetime = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    lifetime.write_all(key).await?;
    Ok(lifetime)
}

/// Claim the local endpoint of a port forward before anything is asked of
/// the peer: a loopback UDP socket for UDP, nothing for TCP (stdin/stdout).
pub async fn claim_forward(service: Service, listen: Option<u16>) -> Result<Option<UdpSocket>> {
    match service {
        Service::Shell => bail!("use massrelay shell PEER for an interactive shell"),
        Service::Tcp(_) => {
            ensure!(listen.is_none(), "--listen applies to udp services");
            Ok(None)
        }
        Service::Udp(port) => Ok(Some(udp::listen(listen.unwrap_or(port.get())).await?)),
    }
}

/// Run an established port forward on the command side.
pub async fn attach_forward(
    socket: TcpStream,
    datagrams: Option<UdpSocket>,
    peer: &str,
    service: Service,
) -> Result<()> {
    if let Some(local) = datagrams {
        let addr = local.local_addr()?;
        eprintln!(
            "massrelay: forwarding {service} on {}; send datagrams to {addr}",
            visible(peer)
        );
        udp::attach(socket, local).await
    } else {
        tcp::attach(socket).await
    }
}
