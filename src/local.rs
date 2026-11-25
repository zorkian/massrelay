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
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::{
    storage, tcp, terminal, udp, visible,
    wire::{self, LocalReply, LocalRequest, Service},
};

const RUNTIME: &str = "runtime.json";
type Tag = Hmac<Sha256>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Runtime {
    addr: SocketAddr,
    key: [u8; 32],
}

pub async fn listen(dir: &Path) -> Result<(TcpListener, Runtime)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let runtime = Runtime {
        addr: listener.local_addr()?,
        key: wire::random()?,
    };
    storage::save(dir, RUNTIME, &runtime)?;
    Ok((listener, runtime))
}

fn proof(key: &[u8; 32], role: &[u8], challenge: &[u8; 32]) -> [u8; 32] {
    let mut mac = Tag::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(role);
    mac.update(challenge);
    mac.finalize().into_bytes().into()
}

pub async fn authenticate(socket: &mut TcpStream, runtime: &Runtime) -> Result<LocalRequest> {
    let mut response = [0; 32];
    socket.read_exact(&mut response).await?;
    socket
        .write_all(&proof(&runtime.key, b"massrelay daemon v1", &response))
        .await?;
    let challenge = wire::random()?;
    socket.write_all(&challenge).await?;
    socket.read_exact(&mut response).await?;
    ensure!(
        bool::from(response.ct_eq(&proof(&runtime.key, b"massrelay client v1", &challenge))),
        "local client authentication failed"
    );
    wire::recv(socket).await
}

async fn open(dir: &Path, request: LocalRequest) -> Result<(TcpStream, LocalReply)> {
    timeout(wire::RPC_TIMEOUT * 3, request_daemon(dir, request))
        .await
        .context("local request timed out")?
}

async fn request_daemon(dir: &Path, request: LocalRequest) -> Result<(TcpStream, LocalReply)> {
    let runtime: Runtime =
        storage::load(dir, RUNTIME).context("start massrelay run for this device")?;
    ensure!(runtime.addr.ip().is_loopback(), "invalid daemon address");
    let mut socket = TcpStream::connect(runtime.addr)
        .await
        .context("start massrelay run for this device")?;
    socket.set_nodelay(true)?;
    let challenge = wire::random()?;
    socket.write_all(&challenge).await?;
    let mut response = [0; 32];
    socket.read_exact(&mut response).await?;
    ensure!(
        bool::from(response.ct_eq(&proof(&runtime.key, b"massrelay daemon v1", &challenge))),
        "local daemon authentication failed"
    );
    socket.read_exact(&mut response).await?;
    socket
        .write_all(&proof(&runtime.key, b"massrelay client v1", &response))
        .await?;
    wire::send(&mut socket, request).await?;
    match wire::recv(&mut socket).await? {
        LocalReply::Error(error) => bail!("{error}"),
        reply => Ok((socket, reply)),
    }
}

pub async fn command(dir: &Path, request: LocalRequest) -> Result<LocalReply> {
    Ok(open(dir, request).await?.1)
}

pub async fn shell(dir: &Path, peer: String) -> Result<i32> {
    let (cols, rows) = terminal::size()?;
    let (socket, reply) = open(dir, LocalRequest::Shell { peer, cols, rows }).await?;
    ensure!(matches!(reply, LocalReply::Shell), "unexpected shell reply");
    let (rx, tx) = socket.into_split();
    terminal::attach(rx, tx, (cols, rows)).await
}

/// Forward a peer's port: TCP over standard input and output, or UDP through a loopback socket.
pub async fn connect(
    dir: &Path,
    peer: String,
    service: Service,
    listen: Option<u16>,
) -> Result<()> {
    let datagrams = match service {
        Service::Shell => bail!("use massrelay shell PEER for an interactive shell"),
        Service::Tcp(_) => {
            ensure!(listen.is_none(), "--listen applies to udp services");
            None
        }
        // Claim the local port before asking anything of the peer.
        Service::Udp(port) => Some(udp::listen(listen.unwrap_or(port.get())).await?),
    };

    // Keep an idle socket for the lifetime of the CLI. Its EOF can be read even if the separate
    // data socket is backed up, and it remains open through a TCP stdin half-close.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let lifetime_key = wire::random()?;
    let request = LocalRequest::Connect {
        peer: peer.clone(),
        service,
        lifetime_port: listener.local_addr()?.port(),
        lifetime_key,
    };
    let lifetime = async {
        let (mut socket, _) = listener.accept().await?;
        let mut response = [0; 32];
        socket.read_exact(&mut response).await?;
        ensure!(
            bool::from(response.ct_eq(&lifetime_key)),
            "invalid connection lifetime key"
        );
        Ok(socket)
    };
    let ((socket, reply), _lifetime) = timeout(wire::RPC_TIMEOUT * 3, async {
        tokio::try_join!(request_daemon(dir, request), lifetime)
    })
    .await
    .context("local request timed out")??;
    ensure!(
        matches!(reply, LocalReply::Connected),
        "unexpected connection reply"
    );

    if let Some(local) = datagrams {
        let addr = local.local_addr()?;
        eprintln!(
            "massrelay: forwarding {service} on {}; send datagrams to {addr}",
            visible(&peer)
        );
        udp::attach(socket, local).await
    } else {
        tcp::attach(socket).await
    }
}

/// Grant a peer a port until this command is interrupted or the grant is removed.
pub async fn expose(
    dir: &Path,
    service: Service,
    peer: String,
    target: Option<String>,
) -> Result<()> {
    let forwarding = match (&target, service) {
        (Some(target), _) => visible(target),
        (None, Service::Tcp(port) | Service::Udp(port)) => format!("loopback port {port}"),
        (None, Service::Shell) => bail!("only a port can be exposed"),
    };
    let request = LocalRequest::Expose {
        service,
        peer,
        target,
    };
    let (socket, reply) = open(dir, request).await?;
    let LocalReply::Exposed { peer, id } = reply else {
        bail!("unexpected exposure reply");
    };
    let (mut rx, mut tx) = socket.into_split();
    let ended = wire::recv::<LocalReply>(&mut rx);
    let interrupted = crate::shutdown();
    let announce = async {
        eprintln!(
            "massrelay: exposing {service} to {} ({id}), forwarding to {forwarding}, \
             until this command exits. Press Ctrl-C to stop.",
            visible(&peer)
        );
        std::future::pending::<Result<()>>().await
    };
    tokio::pin!(ended, interrupted);
    tokio::select! {
        // The signal handler is installed before the announcement invites an interrupt.
        biased;
        signal = &mut interrupted => {
            signal.context("wait for shutdown")?;
            // Wait for the daemon to confirm that the grant is gone.
            tx.shutdown().await?;
            let reply = timeout(wire::RPC_TIMEOUT, ended)
                .await
                .context("the daemon did not confirm that the exposure ended")??;
            ensure!(
                matches!(reply, LocalReply::Done | LocalReply::Error(_)),
                "unexpected exposure reply"
            );
            Ok(())
        }
        reply = &mut ended => match reply {
            Ok(LocalReply::Error(error)) => bail!("{error}"),
            _ => bail!("the local MassRelay daemon stopped, which ended the exposure"),
        },
        never = announce => never,
    }
}
