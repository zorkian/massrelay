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
    storage, terminal,
    wire::{self, LocalReply, LocalRequest},
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
    let runtime: Runtime =
        storage::load(dir, RUNTIME).context("start massrelay run for this device")?;
    ensure!(runtime.addr.ip().is_loopback(), "invalid daemon address");
    timeout(wire::RPC_TIMEOUT * 3, async {
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
    })
    .await
    .context("local request timed out")?
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
