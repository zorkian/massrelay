use std::{io, net::SocketAddr, time::Duration};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointAddr, EndpointId, RelayUrl};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CONTROL: &[u8] = b"massrelay/control/1";
pub const SHELL: &[u8] = b"massrelay/shell/1";
pub const RPC_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_FRAME: usize = 1024 * 1024;

pub async fn send<T: Serialize>(writer: &mut (impl AsyncWrite + Unpin), value: T) -> Result<()> {
    let data = serde_json::to_vec(&value)?;
    frame(writer, &data).await
}

pub async fn recv<T: DeserializeOwned>(reader: &mut (impl AsyncRead + Unpin)) -> Result<T> {
    let bytes = read_frame(reader, MAX_FRAME).await?;
    serde_json::from_slice(&bytes).context("invalid message")
}

pub async fn frame(writer: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<()> {
    ensure!(data.len() <= MAX_FRAME, "frame exceeds size limit");
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(data).await?;
    Ok(())
}

pub async fn read_frame(
    reader: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> io::Result<Vec<u8>> {
    let len = reader.read_u32().await? as usize;
    if len > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds size limit",
        ));
    }
    let mut data = vec![0; len];
    reader.read_exact(&mut data).await?;
    Ok(data)
}

pub fn random() -> Result<[u8; 32]> {
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(secret)
}

pub fn token() -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(random()?))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerAddr {
    pub id: EndpointId,
    pub udp: SocketAddr,
    pub relay: RelayUrl,
}

impl ServerAddr {
    pub fn dial(&self, via_relay: bool) -> EndpointAddr {
        let addr = EndpointAddr::new(self.id).with_ip_addr(self.udp);
        if via_relay {
            addr.with_relay_url(self.relay.clone())
        } else {
            addr
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub server: ServerAddr,
    pub secret: String,
}

impl Ticket {
    pub fn encode(&self) -> Result<String> {
        Ok(format!(
            "mr1_{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?)
        ))
    }

    pub fn decode(text: &str) -> Result<Self> {
        let text = text.trim();
        let encoded = text
            .strip_prefix("mr1_")
            .context("expected a MassRelay ticket")?;
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded)?).context("invalid ticket")
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: EndpointId,
    pub name: String,
    pub addr: Option<EndpointAddr>,
    pub last_seen: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Approve,
    Decline,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct PairView {
    pub generation: u64,
    pub ours: Option<Decision>,
    pub theirs: Option<Decision>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Peer {
    pub member: Member,
    pub pair: PairView,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Roster {
    pub network: String,
    pub peers: Vec<Peer>,
}

#[derive(Serialize, Deserialize)]
pub enum Request {
    Enroll {
        secret: String,
        name: String,
        create: bool,
    },
    Sync {
        addr: EndpointAddr,
    },
    Invite,
    Pair {
        peer: EndpointId,
        decision: Decision,
        generation: u64,
    },
    Revoke {
        peer: EndpointId,
    },
}

#[derive(Serialize, Deserialize)]
pub enum Reply {
    Roster(Roster),
    Invite(String),
    Revoked,
    Error(String),
}

#[derive(Serialize, Deserialize)]
pub enum LocalRequest {
    Peers,
    Invite,
    Pair { peer: String, decision: Decision },
    Revoke { peer: String },
    Shell { peer: String, cols: u16, rows: u16 },
}

#[derive(Serialize, Deserialize)]
pub enum LocalReply {
    Peers(Vec<Peer>),
    Invite(String),
    Done,
    Shell,
    Error(String),
}

#[derive(Serialize, Deserialize)]
pub struct ShellRequest {
    pub network: String,
    pub generation: u64,
    pub cols: u16,
    pub rows: u16,
}
