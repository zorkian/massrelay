use std::{fmt, io, net::SocketAddr, num::NonZeroU16, str::FromStr, time::Duration};

use anyhow::{Context, Result, ensure};
use iroh::{EndpointAddr, EndpointId, RelayUrl};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// Retired protocol identifiers are only used in downgrade tests.
#[cfg(test)]
pub const CONTROL: &[u8] = b"massrelay/control/1";
#[cfg(test)]
pub const SERVICE: &[u8] = b"massrelay/service/1";
pub const RPC_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn send<T: Serialize>(writer: &mut (impl AsyncWrite + Unpin), value: T) -> Result<()> {
    let data = serde_json::to_vec(&value)?;
    frame(writer, &data).await
}

pub async fn recv<T: DeserializeOwned>(reader: &mut (impl AsyncRead + Unpin)) -> Result<T> {
    let bytes = read_frame(reader).await?;
    serde_json::from_slice(&bytes).context("invalid message")
}

pub async fn frame(writer: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len()).context("frame length does not fit the wire format")?;
    writer.write_u32(len).await?;
    writer.write_all(data).await?;
    Ok(())
}

pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    read_frame_max(reader, usize::MAX).await
}

/// `read_frame`, refusing a frame longer than `max` (the largest frame the
/// format can legitimately carry) before reading its body.
pub async fn read_frame_max(
    reader: &mut (impl AsyncRead + Unpin),
    max: usize,
) -> io::Result<Vec<u8>> {
    let len = reader.read_u32().await?;
    if len as usize > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame longer than the format allows",
        ));
    }
    // Grow the buffer as bytes arrive rather than allocating the advertised length up front.
    let mut data = Vec::new();
    reader.take(u64::from(len)).read_to_end(&mut data).await?;
    if data.len() != len as usize {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete frame",
        ));
    }
    Ok(data)
}

pub fn random() -> Result<[u8; 32]> {
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(secret)
}

/// Check an exposure target's form. Its host is resolved later, on the exposing device.
pub fn check_target(target: &str) -> Result<()> {
    let named = || {
        target.rsplit_once(':').is_some_and(|(host, port)| {
            !host.is_empty()
                && !host.contains(|c: char| matches!(c, ':' | '[' | ']') || c.is_whitespace())
                && port.parse::<NonZeroU16>().is_ok()
        })
    };
    ensure!(
        target
            .parse::<SocketAddr>()
            .map_or_else(|_| named(), |addr| addr.port() != 0),
        "expected a target as HOST:PORT, with brackets around an IPv6 address"
    );
    Ok(())
}

/// Something a destination can let a peer use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum Service {
    Shell,
    Tcp(NonZeroU16),
    Udp(NonZeroU16),
}

impl fmt::Display for Service {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shell => out.write_str("shell"),
            Self::Tcp(port) => write!(out, "tcp:{port}"),
            Self::Udp(port) => write!(out, "udp:{port}"),
        }
    }
}

impl FromStr for Service {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let service = match text.split_once(':') {
            None if text == "shell" => Some(Self::Shell),
            Some(("tcp", port)) => port.parse().ok().map(Self::Tcp),
            Some(("udp", port)) => port.parse().ok().map(Self::Udp),
            _ => None,
        };
        service.ok_or_else(|| {
            "expected shell, tcp:PORT, or udp:PORT, with a port from 1 to 65535".into()
        })
    }
}

impl From<Service> for String {
    fn from(service: Service) -> Self {
        service.to_string()
    }
}

impl TryFrom<String> for Service {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        text.parse()
    }
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
pub struct Member {
    pub id: EndpointId,
    pub name: String,
    pub addr: Option<EndpointAddr>,
    pub last_seen: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct GrantView {
    pub service: Service,
    pub peer: Option<String>,
    pub id: Option<EndpointId>,
    pub temporary: bool,
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<GrantRule>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum GrantRule {
    Default,
    Excluded,
}

#[derive(Serialize, Deserialize)]
pub enum ServiceReply {
    Ready,
    Refused { refusal: Refusal, message: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    PairingRequired,
    ServiceNotEnabled,
    TargetUnavailable,
}

impl Refusal {
    /// The reason recorded in the connection log.
    pub fn reason(self) -> &'static str {
        match self {
            Self::PairingRequired => "pairing_required",
            Self::ServiceNotEnabled => "service_not_enabled",
            Self::TargetUnavailable => "target_unavailable",
        }
    }
}
