use std::{fmt, io, net::SocketAddr, num::NonZeroU16, str::FromStr, time::Duration};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointAddr, EndpointId, RelayUrl};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CONTROL: &[u8] = b"massrelay/control/1";
/// Peer services. A destination checks a grant for every request made over this protocol.
pub const SERVICE: &[u8] = b"massrelay/service/1";
/// Connection close reasons with which a destination tells a peer why access ended.
pub const CLOSE_PAIRING_REQUIRED: &[u8] = b"pairing required";
pub const CLOSE_PAIRING_ENDED: &[u8] = b"pairing ended";
pub const CLOSE_GRANT_REMOVED: &[u8] = b"service grant removed";
pub const PAIRING_REQUIRED: &str = "both devices must approve this pairing";
pub const RPC_TIMEOUT: Duration = Duration::from_secs(10);
pub const INVALID_CREATE_TICKET: &str = "invalid create ticket";
pub const INVALID_JOIN_INVITE: &str = "invalid or already used invite";
pub const EXPIRED_INVITE: &str = "invite expired";
pub const NAME_IN_USE: &str = "name already in use";
/// A public relay locator names a relay. It carries no secret and grants no membership.
const LOCATOR_PREFIX: &str = "mrrelay1_";
/// Operator creation tickets and join invites share this secret-bearing format.
const TICKET_PREFIX: &str = "mr1_";

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

pub fn token() -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(random()?))
}

pub fn check_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "name must contain ASCII letters, digits, hyphens, or underscores"
    );
    ensure!(
        name.parse::<EndpointId>().is_err(),
        "name cannot be an endpoint ID"
    );
    Ok(())
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

fn encode(prefix: &str, value: &impl Serialize) -> Result<String> {
    Ok(format!(
        "{prefix}{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?)
    ))
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

    pub fn locator(&self) -> Result<String> {
        encode(LOCATOR_PREFIX, self)
    }

    pub fn from_locator(text: &str) -> Result<Self> {
        let encoded = text
            .trim()
            .strip_prefix(LOCATOR_PREFIX)
            .context("expected a MassRelay relay locator starting with mrrelay1_")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .context("invalid relay locator")?;
        serde_json::from_slice(&bytes).context("invalid relay locator")
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub server: ServerAddr,
    pub secret: String,
}

impl Ticket {
    pub fn encode(&self) -> Result<String> {
        encode(TICKET_PREFIX, self)
    }

    pub fn decode(text: &str) -> Result<Self> {
        let text = text.trim();
        let encoded = text
            .strip_prefix(TICKET_PREFIX)
            .context("expected a MassRelay ticket or invite starting with mr1_")?;
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
    /// Open creation on a shared relay. Membership and the first invite are issued together.
    /// Repeating it from the founder returns that invite while it remains unused and unexpired.
    Create {
        name: String,
    },
}

#[derive(Serialize, Deserialize)]
pub enum Reply {
    Roster(Roster),
    Invite(String),
    Revoked,
    Error(String),
    Created {
        /// The founder's registered name, which a retry cannot change.
        name: String,
        roster: Roster,
        invite: String,
    },
}

#[derive(Serialize, Deserialize)]
pub enum LocalRequest {
    Peers,
    Invite,
    Pair {
        peer: String,
        decision: Decision,
    },
    Revoke {
        peer: String,
    },
    Shell {
        peer: String,
        cols: u16,
        rows: u16,
    },
    /// Forward a TCP or UDP service on a peer through this command.
    Connect {
        peer: String,
        service: Service,
        lifetime_port: u16,
        lifetime_key: [u8; 32],
    },
    Enable {
        service: Service,
        peer: String,
    },
    Disable {
        service: Service,
        peer: String,
    },
    SetServiceDefault {
        service: Service,
        enabled: bool,
    },
    Grants,
    /// Grant a service for as long as the requesting command stays connected.
    Expose {
        service: Service,
        peer: String,
        target: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
pub enum LocalReply {
    Peers(Vec<Peer>),
    Invite(String),
    Done,
    Shell,
    Error(String),
    Connected,
    Grants(Vec<GrantView>),
    Exposed { peer: String, id: EndpointId },
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

/// A peer's request to use a service. It cannot choose what the destination connects to.
#[derive(Serialize, Deserialize)]
pub struct ServiceRequest {
    pub network: String,
    pub generation: u64,
    pub service: Service,
    /// The initial columns and rows of a shell.
    pub terminal: Option<(u16, u16)>,
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
