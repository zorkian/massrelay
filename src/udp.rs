//! Forward UDP datagrams over a session's stream. Each local sender gets its own association,
//! and so its own socket on the destination, which keeps replies with the sender they answer.

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU16,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinSet,
};

use crate::{
    tunnel::{self, Broken, Incoming},
    wire,
};

/// A frame kind and an association number precede each datagram's payload.
const HEADER: usize = 9;
/// Large enough for any UDP payload, so that receiving never truncates one.
const DATAGRAM: usize = 65_535;
/// The largest UDP forwarding frame the format can carry.
#[cfg_attr(not(feature = "private-membership"), allow(dead_code))]
pub const MAX_FRAME: usize = HEADER + DATAGRAM;

fn frame_header(association: u64) -> [u8; HEADER] {
    let mut header = [tunnel::DATA; HEADER];
    header[1..].copy_from_slice(&association.to_be_bytes());
    header
}

fn split_datagram(data: &[u8]) -> Option<(u64, &[u8])> {
    let (association, payload) = data.split_first_chunk()?;
    Some((u64::from_be_bytes(*association), payload))
}

/// Errors that report the fate of an earlier datagram, leaving the socket usable.
fn transient(error: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        error.kind(),
        ConnectionRefused
            | ConnectionReset
            | ConnectionAborted
            | HostUnreachable
            | NetworkUnreachable
            | NetworkDown
            | Interrupted
    )
}

async fn bind(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr).await?;
    // Some systems default to a send buffer too small for the largest datagrams.
    let options = socket2::SockRef::from(&socket);
    if options.send_buffer_size()? < DATAGRAM {
        options.set_send_buffer_size(DATAGRAM)?;
    }
    Ok(socket)
}

/// Choose the destination for datagrams, preferring IPv4 when a name has both kinds of address.
pub async fn resolve(port: NonZeroU16, target: Option<&str>) -> io::Result<SocketAddr> {
    let Some(target) = target else {
        return Ok((Ipv4Addr::LOCALHOST, port.get()).into());
    };
    let addresses: Vec<_> = tokio::net::lookup_host(target).await?.collect();
    addresses
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| addresses.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "the name has no address"))
}

pub async fn associate(target: SocketAddr, first: &[u8]) -> io::Result<UdpSocket> {
    let local: SocketAddr = match (target.is_ipv4(), target.ip().is_loopback()) {
        (true, true) => (Ipv4Addr::LOCALHOST, 0).into(),
        (true, false) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        (false, true) => (Ipv6Addr::LOCALHOST, 0).into(),
        (false, false) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = bind(local).await?;
    // A connected socket accepts datagrams only from the target.
    socket.connect(target).await?;
    send(&socket, first).await;
    Ok(socket)
}

pub async fn send(socket: &UdpSocket, payload: &[u8]) {
    // Delivery is not guaranteed beyond the tunnel, so a refused datagram is dropped.
    let _ = socket.send(payload).await;
}

/// Relay datagrams between the peer's stream and the target until either side fails.
pub async fn bridge<F: Future<Output = Result<UdpSocket, Broken>>>(
    rx: &mut (impl AsyncRead + Unpin),
    tx: &mut (impl AsyncWrite + Unpin),
    start_association: impl Fn(Vec<u8>) -> F,
) -> Result<(), Broken> {
    bridge_with(
        rx,
        tx,
        start_association,
        |socket, payload| async move {
            send(&socket, &payload).await;
            Ok(())
        },
        usize::MAX,
    )
    .await
}

/// `bridge` with a caller-supplied send for every later datagram of an
/// association (for example a guarded one), refusing peer frames longer
/// than `max_frame`.
pub async fn bridge_with<F, S>(
    rx: &mut (impl AsyncRead + Unpin),
    tx: &mut (impl AsyncWrite + Unpin),
    start_association: impl Fn(Vec<u8>) -> F,
    send_datagram: impl Fn(Arc<UdpSocket>, Vec<u8>) -> S,
    max_frame: usize,
) -> Result<(), Broken>
where
    F: Future<Output = Result<UdpSocket, Broken>>,
    S: Future<Output = Result<(), Broken>>,
{
    let (replies, mut queued) = mpsc::channel::<io::Result<Vec<u8>>>(8);
    // Dropping these closes every association's socket.
    let mut sockets = BTreeMap::<u64, Arc<UdpSocket>>::new();
    let mut readers = JoinSet::new();
    let upload = async {
        loop {
            let frame = wire::read_frame_max(rx, max_frame)
                .await
                .map_err(|_| Broken::Peer)?;
            let Some((&tunnel::DATA, data)) = frame.split_first() else {
                return Err::<(), _>(Broken::Peer);
            };
            let (association, payload) = split_datagram(data).ok_or(Broken::Peer)?;
            match sockets.get(&association) {
                Some(socket) => send_datagram(socket.clone(), payload.to_vec()).await?,
                None => {
                    let socket = Arc::new(start_association(payload.to_vec()).await?);
                    sockets.insert(association, socket.clone());
                    let (socket_rx, replies) = (socket.clone(), replies.clone());
                    readers.spawn(async move {
                        let mut buf = vec![0; HEADER + DATAGRAM];
                        buf[..HEADER].copy_from_slice(&frame_header(association));
                        loop {
                            let reply = match socket_rx.recv(&mut buf[HEADER..]).await {
                                Ok(size) => Ok(buf[..HEADER + size].to_vec()),
                                Err(error) if transient(&error) => continue,
                                Err(error) => Err(error),
                            };
                            let failed = reply.is_err();
                            if replies.send(reply).await.is_err() || failed {
                                return;
                            }
                        }
                    });
                }
            }
        }
    };
    let download = async {
        while let Some(reply) = queued.recv().await {
            let reply = reply.map_err(Broken::Target)?;
            wire::frame(tx, &reply).await.map_err(|_| Broken::Peer)?;
        }
        Ok(())
    };
    tokio::try_join!(upload, download).map(|_| ())
}

/// Open the loopback socket that local programs send to.
pub async fn listen(port: u16) -> Result<UdpSocket> {
    bind((Ipv4Addr::LOCALHOST, port).into())
        .await
        .with_context(|| {
            format!("listen on 127.0.0.1:{port}/udp; use --listen PORT to choose another port")
        })
}

/// Forward datagrams between local senders and an established session on the daemon socket.
pub async fn attach(socket: TcpStream, local: UdpSocket) -> Result<()> {
    let (mut rx, mut tx) = socket.into_split();
    // Association numbers index the addresses, in the order the senders first appeared.
    let senders = Mutex::new(Vec::<SocketAddr>::new());

    let receive = async {
        loop {
            let frame = wire::read_frame(&mut rx)
                .await
                .context("the local MassRelay daemon closed the connection")?;
            match tunnel::parse(&frame).context("invalid forwarding frame")? {
                Incoming::Data(data) => {
                    let (association, payload) =
                        split_datagram(data).context("invalid datagram frame")?;
                    let index = usize::try_from(association).context("invalid datagram frame")?;
                    let sender = senders
                        .lock()
                        .expect("sender list lock")
                        .get(index)
                        .copied();
                    let sender = sender.context("reply for an unknown sender")?;
                    // A reply that cannot be delivered locally is lost, as any datagram may be.
                    let _ = local.send_to(payload, sender).await;
                }
                Incoming::Done => return Ok(()),
                Incoming::Failed(message) => bail!("{message}"),
                Incoming::Eof => bail!("invalid forwarding frame"),
            }
        }
    };

    // This ends only if the local socket fails. A failed daemon write is explained by `receive`.
    let send = async {
        let mut associations = HashMap::<SocketAddr, u64>::new();
        let mut buf = vec![0; HEADER + DATAGRAM];
        loop {
            let (size, sender) = match local.recv_from(&mut buf[HEADER..]).await {
                Ok(received) => received,
                Err(error) if transient(&error) => continue,
                Err(error) => return Err(error).context("receive local datagrams"),
            };
            let association = *associations.entry(sender).or_insert_with(|| {
                let mut senders = senders.lock().expect("sender list lock");
                senders.push(sender);
                senders.len() as u64 - 1
            });
            buf[..HEADER].copy_from_slice(&frame_header(association));
            if wire::frame(&mut tx, &buf[..HEADER + size]).await.is_err() {
                return std::future::pending().await;
            }
        }
    };

    tokio::select! {
        result = receive => result,
        result = send => result,
    }
}
