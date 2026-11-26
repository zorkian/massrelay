//! Forward one TCP connection, preserving each direction's end of file.

use std::{
    fs::File,
    io::{self, Read},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU16,
    thread,
};

use anyhow::{Context, Result, anyhow, bail};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};

use crate::{
    tunnel::{self, Broken, Incoming},
    wire,
};

const CHUNK: usize = 8192;
/// The largest TCP forwarding frame any MassRelay sender produces.
#[cfg_attr(not(feature = "private-membership"), allow(dead_code))]
pub const MAX_FRAME: usize = CHUNK + 1;

/// Connect to the owner's chosen address, or else to either loopback address.
pub async fn dial(port: NonZeroU16, target: Option<&str>) -> io::Result<TcpStream> {
    let stream = match target {
        Some(target) => TcpStream::connect(target).await?,
        None => {
            let ipv4 = SocketAddr::from((Ipv4Addr::LOCALHOST, port.get()));
            match TcpStream::connect(ipv4).await {
                Ok(stream) => stream,
                Err(error) => TcpStream::connect((Ipv6Addr::LOCALHOST, port.get()))
                    .await
                    .map_err(|_| error)?,
            }
        }
    };
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Copy between the peer's stream and the target until both directions end.
pub async fn bridge(
    rx: &mut (impl AsyncRead + Unpin),
    tx: &mut (impl AsyncWrite + Unpin),
    target: &mut TcpStream,
) -> Result<(), Broken> {
    bridge_with(rx, tx, target, usize::MAX).await
}

/// `bridge` over any target stream (for example one whose writes are
/// guarded), refusing peer frames longer than `max_frame`.
pub async fn bridge_with(
    rx: &mut (impl AsyncRead + Unpin),
    tx: &mut (impl AsyncWrite + Unpin),
    target: &mut (impl AsyncRead + AsyncWrite + Unpin),
    max_frame: usize,
) -> Result<(), Broken> {
    let (mut target_rx, mut target_tx) = tokio::io::split(target);
    // A failed write must not discard what the target already sent, so it is reported at the end.
    let upload = async {
        loop {
            let frame = wire::read_frame_max(rx, max_frame)
                .await
                .map_err(|_| Broken::Peer)?;
            match frame.split_first() {
                Some((&tunnel::DATA, data)) => {
                    if let Err(error) = target_tx.write_all(data).await {
                        return Ok(Some(error));
                    }
                }
                Some((&tunnel::EOF, [])) => {
                    return Ok(match target_tx.shutdown().await {
                        Err(error) if error.kind() != io::ErrorKind::NotConnected => Some(error),
                        _ => None,
                    });
                }
                _ => return Err(Broken::Peer),
            }
        }
    };
    let download = async {
        let mut buf = [0; CHUNK + 1];
        loop {
            let size = target_rx
                .read(&mut buf[1..])
                .await
                .map_err(Broken::Target)?;
            buf[0] = if size == 0 { tunnel::EOF } else { tunnel::DATA };
            wire::frame(tx, &buf[..size + 1])
                .await
                .map_err(|_| Broken::Peer)?;
            if size == 0 {
                return Ok(());
            }
        }
    };
    match tokio::try_join!(upload, download)? {
        (Some(error), ()) => Err(Broken::Target(error)),
        (None, ()) => Ok(()),
    }
}

/// Take ownership of standard output, so that closing it passes the remote end of file on to
/// whatever is reading. Call this at most once, and write nothing else to standard output.
fn take_stdout() -> File {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        // SAFETY: the caller hands this descriptor over for the rest of the process.
        unsafe { File::from_raw_fd(io::stdout().as_raw_fd()) }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        // SAFETY: the caller hands this handle over for the rest of the process.
        unsafe { File::from_raw_handle(io::stdout().as_raw_handle()) }
    }
}

/// Connect standard input and output to an established session on the daemon socket.
pub async fn attach(socket: TcpStream) -> Result<()> {
    let (mut rx, mut tx) = socket.into_split();
    let (input_tx, mut input_rx) = mpsc::channel::<io::Result<Vec<u8>>>(8);
    thread::Builder::new()
        .name("massrelay-stdin".into())
        .spawn(move || {
            // This CLI process can exit even while the input thread is waiting for more input.
            let mut stdin = io::stdin().lock();
            let mut buf = [0; CHUNK + 1];
            loop {
                let data = match stdin.read(&mut buf[1..]) {
                    Ok(0) => break,
                    Ok(size) => {
                        buf[0] = tunnel::DATA;
                        Ok(buf[..size + 1].to_vec())
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        let _ = input_tx.blocking_send(Err(error));
                        break;
                    }
                };
                if input_tx.blocking_send(data).is_err() {
                    break;
                }
            }
        })?;

    let receive = async {
        let mut stdout = Some(tokio::fs::File::from_std(take_stdout()));
        loop {
            let frame = wire::read_frame(&mut rx)
                .await
                .context("the local MassRelay daemon closed the connection")?;
            match tunnel::parse(&frame).context("invalid forwarding frame")? {
                Incoming::Data(data) => {
                    let stdout = stdout.as_mut().context("data followed end of file")?;
                    stdout.write_all(data).await.context("write to stdout")?;
                    stdout.flush().await.context("write to stdout")?;
                }
                Incoming::Eof => drop(stdout.take()),
                Incoming::Done => return Ok(()),
                Incoming::Failed(message) => bail!("{message}"),
            }
        }
    };

    // This ends only if local input fails. Otherwise the daemon decides when the session is over.
    let send = async {
        while let Some(data) = input_rx.recv().await {
            match data {
                Ok(data) => {
                    if wire::frame(&mut tx, &data).await.is_err() {
                        return std::future::pending().await;
                    }
                }
                Err(error) => return anyhow!(error).context("read stdin"),
            }
        }
        // A failed write is explained by the daemon's final frame.
        let _ = wire::frame(&mut tx, &[tunnel::EOF]).await;
        std::future::pending().await
    };

    tokio::select! {
        result = receive => result,
        error = send => Err(error),
    }
}
