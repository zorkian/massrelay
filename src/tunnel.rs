//! Framing for forwarded ports. The same frames cross the peer stream and the local daemon socket,
//! so that a clean end is always explicit and anything else is reported as a failure.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::wire;

/// TCP bytes, or one UDP datagram preceded by its association number.
/// Why a destination could not finish forwarding.
pub enum Broken {
    /// The service being forwarded to failed.
    Target(std::io::Error),
    /// The peer's stream failed or ended without saying it was finished.
    Peer,
    /// The grant or pairing was removed.
    Denied(wire::Refusal),
}

pub const DATA: u8 = 1;
/// No more TCP bytes will follow in this direction. The other direction stays open.
pub const EOF: u8 = 2;
/// The destination finished both directions.
const DONE: u8 = 3;
/// The session failed. The rest of the frame explains why.
const FAILED: u8 = 4;

pub enum Incoming<'a> {
    Data(&'a [u8]),
    Eof,
    Done,
    Failed(String),
}

/// Interpret a frame arriving from the destination.
pub fn parse(frame: &[u8]) -> Option<Incoming<'_>> {
    match frame.split_first()? {
        (&DATA, data) => Some(Incoming::Data(data)),
        (&EOF, []) => Some(Incoming::Eof),
        (&DONE, []) => Some(Incoming::Done),
        (&FAILED, message) => Some(Incoming::Failed(
            String::from_utf8_lossy(message).into_owned(),
        )),
        _ => None,
    }
}

pub async fn done(writer: &mut (impl AsyncWrite + Unpin)) -> anyhow::Result<()> {
    wire::frame(writer, &[DONE]).await
}

pub async fn fail(writer: &mut (impl AsyncWrite + Unpin), message: &str) -> anyhow::Result<()> {
    let mut frame = vec![FAILED];
    frame.extend_from_slice(message.as_bytes());
    wire::frame(writer, &frame).await
}

/// Which side stopped a delivery before the destination ended the session.
pub enum Cut {
    Peer,
    Local,
}

/// Pass the destination's frames to the local command, through its final frame. Returns whether
/// the destination reported success. `writing` remains set if a local write was left unfinished.
/// A destination frame longer than `max_frame` cuts the delivery.
pub async fn deliver(
    remote: &mut (impl AsyncRead + Unpin),
    local: &mut (impl AsyncWrite + Unpin),
    writing: &mut bool,
    max_frame: usize,
) -> Result<bool, Cut> {
    loop {
        let frame = wire::read_frame_max(remote, max_frame)
            .await
            .map_err(|_| Cut::Peer)?;
        let last = match parse(&frame).ok_or(Cut::Peer)? {
            Incoming::Done => Some(true),
            Incoming::Failed(_) => Some(false),
            Incoming::Data(_) | Incoming::Eof => None,
        };
        *writing = true;
        wire::frame(local, &frame).await.map_err(|_| Cut::Local)?;
        *writing = false;
        if let Some(success) = last {
            return Ok(success);
        }
    }
}

/// Pass the local command's frames to the destination, returning once the command has gone. The
/// command never shuts down its side of the socket while it is still running.
pub async fn pump(local: &mut (impl AsyncRead + Unpin), remote: &mut (impl AsyncWrite + Unpin)) {
    let mut buf = [0; 8192];
    loop {
        match local.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(size) => {
                if remote.write_all(&buf[..size]).await.is_err() {
                    // Delivery from the destination reports why the stream failed.
                    std::future::pending::<()>().await;
                }
            }
        }
    }
}

/// How a local command's port forward ended (destination side of the CLI).
pub enum Forwarded {
    /// Authority ended (the `stopped` future resolved).
    Stopped,
    /// The destination reported success.
    Done,
    /// The destination reported a failure.
    Failed,
    /// The local command went away (its lifetime socket or upload ended).
    LocalClosed,
    /// The destination's stream failed without a final frame.
    PeerCut,
}

/// Bridge a local command's forwarding socket and a destination stream until
/// one of them ends or `stopped` resolves. The lifetime socket, not the
/// upload's EOF, signals that the command left, so a TCP half-close keeps the
/// other direction open. Polling order varies, so that a busy download cannot
/// hold back the upload. Destination frames longer than `max_frame` cut it.
#[allow(clippy::too_many_arguments)]
pub async fn forward(
    remote_rx: &mut (impl AsyncRead + Unpin),
    remote_tx: &mut (impl AsyncWrite + Unpin),
    local_rx: &mut (impl AsyncRead + Unpin),
    local_tx: &mut (impl AsyncWrite + Unpin),
    writing: &mut bool,
    local_closed: &mut (impl std::future::Future<Output = ()> + Unpin),
    stopped: impl std::future::Future<Output = ()>,
    max_frame: usize,
) -> Forwarded {
    tokio::select! {
        _ = stopped => Forwarded::Stopped,
        delivered = deliver(remote_rx, local_tx, writing, max_frame) => match delivered {
            Ok(true) => Forwarded::Done,
            Ok(false) => Forwarded::Failed,
            Err(Cut::Local) => Forwarded::LocalClosed,
            Err(Cut::Peer) => Forwarded::PeerCut,
        },
        _ = local_closed => Forwarded::LocalClosed,
        _ = pump(local_rx, remote_tx) => Forwarded::LocalClosed,
    }
}

/// After a forward ended for a reason other than the command leaving: tell
/// the command why if a frame can still be written, then drain its input so
/// closing cannot discard the final frame before the command reads it.
pub async fn finish_local(
    local_rx: &mut (impl AsyncRead + Unpin),
    local_tx: &mut (impl AsyncWrite + Unpin),
    writing: bool,
    message: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(message) = message {
        // After part of a frame, only closing the socket can report the failure.
        if writing {
            return Ok(());
        }
        fail(local_tx, message).await?;
    }
    tokio::io::copy(local_rx, &mut tokio::io::sink()).await?;
    Ok(())
}
