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
pub async fn deliver(
    remote: &mut (impl AsyncRead + Unpin),
    local: &mut (impl AsyncWrite + Unpin),
    writing: &mut bool,
) -> Result<bool, Cut> {
    loop {
        let frame = wire::read_frame(remote).await.map_err(|_| Cut::Peer)?;
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
