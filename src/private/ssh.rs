use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::mailbox::Bytes;

const INFO: [u8; 8] = [1, 7, 0, 0, 0, 0, 0, 0];
const TUNNEL: [u8; 8] = [1, 8, 0, 0, 0, 0, 0, 0];

#[derive(Clone, Copy)]
pub(super) enum Request {
    Info,
    Tunnel(Bytes<32>),
}

impl Request {
    pub(super) fn header(self) -> &'static [u8; 8] {
        match self {
            Self::Info => &INFO,
            Self::Tunnel(_) => &TUNNEL,
        }
    }
}

pub(super) fn is_info(header: &[u8]) -> bool {
    header == INFO
}

pub(super) fn is_tunnel(header: &[u8]) -> bool {
    header == TUNNEL
}

/// How the runtime keeps its OpenSSH client entries (see `managed`).
#[derive(Clone, Debug)]
pub struct Settings {
    /// How often the opt-in file and this device's peers are checked.
    pub check_every: Duration,
    /// How long a confirmation is used before the peer is asked again.
    pub refresh_every: Duration,
    /// First wait after any other answer; it doubles up to `refresh_every`.
    pub retry_after: Duration,
    /// Bound on one request to a peer.
    pub probe_deadline: Duration,
    /// Program the entries' `ProxyCommand` runs (`None`: the runtime's own).
    pub program: Option<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            check_every: Duration::from_secs(5),
            refresh_every: Duration::from_secs(300),
            retry_after: Duration::from_secs(30),
            probe_deadline: crate::wire::RPC_TIMEOUT * 2,
            program: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub user: String,
    pub key: Bytes<32>,
}

impl Host {
    // The username uses only these ASCII characters. The key uses the
    // existing base64 Bytes encoding. No credentials appear in errors.
    pub(super) const MAX_REPLY: usize = 160;

    pub(super) fn valid_user(user: &str) -> bool {
        !user.is_empty()
            && user.len() <= 64
            && !user.starts_with('-')
            && user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    }
}

#[cfg(any(unix, windows))]
mod client;
#[cfg(any(unix, windows))]
pub(super) use client::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod server;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) use server::*;

#[cfg(windows)]
mod windows;
#[cfg(all(test, windows))]
pub(super) use windows::worker_executable;
#[cfg(windows)]
pub(super) use windows::{Prepared, Sshd, host_info, rotate_host_key, worker_ready};
#[cfg(windows)]
pub(crate) use windows::{WORKER_ARG, run_worker};

#[cfg(any(unix, windows))]
mod keys;

#[cfg(any(unix, windows))]
mod managed;
#[cfg(any(unix, windows))]
pub(super) use managed::maintain;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(crate) use keys::openssh;
