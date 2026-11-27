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
