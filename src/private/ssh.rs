//! SSH to paired peers through the peer's own system OpenSSH server.
//!
//! The destination (`server`) forwards one authorized connection to the installed system
//! server on `127.0.0.1`, authorizing the connecting device's key for it in a dedicated key
//! file (`lease`). Account login, shells, subsystems and host policy are the system server's.
//! The initiator (`client`, `managed`) runs stock OpenSSH over a private `ProxyCommand`.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::mailbox::Bytes;

use super::diagnostics::{self, Level};

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

/// How the runtime serves SSH: its OpenSSH client entries (see `managed`) and the keys of
/// inbound tunnels (see `lease`).
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
    /// How long a tunnel's client key stays authorized on this device, unless the tunnel
    /// ends first.
    pub lease: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            check_every: Duration::from_secs(5),
            refresh_every: Duration::from_secs(300),
            retry_after: Duration::from_secs(30),
            probe_deadline: crate::wire::RPC_TIMEOUT * 2,
            program: None,
            // The system server's default limit on an unauthenticated connection.
            lease: Duration::from_secs(120),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub user: String,
    pub key: Bytes<32>,
    /// `key` belongs to the destination's system SSH server. A destination that predates
    /// this runs a server of MassRelay's own and does not say.
    #[serde(default)]
    pub system: bool,
}

impl Host {
    // The username uses only a few ASCII characters, at most one of which JSON escapes.
    // The key uses the existing base64 Bytes encoding. No credentials appear in errors.
    pub(super) const MAX_REPLY: usize = 160;

    /// An account name that stock OpenSSH accepts from a quoted `User` line: letters,
    /// digits and `_.-@`, inner spaces (Windows accounts), and one `DOMAIN\name` backslash.
    pub(super) fn valid_user(user: &str) -> bool {
        !user.is_empty()
            && user.len() <= 64
            && !user.starts_with(['-', ' ', '\\'])
            && !user.ends_with([' ', '\\'])
            && !user.contains(" -")
            && !user.contains(" \\")
            && !user.contains("\\ ")
            && user.matches('\\').count() <= 1
            && user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-@ \\".contains(&b))
    }
}

/// A local failure of this device's SSH setup: fixed text in the system log, with the
/// cause only on a console.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(super) fn warn(what: &'static str, error: &anyhow::Error) {
    diagnostics::quiet(Level::Warning, what);
    if diagnostics::console() {
        eprintln!("massrelay: {what}: {error:#}");
    }
}

#[cfg(any(unix, windows))]
mod client;
#[cfg(any(unix, windows))]
pub(super) use client::*;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod lease;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod server;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(super) use server::*;

#[cfg(any(unix, windows))]
mod keys;

#[cfg(any(unix, windows))]
mod managed;
#[cfg(any(unix, windows))]
pub(super) use managed::maintain;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(crate) use keys::openssh;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_names_cannot_add_options_and_their_records_stay_bounded() {
        for user in [
            "mark",
            "first.last",
            "John Smith",
            r"CORP\jsmith",
            "me@example.com",
        ] {
            assert!(Host::valid_user(user), "{user}");
        }
        for user in [
            "",
            "-oProxyCommand=x",
            "a -oX",
            " lead",
            "trail ",
            r"trail\",
            r"a\b\c",
            r"a \b",
            "a\"b",
            "a\nProxyCommand x",
            "a'b",
            "a;b",
            "%h",
            "a#b",
        ] {
            assert!(!Host::valid_user(user), "{user:?}");
        }
        let longest = Host {
            user: format!(r"a\{}", "b".repeat(62)),
            key: Bytes([0xff; 32]),
            system: true,
        };
        assert!(Host::valid_user(&longest.user));
        assert!(serde_json::to_vec(&longest).unwrap().len() <= Host::MAX_REPLY);
        // A destination that predates the system server says nothing about it.
        let former = serde_json::json!({"user": "mark", "key": Bytes([1; 32])});
        assert!(!serde_json::from_value::<Host>(former).unwrap().system);
    }
}
