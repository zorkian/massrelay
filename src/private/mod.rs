//! Encrypted membership, admission, and peer services.
//!
//! Devices verify the membership history locally and authorize each
//! connection against their accepted roster and service grants.
//!
//! Module map:
//!
//! - `codec`: canonical encodings and domain-separated hashes.
//! - `binding`: endpoint-key credential bindings and the joiner's proof.
//! - `envelope`: encrypted slots, signed transitions, invites, requests,
//!   replies and admission receipts.
//! - `policy`: the single parent-scoped policy author and recipients share.
//! - `store`: the profile lock, state row and per-epoch MLS files.
//! - `mailbox`: the opaque relay boundary (slot create/read, reply box).
//! - `relay_mailbox`: that boundary over the relay.
//! - `membership`: the state machine.
//! - `pairing`: peer approval, reciprocal consent per connection, grants,
//!   local cutoff and session invalidation over the accepted membership.
//! - `service`: private-ALPN connection handling and service dispatch over
//!   the existing shell, TCP and UDP code.
//! - `pty`: the native nonblocking PTY behind private shells (Unix and
//!   Windows ConPTY).
//! - `runtime`: the thin foreground runtime (owner, listener, authenticated
//!   local control on its own channel, outbound attach, ordered stop).
//! - `audit`: device state, control, and connection events.
//! - `cli`: top-level commands for the device profile.

pub mod audit;
pub mod binding;
pub mod cli;
pub mod codec;
pub mod envelope;
mod fault;
pub mod mailbox;
pub mod membership;
pub mod pairing;
pub mod policy;
pub mod pty;
mod routes;
pub mod runtime;
pub mod service;
pub mod store;

/// The real relay adapter, over the portable mailbox client.
pub mod relay_mailbox;

#[cfg(test)]
mod fake_mailbox;
#[cfg(all(test, unix))]
mod https_test;
#[cfg(all(test, unix))]
mod relay_tests;
#[cfg(test)]
mod tests;

use openmls::prelude::Ciphersuite;

/// Protocol label bound into every record and signature.
pub const PROTOCOL: &[u8] = b"massrelay-private/experimental-1";
/// Format of the profile state row.
pub const STATE_FORMAT: &str = "massrelay-private-membership/experimental-1";
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// Invite reservation window.
pub const INVITE_WINDOW_SECS: u64 = 600;
/// Tolerated backwards issuer clock step. Within it, the high-water mark is
/// used, so the effective time never decreases.
pub const CLOCK_ROLLBACK_TOLERANCE_SECS: u64 = 5;
/// Lifetime of a new join KeyPackage.
pub const KEY_PACKAGE_LIFETIME_SECS: u64 = 24 * 3600;
/// Cap on any admitted KeyPackage's lifetime range, enforced on every Add by
/// every replica.
pub const KEY_PACKAGE_MAX_LIFETIME_SECS: u64 = 7 * 24 * 3600;
