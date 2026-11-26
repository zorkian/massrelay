//! Optional version reports over an encrypted connection after mutual pairing.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use iroh::{EndpointId, endpoint::Connection};
use serde::{Deserialize, Serialize};
use tokio::{task::JoinHandle, time::timeout};

use super::{
    diagnostics::{self, Level},
    pairing::Authorization,
};

const FILE: &str = "peer-versions.json";
const PREFIX: &[u8] = b"massrelay/version/1\0";
const MAX_VERSION: usize = 64;
const REPORT_WAIT: Duration = Duration::from_secs(2);
const SAVE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub version: String,
    /// Local observation time in seconds since the Unix epoch.
    pub observed_at: u64,
}

pub(super) type Observations = BTreeMap<EndpointId, Observation>;

pub(super) struct PeerVersions {
    dir: PathBuf,
    cache: Mutex<Cache>,
}

struct Cache {
    observations: Observations,
    last_save: Option<Instant>,
}

impl PeerVersions {
    pub fn open(dir: &Path) -> Self {
        Self {
            dir: dir.into(),
            cache: Mutex::new(Cache {
                observations: Self::read(dir),
                last_save: None,
            }),
        }
    }

    pub fn read(dir: &Path) -> Observations {
        let mut observations: Observations = crate::storage::load(dir, FILE).unwrap_or_default();
        observations.retain(|_, report| valid_version(&report.version));
        observations
    }

    pub fn observations(&self) -> Observations {
        self.cache
            .lock()
            .expect("peer versions")
            .observations
            .clone()
    }

    /// A separate unidirectional stream leaves the existing service stream
    /// unchanged. Older peers may ignore it without delaying a connection.
    pub fn exchange(self: &Arc<Self>, conn: &Connection, auth: &Authorization) -> Exchange {
        let (versions, conn, ended) = (self.clone(), conn.clone(), auth.watch_end());
        Exchange(tokio::spawn(async move {
            let exchange = async {
                let send = async {
                    let mut stream = conn.open_uni().await?;
                    let mut report = PREFIX.to_vec();
                    report.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());
                    stream.write_all(&report).await?;
                    stream.finish()?;
                    Ok::<_, anyhow::Error>(())
                };
                let receive = async {
                    let mut stream = conn.accept_uni().await.ok()?;
                    let body = stream.read_to_end(PREFIX.len() + MAX_VERSION).await.ok()?;
                    let version = decode_report(&body)?;
                    versions.remember(conn.remote_id(), version);
                    Some(())
                };
                let _ = tokio::join!(send, receive);
            };
            tokio::select! {
                biased;
                _ = ended => {}
                _ = timeout(REPORT_WAIT, exchange) => {}
            }
        }))
    }

    fn remember(&self, peer: EndpointId, version: &str) {
        let mut cache = self.cache.lock().expect("peer versions");
        let changed = cache
            .observations
            .get(&peer)
            .is_none_or(|last| last.version != version);
        let report = Observation {
            version: version.to_owned(),
            observed_at: crate::storage::now(),
        };
        cache.observations.insert(peer, report);
        if changed
            || cache
                .last_save
                .is_none_or(|last| last.elapsed() >= SAVE_INTERVAL)
        {
            // Keep live observations current. For an unchanged version, a periodic
            // checkpoint is enough for offline status and avoids fsync per connection.
            cache.last_save = Some(Instant::now());
            if crate::storage::save(&self.dir, FILE, &cache.observations).is_err() {
                diagnostics::quiet(Level::Warning, "could not save peer versions");
            }
        }
    }
}

pub(super) struct Exchange(JoinHandle<()>);

impl Drop for Exchange {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn valid_version(version: &str) -> bool {
    version.len() <= MAX_VERSION
        && version.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

fn decode_report(bytes: &[u8]) -> Option<&str> {
    let version = std::str::from_utf8(bytes.strip_prefix(PREFIX)?).ok()?;
    valid_version(version).then_some(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_require_the_protocol_and_a_bounded_printable_version() {
        assert_eq!(
            decode_report(&[PREFIX, b"0.5.1-rc.1"].concat()),
            Some("0.5.1-rc.1")
        );
        assert_eq!(decode_report(b"0.5.1"), None);
        assert_eq!(decode_report(&[PREFIX, b"0.5.1\nnext line"].concat()), None);
        assert_eq!(
            decode_report(&[PREFIX, &[b'1'; MAX_VERSION + 1]].concat()),
            None
        );
    }
}
