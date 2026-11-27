//! Optional version and name reports over an encrypted connection after mutual pairing.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use iroh::{EndpointId, endpoint::Connection};
use serde::{Deserialize, Serialize};
use tokio::{task::JoinHandle, time::timeout};

use super::{
    binding::{MAX_DEVICE_NAME, check_device_name},
    diagnostics::{self, Level},
    mailbox::Mailbox,
    membership::Device,
    pairing::Authorization,
};

const FILE: &str = "peer-versions.json";
const PREFIX: &[u8] = b"massrelay/version/1\0";
const NAME_FILE: &str = "device-name.json";
const NAME_PREFIX: &[u8] = b"massrelay/name/1\0";
const REVISION_BYTES: usize = size_of::<u64>();
const MAX_VERSION: usize = 64;
const REPORT_WAIT: Duration = Duration::from_secs(2);
const SAVE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub version: String,
    /// Local observation time in seconds since the Unix epoch.
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<Name>,
}

impl Observation {
    pub fn name(&self) -> Option<&str> {
        self.name.as_ref().map(|report| report.value.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Name {
    revision: u64,
    value: String,
}

impl Name {
    fn valid(&self) -> bool {
        self.revision != 0 && check_device_name(&self.value).is_ok()
    }
}

fn local_name(dir: &Path) -> Result<Option<Name>> {
    let report: Name = match crate::storage::load(dir, NAME_FILE) {
        Ok(report) => report,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    anyhow::ensure!(report.valid(), "invalid saved device name");
    Ok(Some(report))
}

pub(super) fn local_display_name(dir: &Path) -> Result<Option<String>> {
    Ok(local_name(dir)?.map(|report| report.value))
}

/// The caller holds the profile owner and, for a running owner, its stop gate.
pub(super) fn rename_self<M: Mailbox>(device: &Device<M>, name: &str) -> Result<()> {
    check_device_name(name).map_err(anyhow::Error::msg)?;
    let state = device.state().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    anyhow::ensure!(
        state.net.is_some() && state.terminal.is_none(),
        "join a network before renaming this device"
    );
    let dir = device.store().dir();
    let last = local_name(dir)?;
    if last.as_ref().is_some_and(|report| report.value == name) {
        return Ok(());
    }
    let revision = last.map_or(0, |report| report.revision);
    let report = Name {
        revision: revision
            .checked_add(1)
            .context("device name revision exhausted")?,
        value: name.to_owned(),
    };
    crate::storage::save(dir, NAME_FILE, &report)
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
        for report in observations.values_mut() {
            if report.name.as_ref().is_some_and(|name| !name.valid()) {
                report.name = None;
            }
        }
        observations
    }

    pub fn observations(&self) -> Observations {
        self.cache
            .lock()
            .expect("peer versions")
            .observations
            .clone()
    }

    /// The existing version stream comes first. Older peers only read that
    /// stream, and neither report delays the service stream.
    pub fn exchange(self: &Arc<Self>, conn: &Connection, auth: &Authorization) -> Exchange {
        let (versions, conn, ended) = (self.clone(), conn.clone(), auth.watch_end());
        Exchange(tokio::spawn(async move {
            let exchange = async {
                let send = async {
                    let name = local_name(&versions.dir).ok().flatten();
                    send_report(&conn, &[PREFIX, env!("CARGO_PKG_VERSION").as_bytes()]).await?;
                    if let Some(name) = name {
                        send_report(
                            &conn,
                            &[
                                NAME_PREFIX,
                                &name.revision.to_be_bytes(),
                                name.value.as_bytes(),
                            ],
                        )
                        .await?;
                    }
                    Ok::<_, anyhow::Error>(())
                };
                let receive = async {
                    let mut stream = conn.accept_uni().await.ok()?;
                    let body = stream.read_to_end(PREFIX.len() + MAX_VERSION).await.ok()?;
                    let version = decode_report(&body)?;
                    versions.remember(conn.remote_id(), version);
                    let mut stream = conn.accept_uni().await.ok()?;
                    let body = stream
                        .read_to_end(NAME_PREFIX.len() + REVISION_BYTES + MAX_DEVICE_NAME)
                        .await
                        .ok()?;
                    let name = decode_name(&body)?;
                    versions.remember_name(conn.remote_id(), name);
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
        let report = cache
            .observations
            .entry(peer)
            .or_insert_with(|| Observation {
                version: String::new(),
                observed_at: 0,
                name: None,
            });
        let changed = report.version != version;
        if changed {
            version.clone_into(&mut report.version);
        }
        report.observed_at = crate::storage::now();
        if changed
            || cache
                .last_save
                .is_none_or(|last| last.elapsed() >= SAVE_INTERVAL)
        {
            // Keep live observations current. For an unchanged version, a periodic
            // checkpoint is enough for offline status and avoids fsync per connection.
            self.save(&mut cache);
        }
    }

    fn remember_name(&self, peer: EndpointId, name: Name) {
        let mut cache = self.cache.lock().expect("peer versions");
        let Some(report) = cache.observations.get_mut(&peer) else {
            return;
        };
        // Parallel connections may finish out of order. Names only advance
        // within the authenticated sender's own entry.
        if report
            .name
            .as_ref()
            .is_none_or(|last| last.revision < name.revision)
        {
            report.name = Some(name);
            self.save(&mut cache);
        }
    }

    fn save(&self, cache: &mut Cache) {
        cache.last_save = Some(Instant::now());
        if crate::storage::save(&self.dir, FILE, &cache.observations).is_err() {
            diagnostics::quiet(Level::Warning, "could not save peer reports");
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

async fn send_report(conn: &Connection, parts: &[&[u8]]) -> Result<()> {
    let mut stream = conn.open_uni().await?;
    let report = parts.concat();
    stream.write_all(&report).await?;
    stream.finish()?;
    Ok(())
}

fn decode_name(bytes: &[u8]) -> Option<Name> {
    let (revision, value) = bytes
        .strip_prefix(NAME_PREFIX)?
        .split_at_checked(REVISION_BYTES)?;
    let name = Name {
        revision: u64::from_be_bytes(revision.try_into().ok()?),
        value: std::str::from_utf8(value).ok()?.to_owned(),
    };
    name.valid().then_some(name)
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

    #[test]
    fn names_require_a_revision_and_a_valid_device_name() {
        let revision = 2u64.to_be_bytes();
        let body = |name: &[u8]| [NAME_PREFIX, &revision, name].concat();
        assert_eq!(
            decode_name(&body(b"workstation-2")),
            Some(Name {
                revision: 2,
                value: "workstation-2".into()
            })
        );
        assert_eq!(
            decode_name(&[NAME_PREFIX, &[0; REVISION_BYTES], b"alpha"].concat()),
            None
        );
        assert_eq!(decode_name(&body(b"alpha\nspoof")), None);
        assert_eq!(decode_name(&body(&[b'a'; MAX_DEVICE_NAME + 1])), None);
        assert_eq!(decode_name(&[PREFIX, b"0.5.2"].concat()), None);
    }

    #[test]
    fn newer_name_survives_late_reports_legacy_contacts_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let peer = iroh::SecretKey::generate().public();
        // Existing cache entries contain only a version and its timestamp.
        crate::storage::save(
            dir.path(),
            FILE,
            &BTreeMap::from([(
                peer,
                serde_json::json!({"version": "0.5.2", "observed_at": 1}),
            )]),
        )
        .unwrap();
        let versions = PeerVersions::open(dir.path());
        assert_eq!(versions.observations()[&peer].name(), None);
        for (revision, value) in [(2, "current"), (1, "old"), (2, "conflict")] {
            versions.remember_name(
                peer,
                Name {
                    revision,
                    value: value.into(),
                },
            );
        }
        versions.remember(peer, "0.5.3");
        let reopened = PeerVersions::read(dir.path());
        assert_eq!(reopened[&peer].version, "0.5.3");
        assert_eq!(reopened[&peer].name(), Some("current"));
    }
}
