//! Optional version and name reports over an encrypted connection after mutual pairing.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use iroh::{
    EndpointId,
    endpoint::{Connection, SendStream},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};

use super::{
    binding::{check_device_name, signed_name},
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
/// How long a report exchange waits for a step that should follow at once, and for a report
/// stream to move. A report may take any time overall.
const REPORT_IDLE: Duration = Duration::from_secs(2);
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

/// Record the name a device enrolls under when its binding cannot carry all of it, so
/// paired peers learn the rest. Replaces what an abandoned join attempt recorded. The
/// caller holds the profile lock, and the device is not yet a member.
pub(super) fn enroll_name(dir: &Path, name: Option<&str>) -> Result<()> {
    if let Some(name) = name.filter(|name| signed_name(name) != *name) {
        let report = Name {
            revision: 1,
            value: name.to_owned(),
        };
        return crate::storage::save(dir, NAME_FILE, &report);
    }
    match std::fs::remove_file(dir.join(NAME_FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).context("remove an earlier device name")
        }
        _ => Ok(()),
    }
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
                    // The version goes first, so that loading a long name cannot hold it back.
                    send_report(&conn, &[PREFIX, env!("CARGO_PKG_VERSION").as_bytes()]).await?;
                    if let Some(name) = local_name(&versions.dir).ok().flatten() {
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
                let _ = tokio::join!(send, versions.receive(&conn));
            };
            tokio::select! {
                biased;
                _ = ended => {}
                _ = exchange => {}
            }
        }))
    }

    /// Record the peer's reports.
    async fn receive(&self, conn: &Connection) -> Option<()> {
        let mut stream = timeout(REPORT_IDLE, conn.accept_uni()).await.ok()?.ok()?;
        let body = timeout(REPORT_IDLE, stream.read_to_end(PREFIX.len() + MAX_VERSION))
            .await
            .ok()?
            .ok()?;
        let version = decode_report(&body)?;
        self.remember(conn.remote_id(), version);
        // The name is optional, and the peer readies it after sending its version, so
        // nothing times this wait: it lasts until the stream starts or the exchange ends.
        let mut stream = conn.accept_uni().await.ok()?;
        // The stream delimits the name, whatever its length.
        let body = read_report(&mut stream, REPORT_IDLE).await?;
        self.remember_name(conn.remote_id(), decode_name(&body)?);
        Some(())
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
    let mut outgoing = Outgoing {
        stream: timeout(REPORT_IDLE, conn.open_uni()).await??,
        whole: false,
    };
    for part in parts {
        write_report(&mut outgoing.stream, part, REPORT_IDLE).await?;
    }
    outgoing.stream.finish()?;
    outgoing.whole = true;
    Ok(())
}

/// A report being sent. Dropping a send stream finishes it, which would pass off part of a
/// report as all of it, so one abandoned before its end is reset.
struct Outgoing {
    stream: SendStream,
    whole: bool,
}

impl Drop for Outgoing {
    fn drop(&mut self) {
        if !self.whole {
            let _ = self.stream.reset(0u32.into());
        }
    }
}

/// Write all of `bytes`, for as long as the stream keeps taking more of them. Nothing else
/// on the connection counts, so a stalled report soon releases what it holds.
async fn write_report(
    stream: &mut (impl AsyncWrite + Unpin),
    mut bytes: &[u8],
    idle: Duration,
) -> Result<()> {
    while !bytes.is_empty() {
        let written = timeout(idle, stream.write(bytes)).await??;
        ensure!(written > 0, "the report stream closed");
        bytes = &bytes[written..];
    }
    Ok(())
}

/// Read a report to its end, for as long as it keeps arriving.
async fn read_report(stream: &mut (impl AsyncRead + Unpin), idle: Duration) -> Option<Vec<u8>> {
    let mut report = Vec::new();
    while timeout(idle, stream.read_buf(&mut report))
        .await
        .ok()?
        .ok()?
        > 0
    {}
    Some(report)
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        let long = "a".repeat(100_000);
        assert_eq!(decode_name(&body(long.as_bytes())).unwrap().value, long);
        assert_eq!(decode_name(&[PREFIX, b"0.5.2"].concat()), None);
    }

    #[test]
    fn enrollment_keeps_only_a_name_its_binding_cannot_carry() {
        let dir = tempfile::tempdir().unwrap();
        let long = "a".repeat(200);
        enroll_name(dir.path(), Some(&long)).unwrap();
        assert_eq!(local_display_name(dir.path()).unwrap(), Some(long));
        // A later attempt must not report the abandoned attempt's name.
        enroll_name(dir.path(), Some("short")).unwrap();
        assert_eq!(local_display_name(dir.path()).unwrap(), None);
        enroll_name(dir.path(), None).unwrap();
    }

    /// Each direction takes several idle waits in total and completes, because no single
    /// wait passes without progress; a stalled one is given up.
    #[tokio::test]
    async fn a_report_that_keeps_moving_may_outlast_the_idle_wait() {
        const IDLE: Duration = Duration::from_millis(500);
        const STEP: Duration = Duration::from_millis(50);
        const PIECE: usize = 64;
        let report: Vec<u8> = (0..=u8::MAX).cycle().take(30 * PIECE).collect();

        // A slow sender.
        let (mut near, mut far) = tokio::io::duplex(PIECE);
        let started = Instant::now();
        let (received, ()) = tokio::join!(read_report(&mut far, IDLE), async {
            for piece in report.chunks(PIECE) {
                tokio::time::sleep(STEP).await;
                near.write_all(piece).await.unwrap();
            }
            drop(near);
        });
        assert!(started.elapsed() > 2 * IDLE);
        assert_eq!(received.as_ref(), Some(&report));

        // A slow reader.
        let (mut near, mut far) = tokio::io::duplex(PIECE);
        let started = Instant::now();
        let mut received = vec![0; report.len()];
        let (sent, ()) = tokio::join!(write_report(&mut near, &report, IDLE), async {
            for piece in received.chunks_mut(PIECE) {
                tokio::time::sleep(STEP).await;
                far.read_exact(piece).await.unwrap();
            }
        });
        sent.unwrap();
        assert!(started.elapsed() > 2 * IDLE);
        assert_eq!(received, report);

        // Nothing moving, in either direction.
        let (mut near, mut far) = tokio::io::duplex(PIECE);
        assert!(write_report(&mut near, &report, IDLE).await.is_err());
        assert_eq!(read_report(&mut far, IDLE).await, None);
    }

    /// Two loopback endpoints and the connection between them, from each end.
    async fn connected() -> ([iroh::Endpoint; 2], Connection, Connection) {
        use iroh::endpoint::{RelayMode, presets};
        const ALPN: &[u8] = b"massrelay/report-test";
        let bind = || {
            iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Disabled)
                .alpns(vec![ALPN.to_vec()])
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .bind()
        };
        let (a, b) = tokio::try_join!(bind(), bind()).unwrap();
        let address = iroh::EndpointAddr::new(b.id()).with_ip_addr(b.bound_sockets()[0]);
        let (near, far) = tokio::join!(a.connect(address, ALPN), async {
            b.accept().await.unwrap().await.unwrap()
        });
        ([a, b], near.unwrap(), far)
    }

    /// Whether a report stream ends without ever passing for a whole report.
    async fn cut(stream: &mut iroh::endpoint::RecvStream) -> bool {
        let mut rest = Vec::new();
        let read = AsyncReadExt::read_to_end(stream, &mut rest);
        timeout(Duration::from_secs(10), read)
            .await
            .unwrap()
            .is_err()
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP sockets"]
    async fn an_abandoned_report_never_arrives_as_a_whole_one() {
        let (_endpoints, near, far) = connected().await;
        // Far more than a stream may carry before its reader takes any of it.
        let report = vec![b'n'; 16 << 20];
        // The connection outlives the abandoned sender, so only the stream says it was cut.
        let sender = near.clone();
        let sending = tokio::spawn(async move { send_report(&sender, &[&report]).await });
        let mut stream = far.accept_uni().await.unwrap();
        stream.read_exact(&mut [0; 1024]).await.unwrap();
        sending.abort();
        assert!(sending.await.unwrap_err().is_cancelled());
        assert!(cut(&mut stream).await);
        assert!(near.close_reason().is_none());
    }

    /// A sender may take any time to ready its name once its version is out.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP sockets"]
    async fn a_name_that_starts_late_is_recorded() {
        let ([a, _b], near, far) = connected().await;
        let dir = tempfile::tempdir().unwrap();
        let versions = PeerVersions::open(dir.path());
        let (received, ()) = tokio::join!(versions.receive(&far), async {
            send_report(&near, &[PREFIX, b"1.0.0"]).await.unwrap();
            tokio::time::sleep(REPORT_IDLE + Duration::from_millis(500)).await;
            let revision = 1u64.to_be_bytes();
            send_report(&near, &[NAME_PREFIX, &revision, b"desk"])
                .await
                .unwrap();
        });
        assert_eq!(received, Some(()));
        assert_eq!(versions.observations()[&a.id()].name(), Some("desk"));
    }

    /// A report far beyond a stream's window takes several idle waits in total and
    /// arrives, on the progress of its own writes alone.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP sockets"]
    async fn a_large_report_completes_while_its_reader_keeps_taking_it() {
        let (_endpoints, near, far) = connected().await;
        let report: Vec<u8> = (0..=u8::MAX).cycle().take(8 << 20).collect();
        let parts: [&[u8]; 1] = [&report];
        let started = Instant::now();
        let (sent, received) = tokio::join!(send_report(&near, &parts), async {
            let mut stream = far.accept_uni().await.unwrap();
            let (mut received, mut buffer) = (Vec::new(), vec![0; 64 << 10]);
            while let Some(read) = stream.read(&mut buffer).await.unwrap() {
                received.extend_from_slice(&buffer[..read]);
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            received
        });
        sent.unwrap();
        assert!(started.elapsed() > 2 * REPORT_IDLE);
        assert!(received == report);
    }

    /// Only the report stream's own progress holds a report's buffers: traffic elsewhere
    /// on the connection does not.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP sockets"]
    async fn a_stalled_report_is_given_up_on_a_busy_connection() {
        let (_endpoints, near, far) = connected().await;
        let (mut other, _reply) = near.open_bi().await.unwrap();
        let filling = tokio::spawn(async move {
            while other.write_all(&[0; 1024]).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let carried = Arc::new(AtomicUsize::new(0));
        let draining = tokio::spawn({
            let (far, carried) = (far.clone(), carried.clone());
            async move {
                let (_reply, mut other) = far.accept_bi().await.unwrap();
                let mut buffer = [0; 1024];
                while let Ok(Some(read)) = other.read(&mut buffer).await {
                    carried.fetch_add(read, Ordering::SeqCst);
                }
            }
        });

        // Nothing ever reads the report.
        let report = vec![b'n'; 16 << 20];
        let before = carried.load(Ordering::SeqCst);
        let sent = timeout(Duration::from_secs(20), send_report(&near, &[&report]))
            .await
            .expect("other traffic must not keep a stalled report waiting");
        assert!(sent.is_err());
        assert!(carried.load(Ordering::SeqCst) > before);
        assert!(!filling.is_finished() && !draining.is_finished());
        assert!(cut(&mut far.accept_uni().await.unwrap()).await);
        filling.abort();
        draining.abort();
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
