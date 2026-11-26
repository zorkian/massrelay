//! Encrypted mailbox relay and operator commands.
//!
//! The Iroh transport forwards traffic for endpoints without consulting membership.
//! The [`mailbox`] protocol uses a pinned endpoint key and an operator access grant. The relay keeps
//! no roster, member table, invite or pairing state. Its operator contract, from access grants
//! to backup, restore and rotation, is `docs/private-relay-operations.md`.
//!
//! The state directory holds:
//!
//! ```text
//! <dir>/private-relay.json          profile: format, endpoint key, addresses, incarnation
//! <dir>/private-relay-access.json   operator access grants: verifiers only, never secrets
//! <dir>/mailbox/                    the opaque slot store
//! <dir>/private-relay-sealed.json   present once a final backup sealed the store
//! <dir>/retired/                    stores set aside by rotation, never deleted
//! ```
//!
//! [`init`] creates the store, one access grant and the profile, in that order, and refuses any
//! directory holding a legacy relay profile, an existing private profile or an existing mailbox.
//! [`run`] only reopens: it refuses a legacy profile, a profile without its mailbox, a mailbox
//! without its profile, an unknown profile format, a key that does not match the saved identity,
//! a mailbox whose incarnation differs from the profile's, missing access grants, and a sealed
//! store. Startup leaves such a directory untouched.
//!
//! # Admission
//!
//! Storage is admitted by operator grants, not open to anyone who can reach the relay. Each
//! grant is a random bearer secret handed out inside a locator ([`access_issue`]); the relay
//! keeps only its verifier and a label, and a connection that presents a current secret may use
//! storage for its lifetime. Revocation ([`access_revoke`]) keeps the grant's record and stops
//! admitting it from the relay's next start. A grant is a tenancy the operator chose, never a
//! member, device or network, and authorizes nothing inside one.
//!
//! # Maintenance
//!
//! Every maintenance command takes the state directory's lock, so it runs only while the relay
//! is stopped. [`store_check`] verifies the whole store. [`store_backup`] writes a verified,
//! signed snapshot that includes every commit still in SQLite's write-ahead log; with `final`
//! it first seals the store, so the snapshot is complete by construction and this relay never
//! serves that incarnation again. [`store_restore`] keeps the incarnation, and with it every
//! occupied marker, only for a complete snapshot that verifies against the relay identity the
//! operator names; any other restore starts a new incarnation. [`store_rotate`] sets the store
//! aside and starts a new incarnation in place. Nothing deletes an object or a store.

use std::{
    fs::{self, File},
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};
use iroh::{EndpointId, RelayUrl, SecretKey, Signature};
use iroh_relay::server::{RelayConfig, Server, ServerConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;

use crate::{
    bind_endpoint,
    connection_log::ConnectionLog,
    mailbox::{self, AccessKey, Bytes, Locator, refuse_userinfo},
    mailbox_server::{Mailbox, serve_connection},
    slot_store::{DB_FILE, Incarnation, SlotStore, SlotStoreError, Summary},
    slot_wire::hex,
    storage,
    wire::{self, ServerAddr},
};

const LEGACY_PROFILE_FILE: &str = "relay.json";
const PRIVATE_PROFILE_FILE: &str = "private-relay.json";
const STORE_DIR: &str = "mailbox";
const PROFILE_FORMAT: &str = "massrelay-private-relay/experimental-0";
const EVENT_FILE: &str = "private-relay-events.jsonl";
const ACCESS_FILE: &str = "private-relay-access.json";
const ACCESS_FORMAT: &str = "massrelay-private-relay-access/experimental-0";
const SEALED_FILE: &str = "private-relay-sealed.json";
const RETIRED_DIR: &str = "retired";
const MANIFEST_FILE: &str = "manifest.json";
const SIGNATURE_FILE: &str = "manifest.sig";
const CONSUMED_FILE: &str = "restored.json";
const MANIFEST_FORMAT: &str = "massrelay-private-relay-backup/experimental-0";
const MANIFEST_DOMAIN: &[u8] = b"massrelay private relay backup manifest\0";

#[derive(Clone, Serialize, Deserialize)]
struct Profile {
    format: String,
    key: [u8; 32],
    server: ServerAddr,
    incarnation: Bytes<32>,
}

impl Profile {
    fn locator(&self, access: AccessKey) -> Locator {
        Locator {
            server: self.server.clone(),
            incarnation: self.incarnation,
            access,
        }
    }

    fn incarnation(&self) -> Incarnation {
        Incarnation::from_bytes(self.incarnation.0)
    }
}

/// The operator's access grants. Revoked grants stay listed: nothing is deleted.
#[derive(Serialize, Deserialize)]
struct Grants {
    format: String,
    grants: Vec<Grant>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Grant {
    /// Short display identifier: the first eight verifier bytes, in hex.
    id: String,
    verifier: Bytes<32>,
    label: String,
    issued: u64,
    revoked: Option<u64>,
}

impl Grants {
    fn empty() -> Self {
        Self {
            format: ACCESS_FORMAT.into(),
            grants: Vec::new(),
        }
    }

    fn load(dir: &Path) -> Result<Self> {
        ensure!(
            dir.join(ACCESS_FILE).try_exists()?,
            "the private relay in {} has no access grants file; issue a grant with \
             'massrelay relay-grants issue' while it is stopped",
            dir.display()
        );
        let grants: Self = storage::load(dir, ACCESS_FILE)?;
        ensure!(
            grants.format == ACCESS_FORMAT,
            "unsupported access grants format {:?}",
            grants.format
        );
        for grant in &grants.grants {
            ensure!(
                grant.id == grant_id(&grant.verifier.0),
                "access grant {:?} does not match its verifier; the grants file was changed",
                grant.id
            );
        }
        Ok(grants)
    }

    /// Verifiers of every grant not revoked.
    fn current(&self) -> Vec<[u8; 32]> {
        self.grants
            .iter()
            .filter(|grant| grant.revoked.is_none())
            .map(|grant| grant.verifier.0)
            .collect()
    }

    /// Add a fresh grant and return its secret, which is never stored.
    fn issue(&mut self, label: &str) -> Result<AccessKey> {
        let access = AccessKey::random()?;
        let verifier = access.verifier();
        self.grants.push(Grant {
            id: grant_id(&verifier),
            verifier: Bytes(verifier),
            label: label.into(),
            issued: storage::now(),
            revoked: None,
        });
        Ok(access)
    }
}

fn grant_id(verifier: &[u8; 32]) -> String {
    hex(&verifier[..8])
}

/// The record a final backup leaves beside the store it sealed.
#[derive(Serialize, Deserialize)]
struct Sealed {
    snapshot: Bytes<16>,
    sealed: u64,
}

fn refuse_legacy(dir: &Path) -> Result<()> {
    ensure!(
        !dir.join(LEGACY_PROFILE_FILE).try_exists()?,
        "{} holds a legacy relay; use a separate state directory for a private relay",
        dir.display()
    );
    Ok(())
}

/// Initialize a private relay and print a locator carrying its first access grant. The
/// directory must hold no relay state.
pub fn init(dir: &Path, udp: SocketAddr, relay: RelayUrl) -> Result<()> {
    let (profile, access) = create(dir, udp, relay)?;
    eprintln!(
        "Relay initialized. The locator below carries its first access \
         grant: give it only to people whose networks may store objects here."
    );
    println!("{}", profile.locator(access).encode()?);
    Ok(())
}

fn create(dir: &Path, udp: SocketAddr, relay: RelayUrl) -> Result<(Profile, AccessKey)> {
    // Checked before anything is created, saved or printed.
    refuse_userinfo(&relay)?;
    ensure!(
        !udp.ip().is_unspecified() && udp.port() != 0,
        "specify the relay's reachable UDP address"
    );
    let _lock = storage::lock(dir)?;
    refuse_legacy(dir)?;
    ensure!(
        !dir.join(PRIVATE_PROFILE_FILE).try_exists()?,
        "a private relay is already initialized in {}",
        dir.display()
    );
    ensure!(
        !dir.join(STORE_DIR).try_exists()?,
        "{} already has a mailbox without a private relay profile; it was not reset",
        dir.display()
    );
    let store = SlotStore::initialize(&dir.join(STORE_DIR))?;
    let key = wire::random()?;
    let profile = Profile {
        format: PROFILE_FORMAT.into(),
        key,
        server: ServerAddr {
            id: SecretKey::from_bytes(&key).public(),
            udp,
            relay,
        },
        incarnation: store.incarnation().into(),
    };
    let mut grants = Grants::empty();
    let access = grants.issue("initial")?;
    storage::save(dir, ACCESS_FILE, &grants)?;
    // The profile is saved last, so its presence means the mailbox and grants it needs exist.
    storage::save(dir, PRIVATE_PROFILE_FILE, &profile)?;
    Ok((profile, access))
}

/// Load and check the profile alone, without opening its store.
fn load_profile(dir: &Path) -> Result<Profile> {
    let profile: Profile = storage::load(dir, PRIVATE_PROFILE_FILE)?;
    check_profile(&profile)?;
    Ok(profile)
}

fn check_profile(profile: &Profile) -> Result<()> {
    ensure!(
        profile.format == PROFILE_FORMAT,
        "unsupported private relay profile format {:?}",
        profile.format
    );
    ensure!(
        SecretKey::from_bytes(&profile.key).public() == profile.server.id,
        "the private relay profile's key does not match its identity"
    );
    refuse_userinfo(&profile.server.relay)
}

/// Whether a final backup sealed this directory's store.
fn sealed(dir: &Path) -> Result<Option<Sealed>> {
    if !dir.join(SEALED_FILE).try_exists()? {
        return Ok(None);
    }
    Ok(Some(storage::load(dir, SEALED_FILE)?))
}

/// Reopen a private relay's profile and mailbox, failing closed on any mismatch. A sealed
/// store opens only for maintenance that never writes to it (`sealed_ok`).
fn open(dir: &Path, sealed_ok: bool) -> Result<(Profile, SlotStore)> {
    refuse_legacy(dir)?;
    let has_profile = dir.join(PRIVATE_PROFILE_FILE).try_exists()?;
    let has_store = dir.join(STORE_DIR).try_exists()?;
    match (has_profile, has_store) {
        (true, true) => {}
        (false, false) => bail!(
            "no private relay in {}; initialize one explicitly first",
            dir.display()
        ),
        (false, true) => bail!(
            "{} has a mailbox without a private relay profile; it was not reset",
            dir.display()
        ),
        (true, false) => bail!(
            "the private relay in {} has lost its mailbox; it will not start with an unknown \
             store. Restore a backup into a new directory, or run 'massrelay \
             relay-store rotate' to start a new incarnation here",
            dir.display()
        ),
    }
    let profile = load_profile(dir)?;
    if !sealed_ok && let Some(sealed) = sealed(dir)? {
        bail!(
            "the store in {} was sealed by a final backup (snapshot {}); this relay will not \
             serve its incarnation again. Restore that backup with --keep-incarnation on one \
             host, or run 'massrelay relay-store rotate' to start a new incarnation here",
            dir.display(),
            hex(&sealed.snapshot.0)
        );
    }
    // The incarnation is checked from the mailbox header before the store recovers or cleans
    // anything, so a foreign mailbox is left untouched.
    let store = match SlotStore::open_expecting(&dir.join(STORE_DIR), &profile.incarnation()) {
        Err(SlotStoreError::WrongIncarnation) => bail!(
            "the mailbox in {} belongs to another incarnation than its profile; it was not \
             changed",
            dir.display()
        ),
        opened => opened.map_err(|error| match error {
            SlotStoreError::Damaged { .. } => anyhow::anyhow!(
                "{error}. Nothing was repaired. Run 'massrelay relay-store check' for \
                 details; recovery is a complete backup or a new incarnation \
                 (docs/private-relay-operations.md)"
            ),
            error => error.into(),
        })?,
    };
    Ok((profile, store))
}

/// Run a private relay in the foreground.
pub async fn run(dir: PathBuf, udp_bind: SocketAddr, relay_bind: SocketAddr) -> Result<()> {
    let _lock = storage::lock(&dir)?;
    let (profile, store) = open(&dir, false)?;
    let grants = Grants::load(&dir)?.current();
    let log = ConnectionLog::open(Some(&dir.join(EVENT_FILE)))?;
    if grants.is_empty() {
        eprintln!(
            "massrelay: every access grant is revoked; this relay admits no storage until a grant \
             is issued"
        );
    }
    let admitted = grants.len();
    let mailbox = Arc::new(Mailbox::new(store, *profile.server.id.as_bytes(), grants));

    // The transport forwards packets without consulting membership.
    let mut config = ServerConfig::default();
    config.relay = Some(RelayConfig::new(relay_bind));
    let mut server = Server::spawn(config).await?;
    let endpoint = bind_endpoint(
        SecretKey::from_bytes(&profile.key),
        udp_bind,
        Some(profile.server.relay.clone()),
        mailbox::ALPN,
        false,
    )
    .await?;
    // The locator carries an access secret, so it is printed only by the access commands.
    eprintln!(
        "Private relay {} incarnation {}, admitting {admitted} access grant(s)",
        profile.server.id,
        hex(&profile.incarnation.0)
    );
    eprintln!("MassRelay relay listening on {udp_bind} UDP and {relay_bind} TCP");
    log.state("private_relay_started", None, None);

    let shutdown = crate::shutdown();
    tokio::pin!(shutdown);
    let mut connections = JoinSet::new();
    let (server_exited, result) = loop {
        tokio::select! {
            ended = server.join() => {
                let result = ended.context("wait for relay transport")
                    .and_then(|result| result.context("relay transport failed"))
                    .and_then(|()| Err(anyhow::anyhow!("relay service stopped")));
                break (true, result);
            }
            signal = &mut shutdown => break (false, signal.context("wait for relay shutdown")),
            Some(_) = connections.join_next() => {}
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break (false, Err(anyhow::anyhow!("mailbox endpoint closed")));
                };
                let mailbox = mailbox.clone();
                connections.spawn(async move {
                    let connection = tokio::time::timeout(wire::RPC_TIMEOUT, async {
                        incoming.await
                    }).await;
                    if let Ok(Ok(connection)) = connection {
                        serve_connection(mailbox, connection).await;
                    }
                });
            }
        }
    };
    endpoint.close().await;
    connections.shutdown().await;
    let shutdown = if server_exited {
        drop(server);
        Ok(())
    } else {
        server.shutdown().await
    };
    log.state(
        if result.is_ok() && shutdown.is_ok() {
            "private_relay_stopped"
        } else {
            "private_relay_failed"
        },
        None,
        None,
    );
    result?;
    shutdown?;
    Ok(())
}

// ------------------------------------------------------------------ access

/// Read the relay identity without loading the store or printing an access secret.
pub fn info(dir: &Path) -> Result<()> {
    refuse_legacy(dir)?;
    let profile = load_profile(dir)?;
    println!("Endpoint: {}", profile.server.id);
    println!("UDP: {}", profile.server.udp);
    println!("Relay URL: {}", profile.server.relay);
    println!("Incarnation: {}", hex(&profile.incarnation.0));
    Ok(())
}

/// Issue a new access grant and print its locator. It is admitted from the next relay start.
pub fn access_issue(dir: &Path, label: &str) -> Result<()> {
    let access = issue_grant(dir, label)?;
    let profile = load_profile(dir)?;
    eprintln!(
        "Issued access grant {}. Restart the relay to admit it. The locator below is a bearer \
         secret for this relay's storage.",
        grant_id(&access.verifier())
    );
    println!("{}", profile.locator(access).encode()?);
    Ok(())
}

fn issue_grant(dir: &Path, label: &str) -> Result<AccessKey> {
    ensure!(
        !label.chars().any(char::is_control),
        "a grant label must be printable text"
    );
    let _lock = storage::lock(dir)?;
    refuse_legacy(dir)?;
    load_profile(dir)?;
    let mut grants = if dir.join(ACCESS_FILE).try_exists()? {
        Grants::load(dir)?
    } else {
        Grants::empty()
    };
    let access = grants.issue(label)?;
    storage::save(dir, ACCESS_FILE, &grants)?;
    Ok(access)
}

/// List every grant, revoked ones included.
pub fn access_list(dir: &Path) -> Result<()> {
    let grants = Grants::load(dir)?;
    for grant in &grants.grants {
        let state = match grant.revoked {
            None => "current".to_string(),
            Some(at) => format!("revoked {}", date(at)),
        };
        println!(
            "{}  issued {}  {state}  {}",
            grant.id,
            date(grant.issued),
            crate::visible(&grant.label)
        );
    }
    Ok(())
}

/// Revoke one grant by its identifier. It stays listed; the relay stops admitting it at its
/// next start. Connections already admitted keep their admission until then.
pub fn access_revoke(dir: &Path, id: &str) -> Result<()> {
    let _lock = storage::lock(dir)?;
    load_profile(dir)?;
    let mut grants = Grants::load(dir)?;
    let grant = grants
        .grants
        .iter_mut()
        .find(|grant| grant.id == id.trim().to_ascii_lowercase())
        .with_context(|| format!("no access grant {id:?}; nothing was changed"))?;
    if grant.revoked.is_some() {
        eprintln!("Access grant {} was already revoked.", grant.id);
        return Ok(());
    }
    grant.revoked = Some(storage::now());
    storage::save(dir, ACCESS_FILE, &grants)?;
    eprintln!("Revoked access grant {id}. Restart the relay to stop admitting it.");
    Ok(())
}

fn date(at: u64) -> String {
    chrono::DateTime::from_timestamp(at as i64, 0)
        .map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| at.to_string())
}

// ------------------------------------------------------------------- store

fn print_summary(summary: &Summary) {
    println!(
        "Objects: {} occupied ({} queue items, {} acknowledged), {} body bytes",
        summary.objects, summary.queue_items, summary.queue_acks, summary.body_bytes
    );
}

/// Verify the whole stopped store and print what it holds.
pub fn store_check(dir: &Path) -> Result<()> {
    let _lock = storage::lock(dir)?;
    refuse_legacy(dir)?;
    let profile = load_profile(dir)?;
    let summary = SlotStore::verify_stopped(&dir.join(STORE_DIR), &profile.incarnation())?;
    println!("Relay: {}", profile.server.id);
    println!("Incarnation: {}", hex(&profile.incarnation.0));
    if let Some(sealed) = sealed(dir)? {
        println!(
            "Sealed: {} by final backup {}; it will not serve again",
            date(sealed.sealed),
            hex(&sealed.snapshot.0)
        );
    }
    print_summary(&summary);
    match Grants::load(dir) {
        Ok(grants) => println!(
            "Access grants: {} current of {}",
            grants.current().len(),
            grants.grants.len()
        ),
        Err(error) => println!("Access grants: {error:#}"),
    }
    println!("Verified: integrity, exact schema, queue links and every body");
    Ok(())
}

/// A signed backup's manifest. The signature covers its exact bytes.
#[derive(Serialize, Deserialize)]
struct Manifest {
    format: String,
    relay: EndpointId,
    incarnation: Bytes<32>,
    snapshot: Bytes<16>,
    created: u64,
    /// The store was sealed before this snapshot, so it is the incarnation's final state.
    complete: bool,
    objects: u64,
    queue_items: u64,
    queue_acks: u64,
    body_bytes: u64,
    files: Vec<FileDigest>,
}

#[derive(Serialize, Deserialize)]
struct FileDigest {
    name: String,
    len: u64,
    sha256: Bytes<32>,
}

impl Manifest {
    fn summary(&self) -> Summary {
        Summary {
            objects: self.objects,
            queue_items: self.queue_items,
            queue_acks: self.queue_acks,
            body_bytes: self.body_bytes,
        }
    }
}

/// The files every backup holds, in its manifest's order.
const BACKUP_FILES: [&str; 3] = [PRIVATE_PROFILE_FILE, ACCESS_FILE, DB_FILE];

fn signed(manifest: &[u8]) -> Vec<u8> {
    [MANIFEST_DOMAIN, manifest].concat()
}

fn digest_file(path: &Path) -> Result<(u64, [u8; 32])> {
    let mut file = File::open(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let len = std::io::copy(&mut file, &mut hasher)?;
    Ok((len, hasher.finalize().into()))
}

/// Write `bytes` as a new owner-only file and sync it. Never replaces an existing file.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("sync {}", dir.display()))
}

/// Back up the stopped relay into `out`, a directory that must not exist yet. With `final`,
/// seal the store first: the snapshot is then its incarnation's complete final state, and this
/// relay refuses to serve again. A store sealed earlier is always backed up as complete.
pub fn store_backup(dir: &Path, out: &Path, final_: bool) -> Result<()> {
    let _lock = storage::lock(dir)?;
    let (profile, store) = open(dir, true)?;
    let grants = fs::read(dir.join(ACCESS_FILE)).with_context(|| {
        format!(
            "read {}; a relay without access grants cannot be backed up",
            dir.join(ACCESS_FILE).display()
        )
    })?;
    Grants::load(dir)?;
    let parent = match out.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(out).with_context(|| {
        format!(
            "create {}; a backup needs a new directory and never overwrites one",
            out.display()
        )
    })?;

    // Seal before the snapshot, so nothing can be committed after the state it records.
    let snapshot = match sealed(dir)? {
        Some(sealed) => Some(sealed.snapshot),
        None if final_ => {
            let mut id = [0; 16];
            getrandom::fill(&mut id).map_err(|error| anyhow::anyhow!("random: {error}"))?;
            storage::save(
                dir,
                SEALED_FILE,
                &Sealed {
                    snapshot: Bytes(id),
                    sealed: storage::now(),
                },
            )?;
            sync_dir(dir)?;
            Some(Bytes(id))
        }
        None => None,
    };
    let complete = snapshot.is_some();
    let snapshot = match snapshot {
        Some(id) => id,
        None => {
            let mut id = [0; 16];
            getrandom::fill(&mut id).map_err(|error| anyhow::anyhow!("random: {error}"))?;
            Bytes(id)
        }
    };

    let summary = store.snapshot_to(&out.join(DB_FILE))?;
    drop(store);
    write_new(
        &out.join(PRIVATE_PROFILE_FILE),
        &fs::read(dir.join(PRIVATE_PROFILE_FILE))?,
    )?;
    write_new(&out.join(ACCESS_FILE), &grants)?;
    let mut files = Vec::new();
    for name in BACKUP_FILES {
        let (len, sha256) = digest_file(&out.join(name))?;
        files.push(FileDigest {
            name: name.into(),
            len,
            sha256: Bytes(sha256),
        });
    }
    let manifest = serde_json::to_vec_pretty(&Manifest {
        format: MANIFEST_FORMAT.into(),
        relay: profile.server.id,
        incarnation: profile.incarnation,
        snapshot,
        created: storage::now(),
        complete,
        objects: summary.objects,
        queue_items: summary.queue_items,
        queue_acks: summary.queue_acks,
        body_bytes: summary.body_bytes,
        files,
    })?;
    let signature = SecretKey::from_bytes(&profile.key).sign(&signed(&manifest));
    write_new(&out.join(MANIFEST_FILE), &manifest)?;
    write_new(&out.join(SIGNATURE_FILE), &signature.to_bytes())?;
    sync_dir(out)?;
    sync_dir(parent)?;

    println!("Backup: {}", out.display());
    println!("Relay: {}", profile.server.id);
    println!("Incarnation: {}", hex(&profile.incarnation.0));
    print_summary(&summary);
    if complete {
        println!(
            "Complete: this is the final state of the incarnation, and this relay will not serve \
             it again. Restore it with --keep-incarnation on exactly one host."
        );
    } else {
        println!(
            "Not complete: the relay may commit more after this snapshot, so restoring it always \
             starts a new incarnation. It preserves the relay identity and access grants."
        );
    }
    Ok(())
}

/// Copy only the expected files into a private directory before authenticating them. Later
/// reads use this copy so that changes to the source cannot alter what gets installed.
fn stage_backup(dir: &Path, from: &Path, keep_incarnation: bool) -> Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;

    let staged = tempfile::Builder::new()
        .prefix(".restore-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(dir)?;
    for name in BACKUP_FILES
        .into_iter()
        .chain([MANIFEST_FILE, SIGNATURE_FILE])
    {
        if name == DB_FILE && !keep_incarnation {
            continue;
        }
        let source = from.join(name);
        let meta =
            fs::symlink_metadata(&source).with_context(|| format!("read {}", source.display()))?;
        ensure!(
            meta.file_type().is_file(),
            "{} is not a regular file",
            source.display()
        );
        let mut file = File::open(&source).with_context(|| format!("read {}", source.display()))?;
        ensure!(
            file.metadata()?.is_file(),
            "{} is not a regular file",
            source.display()
        );
        let mut copy = File::create(staged.path().join(name))?;
        std::io::copy(&mut file, &mut copy)
            .and_then(|_| copy.sync_all())
            .with_context(|| format!("stage {}", source.display()))?;
    }
    Ok(staged)
}

/// Read and verify a backup's manifest, signature and file digests against the relay identity
/// the operator expects. Returns the manifest and the backed-up profile.
fn verify_backup(from: &Path, snapshot: &Path, expect: &EndpointId) -> Result<(Manifest, Profile)> {
    let bytes = fs::read(from.join(MANIFEST_FILE))
        .with_context(|| format!("read {}", from.join(MANIFEST_FILE).display()))?;
    let signature: [u8; 64] = fs::read(from.join(SIGNATURE_FILE))
        .with_context(|| format!("read {}", from.join(SIGNATURE_FILE).display()))?
        .try_into()
        .ok()
        .context("the backup signature is malformed")?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).context("the backup manifest is malformed")?;
    ensure!(
        manifest.format == MANIFEST_FORMAT,
        "unsupported backup format {:?}",
        manifest.format
    );
    ensure!(
        manifest.relay == *expect,
        "this backup is of relay {}, not {expect}; nothing was restored",
        manifest.relay
    );
    expect
        .verify(&signed(&bytes), &Signature::from_bytes(&signature))
        .map_err(|_| {
            anyhow::anyhow!(
                "the backup manifest is not signed by relay {expect}; nothing was restored"
            )
        })?;
    let names: Vec<&str> = manifest
        .files
        .iter()
        .map(|file| file.name.as_str())
        .collect();
    ensure!(
        names == BACKUP_FILES,
        "the backup manifest lists unexpected files"
    );
    for file in &manifest.files {
        let path = if file.name == DB_FILE {
            snapshot.to_path_buf()
        } else {
            from.join(&file.name)
        };
        let meta =
            fs::symlink_metadata(&path).with_context(|| format!("read {}", path.display()))?;
        ensure!(
            meta.file_type().is_file(),
            "{} is not a regular file",
            path.display()
        );
        let (len, sha256) = digest_file(&path)?;
        ensure!(
            len == file.len && sha256 == file.sha256.0,
            "{} does not match the signed manifest; nothing was restored",
            path.display()
        );
    }
    let profile: Profile = serde_json::from_slice(&fs::read(from.join(PRIVATE_PROFILE_FILE))?)
        .context("the backed-up profile is malformed")?;
    check_profile(&profile)?;
    ensure!(
        profile.server.id == *expect && profile.incarnation == manifest.incarnation,
        "the backed-up profile does not match its manifest"
    );
    let grants: Grants = serde_json::from_slice(&fs::read(from.join(ACCESS_FILE))?)
        .context("the backed-up access grants are malformed")?;
    ensure!(
        grants.format == ACCESS_FORMAT,
        "unsupported access grants format {:?}",
        grants.format
    );
    Ok((manifest, profile))
}

/// Restore a backup into `dir`, which must hold no relay state, as relay `expect`.
///
/// With `keep_incarnation`, the backup must be complete (taken from a sealed store), unused,
/// signed by `expect`, and its snapshot must verify in full and match the manifest; the store
/// is then installed with its incarnation and every occupied marker, and clients continue.
/// The backup is marked used before the store is installed, so it cannot seed a second copy.
/// Without it, the relay identity and grants are restored with a new, empty incarnation, and
/// the snapshot is left untouched in the backup.
pub fn store_restore(
    dir: &Path,
    from: &Path,
    expect: &EndpointId,
    keep_incarnation: bool,
) -> Result<()> {
    let _lock = storage::lock(dir)?;
    refuse_legacy(dir)?;
    for name in [PRIVATE_PROFILE_FILE, ACCESS_FILE, SEALED_FILE, STORE_DIR] {
        ensure!(
            !dir.join(name).try_exists()?,
            "{} already holds private relay state ({name}); restore into a new directory",
            dir.display()
        );
    }
    let staged = stage_backup(dir, from, keep_incarnation)?;
    restore_staged(dir, from, staged.path(), expect, keep_incarnation)
}

fn restore_staged(
    dir: &Path,
    from: &Path,
    staged: &Path,
    expect: &EndpointId,
    keep_incarnation: bool,
) -> Result<()> {
    let snapshot = if keep_incarnation {
        staged.join(DB_FILE)
    } else {
        // No snapshot body is installed on this path. Check its digest in place.
        from.join(DB_FILE)
    };
    let (manifest, mut profile) = verify_backup(staged, &snapshot, expect)?;
    let grants = fs::read(staged.join(ACCESS_FILE))?;
    if keep_incarnation {
        ensure!(
            manifest.complete,
            "this backup is not complete: its relay was not sealed before it was taken, so \
             objects committed later would be lost and their slots could be filled again. \
             Restore it without --keep-incarnation to start a new incarnation"
        );
        ensure!(
            !from.join(CONSUMED_FILE).try_exists()?,
            "this final backup was already restored once ({}); a second copy of an \
             incarnation could accept conflicting objects. Nothing was restored",
            from.join(CONSUMED_FILE).display()
        );
        let (incarnation, summary) = SlotStore::verify_snapshot(&snapshot)?;
        ensure!(
            incarnation == profile.incarnation() && summary == manifest.summary(),
            "the snapshot does not hold what its manifest records; nothing was restored"
        );
        #[derive(Serialize)]
        struct Consumed<'a> {
            restored: u64,
            into: &'a Path,
        }
        write_new(
            &from.join(CONSUMED_FILE),
            &serde_json::to_vec(&Consumed {
                restored: storage::now(),
                into: dir,
            })?,
        )?;
        sync_dir(from)?;
        let store = SlotStore::install_staged(&dir.join(STORE_DIR), &snapshot, &incarnation)?;
        drop(store);
        write_new(&dir.join(ACCESS_FILE), &grants)?;
        write_new(
            &dir.join(PRIVATE_PROFILE_FILE),
            &fs::read(staged.join(PRIVATE_PROFILE_FILE))?,
        )?;
        sync_dir(dir)?;
        println!(
            "Restored relay {expect} with incarnation {}",
            hex(&incarnation.to_bytes())
        );
        print_summary(&summary);
        println!("Clients continue unchanged once the relay runs at its addresses.");
        return Ok(());
    }
    let store = SlotStore::initialize(&dir.join(STORE_DIR))?;
    profile.incarnation = store.incarnation().into();
    drop(store);
    write_new(&dir.join(ACCESS_FILE), &grants)?;
    storage::save(dir, PRIVATE_PROFILE_FILE, &profile)?;
    println!(
        "Restored relay {expect} and its access grants with a NEW incarnation {}.",
        hex(&profile.incarnation.0)
    );
    println!(
        "No objects were restored. Clients pinned to incarnation {} refuse this store; their \
         networks must be created again. Issue locators with 'massrelay relay-grants \
         issue'.",
        hex(&manifest.incarnation.0)
    );
    Ok(())
}

/// Set the current store aside, untouched, under `retired/`, and start a new incarnation in
/// place. For a damaged, lost, sealed or otherwise uncertain store. Nothing is deleted.
pub fn store_rotate(dir: &Path) -> Result<()> {
    let _lock = storage::lock(dir)?;
    refuse_legacy(dir)?;
    let mut profile = load_profile(dir)?;
    let old = profile.incarnation;
    let mailbox = dir.join(STORE_DIR);
    let has_sealed = dir.join(SEALED_FILE).try_exists()?;
    if mailbox.try_exists()? || has_sealed {
        let retired = dir.join(RETIRED_DIR);
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        let place = retired.join(format!("{}-{}", storage::now(), hex(&old.0[..8])));
        builder
            .create(&place)
            .with_context(|| format!("create {}", place.display()))?;
        if mailbox.try_exists()? {
            fs::rename(&mailbox, place.join(STORE_DIR))
                .with_context(|| format!("set aside {}", mailbox.display()))?;
        }
        if has_sealed {
            fs::rename(dir.join(SEALED_FILE), place.join(SEALED_FILE))?;
        }
        sync_dir(&place)?;
        sync_dir(&retired)?;
        sync_dir(dir)?;
        eprintln!("Set the previous store aside in {}.", place.display());
    }
    let store = SlotStore::initialize(&mailbox)?;
    profile.incarnation = store.incarnation().into();
    drop(store);
    storage::save(dir, PRIVATE_PROFILE_FILE, &profile)?;
    println!(
        "New incarnation {} replaces {}.",
        hex(&profile.incarnation.0),
        hex(&old.0)
    );
    println!(
        "Clients pinned to the previous incarnation refuse this store; their networks must be \
         created again. Access grants are unchanged; issue locators with 'massrelay \
         relay-grants issue'."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;

    fn addresses() -> (SocketAddr, RelayUrl) {
        (
            "127.0.0.1:4433".parse().unwrap(),
            "http://127.0.0.1:3340".parse().unwrap(),
        )
    }

    fn err(result: Result<impl Sized>) -> String {
        match result {
            Ok(_) => panic!("expected a refusal"),
            Err(error) => format!("{error:#}"),
        }
    }

    #[test]
    fn creation_and_reopen_are_explicit_and_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let (udp, url) = addresses();
        assert!(err(open(dir.path(), false)).contains("no private relay"));
        assert!(!dir.path().join(STORE_DIR).exists(), "open must not create");

        let (profile, access) = create(dir.path(), udp, url.clone()).unwrap();
        let locator = Locator::decode(&profile.locator(access).encode().unwrap()).unwrap();
        assert!(locator.access == access);
        assert_eq!(locator.server.id, profile.server.id);
        assert_eq!(locator.incarnation, profile.incarnation);

        let (reopened, store) = open(dir.path(), false).unwrap();
        assert_eq!(reopened.server.id, profile.server.id);
        assert_eq!(store.incarnation(), locator.incarnation());
        drop(store);

        assert!(err(create(dir.path(), udp, url)).contains("already initialized"));
        assert_eq!(
            open(dir.path(), false).unwrap().0.server.id,
            profile.server.id
        );
    }

    #[test]
    fn relay_refuses_to_reuse_legacy_state_directory() {
        let (udp, url) = addresses();
        let legacy = tempfile::tempdir().unwrap();
        std::fs::write(legacy.path().join(LEGACY_PROFILE_FILE), b"{}").unwrap();
        assert!(err(create(legacy.path(), udp, url.clone())).contains("legacy relay"));
        assert!(err(open(legacy.path(), false)).contains("legacy relay"));
        assert!(!legacy.path().join(PRIVATE_PROFILE_FILE).exists());
        assert!(!legacy.path().join(STORE_DIR).exists());
    }

    #[test]
    fn relay_urls_with_credentials_are_never_saved_or_printed() {
        let (udp, _) = addresses();
        for url in [
            "http://user@127.0.0.1:3340",
            "https://user:secret@relay.example",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = dir.path().join("state");
            let url: RelayUrl = url.parse().unwrap();
            assert!(err(create(&state, udp, url.clone())).contains("user name or password"));
            assert!(!state.exists(), "nothing was created");
            let locator = Locator {
                server: ServerAddr {
                    id: SecretKey::from_bytes(&[1; 32]).public(),
                    udp,
                    relay: url.clone(),
                },
                incarnation: Bytes([2; 32]),
                access: AccessKey(Bytes([3; 32])),
            };
            assert!(locator.encode().is_err());
            let smuggled = format!(
                "{}{}",
                crate::mailbox::LOCATOR_PREFIX,
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&locator).unwrap())
            );
            assert!(Locator::decode(&smuggled).is_err());
        }

        // A saved profile edited to carry credentials is refused before its locator is printed.
        let dir = tempfile::tempdir().unwrap();
        let (udp, url) = addresses();
        create(dir.path(), udp, url).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join(PRIVATE_PROFILE_FILE)).unwrap())
                .unwrap();
        value["server"]["relay"] = "http://user:secret@127.0.0.1:3340/".into();
        storage::save(dir.path(), PRIVATE_PROFILE_FILE, &value).unwrap();
        assert!(err(open(dir.path(), false)).contains("user name or password"));
    }

    /// The mailbox recovers its own interrupted writes under an intact profile; anything it
    /// cannot prove is refused without touching the profile.
    #[test]
    fn mailbox_recovery_states_under_a_profile() {
        let (udp, url) = addresses();
        let dir = tempfile::tempdir().unwrap();
        let (profile, _) = create(dir.path(), udp, url.clone()).unwrap();
        let incarnation = Incarnation::from_bytes(profile.incarnation.0);
        let slot = crate::slot_store::SlotAddress::from_bytes([4; 32]);
        let (_, store) = open(dir.path(), false).unwrap();
        store.put(&incarnation, &slot, b"committed").unwrap();
        drop(store);
        let journal = dir.path().join(STORE_DIR).join(crate::slot_store::DB_FILE);
        let committed = std::fs::read(&journal).unwrap();

        // A partially copied database: refused, unchanged.
        let torn = committed[..committed.len() / 2].to_vec();
        std::fs::write(&journal, &torn).unwrap();
        assert!(err(open(dir.path(), false)).contains("damaged"));
        assert_eq!(std::fs::read(&journal).unwrap(), torn);
        std::fs::write(&journal, &committed).unwrap();

        // A partially initialized mailbox without a profile is neither opened nor reused.
        let interrupted = tempfile::tempdir().unwrap();
        std::fs::create_dir(interrupted.path().join(STORE_DIR)).unwrap();
        std::fs::write(interrupted.path().join(STORE_DIR).join("intent"), b"").unwrap();
        assert!(err(open(interrupted.path(), false)).contains("without a private relay profile"));
        assert!(
            err(create(interrupted.path(), udp, url)).contains("without a private relay profile")
        );

        let (_, store) = open(dir.path(), false).unwrap();
        assert!(matches!(
            store.get(&incarnation, &slot).unwrap(),
            crate::slot_store::ReadOutcome::Present(body) if body.as_bytes() == b"committed"
        ));
    }

    #[test]
    fn incomplete_or_mismatched_state_fails_closed() {
        let (udp, url) = addresses();
        let dir = tempfile::tempdir().unwrap();
        let (profile, _) = create(dir.path(), udp, url.clone()).unwrap();
        let saved = std::fs::read(dir.path().join(PRIVATE_PROFILE_FILE)).unwrap();

        // A mailbox from another initialization.
        let other = tempfile::tempdir().unwrap();
        create(other.path(), udp, url.clone()).unwrap();
        let mailbox = dir.path().join(STORE_DIR);
        std::fs::rename(&mailbox, dir.path().join("kept")).unwrap();
        std::fs::rename(other.path().join(STORE_DIR), &mailbox).unwrap();
        let foreign = std::fs::read(mailbox.join(crate::slot_store::DB_FILE)).unwrap();
        std::fs::write(mailbox.join("staging").join(".stage-foreign"), b"staged").unwrap();
        assert!(err(open(dir.path(), false)).contains("another incarnation"));
        assert_eq!(
            std::fs::read(mailbox.join(crate::slot_store::DB_FILE)).unwrap(),
            foreign
        );
        assert!(
            mailbox.join("staging").join(".stage-foreign").exists(),
            "no cleanup ran"
        );
        std::fs::remove_dir_all(&mailbox).unwrap();
        std::fs::rename(dir.path().join("kept"), &mailbox).unwrap();
        open(dir.path(), false).unwrap();

        // A profile without its mailbox, and a mailbox without its profile.
        std::fs::rename(&mailbox, dir.path().join("kept")).unwrap();
        assert!(err(open(dir.path(), false)).contains("lost its mailbox"));
        std::fs::rename(dir.path().join("kept"), &mailbox).unwrap();
        std::fs::remove_file(dir.path().join(PRIVATE_PROFILE_FILE)).unwrap();
        assert!(err(open(dir.path(), false)).contains("without a private relay profile"));
        assert!(err(create(dir.path(), udp, url)).contains("without a private relay profile"));
        assert!(
            mailbox.join(crate::slot_store::DB_FILE).is_file(),
            "nothing was reset"
        );

        // A profile of an unknown format or with a key that is not its identity.
        let mut value: serde_json::Value = serde_json::from_slice(&saved).unwrap();
        value["format"] = "massrelay-private-relay/experimental-9".into();
        storage::save(dir.path(), PRIVATE_PROFILE_FILE, &value).unwrap();
        assert!(err(open(dir.path(), false)).contains("unsupported"));
        let mut value: serde_json::Value = serde_json::from_slice(&saved).unwrap();
        value["key"] = serde_json::to_value([7u8; 32]).unwrap();
        storage::save(dir.path(), PRIVATE_PROFILE_FILE, &value).unwrap();
        assert!(err(open(dir.path(), false)).contains("does not match"));

        std::fs::write(dir.path().join(PRIVATE_PROFILE_FILE), &saved).unwrap();
        assert_eq!(
            open(dir.path(), false).unwrap().0.server.id,
            profile.server.id
        );
    }

    fn slot(byte: u8) -> crate::slot_store::SlotAddress {
        crate::slot_store::SlotAddress::from_bytes([byte; 32])
    }

    fn put(dir: &Path, byte: u8) {
        let (profile, store) = open(dir, false).unwrap();
        let written = store
            .put(&profile.incarnation(), &slot(byte), &[byte; 9])
            .unwrap();
        assert_eq!(written, crate::slot_store::WriteOutcome::Created);
    }

    fn holds(dir: &Path, byte: u8) -> bool {
        let (profile, store) = open(dir, true).unwrap();
        store.get(&profile.incarnation(), &slot(byte)).unwrap()
            != crate::slot_store::ReadOutcome::Absent
    }

    /// Grants hold verifiers, never secrets; revocation keeps the record and removes it from
    /// what the relay admits; a relay without a grants file does not start.
    #[test]
    fn access_grants_are_operator_records_without_secrets() {
        let (udp, url) = addresses();
        let dir = tempfile::tempdir().unwrap();
        let (_, initial) = create(dir.path(), udp, url).unwrap();
        let second = issue_grant(dir.path(), "second network").unwrap();
        assert!(err(issue_grant(dir.path(), "bad\nlabel")).contains("printable"));
        let grants = Grants::load(dir.path()).unwrap();
        assert_eq!(grants.current(), [initial.verifier(), second.verifier()]);
        let saved = std::fs::read(dir.path().join(ACCESS_FILE)).unwrap();
        for secret in [initial, second] {
            let encoded = serde_json::to_string(&secret).unwrap();
            let encoded = encoded.trim_matches('"');
            assert!(
                !String::from_utf8_lossy(&saved).contains(encoded),
                "a secret was stored"
            );
        }

        access_revoke(dir.path(), &grant_id(&initial.verifier())).unwrap();
        access_revoke(dir.path(), &grant_id(&initial.verifier())).unwrap();
        assert!(err(access_revoke(dir.path(), "0000")).contains("no access grant"));
        let grants = Grants::load(dir.path()).unwrap();
        assert_eq!(grants.grants.len(), 2, "revoked grants stay listed");
        assert_eq!(grants.current(), [second.verifier()]);

        // An edited grant whose id no longer matches its verifier is refused.
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join(ACCESS_FILE)).unwrap()).unwrap();
        value["grants"][1]["verifier"] = serde_json::to_value(Bytes([1u8; 32])).unwrap();
        storage::save(dir.path(), ACCESS_FILE, &value).unwrap();
        assert!(err(Grants::load(dir.path())).contains("does not match"));

        std::fs::remove_file(dir.path().join(ACCESS_FILE)).unwrap();
        assert!(err(Grants::load(dir.path())).contains("no access grants"));
        // Issuing creates a fresh file for a relay that has none.
        let third = issue_grant(dir.path(), "").unwrap();
        assert_eq!(
            Grants::load(dir.path()).unwrap().current(),
            [third.verifier()]
        );
    }

    /// Only a complete snapshot, taken after sealing and verified against the relay identity
    /// the operator names, keeps its incarnation and occupied markers, and only once. Every
    /// other restore starts a new incarnation; a tampered backup restores nothing.
    #[test]
    fn restores_keep_the_incarnation_only_from_a_complete_trusted_snapshot() {
        let (udp, url) = addresses();
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("relay");
        let (profile, _) = create(&dir, udp, url).unwrap();
        let id = profile.server.id;
        put(&dir, 1);

        // A periodic backup: the relay keeps serving, so it is never complete.
        let periodic = root.path().join("periodic");
        store_backup(&dir, &periodic, false).unwrap();
        assert!(err(store_backup(&dir, &periodic, false)).contains("never overwrites"));
        assert!(!dir.join(SEALED_FILE).exists());
        put(&dir, 2);
        let target = root.path().join("from-periodic");
        assert!(err(store_restore(&target, &periodic, &id, true)).contains("not complete"));
        assert!(!target.join(STORE_DIR).exists());
        store_restore(&target, &periodic, &id, false).unwrap();
        let (rotated, _) = open(&target, false).unwrap();
        assert_eq!(rotated.server.id, id);
        assert_ne!(rotated.incarnation, profile.incarnation);
        assert!(
            !holds(&target, 1),
            "no objects are re-seeded into a new incarnation"
        );
        assert_eq!(
            Grants::load(&target).unwrap().current(),
            Grants::load(&dir).unwrap().current()
        );

        // A final backup seals the source first.
        let last = root.path().join("final");
        store_backup(&dir, &last, true).unwrap();
        assert!(err(open(&dir, false)).contains("sealed"));
        store_check(&dir).unwrap();
        let again = root.path().join("final-again");
        store_backup(&dir, &again, false).unwrap();

        // Trust is anchored in the identity the operator names, and every byte is checked.
        let other = SecretKey::from_bytes(&[9; 32]).public();
        let target = root.path().join("restored");
        assert!(err(store_restore(&target, &last, &other, true)).contains("not "));
        let forged = root.path().join("forged");
        std::fs::create_dir(&forged).unwrap();
        for entry in std::fs::read_dir(&last).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), forged.join(entry.file_name())).unwrap();
        }
        let mut db = std::fs::read(forged.join(DB_FILE)).unwrap();
        let at = db.windows(9).position(|w| w == [2u8; 9]).unwrap();
        db[at] ^= 1;
        std::fs::write(forged.join(DB_FILE), &db).unwrap();
        assert!(err(store_restore(&target, &forged, &id, true)).contains("does not match"));
        let mut manifest = std::fs::read(forged.join(MANIFEST_FILE)).unwrap();
        let text = String::from_utf8(manifest.clone()).unwrap();
        manifest = text
            .replace("\"complete\": true", "\"complete\": false")
            .into_bytes();
        std::fs::write(forged.join(MANIFEST_FILE), &manifest).unwrap();
        assert!(err(store_restore(&target, &forged, &id, true)).contains("not signed"));
        assert!(!target.join(STORE_DIR).exists());
        assert!(!target.join(PRIVATE_PROFILE_FILE).exists());

        // The complete snapshot restores once, with its incarnation and occupied markers.
        store_restore(&target, &last, &id, true).unwrap();
        let (restored, store) = open(&target, false).unwrap();
        assert_eq!(restored.incarnation, profile.incarnation);
        assert_eq!(
            store
                .put(&restored.incarnation(), &slot(2), b"different")
                .unwrap(),
            crate::slot_store::WriteOutcome::Occupied
        );
        drop(store);
        assert!(holds(&target, 1) && holds(&target, 2));
        let second = root.path().join("second-copy");
        assert!(err(store_restore(&second, &last, &id, true)).contains("already restored"));
        assert!(!second.join(STORE_DIR).exists());
        // A restore never merges into existing state.
        assert!(err(store_restore(&target, &again, &id, true)).contains("already holds"));
    }

    #[test]
    fn restore_uses_verified_staged_files_when_source_changes() {
        let (udp, url) = addresses();
        let root = tempfile::tempdir().unwrap();
        let relay = root.path().join("relay");
        let (profile, _) = create(&relay, udp, url).unwrap();
        put(&relay, 1);
        let periodic = root.path().join("periodic");
        store_backup(&relay, &periodic, false).unwrap();
        put(&relay, 2);
        let backup = root.path().join("final");
        store_backup(&relay, &backup, true).unwrap();

        let target = root.path().join("restored");
        let _lock = storage::lock(&target).unwrap();
        let staged = stage_backup(&target, &backup, true).unwrap();
        fs::copy(periodic.join(DB_FILE), backup.join(DB_FILE)).unwrap();
        fs::write(
            backup.join(ACCESS_FILE),
            serde_json::to_vec(&Grants::empty()).unwrap(),
        )
        .unwrap();

        restore_staged(&target, &backup, staged.path(), &profile.server.id, true).unwrap();
        assert!(!staged.path().join(DB_FILE).exists());
        assert!(holds(&target, 2));
        assert_eq!(
            Grants::load(&target).unwrap().current(),
            Grants::load(&relay).unwrap().current()
        );
        assert!(backup.join(CONSUMED_FILE).exists());
    }

    /// Rotation sets the store aside untouched, sealed or damaged alike, and starts a new
    /// incarnation; a damaged store is refused, never repaired.
    #[test]
    fn rotation_sets_the_store_aside_and_starts_a_new_incarnation() {
        let (udp, url) = addresses();
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("relay");
        let (profile, _) = create(&dir, udp, url).unwrap();
        put(&dir, 1);
        let db = dir.join(STORE_DIR).join(DB_FILE);
        let committed = std::fs::read(&db).unwrap();
        std::fs::write(&db, &committed[..committed.len() / 2]).unwrap();
        let refused = err(open(&dir, false));
        assert!(
            refused.contains("damaged") && refused.contains("check"),
            "{refused}"
        );

        store_rotate(&dir).unwrap();
        let (rotated, _) = open(&dir, false).unwrap();
        assert_ne!(rotated.incarnation, profile.incarnation);
        assert_eq!(rotated.server.id, profile.server.id);
        assert!(!holds(&dir, 1));
        let retired: Vec<_> = std::fs::read_dir(dir.join(RETIRED_DIR))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(retired.len(), 1);
        assert_eq!(
            std::fs::read(retired[0].join(STORE_DIR).join(DB_FILE)).unwrap(),
            committed[..committed.len() / 2],
            "the old store is kept exactly"
        );

        // A sealed store rotates too, and its seal goes with it.
        store_backup(&dir, &root.path().join("final"), true).unwrap();
        assert!(err(open(&dir, false)).contains("sealed"));
        store_rotate(&dir).unwrap();
        open(&dir, false).unwrap();
        assert!(!dir.join(SEALED_FILE).exists());
        assert_eq!(std::fs::read_dir(dir.join(RETIRED_DIR)).unwrap().count(), 2);
    }
}
