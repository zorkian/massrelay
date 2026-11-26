//! Local store of opaque, immutable slot objects for a private discovery relay.
//!
//! This is a storage foundation with no network surface. It knows nothing about groups, members,
//! rosters, MLS or the wire format. A slot is addressed by an opaque 32-byte [`SlotAddress`] and
//! holds exactly one opaque byte body, forever. The first committed body wins; an identical retry
//! reports [`WriteOutcome::ExactRetry`] and any different body reports [`WriteOutcome::Occupied`]
//! without touching the stored one. A caller verifies the writer's proof for the slot before it
//! stages a body here; this layer authorizes nothing.
//!
//! Experimental. Built for Unix with the off-by-default `private-relay` feature, on the SQLite
//! already required by the private membership build.
//!
//! # Layout
//!
//! ```text
//! <root>/lock       exclusive lock held while a store is open
//! <root>/slots.db   SQLite database in WAL mode (with its -wal and -shm files)
//! <root>/staging/   bodies still arriving, never authoritative
//! ```
//!
//! The store also keeps append-only opaque queues: each item is an immutable object, named by
//! its digest, committed in the same transaction as its queue row, and ordered by the store;
//! a terminal acknowledgement is an immutable record beside it. Nothing is ever removed:
//! reclaiming acknowledged items is a future explicit operator step.
//!
//! The database holds the store's format and random 32-byte [`Incarnation`], one row per
//! occupied slot (address, length, SHA-256 digest), and the body as ordinary rows of at most
//! [`CHUNK`] bytes keyed by slot and sequence. The chunk size is a buffer and row format, not a
//! limit on a body's size or a slot's count. Triggers refuse any update or delete of a slot or
//! chunk row.
//!
//! # Writes
//!
//! A body is streamed into `staging/` through a bounded buffer while it is hashed, outside any
//! database transaction, so a slow writer never holds the database writer. Committing then runs
//! one SQLite transaction that inserts the slot row and every chunk, copied from the staged file
//! through the same bounded buffer. Only a successful commit returns [`WriteOutcome::Created`];
//! other connections see the slot only once committed. A failure before the commit rolls the
//! transaction back and reports [`SlotStoreError::WriteFailed`]: nothing was published. A failed
//! commit is [`SlotStoreError::Unconfirmed`]: the slot may or may not hold the body. That handle
//! then refuses further writes, and reads it cannot confirm, with
//! [`SlotStoreError::NeedsReopen`]; reopening reads SQLite's committed state. Occupancy and body
//! are one commit, so there is never an occupied marker without its body or a body without its
//! marker. A staged body has no authority and open discards it.
//!
//! Durability uses SQLite's WAL with `synchronous = FULL` and `fullfsync`, which makes every
//! commit durable on a filesystem that honors sync and supports SQLite's locking and shared
//! memory (a local filesystem, not a network share). Initialization and open also sync the root
//! and the directory holding it. Tests cover process aborts and injected faults, not power loss.
//!
//! # Opening
//!
//! [`SlotStore::initialize`] creates a store with a fresh random incarnation, only in an empty or
//! absent directory. [`SlotStore::open`] only reopens: it refuses a missing root, a database
//! without a committed format and incarnation (an interrupted initialization), and anything that
//! is not this format. [`SlotStore::open_expecting`] compares the incarnation, read through a
//! query-only connection that does not checkpoint on close, before any application write or
//! cleanup; SQLite's own recovery of an interrupted transaction is the engine's and restores
//! the last committed state. Open then runs SQLite's `quick_check` and verifies every slot's
//! chunks against its length and digest, refusing [`SlotStoreError::Damaged`] on any mismatch.
//!
//! # Snapshot and restore
//!
//! [`SlotStore::snapshot_to`] writes one consistent copy of the committed database with SQLite's
//! `VACUUM INTO`, which includes commits still in the write-ahead log (copying `slots.db` alone
//! would lose them), as a single synced rollback-journal file, and verifies it in full.
//! [`SlotStore::verify_snapshot`] checks such a file read-only, and [`SlotStore::install_staged`]
//! creates a store from one, only in an empty directory and only for the expected incarnation.
//! The store keeps its incarnation only across such a complete restore. A damaged or
//! incomplete database is refused. A coherent older copy cannot be distinguished from the
//! current state by its own contents: it opens with the same incarnation and serves its older
//! view. Completeness must therefore come from outside the copy; the private relay seals a
//! store before a final snapshot, and any other restore uses a new incarnation
//! (`docs/private-relay-operations.md`).
//!
//! Open and verification compare the schema with this format's exactly, table by table, index
//! by index and trigger by trigger, so a store whose immutability triggers are missing or that
//! carries extra triggers or views is damaged; connections run with `trusted_schema` off.
//!
//! # No delete
//!
//! There is no delete or purge API. A future explicit operator purge must keep the slot row,
//! which holds the address, length and digest (so exact retries remain distinguishable), make
//! reads report the body as deliberately unavailable, keep writes refused, and never happen as a
//! side effect of a write, a cap or automatic pruning.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use fs2::FileExt as _;
use rusqlite::{Connection, OpenFlags, OptionalExtension, config::DbConfig, params};
use sha2::{Digest, Sha256};

pub use crate::slot_wire::{CHUNK, Incarnation, SlotAddress};

const LOCK_FILE: &str = "lock";
pub(crate) const DB_FILE: &str = "slots.db";
const STAGING_DIR: &str = "staging";
const STAGE_PREFIX: &str = ".stage-";
const FORMAT: &str = "massrelay-private-slot-store/sqlite-2";
/// `PRAGMA application_id`: "MRSL".
const APPLICATION_ID: i64 = 0x4D52_534C;
const SCHEMA_VERSION: i64 = 2;
const ITEM_DOMAIN: &[u8] = b"massrelay slot store queue item\0";

const SCHEMA: &str = "
    CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
    CREATE TABLE slots (
        slot BLOB PRIMARY KEY CHECK (length(slot) = 32),
        len INTEGER NOT NULL CHECK (len >= 0),
        digest BLOB NOT NULL CHECK (length(digest) = 32)
    ) STRICT, WITHOUT ROWID;
    CREATE TABLE chunks (
        slot BLOB NOT NULL REFERENCES slots (slot),
        seq INTEGER NOT NULL CHECK (seq >= 0),
        bytes BLOB NOT NULL,
        PRIMARY KEY (slot, seq)
    ) STRICT, WITHOUT ROWID;
    CREATE TRIGGER meta_fixed_update BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'immutable'); END;
    CREATE TRIGGER meta_fixed_delete BEFORE DELETE ON meta BEGIN SELECT RAISE(ABORT, 'immutable'); END;
    CREATE TRIGGER slots_fixed_update BEFORE UPDATE ON slots BEGIN SELECT RAISE(ABORT, 'immutable'); END;
    CREATE TRIGGER slots_fixed_delete BEFORE DELETE ON slots BEGIN SELECT RAISE(ABORT, 'immutable'); END;
    CREATE TRIGGER chunks_fixed_update BEFORE UPDATE ON chunks BEGIN SELECT RAISE(ABORT, 'immutable'); END;
    CREATE TRIGGER chunks_fixed_delete BEFORE DELETE ON chunks BEGIN SELECT RAISE(ABORT, 'immutable'); END;
    CREATE TABLE queue_items (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        queue BLOB NOT NULL CHECK (length(queue) = 32),
        item BLOB NOT NULL CHECK (length(item) = 32),
        object BLOB NOT NULL UNIQUE REFERENCES slots (slot),
        UNIQUE (queue, item)
    ) STRICT;
    CREATE TABLE queue_acks (
        queue BLOB NOT NULL,
        item BLOB NOT NULL,
        PRIMARY KEY (queue, item),
        FOREIGN KEY (queue, item) REFERENCES queue_items (queue, item)
    ) STRICT, WITHOUT ROWID;
    CREATE TRIGGER queue_items_fixed_update BEFORE UPDATE ON queue_items BEGIN SELECT RAISE(ABORT, 'immutable'); END;
    CREATE TRIGGER queue_items_fixed_delete BEFORE DELETE ON queue_items BEGIN SELECT RAISE(ABORT, 'immutable'); END;
    CREATE TRIGGER queue_acks_fixed_update BEFORE UPDATE ON queue_acks BEGIN SELECT RAISE(ABORT, 'immutable'); END;
    CREATE TRIGGER queue_acks_fixed_delete BEFORE DELETE ON queue_acks BEGIN SELECT RAISE(ABORT, 'immutable'); END;
";

/// Immutable opaque bytes read whole from a slot.
#[derive(Clone, PartialEq, Eq)]
pub struct SlotPayload(Box<[u8]>);

impl SlotPayload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SlotPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlotPayload({} bytes)", self.0.len())
    }
}

/// Result of a create-if-absent write that reached a durable decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    /// This write published the slot's value.
    Created,
    /// The slot already holds exactly these bytes.
    ExactRetry,
    /// The slot already holds different bytes, which remain unchanged.
    Occupied,
}

/// Result of a whole-slot read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    Present(SlotPayload),
    Absent,
}

#[derive(Debug)]
pub enum SlotStoreError {
    /// The store root does not exist. Nothing was created.
    Missing { root: PathBuf },
    /// The root holds no completed store. Nothing was created or removed.
    Incomplete { root: PathBuf, detail: String },
    /// The store failed validation. It was not opened, repaired or reset.
    Damaged { root: PathBuf, detail: String },
    /// The path layout could let two stores share data. Nothing was opened.
    UnsafeLayout { root: PathBuf, detail: String },
    /// Initialization found existing contents and changed nothing.
    NotEmpty { root: PathBuf },
    /// Another handle holds the store's lock.
    Locked { root: PathBuf },
    /// The caller's incarnation differs from this store's. Nothing was read or written.
    WrongIncarnation,
    /// The staged body does not match the digest the writer claimed. Nothing was written.
    BodyMismatch,
    /// A stored body failed its length or digest after open. Its slot stays occupied.
    CorruptObject { slot: SlotAddress },
    /// The write failed before anything was committed. The slot is unchanged.
    WriteFailed { context: String, source: io::Error },
    /// The commit itself failed. The slot may or may not hold this body; it is never known to
    /// be absent. Reopen to resolve it.
    Unconfirmed { context: String, source: io::Error },
    /// An earlier commit on this handle is unconfirmed, so this answer cannot be given safely.
    NeedsReopen,
    /// Any other I/O failure. It never implies a slot is absent.
    Io { context: String, source: io::Error },
}

impl fmt::Display for SlotStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { root } => write!(f, "no slot store at {}", root.display()),
            Self::Incomplete { root, detail } => write!(
                f,
                "slot store at {} is not initialized ({detail}); nothing was changed",
                root.display()
            ),
            Self::Damaged { root, detail } => write!(
                f,
                "slot store at {} is damaged or partially restored ({detail}); it was not opened",
                root.display()
            ),
            Self::UnsafeLayout { root, detail } => write!(
                f,
                "unsafe slot store layout at {} ({detail})",
                root.display()
            ),
            Self::NotEmpty { root } => write!(
                f,
                "{} is not empty; a slot store is only initialized in an empty directory",
                root.display()
            ),
            Self::Locked { root } => write!(f, "slot store at {} is in use", root.display()),
            Self::WrongIncarnation => write!(f, "slot store incarnation mismatch"),
            Self::BodyMismatch => write!(f, "the body does not match its claimed digest"),
            Self::CorruptObject { slot } => write!(f, "stored body for {slot:?} is damaged"),
            Self::WriteFailed { context, source } => {
                write!(f, "{context}: {source}; nothing was published")
            }
            Self::Unconfirmed { context, source } => {
                write!(f, "{context}: {source}; the result is unconfirmed")
            }
            Self::NeedsReopen => write!(
                f,
                "an earlier slot store commit is unconfirmed; reopen the store to resolve it"
            ),
            Self::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for SlotStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WriteFailed { source, .. }
            | Self::Unconfirmed { source, .. }
            | Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn io_error(context: impl FnOnce() -> String) -> impl FnOnce(io::Error) -> SlotStoreError {
    move |source| SlotStoreError::Io {
        context: context(),
        source,
    }
}

fn sql_io(error: rusqlite::Error) -> io::Error {
    io::Error::other(error)
}

fn sql_error(context: impl FnOnce() -> String) -> impl FnOnce(rusqlite::Error) -> SlotStoreError {
    move |error| SlotStoreError::Io {
        context: context(),
        source: sql_io(error),
    }
}

fn write_failed(context: &str) -> impl FnOnce(io::Error) -> SlotStoreError + '_ {
    move |source| SlotStoreError::WriteFailed {
        context: context.into(),
        source,
    }
}

/// A step tests can fail, or abort the process at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Stage,
    Begin,
    Row,
    /// Before inserting the chunk with this sequence number.
    Chunk(u64),
    Commit,
    /// After a successful commit, before the outcome is returned.
    Committed,
    /// Before an acknowledgement's commit.
    AckCommit,
    SyncRoot,
    SyncParent,
}

#[cfg(test)]
type FaultHook = std::sync::Arc<dyn Fn(Step) -> io::Result<()> + Send + Sync>;

#[derive(Clone, Default)]
struct Faults {
    #[cfg(test)]
    hook: Option<FaultHook>,
}

impl Faults {
    fn at(&self, step: Step) -> io::Result<()> {
        #[cfg(test)]
        if let Some(hook) = &self.hook {
            return hook(step);
        }
        let _ = step;
        Ok(())
    }

    fn sync_dir(&self, step: Step, dir: &Path) -> Result<(), SlotStoreError> {
        self.at(step)
            .and_then(|()| File::open(dir)?.sync_all())
            .map_err(|source| SlotStoreError::Unconfirmed {
                context: format!("sync directory {}", dir.display()),
                source,
            })
    }
}

/// A body being streamed into a store's staging directory. Dropping it discards the bytes.
pub struct StagedBody {
    file: tempfile::NamedTempFile,
    hasher: Sha256,
    len: u64,
    faults: Faults,
}

impl StagedBody {
    /// Append the next part of the body. A failure leaves nothing published.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), SlotStoreError> {
        self.faults
            .at(Step::Stage)
            .and_then(|()| self.file.write_all(chunk))
            .map_err(write_failed("stage a body"))?;
        self.hasher.update(chunk);
        self.len += chunk.len() as u64;
        Ok(())
    }

    pub fn len(&self) -> u64 {
        self.len
    }
}

/// A committed body being read in bounded chunks under one read snapshot. The digest is checked
/// at the end, so a caller must not treat the bytes as the slot's value until
/// [`SlotReader::read`] returns `Ok(0)`.
pub struct SlotReader {
    conn: Connection,
    slot: SlotAddress,
    len: u64,
    digest: [u8; 32],
    seq: u64,
    chunk: Vec<u8>,
    at: usize,
    read: u64,
    hasher: Sha256,
}

impl SlotReader {
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Read the next bytes into `buf`. Returns `Ok(0)` only once every byte has been read and
    /// matched the committed length and digest.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, SlotStoreError> {
        let corrupt = SlotStoreError::CorruptObject { slot: self.slot };
        if self.at == self.chunk.len() {
            if self.read == self.len {
                let digest: [u8; 32] = std::mem::take(&mut self.hasher).finalize().into();
                let extra: Option<i64> = self
                    .conn
                    .query_row(
                        "SELECT seq FROM chunks WHERE slot = ?1 AND seq = ?2",
                        params![&self.slot.0[..], self.seq as i64],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql_error(|| format!("read {:?}", self.slot)))?;
                return if digest == self.digest && extra.is_none() {
                    Ok(0)
                } else {
                    Err(corrupt)
                };
            }
            let chunk: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT bytes FROM chunks WHERE slot = ?1 AND seq = ?2",
                    params![&self.slot.0[..], self.seq as i64],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error(|| format!("read {:?}", self.slot)))?;
            match chunk {
                Some(chunk) if !chunk.is_empty() => {
                    self.chunk = chunk;
                    self.at = 0;
                    self.seq += 1;
                }
                _ => return Err(corrupt),
            }
        }
        let available = &self.chunk[self.at..];
        let take = available
            .len()
            .min(buf.len())
            .min(usize::try_from(self.len - self.read).unwrap_or(usize::MAX));
        if take == 0 && !buf.is_empty() {
            return Err(corrupt);
        }
        buf[..take].copy_from_slice(&available[..take]);
        self.hasher.update(&buf[..take]);
        self.at += take;
        self.read += take as u64;
        if self.read == self.len && self.at != self.chunk.len() {
            return Err(corrupt);
        }
        Ok(take)
    }

    /// Start again from the first byte, in the same read view.
    fn rewind(&mut self) {
        self.seq = 0;
        self.chunk.clear();
        self.at = 0;
        self.read = 0;
        self.hasher = Sha256::new();
    }
}

/// An open slot store. It holds the root's exclusive lock until dropped and may be shared
/// between threads.
pub struct SlotStore {
    db: PathBuf,
    staging: PathBuf,
    incarnation: Incarnation,
    writer: Mutex<Connection>,
    unconfirmed: AtomicBool,
    faults: Faults,
    _lock: File,
}

struct StoreInspection {
    root: PathBuf,
    db: PathBuf,
    staging: PathBuf,
    incarnation: Incarnation,
    summary: Summary,
    lock: File,
}

impl SlotStore {
    /// Create a new store with a fresh random incarnation in an empty or absent directory.
    pub fn initialize(root: &Path) -> Result<Self, SlotStoreError> {
        Self::initialize_with(root, Faults::default())
    }

    /// Reopen an existing store. Never creates or resets one.
    pub fn open(root: &Path) -> Result<Self, SlotStoreError> {
        Self::open_inner(root, Faults::default(), None)
    }

    /// Reopen an existing store only if it is the expected incarnation, compared before any
    /// application write or cleanup.
    pub fn open_expecting(root: &Path, expected: &Incarnation) -> Result<Self, SlotStoreError> {
        Self::open_inner(root, Faults::default(), Some(*expected))
    }

    /// Inspect a stopped store without running startup cleanup or opening a writer.
    pub fn verify_stopped(root: &Path, expected: &Incarnation) -> Result<Summary, SlotStoreError> {
        Self::inspect(root, Some(*expected), true).map(|store| store.summary)
    }

    /// A new store whose commits fail, for callers' tests of unconfirmed writes.
    #[cfg(test)]
    pub(crate) fn initialize_with_failing_record_sync(root: &Path) -> Result<Self, SlotStoreError> {
        Self::initialize_with(root, fail_at(|step| step == Step::Commit))
    }

    /// A new store whose acknowledgement commits fail, leaving their outcome unknown.
    #[cfg(test)]
    pub(crate) fn initialize_with_failing_acks(root: &Path) -> Result<Self, SlotStoreError> {
        Self::initialize_with(root, fail_at(|step| step == Step::AckCommit))
    }

    /// A new store whose writes fail before committing.
    #[cfg(test)]
    pub(crate) fn initialize_with_failing_publish(root: &Path) -> Result<Self, SlotStoreError> {
        Self::initialize_with(root, fail_at(|step| step == Step::Row))
    }

    fn initialize_with(given: &Path, faults: Faults) -> Result<Self, SlotStoreError> {
        let root = resolve_new_root(given)?;
        let parent = parent_of(&root)?;
        match create_private_dir(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(SlotStoreError::Io {
                    context: format!("create {}", root.display()),
                    source: error,
                });
            }
        }
        if fs::canonicalize(&root).map_err(io_error(|| format!("inspect {}", root.display())))?
            != root
        {
            return Err(SlotStoreError::UnsafeLayout {
                root: given.into(),
                detail: "the root changed during initialization".into(),
            });
        }
        if fs::read_dir(&root)
            .map_err(io_error(|| format!("read {}", root.display())))?
            .next()
            .is_some()
        {
            return Err(SlotStoreError::NotEmpty { root: given.into() });
        }
        let lock = lock(&root, given)?;
        create_private_dir(&root.join(STAGING_DIR))
            .map_err(io_error(|| format!("create staging in {}", root.display())))?;

        let mut incarnation = [0; 32];
        getrandom::fill(&mut incarnation).map_err(|error| SlotStoreError::Io {
            context: "generate store incarnation".into(),
            source: io::Error::other(error.to_string()),
        })?;
        let db = root.join(DB_FILE);
        let context = || format!("initialize {}", db.display());
        let mut conn = Connection::open_with_flags(
            &db,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sql_error(context))?;
        configure(&conn).map_err(sql_error(context))?;
        // The format and incarnation commit together with the schema, so their presence means
        // initialization completed.
        let tx = conn.transaction().map_err(sql_error(context))?;
        tx.execute_batch(SCHEMA).map_err(sql_error(context))?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)
            .and_then(|()| tx.pragma_update(None, "user_version", SCHEMA_VERSION))
            .map_err(sql_error(context))?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('format', ?1), ('incarnation', ?2)",
            params![FORMAT.as_bytes(), &incarnation[..]],
        )
        .map_err(sql_error(context))?;
        tx.commit().map_err(|error| SlotStoreError::Unconfirmed {
            context: context(),
            source: sql_io(error),
        })?;
        drop(conn);
        faults.sync_dir(Step::SyncRoot, &root)?;
        faults.sync_dir(Step::SyncParent, parent)?;
        drop(lock);
        Self::open_inner(&root, faults, Some(Incarnation(incarnation)))
    }

    fn open_inner(
        given: &Path,
        faults: Faults,
        expected: Option<Incarnation>,
    ) -> Result<Self, SlotStoreError> {
        let StoreInspection {
            root,
            db,
            staging,
            incarnation,
            lock,
            ..
        } = Self::inspect(given, expected, false)?;
        let parent = parent_of(&root)?;

        // Application writes start here: discard staged bodies, then serve.
        for staged in
            fs::read_dir(&staging).map_err(io_error(|| format!("read {}", staging.display())))?
        {
            let staged = staged.map_err(io_error(|| format!("read {}", staging.display())))?;
            let is_staged = staged
                .file_name()
                .to_string_lossy()
                .starts_with(STAGE_PREFIX)
                && staged.file_type().is_ok_and(|kind| kind.is_file());
            if is_staged {
                fs::remove_file(staged.path())
                    .map_err(io_error(|| format!("discard {}", staged.path().display())))?;
            }
        }
        let writer = Connection::open_with_flags(
            &db,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sql_error(|| format!("open {}", db.display())))?;
        configure(&writer).map_err(sql_error(|| format!("configure {}", db.display())))?;
        faults.sync_dir(Step::SyncRoot, &root)?;
        faults.sync_dir(Step::SyncParent, parent)?;
        Ok(Self {
            db,
            staging,
            incarnation,
            writer: Mutex::new(writer),
            unconfirmed: AtomicBool::new(false),
            faults,
            _lock: lock,
        })
    }

    fn inspect(
        given: &Path,
        expected: Option<Incarnation>,
        full: bool,
    ) -> Result<StoreInspection, SlotStoreError> {
        let root = match fs::canonicalize(given) {
            Ok(root) => root,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(SlotStoreError::Missing { root: given.into() });
            }
            Err(error) => {
                return Err(SlotStoreError::Io {
                    context: format!("resolve {}", given.display()),
                    source: error,
                });
            }
        };
        parent_of(&root)?;
        let damaged = |detail: String| SlotStoreError::Damaged {
            root: given.into(),
            detail,
        };
        let unsafe_layout = |detail: String| SlotStoreError::UnsafeLayout {
            root: given.into(),
            detail,
        };
        let db = root.join(DB_FILE);
        match fs::symlink_metadata(&db) {
            Ok(meta) if meta.file_type().is_file() && meta.nlink() == 1 => {}
            Ok(_) => {
                return Err(unsafe_layout(format!(
                    "{} is not a single-link regular file",
                    db.display()
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(SlotStoreError::Incomplete {
                    root: given.into(),
                    detail: "the database is missing".into(),
                });
            }
            Err(error) => {
                return Err(SlotStoreError::Io {
                    context: format!("inspect {}", db.display()),
                    source: error,
                });
            }
        }
        let staging = root.join(STAGING_DIR);
        match fs::symlink_metadata(&staging) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => {
                return Err(unsafe_layout(format!(
                    "{} is not a directory",
                    staging.display()
                )));
            }
            Err(_) => return Err(damaged(format!("{} is missing", staging.display()))),
        }
        let lock = lock(&root, given)?;

        // Read the identity without writing or checkpointing anything.
        let mode = if full {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        let conn = Connection::open_with_flags(&db, mode | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .map_err(|error| damaged(format!("cannot open the database: {error}")))?;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
            .and_then(|_| conn.pragma_update(None, "query_only", true))
            .and_then(|()| conn.pragma_update(None, "trusted_schema", false))
            .map_err(sql_error(|| format!("open {}", db.display())))?;
        let fault = |fault: Fault| match fault {
            Fault::Incomplete(detail) => SlotStoreError::Incomplete {
                root: given.into(),
                detail,
            },
            Fault::Damaged(detail) => damaged(detail),
            Fault::Store(error) => error,
        };
        let incarnation = identity(&conn).map_err(fault)?;
        if expected.is_some_and(|expected| expected != incarnation) {
            return Err(SlotStoreError::WrongIncarnation);
        }
        // Verify structure, schema and every body.
        let summary = verify_contents(&conn, &db, full).map_err(fault)?;
        Ok(StoreInspection {
            root,
            db,
            staging,
            incarnation,
            summary,
            lock,
        })
    }

    pub fn incarnation(&self) -> Incarnation {
        self.incarnation
    }

    /// Verify the whole store read-only, with SQLite's full `integrity_check`, its exact schema,
    /// every link and every body. Open already ran the same checks with `quick_check`.
    #[cfg(test)]
    pub fn verify(&self) -> Result<Summary, SlotStoreError> {
        if self.unconfirmed.load(Ordering::SeqCst) {
            return Err(SlotStoreError::NeedsReopen);
        }
        let conn = read_view(&self.db, || format!("verify {}", self.db.display()))?;
        verify_contents(&conn, &self.db, true).map_err(|fault| self.fault(fault))
    }

    fn fault(&self, fault: Fault) -> SlotStoreError {
        let root = self.db.parent().unwrap_or(&self.db).to_path_buf();
        match fault {
            Fault::Incomplete(detail) => SlotStoreError::Incomplete { root, detail },
            Fault::Damaged(detail) => SlotStoreError::Damaged { root, detail },
            Fault::Store(error) => error,
        }
    }

    /// Write one consistent, self-contained copy of the committed database to `dest`, which must
    /// not exist, then verify that copy independently and return what it holds.
    ///
    /// The copy is SQLite's own `VACUUM INTO` of one read snapshot, so it includes every commit
    /// still in the write-ahead log; copying `slots.db` alone would not. The copy is switched to
    /// rollback journaling, so it is a single file with no `-wal` or `-shm` companion, and is
    /// synced before it is verified. Verification reopens the file and runs the full integrity,
    /// schema, link and body checks, and requires this store's incarnation.
    pub fn snapshot_to(&self, dest: &Path) -> Result<Summary, SlotStoreError> {
        if self.unconfirmed.load(Ordering::SeqCst) {
            return Err(SlotStoreError::NeedsReopen);
        }
        let context = || format!("snapshot to {}", dest.display());
        if dest.symlink_metadata().is_ok() {
            return Err(SlotStoreError::Io {
                context: context(),
                source: io::Error::from(io::ErrorKind::AlreadyExists),
            });
        }
        let target = dest.to_str().ok_or_else(|| SlotStoreError::Io {
            context: context(),
            source: io::Error::other("the snapshot path is not valid UTF-8"),
        })?;
        {
            let conn = Connection::open_with_flags(
                &self.db,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(sql_error(context))?;
            conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
                .and_then(|_| conn.pragma_update(None, "trusted_schema", false))
                .and_then(|()| conn.execute("VACUUM INTO ?1", [target]).map(drop))
                .map_err(sql_error(context))?;
        }
        {
            let copy = Connection::open_with_flags(
                dest,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(sql_error(context))?;
            let mode: String = copy
                .pragma_update_and_check(None, "journal_mode", "delete", |row| row.get(0))
                .map_err(sql_error(context))?;
            if !mode.eq_ignore_ascii_case("delete") {
                return Err(SlotStoreError::Io {
                    context: context(),
                    source: io::Error::other(format!("the copy kept journal mode {mode}")),
                });
            }
        }
        File::open(dest)
            .and_then(|file| file.sync_all())
            .map_err(io_error(context))?;
        if let Some(parent) = dest.parent() {
            File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(io_error(context))?;
        }
        let (incarnation, summary) = Self::verify_snapshot(dest)?;
        if incarnation != self.incarnation {
            return Err(SlotStoreError::Damaged {
                root: dest.into(),
                detail: "the copy names another incarnation".into(),
            });
        }
        Ok(summary)
    }

    /// Verify a single-file snapshot made by [`SlotStore::snapshot_to`], read-only: its format,
    /// incarnation, full integrity, exact schema, links and every body. It must be a single-link
    /// regular file in rollback journal mode with no write-ahead log beside it.
    pub fn verify_snapshot(path: &Path) -> Result<(Incarnation, Summary), SlotStoreError> {
        let damaged = |detail: String| SlotStoreError::Damaged {
            root: path.into(),
            detail,
        };
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_file() && meta.nlink() == 1 => {}
            Ok(_) => return Err(damaged("not a single-link regular file".into())),
            Err(error) => {
                return Err(SlotStoreError::Io {
                    context: format!("inspect {}", path.display()),
                    source: error,
                });
            }
        }
        let mut wal = path.as_os_str().to_owned();
        wal.push("-wal");
        if Path::new(&wal).symlink_metadata().is_ok() {
            return Err(damaged(
                "a write-ahead log sits beside the snapshot; it is not self-contained".into(),
            ));
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| damaged(format!("cannot open the snapshot: {error}")))?;
        conn.pragma_update(None, "trusted_schema", false)
            .map_err(sql_error(|| format!("open {}", path.display())))?;
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|error| damaged(format!("cannot read the journal mode: {error}")))?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(damaged(format!("the snapshot is in journal mode {mode}")));
        }
        let fault = |fault: Fault| match fault {
            Fault::Incomplete(detail) | Fault::Damaged(detail) => damaged(detail),
            Fault::Store(error) => error,
        };
        let incarnation = identity(&conn).map_err(fault)?;
        let summary = verify_contents(&conn, path, true).map_err(fault)?;
        Ok((incarnation, summary))
    }

    /// Move a private staged snapshot into an empty store on the same filesystem.
    /// Verify the snapshot before creating the store and again when opening it.
    pub fn install_staged(
        given: &Path,
        snapshot: &Path,
        expected: &Incarnation,
    ) -> Result<Self, SlotStoreError> {
        let (incarnation, _) = Self::verify_snapshot(snapshot)?;
        if incarnation != *expected {
            return Err(SlotStoreError::WrongIncarnation);
        }
        let root = resolve_new_root(given)?;
        let parent = parent_of(&root)?;
        match create_private_dir(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(SlotStoreError::Io {
                    context: format!("create {}", root.display()),
                    source: error,
                });
            }
        }
        if fs::canonicalize(&root).map_err(io_error(|| format!("inspect {}", root.display())))?
            != root
        {
            return Err(SlotStoreError::UnsafeLayout {
                root: given.into(),
                detail: "the root changed during installation".into(),
            });
        }
        if fs::read_dir(&root)
            .map_err(io_error(|| format!("read {}", root.display())))?
            .next()
            .is_some()
        {
            return Err(SlotStoreError::NotEmpty { root: given.into() });
        }
        let lock = lock(&root, given)?;
        create_private_dir(&root.join(STAGING_DIR))
            .map_err(io_error(|| format!("create staging in {}", root.display())))?;
        let context = || format!("install {}", snapshot.display());
        File::open(snapshot)
            .and_then(|file| file.sync_all())
            .map_err(io_error(context))?;
        fs::rename(snapshot, root.join(DB_FILE)).map_err(io_error(context))?;
        let faults = Faults::default();
        faults.sync_dir(Step::SyncRoot, &root)?;
        faults.sync_dir(Step::SyncParent, parent)?;
        drop(lock);
        Self::open_inner(&root, faults, Some(*expected))
    }

    /// Start streaming a body into staging.
    pub fn stage(&self) -> Result<StagedBody, SlotStoreError> {
        let file = tempfile::Builder::new()
            .prefix(STAGE_PREFIX)
            .tempfile_in(&self.staging)
            .map_err(write_failed("stage a body"))?;
        Ok(StagedBody {
            file,
            hasher: Sha256::new(),
            len: 0,
            faults: self.faults.clone(),
        })
    }

    /// Commit a staged body to `slot` unless the slot is already occupied. When `claimed` is
    /// given, the staged bytes must hash to it.
    pub fn commit(
        &self,
        incarnation: &Incarnation,
        slot: &SlotAddress,
        body: StagedBody,
        claimed: Option<&[u8; 32]>,
    ) -> Result<WriteOutcome, SlotStoreError> {
        self.commit_object(incarnation, slot, body, claimed, None)
    }

    /// Append a staged body to `queue` as the item named by its digest. Items are immutable and
    /// distinct items coexist; an exact retry is the same item.
    pub fn append(
        &self,
        incarnation: &Incarnation,
        queue: &[u8; 32],
        body: StagedBody,
        claimed: &[u8; 32],
    ) -> Result<WriteOutcome, SlotStoreError> {
        let object = item_object(queue, claimed);
        self.commit_object(
            incarnation,
            &object,
            body,
            Some(claimed),
            Some((queue, claimed)),
        )
    }

    /// The first item of `queue` after sequence number `after`, or `None`.
    ///
    /// The item's row, acknowledgement and whole body are read in one read view, and the body is
    /// verified against the item's identity before this returns. An item whose order and
    /// identity are intact but whose body is definitively damaged is returned as
    /// [`QueueBody::Damaged`], so a reader can move past it. If even its identity cannot be
    /// trusted, or storage fails, this is an error and nothing is established.
    pub fn queue_next(
        &self,
        incarnation: &Incarnation,
        queue: &[u8; 32],
        after: u64,
    ) -> Result<Option<QueueEntry>, SlotStoreError> {
        self.check(incarnation)?;
        let context = || format!("read queue {}", crate::slot_wire::hex(queue));
        let conn = read_view(&self.db, context)?;
        let row: Option<(i64, Vec<u8>, Vec<u8>, bool)> = conn
            .query_row(
                "SELECT seq, item, object, EXISTS (
                     SELECT 1 FROM queue_acks a WHERE a.queue = q.queue AND a.item = q.item
                 ) FROM queue_items q WHERE queue = ?1 AND seq > ?2 ORDER BY seq LIMIT 1",
                params![&queue[..], i64::try_from(after).unwrap_or(i64::MAX)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sql_error(context))?;
        let Some((seq, item, object, acked)) = row else {
            if self.unconfirmed.load(Ordering::SeqCst) {
                return Err(SlotStoreError::NeedsReopen);
            }
            return Ok(None);
        };
        let object = SlotAddress(object.try_into().map_err(|_| SlotStoreError::Io {
            context: context(),
            source: io::Error::other("malformed queue object"),
        })?);
        // Without a well-formed identity and order there is nothing a reader could move past.
        let item: [u8; 32] = item
            .try_into()
            .map_err(|_| SlotStoreError::CorruptObject { slot: object })?;
        let seq = u64::try_from(seq).map_err(|_| SlotStoreError::CorruptObject { slot: object })?;
        // A mismatched link leaves the item identity uncertain. Do not allow a cursor advance
        // or acknowledgement based on it.
        if object != item_object(queue, &item) {
            return Err(SlotStoreError::CorruptObject { slot: object });
        }
        let body = match verified_item(conn, &item, object) {
            Ok(reader) => QueueBody::Intact(reader),
            Err(SlotStoreError::CorruptObject { .. }) => QueueBody::Damaged,
            Err(error) => return Err(error),
        };
        Ok(Some(QueueEntry {
            seq,
            item,
            acked,
            body,
        }))
    }

    /// Record the terminal acknowledgement of `item` in `queue`: `Some(Created)` when recorded
    /// now, `Some(ExactRetry)` when already recorded, `None` when there is no such item.
    pub fn ack(
        &self,
        incarnation: &Incarnation,
        queue: &[u8; 32],
        item: &[u8; 32],
    ) -> Result<Option<WriteOutcome>, SlotStoreError> {
        self.check(incarnation)?;
        let mut conn = self
            .writer
            .lock()
            .map_err(|_| SlotStoreError::NeedsReopen)?;
        if self.unconfirmed.load(Ordering::SeqCst) {
            return Err(SlotStoreError::NeedsReopen);
        }
        let context = || format!("acknowledge an item of {}", crate::slot_wire::hex(queue));
        let state: Option<(bool, [u8; 32])> = conn
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM queue_acks a WHERE a.queue = q.queue AND a.item = q.item),
                 object
                 FROM queue_items q WHERE queue = ?1 AND item = ?2",
                params![&queue[..], &item[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql_error(context))?;
        let Some((acked, object)) = state else {
            return Ok(None);
        };
        let slot = SlotAddress(object);
        if slot != item_object(queue, item) {
            return Err(SlotStoreError::CorruptObject { slot });
        }
        if acked {
            return Ok(Some(WriteOutcome::ExactRetry));
        }
        let failed = |error: rusqlite::Error| SlotStoreError::WriteFailed {
            context: context(),
            source: sql_io(error),
        };
        self.faults
            .at(Step::Begin)
            .map_err(|source| SlotStoreError::WriteFailed {
                context: context(),
                source,
            })?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(failed)?;
        tx.execute(
            "INSERT INTO queue_acks (queue, item) VALUES (?1, ?2)",
            params![&queue[..], &item[..]],
        )
        .map_err(failed)?;
        if let Err(error) = self
            .faults
            .at(Step::AckCommit)
            .map_err(sql_io_rev)
            .and_then(|()| tx.commit())
        {
            self.unconfirmed.store(true, Ordering::SeqCst);
            return Err(SlotStoreError::Unconfirmed {
                context: context(),
                source: sql_io(error),
            });
        }
        Ok(Some(WriteOutcome::Created))
    }

    fn commit_object(
        &self,
        incarnation: &Incarnation,
        slot: &SlotAddress,
        body: StagedBody,
        claimed: Option<&[u8; 32]>,
        link: Option<(&[u8; 32], &[u8; 32])>,
    ) -> Result<WriteOutcome, SlotStoreError> {
        self.check(incarnation)?;
        if body.file.path().parent() != Some(self.staging.as_path()) {
            return Err(SlotStoreError::WriteFailed {
                context: "commit a body".into(),
                source: io::Error::other("the body was staged for another store"),
            });
        }
        let StagedBody {
            file, hasher, len, ..
        } = body;
        let digest: [u8; 32] = hasher.finalize().into();
        if claimed.is_some_and(|claimed| *claimed != digest) {
            return Err(SlotStoreError::BodyMismatch);
        }
        let mut conn = self
            .writer
            .lock()
            .map_err(|_| SlotStoreError::NeedsReopen)?;
        if self.unconfirmed.load(Ordering::SeqCst) {
            return Err(SlotStoreError::NeedsReopen);
        }
        let stored: Option<(i64, Vec<u8>)> = conn
            .query_row(
                "SELECT len, digest FROM slots WHERE slot = ?1",
                [&slot.0[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql_error(|| format!("look up {slot:?}")))?;
        if let Some((stored_len, stored_digest)) = stored {
            let same = stored_len == len as i64
                && stored_digest == digest
                && self.same_bytes(slot, file.as_file())?;
            return Ok(if same {
                WriteOutcome::ExactRetry
            } else {
                WriteOutcome::Occupied
            });
        }

        // One transaction: the slot row and every chunk. Any failure before the commit rolls it
        // back, so nothing is published.
        let failed = |error: rusqlite::Error| SlotStoreError::WriteFailed {
            context: format!("write {slot:?}"),
            source: sql_io(error),
        };
        let injected = |source: io::Error| SlotStoreError::WriteFailed {
            context: format!("write {slot:?}"),
            source,
        };
        self.faults.at(Step::Begin).map_err(injected)?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(failed)?;
        self.faults.at(Step::Row).map_err(injected)?;
        tx.execute(
            "INSERT INTO slots (slot, len, digest) VALUES (?1, ?2, ?3)",
            params![&slot.0[..], len as i64, &digest[..]],
        )
        .map_err(failed)?;
        let mut staged = file.reopen().map_err(injected)?;
        let mut buf = vec![0; CHUNK];
        let mut seq = 0u64;
        let mut remaining = len;
        let mut readback = Sha256::new();
        {
            let mut insert = tx
                .prepare("INSERT INTO chunks (slot, seq, bytes) VALUES (?1, ?2, ?3)")
                .map_err(failed)?;
            loop {
                let read = read_full(&mut staged, &mut buf).map_err(injected)?;
                if read == 0 {
                    break;
                }
                remaining = remaining
                    .checked_sub(read as u64)
                    .ok_or(SlotStoreError::BodyMismatch)?;
                readback.update(&buf[..read]);
                self.faults.at(Step::Chunk(seq)).map_err(injected)?;
                insert
                    .execute(params![&slot.0[..], seq as i64, &buf[..read]])
                    .map_err(failed)?;
                seq += 1;
            }
        }
        let verified: [u8; 32] = readback.finalize().into();
        if remaining != 0 || verified != digest {
            return Err(SlotStoreError::BodyMismatch);
        }
        if let Some((queue, item)) = link {
            tx.execute(
                "INSERT INTO queue_items (queue, item, object) VALUES (?1, ?2, ?3)",
                params![&queue[..], &item[..], &slot.0[..]],
            )
            .map_err(failed)?;
        }
        if let Err(source) = self.faults.at(Step::Commit) {
            // The transaction is dropped without committing, but this models a commit whose
            // outcome is unknown.
            self.unconfirmed.store(true, Ordering::SeqCst);
            return Err(SlotStoreError::Unconfirmed {
                context: format!("commit {slot:?}"),
                source,
            });
        }
        if let Err(error) = tx.commit() {
            self.unconfirmed.store(true, Ordering::SeqCst);
            return Err(SlotStoreError::Unconfirmed {
                context: format!("commit {slot:?}"),
                source: sql_io(error),
            });
        }
        if let Err(source) = self.faults.at(Step::Committed) {
            // Committed, but the acknowledgement was lost.
            self.unconfirmed.store(true, Ordering::SeqCst);
            return Err(SlotStoreError::Unconfirmed {
                context: format!("acknowledge {slot:?}"),
                source,
            });
        }
        Ok(WriteOutcome::Created)
    }

    /// Store `payload` in `slot` unless the slot is already occupied.
    pub fn put(
        &self,
        incarnation: &Incarnation,
        slot: &SlotAddress,
        payload: &[u8],
    ) -> Result<WriteOutcome, SlotStoreError> {
        self.check(incarnation)?;
        let mut body = self.stage()?;
        for chunk in payload.chunks(CHUNK) {
            body.write(chunk)?;
        }
        self.commit(incarnation, slot, body, None)
    }

    /// Open a committed body for streaming, or `None` if the slot is absent.
    pub fn read(
        &self,
        incarnation: &Incarnation,
        slot: &SlotAddress,
    ) -> Result<Option<SlotReader>, SlotStoreError> {
        self.check(incarnation)?;
        match reader_on(&self.db, *slot)? {
            Some(reader) => Ok(Some(reader)),
            None if self.unconfirmed.load(Ordering::SeqCst) => Err(SlotStoreError::NeedsReopen),
            None => Ok(None),
        }
    }

    /// Read a whole body. For local callers; the relay streams with [`SlotStore::read`].
    pub fn get(
        &self,
        incarnation: &Incarnation,
        slot: &SlotAddress,
    ) -> Result<ReadOutcome, SlotStoreError> {
        let Some(mut reader) = self.read(incarnation, slot)? else {
            return Ok(ReadOutcome::Absent);
        };
        let mut payload = Vec::new();
        let mut buf = vec![0; CHUNK];
        loop {
            match reader.read(&mut buf)? {
                0 => return Ok(ReadOutcome::Present(SlotPayload(payload.into()))),
                read => payload.extend_from_slice(&buf[..read]),
            }
        }
    }

    fn check(&self, incarnation: &Incarnation) -> Result<(), SlotStoreError> {
        if *incarnation == self.incarnation {
            Ok(())
        } else {
            Err(SlotStoreError::WrongIncarnation)
        }
    }

    /// Whether the staged bytes equal the stored body, verifying the stored body as it is read.
    fn same_bytes(&self, slot: &SlotAddress, staged: &File) -> Result<bool, SlotStoreError> {
        let mut reader =
            reader_on(&self.db, *slot)?.ok_or(SlotStoreError::CorruptObject { slot: *slot })?;
        let mut staged = staged
            .try_clone()
            .and_then(|mut file| {
                use std::io::Seek as _;
                file.seek(io::SeekFrom::Start(0))?;
                Ok(file)
            })
            .map_err(io_error(|| "read a staged body".into()))?;
        let (mut ours, mut theirs) = (vec![0; CHUNK], vec![0; CHUNK]);
        let mut same = true;
        loop {
            let read = reader.read(&mut theirs)?;
            if read == 0 {
                if staged
                    .read(&mut ours[..1])
                    .map_err(io_error(|| "read a staged body".into()))?
                    != 0
                {
                    return Err(SlotStoreError::BodyMismatch);
                }
                return Ok(same);
            }
            staged
                .read_exact(&mut ours[..read])
                .map_err(io_error(|| "read a staged body".into()))?;
            same &= ours[..read] == theirs[..read];
        }
    }
}

/// One queue item: its relay-assigned order, identity, acknowledgement and body.
pub struct QueueEntry {
    pub seq: u64,
    pub item: [u8; 32],
    pub acked: bool,
    pub body: QueueBody,
}

/// A queue item's body, as established in the read view its entry came from. One is built per
/// queue read and moved once, so the size difference between variants does not matter.
#[allow(clippy::large_enum_variant)]
pub enum QueueBody {
    /// Verified against the item's identity, and rewound to be read again in the same view.
    Intact(SlotReader),
    /// Definitively damaged body for a verified queue-to-object link.
    Damaged,
}

/// Open `item`'s body on `conn`'s read view and verify every byte against the item's identity,
/// leaving the reader rewound in that same view. Damage of any kind is `CorruptObject`.
fn verified_item(
    conn: Connection,
    item: &[u8; 32],
    object: SlotAddress,
) -> Result<SlotReader, SlotStoreError> {
    let corrupt = SlotStoreError::CorruptObject { slot: object };
    let mut reader = reader_in(conn, object)?.ok_or(corrupt)?;
    if reader.digest != *item {
        return Err(SlotStoreError::CorruptObject { slot: object });
    }
    let mut buf = vec![0; CHUNK];
    while reader.read(&mut buf)? != 0 {}
    reader.rewind();
    Ok(reader)
}

/// What a store's contents add up to, as verified.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Occupied slots, queue item objects included. Each is an occupied marker.
    pub objects: u64,
    pub queue_items: u64,
    pub queue_acks: u64,
    /// Total committed body bytes.
    pub body_bytes: u64,
}

/// Why a database failed verification.
enum Fault {
    Incomplete(String),
    Damaged(String),
    Store(SlotStoreError),
}

/// The store's format and incarnation, read without writing anything.
fn identity(conn: &Connection) -> Result<Incarnation, Fault> {
    let damaged = Fault::Damaged;
    let identity = (|| {
        let application: i64 = conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let tables: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table'",
            [],
            |row| row.get(0),
        )?;
        Ok::<_, rusqlite::Error>((application, version, tables))
    })()
    .map_err(|error| damaged(format!("not a readable slot store: {error}")))?;
    match identity {
        (0, 0, 0) => Err(Fault::Incomplete("initialization did not complete".into())),
        (APPLICATION_ID, SCHEMA_VERSION, _) => {
            let meta = |key: &str| {
                conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
            };
            if meta("format").ok().as_deref() != Some(FORMAT.as_bytes()) {
                return Err(damaged("unknown store format".into()));
            }
            meta("incarnation")
                .ok()
                .and_then(|bytes| Incarnation::from_slice(&bytes))
                .ok_or_else(|| damaged("the incarnation is missing or malformed".into()))
        }
        _ => Err(damaged("not a slot store of this format".into())),
    }
}

type SchemaRow = (String, String, String, Option<String>);

fn schema_rows(conn: &Connection) -> rusqlite::Result<Vec<SchemaRow>> {
    let mut statement = conn.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name, tbl_name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    rows.collect()
}

/// The database's schema must be exactly this format's: every table, index and trigger, with
/// its exact definition, and nothing else. A missing immutability trigger, a changed constraint,
/// or an extra view or trigger that could run on a write is damage, not a variant.
fn verify_schema(conn: &Connection) -> Result<(), Fault> {
    let expected = (|| {
        let reference = Connection::open_in_memory()?;
        reference.execute_batch(SCHEMA)?;
        schema_rows(&reference)
    })()
    .map_err(|error| Fault::Store(sql_error(|| "build the reference schema".into())(error)))?;
    let actual = schema_rows(conn)
        .map_err(|error| Fault::Damaged(format!("cannot read the schema: {error}")))?;
    if actual != expected {
        let differs = actual
            .iter()
            .filter(|row| !expected.contains(row))
            .chain(expected.iter().filter(|row| !actual.contains(row)))
            .map(|(kind, name, ..)| format!("{kind} {name}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(Fault::Damaged(format!(
            "the schema is not this format's ({differs})"
        )));
    }
    Ok(())
}

/// Verify a database's structure, exact schema, links and every body, read-only. `full` runs
/// SQLite's `integrity_check`, which also checks every index against its table, instead of
/// `quick_check`.
fn verify_contents(conn: &Connection, db: &Path, full: bool) -> Result<Summary, Fault> {
    let damaged = Fault::Damaged;
    let pragma = if full {
        "integrity_check"
    } else {
        "quick_check"
    };
    let check: String = conn
        .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
        .map_err(|error| damaged(format!("{pragma} failed: {error}")))?;
    if check != "ok" {
        return Err(damaged(format!("{pragma}: {check}")));
    }
    verify_schema(conn)?;
    let dangling: Option<String> = conn
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()
        .map_err(|error| damaged(format!("foreign_key_check failed: {error}")))?;
    if let Some(table) = dangling {
        return Err(damaged(format!("{table} names a missing row")));
    }
    let mut summary = Summary::default();
    {
        let invalid =
            |error: rusqlite::Error| damaged(format!("cannot check queue links: {error}"));
        let mut links = conn
            .prepare("SELECT queue, item, object FROM queue_items")
            .map_err(invalid)?;
        let mut rows = links.query([]).map_err(invalid)?;
        while let Some(row) = rows.next().map_err(invalid)? {
            let link = (|| {
                let queue: [u8; 32] = row.get(0)?;
                let item: [u8; 32] = row.get(1)?;
                let object: [u8; 32] = row.get(2)?;
                Ok::<_, rusqlite::Error>(item_object(&queue, &item).0 == object)
            })()
            .map_err(|error| damaged(format!("invalid queue link: {error}")))?;
            if !link {
                return Err(damaged("a queue item names the wrong object".into()));
            }
            summary.queue_items += 1;
        }
    }
    summary.queue_acks = conn
        .query_row("SELECT count(*) FROM queue_acks", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|error| damaged(format!("cannot count acknowledgements: {error}")))?
        as u64;
    let slots = (|| {
        let mut statement = conn.prepare("SELECT slot FROM slots")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.collect::<Result<Vec<_>, _>>()
    })()
    .map_err(|error| damaged(format!("cannot list slots: {error}")))?;
    let mut buf = vec![0; CHUNK];
    for slot in slots {
        let slot = SlotAddress(
            slot.try_into()
                .map_err(|_| damaged("a slot address is malformed".into()))?,
        );
        let body_damaged = || damaged(format!("the body for {slot:?} is damaged"));
        let mut reader = match reader_on(db, slot) {
            Ok(Some(reader)) => reader,
            Ok(None) => return Err(damaged(format!("{slot:?} vanished during verification"))),
            Err(SlotStoreError::CorruptObject { .. }) => return Err(body_damaged()),
            Err(error) => return Err(Fault::Store(error)),
        };
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(SlotStoreError::CorruptObject { .. }) => return Err(body_damaged()),
                Err(error) => return Err(Fault::Store(error)),
            }
        }
        summary.objects += 1;
        summary.body_bytes += reader.len();
    }
    Ok(summary)
}

/// Where a queue item's body is stored: an address no slot key can produce.
fn item_object(queue: &[u8; 32], item: &[u8; 32]) -> SlotAddress {
    let mut digest = Sha256::new();
    digest.update(ITEM_DOMAIN);
    digest.update(queue);
    digest.update(item);
    SlotAddress(digest.finalize().into())
}

fn sql_io_rev(error: io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

/// A query-only connection inside a read transaction: every query on it sees one snapshot.
fn read_view(db: &Path, context: impl Fn() -> String) -> Result<Connection, SlotStoreError> {
    let conn = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sql_error(&context))?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .and_then(|_| conn.pragma_update(None, "query_only", true))
        .and_then(|()| conn.pragma_update(None, "trusted_schema", false))
        .and_then(|()| conn.execute_batch("BEGIN DEFERRED"))
        .map_err(sql_error(&context))?;
    Ok(conn)
}

/// A reader for `slot` on its own query-only connection and read snapshot, or `None` if absent.
fn reader_on(db: &Path, slot: SlotAddress) -> Result<Option<SlotReader>, SlotStoreError> {
    reader_in(read_view(db, || format!("read {slot:?}"))?, slot)
}

/// A reader for `slot` continuing `conn`'s read view, or `None` if absent.
fn reader_in(conn: Connection, slot: SlotAddress) -> Result<Option<SlotReader>, SlotStoreError> {
    let context = || format!("read {slot:?}");
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT len, digest FROM slots WHERE slot = ?1",
            [&slot.0[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql_error(context))?;
    let Some((len, digest)) = row else {
        return Ok(None);
    };
    let corrupt = SlotStoreError::CorruptObject { slot };
    // A body whose rows do not add up to its length is refused before any byte is served.
    let stored: i64 = conn
        .query_row(
            "SELECT coalesce(sum(length(bytes)), 0) FROM chunks WHERE slot = ?1",
            [&slot.0[..]],
            |row| row.get(0),
        )
        .map_err(sql_error(context))?;
    if stored != len {
        return Err(corrupt);
    }
    Ok(Some(SlotReader {
        conn,
        slot,
        len: u64::try_from(len).map_err(|_| SlotStoreError::CorruptObject { slot })?,
        digest: digest.try_into().map_err(|_| corrupt)?,
        seq: 0,
        chunk: Vec::new(),
        at: 0,
        read: 0,
        hasher: Sha256::new(),
    }))
}

/// Durable, foreign-key-checked WAL settings for a writing connection.
fn configure(conn: &Connection) -> rusqlite::Result<()> {
    let mode: String =
        conn.pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "journal mode {mode}"
        )));
    }
    conn.pragma_update(None, "trusted_schema", false)?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "fullfsync", true)?;
    conn.pragma_update(None, "checkpoint_fullfsync", true)?;
    conn.pragma_update(None, "foreign_keys", true)
}

/// Fill `buf` from `file` unless the file ends first.
fn read_full(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    Ok(filled)
}

/// Rewrite a committed body behind the store's back, as damage would. Tests only.
#[cfg(test)]
pub(crate) fn tamper_body(root: &Path, slot: &SlotAddress, body: &[u8]) {
    let conn = Connection::open(root.join(DB_FILE)).unwrap();
    conn.execute_batch(
        "DROP TRIGGER IF EXISTS chunks_fixed_delete; DROP TRIGGER IF EXISTS chunks_fixed_update;",
    )
    .unwrap();
    conn.execute("DELETE FROM chunks WHERE slot = ?1", [&slot.0[..]])
        .unwrap();
    conn.execute(
        "INSERT INTO chunks (slot, seq, bytes) VALUES (?1, 0, ?2)",
        params![&slot.0[..], body],
    )
    .unwrap();
    restore_triggers(&conn);
}

/// Recreate, with their exact definitions, any of the format's triggers a test dropped to
/// tamper with rows, so the damage under test is the rows' and not the schema's. Tests only.
#[cfg(test)]
pub(crate) fn restore_triggers(conn: &Connection) {
    let reference = Connection::open_in_memory().unwrap();
    reference.execute_batch(SCHEMA).unwrap();
    for (kind, name, _, sql) in schema_rows(&reference).unwrap() {
        let present: bool = conn
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'trigger' AND name = ?1)",
                [&name],
                |row| row.get(0),
            )
            .unwrap();
        if kind == "trigger" && !present {
            conn.execute_batch(&sql.unwrap()).unwrap();
        }
    }
}

/// Rewrite a committed queue item's body behind the store's back, as damage would. Tests only.
#[cfg(test)]
pub(crate) fn tamper_item(root: &Path, queue: &[u8; 32], item: &[u8; 32], body: &[u8]) {
    tamper_body(root, &item_object(queue, item), body);
}

/// Every occupied slot address, read directly. Tests only.
#[cfg(test)]
pub(crate) fn stored_slots(root: &Path) -> Vec<[u8; 32]> {
    let conn = Connection::open(root.join(DB_FILE)).unwrap();
    let mut statement = conn
        .prepare("SELECT slot FROM slots ORDER BY slot")
        .unwrap();
    statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|slot| slot.unwrap().try_into().unwrap())
        .collect()
}

#[cfg(test)]
fn fail_at(fail: impl Fn(Step) -> bool + Send + Sync + 'static) -> Faults {
    Faults {
        hook: Some(std::sync::Arc::new(move |step| {
            if fail(step) {
                Err(io::Error::other(format!("injected failure at {step:?}")))
            } else {
                Ok(())
            }
        })),
    }
}

fn lock(root: &Path, given: &Path) -> Result<File, SlotStoreError> {
    let path = root.join(LOCK_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(io_error(|| format!("open {}", path.display())))?;
    if let Err(error) = file.try_lock_exclusive() {
        if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
            return Err(SlotStoreError::Locked { root: given.into() });
        }
        return Err(SlotStoreError::Io {
            context: format!("lock {}", path.display()),
            source: error,
        });
    }
    Ok(file)
}

/// The canonical path a new store will occupy, resolving symlinks in the root or its parent.
fn resolve_new_root(root: &Path) -> Result<PathBuf, SlotStoreError> {
    let Some(name) = root.file_name() else {
        return Err(SlotStoreError::UnsafeLayout {
            root: root.into(),
            detail: "name the store directory explicitly".into(),
        });
    };
    match fs::canonicalize(root) {
        Ok(root) => Ok(root),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = match root.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };
            let parent = fs::canonicalize(parent)
                .map_err(io_error(|| format!("resolve {}", parent.display())))?;
            Ok(parent.join(name))
        }
        Err(error) => Err(SlotStoreError::Io {
            context: format!("resolve {}", root.display()),
            source: error,
        }),
    }
}

/// The directory holding a canonical root's entry, which must be synced to make the root durable.
fn parent_of(root: &Path) -> Result<&Path, SlotStoreError> {
    root.parent().ok_or_else(|| SlotStoreError::UnsafeLayout {
        root: root.into(),
        detail: "the root has no parent directory".into(),
    })
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::symlink,
        process::Command,
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;

    const CRASH_ROOT: &str = "MR_SLOT_STORE_CRASH_ROOT";
    const CRASH_AT: &str = "MR_SLOT_STORE_CRASH_AT";

    fn slot(byte: u8) -> SlotAddress {
        SlotAddress::from_bytes([byte; 32])
    }

    fn present(bytes: &[u8]) -> ReadOutcome {
        ReadOutcome::Present(SlotPayload(bytes.into()))
    }

    fn fresh() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("slots-root");
        (dir, root)
    }

    /// Every file under `root` with its bytes, except the lock and SQLite's own WAL index and
    /// log, which the engine may create or keep when a database is read.
    fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = Vec::new();
        let mut dirs = vec![root.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.file_name().unwrap() != LOCK_FILE
                    && !path.to_string_lossy().ends_with("-wal")
                    && !path.to_string_lossy().ends_with("-shm")
                {
                    files.push((
                        path.strip_prefix(root).unwrap().into(),
                        fs::read(&path).unwrap(),
                    ));
                }
            }
        }
        files.sort();
        files
    }

    fn assert_damaged(root: &Path) {
        let result = SlotStore::open(root);
        assert!(
            matches!(result, Err(SlotStoreError::Damaged { .. })),
            "{:?}",
            result.err()
        );
    }

    /// A store at `root` holding slots 1..=n, each with payload [n; 5].
    fn filled(root: &Path, n: u8) -> Incarnation {
        let store = SlotStore::initialize(root).unwrap();
        let id = store.incarnation();
        for n in 1..=n {
            store.put(&id, &slot(n), &[n; 5]).unwrap();
        }
        id
    }

    fn large() -> Vec<u8> {
        (0..3 * CHUNK + 5).map(|n| (n * 31) as u8).collect()
    }

    fn tamper(root: &Path, slot: &SlotAddress, body: &[u8]) {
        tamper_body(root, slot, body);
    }

    /// Queue items and acknowledgements are committed with their bodies, survive a restart,
    /// refuse changes, and a dangling item refuses the store.
    #[test]
    fn checking_a_stopped_store_does_not_remove_staged_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let store = SlotStore::initialize(&root).unwrap();
        let incarnation = store.incarnation();
        drop(store);
        let staged = root.join(STAGING_DIR).join(format!("{STAGE_PREFIX}left"));
        fs::write(&staged, b"partial").unwrap();
        let db = root.join(DB_FILE);
        let before = fs::read(&db).unwrap();

        SlotStore::verify_stopped(&root, &incarnation).unwrap();

        assert_eq!(fs::read(staged).unwrap(), b"partial");
        assert_eq!(fs::read(db).unwrap(), before);
    }

    #[test]
    fn queue_items_are_immutable_and_survive_restart() {
        let (_dir, root) = fresh();
        let store = SlotStore::initialize(&root).unwrap();
        let id = store.incarnation();
        let queue = [5; 32];
        let append = |store: &SlotStore, body: &[u8]| {
            let mut staged = store.stage().unwrap();
            staged.write(body).unwrap();
            let digest: [u8; 32] = Sha256::digest(body).into();
            store.append(&id, &queue, staged, &digest).unwrap()
        };
        assert_eq!(append(&store, b"first"), WriteOutcome::Created);
        assert_eq!(append(&store, b"second"), WriteOutcome::Created);
        assert_eq!(append(&store, b"first"), WriteOutcome::ExactRetry);
        let first: [u8; 32] = Sha256::digest(b"first").into();
        assert_eq!(
            store.ack(&id, &queue, &first).unwrap(),
            Some(WriteOutcome::Created)
        );
        assert_eq!(store.ack(&id, &queue, &[0; 32]).unwrap(), None);
        drop(store);

        let store = SlotStore::open(&root).unwrap();
        let entry = store.queue_next(&id, &queue, 0).unwrap().unwrap();
        assert_eq!((entry.item, entry.acked), (first, true));
        let entry = store.queue_next(&id, &queue, entry.seq).unwrap().unwrap();
        assert!(!entry.acked);
        assert!(store.queue_next(&id, &queue, entry.seq).unwrap().is_none());
        assert!(store.queue_next(&id, &[6; 32], 0).unwrap().is_none());
        assert_eq!(
            store.ack(&id, &queue, &first).unwrap(),
            Some(WriteOutcome::ExactRetry)
        );
        drop(store);

        let conn = Connection::open(root.join(DB_FILE)).unwrap();
        assert!(conn.execute("DELETE FROM queue_acks", []).is_err());
        assert!(conn.execute("UPDATE queue_items SET seq = 9", []).is_err());
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF; DROP TRIGGER slots_fixed_delete; DROP TRIGGER chunks_fixed_delete;",
        )
        .unwrap();
        let object = item_object(&queue, &first);
        conn.execute("DELETE FROM chunks WHERE slot = ?1", [&object.0[..]])
            .unwrap();
        conn.execute("DELETE FROM slots WHERE slot = ?1", [&object.0[..]])
            .unwrap();
        restore_triggers(&conn);
        drop(conn);
        assert_damaged(&root);
    }

    #[test]
    fn an_incorrect_queue_link_is_not_skippable_body_damage() {
        let (_dir, root) = fresh();
        let store = SlotStore::initialize(&root).unwrap();
        let id = store.incarnation();
        let queue = [5; 32];
        let item: [u8; 32] = Sha256::digest(b"request").into();
        let mut staged = store.stage().unwrap();
        staged.write(b"request").unwrap();
        store.append(&id, &queue, staged, &item).unwrap();
        let other = slot(1);
        store.put(&id, &other, b"unrelated").unwrap();

        let conn = Connection::open(root.join(DB_FILE)).unwrap();
        conn.execute_batch("DROP TRIGGER queue_items_fixed_update")
            .unwrap();
        conn.execute("UPDATE queue_items SET object = ?1", [&other.0[..]])
            .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER queue_items_fixed_update BEFORE UPDATE ON queue_items
             BEGIN SELECT RAISE(ABORT, 'immutable'); END;",
        )
        .unwrap();
        drop(conn);
        assert!(matches!(
            store.queue_next(&id, &queue, 0),
            Err(SlotStoreError::CorruptObject { slot }) if slot == other
        ));
        assert!(matches!(
            store.ack(&id, &queue, &item),
            Err(SlotStoreError::CorruptObject { slot }) if slot == other
        ));
        drop(store);
        assert_damaged(&root);
    }

    #[test]
    fn first_value_wins_across_restart() {
        let (_dir, root) = fresh();
        let store = SlotStore::initialize(&root).unwrap();
        let id = store.incarnation();
        assert_eq!(store.get(&id, &slot(1)).unwrap(), ReadOutcome::Absent);
        assert_eq!(
            store.put(&id, &slot(1), b"first").unwrap(),
            WriteOutcome::Created
        );
        assert_eq!(
            store.put(&id, &slot(1), b"first").unwrap(),
            WriteOutcome::ExactRetry
        );
        assert_eq!(
            store.put(&id, &slot(1), b"second").unwrap(),
            WriteOutcome::Occupied
        );
        assert_eq!(
            store.put(&id, &slot(2), b"").unwrap(),
            WriteOutcome::Created
        );
        drop(store);

        let store = SlotStore::open(&root).unwrap();
        assert_eq!(store.incarnation(), id);
        assert_eq!(store.get(&id, &slot(1)).unwrap(), present(b"first"));
        assert_eq!(store.get(&id, &slot(2)).unwrap(), present(b""));
        assert_eq!(store.get(&id, &slot(3)).unwrap(), ReadOutcome::Absent);
        assert_eq!(
            store.put(&id, &slot(1), b"second").unwrap(),
            WriteOutcome::Occupied
        );
        assert_eq!(
            store.put(&id, &slot(1), b"first").unwrap(),
            WriteOutcome::ExactRetry
        );
        // The database refuses to change committed rows, whatever the caller.
        let conn = Connection::open(root.join(DB_FILE)).unwrap();
        assert!(conn.execute("DELETE FROM slots", []).is_err());
        assert!(conn.execute("UPDATE chunks SET bytes = x'00'", []).is_err());
    }

    #[test]
    fn bodies_stream_in_bounded_chunks() {
        let (_dir, root) = fresh();
        let store = SlotStore::initialize(&root).unwrap();
        let id = store.incarnation();
        let payload = large();
        let mut body = store.stage().unwrap();
        for part in payload.chunks(1000) {
            body.write(part).unwrap();
        }
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        assert_eq!(
            store.commit(&id, &slot(1), body, Some(&digest)).unwrap(),
            WriteOutcome::Created
        );
        let conn = Connection::open(root.join(DB_FILE)).unwrap();
        let largest: i64 = conn
            .query_row("SELECT max(length(bytes)) FROM chunks", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            largest as usize, CHUNK,
            "rows are bounded chunks, not one blob"
        );

        let mut reader = store.read(&id, &slot(1)).unwrap().unwrap();
        assert_eq!(
            (reader.len(), reader.digest()),
            (payload.len() as u64, digest)
        );
        let (mut read, mut buf) = (Vec::new(), [0; 777]);
        loop {
            match reader.read(&mut buf).unwrap() {
                0 => break,
                n => read.extend_from_slice(&buf[..n]),
            }
        }
        assert_eq!(read, payload);
        assert!(store.read(&id, &slot(2)).unwrap().is_none());

        // Damage after open is found by the time the reader reaches the end.
        let mut damaged = payload.clone();
        damaged[2 * CHUNK] ^= 1;
        tamper(&root, &slot(1), &damaged);
        let mut reader = store.read(&id, &slot(1)).unwrap().unwrap();
        let result = loop {
            match reader.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(_) => {}
                Err(error) => break Err(error),
            }
        };
        assert!(matches!(result, Err(SlotStoreError::CorruptObject { .. })));
        assert!(matches!(
            store.put(&id, &slot(1), &payload),
            Err(SlotStoreError::CorruptObject { .. })
        ));
        assert_eq!(
            store.put(&id, &slot(1), b"other").unwrap(),
            WriteOutcome::Occupied
        );
        drop(store);
        assert_damaged(&root);
    }

    #[test]
    fn wrong_incarnation_touches_nothing() {
        let (_dir, root) = fresh();
        let store = SlotStore::initialize(&root).unwrap();
        let id = store.incarnation();
        let other = Incarnation::from_bytes([0; 32]);
        store.put(&id, &slot(1), b"kept").unwrap();
        assert!(matches!(
            store.put(&other, &slot(2), b"new"),
            Err(SlotStoreError::WrongIncarnation)
        ));
        assert!(matches!(
            store.get(&other, &slot(1)),
            Err(SlotStoreError::WrongIncarnation)
        ));
        let body = store.stage().unwrap();
        assert!(matches!(
            store.commit(&other, &slot(2), body, None),
            Err(SlotStoreError::WrongIncarnation)
        ));
        assert_eq!(store.get(&id, &slot(2)).unwrap(), ReadOutcome::Absent);
    }

    #[test]
    fn changed_staging_bytes_never_commit_or_confirm_a_retry() {
        let (_dir, root) = fresh();
        let store = SlotStore::initialize(&root).unwrap();
        let id = store.incarnation();
        let digest: [u8; 32] = Sha256::digest(b"original").into();

        for bytes in [&b"changed!"[..], b"short", b"original and more"] {
            let mut body = store.stage().unwrap();
            body.write(b"original").unwrap();
            fs::write(body.file.path(), bytes).unwrap();
            assert!(matches!(
                store.commit(&id, &slot(1), body, Some(&digest)),
                Err(SlotStoreError::BodyMismatch)
            ));
            assert_eq!(store.get(&id, &slot(1)).unwrap(), ReadOutcome::Absent);
        }

        assert_eq!(
            store.put(&id, &slot(1), b"original").unwrap(),
            WriteOutcome::Created
        );
        let mut body = store.stage().unwrap();
        body.write(b"original").unwrap();
        fs::write(body.file.path(), b"original and more").unwrap();
        assert!(matches!(
            store.commit(&id, &slot(1), body, Some(&digest)),
            Err(SlotStoreError::BodyMismatch)
        ));
        drop(store);

        let reopened = SlotStore::open_expecting(&root, &id).unwrap();
        assert_eq!(reopened.get(&id, &slot(1)).unwrap(), present(b"original"));
    }

    /// A foreign store is refused from its identity before any application write or cleanup.
    #[test]
    fn expected_incarnation_is_checked_before_writes() {
        let (_dir, root) = fresh();
        let id = filled(&root, 2);
        fs::write(
            root.join(STAGING_DIR).join(format!("{STAGE_PREFIX}left")),
            b"staged",
        )
        .unwrap();
        let before = snapshot(&root);
        assert!(matches!(
            SlotStore::open_expecting(&root, &Incarnation::from_bytes([0; 32])),
            Err(SlotStoreError::WrongIncarnation)
        ));
        assert_eq!(
            snapshot(&root),
            before,
            "a foreign store is left exactly as it was"
        );
        let store = SlotStore::open_expecting(&root, &id).unwrap();
        assert!(
            !root
                .join(STAGING_DIR)
                .join(format!("{STAGE_PREFIX}left"))
                .exists()
        );
        assert_eq!(store.get(&id, &slot(2)).unwrap(), present(&[2; 5]));
    }

    #[test]
    fn initialization_is_explicit_and_never_resets() {
        let (dir, root) = fresh();
        assert!(matches!(
            SlotStore::open(&root),
            Err(SlotStoreError::Missing { .. })
        ));
        assert!(!root.exists(), "open must not create a store");
        assert!(matches!(
            SlotStore::initialize(Path::new(".")),
            Err(SlotStoreError::UnsafeLayout { .. })
        ));
        let store = SlotStore::initialize(&root).unwrap();
        let id = store.incarnation();
        store.put(&id, &slot(1), b"value").unwrap();
        assert!(matches!(
            SlotStore::open(&root),
            Err(SlotStoreError::Locked { .. })
        ));
        assert!(matches!(
            SlotStore::initialize(&root),
            Err(SlotStoreError::NotEmpty { .. })
        ));
        drop(store);
        assert!(matches!(
            SlotStore::initialize(&root),
            Err(SlotStoreError::NotEmpty { .. })
        ));
        assert_eq!(SlotStore::open(&root).unwrap().incarnation(), id);
        let other = SlotStore::initialize(&dir.path().join("other")).unwrap();
        assert_ne!(other.incarnation(), id);

        // A directory that is not a store, and a SQLite file that is not this format.
        let unrelated = dir.path().join("unrelated");
        fs::create_dir(&unrelated).unwrap();
        fs::write(unrelated.join("data"), b"x").unwrap();
        assert!(matches!(
            SlotStore::initialize(&unrelated),
            Err(SlotStoreError::NotEmpty { .. })
        ));
        assert!(matches!(
            SlotStore::open(&unrelated),
            Err(SlotStoreError::Incomplete { .. })
        ));
        let foreign = dir.path().join("foreign");
        fs::create_dir_all(foreign.join(STAGING_DIR)).unwrap();
        Connection::open(foreign.join(DB_FILE))
            .unwrap()
            .execute_batch("CREATE TABLE notes (x); INSERT INTO notes VALUES (1);")
            .unwrap();
        assert_damaged(&foreign);
    }

    /// Initialization that stops before its single commit leaves nothing that opens or reuses.
    #[test]
    fn interrupted_initialization_is_not_resumed() {
        let (_dir, root) = fresh();
        fs::create_dir_all(root.join(STAGING_DIR)).unwrap();
        let conn = Connection::open(root.join(DB_FILE)).unwrap();
        conn.pragma_update(None, "journal_mode", "wal").unwrap();
        drop(conn);
        let before = snapshot(&root);
        assert!(matches!(
            SlotStore::open(&root),
            Err(SlotStoreError::Incomplete { .. })
        ));
        assert!(matches!(
            SlotStore::initialize(&root),
            Err(SlotStoreError::NotEmpty { .. })
        ));
        assert_eq!(snapshot(&root), before);
    }

    #[test]
    fn damaged_or_partial_databases_fail_closed() {
        let (_dir, root) = fresh();
        filled(&root, 3);
        let db = root.join(DB_FILE);
        let original = fs::read(&db).unwrap();
        assert!(original.len() > 4096 * 2);
        for damaged in [
            original[..original.len() / 2].to_vec(),
            original[..100].to_vec(),
            Vec::new(),
            {
                let mut bytes = original.clone();
                bytes[0] ^= 1;
                bytes
            },
        ] {
            fs::write(&db, &damaged).unwrap();
            let result = SlotStore::open(&root);
            assert!(
                matches!(
                    result,
                    Err(SlotStoreError::Damaged { .. } | SlotStoreError::Incomplete { .. })
                ),
                "{:?}",
                result.err()
            );
        }
        fs::write(&db, &original).unwrap();
        // A slot row whose body rows are gone is damage, never absence.
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("DROP TRIGGER chunks_fixed_delete;")
            .unwrap();
        conn.execute("DELETE FROM chunks WHERE slot = ?1", [&slot(2).0[..]])
            .unwrap();
        restore_triggers(&conn);
        drop(conn);
        assert_damaged(&root);
    }

    #[test]
    fn restore_keeps_the_incarnation_only_when_complete() {
        let (dir, root) = fresh();
        let id = filled(&root, 1);
        let older = dir.path().join("older-copy");
        copy_tree(&root, &older);
        let store = SlotStore::open(&root).unwrap();
        store.put(&id, &slot(2), &[2; 5]).unwrap();
        drop(store);
        let complete = dir.path().join("complete");
        copy_tree(&root, &complete);
        let opened = |target: &Path| {
            let store = SlotStore::open(target).unwrap();
            assert_eq!(store.incarnation(), id);
            (1..=2)
                .map(|n| store.get(&id, &slot(n)).unwrap() != ReadOutcome::Absent)
                .collect::<Vec<_>>()
        };
        assert_eq!(opened(&complete), [true, true]);
        // Inherent limitation: a coherent older copy cannot be told apart by its contents.
        assert_eq!(opened(&older), [true, false]);
    }

    /// A database whose schema differs from the format's in any table, index, trigger or view
    /// is refused before anything is served or written, and accepted again once exact.
    #[test]
    fn the_schema_must_be_exactly_this_formats() {
        let (_dir, root) = fresh();
        filled(&root, 2);
        let db = root.join(DB_FILE);
        let tampered: [(&str, &str); 4] = [
            // An occupied marker that could now be deleted.
            ("DROP TRIGGER slots_fixed_delete", ""),
            (
                "CREATE TRIGGER on_write AFTER INSERT ON slots BEGIN SELECT 1; END",
                "DROP TRIGGER on_write",
            ),
            (
                "CREATE VIEW extra AS SELECT slot FROM slots",
                "DROP VIEW extra",
            ),
            ("CREATE INDEX by_len ON slots (len)", "DROP INDEX by_len"),
        ];
        for (change, undo) in tampered {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(change).unwrap();
            drop(conn);
            match SlotStore::open(&root) {
                Err(SlotStoreError::Damaged { detail, .. }) => {
                    assert!(detail.contains("schema"), "{change}: {detail}")
                }
                other => panic!("{change}: {:?}", other.err()),
            }
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(undo).unwrap();
            restore_triggers(&conn);
            drop(conn);
            SlotStore::open(&root).unwrap();
        }
    }

    /// A snapshot is one verified file holding every commit, including those still only in the
    /// write-ahead log, and installs as the same incarnation with the same occupied markers,
    /// queue order and acknowledgements. Anything else is refused.
    #[test]
    fn snapshots_include_the_log_and_install_only_verified_and_exact() {
        let (dir, root) = fresh();
        let store = SlotStore::initialize(&root).unwrap();
        let id = store.incarnation();
        store.put(&id, &slot(1), &large()).unwrap();
        let queue = [5; 32];
        let mut items = Vec::new();
        for body in [&b"first"[..], b"second"] {
            let mut staged = store.stage().unwrap();
            staged.write(body).unwrap();
            let digest: [u8; 32] = Sha256::digest(body).into();
            store.append(&id, &queue, staged, &digest).unwrap();
            items.push(digest);
        }
        store.ack(&id, &queue, &items[0]).unwrap();
        // The store is still open, so these commits are in its write-ahead log.
        let wal = root.join(format!("{DB_FILE}-wal"));
        assert!(fs::metadata(&wal).unwrap().len() > 0);
        let main_only = dir.path().join("main-only.db");
        fs::copy(root.join(DB_FILE), &main_only).unwrap();
        assert!(
            !matches!(
                SlotStore::verify_snapshot(&main_only),
                Ok((_, summary)) if summary.objects == 3
            ),
            "copying the main file alone loses commits still in the log"
        );

        let out = dir.path().join("out");
        fs::create_dir(&out).unwrap();
        let file = out.join("slots.db");
        let summary = store.snapshot_to(&file).unwrap();
        assert_eq!(
            summary,
            Summary {
                objects: 3,
                queue_items: 2,
                queue_acks: 1,
                body_bytes: large().len() as u64 + 11,
            }
        );
        assert_eq!(store.verify().unwrap(), summary);
        assert!(store.snapshot_to(&file).is_err(), "never overwrites");
        assert!(!out.join("slots.db-wal").exists());
        assert_eq!(SlotStore::verify_snapshot(&file).unwrap(), (id, summary));
        drop(store);

        // Exact install: same incarnation, markers, order and acknowledgement.
        let restored = dir.path().join("restored");
        let other = Incarnation::from_bytes([9; 32]);
        assert!(matches!(
            SlotStore::install_staged(&restored, &file, &other),
            Err(SlotStoreError::WrongIncarnation)
        ));
        assert!(!restored.exists());
        let staged = out.join("staged.db");
        fs::copy(&file, &staged).unwrap();
        let installed = SlotStore::install_staged(&restored, &staged, &id).unwrap();
        assert!(!staged.exists());
        assert_eq!(installed.incarnation(), id);
        assert_eq!(
            installed.get(&id, &slot(1)).unwrap(),
            ReadOutcome::Present(SlotPayload(large().into()))
        );
        assert_eq!(
            installed.put(&id, &slot(1), b"other").unwrap(),
            WriteOutcome::Occupied
        );
        let first = installed.queue_next(&id, &queue, 0).unwrap().unwrap();
        assert_eq!((first.item, first.acked), (items[0], true));
        let second = installed
            .queue_next(&id, &queue, first.seq)
            .unwrap()
            .unwrap();
        assert_eq!((second.item, second.acked), (items[1], false));
        drop(installed);
        assert!(matches!(
            SlotStore::install_staged(&restored, &file, &id),
            Err(SlotStoreError::NotEmpty { .. })
        ));

        // A changed byte, a log beside the file, or a link is refused.
        let original = fs::read(&file).unwrap();
        let mut flipped = original.clone();
        let probe = &large()[1000..1064];
        let at = flipped
            .windows(probe.len())
            .position(|window| window == probe)
            .unwrap();
        flipped[at] ^= 0x55;
        fs::write(&file, &flipped).unwrap();
        assert!(SlotStore::verify_snapshot(&file).is_err());
        fs::write(&file, &original).unwrap();
        fs::write(out.join("slots.db-wal"), b"").unwrap();
        assert!(matches!(
            SlotStore::verify_snapshot(&file),
            Err(SlotStoreError::Damaged { .. })
        ));
        fs::remove_file(out.join("slots.db-wal")).unwrap();
        fs::hard_link(&file, out.join("alias.db")).unwrap();
        assert!(matches!(
            SlotStore::verify_snapshot(&file),
            Err(SlotStoreError::Damaged { .. })
        ));
        fs::remove_file(out.join("alias.db")).unwrap();
        SlotStore::verify_snapshot(&file).unwrap();
    }

    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to.join(STAGING_DIR)).unwrap();
        for (path, bytes) in snapshot(from) {
            fs::write(to.join(path), bytes).unwrap();
        }
    }

    /// Injected failures: before the commit nothing is published and the handle stays usable;
    /// at the commit the result is unconfirmed until reopening reads the committed state.
    #[test]
    fn failures_are_definite_before_the_commit_and_uncertain_at_it() {
        let (_dir, root) = fresh();
        let id = filled(&root, 1);
        let points: [fn(Step) -> bool; 5] = [
            |step| step == Step::Stage,
            |step| step == Step::Begin,
            |step| step == Step::Row,
            |step| step == Step::Chunk(0),
            |step| step == Step::Chunk(2),
        ];
        for fail in points {
            let store = SlotStore::open_inner(&root, fail_at(fail), None).unwrap();
            assert!(matches!(
                store.put(&id, &slot(2), &large()),
                Err(SlotStoreError::WriteFailed { .. })
            ));
            assert_eq!(store.get(&id, &slot(2)).unwrap(), ReadOutcome::Absent);
            assert_eq!(store.get(&id, &slot(1)).unwrap(), present(&[1; 5]));
            drop(store);
        }
        let mut body = SlotStore::open(&root).unwrap().stage().unwrap();
        body.write(b"actual").unwrap();
        drop(body);

        // The commit's outcome is unknown to the caller.
        for (fail, committed) in [(Step::Commit, false), (Step::Committed, true)] {
            let store =
                SlotStore::open_inner(&root, fail_at(move |step| step == fail), None).unwrap();
            let target = slot(if committed { 3 } else { 2 });
            assert!(matches!(
                store.put(&id, &target, &large()),
                Err(SlotStoreError::Unconfirmed { .. })
            ));
            // Never absent: unknown until reopened, or present once actually committed.
            match store.get(&id, &target) {
                Err(SlotStoreError::NeedsReopen) => assert!(!committed),
                Ok(found) => assert!(committed && found == present(&large())),
                Err(error) => panic!("unexpected {error:?}"),
            }
            assert!(matches!(
                store.put(&id, &slot(9), b"x"),
                Err(SlotStoreError::NeedsReopen)
            ));
            assert_eq!(store.get(&id, &slot(1)).unwrap(), present(&[1; 5]));
            drop(store);
            let store = SlotStore::open(&root).unwrap();
            if committed {
                assert_eq!(store.get(&id, &target).unwrap(), present(&large()));
                assert_eq!(
                    store.put(&id, &target, &large()).unwrap(),
                    WriteOutcome::ExactRetry
                );
            } else {
                assert_eq!(store.get(&id, &target).unwrap(), ReadOutcome::Absent);
            }
        }

        // A body that does not match its signed digest is refused before any transaction.
        let store = SlotStore::open(&root).unwrap();
        let mut body = store.stage().unwrap();
        body.write(b"actual").unwrap();
        let claimed: [u8; 32] = Sha256::digest(b"claimed").into();
        assert!(matches!(
            store.commit(&id, &slot(4), body, Some(&claimed)),
            Err(SlotStoreError::BodyMismatch)
        ));
        assert_eq!(store.get(&id, &slot(4)).unwrap(), ReadOutcome::Absent);
    }

    /// Abort the process at a step. Run only as a child of the crash test.
    #[test]
    fn crash_child() {
        let (Ok(root), Ok(at)) = (std::env::var(CRASH_ROOT), std::env::var(CRASH_AT)) else {
            return;
        };
        let faults = Faults {
            hook: Some(Arc::new(move |step| {
                if format!("{step:?}") == at {
                    std::process::abort();
                }
                Ok(())
            })),
        };
        let store = SlotStore::open_inner(Path::new(&root), faults, None).unwrap();
        let id = store.incarnation();
        let _ = store.put(&id, &slot(2), &large());
        std::process::exit(3);
    }

    /// Real process aborts: while staging, partway through the chunk inserts, just before the
    /// commit, and after the commit but before the outcome is returned.
    #[test]
    fn process_aborts_leave_only_committed_values() {
        for (at, committed) in [
            ("Stage", false),
            ("Chunk(1)", false),
            ("Commit", false),
            ("Committed", true),
        ] {
            let (_dir, root) = fresh();
            let id = filled(&root, 1);
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "slot_store::tests::crash_child",
                    "--exact",
                    "--test-threads=1",
                ])
                .env(CRASH_ROOT, &root)
                .env(CRASH_AT, at)
                .output()
                .unwrap();
            assert!(!child.status.success(), "child did not abort at {at}");
            assert_ne!(child.status.code(), Some(3), "{at} never fired");

            let store = SlotStore::open(&root).unwrap();
            assert_eq!(store.get(&id, &slot(1)).unwrap(), present(&[1; 5]), "{at}");
            if committed {
                assert_eq!(store.get(&id, &slot(2)).unwrap(), present(&large()), "{at}");
                assert_eq!(
                    store.put(&id, &slot(2), &large()).unwrap(),
                    WriteOutcome::ExactRetry
                );
            } else {
                assert_eq!(
                    store.get(&id, &slot(2)).unwrap(),
                    ReadOutcome::Absent,
                    "{at}"
                );
                assert_eq!(
                    store.put(&id, &slot(2), &large()).unwrap(),
                    WriteOutcome::Created
                );
            }
            assert_eq!(fs::read_dir(root.join(STAGING_DIR)).unwrap().count(), 0);
        }
    }

    #[test]
    fn aliases_are_refused_and_roots_canonicalized() {
        let (dir, root) = fresh();
        let id = filled(&root, 1);

        // A symlinked root reaches the same lock and is held off.
        let alias = dir.path().join("root-alias");
        symlink(&root, &alias).unwrap();
        let store = SlotStore::open(&root).unwrap();
        assert!(matches!(
            SlotStore::open(&alias),
            Err(SlotStoreError::Locked { .. })
        ));
        drop(store);
        assert_eq!(SlotStore::open(&alias).unwrap().incarnation(), id);

        // A database that is a link, or hard-linked into another root, or a linked staging dir.
        let linked = dir.path().join("linked-db");
        fs::create_dir_all(linked.join(STAGING_DIR)).unwrap();
        symlink(root.join(DB_FILE), linked.join(DB_FILE)).unwrap();
        assert!(matches!(
            SlotStore::open(&linked),
            Err(SlotStoreError::UnsafeLayout { .. })
        ));
        let hard = dir.path().join("hard-db");
        fs::create_dir_all(hard.join(STAGING_DIR)).unwrap();
        fs::hard_link(root.join(DB_FILE), hard.join(DB_FILE)).unwrap();
        for target in [&root, &hard] {
            assert!(matches!(
                SlotStore::open(target),
                Err(SlotStoreError::UnsafeLayout { .. })
            ));
        }
        fs::remove_file(hard.join(DB_FILE)).unwrap();
        let staged = dir.path().join("real-staging");
        fs::rename(root.join(STAGING_DIR), &staged).unwrap();
        symlink(&staged, root.join(STAGING_DIR)).unwrap();
        assert!(matches!(
            SlotStore::open(&root),
            Err(SlotStoreError::UnsafeLayout { .. })
        ));
        fs::remove_file(root.join(STAGING_DIR)).unwrap();
        fs::rename(&staged, root.join(STAGING_DIR)).unwrap();

        // Only regular staged files are discarded; links and other entries are left alone.
        let staging = root.join(STAGING_DIR);
        fs::write(staging.join(format!("{STAGE_PREFIX}crashed")), b"partial").unwrap();
        fs::write(staging.join("operator-note"), b"keep").unwrap();
        symlink(
            root.join(DB_FILE),
            staging.join(format!("{STAGE_PREFIX}link")),
        )
        .unwrap();
        let store = SlotStore::open(&root).unwrap();
        assert!(!staging.join(format!("{STAGE_PREFIX}crashed")).exists());
        assert!(staging.join("operator-note").exists());
        assert!(fs::symlink_metadata(staging.join(format!("{STAGE_PREFIX}link"))).is_ok());
        assert_eq!(store.get(&id, &slot(1)).unwrap(), present(&[1; 5]));

        assert_eq!(
            resolve_new_root(Path::new("relative-root")).unwrap(),
            fs::canonicalize(".").unwrap().join("relative-root")
        );
        for bad in [".", "..", "/", "a/.."] {
            assert!(resolve_new_root(Path::new(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn concurrent_writers_agree_on_one_value() {
        const WRITERS: usize = 16;
        let (_dir, root) = fresh();
        let store = Arc::new(SlotStore::initialize(&root).unwrap());
        let id = store.incarnation();
        let race = |payload: fn(usize) -> Vec<u8>| {
            let barrier = Arc::new(Barrier::new(WRITERS));
            let target = slot(payload(0)[0]);
            let handles: Vec<_> = (0..WRITERS)
                .map(|writer| {
                    let (store, barrier) = (store.clone(), barrier.clone());
                    thread::spawn(move || {
                        let value = payload(writer);
                        barrier.wait();
                        (value.clone(), store.put(&id, &target, &value).unwrap())
                    })
                })
                .collect();
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            (target, results)
        };
        let (target, results) = race(|writer| vec![7; CHUNK + writer]);
        let winners: Vec<_> = results
            .iter()
            .filter(|(_, outcome)| *outcome == WriteOutcome::Created)
            .collect();
        assert_eq!(winners.len(), 1);
        assert!(
            results
                .iter()
                .all(|(_, outcome)| *outcome != WriteOutcome::ExactRetry)
        );
        let winner = winners[0].0.clone();
        let (same, results) = race(|_| vec![9, 9]);
        assert_eq!(
            results
                .iter()
                .filter(|(_, outcome)| *outcome == WriteOutcome::Created)
                .count(),
            1
        );
        assert!(
            results
                .iter()
                .all(|(_, outcome)| *outcome != WriteOutcome::Occupied)
        );

        // Readers racing writers see each slot absent or holding its exact value.
        let barrier = Arc::new(Barrier::new(WRITERS * 2));
        let mut handles = Vec::new();
        for writer in 0..WRITERS {
            let target = slot(100 + writer as u8);
            let (store_w, barrier_w) = (store.clone(), barrier.clone());
            handles.push(thread::spawn(move || {
                barrier_w.wait();
                assert_eq!(
                    store_w.put(&id, &target, &[writer as u8]).unwrap(),
                    WriteOutcome::Created
                );
            }));
            let (store_r, barrier_r) = (store.clone(), barrier.clone());
            handles.push(thread::spawn(move || {
                barrier_r.wait();
                loop {
                    match store_r.get(&id, &target).unwrap() {
                        ReadOutcome::Absent => thread::yield_now(),
                        found => break assert_eq!(found, present(&[writer as u8])),
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        drop(Arc::into_inner(store).unwrap());
        let store = SlotStore::open(&root).unwrap();
        assert_eq!(store.get(&id, &target).unwrap(), present(&winner));
        assert_eq!(store.get(&id, &same).unwrap(), present(&[9, 9]));
        assert_eq!(fs::read_dir(root.join(STAGING_DIR)).unwrap().count(), 0);
    }
}
