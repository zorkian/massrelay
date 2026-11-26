//! Durable storage for the experimental private membership profile.
//!
//! Layout of one profile directory:
//!
//! - `membership.lock`: exclusive profile lock (`flock`/`LockFileEx` via fs2).
//!   Every membership, admission and recovery operation runs under it, in
//!   this process or another one. It is the single writer.
//! - `membership.db`: the application state row (versioned JSON). This file
//!   is never copied or replaced. It names the MLS file of the accepted
//!   epoch, the journal and its candidate file, invites, reservations, the
//!   reply outbox, halts and the clock high-water mark.
//! - `mls/*.db`: OpenMLS state written by `openmls_sqlite_storage`. The
//!   accepted epoch's file is never written once accepted. A candidate or a
//!   remote slot under validation is built in a fresh copy (`VACUUM INTO`).
//!   Promotion is one transaction on `membership.db` that switches the
//!   accepted file name after comparing the exact parent head and journal
//!   identity. Superseded MLS files are deleted after promotion.
//!
//! Because application state is never copied, nothing written to it while a
//! candidate is pending can be lost by promotion, and no reconciliation step
//! exists. Copies other than the journaled candidate only exist while the
//! profile lock is held, so recovery (also under the lock) may delete any
//! unreferenced MLS file without racing a live operation.
//!
//! Both databases use rollback-journal mode with `synchronous=FULL`, and new
//! files are synced and published before they are referenced. Unix syncs the
//! containing directory. Windows publishes a new name using a write-through
//! move. These barriers depend on the underlying filesystem and device.

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::{Serialize, de::DeserializeOwned};

use super::STATE_FORMAT;
use super::codec::{hex, random};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "storage: {}", self.0)
    }
}

macro_rules! st {
    ($e:expr, $ctx:expr) => {
        $e.map_err(|e| StoreError(format!("{}: {}", $ctx, e)))
    };
}

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;
    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }
    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub type Storage<'a> = SqliteStorageProvider<JsonCodec, &'a Connection>;

/// OpenMLS provider bound to one open transaction on one MLS file.
pub struct MlsProvider<'a> {
    crypto: RustCrypto,
    storage: Storage<'a>,
}

impl<'a> OpenMlsProvider for MlsProvider<'a> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = Storage<'a>;
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

pub fn open_conn(path: &Path) -> Result<Connection, StoreError> {
    let conn = st!(Connection::open(path), "open")?;
    st!(
        conn.pragma_update(None, "journal_mode", "DELETE"),
        "journal_mode"
    )?;
    st!(
        conn.pragma_update(None, "synchronous", "FULL"),
        "synchronous"
    )?;
    #[cfg(target_os = "macos")]
    st!(conn.pragma_update(None, "fullfsync", "ON"), "fullfsync")?;
    st!(
        conn.pragma_update(None, "secure_delete", "ON"),
        "secure_delete"
    )?;
    Ok(conn)
}

fn fsync_file(path: &Path) -> Result<(), StoreError> {
    // Windows FlushFileBuffers requires a handle with write access.
    st!(
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|f| f.sync_all()),
        "fsync file"
    )
}

fn fsync_dir(dir: &Path) -> Result<(), StoreError> {
    // Unix additionally syncs the containing directory. Windows syncs the
    // published name with a write-through move instead.
    #[cfg(unix)]
    {
        st!(File::open(dir).and_then(|f| f.sync_all()), "fsync dir")
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Publish a fully written database before it can be recorded in a profile.
fn publish_db(staged: &Path, destination: &Path) -> Result<(), StoreError> {
    fsync_file(staged)?;
    let parent = destination.parent().expect("database directory");
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

        let parent = st!(parent.canonicalize(), "resolve database directory")?;
        let wide_path = |path: &Path| {
            parent
                .join(path.file_name().expect("database filename"))
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>()
        };
        let src = wide_path(staged);
        let dst = wide_path(destination);
        // Both terminated paths remain live across the synchronous call.
        if unsafe { MoveFileExW(src.as_ptr(), dst.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
            return Err(StoreError(format!(
                "publish database: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        st!(fs::rename(staged, destination), "publish database")?;
        fsync_dir(parent)
    }
}

/// Exclusive profile lock. Dropping it releases the lock.
pub struct Guard {
    _file: File,
}

#[derive(Clone, Debug)]
pub struct Store {
    dir: PathBuf,
}

const STATE_DB: &str = "membership.db";

/// Whether `dir` holds an initialized profile state row.
pub fn initialized(dir: &Path) -> bool {
    dir.join(STATE_DB).exists()
}
const LOCK: &str = "membership.lock";
const MLS_DIR: &str = "mls";

impl Store {
    /// Initialize a fresh profile. Fails if one already exists here, so a
    /// used profile is never silently reset.
    pub fn create<S: Serialize>(dir: &Path, initial: &S) -> Result<(Self, Guard), StoreError> {
        st!(fs::create_dir_all(dir), "create profile dir")?;
        let store = Self {
            dir: dir.to_path_buf(),
        };
        let guard = store.lock()?;
        if store.state_path().exists() {
            return Err(StoreError("profile already initialized".into()));
        }
        st!(fs::create_dir_all(store.mls_dir()), "create mls dir")?;
        fsync_dir(dir)?;
        // Write to a temporary name first so a crash never leaves a partial
        // `membership.db` that a later `open` would accept.
        let tmp = dir.join(format!("{STATE_DB}.init-{}", hex(&random::<8>())));
        {
            let conn = open_conn(&tmp)?;
            st!(
                conn.execute_batch(
                    "CREATE TABLE membership_state (id INTEGER PRIMARY KEY CHECK (id = 1), \
                     format TEXT NOT NULL, json BLOB NOT NULL);"
                ),
                "schema"
            )?;
            let json = st!(serde_json::to_vec(initial), "encode state")?;
            st!(
                conn.execute(
                    "INSERT INTO membership_state (id, format, json) VALUES (1, ?1, ?2)",
                    rusqlite::params![STATE_FORMAT, json],
                ),
                "insert state"
            )?;
        }
        publish_db(&tmp, &store.state_path())?;
        Ok((store, guard))
    }

    /// Open an existing profile. Missing or unknown-format state fails.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let store = Self {
            dir: dir.to_path_buf(),
        };
        if !store.state_path().exists() {
            return Err(StoreError("no private membership profile here".into()));
        }
        Ok(store)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join(STATE_DB)
    }

    fn mls_dir(&self) -> PathBuf {
        self.dir.join(MLS_DIR)
    }

    pub fn mls_path(&self, name: &str) -> PathBuf {
        self.mls_dir().join(name)
    }

    pub fn lock(&self) -> Result<Guard, StoreError> {
        let f = st!(
            fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(self.dir.join(LOCK)),
            "open lock"
        )?;
        st!(f.lock_exclusive(), "lock")?;
        Ok(Guard { _file: f })
    }

    pub fn load<S: DeserializeOwned>(&self, _g: &Guard) -> Result<S, StoreError> {
        let conn = open_conn(&self.state_path())?;
        Self::read_state(&conn)
    }

    fn read_state<S: DeserializeOwned>(conn: &Connection) -> Result<S, StoreError> {
        let (format, json): (String, Vec<u8>) = st!(
            conn.query_row(
                "SELECT format, json FROM membership_state WHERE id = 1",
                [],
                |r| { Ok((r.get(0)?, r.get(1)?)) }
            ),
            "load state"
        )?;
        if format != STATE_FORMAT {
            return Err(StoreError(format!("unsupported state format {format:?}")));
        }
        st!(serde_json::from_slice(&json), "decode state")
    }

    /// Load, modify and save the state row in one IMMEDIATE transaction. An
    /// error from `f` leaves the stored state unchanged.
    pub fn update<S, R, E>(
        &self,
        _g: &Guard,
        f: impl FnOnce(&mut S) -> Result<R, E>,
    ) -> Result<R, E>
    where
        S: Serialize + DeserializeOwned,
        E: From<StoreError>,
    {
        let mut conn = open_conn(&self.state_path())?;
        let tx = st!(
            conn.transaction_with_behavior(TransactionBehavior::Immediate),
            "begin"
        )?;
        let mut state: S = Self::read_state(&tx)?;
        let out = f(&mut state)?;
        let json = st!(serde_json::to_vec(&state), "encode state")?;
        st!(
            tx.execute("UPDATE membership_state SET json = ?1 WHERE id = 1", [json]),
            "save state"
        )?;
        st!(tx.commit(), "commit state")?;
        Ok(out)
    }

    // ------------------------------------------------------- auxiliary rows

    /// Load a named auxiliary state row (for example pairing state) stored in
    /// `membership.db` beside the membership row, under the same profile
    /// lock. A missing row yields `None`; a row with another format fails.
    pub fn load_aux<S: DeserializeOwned>(
        &self,
        _g: &Guard,
        name: &str,
        format: &str,
    ) -> Result<Option<S>, StoreError> {
        let conn = open_conn(&self.state_path())?;
        st!(conn.execute_batch(AUX_SCHEMA), "aux schema")?;
        Self::read_aux(&conn, name, format)
    }

    fn read_aux<S: DeserializeOwned>(
        conn: &Connection,
        name: &str,
        format: &str,
    ) -> Result<Option<S>, StoreError> {
        let row: Option<(String, Vec<u8>)> = st!(
            conn.query_row(
                "SELECT format, json FROM aux_state WHERE name = ?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional(),
            "load aux state"
        )?;
        match row {
            None => Ok(None),
            Some((f, _)) if f != format => {
                Err(StoreError(format!("unsupported {name} format {f:?}")))
            }
            Some((_, json)) => Ok(Some(st!(serde_json::from_slice(&json), "decode aux")?)),
        }
    }

    /// Load (or default), modify and save a named auxiliary row in one
    /// IMMEDIATE transaction. An error from `f` leaves it unchanged.
    pub fn update_aux<S, R, E>(
        &self,
        _g: &Guard,
        name: &str,
        format: &str,
        f: impl FnOnce(&mut S) -> Result<R, E>,
    ) -> Result<R, E>
    where
        S: Serialize + DeserializeOwned + Default,
        E: From<StoreError>,
    {
        let mut conn = open_conn(&self.state_path())?;
        st!(conn.execute_batch(AUX_SCHEMA), "aux schema")?;
        let tx = st!(
            conn.transaction_with_behavior(TransactionBehavior::Immediate),
            "begin"
        )?;
        let mut state: S = Self::read_aux(&tx, name, format)?.unwrap_or_default();
        let out = f(&mut state)?;
        let json = st!(serde_json::to_vec(&state), "encode aux")?;
        st!(
            tx.execute(
                "INSERT OR REPLACE INTO aux_state (name, format, json) VALUES (?1, ?2, ?3)",
                rusqlite::params![name, format, json],
            ),
            "save aux"
        )?;
        st!(tx.commit(), "commit aux")?;
        Ok(out)
    }

    // ------------------------------------------------------------ MLS files

    fn fresh_name(prefix: &str) -> String {
        format!("{prefix}-{}.db", hex(&random::<12>()))
    }

    /// Create an empty MLS file with the OpenMLS schema.
    pub fn new_mls_file(&self, _g: &Guard, prefix: &str) -> Result<String, StoreError> {
        let name = Self::fresh_name(prefix);
        let destination = self.mls_path(&name);
        let path = destination.with_extension("db.pending");
        {
            let conn = open_conn(&path)?;
            let mut storage: SqliteStorageProvider<JsonCodec, Connection> =
                SqliteStorageProvider::new(conn);
            st!(storage.run_migrations(), "openmls migrations")?;
        }
        {
            let conn = open_conn(&path)?;
            st!(conn.execute_batch(CANDIDATE_SCHEMA), "candidate schema")?;
        }
        publish_db(&path, &destination)?;
        Ok(name)
    }

    /// Consistent copy of an MLS file into a fresh name.
    pub fn copy_mls(&self, _g: &Guard, src: &str, prefix: &str) -> Result<String, StoreError> {
        let name = Self::fresh_name(prefix);
        let destination = self.mls_path(&name);
        let path = destination.with_extension("db.pending");
        {
            let conn = open_conn(&self.mls_path(src))?;
            st!(
                conn.execute("VACUUM INTO ?1", [path.to_string_lossy().to_string()]),
                "copy mls file"
            )?;
        }
        {
            let conn = open_conn(&path)?;
            st!(
                conn.execute("DELETE FROM massrelay_candidate", []),
                "clear candidate marker"
            )?;
        }
        publish_db(&path, &destination)?;
        Ok(name)
    }

    pub fn delete_mls(&self, _g: &Guard, name: &str) -> Result<(), StoreError> {
        let path = self.mls_path(name);
        for p in [
            path.clone(),
            PathBuf::from(format!("{}-journal", path.display())),
        ] {
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(StoreError(format!("delete {}: {e}", p.display()))),
            }
        }
        fsync_dir(&self.mls_dir())
    }

    pub fn mls_exists(&self, name: &str) -> bool {
        self.mls_path(name).exists()
    }

    pub fn mls_files(&self, _g: &Guard) -> Result<Vec<String>, StoreError> {
        let mut v = vec![];
        for e in st!(fs::read_dir(self.mls_dir()), "list mls dir")? {
            let e = st!(e, "list mls dir")?;
            let n = e.file_name().to_string_lossy().to_string();
            if let Some(base) = n.strip_suffix("-journal") {
                if !v.contains(&base.to_string()) {
                    v.push(base.to_string());
                }
            } else if (n.ends_with(".db") || n.ends_with(".db.pending")) && !v.contains(&n) {
                v.push(n);
            }
        }
        v.sort();
        Ok(v)
    }

    /// Run `f` in one IMMEDIATE transaction on an MLS file. OpenMLS writes
    /// and the candidate marker commit together when `commit` is true and
    /// `f` succeeds; otherwise everything rolls back.
    pub fn with_mls<R, E>(
        &self,
        _g: &Guard,
        name: &str,
        commit: bool,
        f: impl FnOnce(&MlsProvider<'_>, &Connection) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        let path = self.mls_path(name);
        if !path.exists() {
            return Err(StoreError(format!("mls file {name} missing")).into());
        }
        let mut conn = open_conn(&path)?;
        let tx = st!(
            conn.transaction_with_behavior(TransactionBehavior::Immediate),
            "begin mls"
        )?;
        let out = {
            let provider = MlsProvider {
                crypto: RustCrypto::default(),
                storage: SqliteStorageProvider::new(&tx),
            };
            f(&provider, &tx)?
        };
        if commit {
            st!(tx.commit(), "commit mls")?;
        } else {
            st!(tx.rollback(), "rollback mls")?;
        }
        Ok(out)
    }

    pub fn candidate_marker(
        &self,
        _g: &Guard,
        name: &str,
    ) -> Result<Option<([u8; 16], bool)>, StoreError> {
        let conn = open_conn(&self.mls_path(name))?;
        read_marker(&conn)
    }
}

const AUX_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS aux_state \
    (name TEXT PRIMARY KEY, format TEXT NOT NULL, json BLOB NOT NULL);";

/// Marks a candidate file as holding the fully merged and verified successor
/// of exactly one journal (`journal_id`). Copies clear it.
const CANDIDATE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS massrelay_candidate \
    (id INTEGER PRIMARY KEY CHECK (id = 1), journal_id BLOB NOT NULL, prepared INTEGER NOT NULL);";

pub fn write_marker(
    conn: &Connection,
    journal_id: &[u8; 16],
    prepared: bool,
) -> Result<(), StoreError> {
    st!(
        conn.execute(
            "INSERT OR REPLACE INTO massrelay_candidate (id, journal_id, prepared) VALUES (1, ?1, ?2)",
            rusqlite::params![journal_id.to_vec(), prepared as i64],
        ),
        "write candidate marker"
    )?;
    Ok(())
}

pub fn read_marker(conn: &Connection) -> Result<Option<([u8; 16], bool)>, StoreError> {
    let row: Option<(Vec<u8>, i64)> = st!(
        conn.query_row(
            "SELECT journal_id, prepared FROM massrelay_candidate WHERE id = 1",
            [],
            |r| { Ok((r.get(0)?, r.get(1)?)) }
        )
        .optional(),
        "read candidate marker"
    )?;
    match row {
        None => Ok(None),
        Some((id, prepared)) => {
            let id: [u8; 16] = id
                .try_into()
                .map_err(|_| StoreError("marker id length".into()))?;
            Ok(Some((id, prepared != 0)))
        }
    }
}
