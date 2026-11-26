//! Test-only file-backed fake of the opaque relay mailbox. It survives
//! process aborts, so crash tests can share it across processes.
//!
//! Semantics follow `mailbox.rs`: one incarnation (read from disk on every
//! call, so every handle sees a replacement), immutable create-if-absent
//! slots (`link(2)` of a fully written temp file), exact retry, conflict,
//! purge with a retained occupied marker, write-proof verification, and a
//! reply box with the same create-if-absent rule. Writes are handed to a
//! transport thread and return at once. A per-handle gate can hang every
//! network step to model a stalled relay. It never learns group, member or
//! operation.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use super::codec::{Hash, hex, random, sha256};
use super::envelope::{SlotId, verify_object_write, verify_slot_write};
use super::mailbox::{
    AckOutcome, CreateOutcome, Mailbox, MailboxError, Pin, QueueAppend, QueueBody, QueueItem,
    ReadOutcome, SlotWrite, Started,
};
use crate::slot_wire::{
    AckHeader, INVITE_REPLY, INVITE_REQUEST, ReadHeader, verify_ack, verify_append, verify_read,
};

#[derive(Default, Debug)]
struct GateState {
    hung: bool,
    entered: usize,
    /// Steps after this many pass freely, then block while hung.
    free: usize,
    /// `shutdown` was called and is honoured (see `Gate::support_shutdown`).
    shut: bool,
    supports_shutdown: bool,
}

/// Blocks network steps while hung.
#[derive(Default, Debug)]
pub struct Gate {
    state: Mutex<GateState>,
    cv: Condvar,
}

impl Gate {
    pub fn hang(&self) {
        self.state.lock().unwrap().hung = true;
    }

    /// Let the next `n` steps pass, then hang every later one.
    pub fn hang_after(&self, n: usize) {
        let mut s = self.state.lock().unwrap();
        s.free = s.entered + n;
        s.hung = true;
    }

    /// Model a transport that implements `Mailbox::shutdown`: once shut,
    /// blocked and later steps fail at once as `Uncertain`.
    pub fn support_shutdown(&self) {
        self.state.lock().unwrap().supports_shutdown = true;
    }

    fn shutdown(&self) {
        let mut s = self.state.lock().unwrap();
        if s.supports_shutdown {
            s.shut = true;
        }
        self.cv.notify_all();
    }

    pub fn entered(&self) -> usize {
        self.state.lock().unwrap().entered
    }

    pub fn release(&self) {
        self.state.lock().unwrap().hung = false;
        self.cv.notify_all();
    }

    /// Wait until `n` network steps have reached the gate.
    pub fn wait_entered(&self, n: usize) {
        let mut s = self.state.lock().unwrap();
        while s.entered < n {
            s = self.cv.wait(s).unwrap();
        }
    }

    /// `false` once shut down (the step must fail as `Uncertain`).
    fn pass(&self) -> bool {
        let mut s = self.state.lock().unwrap();
        s.entered += 1;
        let me = s.entered;
        self.cv.notify_all();
        while s.hung && me > s.free && !s.shut {
            s = self.cv.wait(s).unwrap();
        }
        !s.shut
    }
}

#[derive(Clone, Debug)]
pub struct FsMailbox {
    dir: PathBuf,
    /// The relay identity this store answers as.
    pub relay_key: [u8; 32],
    pub incarnation: Vec<u8>,
    /// When set, every call reports a transport failure (in this handle).
    pub offline: Arc<AtomicBool>,
    pub gate: Arc<Gate>,
    /// One-shot scripted outcomes per slot id or reply box, modelling what a
    /// real adapter can report. Shared by all handles of this store.
    script: Arc<Mutex<HashMap<Hash, Scripted>>>,
    /// Serializes queue appends across handles of this process.
    queue_lock: Arc<Mutex<()>>,
    /// When set, acknowledgements are lost in transit: nothing is recorded and the outcome is
    /// unknown.
    pub acks_lost: Arc<AtomicBool>,
}

/// A scripted write outcome. With `store_first`, the bytes are stored
/// normally and the scripted result replaces the real one (a lost receipt).
#[derive(Clone, Debug)]
pub struct Scripted {
    pub store_first: bool,
    pub result: Result<CreateOutcome, MailboxError>,
}

impl FsMailbox {
    pub fn create(dir: &Path) -> Self {
        for d in ["slots", "replies", "tmp", "hostile"] {
            fs::create_dir_all(dir.join(d)).unwrap();
        }
        let inc = dir.join("incarnation");
        let incarnation = if inc.exists() {
            fs::read(&inc).unwrap()
        } else {
            let i = random::<32>().to_vec();
            fs::write(&inc, &i).unwrap();
            i
        };
        let key = dir.join("relay_key");
        let relay_key = if key.exists() {
            fs::read(&key).unwrap().try_into().unwrap()
        } else {
            let k = random::<32>();
            fs::write(&key, k).unwrap();
            k
        };
        Self {
            dir: dir.to_path_buf(),
            relay_key,
            incarnation,
            offline: Arc::new(AtomicBool::new(false)),
            gate: Arc::default(),
            script: Arc::default(),
            queue_lock: Arc::default(),
            acks_lost: Arc::default(),
        }
    }

    /// Script the next write outcome for a slot id or reply box.
    pub fn script(&self, target: &Hash, s: Scripted) {
        self.script.lock().unwrap().insert(*target, s);
    }

    fn scripted(&self, target: &Hash) -> Option<Scripted> {
        self.script.lock().unwrap().remove(target)
    }

    /// Run a write, honouring a scripted outcome for `target`.
    fn write_with_script(
        &self,
        target: &Hash,
        real: impl FnOnce() -> Result<CreateOutcome, MailboxError>,
    ) -> Result<CreateOutcome, MailboxError> {
        match self.scripted(target) {
            None => real(),
            Some(s) => {
                if s.store_first {
                    let _ = real();
                }
                s.result
            }
        }
    }

    /// Another handle to the same store with its own gate and offline flag.
    pub fn separate_handle(&self) -> Self {
        Self {
            offline: Arc::new(AtomicBool::new(false)),
            gate: Arc::default(),
            ..self.clone()
        }
    }

    /// A replaced store behind the same relay identity: a new directory and incarnation.
    pub fn replacement(&self, dir: &Path) -> Self {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("relay_key"), self.relay_key).unwrap();
        Self::create(dir)
    }

    /// Simulate a replaced store: a new incarnation for the same directory.
    pub fn reincarnate(&self) {
        fs::write(self.dir.join("incarnation"), random::<32>()).unwrap();
    }

    fn check(&self, pin: &Pin) -> Result<(), MailboxError> {
        self.validate_pin(pin)?;
        let incarnation = pin.incarnation.as_slice();
        if !self.gate.pass() {
            return Err(MailboxError::Uncertain("transport shut down".into()));
        }
        if self.offline.load(Ordering::SeqCst) {
            return Err(MailboxError::Uncertain("offline".into()));
        }
        let current = fs::read(self.dir.join("incarnation"))
            .map_err(|e| MailboxError::Uncertain(e.to_string()))?;
        if incarnation != current.as_slice() {
            return Err(MailboxError::WrongIncarnation);
        }
        Ok(())
    }

    fn slot_path(&self, slot: &SlotId) -> PathBuf {
        self.dir.join("slots").join(hex(slot))
    }

    fn purged(&self, slot: &SlotId) -> PathBuf {
        self.dir.join("slots").join(format!("{}.purged", hex(slot)))
    }

    fn reply_path(&self, reply_box: &Hash) -> PathBuf {
        self.dir.join("replies").join(hex(reply_box))
    }

    fn create_if_absent(&self, target: &Path, bytes: &[u8]) -> Result<CreateOutcome, MailboxError> {
        let tmp = self.dir.join("tmp").join(hex(&random::<12>()));
        fs::write(&tmp, bytes).map_err(|e| MailboxError::Uncertain(e.to_string()))?;
        fs::OpenOptions::new()
            .write(true)
            .open(&tmp)
            .and_then(|f| f.sync_all())
            .map_err(|e| MailboxError::Uncertain(e.to_string()))?;
        let r = match fs::hard_link(&tmp, target) {
            Ok(()) => Ok(CreateOutcome::Created),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing =
                    fs::read(target).map_err(|e| MailboxError::Uncertain(e.to_string()))?;
                Ok(if existing == bytes {
                    CreateOutcome::ExactRetry
                } else {
                    CreateOutcome::Conflict
                })
            }
            Err(e) => Err(MailboxError::Uncertain(e.to_string())),
        };
        let _ = fs::remove_file(&tmp);
        r
    }

    fn create_slot(&self, pin: &Pin, w: &SlotWrite) -> Result<CreateOutcome, MailboxError> {
        self.check(pin)?;
        verify_slot_write(pin, &w.header, &w.bytes)
            .map_err(|e| MailboxError::Refused(format!("write proof: {}", e.0)))?;
        if self.purged(&w.slot()).exists() {
            return Ok(CreateOutcome::Unavailable);
        }
        self.create_if_absent(&self.slot_path(&w.slot()), &w.bytes)
    }

    /// Overwrite the stored body of a queue's `seq`th item behind the store's back, as damage
    /// would; its identity and order are kept.
    pub fn damage_queue_item(&self, queue: &[u8; 32], seq: u64, bytes: &[u8]) {
        let (_, _, path) = self
            .queue_items(queue)
            .into_iter()
            .find(|(s, _, _)| *s == seq)
            .expect("no such queue item");
        fs::write(path, bytes).unwrap();
    }

    /// Forget a queue's items and acknowledgements, as a restore from before they existed would,
    /// keeping the store's identity and incarnation.
    pub fn forget_queue(&self, queue: &[u8; 32]) {
        let _ = fs::remove_dir_all(self.queue_dir(queue));
    }

    /// This store's own pin.
    pub fn pin(&self) -> Pin {
        Pin {
            relay_key: self.relay_key,
            incarnation: self.incarnation.clone(),
        }
    }

    /// Blocking slot write, for adversarial test setup.
    pub fn write_slot_now(&self, w: &SlotWrite) -> Result<CreateOutcome, MailboxError> {
        self.create_slot(&self.pin(), w)
    }

    /// Operator purge: body removed, occupied marker kept.
    pub fn purge(&self, slot: &SlotId) {
        fs::write(self.purged(slot), b"occupied").unwrap();
        let _ = fs::remove_file(self.slot_path(slot));
    }

    /// Hostile view: serve these bytes for a slot regardless of storage.
    pub fn serve_hostile(&self, slot: &SlotId, bytes: &[u8]) {
        fs::write(self.dir.join("hostile").join(hex(slot)), bytes).unwrap();
    }

    pub fn clear_hostile(&self) {
        fs::remove_dir_all(self.dir.join("hostile")).unwrap();
        fs::create_dir_all(self.dir.join("hostile")).unwrap();
    }

    pub fn slot_count(&self) -> usize {
        fs::read_dir(self.dir.join("slots")).unwrap().count()
    }

    /// All slot bodies (relay-visible bytes).
    pub fn all_slots(&self) -> Vec<Vec<u8>> {
        let mut v = vec![];
        for e in fs::read_dir(self.dir.join("slots")).unwrap() {
            let p = e.unwrap().path();
            if !p.to_string_lossy().ends_with(".purged") {
                v.push(fs::read(p).unwrap());
            }
        }
        v
    }

    pub fn all_replies(&self) -> Vec<Vec<u8>> {
        fs::read_dir(self.dir.join("replies"))
            .unwrap()
            .map(|e| fs::read(e.unwrap().path()).unwrap())
            .collect()
    }

    fn queue_dir(&self, queue: &[u8; 32]) -> PathBuf {
        self.dir.join("queues").join(hex(queue))
    }

    /// Every item of a queue, in order: (sequence number, identity, file).
    fn queue_items(&self, queue: &[u8; 32]) -> Vec<(u64, [u8; 32], PathBuf)> {
        let Ok(entries) = fs::read_dir(self.queue_dir(queue)) else {
            return vec![];
        };
        let mut items: Vec<_> = entries
            .filter_map(|e| {
                let path = e.ok()?.path();
                let name = path.file_name()?.to_str()?.to_string();
                let (seq, id) = name.split_once('-')?;
                let id: Vec<u8> = (0..id.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&id[i..i + 2], 16).ok())
                    .collect::<Option<_>>()?;
                Some((seq.parse().ok()?, id.try_into().ok()?, path))
            })
            .collect();
        items.sort_by_key(|(seq, _, _)| *seq);
        items
    }

    pub fn reply_exists(&self, reply_box: &Hash) -> bool {
        self.reply_path(reply_box).exists()
    }

    /// Occupy a reply box with other bytes (conflict setup).
    pub fn occupy_reply(&self, reply_box: &Hash, bytes: &[u8]) {
        fs::write(self.reply_path(reply_box), bytes).unwrap();
    }
}

impl Mailbox for FsMailbox {
    fn validate_pin(&self, pin: &Pin) -> Result<(), MailboxError> {
        // The on-disk incarnation models the relay response, not an adapter configuration.
        if pin.relay_key != self.relay_key {
            return Err(MailboxError::Mispinned("another relay".into()));
        }
        Ok(())
    }

    fn start_create_slot(&self, pin: &Pin, write: SlotWrite) -> Started<CreateOutcome> {
        let (tx, started) = Started::channel();
        let me = self.clone();
        let pin = pin.clone();
        std::thread::spawn(move || {
            let r = me.write_with_script(&write.slot(), || me.create_slot(&pin, &write));
            let _ = tx.send(r);
        });
        started
    }

    fn start_put_reply(&self, pin: &Pin, reply: SlotWrite) -> Started<CreateOutcome> {
        let (tx, started) = Started::channel();
        let me = self.clone();
        let pin = pin.clone();
        std::thread::spawn(move || {
            let reply_box = reply.slot();
            let r = me.check(&pin).and_then(|_| {
                verify_object_write(INVITE_REPLY, &pin, &reply.header, &reply.bytes)
                    .map_err(|e| MailboxError::Refused(format!("reply proof: {}", e.0)))?;
                me.write_with_script(&reply_box, || {
                    me.create_if_absent(&me.reply_path(&reply_box), &reply.bytes)
                })
            });
            let _ = tx.send(r);
        });
        started
    }

    fn start_append(&self, pin: &Pin, append: QueueAppend) -> Started<CreateOutcome> {
        let (tx, started) = Started::channel();
        let me = self.clone();
        let pin = pin.clone();
        std::thread::spawn(move || {
            let r = me.check(&pin).and_then(|_| {
                let h = &append.header;
                if h.purpose != INVITE_REQUEST
                    || h.relay_key != pin.relay_key
                    || h.incarnation.to_bytes().as_slice() != pin.incarnation.as_slice()
                {
                    return Err(MailboxError::Refused(
                        "append for another purpose or store".into(),
                    ));
                }
                verify_append(h)
                    .map_err(|e| MailboxError::Refused(format!("append proof: {e:?}")))?;
                if sha256(&append.bytes) != h.digest || append.bytes.len() as u64 != h.len {
                    return Err(MailboxError::Refused("append body mismatch".into()));
                }
                let dir = me.queue_dir(&h.keys.queue);
                fs::create_dir_all(&dir).map_err(|e| MailboxError::Uncertain(e.to_string()))?;
                let _guard = me.queue_lock.lock().unwrap();
                if me
                    .queue_items(&h.keys.queue)
                    .iter()
                    .any(|(_, id, _)| *id == h.digest)
                {
                    return Ok(CreateOutcome::ExactRetry);
                }
                let seq = me.queue_items(&h.keys.queue).len() as u64 + 1;
                let path = dir.join(format!("{seq:020}-{}", hex(&h.digest)));
                me.create_if_absent(&path, &append.bytes)
            });
            let _ = tx.send(r);
        });
        started
    }

    fn next_item(&self, pin: &Pin, read: ReadHeader) -> Result<Option<QueueItem>, MailboxError> {
        self.check(pin)?;
        if read.relay_key != pin.relay_key {
            return Err(MailboxError::Refused("read for another relay".into()));
        }
        verify_read(&read).map_err(|e| MailboxError::Refused(format!("read proof: {e:?}")))?;
        let acks = self.queue_dir(&read.keys.queue).join("acks");
        Ok(self
            .queue_items(&read.keys.queue)
            .into_iter()
            .find(|(seq, _, _)| *seq > read.after)
            .map(|(seq, id, path)| {
                let bytes = fs::read(path).unwrap();
                QueueItem {
                    seq,
                    acked: acks.join(hex(&id)).exists(),
                    // A stored body that is not the item it is filed as is damaged.
                    body: if sha256(&bytes) == id {
                        QueueBody::Bytes(bytes)
                    } else {
                        QueueBody::Damaged { item: id }
                    },
                }
            }))
    }

    fn start_ack(&self, pin: &Pin, ack: AckHeader) -> Started<AckOutcome> {
        let (tx, started) = Started::channel();
        let me = self.clone();
        let pin = pin.clone();
        std::thread::spawn(move || {
            let result = (|| {
                me.check(&pin)?;
                if ack.relay_key != pin.relay_key {
                    return Err(MailboxError::Refused(
                        "acknowledgement for another relay".into(),
                    ));
                }
                verify_ack(&ack).map_err(|e| MailboxError::Refused(format!("ack proof: {e:?}")))?;
                if me.acks_lost.load(Ordering::SeqCst) {
                    return Err(MailboxError::Uncertain("acknowledgement lost".into()));
                }
                if !me
                    .queue_items(&ack.keys.queue)
                    .iter()
                    .any(|(_, id, _)| *id == ack.item)
                {
                    return Ok(AckOutcome::NoSuchItem);
                }
                let acks = me.queue_dir(&ack.keys.queue).join("acks");
                fs::create_dir_all(&acks).unwrap();
                let marker = acks.join(hex(&ack.item));
                if marker.exists() {
                    return Ok(AckOutcome::AlreadyRecorded);
                }
                fs::write(marker, b"acknowledged").unwrap();
                Ok(AckOutcome::Recorded)
            })();
            let _ = tx.send(result);
        });
        started
    }

    fn read_slot(&self, pin: &Pin, slot: &SlotId) -> Result<ReadOutcome, MailboxError> {
        self.check(pin)?;
        let hostile = self.dir.join("hostile").join(hex(slot));
        if hostile.exists() {
            return Ok(ReadOutcome::Present(fs::read(hostile).unwrap()));
        }
        if self.purged(slot).exists() {
            return Ok(ReadOutcome::Unavailable);
        }
        match fs::read(self.slot_path(slot)) {
            Ok(b) => Ok(ReadOutcome::Present(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ReadOutcome::Absent),
            Err(e) => Err(MailboxError::Uncertain(e.to_string())),
        }
    }

    fn get_reply(&self, pin: &Pin, reply_box: &Hash) -> Result<Option<Vec<u8>>, MailboxError> {
        self.check(pin)?;
        match fs::read(self.reply_path(reply_box)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(MailboxError::Uncertain(e.to_string())),
        }
    }

    fn shutdown(&self) {
        self.gate.shutdown();
    }
}
