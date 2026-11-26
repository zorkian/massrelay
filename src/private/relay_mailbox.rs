//! EXPERIMENTAL: the membership [`Mailbox`] boundary over the real private relay mailbox.
//!
//! Built with the `private-membership` feature on every platform: it uses only the portable
//! mailbox client and codec ([`crate::mailbox`]) and the shared write primitives
//! (`crate::slot_wire`), never the Unix relay host. Nothing in the CLI or daemon uses it yet.
//!
//! - **Pinning.** The adapter serves exactly one relay endpoint key and storage incarnation,
//!   together. It dials that endpoint, whose key Iroh authenticates, and any call whose pin
//!   names another relay or incarnation fails with `Mispinned` before anything is sent, so a
//!   misconfigured adapter can never cause a halt. Every signed header names the relay key as
//!   well as the incarnation, and one naming another is refused locally; the relay refuses it
//!   again. Only the pinned relay's authenticated `WrongIncarnation` is reported as such.
//! - **Identity.** It uses its own random mailbox transport identity, never a device or
//!   membership key, and it holds no write, append or acknowledgement key: devices hand it
//!   fully prepared, signed requests, which it forwards without re-signing.
//! - **Admission.** Each connection presents the relay operator's access credential from the
//!   pinned locator before any request, and is used only once admitted. A refused credential
//!   is the relay operator's decision about this connection, never a verdict on a request: it
//!   reports nothing stored (or, for reads, unavailable storage), so the device keeps its
//!   state and retries once the credential is replaced.
//! - **Handoff.** The `start_*` calls check the pin and the header's fixed-size fields, then
//!   move the device's signed header and owned body onto an unbounded queue owned by a worker
//!   thread. They never copy or hash the body and do no network, disk, connection setup or
//!   capacity wait; the worker checks the body's length and digest before sending. The worker
//!   connects lazily and runs every request with the full fixed-framing completion checks. A
//!   send is never retried invisibly; a later application attempt rechecks eligibility first.
//! - **Shutdown.** [`Mailbox::shutdown`] wakes every call in flight at once: a read reports
//!   `Uncertain`, and a write, append or acknowledgement that may already have been sent reports
//!   `Uncertain`, never a refusal, so the device keeps it possibly delivered. Requests still
//!   queued, and every later call, send nothing and say so. The worker then closes its endpoint.
//! - **Outcomes.** Created, exact retry and conflict come from the store's durable decision.
//!   An authenticated incarnation mismatch, a definitive refusal, a definite no-commit
//!   (`NotStored`), unavailable storage and unknown delivery (`Uncertain`) stay distinct. A failed
//!   read is never absence, and bytes are exposed only after their length and digest checked out.
//!
//! # Invites
//!
//! Join requests are items of an invite's request queue: appended with the invite's shared
//! append key, read and terminally acknowledged only with the issuer's per-invite
//! acknowledgement key. The sealed reply is an immutable object written only with the issuer's
//! per-invite reply key. Both are relay operations; there is no local seam.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

use iroh::{EndpointAddr, SecretKey};
use tokio::sync::{Mutex, mpsc as queue, watch};

use super::codec::Hash;
use super::envelope::SlotId;
use super::mailbox::{
    AckOutcome, CreateOutcome, Mailbox, MailboxError, Pin, QueueAppend, QueueBody, QueueItem,
    ReadOutcome, SlotWrite, Started,
};
use crate::mailbox::{
    AccessKey, AckResult, Client, NextResult, ReadResult, Rejection, Unavailable, WriteResult,
};
use crate::slot_wire::{
    AckHeader, AppendHeader, INVITE_REPLY, INVITE_REQUEST, Incarnation, MEMBERSHIP_SLOT,
    ReadHeader, SlotAddress, WriteHeader, queue_handle, slot_address,
};

/// Transport ALPN the adapter's own endpoint advertises. It accepts nothing.
const CLIENT_ALPN: &[u8] = b"massrelay/mailbox-client/experimental-1";

type Reply<T> = mpsc::Sender<Result<T, MailboxError>>;

enum Job {
    Write {
        header: WriteHeader,
        bytes: Vec<u8>,
        done: Reply<CreateOutcome>,
    },
    Append {
        header: AppendHeader,
        bytes: Vec<u8>,
        done: Reply<CreateOutcome>,
    },
    Read {
        incarnation: Incarnation,
        slot: SlotAddress,
        done: Reply<ReadOutcome>,
    },
    Next {
        header: ReadHeader,
        done: Reply<Option<QueueItem>>,
    },
    Ack {
        header: AckHeader,
        done: Reply<AckOutcome>,
    },
}

/// A membership mailbox backed by one pinned private relay.
pub struct RelayMailbox {
    jobs: queue::UnboundedSender<Job>,
    /// The relay endpoint key and storage incarnation this adapter serves, together.
    pin: Pin,
    /// Set once by `shutdown`; no later call is handed to the worker.
    closed: AtomicBool,
    /// Wakes the worker and every request it is running.
    cancel: watch::Sender<bool>,
}

impl RelayMailbox {
    /// Start the worker: bind a fresh transport identity at `bind` and pin `relay` and
    /// `incarnation`. Binding happens here, never at a handoff.
    pub fn start(
        relay: EndpointAddr,
        incarnation: Incarnation,
        access: AccessKey,
        bind: SocketAddr,
        relay_url: Option<iroh::RelayUrl>,
    ) -> anyhow::Result<Self> {
        let pin = Pin {
            relay_key: *relay.id.as_bytes(),
            incarnation: incarnation.to_bytes().to_vec(),
        };
        let (jobs, mut pending) = queue::unbounded_channel::<Job>();
        let (cancel, cancelled) = watch::channel(false);
        let (ready, started) = mpsc::channel();
        std::thread::Builder::new()
            .name("private-mailbox".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(anyhow::Error::from(error)));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let mut seed = [0; 32];
                    if let Err(error) = getrandom::fill(&mut seed) {
                        let _ = ready.send(Err(anyhow::anyhow!("{error}")));
                        return;
                    }
                    let endpoint = match crate::bind_endpoint(
                        SecretKey::from_bytes(&seed),
                        bind,
                        relay_url,
                        CLIENT_ALPN,
                        false,
                    )
                    .await
                    {
                        Ok(endpoint) => endpoint,
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            return;
                        }
                    };
                    let _ = ready.send(Ok(()));
                    let worker = Arc::new(Worker {
                        endpoint: endpoint.clone(),
                        relay,
                        access,
                        client: Mutex::new(None),
                        cancelled: cancelled.clone(),
                    });
                    let mut running = tokio::task::JoinSet::new();
                    let stop = stopped(cancelled);
                    tokio::pin!(stop);
                    loop {
                        tokio::select! {
                            biased;
                            _ = &mut stop => break,
                            job = pending.recv() => match job {
                                Some(job) => {
                                    running.spawn(worker.clone().run(job));
                                }
                                None => break,
                            },
                            Some(_) = running.join_next() => {}
                        }
                    }
                    // Requests never started were never sent.
                    pending.close();
                    while let Ok(job) = pending.try_recv() {
                        unsent(job, "the mailbox stopped; nothing was sent");
                    }
                    // Requests running were woken by the same signal and answer at once.
                    while running.join_next().await.is_some() {}
                    endpoint.close().await;
                });
            })?;
        started
            .recv()
            .map_err(|_| anyhow::anyhow!("the mailbox worker stopped while starting"))??;
        Ok(Self {
            jobs,
            pin,
            closed: AtomicBool::new(false),
            cancel,
        })
    }

    /// The call's pin must be exactly this adapter's relay and incarnation. Otherwise nothing is
    /// sent, and nothing is reported as the relay's verdict.
    fn pinned(&self, pin: &Pin) -> Result<Incarnation, MailboxError> {
        if *pin != self.pin {
            return Err(MailboxError::Mispinned(
                "this mailbox serves another relay or storage incarnation; nothing was sent".into(),
            ));
        }
        Incarnation::from_slice(&pin.incarnation)
            .ok_or_else(|| MailboxError::Mispinned("the pinned incarnation is not 32 bytes".into()))
    }

    /// Hand a write of `purpose` to the worker after fixed-size checks only.
    fn start_object(
        &self,
        pin: &Pin,
        purpose: [u8; 32],
        write: SlotWrite,
    ) -> Started<CreateOutcome> {
        let incarnation = match self.pinned(pin) {
            Ok(incarnation) => incarnation,
            Err(error) => return Started::done(Err(error)),
        };
        let SlotWrite { header, bytes } = write;
        if header.relay_key != pin.relay_key
            || header.incarnation != incarnation
            || header.purpose != purpose
            || slot_address(&header.write_key) != header.slot
        {
            return Started::done(Err(MailboxError::Refused(
                "the prepared header is not this kind of write for this pin".into(),
            )));
        }
        let (done, started) = Started::channel();
        self.send(Job::Write {
            header,
            bytes,
            done,
        });
        started
    }

    fn send(&self, job: Job) {
        if self.closed.load(Ordering::SeqCst) {
            return unsent(job, "the mailbox was shut down; nothing was sent");
        }
        if let Err(queue::error::SendError(job)) = self.jobs.send(job) {
            unsent(job, "the mailbox worker stopped; nothing was sent");
        }
    }

    fn wait<T>(outcome: mpsc::Receiver<Result<T, MailboxError>>) -> Result<T, MailboxError> {
        outcome.recv().unwrap_or_else(|_| {
            Err(MailboxError::Uncertain(
                "the request ended without an outcome".into(),
            ))
        })
    }
}

/// Answer a request that never reached the network: a write is definitely not stored, and a
/// read established nothing.
fn unsent(job: Job, why: &str) {
    match job {
        Job::Write { done, .. } | Job::Append { done, .. } => {
            let _ = done.send(Err(MailboxError::NotStored(why.into())));
        }
        Job::Read { done, .. } => {
            let _ = done.send(Err(MailboxError::Uncertain(why.into())));
        }
        Job::Next { done, .. } => {
            let _ = done.send(Err(MailboxError::Uncertain(why.into())));
        }
        Job::Ack { done, .. } => {
            let _ = done.send(Err(MailboxError::NotStored(why.into())));
        }
    }
}

/// Resolve once the adapter is shut down.
async fn stopped(mut cancelled: watch::Receiver<bool>) {
    let _ = cancelled.wait_for(|stop| *stop).await;
}

/// What a request woken by shutdown reports: it may already have been sent.
const WOKEN: &str = "the mailbox was shut down during the request; delivery is unknown";

struct Worker {
    endpoint: iroh::Endpoint,
    relay: EndpointAddr,
    /// The operator credential each new connection presents before any request.
    access: AccessKey,
    client: Mutex<Option<Arc<Client>>>,
    cancelled: watch::Receiver<bool>,
}

impl Worker {
    /// The current connection, or a new one. A failure here means nothing was sent.
    async fn client(&self) -> anyhow::Result<Arc<Client>> {
        let mut current = self.client.lock().await;
        if let Some(client) = current.as_ref().filter(|client| !client.is_closed()) {
            return Ok(client.clone());
        }
        let client =
            Arc::new(Client::connect(&self.endpoint, self.relay.clone(), &self.access).await?);
        *current = Some(client.clone());
        Ok(client)
    }

    async fn run(self: Arc<Self>, job: Job) {
        let woken = || MailboxError::Uncertain(WOKEN.into());
        let stop = stopped(self.cancelled.clone());
        tokio::pin!(stop);
        match job {
            Job::Write {
                header,
                bytes,
                done,
            } => {
                let work = self.clone().attempt(Job::Write {
                    header,
                    bytes,
                    done: done.clone(),
                });
                tokio::select! {
                    biased;
                    _ = &mut stop => { let _ = done.send(Err(woken())); }
                    _ = work => {}
                }
            }
            Job::Append {
                header,
                bytes,
                done,
            } => {
                let work = self.clone().attempt(Job::Append {
                    header,
                    bytes,
                    done: done.clone(),
                });
                tokio::select! {
                    biased;
                    _ = &mut stop => { let _ = done.send(Err(woken())); }
                    _ = work => {}
                }
            }
            Job::Read {
                incarnation,
                slot,
                done,
            } => {
                let work = self.clone().attempt(Job::Read {
                    incarnation,
                    slot,
                    done: done.clone(),
                });
                tokio::select! {
                    biased;
                    _ = &mut stop => { let _ = done.send(Err(woken())); }
                    _ = work => {}
                }
            }
            Job::Next { header, done } => {
                let work = self.clone().attempt(Job::Next {
                    header,
                    done: done.clone(),
                });
                tokio::select! {
                    biased;
                    _ = &mut stop => { let _ = done.send(Err(woken())); }
                    _ = work => {}
                }
            }
            Job::Ack { header, done } => {
                let work = self.clone().attempt(Job::Ack {
                    header,
                    done: done.clone(),
                });
                tokio::select! {
                    biased;
                    _ = &mut stop => { let _ = done.send(Err(woken())); }
                    _ = work => {}
                }
            }
        }
    }

    /// Run one request to its outcome and send it.
    async fn attempt(self: Arc<Self>, job: Job) {
        let client = self.client().await;
        let unreachable = |error: &anyhow::Error| {
            format!("could not reach the relay; nothing was sent: {error:#}")
        };
        let unknown = |error: anyhow::Error| MailboxError::Uncertain(format!("{error:#}"));
        match job {
            Job::Write {
                header,
                bytes,
                done,
            } => {
                let outcome = match client {
                    Err(error) => Err(MailboxError::NotStored(unreachable(&error))),
                    Ok(client) => match client.write_prepared(&header, &bytes).await {
                        Ok(result) => write_outcome(result),
                        Err(error) => Err(unknown(error)),
                    },
                };
                let _ = done.send(outcome);
            }
            Job::Append {
                header,
                bytes,
                done,
            } => {
                let outcome = match client {
                    Err(error) => Err(MailboxError::NotStored(unreachable(&error))),
                    Ok(client) => match client.append_prepared(&header, &bytes).await {
                        Ok(result) => write_outcome(result),
                        Err(error) => Err(unknown(error)),
                    },
                };
                let _ = done.send(outcome);
            }
            Job::Read {
                incarnation,
                slot,
                done,
            } => {
                let outcome = match client {
                    Err(error) => Err(MailboxError::Uncertain(unreachable(&error))),
                    Ok(client) => match client.read(&incarnation, &slot).await {
                        Ok(result) => read_outcome(result),
                        Err(error) => Err(unknown(error)),
                    },
                };
                let _ = done.send(outcome);
            }
            Job::Next { header, done } => {
                let outcome = match client {
                    Err(error) => Err(MailboxError::Uncertain(unreachable(&error))),
                    Ok(client) => match client.next_item(&header).await {
                        Ok(result) => next_outcome(result),
                        Err(error) => Err(unknown(error)),
                    },
                };
                let _ = done.send(outcome);
            }
            Job::Ack { header, done } => {
                let outcome = match client {
                    Err(error) => Err(MailboxError::NotStored(unreachable(&error))),
                    Ok(client) => match client.ack(&header).await {
                        Ok(result) => ack_outcome(result),
                        Err(error) => Err(unknown(error)),
                    },
                };
                let _ = done.send(outcome);
            }
        }
    }
}

const NOT_ADMITTED: &str =
    "the relay did not admit this connection's access credential; nothing was stored";

fn write_outcome(result: WriteResult) -> Result<CreateOutcome, MailboxError> {
    match result {
        WriteResult::Created => Ok(CreateOutcome::Created),
        WriteResult::ExactRetry => Ok(CreateOutcome::ExactRetry),
        WriteResult::Occupied => Ok(CreateOutcome::Conflict),
        // Occupied, but its stored body cannot be compared.
        WriteResult::Unavailable(Unavailable::Damaged) => Ok(CreateOutcome::Unavailable),
        WriteResult::WrongIncarnation => Err(MailboxError::WrongIncarnation),
        // Operator admission is about this connection, not the request: never definitive.
        WriteResult::Rejected(Rejection::NotAdmitted) => {
            Err(MailboxError::NotStored(NOT_ADMITTED.into()))
        }
        WriteResult::Rejected(why) => Err(MailboxError::Refused(format!("{why:?}"))),
        WriteResult::Unconfirmed => Err(MailboxError::Uncertain(
            "the relay could not confirm the write".into(),
        )),
        // The relay refused before committing: definitely not stored, retryable.
        WriteResult::WriteFailed => Err(MailboxError::NotStored(
            "the relay's storage failed before committing".into(),
        )),
        WriteResult::Unavailable(why) => Err(MailboxError::NotStored(format!(
            "the relay's storage is unavailable ({why:?}); nothing was committed"
        ))),
    }
}

fn read_outcome(result: ReadResult) -> Result<ReadOutcome, MailboxError> {
    match result {
        ReadResult::Present(bytes) => Ok(ReadOutcome::Present(bytes)),
        ReadResult::Absent => Ok(ReadOutcome::Absent),
        ReadResult::WrongIncarnation => Err(MailboxError::WrongIncarnation),
        // Occupied but unreadable: never absence.
        ReadResult::Unavailable(Unavailable::Damaged) => Ok(ReadOutcome::Unavailable),
        ReadResult::Unavailable(why) => Err(MailboxError::StorageUnavailable(format!("{why:?}"))),
    }
}

fn next_outcome(result: NextResult) -> Result<Option<QueueItem>, MailboxError> {
    match result {
        NextResult::Item { seq, acked, bytes } => Ok(Some(QueueItem {
            seq,
            acked,
            body: QueueBody::Bytes(bytes),
        })),
        NextResult::Damaged { seq, acked, item } => Ok(Some(QueueItem {
            seq,
            acked,
            body: QueueBody::Damaged { item },
        })),
        NextResult::Empty => Ok(None),
        NextResult::WrongIncarnation => Err(MailboxError::WrongIncarnation),
        NextResult::Rejected(Rejection::NotAdmitted) => {
            Err(MailboxError::StorageUnavailable(NOT_ADMITTED.into()))
        }
        NextResult::Rejected(why) => Err(MailboxError::Refused(format!("{why:?}"))),
        NextResult::Unavailable(why) => Err(MailboxError::StorageUnavailable(format!("{why:?}"))),
    }
}

fn ack_outcome(result: AckResult) -> Result<AckOutcome, MailboxError> {
    match result {
        AckResult::Recorded => Ok(AckOutcome::Recorded),
        AckResult::AlreadyRecorded => Ok(AckOutcome::AlreadyRecorded),
        AckResult::NoSuchItem => Ok(AckOutcome::NoSuchItem),
        AckResult::WrongIncarnation => Err(MailboxError::WrongIncarnation),
        AckResult::Rejected(Rejection::NotAdmitted) => {
            Err(MailboxError::NotStored(NOT_ADMITTED.into()))
        }
        AckResult::Rejected(why) => Err(MailboxError::Refused(format!("{why:?}"))),
        AckResult::Unconfirmed => Err(MailboxError::Uncertain(
            "the relay could not confirm the acknowledgement".into(),
        )),
        AckResult::WriteFailed => Err(MailboxError::NotStored(
            "the relay's storage failed before committing".into(),
        )),
        AckResult::Unavailable(why) => Err(MailboxError::NotStored(format!(
            "the relay's storage is unavailable ({why:?}); nothing was committed"
        ))),
    }
}

impl Mailbox for RelayMailbox {
    fn validate_pin(&self, pin: &Pin) -> Result<(), MailboxError> {
        self.pinned(pin).map(|_| ())
    }

    /// Wake every call in flight and refuse later ones without sending (see the module docs).
    fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.cancel.send_replace(true);
    }

    fn start_create_slot(&self, pin: &Pin, write: SlotWrite) -> Started<CreateOutcome> {
        self.start_object(pin, MEMBERSHIP_SLOT, write)
    }

    fn start_put_reply(&self, pin: &Pin, reply: SlotWrite) -> Started<CreateOutcome> {
        self.start_object(pin, INVITE_REPLY, reply)
    }

    fn start_append(&self, pin: &Pin, append: QueueAppend) -> Started<CreateOutcome> {
        let incarnation = match self.pinned(pin) {
            Ok(incarnation) => incarnation,
            Err(error) => return Started::done(Err(error)),
        };
        let QueueAppend { header, bytes } = append;
        let keys = header.keys;
        if header.relay_key != pin.relay_key
            || header.incarnation != incarnation
            || header.purpose != INVITE_REQUEST
            || queue_handle(&keys.append_key, &keys.ack_key) != keys.queue
        {
            return Started::done(Err(MailboxError::Refused(
                "the prepared append is not an invite request for this pin".into(),
            )));
        }
        let (done, started) = Started::channel();
        self.send(Job::Append {
            header,
            bytes,
            done,
        });
        started
    }

    fn read_slot(&self, pin: &Pin, slot: &SlotId) -> Result<ReadOutcome, MailboxError> {
        let incarnation = self.pinned(pin)?;
        let (done, outcome) = mpsc::channel();
        self.send(Job::Read {
            incarnation,
            slot: SlotAddress::from_bytes(*slot),
            done,
        });
        Self::wait(outcome)
    }

    fn get_reply(&self, pin: &Pin, reply_box: &Hash) -> Result<Option<Vec<u8>>, MailboxError> {
        match self.read_slot(pin, reply_box)? {
            ReadOutcome::Present(bytes) => Ok(Some(bytes)),
            ReadOutcome::Absent => Ok(None),
            ReadOutcome::Unavailable => Err(MailboxError::StorageUnavailable(
                "the reply object is occupied but unreadable".into(),
            )),
        }
    }

    fn next_item(&self, pin: &Pin, read: ReadHeader) -> Result<Option<QueueItem>, MailboxError> {
        let incarnation = self.pinned(pin)?;
        if read.relay_key != pin.relay_key || read.incarnation != incarnation {
            return Err(MailboxError::Refused(
                "the read is for another relay or incarnation".into(),
            ));
        }
        let (done, outcome) = mpsc::channel();
        self.send(Job::Next { header: read, done });
        Self::wait(outcome)
    }

    fn start_ack(&self, pin: &Pin, ack: AckHeader) -> Started<AckOutcome> {
        let incarnation = match self.pinned(pin) {
            Ok(incarnation) => incarnation,
            Err(error) => return Started::done(Err(error)),
        };
        if ack.relay_key != pin.relay_key || ack.incarnation != incarnation {
            return Started::done(Err(MailboxError::Refused(
                "the acknowledgement is for another relay or incarnation".into(),
            )));
        }
        let (done, started) = Started::channel();
        self.send(Job::Ack { header: ack, done });
        started
    }
}
