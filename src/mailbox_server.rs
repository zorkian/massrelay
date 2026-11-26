//! Unix-only private relay side of the experimental mailbox protocol: request dispatch against
//! the SQLite slot store, and the QUIC stream server. The one wire codec and the client live in
//! [`crate::mailbox`], which builds wherever the private client does.
//!
//! Storage is admitted per connection by the operator's access grants (see [`Mailbox::new`]):
//! a stream on a connection that has not presented a current credential gets only the
//! incarnation, and every storage request is refused with `NotAdmitted` before its fields are
//! checked or its body read.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail, ensure};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    task::JoinSet,
};

use crate::mailbox::{
    AccessKey, CHUNK, Incarnation, Incoming, MEMBERSHIP_SLOT, Rejection, Reply, Request,
    SlotAddress, Unavailable, WriteHeader, WriteRefusal, at_end, read_request,
};
use crate::slot_store::{QueueBody, SlotStore, SlotStoreError, WriteOutcome};
use crate::slot_wire::{
    AckHeader, AppendHeader, INVITE_REPLY, INVITE_REQUEST, ReadHeader, verify_ack, verify_append,
    verify_proof, verify_read,
};

/// The relay side: dispatches requests against one opaque slot store, for the one endpoint key
/// that serves it. Every signed request names that key, so a request signed for another relay
/// that shares this store's incarnation is refused here.
pub struct Mailbox {
    store: SlotStore,
    relay_key: [u8; 32],
    /// Verifiers of the operator's current access grants. Fixed for this mailbox's lifetime.
    grants: HashSet<[u8; 32]>,
}

impl Mailbox {
    /// Serve `store` as the relay with endpoint key `relay_key`, admitting connections that
    /// present a credential whose verifier is one of `grants`. With no grants, nothing is
    /// admitted: there is no open mode.
    pub fn new(
        store: SlotStore,
        relay_key: [u8; 32],
        grants: impl IntoIterator<Item = [u8; 32]>,
    ) -> Self {
        Self {
            store,
            relay_key,
            grants: grants.into_iter().collect(),
        }
    }

    /// Whether `access` is one of the operator's current grants.
    pub fn admits(&self, access: &AccessKey) -> bool {
        self.grants.contains(&access.verifier())
    }

    pub fn incarnation(&self) -> Incarnation {
        self.store.incarnation()
    }

    /// Check everything a write binds, from its header alone, before any body byte is staged.
    /// Membership slots and invite replies are both immutable objects; only the purpose differs.
    pub fn authorize(&self, header: &WriteHeader) -> Result<(), Reply> {
        if header.purpose != MEMBERSHIP_SLOT && header.purpose != INVITE_REPLY {
            return Err(Reply::Rejected(Rejection::Purpose));
        }
        self.pinned(&header.relay_key, &header.incarnation)?;
        verify_proof(header).map_err(refused)
    }

    /// Check a queue append from its header alone, before any body byte is staged.
    pub fn authorize_append(&self, header: &AppendHeader) -> Result<(), Reply> {
        if header.purpose != INVITE_REQUEST {
            return Err(Reply::Rejected(Rejection::Purpose));
        }
        self.pinned(&header.relay_key, &header.incarnation)?;
        verify_append(header).map_err(refused)
    }

    /// Check an acknowledgement key's read of a queue.
    pub fn authorize_next(&self, header: &ReadHeader) -> Result<(), Reply> {
        self.pinned(&header.relay_key, &header.incarnation)?;
        verify_read(header).map_err(refused)
    }

    /// Check an acknowledgement key's terminal acknowledgement.
    pub fn authorize_ack(&self, header: &AckHeader) -> Result<(), Reply> {
        self.pinned(&header.relay_key, &header.incarnation)?;
        verify_ack(header).map_err(refused)
    }

    /// Whether a request was signed for this relay: its endpoint key, then its incarnation.
    fn pinned(&self, relay_key: &[u8; 32], incarnation: &Incarnation) -> Result<(), Reply> {
        if *relay_key != self.relay_key {
            return Err(Reply::Rejected(Rejection::WrongRelay));
        }
        if *incarnation != self.store.incarnation() {
            return Err(Reply::WrongIncarnation);
        }
        Ok(())
    }
}

fn refused(refusal: WriteRefusal) -> Reply {
    Reply::Rejected(match refusal {
        WriteRefusal::InvalidKey => Rejection::InvalidKey,
        WriteRefusal::SlotKeyMismatch => Rejection::SlotKeyMismatch,
        WriteRefusal::InvalidProof => Rejection::InvalidProof,
        WriteRefusal::BodyMismatch => Rejection::BodyMismatch,
    })
}

fn storage_reply(error: SlotStoreError) -> Reply {
    match error {
        SlotStoreError::WrongIncarnation => Reply::WrongIncarnation,
        SlotStoreError::Unconfirmed { .. } => Reply::Unconfirmed,
        SlotStoreError::WriteFailed { .. } => Reply::WriteFailed,
        SlotStoreError::BodyMismatch => Reply::Rejected(Rejection::BodyMismatch),
        SlotStoreError::NeedsReopen => Reply::Unavailable(Unavailable::Suspended),
        SlotStoreError::CorruptObject { .. } => Reply::Unavailable(Unavailable::Damaged),
        _ => Reply::Unavailable(Unavailable::Storage),
    }
}

/// One connection's admission. A connection starts unadmitted, and a current credential admits
/// it for its lifetime; a later failed attempt does not withdraw that.
#[derive(Default)]
pub struct Session {
    admitted: AtomicBool,
}

impl Session {
    /// A session already admitted, for tests that exercise storage directly.
    #[cfg(test)]
    pub fn admitted() -> Self {
        Self {
            admitted: AtomicBool::new(true),
        }
    }

    fn is_admitted(&self) -> bool {
        self.admitted.load(Ordering::SeqCst)
    }
}

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .context("mailbox storage task failed")
}

/// Serve one request stream. An error means the stream must be reset, not finished: it may have
/// carried part of a body that failed verification.
pub async fn serve_stream(
    mailbox: Arc<Mailbox>,
    session: &Session,
    send: &mut (impl AsyncWrite + Unpin),
    recv: &mut (impl AsyncRead + Unpin),
) -> Result<()> {
    let malformed = Reply::Rejected(Rejection::Malformed);
    let not_admitted = Reply::Rejected(Rejection::NotAdmitted);
    let reply = match read_request(recv).await? {
        Incoming::Refused(reply) => reply,
        // A request is complete only when the client finished its stream right after it.
        Incoming::Request(Request::Incarnation) => match at_end(recv).await? {
            true => Reply::Incarnation(mailbox.incarnation()),
            false => malformed,
        },
        Incoming::Request(Request::Admit(access)) => match at_end(recv).await? {
            false => malformed,
            true if mailbox.admits(&access) => {
                session.admitted.store(true, Ordering::SeqCst);
                Reply::Admitted
            }
            true => not_admitted,
        },
        // Every storage request needs an admitted connection. Writes are refused before their
        // headers are checked or any body byte is read.
        Incoming::Request(Request::Read { .. })
        | Incoming::Request(Request::Next(_))
        | Incoming::Request(Request::Ack(_))
            if !session.is_admitted() =>
        {
            match at_end(recv).await? {
                true => not_admitted,
                false => malformed,
            }
        }
        Incoming::Request(Request::Write(_)) | Incoming::Request(Request::Append(_))
            if !session.is_admitted() =>
        {
            not_admitted
        }
        Incoming::Request(Request::Read { incarnation, slot }) => match at_end(recv).await? {
            true => return serve_read(mailbox, send, incarnation, slot).await,
            false => malformed,
        },
        Incoming::Request(Request::Write(header)) => match mailbox.authorize(&header) {
            Err(reply) => reply,
            Ok(()) => {
                receive_body(mailbox, recv, header.len, move |store, body| {
                    store.commit(
                        &header.incarnation,
                        &header.slot,
                        body,
                        Some(&header.digest),
                    )
                })
                .await?
            }
        },
        Incoming::Request(Request::Append(header)) => match mailbox.authorize_append(&header) {
            Err(reply) => reply,
            Ok(()) => {
                receive_body(mailbox, recv, header.len, move |store, body| {
                    store.append(
                        &header.incarnation,
                        &header.keys.queue,
                        body,
                        &header.digest,
                    )
                })
                .await?
            }
        },
        Incoming::Request(Request::Next(header)) => match at_end(recv).await? {
            false => malformed,
            true => match mailbox.authorize_next(&header) {
                Err(reply) => reply,
                Ok(()) => return serve_next(mailbox, send, header).await,
            },
        },
        Incoming::Request(Request::Ack(header)) => match at_end(recv).await? {
            false => malformed,
            true => match mailbox.authorize_ack(&header) {
                Err(reply) => reply,
                Ok(()) => {
                    let store = mailbox.clone();
                    match blocking(move || {
                        store
                            .store
                            .ack(&header.incarnation, &header.keys.queue, &header.item)
                    })
                    .await?
                    {
                        Ok(None) => Reply::Absent,
                        Ok(Some(WriteOutcome::Created)) => Reply::Created,
                        Ok(Some(_)) => Reply::ExactRetry,
                        Err(error) => storage_reply(error),
                    }
                }
            },
        },
    };
    send.write_all(&reply.encode()).await?;
    Ok(())
}

async fn serve_read(
    mailbox: Arc<Mailbox>,
    send: &mut (impl AsyncWrite + Unpin),
    incarnation: Incarnation,
    slot: SlotAddress,
) -> Result<()> {
    let store = mailbox.clone();
    let reader = match blocking(move || store.store.read(&incarnation, &slot)).await? {
        Ok(Some(reader)) => reader,
        Ok(None) => return Ok(send.write_all(&Reply::Absent.encode()).await?),
        Err(error) => return Ok(send.write_all(&storage_reply(error).encode()).await?),
    };
    let header = Reply::Present {
        len: reader.len(),
        digest: reader.digest(),
    };
    send.write_all(&header.encode()).await?;
    stream_reader(send, reader).await
}

async fn serve_next(
    mailbox: Arc<Mailbox>,
    send: &mut (impl AsyncWrite + Unpin),
    header: ReadHeader,
) -> Result<()> {
    let store = mailbox.clone();
    let entry = match blocking(move || {
        store
            .store
            .queue_next(&header.incarnation, &header.keys.queue, header.after)
    })
    .await?
    {
        Ok(Some(entry)) => entry,
        Ok(None) => return Ok(send.write_all(&Reply::Absent.encode()).await?),
        Err(error) => return Ok(send.write_all(&storage_reply(error).encode()).await?),
    };
    // The store verified the whole body against the item's identity in this read view before
    // returning it, so a success header is only ever sent for a body that verified.
    let reader = match entry.body {
        QueueBody::Intact(reader) => reader,
        QueueBody::Damaged => {
            let damaged = Reply::DamagedEntry {
                seq: entry.seq,
                acked: entry.acked,
                item: entry.item,
            };
            return Ok(send.write_all(&damaged.encode()).await?);
        }
    };
    let reply = Reply::Entry {
        seq: entry.seq,
        acked: entry.acked,
        len: reader.len(),
        digest: reader.digest(),
    };
    send.write_all(&reply.encode()).await?;
    stream_reader(send, reader).await
}

/// Stream a committed body through a bounded buffer, failing the stream if it does not verify.
async fn stream_reader(
    send: &mut (impl AsyncWrite + Unpin),
    mut reader: crate::slot_store::SlotReader,
) -> Result<()> {
    let mut buf = vec![0; CHUNK];
    loop {
        let (returned, returned_buf, read) = blocking(move || {
            let read = reader.read(&mut buf);
            (reader, buf, read)
        })
        .await?;
        (reader, buf) = (returned, returned_buf);
        match read {
            Ok(0) => return Ok(()),
            Ok(read) => send.write_all(&buf[..read]).await?,
            Err(error) => bail!("stored body failed verification: {error}"),
        }
    }
}

/// Stream an authorized write's body into staging, then commit it with `commit`.
async fn receive_body(
    mailbox: Arc<Mailbox>,
    recv: &mut (impl AsyncRead + Unpin),
    len: u64,
    commit: impl FnOnce(
        &SlotStore,
        crate::slot_store::StagedBody,
    ) -> Result<WriteOutcome, SlotStoreError>
    + Send
    + 'static,
) -> Result<Reply> {
    let store = mailbox.clone();
    let mut body = match blocking(move || store.store.stage()).await? {
        Ok(body) => body,
        Err(error) => return Ok(storage_reply(error)),
    };
    let mut buf = vec![0; CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let want = usize::try_from(remaining).map_or(CHUNK, |remaining| remaining.min(CHUNK));
        let read = recv.read(&mut buf[..want]).await?;
        ensure!(read > 0, "the body ended before its declared length");
        let (returned, returned_buf, written) = blocking(move || {
            let written = body.write(&buf[..read]);
            (body, buf, written)
        })
        .await?;
        (body, buf) = (returned, returned_buf);
        if let Err(error) = written {
            return Ok(storage_reply(error));
        }
        remaining -= read as u64;
    }
    // Trailing bytes make the request malformed; the staged body is discarded unpublished.
    if !at_end(recv).await? {
        return Ok(Reply::Rejected(Rejection::Malformed));
    }
    let committed = blocking(move || commit(&mailbox.store, body)).await?;
    Ok(match committed {
        Ok(WriteOutcome::Created) => Reply::Created,
        Ok(WriteOutcome::ExactRetry) => Reply::ExactRetry,
        Ok(WriteOutcome::Occupied) => Reply::Occupied,
        Err(error) => storage_reply(error),
    })
}

/// Serve every request stream a client opens on one connection, until it closes.
pub async fn serve_connection(mailbox: Arc<Mailbox>, connection: Connection) {
    let session = Arc::new(Session::default());
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            accepted = connection.accept_bi() => {
                let Ok((send, recv)) = accepted else { break };
                streams.spawn(serve_quic_stream(mailbox.clone(), session.clone(), send, recv));
            }
            Some(_) = streams.join_next() => {}
        }
    }
    while streams.join_next().await.is_some() {}
}

async fn serve_quic_stream(
    mailbox: Arc<Mailbox>,
    session: Arc<Session>,
    mut send: SendStream,
    mut recv: RecvStream,
) {
    match serve_stream(mailbox, &session, &mut send, &mut recv).await {
        Ok(()) => {
            // Dropping the receive side stops any body the relay refused without reading.
            drop(recv);
            if send.finish().is_ok() {
                let _ = send.stopped().await;
            }
        }
        Err(_) => {
            let _ = send.reset(1u32.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh::{EndpointAddr, PublicKey, SecretKey};
    use sha2::{Digest, Sha256};

    use crate::mailbox::*;
    use crate::slot_wire::QueueKeys;
    use std::{fs, path::PathBuf, time::Duration};

    use tokio::time::timeout;

    use super::*;
    use crate::{bind_endpoint, wire};

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    /// The endpoint key every test mailbox serves as.
    fn relay_id() -> PublicKey {
        key(50).public()
    }

    fn relay() -> [u8; 32] {
        *relay_id().as_bytes()
    }

    /// The operator credential every test mailbox admits.
    fn access() -> AccessKey {
        AccessKey(Bytes([60; 32]))
    }

    fn fresh_mailbox() -> (tempfile::TempDir, PathBuf, Arc<Mailbox>, Incarnation) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mailbox");
        let store = SlotStore::initialize(&root).unwrap();
        let incarnation = store.incarnation();
        (
            dir,
            root,
            Arc::new(Mailbox::new(store, relay(), [access().verifier()])),
            incarnation,
        )
    }

    /// Every file in a store, with its bytes.
    fn snapshot(root: &std::path::Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = Vec::new();
        for dir in ["", "staging"] {
            for entry in fs::read_dir(root.join(dir)).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                // SQLite may create or keep its WAL index and log when the database is read.
                if path.is_file()
                    && name != "lock"
                    && !name.ends_with("-wal")
                    && !name.ends_with("-shm")
                {
                    files.push((path.clone(), fs::read(&path).unwrap()));
                }
            }
        }
        files.sort();
        files
    }

    /// Serve one stream of an admitted connection from an in-memory pair, returning the
    /// client's halves.
    fn served(
        mailbox: &Arc<Mailbox>,
    ) -> (
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        served_in(mailbox, Arc::new(Session::admitted()))
    }

    /// Serve one stream of the connection `session` belongs to.
    fn served_in(
        mailbox: &Arc<Mailbox>,
        session: Arc<Session>,
    ) -> (
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (mut server_recv, mut server_send) = tokio::io::split(server);
        let served = tokio::spawn({
            let mailbox = mailbox.clone();
            async move {
                let result =
                    serve_stream(mailbox, &session, &mut server_send, &mut server_recv).await;
                // Finish the reply, as the QUIC server does.
                server_send.shutdown().await?;
                result
            }
        });
        let (recv, send) = tokio::io::split(client);
        (recv, send, served)
    }

    /// Run one exchange against `serve_stream` with the real client framing.
    async fn call(
        mailbox: &Arc<Mailbox>,
        request: Request,
        body: Option<&[u8]>,
    ) -> Result<(Reply, Option<Vec<u8>>)> {
        let (mut recv, mut send, served) = served(mailbox);
        let result = exchange(&mut send, &mut recv, &request, body).await;
        drop((recv, send));
        let served = served.await.unwrap();
        let result = result?;
        served?;
        Ok(result)
    }

    /// Send raw request bytes, finish, and read whatever single reply comes back.
    async fn call_raw(mailbox: &Arc<Mailbox>, bytes: Vec<u8>) -> Result<Reply> {
        let (mut recv, mut send, served) = served(mailbox);
        let _ = send.write_all(&bytes).await;
        let _ = send.shutdown().await;
        let code = recv.read_u8().await?;
        let reply = Reply::read_fields(code, &mut recv).await;
        drop((recv, send));
        served.await.unwrap()?;
        reply
    }

    async fn write(
        mailbox: &Arc<Mailbox>,
        incarnation: &Incarnation,
        key: &SecretKey,
        payload: &[u8],
    ) -> Reply {
        let header = write_header(&relay_id(), incarnation, key, payload);
        call(mailbox, Request::Write(header), Some(payload))
            .await
            .unwrap()
            .0
    }

    async fn read(
        mailbox: &Arc<Mailbox>,
        incarnation: &Incarnation,
        owner: &SecretKey,
    ) -> (Reply, Option<Vec<u8>>) {
        let request = Request::Read {
            incarnation: *incarnation,
            slot: slot_address(&owner.public()),
        };
        call(mailbox, request, None).await.unwrap()
    }

    #[tokio::test]
    async fn slots_are_immutable_and_reads_stream_exact_bytes() {
        let (_dir, _root, mailbox, incarnation) = fresh_mailbox();
        assert_eq!(
            call(&mailbox, Request::Incarnation, None).await.unwrap(),
            (Reply::Incarnation(incarnation), None)
        );
        let owner = key(1);
        assert_eq!(
            read(&mailbox, &incarnation, &owner).await,
            (Reply::Absent, None)
        );
        // A multi-chunk body with no relay-imposed object cap, and an empty one.
        let payload: Vec<u8> = (0..3 * CHUNK as u32 + 7).map(|n| n as u8).collect();
        assert_eq!(
            write(&mailbox, &incarnation, &owner, &payload).await,
            Reply::Created
        );
        assert_eq!(
            write(&mailbox, &incarnation, &owner, &payload).await,
            Reply::ExactRetry
        );
        assert_eq!(
            write(&mailbox, &incarnation, &owner, b"second").await,
            Reply::Occupied
        );
        let (reply, body) = read(&mailbox, &incarnation, &owner).await;
        assert_eq!(
            reply,
            Reply::Present {
                len: payload.len() as u64,
                digest: Sha256::digest(&payload).into()
            }
        );
        assert_eq!(body.unwrap(), payload);
        assert_eq!(
            write(&mailbox, &incarnation, &key(2), b"").await,
            Reply::Created
        );
        assert_eq!(read(&mailbox, &incarnation, &key(2)).await.1.unwrap(), b"");

        let other = Incarnation::from_bytes([9; 32]);
        assert_eq!(
            read(&mailbox, &other, &owner).await,
            (Reply::WrongIncarnation, None)
        );
        assert_eq!(
            write(&mailbox, &other, &owner, &payload).await,
            Reply::WrongIncarnation
        );
    }

    /// Every bound field is checked from the header, before any body byte is staged.
    #[tokio::test]
    async fn write_proofs_are_checked_before_staging() {
        let (_dir, root, mailbox, incarnation) = fresh_mailbox();
        let (owner, stranger) = (key(1), key(2));
        let payload = b"ciphertext";
        let good = write_header(&relay_id(), &incarnation, &owner, payload);
        let resign = |mut header: WriteHeader, signer: &SecretKey| {
            header.proof = signer.sign(&write_statement(VERSION, &header)).to_bytes();
            header
        };
        let with = |change: &dyn Fn(&mut WriteHeader)| {
            let mut header = good;
            change(&mut header);
            header
        };
        let invalid_key = (0..=255u8)
            .map(|byte| [byte; 32])
            .find(|bytes| PublicKey::from_bytes(bytes).is_err())
            .expect("some bytes are not an Ed25519 point");
        let other_incarnation = Incarnation::from_bytes([9; 32]);
        let mut altered = *payload;
        altered[0] ^= 1;

        let cases: Vec<(WriteHeader, Reply)> = vec![
            (
                resign(with(&|h| h.purpose = [0; 32]), &owner),
                Reply::Rejected(Rejection::Purpose),
            ),
            (
                resign(with(&|h| h.incarnation = other_incarnation), &owner),
                Reply::WrongIncarnation,
            ),
            (
                with(&|h| h.write_key = invalid_key),
                Reply::Rejected(Rejection::InvalidKey),
            ),
            (
                with(&|h| h.slot = slot_address(&stranger.public())),
                Reply::Rejected(Rejection::SlotKeyMismatch),
            ),
            (
                with(&|h| h.write_key = *stranger.public().as_bytes()),
                Reply::Rejected(Rejection::SlotKeyMismatch),
            ),
            // Signed by another key, or over another length, digest, version or incarnation.
            (
                resign(good, &stranger),
                Reply::Rejected(Rejection::InvalidProof),
            ),
            (
                with(&|h| h.len += 1),
                Reply::Rejected(Rejection::InvalidProof),
            ),
            (
                with(&|h| h.digest = Sha256::digest(altered).into()),
                Reply::Rejected(Rejection::InvalidProof),
            ),
            (
                {
                    let mut header = good;
                    header.proof = owner
                        .sign(&write_statement(VERSION + 1, &header))
                        .to_bytes();
                    header
                },
                Reply::Rejected(Rejection::InvalidProof),
            ),
            (
                {
                    let mut signed = good;
                    signed.incarnation = other_incarnation;
                    let mut header = good;
                    header.proof = owner.sign(&write_statement(VERSION, &signed)).to_bytes();
                    header
                },
                Reply::Rejected(Rejection::InvalidProof),
            ),
        ];
        let before = snapshot(&root);
        for (header, expected) in cases {
            assert_eq!(mailbox.authorize(&header), Err(expected));
            // Over the stream, a refused write's body is never read: the reply arrives whether
            // or not the declared body is sent.
            for body in [Some(&payload[..]), None] {
                let (reply, _) = call(&mailbox, Request::Write(header), body).await.unwrap();
                assert_eq!(reply, expected);
            }
        }
        let wrong_version = [
            &Request::Write(good).encode_version(VERSION + 1)[..],
            payload,
        ]
        .concat();
        assert_eq!(
            call_raw(&mailbox, wrong_version).await.unwrap(),
            Reply::Rejected(Rejection::Version)
        );
        let mut unknown = Request::Incarnation.encode();
        unknown[0] = 9;
        assert_eq!(
            call_raw(&mailbox, unknown).await.unwrap(),
            Reply::Rejected(Rejection::Malformed)
        );
        assert_eq!(snapshot(&root), before, "nothing reached the store");

        // An authorized header with a body that does not match its signed digest, or that ends
        // early, publishes nothing and leaves nothing staged.
        let mismatched = call(&mailbox, Request::Write(good), Some(&altered))
            .await
            .unwrap()
            .0;
        assert_eq!(mismatched, Reply::Rejected(Rejection::BodyMismatch));
        assert!(
            call(&mailbox, Request::Write(good), Some(&payload[..4]))
                .await
                .is_err()
        );
        // A validly signed header declaring an enormous body is streamed, never sized up front.
        let enormous = resign(with(&|h| h.len = u64::MAX), &owner);
        assert_eq!(mailbox.authorize(&enormous), Ok(()));
        assert!(
            call(&mailbox, Request::Write(enormous), Some(payload))
                .await
                .is_err()
        );
        assert_eq!(snapshot(&root), before);
        assert_eq!(
            read(&mailbox, &incarnation, &owner).await,
            (Reply::Absent, None)
        );

        assert_eq!(
            write(&mailbox, &incarnation, &owner, payload).await,
            Reply::Created
        );
        assert_eq!(
            read(&mailbox, &incarnation, &owner).await.1.unwrap(),
            payload
        );
    }

    #[tokio::test]
    async fn storage_failures_are_never_absence() {
        // An unconfirmed write suspends the store: nothing it cannot confirm reads as absent.
        let dir = tempfile::tempdir().unwrap();
        let store =
            SlotStore::initialize_with_failing_record_sync(&dir.path().join("mailbox")).unwrap();
        let incarnation = store.incarnation();
        let mailbox = Arc::new(Mailbox::new(store, relay(), [access().verifier()]));
        let (first, second) = (key(1), key(2));
        assert_eq!(
            write(&mailbox, &incarnation, &first, b"one").await,
            Reply::Unconfirmed
        );
        for owner in [&first, &second] {
            assert_eq!(
                read(&mailbox, &incarnation, owner).await,
                (Reply::Unavailable(Unavailable::Suspended), None)
            );
        }
        assert_eq!(
            write(&mailbox, &incarnation, &second, b"two").await,
            Reply::Unavailable(Unavailable::Suspended)
        );

        // Damaged stored bytes keep the slot occupied and unavailable, never absent or writable.
        let (_dir, root, mailbox, incarnation) = fresh_mailbox();
        let owner = key(3);
        assert_eq!(
            write(&mailbox, &incarnation, &owner, b"stored").await,
            Reply::Created
        );
        let slot = slot_address(&owner.public());
        crate::slot_store::tamper_body(&root, &slot, b"Stored");
        // The relay announces the committed length and digest, then fails the stream when the
        // stored bytes do not match; the client never accepts them.
        let request = Request::Read {
            incarnation,
            slot: slot_address(&owner.public()),
        };
        assert!(call(&mailbox, request, None).await.is_err());
        crate::slot_store::tamper_body(&root, &slot, b"short");
        assert_eq!(
            read(&mailbox, &incarnation, &owner).await,
            (Reply::Unavailable(Unavailable::Damaged), None)
        );
        assert_eq!(
            write(&mailbox, &incarnation, &owner, b"stored").await,
            Reply::Unavailable(Unavailable::Damaged)
        );
        assert_eq!(
            write(&mailbox, &incarnation, &owner, b"replacement").await,
            Reply::Occupied
        );
    }

    fn queue(append: &SecretKey, ack: &SecretKey) -> QueueKeys {
        QueueKeys::new(*append.public().as_bytes(), *ack.public().as_bytes())
    }

    fn append_by(
        signer: &SecretKey,
        purpose: [u8; 32],
        incarnation: Incarnation,
        keys: QueueKeys,
        body: &[u8],
    ) -> AppendHeader {
        let mut h = crate::slot_wire::unsigned_append(purpose, relay(), incarnation, keys, body);
        h.proof = signer
            .sign(&crate::slot_wire::append_statement(VERSION, &h))
            .to_bytes();
        h
    }

    fn read_by(
        signer: &SecretKey,
        incarnation: Incarnation,
        keys: QueueKeys,
        after: u64,
    ) -> ReadHeader {
        let mut h = ReadHeader {
            relay_key: relay(),
            incarnation,
            keys,
            after,
            proof: [0; 64],
        };
        h.proof = signer
            .sign(&crate::slot_wire::read_statement(VERSION, &h))
            .to_bytes();
        h
    }

    fn ack_by(
        signer: &SecretKey,
        incarnation: Incarnation,
        keys: QueueKeys,
        item: [u8; 32],
    ) -> AckHeader {
        let mut h = AckHeader {
            relay_key: relay(),
            incarnation,
            keys,
            item,
            proof: [0; 64],
        };
        h.proof = signer
            .sign(&crate::slot_wire::ack_statement(VERSION, &h))
            .to_bytes();
        h
    }

    /// Run one exchange on the connection `session` belongs to.
    async fn call_in(
        mailbox: &Arc<Mailbox>,
        session: &Arc<Session>,
        request: Request,
        body: Option<&[u8]>,
    ) -> Reply {
        let (mut recv, mut send, served) = served_in(mailbox, session.clone());
        let result = exchange(&mut send, &mut recv, &request, body).await;
        drop((recv, send));
        served.await.unwrap().unwrap();
        result.unwrap().0
    }

    /// Without a current operator credential a connection gets the incarnation and nothing
    /// else: every storage request, read or write, is refused before its proof is checked or a
    /// body byte is read, and storage is untouched. A granted credential admits the connection
    /// for its lifetime; a mailbox with no grants admits nobody.
    #[tokio::test]
    async fn storage_needs_an_operator_admitted_connection() {
        let (_dir, root, mailbox, incarnation) = fresh_mailbox();
        let owner = key(1);
        let (append, ack) = (key(2), key(3));
        let keys = queue(&append, &ack);
        let large = vec![7; 4 * CHUNK];
        let session = Arc::new(Session::default());
        let before = snapshot(&root);
        let item: [u8; 32] = Sha256::digest(b"request").into();
        let storage = [
            (
                Request::Write(write_header(&relay_id(), &incarnation, &owner, &large)),
                Some(&large[..]),
            ),
            (
                Request::Append(append_by(
                    &append,
                    INVITE_REQUEST,
                    incarnation,
                    keys,
                    b"request",
                )),
                Some(&b"request"[..]),
            ),
            (
                Request::Read {
                    incarnation,
                    slot: slot_address(&owner.public()),
                },
                None,
            ),
            (Request::Next(read_by(&ack, incarnation, keys, 0)), None),
            (Request::Ack(ack_by(&ack, incarnation, keys, item)), None),
        ];
        for (request, body) in &storage {
            assert_eq!(
                call_in(&mailbox, &session, *request, *body).await,
                Reply::Rejected(Rejection::NotAdmitted),
                "{request:?}"
            );
        }
        // Even a forged proof gets the same answer: nothing about the request is evaluated.
        let mut forged = write_header(&relay_id(), &incarnation, &owner, b"x");
        forged.proof = [0; 64];
        assert_eq!(
            call_in(&mailbox, &session, Request::Write(forged), Some(b"x")).await,
            Reply::Rejected(Rejection::NotAdmitted)
        );
        assert_eq!(
            call_in(&mailbox, &session, Request::Incarnation, None).await,
            Reply::Incarnation(incarnation)
        );
        assert_eq!(
            call_in(
                &mailbox,
                &session,
                Request::Admit(AccessKey(Bytes([61; 32]))),
                None
            )
            .await,
            Reply::Rejected(Rejection::NotAdmitted)
        );
        assert_eq!(
            call_in(&mailbox, &session, storage[0].0, storage[0].1).await,
            Reply::Rejected(Rejection::NotAdmitted)
        );
        assert_eq!(snapshot(&root), before, "storage was untouched");

        assert_eq!(
            call_in(&mailbox, &session, Request::Admit(access()), None).await,
            Reply::Admitted
        );
        assert_eq!(
            call_in(&mailbox, &session, storage[0].0, storage[0].1).await,
            Reply::Created
        );
        assert_eq!(
            call_in(&mailbox, &session, storage[1].0, storage[1].1).await,
            Reply::Created
        );
        // A later bad attempt does not withdraw the admission.
        assert_eq!(
            call_in(
                &mailbox,
                &session,
                Request::Admit(AccessKey(Bytes([61; 32]))),
                None
            )
            .await,
            Reply::Rejected(Rejection::NotAdmitted)
        );
        assert_eq!(
            call_in(&mailbox, &session, storage[0].0, storage[0].1).await,
            Reply::ExactRetry
        );
        // Another connection starts unadmitted.
        let other = Arc::new(Session::default());
        assert_eq!(
            call_in(&mailbox, &other, storage[2].0, None).await,
            Reply::Rejected(Rejection::NotAdmitted)
        );

        // No grants, no admission.
        let dir = tempfile::tempdir().unwrap();
        let store = SlotStore::initialize(&dir.path().join("mailbox")).unwrap();
        let closed = Arc::new(Mailbox::new(store, relay(), []));
        let session = Arc::new(Session::default());
        assert_eq!(
            call_in(&closed, &session, Request::Admit(access()), None).await,
            Reply::Rejected(Rejection::NotAdmitted)
        );
    }

    /// Distinct items coexist, an exact retry is the same item, the acknowledgement key alone
    /// reads and acknowledges, and items survive a restart.
    #[tokio::test]
    async fn queues_hold_independent_immutable_items() {
        let (_dir, root, mailbox, incarnation) = fresh_mailbox();
        let (append, ack) = (key(1), key(2));
        let keys = queue(&append, &ack);
        let append_item = |body: &'static [u8]| {
            let header = append_by(&append, INVITE_REQUEST, incarnation, keys, body);
            (Request::Append(header), body)
        };
        for (body, expected) in [
            (&b"garbage first"[..], Reply::Created),
            (b"valid second", Reply::Created),
            (b"garbage first", Reply::ExactRetry),
            (b"", Reply::Created),
        ] {
            let (request, body) = append_item(body);
            assert_eq!(
                call(&mailbox, request, Some(body)).await.unwrap().0,
                expected
            );
        }
        let mut cursor = 0;
        let mut seen = Vec::new();
        loop {
            let next = Request::Next(read_by(&ack, incarnation, keys, cursor));
            match call(&mailbox, next, None).await.unwrap() {
                (
                    Reply::Entry {
                        seq, acked, digest, ..
                    },
                    Some(bytes),
                ) => {
                    assert!(seq > cursor && !acked);
                    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&bytes)));
                    seen.push(bytes);
                    cursor = seq;
                }
                (Reply::Absent, None) => break,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(seen, [&b"garbage first"[..], b"valid second", b""]);

        let item: [u8; 32] = Sha256::digest(b"garbage first").into();
        for expected in [Reply::Created, Reply::ExactRetry] {
            let request = Request::Ack(ack_by(&ack, incarnation, keys, item));
            assert_eq!(call(&mailbox, request, None).await.unwrap().0, expected);
        }
        let unknown = Request::Ack(ack_by(&ack, incarnation, keys, [9; 32]));
        assert_eq!(
            call(&mailbox, unknown, None).await.unwrap().0,
            Reply::Absent
        );
        let first = Request::Next(read_by(&ack, incarnation, keys, 0));
        assert!(matches!(
            call(&mailbox, first, None).await.unwrap().0,
            Reply::Entry { acked: true, .. }
        ));

        // A restart keeps every item and acknowledgement.
        drop(mailbox);
        let mailbox = Arc::new(Mailbox::new(
            SlotStore::open(&root).unwrap(),
            relay(),
            [access().verifier()],
        ));
        let first = Request::Next(read_by(&ack, incarnation, keys, 0));
        assert!(matches!(
            call(&mailbox, first, None).await.unwrap(),
            (Reply::Entry { acked: true, .. }, Some(bytes)) if bytes == b"garbage first"
        ));
    }

    /// Each capability works only in its own domain, and nothing reaches the store otherwise.
    #[tokio::test]
    async fn queue_and_reply_capabilities_never_cross_domains() {
        let (_dir, root, mailbox, incarnation) = fresh_mailbox();
        let (append, ack, reply) = (key(1), key(2), key(3));
        let keys = queue(&append, &ack);
        let before = snapshot(&root);
        let rejected = |why| Reply::Rejected(why);
        let mut wrong_handle = keys;
        wrong_handle.queue[0] ^= 1;
        let reply_box = slot_address(&reply.public());
        // A joiner holding the append key forges a reply into the issuer's reply object.
        let mut forged_reply = write_header(&relay_id(), &incarnation, &append, b"reply");
        forged_reply.slot = reply_box;
        forged_reply.purpose = INVITE_REPLY;
        let cases: Vec<(Request, Option<&[u8]>, Reply)> = vec![
            // Append signed by the acknowledgement key, or under a handle not binding its keys.
            (
                Request::Append(append_by(&ack, INVITE_REQUEST, incarnation, keys, b"x")),
                Some(b"x"),
                rejected(Rejection::InvalidProof),
            ),
            (
                Request::Append(append_by(
                    &append,
                    INVITE_REQUEST,
                    incarnation,
                    wrong_handle,
                    b"x",
                )),
                Some(b"x"),
                rejected(Rejection::SlotKeyMismatch),
            ),
            // An append or object under the other's purpose.
            (
                Request::Append(append_by(&append, INVITE_REPLY, incarnation, keys, b"x")),
                Some(b"x"),
                rejected(Rejection::Purpose),
            ),
            (
                Request::Write({
                    let mut h = write_header(&relay_id(), &incarnation, &reply, b"x");
                    h.purpose = INVITE_REQUEST;
                    h
                }),
                Some(b"x"),
                rejected(Rejection::Purpose),
            ),
            // The append key can neither read nor acknowledge.
            (
                Request::Next(read_by(&append, incarnation, keys, 0)),
                None,
                rejected(Rejection::InvalidProof),
            ),
            (
                Request::Ack(ack_by(&append, incarnation, keys, [0; 32])),
                None,
                rejected(Rejection::InvalidProof),
            ),
            // Nor can it write the issuer's reply object.
            (
                Request::Write(forged_reply),
                Some(b"reply"),
                rejected(Rejection::SlotKeyMismatch),
            ),
            // Another incarnation.
            (
                Request::Next(read_by(&ack, Incarnation::from_bytes([9; 32]), keys, 0)),
                None,
                Reply::WrongIncarnation,
            ),
        ];
        for (request, body, expected) in cases {
            assert_eq!(
                call(&mailbox, request, body).await.unwrap().0,
                expected,
                "{request:?}"
            );
        }
        assert_eq!(snapshot(&root), before, "nothing reached the store");

        // The issuer's reply key writes its object once; nobody can replace it.
        let mut h = write_header(&relay_id(), &incarnation, &reply, b"sealed reply");
        h.purpose = INVITE_REPLY;
        h.proof = reply.sign(&write_statement(VERSION, &h)).to_bytes();
        assert_eq!(
            call(&mailbox, Request::Write(h), Some(b"sealed reply"))
                .await
                .unwrap()
                .0,
            Reply::Created
        );
        let mut other = write_header(&relay_id(), &incarnation, &reply, b"another reply");
        other.purpose = INVITE_REPLY;
        other.proof = reply.sign(&write_statement(VERSION, &other)).to_bytes();
        assert_eq!(
            call(&mailbox, Request::Write(other), Some(b"another reply"))
                .await
                .unwrap()
                .0,
            Reply::Occupied
        );
    }

    /// Correctly signed requests for another relay identity that shares this store's
    /// incarnation are refused before any storage work, for every signed operation.
    #[tokio::test]
    async fn requests_signed_for_another_relay_are_refused() {
        let (_dir, root, mailbox, incarnation) = fresh_mailbox();
        let (owner, append, ack) = (key(1), key(2), key(3));
        let keys = queue(&append, &ack);
        // Stored first, so the queue read and acknowledgement name a real item.
        let item_body = b"request";
        let stored = append_by(&append, INVITE_REQUEST, incarnation, keys, item_body);
        assert_eq!(
            call(&mailbox, Request::Append(stored), Some(item_body))
                .await
                .unwrap()
                .0,
            Reply::Created
        );
        let before = snapshot(&root);
        let other = key(51).public();
        let wrong = *other.as_bytes();
        let item: [u8; 32] = Sha256::digest(item_body).into();
        let mut a = append_by(&append, INVITE_REQUEST, incarnation, keys, b"second");
        a.relay_key = wrong;
        a.proof = append
            .sign(&crate::slot_wire::append_statement(VERSION, &a))
            .to_bytes();
        let mut r = read_by(&ack, incarnation, keys, 0);
        r.relay_key = wrong;
        r.proof = ack
            .sign(&crate::slot_wire::read_statement(VERSION, &r))
            .to_bytes();
        let mut k = ack_by(&ack, incarnation, keys, item);
        k.relay_key = wrong;
        k.proof = ack
            .sign(&crate::slot_wire::ack_statement(VERSION, &k))
            .to_bytes();
        let cases: Vec<(Request, Option<&[u8]>)> = vec![
            (
                Request::Write(write_header(&other, &incarnation, &owner, b"slot")),
                Some(b"slot"),
            ),
            (Request::Append(a), Some(b"second")),
            (Request::Next(r), None),
            (Request::Ack(k), None),
        ];
        for (request, body) in cases {
            assert_eq!(
                call(&mailbox, request, body).await.unwrap().0,
                Reply::Rejected(Rejection::WrongRelay),
                "{request:?}"
            );
        }
        assert_eq!(snapshot(&root), before, "nothing reached the store");
        // The same item is still served, unacknowledged, to a request signed for this relay.
        assert!(matches!(
            call(&mailbox, Request::Next(read_by(&ack, incarnation, keys, 0)), None)
                .await
                .unwrap(),
            (Reply::Entry { seq: 1, acked: false, .. }, Some(bytes)) if bytes == item_body
        ));
    }

    /// A queue item whose stored body is definitively damaged is reported with its order and
    /// identity and no body, before any success header; later items are still served, and the
    /// damaged one can be acknowledged.
    #[tokio::test]
    async fn damaged_queue_items_are_typed_and_block_nothing() {
        let (_dir, root, mailbox, incarnation) = fresh_mailbox();
        let (append, ack) = (key(1), key(2));
        let keys = queue(&append, &ack);
        let bodies: [&[u8]; 3] = [b"first item", b"second item", b"third item"];
        for body in bodies {
            let header = append_by(&append, INVITE_REQUEST, incarnation, keys, body);
            assert_eq!(
                call(&mailbox, Request::Append(header), Some(body))
                    .await
                    .unwrap()
                    .0,
                Reply::Created
            );
        }
        let id = |body: &[u8]| -> [u8; 32] { Sha256::digest(body).into() };
        // Same length, other bytes: only the final digest check can tell.
        crate::slot_store::tamper_item(&root, &keys.queue, &id(bodies[0]), b"First item");
        // Fewer bytes than committed.
        crate::slot_store::tamper_item(&root, &keys.queue, &id(bodies[2]), b"third");
        let next = |after| Request::Next(read_by(&ack, incarnation, keys, after));
        let damaged = |seq, acked, body: &[u8]| {
            (
                Reply::DamagedEntry {
                    seq,
                    acked,
                    item: id(body),
                },
                None,
            )
        };
        assert_eq!(
            call(&mailbox, next(0), None).await.unwrap(),
            damaged(1, false, bodies[0])
        );
        assert!(matches!(
            call(&mailbox, next(1), None).await.unwrap(),
            (Reply::Entry { seq: 2, acked: false, .. }, Some(bytes)) if bytes == bodies[1]
        ));
        assert_eq!(
            call(&mailbox, next(2), None).await.unwrap(),
            damaged(3, false, bodies[2])
        );
        assert_eq!(
            call(&mailbox, next(3), None).await.unwrap(),
            (Reply::Absent, None)
        );
        let acked = Request::Ack(ack_by(&ack, incarnation, keys, id(bodies[0])));
        assert_eq!(call(&mailbox, acked, None).await.unwrap().0, Reply::Created);
        assert_eq!(
            call(&mailbox, next(0), None).await.unwrap(),
            damaged(1, true, bodies[0])
        );
    }

    /// A request is complete only at the client's finish; trailing bytes are refused unread.
    #[tokio::test]
    async fn requests_must_end_exactly() {
        let (_dir, root, mailbox, incarnation) = fresh_mailbox();
        let owner = key(1);
        let read = Request::Read {
            incarnation,
            slot: slot_address(&owner.public()),
        };
        for request in [Request::Incarnation, read] {
            let trailing = [&request.encode()[..], &[0]].concat();
            assert_eq!(
                call_raw(&mailbox, trailing).await.unwrap(),
                Reply::Rejected(Rejection::Malformed)
            );
        }
        let before = snapshot(&root);
        let payload = b"body";
        let header = write_header(&relay_id(), &incarnation, &owner, payload);
        let trailing = [&Request::Write(header).encode()[..], payload, b"!"].concat();
        assert_eq!(
            call_raw(&mailbox, trailing).await.unwrap(),
            Reply::Rejected(Rejection::Malformed)
        );
        assert_eq!(
            snapshot(&root),
            before,
            "nothing was published or left staged"
        );

        // The relay answers only once the client has finished its stream.
        let (mut recv, mut send, served) = served(&mailbox);
        send.write_all(&Request::Incarnation.encode())
            .await
            .unwrap();
        let mut byte = [0; 1];
        assert!(
            timeout(Duration::from_millis(200), recv.read(&mut byte))
                .await
                .is_err(),
            "replied before the request was complete"
        );
        send.shutdown().await.unwrap();
        assert_eq!(
            Reply::read_for(&Request::Incarnation, &mut recv)
                .await
                .unwrap(),
            Reply::Incarnation(incarnation)
        );
        drop((recv, send));
        served.await.unwrap().unwrap();
    }

    /// A sink that records the largest write it was handed.
    #[derive(Default)]
    struct Recorder {
        bytes: Vec<u8>,
        largest: usize,
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.largest = self.largest.max(buf.len());
            self.bytes.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn bodies_stream_to_a_bounded_consumer() {
        let (_dir, _root, mailbox, incarnation) = fresh_mailbox();
        let owner = key(1);
        let payload: Vec<u8> = (0..5 * CHUNK as u32 + 3).map(|n| (n * 7) as u8).collect();
        assert_eq!(
            write(&mailbox, &incarnation, &owner, &payload).await,
            Reply::Created
        );
        let request = Request::Read {
            incarnation,
            slot: slot_address(&owner.public()),
        };
        let (mut recv, mut send, served) = served(&mailbox);
        send_request(&mut send, &request, None).await.unwrap();
        let Reply::Present { len, digest } = Reply::read_for(&request, &mut recv).await.unwrap()
        else {
            panic!("expected the body");
        };
        let mut sink = Recorder::default();
        receive_body_into(&mut recv, len, &digest, &mut sink)
            .await
            .unwrap();
        assert_eq!(sink.bytes, payload);
        assert!(
            sink.largest <= CHUNK,
            "handed {} bytes at once",
            sink.largest
        );
        drop((recv, send));
        served.await.unwrap().unwrap();
    }

    /// Disposable loopback endpoints with relay and discovery disabled.
    #[tokio::test]
    async fn quic_clients_pin_the_relay_and_race_for_slots() -> Result<()> {
        let (_dir, _root, mailbox, incarnation) = fresh_mailbox();
        let loopback = "127.0.0.1:0".parse()?;
        let relay = bind_endpoint(key(50), loopback, None, ALPN, false).await?;
        let server = tokio::spawn({
            let (relay, mailbox) = (relay.clone(), mailbox.clone());
            async move {
                let mut connections = JoinSet::new();
                while let Some(incoming) = relay.accept().await {
                    let mailbox = mailbox.clone();
                    connections.spawn(async move {
                        if let Ok(connection) = incoming.await {
                            serve_connection(mailbox, connection).await;
                        }
                    });
                }
            }
        });
        let client_endpoint =
            bind_endpoint(key(51), loopback, None, b"massrelay/test-client", false).await?;
        let socket = relay.bound_sockets()[0];
        let pinned = EndpointAddr::new(relay.id()).with_ip_addr(socket);

        timeout(Duration::from_secs(30), async {
            // A different identity at the same address is never accepted as the relay, and the
            // legacy control ALPN is not served here.
            let impostor = EndpointAddr::new(key(52).public()).with_ip_addr(socket);
            let refused = timeout(
                Duration::from_secs(5),
                Client::connect(&client_endpoint, impostor, &access()),
            )
            .await;
            assert!(
                !matches!(refused, Ok(Ok(_))),
                "connected to an unpinned identity"
            );
            let legacy = timeout(
                Duration::from_secs(5),
                client_endpoint.connect(pinned.clone(), wire::CONTROL),
            )
            .await;
            assert!(!matches!(legacy, Ok(Ok(_))), "legacy ALPN accepted");

            // A credential the operator never granted is refused, but the incarnation is
            // still served on the pinned channel.
            let refused = Client::connect(
                &client_endpoint,
                pinned.clone(),
                &AccessKey(Bytes([61; 32])),
            )
            .await
            .err()
            .expect("an ungranted credential was admitted");
            assert!(
                refused.downcast_ref::<NotAdmitted>().is_some(),
                "{refused:#}"
            );
            let unadmitted = Client::connect_unadmitted(&client_endpoint, pinned.clone()).await?;
            assert_eq!(unadmitted.incarnation().await?, incarnation);
            assert!(
                unadmitted
                    .read(&incarnation, &slot_address(&key(1).public()))
                    .await
                    .is_err(),
                "an unadmitted read is never absence"
            );

            let client =
                Arc::new(Client::connect(&client_endpoint, pinned.clone(), &access()).await?);
            assert_eq!(client.incarnation().await?, incarnation);
            let other = Incarnation::from_bytes([9; 32]);
            let owner = key(1);
            let slot = slot_address(&owner.public());
            assert_eq!(
                client.read(&other, &slot).await?,
                ReadResult::WrongIncarnation
            );
            assert_eq!(client.read(&incarnation, &slot).await?, ReadResult::Absent);

            // A refused multi-chunk write gets its reply without the relay reading the body.
            let large = vec![5; 4 * CHUNK];
            assert_eq!(
                client.write(&other, &owner, &large).await?,
                WriteResult::WrongIncarnation
            );

            // Different values raced over one connection: one wins, the rest see it occupied.
            let mut racers = JoinSet::new();
            for writer in 0..16u8 {
                let (client, owner) = (client.clone(), owner.clone());
                racers.spawn(async move {
                    let payload = vec![writer; CHUNK + usize::from(writer)];
                    (
                        payload.clone(),
                        client.write(&incarnation, &owner, &payload).await,
                    )
                });
            }
            let mut winners = Vec::new();
            while let Some(joined) = racers.join_next().await {
                let (payload, result) = joined?;
                match result? {
                    WriteResult::Created => winners.push(payload),
                    WriteResult::Occupied => {}
                    other => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(winners.len(), 1);
            let mut sink = Recorder::default();
            assert_eq!(
                client.read_into(&incarnation, &slot, &mut sink).await?,
                ReadInto::Present {
                    len: winners[0].len() as u64,
                    digest: Sha256::digest(&winners[0]).into()
                }
            );
            assert_eq!(sink.bytes, winners[0]);
            assert!(
                client
                    .is_published(&incarnation, &slot, &winners[0])
                    .await?
            );
            assert!(!client.is_published(&incarnation, &slot, &[200; 64]).await?);

            // The same value raced over separate connections: one creates, the rest retry.
            let same = key(2);
            let mut racers = JoinSet::new();
            for _ in 0..8 {
                let (endpoint, pinned, same) =
                    (client_endpoint.clone(), pinned.clone(), same.clone());
                racers.spawn(async move {
                    let client = Client::connect(&endpoint, pinned, &access()).await?;
                    client.write(&incarnation, &same, b"agreed").await
                });
            }
            let mut created = 0;
            while let Some(joined) = racers.join_next().await {
                match joined?? {
                    WriteResult::Created => created += 1,
                    WriteResult::ExactRetry => {}
                    other => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(created, 1);
            assert_eq!(
                client
                    .read(&incarnation, &slot_address(&same.public()))
                    .await?,
                ReadResult::Present(b"agreed".to_vec())
            );
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        client_endpoint.close().await;
        relay.close().await;
        server.await?;
        Ok(())
    }
}
