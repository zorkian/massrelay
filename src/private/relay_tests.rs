//! Membership over the real private relay mailbox, on disposable loopback endpoints and
//! temporary directories. Relay and discovery are disabled; every key is throwaway.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use iroh::{EndpointAddr, SecretKey};
use tokio::sync::{RwLock, watch};

use super::binding::{EndpointKey, EndpointSecret};
use super::codec::{Enc, random};
use super::envelope::{InviteToken, verify_slot_write};
use super::mailbox::{
    AckOutcome, CreateOutcome, Mailbox, MailboxError, Pin, ReadOutcome, SlotWrite,
};
use super::membership::*;
use super::relay_mailbox::RelayMailbox;
use crate::mailbox::{
    ALPN, AccessKey, AckResult, Bytes, Client, NextResult, Rejection, WriteResult,
};
use crate::mailbox_server::{Mailbox as RelayStore, Session, serve_stream};
use crate::slot_store::SlotStore;
use crate::slot_wire::Incarnation;

/// The operator credential every test relay grants and every test adapter presents.
const ACCESS: AccessKey = AccessKey(Bytes([70; 32]));

/// A loopback private relay whose store can be replaced and whose streams can be held.
struct Relay {
    runtime: tokio::runtime::Runtime,
    endpoint: iroh::Endpoint,
    addr: EndpointAddr,
    store: Arc<RwLock<Arc<RelayStore>>>,
    hold: watch::Sender<bool>,
    held: Arc<AtomicUsize>,
    /// Request streams this relay has accepted.
    served: Arc<AtomicUsize>,
    root: PathBuf,
}

impl Relay {
    fn start(root: &Path, store: SlotStore) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let endpoint = runtime
            .block_on(crate::bind_endpoint(
                SecretKey::from_bytes(&random()),
                "127.0.0.1:0".parse().unwrap(),
                None,
                ALPN,
                false,
            ))
            .unwrap();
        let addr = EndpointAddr::new(endpoint.id()).with_ip_addr(endpoint.bound_sockets()[0]);
        let key = *endpoint.id().as_bytes();
        let store = Arc::new(RwLock::new(Arc::new(RelayStore::new(
            store,
            key,
            [ACCESS.verifier()],
        ))));
        let (hold, held_rx) = watch::channel(false);
        let held = Arc::new(AtomicUsize::new(0));
        let served = Arc::new(AtomicUsize::new(0));
        let (accepting, current, entered, count) = (
            endpoint.clone(),
            store.clone(),
            held.clone(),
            served.clone(),
        );
        runtime.spawn(async move {
            while let Some(incoming) = accepting.accept().await {
                let (current, gate, entered, count) = (
                    current.clone(),
                    held_rx.clone(),
                    entered.clone(),
                    count.clone(),
                );
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    let session = Arc::new(Session::default());
                    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                        count.fetch_add(1, Ordering::SeqCst);
                        let (current, mut gate, entered, session) = (
                            current.clone(),
                            gate.clone(),
                            entered.clone(),
                            session.clone(),
                        );
                        tokio::spawn(async move {
                            if *gate.borrow() {
                                entered.fetch_add(1, Ordering::SeqCst);
                                let _ = gate.wait_for(|held| !*held).await;
                            }
                            let store = current.read().await.clone();
                            match serve_stream(store, &session, &mut send, &mut recv).await {
                                Ok(()) => {
                                    drop(recv);
                                    if send.finish().is_ok() {
                                        let _ = send.stopped().await;
                                    }
                                }
                                Err(_) => {
                                    let _ = send.reset(1u32.into());
                                }
                            }
                        });
                    }
                });
            }
        });
        Self {
            runtime,
            endpoint,
            addr,
            store,
            hold,
            held,
            served,
            root: root.into(),
        }
    }

    fn incarnation(&self) -> Incarnation {
        self.runtime.block_on(self.store.read()).incarnation()
    }

    /// Serve a different store, as after an incomplete restore, behind the same relay identity.
    fn replace_store(&self, store: SlotStore) {
        let key = *self.endpoint.id().as_bytes();
        *self.runtime.block_on(self.store.write()) =
            Arc::new(RelayStore::new(store, key, [ACCESS.verifier()]));
    }

    /// Restart this relay's own store, as a relay process restart would.
    fn restart_store(&self, scratch: &Path) {
        let key = *self.endpoint.id().as_bytes();
        let mut current = self.runtime.block_on(self.store.write());
        *current = Arc::new(RelayStore::new(
            SlotStore::initialize(scratch).unwrap(),
            key,
            [ACCESS.verifier()],
        ));
        *current = Arc::new(RelayStore::new(
            SlotStore::open(&self.root).unwrap(),
            key,
            [ACCESS.verifier()],
        ));
    }

    fn hold(&self) {
        self.hold.send_replace(true);
    }

    fn release(&self) {
        self.hold.send_replace(false);
    }

    /// Every file the relay stores, with its bytes.
    fn artifacts(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = Vec::new();
        let mut dirs = vec![self.root.clone()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else {
                    files.push((path.clone(), std::fs::read(&path).unwrap()));
                }
            }
        }
        files
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let endpoint = self.endpoint.clone();
        self.runtime.block_on(endpoint.close());
    }
}

type Adapter = RelayMailbox;

struct Net {
    _dir: tempfile::TempDir,
    root: PathBuf,
    relay: Relay,
}

impl Net {
    fn new() -> Self {
        Self::with_store(|root| SlotStore::initialize(root).unwrap())
    }

    fn with_store(store: impl FnOnce(&Path) -> SlotStore) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let relay_root = root.join("relay");
        let relay = Relay::start(&relay_root, store(&relay_root));
        Self {
            _dir: dir,
            root,
            relay,
        }
    }

    /// A new adapter with its own transport identity, pinned to this relay.
    fn adapter(&self) -> Adapter {
        RelayMailbox::start(
            self.relay.addr.clone(),
            self.relay.incarnation(),
            ACCESS,
            "127.0.0.1:0".parse().unwrap(),
            None,
        )
        .unwrap()
    }

    fn relay_key(&self) -> [u8; 32] {
        *self.relay.endpoint.id().as_bytes()
    }

    fn pin(&self) -> Pin {
        Pin {
            relay_key: self.relay_key(),
            incarnation: self.relay.incarnation().to_bytes().to_vec(),
        }
    }
}

struct Member {
    dev: Device<Adapter>,
    ep: EndpointKey,
    path: PathBuf,
}

impl Member {
    fn head(&self) -> [u8; 32] {
        self.dev.state().unwrap().net.unwrap().head
    }

    fn reopen(&self, n: &Net) -> Device<Adapter> {
        Device::open(&self.path, n.adapter(), Clock::System).unwrap()
    }
}

fn create(n: &Net, name: &str) -> Member {
    let secret = EndpointSecret::generate();
    let path = n.root.join(name);
    let dev = Device::create_network(
        &path,
        &secret,
        n.relay_key(),
        n.relay.incarnation().to_bytes().to_vec(),
        n.adapter(),
        Clock::System,
    )
    .unwrap();
    Member {
        dev,
        ep: secret.public(),
        path,
    }
}

/// The joiner and its invite id: the request travels through the relay's invite queue and the
/// issuer reserves it from there.
fn request_join(n: &Net, issuer: &Member, name: &str) -> (Member, [u8; 16], Vec<u8>) {
    let token = issuer.dev.issue_invite().unwrap();
    let secret = EndpointSecret::generate();
    let path = n.root.join(name);
    let (dev, _request) =
        Device::begin_join(&path, &secret, &token, n.adapter(), Clock::System).unwrap();
    let invite_id = InviteToken::decode(&token).unwrap().invite_id;
    assert_eq!(dev.send_join_request().unwrap(), CreateOutcome::Created);
    let polled = issuer.dev.poll_join_requests().unwrap();
    assert!(
        polled.iter().any(|p| p.invite_id == invite_id
            && matches!(
                p.verdict,
                Verdict::Reserved(ReserveOutcome::Reserved { .. })
            )
            && p.ack == AckState::Confirmed(AckOutcome::Recorded)),
        "{polled:?}"
    );
    let member = Member {
        dev,
        ep: secret.public(),
        path,
    };
    (member, invite_id, token)
}

/// The joiner's request delivered to the issuer locally, for relays whose storage is meant to
/// fail every write.
fn request_join_locally(n: &Net, issuer: &Member, name: &str) -> (Member, [u8; 16]) {
    let token = issuer.dev.issue_invite().unwrap();
    let secret = EndpointSecret::generate();
    let path = n.root.join(name);
    let (dev, request) =
        Device::begin_join(&path, &secret, &token, n.adapter(), Clock::System).unwrap();
    let invite_id = InviteToken::decode(&token).unwrap().invite_id;
    assert!(matches!(
        issuer
            .dev
            .receive_join_request(&invite_id, &request)
            .unwrap(),
        ReserveOutcome::Reserved { .. }
    ));
    let member = Member {
        dev,
        ep: secret.public(),
        path,
    };
    (member, invite_id)
}

fn admit(issuer: &Member, joiner: &Member, invite_id: &[u8; 16]) {
    issuer.dev.stage_add(invite_id).unwrap();
    assert_eq!(issuer.dev.publish().unwrap(), CreateOutcome::Created);
    assert_eq!(issuer.dev.settle().unwrap(), Settle::Accepted);
    assert_eq!(
        issuer.dev.dispatch_replies().unwrap(),
        vec![Dispatch::Sent {
            invite_id: *invite_id
        }]
    );
    joiner.dev.complete_join().unwrap();
}

fn agree(members: &[&Member]) {
    let fingerprint = members[0].dev.group_fingerprint().unwrap();
    for m in &members[1..] {
        assert_eq!(m.dev.group_fingerprint().unwrap(), fingerprint);
        assert_eq!(m.head(), members[0].head(), "accepted heads differ");
        assert_eq!(m.dev.roster().unwrap(), members[0].dev.roster().unwrap());
    }
}

fn journal_write(m: &Member) -> SlotWrite {
    let st = m.dev.state().unwrap();
    let j = st.journal.unwrap();
    SlotWrite {
        header: j.write_header(&st.net.unwrap().pin()).unwrap(),
        bytes: j.slot_bytes,
    }
}

#[test]
fn create_invite_join_and_catch_up_over_the_real_relay() {
    let n = Net::new();
    let alice = create(&n, "alice");
    let (bob, bob_invite, bob_token) = request_join(&n, &alice, "bob");
    admit(&alice, &bob, &bob_invite);
    agree(&[&alice, &bob]);
    let (carol, carol_invite, carol_token) = request_join(&n, &bob, "carol");
    admit(&bob, &carol, &carol_invite);
    let (applied, stop) = alice.dev.catch_up();
    assert_eq!(stop, Stop::UpToDate);
    assert_eq!(applied.len(), 1, "alice caught up through bob's add");
    agree(&[&alice, &bob, &carol]);
    let mut roster = vec![alice.ep, bob.ep, carol.ep];
    roster.sort();
    assert_eq!(alice.dev.roster().unwrap(), roster);

    // The relay holds two immutable slots of ciphertext: no group id or tag, endpoint or MLS
    // key, invite secret or token appears in any file it stores, database or log.
    let net = alice.dev.state().unwrap().net.unwrap();
    let mut private: Vec<Vec<u8>> = vec![net.group_id.clone(), net.group_tag.to_vec()];
    for m in [&alice, &bob, &carol] {
        private.push(m.ep.to_vec());
        private.push(m.dev.state().unwrap().net.unwrap().mls_key);
    }
    for token in [&bob_token, &carol_token] {
        private.push(InviteToken::decode(token).unwrap().secret.to_vec());
        private.push(token.clone());
    }
    let artifacts = n.relay.artifacts();
    // The relay holds the two accepted slots, the two reply objects and the two request items,
    // and nothing else.
    let stored = crate::slot_store::stored_slots(&n.relay.root);
    assert_eq!(stored.len(), 6, "{stored:?}");
    for slot in net.accepted.iter().map(|a| a.slot) {
        assert!(stored.contains(&slot));
    }
    for token in [&bob_token, &carol_token] {
        assert!(stored.contains(&InviteToken::decode(token).unwrap().reply_box()));
    }
    for (path, bytes) in &artifacts {
        for field in &private {
            assert!(
                !bytes.windows(field.len()).any(|w| w == field.as_slice()),
                "{} contains a private field",
                path.display()
            );
        }
    }
}

#[test]
fn device_and_relay_share_one_write_proof_and_exact_bytes() {
    let n = Net::new();
    let alice = create(&n, "alice");
    let (_carol, invite, _) = request_join(&n, &alice, "carol");
    alice.dev.stage_add(&invite).unwrap();
    let write = journal_write(&alice);
    let pin = n.pin();
    let incarnation = n.relay.incarnation().to_bytes();
    // The same prepared write passes the device's check and the relay's.
    verify_slot_write(&pin, &write.header, &write.bytes).unwrap();

    let mailbox = n.adapter();
    let mut forged_proof = write.clone();
    forged_proof.header.proof[0] ^= 1;
    let mut forged_bytes = write.clone();
    forged_bytes.bytes[0] ^= 1;
    let mut forged_shape = write.clone();
    forged_shape.header.slot = crate::slot_wire::SlotAddress::from_bytes([0; 32]);
    for forged in [forged_proof, forged_bytes] {
        assert!(matches!(
            mailbox.start_create_slot(&pin, forged).wait(),
            Err(MailboxError::Refused(_))
        ));
    }
    // A header that is not a membership write for this pin is refused before anything is sent.
    let served = n.relay.served.load(Ordering::SeqCst);
    let mut forged_purpose = write.clone();
    forged_purpose.header.purpose = [0; 32];
    for forged in [forged_shape, forged_purpose] {
        assert!(matches!(
            mailbox.start_create_slot(&pin, forged).wait(),
            Err(MailboxError::Refused(_))
        ));
    }
    assert_eq!(n.relay.served.load(Ordering::SeqCst), served);
    assert_eq!(
        mailbox.read_slot(&pin, &write.slot()).unwrap(),
        ReadOutcome::Absent
    );

    assert_eq!(
        mailbox.start_create_slot(&pin, write.clone()).wait(),
        Ok(CreateOutcome::Created)
    );
    assert_eq!(
        mailbox.start_create_slot(&pin, write.clone()).wait(),
        Ok(CreateOutcome::ExactRetry)
    );
    // A different body properly signed by the same slot key cannot replace it.
    let (keys, _) = alice.dev.slot_keys().unwrap();
    let rival = keys.seal(&incarnation, &Enc::new().bytes(b"rival").finish());
    let rival = SlotWrite {
        header: keys.prepare(&pin, &rival).unwrap(),
        bytes: rival,
    };
    assert_eq!(rival.slot(), write.slot());
    assert_eq!(
        mailbox.start_create_slot(&pin, rival).wait(),
        Ok(CreateOutcome::Conflict)
    );
    assert_eq!(
        mailbox.read_slot(&pin, &write.slot()).unwrap(),
        ReadOutcome::Present(write.bytes.clone())
    );
    // The device's own publication is an exact retry, and only the matching read settles it.
    assert_eq!(alice.dev.publish().unwrap(), CreateOutcome::ExactRetry);
    assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
}

#[test]
fn an_authenticated_incarnation_mismatch_halts_membership() {
    let n = Net::new();
    let alice = create(&n, "alice");
    let (bob, invite, _) = request_join(&n, &alice, "bob");
    admit(&alice, &bob, &invite);
    let (_carol, carol_invite, _) = request_join(&n, &alice, "carol");
    alice.dev.stage_add(&carol_invite).unwrap();
    let dana_token = alice.dev.issue_invite().unwrap();
    let dana = begin(&n, &dana_token, "dana");

    // The pinned relay now serves a different store.
    n.relay
        .replace_store(SlotStore::initialize(&n.root.join("replacement")).unwrap());
    // A joiner's request append, and the issuer's queue read, see the authenticated mismatch.
    assert!(matches!(
        dana.dev.send_join_request(),
        Err(Error::Join(JoinError::Halted(_)))
    ));
    assert!(
        dana.dev
            .state()
            .unwrap()
            .pending_join
            .unwrap()
            .halted
            .is_some()
    );
    assert!(matches!(
        alice.dev.publish(),
        Err(Error::Mailbox(MailboxError::WrongIncarnation))
    ));
    assert!(matches!(
        alice.dev.poll_join_requests(),
        Err(Error::Halted(Halt::IncarnationMismatch { .. }))
    ));
    assert!(matches!(
        alice.dev.state().unwrap().halt,
        Some(Halt::IncarnationMismatch { .. })
    ));
    assert!(matches!(
        bob.dev.catch_up().1,
        Stop::Halted(Halt::IncarnationMismatch { .. })
    ));
    // The halt persists across reopening, without contacting the relay.
    let reopened = alice.reopen(&n);
    assert!(matches!(
        reopened.state().unwrap().halt,
        Some(Halt::IncarnationMismatch { .. })
    ));
    assert!(reopened.publish().is_err());
}

#[test]
fn definite_and_unknown_completion_stay_distinct() {
    let staged = |n: &Net| {
        let alice = create(n, "alice");
        let (carol, invite) = request_join_locally(n, &alice, "carol");
        alice.dev.stage_add(&invite).unwrap();
        (alice, carol)
    };

    // The relay's storage failed before committing: definitely not stored, retryable.
    let n = Net::with_store(|root| SlotStore::initialize_with_failing_publish(root).unwrap());
    let (alice, _carol) = staged(&n);
    assert!(matches!(
        alice.dev.publish(),
        Err(Error::Mailbox(MailboxError::NotStored(_)))
    ));
    assert_eq!(
        alice
            .dev
            .mailbox()
            .read_slot(&n.pin(), &journal_write(&alice).slot())
            .unwrap(),
        ReadOutcome::Absent
    );

    // The relay could not confirm the write: unknown, and later reads are unavailable storage,
    // never absence.
    let n = Net::with_store(|root| SlotStore::initialize_with_failing_record_sync(root).unwrap());
    let (alice, _carol) = staged(&n);
    assert!(matches!(
        alice.dev.publish(),
        Err(Error::Mailbox(MailboxError::Uncertain(_)))
    ));
    assert!(matches!(
        alice.dev.settle(),
        Err(Error::Mailbox(MailboxError::StorageUnavailable(_)))
    ));

    // A pinned identity that does not answer at its address: nothing was sent.
    let n = Net::new();
    let (alice, _carol) = staged(&n);
    let absent = SecretKey::from_bytes(&random()).public();
    let unreachable = RelayMailbox::start(
        EndpointAddr::new(absent).with_ip_addr(n.relay.endpoint.bound_sockets()[0]),
        n.relay.incarnation(),
        ACCESS,
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .unwrap();
    let pin = Pin {
        relay_key: *absent.as_bytes(),
        incarnation: n.relay.incarnation().to_bytes().to_vec(),
    };
    // A header signed for the network's relay is refused locally by an adapter pinned elsewhere.
    assert!(matches!(
        unreachable
            .start_create_slot(&pin, journal_write(&alice))
            .wait(),
        Err(MailboxError::Refused(_))
    ));
    let mut elsewhere = journal_write(&alice);
    elsewhere.header.relay_key = pin.relay_key;
    assert!(matches!(
        unreachable.start_create_slot(&pin, elsewhere).wait(),
        Err(MailboxError::NotStored(_))
    ));
    assert!(matches!(
        unreachable.read_slot(&pin, &journal_write(&alice).slot()),
        Err(MailboxError::Uncertain(_))
    ));
}

/// An adapter whose operator credential the relay does not grant stores nothing, and its
/// outcomes are availability, never a definitive refusal of the device's request: the same
/// signed write completes once the adapter presents a granted credential.
#[test]
fn an_ungranted_credential_is_availability_never_a_refusal() {
    let n = Net::new();
    let alice = create(&n, "alice");
    let (_carol, invite) = request_join_locally(&n, &alice, "carol");
    alice.dev.stage_add(&invite).unwrap();
    let before = n.relay.artifacts();
    let ungranted = RelayMailbox::start(
        n.relay.addr.clone(),
        n.relay.incarnation(),
        AccessKey(Bytes([71; 32])),
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .unwrap();
    let write = journal_write(&alice);
    assert!(matches!(
        ungranted.start_create_slot(&n.pin(), write.clone()).wait(),
        Err(MailboxError::NotStored(_))
    ));
    assert!(matches!(
        ungranted.read_slot(&n.pin(), &write.slot()),
        Err(MailboxError::Uncertain(_))
    ));
    ungranted.shutdown();
    assert_eq!(n.relay.artifacts(), before, "nothing was stored");
    let granted = n.adapter();
    assert!(matches!(
        granted.start_create_slot(&n.pin(), write.clone()).wait(),
        Ok(CreateOutcome::Created)
    ));
}

#[test]
fn a_stalled_mailbox_send_never_blocks_live_local_cutoff() {
    let n = Net::new();
    let alice = create(&n, "alice");
    let (bob, invite, _) = request_join(&n, &alice, "bob");
    admit(&alice, &bob, &invite);
    let (_carol, carol_invite, _) = request_join(&n, &alice, "carol");
    alice.dev.stage_add(&carol_invite).unwrap();

    n.relay.hold();
    let stalled = alice.reopen(&n);
    std::thread::scope(|s| {
        let publishing = s.spawn(|| stalled.publish());
        let deadline = Instant::now() + Duration::from_secs(20);
        while n.relay.held.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "the send never reached the relay"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            alice
                .dev
                .state()
                .unwrap()
                .journal
                .unwrap()
                .publish_attempted
        );
        // Local cutoffs and other local writes proceed while the send is stalled.
        let started = Instant::now();
        let outcome = alice
            .dev
            .revoke(&EndpointSecret::generate().public())
            .unwrap();
        assert!(outcome.local_cutoff);
        alice.dev.issue_invite().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!publishing.is_finished(), "the send is still stalled");
        n.relay.release();
        assert_eq!(publishing.join().unwrap().unwrap(), CreateOutcome::Created);
    });
    assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
    let (_, stop) = bob.dev.catch_up();
    assert_eq!(stop, Stop::UpToDate);
    agree(&[&alice, &bob]);
}

/// A mailbox configured for another relay, with the same or another storage incarnation, sends
/// nothing and halts nothing. Only the pinned relay's authenticated mismatch halts.
#[test]
fn a_wrong_relay_identity_is_refused_locally_and_sends_nothing() {
    // Another relay identity serving an offline copy of this relay's store (same incarnation),
    // and another with a store of its own (another incarnation).
    let mut copy = PathBuf::new();
    let n = Net::with_store(|root| {
        drop(SlotStore::initialize(root).unwrap());
        copy = root.parent().unwrap().join("copy");
        copy_dir(root, &copy);
        SlotStore::open(root).unwrap()
    });
    let same = Relay::start(&copy, SlotStore::open(&copy).unwrap());
    assert_eq!(same.incarnation(), n.relay.incarnation());
    assert_ne!(same.addr.id, n.relay.addr.id);
    let alice = create(&n, "alice");
    let (bob, invite, _) = request_join(&n, &alice, "bob");
    admit(&alice, &bob, &invite);
    let (carol, carol_invite, carol_token) = request_join(&n, &alice, "carol");
    alice.dev.stage_add(&carol_invite).unwrap();
    let fresh = n.root.join("fresh");
    let other = Relay::start(&fresh, SlotStore::initialize(&fresh).unwrap());
    let adapter = |relay: &Relay| {
        RelayMailbox::start(
            relay.addr.clone(),
            relay.incarnation(),
            ACCESS,
            "127.0.0.1:0".parse().unwrap(),
            None,
        )
        .unwrap()
    };
    for wrong in [&same, &other] {
        let alice_wrong = Device::open(&alice.path, adapter(wrong), Clock::System).unwrap();
        assert!(matches!(
            alice_wrong.publish(),
            Err(Error::Mailbox(MailboxError::Mispinned(_)))
        ));
        assert!(
            !alice
                .dev
                .state()
                .unwrap()
                .journal
                .unwrap()
                .publish_attempted
        );
        assert!(matches!(
            alice_wrong.settle(),
            Err(Error::Mailbox(MailboxError::Mispinned(_)))
        ));
        assert!(matches!(
            alice_wrong.audit_accepted(),
            Err(Error::Mailbox(MailboxError::Mispinned(_)))
        ));
        let bob_wrong = Device::open(&bob.path, adapter(wrong), Clock::System).unwrap();
        assert!(matches!(bob_wrong.catch_up().1, Stop::Unavailable(_)));
        let carol_wrong = Device::open(&carol.path, adapter(wrong), Clock::System).unwrap();
        assert!(matches!(
            carol_wrong.complete_join(),
            Err(Error::Mailbox(MailboxError::Mispinned(_)))
        ));
        // Queue operations are pinned the same way: nothing is appended, read or acknowledged.
        assert!(matches!(
            carol_wrong.send_join_request(),
            Err(Error::Mailbox(MailboxError::Mispinned(_)))
        ));
        assert!(
            alice_wrong
                .poll_join_requests()
                .unwrap()
                .iter()
                .all(|p| matches!(p.verdict, Verdict::Unavailable(MailboxError::Mispinned(_))))
        );
        assert_eq!(
            wrong.served.load(Ordering::SeqCst),
            0,
            "nothing reached the wrong relay"
        );
        assert!(alice.dev.state().unwrap().halt.is_none());
        assert!(bob.dev.state().unwrap().halt.is_none());
        assert!(
            carol
                .dev
                .state()
                .unwrap()
                .pending_join
                .unwrap()
                .halted
                .is_none()
        );
    }

    // A client that reaches the relay sharing the incarnation anyway, with every kind of
    // request correctly signed for the pinned relay, is refused there: each proof names the
    // relay it is for.
    let before = same.artifacts();
    let token = InviteToken::decode(&carol_token).unwrap();
    let queue = token.request_queue();
    let issued = alice
        .dev
        .state()
        .unwrap()
        .invites
        .into_iter()
        .find(|i| i.invite_id == carol_invite)
        .unwrap();
    let keys = super::envelope::InviteKeys::from_seeds(&issued.ack_seed, &issued.reply_seed);
    let write = journal_write(&alice);
    let request = b"another request";
    let append = token.prepare_request(request).unwrap();
    let read = keys.read(&n.pin(), queue, 0).unwrap();
    let ack = keys.ack(&n.pin(), queue, [0; 32]).unwrap();
    same.runtime.block_on(async {
        let endpoint = crate::bind_endpoint(
            SecretKey::from_bytes(&random()),
            "127.0.0.1:0".parse().unwrap(),
            None,
            b"massrelay/test-client",
            false,
        )
        .await
        .unwrap();
        let client = Client::connect(&endpoint, same.addr.clone(), &ACCESS)
            .await
            .unwrap();
        let refused = Rejection::WrongRelay;
        assert_eq!(
            client
                .write_prepared(&write.header, &write.bytes)
                .await
                .unwrap(),
            WriteResult::Rejected(refused)
        );
        assert_eq!(
            client.append_prepared(&append, request).await.unwrap(),
            WriteResult::Rejected(refused)
        );
        assert_eq!(
            client.next_item(&read).await.unwrap(),
            NextResult::Rejected(refused)
        );
        assert_eq!(
            client.ack(&ack).await.unwrap(),
            AckResult::Rejected(refused)
        );
        endpoint.close().await;
    });
    assert_eq!(same.artifacts(), before, "nothing reached its store");

    // A normal retry through the right relay then completes.
    assert_eq!(alice.dev.publish().unwrap(), CreateOutcome::Created);
    assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
    assert_eq!(
        alice.dev.dispatch_replies().unwrap(),
        vec![Dispatch::Sent {
            invite_id: carol_invite
        }]
    );
    carol.dev.complete_join().unwrap();
    let (_, stop) = bob.dev.catch_up();
    assert_eq!(stop, Stop::UpToDate);
    agree(&[&alice, &bob, &carol]);
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        let target = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_dir(&path, &target);
        } else if path.file_name().unwrap() != "lock" {
            std::fs::copy(&path, &target).unwrap();
        }
    }
}

/// A joiner who began joining with `token` and handed its request to the relay.
fn begin(n: &Net, token: &[u8], name: &str) -> Member {
    let secret = EndpointSecret::generate();
    let path = n.root.join(name);
    let (dev, _) = Device::begin_join(&path, &secret, token, n.adapter(), Clock::System).unwrap();
    assert_eq!(dev.send_join_request().unwrap(), CreateOutcome::Created);
    Member {
        dev,
        ep: secret.public(),
        path,
    }
}

fn invite_id(token: &[u8]) -> [u8; 16] {
    InviteToken::decode(token).unwrap().invite_id
}

/// Hand an arbitrary item to an invite's request queue, as any holder of the invite can.
fn append_raw(n: &Net, token: &[u8], body: &[u8]) {
    let token = InviteToken::decode(token).unwrap();
    let header = token.prepare_request(body).unwrap();
    let append = super::mailbox::QueueAppend {
        header,
        bytes: body.to_vec(),
    };
    assert_eq!(
        n.adapter().start_append(&n.pin(), append).wait(),
        Ok(CreateOutcome::Created)
    );
}

fn verdicts(polled: &[Polled]) -> Vec<&Verdict> {
    polled.iter().map(|p| &p.verdict).collect()
}

/// A malformed or forged first item neither consumes the invite nor holds up a later valid
/// request, and each item is acknowledged once its verdict is durable.
#[test]
fn an_invalid_first_request_never_consumes_the_invite() {
    let n = Net::new();
    let alice = create(&n, "alice");
    let token = alice.dev.issue_invite().unwrap();
    append_raw(&n, &token, b"not a sealed request");
    let other_invite = InviteToken::decode(&alice.dev.issue_invite().unwrap()).unwrap();
    let foreign = {
        let probe = n.root.join("probe");
        let (_, request) = Device::begin_join(
            &probe,
            &EndpointSecret::generate(),
            &other_invite.encode(),
            n.adapter(),
            Clock::System,
        )
        .unwrap();
        request
    };
    append_raw(&n, &token, &foreign);
    let bob = begin(&n, &token, "bob");

    let polled = alice.dev.poll_join_requests().unwrap();
    let mine: Vec<_> = polled
        .iter()
        .filter(|p| p.invite_id == invite_id(&token))
        .collect();
    assert_eq!(mine.len(), 3, "{polled:?}");
    assert!(matches!(
        mine[0].verdict,
        Verdict::Rejected(AdmissionError::MalformedRequest(_))
    ));
    assert!(matches!(
        mine[1].verdict,
        Verdict::Rejected(AdmissionError::MalformedRequest(_))
    ));
    assert!(matches!(
        mine[2].verdict,
        Verdict::Reserved(ReserveOutcome::Reserved { .. })
    ));
    assert!(
        mine.iter()
            .all(|p| p.ack == AckState::Confirmed(AckOutcome::Recorded))
    );
    // Nothing new on the next poll: progress and acknowledgements are durable.
    assert!(
        alice
            .dev
            .poll_join_requests()
            .unwrap()
            .iter()
            .all(|p| p.invite_id != invite_id(&token))
    );
    admit(&alice, &bob, &invite_id(&token));
    agree(&[&alice, &bob]);
}

/// Two distinct candidates for one invite: the issuer reserves the first valid one it judges,
/// the other is refused, and only the reserved joiner can install the reply.
#[test]
fn two_candidates_racing_for_one_invite_admit_exactly_one() {
    let n = Net::new();
    let alice = create(&n, "alice");
    let token = alice.dev.issue_invite().unwrap();
    let bob = begin(&n, &token, "bob");
    let carol = begin(&n, &token, "carol");
    let polled = alice.dev.poll_join_requests().unwrap();
    assert_eq!(polled.len(), 2, "{polled:?}");
    let reserved = polled
        .iter()
        .filter(|p| {
            matches!(
                p.verdict,
                Verdict::Reserved(ReserveOutcome::Reserved { .. })
            )
        })
        .count();
    let refused = polled
        .iter()
        .filter(|p| matches!(p.verdict, Verdict::Rejected(AdmissionError::AlreadyUsed)))
        .count();
    assert_eq!((reserved, refused), (1, 1));
    let joiner = alice
        .dev
        .state()
        .unwrap()
        .invites
        .iter()
        .find(|i| i.invite_id == invite_id(&token))
        .unwrap()
        .reservation
        .as_ref()
        .unwrap()
        .joiner;
    let (winner, loser) = if joiner == bob.ep {
        (&bob, &carol)
    } else {
        (&carol, &bob)
    };
    admit(&alice, winner, &invite_id(&token));
    assert!(loser.dev.complete_join().is_err());
    assert!(
        loser.dev.state().unwrap().net.is_none(),
        "the loser installs nothing"
    );
    agree(&[&alice, winner]);
}

/// Exact retries are the same item and renew nothing; a late request cannot refresh an
/// expired invite.
#[test]
fn exact_retries_and_late_requests_renew_nothing() {
    let n = Net::new();
    let secret = EndpointSecret::generate();
    let clock = Clock::manual(Clock::System.now());
    let alice = Member {
        dev: Device::create_network(
            &n.root.join("alice"),
            &secret,
            n.relay_key(),
            n.relay.incarnation().to_bytes().to_vec(),
            n.adapter(),
            clock.clone(),
        )
        .unwrap(),
        ep: secret.public(),
        path: n.root.join("alice"),
    };
    let token = alice.dev.issue_invite().unwrap();
    let bob = begin(&n, &token, "bob");
    assert_eq!(
        bob.dev.send_join_request().unwrap(),
        CreateOutcome::ExactRetry
    );
    let polled = alice.dev.poll_join_requests().unwrap();
    assert!(
        matches!(
            verdicts(&polled)[..],
            [Verdict::Reserved(ReserveOutcome::Reserved { .. })]
        ),
        "{polled:?}"
    );
    // A retry after the reservation, over a fresh connection, is still the same item.
    let retry = Device::open(&bob.path, n.adapter(), Clock::System).unwrap();
    assert_eq!(
        retry.send_join_request().unwrap(),
        CreateOutcome::ExactRetry
    );
    assert!(alice.dev.poll_join_requests().unwrap().is_empty());

    // After the window, a first request for another invite is refused, not reserved.
    let late = alice.dev.issue_invite().unwrap();
    if let Clock::Manual(now) = &clock {
        now.fetch_add(super::INVITE_WINDOW_SECS + 1, Ordering::SeqCst);
    }
    let _dana = begin(&n, &late, "dana");
    let polled = alice.dev.poll_join_requests().unwrap();
    assert!(matches!(
        verdicts(&polled)[..],
        [Verdict::Rejected(AdmissionError::Expired { .. })]
    ));
    assert!(
        alice
            .dev
            .state()
            .unwrap()
            .invites
            .iter()
            .find(|i| i.invite_id == invite_id(&late))
            .unwrap()
            .reservation
            .is_none()
    );
}

/// An acknowledgement whose outcome is unknown holds up no other item, and is retried until
/// the relay confirms it.
#[test]
fn unknown_acknowledgements_hold_up_nothing() {
    let n = Net::with_store(|root| SlotStore::initialize_with_failing_acks(root).unwrap());
    let alice = create(&n, "alice");
    let token = alice.dev.issue_invite().unwrap();
    append_raw(&n, &token, b"garbage");
    let _bob = begin(&n, &token, "bob");
    let polled = alice.dev.poll_join_requests().unwrap();
    assert!(
        matches!(
            verdicts(&polled)[..],
            [
                Verdict::Rejected(AdmissionError::MalformedRequest(_)),
                Verdict::Reserved(ReserveOutcome::Reserved { .. }),
                // The suspended store cannot say the queue is empty, so it does not.
                Verdict::Unavailable(MailboxError::StorageUnavailable(_)),
            ]
        ),
        "{polled:?}"
    );
    assert!(
        polled[..2]
            .iter()
            .all(|p| matches!(p.ack, AckState::Unconfirmed(_)))
    );
    let pending = |m: &Member| m.dev.state().unwrap().invites[0].unacked.len();
    assert_eq!(pending(&alice), 2);

    n.relay.restart_store(&n.root.join("scratch"));
    let retried = alice.dev.poll_join_requests().unwrap();
    assert!(
        retried.len() == 2
            && retried
                .iter()
                .all(|p| matches!(p.verdict, Verdict::Retried { .. })
                    && p.ack == AckState::Confirmed(AckOutcome::Recorded)),
        "{retried:?}"
    );
    assert!(alice.dev.poll_join_requests().unwrap().is_empty());
    assert_eq!(
        pending(&alice),
        0,
        "acknowledgements were retried and confirmed"
    );
}

/// Over the real relay, a request item whose stored body is damaged is reported, recorded and
/// acknowledged without consuming the invite, and the valid request behind it is admitted.
#[test]
fn a_damaged_stored_request_blocks_nothing_behind_it() {
    let n = Net::new();
    let alice = create(&n, "alice");
    let token = alice.dev.issue_invite().unwrap();
    let damaged = b"a request the relay will lose";
    append_raw(&n, &token, damaged);
    let queue = InviteToken::decode(&token).unwrap().request_queue().queue;
    let item = super::codec::sha256(damaged);
    crate::slot_store::tamper_item(
        &n.relay.root,
        &queue,
        &item,
        b"A request the relay will lose",
    );
    let _bob = begin(&n, &token, "bob");
    let polled = alice.dev.poll_join_requests().unwrap();
    assert!(
        matches!(
            &polled[..],
            [
                Polled {
                    seq: Some(1),
                    verdict: Verdict::Damaged,
                    ack: AckState::Confirmed(AckOutcome::Recorded),
                    ..
                },
                Polled {
                    seq: Some(2),
                    verdict: Verdict::Reserved(ReserveOutcome::Reserved { .. }),
                    ack: AckState::Confirmed(AckOutcome::Recorded),
                    ..
                },
            ]
        ),
        "{polled:?}"
    );
    let inv = &alice.dev.state().unwrap().invites[0];
    assert!(inv.unacked.is_empty() && inv.queue_cursor == 2);
    assert!(alice.dev.poll_join_requests().unwrap().is_empty());
}

/// A reply object already holding other bytes conflicts for that entry only.
#[test]
fn an_occupied_reply_is_isolated_to_its_entry() {
    let n = Net::new();
    let alice = create(&n, "alice");
    let bob_token = alice.dev.issue_invite().unwrap();
    let bob = begin(&n, &bob_token, "bob");
    let carol_token = alice.dev.issue_invite().unwrap();
    let carol = begin(&n, &carol_token, "carol");
    assert_eq!(alice.dev.poll_join_requests().unwrap().len(), 2);
    for token in [&bob_token, &carol_token] {
        alice.dev.stage_add(&invite_id(token)).unwrap();
        assert_eq!(alice.dev.publish().unwrap(), CreateOutcome::Created);
        assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
    }
    // The issuer's own reply key already wrote other bytes for Bob's invite.
    let seed = alice
        .dev
        .state()
        .unwrap()
        .invites
        .iter()
        .find(|i| i.invite_id == invite_id(&bob_token))
        .unwrap()
        .reply_seed;
    let header = super::envelope::reply_header(&seed, &n.pin(), b"stale reply").unwrap();
    let stale = SlotWrite {
        header,
        bytes: b"stale reply".to_vec(),
    };
    assert_eq!(
        n.adapter().start_put_reply(&n.pin(), stale).wait(),
        Ok(CreateOutcome::Created)
    );
    let dispatched = alice.dev.dispatch_replies().unwrap();
    assert!(dispatched.contains(&Dispatch::Conflicted {
        invite_id: invite_id(&bob_token)
    }));
    assert!(dispatched.contains(&Dispatch::Sent {
        invite_id: invite_id(&carol_token)
    }));
    assert!(bob.dev.complete_join().is_err());
    carol.dev.complete_join().unwrap();
    let (_, stop) = carol.dev.catch_up();
    assert_eq!(stop, Stop::UpToDate);
}

/// Wait, without a fixed sleep, until the relay holds at least `n` request streams.
fn until_held(n: &Net, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while n.relay.held.load(Ordering::SeqCst) < count {
        assert!(
            Instant::now() < deadline,
            "no request reached the held relay"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Shutting the adapter down wakes a write stalled on a real loopback relay connection as
/// unknown delivery, never a refusal, and every later call sends nothing.
#[test]
fn adapter_shutdown_wakes_a_stalled_write_as_unknown_and_sends_nothing_after() {
    let n = Net::new();
    let alice = create(&n, "alice");
    let (_carol, invite, _) = request_join(&n, &alice, "carol");
    alice.dev.stage_add(&invite).unwrap();
    let write = journal_write(&alice);
    let adapter = n.adapter();
    n.relay.hold();
    let started = adapter.start_create_slot(&n.pin(), write.clone());
    until_held(&n, 1);
    adapter.shutdown();
    // Bounded, so a shutdown that wakes nothing fails here instead of hanging.
    let (woken, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || woken.send(started.wait()));
    let outcome = outcome.recv_timeout(Duration::from_secs(20));
    if outcome.is_err() {
        n.relay.release();
    }
    assert!(
        matches!(outcome, Ok(Err(MailboxError::Uncertain(_)))),
        "a write in flight is woken as possibly delivered: {outcome:?}"
    );
    let served = n.relay.served.load(Ordering::SeqCst);
    assert!(matches!(
        adapter.start_create_slot(&n.pin(), write.clone()).wait(),
        Err(MailboxError::NotStored(_))
    ));
    assert!(matches!(
        adapter.read_slot(&n.pin(), &write.slot()),
        Err(MailboxError::Uncertain(_))
    ));
    n.relay.release();
    assert_eq!(
        n.relay.served.load(Ordering::SeqCst),
        served,
        "nothing reached the relay after shutdown"
    );
    // The exact write is still the device's to resend: a fresh adapter completes it.
    assert!(matches!(
        n.adapter().start_create_slot(&n.pin(), write).wait(),
        Ok(CreateOutcome::Created | CreateOutcome::ExactRetry)
    ));
}

/// Stopping the runtime while its membership pass is stalled on a real loopback relay
/// connection wakes that call and releases the owner, so the profile can be reopened at once.
#[test]
fn runtime_stop_releases_the_owner_while_the_relay_stalls() {
    use super::pairing::Owner;
    use super::runtime::{Config, Runtime};
    use super::service::SERVICE_ALPN;

    let n = Net::new();
    let secret = EndpointSecret::generate();
    let path = n.root.join("alice");
    let alice = Device::create_network(
        &path,
        &secret,
        n.relay_key(),
        n.relay.incarnation().to_bytes().to_vec(),
        n.adapter(),
        Clock::System,
    )
    .unwrap();
    // One invite, so the pass has a queue to read.
    alice.issue_invite().unwrap();
    drop(alice);
    let adapter = n.adapter();
    n.relay.hold();
    let device_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let stopped = device_runtime.block_on(async {
        let endpoint = crate::bind_endpoint(
            SecretKey::from_bytes(&secret.to_bytes()),
            "127.0.0.1:0".parse().unwrap(),
            None,
            SERVICE_ALPN,
            false,
        )
        .await
        .unwrap();
        let mut config = Config::new(&path);
        config.sync_every = Some(Duration::from_millis(50));
        let runtime = Runtime::start(config, adapter, Clock::System, endpoint)
            .await
            .unwrap();
        tokio::task::block_in_place(|| until_held(&n, 1));
        runtime.stop().await
    });
    // Released before asserting, so a call left blocked cannot hang the test.
    n.relay.release();
    assert!(stopped.owner_released, "{stopped:?}");
    assert!(stopped.aborted.is_empty(), "{stopped:?}");
    assert!(Owner::acquire(&path).is_ok(), "the owner lock was released");
}
