//! End-to-end local contract tests for private membership and admission,
//! using the file-backed fake mailbox. Every key is throwaway and every
//! adversarial input is deterministic local data.

use std::path::{Path, PathBuf};
use std::process::Command;

use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use openmls_traits::types::SignatureScheme;

use super::CIPHERSUITE;
use super::binding::{CredentialBinding, EndpointKey, EndpointSecret, JoinTranscript};
use super::codec::{Dec, Enc, random, sha256};
use super::envelope::{InviteToken, JoinRequest, Reply};
use super::fake_mailbox::{FsMailbox, Scripted};
use super::fault;
use super::mailbox::{AckOutcome, CreateOutcome, Mailbox, MailboxError, SlotWrite};
use super::membership::Error;
use super::membership::*;
use super::store::Store;

const T0: u64 = 1_700_000_000;

/// Exercise the same valid synthetic attestations that intermittently failed on the Linux
/// development host. Release-mode runs repeat the exact inputs on each native CI runner.
#[test]
fn verifies_captured_synthetic_binding_signatures() {
    use super::binding::verify_ed25519;
    use super::codec::unhex;
    use std::hint::black_box;

    let repetitions = if cfg!(debug_assertions) { 1 } else { 20_000 };
    let fixtures = include_str!("../../tests/fixtures/private-binding-signatures.txt");
    for (index, row) in fixtures.lines().enumerate() {
        let fields: Vec<_> = row
            .split_whitespace()
            .map(|part| unhex(part).unwrap())
            .collect();
        let [key, message, signature] = fields.as_slice() else {
            panic!("unexpected fixture format");
        };
        for iteration in 0..repetitions {
            assert!(
                verify_ed25519(black_box(key), black_box(message), black_box(signature)).is_ok(),
                "synthetic signature {index} was rejected at iteration {iteration}"
            );
        }
        let mut changed = message.clone();
        changed[0] ^= 1;
        assert!(verify_ed25519(key, &changed, signature).is_err());
    }
}

struct Net {
    _root: tempfile::TempDir,
    root: PathBuf,
    mailbox: FsMailbox,
    relay_key: [u8; 32],
}

fn net() -> Net {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_path_buf();
    let mailbox = FsMailbox::create(&path.join("relay"));
    let relay_key = mailbox.relay_key;
    Net {
        _root: root,
        root: path,
        mailbox,
        relay_key,
    }
}

fn dir(n: &Net, name: &str) -> PathBuf {
    n.root.join(name)
}

struct Member {
    dev: Device<FsMailbox>,
    secret: EndpointSecret,
    ep: EndpointKey,
    clock: Clock,
    path: PathBuf,
}

impl Member {
    fn state(&self) -> State {
        self.dev.state().unwrap()
    }
    fn head(&self) -> [u8; 32] {
        self.state().net.unwrap().head
    }
    fn reopen(&self, n: &Net) -> Device<FsMailbox> {
        Device::open(&self.path, n.mailbox.clone(), self.clock.clone()).unwrap()
    }
}

fn create(n: &Net, name: &str, clock: Clock) -> Member {
    let secret = EndpointSecret::generate();
    let path = dir(n, name);
    let dev = Device::create_network(
        &path,
        &secret,
        n.relay_key,
        n.mailbox.incarnation.clone(),
        n.mailbox.clone(),
        clock.clone(),
    )
    .unwrap();
    Member {
        dev,
        ep: secret.public(),
        secret,
        clock,
        path,
    }
}

struct Pending {
    m: Member,
    invite_id: [u8; 16],
    token: Vec<u8>,
    request: Vec<u8>,
}

fn begin(n: &Net, token: &[u8], name: &str, clock: Clock) -> Pending {
    let secret = EndpointSecret::generate();
    let path = dir(n, name);
    let (dev, request) =
        Device::begin_join(&path, &secret, token, n.mailbox.clone(), clock.clone()).unwrap();
    let invite_id = InviteToken::decode(token).unwrap().invite_id;
    Pending {
        m: Member {
            dev,
            ep: secret.public(),
            secret,
            clock,
            path,
        },
        invite_id,
        token: token.to_vec(),
        request,
    }
}

fn request_join(n: &Net, issuer: &Member, name: &str, clock: Clock) -> Pending {
    let token = issuer.dev.issue_invite().unwrap();
    let p = begin(n, &token, name, clock);
    assert!(matches!(
        issuer
            .dev
            .receive_join_request(&p.invite_id, &p.request)
            .unwrap(),
        ReserveOutcome::Reserved { .. }
    ));
    p
}

/// Stage, publish, settle and dispatch an Add for a reserved invite.
fn admit(issuer: &Member, p: &Pending) {
    issuer.dev.stage_add(&p.invite_id).unwrap();
    assert_eq!(issuer.dev.publish().unwrap(), CreateOutcome::Created);
    assert_eq!(issuer.dev.settle().unwrap(), Settle::Accepted);
    assert_eq!(
        issuer.dev.dispatch_replies().unwrap(),
        vec![Dispatch::Sent {
            invite_id: p.invite_id
        }]
    );
    p.m.dev.complete_join().unwrap();
}

fn join(n: &Net, issuer: &Member, name: &str, clock: Clock) -> Member {
    let p = request_join(n, issuer, name, clock);
    admit(issuer, &p);
    p.m
}

fn sync(ms: &[&Member]) {
    for m in ms {
        let (_, stop) = m.dev.catch_up();
        assert_eq!(stop, Stop::UpToDate, "catch-up stopped");
    }
}

fn agree(ms: &[&Member]) {
    let f0 = ms[0].dev.group_fingerprint().unwrap();
    let h0 = ms[0].head();
    let r0 = ms[0].dev.roster().unwrap();
    for m in &ms[1..] {
        assert_eq!(
            m.dev.group_fingerprint().unwrap(),
            f0,
            "group context / epoch authenticator differ"
        );
        assert_eq!(m.head(), h0, "accepted heads differ");
        assert_eq!(m.dev.roster().unwrap(), r0, "rosters differ");
    }
}

fn mls_files(m: &Member) -> Vec<String> {
    let g = m.dev.store().lock().unwrap();
    m.dev.store().mls_files(&g).unwrap()
}

fn accepted_file_digest(m: &Member) -> [u8; 32] {
    let f = m.state().net.unwrap().mls_file;
    sha256(&std::fs::read(m.dev.store().mls_path(&f)).unwrap())
}

/// Build a join request outside `Device::begin_join`, with a chosen
/// KeyPackage lifetime and optionally a binding signed by another key.
fn custom_request(
    tmp: &Path,
    token: &InviteToken,
    ep: &EndpointSecret,
    lifetime: Lifetime,
    forge_binding_with: Option<&EndpointSecret>,
) -> JoinRequest {
    let (store, g) = Store::create(tmp, &0u8).unwrap();
    let f = store.new_mls_file(&g, "kp").unwrap();
    let (kp, kp_ref) = store
        .with_mls(&g, &f, true, |p, _| {
            let s = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
            s.store(p.storage()).unwrap();
            let mut binding = CredentialBinding::create(
                forge_binding_with.unwrap_or(ep),
                &token.group_tag,
                s.public(),
            );
            binding.endpoint = ep.public();
            let cred = CredentialWithKey {
                credential: binding.credential(),
                signature_key: s.public().into(),
            };
            let b = KeyPackage::builder()
                .key_package_lifetime(lifetime)
                .build(CIPHERSUITE, p, &s, cred)
                .unwrap();
            let kp = b.key_package();
            Ok::<_, super::store::StoreError>((
                kp.tls_serialize_detached().unwrap(),
                kp.hash_ref(p.crypto()).unwrap().as_slice().to_vec(),
            ))
        })
        .unwrap();
    let transcript = JoinTranscript {
        group_tag: token.group_tag,
        relay_key: token.relay_key,
        incarnation: token.incarnation.clone(),
        issuer_endpoint: token.issuer_endpoint,
        issuer_mls_key: token.issuer_mls_key.clone(),
        invite_id: token.invite_id,
        joiner_endpoint: ep.public(),
        key_package_ref: kp_ref,
        request_nonce: random(),
    };
    let proof = transcript.sign(ep);
    JoinRequest {
        transcript,
        proof,
        key_package: kp,
    }
}

/// An adversarial issuer writes its journaled bytes directly, bypassing the
/// honest publication checks.
fn force_publish(m: &Member, n: &Net) {
    let j = m.state().journal.unwrap();
    let w = SlotWrite {
        header: j.write_header(&n.mailbox.pin()).unwrap(),
        bytes: j.slot_bytes.clone(),
    };
    assert_eq!(
        n.mailbox.write_slot_now(&w).unwrap(),
        CreateOutcome::Created
    );
}

/// A member's MLS signer, read from its accepted MLS file (test fixtures
/// that re-sign receipts as the genuine issuer).
fn mls_signer(m: &Member) -> SignatureKeyPair {
    let netw = m.state().net.unwrap();
    let g = m.dev.store().lock().unwrap();
    m.dev
        .store()
        .with_mls(&g, &netw.mls_file, false, |p, _| {
            Ok::<_, super::store::StoreError>(
                SignatureKeyPair::read(p.storage(), &netw.mls_key, SignatureScheme::ED25519)
                    .unwrap(),
            )
        })
        .unwrap()
}

fn rejected_class(stop: &Stop) -> (RejectClass, String) {
    match stop {
        Stop::Halted(Halt::Rejected { class, reason, .. }) => (*class, reason.clone()),
        other => panic!("expected a rejected slot, got {other:?}"),
    }
}

// ------------------------------------------------------------------ tests

#[test]
fn end_to_end_create_invite_join_and_catch_up() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    agree(&[&alice, &bob]);
    // Bob issues Carol's invite; Alice catches up through Bob's Add.
    let carol = join(&n, &bob, "carol", Clock::System);
    let (applied, stop) = alice.dev.catch_up();
    assert_eq!(stop, Stop::UpToDate);
    assert_eq!(
        applied,
        vec![Advance::Advanced {
            epoch: 2,
            author_leaf: 1,
            op: OpSummary::Add { joiner: carol.ep }
        }]
    );
    agree(&[&alice, &bob, &carol]);
    let mut eps = vec![alice.ep, bob.ep, carol.ep];
    eps.sort();
    assert_eq!(alice.dev.roster().unwrap(), eps);
    assert_eq!(alice.state().net.unwrap().accepted.len(), 2);
    assert_eq!(
        carol.state().net.unwrap().accepted.len(),
        1,
        "joiner pins its admission checkpoint"
    );

    // Relay-visible bytes carry no group id, endpoint keys, MLS keys or
    // KeyPackage references.
    let a = alice.state().net.unwrap();
    let mut secrets: Vec<Vec<u8>> =
        vec![a.group_id.clone(), a.group_tag.to_vec(), a.mls_key.clone()];
    for m in [&alice, &bob, &carol] {
        secrets.push(m.ep.to_vec());
        secrets.push(m.state().net.unwrap().mls_key);
    }
    let mut visible = n.mailbox.all_slots();
    for e in std::fs::read_dir(n.root.join("relay/replies")).unwrap() {
        visible.push(std::fs::read(e.unwrap().path()).unwrap());
    }
    for v in &visible {
        for s in &secrets {
            assert!(
                !v.windows(s.len()).any(|w| w == s.as_slice()),
                "relay-visible bytes contain a private field"
            );
        }
    }
}

#[test]
fn reservation_window_clock_and_exact_retry() {
    let n = net();
    let clock = Clock::manual(T0);
    let alice = create(&n, "alice", clock.clone());
    let token = alice.dev.issue_invite().unwrap();
    let bob = begin(&n, &token, "bob", clock.clone());
    clock.set(T0 + 10);
    assert_eq!(
        alice
            .dev
            .receive_join_request(&bob.invite_id, &bob.request)
            .unwrap(),
        ReserveOutcome::Reserved {
            reserved_at: T0 + 10
        }
    );
    // Exact retransmit after expiry: same identity, nothing renewed.
    clock.set(T0 + 700);
    assert_eq!(
        bob.m.dev.join_request().unwrap(),
        bob.request,
        "joiner retransmits exact bytes"
    );
    assert_eq!(
        alice
            .dev
            .receive_join_request(&bob.invite_id, &bob.request)
            .unwrap(),
        ReserveOutcome::ExactRetry {
            reserved_at: T0 + 10
        }
    );
    let inv = alice
        .state()
        .invites
        .into_iter()
        .find(|i| i.invite_id == bob.invite_id)
        .unwrap();
    assert_eq!((inv.not_before, inv.expires_at), (T0, T0 + 600));
    // A different request for the consumed invite.
    let mallory = begin(&n, &token, "mallory", clock.clone());
    assert_eq!(
        alice
            .dev
            .receive_join_request(&mallory.invite_id, &mallory.request),
        Err(Error::Admission(AdmissionError::AlreadyUsed))
    );

    // Late first reservation, then rollback.
    let token2 = alice.dev.issue_invite().unwrap();
    clock.set(T0 + 1400);
    let dana = begin(&n, &token2, "dana", clock.clone());
    assert_eq!(
        alice
            .dev
            .receive_join_request(&dana.invite_id, &dana.request),
        Err(Error::Admission(AdmissionError::Expired {
            now: T0 + 1400,
            expires_at: T0 + 1300
        }))
    );
    // The rejected operation's clock observation persisted.
    assert_eq!(alice.state().clock_high_water, T0 + 1400);
    clock.set(T0 + 800);
    assert_eq!(
        alice
            .dev
            .receive_join_request(&dana.invite_id, &dana.request),
        Err(Error::Admission(AdmissionError::ClockRollback {
            now: T0 + 800,
            high_water: T0 + 1400
        }))
    );
    assert!(matches!(
        alice.dev.issue_invite(),
        Err(Error::Admission(AdmissionError::ClockRollback { .. }))
    ));
    assert!(matches!(
        alice.dev.stage_add(&bob.invite_id),
        Err(Error::Admission(AdmissionError::ClockRollback { .. }))
    ));
    // Revocation does not depend on time and is not blocked by rollback.
    let removal = alice
        .dev
        .revoke(&EndpointSecret::generate().public())
        .unwrap();
    assert!(removal.local_cutoff);
    assert!(removal.removal.unwrap_err().contains("not a member"));
    // Exact retries still answer during rollback, without renewal.
    assert_eq!(
        alice
            .dev
            .receive_join_request(&bob.invite_id, &bob.request)
            .unwrap(),
        ReserveOutcome::ExactRetry {
            reserved_at: T0 + 10
        }
    );
    // A tolerated step back uses the high-water mark: no reopened window.
    clock.set(T0 + 1397);
    assert_eq!(
        alice
            .dev
            .receive_join_request(&dana.invite_id, &dana.request),
        Err(Error::Admission(AdmissionError::Expired {
            now: T0 + 1400,
            expires_at: T0 + 1300
        }))
    );
    // The lower invite bound is enforced as well.
    let token3 = alice.dev.issue_invite().unwrap();
    let erin = begin(&n, &token3, "erin", clock.clone());
    {
        let g = alice.dev.store().lock().unwrap();
        alice
            .dev
            .store()
            .update(&g, |st: &mut State| {
                let i = st
                    .invites
                    .iter_mut()
                    .find(|i| i.invite_id == erin.invite_id)
                    .unwrap();
                i.not_before = T0 + 2000;
                i.expires_at = T0 + 2600;
                Ok::<_, Error>(())
            })
            .unwrap();
    }
    assert_eq!(
        alice
            .dev
            .receive_join_request(&erin.invite_id, &erin.request),
        Err(Error::Admission(AdmissionError::NotYetValid {
            now: T0 + 1400,
            not_before: T0 + 2000
        }))
    );
    // Forward again: the reserved operation completes after its window.
    clock.set(T0 + 1500);
    admit(&alice, &bob);
    agree(&[&alice, &bob.m]);
    assert_eq!(
        alice
            .dev
            .receive_join_request(&bob.invite_id, &bob.request)
            .unwrap(),
        ReserveOutcome::AlreadyAdmitted {
            reserved_at: T0 + 10
        }
    );
    assert_eq!(
        alice.dev.stage_add(&bob.invite_id),
        Err(Error::Admission(AdmissionError::AlreadyAdmitted))
    );
}

#[test]
fn malicious_requests_do_not_consume_the_invite() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let token_bytes = alice.dev.issue_invite().unwrap();
    let token = InviteToken::decode(&token_bytes).unwrap();
    let other = InviteToken::decode(&alice.dev.issue_invite().unwrap()).unwrap();
    let bob = begin(&n, &token_bytes, "bob", Clock::System);
    let genuine = token.open_request(&bob.request).unwrap();
    let id = token.invite_id;
    let try_req = |r: &JoinRequest| alice.dev.receive_join_request(&id, &token.seal_request(r));

    assert!(matches!(
        alice.dev.receive_join_request(&id, b"garbage"),
        Err(Error::Admission(AdmissionError::MalformedRequest(_)))
    ));
    // Sealed under another invite's secret.
    assert!(matches!(
        alice
            .dev
            .receive_join_request(&id, &other.seal_request(&genuine)),
        Err(Error::Admission(AdmissionError::MalformedRequest(_)))
    ));
    // Proof by a key other than the claimed endpoint.
    let mallory = EndpointSecret::generate();
    let mut t = genuine.transcript.clone();
    t.joiner_endpoint = mallory.public();
    let mallory_proof = t.sign(&mallory);
    let r = JoinRequest {
        proof: mallory_proof,
        ..genuine.clone()
    };
    assert!(matches!(
        try_req(&r),
        Err(Error::Admission(AdmissionError::ProofInvalid(_)))
    ));
    // Endpoint swap: valid proof by Mallory, KeyPackage bound to Bob.
    let r = JoinRequest {
        transcript: t.clone(),
        proof: t.sign(&mallory),
        ..genuine.clone()
    };
    assert!(matches!(
        try_req(&r),
        Err(Error::Admission(AdmissionError::BindingInvalid(_)))
    ));
    // Transcript names another KeyPackage.
    let mut t2 = genuine.transcript.clone();
    t2.key_package_ref = vec![7; 32];
    let r = JoinRequest {
        transcript: t2.clone(),
        proof: t2.sign(&bob.m.secret),
        ..genuine.clone()
    };
    assert!(matches!(
        try_req(&r),
        Err(Error::Admission(AdmissionError::InviteMismatch(_)))
    ));
    // Transcript names another group.
    let mut t3 = genuine.transcript.clone();
    t3.group_tag = random();
    let r = JoinRequest {
        transcript: t3.clone(),
        proof: t3.sign(&bob.m.secret),
        ..genuine.clone()
    };
    assert!(matches!(
        try_req(&r),
        Err(Error::Admission(AdmissionError::InviteMismatch(_)))
    ));
    // Forged cross-device credential binding (signed by another endpoint).
    let carol = EndpointSecret::generate();
    let forged = custom_request(
        &n.root.join("forge"),
        &token,
        &carol,
        Lifetime::new(3600),
        Some(&mallory),
    );
    assert!(matches!(
        try_req(&forged),
        Err(Error::Admission(AdmissionError::BindingInvalid(_)))
    ));
    // Lifetime beyond the cap.
    let long = custom_request(
        &n.root.join("long"),
        &token,
        &carol,
        Lifetime::new(30 * 24 * 3600),
        None,
    );
    assert_eq!(
        try_req(&long),
        Err(Error::Admission(AdmissionError::KeyPackageLifetimeTooLong))
    );

    // None of these consumed the invite.
    assert!(
        alice
            .state()
            .invites
            .iter()
            .all(|i| i.reservation.is_none())
    );
    assert!(matches!(
        alice.dev.receive_join_request(&id, &bob.request).unwrap(),
        ReserveOutcome::Reserved { .. }
    ));
    admit(&alice, &bob);
    agree(&[&alice, &bob.m]);
}

#[test]
fn key_package_live_checks_and_resume_after_expiry() {
    let n = net();
    let clock = Clock::manual(T0);
    let alice = create(&n, "alice", clock.clone());
    let bob = request_join(&n, &alice, "bob", clock.clone());
    clock.set(T0 + 20);
    let carol = request_join(&n, &alice, "carol", clock.clone());
    clock.set(T0 + 40);
    alice.dev.stage_add(&carol.invite_id).unwrap();
    // Far past both KeyPackages' lifetimes and both invite windows.
    clock.set(T0 + 30 * 24 * 3600);
    assert_eq!(alice.dev.publish().unwrap(), CreateOutcome::Created);
    assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
    assert_eq!(
        alice.dev.dispatch_replies().unwrap(),
        vec![Dispatch::Sent {
            invite_id: carol.invite_id
        }]
    );
    carol.m.dev.complete_join().unwrap();
    agree(&[&alice, &carol.m]);
    // A fresh stage needs a KeyPackage valid now.
    let before = mls_files(&alice);
    assert!(matches!(
        alice.dev.stage_add(&bob.invite_id),
        Err(Error::Admission(AdmissionError::KeyPackageExpired(_)))
    ));
    assert!(alice.state().journal.is_none());
    assert_eq!(mls_files(&alice), before, "no candidate left behind");
    assert_eq!(
        alice
            .dev
            .receive_join_request(&bob.invite_id, &bob.request)
            .unwrap(),
        ReserveOutcome::ExactRetry { reserved_at: T0 }
    );
}

#[test]
fn competing_writers_loser_adopts_winner_and_restages() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    let dana = request_join(&n, &bob, "dana", Clock::System);
    let a_before = accepted_file_digest(&alice);
    alice.dev.stage_add(&carol.invite_id).unwrap();
    bob.dev.stage_add(&dana.invite_id).unwrap();
    assert_eq!(
        accepted_file_digest(&alice),
        a_before,
        "staging never touches the accepted MLS file"
    );
    let loser_bytes = alice.state().journal.unwrap().slot_bytes;
    assert_eq!(bob.dev.publish().unwrap(), CreateOutcome::Created);
    assert_eq!(alice.dev.publish().unwrap(), CreateOutcome::Conflict);
    assert_eq!(bob.dev.publish().unwrap(), CreateOutcome::ExactRetry);
    assert_eq!(bob.dev.settle().unwrap(), Settle::Accepted);
    assert_eq!(
        alice.dev.settle().unwrap(),
        Settle::Lost {
            winner: Advance::Advanced {
                epoch: 2,
                author_leaf: 1,
                op: OpSummary::Add { joiner: dana.m.ep }
            }
        }
    );
    let st = alice.state();
    assert!(st.journal.is_none());
    assert!(
        st.outbox
            .iter()
            .all(|o| o.reply.invite_id != carol.invite_id),
        "the loser's Welcome is never queued"
    );
    assert_eq!(st.stats.discarded, vec![sha256(&loser_bytes)]);
    assert_eq!(mls_files(&alice).len(), 1, "loser candidate deleted");
    let inv = st
        .invites
        .iter()
        .find(|i| i.invite_id == carol.invite_id)
        .unwrap();
    assert!(
        inv.reservation.is_some() && inv.admitted_slot.is_none(),
        "reservation kept"
    );
    assert_eq!(bob.dev.dispatch_replies().unwrap().len(), 1);
    dana.m.dev.complete_join().unwrap();
    // Restage on the new parent and win.
    admit(&alice, &carol);
    sync(&[&bob, &dana.m]);
    agree(&[&alice, &bob, &carol.m, &dana.m]);
    // Every candidate, winning or losing, used a fresh salt and nonce.
    let mut records = n.mailbox.all_slots();
    records.push(loser_bytes);
    let pairs: Vec<_> = records
        .iter()
        .map(|b| record_salt_nonce(b).unwrap())
        .collect();
    for (i, a) in pairs.iter().enumerate() {
        for b in &pairs[i + 1..] {
            assert_ne!(a.0, b.0, "candidate salt reused");
            assert_ne!(a.1, b.1, "nonce reused");
        }
    }
}

// --------------------------------------------------- crash and recovery

const CRASH_ENV: &str = "MR_PRIVATE_CRASH_ROOT";

/// Child half of the crash tests: drives Alice's admission of the reserved
/// invite until `MR_PRIVATE_CRASH_AT` aborts the process.
#[test]
fn crash_child() {
    let Ok(root) = std::env::var(CRASH_ENV) else {
        return;
    };
    let root = PathBuf::from(root);
    let mailbox = FsMailbox::create(&root.join("relay"));
    let alice = Device::open(&root.join("alice"), mailbox, Clock::System).unwrap();
    let id: [u8; 16] = std::fs::read(root.join("invite_id"))
        .unwrap()
        .try_into()
        .unwrap();
    alice.stage_add(&id).unwrap();
    alice.publish().unwrap();
    alice.settle().unwrap();
    alice.dispatch_replies().unwrap();
    // The crash point must have fired.
    std::process::exit(3);
}

fn run_child(root: &Path, point: &str) {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "private::tests::crash_child",
            "--exact",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CRASH_ENV, root)
        .env("MR_PRIVATE_CRASH_AT", point)
        .output()
        .unwrap();
    assert!(!status.status.success(), "child did not abort at {point}");
    assert_ne!(
        status.status.code(),
        Some(3),
        "crash point {point} never fired"
    );
}

fn crash_setup(name: &str) -> (Net, Member, Pending) {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = request_join(&n, &alice, name, Clock::System);
    std::fs::write(n.root.join("invite_id"), bob.invite_id).unwrap();
    (n, alice, bob)
}

/// Drive a recovered Alice to a dispatched admission.
fn finish(alice: &Device<FsMailbox>, invite_id: &[u8; 16]) {
    let st = alice.state().unwrap();
    let inv = st
        .invites
        .iter()
        .find(|i| &i.invite_id == invite_id)
        .unwrap();
    if st.journal.is_none() && inv.admitted_slot.is_none() {
        alice.stage_add(invite_id).unwrap();
    }
    loop {
        match alice.settle().unwrap() {
            Settle::NoCandidate => break,
            Settle::Accepted => break,
            Settle::NotPublished | Settle::Pending => {
                let o = alice.publish().unwrap();
                assert!(matches!(
                    o,
                    CreateOutcome::Created | CreateOutcome::ExactRetry
                ));
            }
            other => panic!("unexpected settle {other:?}"),
        }
    }
    alice.dispatch_replies().unwrap();
}

#[test]
fn crash_restart_merges_exactly_once() {
    for point in [
        "after_candidate_written",
        "after_journal",
        "after_publish_marked",
        "after_slot_write",
        "after_promote",
        "after_dispatch_marked",
        "after_reply_put",
    ] {
        let (n, alice, bob) = crash_setup("bob");
        run_child(&n.root, point);
        let a = alice.reopen(&n);
        let rec = a.recover().unwrap();
        match point {
            "after_candidate_written" => {
                assert_eq!(rec.swept.len(), 1, "{point}: orphan candidate swept")
            }
            "after_promote" => assert_eq!(rec.swept.len(), 1, "{point}: superseded epoch swept"),
            _ => assert!(rec.swept.is_empty(), "{point}: {rec:?}"),
        }
        finish(&a, &bob.invite_id);
        let st = a.state().unwrap();
        assert_eq!(st.stats.own_merges, 1, "{point}: merged exactly once");
        assert_eq!(st.net.as_ref().unwrap().epoch, 1, "{point}");
        assert!(matches!(st.outbox[0].status, OutboxStatus::Sent), "{point}");
        assert_eq!(
            mls_files(&alice).len(),
            1,
            "{point}: only the accepted epoch remains"
        );
        bob.m.dev.complete_join().unwrap();
        agree(&[&alice, &bob.m]);
        // A second recovery is a no-op.
        assert_eq!(a.recover().unwrap(), Recovered::default(), "{point}");
        assert_eq!(a.dispatch_replies().unwrap(), vec![], "{point}");
    }
}

#[test]
fn learned_cutoff_withholds_recovered_welcome() {
    for (point, possibly_sent) in [("after_promote", false), ("after_dispatch_marked", true)] {
        let (n, alice, bob) = crash_setup("bob");
        run_child(&n.root, point);
        let a = alice.reopen(&n);
        // A cutoff learned after the crash, before dispatch resumes.
        let out = a.revoke(&bob.m.ep).unwrap();
        assert!(out.local_cutoff);
        a.recover().unwrap();
        let d = a.dispatch_replies().unwrap();
        assert_eq!(
            d,
            vec![Dispatch::Withheld {
                invite_id: bob.invite_id,
                reason: "joiner is locally cut off".into(),
                possibly_sent
            }],
            "{point}"
        );
        assert!(
            !n.mailbox
                .reply_exists(&InviteToken::decode(&bob.token).unwrap().reply_box()),
            "{point}"
        );
        assert_eq!(
            bob.m.dev.complete_join(),
            Err(Error::Join(JoinError::Waiting))
        );
    }
}

#[test]
fn remote_removal_withholds_pending_welcome() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let dave = join(&n, &alice, "dave", Clock::System);
    let bob = request_join(&n, &alice, "bob", Clock::System);
    alice.dev.stage_add(&bob.invite_id).unwrap();
    alice.dev.publish().unwrap();
    assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
    // Dave learns the Add and removes Bob before Alice dispatches.
    sync(&[&dave]);
    let slot = dave.dev.stage_remove(&bob.m.ep).unwrap();
    dave.dev.publish().unwrap();
    assert_eq!(dave.dev.settle().unwrap(), Settle::Accepted);
    let (applied, _) = alice.dev.catch_up();
    assert_eq!(
        applied,
        vec![Advance::Advanced {
            epoch: 3,
            author_leaf: 1,
            op: OpSummary::Remove { subject: bob.m.ep }
        }]
    );
    assert!(
        alice
            .state()
            .net
            .unwrap()
            .accepted
            .iter()
            .any(|a| a.slot == slot)
    );
    assert_eq!(
        alice.dev.dispatch_replies().unwrap(),
        vec![Dispatch::Withheld {
            invite_id: bob.invite_id,
            reason: "joiner was removed".into(),
            possibly_sent: false
        }]
    );
    agree(&[&alice, &dave]);
}

#[test]
fn concurrent_local_writes_and_catch_up_serialize() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    // Three reserved admissions to run, twelve requests to reserve meanwhile.
    let admits: Vec<Pending> = (0..3)
        .map(|i| request_join(&n, &alice, &format!("a{i}"), Clock::System))
        .collect();
    let mut queued = vec![];
    for i in 0..12 {
        let token = alice.dev.issue_invite().unwrap();
        queued.push(begin(&n, &token, &format!("q{i}"), Clock::System));
    }
    let a2 = alice.reopen(&n);
    let reqs: Vec<([u8; 16], Vec<u8>)> = queued
        .iter()
        .map(|p| (p.invite_id, p.request.clone()))
        .collect();
    std::thread::scope(|s| {
        s.spawn(|| {
            for (id, r) in &reqs {
                assert!(matches!(
                    a2.receive_join_request(id, r).unwrap(),
                    ReserveOutcome::Reserved { .. }
                ));
            }
        });
        s.spawn(|| {
            for p in &admits {
                alice.dev.stage_add(&p.invite_id).unwrap();
                alice.dev.publish().unwrap();
                assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
            }
        });
    });
    let st = alice.state();
    assert_eq!(
        st.invites
            .iter()
            .filter(|i| i.reservation.is_some())
            .count(),
        16,
        "no reservation lost"
    );
    assert_eq!(
        st.stats.own_merges, 4,
        "Bob plus three concurrent admissions"
    );
    assert_eq!(st.net.as_ref().unwrap().epoch, 4);
    // Two handles of one profile catch up concurrently.
    let b2 = bob.reopen(&n);
    let (r1, r2) = std::thread::scope(|s| {
        let h1 = s.spawn(|| bob.dev.catch_up());
        let h2 = s.spawn(|| b2.catch_up());
        (h1.join().unwrap(), h2.join().unwrap())
    });
    assert_eq!(r1.1, Stop::UpToDate);
    assert_eq!(r2.1, Stop::UpToDate);
    assert_eq!(r1.0.len() + r2.0.len(), 3, "each slot applied once");
    assert_eq!(bob.state().stats.remote_merges, 3);
    agree(&[&alice, &bob]);
}

#[test]
fn signature_rejection_holds_the_parent() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    alice.dev.stage_add(&carol.invite_id).unwrap();
    let genuine = alice.state().journal.unwrap().slot_bytes;
    // Bob holds the successor keys; flip one byte of the author signature.
    let (keys, inc) = bob.dev.slot_keys().unwrap();
    let plain = keys.open(&inc, &genuine).unwrap();
    let mut d = Dec::new(&plain);
    let body = d.bytes().unwrap();
    let mut sig = d.bytes().unwrap();
    sig[5] ^= 1;
    let forged = keys.seal(&inc, &Enc::new().bytes(&body).bytes(&sig).finish());
    let w = SlotWrite {
        header: keys.prepare(&n.mailbox.pin(), &forged).unwrap(),
        bytes: forged,
    };
    assert_eq!(
        n.mailbox.write_slot_now(&w).unwrap(),
        CreateOutcome::Created
    );

    let head = bob.head();
    let file = accepted_file_digest(&bob);
    let (applied, stop) = bob.dev.catch_up();
    assert!(applied.is_empty());
    let (class, reason) = rejected_class(&stop);
    assert_eq!(class, RejectClass::VerificationFault, "{reason}");
    assert_eq!(bob.head(), head, "accepted parent kept");
    assert_eq!(accepted_file_digest(&bob), file);
    // Suspended: no retry, no writes, no admissions.
    assert_eq!(bob.dev.catch_up().1, stop);
    assert!(matches!(
        bob.dev.stage_remove(&alice.ep),
        Err(Error::Halted(_))
    ));
    assert!(matches!(
        bob.dev.issue_invite(),
        Err(Error::Admission(AdmissionError::IssuerNotAuthorized(_)))
    ));
    // Alice's own candidate lost to the forged value; she holds her parent.
    assert!(matches!(alice.dev.publish(), Ok(CreateOutcome::Conflict)));
    match alice.dev.settle() {
        Err(Error::Slot(r)) => assert_eq!(r.class, RejectClass::VerificationFault),
        other => panic!("{other:?}"),
    }
    assert!(alice.state().journal.is_none());
    assert!(
        alice
            .state()
            .invites
            .iter()
            .any(|i| i.invite_id == carol.invite_id && i.reservation.is_some())
    );
    assert!(
        alice
            .state()
            .outbox
            .iter()
            .all(|o| o.reply.invite_id != carol.invite_id)
    );
}

/// One network per adversarial case: Alice (adversarial author), Bob and
/// Carol (recipients).
fn adversarial_case(adv: Adversary, expect: RejectClass, needle: &str) {
    let n = net();
    let clock = Clock::manual(T0);
    let alice = create(&n, "alice", clock.clone());
    let bob = join(&n, &alice, "bob", clock.clone());
    let dana = request_join(&n, &alice, "dana", clock.clone());
    let head = bob.head();
    let file = accepted_file_digest(&bob);
    alice
        .dev
        .stage_adversarial(Some(dana.invite_id), None, adv)
        .unwrap();
    // The honest publish path refuses a candidate whose successor does not
    // match its signed digest, so the adversary writes directly.
    force_publish(&alice, &n);
    let (_, stop) = bob.dev.catch_up();
    let (class, reason) = rejected_class(&stop);
    assert_eq!(class, expect, "{reason}");
    assert!(reason.contains(needle), "{reason} lacks {needle}");
    assert_eq!(bob.head(), head);
    assert_eq!(
        accepted_file_digest(&bob),
        file,
        "no mutation of the accepted MLS file"
    );
}

#[test]
fn recipients_reject_policy_violations_before_mutation() {
    adversarial_case(
        Adversary {
            no_path: true,
            ..Default::default()
        },
        RejectClass::Invalid,
        "missing update path",
    );
    adversarial_case(
        Adversary {
            extra_remove: Some(1),
            ..Default::default()
        },
        RejectClass::Invalid,
        "exactly one proposal",
    );
    adversarial_case(
        Adversary {
            tamper_digest: true,
            ..Default::default()
        },
        RejectClass::Invalid,
        "digest mismatch",
    );
    adversarial_case(
        Adversary {
            forge_proof: true,
            ..Default::default()
        },
        RejectClass::VerificationFault,
        "joiner proof",
    );
    adversarial_case(
        Adversary {
            signed_reserved_at: Some(T0 + 10_000),
            ..Default::default()
        },
        RejectClass::Invalid,
        "outside the signed invite window",
    );
    // Signed commit time outside the KeyPackage lifetime: OpenMLS VerifyAt.
    adversarial_case(
        Adversary {
            signed_issued_at: Some(T0 + 60 * 24 * 3600),
            ..Default::default()
        },
        RejectClass::Invalid,
        "Lifetime",
    );
}

#[test]
fn recipients_reject_unsafe_admissions_by_a_current_issuer() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    let carol = join(&n, &alice, "carol", Clock::System);
    sync(&[&bob]);
    let token = InviteToken::decode(&alice.dev.issue_invite().unwrap()).unwrap();
    let raw = Adversary {
        skip_issuer_checks: true,
        ..Default::default()
    };

    let case = |req: JoinRequest, needle: &str, class: RejectClass| {
        let head = bob.head();
        alice.dev.stage_raw_add(&req, raw.clone(), None).unwrap();
        force_publish(&alice, &n);
        let (_, stop) = bob.dev.catch_up();
        let (c, reason) = rejected_class(&stop);
        assert_eq!(c, class, "{reason}");
        assert!(reason.contains(needle), "{reason} lacks {needle}");
        assert_eq!(bob.head(), head);
    };
    // Identity replacement: a new MLS key for Carol's endpoint.
    case(
        custom_request(
            &n.root.join("r1"),
            &token,
            &carol.secret,
            Lifetime::new(3600),
            None,
        ),
        "already a member",
        RejectClass::Invalid,
    );
}

#[test]
fn recipients_reject_forged_binding_long_lifetime_and_revoked_readmission() {
    for case in 0..3 {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let carol = join(&n, &alice, "carol", Clock::System);
        sync(&[&bob]);
        let raw = Adversary {
            skip_issuer_checks: true,
            ..Default::default()
        };
        let token = InviteToken::decode(&alice.dev.issue_invite().unwrap()).unwrap();
        let (req, needle, class) = match case {
            0 => {
                let mallory = EndpointSecret::generate();
                let erin = EndpointSecret::generate();
                (
                    custom_request(
                        &n.root.join("r"),
                        &token,
                        &erin,
                        Lifetime::new(3600),
                        Some(&mallory),
                    ),
                    "endpoint binding",
                    RejectClass::VerificationFault,
                )
            }
            1 => {
                let erin = EndpointSecret::generate();
                (
                    custom_request(
                        &n.root.join("r"),
                        &token,
                        &erin,
                        Lifetime::new(30 * 24 * 3600),
                        None,
                    ),
                    "lifetime exceeds the cap",
                    RejectClass::Invalid,
                )
            }
            _ => {
                // Remove Carol properly, then readmit her endpoint.
                alice.dev.revoke(&carol.ep).unwrap().removal.unwrap();
                alice.dev.publish().unwrap();
                alice.dev.settle().unwrap();
                sync(&[&bob]);
                let token = InviteToken::decode(&alice.dev.issue_invite().unwrap()).unwrap();
                (
                    custom_request(
                        &n.root.join("r"),
                        &token,
                        &carol.secret,
                        Lifetime::new(3600),
                        None,
                    ),
                    "readmits a revoked endpoint",
                    RejectClass::Invalid,
                )
            }
        };
        let head = bob.head();
        alice.dev.stage_raw_add(&req, raw, None).unwrap();
        force_publish(&alice, &n);
        let (_, stop) = bob.dev.catch_up();
        let (c, reason) = rejected_class(&stop);
        assert_eq!(c, class, "case {case}: {reason}");
        assert!(
            reason.contains(needle),
            "case {case}: {reason} lacks {needle}"
        );
        assert_eq!(bob.head(), head);
    }
}

#[test]
fn historical_catch_up_with_expired_key_packages() {
    let n = net();
    let clock = Clock::manual(T0);
    let alice = create(&n, "alice", clock.clone());
    clock.set(T0 + 100);
    let bob = join(&n, &alice, "bob", clock.clone());
    clock.set(T0 + 200);
    let carol = join(&n, &alice, "carol", clock.clone());
    sync(&[&bob]);
    // Carol goes offline. Dana is added on day 0, Erin on day 10 (her
    // Welcome tree holds leaves whose KeyPackages expired long ago), and
    // Dana is removed on day 20.
    clock.set(T0 + 300);
    let dana = join(&n, &alice, "dana", clock.clone());
    clock.set(T0 + 10 * 24 * 3600);
    let erin = join(&n, &alice, "erin", clock.clone());
    clock.set(T0 + 20 * 24 * 3600);
    alice.dev.stage_remove(&dana.ep).unwrap();
    alice.dev.publish().unwrap();
    alice.dev.settle().unwrap();
    // Every KeyPackage expired years before the real wall clock; replay
    // uses only the signed issuer times.
    let (applied, stop) = carol.dev.catch_up();
    assert_eq!(stop, Stop::UpToDate);
    assert_eq!(applied.len(), 3);
    sync(&[&bob, &erin]);
    agree(&[&alice, &bob, &carol, &erin]);
    assert_eq!(carol.state().net.unwrap().revoked, vec![dana.ep]);
    assert_eq!(dana.dev.catch_up().1, Stop::Terminal);
}

#[test]
fn removal_terminates_locally_and_remaining_members_advance() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    let carol = join(&n, &alice, "carol", Clock::System);
    sync(&[&bob]);
    let out = alice.dev.revoke(&carol.ep).unwrap();
    assert!(out.local_cutoff && out.removal.is_ok());
    alice.dev.publish().unwrap();
    assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
    let (applied, stop) = carol.dev.catch_up();
    assert_eq!(applied, vec![Advance::SelfRemoved { author_leaf: 0 }]);
    assert_eq!(stop, Stop::Terminal);
    let st = carol.state();
    assert!(st.terminal.is_some());
    assert!(
        mls_files(&carol).is_empty(),
        "no group state or successor secrets kept"
    );
    assert_eq!(carol.dev.issue_invite(), Err(Error::Terminal));
    assert!(matches!(carol.dev.slot_keys(), Err(Error::Terminal)));
    let (applied, _) = bob.dev.catch_up();
    assert_eq!(
        applied,
        vec![Advance::Advanced {
            epoch: 3,
            author_leaf: 0,
            op: OpSummary::Remove { subject: carol.ep }
        }]
    );
    // Remaining members keep advancing.
    let dana = join(&n, &bob, "dana", Clock::System);
    sync(&[&alice]);
    agree(&[&alice, &bob, &dana]);
    assert!(!alice.dev.roster().unwrap().contains(&carol.ep));
    assert_eq!(carol.dev.catch_up().1, Stop::Terminal);
}

#[test]
fn joiner_verifies_reply_receipt_slot_and_welcome() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let token_bytes = alice.dev.issue_invite().unwrap();
    let token = InviteToken::decode(&token_bytes).unwrap();
    let bob = begin(&n, &token_bytes, "bob", Clock::System);
    let mallory = begin(&n, &token_bytes, "mallory", Clock::System);
    alice
        .dev
        .receive_join_request(&bob.invite_id, &bob.request)
        .unwrap();
    alice.dev.stage_add(&bob.invite_id).unwrap();
    alice.dev.publish().unwrap();
    alice.dev.settle().unwrap();
    assert_eq!(
        bob.m.dev.complete_join(),
        Err(Error::Join(JoinError::Waiting)),
        "no Welcome before dispatch"
    );
    alice.dev.dispatch_replies().unwrap();
    // Mallory holds the same invite secret but not the selected request.
    assert_eq!(
        mallory.m.dev.complete_join(),
        Err(Error::Join(JoinError::InviteUsed))
    );
    assert!(mallory.m.state().pending_join.is_none());
    assert!(mls_files(&mallory.m).is_empty());

    let sealed = n
        .mailbox
        .get_reply(&n.mailbox.pin(), &token.reply_box())
        .unwrap()
        .unwrap();
    let plain = token.open_reply(&sealed).unwrap();
    let reply = Reply::decode(&plain).unwrap();
    // Receipt signed by a key other than the invite-pinned issuer.
    let stranger = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let resigned = token.seal_reply(&Reply::build(
        reply.welcome.clone(),
        reply.receipt.clone(),
        &stranger,
    ));
    assert!(matches!(
        bob.m.dev.complete_join_with(&resigned),
        Err(Error::Join(JoinError::VerificationFault(_)))
    ));
    // Properly signed receipts with altered bindings.
    let issuer = mls_signer(&alice);
    let resign = |f: &dyn Fn(&mut super::envelope::Receipt)| {
        let mut r = reply.receipt.clone();
        f(&mut r);
        token.seal_reply(&Reply::build(reply.welcome.clone(), r, &issuer))
    };
    type Edit = Box<dyn Fn(&mut super::envelope::Receipt)>;
    let mismatches: Vec<Edit> = vec![
        Box::new(|r| r.key_package_ref = vec![1; 32]),
        Box::new(|r| r.request_digest = [2; 32]),
        Box::new(|r| r.welcome_hash = [3; 32]),
        Box::new(|r| r.epoch_authenticator = vec![4; 32]),
        Box::new(|r| r.group_context.push(0)),
        Box::new(|r| r.roster.pop().map(|_| ()).unwrap_or(())),
        Box::new(|r| r.ct_hash = [5; 32]),
        Box::new(|r| r.incarnation = vec![6; 16]),
    ];
    for (i, f) in mismatches.iter().enumerate() {
        let e = bob
            .m
            .dev
            .complete_join_with(&resign(f.as_ref()))
            .unwrap_err();
        assert!(
            matches!(e, Error::Join(JoinError::Mismatch(_))),
            "case {i}: {e:?}"
        );
    }
    // A relay view serving different bytes for the admitting slot.
    n.mailbox.serve_hostile(&reply.receipt.slot, b"other bytes");
    assert!(matches!(
        bob.m.dev.complete_join(),
        Err(Error::Join(JoinError::Mismatch(_)))
    ));
    n.mailbox.clear_hostile();
    // Nothing was persisted by the failures; the genuine reply succeeds.
    assert!(bob.m.state().net.is_none());
    bob.m.dev.complete_join().unwrap();
    agree(&[&alice, &bob.m]);
    assert_eq!(
        bob.m.dev.complete_join(),
        Err(Error::Join(JoinError::NoPendingJoin))
    );
}

#[test]
fn candidate_loss_before_and_after_publication() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = request_join(&n, &alice, "bob", Clock::System);
    // Lost before any publication attempt: dropped safely, reservation kept.
    alice.dev.stage_add(&bob.invite_id).unwrap();
    let cand = alice.state().journal.unwrap().candidate_mls_file;
    std::fs::remove_file(alice.dev.store().mls_path(&cand)).unwrap();
    assert!(matches!(
        alice.dev.settle().unwrap(),
        Settle::Discarded { .. }
    ));
    assert!(alice.state().journal.is_none());
    // An unreferenced copy (crashed operation) is swept; the journaled
    // candidate is kept.
    alice.dev.stage_add(&bob.invite_id).unwrap();
    {
        let f = alice.state().net.unwrap().mls_file;
        let g = alice.dev.store().lock().unwrap();
        alice.dev.store().copy_mls(&g, &f, "val").unwrap();
    }
    let rec = alice.dev.recover().unwrap();
    assert_eq!(rec.swept.len(), 1);
    assert!(
        alice
            .dev
            .store()
            .mls_exists(&alice.state().journal.unwrap().candidate_mls_file)
    );
    // Lost after a publication attempt: hold the parent and halt.
    alice.dev.publish().unwrap();
    let head = alice.head();
    let cand = alice.state().journal.unwrap().candidate_mls_file;
    std::fs::remove_file(alice.dev.store().mls_path(&cand)).unwrap();
    assert!(matches!(
        alice.dev.settle(),
        Err(Error::Halted(Halt::CandidateLost { .. }))
    ));
    assert_eq!(alice.head(), head);
    assert!(matches!(
        alice.dev.issue_invite(),
        Err(Error::Admission(AdmissionError::IssuerNotAuthorized(_)))
    ));
}

#[test]
fn storage_failure_at_promotion_preserves_the_parent() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    let head = alice.head();
    alice.dev.stage_add(&carol.invite_id).unwrap();
    alice.dev.publish().unwrap();
    fault::arm("promote");
    assert!(matches!(alice.dev.settle(), Err(Error::Storage(_))));
    assert_eq!(alice.head(), head);
    assert!(alice.state().journal.is_some());
    assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
    assert_eq!(
        alice.state().stats.own_merges,
        2,
        "Bob's admission plus this one"
    );
    // Remote promotion failure: Bob keeps his parent and retries cleanly.
    let bhead = bob.head();
    fault::arm("promote");
    assert!(matches!(
        bob.dev.catch_up().1,
        Stop::Failed(Error::Storage(_))
    ));
    assert_eq!(bob.head(), bhead);
    assert_eq!(mls_files(&bob).len(), 1, "validation copy removed");
    sync(&[&bob]);
    assert_eq!(bob.state().stats.remote_merges, 1);
    alice.dev.dispatch_replies().unwrap();
    carol.m.dev.complete_join().unwrap();
    agree(&[&alice, &bob, &carol.m]);
}

#[test]
fn quarantine_incarnation_and_availability() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    // Transport failures are not publication and change nothing.
    alice.dev.stage_add(&carol.invite_id).unwrap();
    n.mailbox
        .offline
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(alice.dev.publish(), Err(Error::Mailbox(_))));
    assert!(matches!(alice.dev.settle(), Err(Error::Mailbox(_))));
    n.mailbox
        .offline
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(alice.state().halt.is_none());
    assert_eq!(alice.dev.settle().unwrap(), Settle::Pending);
    alice.dev.publish().unwrap();
    alice.dev.settle().unwrap();
    // A purged body is unavailable, not absent, and does not halt.
    let slot = alice.state().net.unwrap().accepted.last().unwrap().slot;
    n.mailbox.purge(&slot);
    assert!(matches!(bob.dev.catch_up().1, Stop::Unavailable(_)));
    assert!(bob.state().halt.is_none());
    // A different value for an accepted slot quarantines.
    n.mailbox.serve_hostile(&slot, b"conflicting history");
    assert!(matches!(
        alice.dev.audit_accepted(),
        Err(Error::Halted(Halt::Quarantined { .. }))
    ));
    assert!(matches!(
        alice.dev.stage_remove(&bob.ep),
        Err(Error::Halted(Halt::Quarantined { .. }))
    ));
    assert!(matches!(
        alice.dev.dispatch_replies().unwrap()[..],
        [Dispatch::Withheld {
            possibly_sent: false,
            ..
        }]
    ));
    // A replaced store suspends membership sync.
    n.mailbox.reincarnate();
    assert!(matches!(
        bob.dev.catch_up().1,
        Stop::Halted(Halt::IncarnationMismatch { .. })
    ));
}

#[test]
fn profile_initialization_is_explicit_and_versioned() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let again = Device::create_network(
        &alice.path,
        &EndpointSecret::generate(),
        n.relay_key,
        n.mailbox.incarnation.clone(),
        n.mailbox.clone(),
        Clock::System,
    );
    assert!(
        matches!(again, Err(Error::Storage(_))),
        "a used profile is never reset"
    );
    assert!(Device::open(&n.root.join("missing"), n.mailbox.clone(), Clock::System).is_err());
    let conn = rusqlite::Connection::open(alice.path.join("membership.db")).unwrap();
    conn.execute("UPDATE membership_state SET format = 'other/9'", [])
        .unwrap();
    drop(conn);
    assert!(matches!(
        Device::open(&alice.path, n.mailbox.clone(), Clock::System),
        Err(Error::Storage(_))
    ));
}

// ------------------------------------------- review fixes (second round)

/// Stage, publish and settle an Add without dispatching its reply.
fn accept_add(issuer: &Member, p: &Pending) {
    issuer.dev.stage_add(&p.invite_id).unwrap();
    assert_eq!(issuer.dev.publish().unwrap(), CreateOutcome::Created);
    assert_eq!(issuer.dev.settle().unwrap(), Settle::Accepted);
}

#[test]
fn hung_read_never_blocks_cutoff_or_revives_a_stale_result() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    accept_add(&alice, &carol);
    // A Bob handle whose relay stalls on every network step.
    let hung = n.mailbox.separate_handle();
    hung.gate.hang();
    let b_hung = Device::open(&bob.path, hung.clone(), Clock::System).unwrap();
    std::thread::scope(|s| {
        let h = s.spawn(|| b_hung.catch_up());
        hung.gate.wait_entered(1);
        // The read is in flight without the lock. Local work proceeds.
        let stranger = EndpointSecret::generate().public();
        let r = bob.dev.revoke(&stranger).unwrap();
        assert!(r.local_cutoff);
        assert!(bob.state().local_cutoffs.contains(&stranger));
        let t = bob.dev.issue_invite().unwrap();
        let p = begin(&n, &t, "erin", Clock::System);
        assert!(matches!(
            bob.dev
                .receive_join_request(&p.invite_id, &p.request)
                .unwrap(),
            ReserveOutcome::Reserved { .. }
        ));
        // Another handle advances Bob past the slot the hung read targets.
        let (applied, stop) = bob.dev.catch_up();
        assert_eq!(stop, Stop::UpToDate);
        assert_eq!(applied.len(), 1);
        hung.gate.release();
        let (applied, stop) = h.join().unwrap();
        assert_eq!(stop, Stop::UpToDate);
        assert!(applied.is_empty(), "the stale read was not applied");
    });
    let st = bob.state();
    assert_eq!(
        st.stats.remote_merges, 1,
        "the slot was applied exactly once"
    );
    assert!(st.stats.stale_reads >= 1, "the stale result was discarded");
    agree(&[&alice, &bob]);
}

#[test]
fn hung_send_linearizes_cutoffs_at_handoff() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    accept_add(&alice, &carol);
    let dana = request_join(&n, &alice, "dana", Clock::System);
    accept_add(&alice, &dana);
    // Dana's cutoff is recorded before any handoff.
    assert!(alice.dev.revoke(&dana.m.ep).unwrap().local_cutoff);
    let hung = n.mailbox.separate_handle();
    hung.gate.hang();
    let a_hung = Device::open(&alice.path, hung.clone(), Clock::System).unwrap();
    std::thread::scope(|s| {
        let h = s.spawn(|| a_hung.dispatch_replies());
        hung.gate.wait_entered(1);
        // Carol's reply is handed off; a cutoff now cannot recall it, but
        // recording the cutoff is not blocked by the stalled send.
        let st = alice.state();
        let e = st
            .outbox
            .iter()
            .find(|o| o.reply.invite_id == carol.invite_id)
            .unwrap();
        assert!(matches!(e.status, OutboxStatus::Dispatching { .. }));
        assert!(alice.dev.revoke(&carol.m.ep).unwrap().local_cutoff);
        hung.gate.release();
        let out = h.join().unwrap().unwrap();
        assert_eq!(
            out,
            vec![
                Dispatch::Sent {
                    invite_id: carol.invite_id
                },
                Dispatch::Withheld {
                    invite_id: dana.invite_id,
                    reason: "joiner is locally cut off".into(),
                    possibly_sent: false
                },
            ]
        );
    });
    let rb = |p: &Pending| InviteToken::decode(&p.token).unwrap().reply_box();
    assert!(
        n.mailbox.reply_exists(&rb(&carol)),
        "handed off before the cutoff"
    );
    assert!(
        !n.mailbox.reply_exists(&rb(&dana)),
        "cutoff recorded before handoff"
    );
}

#[test]
fn hung_publish_does_not_block_local_writes() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    alice.dev.stage_add(&carol.invite_id).unwrap();
    let hung = n.mailbox.separate_handle();
    hung.gate.hang();
    let a_hung = Device::open(&alice.path, hung.clone(), Clock::System).unwrap();
    std::thread::scope(|s| {
        let h = s.spawn(|| a_hung.publish());
        hung.gate.wait_entered(1);
        assert!(alice.state().journal.unwrap().publish_attempted);
        assert!(
            alice
                .dev
                .revoke(&EndpointSecret::generate().public())
                .unwrap()
                .local_cutoff
        );
        assert!(alice.dev.issue_invite().is_ok());
        hung.gate.release();
        assert_eq!(h.join().unwrap().unwrap(), CreateOutcome::Created);
    });
    assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
    sync(&[&bob]);
    agree(&[&alice, &bob]);
}

#[test]
fn publish_requires_a_prepared_successor() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = request_join(&n, &alice, "bob", Clock::System);
    let before = n.mailbox.slot_count();
    // Candidate lost after staging, then publish directly: nothing written.
    alice.dev.stage_add(&bob.invite_id).unwrap();
    let cand = alice.state().journal.unwrap().candidate_mls_file;
    std::fs::remove_file(alice.dev.store().mls_path(&cand)).unwrap();
    assert!(matches!(
        alice.dev.publish(),
        Err(Error::CandidateUnusable(_))
    ));
    assert_eq!(
        n.mailbox.slot_count(),
        before,
        "no immutable write without a successor"
    );
    assert!(alice.state().journal.is_none());
    // Candidate replaced by an unmerged copy of the parent: refused too.
    alice.dev.stage_add(&bob.invite_id).unwrap();
    let st = alice.state();
    let j = st.journal.clone().unwrap();
    std::fs::copy(
        alice.dev.store().mls_path(&st.net.unwrap().mls_file),
        alice.dev.store().mls_path(&j.candidate_mls_file),
    )
    .unwrap();
    assert!(matches!(
        alice.dev.publish(),
        Err(Error::CandidateUnusable(_))
    ));
    assert_eq!(n.mailbox.slot_count(), before);
    // The reservation survives and a fresh stage succeeds.
    admit(&alice, &bob);
    agree(&[&alice, &bob.m]);
}

#[test]
fn different_winner_adopted_after_own_candidate_vanished() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    let dana = request_join(&n, &bob, "dana", Clock::System);
    alice.dev.stage_add(&carol.invite_id).unwrap();
    bob.dev.stage_add(&dana.invite_id).unwrap();
    assert_eq!(bob.dev.publish().unwrap(), CreateOutcome::Created);
    assert_eq!(alice.dev.publish().unwrap(), CreateOutcome::Conflict);
    let cand = alice.state().journal.unwrap().candidate_mls_file;
    std::fs::remove_file(alice.dev.store().mls_path(&cand)).unwrap();
    assert_eq!(bob.dev.settle().unwrap(), Settle::Accepted);
    // The winner is validated from the accepted parent, not the candidate.
    assert!(matches!(alice.dev.settle().unwrap(), Settle::Lost { .. }));
    assert!(alice.state().halt.is_none());
    agree(&[&alice, &bob]);
    admit(&alice, &carol);
    sync(&[&bob]);
    agree(&[&alice, &bob, &carol.m]);
}

#[test]
fn signed_proposal_vector_must_hold_exactly_one_inline_proposal() {
    use super::envelope::Transition;
    use super::policy::{check_proposal_vector, commit_proposal_span};
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    alice.dev.stage_add(&carol.invite_id).unwrap();
    let (keys, inc) = bob.dev.slot_keys().unwrap();
    let plain = keys
        .open(&inc, &alice.state().journal.unwrap().slot_bytes)
        .unwrap();
    let commit = Transition::decode_signed(&plain).unwrap().transition.commit;
    let (prefix, body, len) = commit_proposal_span(&commit).unwrap();
    let one = commit[body..body + len].to_vec();
    check_proposal_vector(&commit, &one).unwrap();
    // The same proposal twice in the vector (no valid signature is made;
    // OpenMLS would deduplicate it in `queued_proposals`).
    let mut dup = commit[..prefix].to_vec();
    let l = (2 * len) as u32;
    if l < 64 {
        dup.push(l as u8);
    } else if l < 16384 {
        dup.extend_from_slice(&((l as u16) | 0x4000).to_be_bytes());
    } else {
        dup.extend_from_slice(&(l | 0x8000_0000).to_be_bytes());
    }
    dup.extend_from_slice(&one);
    dup.extend_from_slice(&one);
    dup.extend_from_slice(&commit[body + len..]);
    assert_eq!(commit_proposal_span(&dup).unwrap().2, 2 * len);
    assert!(check_proposal_vector(&dup, &one).is_err());
    // Framing that is not a member PublicMessage commit is refused.
    assert!(commit_proposal_span(&commit[..prefix]).is_err());
    let mut wrong = commit.clone();
    wrong[3] = 2;
    assert!(commit_proposal_span(&wrong).is_err());
    // Honest commits pass the check end to end.
    force_publish(&alice, &n);
    sync(&[&bob]);
}

#[test]
fn welcome_from_another_signer_or_key_package_is_rejected() {
    for case in ["signer", "key_package"] {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let token_bytes = alice.dev.issue_invite().unwrap();
        let token = InviteToken::decode(&token_bytes).unwrap();
        let dana = begin(&n, &token_bytes, "dana", Clock::System);
        alice
            .dev
            .receive_join_request(&dana.invite_id, &dana.request)
            .unwrap();
        // Bob, another current member, commits Dana's admission himself and
        // seals a reply under Alice's invite.
        let req = match case {
            "signer" => token.open_request(&dana.request).unwrap(),
            _ => custom_request(
                &n.root.join("kp2"),
                &token,
                &dana.m.secret,
                Lifetime::new(3600),
                None,
            ),
        };
        let raw = Adversary {
            skip_issuer_checks: true,
            ..Default::default()
        };
        bob.dev
            .stage_raw_add(&req, raw, Some(&token_bytes))
            .unwrap();
        let sealed = bob.state().journal.unwrap().reply.unwrap().bytes;
        force_publish(&bob, &n);
        let reply = Reply::decode(&token.open_reply(&sealed).unwrap()).unwrap();
        // Re-sign the receipt as the genuine issuer, naming Dana's pending
        // request and KeyPackage, so only the Welcome itself differs.
        let mut r = reply.receipt.clone();
        r.issuer_endpoint = token.issuer_endpoint;
        r.issuer_mls_key = token.issuer_mls_key.clone();
        let pj = dana.m.state().pending_join.unwrap();
        r.key_package_ref = pj.key_package_ref.clone();
        let mut d = Dec::new(&pj.transcript);
        r.request_digest = JoinTranscript::decode(&mut d).unwrap().digest();
        let forged = token.seal_reply(&Reply::build(reply.welcome.clone(), r, &mls_signer(&alice)));
        let e = dana.m.dev.complete_join_with(&forged).unwrap_err();
        let needle = match case {
            "signer" => "Welcome signed by another member than the invite issuer",
            _ => "Welcome is not encrypted to the pending KeyPackage",
        };
        assert_eq!(e, Error::Join(JoinError::Mismatch(needle.into())), "{case}");
        assert!(dana.m.state().net.is_none(), "{case}: nothing installed");
        assert!(
            dana.m.state().pending_join.is_some(),
            "{case}: pending join kept"
        );
    }
}

#[test]
fn terminal_recovery_drops_all_group_state() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let carol = join(&n, &alice, "carol", Clock::System);
    alice.dev.revoke(&carol.ep).unwrap().removal.unwrap();
    alice.dev.publish().unwrap();
    assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
    // Terminal state commits, then cleanup fails (as after a crash).
    fault::arm("remote_cleanup");
    assert!(matches!(
        carol.dev.catch_up().1,
        Stop::Failed(Error::Storage(_))
    ));
    assert!(carol.state().terminal.is_some());
    assert!(!mls_files(&carol).is_empty());
    let rec = carol.dev.recover().unwrap();
    assert!(!rec.swept.is_empty());
    assert!(
        mls_files(&carol).is_empty(),
        "no old MLS state survives recovery"
    );
}

#[test]
fn reply_conflict_is_isolated_to_its_entry() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    accept_add(&alice, &carol);
    let dana = request_join(&n, &alice, "dana", Clock::System);
    accept_add(&alice, &dana);
    n.mailbox.occupy_reply(
        &InviteToken::decode(&carol.token).unwrap().reply_box(),
        b"someone else",
    );
    assert_eq!(
        alice.dev.dispatch_replies().unwrap(),
        vec![
            Dispatch::Conflicted {
                invite_id: carol.invite_id
            },
            Dispatch::Sent {
                invite_id: dana.invite_id
            }
        ]
    );
    assert_eq!(alice.dev.dispatch_replies().unwrap(), vec![]);
    dana.m.dev.complete_join().unwrap();
    assert!(matches!(
        carol.m.dev.complete_join(),
        Err(Error::Join(
            JoinError::Malformed(_) | JoinError::ReplyUndecryptable
        ))
    ));
}

#[test]
fn authenticated_incarnation_mismatch_persists_on_every_path() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    accept_add(&alice, &carol);
    n.mailbox.reincarnate();
    // Reply write by an unhalted issuer: halts and is persisted.
    assert!(matches!(
        alice.dev.dispatch_replies(),
        Err(Error::Halted(Halt::IncarnationMismatch { .. }))
    ));
    assert!(matches!(
        alice.state().halt,
        Some(Halt::IncarnationMismatch { .. })
    ));
    // The halted issuer now withholds the reply instead of resending it.
    assert!(matches!(
        alice.dev.dispatch_replies().unwrap()[..],
        [Dispatch::Withheld {
            possibly_sent: true,
            ..
        }]
    ));
    // Audit reports the persistent mismatch.
    assert!(matches!(
        alice.dev.audit_accepted(),
        Err(Error::Halted(Halt::IncarnationMismatch { .. }))
    ));
    // Reply reads by a joiner persist a stop as well.
    assert!(matches!(
        carol.m.dev.complete_join(),
        Err(Error::Join(JoinError::Halted(_)))
    ));
    assert!(carol.m.state().pending_join.unwrap().halted.is_some());
    assert!(matches!(
        carol.m.dev.complete_join(),
        Err(Error::Join(JoinError::Halted(_)))
    ));
}

#[test]
fn audit_persists_an_incarnation_mismatch() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let _bob = join(&n, &alice, "bob", Clock::System);
    n.mailbox.reincarnate();
    assert!(matches!(
        alice.dev.audit_accepted(),
        Err(Error::Halted(Halt::IncarnationMismatch { .. }))
    ));
    assert!(matches!(
        alice.state().halt,
        Some(Halt::IncarnationMismatch { .. })
    ));
}

// ------------------------------------- incarnation races, adapter contract

#[test]
fn join_completion_cannot_install_after_a_concurrent_halt() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let dana = request_join(&n, &alice, "dana", Clock::System);
    admit_without_join(&alice, &dana);
    // Completion A reads through a stalled handle of the pinned relay.
    let hung = n.mailbox.separate_handle();
    hung.gate.hang();
    let a = Device::open(&dana.m.path, hung.clone(), Clock::System).unwrap();
    // Completion B reaches a replacement store with another incarnation.
    let replacement = n.mailbox.replacement(&n.root.join("replacement"));
    let b = Device::open(&dana.m.path, replacement, Clock::System).unwrap();
    std::thread::scope(|s| {
        let h = s.spawn(|| a.complete_join());
        hung.gate.wait_entered(1);
        assert!(matches!(
            b.complete_join(),
            Err(Error::Join(JoinError::Halted(_)))
        ));
        assert!(dana.m.state().pending_join.unwrap().halted.is_some());
        hung.gate.release();
        // A's reply and slot are genuine, but the halt wins at install.
        assert!(matches!(
            h.join().unwrap(),
            Err(Error::Join(JoinError::Halted(_)))
        ));
    });
    let st = dana.m.state();
    assert!(st.net.is_none(), "no membership installed after the halt");
    assert!(st.pending_join.unwrap().halted.is_some());
}

#[test]
fn join_mismatch_halts_membership_installed_by_a_concurrent_completion() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let dana = request_join(&n, &alice, "dana", Clock::System);
    admit_without_join(&alice, &dana);
    let replacement = n.mailbox.replacement(&n.root.join("replacement"));
    replacement.gate.hang();
    let b = Device::open(&dana.m.path, replacement.clone(), Clock::System).unwrap();
    std::thread::scope(|s| {
        let late_mismatch = s.spawn(|| b.complete_join());
        replacement.gate.wait_entered(1);
        let installed = dana.m.dev.complete_join();
        replacement.gate.release();
        installed.unwrap();
        assert!(matches!(
            late_mismatch.join().unwrap(),
            Err(Error::Join(JoinError::Halted(_)))
        ));
    });
    let st = dana.m.state();
    assert!(st.net.is_some());
    assert!(st.pending_join.is_none());
    assert!(matches!(st.halt, Some(Halt::IncarnationMismatch { .. })));
}

/// Stage, publish, settle and dispatch an Add, leaving the joiner pending.
fn admit_without_join(issuer: &Member, p: &Pending) {
    accept_add(issuer, p);
    assert_eq!(
        issuer.dev.dispatch_replies().unwrap(),
        vec![Dispatch::Sent {
            invite_id: p.invite_id
        }]
    );
}

#[test]
fn settle_processes_a_mismatch_after_concurrent_settlement() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    alice.dev.stage_add(&carol.invite_id).unwrap();
    assert_eq!(alice.dev.publish().unwrap(), CreateOutcome::Created);
    let hung = n.mailbox.separate_handle();
    hung.gate.hang();
    let a_hung = Device::open(&alice.path, hung.clone(), Clock::System).unwrap();
    std::thread::scope(|s| {
        let h = s.spawn(|| a_hung.settle());
        hung.gate.wait_entered(1);
        // Another handle settles first: head and journal both change.
        assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
        n.mailbox.reincarnate();
        hung.gate.release();
        assert!(matches!(
            h.join().unwrap(),
            Err(Error::Halted(Halt::IncarnationMismatch { .. }))
        ));
    });
    assert!(matches!(
        alice.state().halt,
        Some(Halt::IncarnationMismatch { .. })
    ));
}

#[test]
fn catch_up_processes_a_mismatch_after_concurrent_advance() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = join(&n, &alice, "bob", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    accept_add(&alice, &carol);
    let hung = n.mailbox.separate_handle();
    hung.gate.hang();
    let b_hung = Device::open(&bob.path, hung.clone(), Clock::System).unwrap();
    std::thread::scope(|s| {
        let h = s.spawn(|| b_hung.catch_up());
        hung.gate.wait_entered(1);
        assert_eq!(bob.dev.catch_up().1, Stop::UpToDate);
        n.mailbox.reincarnate();
        hung.gate.release();
        let (applied, stop) = h.join().unwrap();
        assert!(applied.is_empty());
        assert!(matches!(
            stop,
            Stop::Halted(Halt::IncarnationMismatch { .. })
        ));
    });
    assert!(matches!(
        bob.state().halt,
        Some(Halt::IncarnationMismatch { .. })
    ));
    assert_eq!(bob.state().stats.remote_merges, 1);
}

fn reply_box(p: &Pending) -> [u8; 32] {
    InviteToken::decode(&p.token).unwrap().reply_box()
}

#[test]
fn reply_outcomes_are_distinct_and_scoped_to_their_entry() {
    use super::fake_mailbox::Scripted;
    use super::mailbox::MailboxError;
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let mut ps = vec![];
    for name in ["refused", "lost_receipt", "unknown", "purged", "fine"] {
        let p = request_join(&n, &alice, name, Clock::System);
        accept_add(&alice, &p);
        ps.push(p);
    }
    let script = |p: &Pending, store_first, result| {
        n.mailbox.script(
            &reply_box(p),
            Scripted {
                store_first,
                result,
            },
        )
    };
    script(&ps[0], false, Err(MailboxError::Refused("framing".into())));
    script(
        &ps[1],
        true,
        Err(MailboxError::Uncertain("receipt lost".into())),
    );
    script(
        &ps[2],
        false,
        Err(MailboxError::Uncertain("timeout".into())),
    );
    script(&ps[3], false, Ok(CreateOutcome::Unavailable));
    let out = alice.dev.dispatch_replies().unwrap();
    assert_eq!(
        out[0],
        Dispatch::Refused {
            invite_id: ps[0].invite_id,
            reason: "framing".into()
        }
    );
    assert!(matches!(
        &out[1],
        Dispatch::Unconfirmed {
            error: MailboxError::Uncertain(_),
            ..
        }
    ));
    assert!(matches!(
        &out[2],
        Dispatch::Unconfirmed {
            error: MailboxError::Uncertain(_),
            ..
        }
    ));
    assert_eq!(
        out[3],
        Dispatch::Unavailable {
            invite_id: ps[3].invite_id
        }
    );
    assert_eq!(
        out[4],
        Dispatch::Sent {
            invite_id: ps[4].invite_id
        }
    );
    let status = |p: &Pending| {
        alice
            .state()
            .outbox
            .into_iter()
            .find(|o| o.reply.invite_id == p.invite_id)
            .unwrap()
            .status
    };
    assert!(matches!(status(&ps[0]), OutboxStatus::Refused { .. }));
    assert!(matches!(status(&ps[1]), OutboxStatus::Dispatching { .. }));
    assert!(matches!(status(&ps[2]), OutboxStatus::Dispatching { .. }));
    assert_eq!(status(&ps[3]), OutboxStatus::Unavailable);
    assert!(
        n.mailbox.reply_exists(&reply_box(&ps[1])),
        "stored despite the lost receipt"
    );
    assert!(
        !n.mailbox.reply_exists(&reply_box(&ps[0])),
        "refusal stored nothing"
    );
    // Only the uncertain entries are handed off again, with the exact bytes.
    let again = alice.dev.dispatch_replies().unwrap();
    assert_eq!(
        again,
        vec![
            Dispatch::Sent {
                invite_id: ps[1].invite_id
            },
            Dispatch::Sent {
                invite_id: ps[2].invite_id
            }
        ]
    );
    assert_eq!(alice.dev.dispatch_replies().unwrap(), vec![]);
    for p in [&ps[1], &ps[2], &ps[4]] {
        p.m.dev.complete_join().unwrap();
    }
    assert_eq!(
        ps[0].m.dev.complete_join(),
        Err(Error::Join(JoinError::Waiting))
    );
}

#[test]
fn slot_write_acknowledgements_never_count_as_publication() {
    use super::fake_mailbox::Scripted;
    use super::mailbox::MailboxError;
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = request_join(&n, &alice, "bob", Clock::System);
    let head = alice.head();
    let slot = alice.dev.stage_add(&bob.invite_id).unwrap();
    // A relay claiming success without storing: still only a read decides.
    n.mailbox.script(
        &slot,
        Scripted {
            store_first: false,
            result: Ok(CreateOutcome::Created),
        },
    );
    assert_eq!(alice.dev.publish().unwrap(), CreateOutcome::Created);
    assert_eq!(alice.head(), head, "an acknowledgement is not acceptance");
    assert_eq!(alice.dev.settle().unwrap(), Settle::Pending);
    // A definitive refusal is recorded, keeps the journal and halts nothing.
    n.mailbox.script(
        &slot,
        Scripted {
            store_first: false,
            result: Err(MailboxError::Refused("proof".into())),
        },
    );
    assert_eq!(
        alice.dev.publish(),
        Err(Error::Mailbox(MailboxError::Refused("proof".into())))
    );
    let st = alice.state();
    assert!(st.halt.is_none());
    assert!(
        st.journal
            .as_ref()
            .unwrap()
            .last_outcome
            .as_ref()
            .unwrap()
            .contains("Refused")
    );
    // Uncertain with the bytes actually stored: the exact read accepts.
    n.mailbox.script(
        &slot,
        Scripted {
            store_first: true,
            result: Err(MailboxError::Uncertain("lost".into())),
        },
    );
    assert!(matches!(
        alice.dev.publish(),
        Err(Error::Mailbox(MailboxError::Uncertain(_)))
    ));
    assert_eq!(alice.head(), head);
    assert_eq!(alice.dev.settle().unwrap(), Settle::Accepted);
    alice.dev.dispatch_replies().unwrap();
    bob.m.dev.complete_join().unwrap();
    agree(&[&alice, &bob.m]);
}

#[test]
fn purged_slot_write_is_unavailable_not_conflict() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = request_join(&n, &alice, "bob", Clock::System);
    let slot = alice.dev.stage_add(&bob.invite_id).unwrap();
    n.mailbox.purge(&slot);
    assert_eq!(alice.dev.publish().unwrap(), CreateOutcome::Unavailable);
    assert!(matches!(alice.dev.settle(), Err(Error::Unavailable(_))));
    assert!(alice.state().halt.is_none());
    assert!(alice.state().journal.is_some());
}

#[test]
fn wrong_successor_digest_behind_a_valid_prepared_marker_is_refused() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let carol = request_join(&n, &alice, "carol", Clock::System);
    let dana = request_join(&n, &alice, "dana", Clock::System);
    // A genuine prepared successor for Carol's Add, kept aside.
    alice.dev.stage_add(&carol.invite_id).unwrap();
    let c1 = alice.state().journal.unwrap().candidate_mls_file;
    let carol_successor = std::fs::read(alice.dev.store().mls_path(&c1)).unwrap();
    alice.dev.abandon_unpublished().unwrap();
    // Dana's journal, with Carol's successor (epoch parent + 1) behind a
    // marker rewritten to Dana's journal id.
    alice.dev.stage_add(&dana.invite_id).unwrap();
    let j = alice.state().journal.unwrap();
    let c2 = alice.dev.store().mls_path(&j.candidate_mls_file);
    std::fs::write(&c2, &carol_successor).unwrap();
    let conn = rusqlite::Connection::open(&c2).unwrap();
    conn.execute(
        "UPDATE massrelay_candidate SET journal_id = ?1, prepared = 1",
        [j.id.to_vec()],
    )
    .unwrap();
    drop(conn);
    let before = n.mailbox.slot_count();
    match alice.dev.publish() {
        Err(Error::CandidateUnusable(why)) => assert!(why.contains("successor mismatch"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(n.mailbox.slot_count(), before, "nothing written");
    assert!(alice.state().journal.is_none());
    admit(&alice, &dana);
}

// ------------------------------------------------- invite queue and reply integrity

fn request_queue(token: &[u8]) -> [u8; 32] {
    InviteToken::decode(token).unwrap().request_queue().queue
}

fn sent_request(n: &Net, token: &[u8], name: &str) -> Pending {
    let p = begin(n, token, name, Clock::System);
    assert_eq!(p.m.dev.send_join_request().unwrap(), CreateOutcome::Created);
    p
}

/// A definitively damaged request item is recorded and acknowledged without consuming the
/// invite, and the valid request after it is still judged.
#[test]
fn a_damaged_request_is_recorded_past_without_consuming_the_invite() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let token = alice.dev.issue_invite().unwrap();
    let _bob = sent_request(&n, &token, "bob");
    n.mailbox
        .damage_queue_item(&request_queue(&token), 1, b"damaged");
    let carol = sent_request(&n, &token, "carol");
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
    let inv = alice
        .state()
        .invites
        .into_iter()
        .find(|i| i.invite_id == carol.invite_id)
        .unwrap();
    assert_eq!(inv.queue_cursor, 2);
    assert!(inv.unacked.is_empty());
    assert!(inv.reservation.is_some(), "the valid request reserved it");
    assert!(alice.dev.poll_join_requests().unwrap().is_empty());
}

#[test]
fn shutdown_between_verdict_and_ack_keeps_the_ack_pending() {
    struct StopAfterVerdict(std::cell::Cell<bool>);

    impl Gate for StopAfterVerdict {
        fn run<R>(&self, f: impl FnOnce(&mut Vec<Advance>) -> R) -> Option<R> {
            if self.0.get() {
                return None;
            }
            let result = f(&mut vec![]);
            self.0.set(true);
            Some(result)
        }

        fn admits(&self) -> bool {
            // Model a caller that observed an open gate just before shutdown.
            true
        }
    }

    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let token = alice.dev.issue_invite().unwrap();
    let _bob = sent_request(&n, &token, "bob");
    let gate = StopAfterVerdict(std::cell::Cell::new(false));
    let polled = alice.dev.poll_join_requests_gated(&gate).unwrap();
    assert!(matches!(
        &polled[..],
        [Polled {
            verdict: Verdict::Reserved(_),
            ack: AckState::Unconfirmed(MailboxError::NotStored(_)),
            ..
        }]
    ));
    assert_eq!(alice.state().invites[0].unacked.len(), 1);

    let retried = alice.dev.poll_join_requests().unwrap();
    assert!(matches!(
        &retried[..],
        [Polled {
            verdict: Verdict::Retried { .. },
            ack: AckState::Confirmed(AckOutcome::Recorded),
            ..
        }]
    ));
    assert!(alice.state().invites[0].unacked.is_empty());
}

/// A relay view without the item is not an acknowledgement: it is reported as such on every
/// retry, and the item stays pending.
#[test]
fn an_acknowledgement_of_a_missing_item_stays_unresolved() {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let token = alice.dev.issue_invite().unwrap();
    let _bob = sent_request(&n, &token, "bob");
    n.mailbox
        .acks_lost
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let polled = alice.dev.poll_join_requests().unwrap();
    assert!(
        matches!(
            &polled[..],
            [Polled {
                verdict: Verdict::Reserved(_),
                ack: AckState::Unconfirmed(MailboxError::Uncertain(_)),
                ..
            }]
        ),
        "{polled:?}"
    );
    let pending = || alice.state().invites[0].unacked.clone();
    let [item] = pending()[..] else {
        panic!("one pending acknowledgement")
    };

    // A restore from before the item: same relay, same incarnation, no such item.
    n.mailbox.forget_queue(&request_queue(&token));
    n.mailbox
        .acks_lost
        .store(false, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..2 {
        assert_eq!(
            alice.dev.poll_join_requests().unwrap(),
            vec![Polled {
                invite_id: InviteToken::decode(&token).unwrap().invite_id,
                seq: None,
                verdict: Verdict::Retried { item },
                ack: AckState::NoSuchItem,
            }]
        );
        assert_eq!(pending(), vec![item], "still unresolved");
    }
}

fn outbox_status(m: &Member, invite_id: &[u8; 16]) -> OutboxStatus {
    m.state()
        .outbox
        .into_iter()
        .find(|o| &o.reply.invite_id == invite_id)
        .unwrap()
        .status
}

/// Every reply is preflighted locally before it is marked as dispatching. A mailbox that cannot
/// serve the pin sends nothing and changes no entry, so earlier uncertainty is kept, and a
/// malformed record is withheld on its own while the others are still sent.
#[test]
fn reply_dispatch_is_preflighted_per_entry() {
    for damage in [
        |reply: &mut super::membership::PendingReply| {
            reply.reply_proof.pop();
        },
        |reply: &mut super::membership::PendingReply| reply.reply_proof[0] ^= 1,
        |reply: &mut super::membership::PendingReply| reply.reply_box[0] ^= 1,
        |reply: &mut super::membership::PendingReply| reply.bytes[0] ^= 1,
    ] {
        check_reply_preflight(damage);
    }
}

fn check_reply_preflight(damage: impl FnOnce(&mut super::membership::PendingReply)) {
    let n = net();
    let alice = create(&n, "alice", Clock::System);
    let bob = request_join(&n, &alice, "bob", Clock::System);
    accept_add(&alice, &bob);
    let reply_box = alice.state().outbox[0].reply.reply_box;
    n.mailbox.script(
        &reply_box,
        Scripted {
            store_first: false,
            result: Err(MailboxError::Uncertain("lost in transit".into())),
        },
    );
    assert!(matches!(
        &alice.dev.dispatch_replies().unwrap()[..],
        [Dispatch::Unconfirmed { .. }]
    ));
    let uncertain = outbox_status(&alice, &bob.invite_id);
    assert!(matches!(uncertain, OutboxStatus::Dispatching { .. }));
    let carol = request_join(&n, &alice, "carol", Clock::System);
    accept_add(&alice, &carol);

    // A mailbox for another relay: nothing is attempted and nothing changes.
    let elsewhere = FsMailbox::create(&n.root.join("elsewhere"));
    let misconfigured = Device::open(&alice.path, elsewhere, Clock::System).unwrap();
    let dispatched = misconfigured.dispatch_replies().unwrap();
    assert!(
        matches!(
            &dispatched[..],
            [
                Dispatch::NotAttempted {
                    error: MailboxError::Mispinned(_),
                    ..
                },
                Dispatch::NotAttempted {
                    error: MailboxError::Mispinned(_),
                    ..
                },
            ]
        ),
        "{dispatched:?}"
    );
    assert_eq!(outbox_status(&alice, &bob.invite_id), uncertain);
    assert_eq!(outbox_status(&alice, &carol.invite_id), OutboxStatus::Ready);

    // Bob's stored record is damaged: withheld, still possibly sent; Carol's is still sent.
    {
        let g = alice.dev.store().lock().unwrap();
        alice
            .dev
            .store()
            .update(&g, |st: &mut State| {
                let o = st
                    .outbox
                    .iter_mut()
                    .find(|o| o.reply.invite_id == bob.invite_id)
                    .unwrap();
                damage(&mut o.reply);
                Ok::<_, Error>(())
            })
            .unwrap();
    }
    let dispatched = alice.dev.dispatch_replies().unwrap();
    assert!(
        matches!(
            &dispatched[..],
            [
                Dispatch::Withheld {
                    invite_id,
                    reason,
                    possibly_sent: true,
                },
                Dispatch::Sent { invite_id: sent },
            ] if *invite_id == bob.invite_id
                && reason.starts_with("malformed local reply record")
                && *sent == carol.invite_id
        ),
        "{dispatched:?}"
    );
}

// ------------------------------------------------------- peer authorization

mod pairing {
    use super::*;
    use crate::private::pairing::{Authorization, Owner, PairError, Peers, Refusal, TestLink};
    use crate::wire::Service;
    use std::num::NonZeroU16;
    use std::sync::Arc;

    fn tcp(p: u16) -> Service {
        Service::Tcp(NonZeroU16::new(p).unwrap())
    }

    fn udp(p: u16) -> Service {
        Service::Udp(NonZeroU16::new(p).unwrap())
    }

    /// A three-member network: Alice, Bob, Carol, all caught up.
    fn three() -> (Net, Member, Member, Member) {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let carol = join(&n, &alice, "carol", Clock::System);
        sync(&[&bob]);
        (n, alice, bob, carol)
    }

    fn owner(m: &Member) -> Owner {
        Owner::acquire(&m.path).unwrap()
    }

    /// Both ends of one simulated authenticated connection.
    fn link(a: &Member, b: &Member) -> (Arc<TestLink>, Arc<TestLink>) {
        let binding = random();
        (TestLink::new(b.ep, binding), TestLink::new(a.ep, binding))
    }

    type P<'d, 'o> = Peers<'d, 'o, FsMailbox>;

    /// Run the exchange over `(la, lb)`; returns (a's, b's) result.
    fn exchange(
        pa: &P<'_, '_>,
        la: &Arc<TestLink>,
        pb: &P<'_, '_>,
        lb: &Arc<TestLink>,
    ) -> (
        Result<Authorization, PairError>,
        Result<Authorization, PairError>,
    ) {
        let ea = pa.exchange(la.clone()).unwrap();
        let eb = pb.exchange(lb.clone()).unwrap();
        let (oa, ob) = (ea.offer(), eb.offer());
        let (ca, confa) = ea.on_offer(&ob).unwrap();
        let (cb, confb) = eb.on_offer(&oa).unwrap();
        (ca.finish(&confb), cb.finish(&confa))
    }

    fn pair(
        pa: &P<'_, '_>,
        a: &Member,
        pb: &P<'_, '_>,
        b: &Member,
    ) -> (Authorization, Authorization) {
        let (la, lb) = link(a, b);
        let (x, y) = exchange(pa, &la, pb, &lb);
        (x.unwrap(), y.unwrap())
    }

    fn approve_both(pa: &P<'_, '_>, a: &Member, pb: &P<'_, '_>, b: &Member) {
        pa.approve("peer-b", &b.ep, false).unwrap();
        pb.approve("peer-a", &a.ep, false).unwrap();
    }

    fn refused<T: std::fmt::Debug>(r: Result<T, PairError>) -> Refusal {
        match r {
            Err(PairError::Refused(x)) => x,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn mutual_consent_and_exact_grant_open_a_service() {
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (aa, ab) = pair(&pa, &alice, &pb, &bob);
        let (x, y) = (aa.approvals(), ab.approvals());
        assert_eq!(
            (x.0, x.1),
            (y.1, y.0),
            "both sides bind the same pair of approval values"
        );
        assert_eq!(refused(pb.open(&ab, tcp(8080))), Refusal::ServiceNotGranted);
        assert!(pb.grant(&alice.ep, tcp(8080)).unwrap());
        let s = pb.open(&ab, tcp(8080)).unwrap();
        assert_eq!(
            (s.peer, s.service, s.target.clone()),
            (alice.ep, tcp(8080), None)
        );
        assert_eq!(s.start_now(|| 7).unwrap(), 7);
        for other in [udp(8080), tcp(8081), Service::Shell] {
            assert_eq!(
                refused(pb.open(&ab, other)),
                Refusal::ServiceNotGranted,
                "{other}"
            );
        }
        pb.set_default(udp(53), true).unwrap();
        pb.open(&ab, udp(53)).unwrap();
        pb.exclude(&alice.ep, udp(53)).unwrap();
        assert_eq!(refused(pb.open(&ab, udp(53))), Refusal::ServiceNotGranted);
        assert_eq!(refused(pa.open(&aa, tcp(8080))), Refusal::ServiceNotGranted);
    }

    #[test]
    fn one_sided_approval_is_not_a_pairing() {
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        pb.approve("alice", &alice.ep, false).unwrap();
        assert!(pb.grant(&alice.ep, tcp(22)).unwrap());
        pa.decline(&bob.ep).unwrap();
        let (la, lb) = link(&alice, &bob);
        let (x, y) = exchange(&pa, &la, &pb, &lb);
        assert_eq!(
            (refused(x), refused(y)),
            (Refusal::NotApproved, Refusal::RemoteDeclined)
        );
        assert!(pb.state().unwrap().pending_grants.is_empty());
        let peer = pa
            .state()
            .unwrap()
            .peers
            .into_iter()
            .find(|p| p.endpoint == bob.ep)
            .unwrap();
        pa.approve(&peer.alias, &bob.ep, false).unwrap();
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        assert_eq!(refused(pb.open(&ab, tcp(22))), Refusal::ServiceNotGranted);
    }

    #[test]
    fn a_grant_waiting_for_pairing_survives_restart_and_is_generation_bound() {
        let (n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let pa = Peers::new(&alice.dev, &oa).unwrap();
        {
            let pb = Peers::new(&bob.dev, &ob).unwrap();
            assert!(pb.grant(&alice.ep, tcp(22)).unwrap());
        }
        drop(ob);
        let bob_device = bob.reopen(&n);
        let ob = owner(&bob);
        let pb = Peers::new(&bob_device, &ob).unwrap();
        approve_both(&pa, &alice, &pb, &bob);
        let exposure = pb
            .expose(&alice.ep, tcp(23), Some("localhost:42".into()))
            .unwrap();
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        let temporary = pb.open(&ab, tcp(23)).unwrap();
        assert_eq!(temporary.target.as_deref(), Some("localhost:42"));
        drop(exposure);
        assert!(temporary.cancelled().is_some());
        assert_eq!(refused(pb.open(&ab, tcp(23))), Refusal::ServiceNotGranted);
        pb.open(&ab, tcp(22)).unwrap();
        assert!(pb.state().unwrap().pending_grants.is_empty());
        pb.approve("peer-a", &alice.ep, true).unwrap();
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        assert_eq!(refused(pb.open(&ab, tcp(22))), Refusal::ServiceNotGranted);
    }

    #[test]
    fn impersonation_and_cross_connection_replay_are_refused() {
        let (_n, alice, bob, carol) = three();
        let (oa, ob, oc) = (owner(&alice), owner(&bob), owner(&carol));
        let pa = Peers::new(&alice.dev, &oa).unwrap();
        let pb = Peers::new(&bob.dev, &ob).unwrap();
        let pc = Peers::new(&carol.dev, &oc).unwrap();
        approve_both(&pa, &alice, &pb, &bob);
        // Carol's connection to Bob is authenticated as Carol; an offer
        // naming Alice as sender is refused.
        let (_, lb_carol) = link(&carol, &bob);
        let (la, _) = link(&alice, &bob);
        let eb = pb.exchange(lb_carol).unwrap();
        let ea = pa.exchange(la).unwrap();
        assert!(matches!(
            refused(eb.on_offer(&ea.offer()).map(|_| ())),
            Refusal::StaleExchange(_)
        ));
        // A confirmation from one connection does not complete another.
        let (la1, lb1) = link(&alice, &bob);
        let (la2, lb2) = link(&alice, &bob);
        let (ea1, eb1) = (pa.exchange(la1).unwrap(), pb.exchange(lb1).unwrap());
        let (ea2, eb2) = (pa.exchange(la2).unwrap(), pb.exchange(lb2).unwrap());
        let (_c_a1, confirm_a1) = ea1.on_offer(&eb1.offer()).unwrap();
        let (c_b2, _) = eb2.on_offer(&ea2.offer()).unwrap();
        assert!(matches!(
            refused(c_b2.finish(&confirm_a1)),
            Refusal::StaleExchange(_)
        ));
        // A stranger outside the roster cannot be approved.
        let stranger = EndpointSecret::generate().public();
        assert!(matches!(
            refused(pb.approve("x", &stranger, false)),
            Refusal::NotMember(_)
        ));
        let _ = pc;
    }

    #[test]
    fn authorization_and_sessions_die_with_their_connection() {
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (la, lb) = link(&alice, &bob);
        let (_aa, ab) = exchange(&pa, &la, &pb, &lb);
        let ab = ab.unwrap();
        pb.grant(&alice.ep, tcp(80)).unwrap();
        let s = pb.open(&ab, tcp(80)).unwrap();
        lb.close();
        assert_eq!(s.start_now(|| ()), Err(Refusal::ConnectionClosed));
        assert_eq!(refused(pb.open(&ab, tcp(80))), Refusal::ConnectionClosed);
        assert_eq!(
            refused(pb.exchange(lb.clone()).map(|_| ())),
            Refusal::ConnectionClosed
        );
    }

    #[test]
    fn delayed_older_decisions_never_override_newer_ones() {
        let (n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        // Exchange X carries Alice's approval (order 1) but is delayed.
        let (lx_a, lx_b) = link(&alice, &bob);
        let (ex_a, ex_b) = (pa.exchange(lx_a).unwrap(), pb.exchange(lx_b).unwrap());
        let (ox_a, ox_b) = (ex_a.offer(), ex_b.offer());
        let (_, x_confirm_a) = ex_a.on_offer(&ox_b).unwrap();
        let (x_b, _) = ex_b.on_offer(&ox_a).unwrap();
        // Alice declines (order 2); Bob learns it on exchange Y.
        pa.decline(&bob.ep).unwrap();
        let (ly_a, ly_b) = link(&alice, &bob);
        assert_eq!(
            refused(exchange(&pa, &ly_a, &pb, &ly_b).1),
            Refusal::RemoteDeclined
        );
        // The delayed approval is older: ignored, no pairing.
        assert_eq!(refused(x_b.finish(&x_confirm_a)), Refusal::StaleDecision);
        assert!(pb.state().unwrap().peers[0].pairing.is_none());

        // Now the reverse: a delayed decline after a newer approval.
        let (lz_a, lz_b) = link(&alice, &bob);
        let (ez_a, ez_b) = (pa.exchange(lz_a).unwrap(), pb.exchange(lz_b).unwrap());
        let (oz_a, oz_b) = (ez_a.offer(), ez_b.offer());
        let (_, z_confirm_a) = ez_a.on_offer(&oz_b).unwrap();
        let (z_b, _) = ez_b.on_offer(&oz_a).unwrap();
        assert!(
            pa.approve("peer-b", &bob.ep, false).unwrap().fresh,
            "order 3"
        );
        let (_aw, bw) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, tcp(22)).unwrap();
        let s = pb.open(&bw, tcp(22)).unwrap();
        assert_eq!(refused(z_b.finish(&z_confirm_a)), Refusal::StaleDecision);
        assert!(s.cancelled().is_none(), "the newer pairing stays");
        pb.open(&bw, tcp(22)).unwrap();
        // The learned order survives a restart (new owner after the old one).
        drop((s, pb));
        drop(ob);
        let bob2 = bob.reopen(&n);
        let ob2 = Owner::acquire(&bob.path).unwrap();
        let pb2 = Peers::new(&bob2, &ob2).unwrap();
        let rec = pb2
            .state()
            .unwrap()
            .peers
            .into_iter()
            .find(|p| p.endpoint == alice.ep)
            .unwrap();
        assert_eq!(rec.remote_order, 3);
    }

    #[test]
    fn same_order_with_a_different_decision_is_a_conflict() {
        use crate::private::pairing::{Decision, PairingState};
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        // Alice's profile rolls back to the same order with another value.
        {
            let g = alice.dev.store().lock().unwrap();
            alice
                .dev
                .store()
                .update_aux(
                    &g,
                    "pairing",
                    crate::private::pairing::PAIRING_FORMAT,
                    |st: &mut PairingState| {
                        st.peers[0].local = Decision::Approve { approval: [9; 32] };
                        Ok::<_, super::super::store::StoreError>(())
                    },
                )
                .unwrap();
        }
        let (la, lb) = link(&alice, &bob);
        assert_eq!(
            refused(exchange(&pa, &la, &pb, &lb).1),
            Refusal::ConflictingDecision
        );
        pb.grant(&alice.ep, tcp(1)).unwrap();
        pb.open(&ab, tcp(1)).unwrap();
    }

    #[test]
    fn decline_reapproval_and_restart_never_revive_old_authority() {
        let (n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let pa = Peers::new(&alice.dev, &oa).unwrap();
        let pb = Peers::new(&bob.dev, &ob).unwrap();
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, Service::Shell).unwrap();
        let live = pb.open(&ab, Service::Shell).unwrap();
        pb.decline(&alice.ep).unwrap();
        assert_eq!(live.cancelled().as_deref(), Some("declined locally"));
        // The authorization itself was ended by the decline.
        assert_eq!(
            refused(pb.open(&ab, Service::Shell)),
            Refusal::Invalidated("declined locally".into())
        );
        drop((live, pb));
        drop(ob);
        let bob2 = bob.reopen(&n);
        let ob2 = Owner::acquire(&bob.path).unwrap();
        let pb2 = Peers::new(&bob2, &ob2).unwrap();
        assert!(pb2.approve("peer-a", &alice.ep, false).unwrap().fresh);
        // A proof minted under the previous runtime owner is refused outright.
        assert_eq!(
            refused(pb2.open(&ab, Service::Shell)),
            Refusal::StaleExchange("authorization from another runtime owner")
        );
        let (_aa2, ab2) = pair(&pa, &alice, &pb2, &bob);
        assert_ne!(ab2.generation(), ab.generation());
        assert_eq!(
            refused(pb2.open(&ab2, Service::Shell)),
            Refusal::ServiceNotGranted
        );
    }

    #[tokio::test]
    async fn a_pending_start_never_resumes_after_a_transition() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::Poll;
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, Service::Shell).unwrap();
        let s = pb.open(&ab, Service::Shell).unwrap();
        let ran = AtomicBool::new(false);
        let start = s.start(async {
            tokio::task::yield_now().await;
            ran.store(true, Ordering::SeqCst);
        });
        tokio::pin!(start);
        // First poll: authorized, the local step is pending.
        assert!(std::future::poll_fn(|cx| Poll::Ready(start.as_mut().poll(cx).is_pending())).await);
        // The registry lock is not held between polls, so a cutoff proceeds.
        pb.cutoff(&alice.ep).unwrap();
        assert!(matches!(start.await, Err(Refusal::Invalidated(_))));
        assert!(
            !ran.load(Ordering::SeqCst),
            "the side effect never ran after the cutoff"
        );
    }

    #[tokio::test]
    #[ignore = "opens loopback UDP sockets"]
    async fn udp_association_and_first_send_are_inside_the_boundary() {
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap();
        pb.grant(&alice.ep, udp(addr.port())).unwrap();
        let s = pb.open(&ab, udp(addr.port())).unwrap();
        // Authorized: the association and its first datagram happen.
        let sock = s
            .start(crate::udp::associate(addr, b"first"))
            .await
            .unwrap()
            .unwrap();
        let mut buf = [0u8; 16];
        let n = target.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first");
        drop(sock);
        // A new association pending between polls when the grant goes.
        let next = s.start(async {
            tokio::task::yield_now().await;
            crate::udp::associate(addr, b"second").await
        });
        tokio::pin!(next);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(next.as_mut().poll(cx).is_pending()))
                .await
        );
        pb.revoke_grant(&alice.ep, udp(addr.port())).unwrap();
        assert!(matches!(next.await, Err(Refusal::Invalidated(_))));
        let r = tokio::time::timeout(std::time::Duration::from_millis(300), target.recv(&mut buf))
            .await;
        assert!(r.is_err(), "no datagram after the grant was removed");
    }

    #[test]
    fn cutoff_survives_a_pairing_row_save_failure() {
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, tcp(5)).unwrap();
        let s = pb.open(&ab, tcp(5)).unwrap();
        fault::arm("pairing_save");
        // The durable local cutoff is returned separately from the later
        // pairing save failure and the (independent) network removal.
        let out = pb.cutoff(&alice.ep).unwrap();
        assert!(out.local_cutoff);
        assert!(out.pairing_saved.is_err());
        assert!(out.removal.is_ok(), "removal staged after the local cutoff");
        assert!(s.cancelled().is_some(), "flagged despite the failed save");
        assert_eq!(
            refused(pb.open(&ab, tcp(5))),
            Refusal::Invalidated("cut off".into())
        );
        assert!(bob.state().local_cutoffs.contains(&alice.ep));
    }

    #[test]
    fn each_applied_removal_ends_sessions_before_the_next_mailbox_wait() {
        let (n, alice, bob, carol) = three();
        let (ob, oc) = (owner(&bob), owner(&carol));
        let (pb, pc) = (
            Peers::new(&bob.dev, &ob).unwrap(),
            Peers::new(&carol.dev, &oc).unwrap(),
        );
        pb.approve("carol", &carol.ep, false).unwrap();
        pc.approve("bob", &bob.ep, false).unwrap();
        let (bc, _cb) = pair(&pb, &bob, &pc, &carol);
        pb.grant(&carol.ep, Service::Shell).unwrap();
        let s = pb.open(&bc, Service::Shell).unwrap();
        // Alice removes Carol (no owner of Alice's profile is involved here).
        alice.dev.revoke(&carol.ep).unwrap().removal.unwrap();
        alice.dev.publish().unwrap();
        alice.dev.settle().unwrap();
        // Bob's relay answers the removal slot, then stalls on the next read.
        let hung = n.mailbox.separate_handle();
        hung.gate.hang_after(1);
        let b_hung = Device::open(&bob.path, hung.clone(), Clock::System).unwrap();
        let pb_hung = Peers::new(&b_hung, &ob).unwrap();
        std::thread::scope(|sc| {
            let h = sc.spawn(|| pb_hung.advance_membership().unwrap());
            hung.gate.wait_entered(2);
            // Observed while the next read is still stalled.
            let seen = s.cancelled();
            hung.gate.release();
            assert_eq!(h.join().unwrap().1, Stop::UpToDate);
            assert_eq!(seen.as_deref(), Some("removed from the network"));
        });
    }

    #[test]
    fn reconcile_flags_sessions_even_if_the_row_save_fails() {
        let (_n, alice, bob, carol) = three();
        let (ob, oc) = (owner(&bob), owner(&carol));
        let (pb, pc) = (
            Peers::new(&bob.dev, &ob).unwrap(),
            Peers::new(&carol.dev, &oc).unwrap(),
        );
        pb.approve("carol", &carol.ep, false).unwrap();
        pc.approve("bob", &bob.ep, false).unwrap();
        let (bc, _cb) = pair(&pb, &bob, &pc, &carol);
        pb.grant(&carol.ep, Service::Shell).unwrap();
        let s = pb.open(&bc, Service::Shell).unwrap();
        alice.dev.revoke(&carol.ep).unwrap().removal.unwrap();
        alice.dev.publish().unwrap();
        alice.dev.settle().unwrap();
        sync(&[&bob]);
        fault::arm("pairing_save");
        assert!(pb.reconcile().is_err());
        assert!(s.cancelled().is_some());
        assert!(matches!(
            refused(pb.open(&bc, Service::Shell)),
            Refusal::Invalidated(_)
        ));
    }

    #[test]
    fn own_removal_ends_everything() {
        let (_n, alice, bob, carol) = three();
        let (ob, oc) = (owner(&bob), owner(&carol));
        let (pb, pc) = (
            Peers::new(&bob.dev, &ob).unwrap(),
            Peers::new(&carol.dev, &oc).unwrap(),
        );
        pb.approve("carol", &carol.ep, false).unwrap();
        pc.approve("bob", &bob.ep, false).unwrap();
        let (_bc, cb) = pair(&pb, &bob, &pc, &carol);
        pc.grant(&bob.ep, Service::Shell).unwrap();
        let s = pc.open(&cb, Service::Shell).unwrap();
        alice.dev.revoke(&carol.ep).unwrap().removal.unwrap();
        alice.dev.publish().unwrap();
        alice.dev.settle().unwrap();
        assert_eq!(pc.advance_membership().unwrap().1, Stop::Terminal);
        assert_eq!(s.cancelled().as_deref(), Some("this device was removed"));
        assert_eq!(
            refused(pc.open(&cb, Service::Shell)),
            Refusal::Invalidated("this device was removed".into())
        );
    }

    #[test]
    fn opens_racing_a_decline_never_outlive_it() {
        use crate::private::pairing::OPEN_PAUSE;
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, tcp(9001)).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        *OPEN_PAUSE.lock().unwrap() = Some((alice.ep, tx));
        std::thread::scope(|s| {
            let h = s.spawn(|| pb.open(&ab, tcp(9001)).unwrap());
            rx.recv().unwrap();
            pb.decline(&alice.ep).unwrap();
            let session = h.join().unwrap();
            assert!(matches!(session.status(), Err(Refusal::Invalidated(_))));
        });
    }

    #[test]
    fn one_runtime_owner_per_profile() {
        let (n, alice, bob, _carol) = three();
        let first = Owner::acquire(&bob.path).unwrap();
        assert_eq!(
            Owner::acquire(&bob.path).err(),
            Some(PairError::OwnedElsewhere)
        );
        // Another process cannot own it either.
        assert_eq!(owner_child(&bob.path), Some(4));
        // A Peers boundary needs the owner of its own profile.
        assert!(Peers::new(&alice.dev, &first).is_err());
        let _pb = Peers::new(&bob.dev, &first).unwrap();
        // Short local transactions by other handles still work.
        assert!(bob.reopen(&n).state().is_ok());
        drop(first);
        assert_eq!(
            owner_child(&bob.path),
            Some(0),
            "a released owner can be re-acquired (restart)"
        );
        Owner::acquire(&bob.path).unwrap();
    }

    const OWNER_ENV: &str = "MR_PRIVATE_OWNER_DIR";

    #[test]
    fn owner_child_probe() {
        let Ok(dir) = std::env::var(OWNER_ENV) else {
            return;
        };
        let code = match Owner::acquire(Path::new(&dir)) {
            Ok(_) => 0,
            Err(PairError::OwnedElsewhere) => 4,
            Err(_) => 5,
        };
        std::process::exit(code);
    }

    fn owner_child(dir: &Path) -> Option<i32> {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "private::tests::pairing::owner_child_probe",
                "--exact",
                "--test-threads=1",
            ])
            .env(OWNER_ENV, dir)
            .output()
            .unwrap()
            .status
            .code()
    }

    #[test]
    fn exclusions_persist_while_the_default_is_off() {
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        assert!(
            pb.exclude(&alice.ep, Service::Shell).unwrap(),
            "recorded with the default off"
        );
        pb.set_default(Service::Shell, true).unwrap();
        assert_eq!(
            refused(pb.open(&ab, Service::Shell)),
            Refusal::ServiceNotGranted
        );
        pb.clear_exclusion(&alice.ep, Service::Shell).unwrap();
        pb.open(&ab, Service::Shell).unwrap();
    }

    #[test]
    fn cutoff_and_decline_proceed_while_the_mailbox_is_stalled() {
        let (n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, Service::Shell).unwrap();
        let s = pb.open(&ab, Service::Shell).unwrap();
        let hung = n.mailbox.separate_handle();
        hung.gate.hang();
        let b_hung = Device::open(&bob.path, hung.clone(), Clock::System).unwrap();
        std::thread::scope(|sc| {
            let h = sc.spawn(|| b_hung.catch_up());
            hung.gate.wait_entered(1);
            assert!(pb.cutoff(&alice.ep).unwrap().local_cutoff);
            assert!(s.cancelled().is_some());
            hung.gate.release();
            let _ = h.join().unwrap();
        });
        assert!(
            bob.reopen(&n)
                .state()
                .unwrap()
                .local_cutoffs
                .contains(&alice.ep)
        );
    }

    #[test]
    fn paired_access_is_independent_of_the_relay() {
        let (n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        n.mailbox
            .offline
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(bob.dev.catch_up().1, Stop::Unavailable(_)));
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, tcp(443)).unwrap();
        pb.open(&ab, tcp(443)).unwrap().start_now(|| ()).unwrap();
    }

    #[test]
    fn aliases_bind_exact_keys() {
        let (_n, alice, bob, carol) = three();
        let ob = owner(&bob);
        let pb = Peers::new(&bob.dev, &ob).unwrap();
        pb.approve("alice", &alice.ep, false).unwrap();
        assert!(matches!(
            pb.approve("alice", &carol.ep, false),
            Err(PairError::Alias(_))
        ));
        assert!(matches!(
            pb.approve("someone", &alice.ep, false),
            Err(PairError::Alias(_))
        ));
        assert!(matches!(
            pb.approve("bad name", &carol.ep, false),
            Err(PairError::Alias(_))
        ));
        assert!(matches!(
            refused(pb.approve("me", &bob.ep, false)),
            Refusal::NotMember(_)
        ));
        assert_eq!(pb.resolve("alice").unwrap(), Some(alice.ep));
    }

    // ------------------------------------------- integrated guard tests

    #[test]
    fn removal_promotion_and_session_end_are_one_step() {
        let (_n, alice, bob, carol) = three();
        let (ob, oc) = (owner(&bob), owner(&carol));
        let (pb, pc) = (
            Peers::new(&bob.dev, &ob).unwrap(),
            Peers::new(&carol.dev, &oc).unwrap(),
        );
        pb.approve("carol", &carol.ep, false).unwrap();
        pc.approve("bob", &bob.ep, false).unwrap();
        let (bc, _cb) = pair(&pb, &bob, &pc, &carol);
        pb.grant(&carol.ep, Service::Shell).unwrap();
        let s = pb.open(&bc, Service::Shell).unwrap();
        alice.dev.revoke(&carol.ep).unwrap().removal.unwrap();
        alice.dev.publish().unwrap();
        alice.dev.settle().unwrap();
        let ran = std::sync::atomic::AtomicBool::new(false);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|sc| {
            let h = sc.spawn(move || {
                // Pause inside the gate, right after the removal is durable.
                tx.send(fault::arm_pause("after_remote_commit")).unwrap();
                pb.advance_membership().unwrap()
            });
            let paused = rx.recv().unwrap();
            paused.recv().unwrap();
            // A start attempted in exactly that interval waits for the gate
            // and then sees the session ended.
            let r = s.start_now(|| ran.store(true, std::sync::atomic::Ordering::SeqCst));
            assert!(matches!(r, Err(Refusal::Invalidated(_))), "{r:?}");
            h.join().unwrap();
        });
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn a_postcommit_cleanup_error_still_ends_sessions() {
        let (_n, alice, bob, carol) = three();
        let (ob, oc) = (owner(&bob), owner(&carol));
        let (pb, pc) = (
            Peers::new(&bob.dev, &ob).unwrap(),
            Peers::new(&carol.dev, &oc).unwrap(),
        );
        pb.approve("carol", &carol.ep, false).unwrap();
        pc.approve("bob", &bob.ep, false).unwrap();
        let (bc, _cb) = pair(&pb, &bob, &pc, &carol);
        pb.grant(&carol.ep, Service::Shell).unwrap();
        let s = pb.open(&bc, Service::Shell).unwrap();
        alice.dev.revoke(&carol.ep).unwrap().removal.unwrap();
        alice.dev.publish().unwrap();
        alice.dev.settle().unwrap();
        fault::arm("remote_cleanup");
        let (_, stop) = pb.advance_membership().unwrap();
        assert!(matches!(stop, Stop::Failed(_)), "{stop:?}");
        assert_eq!(s.cancelled().as_deref(), Some("removed from the network"));
    }

    #[tokio::test]
    async fn owner_shutdown_ends_sessions_and_wakes_a_pending_start() {
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let pa = Peers::new(&alice.dev, &oa).unwrap();
        let pb = Peers::new(&bob.dev, &ob).unwrap();
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, Service::Shell).unwrap();
        let s = pb.open(&ab, Service::Shell).unwrap();
        drop(ab);
        let _ = &pb;
        let pending = tokio::spawn(async move {
            let r = s.start(std::future::pending::<()>()).await;
            (r, s)
        });
        tokio::task::yield_now().await;
        drop(ob);
        let (r, s) = tokio::time::timeout(std::time::Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r, Err(Refusal::Invalidated("runtime owner stopped".into())));
        assert!(s.status().is_err());
        // The next owner starts clean.
        Owner::acquire(&bob.path).unwrap();
    }

    #[tokio::test]
    async fn a_pending_start_wakes_on_decline_and_on_connection_close() {
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (la, lb) = link(&alice, &bob);
        let (_aa, ab) = exchange(&pa, &la, &pb, &lb);
        let ab = ab.unwrap();
        pb.grant(&alice.ep, tcp(1)).unwrap();
        pb.grant(&alice.ep, tcp(2)).unwrap();
        let s1 = pb.open(&ab, tcp(1)).unwrap();
        let s2 = pb.open(&ab, tcp(2)).unwrap();
        let t = std::time::Duration::from_secs(5);
        // A grant removal wakes an already pending start.
        let (r, ()) = tokio::join!(
            tokio::time::timeout(t, s1.start(std::future::pending::<()>())),
            async {
                tokio::task::yield_now().await;
                pb.revoke_grant(&alice.ep, tcp(1)).unwrap();
            }
        );
        assert!(matches!(r.unwrap(), Err(Refusal::Invalidated(_))));
        // So does the connection closing.
        let (r, ()) = tokio::join!(
            tokio::time::timeout(t, s2.start(std::future::pending::<()>())),
            async {
                tokio::task::yield_now().await;
                lb.close();
            }
        );
        assert_eq!(r.unwrap(), Err(Refusal::ConnectionClosed));
    }

    #[test]
    fn a_default_exclusion_ends_default_sessions_only() {
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, Service::Shell).unwrap();
        pb.set_default(udp(53), true).unwrap();
        let explicit = pb.open(&ab, Service::Shell).unwrap();
        let inherited = pb.open(&ab, udp(53)).unwrap();
        pb.exclude(&alice.ep, Service::Shell).unwrap();
        assert!(
            explicit.cancelled().is_none(),
            "the explicit grant still permits it"
        );
        pb.open(&ab, Service::Shell).unwrap();
        pb.exclude(&alice.ep, udp(53)).unwrap();
        assert!(inherited.cancelled().is_some());
    }

    #[tokio::test]
    async fn a_local_decline_retires_an_in_flight_negotiation() {
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_la, lb) = link(&alice, &bob);
        let ex = pb.exchange(lb.clone()).unwrap();
        let (peer, snapshot) = ex.snapshot();
        // Before the decline a guarded send goes through.
        pb.guarded(&peer, snapshot, &*lb, async { 1 })
            .await
            .unwrap();
        let retired = pb.retired(&peer, snapshot);
        tokio::pin!(retired);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                retired.as_mut().poll(cx).is_pending()
            ))
            .await
        );
        pb.decline(&alice.ep).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), retired)
            .await
            .unwrap();
        // The withdrawn approval is never sent.
        assert!(matches!(
            refused(pb.guarded(&peer, snapshot, &*lb, async { 1 }).await),
            Refusal::StaleExchange(_)
        ));
    }

    #[test]
    fn unknown_keys_get_no_offer_and_records_are_size_bounded() {
        let (_n, _alice, bob, _carol) = three();
        let ob = owner(&bob);
        let pb = Peers::new(&bob.dev, &ob).unwrap();
        let stranger = EndpointSecret::generate().public();
        let l = TestLink::new(stranger, random());
        assert!(matches!(
            refused(pb.exchange(l).map(|_| ())),
            Refusal::NotMember(_)
        ));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            use crate::private::pairing::read_bounded;
            let mut huge: &[u8] = &[0, 0x0f, 0x42, 0x40, 1, 2, 3];
            assert!(matches!(
                read_bounded(&mut huge, &[106, 138]).await,
                Err(PairError::Malformed(_))
            ));
            assert_eq!(huge, &[1, 2, 3], "the body was never read");
        });
    }

    #[test]
    fn an_own_accepted_removal_ends_sessions_at_commit() {
        let (_n, alice, _bob, carol) = three();
        let (oa, oc) = (owner(&alice), owner(&carol));
        let (pa, pc) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&carol.dev, &oc).unwrap(),
        );
        pa.approve("carol", &carol.ep, false).unwrap();
        pc.approve("alice", &alice.ep, false).unwrap();
        let (ac, _ca) = pair(&pa, &alice, &pc, &carol);
        pa.grant(&carol.ep, Service::Shell).unwrap();
        let s = pa.open(&ac, Service::Shell).unwrap();
        // Alice's own removal of Carol, staged and published without the
        // registry (as a raw device step would be).
        alice.dev.stage_remove(&carol.ep).unwrap();
        alice.dev.publish().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|sc| {
            let h = sc.spawn(|| {
                tx.send(fault::arm_pause("settled_before_reconcile"))
                    .unwrap();
                pa.settle()
            });
            rx.recv().unwrap().recv().unwrap();
            // Promotion committed, reconciliation not yet run: the gate
            // already ended Carol's session at commit.
            assert_eq!(s.cancelled().as_deref(), Some("removed from the network"));
            assert!(s.status().is_err());
            assert_eq!(h.join().unwrap().unwrap(), Settle::Accepted);
        });
        assert!(ac.status().is_err(), "the authorization ended too");
    }

    #[tokio::test]
    async fn guarded_native_writes_stop_at_a_cutoff() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, tcp(5)).unwrap();
        let s = pb.open(&ab, tcp(5)).unwrap();
        let (near, mut far) = tokio::io::duplex(64);
        let mut g = s.guard(near);
        g.write_all(b"a").await.unwrap();
        assert!(pb.cutoff(&alice.ep).unwrap().local_cutoff);
        let e = g.write_all(b"b").await.unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        let e = g.shutdown().await.unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        drop(g);
        let mut got = vec![];
        far.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"a", "nothing handed over after the cutoff");
    }

    #[tokio::test]
    async fn an_authorization_is_registered_until_dropped() {
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (aa, ab) = pair(&pa, &alice, &pb, &bob);
        assert_eq!(ob.live_sessions(), 1);
        assert!(ab.status().is_ok());
        // Before any request: a local decline ends it, and `done` wakes.
        pb.decline(&alice.ep).unwrap();
        assert!(matches!(ab.status(), Err(Refusal::Invalidated(_))));
        let why = tokio::time::timeout(std::time::Duration::from_secs(1), ab.done())
            .await
            .unwrap();
        assert_eq!(why, Refusal::Invalidated("declined locally".into()));
        assert!(aa.status().is_ok(), "the other side has its own registry");
        drop(ab);
        assert_eq!(ob.live_sessions(), 0);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts a native PTY and /bin/sh"]
    async fn a_cutoff_stops_pty_input_at_the_native_boundary() {
        use crate::private::pty;
        use tokio::io::AsyncWriteExt;
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, Service::Shell).unwrap();
        let s = pb.open(&ab, Service::Shell).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        let workers = Arc::new(());
        let mut p = pty::spawn(
            80,
            24,
            Some(std::path::Path::new("/bin/sh")),
            workers.clone(),
        )
        .unwrap();
        let teardown = p.teardown();
        let mut input = s.guard(p.writer());
        let cmd = |f: &std::path::Path| format!("touch {}\r", f.display());
        input.write_all(cmd(&a).as_bytes()).await.unwrap();
        let seen = async {
            while !a.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), seen)
            .await
            .expect("authorized input runs");
        assert!(pb.cutoff(&alice.ep).unwrap().local_cutoff);
        // After the cutoff returns, the next write is refused at the guard:
        // nothing is queued anywhere between it and the PTY.
        let e = input.write_all(cmd(&b).as_bytes()).await.unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            !b.exists(),
            "input after the cutoff never reached the shell"
        );
        // Dropping the PTY wakes its idle reaper, which kills and reaps the
        // shell and releases its worker token.
        drop(input);
        drop(p);
        tokio::time::timeout(std::time::Duration::from_secs(5), teardown.wait())
            .await
            .expect("reaper exits promptly");
        assert_eq!(Arc::strong_count(&workers), 1, "no PTY worker survives");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts a native PTY and /bin/sh"]
    async fn an_idle_reaper_wakes_on_drop_and_kills_a_hangup_ignoring_shell() {
        use crate::private::pty;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // A "shell" that survives the terminal hangup on its own.
        let script = dir.path().join("stubborn");
        std::fs::write(&script, "#!/bin/sh\ntrap '' HUP\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let workers = Arc::new(());
        let mut p = pty::spawn(80, 24, Some(&script), workers.clone()).unwrap();
        let teardown = p.teardown();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let t0 = std::time::Instant::now();
        drop(p);
        // Poll the worker token (not a blocking join) so a failure here
        // cannot hang the test runtime.
        drop(teardown);
        while Arc::strong_count(&workers) > 1 && t0.elapsed() < std::time::Duration::from_secs(5) {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            Arc::strong_count(&workers),
            1,
            "the reaper woke, killed and reaped the shell"
        );
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts a native ConPTY and cmd.exe"]
    async fn a_cutoff_stops_conpty_input_at_the_native_boundary() {
        use crate::private::pty;
        use tokio::io::AsyncWriteExt;
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, Service::Shell).unwrap();
        let s = pb.open(&ab, Service::Shell).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        let workers = Arc::new(());
        // Found on PATH, as a `--shell` name would be.
        let mut p = pty::spawn(80, 24, Some(Path::new("cmd.exe")), workers.clone()).unwrap();
        let teardown = p.teardown();
        let mut input = s.guard(p.writer());
        let cmd = |f: &Path| format!("type nul > \"{}\"\r", f.display());
        input.write_all(cmd(&a).as_bytes()).await.unwrap();
        let seen = async {
            while !a.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), seen)
            .await
            .expect("authorized input runs");
        // Fill the same native nonblocking pipe implementation while its
        // read end is deliberately idle. No console host can drain it.
        let idle = pty::TestInput::new().unwrap();
        let mut blocked_input = s.guard(idle.writer());
        let payload = vec![b'x'; 1024 * 1024];
        let mut pending = std::pin::pin!(blocked_input.write_all(&payload));
        let blocked = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(std::future::Future::poll(pending.as_mut(), cx).is_pending())
        })
        .await;
        assert!(blocked, "the full input pipe must yield");

        assert!(pb.cutoff(&alice.ep).unwrap().local_cutoff);
        let denied = tokio::time::timeout(std::time::Duration::from_secs(2), pending)
            .await
            .expect("cutoff wakes the pending input")
            .unwrap_err();
        assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
        // After the cutoff returns, the next write is refused at the guard:
        // nothing is queued anywhere between it and the input pipe.
        let e = input.write_all(cmd(&b).as_bytes()).await.unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            !b.exists(),
            "input after the cutoff never reached the shell"
        );
        // Dropping the PTY wakes its idle reaper, which terminates the still
        // running shell, closes the pseudoconsole and waits for the output
        // reader (which drains output nobody consumed).
        drop(input);
        drop(p);
        tokio::time::timeout(std::time::Duration::from_secs(10), teardown.wait())
            .await
            .expect("reaper exits promptly");
        assert_eq!(Arc::strong_count(&workers), 1, "no PTY worker survives");
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "starts a native ConPTY and cmd.exe"]
    async fn a_conpty_shell_runs_input_and_reports_its_exit() {
        use crate::private::pty;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let workers = Arc::new(());
        // The default shell: %ComSpec%.
        let mut p = pty::spawn(80, 24, None, workers.clone()).unwrap();
        let teardown = p.teardown();
        let mut exited = p.take_exit();
        {
            let p = &p;
            let mut input = p.writer();
            let mut output = p.reader();
            // The echoed command line shows `%OS%`; only the expansion
            // proves the shell ran the input.
            input.write_all(b"echo massrelay-%OS%\r").await.unwrap();
            let want = b"massrelay-Windows_NT";
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            let found = async {
                while !seen.windows(want.len()).any(|w| w == want) {
                    let n = output.read(&mut buf).await.unwrap();
                    assert!(n > 0, "output ended while the shell runs");
                    seen.extend_from_slice(&buf[..n]);
                }
            };
            tokio::time::timeout(std::time::Duration::from_secs(10), found)
                .await
                .expect("the shell's output arrives");
            input.write_all(b"exit 7\r").await.unwrap();
        }
        let code = tokio::time::timeout(std::time::Duration::from_secs(10), &mut exited)
            .await
            .expect("the shell exits")
            .unwrap()
            .unwrap();
        assert_eq!(code, 7);
        // The reaper reported the exit and waits for the drop before it
        // closes the pseudoconsole.
        assert!(
            Arc::strong_count(&workers) >= 2,
            "the reaper is still alive"
        );
        drop(p);
        tokio::time::timeout(std::time::Duration::from_secs(10), teardown.wait())
            .await
            .expect("reaper exits promptly");
        assert_eq!(Arc::strong_count(&workers), 1, "no PTY worker survives");
    }

    #[test]
    fn stopping_is_permanent_and_refuses_every_new_step() {
        use crate::private::membership::Gate;
        let (_n, alice, bob, _carol) = three();
        let (oa, ob) = (owner(&alice), owner(&bob));
        let (pa, pb) = (
            Peers::new(&alice.dev, &oa).unwrap(),
            Peers::new(&bob.dev, &ob).unwrap(),
        );
        approve_both(&pa, &alice, &pb, &bob);
        let (_aa, ab) = pair(&pa, &alice, &pb, &bob);
        pb.grant(&alice.ep, Service::Shell).unwrap();
        let live = pb.open(&ab, Service::Shell).unwrap();
        // An authentication in flight on Bob when the stop linearizes.
        let (la, lb) = link(&alice, &bob);
        let ea = pa.exchange(la.clone()).unwrap();
        let eb = pb.exchange(lb.clone()).unwrap();
        let (oa_offer, ob_offer) = (ea.offer(), eb.offer());
        let (ca, confa) = ea.on_offer(&ob_offer).unwrap();
        ob.retire("runtime stopping");
        assert!(ob.stopping());
        let late = eb
            .on_offer(&oa_offer)
            .and_then(|(cb, _confb)| cb.finish(&confa));
        assert!(
            matches!(late, Err(PairError::Refused(Refusal::Stopping))),
            "no exchange commits after stop"
        );
        drop(ca);
        // Nothing new: exchange, open, start, decision, grant, cutoff, gate.
        assert!(matches!(
            pb.exchange(link(&alice, &bob).1),
            Err(PairError::Refused(Refusal::Stopping))
        ));
        assert_eq!(refused(pb.open(&ab, Service::Shell)), Refusal::Stopping);
        assert!(live.start_now(|| ()).is_err());
        assert_eq!(refused(pb.decline(&alice.ep)), Refusal::Stopping);
        assert_eq!(refused(pb.grant(&alice.ep, tcp(9))), Refusal::Stopping);
        assert_eq!(
            refused(pb.set_default(Service::Shell, true)),
            Refusal::Stopping
        );
        assert_eq!(refused(pb.cutoff(&alice.ep)), Refusal::Stopping);
        assert_eq!(refused(pb.while_running(|| ())), Refusal::Stopping);
        assert!(pb.run(|_| ()).is_none(), "the membership gate is closed");
        assert!(!pb.admits());
        assert!(!bob.state().local_cutoffs.contains(&alice.ep));
        // Permanent: a second retire changes nothing and nothing reopens.
        ob.retire("again");
        assert_eq!(refused(pb.grant(&alice.ep, tcp(9))), Refusal::Stopping);
    }
}

// ------------------------------------------- private service dispatch (Iroh)

/// Real-socket tests: disposable loopback Iroh endpoints with relays
/// disabled (direct UDP paths only; no relay or HTTPS forwarding), a native
/// PTY for the shell, and temporary loopback TCP/UDP echo fixtures. Ignored
/// by default like the legacy loopback tests; run with `--ignored`.
mod service {
    use super::*;
    use crate::private::pairing::Owner;
    use crate::private::service::{
        CLOSE_AUTHORITY_ENDED, CLOSE_NOT_AUTHORIZED, CLOSE_WRONG_PROTOCOL, Node, PrivateRequest,
        SERVICE_ALPN, ServiceStream,
    };
    use crate::wire::{self, Refusal as WireRefusal, Service, ServiceReply};
    use iroh::endpoint::{ConnectionError, RelayMode, presets};
    use iroh::{Endpoint, EndpointAddr, SecretKey};
    use std::num::NonZeroU16;
    use std::sync::Arc;
    use std::time::Duration;

    const T: Duration = Duration::from_secs(20);

    struct Peer {
        node: Arc<Node<FsMailbox>>,
        endpoint: Endpoint,
        ep: EndpointKey,
    }

    async fn endpoint(secret: &EndpointSecret, alpns: Vec<Vec<u8>>) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&secret.to_bytes()))
            .relay_mode(RelayMode::Disabled)
            .alpns(alpns)
            .bind()
            .await
            .unwrap()
    }

    fn addr(e: &Endpoint) -> EndpointAddr {
        let port = e.bound_sockets().first().map(|a| a.port()).expect("bound");
        EndpointAddr::new(e.id()).with_ip_addr(([127, 0, 0, 1], port).into())
    }

    async fn start(n: &Net, m: &Member, serve: bool) -> Peer {
        let shell = if cfg!(windows) { "cmd.exe" } else { "/bin/sh" };
        let node = Node::new(
            m.reopen(n),
            Owner::acquire(&m.path).unwrap(),
            Some(shell.into()),
        )
        .unwrap();
        let endpoint = endpoint(&m.secret, vec![SERVICE_ALPN.to_vec()]).await;
        if serve {
            tokio::spawn(node.clone().accept_loop(endpoint.clone()));
        }
        Peer {
            node,
            endpoint,
            ep: m.ep,
        }
    }

    async fn open(from: &Peer, to: &Peer, service: Service) -> ServiceStream {
        let req = PrivateRequest {
            service,
            elevated: false,
            terminal: Some((80, 24)),
        };
        tokio::time::timeout(
            T,
            from.node
                .open_service(&from.endpoint, addr(&to.endpoint), req),
        )
        .await
        .unwrap()
        .unwrap()
    }

    fn tcp(p: u16) -> Service {
        Service::Tcp(NonZeroU16::new(p).unwrap())
    }

    fn udp(p: u16) -> Service {
        Service::Udp(NonZeroU16::new(p).unwrap())
    }

    /// The runtime's membership pass alone admits an invited joiner: it
    /// reserves the queued request, stages, publishes and settles the Add,
    /// and dispatches the sealed reply. A later request on the used invite is
    /// judged and acknowledged but admits nobody.
    #[test]
    fn the_membership_pass_admits_an_invited_joiner_once() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let token = alice.dev.issue_invite().unwrap();
        let bob = sent_request(&n, &token, "bob");
        let node = Node::new(alice.reopen(&n), Owner::acquire(&alice.path).unwrap(), None).unwrap();
        let pass = node.sync_membership();
        assert!(
            matches!(&pass.requests, Ok(p) if matches!(
                &p[..],
                [Polled { verdict: Verdict::Reserved(ReserveOutcome::Reserved { .. }), .. }]
            )),
            "{pass:?}"
        );
        assert!(matches!(pass.staged, Some(Ok(()))), "{pass:?}");
        assert!(matches!(pass.settle, Ok(Settle::Accepted)), "{pass:?}");
        assert!(
            matches!(&pass.replies, Ok(r) if r[..] == [Dispatch::Sent { invite_id: bob.invite_id }]),
            "{pass:?}"
        );
        bob.m.dev.complete_join().unwrap();
        assert_eq!(node.roster().unwrap().len(), 2);

        let carol = sent_request(&n, &token, "carol");
        let pass = node.sync_membership();
        assert!(pass.staged.is_none(), "{pass:?}");
        assert!(
            matches!(&pass.requests, Ok(p) if p.iter().all(|p| !matches!(
                p.verdict,
                Verdict::Reserved(ReserveOutcome::Reserved { .. })
            ))),
            "{pass:?}"
        );
        assert_eq!(
            carol.m.dev.complete_join(),
            Err(Error::Join(JoinError::InviteUsed))
        );
        assert_eq!(node.roster().unwrap().len(), 2);
    }

    #[test]
    fn membership_retries_identical_bytes_and_restages_a_losing_removal() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let carol = join(&n, &alice, "carol", Clock::System);
        let a = Node::new(alice.reopen(&n), Owner::acquire(&alice.path).unwrap(), None).unwrap();
        let pending = sent_request(&n, &alice.dev.issue_invite().unwrap(), "dana");
        alice.dev.poll_join_requests().unwrap();
        let slot = alice.dev.stage_add(&pending.invite_id).unwrap();
        let staged = alice.state().journal.unwrap().slot_bytes;
        n.mailbox.script(
            &slot,
            Scripted {
                store_first: false,
                result: Err(MailboxError::NotStored("transient".into())),
            },
        );
        assert!(matches!(a.sync_membership().settle, Ok(Settle::Pending)));
        assert_eq!(alice.state().journal.unwrap().slot_bytes, staged);
        assert!(matches!(a.sync_membership().settle, Ok(Settle::Accepted)));
        pending.m.dev.complete_join().unwrap();

        assert!(a.cutoff(&bob.ep).unwrap().removal.is_ok());
        carol.dev.catch_up();
        let invite = carol.dev.issue_invite().unwrap();
        let next = sent_request(&n, &invite, "ellen");
        carol.dev.poll_join_requests().unwrap();
        carol.dev.stage_add(&next.invite_id).unwrap();
        carol.dev.publish().unwrap();
        assert!(matches!(
            a.sync_membership().settle,
            Ok(Settle::Lost { .. })
        ));
        assert!(alice.state().local_cutoffs.contains(&bob.ep));
        assert!(matches!(a.sync_membership().settle, Ok(Settle::Accepted)));
        assert!(!a.roster().unwrap().contains(&bob.ep));
    }

    /// Approve both ways, pair once (first request is refused for lack of a
    /// grant), then grant `services` on the destination.
    async fn authorize(src: &Peer, dst: &Peer, services: &[Service]) {
        src.node.approve("dst", &dst.ep, false).unwrap();
        dst.node.approve("src", &src.ep, false).unwrap();
        let first = open(src, dst, Service::Shell).await;
        assert!(matches!(
            first.reply,
            ServiceReply::Refused {
                refusal: WireRefusal::ServiceNotEnabled,
                ..
            }
        ));
        for s in services {
            dst.node.grant(&src.ep, *s).unwrap();
        }
    }

    async fn tcp_echo() -> (u16, tokio::sync::mpsc::UnboundedReceiver<&'static str>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (events, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let events = events.clone();
                let _ = events.send("accepted");
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => {
                                let _ = events.send("closed");
                                return;
                            }
                            Ok(n) => {
                                let _ = s.write_all(&buf[..n]).await;
                            }
                        }
                    }
                });
            }
        });
        (port, rx)
    }

    async fn udp_echo() -> (u16, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = s.local_addr().unwrap().port();
        let (seen, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut buf).await {
                let _ = seen.send(buf[..n].to_vec());
                let _ = s.send_to(&buf[..n], from).await;
            }
        });
        (port, rx)
    }

    fn datagram(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![crate::tunnel::DATA];
        f.extend_from_slice(&0u64.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    async fn closed_with(s: &ServiceStream, reason: &[u8]) {
        let e = tokio::time::timeout(T, s.conn.closed()).await.unwrap();
        match e {
            ConnectionError::ApplicationClosed(c) => assert_eq!(c.reason.as_ref(), reason),
            other => panic!("closed with {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "runs disposable loopback endpoints and a TCP target"]
    async fn direct_dial_uses_a_saved_route_after_restart() {
        let network = net();
        let alice = create(&network, "alice", Clock::System);
        let bob = join(&network, &alice, "bob", Clock::System);
        let (port, _) = tcp_echo().await;
        let service = tcp(port);
        let a = start(&network, &alice, false).await;
        let b = start(&network, &bob, true).await;
        authorize(&a, &b, &[service]).await;
        let mut stream = open(&a, &b, service).await;
        // Production client and server poll the route watcher while serving.
        tokio::select! {
            biased;
            _ = a.node.watch_routes(&stream.conn) => unreachable!(),
            _ = async {
                wire::frame(&mut stream.tx, b"\x01cached route").await.unwrap();
                assert_eq!(wire::read_frame(&mut stream.rx).await.unwrap(), b"\x01cached route");
            } => {},
        }
        drop(stream);
        a.endpoint.close().await;
        drop(a);
        let restarted = start(&network, &alice, false).await;
        let request = PrivateRequest {
            service,
            elevated: false,
            terminal: None,
        };
        let stream = tokio::time::timeout(
            T,
            restarted.node.open_service(
                &restarted.endpoint,
                EndpointAddr::new(b.endpoint.id()),
                request,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(stream.reply, ServiceReply::Ready));
        restarted.endpoint.close().await;
        b.endpoint.close().await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "runs a loopback relay and TCP target"]
    async fn encrypted_port_forward_works_with_only_a_relay_path() -> anyhow::Result<()> {
        use crate::private::pairing::PairError;
        use iroh::RelayUrl;
        use iroh_relay::server::{RelayConfig, Server, ServerConfig};

        let pair_error = |error: PairError| anyhow::anyhow!("{error:?}");
        let network = net();
        let alice = create(&network, "alice", Clock::System);
        let bob = join(&network, &alice, "bob", Clock::System);
        let source = Node::new(
            alice.reopen(&network),
            Owner::acquire(&alice.path).map_err(pair_error)?,
            None,
        )
        .map_err(pair_error)?;
        let destination = Node::new(
            bob.reopen(&network),
            Owner::acquire(&bob.path).map_err(pair_error)?,
            None,
        )
        .map_err(pair_error)?;
        source.approve("bob", &bob.ep, false).map_err(pair_error)?;
        destination
            .approve("alice", &alice.ep, false)
            .map_err(pair_error)?;
        let (port, mut events) = tcp_echo().await;
        let service = tcp(port);

        let mut config = ServerConfig::default();
        config.relay = Some(RelayConfig::new(([127, 0, 0, 1], 0)));
        let relay = Server::spawn(config).await?;
        let url: RelayUrl = format!("http://{}", relay.http_addr().unwrap()).parse()?;
        let bind = |key| {
            Endpoint::builder(presets::Minimal)
                .clear_ip_transports()
                .secret_key(key)
                .relay_mode(RelayMode::custom([url.clone()]))
                .alpns(vec![SERVICE_ALPN.to_vec()])
                .bind()
        };
        let (a, b) = tokio::try_join!(
            bind(SecretKey::from_bytes(&alice.secret.to_bytes())),
            bind(SecretKey::from_bytes(&bob.secret.to_bytes())),
        )?;
        assert!(a.bound_sockets().is_empty() && b.bound_sockets().is_empty());
        let served = tokio::spawn(destination.clone().accept_loop(b.clone()));

        tokio::time::timeout(T, async {
            b.online().await;
            let addr = EndpointAddr::new(b.id()).with_relay_url(url);
            let request = PrivateRequest {
                service,
                elevated: false,
                terminal: None,
            };
            let first = source
                .open_service(&a, addr.clone(), request)
                .await
                .map_err(pair_error)?;
            assert!(matches!(first.reply, ServiceReply::Refused { .. }));
            drop(first);
            assert!(events.try_recv().is_err());

            let ping = source
                .open_ping(&a, addr.clone())
                .await
                .map_err(pair_error)?;
            assert!(matches!(ping.reply, ServiceReply::Ready));
            assert!(ping.probe().await?.is_some());

            destination.grant(&alice.ep, service).map_err(pair_error)?;
            let mut stream = source
                .open_service(&a, addr, request)
                .await
                .map_err(pair_error)?;
            assert!(matches!(stream.reply, ServiceReply::Ready));
            wire::frame(&mut stream.tx, b"\x01opaque to the relay").await?;
            assert_eq!(
                wire::read_frame(&mut stream.rx).await?,
                b"\x01opaque to the relay"
            );
            assert_eq!(events.recv().await, Some("accepted"));
            let connections = destination.log().connections();
            assert_eq!(connections.len(), 1);
            assert_eq!(connections[0].service, service);
            assert_eq!(connections[0].route, crate::private::audit::Route::Relayed);
            assert!(
                destination
                    .cutoff(&alice.ep)
                    .map_err(pair_error)?
                    .local_cutoff
            );
            closed_with(&ping, CLOSE_AUTHORITY_ENDED).await;
            assert!(ping.probe().await.is_err());
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        a.close().await;
        b.close().await;
        served.await?;
        relay.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[cfg_attr(
        not(windows),
        ignore = "opens loopback UDP/TCP sockets and a native PTY"
    )]
    async fn shell_tcp_and_udp_dispatch_with_the_mailbox_offline() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        // Direct service needs no relay mailbox at all.
        n.mailbox
            .offline
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (tport, _tev) = tcp_echo().await;
        let (uport, mut useen) = udp_echo().await;
        let (a, b) = (start(&n, &alice, false).await, start(&n, &bob, true).await);
        authorize(&a, &b, &[Service::Shell, tcp(tport), udp(uport)]).await;

        #[cfg(not(windows))]
        {
            let req = PrivateRequest {
                service: Service::Shell,
                terminal: Some((80, 24)),
                elevated: true,
            };
            let shell =
                tokio::time::timeout(T, a.node.open_service(&a.endpoint, addr(&b.endpoint), req))
                    .await
                    .unwrap()
                    .unwrap();
            assert!(matches!(
                shell.reply,
                ServiceReply::Refused {
                    refusal: WireRefusal::TargetUnavailable,
                    ..
                }
            ));
        }

        let mut sh = open(&a, &b, Service::Shell).await;
        assert!(matches!(sh.reply, ServiceReply::Ready));
        let command: &[u8] = if cfg!(windows) {
            b"\x01echo private_^shell & exit /b 7\r"
        } else {
            b"\x01printf '%s%s\\n' private_ shell; exit 7\r"
        };
        wire::frame(&mut sh.tx, command).await.unwrap();
        let mut out = vec![];
        let code = loop {
            let f = tokio::time::timeout(T, wire::read_frame(&mut sh.rx))
                .await
                .unwrap()
                .unwrap();
            match f.split_first() {
                Some((&1, d)) => out.extend_from_slice(d),
                Some((&3, c)) => break i32::from_be_bytes(c.try_into().unwrap()),
                _ => panic!("unexpected shell frame"),
            }
        };
        assert_eq!(code, 7);
        assert!(out.windows(13).any(|w| w == b"private_shell"));

        let mut t = open(&a, &b, tcp(tport)).await;
        assert!(matches!(t.reply, ServiceReply::Ready));
        wire::frame(&mut t.tx, b"\x01hello tcp").await.unwrap();
        let f = tokio::time::timeout(T, wire::read_frame(&mut t.rx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&f[..], b"\x01hello tcp");

        let mut u = open(&a, &b, udp(uport)).await;
        assert!(matches!(u.reply, ServiceReply::Ready));
        wire::frame(&mut u.tx, &datagram(b"hello udp"))
            .await
            .unwrap();
        let f = tokio::time::timeout(T, wire::read_frame(&mut u.rx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&f[..], &datagram(b"hello udp")[..]);
        assert_eq!(useen.recv().await.unwrap(), b"hello udp");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets"]
    async fn refusals_come_before_any_privileged_action() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let carol = join(&n, &alice, "carol", Clock::System);
        sync(&[&bob]);
        let (tport, mut tev) = tcp_echo().await;
        let (other, _oev) = tcp_echo().await;
        let (a, b) = (start(&n, &alice, false).await, start(&n, &bob, true).await);
        authorize(&a, &b, &[]).await;
        // A paired peer without the grant, and an unrelated granted service.
        let s = open(&a, &b, tcp(tport)).await;
        assert!(matches!(
            s.reply,
            ServiceReply::Refused {
                refusal: WireRefusal::ServiceNotEnabled,
                ..
            }
        ));
        b.node.grant(&a.ep, tcp(other)).unwrap();
        let s = open(&a, &b, tcp(tport)).await;
        assert!(matches!(
            s.reply,
            ServiceReply::Refused {
                refusal: WireRefusal::ServiceNotEnabled,
                ..
            }
        ));
        let s = open(&a, &b, udp(tport)).await;
        assert!(matches!(
            s.reply,
            ServiceReply::Refused {
                refusal: WireRefusal::ServiceNotEnabled,
                ..
            }
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(300), tev.recv())
                .await
                .is_err(),
            "the target was never contacted"
        );
        // A member Bob never approved: the exchange fails, nothing is served.
        let c = start(&n, &carol, false).await;
        c.node.approve("bob", &b.ep, false).unwrap();
        let req = PrivateRequest {
            service: Service::Shell,
            elevated: false,
            terminal: None,
        };
        let r = tokio::time::timeout(T, c.node.open_service(&c.endpoint, addr(&b.endpoint), req))
            .await
            .unwrap();
        assert!(r.is_err(), "unapproved key must not be served");
        // The legacy service ALPN on a listener that also advertises it.
        // (A separate key, so the client's cached path for Bob is not used.)
        let both = endpoint(
            &EndpointSecret::generate(),
            vec![SERVICE_ALPN.to_vec(), wire::SERVICE.to_vec()],
        )
        .await;
        let node = b.node.clone();
        let serve_both = both.clone();
        tokio::spawn(async move {
            if let Some(i) = serve_both.accept().await
                && let Ok(conn) = i.await
            {
                node.serve_connection(conn).await;
            }
        });
        let legacy = a
            .endpoint
            .connect(addr(&both), wire::SERVICE)
            .await
            .unwrap();
        match tokio::time::timeout(T, legacy.closed()).await.unwrap() {
            ConnectionError::ApplicationClosed(c) => {
                assert_eq!(c.reason.as_ref(), CLOSE_WRONG_PROTOCOL)
            }
            other => panic!("{other:?}"),
        }
        let _ = CLOSE_NOT_AUTHORIZED;
    }

    /// First `PID=<digits>` that is complete (followed by a line end), so a
    /// prompt, escape sequence or chunk boundary cannot produce a wrong pid.
    fn pid_in(text: &str) -> Option<i32> {
        text.match_indices("PID=").find_map(|(i, _)| {
            let rest = &text[i + 4..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            let end = rest[digits.len()..].chars().next()?;
            (!digits.is_empty() && (end == '\r' || end == '\n')).then(|| digits.parse().ok())?
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets and a native PTY"]
    async fn active_cutoff_ends_shell_tcp_and_udp_sessions() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let (tport, mut tev) = tcp_echo().await;
        let (uport, _useen) = udp_echo().await;
        let (a, b) = (start(&n, &alice, false).await, start(&n, &bob, true).await);
        authorize(&a, &b, &[Service::Shell, tcp(tport), udp(uport)]).await;
        // A running shell that reports its pid, then waits.
        let mut sh = open(&a, &b, Service::Shell).await;
        wire::frame(&mut sh.tx, b"\x01echo PID=$$\r").await.unwrap();
        let mut out = vec![];
        let pid = loop {
            let f = tokio::time::timeout(T, wire::read_frame(&mut sh.rx))
                .await
                .unwrap()
                .unwrap();
            out.extend_from_slice(&f[1..]);
            if let Some(p) = pid_in(&String::from_utf8_lossy(&out)) {
                break p;
            }
        };
        let mut t = open(&a, &b, tcp(tport)).await;
        wire::frame(&mut t.tx, b"\x01x").await.unwrap();
        let _ = tokio::time::timeout(T, wire::read_frame(&mut t.rx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tev.recv().await, Some("accepted"));
        let mut u = open(&a, &b, udp(uport)).await;
        wire::frame(&mut u.tx, &datagram(b"x")).await.unwrap();
        let _ = tokio::time::timeout(T, wire::read_frame(&mut u.rx))
            .await
            .unwrap()
            .unwrap();
        // Three connection authorizations and their three service sessions.
        assert_eq!(b.node.live_sessions(), 6);

        let out = b.node.cutoff(&a.ep).unwrap();
        assert!(out.local_cutoff);
        for s in [&sh, &t, &u] {
            match tokio::time::timeout(T, s.conn.closed()).await.unwrap() {
                ConnectionError::ApplicationClosed(close) => {
                    assert_eq!(close.reason.as_ref(), CLOSE_AUTHORITY_ENDED);
                }
                // The peer can receive a stateless reset if the close frame is lost.
                // The assertions below still verify local teardown and refusal.
                ConnectionError::Reset => {}
                other => panic!("closed with {other:?}"),
            }
        }
        // The TCP target saw its connection closed.
        assert_eq!(
            tokio::time::timeout(T, tev.recv()).await.unwrap(),
            Some("closed")
        );
        // The shell process was killed and reaped.
        let gone = async {
            loop {
                let still_running = cfg!(target_os = "linux")
                    && std::path::Path::new(&format!("/proc/{pid}")).exists();
                if b.node.native_workers() == 0 && !still_running {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(T, gone)
            .await
            .expect("shell process still running");
        let gone_sessions = async {
            while b.node.live_sessions() > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(T, gone_sessions).await.unwrap();
        // A new attempt is refused before any exchange completes.
        let req = PrivateRequest {
            service: Service::Shell,
            elevated: false,
            terminal: None,
        };
        assert!(
            a.node
                .open_service(&a.endpoint, addr(&b.endpoint), req)
                .await
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP sockets"]
    async fn a_pending_udp_association_never_sends_after_a_decline() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let (uport, mut useen) = udp_echo().await;
        let (a, b) = (start(&n, &alice, false).await, start(&n, &bob, true).await);
        authorize(&a, &b, &[udp(uport)]).await;
        let mut u = open(&a, &b, udp(uport)).await;
        assert!(matches!(u.reply, ServiceReply::Ready));
        // Ready, but no association exists yet. Decline, then send.
        b.node.decline(&a.ep).unwrap();
        let _ = wire::frame(&mut u.tx, &datagram(b"late")).await;
        closed_with(&u, CLOSE_AUTHORITY_ENDED).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(300), useen.recv())
                .await
                .is_err(),
            "no first send"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP sockets"]
    async fn a_restarted_destination_requires_a_fresh_exchange() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let (tport, _tev) = tcp_echo().await;
        let (a, b) = (start(&n, &alice, false).await, start(&n, &bob, true).await);
        authorize(&a, &b, &[tcp(tport)]).await;
        let mut old = open(&a, &b, tcp(tport)).await;
        assert!(matches!(old.reply, ServiceReply::Ready));
        // Restart Bob: endpoint closed, owner released, a new owner acquired.
        b.endpoint.close().await;
        drop(b);
        let b2 = start(&n, &bob, true).await;
        assert!(
            wire::frame(&mut old.tx, b"\x01x").await.is_err() || old.conn.close_reason().is_some()
        );
        let fresh = open(&a, &b2, tcp(tport)).await;
        assert!(
            matches!(fresh.reply, ServiceReply::Ready),
            "the grant persists; consent is fresh"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets"]
    async fn a_learned_network_removal_ends_served_sessions() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let carol = join(&n, &alice, "carol", Clock::System);
        sync(&[&bob]);
        let (tport, mut tev) = tcp_echo().await;
        let (c, b) = (start(&n, &carol, false).await, start(&n, &bob, true).await);
        authorize(&c, &b, &[tcp(tport)]).await;
        let mut t = open(&c, &b, tcp(tport)).await;
        wire::frame(&mut t.tx, b"\x01x").await.unwrap();
        let _ = tokio::time::timeout(T, wire::read_frame(&mut t.rx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tev.recv().await, Some("accepted"));
        alice.dev.revoke(&carol.ep).unwrap().removal.unwrap();
        alice.dev.publish().unwrap();
        alice.dev.settle().unwrap();
        let (applied, _) = b.node.advance_membership().unwrap();
        assert_eq!(applied.len(), 1);
        closed_with(&t, CLOSE_AUTHORITY_ENDED).await;
        assert_eq!(
            tokio::time::timeout(T, tev.recv()).await.unwrap(),
            Some("closed")
        );
    }

    /// The profile's device and owner without a `Node`, to play a
    /// misbehaving peer through the real exchange.
    fn raw(n: &Net, m: &Member) -> (Device<FsMailbox>, Owner) {
        (m.reopen(n), Owner::acquire(&m.path).unwrap())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP sockets"]
    async fn a_partial_request_is_cancelled_by_a_cutoff() {
        use crate::private::pairing::Peers;
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let b = start(&n, &bob, true).await;
        let (da, oa) = raw(&n, &alice);
        let pa = Peers::new(&da, &oa).unwrap();
        pa.approve("bob", &bob.ep, false).unwrap();
        b.node.approve("alice", &alice.ep, false).unwrap();
        let ea = endpoint(&alice.secret, vec![SERVICE_ALPN.to_vec()]).await;
        let conn = ea.connect(addr(&b.endpoint), SERVICE_ALPN).await.unwrap();
        let (_auth, mut tx, _rx) = tokio::time::timeout(T, pa.authorize(&conn, true))
            .await
            .unwrap()
            .unwrap();
        // The request's length prefix and three of its eight bytes.
        tx.write_all(&[0, 0, 0, 8, 1, 1, 0]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(b.node.live_sessions(), 1, "the authorization is registered");
        assert!(b.node.cutoff(&alice.ep).unwrap().local_cutoff);
        match tokio::time::timeout(T, conn.closed()).await.unwrap() {
            ConnectionError::ApplicationClosed(c) => {
                assert_eq!(c.reason.as_ref(), CLOSE_AUTHORITY_ENDED)
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP sockets"]
    async fn an_oversized_reply_is_refused_before_it_is_buffered() {
        use crate::private::pairing::{Peers, read_bounded};
        use crate::private::service::max_reply_len;
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let a = start(&n, &alice, false).await;
        a.node.approve("bob", &bob.ep, false).unwrap();
        let (db, ob) = raw(&n, &bob);
        let eb = endpoint(&bob.secret, vec![SERVICE_ALPN.to_vec()]).await;
        let (ready, approved) = tokio::sync::oneshot::channel();
        let alice_ep = alice.ep;
        let hostile_ep = eb.clone();
        let hostile = tokio::spawn(async move {
            let pb = Peers::new(&db, &ob).unwrap();
            pb.approve("alice", &alice_ep, false).unwrap();
            ready.send(()).unwrap();
            let conn = hostile_ep.accept().await.unwrap().await.unwrap();
            let (_auth, mut tx, mut rx) = pb.authorize(&conn, false).await.unwrap();
            read_bounded(&mut rx, &[8]).await.unwrap();
            // One byte longer than any private reply can be.
            let _ = wire::frame(&mut tx, &vec![b' '; max_reply_len() + 1]).await;
            let _ = conn.closed().await;
        });
        approved.await.unwrap();
        let req = PrivateRequest {
            service: Service::Shell,
            elevated: false,
            terminal: None,
        };
        let r = tokio::time::timeout(T, a.node.open_service(&a.endpoint, addr(&eb), req))
            .await
            .unwrap();
        match r {
            Err(crate::private::pairing::PairError::Local(m)) => {
                assert!(m.contains("longer than the format allows"), "{m}")
            }
            Err(e) => panic!("{e:?}"),
            Ok(_) => panic!("an oversized reply was accepted"),
        }
        hostile.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP sockets; waits for the drain bound"]
    async fn a_finished_reply_drains_then_closes_without_the_dialer() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let (a, b) = (start(&n, &alice, false).await, start(&n, &bob, true).await);
        a.node.approve("bob", &b.ep, false).unwrap();
        b.node.approve("alice", &a.ep, false).unwrap();
        let s = open(&a, &b, Service::Shell).await;
        assert!(matches!(s.reply, ServiceReply::Refused { .. }));
        // The dialer keeps the connection open and never closes it.
        let t0 = std::time::Instant::now();
        closed_with(&s, crate::private::service::CLOSE_DONE).await;
        let waited = t0.elapsed();
        assert!(
            waited >= wire::RPC_TIMEOUT - Duration::from_secs(1),
            "{waited:?}"
        );
        assert_eq!(b.node.live_sessions(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP sockets"]
    async fn early_data_is_never_served() {
        use iroh::endpoint::{ConnectOptions, ZeroRttStatus};
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let (a, b) = (start(&n, &alice, false).await, start(&n, &bob, true).await);
        // A full handshake first, so Alice holds resumption state for Bob.
        authorize(&a, &b, &[Service::Shell]).await;
        let connecting = a
            .endpoint
            .connect_with_opts(addr(&b.endpoint), SERVICE_ALPN, ConnectOptions::new())
            .await
            .unwrap();
        let zc = match connecting.into_0rtt() {
            Ok(zc) => zc,
            Err(_) => {
                eprintln!("0-RTT not attempted: no resumption state was available");
                return;
            }
        };
        let (mut tx, _rx) = zc.open_bi().await.unwrap();
        // Early bytes shaped like an offer's length prefix.
        let early = wire::frame(&mut tx, &[1u8; 106]).await;
        match zc.handshake_completed().await.unwrap() {
            ZeroRttStatus::Accepted(conn) => {
                eprintln!("0-RTT accepted by the transport (early write: {early:?})");
                // The destination refuses the early-data stream outright.
                match tokio::time::timeout(T, conn.closed()).await.unwrap() {
                    ConnectionError::ApplicationClosed(c) => {
                        assert_eq!(c.reason.as_ref(), CLOSE_NOT_AUTHORIZED)
                    }
                    other => panic!("{other:?}"),
                }
            }
            ZeroRttStatus::Rejected(conn) => {
                eprintln!("0-RTT rejected by the transport; early data was discarded");
                conn.close(0u32.into(), b"done");
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets"]
    async fn the_exact_grant_guards_the_final_drain() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        // A target that closes at once, so the service finishes cleanly.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                drop(s);
            }
        });
        let (a, b) = (start(&n, &alice, false).await, start(&n, &bob, true).await);
        authorize(&a, &b, &[tcp(port)]).await;
        let mut t = open(&a, &b, tcp(port)).await;
        assert!(matches!(t.reply, ServiceReply::Ready));
        wire::frame(&mut t.tx, &[crate::tunnel::EOF]).await.unwrap();
        loop {
            let f = tokio::time::timeout(T, wire::read_frame(&mut t.rx))
                .await
                .unwrap()
                .unwrap();
            if f == [3] {
                break;
            }
        }
        // The destination is draining; the dialer keeps the connection.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let t0 = std::time::Instant::now();
        assert!(b.node.revoke_grant(&a.ep, tcp(port)).unwrap());
        closed_with(&t, CLOSE_AUTHORITY_ENDED).await;
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    }
}

// ------------------------------------------ private foreground runtime (Iroh)

/// The runtime through its normal entry points: `Runtime::start`, the
/// private control channel (`runtime::request`) and `Runtime::stop`, over
/// loopback Iroh endpoints with relays disabled.
mod runtime {
    use super::*;
    use crate::private::codec::hex;
    use crate::private::pairing::{Owner, PairError};
    use crate::private::runtime::{
        self as rt, CONTROL, Config, ControlReply, ControlRequest, Runtime, Stopped, offline_status,
    };
    use crate::private::service::SERVICE_ALPN;
    use crate::wire::{self, Service};
    use iroh::endpoint::{RelayMode, presets};
    use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
    use std::collections::BTreeMap;
    use std::num::NonZeroU16;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const T: Duration = Duration::from_secs(20);
    type Book = Arc<Mutex<BTreeMap<EndpointKey, EndpointAddr>>>;

    async fn endpoint(secret: &EndpointSecret) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&secret.to_bytes()))
            .relay_mode(RelayMode::Disabled)
            .alpns(vec![SERVICE_ALPN.to_vec()])
            .bind()
            .await
            .unwrap()
    }

    fn addr(e: &Endpoint) -> EndpointAddr {
        let port = e.bound_sockets().first().map(|a| a.port()).expect("bound");
        EndpointAddr::new(e.id()).with_ip_addr(([127, 0, 0, 1], port).into())
    }

    /// Releases a hung gate when dropped, so a failing assertion cannot
    /// leave a blocked mailbox call holding the test runtime open.
    struct Release(Arc<crate::private::fake_mailbox::Gate>);

    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    async fn run(
        m: &Member,
        book: &Book,
        mailbox: FsMailbox,
        sync: Option<Duration>,
    ) -> Runtime<FsMailbox> {
        let e = endpoint(&m.secret).await;
        book.lock().unwrap().insert(m.ep, addr(&e));
        let b = book.clone();
        let mut cfg = Config::new(&m.path);
        cfg.shell = Some("/bin/sh".into());
        cfg.sync_every = sync;
        cfg.addresses = Arc::new(move |k| b.lock().unwrap().get(k).cloned());
        Runtime::start(cfg, mailbox, Clock::System, e)
            .await
            .unwrap()
    }

    async fn cmd(m: &Member, r: ControlRequest) -> ControlReply {
        tokio::time::timeout(T, rt::request(&m.path, r))
            .await
            .unwrap()
            .unwrap()
            .1
    }

    fn key(m: &Member) -> String {
        hex(&m.ep)
    }

    fn tcp(p: u16) -> Service {
        Service::Tcp(NonZeroU16::new(p).unwrap())
    }

    /// Ask for a shell through control, with its own lifetime socket.
    async fn shell_to(
        m: &Member,
        peer: &str,
    ) -> (
        tokio::net::TcpStream,
        ControlReply,
        Option<tokio::net::TcpStream>,
    ) {
        let life = crate::local::Lifetime::bind().await.unwrap();
        let req = ControlRequest::Shell {
            elevated: false,
            peer: peer.into(),
            cols: 80,
            rows: 24,
            lifetime_port: life.port,
            lifetime_key: life.key,
        };
        let (sock, r) = tokio::time::timeout(T, rt::request(&m.path, req))
            .await
            .unwrap()
            .unwrap();
        let keep = tokio::time::timeout(Duration::from_secs(2), life.accept())
            .await
            .ok()
            .and_then(Result::ok);
        (sock, r, keep)
    }

    fn approve(peer: &Member, alias: &str) -> ControlRequest {
        ControlRequest::Approve {
            peer: key(peer),
            alias: alias.into(),
            reapprove: false,
        }
    }

    fn connect(peer: &str, service: Service, l: &crate::local::Lifetime) -> ControlRequest {
        ControlRequest::Connect {
            peer: peer.into(),
            service,
            lifetime_port: l.port,
            lifetime_key: l.key,
        }
    }

    /// A TCP target that answers `bye:<everything it read>` after its
    /// input ends, then closes; it reports "closed" when a peer goes away.
    async fn half_close_target() -> (u16, tokio::sync::mpsc::UnboundedReceiver<&'static str>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (events, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let events = events.clone();
                tokio::spawn(async move {
                    let mut got = b"bye:".to_vec();
                    let mut buf = [0u8; 1024];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                            Err(_) => {
                                let _ = events.send("closed");
                                return;
                            }
                        }
                    }
                    let _ = events.send("eof");
                    if s.write_all(&got).await.is_err() {
                        let _ = events.send("closed");
                        return;
                    }
                    let _ = s.shutdown().await;
                    let _ = events.send("closed");
                });
            }
        });
        (port, rx)
    }

    /// Read tunnel frames from a local command socket until DONE or FAILED.
    async fn drain(sock: &mut tokio::net::TcpStream) -> (Vec<u8>, Option<String>) {
        let mut got = vec![];
        loop {
            let f = match tokio::time::timeout(T, wire::read_frame(sock))
                .await
                .unwrap()
            {
                Ok(f) => f,
                Err(_) => return (got, None),
            };
            match f.split_first() {
                Some((1, data)) => got.extend_from_slice(data),
                Some((2, [])) => {}
                Some((3, [])) => return (got, None),
                Some((4, m)) => return (got, Some(String::from_utf8_lossy(m).into())),
                other => panic!("unexpected frame {other:?}"),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets"]
    async fn control_is_separate_authenticated_and_owner_exclusive() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let book = Book::default();
        let rb = run(&bob, &book, n.mailbox.clone(), None).await;
        assert!(bob.path.join(CONTROL.marker).exists());
        assert!(!bob.path.join("runtime.json").exists());
        // Legacy roles cannot authenticate on the private marker.
        let legacy_roles = crate::local::Channel {
            marker: CONTROL.marker,
            daemon_role: b"massrelay daemon v1",
            client_role: b"massrelay client v1",
            ..CONTROL
        };
        assert!(
            crate::local::connect_on(&bob.path, &legacy_roles)
                .await
                .is_err()
        );
        // The wrong local key fails before any command is read.
        let wrong = tempfile::tempdir().unwrap();
        let raw = std::fs::read(bob.path.join(CONTROL.marker)).unwrap();
        let mut marker: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        marker["key"] = serde_json::json!(vec![0u8; 32]);
        std::fs::write(
            wrong.path().join(CONTROL.marker),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        assert!(
            crate::local::connect_on(wrong.path(), &CONTROL)
                .await
                .is_err()
        );
        // The owner answers status.
        let ControlReply::Status(v) = cmd(&bob, ControlRequest::Status).await else {
            panic!("status");
        };
        assert!(v.running);
        assert_eq!(v.endpoint, key(&bob));
        // A second runtime on the profile is refused; a second process
        // still reads status, without the owner.
        let second = Runtime::start(
            Config::new(&bob.path),
            n.mailbox.clone(),
            Clock::System,
            endpoint(&bob.secret).await,
        )
        .await;
        assert!(matches!(second.err(), Some(PairError::OwnedElsewhere)));
        assert!(matches!(
            Owner::acquire(&bob.path),
            Err(PairError::OwnedElsewhere)
        ));
        let offline = offline_status(&bob.reopen(&n)).unwrap();
        assert!(!offline.running);
        assert_eq!(offline.endpoint, key(&bob));
        // The wrong endpoint for a profile is refused, and its owner released.
        let r = Runtime::start(
            Config::new(&alice.path),
            n.mailbox.clone(),
            Clock::System,
            endpoint(&bob.secret).await,
        )
        .await;
        assert!(matches!(
            r.err(),
            Some(PairError::Local(m)) if m.contains("not this profile's endpoint")
        ));
        drop(Owner::acquire(&alice.path).unwrap());
        // Ordered stop: owner released, marker gone, control unavailable.
        assert_eq!(
            rb.stop().await,
            Stopped {
                aborted: vec![],
                native_workers: 0,
                owner_released: true
            }
        );
        assert!(!bob.path.join(CONTROL.marker).exists());
        assert!(
            rt::request(&bob.path, ControlRequest::Status)
                .await
                .is_err()
        );
        drop(Owner::acquire(&bob.path).unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets"]
    async fn decisions_defaults_and_aliases_persist_across_restart() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let book = Book::default();
        let rb = run(&bob, &book, n.mailbox.clone(), None).await;
        // Nothing resolves a name this device never pinned.
        let by_name = ControlRequest::Approve {
            peer: "alice".into(),
            alias: "alice".into(),
            reapprove: false,
        };
        assert!(matches!(cmd(&bob, by_name).await, ControlReply::Error(_)));
        // An alias cannot pose as a key.
        let posing = ControlRequest::Approve {
            peer: key(&alice),
            alias: hex(&[9u8; 32]),
            reapprove: false,
        };
        assert!(matches!(cmd(&bob, posing).await, ControlReply::Error(_)));
        assert!(matches!(
            cmd(&bob, approve(&alice, "alice")).await,
            ControlReply::Approved { fresh: true, .. }
        ));
        let set = |service, enabled| ControlRequest::SetDefault { service, enabled };
        assert_eq!(
            cmd(&bob, set(Service::Shell, true)).await,
            ControlReply::Changed(true)
        );
        assert_eq!(
            cmd(&bob, set(tcp(8080), true)).await,
            ControlReply::Changed(true)
        );
        let exclude = ControlRequest::Exclude {
            peer: "alice".into(),
            service: Service::Shell,
        };
        assert_eq!(cmd(&bob, exclude).await, ControlReply::Changed(true));
        assert!(rb.stop().await.owner_released);

        let rb = run(&bob, &book, n.mailbox.clone(), None).await;
        let ControlReply::Status(v) = cmd(&bob, ControlRequest::Status).await else {
            panic!("status");
        };
        assert!(v.defaults.contains(&Service::Shell) && v.defaults.contains(&tcp(8080)));
        assert_eq!(v.exclusions, vec![(key(&alice), Service::Shell)]);
        let p = v.peers.iter().find(|p| p.key == key(&alice)).unwrap();
        assert_eq!(p.alias.as_deref(), Some("alice"));
        assert_eq!(p.local, "approved");
        assert_eq!(p.remote, "none", "nothing proved on an exchange yet");
        assert!(p.member);
        // The pinned alias still selects the key after the restart.
        let clear = ControlRequest::ClearExclusion {
            peer: "alice".into(),
            service: Service::Shell,
        };
        assert_eq!(cmd(&bob, clear).await, ControlReply::Changed(true));
        assert!(rb.stop().await.owner_released);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets and a native PTY"]
    async fn shell_and_port_connect_through_control() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let carol = join(&n, &alice, "carol", Clock::System);
        sync(&[&bob]);
        let book = Book::default();
        let ra = run(&alice, &book, n.mailbox.clone(), None).await;
        let rb = run(&bob, &book, n.mailbox.clone(), None).await;
        cmd(&alice, approve(&bob, "bob")).await;
        cmd(&bob, approve(&alice, "alice")).await;
        // The first exchange pairs; nothing is granted yet.
        let (_, r, _) = shell_to(&alice, "bob").await;
        assert!(
            matches!(&r, ControlReply::Error(e) if e.contains("not authorized")),
            "{r:?}"
        );
        let enable = |service| ControlRequest::Enable {
            peer: "alice".into(),
            service,
        };
        assert_eq!(
            cmd(&bob, enable(Service::Shell)).await,
            ControlReply::Changed(true)
        );

        // Shell, with the configured shell override.
        let (mut sh, r, _life) = shell_to(&alice, "bob").await;
        assert_eq!(r, ControlReply::Shell);
        wire::frame(&mut sh, b"\x01printf '%s%s\\n' private_ control; exit 5\r")
            .await
            .unwrap();
        let mut out = vec![];
        let code = loop {
            let f = tokio::time::timeout(T, wire::read_frame(&mut sh))
                .await
                .unwrap()
                .unwrap();
            match f.split_first() {
                Some((1, data)) => out.extend_from_slice(data),
                Some((3, code)) => break i32::from_be_bytes(code.try_into().unwrap()),
                _ => {}
            }
        };
        assert_eq!(code, 5);
        assert!(String::from_utf8_lossy(&out).contains("private_control"));
        drop(sh);

        // TCP: an upload half-close keeps the download open.
        let (port, mut tev) = half_close_target().await;
        assert_eq!(
            cmd(&bob, enable(tcp(port))).await,
            ControlReply::Changed(true)
        );
        let life = crate::local::Lifetime::bind().await.unwrap();
        let ((mut sock, r), keep) = tokio::try_join!(
            rt::request(&alice.path, connect("bob", tcp(port), &life)),
            life.accept()
        )
        .unwrap();
        assert_eq!(r, ControlReply::Connected);

        // Renaming the remote peer on the granting device preserves both
        // its authorization on this connection and its persistent grant.
        let rename = |peer: &str, alias: &str| ControlRequest::Rename {
            peer: peer.into(),
            alias: alias.into(),
        };
        assert!(matches!(
            cmd(&bob, approve(&carol, "carol")).await,
            ControlReply::Approved { fresh: true, .. }
        ));
        let before = crate::private::pairing::read_state(&bob.dev).unwrap();
        let mut expected = before.peer(&alice.ep).unwrap().clone();
        assert!(expected.pairing.is_some());
        for unavailable in ["carol".to_owned(), key(&carol)] {
            assert!(matches!(
                cmd(&bob, rename("alice", &unavailable)).await,
                ControlReply::Error(_)
            ));
        }
        assert_eq!(
            cmd(&bob, rename("alice", "workstation")).await,
            ControlReply::Changed(true)
        );
        assert_eq!(
            cmd(&bob, rename(&key(&alice), "workstation")).await,
            ControlReply::Changed(false)
        );
        let after = crate::private::pairing::read_state(&bob.dev).unwrap();
        expected.alias = "workstation".into();
        assert_eq!(after.peer(&alice.ep), Some(&expected));
        assert_eq!(after.peer(&carol.ep), before.peer(&carol.ep));
        let enable_port = |peer: &str| ControlRequest::Enable {
            peer: peer.into(),
            service: tcp(port),
        };
        assert!(matches!(
            cmd(&bob, enable_port("alice")).await,
            ControlReply::Error(_)
        ));
        assert_eq!(
            cmd(&bob, enable_port("workstation")).await,
            ControlReply::Changed(false)
        );
        let ControlReply::Status(status) = cmd(&bob, ControlRequest::Status).await else {
            panic!("status");
        };
        assert!(status.grants.contains(&(key(&alice), tcp(port))));
        let peer = status.peers.iter().find(|p| p.key == key(&alice)).unwrap();
        assert_eq!(peer.alias.as_deref(), Some("workstation"));
        assert!(peer.paired);

        wire::frame(&mut sock, b"\x01hello").await.unwrap();
        wire::frame(&mut sock, &[crate::tunnel::EOF]).await.unwrap();
        assert_eq!(drain(&mut sock).await, (b"bye:hello".to_vec(), None));
        assert_eq!(tev.recv().await, Some("eof"));
        drop((sock, keep));

        // The local command leaving ends the session on both devices.
        let life = crate::local::Lifetime::bind().await.unwrap();
        let ((mut sock, r), keep) = tokio::try_join!(
            rt::request(&alice.path, connect("bob", tcp(port), &life)),
            life.accept()
        )
        .unwrap();
        assert_eq!(r, ControlReply::Connected);
        wire::frame(&mut sock, b"\x01x").await.unwrap();
        drop((sock, keep));
        let closed = async {
            loop {
                match tev.recv().await {
                    Some("closed") => return,
                    Some(_) => {}
                    None => panic!("target gone"),
                }
            }
        };
        tokio::time::timeout(T, closed).await.unwrap();

        // The address book cannot redirect a selected key to another endpoint.
        let real = book.lock().unwrap().insert(
            bob.ep,
            EndpointAddr::new(EndpointId::from_bytes(&carol.ep).unwrap()),
        );
        let (_, r, _) = shell_to(&alice, "bob").await;
        assert!(
            matches!(&r, ControlReply::Error(e) if e.contains("different endpoint")),
            "{r:?}"
        );
        book.lock().unwrap().insert(bob.ep, real.unwrap());

        // A local decline on the initiating device ends its outbound session.
        let life = crate::local::Lifetime::bind().await.unwrap();
        let ((mut sock, r), keep) = tokio::try_join!(
            rt::request(&alice.path, connect("bob", tcp(port), &life)),
            life.accept()
        )
        .unwrap();
        assert_eq!(r, ControlReply::Connected);
        let decline = ControlRequest::Decline { peer: "bob".into() };
        assert_eq!(cmd(&alice, decline).await, ControlReply::Done);
        let (_, failed) = drain(&mut sock).await;
        assert_eq!(
            failed.as_deref(),
            Some("the authorization ended on this device")
        );
        // The command exits after its final frame.
        drop((sock, keep));

        // Stopping a runtime ends its live sessions before its owner goes.
        let again = ControlRequest::Approve {
            peer: key(&bob),
            alias: "bob".into(),
            reapprove: true,
        };
        assert!(matches!(
            cmd(&alice, again).await,
            ControlReply::Approved { .. }
        ));
        let default = ControlRequest::SetDefault {
            service: Service::Shell,
            enabled: true,
        };
        assert_eq!(cmd(&bob, default).await, ControlReply::Changed(true));
        let (mut sh, r, _life) = shell_to(&alice, "bob").await;
        assert_eq!(r, ControlReply::Shell);
        assert_eq!(
            rb.stop().await,
            Stopped {
                aborted: vec![],
                native_workers: 0,
                owner_released: true
            }
        );
        let ended = async { while wire::read_frame(&mut sh).await.is_ok() {} };
        tokio::time::timeout(T, ended).await.unwrap();
        drop(sh);
        let log = events(&bob);
        for (event, alias) in [
            ("approval_granted", "alice"),
            ("peer_alias_renamed", "workstation"),
            ("disconnected", "workstation"),
        ] {
            assert!(
                find(&log, &[("event", event), ("peer_name", alias)]).is_some(),
                "missing {event} for {alias}"
            );
        }
        assert_eq!(
            ra.stop().await,
            Stopped {
                aborted: vec![],
                native_workers: 0,
                owner_released: true
            }
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets"]
    async fn local_cutoff_proceeds_while_the_membership_pass_is_stalled() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let book = Book::default();
        // Bob's relay stalls on every network step.
        let hung = n.mailbox.separate_handle();
        hung.gate.hang();
        let _release = Release(hung.gate.clone());
        let rb = run(&bob, &book, hung.clone(), Some(Duration::from_millis(20))).await;
        let ra = run(&alice, &book, n.mailbox.clone(), None).await;
        cmd(&alice, approve(&bob, "bob")).await;
        cmd(&bob, approve(&alice, "alice")).await;
        let (port, mut tev) = half_close_target().await;
        let life = crate::local::Lifetime::bind().await.unwrap();
        let first = cmd(&alice, connect("bob", tcp(port), &life)).await;
        assert!(matches!(first, ControlReply::Error(_)), "not granted yet");
        let enable = ControlRequest::Enable {
            peer: "alice".into(),
            service: tcp(port),
        };
        assert_eq!(cmd(&bob, enable).await, ControlReply::Changed(true));
        // Bob's membership pass is now blocked inside the mailbox.
        let gate = hung.gate.clone();
        tokio::task::spawn_blocking(move || gate.wait_entered(1))
            .await
            .unwrap();

        let life = crate::local::Lifetime::bind().await.unwrap();
        let ((mut sock, r), _keep) = tokio::try_join!(
            rt::request(&alice.path, connect("bob", tcp(port), &life)),
            life.accept()
        )
        .unwrap();
        assert_eq!(r, ControlReply::Connected);
        wire::frame(&mut sock, b"\x01live").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Bob's local cutoff completes at once and ends the active session.
        let t0 = std::time::Instant::now();
        let revoke = ControlRequest::Revoke {
            peer: "alice".into(),
        };
        let r = tokio::time::timeout(Duration::from_secs(5), rt::command(&bob.path, revoke))
            .await
            .expect("cutoff waited for the stalled mailbox")
            .unwrap();
        assert!(matches!(r, ControlReply::CutOff { .. }), "{r:?}");
        assert!(t0.elapsed() < Duration::from_secs(5));
        assert_eq!(
            cmd(&bob, ControlRequest::Peers).await,
            ControlReply::Peers(vec![])
        );
        assert!(
            rt::offline_status(&bob.reopen(&n))
                .unwrap()
                .peers
                .is_empty()
        );
        let (_, failed) = drain(&mut sock).await;
        assert_eq!(
            failed.as_deref(),
            Some("the destination ended this authorization")
        );
        let closed = async {
            loop {
                if tev.recv().await == Some("closed") {
                    return;
                }
            }
        };
        tokio::time::timeout(T, closed).await.unwrap();
        assert!(
            bob.reopen(&n)
                .state()
                .unwrap()
                .local_cutoffs
                .contains(&alice.ep)
        );

        // Stop while the pass is still blocked: everything else stops, and
        // the owner is held only by that pass until it returns.
        let stopped = rb.stop().await;
        assert_eq!(stopped.aborted, Vec::<&str>::new());
        assert!(!stopped.owner_released);
        assert!(matches!(
            Owner::acquire(&bob.path),
            Err(PairError::OwnedElsewhere)
        ));
        hung.gate.release();
        let released = async {
            loop {
                if Owner::acquire(&bob.path).is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(T, released).await.unwrap();
        assert!(ra.stop().await.owner_released);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets"]
    async fn stop_linearizes_before_an_in_flight_control_command() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let book = Book::default();
        let rb = run(&bob, &book, n.mailbox.clone(), None).await;
        // Authenticated, request not yet sent.
        let mut sock = crate::local::connect_on(&bob.path, &CONTROL).await.unwrap();
        let stopping = tokio::spawn(rb.stop());
        // Stop retires before it removes the marker.
        let gone = async {
            while bob.path.join(CONTROL.marker).exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(T, gone).await.unwrap();
        wire::send(&mut sock, approve(&alice, "alice"))
            .await
            .unwrap();
        let reply: ControlReply = tokio::time::timeout(T, wire::recv(&mut sock))
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(&reply, ControlReply::Error(e) if e.to_lowercase().contains("stopping")),
            "{reply:?}"
        );
        assert_eq!(
            stopping.await.unwrap(),
            Stopped {
                aborted: vec![],
                native_workers: 0,
                owner_released: true
            }
        );
        let v = offline_status(&bob.reopen(&n)).unwrap();
        assert!(
            v.peers.iter().all(|p| p.local != "approved"),
            "nothing was applied"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets; waits for the stop bound"]
    async fn a_stopped_membership_pass_neither_applies_nor_calls_again() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let carol = join(&n, &alice, "carol", Clock::System);
        sync(&[&bob]);
        let head = bob.head();
        // A transport without a working stop seam, stalled on every step.
        let hung = n.mailbox.separate_handle();
        hung.gate.hang();
        let _release = Release(hung.gate.clone());
        let book = Book::default();
        let rb = run(&bob, &book, hung.clone(), Some(Duration::from_millis(20))).await;
        let gate = hung.gate.clone();
        tokio::task::spawn_blocking(move || gate.wait_entered(1))
            .await
            .unwrap();
        // A new slot appears while Bob's read is blocked.
        alice.dev.revoke(&carol.ep).unwrap().removal.unwrap();
        alice.dev.publish().unwrap();
        alice.dev.settle().unwrap();
        let stopped = rb.stop().await;
        assert!(!stopped.owner_released, "the blocked call still holds it");
        let entered = hung.gate.entered();
        hung.gate.release();
        let released = async {
            while Owner::acquire(&bob.path).is_err() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(T, released).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(hung.gate.entered(), entered, "no mailbox call afterwards");
        assert_eq!(bob.reopen(&n).state().unwrap().net.unwrap().head, head);
        // The slot was there: a later pass applies it.
        let (applied, _) = bob.reopen(&n).catch_up();
        assert_eq!(applied.len(), 1, "nothing was applied during the stop");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets"]
    async fn the_stop_seam_ends_a_stalled_call_and_releases_the_owner() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let hung = n.mailbox.separate_handle();
        hung.gate.support_shutdown();
        hung.gate.hang();
        let _release = Release(hung.gate.clone());
        let book = Book::default();
        let rb = run(&bob, &book, hung.clone(), Some(Duration::from_millis(20))).await;
        let gate = hung.gate.clone();
        tokio::task::spawn_blocking(move || gate.wait_entered(1))
            .await
            .unwrap();
        let t0 = std::time::Instant::now();
        assert_eq!(
            rb.stop().await,
            Stopped {
                aborted: vec![],
                native_workers: 0,
                owner_released: true
            }
        );
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
        drop(Owner::acquire(&bob.path).unwrap());
        assert_eq!(hung.gate.entered(), 1, "no call after the cancelled one");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets and a native PTY"]
    async fn a_departing_command_ends_its_session_at_once() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let carol = join(&n, &alice, "carol", Clock::System);
        let book = Book::default();
        let ra = run(&alice, &book, n.mailbox.clone(), None).await;
        let rb = run(&bob, &book, n.mailbox.clone(), None).await;
        cmd(&alice, approve(&bob, "bob")).await;
        cmd(&bob, approve(&alice, "alice")).await;
        let (mut ping, reply) = rt::request(
            &alice.path,
            ControlRequest::Ping {
                peer: "bob".into(),
                count: 1000,
            },
        )
        .await
        .unwrap();
        assert_eq!(reply, ControlReply::PingStarted);
        assert!(matches!(
            wire::recv(&mut ping).await.unwrap(),
            ControlReply::PingSample(Some(_))
        ));
        assert!(ra.live_sessions() > 0 && rb.live_sessions() > 0);
        drop(ping);
        tokio::time::timeout(Duration::from_secs(3), async {
            while ra.live_sessions() > 0 || rb.live_sessions() > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("both ping sessions end when the control client disconnects");
        let enable = |service| ControlRequest::Enable {
            peer: "alice".into(),
            service,
        };
        assert_eq!(
            cmd(&bob, enable(Service::Shell)).await,
            ControlReply::Changed(true)
        );

        // During setup: a peer never reached before, whose address
        // swallows the handshake silently.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        book.lock().unwrap().insert(
            carol.ep,
            EndpointAddr::new(EndpointId::from_bytes(&carol.ep).unwrap())
                .with_ip_addr(silent.local_addr().unwrap()),
        );
        let life = crate::local::Lifetime::bind().await.unwrap();
        let mut sock = crate::local::connect_on(&alice.path, &CONTROL)
            .await
            .unwrap();
        let req = ControlRequest::Shell {
            elevated: false,
            peer: key(&carol),
            cols: 80,
            rows: 24,
            lifetime_port: life.port,
            lifetime_key: life.key,
        };
        wire::send(&mut sock, req).await.unwrap();
        let keep = life.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let t0 = std::time::Instant::now();
        drop(keep);
        let mut b = [0u8; 1];
        let r = tokio::time::timeout(T, sock.read(&mut b)).await.unwrap();
        assert!(matches!(r, Ok(0) | Err(_)), "{r:?}");
        assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
        drop(silent);

        // Under backpressure: the shell floods output the command never reads.
        let (mut sh, r, keep) = shell_to(&alice, "bob").await;
        assert_eq!(r, ControlReply::Shell);
        wire::frame(&mut sh, b"\x01yes\r").await.unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(rb.live_sessions() > 0);
        drop(keep);
        let ended = async {
            while rb.live_sessions() > 0 || rb.native_workers() > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), ended)
            .await
            .expect("session and shell end without the data socket draining");
        drop(sh);

        // Port: lifetime EOF exits without the final local drain.
        let (port, mut tev) = half_close_target().await;
        assert_eq!(
            cmd(&bob, enable(tcp(port))).await,
            ControlReply::Changed(true)
        );
        let life = crate::local::Lifetime::bind().await.unwrap();
        let ((mut sock, r), keep) = tokio::try_join!(
            rt::request(&alice.path, connect("bob", tcp(port), &life)),
            life.accept()
        )
        .unwrap();
        assert_eq!(r, ControlReply::Connected);
        wire::frame(&mut sock, b"\x01x").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let t0 = std::time::Instant::now();
        drop(keep);
        // The data socket stays open on this side; the runtime closes its end.
        let r = tokio::time::timeout(T, sock.read(&mut b)).await.unwrap();
        assert!(matches!(r, Ok(0) | Err(_)), "{r:?}");
        assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
        let closed = async { while tev.recv().await != Some("closed") {} };
        tokio::time::timeout(T, closed).await.unwrap();

        assert!(ra.stop().await.owner_released);
        assert!(rb.stop().await.owner_released);
    }

    /// Hold an exposure through control: (control socket, reply, lifetime).
    async fn expose_to(
        m: &Member,
        peer: &str,
        service: Service,
        target: Option<String>,
    ) -> (
        tokio::net::TcpStream,
        ControlReply,
        Option<tokio::net::TcpStream>,
    ) {
        let life = crate::local::Lifetime::bind().await.unwrap();
        let req = ControlRequest::Expose {
            peer: peer.into(),
            service,
            target,
            lifetime_port: life.port,
            lifetime_key: life.key,
        };
        let (sock, r) = tokio::time::timeout(T, rt::request(&m.path, req))
            .await
            .unwrap()
            .unwrap();
        let keep = tokio::time::timeout(Duration::from_secs(2), life.accept())
            .await
            .ok()
            .and_then(Result::ok);
        (sock, r, keep)
    }

    async fn final_reply(sock: &mut tokio::net::TcpStream) -> ControlReply {
        tokio::time::timeout(T, wire::recv(sock))
            .await
            .unwrap()
            .unwrap()
    }

    async fn status(m: &Member) -> rt::StatusView {
        let ControlReply::Status(v) = cmd(m, ControlRequest::Status).await else {
            panic!("status");
        };
        v
    }

    async fn connect_to(
        m: &Member,
        peer: &str,
        service: Service,
    ) -> (tokio::net::TcpStream, ControlReply, tokio::net::TcpStream) {
        let life = crate::local::Lifetime::bind().await.unwrap();
        let ((sock, r), keep) = tokio::try_join!(
            rt::request(&m.path, connect(peer, service, &life)),
            life.accept()
        )
        .unwrap();
        (sock, r, keep)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets"]
    async fn an_exposure_lasts_while_its_command_holds_it_and_ends_only_its_sessions() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let book = Book::default();
        let ra = run(&alice, &book, n.mailbox.clone(), None).await;
        let rb = run(&bob, &book, n.mailbox.clone(), None).await;
        cmd(&alice, approve(&bob, "bob")).await;
        cmd(&bob, approve(&alice, "alice")).await;
        // Shells and malformed targets are never exposed.
        let (_, r, _) = expose_to(&bob, "alice", Service::Shell, None).await;
        assert!(
            matches!(&r, ControlReply::Error(e) if e.contains("port")),
            "{r:?}"
        );
        let (_, r, _) = expose_to(&bob, "alice", tcp(9), Some("nowhere".into())).await;
        assert!(
            matches!(&r, ControlReply::Error(e) if e.contains("HOST:PORT")),
            "{r:?}"
        );

        // A port nothing listens on, forwarded to an owner-chosen target.
        let (target_port, mut tev) = half_close_target().await;
        let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = unused.local_addr().unwrap().port();
        let exposed = tcp(port);
        drop(unused);
        let target = format!("127.0.0.1:{target_port}");
        let (mut held, r, keep) = expose_to(&bob, "alice", exposed, Some(target.clone())).await;
        assert_eq!(
            r,
            ControlReply::Exposed {
                key: key(&alice),
                alias: "alice".into()
            }
        );
        let keep = keep.expect("lifetime");
        let v = status(&bob).await;
        assert_eq!(
            v.exposures,
            vec![rt::ExposureView {
                key: key(&alice),
                service: exposed,
                target: Some(target.clone()),
            }]
        );
        assert!(v.grants.is_empty(), "exposures are not persistent grants");
        let offline = offline_status(&bob.reopen(&n)).unwrap();
        assert!(offline.exposures.is_empty(), "never persisted");

        // One exposure per peer and service, and never beside a grant.
        let (_, r, _) = expose_to(&bob, "alice", exposed, None).await;
        assert!(
            matches!(&r, ControlReply::Error(e) if e.contains("already exposed")),
            "{r:?}"
        );
        let enable = |service| ControlRequest::Enable {
            peer: "alice".into(),
            service,
        };
        let r = cmd(&bob, enable(exposed)).await;
        assert!(
            matches!(&r, ControlReply::Error(e) if e.contains("exposed")),
            "{r:?}"
        );

        // The first connection completes pairing and reaches the owner's target.
        let (mut sock, r, life) = connect_to(&alice, "bob", exposed).await;
        assert_eq!(r, ControlReply::Connected);
        wire::frame(&mut sock, b"\x01hello").await.unwrap();
        wire::frame(&mut sock, &[crate::tunnel::EOF]).await.unwrap();
        assert_eq!(drain(&mut sock).await, (b"bye:hello".to_vec(), None));
        assert_eq!(tev.recv().await, Some("eof"));
        drop((sock, life));

        // A live session under the exposure, and one under a persistent grant.
        let (other_port, mut oev) = half_close_target().await;
        assert_eq!(
            cmd(&bob, enable(tcp(other_port))).await,
            ControlReply::Changed(true)
        );
        let (mut under, r, under_life) = connect_to(&alice, "bob", exposed).await;
        assert_eq!(r, ControlReply::Connected);
        let (mut kept, r, kept_life) = connect_to(&alice, "bob", tcp(other_port)).await;
        assert_eq!(r, ControlReply::Connected);
        wire::frame(&mut under, b"\x01x").await.unwrap();
        wire::frame(&mut kept, b"\x01still ").await.unwrap();

        // The holding command leaves: exactly that exposure is withdrawn.
        drop(keep);
        assert_eq!(final_reply(&mut held).await, ControlReply::Done);
        let (_, failed) = drain(&mut under).await;
        assert_eq!(
            failed.as_deref(),
            Some("the destination ended this authorization")
        );
        drop((under, under_life));
        wire::frame(&mut kept, b"\x01here").await.unwrap();
        wire::frame(&mut kept, &[crate::tunnel::EOF]).await.unwrap();
        assert_eq!(drain(&mut kept).await, (b"bye:still here".to_vec(), None));
        assert_eq!(oev.recv().await, Some("eof"));
        drop((kept, kept_life));
        assert!(status(&bob).await.exposures.is_empty());
        let (_, r, _) = connect_to(&alice, "bob", exposed).await;
        assert!(matches!(&r, ControlReply::Error(_)), "{r:?}");

        // A disable of that service for that peer withdraws a live exposure.
        let udp = Service::Udp(NonZeroU16::new(port).unwrap());
        let (mut held, r, _keep) = expose_to(&bob, "alice", udp, Some(target.clone())).await;
        assert!(matches!(r, ControlReply::Exposed { .. }), "{r:?}");
        let disable = ControlRequest::Disable {
            peer: "alice".into(),
            service: udp,
        };
        assert_eq!(cmd(&bob, disable).await, ControlReply::Changed(true));
        let r = final_reply(&mut held).await;
        assert!(
            matches!(&r, ControlReply::Error(e) if e.contains("grant removed")),
            "{r:?}"
        );
        assert!(status(&bob).await.exposures.is_empty());

        // So does a decline (the pairing ends), and so does stop.
        let (mut held, r, _keep) = expose_to(&bob, "alice", exposed, None).await;
        assert!(matches!(r, ControlReply::Exposed { .. }), "{r:?}");
        let decline = ControlRequest::Decline {
            peer: "alice".into(),
        };
        assert_eq!(cmd(&bob, decline).await, ControlReply::Done);
        let r = final_reply(&mut held).await;
        assert!(
            matches!(&r, ControlReply::Error(e) if e.contains("declined")),
            "{r:?}"
        );
        assert!(status(&bob).await.exposures.is_empty());

        assert!(ra.stop().await.owner_released);
        assert!(rb.stop().await.owner_released);
    }
    fn events(m: &Member) -> Vec<serde_json::Value> {
        std::fs::read_to_string(m.path.join(crate::private::audit::EVENT_FILE))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn find<'a>(
        log: &'a [serde_json::Value],
        fields: &[(&str, &str)],
    ) -> Option<&'a serde_json::Value> {
        log.iter()
            .find(|v| fields.iter().all(|(k, want)| v[*k].as_str() == Some(*want)))
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "opens loopback UDP/TCP sockets"]
    async fn device_events_are_logged_without_secrets() {
        let n = net();
        let alice = create(&n, "alice", Clock::System);
        let bob = join(&n, &alice, "bob", Clock::System);
        let book = Book::default();
        let ra = run(&alice, &book, n.mailbox.clone(), None).await;
        let rb = run(&bob, &book, n.mailbox.clone(), None).await;
        let file = alice.path.join(crate::private::audit::EVENT_FILE);
        assert_eq!(ra.log_file(), Some(file.as_path()));
        let ControlReply::Invite(invite) = cmd(&alice, ControlRequest::Invite).await else {
            panic!("invite");
        };
        cmd(&alice, approve(&bob, "bob")).await;
        cmd(&bob, approve(&alice, "alice")).await;
        // The first exchange pairs; shell is not enabled, so it is refused on
        // both sides.
        let (_, r, _) = shell_to(&alice, "bob").await;
        assert!(matches!(r, ControlReply::Error(_)), "{r:?}");
        let (port, _tev) = half_close_target().await;
        let enable = ControlRequest::Enable {
            peer: "alice".into(),
            service: tcp(port),
        };
        assert_eq!(cmd(&bob, enable).await, ControlReply::Changed(true));
        let life = crate::local::Lifetime::bind().await.unwrap();
        let ((mut sock, r), keep) = tokio::try_join!(
            rt::request(&alice.path, connect("bob", tcp(port), &life)),
            life.accept()
        )
        .unwrap();
        assert_eq!(r, ControlReply::Connected);
        wire::frame(&mut sock, b"\x01payload-bytes").await.unwrap();
        wire::frame(&mut sock, &[crate::tunnel::EOF]).await.unwrap();
        assert_eq!(drain(&mut sock).await.0, b"bye:payload-bytes".to_vec());
        drop((sock, keep));
        assert!(ra.stop().await.owner_released);
        assert!(rb.stop().await.owner_released);

        let (a, b) = (events(&alice), events(&bob));
        let tcp = format!("tcp:{port}");
        let (alice_id, bob_id) = (
            EndpointId::from_bytes(&alice.ep).unwrap().to_string(),
            EndpointId::from_bytes(&bob.ep).unwrap().to_string(),
        );
        for log in [&a, &b] {
            assert_eq!(log.first().unwrap()["event"], "device_started");
            assert_eq!(log.last().unwrap()["event"], "device_stopped");
        }
        // Control commands, by operation and peer only.
        let issued = [("event", "local_control"), ("operation", "issue_invite")];
        assert!(find(&a, &[issued[0], issued[1], ("outcome", "allowed")]).is_some());
        assert!(find(&a, &[("operation", "approve"), ("target_id", &bob_id)]).is_some());
        // State changes, named by the pinned alias.
        assert!(find(&a, &[("event", "approval_granted"), ("peer_name", "bob")]).is_some());
        assert!(
            find(
                &a,
                &[("event", "pairing_established"), ("peer_id", &bob_id)]
            )
            .is_some()
        );
        let enabled = [("event", "service_enabled"), ("service", &tcp)];
        assert!(find(&b, &[enabled[0], enabled[1], ("peer_name", "alice")]).is_some());
        // Sessions in both directions.
        let out = [("direction", "outbound"), ("service", &tcp)];
        assert!(
            find(
                &a,
                &[out[0], out[1], ("event", "connected"), ("peer_name", "bob")]
            )
            .is_some()
        );
        assert!(find(&a, &[out[0], out[1], ("event", "disconnected")]).is_some());
        let inb = [("direction", "inbound"), ("service", &tcp)];
        assert!(
            find(
                &b,
                &[
                    inb[0],
                    inb[1],
                    ("event", "connected"),
                    ("peer_id", &alice_id)
                ]
            )
            .is_some()
        );
        let done = [("event", "disconnected"), ("reason", "stream_closed")];
        assert!(
            find(&b, &[inb[0], inb[1], done[0], done[1]]).is_some(),
            "{b:#?}"
        );
        let refused = [("event", "connection_failed"), ("service", "shell")];
        let refused = [refused[0], refused[1], ("reason", "service_not_enabled")];
        assert!(
            find(
                &a,
                &[
                    refused[0],
                    refused[1],
                    refused[2],
                    ("direction", "outbound")
                ]
            )
            .is_some()
        );
        assert!(
            find(
                &b,
                &[refused[0], refused[1], refused[2], ("direction", "inbound")]
            )
            .is_some()
        );
        // Nothing secret or carried reaches either log.
        for m in [&alice, &bob] {
            let raw =
                std::fs::read_to_string(m.path.join(crate::private::audit::EVENT_FILE)).unwrap();
            assert!(!raw.contains(&invite), "invite token logged");
            assert!(!raw.contains(&hex(&m.secret.to_bytes())));
            assert!(!raw.contains("payload-bytes"));
            assert!(!raw.contains("approval\":"));
        }
    }
}

// ------------------------------------------------------- device display names

mod device_names {
    use super::super::binding::{BindingError, MAX_DEVICE_NAME, check_device_name};
    use super::*;

    fn create_named(n: &Net, dir_name: &str, name: Option<&str>) -> Member {
        let secret = EndpointSecret::generate();
        let path = dir(n, dir_name);
        let clock = Clock::manual(T0);
        let dev = Device::create_network_named(
            &path,
            &secret,
            n.relay_key,
            n.mailbox.incarnation.clone(),
            n.mailbox.clone(),
            clock.clone(),
            name,
        )
        .unwrap();
        Member {
            dev,
            ep: secret.public(),
            secret,
            clock,
            path,
        }
    }

    fn join_named(n: &Net, issuer: &Member, dir_name: &str, name: Option<&str>) -> Member {
        let token = issuer.dev.issue_invite().unwrap();
        let secret = EndpointSecret::generate();
        let path = dir(n, dir_name);
        let clock = issuer.clock.clone();
        let (dev, request) = Device::begin_join_named(
            &path,
            &secret,
            &token,
            n.mailbox.clone(),
            clock.clone(),
            name,
        )
        .unwrap();
        let p = Pending {
            m: Member {
                dev,
                ep: secret.public(),
                secret,
                clock,
                path,
            },
            invite_id: InviteToken::decode(&token).unwrap().invite_id,
            token,
            request,
        };
        assert!(matches!(
            issuer
                .dev
                .receive_join_request(&p.invite_id, &p.request)
                .unwrap(),
            ReserveOutcome::Reserved { .. }
        ));
        admit(issuer, &p);
        p.m
    }

    fn named(r: &[RosterMember], ep: &EndpointKey) -> Option<String> {
        r.iter().find(|m| &m.endpoint == ep).unwrap().name.clone()
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn relay_bytes_contain(root: &Path, needle: &[u8]) -> bool {
        let mut stack = vec![root.to_path_buf()];
        while let Some(p) = stack.pop() {
            if p.is_dir() {
                stack.extend(std::fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
            } else if contains(&std::fs::read(&p).unwrap(), needle) {
                return true;
            }
        }
        false
    }

    /// Names set at create and join reach every member through the
    /// authenticated MLS state, a nameless member stays nameless, and the
    /// relay's stored bytes never contain a name.
    #[test]
    fn names_reach_every_member_and_never_the_relay() {
        let n = net();
        let a = create_named(&n, "a", Some("zq-alpha-host"));
        let b = join_named(&n, &a, "b", Some("zq-bravo-host"));
        let c = join_named(&n, &a, "c", None);
        sync(&[&a, &b, &c]);
        agree(&[&a, &b, &c]);

        let ra = a.dev.named_roster().unwrap();
        assert_eq!(ra.len(), 3);
        for m in [&b, &c] {
            assert_eq!(m.dev.named_roster().unwrap(), ra, "named rosters differ");
        }
        assert_eq!(named(&ra, &a.ep).as_deref(), Some("zq-alpha-host"));
        assert_eq!(named(&ra, &b.ep).as_deref(), Some("zq-bravo-host"));
        assert_eq!(named(&ra, &c.ep), None);
        // The key-only roster is unchanged by names.
        assert_eq!(
            a.dev.roster().unwrap(),
            ra.iter().map(|m| m.endpoint).collect::<Vec<_>>()
        );

        let relay = n.root.join("relay");
        assert!(
            relay_bytes_contain(&relay, &n.relay_key),
            "scan sanity: raw relay bytes are visible"
        );
        assert!(
            !relay_bytes_contain(&relay, &b.ep),
            "relay store contains an endpoint"
        );
        for name in ["zq-alpha-host", "zq-bravo-host"] {
            assert!(
                !relay_bytes_contain(&relay, name.as_bytes()),
                "relay store contains {name}"
            );
        }
        // A reopened device reads the same names from its own state.
        assert_eq!(b.reopen(&n).named_roster().unwrap(), ra);
    }

    /// An invalid name is refused before any profile state is written.
    #[test]
    fn named_constructors_refuse_invalid_names_without_state() {
        let n = net();
        let secret = EndpointSecret::generate();
        let path = dir(&n, "bad");
        let r = Device::create_network_named(
            &path,
            &secret,
            n.relay_key,
            n.mailbox.incarnation.clone(),
            n.mailbox.clone(),
            Clock::manual(T0),
            Some("has space"),
        );
        assert!(r.is_err());
        assert!(!path.exists());

        let a = create(&n, "a", Clock::manual(T0));
        let token = a.dev.issue_invite().unwrap();
        let r = Device::begin_join_named(
            &path,
            &secret,
            &token,
            n.mailbox.clone(),
            Clock::manual(T0),
            Some(""),
        );
        assert!(r.is_err());
        assert!(!path.exists());
    }

    #[test]
    fn device_name_rule() {
        for ok in [
            "laptop",
            "a",
            "web-01",
            "Build_box",
            &"x".repeat(MAX_DEVICE_NAME),
        ] {
            assert_eq!(check_device_name(ok), Ok(()), "{ok}");
        }
        let iroh_form = iroh::SecretKey::from_bytes(&[7; 32]).public().to_string();
        let hex_form = super::super::codec::hex(&[7u8; 32]);
        for bad in [
            "",
            "two words",
            "tab\t",
            "émile",
            "dot.local",
            &"x".repeat(MAX_DEVICE_NAME + 1),
            &iroh_form,
            &hex_form,
        ] {
            assert!(check_device_name(bad).is_err(), "{bad:?}");
        }
    }

    /// A nameless binding keeps the version 1 encoding exactly; a named one
    /// is version 2, signs its name and checks it on decode.
    #[test]
    fn bindings_sign_and_check_the_name() {
        let secret = EndpointSecret::generate();
        let tag = [3u8; 32];
        let mls_key = [9u8; 32];
        let legacy = CredentialBinding::create(&secret, &tag, &mls_key);
        assert_eq!(legacy.name, None);
        let bytes = legacy.encode();
        assert_eq!(bytes[0], 1);
        assert_eq!(CredentialBinding::decode(&bytes).unwrap(), legacy);
        let (ep, name) =
            CredentialBinding::verify_credential_named(&legacy.credential(), &mls_key, &tag)
                .unwrap();
        assert_eq!((ep, name), (secret.public(), None));

        let b = CredentialBinding::create_named(&secret, &tag, &mls_key, Some("desk")).unwrap();
        assert_eq!(b.encode()[0], 2);
        assert_eq!(CredentialBinding::decode(&b.encode()).unwrap(), b);
        assert_eq!(
            CredentialBinding::verify_credential_named(&b.credential(), &mls_key, &tag).unwrap(),
            (secret.public(), Some("desk".into()))
        );
        assert_eq!(
            CredentialBinding::verify_credential(&b.credential(), &mls_key, &tag).unwrap(),
            secret.public()
        );

        // Another valid name under the same signature: rejected.
        let mut renamed = b.clone();
        renamed.name = Some("dusk".into());
        assert!(matches!(
            CredentialBinding::verify_credential(&renamed.credential(), &mls_key, &tag),
            Err(BindingError::Signature(_))
        ));
        // Dropping the name (a version 1 encoding of a named signature): rejected.
        let mut stripped = b.clone();
        stripped.name = None;
        assert!(matches!(
            CredentialBinding::verify_credential(&stripped.credential(), &mls_key, &tag),
            Err(BindingError::Signature(_))
        ));
        // A name breaking the rule never decodes, whoever signed it.
        let mut bad = b.clone();
        bad.name = Some("not ok".into());
        assert!(matches!(
            CredentialBinding::decode(&bad.encode()),
            Err(BindingError::Name(_))
        ));
        assert!(matches!(
            CredentialBinding::create_named(&secret, &tag, &mls_key, Some("not ok")),
            Err(BindingError::Name(_))
        ));
    }

    /// Exact key, then local alias, then a unique roster name. Duplicate
    /// names (case-insensitively) never pick a peer; key or alias does.
    #[test]
    fn selectors_prefer_pinned_and_refuse_duplicate_names() {
        let (k1, k2, k3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let roster = vec![
            RosterMember {
                endpoint: k1,
                name: Some("laptop".into()),
            },
            RosterMember {
                endpoint: k2,
                name: Some("Laptop".into()),
            },
            RosterMember {
                endpoint: k3,
                name: Some("desk".into()),
            },
        ];
        let aliases = vec![("work".to_string(), k2), ("desk".to_string(), k1)];

        assert_eq!(
            select_peer("desk", Some(k3), &aliases, &roster),
            Ok(PeerMatch::Key(k3))
        );
        // A local alias outranks a roster member that names itself the same.
        let m = select_peer("desk", None, &aliases, &roster).unwrap();
        assert_eq!(m, PeerMatch::Alias(k1));
        assert!(m.pinned());
        assert_eq!(
            select_peer("laptop", None, &aliases, &roster),
            Err(SelectError::AmbiguousName(vec![k1, k2]))
        );
        assert_eq!(
            select_peer("work", None, &aliases, &roster),
            Ok(PeerMatch::Alias(k2))
        );
        assert_eq!(
            select_peer("nobody", None, &aliases, &roster),
            Err(SelectError::NoMatch)
        );
        let m = select_peer("DESK", None, &[], &roster).unwrap();
        assert_eq!(m, PeerMatch::Name(k3));
        assert!(!m.pinned());
        assert_eq!(m.endpoint(), k3);
    }
}
