//! The update transaction, its reversal and recovery against a scripted service, and staging
//! and preflight against local fixtures. `crate::private::tests` runs the same transaction
//! over a real runtime.
//!
//! The update's `Service` has no way to stop anything, so a process can only end here by
//! retiring itself on a commit, or because the test plays an operator or a crash. The
//! scripted service records every runtime that ended itself and the sessions it had, which
//! must be none, and every start of a service that was already running, which must not happen.

use std::sync::Mutex;

use super::*;

pub(crate) const FAST: Timing = Timing {
    poll: Duration::from_millis(20),
    verify: Duration::from_millis(400),
    retry: Duration::from_millis(5),
};

/// Never interrupts.
pub(crate) struct Patient;

impl Interrupt for Patient {
    fn interrupted(&self) -> bool {
        false
    }
}

/// Interrupts once set.
#[derive(Default)]
struct Flag(AtomicBool);

impl Interrupt for Flag {
    fn interrupted(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// A service whose "program" is a text file holding the version it reports when started.
/// A program reading `broken` does not start.
struct Fake {
    installed: PathBuf,
    events: PathBuf,
    /// Whether the program can be replaced while the service runs from it.
    replaces_running: bool,
    state: Arc<Mutex<State>>,
}

/// One process of the service.
#[derive(Clone)]
struct Process {
    pid: u32,
    version: String,
    sessions: usize,
    /// Whether it answers control.
    answers: bool,
    /// An update's hold is in force on it.
    held: bool,
    /// It has received a commit that it has not acted on yet: this many more times it
    /// answers `identify`, still held, before it retires and ends.
    stalled: Option<usize>,
}

type Hook = Box<dyn FnMut(&mut State) + Send>;

#[derive(Default)]
struct State {
    program: PathBuf,
    running: Option<Process>,
    pids: u32,
    /// The service manager starts the installed program again when a process ends.
    relaunches: bool,
    /// Commits that find their hold lapsed: the runtime retires nothing and serves on.
    lapses: usize,
    /// Commits that retire the runtime but whose confirmation is lost.
    lost_confirmations: usize,
    /// A commit is not acted on until the runtime has answered `identify` this many times
    /// more: the gap between a commit and the retirement it leads to.
    stall: Option<usize>,
    /// How many times the service manager reports the service as in between, after a process
    /// ends and after a start, before it reports what is so.
    pending: usize,
    pending_left: usize,
    /// What was installed each time the manager reported the service as in between.
    installed_while_pending: Vec<String>,
    /// Starts asked for while the manager reported the service as in between. Must stay zero.
    started_pending: usize,
    /// The service's definition no longer starts the installed program.
    redefined: bool,
    /// A program of this version starts but never answers control.
    mute: Option<String>,
    /// Sessions a runtime of this version has as soon as it starts.
    busy: Option<(String, usize)>,
    before_start: Option<Hook>,
    /// Runs when a hold is granted, before it is returned.
    on_hold: Option<Hook>,
    /// Runs when a commit arrives, before the runtime sees it.
    on_commit: Option<Hook>,
    holds: usize,
    commits: usize,
    starts: usize,
    /// Each runtime that ended itself on a commit: its process and the sessions it had.
    retired: Vec<(u32, usize)>,
    /// Starts asked for while a process was running. Must stay zero.
    started_running: usize,
}

impl State {
    /// The service manager launches the installed program.
    fn launch(&mut self) -> bool {
        let Ok(version) = fs::read_to_string(&self.program) else {
            return false;
        };
        if version == "broken" {
            return false;
        }
        self.pids += 1;
        self.running = Some(Process {
            pid: 100 + self.pids,
            sessions: match &self.busy {
                Some((busy, sessions)) if *busy == version => *sessions,
                _ => 0,
            },
            answers: self.mute.as_deref() != Some(&version),
            held: false,
            stalled: None,
            version,
        });
        self.pending_left = self.pending;
        true
    }

    /// The running process retires and ends itself, and its manager may start the service again.
    fn retire(&mut self) {
        let process = self.running.take().expect("a process to retire");
        self.retired.push((process.pid, process.sessions));
        self.pending_left = self.pending;
        if self.relaunches {
            self.launch();
        }
    }

    /// The operator restarts the service, or it crashes and its manager starts it again:
    /// another process takes the name, serving `sessions`.
    fn replaced(&mut self, sessions: usize) {
        self.running = None;
        assert!(self.launch());
        self.running.as_mut().unwrap().sessions = sessions;
        self.pending_left = 0;
    }

    fn hook(&mut self, pick: fn(&mut State) -> &mut Option<Hook>) {
        if let Some(mut hook) = pick(self).take() {
            hook(self);
            *pick(self) = Some(hook);
        }
    }
}

struct FakeHold {
    state: Arc<Mutex<State>>,
    identity: Identity,
}

impl Drop for FakeHold {
    /// A hold that was not committed, or whose commit was not taken, is released.
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        if let Some(process) = &mut state.running
            && process.pid == self.identity.pid
            && process.stalled.is_none()
        {
            process.held = false;
        }
    }
}

impl Hold for FakeHold {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn lease(&self) -> Duration {
        Duration::from_millis(50)
    }

    fn commit(&mut self) -> bool {
        let mut state = self.state.lock().unwrap();
        state.commits += 1;
        state.hook(|state| &mut state.on_commit);
        // The commit reaches only the process whose connection this is.
        let held = state
            .running
            .clone()
            .filter(|process| process.pid == self.identity.pid);
        let Some(process) = held else {
            return false;
        };
        if state.lapses > 0 {
            state.lapses -= 1;
            state.running.as_mut().unwrap().held = false;
            return false;
        }
        assert!(process.held, "a commit on a hold that is not in force");
        if let Some(stall) = state.stall.take() {
            // The commit has arrived, and the runtime has not acted on it yet.
            state.running.as_mut().unwrap().stalled = Some(stall);
            return false;
        }
        state.retire();
        if state.lost_confirmations > 0 {
            state.lost_confirmations -= 1;
            return false;
        }
        true
    }
}

impl Service for Fake {
    fn label(&self) -> String {
        "fixture.service".into()
    }

    fn events(&self) -> PathBuf {
        self.events.clone()
    }

    fn launches(&self, program: &Path) -> Result<bool> {
        Ok(program == self.installed && !self.state.lock().unwrap().redefined)
    }

    fn replaces_running(&self) -> bool {
        self.replaces_running
    }

    fn state(&self) -> Result<Manager> {
        let mut state = self.state.lock().unwrap();
        if state.pending_left > 0 {
            state.pending_left -= 1;
            let installed = fs::read_to_string(&self.installed).unwrap_or_default();
            state.installed_while_pending.push(installed);
            return Ok(Manager::Pending("as in between".into()));
        }
        Ok(match &state.running {
            Some(process) => Manager::Running(process.pid),
            None => Manager::Stopped,
        })
    }

    fn start(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.hook(|state| &mut state.before_start);
        state.starts += 1;
        if state.pending_left > 0 {
            state.started_pending += 1;
        }
        if state.running.is_some() {
            state.started_running += 1;
            return Ok(());
        }
        ensure!(state.launch(), "the program exited at once");
        Ok(())
    }
}

impl Fake {
    fn identity(&self, process: &Process) -> Identity {
        Identity {
            pid: process.pid,
            executable: self.installed.to_str().map(str::to_owned),
            version: process.version.clone(),
            endpoint: "device".into(),
            held: process.held,
        }
    }
}

impl Host for Fake {
    fn service(&self) -> &dyn Service {
        self
    }

    fn identify(&self) -> Result<Identity> {
        let mut state = self.state.lock().unwrap();
        let process = state.running.clone().context("nothing answers")?;
        ensure!(process.answers, "nothing answers");
        // A runtime that has a commit to act on answers, still held, until it does.
        match process.stalled {
            Some(0) => {
                state.retire();
                bail!("the runtime retired and is ending");
            }
            Some(left) => state.running.as_mut().unwrap().stalled = Some(left - 1),
            None => {}
        }
        Ok(self.identity(&process))
    }

    fn hold(&self) -> Result<Held> {
        let mut state = self.state.lock().unwrap();
        let process = state.running.clone().context("nothing answers")?;
        ensure!(process.answers, "nothing answers");
        if process.sessions > 0 {
            return Ok(Held::Busy {
                connections: process.sessions,
                exposures: 0,
                held: false,
            });
        }
        ensure!(!process.held, "another hold is in force");
        state.holds += 1;
        state.running.as_mut().unwrap().held = true;
        let identity = self.identity(&process);
        state.hook(|state| &mut state.on_hold);
        Ok(Held::Yes(Box::new(FakeHold {
            state: self.state.clone(),
            identity,
        })))
    }

    fn released(&self) -> bool {
        self.state.lock().unwrap().running.is_none()
    }
}

/// An update prepared the way `run` leaves it before the transaction.
pub(crate) struct Prepared {
    pub root: tempfile::TempDir,
    pub state_dir: PathBuf,
    pub installed: PathBuf,
    pub staging: Staging,
    pub journal: Journal,
}

/// Write a file that only its owner can change, whatever the umask, as a program is installed.
fn put(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    fs::write(&path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

/// A directory only its owner can change, whatever the umask.
fn private_dir(path: &Path) {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o755);
    }
    builder.create(path).unwrap();
}

/// A temporary directory by its real path, as an installed program is named.
fn scratch() -> tempfile::TempDir {
    let root = std::env::temp_dir().canonicalize().unwrap();
    let scratch = tempfile::tempdir_in(root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    scratch
}

/// Open the staging directory where the service has nothing of its own to say about paths.
fn open(installed: &Path, state_dir: &Path) -> Result<Staging> {
    Staging::open(installed, state_dir, &|_| Ok(()))
}

/// Install `old` as the program, stage `new` as its candidate, and arm the journal for an
/// update from `previous_version` to `candidate_version`.
pub(crate) fn prepare(
    old: &str,
    new: &str,
    previous_version: &str,
    candidate_version: &str,
    endpoint: &str,
) -> Prepared {
    let root = scratch();
    let state_dir = root.path().join("state");
    let bin = root.path().join("bin");
    private_dir(&state_dir);
    private_dir(&bin);
    let installed = bin.join("massrelay");
    put(&installed, old).unwrap();
    let staging = open(&installed, &state_dir).unwrap();
    put(staging.candidate(), new).unwrap();
    let mut journal = Journal {
        format: JOURNAL_FORMAT.into(),
        phase: Phase::Armed,
        installed: installed.clone(),
        previous_version: previous_version.into(),
        previous_sha256: keep_previous(&staging, &installed).unwrap(),
        candidate_version: candidate_version.into(),
        candidate_sha256: sha256_file(&staging.candidate()).unwrap(),
        endpoint: endpoint.into(),
    };
    journal.record(&state_dir, Phase::Armed).unwrap();
    Prepared {
        root,
        state_dir,
        installed,
        staging,
        journal,
    }
}

/// The service of a prepared update, running its previous version. `in_place` says whether
/// its program can be replaced while it runs, and `relaunches` whether its manager starts
/// the installed program again when a process ends.
fn service(prepared: &Prepared, in_place: bool, relaunches: bool) -> Fake {
    let mut state = State {
        program: prepared.installed.clone(),
        relaunches,
        ..State::default()
    };
    assert!(state.launch());
    Fake {
        installed: prepared.installed.clone(),
        events: prepared.root.path().join("events.jsonl"),
        replaces_running: in_place,
        state: Arc::new(Mutex::new(state)),
    }
}

/// A service like systemd's with `Restart=on-failure`, or launchd's: the program is replaced
/// under it, and a runtime that ends itself is started again.
fn fake(prepared: &Prepared) -> Fake {
    service(prepared, true, true)
}

fn update(
    host: &Fake,
    prepared: Prepared,
    interrupt: &dyn Interrupt,
) -> (Outcome, tempfile::TempDir) {
    let Prepared {
        root,
        state_dir,
        staging,
        journal,
        ..
    } = prepared;
    let outcome = transact(host, &state_dir, staging, journal, FAST, interrupt);
    (outcome, root)
}

/// Whether the journal or either recovery image remains.
fn kept(root: &Path) -> (bool, bool) {
    (
        root.join("state").join(JOURNAL).exists(),
        ["previous", "candidate"].into_iter().any(|name| {
            let extension = if cfg!(windows) { ".exe" } else { "" };
            root.join("bin")
                .join(STAGING)
                .join(format!("{name}{extension}"))
                .exists()
        }),
    )
}

fn installed(host: &Fake) -> String {
    fs::read_to_string(&host.installed).unwrap()
}

fn running(host: &Fake) -> Option<String> {
    let state = host.state.lock().unwrap();
    state.running.as_ref().map(|p| p.version.clone())
}

/// Every runtime that ended did so itself, idle, and no running service was started again.
fn assert_nothing_was_ended(host: &Fake) {
    let state = host.state.lock().unwrap();
    assert!(
        state.retired.iter().all(|(_, sessions)| *sessions == 0),
        "{:?}",
        state.retired
    );
    assert_eq!((state.started_running, state.started_pending), (0, 0));
}

/// `recover`, as the next run does it. A process another test is starting can hold a copy of a
/// just-released staging lock for a moment, which a real next run never meets.
fn recovered(host: &dyn Host, state_dir: &Path) -> Result<String> {
    loop {
        match recover(host, state_dir, FAST, &Patient) {
            Err(error) if format!("{error:#}").contains("already working") => {
                std::thread::sleep(Duration::from_millis(5));
            }
            done => return done.map(|said| said.expect("an update to recover")),
        }
    }
}

/// A prepared update as an earlier run left it once its exchange had begun, with the staging
/// lock released and the candidate installed or not.
fn interrupted(swapped: bool) -> (Fake, PathBuf, tempfile::TempDir) {
    let mut prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
    let host = fake(&prepared);
    prepared
        .journal
        .record(&prepared.state_dir, Phase::Switching)
        .unwrap();
    if swapped {
        let candidate = prepared.journal.candidate(&prepared.staging);
        prepared
            .staging
            .place(&candidate.file, &candidate.sha256, &prepared.installed)
            .unwrap();
    }
    let Prepared {
        root,
        state_dir,
        staging,
        ..
    } = prepared;
    drop(staging);
    (host, state_dir, root)
}

fn saved(root: &Path) -> PathBuf {
    root.join("bin").join(STAGING).join("previous")
}

/// Under every kind of service manager the idle runtime ends itself and the candidate takes
/// over: with the program replaced under it or after it, started again by its manager or by
/// the update.
#[test]
fn an_idle_service_ends_itself_and_the_staged_program_takes_over() {
    for (in_place, relaunches) in [(true, true), (true, false), (false, false)] {
        let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
        let host = service(&prepared, in_place, relaunches);
        let first = host.state.lock().unwrap().running.clone().unwrap().pid;
        let (outcome, root) = update(&host, prepared, &Patient);
        assert_eq!(outcome, Outcome::Updated, "{in_place} {relaunches}");
        assert_eq!(installed(&host), "2.0.0");
        assert_eq!(running(&host).as_deref(), Some("2.0.0"));
        {
            let state = host.state.lock().unwrap();
            // The one process that ended is the one that was held, and it ended itself.
            assert_eq!(state.retired, [(first, 0)]);
            assert_eq!(state.commits, 1);
            // A manager that starts it again needs no start from the update.
            assert_eq!(state.starts, usize::from(!relaunches));
        }
        assert_nothing_was_ended(&host);
        // Nothing of the update remains beside the program or in the state directory.
        assert_eq!(kept(root.path()), (false, false));
    }
}

#[test]
fn a_live_session_is_waited_for_and_cancelling_the_wait_changes_nothing() {
    let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
    let host = fake(&prepared);
    host.state
        .lock()
        .unwrap()
        .running
        .as_mut()
        .unwrap()
        .sessions = 1;
    let cancel = Flag::default();
    cancel.0.store(true, Ordering::SeqCst);
    let (outcome, root) = update(&host, prepared, &cancel);
    assert!(matches!(&outcome, Outcome::Unchanged(cause) if cause.contains("cancelled")));
    assert_eq!(installed(&host), "1.0.0");
    let state = host.state.lock().unwrap();
    assert_eq!(state.running.as_ref().unwrap().sessions, 1);
    assert_eq!((state.commits, state.starts), (0, 0));
    assert!(state.retired.is_empty());
    assert_eq!(kept(root.path()), (false, false));
}

/// A commit that finds its hold lapsed retires nothing. The runtime serves on, and the update
/// ends with the previous program's own bytes back under it and nothing started or ended.
#[test]
fn a_hold_that_lapsed_before_its_commit_ends_nothing() {
    for in_place in [true, false] {
        let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
        let host = service(&prepared, in_place, in_place);
        let first = host.state.lock().unwrap().running.clone().unwrap().pid;
        host.state.lock().unwrap().lapses = 1;
        let (outcome, root) = update(&host, prepared, &Patient);
        assert!(
            matches!(&outcome, Outcome::Unchanged(cause) if cause.contains("did not confirm")),
            "{outcome:?}"
        );
        assert_eq!(installed(&host), "1.0.0");
        let state = host.state.lock().unwrap();
        assert_eq!(state.running.as_ref().unwrap().pid, first, "it serves on");
        assert!(state.retired.is_empty());
        assert_eq!((state.commits, state.starts), (1, 0));
        assert_eq!(kept(root.path()), (false, false));
    }
}

/// A commit whose confirmation is lost may or may not have retired the runtime. The update
/// reads the answer from what serves afterwards instead of assuming either.
#[test]
fn a_lost_confirmation_is_settled_by_what_serves_afterwards() {
    for (in_place, relaunches) in [(true, true), (true, false), (false, false)] {
        let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
        let host = service(&prepared, in_place, relaunches);
        host.state.lock().unwrap().lost_confirmations = 1;
        let (outcome, root) = update(&host, prepared, &Patient);
        assert_eq!(outcome, Outcome::Updated, "{in_place} {relaunches}");
        assert_eq!(installed(&host), "2.0.0");
        assert_eq!(running(&host).as_deref(), Some("2.0.0"));
        assert_nothing_was_ended(&host);
        assert_eq!(kept(root.path()), (false, false));
    }
}

/// Between a commit and the end it leads to, the old process is still there and still
/// answers. It answers as a held runtime, which is neither a serving previous version to
/// settle on or go back to, nor grounds to close the update: it is waited out. The same holds
/// for a run that finds it in that state with an update's journal already written.
#[test]
fn a_runtime_between_its_commit_and_its_end_is_waited_out_not_judged() {
    for (in_place, relaunches) in [(true, true), (true, false), (false, false)] {
        let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
        let host = service(&prepared, in_place, relaunches);
        let first = host.state.lock().unwrap().running.clone().unwrap().pid;
        host.state.lock().unwrap().stall = Some(6);
        let (outcome, root) = update(&host, prepared, &Patient);
        // Had the old process been taken for a previous version that serves on, the previous
        // program would have been put back and the update closed while it was still ending.
        assert_eq!(outcome, Outcome::Updated, "{in_place} {relaunches}");
        assert_eq!(installed(&host), "2.0.0");
        assert_eq!(running(&host).as_deref(), Some("2.0.0"));
        assert_eq!(host.state.lock().unwrap().retired, [(first, 0)]);
        assert_nothing_was_ended(&host);
        assert_eq!(kept(root.path()), (false, false));
    }

    // The updater died after its commit, with the new program already in place. The next
    // run finds the old runtime still ending, waits, and then finds the update finished.
    let (host, state_dir, root) = interrupted(true);
    {
        let mut state = host.state.lock().unwrap();
        let process = state.running.as_mut().unwrap();
        process.held = true;
        process.stalled = Some(6);
    }
    let said = recovered(&host, &state_dir).unwrap();
    assert!(said.contains("had finished"), "{said}");
    assert_eq!(installed(&host), "2.0.0");
    assert_eq!(running(&host).as_deref(), Some("2.0.0"));
    assert_nothing_was_ended(&host);
    assert_eq!(kept(root.path()), (false, false));

    // The same where the program had not been replaced yet and nothing starts the service
    // again: the next run waits for the old runtime to end, and only then starts the
    // previous program.
    let (host, state_dir, root) = interrupted(false);
    {
        let mut state = host.state.lock().unwrap();
        state.relaunches = false;
        let process = state.running.as_mut().unwrap();
        process.held = true;
        process.stalled = Some(6);
    }
    let said = recovered(&host, &state_dir).unwrap();
    assert!(said.contains("restored"), "{said}");
    assert_eq!(installed(&host), "1.0.0");
    assert_eq!(running(&host).as_deref(), Some("1.0.0"));
    assert_eq!(host.state.lock().unwrap().starts, 1);
    assert_nothing_was_ended(&host);
    assert_eq!(kept(root.path()), (false, false));
}

/// A service manager says more than "running" or not: a service can be starting or stopping.
/// Neither is stopped. The program is not replaced, and the service is not started, until the
/// manager itself says that nothing runs, and the wait for that is bounded.
#[test]
fn a_service_reported_as_starting_or_stopping_is_never_taken_for_stopped() {
    for (in_place, relaunches) in [(true, true), (false, false)] {
        let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
        let host = service(&prepared, in_place, relaunches);
        host.state.lock().unwrap().pending = 5;
        let (outcome, root) = update(&host, prepared, &Patient);
        assert_eq!(outcome, Outcome::Updated, "{in_place}");
        let state = host.state.lock().unwrap();
        assert!(state.installed_while_pending.len() >= 5);
        if !in_place {
            // While the manager still reported the old runtime as stopping, the program was
            // not replaced, although the profile was already released.
            assert_eq!(state.installed_while_pending[..5], ["1.0.0"; 5]);
        }
        assert_eq!((state.started_running, state.started_pending), (0, 0));
        assert_eq!(kept(root.path()), (false, false));
    }

    // A stop that the manager never reports as complete: the update gives up within its
    // bound, replaces nothing, starts nothing, and stays unfinished.
    let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
    let host = service(&prepared, false, false);
    let state_dir = prepared.state_dir.clone();
    host.state.lock().unwrap().pending = usize::MAX;
    let began = Instant::now();
    let (outcome, root) = update(&host, prepared, &Patient);
    let Outcome::Stranded(what) = &outcome else {
        panic!("{outcome:?}");
    };
    assert!(what.contains("has not ended"), "{what}");
    assert!(began.elapsed() < Duration::from_secs(10));
    assert_eq!(installed(&host), "1.0.0");
    assert_eq!(host.state.lock().unwrap().starts, 0);
    assert_eq!(kept(root.path()), (true, true));
    // The next run, with the manager still in between, does the same.
    assert!(recovered(&host, &state_dir).is_err());
    assert_eq!(installed(&host), "1.0.0");
    assert_eq!(host.state.lock().unwrap().starts, 0);
    assert_eq!(kept(root.path()), (true, true));
    // Once the manager reports it stopped, the previous program is started again.
    {
        let mut state = host.state.lock().unwrap();
        state.pending = 0;
        state.pending_left = 0;
    }
    let said = recovered(&host, &state_dir).unwrap();
    assert!(said.contains("restored"), "{said}");
    assert_eq!(running(&host).as_deref(), Some("1.0.0"));
    assert_eq!(kept(root.path()), (false, false));
}

/// Between the first checks, the hold and the commit, the operator or a crash can put another
/// process under the service's name. Nothing is aimed at that name, so the replacement is
/// never ended: a commit reaches only the connection of the runtime that was held.
#[test]
fn a_service_replaced_during_the_update_is_never_the_one_that_ends() {
    // Replaced after the hold was granted: the process that is idle is no longer the
    // service's. Nothing is replaced, and nothing is asked to retire.
    let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
    let host = fake(&prepared);
    host.state.lock().unwrap().on_hold = Some(Box::new(|state| state.replaced(2)));
    let (outcome, root) = update(&host, prepared, &Patient);
    assert!(
        matches!(&outcome, Outcome::Unchanged(cause) if cause.contains("not the installed service")),
        "{outcome:?}"
    );
    assert_eq!(installed(&host), "1.0.0");
    {
        let state = host.state.lock().unwrap();
        assert_eq!(state.running.as_ref().unwrap().sessions, 2);
        assert_eq!((state.commits, state.starts), (0, 0));
        assert!(state.retired.is_empty());
    }
    assert_eq!(kept(root.path()), (false, false));

    // Replaced as the commit is sent, where the program is replaced first: the replacement
    // already runs the new program, serving two peers. It is verified and kept, untouched.
    let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
    let host = fake(&prepared);
    host.state.lock().unwrap().on_commit = Some(Box::new(|state| {
        if state.commits == 1 {
            state.replaced(2);
        }
    }));
    let (outcome, root) = update(&host, prepared, &Patient);
    assert_eq!(outcome, Outcome::Updated);
    assert_eq!(installed(&host), "2.0.0");
    {
        let state = host.state.lock().unwrap();
        let process = state.running.as_ref().unwrap();
        assert_eq!((process.version.as_str(), process.sessions), ("2.0.0", 2));
        assert!(state.retired.is_empty(), "the commit reached nobody");
        assert_eq!(state.starts, 0);
    }
    assert_eq!(kept(root.path()), (false, false));

    // The same where the program is replaced afterwards: the replacement runs the previous
    // program, serving. It stays, and so does its program.
    let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
    let host = service(&prepared, false, false);
    host.state.lock().unwrap().on_commit = Some(Box::new(|state| {
        if state.commits == 1 {
            state.replaced(2);
        }
    }));
    let (outcome, root) = update(&host, prepared, &Patient);
    assert!(matches!(&outcome, Outcome::Unchanged(_)), "{outcome:?}");
    assert_eq!(installed(&host), "1.0.0");
    let state = host.state.lock().unwrap();
    let process = state.running.as_ref().unwrap();
    assert_eq!((process.version.as_str(), process.sessions), ("1.0.0", 2));
    assert!(state.retired.is_empty());
    assert_eq!(state.starts, 0);
    assert_eq!(kept(root.path()), (false, false));
}

#[test]
fn a_new_program_that_fails_is_replaced_by_the_previous_bytes_and_restarted() {
    for (in_place, relaunches) in [(true, true), (true, false), (false, false)] {
        // It does not start at all.
        let prepared = prepare("1.0.0", "broken", "1.0.0", "2.0.0", "device");
        let host = service(&prepared, in_place, relaunches);
        let (outcome, root) = update(&host, prepared, &Patient);
        assert!(matches!(&outcome, Outcome::RolledBack(_)), "{outcome:?}");
        assert_eq!(installed(&host), "1.0.0");
        assert_eq!(running(&host).as_deref(), Some("1.0.0"));
        assert_nothing_was_ended(&host);
        assert_eq!(kept(root.path()), (false, false));

        // It starts, but is not the version the release promised. It is a serving runtime,
        // so it leaves the way the previous one did: by itself, idle.
        let prepared = prepare("1.0.0", "3.0.0", "1.0.0", "2.0.0", "device");
        let host = service(&prepared, in_place, relaunches);
        let (outcome, root) = update(&host, prepared, &Patient);
        assert!(
            matches!(&outcome, Outcome::RolledBack(cause) if cause.contains("3.0.0")),
            "{outcome:?}"
        );
        assert_eq!(installed(&host), "1.0.0");
        assert_eq!(running(&host).as_deref(), Some("1.0.0"));
        assert_eq!(host.state.lock().unwrap().retired.len(), 2);
        assert_nothing_was_ended(&host);
        assert_eq!(kept(root.path()), (false, false));
    }
}

/// A new program that must go may already serve a peer. It is not ended under that session:
/// the reversal waits, and giving up the wait leaves the update unfinished, with its journal
/// and both programs kept, for the next run to complete.
#[test]
fn a_reversal_waits_for_the_new_programs_sessions_and_stays_pending_if_abandoned() {
    let prepared = prepare("1.0.0", "3.0.0", "1.0.0", "2.0.0", "device");
    let host = fake(&prepared);
    let state_dir = prepared.state_dir.clone();
    let cancel = Arc::new(Flag::default());
    let give_up = cancel.clone();
    {
        let mut state = host.state.lock().unwrap();
        state.busy = Some(("3.0.0".into(), 2));
        // The operator interrupts once the new program has been committed to.
        state.on_commit = Some(Box::new(move |_| give_up.0.store(true, Ordering::SeqCst)));
    }
    let (outcome, root) = update(&host, prepared, cancel.as_ref());
    let Outcome::Stranded(what) = &outcome else {
        panic!("{outcome:?}");
    };
    assert!(what.contains("left running"), "{what}");
    assert!(
        what.contains(saved(root.path()).to_str().unwrap()),
        "{what}"
    );
    assert_eq!(installed(&host), "3.0.0");
    {
        let state = host.state.lock().unwrap();
        let process = state.running.as_ref().unwrap();
        assert_eq!((process.version.as_str(), process.sessions), ("3.0.0", 2));
        assert_eq!(state.retired.len(), 1, "only the previous runtime ended");
    }
    assert_eq!(kept(root.path()), (true, true));
    assert!(saved(root.path()).exists());

    // The next run, once those sessions are over, finishes the reversal.
    host.state
        .lock()
        .unwrap()
        .running
        .as_mut()
        .unwrap()
        .sessions = 0;
    let said = recovered(&host, &state_dir).unwrap();
    assert!(said.contains("restored"), "{said}");
    assert_eq!(installed(&host), "1.0.0");
    assert_eq!(running(&host).as_deref(), Some("1.0.0"));
    assert_nothing_was_ended(&host);
    assert_eq!(kept(root.path()), (false, false));
}

/// A new program that starts but never answers control cannot be asked to leave, and is not
/// forced to. The update stays unfinished. Where the program can be replaced under it, the
/// previous bytes go back, so that whatever starts next is the previous version.
#[test]
fn a_new_program_that_does_not_answer_is_left_running_and_the_update_stays_pending() {
    for in_place in [true, false] {
        let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
        let host = service(&prepared, in_place, in_place);
        let state_dir = prepared.state_dir.clone();
        host.state.lock().unwrap().mute = Some("2.0.0".into());
        let (outcome, root) = update(&host, prepared, &Patient);
        let Outcome::Stranded(what) = &outcome else {
            panic!("{outcome:?}");
        };
        assert!(what.contains("It was not stopped"), "{what}");
        {
            let state = host.state.lock().unwrap();
            // The process that does not answer still runs: only the first runtime ended.
            assert_eq!(state.running.as_ref().unwrap().version, "2.0.0");
            assert_eq!(state.retired.len(), 1);
            assert_eq!(state.started_running, 0);
        }
        assert_eq!(installed(&host), if in_place { "1.0.0" } else { "2.0.0" });
        assert_eq!(kept(root.path()), (true, true));
        assert!(saved(root.path()).exists());

        // Still not answering: the next run changes nothing and keeps everything.
        let error = recovered(&host, &state_dir).unwrap_err();
        assert!(
            format!("{error:#}").contains("It was not stopped"),
            "{error:#}"
        );
        assert_eq!(kept(root.path()), (true, true));
        assert_eq!(
            host.state.lock().unwrap().running.as_ref().unwrap().version,
            "2.0.0"
        );

        // Once that process is gone (the operator restarts the service, or it crashes), the
        // next run brings the previous version back.
        {
            let mut state = host.state.lock().unwrap();
            state.mute = None;
            state.running = None;
        }
        let said = recovered(&host, &state_dir).unwrap();
        assert!(said.contains("restored"), "{said}");
        assert_eq!(installed(&host), "1.0.0");
        assert_eq!(running(&host).as_deref(), Some("1.0.0"));
        assert_eq!(kept(root.path()), (false, false));
    }
}

/// Between the first checks and the moment the service is idle, the things those checks
/// relied on can change. They are checked again under the staging lock, against the identity
/// that came with the hold, and a change ends the update before anything is replaced or asked
/// to retire.
#[test]
fn what_changed_while_waiting_is_caught_before_anything_is_replaced_or_retired() {
    let unchanged = |host: &Fake, outcome: &Outcome, why: &str| {
        assert!(
            matches!(outcome, Outcome::Unchanged(cause) if cause.contains(why)),
            "{outcome:?}"
        );
        let state = host.state.lock().unwrap();
        assert_eq!((state.commits, state.starts), (0, 0));
        assert!(state.retired.is_empty());
        assert_eq!(state.running.as_ref().unwrap().version, "1.0.0");
    };

    // The installed program is replaced (another installer ran).
    let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
    let host = fake(&prepared);
    let program = prepared.installed.clone();
    host.state.lock().unwrap().on_hold = Some(Box::new(move |_| {
        // A new file, as an installer writes one; the saved previous program is untouched.
        fs::remove_file(&program).unwrap();
        put(&program, "1.0.1").unwrap();
    }));
    let (outcome, root) = update(&host, prepared, &Patient);
    unchanged(&host, &outcome, "was replaced");
    assert_eq!(installed(&host), "1.0.1");
    assert_eq!(kept(root.path()), (false, false));

    // The service's definition is changed to start something else.
    let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
    let host = fake(&prepared);
    host.state.lock().unwrap().on_hold = Some(Box::new(|state| state.redefined = true));
    let (outcome, _root) = update(&host, prepared, &Patient);
    unchanged(&host, &outcome, "not set up to start");
    assert_eq!(installed(&host), "1.0.0");

    // A staged file, or the saved previous program, is altered after it was verified.
    for altered in ["candidate", "previous"] {
        let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
        let host = fake(&prepared);
        let file = prepared.staging.file(altered);
        fs::remove_file(&file).unwrap();
        put(&file, "something else").unwrap();
        let (outcome, _root) = update(&host, prepared, &Patient);
        unchanged(&host, &outcome, "staged files");
        assert_eq!(installed(&host), "1.0.0");
    }

    // The runtime that grants the hold is another version than the one that was checked.
    let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
    let host = fake(&prepared);
    host.state.lock().unwrap().running.as_mut().unwrap().version = "1.0.1".into();
    let (outcome, _root) = update(&host, prepared, &Patient);
    assert!(
        matches!(&outcome, Outcome::Unchanged(cause) if cause.contains("not the one that was checked")),
        "{outcome:?}"
    );
    assert_eq!(host.state.lock().unwrap().commits, 0);
}

/// Installing never uses up the only copy of a program: the saved previous program and the
/// staged candidate both stay until the update is verified, and a failure to restore keeps
/// them and the journal.
#[test]
fn a_failed_restore_keeps_both_programs_and_the_journal_for_recovery() {
    let prepared = prepare("1.0.0", "broken", "1.0.0", "2.0.0", "device");
    let host = fake(&prepared);
    let previous = prepared.staging.previous();
    let candidate = prepared.staging.candidate();
    let state_dir = prepared.state_dir.clone();
    // The saved program is damaged just as the previous runtime ends.
    let damaged = previous.clone();
    host.state.lock().unwrap().on_commit = Some(Box::new(move |_| {
        fs::remove_file(&damaged).unwrap();
        put(&damaged, "damaged").unwrap();
    }));
    let (outcome, root) = update(&host, prepared, &Patient);
    let Outcome::Stranded(what) = &outcome else {
        panic!("{outcome:?}");
    };
    assert!(what.contains(previous.to_str().unwrap()), "{what}");
    // Nothing was overwritten with bytes that are not the previous program's.
    assert_eq!(installed(&host), "broken");
    assert!(previous.exists() && candidate.exists());
    assert_eq!(kept(root.path()), (true, true));

    // While the saved program is damaged, recovery fails and keeps everything.
    assert!(recovered(&host, &state_dir).is_err());
    assert_eq!(kept(root.path()), (true, true));
    assert_eq!(installed(&host), "broken");

    // With it intact again, the next run restores it and starts the service.
    put(&previous, "1.0.0").unwrap();
    let said = recovered(&host, &state_dir).unwrap();
    assert!(said.contains("restored"), "{said}");
    assert_eq!(installed(&host), "1.0.0");
    assert_eq!(running(&host).as_deref(), Some("1.0.0"));
    assert_eq!(kept(root.path()), (false, false));
}

/// Recovery acts on what is installed and what serves, and neither restarts a healthy
/// service nor ends one that serves.
#[test]
fn recovery_leaves_a_serving_previous_or_new_version_alone() {
    // The update died before the previous runtime retired, with the new program already
    // under it or not. That runtime still serves a peer; it keeps serving, on its own bytes.
    for swapped in [false, true] {
        let (host, state_dir, root) = interrupted(swapped);
        let first = host.state.lock().unwrap().running.clone().unwrap().pid;
        host.state
            .lock()
            .unwrap()
            .running
            .as_mut()
            .unwrap()
            .sessions = 1;
        let said = recovered(&host, &state_dir).unwrap();
        assert!(said.contains("serves as before"), "{said}");
        assert_eq!(installed(&host), "1.0.0");
        let state = host.state.lock().unwrap();
        let process = state.running.as_ref().unwrap();
        assert_eq!((process.pid, process.sessions), (first, 1));
        assert_eq!((state.holds, state.commits, state.starts), (0, 0, 0));
        assert_eq!(kept(root.path()), (false, false));
    }

    // The update died after the new version was up. It serves a peer; it is kept.
    let (host, state_dir, root) = interrupted(true);
    host.state.lock().unwrap().replaced(1);
    let said = recovered(&host, &state_dir).unwrap();
    assert!(said.contains("had finished"), "{said}");
    assert_eq!(installed(&host), "2.0.0");
    let state = host.state.lock().unwrap();
    let process = state.running.as_ref().unwrap();
    assert_eq!((process.version.as_str(), process.sessions), ("2.0.0", 1));
    assert_eq!((state.holds, state.commits, state.starts), (0, 0, 0));
    assert_eq!(kept(root.path()), (false, false));
}

#[test]
fn recovery_starts_a_stopped_service_on_the_previous_program() {
    for swapped in [false, true] {
        let (host, state_dir, root) = interrupted(swapped);
        host.state.lock().unwrap().running = None;
        let said = recovered(&host, &state_dir).unwrap();
        assert!(said.contains("restored"), "{said}");
        assert_eq!(installed(&host), "1.0.0");
        assert_eq!(running(&host).as_deref(), Some("1.0.0"));
        assert_eq!(host.state.lock().unwrap().starts, 1);
        assert_eq!(kept(root.path()), (false, false));
    }
}

/// A recovery that cannot verify the intended program on disk and its service healthy keeps
/// the journal and both programs, so that it can be run again.
#[test]
fn a_recovery_that_cannot_finish_keeps_the_journal_and_both_programs() {
    // The previous program is installed, but the service manager cannot start it.
    let (host, state_dir, root) = interrupted(false);
    host.state.lock().unwrap().running = None;
    let error = recovered(&Stuck(&host), &state_dir).unwrap_err();
    assert!(format!("{error:#}").contains("did not start"), "{error:#}");
    assert_eq!(kept(root.path()), (true, true));
    assert!(saved(root.path()).exists());
    // When the manager can start it again, the same recovery finishes.
    recovered(&host, &state_dir).unwrap();
    assert_eq!(running(&host).as_deref(), Some("1.0.0"));
    assert_eq!(kept(root.path()), (false, false));

    // The new program is installed and not serving, and the saved program is gone: there is
    // nothing verified to go back to, so nothing is cleared and nothing is started.
    let (host, state_dir, root) = interrupted(true);
    host.state.lock().unwrap().running = None;
    fs::remove_file(saved(root.path())).unwrap();
    let error = recovered(&host, &state_dir).unwrap_err();
    assert!(format!("{error:#}").contains("unfinished"), "{error:#}");
    assert_eq!(kept(root.path()), (true, true));
    assert_eq!(installed(&host), "2.0.0");
    assert_eq!(host.state.lock().unwrap().starts, 0);
    // Only once that program is seen serving healthily is the update taken as finished.
    assert!(host.state.lock().unwrap().launch());
    recovered(&host, &state_dir).unwrap();
    assert_eq!(kept(root.path()), (false, false));

    // The service's definition no longer starts the installed program: nothing is started.
    let (host, state_dir, root) = interrupted(false);
    {
        let mut state = host.state.lock().unwrap();
        state.running = None;
        state.redefined = true;
    }
    let error = recovered(&host, &state_dir).unwrap_err();
    assert!(
        format!("{error:#}").contains("not set up to start"),
        "{error:#}"
    );
    assert_eq!(kept(root.path()), (true, true));
    assert_eq!(host.state.lock().unwrap().starts, 0);

    // Another program was installed since and its service is not running: nothing is touched.
    let (host, state_dir, root) = interrupted(true);
    host.state.lock().unwrap().running = None;
    fs::remove_file(&host.installed).unwrap();
    put(&host.installed, "2.0.1").unwrap();
    let error = recovered(&host, &state_dir).unwrap_err();
    assert!(
        format!("{error:#}").contains("replaced by another program"),
        "{error:#}"
    );
    assert_eq!(kept(root.path()), (true, true));
    assert!(saved(root.path()).exists());
    assert_eq!(host.state.lock().unwrap().starts, 0);
}

/// The fixture service with a manager that cannot start anything.
struct Stuck<'a>(&'a Fake);

impl Service for Stuck<'_> {
    fn label(&self) -> String {
        self.0.label()
    }

    fn events(&self) -> PathBuf {
        self.0.events()
    }

    fn launches(&self, program: &Path) -> Result<bool> {
        self.0.launches(program)
    }

    fn state(&self) -> Result<Manager> {
        self.0.state()
    }

    fn start(&self) -> Result<()> {
        bail!("the service manager cannot start it")
    }
}

impl Host for Stuck<'_> {
    fn service(&self) -> &dyn Service {
        self
    }

    fn identify(&self) -> Result<Identity> {
        self.0.identify()
    }

    fn hold(&self) -> Result<Held> {
        self.0.hold()
    }

    fn released(&self) -> bool {
        self.0.released()
    }
}

#[test]
fn a_program_replaced_since_an_interrupted_update_is_left_as_it_is() {
    let (host, state_dir, root) = interrupted(true);
    // Someone installed another build since, and its service runs.
    fs::remove_file(&host.installed).unwrap();
    put(&host.installed, "2.0.1").unwrap();
    host.state.lock().unwrap().replaced(0);
    let said = recovered(&host, &state_dir).unwrap();
    assert!(said.contains("replaced since"), "{said}");
    assert_eq!(installed(&host), "2.0.1");
    let state = host.state.lock().unwrap();
    assert_eq!((state.commits, state.starts), (0, 0));
    assert_eq!(kept(root.path()), (false, false));
}

/// A journal read before the staging lock was taken may describe an update that another run
/// has finished or replaced since. Only the journal as it reads under the lock is acted on.
#[test]
fn a_journal_that_went_stale_before_the_lock_is_not_acted_on() {
    // Another run holds the lock: recovery does not act on the journal it can see.
    let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
    let host = fake(&prepared);
    let state_dir = prepared.state_dir.clone();
    let error = recover(&host, &state_dir, FAST, &Patient).err().unwrap();
    assert!(
        format!("{error:#}").contains("already working"),
        "{error:#}"
    );
    assert_eq!(kept(prepared.root.path()), (true, true));
    assert_eq!(host.state.lock().unwrap().starts, 0);

    // That run finishes and releases the lock. The copy read before is stale: under the
    // lock there is no journal any more, and nothing is done on the strength of the copy.
    let stale = Journal::load(&state_dir).unwrap().unwrap();
    let Prepared {
        root,
        staging,
        installed,
        ..
    } = prepared;
    close(&state_dir, staging).unwrap();
    let lock = |seen: &Journal| loop {
        match Journal::lock(&state_dir, seen, &host) {
            Err(error) if format!("{error:#}").contains("already working") => {
                std::thread::sleep(Duration::from_millis(5));
            }
            locked => return locked,
        }
    };
    assert!(lock(&stale).unwrap().is_none());
    assert_eq!(fs::read_to_string(&installed).unwrap(), "1.0.0");

    // Or another update of the profile is recorded by then: the stale copy is refused.
    let mut newer = stale.clone();
    newer.candidate_version = "2.0.1".into();
    newer.record(&state_dir, Phase::Switching).unwrap();
    let error = lock(&stale).err().unwrap();
    assert!(format!("{error:#}").contains("changed"), "{error:#}");
    // Read fresh, it is the newer one that is returned, with the lock.
    let (_staging, current) = lock(&newer).unwrap().unwrap();
    assert_eq!(current.candidate_version, "2.0.1");
    drop(root);
}

#[test]
fn one_update_at_a_time_works_on_a_program_even_across_profiles() {
    let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
    let error = open(&prepared.installed, &prepared.state_dir)
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("already working"));

    // Another profile's service shares the program. While this profile's update is
    // unfinished, the other cannot sweep its staged files away.
    let Prepared {
        root,
        state_dir,
        installed,
        staging,
        ..
    } = prepared;
    drop(staging);
    let other = root.path().join("other-state");
    private_dir(&other);
    // A process another test is starting can hold a copy of the released lock for a moment.
    let open = |profile: &Path| loop {
        match self::open(&installed, profile) {
            Err(error) if format!("{error:#}").contains("already working") => {
                std::thread::sleep(Duration::from_millis(5));
            }
            opened => return opened,
        }
    };
    let error = open(&other).err().unwrap();
    assert!(format!("{error:#}").contains("unfinished"), "{error:#}");
    assert!(saved(root.path()).exists());
    // Once it is finished, the directory is free for the other profile.
    fs::remove_file(state_dir.join(JOURNAL)).unwrap();
    open(&other).unwrap();
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;

    use super::super::release::fixture::{Answer, Server};
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A program in a directory of its own, with a state directory beside it.
    fn installation() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = scratch();
        let (bin, state) = (root.path().join("bin"), root.path().join("state"));
        private_dir(&bin);
        private_dir(&state);
        let installed = bin.join("massrelay");
        put(&installed, "old program").unwrap();
        (root, installed, state)
    }

    /// The staged download is run and installed, so its directory must be this account's
    /// alone, reached through a directory nobody else can change, with no links in the way.
    #[test]
    fn staging_is_refused_unless_it_is_a_private_boundary() {
        let refused = |installed: &Path, state: &Path, why: &str| {
            let error = open(installed, state).err().unwrap();
            assert!(format!("{error:#}").contains(why), "{error:#}");
        };

        // The program's directory can be changed by its group or by everyone.
        let (_root, installed, state) = installation();
        let bin = installed.parent().unwrap().to_path_buf();
        for open in [0o775, 0o757] {
            chmod(&bin, open);
            refused(&installed, &state, "can be changed by other accounts");
            assert!(!bin.join(STAGING).exists(), "nothing was created there");
        }
        chmod(&bin, 0o755);

        // The installed program itself can be rewritten by its group or by everyone, or is a
        // link to a program elsewhere. It is refused before it is run or saved.
        for open in [0o775, 0o757] {
            chmod(&installed, open);
            refused(&installed, &state, "can be changed by other accounts");
            assert!(!bin.join(STAGING).exists(), "nothing was created there");
        }
        chmod(&installed, 0o755);
        let real = bin.join("real");
        fs::rename(&installed, &real).unwrap();
        std::os::unix::fs::symlink(&real, &installed).unwrap();
        refused(&installed, &state, "not a regular file");
        assert!(!bin.join(STAGING).exists(), "nothing was created there");
        fs::remove_file(&installed).unwrap();
        fs::rename(&real, &installed).unwrap();

        // A sticky directory lets only an entry's owner replace it.
        let (_sticky_root, sticky_program, sticky_state) = installation();
        chmod(sticky_program.parent().unwrap(), 0o1777);
        drop(open(&sticky_program, &sticky_state).unwrap());

        // An existing staging directory that others can enter, or that is a link elsewhere.
        let staging = bin.join(STAGING);
        fs::create_dir(&staging).unwrap();
        chmod(&staging, 0o755);
        refused(&installed, &state, "only this account can use");
        fs::remove_dir(&staging).unwrap();
        let elsewhere = bin.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        chmod(&elsewhere, 0o700);
        std::os::unix::fs::symlink(&elsewhere, &staging).unwrap();
        refused(&installed, &state, "only this account can use");
        fs::remove_file(&staging).unwrap();

        // A lock or a staged file that is a link is not followed.
        fs::create_dir(&staging).unwrap();
        chmod(&staging, 0o700);
        let target = bin.join("target");
        put(&target, "precious").unwrap();
        std::os::unix::fs::symlink(&target, staging.join("lock")).unwrap();
        refused(&installed, &state, "not a regular file");
        fs::remove_file(staging.join("lock")).unwrap();
        let opened = open(&installed, &state).unwrap();
        std::os::unix::fs::symlink(&target, opened.candidate()).unwrap();
        assert!(sha256_file(&opened.candidate()).is_err());
        assert!(
            opened
                .place(&opened.candidate(), "anything", &installed)
                .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), b"precious");
        assert_eq!(fs::read(&installed).unwrap(), b"old program");
    }

    /// The update is closed by removing its journal, durably, before anything else of it is
    /// removed. If the journal cannot be removed, both programs stay, whatever the outcome
    /// was, because a journal that is still there must still find them.
    #[test]
    fn an_update_whose_journal_cannot_be_removed_keeps_both_programs() {
        use std::os::unix::fs::MetadataExt;
        let probe = scratch();
        if fs::metadata(probe.path()).unwrap().uid() == 0 {
            // Root removes files from a read-only directory.
            return;
        }
        let staged = |root: &Path| {
            let staging = root.join("bin").join(STAGING);
            staging.join("previous").exists() && staging.join("candidate").exists()
        };

        // The new version is installed and serving, but the journal cannot be removed.
        let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
        let host = fake(&prepared);
        let state_dir = prepared.state_dir.clone();
        let sealed = state_dir.clone();
        host.state.lock().unwrap().on_commit = Some(Box::new(move |_| chmod(&sealed, 0o555)));
        let (outcome, root) = update(&host, prepared, &Patient);
        let Outcome::Stranded(what) = &outcome else {
            panic!("{outcome:?}");
        };
        assert!(what.contains("could not be removed durably"), "{what}");
        assert_eq!(installed(&host), "2.0.0");
        assert_eq!(running(&host).as_deref(), Some("2.0.0"));
        assert_eq!(kept(root.path()), (true, true));
        assert!(staged(root.path()));
        // The next run cannot remove it either, and keeps everything again.
        let error = recovered(&host, &state_dir).unwrap_err();
        assert!(
            format!("{error:#}").contains("could not be removed durably"),
            "{error:#}"
        );
        assert_eq!(kept(root.path()), (true, true));
        assert!(staged(root.path()));
        // Once it can, the update is closed as the finished one it is.
        chmod(&state_dir, 0o755);
        let said = recovered(&host, &state_dir).unwrap();
        assert!(said.contains("had finished"), "{said}");
        assert_eq!(running(&host).as_deref(), Some("2.0.0"));
        assert_eq!(kept(root.path()), (false, false));

        // The same when nothing was changed at all: a cancelled wait.
        let prepared = prepare("1.0.0", "2.0.0", "1.0.0", "2.0.0", "device");
        let host = fake(&prepared);
        host.state
            .lock()
            .unwrap()
            .running
            .as_mut()
            .unwrap()
            .sessions = 1;
        chmod(&prepared.state_dir, 0o555);
        let state_dir = prepared.state_dir.clone();
        let cancel = Flag::default();
        cancel.0.store(true, Ordering::SeqCst);
        let (outcome, root) = update(&host, prepared, &cancel);
        assert!(matches!(&outcome, Outcome::Stranded(what) if what.contains("cancelled")));
        assert_eq!(kept(root.path()), (true, true));
        assert!(staged(root.path()));
        chmod(&state_dir, 0o755);
    }

    /// The service's own check of a path comes before anything is created or opened there:
    /// first the installed program, then the staging directory.
    #[test]
    fn nothing_is_written_until_the_service_trusts_the_program_and_the_staging_directory() {
        let (_root, installed, state) = installation();
        let staging = installed.parent().unwrap().join(STAGING);

        let error = Staging::open(&installed, &state, &|path| {
            ensure!(path != installed, "the program is not trusted");
            Ok(())
        })
        .err()
        .unwrap();
        assert!(format!("{error:#}").contains("the program is not trusted"));
        assert!(!staging.exists(), "nothing was created beside it");

        let error = Staging::open(&installed, &state, &|path| {
            ensure!(path != staging, "the staging directory is not trusted");
            Ok(())
        })
        .err()
        .unwrap();
        assert!(format!("{error:#}").contains("the staging directory is not trusted"));
        assert_eq!(
            fs::read_dir(&staging).unwrap().count(),
            0,
            "no lock or marker was written"
        );

        let asked = std::cell::RefCell::new(vec![]);
        Staging::open(&installed, &state, &|path| {
            asked.borrow_mut().push(path.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert_eq!(*asked.borrow(), [installed.clone(), staging.clone()]);
    }

    /// The check covers the whole path to the program, not only its own directory: a
    /// directory above it that another account can change, or a symbolic link on the way,
    /// lets that account put another directory, and so another program, in its place.
    #[test]
    fn staging_is_refused_below_an_ancestor_another_account_can_change() {
        let root = scratch();
        let (outer, state) = (root.path().join("outer"), root.path().join("state"));
        private_dir(&outer);
        private_dir(&state);
        let bin = outer.join("opt").join("bin");
        private_dir(&outer.join("opt"));
        private_dir(&bin);
        let installed = bin.join("massrelay");
        put(&installed, "old program").unwrap();
        let refused = |installed: &Path, why: &str| {
            let error = open(installed, &state).err().unwrap();
            assert!(format!("{error:#}").contains(why), "{error:#}");
            let parent = installed.parent().unwrap();
            assert!(!parent.join(STAGING).exists(), "nothing was created there");
        };

        // The program's own directory is private; one two levels up is not.
        for open in [0o775, 0o777] {
            chmod(&outer, open);
            refused(&installed, "can be changed by other accounts");
        }
        chmod(&outer, 0o755);

        // The program is named through a symbolic link to its directory.
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&bin, &alias).unwrap();
        refused(&alias.join("massrelay"), "through a symbolic link");
        // Or through a link higher up.
        let above = root.path().join("above");
        std::os::unix::fs::symlink(&outer, &above).unwrap();
        refused(
            &above.join("opt").join("bin").join("massrelay"),
            "through a symbolic link",
        );

        // An existing staging directory is checked the same way each time it is used.
        let staging = open(&installed, &state).unwrap();
        chmod(&outer, 0o777);
        let error = Staging::check(&staging.dir).unwrap_err();
        assert!(format!("{error:#}").contains("can be changed by other accounts"));
        chmod(&outer, 0o755);
    }

    #[tokio::test]
    #[ignore = "opens a disposable HTTPS server on loopback"]
    async fn a_download_is_staged_privately_beside_the_program_with_its_permissions() {
        let (_root, installed, state) = installation();
        chmod(&installed, 0o750);
        let server = Server::start().await;
        server.publish("v9.8.7", b"new program");
        let source = server.source();
        let client = source.client().unwrap();
        let release = client.latest().await.unwrap();

        let staging = open(&installed, &state).unwrap();
        let digest = stage(&client, &release, &staging, &installed)
            .await
            .unwrap();
        let candidate = staging.candidate();
        assert_eq!(fs::read(&candidate).unwrap(), b"new program");
        assert_eq!(digest, sha256_file(&candidate).unwrap());
        // Same directory tree as the program, so the swap is a rename on one filesystem.
        assert_eq!(staging.dir.parent(), installed.parent());
        assert_eq!(mode(&staging.dir), 0o700);
        assert_eq!(mode(&candidate), 0o750);
        // The installed program is not touched by staging.
        assert_eq!(fs::read(&installed).unwrap(), b"old program");

        // A binary that does not match the published checksum leaves nothing staged.
        let asset = release::asset().unwrap();
        server.route(
            format!("/{}/releases/download/v9.8.7/{asset}", release::REPOSITORY),
            Answer::ok("tampered program"),
        );
        let error = stage(&client, &release, &staging, &installed)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("does not match the checksum"));
        assert!(!candidate.exists());
        assert_eq!(fs::read(&installed).unwrap(), b"old program");
    }

    /// A stand-in candidate: a script that answers the self-check with `body`.
    fn candidate(root: &Path, body: &str) -> PathBuf {
        let path = root.join("candidate");
        put(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        chmod(&path, 0o700);
        path
    }

    fn check(root: &Path, body: &str, limit: Duration) -> Result<()> {
        let release = Release {
            tag: "v9.8.7".into(),
            version: Version::parse("9.8.7").unwrap(),
        };
        let program = candidate(root, body);
        let digest = sha256_file(&program).unwrap();
        loop {
            let checked = preflight(&program, &digest, root, &release, "device", limit);
            // Another test's fork can briefly hold the freshly written script open.
            match &checked {
                Err(error) if format!("{error:#}").contains("Text file busy") => {}
                _ => return checked,
            }
        }
    }

    #[test]
    fn a_candidate_must_pass_its_bounded_self_check_before_anything_stops() {
        let root = tempfile::tempdir().unwrap();
        let limit = Duration::from_secs(20);
        let report = |version: &str, asset: &str, endpoint: &str| {
            format!(
                r#"echo '{{"format":"{SELF_CHECK_FORMAT}","version":"{version}","asset":"{asset}","endpoint":"{endpoint}"}}'"#
            )
        };
        let asset = release::asset().unwrap();
        let good = report("9.8.7", asset, "device");
        check(root.path(), &good, limit).unwrap();

        let refused = |body: String, why: &str| {
            let error = check(root.path(), &body, limit).unwrap_err();
            assert!(format!("{error:#}").contains(why), "{error:#}");
        };
        refused(report("9.8.6", asset, "device"), "reports version 9.8.6");
        refused(
            report("9.8.7", "massrelay-other", "device"),
            "another platform",
        );
        refused(
            report("9.8.7", asset, "someone else"),
            "another device identity",
        );
        refused(
            "echo 'could not reach the relay' >&2; exit 1".into(),
            "could not reach the relay",
        );
        refused("echo nonsense".into(), "no usable report");

        // What runs is the file that was verified: a staged file with other bytes is not run.
        let program = candidate(
            root.path(),
            &format!("touch {}/ran; {good}", root.path().display()),
        );
        let release = Release {
            tag: "v9.8.7".into(),
            version: Version::parse("9.8.7").unwrap(),
        };
        let other = "0".repeat(64);
        let error =
            preflight(&program, &other, root.path(), &release, "device", limit).unwrap_err();
        assert!(format!("{error:#}").contains("not the verified download"));
        assert!(!root.path().join("ran").exists());
    }

    /// The limit covers the candidate's output as well as its exit: neither a candidate that
    /// hangs nor one that exits while a process it started keeps its output open holds the
    /// update up.
    #[test]
    fn a_candidate_cannot_outlast_its_limit_by_hanging_or_leaving_its_output_open() {
        let root = tempfile::tempdir().unwrap();
        let limit = Duration::from_millis(400);
        for body in [
            "exec sleep 60",
            // The candidate exits at once; a child inherits its output and lives on.
            "sleep 60 &\necho '{}'\nexit 0",
            "sleep 60 2>&1 &\nexit 1",
        ] {
            let started = Instant::now();
            let error = check(root.path(), body, limit).unwrap_err();
            assert!(format!("{error:#}").contains("did not finish"), "{error:#}");
            assert!(started.elapsed() < Duration::from_secs(10), "{body}");
        }
    }
}

/// Native acceptance against a real systemd user manager and a real runtime process. It is
/// not part of any ordinary run: `tests/update-systemd.sh` installs a disposable profile's
/// service from a disposable copy of the program, names both here, and removes them again.
/// Only the release download is left out, which the fixture tests above cover.
#[cfg(target_os = "linux")]
mod systemd {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn show(unit: &str, property: &str) -> String {
        let shown = run_within(
            Command::new("systemctl")
                .args(["--user", "show", "--value", "--property"])
                .arg(property)
                .arg(unit),
            MANAGER_LIMIT,
        )
        .unwrap();
        assert!(shown.success, "{}", shown.stderr);
        shown.stdout.trim().to_owned()
    }

    /// Stage `candidate` beside the installed program as an update to `promised`.
    fn stage_update(
        host: &dyn Host,
        state_dir: &Path,
        program: &Path,
        identity: &Identity,
        candidate: &[u8],
        promised: &str,
    ) -> (Staging, Journal) {
        let staging =
            Staging::open(program, state_dir, &|path| host.service().trusts(path)).unwrap();
        staging.sweep();
        fs::write(staging.candidate(), candidate).unwrap();
        fs::set_permissions(staging.candidate(), fs::Permissions::from_mode(0o755)).unwrap();
        let mut journal = Journal {
            format: JOURNAL_FORMAT.into(),
            phase: Phase::Armed,
            installed: program.to_path_buf(),
            previous_version: identity.version.clone(),
            previous_sha256: keep_previous(&staging, program).unwrap(),
            candidate_version: promised.into(),
            candidate_sha256: sha256_file(&staging.candidate()).unwrap(),
            endpoint: identity.endpoint.clone(),
        };
        journal.record(state_dir, Phase::Armed).unwrap();
        (staging, journal)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "run by tests/update-systemd.sh against a disposable systemd user service"]
    async fn a_disposable_systemd_service_is_updated_and_reverted() {
        let (Some(state_dir), Some(program)) = (
            std::env::var_os("MASSRELAY_ACCEPTANCE_STATE_DIR"),
            std::env::var_os("MASSRELAY_ACCEPTANCE_PROGRAM"),
        ) else {
            return;
        };
        let (state_dir, program) = (PathBuf::from(state_dir), PathBuf::from(program));
        let profile = state_dir.join(cli::DIR_NAME);
        let timing = Timing {
            poll: Duration::from_secs(1),
            verify: Duration::from_secs(20),
            retry: Duration::from_secs(1),
        };
        let host = live(&state_dir).unwrap();
        let unit = host.service().label();
        assert_ne!(unit, "massrelay-client.service", "not a disposable profile");
        let serving = |host: Arc<Live<crate::background_service::Managed>>| async move {
            blocking(move || match super::super::serving(host.as_ref()) {
                Serving::Managed(identity) => identity,
                Serving::Stopped => panic!("the service is stopped"),
                Serving::Unsettled(what) => panic!("{what}"),
            })
            .await
            .unwrap()
        };

        // The service as the manager runs it: the real unit, policy and process.
        let first = serving(host.clone()).await;
        assert_eq!(first.executable.as_deref(), program.to_str());
        assert!(host.service().launches(&program).unwrap());
        assert_eq!(show(&unit, "Restart"), "on-failure");
        let restarts: u32 = show(&unit, "NRestarts").parse().unwrap();
        say(format!(
            "acceptance: {unit} runs process {} from {}",
            first.pid,
            program.display()
        ));

        // An update to the same program with other bytes: a different file, the same version.
        let mut candidate = fs::read(&program).unwrap();
        candidate.extend_from_slice(b"\nmassrelay update acceptance candidate\n");
        let (staging, journal) = stage_update(
            host.as_ref(),
            &state_dir,
            &program,
            &first,
            &candidate,
            &first.version,
        );
        let (previous_digest, candidate_digest) = (
            journal.previous_sha256.clone(),
            journal.candidate_sha256.clone(),
        );
        let (applying, dir) = (host.clone(), state_dir.clone());
        let outcome = blocking(move || {
            let host: &dyn Host = applying.as_ref();
            transact(host, &dir, staging, journal, timing, &Patient)
        })
        .await
        .unwrap();
        assert_eq!(outcome, Outcome::Updated);
        assert_eq!(sha256_file(&program).unwrap(), candidate_digest);
        let second = serving(host.clone()).await;
        assert_ne!(second.pid, first.pid, "another process took over");
        assert_eq!(second.endpoint, first.endpoint);
        // Nothing asked systemd to stop or start the unit: the old runtime ended itself with
        // a failure status, and the unit's own `Restart=on-failure` started the new program.
        let restarted: u32 = show(&unit, "NRestarts").parse().unwrap();
        assert_eq!(
            restarted,
            restarts + 1,
            "systemd restarted it once, by its own policy"
        );
        assert!(Journal::load(&state_dir).unwrap().is_none());
        let stage = program.parent().unwrap().join(STAGING);
        assert!(!stage.join("candidate").exists() && !stage.join("previous").exists());
        say(format!(
            "acceptance: updated; systemd restarted {unit} itself as process {}",
            second.pid
        ));

        // An update to a program that does not run: the previous bytes come back and serve.
        let (staging, journal) = stage_update(
            host.as_ref(),
            &state_dir,
            &program,
            &second,
            b"#!/bin/sh\nexit 1\n",
            "999.0.0",
        );
        let (applying, dir) = (host.clone(), state_dir.clone());
        let outcome = blocking(move || {
            let host: &dyn Host = applying.as_ref();
            transact(host, &dir, staging, journal, timing, &Patient)
        })
        .await
        .unwrap();
        assert!(matches!(&outcome, Outcome::RolledBack(_)), "{outcome:?}");
        assert_eq!(sha256_file(&program).unwrap(), candidate_digest);
        assert_ne!(candidate_digest, previous_digest);
        let third = serving(host.clone()).await;
        assert_ne!(third.pid, second.pid);
        assert_eq!(third.endpoint, first.endpoint);
        assert!(profile.join(CONTROL.marker).exists());
        assert!(Journal::load(&state_dir).unwrap().is_none());
        let stage = program.parent().unwrap().join(STAGING);
        assert!(!stage.join("candidate").exists() && !stage.join("previous").exists());
        say(format!(
            "acceptance: a program that does not start was reverted; {unit} serves as process {}",
            third.pid
        ));
    }
}
