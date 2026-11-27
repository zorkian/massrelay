//! `massrelay update` asked for inside one of this device's own shells. The update waits for
//! every session to end and then the daemon ends, so it has to outlive both: it runs as a
//! separate process with a console of its own (not the session's pseudoconsole), outside any
//! job object, with no handle of the session's, writing to a log in the state directory.
//!
//! Only one is queued at a time. `update.lock` admits one opener, and the queuing command, the
//! updater and its helper pass that handle on, so Windows holds it until the last of them has
//! ended, however it ends. Each request logs to a new file, which replaces `update.log` only
//! once its updater is activated, so a refused request leaves the last diagnostics as they
//! were.
//!
//! The queuing command can be ended at any moment, and checks the updater after starting it.
//! So the updater does nothing until that command writes a byte to its input
//! (`wait_for_activation`). If the command ends first the pipe closes, and the updater exits
//! and releases the lock.
//!
//! It runs with the token of the process that queues it. Nothing is registered with Windows
//! and no permission changes. A token that may not start the service is refused before
//! anything is created: its update would leave the device stopped once the daemon retired.

use std::io::Write as _;

use windows_sys::Win32::{
    Foundation::{ERROR_SHARING_VIOLATION, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation},
    System::{
        JobObjects::IsProcessInJob,
        Threading::{
            CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW,
            CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
            EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

use super::*;
use crate::update::Service as _;

const START_REQUIRED: &str = "nothing was queued: the update could not confirm that this \
    shell may start the service again afterwards. Regular shells, including SSH sessions, \
    normally may not. If the service runs as an administrator, open \
    'massrelay shell DEVICE --elevated' from a peer and run 'massrelay update' there, or run \
    it in an elevated PowerShell on this device under the account that installed the service";

/// Set for a queued update alone: its input is the gate it waits at before doing anything.
const GATE: &str = "MASSRELAY_QUEUED_UPDATE";
/// How long a queued update waits for a queuing command that is neither done nor gone.
const ACTIVATION_LIMIT: Duration = Duration::from_secs(30);

/// For `massrelay update` to call before it does anything. A queued update returns once the
/// command that queued it has activated it, and fails if that does not happen. Any other
/// update returns at once.
pub fn wait_for_activation() -> Result<()> {
    if env::var_os(GATE).is_none() {
        return Ok(());
    }
    super::super::await_activation(io::stdin(), ACTIVATION_LIMIT)
}

impl Managed {
    /// Start `program update` for this profile, detached from this session, and return the
    /// path of the log it writes: `update.log`, or the new file itself if that could not be
    /// replaced. `program` must be the one the service runs. Refused while an earlier queued
    /// update, or its helper, is still running.
    pub(crate) fn queue_update(&self, program: &Path) -> Result<String> {
        self.controllable().context(START_REQUIRED)?;
        self.trusts(program)?;
        ensure!(
            self.launches(program)?,
            "the service {} is not set up to start {} for this profile; run the installed \
             program's 'massrelay update'",
            self.name,
            program.display()
        );
        let account = Account::current()?;
        ensure_trusted(&self.dir, Role::Holder, &account)?;
        let program = super::super::plain(
            &program
                .canonicalize()
                .with_context(|| format!("find {}", program.display()))?,
        )?;
        let command = super::super::update_command_line(&program, &self.dir)?;
        let dir = Path::new(&self.dir);
        let lock = queue_lock(&account, dir)?;
        let log = new_log(&account, dir)?;
        let latest = dir.join(super::super::UPDATE_LOG);
        let path = super::super::start_logged(log, &latest, |log| {
            let mut worker = Gated::create(
                &program,
                &command,
                env::vars_os(),
                log,
                &lock,
                CREATE_BREAKAWAY_FROM_JOB,
            )?;
            worker
                .require_no_job()
                .and_then(|()| worker.activate())
                .inspect_err(|_| worker.end())
        })?;
        path.into_os_string()
            .into_string()
            .map_err(|_| anyhow!("the update log's path is not Unicode"))
    }
}

/// Take the profile's queue lock, a file that is never read or written. It is refused while any
/// process still holds the handle from an earlier request.
fn queue_lock(account: &Account, dir: &Path) -> Result<File> {
    let path = dir.join(super::super::UPDATE_LOCK);
    // Windows applies a share mode only against a handle that can read, write or delete.
    let lock = PrivateFile::new(account)?
        .open_sharing(&path, GENERIC_READ, 0, OPEN_ALWAYS)
        .map_err(|error| {
            let context = if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) {
                format!(
                    "an update is already queued or running for this profile (or another \
                     program holds {} open). Its log is update.log beside that file, or the \
                     file named when it was queued",
                    path.display()
                )
            } else {
                format!("open the update queue lock {}", path.display())
            };
            anyhow!(error).context(context)
        })?;
    let metadata = lock.metadata()?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "the update queue lock {} must be a regular file",
        path.display()
    );
    Ok(lock)
}

/// A new log for one request, private to the account. Its name is one nothing has, so no
/// existing file or link is opened. Others may read it and rename it, not write to it. It is
/// removed again unless it is kept.
fn new_log(account: &Account, dir: &Path) -> Result<tempfile::NamedTempFile> {
    let permissions = PrivateFile::new(account)?;
    tempfile::Builder::new()
        .prefix("update-")
        .suffix(".log")
        .make_in(dir, |path| {
            let share = FILE_SHARE_READ | FILE_SHARE_DELETE;
            permissions.open_sharing(path, FILE_APPEND_DATA, share, CREATE_NEW)
        })
        .with_context(|| format!("create an update log in {}", dir.display()))
}

/// An owned process or thread handle.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle is open and owned only by this value.
        unsafe { CloseHandle(self.0) };
    }
}

/// The list naming the only handles a new process inherits.
struct Inherit<'a> {
    list: Vec<usize>,
    _handles: &'a [HANDLE],
}

impl<'a> Inherit<'a> {
    fn only(handles: &'a [HANDLE]) -> Result<Self> {
        let mut bytes = 0;
        // SAFETY: a size query; nothing is written but `bytes`.
        unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes) };
        // `usize` elements keep the list pointer-aligned.
        let mut list = vec![0usize; bytes.div_ceil(size_of::<usize>()).max(1)];
        // SAFETY: the list is writable for at least `bytes` bytes.
        ensure!(
            unsafe {
                InitializeProcThreadAttributeList(list.as_mut_ptr().cast(), 1, 0, &mut bytes)
            } != 0,
            "prepare the update process: {}",
            io::Error::last_os_error()
        );
        let mut inherit = Self {
            list,
            _handles: handles,
        };
        // SAFETY: the list is initialized for one attribute, and the handles outlive it.
        ensure!(
            unsafe {
                UpdateProcThreadAttribute(
                    inherit.list.as_mut_ptr().cast(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    size_of_val(handles),
                    null_mut(),
                    null(),
                )
            } != 0,
            "limit what the update process inherits: {}",
            io::Error::last_os_error()
        );
        Ok(inherit)
    }
}

impl Drop for Inherit<'_> {
    fn drop(&mut self) {
        // SAFETY: the list was initialized in `only`.
        unsafe { DeleteProcThreadAttributeList(self.list.as_mut_ptr().cast()) };
    }
}

/// A new process waiting at its gate, whose writing end this process alone holds.
struct Gated {
    process: Owned,
    gate: io::PipeWriter,
}

impl Gated {
    /// Create `application` under this process's own token, with a hidden console of its own,
    /// in the system directory, with a new gate as its input and `log` as both outputs,
    /// inheriting those and `held` alone, and with `variables` except the one naming the
    /// runtime that serves this shell. It runs at once, and is told by `GATE` to wait for
    /// `activate`.
    fn create(
        application: &str,
        command: &str,
        variables: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
        log: &File,
        held: &File,
        flags: u32,
    ) -> Result<Self> {
        // Neither end is inheritable; the reading end alone is made so, below.
        let (input, gate) = io::pipe().context("create the update's gate")?;
        let handles = [
            input.as_raw_handle(),
            log.as_raw_handle(),
            held.as_raw_handle(),
        ];
        for handle in handles {
            // SAFETY: the handle is open.
            ensure!(
                unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }
                    != 0,
                "prepare the handles the update inherits: {}",
                io::Error::last_os_error()
            );
        }
        let mut inherit = Inherit::only(&handles)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[1];
        startup.lpAttributeList = inherit.list.as_mut_ptr().cast();

        let variables = variables
            .filter(|(name, _)| !name.eq_ignore_ascii_case(GATE))
            .chain([(GATE.into(), "1".into())]);
        let environment =
            super::super::environment_block(variables, |text| text.encode_wide().collect());

        let (application, mut command) = (wide(application)?, wide(command)?);
        let directory = wide(system_directory()?)?;
        let mut process = PROCESS_INFORMATION::default();
        // SAFETY: every string is NUL-terminated, the command line is writable, the
        // environment block ends with two NULs, and these, the attribute list and the two
        // inherited handles live until the call returns.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                flags
                    | CREATE_NO_WINDOW
                    | CREATE_NEW_PROCESS_GROUP
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                directory.as_ptr(),
                &startup.StartupInfo,
                &mut process,
            )
        };
        ensure!(
            created != 0,
            "start the detached update (a job object around this shell may forbid leaving \
             it): {}",
            io::Error::last_os_error()
        );
        drop(Owned(process.hThread));
        Ok(Self {
            process: Owned(process.hProcess),
            gate,
        })
    }

    /// A job object can end its processes when the session or daemon that owns it ends, and
    /// the limits of an enclosing job cannot be read from here. So the update must be in none.
    fn require_no_job(&self) -> Result<()> {
        let mut member = 0;
        // SAFETY: the process handle is open; a null job asks about any job.
        ensure!(
            unsafe { IsProcessInJob(self.process.0, null_mut(), &mut member) } != 0,
            "check the update's job membership: {}",
            io::Error::last_os_error()
        );
        ensure!(
            member == 0,
            "nothing was queued: Windows kept the update inside a job object, which could end \
             it along with this shell or the service. Run 'massrelay update' in an elevated \
             PowerShell on this device"
        );
        Ok(())
    }

    /// Let the process act.
    fn activate(&mut self) -> Result<()> {
        self.gate
            .write_all(&[super::super::ACTIVATE])
            .context("activate the detached update")
    }

    /// End a refused process, and wait for it to let go of the lock and its log.
    fn end(&self) {
        // SAFETY: the process handle is open and grants termination and waiting.
        unsafe {
            TerminateProcess(self.process.0, 1);
            WaitForSingleObject(self.process.0, 10_000);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};

    use super::super::super::{UPDATE_LOG, plain, quote, start_logged};
    use super::*;
    use windows_sys::Win32::{Foundation::WAIT_OBJECT_0, System::Threading::GetExitCodeProcess};

    /// Stands in for `massrelay update` in the test below: it waits at the gate, and then
    /// leaves a process running as the update leaves its helper.
    #[test]
    #[ignore = "started by the queued update test as its worker"]
    #[allow(clippy::zombie_processes)]
    fn queued_worker() -> Result<()> {
        if env::var_os(GATE).is_none() {
            return Ok(());
        }
        wait_for_activation()?;
        ensure!(
            env::var_os(crate::private::HOST_ENV).is_none(),
            "the shell's marker was kept"
        );
        println!("worker-ran");
        // Started as `hand_over` starts the helper.
        let mut helper = Command::new(system_directory()?.join("ping.exe"))
            .args(["-n", "8", "127.0.0.1"])
            .stdin(Stdio::piped())
            .spawn()?;
        std::mem::forget(helper.stdin.take());
        Ok(())
    }

    /// The exit code of a process that ends within `limit`.
    fn exit_code(process: &Owned, limit: Duration) -> Result<u32> {
        let wait = u32::try_from(limit.as_millis())?;
        // SAFETY: the process handle is open.
        ensure!(
            unsafe { WaitForSingleObject(process.0, wait) } == WAIT_OBJECT_0,
            "the worker did not end"
        );
        let mut code = 0;
        // SAFETY: the process handle is open and `code` is writable.
        ensure!(
            unsafe { GetExitCodeProcess(process.0, &mut code) } != 0,
            "read the worker's exit code: {}",
            io::Error::last_os_error()
        );
        Ok(code)
    }

    /// Job membership depends on what runs the tests, so the worker is not asked to leave
    /// one here. Run single-threaded: another test's child could inherit these handles.
    #[test]
    fn a_queued_update_acts_only_when_activated_and_keeps_the_lock_to_its_helper() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let dir = temp.path();
        let latest = dir.join(UPDATE_LOG);
        fs::write(&latest, "previous")?;
        let account = Account::current()?;
        let this = plain(&env::current_exe()?.canonicalize()?)?;
        let (_, module) = module_path!().split_once("::").context("the test module")?;
        let command = format!(
            "{} {module}::queued_worker --exact --ignored --nocapture",
            quote(&this)?
        );
        let marked = || env::vars_os().chain([("MassRelay_Shell_Host".into(), "1".into())]);

        // A process Windows cannot create leaves the previous log, and no new one.
        let lock = queue_lock(&account, dir)?;
        assert!(queue_lock(&account, dir).is_err());
        let missing = plain(&system_directory()?.join("massrelay-no-such-program.exe"))?;
        let refused = start_logged(new_log(&account, dir)?, &latest, |log| {
            Gated::create(&missing, "update", marked(), log, &lock, 0).map(drop)
        });
        assert!(refused.is_err());
        assert_eq!(fs::read_to_string(&latest)?, "previous");
        assert_eq!(fs::read_dir(dir)?.count(), 2);

        // The queuing command is ended before it activates the worker: its handles close.
        let log = new_log(&account, dir)?;
        let Gated { process, gate } =
            Gated::create(&this, &command, marked(), log.as_file(), &lock, 0)?;
        drop(lock);
        assert!(queue_lock(&account, dir).is_err());
        drop(gate);
        // Well within the gate's time limit, so it was the closed pipe that ended it.
        assert_ne!(exit_code(&process, ACTIVATION_LIMIT / 2)?, 0);
        let text = fs::read_to_string(log.path())?;
        assert!(text.contains("did not activate"), "{text}");
        assert!(!text.contains("worker-ran"), "{text}");
        assert_eq!(fs::read_to_string(&latest)?, "previous");
        let lock = queue_lock(&account, dir)?;
        drop(log);

        // What an SSH command's output is: a pipe this process passes on to children.
        let (mut session, output) = io::pipe()?;
        // SAFETY: the pipe's handle is open.
        ensure!(
            unsafe {
                SetHandleInformation(
                    output.as_raw_handle(),
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT,
                )
            } != 0,
            "make the pipe inheritable"
        );
        let mut process = None;
        let path = start_logged(new_log(&account, dir)?, &latest, |log| {
            let mut worker = Gated::create(&this, &command, marked(), log, &lock, 0)?;
            worker.activate()?;
            process = Some(worker.process);
            Ok(())
        })?;
        assert_eq!(path, latest);
        drop((lock, output));

        // The pipe ends while the update still runs, so none of its processes holds it.
        session.read_to_end(&mut Vec::new())?;
        let process = process.context("no worker")?;
        assert_eq!(exit_code(&process, ACTIVATION_LIMIT)?, 0);
        // The process it left behind holds the lock until that ends too.
        assert!(queue_lock(&account, dir).is_err());
        let deadline = Instant::now() + Duration::from_secs(30);
        while queue_lock(&account, dir).is_err() {
            ensure!(Instant::now() < deadline, "the lock was never released");
            thread::sleep(POLL);
        }
        let text = fs::read_to_string(&latest)?;
        assert!(text.contains("worker-ran"), "{text}");
        Ok(())
    }
}
