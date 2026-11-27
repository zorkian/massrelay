//! Windows backend: ConPTY, driven directly through `windows-sys`.
//!
//! `portable_pty` hides the ConPTY input pipe behind a blocking writer, so
//! this backend creates the pipes and the pseudoconsole itself. The input
//! pipe's write end is put in nonblocking mode (`PIPE_NOWAIT`), which makes
//! every input write one `WriteFile` that returns at once: it writes what
//! fits (possibly nothing) and never waits for the console host to read.
//! See the parent module for the boundary this gives.
//!
//! # Privilege
//!
//! A shell is *regular* unless the caller asks for an elevated one.
//!
//! A regular shell never holds administrator rights. When this process has
//! none (a standard account, or an administrator's UAC-limited token) the
//! shell inherits its token. Otherwise (an elevated terminal, or a service
//! of an administrator account, whose service logon has no limited twin)
//! the shell gets a filtered copy of this process's own primary token:
//! `CreateRestrictedToken` with `LUA_TOKEN`, `BUILTIN\Administrators` made
//! deny-only and every privilege a standard user lacks deleted; then medium
//! integrity, the user as owner and a default DACL for the user. The copy
//! is checked (primary, Administrators not enabled, not elevated, at most
//! medium integrity, no other privilege) before `CreateProcessAsUserW` uses
//! it, and any failure refuses the shell. A restricted child of the
//! caller's own token needs no `SeAssignPrimaryTokenPrivilege`. Neither the
//! linked token nor the desktop shell's token is used, so nothing depends
//! on a limited token or a signed-in desktop existing.
//!
//! An elevated shell inherits this process's token, and only when that
//! token is an administrator's: Administrators enabled, elevated and at
//! high integrity or above. Nothing asks UAC for consent; without such a
//! token the shell is refused.
//!
//! Limits: the pseudoconsole host is started by `CreatePseudoConsole` under
//! this process's token whatever the shell's, and a regular shell is still
//! the same account, so it can read and write what the account itself (not
//! the Administrators group) is granted.

use super::*;
use std::ffi::{OsStr, OsString, c_void};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::pin::Pin;
use std::ptr::{null, null_mut};
use std::sync::mpsc::RecvTimeoutError;
use std::task::{Context, Poll, ready};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch};
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, LUID, SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, CheckTokenMembership,
    CreateRestrictedToken, CreateWellKnownSid, DuplicateToken, EqualSid, GetLengthSid,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, InitializeAcl, LUA_TOKEN,
    LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, PSID, SE_CHANGE_NOTIFY_NAME,
    SE_INC_WORKING_SET_NAME, SE_SHUTDOWN_NAME, SE_TIME_ZONE_NAME, SE_UNDOCK_NAME,
    SID_AND_ATTRIBUTES, SecurityIdentification, SetTokenInformation, TOKEN_ACCESS_MASK,
    TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE,
    TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_OWNER,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_TYPE, TOKEN_USER, TokenDefaultDacl, TokenElevation,
    TokenGroups, TokenIntegrityLevel, TokenOwner, TokenPrimary, TokenPrivileges, TokenType,
    TokenUser, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    WinMediumLabelSid,
};
use windows_sys::Win32::Security::{LookupAccountSidW, SidTypeUser};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, ReadFile, WriteFile};
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, GetStdHandle, HPCON, ResizePseudoConsole,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Pipes::{CreatePipe, PIPE_NOWAIT, SetNamedPipeHandleState};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

/// Requested buffer of each pipe. Large enough that the console host's
/// startup output, and a whole input write, fit without a reader.
const PIPE_BUFFER: u32 = 64 * 1024;
/// Largest single input write. Well under `PIPE_BUFFER`, so a write makes
/// progress once the host has read whatever was already queued.
const MAX_WRITE: usize = 4096;
/// Retry interval for an input write that found the pipe full: a
/// nonblocking pipe has no readiness signal.
const WRITE_RETRY: Duration = Duration::from_millis(10);
/// Reaper poll interval, as on Unix.
const REAP_POLL: Duration = Duration::from_millis(30);
/// Output read size.
const READ_CHUNK: usize = 8192;

/// `SE_GROUP_ENABLED`: the group counts in access checks. A deny-only group
/// does not have it.
const GROUP_ENABLED: u32 = 0x4;
/// `SE_GROUP_INTEGRITY`: the attribute of a mandatory label.
const GROUP_INTEGRITY: u32 = 0x20;
/// `SE_GROUP_LOGON_ID`: the group is the logon session's own SID.
const GROUP_LOGON_ID: u32 = 0xC000_0000;
/// `SECURITY_MANDATORY_MEDIUM_RID`, a standard user's integrity level.
const INTEGRITY_MEDIUM: u32 = 0x2000;
/// `SECURITY_MANDATORY_HIGH_RID`, an administrator's integrity level.
const INTEGRITY_HIGH: u32 = 0x3000;
/// The privileges of a standard user (the ones UAC leaves in an
/// administrator's limited token). A regular shell holds no other.
const REGULAR_PRIVILEGES: [windows_sys::core::PCWSTR; 5] = [
    SE_CHANGE_NOTIFY_NAME,
    SE_SHUTDOWN_NAME,
    SE_UNDOCK_NAME,
    SE_INC_WORKING_SET_NAME,
    SE_TIME_ZONE_NAME,
];

/// An owned kernel handle (pipe end or process).
struct Handle(HANDLE);

// SAFETY: a pipe or process handle is a process-wide kernel reference that
// any thread may use; every use here is a single synchronous call.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is open and owned only by this value.
        unsafe { CloseHandle(self.0) };
    }
}

impl From<Handle> for std::fs::File {
    fn from(handle: Handle) -> Self {
        let handle = std::mem::ManuallyDrop::new(handle);
        // SAFETY: the open handle was owned by Handle and is now owned by File.
        unsafe { Self::from_raw_handle(handle.0) }
    }
}

/// The pseudoconsole, closed on drop. Owned by the reaper.
struct Console(HPCON);

impl Drop for Console {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful `CreatePseudoConsole` and
        // is closed only here. Before Windows 11 24H2 this waits until the
        // host has written its last output; the reader thread keeps draining
        // the output pipe until it ends, so the wait is bounded by the host.
        unsafe { ClosePseudoConsole(self.0) };
    }
}

/// The shell process. Dropping it kills the shell (if still running) and
/// waits until it has exited.
struct Shell(Handle);

impl Shell {
    fn exited(&self) -> bool {
        // SAFETY: the process handle is open.
        unsafe { WaitForSingleObject(self.0.0, 0) == WAIT_OBJECT_0 }
    }

    fn exit_code(&self) -> io::Result<i32> {
        let mut code = 0u32;
        // SAFETY: the process handle is open; `code` is a valid out pointer.
        check(unsafe { GetExitCodeProcess(self.0.0, &mut code) })?;
        Ok(i32::try_from(code).unwrap_or(1))
    }
}

impl Drop for Shell {
    fn drop(&mut self) {
        if !self.exited() {
            // SAFETY: the process handle is open. Termination is
            // asynchronous, so wait until the process has exited.
            unsafe {
                TerminateProcess(self.0.0, 1);
                WaitForSingleObject(self.0.0, INFINITE);
            }
        }
    }
}

pub struct Pty {
    /// Declared first, so it is dropped first: the reader thread then
    /// discards output instead of waiting for a consumer.
    output: std::sync::Mutex<Output>,
    /// The input pipe's write end, in nonblocking mode.
    input: Handle,
    exited: Option<oneshot::Receiver<io::Result<i32>>>,
    /// Dropping it wakes the reaper, which kills and reaps the shell.
    _stop: std::sync::mpsc::Sender<()>,
    reaper: Option<JoinHandle<()>>,
}

struct Output {
    chunks: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    at: usize,
}

/// Spawn `shell` (or `%ComSpec%`, else `cmd.exe`) on a new pseudoconsole,
/// as a regular shell: one without administrator rights, whatever this
/// process holds. `token` is held by the reaper until the shell is reaped
/// and the pseudoconsole closed, and by the output reader until the output
/// ends.
#[cfg(test)]
pub fn spawn(cols: u16, rows: u16, shell: Option<&Path>, token: Arc<()>) -> io::Result<Pty> {
    Pty::spawn_with_privilege(cols, rows, shell, token, false)
}

impl Pty {
    /// Start a shell at the chosen privilege. A regular shell (`elevated` false)
    /// never holds administrator rights; it is refused when a token without
    /// them cannot be made and verified. An elevated shell runs with this
    /// process's administrator token and is refused with
    /// `ErrorKind::PermissionDenied` when this process has none: nothing
    /// prompts for elevation. The token is settled before any pipe,
    /// pseudoconsole or thread exists.
    pub fn spawn_with_privilege(
        cols: u16,
        rows: u16,
        shell: Option<&Path>,
        token: Arc<()>,
        elevated: bool,
    ) -> io::Result<Pty> {
        let identity = Identity::select(elevated)?;
        launch(cols, rows, shell, token, &identity, None)
    }

    pub(in crate::private) fn spawn_ssh(
        shell: &Path,
        arguments: &str,
        dimensions: watch::Receiver<(u16, u16)>,
    ) -> io::Result<Self> {
        require_regular_process()?;
        let (cols, rows) = *dimensions.borrow();
        launch(
            cols,
            rows,
            Some(shell),
            Arc::new(()),
            &Identity::Inherited,
            Some((arguments, dimensions)),
        )
    }
}

/// Start the shell under `identity` on a new pseudoconsole.
fn launch(
    cols: u16,
    rows: u16,
    shell: Option<&Path>,
    token: Arc<()>,
    identity: &Identity,
    ssh: Option<(&str, watch::Receiver<(u16, u16)>)>,
) -> io::Result<Pty> {
    let (input_read, input) = input_pipe()?;
    let (output, output_write) = pipe()?;
    // Start the reaper before creating ConPTY. A thread creation failure
    // leaves no shell or console to shut down with a live output receiver.
    let (start_reaper, ready) = std::sync::mpsc::channel();
    let reaper = std::thread::Builder::new()
        .name("massrelay-private-pty-wait".into())
        .spawn(move || {
            if let Ok((shell, console, reader, exit, stop, token, dimensions)) = ready.recv() {
                reap(shell, console, reader, exit, stop, token, dimensions);
            }
        })?;
    let mut con: HPCON = 0;
    // SAFETY: both handles are open pipe ends; `con` is a valid out pointer.
    let hr =
        unsafe { CreatePseudoConsole(size(cols, rows), input_read.0, output_write.0, 0, &mut con) };
    if hr < 0 {
        return Err(other(format!("CreatePseudoConsole: HRESULT {hr:#x}")));
    }
    let console = Console(con);
    // The host holds its own duplicates. Ours would keep the output open
    // after the host has gone.
    drop((input_read, output_write));
    let (chunks, rx) = mpsc::channel(16);
    let reader = {
        let token = token.clone();
        std::thread::Builder::new()
            .name("massrelay-private-pty-read".into())
            .spawn(move || read_output(output, chunks, token))?
    };
    let (arguments, dimensions) = match ssh {
        Some((arguments, dimensions)) => (arguments, Some(dimensions)),
        None => ("", None),
    };
    let shell = Shell(start(
        con,
        shell,
        arguments,
        identity,
        dimensions.is_some(),
    )?);
    let (exit_tx, exited) = oneshot::channel();
    let (_stop, stop) = std::sync::mpsc::channel::<()>();
    if let Err(unsent) =
        start_reaper.send((shell, console, reader, exit_tx, stop, token, dimensions))
    {
        // Disconnect output first so the reader drains while ConPTY closes.
        drop(rx);
        drop(unsent);
        return Err(other("the pseudoconsole reaper exited before startup"));
    }
    Ok(Pty {
        output: std::sync::Mutex::new(Output {
            chunks: rx,
            pending: Vec::new(),
            at: 0,
        }),
        input,
        exited: Some(exited),
        _stop,
        reaper: Some(reaper),
    })
}

/// Report the shell's exit once, then wait for the `Pty` to be dropped;
/// then kill the shell if it is still running, close the pseudoconsole and
/// wait for the output reader.
fn reap(
    shell: Shell,
    console: Console,
    reader: JoinHandle<()>,
    exit: oneshot::Sender<io::Result<i32>>,
    stop: std::sync::mpsc::Receiver<()>,
    _token: Arc<()>,
    mut dimensions: Option<watch::Receiver<(u16, u16)>>,
) {
    let mut exit = Some(exit);
    loop {
        // SAFETY: the process handle is open.
        let status = unsafe { WaitForSingleObject(shell.0.0, 0) };
        let report = match status {
            WAIT_TIMEOUT => match stop.recv_timeout(REAP_POLL) {
                Err(RecvTimeoutError::Timeout) => {
                    if let Some(dimensions) = dimensions.as_mut()
                        && dimensions.has_changed().unwrap_or(false)
                    {
                        let (cols, rows) = *dimensions.borrow_and_update();
                        // SAFETY: the reaper owns this open pseudoconsole.
                        unsafe { ResizePseudoConsole(console.0, size(cols, rows)) };
                    }
                    continue;
                }
                _ => break,
            },
            WAIT_OBJECT_0 => shell.exit_code(),
            _ => Err(io::Error::last_os_error()),
        };
        if let Some(exit) = exit.take() {
            let _ = exit.send(report);
        }
        if dimensions.is_none() {
            // Nobody sends; this returns when the legacy `Pty` is dropped.
            let _ = stop.recv();
        }
        break;
    }
    drop(shell);
    drop(console);
    let _ = reader.join();
}

/// Forward output chunks until the output pipe ends (the pseudoconsole was
/// closed). Once the consumer is gone, keep draining so the host never
/// blocks on a full pipe.
fn read_output(pipe: Handle, chunks: mpsc::Sender<Vec<u8>>, _token: Arc<()>) {
    let mut chunks = Some(chunks);
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let mut n = 0u32;
        // SAFETY: the handle is open and synchronous; `buf` is valid for
        // its length; `n` is a valid out pointer.
        let ok = unsafe {
            ReadFile(
                pipe.0,
                buf.as_mut_ptr(),
                READ_CHUNK as u32,
                &mut n,
                null_mut(),
            )
        };
        if ok == 0 {
            // ERROR_BROKEN_PIPE: every write end is closed.
            return;
        }
        if n == 0 {
            continue;
        }
        if let Some(tx) = &chunks
            && tx.blocking_send(buf[..n as usize].to_vec()).is_err()
        {
            chunks = None;
        }
    }
}

/// A new anonymous pipe, (read end, write end). Neither end is inheritable.
fn pipe() -> io::Result<(Handle, Handle)> {
    let (mut read, mut write) = (null_mut(), null_mut());
    // SAFETY: valid out pointers; no security attributes, so the handles
    // are not inheritable.
    check(unsafe { CreatePipe(&mut read, &mut write, null(), PIPE_BUFFER) })?;
    Ok((Handle(read), Handle(write)))
}

fn input_pipe() -> io::Result<(Handle, Handle)> {
    let (read, write) = pipe()?;
    // SAFETY: `write` is an open pipe handle; the mode is a valid value.
    check(unsafe { SetNamedPipeHandleState(write.0, &PIPE_NOWAIT, null(), null()) })?;
    Ok((read, write))
}

/// A native input pipe with an open but deliberately idle reader.
#[cfg(test)]
pub(crate) struct TestInput {
    _read: Handle,
    write: Handle,
}

#[cfg(test)]
impl TestInput {
    pub(crate) fn new() -> io::Result<Self> {
        let (read, write) = input_pipe()?;
        Ok(Self { _read: read, write })
    }

    pub(crate) fn writer(&self) -> PtyWriter<'_> {
        PtyWriter {
            pipe: &self.write,
            retry: None,
        }
    }
}

fn pty_error(action: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{action}: {error}"))
}

/// Start the shell attached to `con` under `identity`, returning its
/// process handle.
fn start(
    con: HPCON,
    shell: Option<&Path>,
    arguments: &str,
    identity: &Identity,
    ssh: bool,
) -> io::Result<Handle> {
    let program: OsString = match shell {
        Some(path) => path.as_os_str().to_owned(),
        None => std::env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into()),
    };
    let mut command_line = quote(&program)?;
    command_line.pop();
    command_line.extend(arguments.encode_utf16());
    command_line.push(0);
    let application = shell.filter(|_| ssh).map(|path| wide(path.as_os_str()));
    let application = application.as_ref().map_or(null(), |path| path.as_ptr());
    let environment = environment(ssh);
    let directory = std::env::var_os("USERPROFILE")
        .filter(|dir| Path::new(dir).is_dir())
        .map(|dir| wide(&dir));

    let mut attributes = Attributes::new()?;
    // SAFETY: the list is initialized for one attribute; for this attribute
    // the value is the HPCON itself, which outlives the process creation.
    check(unsafe {
        UpdateProcThreadAttribute(
            attributes.list(),
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            con as *const c_void,
            std::mem::size_of::<HPCON>(),
            null_mut(),
            null(),
        )
    })?;
    let mut info = STARTUPINFOEXW::default();
    info.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    // Without this the shell would inherit this process's standard handles
    // when they are redirected (a service's log file) instead of using the
    // pseudoconsole.
    info.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    info.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
    info.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
    info.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
    info.lpAttributeList = attributes.list();
    let mut process = PROCESS_INFORMATION::default();
    let flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
    let directory = directory.as_ref().map_or(null(), |d| d.as_ptr());
    // SAFETY: every pointer is valid for the call: the command line is a
    // mutable NUL-terminated buffer, the environment a double-NUL-terminated
    // UTF-16 block, the directory NUL-terminated or null. No handle is
    // inherited. A filtered token is an open primary token with
    // TOKEN_QUERY, TOKEN_DUPLICATE and TOKEN_ASSIGN_PRIMARY access.
    check(unsafe {
        match identity {
            Identity::Inherited => CreateProcessW(
                application,
                command_line.as_mut_ptr(),
                null(),
                null(),
                0,
                flags,
                environment.as_ptr() as *const c_void,
                directory,
                &info.StartupInfo,
                &mut process,
            ),
            Identity::Filtered(token) => CreateProcessAsUserW(
                token.0,
                application,
                command_line.as_mut_ptr(),
                null(),
                null(),
                0,
                flags,
                environment.as_ptr() as *const c_void,
                directory,
                &info.StartupInfo,
                &mut process,
            ),
        }
    })
    .map_err(|error| {
        let action = match identity {
            Identity::Inherited => "CreateProcessW",
            Identity::Filtered(_) => "CreateProcessAsUserW",
        };
        pty_error(action, error)
    })?;
    drop(Handle(process.hThread));
    Ok(Handle(process.hProcess))
}

/// The token a shell runs under.
enum Identity {
    /// This process's own token, which `CreateProcessW` hands on.
    Inherited,
    /// A filtered copy of this process's token without administrator
    /// rights, for `CreateProcessAsUserW`.
    Filtered(Handle),
}

impl Identity {
    /// Settle the token for a shell, or refuse the shell. See the module
    /// documentation for what each privilege requires.
    fn select(elevated: bool) -> io::Result<Self> {
        if elevated {
            let own = process_token(TOKEN_QUERY | TOKEN_DUPLICATE)?;
            if !Standing::of(&own)?.is_administrator() || !effective_admin(&own)? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "an elevated shell needs MassRelay itself to run with administrator rights",
                ));
            }
            return Ok(Self::Inherited);
        }
        let kept = regular_privileges()?;
        if is_regular_token(&process_token(TOKEN_QUERY)?, &kept)? {
            return Ok(Self::Inherited);
        }
        filtered_token(&kept).map(Self::Filtered)
    }
}

/// Check membership against the exact runtime token, including restricting
/// SIDs, without impersonating on this thread.
fn effective_admin(token: &Handle) -> io::Result<bool> {
    let mut duplicate = null_mut();
    // SAFETY: the source has TOKEN_DUPLICATE; the output pointer is valid.
    check(unsafe { DuplicateToken(token.0, SecurityIdentification, &mut duplicate) })?;
    let duplicate = Handle(duplicate);
    let admins = Sid::well_known(WinBuiltinAdministratorsSid)?;
    let mut member = 0;
    // SAFETY: the duplicate is an open impersonation token; the SID and output
    // pointer are valid.
    check(unsafe { CheckTokenMembership(duplicate.0, admins.as_psid(), &mut member) })?;
    Ok(member != 0)
}

/// What a token may do, as far as choosing a shell's privilege goes.
struct Standing {
    /// `BUILTIN\Administrators` is enabled for access checks.
    administrator: bool,
    /// Windows reports the token as elevated: it holds an administrative
    /// group or privilege.
    elevated: bool,
    /// The mandatory integrity level (the label's last subauthority).
    integrity: u32,
}

impl Standing {
    fn of(token: &Handle) -> io::Result<Self> {
        let admins = Sid::well_known(WinBuiltinAdministratorsSid)?;
        let groups = token_info(token, TokenGroups)?;
        // SAFETY: `groups` holds the TOKEN_GROUPS just read.
        let groups = unsafe { group_entries(&groups) }?;
        let administrator = groups.iter().any(|group| {
            // SAFETY: both are valid SIDs: one from the token, one built above.
            group.Attributes & GROUP_ENABLED != 0
                && unsafe { EqualSid(group.Sid, admins.as_psid()) } != 0
        });
        let elevation = token_info(token, TokenElevation)?;
        // SAFETY: the buffer holds the TOKEN_ELEVATION just read.
        let elevated = unsafe { (*elevation.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated };
        Ok(Self {
            administrator,
            elevated: elevated != 0,
            integrity: integrity(token)?,
        })
    }

    /// No administrator rights of any kind.
    fn is_regular(&self) -> bool {
        !self.administrator && !self.elevated && self.integrity <= INTEGRITY_MEDIUM
    }

    /// An administrator's token as a process actually runs with it; a
    /// UAC-limited token of an administrator account is not one.
    fn is_administrator(&self) -> bool {
        self.administrator && self.elevated && self.integrity >= INTEGRITY_HIGH
    }
}

/// A filtered copy of this process's primary token that passed every check
/// for a regular shell.
fn filtered_token(kept: &[LUID]) -> io::Result<Handle> {
    // The new token's handle carries the same access as this one.
    let own =
        process_token(TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT)?;
    let user = token_info(&own, TokenUser)?;
    // SAFETY: the buffer holds the TOKEN_USER just read; its SID points into
    // the buffer, which lives to the end of this function.
    let user = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let system = Sid::well_known(WinLocalSystemSid)?;
    // SAFETY: both are valid SIDs.
    if unsafe { EqualSid(user, system.as_psid()) } != 0 {
        // Filtering cannot take away what the SYSTEM account itself is granted.
        return Err(other("a shell run by the SYSTEM account cannot be regular"));
    }

    let held = token_info(&own, TokenPrivileges)?;
    // SAFETY: `held` holds the TOKEN_PRIVILEGES just read.
    let held = unsafe { privilege_entries(&held) }?;
    let delete: Vec<LUID_AND_ATTRIBUTES> = held
        .iter()
        .filter(|privilege| !kept.iter().any(|keep| same_luid(keep, &privilege.Luid)))
        .map(|privilege| LUID_AND_ATTRIBUTES {
            Luid: privilege.Luid,
            Attributes: 0,
        })
        .collect();
    let admins = Sid::well_known(WinBuiltinAdministratorsSid)?;
    let deny_only = [SID_AND_ATTRIBUTES {
        Sid: admins.as_psid(),
        Attributes: 0,
    }];
    let mut filtered = null_mut();
    // SAFETY: `own` is open with TOKEN_DUPLICATE; both lists are valid for
    // the counts given; `filtered` is a valid out pointer. LUA_TOKEN applies
    // the UAC filter (administrative groups deny-only, administrative
    // privileges removed); the lists make the two outcomes this relies on
    // explicit.
    check(unsafe {
        CreateRestrictedToken(
            own.0,
            LUA_TOKEN,
            deny_only.len() as u32,
            deny_only.as_ptr(),
            delete.len() as u32,
            delete.as_ptr(),
            0,
            null(),
            &mut filtered,
        )
    })
    .map_err(|error| pty_error("CreateRestrictedToken", error))?;
    let filtered = Handle(filtered);

    // Filtering leaves the integrity level alone. A token's level may always
    // be lowered.
    if integrity(&filtered)? > INTEGRITY_MEDIUM {
        let medium = Sid::well_known(WinMediumLabelSid)?;
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: medium.as_psid(),
                Attributes: GROUP_INTEGRITY,
            },
        };
        // SAFETY: `label` and its SID are valid for the call.
        let bytes = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32
            + unsafe { GetLengthSid(medium.as_psid()) };
        // SAFETY: as above; the handle has TOKEN_ADJUST_DEFAULT access.
        check(unsafe {
            SetTokenInformation(
                filtered.0,
                TokenIntegrityLevel,
                (&raw const label).cast(),
                bytes,
            )
        })
        .map_err(|error| pty_error("set regular shell integrity", error))?;
    }

    // An administrator's token names Administrators as the owner of what it
    // creates and grants those objects to Administrators and SYSTEM only.
    // With Administrators deny-only, the shell could not reopen its own
    // objects. Give it what a standard user's token has.
    let owner = TOKEN_OWNER { Owner: user };
    // SAFETY: `owner` and the user SID are valid for the call.
    check(unsafe {
        SetTokenInformation(
            filtered.0,
            TokenOwner,
            (&raw const owner).cast(),
            std::mem::size_of::<TOKEN_OWNER>() as u32,
        )
    })
    .map_err(|error| pty_error("set regular shell token owner", error))?;
    let groups = token_info(&filtered, TokenGroups)?;
    // SAFETY: `groups` holds the TOKEN_GROUPS just read.
    let logon = unsafe { group_entries(&groups) }?
        .iter()
        .find(|group| group.Attributes & GROUP_LOGON_ID == GROUP_LOGON_ID)
        .map(|group| (group.Sid, GENERIC_READ | GENERIC_EXECUTE));
    let grants: Vec<(PSID, u32)> = [(user, GENERIC_ALL), (system.as_psid(), GENERIC_ALL)]
        .into_iter()
        .chain(logon)
        .collect();
    let mut acl = acl(&grants)?;
    let dacl = TOKEN_DEFAULT_DACL {
        DefaultDacl: acl.as_mut_ptr().cast(),
    };
    // SAFETY: `dacl` points at the access list built above.
    check(unsafe {
        SetTokenInformation(
            filtered.0,
            TokenDefaultDacl,
            (&raw const dacl).cast(),
            std::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
    })
    .map_err(|error| pty_error("set regular shell default access list", error))?;

    if !is_regular_token(&filtered, kept)? {
        return Err(other(
            "Windows did not produce a token without administrator rights for a regular shell",
        ));
    }
    Ok(filtered)
}

/// An inherited or filtered regular token must satisfy the same checks.
fn is_regular_token(token: &Handle, kept: &[LUID]) -> io::Result<bool> {
    if !Standing::of(token)?.is_regular() {
        return Ok(false);
    }
    let kind = token_info(token, TokenType)?;
    // SAFETY: the buffer holds the TOKEN_TYPE just read.
    let primary = unsafe { *kind.as_ptr().cast::<TOKEN_TYPE>() } == TokenPrimary;
    let held = token_info(token, TokenPrivileges)?;
    // SAFETY: `held` holds the TOKEN_PRIVILEGES just read.
    let held = unsafe { privilege_entries(&held) }?;
    let user = token_info(token, TokenUser)?;
    let system = Sid::well_known(WinLocalSystemSid)?;
    // SAFETY: both SIDs are valid for these buffers' lifetimes.
    let is_system = unsafe {
        EqualSid(
            (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid,
            system.as_psid(),
        )
    } != 0;
    Ok(primary
        && !is_system
        && held
            .iter()
            .all(|privilege| kept.iter().any(|keep| same_luid(keep, &privilege.Luid))))
}

/// This process's primary token.
fn process_token(access: TOKEN_ACCESS_MASK) -> io::Result<Handle> {
    // SAFETY: GetCurrentProcess returns the current process pseudo-handle.
    token_for_process(unsafe { GetCurrentProcess() }, access)
}

fn token_for_process(process: HANDLE, access: TOKEN_ACCESS_MASK) -> io::Result<Handle> {
    let mut token = null_mut();
    // SAFETY: callers supply a live process handle; token is a valid out pointer.
    check(unsafe { OpenProcessToken(process, access, &mut token) })?;
    Ok(Handle(token))
}

pub(in crate::private) fn require_regular_process() -> io::Result<()> {
    if is_regular_token(&process_token(TOKEN_QUERY)?, &regular_privileges()?)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SSH worker requires a regular token",
        ))
    }
}

/// Resolve the account carried by the same token the regular shell uses.
pub(in crate::private) fn regular_account() -> io::Result<String> {
    let identity = Identity::select(false)?;
    let own = process_token(TOKEN_QUERY)?;
    let token = match &identity {
        Identity::Inherited => &own,
        Identity::Filtered(token) => token,
    };
    let user = token_info(token, TokenUser)?;
    let mut name = [0u16; 257];
    let mut domain = [0u16; 257];
    let (mut name_size, mut domain_size) = (name.len() as u32, domain.len() as u32);
    let mut sid_type = 0;
    // SAFETY: the SID points into the token information. Both output buffers
    // and their lengths are valid.
    check(unsafe {
        LookupAccountSidW(
            null(),
            (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid,
            name.as_mut_ptr(),
            &mut name_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut sid_type,
        )
    })?;
    if sid_type != SidTypeUser {
        return Err(other("the SSH token does not identify a Windows user"));
    }
    String::from_utf16(&name[..name_size as usize]).map_err(other)
}

pub(in crate::private) struct WorkerStream {
    read: tokio::fs::File,
    write: Option<Handle>,
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl AsyncRead for WorkerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.read).poll_read(cx, buf) {
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe => {
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl AsyncWrite for WorkerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = self.get_mut();
        let Some(pipe) = stream.write.as_ref() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        poll_pipe_write(pipe, &mut stream.retry, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write.take();
        Poll::Ready(Ok(()))
    }
}

pub(in crate::private) struct WorkerProcess(Handle);

impl WorkerProcess {
    fn exited(&self) -> bool {
        // SAFETY: the process handle remains open.
        unsafe { WaitForSingleObject(self.0.0, 0) == WAIT_OBJECT_0 }
    }

    pub(in crate::private) fn terminate(&self) {
        if !self.exited() {
            // SAFETY: the process handle is open and grants termination.
            unsafe { TerminateProcess(self.0.0, 1) };
        }
    }

    pub(in crate::private) async fn wait(&self) {
        while !self.exited() {
            tokio::time::sleep(REAP_POLL).await;
        }
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// Start the SSH worker with only its private pipe ends. The process is
/// suspended until its actual token has been verified against the caller.
pub(in crate::private) fn start_ssh_worker(
    exe: &Path,
    argument: &str,
    bootstrap: &[u8; 64],
) -> io::Result<(WorkerStream, WorkerProcess)> {
    let identity = Identity::select(false)?;
    let (stdin, write) = input_pipe()?;
    let (read, stdout) = pipe()?;
    let handles = [stdin.0, stdout.0];
    for handle in handles {
        // SAFETY: the handles are live, and only the child ends are inheritable.
        check(unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) })?;
    }
    let mut attributes = Attributes::new()?;
    // SAFETY: the initialized list and handle array both outlive process startup.
    check(unsafe {
        UpdateProcThreadAttribute(
            attributes.list(),
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr().cast(),
            std::mem::size_of_val(&handles),
            null_mut(),
            null(),
        )
    })?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin.0;
    startup.StartupInfo.hStdOutput = stdout.0;
    startup.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
    startup.lpAttributeList = attributes.list();
    let application = wide(exe.as_os_str());
    let mut line = quote(exe.as_os_str())?;
    line.pop();
    line.push(u16::from(b' '));
    line.extend(argument.encode_utf16());
    line.push(0);
    let environment = environment(false);
    let environment = environment.as_ptr().cast::<c_void>();
    let directory = exe.parent().map(|dir| wide(dir.as_os_str()));
    let directory = directory.as_ref().map_or(null(), |dir| dir.as_ptr());
    let flags = EXTENDED_STARTUPINFO_PRESENT
        | CREATE_UNICODE_ENVIRONMENT
        | CREATE_NO_WINDOW
        | CREATE_SUSPENDED;
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: all buffers and attributes remain live until startup returns.
    // The child inherits only the two pipe ends listed in the attribute.
    check(unsafe {
        match identity {
            Identity::Inherited => CreateProcessW(
                application.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                1,
                flags,
                environment,
                directory,
                &startup.StartupInfo,
                &mut process,
            ),
            Identity::Filtered(token) => CreateProcessAsUserW(
                token.0,
                application.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                1,
                flags,
                environment,
                directory,
                &startup.StartupInfo,
                &mut process,
            ),
        }
    })?;
    let worker = WorkerProcess(Handle(process.hProcess));
    let thread = Handle(process.hThread);
    drop((stdin, stdout));
    let child = token_for_process(worker.0.0, TOKEN_QUERY)?;
    let caller = process_token(TOKEN_QUERY)?;
    let child_user = token_info(&child, TokenUser)?;
    let caller_user = token_info(&caller, TokenUser)?;
    // SAFETY: both SIDs point into these live token buffers.
    let same_user = unsafe {
        EqualSid(
            (*child_user.as_ptr().cast::<TOKEN_USER>()).User.Sid,
            (*caller_user.as_ptr().cast::<TOKEN_USER>()).User.Sid,
        ) != 0
    };
    if !same_user || !is_regular_token(&child, &regular_privileges()?)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected SSH worker token",
        ));
    }
    let mut count = 0;
    // SAFETY: the pipe is open and nonblocking. The worker is suspended, so
    // this writes the only data into the empty startup pipe.
    check(unsafe {
        WriteFile(
            write.0,
            bootstrap.as_ptr(),
            bootstrap.len() as u32,
            &mut count,
            null_mut(),
        )
    })?;
    if count != bootstrap.len() as u32 {
        return Err(io::ErrorKind::WriteZero.into());
    }
    // SAFETY: the thread handle belongs to the worker created suspended.
    if unsafe { ResumeThread(thread.0) } != 1 {
        return Err(other("could not resume the SSH worker"));
    }
    let mut read = tokio::fs::File::from_std(read.into());
    read.set_max_buf_size(16 * 1024);
    Ok((
        WorkerStream {
            read,
            write: Some(write),
            retry: None,
        },
        worker,
    ))
}

/// Claim the worker pipes before the worker launches any subprocesses.
pub(in crate::private) fn ssh_worker_stdio() -> io::Result<(std::fs::File, std::fs::File)> {
    // SAFETY: reading standard handles does not transfer ownership.
    let (read, write) = unsafe {
        (
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
        )
    };
    if read == write {
        return Err(other("SSH worker requires separate input and output pipes"));
    }
    for pipe in [read, write] {
        // SAFETY: GetFileType also handles missing and invalid handles.
        if unsafe { GetFileType(pipe) } != FILE_TYPE_PIPE {
            return Err(other("SSH worker requires private input and output pipes"));
        }
        // SAFETY: the handle is a live pipe.
        check(unsafe { SetHandleInformation(pipe, HANDLE_FLAG_INHERIT, 0) })?;
    }
    Ok((Handle(read).into(), Handle(write).into()))
}

/// One class of a token's information. `u64` elements keep the structure in
/// it aligned.
fn token_info(token: &Handle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut bytes = 0u32;
    // SAFETY: a size query; nothing is written but `bytes`.
    unsafe { GetTokenInformation(token.0, class, null_mut(), 0, &mut bytes) };
    if bytes == 0 {
        return Err(pty_error(
            &format!("size of token information class {class}"),
            io::Error::last_os_error(),
        ));
    }
    let mut buf = vec![0u64; (bytes as usize).div_ceil(8)];
    // The allocation is rounded up for alignment. Win32 requires the
    // exact requested length for fixed-size information classes.
    // SAFETY: `buf` is writable for at least `bytes` bytes.
    check(unsafe {
        GetTokenInformation(token.0, class, buf.as_mut_ptr().cast(), bytes, &mut bytes)
    })
    .map_err(|error| pty_error(&format!("read token information class {class}"), error))?;
    Ok(buf)
}

/// The groups of a `TOKEN_GROUPS`.
///
/// # Safety
/// `buf` is a `TokenGroups` result of [`token_info`].
unsafe fn group_entries(buf: &[u64]) -> io::Result<&[SID_AND_ATTRIBUTES]> {
    let list = buf.as_ptr().cast::<TOKEN_GROUPS>();
    // SAFETY: Windows wrote the structure, its count and that many entries.
    unsafe { entries(buf, (*list).GroupCount, (&raw const (*list).Groups).cast()) }
}

/// The privileges of a `TOKEN_PRIVILEGES`.
///
/// # Safety
/// `buf` is a `TokenPrivileges` result of [`token_info`].
unsafe fn privilege_entries(buf: &[u64]) -> io::Result<&[LUID_AND_ATTRIBUTES]> {
    let list = buf.as_ptr().cast::<TOKEN_PRIVILEGES>();
    // SAFETY: Windows wrote the structure, its count and that many entries.
    unsafe {
        entries(
            buf,
            (*list).PrivilegeCount,
            (&raw const (*list).Privileges).cast(),
        )
    }
}

/// The `count` entries starting at `first` of a counted list that Windows
/// wrote to `buf`, refused if they would not fit in it.
///
/// # Safety
/// `first` points into `buf`, where Windows wrote that many entries.
unsafe fn entries<T>(buf: &[u64], count: u32, first: *const T) -> io::Result<&[T]> {
    let offset = (first as usize).wrapping_sub(buf.as_ptr() as usize);
    let end = (count as usize)
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| bytes.checked_add(offset));
    if end.is_none_or(|end| end > std::mem::size_of_val(buf)) {
        return Err(other("a token list is larger than its buffer"));
    }
    // SAFETY: the entries lie inside `buf` (checked above), which the
    // returned slice borrows.
    Ok(unsafe { std::slice::from_raw_parts(first, count as usize) })
}

/// A token's integrity level: the last subauthority of its mandatory label.
fn integrity(token: &Handle) -> io::Result<u32> {
    let label = token_info(token, TokenIntegrityLevel)?;
    // SAFETY: the buffer holds the TOKEN_MANDATORY_LABEL just read, whose
    // SID points into it; a subauthority below the count is in the SID.
    unsafe {
        let sid = (*label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        match *GetSidSubAuthorityCount(sid) {
            0 => Err(other("the token's integrity label is empty")),
            count => Ok(*GetSidSubAuthority(sid, u32::from(count) - 1)),
        }
    }
}

/// The identifiers of [`REGULAR_PRIVILEGES`] on this machine.
fn regular_privileges() -> io::Result<Vec<LUID>> {
    REGULAR_PRIVILEGES
        .iter()
        .map(|&name| {
            let mut luid = LUID::default();
            // SAFETY: `name` is a NUL-terminated constant; `luid` is a valid
            // out pointer. A null system name is this machine.
            check(unsafe { LookupPrivilegeValueW(null(), name, &mut luid) })?;
            Ok(luid)
        })
        .collect()
}

fn same_luid(a: &LUID, b: &LUID) -> bool {
    a.LowPart == b.LowPart && a.HighPart == b.HighPart
}

/// A well-known SID. `SECURITY_MAX_SID_SIZE` is 68 bytes; `u32` elements
/// keep it aligned.
struct Sid([u32; 17]);

impl Sid {
    fn well_known(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Self> {
        let mut sid = Self([0; 17]);
        let mut bytes = std::mem::size_of_val(&sid.0) as u32;
        // SAFETY: the buffer is writable for `bytes` bytes; these SIDs have
        // no domain part.
        check(unsafe {
            CreateWellKnownSid(kind, null_mut(), sid.0.as_mut_ptr().cast(), &mut bytes)
        })?;
        Ok(sid)
    }

    /// For calls that only read the SID.
    fn as_psid(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }
}

/// An access list that allows each SID its mask. `u32` elements keep it
/// aligned.
fn acl(grants: &[(PSID, u32)]) -> io::Result<Vec<u32>> {
    // Each entry ends with its SID, whose first four bytes the entry
    // structure already counts.
    let fixed = std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>();
    let bytes = grants
        .iter()
        .fold(std::mem::size_of::<ACL>(), |bytes, (sid, _)| {
            // SAFETY: every SID given is valid.
            bytes + fixed + unsafe { GetLengthSid(*sid) } as usize
        });
    let mut acl = vec![0u32; bytes.div_ceil(4)];
    let list = acl.as_mut_ptr().cast::<ACL>();
    // SAFETY: the buffer is writable for the length given.
    check(unsafe {
        InitializeAcl(
            list,
            std::mem::size_of_val(acl.as_slice()) as u32,
            ACL_REVISION,
        )
    })?;
    for &(sid, mask) in grants {
        // SAFETY: the list was initialized with room for every entry.
        check(unsafe { AddAccessAllowedAce(list, ACL_REVISION, mask, sid) })?;
    }
    Ok(acl)
}

/// A process thread attribute list with room for one attribute.
struct Attributes(Vec<usize>);

impl Attributes {
    fn new() -> io::Result<Self> {
        let mut bytes = 0usize;
        // SAFETY: a size query; it fails with ERROR_INSUFFICIENT_BUFFER and
        // sets `bytes`.
        unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes) };
        // `usize` elements keep the list pointer-aligned.
        let mut buf = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: `buf` holds at least `bytes` bytes.
        check(unsafe {
            InitializeProcThreadAttributeList(buf.as_mut_ptr().cast(), 1, 0, &mut bytes)
        })?;
        Ok(Self(buf))
    }

    fn list(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.0.as_mut_ptr().cast()
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: the list was initialized in `new`.
        unsafe { DeleteProcThreadAttributeList(self.list()) };
    }
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// The shell's command line: the program alone, quoted. A Windows path
/// cannot contain a double quote, so no escaping is needed.
fn quote(program: &OsStr) -> io::Result<Vec<u16>> {
    let name: Vec<u16> = program.encode_wide().collect();
    if name.is_empty() || name.iter().any(|&c| c == 0 || c == u16::from(b'"')) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid shell path",
        ));
    }
    let quote = u16::from(b'"');
    let mut line = Vec::with_capacity(name.len() + 3);
    line.push(quote);
    line.extend(name);
    line.extend([quote, 0]);
    Ok(line)
}

/// This process's environment with `TERM=xterm-256color` and the serving
/// runtime's process ID, as a sorted UTF-16 block.
fn environment(preserve_host: bool) -> Vec<u16> {
    let host = crate::private::HOST_ENV;
    let mut vars: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("TERM") && !k.eq_ignore_ascii_case(host))
        .collect();
    vars.push(("TERM".into(), "xterm-256color".into()));
    let pid = if preserve_host {
        std::env::var_os(host)
    } else {
        None
    };
    vars.push((
        host.into(),
        pid.unwrap_or_else(|| std::process::id().to_string().into()),
    ));
    vars.sort_by_cached_key(|(k, _)| k.to_string_lossy().to_uppercase());
    let mut block = Vec::new();
    for (k, v) in vars {
        block.extend(k.encode_wide());
        block.push(u16::from(b'='));
        block.extend(v.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

fn check(ok: windows_sys::core::BOOL) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn size(cols: u16, rows: u16) -> COORD {
    let dim = |n: u16| i16::try_from(n.max(1)).unwrap_or(i16::MAX);
    COORD {
        X: dim(cols),
        Y: dim(rows),
    }
}

impl Pty {
    pub fn reader(&self) -> PtyReader<'_> {
        PtyReader(&self.output)
    }

    pub fn writer(&self) -> PtyWriter<'_> {
        PtyWriter {
            pipe: &self.input,
            retry: None,
        }
    }

    /// The shell's exit code, once (take before serving).
    pub fn take_exit(&mut self) -> oneshot::Receiver<io::Result<i32>> {
        self.exited.take().expect("exit taken once")
    }

    /// Waits for the reaper after this `Pty` is dropped.
    pub fn teardown(&mut self) -> Teardown {
        Teardown(self.reaper.take())
    }
}

/// Waits until a dropped PTY's shell is killed and reaped, its
/// pseudoconsole closed and its output reader finished.
pub struct Teardown(Option<JoinHandle<()>>);

impl Teardown {
    pub async fn wait(self) {
        if let Some(reaper) = self.0 {
            let _ = tokio::task::spawn_blocking(move || reaper.join()).await;
        }
    }
}

/// Shell output. End of output (the pseudoconsole closed) reads as EOF.
pub struct PtyReader<'a>(&'a std::sync::Mutex<Output>);

/// Shell input: each poll is at most one nonblocking `WriteFile`.
pub struct PtyWriter<'a> {
    pipe: &'a Handle,
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl AsyncRead for PtyReader<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut guard = self.0.lock().map_err(|_| other("PTY output lock"))?;
        let out = &mut *guard;
        if out.at == out.pending.len() {
            match ready!(out.chunks.poll_recv(cx)) {
                Some(chunk) => {
                    out.pending = chunk;
                    out.at = 0;
                }
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = (out.pending.len() - out.at).min(buf.remaining());
        buf.put_slice(&out.pending[out.at..out.at + n]);
        out.at += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PtyWriter<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let writer = self.get_mut();
        poll_pipe_write(writer.pipe, &mut writer.retry, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// A pseudoconsole has no input half-close; nothing to do.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn poll_pipe_write(
    pipe: &Handle,
    retry: &mut Option<Pin<Box<tokio::time::Sleep>>>,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<io::Result<usize>> {
    if buf.is_empty() {
        return Poll::Ready(Ok(0));
    }
    let len = buf.len().min(MAX_WRITE) as u32;
    let mut written = 0u32;
    // SAFETY: `pipe` is open and synchronous, `buf` is valid for `len`
    // bytes, and the pipe is in nonblocking mode.
    let ok = unsafe { WriteFile(pipe.0, buf.as_ptr(), len, &mut written, null_mut()) };
    if ok == 0 {
        return Poll::Ready(Err(io::Error::last_os_error()));
    }
    if written > 0 {
        return Poll::Ready(Ok(written as usize));
    }
    // The pipe is full. Each retry is a new poll that can re-check authority.
    let at = tokio::time::Instant::now() + WRITE_RETRY;
    let retry = retry.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
    retry.as_mut().reset(at);
    if retry.as_mut().poll(cx).is_ready() {
        cx.waker().wake_by_ref();
    }
    Poll::Pending
}
