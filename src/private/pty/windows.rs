//! Windows backend: ConPTY, driven directly through `windows-sys`.
//!
//! `portable_pty` hides the ConPTY input pipe behind a blocking writer, so
//! this backend creates the pipes and the pseudoconsole itself. The input
//! pipe's write end is put in nonblocking mode (`PIPE_NOWAIT`), which makes
//! every input write one `WriteFile` that returns at once: it writes what
//! fits (possibly nothing) and never waits for the console host to read.
//! See the parent module for the boundary this gives.

use super::*;
use std::ffi::{OsStr, OsString, c_void};
use std::os::windows::ffi::OsStrExt;
use std::pin::Pin;
use std::ptr::{null, null_mut};
use std::sync::mpsc::RecvTimeoutError;
use std::task::{Context, Poll, ready};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON};
use windows_sys::Win32::System::Pipes::{CreatePipe, PIPE_NOWAIT, SetNamedPipeHandleState};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
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

/// Spawn `shell` (or `%ComSpec%`, else `cmd.exe`) on a new pseudoconsole.
/// `token` is held by the reaper until the shell is reaped and the
/// pseudoconsole closed, and by the output reader until the output ends.
pub fn spawn(cols: u16, rows: u16, shell: Option<&Path>, token: Arc<()>) -> io::Result<Pty> {
    let (input_read, input) = input_pipe()?;
    let (output, output_write) = pipe()?;
    // Start the reaper before creating ConPTY. A thread creation failure
    // leaves no shell or console to shut down with a live output receiver.
    let (start_reaper, ready) = std::sync::mpsc::channel();
    let reaper = std::thread::Builder::new()
        .name("massrelay-private-pty-wait".into())
        .spawn(move || {
            if let Ok((shell, console, reader, exit, stop, token)) = ready.recv() {
                reap(shell, console, reader, exit, stop, token);
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
    let shell = Shell(start(con, shell)?);
    let (exit_tx, exited) = oneshot::channel();
    let (_stop, stop) = std::sync::mpsc::channel::<()>();
    if let Err(unsent) = start_reaper.send((shell, console, reader, exit_tx, stop, token)) {
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
) {
    let mut exit = Some(exit);
    loop {
        // SAFETY: the process handle is open.
        let status = unsafe { WaitForSingleObject(shell.0.0, 0) };
        let report = match status {
            WAIT_TIMEOUT => match stop.recv_timeout(REAP_POLL) {
                Err(RecvTimeoutError::Timeout) => continue,
                _ => break,
            },
            WAIT_OBJECT_0 => shell.exit_code(),
            _ => Err(io::Error::last_os_error()),
        };
        if let Some(exit) = exit.take() {
            let _ = exit.send(report);
        }
        // Nobody sends; this returns when the `Pty` is dropped.
        let _ = stop.recv();
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

/// Start the shell attached to `con`, returning its process handle.
fn start(con: HPCON, shell: Option<&Path>) -> io::Result<Handle> {
    let program: OsString = match shell {
        Some(path) => path.as_os_str().to_owned(),
        None => std::env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into()),
    };
    let mut command_line = quote(&program)?;
    let environment = environment();
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
    // SAFETY: every pointer is valid for the call: the command line is a
    // mutable NUL-terminated buffer, the environment a double-NUL-terminated
    // UTF-16 block, the directory NUL-terminated or null. No handle is
    // inherited.
    check(unsafe {
        CreateProcessW(
            null(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr() as *const c_void,
            directory.as_ref().map_or(null(), |d| d.as_ptr()),
            &info.StartupInfo,
            &mut process,
        )
    })?;
    drop(Handle(process.hThread));
    Ok(Handle(process.hProcess))
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

/// This process's environment with `TERM=xterm-256color`, as a sorted
/// UTF-16 block.
fn environment() -> Vec<u16> {
    let mut vars: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("TERM"))
        .collect();
    vars.push(("TERM".into(), "xterm-256color".into()));
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
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let len = buf.len().min(MAX_WRITE) as u32;
        let mut written = 0u32;
        // SAFETY: the handle is open while this writer borrows the `Pty`;
        // `buf` is valid for `len` bytes; the pipe is synchronous (no
        // OVERLAPPED) and in nonblocking mode, so this returns at once.
        let ok = unsafe { WriteFile(this.pipe.0, buf.as_ptr(), len, &mut written, null_mut()) };
        if ok == 0 {
            // ERROR_NO_DATA or ERROR_BROKEN_PIPE once the host has gone.
            return Poll::Ready(Err(io::Error::last_os_error()));
        }
        if written > 0 {
            return Poll::Ready(Ok(written as usize));
        }
        // The pipe is full. Poll again shortly; each retry is a new guarded
        // poll, so it re-checks authority first.
        let at = tokio::time::Instant::now() + WRITE_RETRY;
        let retry = this
            .retry
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
        retry.as_mut().reset(at);
        if retry.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// A pseudoconsole has no input half-close; nothing to do.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
