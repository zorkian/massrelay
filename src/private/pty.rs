//! EXPERIMENTAL native PTY for private shell sessions, with a nonblocking
//! input boundary.
//!
//! # Unix
//!
//! The PTY master is made nonblocking and driven by tokio's `AsyncFd`, so
//! there is no reader or writer thread. Every input write is one
//! nonblocking `write(2)`; a caller can poll it under the session registry
//! lock (`SessionHandle::guard`) without blocking under that lock. Input
//! bytes reach the PTY only from a poll that re-checked authority, and
//! nothing is queued in this process between the peer's stream and the PTY:
//! after a cutoff returns, no further input is handed over. Bytes already
//! written are in the kernel's PTY buffer and cannot be withdrawn.
//!
//! One reaper thread polls for the shell's exit. Dropping the `Pty` wakes it
//! at once (its stop channel disconnects); it then kills the shell (SIGHUP,
//! a grace of about 200 ms, then SIGKILL, as `portable_pty` does) and reaps
//! it. Dropping also closes the master, which hangs up the terminal and
//! signals its foreground process group. The reaper holds a caller-given
//! worker token until it has reaped the shell, so an owner can tell whether
//! any PTY worker survives.
//!
//! Limits: descendants that ignore SIGHUP, or that left the terminal's
//! session (`setsid`, daemonized jobs), are not killed and may keep the
//! slave open. A shell in uninterruptible sleep cannot be reaped until it
//! leaves it; its reaper (and token) then outlives the session.
//!
//! # Windows
//!
//! The shell runs on a ConPTY pseudoconsole (Windows 10 1809 or later),
//! created through `windows-sys` so this module owns its pipes. The input
//! pipe's write end is in nonblocking mode (`PIPE_NOWAIT`): every input
//! write is one `WriteFile` that writes what fits, possibly nothing, and
//! returns at once, so it too can be polled under the registry lock. A
//! write that found the pipe full is retried by a later poll (after about
//! 10 ms; such a pipe has no readiness signal), and each retry re-checks
//! authority. Nothing is queued in this process: bytes written are in the
//! pipe or the console host and cannot be withdrawn, as on Unix.
//!
//! Output is read by one thread (blocking `ReadFile`) into a small channel.
//! After the consumer is gone it keeps draining, so the console host never
//! blocks on a full pipe. The reaper polls for the shell's exit; dropping
//! the `Pty` wakes it, and it terminates the shell (`TerminateProcess`, no
//! grace period), waits for it, closes the pseudoconsole and waits for the
//! output reader. Both threads hold the worker token. The pseudoconsole
//! keeps the terminal dimensions chosen when the shell opens.
//!
//! Limits: closing the pseudoconsole signals its other attached processes
//! (`CTRL_CLOSE_EVENT`), but descendants that ignore it or detached from
//! the console are not killed. A shell that cannot be terminated, or a
//! console host that does not exit, keeps the reaper (and token) alive.
//!
//! # Other platforms
//!
//! `spawn` returns `ErrorKind::Unsupported`, so private shells are refused.

use std::io;
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
pub use unix::{Pty, Teardown, spawn};

#[cfg(windows)]
pub use windows::{Pty, Teardown, spawn};

#[cfg(all(test, windows))]
pub(crate) use windows::TestInput;

#[cfg(not(any(unix, windows)))]
pub use other::{Pty, Teardown, spawn};

#[cfg(windows)]
mod windows;

#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{BorrowedFd, OwnedFd};
    use std::pin::Pin;
    use std::task::{Context, Poll, ready};
    use std::time::Duration;

    use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::sync::oneshot;

    /// POSIX `EIO`, which a PTY master reads once every slave is closed
    /// (5 on Linux, macOS and the BSDs). Treated as end of output.
    const EIO: i32 = 5;

    type Io = AsyncFd<File>;

    pub struct Pty {
        io: Arc<Io>,
        /// Only for resize; locked for one ioctl.
        master: std::sync::Mutex<Box<dyn MasterPty + Send>>,
        exited: Option<oneshot::Receiver<io::Result<i32>>>,
        /// Dropping it wakes the reaper, which kills and reaps the shell.
        _stop: std::sync::mpsc::Sender<()>,
        reaper: Option<std::thread::JoinHandle<()>>,
    }

    /// Spawn `shell` (or the platform default) on a new PTY. `token` is held
    /// by the reaper until the shell is reaped.
    pub fn spawn(cols: u16, rows: u16, shell: Option<&Path>, token: Arc<()>) -> io::Result<Pty> {
        let pair = native_pty_system()
            .openpty(size(cols, rows))
            .map_err(other)?;
        let mut command = shell.map_or_else(CommandBuilder::new_default_prog, CommandBuilder::new);
        command.env("TERM", "xterm-256color");
        let mut child = pair.slave.spawn_command(command).map_err(other)?;
        drop(pair.slave);
        let (exit_tx, exited) = oneshot::channel();
        let (_stop, stop) = std::sync::mpsc::channel::<()>();
        // From here on, any early return drops `_stop` and the reaper kills
        // and reaps the shell.
        let reaper = std::thread::Builder::new()
            .name("massrelay-private-pty-wait".into())
            .spawn(move || {
                let _token = token;
                loop {
                    match child.try_wait() {
                        Ok(None) => {
                            if !matches!(
                                stop.recv_timeout(Duration::from_millis(30)),
                                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                            ) {
                                break;
                            }
                        }
                        Ok(Some(status)) => {
                            let code = i32::try_from(status.exit_code()).unwrap_or(1);
                            let _ = exit_tx.send(Ok(code));
                            return;
                        }
                        Err(e) => {
                            let _ = exit_tx.send(Err(e));
                            break;
                        }
                    }
                }
                if !matches!(child.try_wait(), Ok(Some(_))) {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            })?;
        let master = pair.master;
        let raw = master
            .as_raw_fd()
            .ok_or_else(|| other("no PTY master descriptor"))?;
        // SAFETY: `raw` is open and owned by `master`, which is alive for
        // this borrow; the clone is a separate descriptor we own.
        let fd = unsafe { BorrowedFd::borrow_raw(raw) }.try_clone_to_owned()?;
        set_nonblocking(&fd)?;
        // SAFETY: the `File` owns this descriptor; it stays open and refers
        // to the same file description until the `AsyncFd` (which owns the
        // `File`) is dropped, and `as_raw_fd` always returns it.
        let io = unsafe { AsyncFd::register(File::from(fd)) }.map_err(|e| other(&e))?;
        let io = Arc::new(io);
        Ok(Pty {
            io,
            master: std::sync::Mutex::new(master),
            exited: Some(exited),
            _stop,
            reaper: Some(reaper),
        })
    }

    /// Set O_NONBLOCK on the descriptor's open file description (shared by
    /// every descriptor of this master). std offers this only through its
    /// socket types; `UnixStream::set_nonblocking` (FIONBIO) works on any
    /// descriptor, including a PTY master.
    fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
        std::os::unix::net::UnixStream::from(fd.try_clone()?).set_nonblocking(true)
    }

    fn size(cols: u16, rows: u16) -> PtySize {
        PtySize {
            rows: rows.max(1),
            cols: cols.max(1),
            pixel_width: 0,
            pixel_height: 0,
        }
    }

    impl Pty {
        pub fn reader(&self) -> PtyReader {
            PtyReader(self.io.clone())
        }

        pub fn writer(&self) -> PtyWriter {
            PtyWriter(self.io.clone())
        }

        /// One nonblocking ioctl.
        pub fn resize(&self, cols: u16, rows: u16) -> io::Result<()> {
            self.master
                .lock()
                .map_err(|_| other("PTY master lock"))?
                .resize(size(cols, rows))
                .map_err(other)
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

    /// Waits until a dropped PTY's shell is killed and reaped.
    pub struct Teardown(Option<std::thread::JoinHandle<()>>);

    impl Teardown {
        pub async fn wait(self) {
            if let Some(reaper) = self.0 {
                let _ = tokio::task::spawn_blocking(move || reaper.join()).await;
            }
        }
    }

    /// Shell output. End of output (all slaves closed) reads as EOF.
    pub struct PtyReader(Arc<Io>);

    /// Shell input: each poll is one nonblocking write.
    pub struct PtyWriter(Arc<Io>);

    impl AsyncRead for PtyReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                let mut guard = ready!(self.0.poll_read_ready(cx))?;
                let unfilled = buf.initialize_unfilled();
                match guard.try_io(|inner| inner.get_ref().read(unfilled)) {
                    Ok(Ok(n)) => {
                        buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Err(e)) if e.raw_os_error() == Some(EIO) => return Poll::Ready(Ok(())),
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    Err(_would_block) => continue,
                }
            }
        }
    }

    impl AsyncWrite for PtyWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            loop {
                let mut guard = ready!(self.0.poll_write_ready(cx))?;
                match guard.try_io(|inner| inner.get_ref().write(buf)) {
                    Ok(r) => return Poll::Ready(r),
                    Err(_would_block) => continue,
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        /// A PTY has no input half-close; nothing to do.
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod other {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::sync::oneshot;

    /// Uninhabited: `spawn` never returns one on this platform.
    pub enum Pty {}
    pub enum PtyReader {}
    pub enum PtyWriter {}
    pub struct Teardown;

    pub fn spawn(_: u16, _: u16, _: Option<&Path>, _: Arc<()>) -> io::Result<Pty> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private shells need a nonblocking PTY (Unix or Windows)",
        ))
    }

    impl Pty {
        pub fn reader(&self) -> PtyReader {
            match *self {}
        }
        pub fn writer(&self) -> PtyWriter {
            match *self {}
        }
        pub fn resize(&self, _: u16, _: u16) -> io::Result<()> {
            match *self {}
        }
        pub fn take_exit(&mut self) -> oneshot::Receiver<io::Result<i32>> {
            match *self {}
        }
        pub fn teardown(&mut self) -> Teardown {
            match *self {}
        }
    }

    impl Teardown {
        pub async fn wait(self) {}
    }

    impl AsyncRead for PtyReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match *self {}
        }
    }

    impl AsyncWrite for PtyWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            match *self {}
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            match *self {}
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            match *self {}
        }
    }
}
