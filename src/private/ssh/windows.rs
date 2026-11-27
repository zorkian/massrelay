use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use russh::ChannelReadHalf;
use russh::keys::{HashAlg, PrivateKey};
use tempfile::NamedTempFile;
use tokio::io::{self as aio, AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
use zeroize::Zeroizing;

use crate::mailbox::Bytes;
use crate::private::pty::windows::{
    Pty, WorkerProcess, WorkerStream, regular_account, require_regular_process, ssh_worker_stdio,
    start_ssh_worker,
};

use super::Host;

mod protocol;

use protocol::{Dimensions, Output, Process, Program};

const HOST_FILE: &str = "ssh-host-ed25519-win32";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const READY: u8 = 1;

pub(crate) const WORKER_ARG: &str = "--massrelay-ssh-worker";

fn ssh_account() -> Result<String> {
    // Authentication binds the peer's key to the worker. Windows selects
    // the actual account from the worker's verified token.
    regular_account()?;
    Ok("massrelay".to_owned())
}

fn load_seed(path: &Path) -> io::Result<Zeroizing<[u8; 32]>> {
    let mut file = File::open(path)?;
    let mut seed = Zeroizing::new([0; 32]);
    file.read_exact(seed.as_mut())?;
    if file.read(&mut [0])? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SSH host key",
        ));
    }
    Ok(seed)
}

fn host_seed(dir: &Path, rotate: bool) -> Result<Zeroizing<[u8; 32]>> {
    crate::windows_service::ssh_private_dir(dir)?;
    let path = dir.join(HOST_FILE);
    if !rotate {
        match load_seed(&path) {
            Ok(seed) => return Ok(seed),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("read SSH host key"),
        }
    }
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| anyhow::anyhow!("generate SSH host key"))?;
    let mut staged = NamedTempFile::new_in(dir)?;
    staged.write_all(seed.as_ref())?;
    staged.as_file().sync_all()?;
    if rotate {
        staged.persist(&path)?;
    } else if let Err(error) = staged.persist_noclobber(&path) {
        if error.error.kind() == io::ErrorKind::AlreadyExists {
            return load_seed(&path).context("read concurrent SSH host key");
        }
        return Err(error.error).context("publish SSH host key");
    }
    Ok(seed)
}

fn host_key(dir: &Path, rotate: bool) -> Result<PrivateKey> {
    let seed = host_seed(dir, rotate)?;
    protocol::private_key(&seed)
}

pub(in crate::private) async fn host_info(dir: &Path) -> Result<Host> {
    let dir = dir.to_owned();
    tokio::task::spawn_blocking(move || {
        let user = ssh_account()?;
        cmd_path()?;
        let key = Bytes(protocol::public_key(&host_key(&dir, false)?));
        Ok(Host { user, key })
    })
    .await?
}

pub(in crate::private) async fn rotate_host_key(dir: &Path) -> Result<String> {
    let dir = dir.to_owned();
    tokio::task::spawn_blocking(move || {
        ssh_account()?;
        Ok(host_key(&dir, true)?
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string())
    })
    .await?
}

#[cfg(test)]
pub(in crate::private) fn worker_executable() -> Result<PathBuf> {
    std::env::current_exe()?
        .ancestors()
        .skip(1)
        .map(|dir| dir.join("massrelay.exe"))
        .find(|path| path.is_file())
        .context("build massrelay.exe before testing its SSH worker")?
        .canonicalize()
        .context("resolve the built SSH worker")
}

pub(in crate::private) struct Prepared {
    exe: PathBuf,
    bootstrap: Zeroizing<[u8; 64]>,
}

impl Prepared {
    pub(in crate::private) async fn new(dir: &Path, client: &[u8; 32]) -> Result<Self> {
        let dir = dir.to_owned();
        let client = *client;
        tokio::task::spawn_blocking(move || {
            ssh_account()?;
            #[cfg(not(test))]
            let exe = std::env::current_exe()?;
            #[cfg(test)]
            let exe = worker_executable()?;
            let mut bootstrap = Zeroizing::new([0; 64]);
            bootstrap[..32].copy_from_slice(host_seed(&dir, false)?.as_ref());
            bootstrap[32..].copy_from_slice(&client);
            Ok(Self { exe, bootstrap })
        })
        .await?
    }

    pub(in crate::private) fn start(self, _dir: &Path) -> Result<(WorkerStream, Sshd)> {
        let (stream, worker) = start_ssh_worker(&self.exe, WORKER_ARG, &self.bootstrap)?;
        Ok((stream, Sshd(worker)))
    }
}

pub(in crate::private) async fn worker_ready(stream: &mut (impl AsyncRead + Unpin)) -> Result<()> {
    let ready = tokio::time::timeout(STARTUP_TIMEOUT, stream.read_u8())
        .await
        .context("SSH worker startup timed out")??;
    ensure!(ready == READY, "SSH worker did not become ready");
    Ok(())
}

pub(in crate::private) struct Sshd(WorkerProcess);

impl Sshd {
    pub(in crate::private) fn terminate(&self) {
        self.0.terminate();
    }

    /// The bridge has closed both directions before this wait. The worker
    /// normally cleans up its attached children on EOF.
    pub(in crate::private) async fn reap(self) {
        if tokio::time::timeout(SHUTDOWN_TIMEOUT, self.0.wait())
            .await
            .is_err()
        {
            self.terminate();
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, self.0.wait()).await;
        }
    }
}

/// Hidden entry point. The caller must dispatch before writing to stdio.
pub(crate) fn run_worker() -> Result<()> {
    require_regular_process()?;
    let (input, output) = ssh_worker_stdio()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(serve_worker(input, output));
    // Tokio File uses blocking I/O for the inherited synchronous pipe ends.
    // Never let an outstanding read or write keep the worker alive on exit.
    runtime.shutdown_timeout(Duration::from_millis(200));
    result
}

async fn serve_worker(input: File, output: File) -> Result<()> {
    let mut input = tokio::fs::File::from_std(input);
    let mut output = tokio::fs::File::from_std(output);
    input.set_max_buf_size(16 * 1024);
    output.set_max_buf_size(16 * 1024);
    let mut bootstrap = Zeroizing::new([0; 64]);
    tokio::time::timeout(STARTUP_TIMEOUT, input.read_exact(bootstrap.as_mut())).await??;
    let host = protocol::private_key(bootstrap[..32].try_into()?)?;
    let client = bootstrap[32..].try_into()?;
    drop(bootstrap);
    let user = ssh_account()?;
    cmd_path()?;
    output.write_u8(READY).await?;
    output.flush().await?;
    protocol::serve(aio::join(input, output), user, host, client, launch).await
}

fn system_executable(name: &str) -> io::Result<PathBuf> {
    let mut path = [0u16; 1024];
    // SAFETY: the buffer is writable for the supplied number of UTF-16 units.
    let len = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    if len >= path.len() {
        return Err(io::Error::other(
            "Windows system directory path is too long",
        ));
    }
    let exe = PathBuf::from(OsString::from_wide(&path[..len])).join(name);
    if exe.is_file() {
        Ok(exe)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "required Windows executable is missing",
        ))
    }
}

fn cmd_path() -> io::Result<PathBuf> {
    system_executable("cmd.exe")
}

fn shell_arguments(program: Program<'_>) -> io::Result<String> {
    match program {
        Program::Shell => Ok(" /d".into()),
        Program::Exec(command)
            if !command.contains('\0') && command.encode_utf16().count() <= 8000 =>
        {
            // cmd.exe /S removes only the outer pair of quotes. The command
            // inside is interpreted with the usual Windows cmd.exe syntax.
            Ok(format!(" /d /s /c \"{command}\""))
        }
        _ => Err(io::ErrorKind::InvalidInput.into()),
    }
}

fn launch(
    program: Program<'_>,
    terminal: Option<watch::Receiver<Dimensions>>,
) -> io::Result<Process> {
    if matches!(program, Program::Sftp) {
        let child = start_command(&system_executable(r"OpenSSH\sftp-server.exe")?, "")?;
        return Ok(Box::new(move |input, output| {
            Box::pin(serve_command(child, input, output))
        }));
    }
    let cmd = cmd_path()?;
    let args = shell_arguments(program)?;
    if let Some(terminal) = terminal {
        let pty = Pty::spawn_ssh(&cmd, &args, terminal)?;
        Ok(Box::new(move |input, output| {
            Box::pin(serve_pty(pty, input, output))
        }))
    } else {
        let child = start_command(&cmd, &args)?;
        Ok(Box::new(move |input, output| {
            Box::pin(serve_command(child, input, output))
        }))
    }
}

fn start_command(path: &Path, raw: &str) -> io::Result<Child> {
    let mut command = Command::new(path);
    if !raw.is_empty() {
        command.raw_arg(raw);
    }
    if let Some(home) = std::env::var_os("USERPROFILE").filter(|p| Path::new(p).is_dir()) {
        command.current_dir(home);
    }
    command
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
}

async fn serve_command(
    mut child: Child,
    mut input: ChannelReadHalf,
    output: Output,
) -> io::Result<u32> {
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let mut out = output.make_writer();
    let mut err = output.make_writer_ext(Some(1));
    let read = async {
        let _ = aio::copy(&mut input.make_reader(), &mut stdin).await;
        drop(stdin);
        while input.wait().await.is_some() {}
        std::future::pending::<io::Result<u32>>().await
    };
    let write = async {
        let (status, _, _) = tokio::try_join!(
            child.wait(),
            aio::copy(&mut stdout, &mut out),
            aio::copy(&mut stderr, &mut err),
        )?;
        Ok(status.code().unwrap_or(1) as u32)
    };
    tokio::select! { result = read => result, result = write => result }
}

async fn serve_pty(mut pty: Pty, mut input: ChannelReadHalf, output: Output) -> io::Result<u32> {
    let exit = pty.take_exit();
    let mut stdin = pty.writer();
    let mut stdout = pty.reader();
    let mut out = output.make_writer();
    let read = async {
        let _ = aio::copy(&mut input.make_reader(), &mut stdin).await;
        while input.wait().await.is_some() {}
        std::future::pending::<io::Result<u32>>().await
    };
    let write = async {
        aio::copy(&mut stdout, &mut out).await?;
        let code = exit.await.map_err(io::Error::other)??;
        Ok(code as u32)
    };
    tokio::select! { result = read => result, result = write => result }
}
