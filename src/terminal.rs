use std::{
    io::{self, IsTerminal, Read, Write},
    path::Path,
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use portable_pty::{Child, CommandBuilder, PtySize, native_pty_system};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot},
};

use crate::wire::{self, LocalReply};

const DATA: u8 = 1;
const RESIZE: u8 = 2;
const EXIT: u8 = 3;
const CHUNK: usize = 8192;

fn dimensions(cols: u16, rows: u16) -> PtySize {
    #[cfg(windows)]
    let (cols, rows) = (cols.min(i16::MAX as u16), rows.min(i16::MAX as u16));
    PtySize {
        cols: cols.max(1),
        rows: rows.max(1),
        pixel_width: 0,
        pixel_height: 0,
    }
}

pub fn size() -> Result<(u16, u16)> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "shell requires an interactive terminal"
    );
    Ok(crossterm::terminal::size()?)
}

struct LocalTerminal {
    #[cfg(windows)]
    console: WindowsConsole,
}

impl LocalTerminal {
    fn enter() -> Result<Self> {
        #[cfg(windows)]
        let console = WindowsConsole::capture()?;
        crossterm::terminal::enable_raw_mode()?;
        let terminal = Self {
            #[cfg(windows)]
            console,
        };
        #[cfg(windows)]
        terminal.console.enable_vt()?;
        Ok(terminal)
    }
}

impl Drop for LocalTerminal {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

#[cfg(windows)]
struct WindowsConsole {
    input: windows_sys::Win32::Foundation::HANDLE,
    output: windows_sys::Win32::Foundation::HANDLE,
    input_mode: u32,
    output_mode: u32,
}

#[cfg(windows)]
impl WindowsConsole {
    fn capture() -> io::Result<Self> {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };
        let (mut input_mode, mut output_mode) = (0, 0);
        unsafe {
            let input = GetStdHandle(STD_INPUT_HANDLE);
            let output = GetStdHandle(STD_OUTPUT_HANDLE);
            if GetConsoleMode(input, &mut input_mode) == 0
                || GetConsoleMode(output, &mut output_mode) == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                input,
                output,
                input_mode,
                output_mode,
            })
        }
    }

    fn enable_vt(&self) -> io::Result<()> {
        use windows_sys::Win32::System::Console::{
            ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode,
            SetConsoleMode,
        };
        let mut raw = 0;
        unsafe {
            if GetConsoleMode(self.input, &mut raw) == 0
                || SetConsoleMode(self.input, raw | ENABLE_VIRTUAL_TERMINAL_INPUT) == 0
                || SetConsoleMode(
                    self.output,
                    self.output_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
                ) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsConsole {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::SetConsoleMode;
        unsafe {
            SetConsoleMode(self.input, self.input_mode);
            SetConsoleMode(self.output, self.output_mode);
        }
    }
}

pub async fn attach(
    mut rx: impl AsyncRead + Unpin,
    mut tx: impl AsyncWrite + Unpin,
    initial_size: (u16, u16),
) -> Result<i32> {
    let _terminal = LocalTerminal::enter()?;
    let (input_tx, mut input_rx) = mpsc::channel::<io::Result<Vec<u8>>>(8);
    thread::Builder::new()
        .name("massrelay-stdin".into())
        .spawn(move || {
            // This CLI process can exit even while the input thread is waiting for another keystroke.
            let mut stdin = io::stdin().lock();
            let mut buf = [0; CHUNK];
            loop {
                let data = match stdin.read(&mut buf[1..]) {
                    Ok(0) => break,
                    Ok(size) => {
                        buf[0] = DATA;
                        Ok(buf[..size + 1].to_vec())
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        let _ = input_tx.blocking_send(Err(error));
                        break;
                    }
                };
                if input_tx.blocking_send(data).is_err() {
                    break;
                }
            }
        })?;

    let receive = async {
        let mut stdout = tokio::io::stdout();
        #[cfg(windows)]
        let mut pending = Vec::new();
        loop {
            let data = wire::read_frame(&mut rx, CHUNK)
                .await
                .context("remote shell disconnected")?;
            match data.split_first() {
                Some((&DATA, bytes)) => {
                    #[cfg(not(windows))]
                    stdout.write_all(bytes).await?;
                    #[cfg(windows)]
                    {
                        // Rust's Windows console writer expects complete UTF-8 characters.
                        pending.extend_from_slice(bytes);
                        let end = complete_utf8_prefix(&pending);
                        stdout
                            .write_all(String::from_utf8_lossy(&pending[..end]).as_bytes())
                            .await?;
                        pending.drain(..end);
                    }
                    stdout.flush().await?;
                }
                Some((&EXIT, bytes)) => {
                    #[cfg(windows)]
                    if !pending.is_empty() {
                        stdout.write_all("�".as_bytes()).await?;
                        stdout.flush().await?;
                    }
                    let bytes: [u8; 4] = bytes.try_into().context("invalid shell exit status")?;
                    return Ok(i32::from_be_bytes(bytes));
                }
                _ => bail!("invalid shell output frame"),
            }
        }
    };

    let send = async {
        let mut size = initial_size;
        let mut interval = tokio::time::interval(Duration::from_millis(150));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                data = input_rx.recv() => {
                    let Some(data) = data else { bail!("local terminal input closed") };
                    wire::frame(&mut tx, &data?).await?;
                }
                _ = interval.tick() => {
                    let next = crossterm::terminal::size()?;
                    if next != size {
                        size = next;
                        let [c0, c1] = size.0.to_be_bytes();
                        let [r0, r1] = size.1.to_be_bytes();
                        wire::frame(&mut tx, &[RESIZE, c0, c1, r0, r1]).await?;
                    }
                }
            }
        }
    };

    tokio::select! {
        result = receive => result,
        result = send => result,
    }
}

#[cfg(windows)]
fn complete_utf8_prefix(bytes: &[u8]) -> usize {
    let mut rest = bytes;
    while let Err(error) = std::str::from_utf8(rest) {
        let end = error.valid_up_to();
        match error.error_len() {
            Some(len) => rest = &rest[end + len..],
            None => return bytes.len() - rest.len() + end,
        }
    }
    bytes.len()
}

enum Input {
    Data(Vec<u8>),
    Resize(PtySize),
}

struct Process(Box<dyn Child + Send + Sync>);

impl Drop for Process {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

pub async fn serve(
    rx: &mut (impl AsyncRead + Unpin),
    tx: &mut (impl AsyncWrite + Unpin),
    cols: u16,
    rows: u16,
    shell: Option<&Path>,
) -> Result<()> {
    let pair = native_pty_system().openpty(dimensions(cols, rows))?;
    let master = pair.master;
    let mut reader = master.try_clone_reader()?;
    let mut writer = master.take_writer()?;
    let mut command = shell.map_or_else(CommandBuilder::new_default_prog, CommandBuilder::new);
    command.env("TERM", "xterm-256color");
    let mut process = Process(pair.slave.spawn_command(command)?);
    drop(pair.slave);
    let (input_tx, mut input_rx) = mpsc::channel::<Input>(8);
    let (output_tx, mut output_rx) = mpsc::channel(16);
    let (exit_tx, mut exit_rx) = oneshot::channel();
    let (_stop, stop) = std::sync::mpsc::channel::<()>();

    thread::Builder::new()
        .name("massrelay-pty-wait".into())
        .spawn(move || {
            loop {
                match process.0.try_wait() {
                    Ok(None) => {
                        if !matches!(
                            stop.recv_timeout(Duration::from_millis(30)),
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                        ) {
                            break;
                        }
                    }
                    Ok(Some(status)) => {
                        let _ = exit_tx.send(Ok(status));
                        break;
                    }
                    Err(error) => {
                        let _ = exit_tx.send(Err(error));
                        break;
                    }
                }
            }
        })?;
    thread::Builder::new()
        .name("massrelay-pty-write".into())
        .spawn(move || {
            while let Some(input) = input_rx.blocking_recv() {
                let result = match input {
                    Input::Data(bytes) => writer.write_all(&bytes).map_err(anyhow::Error::from),
                    Input::Resize(size) => master.resize(size),
                };
                if result.is_err() {
                    break;
                }
            }
        })?;
    thread::Builder::new()
        .name("massrelay-pty-read".into())
        .spawn(move || {
            let mut buf = [0; CHUNK];
            buf[0] = DATA;
            loop {
                match reader.read(&mut buf[1..]) {
                    Ok(0) => break,
                    Ok(size) => {
                        if output_tx.blocking_send(buf[..size + 1].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        })?;

    wire::send(tx, LocalReply::Shell).await?;
    let read_inputs = async {
        loop {
            let data = wire::read_frame(rx, CHUNK).await?;
            let input = match data.as_slice() {
                [RESIZE, c0, c1, r0, r1] => Input::Resize(dimensions(
                    u16::from_be_bytes([*c0, *c1]),
                    u16::from_be_bytes([*r0, *r1]),
                )),
                [DATA, bytes @ ..] => Input::Data(bytes.to_vec()),
                _ => bail!("invalid shell input frame"),
            };
            input_tx
                .send(input)
                .await
                .context("remote terminal input closed")?;
        }
    };

    let write_outputs = async {
        let status = loop {
            tokio::select! {
                result = &mut exit_rx => break result??,
                data = output_rx.recv() => match data {
                    Some(data) => wire::frame(tx, &data).await?,
                    None => break exit_rx.await??,
                },
            }
        };
        // ConPTY or a descendant may keep the output handle open after the shell exits.
        // Time out waiting for a chunk, never in the middle of writing a frame.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        while let Ok(Some(data)) = tokio::time::timeout_at(deadline, output_rx.recv()).await {
            wire::frame(tx, &data).await?;
        }
        Ok::<_, anyhow::Error>(status)
    };

    let status = tokio::select! {
        result = write_outputs => result?,
        result = read_inputs => return result,
    };
    let code = i32::try_from(status.exit_code()).unwrap_or(1);
    let [a, b, c, d] = code.to_be_bytes();
    wire::frame(tx, &[EXIT, a, b, c, d]).await
}
