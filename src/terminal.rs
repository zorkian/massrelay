use std::{
    io::{self, IsTerminal, Read},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use crate::wire;

pub(crate) const DATA: u8 = 1;
pub(crate) const RESIZE: u8 = 2;
pub(crate) const EXIT: u8 = 3;
pub(crate) const CHUNK: usize = 8192;
/// The largest shell input frame a MassRelay client sends (data or resize).
pub const MAX_INPUT_FRAME: usize = CHUNK;
/// The largest output frame a shell server sends (output chunk or exit).
pub const MAX_OUTPUT_FRAME: usize = CHUNK;

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

pub async fn attach_max(
    mut rx: impl AsyncRead + Unpin,
    mut tx: impl AsyncWrite + Unpin,
    initial_size: (u16, u16),
    max_frame: usize,
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
            let data = wire::read_frame_max(&mut rx, max_frame)
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
