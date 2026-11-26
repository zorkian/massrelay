//! Human-readable runtime diagnostics in the operating system's own log.
//!
//! `massrelay run` writes its diagnostics to the host's native log, whether
//! it runs in a terminal or under a service manager, and `massrelay logs`
//! reads them back for the selected profile:
//!
//! | Host    | Destination                              | Reader                |
//! |---------|------------------------------------------|-----------------------|
//! | Linux   | the systemd journal (native socket)      | `journalctl`          |
//! | macOS   | Unified Logging (`os_log`)               | `/usr/bin/log`        |
//! | Windows | the Application event log (`ReportEvent`)| `wevtutil`            |
//!
//! The host owns storage, retention and rotation. MassRelay writes no
//! diagnostics file of its own. The connection audit (`super::audit`,
//! `connections.jsonl` or `--log-file`) is a separate record with its own
//! contract and is not touched here.
//!
//! # Profiles
//!
//! Every entry carries a profile identifier: the first sixteen hex digits of
//! the SHA-256 of the canonical state directory. It names no user, device or
//! network, depends only on the path, and is the same for the service and for
//! the command that reads its log. It is the journal field
//! `MASSRELAY_PROFILE`, the Unified Logging category under the subsystem
//! `com.massrelay.client`, and the second string of each Windows event from
//! the source `MassRelay`.
//!
//! # What is never logged
//!
//! These logs can be read by other accounts on the machine. Callers pass
//! fixed text and, at most, a local error cause. They never pass an access
//! or invite credential, payload, peer identity, alias, endpoint identifier,
//! roster or grant. As a second line of defence every entry is scrubbed
//! before it leaves the process: control characters become spaces (one entry
//! is always one line and cannot add fields), any run of 32 or more
//! key-alphabet characters (hex, base64url) and any printed byte array is
//! replaced by `[redacted]`, and the entry is cut to a fixed length.
//!
//! # The console
//!
//! Prompts and command results stay plain text on the terminal. `event` also
//! prints its message on standard error, as these messages were before,
//! unless standard error is itself the journal (a systemd unit), where that
//! would record the entry twice. `quiet` writes only to the native log, for
//! events the console already words itself. When the native log cannot be
//! reached, one notice says so and diagnostics continue on standard error.
//! Before `start` (every command but `run`), `event` only prints.

use std::fmt::Display;
use std::io::{self, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

use super::codec::hex;

/// How many recent entries `massrelay logs` shows.
const RECENT: usize = 200;
/// Longest entry written to the native log, in characters.
const MAX_ENTRY: usize = 1000;
/// A run of this many key-alphabet characters is treated as a secret.
const SECRET_RUN: usize = 32;
const REDACTED: &str = "[redacted]";
const NONE_YET: &str = "No diagnostics are recorded for this profile. They are written while \
                        'massrelay run' or the background service is running.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    Error,
}

struct Diagnostics {
    native: Option<native::Log>,
    /// Standard error is a destination of its own, not the native log.
    console: bool,
    write_failed: AtomicBool,
}

static ACTIVE: OnceLock<Diagnostics> = OnceLock::new();

/// The stable, nonsecret identifier of the profile in `state_dir`.
pub fn profile_id(state_dir: &Path) -> String {
    let path = state_dir
        .canonicalize()
        .or_else(|_| std::path::absolute(state_dir))
        .unwrap_or_else(|_| state_dir.to_path_buf());
    hex(&Sha256::digest(path.as_os_str().as_encoded_bytes())[..8])
}

/// Send this process's diagnostics for the profile in `state_dir` to the
/// native log. Called once, by `run`.
pub fn start(state_dir: &Path) {
    let native = match native::Log::open(&profile_id(state_dir)) {
        Ok(log) => Some(log),
        Err(error) => {
            eprintln!(
                "massrelay: {} is not available ({error}); diagnostics stay on standard error",
                native::FACILITY
            );
            None
        }
    };
    let _ = ACTIVE.set(Diagnostics {
        native,
        console: !native::stderr_is_log(),
        write_failed: AtomicBool::new(false),
    });
}

/// Whether standard error is a destination of its own. `false` only when it
/// is the native log itself, where console wording would be recorded as a
/// second, unscrubbed entry.
pub fn console() -> bool {
    ACTIVE.get().is_none_or(|active| active.console)
}

/// Record a diagnostic and print it on the console.
pub fn event(level: Level, message: impl Display) {
    let message = message.to_string();
    match ACTIVE.get() {
        Some(active) => active.emit(level, &message, true),
        None => print(&message),
    }
}

/// Record a diagnostic the console already words itself.
pub fn quiet(level: Level, message: impl Display) {
    if let Some(active) = ACTIVE.get() {
        active.emit(level, &message.to_string(), false);
    }
}

fn print(message: &str) {
    eprintln!("massrelay: {}", crate::visible(message));
}

impl Diagnostics {
    fn emit(&self, level: Level, message: &str, console: bool) {
        let entry = entry(level, message);
        let delivered = match &self.native {
            Some(log) => match log.send(level, &entry) {
                Ok(()) => true,
                Err(error) => {
                    if !self.write_failed.swap(true, Ordering::Relaxed) {
                        eprintln!(
                            "massrelay: could not write to {} ({error}); diagnostics that \
                             cannot be written there stay on standard error",
                            native::FACILITY
                        );
                    }
                    false
                }
            },
            None => false,
        };
        if !self.console {
            // Standard error is the native log by another route: the same
            // scrubbed entry, and only when the direct route failed.
            if !delivered {
                print(&entry);
            }
        } else if console || !delivered {
            print(message);
        }
    }
}

/// The one-line, scrubbed text of a native log entry.
fn entry(level: Level, message: &str) -> String {
    let prefix = match level {
        Level::Info => "",
        Level::Warning => "warning: ",
        Level::Error => "error: ",
    };
    format!("{prefix}{}", scrub(message))
}

fn key_alphabet(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// See "What is never logged" in the module documentation.
fn scrub(text: &str) -> String {
    let text: Vec<char> = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut clean = String::with_capacity(text.len());
    let mut rest = text.as_slice();
    while let Some(&first) = rest.first() {
        let (taken, secret) = if key_alphabet(first) {
            let run = rest.iter().take_while(|c| key_alphabet(**c)).count();
            (run, run >= SECRET_RUN)
        } else if let Some(array) = byte_array(rest) {
            (array, true)
        } else {
            (1, false)
        };
        if secret {
            clean.push_str(REDACTED);
        } else {
            clean.extend(&rest[..taken]);
        }
        rest = &rest[taken..];
    }
    match clean.char_indices().nth(MAX_ENTRY) {
        Some((end, _)) => {
            clean.truncate(end);
            clean.push_str("...");
            clean
        }
        None => clean,
    }
}

/// The length of a printed byte array (`[12, 34, ...]`, at least eight
/// numbers) at the start of `text`.
fn byte_array(text: &[char]) -> Option<usize> {
    if text.first() != Some(&'[') {
        return None;
    }
    let end = text.iter().position(|c| *c == ']')?;
    let inner = &text[1..end];
    let numbers = inner
        .iter()
        .all(|c| c.is_ascii_digit() || *c == ',' || *c == ' ');
    (numbers && inner.iter().filter(|c| **c == ',').count() >= 7).then_some(end + 1)
}

// ----------------------------------------------------------------- reading

/// `massrelay logs`: print the profile's recent diagnostics, then, with
/// `follow`, new ones as they are written.
pub fn show(state_dir: &Path, follow: bool) -> Result<i32> {
    let profile = profile_id(state_dir);
    if follow {
        return native::follow(&profile);
    }
    let lines = native::recent(&profile)?;
    if lines.is_empty() {
        eprintln!("{NONE_YET}");
    }
    write_lines(&lines)?;
    Ok(0)
}

/// Print to standard output. A reader that stops early (a closed pipe) ends
/// the output without an error.
fn write_lines(lines: &[String]) -> Result<bool> {
    let mut out = io::stdout().lock();
    let written = lines
        .iter()
        .try_for_each(|line| writeln!(out, "{line}"))
        .and_then(|()| out.flush());
    match written {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Why a host log tool could not run: most usefully, that the host has none.
fn tool_error(command: &Command, error: io::Error) -> anyhow::Error {
    let tool = command.get_program().to_string_lossy().into_owned();
    if error.kind() == io::ErrorKind::NotFound {
        anyhow::anyhow!(
            "{} cannot be read on this host: {tool} was not found",
            native::FACILITY
        )
    } else {
        anyhow::Error::new(error).context(format!("run {tool}"))
    }
}

/// Run a host log tool and return what it printed.
fn capture(command: &mut Command) -> Result<String> {
    let output = command
        .stdin(Stdio::null())
        .output()
        .map_err(|error| tool_error(command, error))?;
    if !output.status.success() {
        bail!(
            "could not read {} ({}): {}",
            native::FACILITY,
            output.status,
            crate::visible(String::from_utf8_lossy(&output.stderr).trim())
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Become a host log tool that prints until it is interrupted. Replacing
/// this process leaves no child behind when only this process is signalled.
#[cfg(unix)]
fn become_tool(command: &mut Command) -> Result<i32> {
    use std::os::unix::process::CommandExt;

    let error = command.stdin(Stdio::null()).exec();
    Err(tool_error(command, error))
}

/// One Windows event of this program, from `wevtutil`'s XML rendering.
#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
struct WindowsEvent {
    record: u64,
    /// UTC, as the event log wrote it.
    time: String,
    message: String,
}

/// The events of `profile` in `wevtutil qe /f:xml` output, oldest first.
/// Each event's strings are its message, then its profile.
#[cfg(any(windows, test))]
fn windows_events(xml: &str, profile: &str) -> Vec<WindowsEvent> {
    fn between<'a>(text: &'a str, open: &str, close: &str) -> Option<&'a str> {
        let start = text.find(open)? + open.len();
        Some(&text[start..start + text[start..].find(close)?])
    }
    fn unescape(text: &str) -> String {
        text.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&")
    }
    let mut events: Vec<WindowsEvent> = xml
        .split("<Event ")
        .skip(1)
        .filter_map(|event| {
            let mut strings = event
                .split("<Data>")
                .skip(1)
                .filter_map(|data| Some(unescape(&data[..data.find("</Data>")?])));
            let message = strings.next()?;
            if strings.next()? != profile {
                return None;
            }
            let time = ["SystemTime='", "SystemTime=\""]
                .into_iter()
                .find_map(|open| between(event, open, &open[open.len() - 1..]))?;
            Some(WindowsEvent {
                record: between(event, "<EventRecordID>", "</EventRecordID>")?
                    .trim()
                    .parse()
                    .ok()?,
                time: time.to_owned(),
                message,
            })
        })
        .collect();
    events.sort_by_key(|event| event.record);
    events
}

// -------------------------------------------------------------------- Linux

#[cfg(target_os = "linux")]
mod native {
    use std::io;
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixDatagram;
    use std::path::Path;
    use std::process::Command;

    use anyhow::Result;

    use super::{Level, RECENT};

    pub const FACILITY: &str = "the systemd journal";
    const SOCKET: &str = "/run/systemd/journal/socket";
    const IDENTIFIER: &str = "massrelay";
    const PROFILE_FIELD: &str = "MASSRELAY_PROFILE";

    /// The journal's native datagram socket.
    pub struct Log {
        socket: UnixDatagram,
        profile: String,
    }

    impl Log {
        pub fn open(profile: &str) -> io::Result<Self> {
            Self::open_at(Path::new(SOCKET), profile)
        }

        pub fn open_at(socket: &Path, profile: &str) -> io::Result<Self> {
            let journal = UnixDatagram::unbound()?;
            journal.connect(socket)?;
            // A stalled journal must never stall the runtime.
            journal.set_nonblocking(true)?;
            Ok(Self {
                socket: journal,
                profile: profile.to_owned(),
            })
        }

        /// `text` is one line (see `super::scrub`), so every field is one
        /// `NAME=value` line of the native protocol.
        pub fn send(&self, level: Level, text: &str) -> io::Result<()> {
            let priority = match level {
                Level::Info => 6,
                Level::Warning => 4,
                Level::Error => 3,
            };
            let fields = format!(
                "PRIORITY={priority}\nSYSLOG_IDENTIFIER={IDENTIFIER}\n{PROFILE_FIELD}={}\n\
                 MESSAGE={text}\n",
                self.profile
            );
            self.socket.send(fields.as_bytes()).map(drop)
        }
    }

    /// Whether systemd connected standard error to the journal: it names
    /// that stream's device and inode in `JOURNAL_STREAM`.
    pub fn stderr_is_log() -> bool {
        let Ok(stream) = std::env::var("JOURNAL_STREAM") else {
            return false;
        };
        io::stderr()
            .as_fd()
            .try_clone_to_owned()
            .and_then(|fd| std::fs::File::from(fd).metadata())
            .is_ok_and(|stderr| stream == format!("{}:{}", stderr.dev(), stderr.ino()))
    }

    fn journalctl(profile: &str) -> Command {
        let mut command = Command::new("journalctl");
        command
            .args(["--quiet", "--no-pager", "--output=short-iso"])
            .arg(format!("--lines={RECENT}"))
            .arg(format!("{PROFILE_FIELD}={profile}"));
        command
    }

    pub fn recent(profile: &str) -> Result<Vec<String>> {
        let text = super::capture(&mut journalctl(profile))?;
        Ok(text.lines().map(str::to_owned).collect())
    }

    pub fn follow(profile: &str) -> Result<i32> {
        super::become_tool(journalctl(profile).arg("--follow"))
    }
}

// -------------------------------------------------------------------- macOS

#[cfg(target_os = "macos")]
mod native {
    use std::ffi::{CStr, CString, c_char, c_void};
    use std::io;
    use std::process::Command;

    use anyhow::Result;

    use super::{Level, RECENT};

    pub const FACILITY: &str = "macOS Unified Logging";
    const SUBSYSTEM: &CStr = c"com.massrelay.client";
    /// `os_log_type_t`. Default entries are stored; info entries are not.
    const OS_LOG_TYPE_DEFAULT: u8 = 0x00;
    const OS_LOG_TYPE_ERROR: u8 = 0x10;

    // `os_log` is a C macro over these. It passes the image, a format string
    // constant in that image, and the arguments encoded as clang's
    // `__builtin_os_log_format` lays them out.
    unsafe extern "C" {
        #[allow(non_upper_case_globals)]
        static __dso_handle: u8;
        fn os_log_create(subsystem: *const c_char, category: *const c_char) -> *mut c_void;
        fn os_log_type_enabled(log: *mut c_void, kind: u8) -> bool;
        fn _os_log_impl(
            dso: *mut c_void,
            log: *mut c_void,
            kind: u8,
            format: *const c_char,
            buffer: *mut u8,
            size: u32,
        );
    }

    #[unsafe(link_section = "__TEXT,__oslogstring,cstring_literals")]
    static FORMAT: [u8; 11] = *b"%{public}s\0";

    /// The encoded arguments of `FORMAT`: one public C string.
    #[repr(C, align(16))]
    struct Arguments([u8; 12]);

    impl Arguments {
        fn new(text: &CStr) -> Self {
            let mut encoded = [0; 12];
            // Summary: has non-scalar items. One argument. Its descriptor
            // (string kind, public) and size, then the pointer.
            encoded[..4].copy_from_slice(&[0x02, 0x01, 0x22, 0x08]);
            encoded[4..].copy_from_slice(&(text.as_ptr() as usize as u64).to_ne_bytes());
            Self(encoded)
        }
    }

    /// An `os_log_t` for the subsystem, with the profile as its category.
    pub struct Log(*mut c_void);

    // SAFETY: an `os_log_t` is immutable once created and may be used from
    // any thread.
    unsafe impl Send for Log {}
    unsafe impl Sync for Log {}

    impl Log {
        pub fn open(profile: &str) -> io::Result<Self> {
            let category = CString::new(profile).map_err(io::Error::other)?;
            // SAFETY: both arguments are valid C strings, which the call copies.
            let log = unsafe { os_log_create(SUBSYSTEM.as_ptr(), category.as_ptr()) };
            if log.is_null() {
                return Err(io::Error::other("os_log_create failed"));
            }
            Ok(Self(log))
        }

        pub fn send(&self, level: Level, text: &str) -> io::Result<()> {
            let kind = match level {
                Level::Info | Level::Warning => OS_LOG_TYPE_DEFAULT,
                Level::Error => OS_LOG_TYPE_ERROR,
            };
            let text = CString::new(text).map_err(io::Error::other)?;
            let mut arguments = Arguments::new(&text);
            // SAFETY: the log handle is live, the format is a constant C
            // string in this image, and the argument buffer matches it and
            // points at `text`, which outlives the call.
            unsafe {
                if os_log_type_enabled(self.0, kind) {
                    _os_log_impl(
                        (&raw const __dso_handle).cast_mut().cast(),
                        self.0,
                        kind,
                        FORMAT.as_ptr().cast(),
                        arguments.0.as_mut_ptr(),
                        arguments.0.len() as u32,
                    );
                }
            }
            Ok(())
        }
    }

    pub fn stderr_is_log() -> bool {
        false
    }

    fn log(action: &str, profile: &str) -> Command {
        let mut command = Command::new("/usr/bin/log");
        command
            .args([action, "--style", "compact", "--predicate"])
            .arg(format!(
                "subsystem == \"{}\" AND category == \"{profile}\"",
                SUBSYSTEM.to_string_lossy()
            ));
        command
    }

    pub fn recent(profile: &str) -> Result<Vec<String>> {
        let text = super::capture(log("show", profile).args(["--last", "1d"]))?;
        // The first line is the column heading.
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| !line.starts_with("Timestamp") && !line.trim().is_empty())
            .collect();
        let skipped = lines.len().saturating_sub(RECENT);
        Ok(lines[skipped..]
            .iter()
            .map(|line| (*line).to_owned())
            .collect())
    }

    pub fn follow(profile: &str) -> Result<i32> {
        if !super::write_lines(&recent(profile)?)? {
            return Ok(0);
        }
        super::become_tool(&mut log("stream", profile))
    }
}

// ------------------------------------------------------------------ Windows

#[cfg(windows)]
mod native {
    use std::io;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    use anyhow::Result;
    use chrono::{DateTime, Local};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE,
        EVENTLOG_WARNING_TYPE, RegisterEventSourceW, ReportEventW,
    };

    use super::{Level, RECENT, WindowsEvent};

    pub const FACILITY: &str = "the Windows Event Log";
    /// Event source in the Application log.
    const SOURCE: &str = "MassRelay";
    const EVENT_ID: u32 = 1;
    /// How many of the source's newest events are searched for the profile's.
    const SEARCHED: usize = 2000;
    /// How often `logs --follow` looks for new events.
    const POLL: Duration = Duration::from_secs(2);

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    /// An event source handle. Each event carries two strings: the message,
    /// then the profile.
    pub struct Log {
        source: HANDLE,
        profile: Vec<u16>,
    }

    // SAFETY: an event source handle may be used from any thread.
    unsafe impl Send for Log {}
    unsafe impl Sync for Log {}

    impl Log {
        pub fn open(profile: &str) -> io::Result<Self> {
            let name = wide(SOURCE);
            // SAFETY: `name` is a NUL-terminated UTF-16 string.
            let source = unsafe { RegisterEventSourceW(std::ptr::null(), name.as_ptr()) };
            if source.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                source,
                profile: wide(profile),
            })
        }

        pub fn send(&self, level: Level, text: &str) -> io::Result<()> {
            let kind = match level {
                Level::Info => EVENTLOG_INFORMATION_TYPE,
                Level::Warning => EVENTLOG_WARNING_TYPE,
                Level::Error => EVENTLOG_ERROR_TYPE,
            };
            let message = wide(text);
            let strings = [message.as_ptr(), self.profile.as_ptr()];
            // SAFETY: the handle is live and `strings` holds two
            // NUL-terminated UTF-16 strings that outlive the call.
            let reported = unsafe {
                ReportEventW(
                    self.source,
                    kind,
                    0,
                    EVENT_ID,
                    std::ptr::null_mut(),
                    strings.len() as u16,
                    0,
                    strings.as_ptr(),
                    std::ptr::null(),
                )
            };
            if reported == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for Log {
        fn drop(&mut self) {
            // SAFETY: the handle came from `RegisterEventSourceW`.
            unsafe { DeregisterEventSource(self.source) };
        }
    }

    pub fn stderr_is_log() -> bool {
        false
    }

    /// This profile's events among the source's `newest` most recent,
    /// oldest first. The profile is matched here, not in the query.
    fn query(profile: &str, newest: usize) -> Result<Vec<WindowsEvent>> {
        let tool = std::env::var_os("SystemRoot")
            .map(|root| PathBuf::from(root).join("System32").join("wevtutil.exe"))
            .unwrap_or_else(|| "wevtutil.exe".into());
        let mut command = Command::new(tool);
        command
            .args(["qe", "Application", "/f:xml", "/rd:true"])
            .arg(format!("/c:{newest}"))
            .arg(format!("/q:*[System[Provider[@Name='{SOURCE}']]]"));
        Ok(super::windows_events(
            &super::capture(&mut command)?,
            profile,
        ))
    }

    fn lines(events: &[WindowsEvent]) -> Vec<String> {
        events
            .iter()
            .map(|event| {
                let time = DateTime::parse_from_rfc3339(&event.time).map_or_else(
                    |_| event.time.clone(),
                    |time| {
                        time.with_timezone(&Local)
                            .format("%Y-%m-%d %H:%M:%S")
                            .to_string()
                    },
                );
                format!("{time} {}", event.message)
            })
            .collect()
    }

    fn recent_events(profile: &str) -> Result<Vec<WindowsEvent>> {
        let mut events = query(profile, SEARCHED)?;
        events.drain(..events.len().saturating_sub(RECENT));
        Ok(events)
    }

    pub fn recent(profile: &str) -> Result<Vec<String>> {
        Ok(lines(&recent_events(profile)?))
    }

    pub fn follow(profile: &str) -> Result<i32> {
        let mut events = recent_events(profile)?;
        let mut last = 0;
        loop {
            last = events.last().map_or(last, |event| event.record);
            if !super::write_lines(&lines(&events))? {
                return Ok(0);
            }
            std::thread::sleep(POLL);
            events = query(profile, RECENT)?;
            events.retain(|event| event.record > last);
        }
    }
}

// ------------------------------------------------------------- other hosts

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod native {
    use std::io;

    use anyhow::{Result, bail};

    use super::Level;

    pub const FACILITY: &str = "a native log";

    pub struct Log;

    impl Log {
        pub fn open(_profile: &str) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this platform has none MassRelay can write",
            ))
        }

        pub fn send(&self, _level: Level, _text: &str) -> io::Result<()> {
            Ok(())
        }
    }

    pub fn stderr_is_log() -> bool {
        false
    }

    pub fn recent(_profile: &str) -> Result<Vec<String>> {
        bail!("MassRelay keeps no diagnostics log on this platform")
    }

    pub fn follow(profile: &str) -> Result<i32> {
        recent(profile).map(|_| 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entries are readable by other accounts, so nothing shaped like a key,
    /// credential or printed secret may survive, whatever text an error
    /// carried, and one entry must stay one line.
    #[test]
    fn entries_carry_no_key_material_or_extra_lines() {
        let endpoint = hex(&[0xab; 32]);
        let credential = "mrprivx1_eyJzZXJ2ZXIiOnsiaWQiOiJhYmNkZWYwMTIzNDU2Nzg5In19";
        let invite = "mrprivinv0_eyJmb3JtYXQiOiJtYXNzcmVsYXktcHJpdmF0ZS1pbnZpdGUifQ";
        let bytes = format!("{:?}", [7u8; 32]);
        let text = entry(
            Level::Error,
            &format!(
                "runtime failed: NotMember({bytes}) for {endpoint}\nMASSRELAY_PROFILE=other\r\n\
                 at /home/a user/state: {credential} {invite} (os error 13)"
            ),
        );
        for secret in [&endpoint, credential, invite, bytes.as_str()] {
            assert!(!text.contains(secret), "{text}");
        }
        assert!(!text.contains(|c: char| c.is_control()), "{text}");
        assert_eq!(
            text,
            "error: runtime failed: NotMember([redacted]) for [redacted] \
             MASSRELAY_PROFILE=other  at /home/a user/state: [redacted] [redacted] (os error 13)"
        );
        // Ordinary diagnostics are untouched, and a flood is bounded.
        let plain = "could not reuse UDP port 4433: Address already in use (os error 98) [1, 2]";
        assert_eq!(entry(Level::Info, plain), plain);
        assert_eq!(
            entry(Level::Warning, &"word ".repeat(1000)).chars().count(),
            "warning: ...".len() + MAX_ENTRY
        );
    }

    /// The service writes under the canonical state directory and the command
    /// that reads its log may spell the same directory another way; both must
    /// select the same profile, and no other.
    #[test]
    fn a_profile_is_identified_by_its_directory_however_it_is_spelled() {
        let root = tempfile::tempdir().unwrap();
        let (a, b) = (root.path().join("a"), root.path().join("b"));
        std::fs::create_dir_all(a.join("nested")).unwrap();
        std::fs::create_dir(&b).unwrap();
        let id = profile_id(&a);
        assert_eq!(id.len(), 16);
        assert!(id.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(profile_id(&a.join("nested").join("..")), id);
        assert_eq!(profile_id(&a.canonicalize().unwrap()), id);
        assert_ne!(profile_id(&b), id);
        #[cfg(unix)]
        {
            let link = root.path().join("link");
            std::os::unix::fs::symlink(&a, &link).unwrap();
            assert_eq!(profile_id(&link), id);
        }
    }

    /// The exact journal entry: the profile field `massrelay logs` filters
    /// on, the priority, and a message that cannot add or replace a field. A
    /// host without the journal is reported, not fatal.
    #[cfg(target_os = "linux")]
    #[test]
    fn journal_entries_are_single_fields_tagged_with_the_profile() {
        use std::os::unix::net::UnixDatagram;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("journal");
        assert!(native::Log::open_at(&path, "0123456789abcdef").is_err());
        let journal = UnixDatagram::bind(&path).unwrap();
        let active = Diagnostics {
            native: Some(native::Log::open_at(&path, "0123456789abcdef").unwrap()),
            console: false,
            write_failed: AtomicBool::new(false),
        };
        active.emit(
            Level::Warning,
            &format!(
                "no sync\nMASSRELAY_PROFILE=ffff\nPRIORITY=0 {}",
                hex(&[1; 32])
            ),
            false,
        );
        let mut received = [0; 4096];
        let length = journal.recv(&mut received).unwrap();
        assert_eq!(
            std::str::from_utf8(&received[..length]).unwrap(),
            "PRIORITY=4\nSYSLOG_IDENTIFIER=massrelay\nMASSRELAY_PROFILE=0123456789abcdef\n\
             MESSAGE=warning: no sync MASSRELAY_PROFILE=ffff PRIORITY=0 [redacted]\n"
        );
        // A journal that has gone away costs the entry, never the runtime.
        drop(journal);
        std::fs::remove_file(&path).unwrap();
        active.emit(Level::Info, "after the journal stopped", false);
        assert!(active.write_failed.load(Ordering::Relaxed));
    }

    /// `massrelay logs` on Windows reads `wevtutil`'s XML rendering, newest
    /// first, and keeps only the selected profile's events.
    #[test]
    fn windows_events_are_read_from_wevtutil_xml() {
        let event = |record: u32, message: &str, profile: &str| {
            format!(
                "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
                 <Provider Name='MassRelay'/><EventID Qualifiers='0'>1</EventID><Level>4</Level>\
                 <Task>0</Task><Keywords>0x80000000000000</Keywords>\
                 <TimeCreated SystemTime='2026-11-26T18:40:0{record}.1234567Z'/>\
                 <EventRecordID>{record}</EventRecordID><Channel>Application</Channel>\
                 <Computer>host</Computer><Security/></System><EventData><Data>{message}</Data>\
                 <Data>{profile}</Data></EventData></Event>"
            )
        };
        let (mine, other) = ("0123456789abcdef", "fedcba9876543210");
        let escaped = "warning: could not reuse UDP port 1: &lt;in use&gt; &amp;amp; &apos;x&apos;";
        let xml = format!(
            "{}\r\n{}\r\n{}\r\n{}\r\n",
            event(9, mine, other),
            event(8, escaped, mine),
            event(7, "the runtime started (massrelay 0.4.0)", mine),
            event(6, "the runtime stopped", other),
        );
        assert_eq!(
            windows_events(&xml, mine),
            [
                WindowsEvent {
                    record: 7,
                    time: "2026-11-26T18:40:07.1234567Z".into(),
                    message: "the runtime started (massrelay 0.4.0)".into(),
                },
                WindowsEvent {
                    record: 8,
                    time: "2026-11-26T18:40:08.1234567Z".into(),
                    message: "warning: could not reuse UDP port 1: <in use> &amp; 'x'".into(),
                },
            ]
        );
        assert!(windows_events("", mine).is_empty());
    }

    /// Against the host's real log: an entry written for one profile is read
    /// back by that profile's query, scrubbed, and by no other profile's.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    #[ignore = "writes to and reads from this host's log"]
    fn native_log_round_trip() {
        let root = tempfile::tempdir().unwrap();
        let (profile, other) = (profile_id(root.path()), profile_id(&root.path().join("x")));
        let log = match native::Log::open(&profile) {
            Ok(log) => log,
            Err(error) => {
                eprintln!("skipped: {} is not available: {error}", native::FACILITY);
                return;
            }
        };
        let active = Diagnostics {
            native: Some(log),
            console: false,
            write_failed: AtomicBool::new(false),
        };
        let secret = hex(&crate::wire::random().unwrap());
        active.emit(
            Level::Warning,
            &format!("round trip for {secret}\nsecond line"),
            false,
        );
        assert!(!active.write_failed.load(Ordering::Relaxed));
        let expected = "warning: round trip for [redacted] second line";
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let lines = loop {
            let lines = native::recent(&profile).unwrap();
            if !lines.is_empty() || std::time::Instant::now() > deadline {
                break lines;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        };
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].ends_with(expected), "{lines:?}");
        assert!(native::recent(&other).unwrap().is_empty());
    }
}
