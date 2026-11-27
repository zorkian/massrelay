//! Read the local connection audit for the logs command.

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Local, SecondsFormat};
use serde::Deserialize;

use crate::connection_log::Direction;
use crate::wire::Service;

/// Bound the history scan and the amount of work per follow poll.
const WINDOW: u64 = 1024 * 1024;
const ANCHOR: usize = 256;

pub(super) struct Tail {
    path: PathBuf,
    required: bool,
    offset: u64,
    anchor: Vec<u8>,
}

impl Tail {
    pub(super) fn new(path: PathBuf, required: bool) -> Self {
        Self {
            path,
            required,
            offset: 0,
            anchor: Vec::new(),
        }
    }

    pub(super) fn read(&mut self, limit: usize) -> Result<Vec<String>> {
        self.read_file(limit)
            .with_context(|| format!("read connection audit {}", self.path.display()))
    }

    fn read_file(&mut self, limit: usize) -> Result<Vec<String>> {
        // Check before opening so an ordinary non-file path (e.g. a FIFO) cannot block logs.
        let file = fs::metadata(&self.path).and_then(|metadata| {
            if !metadata.is_file() {
                return Err(io::Error::other("expected a regular file"));
            }
            File::open(&self.path)
        });
        let mut file = match file {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound && !self.required => {
                self.offset = 0;
                self.anchor.clear();
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };
        self.required = false;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "expected a regular file");
        let end = metadata.len();

        // Reopen by path on each poll. A short anchor detects replacement or truncation
        // even if the new file has already grown past the previous offset.
        if end < self.offset || !self.matches_anchor(&mut file)? {
            self.offset = 0;
            self.anchor.clear();
        }
        let start = self.offset.max(end.saturating_sub(WINDOW));
        if start == end {
            return Ok(Vec::new());
        }

        file.seek(SeekFrom::Start(start.saturating_sub(1)))?;
        let mut bytes = Vec::new();
        file.take(end - start.saturating_sub(1))
            .read_to_end(&mut bytes)?;
        // When the window starts mid-record, skip through the first newline.
        let mut records = bytes.as_slice();
        if start > 0 {
            let Some((&previous, rest)) = records.split_first() else {
                return Ok(Vec::new());
            };
            records = if previous == b'\n' {
                rest
            } else {
                rest.iter()
                    .position(|&b| b == b'\n')
                    .map_or(&[][..], |i| &rest[i + 1..])
            };
        }
        // Remember the last completed line. A later append can finish a partial line.
        if let Some(last) = bytes.iter().rposition(|&b| b == b'\n')
            && let offset = start.saturating_sub(1) + last as u64 + 1
            && offset > self.offset
        {
            self.offset = offset;
            self.anchor = bytes[(last + 1).saturating_sub(ANCHOR)..=last].to_vec();
        }
        let mut lines: Vec<_> = records
            .rsplit(|&b| b == b'\n')
            .skip(1) // The final segment is either empty or still being written.
            .filter_map(render)
            .take(limit)
            .collect();
        lines.reverse();
        Ok(lines)
    }

    fn matches_anchor(&self, file: &mut File) -> io::Result<bool> {
        if self.anchor.is_empty() {
            return Ok(true);
        }
        let len = self.anchor.len();
        let mut bytes = [0; ANCHOR];
        file.seek(SeekFrom::Start(self.offset - len as u64))?;
        match file.read_exact(&mut bytes[..len]) {
            Ok(()) => Ok(bytes[..len] == self.anchor),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::path::Path;

    fn append(path: &Path, bytes: &[u8]) {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    fn record(event: &str) -> String {
        format!("{{\"timestamp\":\"2026-11-27T00:00:00Z\",\"event\":\"{event}\"}}")
    }

    #[test]
    fn tails_complete_records_across_appends_and_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut tail = Tail::new(path.clone(), false);
        assert!(tail.read(10).unwrap().is_empty());

        append(
            &path,
            format!("{}\n{}", record("connected"), record("disconnected")).as_bytes(),
        );
        assert!(tail.read(10).unwrap()[0].ends_with("connected"));
        assert!(tail.read(10).unwrap().is_empty());
        append(&path, b"\n");
        assert!(tail.read(10).unwrap()[0].ends_with("disconnected"));
        assert!(tail.read(10).unwrap().is_empty());

        fs::rename(&path, dir.path().join("old.jsonl")).unwrap();
        fs::write(&path, format!("{}\n", record("approval_granted")).repeat(3)).unwrap();
        let lines = tail.read(10).unwrap();
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|line| line.ends_with("approval granted")));

        fs::write(&path, format!("{}\n", record("service_enabled"))).unwrap();
        let lines = tail.read(10).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].ends_with("service enabled"));
    }

    #[test]
    fn bounds_history_and_skips_bad_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        append(&path, format!("{}\n", record("older")).as_bytes());
        append(&path, &vec![b'x'; WINDOW as usize]);
        append(&path, b"\n");
        append(
            &path,
            format!(
                "{}\n{{corrupt}}\n{}\n",
                record("connected"),
                record("disconnected")
            )
            .as_bytes(),
        );
        let mut tail = Tail::new(path, true);
        let lines = tail.read(1).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].ends_with("disconnected"));
        assert!(tail.read(10).unwrap().is_empty());
    }
}

#[derive(Deserialize)]
struct Record<'a> {
    timestamp: &'a str,
    event: &'a str,
    peer_id: Option<&'a str>,
    peer_name: Option<String>,
    service: Option<Service>,
    direction: Option<Direction>,
    pid: Option<u32>,
    session: Option<u64>,
    operation: Option<&'a str>,
    outcome: Option<&'a str>,
    target_id: Option<&'a str>,
    reason: Option<&'a str>,
    exit_code: Option<i32>,
}

fn words(token: &str) -> Option<String> {
    (!token.is_empty()
        && token.len() <= 64
        && token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
    .then(|| token.replace('_', " "))
}

fn render(line: &[u8]) -> Option<String> {
    let record: Record<'_> = serde_json::from_slice(line).ok()?;
    if record.event == "local_control"
        && (record.outcome == Some("requested")
            || matches!(record.operation, Some("status" | "list_peers")))
    {
        return None;
    }
    let time = DateTime::parse_from_rfc3339(record.timestamp)
        .ok()?
        .with_timezone(&Local)
        .to_rfc3339_opts(SecondsFormat::Millis, false);
    let event = words(record.event)?;
    let mut line = format!("{time} [audit] {event}");
    if let Some(operation) = record.operation.and_then(words) {
        write!(line, " {operation}").unwrap();
    }
    if let Some(outcome) = record.outcome.and_then(words) {
        write!(line, " ({outcome})").unwrap();
    }
    if let Some(direction) = record.direction {
        line.push_str(match direction {
            Direction::Inbound => " inbound",
            Direction::Outbound => " outbound",
        });
    }
    if let Some(service) = record.service {
        write!(line, " {service}").unwrap();
    }
    if let Some(name) = record.peer_name.filter(|name| !name.is_empty()) {
        // Debug string formatting escapes control and bidi characters in untrusted aliases.
        let name: String = name.chars().take(80).collect();
        write!(line, " peer {name:?}").unwrap();
    } else if let Some(id) = record.peer_id.or(record.target_id)
        && id.len() == 64
        && id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        write!(line, " peer {}", &id[..8]).unwrap();
    }
    if let Some(session) = record.session {
        if let Some(pid) = record.pid {
            write!(line, " [session {pid}/{session}]").unwrap();
        } else {
            write!(line, " [session {session}]").unwrap();
        }
    }
    if let Some(reason) = record.reason.and_then(words) {
        write!(line, " — {reason}").unwrap();
    }
    if let Some(code) = record.exit_code {
        write!(line, " (exit {code})").unwrap();
    }
    Some(line)
}
