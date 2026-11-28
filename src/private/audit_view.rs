//! Read the local connection audit for the logs command.

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Take};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Local, SecondsFormat};
use serde::Deserialize;

use crate::connection_log::Direction;
use crate::wire::Service;

/// Read size for scanning, and about how much one follow batch covers. Not a limit: a
/// longer record is read whole.
const CHUNK: usize = 64 * 1024;
const ANCHOR: usize = 256;

pub(super) struct Tail {
    path: PathBuf,
    required: bool,
    /// Just past the last complete record read.
    offset: u64,
    /// The bytes ending at `offset`.
    anchor: Vec<u8>,
    /// The file those were read from.
    source: Option<Source>,
}

/// Which file the audit path named.
struct Source {
    identity: Identity,
    /// Held open so that the inode number cannot pass to a replacement. A Windows file
    /// number carries its own reuse count on NTFS, and holding a removed file open
    /// there could keep its name from being used again.
    #[cfg(unix)]
    _held: File,
}

/// A file's volume and its number there.
type Identity = (u64, u64);

#[cfg(unix)]
fn identity(file: &File) -> io::Result<Identity> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn identity(file: &File) -> io::Result<Identity> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open and the structure is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let number = u64::from(information.nFileIndexHigh) << 32 | u64::from(information.nFileIndexLow);
    Ok((u64::from(information.dwVolumeSerialNumber), number))
}

impl Tail {
    pub(super) fn new(path: PathBuf, required: bool) -> Self {
        Self {
            path,
            required,
            offset: 0,
            anchor: Vec::new(),
            source: None,
        }
    }

    /// The newest `limit` entries, oldest first. `unread` continues after them.
    pub(super) fn recent(&mut self, limit: usize) -> Result<Vec<String>> {
        self.scan_back(limit).with_context(|| failed(&self.path))
    }

    /// Entries completed since the last read, up to the audit's length now.
    pub(super) fn unread(&mut self) -> Result<Unread<'_>> {
        let records = self
            .open()
            .and_then(|opened| {
                let Some((mut file, end)) = opened else {
                    return Ok(None);
                };
                file.seek(SeekFrom::Start(self.offset))?;
                let records = file.take(end - self.offset);
                Ok(Some(BufReader::with_capacity(CHUNK, records)))
            })
            .with_context(|| failed(&self.path))?;
        Ok(Unread {
            tail: self,
            records,
        })
    }

    /// The audit and its length, or `None` while there is none. Starts over if the file
    /// is not the one read before.
    fn open(&mut self) -> Result<Option<(File, u64)>> {
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
                self.start_over();
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        self.required = false;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "expected a regular file");
        let end = metadata.len();

        // Reopen by path on each read. The file's identity detects replacement. A short
        // anchor detects a rewrite in place, even one grown past the previous offset.
        let found = identity(&file)?;
        let replaced = self
            .source
            .as_ref()
            .is_some_and(|source| source.identity != found);
        if replaced || end < self.offset || !self.matches_anchor(&mut file)? {
            self.start_over();
        }
        if self.source.is_none() {
            self.source = Some(Source {
                identity: found,
                #[cfg(unix)]
                _held: file.try_clone()?,
            });
        }
        Ok(Some((file, end)))
    }

    fn start_over(&mut self) {
        self.offset = 0;
        self.anchor.clear();
        self.source = None;
    }

    /// Read backwards from the end until `limit` entries are found.
    fn scan_back(&mut self, limit: usize) -> Result<Vec<String>> {
        let Some((mut file, end)) = self.open()? else {
            return Ok(Vec::new());
        };
        let mut lines = Vec::new();
        // The later pieces of a record whose start has not been read, last piece first.
        let mut pieces: Vec<Vec<u8>> = Vec::new();
        // Whether a newline has been passed. Text after the last one is still being written.
        let mut complete = false;
        let mut position = end;
        let mut buffer = vec![0; CHUNK];
        while position > 0 && lines.len() < limit {
            let length = position.min(CHUNK as u64) as usize;
            position -= length as u64;
            file.seek(SeekFrom::Start(position))?;
            file.read_exact(&mut buffer[..length])?;
            let mut chunk = &buffer[..length];
            while lines.len() < limit
                && let Some(newline) = chunk.iter().rposition(|&b| b == b'\n')
            {
                if complete {
                    lines.extend(render_pieces(&chunk[newline + 1..], &mut pieces));
                } else {
                    complete = true;
                    self.offset = position + newline as u64 + 1;
                    let start = self.offset.saturating_sub(ANCHOR as u64);
                    self.anchor = vec![0; (self.offset - start) as usize];
                    file.seek(SeekFrom::Start(start))?;
                    file.read_exact(&mut self.anchor)?;
                }
                chunk = &chunk[..newline];
            }
            if complete && lines.len() < limit {
                pieces.push(chunk.to_vec());
            }
        }
        // The first record has no newline before it.
        if complete && lines.len() < limit {
            lines.extend(render_pieces(&[], &mut pieces));
        }
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

/// The unread part of one audit, read a bounded batch at a time.
pub(super) struct Unread<'a> {
    tail: &'a mut Tail,
    records: Option<BufReader<Take<File>>>,
}

impl Unread<'_> {
    /// The next entries, oldest first (possibly none, if the records read are not shown),
    /// or `None` once every complete record has been read.
    pub(super) fn next_batch(&mut self) -> Result<Option<Vec<String>>> {
        let Some(records) = &mut self.records else {
            return Ok(None);
        };
        let mut lines = Vec::new();
        let mut line = Vec::new();
        let mut read = 0;
        while read < CHUNK {
            line.clear();
            records
                .read_until(b'\n', &mut line)
                .with_context(|| failed(&self.tail.path))?;
            // The end, or a record that a later append can finish.
            if line.last() != Some(&b'\n') {
                self.records = None;
                break;
            }
            read += line.len();
            self.tail.offset += line.len() as u64;
            let anchor = &mut self.tail.anchor;
            anchor.extend_from_slice(&line[line.len().saturating_sub(ANCHOR)..]);
            anchor.drain(..anchor.len().saturating_sub(ANCHOR));
            lines.extend(render(&line[..line.len() - 1]));
        }
        Ok((read > 0).then_some(lines))
    }
}

fn failed(path: &Path) -> String {
    format!("read connection audit {}", path.display())
}

/// Render the record that starts with `first` and continues with `pieces`.
fn render_pieces(first: &[u8], pieces: &mut Vec<Vec<u8>>) -> Option<String> {
    let mut record = first.to_vec();
    for piece in pieces.drain(..).rev() {
        record.extend(piece);
    }
    render(&record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

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

    fn named(name: &str) -> String {
        record("connected").replace('}', &format!(",\"peer_name\":\"{name}\"}}"))
    }

    fn drain(tail: &mut Tail) -> Vec<String> {
        let mut unread = tail.unread().unwrap();
        let mut lines = Vec::new();
        while let Some(batch) = unread.next_batch().unwrap() {
            lines.extend(batch);
        }
        lines
    }

    #[test]
    fn tails_complete_records_across_appends_and_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut tail = Tail::new(path.clone(), false);
        assert!(tail.recent(10).unwrap().is_empty());
        assert!(drain(&mut tail).is_empty());

        append(
            &path,
            format!("{}\n{}", record("connected"), record("disconnected")).as_bytes(),
        );
        let lines = tail.recent(10).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].ends_with("connected"));
        assert!(drain(&mut tail).is_empty());
        append(&path, b"\n");
        assert!(drain(&mut tail)[0].ends_with("disconnected"));
        assert!(drain(&mut tail).is_empty());

        fs::rename(&path, dir.path().join("old.jsonl")).unwrap();
        fs::write(&path, format!("{}\n", record("approval_granted")).repeat(3)).unwrap();
        let lines = drain(&mut tail);
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|line| line.ends_with("approval granted")));

        fs::write(&path, format!("{}\n", record("service_enabled"))).unwrap();
        let lines = drain(&mut tail);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].ends_with("service enabled"));
    }

    /// Repeated records make two files agree just before the cursor. A replacement is
    /// still read from its start, whether the old file was moved aside or removed (which
    /// frees its inode number), and so is a rewrite in place that differs there.
    #[test]
    fn rereads_a_replacement_that_matches_the_bytes_before_the_cursor() {
        let repeated = named(&"n".repeat(ANCHOR));
        let old = format!("{}\n{repeated}\n", record("first_old"));
        let new = format!(
            "{}\n{repeated}\n{}\n",
            record("first_new"),
            record("appended")
        );
        for moved_aside in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("audit.jsonl");
            fs::write(&path, &old).unwrap();
            let mut tail = Tail::new(path.clone(), true);
            assert_eq!(tail.recent(10).unwrap().len(), 2);
            // Twice, so that the identity learned while following is checked too.
            for _ in 0..2 {
                if moved_aside {
                    fs::rename(&path, dir.path().join("old.jsonl")).unwrap();
                } else {
                    fs::remove_file(&path).unwrap();
                }
                fs::write(&path, &new).unwrap();
                let lines = drain(&mut tail);
                assert_eq!(lines.len(), 3, "moved aside: {moved_aside}");
                assert!(lines[0].ends_with("first new"));
                assert!(drain(&mut tail).is_empty());
            }

            let rewritten = format!("{}\n", record("rewritten")).repeat(20);
            fs::write(&path, rewritten).unwrap();
            assert_eq!(drain(&mut tail).len(), 20);
        }
    }

    /// A backlog far beyond one batch, with records longer than a read, arrives whole
    /// and in order. A record appended during the catch-up waits for the next read.
    #[test]
    fn follows_every_unread_record_in_bounded_batches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        append(&path, format!("{}\n", record("older")).as_bytes());
        let mut tail = Tail::new(path.clone(), true);
        assert_eq!(tail.recent(10).unwrap().len(), 1);

        let long = "n".repeat(3 * CHUNK);
        let mut backlog = format!("{}\n", named(&long));
        for number in 0..20_000 {
            writeln_record(&mut backlog, &named(&format!("peer-{number}")));
        }
        writeln_record(&mut backlog, &named(&long));
        assert!(backlog.len() > 1024 * 1024);
        append(&path, backlog.as_bytes());

        let mut unread = tail.unread().unwrap();
        let mut lines = unread.next_batch().unwrap().unwrap();
        assert_eq!(lines.len(), 1, "a batch ends once it has read enough");
        append(&path, format!("{}\n", record("later")).as_bytes());
        while let Some(batch) = unread.next_batch().unwrap() {
            assert!(batch.iter().map(String::len).sum::<usize>() < 5 * CHUNK);
            lines.extend(batch);
        }
        assert_eq!(lines.len(), 20_002);
        for (number, line) in lines[1..20_001].iter().enumerate() {
            assert!(line.ends_with(&format!("peer \"peer-{number}\"")), "{line}");
        }
        for line in [&lines[0], &lines[20_001]] {
            assert!(line.contains(&long), "a long name is shown whole");
        }
        let lines = drain(&mut tail);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].ends_with("later"));
    }

    fn writeln_record(text: &mut String, record: &str) {
        text.push_str(record);
        text.push('\n');
    }

    #[test]
    fn history_is_the_newest_entries_however_far_back_they_are() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let long = "n".repeat(2 * 1024 * 1024);
        append(
            &path,
            format!(
                "{}\n{}\n{}\n{}\n{{corrupt}}\n{}\n{{\"unfinished",
                record("older"),
                record("connected"),
                named(&long),
                "x".repeat(3 * CHUNK),
                record("disconnected")
            )
            .as_bytes(),
        );
        let lines = Tail::new(path.clone(), true).recent(3).unwrap();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].ends_with("connected"));
        assert!(lines[1].contains(&long));
        assert!(lines[2].ends_with("disconnected"));
        let mut tail = Tail::new(path, true);
        let lines = tail.recent(10).unwrap();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].ends_with("older"));
        assert!(drain(&mut tail).is_empty());
    }

    /// Records that straddle a read boundary are neither split nor repeated.
    #[test]
    fn history_joins_records_across_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let first = format!("{}\n", record("first"));
        let last = named("last");
        // Place the newline before the last record on either side of a boundary.
        for padding in CHUNK - last.len() - 3..=CHUNK - last.len() + 1 {
            let middle = "x".repeat(padding);
            fs::write(&path, format!("{first}{middle}\n{last}\n")).unwrap();
            let lines = Tail::new(path.clone(), true).recent(10).unwrap();
            assert_eq!(lines.len(), 2, "padding {padding}");
            assert!(lines[0].ends_with("first"));
            assert!(lines[1].ends_with("peer \"last\""));
        }
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
