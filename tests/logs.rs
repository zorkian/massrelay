#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};

struct Fixture {
    dir: TempDir,
}

impl Fixture {
    fn new(journalctl: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("journalctl");
        fs::write(&tool, format!("#!/bin/sh\n{journalctl}\n")).unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        Self { dir }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_massrelay"));
        command
            .env("PATH", self.dir.path())
            .args(["--state-dir"])
            .arg(self.dir.path())
            .arg("logs");
        command
    }

    fn append(&self, event: Value) {
        append(&self.dir.path().join("connections.jsonl"), event);
    }
}

fn append(path: &Path, mut event: Value) {
    event["timestamp"] = json!("2026-11-27T00:00:00.123Z");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(file, "{event}").unwrap();
}

#[test]
fn reads_profile_history_and_escapes_private_audit_fields() {
    let fixture = Fixture::new("printf '%s\\n' \"$@\" 'the runtime started'");
    let peer_id = "0123456789abcdef".repeat(4);
    fixture.append(json!({
        "event": "approval_granted", "peer_id": peer_id,
        "peer_name": "laptop\n\x1b[31m\u{202e}", "ignored_secret": "private-payload",
    }));
    fixture.append(json!({ "event": "service_default_enabled", "service": "shell" }));
    fixture.append(json!({
        "event": "connected", "direction": "inbound", "service": "shell",
        "peer_id": peer_id, "pid": 42, "session": 7,
    }));
    fixture.append(json!({
        "event": "connection_failed", "direction": "outbound", "service": "tcp:4000",
        "peer_name": "laptop", "reason": "service_not_enabled",
    }));
    let output = fixture.command().output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let profile = Sha256::digest(
        fixture
            .dir
            .path()
            .canonicalize()
            .unwrap()
            .as_os_str()
            .as_encoded_bytes(),
    );
    let profile = format!("{profile:x}");
    assert!(
        stdout.contains(&format!("MASSRELAY_PROFILE={}", &profile[..16])),
        "{stdout}"
    );
    assert!(stdout.contains("the runtime started"), "{stdout}");
    assert!(
        stdout.contains(r#"[audit] approval granted peer "laptop\n\u{1b}[31m\u{202e}""#),
        "{stdout}"
    );
    assert!(
        stdout.contains("[audit] service default enabled shell"),
        "{stdout}"
    );
    assert!(
        stdout.contains("[audit] connected inbound shell peer 01234567 [session 42/7]"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            r#"[audit] connection failed outbound tcp:4000 peer "laptop" — service not enabled"#
        ),
        "{stdout}"
    );
    for hidden in [&*peer_id, "private-payload", "\x1b", "\u{202e}"] {
        assert!(!stdout.contains(hidden), "{stdout}");
    }
}

#[tokio::test]
async fn follows_native_output_and_an_audit_created_after_start() {
    let fixture = Fixture::new(
        "[ \"$6\" = --follow ] || exit 2\nprintf 'the runtime started %s\\n' \"$$\"\nexec /bin/sleep 10",
    );
    let mut command = tokio::process::Command::from(fixture.command());
    let mut process = command
        .arg("--follow")
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(process.stdout.take().unwrap()).lines();
    let native_pid = tokio::time::timeout(Duration::from_secs(5), async {
        let native = stdout.next_line().await.unwrap().unwrap();
        let native_pid = native.strip_prefix("the runtime started ").unwrap();
        fixture
            .append(json!({ "event": "connected", "direction": "outbound", "service": "shell" }));
        let live = stdout.next_line().await.unwrap().unwrap();
        assert!(live.ends_with("[audit] connected outbound shell"), "{live}");
        native_pid.parse::<u32>().unwrap()
    })
    .await
    .unwrap();
    // Force a broken pipe on the next audit event. The native tool should be reaped.
    drop(stdout);
    fixture.append(json!({ "event": "disconnected", "direction": "outbound", "service": "shell" }));
    let status = tokio::time::timeout(Duration::from_secs(5), process.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success(), "{status}");
    assert!(!Path::new("/proc").join(native_pid.to_string()).exists());
}

#[test]
fn custom_audit_replaces_defaults_and_errors_leave_history_available() {
    let fixture = Fixture::new("exit 0");
    let custom = fixture.dir.path().join("custom.jsonl");
    fixture.append(json!({ "event": "approval_granted" }));
    append(
        &custom,
        json!({ "event": "service_enabled", "service": "shell" }),
    );
    let output = fixture
        .command()
        .arg("--log-file")
        .arg(&custom)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("[audit] service enabled shell"), "{stdout}");
    assert!(!stdout.contains("approval granted"), "{stdout}");

    let output = fixture
        .command()
        .arg("--log-file")
        .arg(fixture.dir.path().join("missing"))
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("read connection audit")
    );

    let output = fixture
        .command()
        .arg("--log-file")
        .arg(fixture.dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("expected a regular file")
    );

    fs::remove_file(fixture.dir.path().join("journalctl")).unwrap();
    for follow in [false, true] {
        let mut command = fixture.command();
        if follow {
            command.arg("--follow");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success(), "{output:?}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("[audit] approval granted")
        );
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("journalctl was not found")
        );
    }
}
