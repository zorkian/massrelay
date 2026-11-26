"""Exercise private discovery through the real CLI on loopback.

Build with the off-by-default feature, then run:

    cargo build --features private-membership
    python3 tests/private.py target/debug/massrelay

Every relay, device and key is throwaway, in a temporary directory, on 127.0.0.1. Nothing here
says anything about deployment, HTTPS or platform durability.
"""

import base64
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from pocket import (  # noqa: E402
    TcpTarget, UdpTarget, echo, eventually, free_port, read_exactly, read_line, stop,
)


def exercise(binary, root):
    processes = []
    try:
        _exercise(binary, root, processes)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                try:
                    os.kill(process.pid, signal.SIGCONT)
                except OSError:
                    pass
            stop(process)


def _exercise(binary, root, processes):
    inherited = {k: v for k, v in os.environ.items() if not k.startswith("MASSRELAY_")}

    def args(state, *command):
        return [binary, "--state-dir", str(root / state), *command]

    def cli(state, *command, data=None, check=True):
        result = subprocess.run(
            args(state, *command), input=data, capture_output=True, text=True,
            timeout=90, env=inherited,
        )
        if check:
            assert result.returncode == 0, (command, result.stdout, result.stderr)
        return result

    def private(state, *command, **kwargs):
        return cli(state, "private", *command, **kwargs)

    def start(state, *command):
        log = (root / f"{state}.log").open("a")
        process = subprocess.Popen(
            args(state, *command), stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            env=inherited,
        )
        processes.append(process)
        return process

    def popen(state, *command):
        process = subprocess.Popen(
            args(state, "private", *command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=inherited, bufsize=0,
        )
        processes.append(process)
        return process

    def finish(process):
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            assert process.wait(timeout=30) == 0, (root / "log").name

    def run(state):
        process = start(
            state, "private", "run", "--shell", "/bin/sh", "--bind", "127.0.0.1:0",
            "--sync-every", "1",
        )
        eventually(
            lambda: "private runtime running as" in (root / f"{state}.log").read_text(),
            f"{state} runtime started",
        )
        return process

    def key(state):
        line = [l for l in private(state, "status").stdout.splitlines() if l.startswith("Endpoint:")]
        return line[0].split()[1]

    def status(state):
        return private(state, "status").stdout

    def peers(state):
        rows = private(state, "peers").stdout.splitlines()
        assert rows[0].split("\t") == ["ENDPOINT", "ALIAS", "MEMBER", "LOCAL", "REMOTE", "PAIRED"]
        return {row.split("\t")[0]: row.split("\t")[1:] for row in rows[1:]}

    def members(state):
        return {k for k, row in peers(state).items() if row[1] == "yes"}

    def terminal(source, target, allowed):
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            args(source, "private", "shell", target), stdin=slave, stdout=slave, stderr=slave,
            env=inherited,
        )
        os.close(slave)
        output = bytearray()
        sent = False
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    output.extend(data)
                    if allowed and not sent:
                        # Split the marker so terminal echo alone cannot satisfy the check.
                        os.write(master, b"printf '%s%s\\n' PRIVATE_ SMOKE; exit 7\r")
                        sent = True
                if proc.poll() is not None and not ready:
                    break
            code = proc.wait(timeout=5)
        finally:
            os.close(master)
            stop(proc)
        if allowed:
            assert code == 7 and b"PRIVATE_SMOKE" in output, (code, bytes(output))
        else:
            assert code == 1 and b"PRIVATE_SMOKE" not in output, (code, bytes(output))
            assert b"refus" in output.lower() or b"not " in output.lower(), bytes(output)
        return bytes(output)

    def open_shell(source, target):
        """A live private shell that has proven it runs; returns the process and its terminal."""
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            args(source, "private", "shell", target), stdin=slave, stdout=slave, stderr=slave,
            env=inherited,
        )
        os.close(slave)
        processes.append(proc)
        output = bytearray()
        os.write(master, b"printf '%s%s\\n' LIVE_ SHELL\r")
        deadline = time.monotonic() + 30
        while b"LIVE_SHELL" not in output and time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                output.extend(os.read(master, 65536))
        assert b"LIVE_SHELL" in output, bytes(output)
        return proc, master

    def forward(source, target, service, data=b""):
        # A UDP forward listens on an ephemeral port: the target holds the service's port here.
        extra = ("--listen", "0") if service.startswith("udp:") else ()
        return subprocess.run(
            args(source, "private", "connect", target, service, *extra), input=data,
            capture_output=True, timeout=60, env=inherited,
        )

    def refused(source, target, service):
        result = forward(source, target, service, b"unsent")
        assert result.returncode == 1 and not result.stdout, result
        assert b"refused" in result.stderr.lower(), result.stderr
        return result.stderr.decode()

    def envelope(text):
        body = text.strip().removeprefix("mrprivinv0_")
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))

    def seal(value):
        raw = base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
        return "mrprivinv0_" + raw

    def locator(text):
        body = text.strip().removeprefix("mrprivx1_")
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))

    def encode_locator(value):
        raw = base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
        return "mrprivx1_" + raw

    udp, tcp = free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_STREAM)
    advertised = ("--public-udp", f"127.0.0.1:{udp}", "--url", f"http://127.0.0.1:{tcp}")
    binds = ("--udp-bind", f"127.0.0.1:{udp}", "--relay-bind", f"127.0.0.1:{tcp}")
    relay_locator = cli("relay", "private-relay-init", *advertised).stdout.strip()

    def log_count(state, text):
        path = root / f"{state}.log"
        return path.read_text().count(text) if path.exists() else 0

    def start_relay(state="relay"):
        before = log_count(state, "private relay listening")
        process = start(state, "private-relay", *binds)
        eventually(
            lambda: log_count(state, "private relay listening") > before,
            "private relay started",
        )
        return process

    def stop_relay(process):
        stop(process)
        eventually(lambda: process.poll() is not None, "relay stopped")
        with socket.socket() as probe:
            assert probe.connect_ex(("127.0.0.1", tcp)) != 0, "the relay port still accepts"

    relay = start_relay()

    # ------------------------------------------------------------ operator admission
    # A locator whose access credential the operator never granted is refused by the relay
    # before any profile is saved; the running relay logs no credential.
    forged = locator(relay_locator)
    forged["access"] = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    intruder = private(
        "intruder", "create", "--relay", encode_locator(forged), "--bind", "127.0.0.1:0",
        check=False,
    )
    assert intruder.returncode == 1 and "access credential" in intruder.stderr, intruder
    assert not (root / "intruder" / "private-experimental-0" / "private-device.json").exists()
    assert locator(relay_locator)["access"] not in (root / "relay.log").read_text()
    busy = cli("relay", "private-relay-access", "list", check=False)
    assert busy.returncode == 0, busy  # listing reads only; changes need the relay stopped
    busy = cli("relay", "private-relay-access", "issue", check=False)
    assert busy.returncode == 1 and "in use" in busy.stderr, busy

    # ------------------------------------------------------------ create and join
    private("a", "create", "--bind", "127.0.0.1:0", data=relay_locator + "\n")
    assert (root / "a" / "private-experimental-0" / "private-device.json").exists()
    assert not (root / "a" / "device.json").exists(), "no legacy profile is written"
    again = private("a", "create", "--relay", relay_locator, check=False)
    assert again.returncode == 1 and "already" in again.stderr, again
    # Management needs the running owner; nothing mutates the profile from outside it.
    offline = private("a", "invite", check=False)
    assert offline.returncode == 1 and "start it in the foreground" in offline.stderr, offline
    assert "Runtime: not running" in status("a")

    run_a = run("a")
    # A duplicate must refuse ownership before trying to bind, even when its port is occupied.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
        occupied.bind(("127.0.0.1", 0))
        bind = f"127.0.0.1:{occupied.getsockname()[1]}"
        second = private("a", "run", "--bind", bind, check=False)
    assert second.returncode == 1 and "already running" in second.stderr, second

    # An envelope whose locator names another relay or incarnation than its invite is refused
    # before anything is sent or saved.
    other_relay = locator(cli("other-relay", "private-relay-init", *advertised).stdout)
    invite = private("a", "invite").stdout.strip()
    assert invite.startswith("mrprivinv0_") and invite not in (root / "a.log").read_text()
    for field in ["server", "incarnation"]:
        swapped = envelope(invite)
        swapped["locator"][field] = other_relay[field]
        refusal = private("wrong", "join", "--bind", "127.0.0.1:0", data=seal(swapped), check=False)
        assert refusal.returncode == 1 and "nothing was sent" in refusal.stderr, refusal
        assert not (root / "wrong" / "private-experimental-0" / "private-device.json").exists()

    # The same invite, unchanged, admits b: the running issuer reserves the request, stages,
    # publishes and settles the Add, and dispatches the sealed reply.
    joined = private("b", "join", "--bind", "127.0.0.1:0", data=invite + "\n")
    assert "joined the private network" in joined.stderr.lower(), joined.stderr
    a, b = key("a"), key("b")
    assert joined.stdout.strip() == b
    resumed = private("b", "join", check=False)
    assert resumed.returncode == 1 and "already a member" in resumed.stderr
    # A used invite admits nobody else.
    reused = private("x", "join", "--bind", "127.0.0.1:0", data=invite + "\n", check=False)
    assert reused.returncode == 1 and "used by another device" in reused.stderr, reused
    run_b = run("b")
    eventually(lambda: members("a") == {b} and members("b") == {a}, "a and b see each other")

    # ------------------------------------------------------ pairing and services
    # Unapproved: refused, and nothing is paired.
    terminal("b", a, False)
    private("a", "approve", b, "--as", "bob")
    terminal("b", a, False)
    private("b", "approve", a, "--as", "alice")
    # Mutually approved, but no grant: refused; the attempt completes the pairing.
    terminal("b", "alice", False)
    eventually(lambda: peers("a")[b][4] == "yes", "a paired with b")
    alias = private("a", "approve", b, "--as", b, check=False)
    assert alias.returncode == 1 and "must not look like an endpoint key" in alias.stderr
    unknown = private("a", "enable", "shell", "carol", check=False)
    assert unknown.returncode == 1 and "no peer pinned" in unknown.stderr

    private("a", "enable", "shell", "bob")
    terminal("b", "alice", True)

    echo_target, other_target = TcpTarget(echo), TcpTarget(echo)
    tcp_service, other_service = f"tcp:{echo_target.port}", f"tcp:{other_target.port}"
    refused("b", "alice", tcp_service)
    private("a", "enable", tcp_service, "bob")
    payload = os.urandom(256 * 1024)
    result = forward("b", "alice", tcp_service, payload)
    assert result.returncode == 0 and result.stdout == payload, result.stderr
    # A grant covers one exact service.
    refused("b", "alice", other_service)
    assert other_target.accepted == 0

    udp_target = UdpTarget()
    udp_service = f"udp:{udp_target.port}"
    refused("b", "alice", udp_service)
    private("a", "enable", udp_service, "bob")
    datagrams = popen("b", "connect", "alice", udp_service, "--listen", "0")
    line = read_line(datagrams.stderr, "send datagrams to")
    local = int(line.strip().rsplit(":", 1)[1])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.settimeout(15)
        for size in [0, 1, 1400, 9000]:
            datagram = os.urandom(size)
            sender.sendto(datagram, ("127.0.0.1", local))
            assert sender.recv(65536) == datagram
    private("a", "disable", udp_service, "bob")
    assert datagrams.wait(timeout=20) == 1
    refused("b", "alice", udp_service)

    # A default covers paired peers unless excluded; disabling a peer excludes it.
    refused("b", "alice", other_service)
    private("a", "enable", other_service)
    assert forward("b", "alice", other_service, b"default").stdout == b"default"
    private("a", "disable", other_service, "bob")
    refused("b", "alice", other_service)
    assert f"Excluded from default: {other_service} for {b}" in status("a")
    private("a", "disable", "shell", "bob")
    terminal("b", "alice", False)
    private("a", "enable", "shell", "bob")
    terminal("b", "alice", True)

    # The native shell/TCP/UDP test establishes direct routes with the mailbox
    # offline. This CLI fixture uses relay discovery, so a previous call alone
    # says nothing about whether Iroh has negotiated a direct path.
    stop_relay(relay)
    assert b in status("a")
    assert a in status("b")
    relay = start_relay()

    # ------------------------------- stop while a relay call stalls and a shell is live
    # The relay process is frozen, so the issuer's next membership call stalls on its open
    # loopback mailbox connection. Stopping the runtime wakes that call, ends the live shell
    # into it, releases the profile and exits cleanly; the runtime then starts again at once.
    shell, master = open_shell("b", "alice")
    os.kill(relay.pid, signal.SIGSTOP)
    try:
        time.sleep(3)  # at least two pass intervals: a membership call is now in flight
        stopping = time.monotonic()
        run_a.send_signal(signal.SIGINT)
        assert run_a.wait(timeout=60) == 0
        stop_seconds = time.monotonic() - stopping
        log = (root / "a.log").read_text()
        shutdown_log = log.rsplit("Press Ctrl-C to stop.", 1)[1].strip()
        assert "stopped without waiting for" not in shutdown_log, shutdown_log
        assert "the profile is released" in shutdown_log, log
        assert shell.wait(timeout=30) != 0, "the live shell ended with its runtime"
        os.close(master)
        assert "Runtime: not running" in status("a")
        run_a = run("a")
    finally:
        os.kill(relay.pid, signal.SIGCONT)
    print(f"Stopped with a stalled relay call in {stop_seconds:.1f}s; owner released")
    print(f"  runtime said: {shutdown_log!r}")
    terminal("b", "alice", True)

    # ---------------------------------------------- membership propagation
    invite_c = private("b", "invite").stdout.strip()
    joined_c = private("c", "join", invite_c, "--bind", "127.0.0.1:0")
    c = joined_c.stdout.strip()
    run_c = run("c")
    eventually(lambda: members("a") == {b, c}, "a learns c, admitted by b", seconds=60)
    eventually(lambda: members("c") == {a, b}, "c sees a and b", seconds=60)
    private("a", "approve", c, "--as", "carol")
    private("c", "approve", a, "--as", "alice")
    terminal("c", "alice", False)
    private("a", "enable", "shell", "carol")
    terminal("c", "alice", True)

    # ---------------------------------------------------------------- cutoff
    session = popen("b", "connect", "alice", tcp_service)
    session.stdin.write(b"live\0\xff")
    assert read_exactly(session.stdout, 6) == b"live\0\xff"
    cut = private("a", "revoke", "bob")
    assert "Cut off locally" in cut.stdout, cut
    assert session.wait(timeout=20) == 1, "the open session ended at the cutoff"
    # A cut-off peer's dial is closed by the destination during the pairing exchange; the
    # dialer reports either the refusal or the lost stream, and never reaches the target.
    reached = echo_target.accepted
    result = forward("b", "alice", tcp_service, b"unsent")
    assert result.returncode == 1 and not result.stdout, result
    message = result.stderr.lower()
    assert b"refused" in message or b"connection lost" in message, result.stderr
    assert echo_target.accepted == reached
    terminal("b", "alice", False)
    eventually(lambda: members("c") == {a}, "c learns b's removal", seconds=60)
    eventually(lambda: "this device was removed" in status("b"), "b learns its removal", seconds=60)

    # --------------------------------- halt on a relay serving another incarnation
    # A periodic backup is never complete, so restoring it keeps the relay identity and
    # grants but starts a new incarnation. The pinned relay's authenticated answer halts
    # membership; nothing is repaired or re-seeded.
    stop_relay(relay)
    backup = root / "relay-backup"
    cli("relay", "private-relay-store", "check")
    cli("relay", "private-relay-store", "backup", "--to", str(backup))
    relay_id = json.loads((backup / "manifest.json").read_text())["relay"]
    kept = cli(
        "restored", "private-relay-store", "restore", "--from", str(backup), "--relay",
        relay_id, "--keep-incarnation", check=False,
    )
    assert kept.returncode == 1 and "not complete" in kept.stderr, kept
    cli("restored", "private-relay-store", "restore", "--from", str(backup), "--relay", relay_id)
    relay = start_relay("restored")
    eventually(lambda: "Membership: halted" in status("a"), "a halts", seconds=60)
    eventually(lambda: "Membership: halted" in status("c"), "c halts", seconds=60)
    # Verified pairs keep working through a halt; membership changes do not.
    terminal("c", "alice", True)
    halted_invite = private("a", "invite", check=False)
    assert halted_invite.returncode == 1, halted_invite

    for process in [run_a, run_b, run_c]:
        finish(process)
    stop(relay)
    assert "Runtime: not running" in status("a")
    print("Private discovery end to end passed")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="massrelay-private-test-") as directory:
        root = Path(directory)
        try:
            exercise(str(Path(sys.argv[1]).resolve()), root)
        except Exception:
            for path in sorted(root.glob("*.log")):
                print(f"\n{path.name}\n{path.read_text()}", file=sys.stderr)
            raise
