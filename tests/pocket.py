"""Exercise three MassRelay devices using isolated state and loopback ports."""

import errno
import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def eventually(check, description, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.15)
    raise AssertionError(f"timed out: {description}")


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def exercise(binary, root):
    processes = []

    def args(state, *command):
        return [binary, "--state-dir", str(root / state), *command]

    def cli(state, *command, ticket=None, check=True):
        return subprocess.run(
            args(state, *command), input=ticket, capture_output=True,
            text=True, check=check, timeout=35,
        )

    def start(state, *command):
        with (root / f"{state}.log").open("a") as log:
            process = subprocess.Popen(
                args(state, *command), stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            )
        processes.append(process)
        return process

    def rows(state):
        peers = cli(state, "peers", check=False)
        if peers.returncode:
            return {}
        return {row.split()[0]: row.split("\t")[1:3] for row in peers.stdout.splitlines()[1:]}

    def paired(left, right):
        return all(
            rows(a).get(b, ["", ""])[1] == "paired"
            for a, b in [(left, right), (right, left)]
        )

    def terminal(source, target, allowed, during=None):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        proc = subprocess.Popen(
            args(source, "shell", target), stdin=slave, stdout=slave, stderr=slave,
        )
        os.close(slave)
        output = bytearray()
        try:
            deadline = time.monotonic() + 28
            sent = False
            interrupted = False
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        data = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not data:
                        break
                    output.extend(data)
                    if allowed and not sent:
                        # Split the marker so terminal echo alone cannot satisfy the test.
                        command = b"printf '%s%s\\n' MASSRELAY_ SMOKE; stty size; "
                        os.write(master, command + (b"read WAIT\r" if during else b"exit 7\r"))
                        sent = True
                    if during and not interrupted and b"MASSRELAY_SMOKE" in output:
                        during()
                        interrupted = True
                if proc.poll() is not None and not ready:
                    break
            code = proc.wait(timeout=2)
            if during:
                assert interrupted and code == 1 and b"24 80" in output, output
            elif allowed:
                assert code == 7 and b"MASSRELAY_SMOKE" in output and b"24 80" in output, output
            else:
                assert code == 1 and b"MASSRELAY_SMOKE" not in output, output
        finally:
            os.close(master)
            stop(proc)

    def run_peer(name):
        # Explicit shell avoids invoking the host user's login startup files.
        return start(name, "run", "--allow-shell", "--shell", "/bin/sh", "--bind", "127.0.0.1:0")

    def approve(source, target):
        # Use the key printed on the destination, as a scripted approval would.
        log = (root / f"{target}.log").read_text()
        key = log.rsplit("MassRelay running as ", 1)[1].splitlines()[0]
        cli(source, "approve", key)

    udp = f"127.0.0.1:{free_port(socket.SOCK_DGRAM)}"
    tcp = f"127.0.0.1:{free_port(socket.SOCK_STREAM)}"
    try:
        create = cli("relay", "relay-init", "--public-udp", udp, "--url", f"http://{tcp}").stdout
        relay = start("relay", "relay", "--udp-bind", udp, "--relay-bind", tcp)
        eventually(lambda: "listening" in (root / "relay.log").read_text(), "relay up")
        cli("a", "create", "a", ticket=create)
        a = run_peer("a")
        eventually(lambda: cli("a", "peers", check=False).returncode == 0, "device a up")

        invite = cli("a", "invite").stdout
        cli("b", "join", "b", ticket=invite)
        assert cli("replay", "join", "replay", ticket=invite, check=False).returncode == 1
        b = run_peer("b")
        eventually(lambda: "a" in rows("b"), "device b up")
        # B can enroll while the network founder is absent.
        stop(a)
        cli("c", "join", "c", ticket=cli("b", "invite").stdout)
        run_peer("a")
        run_peer("c")
        eventually(lambda: set(rows("a")) == {"b", "c"} and set(rows("c")) == {"a", "b"}, "visible roster")
        eventually(lambda: all(row[0] == "recent" for row in rows("a").values()), "peer presence")

        approve("a", "b")
        terminal("a", "b", False)
        approve("b", "a")
        approve("b", "c")
        approve("c", "b")
        approve("a", "c")
        cli("c", "decline", "a")
        eventually(lambda: paired("a", "b") and paired("b", "c"), "two approved pairs")

        for source, target in [("a", "b"), ("b", "a"), ("b", "c"), ("c", "b")]:
            terminal(source, target, True)
        terminal("a", "c", False)
        terminal("c", "a", False)

        stop(relay)
        stop(b)
        run_peer("b")
        eventually(lambda: bool(rows("b")), "device b restarted without relay")
        terminal("a", "b", True)
        cli("a", "decline", "b")
        terminal("b", "a", False)
        relay = start("relay", "relay", "--udp-bind", udp, "--relay-bind", tcp)
        eventually(lambda: relay.poll() is None and rows("a").get("b", [""])[0] == "recent", "relay restarted")
        approve("a", "b")
        terminal("a", "b", False)
        approve("b", "a")
        eventually(lambda: paired("a", "b"), "fresh mutual approval after offline decline")
        terminal("a", "b", True)
        terminal("c", "b", True, during=lambda: cli("b", "revoke", "c"))
        eventually(lambda: "c" not in rows("a"), "revocation reached peer")
        terminal("b", "c", False)
        terminal("c", "b", False)

        print("Three-device pocket network passed")
    except Exception:
        for path in root.glob("*.log"):
            print(f"\n{path.name}\n{path.read_text()}", file=sys.stderr)
        raise
    finally:
        for process in reversed(processes):
            stop(process)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="massrelay-test-") as directory:
        exercise(str(Path(sys.argv[1]).resolve()), Path(directory))
