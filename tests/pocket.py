"""Exercise MassRelay relays and devices using isolated state and loopback ports."""

import base64
import errno
import fcntl
import json
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
    inherited = {k: v for k, v in os.environ.items() if not k.startswith("MASSRELAY_")}

    def args(state, *command):
        return [binary, "--state-dir", str(root / state), *command]

    def cli(state, *command, ticket=None, check=True, env=None):
        return subprocess.run(
            args(state, *command), input=ticket, capture_output=True,
            text=True, check=check, timeout=35, env={**inherited, **(env or {})},
        )

    def start(state, *command):
        with (root / f"{state}.log").open("a") as log:
            process = subprocess.Popen(
                args(state, *command), stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                env=inherited,
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

    def endpoint_id(state):
        log = (root / f"{state}.log").read_text()
        return log.rsplit("MassRelay running as ", 1)[1].splitlines()[0]

    def approve(source, target):
        # Use the key printed on the destination, as a scripted approval would.
        cli(source, "approve", endpoint_id(target))

    def addresses():
        return (
            f"127.0.0.1:{free_port(socket.SOCK_DGRAM)}",
            f"127.0.0.1:{free_port(socket.SOCK_STREAM)}",
        )

    def operator_ticket_relay():
        udp, tcp = addresses()
        advertised = ("--public-udp", udp, "--url", f"http://{tcp}")
        create = cli("relay", "relay-init", *advertised).stdout

        # State saved by an earlier version has no mode field, and stays ticket-only.
        state_file = root / "relay" / "relay.json"
        saved = json.loads(state_file.read_text())
        del saved["shared"]
        state_file.write_text(json.dumps(saved))
        assert cli("relay", "relay", *advertised, "--udp-bind", udp, "--relay-bind", tcp,
                   check=False).returncode == 1
        assert cli("relay", "relay-info", check=False).returncode == 1

        relay = start("relay", "relay", "--udp-bind", udp, "--relay-bind", tcp)
        eventually(lambda: "listening" in (root / "relay.log").read_text(), "relay up")
        # Even someone who builds this relay's locator cannot create a network without a ticket.
        encoded = create.strip().removeprefix("mr1_")
        padded = encoded + "=" * (-len(encoded) % 4)
        server = json.loads(base64.urlsafe_b64decode(padded))["server"]
        packed = base64.urlsafe_b64encode(json.dumps(server).encode()).decode()
        locator = "mrrelay1_" + packed.rstrip("=")
        refused = cli("stranger", "create", "--relay", locator, check=False)
        assert refused.returncode == 1 and not refused.stdout, refused
        assert "operator creation ticket" in refused.stderr, refused.stderr

        # A configured shared locator does not change the ticket form.
        cli("a", "create", "a", ticket=create, env={"MASSRELAY_RELAY": locator})
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

    def shared_relay():
        udp, tcp = addresses()
        advertised = ("--public-udp", udp, "--url", f"http://{tcp}")
        binds = ("--udp-bind", udp, "--relay-bind", tcp)
        log = root / "shared.log"
        starts = 0

        def start_shared(*extra):
            nonlocal starts
            process = start("shared", "relay", *binds, *extra)
            starts += 1
            eventually(lambda: log.read_text().count("listening") == starts, "shared relay up")
            return process

        def state(name, filename="device.json"):
            return json.loads((root / name / filename).read_text())

        relay = start_shared(*advertised)
        locator = cli("shared", "relay-info").stdout.strip()
        assert locator.startswith("mrrelay1_"), locator
        assert f"Shared relay locator (public): {locator}\n" in log.read_text()

        # The first device needs neither a ticket nor a daemon. Stdout holds only the invite.
        made = cli("s1", "create", "--relay", locator, env={"HOSTNAME": "First Host.example.test"})
        invite = made.stdout.strip()
        assert made.stdout == f"{invite}\n" and invite.startswith("mr1_"), made.stdout
        assert "First-Host" in made.stderr, made.stderr

        # Reproduce the client's state after a lost reply, then restart the relay and retry.
        first = state("s1")
        pending_file = root / "s1" / "pending-device.json"
        pending_file.write_text(json.dumps(first["identity"]))
        (root / "s1" / "device.json").unlink()
        stop(relay)
        relay = start_shared()
        other = cli("t1", "create", "--name", "First-Host", env={"MASSRELAY_RELAY": locator}).stdout

        # An older pending file has no proof that the supplied invite is the original one.
        legacy_retry = cli("s1", "join", other.strip(), "--name", "wrong", check=False)
        assert legacy_retry.returncode == 1 and not (root / "s1" / "device.json").exists()
        pending_file.write_text(json.dumps(dict(first["identity"], operation="SharedCreate")))
        wrong_network = cli("s1", "join", other.strip(), "--name", "wrong", check=False)
        assert wrong_network.returncode == 1, wrong_network.stdout
        assert not (root / "s1" / "device.json").exists()
        retried = cli("s1", "create", env={"MASSRELAY_RELAY": locator})
        assert retried.stdout == made.stdout, "retry changed the first invite"
        assert state("s1")["roster"]["network"] == first["roster"]["network"]
        assert len(state("shared", "relay.json")["networks"]) == 2

        # A hostname collision explains the remedy and does not spend the invite.
        clash = cli("s2", "join", invite, env={"HOSTNAME": "first-host"}, check=False)
        assert clash.returncode == 1 and "--name" in clash.stderr, clash.stderr
        cli("s2", "join", invite, env={"HOSTNAME": "Second.local"})
        assert cli("replay2", "join", invite, "--name", "replay", check=False).returncode == 1

        # Another network on the same relay may reuse names. A name that resembles a token still works.
        cli("t2", "join", "mr1_second", ticket=other)

        for name in ["s1", "s2", "t1", "t2"]:
            run_peer(name)
        eventually(
            lambda: set(rows("s1")) == {"Second"} and set(rows("s2")) == {"First-Host"},
            "first roster",
        )
        eventually(
            lambda: set(rows("t1")) == {"mr1_second"} and set(rows("t2")) == {"First-Host"},
            "second roster",
        )

        # A definitive rejection of a spent invite allows a replacement in the same profile.
        assert cli("t3", "join", other.strip(), "--name", "third", check=False).returncode == 1
        cli("t3", "join", "--name", "third", ticket=cli("t2", "invite").stdout)
        eventually(lambda: set(rows("t1")) == {"mr1_second", "third"}, "second network grew")
        assert set(rows("s1")) == {"Second"}

        # Knowing another network's endpoint ID gives no way to pair with it or revoke it.
        for command in ["approve", "revoke"]:
            refused = cli("s1", command, endpoint_id("t1"), check=False)
            assert refused.returncode == 1 and "unknown peer" in refused.stderr, refused.stderr

        approve("s1", "s2")
        approve("s2", "s1")
        eventually(
            lambda: rows("s1").get("Second", ["", ""])[1] == "paired"
            and rows("s2").get("First-Host", ["", ""])[1] == "paired",
            "shared pair",
        )
        terminal("s1", "Second", True)

        # Restart keeps identity and membership, and never takes new advertised addresses.
        stop(relay)
        saved = (root / "shared" / "relay.json").read_bytes()
        other_udp, other_tcp = addresses()
        for changed in [
            ("--public-udp", other_udp, "--url", f"http://{tcp}"),
            ("--public-udp", udp, "--url", f"http://{other_tcp}"),
        ]:
            assert cli("shared", "relay", *binds, *changed, check=False).returncode == 1
        assert (root / "shared" / "relay.json").read_bytes() == saved
        assert cli("shared", "relay-info").stdout.strip() == locator
        relay = start_shared(*advertised)
        fresh = eventually(
            lambda: cli("s2", "invite", check=False).stdout.strip(), "invite after restart"
        )
        cli("t4", "join", fresh, "--name", "fourth")
        eventually(lambda: set(rows("s1")) == {"Second", "fourth"}, "membership after restart")
        assert set(rows("t1")) == {"mr1_second", "third"}

        print("Shared relay with isolated pocket networks passed")

    try:
        operator_ticket_relay()
        shared_relay()
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
