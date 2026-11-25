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
import threading
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


class TcpTarget:
    """A loopback TCP service that runs one handler thread for each connection."""

    def __init__(self, handler, host="127.0.0.1"):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        self.listener.bind((host, 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.accepted = 0
        self.handler = handler
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self.serve, args=(connection,), daemon=True).start()

    def serve(self, connection):
        with connection:
            try:
                self.handler(connection)
            except OSError:
                pass

    def close(self):
        self.listener.close()


def echo(connection):
    while data := connection.recv(65536):
        connection.sendall(data)


def read_all(connection):
    data = bytearray()
    while chunk := connection.recv(65536):
        data.extend(chunk)
    return bytes(data)


def reply_after_eof(connection):
    request = read_all(connection)
    connection.sendall(b"reply:" + request)


class UdpTarget:
    """A loopback UDP service that echoes each datagram and records who sent it."""

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65535)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.received = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                data, sender = self.socket.recvfrom(65536)
                self.received.append((data, sender))
                self.socket.sendto(data, sender)
            except OSError:
                return


def read_exactly(stream, size, seconds=15):
    deadline = time.monotonic() + seconds
    data = bytearray()
    while len(data) < size and time.monotonic() < deadline:
        if select.select([stream], [], [], 0.1)[0]:
            chunk = os.read(stream.fileno(), size - len(data))
            if not chunk:
                break
            data.extend(chunk)
    assert len(data) == size, f"expected {size} bytes, received {bytes(data[:200])!r}"
    return bytes(data)


def read_line(stream, containing, seconds=15):
    deadline = time.monotonic() + seconds
    data = bytearray()
    while time.monotonic() < deadline:
        if select.select([stream], [], [], 0.1)[0]:
            chunk = os.read(stream.fileno(), 1)
            if not chunk:
                break
            data.extend(chunk)
            if chunk == b"\n" and containing.encode() in data:
                return data.decode()
    raise AssertionError(f"no line containing {containing!r} in {bytes(data)!r}")


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

    def terminal(source, target, allowed, during=None, command="shell"):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        proc = subprocess.Popen(
            args(source, command, target), stdin=slave, stdout=slave, stderr=slave,
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
        opts = ("--log-file", str(root / f"{name}-connections.jsonl")) if name != "a" else ()
        return start(name, "run", "--shell", "/bin/sh", "--bind", "127.0.0.1:0", *opts)

    def connection_events(name, supervisor=False):
        if supervisor:
            path = root / f"{name}.log"
        elif name == "a":
            path = root / name / "connections.jsonl"
        else:
            path = root / f"{name}-connections.jsonl"
        data = path.read_text()
        assert "MASSRELAY_SMOKE" not in data
        return [json.loads(line) for line in data.splitlines() if not supervisor or line.startswith("{")]

    def recorded_session(local, peer, direction, exit_code=None, supervisor=False):
        events = [
            event for event in connection_events(local, supervisor)
            if event.get("direction") == direction
            and event["peer_id"] == endpoint_id(peer)
            and event["peer_name"] == peer
        ]
        opened = {(event["pid"], event["session"]) for event in events if event["event"] == "connected"}
        return any(
            event["event"] == "disconnected"
            and (event["pid"], event["session"]) in opened
            and event.get("exit_code") == exit_code
            for event in events
        )

    def shell_refused(source, target, reason):
        # The log shows why a shell was refused, not just that it was.
        before = len(connection_events(source))
        terminal(source, target, False)
        eventually(
            lambda: any(
                event["event"] == "connection_failed" and event["direction"] == "outbound"
                and event.get("reason") == reason and event.get("service") == "shell"
                for event in connection_events(source)[before:]
            ),
            f"{source} to {target} refused for {reason}",
        )

    def grant(owner, peer, service="shell"):
        cli(owner, "enable", service, peer)

    def grants(state):
        lines = cli(state, "list", "--full").stdout.splitlines()
        assert lines[0] == "SERVICE\tPEER\tENDPOINT\tMODE\tTARGET", lines
        return [line.split("\t") for line in lines[1:]]

    def popen(state, *command):
        process = subprocess.Popen(
            args(state, *command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=inherited, bufsize=0,
        )
        processes.append(process)
        return process

    def finished(process, code, message=None):
        assert process.wait(timeout=15) == code, (process.returncode, process.stderr.read())
        error = process.stderr.read().decode()
        if message is None:
            assert not error, error
        else:
            assert message in error, error

    def forward(source, target, service, data=b""):
        return subprocess.run(
            args(source, "connect", target, service), input=data, capture_output=True,
            timeout=40, env=inherited,
        )

    def forward_refused(source, target, service, message):
        result = forward(source, target, service, b"unsent")
        assert result.returncode == 1 and not result.stdout, result
        assert message in result.stderr.decode(), result.stderr

    def stream(source, target, service):
        # An open session that has proven it can carry data both ways.
        process = popen(source, "connect", target, service)
        alive(process)
        return process

    def alive(process):
        process.stdin.write(b"ping\0\xff")
        assert read_exactly(process.stdout, 6) == b"ping\0\xff"

    def expose(owner, *command):
        process = popen(owner, "expose", *command)
        read_line(process.stderr, "Press Ctrl-C to stop.")
        return process

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

    def port_services(owner_process):
        """b owns the services. a and c are paired with b."""
        echo_one, echo_two = TcpTarget(echo), TcpTarget(echo)
        replying = TcpTarget(reply_after_eof)
        one, two = f"tcp:{echo_one.port}", f"tcp:{echo_two.port}"
        reply = f"tcp:{replying.port}"

        # Nothing is granted by pairing, and a refused request never reaches the target.
        forward_refused("a", "b", reply, f"{reply} is not enabled for this device")
        assert replying.accepted == 0

        grant("b", "A", reply)
        grant("b", endpoint_id("a"), reply)
        assert [row for row in grants("b") if row[0] == reply] == [
            [reply, "a", endpoint_id("a"), "persistent", f"loopback:{replying.port}"]
        ]
        # Binary data larger than any buffer survives, and EOF still allows a reply.
        payload = bytes(range(256)) * 512 + os.urandom(3 * 1024 * 1024)
        result = forward("a", "b", reply, payload)
        assert result.returncode == 0 and not result.stderr, result.stderr
        assert result.stdout == b"reply:" + payload
        result = forward("a", "b", reply)
        assert result.returncode == 0 and result.stdout == b"reply:", result

        # The grant covers one peer and one service.
        forward_refused("c", "b", reply, "is not enabled for this device")
        forward_refused("a", "b", one, f"{one} is not enabled for this device")
        assert replying.accepted == 2 and echo_one.accepted == 0
        # A port grant does not confer a shell, and removing a shell grant leaves ports alone.
        cli("b", "disable", "shell", "a")
        shell_refused("a", "b", "service_not_enabled")
        assert forward("a", "b", reply).returncode == 0

        closed = free_port(socket.SOCK_STREAM)
        grant("b", "a", f"tcp:{closed}")
        forward_refused("a", "b", f"tcp:{closed}", f"could not connect to loopback port {closed}")
        cli("b", "disable", f"tcp:{closed}", "a")

        # The target may finish sending first, while still receiving.
        received = []
        done = threading.Event()

        def greet(connection):
            connection.sendall(b"greeting")
            connection.shutdown(socket.SHUT_WR)
            received.append(read_all(connection))
            done.set()

        greeting = TcpTarget(greet)
        grant("b", "a", f"tcp:{greeting.port}")
        process = popen("a", "connect", "b", f"tcp:{greeting.port}")
        assert read_exactly(process.stdout, 8) == b"greeting"
        # Standard output reaches end of file while the command still accepts input.
        assert select.select([process.stdout], [], [], 15)[0]
        assert os.read(process.stdout.fileno(), 1) == b"" and process.poll() is None
        process.stdin.write(b"sent after the remote EOF")
        process.stdin.close()
        finished(process, 0)
        assert done.wait(10) and received == [b"sent after the remote EOF"]

        # Both directions move bulk data at the same time.
        grant("b", "a", one)
        bulk = os.urandom(8 * 1024 * 1024)
        result = forward("a", "b", one, bulk)
        assert result.returncode == 0 and result.stdout == bulk, (result.returncode, result.stderr)

        # A reset from the target is a failure, reported after what it already sent.
        def reset(connection):
            connection.recv(1)
            connection.sendall(b"partial")
            time.sleep(0.5)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))

        resetting = TcpTarget(reset)
        grant("b", "a", f"tcp:{resetting.port}")
        process = popen("a", "connect", "b", f"tcp:{resetting.port}")
        process.stdin.write(b"x")
        assert read_exactly(process.stdout, 7) == b"partial"
        finished(process, 1, f"forwarding tcp:{resetting.port} failed on the destination")
        resetting.close()

        # Loopback may be IPv6 only.
        try:
            ipv6 = TcpTarget(reply_after_eof, "::1")
        except OSError:
            print("IPv6 loopback unavailable; skipped")
        else:
            grant("b", "a", f"tcp:{ipv6.port}")
            result = forward("a", "b", f"tcp:{ipv6.port}", b"six")
            assert result.stdout == b"reply:six", result

        # Disabling closes matching sessions only, even with local input still open.
        grant("b", "a", two)
        grant("b", "c", one)
        a_one, a_two, c_one = stream("a", "b", one), stream("a", "b", two), stream("c", "b", one)
        cli("b", "disable", one, "a")
        finished(a_one, 1, f"access to {one} was removed on the destination")
        alive(a_two)
        alive(c_one)
        cli("b", "disable", one, "a")
        forward_refused("a", "b", one, "is not enabled")
        # A replacement grant does not carry over a session from the removed one.
        grant("b", "a", one)
        a_one = stream("a", "b", one)
        cli("b", "disable", one, "a")
        grant("b", "a", one)
        finished(a_one, 1, "was removed on the destination")
        alive(c_one)

        # Declining on either side ends the pair's forwarded sessions and grants.
        for decliner, other_side in [("b", "c"), ("c", "b")]:
            process = stream("c", "b", one)
            alive(a_two)
            cli(decliner, "decline", other_side)
            finished(process, 1, "pairing")
            alive(a_two)
            # The decline must reach the relay before either side can approve again.
            eventually(
                lambda: rows(other_side).get(decliner, ["", ""])[1] == "declined by peer",
                "decline reached peer",
            )
            approve("b", "c")
            approve("c", "b")
            eventually(lambda: paired("b", "c"), "paired again")
            assert all(row[1] != "c" for row in grants("b")), grants("b")
            forward_refused("c", "b", one, "is not enabled")
            grant("b", "c", one)
        c_one = stream("c", "b", one)
        for direction, node in [("inbound", "b"), ("outbound", "a")]:
            reasons = {
                (event["event"], event.get("reason"))
                for event in connection_events(node)
                if event.get("direction") == direction and event.get("service") == one
            }
            assert {("connected", None), ("disconnected", "grant_removed")} <= reasons, reasons

        # A lost local command ends its session without disturbing others.
        a_one = stream("a", "b", one)
        a_one.kill()
        a_one.wait(timeout=5)
        eventually(
            lambda: any(
                event["event"] == "disconnected" and event.get("service") == one
                and event.get("reason") == "peer_disconnected"
                for event in connection_events("b")
            ),
            "destination noticed the lost command",
        )

        # Exiting the CLI also closes a tunnel whose target has stopped reading.
        release_target = threading.Event()

        def stop_reading(connection):
            connection.sendall(b"ready")
            release_target.wait()

        stalled = TcpTarget(stop_reading)
        service = f"tcp:{stalled.port}"
        grant("b", "a", service)
        process = popen("a", "connect", "b", service)
        try:
            assert read_exactly(process.stdout, 5) == b"ready"
            fd = process.stdin.fileno()
            os.set_blocking(fd, False)
            deadline = time.monotonic() + 10
            while select.select([], [fd], [], 0.25)[1]:
                assert time.monotonic() < deadline, "target did not stall the connection"
                try:
                    os.write(fd, bytes(65536))
                except BlockingIOError:
                    pass
            process.kill()
            process.wait(timeout=5)
            eventually(
                lambda: any(
                    event["event"] == "disconnected" and event.get("service") == service
                    and event.get("reason") == "peer_disconnected"
                    for event in connection_events("b")
                ),
                "destination closed the stalled connection",
            )
        finally:
            release_target.set()
            stalled.close()

        # Persistent grants survive a restart.
        before = grants("b")
        stop(owner_process)
        finished(c_one, 1, "connection to the destination was lost")
        finished(a_two, 1, "connection to the destination was lost")
        owner_process = run_peer("b")
        eventually(lambda: cli("b", "list", check=False).returncode == 0, "owner restarted")
        assert grants("b") == before
        eventually(
            lambda: forward("a", "b", reply, b"again").stdout == b"reply:again",
            "grant after restart",
        )

        # Profiles saved before grants existed keep their pairing and grant nothing.
        stop(owner_process)
        profile = root / "b" / "device.json"
        saved = json.loads(profile.read_text())
        del saved["grants"]
        profile.write_text(json.dumps(saved))
        owner_process = run_peer("b")
        eventually(lambda: cli("b", "list", check=False).returncode == 0, "legacy profile up")
        assert grants("b") == []
        eventually(
            lambda: "is not enabled" in forward("a", "b", reply).stderr.decode(),
            "legacy profile denies",
        )
        assert paired("a", "b")

        exposures(owner_process)
        for state, event in [(s, e) for s in "abc" for e in connection_events(s)]:
            assert "greeting" not in json.dumps(event), (state, event)
        for target in [echo_one, echo_two, replying, greeting]:
            target.close()
        print("Per-peer services and one-off exposures passed")

    def exposures(owner_process):
        mapped, other = TcpTarget(echo), TcpTarget(echo)
        service = f"tcp:{free_port(socket.SOCK_STREAM)}"
        keep = f"tcp:{other.port}"
        grant("b", "a", keep)
        steady = stream("a", "b", keep)

        # A temporary grant maps the service to the owner's chosen address.
        lease = expose("b", "--tcp", service[4:], "--to", "a", f"localhost:{mapped.port}")
        row = [service, "a", endpoint_id("a"), "temporary", f"localhost:{mapped.port}"]
        assert row in grants("b"), grants("b")
        assert service not in (root / "b" / "device.json").read_text()
        live = stream("a", "b", service)
        assert mapped.accepted == 1
        forward_refused("c", "b", service, "is not enabled")
        for command, message in [
            (("enable", service, "a"), "currently exposed"),
            (("expose", "--tcp", service[4:], "--to", "a"), "already exposed"),
            (("expose", "--tcp", keep[4:], "--to", "a"), "already enabled"),
        ]:
            conflict = cli("b", *command, check=False)
            assert conflict.returncode == 1 and message in conflict.stderr, conflict
        assert row in grants("b")
        alive(live)

        # Ctrl-C removes the grant before the command exits, and closes only its sessions.
        lease.send_signal(signal.SIGINT)
        finished(lease, 0)
        assert all(grant_row[0] != service for grant_row in grants("b"))
        finished(live, 1, "was removed on the destination")
        forward_refused("a", "b", service, "is not enabled")
        alive(steady)

        # So does losing the command without any chance to clean up, or SIGTERM.
        for end in [signal.SIGKILL, signal.SIGTERM]:
            lease = expose("b", "--tcp", service[4:], "--to", "a", f"127.0.0.1:{mapped.port}")
            live = stream("a", "b", service)
            lease.send_signal(end)
            lease.wait(timeout=10)
            finished(live, 1, "was removed on the destination")
            assert all(grant_row[0] != service for grant_row in grants("b"))

        # Explicit disable stops the lease.
        lease = expose("b", "--tcp", service[4:], "--to", endpoint_id("a"), f"127.0.0.1:{mapped.port}")
        live = stream("a", "b", service)
        cli("b", "disable", service, "a")
        finished(lease, 1, "ended because it was disabled")
        finished(live, 1, "was removed on the destination")
        alive(steady)

        # With no address, an exposure forwards to loopback on the same port.
        lease = expose("b", "--tcp", str(mapped.port), "--to", "a")
        result = stream("a", "b", f"tcp:{mapped.port}")
        result.stdin.close()
        finished(result, 0)
        lease.send_signal(signal.SIGINT)
        finished(lease, 0)

        # A peer learns that an exposed address failed, but not what the address is.
        closed = free_port(socket.SOCK_STREAM)
        lease = expose("b", "--tcp", service[4:], "--to", "a", f"127.0.0.1:{closed}")
        result = forward("a", "b", service)
        error = result.stderr.decode()
        assert result.returncode == 1 and f"the {service} target" in error, error
        assert str(closed) not in error.replace(service, ""), error
        lease.send_signal(signal.SIGINT)
        finished(lease, 0)

        udp_services()

        # Ending the pairing ends an exposure, and a new pairing does not restore it.
        lease = expose("b", "--tcp", service[4:], "--to", "a", f"127.0.0.1:{mapped.port}")
        live = stream("a", "b", service)
        cli("a", "decline", "b")
        finished(lease, 1, "the pairing changed")
        finished(live, 1, "pairing")
        eventually(
            lambda: rows("b").get("a", ["", ""])[1] == "declined by peer", "decline reached owner"
        )
        approve("a", "b")
        approve("b", "a")
        eventually(lambda: paired("a", "b"), "paired after exposure")
        forward_refused("a", "b", service, "is not enabled")
        grant("b", "a", keep)
        steady = stream("a", "b", keep)

        # Stopping the daemon ends its exposures.
        lease = expose("b", "--tcp", service[4:], "--to", "a", f"127.0.0.1:{mapped.port}")
        stop(owner_process)
        finished(lease, 1, "daemon stopped")
        finished(steady, 1, "connection to the destination was lost")
        run_peer("b")
        eventually(lambda: cli("b", "list", check=False).returncode == 0, "owner back")
        assert all(grant_row[3] == "persistent" for grant_row in grants("b"))
        for target in [mapped, other]:
            target.close()

    def udp_services():
        target = UdpTarget()
        port = free_port(socket.SOCK_DGRAM)
        service = f"udp:{port}"
        denied = cli("a", "connect", "b", service, check=False)
        assert denied.returncode == 1, denied
        assert f"massrelay expose --udp {port} --to a" in denied.stderr, denied.stderr

        lease = expose("b", "--udp", str(port), "--to", "a", f"127.0.0.1:{target.port}")

        def consumer(*extra):
            process = popen("a", "connect", "b", service, *extra)
            line = read_line(process.stderr, "send datagrams to")
            host, local = line.strip().rsplit(" ", 1)[1].rsplit(":", 1)
            assert host == "127.0.0.1", line
            return process, int(local)

        # The default local port is the service's port.
        process, local = consumer()
        assert local == port
        process.send_signal(signal.SIGINT)
        process.wait(timeout=5)

        process, local = consumer("--listen", "0")
        senders = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
        for sender in senders:
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65535)
            sender.settimeout(10)
        sizes = [0, 1, 1400, 9217, 65507, 0, 3]
        for size in sizes:
            for sender in senders:
                datagram = os.urandom(size)
                sender.sendto(datagram, ("127.0.0.1", local))
                reply, origin = sender.recvfrom(65536)
                assert reply == datagram and origin == ("127.0.0.1", local), (size, len(reply))
        # Queued datagrams keep their boundaries and their senders.
        markers_start = len(target.received)
        for number in range(10):
            for index, sender in enumerate(senders):
                sender.sendto(f"{index}-{number}".encode(), ("127.0.0.1", local))
        for index, sender in enumerate(senders):
            replies = [sender.recv(100).decode() for _ in range(10)]
            assert replies == [f"{index}-{number}" for number in range(10)], replies
        origins = {}
        for data, origin in target.received[markers_start:]:
            if data[:2] in (b"0-", b"1-"):
                origins.setdefault(data[:1], set()).add(origin)
        assert len(origins[b"0"]) == len(origins[b"1"]) == 1 and origins[b"0"] != origins[b"1"]

        cli("b", "disable", service, "a")
        finished(process, 1, f"access to {service} was removed on the destination")
        finished(lease, 1, "ended because it was disabled")

        # A persistent UDP grant forwards to loopback on its own port.
        persistent = f"udp:{target.port}"
        grant("b", "a", persistent)
        process = popen("a", "connect", "b", persistent, "--listen", "0")
        local = int(read_line(process.stderr, "send datagrams to").strip().rsplit(":", 1)[1])
        senders[0].sendto(b"persistent", ("127.0.0.1", local))
        assert senders[0].recv(100) == b"persistent"
        cli("b", "disable", persistent, "a")
        finished(process, 1, "was removed on the destination")

        # A target that is not listening yet does not end the session.
        late = free_port(socket.SOCK_DGRAM)
        grant("b", "a", f"udp:{late}")
        process = popen("a", "connect", "b", f"udp:{late}", "--listen", "0")
        local = int(read_line(process.stderr, "send datagrams to").strip().rsplit(":", 1)[1])
        senders[0].sendto(b"lost", ("127.0.0.1", local))
        time.sleep(1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", late))
            listener.settimeout(10)
            senders[0].sendto(b"heard", ("127.0.0.1", local))
            data, origin = listener.recvfrom(100)
            assert data == b"heard", data
            listener.sendto(b"answer", origin)
            assert senders[0].recv(100) == b"answer"
        assert process.poll() is None
        process.send_signal(signal.SIGINT)
        process.wait(timeout=5)
        for sender in senders:
            sender.close()
        target.socket.close()

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
        empty = cli("a", "status").stdout
        assert "unenrolled" in empty and not (root / "a").exists(), empty
        home = cli("a").stdout
        assert "massrelay join" in home and "massrelay create" in home and not (root / "a").exists()
        cli("a", "create", "a", ticket=create, env={"MASSRELAY_RELAY": locator})
        offline = cli("a", "status").stdout
        assert "enrolled" in offline and "unavailable" in offline, offline
        assert cli("a", "relay-info", check=False).returncode != 0
        a = run_peer("a")
        eventually(lambda: cli("a", "peers", check=False).returncode == 0, "device a up")
        online = cli("a", "status").stdout
        assert "running" in online and endpoint_id("a") in online, online

        if sys.platform.startswith("linux"):
            clipboard = root / "clipboard"
            helper = root / "wl-copy"
            helper.write_text('#!/bin/sh\ncat > "$MASSRELAY_TEST_CLIPBOARD"\n')
            helper.chmod(0o700)
            copied = cli("a", "invite", "--copy", env={
                "PATH": f"{root}:{inherited['PATH']}",
                "WAYLAND_DISPLAY": "test",
                "MASSRELAY_TEST_CLIPBOARD": str(clipboard),
            })
            assert not copied.stdout and clipboard.read_text().startswith("mr1_"), copied
            assert clipboard.read_text() not in copied.stderr

        # An invalid local proof is audited without authenticating a caller or logging the proof.
        runtime = json.loads((root / "a" / "runtime.json").read_text())
        host, port = runtime["addr"].rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=5) as local:
            local.sendall(bytes(32))
            with local.makefile("rb") as challenge:
                assert len(challenge.read(64)) == 64
                local.sendall(bytes(32))
                assert challenge.read(1) == b""
        assert any(event["event"] == "local_control" and event["operation"] == "authenticate"
                   and event["outcome"] == "denied" and "actor_id" not in event
                   for event in connection_events("a"))
        assert any(event["event"] == "enrollment" and event["operation"] == "commit"
                   and event["actor_id"] == endpoint_id("a") for event in connection_events("a"))

        invite = cli("a", "invite").stdout
        cli("b", "join", "b", ticket=invite)
        assert cli("replay", "join", "replay", ticket=invite, check=False).returncode == 1
        audit_data = (root / "relay" / "relay-events.jsonl").read_text()
        audit = [json.loads(line) for line in audit_data.splitlines()]
        for token in (create, invite):
            payload = token.strip().removeprefix("mr1_")
            payload += "=" * (-len(payload) % 4)
            secret = json.loads(base64.urlsafe_b64decode(payload))["secret"]
            assert token.strip() not in audit_data and secret not in audit_data
        assert any(event["event"] == "relay_control" and event["operation"] == "issue_invite"
                   and event["outcome"] == "allowed" and event["actor_id"] == endpoint_id("a")
                   for event in audit)
        assert any(event["event"] == "relay_control" and event["operation"] == "join_network"
                   and event["outcome"] == "denied" and event["reason"] == "invalid_or_spent_invite"
                   for event in audit)
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
        assert any(event["event"] == "connection_failed" and event["peer_id"] == endpoint_id("b")
                   for event in connection_events("a"))
        approve("b", "a")
        approve("b", "c")
        approve("c", "b")
        approve("a", "c")
        cli("c", "decline", "a")
        eventually(lambda: paired("a", "b") and paired("b", "c"), "two approved pairs")

        # The chooser lists paired devices and an empty selection opens no session.
        master, slave = pty.openpty()
        try:
            before = len(connection_events("a"))
            os.write(master, b"\n")
            picked = subprocess.run(args("a", "connect"), stdin=slave, stdout=slave, stderr=subprocess.PIPE,
                                    text=True, check=True, timeout=5, env=inherited)
            assert [line.strip() for line in picked.stderr.splitlines() if line.startswith("  ")] == ["1  b"]
            assert all(event["event"] != "connected" for event in connection_events("a")[before:])
        finally:
            os.close(master)
            os.close(slave)

        pairs = [("a", "b"), ("b", "a"), ("b", "c"), ("c", "b")]
        for source, target in pairs:
            shell_refused(source, target, "service_not_enabled")
        cli("b", "enable", "shell")
        for source, target in pairs:
            if target != "b":
                grant(target, source)
        short_ids = {row.split("\t")[2] for row in cli("b", "list").stdout.splitlines()[1:]}
        assert short_ids == {endpoint_id(peer)[:8] for peer in ("a", "c")}, short_ids
        master, slave = pty.openpty()
        with os.fdopen(master) as output, os.fdopen(slave) as tty:
            subprocess.run(args("b", "list"), stdout=tty, check=True, timeout=5, env=inherited)
            header, first, second = (output.readline() for _ in range(3))
        column = header.index("ENDPOINT")
        assert {row[column:column + 8] for row in (first, second)} == short_ids
        # Re-enabling the same grant does not record a state change a second time.
        grant("b", "a")
        for supervisor in (False, True):
            events = connection_events("b", supervisor)
            matches = [
                event for event in events if event["event"] == "service_enabled"
                and event["peer_id"] == endpoint_id("a") and event.get("service") == "shell"
            ]
            assert len(matches) == 1 and matches[0]["peer_name"] == "a", matches
            assert any(event["event"] == "pairing_established" and event["peer_name"] == "a"
                       for event in events)
        for source, target in pairs:
            terminal(source, target, True, command="connect")
        eventually(lambda: recorded_session("a", "b", "outbound"), "outbound connection log")
        eventually(lambda: recorded_session("b", "a", "inbound", 7), "inbound connection log")
        eventually(lambda: recorded_session("a", "b", "outbound", supervisor=True),
                   "outbound session mirrored")
        eventually(lambda: recorded_session("b", "a", "inbound", 7, supervisor=True),
                   "inbound session mirrored")
        terminal("a", "c", False)
        terminal("c", "a", False)

        stop(relay)
        audit = [json.loads(line) for line in (root / "relay" / "relay-events.jsonl").read_text().splitlines()]
        opened = {(event["pid"], event["actor_id"], event["transport_id"]) for event in audit
                  if event["event"] == "relay_transport" and event["operation"] == "connect"
                  and event["outcome"] == "allowed"}
        assert any((event["pid"], event["actor_id"], event["transport_id"]) in opened for event in audit
                   if event["event"] == "relay_transport" and event["operation"] == "disconnect")
        stop(b)
        peer_b = [run_peer("b")]
        eventually(lambda: bool(rows("b")), "device b restarted without relay")
        terminal("a", "b", True)
        # Grants are local decisions, so they change while the relay is away.
        cli("b", "disable", "shell", "a")
        assert any(event["event"] == "service_disabled" and event["peer_name"] == "a"
                   and event.get("service") == "shell" for event in connection_events("b", True))
        shell_refused("a", "b", "service_not_enabled")
        grant("b", "a")
        terminal("a", "b", True)
        cli("a", "decline", "b")
        assert all(row[1] != "b" for row in grants("a")), grants("a")
        pending = cli("a", "enable", "shell", "b", check=False)
        assert pending.returncode == 1 and "has not reached the relay" in pending.stderr, pending
        terminal("b", "a", False)
        relay = start("relay", "relay", "--udp-bind", udp, "--relay-bind", tcp)
        eventually(lambda: relay.poll() is None and rows("a").get("b", [""])[0] == "recent", "relay restarted")
        approve("a", "b")
        terminal("a", "b", False)
        approve("b", "a")
        eventually(lambda: paired("a", "b"), "fresh mutual approval after offline decline")
        # The earlier grants ended with the earlier pairing, on both devices.
        shell_refused("a", "b", "service_not_enabled")
        shell_refused("b", "a", "service_not_enabled")
        grant("b", "a")
        terminal("a", "b", True)
        terminal("a", "b", True, during=lambda: cli("b", "disable", "shell"))
        assert all(row[0] != "shell" for row in grants("b"))
        shell_refused("a", "b", "service_not_enabled")
        grant("b", "a")

        port_services(peer_b[0])
        eventually(lambda: paired("a", "b") and paired("b", "c"), "pairs after restarts")
        grant("b", "c")
        # Revocation ends forwarded ports as well as shells.
        target = TcpTarget(echo)
        grant("b", "c", f"tcp:{target.port}")
        forwarded = stream("c", "b", f"tcp:{target.port}")
        terminal("c", "b", True, during=lambda: cli("b", "revoke", "c"))
        finished(forwarded, 1, "pairing")
        target.close()
        eventually(lambda: "c" not in rows("a"), "revocation reached peer")
        assert all(row[1] != "c" for row in grants("b")), grants("b")
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
        grant("s2", "First-Host")
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
