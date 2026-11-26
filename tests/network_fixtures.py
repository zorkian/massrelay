"""Loopback fixtures for the CLI integration test."""

import os
import select
import signal
import socket
import subprocess
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
