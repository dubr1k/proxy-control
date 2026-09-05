"""Prove one Mieru transport end to end with the pinned official client.

The probe applies the reveal's own client configuration, starts the client,
and requires one exact status code from a well-known endpoint through the
client's SOCKS5 port. Anything less would prove the daemon starts, not that
the transport carries traffic.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time

_DEADLINE_SECONDS = 20.0
_INTERVAL_SECONDS = 0.4


def _run(*arguments: str) -> tuple[int, str]:
    """Run one client command without inheriting a pipe to its daemon.

    `mieru start` leaves a background process behind, and that child keeps a
    captured pipe open, so reading one would block until the daemon exits.
    Output goes to a temporary file instead, which the daemon may inherit
    harmlessly.
    """
    with tempfile.TemporaryFile() as sink:
        completed = subprocess.run(
            ("mieru", *arguments),
            stdin=subprocess.DEVNULL,
            stdout=sink,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        sink.seek(0)
        return completed.returncode, sink.read().decode("utf-8", "replace")


def _endpoint(value: str) -> tuple[str, int]:
    host, _separator, port = value.rpartition(":")
    return host, int(port)


def _socks5_connect(proxy: tuple[str, int], host: str, port: int) -> socket.socket:
    client = socket.create_connection(proxy, timeout=10)
    try:
        client.sendall(b"\x05\x01\x00")
        if client.recv(2) != b"\x05\x00":
            raise OSError("SOCKS5 greeting refused")
        name = host.encode("idna")
        client.sendall(
            b"\x05\x01\x00\x03"
            + bytes((len(name),))
            + name
            + port.to_bytes(2, "big")
        )
        reply = client.recv(4)
        if len(reply) < 4 or reply[1] != 0:
            raise OSError("SOCKS5 connect refused")
        # Drain the bound address so the stream starts at the payload.
        kind = reply[3]
        if kind == 1:
            client.recv(4)
        elif kind == 3:
            client.recv(client.recv(1)[0])
        elif kind == 4:
            client.recv(16)
        else:
            raise OSError("SOCKS5 reply is malformed")
        client.recv(2)
        return client
    except BaseException:
        client.close()
        raise


def _status_through(proxy: tuple[str, int], url: str) -> int:
    scheme, _separator, rest = url.partition("://")
    if scheme != "http":
        raise ValueError("the probe endpoint must be plain HTTP")
    authority, _slash, path = rest.partition("/")
    host, _colon, port = authority.partition(":")
    connection = _socks5_connect(proxy, host, int(port or 80))
    try:
        connection.sendall(
            f"GET /{path} HTTP/1.1\r\nHost: {authority}\r\n"
            "Connection: close\r\nUser-Agent: proxy-control-acceptance\r\n\r\n".encode()
        )
        connection.settimeout(10)
        head = b""
        while b"\r\n" not in head and len(head) < 256:
            chunk = connection.recv(64)
            if not chunk:
                break
            head += chunk
        fields = head.split(b"\r\n", 1)[0].split()
        if len(fields) < 2 or not fields[1].isdigit():
            raise OSError("the probe endpoint returned no status line")
        return int(fields[1])
    finally:
        connection.close()


def main() -> int:
    expected = int(os.environ["MIERU_PROBE_STATUS"])
    url = os.environ["MIERU_PROBE_URL"]
    proxy = _endpoint(os.environ["MIERU_PROBE_SOCKS"])
    code, output = _run("apply", "config", os.environ["MIERU_PROBE_CONFIG"])
    if code != 0:
        sys.stderr.write(f"mieru could not apply the client configuration: {output}\n")
        return 1
    code, output = _run("start")
    if code != 0:
        sys.stderr.write(f"mieru client did not start: {output}\n")
        return 1
    try:
        deadline = time.monotonic() + _DEADLINE_SECONDS
        last = "no attempt completed"
        while time.monotonic() < deadline:
            try:
                status = _status_through(proxy, url)
            except (OSError, ValueError) as exc:
                last = type(exc).__name__
                time.sleep(_INTERVAL_SECONDS)
                continue
            if status == expected:
                return 0
            last = f"status {status}"
            time.sleep(_INTERVAL_SECONDS)
        sys.stderr.write(f"no probe reached the expected status: {last}\n")
        return 1
    finally:
        _run("stop")


if __name__ == "__main__":
    raise SystemExit(main())
