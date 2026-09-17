"""Minimal authenticated UDS probes for the router container: the health check the
container runs, and `--status` for the installer's verification (`docker exec`)."""
from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path


def _request(socket_path: Path | str, token_path: Path | str, target: str, *, timeout: float,
             method: str = "GET", body: bytes = b"") -> tuple[bytes, bytes]:
    """(status line, body) of one authenticated request, or `OSError`/`UnicodeError`."""
    token = Path(token_path).read_text().strip()
    if not 32 <= len(token) <= 512 or "\r" in token or "\n" in token:
        raise ValueError("malformed token")
    request = (
        f"{method} {target} HTTP/1.1\r\n"
        "Host: xray-router\r\n"
        f"X-Xray-Router-Token: {token}\r\n"
        + ("Content-Type: application/json\r\n" f"Content-Length: {len(body)}\r\n" if body else "")
        + "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(str(socket_path))
        client.sendall(request)
        chunks = []
        while chunk := client.recv(65536):
            chunks.append(chunk)
    head, _separator, body = b"".join(chunks).partition(b"\r\n\r\n")
    return head.split(b"\r\n", 1)[0], body


def check(socket_path: Path | str, token_path: Path | str, *, timeout: float = 2) -> bool:
    try:
        status_line, _body = _request(socket_path, token_path, "/v1/health", timeout=timeout)
    except (OSError, UnicodeError, ValueError):
        return False
    return status_line in {b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK"}


def status(socket_path: Path | str, token_path: Path | str, *, timeout: float = 5) -> bytes | None:
    """The raw JSON of `/v1/status`, or None when the manager does not answer 200."""
    try:
        status_line, body = _request(socket_path, token_path, "/v1/status", timeout=timeout)
    except (OSError, UnicodeError, ValueError):
        return None
    return body if status_line in {b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK"} else None


def relay(socket_path: Path | str, token_path: Path | str, *, timeout: float = 5) -> bytes | None:
    """The raw JSON of `/v1/relay` (its public part), or None."""
    try:
        status_line, body = _request(socket_path, token_path, "/v1/relay", timeout=timeout)
    except (OSError, UnicodeError, ValueError):
        return None
    return body if status_line in {b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK"} else None


def relay_enable(socket_path: Path | str, token_path: Path | str, server_name: str, port: int, *,
                 timeout: float = 30) -> bytes | None:
    """`POST /v1/relay` for the installer (v0.7): the inbound up on `port` with the node's
    own panel name as its cover; the keypair is minted once, by the manager. The public
    part comes back, or None when the manager refused."""
    payload = json.dumps({"server_name": server_name, "port": port}).encode()
    try:
        status_line, body = _request(socket_path, token_path, "/v1/relay", timeout=timeout, method="POST", body=payload)
    except (OSError, UnicodeError, ValueError):
        return None
    return body if status_line in {b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK"} else None


def main(argv: list[str] | None = None) -> None:
    arguments = sys.argv[1:] if argv is None else argv
    socket_path = os.getenv("XRAY_ROUTER_SOCKET", "/run/xray-router/manager.sock")
    token_path = os.getenv("XRAY_ROUTER_MANAGER_TOKEN_FILE", "/run/secrets/xray-router-manager-token")
    body: bytes | None = None
    if arguments == ["--status"]:
        body = status(socket_path, token_path)
    elif arguments == ["--relay"]:
        body = relay(socket_path, token_path)
    elif len(arguments) == 3 and arguments[0] == "--relay-enable" and arguments[2].isdigit():
        body = relay_enable(socket_path, token_path, arguments[1], int(arguments[2]))
    elif arguments:
        raise SystemExit("usage: python -m xray_router_manager.healthcheck [--status | --relay | --relay-enable <server_name> <port>]")
    else:
        raise SystemExit(0 if check(socket_path, token_path) else 1)
    if body is None:
        raise SystemExit(1)
    sys.stdout.buffer.write(body + b"\n")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
