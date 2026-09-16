"""Minimal authenticated UDS health probe for the router container."""
from __future__ import annotations

import os
import socket
from pathlib import Path


def check(socket_path: Path | str, token_path: Path | str, *, timeout: float = 2) -> bool:
    try:
        token = Path(token_path).read_text().strip()
        if not 32 <= len(token) <= 512 or "\r" in token or "\n" in token:
            return False
        request = (
            "GET /v1/health HTTP/1.1\r\n"
            "Host: xray-router\r\n"
            f"X-Xray-Router-Token: {token}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(socket_path))
            client.sendall(request)
            chunks = []
            while chunk := client.recv(4096):
                chunks.append(chunk)
        status_line = b"".join(chunks).split(b"\r\n", 1)[0]
        return status_line in {b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK"}
    except (OSError, UnicodeError):
        return False


def main() -> None:
    socket_path = os.getenv("XRAY_ROUTER_SOCKET", "/run/xray-router/manager.sock")
    token_path = os.getenv("XRAY_ROUTER_MANAGER_TOKEN_FILE", "/run/secrets/xray-router-manager-token")
    raise SystemExit(0 if check(socket_path, token_path) else 1)


if __name__ == "__main__":
    main()
