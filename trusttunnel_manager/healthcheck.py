"""Minimal authenticated UDS health probe for the manager container."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket

# A manager that waits for the installer to issue the certificate is up; anything else
# that is not "ok" fails the container health.
TOLERATED = {("degraded", "certificate_missing")}


def check(socket_path: Path | str, token_path: Path | str, *, timeout: float = 2) -> bool:
    try:
        token = Path(token_path).read_text().strip()
        if not 32 <= len(token) <= 512 or "\r" in token or "\n" in token:
            return False
        request = (
            "GET /v1/health HTTP/1.1\r\n"
            "Host: trusttunnel-manager\r\n"
            f"X-Trusttunnel-Token: {token}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(socket_path))
            client.sendall(request)
            chunks = []
            while chunk := client.recv(4096):
                chunks.append(chunk)
        head, _, body = b"".join(chunks).partition(b"\r\n\r\n")
        if head.split(b"\r\n", 1)[0] not in {b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK"}:
            return False
        health = json.loads(body)
        status = health.get("status")
        return status == "ok" or (status, health.get("code")) in TOLERATED
    except (OSError, UnicodeError, ValueError, AttributeError):
        return False


def main() -> None:
    socket_path = os.getenv("TT_MANAGER_SOCKET", "/run/trusttunnel-manager/manager.sock")
    token_path = os.getenv("TT_MANAGER_TOKEN_FILE", "/run/secrets/trusttunnel-manager-token")
    raise SystemExit(0 if check(socket_path, token_path) else 1)


if __name__ == "__main__":
    main()
