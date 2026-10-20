"""Minimal authenticated UDS health probe for the manager container."""
from __future__ import annotations

import json
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
            "Host: awg-manager\r\n"
            f"X-Awg-Token: {token}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(socket_path))
            client.sendall(request)
            # Read to EOF: hanging up early leaves the manager writing into a
            # closed socket, which it would report as a failed request.
            chunks = []
            while chunk := client.recv(4096):
                chunks.append(chunk)
        head, _, body = b"".join(chunks).partition(b"\r\n\r\n")
        if head.split(b"\r\n", 1)[0] not in {b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK"}:
            return False
        # 200 alone is not enough: every enabled instance must be up and forwarding on.
        health = json.loads(body)
        return health.get("status") == "ok" and all(
            i.get("running") is True for i in health.get("instances", {}).values()
        )
    except (OSError, UnicodeError, ValueError, AttributeError):
        return False


def main() -> None:
    socket_path = os.getenv(
        "AWG_MANAGER_SOCKET", "/run/awg-manager/manager.sock"
    )
    token_path = os.getenv(
        "AWG_MANAGER_TOKEN_FILE", "/run/secrets/awg-manager-token"
    )
    raise SystemExit(0 if check(socket_path, token_path) else 1)


if __name__ == "__main__":
    main()
