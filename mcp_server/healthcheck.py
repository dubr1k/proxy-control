"""The container's health check: `GET /healthz` on the loopback answers 200 with
`{"status": "ok"}`; no token is needed for it."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8793/healthz"


def check(url: str = DEFAULT_URL, timeout: float = 3.0) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 — loopback only
            return response.status == 200 and json.loads(response.read().decode()).get("status") == "ok"
    except (OSError, ValueError, urllib.error.URLError):
        return False


def main() -> None:
    port = os.getenv("MCP_BIND", "0.0.0.0:8793").rpartition(":")[2] or "8793"
    raise SystemExit(0 if check(f"http://127.0.0.1:{port}/healthz") else 1)


if __name__ == "__main__":
    main()
