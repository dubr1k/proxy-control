"""The WARP account the AmneziaWG egress tunnel uses (v2.3.0).

The host's own WARP client (`warp-svc`, proxy mode) runs MASQUE with ECDSA keys and offers SOCKS5
without UDP, so AmneziaWG — whose clients send UDP as much as TCP (DNS, QUIC, calls) — gets a WARP
device of its own: a WireGuard key pair made here, registered once at Cloudflare's client API (the
same call the 1.1.1.1 app makes), kept in the manager's state (0600) and reused until it is
deregistered. Registration answers with the tunnel address and the peer; nothing else is stored.
"""
from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Callable

from .keys import b64, generate_private, public_key, unb64

API = "https://api.cloudflareclient.com/v0a5641"
HEADERS = {
    "User-Agent": "okhttp/3.12.1",
    "CF-Client-Version": "a-6.38.9-5641",
    "Content-Type": "application/json; charset=UTF-8",
}
PORT = 2408
TIMEOUT = 20

# (method, url, headers, body or None) -> (status, parsed JSON or None). Injected in tests.
Opener = Callable[[str, str, dict, bytes | None], tuple[int, object]]


class WarpError(RuntimeError):
    """Registration failed or answered something this manager cannot use. Never carries a key."""


def _urllib_opener(method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, object]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT, context=ssl.create_default_context()) as response:
            raw = response.read(65536)
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (OSError, ValueError) as exc:
        raise WarpError(f"WARP API unreachable: {type(exc).__name__}") from exc


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def register(opener: Opener | None = None) -> dict:
    """A new WARP device: the stored account (with its private key) or `WarpError`."""
    opener = opener or _urllib_opener
    private = generate_private()
    body = {"key": b64(public_key(private)), "install_id": "", "fcm_token": "", "tos": _now(),
            "model": "PC", "serial_number": "", "locale": "en_US"}
    status, data = opener("POST", f"{API}/reg", HEADERS, json.dumps(body).encode())
    if status != 200 or not isinstance(data, dict):
        raise WarpError(f"WARP registration refused (HTTP {status})")
    try:
        config = data["config"]
        peer = config["peers"][0]
        address = str(ipaddress.IPv4Address(config["interface"]["addresses"]["v4"]))
        endpoint = str(ipaddress.IPv4Address(peer["endpoint"]["v4"].rsplit(":", 1)[0]))
        peer_key = peer["public_key"]
        unb64(peer_key)
        device_id, token = str(data["id"]), str(data["token"])
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise WarpError("WARP registration answered an unexpected shape") from exc
    if not device_id or not token:
        raise WarpError("WARP registration answered an unexpected shape")
    return {
        "id": device_id, "token": token, "private_key": b64(private), "address": address,
        "peer_public_key": peer_key, "endpoint": f"{endpoint}:{PORT}",
        "account_type": str((data.get("account") or {}).get("account_type") or ""),
        "registered_at": _now(),
    }


def deregister(account: dict, opener: Opener | None = None) -> None:
    """Remove the device at Cloudflare. A device already gone (404) counts as removed."""
    opener = opener or _urllib_opener
    headers = {**HEADERS, "Authorization": f"Bearer {account['token']}"}
    status, _ = opener("DELETE", f"{API}/reg/{account['id']}", headers, None)
    if status not in (200, 204, 404):
        raise WarpError(f"WARP deregistration refused (HTTP {status})")


def valid_account(account: object) -> bool:
    """A stored account this manager can bring a tunnel up with."""
    if not isinstance(account, dict):
        return False
    try:
        unb64(account["private_key"])
        unb64(account["peer_public_key"])
        ipaddress.IPv4Address(account["address"])
        host, _, port = account["endpoint"].rpartition(":")
        ipaddress.IPv4Address(host)
        return 0 < int(port) < 65536 and bool(account["id"]) and bool(account["token"])
    except (KeyError, TypeError, ValueError):
        return False
