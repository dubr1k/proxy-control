"""The router's own WARP device for AmneziaWG's `warp` (v2.3.0): a WireGuard key pair, registered once
at Cloudflare's client API (the call the 1.1.1.1 app makes) and kept in the router's state directory
(`warp-wg.json`, 0600). The host's warp-svc stays what every other service uses; this account exists
because warp-svc's SOCKS5 refuses UDP, and AmneziaWG's tunnels carry UDP as much as TCP.

The key pair comes from the pinned Xray (`xray x25519`, base64url) and is turned into the standard
base64 WireGuard and the API use. Nothing here ever logs a key or the token."""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Callable

API = "https://api.cloudflareclient.com/v0a5641"
HEADERS = {
    "User-Agent": "okhttp/3.12.1",
    "CF-Client-Version": "a-6.38.9-5641",
    "Content-Type": "application/json; charset=UTF-8",
}
PORT = 2408
TIMEOUT = 20

Opener = Callable[[str, str, dict, bytes | None], tuple[int, object]]


class WarpError(RuntimeError):
    """Registration failed or answered something unusable. Never carries a key."""


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


def standard_b64(urlsafe: str) -> str:
    """A 32-byte key printed as base64url (no padding) as standard base64."""
    try:
        raw = base64.urlsafe_b64decode(urlsafe + "=" * (-len(urlsafe) % 4))
    except (binascii.Error, ValueError) as exc:
        raise WarpError("the key pair is not base64url") from exc
    if len(raw) != 32:
        raise WarpError("the key pair is not 32 bytes")
    return base64.b64encode(raw).decode()


def register(keypair: tuple[str, str], opener: Opener | None = None) -> dict:
    """A new WARP device for the (private, public) base64url pair: the stored account or WarpError."""
    opener = opener or _urllib_opener
    private, public = standard_b64(keypair[0]), standard_b64(keypair[1])
    tos = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    body = {"key": public, "install_id": "", "fcm_token": "", "tos": tos, "model": "PC", "serial_number": "",
            "locale": "en_US"}
    status, data = opener("POST", f"{API}/reg", HEADERS, json.dumps(body).encode())
    if status != 200 or not isinstance(data, dict):
        raise WarpError(f"WARP registration refused (HTTP {status})")
    try:
        config = data["config"]
        peer = config["peers"][0]
        address = str(ipaddress.IPv4Address(config["interface"]["addresses"]["v4"]))
        endpoint = str(ipaddress.IPv4Address(peer["endpoint"]["v4"].rsplit(":", 1)[0]))
        peer_key = peer["public_key"]
        if len(base64.b64decode(peer_key, validate=True)) != 32:
            raise ValueError("peer key")
        device_id, token = str(data["id"]), str(data["token"])
    except (KeyError, IndexError, TypeError, ValueError, binascii.Error) as exc:
        raise WarpError("WARP registration answered an unexpected shape") from exc
    if not device_id or not token:
        raise WarpError("WARP registration answered an unexpected shape")
    return {"id": device_id, "token": token, "private_key": private, "address": address, "peer_public_key": peer_key,
            "endpoint": f"{endpoint}:{PORT}", "registered_at": tos}


def valid_account(account: object) -> bool:
    if not isinstance(account, dict):
        return False
    try:
        for key in ("private_key", "peer_public_key"):
            if len(base64.b64decode(account[key], validate=True)) != 32:
                return False
        ipaddress.IPv4Address(account["address"])
        host, _, port = account["endpoint"].rpartition(":")
        ipaddress.IPv4Address(host)
        return 0 < int(port) < 65536 and bool(account["id"]) and bool(account["token"])
    except (KeyError, TypeError, ValueError, binascii.Error):
        return False
