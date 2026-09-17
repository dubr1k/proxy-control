"""Lanes for Mieru (v0.7, docs/spikes/CHAINS_PER_CLIENT.md): one mita daemon per lane.

mita has one `egress` section per daemon and no per-user selector, so a lane — a group of
users whose traffic leaves through its own account on the node's Xray-router — is one of
the *slot* daemons the installer keeps running beside the managed one (`mita@<n>`: its
own port, UDS and state directory, idle until a lane is assigned). The main daemon stays
the source of truth for users; a slot mirrors its lane's users (name, stored hash,
quotas) with an egress that sends everything to the lane's ingress account. A lane user's
share link carries the slot's port, which is what makes the lane theirs.

The installer names the slots in `MIERU_LANE_SLOTS`:

    1:46101:/run/mita/lane-1.sock:/var/lib/mita/lanes/1,2:46102:/run/mita/lane-2.sock:/var/lib/mita/lanes/2
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, urlencode

LANE_ID = re.compile(r"grant:[A-Za-z0-9_-]{1,64}\Z")
ACCOUNT_USER = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
ACCOUNT_PASSWORD = re.compile(r"[A-Za-z0-9._~-]{16,128}\Z")
MAX_LANES = 32
MAX_LANE_USERS = 256
MAX_SLOTS = 64


class LanesInvalid(ValueError):
    """The lanes request (or the slot list) is outside what this manager handles."""


@dataclass(frozen=True)
class Slot:
    index: int
    port: int
    uds: str
    state_dir: str


def parse_slots(value: str | None) -> list[Slot]:
    """`MIERU_LANE_SLOTS` as slots, in index order; unique indexes and ports."""
    if not value:
        return []
    slots: list[Slot] = []
    for item in value.split(","):
        parts = item.strip().split(":")
        if len(parts) != 4 or not parts[0].isdigit() or not parts[1].isdigit():
            raise LanesInvalid("invalid lane slot list")
        index, port, uds, state_dir = int(parts[0]), int(parts[1]), parts[2], parts[3]
        if not 1 <= index <= MAX_SLOTS or not 1 <= port <= 65535 or not uds.startswith("/") or not state_dir.startswith("/"):
            raise LanesInvalid("invalid lane slot")
        slots.append(Slot(index, port, uds, state_dir))
    if len({slot.index for slot in slots}) != len(slots) or len({slot.port for slot in slots}) != len(slots):
        raise LanesInvalid("lane slots must have unique indexes and ports")
    return sorted(slots, key=lambda slot: slot.index)


def validate_request(body: object, known_users: set[str]) -> list[dict]:
    """`{"lanes": [{"lane", "users": [...], "upstream": {"user", "password"}}]}` normalised,
    or `LanesInvalid`. Every named user must exist; a user sits in at most one lane."""
    if not isinstance(body, dict) or set(body) != {"lanes"} or not isinstance(body["lanes"], list):
        raise LanesInvalid("invalid lanes request")
    if len(body["lanes"]) > MAX_LANES:
        raise LanesInvalid("too many lanes")
    seen_lanes: set[str] = set()
    seen_users: set[str] = set()
    lanes = []
    for entry in body["lanes"]:
        if not isinstance(entry, dict) or set(entry) != {"lane", "users", "upstream"}:
            raise LanesInvalid("invalid lane")
        lane = entry["lane"]
        if not isinstance(lane, str) or LANE_ID.fullmatch(lane) is None or lane in seen_lanes:
            raise LanesInvalid("invalid lane id")
        users = entry["users"]
        if not isinstance(users, list) or not users or len(users) > MAX_LANE_USERS:
            raise LanesInvalid("a lane names its users")
        for user in users:
            if not isinstance(user, str) or user not in known_users:
                raise LanesInvalid("unknown lane user")
            if user in seen_users:
                raise LanesInvalid("a user sits in one lane")
            seen_users.add(user)
        upstream = entry["upstream"]
        if (not isinstance(upstream, dict) or set(upstream) != {"user", "password"}
                or not isinstance(upstream["user"], str) or ACCOUNT_USER.fullmatch(upstream["user"]) is None
                or not isinstance(upstream["password"], str) or ACCOUNT_PASSWORD.fullmatch(upstream["password"]) is None):
            raise LanesInvalid("invalid lane upstream account")
        seen_lanes.add(lane)
        lanes.append({"lane": lane, "users": list(users), "upstream": {"user": upstream["user"], "password": upstream["password"]}})
    return lanes


def empty_config(slot: Slot) -> dict:
    """What an unassigned slot runs: its port, nobody, no egress — and it is stopped."""
    return {"portBindings": [{"port": slot.port, "protocol": "TCP"}], "loggingLevel": "INFO"}


def slot_config(slot: Slot, users: list[dict], router_endpoint: tuple[str, int], credential: tuple[str, str],
                *, mtu: int | None = None) -> dict:
    """A lane's mita config: the slot's port, the lane's users as the main daemon stores
    them (hash, quotas, flags), one proxy — the router ingress with the lane's account —
    and one rule sending everything through it."""
    config: dict = {"portBindings": [{"port": slot.port, "protocol": "TCP"}], "loggingLevel": "INFO"}
    if users:
        config["users"] = [dict(user) for user in users]
    if mtu is not None:
        config["mtu"] = mtu
    host, port = router_endpoint
    config["egress"] = {
        "proxies": [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": host, "port": port,
                     "socks5Authentication": {"user": credential[0], "password": credential[1]}}],
        "rules": [{"ipRanges": ["*"], "domainNames": ["*"], "action": "PROXY", "proxyNames": ["router"]}],
    }
    return config


def share_template(username: str, host: str, port: int, mtu: int) -> str:
    """The link shape of a lane user — the panel fills the credential in."""
    try:
        if ipaddress.ip_address(host).version == 6:
            host = f"[{host}]"
    except ValueError:
        pass
    query = urlencode([("profile", username), ("port", str(port)), ("protocol", "TCP"), ("mtu", str(mtu))])
    return f"mierus://{{username}}:{{password}}@{host}?{query}"


def redact_lane(entry: dict) -> dict:
    return {**entry, "upstream": {"user": "***", "password": "***"}}


def account_url(router_url: str, credential: tuple[str, str]) -> str:
    """`socks5://user:pass@host:port` — only for the masked view."""
    user, password = (quote(part, safe="") for part in credential)
    scheme, _sep, rest = router_url.partition("://")
    return f"{scheme}://{user}:{password}@{rest.rsplit('@', 1)[-1]}"
