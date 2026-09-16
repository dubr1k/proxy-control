"""The routing intent of one service on the dedicated Xray router (v0.5, ADR 007).

The panel compiles a policy into this document and nothing else: no Xray JSON, no file
paths, no list URLs. It names what the operator wants for one ingress tag — a default for
the whole service, then ordered first-match rules over domains, `geosite` codes, CIDRs,
`geoip` codes and ports — and the manager alone turns it into the config Xray runs.

    {"schema": 1,
     "default": {"action": "direct" | "egress", "egress": "warp" | null},
     "rules": [{"domains": [...], "geosites": [...], "cidrs": [...], "geoips": [...],
                "ports": [...], "action": "direct" | "block" | "egress", "egress": "warp" | null}]}

Limits are the routing spec's (128 rules, 64 selectors of each kind and 32 ports per rule,
16 KiB per document); `geoip:private` is the router's own bypass and never a rule.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from urllib.parse import urlsplit

SCHEMA = 1
SERVICES = ("naive", "mieru")
PORTS = {"naive": 45101, "mieru": 45102}
PROVIDERS = ("warp",)
ACTIONS = ("direct", "block", "egress")
DEFAULT_ACTIONS = ("direct", "egress")
# What the spike proved this router enforces (docs/spikes/XRAY_EGRESS_ROUTER.md).
CAPABILITIES = (
    "whole_direct", "whole_warp",
    "block_domain", "block_cidr", "block_port", "block_geosite", "block_geoip",
    "selective_domain", "selective_cidr", "selective_port", "selective_geosite", "selective_geoip",
)
MAX_RULES = 128
MAX_SELECTORS = 64
MAX_PORTS = 32
MAX_DOCUMENT_BYTES = 16384
_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_GEO_CODE = re.compile(r"[a-z0-9][a-z0-9@!_-]{0,63}\Z")
_PORT_RANGE = re.compile(r"([0-9]{1,5})-([0-9]{1,5})\Z")


class EgressInvalid(ValueError):
    """The document is outside the schema this manager renders; `code` is the bounded
    reason a client can act on (`egress_invalid`, or what `xray run -test` named)."""

    def __init__(self, message: str, code: str = "egress_invalid"):
        super().__init__(message)
        self.code = code


class EgressUnreachable(RuntimeError):
    """The provider's endpoint did not answer a SOCKS5 greeting."""


def canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def document_digest(document: dict) -> str:
    return hashlib.sha256(canonical(document)).hexdigest()


def direct_document() -> dict:
    """The floor of every service: pass-through, no rules — what a fresh router runs."""
    return {"schema": SCHEMA, "default": {"action": "direct", "egress": None}, "rules": []}


def _domain(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 255 or any(c.isspace() for c in value):
        raise EgressInvalid("invalid domain")
    candidate = value.lower().rstrip(".")
    host = candidate[2:] if candidate.startswith("*.") else candidate
    if not host or "*" in host or "/" in host or _DOMAIN.fullmatch(host) is None:
        raise EgressInvalid("invalid domain")
    return candidate


def _cidr(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EgressInvalid("invalid cidr")
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise EgressInvalid("invalid cidr") from exc


def _geo_code(value: object, kind: str) -> str:
    if not isinstance(value, str) or _GEO_CODE.fullmatch(value) is None:
        raise EgressInvalid(f"invalid {kind} code")
    if kind == "geoip" and value == "private":
        raise EgressInvalid("geoip:private is the router's bypass, not a rule")
    return value


def _port(value: object) -> int | str:
    if isinstance(value, bool):
        raise EgressInvalid("invalid port")
    if isinstance(value, int):
        if not 1 <= value <= 65535:
            raise EgressInvalid("invalid port")
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return _port(int(text))
        match = _PORT_RANGE.fullmatch(text)
        if match and 1 <= int(match[1]) <= int(match[2]) <= 65535:
            return f"{int(match[1])}-{int(match[2])}"
    raise EgressInvalid("invalid port")


def _unique(items: list) -> list:
    seen: list = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def _selectors(rule: dict, key: str, convert, limit: int) -> list:
    values = rule.get(key, [])
    if not isinstance(values, list) or len(values) > limit:
        raise EgressInvalid(f"invalid {key} list")
    return _unique([convert(item) for item in values])


def _egress(action: str, egress: object, *, label: str) -> str | None:
    if action == "egress":
        if egress not in PROVIDERS:
            raise EgressInvalid(f"{label} must name its egress provider")
        return egress
    if egress is not None:
        raise EgressInvalid(f"only an egress {label} names an egress provider")
    return None


def validate_document(document: object) -> dict:
    """The intent, normalised, or `EgressInvalid`. Bounded, secret-free, nothing raw."""
    if not isinstance(document, dict) or set(document) - {"schema", "default", "rules"}:
        raise EgressInvalid("unknown field in routing intent")
    if document.get("schema") != SCHEMA:
        raise EgressInvalid("unsupported routing intent schema")
    default = document.get("default")
    if not isinstance(default, dict) or set(default) - {"action", "egress"} or default.get("action") not in DEFAULT_ACTIONS:
        raise EgressInvalid("invalid default")
    default_action = default["action"]
    default_egress = _egress(default_action, default.get("egress"), label="default")
    rules = document.get("rules", [])
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise EgressInvalid("invalid rules list")
    normalised_rules = []
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - {"domains", "geosites", "cidrs", "geoips", "ports", "action", "egress"}:
            raise EgressInvalid("invalid rule")
        if rule.get("action") not in ACTIONS:
            raise EgressInvalid("invalid rule action")
        entry = {
            "domains": _selectors(rule, "domains", _domain, MAX_SELECTORS),
            "geosites": _selectors(rule, "geosites", lambda v: _geo_code(v, "geosite"), MAX_SELECTORS),
            "cidrs": _selectors(rule, "cidrs", _cidr, MAX_SELECTORS),
            "geoips": _selectors(rule, "geoips", lambda v: _geo_code(v, "geoip"), MAX_SELECTORS),
            "ports": _selectors(rule, "ports", _port, MAX_PORTS),
            "action": rule["action"],
            "egress": _egress(rule["action"], rule.get("egress"), label="rule"),
        }
        if not any(entry[key] for key in ("domains", "geosites", "cidrs", "geoips", "ports")):
            raise EgressInvalid("a rule must name at least one selector")
        normalised_rules.append(entry)
    normalised = {"schema": SCHEMA, "default": {"action": default_action, "egress": default_egress}, "rules": normalised_rules}
    if len(canonical(normalised)) > MAX_DOCUMENT_BYTES:
        raise EgressInvalid("routing intent too large")
    return normalised


def uses_provider(document: dict, provider: str = "warp") -> bool:
    return document["default"]["egress"] == provider or any(rule["egress"] == provider for rule in document["rules"])


def provider_endpoint(provider_url: str | None) -> tuple[str, int]:
    """Host and port of the provider's SOCKS5 endpoint; the router's `socks` outbound."""
    if not provider_url:
        raise EgressInvalid("egress provider warp is not configured on this node")
    parts = urlsplit(provider_url)
    if parts.scheme not in ("socks5", "socks5h") or not parts.hostname or not parts.port:
        raise EgressInvalid("egress provider warp must be a socks5:// endpoint")
    return parts.hostname, parts.port


def check_reachable(url: str, timeout: float = 3.0) -> bool:
    """A SOCKS5 greeting without authentication; never raises — the answer is the fact."""
    try:
        host, port = provider_endpoint(url)
    except EgressInvalid:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as stream:
            stream.settimeout(timeout)
            stream.sendall(b"\x05\x01\x00")
            return stream.recv(2) == b"\x05\x00"
    except OSError:
        return False
