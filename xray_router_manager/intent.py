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

Schema 2 (v0.7, docs/spikes/CHAINS_PER_CLIENT.md) carries the same vocabulary per *lane* — the
service's own lane `svc:<service>` and one `grant:<id>` lane per client with its own routing —
and *chains*: an egress may be `chain:<id>`, a list of up to three hops (another node's relay
inbound, VLESS+Reality) and what the last hop does with the connection (`direct` or its `warp`).

    {"schema": 2,
     "lanes": {"svc:naive": {"default": …, "rules": […]}, "grant:<id>": {…}},
     "chains": {"<id>": {"hops": [{"guid", "address", "port", "server_name", "public_key",
                                  "short_id", "uuid"}], "exit": "direct" | "warp"}}}

A schema-1 document is one service lane; `lanes_of()` presents either form the same way.
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
# Schema 2: lanes multiply the volume; chains are small and few.
SCHEMA_V2 = 2
MAX_LANES = 32
MAX_CHAINS = 16
MAX_HOPS = 3
MAX_DOCUMENT_BYTES_V2 = 65536
CHAIN_EXITS = ("direct", "warp")
_LANE = re.compile(r"(?:svc:(?:naive|mieru)|grant:[A-Za-z0-9_-]{1,64})\Z")
_CHAIN_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
_GUID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_PUBLIC_KEY = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_SHORT_ID = re.compile(r"(?:[0-9a-f]{2}){0,8}\Z")
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


def _egress(action: str, egress: object, *, label: str, chains: tuple[str, ...] = ()) -> str | None:
    if action == "egress":
        if egress in PROVIDERS:
            return egress
        if isinstance(egress, str) and egress.startswith("chain:") and egress[6:] in chains:
            return egress
        raise EgressInvalid(f"{label} must name its egress provider")
    if egress is not None:
        raise EgressInvalid(f"only an egress {label} names an egress provider")
    return None


def validate_document(document: object) -> dict:
    """The intent, normalised, or `EgressInvalid`. Bounded, secret-free, nothing raw."""
    if isinstance(document, dict) and document.get("schema") == SCHEMA_V2:
        return _validate_v2(document)
    if not isinstance(document, dict) or set(document) - {"schema", "default", "rules"}:
        raise EgressInvalid("unknown field in routing intent")
    if document.get("schema") != SCHEMA:
        raise EgressInvalid("unsupported routing intent schema")
    lane = _validate_lane(document, chains=())
    if len(canonical(lane)) > MAX_DOCUMENT_BYTES:
        raise EgressInvalid("routing intent too large")
    return {"schema": SCHEMA, **lane}


def _validate_lane(document: dict, *, chains: tuple[str, ...]) -> dict:
    """One lane's body — a default and its first-match rules — normalised."""
    if not isinstance(document, dict) or set(document) - {"schema", "default", "rules"}:
        raise EgressInvalid("unknown field in routing intent")
    default = document.get("default")
    if not isinstance(default, dict) or set(default) - {"action", "egress"} or default.get("action") not in DEFAULT_ACTIONS:
        raise EgressInvalid("invalid default")
    default_action = default["action"]
    default_egress = _egress(default_action, default.get("egress"), label="default", chains=chains)
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
            "egress": _egress(rule["action"], rule.get("egress"), label="rule", chains=chains),
        }
        if not any(entry[key] for key in ("domains", "geosites", "cidrs", "geoips", "ports")):
            raise EgressInvalid("a rule must name at least one selector")
        normalised_rules.append(entry)
    return {"default": {"action": default_action, "egress": default_egress}, "rules": normalised_rules}


def _hop(value: object) -> dict:
    fields = {"guid", "address", "port", "server_name", "public_key", "short_id", "uuid"}
    if not isinstance(value, dict) or set(value) != fields:
        raise EgressInvalid("invalid chain hop")
    if not isinstance(value["guid"], str) or _GUID.fullmatch(value["guid"]) is None:
        raise EgressInvalid("invalid hop guid")
    address = value["address"]
    if not isinstance(address, str) or not address:
        raise EgressInvalid("invalid hop address")
    try:
        ipaddress.ip_address(address)
    except ValueError:
        address = _domain(address)
        if address.startswith("*."):
            raise EgressInvalid("invalid hop address")
    port = value["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise EgressInvalid("invalid hop port")
    server_name = _domain(value["server_name"])
    if server_name.startswith("*."):
        raise EgressInvalid("invalid hop server name")
    if not isinstance(value["public_key"], str) or _PUBLIC_KEY.fullmatch(value["public_key"]) is None:
        raise EgressInvalid("invalid hop public key")
    if not isinstance(value["short_id"], str) or _SHORT_ID.fullmatch(value["short_id"]) is None:
        raise EgressInvalid("invalid hop short id")
    if not isinstance(value["uuid"], str) or _UUID.fullmatch(value["uuid"]) is None:
        raise EgressInvalid("invalid hop credential")
    return {"guid": value["guid"], "address": address, "port": port, "server_name": server_name,
            "public_key": value["public_key"], "short_id": value["short_id"], "uuid": value["uuid"]}


def _validate_v2(document: dict) -> dict:
    if set(document) - {"schema", "lanes", "chains"}:
        raise EgressInvalid("unknown field in routing intent")
    chains = document.get("chains", {})
    if not isinstance(chains, dict) or len(chains) > MAX_CHAINS:
        raise EgressInvalid("invalid chains list")
    normalised_chains: dict[str, dict] = {}
    for chain_id, chain in chains.items():
        if not isinstance(chain_id, str) or _CHAIN_ID.fullmatch(chain_id) is None:
            raise EgressInvalid("invalid chain id")
        if not isinstance(chain, dict) or set(chain) != {"hops", "exit"}:
            raise EgressInvalid("invalid chain")
        hops = chain["hops"]
        if not isinstance(hops, list) or not 1 <= len(hops) <= MAX_HOPS:
            raise EgressInvalid("a chain has one to three hops")
        if chain["exit"] not in CHAIN_EXITS:
            raise EgressInvalid("a chain exits direct or through its last hop's warp")
        normalised_chains[chain_id] = {"hops": [_hop(hop) for hop in hops], "exit": chain["exit"]}
    lanes = document.get("lanes")
    if not isinstance(lanes, dict) or not lanes or len(lanes) > MAX_LANES:
        raise EgressInvalid("invalid lanes list")
    normalised_lanes: dict[str, dict] = {}
    for lane_id, lane in lanes.items():
        if not isinstance(lane_id, str) or _LANE.fullmatch(lane_id) is None:
            raise EgressInvalid("invalid lane id")
        normalised_lanes[lane_id] = _validate_lane(lane, chains=tuple(normalised_chains))
    if sum(1 for lane_id in normalised_lanes if lane_id.startswith("svc:")) != 1:
        raise EgressInvalid("exactly one service lane is required")
    normalised = {"schema": SCHEMA_V2, "lanes": normalised_lanes, "chains": normalised_chains}
    if len(canonical(normalised)) > MAX_DOCUMENT_BYTES_V2:
        raise EgressInvalid("routing intent too large")
    return normalised


def lanes_of(document: dict, service: str) -> dict[str, dict]:
    """Either schema as lanes: a schema-1 document is the service's own lane."""
    if document.get("schema") == SCHEMA_V2:
        return document["lanes"]
    return {f"svc:{service}": {"default": document["default"], "rules": document["rules"]}}


def chain_ids(document: dict) -> list[str]:
    return list(document.get("chains", {})) if document.get("schema") == SCHEMA_V2 else []


def uses_chain(document: dict, chain_id: str) -> bool:
    target = f"chain:{chain_id}"
    return any(lane["default"]["egress"] == target or any(rule["egress"] == target for rule in lane["rules"])
               for lane in lanes_of(document, "").values())


def redact_intent(document: dict) -> dict:
    """The intent with every hop credential masked — what may reach a log, a diff or an API answer."""
    if document.get("schema") != SCHEMA_V2:
        return document
    masked = json.loads(json.dumps(document))
    for chain in masked["chains"].values():
        for hop in chain["hops"]:
            hop["uuid"] = "***"
    return masked


def uses_provider(document: dict, provider: str = "warp") -> bool:
    return any(lane["default"]["egress"] == provider or any(rule["egress"] == provider for rule in lane["rules"])
               for lane in lanes_of(document, "").values())


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
