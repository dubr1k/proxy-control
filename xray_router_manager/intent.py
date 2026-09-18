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
    # v0.8: the geodata files are the operator's to choose and refresh (`/v1/geodata`); a rule
    # may stand on what the sniffer saw (`bittorrent`, `tls`, `http`, `quic`).
    "geodata", "block_protocol", "selective_protocol",
    # v0.8: outbounds of the operator's own (`exits` of a schema-2 intent, `/v1/exits/test`).
    "custom_exits",
)
# An operator's own outbound (v0.8): what Xray dials on the operator's behalf.
EXIT_PROTOCOLS = ("socks", "http", "vless", "trojan", "shadowsocks")
EXIT_NETWORKS = ("tcp", "ws", "grpc", "xhttp")
EXIT_SECURITY = ("none", "tls", "reality")
EXIT_FLOWS = ("", "xtls-rprx-vision")
SS_METHODS = ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
              "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "none")
MAX_EXITS = 16
_EXIT_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
_FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")
SNIFFED_PROTOCOLS = ("http", "tls", "quic", "bittorrent")
MAX_PROTOCOLS = 4
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


def _protocol_name(value: object) -> str:
    if not isinstance(value, str) or value not in SNIFFED_PROTOCOLS:
        raise EgressInvalid("invalid protocol selector")
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


def _egress(action: str, egress: object, *, label: str, chains: tuple[str, ...] = (), exits: tuple[str, ...] = ()) -> str | None:
    if action == "egress":
        if egress in PROVIDERS:
            return egress
        if isinstance(egress, str) and egress.startswith("chain:") and egress[6:] in chains:
            return egress
        if isinstance(egress, str) and egress.startswith("exit:") and egress[5:] in exits:
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
    lane = _validate_lane(document, chains=(), exits=())
    if len(canonical(lane)) > MAX_DOCUMENT_BYTES:
        raise EgressInvalid("routing intent too large")
    return {"schema": SCHEMA, **lane}


def _validate_lane(document: dict, *, chains: tuple[str, ...], exits: tuple[str, ...] = ()) -> dict:
    """One lane's body — a default and its first-match rules — normalised."""
    if not isinstance(document, dict) or set(document) - {"schema", "default", "rules"}:
        raise EgressInvalid("unknown field in routing intent")
    default = document.get("default")
    if not isinstance(default, dict) or set(default) - {"action", "egress"} or default.get("action") not in DEFAULT_ACTIONS:
        raise EgressInvalid("invalid default")
    default_action = default["action"]
    default_egress = _egress(default_action, default.get("egress"), label="default", chains=chains, exits=exits)
    rules = document.get("rules", [])
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise EgressInvalid("invalid rules list")
    normalised_rules = []
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - {"domains", "geosites", "cidrs", "geoips", "ports", "protocols", "action", "egress"}:
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
            "egress": _egress(rule["action"], rule.get("egress"), label="rule", chains=chains, exits=exits),
        }
        protocols = _selectors(rule, "protocols", _protocol_name, MAX_PROTOCOLS)
        if protocols:
            entry["protocols"] = protocols
        if not any(entry.get(key) for key in ("domains", "geosites", "cidrs", "geoips", "ports", "protocols")):
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


def _host(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EgressInvalid(f"invalid {label}")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        host = _domain(value)
        if host.startswith("*."):
            raise EgressInvalid(f"invalid {label}")
        return host


def _text(value: object, label: str, *, limit: int = 256, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or (not value and not allow_empty) or any(c in value for c in "\r\n\x00"):
        raise EgressInvalid(f"invalid {label}")
    return value


def validate_exit(value: object) -> dict:
    """One custom outbound of the intent: protocol, where to dial, the credential, the
    transport and the security layer — bounded, and nothing Xray would not understand."""
    if not isinstance(value, dict) or set(value) - {"protocol", "address", "port", "credential", "transport", "security", "method", "flow"}:
        raise EgressInvalid("invalid exit")
    protocol = value.get("protocol")
    if protocol not in EXIT_PROTOCOLS:
        raise EgressInvalid("invalid exit protocol")
    address = _host(value.get("address"), "exit address")
    port = value.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise EgressInvalid("invalid exit port")
    credential = value.get("credential") or {}
    if not isinstance(credential, dict) or set(credential) - {"username", "password", "uuid"}:
        raise EgressInvalid("invalid exit credential")
    out_credential: dict = {}
    if protocol in ("socks", "http"):
        username = credential.get("username")
        password = credential.get("password")
        if (username is None) != (password is None):
            raise EgressInvalid("exit credential needs both username and password")
        if username is not None:
            out_credential = {"username": _text(username, "exit username", limit=128), "password": _text(password, "exit password", limit=256)}
    elif protocol == "vless":
        uuid = credential.get("uuid")
        if not isinstance(uuid, str) or _UUID.fullmatch(uuid) is None:
            raise EgressInvalid("invalid exit uuid")
        out_credential = {"uuid": uuid}
    else:  # trojan, shadowsocks
        out_credential = {"password": _text(credential.get("password"), "exit password", limit=256)}
    entry: dict = {"protocol": protocol, "address": address, "port": port, "credential": out_credential}
    if protocol == "shadowsocks":
        method = value.get("method")
        if method not in SS_METHODS:
            raise EgressInvalid("invalid shadowsocks method")
        entry["method"] = method
    if protocol == "vless":
        flow = value.get("flow") or ""
        if flow not in EXIT_FLOWS:
            raise EgressInvalid("invalid exit flow")
        entry["flow"] = flow
    transport = value.get("transport") or {"network": "tcp"}
    if not isinstance(transport, dict) or set(transport) - {"network", "path", "host", "service_name"}:
        raise EgressInvalid("invalid exit transport")
    network = transport.get("network", "tcp")
    if network not in EXIT_NETWORKS:
        raise EgressInvalid("invalid exit transport network")
    if protocol in ("socks", "http", "shadowsocks") and network != "tcp":
        raise EgressInvalid("this exit protocol runs over tcp only")
    out_transport = {"network": network}
    for key in ("path", "host", "service_name"):
        if transport.get(key) not in (None, ""):
            out_transport[key] = _text(transport[key], f"exit transport {key}", limit=512)
    entry["transport"] = out_transport
    security = value.get("security") or {"kind": "none"}
    if not isinstance(security, dict) or set(security) - {"kind", "server_name", "fingerprint", "alpn", "public_key", "short_id", "insecure"}:
        raise EgressInvalid("invalid exit security")
    kind = security.get("kind", "none")
    if kind not in EXIT_SECURITY:
        raise EgressInvalid("invalid exit security kind")
    if protocol in ("socks", "http", "shadowsocks") and kind == "reality":
        raise EgressInvalid("reality needs vless or trojan")
    out_security: dict = {"kind": kind}
    if kind != "none":
        if security.get("server_name") not in (None, ""):
            out_security["server_name"] = _host(security["server_name"], "exit server name")
        fingerprint = security.get("fingerprint") or "chrome"
        if fingerprint not in _FINGERPRINTS:
            raise EgressInvalid("invalid exit fingerprint")
        out_security["fingerprint"] = fingerprint
        alpn = security.get("alpn")
        if alpn not in (None, ""):
            if not isinstance(alpn, list) or len(alpn) > 4 or not all(isinstance(item, str) and 0 < len(item) <= 16 for item in alpn):
                raise EgressInvalid("invalid exit alpn")
            out_security["alpn"] = list(alpn)
        if kind == "tls" and security.get("insecure") is True:
            out_security["insecure"] = True
    if kind == "reality":
        public_key, short_id = security.get("public_key"), security.get("short_id") or ""
        if not isinstance(public_key, str) or _PUBLIC_KEY.fullmatch(public_key) is None:
            raise EgressInvalid("invalid exit public key")
        if not isinstance(short_id, str) or (short_id and _SHORT_ID.fullmatch(short_id) is None):
            raise EgressInvalid("invalid exit short id")
        if "server_name" not in out_security:
            raise EgressInvalid("reality needs a server name")
        out_security.update({"public_key": public_key, "short_id": short_id})
    if protocol == "vless" and entry["flow"] and (network != "tcp" or kind == "none"):
        raise EgressInvalid("xtls-rprx-vision needs tcp with tls or reality")
    entry["security"] = out_security
    return entry


def _validate_v2(document: dict) -> dict:
    if set(document) - {"schema", "lanes", "chains", "exits"}:
        raise EgressInvalid("unknown field in routing intent")
    exits = document.get("exits", {})
    if not isinstance(exits, dict) or len(exits) > MAX_EXITS:
        raise EgressInvalid("invalid exits list")
    normalised_exits: dict[str, dict] = {}
    for exit_id, exit_ in exits.items():
        if not isinstance(exit_id, str) or _EXIT_ID.fullmatch(exit_id) is None:
            raise EgressInvalid("invalid exit id")
        normalised_exits[exit_id] = validate_exit(exit_)
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
        normalised_lanes[lane_id] = _validate_lane(lane, chains=tuple(normalised_chains), exits=tuple(normalised_exits))
    if sum(1 for lane_id in normalised_lanes if lane_id.startswith("svc:")) != 1:
        raise EgressInvalid("exactly one service lane is required")
    normalised = {"schema": SCHEMA_V2, "lanes": normalised_lanes, "chains": normalised_chains}
    if normalised_exits:
        # Only when named: a v0.7 router refuses an unknown key, and a document without exits
        # hashes as it always did.
        normalised["exits"] = normalised_exits
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
    """The intent with every hop credential and exit credential masked — what may reach a
    log, a diff or an API answer."""
    if document.get("schema") != SCHEMA_V2:
        return document
    masked = json.loads(json.dumps(document))
    for chain in masked["chains"].values():
        for hop in chain["hops"]:
            hop["uuid"] = "***"
    for exit_ in masked.get("exits", {}).values():
        exit_["credential"] = {key: "***" for key in exit_.get("credential", {})}
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
