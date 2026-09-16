"""The `egress` section of the mita config as the panel's compiled document (v0.4, ADR 007).

The panel sends `{"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}],
"rules": [{"domains": [...], "cidrs": [...], "action": "DIRECT|PROXY|REJECT", "proxy":
"warp"|null}, ...]}` — never an address: the provider's endpoint is this host's own
configuration (`MIERU_EGRESS_WARP`). `to_mita` renders that into mita's `egress` (first
match wins, DIRECT when nothing matches) and `from_mita` reads it back; a section naming a
proxy this host has no provider for reads back as None — a `custom` egress the panel
shows but does not claim to own until it applies its own document.

What the spike proved (docs/spikes/VNEXT_ROUTING_ENGINE.md): domain rules match the
hostname the client sends (suffix), `ipRanges` match literal-IP targets only, and a change
takes effect only after mita restarts — so the manager applies egress in `restart` mode.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import socket
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA = 1
# `warp`: the host's WARP proxy-mode endpoint (v0.4). `router`: this service's private
# ingress on the node's Xray-router (v0.5) — SOCKS5 with a credential the manager reads
# from its own state directory when it renders the section, never from the panel.
PROVIDERS = ("warp", "router")
ROUTER_CREDENTIAL = re.compile(r"([A-Za-z0-9._-]{1,64}):([A-Za-z0-9._~-]{16,128})\Z")
CAPABILITIES = ("whole_direct", "whole_warp", "block_domain", "block_cidr", "selective_domain", "selective_cidr")
ACTIONS = ("DIRECT", "PROXY", "REJECT")
MAX_RULES = 128
MAX_SELECTORS = 64
MAX_DOCUMENT_BYTES = 16384
_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class EgressInvalid(ValueError):
    """The document is outside the schema this manager renders."""


class EgressUnreachable(RuntimeError):
    """The provider's endpoint did not answer a SOCKS5 greeting."""


def canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def document_digest(document: dict) -> str:
    return hashlib.sha256(canonical(document)).hexdigest()


def _domain(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise EgressInvalid("invalid domain selector")
    if value == "*":
        return value
    candidate = value.lower().rstrip(".")
    if _DOMAIN.fullmatch(candidate) is None:
        raise EgressInvalid("invalid domain selector")
    return candidate


def _cidr(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise EgressInvalid("invalid cidr selector")
    if value == "*":
        return value
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise EgressInvalid("invalid cidr selector") from exc


def validate_document(document: object) -> dict:
    """The compiled document, normalised, or `EgressInvalid`. Bounded and secret-free."""
    if not isinstance(document, dict) or set(document) - {"schema", "proxies", "rules"}:
        raise EgressInvalid("unknown field in egress document")
    if document.get("schema") != SCHEMA:
        raise EgressInvalid("unsupported egress document schema")
    proxies = document.get("proxies", [])
    if not isinstance(proxies, list) or len(proxies) > len(PROVIDERS):
        raise EgressInvalid("invalid proxy list")
    declared = []
    for proxy in proxies:
        if (not isinstance(proxy, dict) or set(proxy) != {"name", "provider"} or proxy["provider"] not in PROVIDERS
                or proxy["name"] != proxy["provider"] or proxy["name"] in declared):
            raise EgressInvalid("unknown egress provider")
        declared.append(proxy["name"])
    rules = document.get("rules", [])
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise EgressInvalid("invalid rule list")
    normalised_rules = []
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - {"domains", "cidrs", "action", "proxy"}:
            raise EgressInvalid("invalid egress rule")
        domains, cidrs = rule.get("domains", []), rule.get("cidrs", [])
        if not isinstance(domains, list) or not isinstance(cidrs, list):
            raise EgressInvalid("invalid egress rule")
        if len(domains) > MAX_SELECTORS or len(cidrs) > MAX_SELECTORS or not (domains or cidrs):
            raise EgressInvalid("invalid egress rule selectors")
        action = rule.get("action")
        if action not in ACTIONS:
            raise EgressInvalid("invalid egress action")
        proxy = rule.get("proxy")
        if action == "PROXY":
            if proxy not in declared:
                raise EgressInvalid("egress rule names an undeclared proxy")
        elif proxy is not None:
            raise EgressInvalid("egress rule proxy must be null for a non-PROXY action")
        normalised_rules.append({"domains": [_domain(item) for item in domains], "cidrs": [_cidr(item) for item in cidrs],
                                 "action": action, "proxy": proxy})
    normalised = {"schema": SCHEMA, "proxies": [{"name": name, "provider": name} for name in declared],
                  "rules": normalised_rules}
    if len(canonical(normalised)) > MAX_DOCUMENT_BYTES:
        raise EgressInvalid("egress document too large")
    return normalised


def provider_endpoint(provider_url: str | None, name: str = "warp") -> tuple[str, int]:
    """Host and port of the provider's SOCKS5 endpoint; mita speaks SOCKS5 only."""
    if not provider_url:
        raise EgressInvalid(f"egress provider {name} is not configured on this node")
    parts = urlsplit(provider_url)
    if parts.scheme not in ("socks5", "socks5h") or not parts.hostname or not parts.port:
        raise EgressInvalid(f"egress provider {name} must be a socks5:// endpoint for mita")
    return parts.hostname, parts.port


def provider_map(providers: dict[str, str | None] | str | None) -> dict[str, str | None]:
    """The URL per provider name. A bare string (or None) is the v0.4 shape: the WARP URL."""
    if isinstance(providers, dict):
        return providers
    return {"warp": providers or None}


def read_credential(path) -> tuple[str, str]:
    """The `user:password` line of the router ingress credential file, or `EgressInvalid`."""
    try:
        text = Path(path).read_text().strip()
    except OSError as exc:
        raise EgressInvalid("egress provider router credential is unavailable on this node") from exc
    match = ROUTER_CREDENTIAL.fullmatch(text)
    if match is None:
        raise EgressInvalid("egress provider router credential is malformed")
    return match.group(1), match.group(2)


def redact_section(section: object) -> object:
    """A mita `egress` section with every `socks5Authentication` masked: what a `raw`
    (custom) view may show."""
    if not isinstance(section, dict):
        return section
    masked = copy.deepcopy(section)
    for proxy in masked.get("proxies") or []:
        if isinstance(proxy, dict) and "socks5Authentication" in proxy:
            proxy["socks5Authentication"] = {"user": "***", "password": "***"}
    return masked


def to_mita(document: dict, providers: dict[str, str | None] | str | None,
            credentials: dict[str, tuple[str, str]] | None = None) -> dict:
    """mita's `egress` section for a validated document. Empty repeated fields are left out,
    as mita's protobuf JSON renders them, so the readback hash matches; `{}` means "no
    egress key at all" (direct) and the manager drops the key. The `router` proxy carries
    the ingress credential (`socks5Authentication`) the manager read from its file."""
    urls = provider_map(providers)
    proxies = []
    for proxy in document["proxies"]:
        name = proxy["name"]
        host, port = provider_endpoint(urls.get(name), name)
        rendered = {"name": name, "protocol": "SOCKS5_PROXY_PROTOCOL", "host": host, "port": port}
        if name == "router":
            credential = (credentials or {}).get("router")
            if credential is None:
                raise EgressInvalid("egress provider router credential is unavailable on this node")
            rendered["socks5Authentication"] = {"user": credential[0], "password": credential[1]}
        proxies.append(rendered)
    rules = []
    for rule in document["rules"]:
        rendered = {"action": rule["action"]}
        if rule["cidrs"]:
            rendered["ipRanges"] = list(rule["cidrs"])
        if rule["domains"]:
            rendered["domainNames"] = list(rule["domains"])
        if rule["action"] == "PROXY":
            rendered["proxyNames"] = [rule["proxy"]]
        rules.append(rendered)
    section = {}
    if proxies:
        section["proxies"] = proxies
    if rules:
        section["rules"] = rules
    return section


def _endpoints(providers: dict[str, str | None] | str | None) -> dict[str, tuple[str, int]]:
    endpoints = {}
    for name, url in provider_map(providers).items():
        if url:
            try:
                endpoints[name] = provider_endpoint(url, name)
            except EgressInvalid:
                continue
    return endpoints


def from_mita(section: object, providers: dict[str, str | None] | str | None) -> dict | None:
    """The document a mita `egress` section amounts to, or None when it names something this
    host's providers do not (a hand-written proxy, another port) — `custom`. The `router`
    proxy must carry a credential (any: the file's is the truth), the `warp` proxy none."""
    if section is None:
        return {"schema": SCHEMA, "proxies": [], "rules": []}
    if not isinstance(section, dict):
        return None
    proxies = section.get("proxies") or []
    rules = section.get("rules") or []
    endpoints = _endpoints(providers)
    declared = []
    for proxy in proxies:
        if not isinstance(proxy, dict) or proxy.get("protocol") != "SOCKS5_PROXY_PROTOCOL":
            return None
        name = proxy.get("name")
        if name not in PROVIDERS or name in declared or endpoints.get(name) != (proxy.get("host"), proxy.get("port")):
            return None
        if ("socks5Authentication" in proxy) != (name == "router"):
            return None
        declared.append(name)
    document_rules = []
    for rule in rules:
        if not isinstance(rule, dict):
            return None
        action = rule.get("action", "PROXY")
        names = rule.get("proxyNames") or []
        if action not in ACTIONS or (action == "PROXY" and (len(names) != 1 or names[0] not in declared)):
            return None
        document_rules.append({"domains": list(rule.get("domainNames") or []), "cidrs": list(rule.get("ipRanges") or []),
                               "action": action, "proxy": names[0] if action == "PROXY" else None})
    try:
        return validate_document({"schema": SCHEMA, "proxies": [{"name": n, "provider": n} for n in declared],
                                  "rules": document_rules})
    except EgressInvalid:
        return None


def router_credential_stale(section: object, credential: tuple[str, str]) -> bool:
    """The `router` proxy of the running section carries a credential other than the file's
    (a rotation happened while this manager was down)."""
    if not isinstance(section, dict):
        return False
    for proxy in section.get("proxies") or []:
        if isinstance(proxy, dict) and proxy.get("name") == "router":
            auth = proxy.get("socks5Authentication") or {}
            return (auth.get("user"), auth.get("password")) != credential
    return False


def check_reachable(url: str, timeout: float = 3.0, *, auth: bool = False) -> bool:
    """A SOCKS5 greeting — offering no authentication, or (`auth`) the username/password
    method the router ingress demands, without completing it; never raises — the answer is
    the fact."""
    try:
        host, port = provider_endpoint(url)
    except EgressInvalid:
        return False
    method = b"\x02" if auth else b"\x00"
    try:
        with socket.create_connection((host, port), timeout=timeout) as stream:
            stream.settimeout(timeout)
            stream.sendall(b"\x05\x01" + method)
            return stream.recv(2) == b"\x05" + method
    except OSError:
        return False
