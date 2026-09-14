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

import hashlib
import ipaddress
import json
import re
import socket
from urllib.parse import urlsplit

SCHEMA = 1
PROVIDERS = ("warp",)
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


def provider_endpoint(provider_url: str | None) -> tuple[str, int]:
    """Host and port of the provider's SOCKS5 endpoint; mita speaks SOCKS5 only."""
    if not provider_url:
        raise EgressInvalid("egress provider warp is not configured on this node")
    parts = urlsplit(provider_url)
    if parts.scheme not in ("socks5", "socks5h") or not parts.hostname or not parts.port:
        raise EgressInvalid("egress provider warp must be a socks5:// endpoint for mita")
    return parts.hostname, parts.port


def to_mita(document: dict, provider_url: str | None) -> dict:
    """mita's `egress` section for a validated document. Empty repeated fields are left out,
    as mita's protobuf JSON renders them, so the readback hash matches; `{}` means "no
    egress key at all" (direct) and the manager drops the key."""
    proxies = []
    for proxy in document["proxies"]:
        host, port = provider_endpoint(provider_url)
        proxies.append({"name": proxy["name"], "protocol": "SOCKS5_PROXY_PROTOCOL", "host": host, "port": port})
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


def from_mita(section: object, provider_url: str | None) -> dict | None:
    """The document a mita `egress` section amounts to, or None when it names something this
    host's provider does not (a hand-written proxy, another port) — `custom`."""
    if section is None:
        return {"schema": SCHEMA, "proxies": [], "rules": []}
    if not isinstance(section, dict):
        return None
    proxies = section.get("proxies") or []
    rules = section.get("rules") or []
    endpoint = None
    if provider_url:
        try:
            endpoint = provider_endpoint(provider_url)
        except EgressInvalid:
            endpoint = None
    declared = []
    for proxy in proxies:
        if not isinstance(proxy, dict) or proxy.get("protocol") != "SOCKS5_PROXY_PROTOCOL" or "socks5Authentication" in proxy:
            return None
        if endpoint is None or (proxy.get("host"), proxy.get("port")) != endpoint or proxy.get("name") != "warp":
            return None
        declared.append("warp")
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
