"""The egress block of the NaiveProxy Caddyfile (v0.4 routing, ADR 007).

The manager owns exactly one block inside `forward_proxy`:

    # BEGIN NAIVE-MANAGER EGRESS
    upstream socks5://127.0.0.1:45000
    acl {
        deny example.com *.example.com 10.0.0.0/8
    }
    # END NAIVE-MANAGER EGRESS

What the panel sends is a *compiled document* — `{"schema": 1, "upstream": {"provider":
"warp"} | null, "acl": [{"deny": [...]}, ...]}` — never an address, a path or a raw
directive: the provider's URL is this host's own configuration (`NAIVE_EGRESS_WARP`).
The pinned forwardproxy skips its ACL when an upstream is set (routing spike, 2026-09-14),
so a document that carries both is refused here as well as in the panel's compiler.

A Caddyfile written before v0.4 (or by hand) has an `upstream` line without markers:
`parse()` reports it as `custom` (or as the provider's when the URL matches), and the
first `render()` moves it into the managed block, keeping the original lines beside the
journal so a rollback puts them back byte for byte. Everything outside the block is left
untouched — the manager's user block and accounting block included.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlsplit

EGRESS_BEGIN = "# BEGIN NAIVE-MANAGER EGRESS"
EGRESS_END = "# END NAIVE-MANAGER EGRESS"
SCHEMA = 1
# `warp`: the host's WARP proxy-mode endpoint (v0.4). `router`: this service's private
# ingress on the node's Xray-router (v0.5) — a SOCKS5 endpoint with a credential the
# manager reads from its own state directory when it renders the line, never from the panel.
PROVIDERS = ("warp", "router")
# What the spike proved this build enforces (docs/spikes/VNEXT_ROUTING_ENGINE.md); a block
# rule holds only without an upstream, which `validate_document` enforces.
CAPABILITIES = ("whole_direct", "whole_warp", "block_domain", "block_cidr")
MAX_RULES = 128
MAX_SUBJECTS = 64
MAX_DOCUMENT_BYTES = 16384
_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_UPSTREAM = re.compile(r"^\s*upstream\s+(\S+)\s*(?:#.*)?$")
_ACL_OPEN = re.compile(r"^\s*acl\s*\{\s*(?:#.*)?$")
_DENY = re.compile(r"^\s*deny\s+(.+?)\s*$")
_PROBE_RESISTANCE = re.compile(r"^\s*probe_resistance(?:\s|$)")
_USERINFO = re.compile(r"(?<=://)[^/@\s]+@")
ROUTER_CREDENTIAL = re.compile(r"([A-Za-z0-9._-]{1,64}):([A-Za-z0-9._~-]{16,128})\Z")


class EgressInvalid(ValueError):
    """The document is outside the schema this manager renders."""


class EgressUnreachable(RuntimeError):
    """The provider's endpoint did not answer a SOCKS5 greeting / a TCP connect."""


@dataclass(frozen=True)
class ParsedEgress:
    mode: str  # direct | proxy | custom
    upstream: str | None
    acl_deny: tuple[str, ...]
    managed: bool
    revision: str
    # The lines the manager will replace: the managed block, or the unmanaged `upstream` /
    # `acl` lines a first apply adopts (kept for the rollback to restore them verbatim).
    raw_lines: tuple[str, ...] = field(default_factory=tuple)


def forward_proxy_bounds(lines: list[str]) -> tuple[int, int]:
    """Start and end line indexes of the service's own `forward_proxy { … }` block — the one
    outside the lanes block (v0.7), whose handlers the lanes module owns."""
    from .lanes import LanesInvalid, outside_lanes

    try:
        outside = outside_lanes(lines)
    except LanesInvalid as exc:
        raise EgressInvalid(str(exc)) from exc
    directives = [index for index in outside if re.match(r"^\s*forward_proxy(?:\s|$)", lines[index])]
    if len(directives) != 1:
        raise EgressInvalid("exactly one forward_proxy block is required")
    start = directives[0]
    if re.fullmatch(r"\s*forward_proxy\s*\{\s*(?:#.*)?", lines[start]) is None:
        raise EgressInvalid("forward_proxy must use managed block form")
    depth = 0
    for index in range(start, len(lines)):
        depth += lines[index].count("{") - lines[index].count("}")
        if index > start and depth == 0:
            return start, index
    raise EgressInvalid("unterminated forward_proxy block")


def valid_subject(value: str) -> str:
    """One ACL subject: a domain, a `*.` suffix, or a CIDR — as forwardproxy parses them."""
    if not isinstance(value, str) or not value or len(value) > 253 or any(c.isspace() for c in value):
        raise EgressInvalid("invalid acl subject")
    candidate = value.lower()
    try:
        return str(ipaddress.ip_network(candidate, strict=False))
    except ValueError:
        pass
    if "/" in candidate:
        raise EgressInvalid("invalid acl subject")
    host = candidate[2:] if candidate.startswith("*.") else candidate
    if _DOMAIN.fullmatch(host) is None:
        raise EgressInvalid("invalid acl subject")
    return candidate


def validate_document(document: object) -> dict:
    """The compiled document, normalised, or `EgressInvalid`. Bounded and secret-free."""
    if not isinstance(document, dict) or set(document) - {"schema", "upstream", "acl"}:
        raise EgressInvalid("unknown field in egress document")
    if document.get("schema") != SCHEMA:
        raise EgressInvalid("unsupported egress document schema")
    upstream = document.get("upstream")
    if upstream is not None:
        if not isinstance(upstream, dict) or set(upstream) != {"provider"} or upstream["provider"] not in PROVIDERS:
            raise EgressInvalid("unknown egress provider")
        upstream = {"provider": upstream["provider"]}
    acl = document.get("acl", [])
    if not isinstance(acl, list) or len(acl) > MAX_RULES:
        raise EgressInvalid("invalid acl list")
    rules = []
    for rule in acl:
        if not isinstance(rule, dict) or set(rule) != {"deny"} or not isinstance(rule["deny"], list) or not rule["deny"]:
            raise EgressInvalid("invalid acl rule")
        if len(rule["deny"]) > MAX_SUBJECTS:
            raise EgressInvalid("too many acl subjects")
        rules.append({"deny": [valid_subject(item) for item in rule["deny"]]})
    if upstream is not None and rules:
        raise EgressInvalid("acl is not enforced by forwardproxy when an upstream is set")
    normalised = {"schema": SCHEMA, "upstream": upstream, "acl": rules}
    if len(canonical(normalised)) > MAX_DOCUMENT_BYTES:
        raise EgressInvalid("egress document too large")
    return normalised


def canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def document_digest(document: dict) -> str:
    return hashlib.sha256(canonical(document)).hexdigest()


def parse(text: str) -> ParsedEgress:
    lines = text.splitlines()
    start, end = forward_proxy_bounds(lines)
    begins = [i for i in range(start + 1, end) if lines[i].strip() == EGRESS_BEGIN]
    ends = [i for i in range(start + 1, end) if lines[i].strip() == EGRESS_END]
    if len(begins) > 1 or len(ends) > 1 or len(begins) != len(ends):
        raise EgressInvalid("managed egress block must have exactly one marker pair")
    if begins:
        block_start, block_end = begins[0], ends[0]
        if block_start >= block_end:
            raise EgressInvalid("managed egress block markers are out of order")
        body = list(range(block_start + 1, block_end))
        outside = [i for i in range(start + 1, end) if i not in range(block_start, block_end + 1)]
        managed = True
    else:
        body, outside, managed = [], list(range(start + 1, end)), False
    for index in outside:
        if _UPSTREAM.match(lines[index]) or _ACL_OPEN.match(lines[index]):
            if managed:
                raise EgressInvalid("upstream or acl directive outside the managed egress block")
    raw_indexes = list(range(begins[0], ends[0] + 1)) if managed else _unmanaged_egress_lines(lines, outside)
    scan = body if managed else raw_indexes
    upstream, deny = None, []
    index = 0
    scan_lines = [lines[i] for i in scan]
    while index < len(scan_lines):
        line = scan_lines[index]
        if match := _UPSTREAM.match(line):
            if upstream is not None:
                raise EgressInvalid("more than one upstream directive")
            upstream = match.group(1)
        elif _ACL_OPEN.match(line):
            index += 1
            while index < len(scan_lines) and scan_lines[index].strip() != "}":
                if match := _DENY.match(scan_lines[index]):
                    deny.extend(match.group(1).split())
                elif scan_lines[index].strip() and not scan_lines[index].strip().startswith("#"):
                    raise EgressInvalid("unsupported acl directive")
                index += 1
        elif line.strip() and not line.strip().startswith("#") and managed:
            raise EgressInvalid("unsupported directive in the managed egress block")
        index += 1
    raw = tuple(lines[i] for i in raw_indexes)
    mode = "proxy" if upstream else "direct"
    if upstream and not managed:
        mode = "custom"
    return ParsedEgress(mode=mode, upstream=upstream, acl_deny=tuple(deny), managed=managed,
                        revision=revision_of_lines(raw), raw_lines=raw)


def _unmanaged_egress_lines(lines: list[str], indexes: list[int]) -> list[int]:
    """The indexes of unmanaged `upstream` lines and whole `acl { … }` blocks."""
    found: list[int] = []
    skip_until = -1
    for index in indexes:
        if index <= skip_until:
            found.append(index)
            continue
        if _UPSTREAM.match(lines[index]):
            found.append(index)
        elif _ACL_OPEN.match(lines[index]):
            depth = 0
            for probe in range(index, indexes[-1] + 1):
                depth += lines[probe].count("{") - lines[probe].count("}")
                if depth == 0:
                    skip_until = probe
                    break
            else:
                raise EgressInvalid("unterminated acl block")
            found.append(index)
    return found


def redact_userinfo(text: str) -> str:
    """Every `scheme://user:pass@host` in `text` with its userinfo masked: what the API may
    show of a hand-written upstream (the journal keeps the bytes for the rollback)."""
    return _USERINFO.sub("***@", text)


def revision_of_lines(raw: tuple[str, ...]) -> str:
    """The revision the panel pins an apply to: the managed block (or the adopted lines)."""
    return hashlib.sha256(("\n".join(raw) or "direct").encode()).hexdigest()


def revision_of(text: str) -> str:
    return parse(text).revision


def provider_map(providers: dict[str, str | None] | str | None) -> dict[str, str | None]:
    """The URL per provider name. A bare string (or None) is the v0.4 shape: the WARP URL."""
    if isinstance(providers, dict):
        return providers
    return {"warp": providers or None}


def resolve_provider(document: dict, providers: dict[str, str | None] | str | None) -> str | None:
    """The upstream URL the document names, or None for direct; `EgressInvalid` when the
    provider is not configured on this host (`NAIVE_EGRESS_WARP` / `NAIVE_EGRESS_ROUTER` empty)."""
    if document["upstream"] is None:
        return None
    name = document["upstream"]["provider"]
    url = provider_map(providers).get(name)
    if not url:
        raise EgressInvalid(f"egress provider {name} is not configured on this node")
    return url


def strip_userinfo(url: str) -> str:
    """The endpoint without its credential: what views and comparisons use."""
    return _USERINFO.sub("", url)


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


def with_credential(url: str, credential: tuple[str, str]) -> str:
    """`socks5://user:pass@host:port` for the router ingress (RFC 3986 userinfo, escaped)."""
    user, password = (quote(part, safe="") for part in credential)
    parts = urlsplit(strip_userinfo(url))
    return f"{parts.scheme}://{user}:{password}@{parts.netloc}"


def block_lines(document: dict, providers: dict[str, str | None] | str | None, indent: str) -> list[str]:
    upstream = resolve_provider(document, providers)
    lines = [f"{indent}{EGRESS_BEGIN}"]
    if upstream:
        lines.append(f"{indent}upstream {upstream}")
    for rule in document["acl"]:
        lines += [f"{indent}acl {{", f"{indent}    deny {' '.join(rule['deny'])}", f"{indent}}}"]
    lines.append(f"{indent}{EGRESS_END}")
    return lines


def render(text: str, document: dict, providers: dict[str, str | None] | str | None) -> str:
    """The Caddyfile with the managed block carrying `document`, everything else verbatim."""
    parsed = parse(text)
    lines = text.splitlines()
    return _replace(lines, parsed, block_lines(document, providers, _indent(lines, parsed)))


def render_raw(text: str, raw_lines: tuple[str, ...]) -> str:
    """The Caddyfile with the managed block replaced by `raw_lines` verbatim (a rollback to
    the lines a first apply adopted)."""
    parsed = parse(text)
    lines = text.splitlines()
    return _replace(lines, parsed, list(raw_lines))


def _indent(lines: list[str], parsed: ParsedEgress) -> str:
    start, end = forward_proxy_bounds(lines)
    for index in range(start + 1, end):
        if lines[index].strip():
            return re.match(r"^(\s*)", lines[index]).group(1)
    return re.match(r"^(\s*)", lines[start]).group(1) + "    "


def _replace(lines: list[str], parsed: ParsedEgress, block: list[str]) -> str:
    start, end = forward_proxy_bounds(lines)
    if parsed.managed:
        begin = next(i for i in range(start + 1, end) if lines[i].strip() == EGRESS_BEGIN)
        finish = next(i for i in range(start + 1, end) if lines[i].strip() == EGRESS_END)
        lines[begin:finish + 1] = block
        return "\n".join(lines) + "\n"
    # Adoption: the unmanaged lines go, the block lands after `probe_resistance` (or at the
    # end of the handler) — where the installer's template would have put it.
    drop = set(_unmanaged_egress_lines(lines, list(range(start + 1, end))))
    kept = [line for i, line in enumerate(lines) if i not in drop]
    start, end = forward_proxy_bounds(kept)
    anchor = next((i for i in range(start + 1, end) if _PROBE_RESISTANCE.match(kept[i])), None)
    position = anchor + 1 if anchor is not None else end
    kept[position:position] = block
    return "\n".join(kept) + "\n"


def check_reachable(url: str, timeout: float = 3.0, *, auth: bool = False) -> bool:
    """A SOCKS5 greeting for `socks5://` — offering no authentication, or (`auth`) the
    username/password method the router ingress demands, without completing it; a TCP
    connect for `http(s)://`. Never raises: the answer is the fact."""
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port
    if not host or not port:
        return False
    method = b"\x02" if auth else b"\x00"
    try:
        with socket.create_connection((host, port), timeout=timeout) as stream:
            if parts.scheme in ("socks5", "socks5h"):
                stream.settimeout(timeout)
                stream.sendall(b"\x05\x01" + method)
                return stream.recv(2) == b"\x05" + method
            return True
    except OSError:
        return False
