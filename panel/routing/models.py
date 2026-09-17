"""The engine-neutral routing policy (ADR 006) and what compiling it produces.

A policy says what the operator wants — a default for the whole service, then ordered
first-match rules — in one vocabulary for every backend. It never names an address, a
path or a raw directive: the compiler turns it into the document a manager validates
and the manager alone knows the provider's endpoint. Limits are the spec's (§5): 128
rules, 64 domains and 64 CIDRs and 32 ports per rule, a 120-character note.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Protocol = Literal["naive", "mieru"]
# The native backend of each data plane (v0.4) or the node's dedicated Xray-router (v0.5).
Backend = Literal["naive_native", "mieru_native", "xray_router"]
Action = Literal["direct", "block", "egress"]
DefaultAction = Literal["direct", "egress"]
# An egress names where the connection leaves (v0.7): this node's WARP, or a chain of other
# nodes' relays — `node:<guid>[,<guid>[,<guid>]][:warp]`, the last hop exiting direct or
# through its own WARP. A `str` here; `normalise_exit` is the grammar.
Egress = str
Fallback = Literal["fail_closed", "approved_direct"]
State = Literal["draft", "applying", "applied", "failed", "rolled_back"]

BACKEND_FOR: dict[str, str] = {"naive": "naive_native", "mieru": "mieru_native"}
NATIVE_BACKEND_FOR = BACKEND_FOR
ROUTER_BACKEND = "xray_router"
MAX_RULES = 128
MAX_SELECTORS = 64
MAX_PORTS = 32
MAX_NOTE = 120
# "2": rules may name geosite/geoip codes and stand on ports alone (v0.5).
COMPILER_VERSION = "2"

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_GUID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
LANE_SERVICE = "svc"
LANE_GRANT = re.compile(r"grant:[A-Za-z0-9_-]{1,64}\Z")
MAX_CHAIN_HOPS = 3
_DOMAIN = re.compile(rf"(?=.{{1,253}}\Z)(?:{_LABEL}\.)*{_LABEL}\Z")
_PORT_RANGE = re.compile(r"^([0-9]{1,5})-([0-9]{1,5})$")
_GEO_CODE = re.compile(r"[a-z0-9][a-z0-9@!_-]{0,63}\Z")


def normalise_exit(value: object) -> str:
    """`warp`, or `node:<guid>[,<guid>…][:warp]` — lower-cased keyword and exit, guids as
    given; a chain names each node once and at most three."""
    if not isinstance(value, str) or not value:
        raise ValueError("an egress must be warp or node:<guid>")
    text = value.strip()
    if text.lower() == "warp":
        return "warp"
    kind, _sep, rest = text.partition(":")
    if kind.lower() != "node" or not rest:
        raise ValueError("an egress must be warp or node:<guid>")
    via = "direct"
    if ":" in rest:
        rest, _sep, tail = rest.partition(":")
        if tail.lower() != "warp":
            raise ValueError("a chain exits direct or through the last node's warp")
        via = "warp"
    guids = rest.split(",")
    if not 1 <= len(guids) <= MAX_CHAIN_HOPS or len(set(guids)) != len(guids) or any(_GUID.fullmatch(g) is None for g in guids):
        raise ValueError("a chain names one to three distinct nodes")
    return "node:" + ",".join(guids) + (":warp" if via == "warp" else "")


def exit_hops(value: str | None) -> tuple[list[str], str | None]:
    """The node guids a normalised exit chains through and the last hop's exit; `warp` and
    None have no hops."""
    if not value or not value.startswith("node:"):
        return [], None
    body = value[5:]
    via = "direct"
    if body.endswith(":warp"):
        body, via = body[:-5], "warp"
    return body.split(","), via


def is_node_exit(value: object) -> bool:
    return isinstance(value, str) and value.startswith("node:")


def normalise_lane(value: object) -> str:
    if value in (None, "", LANE_SERVICE):
        return LANE_SERVICE
    if isinstance(value, str) and LANE_GRANT.fullmatch(value):
        return value
    raise ValueError("a lane is svc or grant:<id>")


def backends_for(protocol: str) -> tuple[str, ...]:
    """The backends a protocol's policy may target: its native one, and the router."""
    native = BACKEND_FOR.get(protocol)
    return () if native is None else (native, ROUTER_BACKEND)


def normalise_domain(value: str) -> str:
    """Lower-cased IDNA, an optional `*.` prefix meaning "any subdomain"."""
    if not isinstance(value, str):
        raise ValueError("domain must be a string")
    candidate = value.strip().rstrip(".").lower()
    wildcard = candidate.startswith("*.")
    host = candidate[2:] if wildcard else candidate
    if not host or "*" in host or "/" in host or any(c.isspace() for c in host):
        raise ValueError(f"invalid domain: {value!r}")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid domain: {value!r}") from exc
    if _DOMAIN.fullmatch(host) is None:
        raise ValueError(f"invalid domain: {value!r}")
    return f"*.{host}" if wildcard else host


def normalise_cidr(value: str) -> str:
    """A network in canonical form; a bare address becomes its /32 or /128."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("cidr must be a string")
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise ValueError(f"invalid cidr: {value!r}") from exc


def normalise_geo_code(value: str, kind: str) -> str:
    """A `geosite:`/`geoip:` code as the Xray geodata names it (lower-case, no prefix).
    `private` is the router's own bypass, never a rule."""
    if not isinstance(value, str):
        raise ValueError(f"{kind} code must be a string")
    code = value.strip().lower()
    if code.startswith(f"{kind}:"):
        code = code[len(kind) + 1:]
    if _GEO_CODE.fullmatch(code) is None:
        raise ValueError(f"invalid {kind} code: {value!r}")
    if kind == "geoip" and code == "private":
        raise ValueError("geoip:private is the router's bypass, not a rule")
    return code


def normalise_port(value: int | str) -> int | str:
    if isinstance(value, bool):
        raise ValueError("invalid port")
    if isinstance(value, int):
        if not 1 <= value <= 65535:
            raise ValueError(f"port out of range: {value}")
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return normalise_port(int(text))
        match = _PORT_RANGE.match(text)
        if match and 1 <= int(match[1]) <= int(match[2]) <= 65535:
            return f"{int(match[1])}-{int(match[2])}"
    raise ValueError(f"invalid port: {value!r}")


def _unique(items: list) -> list:
    seen: list = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


class RuleMatch(BaseModel):
    """What a rule matches: any of its domains, geosite codes, CIDRs or geoip codes, on any
    of its ports. A rule may stand on ports alone (the router enforces it; native backends
    say `unsupported`)."""

    model_config = ConfigDict(extra="forbid")
    domains: list[str] = Field(default_factory=list, max_length=MAX_SELECTORS)
    cidrs: list[str] = Field(default_factory=list, max_length=MAX_SELECTORS)
    ports: list[int | str] = Field(default_factory=list, max_length=MAX_PORTS)
    geosites: list[str] = Field(default_factory=list, max_length=MAX_SELECTORS)
    geoips: list[str] = Field(default_factory=list, max_length=MAX_SELECTORS)

    @field_validator("domains")
    @classmethod
    def _domains(cls, value: list[str]) -> list[str]:
        return _unique([normalise_domain(item) for item in value])

    @field_validator("cidrs")
    @classmethod
    def _cidrs(cls, value: list[str]) -> list[str]:
        return _unique([normalise_cidr(item) for item in value])

    @field_validator("geosites")
    @classmethod
    def _geosites(cls, value: list[str]) -> list[str]:
        return _unique([normalise_geo_code(item, "geosite") for item in value])

    @field_validator("geoips")
    @classmethod
    def _geoips(cls, value: list[str]) -> list[str]:
        return _unique([normalise_geo_code(item, "geoip") for item in value])

    @field_validator("ports", mode="before")
    @classmethod
    def _ports(cls, value: object) -> list[int | str]:
        # Before pydantic's own coercion: a bool must not slip through as 0 or 1.
        if not isinstance(value, list):
            raise ValueError("ports must be a list")
        return _unique([normalise_port(item) for item in value])

    @model_validator(mode="after")
    def _not_empty(self):
        if not (self.domains or self.cidrs or self.geosites or self.geoips or self.ports):
            raise ValueError("a rule must name at least one domain, geosite, cidr, geoip or port")
        return self

    @property
    def selectors(self) -> bool:
        """True when the rule narrows by destination name or address (not by port alone)."""
        return bool(self.domains or self.cidrs or self.geosites or self.geoips)


class RoutingRule(BaseModel):
    """One first-match rule. `id` is the server's; a rule sent without one is new.
    `position` is the order the server stored — on input the list order wins."""

    model_config = ConfigDict(extra="forbid")
    id: str | None = Field(default=None, pattern=r"^[0-9a-f-]{36}$")
    position: int = Field(default=0, ge=0)
    enabled: bool = True
    match: RuleMatch
    action: Action
    egress: Egress | None = None
    note: str = Field(default="", max_length=MAX_NOTE)

    @field_validator("egress")
    @classmethod
    def _egress(cls, value: str | None) -> str | None:
        return None if value is None else normalise_exit(value)

    @model_validator(mode="after")
    def _egress_only_for_egress(self):
        if self.action == "egress" and self.egress is None:
            raise ValueError("an egress rule must name its egress")
        if self.action != "egress" and self.egress is not None:
            raise ValueError("only an egress rule names an egress")
        return self


class _Intent(BaseModel):
    """The operator's intent: a default for the whole service, then first-match rules."""

    model_config = ConfigDict(extra="forbid")
    default_action: DefaultAction = "direct"
    default_egress: Egress | None = None
    fallback: Fallback = "fail_closed"
    rules: list[RoutingRule] = Field(default_factory=list, max_length=MAX_RULES)

    @field_validator("default_egress")
    @classmethod
    def _default_egress_value(cls, value: str | None) -> str | None:
        return None if value is None else normalise_exit(value)

    @model_validator(mode="after")
    def _default_egress(self):
        if self.default_action == "egress" and self.default_egress is None:
            raise ValueError("a default of egress must name its egress")
        if self.default_action != "egress" and self.default_egress is not None:
            raise ValueError("only a default of egress names an egress")
        return self

    def exits(self) -> list[str]:
        """Every distinct egress the intent names, the default first, in rule order."""
        found: list[str] = []
        for value in [self.default_egress, *(rule.egress for rule in self.rules if rule.enabled)]:
            if value is not None and value not in found:
                found.append(value)
        return found

    def node_exits(self) -> list[str]:
        return [value for value in self.exits() if is_node_exit(value)]


class PolicyInput(_Intent):
    """What `PUT` accepts: the intent without the server's bookkeeping. `backend` may be
    left out — the policy keeps the backend it has (its native one at birth) — but a named
    one must be one the protocol can run on (`backends_for`)."""

    backend: Backend | None = None

    @classmethod
    def from_policy(cls, policy: RoutingPolicy) -> PolicyInput:
        return cls.model_validate(policy.model_dump(include=set(cls.model_fields)))


class RoutingPolicy(_Intent):
    """A stored policy: the intent plus where it stands on the node. `lane` (v0.7) is
    `svc` — the service's own policy — or `grant:<id>`, a client's own lane."""

    id: str
    node_id: str
    protocol: Protocol
    lane: str = LANE_SERVICE
    backend: Backend
    revision: int = Field(ge=1)
    state: State = "draft"
    applied_revision: int | None = None
    applied_digest: str | None = None
    applied_at: int | None = None
    last_error: str | None = None
    created_at: int = 0
    updated_at: int = 0

    @property
    def applied_current(self) -> bool:
        return self.state == "applied" and self.applied_revision == self.revision


class Reason(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str
    rule_id: str | None = None
    message: str = ""


class Compiled(BaseModel):
    """The honest preview: a document the backend can enforce, or the reasons it cannot."""

    model_config = ConfigDict(extra="forbid")
    status: Literal["supported", "unsupported"]
    reasons: list[Reason] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    document: dict | None = None
    digest: str | None = None
    diff: list[str] = Field(default_factory=list)
    restart_required: bool = False
    rollback: dict | None = None
    compiler_version: str = COMPILER_VERSION
    backend: str | None = None
    runtime_version: str | None = None
    # `xray_router` (v0.5): the native manager's document that keeps the service handed to
    # the router — applied beside `document` (the router's intent) when it is not in place.
    attach: dict | None = None
