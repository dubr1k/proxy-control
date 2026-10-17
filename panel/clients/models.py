"""What a client is and what access it holds — typed, and never carrying a credential.

An `AccessGrant` names an account on one endpoint of one node and points at a secret
version by reference. The value itself lives encrypted in `secret_versions`, so a grant
can be logged, diffed and rendered without a credential ever passing through it.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..fleet import LIMIT_FIELDS
from ..secrets_store import SecretRef

PROTOCOLS = ("mtproxy", "naive", "mieru", "amneziawg")
# The AmneziaWG protocol versions a node can serve, oldest first. They are not compatible with
# one another (server-side parameters differ), so a grant names exactly one.
AWG_VERSIONS = ("1.5", "2.0", "3.1")
# Client-config keys a node's manager may publish as obfuscation parameters.
AWG_OBFUSCATION_KEYS = frozenset({
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition",
})
USERNAME_RE = r"^[A-Za-z0-9_.-]{1,64}$"
# A share template is a shape, not a link: the credential is substituted at render time.
_TEMPLATE_CREDENTIALS = re.compile(r"^[a-z][a-z0-9+.-]*://(?P<credentials>[^@/]*)@")


def _limit(name: str, description: str):
    low, high = LIMIT_FIELDS[name]
    return Field(default=None, strict=True, ge=low, le=high, description=description)


class MieruQuota(BaseModel):
    model_config = ConfigDict(extra="forbid")

    days: int = Field(strict=True, ge=1, le=3650)
    megabytes: int = Field(strict=True, ge=1, le=2**31 - 1)


class MtproxyOptions(BaseModel):
    """Bounds are `panel.fleet.LIMIT_FIELDS`: one definition for the panel and the transport."""

    model_config = ConfigDict(extra="forbid")

    data_quota_bytes: int | None = _limit("data_quota_bytes", "total traffic allowance")
    rate_limit_up_bps: int | None = _limit("rate_limit_up_bps", "upstream rate limit")
    rate_limit_down_bps: int | None = _limit("rate_limit_down_bps", "downstream rate limit")
    max_tcp_conns: int | None = _limit("max_tcp_conns", "concurrent TCP connections")
    max_unique_ips: int | None = _limit("max_unique_ips", "distinct source addresses")
    expiration: int | None = Field(default=None, strict=True, ge=0, le=2**63 - 1)
    # Learned from the link Telemt returned, never configured: the panel has no other
    # source for where the runtime listens, and a link rebuilt from escrow needs one.
    host: str | None = Field(default=None, min_length=1, max_length=253)
    port: int | None = Field(default=None, strict=True, ge=1, le=65535)


class NaiveOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    quota_bytes: int | None = Field(default=None, strict=True, ge=1, le=2**63 - 1)


class MieruOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # No quota unless one is named: the grant dialog sends `{}` for every protocol.
    quotas: list[MieruQuota] = Field(default_factory=list, max_length=16)
    share_template: str | None = Field(default=None, max_length=512)

    @field_validator("share_template")
    @classmethod
    def template_holds_no_credential(cls, value):
        if value is None:
            return value
        if "{username}" not in value or "{password}" not in value:
            raise ValueError("share_template must contain {username} and {password}")
        match = _TEMPLATE_CREDENTIALS.match(value)
        if match and match.group("credentials") != "{username}:{password}":
            raise ValueError("share_template must carry placeholders, not a credential")
        return value


class AmneziawgOptions(BaseModel):
    """One AmneziaWG access. `version` is the operator's choice; everything else is learned from
    the node's manager at issue time (its address in the tunnel, the port of that version's
    interface, the server key and the obfuscation parameters the client must repeat), so a config
    rebuilt from escrow needs no call to the node."""

    model_config = ConfigDict(extra="forbid")

    version: Literal["1.5", "2.0", "3.1"] = "2.0"
    address: str | None = Field(default=None, max_length=15)
    port: int | None = Field(default=None, strict=True, ge=1, le=65535)
    server_public_key: str | None = Field(default=None, min_length=44, max_length=44)
    mtu: int | None = Field(default=None, strict=True, ge=576, le=1500)
    dns: list[str] = Field(default_factory=list, max_length=4)
    obfuscation: dict[str, str] = Field(default_factory=dict)

    @field_validator("address")
    @classmethod
    def address_is_ipv4(cls, value):
        if value is not None:
            ipaddress.IPv4Address(value)
        return value

    @field_validator("dns")
    @classmethod
    def dns_are_addresses(cls, value):
        for item in value:
            ipaddress.ip_address(item)
        return value

    @field_validator("obfuscation")
    @classmethod
    def obfuscation_is_bounded(cls, value):
        if len(value) > len(AWG_OBFUSCATION_KEYS):
            raise ValueError("too many obfuscation parameters")
        for key, item in value.items():
            if key not in AWG_OBFUSCATION_KEYS:
                raise ValueError(f"unknown obfuscation parameter {key}")
            if not isinstance(item, str) or len(item) > 2048 or "\n" in item or "\r" in item:
                raise ValueError(f"invalid obfuscation parameter {key}")
        return value


Options = MtproxyOptions | NaiveOptions | MieruOptions | AmneziawgOptions
PROTOCOL_OPTIONS: dict[str, type[Options]] = {
    "mtproxy": MtproxyOptions,
    "naive": NaiveOptions,
    "mieru": MieruOptions,
    "amneziawg": AmneziawgOptions,
}


class _ProtocolOptions(BaseModel):
    """Shared rule: the options object must be the one this protocol understands.

    Each options model forbids extra keys, so pydantic will not quietly reshape one
    protocol's options into another's; this validator rejects what is left.
    """

    protocol: str = Field(pattern=r"^(mtproxy|naive|mieru|amneziawg)$")
    options: Options

    @model_validator(mode="after")
    def options_match_protocol(self):
        expected = PROTOCOL_OPTIONS[self.protocol]
        if type(self.options) is not expected:
            raise ValueError(f"{self.protocol} requires {expected.__name__}")
        return self


class Client(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    display_name: str = Field(min_length=1, max_length=128)
    state: str = Field(pattern=r"^(active|suspended|archived)$")
    metadata: dict = Field(default_factory=dict)
    created_at: int
    updated_at: int


class GrantIntent(_ProtocolOptions):
    """What an operator asks for; the grant is what the panel then owns."""

    model_config = ConfigDict(extra="forbid")

    node_id: str = "local"
    endpoint_id: str = "default"
    runtime_username: str = Field(pattern=USERNAME_RE)
    valid_from: int | None = None
    valid_until: int | None = None


class AccessGrant(_ProtocolOptions):
    model_config = ConfigDict(extra="forbid")

    id: str
    client_id: str
    node_id: str
    endpoint_id: str = "default"
    runtime_username: str = Field(pattern=USERNAME_RE)
    secret_ref: SecretRef | None = None
    desired_state: str = Field(pattern=r"^(enabled|disabled|deleted)$")
    observed_state: str = Field(default="unknown", pattern=r"^(unknown|pending|enabled|disabled|missing)$")
    valid_from: int | None = None
    valid_until: int | None = None
    origin: str = Field(pattern=r"^(imported|provisioned)$")
    # `own` when the grant has its own routing lane on its node (v0.7); None = the service's.
    routing_lane: str | None = Field(default=None, pattern=r"^own$")
    # The name this access carries in subscriptions; None = «node · protocol».
    label: str | None = Field(default=None, min_length=1, max_length=64)
    created_at: int
    updated_at: int


def effective_enabled(grant: AccessGrant, client: Client, now: int) -> bool:
    """One place decides whether a grant is live right now — validity is not a state column."""
    return (
        client.state == "active"
        and grant.desired_state == "enabled"
        and within_validity(grant.valid_from, grant.valid_until, now)
    )


def within_validity(valid_from: int | None, valid_until: int | None, now: int) -> bool:
    """The same half-open window is enforced by a node even without its central."""
    return (valid_from is None or valid_from <= now) and (valid_until is None or now < valid_until)
