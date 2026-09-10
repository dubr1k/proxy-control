"""What a client is and what access it holds — typed, and never carrying a credential.

An `AccessGrant` names an account on one endpoint of one node and points at a secret
version by reference. The value itself lives encrypted in `secret_versions`, so a grant
can be logged, diffed and rendered without a credential ever passing through it.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..fleet import LIMIT_FIELDS
from ..secrets_store import SecretRef

PROTOCOLS = ("mtproxy", "naive", "mieru")
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


class NaiveOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    quota_bytes: int | None = Field(default=None, strict=True, ge=1, le=2**63 - 1)


class MieruOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    quotas: list[MieruQuota] = Field(max_length=16)
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


Options = MtproxyOptions | NaiveOptions | MieruOptions
PROTOCOL_OPTIONS: dict[str, type[Options]] = {
    "mtproxy": MtproxyOptions,
    "naive": NaiveOptions,
    "mieru": MieruOptions,
}


class _ProtocolOptions(BaseModel):
    """Shared rule: the options object must be the one this protocol understands.

    Each options model forbids extra keys, so pydantic will not quietly reshape one
    protocol's options into another's; this validator rejects what is left.
    """

    protocol: str = Field(pattern=r"^(mtproxy|naive|mieru)$")
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
    created_at: int
    updated_at: int


def effective_enabled(grant: AccessGrant, client: Client, now: int) -> bool:
    """One place decides whether a grant is live right now — validity is not a state column."""
    return (
        client.state == "active"
        and grant.desired_state == "enabled"
        and (grant.valid_from is None or grant.valid_from <= now)
        and (grant.valid_until is None or now < grant.valid_until)
    )
