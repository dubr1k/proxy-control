"""One contract for three unlike protocols, with their differences stated, not hidden.

The three data planes genuinely differ: Telemt generates the credential itself and has
no operation id, Naive and Mieru accept a caller-supplied one, and only two of the
three can hand a live credential back without rotating it. The adapter surface names
each of those facts (`credential_origin`, `capture_supported`) instead of pretending
they behave alike — a uniform interface that lies would cost a subscriber their access.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable

from ..clients.models import AccessGrant, GrantIntent


class AdapterError(RuntimeError):
    """A refused or failed protocol operation. Messages never carry a credential."""


class ManualInterventionRequired(AdapterError):
    """The runtime changed but the credential is unrecoverable; a human must decide."""


@dataclass(frozen=True)
class ObservedGrant:
    runtime_username: str
    enabled: bool
    options: dict = field(default_factory=dict)
    revision: str | None = None


@dataclass(frozen=True)
class ObservedInventory:
    items: tuple[ObservedGrant, ...] = ()


@dataclass(frozen=True)
class Preflight:
    ok: bool
    reason: str | None = None


@dataclass(frozen=True)
class CredentialPlan:
    """Who chooses the credential. `caller` must carry the plaintext it chose."""

    origin: Literal["caller", "manager"]
    plaintext: bytes | None = None

    def __post_init__(self):
        if self.origin == "caller" and not self.plaintext:
            raise AdapterError("a caller-supplied credential needs its plaintext")
        if self.origin == "manager" and self.plaintext:
            raise AdapterError("a manager-generated credential cannot be supplied")


@dataclass(frozen=True)
class GrantRef:
    protocol: str
    runtime_username: str
    revision: str | None = None


@dataclass(frozen=True)
class AppliedGrant:
    runtime_username: str
    enabled: bool
    credential: bytes | None = None
    revision: str | None = None
    artifact_template: dict = field(default_factory=dict)
    # True when the reply was lost and the outcome had to be read back or replayed.
    recovered: bool = False
    # Who ended up choosing the credential actually applied. Usually matches the
    # `CredentialPlan` the caller passed in, except when a runtime refuses a
    # caller-supplied one and the adapter falls back to letting the manager generate it.
    credential_origin: str = "caller"


@dataclass(frozen=True)
class AccessArtifact:
    kind: str
    label: str
    media_type: str
    value: str
    # Whether the panel can re-render this from a stored credential without touching
    # the manager. `unsupported` means the operator must rotate to get it again.
    auto_refresh: Literal["supported", "unsupported"] = "supported"


@runtime_checkable
class ProtocolAdapter(Protocol):
    protocol: str
    credential_origin: Literal["caller", "manager"]
    capture_supported: bool
    # Whether `create`/`rotate` can accept a caller-chosen credential at all. Telemt's
    # pinned build does; the fallback to a manager-generated one is a safety net.
    accepts_caller_credential: bool

    async def discover(self) -> ObservedInventory: ...
    async def preflight(self, intent: GrantIntent) -> Preflight: ...
    async def create(
        self, operation_id: str, intent: GrantIntent, credential: CredentialPlan
    ) -> AppliedGrant: ...
    async def enable(self, grant: GrantRef) -> AppliedGrant: ...
    async def disable(self, grant: GrantRef) -> AppliedGrant: ...
    async def rotate(
        self, operation_id: str, grant: GrantRef, credential: CredentialPlan
    ) -> AppliedGrant: ...
    async def delete(self, grant: GrantRef) -> None: ...
    async def capture(self, grant: GrantRef) -> bytes | None: ...
    async def update_options(self, grant: GrantRef, options: dict) -> AppliedGrant | None: ...
    def render_artifacts(
        self, grant: AccessGrant, credential: bytes, *, public_host: str
    ) -> list[AccessArtifact]: ...
