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
from ..routing.document import EGRESS_REASON_CODES, attached_to_router, document_digest

# What an egress operation may fail with (v0.4 routing): the managers' own bounded codes,
# plus the ones only the panel can know — a backend without egress, a manager that cannot
# answer at all, and (v0.5) a router that is absent, unreachable from the service's manager
# or not the service's current backend. Anything else a manager says is folded into these.
EGRESS_ERROR_CODES = EGRESS_REASON_CODES | {"egress_unsupported", "manager_unavailable", "router_unavailable",
                                            "router_unreachable", "not_attached"}


class AdapterError(RuntimeError):
    """A refused or failed protocol operation. Messages never carry a credential.

    `already_gone`: the runtime answered "no such user" to a delete — the outcome the
    caller wanted already holds, so a lifecycle may treat it as done.
    `code`: the bounded reason of an egress failure (`EGRESS_ERROR_CODES`), None for the
    grant operations that predate it."""

    def __init__(self, message: str = "", *, already_gone: bool = False, code: str | None = None):
        super().__init__(message)
        self.already_gone = already_gone
        self.code = code


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
class EgressTarget:
    """What a backend's egress looks like right now, as the compiler needs it (spec §5).

    `providers` names what this host can route through and whether the manager found it
    reachable — never the endpoint itself, which stays in the manager's environment.
    `applied` is the managed document the runtime runs (`revision`, `digest`, `document`),
    or None when the runtime carries an `upstream`/`egress` somebody wrote by hand (`mode`
    `custom`): the first apply adopts it, and a rollback puts it back verbatim."""

    protocol: str
    backend: Literal["naive_native", "mieru_native", "xray_router"]
    capabilities: frozenset[str]
    providers: dict[str, dict]
    revision: str
    applied: dict | None
    mode: Literal["direct", "proxy", "custom"] = "direct"
    restart_required: bool = False
    warnings: tuple[str, ...] = ()
    runtime_version: str | None = None
    # The applied native document hands the whole service to the node's Xray-router (v0.5):
    # the policy then lives in the router and this backend's own document stays fixed.
    router_attached: bool = False


@dataclass(frozen=True)
class RouterTarget:
    """One service's section on the node's Xray-router as the compiler needs it (v0.5): the
    router's capability cells, the WARP provider as the router sees it, the section's
    revision and applied intent. `available` False carries the reason (`router_unavailable`,
    `artifact_mismatch`, `manual_intervention_required`)."""

    available: bool
    service: str
    capabilities: frozenset[str] = frozenset()
    providers: dict[str, dict] = field(default_factory=dict)
    revision: str = ""
    applied: dict | None = None
    xray_version: str | None = None
    restart_required: bool = True
    reason: str | None = None


@dataclass(frozen=True)
class AppliedEgress:
    """The manager's answer to an apply or a rollback: the revision the runtime is at now
    and the digest of the document it runs (None after a rollback to a hand-written
    section). `readback_sha256` is what the manager verified after reloading, where it
    reports one."""

    revision: str
    digest: str | None
    readback_sha256: str | None = None
    replayed: bool = False


def egress_target_from_view(protocol: str, backend: str, view: dict) -> EgressTarget:
    """Both managers answer `GET /v1/egress` in the same vocabulary; only the document
    shapes differ, and those pass through untouched."""
    document = view.get("document")
    revision = str(view.get("revision") or "")
    providers = {name: {"reachable": entry.get("reachable")} for name, entry in (view.get("providers") or {}).items()
                 if isinstance(entry, dict)}
    return EgressTarget(
        protocol=protocol, backend=backend,
        capabilities=frozenset(item for item in view.get("capabilities", []) if isinstance(item, str)),
        providers=providers, revision=revision,
        applied=None if document is None else {"revision": revision, "digest": document_digest(document),
                                               "document": document},
        mode=view.get("mode") if view.get("mode") in ("direct", "proxy", "custom") else "custom",
        restart_required=view.get("restart_required") is True,
        warnings=tuple(item for item in view.get("warnings", []) if isinstance(item, str)),
        router_attached=attached_to_router(protocol, document),
    )


def router_target_from_view(service: str, view: dict) -> RouterTarget:
    """The router manager's `GET /v1/egress/{service}` as the compiler's target."""
    document = view.get("document")
    revision = str(view.get("revision") or "")
    providers = {name: {"reachable": entry.get("reachable")} for name, entry in (view.get("providers") or {}).items()
                 if isinstance(entry, dict)}
    return RouterTarget(
        available=True, service=service,
        capabilities=frozenset(item for item in view.get("capabilities", []) if isinstance(item, str)),
        providers=providers, revision=revision,
        applied=None if document is None else {"revision": revision, "digest": document_digest(document),
                                               "document": document},
        xray_version=view.get("runtime_version") if isinstance(view.get("runtime_version"), str) else None,
        restart_required=view.get("restart_required") is not False,
    )


def applied_egress_from_view(view: dict) -> AppliedEgress:
    document = view.get("applied")
    return AppliedEgress(
        revision=str(view.get("revision") or ""),
        digest=None if document is None else document_digest(document),
        readback_sha256=view.get("readback_sha256") if isinstance(view.get("readback_sha256"), str) else None,
        replayed=view.get("replayed") is True,
    )


def egress_error(runtime: str, status_code: int, code: str | None) -> AdapterError:
    """A manager's egress refusal as the typed error the routing service acts on."""
    if code not in EGRESS_REASON_CODES:
        code = {409: "egress_conflict", 422: "egress_invalid"}.get(status_code, "manager_unavailable")
    if code == "manual_intervention_required":
        return ManualInterventionRequired(f"{runtime} egress needs recovery by hand", code=code)
    return AdapterError(f"{runtime} refused the egress change", code=code)


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
    # egress (v0.4 routing): None / `egress_unsupported` for a data plane without one.
    async def egress_target(self) -> EgressTarget | None: ...
    async def plan_egress(self, document: dict, *, expected_revision: str) -> dict: ...
    async def apply_egress(
        self, document: dict, *, expected_revision: str, operation_id: str
    ) -> AppliedEgress: ...
    async def rollback_egress(self, *, expected_revision: str) -> AppliedEgress: ...
