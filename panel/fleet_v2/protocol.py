"""Fleet v2 wire contract (spec §4–5): typed, bounded, secret-free documents."""
from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..routing.document import canonical, document_digest

MAX_PUSH_BYTES = 65536
# A compiled egress document per protocol (spec §5 limits); the push stays within MAX_PUSH_BYTES.
MAX_EGRESS_BYTES = 16384
MAX_RESOURCES = 500
# A node reads back at most this many credentials per `POST credentials/capture`; a central
# asking for more (a generation may carry MAX_RESOURCES) batches its request.
CAPTURE_MAX_RESOURCES = 200
SCHEMA_VERSION = 1
CONFLICT_CODES = ("guid_mismatch", "foreign_master", "stale_generation", "digest_conflict", "digest_invalid")


class GenerationConflict(Exception):
    def __init__(self, code: str, message: str = ""):
        assert code in CONFLICT_CODES
        super().__init__(message or code)
        self.code = code


class _Strict(BaseModel):
    """What the node validates before acting on it: an unknown field is a 422."""

    model_config = ConfigDict(extra="forbid")


class _Report(BaseModel):
    """What the node reports and the central reads: a report may gain fields (a newer node
    talking to an older central — nodes are upgraded first), and a central ignores the
    ones it does not know instead of refusing the whole report."""

    model_config = ConfigDict(extra="ignore")


class Resource(_Strict):
    ref: str = Field(min_length=1, max_length=128)
    protocol: Literal["mtproxy", "naive", "mieru"]
    runtime_username: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    desired_state: Literal["enabled", "disabled", "deleted"]
    credential_ref: str = Field(min_length=1, max_length=160)
    credential_origin: Literal["caller", "manager"]
    # `imported`: the operator adopted a user already running on the node (ADR 003
    # `adopted`), so the node may claim that user as the central's without touching it.
    # A `provisioned` resource never adopts: a runtime user of the same name is a collision.
    origin: Literal["provisioned", "imported"] = "provisioned"
    options: dict = Field(default_factory=dict)
    valid_from: int | None = None
    valid_until: int | None = None


class EgressDocument(_Strict):
    """What one protocol's egress should be on the node (v0.4, spec §8.3): the compiled
    document the manager validates, named by the policy revision it came from.

    With the node's Xray-router (v0.5) a section names *two* managers: `backend` says
    which one `document` is for (the router's intent under `xray_router`, the native
    manager's document otherwise) and `companion` is what the *other* one gets afterwards
    — the native attach document beside a router intent, the router's pass-through beside a
    native detach. Absent from the wire when None, so a v0.4 node keeps its strict model."""

    backend: Literal["naive_native", "mieru_native", "xray_router"]
    policy_id: str = Field(min_length=1, max_length=64)
    policy_revision: int = Field(ge=1)
    document: dict
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    companion: dict | None = None
    # An attach/detach generation (v0.5): the backend runs its pass-through, the policy's own
    # rules are not what this section applies. Omitted from the wire when False.
    passthrough: bool = False

    @model_validator(mode="after")
    def digest_names_the_document(self):
        if len(canonical(self.document)) > MAX_EGRESS_BYTES:
            raise ValueError("egress document too large")
        if document_digest(self.document) != self.digest:
            raise ValueError("egress digest does not match the document")
        if self.companion is not None and len(canonical(self.companion)) > MAX_EGRESS_BYTES:
            raise ValueError("egress companion document too large")
        return self


class GenerationDocument(_Strict):
    schema_version: Literal[1] = SCHEMA_VERSION
    node_guid: str = Field(min_length=1, max_length=64)
    master_guid: str = Field(min_length=1, max_length=64)
    generation: int = Field(ge=1)
    previous_generation: int = Field(ge=0)
    created_at: int
    created_by: str = Field(max_length=128)
    resources: list[Resource] = Field(max_length=MAX_RESOURCES)
    # Egress per protocol (v0.4). Absent = leave the node's egress as it is. Never sent to a
    # node without `egress.v1` — its strict model would refuse the whole generation — and
    # left out of the wire form and the digest when None, so a v0.3 central and a v0.4 node
    # (or the reverse) agree on every document that carries no egress.
    egress: dict[Literal["naive", "mieru"], EgressDocument] | None = None

    def wire(self) -> dict:
        payload = self.model_dump()
        if payload.get("egress") is None:
            payload.pop("egress", None)
        else:
            for entry in payload["egress"].values():
                if entry.get("companion") is None:
                    entry.pop("companion", None)
                if not entry.get("passthrough"):
                    entry.pop("passthrough", None)
        return payload

    @model_validator(mode="after")
    def resources_do_not_collide_on_the_same_runtime_user(self):
        """Two resources naming the same (protocol, runtime_username) would race the
        same runtime account and make `apply()`'s outcome depend on list order."""
        seen: set[tuple[str, str]] = set()
        for resource in self.resources:
            key = (resource.protocol, resource.runtime_username)
            if key in seen:
                raise ValueError(f"duplicate resource for {resource.protocol}/{resource.runtime_username}")
            seen.add(key)
        return self


def canonical_digest(document: GenerationDocument) -> str:
    payload = document.wire()
    payload["resources"] = sorted(payload["resources"], key=lambda item: item["ref"])
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


class PushRequest(_Strict):
    expected_guid: str
    generation: GenerationDocument
    secrets: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def secrets_belong_to_the_document(self):
        refs = {item.credential_ref for item in self.generation.resources}
        stray = set(self.secrets) - refs
        if stray:
            raise ValueError(f"secrets for unknown refs: {sorted(stray)}")
        return self

    def wire(self) -> dict:
        return {"expected_guid": self.expected_guid, "generation": self.generation.wire(), "secrets": dict(self.secrets)}


class ObservedResource(_Report):
    ref: str
    protocol: str
    runtime_username: str
    state: Literal["enabled", "disabled", "missing", "failed", "drifted"]
    error: str | None = None
    revision: str | None = None
    # What the runtime taught the node about this resource and the central cannot know
    # otherwise — Telemt's public host and port, mita's share template: the options the
    # protocol model has a field for (`Reconciler.LEARNED_OPTIONS`). Never a credential.
    learned: dict[str, str | int] = Field(default_factory=dict, max_length=8)


class ObservedEgress(_Report):
    """What the node did with one protocol's egress section (v0.4): `converged` at the
    manager's revision and the digest it runs, `failed` with the manager's code, or
    `unsupported` when the protocol has no egress here."""

    state: Literal["converged", "failed", "unsupported"]
    revision: str | None = None
    digest: str | None = None
    error: str | None = None
    # The router's side of the section (v0.5): its own revision and generation; an older
    # central ignores the field.
    router: dict | None = None


class ObservedGeneration(_Report):
    applied_generation: int
    digest: str
    reconcile_state: Literal["idle", "applying", "converged", "failed"]
    resources: list[ObservedResource]
    reported_at: int
    # Per protocol, the egress the node last applied for a generation (v0.4); an older
    # central ignores the field.
    egress: dict[str, ObservedEgress] = Field(default_factory=dict)


class PushResponse(_Report):
    observed: ObservedGeneration
    credentials: dict[str, str] = Field(default_factory=dict)
