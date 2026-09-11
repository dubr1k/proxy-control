"""Fleet v2 wire contract (spec §4–5): typed, bounded, secret-free documents."""
from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_PUSH_BYTES = 65536
MAX_RESOURCES = 500
SCHEMA_VERSION = 1
CONFLICT_CODES = ("guid_mismatch", "foreign_master", "stale_generation", "digest_conflict", "digest_invalid")


class GenerationConflict(Exception):
    def __init__(self, code: str, message: str = ""):
        assert code in CONFLICT_CODES
        super().__init__(message or code)
        self.code = code


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Resource(_Strict):
    ref: str = Field(min_length=1, max_length=128)
    protocol: Literal["mtproxy", "naive", "mieru"]
    runtime_username: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    desired_state: Literal["enabled", "disabled", "deleted"]
    credential_ref: str = Field(min_length=1, max_length=160)
    credential_origin: Literal["caller", "manager"]
    options: dict = Field(default_factory=dict)
    valid_from: int | None = None
    valid_until: int | None = None


class GenerationDocument(_Strict):
    schema_version: Literal[1] = SCHEMA_VERSION
    node_guid: str = Field(min_length=1, max_length=64)
    master_guid: str = Field(min_length=1, max_length=64)
    generation: int = Field(ge=1)
    previous_generation: int = Field(ge=0)
    created_at: int
    created_by: str = Field(max_length=128)
    resources: list[Resource] = Field(max_length=MAX_RESOURCES)


def canonical_digest(document: GenerationDocument) -> str:
    payload = document.model_dump()
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


class ObservedResource(_Strict):
    ref: str
    protocol: str
    runtime_username: str
    state: Literal["enabled", "disabled", "missing", "failed", "drifted"]
    error: str | None = None
    revision: str | None = None


class ObservedGeneration(_Strict):
    applied_generation: int
    digest: str
    reconcile_state: Literal["idle", "applying", "converged", "failed"]
    resources: list[ObservedResource]
    reported_at: int


class PushResponse(_Strict):
    observed: ObservedGeneration
    credentials: dict[str, str] = Field(default_factory=dict)
