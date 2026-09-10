"""What a subscription is, and what a client's manifest says right now.

Neither type carries the token: the panel keeps only its hash, so nothing that can be
handed to a subscriber is ever loaded back into a model, logged, or serialised by
accident.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Subscription:
    id: str
    client_id: str
    generation: int
    state: str
    update_interval_hours: int
    last_fetched_at: int | None
    created_at: int
    updated_at: int
    revoked_at: int | None = None


@dataclass(frozen=True)
class ManifestGrant:
    grant_id: str
    protocol: str
    node_id: str
    endpoint_id: str
    runtime_username: str
    secret_version: int
    options: dict
    enabled: bool
    valid_from: int | None = None
    valid_until: int | None = None


@dataclass(frozen=True)
class Manifest:
    client_id: str
    client_name: str
    generation: int
    grants: list[ManifestGrant] = field(default_factory=list)
    version: int = 1
