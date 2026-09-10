"""Audit rows written inside the caller's transaction, never with secret values.

Two properties matter here. First, the row goes in through the same connection
as the change it describes, so a rolled-back change leaves no audit trail
claiming it happened. Second, scrubbing is recursive and key-based: a secret
nested in a list inside a dict is dropped just like a top-level one.
"""
from __future__ import annotations

import hashlib
import json
import time

FORBIDDEN_FRAGMENTS = ("secret", "password", "token", "credential", "link", "url", "authorization")


def _forbidden(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return any(fragment in normalized for fragment in FORBIDDEN_FRAGMENTS)


def scrub(value):
    if isinstance(value, dict):
        return {
            key: scrub(child)
            for key, child in value.items()
            if isinstance(key, str) and not _forbidden(key)
        }
    if isinstance(value, list):
        return [scrub(child) for child in value[:100]]
    if isinstance(value, str):
        return value[:512]
    return value if value is None or isinstance(value, (int, float, bool)) else str(type(value).__name__)


def digest(value) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def record(
    db,
    *,
    actor: dict,
    action: str,
    target: str,
    ip: str,
    detail: dict | None = None,
    request_id: str | None = None,
    correlation_id: str | None = None,
    reason_code: str | None = None,
    generation: int | None = None,
    before_digest: str | None = None,
    after_digest: str | None = None,
) -> int:
    cursor = db.execute(
        """INSERT INTO audit_log(happened_at,actor_id,actor_username,action,target,detail_json,ip,
           request_id,correlation_id,reason_code,generation,before_digest,after_digest)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            int(time.time()),
            actor.get("admin_id") or actor.get("id"),
            actor["username"],
            action,
            target,
            json.dumps(scrub(detail or {}), ensure_ascii=True),
            ip,
            request_id,
            correlation_id,
            reason_code,
            generation,
            before_digest,
            after_digest,
        ),
    )
    return cursor.lastrowid
