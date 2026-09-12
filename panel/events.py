"""Subscription and node events: facts the panel recorded, never a promise it delivered.

An event says that the generation moved, that a client fetched the subscription, that
a URL was revoked, or that a linked panel's heartbeat changed status. It never says
`applied` or `delivered` — the panel cannot know what a client did with what it
received, and an event name that claimed otherwise would be read as a guarantee. Every
event is a row in `audit_log` (written inside the caller's transaction, so a rolled-back
change leaves no event behind) mirrored into a bounded in-memory ring for cheap polling;
the payload passes through the audit scrubber, so a token, a link or a credential cannot
end up in it by accident. A node event carries the node's id and nothing else.
"""
from __future__ import annotations

import json
import time
from collections import deque

from .audit import record, scrub

NAMES = ("subscription.generation.changed", "subscription.fetched", "subscription.revoked", "node.up", "node.down")
SYSTEM_ACTOR = {"id": None, "username": "system"}
MAX_PAGE = 500


class EventBus:
    def __init__(self, database, *, capacity: int = 500, clock=time):
        self.database = database
        self.clock = clock
        self.recent: deque[dict] = deque(maxlen=capacity)

    def emit(self, db, name: str, payload: dict) -> int:
        """Record one event inside the caller's transaction and return its row id."""
        if name not in NAMES:
            raise ValueError(f"unknown event name: {name}")
        target = payload.get("subscription_id") or payload.get("node_id")
        if not isinstance(target, str) or not target:
            raise ValueError("an event names the subscription or node it is about")
        clean = scrub(payload)
        row_id = record(
            db, actor=SYSTEM_ACTOR, action=name, target=target, ip="local", detail=clean
        )
        self.recent.append({"id": row_id, "name": name, "at": int(self.clock.time()), **clean})
        return row_id

    def since(self, after: int, limit: int) -> list[dict]:
        """Events with an id above `after`, oldest first — the durable trail, not the ring."""
        placeholders = ",".join("?" for _ in NAMES)
        with self.database.connect() as db:
            rows = db.execute(
                f"SELECT id, happened_at, action, target, detail_json FROM audit_log"
                f" WHERE id > ? AND action IN ({placeholders}) ORDER BY id LIMIT ?",
                (after, *NAMES, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "name": row["action"],
                "at": row["happened_at"],
                ("node_id" if row["action"].startswith("node.") else "subscription_id"): row["target"],
                **json.loads(row["detail_json"]),
            }
            for row in rows
        ]
