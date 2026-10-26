"""Subscription events are facts the panel recorded, never a promise that anyone received them.

Three moments produce one: the generation moved (inside the same transaction, so a
rolled-back change produces nothing), a client fetched the subscription (200 or 304),
and a URL was revoked — by an operator or by a rotation. No payload carries the token,
a link, or a claim such as `applied`/`delivered`.
"""

# ruff: noqa: F811  (fixtures imported from the HTTP suite reappear as test parameters)
from __future__ import annotations

import json

import httpx
import pytest

from test_subscription_http import (  # noqa: F401  (fixtures are registered by import)
    CTX,
    PANEL_HOST,
    app,
    client_id,
    clock,
    owner,
    public,
    subscriptions,
    token,
)

pytestmark = pytest.mark.anyio


def _events(app, after=0):
    with app.state.database.connect() as db:
        rows = db.execute(
            "SELECT id, action, target, detail_json, actor_username FROM audit_log"
            " WHERE action LIKE 'subscription.%' AND id > ? ORDER BY id",
            (after,),
        ).fetchall()
    return [
        {"id": row[0], "name": row[1], "target": row[2], "actor": row[4], **json.loads(row[3])}
        for row in rows
    ]





















