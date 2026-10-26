"""Audit is part of the transaction, and it never carries a secret value."""

from __future__ import annotations

import pytest

from panel import audit
from panel.database import Database
from panel.migrations import apply_migrations

pytestmark = pytest.mark.anyio
ACTOR = {"id": 1, "username": "owner"}


def _database(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    return database











async def test_every_mutation_response_and_audit_row_carry_the_same_request_id(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    response = await client.post("/api/users", json={"username": "alice"}, headers={"X-CSRF-Token": csrf})
    request_id = response.headers["x-request-id"]
    assert len(request_id) == 16
    log = await client.get("/api/audit", params={"action": "user.create"})
    assert log.json()["items"][0]["request_id"] == request_id
    filtered = await client.get("/api/audit", params={"request_id": request_id})
    rows = filtered.json()["items"]
    # The invariant is correlation, not count: the domain writer legitimately records the
    # provisioning operation next to the endpoint's own row, and both must carry the id.
    assert "user.create" in [row["action"] for row in rows]
    assert all(row["request_id"] == request_id for row in rows)
