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


def test_domain_write_and_audit_commit_or_roll_back_together(tmp_path):
    database = _database(tmp_path)
    with pytest.raises(RuntimeError):
        with database.transaction() as db:
            db.execute(
                "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at)"
                " VALUES('n1','n','unenrolled','{}',1,1)"
            )
            audit.record(db, actor=ACTOR, action="fleet.node.create", target="n1", ip="127.0.0.1")
            raise RuntimeError("injected after domain write and audit")
    with database.connect() as db:
        assert db.execute("SELECT count(*) FROM fleet_nodes WHERE node_id='n1'").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 0
    with database.transaction() as db:
        db.execute(
            "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at)"
            " VALUES('n1','n','unenrolled','{}',1,1)"
        )
        audit.record(
            db,
            actor=ACTOR,
            action="fleet.node.create",
            target="n1",
            ip="127.0.0.1",
            request_id="req-1",
            reason_code="operator",
            after_digest=audit.digest({"node_id": "n1"}),
        )
    with database.connect() as db:
        assert db.execute("SELECT count(*) FROM fleet_nodes WHERE node_id='n1'").fetchone()[0] == 1
        row = db.execute("SELECT * FROM audit_log").fetchone()
        assert (row["request_id"], row["reason_code"]) == ("req-1", "operator")
        assert len(row["after_digest"]) == 64


@pytest.mark.parametrize("detail", [
    {"password": "CANARY-1", "quota_bytes": 5},
    {"nested": {"share_url": "mierus://user:CANARY-2@host", "keep": 1}, "quota_bytes": 5},
    {"list": [{"token": "CANARY-3"}], "quota_bytes": 5},
    {"proxy-url": "CANARY-4", "quota_bytes": 5},
])
def test_scrub_removes_secret_bearing_keys_recursively(detail):
    # The canary is a distinctive string on purpose: asserting on a single letter
    # would match ordinary text such as the surviving "keep" key.
    scrubbed = audit.scrub(detail)
    rendered = str(scrubbed)
    assert scrubbed["quota_bytes"] == 5
    assert "CANARY" not in rendered and "mierus" not in rendered
    for forbidden in ("password", "share_url", "token", "proxy-url"):
        assert forbidden not in rendered
    if "nested" in detail:
        assert scrubbed["nested"] == {"keep": 1}


def test_scrubbed_detail_is_written_without_the_secret(tmp_path):
    database = _database(tmp_path)
    with database.transaction() as db:
        audit.record(
            db,
            actor=ACTOR,
            action="naive.create",
            target="alice",
            ip="127.0.0.1",
            detail={"quota_bytes": 5, "password": "CANARY-PASSWORD", "clients": [{"share_url": "naive+https://x"}]},
        )
    # WAL keeps recent pages beside the database file, so both are scanned: reading
    # only panel.sqlite3 would pass even if the value had been written.
    written = database.path.read_bytes()
    wal = database.path.with_name(database.path.name + "-wal")
    if wal.exists():
        written += wal.read_bytes()
    assert b"CANARY-PASSWORD" not in written
    with database.connect() as db:
        assert db.execute("SELECT detail_json FROM audit_log").fetchone()[0] == '{"quota_bytes": 5, "clients": [{}]}'


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
