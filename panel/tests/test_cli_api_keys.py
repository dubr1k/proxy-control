"""Installer-facing API key commands through the actual panel binary."""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.anyio


def create(server, name="mcp", scope="admin", *extra):
    code, out, err = server.cli("api-key-create", "--name", name, "--scope", scope, *extra)
    assert code == 0, (out, err)
    assert err == "" and len(out.splitlines()) == 1
    return json.loads(out)


async def test_create_prints_one_json_line_with_the_plaintext(panel_server):
    server = panel_server()
    row = create(server)
    assert set(row) == {"id", "name", "scope", "plaintext"}
    assert row["name"] == "mcp" and row["scope"] == "admin" and row["plaintext"].startswith("pc_")
    response = await server.client.get("/api/auth/me", headers={"Authorization": f"Bearer {row['plaintext']}"})
    assert response.status_code == 200 and response.json()["role"] == "owner"
    with server.db() as db:
        audit = db.execute("SELECT actor_username, ip, action FROM audit_log WHERE action='api_key.create' ORDER BY id DESC").fetchone()
        stored = str([dict(r) for r in db.execute("SELECT * FROM api_keys")])
    assert tuple(audit) == ("installer", "127.0.0.1", "api_key.create")
    assert row["plaintext"] not in stored


async def test_create_honours_expires_days(panel_server):
    server = panel_server()
    row = create(server, "short", "monitor", "--expires-days", "7")
    with server.db() as db:
        key = db.execute("SELECT * FROM api_keys WHERE id=?", (row["id"],)).fetchone()
    assert key["scope"] == "monitor"
    assert key["expires_at"] - key["created_at"] == 7 * 86400


async def test_create_refuses_a_name_that_is_still_enabled(panel_server):
    server = panel_server()
    create(server)
    code, _, _ = server.cli("api-key-create", "--name", "mcp", "--scope", "admin")
    assert code != 0
    with server.db() as db:
        assert db.execute("SELECT count(*) FROM api_keys").fetchone()[0] == 1


async def test_revoke_deletes_every_key_of_that_name(panel_server):
    server = panel_server()
    created = create(server)
    code, out, _ = server.cli("api-key-revoke", "--name", "mcp")
    assert code == 0 and json.loads(out) == {"revoked": 1}
    with server.db() as db:
        assert db.execute("SELECT count(*) FROM api_keys").fetchone()[0] == 0
    response = await server.client.get("/api/auth/me", headers={"Authorization": f"Bearer {created['plaintext']}"})
    assert response.status_code == 401
    code, out, _ = server.cli("api-key-revoke", "--name", "mcp")
    assert code == 0 and json.loads(out) == {"revoked": 0}
    create(server)
