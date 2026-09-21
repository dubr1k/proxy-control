"""`python -m panel.cli api-key-create / api-key-revoke` (v0.11, spec §9a): the installer
issues the MCP server's panel key and parses one JSON line from stdout."""
from __future__ import annotations

import json

import pytest

from panel import cli
from panel.api_keys import ApiKeyService
from panel.database import Database
from panel.migrations import apply_migrations


@pytest.fixture
def database_path(tmp_path):
    path = tmp_path / "panel.sqlite3"
    apply_migrations(Database(path))
    return path


def _run(monkeypatch, capsys, database_path, *argv):
    monkeypatch.setattr("sys.argv", ["panel.cli", "--database", str(database_path), *argv])
    cli.main()
    return capsys.readouterr()


def test_create_prints_one_json_line_with_the_plaintext(monkeypatch, capsys, database_path):
    out = _run(monkeypatch, capsys, database_path, "api-key-create", "--name", "mcp", "--scope", "admin")
    assert out.err == ""
    lines = out.out.splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert set(row) == {"id", "name", "scope", "plaintext"}
    assert row["name"] == "mcp" and row["scope"] == "admin" and row["plaintext"].startswith("pc_")
    service = ApiKeyService(Database(database_path))
    user = service.authenticate(row["plaintext"])
    assert user["role"] == "owner" and user["via"] == "api-key"
    with Database(database_path).connect() as db:
        audit = db.execute("SELECT actor_username, ip, action FROM audit_log ORDER BY id DESC").fetchone()
    assert (audit["actor_username"], audit["ip"], audit["action"]) == ("installer", "127.0.0.1", "api_key.create")


def test_create_honours_expires_days(monkeypatch, capsys, database_path):
    out = _run(monkeypatch, capsys, database_path, "api-key-create", "--name", "short", "--scope", "monitor",
               "--expires-days", "7")
    row = json.loads(out.out)
    listed = ApiKeyService(Database(database_path)).list()
    key = next(item for item in listed if item["id"] == row["id"])
    assert key["expires_at"] is not None and key["scope"] == "monitor"


def test_create_refuses_a_name_that_is_still_enabled(monkeypatch, capsys, database_path):
    _run(monkeypatch, capsys, database_path, "api-key-create", "--name", "mcp", "--scope", "admin")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, capsys, database_path, "api-key-create", "--name", "mcp", "--scope", "admin")
    assert exc.value.code != 0
    assert len(ApiKeyService(Database(database_path)).list()) == 1


def test_revoke_deletes_every_key_of_that_name(monkeypatch, capsys, database_path):
    created = json.loads(_run(monkeypatch, capsys, database_path, "api-key-create", "--name", "mcp", "--scope", "admin").out)
    out = _run(monkeypatch, capsys, database_path, "api-key-revoke", "--name", "mcp")
    assert json.loads(out.out) == {"revoked": 1}
    assert ApiKeyService(Database(database_path)).list() == []
    assert ApiKeyService(Database(database_path)).authenticate(created["plaintext"]) is None
    # Revoking again is not an error: the installer's rollback may run twice.
    assert json.loads(_run(monkeypatch, capsys, database_path, "api-key-revoke", "--name", "mcp").out) == {"revoked": 0}
    # A revoked name can be issued again.
    _run(monkeypatch, capsys, database_path, "api-key-create", "--name", "mcp", "--scope", "admin")
