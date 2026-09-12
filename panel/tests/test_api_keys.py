# panel/tests/test_api_keys.py
from __future__ import annotations

import pytest

from panel.api_keys import ApiKeyService, SCOPES
from panel.database import Database
from panel.fleet_v2.identity import ensure_guid, read_panel_version
from panel.migrations import apply_migrations

ACTOR = {"id": 1, "username": "owner"}


@pytest.fixture
def database(tmp_path):
    db = Database(tmp_path / "panel.sqlite3")
    apply_migrations(db)
    return db


def test_guid_is_created_once_and_stable(database):
    first = ensure_guid(database)
    assert len(first) == 36
    assert ensure_guid(database) == first


def test_panel_version_falls_back_to_dev_instead_of_crashing(tmp_path):
    """Fix round 1, I2: a missing, unreadable or empty VERSION never stops the panel."""
    assert read_panel_version(tmp_path / "absent") == "dev"
    assert read_panel_version(tmp_path) == "dev"  # a directory raises OSError, not a crash-loop
    (tmp_path / "VERSION").write_text("\n")
    assert read_panel_version(tmp_path / "VERSION") == "dev"
    (tmp_path / "VERSION").write_text("0.3.0\n")
    assert read_panel_version(tmp_path / "VERSION") == "0.3.0"


def test_create_returns_plaintext_once_and_stores_only_a_hash(database):
    service = ApiKeyService(database)
    row, plaintext = service.create("central", "node-sync", None, actor=ACTOR, ip="127.0.0.1")
    assert plaintext.startswith("pc_") and row["scope"] == "node-sync"
    assert "token" not in row and "key_hash" not in row
    with database.connect() as db:
        stored = db.execute("SELECT key_hash, prefix FROM api_keys").fetchone()
    assert plaintext not in stored["key_hash"] and plaintext.startswith(f"pc_{stored['prefix']}_")
    listed = service.list()
    assert [item["name"] for item in listed] == ["central"] and "key_hash" not in listed[0]


@pytest.mark.parametrize("scope,role", [("admin", "owner"), ("monitor", "viewer"), ("node-sync", "node-sync")])
def test_authenticate_maps_scope_to_role(database, scope, role):
    service = ApiKeyService(database)
    _, plaintext = service.create("k", scope, None, actor=ACTOR, ip="x")
    user = service.authenticate(plaintext)
    assert user["role"] == role and user["username"] == "key:k" and user["via"] == "api-key"


def test_wrong_disabled_expired_and_deleted_keys_do_not_authenticate(database):
    clock = type("Clock", (), {"time": staticmethod(lambda: 1_000_000)})
    service = ApiKeyService(database, clock=clock)
    row, plaintext = service.create("k", "admin", 1_000_100, actor=ACTOR, ip="x")
    assert service.authenticate(plaintext[:-1] + ("A" if plaintext[-1] != "A" else "B")) is None
    assert service.authenticate("pc_not_a_key") is None
    service.set_enabled(row["id"], False, actor=ACTOR, ip="x")
    assert service.authenticate(plaintext) is None
    service.set_enabled(row["id"], True, actor=ACTOR, ip="x")
    clock.time = staticmethod(lambda: 1_000_101)
    assert service.authenticate(plaintext) is None
    service.delete(row["id"], actor=ACTOR, ip="x")
    assert service.list() == []


def test_invalid_scope_and_name_are_refused(database):
    service = ApiKeyService(database)
    with pytest.raises(ValueError):
        service.create("k", "root", None, actor=ACTOR, ip="x")
    with pytest.raises(ValueError):
        service.create("", "admin", None, actor=ACTOR, ip="x")
    assert set(SCOPES) == {"admin", "monitor", "node-sync"}


def test_every_change_is_audited_without_the_key(database):
    service = ApiKeyService(database)
    row, plaintext = service.create("k", "admin", None, actor=ACTOR, ip="x")
    service.delete(row["id"], actor=ACTOR, ip="x")
    with database.connect() as db:
        rows = db.execute("SELECT action, detail_json FROM audit_log ORDER BY id").fetchall()
    assert [r["action"] for r in rows] == ["api_key.create", "api_key.delete"]
    assert all(plaintext not in r["detail_json"] for r in rows)
