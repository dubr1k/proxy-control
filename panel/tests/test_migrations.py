"""The database boundary: one migration runner, safe for two processes at once.

`PRE_V02_SCHEMA_SQL` is a verbatim snapshot of what v0.1.0 code produced
(`Store.dump_schema()` after `Store._init` and `FleetStore._init` ran on the lab
host, 2026-09-10). A database built from it is what a real upgrade starts from.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from panel.database import Database, DatabaseError
from panel.fleet import FleetStore
from panel.migrations import MIGRATIONS, MigrationError, apply_migrations, migration_status
from panel.store import Store

PRE_V02_SCHEMA_SQL = ";\n".join((
    """CREATE TABLE admins (
              id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
              password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','admin','viewer')),
              active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL
            )""",
    """CREATE TABLE sessions (
              token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
              csrf_hash TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              last_seen_at INTEGER NOT NULL
            )""",
    """CREATE TABLE login_attempts (
              scope TEXT NOT NULL, happened_at INTEGER NOT NULL,
              reservation_id TEXT NOT NULL
            )""",
    "CREATE INDEX login_attempts_scope_time ON login_attempts(scope,happened_at)",
    """CREATE TABLE audit_log (
              id INTEGER PRIMARY KEY, happened_at INTEGER NOT NULL, actor_id INTEGER,
              actor_username TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
              detail_json TEXT NOT NULL DEFAULT '{}', ip TEXT NOT NULL
            )""",
    """CREATE TABLE fleet_nodes (
              node_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, auth_state TEXT NOT NULL,
              inventory_json TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
              next_sequence INTEGER NOT NULL DEFAULT 1, last_result_sequence INTEGER NOT NULL DEFAULT 0
            , last_seen_at INTEGER)""",
    """CREATE TABLE fleet_commands (
              command_id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE RESTRICT,
              sequence INTEGER NOT NULL, idempotency_key TEXT NOT NULL, protocol_version INTEGER NOT NULL,
              operation TEXT NOT NULL, expected_revision TEXT NOT NULL, payload_json TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('queued','dispatched','succeeded','failed','indeterminate')),
              result_json TEXT, created_at INTEGER NOT NULL, completed_at INTEGER, actor TEXT NOT NULL DEFAULT 'system', expires_at INTEGER NOT NULL DEFAULT 0, payload_sha256 TEXT NOT NULL DEFAULT '', dispatched_at INTEGER,
              UNIQUE(node_id,sequence), UNIQUE(node_id,idempotency_key)
            )""",
    "CREATE INDEX fleet_commands_node_sequence ON fleet_commands(node_id,sequence)",
    """CREATE TABLE fleet_certificates (
              serial TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE RESTRICT,
              fingerprint_sha256 TEXT NOT NULL UNIQUE, not_before INTEGER NOT NULL, not_after INTEGER NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('active','revoked')), issued_at INTEGER NOT NULL, revoked_at INTEGER
            )""",
))


def _legacy_database(path: Path) -> None:
    """Build a database exactly the way v0.1.0 code did: two executescript initialisers."""
    db = sqlite3.connect(path)
    db.executescript(PRE_V02_SCHEMA_SQL)
    db.execute(
        "INSERT INTO admins(username,password_hash,role,created_at) VALUES('owner','$argon2id$stub','owner',1)"
    )
    db.execute(
        "INSERT INTO audit_log(happened_at,actor_username,action,target,ip)"
        " VALUES(1,'owner','login','-','127.0.0.1')"
    )
    db.execute(
        "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at)"
        " VALUES('edge-01','edge','unenrolled','{}',1,1)"
    )
    db.commit()
    db.close()


def test_migrates_pre_v02_database_and_keeps_rows_readable(tmp_path):
    path = tmp_path / "panel.sqlite3"
    _legacy_database(path)
    # `db-status` before the first migration is a question an operator asks; the
    # answer is "nothing applied yet", and asking must not create the table.
    before = migration_status(Database(path))
    assert [row["applied"] for row in before] == [False] * len(MIGRATIONS)
    with sqlite3.connect(path) as raw:
        assert raw.execute("SELECT count(*) FROM sqlite_master WHERE name='schema_migrations'").fetchone()[0] == 0
    applied = apply_migrations(Database(path))
    assert applied == [migration.version for migration in MIGRATIONS]
    assert [row["username"] for row in Store(path).admins()] == ["owner"]
    assert Store(path).audits()[0]["action"] == "login"
    assert FleetStore(path).node("edge-01")["display_name"] == "edge"
    # The reserved local identity is added to an upgraded database too, next to the real node.
    assert FleetStore(path).node("local")["kind"] == "local"
    assert [node["node_id"] for node in FleetStore(path).nodes()] == ["edge-01", "local"]
    status = migration_status(Database(path))
    assert all(row["applied"] for row in status)


def test_migration_creates_exactly_one_local_node_idempotently(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    apply_migrations(database)
    with database.connect() as db:
        rows = db.execute(
            "SELECT node_id,kind,display_name,disabled,auth_state FROM fleet_nodes"
        ).fetchall()
    assert [tuple(row) for row in rows] == [("local", "local", "Этот сервер", 0, "local")]


def test_fresh_database_gets_the_same_schema_as_a_migrated_one(tmp_path):
    fresh, legacy = tmp_path / "fresh.sqlite3", tmp_path / "legacy.sqlite3"
    _legacy_database(legacy)
    apply_migrations(Database(fresh))
    apply_migrations(Database(legacy))

    def columns(path):
        db = sqlite3.connect(path)
        return {
            table: [row[1] for row in db.execute(f"PRAGMA table_info({table})")]
            for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        }

    assert columns(fresh) == columns(legacy)


def test_interrupted_migration_rolls_back_and_records_nothing(tmp_path, monkeypatch):
    from panel import migrations

    broken = migrations.Migration(
        version=9999, name="broken", statements=("CREATE TABLE probe(x)", "CREATE TABLE probe(x)"),
    )
    monkeypatch.setattr(migrations, "MIGRATIONS", migrations.MIGRATIONS + (broken,))
    path = tmp_path / "panel.sqlite3"
    with pytest.raises(sqlite3.OperationalError):
        apply_migrations(Database(path))
    db = sqlite3.connect(path)
    assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='probe'").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM schema_migrations WHERE version=9999").fetchone()[0] == 0


def test_checksum_mismatch_fails_closed(tmp_path):
    path = tmp_path / "panel.sqlite3"
    apply_migrations(Database(path))
    db = sqlite3.connect(path)
    db.execute("UPDATE schema_migrations SET checksum='tampered' WHERE version=1")
    db.commit()
    db.close()
    with pytest.raises(MigrationError, match="checksum"):
        apply_migrations(Database(path))


def test_newer_database_than_code_fails_closed(tmp_path):
    path = tmp_path / "panel.sqlite3"
    apply_migrations(Database(path))
    db = sqlite3.connect(path)
    db.execute("INSERT INTO schema_migrations VALUES(9999,'future','x',1)")
    db.commit()
    db.close()
    with pytest.raises(MigrationError, match="newer"):
        apply_migrations(Database(path))


def test_two_processes_initialising_concurrently_are_safe(tmp_path):
    path = tmp_path / "panel.sqlite3"
    errors = []

    def run():
        try:
            apply_migrations(Database(path))
        except Exception as exc:  # noqa: BLE001 - the test records any failure
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(migration_status(Database(path))) == len(MIGRATIONS)


def test_transaction_helper_commits_or_rolls_back_everything(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    with pytest.raises(RuntimeError):
        with database.transaction() as db:
            db.execute(
                "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at)"
                " VALUES('a','a','unenrolled','{}',1,1)"
            )
            raise RuntimeError("injected")
    with database.connect() as db:
        assert db.execute("SELECT count(*) FROM fleet_nodes WHERE node_id='a'").fetchone()[0] == 0


def test_wal_is_enabled_even_while_another_connection_holds_the_database(tmp_path):
    """Two processes open this database, so a cold start can collide.

    SQLite does not run the busy handler for a journal-mode change: the pragma fails
    immediately while anyone else holds the file. Without a retry the panel or the
    fleet ingress dies at startup with "database is locked".
    """
    path = tmp_path / "panel.sqlite3"
    plain = sqlite3.connect(path)
    plain.execute("CREATE TABLE probe(x)")
    plain.commit()
    assert plain.execute("PRAGMA journal_mode").fetchone()[0] == "delete"

    locked, released = threading.Event(), threading.Event()

    def hold():
        holder = sqlite3.connect(path, timeout=10)
        holder.execute("BEGIN IMMEDIATE")
        holder.execute("INSERT INTO probe VALUES(1)")
        locked.set()
        released.wait(5)
        holder.execute("COMMIT")
        holder.close()

    thread = threading.Thread(target=hold)
    thread.start()
    try:
        assert locked.wait(5)
        opener = threading.Timer(0.3, released.set)
        opener.start()
        database = Database(path)
    finally:
        released.set()
        thread.join(10)
    with database.connect() as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    plain.close()


def test_a_database_that_never_becomes_writable_fails_with_a_named_error(tmp_path):
    path = tmp_path / "panel.sqlite3"
    plain = sqlite3.connect(path)
    plain.execute("CREATE TABLE probe(x)")
    plain.commit()
    holder = sqlite3.connect(path, timeout=10)
    holder.execute("BEGIN IMMEDIATE")
    holder.execute("INSERT INTO probe VALUES(1)")
    try:
        with pytest.raises(DatabaseError, match="write-ahead logging"):
            Database(path, timeout=0.5)
    finally:
        holder.close()
        plain.close()
