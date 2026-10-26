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











def test_migration_20_adds_escrow_columns_and_keeps_old_subscriptions_readable(tmp_path, monkeypatch):
    """The escrow copy is new in v0.10; a subscription row written before it (hash only,
    no secret_id/secret_version) stays readable, with `secret_ref` reported as None."""
    from panel import migrations as module
    from panel.subscriptions.store import SubscriptionStore

    database = Database(tmp_path / "panel.sqlite3")
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS[:19])
    apply_migrations(database)
    with database.transaction() as db:
        db.execute("INSERT INTO clients(id,display_name,state,created_at,updated_at) VALUES('c1','Old','active',1,1)")
        db.execute(
            "INSERT INTO client_subscriptions(id,client_id,public_token_hash,generation,state,update_interval_hours,created_at,updated_at)"
            " VALUES('s1','c1','hash-1',1,'active',12,1,1)"
        )
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS)
    assert apply_migrations(database) == [20, 21, 22, 23, 24, 25, 26]
    with database.connect() as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(client_subscriptions)")}
        assert {"secret_id", "secret_version"} <= columns
        old = SubscriptionStore.active(db, "c1")
    assert old is not None and old.secret_ref is None














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














def test_migration_24_widens_grants_routing_and_egress_and_keeps_every_row(tmp_path, monkeypatch):
    """TrustTunnel (v1.6): three CHECK lists are rebuilt; rows, children and indexes survive."""
    from panel import migrations as module

    database = Database(tmp_path / "panel.sqlite3")
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS[:23])
    apply_migrations(database)
    with database.transaction() as db:
        db.execute("INSERT INTO clients(id,display_name,state,created_at,updated_at) VALUES('c1','A','active',1,1)")
        db.execute("INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,origin,"
                   "created_at,updated_at,label) VALUES('g1','c1','amneziawg','local','alice','enabled','provisioned',1,1,'L')")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,origin,"
                       "created_at,updated_at) VALUES('g2','c1','trusttunnel','local','bob','enabled','provisioned',1,1)")
        db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
                   " VALUES('p1','local','naive','naive_native','direct','fail_closed',1,1)")
        db.execute("INSERT INTO routing_rules(id,policy_id,position,match_json,action,created_at,updated_at)"
                   " VALUES('r1','p1',1,'{}','direct',1,1)")
        db.execute("INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('naive',1,'converged',1)")
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS)
    assert apply_migrations(database) == [24, 25, 26]
    with database.transaction() as db:
        assert db.execute("SELECT label,protocol FROM access_grants WHERE id='g1'").fetchone()[:] == ("L", "amneziawg")
        assert db.execute("SELECT count(*) FROM routing_rules WHERE policy_id='p1'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM managed_egress").fetchone()[0] == 1
        db.execute("INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,origin,"
                   "created_at,updated_at) VALUES('g2','c1','trusttunnel','local','bob','enabled','provisioned',1,1)")
        db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
                   " VALUES('p2','local','trusttunnel','trusttunnel_native','direct','fail_closed',1,1)")
        db.execute("INSERT INTO routing_rules(id,policy_id,position,match_json,action,created_at,updated_at)"
                   " VALUES('r2','p2',1,'{}','block',1,1)")
        db.execute("INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('trusttunnel',1,'converged',1)")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('socks',1,'converged',1)")
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {"access_grants_client", "routing_applies_policy"} <= names
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name LIKE '%\\_old' ESCAPE '\\'").fetchone()[0] == 0
        # the children follow the new parent: deleting a policy cascades
        db.execute("DELETE FROM routing_policies WHERE id='p2'")
        assert db.execute("SELECT count(*) FROM routing_rules WHERE policy_id='p2'").fetchone()[0] == 0


def test_migration_26_admits_amneziawg_egress_and_keeps_every_row(tmp_path, monkeypatch):
    """AmneziaWG egress (v3.0.0): routing policies and the node's egress record take `amneziawg` and
    `amneziawg_native`; policies, their rules and applies, and the egress rows survive the rebuild."""
    from panel import migrations as module

    database = Database(tmp_path / "panel.sqlite3")
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS[:25])
    apply_migrations(database)
    with database.transaction() as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
                       " VALUES('px','local','amneziawg','amneziawg_native','direct','fail_closed',1,1)")
        db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
                   " VALUES('p1','local','trusttunnel','xray_router','egress','fail_closed',1,1)")
        db.execute("INSERT INTO routing_rules(id,policy_id,position,match_json,action,created_at,updated_at)"
                   " VALUES('r1','p1',1,'{}','direct',1,1)")
        db.execute("INSERT INTO routing_applies(policy_id,revision,backend,compiler_version,outcome,actor,created_at)"
                   " VALUES('p1',1,'xray_router','3','applied','owner',1)")
        db.execute("INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('trusttunnel',1,'converged',1)")
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS)
    assert apply_migrations(database) == [26]
    with database.transaction() as db:
        assert db.execute("SELECT default_action FROM routing_policies WHERE id='p1'").fetchone()[0] == "egress"
        assert db.execute("SELECT count(*) FROM routing_rules WHERE policy_id='p1'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM routing_applies WHERE policy_id='p1'").fetchone()[0] == 1
        db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
                   " VALUES('p2','local','amneziawg','amneziawg_native','egress','fail_closed',1,1)")
        db.execute("INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('amneziawg',1,'converged',1)")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
                       " VALUES('p3','local','socks','naive_native','direct','fail_closed',1,1)")
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name LIKE '%\\_old' ESCAPE '\\'").fetchone()[0] == 0
        assert "routing_applies_policy" in {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        db.execute("DELETE FROM routing_policies WHERE id='p1'")
        assert db.execute("SELECT count(*) FROM routing_rules WHERE policy_id='p1'").fetchone()[0] == 0



