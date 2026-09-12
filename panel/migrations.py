"""Versioned, checksummed, cross-process-safe schema migrations for panel.sqlite3.

Two processes open this database — the panel and the fleet ingress — so the
runner takes `BEGIN IMMEDIATE` before touching anything, refuses a database
newer than the code, and refuses a migration whose recorded checksum no longer
matches. Nothing here imports FastAPI: `panel.agent_ingress` must stay importable
in the ingress image.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from .database import Database


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]

    @property
    def checksum(self) -> str:
        canonical = "\n".join(" ".join(statement.split()) for statement in self.statements)
        return hashlib.sha256(f"{self.version}:{self.name}\n{canonical}".encode()).hexdigest()


# Baseline = the exact tables v0.1.0 created in Store._init and FleetStore._init, with the
# columns FleetStore added incrementally already present. Older databases are aligned by
# _legacy_upgrade() first, so the baseline is a no-op for them.
BASELINE = Migration(1, "baseline-v0.1.0", (
    """CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','admin','viewer')),
      active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
      csrf_hash TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS login_attempts (
      scope TEXT NOT NULL, happened_at INTEGER NOT NULL, reservation_id TEXT NOT NULL DEFAULT '')""",
    "CREATE INDEX IF NOT EXISTS login_attempts_scope_time ON login_attempts(scope,happened_at)",
    """CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY, happened_at INTEGER NOT NULL, actor_id INTEGER,
      actor_username TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
      detail_json TEXT NOT NULL DEFAULT '{}', ip TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS fleet_nodes (
      node_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, auth_state TEXT NOT NULL,
      inventory_json TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      next_sequence INTEGER NOT NULL DEFAULT 1, last_result_sequence INTEGER NOT NULL DEFAULT 0,
      last_seen_at INTEGER)""",
    """CREATE TABLE IF NOT EXISTS fleet_commands (
      command_id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE RESTRICT,
      sequence INTEGER NOT NULL, idempotency_key TEXT NOT NULL, protocol_version INTEGER NOT NULL,
      operation TEXT NOT NULL, expected_revision TEXT NOT NULL, payload_json TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('queued','dispatched','succeeded','failed','indeterminate')),
      result_json TEXT, created_at INTEGER NOT NULL, completed_at INTEGER,
      actor TEXT NOT NULL DEFAULT 'system', expires_at INTEGER NOT NULL DEFAULT 0,
      payload_sha256 TEXT NOT NULL DEFAULT '', dispatched_at INTEGER,
      UNIQUE(node_id,sequence), UNIQUE(node_id,idempotency_key))""",
    "CREATE INDEX IF NOT EXISTS fleet_commands_node_sequence ON fleet_commands(node_id,sequence)",
    """CREATE TABLE IF NOT EXISTS fleet_certificates (
      serial TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE RESTRICT,
      fingerprint_sha256 TEXT NOT NULL UNIQUE, not_before INTEGER NOT NULL, not_after INTEGER NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('active','revoked')), issued_at INTEGER NOT NULL, revoked_at INTEGER)""",
))

# Structured audit: one row per business transaction, correlated with the HTTP request
# that caused it and carrying digests instead of values (Task 5, ADR 005).
AUDIT_V2 = Migration(2, "audit-structured", (
    "ALTER TABLE audit_log ADD COLUMN request_id TEXT",
    "ALTER TABLE audit_log ADD COLUMN correlation_id TEXT",
    "ALTER TABLE audit_log ADD COLUMN reason_code TEXT",
    "ALTER TABLE audit_log ADD COLUMN generation INTEGER",
    "ALTER TABLE audit_log ADD COLUMN before_digest TEXT",
    "ALTER TABLE audit_log ADD COLUMN after_digest TEXT",
    "CREATE INDEX IF NOT EXISTS audit_log_request ON audit_log(request_id)",
))

# Encrypted secret versions (Task 6, ADR 005). Ciphertext and nonce are BLOBs; the row's
# identity is repeated in columns so it can be rebuilt into the AAD on read.
SECRETS_V3 = Migration(3, "secret-versions", (
    """CREATE TABLE IF NOT EXISTS secret_versions (
      secret_id TEXT NOT NULL, version INTEGER NOT NULL, purpose TEXT NOT NULL,
      grant_id TEXT, permitted_node_id TEXT, key_id TEXT NOT NULL,
      nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('pending','active','retiring','revoked')),
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      PRIMARY KEY(secret_id, version))""",
    "CREATE INDEX IF NOT EXISTS secret_versions_key ON secret_versions(key_id)",
    "CREATE INDEX IF NOT EXISTS secret_versions_grant ON secret_versions(grant_id, state)",
))

# Node lifecycle (Task 7, ADR 001/003): the central host becomes a reserved node with
# kind='local' and no fleet transport; `disabled` is an operator switch the transport
# honours, so a disabled node cannot authenticate or receive commands.
NODES_V4 = Migration(4, "node-lifecycle", (
    "ALTER TABLE fleet_nodes ADD COLUMN kind TEXT NOT NULL DEFAULT 'remote' CHECK(kind IN ('local','remote'))",
    "ALTER TABLE fleet_nodes ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0",
))

# The reserved local identity (Task 9, ADR 001/003): the central host is a node like any
# other so that a grant can point at it, but it has no transport. INSERT OR IGNORE keeps the
# migration idempotent and never overwrites a pre-v0.2 node that happens to be called "local";
# NodeRegistry.insert refuses that id from now on, so a new collision cannot appear.
LOCAL_NODE_V5 = Migration(5, "local-node", (
    """INSERT OR IGNORE INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at,kind)
       VALUES('local','Этот сервер','local','{}',CAST(strftime('%s','now') AS INTEGER),
              CAST(strftime('%s','now') AS INTEGER),'local')""",
))

# Clients and their access grants (Task 10, ADR 002/006). A grant is the pair
# (protocol, node, endpoint, runtime username): that tuple is unique, so two clients
# cannot claim the same account on the same endpoint. The credential itself is never
# here — only a reference into secret_versions.
CLIENTS_V6 = Migration(6, "clients-and-grants", (
    """CREATE TABLE IF NOT EXISTS clients (
      id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('active','suspended','archived')),
      metadata_json TEXT NOT NULL DEFAULT '{}',
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS access_grants (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
      protocol TEXT NOT NULL CHECK(protocol IN ('mtproxy','naive','mieru')),
      node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE RESTRICT,
      endpoint_id TEXT NOT NULL DEFAULT 'default',
      runtime_username TEXT NOT NULL,
      secret_id TEXT, secret_version INTEGER,
      desired_state TEXT NOT NULL CHECK(desired_state IN ('enabled','disabled','deleted')),
      observed_state TEXT NOT NULL DEFAULT 'unknown'
        CHECK(observed_state IN ('unknown','pending','enabled','disabled','missing')),
      valid_from INTEGER, valid_until INTEGER,
      protocol_options_json TEXT NOT NULL DEFAULT '{}',
      origin TEXT NOT NULL CHECK(origin IN ('imported','provisioned')),
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      UNIQUE(protocol,node_id,endpoint_id,runtime_username))""",
    "CREATE INDEX IF NOT EXISTS access_grants_client ON access_grants(client_id)",
))

# The provisioning journal (Task 13, ADR 004). Three managers cannot share a
# transaction, so the operation's progress is written down instead: a restart resumes
# from the last checkpoint rather than repeating work that already reached a runtime.
PROVISIONING_V7 = Migration(7, "provisioning-operations", (
    """CREATE TABLE IF NOT EXISTS provisioning_operations (
      operation_id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
      status TEXT NOT NULL CHECK(status IN
        ('pending','applying','succeeded','compensating','compensated','manual_intervention_required')),
      steps_json TEXT NOT NULL,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS provisioning_operations_client ON provisioning_operations(client_id)",
))

# One subscription URL per client (Task 15, ADR 002). Only the token's hash is stored,
# and the partial unique index makes "at most one active URL" a database fact rather
# than a promise the service has to keep.
SUBSCRIPTIONS_V8 = Migration(8, "client-subscriptions", (
    """CREATE TABLE IF NOT EXISTS client_subscriptions (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
      public_token_hash TEXT NOT NULL UNIQUE,
      generation INTEGER NOT NULL DEFAULT 1,
      state TEXT NOT NULL CHECK(state IN ('active','revoked')),
      update_interval_hours INTEGER NOT NULL DEFAULT 12,
      last_fetched_at INTEGER,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, revoked_at INTEGER)""",
    "CREATE UNIQUE INDEX IF NOT EXISTS client_subscriptions_one_active"
    " ON client_subscriptions(client_id) WHERE state='active'",
))

# Panel-wide settings and scoped API keys (v0.3, ADR 008). The key itself is never
# stored: `prefix` finds the row, `key_hash` (SHA-256 of the full plaintext) proves it.
API_KEYS_V9 = Migration(9, "panel-settings-and-api-keys", (
    """CREATE TABLE IF NOT EXISTS panel_settings (
      key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY, name TEXT NOT NULL,
      scope TEXT NOT NULL CHECK(scope IN ('admin','monitor','node-sync')),
      prefix TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
      enabled INTEGER NOT NULL DEFAULT 1, expires_at INTEGER,
      created_at INTEGER NOT NULL, created_by TEXT NOT NULL, last_used_at INTEGER)""",
    "CREATE INDEX IF NOT EXISTS api_keys_prefix ON api_keys(prefix)",
))

# Node side of Fleet v2 (spec §4): what the central panel asked for and what this
# panel actually runs. `managed_resources` is the ownership register ADR 003 needs.
MANAGED_V10 = Migration(10, "fleet-v2-managed", (
    """CREATE TABLE IF NOT EXISTS managed_generations (
      generation INTEGER PRIMARY KEY, digest TEXT NOT NULL, master_guid TEXT NOT NULL,
      document_json TEXT NOT NULL, received_at INTEGER NOT NULL, applied_at INTEGER,
      state TEXT NOT NULL CHECK(state IN ('received','applying','converged','failed')))""",
    """CREATE TABLE IF NOT EXISTS managed_resources (
      protocol TEXT NOT NULL, runtime_username TEXT NOT NULL, ref TEXT NOT NULL,
      credential_ref TEXT, generation INTEGER NOT NULL, state TEXT NOT NULL,
      last_error TEXT, revision TEXT, updated_at INTEGER NOT NULL,
      PRIMARY KEY(protocol, runtime_username))""",
))

# Central side of Fleet v2 (spec §4): how to reach a linked panel, what was asked of it
# and what it last reported. `api_key_secret_id` points into secret_versions.
LINKS_V11 = Migration(11, "fleet-v2-links", (
    "ALTER TABLE fleet_nodes ADD COLUMN transport TEXT NOT NULL DEFAULT 'v1' CHECK(transport IN ('v1','panel'))",
    """CREATE TABLE IF NOT EXISTS node_links (
      node_id TEXT PRIMARY KEY REFERENCES fleet_nodes(node_id) ON DELETE CASCADE,
      panel_url TEXT NOT NULL, tls_verify TEXT NOT NULL CHECK(tls_verify IN ('verify','pin')),
      pinned_cert_sha256 TEXT, api_key_secret_id TEXT NOT NULL, allow_private_address INTEGER NOT NULL DEFAULT 0,
      enabled INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'unknown' CHECK(status IN ('unknown','online','offline')),
      latency_ms INTEGER, panel_version TEXT, identity_json TEXT NOT NULL DEFAULT '{}',
      status_json TEXT NOT NULL DEFAULT '{}', last_heartbeat_at INTEGER, last_error TEXT,
      config_dirty INTEGER NOT NULL DEFAULT 0, desired_generation INTEGER NOT NULL DEFAULT 0,
      acknowledged_generation INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS desired_generations (
      node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE CASCADE,
      generation INTEGER NOT NULL, digest TEXT NOT NULL, content_digest TEXT NOT NULL,
      document_json TEXT NOT NULL,
      previous_generation INTEGER NOT NULL, created_at INTEGER NOT NULL, created_by TEXT NOT NULL,
      pushed_at INTEGER, acknowledged_at INTEGER, PRIMARY KEY(node_id, generation))""",
    """CREATE TABLE IF NOT EXISTS observed_generations (
      node_id TEXT PRIMARY KEY REFERENCES fleet_nodes(node_id) ON DELETE CASCADE,
      applied_generation INTEGER NOT NULL, digest TEXT NOT NULL, reconcile_state TEXT NOT NULL,
      resources_json TEXT NOT NULL, reported_at INTEGER NOT NULL)""",
))

# An operation whose grants live on a linked panel waits for that node (spec §6):
# `pending_remote` joins the status set. SQLite cannot widen a CHECK in place, so the
# table is rebuilt the way the runner already rebuilds fleet_commands; nothing references
# provisioning_operations, so the rename touches no other table.
REMOTE_OPERATIONS_V12 = Migration(12, "provisioning-pending-remote", (
    "DROP INDEX IF EXISTS provisioning_operations_client",
    "ALTER TABLE provisioning_operations RENAME TO provisioning_operations_old",
    """CREATE TABLE provisioning_operations (
      operation_id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
      status TEXT NOT NULL CHECK(status IN
        ('pending','pending_remote','applying','succeeded','compensating','compensated',
         'manual_intervention_required')),
      steps_json TEXT NOT NULL,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""",
    """INSERT INTO provisioning_operations SELECT operation_id,client_id,status,steps_json,created_at,updated_at
       FROM provisioning_operations_old""",
    "DROP TABLE provisioning_operations_old",
    "CREATE INDEX provisioning_operations_client ON provisioning_operations(client_id)",
))

MIGRATIONS: tuple[Migration, ...] = (
    BASELINE, AUDIT_V2, SECRETS_V3, NODES_V4, LOCAL_NODE_V5, CLIENTS_V6, PROVISIONING_V7,
    SUBSCRIPTIONS_V8, API_KEYS_V9, MANAGED_V10, LINKS_V11, REMOTE_OPERATIONS_V12,
)

_FLEET_COMMANDS_STATEMENT = BASELINE.statements[6]


def _columns(db, table: str) -> set[str]:
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


def _legacy_upgrade(db) -> None:
    """Exactly what Store._init / FleetStore._init did incrementally before the runner existed."""
    if _columns(db, "login_attempts") and "reservation_id" not in _columns(db, "login_attempts"):
        db.execute("ALTER TABLE login_attempts ADD COLUMN reservation_id TEXT NOT NULL DEFAULT ''")
    if not _columns(db, "fleet_commands"):
        return
    for column, definition in (
        ("last_seen_at", "INTEGER"),
    ):
        if column not in _columns(db, "fleet_nodes"):
            db.execute(f"ALTER TABLE fleet_nodes ADD COLUMN {column} {definition}")
    for column, definition in (
        ("actor", "TEXT NOT NULL DEFAULT 'system'"),
        ("expires_at", "INTEGER NOT NULL DEFAULT 0"),
        ("payload_sha256", "TEXT NOT NULL DEFAULT ''"),
        ("dispatched_at", "INTEGER"),
    ):
        if column not in _columns(db, "fleet_commands"):
            db.execute(f"ALTER TABLE fleet_commands ADD COLUMN {column} {definition}")
    rows = db.execute(
        "SELECT command_id,payload_json,created_at FROM fleet_commands"
        " WHERE payload_sha256='' OR expires_at=0"
    ).fetchall()
    for row in rows:
        db.execute(
            "UPDATE fleet_commands SET payload_sha256=?,expires_at=? WHERE command_id=?",
            (
                hashlib.sha256(row["payload_json"].encode()).hexdigest(),
                row["created_at"] + 300,
                row["command_id"],
            ),
        )
    sql = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='fleet_commands'"
    ).fetchone()[0]
    if "'dispatched'" not in sql:
        # Verbatim FleetStore._migrate_command_status_constraint, now inside the runner's transaction.
        db.execute("DROP INDEX IF EXISTS fleet_commands_node_sequence")
        db.execute("ALTER TABLE fleet_commands RENAME TO fleet_commands_old")
        db.execute(_FLEET_COMMANDS_STATEMENT)
        db.execute(
            """INSERT INTO fleet_commands SELECT command_id,node_id,sequence,idempotency_key,protocol_version,
            operation,expected_revision,payload_json,status,result_json,created_at,completed_at,actor,expires_at,
            payload_sha256,dispatched_at FROM fleet_commands_old"""
        )
        db.execute("DROP TABLE fleet_commands_old")
        db.execute("CREATE INDEX fleet_commands_node_sequence ON fleet_commands(node_id,sequence)")


def apply_migrations(database: Database) -> list[int]:
    with database.connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL)""")
    applied: list[int] = []
    with database.transaction() as db:
        newest = db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] or 0
        if newest > MIGRATIONS[-1].version:
            raise MigrationError(
                f"database schema {newest} is newer than this code ({MIGRATIONS[-1].version})"
            )
        for migration in MIGRATIONS:
            row = db.execute(
                "SELECT checksum FROM schema_migrations WHERE version=?", (migration.version,)
            ).fetchone()
            if row is not None:
                if row["checksum"] != migration.checksum:
                    raise MigrationError(f"migration {migration.version} checksum mismatch")
                continue
            if migration is BASELINE:
                _legacy_upgrade(db)
            for statement in migration.statements:
                db.execute(statement)
            db.execute(
                "INSERT INTO schema_migrations VALUES(?,?,?,?)",
                (migration.version, migration.name, migration.checksum, int(time.time())),
            )
            applied.append(migration.version)
    return applied


def migration_status(database: Database) -> list[dict]:
    """Read-only: a v0.1.0 database has no migrations table yet, and that is an answer
    ("nothing applied"), not an error. Only `apply_migrations` creates the table."""
    with database.connect() as db:
        present = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
        ).fetchone()
        rows = (
            {row["version"]: dict(row) for row in db.execute("SELECT * FROM schema_migrations")}
            if present
            else {}
        )
    return [
        {
            "version": migration.version,
            "name": migration.name,
            "applied": migration.version in rows,
            "checksum_ok": rows.get(migration.version, {}).get("checksum") == migration.checksum,
        }
        for migration in MIGRATIONS
    ]
