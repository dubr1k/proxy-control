BEGIN TRANSACTION;
CREATE TABLE admins (
      id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','admin','viewer')),
      active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
INSERT INTO "admins" VALUES(1,'owner','$argon2id$stub','owner',1,1);
CREATE TABLE audit_log (
      id INTEGER PRIMARY KEY, happened_at INTEGER NOT NULL, actor_id INTEGER,
      actor_username TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
      detail_json TEXT NOT NULL DEFAULT '{}', ip TEXT NOT NULL, request_id TEXT, correlation_id TEXT, reason_code TEXT, generation INTEGER, before_digest TEXT, after_digest TEXT);
INSERT INTO "audit_log" VALUES(1,1,NULL,'owner','login','-','{"name": "\u0430"}','127.0.0.1',NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO "audit_log" VALUES(2,2,NULL,'owner','x','t','{}','::1','rq','co','rc',3,'b','a');
CREATE TABLE fleet_certificates (
      serial TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE RESTRICT,
      fingerprint_sha256 TEXT NOT NULL UNIQUE, not_before INTEGER NOT NULL, not_after INTEGER NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('active','revoked')), issued_at INTEGER NOT NULL, revoked_at INTEGER);
INSERT INTO "fleet_certificates" VALUES('0A','edge-01','ff',1,2,'active',1,NULL);
CREATE TABLE fleet_commands (
      command_id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE RESTRICT,
      sequence INTEGER NOT NULL, idempotency_key TEXT NOT NULL, protocol_version INTEGER NOT NULL,
      operation TEXT NOT NULL, expected_revision TEXT NOT NULL, payload_json TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('queued','dispatched','succeeded','failed','indeterminate')),
      result_json TEXT, created_at INTEGER NOT NULL, completed_at INTEGER,
      actor TEXT NOT NULL DEFAULT 'system', expires_at INTEGER NOT NULL DEFAULT 0,
      payload_sha256 TEXT NOT NULL DEFAULT '', dispatched_at INTEGER,
      UNIQUE(node_id,sequence), UNIQUE(node_id,idempotency_key));
INSERT INTO "fleet_commands" VALUES('cmd-1','edge-01',1,'k1',1,'users.list','r0','{"a":1}','queued',NULL,1,NULL,'system',301,'abc',NULL);
CREATE TABLE fleet_nodes (
      node_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, auth_state TEXT NOT NULL,
      inventory_json TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      next_sequence INTEGER NOT NULL DEFAULT 1, last_result_sequence INTEGER NOT NULL DEFAULT 0,
      last_seen_at INTEGER, kind TEXT NOT NULL DEFAULT 'remote' CHECK(kind IN ('local','remote')), disabled INTEGER NOT NULL DEFAULT 0);
INSERT INTO "fleet_nodes" VALUES('edge-01','Узел 1','enrolled','{}',1,1,1,0,NULL,'remote',1);
CREATE TABLE login_attempts (
      scope TEXT NOT NULL, happened_at INTEGER NOT NULL, reservation_id TEXT NOT NULL DEFAULT '');
INSERT INTO "login_attempts" VALUES('ip:192.0.2.1',5,'r1');
CREATE TABLE schema_migrations (
            version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL);
INSERT INTO "schema_migrations" VALUES(1,'baseline-v0.1.0','65266de1f801afb3720c00be88b27870bff1598636d4ea1a1c37a529bbdc8033',1792957600);
INSERT INTO "schema_migrations" VALUES(2,'audit-structured','f094bd8f6e7a21e390b9d021cc65f8db1663eb6cc2d27d7370e63b79b0826c1d',1792957600);
INSERT INTO "schema_migrations" VALUES(3,'secret-versions','154d0677662fe5ef743706e23ac3934cf3c1b66abe2e0d3b0447e763aead47ad',1792957600);
INSERT INTO "schema_migrations" VALUES(4,'node-lifecycle','0db82e9647af5823246f7976bc55154705a8c66fab37235d6999169907f9256a',1792957600);
CREATE TABLE secret_versions (
      secret_id TEXT NOT NULL, version INTEGER NOT NULL, purpose TEXT NOT NULL,
      grant_id TEXT, permitted_node_id TEXT, key_id TEXT NOT NULL,
      nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('pending','active','retiring','revoked')),
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      PRIMARY KEY(secret_id, version));
INSERT INTO "secret_versions" VALUES('s1',1,'grant','g1','edge-01','k1',X'00FF10',X'DEADBEEF','active',1,1);
CREATE TABLE sessions (
      token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
      csrf_hash TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL);
INSERT INTO "sessions" VALUES('th',1,'ch',1,2,1);
CREATE INDEX login_attempts_scope_time ON login_attempts(scope,happened_at);
CREATE INDEX fleet_commands_node_sequence ON fleet_commands(node_id,sequence);
CREATE INDEX audit_log_request ON audit_log(request_id);
CREATE INDEX secret_versions_key ON secret_versions(key_id);
CREATE INDEX secret_versions_grant ON secret_versions(grant_id, state);
COMMIT;
