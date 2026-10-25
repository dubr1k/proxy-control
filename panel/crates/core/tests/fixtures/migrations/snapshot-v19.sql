BEGIN TRANSACTION;
CREATE TABLE access_grants (
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
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, routing_lane TEXT,
      UNIQUE(protocol,node_id,endpoint_id,runtime_username));
INSERT INTO "access_grants" VALUES('g1','c1','mtproxy','edge-01','default','alice','s1',1,'enabled','enabled',NULL,99,'{}','provisioned',1,1,'grant:g1');
CREATE TABLE admins (
      id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','admin','viewer')),
      active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
INSERT INTO "admins" VALUES(1,'owner','$argon2id$stub','owner',1,1);
CREATE TABLE api_keys (
      id INTEGER PRIMARY KEY, name TEXT NOT NULL,
      scope TEXT NOT NULL CHECK(scope IN ('admin','monitor','node-sync')),
      prefix TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
      enabled INTEGER NOT NULL DEFAULT 1, expires_at INTEGER,
      created_at INTEGER NOT NULL, created_by TEXT NOT NULL, last_used_at INTEGER);
INSERT INTO "api_keys" VALUES(1,'mcp','monitor','pc_ab','kh',1,NULL,1,'owner',NULL);
CREATE TABLE audit_log (
      id INTEGER PRIMARY KEY, happened_at INTEGER NOT NULL, actor_id INTEGER,
      actor_username TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
      detail_json TEXT NOT NULL DEFAULT '{}', ip TEXT NOT NULL, request_id TEXT, correlation_id TEXT, reason_code TEXT, generation INTEGER, before_digest TEXT, after_digest TEXT);
INSERT INTO "audit_log" VALUES(1,1,NULL,'owner','login','-','{"name": "\u0430"}','127.0.0.1',NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO "audit_log" VALUES(2,2,NULL,'owner','x','t','{}','::1','rq','co','rc',3,'b','a');
CREATE TABLE client_subscriptions (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
      public_token_hash TEXT NOT NULL UNIQUE,
      generation INTEGER NOT NULL DEFAULT 1,
      state TEXT NOT NULL CHECK(state IN ('active','revoked')),
      update_interval_hours INTEGER NOT NULL DEFAULT 12,
      last_fetched_at INTEGER,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, revoked_at INTEGER);
INSERT INTO "client_subscriptions" VALUES('sub1','c1','hash1',1,'active',12,NULL,1,1,NULL);
CREATE TABLE clients (
      id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('active','suspended','archived')),
      metadata_json TEXT NOT NULL DEFAULT '{}',
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
INSERT INTO "clients" VALUES('c1','Алиса 🙂','active','{"a":1}',1,2);
CREATE TABLE desired_generations (
      node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE CASCADE,
      generation INTEGER NOT NULL, digest TEXT NOT NULL, content_digest TEXT NOT NULL,
      document_json TEXT NOT NULL,
      previous_generation INTEGER NOT NULL, created_at INTEGER NOT NULL, created_by TEXT NOT NULL,
      pushed_at INTEGER, acknowledged_at INTEGER, PRIMARY KEY(node_id, generation));
INSERT INTO "desired_generations" VALUES('edge-01',1,'d','c','{}',0,1,'owner',NULL,NULL);
CREATE TABLE egress_exits (
      id TEXT PRIMARY KEY,
      node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      protocol TEXT NOT NULL CHECK(protocol IN ('socks','http','vless','trojan','shadowsocks')),
      settings_json TEXT NOT NULL,
      secret_id TEXT, secret_version INTEGER,
      enabled INTEGER NOT NULL DEFAULT 1,
      last_test_json TEXT,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      UNIQUE(node_id, name));
INSERT INTO "egress_exits" VALUES('e1','local','home','socks','{"server": "192.0.2.9"}',NULL,NULL,1,NULL,1,1);
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
      last_seen_at INTEGER, kind TEXT NOT NULL DEFAULT 'remote' CHECK(kind IN ('local','remote')), disabled INTEGER NOT NULL DEFAULT 0, transport TEXT NOT NULL DEFAULT 'v1' CHECK(transport IN ('v1','panel')));
INSERT INTO "fleet_nodes" VALUES('local','Этот сервер','local','{}',1792957602,1792957602,1,0,NULL,'local',0,'v1');
INSERT INTO "fleet_nodes" VALUES('edge-01','Узел 1','enrolled','{}',1,1,1,0,NULL,'remote',1,'panel');
CREATE TABLE login_attempts (
      scope TEXT NOT NULL, happened_at INTEGER NOT NULL, reservation_id TEXT NOT NULL DEFAULT '');
INSERT INTO "login_attempts" VALUES('ip:192.0.2.1',5,'r1');
CREATE TABLE managed_egress (
      protocol TEXT PRIMARY KEY CHECK(protocol IN ('naive','mieru')),
      generation INTEGER NOT NULL, revision TEXT, digest TEXT,
      state TEXT NOT NULL CHECK(state IN ('converged','failed','unsupported')),
      last_error TEXT, updated_at INTEGER NOT NULL, router_revision TEXT, router_digest TEXT);
INSERT INTO "managed_egress" VALUES('naive',1,NULL,NULL,'converged',NULL,1,'rv','rd');
CREATE TABLE managed_generations (
      generation INTEGER PRIMARY KEY, digest TEXT NOT NULL, master_guid TEXT NOT NULL,
      document_json TEXT NOT NULL, received_at INTEGER NOT NULL, applied_at INTEGER,
      state TEXT NOT NULL CHECK(state IN ('received','applying','converged','failed')));
INSERT INTO "managed_generations" VALUES(1,'d','m','{}',1,NULL,'converged');
CREATE TABLE managed_resources (
      protocol TEXT NOT NULL, runtime_username TEXT NOT NULL, ref TEXT NOT NULL,
      credential_ref TEXT, generation INTEGER NOT NULL, state TEXT NOT NULL,
      last_error TEXT, revision TEXT, updated_at INTEGER NOT NULL, learned_json TEXT,
      PRIMARY KEY(protocol, runtime_username));
INSERT INTO "managed_resources" VALUES('naive','bob','g9',NULL,1,'converged',NULL,NULL,1,'{"port": 443}');
CREATE TABLE node_links (
      node_id TEXT PRIMARY KEY REFERENCES fleet_nodes(node_id) ON DELETE CASCADE,
      panel_url TEXT NOT NULL, tls_verify TEXT NOT NULL CHECK(tls_verify IN ('verify','pin')),
      pinned_cert_sha256 TEXT, api_key_secret_id TEXT NOT NULL, allow_private_address INTEGER NOT NULL DEFAULT 0,
      enabled INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'unknown' CHECK(status IN ('unknown','online','offline')),
      latency_ms INTEGER, panel_version TEXT, identity_json TEXT NOT NULL DEFAULT '{}',
      status_json TEXT NOT NULL DEFAULT '{}', last_heartbeat_at INTEGER, last_error TEXT,
      config_dirty INTEGER NOT NULL DEFAULT 0, desired_generation INTEGER NOT NULL DEFAULT 0,
      acknowledged_generation INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, auto_import INTEGER NOT NULL DEFAULT 1);
INSERT INTO "node_links" VALUES('edge-01','https://edge.example','pin','aa','node-key:edge-01:1',0,1,'unknown',NULL,NULL,'{}','{}',NULL,NULL,0,0,0,1,1,0);
CREATE TABLE observed_generations (
      node_id TEXT PRIMARY KEY REFERENCES fleet_nodes(node_id) ON DELETE CASCADE,
      applied_generation INTEGER NOT NULL, digest TEXT NOT NULL, reconcile_state TEXT NOT NULL,
      resources_json TEXT NOT NULL, reported_at INTEGER NOT NULL, relay_json TEXT);
INSERT INTO "observed_generations" VALUES('edge-01',1,'d','converged','[]',1,'{"port": 8443}');
CREATE TABLE panel_settings (
      key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
INSERT INTO "panel_settings" VALUES('panel_guid','00000000-0000-4000-8000-000000000000',1);
CREATE TABLE provisioning_operations (
      operation_id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
      status TEXT NOT NULL CHECK(status IN
        ('pending','pending_remote','applying','succeeded','compensating','compensated',
         'manual_intervention_required')),
      steps_json TEXT NOT NULL,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
INSERT INTO "provisioning_operations" VALUES('op1','c1','succeeded','[{"grant_id": "g1"}]',1,1);
INSERT INTO "provisioning_operations" VALUES('op2','c1','pending_remote','[]',2,2);
CREATE TABLE relay_peers (
      node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE CASCADE,
      source_node_id TEXT NOT NULL,
      exit TEXT NOT NULL CHECK(exit IN ('direct','warp')),
      secret_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY(node_id, source_node_id, exit));
INSERT INTO "relay_peers" VALUES('edge-01','local','warp','rs',1);
CREATE TABLE router_relays (
      node_id TEXT PRIMARY KEY REFERENCES fleet_nodes(node_id) ON DELETE CASCADE,
      port INTEGER, public_key TEXT, short_id TEXT, server_name TEXT,
      enabled INTEGER NOT NULL DEFAULT 0,
      updated_at INTEGER NOT NULL);
INSERT INTO "router_relays" VALUES('edge-01',8443,'pk','sid','sn',1,1);
CREATE TABLE "routing_applies" (
      id INTEGER PRIMARY KEY,
      policy_id TEXT NOT NULL REFERENCES routing_policies(id) ON DELETE CASCADE,
      revision INTEGER NOT NULL, digest TEXT, backend TEXT NOT NULL, compiler_version TEXT NOT NULL,
      runtime_version TEXT,
      outcome TEXT NOT NULL CHECK(outcome IN ('applied','failed','rolled_back')),
      detail TEXT, document_json TEXT, actor TEXT NOT NULL, created_at INTEGER NOT NULL);
INSERT INTO "routing_applies" VALUES(1,'p1',1,'dg','naive_native','1',NULL,'applied',NULL,NULL,'owner',1);
CREATE TABLE routing_policies (
      id TEXT PRIMARY KEY,
      node_id TEXT NOT NULL REFERENCES fleet_nodes(node_id) ON DELETE CASCADE,
      protocol TEXT NOT NULL CHECK(protocol IN ('naive','mieru')),
      lane TEXT NOT NULL DEFAULT 'svc',
      backend TEXT NOT NULL CHECK(backend IN ('naive_native','mieru_native','xray_router')),
      default_action TEXT NOT NULL CHECK(default_action IN ('direct','egress')),
      default_egress TEXT,
      fallback TEXT NOT NULL CHECK(fallback IN ('fail_closed','approved_direct')),
      revision INTEGER NOT NULL DEFAULT 1,
      state TEXT NOT NULL DEFAULT 'draft' CHECK(state IN ('draft','applying','applied','failed','rolled_back')),
      applied_revision INTEGER, applied_digest TEXT, applied_at INTEGER, last_error TEXT,
      desired_json TEXT,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      UNIQUE(node_id, protocol, lane));
INSERT INTO "routing_policies" VALUES('p1','local','naive','svc','naive_native','egress','warp','fail_closed',1,'draft',NULL,NULL,NULL,NULL,NULL,1,1);
INSERT INTO "routing_policies" VALUES('p2','local','mieru','svc','xray_router','direct',NULL,'approved_direct',1,'draft',NULL,NULL,NULL,NULL,NULL,1,1);
INSERT INTO "routing_policies" VALUES('p3','local','naive','grant:g1','xray_router','egress','node:x','fail_closed',1,'draft',NULL,NULL,NULL,NULL,NULL,1,1);
CREATE TABLE "routing_rules" (
      id TEXT PRIMARY KEY,
      policy_id TEXT NOT NULL REFERENCES routing_policies(id) ON DELETE CASCADE,
      position INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
      match_json TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('direct','block','egress')),
      egress TEXT, note TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, preset TEXT,
      UNIQUE(policy_id, position));
INSERT INTO "routing_rules" VALUES('r1','p1',1,1,'{"domain": ["example.com"]}','direct',NULL,'',1,1,'ads');
CREATE TABLE schema_migrations (
            version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL);
INSERT INTO "schema_migrations" VALUES(1,'baseline-v0.1.0','65266de1f801afb3720c00be88b27870bff1598636d4ea1a1c37a529bbdc8033',1792957602);
INSERT INTO "schema_migrations" VALUES(2,'audit-structured','f094bd8f6e7a21e390b9d021cc65f8db1663eb6cc2d27d7370e63b79b0826c1d',1792957602);
INSERT INTO "schema_migrations" VALUES(3,'secret-versions','154d0677662fe5ef743706e23ac3934cf3c1b66abe2e0d3b0447e763aead47ad',1792957602);
INSERT INTO "schema_migrations" VALUES(4,'node-lifecycle','0db82e9647af5823246f7976bc55154705a8c66fab37235d6999169907f9256a',1792957602);
INSERT INTO "schema_migrations" VALUES(5,'local-node','a6c4042ff026a51e1e9cb5a814eff944b5bcce8b13362af6769f80a8ca38633c',1792957602);
INSERT INTO "schema_migrations" VALUES(6,'clients-and-grants','e9b0c301fb155193f8a57908b5a594df4239750ae46436a51b18849c91891e9d',1792957602);
INSERT INTO "schema_migrations" VALUES(7,'provisioning-operations','2ef3fab99218ab4b466cd961d35b8e5de2f85d5998bf7026477b7467edff7642',1792957602);
INSERT INTO "schema_migrations" VALUES(8,'client-subscriptions','999ab285cba4061ccc16698ef930007d7d2a2ab4b0959504712507931298a1e0',1792957602);
INSERT INTO "schema_migrations" VALUES(9,'panel-settings-and-api-keys','4f7ee8475c471e6a7d872bff9a59a688d5ded2260d3733740673f0f1c083834b',1792957602);
INSERT INTO "schema_migrations" VALUES(10,'fleet-v2-managed','2cb4b8da09553a7146a3866218c6100c82a4d6bbf6b359d5d93681445f572600',1792957602);
INSERT INTO "schema_migrations" VALUES(11,'fleet-v2-links','d4d672944a9854fece96e449cbdf20519757253fa9f228884d37cef878c77ec8',1792957602);
INSERT INTO "schema_migrations" VALUES(12,'provisioning-pending-remote','0e409295295f7e5eb9068703d17230168d7c43e5bb856e44c0e2298db07281aa',1792957602);
INSERT INTO "schema_migrations" VALUES(13,'fleet-v2-learned-options','d6b39ee2cfee0822a97589d729f1804c7212680042ae8d072ea6f3eb98ff5d00',1792957602);
INSERT INTO "schema_migrations" VALUES(14,'routing-policies','628ac9b5966a545caf3c32eea49fa68db24ca30694299a23195fb338663141a2',1792957602);
INSERT INTO "schema_migrations" VALUES(15,'routing-xray-router','3e50af81b5f555d0ccdcb16ff6af120ae5b86e727d7e676c33ce731f85d18f6e',1792957602);
INSERT INTO "schema_migrations" VALUES(16,'routing-chains-lanes','f0e8b982652d2f95d6f6f78594f77023905e3acbbd8cbdd9be0ade6550c5f559',1792957602);
INSERT INTO "schema_migrations" VALUES(17,'links-auto-import','7b0cf9f4a1f854b5d167d605207a5569f2c3bf78e2630fd7aa19f96edb5b421e',1792957602);
INSERT INTO "schema_migrations" VALUES(18,'routing-presets','3c3d33b5d60b106bb5f49b95e42a63c0bffbf8625d9da411a58d162f4f153a53',1792957602);
INSERT INTO "schema_migrations" VALUES(19,'routing-exits','cae2c5422b2c9876a55160464f940eb83ee4f8aeeabbe00c5148094e3405c72f',1792957602);
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
CREATE INDEX access_grants_client ON access_grants(client_id);
CREATE UNIQUE INDEX client_subscriptions_one_active ON client_subscriptions(client_id) WHERE state='active';
CREATE INDEX api_keys_prefix ON api_keys(prefix);
CREATE INDEX provisioning_operations_client ON provisioning_operations(client_id);
CREATE INDEX routing_applies_policy ON routing_applies(policy_id, id);
COMMIT;
