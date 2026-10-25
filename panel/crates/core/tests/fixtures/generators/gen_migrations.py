"""Record what the Python migration runner produces, for the Rust `panel-core` tests.

Run from the repository root with the panel's Python environment:

    PYTHONPATH=. python panel/crates/core/tests/fixtures/generators/gen_migrations.py \
        panel/crates/core/tests/fixtures/migrations

Writes:
- `migrations.json`: every migration's version, name, statements (verbatim) and checksum;
- `schema-v26.json`: `sqlite_master` of an empty database migrated to the last version;
- `python-v26.sqlite3`: a database migrated and seeded by Python (the Rust runner must accept it
  and leave it untouched);
- `python-v26.json`: the canonical dump of its rows;
- `snapshot-vNN.sql` + `expected-vNN.json`: a seeded database at version NN (Python's `iterdump`)
  and the canonical dump of the rows of the same database after Python upgraded it to the last
  version (its schema is asserted to equal `schema-v26.json`).
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from panel import migrations as module
from panel.database import Database

MIGRATIONS = module.MIGRATIONS
SNAPSHOTS = (1, 4, 5, 11, 12, 14, 15, 16, 19, 21, 23, 24, 25)

# (first version the statement is valid at, statement). A snapshot at version N holds every
# statement whose version is <= N, so the rows exercise each table rebuild that follows.
SEEDS = (
    (1, "INSERT INTO admins(username,password_hash,role,created_at) VALUES('owner','$argon2id$stub','owner',1)"),
    (1, "INSERT INTO sessions(token_hash,admin_id,csrf_hash,created_at,expires_at,last_seen_at)"
        " VALUES('th',1,'ch',1,2,1)"),
    (1, "INSERT INTO login_attempts(scope,happened_at,reservation_id) VALUES('ip:192.0.2.1',5,'r1')"),
    (1, "INSERT INTO audit_log(happened_at,actor_username,action,target,detail_json,ip)"
        " VALUES(1,'owner','login','-','{\"name\": \"\\u0430\"}','127.0.0.1')"),
    (1, "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at)"
        " VALUES('edge-01','Узел 1','enrolled','{}',1,1)"),
    (1, "INSERT INTO fleet_commands(command_id,node_id,sequence,idempotency_key,protocol_version,operation,"
        "expected_revision,payload_json,status,created_at,expires_at,payload_sha256)"
        " VALUES('cmd-1','edge-01',1,'k1',1,'users.list','r0','{\"a\":1}','queued',1,301,'abc')"),
    (1, "INSERT INTO fleet_certificates(serial,node_id,fingerprint_sha256,not_before,not_after,state,issued_at)"
        " VALUES('0A','edge-01','ff',1,2,'active',1)"),
    (2, "INSERT INTO audit_log(happened_at,actor_username,action,target,ip,request_id,correlation_id,"
        "reason_code,generation,before_digest,after_digest) VALUES(2,'owner','x','t','::1','rq','co','rc',3,'b','a')"),
    (3, "INSERT INTO secret_versions(secret_id,version,purpose,grant_id,permitted_node_id,key_id,nonce,ciphertext,"
        "state,created_at,updated_at) VALUES('s1',1,'grant','g1','edge-01','k1',X'00ff10',X'deadbeef','active',1,1)"),
    (4, "UPDATE fleet_nodes SET disabled=1 WHERE node_id='edge-01'"),
    (6, "INSERT INTO clients(id,display_name,state,metadata_json,created_at,updated_at)"
        " VALUES('c1','Алиса 🙂','active','{\"a\":1}',1,2)"),
    (6, "INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,secret_id,secret_version,"
        "desired_state,observed_state,valid_until,protocol_options_json,origin,created_at,updated_at)"
        " VALUES('g1','c1','mtproxy','edge-01','alice','s1',1,'enabled','enabled',99,'{}','provisioned',1,1)"),
    (7, "INSERT INTO provisioning_operations(operation_id,client_id,status,steps_json,created_at,updated_at)"
        " VALUES('op1','c1','succeeded','[{\"grant_id\": \"g1\"}]',1,1)"),
    (8, "INSERT INTO client_subscriptions(id,client_id,public_token_hash,state,created_at,updated_at)"
        " VALUES('sub1','c1','hash1','active',1,1)"),
    (9, "INSERT INTO panel_settings(key,value,updated_at) VALUES('panel_guid','00000000-0000-4000-8000-000000000000',1)"),
    (9, "INSERT INTO api_keys(name,scope,prefix,key_hash,created_at,created_by) VALUES('mcp','monitor','pc_ab','kh',1,'owner')"),
    (10, "INSERT INTO managed_generations(generation,digest,master_guid,document_json,received_at,state)"
         " VALUES(1,'d','m','{}',1,'converged')"),
    (10, "INSERT INTO managed_resources(protocol,runtime_username,ref,generation,state,updated_at)"
         " VALUES('naive','bob','g9',1,'converged',1)"),
    (11, "UPDATE fleet_nodes SET transport='panel' WHERE node_id='edge-01'"),
    (11, "INSERT INTO node_links(node_id,panel_url,tls_verify,pinned_cert_sha256,api_key_secret_id,created_at,updated_at)"
         " VALUES('edge-01','https://edge.example','pin','aa','node-key:edge-01:1',1,1)"),
    (11, "INSERT INTO desired_generations(node_id,generation,digest,content_digest,document_json,previous_generation,"
         "created_at,created_by) VALUES('edge-01',1,'d','c','{}',0,1,'owner')"),
    (11, "INSERT INTO observed_generations(node_id,applied_generation,digest,reconcile_state,resources_json,reported_at)"
         " VALUES('edge-01',1,'d','converged','[]',1)"),
    (12, "INSERT INTO provisioning_operations(operation_id,client_id,status,steps_json,created_at,updated_at)"
         " VALUES('op2','c1','pending_remote','[]',2,2)"),
    (13, "UPDATE managed_resources SET learned_json='{\"port\": 443}'"),
    (14, "INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,default_egress,fallback,"
         "created_at,updated_at) VALUES('p1','local','naive','naive_native','egress','warp','fail_closed',1,1)"),
    (14, "INSERT INTO routing_rules(id,policy_id,position,match_json,action,created_at,updated_at)"
         " VALUES('r1','p1',1,'{\"domain\": [\"example.com\"]}','direct',1,1)"),
    (14, "INSERT INTO routing_applies(policy_id,revision,digest,backend,compiler_version,outcome,actor,created_at)"
         " VALUES('p1',1,'dg','naive_native','1','applied','owner',1)"),
    (14, "INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('naive',1,'converged',1)"),
    (15, "INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
         " VALUES('p2','local','mieru','xray_router','direct','approved_direct',1,1)"),
    (15, "UPDATE managed_egress SET router_revision='rv',router_digest='rd'"),
    (16, "UPDATE access_grants SET routing_lane='grant:g1' WHERE id='g1'"),
    (16, "INSERT INTO routing_policies(id,node_id,protocol,lane,backend,default_action,default_egress,fallback,"
         "created_at,updated_at) VALUES('p3','local','naive','grant:g1','xray_router','egress','node:x','fail_closed',1,1)"),
    (16, "INSERT INTO relay_peers(node_id,source_node_id,exit,secret_id,created_at) VALUES('edge-01','local','warp','rs',1)"),
    (16, "INSERT INTO router_relays(node_id,port,public_key,short_id,server_name,enabled,updated_at)"
         " VALUES('edge-01',8443,'pk','sid','sn',1,1)"),
    (16, "UPDATE observed_generations SET relay_json='{\"port\": 8443}'"),
    (17, "UPDATE node_links SET auto_import=0"),
    (18, "UPDATE routing_rules SET preset='ads'"),
    (19, "INSERT INTO egress_exits(id,node_id,name,protocol,settings_json,created_at,updated_at)"
         " VALUES('e1','local','home','socks','{\"server\": \"192.0.2.9\"}',1,1)"),
    (20, "UPDATE client_subscriptions SET secret_id='sub-secret',secret_version=1"),
    (21, "INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
         " VALUES('p4','local','mtproxy','mtproxy_native','direct','fail_closed',1,1)"),
    (21, "INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('mtproxy',2,'failed',2)"),
    (22, "UPDATE access_grants SET label='Метка' WHERE id='g1'"),
    (23, "INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,origin,created_at,"
         "updated_at) VALUES('g2','c1','amneziawg','local','alice-awg','enabled','provisioned',1,1)"),
    (24, "INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,origin,created_at,"
         "updated_at) VALUES('g3','c1','trusttunnel','local','alice-tt','disabled','imported',1,1)"),
    (24, "INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
         " VALUES('p5','local','trusttunnel','trusttunnel_native','direct','fail_closed',1,1)"),
    (24, "INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('trusttunnel',1,'unsupported',1)"),
    (25, "INSERT INTO metric_rollups VALUES(60,120,'local','host.cpu',0.1,3,1e-05,1e16)"),
    (25, "INSERT INTO metric_rollups VALUES(900,0,'edge-01','proto.naive.rx',12.5,1,12.5,-0.0)"),
    (26, "INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
         " VALUES('p6','local','amneziawg','amneziawg_native','egress','fail_closed',1,1)"),
    (26, "INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('amneziawg',1,'converged',1)"),
)


def migrate(path: Path, upto: int) -> list[int]:
    module.MIGRATIONS = MIGRATIONS[:upto]
    try:
        return module.apply_migrations(Database(path))
    finally:
        module.MIGRATIONS = MIGRATIONS


def seed(path: Path, upto: int) -> None:
    with Database(path).transaction() as db:
        for version, statement in SEEDS:
            if version <= upto:
                db.execute(statement)


def value(cell):
    if isinstance(cell, bytes):
        return {"blob": cell.hex()}
    return cell


def canonical_dump(path: Path, snapshot_version: int | None = None) -> dict:
    """Schema and every row, in an order both implementations get from SQL alone.

    Values that depend on the wall clock of the upgrade are nulled: `applied_at` of migrations
    applied after the snapshot, and the reserved local node's timestamps when the snapshot
    predates migration 5 (which inserts it with `strftime('%s','now')`)."""
    db = sqlite3.connect(path)
    try:
        schema = [list(row) for row in db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")]
        tables = {}
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall():
            cursor = db.execute(f'SELECT * FROM "{name}" LIMIT 0')
            columns = [column[0] for column in cursor.description]
            order = ",".join(str(index + 1) for index in range(len(columns)))
            rows = [[value(cell) for cell in row] for row in db.execute(f'SELECT * FROM "{name}" ORDER BY {order}')]
            if snapshot_version is not None and name == "schema_migrations":
                for row in rows:
                    if row[0] > snapshot_version:
                        row[3] = None
            if snapshot_version is not None and snapshot_version < 5 and name == "fleet_nodes":
                for row in rows:
                    if row[0] == "local":
                        row[columns.index("created_at")] = None
                        row[columns.index("updated_at")] = None
            tables[name] = {"columns": columns, "rows": rows}
        return {"schema": schema, "tables": tables}
    finally:
        db.close()


def write_json(path: Path, payload, *, indent: int | None = 1) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=indent) + "\n", encoding="utf-8")


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "migrations.json", [
        {"version": m.version, "name": m.name, "checksum": m.checksum, "statements": list(m.statements)}
        for m in MIGRATIONS
    ])
    with tempfile.TemporaryDirectory() as raw:
        work = Path(raw)
        fresh = work / "fresh.sqlite3"
        assert migrate(fresh, len(MIGRATIONS)) == [m.version for m in MIGRATIONS]
        schema = canonical_dump(fresh)["schema"]
        write_json(out / "schema-v26.json", schema)

        full = work / "python-v26.sqlite3"
        migrate(full, len(MIGRATIONS))
        seed(full, len(MIGRATIONS))
        for leftover in (full.with_name(full.name + "-wal"), full.with_name(full.name + "-shm")):
            assert not leftover.exists(), leftover
        shutil.copyfile(full, out / "python-v26.sqlite3")
        seeded = canonical_dump(full)
        assert seeded.pop("schema") == schema
        write_json(out / "python-v26.json", seeded, indent=None)

        for version in SNAPSHOTS:
            path = work / f"snapshot-v{version:02d}.sqlite3"
            assert migrate(path, version) == list(range(1, version + 1))
            seed(path, version)
            db = sqlite3.connect(path)
            dump = "\n".join(db.iterdump()) + "\n"
            db.close()
            (out / f"snapshot-v{version:02d}.sql").write_text(dump, encoding="utf-8")
            assert module.apply_migrations(Database(path)) == list(range(version + 1, len(MIGRATIONS) + 1))
            expected = canonical_dump(path, version)
            # An upgraded database ends with exactly the fresh schema; only the rows are recorded.
            assert expected.pop("schema") == schema
            write_json(out / f"expected-v{version:02d}.json", expected, indent=None)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
