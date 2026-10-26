"""Golden vectors for `panel-nodes`: what the Python panel's node lifecycle produces.

Run on ams-test with the panel venv against a copy of this tree, from the repository root:

    PYTHONPATH=. PANEL_IMPL=python /root/dev/proxy-control/.venv/bin/python \
        panel/crates/nodes/tests/fixtures/generators/gen_nodes.py panel/crates/nodes/tests/fixtures

Writes (every id, name and key below is made up for this recording; nothing is in use anywhere):

- `nodes.db` — a migrated database seeded with every node shape the views distinguish (the local
  node, v1 nodes enrolled/online/stale/never/revoked/unenrolled, linked panels with and without
  an observed generation, odd inventories), certificates, fleet v1 commands, clients and grants;
- `nodes.json` — what the service layer makes of it at `now`: the node views (`asdict`), the
  registry rows and link rows, the grant/command counts, the `node-list` CLI line, then a sequence
  of lifecycle mutations (results or errors) with the rows and audit lines they leave behind, and
  `NodeRegistry.insert` cases;
- `http.db` + `http.json` — the same seed inside a running panel (in-process, the manager doubles
  over their sockets) and the exchanges of the node routes: request, status, content type and the
  body bytes, plus the panel GUID and the audit rows the requests wrote.

Time is pinned: the services' clock and the registry's/audit's `time.time()` answer `NOW`.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import types
from dataclasses import asdict
from pathlib import Path

os.environ.setdefault("PANEL_IMPL", "python")

from panel import audit as audit_module  # noqa: E402
from panel.amneziawg import MemoryAmneziawg  # noqa: E402
from panel.database import Database  # noqa: E402
from panel.fleet import FleetStore, ProtocolError  # noqa: E402
from panel.migrations import apply_migrations  # noqa: E402
from panel.mieru import MemoryMieru  # noqa: E402
from panel.naive import MemoryNaive  # noqa: E402
from panel.nodes import registry as registry_module  # noqa: E402
from panel.nodes.registry import NodeRegistry  # noqa: E402
from panel.nodes.service import NodeConflict, NodeLifecycleService  # noqa: E402
from panel.telemt import MemoryTelemt  # noqa: E402
from panel.tests.harness import fake_managers  # noqa: E402
from panel.tests.harness.server import start_panel  # noqa: E402

NOW = 1793000000
PASSWORD = "correct horse battery staple"
VIEWER_PASSWORD = "viewer-password-123"
LINKED_A = "a1b2c3d4-0000-4000-8000-000000000001"
LINKED_B = "a1b2c3d4-0000-4000-8000-000000000002"
NODE_IDS = ["local", "edge-01", "edge-02", "edge-03", "edge-04", "edge-05", "edge-06", LINKED_A, LINKED_B]

FIXED_TIME = types.SimpleNamespace(time=lambda: float(NOW))


class FixedClock:
    @staticmethod
    def time() -> float:
        return float(NOW)

    @staticmethod
    def monotonic() -> float:
        return float(NOW - 1_700_000_000)


def pin_time() -> None:
    """The registry and the audit log read `time.time()` themselves; the services take a clock."""
    registry_module.time = FIXED_TIME
    audit_module.time = FIXED_TIME


def body(value) -> str:
    """FastAPI's JSONResponse bytes."""
    return json.dumps(value, ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":"))


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=1, ensure_ascii=False) + "\n")


def snapshot(source: Path, target: Path) -> None:
    """A self-contained copy (WAL folded in, rollback journal) of a live database."""
    if target.exists():
        target.unlink()
    src, dst = sqlite3.connect(source), sqlite3.connect(target)
    try:
        src.backup(dst)
        dst.execute("PRAGMA journal_mode=DELETE")
        dst.execute("VACUUM")
    finally:
        src.close()
        dst.close()


def seed(db: sqlite3.Connection) -> None:
    db.execute("UPDATE fleet_nodes SET display_name=?,updated_at=? WHERE node_id='local'",
               ("Амстердам «центр»", NOW - 500))
    node = """INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at,
              next_sequence,last_result_sequence,last_seen_at,kind,disabled,transport) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"""
    inventory = {"hostname": "edge-01.example", "telemt_version": "3.4.25", "api_token": "made-up-leak",
                 "capabilities": ["telemt.inventory.refresh", "mieru.inspect", 7, "telemt.user.enable"],
                 "region": "eu-central", "agent_version": "1.0"}
    db.execute(node, ("edge-01", "Франкфурт edge", "connected", json.dumps(inventory), NOW - 9000, NOW - 100,
                      4, 1, NOW - 30, "remote", 0, "v1"))
    db.execute(node, ("edge-02", "Never seen", "unenrolled", "{}", NOW - 8000, NOW - 8000, 1, 0, None,
                      "remote", 0, "v1"))
    db.execute(node, ("edge-03", "Revoked", "revoked", '{"telemt_version": "", "platform": "linux"}', NOW - 7000,
                      NOW - 600, 1, 0, NOW - 600, "remote", 1, "v1"))
    db.execute(node, ("edge-04", "Odd inventory", "enrolled", "[1, 2]", NOW - 6000, NOW - 6000, 1, 0, None,
                      "remote", 0, "v1"))
    db.execute(node, ("edge-05", "On the edge", "connected",
                      '{"capabilities": "telemt.user.enable", "telemt_version": "3.5.0"}', NOW - 5000, NOW - 90,
                      2, 1, NOW - 90, "remote", 0, "v1"))
    db.execute(node, ("edge-06", "Stale", "connected", '{"telemt_version": "3.4.0", "capabilities": []}',
                      NOW - 5000, NOW - 91, 1, 0, NOW - 91, "remote", 0, "v1"))
    db.execute(node, (LINKED_A, "Ниш", "linked", "{}", NOW - 4000, NOW - 50, 1, 0, None, "remote", 1, "panel"))
    db.execute(node, (LINKED_B, "Second panel", "linked", "{}", NOW - 3000, NOW - 3000, 1, 0, None, "remote", 0,
                      "panel"))
    cert = """INSERT INTO fleet_certificates(serial,node_id,fingerprint_sha256,not_before,not_after,state,issued_at,
              revoked_at) VALUES(?,?,?,?,?,?,?,?)"""
    db.execute(cert, ("AA00", "edge-01", "0" * 64, NOW - 9000, NOW + 86400, "revoked", NOW - 9000, NOW - 8000))
    db.execute(cert, ("AA01", "edge-01", "1" * 64, NOW - 8000, NOW + 86400, "active", NOW - 8000, None))
    db.execute(cert, ("BB01", "edge-03", "2" * 64, NOW - 7000, NOW + 86400, "revoked", NOW - 7000, NOW - 650))
    db.execute(cert, ("CC01", "edge-04", "3" * 64, NOW - 6000, NOW + 86400, "active", NOW - 6000, None))
    db.execute(cert, ("DD01", "edge-05", "4" * 64, NOW - 5000, NOW + 86400, "active", NOW - 5000, None))
    db.execute(cert, ("EE01", "edge-06", "5" * 64, NOW - 5000, NOW + 86400, "active", NOW - 5000, None))
    command = """INSERT INTO fleet_commands(command_id,node_id,sequence,idempotency_key,protocol_version,operation,
                 expected_revision,payload_json,status,result_json,created_at,completed_at,actor,expires_at,
                 payload_sha256,dispatched_at) VALUES(?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?)"""
    db.execute(command, ("00000000-0000-4000-8000-000000000001", "edge-01", 1, "refresh-0001",
                         "telemt.inventory.refresh", "rev-1", "{}", "succeeded", '{"message":"ok"}', NOW - 300,
                         NOW - 290, "owner", NOW, "", NOW - 295))
    db.execute(command, ("00000000-0000-4000-8000-000000000002", "edge-01", 2, "disable-alice-1",
                         "telemt.user.disable", "rev-1", '{"username":"alice"}', "dispatched", None, NOW - 200, None,
                         "owner", NOW + 100, "", NOW - 190))
    db.execute(command, ("00000000-0000-4000-8000-000000000003", "edge-01", 3, "enable-alice-1",
                         "telemt.user.enable", "rev-1", '{"username":"alice"}', "queued", None, NOW - 100, None,
                         "owner", NOW + 200, "", None))
    db.execute(command, ("00000000-0000-4000-8000-000000000004", "edge-05", 1, "refresh-0002",
                         "telemt.inventory.refresh", "rev-2", "{}", "failed",
                         '{"message":"command rejected (ProtocolError)"}', NOW - 100, NOW - 90, "system", NOW, "", None))
    link = """INSERT INTO node_links(node_id,panel_url,tls_verify,pinned_cert_sha256,api_key_secret_id,
              allow_private_address,enabled,status,latency_ms,panel_version,identity_json,status_json,
              last_heartbeat_at,last_error,config_dirty,desired_generation,acknowledged_generation,created_at,
              updated_at,auto_import) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
    identity = {"api_version": 2, "guid": LINKED_A, "master_guid": "c0ffee00-0000-4000-8000-000000000000",
                "panel_version": "3.3.0", "name": "Ниш",
                "protocols": {"amneziawg": {"versions": ["2.0", "1.5"]}, "mtproxy": {"enabled": True}}}
    db.execute(link, (LINKED_A, "https://node-a.example", "pin", "ab" * 32, f"node-key:{LINKED_A}:0a1b2c3d", 0, 0,
                      "online", 42, "3.3.0", json.dumps(identity), json.dumps({"uptime": 5, "load": 0.25}),
                      NOW - 5, None, 1, 7, 6, NOW - 4000, NOW - 50, 0))
    db.execute(link, (LINKED_B, "https://node-b.example:8443", "verify", None, f"node-key:{LINKED_B}:deadbeef", 1, 1,
                      "unknown", None, None, "{}", "{}", None, "TimeoutError", 0, 0, 0, NOW - 3000, NOW - 3000, 1))
    db.execute("""INSERT INTO observed_generations(node_id,applied_generation,digest,reconcile_state,resources_json,
                  reported_at,relay_json) VALUES(?,?,?,?,?,?,?)""",
               (LINKED_A, 6, "d" * 64, "converged", "[]", NOW - 5, None))
    db.execute("""INSERT INTO clients(id,display_name,state,metadata_json,created_at,updated_at)
                  VALUES('client-1','Alice','active','{}',?,?)""", (NOW, NOW))
    grant = """INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,origin,
               created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)"""
    db.execute(grant, ("grant-1", "client-1", "mtproxy", "edge-02", "alice", "enabled", "provisioned", NOW, NOW))
    db.execute(grant, ("grant-2", "client-1", "mtproxy", "edge-03", "alice", "deleted", "provisioned", NOW, NOW))
    db.execute(grant, ("grant-3", "client-1", "naive", LINKED_A, "alice", "disabled", "imported", NOW, NOW))
    db.execute(grant, ("grant-4", "client-1", "mieru", LINKED_A, "alice", "enabled", "provisioned", NOW, NOW))
    db.execute(grant, ("grant-5", "client-1", "naive", LINKED_B, "alice", "deleted", "imported", NOW, NOW))


def outcome(call):
    try:
        value = call()
    except (NodeConflict, ProtocolError) as exc:
        return {"error": type(exc).__name__, "message": str(exc)}
    except KeyError:
        return {"error": "KeyError"}
    except sqlite3.IntegrityError:
        return {"error": "IntegrityError"}
    if hasattr(value, "node_id"):
        return {"ok": body(asdict(value))}
    return {"ok": value}


def table(path: Path, sql: str) -> list[dict]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(sql)]
    finally:
        connection.close()


def record_service(out: Path, work: Path) -> None:
    path = work / "service.sqlite3"
    database = Database(path)
    apply_migrations(database)
    with database.connect() as db:
        seed(db)
    snapshot(path, out / "nodes.db")
    service = NodeLifecycleService(database, FleetStore(path), clock=FixedClock)
    result: dict = {"now": NOW, "node_ids": NODE_IDS}
    result["list"] = body([asdict(view) for view in service.list()])
    result["get"] = {node_id: outcome(lambda node_id=node_id: service.get(node_id)) for node_id in [*NODE_IDS, "ghost"]}
    result["cli_node_list"] = json.dumps([asdict(view) for view in service.list()], sort_keys=True, default=str)
    with database.connect() as db:
        result["rows"] = body(NodeRegistry.rows(db))
        result["row"] = {node_id: body(NodeRegistry.row(db, node_id)) for node_id in NODE_IDS}
        result["link_rows"] = body([NodeRegistry.link_row(row)
                                    for row in db.execute("SELECT * FROM node_links ORDER BY node_id")])
        result["counts"] = {node_id: {"active_grants": NodeRegistry.active_grants(db, node_id),
                                      "provisioned_grants": NodeRegistry.provisioned_grants(db, node_id),
                                      "pending_commands": NodeRegistry.pending_commands(db, node_id)}
                            for node_id in [*NODE_IDS, "ghost"]}
    ctx = {"actor": {"id": 1, "username": "owner"}, "ip": "203.0.113.7", "request_id": "req-1"}
    cli = {"actor": {"username": "cli"}, "ip": "cli"}
    steps = [
        ("rename", "local", "  Амстердам  ", ctx),
        ("rename", "ghost", "x", ctx),
        ("rename", "edge-01", "   ", ctx),
        ("rename", "edge-01", "x" * 129, ctx),
        ("rename", "edge-01", "　Tokyo ", ctx),
        ("rename", "edge-01", "я" * 128, cli),
        ("set_disabled", "local", True, ctx),
        ("set_disabled", "edge-01", True, ctx),
        ("set_disabled", "edge-02", True, ctx),
        ("set_disabled", "edge-03", True, ctx),
        ("set_disabled", "edge-03", False, cli),
        ("set_disabled", LINKED_A, True, ctx),
        ("set_disabled", LINKED_A, False, ctx),
        ("set_disabled", LINKED_B, True, cli),
        ("set_disabled", "ghost", True, ctx),
        ("set_disabled", "local", False, ctx),
        ("set_disabled", "edge-02", False, ctx),
    ]
    mutations = []
    for operation, node_id, value, context in steps:
        mutations.append({"op": operation, "node_id": node_id, "value": value,
                          "actor": context["actor"], "ip": context["ip"], "request_id": context.get("request_id"),
                          "result": outcome(lambda: getattr(service, operation)(node_id, value, **context))})
    result["mutations"] = mutations
    inserts = [
        ("Bad_ID", "x", "remote", "v1"), ("local", "Impostor", "remote", "v1"), ("edge-07", "  ", "remote", "v1"),
        ("edge-07", "y" * 129, "remote", "v1"), ("-edge", "x", "remote", "v1"), ("a" * 65, "x", "remote", "v1"),
        ("edge-01", "Duplicate", "remote", "v1"), ("edge-07", "  New\tedge ", "remote", "v1"),
        ("c0ffee00-0000-4000-8000-0000000000aa", "Linked", "remote", "panel"), ("x", "One", "remote", "v1"),
        ("edge.07-b", "Dots", "remote", "v1"), ("edge-07\n", "Newline", "remote", "v1"),
    ]
    insert_results = []
    for node_id, display_name, kind, transport in inserts:
        def insert(node_id=node_id, display_name=display_name, kind=kind, transport=transport):
            with database.transaction() as db:
                NodeRegistry.insert(db, node_id, display_name, kind=kind, transport=transport)
            return None
        insert_results.append({"node_id": node_id, "display_name": display_name, "kind": kind,
                               "transport": transport, "result": outcome(insert)})
    result["inserts"] = insert_results
    result["after"] = {
        "fleet_nodes": table(path, "SELECT * FROM fleet_nodes ORDER BY node_id"),
        "node_links": table(path, "SELECT node_id,enabled,updated_at FROM node_links ORDER BY node_id"),
        "audit_log": table(path, "SELECT * FROM audit_log ORDER BY id"),
    }
    write_json(out / "nodes.json", result)


async def owner_session(server, username: str, password: str):
    http = server.http("testserver")
    page = await http.get("/login")
    response = await http.post("/api/auth/login", json={"username": username, "password": password},
                               headers={"X-CSRF-Token": page.cookies["panel_csrf"]})
    assert response.status_code in (200, 204), (response.status_code, response.text)
    http.headers["X-CSRF-Token"] = http.cookies["panel_csrf"]
    return http


async def record_http(out: Path, work: Path) -> None:
    server = start_panel(work, name="nodes", telemt=MemoryTelemt(), naive=MemoryNaive(), mieru=MemoryMieru(),
                         amneziawg=MemoryAmneziawg(versions=("2.0", "1.5")), naive_enabled=True,
                         naive_public_host="naive.example.com", mieru_enabled=True, amneziawg_enabled=True,
                         amneziawg_public_host="awg.example.com", trusttunnel_enabled=False)
    try:
        server.clock.set(NOW)
        server.create_admin("owner", PASSWORD, "owner")
        server.create_admin("viewer", VIEWER_PASSWORD, "viewer")
        with server.db(write=True) as db:
            seed(db)
        snapshot(server.db_path, out / "http.db")
        server.mieru.broken = True
        owner = await owner_session(server, "owner", PASSWORD)
        viewer = await owner_session(server, "viewer", VIEWER_PASSWORD)
        anonymous = server.http("testserver")
        no_csrf = server.http("testserver")
        no_csrf.cookies = owner.cookies
        sessions = {"owner": owner, "viewer": viewer, "anonymous": anonymous, "no-csrf": no_csrf}
        plan = [
            ("owner", "GET", "/api/nodes", None),
            ("viewer", "GET", "/api/nodes/local", None),
            ("owner", "GET", "/api/nodes/edge-01", None),
            ("owner", "GET", f"/api/nodes/{LINKED_A}", None),
            ("owner", "GET", f"/api/nodes/{LINKED_B}", None),
            ("owner", "GET", "/api/nodes/edge-04", None),
            ("owner", "GET", "/api/nodes/ghost", None),
            ("anonymous", "GET", "/api/nodes", None),
            ("owner", "POST", "/api/nodes/edge-01/rename", {"display_name": "  Новое имя  "}),
            ("owner", "POST", "/api/nodes/edge-01/rename", {"display_name": "   "}),
            ("owner", "POST", "/api/nodes/edge-01/rename", {"display_name": ""}),
            ("owner", "POST", "/api/nodes/edge-01/rename", {"display_name": "z" * 129}),
            ("owner", "POST", "/api/nodes/edge-01/rename", {}),
            ("owner", "POST", "/api/nodes/edge-01/rename", {"display_name": 5, "extra": True}),
            ("owner", "POST", "/api/nodes/edge-01/rename", [1]),
            ("owner", "POST", "/api/nodes/ghost/rename", {"display_name": "x"}),
            ("owner", "POST", "/api/nodes/local/rename", {"display_name": "Амстердам"}),
            ("viewer", "POST", "/api/nodes/edge-01/rename", {"display_name": "x"}),
            ("no-csrf", "POST", "/api/nodes/edge-01/rename", {"display_name": "x"}),
            ("anonymous", "POST", "/api/nodes/edge-01/disable", None),
            ("owner", "POST", "/api/nodes/local/disable", None),
            ("owner", "POST", "/api/nodes/edge-01/disable", None),
            ("owner", "POST", "/api/nodes/edge-02/disable", None),
            ("owner", "POST", "/api/nodes/edge-03/disable", None),
            ("owner", "POST", "/api/nodes/edge-03/enable", None),
            ("owner", "POST", f"/api/nodes/{LINKED_A}/disable", None),
            ("owner", "POST", f"/api/nodes/{LINKED_A}/enable", None),
            ("owner", "POST", "/api/nodes/ghost/disable", None),
            ("owner", "POST", "/api/nodes/ghost/enable", None),
            ("owner", "POST", "/api/nodes/local/enable", None),
            ("viewer", "POST", "/api/nodes/edge-03/disable", None),
            ("owner", "GET", "/api/nodes", None),
        ]
        exchanges = []
        for who, method, path, payload in plan:
            kwargs = {} if payload is None else {"json": payload}
            response = await sessions[who].request(method, path, **kwargs)
            exchanges.append({"as": who, "method": method, "path": path, "json": payload,
                              "status": response.status_code,
                              "content_type": response.headers.get("content-type"),
                              "body": response.content.decode("utf-8")})
        for http in sessions.values():
            if http is not no_csrf:
                await http.aclose()
        with server.db() as db:
            audits = [{key: row[key] for key in row.keys() if key not in {"id", "request_id"}}
                      for row in db.execute("SELECT * FROM audit_log WHERE action LIKE 'node.%' ORDER BY id")]
        result = {"now": NOW, "panel_guid": server.state.panel_guid,
                  "services_note": "telemt ok, naive ok, mieru broken, amneziawg 2.0+1.5, trusttunnel off",
                  "exchanges": exchanges, "audit_log": audits}
        write_json(out / "http.json", result)
    finally:
        server.close()
        fake_managers.close_all()


def main() -> int:
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    pin_time()
    work = Path(tempfile.mkdtemp(prefix="panel-nodes-goldens-"))
    try:
        record_service(out, work)
        asyncio.run(record_http(out, work))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
