"""The routing model and store of v0.7: exits through other nodes (`node:<guid>[,<guid>][:warp]`),
lanes on a policy's key, migration 16 (lanes, grant lanes, relay peers and relays)."""
from __future__ import annotations

import sqlite3

import pytest
from pydantic import ValidationError

from panel.database import Database
from panel.migrations import MIGRATIONS, apply_migrations
from panel.routing.models import (
    PolicyInput,
    RoutingRule,
    RuleMatch,
    exit_hops,
    is_node_exit,
    normalise_exit,
)
from panel.routing.store import RoutingStore

GUID_B = "b" * 32
GUID_C = "c" * 32


def _rule(egress: str | None = None, action: str = "egress", **match) -> RoutingRule:
    return RoutingRule(match=RuleMatch(**(match or {"domains": ["a.example"]})), action=action, egress=egress)


def test_an_exit_is_warp_or_a_chain_of_nodes_with_the_last_hops_exit():
    assert normalise_exit("warp") == "warp"
    assert normalise_exit(f"node:{GUID_B}") == f"node:{GUID_B}"
    assert normalise_exit(f"NODE:{GUID_B}:WARP") == f"node:{GUID_B}:warp"
    assert normalise_exit(f"node:{GUID_B},{GUID_C}:warp") == f"node:{GUID_B},{GUID_C}:warp"
    assert exit_hops("warp") == ([], None) and exit_hops(f"node:{GUID_B}") == ([GUID_B], "direct")
    assert exit_hops(f"node:{GUID_B},{GUID_C}:warp") == ([GUID_B, GUID_C], "warp")
    assert is_node_exit(f"node:{GUID_B}") and not is_node_exit("warp") and not is_node_exit(None)
    for bad in ("direct", "node:", "node:has space", f"node:{GUID_B}:direct", f"node:{GUID_B},{GUID_B}",
                f"node:{GUID_B},{GUID_C},{'d' * 32},{'e' * 32}", "socks5://x", "", None, 5):
        with pytest.raises(ValueError):
            normalise_exit(bad)


def test_rules_and_defaults_accept_node_exits_and_refuse_the_rest():
    rule = _rule(f"node:{GUID_B}:warp")
    assert rule.egress == f"node:{GUID_B}:warp" and rule.action == "egress"
    policy = PolicyInput(default_action="egress", default_egress=f"node:{GUID_B},{GUID_C}", rules=[rule, _rule("warp")])
    assert policy.default_egress == f"node:{GUID_B},{GUID_C}"
    assert policy.exits() == [f"node:{GUID_B},{GUID_C}", f"node:{GUID_B}:warp", "warp"]
    assert policy.node_exits() == [f"node:{GUID_B},{GUID_C}", f"node:{GUID_B}:warp"]
    with pytest.raises(ValidationError):
        _rule("node:nope!")
    with pytest.raises(ValidationError):
        PolicyInput(default_action="egress", default_egress="direct")
    with pytest.raises(ValidationError):
        _rule("warp", action="direct")


def test_migration_16_adds_lanes_relay_tables_and_keeps_every_row(tmp_path, monkeypatch):
    from panel import migrations as module

    database = Database(tmp_path / "panel.sqlite3")
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS[:15])
    assert apply_migrations(database) == list(range(1, 16))
    with database.transaction() as db:
        db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,default_egress,fallback,revision,state,"
                   "created_at,updated_at) VALUES('p1','local','naive','xray_router','egress','warp','fail_closed',2,'applied',1,1)")
        db.execute("INSERT INTO routing_rules(id,policy_id,position,enabled,match_json,action,egress,created_at,updated_at)"
                   " VALUES('11111111-0000-4000-8000-111111111111','p1',0,1,'{\"domains\": [\"a.example\"]}','egress','warp',1,1)")
        db.execute("INSERT INTO routing_applies(policy_id,revision,digest,backend,compiler_version,outcome,actor,created_at)"
                   " VALUES('p1',2,'d','xray_router','2','applied','owner',1)")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE routing_policies SET default_egress='node:" + GUID_B + "' WHERE id='p1'")
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS)
    assert apply_migrations(database) == [16, 17, 18, 19, 20]
    with database.transaction() as db:
        row = db.execute("SELECT id,lane,default_egress,revision,state FROM routing_policies").fetchone()
        assert tuple(row) == ("p1", "svc", "warp", 2, "applied")
        assert db.execute("SELECT count(*) FROM routing_rules WHERE policy_id='p1'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM routing_applies WHERE policy_id='p1'").fetchone()[0] == 1
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        db.execute("UPDATE routing_policies SET default_egress='node:" + GUID_B + "' WHERE id='p1'")
        # the key now carries the lane: a second policy for a grant lane on the same service
        db.execute("INSERT INTO routing_policies(id,node_id,protocol,lane,backend,default_action,fallback,revision,state,"
                   "created_at,updated_at) VALUES('p2','local','naive','grant:g1','xray_router','direct','fail_closed',1,'draft',1,1)")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO routing_policies(id,node_id,protocol,lane,backend,default_action,fallback,revision,state,"
                       "created_at,updated_at) VALUES('p3','local','naive','svc','xray_router','direct','fail_closed',1,'draft',1,1)")
        assert "routing_lane" in {r[1] for r in db.execute("PRAGMA table_info(access_grants)")}
        assert {r[1] for r in db.execute("PRAGMA table_info(relay_peers)")} >= {"node_id", "source_node_id", "exit", "secret_id", "created_at"}
        assert {r[1] for r in db.execute("PRAGMA table_info(router_relays)")} >= {"node_id", "port", "public_key", "short_id", "server_name", "enabled", "updated_at"}
        db.execute("DELETE FROM routing_policies WHERE id='p1'")
        assert db.execute("SELECT count(*) FROM routing_rules").fetchone()[0] == 0


def test_store_keys_policies_by_lane(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    with database.transaction() as db:
        service = RoutingStore.upsert(db, "local", "naive", PolicyInput(), expected_revision=None)
        lane = RoutingStore.upsert(db, "local", "naive", PolicyInput(default_action="egress", default_egress=f"node:{GUID_B}"),
                                   expected_revision=None, lane="grant:g1")
        assert service.lane == "svc" and lane.lane == "grant:g1" and service.id != lane.id
        assert RoutingStore.get(db, "local", "naive").id == service.id
        assert RoutingStore.get(db, "local", "naive", lane="grant:g1").id == lane.id
        assert RoutingStore.get(db, "local", "naive", lane="grant:none") is None
        assert [p.lane for p in RoutingStore.list(db, "local")] == ["svc", "grant:g1"]
        assert [p.lane for p in RoutingStore.lanes_of(db, "local", "naive")] == ["svc", "grant:g1"]
        # a lane policy is deleted on its own; the service policy stays
        RoutingStore.delete(db, lane.id)
        assert RoutingStore.get(db, "local", "naive", lane="grant:g1") is None and RoutingStore.get(db, "local", "naive") is not None
