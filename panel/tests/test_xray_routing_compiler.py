"""Policy → the router's intent (v0.5): every cell the router enforces, every refusal named,
the attach document beside the intent — and what the native backends now say about the
selectors only the router understands."""
from __future__ import annotations

import sqlite3

import pytest
from pydantic import ValidationError

from panel.database import Database
from panel.migrations import MIGRATIONS, apply_migrations
from panel.protocols import EgressTarget, RouterTarget
from panel.routing.compiler import compile
from panel.routing.document import attach_document, document_digest
from panel.routing.models import COMPILER_VERSION, PolicyInput, RoutingPolicy, RoutingRule, RuleMatch, backends_for
from panel.routing.store import RoutingStore
from panel.xray_router import ROUTER_CAPABILITIES

NAIVE_CAPS = ("whole_direct", "whole_warp", "block_domain", "block_cidr")


def _target(protocol="naive", *, attached=True, providers=None, warnings=()):
    backend = "naive_native" if protocol == "naive" else "mieru_native"
    document = attach_document(protocol) if attached else {"schema": 1, "upstream": None, "acl": []}
    return EgressTarget(protocol=protocol, backend=backend, capabilities=frozenset(NAIVE_CAPS),
                        providers=providers if providers is not None else {"warp": {"reachable": True}, "router": {"reachable": True}},
                        revision="rev-native", applied={"revision": "rev-native", "digest": document_digest(document),
                                                        "document": document},
                        mode="proxy" if attached else "direct", warnings=tuple(warnings), router_attached=attached)


def _router(*, caps=ROUTER_CAPABILITIES, providers=None, applied=None, available=True, reason=None):
    return RouterTarget(available=available, service="naive", capabilities=frozenset(caps),
                        providers=providers if providers is not None else {"warp": {"reachable": True}},
                        revision="rev-router", applied=applied, xray_version="Xray 26.3.27", reason=reason)


def _rule(action="block", *, domains=(), cidrs=(), ports=(), geosites=(), geoips=(), egress=None, rule_id=None, enabled=True):
    return RoutingRule(id=rule_id, enabled=enabled, action=action, egress=egress,
                       match=RuleMatch(domains=list(domains), cidrs=list(cidrs), ports=list(ports),
                                       geosites=list(geosites), geoips=list(geoips)))


def _policy(protocol="naive", *, backend="xray_router", default_action="direct", fallback="fail_closed", rules=()):
    return RoutingPolicy(id="p1", node_id="local", protocol=protocol, backend=backend, default_action=default_action,
                         default_egress="warp" if default_action == "egress" else None, fallback=fallback,
                         rules=list(rules), revision=1)


# -- models --------------------------------------------------------------------------


def test_rule_match_geo_codes_normalised_and_private_rejected():
    match = RuleMatch(geosites=["geosite:Category-Ads-All", "category-ads-all", "cn"], geoips=["GeoIP:CN", "cloudflare"])
    assert match.geosites == ["category-ads-all", "cn"] and match.geoips == ["cn", "cloudflare"]
    with pytest.raises(ValidationError, match="bypass"):
        RuleMatch(geoips=["private"])
    with pytest.raises(ValidationError):
        RuleMatch(geosites=["not a code"])
    assert match.selectors is True


def test_rule_match_ports_only_is_allowed_and_empty_is_not():
    match = RuleMatch(ports=[25, "80-90"])
    assert match.ports == [25, "80-90"] and match.selectors is False
    with pytest.raises(ValidationError):
        RuleMatch()


def test_backend_accepts_xray_router_and_backends_for():
    assert backends_for("naive") == ("naive_native", "xray_router")
    assert backends_for("mieru") == ("mieru_native", "xray_router")
    assert backends_for("mtproxy") == ()
    assert PolicyInput(backend="xray_router").backend == "xray_router"
    with pytest.raises(ValidationError):
        PolicyInput(backend="sing_box")
    assert COMPILER_VERSION == "2"


# -- the router compiler --------------------------------------------------------------


def test_compile_router_whole_warp_intent():
    compiled = compile(_policy(default_action="egress"), _target(), router=_router())
    assert compiled.status == "supported" and compiled.reasons == []
    assert compiled.document == {"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": []}
    assert compiled.digest == document_digest(compiled.document)
    assert compiled.attach == attach_document("naive") and compiled.backend == "xray_router"
    assert compiled.restart_required is True and compiled.runtime_version == "Xray 26.3.27"
    assert compiled.compiler_version == "2" and compiled.rollback is None


def test_compile_router_block_beside_warp_default_is_supported():
    compiled = compile(_policy(default_action="egress", rules=[_rule(domains=["example.com", "*.example.com"], rule_id="11111111-0000-4000-8000-111111111111")]),
                       _target(), router=_router())
    assert compiled.status == "supported"
    assert compiled.document["rules"] == [{"domains": ["example.com"], "geosites": [], "cidrs": [], "geoips": [], "ports": [],
                                           "action": "block", "egress": None}]


def test_compile_router_geosite_geoip_ports_in_order():
    rules = [
        _rule("block", geosites=["category-ads-all"], rule_id="aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa"),
        _rule("direct", geoips=["cn"], cidrs=["1.1.1.0/24"], rule_id="bbbbbbbb-0000-4000-8000-bbbbbbbbbbbb"),
        _rule("egress", egress="warp", ports=[443, "1000-2000"], rule_id="cccccccc-0000-4000-8000-cccccccccccc"),
        _rule("block", domains=["x.example"], enabled=False, rule_id="dddddddd-0000-4000-8000-dddddddddddd"),
    ]
    compiled = compile(_policy(rules=rules), _target(), router=_router())
    assert compiled.status == "supported"
    assert [rule["action"] for rule in compiled.document["rules"]] == ["block", "direct", "egress"]
    assert compiled.document["rules"][0]["geosites"] == ["category-ads-all"]
    assert compiled.document["rules"][1]["geoips"] == ["cn"] and compiled.document["rules"][1]["cidrs"] == ["1.1.1.0/24"]
    assert compiled.document["rules"][2]["ports"] == [443, "1000-2000"] and compiled.document["rules"][2]["egress"] == "warp"


def test_compile_router_unavailable_and_not_attached():
    compiled = compile(_policy(), _target(), router=None)
    assert compiled.status == "unsupported" and compiled.reasons[0].code == "router_unavailable"
    compiled = compile(_policy(), _target(), router=_router(available=False, reason="artifact_mismatch"))
    assert compiled.reasons[0].code == "artifact_mismatch"
    compiled = compile(_policy(), _target(attached=False), router=_router())
    assert compiled.reasons[0].code == "not_attached"


def test_compile_router_capability_missing_from_status():
    router = _router(caps=[cap for cap in ROUTER_CAPABILITIES if cap != "block_geosite"])
    compiled = compile(_policy(rules=[_rule(geosites=["cn"], rule_id="11111111-0000-4000-8000-111111111111")]), _target(), router=router)
    assert compiled.status == "unsupported"
    assert compiled.reasons[0].code == "backend_capability_missing" and compiled.reasons[0].rule_id == "11111111-0000-4000-8000-111111111111"
    assert "block_geosite" in compiled.reasons[0].message


def test_compile_router_private_destination_rejected_but_block_allowed():
    compiled = compile(_policy(rules=[_rule("direct", cidrs=["10.0.0.0/8"], rule_id="11111111-0000-4000-8000-111111111111")]), _target(), router=_router())
    assert compiled.reasons[0].code == "private_destination"
    compiled = compile(_policy(rules=[_rule("block", cidrs=["10.0.0.0/8"], domains=["localhost"])]), _target(), router=_router())
    assert compiled.status == "supported"


def test_compile_router_provider_unreachable_fail_closed_and_approved_direct():
    router = _router(providers={"warp": {"reachable": False}})
    compiled = compile(_policy(default_action="egress"), _target(), router=router)
    assert compiled.status == "unsupported" and compiled.reasons[0].code == "provider_unreachable"
    compiled = compile(_policy(default_action="egress", fallback="approved_direct",
                               rules=[_rule("egress", egress="warp", domains=["a.example"])]), _target(), router=router)
    assert compiled.status == "supported" and "provider_unreachable" in compiled.warnings
    assert compiled.document["default"] == {"action": "direct", "egress": None}
    assert compiled.document["rules"][0]["action"] == "direct" and compiled.document["rules"][0]["egress"] is None
    compiled = compile(_policy(default_action="egress"), _target(), router=_router(providers={}))
    assert compiled.reasons[0].code == "provider_unavailable"


def test_compile_router_diff_against_applied_intent_and_rollback_target():
    applied_document = {"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": []}
    router = _router(applied={"revision": "rev-router", "digest": document_digest(applied_document), "document": applied_document})
    compiled = compile(_policy(default_action="egress"), _target(), router=router)
    assert compiled.diff == [] and compiled.rollback == {"to_revision": "rev-router", "to_digest": document_digest(applied_document)}
    compiled = compile(_policy(), _target(), router=router)
    assert any('"action": "direct"' in line for line in compiled.diff) and "policy_empty" in compiled.warnings
    # A linked node reports the digest only: same digest → no diff, another → the whole document.
    router = _router(applied={"revision": "r", "digest": document_digest(applied_document), "document": None})
    assert compile(_policy(default_action="egress"), _target(), router=router).diff == []
    assert compile(_policy(), _target(), router=router).diff != []


def test_compile_router_document_size_limit():
    rules = [_rule(domains=[f"{'x' * 60}{i:03d}.{'y' * 60}.example" for i in range(64)]) for _ in range(3)]
    compiled = compile(_policy(rules=rules), _target(), router=_router())
    assert compiled.status == "unsupported" and compiled.reasons[0].code == "document_too_large"


def test_compile_router_attach_document_per_protocol():
    target = _target("mieru")
    compiled = compile(_policy("mieru", default_action="egress"), target, router=_router())
    assert compiled.attach == attach_document("mieru") and compiled.attach["rules"][0]["proxy"] == "router"


# -- what the native backends say now ---------------------------------------------------


def test_compile_native_geo_and_port_rules_are_unsupported_naming_the_router():
    native = _policy(backend="naive_native", rules=[_rule(geoips=["cn"], rule_id="eeeeeeee-0000-4000-8000-eeeeeeeeeeee"), _rule(ports=[25], rule_id="ffffffff-0000-4000-8000-ffffffffffff")])
    compiled = compile(native, _target(attached=False))
    assert compiled.status == "unsupported"
    assert [(reason.code, reason.rule_id) for reason in compiled.reasons] == [("rule_kind_unsupported", "eeeeeeee-0000-4000-8000-eeeeeeeeeeee"),
                                                                              ("rule_kind_unsupported", "ffffffff-0000-4000-8000-ffffffffffff")]
    assert all("xray_router" in reason.message for reason in compiled.reasons)


def test_compile_native_policy_on_attached_service_is_unsupported():
    compiled = compile(_policy(backend="naive_native", default_action="egress"), _target(attached=True), router=_router())
    assert compiled.status == "unsupported" and compiled.reasons[0].code == "backend_capability_missing"
    assert "attached" in compiled.reasons[0].message
    compiled = compile(_policy(backend="naive_native", default_action="egress"), _target(attached=False))
    assert compiled.status == "supported"


# -- migration 15 and the store ---------------------------------------------------------


def test_routing_v15_rebuilds_policies_keeping_rows_and_foreign_keys(tmp_path, monkeypatch):
    from panel import migrations as module

    database = Database(tmp_path / "panel.sqlite3")
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS[:14])
    assert apply_migrations(database) == list(range(1, 15))
    with database.transaction() as db:
        db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,revision,state,"
                   "created_at,updated_at) VALUES('p1','local','naive','naive_native','egress','fail_closed',3,'applied',1,1)")
        db.execute("INSERT INTO routing_rules(id,policy_id,position,enabled,match_json,action,created_at,updated_at)"
                   " VALUES('11111111-0000-4000-8000-111111111111','p1',0,1,'{\"domains\": [\"a.example\"], \"cidrs\": [], \"ports\": []}','block',1,1)")
        db.execute("INSERT INTO routing_applies(policy_id,revision,digest,backend,compiler_version,outcome,actor,created_at)"
                   " VALUES('p1',3,'d','naive_native','1','applied','owner',1)")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE routing_policies SET backend='xray_router' WHERE id='p1'")
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS)
    assert apply_migrations(database) == [15]
    with database.transaction() as db:
        row = db.execute("SELECT id,backend,revision,state FROM routing_policies").fetchone()
        assert tuple(row) == ("p1", "naive_native", 3, "applied")
        assert db.execute("SELECT count(*) FROM routing_rules WHERE policy_id='p1'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM routing_applies WHERE policy_id='p1'").fetchone()[0] == 1
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='routing_policies_old'").fetchone()[0] == 0
        db.execute("UPDATE routing_policies SET backend='xray_router' WHERE id='p1'")
        # The children still hang off the policy: deleting it cascades as before.
        db.execute("DELETE FROM routing_policies WHERE id='p1'")
        assert db.execute("SELECT count(*) FROM routing_rules").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM routing_applies").fetchone()[0] == 0
        assert {row[1] for row in db.execute("PRAGMA table_info(managed_egress)")} >= {"router_revision", "router_digest"}
        # A v0.4 rule row without the new keys still reads.
        db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,revision,state,"
                   "created_at,updated_at) VALUES('p2','local','naive','naive_native','direct','fail_closed',1,'draft',1,1)")
        db.execute("INSERT INTO routing_rules(id,policy_id,position,enabled,match_json,action,created_at,updated_at)"
                   " VALUES('22222222-0000-4000-8000-222222222222','p2',0,1,'{\"domains\": [\"a.example\"], \"cidrs\": [], \"ports\": []}','block',1,1)")
        policy = RoutingStore.get(db, "local", "naive")
        assert policy.rules[0].match.geosites == [] and policy.rules[0].match.geoips == []


def test_store_keeps_or_switches_the_backend_and_retargets(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    with database.transaction() as db:
        policy = RoutingStore.upsert(db, "local", "naive", PolicyInput(), expected_revision=None)
        assert policy.backend == "naive_native" and policy.revision == 1
        policy = RoutingStore.upsert(db, "local", "naive", PolicyInput(rules=[_rule(geoips=["cn"])]), expected_revision=1)
        assert policy.backend == "naive_native" and policy.rules[0].match.geoips == ["cn"]
        policy = RoutingStore.upsert(db, "local", "naive", PolicyInput(backend="xray_router"), expected_revision=2)
        assert policy.backend == "xray_router" and policy.revision == 3
        with pytest.raises(ValueError):
            RoutingStore.upsert(db, "local", "naive", PolicyInput(backend="mieru_native"), expected_revision=3)
        RoutingStore.mark(db, policy.id, state="applied", applied_revision=3, applied_digest="d")
        retargeted = RoutingStore.retarget(db, policy.id, "naive_native")
        assert (retargeted.backend, retargeted.revision, retargeted.state) == ("naive_native", 4, "draft")
        with pytest.raises(ValueError):
            RoutingStore.retarget(db, policy.id, "mieru_native")
        created = RoutingStore.upsert(db, "local", "mieru", PolicyInput(backend="xray_router"), expected_revision=None)
        assert created.backend == "xray_router"
