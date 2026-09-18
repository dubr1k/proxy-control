"""The routing IR (ADR 006): validation, the compiler against the capability matrix (spec
§5), and the store behind migration 14."""

from __future__ import annotations

import ipaddress
import sqlite3

import pytest
from pydantic import ValidationError

from panel.database import Database
from panel.migrations import MIGRATIONS, apply_migrations
from panel.protocols import EgressTarget
from panel.routing.compiler import PRIVATE_NETWORKS, compile
from panel.routing.document import document_digest
from panel.routing.models import (
    COMPILER_VERSION,
    MAX_RULES,
    PolicyInput,
    RoutingPolicy,
    RoutingRule,
    RuleMatch,
)
from panel.routing.store import PolicyConflict, PolicyNotFound, RoutingStore

NAIVE_CAPS = frozenset({"whole_direct", "whole_warp", "block_domain", "block_cidr"})
MIERU_CAPS = NAIVE_CAPS | {"selective_domain", "selective_cidr"}


def _target(protocol="naive", *, caps=None, providers=None, applied=None, mode="direct", warnings=(),
            restart_required=False):
    backend = "naive_native" if protocol == "naive" else "mieru_native"
    if caps is None:
        caps = NAIVE_CAPS if protocol == "naive" else MIERU_CAPS
    if providers is None:
        providers = {"warp": {"reachable": True}}
    return EgressTarget(protocol=protocol, backend=backend, capabilities=frozenset(caps), providers=providers,
                        revision="rev-a", applied=applied, mode=mode, warnings=tuple(warnings),
                        restart_required=restart_required or protocol == "mieru")


def _rule(action="block", *, domains=(), cidrs=(), ports=(), egress=None, rule_id=None, enabled=True):
    return RoutingRule(id=rule_id, enabled=enabled, action=action, egress=egress,
                       match=RuleMatch(domains=list(domains), cidrs=list(cidrs), ports=list(ports)))


def _policy(protocol="naive", *, default_action="direct", fallback="fail_closed", rules=(), revision=1):
    return RoutingPolicy(id="p1", node_id="local", protocol=protocol,
                         backend="naive_native" if protocol == "naive" else "mieru_native",
                         default_action=default_action, default_egress="warp" if default_action == "egress" else None,
                         fallback=fallback, rules=list(rules), revision=revision)


# -- models ------------------------------------------------------------------------


def test_rule_match_normalizes_domains_and_cidrs():
    match = RuleMatch(domains=["Example.COM.", "*.CDN.example", "пример.рф", "example.com"],
                      cidrs=["10.1.2.3", "192.168.1.0/24", "2001:db8::1", "10.0.0.5/8"], ports=[443, "80", "1000-2000"])
    assert match.domains == ["example.com", "*.cdn.example", "xn--e1afmkfd.xn--p1ai"]
    assert match.cidrs == ["10.1.2.3/32", "192.168.1.0/24", "2001:db8::1/128", "10.0.0.0/8"]
    assert match.ports == [443, 80, "1000-2000"]


@pytest.mark.parametrize("bad", [
    {"domains": ["exa mple.com"]}, {"domains": ["*"]}, {"domains": ["a.*.com"]}, {"domains": ["-bad.com"]},
    {"cidrs": ["300.1.1.1"]}, {"cidrs": ["10.0.0.0/33"]}, {"domains": ["ok.com"], "ports": [0]},
    {"domains": ["ok.com"], "ports": ["9-1"]}, {"domains": ["ok.com"], "ports": [True]},
    {"domains": ["ok.com"], "extra": 1},
])
def test_rule_match_rejects_bad_selectors(bad):
    with pytest.raises(ValidationError):
        RuleMatch(**bad)


def test_rule_match_rejects_empty():
    with pytest.raises(ValidationError):
        RuleMatch()
    # A rule on ports alone is a valid selector since v0.5 (the router enforces it).
    assert RuleMatch(ports=[443]).ports == [443]


def test_egress_required_for_egress_action_only():
    with pytest.raises(ValidationError):
        _rule("egress")
    with pytest.raises(ValidationError):
        _rule("block", domains=["a.com"], egress="warp")
    assert _rule("egress", domains=["a.com"], egress="warp").egress == "warp"
    with pytest.raises(ValidationError):
        PolicyInput(default_action="egress")
    with pytest.raises(ValidationError):
        PolicyInput(default_action="direct", default_egress="warp")
    with pytest.raises(ValidationError):
        PolicyInput(default_action="egress", default_egress="tor")


def test_policy_limits():
    rule = _rule(domains=["a.com"])
    assert len(PolicyInput(rules=[rule] * MAX_RULES).rules) == MAX_RULES
    with pytest.raises(ValidationError):
        PolicyInput(rules=[rule] * (MAX_RULES + 1))
    with pytest.raises(ValidationError):
        RuleMatch(domains=[f"h{i}.com" for i in range(65)])
    with pytest.raises(ValidationError):
        RuleMatch(cidrs=[f"10.0.{i}.0/24" for i in range(65)])
    with pytest.raises(ValidationError):
        RuleMatch(domains=["a.com"], ports=list(range(1, 34)))
    with pytest.raises(ValidationError):
        RoutingRule(action="block", match=RuleMatch(domains=["a.com"]), note="x" * 121)


def test_policy_input_ignores_server_fields():
    policy = _policy(rules=[_rule(domains=["a.com"], rule_id="0" * 8 + "-0000-4000-8000-" + "0" * 12)], revision=7)
    policy = policy.model_copy(update={"state": "applied", "applied_revision": 7, "applied_digest": "d"})
    draft = PolicyInput.from_policy(policy)
    assert set(draft.model_dump()) == {"backend", "default_action", "default_egress", "fallback", "rules"}
    assert draft.rules[0].id == policy.rules[0].id
    with pytest.raises(ValidationError):  # the server's bookkeeping is not accepted from a client
        PolicyInput(revision=3)
    with pytest.raises(ValidationError):
        PolicyInput(state="applied")


# -- compiler: naive_native ----------------------------------------------------------


def test_compile_naive_whole_warp():
    compiled = compile(_policy(default_action="egress"), _target())
    assert compiled.status == "supported" and compiled.reasons == []
    assert compiled.document == {"schema": 1, "upstream": {"provider": "warp"}, "acl": []}
    assert compiled.digest == document_digest(compiled.document)
    assert compiled.restart_required is False and compiled.backend == "naive_native"
    assert compiled.compiler_version == COMPILER_VERSION and compiled.rollback is None


def test_compile_naive_direct():
    compiled = compile(_policy(), _target())
    assert compiled.status == "supported"
    assert compiled.document == {"schema": 1, "upstream": None, "acl": []}
    assert "policy_empty" in compiled.warnings


def test_compile_naive_block_domain_and_cidr_into_one_acl():
    rules = [_rule(domains=["example.com", "*.example.com"], rule_id="a" * 8 + "-aaaa-4aaa-8aaa-" + "a" * 12),
             _rule(cidrs=["10.0.0.0/8"]), _rule(domains=["skip.me"], enabled=False), _rule(domains=["z.example"])]
    compiled = compile(_policy(rules=rules), _target())
    assert compiled.status == "supported"
    assert compiled.document == {"schema": 1, "upstream": None,
                                 "acl": [{"deny": ["example.com", "*.example.com", "10.0.0.0/8", "z.example"]}]}
    assert "policy_empty" not in compiled.warnings


def test_compile_naive_chunks_a_long_acl_by_forwardproxy_line_limit():
    rules = [_rule(domains=[f"h{i}.example" for i in range(64)], cidrs=[f"10.0.{i}.0/24" for i in range(10)])]
    compiled = compile(_policy(rules=rules), _target())
    assert compiled.status == "supported"
    assert [len(entry["deny"]) for entry in compiled.document["acl"]] == [64, 10]


def test_compile_naive_selective_rule_is_unsupported_with_rule_id():
    rule = _rule("egress", domains=["a.com"], egress="warp", rule_id="b" * 8 + "-bbbb-4bbb-8bbb-" + "b" * 12)
    compiled = compile(_policy(rules=[rule, _rule("direct", cidrs=["1.2.3.0/24"])]), _target())
    assert compiled.status == "unsupported" and compiled.document is None and compiled.digest is None
    codes = [(reason.code, reason.rule_id) for reason in compiled.reasons]
    assert codes == [("backend_capability_missing", rule.id), ("backend_capability_missing", None)]
    assert "selective_domain" in compiled.reasons[0].message


def test_compile_naive_block_port_unsupported():
    compiled = compile(_policy(rules=[_rule(domains=["a.com"], ports=[25])]), _target())
    assert compiled.status == "unsupported"
    assert [reason.code for reason in compiled.reasons] == ["rule_kind_unsupported"]


def test_compile_naive_block_beside_warp_default_is_unsupported():
    compiled = compile(_policy(default_action="egress", rules=[_rule(domains=["a.com"])]), _target())
    assert compiled.status == "unsupported"
    assert [reason.code for reason in compiled.reasons] == ["rule_kind_unsupported"]
    assert "upstream" in compiled.reasons[0].message


# -- compiler: mieru_native ----------------------------------------------------------


def test_compile_mieru_selective_rules_in_order():
    rules = [_rule("egress", domains=["*.stream.example", "stream.example"], egress="warp"),
             _rule("block", cidrs=["203.0.113.0/24"]), _rule("direct", domains=["bank.example"]),
             _rule("block", domains=["off.example"], enabled=False)]
    compiled = compile(_policy("mieru", rules=rules), _target("mieru"))
    assert compiled.status == "supported" and compiled.restart_required is True
    assert compiled.document == {
        "schema": 1, "proxies": [{"name": "warp", "provider": "warp"}],
        "rules": [
            {"domains": ["stream.example"], "cidrs": [], "action": "PROXY", "proxy": "warp"},
            {"domains": [], "cidrs": ["203.0.113.0/24"], "action": "REJECT", "proxy": None},
            {"domains": ["bank.example"], "cidrs": [], "action": "DIRECT", "proxy": None},
        ]}


def test_compile_mieru_default_proxy_with_direct_exception():
    compiled = compile(_policy("mieru", default_action="egress", rules=[_rule("direct", domains=["bank.example"])]),
                       _target("mieru"))
    assert compiled.status == "supported"
    assert compiled.document["rules"] == [
        {"domains": ["bank.example"], "cidrs": [], "action": "DIRECT", "proxy": None},
        {"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"},
    ]
    assert compiled.document["proxies"] == [{"name": "warp", "provider": "warp"}]


def test_compile_mieru_direct_without_rules_has_no_proxies():
    compiled = compile(_policy("mieru"), _target("mieru"))
    assert compiled.document == {"schema": 1, "proxies": [], "rules": []}
    assert compiled.status == "supported" and "policy_empty" in compiled.warnings


# -- compiler: providers, capabilities, targets ---------------------------------------


@pytest.mark.parametrize("cidr", ["127.0.0.1", "10.1.2.0/24", "192.168.0.0/16", "169.254.1.1", "::1", "fd00::/8"])
def test_compile_private_destination_rejected(cidr):
    compiled = compile(_policy("mieru", rules=[_rule("direct", cidrs=[cidr])]), _target("mieru"))
    assert [reason.code for reason in compiled.reasons] == ["private_destination"]
    blocked = compile(_policy("mieru", rules=[_rule("block", cidrs=[cidr])]), _target("mieru"))
    assert blocked.status == "supported"  # blocking a private network is fine, opening one is not
    assert any(ipaddress.ip_network(cidr, strict=False).overlaps(net) for net in PRIVATE_NETWORKS
               if net.version == ipaddress.ip_network(cidr, strict=False).version)


def test_compile_private_domain_rejected():
    compiled = compile(_policy("mieru", rules=[_rule("egress", domains=["localhost"], egress="warp")]), _target("mieru"))
    assert [reason.code for reason in compiled.reasons] == ["private_destination"]


def test_compile_provider_unavailable_fail_closed():
    for fallback in ("fail_closed", "approved_direct"):
        compiled = compile(_policy(default_action="egress", fallback=fallback), _target(providers={}))
        assert compiled.status == "unsupported"
        assert [reason.code for reason in compiled.reasons] == ["provider_unavailable"]


def test_compile_provider_unreachable_warning_and_approved_direct_fallback():
    down = _target("mieru", providers={"warp": {"reachable": False}})
    closed = compile(_policy("mieru", default_action="egress"), down)
    assert closed.status == "unsupported" and [r.code for r in closed.reasons] == ["provider_unreachable"]
    rules = [_rule("egress", domains=["a.example"], egress="warp"), _rule("block", domains=["b.example"])]
    opened = compile(_policy("mieru", default_action="egress", fallback="approved_direct", rules=rules), down)
    assert opened.status == "supported" and "provider_unreachable" in opened.warnings
    assert opened.document == {"schema": 1, "proxies": [], "rules": [
        {"domains": ["a.example"], "cidrs": [], "action": "DIRECT", "proxy": None},
        {"domains": ["b.example"], "cidrs": [], "action": "REJECT", "proxy": None},
    ]}
    unknown = compile(_policy("mieru", default_action="egress"), _target("mieru", providers={"warp": {"reachable": None}}))
    assert unknown.status == "supported" and "provider_unreachable" not in unknown.warnings


def test_compile_node_lacks_egress_v1():
    compiled = compile(_policy(), _target(), node_egress_v1=False)
    assert compiled.status == "unsupported" and [r.code for r in compiled.reasons] == ["node_lacks_egress_v1"]
    disabled = compile(_policy(), None)
    assert [r.code for r in disabled.reasons] == ["protocol_disabled_on_node"]


def test_compile_capability_missing_from_target():
    target = _target(caps=NAIVE_CAPS - {"block_cidr"})
    compiled = compile(_policy(rules=[_rule(cidrs=["1.2.3.0/24"]), _rule(domains=["a.com"])]), target)
    assert [(r.code, r.message) for r in compiled.reasons] == [("backend_capability_missing", "naive_native lacks block_cidr")]
    whole = compile(_policy(default_action="egress"), _target(caps=NAIVE_CAPS - {"whole_warp"}))
    assert [r.code for r in whole.reasons] == ["backend_capability_missing"]
    mismatch = compile(_policy("naive"), _target("mieru"))
    assert [r.code for r in mismatch.reasons] == ["backend_capability_missing"] and "mieru_native" in mismatch.reasons[0].message


def test_compile_disabled_rules_skipped():
    rules = [_rule(domains=["a.com"], ports=[25], enabled=False), _rule("egress", domains=["b.com"], egress="warp", enabled=False)]
    compiled = compile(_policy(rules=rules), _target(providers={}))
    assert compiled.status == "supported" and compiled.document["acl"] == []


def test_compile_digest_is_canonical():
    first = compile(_policy(rules=[_rule(domains=["a.com"], cidrs=["10.0.0.0/8"])]), _target())
    second = compile(_policy(rules=[_rule(cidrs=["10.0.0.0/8"], domains=["a.com"])]), _target())
    assert first.digest == second.digest == document_digest(first.document)
    assert compile(_policy(rules=[_rule(domains=["b.com"])]), _target()).digest != first.digest


def test_compile_diff_against_applied():
    applied_doc = {"schema": 1, "upstream": None, "acl": []}
    target = _target(applied={"revision": "rev-a", "digest": document_digest(applied_doc), "document": applied_doc},
                     warnings=("adopts_unmanaged_upstream",))
    compiled = compile(_policy(default_action="egress"), target)
    assert compiled.rollback == {"to_revision": "rev-a", "to_digest": document_digest(applied_doc)}
    assert any(line.startswith("+") and "warp" in line for line in compiled.diff)
    assert any(line.startswith("-") and "null" in line for line in compiled.diff)
    assert "adopts_unmanaged_upstream" in compiled.warnings
    assert compile(_policy(), target).diff == []


def test_compile_document_size_limit():
    rules = [_rule(domains=[f"{'x' * 60}{i:03d}.{'y' * 60}.example" for i in range(64)]) for _ in range(3)]
    compiled = compile(_policy(rules=rules), _target())
    assert compiled.status == "unsupported" and [r.code for r in compiled.reasons] == ["document_too_large"]


# -- store ------------------------------------------------------------------------------


@pytest.fixture
def database(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    with database.transaction() as db:
        db.execute("INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at,kind) VALUES('n1','Node','pending','{}',1,1,'remote')")
    return database


def test_upsert_creates_with_revision_1(database):
    with database.transaction() as db:
        policy = RoutingStore.upsert(db, "local", "naive", PolicyInput(rules=[_rule(domains=["a.com"])]), expected_revision=None, now=10)
    assert policy.revision == 1 and policy.state == "draft" and policy.backend == "naive_native"
    assert policy.protocol == "naive" and policy.node_id == "local" and policy.created_at == 10
    assert len(policy.rules) == 1 and policy.rules[0].id and policy.rules[0].position == 0
    with database.connect() as db:
        assert RoutingStore.get(db, "local", "naive") == policy
        assert RoutingStore.get(db, "local", "mieru") is None
        assert [p.id for p in RoutingStore.list(db)] == [policy.id]
        assert RoutingStore.list(db, "n1") == []
        with pytest.raises(PolicyNotFound):
            RoutingStore.get_by_id(db, "missing")


def test_upsert_conflict(database):
    with database.transaction() as db:
        RoutingStore.upsert(db, "local", "naive", PolicyInput(), expected_revision=None)
        with pytest.raises(PolicyConflict) as failure:
            RoutingStore.upsert(db, "local", "naive", PolicyInput(), expected_revision=5)
        assert failure.value.current_revision == 1
        assert RoutingStore.upsert(db, "local", "naive", PolicyInput(), expected_revision=1).revision == 2
        assert RoutingStore.upsert(db, "local", "naive", PolicyInput(), expected_revision=None).revision == 3
        with pytest.raises(PolicyConflict):  # a create that expected an existing revision
            RoutingStore.upsert(db, "local", "mieru", PolicyInput(), expected_revision=1)
        with pytest.raises(ValueError):
            RoutingStore.upsert(db, "local", "mieru", PolicyInput(backend="naive_native"), expected_revision=None)


def test_upsert_preserves_rule_ids_and_reorders(database):
    with database.transaction() as db:
        first = RoutingStore.upsert(db, "local", "mieru", PolicyInput(rules=[
            _rule(domains=["a.com"]), _rule(domains=["b.com"]), _rule(domains=["c.com"])]), expected_revision=None)
        a, b, c = first.rules
        foreign = RoutingStore.upsert(db, "n1", "mieru", PolicyInput(rules=[_rule(domains=["x.com"])]), expected_revision=None)
        second = RoutingStore.upsert(db, "local", "mieru", PolicyInput(rules=[
            c.model_copy(update={"note": "moved up"}), _rule(domains=["new.com"]), a,
            foreign.rules[0], b.model_copy(update={"id": b.id}), b]), expected_revision=1)
    assert second.revision == 2
    assert [r.position for r in second.rules] == [0, 1, 2, 3, 4, 5]
    assert second.rules[0].id == c.id and second.rules[0].note == "moved up"
    assert second.rules[2].id == a.id and second.rules[4].id == b.id
    assert second.rules[1].id not in {a.id, b.id, c.id}
    assert second.rules[3].id != foreign.rules[0].id  # another policy's rule is not adopted
    assert second.rules[5].id != b.id  # the same id twice: the second one is a new rule
    with database.connect() as db:
        assert RoutingStore.get(db, "n1", "mieru").rules[0].id == foreign.rules[0].id


def test_delete_cascades_rules(database):
    with database.transaction() as db:
        policy = RoutingStore.upsert(db, "local", "naive", PolicyInput(rules=[_rule(domains=["a.com"])]), expected_revision=None)
        RoutingStore.record_apply(db, policy.id, revision=1, digest="d", backend="naive_native", outcome="applied")
        RoutingStore.delete(db, policy.id)
        assert db.execute("SELECT count(*) FROM routing_rules").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM routing_applies").fetchone()[0] == 0
        with pytest.raises(PolicyNotFound):
            RoutingStore.delete(db, policy.id)
        # Deleting the node takes its policies with it.
        RoutingStore.upsert(db, "n1", "naive", PolicyInput(rules=[_rule(domains=["a.com"])]), expected_revision=None)
        db.execute("DELETE FROM fleet_nodes WHERE node_id='n1'")
        assert db.execute("SELECT count(*) FROM routing_policies").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM routing_rules").fetchone()[0] == 0


def test_mark_and_history_limit(database):
    with database.transaction() as db:
        policy = RoutingStore.upsert(db, "local", "naive", PolicyInput(), expected_revision=None)
        for index in range(60):
            RoutingStore.record_apply(db, policy.id, revision=index, digest=f"d{index}", backend="naive_native",
                                      outcome="applied" if index % 2 == 0 else "failed", detail=None, actor="owner",
                                      runtime_version="2.11.4", now=index)
        RoutingStore.mark(db, policy.id, state="applied", applied_revision=1, applied_digest="d1", now=99)
        marked = RoutingStore.get_by_id(db, policy.id)
        assert (marked.state, marked.applied_revision, marked.applied_digest, marked.applied_at) == ("applied", 1, "d1", 99)
        assert marked.applied_current is True
        RoutingStore.mark(db, policy.id, state="failed", last_error="egress_unreachable", now=100)
        failed = RoutingStore.get_by_id(db, policy.id)
        assert failed.state == "failed" and failed.last_error == "egress_unreachable" and failed.applied_revision == 1
        assert failed.applied_current is False
        history = RoutingStore.history(db, policy.id)
        assert len(history) == 50 and history[0]["revision"] == 59 and history[-1]["revision"] == 10
        assert history[0]["actor"] == "owner" and history[0]["runtime_version"] == "2.11.4"
        assert RoutingStore.history(db, policy.id, limit=2)[1]["outcome"] == "applied"
        assert RoutingStore.last_applied(db, policy.id)["revision"] == 56
        with pytest.raises(sqlite3.IntegrityError):
            RoutingStore.record_apply(db, policy.id, revision=1, digest="d", backend="naive_native", outcome="bogus")


def test_routing_v14_on_populated_db(tmp_path, monkeypatch):
    """The migration is additive on a database that already carries v0.3 rows."""
    from panel import migrations as module

    database = Database(tmp_path / "panel.sqlite3")
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS[:13])
    assert apply_migrations(database) == list(range(1, 14))
    with database.transaction() as db:
        db.execute("INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at,kind) VALUES('n1','Node','pending','{}',1,1,'remote')")
        db.execute("INSERT INTO managed_resources(protocol,runtime_username,ref,generation,state,updated_at)"
                   " VALUES('naive','alice','r1',1,'converged',1)")
    monkeypatch.setattr(module, "MIGRATIONS", MIGRATIONS)
    assert apply_migrations(database) == [14, 15, 16, 17, 18, 19]
    assert apply_migrations(database) == []
    with database.transaction() as db:
        assert db.execute("SELECT count(*) FROM managed_resources").fetchone()[0] == 1
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"routing_policies", "routing_rules", "routing_applies", "managed_egress"} <= tables
        db.execute("INSERT INTO managed_egress(protocol,generation,revision,digest,state,updated_at)"
                   " VALUES('naive',3,'r','d','converged',1)")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('mtproxy',3,'converged',1)")
        with pytest.raises(sqlite3.IntegrityError):  # a policy needs its node
            db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
                       " VALUES('p','ghost','naive','naive_native','direct','fail_closed',1,1)")
        policy = RoutingStore.upsert(db, "n1", "naive", PolicyInput(), expected_revision=None)
        with pytest.raises(sqlite3.IntegrityError):  # one policy per (node, protocol)
            db.execute("INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at)"
                       " VALUES('p2','n1','naive','naive_native','direct','fail_closed',1,1)")
        assert policy.id != "p2"
