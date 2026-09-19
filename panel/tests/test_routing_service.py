"""RoutingService on the local node: targets, preview, apply, rollback — manager I/O
outside the transaction, the outcome and its audit row inside one."""

from __future__ import annotations

import json

import pytest

from panel.database import Database
from panel.migrations import apply_migrations
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.nodes.registry import NodeRegistry
from panel.protocols import MieruAdapter, NaiveAdapter, TelemtAdapter
from panel.routing.compiler import direct_document
from panel.routing.document import document_digest
from panel.routing.models import PolicyInput, RoutingRule, RuleMatch
from panel.routing.service import RoutingError, RoutingService
from panel.routing.store import RoutingStore
from panel.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio
ACTOR = {"id": 1, "username": "owner", "role": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": "req-1"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def stand(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    naive, mieru = MemoryNaive(), MemoryMieru()
    adapters = {
        "mtproxy": TelemtAdapter(MemoryTelemt(public_host="proxy.example.com", public_port=443), public_host="proxy.example.com"),
        "naive": NaiveAdapter(naive, public_host="naive.example.com"),
        "mieru": MieruAdapter(mieru, public_host="mieru.example.com"),
    }
    enabled = {"naive": True, "mieru": True}
    service = RoutingService(database, RoutingStore(database), adapters, NodeRegistry(database),
                             enabled=lambda protocol: enabled.get(protocol, True))
    return {"database": database, "service": service, "naive": naive, "mieru": mieru, "enabled": enabled,
            "adapters": adapters}


def _warp(**extra):
    return PolicyInput(default_action="egress", default_egress="warp", **extra)


def _block(*domains):
    return PolicyInput(rules=[RoutingRule(action="block", match=RuleMatch(domains=list(domains)))])


def _audits(database, action):
    with database.connect() as db:
        rows = db.execute("SELECT target, detail_json FROM audit_log WHERE action=? ORDER BY id", (action,)).fetchall()
    return [(row["target"], json.loads(row["detail_json"])) for row in rows]


async def test_targets_lists_local_protocols_with_backends_and_mtproxy_out_of_scope(stand):
    service = stand["service"]
    stand["mieru"].reachable = False
    service.save("local", "naive", _warp(), expected_revision=None, **CTX)
    items = await service.targets()
    assert [(i["node_id"], i["protocol"]) for i in items] == [("local", "mtproxy"), ("local", "naive"), ("local", "mieru")]
    mtproxy, naive, mieru = items
    assert mtproxy["backend"] is None and mtproxy["reason"] == "protocol_out_of_scope" and mtproxy["policy"] is None
    assert naive["backend"] == "naive_native" and naive["egress_v1"] is True and naive["kind"] == "local"
    assert naive["providers"] == {"warp": {"reachable": True}} and "whole_warp" in naive["capabilities"]
    assert naive["policy"]["revision"] == 1 and naive["policy"]["state"] == "draft" and naive["policy"]["applied_current"] is False
    assert mieru["providers"] == {"warp": {"reachable": False}} and mieru["reason"] is None
    stand["enabled"]["mieru"] = False
    assert (await service.targets())[2]["reason"] == "protocol_disabled_on_node"
    stand["naive"].broken = True
    assert (await service.targets())[1]["reason"] == "manager_unavailable"
    assert "socks5://" not in json.dumps(await service.targets())


async def test_targets_say_whether_the_node_already_runs_the_policy(stand):
    """v0.9: a hand-written upstream that names the provider makes the node run exactly what
    a draft compiles to — the target says so (`matches_node`), instead of a bare «не применено»;
    a policy the node drifted away from after an apply says the opposite."""
    service, naive = stand["service"], stand["naive"]
    naive.egress_document = {"schema": 1, "upstream": {"provider": "warp"}, "acl": []}  # adopted line, no journal
    service.save("local", "naive", _warp(), expected_revision=None, **CTX)
    service.save("local", "mieru", _warp(), expected_revision=None, **CTX)
    items = {item["protocol"]: item for item in await service.targets()}
    assert items["naive"]["policy"]["applied_current"] is False and items["naive"]["policy"]["matches_node"] is True
    assert items["mieru"]["policy"]["matches_node"] is False
    assert items["mtproxy"]["policy"] is None
    await service.apply("local", "mieru", expected_revision=1, **CTX)
    assert (await service.targets())[2]["policy"]["matches_node"] is True
    stand["mieru"].egress_document = {"schema": 1, "proxies": [], "rules": []}  # changed behind the panel's back
    assert (await service.targets())[2]["policy"]["matches_node"] is False
    stand["naive"].broken = True
    assert (await service.targets())[1]["policy"]["matches_node"] is None


async def test_preview_of_a_draft_never_saves_and_reports_unsupported_rules(stand):
    service = stand["service"]
    with pytest.raises(RoutingError) as failure:
        await service.preview("local", "naive", None)
    assert failure.value.status == 404 and failure.value.code == "policy_not_found"
    draft = PolicyInput(rules=[RoutingRule(action="egress", egress="warp", match=RuleMatch(domains=["a.com"]))])
    compiled = await service.preview("local", "naive", draft)
    assert compiled.status == "unsupported" and compiled.reasons[0].code == "backend_capability_missing"
    assert (await service.preview("local", "mieru", draft)).status == "supported"
    with pytest.raises(RoutingError) as failure:
        await service.preview("local", "mtproxy", draft)
    assert failure.value.status == 422 and failure.value.code == "protocol_out_of_scope"
    with pytest.raises(RoutingError) as failure:
        await service.preview("ghost", "naive", draft)
    assert failure.value.status == 404 and failure.value.code == "node_not_found"
    with pytest.raises(RoutingError) as failure:
        await service.preview("local", "naive", PolicyInput(backend="mieru_native"))
    assert failure.value.code == "backend_mismatch"
    with stand["database"].connect() as db:
        assert RoutingStore.list(db) == []
    stand["naive"].broken = True
    down = await service.preview("local", "naive", draft)
    assert down.status == "unsupported" and down.reasons[0].code == "manager_unavailable"


async def test_apply_local_calls_manager_and_records_applied(stand):
    service, database, naive = stand["service"], stand["database"], stand["naive"]
    policy = service.save("local", "naive", _warp(), expected_revision=None, **CTX)
    assert (await service.preview("local", "naive", None)).status == "supported"
    result = await service.apply("local", "naive", expected_revision=1, **CTX)
    updated, applied, compiled = result["policy"], result["applied"], result["compiled"]
    assert updated.state == "applied" and updated.applied_revision == 1 and updated.applied_current is True
    assert updated.applied_digest == compiled.digest == applied.digest == document_digest(compiled.document)
    assert naive.egress_document == compiled.document and ("egress_apply", f"routing:{policy.id}:1") in naive.calls
    history = service.history("local", "naive")
    assert len(history) == 1 and history[0]["outcome"] == "applied" and history[0]["actor"] == "owner"
    assert json.loads(history[0]["detail"])["manager_revision"] == applied.revision
    audits = _audits(database, "routing.policy.apply")
    assert audits == [(policy.id, {"node_id": "local", "protocol": "naive", "lane": "svc", "revision": 1, "outcome": "applied",
                                   "digest": compiled.digest, "manager_revision": applied.revision,
                                   "readback_sha256": applied.readback_sha256, "replayed": False})]
    # The target now carries the applied document; a second apply of the same revision replays.
    again = await service.apply("local", "naive", expected_revision=1, **CTX)
    assert again["applied"].replayed is True and (await service.preview("local", "naive", None)).diff == []
    # Editing moves the policy ahead of what is applied.
    edited = service.save("local", "naive", _block("x.example"), expected_revision=1, **CTX)
    assert edited.revision == 2 and edited.state == "applied" and edited.applied_current is False
    assert (await service.preview("local", "naive", None)).rollback == {"to_revision": applied.revision,
                                                                          "to_digest": applied.digest}


async def test_apply_unsupported_is_422_without_manager_call(stand):
    service, naive = stand["service"], stand["naive"]
    service.save("local", "naive", _warp(rules=[RoutingRule(action="block", match=RuleMatch(domains=["a.com"]))]),
                 expected_revision=None, **CTX)
    with pytest.raises(RoutingError) as failure:
        await service.apply("local", "naive", expected_revision=1, **CTX)
    assert failure.value.status == 422 and failure.value.code == "unsupported"
    assert failure.value.compiled.reasons[0].code == "rule_kind_unsupported"
    assert naive.calls == [] and service.get("local", "naive").state == "draft"
    with pytest.raises(RoutingError) as failure:
        await service.apply("local", "naive", expected_revision=7, **CTX)
    assert failure.value.status == 409 and failure.value.code == "policy_conflict"


async def test_apply_manager_conflict_marks_failed(stand):
    service, naive, database = stand["service"], stand["naive"], stand["database"]
    policy = service.save("local", "naive", _warp(), expected_revision=None, **CTX)
    naive.egress_fail_next = "egress_readback_mismatch"
    with pytest.raises(RoutingError) as failure:
        await service.apply("local", "naive", expected_revision=1, **CTX)
    assert failure.value.status == 409 and failure.value.code == "egress_readback_mismatch"
    failed = service.get("local", "naive")
    assert failed.state == "failed" and failed.last_error == "egress_readback_mismatch" and failed.applied_revision is None
    assert service.history("local", "naive")[0]["outcome"] == "failed"
    assert _audits(database, "routing.policy.apply")[0][1]["outcome"] == "failed"
    naive.egress_fail_next = "manual_intervention_required"
    with pytest.raises(RoutingError) as failure:
        await service.apply("local", "naive", expected_revision=1, **CTX)
    assert failure.value.status == 503
    naive.broken = True
    with pytest.raises(RoutingError) as failure:
        await service.apply("local", "naive", expected_revision=1, **CTX)
    assert failure.value.status == 502 and failure.value.code == "manager_unavailable"
    assert policy.id == service.get("local", "naive").id


async def test_apply_unreachable_provider_leaves_policy_unchanged(stand):
    service, mieru = stand["service"], stand["mieru"]
    service.save("local", "mieru", _block("a.example"), expected_revision=None, **CTX)
    await service.apply("local", "mieru", expected_revision=1, **CTX)
    service.save("local", "mieru", _warp(), expected_revision=1, **CTX)
    mieru.reachable = False
    with pytest.raises(RoutingError) as failure:  # the compiler already knows: fail-closed, no manager call
        await service.apply("local", "mieru", expected_revision=2, **CTX)
    assert failure.value.status == 422 and failure.value.compiled.reasons[0].code == "provider_unreachable"
    mieru.reachable = True
    mieru.egress_fail_next = "egress_unreachable"  # the manager's own probe at apply time
    with pytest.raises(RoutingError) as failure:
        await service.apply("local", "mieru", expected_revision=2, **CTX)
    assert failure.value.status == 409 and failure.value.code == "egress_unreachable"
    policy = service.get("local", "mieru")
    assert policy.revision == 2 and policy.applied_revision == 1 and policy.state == "failed"
    assert mieru.egress_document["rules"][0]["action"] == "REJECT"  # the node still runs revision 1


async def test_rollback_local(stand):
    service, naive = stand["service"], stand["naive"]
    with pytest.raises(RoutingError) as failure:
        await service.rollback("local", "naive", expected_revision=1, **CTX)
    assert failure.value.status == 404
    service.save("local", "naive", _block("a.example"), expected_revision=None, **CTX)
    first = await service.apply("local", "naive", expected_revision=1, **CTX)
    service.save("local", "naive", _warp(), expected_revision=1, **CTX)
    await service.apply("local", "naive", expected_revision=2, **CTX)
    with pytest.raises(RoutingError) as failure:
        await service.rollback("local", "naive", expected_revision=1, **CTX)
    assert failure.value.code == "policy_conflict"
    result = await service.rollback("local", "naive", expected_revision=2, **CTX)
    policy = result["policy"]
    assert policy.state == "rolled_back" and policy.applied_revision == 1 and policy.applied_digest == first["applied"].digest
    assert naive.egress_document["upstream"] is None and result["applied"].digest == first["applied"].digest
    assert service.history("local", "naive")[0]["outcome"] == "rolled_back"
    assert _audits(stand["database"], "routing.policy.rollback")[0][1]["to_revision"] == 1
    # Back to the floor the first apply adopted: nothing the policy ever produced.
    result = await service.rollback("local", "naive", expected_revision=2, **CTX)
    assert result["policy"].applied_revision is None and result["applied"].digest == document_digest(naive.egress_document)
    with pytest.raises(RoutingError) as failure:
        await service.rollback("local", "naive", expected_revision=2, **CTX)
    assert failure.value.code == "egress_no_previous" and failure.value.status == 409


async def test_delete_refuses_an_applied_policy_until_reset(stand):
    service, database = stand["service"], stand["database"]
    service.save("local", "mieru", _block("a.example"), expected_revision=None, **CTX)
    await service.apply("local", "mieru", expected_revision=1, **CTX)
    with pytest.raises(RoutingError) as failure:
        service.delete("local", "mieru", **CTX)
    assert failure.value.status == 409 and failure.value.code == "policy_applied"
    service.save("local", "mieru", PolicyInput(), expected_revision=1, **CTX)
    with pytest.raises(RoutingError):  # saved as direct, but revision 1 is still what runs
        service.delete("local", "mieru", **CTX)
    await service.apply("local", "mieru", expected_revision=2, **CTX)
    assert service.get("local", "mieru").applied_digest == document_digest(direct_document("mieru_native"))
    service.delete("local", "mieru", **CTX)
    with pytest.raises(RoutingError) as failure:
        service.get("local", "mieru")
    assert failure.value.code == "policy_not_found"
    assert _audits(database, "routing.policy.delete")[0][1]["protocol"] == "mieru"
    # A never-applied policy goes at once.
    service.save("local", "naive", _warp(), expected_revision=None, **CTX)
    service.delete("local", "naive", **CTX)


async def test_apply_io_outside_transaction(stand, tmp_path):
    """The manager call must not run under BEGIN IMMEDIATE: an adapter that itself touches
    the database (a second connection, short timeout) would otherwise hit «database is locked»."""
    service, adapter = stand["service"], stand["adapters"]["naive"]
    other = Database(tmp_path / "panel.sqlite3", timeout=0.2)
    inner = adapter.apply_egress

    async def apply_egress(document, *, expected_revision, operation_id):
        with other.transaction() as db:
            db.execute("SELECT count(*) FROM routing_policies").fetchone()
        return await inner(document, expected_revision=expected_revision, operation_id=operation_id)

    adapter.apply_egress = apply_egress
    service.save("local", "naive", _warp(), expected_revision=None, **CTX)
    assert (await service.apply("local", "naive", expected_revision=1, **CTX))["policy"].state == "applied"
