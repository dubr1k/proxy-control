"""RoutingService with the node's Xray-router (v0.5): targets that name the router, attach
and detach as explicit operator actions, policies applied and rolled back through the
router — the router first, the native manager second, and the outcome in one transaction."""
from __future__ import annotations

import json

import pytest

from panel.database import Database
from panel.migrations import apply_migrations
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.nodes.registry import NodeRegistry
from panel.protocols import MieruAdapter, NaiveAdapter, RouterAdapter, TelemtAdapter
from panel.routing.document import ROUTER_DIRECT_INTENT, attach_document, document_digest
from panel.routing.models import PolicyInput, RoutingRule, RuleMatch
from panel.routing.service import RoutingError, RoutingService
from panel.routing.store import RoutingStore
from panel.telemt import MemoryTelemt
from panel.xray_router import MemoryXrayRouter

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
    naive, mieru, router = MemoryNaive(), MemoryMieru(), MemoryXrayRouter()
    naive.router_url, mieru.router_url = "socks5://127.0.0.1:45101", "socks5://127.0.0.1:45102"
    adapters = {
        "mtproxy": TelemtAdapter(MemoryTelemt(public_host="proxy.example.com", public_port=443), public_host="proxy.example.com"),
        "naive": NaiveAdapter(naive, public_host="naive.example.com"),
        "mieru": MieruAdapter(mieru, public_host="mieru.example.com"),
    }
    service = RoutingService(database, RoutingStore(database), adapters, NodeRegistry(database), router=RouterAdapter(router))
    return {"database": database, "service": service, "naive": naive, "mieru": mieru, "router": router}


def _warp(**extra):
    return PolicyInput(default_action="egress", default_egress="warp", **extra)


def _rules(*rules, **extra):
    return PolicyInput(rules=list(rules), **extra)


def _block(domains=(), **match):
    return RoutingRule(action="block", match=RuleMatch(domains=list(domains), **match))


def _audits(database, action):
    with database.connect() as db:
        rows = db.execute("SELECT target, detail_json FROM audit_log WHERE action=? ORDER BY id", (action,)).fetchall()
    return [(row["target"], json.loads(row["detail_json"])) for row in rows]


async def _item(service, protocol="naive"):
    return next(item for item in await service.targets() if item["protocol"] == protocol)


async def test_targets_show_router_available_and_not_attached(stand):
    item = await _item(stand["service"])
    assert item["router"] == {"available": True, "attached": False, "xray_version": "Xray 26.3.27 (memory)",
                              "restart_required": True, "reason": None}
    assert item["backend"] == "naive_native" and item["providers"]["router"] == {"reachable": True}
    assert "block_geosite" not in item["capabilities"]
    assert (await _item(stand["service"], "mtproxy"))["router"] is None


async def test_router_none_means_targets_report_no_router(stand):
    stand["service"].router = None
    item = await _item(stand["service"])
    assert item["router"] is None and item["backend"] == "naive_native"
    with pytest.raises(RoutingError) as caught:
        await stand["service"].attach("local", "naive", **CTX)
    assert caught.value.code == "router_unavailable"


async def test_attach_naive_applies_router_direct_then_native_upstream_and_retargets_policy(stand):
    service, naive, router = stand["service"], stand["naive"], stand["router"]
    service.save("local", "naive", _rules(_block(["example.com"])), expected_revision=None, **CTX)
    item = await service.attach("local", "naive", **CTX)
    assert item["backend"] == "xray_router" and item["router"]["attached"] is True
    assert "block_geosite" in item["capabilities"] and item["policy"]["backend"] == "xray_router"
    assert item["policy"]["state"] == "draft" and item["policy"]["revision"] == 2
    # The native manager was handed the attach document after the router was left pass-through.
    assert naive.egress_document == attach_document("naive")
    assert router.documents["naive"] == ROUTER_DIRECT_INTENT and router.calls == []  # already pass-through: no apply
    assert [call for call in naive.calls if call[0] == "egress_apply"][-1][1].startswith("routing:attach:naive:")
    audits = _audits(stand["database"], "routing.target.attach")
    assert audits[-1][1]["backend"] == "xray_router" and audits[-1][1]["outcome"] == "attached"
    # Attaching again is a no-op on the managers.
    calls = len(naive.calls)
    again = await service.attach("local", "naive", **CTX)
    assert again["router"]["attached"] is True and len(naive.calls) == calls


async def test_attach_creates_empty_draft_policy_when_none(stand):
    item = await stand["service"].attach("local", "mieru", **CTX)
    assert item["policy"]["backend"] == "xray_router" and item["policy"]["revision"] == 1
    assert stand["mieru"].egress_document == attach_document("mieru")
    policy = stand["service"].get("local", "mieru")
    assert policy.backend == "xray_router" and policy.rules == [] and policy.state == "draft"


async def test_attach_refuses_applied_native_policy_with_rules(stand):
    service = stand["service"]
    service.save("local", "naive", _warp(), expected_revision=None, **CTX)
    await service.apply("local", "naive", expected_revision=1, **CTX)
    with pytest.raises(RoutingError) as caught:
        await service.attach("local", "naive", **CTX)
    assert (caught.value.status, caught.value.code) == (409, "policy_applied")
    assert stand["naive"].egress_document["upstream"] == {"provider": "warp"}


async def test_attach_refuses_when_router_unreachable_from_manager_or_absent(stand):
    stand["naive"].router_reachable = False
    with pytest.raises(RoutingError) as caught:
        await stand["service"].attach("local", "naive", **CTX)
    assert caught.value.code == "router_unreachable"
    stand["naive"].router_reachable, stand["naive"].router_url = True, None
    with pytest.raises(RoutingError) as caught:
        await stand["service"].attach("local", "naive", **CTX)
    assert caught.value.code == "router_unavailable"
    stand["naive"].router_url = "socks5://127.0.0.1:45101"
    stand["router"].artifact_error = "digest"
    with pytest.raises(RoutingError) as caught:
        await stand["service"].attach("local", "naive", **CTX)
    assert (caught.value.status, caught.value.code) == (503, "artifact_mismatch")
    stand["router"].artifact_error, stand["router"].available = None, False
    with pytest.raises(RoutingError) as caught:
        await stand["service"].attach("local", "naive", **CTX)
    assert caught.value.code == "router_unavailable"
    assert (await _item(stand["service"]))["router"] == {"available": False, "attached": False, "xray_version": None,
                                                         "restart_required": True, "reason": "router_unavailable"}


async def test_apply_router_policy_calls_router_and_records_applied(stand):
    service, router = stand["service"], stand["router"]
    await service.attach("local", "naive", **CTX)
    service.save("local", "naive", _warp(rules=[_block(["example.com"]), RoutingRule(action="block", match=RuleMatch(geosites=["category-ads-all"]))]),
                 expected_revision=1, **CTX)
    result = await service.apply("local", "naive", expected_revision=2, **CTX)
    assert result["compiled"].backend == "xray_router" and result["compiled"].attach == attach_document("naive")
    assert router.documents["naive"]["default"] == {"action": "egress", "egress": "warp"}
    assert router.documents["naive"]["rules"][1]["geosites"] == ["category-ads-all"]
    assert router.calls[-1][0] == "apply" and router.calls[-1][2] == f"routing:{result['policy'].id}:2"
    assert result["policy"].state == "applied" and result["policy"].applied_digest == document_digest(router.documents["naive"])
    assert result["applied"].revision == (await service.router.target("naive")).revision
    history = service.history("local", "naive")
    assert history[0]["backend"] == "xray_router" and history[0]["outcome"] == "applied"
    assert history[0]["runtime_version"] == "Xray 26.3.27 (memory)"
    assert stand["naive"].egress_document == attach_document("naive")  # the native side did not move


async def test_apply_router_policy_on_detached_service_is_409_not_attached(stand):
    service = stand["service"]
    service.save("local", "naive", _warp(backend="xray_router"), expected_revision=None, **CTX)
    with pytest.raises(RoutingError) as caught:
        await service.apply("local", "naive", expected_revision=1, **CTX)
    assert (caught.value.status, caught.value.code) == (409, "not_attached")
    assert caught.value.compiled.reasons[0].code == "not_attached"
    assert stand["router"].calls == []
    preview = await service.preview("local", "naive", None)
    assert preview.status == "unsupported" and preview.reasons[0].code == "not_attached"


async def test_apply_router_failure_marks_failed_and_maps_codes(stand):
    service, router = stand["service"], stand["router"]
    await service.attach("local", "naive", **CTX)
    service.save("local", "naive", _rules(_block(["example.com"])), expected_revision=1, **CTX)
    router.fail_next = "geosite_unknown"
    with pytest.raises(RoutingError) as caught:
        await service.apply("local", "naive", expected_revision=2, **CTX)
    assert (caught.value.status, caught.value.code) == (409, "geosite_unknown")
    assert service.get("local", "naive").state == "failed" and service.get("local", "naive").last_error == "geosite_unknown"
    router.fail_next = "manual_intervention_required"
    with pytest.raises(RoutingError) as caught:
        await service.apply("local", "naive", expected_revision=2, **CTX)
    assert caught.value.status == 503


async def test_rollback_router_policy(stand):
    service, router = stand["service"], stand["router"]
    await service.attach("local", "naive", **CTX)
    service.save("local", "naive", _warp(), expected_revision=1, **CTX)
    await service.apply("local", "naive", expected_revision=2, **CTX)
    service.save("local", "naive", _rules(_block(["example.com"])), expected_revision=2, **CTX)
    await service.apply("local", "naive", expected_revision=3, **CTX)
    result = await service.rollback("local", "naive", expected_revision=3, **CTX)
    assert router.calls[-1] == ("rollback", "naive")
    assert router.documents["naive"]["default"]["action"] == "egress"
    assert result["policy"].state == "rolled_back" and result["policy"].applied_revision == 2
    assert stand["naive"].egress_document == attach_document("naive")


async def test_detach_applies_native_direct_then_router_direct(stand):
    service, naive, router = stand["service"], stand["naive"], stand["router"]
    await service.attach("local", "naive", **CTX)
    service.save("local", "naive", _warp(), expected_revision=1, **CTX)
    await service.apply("local", "naive", expected_revision=2, **CTX)
    naive.calls.clear()
    router.calls.clear()
    item = await service.detach("local", "naive", **CTX)
    assert item["backend"] == "naive_native" and item["router"]["attached"] is False
    assert item["policy"]["backend"] == "naive_native" and item["policy"]["state"] == "draft"
    assert naive.egress_document == {"schema": 1, "upstream": None, "acl": []}
    assert router.documents["naive"] == ROUTER_DIRECT_INTENT
    assert naive.calls[0][0] == "egress_apply" and router.calls[0][0] == "apply"  # native first, router second
    assert _audits(stand["database"], "routing.target.detach")[-1][1]["outcome"] == "detached"
    # The policy kept its rules; it now compiles for the native backend again.
    preview = await service.preview("local", "naive", None)
    assert preview.backend == "naive_native" and preview.status == "supported"


async def test_apply_native_policy_on_attached_service_is_422(stand):
    service = stand["service"]
    await service.attach("local", "naive", **CTX)
    service.save("local", "naive", _warp(backend="naive_native"), expected_revision=1, **CTX)
    with pytest.raises(RoutingError) as caught:
        await service.apply("local", "naive", expected_revision=2, **CTX)
    assert caught.value.status == 422 and caught.value.compiled.reasons[0].code == "backend_capability_missing"


async def test_delete_router_policy_only_when_reset(stand):
    service = stand["service"]
    await service.attach("local", "naive", **CTX)
    service.save("local", "naive", _warp(), expected_revision=1, **CTX)
    await service.apply("local", "naive", expected_revision=2, **CTX)
    with pytest.raises(RoutingError) as caught:
        service.delete("local", "naive", **CTX)
    assert caught.value.code == "policy_applied"
    service.save("local", "naive", PolicyInput(), expected_revision=2, **CTX)
    await service.apply("local", "naive", expected_revision=3, **CTX)
    service.delete("local", "naive", **CTX)
    assert (await _item(service))["policy"] is None
