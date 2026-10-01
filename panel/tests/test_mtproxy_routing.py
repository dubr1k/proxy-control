"""MTProxy routing (v1.1): Telemt's upstream handed to the node's Xray-router through the
`xray-router-ingress` bridge, policies on the router like any service, the native backend
that can only be direct, the journal for rollback, and what a node before v1.1 is told."""
from __future__ import annotations

import json

import pytest

from panel.database import Database
from panel.migrations import apply_migrations
from panel.nodes.registry import NodeRegistry
from panel.protocols import RouterAdapter, TelemtAdapter
from panel.protocols.base import AdapterError
from panel.routing.document import MTPROXY_BRIDGE_ADDRESS, TELEMT_DIRECT_DOCUMENT, attach_document, document_digest
from panel.routing.models import PolicyInput, RoutingRule, RuleMatch
from panel.routing.service import RoutingError, RoutingService, router_target_from_identity
from panel.routing.store import RoutingStore
from panel.telemt import MemoryTelemt
from panel.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio
ACTOR = {"id": 1, "username": "owner", "role": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": "req-1"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


class Bridge:
    def __init__(self):
        self.up, self.calls = True, []

    async def __call__(self, ingress):
        self.calls.append(ingress["address"])
        return self.up


def _adapter(telemt, router=None, bridge=None, journal=None):
    adapter = TelemtAdapter(telemt, public_host="proxy.example.com", router=router, journal_path=journal,
                            bridge_probe=bridge or Bridge())
    adapter.reload_poll = 0
    return adapter


@pytest.fixture
def stand(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    telemt, router, bridge = MemoryTelemt(public_host="proxy.example.com"), MemoryXrayRouter(), Bridge()
    router_adapter = RouterAdapter(router)
    adapter = _adapter(telemt, router_adapter, bridge, tmp_path / "telemt-egress.json")
    service = RoutingService(database, RoutingStore(database), {"mtproxy": adapter}, NodeRegistry(database),
                             router=router_adapter)
    return {"database": database, "service": service, "telemt": telemt, "router": router, "bridge": bridge,
            "adapter": adapter, "journal": tmp_path / "telemt-egress.json"}


async def _item(service):
    return next(item for item in await service.targets() if item["protocol"] == "mtproxy")


# -- the adapter --------------------------------------------------------------------------------


async def test_a_fresh_telemt_is_direct_and_offers_the_router():
    telemt, bridge = MemoryTelemt(), Bridge()
    target = await _adapter(telemt, RouterAdapter(MemoryXrayRouter()), bridge).egress_target()
    assert target.backend == "mtproxy_native" and target.mode == "direct" and not target.router_attached
    assert target.applied["document"] == TELEMT_DIRECT_DOCUMENT and target.capabilities == {"whole_direct"}
    assert target.providers == {"router": {"reachable": True}} and bridge.calls == [MTPROXY_BRIDGE_ADDRESS]


async def test_no_router_means_no_router_provider_and_an_old_router_too():
    assert (await _adapter(MemoryTelemt()).egress_target()).providers == {}
    old = RouterAdapter(MemoryXrayRouter(mtproxy=False))
    assert (await _adapter(MemoryTelemt(), old).egress_target()).providers == {}
    assert (await old.target("mtproxy")).reason == "router_lacks_mtproxy"


async def test_a_telemt_without_the_config_api_is_named():
    telemt = MemoryTelemt()
    telemt.config_api = False
    with pytest.raises(AdapterError) as caught:
        await _adapter(telemt).egress_target()
    assert caught.value.code == "telemt_api_unsupported"


async def test_the_revision_ignores_users_and_never_carries_the_password():
    telemt = MemoryTelemt()
    adapter = _adapter(telemt, RouterAdapter(MemoryXrayRouter()))
    before = (await adapter.egress_target()).revision
    await telemt.create_user("alice")
    telemt.config_version += 1  # a user change moves the config's revision, not the upstreams'
    assert (await adapter.egress_target()).revision == before
    target = await adapter.egress_target()
    await adapter.apply_egress(attach_document("mtproxy"), expected_revision=target.revision, operation_id="op-1")
    attached = await adapter.egress_target()
    assert attached.router_attached and attached.mode == "proxy"
    assert "m" * 43 not in attached.revision and telemt.upstreams[0]["password"] == "m" * 43


async def test_attach_patches_reloads_waits_and_reads_back():
    telemt = MemoryTelemt()
    adapter = _adapter(telemt, RouterAdapter(MemoryXrayRouter()))
    target = await adapter.egress_target()
    applied = await adapter.apply_egress(attach_document("mtproxy"), expected_revision=target.revision, operation_id="op-1")
    assert telemt.upstreams == [{"type": "socks5", "address": MTPROXY_BRIDGE_ADDRESS, "username": "telemt",
                                 "password": "m" * 43, "weight": 1, "enabled": True}]
    assert telemt.runtime_upstreams == telemt.upstreams
    assert [call[0] for call in telemt.config_calls] == ["patch", "reload"]
    assert applied.digest == document_digest(attach_document("mtproxy"))
    replay = await adapter.apply_egress(attach_document("mtproxy"), expected_revision=target.revision, operation_id="op-1")
    assert replay.replayed and [call[0] for call in telemt.config_calls] == ["patch", "reload"]


async def test_detach_puts_back_exactly_the_direct_upstream_telemt_had():
    telemt = MemoryTelemt()
    telemt.upstreams = [{"type": "direct", "ipv4": True, "ipv6": True, "weight": 3}]
    adapter = _adapter(telemt, RouterAdapter(MemoryXrayRouter()))
    target = await adapter.egress_target()
    await adapter.apply_egress(attach_document("mtproxy"), expected_revision=target.revision, operation_id="op-1")
    target = await adapter.egress_target()
    await adapter.apply_egress(TELEMT_DIRECT_DOCUMENT, expected_revision=target.revision, operation_id="op-2")
    assert telemt.upstreams == [{"type": "direct", "ipv4": True, "ipv6": True, "weight": 3}]


async def test_a_bridge_that_does_not_answer_leaves_telemt_untouched():
    telemt, bridge = MemoryTelemt(), Bridge()
    bridge.up = False
    adapter = _adapter(telemt, RouterAdapter(MemoryXrayRouter()), bridge)
    target = await adapter.egress_target()
    with pytest.raises(AdapterError) as caught:
        await adapter.apply_egress(attach_document("mtproxy"), expected_revision=target.revision, operation_id="op-1")
    assert caught.value.code == "ingress_unreachable" and telemt.config_calls == []


@pytest.mark.parametrize("outcome", ["failed", "rolled_back", "stuck"])
async def test_a_reload_that_does_not_activate_puts_the_file_back(outcome):
    telemt = MemoryTelemt()
    telemt.reload_outcome = outcome
    adapter = _adapter(telemt, RouterAdapter(MemoryXrayRouter()))
    adapter.reload_timeout = 0
    target = await adapter.egress_target()
    with pytest.raises(AdapterError) as caught:
        await adapter.apply_egress(attach_document("mtproxy"), expected_revision=target.revision, operation_id="op-1")
    assert caught.value.code == "egress_reload_failed"
    assert telemt.upstreams == [{"type": "direct", "ipv4": True, "ipv6": False}]


async def test_a_lost_patch_reply_is_decided_by_reading_back():
    telemt = MemoryTelemt()
    telemt.faults["patch"] = "lose_response"
    adapter = _adapter(telemt, RouterAdapter(MemoryXrayRouter()))
    target = await adapter.egress_target()
    applied = await adapter.apply_egress(attach_document("mtproxy"), expected_revision=target.revision, operation_id="op-1")
    assert applied.digest == document_digest(attach_document("mtproxy")) and telemt.runtime_upstreams == telemt.upstreams


async def test_hand_written_upstreams_are_not_touched():
    telemt = MemoryTelemt()
    telemt.upstreams = [{"type": "socks5", "address": "203.0.113.5:1080", "username": "me", "password": "secret-value"}]
    adapter = _adapter(telemt, RouterAdapter(MemoryXrayRouter()))
    target = await adapter.egress_target()
    assert target.mode == "custom" and target.applied is None and not target.router_attached
    with pytest.raises(AdapterError) as caught:
        await adapter.apply_egress(attach_document("mtproxy"), expected_revision=target.revision, operation_id="op-1")
    assert caught.value.code == "manual_intervention_required" and telemt.config_calls == []


async def test_a_stale_revision_is_a_conflict_and_an_unknown_document_is_refused():
    adapter = _adapter(MemoryTelemt(), RouterAdapter(MemoryXrayRouter()))
    with pytest.raises(AdapterError) as caught:
        await adapter.apply_egress(attach_document("mtproxy"), expected_revision="0" * 64, operation_id="op-1")
    assert caught.value.code == "egress_conflict"
    with pytest.raises(AdapterError) as caught:
        await adapter.apply_egress({"schema": 1, "upstream": {"provider": "warp"}}, expected_revision="x", operation_id="op-2")
    assert caught.value.code == "egress_invalid"


async def test_rollback_returns_to_the_previous_document_once(tmp_path):
    telemt = MemoryTelemt()
    adapter = _adapter(telemt, RouterAdapter(MemoryXrayRouter()), journal=tmp_path / "journal.json")
    with pytest.raises(AdapterError) as caught:
        await adapter.rollback_egress(expected_revision=(await adapter.egress_target()).revision)
    assert caught.value.code == "egress_no_previous"
    target = await adapter.egress_target()
    await adapter.apply_egress(TELEMT_DIRECT_DOCUMENT, expected_revision=target.revision, operation_id="op-0")
    target = await adapter.egress_target()
    await adapter.apply_egress(attach_document("mtproxy"), expected_revision=target.revision, operation_id="op-1")
    journal = json.loads((tmp_path / "journal.json").read_text())
    assert "m" * 43 not in json.dumps(journal) and journal["current"]["document"] == attach_document("mtproxy")
    target = await adapter.egress_target()
    applied = await adapter.rollback_egress(expected_revision=target.revision)
    assert applied.digest == document_digest(TELEMT_DIRECT_DOCUMENT) and telemt.upstreams[0]["type"] == "direct"
    with pytest.raises(AdapterError):
        await adapter.rollback_egress(expected_revision=(await adapter.egress_target()).revision)


# -- the routing service ------------------------------------------------------------------------


async def test_the_target_is_routable_now(stand):
    item = await _item(stand["service"])
    assert item["reason"] is None and item["backend"] == "mtproxy_native"
    assert item["router"]["available"] and not item["router"]["attached"]


async def test_a_native_policy_other_than_direct_must_attach_first(stand):
    service = stand["service"]
    compiled = await service.preview("local", "mtproxy", PolicyInput(default_action="egress", default_egress="warp"))
    assert compiled.status == "unsupported" and [reason.code for reason in compiled.reasons] == ["not_attached"]
    compiled = await service.preview("local", "mtproxy", PolicyInput())
    assert compiled.status == "supported" and compiled.document == TELEMT_DIRECT_DOCUMENT


async def test_attach_then_warp_then_detach(stand):
    service, telemt, router = stand["service"], stand["telemt"], stand["router"]
    await service.attach("local", "mtproxy", **CTX)
    item = await _item(service)
    assert item["backend"] == "xray_router" and item["router"]["attached"]
    assert telemt.upstreams[0]["address"] == MTPROXY_BRIDGE_ADDRESS
    policy = service.get("local", "mtproxy")
    saved = service.save("local", "mtproxy", PolicyInput(default_action="egress", default_egress="warp"),
                         expected_revision=policy.revision, **CTX)
    result = await service.apply("local", "mtproxy", expected_revision=saved.revision, **CTX)
    assert result["policy"].state == "applied"
    assert router.documents["mtproxy"]["default"] == {"action": "egress", "egress": "warp"}
    reset = service.save("local", "mtproxy", PolicyInput(backend="xray_router"), expected_revision=result["policy"].revision, **CTX)
    await service.apply("local", "mtproxy", expected_revision=reset.revision, **CTX)
    await service.detach("local", "mtproxy", **CTX)
    assert telemt.upstreams == [{"type": "direct", "ipv4": True, "ipv6": False}]
    assert (await _item(service))["backend"] == "mtproxy_native"


async def test_domain_geosite_and_protocol_rules_are_refused_on_mtproxy(stand):
    service = stand["service"]
    await service.attach("local", "mtproxy", **CTX)
    draft = PolicyInput(backend="xray_router", rules=[
        RoutingRule(action="block", match=RuleMatch(domains=["example.com"])),
        RoutingRule(action="block", match=RuleMatch(geosites=["category-ads-all"])),
        RoutingRule(action="block", match=RuleMatch(protocols=["bittorrent"])),
        RoutingRule(action="egress", egress="warp", match=RuleMatch(cidrs=["149.154.160.0/20"])),
        RoutingRule(action="block", match=RuleMatch(geoips=["cn"], ports=[443])),
    ])
    compiled = await service.preview("local", "mtproxy", draft)
    assert compiled.status == "unsupported"
    assert [reason.code for reason in compiled.reasons] == ["rule_kind_unsupported"] * 3
    supported = await service.preview("local", "mtproxy", PolicyInput(backend="xray_router", rules=draft.rules[3:]))
    assert supported.status == "supported"


async def test_an_old_router_is_named_and_attach_is_refused(stand):
    stand["router"].mtproxy = False
    item = await _item(stand["service"])
    assert item["router"]["available"] is False and item["router"]["reason"] == "router_lacks_mtproxy"
    with pytest.raises(RoutingError) as caught:
        await stand["service"].attach("local", "mtproxy", **CTX)
    assert caught.value.code == "router_lacks_mtproxy"


async def test_a_bridge_down_refuses_attach(stand):
    stand["bridge"].up = False
    with pytest.raises(RoutingError) as caught:
        await stand["service"].attach("local", "mtproxy", **CTX)
    assert caught.value.code == "router_unreachable"
    assert stand["telemt"].config_calls == []


def test_a_linked_router_without_mtproxy_is_named():
    router = {"available": True, "services": {"naive": {"revision": "r"}, "mieru": {"revision": "r"}}, "capabilities": []}
    assert router_target_from_identity("mtproxy", router).reason == "router_lacks_mtproxy"
    assert router_target_from_identity("naive", router).available


def test_migration_21_widens_the_checks(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    with database.transaction() as db:
        db.execute("INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('mtproxy',1,'converged',0)")
        sql = db.execute("SELECT sql FROM sqlite_master WHERE name='routing_policies'").fetchone()["sql"]
    assert "'mtproxy'" in sql and "'mtproxy_native'" in sql
