"""TrustTunnel routing (v1.6): a service-level policy on the node's Xray-router through a no-auth
loopback SOCKS ingress, the native backend that can only be direct, attach/detach through the
manager's `{mode, address}` document, no client lanes, and the fleet's capability gate."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from panel.database import Database
from panel.fleet_v2.generations import egress_section
from panel.fleet_v2.node_routes import CAPABILITIES
from panel.fleet_v2.protocol import EgressDocument, GenerationDocument
from panel.migrations import apply_migrations
from panel.nodes.registry import NodeRegistry
from panel.protocols import RouterAdapter, TrusttunnelAdapter
from panel.protocols.base import EgressTarget
from panel.routing.compiler import compile as compile_policy
from panel.routing.compiler import direct_document, explain
from panel.routing.document import ATTACH_DOCUMENTS, ROUTER_DIRECT_INTENT, attach_document, attached_to_router, document_digest
from panel.routing.lanes import LaneError, LaneService
from panel.routing.models import BACKEND_FOR, LANE_PROTOCOLS, PolicyInput, RoutingPolicy, RoutingRule, RuleMatch
from panel.routing.presets import rule_for
from panel.routing.service import PROTOCOLS, RoutingError, RoutingService, router_target_from_identity
from panel.routing.store import RoutingStore
from panel.trusttunnel import MemoryTrusttunnel
from panel.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio
ACTOR = {"id": 1, "username": "owner", "role": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": "req-1"}
ATTACHED = {"mode": "socks5", "address": "127.0.0.1:45104"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def stand(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    manager, router = MemoryTrusttunnel(), MemoryXrayRouter()
    router_adapter = RouterAdapter(router)
    adapters = {"trusttunnel": TrusttunnelAdapter(manager, public_host="gate.example.com", router=router_adapter)}
    service = RoutingService(database, RoutingStore(database), adapters, NodeRegistry(database), router=router_adapter)
    return {"database": database, "service": service, "manager": manager, "router": router, "adapters": adapters}


async def _item(service):
    return next(item for item in await service.targets() if item["protocol"] == "trusttunnel")


def _torrent():
    return PolicyInput(rules=[RoutingRule.model_validate(rule_for("torrent"))])


def _block(domain):
    return PolicyInput(rules=[RoutingRule(action="block", match=RuleMatch(domains=[domain]))])


# -- the vocabulary -----------------------------------------------------------------------------


def test_trusttunnel_is_a_routing_service_without_lanes():
    assert BACKEND_FOR["trusttunnel"] == "trusttunnel_native" and "trusttunnel" in PROTOCOLS
    assert "trusttunnel" not in LANE_PROTOCOLS and BACKEND_FOR["mtproxy"] == "mtproxy_native"
    assert direct_document("trusttunnel_native") == {"mode": "direct"}


def test_the_attach_document_is_the_managers_own_socks5_upstream():
    assert attach_document("trusttunnel") == ATTACHED and ATTACH_DOCUMENTS["trusttunnel"] == ATTACHED
    assert attached_to_router("trusttunnel", ATTACHED)
    assert not attached_to_router("trusttunnel", {"mode": "direct"})
    assert not attached_to_router("trusttunnel", {"mode": "socks5", "address": "127.0.0.1:41001"})
    assert not attached_to_router("trusttunnel", None)


def test_the_node_declares_the_capability_and_a_central_filters_by_it():
    assert "egress.trusttunnel.v1" in CAPABILITIES
    entry = EgressDocument(backend="trusttunnel_native", policy_id="p", policy_revision=1, document={"mode": "direct"},
                           digest=document_digest({"mode": "direct"}))
    generation = GenerationDocument(node_guid="n", master_guid="m", generation=1, previous_generation=0, created_at=1,
                                    created_by="t", resources=[], egress={"trusttunnel": entry})
    assert generation.wire()["egress"]["trusttunnel"]["backend"] == "trusttunnel_native"


def test_a_node_without_the_capability_never_receives_a_trusttunnel_section(monkeypatch):
    from panel.fleet_v2 import generations

    document = {"mode": "direct"}
    desired = {"trusttunnel": {"backend": "trusttunnel_native", "policy_id": "p", "policy_revision": 1,
                               "document": document, "digest": document_digest(document)}}
    routing = SimpleNamespace(desired_for_node=lambda db, node_id: desired)
    base = ["egress.v1", "egress.router.v1", "egress.lanes.v1", "egress.mtproxy.v1"]
    monkeypatch.setattr(generations, "node_capabilities", lambda db, node_id: base)
    assert egress_section(None, routing, "n1") is None
    monkeypatch.setattr(generations, "node_capabilities", lambda db, node_id: [*base, "egress.trusttunnel.v1"])
    assert set(egress_section(None, routing, "n1")) == {"trusttunnel"}


def test_a_linked_nodes_router_without_the_service_is_named():
    identity = {"available": True, "capabilities": ["whole_direct"], "services": {"naive": {}, "mieru": {}, "mtproxy": {}}}
    assert router_target_from_identity("trusttunnel", identity).reason == "router_lacks_trusttunnel"
    identity["services"]["trusttunnel"] = {"revision": "r", "applied_digest": "d"}
    target = router_target_from_identity("trusttunnel", identity)
    assert target.available and target.revision == "r"


# -- the compiler -------------------------------------------------------------------------------


def _policy(**extra):
    return RoutingPolicy(id="p", node_id="local", protocol="trusttunnel", revision=1, **{"backend": "trusttunnel_native", **extra})


def _target(*, attached):
    return EgressTarget(protocol="trusttunnel", backend="trusttunnel_native", capabilities=frozenset({"whole_direct"}),
                        providers={"router": {"reachable": True}}, revision="r1",
                        applied={"revision": "r1", "digest": document_digest(ATTACHED if attached else {"mode": "direct"}),
                                 "document": ATTACHED if attached else {"mode": "direct"}},
                        mode="proxy" if attached else "direct", router_attached=attached)


def test_the_native_backend_compiles_direct_only_and_asks_for_the_router_otherwise():
    direct = compile_policy(_policy(), _target(attached=False))
    assert direct.status == "supported" and direct.document == {"mode": "direct"} and direct.backend == "trusttunnel_native"
    blocked = compile_policy(_policy(rules=[RoutingRule(action="block", match=RuleMatch(domains=["example.com"]))]),
                             _target(attached=False))
    assert blocked.status == "unsupported" and blocked.reasons[0].code == "not_attached"
    warp = compile_policy(_policy(default_action="egress", default_egress="warp"), _target(attached=False))
    assert warp.status == "unsupported" and warp.reasons[0].code == "not_attached"


def test_on_the_router_a_service_policy_compiles_to_the_service_intent():
    router = router_target_from_identity("trusttunnel", {
        "available": True, "capabilities": ["whole_direct", "whole_warp", "block_domain", "selective_domain", "block_geosite",
                                            "block_protocol", "selective_protocol"],
        "providers": {"warp": {"reachable": True}}, "services": {"trusttunnel": {"revision": "r", "applied_digest": None}}})
    policy = _policy(backend="xray_router", rules=[RoutingRule.model_validate(rule_for("torrent")),
                                                   RoutingRule(action="block", match=RuleMatch(domains=["example.com"]))])
    compiled = compile_policy(policy, _target(attached=True), router=router)
    assert compiled.status == "supported" and compiled.backend == "xray_router"
    assert compiled.document["schema"] == 1 and len(compiled.document["rules"]) == 2
    detached = compile_policy(policy, _target(attached=False), router=router)
    assert detached.status == "unsupported" and detached.reasons[0].code == "not_attached"


def test_a_client_lane_is_refused_for_trusttunnel():
    router = router_target_from_identity("trusttunnel", {
        "available": True, "capabilities": ["whole_direct"], "services": {"trusttunnel": {"revision": "r", "applied_digest": None}}})
    lane = _policy(backend="xray_router", lane="grant:abc")
    compiled = compile_policy(_policy(backend="xray_router"), _target(attached=True), router=router, lanes=[lane])
    assert compiled.status == "unsupported" and compiled.reasons[0].code == "lanes_unsupported"
    assert "TrustTunnel" in compiled.reasons[0].message


def test_explain_works_like_any_service():
    result = explain(_policy(rules=[RoutingRule(action="block", match=RuleMatch(domains=["example.com"]))]), "a.example.com", 443)
    assert result["action"] == "block" and result["lane"] == "svc"
    assert explain(_policy(), "a.example.com", 443)["action"] == "direct"


# -- the adapter --------------------------------------------------------------------------------








# -- the service: attach, apply, preview, explain, history, rollback, detach -----------------------




















# -- no lanes -----------------------------------------------------------------------------------


async def test_a_policy_for_a_client_lane_of_trusttunnel_is_refused_with_a_clear_code(stand):
    with pytest.raises(RoutingError) as caught:
        stand["service"].save("local", "trusttunnel", PolicyInput(), expected_revision=None, lane="grant:abc", **CTX)
    assert caught.value.status == 422 and caught.value.code == "lanes_unsupported"
    assert "TrustTunnel" in str(caught.value)


async def test_enabling_a_lane_for_a_trusttunnel_grant_is_refused(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    clients = SimpleNamespace(store=SimpleNamespace(grant=lambda db, grant_id: SimpleNamespace(
        protocol="trusttunnel", node_id="local", id=grant_id)))
    lanes = LaneService(database, RoutingStore(database), clients, {}, None)
    with pytest.raises(LaneError) as caught:
        await lanes.enable("g1", **{k: v for k, v in CTX.items() if k != "request_id"})
    assert caught.value.status == 422 and caught.value.code == "lanes_unsupported"
