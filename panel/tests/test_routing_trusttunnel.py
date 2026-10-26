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



from panel.routing.document import document_digest
from panel.routing.lanes import LaneError, LaneService
from panel.routing.models import PolicyInput

from panel.routing.service import RoutingError, RoutingService, router_target_from_identity
from panel.routing.store import RoutingStore
from panel.tests.harness.memories.trusttunnel import MemoryTrusttunnel
from panel.tests.harness.memories.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio
ACTOR = {"id": 1, "username": "owner", "role": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": "req-1"}






@pytest.fixture
def stand(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    manager, router = MemoryTrusttunnel(), MemoryXrayRouter()
    router_adapter = RouterAdapter(router)
    adapters = {"trusttunnel": TrusttunnelAdapter(manager, public_host="gate.example.com", router=router_adapter)}
    service = RoutingService(database, RoutingStore(database), adapters, NodeRegistry(database), router=router_adapter)
    return {"database": database, "service": service, "manager": manager, "router": router, "adapters": adapters}











# -- the vocabulary -----------------------------------------------------------------------------








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
