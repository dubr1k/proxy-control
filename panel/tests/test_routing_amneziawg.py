"""AmneziaWG routing (v3.0.0): the whole tunnel directly or through the AWG manager's own WARP tunnel
(`amneziawg_native`: whole_direct, whole_warp) — no rules, no lanes, no router — and the fleet's
capability gate, the overview's egress state and the UI wiring."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest



from panel.fleet_v2.generations import egress_section
from panel.fleet_v2.node_routes import CAPABILITIES
from panel.fleet_v2.protocol import EgressDocument, GenerationDocument






from panel.routing.document import document_digest



from panel.routing.service import router_target_from_identity



pytestmark = pytest.mark.anyio


WARP = {"schema": 1, "upstream": {"provider": "warp"}}

JS = Path(__file__).resolve().parent.parent / "static" / "js"

















# -- the vocabulary and the fleet -------------------------------------------------------------





def test_a_linked_nodes_router_without_the_service_is_named():
    identity = {"available": True, "capabilities": ["whole_direct"], "services": {"naive": {}, "mieru": {}}}
    assert router_target_from_identity("amneziawg", identity).reason == "router_lacks_amneziawg"
    identity["services"]["amneziawg"] = {"revision": "r", "applied_digest": "d"}
    assert router_target_from_identity("amneziawg", identity).available


def test_the_node_declares_the_capability_and_a_central_filters_by_it(monkeypatch):
    from panel.fleet_v2 import generations

    assert "egress.amneziawg.v1" in CAPABILITIES
    entry = EgressDocument(backend="amneziawg_native", policy_id="p", policy_revision=1, document=WARP,
                           digest=document_digest(WARP))
    generation = GenerationDocument(node_guid="n", master_guid="m", generation=1, previous_generation=0, created_at=1,
                                    created_by="t", resources=[], egress={"amneziawg": entry})
    assert generation.wire()["egress"]["amneziawg"]["backend"] == "amneziawg_native"
    desired = {"amneziawg": {"backend": "amneziawg_native", "policy_id": "p", "policy_revision": 1, "document": WARP,
                             "digest": document_digest(WARP)}}
    routing = SimpleNamespace(desired_for_node=lambda db, node_id: desired)
    base = ["egress.v1", "egress.router.v1", "egress.lanes.v1", "egress.mtproxy.v1", "egress.trusttunnel.v1"]
    monkeypatch.setattr(generations, "node_capabilities", lambda db, node_id: base)
    assert egress_section(None, routing, "n1") is None
    monkeypatch.setattr(generations, "node_capabilities", lambda db, node_id: [*base, "egress.amneziawg.v1"])
    assert set(egress_section(None, routing, "n1")) == {"amneziawg"}


# -- the compiler -------------------------------------------------------------------------------











# -- the adapter and the service --------------------------------------------------------------














# -- the screens ---------------------------------------------------------------------------------








# -- variant 2: through the Xray-router ----------------------------------------------------------









