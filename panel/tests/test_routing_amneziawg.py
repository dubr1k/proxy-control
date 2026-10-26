"""AmneziaWG routing (v3.0.0): the whole tunnel directly or through the AWG manager's own WARP tunnel
(`amneziawg_native`: whole_direct, whole_warp) — no rules, no lanes, no router — and the fleet's
capability gate, the overview's egress state and the UI wiring."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from panel.amneziawg import MemoryAmneziawg
from panel.database import Database
from panel.fleet_v2.generations import egress_section
from panel.fleet_v2.node_routes import CAPABILITIES
from panel.fleet_v2.protocol import EgressDocument, GenerationDocument
from panel.migrations import apply_migrations
from panel.nodes.registry import NodeRegistry
from panel.protocols import AmneziawgAdapter
from panel.protocols.base import EgressTarget
from panel.routing.compiler import compile as compile_policy
from panel.routing.compiler import direct_document
from panel.routing.document import document_digest
from panel.routing.models import BACKEND_FOR, LANE_PROTOCOLS, PolicyInput, RoutingPolicy, RoutingRule, RuleMatch, backends_for
from panel.protocols import RouterAdapter
from panel.routing.document import ROUTER_DIRECT_INTENT, attach_document, attached_to_router
from panel.routing.service import PROTOCOLS, RoutingError, RoutingService, router_target_from_identity
from panel.routing.store import RoutingStore
from panel.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio
ACTOR = {"id": 1, "username": "owner", "role": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": "req-1"}
WARP = {"schema": 1, "upstream": {"provider": "warp"}}
DIRECT = {"schema": 1, "upstream": None}
JS = Path(__file__).resolve().parent.parent / "static" / "js"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def routed(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    manager, router = MemoryAmneziawg(), MemoryXrayRouter()
    router_adapter = RouterAdapter(router)
    adapters = {"amneziawg": AmneziawgAdapter(manager, public_host="awg.example.com")}
    service = RoutingService(database, RoutingStore(database), adapters, NodeRegistry(database), router=router_adapter)
    return {"service": service, "manager": manager, "router": router}


@pytest.fixture
def stand(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    manager = MemoryAmneziawg()
    adapters = {"amneziawg": AmneziawgAdapter(manager, public_host="awg.example.com")}
    service = RoutingService(database, RoutingStore(database), adapters, NodeRegistry(database))
    return {"service": service, "manager": manager, "adapters": adapters}


def _policy(**extra):
    return RoutingPolicy(id="p", node_id="local", protocol="amneziawg", revision=1,
                         **{"backend": "amneziawg_native", **extra})


def _target(*, reachable=True, document=DIRECT):
    return EgressTarget(protocol="amneziawg", backend="amneziawg_native",
                        capabilities=frozenset({"whole_direct", "whole_warp"}),
                        providers={"warp": {"reachable": reachable}}, revision="0",
                        applied={"revision": "0", "digest": document_digest(document), "document": document})


# -- the vocabulary and the fleet -------------------------------------------------------------


def test_amneziawg_is_a_routing_service_with_its_own_backend_and_the_router():
    assert BACKEND_FOR["amneziawg"] == "amneziawg_native" and "amneziawg" in PROTOCOLS
    assert backends_for("amneziawg") == ("amneziawg_native", "xray_router") and "amneziawg" not in LANE_PROTOCOLS
    assert direct_document("amneziawg_native") == DIRECT
    # variant 2: the manager steers the tunnels into the router's tun device
    assert attach_document("amneziawg") == {"schema": 1, "upstream": {"provider": "router"}}
    assert attached_to_router("amneziawg", {"schema": 1, "upstream": {"provider": "router"}})
    assert not attached_to_router("amneziawg", WARP) and not attached_to_router("amneziawg", DIRECT)


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


def test_the_whole_tunnel_compiles_to_direct_or_warp():
    direct = compile_policy(_policy(), _target())
    assert direct.status == "supported" and direct.document == DIRECT and direct.backend == "amneziawg_native"
    warp = compile_policy(_policy(default_action="egress", default_egress="warp"), _target())
    assert warp.status == "supported" and warp.document == WARP and warp.restart_required is False


def test_on_its_own_rules_lanes_and_other_exits_are_refused_with_the_reason():
    ruled = compile_policy(_policy(rules=[RoutingRule(action="block", match=RuleMatch(domains=["example.com"]))]), _target())
    assert ruled.status == "unsupported" and ruled.reasons[0].code == "rule_kind_unsupported"
    assert "attach it to the node's Xray-router" in ruled.reasons[0].message
    lane = compile_policy(_policy(lane="grant:abc"), _target())
    assert lane.status == "unsupported" and lane.reasons[0].code == "lanes_unsupported"
    router = compile_policy(_policy(backend="xray_router"), _target())
    assert router.status == "unsupported" and router.reasons[0].code == "router_unavailable"
    chain = compile_policy(_policy(default_action="egress", default_egress="node:" + "a" * 32), _target())
    assert chain.status == "unsupported"


def test_an_unreachable_warp_stays_fail_closed_or_falls_back_when_approved():
    closed = compile_policy(_policy(default_action="egress", default_egress="warp"), _target(reachable=False))
    assert closed.status == "unsupported" and closed.reasons[0].code == "provider_unreachable"
    approved = compile_policy(_policy(default_action="egress", default_egress="warp", fallback="approved_direct"),
                              _target(reachable=False))
    assert approved.status == "supported" and approved.document == DIRECT and "provider_unreachable" in approved.warnings
    # not registered yet: the manager registers on the first apply, so «unknown» is not a refusal
    assert compile_policy(_policy(default_action="egress", default_egress="warp"), _target(reachable=None)).status == "supported"


# -- the adapter and the service --------------------------------------------------------------














# -- the screens ---------------------------------------------------------------------------------


def test_the_amneziawg_screen_shows_the_exit_and_links_to_routing():
    source = (JS / "amneziawg.js").read_text(encoding="utf-8")
    assert "function egressCard(context, egress)" in source and "egressCard(context, data.egress)" in source
    assert 'data-awg-action="route"' in source and 'context.state.routingProtocol = "amneziawg";' in source
    assert "Через WARP" in source and "Нет связи с WARP" in source


def test_the_routing_screen_offers_only_the_whole_tunnel_for_amneziawg():
    source = (JS / "routing.js").read_text(encoding="utf-8")
    assert 'amneziawg: "AmneziaWG"' in source and 'amneziawg_native: "WARP-туннель AmneziaWG"' in source
    assert 'const WHOLE_ONLY = new Set(["amneziawg"]);' in source
    assert "if (wholeOnly(target)) return options;" in source
    assert "Правил у AmneziaWG нет" in source and 'target.protocol === "amneziawg"' in source
    assert 'return WHOLE_ONLY.has(target?.protocol) && target?.backend !== "xray_router";' in source
    assert "router_lacks_amneziawg" in source and "AmneziaWG идёт через Xray-router" in source


# -- variant 2: through the Xray-router ----------------------------------------------------------









