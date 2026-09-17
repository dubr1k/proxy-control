"""Policy → the router's intent with lanes and chains (v0.7): one intent per service folding
every lane, chains resolved to relay hops, each refusal named — and `explain`, the path a
destination takes through a lane's rules."""
from __future__ import annotations

from panel.routing.compiler import ChainHop, compile, explain
from panel.routing.models import COMPILER_VERSION, Reason, RoutingPolicy
from panel.tests.test_xray_routing_compiler import _policy, _router, _rule, _target

GUID_B, GUID_C = "b" * 32, "c" * 32
HOP_B = ChainHop(guid=GUID_B, address="panel.node-b.example.org", port=45443, server_name="panel.node-b.example.org",
                 public_key="SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s", short_id="0123abcd",
                 uuid_direct="3f0d9c6e-1b4e-4a6b-9a1e-2c8f5d7e9a10", uuid_warp="9a1e2c8f-5d7e-4a10-8b6e-3f0d9c6e1b4e")
HOP_C = ChainHop(guid=GUID_C, address="203.0.113.7", port=45443, server_name="panel.node-c.example.org",
                 public_key="SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s", short_id="89abcdef",
                 uuid_direct="1b4e4a6b-9a1e-4c8f-8d7e-9a103f0d9c6e", uuid_warp=None)


class Resolver:
    """What the service would answer: hops per node guid, or a reason."""

    def __init__(self, hops=None, reasons=None):
        self.hops = hops or {GUID_B: HOP_B, GUID_C: HOP_C}
        self.reasons = reasons or {}

    def resolve(self, guid: str) -> ChainHop | Reason:
        if guid in self.reasons:
            return self.reasons[guid]
        if guid not in self.hops:
            return Reason(code="node_unknown", message=f"no node {guid}")
        return self.hops[guid]


def _lane(lane: str, **kwargs) -> RoutingPolicy:
    policy = _policy(**kwargs)
    return policy.model_copy(update={"id": f"p-{lane}", "lane": lane})


def test_a_service_without_lanes_or_node_exits_still_compiles_to_schema_1():
    compiled = compile(_policy(default_action="egress", rules=[_rule("block", domains=["a.example"])]), _target(),
                       router=_router(), lanes=[], chains=Resolver())
    assert compiled.status == "supported" and compiled.document["schema"] == 1
    assert compiled.compiler_version == COMPILER_VERSION


def test_lanes_fold_into_one_schema_2_intent_with_the_service_lane_and_chains():
    service = _policy(default_action="direct", rules=[_rule("block", domains=["ads.example"])])
    lane = _lane("grant:7f3a", default_action="egress",
                 rules=[_rule("egress", geosites=["category-ads-all"], egress=f"node:{GUID_B}:warp"),
                        _rule("direct", geoips=["ru"]),
                        _rule("egress", domains=["*.example.net"], egress=f"node:{GUID_B},{GUID_C}")])
    lane = lane.model_copy(update={"default_egress": "warp"})
    compiled = compile(service, _target(), router=_router(), lanes=[lane], chains=Resolver())
    assert compiled.status == "supported", compiled.reasons
    intent = compiled.document
    assert intent["schema"] == 2 and list(intent["lanes"]) == ["svc:naive", "grant:7f3a"]
    assert intent["lanes"]["svc:naive"]["default"] == {"action": "direct", "egress": None}
    assert intent["lanes"]["svc:naive"]["rules"][0]["action"] == "block"
    grant = intent["lanes"]["grant:7f3a"]
    assert grant["default"] == {"action": "egress", "egress": "warp"}
    assert [rule["egress"] for rule in grant["rules"]] == ["chain:c1", None, "chain:c2"]
    assert intent["chains"]["c1"] == {"hops": [{"guid": GUID_B, "address": "panel.node-b.example.org", "port": 45443,
                                                "server_name": "panel.node-b.example.org", "public_key": HOP_B.public_key,
                                                "short_id": "0123abcd", "uuid": HOP_B.uuid_warp}], "exit": "warp"}
    assert [hop["guid"] for hop in intent["chains"]["c2"]["hops"]] == [GUID_B, GUID_C] and intent["chains"]["c2"]["exit"] == "direct"
    # the middle hop of a chain is dialled through, so it carries its *direct* account
    assert intent["chains"]["c2"]["hops"][0]["uuid"] == HOP_B.uuid_direct and intent["chains"]["c2"]["hops"][1]["uuid"] == HOP_C.uuid_direct
    assert compiled.attach is not None and compiled.digest


def test_compiling_a_lane_policy_folds_the_service_and_the_other_lanes():
    service = _policy(default_action="direct")
    mine = _lane("grant:7f3a", default_action="egress", rules=[]).model_copy(update={"default_egress": f"node:{GUID_B}"})
    other = _lane("grant:0000", default_action="direct", rules=[_rule("block", ports=[25])])
    compiled = compile(mine, _target(), router=_router(), lanes=[service, other], chains=Resolver())
    assert compiled.status == "supported"
    assert list(compiled.document["lanes"]) == ["svc:naive", "grant:7f3a", "grant:0000"]
    assert compiled.document["lanes"]["grant:7f3a"]["default"]["egress"] == "chain:c1"


def test_node_exit_refusals_are_named():
    service = _policy(default_action="egress").model_copy(update={"default_egress": f"node:{GUID_B}"})
    pending = Resolver(reasons={GUID_B: Reason(code="relay_credential_pending", message="the node has not confirmed the relay account")})
    compiled = compile(service, _target(), router=_router(), lanes=[], chains=pending)
    assert compiled.status == "unsupported" and [r.code for r in compiled.reasons] == ["relay_credential_pending"]
    for code in ("node_lacks_relay", "relay_disabled", "node_unknown"):
        resolver = Resolver(reasons={GUID_B: Reason(code=code, message=code)})
        compiled = compile(service, _target(), router=_router(), lanes=[], chains=resolver)
        assert [r.code for r in compiled.reasons] == [code]
    # a rule's refusal names the rule
    ruled = _policy(rules=[_rule("egress", domains=["a.example"], egress=f"node:{GUID_C}", rule_id="11111111-0000-4000-8000-111111111111")])
    compiled = compile(ruled, _target(), router=_router(), lanes=[], chains=Resolver(reasons={GUID_C: Reason(code="relay_disabled", message="off")}))
    assert compiled.reasons[0].rule_id == "11111111-0000-4000-8000-111111111111"
    # a chain that exits through a hop's warp needs that hop's warp account
    no_warp = compile(_policy(default_action="egress").model_copy(update={"default_egress": f"node:{GUID_C}:warp"}),
                      _target(), router=_router(), lanes=[], chains=Resolver())
    assert [r.code for r in no_warp.reasons] == ["relay_no_warp"]
    # a chain through this very node is a loop
    loop = compile(_policy(default_action="egress").model_copy(update={"default_egress": f"node:{GUID_B},local"}),
                   _target(), router=_router(), lanes=[], chains=Resolver())
    assert [r.code for r in loop.reasons] == ["chain_loop"]


def test_lanes_and_node_exits_need_the_router_and_the_attachment():
    lane = _lane("grant:7f3a", default_action="direct")
    unattached = compile(lane, _target(attached=False), router=_router(), lanes=[_policy()], chains=Resolver())
    assert [r.code for r in unattached.reasons] == ["lane_not_attached"]
    no_router = compile(lane, _target(attached=False), router=None, lanes=[_policy()], chains=Resolver())
    assert [r.code for r in no_router.reasons] == ["lane_requires_router"]
    # a node exit on a native backend is refused as the kind of rule only the router runs
    native = _policy(backend="naive_native", default_action="egress").model_copy(update={"default_egress": f"node:{GUID_B}"})
    compiled = compile(native, _target(attached=False), router=None, lanes=[], chains=Resolver())
    assert "rule_kind_unsupported" in [r.code for r in compiled.reasons]
    # a lane policy on a native backend never compiles
    native_lane = lane.model_copy(update={"backend": "naive_native"})
    compiled = compile(native_lane, _target(attached=False), router=None, lanes=[], chains=Resolver())
    assert [r.code for r in compiled.reasons] == ["lane_requires_router"]


def test_this_nodes_warp_is_only_needed_by_lanes_that_use_it():
    service = _policy(default_action="egress").model_copy(update={"default_egress": f"node:{GUID_B}:warp"})
    compiled = compile(service, _target(), router=_router(providers={}), lanes=[], chains=Resolver())
    assert compiled.status == "supported"  # the hop's warp, not ours
    lane = _lane("grant:1", default_action="egress").model_copy(update={"default_egress": "warp"})
    compiled = compile(service, _target(), router=_router(providers={}), lanes=[lane], chains=Resolver())
    assert [r.code for r in compiled.reasons] == ["provider_unavailable"]
    # the lane's own fallback turns an unreachable warp into direct for that lane only
    lane = lane.model_copy(update={"fallback": "approved_direct"})
    compiled = compile(service, _target(), router=_router(providers={"warp": {"reachable": False}}), lanes=[lane], chains=Resolver())
    assert compiled.status == "supported" and "provider_unreachable" in compiled.warnings
    assert compiled.document["lanes"]["grant:1"]["default"] == {"action": "direct", "egress": None}


def test_explain_walks_a_lanes_rules_for_a_destination():
    lane = _lane("grant:7f3a", default_action="egress", rules=[
        _rule("block", domains=["ads.example", "*.ads.example"], rule_id="11111111-0000-4000-8000-111111111111"),
        _rule("egress", geosites=["youtube"], egress=f"node:{GUID_B}:warp", rule_id="22222222-0000-4000-8000-222222222222"),
        _rule("direct", cidrs=["203.0.113.0/24"], ports=[443], rule_id="33333333-0000-4000-8000-333333333333"),
    ]).model_copy(update={"default_egress": "warp"})
    assert explain(lane, "tracker.ads.example", 443) == {
        "lane": "grant:7f3a", "rule_id": "11111111-0000-4000-8000-111111111111", "action": "block", "exit": None,
        "hops": [], "via": None, "uncertain": []}
    assert explain(lane, "203.0.113.9", 443) == {
        "lane": "grant:7f3a", "rule_id": "33333333-0000-4000-8000-333333333333", "action": "direct", "exit": None,
        "hops": [], "via": None, "uncertain": ["22222222-0000-4000-8000-222222222222"]}
    assert explain(lane, "203.0.113.9", 80)["rule_id"] is None  # the port does not match: the default
    assert explain(lane, "example.org", 443) == {
        "lane": "grant:7f3a", "rule_id": None, "action": "egress", "exit": "warp", "hops": [], "via": None,
        "uncertain": ["22222222-0000-4000-8000-222222222222"]}
    chained = lane.model_copy(update={"default_egress": f"node:{GUID_B},{GUID_C}:warp"})
    result = explain(chained, "example.org", 443)
    assert result["hops"] == [GUID_B, GUID_C] and result["via"] == "warp" and result["exit"] == f"node:{GUID_B},{GUID_C}:warp"
