"""The routing intent the Xray-router manager accepts (v0.5): bounded, normalised, never raw."""
from __future__ import annotations

import pytest

from xray_router_manager.intent import (
    CAPABILITIES,
    MAX_DOCUMENT_BYTES,
    EgressInvalid,
    direct_document,
    document_digest,
    provider_endpoint,
    uses_provider,
    validate_document,
)


def _doc(rules, default=None):
    return {"schema": 1, "default": default or {"action": "direct", "egress": None}, "rules": rules}


def test_validate_document_normalises_and_orders():
    document = validate_document(_doc([
        {"domains": ["Example.COM.", "*.Example.com", "example.com"], "cidrs": ["10.0.0.1", "10.0.0.0/8"],
         "geosites": ["category-ads-all"], "geoips": ["cloudflare"], "ports": ["80", 443, "1000-2000"],
         "action": "egress", "egress": "warp"},
        {"ports": [25], "action": "block"},
    ], default={"action": "egress", "egress": "warp"}))
    first, second = document["rules"]
    assert first["domains"] == ["example.com", "*.example.com"]
    assert first["cidrs"] == ["10.0.0.1/32", "10.0.0.0/8"]
    assert first["geosites"] == ["category-ads-all"] and first["geoips"] == ["cloudflare"]
    assert first["ports"] == [80, 443, "1000-2000"] and first["egress"] == "warp"
    assert second == {"domains": [], "geosites": [], "cidrs": [], "geoips": [], "ports": [25], "action": "block",
                      "egress": None}
    assert document["default"] == {"action": "egress", "egress": "warp"}
    assert uses_provider(document) and not uses_provider(direct_document())
    assert len(document_digest(document)) == 64


@pytest.mark.parametrize("document", [
    {"schema": 1, "default": {"action": "direct"}, "rules": [], "inbounds": []},
    {"schema": 2, "default": {"action": "direct"}, "rules": []},
    {"schema": 1, "default": {"action": "block"}, "rules": []},
    {"schema": 1, "default": {"action": "egress"}, "rules": []},
    {"schema": 1, "default": {"action": "direct", "egress": "warp"}, "rules": []},
    {"schema": 1, "default": {"action": "direct"}, "rules": [{"domains": ["a.example"], "action": "egress"}]},
    {"schema": 1, "default": {"action": "direct"}, "rules": [{"domains": ["a.example"], "action": "direct", "egress": "warp"}]},
    {"schema": 1, "default": {"action": "direct"}, "rules": [{"domains": ["a.example"], "action": "direct", "path": "/x"}]},
    {"schema": 1, "default": {"action": "direct"}, "rules": [{"domains": ["not a host"], "action": "direct"}]},
    {"schema": 1, "default": {"action": "direct"}, "rules": [{"cidrs": ["300.1.1.1"], "action": "direct"}]},
    {"schema": 1, "default": {"action": "direct"}, "rules": [{"geosites": ["Bad Code"], "action": "direct"}]},
    {"schema": 1, "default": {"action": "direct"}, "rules": [{"ports": [0], "action": "direct"}]},
    {"schema": 1, "default": {"action": "direct"}, "rules": [{"ports": [True], "action": "direct"}]},
    {"schema": 1, "default": {"action": "direct"}, "rules": [{"ports": ["9-3"], "action": "direct"}]},
    ["not", "an", "object"],
    {"inbounds": [{"protocol": "socks"}]},
])
def test_validate_document_rejects_unknown_fields_schema_and_raw_json(document):
    with pytest.raises(EgressInvalid):
        validate_document(document)


def test_validate_document_rejects_private_geoip_and_empty_rule():
    with pytest.raises(EgressInvalid, match="bypass"):
        validate_document(_doc([{"geoips": ["private"], "action": "block"}]))
    with pytest.raises(EgressInvalid, match="selector"):
        validate_document(_doc([{"action": "block"}]))
    with pytest.raises(EgressInvalid, match="selector"):
        validate_document(_doc([{"domains": [], "cidrs": [], "action": "block"}]))


def test_validate_document_limits_and_size():
    with pytest.raises(EgressInvalid):
        validate_document(_doc([{"domains": ["a.example"], "action": "block"}] * 129))
    with pytest.raises(EgressInvalid):
        validate_document(_doc([{"domains": [f"h{i}.example" for i in range(65)], "action": "block"}]))
    with pytest.raises(EgressInvalid):
        validate_document(_doc([{"ports": list(range(1, 34)), "action": "block"}]))
    long_rules = [{"domains": [f"{'x' * 60}{i:03d}.{'y' * 60}.example" for i in range(64)], "action": "block"}] * 3
    with pytest.raises(EgressInvalid, match="too large"):
        validate_document(_doc(long_rules))
    assert MAX_DOCUMENT_BYTES == 16384


def test_direct_document_is_the_floor():
    assert validate_document(direct_document()) == direct_document()
    assert direct_document()["rules"] == [] and direct_document()["default"]["action"] == "direct"
    assert len(CAPABILITIES) == 16 and "block_port" in CAPABILITIES and "geodata" in CAPABILITIES and "block_protocol" in CAPABILITIES


def test_provider_endpoint_accepts_socks5_only():
    assert provider_endpoint("socks5://127.0.0.1:45000") == ("127.0.0.1", 45000)
    for url in (None, "", "http://127.0.0.1:8118", "socks5://127.0.0.1"):
        with pytest.raises(EgressInvalid):
            provider_endpoint(url)


# --- schema 2 (v0.7): lanes, chains, exits through other nodes ------------------------------

HOP = {"guid": "b" * 32, "address": "panel.node-b.example.org", "port": 45443, "server_name": "panel.node-b.example.org",
       "public_key": "SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s", "short_id": "0123abcd",
       "uuid": "3f0d9c6e-1b4e-4a6b-9a1e-2c8f5d7e9a10"}


def _v2(lanes=None, chains=None):
    return {"schema": 2,
            "lanes": lanes if lanes is not None else {"svc:naive": {"default": {"action": "direct", "egress": None}, "rules": []}},
            "chains": chains if chains is not None else {}}


def test_schema_2_normalises_lanes_chains_and_keeps_the_service_lane_last():
    from xray_router_manager.intent import chain_ids, lanes_of, uses_chain

    document = validate_document(_v2(
        lanes={
            "grant:7f3a": {"default": {"action": "egress", "egress": "chain:c1"},
                           "rules": [{"geosites": ["category-ads-all"], "action": "block"},
                                     {"geoips": ["ru"], "action": "direct"},
                                     {"domains": ["*.Example.NET"], "action": "egress", "egress": "warp"}]},
            "svc:naive": {"default": {"action": "direct", "egress": None}, "rules": []},
        },
        chains={"c1": {"hops": [HOP], "exit": "warp"}},
    ))
    assert document["schema"] == 2
    assert list(document["lanes"]) == ["grant:7f3a", "svc:naive"]  # insertion order kept; the renderer puts svc last
    lane = document["lanes"]["grant:7f3a"]
    assert lane["default"] == {"action": "egress", "egress": "chain:c1"}
    assert lane["rules"][2]["domains"] == ["*.example.net"] and lane["rules"][2]["egress"] == "warp"
    assert document["chains"]["c1"]["hops"][0]["address"] == "panel.node-b.example.org"
    assert document["chains"]["c1"]["exit"] == "warp"
    assert uses_provider(document) and uses_chain(document, "c1") and chain_ids(document) == ["c1"]
    # a v1 document is one service lane; the renderer asks for it by the service's name
    assert lanes_of(direct_document(), "mieru") == {"svc:mieru": direct_document() | {"schema": 2}} or \
        lanes_of(direct_document(), "mieru")["svc:mieru"]["default"] == {"action": "direct", "egress": None}
    assert lanes_of(document, "naive") is document["lanes"]


@pytest.mark.parametrize("document", [
    _v2(lanes={"svc:naive": {"default": {"action": "egress", "egress": "chain:missing"}, "rules": []}}),
    _v2(lanes={"grant:1": {"default": {"action": "direct", "egress": None}, "rules": []}}),  # no service lane
    _v2(lanes={"svc:naive": {"default": {"action": "direct", "egress": None}, "rules": []},
               "svc:mieru": {"default": {"action": "direct", "egress": None}, "rules": []}}),  # two service lanes
    _v2(lanes={"svc:naive": {"default": {"action": "block", "egress": None}, "rules": []}}),
    _v2(lanes={"svc:naive": {"default": {"action": "direct", "egress": None}, "rules": [{"domains": ["a.example"], "action": "egress", "egress": "node-b"}]}}),
    _v2(lanes={"lane with space": {"default": {"action": "direct", "egress": None}, "rules": []}}),
    _v2(chains={"c1": {"hops": [], "exit": "direct"}}),
    _v2(chains={"c1": {"hops": [HOP] * 4, "exit": "direct"}}),
    _v2(chains={"c1": {"hops": [HOP | {"uuid": "not-a-uuid"}], "exit": "direct"}}),
    _v2(chains={"c1": {"hops": [HOP | {"port": 70000}], "exit": "direct"}}),
    _v2(chains={"c1": {"hops": [HOP | {"public_key": "short"}], "exit": "direct"}}),
    _v2(chains={"c1": {"hops": [HOP | {"short_id": "xyz"}], "exit": "direct"}}),
    _v2(chains={"c1": {"hops": [HOP], "exit": "block"}}),
    _v2(chains={"c1": {"hops": [HOP], "exit": "direct", "extra": 1}}),
    _v2(chains={"bad id!": {"hops": [HOP], "exit": "direct"}}),
    {"schema": 2, "lanes": {}, "chains": {}, "default": {"action": "direct"}},
])
def test_schema_2_rejects_bad_lanes_chains_and_hops(document):
    with pytest.raises(EgressInvalid):
        validate_document(document)


def test_schema_2_limits():
    from xray_router_manager.intent import MAX_CHAINS, MAX_HOPS, MAX_LANES, MAX_DOCUMENT_BYTES_V2

    assert (MAX_LANES, MAX_CHAINS, MAX_HOPS, MAX_DOCUMENT_BYTES_V2) == (32, 16, 3, 65536)
    lanes = {f"grant:{i}": {"default": {"action": "direct", "egress": None}, "rules": []} for i in range(32)}
    lanes["svc:naive"] = {"default": {"action": "direct", "egress": None}, "rules": []}
    with pytest.raises(EgressInvalid, match="lanes"):
        validate_document(_v2(lanes=lanes))
    chains = {f"c{i}": {"hops": [HOP], "exit": "direct"} for i in range(17)}
    with pytest.raises(EgressInvalid, match="chains"):
        validate_document(_v2(chains=chains))
    # the v2 ceiling is the v1 ceiling times the lanes it may carry
    assert validate_document(_v2(chains={f"c{i}": {"hops": [HOP] * 3, "exit": "direct"} for i in range(16)}))["schema"] == 2


def test_schema_2_redaction_masks_every_hop_secret():
    from xray_router_manager.intent import redact_intent

    document = validate_document(_v2(chains={"c1": {"hops": [HOP, HOP | {"guid": "c" * 32}], "exit": "direct"}}))
    masked = redact_intent(document)
    assert all(hop["uuid"] == "***" for hop in masked["chains"]["c1"]["hops"])
    assert document["chains"]["c1"]["hops"][0]["uuid"] == HOP["uuid"]  # the original is untouched
    assert masked["chains"]["c1"]["hops"][0]["public_key"] == HOP["public_key"]  # public stays public
    assert redact_intent(direct_document()) == direct_document()
