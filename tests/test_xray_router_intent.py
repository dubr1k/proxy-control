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
    assert len(CAPABILITIES) == 12 and "block_port" in CAPABILITIES


def test_provider_endpoint_accepts_socks5_only():
    assert provider_endpoint("socks5://127.0.0.1:45000") == ("127.0.0.1", 45000)
    for url in (None, "", "http://127.0.0.1:8118", "socks5://127.0.0.1"):
        with pytest.raises(EgressInvalid):
            provider_endpoint(url)
