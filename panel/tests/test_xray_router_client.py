"""The panel's side of the Xray-router (v0.5): the client's routes and bounded codes, the
memory twin, the router adapter's typed target/applied results, and the attach documents
the native managers accept."""
from __future__ import annotations


import pytest





from panel.routing.document import ROUTER_DIRECT_INTENT, attach_document, attached_to_router
from panel.xray_router import ROUTER_CAPABILITIES, MemoryXrayRouter, XrayRouterError

pytestmark = pytest.mark.anyio

WARP_INTENT = {"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": []}
BLOCK_INTENT = {"schema": 1, "default": {"action": "direct", "egress": None},
                "rules": [{"domains": ["example.com"], "geosites": [], "cidrs": [], "geoips": [], "ports": [],
                           "action": "block", "egress": None}]}














async def test_attach_documents_and_attached_detection():
    assert attached_to_router("naive", attach_document("naive")) is True
    assert attached_to_router("mieru", attach_document("mieru")) is True
    assert attached_to_router("naive", {"schema": 1, "upstream": {"provider": "warp"}, "acl": []}) is False
    assert attached_to_router("naive", None) is False
    assert attached_to_router("mieru", {"schema": 1, "proxies": [{"name": "router", "provider": "router"}],
                                        "rules": [{"domains": ["a.example"], "cidrs": [], "action": "PROXY", "proxy": "router"}]}) is False
    assert attached_to_router("mtproxy", {}) is False
    # The attach document is a copy each time: a caller cannot poison the constant.
    document = attach_document("naive")
    document["acl"].append({"deny": ["x"]})
    assert attach_document("naive")["acl"] == []



