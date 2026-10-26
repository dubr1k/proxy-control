"""The panel's side of the Xray-router (v0.5): the client's routes and bounded codes, the
memory twin, the router adapter's typed target/applied results, and the attach documents
the native managers accept."""
from __future__ import annotations

import httpx
import pytest

from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.protocols import AdapterError, AppliedEgress, MieruAdapter, NaiveAdapter, RouterTarget
from panel.protocols.xray_router import RouterAdapter
from panel.routing.document import EGRESS_REASON_CODES, ROUTER_DIRECT_INTENT, attach_document, attached_to_router
from panel.xray_router import ROUTER_CAPABILITIES, MemoryXrayRouter, XrayRouterClient, XrayRouterError

pytestmark = pytest.mark.anyio

WARP_INTENT = {"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": []}
BLOCK_INTENT = {"schema": 1, "default": {"action": "direct", "egress": None},
                "rules": [{"domains": ["example.com"], "geosites": [], "cidrs": [], "geoips": [], "ports": [],
                           "action": "block", "egress": None}]}


@pytest.fixture
def anyio_backend():
    return "asyncio"





async def test_memory_router_behaves_like_the_manager():
    router = MemoryXrayRouter()
    view = await router.egress("naive")
    assert view["document"] == ROUTER_DIRECT_INTENT and view["mode"] == "direct" and view["previous"] is None
    assert view["capabilities"] == list(ROUTER_CAPABILITIES) and view["restart_required"] is True
    applied = await router.egress_apply("naive", view["revision"], WARP_INTENT, "op-1")
    assert applied["generation"] == 2 and applied["replayed"] is False
    again = await router.egress_apply("naive", "stale", WARP_INTENT, "op-1")
    assert again["replayed"] is True
    with pytest.raises(XrayRouterError) as caught:
        await router.egress_apply("naive", "stale", BLOCK_INTENT, "op-2")
    assert caught.value.code == "egress_conflict"
    assert (await router.egress("mieru"))["document"] == ROUTER_DIRECT_INTENT  # untouched
    router.reachable = False
    with pytest.raises(XrayRouterError) as caught:
        await router.egress_apply("mieru", (await router.egress("mieru"))["revision"], WARP_INTENT, "op-3")
    assert caught.value.code == "egress_unreachable"
    router.fail_next = "geoip_unknown"
    with pytest.raises(XrayRouterError) as caught:
        await router.egress_apply("naive", (await router.egress("naive"))["revision"], BLOCK_INTENT, "op-4")
    assert (caught.value.status_code, caught.value.code) == (422, "geoip_unknown")
    rolled = await router.egress_rollback("naive", (await router.egress("naive"))["revision"])
    assert rolled["applied"] == ROUTER_DIRECT_INTENT
    with pytest.raises(XrayRouterError) as caught:
        await router.egress_rollback("naive", (await router.egress("naive"))["revision"])
    assert caught.value.code == "egress_no_previous"
    router.available = False
    with pytest.raises(XrayRouterError):
        await router.status()
    assert MemoryXrayRouter(warp_url=None)._providers() == {}





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



