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


async def test_client_speaks_the_router_routes_and_keeps_the_bounded_codes():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path, request.headers.get("X-Xray-Router-Token")))
        if request.url.path == "/v1/status":
            return httpx.Response(200, json={"running": {"generation": 1}})
        if request.url.path == "/v1/egress/naive/apply":
            return httpx.Response(422, json={"detail": "xray refused", "code": "geosite_unknown"})
        if request.url.path == "/v1/egress/naive/rollback":
            return httpx.Response(409, json={"detail": "nope", "code": "not-a-known-code"})
        if request.url.path == "/v1/egress/mieru":
            return httpx.Response(503, json={"detail": "digest", "code": "artifact_mismatch"})
        return httpx.Response(200, json={"revision": "r"})

    client = XrayRouterClient("/run/x.sock", "t" * 40, transport=httpx.MockTransport(handler))
    assert (await client.status())["running"]["generation"] == 1
    assert (await client.egress("naive"))["revision"] == "r"
    assert (await client.egress_plan("naive", "r", WARP_INTENT))["revision"] == "r"
    with pytest.raises(XrayRouterError) as caught:
        await client.egress_apply("naive", "r", WARP_INTENT, "op-1")
    assert (caught.value.status_code, caught.value.code) == (422, "geosite_unknown")
    with pytest.raises(XrayRouterError) as caught:
        await client.egress_rollback("naive", "r")
    assert (caught.value.status_code, caught.value.code) == (409, None)
    with pytest.raises(XrayRouterError) as caught:
        await client.egress("mieru")
    assert (caught.value.status_code, caught.value.code) == (503, "artifact_mismatch")
    assert all(token == "t" * 40 for _, _, token in seen)
    assert {"geosite_unknown", "geoip_unknown", "artifact_mismatch"} <= EGRESS_REASON_CODES


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


async def test_router_adapter_maps_codes_and_targets():
    router = MemoryXrayRouter()
    adapter = RouterAdapter(router)
    target = await adapter.target("naive")
    assert isinstance(target, RouterTarget) and target.available and target.service == "naive"
    assert target.capabilities == frozenset(ROUTER_CAPABILITIES) and target.providers == {"warp": {"reachable": True}}
    assert target.applied["document"] == ROUTER_DIRECT_INTENT and target.xray_version.startswith("Xray")
    assert target.restart_required is True and target.reason is None
    applied = await adapter.apply("naive", WARP_INTENT, expected_revision=target.revision, operation_id="op-1")
    assert isinstance(applied, AppliedEgress) and applied.digest is not None and applied.replayed is False
    plan = await adapter.plan("naive", BLOCK_INTENT, expected_revision=applied.revision)
    assert plan["restart_required"] is True
    with pytest.raises(AdapterError) as caught:
        await adapter.apply("naive", BLOCK_INTENT, expected_revision="stale", operation_id="op-2")
    assert caught.value.code == "egress_conflict"
    router.fail_next = "manual_intervention_required"
    with pytest.raises(AdapterError) as caught:
        await adapter.rollback("naive", expected_revision=applied.revision)
    assert caught.value.code == "manual_intervention_required"
    router.artifact_error = "digest"
    unavailable = await adapter.target("naive")
    assert unavailable.available is False and unavailable.reason == "artifact_mismatch"
    assert await adapter.status() is None
    router.artifact_error = None
    router.available = False
    unavailable = await adapter.target("mieru")
    assert unavailable.available is False and unavailable.reason == "router_unavailable"


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


async def test_native_fakes_accept_the_attach_document_only_with_a_router():
    naive, mieru = MemoryNaive(), MemoryMieru()
    for fake, protocol in ((naive, "naive"), (mieru, "mieru")):
        adapter = NaiveAdapter(fake, public_host="n") if protocol == "naive" else MieruAdapter(fake, public_host="m")
        target = await adapter.egress_target()
        assert target.router_attached is False and "router" not in target.providers
        with pytest.raises(AdapterError) as caught:
            await adapter.apply_egress(attach_document(protocol), expected_revision=target.revision, operation_id="op-a")
        assert caught.value.code == "egress_invalid"
        fake.router_url = f"socks5://127.0.0.1:{45101 if protocol == 'naive' else 45102}"
        target = await adapter.egress_target()
        assert target.providers["router"] == {"reachable": True}
        fake.router_reachable = False
        with pytest.raises(AdapterError) as caught:
            await adapter.apply_egress(attach_document(protocol), expected_revision=target.revision, operation_id="op-b")
        assert caught.value.code == "egress_unreachable"
        fake.router_reachable = True
        applied = await adapter.apply_egress(attach_document(protocol), expected_revision=target.revision, operation_id="op-c")
        target = await adapter.egress_target()
        assert target.router_attached is True and target.applied["digest"] == applied.digest and target.mode == "proxy"
        rolled = await adapter.rollback_egress(expected_revision=target.revision)
        assert rolled.digest is not None and (await adapter.egress_target()).router_attached is False
