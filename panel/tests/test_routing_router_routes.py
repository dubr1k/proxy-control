"""The routing API with the node's Xray-router (v0.5): attach/detach are owner-only, audited,
and `targets` names the router; a router policy round-trips through the same routes."""
from __future__ import annotations

import pytest

from panel.routing.document import attach_document
from panel.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio

WARP = {"default_action": "egress", "default_egress": "warp", "fallback": "fail_closed", "rules": []}
GEO = {"default_action": "egress", "default_egress": "warp", "fallback": "fail_closed",
       "rules": [{"action": "block", "match": {"geosites": ["category-ads-all"], "ports": [25]}, "note": "ads"}]}


def _csrf(client) -> dict:
    return {"X-CSRF-Token": client.cookies["panel_csrf"]}


@pytest.fixture
def router(client, naive, mieru):
    """The app under test wired to a memory router; the fakes know their ingress."""
    from panel.protocols import RouterAdapter

    app = client._transport.app
    fake = MemoryXrayRouter()
    app.state.router = RouterAdapter(fake)
    app.state.routing.router = app.state.router
    naive.router_url, mieru.router_url = "socks5://127.0.0.1:45101", "socks5://127.0.0.1:45102"
    return fake


async def test_attach_detach_are_owner_only_and_audited(client, login_user, router, naive):
    await login_user(client)
    targets = await client.get("/api/routing/targets")
    item = next(item for item in targets.json()["items"] if item["protocol"] == "naive")
    assert item["router"]["available"] is True and item["router"]["attached"] is False
    attached = await client.post("/api/routing/targets/local/naive/attach", headers=_csrf(client))
    assert attached.status_code == 200, attached.text
    assert attached.json()["target"]["backend"] == "xray_router" and attached.json()["target"]["router"]["attached"] is True
    assert naive.egress_document == attach_document("naive")
    audits = client._transport.app.state.store.audits()
    assert any(row["action"] == "routing.target.attach" for row in audits)
    # A policy on the router, previewed and applied through the usual routes.
    put = await client.put("/api/routing/policies/local/naive", json={**GEO, "expected_revision": 1}, headers=_csrf(client))
    assert put.status_code == 200 and put.json()["backend"] == "xray_router" and put.json()["revision"] == 2
    assert put.json()["rules"][0]["match"]["geosites"] == ["category-ads-all"]
    preview = await client.post("/api/routing/policies/local/naive/preview", headers=_csrf(client))
    assert preview.status_code == 200 and preview.json()["status"] == "supported"
    assert preview.json()["attach"] == attach_document("naive") and preview.json()["restart_required"] is True
    applied = await client.post("/api/routing/policies/local/naive/apply", json={"expected_revision": 2}, headers=_csrf(client))
    assert applied.status_code == 200 and applied.json()["policy"]["state"] == "applied"
    assert router.documents["naive"]["rules"][0]["ports"] == [25]
    # Detach is refused while a policy with rules is applied? No: detach takes the service back
    # regardless — the policy moves to the native backend as a draft.
    detached = await client.post("/api/routing/targets/local/naive/detach", headers=_csrf(client))
    assert detached.status_code == 200 and detached.json()["target"]["backend"] == "naive_native"
    assert detached.json()["target"]["policy"]["backend"] == "naive_native"
    assert any(row["action"] == "routing.target.detach" for row in client._transport.app.state.store.audits())
    # Now the policy's geosite rule is honestly unsupported on the native backend.
    preview = await client.post("/api/routing/policies/local/naive/preview", headers=_csrf(client))
    assert preview.json()["status"] == "unsupported" and preview.json()["reasons"][0]["code"] == "rule_kind_unsupported"
    # Viewer: reads the router, cannot attach.
    await client.post("/api/auth/logout", headers=_csrf(client))
    client.cookies.clear()
    client._transport.app.state.store.create_admin("reader", "viewer correct horse battery", "viewer")
    await login_user(client, "reader", "viewer correct horse battery")
    assert (await client.get("/api/routing/targets")).status_code == 200
    for path in ("/api/routing/targets/local/naive/attach", "/api/routing/targets/local/naive/detach"):
        assert (await client.post(path, headers=_csrf(client))).status_code == 403


async def test_attach_refusals_carry_codes(client, login_user, router, naive):
    await login_user(client)
    assert (await client.post("/api/routing/targets/local/mtproxy/attach", headers=_csrf(client))).status_code == 422
    assert (await client.post("/api/routing/targets/missing/naive/attach", headers=_csrf(client))).status_code == 404
    naive.router_reachable = False
    refused = await client.post("/api/routing/targets/local/naive/attach", headers=_csrf(client))
    assert (refused.status_code, refused.json()["code"]) == (409, "router_unreachable")
    naive.router_reachable = True
    router.available = False
    refused = await client.post("/api/routing/targets/local/naive/attach", headers=_csrf(client))
    assert (refused.status_code, refused.json()["code"]) == (409, "router_unavailable")
    # Without any router the panel still answers, with the reason.
    client._transport.app.state.routing.router = None
    targets = await client.get("/api/routing/targets")
    assert next(item for item in targets.json()["items"] if item["protocol"] == "naive")["router"] is None
