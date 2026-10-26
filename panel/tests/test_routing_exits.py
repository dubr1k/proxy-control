"""Custom exits through the panel (v0.8): the store and its escrow, share links, the
routes (owner-only, audited, credentials never in an answer), the compiler naming an exit
in a router intent, and the test through this server's router and a linked panel's."""
from __future__ import annotations

import json


import pytest



from panel.tests.harness.memories.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio

UUID = "9d3b6b2c-1e6a-4b2a-9f0e-3c2f8a1d5e77"



def _csrf(client) -> dict:
    return {"X-CSRF-Token": client.cookies["panel_csrf"]}


@pytest.fixture
def router(xray_router, naive, mieru):
    """The shared panel wired to the router double (over its socket); the fakes know their ingress."""
    naive.router_url, mieru.router_url = "socks5://127.0.0.1:45101", "socks5://127.0.0.1:45102"
    return xray_router








async def test_exits_crud_import_test_and_the_policy_that_uses_one(client, server, login_user, router):
    await login_user(client)
    headers = _csrf(client)
    created = await client.post("/api/routing/exits", headers=headers, json={
        "node_id": "local", "name": "lab socks", "protocol": "socks", "address": "10.0.0.2", "port": 1080,
        "credential": {"username": "u", "password": "p"}})
    assert created.status_code == 201, created.text
    exit_id = created.json()["id"]
    assert created.json()["has_credential"] is True and "credential" not in created.json() and '"password"' not in created.text
    imported = await client.post("/api/routing/exits/import", headers=headers,
                                 json={"node_id": "local", "link": f"vless://{UUID}@vpn.example.org:443?security=tls&sni=vpn.example.org#NL"})
    assert imported.status_code == 201 and imported.json()["protocol"] == "vless" and imported.json()["name"] == "NL"
    assert UUID not in imported.text
    listing = await client.get("/api/routing/exits?node=local")
    assert [item["name"] for item in listing.json()["items"]] == ["lab socks", "NL"]
    # The targets name the node's exits for the editor.
    targets = await client.get("/api/routing/targets")
    item = next(t for t in targets.json()["items"] if t["protocol"] == "naive" and t["node_id"] == "local")
    assert [e["name"] for e in item["custom_exits"]] == ["lab socks", "NL"]
    # Test: the router's probe, recorded on the row.
    tested = await client.post(f"/api/routing/exits/{exit_id}/test", headers=headers)
    assert tested.status_code == 200 and tested.json()["ok"] is True and tested.json()["ip"] == "203.0.113.9"
    assert router.calls[-1] == ("exit_test", "socks", "10.0.0.2")
    listing = await client.get("/api/routing/exits?node=local")
    assert listing.json()["items"][0]["last_test"]["colo"] == "AMS"
    # A policy on the router leaves through the exit; the intent carries the outbound, the
    # preview masks its credential.
    await client.post("/api/routing/targets/local/naive/attach", headers=headers)
    policy = {"backend": "xray_router", "default_action": "egress", "default_egress": f"exit:{exit_id}", "fallback": "fail_closed",
              "rules": [{"action": "egress", "egress": f"exit:{exit_id}", "match": {"geosites": ["youtube"]}}]}
    preview = await client.post("/api/routing/policies/local/naive/preview", headers=headers, json=policy)
    assert preview.status_code == 200, preview.text
    compiled = preview.json()
    assert compiled["status"] == "supported", compiled["reasons"]
    document = compiled["document"]
    assert document["schema"] == 2 and document["lanes"]["svc:naive"]["default"]["egress"] == "exit:e1"
    assert document["exits"]["e1"]["credential"] == {"username": "***", "password": "***"} and document["exits"]["e1"]["address"] == "10.0.0.2"
    assert '"p"' not in json.dumps(compiled)
    saved = await client.put("/api/routing/policies/local/naive", headers=headers, json={**policy, "expected_revision": None})
    assert saved.status_code == 200, saved.text
    applied = await client.post("/api/routing/policies/local/naive/apply", headers=headers, json={"expected_revision": saved.json()["revision"]})
    assert applied.status_code == 200, applied.text
    # The router received the real credential.
    assert router.documents["naive"]["exits"]["e1"]["credential"] == {"username": "u", "password": "p"}
    # Deleting an exit in use is refused with where; disabling marks the policy dirty.
    refused = await client.post(f"/api/routing/exits/{exit_id}/delete", headers=headers)
    assert refused.status_code == 409 and refused.json()["code"] == "exit_in_use" and refused.json()["used_by"][0]["protocol"] == "naive"
    disabled = await client.post(f"/api/routing/exits/{exit_id}/disable", headers=headers)
    assert disabled.json()["enabled"] is False
    preview = await client.post("/api/routing/policies/local/naive/preview", headers=headers)
    assert preview.json()["status"] == "unsupported" and preview.json()["reasons"][0]["code"] == "exit_disabled"
    # v0.9: dirty, but the node still runs the applied revision — kept, so the card says
    # «на узле rev N» and «Откатить» stays; the applied policy is not deletable either.
    stored = (await client.get("/api/routing/policies/local/naive")).json()
    assert stored["state"] == "draft" and stored["applied_revision"] == saved.json()["revision"] and stored["applied_current"] is False
    assert (await client.delete("/api/routing/policies/local/naive", headers=headers)).status_code == 409
    await client.post(f"/api/routing/exits/{exit_id}/enable", headers=headers)
    # An update rotates the credential and leaves the policy a draft again.
    updated = await client.put(f"/api/routing/exits/{exit_id}", headers=headers, json={
        "name": "lab socks 2", "protocol": "socks", "address": "10.0.0.2", "port": 1081, "credential": {"username": "u2", "password": "p2"}})
    assert updated.status_code == 200 and updated.json()["port"] == 1081
    assert (await client.get("/api/routing/policies/local/naive")).json()["state"] == "draft"
    # Unknown exit in a policy: named honestly.
    bad = await client.post("/api/routing/policies/local/naive/preview", headers=headers,
                            json={**policy, "default_egress": "exit:nope", "rules": []})
    assert bad.json()["reasons"][0]["code"] == "exit_unknown"
    actions = [row["action"] for row in server.audits()]
    for action in ("routing.exit.create", "routing.exit.import", "routing.exit.test", "routing.exit.disable", "routing.exit.enable", "routing.exit.update"):
        assert action in actions, action
    assert all("p2" not in json.dumps(row.get("detail", "")) for row in server.audits())


async def test_exits_are_owner_only_and_a_native_backend_refuses_them(client, server, login_user, router):
    await login_user(client)
    headers = _csrf(client)
    created = await client.post("/api/routing/exits", headers=headers, json={
        "node_id": "local", "name": "s", "protocol": "socks", "address": "10.0.0.2", "port": 1080})
    exit_id = created.json()["id"]
    preview = await client.post("/api/routing/policies/local/naive/preview", headers=headers, json={
        "default_action": "egress", "default_egress": f"exit:{exit_id}", "fallback": "fail_closed", "rules": []})
    assert preview.json()["status"] == "unsupported" and preview.json()["reasons"][0]["code"] == "rule_kind_unsupported"
    server.create_admin("reader", "viewer correct horse battery", "viewer")
    await client.post("/api/auth/logout", headers=headers)
    client.cookies.clear()
    await login_user(client, "reader", "viewer correct horse battery")
    assert (await client.get("/api/routing/exits?node=local")).status_code == 200
    assert (await client.post(f"/api/routing/exits/{exit_id}/test", headers=_csrf(client))).status_code == 403
    assert (await client.post("/api/routing/exits", headers=_csrf(client), json={"node_id": "local", "name": "x", "protocol": "socks", "address": "h", "port": 1})).status_code == 403


async def test_a_linked_panels_exit_is_tested_through_its_fleet_api(pair_factory, login_user):
    from panel.tests.harness.routing import csrf, linked

    fake = MemoryXrayRouter()
    node, central, plaintext = pair_factory(node={"router": fake})
    async with linked(central, plaintext, login_user) as (client, node_id):
        data = {"node_id": node_id, "name": "edge socks", "protocol": "socks", "address": "10.0.0.9",
                "port": 1080, "credential": {"username": "u", "password": "p"}}
        created = await client.post("/api/routing/exits", headers=csrf(client), json=data)
        assert created.status_code == 201, created.text
        result = await client.post(f"/api/routing/exits/{created.json()['id']}/test", headers=csrf(client))
        assert result.status_code == 200 and result.json()["ok"] is True, result.text
        assert fake.calls[-1] == ("exit_test", "socks", "10.0.0.9")
        assert "fleet.exit.test" in [row["action"] for row in node.audits()]
        down = await client.post("/api/routing/exits", headers=csrf(client), json={
            "node_id": node_id, "name": "down", "protocol": "http", "address": "down.example.org", "port": 3128})
        assert down.status_code == 201, down.text
        result = await client.post(f"/api/routing/exits/{down.json()['id']}/test", headers=csrf(client))
        assert result.json()["code"] == "exit_unreachable"
