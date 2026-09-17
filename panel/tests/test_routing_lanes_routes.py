"""The routing API of v0.7 through the app: a grant's own lane (router account → manager
handler/slot → draft policy), exits through another node (relay accounts issued on apply,
the chain in the intent), «куда пойдёт» and the node's relay — owner-only, audited, and
never a UUID or a lane key in any answer."""
from __future__ import annotations

import pytest

from panel.routing.document import attach_document
from panel.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio

GUID_B = "b" * 32


def _csrf(client) -> dict:
    return {"X-CSRF-Token": client.cookies["panel_csrf"]}


@pytest.fixture
def router(client, naive, mieru):
    from panel.protocols import RouterAdapter

    app = client._transport.app
    fake = MemoryXrayRouter()
    app.state.router = RouterAdapter(fake)
    app.state.routing.router = app.state.router
    app.state.lanes.router = app.state.router
    naive.router_url, mieru.router_url = "socks5://127.0.0.1:45101", "socks5://127.0.0.1:45102"
    return fake


async def _grant(client, login_user, protocol="naive", username="alice"):
    await login_user(client)
    csrf = _csrf(client)
    created = await client.post("/api/clients", json={"display_name": "A"}, headers=csrf)
    client_id = created.json()["id"]
    started = await client.post(f"/api/clients/{client_id}/grants", headers=csrf,
                                json={"grants": [{"protocol": protocol, "node_id": "local", "runtime_username": username, "options": {}}]})
    assert started.status_code == 200, started.text
    listing = (await client.get(f"/api/clients/{client_id}")).json()
    return listing["grants"][0]["id"], client_id, csrf


async def _attach(client, csrf, protocol="naive"):
    attached = await client.post(f"/api/routing/targets/local/{protocol}/attach", headers=csrf)
    assert attached.status_code == 200, attached.text


async def test_a_grant_gets_its_own_lane_and_loses_it_again(client, login_user, router, naive):
    grant_id, client_id, csrf = await _grant(client, login_user)
    await _attach(client, csrf)
    enabled = await client.post(f"/api/routing/lanes/{grant_id}", json={"mode": "own"}, headers=csrf)
    assert enabled.status_code == 200, enabled.text
    lane = f"grant:{grant_id}"
    assert enabled.json()["mode"] == "own" and enabled.json()["lane"] == lane
    # the router minted the lane's account, the manager moved alice into the lane's handler
    assert lane in router.lane_accounts["naive"] and ("lane_issue", "naive", lane) in router.calls
    assert naive.lane_table[lane]["users"] == ["alice"] and naive.lane_table[lane]["upstream_user"] == "grant-" + grant_id
    assert router.lane_accounts["naive"][lane] not in enabled.text
    # a draft policy on the lane, copied from the service's, on the router backend
    policy = await client.get(f"/api/routing/policies/local/naive?lane={lane}")
    assert policy.status_code == 200 and policy.json()["lane"] == lane and policy.json()["backend"] == "xray_router"
    assert policy.json()["state"] == "draft"
    # the lane shows on the targets and on the grant
    targets = await client.get("/api/routing/targets")
    item = next(item for item in targets.json()["items"] if item["protocol"] == "naive" and item["node_id"] == "local")
    assert [lane_view["lane"] for lane_view in item["lanes"]] == [lane]
    listing = (await client.get(f"/api/clients/{client_id}")).json()
    assert listing["grants"][0]["routing_lane"] == "own"
    audits = client._transport.app.state.store.audits()
    assert any(row["action"] == "grant.lane.enable" for row in audits)
    # enabling twice is idempotent; disabling returns alice to the service and drops the policy
    assert (await client.post(f"/api/routing/lanes/{grant_id}", json={"mode": "own"}, headers=csrf)).json()["mode"] == "own"
    disabled = await client.post(f"/api/routing/lanes/{grant_id}", json={"mode": "service"}, headers=csrf)
    assert disabled.status_code == 200 and disabled.json()["mode"] == "service"
    assert naive.lane_table == {} and lane not in router.lane_accounts["naive"]
    assert (await client.get(f"/api/routing/policies/local/naive?lane={lane}")).status_code == 404
    assert any(row["action"] == "grant.lane.disable" for row in client._transport.app.state.store.audits())


async def test_a_lane_policy_with_rules_applies_as_one_intent_with_the_service(client, login_user, router, naive):
    grant_id, _client_id, csrf = await _grant(client, login_user)
    await _attach(client, csrf)
    lane = f"grant:{grant_id}"
    await client.post(f"/api/routing/lanes/{grant_id}", json={"mode": "own"}, headers=csrf)
    body = {"default_action": "egress", "default_egress": "warp", "fallback": "fail_closed",
            "rules": [{"action": "block", "match": {"geosites": ["category-ads-all"]}, "note": "ads"}], "expected_revision": 1}
    put = await client.put(f"/api/routing/policies/local/naive?lane={lane}", json=body, headers=csrf)
    assert put.status_code == 200, put.text
    preview = await client.post(f"/api/routing/policies/local/naive/preview?lane={lane}", headers=csrf)
    assert preview.status_code == 200 and preview.json()["status"] == "supported", preview.text
    intent = preview.json()["document"]
    assert intent["schema"] == 2 and list(intent["lanes"]) == ["svc:naive", lane]
    assert intent["lanes"][lane]["default"] == {"action": "egress", "egress": "warp"}
    applied = await client.post(f"/api/routing/policies/local/naive/apply?lane={lane}", json={"expected_revision": 2}, headers=csrf)
    assert applied.status_code == 200, applied.text
    assert applied.json()["policy"]["state"] == "applied" and router.documents["naive"]["schema"] == 2
    # the service's own policy stands applied at the same intent digest
    service_policy = (await client.get("/api/routing/policies/local/naive")).json()
    assert service_policy["state"] == "applied" and service_policy["applied_digest"] == applied.json()["compiled"]["digest"]
    # explain: the ads rule blocks, everything else takes the lane's warp default
    explained = await client.post(f"/api/routing/policies/local/naive/explain?lane={lane}", json={"host": "example.org"}, headers=csrf)
    assert explained.status_code == 200 and explained.json()["action"] == "egress" and explained.json()["exit"] == "warp"
    assert explained.json()["uncertain"] == [put.json()["rules"][0]["id"]]
    # a lane policy cannot be deleted on its own
    assert (await client.delete(f"/api/routing/policies/local/naive?lane={lane}", headers=csrf)).status_code == 409
    # a lane for a grant that has none is not found; a bad lane is 422
    assert (await client.get("/api/routing/policies/local/naive?lane=grant:nope")).status_code == 404
    assert (await client.get("/api/routing/policies/local/naive?lane=bogus")).status_code == 422


async def test_lane_refusals_carry_codes(client, login_user, router, naive):
    grant_id, first_client, csrf = await _grant(client, login_user)
    # without the service attached to the router, the lane's policy says so
    await client.post(f"/api/routing/lanes/{grant_id}", json={"mode": "own"}, headers=csrf)
    lane = f"grant:{grant_id}"
    preview = await client.post(f"/api/routing/policies/local/naive/preview?lane={lane}", headers=csrf)
    assert preview.json()["status"] == "unsupported" and preview.json()["reasons"][0]["code"] == "lane_not_attached"
    # mtproxy grants have no lane; a manager that refuses leaves the grant as it was
    await login_user(client)
    csrf = _csrf(client)
    created = await client.post("/api/clients", json={"display_name": "B"}, headers=csrf)
    client_id = created.json()["id"]
    await client.post(f"/api/clients/{client_id}/grants", headers=csrf,
                      json={"grants": [{"protocol": "mtproxy", "node_id": "local", "runtime_username": "tg", "options": {}}]})
    mt_grant = (await client.get(f"/api/clients/{client_id}")).json()["grants"][0]["id"]
    refused = await client.post(f"/api/routing/lanes/{mt_grant}", json={"mode": "own"}, headers=csrf)
    assert (refused.status_code, refused.json()["code"]) == (422, "protocol_out_of_scope")
    await client.post(f"/api/routing/lanes/{grant_id}", json={"mode": "service"}, headers=csrf)
    naive.lanes_fail_next = "lanes_invalid"
    refused = await client.post(f"/api/routing/lanes/{grant_id}", json={"mode": "own"}, headers=csrf)
    assert (refused.status_code, refused.json()["code"]) == (409, "lanes_invalid")
    assert (await client.get(f"/api/clients/{first_client}")).json()["grants"][0]["routing_lane"] is None
    assert lane not in router.lane_accounts["naive"]
    # a viewer may read a lane's policy but not set one
    await client.post("/api/auth/logout", headers=csrf)
    client.cookies.clear()
    client._transport.app.state.store.create_admin("reader", "viewer correct horse battery", "viewer")
    await login_user(client, "reader", "viewer correct horse battery")
    assert (await client.post(f"/api/routing/lanes/{grant_id}", json={"mode": "own"}, headers=_csrf(client))).status_code == 403


async def test_relay_enable_rotate_and_an_exit_through_this_nodes_relay_from_itself_is_a_loop(client, login_user, router, naive):
    await login_user(client)
    csrf = _csrf(client)
    enabled = await client.post("/api/routing/relay/local/enable", headers=csrf)
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["enabled"] is True and enabled.json()["port"] == 45443 and enabled.json()["public_key"] == router.public_key
    assert ("relay_enable", "panel.example.com", 45443) in router.calls or any(call[0] == "relay_enable" for call in router.calls)
    targets = await client.get("/api/routing/targets")
    item = next(item for item in targets.json()["items"] if item["protocol"] == "naive" and item["node_id"] == "local")
    assert item["exits"] == []  # a node never exits through itself
    assert any(row["action"] == "routing.relay.enable" for row in client._transport.app.state.store.audits())
    rotated = await client.post("/api/routing/relay/local/rotate", headers=csrf)
    assert rotated.status_code == 200 and rotated.json()["rotated"] == 0
    await _attach(client, csrf)
    own = client._transport.app.state.panel_guid
    body = {"default_action": "egress", "default_egress": f"node:{own}", "fallback": "fail_closed", "rules": [], "expected_revision": 1}
    put = await client.put("/api/routing/policies/local/naive", json=body, headers=csrf)
    assert put.status_code == 200, put.text
    preview = await client.post("/api/routing/policies/local/naive/preview", headers=csrf)
    assert preview.json()["status"] == "unsupported" and preview.json()["reasons"][0]["code"] == "chain_loop"
    unknown = {**body, "default_egress": f"node:{GUID_B}", "expected_revision": 2}
    assert (await client.put("/api/routing/policies/local/naive", json=unknown, headers=csrf)).status_code == 200
    preview = await client.post("/api/routing/policies/local/naive/preview", headers=csrf)
    assert preview.json()["reasons"][0]["code"] == "node_unknown"
    # not an owner: refused
    await client.post("/api/auth/logout", headers=csrf)
    client.cookies.clear()
    client._transport.app.state.store.create_admin("reader", "viewer correct horse battery", "viewer")
    await login_user(client, "reader", "viewer correct horse battery")
    assert (await client.post("/api/routing/relay/local/enable", headers=_csrf(client))).status_code == 403


async def test_mieru_lane_carries_the_slot_port_into_the_grant_link(client, login_user, router, mieru):
    grant_id, client_id, csrf = await _grant(client, login_user, protocol="mieru", username="phone")
    await _attach(client, csrf, "mieru")
    enabled = await client.post(f"/api/routing/lanes/{grant_id}", json={"mode": "own"}, headers=csrf)
    assert enabled.status_code == 200, enabled.text
    lane = f"grant:{grant_id}"
    assert mieru.lane_table[lane]["slot"] == 1 and mieru.lane_table[lane]["users"] == ["phone"]
    assert attach_document("mieru") == mieru.egress_document
    # the grant's link and its subscription carry the slot's port, never a credential in the template
    listing = (await client.get(f"/api/clients/{client_id}")).json()
    template = listing["grants"][0]["options"]["share_template"]
    assert template.endswith(f"port={mieru.lane_slots[1]}&protocol=TCP&mtu=1400") and "{password}" in template
    assert f"port={mieru.lane_slots[1]}" in _subscription(client, client_id)
    # back on the service: the main port again
    assert (await client.post(f"/api/routing/lanes/{grant_id}", json={"mode": "service"}, headers=csrf)).status_code == 200
    listing = (await client.get(f"/api/clients/{client_id}")).json()
    assert "port=8443" in listing["grants"][0]["options"]["share_template"]  # the manager's service template
    rendered = _subscription(client, client_id)
    assert f"port={mieru.lane_slots[1]}" not in rendered and "port=8443" in rendered


def _subscription(client, client_id: str) -> str:
    """The client's subscription as `/s/{token}` renders it (raw links), from the same
    reveal-and-render path the public route uses."""
    from panel.fleet_v2.central_routes import public_hosts_for
    from panel.subscriptions.renderers import RENDERERS, resolve_artifacts

    app = client._transport.app
    service = app.state.subscriptions
    ctx = {"actor": {"id": 1, "username": "owner"}, "ip": "127.0.0.1", "request_id": None}
    subscription = service.get(client_id) or service.create(client_id, **ctx)[0]
    manifest = service.effective_manifest(subscription, int(app.state.clock.time()) if hasattr(app.state, "clock") else 0)
    with app.state.database.connect() as db:
        artifacts = resolve_artifacts(manifest, app.state.secrets, app.state.adapters, db,
                                      public_hosts=lambda node_id: public_hosts_for(app.state, node_id))
    return RENDERERS["raw"].render(manifest, artifacts).decode()
