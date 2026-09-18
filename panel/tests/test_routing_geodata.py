"""Geodata through the panel (v0.8): this server's router over its adapter, a linked panel's
over the node's Fleet API; owner-only mutations, audited on both sides; the manager's
refusals as the operator's 422."""
from __future__ import annotations

import pytest

from panel.protocols import RouterAdapter
from panel.xray_router import MemoryXrayRouter

pytestmark = pytest.mark.anyio
ACTOR = {"id": 1, "username": "owner"}


def _csrf(client) -> dict:
    return {"X-CSRF-Token": client.cookies["panel_csrf"]}


@pytest.fixture
def router(client, naive, mieru):
    app = client._transport.app
    fake = MemoryXrayRouter()
    app.state.router = RouterAdapter(fake)
    app.state.routing.router = app.state.router
    naive.router_url, mieru.router_url = "socks5://127.0.0.1:45101", "socks5://127.0.0.1:45102"
    return fake


async def test_local_geodata_view_settings_update_restore_and_audit(client, login_user, router):
    await login_user(client)
    view = await client.get("/api/routing/geodata")
    assert view.status_code == 200 and view.json()["source"]["kind"] == "xray" and view.json()["files"]["geosite"]["codes"] == 3
    codes = await client.get("/api/routing/geodata/codes?node=local")
    assert codes.json()["codes"]["geosite"] == ["category-ads-all", "cn", "youtube"]
    # Nothing to fetch for the pinned pair.
    same = await client.post("/api/routing/geodata/update", headers=_csrf(client))
    assert same.status_code == 200 and same.json()["changed"] is False
    saved = await client.put("/api/routing/geodata/settings", headers=_csrf(client),
                             json={"source": {"kind": "loyalsoldier"}, "auto_update": True, "interval_hours": 12})
    assert saved.status_code == 200 and saved.json()["auto_update"] is True and saved.json()["interval_hours"] == 12
    updated = await client.post("/api/routing/geodata/update", headers=_csrf(client))
    assert updated.status_code == 200 and updated.json()["changed"] is True and updated.json()["version"] == "v1"
    restored = await client.post("/api/routing/geodata/restore", headers=_csrf(client))
    assert restored.json()["origin"] == "seed" and restored.json()["source"]["kind"] == "xray"
    actions = [row["action"] for row in client._transport.app.state.store.audits()]
    assert actions.count("routing.geodata.settings") == 1 and "routing.geodata.update" in actions and "routing.geodata.restore" in actions
    # A custom source needs https on both URLs (the manager's refusal is a 422 here).
    bad = await client.put("/api/routing/geodata/settings", headers=_csrf(client),
                           json={"source": {"kind": "custom", "geosite_url": "http://m/a.dat", "geoip_url": "https://m/b.dat"}})
    assert bad.status_code == 422 and bad.json()["code"] == "geodata_invalid"
    assert (await client.put("/api/routing/geodata/settings", headers=_csrf(client), json={"interval_hours": 0})).status_code == 422
    assert (await client.post("/api/routing/geodata/reboot", headers=_csrf(client))).status_code == 422


async def test_geodata_is_owner_only_to_change_and_needs_a_router(client, login_user, router):
    await login_user(client)
    app = client._transport.app
    app.state.store.create_admin("reader", "viewer correct horse battery", "viewer")
    await client.post("/api/auth/logout", headers=_csrf(client))
    client.cookies.clear()
    await login_user(client, "reader", "viewer correct horse battery")
    assert (await client.get("/api/routing/geodata")).status_code == 200
    assert (await client.post("/api/routing/geodata/update", headers=_csrf(client))).status_code == 403
    assert (await client.put("/api/routing/geodata/settings", headers=_csrf(client), json={"auto_update": True})).status_code == 403
    app.state.routing.router = None
    missing = await client.get("/api/routing/geodata")
    assert missing.status_code == 404 and missing.json()["code"] == "router_unavailable"
    assert (await client.get("/api/routing/geodata?node=nope")).status_code == 404


async def test_a_linked_panels_geodata_is_driven_through_its_fleet_api(pair, monkeypatch):
    node, central, plaintext = pair
    fake = MemoryXrayRouter()
    node.state.router = RouterAdapter(fake)
    node.state.routing.router = node.state.router
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False,
                                            actor=ACTOR, ip="x", auto_import=False)
    await central.state.pusher.tick()  # the heartbeat records the node's capabilities, geodata.v1 among them
    view = await central.state.routing.geodata(node_id, "view")
    assert view["source"]["kind"] == "xray"
    saved = await central.state.routing.geodata(node_id, "settings", {"source": {"kind": "loyalsoldier"}, "auto_update": True},
                                                actor=ACTOR, ip="x")
    assert saved["source"]["kind"] == "loyalsoldier"
    updated = await central.state.routing.geodata(node_id, "update", actor=ACTOR, ip="x")
    assert updated["changed"] is True and fake.calls[-1] == ("geodata_update",)
    codes = await central.state.routing.geodata(node_id, "codes")
    assert codes["codes"]["geoip"] == ["cn", "ru"]
    with central.state.database.connect() as db:
        rows = [row["action"] for row in db.execute("SELECT action FROM audit_log")]
    assert "routing.geodata.settings" in rows and "routing.geodata.update" in rows
    with node.state.database.connect() as db:
        node_rows = [row["action"] for row in db.execute("SELECT action FROM audit_log")]
    assert "fleet.geodata.settings" in node_rows and "fleet.geodata.update" in node_rows
    # The manager's refusal travels back with its code and the operator's status.
    fake.fail_next = "geodata_rejected"
    from panel.routing.service import RoutingError
    with pytest.raises(RoutingError) as refused:
        await central.state.routing.geodata(node_id, "update", actor=ACTOR, ip="x")
    assert refused.value.status == 422 and refused.value.code == "geodata_rejected"


async def test_node_geodata_and_exit_routes_answer_the_central_key(client, login_user, router):
    """The node side of v0.8 under the node-sync key: geodata view/codes/settings/actions and
    the exit probe — audited as `fleet.*`, refused without the key, 404 without a router."""
    await login_user(client)
    created = await client.post("/api/keys", json={"name": "central", "scope": "node-sync"},
                                headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
    client.cookies.clear()
    headers = {"Authorization": f"Bearer {created.json()['plaintext']}"}
    assert (await client.get("/api/fleet/v2/geodata")).status_code == 401
    view = await client.get("/api/fleet/v2/geodata", headers=headers)
    assert view.status_code == 200 and view.json()["source"]["kind"] == "xray"
    codes = await client.get("/api/fleet/v2/geodata/codes", headers=headers)
    assert codes.json()["codes"]["geoip"] == ["cn", "ru"]
    saved = await client.put("/api/fleet/v2/geodata/settings", headers=headers, json={"source": {"kind": "loyalsoldier"}, "auto_update": True})
    assert saved.status_code == 200 and saved.json()["auto_update"] is True
    assert (await client.put("/api/fleet/v2/geodata/settings", headers=headers, json={"nope": 1})).status_code == 422
    updated = await client.post("/api/fleet/v2/geodata/update", headers=headers)
    assert updated.status_code == 200 and updated.json()["changed"] is True
    assert (await client.post("/api/fleet/v2/geodata/reboot", headers=headers)).status_code == 422
    probe = await client.post("/api/fleet/v2/exits/test", headers=headers,
                              json={"exit": {"protocol": "socks", "address": "10.0.0.2", "port": 1080, "credential": {}}})
    assert probe.status_code == 200 and probe.json()["ok"] is True and probe.headers["cache-control"] == "no-store"
    bad = await client.post("/api/fleet/v2/exits/test", headers=headers, json={"exit": {"protocol": "wireguard"}})
    assert bad.status_code == 422 and bad.json()["code"] == "egress_invalid"
    actions = [row["action"] for row in client._transport.app.state.store.audits()]
    for action in ("fleet.geodata.settings", "fleet.geodata.update", "fleet.exit.test"):
        assert action in actions, action
    client._transport.app.state.router = None
    missing = await client.get("/api/fleet/v2/geodata", headers=headers)
    assert missing.status_code == 404 and missing.json()["code"] == "router_unavailable"
