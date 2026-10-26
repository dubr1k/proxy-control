"""Access transitions through real local and linked-panel HTTP listeners."""
import pytest

from panel.tests.test_fleet_v2_delivery import answer, converge
from panel.tests.test_grant_lifecycle import _grants, _mutation, _remote

pytestmark = pytest.mark.anyio


async def test_suspension_reaches_remote_runtime_and_resume_preserves_disabled_grant(pair):
    node, central, _, client_id, _, grant = await _remote(pair)
    await converge(node, central)
    await answer(central.client, "POST", f"/api/clients/{client_id}/state", {"state": "suspended"})
    await converge(node, central)
    assert (await node.naive.list_users())[0]["enabled"] is False
    await _mutation(central, grant["id"], "disable")
    await answer(central.client, "POST", f"/api/clients/{client_id}/state", {"state": "active"})
    await converge(node, central)
    assert (await node.naive.list_users())[0]["enabled"] is False
    assert (await _grants(central, client_id))[0]["observed_state"] == "disabled"


@pytest.mark.parametrize("protocol", ["mtproxy", "naive", "mieru"])
async def test_protocol_enable_cannot_bypass_a_suspended_known_grant(server, login_user, protocol):
    client = server.client
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    person = await client.post("/api/clients", json={"display_name": "A", "subscription": False}, headers=headers)
    assert person.status_code == 201, person.text
    client_id = person.json()["id"]
    started = await client.post(f"/api/clients/{client_id}/grants", headers=headers, json={"grants": [
        {"protocol": protocol, "runtime_username": "alice", "options": {}},
    ]})
    assert started.status_code == 200 and started.json()["status"] == "succeeded", started.text
    suspended = await client.post(f"/api/clients/{client_id}/state", headers=headers, json={"state": "suspended"})
    assert suspended.status_code == 200, suspended.text
    await server.tick("enforcer")
    path = {"mtproxy": "/api/users", "naive": "/api/naive/users", "mieru": "/api/mieru/users"}[protocol]
    body = {"expected_revision": server.mieru.revision} if protocol == "mieru" else {}
    response = await client.post(f"{path}/alice/enable", json=body, headers=headers)
    assert response.status_code == 200, response.text
    manager = {"mtproxy": server.telemt, "naive": server.naive, "mieru": server.mieru}[protocol]
    users = await manager.list_users()
    if isinstance(users, dict):
        users = users["users"]
    assert next(row for row in users if row["username"] == "alice")["enabled"] is False
