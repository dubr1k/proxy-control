"""TrustTunnel cannot route individual client lanes, as enforced by the Rust HTTP API."""

import pytest

from panel.tests.harness.memories.amneziawg import MemoryAmneziawg
from panel.tests.harness.memories.trusttunnel import MemoryTrusttunnel

pytestmark = pytest.mark.anyio


@pytest.fixture
def tunnel_panel(panel_server, telemt):
    panel = panel_server(
        telemt=telemt, amneziawg=MemoryAmneziawg(), trusttunnel=MemoryTrusttunnel(),
        amneziawg_enabled=True, trusttunnel_enabled=True,
        amneziawg_public_host="vpn.example.com", trusttunnel_public_host="gate.example.com",
    )
    panel.create_admin("owner", "correct horse battery staple", "owner")
    return panel


async def test_trusttunnel_policy_refuses_a_client_lane(tunnel_panel, login_user):
    client = tunnel_panel.client
    await login_user(client)
    response = await client.put(
        "/api/routing/policies/local/trusttunnel?lane=grant:abc",
        json={}, headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
    )
    assert (response.status_code, response.json()["code"]) == (422, "lanes_unsupported")
    assert "TrustTunnel" in response.json()["detail"]


async def test_trusttunnel_grant_cannot_enable_a_lane(tunnel_panel, login_user):
    client = tunnel_panel.client
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    owner = await client.post("/api/clients", json={"display_name": "Alice"}, headers=headers)
    assert owner.status_code == 201, owner.text
    client_id = owner.json()["id"]
    issued = await client.post(f"/api/clients/{client_id}/grants", headers=headers, json={"grants": [
        {"protocol": "trusttunnel", "runtime_username": "alice-tt", "options": {"name": "Alice phone"}},
    ]})
    assert issued.status_code == 200 and issued.json()["status"] == "succeeded", issued.text
    grant_id = (await client.get(f"/api/clients/{client_id}")).json()["grants"][0]["id"]
    refused = await client.post(f"/api/routing/lanes/{grant_id}", json={"mode": "own"}, headers=headers)
    assert (refused.status_code, refused.json()["code"]) == (422, "lanes_unsupported")
