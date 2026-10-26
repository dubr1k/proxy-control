"""Names an operator gives: a client, one access in the subscription, and a node.

Only presentation changes — the account name, the endpoint and the credential stay as
they were, and the subscription URL does not move.
"""

import pytest


pytestmark = pytest.mark.anyio


async def _client_with_grant(client, login_user, name="A"):
    await login_user(client)
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    client_id = (await client.post("/api/clients", json={"display_name": name}, headers=csrf)).json()["id"]
    await client.post(f"/api/clients/{client_id}/grants", headers=csrf, json={
        "grants": [{"protocol": "naive", "node_id": "local", "runtime_username": "alice", "options": {}}]})
    grant = (await client.get(f"/api/clients/{client_id}")).json()["grants"][0]
    return client_id, grant["id"], csrf


async def test_a_client_is_renamed_and_the_rename_is_audited(client, login_user, naive):
    client_id, grant_id, csrf = await _client_with_grant(client, login_user)
    response = await client.post(f"/api/clients/{client_id}/rename", json={"display_name": "  Мама   Samsung "}, headers=csrf)
    assert response.status_code == 200 and response.json()["display_name"] == "Мама Samsung"
    shown = (await client.get(f"/api/clients/{client_id}")).json()
    assert shown["client"]["display_name"] == "Мама Samsung"
    assert shown["grants"][0]["runtime_username"] == "alice"  # the account is not renamed
    assert "client.rename" in {row["action"] for row in (await client.get("/api/audit")).json()["items"]}


async def test_renaming_a_client_refuses_blank_missing_and_needs_csrf(client, login_user, naive):
    client_id, grant_id, csrf = await _client_with_grant(client, login_user)
    assert (await client.post(f"/api/clients/{client_id}/rename", json={"display_name": "   "}, headers=csrf)).status_code == 422
    assert (await client.post(f"/api/clients/{client_id}/rename", json={"display_name": "x" * 129}, headers=csrf)).status_code == 422
    assert (await client.post("/api/clients/nope/rename", json={"display_name": "B"}, headers=csrf)).status_code == 404
    assert (await client.post(f"/api/clients/{client_id}/rename", json={"display_name": "B"})).status_code in (401, 403)


async def test_a_grant_label_is_set_shown_and_reset(client, login_user, naive):
    client_id, grant_id, csrf = await _client_with_grant(client, login_user)
    saved = await client.post(f"/api/clients/grants/{grant_id}/label", json={"label": " Дом  Naive "}, headers=csrf)
    assert saved.status_code == 200 and saved.json()["label"] == "Дом Naive"
    assert saved.json()["runtime_username"] == "alice"
    assert (await client.get(f"/api/clients/{client_id}")).json()["grants"][0]["label"] == "Дом Naive"
    reset = await client.post(f"/api/clients/grants/{grant_id}/label", json={"label": ""}, headers=csrf)
    assert reset.json()["label"] is None
    assert "grant.label" in {row["action"] for row in (await client.get("/api/audit")).json()["items"]}


async def test_a_grant_label_refuses_too_long_unknown_and_deleted(client, login_user, naive):
    client_id, grant_id, csrf = await _client_with_grant(client, login_user)
    assert (await client.post(f"/api/clients/grants/{grant_id}/label", json={"label": "x" * 65}, headers=csrf)).status_code == 422
    assert (await client.post("/api/clients/grants/nope/label", json={"label": "A"}, headers=csrf)).status_code == 404
    await client.post(f"/api/clients/grants/{grant_id}/delete", headers=csrf)
    assert (await client.post(f"/api/clients/grants/{grant_id}/label", json={"label": "A"}, headers=csrf)).status_code == 404

















