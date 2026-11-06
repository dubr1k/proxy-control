"""Public client identity, unlimited defaults and editable lifetime over real panel HTTP."""
from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.anyio


async def issue(client, login_user, protocols=("mtproxy", "naive", "mieru")):
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    made = await client.post("/api/clients", json={"display_name": "Клиент <Анна>"}, headers=headers)
    assert made.status_code == 201, made.text
    client_id = made.json()["id"]
    response = await client.post(f"/api/clients/{client_id}/grants", headers=headers, json={"grants": [
        {"protocol": protocol, "runtime_username": f"anna-{protocol}", "options": {}} for protocol in protocols
    ]})
    assert response.status_code == 200 and response.json()["status"] == "succeeded", response.text
    details = (await client.get(f"/api/clients/{client_id}")).json()
    return client_id, headers, details["grants"]


async def test_protocol_rows_show_public_client_holder_without_secret_material(server, client, login_user):
    client_id, _, grants = await issue(client, login_user)
    # Newer clients put the first holder beyond a small client-list page.
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    for n in range(105):
        other = await client.post("/api/clients", headers=headers,json={"display_name":f"Other {n}"})
        assert other.status_code == 201, other.text
    for protocol, path in [("mtproxy", "/api/users"), ("naive", "/api/naive/users"), ("mieru", "/api/mieru/users")]:
        response = await client.get(path)
        assert response.status_code == 200, response.text
        row = next(row for row in response.json()["items"] if row["username"] == f"anna-{protocol}")
        assert row["client_id"] == client_id
        assert row["client_name"] == "Клиент <Анна>"
        assert row["client_state"] == "active"
        assert row["grant_id"] == next(g["id"] for g in grants if g["protocol"] == protocol)
        assert not {"secret", "password", "secret_ref", "options", "links", "credential"}.intersection(row)


async def test_new_grants_default_unlimited_and_lifetime_can_be_set_and_cleared(client, login_user):
    _, headers, grants = await issue(client, login_user)
    for grant in grants:
        assert grant["valid_until"] is None
        options = grant["options"]
        if grant["protocol"] == "mtproxy":
            assert options["data_quota_bytes"] is None and options["expiration"] is None
        elif grant["protocol"] == "naive":
            assert options["quota_bytes"] is None
        else:
            assert not options["quotas"]
        path = f"/api/clients/grants/{grant['id']}/validity"
        until = int(time.time()) + 7 * 86400
        changed = await client.post(path, headers=headers, json={"valid_until": until})
        assert changed.status_code == 200, changed.text
        assert changed.json()["valid_until"] == until
        assert changed.json()["options"] == options
        expired = await client.post(path, headers=headers, json={"valid_until": 0})
        assert expired.status_code == 200, expired.text
        listing = {"mtproxy":"/api/users","naive":"/api/naive/users","mieru":"/api/mieru/users"}[grant["protocol"]]
        rows = (await client.get(listing)).json()["items"]
        assert not next(row for row in rows if row["username"] == grant["runtime_username"])["enabled"]
        cleared = await client.post(path, headers=headers, json={"valid_until": None})
        assert cleared.status_code == 200 and cleared.json()["valid_until"] is None, cleared.text
        invalid = await client.post(path, headers=headers, json={})
        assert invalid.status_code == 422


async def test_deleted_grant_cannot_change_lifetime(client, login_user):
    client_id, headers, grants = await issue(client, login_user, ("mtproxy",))
    deleted = await client.post(f"/api/clients/grants/{grants[0]['id']}/delete",headers=headers)
    assert deleted.status_code == 200, deleted.text
    response = await client.post(f"/api/clients/{client_id}/state",headers=headers,json={"state":"archived"})
    assert response.status_code == 200, response.text
    result = await client.post(f"/api/clients/grants/{grants[0]['id']}/validity",headers=headers,json={"valid_until":None})
    assert result.status_code == 404


async def test_viewer_cannot_change_lifetime(server, client, login_user):
    _, _, grants = await issue(client, login_user, ("mtproxy",))
    server.create_admin("observer", "correct horse battery staple", "viewer")
    await login_user(client, username="observer")
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    result = await client.post(f"/api/clients/grants/{grants[0]['id']}/validity",headers=headers,json={"valid_until":None})
    assert result.status_code == 403
