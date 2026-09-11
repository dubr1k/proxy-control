from __future__ import annotations

import pytest

pytestmark = pytest.mark.anyio


async def _key(client, login_user, scope="admin"):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post("/api/keys", json={"name": "t", "scope": scope}, headers={"X-CSRF-Token": csrf})
    assert created.status_code == 201, created.text
    return created.json()


async def test_admin_key_reads_and_mutates_without_a_session(client, login_user):
    body = await _key(client, login_user, "admin")
    client.cookies.clear()
    headers = {"Authorization": f"Bearer {body['plaintext']}"}
    assert (await client.get("/api/auth/me", headers=headers)).json()["via"] == "api-key"
    created = await client.post("/api/clients", json={"display_name": "via key"}, headers=headers)
    assert created.status_code == 201
    audit = await client.get("/api/audit", headers=headers)
    assert any(row["actor_username"] == "key:t" for row in audit.json()["items"])


async def test_monitor_key_is_read_only(client, login_user):
    body = await _key(client, login_user, "monitor")
    client.cookies.clear()
    headers = {"Authorization": f"Bearer {body['plaintext']}"}
    assert (await client.get("/api/clients", headers=headers)).status_code == 200
    assert (await client.post("/api/clients", json={"display_name": "x"}, headers=headers)).status_code == 403


async def test_node_sync_key_reaches_only_the_fleet_api(client, login_user):
    body = await _key(client, login_user, "node-sync")
    client.cookies.clear()
    headers = {"Authorization": f"Bearer {body['plaintext']}"}
    assert (await client.get("/api/clients", headers=headers)).status_code == 403
    assert (await client.get("/api/fleet/v2/identity", headers=headers)).status_code == 200


async def test_bad_missing_or_disabled_key_is_401(client, login_user):
    body = await _key(client, login_user, "admin")
    csrf = client.cookies["panel_csrf"]
    assert (await client.post(f"/api/keys/{body['key']['id']}/enabled", json={"enabled": False},
                              headers={"X-CSRF-Token": csrf})).status_code == 200
    client.cookies.clear()
    assert (await client.get("/api/clients", headers={"Authorization": f"Bearer {body['plaintext']}"})).status_code == 401
    assert (await client.get("/api/clients", headers={"Authorization": "Bearer pc_nope_x"})).status_code == 401


async def test_key_management_is_owner_only_and_never_lists_plaintext(client, login_user):
    body = await _key(client, login_user, "admin")
    listed = await client.get("/api/keys")
    assert listed.status_code == 200 and "plaintext" not in listed.text and body["plaintext"] not in listed.text
    csrf = client.cookies["panel_csrf"]
    await client.post("/api/admins", json={"username": "adm", "password": "correct horse battery staple", "role": "admin"},
                      headers={"X-CSRF-Token": csrf})
    await client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    await login_user(client, "adm")
    assert (await client.post("/api/keys", json={"name": "n", "scope": "admin"},
                              headers={"X-CSRF-Token": client.cookies["panel_csrf"]})).status_code == 403


async def test_key_rate_limit_answers_429(client, login_user):
    body = await _key(client, login_user, "monitor")
    client.cookies.clear()
    headers = {"Authorization": f"Bearer {body['plaintext']}"}
    client._transport.app.state.key_rate.limit = 3
    codes = [(await client.get("/api/clients", headers=headers)).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
