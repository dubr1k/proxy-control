"""Characterization of the boundaries vNext v0.2 must not break.

These tests describe today's behaviour, not a wish list: Fleet v1 stays a
Telemt-only, secret-free command queue, the three protocol managers keep
independent accounts for the same username, and only MTProxy and Naive can hand
back an existing credential — mita keeps a hash, so Mieru has no access route at
all. Any change to these facts is a deliberate decision, not a refactor.
"""

from __future__ import annotations

import re

import pytest

from panel.fleet import OPERATIONS, ProtocolError, validate_payload, validate_result

pytestmark = pytest.mark.anyio


async def _csrf(client, login_user):
    await login_user(client)
    return client.cookies["panel_csrf"]


def test_fleet_v1_allowlist_is_exactly_the_five_telemt_operations():
    assert OPERATIONS == {
        "telemt.inventory.refresh",
        "telemt.user.enable",
        "telemt.user.disable",
        "telemt.user.update_limits",
        "telemt.user.reset_quota",
    }


@pytest.mark.parametrize("payload", [
    {"username": "alice", "token": "x"},
    {"username": "alice", "proxy_url": "tg://proxy"},
    {"username": "alice", "nested": {"api_token": "x"}},
])
def test_fleet_v1_rejects_secret_bearing_payload(payload):
    with pytest.raises(ProtocolError):
        validate_payload("telemt.user.update_limits", payload)


def test_fleet_v1_rejects_secret_bearing_result():
    with pytest.raises(ProtocolError, match="secret-bearing"):
        validate_result({"message": "ok", "link": "tg://proxy?secret=00"}, "telemt.user.enable", "succeeded")


async def test_same_username_in_three_managers_is_three_independent_accounts(client, login_user, telemt, naive, mieru):
    csrf = await _csrf(client, login_user)
    headers = {"X-CSRF-Token": csrf}
    assert (await client.post("/api/users", json={"username": "alice"}, headers=headers)).status_code == 201
    assert (await client.post("/api/naive/users", json={"username": "alice"}, headers=headers)).status_code == 201
    created = await client.post(
        "/api/mieru/users",
        json={"username": "alice", "quotas": [], "expected_revision": mieru.revision},
        headers=headers,
    )
    assert created.status_code == 201
    assert (await client.post("/api/naive/users/alice/disable", headers=headers)).status_code == 200
    assert telemt.users["alice"]["enabled"] is True
    assert naive.users["alice"]["enabled"] is False
    # MemoryMieru keeps a `users` dict keyed by username; there is no `config`.
    assert "alice" in mieru.users


async def test_mtproxy_and_naive_access_are_re_revealable_but_mieru_is_not(client, login_user, mieru):
    csrf = await _csrf(client, login_user)
    headers = {"X-CSRF-Token": csrf}
    await client.post("/api/users", json={"username": "phone"}, headers=headers)
    await client.post("/api/naive/users", json={"username": "phone"}, headers=headers)
    await client.post(
        "/api/mieru/users",
        json={"username": "phone", "quotas": [], "expected_revision": mieru.revision},
        headers=headers,
    )
    mtproxy = await client.post("/api/users/phone/access", headers=headers)
    assert mtproxy.status_code == 200 and mtproxy.json()["link"].startswith("tg://proxy")
    # Naive returns the reveal payload itself, not a reveal token: the password
    # lives in the manager state and can be read back at any time.
    naive_access = await client.post("/api/naive/users/phone/access", headers=headers)
    assert naive_access.status_code == 200
    body = naive_access.json()
    assert "reveal_token" not in body
    assert body["clients"]["nekobox"]["share_url"].startswith("naive+https://")
    # Mieru keeps only hashedPassword: there is no re-reveal route at all.
    mieru_access = await client.post("/api/mieru/users/phone/access", headers=headers)
    assert mieru_access.status_code in {404, 405, 422}


async def test_one_time_reveal_is_consumed_once_and_lives_only_in_memory(client, login_user):
    csrf = await _csrf(client, login_user)
    created = await client.post("/api/naive/users", json={"username": "laptop"}, headers={"X-CSRF-Token": csrf})
    token = created.json()["reveal_token"]
    assert (await client.get(f"/api/reveal/{token}")).status_code == 200
    assert (await client.get(f"/api/reveal/{token}")).status_code == 410
    schema = " ".join(client._transport.app.state.store.dump_schema()).lower()
    # One-time reveals stay in process memory: no table is named after them.
    assert "reveal" not in schema
    # Task 6 deliberately added `secret_versions`; it is the only place the schema
    # mentions secrets, and it holds ciphertext under a key kept outside the database.
    assert set(re.findall(r"secret\w*", schema)) <= {
        "secret_versions", "secret_versions_key", "secret_versions_grant",
        # access_grants points at a secret version; the value itself stays ciphertext.
        "secret_id", "secret_version",
    }
    assert "ciphertext" in schema and "nonce" in schema
