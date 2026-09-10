"""Adopting what already runs: the panel reads the managers and writes only its own rows.

Import must never mutate a manager. An existing user keeps its password, its quota and
its enabled flag; the panel only records who it belongs to.
"""

from __future__ import annotations

import copy

import pytest

pytestmark = pytest.mark.anyio


async def _seed(client, login_user, telemt, naive, mieru):
    """Accounts that existed before the panel did.

    They are seeded straight into the managers on purpose: anything created through the
    panel's own API is already recorded under the domain writer, and would leave nothing
    to import. Import exists for what predates the panel.
    """
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    await telemt.create_user("alice")
    await naive.create("alice")
    await naive.create("bob")
    await mieru.create({"username": "alice", "quotas": [], "expected_revision": mieru.revision})
    return headers


async def test_inventory_proposes_same_username_only_as_a_hint(client, login_user, telemt, naive, mieru):
    await _seed(client, login_user, telemt, naive, mieru)
    inventory = await client.get("/api/clients/import/inventory")
    assert inventory.status_code == 200
    body = inventory.json()
    proposals = body["proposals"]
    alice = [item for item in proposals if item["display_name"] == "alice"]
    # One proposal per (protocol, username): a shared name is a hint, never a merge.
    assert len(alice) == 3 and all(item["same_username_hint"] for item in alice)
    assert {item["items"][0]["protocol"] for item in alice} == {"mtproxy", "naive", "mieru"}
    assert [item for item in proposals if item["display_name"] == "bob"][0]["same_username_hint"] is False
    assert body["already_imported"] == 0
    assert all(item["items"][0]["imported_grant_id"] is None for item in proposals)


async def test_import_is_idempotent_and_makes_no_manager_mutation(client, login_user, telemt, naive, mieru):
    headers = await _seed(client, login_user, telemt, naive, mieru)
    before = (copy.deepcopy(telemt.users), copy.deepcopy(naive.users), copy.deepcopy(mieru.users))
    decisions = [
        {"display_name": "Alice phone", "client_id": None, "items": [["mtproxy", "alice"], ["naive", "alice"]]},
        {"display_name": "Alice mieru", "client_id": None, "items": [["mieru", "alice"]]},
        {"display_name": "bob", "client_id": None, "items": [["naive", "bob"]]},
    ]
    first = await client.post("/api/clients/import", json={"decisions": decisions}, headers=headers)
    assert first.status_code == 200
    assert (first.json()["created_clients"], first.json()["created_grants"]) == (3, 4)
    second = await client.post("/api/clients/import", json={"decisions": decisions}, headers=headers)
    assert second.json()["created_grants"] == 0 and len(second.json()["skipped"]) == 4
    # The second run created no client either: every item was already adopted.
    assert second.json()["created_clients"] == 0
    assert (telemt.users, naive.users, mieru.users) == before
    listed = (await client.get("/api/clients")).json()["items"]
    assert {item["client"]["display_name"] for item in listed} == {"Alice phone", "Alice mieru", "bob"}
    grant = [g for item in listed for g in item["grants"] if g["protocol"] == "mieru"][0]
    assert grant["node_id"] == "local" and grant["origin"] == "imported" and grant["secret_ref"] is None
    inventory = (await client.get("/api/clients/import/inventory")).json()
    assert inventory["already_imported"] == 4


async def test_import_records_the_runtime_state_and_never_a_credential(client, login_user, telemt, naive, mieru):
    headers = await _seed(client, login_user, telemt, naive, mieru)
    await naive.set_enabled("bob", False)
    decisions = [{"display_name": "bob", "client_id": None, "items": [["naive", "bob"]]}]
    assert (await client.post("/api/clients/import", json={"decisions": decisions}, headers=headers)).status_code == 200
    grants = [g for item in (await client.get("/api/clients")).json()["items"] for g in item["grants"]]
    assert (grants[0]["desired_state"], grants[0]["observed_state"]) == ("disabled", "disabled")
    audit = (await client.get("/api/audit", params={"action": "client.import"})).json()["items"][0]
    assert audit["detail"]["created_grants"] == 1
    body = str(audit)
    assert naive.users["bob"]["password"] not in body and "password" not in body


async def test_import_can_attach_to_an_existing_client(client, login_user, telemt, naive, mieru):
    headers = await _seed(client, login_user, telemt, naive, mieru)
    created = await client.post("/api/clients", json={"display_name": "Sergey"}, headers=headers)
    assert created.status_code == 201
    client_id = created.json()["id"]
    decisions = [{"display_name": "ignored", "client_id": client_id, "items": [["naive", "bob"]]}]
    result = await client.post("/api/clients/import", json={"decisions": decisions}, headers=headers)
    assert (result.json()["created_clients"], result.json()["created_grants"]) == (0, 1)
    listed = (await client.get(f"/api/clients/{client_id}")).json()
    assert listed["client"]["display_name"] == "Sergey"
    assert [grant["runtime_username"] for grant in listed["grants"]] == ["bob"]


async def test_import_rejects_unknown_runtime_user_and_needs_admin(client, login_user, telemt, naive, mieru):
    headers = await _seed(client, login_user, telemt, naive, mieru)
    bad = await client.post(
        "/api/clients/import",
        json={"decisions": [{"display_name": "x", "client_id": None, "items": [["naive", "ghost"]]}]},
        headers=headers,
    )
    assert bad.status_code == 422
    # A refused decision leaves nothing behind: the whole import is one transaction.
    assert (await client.get("/api/clients")).json()["items"] == []
    app = client._transport.app
    app.state.store.create_admin("viewer", "viewer-password-123", "viewer")
    await login_user(client, "viewer", "viewer-password-123")
    assert (await client.get("/api/clients")).status_code == 200
    assert (await client.get("/api/clients/import/inventory")).status_code == 403
    denied = await client.post(
        "/api/clients", json={"display_name": "x"}, headers={"X-CSRF-Token": client.cookies["panel_csrf"]}
    )
    assert denied.status_code == 403


async def test_node_with_active_grants_cannot_be_disabled(client, login_user, telemt, naive, mieru):
    headers = await _seed(client, login_user, telemt, naive, mieru)
    await client.post("/api/nodes", json={"node_id": "edge-01", "display_name": "Edge"}, headers=headers)
    app = client._transport.app
    with app.state.database.transaction() as db:
        db.execute("INSERT INTO clients VALUES('c1','c','active','{}',1,1)")
        db.execute(
            """INSERT INTO access_grants(id,client_id,protocol,node_id,endpoint_id,runtime_username,
               desired_state,origin,created_at,updated_at)
               VALUES('g1','c1','naive','edge-01','default','remote-user','enabled','imported',1,1)"""
        )
    refused = await client.post("/api/nodes/edge-01/disable", headers=headers)
    assert refused.status_code == 409 and "grant" in refused.json()["detail"]
    with app.state.database.transaction() as db:
        db.execute("UPDATE access_grants SET desired_state='deleted' WHERE id='g1'")
    assert (await client.post("/api/nodes/edge-01/disable", headers=headers)).status_code == 200


async def test_adopting_an_imported_grant_makes_it_renderable(client, login_user, telemt, naive, mieru):
    headers = await _seed(client, login_user, telemt, naive, mieru)
    decisions = [
        {"display_name": "bob", "client_id": None, "items": [["naive", "bob"]]},
        {"display_name": "alice mieru", "client_id": None, "items": [["mieru", "alice"]]},
    ]
    await client.post("/api/clients/import", json={"decisions": decisions}, headers=headers)
    grants = {
        grant["protocol"]: grant
        for item in (await client.get("/api/clients")).json()["items"]
        for grant in item["grants"]
    }
    assert all(grant["secret_ref"] is None for grant in grants.values())

    # NaiveProxy can be read back, so adoption keeps the subscriber's link working.
    adopted = await client.post(
        f"/api/clients/grants/{grants['naive']['id']}/adopt",
        json={"allow_rotation": False}, headers=headers,
    )
    assert adopted.status_code == 200 and adopted.json()["adopted"] is True

    # Mieru cannot: without consent the panel refuses and the manager is untouched.
    revision = mieru.revision
    refused = await client.post(
        f"/api/clients/grants/{grants['mieru']['id']}/adopt",
        json={"allow_rotation": False}, headers=headers,
    )
    assert refused.status_code == 409 and "rotation" in refused.json()["detail"]
    assert mieru.revision == revision

    granted = await client.post(
        f"/api/clients/grants/{grants['mieru']['id']}/adopt",
        json={"allow_rotation": True}, headers=headers,
    )
    assert granted.status_code == 200 and mieru.revision != revision
    listed = {
        grant["protocol"]: grant
        for item in (await client.get("/api/clients")).json()["items"]
        for grant in item["grants"]
    }
    assert all(grant["secret_ref"] is not None for grant in listed.values())
    body = str(listed)
    assert "password" not in body and mieru.users["alice"].get("password") is None


async def test_adopt_batch_reports_what_it_could_not_take(client, login_user, telemt, naive, mieru):
    headers = await _seed(client, login_user, telemt, naive, mieru)
    decisions = [{"display_name": "alice mieru", "client_id": None, "items": [["mieru", "alice"]]}]
    await client.post("/api/clients/import", json={"decisions": decisions}, headers=headers)
    refused = await client.post(
        "/api/clients/grants/adopt-batch",
        json={"protocol": "mieru", "allow_rotation": False}, headers=headers,
    )
    assert refused.json()["adopted"] == [] and len(refused.json()["refused"]) == 1
    accepted = await client.post(
        "/api/clients/grants/adopt-batch",
        json={"protocol": "mieru", "allow_rotation": True}, headers=headers,
    )
    assert len(accepted.json()["adopted"]) == 1 and accepted.json()["refused"] == []


async def test_creating_several_grants_is_one_journalled_operation(client, login_user, telemt, naive, mieru):
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    created = await client.post("/api/clients", json={"display_name": "Sergey"}, headers=headers)
    client_id = created.json()["id"]
    request = {"grants": [
        {"protocol": "mtproxy", "runtime_username": "laptop", "options": {}},
        {"protocol": "naive", "runtime_username": "laptop", "options": {}},
    ]}
    started = await client.post(f"/api/clients/{client_id}/grants", json=request, headers=headers)
    assert started.status_code == 200 and started.json()["status"] == "succeeded"
    operation_id = started.json()["operation_id"]

    state = (await client.get(f"/api/operations/{operation_id}")).json()
    assert state["status"] == "succeeded"
    assert {step["protocol"] for step in state["steps"]} == {"mtproxy", "naive"}

    listed = (await client.get(f"/api/clients/{client_id}")).json()
    assert all(grant["secret_ref"] is not None for grant in listed["grants"])

    bundle = await client.post(f"/api/operations/{operation_id}/bundle", headers=headers)
    token = bundle.json()["reveal_token"]
    revealed = await client.get(f"/api/reveal/{token}")
    assert revealed.status_code == 200
    assert {item["protocol"] for item in revealed.json()["grants"]} == {"mtproxy", "naive"}
    # One-time: the same token cannot be replayed.
    assert (await client.get(f"/api/reveal/{token}")).status_code == 410


async def test_a_username_the_runtime_already_uses_is_refused_before_anything_is_written(
    client, login_user, telemt, naive, mieru
):
    headers = await _seed(client, login_user, telemt, naive, mieru)
    created = await client.post("/api/clients", json={"display_name": "Sergey"}, headers=headers)
    client_id = created.json()["id"]
    refused = await client.post(
        f"/api/clients/{client_id}/grants",
        json={"grants": [{"protocol": "naive", "runtime_username": "alice", "options": {}}]},
        headers=headers,
    )
    assert refused.status_code == 409 and "already" in refused.json()["detail"]
    assert (await client.get(f"/api/clients/{client_id}")).json()["grants"] == []
