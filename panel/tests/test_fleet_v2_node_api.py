import pytest

from panel.fleet_v2.protocol import GenerationDocument, Resource

pytestmark = pytest.mark.anyio

MASTER = "m" * 36


async def _node_key(client, login_user):
    await login_user(client)
    created = await client.post("/api/keys", json={"name": "central", "scope": "node-sync"},
                                headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
    client.cookies.clear()
    return {"Authorization": f"Bearer {created.json()['plaintext']}"}


def _doc(guid, generation, users=("alice",), master=MASTER, state="enabled"):
    return GenerationDocument(node_guid=guid, master_guid=master, generation=generation,
                              previous_generation=generation - 1, created_at=1, created_by="c",
                              resources=[Resource(ref=f"grant:{u}", protocol="naive", runtime_username=u,
                                                  desired_state=state, credential_ref=f"grant:{u}:1",
                                                  credential_origin="caller") for u in users])


async def _push(client, headers, guid, generation, **kw):
    doc = _doc(guid, generation, **kw)
    return await client.put("/api/fleet/v2/generation", headers=headers, json={
        "expected_guid": guid, "generation": doc.model_dump(),
        "secrets": {r.credential_ref: f"pw-{r.runtime_username}" for r in doc.resources if r.desired_state != "deleted"}})


async def test_identity_status_and_inventory_are_secret_free(client, login_user, naive):
    headers = await _node_key(client, login_user)
    naive.seed("bob", "hunter2")
    identity = (await client.get("/api/fleet/v2/identity", headers=headers)).json()
    assert identity["api_version"] == 2 and identity["protocols"]["naive"]["public_host"] == "naive.example.com"
    status = await client.get("/api/fleet/v2/status", headers=headers)
    assert status.status_code == 200 and "versions" in status.json()
    inventory = (await client.get("/api/fleet/v2/inventory", headers=headers)).json()
    bob = next(r for r in inventory["protocols"]["naive"] if r["runtime_username"] == "bob")
    assert bob["ownership"] == "local" and "hunter2" not in inventory.__repr__()


async def test_push_applies_and_answers_with_observed(client, login_user, naive):
    headers = await _node_key(client, login_user)
    guid = (await client.get("/api/fleet/v2/identity", headers=headers)).json()["guid"]
    response = await _push(client, headers, guid, 1)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["observed"]["applied_generation"] == 1 and body["observed"]["reconcile_state"] == "converged"
    assert response.headers["cache-control"] == "no-store"
    assert "alice" in [u["username"] for u in await naive.list_users()]
    observed = await client.get("/api/fleet/v2/observed", headers=headers)
    assert observed.json()["applied_generation"] == 1
    assert (await client.get("/api/fleet/v2/identity", headers=headers)).json()["master_guid"] == MASTER


async def test_push_conflicts_are_409_with_a_code(client, login_user):
    headers = await _node_key(client, login_user)
    guid = (await client.get("/api/fleet/v2/identity", headers=headers)).json()["guid"]
    assert (await _push(client, headers, guid, 2)).status_code == 200
    assert (await _push(client, headers, guid, 1)).json()["code"] == "stale_generation"
    assert (await _push(client, headers, guid, 2, users=("zed",))).json()["code"] == "digest_conflict"
    assert (await _push(client, headers, guid, 3, master="o" * 36)).json()["code"] == "foreign_master"
    assert (await _push(client, headers, "x" * 36, 3)).json()["code"] == "guid_mismatch"


async def test_central_owned_users_refuse_local_mutation_and_leave_local_inventory(client, login_user):
    headers = await _node_key(client, login_user)
    guid = (await client.get("/api/fleet/v2/identity", headers=headers)).json()["guid"]
    await _push(client, headers, guid, 1)
    await login_user(client)
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    blocked = await client.delete("/api/naive/users/alice", headers=csrf)
    assert blocked.status_code == 409 and blocked.headers["x-reason"] == "managed_by_central"
    inventory = await client.get("/api/clients/import/inventory")
    assert "alice" not in inventory.text


async def test_every_local_writer_refuses_a_central_resource(client, login_user, naive):
    """Route gate, façade gate and provisioning preflight all answer the same way."""
    headers = await _node_key(client, login_user)
    guid = (await client.get("/api/fleet/v2/identity", headers=headers)).json()["guid"]
    await _push(client, headers, guid, 1)
    await login_user(client)
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    for path in ("/api/naive/users/alice/quota", "/api/naive/users/alice/disable", "/api/naive/users/alice/rotate"):
        blocked = await client.post(path, headers=csrf, json={"quota_bytes": 1})
        assert blocked.status_code == 409 and blocked.headers["x-reason"] == "managed_by_central", path
    recreated = await client.post("/api/naive/users", headers=csrf, json={"username": "alice"})
    assert recreated.status_code == 409 and recreated.headers["x-reason"] == "managed_by_central"
    owner = (await client.post("/api/clients", headers=csrf, json={"display_name": "Alice"})).json()
    granted = await client.post(f"/api/clients/{owner['id']}/grants", headers=csrf,
                                json={"grants": [{"protocol": "naive", "runtime_username": "alice"}]})
    assert granted.status_code == 409 and "managed by central" in granted.text
    # Nothing above touched the runtime: alice still carries the pushed credential.
    assert naive.users["alice"]["password"] == "pw-alice"


async def test_owner_unlinks_from_the_ui_but_a_node_key_may_not_use_that_route(client, login_user):
    headers = await _node_key(client, login_user)
    guid = (await client.get("/api/fleet/v2/identity", headers=headers)).json()["guid"]
    await _push(client, headers, guid, 1)
    assert (await client.post("/api/nodes/local/unlink", headers=headers)).status_code == 403
    await login_user(client)
    released = await client.post("/api/nodes/local/unlink", headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
    assert released.status_code == 200 and released.json()["released"] == 1
    client.cookies.clear()
    assert (await client.get("/api/fleet/v2/identity", headers=headers)).json()["master_guid"] is None
    inventory = (await client.get("/api/fleet/v2/inventory", headers=headers)).json()
    assert next(r for r in inventory["protocols"]["naive"] if r["runtime_username"] == "alice")["ownership"] == "local"


async def test_capture_unlink_and_versions_update(client, login_user, naive):
    headers = await _node_key(client, login_user)
    naive.seed("bob", "hunter2")
    captured = await client.post("/api/fleet/v2/credentials/capture", headers=headers,
                                 json={"resources": [{"protocol": "naive", "runtime_username": "bob"}]})
    assert captured.json()["credentials"]["naive:bob"] == "hunter2"
    guid = (await client.get("/api/fleet/v2/identity", headers=headers)).json()["guid"]
    await _push(client, headers, guid, 1)
    released = await client.post("/api/fleet/v2/unlink", headers=headers)
    assert released.json()["released"] == 1
    assert (await client.get("/api/fleet/v2/identity", headers=headers)).json()["master_guid"] is None
    assert "alice" in [u["username"] for u in await naive.list_users()]
    update = await client.post("/api/fleet/v2/versions/update", headers=headers,
                               json={"component": "telemt", "version": "1.0", "expected_current": None})
    assert update.status_code in (502, 503)  # no version agent in tests, but the route exists
