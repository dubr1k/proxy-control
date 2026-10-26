"""Grant transitions through real central/node HTTP and persisted state."""
import json

import pytest

from panel.tests.test_fleet_v2_delivery import answer, converge, linked

pytestmark = pytest.mark.anyio


async def _grant(client, login_user, node_id="local"):
    await login_user(client)
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    created = await client.post("/api/clients", json={"display_name": "A"}, headers=csrf)
    client_id = created.json()["id"]
    await client.post(f"/api/clients/{client_id}/grants", headers=csrf,
                      json={"grants": [{"protocol": "naive", "node_id": node_id, "runtime_username": "alice", "options": {}}]})
    listing = (await client.get(f"/api/clients/{client_id}")).json()
    return listing["grants"][0]["id"], csrf


async def test_local_grant_lifecycle_reaches_the_manager_and_is_audited(client, login_user, naive):
    grant_id, csrf = await _grant(client, login_user)
    assert (await client.post(f"/api/clients/grants/{grant_id}/disable", headers=csrf)).status_code == 200
    assert {u["username"]: u["enabled"] for u in await naive.list_users()}["alice"] is False
    before = (await naive.reveal("alice"))["proxy_url"]
    assert (await client.post(f"/api/clients/grants/{grant_id}/rotate", headers=csrf)).status_code == 200
    assert (await naive.reveal("alice"))["proxy_url"] != before
    assert (await client.post(f"/api/clients/grants/{grant_id}/delete", headers=csrf)).status_code == 200
    assert "alice" not in [u["username"] for u in await naive.list_users()]
    audit = (await client.get("/api/audit")).json()["items"]
    assert {"grant.disable", "grant.rotate", "grant.delete"} <= {row["action"] for row in audit}


async def test_local_delete_purges_the_row_at_once_and_frees_the_name(client, server, login_user, naive):
    grant_id, csrf = await _grant(client, login_user)
    assert (await client.post(f"/api/clients/grants/{grant_id}/delete", headers=csrf)).status_code == 200
    with server.db() as db:
        assert db.execute("SELECT count(*) FROM access_grants WHERE id=?", (grant_id,)).fetchone()[0] == 0
        states = [row["state"] for row in db.execute("SELECT state FROM secret_versions WHERE secret_id=?", (f"grant:{grant_id}",))]
    assert states == ["revoked"]
    client_id = (await client.get("/api/clients")).json()["items"][0]["client"]["id"]
    again = await client.post(f"/api/clients/{client_id}/grants", headers=csrf,
                              json={"grants": [{"protocol": "naive", "runtime_username": "alice", "options": {}}]})
    assert again.status_code == 200 and again.json()["status"] == "succeeded"
    listing = (await client.get(f"/api/clients/{client_id}")).json()["grants"]
    assert [g["runtime_username"] for g in listing] == ["alice"] and listing[0]["id"] != grant_id
    assert {u["username"]: u["enabled"] for u in await naive.list_users()}["alice"] is True


async def test_local_enable_route_reaches_the_manager_and_rotation_keeps_a_disabled_grant_disabled(client, server, login_user, naive):
    grant_id, csrf = await _grant(client, login_user)
    assert (await client.post(f"/api/clients/grants/{grant_id}/disable", headers=csrf)).status_code == 200
    rotated = await client.post(f"/api/clients/grants/{grant_id}/rotate", headers=csrf)
    assert rotated.status_code == 200 and rotated.json()["desired_state"] == "disabled"
    assert {u["username"]: u["enabled"] for u in await naive.list_users()}["alice"] is False
    enabled = await client.post(f"/api/clients/grants/{grant_id}/enable", headers=csrf)
    assert enabled.status_code == 200 and enabled.json()["desired_state"] == "enabled"
    assert {u["username"]: u["enabled"] for u in await naive.list_users()}["alice"] is True
    assert rotated.json()["secret_ref"]["version"] == 2 and enabled.json()["secret_ref"]["version"] == 2
    # The runtime already runs the new credential: exactly one live version remains.
    with server.db() as db:
        rows = db.execute("SELECT version, state FROM secret_versions WHERE secret_id=? ORDER BY version",
                          (f"grant:{grant_id}",)).fetchall()
    assert [tuple(row) for row in rows] == [(1, "revoked"), (2, "active")]
    assert "grant.enable" in {row["action"] for row in (await client.get("/api/audit")).json()["items"]}


async def test_grant_routes_map_errors_and_check_csrf(client, login_user, naive):
    grant_id, csrf = await _grant(client, login_user)
    assert (await client.post("/api/clients/grants/no-such-grant/enable", headers=csrf)).status_code == 404
    assert (await client.post(f"/api/clients/grants/{grant_id}/freeze", headers=csrf)).status_code == 422
    assert (await client.post(f"/api/clients/grants/{grant_id}/disable")).status_code == 403  # no CSRF token
    assert (await client.post(f"/api/clients/grants/{grant_id}/delete", headers=csrf)).status_code == 200
    assert (await client.post(f"/api/clients/grants/{grant_id}/delete", headers=csrf)).status_code == 404  # purged
    assert "alice" not in [u["username"] for u in await naive.list_users()]


async def test_a_grant_on_a_node_this_panel_cannot_write_is_refused_before_anything_is_written(client, login_user, naive):
    await login_user(client)
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    client_id = (await client.post("/api/clients", json={"display_name": "A"}, headers=csrf)).json()["id"]
    refused = await client.post(f"/api/clients/{client_id}/grants", headers=csrf,
                                json={"grants": [{"protocol": "naive", "node_id": "nowhere", "runtime_username": "alice", "options": {}}]})
    assert refused.status_code == 409 and "nowhere" in refused.json()["detail"]
    assert (await client.get(f"/api/clients/{client_id}")).json()["grants"] == []
    assert "alice" not in [u["username"] for u in await naive.list_users()]


async def _start(central, client_id, node_id, *names, protocol="naive", **window):
    return await answer(central.client, "POST", f"/api/clients/{client_id}/grants", {"grants": [
        {"protocol": protocol, "node_id": node_id, "runtime_username": name, "options": {}, **window}
        for name in names
    ]})


async def _grants(central, client_id):
    return (await answer(central.client, "GET", f"/api/clients/{client_id}"))["grants"]


async def _remote(pair, protocol="naive", **window):
    node, central, node_id = await linked(pair)
    client = await answer(central.client, "POST", "/api/clients", {"display_name": "A", "subscription": False}, 201)
    operation = await _start(central, client["id"], node_id, "alice", protocol=protocol, **window)
    [grant] = await _grants(central, client["id"])
    return node, central, node_id, client["id"], operation["operation_id"], grant


def _secret_states(central, grant_id):
    with central.db() as db:
        return [tuple(row) for row in db.execute(
            "SELECT version,state FROM secret_versions WHERE secret_id=? ORDER BY version", (f"grant:{grant_id}",))]


def _generation(central, node_id):
    with central.db() as db:
        row = dict(db.execute(
            "SELECT * FROM desired_generations WHERE node_id=? ORDER BY generation DESC LIMIT 1", (node_id,)).fetchone())
    row["document"] = json.loads(row["document_json"])
    return row


async def _mutation(central, grant_id, action):
    return await answer(central.client, "POST", f"/api/clients/grants/{grant_id}/{action}")


async def _status(central, operation):
    return await answer(central.client, "GET", f"/api/operations/{operation}")


async def test_remote_grant_lifecycle_only_records_desired_state(pair):
    node, central, node_id, _, _, grant = await _remote(pair)
    rotated = await _mutation(central, grant["id"], "rotate")
    assert rotated["secret_ref"]["version"] == 2 and rotated["observed_state"] == "pending"
    assert _secret_states(central, grant["id"]) == [(1, "retiring"), (2, "pending")]
    assert _generation(central, node_id)["generation"] == 2
    assert await node.naive.list_users() == []


async def test_is_remote_tells_a_linked_panel_from_the_local_node(pair):
    node, central, node_id, client_id, _, grant = await _remote(pair)
    local = await _start(central, client_id, "local", "bob")
    assert local["status"] == "succeeded"
    assert [user["username"] for user in await central.naive.list_users()] == ["bob"]
    assert await node.naive.list_users() == []
    await converge(node, central)
    assert [user["username"] for user in await node.naive.list_users()] == ["alice"]
    assert grant["node_id"] == node_id


async def test_remote_disable_and_enable_change_only_what_the_central_wants(pair):
    node, central, node_id, client_id, _, grant = await _remote(pair)
    await converge(node, central)
    for action, desired, generation in [("disable", "disabled", 2), ("enable", "enabled", 3)]:
        changed = await _mutation(central, grant["id"], action)
        assert (changed["desired_state"], changed["observed_state"]) == (desired, "pending")
        latest = _generation(central, node_id)
        assert latest["generation"] == generation
        assert [r["desired_state"] for r in latest["document"]["resources"]] == [desired]
        assert (await node.naive.list_users())[0]["enabled"] is (action == "disable")
        await converge(node, central)
        assert (await node.naive.list_users())[0]["enabled"] is (action == "enable")
        assert (await _grants(central, client_id))[0]["observed_state"] == desired
    actions = [row["action"] for row in reversed(central.audits())]
    assert [action for action in actions if action in ("grant.disable", "grant.enable")] == ["grant.disable", "grant.enable"]
    assert await central.naive.list_users() == []


async def test_remote_rotation_is_confirmed_by_the_node_and_retires_the_old_version(pair):
    node, central, node_id, client_id, _, grant = await _remote(pair)
    await converge(node, central)
    before = (await node.naive.reveal("alice"))["proxy_url"]
    assert _secret_states(central, grant["id"]) == [(1, "active")]
    rotated = await _mutation(central, grant["id"], "rotate")
    assert rotated["secret_ref"]["version"] == 2 and rotated["observed_state"] == "pending"
    assert _secret_states(central, grant["id"]) == [(1, "retiring"), (2, "pending")]
    assert [r["credential_ref"] for r in _generation(central, node_id)["document"]["resources"]] == [f"grant:{grant['id']}:2"]
    await converge(node, central)
    assert (await node.naive.reveal("alice"))["proxy_url"] != before
    assert _secret_states(central, grant["id"]) == [(1, "revoked"), (2, "active")]
    current = (await _grants(central, client_id))[0]
    assert current["secret_ref"]["version"] == 2 and current["observed_state"] == "enabled"
    assert central.audits(action="grant.rotate")


async def test_remote_mtproxy_rotation_escrows_a_telemt_shaped_secret(pair):
    node, central, _, _, _, grant = await _remote(pair, protocol="mtproxy")
    await _mutation(central, grant["id"], "rotate")
    await converge(node, central)
    secret = node.telemt.users["alice"]["secret"]
    assert len(secret) == 32 and int(secret, 16) >= 0
    assert await central.telemt.list_users() == []
    assert _secret_states(central, grant["id"]) == [(1, "revoked"), (2, "active")]


async def test_remote_delete_is_declared_and_the_node_confirms_it_gone(pair):
    node, central, node_id, client_id, operation, grant = await _remote(pair)
    await converge(node, central)
    await _mutation(central, grant["id"], "delete")
    assert await _grants(central, client_id) == []
    with central.db() as db:
        row = db.execute("SELECT desired_state,observed_state FROM access_grants WHERE id=?", (grant["id"],)).fetchone()
    assert tuple(row) == ("deleted", "pending")
    assert _generation(central, node_id)["document"]["resources"][0]["desired_state"] == "deleted"
    assert [user["username"] for user in await node.naive.list_users()] == ["alice"]
    await converge(node, central)
    assert await node.naive.list_users() == []
    with central.db() as db:
        assert db.execute("SELECT 1 FROM access_grants WHERE id=?", (grant["id"],)).fetchone() is None
    assert _secret_states(central, grant["id"]) == [(1, "revoked")]
    assert (await _status(central, operation))["status"] == "succeeded"
    assert central.audits(action="grant.delete")
    again = await _start(central, client_id, node_id, "alice")
    await converge(node, central)
    assert (await _status(central, again["operation_id"]))["status"] == "succeeded"
    assert (await _grants(central, client_id))[0]["id"] != grant["id"]


async def test_deleting_a_remote_grant_the_node_never_applied_settles_its_operation(pair):
    node, central, _, _, operation, grant = await _remote(pair)
    assert (await _status(central, operation))["status"] == "pending_remote"
    await _mutation(central, grant["id"], "delete")
    status = await _status(central, operation)
    assert status["status"] == status["steps"][0]["status"] == "compensated"
    assert "deleted" in status["steps"][0]["error"]
    await converge(node, central)
    assert await node.naive.list_users() == []
    assert (await _status(central, operation))["status"] == "compensated"
    assert _secret_states(central, grant["id"]) == [(1, "revoked")]
    with central.db() as db:
        assert db.execute("SELECT 1 FROM access_grants WHERE id=?", (grant["id"],)).fetchone() is None


async def test_deleting_one_grant_of_a_pending_operation_leaves_the_other_step_waiting(pair):
    node, central, node_id, client_id, operation, alice = await _remote(pair)
    other = await _start(central, client_id, node_id, "bob")
    await _mutation(central, alice["id"], "delete")
    assert (await _status(central, operation))["status"] == "compensated"
    assert (await _status(central, other["operation_id"]))["status"] == "pending_remote"
    await converge(node, central)
    assert (await _status(central, other["operation_id"]))["status"] == "succeeded"
    assert [user["username"] for user in await node.naive.list_users()] == ["bob"]


async def test_disabling_a_remote_grant_before_the_node_applied_it_still_finishes_the_operation(pair):
    node, central, _, client_id, operation, grant = await _remote(pair)
    await _mutation(central, grant["id"], "disable")
    assert (await _status(central, operation))["status"] == "pending_remote"
    await converge(node, central)
    assert (await node.naive.list_users())[0]["enabled"] is False
    assert (await _status(central, operation))["status"] == "succeeded"
    assert _secret_states(central, grant["id"]) == [(1, "active")]
    assert (await _grants(central, client_id))[0]["observed_state"] == "disabled"


async def test_enabling_a_remote_grant_twice_is_a_no_op(pair):
    node, central, node_id, client_id, _, grant = await _remote(pair)
    await converge(node, central)
    before = await _grants(central, client_id)
    await _mutation(central, grant["id"], "enable")
    assert await _grants(central, client_id) == before
    assert _generation(central, node_id)["generation"] == 1
    assert central.audits(action="grant.enable") == []
    await _mutation(central, grant["id"], "disable")
    await converge(node, central)
    await _mutation(central, grant["id"], "disable")
    assert (await _grants(central, client_id))[0]["observed_state"] == "disabled"
    assert _generation(central, node_id)["generation"] == 2
    assert len(central.audits(action="grant.disable")) == 1


async def test_bundle_never_renders_a_withdrawn_or_deleted_grant(pair):
    node, central, node_id, client_id, operation, alice = await _remote(pair)
    await _start(central, client_id, node_id, "bob")
    await converge(node, central)

    async def rendered(operation_id=operation):
        created = await answer(central.client, "POST", f"/api/operations/{operation_id}/bundle")
        bundle = await answer(central.client, "GET", f"/api/reveal/{created['reveal_token']}")
        return [g["runtime_username"] for g in bundle["grants"]]

    assert await rendered() == ["alice"]
    await _mutation(central, alice["id"], "delete")
    assert await rendered() == []
    await converge(node, central)
    assert await rendered() == []
    pair_op = await _start(central, client_id, node_id, "carol", "dave")
    grants = {g["runtime_username"]: g for g in await _grants(central, client_id)}
    await _mutation(central, grants["carol"]["id"], "delete")
    await converge(node, central)
    status = await _status(central, pair_op["operation_id"])
    assert status["status"] == "succeeded" and {step["status"] for step in status["steps"]} == {"compensated", "active"}
    assert await rendered(pair_op["operation_id"]) == ["dave"]
    assert sorted(user["username"] for user in await node.naive.list_users()) == ["bob", "dave"]


async def test_a_deleted_or_unknown_grant_is_refused(pair):
    _, central, node_id, _, _, grant = await _remote(pair)
    await answer(central.client, "POST", "/api/clients/grants/no-such-grant/enable", status=404)
    await _mutation(central, grant["id"], "delete")
    for action in ("enable", "rotate", "delete"):
        await answer(central.client, "POST", f"/api/clients/grants/{grant['id']}/{action}", status=409)
    assert _generation(central, node_id)["generation"] == 2
