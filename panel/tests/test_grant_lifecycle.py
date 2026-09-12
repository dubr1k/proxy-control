"""Enable, disable, rotate and delete one grant — on this panel's runtime or on a linked panel.

A local grant reaches the manager first and the `DomainFacade` second, as the protocol
routes do. A remote grant only changes what the central wants — the row, a secret
version, the generation compiled from them — and the node's report is what moves
`observed_state`; nothing is pushed from the lifecycle itself.
"""
import pytest

from panel.clients.models import GrantIntent, MtproxyOptions, NaiveOptions
from panel.clients.store import ClientConflict

pytestmark = pytest.mark.anyio

ACTOR = {"id": 1, "username": "owner"}  # фикстура `pair` приходит из panel/tests/conftest.py


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


async def test_remote_grant_lifecycle_only_records_desired_state(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    from panel.clients.models import GrantIntent, NaiveOptions
    await central.state.provisioning.start(client.id, [GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())], actor=ACTOR, ip="x")
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    updated = await central.state.lifecycle.rotate(grant.id, actor=ACTOR, ip="x")
    assert updated.secret_ref.version == 2 and updated.observed_state == "pending"
    with central.state.database.connect() as db:
        states = [r["state"] for r in db.execute("SELECT state FROM secret_versions WHERE secret_id=? ORDER BY version", (f"grant:{grant.id}",))]
        assert states == ["retiring", "pending"]
        assert central.state.desired.latest(db, node_id)["generation"] == 2
    assert "alice" not in [u["username"] for u in await node.state.naive.list_users()]  # nothing pushed yet


# --- additional coverage beyond the brief's Step 1 tests ---

async def _remote(pair, protocol="naive"):
    """A linked node, one client and one grant on that node (operation `pending_remote`)."""
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    options = NaiveOptions() if protocol == "naive" else MtproxyOptions()
    intent = GrantIntent(protocol=protocol, node_id=node_id, runtime_username="alice", options=options)
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    return node, central, node_id, client, operation, grant


def _secret_states(central, grant_id) -> list[tuple[int, str]]:
    with central.state.database.connect() as db:
        rows = db.execute("SELECT version, state FROM secret_versions WHERE secret_id=? ORDER BY version",
                          (f"grant:{grant_id}",)).fetchall()
    return [tuple(row) for row in rows]


def _generation(central, node_id) -> dict:
    with central.state.database.connect() as db:
        return central.state.desired.latest(db, node_id)


def _actions(central) -> list[str]:
    with central.state.database.connect() as db:
        return [row["action"] for row in db.execute("SELECT action FROM audit_log ORDER BY id")]


async def _node_users(node) -> dict:
    return {u["username"]: u for u in await node.state.naive.list_users()}


async def test_is_remote_tells_a_linked_panel_from_the_local_node(pair):
    node, central, node_id, client, operation, remote = await _remote(pair)
    local = GrantIntent(protocol="naive", node_id="local", runtime_username="bob", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [local], actor=ACTOR, ip="x")
    grants = {g.runtime_username: g for g in central.state.clients.client_with_grants(client.id)[1]}
    with central.state.database.connect() as db:
        assert central.state.lifecycle.is_remote(db, grants["alice"]) is True
        assert central.state.lifecycle.is_remote(db, grants["bob"]) is False


async def test_remote_disable_and_enable_change_only_what_the_central_wants(pair):
    node, central, node_id, client, operation, grant = await _remote(pair)
    await central.state.pusher.tick()
    assert (await _node_users(node))["alice"]["enabled"] is True
    disabled = await central.state.lifecycle.set_enabled(grant.id, False, actor=ACTOR, ip="x")
    assert (disabled.desired_state, disabled.observed_state) == ("disabled", "pending")
    latest = _generation(central, node_id)
    assert latest["generation"] == 2 and [r.desired_state for r in latest["document"].resources] == ["disabled"]
    assert (await _node_users(node))["alice"]["enabled"] is True  # nothing pushed by the lifecycle
    await central.state.pusher.tick()
    assert (await _node_users(node))["alice"]["enabled"] is False
    assert central.state.clients.client_with_grants(client.id)[1][0].observed_state == "disabled"
    enabled = await central.state.lifecycle.set_enabled(grant.id, True, actor=ACTOR, ip="x")
    assert (enabled.desired_state, enabled.observed_state) == ("enabled", "pending")
    assert _generation(central, node_id)["generation"] == 3
    await central.state.pusher.tick()
    assert (await _node_users(node))["alice"]["enabled"] is True
    assert [a for a in _actions(central) if a in ("grant.disable", "grant.enable")] == ["grant.disable", "grant.enable"]
    assert await central.state.naive.list_users() == []  # the central's own runtime is never touched


async def test_remote_rotation_is_confirmed_by_the_node_and_retires_the_old_version(pair):
    node, central, node_id, client, operation, grant = await _remote(pair)
    await central.state.pusher.tick()
    assert _secret_states(central, grant.id) == [(1, "active")]
    before = (await node.state.naive.reveal("alice"))["proxy_url"]
    rotated = await central.state.lifecycle.rotate(grant.id, actor=ACTOR, ip="x")
    assert rotated.secret_ref.version == 2 and rotated.observed_state == "pending"
    assert _secret_states(central, grant.id) == [(1, "retiring"), (2, "pending")]
    document = _generation(central, node_id)["document"]
    assert [r.credential_ref for r in document.resources] == [f"grant:{grant.id}:2"]
    await central.state.pusher.tick()
    assert (await node.state.naive.reveal("alice"))["proxy_url"] != before
    # The node runs the new credential: it is active, the one it replaced is history.
    assert _secret_states(central, grant.id) == [(1, "revoked"), (2, "active")]
    current = central.state.clients.client_with_grants(client.id)[1][0]
    assert current.secret_ref.version == 2 and current.observed_state == "enabled"
    with central.state.database.connect() as db:
        escrowed = central.state.secrets.reveal(db, current.secret_ref, purpose="grant.credential", grant_id=grant.id,
                                                permitted_node_id=node_id).decode()
    assert escrowed in (await node.state.naive.reveal("alice"))["proxy_url"]
    assert "grant.rotate" in _actions(central)


async def test_remote_mtproxy_rotation_escrows_a_telemt_shaped_secret(pair):
    node, central, node_id, client, operation, grant = await _remote(pair, protocol="mtproxy")
    rotated = await central.state.lifecycle.rotate(grant.id, actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        secret = central.state.secrets.reveal(db, rotated.secret_ref, purpose="grant.credential", grant_id=grant.id,
                                              permitted_node_id=node_id).decode()
    assert len(secret) == 32 and int(secret, 16) >= 0
    assert await central.state.telemt.list_users() == []


async def test_remote_delete_is_declared_and_the_node_confirms_it_gone(pair):
    node, central, node_id, client, operation, grant = await _remote(pair)
    await central.state.pusher.tick()
    assert "alice" in await _node_users(node)
    await central.state.lifecycle.delete(grant.id, actor=ACTOR, ip="x")
    assert central.state.clients.client_with_grants(client.id)[1] == []
    with central.state.database.connect() as db:
        row = central.state.clients.store.grant(db, grant.id)
    assert (row.desired_state, row.observed_state) == ("deleted", "pending")
    latest = _generation(central, node_id)
    assert latest["generation"] == 2 and [r.desired_state for r in latest["document"].resources] == ["deleted"]
    assert "alice" in await _node_users(node)  # nothing pushed by the lifecycle
    await central.state.pusher.tick()
    assert "alice" not in await _node_users(node)
    with central.state.database.connect() as db:
        assert central.state.clients.store.grant(db, grant.id).observed_state == "missing"
    assert central.state.provisioning.status(operation)["status"] == "succeeded"  # applied before the deletion stands
    assert "grant.delete" in _actions(central)


async def test_deleting_a_remote_grant_the_node_never_applied_settles_its_operation(pair):
    node, central, node_id, client, operation, grant = await _remote(pair)
    assert central.state.provisioning.status(operation)["status"] == "pending_remote"
    await central.state.lifecycle.delete(grant.id, actor=ACTOR, ip="x")
    status = central.state.provisioning.status(operation)
    assert status["status"] == "compensated"
    assert status["steps"][0]["status"] == "compensated" and "deleted" in status["steps"][0]["error"]
    await central.state.pusher.tick()
    assert "alice" not in await _node_users(node)
    assert central.state.provisioning.status(operation)["status"] == "compensated"
    with central.state.database.connect() as db:
        assert central.state.clients.store.grant(db, grant.id).observed_state == "missing"


async def test_deleting_one_grant_of_a_pending_operation_leaves_the_other_step_waiting(pair):
    node, central, node_id, client, operation, alice = await _remote(pair)
    bob = GrantIntent(protocol="naive", node_id=node_id, runtime_username="bob", options=NaiveOptions())
    other = await central.state.provisioning.start(client.id, [bob], actor=ACTOR, ip="x")
    await central.state.lifecycle.delete(alice.id, actor=ACTOR, ip="x")
    assert central.state.provisioning.status(operation)["status"] == "compensated"
    assert central.state.provisioning.status(other)["status"] == "pending_remote"
    await central.state.pusher.tick()
    assert central.state.provisioning.status(other)["status"] == "succeeded"
    assert list(await _node_users(node)) == ["bob"]


async def test_disabling_a_remote_grant_before_the_node_applied_it_still_finishes_the_operation(pair):
    node, central, node_id, client, operation, grant = await _remote(pair)
    await central.state.lifecycle.set_enabled(grant.id, False, actor=ACTOR, ip="x")
    assert central.state.provisioning.status(operation)["status"] == "pending_remote"
    await central.state.pusher.tick()
    assert (await _node_users(node))["alice"]["enabled"] is False
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    assert _secret_states(central, grant.id) == [(1, "active")]
    assert central.state.clients.client_with_grants(client.id)[1][0].observed_state == "disabled"


async def test_a_deleted_or_unknown_grant_is_refused(pair):
    node, central, node_id, client, operation, grant = await _remote(pair)
    with pytest.raises(KeyError):
        await central.state.lifecycle.set_enabled("no-such-grant", True, actor=ACTOR, ip="x")
    await central.state.lifecycle.delete(grant.id, actor=ACTOR, ip="x")
    for call in (
        lambda: central.state.lifecycle.set_enabled(grant.id, True, actor=ACTOR, ip="x"),
        lambda: central.state.lifecycle.rotate(grant.id, actor=ACTOR, ip="x"),
        lambda: central.state.lifecycle.delete(grant.id, actor=ACTOR, ip="x"),
    ):
        with pytest.raises(ClientConflict, match="deleted"):
            await call()
    assert _generation(central, node_id)["generation"] == 2  # the refusals published nothing


async def test_local_enable_route_reaches_the_manager_and_rotation_keeps_a_disabled_grant_disabled(client, login_user, naive):
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
    with client._transport.app.state.database.connect() as db:
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
    assert (await client.post(f"/api/clients/grants/{grant_id}/delete", headers=csrf)).status_code == 409
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
