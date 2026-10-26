"""v0.3 post-merge fix-wave, node side and local lifecycle."""
import pytest

from panel.tests.test_fleet_v2_delivery import answer, linked, provision

from panel.tests.harness.memories.naive import NaiveError
from panel.tests.harness.memories.telemt import TelemtError

pytestmark = pytest.mark.anyio

ACTOR = {"id": 1, "username": "owner"}



async def _node_key(client, login_user):
    await login_user(client)
    created = await client.post("/api/keys", json={"name": "central", "scope": "node-sync"},
                                headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
    client.cookies.clear()
    return {"Authorization": f"Bearer {created.json()['plaintext']}"}










# --- [T6] a superseded generation is the only KeyError the push route swallows ---




# --- [T6]/[re-review] capture: audited, and local users only for an import ---




async def test_capture_with_an_unknown_purpose_is_422(client, login_user):
    headers = await _node_key(client, login_user)
    response = await client.post("/api/fleet/v2/credentials/capture", headers=headers,
                                 json={"resources": [], "purpose": "steal"})
    assert response.status_code == 422


async def test_the_central_imports_with_the_import_purpose(pair):
    node, central, node_id = await linked(pair)
    node.naive.seed("legacy", "pw-legacy")
    result = await answer(central.client, "POST", f"/api/nodes/{node_id}/import", {
        "resources": [{"protocol": "naive", "runtime_username": "legacy", "client": "new"}]})
    assert result["imported"][0]["has_credential"] is True and result["without_credential"] == []
    assert node.audits(action="fleet.credentials.capture")[0]["detail"]["purpose"] == "import"


# --- [T10] a drifted local grant: "no such user" on delete means already deleted ---

async def test_deleting_a_grant_whose_user_is_already_gone_succeeds(client, login_user, naive):
    await login_user(client)
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    owner = (await client.post("/api/clients", headers=csrf, json={"display_name": "Alice"})).json()
    granted = await client.post(f"/api/clients/{owner['id']}/grants", headers=csrf,
                                json={"grants": [{"protocol": "naive", "runtime_username": "alice"}]})
    assert granted.status_code in (200, 201, 202), granted.text
    grant = (await client.get(f"/api/clients/{owner['id']}")).json()["grants"][0]
    naive.users.pop("alice")  # deleted behind the panel's back
    with pytest.raises(NaiveError):
        await naive.delete("alice")
    deleted = await client.post(f"/api/clients/grants/{grant['id']}/delete", headers=csrf)
    assert deleted.status_code == 200, deleted.text
    assert (await client.get(f"/api/clients/{owner['id']}")).json()["grants"] == []


# --- [T10] a compensated local step leaves no tombstone row ---

async def test_a_compensated_local_grant_is_purged(client, server, login_user, naive, telemt):
    await login_user(client)
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    owner = (await client.post("/api/clients", headers=csrf, json={"display_name": "Alice"})).json()

    async def refuse(*args, **kwargs):
        raise TelemtError("Telemt API error (500)")

    telemt.create_user = refuse
    result = await client.post(f"/api/clients/{owner['id']}/grants", headers=csrf, json={"grants": [
        {"protocol": "naive", "node_id": "local", "runtime_username": "alice", "options": {}},
        {"protocol": "mtproxy", "node_id": "local", "runtime_username": "alice", "options": {}},
    ]})
    assert result.status_code == 200 and result.json()["status"] == "compensated", result.text
    assert "alice" not in [u["username"] for u in await naive.list_users()]
    with server.db() as db:
        rows = db.execute("SELECT desired_state, observed_state FROM access_grants WHERE client_id=?",
                          (owner["id"],)).fetchall()
    assert rows == []  # no `deleted/missing` tombstone left behind


# --- [re-review] the local capture/adopt paths refuse a grant that lives on another node ---

async def test_capture_credential_refuses_a_remote_grant(pair):
    _, central, node_id = await linked(pair)
    client_id, _ = await provision(central, node_id)
    grant = (await answer(central.client, "GET", f"/api/clients/{client_id}"))["grants"][0]
    refused = await central.client.post(f"/api/clients/grants/{grant['id']}/adopt", json={"allow_rotation": True})
    assert refused.status_code == 409 and "another node" in refused.json()["detail"]


# --- [round 3] Telemt errors on enable/disable/options are AdapterError, not 502 ---

@pytest.mark.parametrize("call", ["enable", "disable", "update_options"])
async def test_telemt_adapter_wraps_a_failing_readback(call):
    from panel.protocols.base import AdapterError, GrantRef
    from panel.protocols.telemt import TelemtAdapter
    from panel.tests.harness.memories.telemt import MemoryTelemt

    telemt = MemoryTelemt()
    await telemt.create_user("alice")
    adapter = TelemtAdapter(telemt)

    async def broken(username):
        raise TelemtError("Telemt API error (502)")

    telemt.current_access = broken
    ref = GrantRef("mtproxy", "alice")
    with pytest.raises(AdapterError):
        if call == "update_options":
            await adapter.update_options(ref, {"max_tcp_conns": 3})
        else:
            await getattr(adapter, call)(ref)


