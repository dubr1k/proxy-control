"""v0.3 post-merge fix-wave, node side and local lifecycle
(`docs/superpowers/plans/2026-09-14-v0.3-post-merge-issues.md`)."""
import pytest

from panel.clients.models import GrantIntent, MtproxyOptions, NaiveOptions
from panel.clients.store import ClientConflict
from panel.fleet_v2.protocol import GenerationDocument, Resource
from panel.naive import NaiveError
from panel.telemt import TelemtError

pytestmark = pytest.mark.anyio

ACTOR = {"id": 1, "username": "owner"}
MASTER = "m" * 36


async def _node_key(client, login_user):
    await login_user(client)
    created = await client.post("/api/keys", json={"name": "central", "scope": "node-sync"},
                                headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
    client.cookies.clear()
    return {"Authorization": f"Bearer {created.json()['plaintext']}"}


def _doc(guid, generation, users=("alice",), protocol="naive", origin="provisioned"):
    return GenerationDocument(node_guid=guid, master_guid=MASTER, generation=generation,
                              previous_generation=generation - 1, created_at=1, created_by="c",
                              resources=[Resource(ref=f"grant:{u}", protocol=protocol, runtime_username=u,
                                                  desired_state="enabled", credential_ref=f"grant:{u}:1",
                                                  credential_origin="caller", origin=origin) for u in users])


async def _push(client, headers, guid, generation, **kw):
    doc = _doc(guid, generation, **kw)
    return await client.put("/api/fleet/v2/generation", headers=headers, json={
        "expected_guid": guid, "generation": doc.model_dump(),
        "secrets": {r.credential_ref: f"pw-{r.runtime_username}" for r in doc.resources}})


def _audit(app, action):
    with app.state.database.connect() as db:
        return [dict(r) for r in db.execute("SELECT * FROM audit_log WHERE action=? ORDER BY id", (action,))]


# --- [T6] a superseded generation is the only KeyError the push route swallows ---

async def test_only_a_superseded_generation_is_answered_stale(client, login_user, monkeypatch):
    from panel.fleet_v2.reconcile import GenerationSuperseded

    app = client._transport.app
    headers = await _node_key(client, login_user)
    guid = (await client.get("/api/fleet/v2/identity", headers=headers)).json()["guid"]

    async def superseded(generation):
        raise GenerationSuperseded(generation)

    monkeypatch.setattr(app.state.reconciler, "apply", superseded)
    response = await _push(client, headers, guid, 1)
    assert (response.status_code, response.json()["code"]) == (409, "stale_generation")

    async def broken(generation):
        raise KeyError("an adapter's bug, not a superseded generation")

    monkeypatch.setattr(app.state.reconciler, "apply", broken)
    with pytest.raises(KeyError):
        await _push(client, headers, guid, 2)


# --- [T6]/[re-review] capture: audited, and local users only for an import ---

async def test_capture_is_audited_and_answers_local_users_only_for_an_import(client, login_user, naive):
    app = client._transport.app
    headers = await _node_key(client, login_user)
    guid = (await client.get("/api/fleet/v2/identity", headers=headers)).json()["guid"]
    naive.seed("local-bob", "hunter2")
    await _push(client, headers, guid, 1)  # alice is the central's
    body = {"resources": [{"protocol": "naive", "runtime_username": "alice"},
                          {"protocol": "naive", "runtime_username": "local-bob"}]}
    escrow = (await client.post("/api/fleet/v2/credentials/capture", headers=headers, json=body)).json()
    assert escrow["credentials"] == {"naive:alice": "pw-alice"} and escrow["refused"] == ["naive:local-bob"]
    imported = (await client.post("/api/fleet/v2/credentials/capture", headers=headers,
                                  json={**body, "purpose": "import"})).json()
    assert imported["credentials"] == {"naive:alice": "pw-alice", "naive:local-bob": "hunter2"}
    assert imported["refused"] == []
    rows = _audit(app, "fleet.credentials.capture")
    assert len(rows) == 2
    assert "hunter2" not in rows[1]["detail_json"] and "pw-alice" not in rows[1]["detail_json"]
    assert '"purpose": "import"' in rows[1]["detail_json"] and '"naive:local-bob"' in rows[1]["detail_json"]


async def test_capture_with_an_unknown_purpose_is_422(client, login_user):
    headers = await _node_key(client, login_user)
    response = await client.post("/api/fleet/v2/credentials/capture", headers=headers,
                                 json={"resources": [], "purpose": "steal"})
    assert response.status_code == 422


async def test_the_central_imports_with_the_import_purpose(pair):
    from panel.fleet_v2.importing import ImportItem, import_resources

    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False,
                                            actor=ACTOR, ip="x")
    node.state.naive.seed("legacy", "pw-legacy")
    result = await import_resources(central.state, node_id, [ImportItem("naive", "legacy", "new")], actor=ACTOR, ip="x")
    assert result["imported"][0]["has_credential"] is True and result["without_credential"] == []
    assert _audit(node, "fleet.credentials.capture")[-1]["detail_json"].count("import") == 1


# --- [T10] a drifted local grant: "no such user" on delete means already deleted ---

async def test_deleting_a_grant_whose_user_is_already_gone_succeeds(client, login_user, naive):
    app = client._transport.app
    await login_user(client)
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    owner = (await client.post("/api/clients", headers=csrf, json={"display_name": "Alice"})).json()
    granted = await client.post(f"/api/clients/{owner['id']}/grants", headers=csrf,
                                json={"grants": [{"protocol": "naive", "runtime_username": "alice"}]})
    assert granted.status_code in (200, 201, 202), granted.text
    grant = app.state.clients.client_with_grants(owner["id"])[1][0]
    naive.users.pop("alice")  # deleted behind the panel's back
    with pytest.raises(NaiveError):
        await naive.delete("alice")
    await app.state.lifecycle.delete(grant.id, actor=ACTOR, ip="x")
    assert app.state.clients.client_with_grants(owner["id"])[1] == []


# --- [T10] a compensated local step leaves no tombstone row ---

async def test_a_compensated_local_grant_is_purged(client, login_user, naive):
    app = client._transport.app
    await login_user(client)
    owner = app.state.clients.create_client("Alice", actor=ACTOR, ip="x")
    intents = [GrantIntent(protocol="naive", node_id="local", runtime_username="alice", options=NaiveOptions()),
               GrantIntent(protocol="mtproxy", node_id="local", runtime_username="alice", options=MtproxyOptions())]
    telemt = app.state.telemt

    async def refuse(*args, **kwargs):
        raise TelemtError("Telemt API error (500)")

    telemt.create_user = refuse
    operation = await app.state.provisioning.start(owner.id, intents, actor=ACTOR, ip="x")
    result = await app.state.provisioning.run(operation)
    assert result.status == "compensated"
    assert "alice" not in [u["username"] for u in await naive.list_users()]
    with app.state.database.connect() as db:
        rows = db.execute("SELECT desired_state, observed_state FROM access_grants WHERE client_id=?",
                          (owner.id,)).fetchall()
    assert rows == []  # no `deleted/missing` tombstone left behind


# --- [re-review] the local capture/adopt paths refuse a grant that lives on another node ---

async def test_capture_credential_refuses_a_remote_grant(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False,
                                            actor=ACTOR, ip="x")
    client = central.state.clients.create_client("Alice", actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="naive", node_id=node_id, runtime_username="alice", options=NaiveOptions())
    await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    grant = central.state.clients.client_with_grants(client.id)[1][0]
    with pytest.raises(ClientConflict, match="another node"):
        await central.state.clients.capture_credential(grant.id, actor=ACTOR, ip="x")
    with pytest.raises(ClientConflict, match="another node"):
        await central.state.clients.adopt_credential(grant.id, allow_rotation=True, actor=ACTOR, ip="x")


# --- [round 3] Telemt errors on enable/disable/options are AdapterError, not 502 ---

@pytest.mark.parametrize("call", ["enable", "disable", "update_options"])
async def test_telemt_adapter_wraps_a_failing_readback(call):
    from panel.protocols.base import AdapterError, GrantRef
    from panel.protocols.telemt import TelemtAdapter
    from panel.telemt import MemoryTelemt

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


# --- [T10] one name per audit event: the local and the remote path record the same action ---

def test_audit_event_names_are_documented_once():
    from pathlib import Path

    text = Path(__file__).resolve().parents[2].joinpath("docs", "AUDIT_EVENTS.md").read_text()
    for name in ("fleet.generation.accept", "fleet.credentials.capture", "fleet.unlink", "node.link", "node.unlink",
                 "node.pause", "node.resume", "node.import", "grant.credential.capture", "grant.credential.adopt",
                 "grant.provision.start", "grant.enable", "grant.disable", "grant.rotate", "grant.delete"):
        assert f"`{name}`" in text, name
    for retired in ("grant.enabled", "grant.disabled", "grant.deleted", "grant.credential.rotate"):
        assert f"`{retired}`" not in text, retired
