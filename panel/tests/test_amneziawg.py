"""AmneziaWG: the panel's keys, the node manager's server side, one version per access."""
from __future__ import annotations

import base64
import json

import pytest
from pydantic import ValidationError

from panel.amneziawg import AmneziawgClient, AmneziawgError, MemoryAmneziawg
from panel.clients.models import AccessGrant, AmneziawgOptions, GrantIntent, MieruOptions
from panel.clients.provisioning import new_credential
from panel.protocols import AmneziawgAdapter, CredentialPlan, GrantRef
from panel.protocols.amneziawg import parse_credential, public_key_of, render_conf

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _adapter(manager=None):
    manager = manager or MemoryAmneziawg()
    return manager, AmneziawgAdapter(manager, public_host="vpn.example.com")


def _intent(version="2.0", username="alice-awg20"):
    return GrantIntent(protocol="amneziawg", runtime_username=username, options=AmneziawgOptions(version=version))


def _grant(applied, version="2.0", username="alice-awg20"):
    return AccessGrant(
        id="g1", client_id="c1", protocol="amneziawg", node_id="local", endpoint_id="default",
        runtime_username=username, desired_state="enabled",
        options=AmneziawgOptions(**{**applied.artifact_template, "version": version}),
        origin="provisioned", created_at=1, updated_at=1,
    )


def test_a_new_credential_is_a_key_pair_and_a_preshared_key():
    private, preshared = parse_credential(new_credential("amneziawg"))
    assert len(base64.b64decode(private)) == 32 and len(base64.b64decode(preshared)) == 32
    assert len(public_key_of(private)) == 44
    assert new_credential("amneziawg") != new_credential("amneziawg")


def test_a_malformed_credential_is_refused():
    from panel.protocols import AdapterError

    for bad in (b"not json", b'{"private_key":"x","preshared_key":"y"}', b"[]", b'{"private_key":1}'):
        with pytest.raises(AdapterError):
            parse_credential(bad)


async def test_the_manager_receives_public_material_only():
    manager, adapter = _adapter()
    credential = new_credential("amneziawg")
    applied = await adapter.create("op-1", _intent(), CredentialPlan("caller", credential))
    private, preshared = parse_credential(credential)
    stored = manager.peer_table["alice-awg20"]
    assert stored["public_key"] == public_key_of(private) and stored["preshared_key"] == preshared
    assert private not in json.dumps(stored)
    assert applied.credential == credential and applied.enabled
    template = applied.artifact_template
    assert template["version"] == "2.0" and template["address"].startswith("10.66.20.") and template["port"] == 51821
    assert template["obfuscation"]["S4"] == "16" and "HeaderProtectionKey" not in template["obfuscation"]


async def test_full_lifecycle():
    manager, adapter = _adapter()
    first = new_credential("amneziawg")
    applied = await adapter.create("op-1", _intent(), CredentialPlan("caller", first))
    ref = GrantRef("amneziawg", "alice-awg20", applied.revision)
    assert (await adapter.disable(ref)).enabled is False
    assert manager.peer_table["alice-awg20"]["enabled"] is False
    assert (await adapter.enable(ref)).enabled is True

    second = new_credential("amneziawg")
    rotated = await adapter.rotate("op-2", ref, CredentialPlan("caller", second))
    assert rotated.credential == second
    assert manager.peer_table["alice-awg20"]["public_key"] == public_key_of(parse_credential(second)[0])
    assert manager.peer_table["alice-awg20"]["address"] == applied.artifact_template["address"]

    assert await adapter.capture(ref) is None
    await adapter.delete(ref)
    assert [item.runtime_username for item in (await adapter.discover()).items] == []
    with pytest.raises(Exception) as missing:
        await adapter.delete(ref)
    assert missing.value.already_gone is True


async def test_each_version_lands_on_its_own_interface_and_port():
    manager, adapter = _adapter()
    seen = {}
    for version in ("1.5", "2.0", "3.1"):
        applied = await adapter.create(f"op-{version}", _intent(version, f"bob-{version}"),
                                       CredentialPlan("caller", new_credential("amneziawg")))
        seen[version] = applied.artifact_template
    assert [seen[v]["port"] for v in ("1.5", "2.0", "3.1")] == [51820, 51821, 51822]
    assert len({template["address"].rsplit(".", 1)[0] for template in seen.values()}) == 3
    assert "S3" not in seen["1.5"]["obfuscation"] and "S3" in seen["2.0"]["obfuscation"]
    assert seen["3.1"]["obfuscation"]["HeaderProtectionKey"]


async def test_preflight_refuses_a_version_the_node_does_not_serve_and_a_taken_name():
    manager, adapter = _adapter(MemoryAmneziawg(versions=("2.0",)))
    refused = await adapter.preflight(_intent("3.1"))
    assert refused.ok is False and "3.1" in refused.reason
    assert (await adapter.preflight(_intent("2.0"))).ok
    await adapter.create("op-1", _intent("2.0"), CredentialPlan("caller", new_credential("amneziawg")))
    taken = await adapter.preflight(_intent("2.0"))
    assert taken.ok is False and "already" in taken.reason
    assert await adapter.versions() == ["2.0"]


async def test_a_lost_reply_is_replayed_without_a_second_peer():
    manager, adapter = _adapter()
    manager.faults["create"] = "lose_response"
    applied = await adapter.create("op-1", _intent(), CredentialPlan("caller", new_credential("amneziawg")))
    assert applied.recovered is True
    assert list(manager.peer_table) == ["alice-awg20"]


async def test_the_manager_being_down_is_an_adapter_error_not_a_crash():
    from panel.protocols import AdapterError

    manager, adapter = _adapter()
    manager.broken = True
    with pytest.raises(AdapterError):
        await adapter.discover()
    with pytest.raises(AdapterError):
        await adapter.create("op-1", _intent(), CredentialPlan("caller", new_credential("amneziawg")))


async def test_the_config_is_built_from_escrow_alone():
    manager, adapter = _adapter()
    credential = new_credential("amneziawg")
    applied = await adapter.create("op-1", _intent("3.1", "carol-awg31"), CredentialPlan("caller", credential))
    grant = _grant(applied, "3.1", "carol-awg31")
    [artifact] = adapter.render_artifacts(grant, credential, public_host="vpn.example.com")
    assert artifact.kind == "awg_conf" and artifact.media_type == "text/x-amneziawg-conf"
    assert artifact.label == "AmneziaWG 3.1"
    private, preshared = parse_credential(credential)
    lines = artifact.value.splitlines()
    assert lines[0] == "[Interface]" and lines[1] == f"PrivateKey = {private}"
    assert f"Address = {applied.artifact_template['address']}/32" in lines
    assert "DNS = 1.1.1.1, 1.0.0.1" in lines and "MTU = 1280" in lines
    assert "Endpoint = vpn.example.com:51822" in lines and f"PresharedKey = {preshared}" in lines
    assert "PersistentKeepalive = 25" in lines and "AllowedIPs = 0.0.0.0/0, ::/0" in lines
    # the obfuscation block keeps the documented order and carries the 3.x-only keys
    keys = [line.split(" = ")[0] for line in lines[lines.index("MTU = 1280") + 1:lines.index("[Peer]") - 1]]
    assert keys.index("Jc") < keys.index("S1") < keys.index("H1") < keys.index("I1") < keys.index("HeaderProtectionKey")
    assert "ContentPaddingAddition" in keys


def test_a_config_needs_what_the_node_taught_and_a_host():
    from panel.protocols import AdapterError

    unlearned = AccessGrant(
        id="g1", client_id="c1", protocol="amneziawg", node_id="local", endpoint_id="default",
        runtime_username="x", desired_state="enabled", options=AmneziawgOptions(),
        origin="provisioned", created_at=1, updated_at=1)
    with pytest.raises(AdapterError, match="not learned"):
        render_conf(unlearned, new_credential("amneziawg"), public_host="vpn.example.com")


def test_options_are_bounded():
    assert AmneziawgOptions().version == "2.0"
    for bad in ({"version": "1.0"}, {"version": "4.0"}, {"address": "999.1.1.1"}, {"port": 0},
                {"obfuscation": {"Evil": "1"}}, {"obfuscation": {"Jc": "1\nPostUp = rm -rf /"}},
                {"dns": ["not-an-ip"]}, {"unknown": 1}):
        with pytest.raises(ValidationError):
            AmneziawgOptions(**bad)
    with pytest.raises(ValidationError):
        GrantIntent(protocol="amneziawg", runtime_username="x", options=MieruOptions())


async def test_the_real_client_speaks_the_manager_contract():
    """The same calls over the wire: paths, the token header and the error mapping."""
    import httpx

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, request.headers.get("x-awg-token")))
        if request.url.path == "/v1/peers/ghost/enable":
            return httpx.Response(404, json={"detail": "no", "code": "not_found"})
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(200, json={"peers": [], "instances": []})

    client = AmneziawgClient("/unused", "tok", transport=httpx.MockTransport(handler))
    assert await client.peers() == [] and await client.instances() == []
    await client.delete_peer("alice-awg20")
    with pytest.raises(AmneziawgError) as error:
        await client.peer_state("ghost", "enable")
    assert error.value.status_code == 404 and error.value.code == "not_found"
    assert all(token == "tok" for _m, _p, token in calls)
    assert ("DELETE", "/v1/peers/alice-awg20", "tok") in calls


# ---- through the whole panel ---------------------------------------------------------------------

import httpx  # noqa: E402

from panel.app import Settings, create_app  # noqa: E402
from panel.keyring import Keyring  # noqa: E402
from panel.mieru import MemoryMieru  # noqa: E402
from panel.naive import MemoryNaive  # noqa: E402
from panel.telemt import MemoryTelemt  # noqa: E402
from panel.versions import VersionClient  # noqa: E402


@pytest.fixture
def awg() -> MemoryAmneziawg:
    return MemoryAmneziawg()


@pytest.fixture
async def api(tmp_path, awg):
    master_key = tmp_path / "panel-master-key"
    Keyring.generate().save(master_key)
    settings = Settings(
        database_path=tmp_path / "panel.sqlite3", master_key_file=master_key, session_cookie_secure=False,
        allowed_hosts=("testserver",), reveal_ttl_seconds=60, naive_public_host="vpn.example.com",
        naive_enabled=True, mieru_enabled=True, amneziawg_enabled=True, vnext_writer="domain",
    )
    app = create_app(settings, telemt=MemoryTelemt(public_host="proxy.example.com"), naive=MemoryNaive(),
                     mieru=MemoryMieru(), amneziawg=awg,
                     version_client=VersionClient(str(tmp_path / "missing-version-agent.sock")))
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver",
                                 follow_redirects=False) as client:
        page = await client.get("/login")
        await client.post("/api/auth/login", json={"username": "owner", "password": "correct horse battery staple"},
                          headers={"X-CSRF-Token": page.cookies["panel_csrf"]})
        client.app_state = app.state
        yield client


def _headers(api):
    return {"X-CSRF-Token": api.cookies["panel_csrf"]}


async def _issue(api, grants):
    created = await api.post("/api/clients", json={"display_name": "Alice"}, headers=_headers(api))
    client_id = created.json()["id"]
    started = await api.post(f"/api/clients/{client_id}/grants", json={"grants": grants}, headers=_headers(api))
    assert started.status_code == 200 and started.json()["status"] == "succeeded", started.text
    return client_id


async def _config_of(api, client_id, grant_id):
    issued = await api.post(f"/api/clients/{client_id}/links?grant_id={grant_id}", headers=_headers(api))
    assert issued.status_code == 200, issued.text
    revealed = await api.get(f"/api/reveal/{issued.json()['reveal_token']}")
    [grant] = revealed.json()["grants"]
    [artifact] = grant["artifacts"]
    return artifact


async def test_a_client_holds_every_version_and_each_gets_its_own_config(api, awg):
    client_id = await _issue(api, [
        {"protocol": "amneziawg", "runtime_username": f"alice-awg{v.replace('.', '')}", "options": {"version": v}}
        for v in ("1.5", "2.0", "3.1")])
    grants = (await api.get(f"/api/clients/{client_id}")).json()["grants"]
    assert sorted(g["options"]["version"] for g in grants) == ["1.5", "2.0", "3.1"]
    by_version = {g["options"]["version"]: g for g in grants}
    assert {v: g["options"]["port"] for v, g in by_version.items()} == {"1.5": 51820, "2.0": 51821, "3.1": 51822}
    assert all(g["observed_state"] == "enabled" for g in grants)
    for version, port in (("1.5", 51820), ("2.0", 51821), ("3.1", 51822)):
        artifact = await _config_of(api, client_id, by_version[version]["id"])
        assert artifact["media_type"] == "text/x-amneziawg-conf" and artifact["label"] == f"AmneziaWG {version}"
        assert f"Endpoint = vpn.example.com:{port}" in artifact["value"]
        assert artifact["qr"].startswith("data:image/svg+xml;base64,")
        assert ("HeaderProtectionKey" in artifact["value"]) is (version == "3.1")
        assert ("S3 = " in artifact["value"]) is (version != "1.5")
    # the node holds three peers on three interfaces, public material only
    assert sorted((row["version"], row["address"].rsplit(".", 1)[0]) for row in await awg.peers()) == [
        ("1.5", "10.66.15"), ("2.0", "10.66.20"), ("3.1", "10.66.31")]


async def test_disable_rotate_and_delete_reach_the_node(api, awg):
    client_id = await _issue(api, [{"protocol": "amneziawg", "runtime_username": "alice-awg20",
                                    "options": {"version": "2.0"}}])
    [grant] = (await api.get(f"/api/clients/{client_id}")).json()["grants"]
    before = (await _config_of(api, client_id, grant["id"]))["value"]
    assert (await api.post(f"/api/clients/grants/{grant['id']}/disable", headers=_headers(api))).status_code == 200
    assert awg.peer_table["alice-awg20"]["enabled"] is False
    assert (await api.post(f"/api/clients/grants/{grant['id']}/enable", headers=_headers(api))).status_code == 200
    key_before = awg.peer_table["alice-awg20"]["public_key"]
    assert (await api.post(f"/api/clients/grants/{grant['id']}/rotate", headers=_headers(api))).status_code == 200
    assert awg.peer_table["alice-awg20"]["public_key"] != key_before
    after = (await _config_of(api, client_id, grant["id"]))["value"]
    assert after != before and after.splitlines()[1] != before.splitlines()[1]  # a new PrivateKey
    assert (await api.post(f"/api/clients/grants/{grant['id']}/delete", headers=_headers(api))).status_code == 200
    assert awg.peer_table == {}


async def test_a_version_the_node_does_not_serve_is_refused_before_anything_is_written(tmp_path):
    awg = MemoryAmneziawg(versions=("2.0",))
    master_key = tmp_path / "k"
    Keyring.generate().save(master_key)
    app = create_app(Settings(database_path=tmp_path / "p.sqlite3", master_key_file=master_key,
                              session_cookie_secure=False, allowed_hosts=("testserver",), amneziawg_enabled=True,
                              naive_public_host="vpn.example.com", vnext_writer="domain"),
                     telemt=MemoryTelemt(), naive=MemoryNaive(), mieru=MemoryMieru(), amneziawg=awg,
                     version_client=VersionClient(str(tmp_path / "none.sock")))
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as api:
        page = await api.get("/login")
        await api.post("/api/auth/login", json={"username": "owner", "password": "correct horse battery staple"},
                       headers={"X-CSRF-Token": page.cookies["panel_csrf"]})
        created = await api.post("/api/clients", json={"display_name": "Bob"}, headers=_headers(api))
        refused = await api.post(f"/api/clients/{created.json()['id']}/grants", headers=_headers(api), json={
            "grants": [{"protocol": "amneziawg", "runtime_username": "bob-awg31", "options": {"version": "3.1"}}]})
    assert refused.status_code in (409, 422) and "3.1" in refused.text
    assert awg.peer_table == {}


async def test_amneziawg_never_enters_a_subscription_feed(api):
    client_id = await _issue(api, [
        {"protocol": "amneziawg", "runtime_username": "alice-awg20", "options": {"version": "2.0"}},
        {"protocol": "naive", "runtime_username": "alice", "options": {}}])
    state = api.app_state
    with state.database.connect() as db:
        grants = state.clients.store.grants(db, client_id=client_id)
        subscription = type("S", (), {"client_id": client_id, "generation": 1})()
    assert {grant.protocol for grant in grants} == {"amneziawg", "naive"}
    manifest = state.subscriptions.effective_manifest(subscription, 0)
    assert [grant.protocol for grant in manifest.grants] == ["naive"]


async def test_the_node_reports_its_versions_and_the_dashboard_counts_peers(api, awg):
    await _issue(api, [{"protocol": "amneziawg", "runtime_username": "alice-awg20", "options": {"version": "2.0"}}])
    local = (await api.get("/api/nodes/local")).json()
    assert local["services"]["amneziawg"] == "ok" and local["identity"]["awg_versions"] == ["1.5", "2.0", "3.1"]
    me = (await api.get("/api/auth/me")).json()
    assert me["features"]["amneziawg"] is True
    dashboard = (await api.get("/api/dashboard")).json()["protocols"]["amneziawg"]
    assert dashboard["ready"] is True and dashboard["versions"] == {"2.0": 1}
    assert dashboard["credentials"] == {"active": 1, "disabled": 0, "total": 1}
    identity = (await api.get("/api/fleet/v2/identity", headers={"Authorization": "Bearer none"}))
    assert identity.status_code in (200, 401, 403)  # the node-sync key is covered by the fleet tests


async def test_the_protocol_filter_and_the_search_know_amneziawg(api):
    client_id = await _issue(api, [{"protocol": "amneziawg", "runtime_username": "alice-awg20",
                                    "options": {"version": "2.0"}}])
    listed = (await api.get("/api/clients?protocol=amneziawg")).json()
    assert [item["client"]["id"] for item in listed["items"]] == [client_id]
    found = (await api.get("/api/clients?q=amneziawg")).json()
    assert [item["client"]["id"] for item in found["items"]] == [client_id]


# ---- a central and a linked node ----------------------------------------------------------------

from panel.clients.models import AmneziawgOptions as _Options  # noqa: E402
from panel.fleet_v2.client import NodeClient  # noqa: E402

ACTOR = {"id": 1, "username": "owner"}


def _awg_app(tmp_path, name, awg=None, enabled=True):
    key = tmp_path / f"{name}-key"
    Keyring.generate().save(key)
    settings = Settings(database_path=tmp_path / f"{name}.sqlite3", master_key_file=key, session_cookie_secure=False,
                        allowed_hosts=("testserver", f"{name}.example"), naive_public_host=f"{name}.example",
                        amneziawg_enabled=enabled, version_agent_socket=str(tmp_path / "none.sock"))
    return create_app(settings, telemt=MemoryTelemt(public_host=f"{name}.example"), naive=MemoryNaive(),
                      mieru=MemoryMieru(), amneziawg=awg or MemoryAmneziawg(),
                      version_client=VersionClient(str(tmp_path / "none.sock")))


async def _linked_awg(tmp_path, *, node_enabled=True):
    node = _awg_app(tmp_path, "node", enabled=node_enabled)
    central = _awg_app(tmp_path, "central", enabled=False)
    _, plaintext = node.state.api_keys.create("central", "node-sync", None, actor=ACTOR, ip="x")
    central.state.links.client_factory = lambda url, key, **kw: NodeClient(
        url, key, transport=httpx.ASGITransport(app=node), **kw)
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False,
                                            actor=ACTOR, ip="x")
    return node, central, node_id


async def test_a_linked_node_applies_the_access_and_the_central_learns_its_details(tmp_path):
    node, central, node_id = await _linked_awg(tmp_path)
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="amneziawg", node_id=node_id, runtime_username="alice-awg31",
                         options=_Options(version="3.1"))
    operation = await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    assert central.state.provisioning.status(operation)["status"] == "pending_remote"
    # the central has no AmneziaWG manager of its own and never called one
    await central.state.pusher.tick()
    assert central.state.provisioning.status(operation)["status"] == "succeeded"
    assert list(node.state.amneziawg.peer_table) == ["alice-awg31"]
    [grant] = central.state.clients.client_with_grants(client.id)[1]
    assert grant.observed_state == "enabled" and grant.options.version == "3.1"
    assert grant.options.port == 51822 and grant.options.address.startswith("10.66.31.")
    assert grant.options.obfuscation["HeaderProtectionKey"]
    # the node never saw the client's private key: only what the adapter derives from it
    stored = node.state.amneziawg.peer_table["alice-awg31"]
    with central.state.database.connect() as db:
        credential = central.state.secrets.reveal(db, grant.secret_ref, purpose="grant.credential",
                                                  grant_id=grant.id, permitted_node_id=node_id)
    assert parse_credential(credential)[0] not in json.dumps(stored)
    adapter = central.state.adapters["amneziawg"]
    from panel.fleet_v2.central_routes import public_hosts_for

    host = public_hosts_for(central.state, node_id)["amneziawg"]
    [artifact] = adapter.render_artifacts(grant, credential, public_host=host)
    assert "Endpoint = node.example:51822" in artifact.value and "[Peer]" in artifact.value


async def test_a_node_without_amneziawg_is_refused_before_anything_is_written(tmp_path):
    from panel.clients.store import ClientConflict

    node, central, node_id = await _linked_awg(tmp_path, node_enabled=False)
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="amneziawg", node_id=node_id, runtime_username="alice-awg20",
                         options=_Options(version="2.0"))
    with pytest.raises(ClientConflict, match="not enabled"):
        await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        assert db.execute("SELECT count(*) FROM access_grants").fetchone()[0] == 0


async def test_an_older_node_never_receives_the_resource(tmp_path):
    from panel.clients.store import ClientConflict

    node, central, node_id = await _linked_awg(tmp_path)
    with central.state.database.connect() as db:
        identity = json.loads(db.execute("SELECT identity_json FROM node_links WHERE node_id=?", (node_id,)).fetchone()[0])
    identity["capabilities"] = [c for c in identity["capabilities"] if c != "protocol.amneziawg.v1"]
    with central.state.database.transaction() as db:
        db.execute("UPDATE node_links SET identity_json=? WHERE node_id=?", (json.dumps(identity), node_id))
    client = central.state.clients.create_client("A", actor=ACTOR, ip="x")
    intent = GrantIntent(protocol="amneziawg", node_id=node_id, runtime_username="alice-awg20",
                         options=_Options(version="2.0"))
    with pytest.raises(ClientConflict, match="without AmneziaWG"):
        await central.state.provisioning.start(client.id, [intent], actor=ACTOR, ip="x")


async def test_the_node_declares_the_capability_and_its_versions(tmp_path):
    node, central, node_id = await _linked_awg(tmp_path)
    with central.state.database.connect() as db:
        identity = json.loads(db.execute("SELECT identity_json FROM node_links WHERE node_id=?", (node_id,)).fetchone()[0])
    assert "protocol.amneziawg.v1" in identity["capabilities"]
    entry = identity["protocols"]["amneziawg"]
    assert entry["enabled"] is True and entry["versions"] == ["1.5", "2.0", "3.1"] and entry["daemon"] == "ok"
    assert entry["public_host"] == "node.example"


# ---- the AmneziaWG screen ------------------------------------------------------------------------

async def test_the_overview_joins_the_manager_with_the_clients_that_hold_the_accesses(api, awg):
    client_id = await _issue(api, [
        {"protocol": "amneziawg", "runtime_username": "alice-awg20", "options": {"version": "2.0"}},
        {"protocol": "amneziawg", "runtime_username": "alice-awg31", "options": {"version": "3.1"}}])
    # a peer on the node the panel knows nothing about (made by hand on the manager)
    await awg.create_peer({"operation_id": "x", "username": "stranger", "version": "1.5",
                           "public_key": "A" * 43 + "=", "preshared_key": "B" * 43 + "="})
    awg.peer_table["alice-awg20"]["latest_handshake"] = 1_700_000_000
    data = (await api.get("/api/amneziawg/overview")).json()
    assert data["status"] == "ok" and data["ip_forward"] is True and data["public_host"] == "vpn.example.com"
    assert [(v["version"], v["port"], v["peers"], v["running"]) for v in data["versions"]] == [
        ("1.5", 51820, 1, True), ("2.0", 51821, 1, True), ("3.1", 51822, 1, True)]
    by_name = {row["username"]: row for row in data["peers"]}
    assert by_name["alice-awg20"]["client_name"] == "Alice" and by_name["alice-awg20"]["client_id"] == client_id
    assert by_name["alice-awg20"]["grant_id"] and by_name["alice-awg20"]["version"] == "2.0"
    assert by_name["stranger"]["client_id"] is None and by_name["stranger"]["grant_id"] is None
    assert data["pending"] == []
    # nothing secret leaves: no keys, no obfuscation values
    assert "HeaderProtectionKey" not in json.dumps(data) and "private" not in json.dumps(data).lower()


async def test_the_overview_says_so_when_the_manager_is_down_or_the_feature_is_off(api, awg, tmp_path):
    await _issue(api, [{"protocol": "amneziawg", "runtime_username": "alice-awg20", "options": {"version": "2.0"}}])
    awg.broken = True
    down = (await api.get("/api/amneziawg/overview")).json()
    assert down["status"] == "down" and down["peers"] == [] and [p["username"] for p in down["pending"]] == ["alice-awg20"]

    master_key = tmp_path / "off-key"
    Keyring.generate().save(master_key)
    app = create_app(Settings(database_path=tmp_path / "off.sqlite3", master_key_file=master_key,
                              session_cookie_secure=False, allowed_hosts=("testserver",), vnext_writer="domain"),
                     telemt=MemoryTelemt(), naive=MemoryNaive(), mieru=MemoryMieru(), amneziawg=MemoryAmneziawg(),
                     version_client=VersionClient(str(tmp_path / "none.sock")))
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as off:
        page = await off.get("/login")
        await off.post("/api/auth/login", json={"username": "owner", "password": "correct horse battery staple"},
                       headers={"X-CSRF-Token": page.cookies["panel_csrf"]})
        assert (await off.get("/api/amneziawg/overview")).status_code == 404


def test_the_screen_is_in_the_navigation_and_opens_the_access_window():
    from pathlib import Path

    static = Path(__file__).resolve().parents[1] / "static"
    index = (static / "index.html").read_text(encoding="utf-8")
    main = (static / "js/main.js").read_text(encoding="utf-8")
    screen = (static / "js/amneziawg.js").read_text(encoding="utf-8")
    assert index.count('data-view="amneziawg"') == 2  # the sidebar and the phone bar
    assert 'amneziawg: renderAmneziawg' in main and "handleAmneziawgClick" in main
    assert "features?.amneziawg" in main  # hidden unless the server has the protocol
    assert "/api/amneziawg/overview" in screen and "context.grants.open" in screen
    assert "private" not in screen.lower() or "приватн" not in screen.lower()
