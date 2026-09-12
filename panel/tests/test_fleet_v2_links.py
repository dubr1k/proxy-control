"""Linking a node panel to the central one: two panels in-process (`pair` from conftest)."""
import pytest

from panel.fleet_v2.links import LinkConflict
from panel.secrets_store import SecretError

pytestmark = pytest.mark.anyio

ACTOR = {"id": 1, "username": "owner"}


async def test_test_and_add_link_a_panel_by_url_and_key(pair):
    node, central, plaintext = pair
    probe = await central.state.links.test("https://node.example", plaintext, "verify", None, False)
    assert probe["identity"]["guid"] == node.state.panel_guid and "naive" in probe["inventory"]["protocols"]
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    assert node_id == node.state.panel_guid
    view = central.state.nodes.get(node_id)
    assert view.kind == "remote" and view.enrollment_state == "linked" and view.link["has_api_key"] is True
    assert plaintext not in repr(view)
    with central.state.database.connect() as db:
        row = db.execute("SELECT * FROM secret_versions WHERE purpose='node-api-key'").fetchone()
    assert row is not None and plaintext.encode() not in row["ciphertext"]


async def test_wrong_key_and_foreign_master_are_refused(pair):
    node, central, plaintext = pair
    with pytest.raises(LinkConflict):
        await central.state.links.test("https://node.example", "pc_wrong_x", "verify", None, False)
    with node.state.database.transaction() as db:
        from panel.fleet_v2.identity import MASTER_KEY, write_setting
        write_setting(db, MASTER_KEY, "someone-else")
    with pytest.raises(LinkConflict):
        await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")


async def test_delete_refuses_while_grants_exist_and_unlinks_the_node(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    with central.state.database.transaction() as db:
        db.execute("INSERT INTO clients VALUES('c1','A','active','{}',0,0)")
        db.execute("""INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,origin,created_at,updated_at)
                      VALUES('g1','c1','naive',?,'alice','enabled','provisioned',0,0)""", (node_id,))
    with pytest.raises(LinkConflict):
        await central.state.links.delete(node_id, actor=ACTOR, ip="x")
    with central.state.database.transaction() as db:
        db.execute("UPDATE access_grants SET desired_state='deleted'")
    await central.state.links.delete(node_id, actor=ACTOR, ip="x")
    assert node_id not in [n.node_id for n in central.state.nodes.list()]


async def test_heartbeat_transitions_emit_events(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    with central.state.database.transaction() as db:
        assert central.state.links.record_heartbeat(db, node_id, online=True, latency_ms=3) == "node.up"
        assert central.state.links.record_heartbeat(db, node_id, online=True, latency_ms=4) is None
        assert central.state.links.record_heartbeat(db, node_id, online=False, error="refused") == "node.down"
    assert central.state.nodes.get(node_id).connectivity_state == "offline"


# --- additional coverage beyond the brief's Step 3 tests ---

async def _linked(pair):
    node, central, plaintext = pair
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    return node, central, plaintext, node_id


async def test_add_writes_node_link_key_and_audit_together_and_the_view_is_secret_free(pair):
    node, central, plaintext, node_id = await _linked(pair)
    view = central.state.nodes.get(node_id)
    assert view.transport == "panel" and view.connectivity_state == "unknown" and view.daemon_health == "reported"
    assert view.link["panel_url"] == "https://node.example" and view.link["enabled"] is True
    assert view.link["identity"]["guid"] == node_id and "protocols" in view.link["identity"]
    assert set(view.link) == {"panel_url", "tls_verify", "status", "latency_ms", "panel_version", "last_heartbeat_at",
                              "last_error", "config_dirty", "desired_generation", "acknowledged_generation", "identity",
                              "status_json", "has_api_key", "enabled"}
    with central.state.database.connect() as db:
        node_row = db.execute("SELECT kind, auth_state, transport FROM fleet_nodes WHERE node_id=?", (node_id,)).fetchone()
        audit = db.execute("SELECT action, target, detail_json FROM audit_log WHERE action='node.link'").fetchone()
        link = central.state.links.link(db, node_id)
    assert tuple(node_row) == ("remote", "linked", "panel")
    assert audit["target"] == node_id and plaintext not in audit["detail_json"]
    assert plaintext not in repr(link) and link["api_key_secret_id"].startswith(f"node-key:{node_id}:")


async def test_add_refuses_a_second_link_to_the_same_panel_and_a_bad_url(pair):
    node, central, plaintext, node_id = await _linked(pair)
    with pytest.raises(LinkConflict, match="already linked"):
        await central.state.links.add("Again", "https://node.example", plaintext, "verify", None, False, actor=ACTOR, ip="x")
    with pytest.raises(ValueError):
        await central.state.links.test("http://node.example", plaintext, "verify", None, False)
    assert [n.node_id for n in central.state.nodes.list() if n.kind == "remote"] == [node_id]


async def test_client_for_reveals_the_key_and_reaches_the_node(pair):
    node, central, plaintext, node_id = await _linked(pair)
    identity = await central.state.links.client_for(node_id).identity()
    assert identity["guid"] == node_id


async def test_update_rotates_the_key_and_revokes_the_old_version(pair):
    node, central, plaintext, node_id = await _linked(pair)
    _, fresh = node.state.api_keys.create("central-2", "node-sync", None, actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        before = central.state.links.link(db, node_id)["api_key_secret_id"]
    central.state.links.update(node_id, display_name="Edge 2", api_key=fresh, actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        link = central.state.links.link(db, node_id)
        states = {row["secret_id"]: row["state"] for row in db.execute("SELECT secret_id, state FROM secret_versions")}
        audit = db.execute("SELECT detail_json FROM audit_log WHERE action='node.link.update'").fetchone()
    assert link["api_key_secret_id"] != before and states[before] == "revoked" and states[link["api_key_secret_id"]] == "active"
    assert central.state.nodes.get(node_id).display_name == "Edge 2"
    assert fresh not in audit["detail_json"] and plaintext not in audit["detail_json"]
    # The new key is what the client now sends; the old one is unrecoverable.
    assert (await central.state.links.client_for(node_id).identity())["guid"] == node_id
    with central.state.database.connect() as db, pytest.raises(SecretError):
        central.state.links._reveal_key(db, {**link, "api_key_secret_id": before})


async def test_update_validates_url_and_pin_mode_before_writing(pair):
    node, central, plaintext, node_id = await _linked(pair)
    with pytest.raises(ValueError):
        central.state.links.update(node_id, url="https://10.0.0.1", actor=ACTOR, ip="x")
    with pytest.raises(ValueError):
        central.state.links.update(node_id, tls_verify="pin", actor=ACTOR, ip="x")
    central.state.links.update(node_id, url="https://node.example:8443/", tls_verify="pin", pinned_sha256="a" * 64,
                               actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        link = central.state.links.link(db, node_id)
    assert (link["panel_url"], link["tls_verify"], link["pinned_cert_sha256"]) == ("https://node.example:8443", "pin", "a" * 64)
    with pytest.raises(KeyError):
        central.state.links.update("missing", display_name="x", actor=ACTOR, ip="x")


async def test_set_enabled_pauses_and_resumes_with_audit(pair):
    node, central, plaintext, node_id = await _linked(pair)
    central.state.links.set_enabled(node_id, False, actor=ACTOR, ip="x")
    assert central.state.nodes.get(node_id).link["enabled"] is False
    with central.state.database.connect() as db:
        assert [link["enabled"] for link in central.state.links.links(db)] == [0]
    central.state.links.set_enabled(node_id, True, actor=ACTOR, ip="x")
    assert central.state.nodes.get(node_id).link["enabled"] is True
    with central.state.database.connect() as db:
        actions = [row["action"] for row in db.execute("SELECT action FROM audit_log ORDER BY id")]
    assert actions[-2:] == ["node.pause", "node.resume"]


async def test_delete_removes_the_link_key_and_audits_even_when_the_node_is_unreachable(pair):
    node, central, plaintext, node_id = await _linked(pair)

    def dead(url, key, **kw):
        from panel.fleet_v2.client import NodeUnreachable

        class Dead:
            async def unlink(self):
                raise NodeUnreachable("ConnectError")

        return Dead()

    central.state.links.client_factory = dead
    await central.state.links.delete(node_id, actor=ACTOR, ip="x")
    with central.state.database.connect() as db:
        assert db.execute("SELECT count(*) FROM node_links").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM secret_versions WHERE purpose='node-api-key'").fetchone()[0] == 0
        audit = db.execute("SELECT detail_json FROM audit_log WHERE action='node.unlink'").fetchone()
    assert audit is not None and '"node_released": false' in audit["detail_json"]
    with pytest.raises(KeyError):
        central.state.nodes.get(node_id)


async def test_delete_tells_the_node_to_forget_its_master(pair):
    node, central, plaintext, node_id = await _linked(pair)
    with node.state.database.transaction() as db:
        from panel.fleet_v2.identity import MASTER_KEY, write_setting
        write_setting(db, MASTER_KEY, central.state.panel_guid)
    await central.state.links.delete(node_id, actor=ACTOR, ip="x")
    with node.state.database.connect() as db:
        assert node.state.managed.master_guid(db) is None


async def test_heartbeat_records_identity_status_and_errors(pair):
    node, central, plaintext, node_id = await _linked(pair)
    with central.state.database.transaction() as db:
        central.state.links.record_heartbeat(db, node_id, online=True, identity={"guid": node_id, "panel_version": "9.9",
                                                                                   "protocols": {"naive": {}}},
                                             status={"managed_resources": 2}, latency_ms=11)
        link = central.state.links.link(db, node_id)
    assert (link["status"], link["latency_ms"], link["panel_version"]) == ("online", 11, "9.9")
    assert link["status_json"] == {"managed_resources": 2} and link["last_error"] is None and link["last_heartbeat_at"]
    with central.state.database.transaction() as db:
        central.state.links.record_heartbeat(db, node_id, online=False, error="NodeUnreachable: ConnectError")
        link = central.state.links.link(db, node_id)
    # A failed contact keeps what the last good one reported, and says why it failed.
    assert (link["status"], link["last_error"], link["panel_version"]) == ("offline", "NodeUnreachable: ConnectError", "9.9")
    with central.state.database.transaction() as db, pytest.raises(KeyError):
        central.state.links.record_heartbeat(db, "missing", online=True)


async def test_a_grant_change_publishes_a_generation_for_the_linked_node_in_the_same_transaction(pair):
    node, central, plaintext, node_id = await _linked(pair)
    from panel.clients.models import AccessGrant, NaiveOptions

    client = central.state.clients.create_client("Alice", actor=ACTOR, ip="x")
    with central.state.database.transaction() as db:
        assert central.state.desired.latest(db, node_id) is None
        central.state.clients.store.insert_grant(db, AccessGrant(
            id="g1", client_id=client.id, protocol="naive", node_id=node_id, runtime_username="alice",
            desired_state="enabled", options=NaiveOptions(), origin="provisioned", created_at=0, updated_at=0))
        central.state.clients.notify(db, client.id)
        latest = central.state.desired.latest(db, node_id)
        assert latest["generation"] == 1 and latest["document"].master_guid == central.state.panel_guid
        assert [r.ref for r in latest["document"].resources] == ["grant:g1"]
    view = central.state.nodes.get(node_id)
    assert view.link["config_dirty"] is True and view.link["desired_generation"] == 1
    # A rolled-back change publishes nothing.
    with pytest.raises(RuntimeError):
        with central.state.database.transaction() as db:
            central.state.clients.store.update_grant(db, "g1", desired_state="disabled", updated_at=1)
            central.state.clients.notify(db, client.id)
            raise RuntimeError("injected")
    with central.state.database.connect() as db:
        assert central.state.desired.latest(db, node_id)["generation"] == 1


async def test_a_panel_cannot_link_itself(pair):
    node, central, plaintext = pair
    import httpx

    from panel.fleet_v2.client import NodeClient
    _, own_key = central.state.api_keys.create("self", "node-sync", None, actor=ACTOR, ip="x")
    central.state.links.client_factory = lambda url, key, **kw: NodeClient(url, key, transport=httpx.ASGITransport(app=central), **kw)
    with pytest.raises(LinkConflict, match="itself"):
        await central.state.links.add("Me", "https://central.example", own_key, "verify", None, False, actor=ACTOR, ip="x")
