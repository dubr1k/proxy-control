"""Fleet v2 central acceptance through HTTP, CLI and the persisted wire contract only."""
import json

import pytest

from panel.fleet_v2.protocol import GenerationDocument, canonical_digest

pytestmark = pytest.mark.anyio


async def answer(http, method, path, body=None, status=200):
    response = await http.request(method, path, json=body)
    assert response.status_code == status, response.text
    return response.json()


async def linked(pair, *, auto_import=False):
    node, central, key = pair
    central.client.headers["Authorization"] = "Bearer " + central.create_api_key("owner", "admin")
    view = await answer(central.client, "POST", "/api/nodes/link", {
        "display_name": "Edge", "url": "https://node.example", "api_key": key,
        "auto_import": auto_import,
    }, 201)
    return node, central, view["node_id"]


async def provision(central, node_id, protocol="naive", username="alice"):
    client = await answer(central.client, "POST", "/api/clients", {"display_name": "Alice", "subscription": False}, 201)
    result = await answer(central.client, "POST", f"/api/clients/{client['id']}/grants", {
        "grants": [{"protocol": protocol, "node_id": node_id, "runtime_username": username, "options": {}}],
    })
    assert result["status"] == "pending_remote"
    return client["id"], result["operation_id"]


async def converge(node, central):
    await central.tick("pusher")
    await node.settle()
    await central.tick("pusher")


def digests_match(node, central, node_id):
    with central.db() as db:
        desired = dict(db.execute("SELECT * FROM desired_generations WHERE node_id=? ORDER BY generation DESC LIMIT 1", (node_id,)).fetchone())
        link = dict(db.execute("SELECT * FROM node_links WHERE node_id=?", (node_id,)).fetchone())
    with node.db() as db:
        managed = dict(db.execute("SELECT * FROM managed_generations ORDER BY generation DESC LIMIT 1").fetchone())
    document = GenerationDocument.model_validate_json(desired["document_json"])
    expected = canonical_digest(document)
    assert desired["digest"] == managed["digest"] == expected
    assert desired["generation"] == managed["generation"] == link["acknowledged_generation"]
    assert link["config_dirty"] == 0 and desired["acknowledged_at"] is not None
    return desired


@pytest.mark.parametrize("protocol", ["naive", "mieru", "mtproxy"])
async def test_delivery_lifecycle_keeps_wire_digests_and_credentials(pair, protocol):
    node, central, node_id = await linked(pair)
    client_id, operation = await provision(central, node_id, protocol)
    await converge(node, central)
    status = await answer(central.client, "GET", f"/api/operations/{operation}")
    assert status["status"] == "succeeded"
    view = await answer(central.client, "GET", f"/api/clients/{client_id}")
    grant = view["grants"][0]
    assert grant["observed_state"] == "enabled" and grant["secret_ref"]["version"] == 1
    first = digests_match(node, central, node_id)
    assert first["generation"] == 1
    with central.db() as db:
        row = db.execute("SELECT state FROM secret_versions WHERE secret_id=?", (grant["secret_ref"]["secret_id"],)).fetchone()
        assert row["state"] == "active"
    await answer(central.client, "POST", f"/api/clients/grants/{grant['id']}/disable")
    await converge(node, central)
    assert digests_match(node, central, node_id)["generation"] == 2
    rotated = await answer(central.client, "POST", f"/api/clients/grants/{grant['id']}/rotate")
    assert rotated["secret_ref"]["version"] == 2
    await converge(node, central)
    assert digests_match(node, central, node_id)["generation"] == 3
    await answer(central.client, "POST", f"/api/clients/grants/{grant['id']}/delete")
    await converge(node, central)
    assert digests_match(node, central, node_id)["generation"] == 4
    with central.db() as db:
        assert db.execute("SELECT 1 FROM access_grants WHERE id=?", (grant["id"],)).fetchone() is None
    await answer(central.client, "DELETE", f"/api/nodes/{node_id}")
    with node.db() as db:
        assert db.execute("SELECT 1 FROM panel_settings WHERE key='fleet_master_guid'").fetchone() is None


async def test_paused_probe_heartbeats_without_delivering(pair):
    node, central, node_id = await linked(pair)
    await answer(central.client, "POST", f"/api/nodes/{node_id}/pause")
    await provision(central, node_id)
    await central.tick("pusher")
    view = await answer(central.client, "POST", f"/api/nodes/{node_id}/probe")
    assert view["link"]["status"] == "online" and view["link"]["enabled"] is False
    assert await node.naive.list_users() == []
    with node.db() as db:
        assert db.execute("SELECT count(*) FROM managed_generations").fetchone()[0] == 0
    await answer(central.client, "POST", f"/api/nodes/{node_id}/resume")
    await converge(node, central)
    digests_match(node, central, node_id)


async def test_auto_import_groups_protocols_and_unlink_releases_users(pair):
    node, central, node_id = await linked(pair, auto_import=True)
    node.naive.seed("existing", "naive-secret")
    await node.telemt.create_user("existing")
    await converge(node, central)
    with central.db() as db:
        grants = [dict(row) for row in db.execute("SELECT * FROM access_grants WHERE node_id=?", (node_id,))]
    assert len(grants) == 2 and len({grant["client_id"] for grant in grants}) == 1
    assert {grant["origin"] for grant in grants} == {"imported"}
    digests_match(node, central, node_id)
    await answer(central.client, "DELETE", f"/api/nodes/{node_id}")
    assert [row["username"] for row in await node.naive.list_users()] == ["existing"]
    assert [row["username"] for row in await node.telemt.list_users()] == ["existing"]
    with central.db() as db:
        assert db.execute("SELECT count(*) FROM access_grants WHERE node_id=?", (node_id,)).fetchone()[0] == 0
        assert {row[0] for row in db.execute("SELECT state FROM secret_versions WHERE purpose='grant.credential'")} == {"revoked"}


async def test_resync_republishes_above_the_node_after_restore(pair):
    node, central, node_id = await linked(pair)
    node.client.headers["Authorization"] = "Bearer " + pair[2]
    await answer(node.client, "PUT", "/api/fleet/v2/generation", {
        "expected_guid": node_id, "generation": {
            "node_guid": node_id, "master_guid": central.panel_guid, "generation": 5,
            "previous_generation": 4, "created_at": 1, "created_by": "system", "resources": [],
        }, "secrets": {},
    })
    await provision(central, node_id)
    await central.tick("pusher")
    with central.db() as db:
        row = db.execute("SELECT generation,previous_generation FROM desired_generations ORDER BY generation DESC LIMIT 1").fetchone()
    assert tuple(row) == (6, 5)
    await converge(node, central)
    assert digests_match(node, central, node_id)["generation"] == 6


async def test_rotating_link_key_is_atomic_and_never_public(pair):
    node, central, node_id = await linked(pair)
    fresh = node.create_api_key("replacement", "node-sync")
    with central.db() as db:
        old = db.execute("SELECT api_key_secret_id FROM node_links WHERE node_id=?", (node_id,)).fetchone()[0]
    await answer(central.client, "POST", f"/api/nodes/{node_id}/link", {"api_key": fresh, "display_name": "Renamed"})
    view = await answer(central.client, "POST", f"/api/nodes/{node_id}/probe")
    assert view["link"]["status"] == "online" and view["display_name"] == "Renamed"
    assert fresh not in json.dumps(view) and pair[2] not in json.dumps(view)
    with central.db() as db:
        assert db.execute("SELECT state FROM secret_versions WHERE secret_id=?", (old,)).fetchone()[0] == "revoked"
    await answer(central.client, "POST", f"/api/nodes/{node_id}/link", {"display_name": "Must rollback", "url": "https://10.0.0.1"}, 422)
    assert (await answer(central.client, "GET", f"/api/nodes/{node_id}"))["display_name"] == "Renamed"
    audits = central.audits(action="node.link.update")
    assert len(audits) == 1 and fresh not in json.dumps(audits)


async def test_provisioned_grants_block_unlink_until_force(pair):
    node, central, node_id = await linked(pair)
    await provision(central, node_id)
    await answer(central.client, "DELETE", f"/api/nodes/{node_id}", status=409)
    await answer(central.client, "DELETE", f"/api/nodes/{node_id}?force=true")
    with central.db() as db:
        assert db.execute("SELECT count(*) FROM access_grants WHERE node_id=?", (node_id,)).fetchone()[0] == 0
    audit = central.audits(action="node.unlink")[0]
    assert audit["detail"]["forced"] is True and audit["detail"]["abandoned_provisioned"] == 1


async def test_auth_failure_transitions_once_and_recovers_without_leaking_key(pair):
    node, central, node_id = await linked(pair)
    node.client.headers["Authorization"] = "Bearer " + node.create_api_key("operator", "admin")
    keys = await answer(node.client, "GET", "/api/keys")
    sync_id = next(key["id"] for key in keys["items"] if key["scope"] == "node-sync")
    await central.tick("pusher")
    await central.tick("pusher")
    await answer(node.client, "POST", f"/api/keys/{sync_id}/enabled", {"enabled": False})
    await central.tick("pusher")
    await central.tick("pusher")
    view = await answer(central.client, "GET", f"/api/nodes/{node_id}")
    assert view["link"]["status"] == "offline" and view["link"]["last_error"].startswith("NodeAuthFailed")
    assert pair[2] not in json.dumps(view)
    await answer(node.client, "POST", f"/api/keys/{sync_id}/enabled", {"enabled": True})
    await central.tick("pusher")
    with central.db() as db:
        events = [row[0] for row in db.execute("SELECT action FROM audit_log WHERE action IN ('node.up','node.down') ORDER BY id")]
    assert events == ["node.up", "node.down", "node.up"]


async def test_linked_metrics_live_history_summary_and_stale_cache(pair_factory):
    from panel.metrics.fakes import FakeClock, MemoryAgentMetrics

    agent = MemoryAgentMetrics(FakeClock())
    pair = pair_factory(node={"versions": agent})
    node, central, node_id = await linked(pair)
    node.clock.set(agent.clock.now)
    central.clock.set(agent.clock.now)
    await node.tick("metrics")
    await central.tick("pusher")
    live = await answer(central.client, "GET", f"/api/metrics/live?node={node_id}")
    [entry] = live["nodes"]
    assert entry["node_id"] == node_id and entry["name"] == "Edge" and entry["status"] == "ok"
    assert entry["host"]["mem"]["percent"] == 40.0
    history = await answer(central.client, "GET", f"/api/metrics/history?node={node_id}&series=host.cpu&range=1h")
    assert history["node_id"] == node_id and history["status"] == "ok" and "host.cpu" in history["series"]
    summary = await answer(central.client, "GET", f"/api/metrics/summary?node={node_id}&range=1h")
    assert summary["nodes"][0]["node_id"] == node_id and summary["nodes"][0]["status"] == "ok"
    node.client.headers["Authorization"] = "Bearer " + node.create_api_key("operator", "admin")
    keys = await answer(node.client, "GET", "/api/keys")
    sync_id = next(key["id"] for key in keys["items"] if key["scope"] == "node-sync")
    await answer(node.client, "POST", f"/api/keys/{sync_id}/enabled", {"enabled": False})
    central.clock.advance(3)
    stale = await answer(central.client, "GET", f"/api/metrics/live?node={node_id}")
    assert stale["nodes"][0]["status"] == "stale" and stale["nodes"][0]["age_seconds"] >= 3.0
    central.clock.advance(121)
    expired = await answer(central.client, "GET", f"/api/metrics/live?node={node_id}")
    assert expired["nodes"][0]["status"] == "unavailable"
