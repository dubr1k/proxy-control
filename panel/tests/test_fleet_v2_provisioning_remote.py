"""Mixed local/remote provisioning through actual linked Rust panels."""
import pytest

from panel.tests.test_fleet_v2_delivery import answer, converge, linked
from panel.tests.test_grant_lifecycle import _grants, _start, _status

pytestmark = pytest.mark.anyio


async def test_local_only_mutations_publish_no_remote_generation(pair):
    _, central, node_id = await linked(pair)
    person = await answer(central.client, "POST", "/api/clients", {"display_name": "A", "subscription": False}, 201)
    await _start(central, person["id"], "local", "bob")
    with central.db() as db:
        assert db.execute("SELECT 1 FROM desired_generations WHERE node_id=?", (node_id,)).fetchone() is None


async def test_run_leaves_remote_steps_to_the_pusher_and_finishes_local_ones(pair):
    node, central, node_id = await linked(pair)
    person = await answer(central.client, "POST", "/api/clients", {"display_name": "A", "subscription": False}, 201)
    result = await answer(central.client, "POST", f"/api/clients/{person['id']}/grants", {"grants": [
        {"protocol": "naive", "node_id": node_id, "runtime_username": "alice", "options": {}},
        {"protocol": "naive", "node_id": "local", "runtime_username": "bob", "options": {}},
    ]})
    assert result["status"] == "pending_remote"
    journal = await answer(central.client, "GET", f"/api/operations/{result['operation_id']}")
    assert sorted(step["status"] for step in journal["steps"]) == ["active", "remote"]
    assert [row["username"] for row in await central.naive.list_users()] == ["bob"]
    assert await node.naive.list_users() == []
    resumed = await answer(central.client, "POST", f"/api/operations/{result['operation_id']}/resume")
    assert resumed["status"] == "pending_remote"
    await converge(node, central)
    assert (await _status(central, result["operation_id"]))["status"] == "succeeded"
    assert [row["username"] for row in await node.naive.list_users()] == ["alice"]


async def test_remote_links_render_with_the_nodes_runtime_host_port_and_fake_tls_secret(pair):
    node, central, node_id = await linked(pair)
    person = await answer(central.client, "POST", "/api/clients", {"display_name": "A", "subscription": False}, 201)
    node.telemt.public_host, node.telemt.public_port = "proxy.node.example", 8443
    result = await answer(central.client, "POST", f"/api/clients/{person['id']}/grants", {"grants": [
        {"protocol": protocol, "node_id": node_id, "runtime_username": "alice", "options": {}}
        for protocol in ("mtproxy", "mieru")
    ]})
    await converge(node, central)
    assert (await _status(central, result["operation_id"]))["status"] == "succeeded"
    grants = {grant["protocol"]: grant for grant in await _grants(central, person["id"])}
    assert grants["mtproxy"]["options"]["host"] == "proxy.node.example"
    assert grants["mtproxy"]["options"]["port"] == 8443
    assert grants["mieru"]["options"]["share_template"].startswith("mierus://{username}:{password}@mieru.example.com")
    created = await answer(central.client, "POST", f"/api/operations/{result['operation_id']}/bundle")
    bundle = await answer(central.client, "GET", f"/api/reveal/{created['reveal_token']}")
    links = {grant["protocol"]: grant["artifacts"][0]["value"] for grant in bundle["grants"]}
    assert links["mtproxy"].startswith("tg://proxy?server=proxy.node.example&port=8443&secret=ee")
    assert links["mieru"].startswith("mierus://alice:") and "@mieru.example.com" in links["mieru"]
    with central.db() as db:
        assert [row[0] for row in db.execute("SELECT state FROM secret_versions WHERE secret_id=?", (f"grant:{grants['mtproxy']['id']}",))] == ["active"]
