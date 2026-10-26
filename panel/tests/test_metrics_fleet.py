"""Fleet meters (v2.0): the node endpoints under `/api/fleet/v2/metrics*`, `NodeClient`'s meter calls and
the central `FleetMetricsSource` (cache, single flight, concurrency cap, budget, stale fallback)."""
from __future__ import annotations

import asyncio
import json

from panel.tests.test_fleet_v2_delivery import answer, linked


import pytest

from panel.tests.harness.memories.amneziawg import MemoryAmneziawg
from panel.tests.harness.memories.mieru import MemoryMieru
from panel.tests.harness.memories.fakes import FakeClock, MemoryAgentMetrics
from panel.tests.harness.memories.naive import MemoryNaive
from panel.tests.harness.memories.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio

ACTOR = {"id": 1, "username": "owner"}
PASSWORD = "correct horse battery staple"




# ---- the node endpoints --------------------------------------------------------------------------------
def make_app(panel_server, name, *, awg=None, **flags):
    """A panel whose host-agent double and own clock move together (`tick`)."""
    agent = MemoryAgentMetrics(FakeClock())
    server = panel_server(name=name, hosts=("testserver", f"{name}.example"), naive_public_host=f"{name}.example",
                          telemt=MemoryTelemt(public_host=f"{name}.example"), naive=MemoryNaive(), mieru=MemoryMieru(),
                          amneziawg=awg or MemoryAmneziawg(), versions=agent, **flags)
    server.create_admin("owner", PASSWORD, "owner")
    server.clock.set(agent.clock.now)
    return server, agent.clock, agent


async def tick(server, clock, times=1):
    for _ in range(times):
        clock.advance(2.0)
        server.clock.set(clock.now)
        await server.tick("metrics")


@pytest.fixture
async def node(panel_server):
    server, clock, agent = make_app(panel_server, "node")
    agent.set_protocol("trusttunnel", 1000.0, 3000.0)
    plaintext = server.create_api_key("central", "node-sync")
    http = server.http()
    http.key = {"Authorization": f"Bearer {plaintext}"}
    http.server, http.clock = server, clock
    async with http:
        yield http


PATHS = ["/api/fleet/v2/metrics", "/api/fleet/v2/metrics/history?series=host.cpu", "/api/fleet/v2/metrics/summary"]


@pytest.mark.parametrize("path", PATHS)
async def test_the_node_meter_routes_need_a_node_sync_key(node, login_user, path):
    await tick(node.server, node.clock, 2)
    assert (await node.get(path)).status_code == 401
    assert (await node.get(path, headers={"Authorization": "Bearer pc_nonsense"})).status_code == 401
    assert (await node.get(path, headers=node.key)).status_code == 200
    reader = node.server.create_api_key("reader", "monitor")
    assert (await node.get(path, headers={"Authorization": f"Bearer {reader}"})).status_code == 403
    await login_user(node)  # a browser session is not a node key either
    assert (await node.get(path)).status_code == 403


async def test_the_node_live_entry_is_the_collectors_latest(node):
    await tick(node.server, node.clock, 2)
    response = await node.get("/api/fleet/v2/metrics", headers=node.key)
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"node_id", "name", "status", "age_seconds", "host", "protocols", "top_clients",
                         "kernel_counters", "alerts"}
    assert body["node_id"] == "local" and body["status"] == "ok" and body["host"]["cpu_percent"] == 12.5
    assert body["protocols"]["trusttunnel"]["down_bps"] == 3000.0 and body["kernel_counters"] == "ok"


async def test_the_node_history_and_summary_match_the_local_routes(node, login_user):
    await tick(node.server, node.clock, 3)
    history = (await node.get("/api/fleet/v2/metrics/history?series=host.cpu,trusttunnel.down_bps&range=15m&points=450",
                              headers=node.key)).json()
    assert history["status"] == "ok" and history["node_id"] == "local" and set(history["series"]) == {
        "host.cpu", "trusttunnel.down_bps"}
    summary = (await node.get("/api/fleet/v2/metrics/summary?range=1h", headers=node.key)).json()
    assert summary["range"] == "1h" and summary["host"]["cpu"]["avg"] == 12.5 and "alerts" in summary
    await login_user(node)
    local = (await node.get("/api/metrics/history?series=host.cpu,trusttunnel.down_bps&range=15m&points=450")).json()
    assert local == history


@pytest.mark.parametrize("path", ["/api/fleet/v2/metrics/history?series=host.nope",
                                  "/api/fleet/v2/metrics/history?series=host.cpu&range=2d",
                                  "/api/fleet/v2/metrics/history?series=host.cpu&points=5",
                                  "/api/fleet/v2/metrics/summary?range=2d"])
async def test_the_node_validates_its_parameters(node, path):
    await tick(node.server, node.clock)
    assert (await node.get(path, headers=node.key)).status_code == 422


async def test_before_the_first_sample_the_node_says_it_is_warming_up(node):
    for path in PATHS:
        response = await node.get(path, headers=node.key)
        assert response.status_code == 503 and response.json() == {"detail": "metrics_warming_up"}


async def test_a_node_with_metrics_off_answers_404_and_does_not_advertise_them(panel_server):
    server, _, _ = make_app(panel_server, "off", metrics_enabled=False)
    headers = {"Authorization": f"Bearer {server.create_api_key('central', 'node-sync')}"}
    async with server.http() as http:
        for path in PATHS:
            response = await http.get(path, headers=headers)
            assert response.status_code == 404 and response.json() == {"detail": "metrics_disabled"}
        assert "metrics.v1" not in (await http.get("/api/fleet/v2/identity", headers=headers)).json()["capabilities"]


async def test_the_identity_advertises_metrics_v1(node):
    identity = (await node.get("/api/fleet/v2/identity", headers=node.key)).json()
    assert "metrics.v1" in identity["capabilities"] and "egress.v1" in identity["capabilities"]


# ---- the status block of AmneziaWG ---------------------------------------------------------------------
async def test_the_status_reports_amneziawg_traffic(panel_server):
    awg = MemoryAmneziawg()
    awg.peer_table = {"a": {"version": "3.1", "enabled": True, "address": "10.0.0.2", "public_key": "k", "revision": "r"},
                      "b": {"version": "2.0", "enabled": True, "address": "10.0.0.3", "public_key": "k", "revision": "r"}}
    rows = {"a": (100, 400), "b": (20, 30)}
    original = awg._view
    awg._view = lambda name: {**original(name), "rx": rows[name][0], "tx": rows[name][1]}
    server, _, _ = make_app(panel_server, "awg", awg=awg, amneziawg_enabled=True)
    headers = {"Authorization": f"Bearer {server.create_api_key('central', 'node-sync')}"}
    async with server.http() as http:
        traffic = (await http.get("/api/fleet/v2/status", headers=headers)).json()["protocols"]["amneziawg"]["traffic"]
        assert traffic == {"upload_bytes": 120, "download_bytes": 430, "total_bytes": 550}
        awg.broken = True
        assert (await http.get("/api/fleet/v2/status", headers=headers)).json()["protocols"]["amneziawg"]["traffic"] is None


# ---- central: a real link, the routes and the stream ----------------------------------------------------

async def all_nodes(pair_factory):
    agent = MemoryAgentMetrics(FakeClock())
    node, central, node_id = await linked(pair_factory(node={"versions": agent}))
    node.clock.set(agent.clock.now)
    central.clock.set(agent.clock.now)
    await tick(node, agent.clock, 2)
    await central.tick("pusher")
    await central.tick("metrics")
    return node, central, node_id, agent


async def test_all_includes_the_linked_node_once_it_is_online(pair_factory):
    _, central, node_id, _ = await all_nodes(pair_factory)
    body = await answer(central.client, "GET", "/api/metrics/live?node=all")
    assert [entry["node_id"] for entry in body["nodes"]] == ["local", node_id]
    remote = body["nodes"][1]
    assert remote["name"] == "Edge" and remote["status"] == "ok"
    assert remote["host"]["cpu_percent"] == 12.5
    one = await answer(central.client, "GET", f"/api/metrics/live?node={node_id}")
    assert one["nodes"] == [remote]


async def test_the_all_stream_carries_the_remote_node_each_tick(pair_factory):
    node, central, node_id, agent = await all_nodes(pair_factory)
    async with central.client.stream("GET", "/api/metrics/stream?node=all") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["cache-control"] == "no-store"
        lines = response.aiter_lines()

        async def snapshot():
            async with asyncio.timeout(10):
                async for line in lines:
                    if line.startswith("data:"):
                        return json.loads(line.removeprefix("data:").strip())
            pytest.fail("metrics stream ended before a snapshot")

        first = await snapshot()
        for payload in (first,):
            assert [entry["node_id"] for entry in payload["nodes"]] == ["local", node_id]
            assert payload["nodes"][1]["status"] == "ok"
        await tick(node, agent.clock)
        central.clock.advance(3)
        await central.tick("metrics")
        second = await snapshot()
        assert [entry["node_id"] for entry in second["nodes"]] == ["local", node_id]
        assert second["nodes"][1]["host"]["cpu_percent"] == 12.5
        assert second["nodes"][1]["status"] == "ok"

# ---- central: the compare table over three nodes ----------------------------------------------------------
async def test_summary_compare_has_a_row_per_node_sorted_by_traffic(panel_server, login_user):
    remotes = {}
    for name, rate in (("alpha", 10), ("bravo", 5000), ("charlie", 700)):
        server, clock, agent = make_app(panel_server, name)
        agent.set_protocol("naive", rate, 0)
        await tick(server, clock, 3)
        remotes[name] = server
    central, clock, _ = make_app(panel_server, "central",
        node_routes={f"{name}.example": server for name, server in remotes.items()})
    await tick(central, clock, 3)
    central.client.headers["Authorization"] = "Bearer " + central.create_api_key("operator", "admin")
    ids = {}
    for name, server in remotes.items():
        result = await answer(central.client, "POST", "/api/nodes/link", {
            "display_name": name.title(), "url": f"https://{name}.example",
            "api_key": server.create_api_key("central", "node-sync")}, 201)
        ids[name] = result["node_id"]
    await central.tick("pusher")
    await remotes["charlie"].aclose()
    body = await answer(central.client, "GET", "/api/metrics/summary?node=all&range=1h")
    rows = body["compare"]
    assert [(row["node_id"], row["status"]) for row in rows] == [
        (ids["bravo"], "ok"), (ids["alpha"], "ok"), ("local", "ok"), (ids["charlie"], "unavailable")]
    assert rows[0]["total_bytes"] > rows[1]["total_bytes"] > rows[2]["total_bytes"] == 0
    assert rows[0]["peak_bps"] == 5000 and rows[-1]["total_bytes"] is None
    # The compare row is deliberately unknown when the node is offline. Its separate
    # history can still retain measured protocol peaks if the last summary was cached.
    offline = body["nodes"][-1]
    assert offline["node_id"] == ids["charlie"] and offline["status"] == "unavailable"
    naive = offline["protocols"].get("naive")
    if naive and naive.get("peak_bps") is not None:
        assert naive["peak_bps"] == 700
