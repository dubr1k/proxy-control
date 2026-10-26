"""`/api/metrics/*`: sign-in required, validation, the node entries, the disabled switch and the SSE stream."""
from __future__ import annotations



import json

import pytest

from panel.tests.harness.memories.fakes import FakeClock, MemoryAgentMetrics


pytestmark = pytest.mark.anyio


class Rig:
    """A panel whose agent double and whose own clock move together (`tick`)."""

    def __init__(self, server, agent):
        self.server, self.client, self.agent = server, server.client, agent
        self.clock = agent.clock

    async def tick(self, seconds=2.0, times=1):
        for _ in range(times):
            self.clock.advance(seconds)
            self.server.clock.set(self.clock.now)
            await self.server.tick("metrics")


async def build(panel_server, **flags) -> Rig:
    agent = MemoryAgentMetrics(FakeClock())
    server = panel_server(name="panel", key_name="key", naive_public_host="naive.example", versions=agent, **flags)
    server.create_admin("owner", "correct horse battery staple", "owner")
    server.create_admin("viewer", "correct horse battery staple", "viewer")
    server.clock.set(agent.clock.now)  # one timeline for the panel and its host agent
    return Rig(server, agent)


@pytest.fixture
async def rig(panel_server, login_user):
    value = await build(panel_server)
    value.agent.set_protocol("trusttunnel", 1000.0, 3000.0)
    value.agent.set_protocol("amneziawg", 200.0, 800.0, source="interface")
    await login_user(value.client)
    await value.tick(times=3)
    yield value
    await value.client.aclose()


ROUTES = ["/api/metrics/clients?protocol=mieru", "/api/metrics/live", "/api/metrics/stream", "/api/metrics/history?series=host.cpu", "/api/metrics/summary"]


@pytest.mark.parametrize("path", ROUTES)
async def test_every_metrics_route_needs_a_session(panel_server, path):
    rig = await build(panel_server)
    async with rig.client:
        assert (await rig.client.get(path)).status_code == 401


async def test_live_snapshot_shape_and_no_store(rig):
    response = await rig.client.get("/api/metrics/live")
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"ts", "interval", "nodes"} and body["interval"] == 2.0
    [node] = body["nodes"]
    assert set(node) == {"node_id", "name", "status", "age_seconds", "host", "protocols", "top_clients",
                         "kernel_counters", "alerts"}
    assert node["status"] == "ok" and node["host"]["mem"]["percent"] == 40.0
    tt = node["protocols"]["trusttunnel"]
    assert set(tt) >= {"available", "live", "source", "up_bps", "down_bps", "up_bytes", "down_bytes", "sessions", "clients"}
    assert (tt["source"], tt["up_bps"], tt["down_bps"]) == ("kernel", 1000.0, 3000.0)
    assert node["protocols"]["amneziawg"]["source"] == "interface"
    assert node["protocols"]["naive"]["available"] is False
    assert "password" not in json.dumps(body)








async def test_a_viewer_may_read_the_meters(rig, login_user):
    async with rig.server.http() as other:
        await login_user(other, "viewer")
        assert (await other.get("/api/metrics/live")).status_code == 200


async def test_history_and_summary_answer_for_the_local_node(rig):
    history = (await rig.client.get("/api/metrics/history?series=host.cpu,trusttunnel.down_bps&range=15m&points=450")).json()
    assert history["status"] == "ok" and history["node_id"] == "local" and history["range"] == "15m"
    assert set(history["series"]) == {"host.cpu", "trusttunnel.down_bps"}
    assert history["series"]["host.cpu"][-1][1:] == [12.5, 12.5]
    summary = (await rig.client.get("/api/metrics/summary?range=1h")).json()
    [node] = summary["nodes"]
    assert summary["range"] == "1h" and node["node_id"] == "local" and node["host"]["cpu"]["avg"] == 12.5
    assert "compare" not in summary


@pytest.mark.parametrize("query", [
    "/api/metrics/live?node=ghost", "/api/metrics/live?node=bad%20id", "/api/metrics/summary?range=2d",
    "/api/metrics/history?series=host.cpu&range=2d", "/api/metrics/history?series=host.nope",
    "/api/metrics/history?series=", "/api/metrics/history", "/api/metrics/history?series=host.cpu&points=5",
    "/api/metrics/history?series=host.cpu&points=99999", "/api/metrics/history?series=host.cpu&node=all",
    "/api/metrics/summary?node=ghost", "/api/metrics/stream?node=ghost",
])
async def test_unknown_node_range_or_series_is_422(rig, query):
    assert (await rig.client.get(query)).status_code == 422








@pytest.mark.parametrize("path", ROUTES)
async def test_disabled_monitoring_answers_404(panel_server, login_user, path):
    rig = await build(panel_server, metrics_enabled=False)
    async with rig.client:
        await login_user(rig.client)
        response = await rig.client.get(path)
        assert response.status_code == 404 and response.json() == {"detail": "metrics_disabled"}


async def test_stale_agent_is_reported_not_hidden(rig):
    rig.agent.broken = True
    await rig.tick(10.0)
    node = (await rig.client.get("/api/metrics/live")).json()["nodes"][0]
    assert node["status"] == "stale" and node["age_seconds"] == 10.0


# ---- the stream --------------------------------------------------------------------------------

























