"""`/api/metrics/*`: sign-in required, validation, the node entries, the disabled switch and the SSE stream."""
from __future__ import annotations

import asyncio
import dataclasses
import json
from pathlib import Path

import httpx
import pytest

from panel.app import Settings, create_app
from panel.keyring import Keyring
from panel.metrics import setup_metrics
from panel.metrics.fakes import FakeClock, MemoryAgentMetrics
from panel.metrics.sse import StreamRegistry, event_stream

pytestmark = pytest.mark.anyio


class Rig:
    def __init__(self, app, client, clock, agent):
        self.app, self.client, self.clock, self.agent = app, client, clock, agent

    async def tick(self, seconds=2.0, times=1):
        for _ in range(times):
            self.clock.advance(seconds)
            await self.app.state.metrics_collector.tick()
            await self.app.state.metrics_collector.drain()


async def build(tmp_path: Path, **flags) -> Rig:
    key = tmp_path / "key"
    Keyring.generate().save(key)
    settings = Settings(database_path=tmp_path / "panel.sqlite3", master_key_file=key, session_cookie_secure=False,
                        allowed_hosts=("testserver",), naive_public_host="naive.example", **flags)
    clock = FakeClock()
    agent = MemoryAgentMetrics(clock)
    app = create_app(settings, version_client=agent)
    setup_metrics(app, settings, clock=clock)
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    app.state.store.create_admin("viewer", "correct horse battery staple", "viewer")
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")
    return Rig(app, client, clock, agent)


@pytest.fixture
async def rig(tmp_path, login_user):
    value = await build(tmp_path)
    value.agent.set_protocol("trusttunnel", 1000.0, 3000.0)
    value.agent.set_protocol("amneziawg", 200.0, 800.0, source="interface")
    await login_user(value.client)
    await value.tick(times=3)
    yield value
    await value.client.aclose()


ROUTES = ["/api/metrics/clients?protocol=mieru", "/api/metrics/live", "/api/metrics/stream", "/api/metrics/history?series=host.cpu", "/api/metrics/summary"]


@pytest.mark.parametrize("path", ROUTES)
async def test_every_metrics_route_needs_a_session(tmp_path, path):
    rig = await build(tmp_path)
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


async def test_client_rates_of_one_protocol_for_the_protocol_pages(rig):
    collector = rig.app.state.metrics_collector
    collector.settings = dataclasses.replace(collector.settings, trusttunnel_enabled=True)
    rig.app.state.trusttunnel = type("Rows", (), {"clients": staticmethod(lambda: _rows([
        {"username": "alice", "tx": 0, "rx": 0, "sessions": 1}]))})()
    await rig.tick(times=1)
    rig.app.state.trusttunnel = type("Rows", (), {"clients": staticmethod(lambda: _rows([
        {"username": "alice", "tx": 6000, "rx": 2000, "sessions": 1}]))})()
    await rig.tick(5.0)
    body = (await rig.client.get("/api/metrics/clients?protocol=trusttunnel")).json()
    assert body["protocol"] == "trusttunnel" and body["live"] is True
    assert body["clients"]["alice"] == {"up_bps": 400.0, "down_bps": 1200.0, "total_bps": 1600.0}
    naive = (await rig.client.get("/api/metrics/clients?protocol=naive")).json()
    assert naive["live"] is False and naive["clients"] == {}  # naive is not enabled here: nothing measured
    assert (await rig.client.get("/api/metrics/clients?protocol=nope")).status_code == 422
    assert (await rig.client.get("/api/metrics/clients")).status_code == 422


async def _rows(rows):
    return rows


async def test_a_viewer_may_read_the_meters(rig, login_user):
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=rig.app), base_url="http://testserver")
    async with other:
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


async def test_linked_nodes_are_unsupported_until_a_source_is_plugged_in(rig):
    rig.app.state.nodes.register("amsterdam", "Amsterdam", actor={"id": 1, "username": "owner"}, ip="x")
    live = (await rig.client.get("/api/metrics/live?node=amsterdam")).json()
    assert live["nodes"] == [{"node_id": "amsterdam", "name": "Amsterdam", "status": "unsupported", "age_seconds": None,
                              "host": None, "protocols": {}, "top_clients": [], "kernel_counters": None, "alerts": []}]
    both = (await rig.client.get("/api/metrics/live?node=all")).json()["nodes"]
    assert [n["node_id"] for n in both] == ["local", "amsterdam"] and both[1]["status"] == "unsupported"
    history = (await rig.client.get("/api/metrics/history?node=amsterdam&series=host.cpu")).json()
    assert history == {"node_id": "amsterdam", "range": "1h", "status": "unsupported", "series": {}}
    summary = (await rig.client.get("/api/metrics/summary?node=all&range=1h")).json()
    assert [row["node_id"] for row in summary["compare"]] == ["local", "amsterdam"]
    assert summary["compare"][1]["status"] == "unsupported" and summary["nodes"][1]["protocols"] == {}


async def test_a_node_metrics_source_serves_the_linked_nodes(rig):
    class Source:
        async def live(self, node_id):
            return {"node_id": node_id, "name": "Amsterdam", "status": "ok", "age_seconds": 1.0, "host": {"cpu_percent": 3.0},
                    "protocols": {}, "top_clients": [], "kernel_counters": "ok"} if node_id == "amsterdam" else None

        async def history(self, node_id, series, range, points):
            return {"node_id": node_id, "range": range, "series": {name: [] for name in series}}

        async def nodes(self):
            return [{"node_id": "amsterdam", "name": "Amsterdam"}]

    rig.app.state.nodes.register("amsterdam", "Amsterdam", actor={"id": 1, "username": "owner"}, ip="x")
    rig.app.state.nodes.register("berlin", "Berlin", actor={"id": 1, "username": "owner"}, ip="x")
    rig.app.state.metrics_source = Source()
    nodes = (await rig.client.get("/api/metrics/live?node=all")).json()["nodes"]
    assert [(n["node_id"], n["status"]) for n in nodes] == [("local", "ok"), ("amsterdam", "ok"), ("berlin", "unavailable")]
    history = (await rig.client.get("/api/metrics/history?node=amsterdam&series=host.cpu&range=6h")).json()
    assert history["range"] == "6h" and history["series"] == {"host.cpu": []}


@pytest.mark.parametrize("path", ROUTES)
async def test_disabled_monitoring_answers_404(tmp_path, login_user, path):
    rig = await build(tmp_path, metrics_enabled=False)
    async with rig.client:
        await login_user(rig.client)
        response = await rig.client.get(path)
        assert response.status_code == 404 and response.json() == {"detail": "metrics_disabled"}
        assert rig.app.state.metrics_collector is None


async def test_stale_agent_is_reported_not_hidden(rig):
    rig.agent.broken = True
    await rig.tick(10.0)
    node = (await rig.client.get("/api/metrics/live")).json()["nodes"][0]
    assert node["status"] == "stale" and node["age_seconds"] == 10.0


# ---- the stream --------------------------------------------------------------------------------
class FakeRequest:
    def __init__(self):
        self.gone = False

    async def is_disconnected(self):
        return self.gone


def stream_of(rig, request, lease, **kwargs):
    collector = rig.app.state.metrics_collector

    async def build():
        return collector.snapshot()

    async def alive():
        return True

    options = {"build": build, "version": lambda: collector.version, "next_event": collector.next_event,
               "alive": alive, "clock": rig.clock, "poll": 0.005}
    return event_stream(request, lease, **{**options, **kwargs})


async def test_stream_frames_retry_snapshot_ping_and_bye(rig):
    registry = StreamRegistry()
    lease = registry.acquire("s1")
    request = FakeRequest()
    gen = stream_of(rig, request, lease)
    assert await gen.__anext__() == "retry: 3000\n\n"
    snapshot = await gen.__anext__()
    assert snapshot.startswith("event: snapshot\ndata: ") and snapshot.endswith("\n\n")
    assert json.loads(snapshot.split("data: ", 1)[1])["nodes"][0]["node_id"] == "local"
    rig.clock.advance(16)
    assert await gen.__anext__() == ": ping\n\n"
    await rig.tick()
    assert (await gen.__anext__()).startswith("event: snapshot")  # a new collector tick, one new frame
    rig.clock.advance(55 * 60)
    assert await gen.__anext__() == 'event: bye\ndata: {"reason":"max_age"}\n\n'
    with pytest.raises(StopAsyncIteration):
        await gen.__anext__()
    assert registry.open_streams() == 0


async def test_stream_pings_every_fifteen_seconds_even_while_snapshots_flow(rig):
    registry = StreamRegistry()
    gen = stream_of(rig, FakeRequest(), registry.acquire("s1"))
    assert await gen.__anext__() == "retry: 3000\n\n"
    assert (await gen.__anext__()).startswith("event: snapshot")
    frames = []
    for _ in range(9):  # a collector tick every 2 s for 18 s: ticks keep coming, the keep-alive still goes out
        rig.clock.advance(2)
        await rig.tick()
        frames.append(await gen.__anext__())
    pending = asyncio.ensure_future(gen.__anext__())
    done, _ = await asyncio.wait({pending}, timeout=1)
    frames += [pending.result()] if done else []
    assert ": ping\n\n" in frames
    await gen.aclose()


async def test_stream_ends_when_the_client_leaves_or_the_session_is_gone(rig):
    registry = StreamRegistry()
    request = FakeRequest()
    gen = stream_of(rig, request, registry.acquire("s1"))
    await gen.__anext__()
    await gen.__anext__()
    request.gone = True
    with pytest.raises(StopAsyncIteration):
        await gen.__anext__()
    assert registry.open_streams() == 0
    revoked = stream_of(rig, FakeRequest(), registry.acquire("s2"), alive=_never)
    await revoked.__anext__()
    await revoked.__anext__()
    rig.clock.advance(61)
    assert (await revoked.__anext__()).startswith("event: bye")
    with pytest.raises(StopAsyncIteration):
        await revoked.__anext__()
    assert registry.open_streams() == 0


async def _never():
    return False


def test_stream_limits_four_per_session_and_twenty_four_in_total():
    registry = StreamRegistry()
    mine = [registry.acquire("a") for _ in range(4)]
    assert all(mine) and registry.acquire("a") is None
    others = [registry.acquire(f"s{i}") for i in range(20)]
    assert all(others) and registry.acquire("late") is None  # 24 open
    mine[0].release()
    mine[0].release()  # a second release changes nothing
    assert registry.open_streams() == 23 and registry.acquire("late") is not None


async def test_stream_route_answers_429_beyond_the_session_limit(rig):
    cookie = rig.client.cookies["panel_session"]
    registry = rig.app.state.metrics_streams
    session = rig.app.state.store.session(cookie)["token_hash"]
    held = [registry.acquire(session) for _ in range(4)]
    response = await rig.client.get("/api/metrics/stream")
    assert response.status_code == 429 and response.json() == {"detail": "too many metric streams"}
    assert len(held) == 4


async def test_stream_route_sends_event_stream_headers_and_frees_its_slot_on_disconnect(rig):
    cookie = rig.client.cookies["panel_session"]
    sent: list[dict] = []
    seen_snapshot = asyncio.Event()
    leave = asyncio.Event()
    asked = False

    async def receive():
        nonlocal asked
        if not asked:
            asked = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await leave.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)
        if b"event: snapshot" in message.get("body", b""):
            seen_snapshot.set()

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "http",
             "path": "/api/metrics/stream", "raw_path": b"/api/metrics/stream", "query_string": b"", "root_path": "",
             "headers": [(b"host", b"testserver"), (b"cookie", f"panel_session={cookie}".encode())],
             "client": ("127.0.0.1", 1), "server": ("testserver", 80)}
    task = asyncio.create_task(rig.app(scope, receive, send))
    await asyncio.wait_for(seen_snapshot.wait(), 5)
    start = next(m for m in sent if m["type"] == "http.response.start")
    headers = {k.decode(): v.decode() for k, v in start["headers"]}
    assert start["status"] == 200 and headers["content-type"].startswith("text/event-stream")
    assert headers["cache-control"] == "no-store" and headers["x-accel-buffering"] == "no"
    assert rig.app.state.metrics_streams.open_streams() == 1
    leave.set()
    await asyncio.wait_for(task, 5)
    assert rig.app.state.metrics_streams.open_streams() == 0
