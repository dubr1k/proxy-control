"""Fleet meters (v2.0): the node endpoints under `/api/fleet/v2/metrics*`, `NodeClient`'s meter calls and
the central `FleetMetricsSource` (cache, single flight, concurrency cap, budget, stale fallback)."""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from panel.amneziawg import MemoryAmneziawg
from panel.fleet_v2.client import NodeClient, NodeRejected, NodeUnreachable
from panel.fleet_v2.metrics_source import FleetMetricsSource
from panel.mieru import MemoryMieru
from panel.metrics.fakes import FakeClock, MemoryAgentMetrics
from panel.naive import MemoryNaive
from panel.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio

ACTOR = {"id": 1, "username": "owner"}
PASSWORD = "correct horse battery staple"


# ---- doubles for the source -----------------------------------------------------------------------
def entry(cpu=10.0, status="ok", age=0.0, **extra):
    return {"node_id": "local", "name": "local", "status": status, "age_seconds": age,
            "host": {"cpu_percent": cpu}, "protocols": {}, "top_clients": [], "kernel_counters": "ok",
            "alerts": [], **extra}


class FakeNode:
    """What `NodeClient` answers for one node: a body, a failure, or a delay."""

    def __init__(self, body=None, delay=0.0):
        self.body, self.delay, self.fail = body if body is not None else entry(), delay, None
        self.calls = 0
        self.history_body = None
        self.summary_body = {"range": "1h", "host": {"cpu": {"avg": 5.0}}, "protocols": {}, "hours_of_day": {},
                             "alerts": []}
        self.timeouts = []


class Harness:
    def __init__(self, nodes: dict[str, FakeNode], *, caps=("metrics.v1",), online=True, **options):
        self.nodes, self.caps, self.online = nodes, {n: list(caps) for n in nodes}, {n: online for n in nodes}
        self.clock = FakeClock()
        self.active = self.peak = 0
        self.clients_built = 0
        self.source = FleetMetricsSource(names=self._names, link_state=self._state, node_client=self._client,
                                         clock=self.clock, **options)

    def _names(self):
        return [{"node_id": n, "name": n.title()} for n in self.nodes]

    def _state(self, node_id):
        if node_id not in self.nodes:
            return None
        return {"online": self.online[node_id], "capabilities": self.caps[node_id]}

    def _client(self, node_id):
        self.clients_built += 1
        return _Client(self, self.nodes[node_id])


class _Client:
    def __init__(self, harness, node):
        self.h, self.node = harness, node

    async def _answer(self, body, timeout):
        self.node.calls += 1
        self.node.timeouts.append(timeout)
        self.h.active += 1
        self.h.peak = max(self.h.peak, self.h.active)
        try:
            if self.node.delay:
                await asyncio.sleep(self.node.delay)
            if self.node.fail is not None:
                raise self.node.fail
            return body
        finally:
            self.h.active -= 1

    async def metrics(self, timeout=3.0):
        return await self._answer(self.node.body, timeout)

    async def metrics_history(self, series, range, points, timeout=10.0):
        return await self._answer(self.node.history_body or {"node_id": "local", "range": range, "step": 60,
                                                              "series": {n: [[1, 2.0, 3.0]] for n in series}}, timeout)

    async def metrics_summary(self, range, timeout=10.0):
        return await self._answer(self.node.summary_body, timeout)


# ---- capability gating and mapping -------------------------------------------------------------------
async def test_a_node_without_the_capability_is_unsupported_and_never_called():
    h = Harness({"berlin": FakeNode()}, caps=("generation.v1",))
    got = await h.source.live("berlin")
    assert got["status"] == "unsupported" and got["node_id"] == "berlin" and got["host"] is None
    assert h.nodes["berlin"].calls == 0
    assert (await h.source.history("berlin", ["host.cpu"], "1h", 240))["status"] == "unsupported"
    assert (await h.source.summary("berlin", "1h"))["status"] == "unsupported"
    assert (await h.source.live("stranger"))["status"] == "unsupported"  # no v2 link at all


async def test_a_node_whose_link_is_not_online_is_unavailable_without_a_call():
    h = Harness({"berlin": FakeNode()}, online=False)
    got = await h.source.live("berlin")
    assert got["status"] == "unavailable" and h.nodes["berlin"].calls == 0
    assert (await h.source.history("berlin", ["host.cpu"], "1h", 240))["status"] == "unavailable"
    assert (await h.source.summary("berlin", "1h"))["status"] == "unavailable"


async def test_remote_entries_carry_the_registry_id_and_name_and_a_3s_timeout():
    h = Harness({"berlin": FakeNode(entry(cpu=33.0))})
    got = await h.source.live("berlin")
    assert (got["node_id"], got["name"], got["status"], got["host"]) == ("berlin", "Berlin", "ok", {"cpu_percent": 33.0})
    assert h.nodes["berlin"].timeouts == [3.0]


async def test_a_nodes_own_stale_status_is_passed_through():
    h = Harness({"berlin": FakeNode(entry(status="stale", age=12.0))})
    got = await h.source.live("berlin")
    assert got["status"] == "stale" and got["age_seconds"] == 12.0


async def test_a_404_from_the_node_means_unsupported():
    h = Harness({"berlin": FakeNode()})
    h.nodes["berlin"].fail = NodeRejected(404, None, "metrics_disabled")
    assert (await h.source.live("berlin"))["status"] == "unsupported"


# ---- cache, single flight, cap, budget -----------------------------------------------------------------
async def test_the_answer_is_cached_for_two_seconds_per_node():
    h = Harness({"berlin": FakeNode(), "oslo": FakeNode()})
    await h.source.live("berlin")
    h.clock.advance(1.9)
    await h.source.live("berlin")
    assert h.nodes["berlin"].calls == 1 and h.nodes["oslo"].calls == 0
    h.clock.advance(0.2)
    await h.source.live("berlin")
    assert h.nodes["berlin"].calls == 2


async def test_concurrent_callers_share_one_request():
    h = Harness({"berlin": FakeNode(delay=0.05)})
    results = await asyncio.gather(*(h.source.live("berlin") for _ in range(20)))
    assert h.nodes["berlin"].calls == 1 and all(r["status"] == "ok" for r in results)
    assert h.clients_built == 1


async def test_a_caller_that_leaves_does_not_cancel_the_shared_request():
    h = Harness({"berlin": FakeNode(delay=0.05)})
    waiter = asyncio.ensure_future(h.source.live("berlin"))
    await asyncio.sleep(0.01)
    waiter.cancel()
    await asyncio.sleep(0.1)
    assert (await h.source.live("berlin"))["status"] == "ok" and h.nodes["berlin"].calls == 1


async def test_at_most_eight_node_calls_run_at_once():
    h = Harness({f"n{i}": FakeNode(delay=0.03) for i in range(20)})
    got = await h.source.live_many([{"node_id": n, "name": n} for n in h.nodes], budget=5.0)
    assert len(got) == 20 and all(r["status"] == "ok" for r in got)
    assert h.peak == 8


async def test_a_slow_node_does_not_hold_the_others_back_within_the_budget():
    h = Harness({"fast": FakeNode(), "slow": FakeNode(delay=0.5)}, call_timeout=1.0)
    started = asyncio.get_running_loop().time()
    got = await h.source.live_many([{"node_id": "fast", "name": "Fast"}, {"node_id": "slow", "name": "Slow"}], budget=0.05)
    assert asyncio.get_running_loop().time() - started < 0.3
    assert [(r["node_id"], r["status"]) for r in got] == [("fast", "ok"), ("slow", "unavailable")]
    await asyncio.sleep(0.6)  # the late call finished and fed the cache for the next tick
    again = await h.source.live_many([{"node_id": "slow", "name": "Slow"}], budget=0.05)
    assert again[0]["status"] == "ok" and h.nodes["slow"].calls == 1


async def test_a_late_node_with_a_recent_good_sample_goes_out_as_stale():
    h = Harness({"slow": FakeNode()}, call_timeout=1.0)
    await h.source.live("slow")
    h.clock.advance(30)
    h.nodes["slow"].delay = 0.5
    got = (await h.source.live_many([{"node_id": "slow", "name": "Slow"}], budget=0.05))[0]
    assert got["status"] == "stale" and got["age_seconds"] == 30.0 and got["host"] == {"cpu_percent": 10.0}


# ---- stale fallback ------------------------------------------------------------------------------------
async def test_a_failing_node_keeps_its_last_good_sample_as_stale_for_120_seconds():
    h = Harness({"berlin": FakeNode(entry(cpu=44.0, age=1.0))})
    assert (await h.source.live("berlin"))["status"] == "ok"
    h.nodes["berlin"].fail = NodeUnreachable("ConnectTimeout")
    h.clock.advance(30)
    got = await h.source.live("berlin")
    assert got["status"] == "stale" and got["age_seconds"] == 31.0 and got["host"] == {"cpu_percent": 44.0}
    assert (got["node_id"], got["name"]) == ("berlin", "Berlin")
    h.clock.advance(100)  # 130 s since the last good sample
    got = await h.source.live("berlin")
    assert got["status"] == "unavailable" and got["host"] is None and got["age_seconds"] is None


async def test_a_node_that_never_answered_is_unavailable():
    h = Harness({"berlin": FakeNode()})
    h.nodes["berlin"].fail = NodeRejected(503, "x", "metrics_warming_up")
    assert (await h.source.live("berlin"))["status"] == "unavailable"


async def test_a_node_slower_than_the_call_timeout_is_cut_off():
    h = Harness({"berlin": FakeNode(delay=1.0)}, call_timeout=0.05)
    assert (await h.source.live("berlin"))["status"] == "unavailable"


# ---- history and summary on demand ---------------------------------------------------------------------
async def test_history_and_summary_are_fetched_from_the_node_and_tagged():
    h = Harness({"berlin": FakeNode()})
    history = await h.source.history("berlin", ["host.cpu"], "6h", 120)
    assert (history["node_id"], history["status"], history["range"]) == ("berlin", "ok", "6h")
    assert history["series"] == {"host.cpu": [[1, 2.0, 3.0]]}
    summary = await h.source.summary("berlin", "1h")
    assert (summary["node_id"], summary["name"], summary["status"]) == ("berlin", "Berlin", "ok")
    assert summary["host"] == {"cpu": {"avg": 5.0}}
    h.nodes["berlin"].fail = NodeUnreachable("x")
    assert (await h.source.history("berlin", ["host.cpu"], "1h", 120))["status"] == "unavailable"
    assert (await h.source.summary("berlin", "1h"))["status"] == "unavailable"


async def test_concurrent_identical_history_requests_share_one_call():
    h = Harness({"berlin": FakeNode(delay=0.05)})
    await asyncio.gather(*(h.source.history("berlin", ["host.cpu"], "1h", 240) for _ in range(5)))
    assert h.nodes["berlin"].calls == 1


# ---- NodeClient ----------------------------------------------------------------------------------------
async def test_the_client_calls_the_three_meter_routes_with_a_shorter_timeout():
    seen = []

    def handler(request):
        seen.append((request.url.path, dict(request.url.params), request.extensions["timeout"]))
        return httpx.Response(200, json={"ok": True})

    client = NodeClient("https://node.example", "pc_k", transport=httpx.MockTransport(handler))
    await client.metrics()
    await client.metrics_history(["host.cpu", "net.rx_bps"], "6h", 120)
    await client.metrics_summary("7d")
    assert [(p, q) for p, q, _ in seen] == [
        ("/api/fleet/v2/metrics", {}),
        ("/api/fleet/v2/metrics/history", {"series": "host.cpu,net.rx_bps", "range": "6h", "points": "120"}),
        ("/api/fleet/v2/metrics/summary", {"range": "7d"})]
    assert seen[0][2]["read"] == 3.0 and seen[1][2]["read"] == 10.0


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
@pytest.fixture
async def linked(panel_server, login_user):
    node, node_clock, node_agent = make_app(panel_server, "node")
    node_agent.set_protocol("naive", 500.0, 1500.0)
    central, central_clock, _ = make_app(panel_server, "central", node_routes={"node.example": node})
    plaintext = node.create_api_key("central", "node-sync")
    async with central.http() as http:
        await login_user(http)
        http.headers["X-CSRF-Token"] = http.cookies["panel_csrf"]
        linked = await http.post("/api/nodes/link", json={"display_name": "Edge", "url": "https://node.example",
                                                          "api_key": plaintext, "tls_verify": "verify",
                                                          "allow_private_address": False})
        assert linked.status_code == 201, linked.text
        await tick(node, node_clock, 3)
        await tick(central, central_clock, 3)
        yield central, http, linked.json()["node_id"]








# ---- central: the compare table over three nodes ----------------------------------------------------------
async def test_summary_compare_has_a_row_per_node_sorted_by_traffic(panel_server, login_user):
    central, clock, _ = make_app(panel_server, "central")
    await tick(central, clock, 3)
    for node_id, name in (("a", "Alpha"), ("b", "Bravo"), ("c", "Charlie")):
        central.state.nodes.register(node_id, name, actor=ACTOR, ip="x")
    nodes = {"a": FakeNode(), "b": FakeNode(), "c": FakeNode()}
    for node_id, total in (("a", 10), ("b", 5000), ("c", 700)):
        nodes[node_id].summary_body = {
            "range": "1h", "host": {"cpu": {"avg": 20.0}, "mem": {"avg": 30.0}},
            "protocols": {"naive": {"total_bytes": total, "peak_bps": total / 10}}, "hours_of_day": {}, "alerts": [{}]}
    nodes["c"].fail = NodeUnreachable("x")  # c cannot answer: it sorts last, as unavailable
    harness = Harness(nodes)
    central.state.metrics_source = harness.source
    async with central.http() as http:
        await login_user(http)
        body = (await http.get("/api/metrics/summary?node=all&range=1h")).json()
    assert [(r["node_id"], r["status"]) for r in body["compare"]] == [
        ("b", "ok"), ("a", "ok"), ("local", "ok"), ("c", "unavailable")]
    assert [r["total_bytes"] for r in body["compare"][:2]] == [5000, 10] and body["compare"][3]["total_bytes"] is None
    assert body["compare"][0]["peak_bps"] == 500.0 and body["compare"][0]["alerts"] == 1
    assert body["compare"][-1]["node_id"] == "c" and body["nodes"][-1]["protocols"] == {}
