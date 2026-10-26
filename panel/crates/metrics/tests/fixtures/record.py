"""Records the goldens of `panel-metrics` from the Python panel (the specification until cutover).

Run on ams-test from a copy of the tree, with the panel venv:

    cd /root/dev/rust-panel-wp13 && PYTHONPATH=. /root/dev/proxy-control/.venv/bin/python -I \
        panel/crates/metrics/tests/fixtures/record.py

It writes next to itself:
- `scenarios.jsonl` — collector/store runs (one per line): every answer the host agent and the managers gave, the
  node entry after each tick, rollup rows, prune counts, history/summary bodies (byte-exact text);
- `routes.json` — `/api/metrics/*` answers of a real Python app (status, headers, body text);
- `sse.json` — SSE frames for given payloads;
- `floats.json` — Python `round`, `format` and floor-division vectors the port relies on.

Each scenario mirrors a test of `panel/tests/test_metrics_collector.py` / `test_metrics_store.py`
(same name, the assertions left to the Rust port). No secrets: everything is synthetic."""
from __future__ import annotations

import asyncio
import copy
import json
import random
import sys
import tempfile
from pathlib import Path

import httpx

from panel.app import Settings, create_app
from panel.keyring import Keyring
from panel.metrics import setup_metrics, sse
from panel.metrics.fakes import FakeClock, ManagerRows, MemoryAgentMetrics, MetricsRig

OUT = Path(__file__).resolve().parent


def dumps(value) -> str:
    """Starlette's `JSONResponse.render`."""
    return json.dumps(value, ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":"))


MANAGERS = (("trusttunnel", "tt", "clients"), ("amneziawg", "awg", "peers"), ("mtproxy", "telemt", "list_users"),
            ("mieru", "mieru", "traffic"), ("naive", "naive", "traffic"))


class Calls:
    """Every answer of the agent and the managers since the last reset, per source."""

    def __init__(self):
        self.calls: dict[str, list] = {}

    def wrap(self, label, fn):
        async def call():
            try:
                value = await fn()
            except Exception as exc:  # noqa: BLE001
                self.calls.setdefault(label, []).append({"error": str(exc)})
                raise
            self.calls.setdefault(label, []).append({"ok": copy.deepcopy(value)})
            return value
        return call

    def take(self) -> dict:
        out, self.calls = self.calls, {}
        return out


class Recorder:
    def __init__(self, name: str, tmp: Path, **flags):
        self.name = name
        self.rig = MetricsRig(tmp, **flags)
        self.ops: list[dict] = []
        self.log = Calls()
        self.flags = flags
        self.rig.agent.metrics = self.log.wrap("agent", self.rig.agent.metrics)
        for label, attr, method in MANAGERS:
            double = getattr(self.rig, attr)
            setattr(double, method, self.log.wrap(label, getattr(double, method)))
        self.start = self.rig.clock.now

    @property
    def collector(self):
        return self.rig.collector

    @property
    def store(self):
        return self.rig.store

    async def step(self, seconds=2.0, keep=True):
        self.log.take()
        await self.rig.step(seconds)
        op = {"op": "step", "advance": seconds, "calls": self.log.take(), "version": self.collector.version,
              "flushes": self.collector.calls["flush"]}
        if keep:
            op["latest"] = dumps(self.collector.latest)
            op["snapshot"] = dumps(self.collector.snapshot())
        self.ops.append(op)

    def put(self, series, bucket, avg, *, count=1, peak=None, resolution=60):
        row = [avg * count, count, avg if peak is None else peak, avg]
        self.store.write({(resolution, bucket, series): row})
        self.ops.append({"op": "put", "resolution": resolution, "bucket": bucket, "series": series, "sum": row[0],
                         "count": row[1], "max": row[2], "last": row[3]})

    def sql(self, statement):
        with self.rig.database.transaction() as db:
            db.execute(statement)
        self.ops.append({"op": "sql", "sql": statement})

    async def history(self, series, range_name, points):
        body = await self.store.history(series, range_name, points)
        self.ops.append({"op": "history", "series": series, "range": range_name, "points": points, "body": dumps(body)})
        return body

    async def summary(self, range_name):
        body = await self.store.summary(range_name)
        self.ops.append({"op": "summary", "range": range_name, "body": dumps(body)})
        return body

    async def prune(self, now=None):
        removed = await self.store.prune(now)
        self.ops.append({"op": "prune", "now": now, "removed": removed})

    def rollups(self):
        with self.rig.database.connect() as db:
            rows = [list(r) for r in db.execute(
                "SELECT resolution,bucket,node_id,series,sum,count,max,last FROM metric_rollups ORDER BY 1,2,3,4")]
        self.ops.append({"op": "rollups", "rows": rows, "flushed_until": self.store.flushed_until})

    def ring(self):
        ring = self.rig.ring
        self.ops.append({"op": "ring", "series": {name: [list(p) for p in ring.points_of(name)]
                                                    for name in ring.series_names()}})

    def client_rates(self, protocol):
        self.ops.append({"op": "client_rates", "protocol": protocol,
                         "body": dumps(self.collector.client_rates(protocol))})

    def dump(self) -> dict:
        return {"name": self.name, "flags": self.flags, "start": self.start, "ops": self.ops}


# ---- scenarios: the bodies of the Python tests ----------------------------------------------------------
ALL = {"trusttunnel_enabled": True, "amneziawg_enabled": True, "naive_enabled": True, "mieru_enabled": True}


async def snapshot_shape_from_kernel_counters_and_managers(r):
    rig = r.rig
    rig.agent.set_protocol("trusttunnel", 1000.0, 3000.0)
    rig.agent.set_protocol("amneziawg", 200.0, 800.0, source="interface")
    rig.agent.set_protocol("mtproxy", 10.0, 20.0)
    rig.tt.rows = [{"username": "alice", "tx": 0, "rx": 0, "sessions": 2}, {"username": "bob", "tx": 0, "rx": 0, "sessions": 0}]
    rig.awg.rows = [{"username": "carol", "rx": 0, "tx": 0, "latest_handshake": int(rig.clock.time()) - 30},
                    {"username": "dave", "rx": 0, "tx": 0, "latest_handshake": int(rig.clock.time()) - 900}]
    rig.telemt.rows = [{"username": "erin", "total_octets": 0, "current_connections": 3}]
    await r.step()
    rig.tt.rows = [{"username": "alice", "tx": 45000, "rx": 15000, "sessions": 2},
                   {"username": "bob", "tx": 0, "rx": 0, "sessions": 0}]
    rig.telemt.rows = [{"username": "erin", "total_octets": 18000, "current_connections": 3}]
    await r.step(15.0)
    r.client_rates("trusttunnel")
    r.client_rates("mtproxy")
    r.ring()


async def kernel_rates_are_averaged_over_the_panel_tick_not_the_agents_last_second(r):
    rig = r.rig
    rig.agent.set_protocol("naive", 0.0, 0.0)
    await r.step()
    rig.agent.protocols["naive"].update(up_bytes=1000, down_bytes=6000, up_bps=5000.0, down_bps=90000.0)
    rig.agent._at = rig.clock.now + 2.0
    await r.step()
    rig.agent.protocols["naive"].update(up_bytes=10, down_bytes=20, up_bps=0.0, down_bps=0.0)
    rig.agent._at = rig.clock.now + 2.0
    await r.step()
    r.ring()


async def top_clients_are_named_through_the_client_store_and_capped_at_ten(r):
    rig = r.rig
    r.sql("INSERT INTO clients(id,display_name,state,created_at,updated_at) VALUES('c1','Alice Doe','active',1,1)")
    r.sql("INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,origin,"
          "created_at,updated_at) VALUES('g1','c1','trusttunnel','local','u0','enabled','provisioned',1,1)")
    rig.tt.rows = [{"username": f"u{i}", "tx": 0, "rx": 0, "sessions": 1} for i in range(14)]
    await r.step()
    rig.tt.rows = [{"username": f"u{i}", "tx": 100 * (i + 1), "rx": 0, "sessions": 1} for i in range(14)]
    await r.step(5.0)
    rig.tt.rows[0]["tx"] = 10_000
    await r.step(5.0)
    r.client_rates("trusttunnel")


async def without_kernel_counters_rates_come_from_manager_deltas(r):
    rig = r.rig
    rig.agent.kernel_counters = "unavailable"
    rig.tt.rows = [{"username": "alice", "tx": 1000, "rx": 1000, "sessions": 1}]
    await r.step()
    rig.tt.rows = [{"username": "alice", "tx": 1000 + 10000, "rx": 1000 + 5000, "sessions": 1}]
    await r.step(5.0)
    rig.naive.rows = [{"username": "alice", "upload_bytes": 0, "download_bytes": 0}]
    await r.step(30.0)
    rig.naive.rows = [{"username": "alice", "upload_bytes": 3000, "download_bytes": 27000}]
    await r.step(30.0)
    r.client_rates("naive")
    r.ring()


async def naive_is_polled_every_15_seconds_even_when_the_kernel_counts_it(r):
    for _ in range(46):
        await r.step(keep=False)
        r.rig.agent.set_protocol("naive", 1.0, 1.0)
    await r.step()


async def naive_is_polled_every_15_seconds_without_the_kernel(r):
    r.rig.agent.kernel_counters = "unavailable"
    for _ in range(46):
        await r.step(keep=False)
    await r.step()


async def naive_and_mieru_clients_get_their_own_rows_while_the_kernel_keeps_the_node_totals(r):
    rig = r.rig
    rig.agent.set_protocol("naive", 4000.0, 9000.0)
    rig.agent.set_protocol("mieru", 2000.0, 7000.0)
    rig.naive.rows = [{"username": "nina", "upload_bytes": 0, "download_bytes": 0}]
    rig.mieru.rows = [{"username": "mia", "upload_bytes": 100, "download_bytes": 1000}]
    await r.step()
    rig.naive.rows = [{"username": "nina", "upload_bytes": 1500, "download_bytes": 15000}]
    rig.mieru.rows = [{"username": "mia", "upload_bytes": 100 + 4000, "download_bytes": 1000 + 20000}]
    await r.step(20.0)


async def mieru_rates_fall_back_to_the_manager_counters_without_the_kernel(r):
    rig = r.rig
    rig.agent.kernel_counters = "unavailable"
    rig.mieru.rows = [{"username": "mia", "upload_bytes": 0, "download_bytes": 0}]
    await r.step()
    rig.mieru.rows = [{"username": "mia", "upload_bytes": 500, "download_bytes": 5000}]
    await r.step(5.0)
    rig.mieru.rows = [{"username": "mia", "upload_bytes": 20, "download_bytes": 40}]
    await r.step(5.0)


async def an_old_mieru_manager_without_the_route_leaves_the_rest_untouched(r):
    rig = r.rig
    rig.agent.set_protocol("mieru", 1000.0, 1000.0)
    rig.mieru.broken = True
    await r.step()
    await r.step(5.0)


async def a_failing_manager_marks_only_its_protocol_unavailable(r):
    rig = r.rig
    rig.agent.kernel_counters = "unavailable"
    rig.tt.rows = [{"username": "alice", "tx": 1, "rx": 1, "sessions": 1}]
    rig.awg.rows = [{"username": "carol", "rx": 1, "tx": 1, "latest_handshake": None}]
    await r.step()
    await r.step(5.0)
    rig.tt.broken = True
    await r.step(5.0)
    await r.step(5.0)


async def an_unreachable_agent_makes_the_node_stale_with_its_age_and_records_nothing(r):
    await r.step()
    r.rig.agent.broken = True
    await r.step(10.0)
    r.ring()


async def an_unreachable_agent_from_the_start_leaves_the_node_unavailable(r):
    r.rig.agent.broken = True
    await r.step()


async def kernel_counter_reset_adds_the_reading_not_a_negative_spike(r):
    rig = r.rig
    rig.agent.set_protocol("trusttunnel", 100.0, 100.0)
    await r.step()
    await r.step()
    rig.agent.reset_counters("trusttunnel")
    await r.step()
    r.ring()


async def connections_come_from_the_agent_next_to_the_manager_sessions(r):
    rig = r.rig
    rig.agent.set_protocol("trusttunnel", 1000.0, 3000.0)
    rig.agent.set_protocol("amneziawg", 200.0, 800.0, source="interface")
    rig.agent.protocols["trusttunnel"]["connections"] = 5
    rig.agent.protocols["amneziawg"]["connections"] = None
    rig.tt.rows = [{"username": "alice", "tx": 0, "rx": 0, "sessions": 0}]
    await r.step()
    await r.step()
    r.ring()


async def windowed_naive_rates_over_a_long_run(r):
    """Extra: the 60 s window, resets and forgetting over many polls (naive and mieru via the managers)."""
    rig = r.rig
    rig.agent.kernel_counters = "unavailable"
    up = down = 0
    for i in range(60):
        if i % 7 == 3:
            up, down = up + 1234 * i, down + 98765
        if i == 40:
            up, down = 17, 33  # the log restarted
        rig.naive.rows = [{"username": "nina", "upload_bytes": up, "download_bytes": down},
                          {"username": f"u{i % 3}", "upload_bytes": i * 10, "download_bytes": i * 100}]
        rig.mieru.rows = [{"username": "mia", "upload_bytes": i * 333, "download_bytes": i * 777.5}]
        await r.step(5.0 if i % 5 else 3.0, keep=i % 10 == 9)
    await r.step(700.0)
    r.ring()
    r.rollups()


# -- store ---------------------------------------------------------------------------------------------------
async def flush_writes_all_three_resolutions_in_one_pass_and_merges_the_next_flush(r):
    r.rig.agent.cpu = 10.0
    for _ in range(16):
        await r.step(keep=False)
    r.rollups()
    for _ in range(16):
        await r.step(keep=False)
    r.rollups()


async def prune_drops_buckets_past_each_resolutions_retention(r):
    now = int(r.rig.clock.time())
    for resolution, age_days in ((60, 4), (60, 1), (900, 40), (900, 10), (3600, 401), (3600, 100)):
        r.put("host.cpu", now // resolution * resolution - age_days * 86400, 1.0, resolution=resolution)
    await r.prune()
    r.rollups()


async def prune_at_the_edges_of_each_retention(r):
    """Extra: buckets exactly at, one second before and after each retention boundary."""
    now = int(r.rig.clock.time()) + 0.75
    for resolution, keep in ((60, 3 * 86400), (900, 35 * 86400), (3600, 400 * 86400)):
        for offset in (-1, 0, 1):
            r.put("net.rx_bps", int(now - keep) + offset, 5.0, resolution=resolution)
    await r.prune(now)
    r.rollups()


async def history_native_step_from_the_ring_with_gaps_where_the_agent_was_silent(r):
    for i in range(30):
        r.rig.agent.cpu = float(i)
        if i == 10:
            r.rig.agent.broken = True
        if i == 16:
            r.rig.agent.broken = False
        await r.step(keep=False)
    await r.history(["host.cpu"], "15m", 450)


async def history_downsamples_to_the_requested_points_keeping_the_peak(r):
    for i in range(30):
        r.rig.agent.cpu = 50.0 if i != 20 else 90.0
        await r.step(keep=False)
    await r.history(["host.cpu"], "15m", 100)


async def history_beyond_the_ring_comes_from_rollups_plus_the_unflushed_tail_exactly(r):
    for i in range(100):
        r.rig.agent.cpu = float(i)
        r.rig.agent.set_protocol("trusttunnel", 100.0, 0.0)
        await r.step(keep=False)
    await r.history(["host.cpu", "trusttunnel.up_bytes"], "6h", 2000)
    await r.history(["host.cpu", "trusttunnel.up_bps", "trusttunnel.up_bytes"], "1h", 240)
    await r.history(["host.cpu"], "15m", 37)
    await r.summary("1h")
    await r.summary("24h")
    r.ring()
    r.rollups()


async def history_picks_the_rollup_resolution_by_range(r):
    for range_name, points in (("6h", 2000), ("24h", 240), ("7d", 2000), ("30d", 2000), ("90d", 2000)):
        await r.history(["host.cpu"], range_name, points)


async def summary_statistics_shares_and_peaks(r):
    now = int(r.rig.clock.time()) // 60 * 60
    for i in range(1, 101):
        r.put("host.cpu", now - (101 - i) * 60, float(i), peak=float(i) + (0 if i < 100 else 0))
    r.put("host.mem", now - 120, 40.0)
    for bucket, up, down in ((now - 300, 1000, 2000), (now - 240, 1000, 2000), (now - 180, 1000, 2000)):
        r.put("trusttunnel.up_bytes", bucket, up)
        r.put("trusttunnel.down_bytes", bucket, down)
    r.put("naive.up_bytes", now - 300, 500)
    r.put("naive.down_bytes", now - 300, 1500)
    for bucket, up, down in ((now - 300, 100.0, 300.0), (now - 240, 400.0, 600.0)):
        r.put("trusttunnel.up_bps", bucket, up, peak=up * 2)
        r.put("trusttunnel.down_bps", bucket, down, peak=down * 2)
    r.put("trusttunnel.sessions", now - 240, 3.0, peak=7.0)
    r.put("trusttunnel.connections", now - 240, 4.0, peak=9.0)
    await r.summary("24h")
    await r.history(["host.cpu", "trusttunnel.up_bytes", "trusttunnel.sessions"], "24h", 240)


async def summary_hours_of_day_for_a_week(r):
    base = int(r.rig.clock.time()) // 3600 * 3600
    for hours_ago in range(1, 49):
        bucket = base - hours_ago * 3600
        hour = bucket // 3600 % 24
        r.put("trusttunnel.up_bps", bucket, 100.0 * (hour + 1), resolution=900)
        r.put("trusttunnel.down_bps", bucket, 50.0, resolution=900)
    await r.summary("7d")
    await r.summary("30d")


async def alerts_follow_the_plan_thresholds(r):
    rig = r.rig
    rig.agent.cpu, rig.agent.mem, rig.agent.disk, rig.agent.swap = 90.0, 95.0, 50.0, 60.0
    for i in range(160):
        await r.step(keep=i == 159)
    rig.agent.cpu, rig.agent.mem = 99.0, 99.0
    for i in range(160):
        await r.step(keep=i == 159)
    rig.agent.cpu, rig.agent.mem, rig.agent.swap = 20.0, 20.0, 10.0
    for i in range(160):
        await r.step(keep=i == 159)


async def a_silent_agent_raises_a_stale_alert_after_a_minute(r):
    await r.step()
    r.rig.agent.broken = True
    await r.step(30.0)
    await r.step(40.0)
    await r.step(300.0)


async def network_spike_is_three_times_the_p95_of_the_last_day(r):
    now = int(r.rig.clock.time()) // 60 * 60
    for i in range(1, 200):
        r.put("net.rx_bps", now - i * 60, 100_000.0)
        r.put("net.tx_bps", now - i * 60, 100_000.0)
    r.rig.agent.rx_bps = r.rig.agent.tx_bps = 150_000.0
    for i in range(20):
        await r.step(keep=i == 19)
    r.rig.agent.rx_bps = r.rig.agent.tx_bps = 400_000.0
    for i in range(20):
        await r.step(keep=i == 19)


async def the_spike_baseline_is_read_once_a_minute_not_every_tick(r):
    now = int(r.rig.clock.time()) // 60 * 60
    for i in range(1, 200):
        r.put("net.rx_bps", now - i * 60, 100_000.0)
        r.put("net.tx_bps", now - i * 60, 100_000.0)
    reads = []
    original = r.store._read
    r.store._read = lambda *a: reads.append(a) or original(*a)
    r.rig.agent.rx_bps = r.rig.agent.tx_bps = 400_000.0
    start = r.rig.clock.time()
    while r.rig.clock.time() - start < 180:
        await r.step(keep=False)
    await r.step()
    r.ops.append({"op": "day_reads", "count": len([a for a in reads if a[0] == ["net.rx_bps", "net.tx_bps"]])})


SCENARIOS = [
    (snapshot_shape_from_kernel_counters_and_managers, ALL),
    (kernel_rates_are_averaged_over_the_panel_tick_not_the_agents_last_second, ALL),
    (top_clients_are_named_through_the_client_store_and_capped_at_ten, ALL),
    (without_kernel_counters_rates_come_from_manager_deltas, ALL),
    (naive_is_polled_every_15_seconds_even_when_the_kernel_counts_it, ALL),
    (naive_is_polled_every_15_seconds_without_the_kernel, {"naive_enabled": True}),
    (naive_and_mieru_clients_get_their_own_rows_while_the_kernel_keeps_the_node_totals, ALL),
    (mieru_rates_fall_back_to_the_manager_counters_without_the_kernel, ALL),
    (an_old_mieru_manager_without_the_route_leaves_the_rest_untouched, ALL),
    (a_failing_manager_marks_only_its_protocol_unavailable, ALL),
    (an_unreachable_agent_makes_the_node_stale_with_its_age_and_records_nothing, ALL),
    (an_unreachable_agent_from_the_start_leaves_the_node_unavailable, {"trusttunnel_enabled": False}),
    (kernel_counter_reset_adds_the_reading_not_a_negative_spike, ALL),
    (connections_come_from_the_agent_next_to_the_manager_sessions, ALL),
    (windowed_naive_rates_over_a_long_run, ALL),
    (flush_writes_all_three_resolutions_in_one_pass_and_merges_the_next_flush, {"trusttunnel_enabled": True}),
    (prune_drops_buckets_past_each_resolutions_retention, {"trusttunnel_enabled": True}),
    (prune_at_the_edges_of_each_retention, {"trusttunnel_enabled": True}),
    (history_native_step_from_the_ring_with_gaps_where_the_agent_was_silent, {"trusttunnel_enabled": True}),
    (history_downsamples_to_the_requested_points_keeping_the_peak, {"trusttunnel_enabled": True}),
    (history_beyond_the_ring_comes_from_rollups_plus_the_unflushed_tail_exactly, {"trusttunnel_enabled": True}),
    (history_picks_the_rollup_resolution_by_range, {"trusttunnel_enabled": True}),
    (summary_statistics_shares_and_peaks, {"trusttunnel_enabled": True}),
    (summary_hours_of_day_for_a_week, {"trusttunnel_enabled": True}),
    (alerts_follow_the_plan_thresholds, {"trusttunnel_enabled": True}),
    (a_silent_agent_raises_a_stale_alert_after_a_minute, {"trusttunnel_enabled": True}),
    (network_spike_is_three_times_the_p95_of_the_last_day, {"trusttunnel_enabled": True}),
    (the_spike_baseline_is_read_once_a_minute_not_every_tick, {"trusttunnel_enabled": True}),
]


async def record_scenarios(tmp: Path) -> list[dict]:
    out = []
    for i, (body, flags) in enumerate(SCENARIOS):
        recorder = Recorder(body.__name__, tmp / f"s{i}", **flags)
        await body(recorder)
        out.append(recorder.dump())
    return out


# ---- routes: a real Python app ------------------------------------------------------------------------------
PASSWORD = "correct horse battery staple"
ACTOR = {"id": 1, "username": "owner"}


async def login(client):
    page = await client.get("/login")
    await client.post("/api/auth/login", json={"username": "owner", "password": PASSWORD},
                      headers={"X-CSRF-Token": page.cookies["panel_csrf"]})


class RouteRig:
    def __init__(self, tmp: Path, **flags):
        key = tmp / "key"
        tmp.mkdir(parents=True, exist_ok=True)
        Keyring.generate().save(key)
        self.settings = Settings(database_path=tmp / "panel.sqlite3", master_key_file=key,
                                 session_cookie_secure=False, allowed_hosts=("testserver",),
                                 naive_public_host="naive.example", **flags)
        self.clock = FakeClock()
        self.agent = MemoryAgentMetrics(self.clock)
        self.app = create_app(self.settings, version_client=self.agent)
        setup_metrics(self.app, self.settings, clock=self.clock)
        self.app.state.store.create_admin("owner", PASSWORD, "owner")
        self.log = Calls()
        self.agent_metrics = self.agent.metrics
        self.app.state.versions.metrics = self.log.wrap("agent", self.agent.metrics)
        self.doubles = {}
        for label, _attr, method in MANAGERS:
            double = ManagerRows()
            setattr(double, method, self.log.wrap(label, getattr(double, method)))
            self.doubles[label] = double
        state = self.app.state
        state.trusttunnel, state.amneziawg, state.telemt = (self.doubles["trusttunnel"], self.doubles["amneziawg"],
                                                            self.doubles["mtproxy"])
        state.mieru, state.naive = self.doubles["mieru"], self.doubles["naive"]
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://testserver")
        self.ops: list[dict] = []
        self.flags = flags

    def linked(self):
        return [{"node_id": n.node_id, "name": n.display_name} for n in self.app.state.nodes.list()
                if n.node_id != "local" and not n.disabled]

    async def tick(self, seconds=2.0):
        collector = self.app.state.metrics_collector
        self.log.take()
        self.clock.advance(seconds)
        await collector.tick()
        await collector.drain()
        self.ops.append({"op": "step", "advance": seconds, "calls": self.log.take(), "version": collector.version,
                         "latest": dumps(collector.latest)})

    async def get(self, path):
        response = await self.client.get(path)
        headers = {name: response.headers[name] for name in ("content-type", "cache-control", "retry-after")
                   if name in response.headers}
        self.ops.append({"op": "get", "path": path, "linked": self.linked(), "status": response.status_code,
                         "headers": headers, "body": response.text})
        return response

    def sql(self, statement):
        with self.app.state.database.transaction() as db:
            db.execute(statement)
        self.ops.append({"op": "sql", "sql": statement})

    def dump(self, name):
        return {"name": name, "flags": self.flags, "start": 1_800_000_000.0,
                "local_name": self.app.state.nodes.local().display_name, "ops": self.ops}


HISTORY_ERRORS = [
    "/api/metrics/history", "/api/metrics/history?series=", "/api/metrics/history?series=host.nope",
    "/api/metrics/history?series=host.cpu&points=5", "/api/metrics/history?series=host.cpu&points=99999",
    "/api/metrics/history?series=host.cpu&points=abc", "/api/metrics/history?series=host.cpu&points=",
    "/api/metrics/history?series=host.cpu&points=1.5", "/api/metrics/history?series=host.cpu&points=2e2",
    "/api/metrics/history?series=host.cpu&points=0x10", "/api/metrics/history?series=host.cpu&points=-1",
    "/api/metrics/history?points=5", "/api/metrics/history?points=abc&range=nope",
    "/api/metrics/history?series=host.cpu&range=2d", "/api/metrics/history?series=host.cpu&node=all",
    "/api/metrics/history?series=host.cpu&node=ghost", "/api/metrics/history?series=host.cpu&node=bad%20id",
    "/api/metrics/history?series=host.cpu&points=%EF%BC%91%EF%BC%92",
    "/api/metrics/history?series=" + ",".join(["host.cpu"] * 41),
    "/api/metrics/history?series=" + ",".join(f"{p}.{s}" for p in ("mtproxy", "naive", "mieru", "amneziawg", "trusttunnel", "x")
                                              for s in ("up_bps", "down_bps", "sessions", "clients", "connections", "up_bytes", "down_bytes")),
]
HISTORY_OK = [
    "/api/metrics/history?series=host.cpu,trusttunnel.down_bps&range=15m&points=450",
    "/api/metrics/history?series=host.cpu&points=300",
    "/api/metrics/history?series=host.cpu&points=+300",
    "/api/metrics/history?series=host.cpu&points=%20300%20",
    "/api/metrics/history?series=host.cpu&points=1_000",
    "/api/metrics/history?series=host.cpu&points=300.0",
    "/api/metrics/history?series=host.cpu&points=0300",
    "/api/metrics/history?series=host.cpu&series=net.rx_bps&range=1h&range=15m",
    "/api/metrics/history?series=%20host.cpu%20,,host.cpu,net.tx_bps&range=15m",
    "/api/metrics/history?series=host.cpu+&range=15m",
    "/api/metrics/history?node=local&series=host.mem&range=6h&points=10",
    "/api/metrics/history?series=host.cpu&range=15m&points=2000&unknown=1",
]


async def record_routes(tmp: Path) -> list[dict]:
    out = []
    # 1. the main app: trusttunnel on, a named client, ticks, every route and its validation
    rig = RouteRig(tmp / "main", trusttunnel_enabled=True)
    rig.sql("INSERT INTO clients(id,display_name,state,created_at,updated_at) VALUES('c1','Алиса «Doe»','active',1,1)")
    rig.sql("INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,origin,"
            "created_at,updated_at) VALUES('g1','c1','trusttunnel','local','alice','enabled','provisioned',1,1)")
    rig.agent.set_protocol("trusttunnel", 1000.0, 3000.0)
    rig.agent.set_protocol("amneziawg", 200.0, 800.0, source="interface")
    rig.doubles["trusttunnel"].rows = [{"username": "alice", "tx": 0, "rx": 0, "sessions": 1}]
    rig.doubles["mtproxy"].broken = True
    async with rig.client:
        await login(rig.client)
        await rig.get("/api/metrics/live")  # before the first tick
        await rig.get("/api/metrics/clients?protocol=trusttunnel")
        await rig.get("/api/metrics/summary?range=1h")
        await rig.get("/api/metrics/history?series=host.cpu&range=15m")
        for _ in range(3):
            await rig.tick()
        rig.doubles["trusttunnel"].rows = [{"username": "alice", "tx": 6000, "rx": 2000, "sessions": 1}]
        await rig.tick(5.0)
        for path in ["/api/metrics/live", "/api/metrics/live?node=local", "/api/metrics/live?node=all",
                     "/api/metrics/live?node=ghost", "/api/metrics/live?node=bad%20id", "/api/metrics/live?node=",
                     "/api/metrics/live?node=" + "a" * 65,
                     "/api/metrics/clients?protocol=trusttunnel", "/api/metrics/clients?protocol=naive",
                     "/api/metrics/clients?protocol=nope", "/api/metrics/clients",
                     "/api/metrics/summary", "/api/metrics/summary?range=1h", "/api/metrics/summary?range=2d",
                     "/api/metrics/summary?node=all&range=1h", "/api/metrics/summary?node=ghost",
                     "/api/metrics/stream?node=ghost", *HISTORY_OK, *HISTORY_ERRORS]:
            await rig.get(path)
        rig.agent.broken = True
        await rig.tick(10.0)
        await rig.get("/api/metrics/live")
        # 4 streams of this session are open: the fifth is refused
        session = rig.app.state.store.session(rig.client.cookies["panel_session"])["token_hash"]
        held = [rig.app.state.metrics_streams.acquire(session) for _ in range(4)]
        await rig.get("/api/metrics/stream")
        for lease in held:
            lease.release()
        rig.app.state.nodes.register("amsterdam", "Amsterdam", actor=ACTOR, ip="x")
        for path in ["/api/metrics/live?node=amsterdam", "/api/metrics/live?node=all",
                     "/api/metrics/history?node=amsterdam&series=host.cpu",
                     "/api/metrics/summary?node=all&range=1h", "/api/metrics/summary?node=amsterdam"]:
            await rig.get(path)
    out.append(rig.dump("main"))

    # 2. a node metrics source serves the linked nodes
    class Source:
        async def live(self, node_id):
            return {"node_id": node_id, "name": "Amsterdam", "status": "ok", "age_seconds": 1.0, "host": {"cpu_percent": 3.0},
                    "protocols": {}, "top_clients": [], "kernel_counters": "ok"} if node_id == "amsterdam" else None

        async def history(self, node_id, series, range, points):
            return {"node_id": node_id, "range": range, "series": {name: [] for name in series}}

        async def summary(self, node_id, range):
            if node_id == "berlin":
                raise RuntimeError("down")
            return {"range": range, "host": {"cpu": {"avg": 5.0}, "mem": {"avg": 7.5}},
                    "protocols": {"naive": {"total_bytes": 4000, "peak_bps": 0.0}, "mieru": {"total_bytes": 1.5, "peak_bps": None}},
                    "hours_of_day": {}, "alerts": [{}, {}], "name": "ignored", "extra": "x"}

        async def nodes(self):
            return [{"node_id": "amsterdam", "name": "Amsterdam"}]

    rig = RouteRig(tmp / "source")
    async with rig.client:
        await login(rig.client)
        for _ in range(2):
            await rig.tick()
        rig.app.state.nodes.register("amsterdam", "Amsterdam", actor=ACTOR, ip="x")
        rig.app.state.nodes.register("berlin", "Berlin", actor=ACTOR, ip="x")
        rig.app.state.metrics_source = Source()
        for path in ["/api/metrics/live?node=all", "/api/metrics/live?node=berlin",
                     "/api/metrics/history?node=amsterdam&series=host.cpu&range=6h",
                     "/api/metrics/history?node=berlin&series=host.cpu,net.rx_bps",
                     "/api/metrics/summary?node=all&range=1h", "/api/metrics/summary?node=amsterdam&range=7d"]:
            await rig.get(path)
    out.append(rig.dump("source"))

    # 3. monitoring switched off: every route answers 404, validation still comes first
    rig = RouteRig(tmp / "off", metrics_enabled=False)
    async with rig.client:
        await login(rig.client)
        for path in ["/api/metrics/clients?protocol=mieru", "/api/metrics/live", "/api/metrics/stream",
                     "/api/metrics/history?series=host.cpu", "/api/metrics/summary", "/api/metrics/live?node=ghost",
                     "/api/metrics/history?series=host.cpu&points=5", "/api/metrics/history",
                     "/api/metrics/clients"]:
            await rig.get(path)
    out.append(rig.dump("off"))
    return out


# ---- SSE frames and float vectors ----------------------------------------------------------------------------
def record_sse() -> dict:
    payloads = [
        {"reason": "max_age"}, {"reason": "session_ended"},
        {"ts": 1800000000.123, "interval": 2.0, "nodes": [{"node_id": "local", "name": "Узел «1» ✓", "age_seconds": 0.0,
                                                           "host": {"load": [0.42, 0.4, 0.3], "big": 1e16, "small": 1e-05,
                                                                    "sum": 0.1 + 0.2, "int": 7, "neg": -3.5},
                                                           "emoji": "🙂", "ctl": "a\tb\n\"q\"\\", "none": None, "t": True}]},
        [], {}, "plain", 12, 1.5,
    ]
    return {"retry": f"retry: {sse.RETRY_MS}\n\n", "ping": ": ping\n\n",
            "frames": [{"event": event, "payload": dumps(payload), "frame": sse.frame(event, payload)}
                       for event in ("snapshot", "bye") for payload in payloads],
            "limits": {"per_session": sse.PER_SESSION, "global": sse.GLOBAL, "ping": sse.PING_SECONDS,
                       "max_age": sse.MAX_AGE_SECONDS, "recheck": sse.RECHECK_SECONDS}}


def record_floats() -> dict:
    rng = random.Random(20261026)
    values = [0.25, 0.35, 0.5, 1.5, 2.5, 3.5, -0.5, -2.5, 1.0005, 2.675, 12.345, 1e16, 123456789.0125, 0.1 + 0.2,
              1800000000.0005, 1 / 3, 2 / 3, 89.95, 90.05, 99.99, 1e-05, 5e-324, 0.0, -0.0, 4.35, 4.45, 1234.5,
              2.0, 0.75, 1.25, 1800000123.4567, 255.5, 256.5, 81.81818181818181, 18.181818181818183]
    values += [rng.uniform(0, 1000) for _ in range(150)] + [rng.uniform(1.7e9, 1.9e9) for _ in range(50)]
    values += [round(rng.uniform(0, 200), 2) for _ in range(50)] + [rng.randint(0, 2000) / 8 for _ in range(50)]
    rows = []
    for x in values:
        rows.append({"x": x, "round0": round(x), "round1": round(x, 1), "round3": round(x, 3),
                     "f1": format(x, ".1f"), "f0": format(x, ".0f"),
                     "fd60": x // 60, "fd900": x // 900, "fd3600": x // 3600})
    return {"rows": rows}


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        scenarios = await record_scenarios(Path(tmp) / "scenarios")
        routes = await record_routes(Path(tmp) / "routes")
    (OUT / "scenarios.jsonl").write_text("".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n"
                                                 for item in scenarios))
    (OUT / "routes.json").write_text(json.dumps(routes, ensure_ascii=False, indent=1) + "\n")
    (OUT / "sse.json").write_text(json.dumps(record_sse(), ensure_ascii=False, indent=1) + "\n")
    (OUT / "floats.json").write_text(json.dumps(record_floats(), ensure_ascii=False, indent=1) + "\n")
    print("recorded", len(scenarios), "scenarios,", sum(len(r["ops"]) for r in routes), "route ops", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
