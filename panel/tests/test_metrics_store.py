"""Rollups, history resolution and gaps, summary maths and alert thresholds with synthetic data."""
from __future__ import annotations

import pytest

from panel.metrics.fakes import MetricsRig as Rig
from panel.metrics.store import percentile

pytestmark = pytest.mark.anyio


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path, trusttunnel_enabled=True)


def put(store, series, bucket, avg, *, count=1, peak=None, resolution=60):
    store.write({(resolution, bucket, series): [avg * count, count, avg if peak is None else peak, avg]})


def rollups(rig, resolution=60, series="host.cpu"):
    with rig.database.connect() as db:
        return [tuple(r) for r in db.execute(
            "SELECT bucket,sum,count,max,last FROM metric_rollups WHERE resolution=? AND series=? ORDER BY bucket",
            (resolution, series))]


def test_percentile_is_nearest_rank():
    assert percentile(list(range(1, 101)), 0.95) == 95
    assert percentile([], 0.95) is None


async def test_flush_writes_all_three_resolutions_in_one_pass_and_merges_the_next_flush(rig):
    rig.agent.cpu = 10.0
    for _ in range(16):
        await rig.step()  # 32 s: the collector flushes once the 30 s are over
    assert rig.collector.calls["flush"] == 1
    rows = rollups(rig)
    assert rows and sum(r[2] for r in rows) == len(
        [p for p in rig.ring.points_of("host.cpu") if p[0] <= rig.store.flushed_until])
    assert {resolution for (resolution,) in _distinct(rig, "resolution")} == {60, 900, 3600}
    before = sum(r[2] for r in rollups(rig))
    for _ in range(16):
        await rig.step()
    after = sum(r[2] for r in rollups(rig))
    assert after > before  # the second flush adds to a bucket without replacing it
    assert all(r[1] == pytest.approx(r[2] * 10.0) for r in rollups(rig))


def _distinct(rig, column):
    with rig.database.connect() as db:
        return [tuple(r) for r in db.execute(f"SELECT DISTINCT {column} FROM metric_rollups")]


async def test_prune_drops_buckets_past_each_resolutions_retention(rig):
    now = int(rig.clock.time())
    for resolution, age_days in ((60, 4), (60, 1), (900, 40), (900, 10), (3600, 401), (3600, 100)):
        put(rig.store, "host.cpu", now // resolution * resolution - age_days * 86400, 1.0, resolution=resolution)
    assert await rig.store.prune() == 3
    assert [len(rollups(rig, r)) for r in (60, 900, 3600)] == [1, 1, 1]


async def test_history_native_step_from_the_ring_with_gaps_where_the_agent_was_silent(rig):
    for i in range(30):
        rig.agent.cpu = float(i)
        if i == 10:
            rig.agent.broken = True
        if i == 16:
            rig.agent.broken = False
        await rig.step()
    body = await rig.store.history(["host.cpu"], "15m", 450)
    assert (body["source"], body["resolution"], body["step"], body["range"], body["node_id"]) == ("ring", 0, 2, "15m", "local")
    rows = body["series"]["host.cpu"]
    nulls = [row for row in rows if row[1] is None]
    assert rows[-1][1:] == [29.0, 29.0] and rows[-1][0] % 2 == 0
    inside = [row for row in nulls if rows[-30][0] <= row[0]]
    assert len(inside) >= 3 and all(row[2] is None for row in nulls)  # a gap, never a zero
    assert rows[0][0] < rows[-1][0] and len(rows) > 400


async def test_history_downsamples_to_the_requested_points_keeping_the_peak(rig):
    for i in range(30):
        rig.agent.cpu = 50.0 if i != 20 else 90.0
        await rig.step()
    body = await rig.store.history(["host.cpu"], "15m", 100)
    assert body["step"] == 10  # 900 s / 2 s = 450 native points -> every 5th
    present = [row for row in body["series"]["host.cpu"] if row[1] is not None]
    assert max(row[2] for row in present) == 90.0 and max(row[1] for row in present) < 90.0


async def test_history_beyond_the_ring_comes_from_rollups_plus_the_unflushed_tail_exactly(rig):
    for i in range(100):  # 200 s
        rig.agent.cpu = float(i)
        rig.agent.set_protocol("trusttunnel", 100.0, 0.0)
        await rig.step()
    assert rig.store.flushed_until < rig.clock.time()  # a tail the database has not got yet
    body = await rig.store.history(["host.cpu", "trusttunnel.up_bytes"], "6h", 2000)
    assert (body["source"], body["resolution"], body["step"]) == ("rollup", 60, 60)
    expected: dict[int, list[float]] = {}
    for ts, value in rig.ring.points_of("host.cpu"):
        expected.setdefault(int(ts // 60 * 60), []).append(value)
    got = {row[0]: row[1] for row in body["series"]["host.cpu"] if row[1] is not None}
    assert got.keys() == expected.keys()
    for bucket, values in expected.items():
        assert got[bucket] == pytest.approx(sum(values) / len(values), abs=0.001)
    volume = sum(row[1] for row in body["series"]["trusttunnel.up_bytes"] if row[1] is not None)
    assert volume == sum(v for _t, v in rig.ring.points_of("trusttunnel.up_bytes"))  # bytes series carry the sum


@pytest.mark.parametrize(("range_name", "points", "resolution", "step"), [
    ("6h", 2000, 60, 60), ("24h", 240, 60, 360), ("7d", 2000, 900, 900), ("30d", 2000, 900, 1800), ("90d", 2000, 3600, 7200)])
async def test_history_picks_the_rollup_resolution_by_range(rig, range_name, points, resolution, step):
    body = await rig.store.history(["host.cpu"], range_name, points)
    assert (body["source"], body["resolution"], body["step"]) == ("rollup", resolution, step)
    assert all(row[1] is None for row in body["series"]["host.cpu"])  # nothing recorded: all gaps


async def test_summary_statistics_shares_and_peaks(rig):
    now = int(rig.clock.time()) // 60 * 60
    for i in range(1, 101):  # 100 minutes of cpu averaging 1..100, peak 100 in the last one
        put(rig.store, "host.cpu", now - (101 - i) * 60, float(i), peak=float(i) + (0 if i < 100 else 0))
    put(rig.store, "host.mem", now - 120, 40.0)
    for bucket, up, down in ((now - 300, 1000, 2000), (now - 240, 1000, 2000), (now - 180, 1000, 2000)):
        put(rig.store, "trusttunnel.up_bytes", bucket, up)
        put(rig.store, "trusttunnel.down_bytes", bucket, down)
    put(rig.store, "naive.up_bytes", now - 300, 500)
    put(rig.store, "naive.down_bytes", now - 300, 1500)
    for bucket, up, down in ((now - 300, 100.0, 300.0), (now - 240, 400.0, 600.0)):
        put(rig.store, "trusttunnel.up_bps", bucket, up, peak=up * 2)
        put(rig.store, "trusttunnel.down_bps", bucket, down, peak=down * 2)
    put(rig.store, "trusttunnel.sessions", now - 240, 3.0, peak=7.0)
    put(rig.store, "trusttunnel.connections", now - 240, 4.0, peak=9.0)
    body = await rig.store.summary("24h")
    cpu = body["host"]["cpu"]
    assert (cpu["avg"], cpu["p95"], cpu["max"], cpu["max_at"]) == (50.5, 95.0, 100.0, now - 60)
    assert body["host"]["mem"]["avg"] == 40.0 and body["host"]["swap"] == {"avg": None, "p95": None, "max": None, "max_at": None}
    tt, naive = body["protocols"]["trusttunnel"], body["protocols"]["naive"]
    assert (tt["up_bytes"], tt["down_bytes"], tt["total_bytes"]) == (3000, 6000, 9000)
    assert (naive["total_bytes"], tt["share_percent"], naive["share_percent"]) == (2000, 81.8, 18.2)
    assert tt["avg_bps"] == pytest.approx(250.0 + 450.0)  # mean up + mean down
    assert (tt["peak_bps"], tt["peak_at"]) == (1200.0 + 800.0, now - 240)  # upper bound: peak up + peak down
    assert tt["connections_peak"] == 9 and body["protocols"]["naive"]["connections_peak"] is None
    assert tt["sessions_peak"] == 7 and body["protocols"]["mieru"]["total_bytes"] is None
    assert body["hours_of_day"] == {}  # only a week or more has a daily shape


async def test_summary_hours_of_day_for_a_week(rig):
    base = int(rig.clock.time()) // 3600 * 3600
    for hours_ago in range(1, 49):
        bucket = base - hours_ago * 3600
        hour = bucket // 3600 % 24
        put(rig.store, "trusttunnel.up_bps", bucket, 100.0 * (hour + 1), resolution=900)
        put(rig.store, "trusttunnel.down_bps", bucket, 50.0, resolution=900)
    body = await rig.store.summary("7d")
    hours = body["hours_of_day"]["trusttunnel"]
    assert len(hours) == 24 and all(v is not None for v in hours)
    assert hours[3] == pytest.approx(100.0 * 4 + 50.0)
    assert body["hours_of_day"]["mieru"] == [None] * 24


async def test_alerts_follow_the_plan_thresholds(rig):
    rig.agent.cpu, rig.agent.mem, rig.agent.disk, rig.agent.swap = 90.0, 95.0, 50.0, 60.0
    for _ in range(160):  # 320 s over the cpu threshold
        await rig.step()
    kinds = {a["kind"]: a for a in rig.collector.latest["alerts"]}
    assert set(kinds) == {"cpu", "mem", "swap"}
    assert kinds["cpu"]["severity"] == "warn" and kinds["mem"]["severity"] == "warn" and kinds["swap"]["severity"] == "warn"
    assert kinds["mem"]["since"] <= kinds["cpu"]["since"] and "90" in kinds["cpu"]["detail"]
    rig.agent.cpu, rig.agent.mem = 99.0, 99.0
    for _ in range(160):
        await rig.step()
    kinds = {a["kind"]: a for a in rig.collector.latest["alerts"]}
    assert kinds["cpu"]["severity"] == "critical" and kinds["mem"]["severity"] == "critical"
    rig.agent.cpu, rig.agent.mem, rig.agent.swap = 20.0, 20.0, 10.0
    for _ in range(160):
        await rig.step()
    assert rig.collector.latest["alerts"] == []


async def test_a_silent_agent_raises_a_stale_alert_after_a_minute(rig):
    await rig.step()
    rig.agent.broken = True
    await rig.step(30.0)
    assert rig.collector.latest["alerts"] == []
    await rig.step(40.0)
    alert = rig.collector.latest["alerts"][0]
    assert (alert["kind"], alert["severity"], alert["since"]) == ("stale", "warn", int(rig.clock.time()) - 70)
    await rig.step(300.0)
    assert rig.collector.latest["alerts"][0]["severity"] == "critical"


async def test_network_spike_is_three_times_the_p95_of_the_last_day(rig):
    now = int(rig.clock.time()) // 60 * 60
    for i in range(1, 200):
        put(rig.store, "net.rx_bps", now - i * 60, 100_000.0)
        put(rig.store, "net.tx_bps", now - i * 60, 100_000.0)
    rig.agent.rx_bps = rig.agent.tx_bps = 150_000.0
    for _ in range(20):
        await rig.step()
    assert rig.collector.latest["alerts"] == []  # 300 kB/s against a 200 kB/s p95
    rig.agent.rx_bps = rig.agent.tx_bps = 400_000.0
    for _ in range(20):
        await rig.step()
    [alert] = rig.collector.latest["alerts"]
    assert alert["kind"] == "net_spike" and alert["severity"] == "warn"


async def test_the_spike_baseline_is_read_once_a_minute_not_every_tick(rig, monkeypatch):
    now = int(rig.clock.time()) // 60 * 60
    for i in range(1, 200):
        put(rig.store, "net.rx_bps", now - i * 60, 100_000.0)
        put(rig.store, "net.tx_bps", now - i * 60, 100_000.0)
    reads = []
    original = rig.store._read
    monkeypatch.setattr(rig.store, "_read", lambda *a: reads.append(a) or original(*a))
    rig.agent.rx_bps = rig.agent.tx_bps = 400_000.0
    start = rig.clock.time()
    while rig.clock.time() - start < 180:
        await rig.step()
    assert rig.collector.latest["alerts"][0]["kind"] == "net_spike"
    day_reads = [a for a in reads if a[0] == ["net.rx_bps", "net.tx_bps"]]
    assert 1 <= len(day_reads) <= 4  # three minutes of ticks, a fresh day window per minute
