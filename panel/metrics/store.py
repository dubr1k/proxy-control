"""Rollups in SQLite and the read side: history, summary and alerts.

The ring holds the newest points at the native step; `metric_rollups` holds 60 s, 900 s and
3600 s buckets. A read merges both: the database has every point up to `flushed_until`, the
ring has the rest, so adding the ring's tail to the stored buckets is exact."""
from __future__ import annotations

import asyncio
import math
import time

from .model import (ALL_SERIES, LOCAL_NODE, PROTOCOLS, RANGES, RETENTION, is_bytes_series, resolution_for)

EPS = 1e-6
UPSERT = """INSERT INTO metric_rollups(resolution,bucket,node_id,series,sum,count,max,last)
  VALUES(?,?,?,?,?,?,?,?)
  ON CONFLICT(resolution,bucket,node_id,series) DO UPDATE SET
    sum=sum+excluded.sum, count=count+excluded.count, max=max(max,excluded.max), last=excluded.last"""

SUMMARY_HOST = {
    "cpu": "host.cpu", "mem": "host.mem", "swap": "host.swap", "disk": "host.disk",
    "load1": "host.load1", "net_rx_bps": "net.rx_bps", "net_tx_bps": "net.tx_bps",
}
# Alert thresholds (plan, Panel API): warn above, critical above the second number.
CPU_AVG = (85.0, 95.0)
MEM = (90.0, 97.0)
DISK = (90.0, 95.0)
SWAP = (50.0, 80.0)
STALE_SECONDS = (60.0, 300.0)
SPIKE_FACTOR = (3.0, 6.0)
SPIKE_FLOOR_BPS = 256 * 1024.0


def _bucket(ts: float, step: float) -> float:
    return math.floor(ts / step) * step


def _num(value: float | None, digits: int = 3):
    return None if value is None else round(value, digits)


def percentile(values: list[float], q: float) -> float | None:
    """Nearest-rank percentile."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(q * len(ordered)))
    return ordered[rank - 1]


class MetricsStore:
    def __init__(self, database, ring, *, interval: float = 2.0, clock=time, node_id: str = LOCAL_NODE):
        self.database, self.ring, self.interval = database, ring, interval
        self.clock, self.node_id = clock, node_id
        self.flushed_until = 0.0
        self.last_prune = 0.0

    # ---- write side -------------------------------------------------------------------------
    def pending(self) -> list[tuple[str, float, float]]:
        points = []
        for series in self.ring.series_names():
            points += [(series, ts, value) for ts, value in self.ring.points_of(series, self.flushed_until + EPS)]
        return sorted(points, key=lambda item: item[1])

    @staticmethod
    def aggregate(points) -> dict[tuple[int, int, str], list[float]]:
        rows: dict[tuple[int, int, str], list[float]] = {}
        for series, ts, value in points:
            for resolution in RETENTION:
                key = (resolution, int(ts // resolution * resolution), series)
                row = rows.get(key)
                if row is None:
                    rows[key] = [value, 1, value, value]
                else:
                    row[0] += value
                    row[1] += 1
                    row[2] = max(row[2], value)
                    row[3] = value
        return rows

    def write(self, rows: dict) -> None:
        """All rows of one flush in ONE transaction (two processes write this file)."""
        with self.database.transaction() as db:
            db.executemany(UPSERT, [(res, bucket, self.node_id, series, s, int(c), m, last)
                                    for (res, bucket, series), (s, c, m, last) in rows.items()])

    async def flush(self) -> int:
        points = self.pending()
        if not points:
            return 0
        rows = self.aggregate(points)
        await asyncio.to_thread(self.write, rows)
        self.flushed_until = max(ts for _s, ts, _v in points)
        return len(rows)

    def _prune(self, now: float) -> int:
        removed = 0
        with self.database.transaction() as db:
            for resolution, keep in RETENTION.items():
                removed += db.execute("DELETE FROM metric_rollups WHERE resolution=? AND bucket<?",
                                      (resolution, int(now - keep))).rowcount
        return removed

    async def prune(self, now: float | None = None) -> int:
        now = self.clock.time() if now is None else now
        self.last_prune = now
        return await asyncio.to_thread(self._prune, now)

    # ---- read side --------------------------------------------------------------------------
    def _read(self, series: list[str], resolution: int, start: int, end: int) -> list[tuple]:
        marks = ",".join("?" * len(series))
        with self.database.connect() as db:
            return [tuple(row) for row in db.execute(
                f"SELECT series,bucket,sum,count,max,last FROM metric_rollups WHERE node_id=? AND resolution=? "
                f"AND bucket>=? AND bucket<=? AND series IN ({marks})",
                (self.node_id, resolution, start, end, *series))]

    def _stored_before(self, start: float, oldest: float) -> bool:
        with self.database.connect() as db:
            return db.execute(
                "SELECT 1 FROM metric_rollups WHERE resolution=60 AND bucket>=? AND bucket<? AND node_id=? LIMIT 1",
                (int(_bucket(start, 60)), int(_bucket(oldest, 60)), self.node_id)).fetchone() is not None

    async def _ring_covers(self, start: float) -> bool:
        """The ring answers a short range when it reaches back to its start, or when the
        database has nothing older in that window (a fresh process, not a wrapped ring)."""
        oldest = self.ring.oldest()
        if oldest is None:
            return False
        if oldest <= start + 2 * self.interval:
            return True
        return not await asyncio.to_thread(self._stored_before, start, oldest)

    async def gather(self, series: list[str], range_seconds: int, points: int):
        """Buckets for the series over the last `range_seconds`: (mode, step, start, end, data)
        where data[series][bucket_ts] = [sum, count, max, last]."""
        end = self.clock.time()
        start = end - range_seconds
        data: dict[str, dict[float, list[float]]] = {name: {} for name in series}
        if range_seconds <= 3600 and await self._ring_covers(start):
            step = max(1, round(self.interval * max(1, math.ceil(range_seconds / self.interval / points))))
            for name in series:
                self._add(data[name], self.ring.points_of(name, start, end), step)
            return "ring", step, start, end, data
        resolution = resolution_for(range_seconds)
        step = resolution * max(1, math.ceil(range_seconds / resolution / points))
        rows = await asyncio.to_thread(self._read, series, resolution, int(_bucket(start, resolution)), int(end))
        for name, bucket, total, count, peak, last in rows:
            slot = data[name].setdefault(_bucket(bucket, step), [0.0, 0, float("-inf"), 0.0])
            slot[0] += total
            slot[1] += count
            slot[2] = max(slot[2], peak)
            slot[3] = last
        for name in series:  # the ring holds what the database has not got yet
            self._add(data[name], self.ring.points_of(name, max(start, self.flushed_until + EPS), end), step)
        return "rollup", step, start, end, data

    @staticmethod
    def _add(target: dict, points, step: float) -> None:
        for ts, value in points:
            slot = target.setdefault(_bucket(ts, step), [0.0, 0, float("-inf"), 0.0])
            slot[0] += value
            slot[1] += 1
            slot[2] = max(slot[2], value)
            slot[3] = value

    async def history(self, series: list[str], range_name: str, points: int) -> dict:
        seconds = RANGES[range_name]
        mode, step, start, end, data = await self.gather(series, seconds, points)
        grid = []
        bucket = _bucket(start, step)
        while bucket <= end:
            grid.append(bucket)
            bucket += step
        out = {}
        for name in series:
            rows = []
            for bucket in grid:
                slot = data[name].get(bucket)
                if slot is None:
                    rows.append([int(bucket), None, None])
                else:
                    value = slot[0] if is_bytes_series(name) else slot[0] / slot[1]
                    rows.append([int(bucket), _num(value), _num(slot[2])])
            out[name] = rows
        return {"node_id": self.node_id, "range": range_name, "step": step, "from": int(start), "to": int(end),
                "source": mode,
                "resolution": 0 if mode == "ring" else resolution_for(seconds), "series": out}

    async def summary(self, range_name: str) -> dict:
        seconds = RANGES[range_name]
        mode, step, start, end, data = await self.gather(list(ALL_SERIES), seconds, 2000)

        def stats(name: str) -> dict:
            slots = data.get(name, {})
            if not slots:
                return {"avg": None, "p95": None, "max": None, "max_at": None}
            count = sum(slot[1] for slot in slots.values())
            top = max(slots.items(), key=lambda item: item[1][2])
            return {"avg": _num(sum(slot[0] for slot in slots.values()) / count),
                    "p95": _num(percentile([slot[0] / slot[1] for slot in slots.values()], 0.95)),
                    "max": _num(top[1][2]), "max_at": int(top[0])}

        def avg(name: str) -> float | None:
            slots = data.get(name, {})
            count = sum(slot[1] for slot in slots.values())
            return sum(slot[0] for slot in slots.values()) / count if count else None

        host = {key: stats(series) for key, series in SUMMARY_HOST.items()}
        totals = {}
        for proto in PROTOCOLS:
            up_b = sum(slot[0] for slot in data[f"{proto}.up_bytes"].values())
            down_b = sum(slot[0] for slot in data[f"{proto}.down_bytes"].values())
            has_bytes = bool(data[f"{proto}.up_bytes"] or data[f"{proto}.down_bytes"])
            rate_parts = [v for v in (avg(f"{proto}.up_bps"), avg(f"{proto}.down_bps")) if v is not None]
            peaks = {}
            for direction in ("up_bps", "down_bps"):
                for bucket, slot in data[f"{proto}.{direction}"].items():
                    peaks[bucket] = peaks.get(bucket, 0.0) + slot[2]
            peak = max(peaks.items(), key=lambda item: item[1]) if peaks else None
            sessions = data[f"{proto}.sessions"]
            totals[proto] = {
                "up_bytes": int(up_b) if has_bytes else None, "down_bytes": int(down_b) if has_bytes else None,
                "total_bytes": int(up_b + down_b) if has_bytes else None,
                "avg_bps": _num(sum(rate_parts)) if rate_parts else None,
                "peak_bps": _num(peak[1]) if peak else None, "peak_at": int(peak[0]) if peak else None,
                "share_percent": None,
                "sessions_peak": int(max(slot[2] for slot in sessions.values())) if sessions else None,
            }
        grand = sum(row["total_bytes"] or 0 for row in totals.values())
        for row in totals.values():
            if row["total_bytes"] is not None and grand > 0:
                row["share_percent"] = round(row["total_bytes"] * 100.0 / grand, 1)
        hours = {}
        if seconds >= RANGES["7d"]:
            for proto in PROTOCOLS:
                cells: dict[int, dict[str, list[float]]] = {}
                for direction in ("up_bps", "down_bps"):
                    for bucket, slot in data[f"{proto}.{direction}"].items():
                        cell = cells.setdefault(int(bucket // 3600 % 24), {}).setdefault(direction, [0.0, 0])
                        cell[0] += slot[0]
                        cell[1] += slot[1]
                hours[proto] = [_num(sum(c[0] / c[1] for c in cells[h].values())) if h in cells else None
                                for h in range(24)]
        return {"node_id": self.node_id, "range": range_name, "from": int(start), "to": int(end), "step": step,
                "source": mode, "host": host, "protocols": totals, "hours_of_day": hours}

    # ---- alerts -----------------------------------------------------------------------------
    @staticmethod
    def _tail_since(points, over: float) -> float | None:
        since = None
        for ts, value in reversed(points):
            if value <= over:
                break
            since = ts
        return since

    async def alerts(self, status: str, age_seconds: float | None) -> list[dict]:
        now = self.clock.time()
        found: list[dict] = []

        def add(kind, level, since, detail):
            found.append({"kind": kind, "severity": level, "since": int(since), "detail": detail})

        if status in ("stale", "unavailable") and (age_seconds is None or age_seconds > STALE_SECONDS[0]):
            level = "critical" if age_seconds is None or age_seconds > STALE_SECONDS[1] else "warn"
            add("stale", level, now - (age_seconds or 0), f"no host sample for {int(age_seconds or 0)} s")
        window = self.ring.points_of("host.cpu", now - 300, now)
        if window and window[0][0] <= now - 300 + 2 * self.interval:
            mean = sum(v for _t, v in window) / len(window)
            if mean > CPU_AVG[0]:
                since = self._tail_since(window, CPU_AVG[0]) or window[0][0]
                add("cpu", "critical" if mean > CPU_AVG[1] else "warn", since, f"cpu {mean:.1f}% average over 5 min")
        for kind, series, (warn, crit) in (("mem", "host.mem", MEM), ("disk", "host.disk", DISK),
                                           ("swap", "host.swap", SWAP)):
            recent = self.ring.points_of(series, now - 3600, now)
            if recent and recent[-1][1] > warn:
                add(kind, "critical" if recent[-1][1] > crit else "warn",
                    self._tail_since(recent, warn) or recent[-1][0], f"{kind} {recent[-1][1]:.1f}%")
        rx, tx = self.ring.points_of("net.rx_bps", now - 30, now), self.ring.points_of("net.tx_bps", now - 30, now)
        if rx and tx:
            current = (sum(v for _t, v in rx) / len(rx)) + (sum(v for _t, v in tx) / len(tx))
            if current > SPIKE_FLOOR_BPS:
                baseline = await asyncio.to_thread(self._baseline, int(now))
                if baseline and current > SPIKE_FACTOR[0] * baseline:
                    add("net_spike", "critical" if current > SPIKE_FACTOR[1] * baseline else "warn", now - 30,
                        f"network {current:.0f} B/s against p95 {baseline:.0f} B/s of the last 24 h")
        return found

    def _baseline(self, now: int) -> float | None:
        """p95 of the last 24 h of rx+tx, from the 60 s rollups; None until there is a day-ish of shape."""
        rows = self._read(["net.rx_bps", "net.tx_bps"], 60, (now - 86400) // 60 * 60, now)
        by_bucket: dict[int, float] = {}
        for _name, bucket, total, count, _peak, _last in rows:
            by_bucket[bucket] = by_bucket.get(bucket, 0.0) + total / count
        return percentile(list(by_bucket.values()), 0.95) if len(by_bucket) >= 60 else None
