"""In-memory doubles for the monitor: the host agent's meter endpoint, a clock to drive and a rig
that wires a collector, a store and manager stand-ins together."""
from __future__ import annotations

from types import SimpleNamespace

from ..database import Database
from ..migrations import apply_migrations
from ..settings import Settings
from .collector import MetricsCollector
from .ring import SeriesRing
from .store import MetricsStore


class FakeClock:
    """`time()` and `monotonic()` that only move when a test says so."""

    def __init__(self, start: float = 1_800_000_000.0):
        self.now = start

    def time(self) -> float:
        return self.now

    def monotonic(self) -> float:
        return self.now - 1_700_000_000.0

    def advance(self, seconds: float) -> None:
        self.now += seconds


class MemoryAgentMetrics:
    """What `VersionClient.metrics()` returns: the agent's `/v1/metrics` sample, with cumulative
    protocol counters that grow by rate x elapsed time. `broken` makes the agent unreachable."""

    def __init__(self, clock: FakeClock | None = None, *, interval: float = 1.0):
        self.clock, self.interval = clock or FakeClock(), interval
        self.broken = False
        self.calls = 0
        self.kernel_counters = "ok"
        self.cpu, self.mem, self.swap, self.disk, self.load = 12.5, 40.0, 5.0, 30.0, 0.42
        self.disk_read_bps, self.disk_write_bps = 1000.0, 2000.0
        self.rx_bps, self.tx_bps = 5000.0, 7000.0
        self.protocols: dict[str, dict] = {}
        self._at = self.clock.now

    def set_protocol(self, name: str, up_bps: float, down_bps: float, *, source: str = "kernel") -> None:
        row = self.protocols.setdefault(name, {"up_bytes": 0, "down_bytes": 0})
        row.update(up_bps=up_bps, down_bps=down_bps, source=source)

    def reset_counters(self, name: str) -> None:
        self.protocols[name].update(up_bytes=0, down_bytes=0)

    def _grow(self) -> None:
        elapsed = self.clock.now - self._at
        self._at = self.clock.now
        for row in self.protocols.values():
            row["up_bytes"] += int(row["up_bps"] * elapsed)
            row["down_bytes"] += int(row["down_bps"] * elapsed)

    async def metrics(self):
        self.calls += 1
        if self.broken:
            return None
        self._grow()
        return {
            "ts": self.clock.now, "interval": self.interval,
            "host": {
                "cpu_percent": self.cpu, "cores": 4, "load": [self.load, 0.4, 0.3],
                "mem": {"used": 1_000, "total": 4_000, "percent": self.mem, "available": 3_000},
                "swap": {"used": 10, "total": 200, "percent": self.swap},
                "disk": {"used": 3, "total": 10, "percent": self.disk, "read_bps": self.disk_read_bps,
                         "write_bps": self.disk_write_bps, "busy_percent": 4.0},
                "net": {"rx_bps": self.rx_bps, "tx_bps": self.tx_bps, "interfaces": []},
                "uptime_seconds": 1234, "containers": [],
            },
            "protocols": {name: dict(row) for name, row in self.protocols.items()},
            "kernel_counters": self.kernel_counters,
        }


class ManagerRows:
    """A manager double that answers with whatever rows the test sets."""

    def __init__(self, rows=None):
        self.rows, self.calls, self.broken = rows or [], 0, False

    def _answer(self):
        self.calls += 1
        if self.broken:
            raise RuntimeError("manager down")
        return self.rows

    async def clients(self):
        return self._answer()

    async def peers(self):
        return self._answer()

    async def list_users(self):
        return self._answer()

    async def traffic(self):
        return {"users": self._answer()}


class MetricsRig:
    """A collector over a real (temporary) database with every dependency a double."""

    def __init__(self, tmp_path, **flags):
        self.clock = FakeClock()
        self.agent = MemoryAgentMetrics(self.clock)
        self.database = Database(tmp_path / "panel.sqlite3")
        apply_migrations(self.database)
        self.settings = Settings(database_path=tmp_path / "panel.sqlite3", metrics_interval_seconds=2.0, **flags)
        self.tt, self.awg, self.telemt, self.naive = ManagerRows(), ManagerRows(), ManagerRows(), ManagerRows()
        self.mieru = ManagerRows()
        self.state = SimpleNamespace(versions=self.agent, database=self.database, nodes=None, trusttunnel=self.tt,
                                     amneziawg=self.awg, telemt=self.telemt, naive=self.naive,
                                     mieru=self.mieru)
        self.ring = SeriesRing(900)
        self.store = MetricsStore(self.database, self.ring, interval=2.0, clock=self.clock)
        self.collector = MetricsCollector(self.state, self.settings, store=self.store, ring=self.ring, interval=2.0,
                                          clock=self.clock)

    async def step(self, seconds=2.0):
        self.clock.advance(seconds)
        await self.collector.tick()
        await self.collector.drain()
