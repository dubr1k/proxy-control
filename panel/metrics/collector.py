"""The panel-side sampler: the host agent's `/v1/metrics` every tick, the protocol managers on
their own slower cadence, the ring, the rollup flush and the latest snapshot the API serves."""
from __future__ import annotations

import asyncio
import logging
import time

from .model import LOCAL_NODE, PROTOCOLS, NodeMetricsSource
from .rates import ClientRates, fold
from .ring import SeriesRing
from .store import MetricsStore

log = logging.getLogger(__name__)

AGENT_TIMEOUT = 3.5
MANAGER_TIMEOUT = 4.0
NAIVE_TIMEOUT = 15.0
# Seconds between manager polls. Telemt answers with every user, NaiveProxy's `traffic()` scans
# a log: it is the expensive one. Mieru reads mita's own counters (one short CLI call).
CADENCE = {"trusttunnel": 5.0, "amneziawg": 5.0, "mieru": 5.0, "mtproxy": 15.0, "naive": 15.0}
# NaiveProxy's access log is written when a CONNECT closes: its rate is averaged over this window
NAIVE_WINDOW = 60.0
FLUSH_SECONDS = 30.0
PRUNE_SECONDS = 3600.0
REFRESH_NAMES_SECONDS = 60.0
HANDSHAKE_FRESH_SECONDS = 180
TOP_CLIENTS = 10


def _int(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _num(value) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


def host_values(host) -> dict[str, float | None]:
    """The host series of one agent sample; a field the agent does not report stays missing."""
    if not isinstance(host, dict):
        return {}

    def section(name):
        value = host.get(name)
        return value if isinstance(value, dict) else {}

    load = host.get("load")
    net, disk = section("net"), section("disk")
    return {
        "host.cpu": _num(host.get("cpu_percent")),
        "host.mem": _num(section("mem").get("percent")),
        "host.swap": _num(section("swap").get("percent")),
        "host.disk": _num(disk.get("percent")),
        "host.disk_read_bps": _num(disk.get("read_bps")),
        "host.disk_write_bps": _num(disk.get("write_bps")),
        "host.load1": _num(load[0]) if isinstance(load, list) and load else None,
        "net.rx_bps": _num(net.get("rx_bps")),
        "net.tx_bps": _num(net.get("tx_bps")),
    }


class MetricsCollector:
    def __init__(self, app_state, settings, *, store: MetricsStore, ring: SeriesRing, interval: float | None = None,
                 clock=time, sleep=None, source: NodeMetricsSource | None = None):
        self.state, self.settings, self.store, self.ring = app_state, settings, store, ring
        self.interval = max(0.5, float(interval if interval is not None else settings.metrics_interval_seconds))
        self.clock, self._sleep, self.source = clock, sleep, source
        self._stop = asyncio.Event()
        self._event = asyncio.Event()
        self.latest: dict | None = None  # this panel's node entry
        self.version = 0
        self.rates = ClientRates()
        self._last_agent: dict | None = None
        self._agent_now: dict | None = None  # the agent sample of the latest tick (None when it failed)
        self._last_agent_wall: float | None = None
        self._kernel_prev: dict[str, tuple[float, float]] = {}
        self._kernel_seen: dict[str, tuple[float, float, float]] = {}  # protocol -> (agent ts, up, down) of the last read
        self._derived: dict[str, tuple[float, float]] = {}  # protocol -> (up_bps, down_bps) between the last two reads
        self._manager: dict[str, dict] = {}
        self._last_poll: dict[str, float] = {}
        self._inflight: dict[str, asyncio.Task] = {}
        self._names: dict[tuple[str, str], str] = {}
        self._node_name = LOCAL_NODE
        self._names_at = -1e9
        self._last_flush = self.clock.monotonic()
        self._last_prune = self.clock.monotonic()
        self.calls = {"agent": 0, "flush": 0}

    # ---- lifecycle --------------------------------------------------------------------------
    async def run_forever(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    await self.tick()
                except Exception:  # noqa: BLE001 — a bad tick must not end the monitor
                    log.warning("metrics tick failed; retrying", exc_info=True)
                await self._wait(self.interval)
        finally:
            for task in self._inflight.values():
                task.cancel()
            await asyncio.gather(*self._inflight.values(), return_exceptions=True)

    async def _wait(self, seconds: float) -> None:
        if self._sleep is not None:
            await self._sleep(seconds)
            return
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    def stop(self) -> None:
        self._stop.set()

    # ---- readers ----------------------------------------------------------------------------
    def snapshot(self) -> dict | None:
        """The live envelope for this panel's node, or None before the first tick."""
        if self.latest is None:
            return None
        return {"ts": round(self.clock.time(), 3), "interval": self.interval, "nodes": [self.latest]}

    def next_event(self) -> asyncio.Event:
        """Set when the next snapshot is ready (a fresh event per tick)."""
        return self._event

    async def drain(self) -> None:
        """Wait for the manager polls in flight (tests and shutdown)."""
        pending = [task for task in self._inflight.values() if not task.done()]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    # ---- one tick ---------------------------------------------------------------------------
    async def tick(self) -> None:
        mono, wall = self.clock.monotonic(), self.clock.time()
        if mono - self._names_at >= REFRESH_NAMES_SECONDS:
            self._names_at = mono
            await self._refresh_names()
        agent = await self._fetch_agent()
        self._agent_now = agent
        self._derived = self._derive_rates(agent) if agent is not None else {}
        if agent is not None:
            self._last_agent, self._last_agent_wall = agent, wall
        self._launch_due(mono, agent or self._last_agent)
        self.rates.prune(mono)
        node = self._build(agent, wall, mono)
        values = self._record(agent, mono)
        self.ring.add_sample(wall, values)
        node["alerts"] = await self.store.alerts(node["status"], node["age_seconds"])
        self.latest = node
        self.version += 1
        previous, self._event = self._event, asyncio.Event()
        previous.set()
        if mono - self._last_flush >= FLUSH_SECONDS:
            self._last_flush = mono
            try:
                await self.store.flush()
                self.calls["flush"] += 1
            except Exception:  # noqa: BLE001 — the ring keeps the points for the next flush
                log.warning("metrics flush failed; retrying", exc_info=True)
        if mono - self._last_prune >= PRUNE_SECONDS:
            self._last_prune = mono
            try:
                await self.store.prune()
            except Exception:  # noqa: BLE001
                log.warning("metrics prune failed; retrying", exc_info=True)

    async def _fetch_agent(self) -> dict | None:
        fetch = getattr(self.state.versions, "metrics", None)
        if fetch is None:
            return None
        self.calls["agent"] += 1
        try:
            sample = await asyncio.wait_for(fetch(), AGENT_TIMEOUT)
        except Exception:  # noqa: BLE001 — a wedged agent costs the sample, not the monitor
            return None
        return sample if isinstance(sample, dict) and isinstance(sample.get("host"), dict) else None

    def _derive_rates(self, agent: dict) -> dict[str, tuple[float, float]]:
        """Protocol rates from the cumulative counters between this read and the previous one. The agent's own
        `up_bps` is one second of a bursty flow; read every 2 s it aliases with the sender's rhythm. The
        growth over the whole panel tick counts every byte once. A reset counter yields its reading."""
        ts = _num(agent.get("ts"))
        out: dict[str, tuple[float, float]] = {}
        protocols = agent.get("protocols")
        if ts is None or not isinstance(protocols, dict):
            return out
        for protocol, row in protocols.items():
            up, down = (_num(row.get("up_bytes")), _num(row.get("down_bytes"))) if isinstance(row, dict) else (None, None)
            if up is None or down is None:
                continue
            seen = self._kernel_seen.get(protocol)
            if seen is not None and ts - seen[0] < 0.5:
                if ts - seen[0] >= 0:
                    continue  # the same sample again: keep the older baseline
                seen = None  # the agent's clock went back: start over
            self._kernel_seen[protocol] = (ts, up, down)
            if seen is not None:
                span = ts - seen[0]
                out[protocol] = (fold(seen[1], up) / span, fold(seen[2], down) / span)
        return out

    async def _refresh_names(self) -> None:
        def read():
            with self.state.database.connect() as db:
                rows = db.execute("""SELECT g.protocol,g.runtime_username,c.display_name FROM access_grants g
                                     JOIN clients c ON c.id=g.client_id WHERE g.node_id=?""", (LOCAL_NODE,)).fetchall()
            name = LOCAL_NODE
            nodes = getattr(self.state, "nodes", None)
            if nodes is not None:
                try:
                    name = nodes.local().display_name or LOCAL_NODE
                except Exception:  # noqa: BLE001
                    pass
            return {(r[0], r[1]): r[2] for r in rows}, name

        try:
            self._names, self._node_name = await asyncio.to_thread(read)
        except Exception:  # noqa: BLE001 — names are decoration
            pass

    # ---- manager polls ----------------------------------------------------------------------
    def _kernel_has(self, protocol: str, agent: dict | None) -> bool:
        if not agent or agent.get("kernel_counters") != "ok":
            return False
        entry = (agent.get("protocols") or {}).get(protocol)
        return isinstance(entry, dict) and _num(entry.get("up_bps")) is not None

    def _wanted(self, protocol: str, agent: dict | None) -> bool:
        s = self.settings
        # naive and mieru are read even when the kernel counts their port: the kernel sees one
        # shared port, only the manager knows which user the bytes belong to (the clients table).
        return {"trusttunnel": s.trusttunnel_enabled, "amneziawg": s.amneziawg_enabled, "mtproxy": True,
                "naive": bool(s.naive_enabled), "mieru": bool(s.mieru_enabled)}[protocol]

    def _launch_due(self, mono: float, agent: dict | None) -> None:
        for protocol, every in CADENCE.items():
            task = self._inflight.get(protocol)
            if (task is not None and not task.done()) or not self._wanted(protocol, agent):
                continue
            if mono - self._last_poll.get(protocol, -1e9) < max(every, self.interval):
                continue
            self._last_poll[protocol] = mono
            self._inflight[protocol] = asyncio.create_task(self._poll(protocol, mono))

    async def _poll(self, protocol: str, mono: float) -> None:
        state = self._manager.setdefault(protocol, {"cum_up": 0.0, "cum_down": 0.0, "pending_up": 0.0,
                                                    "pending_down": 0.0, "ok": False, "at": mono})
        try:
            timeout = NAIVE_TIMEOUT if protocol == "naive" else MANAGER_TIMEOUT
            result = await asyncio.wait_for(getattr(self, f"_read_{protocol}")(mono), timeout)
        except Exception:  # noqa: BLE001 — the protocol turns unavailable, nothing else changes
            state["ok"] = False
            self._refresh_latest()
            return
        delta_up, delta_down = result.pop("delta_up", 0.0), result.pop("delta_down", 0.0)
        state.update(result, ok=True, at=mono)
        state["cum_up"] += delta_up
        state["cum_down"] += delta_down
        state["pending_up"] += delta_up
        state["pending_down"] += delta_down
        self._refresh_latest()

    def _fold_rows(self, protocol: str, rows, mono: float, window: float | None = None) -> dict:
        """Feed (username, up, down, total) readings; return the poll's aggregate."""
        up_bps = down_bps = total_bps = 0.0
        delta_up = delta_down = 0.0
        directional = True
        for username, up, down, total in rows:
            rate = self.rates.update(protocol, username, mono, up=up, down=down, total=total, window=window)
            if rate is None:
                continue
            total_bps += rate.total_bps
            delta_up += rate.up_delta
            delta_down += rate.down_delta
            if rate.up_bps is None or rate.down_bps is None:
                directional = False
            else:
                up_bps += rate.up_bps
                down_bps += rate.down_bps
        return {"up_bps": up_bps if directional else None, "down_bps": down_bps if directional else None,
                "total_bps": total_bps, "delta_up": delta_up, "delta_down": delta_down,
                "directional": directional}

    async def _read_trusttunnel(self, mono: float) -> dict:
        clients = [c for c in await self.state.trusttunnel.clients() if isinstance(c, dict)]
        # The manager names the endpoint's directions: `tx` is its inbound (bytes fetched for the client = the
        # client's DOWNLOAD, measured live against real clients), `rx` its outbound (the client's UPLOAD).
        rows = [(c.get("username"), c.get("rx"), c.get("tx"), None) for c in clients if isinstance(c.get("username"), str)]
        out = self._fold_rows("trusttunnel", rows, mono)
        out["sessions"] = sum(_int(c.get("sessions")) or 0 for c in clients)
        out["clients"] = sum(1 for c in clients if (_int(c.get("sessions")) or 0) > 0)
        return out

    async def _read_amneziawg(self, mono: float) -> dict:
        peers = [p for p in await self.state.amneziawg.peers() if isinstance(p, dict)]
        rows = [(p.get("username"), p.get("rx"), p.get("tx"), None) for p in peers if isinstance(p.get("username"), str)]
        out = self._fold_rows("amneziawg", rows, mono)
        now = self.clock.time()
        active = sum(1 for p in peers if _int(p.get("latest_handshake")) and now - p["latest_handshake"] < HANDSHAKE_FRESH_SECONDS)
        out["sessions"] = out["clients"] = active
        return out

    async def _read_mtproxy(self, mono: float) -> dict:
        users = [u for u in await self.state.telemt.list_users() if isinstance(u, dict)]
        rows = [(u.get("username"), None, None, u.get("total_octets")) for u in users if isinstance(u.get("username"), str)]
        out = self._fold_rows("mtproxy", rows, mono)
        connections = [_int(u.get("current_connections")) or 0 for u in users]
        out["sessions"] = sum(connections)
        out["clients"] = sum(1 for n in connections if n > 0)
        return out

    async def _read_mieru(self, mono: float) -> dict:
        data = await self.state.mieru.traffic()
        users = data.get("users") if isinstance(data, dict) else None
        rows = [(r.get("username"), r.get("upload_bytes"), r.get("download_bytes"), None)
                for r in users or [] if isinstance(r, dict) and isinstance(r.get("username"), str)]
        out = self._fold_rows("mieru", rows, mono)
        out["sessions"] = out["clients"] = None
        return out

    async def _read_naive(self, mono: float) -> dict:
        data = await self.state.naive.traffic()
        users = data.get("users") if isinstance(data, dict) else None
        rows = [(r.get("username"), r.get("upload_bytes"), r.get("download_bytes"), None)
                for r in users or [] if isinstance(r, dict) and isinstance(r.get("username"), str)]
        out = self._fold_rows("naive", rows, mono, window=NAIVE_WINDOW)
        out["sessions"] = out["clients"] = None
        return out

    # ---- snapshot ---------------------------------------------------------------------------
    def _refresh_latest(self) -> None:
        """A manager answered (or failed): show it now instead of at the next tick."""
        if self.latest is None:
            return
        mono = self.clock.monotonic()
        self.latest["protocols"] = {p: self._protocol_entry(p, self._agent_now, mono) for p in PROTOCOLS}
        self.latest["top_clients"] = self._top_clients(mono)

    def _fresh(self, protocol: str, mono: float) -> dict | None:
        state = self._manager.get(protocol)
        if not state or not state.get("ok") or "total_bps" not in state:
            return None
        return state if mono - state["at"] <= 3 * max(CADENCE[protocol], self.interval) else None

    def _protocol_entry(self, protocol: str, agent: dict | None, mono: float) -> dict:
        enabled = {"mtproxy": True, "naive": self.settings.naive_enabled, "mieru": self.settings.mieru_enabled,
                   "amneziawg": self.settings.amneziawg_enabled, "trusttunnel": self.settings.trusttunnel_enabled}[protocol]
        entry = {"available": False, "live": False, "source": None, "up_bps": None, "down_bps": None,
                 "total_bps": None, "up_bytes": None, "down_bytes": None, "sessions": None, "clients": None,
                 "connections": None}
        kernel = (agent or {}).get("protocols", {}).get(protocol) if isinstance(agent, dict) else None
        manager = self._fresh(protocol, mono) if protocol in CADENCE else None
        if self._kernel_has(protocol, agent):
            up, down = _num(kernel.get("up_bps")), _num(kernel.get("down_bps"))
            if agent is self._agent_now and protocol in self._derived:
                up, down = (round(value, 1) for value in self._derived[protocol])
            entry.update(available=True, live=True, source=kernel.get("source") if kernel.get("source") in ("kernel", "interface") else "kernel",
                         up_bps=up, down_bps=down, total_bps=(up or 0.0) + (down or 0.0),
                         up_bytes=_int(kernel.get("up_bytes")), down_bytes=_int(kernel.get("down_bytes")),
                         connections=_int(kernel.get("connections")))
        elif manager is not None:
            entry.update(available=True, live=protocol != "naive", source="manager",
                         up_bps=manager["up_bps"], down_bps=manager["down_bps"], total_bps=manager["total_bps"])
            if manager["directional"]:
                entry.update(up_bytes=int(manager["cum_up"]), down_bytes=int(manager["cum_down"]))
        elif not enabled:
            entry["reason"] = "disabled"
        elif protocol in CADENCE:
            entry["reason"] = "manager_unavailable" if self._manager.get(protocol) else "pending"
        status = self._manager.get(protocol)
        if status and status.get("ok") and manager is not None:
            entry["sessions"], entry["clients"] = status.get("sessions"), status.get("clients")
        return entry

    def client_rates(self, protocol: str) -> dict[str, dict]:
        """Every client of a protocol with a fresh rate (idle ones included, at zero): what the
        protocol pages print next to a user. Empty when the protocol is not measured per client."""
        if protocol not in CADENCE or not self._wanted(protocol, self._last_agent):
            return {}
        mono = self.clock.monotonic()
        window = 3 * max(CADENCE[protocol], self.interval)
        return {username: {"up_bps": _num(rate.up_bps) if rate.up_bps is not None else None,
                           "down_bps": _num(rate.down_bps) if rate.down_bps is not None else None,
                           "total_bps": rate.total_bps}
                for username, rate in self.rates.current(protocol, mono, window).items()}

    def _top_clients(self, mono: float) -> list[dict]:
        rows = []
        for protocol in CADENCE:
            if not self._wanted(protocol, self._last_agent):
                continue
            for username, rate in self.rates.current(protocol, mono, 3 * max(CADENCE[protocol], self.interval)).items():
                if rate.total_bps <= 0:
                    continue
                rows.append({"protocol": protocol, "username": username,
                             "client_name": self._names.get((protocol, username)),
                             "up_bps": _num(rate.up_bps) if rate.up_bps is not None else None,
                             "down_bps": _num(rate.down_bps) if rate.down_bps is not None else None,
                             "total_bps": rate.total_bps, "live": protocol != "naive"})
        rows.sort(key=lambda row: row["total_bps"], reverse=True)
        return rows[:TOP_CLIENTS]

    def _build(self, agent: dict | None, wall: float, mono: float) -> dict:
        use = agent or self._last_agent
        if agent is not None:
            status, age = "ok", 0.0
        elif self._last_agent_wall is not None:
            status, age = "stale", max(0.0, wall - self._last_agent_wall)
        else:
            status, age = "unavailable", None
        return {
            "node_id": LOCAL_NODE, "name": self._node_name, "status": status,
            "age_seconds": None if age is None else round(age, 1),
            "host": use.get("host") if use else None,
            "protocols": {p: self._protocol_entry(p, agent, mono) for p in PROTOCOLS},
            "top_clients": self._top_clients(mono),
            "kernel_counters": use.get("kernel_counters") if use else None,
        }

    # ---- the numbers that go into the ring ---------------------------------------------------
    def _record(self, agent: dict | None, mono: float) -> dict[str, float | None]:
        values: dict[str, float | None] = {}
        if agent is not None:
            values.update(host_values(agent.get("host")))
        for protocol in PROTOCOLS:
            entry = self._protocol_entry(protocol, agent, mono)
            if not entry["available"]:
                continue
            values[f"{protocol}.up_bps"], values[f"{protocol}.down_bps"] = entry["up_bps"], entry["down_bps"]
            values[f"{protocol}.sessions"], values[f"{protocol}.clients"] = entry["sessions"], entry["clients"]
            values[f"{protocol}.connections"] = entry["connections"]
            if entry["source"] in ("kernel", "interface"):
                kernel = agent["protocols"][protocol]
                up, down = _num(kernel.get("up_bytes")), _num(kernel.get("down_bytes"))
                previous = self._kernel_prev.get(protocol)
                if up is not None and down is not None:
                    self._kernel_prev[protocol] = (up, down)
                    if previous is not None:
                        values[f"{protocol}.up_bytes"] = fold(previous[0], up)
                        values[f"{protocol}.down_bytes"] = fold(previous[1], down)
            elif entry["source"] == "manager":
                state = self._manager[protocol]
                if state.get("directional"):
                    values[f"{protocol}.up_bytes"], values[f"{protocol}.down_bytes"] = state["pending_up"], state["pending_down"]
                    state["pending_up"] = state["pending_down"] = 0.0
        return values
