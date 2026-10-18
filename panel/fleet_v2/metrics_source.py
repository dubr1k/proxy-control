"""The central side of the fleet meters: `FleetMetricsSource` serves the linked nodes' live
entries, history and summary to `/api/metrics/*`.

Pull on demand only: nothing polls while nobody watches. Per node, a 2 s cache and one request in
flight at a time (concurrent callers share it); at most 8 node calls run at once; each call has a
3 s budget. A failing node keeps its last good entry for 120 s as `stale`, then turns `unavailable`;
a node that does not advertise `metrics.v1` is `unsupported`."""
from __future__ import annotations

import asyncio
import copy
import time

from ..metrics.model import LOCAL_NODE
from .client import NodeAuthFailed, NodeRejected, NodeUnreachable

CAPABILITY = "metrics.v1"
TTL_SECONDS = 2.0
CALL_TIMEOUT = 3.0
HISTORY_TIMEOUT = 10.0
STALE_SECONDS = 120.0
CONCURRENCY = 8
LIVE_BUDGET = 4.0
EMPTY = {"age_seconds": None, "host": None, "protocols": {}, "top_clients": [], "kernel_counters": None, "alerts": []}
FAILURES = (NodeUnreachable, NodeAuthFailed, NodeRejected, asyncio.TimeoutError, OSError)


class FleetMetricsSource:
    """`NodeMetricsSource` over the fleet-v2 links. The three callables keep it testable:
    `names()` -> `[{node_id, name}]`, `link_state(node_id)` -> `{online, capabilities}` or None for a
    node without a v2 link, `node_client(node_id)` -> a `NodeClient` (sync; it reads the key)."""

    def __init__(self, *, names, link_state, node_client, clock=time, ttl: float = TTL_SECONDS,
                 call_timeout: float = CALL_TIMEOUT, history_timeout: float = HISTORY_TIMEOUT,
                 stale_seconds: float = STALE_SECONDS, concurrency: int = CONCURRENCY):
        self._names, self._link_state, self._node_client = names, link_state, node_client
        self.clock, self.ttl, self.call_timeout = clock, ttl, call_timeout
        self.history_timeout, self.stale_seconds = history_timeout, stale_seconds
        self._slots = asyncio.Semaphore(concurrency)
        self._cache: dict[str, tuple[float, dict]] = {}
        self._good: dict[str, tuple[float, dict]] = {}
        self._inflight: dict[tuple, asyncio.Task] = {}

    # ---- the NodeMetricsSource surface -------------------------------------------------------
    async def nodes(self) -> list[dict]:
        return await asyncio.to_thread(self._names)

    async def live(self, node_id: str) -> dict | None:
        mono = self.clock.monotonic()
        cached = self._cache.get(node_id)
        if cached is not None and mono - cached[0] < self.ttl:
            return copy.deepcopy(cached[1])
        return copy.deepcopy(await self._single_flight(("live", node_id), lambda: self._refresh(node_id)))

    async def live_many(self, items: list[dict], budget: float = LIVE_BUDGET) -> list[dict]:
        """One entry per item, in order, within `budget` seconds. A node that is late is answered
        from its last good entry as `stale` (else `unavailable`); its call keeps running and
        feeds the cache for the next tick."""
        tasks = [asyncio.ensure_future(self.live(item["node_id"])) for item in items]
        if tasks:
            await asyncio.wait(tasks, timeout=budget)
        out = []
        for item, task in zip(items, tasks):
            result = None
            if task.done() and not task.cancelled() and task.exception() is None:
                result = task.result()
            elif not task.done():
                task.cancel()  # only this waiter; the shared request goes on
            elif not task.cancelled():
                task.exception()
            out.append(result or self._failed(item["node_id"], self._name(item["node_id"], item)))
        return out

    async def history(self, node_id: str, series: list[str], range: str, points: int) -> dict | None:
        state, name = self._state(node_id)
        base = {"node_id": node_id, "name": name, "range": range, "series": {}}
        if state is None or CAPABILITY not in state["capabilities"]:
            return {**base, "status": "unsupported"}
        if not state["online"]:
            return {**base, "status": "unavailable"}
        key = ("history", node_id, tuple(series), range, points)

        async def fetch():
            client = await asyncio.to_thread(self._node_client, node_id)
            return await client.metrics_history(series, range, points, timeout=self.history_timeout)

        try:
            body = await self._single_flight(key, lambda: self._guarded(fetch, self.history_timeout + 1))
        except FAILURES as exc:
            return {**base, "status": "unsupported" if _missing(exc) else "unavailable"}
        return {**body, "node_id": node_id, "name": name, "status": body.get("status", "ok")}

    async def summary(self, node_id: str, range: str) -> dict | None:
        state, name = self._state(node_id)
        base = {"node_id": node_id, "name": name, "host": None, "protocols": {}, "hours_of_day": {}, "alerts": []}
        if state is None or CAPABILITY not in state["capabilities"]:
            return {**base, "status": "unsupported"}
        if not state["online"]:
            return {**base, "status": "unavailable"}

        async def fetch():
            client = await asyncio.to_thread(self._node_client, node_id)
            return await client.metrics_summary(range, timeout=self.history_timeout)

        try:
            body = await self._single_flight(("summary", node_id, range),
                                             lambda: self._guarded(fetch, self.history_timeout + 1))
        except FAILURES as exc:
            return {**base, "status": "unsupported" if _missing(exc) else "unavailable"}
        return {**base, "status": "ok", **body, "node_id": node_id, "name": name}

    # ---- internals ---------------------------------------------------------------------------
    def _state(self, node_id: str) -> tuple[dict | None, str]:
        try:
            state = self._link_state(node_id)
        except Exception:  # noqa: BLE001
            state = None
        return state, self._name(node_id)

    def _name(self, node_id: str, item: dict | None = None) -> str:
        if item is not None and item.get("name"):
            return item["name"]
        try:
            for row in self._names():
                if row["node_id"] == node_id:
                    return row["name"]
        except Exception:  # noqa: BLE001
            pass
        return node_id

    async def _single_flight(self, key: tuple, factory):
        task = self._inflight.get(key)
        if task is None:
            task = asyncio.ensure_future(factory())
            self._inflight[key] = task
            task.add_done_callback(lambda done, key=key: (self._inflight.pop(key, None), done.cancelled() or done.exception()))
        # shield: a waiter that gives up (budget, client gone) must not cancel the shared request
        return await asyncio.shield(task)

    async def _guarded(self, fetch, timeout: float):
        async with self._slots:
            return await asyncio.wait_for(fetch(), timeout)

    def _failed(self, node_id: str, name: str) -> dict:
        """The last good entry as `stale` with its age, else `unavailable`."""
        good = self._good.get(node_id)
        now = self.clock.monotonic()
        if good is not None and now - good[0] <= self.stale_seconds:
            entry = copy.deepcopy(good[1])
            entry["status"] = "stale"
            entry["age_seconds"] = round(now - good[0] + (good[1].get("age_seconds") or 0.0), 1)
            entry["node_id"], entry["name"] = node_id, name
            return entry
        return {"node_id": node_id, "name": name, "status": "unavailable", **copy.deepcopy(EMPTY)}

    async def _refresh(self, node_id: str) -> dict:
        state, name = self._state(node_id)
        if state is None or CAPABILITY not in state["capabilities"]:
            entry = {"node_id": node_id, "name": name, "status": "unsupported", **copy.deepcopy(EMPTY)}
        elif not state["online"]:
            entry = {"node_id": node_id, "name": name, "status": "unavailable", **copy.deepcopy(EMPTY)}
        else:
            entry = await self._pull(node_id, name)
        self._cache[node_id] = (self.clock.monotonic(), entry)
        return entry

    async def _pull(self, node_id: str, name: str) -> dict:
        async def fetch():
            client = await asyncio.to_thread(self._node_client, node_id)
            return await client.metrics(timeout=self.call_timeout)

        try:
            body = await self._guarded(fetch, self.call_timeout)
        except FAILURES as exc:
            if _missing(exc):
                return {"node_id": node_id, "name": name, "status": "unsupported", **copy.deepcopy(EMPTY)}
            return self._failed(node_id, name)
        except Exception:  # noqa: BLE001 — a surprise from one node never reaches the others
            return self._failed(node_id, name)
        if not isinstance(body, dict) or "status" not in body:
            return self._failed(node_id, name)
        entry = {**copy.deepcopy(EMPTY), **body, "node_id": node_id, "name": name}
        self._good[node_id] = (self.clock.monotonic(), entry)
        return entry


def _missing(exc: Exception) -> bool:
    """The node answered 404: it does not serve the meters (switched off since its last identity)."""
    return isinstance(exc, NodeRejected) and exc.status == 404


def build_fleet_metrics_source(app) -> FleetMetricsSource:
    """Wire the source to the panel's links and node registry (central side)."""
    links, nodes = app.state.links, app.state.nodes

    def names() -> list[dict]:
        return [{"node_id": n.node_id, "name": n.display_name} for n in nodes.list()
                if n.node_id != LOCAL_NODE and not n.disabled]

    def link_state(node_id: str) -> dict | None:
        with app.state.database.connect() as db:
            try:
                link = links.link(db, node_id)
            except KeyError:
                return None
        capabilities = link["identity"].get("capabilities") if isinstance(link.get("identity"), dict) else None
        return {"online": link["status"] == "online" and bool(link.get("enabled", 1)),
                "capabilities": list(capabilities or [])}

    return FleetMetricsSource(names=names, link_state=link_state, node_client=links.client_for)
