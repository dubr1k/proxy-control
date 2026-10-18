"""`/api/metrics/*`: live snapshot, SSE stream, history and summary. Reads only; any signed-in
role. Nodes other than `local` are served by an optional `NodeMetricsSource` (fleet fan-out)."""
from __future__ import annotations

import asyncio
import re

from fastapi import Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from .model import ALL_SERIES, LOCAL_NODE, POINTS_DEFAULT, POINTS_MAX, POINTS_MIN, RANGES
from .sse import event_stream

NODE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
NO_STORE = {"Cache-Control": "no-store"}
MAX_SERIES = 40
PLACEHOLDER = {"age_seconds": None, "host": None, "protocols": {}, "top_clients": [], "kernel_counters": None,
               "alerts": []}


def register_metrics_routes(app, context) -> None:
    settings = context.settings

    def enabled():
        if not settings.metrics_enabled:
            raise HTTPException(404, "metrics_disabled")

    def check_range(value: str) -> str:
        if value not in RANGES:
            raise HTTPException(422, "range must be one of " + ", ".join(RANGES))
        return value

    async def linked_nodes() -> list[dict]:
        """Every node but this one that the panel knows: `[{node_id, name}]`."""
        def read():
            return [{"node_id": n.node_id, "name": n.display_name} for n in app.state.nodes.list()
                    if n.node_id != LOCAL_NODE and not n.disabled]

        return await asyncio.to_thread(read)

    async def check_node(node: str) -> tuple[str, list[dict]]:
        """The node ids a request addresses, after validation: `all` is this panel and every linked node."""
        if node == "all":
            return "all", await linked_nodes()
        if not NODE_ID.fullmatch(node):
            raise HTTPException(422, "unknown node")
        if node == LOCAL_NODE:
            return node, []
        known = [n for n in await linked_nodes() if n["node_id"] == node]
        if not known:
            raise HTTPException(422, "unknown node")
        return node, known

    def local_entry() -> dict:
        collector = app.state.metrics_collector
        latest = collector.latest if collector else None
        if latest is not None:
            return latest
        return {"node_id": LOCAL_NODE, "name": LOCAL_NODE, "status": "unavailable", **PLACEHOLDER}

    async def remote_entry(item: dict) -> dict:
        source = app.state.metrics_source
        if source is not None:
            try:
                entry = await source.live(item["node_id"])
            except Exception:  # noqa: BLE001 — one node never costs the whole answer
                entry = None
            if entry is not None:
                return entry
            return {"node_id": item["node_id"], "name": item["name"], "status": "unavailable", **PLACEHOLDER}
        return {"node_id": item["node_id"], "name": item["name"], "status": "unsupported", **PLACEHOLDER}

    async def live_payload(node: str, others: list[dict]) -> dict | None:
        collector = app.state.metrics_collector
        if collector is None or (node in (LOCAL_NODE, "all") and collector.latest is None):
            return None
        entries = []
        if node in (LOCAL_NODE, "all"):
            entries.append(local_entry())
        entries += await asyncio.gather(*(remote_entry(item) for item in others))
        return {"ts": round(collector.clock.time(), 3), "interval": collector.interval, "nodes": entries}

    @app.get("/api/metrics/live")
    async def live(node: str = Query(LOCAL_NODE), _user=Depends(context.current)):
        enabled()
        node, others = await check_node(node)
        payload = await live_payload(node, others)
        if payload is None:  # before the first tick: say so rather than invent a snapshot
            collector = app.state.metrics_collector
            payload = {"ts": round(collector.clock.time(), 3), "interval": collector.interval,
                       "nodes": ([local_entry()] if node in (LOCAL_NODE, "all") else [])
                       + list(await asyncio.gather(*(remote_entry(item) for item in others)))}
        return JSONResponse(payload, headers=NO_STORE)

    @app.get("/api/metrics/stream")
    async def stream(request: Request, node: str = Query(LOCAL_NODE), user=Depends(context.current)):
        enabled()
        node, others = await check_node(node)
        registry = app.state.metrics_streams
        lease = registry.acquire(user["token_hash"])
        if lease is None:
            return JSONResponse({"detail": "too many metric streams"}, 429, headers={**NO_STORE, "Retry-After": "5"})
        collector = app.state.metrics_collector

        async def alive() -> bool:
            if user.get("via") == "api-key":
                header = request.headers.get("authorization", "")
                return bool(await asyncio.to_thread(app.state.api_keys.authenticate, header[7:].strip()))
            return bool(await asyncio.to_thread(app.state.store.session, request.cookies.get("panel_session")))

        return StreamingResponse(
            event_stream(request, lease, build=lambda: live_payload(node, others), version=lambda: collector.version,
                         next_event=collector.next_event, alive=alive, clock=collector.clock),
            media_type="text/event-stream", background=BackgroundTask(lease.release),
            headers={**NO_STORE, "X-Accel-Buffering": "no", "Connection": "keep-alive"})

    @app.get("/api/metrics/history")
    async def history(node: str = Query(LOCAL_NODE), series: str = Query(...), range: str = Query("1h"),
                      points: int = Query(POINTS_DEFAULT, ge=POINTS_MIN, le=POINTS_MAX), _user=Depends(context.current)):
        enabled()
        check_range(range)
        names = list(dict.fromkeys(part.strip() for part in series.split(",") if part.strip()))
        if not names or len(names) > MAX_SERIES or any(name not in ALL_SERIES for name in names):
            raise HTTPException(422, "unknown series")
        if node == "all":
            raise HTTPException(422, "history is served for one node at a time")
        node, others = await check_node(node)
        if node != LOCAL_NODE:
            source = app.state.metrics_source
            body = None
            if source is not None:
                try:
                    body = await source.history(node, names, range, points)
                except Exception:  # noqa: BLE001
                    body = None
            if body is None:
                body = {"node_id": node, "range": range, "status": "unavailable" if source else "unsupported",
                        "series": {}}
            return JSONResponse(body, headers=NO_STORE)
        return JSONResponse({"status": "ok", **await app.state.metrics_store.history(names, range, points)},
                            headers=NO_STORE)

    async def local_summary(range: str) -> dict:
        body = await app.state.metrics_store.summary(range)
        entry = local_entry()
        body["name"], body["status"], body["age_seconds"] = entry["name"], entry["status"], entry["age_seconds"]
        body["alerts"] = entry.get("alerts", [])
        return body

    @app.get("/api/metrics/summary")
    async def summary(node: str = Query(LOCAL_NODE), range: str = Query("24h"), _user=Depends(context.current)):
        enabled()
        check_range(range)
        node, others = await check_node(node)
        nodes = []
        if node in (LOCAL_NODE, "all"):
            nodes.append(await local_summary(range))
        for item in others:
            nodes.append({"node_id": item["node_id"], "name": item["name"], "status": "unsupported", "host": None,
                          "protocols": {}, "hours_of_day": {}, "alerts": []})
        body = {"range": range, "nodes": nodes}
        if node == "all":
            def traffic(row):
                return sum(p["total_bytes"] or 0 for p in row["protocols"].values())

            body["compare"] = sorted(
                ({"node_id": row["node_id"], "name": row["name"], "status": row["status"],
                  "total_bytes": traffic(row) if row["protocols"] else None,
                  "peak_bps": max((p["peak_bps"] or 0 for p in row["protocols"].values()), default=None)
                  if row["protocols"] else None,
                  "cpu_avg": (row["host"] or {}).get("cpu", {}).get("avg"),
                  "mem_avg": (row["host"] or {}).get("mem", {}).get("avg"),
                  "alerts": len(row["alerts"])} for row in nodes),
                key=lambda row: row["total_bytes"] or -1, reverse=True)
        return JSONResponse(body, headers=NO_STORE)
