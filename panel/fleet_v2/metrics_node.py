"""`/api/fleet/v2/metrics*`: this node's own meters for the central panel that pulls them
(capability `metrics.v1`). The same data `/api/metrics/*` serves locally, behind the node-sync key."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from ..metrics.model import POINTS_DEFAULT, POINTS_MAX, POINTS_MIN, RANGES
from ..metrics.routes import local_summary, parse_series

NO_STORE = {"Cache-Control": "no-store"}


def register_fleet_v2_metrics_node_routes(app, context) -> None:
    settings = context.settings

    def enabled():
        if not settings.metrics_enabled or getattr(app.state, "metrics_collector", None) is None:
            raise HTTPException(404, "metrics_disabled")

    def check_range(value: str) -> str:
        if value not in RANGES:
            raise HTTPException(422, "range must be one of " + ", ".join(RANGES))
        return value

    @app.get("/api/fleet/v2/metrics")
    async def node_metrics(_key=Depends(context.fleet_key)):
        enabled()
        latest = app.state.metrics_collector.latest
        if latest is None:  # before the first tick: say so rather than invent a sample
            raise HTTPException(503, "metrics_warming_up")
        return JSONResponse(latest, headers=NO_STORE)

    @app.get("/api/fleet/v2/metrics/history")
    async def node_metrics_history(series: str = Query(...), range: str = Query("1h"),
                                   points: int = Query(POINTS_DEFAULT, ge=POINTS_MIN, le=POINTS_MAX),
                                   _key=Depends(context.fleet_key)):
        enabled()
        check_range(range)
        names = parse_series(series)
        if app.state.metrics_collector.latest is None:
            raise HTTPException(503, "metrics_warming_up")
        return JSONResponse({"status": "ok", **await app.state.metrics_store.history(names, range, points)},
                            headers=NO_STORE)

    @app.get("/api/fleet/v2/metrics/summary")
    async def node_metrics_summary(range: str = Query("24h"), _key=Depends(context.fleet_key)):
        enabled()
        check_range(range)
        if app.state.metrics_collector.latest is None:
            raise HTTPException(503, "metrics_warming_up")
        return JSONResponse(await local_summary(app, range), headers=NO_STORE)
