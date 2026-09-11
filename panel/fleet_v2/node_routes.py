"""Node-facing fleet v2 API, gated by a node-sync or admin API key (Task 6 grows this)."""
from __future__ import annotations

from fastapi import Depends

from ..web_context import RequestContext


def register_fleet_v2_node_routes(app, context: RequestContext) -> None:
    @app.get("/api/fleet/v2/identity")
    async def identity(_user=Depends(context.fleet_key)):
        return {"guid": app.state.panel_guid}
