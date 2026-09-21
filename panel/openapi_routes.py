"""The API schema for the MCP server (v0.11, spec §9a): FastAPI's `openapi_url` stays
off, so the schema is not part of the public surface; owners and admins — a session or
an admin API key — read it here and the MCP server builds its tools from it."""
from __future__ import annotations

from fastapi import Depends

from .web_context import RequestContext


def register_openapi_routes(app, context: RequestContext) -> None:
    @app.get("/api/openapi.json")
    async def openapi_schema(_user=Depends(context.read_roles("owner", "admin"))):
        return app.openapi()
