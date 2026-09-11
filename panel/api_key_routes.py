"""Owner-only management of scoped API keys; the plaintext leaves once, at creation."""
from __future__ import annotations

import asyncio

from fastapi import Depends, HTTPException, Request

from .schemas import ApiKeyCreate, ApiKeyEnabled
from .web_context import RequestContext


def register_api_key_routes(app, context: RequestContext) -> None:
    def _ctx(request: Request, user: dict) -> dict:
        return {"actor": user, "ip": context.client_ip(request),
                "request_id": getattr(request.state, "request_id", None)}

    @app.get("/api/keys")
    async def list_keys(_user=Depends(context.read_roles("owner"))):
        return {"items": await asyncio.to_thread(app.state.api_keys.list)}

    @app.post("/api/keys", status_code=201)
    async def create_key(body: ApiKeyCreate, request: Request, user=Depends(context.roles("owner"))):
        try:
            row, plaintext = await asyncio.to_thread(
                app.state.api_keys.create, body.name, body.scope, body.expires_at, **_ctx(request, user))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"key": row, "plaintext": plaintext}

    @app.post("/api/keys/{key_id}/enabled")
    async def set_enabled(key_id: int, body: ApiKeyEnabled, request: Request, user=Depends(context.roles("owner"))):
        try:
            await asyncio.to_thread(app.state.api_keys.set_enabled, key_id, body.enabled, **_ctx(request, user))
        except KeyError as exc:
            raise HTTPException(404, "key not found") from exc
        return {"ok": True}

    @app.delete("/api/keys/{key_id}")
    async def delete_key(key_id: int, request: Request, user=Depends(context.roles("owner"))):
        try:
            await asyncio.to_thread(app.state.api_keys.delete, key_id, **_ctx(request, user))
        except KeyError as exc:
            raise HTTPException(404, "key not found") from exc
        return {"ok": True}
