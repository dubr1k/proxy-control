"""Routing acceptance helpers using only the operator HTTP API and harness controls."""
from __future__ import annotations

from contextlib import asynccontextmanager


def csrf(client):
    return {"X-CSRF-Token": client.cookies["panel_csrf"]}


@asynccontextmanager
async def linked(central, plaintext, login_user, *, auto_import=False):
    central.create_admin("owner", "correct horse battery staple", "owner")
    async with central.http() as client:
        await login_user(client)
        response = await client.post("/api/nodes/link", headers=csrf(client), json={
            "display_name": "Edge", "url": "https://node.example", "api_key": plaintext,
            "tls_verify": "verify", "auto_import": auto_import,
        })
        assert response.status_code == 201, response.text
        await central.tick("pusher")
        yield client, response.json()["node_id"]
