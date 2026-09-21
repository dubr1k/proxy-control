"""`GET /api/openapi.json` (v0.11, spec §9a): the FastAPI schema for the MCP server —
owner/admin only, session or admin API key; `openapi_url` stays off so the public
surface does not grow."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.anyio


async def test_openapi_requires_a_session(client):
    assert (await client.get("/api/openapi.json")).status_code == 401


async def test_viewer_is_refused(client, login_user):
    client._transport.app.state.store.create_admin("viewer", "viewer password long enough", "viewer")
    await login_user(client, "viewer", "viewer password long enough")
    assert (await client.get("/api/openapi.json")).status_code == 403


async def test_owner_reads_the_schema_and_the_public_url_stays_off(client, login_user):
    await login_user(client)
    response = await client.get("/api/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["openapi"].startswith("3.")
    assert "/api/clients" in schema["paths"]
    assert "post" in schema["paths"]["/api/clients"]
    assert "/api/openapi.json" in schema["paths"]
    # FastAPI's own endpoint is disabled; only the gated route answers.
    assert (await client.get("/openapi.json")).status_code == 404


async def test_admin_api_key_reads_the_schema(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post("/api/keys", json={"name": "mcp", "scope": "admin"}, headers={"X-CSRF-Token": csrf})
    client.cookies.clear()
    headers = {"Authorization": f"Bearer {created.json()['plaintext']}"}
    assert (await client.get("/api/openapi.json", headers=headers)).status_code == 200
