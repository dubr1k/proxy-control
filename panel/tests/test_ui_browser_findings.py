"""What the real-browser acceptance (v0.6, tier `ui`) found on its first run — each kept
here so the fixes cannot quietly regress: an inline style the CSP drops, a login form that
reloaded instead of saying «wrong password», a grant dialog whose Mieru body the API refused."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from panel.clients.models import PROTOCOL_OPTIONS, GrantIntent, MieruOptions

pytestmark = pytest.mark.anyio

STATIC = Path(__file__).resolve().parents[1] / "static"











async def test_the_grant_dialog_body_issues_a_mieru_grant(client, login_user, telemt, naive, mieru):
    """Exactly what the screen sends: `options: {}` for all three protocols."""
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    created = await client.post("/api/clients", json={"display_name": "Phone"}, headers=headers)
    body = {"grants": [{"protocol": p, "node_id": "local", "runtime_username": "phone", "options": {}} for p in ("mtproxy", "naive", "mieru")]}
    started = await client.post(f"/api/clients/{created.json()['id']}/grants", json=body, headers=headers)
    assert started.status_code == 200, started.text
    assert started.json()["status"] == "succeeded"
    assert "phone" in mieru.users and mieru.users["phone"]["quotas"] == []















