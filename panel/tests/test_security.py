from __future__ import annotations

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


pytestmark = pytest.mark.anyio


async def test_unauthenticated_browser_root_redirects_to_login_but_api_stays_json_401(client):
    root = await client.get("/", follow_redirects=False)
    assert root.status_code == 303
    assert root.headers["location"] == "/login"
    assert (await client.get("/login")).status_code == 200

    api = await client.get("/api/dashboard")
    assert api.status_code == 401
    assert api.json() == {"detail": "authentication required"}


async def test_login_uses_opaque_server_side_session_and_security_headers(client, login_user):
    response = await login_user(client)
    assert response.status_code == 204
    cookie = response.cookies["panel_session"]
    assert "." not in cookie and len(cookie) >= 40
    assert "HttpOnly" in response.headers["set-cookie"]
    identity = await client.get("/api/auth/me")
    assert identity.status_code == 200
    # `panel_version` travels with the identity so every screen can show which panel is
    # open; its value is the release's VERSION file, "dev" in a checkout without one.
    assert identity.json() == {
        "username": "owner", "role": "owner", "via": "session",
        "panel_version": (ROOT / "VERSION").read_text().strip() or "dev",
        "features": {"naive": True, "mieru": True, "amneziawg": False, "trusttunnel": False},
    }
    dashboard = await client.get("/api/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.headers["content-security-policy"].startswith("default-src 'self'")
    assert "form-action 'self'" in dashboard.headers["content-security-policy"]
    assert dashboard.headers["x-content-type-options"] == "nosniff"


async def test_authenticated_login_page_preserves_session_csrf_for_naive_access(
    client, login_user, naive,
):
    naive.seed("phone", "secret-password")
    await login_user(client)
    csrf = client.cookies["panel_csrf"]

    login_page = await client.get("/login", follow_redirects=False)

    assert login_page.status_code == 200
    assert client.cookies["panel_csrf"] == csrf
    access = await client.post(
        "/api/naive/users/phone/access",
        headers={"X-CSRF-Token": csrf},
    )
    assert access.status_code == 200


async def test_poisoned_matching_csrf_cookie_invalidates_session_for_relogin(
    client, login_user, naive,
):
    naive.seed("phone", "secret-password")
    await login_user(client)
    client.cookies.set(
        "panel_csrf",
        "poisoned-by-stale-login-page",
        domain="testserver.local",
        path="/",
    )

    access = await client.post(
        "/api/naive/users/phone/access",
        headers={"X-CSRF-Token": "poisoned-by-stale-login-page"},
    )

    assert access.status_code == 401
    assert access.json() == {"detail": "session CSRF state invalid"}
    assert (await client.get("/api/auth/me")).status_code == 401


async def test_csrf_required_for_login_and_authenticated_mutations(client, login_user):
    assert (await client.post("/api/auth/login", json={"username": "owner", "password": "x"})).status_code == 403
    await login_user(client)
    assert (await client.post("/api/users", json={"username": "alice"})).status_code == 403


async def test_logout_invalidates_session(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    assert (await client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})).status_code == 204
    assert (await client.get("/api/dashboard")).status_code == 401


async def test_login_rate_limit_is_enforced(client):
    csrf = (await client.get("/login")).cookies["panel_csrf"]
    for _ in range(3):
        response = await client.post("/api/auth/login", json={"username": "owner", "password": "wrong-password"}, headers={"X-CSRF-Token": csrf})
        assert response.status_code == 401
    blocked = await client.post("/api/auth/login", json={"username": "owner", "password": "wrong-password"}, headers={"X-CSRF-Token": csrf})
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers














async def test_body_limit_and_validation(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    oversized = b'{"username":"' + b"a" * 70000 + b'"}'
    assert (await client.post("/api/users", content=oversized, headers={"content-type": "application/json", "X-CSRF-Token": csrf})).status_code == 413
    assert (await client.post("/api/users", json={"username": "bad user"}, headers={"X-CSRF-Token": csrf})).status_code == 422
