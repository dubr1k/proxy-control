from __future__ import annotations

import pytest

from panel.versions import MemoryVersions


@pytest.mark.anyio
async def test_versions_are_visible_and_owner_can_update(client, login_user):
    await login_user(client)
    unavailable = await client.get("/api/versions")
    assert unavailable.status_code == 200
    assert unavailable.json()["enabled"] is False


@pytest.mark.anyio
async def test_version_update_requires_owner_and_current_revision(
    tmp_path, telemt, naive, mieru, login_user
):
    from httpx import ASGITransport, AsyncClient
    from panel.app import Settings, create_app

    versions = MemoryVersions()
    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        naive_public_host="naive.example.com",
        naive_enabled=True,
        mieru_enabled=True,
    )
    app = create_app(
        settings, telemt=telemt, naive=naive, mieru=mieru, version_client=versions
    )
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    app.state.store.create_admin("viewer", "correct horse battery staple", "viewer")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        await login_user(client)
        listed = await client.get("/api/versions")
        assert listed.status_code == 200
        assert listed.json()["components"]["telemt"]["current"] == "3.4.24"
        assert "3.36.0" in {
            item["version"] for item in listed.json()["components"]["mita"]["available"]
        }
        csrf = client.cookies["panel_csrf"]
        response = await client.post(
            "/api/versions/telemt/update",
            json={"version": "3.4.25", "expected_current": "3.4.24"},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200
        assert versions.calls == [("telemt", "3.4.25", "3.4.24")]
        stale = await client.post(
            "/api/versions/telemt/update",
            json={"version": "3.4.24", "expected_current": "3.4.24"},
            headers={"X-CSRF-Token": csrf},
        )
        assert stale.status_code == 409


@pytest.mark.anyio
async def test_version_update_rejects_viewer(tmp_path, telemt, naive, mieru, login_user):
    from httpx import ASGITransport, AsyncClient
    from panel.app import Settings, create_app

    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        naive_public_host="naive.example.com",
        naive_enabled=True,
        mieru_enabled=True,
    )
    app = create_app(
        settings, telemt=telemt, naive=naive, mieru=mieru, version_client=MemoryVersions()
    )
    app.state.store.create_admin("viewer", "correct horse battery staple", "viewer")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        await login_user(client, username="viewer")
        response = await client.post(
            "/api/versions/telemt/update",
            json={"version": "3.4.25", "expected_current": "3.4.24"},
            headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
        )
        assert response.status_code == 403


@pytest.mark.anyio
async def test_overview_reports_host_resources_from_the_agent(
    tmp_path, telemt, naive, mieru, login_user
):
    """The panel cannot measure the host itself, so the card must come from the agent.

    The container runs read-only with ALL capabilities dropped and mounts
    nothing from the host but the agent socket, so CPU/RAM/disk have exactly one
    honest source. The overview carries them alongside the protocol cards.
    """
    from httpx import ASGITransport, AsyncClient
    from panel.app import Settings, create_app

    versions = MemoryVersions()
    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        naive_public_host="naive.example.com",
        naive_enabled=True,
        mieru_enabled=True,
    )
    app = create_app(
        settings, telemt=telemt, naive=naive, mieru=mieru, version_client=versions
    )
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        await login_user(client)
        host = (await client.get("/api/dashboard")).json()["host"]

    assert host["available"] is True
    assert host["cpu"]["used_percent"] == 12.5 and host["cpu"]["cores"] == 4
    assert host["cpu"]["load_average"] == [0.5, 0.4, 0.3]
    assert host["memory"]["used_percent"] == 27.4
    assert host["disk"]["available_bytes"] == 71_940_702_208
    # Only the mapped contract travels: a future agent field must not reach the UI.
    assert set(host) == {"available", "cpu", "memory", "disk"}


@pytest.mark.anyio
async def test_overview_degrades_to_a_reason_when_the_host_agent_is_silent(
    client, login_user,
):
    """A dead agent costs the dashboard one card, never the whole page."""
    await login_user(client)
    body = (await client.get("/api/dashboard")).json()
    assert body["host"] == {
        "available": False,
        "reason": "version_agent_unavailable",
    }
    # The protocol cards are unaffected.
    assert body["protocols"]["mtproxy"]["ready"] is True


@pytest.mark.anyio
async def test_owner_checks_upstream_and_sees_the_candidate(
    tmp_path, telemt, naive, mieru, login_user
):
    """`POST /api/versions/check` (v0.11): the owner asks the agent to poll upstream; the
    reply is the same shape as `GET /api/versions`, now with upstream candidates and, on a
    host with the Xray-router, the `xray` component that the update route accepts."""
    from httpx import ASGITransport, AsyncClient
    from panel.app import Settings, create_app

    versions = MemoryVersions(router=True)
    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        naive_public_host="naive.example.com",
        naive_enabled=True,
        mieru_enabled=True,
    )
    app = create_app(
        settings, telemt=telemt, naive=naive, mieru=mieru, version_client=versions
    )
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    app.state.store.create_admin("viewer", "correct horse battery staple", "viewer")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        await login_user(client)
        csrf = client.cookies["panel_csrf"]
        checked = await client.post("/api/versions/check", headers={"X-CSRF-Token": csrf})
        assert checked.status_code == 200 and versions.checks == 1
        body = checked.json()
        assert body["enabled"] is True and body["checked_at"] == 1
        assert {"version": "3.37.0", "kind": "binary", "source": "upstream"} in body["components"]["mita"]["available"]
        assert body["components"]["xray"]["current"] == "26.3.27"
        updated = await client.post(
            "/api/versions/xray/update",
            json={"version": "26.4.1", "expected_current": "26.3.27"},
            headers={"X-CSRF-Token": csrf},
        )
        assert updated.status_code == 200 and versions.calls[-1] == ("xray", "26.4.1", "26.3.27")
        with app.state.database.connect() as db:
            actions = [row["action"] for row in db.execute("SELECT action FROM audit_log WHERE action LIKE 'runtime.version.%' ORDER BY id")]
        assert actions == ["runtime.version.check", "runtime.version.update"]

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        await login_user(client, username="viewer")
        refused = await client.post("/api/versions/check", headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
        assert refused.status_code == 403 and versions.checks == 1


@pytest.mark.anyio
async def test_owner_updates_the_panel_itself_and_the_answer_is_async(
    tmp_path, telemt, naive, mieru, login_user
):
    """`POST /api/versions/panel/update` (v0.11): the agent accepts the panel's own update
    and answers before the panel restarts; the browser then polls `GET /api/versions`."""
    from httpx import ASGITransport, AsyncClient
    from panel.app import Settings, create_app

    versions = MemoryVersions()
    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        naive_public_host="naive.example.com",
        naive_enabled=True,
        mieru_enabled=True,
    )
    app = create_app(
        settings, telemt=telemt, naive=naive, mieru=mieru, version_client=versions
    )
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        await login_user(client)
        listed = await client.get("/api/versions")
        panel = listed.json()["components"]["panel"]
        assert panel["current"] == "0.10.0-beta.1" and panel["status"] == "ready"
        csrf = client.cookies["panel_csrf"]
        response = await client.post(
            "/api/versions/panel/update",
            json={"version": "0.11.0-beta.1", "expected_current": "0.10.0-beta.1"},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200
        assert response.json() == {"component": "panel", "version": "0.11.0-beta.1", "changed": True, "async": True}
        assert versions.calls == [("panel", "0.11.0-beta.1", "0.10.0-beta.1")]
        after = (await client.get("/api/versions")).json()["components"]["panel"]
        assert after["current"] == "0.11.0-beta.1" and after["status"] == "ready"
        with app.state.database.connect() as db:
            actions = [row["action"] for row in db.execute("SELECT action, target FROM audit_log WHERE action = 'runtime.version.update'")]
        assert actions == ["runtime.version.update"]


def test_memory_versions_offer_xray_only_with_a_router():
    assert "xray" not in MemoryVersions().components
    assert MemoryVersions(router=True).components["xray"]["current"] == "26.3.27"
