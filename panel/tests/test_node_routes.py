"""The node API: read for everyone, lifecycle for the owner, no inventory leaks."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.anyio




















async def test_local_node_reports_unavailable_managers(client, login_user, mieru, telemt):
    from panel.telemt import TelemtError

    await login_user(client)
    mieru.broken = True

    async def failing_health():
        raise TelemtError("Telemt API unavailable")

    telemt.health = failing_health
    services = (await client.get("/api/nodes/local")).json()["services"]
    assert services == {"telemt": "unavailable", "naive": "ok", "mieru": "unavailable", "amneziawg": "disabled", "trusttunnel": "disabled"}


async def test_local_node_marks_switched_off_protocols_disabled(tmp_path):
    import httpx

    from panel.app import Settings
    from panel.tests.harness.server import panel_app
    from panel.mieru import MemoryMieru
    from panel.naive import MemoryNaive
    from panel.telemt import MemoryTelemt
    from panel.versions import VersionClient

    class MustNotBeAsked(MemoryNaive):
        async def health(self):
            raise AssertionError("a disabled protocol was polled for node health")

    class MieruMustNotBeAsked(MemoryMieru):
        async def health(self):
            raise AssertionError("a disabled protocol was polled for node health")

    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        naive_enabled=False,
        mieru_enabled=False,
    )
    app = panel_app(
        settings,
        telemt=MemoryTelemt(),
        naive=MustNotBeAsked(),
        mieru=MieruMustNotBeAsked(),
        version_client=VersionClient(str(tmp_path / "missing-version-agent.sock")),
    )
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver", follow_redirects=False
    ) as client:
        page = await client.get("/login")
        await client.post(
            "/api/auth/login",
            json={"username": "owner", "password": "correct horse battery staple"},
            headers={"X-CSRF-Token": page.cookies["panel_csrf"]},
        )
        services = (await client.get("/api/nodes/local")).json()["services"]
    assert services == {"telemt": "ok", "naive": "disabled", "mieru": "disabled", "amneziawg": "disabled", "trusttunnel": "disabled"}



