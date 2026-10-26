from __future__ import annotations

import pytest

from panel.versions import MemoryVersions


@pytest.fixture
def version_panel(panel_server, telemt, naive, mieru):
    """Exercise the agent over its socket and the panel over HTTP, in either implementation."""
    versions = MemoryVersions(router=True)
    server = panel_server(
        telemt=telemt, naive=naive, mieru=mieru, versions=versions,
        naive_public_host="naive.example.com", naive_enabled=True, mieru_enabled=True,
    )
    server.create_admin("owner", "correct horse battery staple", "owner")
    server.create_admin("viewer", "correct horse battery staple", "viewer")
    return server, versions


@pytest.mark.anyio
async def test_versions_are_visible_and_owner_can_update(client, login_user):
    await login_user(client)
    unavailable = await client.get("/api/versions")
    assert unavailable.status_code == 200
    assert unavailable.json()["enabled"] is False


@pytest.mark.anyio
async def test_version_update_requires_owner_and_current_revision(version_panel, login_user):
    server, versions = version_panel
    client = server.client
    await login_user(client)
    listed = await client.get("/api/versions")
    assert listed.status_code == 200
    assert listed.json()["components"]["telemt"]["current"] == "3.4.24"
    assert "3.36.0" in {item["version"] for item in listed.json()["components"]["mita"]["available"]}
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    response = await client.post(
        "/api/versions/telemt/update",
        json={"version": "3.4.25", "expected_current": "3.4.24"}, headers=csrf,
    )
    assert response.status_code == 200
    assert versions.calls == [("telemt", "3.4.25", "3.4.24")]
    stale = await client.post(
        "/api/versions/telemt/update",
        json={"version": "3.4.24", "expected_current": "3.4.24"}, headers=csrf,
    )
    assert stale.status_code == 409
    assert stale.json() == {"detail": "version agent rejected request"}


@pytest.mark.anyio
async def test_version_update_rejects_viewer(version_panel, login_user):
    server, versions = version_panel
    client = server.client
    await login_user(client, username="viewer")
    response = await client.post(
        "/api/versions/telemt/update", json={"version": "3.4.25", "expected_current": "3.4.24"},
        headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
    )
    assert response.status_code == 403
    assert versions.calls == []


@pytest.mark.anyio
async def test_overview_reports_host_resources_from_the_agent(version_panel, login_user):
    server, _ = version_panel
    client = server.client
    await login_user(client)
    host = (await client.get("/api/dashboard")).json()["host"]
    assert host["available"] is True
    assert host["cpu"]["used_percent"] == 12.5 and host["cpu"]["cores"] == 4
    assert host["cpu"]["load_average"] == [0.5, 0.4, 0.3]
    assert host["memory"]["used_percent"] == 27.4
    assert host["disk"]["available_bytes"] == 71_940_702_208
    assert set(host) == {"available", "cpu", "memory", "swap", "disk"}


@pytest.mark.anyio
async def test_host_resources_are_polled_alone_and_follow_the_agent(version_panel, login_user):
    server, versions = version_panel
    client = server.client
    assert (await client.get("/api/host")).status_code == 401
    await login_user(client)
    first = (await client.get("/api/host")).json()
    versions.host_metrics["cpu"]["used_percent"] = 81.25
    versions.host_metrics["cpu"]["secret_field"] = "never"
    second = (await client.get("/api/host")).json()
    dashboard = (await client.get("/api/dashboard")).json()["host"]
    assert first["available"] is True and first["cpu"]["used_percent"] == 12.5
    assert second["cpu"]["used_percent"] == 81.2
    assert "secret_field" not in second["cpu"]
    assert second == dashboard


@pytest.mark.anyio
async def test_host_resources_report_a_reason_when_the_agent_is_silent(client, login_user):
    await login_user(client)
    assert (await client.get("/api/host")).json() == {
        "available": False, "reason": "version_agent_unavailable",
    }


@pytest.mark.anyio
async def test_overview_degrades_to_a_reason_when_the_host_agent_is_silent(client, login_user):
    await login_user(client)
    body = (await client.get("/api/dashboard")).json()
    assert body["host"] == {"available": False, "reason": "version_agent_unavailable"}
    assert body["protocols"]["mtproxy"]["ready"] is True


@pytest.mark.anyio
async def test_owner_checks_upstream_and_sees_the_candidate(version_panel, login_user):
    server, versions = version_panel
    client = server.client
    await login_user(client)
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    checked = await client.post("/api/versions/check", headers=csrf)
    assert checked.status_code == 200 and versions.checks == 1
    body = checked.json()
    assert body["enabled"] is True and body["checked_at"] == 1
    assert {"version": "3.37.0", "kind": "binary", "source": "upstream"} in body["components"]["mita"]["available"]
    assert body["components"]["xray"]["current"] == "26.3.27"
    updated = await client.post(
        "/api/versions/xray/update", json={"version": "26.4.1", "expected_current": "26.3.27"}, headers=csrf,
    )
    assert updated.status_code == 200 and versions.calls[-1] == ("xray", "26.4.1", "26.3.27")
    with server.db() as db:
        actions = [row["action"] for row in db.execute(
            "SELECT action FROM audit_log WHERE action LIKE 'runtime.version.%' ORDER BY id")]
    assert actions == ["runtime.version.check", "runtime.version.update"]
    await login_user(client, username="viewer")
    refused = await client.post("/api/versions/check", headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
    assert refused.status_code == 403 and versions.checks == 1


@pytest.mark.anyio
async def test_owner_updates_the_panel_itself_and_the_answer_is_async(version_panel, login_user):
    server, versions = version_panel
    client = server.client
    await login_user(client)
    panel = (await client.get("/api/versions")).json()["components"]["panel"]
    assert panel["current"] == "0.10.0-beta.1" and panel["status"] == "ready"
    response = await client.post(
        "/api/versions/panel/update",
        json={"version": "0.11.0-beta.1", "expected_current": "0.10.0-beta.1"},
        headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
    )
    assert response.status_code == 200
    assert response.json() == {"component": "panel", "version": "0.11.0-beta.1", "changed": True, "async": True}
    assert versions.calls == [("panel", "0.11.0-beta.1", "0.10.0-beta.1")]
    after = (await client.get("/api/versions")).json()["components"]["panel"]
    assert after["current"] == "0.11.0-beta.1" and after["status"] == "ready"
    with server.db() as db:
        actions = [row["action"] for row in db.execute(
            "SELECT action FROM audit_log WHERE action = 'runtime.version.update'")]
    assert actions == ["runtime.version.update"]


@pytest.mark.anyio
async def test_owner_rebuilds_pending_managers_viewer_cannot_and_a_running_update_is_409(version_panel, login_user):
    server, versions = version_panel
    versions.components["panel"]["pending_rebuild"] = ["naive_manager", "docker"]
    client = server.client
    await login_user(client, username="viewer")
    refused = await client.post(
        "/api/versions/panel/rebuild-managers", headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
    assert refused.status_code == 403 and versions.calls == []
    await login_user(client)
    csrf = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    versions.components["panel"]["status"] = "updating"
    busy = await client.post("/api/versions/panel/rebuild-managers", headers=csrf)
    assert busy.status_code == 409 and busy.json() == {"detail": "version agent rejected request"}
    versions.components["panel"]["status"] = "ready"
    done = await client.post("/api/versions/panel/rebuild-managers", headers=csrf)
    assert done.status_code == 200 and done.json()["pending_rebuild"] == ["docker"]
    with server.db() as db:
        actions = [row["action"] for row in db.execute(
            "SELECT action FROM audit_log WHERE action LIKE 'runtime.version.%'")]
    assert actions == ["runtime.version.managers_rebuild"]


def test_memory_versions_offer_xray_only_with_a_router():
    assert "xray" not in MemoryVersions().components
    assert MemoryVersions(router=True).components["xray"]["current"] == "26.3.27"
