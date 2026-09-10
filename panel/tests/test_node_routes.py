"""The node API: read for everyone, lifecycle for the owner, no inventory leaks."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.anyio


async def test_viewer_reads_nodes_but_cannot_register(client, login_user):
    app = client._transport.app
    app.state.store.create_admin("viewer", "viewer-password-123", "viewer")
    await login_user(client, "viewer", "viewer-password-123")
    csrf = client.cookies["panel_csrf"]
    assert (await client.get("/api/nodes")).status_code == 200
    denied = await client.post(
        "/api/nodes", json={"node_id": "edge-01", "display_name": "Edge"}, headers={"X-CSRF-Token": csrf}
    )
    assert denied.status_code == 403


async def test_owner_registers_node_and_gets_enrollment_checklist(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post(
        "/api/nodes", json={"node_id": "edge-01", "display_name": "Edge"}, headers={"X-CSRF-Token": csrf}
    )
    assert created.status_code == 201
    body = created.json()
    assert body["node"]["enrollment_state"] == "unenrolled"
    assert any("fleet-sign-csr" in step for step in body["enrollment_checklist"])
    # The checklist tells the operator to keep the key on the node.
    assert any("never the key" in step for step in body["enrollment_checklist"])
    audit = await client.get("/api/audit", params={"action": "node.register"})
    assert audit.json()["items"][0]["target"] == "edge-01"
    listed = await client.get("/api/fleet/nodes")
    assert [node for node in listed.json()["items"] if node["node_id"] == "edge-01"]


async def test_disable_enable_and_revoke_all_are_owner_actions_with_confirmation(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    await client.post(
        "/api/nodes", json={"node_id": "edge-01", "display_name": "Edge"}, headers={"X-CSRF-Token": csrf}
    )
    assert (await client.post("/api/nodes/edge-01/disable", headers={"X-CSRF-Token": csrf})).status_code == 200
    assert (await client.get("/api/nodes/edge-01")).json()["disabled"] is True
    assert (await client.post("/api/nodes/edge-01/enable", headers={"X-CSRF-Token": csrf})).status_code == 200
    wrong = await client.post(
        "/api/nodes/edge-01/certificates/revoke-all", json={"confirm": "nope"}, headers={"X-CSRF-Token": csrf}
    )
    assert wrong.status_code == 409
    ok = await client.post(
        "/api/nodes/edge-01/certificates/revoke-all", json={"confirm": "edge-01"}, headers={"X-CSRF-Token": csrf}
    )
    assert ok.status_code == 200 and ok.json() == {"revoked": 0}


async def test_rename_is_audited_and_unknown_nodes_are_404(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    await client.post(
        "/api/nodes", json={"node_id": "edge-01", "display_name": "Edge"}, headers={"X-CSRF-Token": csrf}
    )
    renamed = await client.post(
        "/api/nodes/edge-01/rename", json={"display_name": "Frankfurt edge"}, headers={"X-CSRF-Token": csrf}
    )
    assert renamed.status_code == 200 and renamed.json()["display_name"] == "Frankfurt edge"
    audit = await client.get("/api/audit", params={"action": "node.rename"})
    assert audit.json()["items"][0]["target"] == "edge-01"
    assert (await client.get("/api/nodes/ghost")).status_code == 404
    missing = await client.post(
        "/api/nodes/ghost/rename", json={"display_name": "x"}, headers={"X-CSRF-Token": csrf}
    )
    assert missing.status_code == 404


async def test_node_view_never_leaks_unknown_inventory_keys(client, login_user):
    await login_user(client)
    app = client._transport.app
    with app.state.database.connect() as db:
        db.execute(
            "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at)"
            " VALUES('edge-02','x','unenrolled','{\"telemt_version\":\"3.4.25\",\"api_token\":\"leak\"}',1,1)"
        )
        db.commit()
    body = (await client.get("/api/nodes/edge-02")).json()
    assert "leak" not in str(body) and body["daemon_health"] == "reported"


async def test_local_node_is_listed_first_with_manager_health(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    await client.post(
        "/api/nodes", json={"node_id": "edge-01", "display_name": "Edge"}, headers={"X-CSRF-Token": csrf}
    )
    items = (await client.get("/api/nodes")).json()["items"]
    # Sorted by node_id "local" would land last; the operator's own host comes first.
    assert [item["node_id"] for item in items] == ["local", "edge-01"]
    assert items[0]["kind"] == "local"
    assert items[0]["services"] == {"telemt": "ok", "naive": "ok", "mieru": "ok"}
    # A remote node is managed over the transport, so it carries no local services block.
    assert "services" not in items[1]
    assert (await client.get("/api/nodes/local")).json()["services"]["telemt"] == "ok"


async def test_local_node_reports_unavailable_managers(client, login_user, mieru, telemt):
    from panel.telemt import TelemtError

    await login_user(client)
    mieru.broken = True

    async def failing_health():
        raise TelemtError("Telemt API unavailable")

    telemt.health = failing_health
    services = (await client.get("/api/nodes/local")).json()["services"]
    assert services == {"telemt": "unavailable", "naive": "ok", "mieru": "unavailable"}


async def test_local_node_marks_switched_off_protocols_disabled(tmp_path):
    import httpx

    from panel.app import Settings, create_app
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
    app = create_app(
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
    assert services == {"telemt": "ok", "naive": "disabled", "mieru": "disabled"}


async def test_local_node_refuses_transport_and_lifecycle_actions(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    queued = await client.post(
        "/api/fleet/nodes/local/commands",
        json={
            "idempotency_key": "refresh-local-01",
            "operation": "telemt.inventory.refresh",
            "payload": {},
            "expected_telemt_revision": "rev-1",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert queued.status_code == 409
    assert (await client.post("/api/nodes/local/disable", headers={"X-CSRF-Token": csrf})).status_code == 409
    revoke = await client.post(
        "/api/nodes/local/certificates/revoke-all",
        json={"confirm": "local"},
        headers={"X-CSRF-Token": csrf},
    )
    assert revoke.status_code == 409
    taken = await client.post(
        "/api/nodes", json={"node_id": "local", "display_name": "Impostor"}, headers={"X-CSRF-Token": csrf}
    )
    assert taken.status_code == 422
    # Renaming the local node is the one lifecycle action it does accept.
    renamed = await client.post(
        "/api/nodes/local/rename", json={"display_name": "Амстердам"}, headers={"X-CSRF-Token": csrf}
    )
    assert renamed.status_code == 200 and renamed.json()["display_name"] == "Амстердам"
