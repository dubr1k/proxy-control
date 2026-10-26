"""WP8 protocol projections over real panel HTTP and manager sockets (Python and Rust)."""
from __future__ import annotations

import json

import pytest

from panel.amneziawg import MemoryAmneziawg
from panel.mieru import MieruError
from panel.naive import NaiveError
from panel.tests.harness.server import IMPL
from panel.trusttunnel import MemoryTrusttunnel

pytestmark = pytest.mark.anyio


@pytest.fixture
def tunnel_panel(panel_server, telemt):
    awg, trusttunnel = MemoryAmneziawg(), MemoryTrusttunnel()
    server = panel_server(
        telemt=telemt, amneziawg=awg, trusttunnel=trusttunnel,
        amneziawg_enabled=True, trusttunnel_enabled=True,
        amneziawg_public_host="vpn.example.com", trusttunnel_public_host="gate.example.com",
    )
    server.create_admin("owner", "correct horse battery staple", "owner")
    return server, awg, trusttunnel


async def test_tunnel_overviews_join_holders_and_never_expose_credentials(tunnel_panel, login_user, monkeypatch):
    server, awg, trusttunnel = tunnel_panel
    client = server.client
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    created = await client.post("/api/clients", json={"display_name": "Alice"}, headers=headers)
    assert created.status_code == 201, created.text
    client_id = created.json()["id"]
    issued = await client.post(f"/api/clients/{client_id}/grants", headers=headers, json={"grants": [
        {"protocol": "amneziawg", "runtime_username": "alice-awg", "options": {"version": "2.0"}},
        {"protocol": "trusttunnel", "runtime_username": "alice-tt", "options": {"name": "Alice phone"}},
    ]})
    assert issued.status_code == 200 and issued.json()["status"] == "succeeded", issued.text
    # MemoryAmneziawg deliberately reports zero counters in _view; inject a measured wire view.
    peers = awg.peers

    async def metered_peers():
        rows = await peers()
        for row in rows:
            row.update(rx=500, tx=2000, latest_handshake=1_700_000_000)
        return rows

    monkeypatch.setattr(awg, "peers", metered_peers)
    trusttunnel.client_table["alice-tt"].update(rx=700, tx=3000, sessions=2)
    wg_answer = await client.get("/api/amneziawg/overview")
    tt_answer = await client.get("/api/trusttunnel/overview")
    assert wg_answer.status_code == tt_answer.status_code == 200
    wg, tt = wg_answer.json(), tt_answer.json()
    assert wg["status"] == tt["status"] == "ok"
    assert wg["public_host"] == "vpn.example.com"
    assert tt["public_host"] == "gate.example.com"
    peer, account = wg["peers"][0], tt["clients"][0]
    assert peer["client_id"] == account["client_id"] == client_id
    assert peer["client_name"] == account["client_name"] == "Alice"
    assert peer["grant_id"] and account["grant_id"]
    assert (peer["version"], peer["rx"], peer["tx"]) == ("2.0", 500, 2000)
    assert (account["upload_bytes"], account["download_bytes"], account["sessions"]) == (700, 3000, 2)
    assert account["name"] == "Alice phone"
    assert [(item["version"], item["peers"], item["running"]) for item in wg["versions"]] == [
        ("1.5", 0, True), ("2.0", 1, True), ("3.1", 0, True),
    ]
    assert tt["totals"] == {"clients": 1, "active": 1, "sessions": 2, "upload_bytes": 700, "download_bytes": 3000}
    assert wg["pending"] == tt["pending"] == []
    serialized = json.dumps([wg, tt])
    assert "private" not in serialized.lower() and "password" not in serialized.lower() and "tt://" not in serialized
    assert trusttunnel.client_table["alice-tt"]["password"] not in serialized
    cards = (await client.get("/api/dashboard")).json()["protocols"]
    assert cards["amneziawg"]["traffic"] == {"available": True, "upload_bytes": 500, "download_bytes": 2000}
    assert cards["trusttunnel"]["traffic"] == {"available": True, "upload_bytes": 700, "download_bytes": 3000}
    awg.peer_table.clear()
    trusttunnel.client_table.clear()
    assert [row["username"] for row in (await client.get("/api/amneziawg/overview")).json()["pending"]] == ["alice-awg"]
    assert [row["username"] for row in (await client.get("/api/trusttunnel/overview")).json()["pending"]] == ["alice-tt"]
    awg.broken = trusttunnel.broken = True
    assert (await client.get("/api/amneziawg/overview")).json()["status"] == "down"
    assert (await client.get("/api/trusttunnel/overview")).json()["status"] == "down"
    cards = (await client.get("/api/dashboard")).json()["protocols"]
    assert cards["amneziawg"]["status"] == cards["trusttunnel"]["status"] == "degraded"


@pytest.mark.parametrize("protocol", ["naive", "mieru", "amneziawg", "trusttunnel"])
async def test_disabled_protocol_pages_fail_closed(panel_server, login_user, protocol):
    server = panel_server()
    server.create_admin("owner", "correct horse battery staple", "owner")
    client = server.client
    await login_user(client)
    endpoint = "users" if protocol in {"naive", "mieru"} else "overview"
    response = await client.get(f"/api/{protocol}/{endpoint}")
    assert response.status_code == 404 and response.json() == {"detail": "feature unavailable"}


@pytest.mark.parametrize("protocol,status", [("naive", 404), ("naive", 409), ("naive", 422),
                                             ("mieru", 404), ("mieru", 409), ("mieru", 422)])
async def test_manager_error_status_and_fixed_detail_cross_the_http_stack(
    client, naive, mieru, login_user, monkeypatch, protocol, status,
):
    error = NaiveError if protocol == "naive" else MieruError

    async def refuse(*_args):
        raise error("upstream-secret-must-not-escape", status)

    if protocol == "naive":
        monkeypatch.setattr(naive, "reveal", refuse)
    else:
        monkeypatch.setattr(mieru, "reset_metrics", refuse)
    await login_user(client)
    path = f"/api/{protocol}/users/phone/" + ("access" if protocol == "naive" else "reset-metrics")
    response = await client.post(path, headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
    assert response.status_code == status
    label = "NaiveProxy" if protocol == "naive" else "Mieru"
    assert response.json() == {"detail": f"{label} manager unavailable"}


@pytest.mark.xfail(IMPL == "python", reason="Python MTProxy page bypassed the kept-grant lifecycle", strict=True)
@pytest.mark.parametrize("operation", ["rotate", "delete"])
async def test_mtproxy_page_keeps_client_credentials_in_sync(panel_server, telemt, login_user, operation):
    """Owner-approved Python bug fixes: the live runtime and client access must not diverge."""
    server = panel_server(telemt=telemt)
    server.create_admin("owner", "correct horse battery staple", "owner")
    client = server.client
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    created = await client.post("/api/users", json={"username": "phone"}, headers=headers)
    assert created.status_code == 201, created.text
    initial = (await client.get("/api/reveal/" + created.json()["reveal_token"])).json()
    with server.db() as db:
        grant = db.execute("SELECT id, client_id, secret_id, secret_version FROM access_grants").fetchone()
    assert grant is not None
    if operation == "rotate":
        rotated = await client.post("/api/users/phone/rotate", headers=headers)
        assert rotated.status_code == 200, rotated.text
        current = (await client.get("/api/reveal/" + rotated.json()["reveal_token"])).json()
        assert current["secret"] != initial["secret"]
        with server.db() as db:
            version = db.execute("SELECT secret_version FROM access_grants WHERE id=?", (grant["id"],)).fetchone()[0]
        assert version > grant["secret_version"]
        issued = await client.post(f"/api/clients/{grant['client_id']}/links", headers=headers)
        assert issued.status_code == 200, issued.text
        kept = (await client.get("/api/reveal/" + issued.json()["reveal_token"])).json()
        assert kept["grants"][0]["artifacts"][0]["value"] == current["link"]
    else:
        deleted = await client.delete("/api/users/phone", headers=headers)
        assert deleted.status_code == 204, deleted.text
        assert "phone" not in telemt.users
        with server.db() as db:
            assert db.execute("SELECT count(*) FROM access_grants WHERE id=?", (grant["id"],)).fetchone()[0] == 0
            states = db.execute("SELECT state FROM secret_versions WHERE secret_id=?", (grant["secret_id"],)).fetchall()
            assert states and all(row["state"] == "revoked" for row in states)
