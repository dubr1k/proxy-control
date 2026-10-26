from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest
from panel.tests.harness.memories.mieru import MieruError





pytestmark = pytest.mark.anyio


async def test_panel_mieru_owner_lifecycle_is_one_time_and_audited(
    client, login_user, mieru
):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    listed = await client.get("/api/mieru/users")
    assert listed.status_code == 200
    assert (
        listed.json()["quota_semantics"]
        == "rolling application-byte admission quota (approximate)"
    )
    created = await client.post(
        "/api/mieru/users",
        json={
            "username": "phone",
            "quotas": [{"days": 30, "megabytes": 1024}],
            "expected_revision": "rev-1",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201
    revealed = await client.get("/api/reveal/" + created.json()["reveal_token"])
    reveal = revealed.json()
    assert set(reveal["clients"]) == {"native", "karing"}
    native = reveal["clients"]["native"]
    assert native["type"] == "config"
    assert native["filename"] == "mieru-client.json"
    assert native["apply_command"] == "mieru apply config mieru-client.json"
    assert native["simple_share_url"].startswith("mierus://phone:")
    native_url = urlsplit(native["simple_share_url"])
    assert native["config"] == {
        "profiles": [{
            "profileName": "phone",
            "user": {"name": "phone", "password": native_url.password},
            "servers": [{
                "domainName": "mieru.example.com",
                "portBindings": [{"port": 8443, "protocol": "TCP"}],
            }],
            "mtu": 1400,
        }],
        "activeProfile": "phone",
        "rpcPort": 50000,
        "socks5Port": 1080,
        "socks5ListenLAN": False,
        "loggingLevel": "INFO",
    }
    assert native["qr"]["payload"] == native["simple_share_url"]
    assert native["qr"]["image"].startswith("data:image/svg+xml;base64,")

    karing = reveal["clients"]["karing"]
    assert karing["type"] == "link"
    assert karing["import_url"].startswith("karing://install-config?")
    assert karing["qr"]["payload"] == karing["import_url"]
    profile = json.loads(parse_qs(urlsplit(karing["import_url"]).query)["url"][0])
    assert profile == karing["config"]
    assert profile["outbounds"] == [{
        "type": "mieru",
        "tag": "mieru-TCP-8443",
        "server": "mieru.example.com",
        "server_port": 8443,
        "transport": "TCP",
        "username": "phone",
        "password": native_url.password,
    }]
    assert reveal["unsupported_clients"] == {
        "nekobox": "Проверенный формат импорта Mieru для NekoBox+ отсутствует.",
        "shadowrocket": "Проверенный формат импорта Mieru для Shadowrocket отсутствует.",
    }
    assert "share_url" not in reveal and "qr" not in reveal
    assert revealed.headers["cache-control"] == "no-store"
    assert (
        await client.get("/api/reveal/" + created.json()["reveal_token"])
    ).status_code == 410
    assert (
        await client.post(
            "/api/mieru/users/phone/disable",
            json={"expected_revision": created.json()["revision"]},
            headers={"X-CSRF-Token": csrf},
        )
    ).status_code == 200
    assert "share_url" not in (await client.get("/api/mieru/users")).text
    audit = str((await client.get("/api/audit")).json())
    assert "mierus://" not in audit and "mieru.create" in audit

async def test_panel_mieru_rotation_uses_a_new_karing_profile_name(
    client, login_user,
):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post(
        "/api/mieru/users",
        json={"username": "phone", "quotas": [], "expected_revision": "rev-1"},
        headers={"X-CSRF-Token": csrf},
    )
    created_reveal = await client.get(
        "/api/reveal/" + created.json()["reveal_token"]
    )
    created_karing = created_reveal.json()["clients"]["karing"]
    created_name = parse_qs(
        urlsplit(created_karing["import_url"]).query
    )["name"][0]

    rotated = await client.post(
        "/api/mieru/users/phone/rotate",
        json={"expected_revision": created.json()["revision"]},
        headers={"X-CSRF-Token": csrf},
    )

    assert rotated.status_code == 200
    reveal = await client.get("/api/reveal/" + rotated.json()["reveal_token"])
    rotated_karing = reveal.json()["clients"]["karing"]
    rotated_name = parse_qs(
        urlsplit(rotated_karing["import_url"]).query
    )["name"][0]
    assert created_name.startswith("Mieru · phone · ")
    assert rotated_name.startswith("Mieru · phone · ")
    assert created_name != rotated_name
    assert set(reveal.json()["clients"]) == {"native", "karing"}
    assert rotated_karing["qr"]["payload"].startswith(
        "karing://install-config?"
    )











def _password(reveal: dict) -> str:
    return urlsplit(reveal["clients"]["native"]["simple_share_url"]).password


async def test_mieru_key_is_kept_and_shown_again_without_rotation(client, login_user, mieru):
    """mita keeps a hash only: the panel's escrow is what lets «Конфигурация» show the
    key again — and a rotation on this page must replace the kept key, or every
    subscription of the client would go on serving the old one."""
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post(
        "/api/mieru/users",
        json={"username": "phone", "quotas": [], "expected_revision": "rev-1"},
        headers={"X-CSRF-Token": csrf},
    )
    first = _password((await client.get("/api/reveal/" + created.json()["reveal_token"])).json())
    listed = (await client.get("/api/mieru/users")).json()["items"]
    assert [item["credential_kept"] for item in listed] == [True]

    revision = mieru.revision
    shown = await client.post("/api/mieru/users/phone/access", headers={"X-CSRF-Token": csrf})
    assert shown.status_code == 200
    assert _password(shown.json()) == first
    assert set(shown.json()["clients"]) == {"native", "karing"}
    assert mieru.revision == revision  # showing the key changed nothing on the node

    rotated = await client.post(
        "/api/mieru/users/phone/rotate",
        json={"expected_revision": mieru.revision},
        headers={"X-CSRF-Token": csrf},
    )
    second = _password((await client.get("/api/reveal/" + rotated.json()["reveal_token"])).json())
    assert second != first
    again = (await client.post("/api/mieru/users/phone/access", headers={"X-CSRF-Token": csrf})).json()
    assert _password(again) == second

    audit = str((await client.get("/api/audit")).json())
    assert "mieru.access" in audit and "mierus://" not in audit and second not in audit


async def test_mieru_key_issued_before_it_was_kept_asks_for_one_rotation(client, login_user, mieru):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    mieru.users["legacy"] = {"username": "legacy", "enabled": True, "quotas": []}

    listed = (await client.get("/api/mieru/users")).json()["items"]
    assert [item["credential_kept"] for item in listed] == [False]
    refused = await client.post("/api/mieru/users/legacy/access", headers={"X-CSRF-Token": csrf})
    assert refused.status_code == 409
    assert "Выпустите новую ссылку один раз" in refused.json()["detail"]

    await client.post(
        "/api/mieru/users/legacy/rotate",
        json={"expected_revision": mieru.revision},
        headers={"X-CSRF-Token": csrf},
    )
    listed = (await client.get("/api/mieru/users")).json()["items"]
    assert [item["credential_kept"] for item in listed] == [True]
    assert (await client.post("/api/mieru/users/legacy/access", headers={"X-CSRF-Token": csrf})).status_code == 200


async def test_mieru_kept_key_follows_the_users_lane_slot(client, login_user, mieru):
    """The link is rebuilt from the shape mita serves now: a user in a lane gets the
    slot's port, not the main one."""
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    await client.post(
        "/api/mieru/users",
        json={"username": "phone", "quotas": [], "expected_revision": "rev-1"},
        headers={"X-CSRF-Token": csrf},
    )
    mieru.router_url = "socks5://lane:secret@127.0.0.1:45102"
    await mieru.set_lanes([{"lane": "grant:x", "users": ["phone"], "upstream": {"user": "u", "password": "p"}}])
    shown = (await client.post("/api/mieru/users/phone/access", headers={"X-CSRF-Token": csrf})).json()
    url = shown["clients"]["native"]["simple_share_url"]
    assert "port=46101" in url and "port=8443" not in url


async def test_deleting_on_the_protocol_pages_takes_the_kept_grant_with_it(client, server, login_user, mieru, naive):
    """The page that keeps a key must not leave its grant behind: a subscription would go on
    listing an account the node no longer has."""
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    await client.post("/api/mieru/users", json={"username": "phone", "quotas": [], "expected_revision": mieru.revision},
                      headers={"X-CSRF-Token": csrf})
    await client.post("/api/naive/users", json={"username": "phone"}, headers={"X-CSRF-Token": csrf})
    with server.db() as db:
        kept = db.execute("SELECT protocol FROM access_grants WHERE runtime_username='phone'").fetchall()
    assert {row["protocol"] for row in kept} == {"mieru", "naive"}

    deleted = await client.request("DELETE", "/api/mieru/users/phone", json={"expected_revision": mieru.revision},
                                   headers={"X-CSRF-Token": csrf})
    assert deleted.status_code == 200 and "phone" not in mieru.users
    assert (await client.delete("/api/naive/users/phone", headers={"X-CSRF-Token": csrf})).status_code == 204
    with server.db() as db:
        assert db.execute("SELECT COUNT(*) FROM access_grants WHERE runtime_username='phone'").fetchone()[0] == 0
    audit = [row["action"] for row in (await client.get("/api/audit")).json()["items"]]
    assert audit.count("grant.delete") == 2 and "mieru.delete" in audit and "naive.delete" in audit


async def test_viewer_cannot_see_a_kept_mieru_key(client, server, login_user, mieru):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    await client.post(
        "/api/mieru/users",
        json={"username": "phone", "quotas": [], "expected_revision": "rev-1"},
        headers={"X-CSRF-Token": csrf},
    )
    server.create_admin("watcher", "correct horse battery staple", "viewer")
    await client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    await login_user(client, "watcher")
    response = await client.post(
        "/api/mieru/users/phone/access", headers={"X-CSRF-Token": client.cookies["panel_csrf"]}
    )
    assert response.status_code == 403


async def test_panel_shows_mita_counters_per_user_and_keeps_the_quota_history_unavailable(
    client, login_user, mieru
):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post(
        "/api/mieru/users",
        json={"username": "phone", "quotas": [], "expected_revision": "rev-1"},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201
    mieru.traffic_rows = {"phone": (1500, 25_000_000), "stranger": (1, 2)}

    listed = (await client.get("/api/mieru/users")).json()
    # the typed quota history stays unavailable: rolling quotas are mita's own, approximate
    assert listed["metrics"] == {"capability": "unavailable", "reason": "typed_histories_unavailable"}
    assert listed["traffic"] == {"available": True, "since": "mita_start"}
    assert listed["items"][0]["traffic_available"] is True
    assert (listed["items"][0]["upload_bytes"], listed["items"][0]["download_bytes"]) == (1500, 25_000_000)
    assert all(item["username"] != "stranger" for item in listed["items"])
    reset = await client.post("/api/mieru/users/phone/reset-metrics", headers={"X-CSRF-Token": csrf})
    assert reset.status_code == 409

    dashboard = (await client.get("/api/dashboard")).json()["protocols"]["mieru"]
    assert dashboard["status"] == "ready"
    assert dashboard["traffic"] == {"available": True, "label": "application bytes", "since": "mita_start",
                                    "upload_bytes": 1501, "download_bytes": 25_000_002}


async def test_a_user_mita_has_not_counted_yet_shows_zero_and_an_old_manager_shows_unavailable(
    client, login_user, mieru, monkeypatch
):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    await client.post("/api/mieru/users", json={"username": "phone", "quotas": [], "expected_revision": "rev-1"},
                      headers={"X-CSRF-Token": csrf})
    quiet = (await client.get("/api/mieru/users")).json()["items"][0]
    assert quiet["traffic_available"] is True and (quiet["upload_bytes"], quiet["download_bytes"]) == (0, 0)

    async def old_manager():
        raise MieruError("manager rejected request")

    monkeypatch.setattr(mieru, "traffic", old_manager)
    listed = (await client.get("/api/mieru/users")).json()
    assert listed["traffic"]["available"] is False
    assert listed["items"][0]["traffic_available"] is False
    assert "upload_bytes" not in listed["items"][0]
    dashboard = (await client.get("/api/dashboard")).json()["protocols"]["mieru"]
    assert dashboard["traffic"]["available"] is False and dashboard["traffic"]["reason"] == "typed_histories_unavailable"





async def test_panel_mieru_viewer_is_read_only(client, server, login_user):
    server.create_admin("viewer-m", "viewer password long enough", "viewer")
    await login_user(client, "viewer-m", "viewer password long enough")
    csrf = client.cookies["panel_csrf"]
    assert (await client.get("/api/mieru/users")).status_code == 200
    response = await client.post(
        "/api/mieru/users",
        json={"username": "x", "quotas": [], "expected_revision": "rev-1"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 403


async def test_dashboard_reports_mieru_disabled_ready_and_degraded(
    client, login_user, mieru
):
    await login_user(client)
    ready = (await client.get("/api/dashboard")).json()["protocols"]["mieru"]
    assert ready["status"] == "ready"
    assert ready["traffic"] == {"available": True, "label": "application bytes", "since": "mita_start",
                                "upload_bytes": 0, "download_bytes": 0}
    mieru.broken = True
    degraded = (await client.get("/api/dashboard")).json()["protocols"]["mieru"]
    assert degraded["status"] == "degraded"













@pytest.mark.anyio
async def test_panel_mieru_quotas_are_replaced_with_the_revision_and_audited(client, login_user, mieru):
    """`POST /api/mieru/users/{username}/quotas` (v0.1 API, the «Квоты» dialog of the
    screen): the whole quota list is replaced under the service revision, the manager gets
    exactly the typed list, the audit names the quotas and never a credential; a viewer is
    refused and a stale revision is the manager's word (409), not the panel's."""
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post("/api/mieru/users", json={"username": "tablet", "quotas": [], "expected_revision": "rev-1"},
                                headers={"X-CSRF-Token": csrf})
    assert created.status_code == 201
    revision = (await client.get("/api/mieru/users")).json()["service"]["revision"]
    updated = await client.post("/api/mieru/users/tablet/quotas",
                                json={"expected_revision": revision, "quotas": [{"days": 7, "megabytes": 512}, {"days": 30, "megabytes": 4096}]},
                                headers={"X-CSRF-Token": csrf})
    assert updated.status_code == 200, updated.text
    assert updated.json()["username"] == "tablet" and updated.json()["revision"] != revision
    assert mieru.users["tablet"]["quotas"] == [{"days": 7, "megabytes": 512}, {"days": 30, "megabytes": 4096}]
    listed = next(u for u in (await client.get("/api/mieru/users")).json()["items"] if u["username"] == "tablet")
    assert listed["quotas"] == [{"days": 7, "megabytes": 512}, {"days": 30, "megabytes": 4096}]
    too_many = await client.post("/api/mieru/users/tablet/quotas",
                                 json={"expected_revision": updated.json()["revision"], "quotas": [{"days": 1, "megabytes": 1}] * 17},
                                 headers={"X-CSRF-Token": csrf})
    assert too_many.status_code == 422
    audit = (await client.get("/api/audit")).json()
    entry = next(item for item in audit["items"] if item["action"] == "mieru.quotas")
    assert entry["target"] == "tablet" and entry["detail"]["quotas"][0] == {"days": 7, "megabytes": 512}
    assert "mierus://" not in str(audit)
