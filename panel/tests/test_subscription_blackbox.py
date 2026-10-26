"""Subscription HTTP contracts exercised against the actual Rust panel binary."""
from __future__ import annotations

import base64
import hashlib
import re
from urllib.parse import urlsplit

import pytest

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.panel_settings(
        hosts=("testserver", "sub.example.com"),
        subscription_url="https://sub.example.com",
        singbox_fork_clients="streisand",
    ),
]

SUB_HOST = "sub.example.com"


def csrf(client):
    return {"X-CSRF-Token": client.cookies["panel_csrf"]}


@pytest.fixture
async def owner(server, login_user):
    await login_user(server.client)
    yield server.client


@pytest.fixture
async def public(server):
    async with server.http(SUB_HOST) as client:
        yield client


@pytest.fixture
async def client_id(owner):
    created = await owner.post("/api/clients", json={"display_name": "Sergey", "subscription": False}, headers=csrf(owner))
    assert created.status_code == 201, created.text
    client_id = created.json()["id"]
    started = await owner.post(f"/api/clients/{client_id}/grants", headers=csrf(owner), json={"grants": [
        {"protocol": "mtproxy", "node_id": "local", "runtime_username": "alice", "options": {}},
        {"protocol": "naive", "node_id": "local", "runtime_username": "alice", "options": {}},
        {"protocol": "mieru", "node_id": "local", "runtime_username": "alice", "options": {}},
    ]})
    assert started.status_code == 200 and started.json()["status"] == "succeeded", started.text
    return client_id


@pytest.fixture
async def token(owner, client_id):
    created = await owner.post(f"/api/clients/{client_id}/subscription", headers=csrf(owner))
    assert created.status_code == 201, created.text
    revealed = await owner.get(f"/api/reveal/{created.json()['reveal_token']}")
    assert revealed.status_code == 200, revealed.text
    return urlsplit(revealed.json()["url"]).path.rsplit("/", 1)[1]


async def test_public_subscription_serves_every_format_with_etag_304_and_head(public, token):
    first = await public.get(f"/s/{token}")
    assert first.status_code == 200 and first.headers["cache-control"] == "private, no-cache"
    assert first.headers["content-type"].startswith("text/plain")
    assert first.headers["vary"] == "Accept, User-Agent"
    assert first.headers["profile-update-interval"] == "12"
    assert first.headers["x-robots-tag"] == "noindex"
    assert "subscription-userinfo" not in first.headers and "content-disposition" not in first.headers
    etag = first.headers["etag"]
    assert re.fullmatch(r'"[0-9a-f]{64}"', etag)
    again = await public.get(f"/s/{token}", headers={"If-None-Match": etag})
    assert again.status_code == 304 and not again.content and again.headers["etag"] == etag
    head = await public.head(f"/s/{token}")
    assert head.status_code == 200 and not head.content and head.headers["content-length"] == "0"
    assert head.headers["etag"] == etag

    expected = {
        "raw": "text/plain",
        "clash": "text/yaml",
        "singbox": "application/json",
        "manifest": "application/vnd.proxy-control.subscription+json",
        "html": "text/html",
    }
    for name, media_type in expected.items():
        response = await public.get(f"/s/{token}", params={"format": name})
        assert response.status_code == 200, (name, response.text)
        assert response.headers["content-type"].startswith(media_type)
        assert response.content
    manifest = (await public.get(f"/s/{token}", params={"format": "manifest"})).json()
    assert manifest["version"] == 1 and {grant["protocol"] for grant in manifest["grants"]} == {"mtproxy", "naive", "mieru"}
    page = await public.get(f"/s/{token}", headers={"Accept": "text/html"})
    assert page.status_code == 200 and "<!doctype html>" in page.text


async def test_singbox_client_variants_and_user_agent_negotiation(public, token):
    for client in ("karing", "singbox", "hiddify", "nekobox", "nyamebox", "throne"):
        response = await public.get(f"/s/{token}", params={"format": "singbox", "client": client})
        assert response.status_code == 200, (client, response.text)
        body = response.json()
        assert body["proxy_control"]["client"] == ("nekobox" if client == "nyamebox" else client)
        expected = {"karing": {"naive", "mieru"}, "singbox": {"naive"}, "hiddify": set(),
                    "nekobox": {"naive", "mieru"}, "nyamebox": {"naive", "mieru"}, "throne": {"naive", "mieru"}}
        assert {item["type"] for item in body["outbounds"]} == expected[client]
    for agent, expected in (("Throne/1.1", "throne"), ("NekoRay/1", "nekobox"), ("Hiddify/1", "hiddify"),
                            ("NyameBox/1", "nekobox"), ("Streisand/3", "fork")):
        response = await public.get(f"/s/{token}", headers={"User-Agent": agent})
        assert response.status_code == 200
        assert response.json()["proxy_control"]["client"] == expected
    official = await public.get(f"/s/{token}", headers={"User-Agent": "sing-box/1.12"})
    assert official.headers["content-type"].startswith("text/plain")
    explicit = await public.get(f"/s/{token}", params={"format": "singbox", "client": "singbox"},
                                headers={"User-Agent": "Throne/1.1"})
    assert explicit.json()["proxy_control"]["client"] == "singbox"
    for params in ({"format": "unknown"}, {"format": "raw", "client": "karing"},
                   {"format": "singbox", "client": "fork"}, {"format": "singbox", "client": "unknown"}):
        assert (await public.get(f"/s/{token}", params=params)).status_code == 404


async def test_host_token_and_revocation_refusals_are_indistinguishable(public, owner, client_id, token):
    missing = await public.get("/s/" + "A" * 43)
    on_panel = await public.get(f"/s/{token}", headers={"Host": "testserver"})
    malformed = await public.get("/s/short")
    assert missing.status_code == on_panel.status_code == malformed.status_code == 404
    assert missing.content == on_panel.content == malformed.content == b'{"detail":"not found"}'
    assert missing.headers["cache-control"] == "private, no-cache"
    assert missing.headers["vary"] == "Accept"
    assert (await owner.post(f"/api/clients/{client_id}/subscription/revoke", headers=csrf(owner))).status_code == 200
    revoked = await public.get(f"/s/{token}")
    assert revoked.status_code == 404 and revoked.content == missing.content


async def test_rate_limit_returns_429_and_counts_misses_too(public, token):
    for _ in range(30):
        assert (await public.get(f"/s/{token}", headers={"If-None-Match": '"none"'})).status_code == 200
    for _ in range(30):
        assert (await public.get("/s/" + "A" * 43)).status_code == 404
    limited = await public.get(f"/s/{token}")
    assert limited.status_code == 429 and limited.json() == {"detail": "too many requests"}
    # Validation precedes the limiter; an unknown format is still the same 404.
    assert (await public.get(f"/s/{token}", params={"format": "bad"})).status_code == 404


async def test_create_reveal_rotate_revoke_and_audited_reveal(owner, public, client_id, server):
    created = await owner.post(f"/api/clients/{client_id}/subscription", headers=csrf(owner))
    assert created.status_code == 201
    reveal_token = created.json()["reveal_token"]
    first = (await owner.get(f"/api/reveal/{reveal_token}")).json()
    assert first["url"].startswith("https://sub.example.com/s/")
    assert first["qr"].startswith("data:image/svg+xml;base64,")
    assert set(first["variants"]) == {"raw", "singbox", "singbox-official", "singbox-hiddify", "singbox-nekobox", "clash"}
    assert all(item["url"].startswith(first["url"]) and item["qr"].startswith("data:image/svg+xml;base64,")
               for item in first["variants"].values())
    assert (await owner.get(f"/api/reveal/{reveal_token}")).status_code == 410

    again = await owner.post(f"/api/clients/{client_id}/subscription/reveal", headers=csrf(owner))
    assert again.status_code == 200
    repeated = (await owner.get(f"/api/reveal/{again.json()['reveal_token']}")).json()
    assert repeated["url"] == first["url"]
    assert server.audits(action="subscription.reveal")

    rotated = await owner.post(f"/api/clients/{client_id}/subscription/rotate", headers=csrf(owner))
    assert rotated.status_code == 200
    second = (await owner.get(f"/api/reveal/{rotated.json()['reveal_token']}")).json()
    old_token = urlsplit(first["url"]).path.rsplit("/", 1)[1]
    new_token = urlsplit(second["url"]).path.rsplit("/", 1)[1]
    assert old_token != new_token
    assert (await public.get(f"/s/{old_token}")).status_code == 404
    assert (await public.get(f"/s/{new_token}")).status_code == 200
    assert (await owner.post(f"/api/clients/{client_id}/subscription/revoke", headers=csrf(owner))).json() == {"revoked": True}
    assert (await public.get(f"/s/{new_token}")).status_code == 404
    assert (await owner.post(f"/api/clients/{client_id}/subscription/revoke", headers=csrf(owner))).json() == {"revoked": False}


async def test_reveal_refuses_a_subscription_without_an_escrowed_copy(owner, client_id, token, server):
    assert len(token) == 43
    with server.db(write=True) as db:
        db.execute("UPDATE client_subscriptions SET secret_id=NULL,secret_version=NULL WHERE client_id=?", (client_id,))
    response = await owner.post(f"/api/clients/{client_id}/subscription/reveal", headers=csrf(owner))
    assert response.status_code == 409 and "not escrowed" in response.json()["detail"]


async def test_management_needs_a_writer_role(server, login_user, client_id):
    server.create_admin("viewer", "correct horse battery staple", "viewer")
    async with server.http("testserver") as viewer:
        await login_user(viewer, "viewer")
        assert (await viewer.get(f"/api/clients/{client_id}/subscription")).status_code == 200
        for suffix in ("", "/rotate", "/reveal", "/revoke"):
            response = await viewer.post(f"/api/clients/{client_id}/subscription{suffix}", headers=csrf(viewer))
            assert response.status_code == 403 and response.json() == {"detail": "insufficient role"}
        async with server.http("testserver") as anonymous:
            assert (await anonymous.get(f"/api/clients/{client_id}/subscription")).status_code == 401


async def test_post_clients_hands_back_a_subscription_reveal(owner):
    created = await owner.post("/api/clients", json={"display_name": "Phone"}, headers=csrf(owner))
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["subscription_reveal_token"]
    revealed = await owner.get(f"/api/reveal/{body['subscription_reveal_token']}")
    assert revealed.status_code == 200 and revealed.json()["generation"] == 1


async def test_compatibility_and_events_endpoints(owner, public, token, server):
    compatibility = await owner.get("/api/subscriptions/compatibility")
    assert compatibility.status_code == 200
    body = compatibility.json()
    assert set(body) == {"matrix", "notes", "platforms", "apps"}
    assert body["matrix"]["naive"]["singbox"] == "supported"
    assert body["matrix"]["mtproxy"]["telegram"] == "unsupported"
    assert body["apps"] and body["platforms"]

    assert (await public.get(f"/s/{token}", params={"format": "singbox"})).status_code == 200
    assert (await public.get("/s/" + "A" * 43)).status_code == 404
    events = (await owner.get("/api/events", params={"limit": 1})).json()
    assert len(events["items"]) == 1
    event = events["items"][0]
    assert event["name"] == "subscription.fetched" and event["status"] == 200 and event["format"] == "singbox"
    rest = (await owner.get("/api/events", params={"after": events["next_after"]})).json()
    assert all(item["id"] > events["next_after"] for item in rest["items"])
    assert token not in str(events) and "delivered" not in str(events)
    assert token not in str(server.audits(limit=500))


async def test_generation_and_etag_follow_grant_and_client_changes(owner, public, client_id, token):
    before = await public.get(f"/s/{token}", params={"format": "singbox"})
    assert before.json()["proxy_control"]["generation"] == 1
    listing = (await owner.get(f"/api/clients/{client_id}")).json()
    grant_id = listing["grants"][0]["id"]
    disabled = await owner.post(f"/api/clients/grants/{grant_id}/disable", headers=csrf(owner))
    assert disabled.status_code == 200, disabled.text
    after = await public.get(f"/s/{token}", params={"format": "singbox"}, headers={"If-None-Match": before.headers["etag"]})
    assert after.status_code == 200 and after.json()["proxy_control"]["generation"] == 2
    renamed = await owner.post(f"/api/clients/{client_id}/rename", json={"display_name": "Renamed"}, headers=csrf(owner))
    assert renamed.status_code == 200
    third = await public.get(f"/s/{token}", params={"format": "singbox"}, headers={"If-None-Match": after.headers["etag"]})
    assert third.status_code == 200 and third.json()["proxy_control"]["generation"] == 3
    label = await owner.post(f"/api/clients/grants/{grant_id}/label", json={"label": "Phone"}, headers=csrf(owner))
    assert label.status_code == 200
    fourth = await public.get(f"/s/{token}", params={"format": "singbox"}, headers={"If-None-Match": third.headers["etag"]})
    assert fourth.status_code == 200 and fourth.json()["proxy_control"]["generation"] == 4


async def test_expiry_and_node_rename_invalidate_the_old_etag(public, client_id, token, server):
    with server.db(write=True) as db:
        db.execute("UPDATE access_grants SET valid_until=? WHERE client_id=?", (int(server.clock.time()) + 10, client_id))
        db.execute("INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at,transport) VALUES('local','Old','active','{}',1,1,'panel') ON CONFLICT(node_id) DO UPDATE SET display_name='Old'")
    before = await public.get(f"/s/{token}", params={"format": "singbox"})
    server.clock.advance(11)
    expired = await public.get(f"/s/{token}", params={"format": "singbox"}, headers={"If-None-Match": before.headers["etag"]})
    assert expired.status_code == 200 and expired.headers["etag"] != before.headers["etag"]
    with server.db(write=True) as db:
        db.execute("UPDATE fleet_nodes SET display_name='New' WHERE node_id='local'")
    renamed = await public.get(f"/s/{token}", params={"format": "singbox"}, headers={"If-None-Match": expired.headers["etag"]})
    assert renamed.status_code == 200 and renamed.headers["etag"] != expired.headers["etag"]


async def test_html_csp_pins_the_exact_inline_style_and_script(public, token):
    response = await public.get(f"/s/{token}", headers={"Accept": "text/html"})
    style_match = re.search(r"<style>(.*?)</style>", response.text, re.S)
    script_match = re.search(r"<script>(.*?)</script>", response.text, re.S)
    assert style_match is not None and script_match is not None
    style, script = style_match.group(1), script_match.group(1)

    def digest(text):
        return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"

    assert f"style-src {digest(style)};" in response.headers["content-security-policy"]
    assert f"script-src {digest(script)};" in response.headers["content-security-policy"]
    assert "default-src 'none'" in response.headers["content-security-policy"]


async def test_deleting_an_archived_client_ends_its_subscription_url(owner, public, client_id, token, server):
    with server.db(write=True) as db:
        db.execute("UPDATE access_grants SET desired_state='deleted',observed_state='missing' WHERE client_id=?", (client_id,))
    assert (await owner.post(f"/api/clients/{client_id}/state", json={"state": "archived"}, headers=csrf(owner))).status_code == 200
    assert (await owner.delete(f"/api/clients/{client_id}", headers=csrf(owner))).status_code == 200
    assert (await public.get(f"/s/{token}")).status_code == 404


async def test_overview_is_secret_free_and_a_second_subscription_is_refused(owner, public, client_id, token):
    await public.get(f"/s/{token}")
    response = await owner.get(f"/api/clients/{client_id}/subscription")
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is True and body["secret_store"] is True and body["escrowed"] is True
    assert body["subscription"]["state"] == "active" and body["subscription"]["generation"] == 1
    assert body["subscription"]["last_fetched_at"] is not None
    assert token not in response.text and "secret_ref" not in response.text and "public_token_hash" not in response.text
    assert {grant["protocol"] for grant in body["grants"]} == {"mtproxy", "naive", "mieru"}
    duplicate = await owner.post(f"/api/clients/{client_id}/subscription", headers=csrf(owner))
    assert duplicate.status_code == 409 and "already" in duplicate.json()["detail"]


async def test_html_language_is_part_of_the_etag(public, token):
    russian = await public.get(f"/s/{token}", params={"format": "html"})
    english = await public.get(f"/s/{token}", params={"format": "html", "lang": "en"})
    assert 'lang="ru"' in russian.text and "Копировать ссылку подписки" in russian.text
    assert 'lang="en"' in english.text and "Copy the subscription link" in english.text
    assert russian.headers["etag"] != english.headers["etag"]
    assert (await public.get(f"/s/{token}", params={"format": "html", "lang": "en"},
                             headers={"If-None-Match": english.headers["etag"]})).status_code == 304
    other = await public.get(f"/s/{token}", params={"format": "html"},
                             headers={"If-None-Match": english.headers["etag"]})
    assert other.status_code == 200


async def test_endpoint_is_off_without_a_subscription_host(panel_server, login_user, telemt, naive, mieru):
    dark = panel_server(name="dark", hosts=("testserver", "sub.example.com"), telemt=telemt, naive=naive, mieru=mieru,
                        naive_enabled=True, naive_public_host="naive.example.com", mieru_enabled=True,
                        subscription_url="")
    dark.create_admin("owner", "correct horse battery staple", "owner")
    await login_user(dark.client)
    created = await dark.client.post("/api/clients", json={"display_name": "Alone", "subscription": False}, headers=csrf(dark.client))
    client_id = created.json()["id"]
    overview = await dark.client.get(f"/api/clients/{client_id}/subscription")
    assert overview.status_code == 200 and overview.json()["configured"] is False
    refused = await dark.client.post(f"/api/clients/{client_id}/subscription", headers=csrf(dark.client))
    assert refused.status_code == 409 and "PANEL_SUBSCRIPTION_URL" in refused.json()["detail"]
    async with dark.http(SUB_HOST) as public:
        assert (await public.get("/s/" + "A" * 43)).status_code == 404


async def test_rendering_never_logs_or_persists_delivery_credentials(public, token, server, client_id):
    secrets = [server.naive.users["alice"]["password"], server.mieru.users["alice"]["password"],
               server.telemt.users["alice"]["secret"], token]
    for format_name in ("raw", "singbox", "clash", "manifest", "html"):
        response = await public.get(f"/s/{token}", params={"format": format_name})
        assert response.status_code == 200
    with server.db() as db:
        stored = str([[tuple(row) for row in db.execute(f"SELECT * FROM {table}")]
                      for table in ("secret_versions", "audit_log", "access_grants", "client_subscriptions")])
    logs = server.log_path.read_text()
    assert all(secret not in stored and secret not in logs for secret in secrets)
    assert client_id in stored


async def test_a_pending_credential_version_is_not_rendered(pair_factory):
    from panel.tests.test_fleet_v2_delivery import answer, converge, linked, provision

    pair = pair_factory(central={"hosts": ("testserver", "central.example", SUB_HOST),
                                 "subscription_url": f"https://{SUB_HOST}"})
    node, central, node_id = await linked(pair)
    client_id, _ = await provision(central, node_id, protocol="mtproxy")
    issued = await answer(central.client, "POST", f"/api/clients/{client_id}/subscription", status=201)
    revealed = await answer(central.client, "GET", "/api/reveal/" + issued["reveal_token"])
    path = urlsplit(revealed["url"]).path
    async with central.http(SUB_HOST) as public:
        pending = await public.get(path, params={"format": "raw"})
        assert pending.status_code == 200
        assert "tg://proxy" not in pending.text
        await converge(node, central)
        active = await public.get(path, params={"format": "raw"})
        assert active.status_code == 200 and "tg://proxy" in active.text
        assert (await node.telemt.current_access("alice"))["secret"] in active.text
