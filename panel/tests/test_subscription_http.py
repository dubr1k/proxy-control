"""`/s/{token}` from the outside: the HTTP semantics a subscriber's client relies on.

The token is a bearer credential, so beyond "the formats come back" the checks are
about what the endpoint refuses to reveal: it exists only on the subscription host,
an unknown token and a revoked one are the same 404 byte for byte, the token never
lands in a log or an audit row, and the ETag moves only when the effective set of
grants moves — including when a grant simply expires.
"""

from __future__ import annotations

import time

import httpx
import pytest

from panel.app import Settings
from panel.tests.harness.server import panel_app
from panel.keyring import Keyring
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.telemt import MemoryTelemt
from panel.versions import VersionClient

pytestmark = pytest.mark.anyio

SUB_HOST = "sub.example.com"
PANEL_HOST = "testserver"
CTX = {"actor": {"id": 1, "username": "owner"}, "ip": "127.0.0.1", "request_id": "req-1"}


class Clock:
    def __init__(self):
        self.now = int(time.time())

    def time(self):
        return self.now

    def monotonic(self):
        return float(self.now)

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def app(tmp_path, clock):
    master_key = tmp_path / "panel-master-key"
    Keyring.generate().save(master_key)
    app = panel_app(
        Settings(
            database_path=tmp_path / "panel.sqlite3", master_key_file=master_key,
            session_cookie_secure=False, allowed_hosts=(PANEL_HOST, SUB_HOST),
            naive_public_host="naive.example.com", naive_enabled=True, mieru_enabled=True,
            subscription_url=f"https://{SUB_HOST}", vnext_writer="domain",
        ),
        telemt=MemoryTelemt(public_host="proxy.example.com", public_port=443),
        naive=MemoryNaive(), mieru=MemoryMieru(),
        version_client=VersionClient(str(tmp_path / "missing.sock")),
    )
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    app.state.clock = clock
    return app


@pytest.fixture
async def public(app):
    """A subscriber: no session, no CSRF, talking to the subscription host."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"http://{SUB_HOST}"
    ) as client:
        yield client


@pytest.fixture
async def client_id(app, login_user, clock):
    """One client with all three protocols, provisioned the way production does it."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"http://{PANEL_HOST}"
    ) as owner:
        await login_user(owner)
        headers = {"X-CSRF-Token": owner.cookies["panel_csrf"]}
        for path, body in (
            ("/api/users", {"username": "alice"}),
            ("/api/naive/users", {"username": "alice"}),
            ("/api/mieru/users", {"username": "alice", "expected_revision": "rev-1"}),
        ):
            response = await owner.post(path, json=body, headers=headers)
            assert response.status_code in (200, 201), (path, response.text)
        items = (await owner.get("/api/clients")).json()["items"]
    assert len(items) == 1
    client = items[0]["client"]["id"]
    # The naive grant expires in a week: the boundary the ETag test crosses.
    with app.state.database.transaction() as db:
        for grant in app.state.clients.store.grants(db, client_id=client, protocol="naive"):
            app.state.clients.store.update_grant(db, grant.id, valid_until=clock.time() + 7 * 86400)
    return client


@pytest.fixture
def subscriptions(app):
    return app.state.subscriptions


@pytest.fixture
def token(subscriptions, client_id):
    return subscriptions.create(client_id, **CTX)[1]


async def test_public_subscription_serves_formats_with_etag_and_304(public, token):
    first = await public.get(f"/s/{token}")
    assert first.status_code == 200 and first.headers["cache-control"] == "private, no-cache"
    assert first.headers["content-type"].startswith("text/plain")
    etag = first.headers["etag"]
    assert etag.startswith('"') and etag.endswith('"')
    assert first.headers["profile-update-interval"] == "12"
    assert first.headers["x-robots-tag"] == "noindex" and first.headers["vary"] == "Accept, User-Agent"
    lines = first.text.splitlines()
    assert any(line.startswith("tg://proxy?server=proxy.example.com&port=443&secret=ee") for line in lines)
    assert any(line.startswith("naive+https://alice:") for line in lines)
    assert any(line.startswith("mierus://alice:") and "@mieru.example.com" in line for line in lines)
    assert not any(line.startswith("#") for line in lines)

    again = await public.get(f"/s/{token}", headers={"If-None-Match": etag})
    assert again.status_code == 304 and again.headers["etag"] == etag and not again.content

    html = await public.get(f"/s/{token}", headers={"Accept": "text/html"})
    assert html.headers["content-type"].startswith("text/html")
    csp = html.headers["content-security-policy"]
    assert csp.startswith("default-src 'none'") and "img-src data:" in csp
    # Style and script are admitted by hash of the exact inline text; nothing is `unsafe-inline`.
    assert "unsafe-inline" not in csp and "style-src 'sha256-" in csp and "script-src 'sha256-" in csp
    singbox = await public.get(f"/s/{token}", params={"format": "singbox"})
    assert singbox.headers["content-type"].startswith("application/json")
    assert {o["type"] for o in singbox.json()["outbounds"]} == {"naive", "mieru"}
    official = await public.get(f"/s/{token}", params={"format": "singbox", "client": "singbox"})
    assert [o["type"] for o in official.json()["outbounds"]] == ["naive"]
    # A different body never shares a tag with the Karing cut, and a conditional
    # request on the variant revalidates against its own tag.
    assert official.headers["etag"] != singbox.headers["etag"]
    again = await public.get(
        f"/s/{token}", params={"format": "singbox", "client": "singbox"},
        headers={"If-None-Match": official.headers["etag"]},
    )
    assert again.status_code == 304
    assert (await public.get(f"/s/{token}", params={"format": "singbox", "client": "mihomo"})).status_code == 404
    assert (await public.get(f"/s/{token}", params={"format": "raw", "client": "singbox"})).status_code == 404
    clash = await public.get(f"/s/{token}", params={"format": "clash"})
    assert clash.headers["content-type"].startswith("text/yaml")
    manifest = await public.get(f"/s/{token}", headers={"Accept": "application/vnd.proxy-control.subscription+json"})
    assert manifest.headers["content-type"].startswith("application/vnd.proxy-control.subscription+json")

    head = await public.head(f"/s/{token}")
    assert head.status_code == 200 and head.headers["etag"] == etag and not head.content


async def test_a_fork_core_client_is_recognised_by_user_agent_and_the_official_core_is_not(public, token):
    """Throne, NekoBox, Hiddify get the sing-box JSON cut for their core without asking for a format; an
    official sing-box or an unknown agent keeps what it got before; an explicit `client` always wins."""
    throne = await public.get(f"/s/{token}", headers={"User-Agent": "Throne/1.1.4"})
    assert throne.headers["content-type"].startswith("application/json")
    assert throne.json()["proxy_control"]["client"] == "throne"
    assert {o["type"] for o in throne.json()["outbounds"]} == {"naive", "mieru"}
    for agent, client in (("NekoBox/Android 5.0", "nekobox"), ("NyameBox/1", "nekobox"), ("HiddifyNext/2.5", "hiddify"),
                          ("nekoray/4.0", "nekobox")):
        body = (await public.get(f"/s/{token}", headers={"User-Agent": agent})).json()
        assert body["proxy_control"]["client"] == client, agent
        if client == "nekobox":
            assert {o["type"] for o in body["outbounds"]} == {"naive", "mieru"}, agent
            explicit = await public.get(
                f"/s/{token}", params={"format": "singbox", "client": "nekobox"},
                headers={"User-Agent": agent},
            )
            assert {o["type"] for o in explicit.json()["outbounds"]} == {"naive", "mieru"}, agent
    for agent in ("sing-box 1.13.0", "SFA/1.13", "SFI/1.13", "curl/8", ""):
        plain = await public.get(f"/s/{token}", headers={"User-Agent": agent})
        assert plain.headers["content-type"].startswith("text/plain"), agent  # nothing changed for them
    official = await public.get(f"/s/{token}", params={"format": "singbox"}, headers={"User-Agent": "sing-box 1.13.0"})
    assert official.json()["proxy_control"]["client"] == "karing"
    forced = await public.get(f"/s/{token}", params={"format": "singbox", "client": "hiddify"}, headers={"User-Agent": "sing-box 1.13.0"})
    assert forced.json()["proxy_control"]["client"] == "hiddify"
    kept = await public.get(f"/s/{token}", params={"format": "singbox", "client": "singbox"}, headers={"User-Agent": "Throne/1.1.4"})
    assert kept.json()["proxy_control"]["client"] == "singbox"
    assert (await public.get(f"/s/{token}", params={"format": "singbox", "client": "nyamebox"})).json()["proxy_control"]["client"] == "nekobox"
    clash = await public.get(f"/s/{token}", params={"format": "clash"}, headers={"User-Agent": "Throne/1.1.4"})
    assert clash.headers["content-type"].startswith("text/yaml")
    # the ETag follows the cut, so a client switching cut is never answered 304 for the other body
    cuts = {(await public.get(f"/s/{token}", headers={"User-Agent": a})).headers["etag"] for a in ("Throne/1", "NekoBox/1", "Hiddify/1")}
    assert len(cuts) == 3





async def test_node_rename_refreshes_subscription_with_the_same_url(public, token, app):
    from panel.nodes.registry import NodeRegistry

    params = {"format": "singbox"}
    before = await public.get(f"/s/{token}", params=params)
    assert before.status_code == 200
    with app.state.database.transaction() as db:
        NodeRegistry.rename(db, "local", "Amsterdam")
    after = await public.get(f"/s/{token}", params=params, headers={"If-None-Match": before.headers["etag"]})
    assert after.status_code == 200 and after.headers["etag"] != before.headers["etag"]
    assert all(out["tag"].startswith("Amsterdam · ") for out in after.json()["outbounds"])
    # A display rename does not provision/rotate anything or change transport fields.
    assert [{k: v for k, v in out.items() if k != "tag"} for out in before.json()["outbounds"]] == [
        {k: v for k, v in out.items() if k != "tag"} for out in after.json()["outbounds"]
    ]
    again = await public.get(f"/s/{token}", params=params, headers={"If-None-Match": after.headers["etag"]})
    assert again.status_code == 304


async def test_disabled_grants_rename_invalidates_html_conditional_get(public, token, app, client_id):
    from panel.nodes.registry import NodeRegistry

    with app.state.database.transaction() as db:
        db.execute("UPDATE access_grants SET desired_state='disabled' WHERE client_id=?", (client_id,))
    before = await public.get(f"/s/{token}", params={"format": "html"})
    assert before.status_code == 200
    with app.state.database.transaction() as db:
        NodeRegistry.rename(db, "local", "Renamed disabled node")
    after = await public.get(
        f"/s/{token}", params={"format": "html"}, headers={"If-None-Match": before.headers["etag"]},
    )
    assert after.status_code == 200
    assert after.headers["etag"] != before.headers["etag"]


async def test_the_panel_host_does_not_serve_subscriptions_at_all(public, token):
    on_panel = await public.get(f"/s/{token}", headers={"host": PANEL_HOST})
    missing = await public.get("/s/" + "A" * 43)
    assert on_panel.status_code == 404 and on_panel.content == missing.content
    assert on_panel.headers["cache-control"] == "private, no-cache"


async def test_absent_and_revoked_tokens_are_indistinguishable_404(public, token, subscriptions, client_id):
    missing = await public.get("/s/" + "A" * 43)
    subscriptions.revoke(client_id, **CTX)
    revoked = await public.get(f"/s/{token}")
    assert missing.status_code == revoked.status_code == 404 and missing.content == revoked.content
    assert (await public.get("/s/short")).status_code == 404
    unknown_format = await public.get("/s/" + "A" * 43, params={"format": "karing"})
    assert unknown_format.status_code == 404 and unknown_format.content == missing.content
    assert (await public.get(f"/s/{token}", params={"format": "karing"})).content == missing.content


async def test_expiry_boundary_invalidates_the_old_etag(public, token, clock):
    etag = (await public.get(f"/s/{token}")).headers["etag"]
    clock.advance(30 * 86400)
    after = await public.get(f"/s/{token}", headers={"If-None-Match": etag})
    assert after.status_code == 200 and after.headers["etag"] != etag
    lines = after.text.splitlines()
    assert "# disabled naive alice" in lines
    assert not any(line.startswith("naive+https://") for line in lines)


async def test_generation_moves_with_a_grant_change_and_the_etag_follows(public, token, app, login_user):
    before = await public.get(f"/s/{token}", params={"format": "singbox"})
    assert before.json()["proxy_control"]["generation"] == 1
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"http://{PANEL_HOST}"
    ) as owner:
        await login_user(owner)
        headers = {"X-CSRF-Token": owner.cookies["panel_csrf"]}
        assert (await owner.post("/api/naive/users/alice/disable", headers=headers)).status_code == 200
    after = await public.get(f"/s/{token}", params={"format": "singbox"}, headers={"If-None-Match": before.headers["etag"]})
    assert after.status_code == 200 and after.headers["etag"] != before.headers["etag"]
    assert after.json()["proxy_control"]["generation"] == 2
    assert {o["type"] for o in after.json()["outbounds"]} == {"mieru"}


async def test_token_never_reaches_application_logs_or_audit(public, token, caplog, app):
    caplog.set_level("DEBUG")
    assert (await public.get(f"/s/{token}")).status_code == 200
    # The test client (httpx) logs the URL it requested; that is the caller's side.
    # Nothing the application logs may carry the token.
    application = [r.getMessage() for r in caplog.records if not r.name.startswith(("httpx", "httpcore"))]
    assert all(token not in line for line in application), application
    with app.state.database.connect() as db:
        rows = db.execute("SELECT detail_json, target FROM audit_log").fetchall()
        stored = db.execute("SELECT public_token_hash FROM client_subscriptions").fetchall()
    assert rows and all(token not in (row[0] or "") and token not in (row[1] or "") for row in rows)
    assert stored and all(token != row[0] for row in stored)


async def test_rate_limit_returns_429_and_counts_misses_too(public, token):
    for _ in range(30):
        assert (await public.get(f"/s/{token}", headers={"If-None-Match": '"none"'})).status_code == 200
    for _ in range(30):
        assert (await public.get("/s/" + "B" * 43)).status_code == 404
    limited = await public.get(f"/s/{token}")
    assert limited.status_code == 429 and limited.headers["cache-control"] == "private, no-cache"


# --- the operator's side: /api/clients/{id}/subscription ----------------------------------


@pytest.fixture
async def owner(app, login_user):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"http://{PANEL_HOST}"
    ) as client:
        await login_user(client)
        client.headers["X-CSRF-Token"] = client.cookies["panel_csrf"]
        yield client


async def test_creating_a_subscription_reveals_the_url_once_and_never_again(owner, public, client_id):
    before = await owner.get(f"/api/clients/{client_id}/subscription")
    assert before.status_code == 200
    assert before.json()["subscription"] is None and before.json()["configured"] is True
    assert {item["protocol"] for item in before.json()["grants"]} == {"mtproxy", "naive", "mieru"}

    created = await owner.post(f"/api/clients/{client_id}/subscription")
    assert created.status_code == 201, created.text
    assert set(created.json()) == {"reveal_token"}
    reveal = await owner.get(f"/api/reveal/{created.json()['reveal_token']}")
    assert reveal.status_code == 200
    payload = reveal.json()
    assert payload["url"].startswith(f"https://{SUB_HOST}/s/") and payload["qr"].startswith("data:image/svg+xml;base64,")
    assert set(payload["variants"]) == {"raw", "singbox", "singbox-official", "singbox-hiddify", "singbox-nekobox", "clash"}
    assert payload["variants"]["singbox"]["url"] == payload["url"] + "?format=singbox"
    assert payload["variants"]["singbox-official"]["url"] == payload["url"] + "?format=singbox&client=singbox"
    assert payload["variants"]["singbox-hiddify"]["url"] == payload["url"] + "?format=singbox&client=hiddify"
    assert payload["variants"]["singbox-nekobox"]["url"] == payload["url"] + "?format=singbox&client=nekobox"
    assert payload["generation"] == 1
    # A reveal is consumed on first read; the URL is not stored anywhere readable.
    assert (await owner.get(f"/api/reveal/{created.json()['reveal_token']}")).status_code == 410

    token = payload["url"].rsplit("/", 1)[1]
    assert (await public.get(f"/s/{token}")).status_code == 200

    after = await owner.get(f"/api/clients/{client_id}/subscription")
    body = after.json()
    assert body["subscription"]["generation"] == 1 and body["subscription"]["state"] == "active"
    assert body["subscription"]["last_fetched_at"] is not None
    assert token not in after.text and "token" not in json_keys(body["subscription"])
    # A second subscription for the same client is refused: one URL per client.
    assert (await owner.post(f"/api/clients/{client_id}/subscription")).status_code == 409


def json_keys(value) -> set[str]:
    return {key.lower() for key in value} if isinstance(value, dict) else set()


async def test_rotate_and_revoke_move_the_public_url(owner, public, client_id, app):
    created = await owner.post(f"/api/clients/{client_id}/subscription")
    first = (await owner.get(f"/api/reveal/{created.json()['reveal_token']}")).json()["url"]
    rotated = await owner.post(f"/api/clients/{client_id}/subscription/rotate")
    assert rotated.status_code == 200, rotated.text
    second = (await owner.get(f"/api/reveal/{rotated.json()['reveal_token']}")).json()
    assert second["url"] != first and second["generation"] == 2
    assert (await public.get("/s/" + first.rsplit("/", 1)[1])).status_code == 404
    assert (await public.get("/s/" + second["url"].rsplit("/", 1)[1])).status_code == 200

    revoked = await owner.post(f"/api/clients/{client_id}/subscription/revoke")
    assert revoked.status_code == 200 and revoked.json() == {"revoked": True}
    assert (await public.get("/s/" + second["url"].rsplit("/", 1)[1])).status_code == 404
    assert (await owner.get(f"/api/clients/{client_id}/subscription")).json()["subscription"] is None
    # Rotating what does not exist is a conflict, revoking it again is a no-op.
    assert (await owner.post(f"/api/clients/{client_id}/subscription/rotate")).status_code == 409
    assert (await owner.post(f"/api/clients/{client_id}/subscription/revoke")).json() == {"revoked": False}
    with app.state.database.connect() as db:
        actions = [row[0] for row in db.execute("SELECT action FROM audit_log ORDER BY id").fetchall()]
    operator_actions = [a for a in actions if a in {"subscription.create", "subscription.rotate", "subscription.revoke"}]
    assert operator_actions == ["subscription.create", "subscription.rotate", "subscription.revoke"]


async def test_the_url_can_be_shown_again_through_an_audited_reveal(owner, public, client_id, app):
    created = await owner.post(f"/api/clients/{client_id}/subscription")
    first = (await owner.get(f"/api/reveal/{created.json()['reveal_token']}")).json()
    overview = (await owner.get(f"/api/clients/{client_id}/subscription")).json()
    assert overview["escrowed"] is True and overview["secret_store"] is True
    assert {item["node_id"] for item in overview["grants"]} == {"local"}

    shown = await owner.post(f"/api/clients/{client_id}/subscription/reveal")
    assert shown.status_code == 200 and set(shown.json()) == {"reveal_token"}
    payload = (await owner.get(f"/api/reveal/{shown.json()['reveal_token']}")).json()
    assert payload["url"] == first["url"] and set(payload["variants"]) == {"raw", "singbox", "singbox-official", "singbox-hiddify", "singbox-nekobox", "clash"}
    assert payload["qr"].startswith("data:image/svg+xml;base64,")
    # Consumed on first read, like every reveal.
    assert (await owner.get(f"/api/reveal/{shown.json()['reveal_token']}")).status_code == 410
    with app.state.database.connect() as db:
        actions = [row[0] for row in db.execute("SELECT action FROM audit_log ORDER BY id").fetchall()]
    assert actions.count("subscription.reveal") == 1

    await owner.post(f"/api/clients/{client_id}/subscription/revoke")
    assert (await owner.post(f"/api/clients/{client_id}/subscription/reveal")).status_code == 404


async def test_reveal_refuses_a_subscription_without_an_escrowed_copy(owner, client_id, app):
    await owner.post(f"/api/clients/{client_id}/subscription")
    with app.state.database.transaction() as db:
        db.execute("UPDATE client_subscriptions SET secret_id=NULL, secret_version=NULL")
    refused = await owner.post(f"/api/clients/{client_id}/subscription/reveal")
    assert refused.status_code == 409 and "rotate" in refused.json()["detail"]
    assert (await owner.get(f"/api/clients/{client_id}/subscription")).json()["escrowed"] is False


async def test_subscription_management_needs_a_writer_role_and_a_configured_url(app, login_user, client_id, tmp_path):
    app.state.store.create_admin("viewer", "correct horse battery staple", "viewer")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"http://{PANEL_HOST}"
    ) as viewer:
        await login_user(viewer, "viewer")
        viewer.headers["X-CSRF-Token"] = viewer.cookies["panel_csrf"]
        assert (await viewer.get(f"/api/clients/{client_id}/subscription")).status_code == 200
        assert (await viewer.post(f"/api/clients/{client_id}/subscription")).status_code == 403
        assert (await viewer.post(f"/api/clients/{client_id}/subscription/rotate")).status_code == 403
        assert (await viewer.post(f"/api/clients/{client_id}/subscription/revoke")).status_code == 403
        assert (await viewer.post(f"/api/clients/{client_id}/subscription/reveal")).status_code == 403
        compat = await viewer.get("/api/subscriptions/compatibility")
        assert compat.status_code == 200 and set(compat.json()["matrix"]) == {"mtproxy", "naive", "mieru", "trusttunnel"}
        # The app catalogue rides along additively: the chooser reads it, matrix and notes keep their shape.
        body = compat.json()
        assert set(body) == {"matrix", "notes", "platforms", "apps"} and body["apps"] and body["platforms"]
        assert {app["variant"] for app in body["apps"]} <= {"singbox", "singbox-hiddify", "singbox-official", "clash"}

    app.state.subscriptions.public_base = ""  # what an empty PANEL_SUBSCRIPTION_URL leaves behind
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"http://{PANEL_HOST}"
    ) as owner:
        await login_user(owner)
        owner.headers["X-CSRF-Token"] = owner.cookies["panel_csrf"]
        assert (await owner.get(f"/api/clients/{client_id}/subscription")).json()["configured"] is False
        refused = await owner.post(f"/api/clients/{client_id}/subscription")
        assert refused.status_code == 409 and "PANEL_SUBSCRIPTION_URL" in refused.json()["detail"]


async def test_the_endpoint_is_off_entirely_without_a_subscription_host(tmp_path, token):
    master_key = tmp_path / "other-master-key"
    Keyring.generate().save(master_key)
    dark = panel_app(
        Settings(
            database_path=tmp_path / "dark.sqlite3", master_key_file=master_key,
            session_cookie_secure=False, allowed_hosts=(PANEL_HOST, SUB_HOST),
        ),
        telemt=MemoryTelemt(), naive=MemoryNaive(), mieru=MemoryMieru(),
        version_client=VersionClient(str(tmp_path / "missing.sock")),
    )
    assert dark.state.settings.subscription_host == ""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=dark), base_url=f"http://{SUB_HOST}"
    ) as client:
        assert (await client.get(f"/s/{token}")).status_code == 404


async def test_post_clients_hands_back_a_subscription_reveal(owner, public):
    created = await owner.post("/api/clients", json={"display_name": "Phone"})
    assert created.status_code == 201, created.text
    body = created.json()
    token = body["subscription_reveal_token"]
    assert token and "token" not in {k for k in body if k != "subscription_reveal_token"}
    payload = (await owner.get(f"/api/reveal/{token}")).json()
    assert payload["url"].startswith(f"https://{SUB_HOST}/s/") and payload["generation"] == 1
    assert (await public.get("/s/" + payload["url"].rsplit("/", 1)[1])).status_code == 200
    overview = (await owner.get(f"/api/clients/{body['id']}/subscription")).json()
    assert overview["subscription"]["generation"] == 1 and overview["escrowed"] is True

    without = await owner.post("/api/clients", json={"display_name": "Card only", "subscription": False})
    assert without.status_code == 201 and without.json()["subscription_reveal_token"] is None


async def test_client_rename_and_access_label_refresh_the_subscription_on_the_same_url(public, token, app, client_id):
    actor = {"id": 1, "username": "owner"}
    params = {"format": "singbox"}
    before = await public.get(f"/s/{token}", params=params)
    with app.state.database.connect() as db:
        grant_id = next(g.id for g in app.state.clients.store.grants(db, client_id=client_id) if g.protocol == "naive")
    app.state.clients.set_grant_label(grant_id, "Дом", actor=actor, ip="x")
    labelled = await public.get(f"/s/{token}", params=params, headers={"If-None-Match": before.headers["etag"]})
    assert labelled.status_code == 200 and labelled.headers["etag"] != before.headers["etag"]
    assert "Дом" in [out["tag"] for out in labelled.json()["outbounds"]]
    app.state.clients.set_grant_label(grant_id, None, actor=actor, ip="x")
    reset = await public.get(f"/s/{token}", params=params)
    assert reset.headers["etag"] == before.headers["etag"]
    html = await public.get(f"/s/{token}", params={"format": "html"})
    app.state.clients.rename_client(client_id, "Мама Samsung", actor=actor, ip="x")
    renamed = await public.get(f"/s/{token}", params={"format": "html"}, headers={"If-None-Match": html.headers["etag"]})
    assert renamed.status_code == 200 and "Мама Samsung" in renamed.text


def _inline(text: str, tag: str) -> str:
    start = text.index(f"<{tag}>") + len(tag) + 2
    return text[start:text.index(f"</{tag}>", start)]


def _hash(text: str) -> str:
    import base64
    import hashlib

    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


async def test_the_page_runs_only_the_inline_style_and_script_the_policy_names_by_hash(public, token):
    page = await public.get(f"/s/{token}", headers={"Accept": "text/html"})
    csp = page.headers["content-security-policy"]
    assert f"style-src {_hash(_inline(page.text, 'style'))};" in csp
    assert f"script-src {_hash(_inline(page.text, 'script'))};" in csp
    assert page.text.count("<script") == 1 and "<script src" not in page.text and 'style="' not in page.text
    assert "onclick" not in page.text and "<link" not in page.text
    # The other formats keep the same strict policy: no script is admitted for a JSON feed either way.
    assert "frame-ancestors 'none'" in csp and "default-src 'none'" in csp


async def test_the_page_offers_the_link_apps_and_follows_lang(public, token):
    page = await public.get(f"/s/{token}", headers={"Accept": "text/html"})
    url = f"https://{SUB_HOST}/s/{token}"
    assert f">{url}</code>" in page.text and "Копировать ссылку подписки" in page.text
    assert "Показать QR" in page.text and "Добавить в Karing" in page.text and 'lang="ru"' in page.text
    assert "karing://install-config?url=" in page.text
    english = await public.get(f"/s/{token}", params={"format": "html", "lang": "en"})
    assert 'lang="en"' in english.text and "Copy the subscription link" in english.text and "Add to Karing" in english.text
    assert english.headers["etag"] != page.headers["etag"]
    # The language is part of the tag: a conditional request for the other language is a full answer.
    other = await public.get(f"/s/{token}", params={"format": "html"}, headers={"If-None-Match": english.headers["etag"]})
    assert other.status_code == 200
    assert (await public.get(f"/s/{token}", params={"format": "html", "lang": "en"},
                             headers={"If-None-Match": english.headers["etag"]})).status_code == 304
