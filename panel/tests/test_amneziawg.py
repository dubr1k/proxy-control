"""AmneziaWG: the panel's keys, the node manager's server side, one version per access."""
from __future__ import annotations

import base64
import json

import pytest
from pydantic import ValidationError

from panel.amneziawg import AmneziawgClient, AmneziawgError, MemoryAmneziawg
from panel.clients.models import AccessGrant, AmneziawgOptions, GrantIntent, MieruOptions
from panel.clients.provisioning import new_credential
from panel.protocols import AmneziawgAdapter, CredentialPlan, GrantRef
from panel.protocols.amneziawg import parse_credential, public_key_of, render_conf

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _adapter(manager=None):
    manager = manager or MemoryAmneziawg()
    return manager, AmneziawgAdapter(manager, public_host="vpn.example.com")


def _intent(version="2.0", username="alice-awg20"):
    return GrantIntent(protocol="amneziawg", runtime_username=username, options=AmneziawgOptions(version=version))


def _grant(applied, version="2.0", username="alice-awg20"):
    return AccessGrant(
        id="g1", client_id="c1", protocol="amneziawg", node_id="local", endpoint_id="default",
        runtime_username=username, desired_state="enabled",
        options=AmneziawgOptions(**{**applied.artifact_template, "version": version}),
        origin="provisioned", created_at=1, updated_at=1,
    )
































def test_options_are_bounded():
    assert AmneziawgOptions().version == "2.0"
    for bad in ({"version": "1.0"}, {"version": "4.0"}, {"address": "999.1.1.1"}, {"port": 0},
                {"obfuscation": {"Evil": "1"}}, {"obfuscation": {"Jc": "1\nPostUp = rm -rf /"}},
                {"dns": ["not-an-ip"]}, {"unknown": 1}):
        with pytest.raises(ValidationError):
            AmneziawgOptions(**bad)
    with pytest.raises(ValidationError):
        GrantIntent(protocol="amneziawg", runtime_username="x", options=MieruOptions())





# ---- through the whole panel ---------------------------------------------------------------------

import httpx  # noqa: E402

from panel.app import Settings  # noqa: E402
from panel.tests.harness.server import panel_app  # noqa: E402
from panel.keyring import Keyring  # noqa: E402
from panel.mieru import MemoryMieru  # noqa: E402
from panel.naive import MemoryNaive  # noqa: E402
from panel.telemt import MemoryTelemt  # noqa: E402
from panel.versions import VersionClient  # noqa: E402


@pytest.fixture
def awg() -> MemoryAmneziawg:
    return MemoryAmneziawg()


@pytest.fixture
async def api(tmp_path, awg):
    master_key = tmp_path / "panel-master-key"
    Keyring.generate().save(master_key)
    settings = Settings(
        database_path=tmp_path / "panel.sqlite3", master_key_file=master_key, session_cookie_secure=False,
        allowed_hosts=("testserver",), reveal_ttl_seconds=60, naive_public_host="vpn.example.com",
        naive_enabled=True, mieru_enabled=True, amneziawg_enabled=True, vnext_writer="domain",
    )
    app = panel_app(settings, telemt=MemoryTelemt(public_host="proxy.example.com"), naive=MemoryNaive(),
                     mieru=MemoryMieru(), amneziawg=awg,
                     version_client=VersionClient(str(tmp_path / "missing-version-agent.sock")))
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver",
                                 follow_redirects=False) as client:
        page = await client.get("/login")
        await client.post("/api/auth/login", json={"username": "owner", "password": "correct horse battery staple"},
                          headers={"X-CSRF-Token": page.cookies["panel_csrf"]})
        client.app_state = app.state
        yield client


def _headers(api):
    return {"X-CSRF-Token": api.cookies["panel_csrf"]}


async def _issue(api, grants):
    created = await api.post("/api/clients", json={"display_name": "Alice"}, headers=_headers(api))
    client_id = created.json()["id"]
    started = await api.post(f"/api/clients/{client_id}/grants", json={"grants": grants}, headers=_headers(api))
    assert started.status_code == 200 and started.json()["status"] == "succeeded", started.text
    return client_id


async def _config_of(api, client_id, grant_id):
    issued = await api.post(f"/api/clients/{client_id}/links?grant_id={grant_id}", headers=_headers(api))
    assert issued.status_code == 200, issued.text
    revealed = await api.get(f"/api/reveal/{issued.json()['reveal_token']}")
    [grant] = revealed.json()["grants"]
    [artifact] = grant["artifacts"]
    return artifact




















# ---- a central and a linked node ----------------------------------------------------------------

from panel.clients.models import AmneziawgOptions as _Options  # noqa: E402
from panel.tests.harness.server import start_panel  # noqa: E402

ACTOR = {"id": 1, "username": "owner"}


def _awg_app(tmp_path, name, awg=None, enabled=True, node_routes=None):
    return start_panel(tmp_path, name=name, hosts=("testserver", f"{name}.example"), naive_public_host=f"{name}.example",
                       amneziawg_enabled=enabled, telemt=MemoryTelemt(public_host=f"{name}.example"),
                       naive=MemoryNaive(), mieru=MemoryMieru(), amneziawg=awg or MemoryAmneziawg(),
                       node_routes=node_routes)


async def _linked_awg(tmp_path, *, node_enabled=True):
    node = _awg_app(tmp_path, "node", enabled=node_enabled)
    central = _awg_app(tmp_path, "central", enabled=False, node_routes={"node.example": node})
    plaintext = node.create_api_key("central", "node-sync")
    node_id = await central.state.links.add("Edge", "https://node.example", plaintext, "verify", None, False,
                                            actor=ACTOR, ip="x")
    return node, central, node_id














# ---- the AmneziaWG screen ------------------------------------------------------------------------







def test_the_screen_is_in_the_navigation_and_opens_the_access_window():
    from pathlib import Path

    static = Path(__file__).resolve().parents[1] / "static"
    index = (static / "index.html").read_text(encoding="utf-8")
    main = (static / "js/main.js").read_text(encoding="utf-8")
    screen = (static / "js/amneziawg.js").read_text(encoding="utf-8")
    assert index.count('data-view="amneziawg"') == 2  # the sidebar and the phone bar
    assert 'amneziawg: renderAmneziawg' in main and "handleAmneziawgClick" in main
    assert "features?.amneziawg" in main  # hidden unless the server has the protocol
    assert "/api/amneziawg/overview" in screen and "context.grants.open" in screen
    assert "private" not in screen.lower() or "приватн" not in screen.lower()
