from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from panel.app import Settings, create_app
from panel.fleet_v2.client import NodeClient
from panel.keyring import Keyring
from panel.naive import MemoryNaive
from panel.mieru import MemoryMieru
from panel.telemt import MemoryTelemt
from panel.versions import VersionClient


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def telemt() -> MemoryTelemt:
    return MemoryTelemt(public_host="proxy.example.com", public_port=443)


@pytest.fixture
def naive() -> MemoryNaive:
    return MemoryNaive()


@pytest.fixture
def mieru() -> MemoryMieru:
    return MemoryMieru()


@pytest.fixture(params=["legacy", "domain"])
async def client(request, tmp_path: Path, telemt: MemoryTelemt, naive: MemoryNaive, mieru: MemoryMieru):
    """Every API test runs against both writers.

    The domain writer must be indistinguishable from the outside: same status codes,
    same response shapes, same audit actions. Anything that differs is a regression,
    not a new feature.
    """
    # Credential escrow is part of the panel now, so the shared app has a keyring.
    master_key = tmp_path / "panel-master-key"
    Keyring.generate().save(master_key)
    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        master_key_file=master_key,
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        login_attempts=3,
        login_window_seconds=60,
        reveal_ttl_seconds=60,
        naive_public_host="naive.example.com",
        naive_enabled=True,
        mieru_enabled=True,
        vnext_writer=request.param,
    )
    app = create_app(
        settings,
        telemt=telemt,
        naive=naive,
        mieru=mieru,
        version_client=VersionClient(str(tmp_path / "missing-version-agent.sock")),
    )
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=False
    ) as value:
        yield value


def _app(tmp_path: Path, name: str, naive: MemoryNaive):
    """One in-process panel with its own database and master key, reachable as
    `https://<name>.example` through an ASGI transport (Fleet v2 central↔node tests)."""
    key = tmp_path / f"{name}-key"
    Keyring.generate().save(key)
    settings = Settings(database_path=tmp_path / f"{name}.sqlite3", master_key_file=key, session_cookie_secure=False,
                        allowed_hosts=("testserver", f"{name}.example"), naive_public_host=f"{name}.example",
                        naive_enabled=True, version_agent_socket=str(tmp_path / "none.sock"))
    return create_app(settings, telemt=MemoryTelemt(public_host=f"{name}.example"), naive=naive, mieru=MemoryMieru(),
                      version_client=VersionClient(str(tmp_path / "none.sock")))


@pytest.fixture
def pair(tmp_path: Path):
    """A node panel and a central panel that reaches it over an in-process transport;
    yields `(node_app, central_app, node_api_key_plaintext)`."""
    node = _app(tmp_path, "node", MemoryNaive())
    central = _app(tmp_path, "central", MemoryNaive())
    _, plaintext = node.state.api_keys.create("central", "node-sync", None, actor={"id": 1, "username": "owner"}, ip="x")
    central.state.links.client_factory = lambda url, key, **kw: NodeClient(url, key, transport=httpx.ASGITransport(app=node), **kw)
    return node, central, plaintext


async def login(client: httpx.AsyncClient, username="owner", password="correct horse battery staple"):
    page = await client.get("/login")
    csrf = page.cookies["panel_csrf"]
    return await client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers={"X-CSRF-Token": csrf},
    )


@pytest.fixture
def login_user():
    return login
