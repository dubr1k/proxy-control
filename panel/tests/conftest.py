from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from panel.app import Settings, create_app
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
