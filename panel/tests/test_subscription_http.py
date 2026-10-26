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
from panel.tests.harness.memories.mieru import MemoryMieru
from panel.tests.harness.memories.naive import MemoryNaive
from panel.tests.harness.memories.telemt import MemoryTelemt
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



































# --- the operator's side: /api/clients/{id}/subscription ----------------------------------


@pytest.fixture
async def owner(app, login_user):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"http://{PANEL_HOST}"
    ) as client:
        await login_user(client)
        client.headers["X-CSRF-Token"] = client.cookies["panel_csrf"]
        yield client





def json_keys(value) -> set[str]:
    return {key.lower() for key in value} if isinstance(value, dict) else set()























def _inline(text: str, tag: str) -> str:
    start = text.index(f"<{tag}>") + len(tag) + 2
    return text[start:text.index(f"</{tag}>", start)]


def _hash(text: str) -> str:
    import base64
    import hashlib

    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"






