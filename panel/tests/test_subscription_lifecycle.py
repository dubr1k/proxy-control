"""A subscription URL is a bearer credential, so the panel keeps only its hash.

Two properties matter beyond that. The generation moves with the change that caused it —
inside the same transaction — so a rolled-back mutation never leaves a bumped counter
telling clients to re-fetch nothing. And the ETag follows the *effective* set of grants,
not the time of the last fetch: a grant that expired changes the answer, reading it does
not.
"""

from __future__ import annotations

import time
import uuid

import pytest

from panel.clients.models import AccessGrant, MieruOptions, NaiveOptions
from panel.clients.service import CREDENTIAL_PURPOSE, ClientService
from panel.clients.store import ClientConflict
from panel.database import Database
from panel.keyring import Keyring
from panel.migrations import apply_migrations
from panel.secrets_store import SecretStore
from panel.subscriptions.service import SubscriptionService

pytestmark = pytest.mark.anyio

CTX = {"actor": {"id": 1, "username": "owner"}, "ip": "127.0.0.1", "request_id": "req-1"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


class Clock:
    def __init__(self):
        self.now = int(time.time())

    def time(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def world(tmp_path, clock):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    secrets = SecretStore(Keyring.generate())
    clients = ClientService(database, secrets, clock=clock)
    subscriptions = SubscriptionService(database, clients, secrets, clock=clock)
    clients.on_change.append(subscriptions.bump_generation)
    return clients, subscriptions


@pytest.fixture
def clients(world):
    return world[0]


@pytest.fixture
def subscriptions(world):
    return world[1]


def _grant(clients, client_id, protocol, username, *, now, valid_until=None, with_secret=True):
    options = {"naive": NaiveOptions(), "mieru": MieruOptions(quotas=[])}[protocol]
    grant = AccessGrant(
        id=str(uuid.uuid4()), client_id=client_id, protocol=protocol, node_id="local",
        endpoint_id="default", runtime_username=username, desired_state="enabled",
        observed_state="enabled", valid_until=valid_until, options=options,
        origin="provisioned", created_at=now, updated_at=now,
    )
    with clients.database.transaction() as db:
        clients.store.insert_grant(db, grant)
        if with_secret:
            reference = clients.secrets.store(
                db, secret_id=f"grant:{grant.id}", version=1, purpose=CREDENTIAL_PURPOSE,
                grant_id=grant.id, permitted_node_id="local",
                plaintext=b"caller-supplied-password-01", state="active",
            )
            clients.store.update_grant(
                db, grant.id, secret_id=reference.secret_id, secret_version=reference.version,
            )
    return grant


@pytest.fixture
def client_id(clients, clock):
    client = clients.create_client("Sergey", **CTX)
    _grant(clients, client.id, "naive", "alice", now=clock.time())
    _grant(clients, client.id, "mieru", "alice", now=clock.time(), valid_until=clock.time() + 7 * 86400)
    return client.id


async def test_token_is_shown_once_and_only_its_hash_is_stored(subscriptions, client_id):
    subscription, token = subscriptions.create(client_id, **CTX)
    assert len(token) >= 43 and subscription.generation == 1
    with subscriptions.database.connect() as db:
        stored = db.execute("SELECT public_token_hash FROM client_subscriptions").fetchone()[0]
    assert stored != token
    # The bearer value must not survive anywhere on disk.
    assert token not in subscriptions.database.path.read_bytes().decode("latin-1")
    assert subscriptions.resolve(token).id == subscription.id
    assert subscriptions.resolve("x" * 43) is None
    assert not hasattr(subscription, "token")


async def test_rotate_revokes_the_old_url(subscriptions, client_id):
    _, old = subscriptions.create(client_id, **CTX)
    _, new = subscriptions.rotate(client_id, **CTX)
    assert old != new
    assert subscriptions.resolve(old) is None and subscriptions.resolve(new) is not None
    subscriptions.revoke(client_id, **CTX)
    assert subscriptions.resolve(new) is None
    assert subscriptions.get(client_id) is None


async def test_generation_increments_with_the_mutation_or_not_at_all(
    subscriptions, clients, client_id, monkeypatch
):
    subscriptions.create(client_id, **CTX)
    clients.set_state(client_id, "suspended", **CTX)
    assert subscriptions.get(client_id).generation == 2

    from panel.clients import service as module

    def broken(*_args, **_kwargs):
        raise RuntimeError("audit down")

    monkeypatch.setattr(module, "record", broken)
    with pytest.raises(RuntimeError):
        clients.set_state(client_id, "active", **CTX)
    # The bump lives in the same transaction as the change, so it rolled back with it.
    assert subscriptions.get(client_id).generation == 2


async def test_create_refuses_grants_without_escrowed_credentials(subscriptions, clients, clock):
    client = clients.create_client("Nobody", **CTX)
    _grant(clients, client.id, "mieru", "orphan", now=clock.time(), with_secret=False)
    with pytest.raises(ClientConflict, match="orphan"):
        subscriptions.create(client.id, **CTX)
    assert subscriptions.get(client.id) is None


async def test_etag_follows_the_effective_set_not_the_fetch_time(subscriptions, client_id, clock):
    subscription, _ = subscriptions.create(client_id, **CTX)
    before = subscriptions.etag(subscriptions.effective_manifest(subscription, clock.time()), 1)
    subscriptions.record_fetch(subscription, clock.time(), status=200, format="raw")
    # Reading the subscription is not a change to it.
    assert subscriptions.etag(subscriptions.effective_manifest(subscription, clock.time()), 1) == before

    clock.advance(30 * 86400)
    after = subscriptions.etag(subscriptions.effective_manifest(subscription, clock.time()), 1)
    assert after != before
    manifest = subscriptions.effective_manifest(subscription, clock.time())
    expired = [item for item in manifest.grants if item.protocol == "mieru"][0]
    assert expired.enabled is False


async def test_a_suspended_client_renders_nothing_as_enabled(subscriptions, clients, client_id, clock):
    subscription, _ = subscriptions.create(client_id, **CTX)
    clients.set_state(client_id, "suspended", **CTX)
    manifest = subscriptions.effective_manifest(subscription, clock.time())
    assert manifest.grants and all(item.enabled is False for item in manifest.grants)


async def test_a_second_active_subscription_cannot_exist(subscriptions, client_id):
    subscriptions.create(client_id, **CTX)
    with pytest.raises(ClientConflict, match="already"):
        subscriptions.create(client_id, **CTX)


async def test_the_public_url_is_built_from_the_configured_base(subscriptions, client_id):
    _, token = subscriptions.create(client_id, **CTX)
    subscriptions.public_base = "https://eclipse.example.com/"
    assert subscriptions.public_url(token) == f"https://eclipse.example.com/s/{token}"


async def test_the_app_wires_the_generation_hook_to_every_change(tmp_path, login_user):
    """Registering the hook once must cover every mutation path, not just direct ones."""
    import httpx

    from panel.app import Settings, create_app
    from panel.mieru import MemoryMieru
    from panel.naive import MemoryNaive
    from panel.telemt import MemoryTelemt
    from panel.versions import VersionClient

    master_key = tmp_path / "panel-master-key"
    Keyring.generate().save(master_key)
    app = create_app(
        Settings(
            database_path=tmp_path / "panel.sqlite3", session_cookie_secure=False,
            allowed_hosts=("testserver",), naive_public_host="naive.example.com",
            naive_enabled=True, mieru_enabled=True, master_key_file=master_key,
            subscription_url="https://eclipse.example.com", vnext_writer="domain",
        ),
        telemt=MemoryTelemt(), naive=MemoryNaive(), mieru=MemoryMieru(),
        version_client=VersionClient(str(tmp_path / "missing.sock")),
    )
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as http:
        await login_user(http)
        headers = {"X-CSRF-Token": http.cookies["panel_csrf"]}
        await http.post("/api/naive/users", json={"username": "alice"}, headers=headers)

        client_id = (await http.get("/api/clients")).json()["items"][0]["client"]["id"]
        subscription, _ = app.state.subscriptions.create(
            client_id, actor={"id": 1, "username": "owner"}, ip="127.0.0.1", request_id="req-1"
        )
        assert subscription.generation == 1

        # A protocol endpoint the subscription knows nothing about still moves it.
        await http.post("/api/naive/users/alice/disable", headers=headers)
        assert app.state.subscriptions.get(client_id).generation == 2
        assert app.state.subscriptions.public_base == "https://eclipse.example.com"
