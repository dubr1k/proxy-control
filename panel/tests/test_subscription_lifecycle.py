"""A subscription URL is a bearer credential, so the panel keeps its hash — and, under the
keyring, an encrypted copy that only an audited reveal opens.

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






























