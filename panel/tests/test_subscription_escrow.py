"""The subscription token is kept twice: as a hash for /s/{token}, and encrypted under the
keyring so the operator can see the URL again. Showing it is an audited action; a rotated
or revoked URL cannot be shown any more; without a keyring nothing is escrowed."""

from __future__ import annotations

import time
import uuid

import pytest

from panel.clients.models import AccessGrant, NaiveOptions
from panel.clients.service import CREDENTIAL_PURPOSE, ClientService
from panel.clients.store import ClientConflict
from panel.database import Database
from panel.keyring import Keyring
from panel.migrations import apply_migrations
from panel.secrets_store import SecretError, SecretStore
from panel.subscriptions.service import SUBSCRIPTION_PURPOSE, SubscriptionService

CTX = {"actor": {"id": 1, "username": "owner"}, "ip": "127.0.0.1", "request_id": "req-1"}


class Clock:
    def __init__(self):
        self.now = int(time.time())

    def time(self):
        return self.now


def _world(tmp_path, *, keyring):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    secrets = SecretStore(keyring)
    clients = ClientService(database, secrets, clock=Clock())
    subscriptions = SubscriptionService(database, clients, secrets, clock=clients.clock, public_base="https://sub.example.com")
    clients.on_change.append(subscriptions.bump_generation)
    return clients, subscriptions


def _grant(clients, client_id, *, with_secret=True):
    now = clients.clock.time()
    grant = AccessGrant(
        id=str(uuid.uuid4()), client_id=client_id, protocol="naive", node_id="local",
        endpoint_id="default", runtime_username="alice", desired_state="enabled",
        observed_state="enabled", options=NaiveOptions(), origin="provisioned",
        created_at=now, updated_at=now,
    )
    with clients.database.transaction() as db:
        clients.store.insert_grant(db, grant)
        if with_secret:
            ref = clients.secrets.store(
                db, secret_id=f"grant:{grant.id}", version=1, purpose=CREDENTIAL_PURPOSE,
                grant_id=grant.id, permitted_node_id="local", plaintext=b"pw", state="active",
            )
            clients.store.update_grant(db, grant.id, secret_id=ref.secret_id, secret_version=ref.version)
    return grant





















