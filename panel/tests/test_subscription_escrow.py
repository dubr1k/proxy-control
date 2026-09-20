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


def test_the_token_is_escrowed_and_can_be_shown_again_with_an_audit_row(tmp_path):
    clients, subscriptions = _world(tmp_path, keyring=Keyring.generate())
    client = clients.create_client("Sergey", **CTX)
    _grant(clients, client.id)
    subscription, token = subscriptions.create(client.id, **CTX)
    assert subscription.secret_ref is not None and subscription.secret_ref.secret_id == f"subscription:{subscription.id}"
    with subscriptions.database.connect() as db:
        row = db.execute("SELECT purpose, grant_id, permitted_node_id, state FROM secret_versions WHERE secret_id=?", (subscription.secret_ref.secret_id,)).fetchone()
        stored_hash = db.execute("SELECT public_token_hash FROM client_subscriptions").fetchone()[0]
    assert tuple(row) == (SUBSCRIPTION_PURPOSE, None, None, "active") and stored_hash != token
    # The plaintext is on disk only as ciphertext.
    assert token not in subscriptions.database.path.read_bytes().decode("latin-1")

    shown, again = subscriptions.reveal_token(client.id, **CTX)
    assert again == token and shown.id == subscription.id
    assert subscriptions.resolve(again).id == subscription.id
    with subscriptions.database.connect() as db:
        actions = [r[0] for r in db.execute("SELECT action FROM audit_log ORDER BY id")]
        details = [r[0] or "" for r in db.execute("SELECT detail_json FROM audit_log")]
    assert actions[-1] == "subscription.reveal" and all(token not in d for d in details)


def test_rotate_and_revoke_retire_the_escrowed_copy(tmp_path):
    clients, subscriptions = _world(tmp_path, keyring=Keyring.generate())
    client = clients.create_client("Sergey", **CTX)
    _grant(clients, client.id)
    first, old_token = subscriptions.create(client.id, **CTX)
    second, new_token = subscriptions.rotate(client.id, **CTX)
    with subscriptions.database.connect() as db:
        states = dict(db.execute("SELECT secret_id, state FROM secret_versions WHERE purpose=?", (SUBSCRIPTION_PURPOSE,)).fetchall())
    assert states[first.secret_ref.secret_id] == "revoked" and states[second.secret_ref.secret_id] == "active"
    assert subscriptions.reveal_token(client.id, **CTX)[1] == new_token
    subscriptions.revoke(client.id, **CTX)
    with subscriptions.database.connect() as db:
        states = dict(db.execute("SELECT secret_id, state FROM secret_versions WHERE purpose=?", (SUBSCRIPTION_PURPOSE,)).fetchall())
    assert states[second.secret_ref.secret_id] == "revoked"
    with pytest.raises(KeyError):
        subscriptions.reveal_token(client.id, **CTX)


def test_without_a_keyring_nothing_is_escrowed_and_reveal_refuses(tmp_path):
    clients, subscriptions = _world(tmp_path, keyring=None)
    client = clients.create_client("Sergey", **CTX)
    subscription, token = subscriptions.create(client.id, **CTX)
    assert subscription.secret_ref is None and len(token) >= 43
    assert subscriptions.escrow_enabled is False
    with pytest.raises(SecretError):
        subscriptions.reveal_token(client.id, **CTX)


def test_a_subscription_issued_before_escrow_is_a_conflict_not_a_crash(tmp_path):
    clients, subscriptions = _world(tmp_path, keyring=Keyring.generate())
    client = clients.create_client("Sergey", **CTX)
    subscription, _ = subscriptions.create(client.id, **CTX)
    with subscriptions.database.transaction() as db:
        db.execute("UPDATE client_subscriptions SET secret_id=NULL, secret_version=NULL WHERE id=?", (subscription.id,))
    with pytest.raises(ClientConflict, match="not escrowed"):
        subscriptions.reveal_token(client.id, **CTX)


def test_grants_without_a_credential_no_longer_block_a_subscription(tmp_path):
    clients, subscriptions = _world(tmp_path, keyring=Keyring.generate())
    client = clients.create_client("Imported", **CTX)
    _grant(clients, client.id, with_secret=False)
    subscription, _ = subscriptions.create(client.id, **CTX)
    assert subscription.generation == 1


def test_rewrap_and_verify_cover_subscription_tokens(tmp_path):
    keyring = Keyring.generate()
    clients, subscriptions = _world(tmp_path, keyring=keyring)
    client = clients.create_client("Sergey", **CTX)
    subscription, token = subscriptions.create(client.id, **CTX)
    rotated = keyring.rotate()
    fresh = SecretStore(rotated)
    with subscriptions.database.transaction() as db:
        while fresh.rewrap(db, batch_size=10):
            pass
        counts = fresh.verify_all(db)
    assert sum(counts.values()) >= 1
    subscriptions.secrets = fresh
    assert subscriptions.reveal_token(client.id, **CTX)[1] == token
