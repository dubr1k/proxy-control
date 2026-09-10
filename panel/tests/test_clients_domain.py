"""Clients and their access grants: one owner per grant, typed options, no secrets in the model."""

from __future__ import annotations

import sqlite3
import time
import uuid

import pytest
from pydantic import ValidationError

from panel.clients.models import AccessGrant, GrantIntent, MieruOptions, MtproxyOptions, NaiveOptions, effective_enabled
from panel.clients.service import ClientService
from panel.clients.store import ClientConflict, ClientStore
from panel.database import Database
from panel.migrations import apply_migrations
from panel.secrets_store import SecretStore

ACTOR = {"id": 1, "username": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": "req-1"}


@pytest.fixture
def service(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    return ClientService(database, SecretStore(None))


def _grant(client_id, protocol="naive", username="alice", node_id="local", **fields):
    now = int(time.time())
    options = {"naive": NaiveOptions(), "mtproxy": MtproxyOptions(), "mieru": MieruOptions(quotas=[])}[protocol]
    return AccessGrant(
        id=str(uuid.uuid4()), client_id=client_id, protocol=protocol, node_id=node_id,
        endpoint_id="default", runtime_username=username, secret_ref=None,
        desired_state="enabled", observed_state="unknown", valid_from=None, valid_until=None,
        options=options, origin="imported", created_at=now, updated_at=now, **fields,
    )


def test_client_ids_are_uuids_and_grants_belong_to_one_client_and_node(service):
    client = service.create_client("Sergey", **CTX)
    uuid.UUID(client.id)
    store = ClientStore(service.database)
    with service.database.transaction() as db:
        store.insert_grant(db, _grant(client.id))
        # Same protocol, node, endpoint and runtime username: the conflict is refused
        # before any SQL runs, so the caller's transaction stays usable.
        with pytest.raises(ClientConflict, match="runtime_username"):
            store.insert_grant(db, _grant(client.id))
        store.insert_grant(db, _grant(client.id, protocol="mtproxy"))
    with service.database.connect() as db:
        assert len(store.grants(db, client_id=client.id)) == 2
        assert store.find_grant(db, "naive", "local", "default", "alice").client_id == client.id
        with pytest.raises(sqlite3.IntegrityError):
            store.insert_grant(db, _grant(client.id, node_id="edge-missing"))


def test_a_grant_round_trips_through_the_database_with_its_typed_options(service):
    client = service.create_client("Sergey", **CTX)
    store = ClientStore(service.database)
    stored = _grant(client.id, protocol="mieru", username="mieru-one")
    stored = stored.model_copy(update={"options": MieruOptions(quotas=[{"days": 30, "megabytes": 10}])})
    with service.database.transaction() as db:
        store.insert_grant(db, stored)
    with service.database.connect() as db:
        loaded = store.grant(db, stored.id)
    assert isinstance(loaded.options, MieruOptions)
    assert loaded.options.quotas[0].megabytes == 10
    assert loaded == stored


def test_options_are_typed_and_secret_free():
    with pytest.raises(ValidationError):
        GrantIntent(protocol="mieru", runtime_username="a", options=NaiveOptions(quota_bytes=1))
    with pytest.raises(ValidationError):
        GrantIntent(protocol="naive", runtime_username="a b", options=NaiveOptions(quota_bytes=1))
    with pytest.raises(ValidationError):
        # A rendered link, not a template: the real credential would be stored in the row.
        MieruOptions(quotas=[], share_template="mierus://u:realpassword@h?port=1")
    with pytest.raises(ValidationError):
        MtproxyOptions(max_tcp_conns=0)
    intent = GrantIntent(protocol="mieru", runtime_username="alice", options=MieruOptions(quotas=[]))
    assert (intent.node_id, intent.endpoint_id) == ("local", "default")
    assert MieruOptions(quotas=[], share_template="mierus://{username}:{password}@h?port=1")


def test_suspended_client_compiles_every_grant_as_disabled(service):
    client = service.create_client("Sergey", **CTX)
    now = int(time.time())
    grant = _grant(client.id)
    assert effective_enabled(grant, client, now) is True
    service.set_state(client.id, "suspended", **CTX)
    client, _ = service.client_with_grants(client.id)
    assert effective_enabled(grant, client, now) is False
    active = client.model_copy(update={"state": "active"})
    assert effective_enabled(grant.model_copy(update={"valid_until": now - 1}), active, now) is False
    assert effective_enabled(grant.model_copy(update={"valid_from": now + 1}), active, now) is False
    assert effective_enabled(grant.model_copy(update={"desired_state": "disabled"}), active, now) is False


def test_archive_refuses_while_grants_are_not_deleted(service):
    client = service.create_client("Sergey", **CTX)
    store = ClientStore(service.database)
    with service.database.transaction() as db:
        store.insert_grant(db, _grant(client.id))
    with pytest.raises(ClientConflict, match="grants"):
        service.set_state(client.id, "archived", **CTX)
    with service.database.transaction() as db:
        store.update_grant(db, store.grants(db, client_id=client.id)[0].id, desired_state="deleted")
    assert service.set_state(client.id, "archived", **CTX).state == "archived"


def test_every_mutation_leaves_an_audit_row_in_the_same_transaction(service, monkeypatch):
    from panel.clients import service as module

    client = service.create_client("Sergey", **CTX)
    with service.database.connect() as db:
        row = db.execute("SELECT action,target,request_id FROM audit_log").fetchone()
    assert tuple(row) == ("client.create", client.id, "req-1")

    def boom(*_args, **_kwargs):
        raise RuntimeError("audit failed")

    monkeypatch.setattr(module, "record", boom)
    with pytest.raises(RuntimeError):
        service.create_client("Nobody", **CTX)
    assert [item.display_name for item in service.list_clients()] == ["Sergey"]


def test_a_state_change_notifies_subscribers_inside_the_transaction(service):
    seen = []
    service.on_change.append(lambda db, client_id: seen.append((db.in_transaction, client_id)))
    client = service.create_client("Sergey", **CTX)
    service.set_state(client.id, "suspended", **CTX)
    assert seen == [(True, client.id), (True, client.id)]
