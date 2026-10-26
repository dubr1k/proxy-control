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




































