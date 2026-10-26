"""Node lifecycle: an operator-facing façade that does not widen the v1 transport."""

from __future__ import annotations

import time

import pytest

from panel.database import Database
from panel.fleet import CommandConflict, FleetStore, ProtocolError
from panel.migrations import apply_migrations
from panel.nodes import LOCAL_NODE_ID
from panel.nodes.models import CertificateInfo
from panel.nodes.read_model import derive
from panel.nodes.service import NodeConflict, NodeLifecycleService

ACTOR = {"id": 1, "username": "owner"}
CTX = {"actor": ACTOR, "ip": "127.0.0.1", "request_id": "req-1"}


def _cert(state="active", not_after=None):
    now = int(time.time())
    return CertificateInfo("AA01", "f" * 64, now - 10, not_after or now + 86400 * 30, state, now - 10, None)


@pytest.fixture
def service(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    return NodeLifecycleService(database, FleetStore(database.path))



























