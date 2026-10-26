# panel/tests/test_api_keys.py
from __future__ import annotations

import pytest

from panel.api_keys import ApiKeyService, SCOPES
from panel.database import Database
from panel.fleet_v2.identity import ensure_guid, read_panel_version
from panel.migrations import apply_migrations

ACTOR = {"id": 1, "username": "owner"}


@pytest.fixture
def database(tmp_path):
    db = Database(tmp_path / "panel.sqlite3")
    apply_migrations(db)
    return db





















