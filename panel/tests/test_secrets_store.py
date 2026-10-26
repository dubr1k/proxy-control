"""Encrypted secret versions: identity-bound, key-rotatable, and silent about plaintext."""

from __future__ import annotations

import base64
import json
import stat

import pytest

from panel.database import Database
from panel.keyring import Keyring, KeyringError
from panel.migrations import apply_migrations
from panel.secrets_store import SecretError, SecretRef, SecretStore


@pytest.fixture
def database(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    return database


@pytest.fixture
def keyring_path(tmp_path):
    path = tmp_path / "master-key"
    Keyring.generate().save(path)
    return path



























