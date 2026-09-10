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


def test_keyring_file_is_private_json_with_one_active_key(keyring_path):
    assert stat.S_IMODE(keyring_path.stat().st_mode) == 0o600
    data = json.loads(keyring_path.read_text())
    assert data["schema"] == 1 and len(data["keys"]) == 1
    assert len(base64.b64decode(data["keys"][0]["key_material"])) == 32
    keyring = Keyring.load(keyring_path)
    assert keyring.active.key_id == data["active_key_id"]


def test_keyring_refuses_world_readable_or_malformed_files(keyring_path):
    keyring_path.chmod(0o644)
    with pytest.raises(KeyringError, match="mode"):
        Keyring.load(keyring_path)
    keyring_path.chmod(0o600)
    keyring_path.write_text('{"schema": 1, "active_key_id": "missing", "keys": []}')
    with pytest.raises(KeyringError):
        Keyring.load(keyring_path)


def test_store_and_reveal_round_trip_binds_identity(database, keyring_path):
    secrets_store = SecretStore(Keyring.load(keyring_path))
    with database.transaction() as db:
        ref = secrets_store.store(
            db,
            secret_id="s1",
            version=1,
            purpose="grant.credential",
            grant_id="g1",
            permitted_node_id="local",
            plaintext=b"hunter2-hunter2",
        )
    assert ref == SecretRef("s1", 1)
    with database.connect() as db:
        revealed = secrets_store.reveal(db, ref, purpose="grant.credential", grant_id="g1", permitted_node_id="local")
        assert revealed == b"hunter2-hunter2"
        with pytest.raises(SecretError):
            secrets_store.reveal(db, ref, purpose="grant.credential", grant_id="g2", permitted_node_id="local")
        with pytest.raises(SecretError):
            secrets_store.reveal(db, ref, purpose="grant.credential", grant_id="g1", permitted_node_id="edge-01")


def test_copied_ciphertext_under_another_row_fails(database, keyring_path):
    secrets_store = SecretStore(Keyring.load(keyring_path))
    with database.transaction() as db:
        secrets_store.store(db, secret_id="s1", version=1, purpose="p", grant_id="g1", permitted_node_id="local", plaintext=b"a")
        secrets_store.store(db, secret_id="s2", version=1, purpose="p", grant_id="g2", permitted_node_id="local", plaintext=b"b")
        row = db.execute("SELECT nonce,ciphertext FROM secret_versions WHERE secret_id='s1'").fetchone()
        db.execute(
            "UPDATE secret_versions SET nonce=?,ciphertext=? WHERE secret_id='s2'",
            (row["nonce"], row["ciphertext"]),
        )
    with database.connect() as db:
        with pytest.raises(SecretError):
            secrets_store.reveal(db, SecretRef("s2", 1), purpose="p", grant_id="g2", permitted_node_id="local")


def test_database_without_key_holds_no_recognisable_secret(database, keyring_path):
    secrets_store = SecretStore(Keyring.load(keyring_path))
    canary = b"CANARY-9f3c1c0a-do-not-leak"
    with database.transaction() as db:
        secrets_store.store(db, secret_id="s1", version=1, purpose="p", grant_id="g1", permitted_node_id="local", plaintext=canary)
    wal = database.path.with_name(database.path.name + "-wal")
    raw = database.path.read_bytes() + (wal.read_bytes() if wal.exists() else b"")
    assert canary not in raw and base64.b64encode(canary) not in raw


def test_unknown_or_retired_key_ids_fail_closed(database, keyring_path):
    keyring = Keyring.load(keyring_path)
    secrets_store = SecretStore(keyring)
    with database.transaction() as db:
        secrets_store.store(db, secret_id="s1", version=1, purpose="p", grant_id="g1", permitted_node_id="local", plaintext=b"x")
    fresh = SecretStore(Keyring.generate())  # a keyring that never had this key
    with database.connect() as db:
        with pytest.raises(SecretError, match="key"):
            fresh.reveal(db, SecretRef("s1", 1), purpose="p", grant_id="g1", permitted_node_id="local")


def test_rotation_is_overlap_first_and_interrupted_rewrap_stays_decryptable(database, keyring_path):
    old = Keyring.load(keyring_path)
    old_store = SecretStore(old)
    with database.transaction() as db:
        for index in range(5):
            old_store.store(
                db,
                secret_id=f"s{index}",
                version=1,
                purpose="p",
                grant_id=f"g{index}",
                permitted_node_id="local",
                plaintext=b"v",
            )
    rotated = old.rotate()
    assert {key.state for key in rotated.keys} == {"active", "retiring"}
    new_store = SecretStore(rotated)
    # Interrupt after the first batch of two rows.
    with pytest.raises(RuntimeError):
        with database.transaction() as db:
            new_store.rewrap(db, batch_size=2)
            raise RuntimeError("crash between batches")
    with database.connect() as db:
        counts = new_store.verify_all(db)
    assert sum(counts.values()) == 5  # every row decrypts under the overlap keyring
    with database.transaction() as db:
        while new_store.rewrap(db, batch_size=2):
            pass
    with database.connect() as db:
        assert new_store.verify_all(db) == {rotated.active.key_id: 5}


def test_repr_and_errors_never_contain_plaintext(database, keyring_path):
    secrets_store = SecretStore(Keyring.load(keyring_path))
    with database.transaction() as db:
        ref = secrets_store.store(
            db,
            secret_id="s1",
            version=1,
            purpose="p",
            grant_id="g1",
            permitted_node_id="local",
            plaintext=b"PLAINTEXT-CANARY",
        )
    assert "PLAINTEXT" not in repr(ref) and "PLAINTEXT" not in repr(secrets_store)
    with database.connect() as db:
        with pytest.raises(SecretError) as exc:
            secrets_store.reveal(db, ref, purpose="wrong", grant_id="g1", permitted_node_id="local")
        assert "PLAINTEXT" not in str(exc.value)


def test_missing_key_with_encrypted_rows_fails_closed_at_app_start(database, keyring_path):
    from panel.app import create_app
    from panel.settings import Settings

    secrets_store = SecretStore(Keyring.load(keyring_path))
    with database.transaction() as db:
        secrets_store.store(db, secret_id="s1", version=1, purpose="p", grant_id="g1", permitted_node_id="local", plaintext=b"x")
    with pytest.raises(ValueError, match="PANEL_MASTER_KEY_FILE"):
        create_app(
            Settings(
                database_path=database.path,
                master_key_file=None,
                allowed_hosts=("testserver",),
                naive_enabled=False,
                mieru_enabled=False,
            )
        )
