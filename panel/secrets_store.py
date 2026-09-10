"""AES-256-GCM secret versions bound to their identity through AAD; plaintext lives one call.

The AAD carries the row's identity — secret id, version, purpose, grant and the
node allowed to receive it — so a ciphertext copied into another row, or handed
to another node, fails authentication instead of decrypting. Error messages are
fixed strings: nothing here interpolates a secret.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keyring import Keyring, KeyringError

STATES = ("pending", "active", "retiring", "revoked")


class SecretError(RuntimeError):
    """Messages are fixed strings: never interpolate plaintext or ciphertext."""


@dataclass(frozen=True)
class SecretRef:
    secret_id: str
    version: int


def _aad(secret_id: str, version: int, purpose: str, grant_id: str | None, permitted_node_id: str | None) -> bytes:
    return json.dumps(
        {
            "secret_id": secret_id,
            "version": version,
            "purpose": purpose,
            "grant_id": grant_id,
            "permitted_node_id": permitted_node_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


class SecretStore:
    def __init__(self, keyring: Keyring | None):
        self._keyring = keyring

    def __repr__(self) -> str:
        return f"SecretStore(enabled={self.enabled})"

    @property
    def enabled(self) -> bool:
        return self._keyring is not None

    def _require(self) -> Keyring:
        if self._keyring is None:
            raise SecretError("secret store is disabled: PANEL_MASTER_KEY_FILE is not configured")
        return self._keyring

    def store(
        self,
        db,
        *,
        secret_id: str,
        version: int,
        purpose: str,
        grant_id: str | None,
        permitted_node_id: str | None,
        plaintext: bytes,
        state: str = "pending",
    ) -> SecretRef:
        if state not in STATES:
            raise SecretError("invalid secret state")
        key = self._require().active
        nonce = os.urandom(12)
        ciphertext = AESGCM(key.material).encrypt(
            nonce, plaintext, _aad(secret_id, version, purpose, grant_id, permitted_node_id)
        )
        now = int(time.time())
        db.execute(
            """INSERT INTO secret_versions(secret_id,version,purpose,grant_id,permitted_node_id,key_id,
               nonce,ciphertext,state,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (secret_id, version, purpose, grant_id, permitted_node_id, key.key_id, nonce, ciphertext, state, now, now),
        )
        return SecretRef(secret_id, version)

    def reveal(self, db, ref: SecretRef, *, purpose: str, grant_id: str | None, permitted_node_id: str | None) -> bytes:
        keyring = self._require()
        row = db.execute(
            "SELECT * FROM secret_versions WHERE secret_id=? AND version=?", (ref.secret_id, ref.version)
        ).fetchone()
        if row is None or row["state"] == "revoked":
            raise SecretError("secret version unavailable")
        try:
            key = keyring.get(row["key_id"])
        except KeyringError as exc:
            raise SecretError("secret version was encrypted under an unknown key") from exc
        try:
            return AESGCM(key.material).decrypt(
                row["nonce"],
                row["ciphertext"],
                _aad(ref.secret_id, ref.version, purpose, grant_id, permitted_node_id),
            )
        except InvalidTag as exc:
            raise SecretError("secret version failed authentication for this identity") from exc

    def transition(self, db, ref: SecretRef, state: str) -> None:
        if state not in STATES:
            raise SecretError("invalid secret state")
        changed = db.execute(
            "UPDATE secret_versions SET state=?,updated_at=? WHERE secret_id=? AND version=?",
            (state, int(time.time()), ref.secret_id, ref.version),
        ).rowcount
        if changed != 1:
            raise SecretError("secret version unavailable")

    def rewrap(self, db, *, batch_size: int = 200) -> int:
        """Re-encrypt up to batch_size rows that are not under the active key; returns how many."""
        keyring = self._require()
        active = keyring.active
        rows = db.execute(
            "SELECT * FROM secret_versions WHERE key_id<>? LIMIT ?", (active.key_id, batch_size)
        ).fetchall()
        for row in rows:
            aad = _aad(row["secret_id"], row["version"], row["purpose"], row["grant_id"], row["permitted_node_id"])
            try:
                plaintext = AESGCM(keyring.get(row["key_id"]).material).decrypt(row["nonce"], row["ciphertext"], aad)
            except (KeyringError, InvalidTag) as exc:
                raise SecretError("rewrap cannot decrypt a row under the overlap keyring") from exc
            nonce = os.urandom(12)
            db.execute(
                "UPDATE secret_versions SET key_id=?,nonce=?,ciphertext=?,updated_at=? WHERE secret_id=? AND version=?",
                (
                    active.key_id,
                    nonce,
                    AESGCM(active.material).encrypt(nonce, plaintext, aad),
                    int(time.time()),
                    row["secret_id"],
                    row["version"],
                ),
            )
        return len(rows)

    def verify_all(self, db) -> dict[str, int]:
        """Decrypt every row (result discarded) and count rows per key id; raises on the first failure."""
        keyring = self._require()
        counts: dict[str, int] = {}
        for row in db.execute("SELECT * FROM secret_versions"):
            aad = _aad(row["secret_id"], row["version"], row["purpose"], row["grant_id"], row["permitted_node_id"])
            try:
                AESGCM(keyring.get(row["key_id"]).material).decrypt(row["nonce"], row["ciphertext"], aad)
            except (KeyringError, InvalidTag) as exc:
                raise SecretError("a secret version does not decrypt under the current keyring") from exc
            counts[row["key_id"]] = counts.get(row["key_id"], 0) + 1
        return counts
