"""Scoped Bearer keys, 3x-ui style: hashed at rest, shown once, revocable (ADR 008)."""
from __future__ import annotations

import hashlib
import secrets
import time

from .audit import record

SCOPES = ("admin", "monitor", "node-sync")
SCOPE_ROLES = {"admin": "owner", "monitor": "viewer", "node-sync": "node-sync"}
KEY_PREFIX = "pc_"
LAST_USED_GRANULARITY = 60


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ApiKeyService:
    def __init__(self, database, clock=time):
        self.database = database
        self.clock = clock

    @staticmethod
    def _row(row) -> dict:
        return {
            "id": row["id"], "name": row["name"], "scope": row["scope"], "prefix": row["prefix"],
            "enabled": bool(row["enabled"]), "expires_at": row["expires_at"],
            "created_at": row["created_at"], "created_by": row["created_by"],
            "last_used_at": row["last_used_at"],
        }

    def create(self, name: str, scope: str, expires_at: int | None, *, actor: dict, ip: str, request_id=None):
        if not isinstance(name, str) or not name.strip() or len(name) > 64:
            raise ValueError("name is invalid")
        if scope not in SCOPES:
            raise ValueError("scope is invalid")
        now = int(self.clock.time())
        if expires_at is not None and expires_at <= now:
            raise ValueError("expires_at is in the past")
        prefix = secrets.token_hex(4)
        plaintext = f"{KEY_PREFIX}{prefix}_{secrets.token_urlsafe(32)}"
        with self.database.transaction() as db:
            cursor = db.execute(
                """INSERT INTO api_keys(name,scope,prefix,key_hash,enabled,expires_at,created_at,created_by)
                   VALUES(?,?,?,?,1,?,?,?)""",
                (name.strip(), scope, prefix, _hash(plaintext), expires_at, now, actor["username"]),
            )
            record(db, actor=actor, action="api_key.create", target=str(cursor.lastrowid), ip=ip,
                   request_id=request_id, detail={"name": name.strip(), "scope": scope, "expires_at": expires_at})
            row = db.execute("SELECT * FROM api_keys WHERE id=?", (cursor.lastrowid,)).fetchone()
        return self._row(row), plaintext

    def list(self) -> list[dict]:
        with self.database.connect() as db:
            return [self._row(row) for row in db.execute("SELECT * FROM api_keys ORDER BY id")]

    def set_enabled(self, key_id: int, enabled: bool, *, actor: dict, ip: str, request_id=None) -> None:
        with self.database.transaction() as db:
            if db.execute("UPDATE api_keys SET enabled=? WHERE id=?", (1 if enabled else 0, key_id)).rowcount != 1:
                raise KeyError(key_id)
            record(db, actor=actor, action="api_key.enable" if enabled else "api_key.disable",
                   target=str(key_id), ip=ip, request_id=request_id)

    def delete(self, key_id: int, *, actor: dict, ip: str, request_id=None) -> None:
        with self.database.transaction() as db:
            if db.execute("DELETE FROM api_keys WHERE id=?", (key_id,)).rowcount != 1:
                raise KeyError(key_id)
            record(db, actor=actor, action="api_key.delete", target=str(key_id), ip=ip, request_id=request_id)

    def authenticate(self, plaintext: str | None) -> dict | None:
        if not plaintext or not plaintext.startswith(KEY_PREFIX) or plaintext.count("_") < 2:
            return None
        prefix = plaintext.split("_", 2)[1]
        digest = _hash(plaintext)
        now = int(self.clock.time())
        with self.database.connect() as db:
            for row in db.execute("SELECT * FROM api_keys WHERE prefix=?", (prefix,)):
                if not secrets.compare_digest(row["key_hash"], digest):
                    continue
                if not row["enabled"] or (row["expires_at"] is not None and row["expires_at"] <= now):
                    return None
                if not row["last_used_at"] or now - row["last_used_at"] >= LAST_USED_GRANULARITY:
                    db.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (now, row["id"]))
                    db.commit()
                return {"id": None, "key_id": row["id"], "username": f"key:{row['name']}",
                        "role": SCOPE_ROLES[row["scope"]], "scope": row["scope"], "via": "api-key"}
        return None
