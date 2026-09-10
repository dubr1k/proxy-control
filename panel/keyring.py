"""Versioned master keyring file: stdlib only so installers can render it without cryptography.

The file is the one thing that must never live beside the database it protects
(ADR 005). It is written 0600, refuses to load if anyone else can read it, and
carries every key needed to decrypt existing rows — rotation is overlap-first,
so a crash mid-rewrap leaves nothing unreadable.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path

SCHEMA = 1
STATES = {"active", "retiring"}


class KeyringError(RuntimeError):
    pass


@dataclass(frozen=True)
class Key:
    key_id: str
    state: str
    created_at: int
    material: bytes

    def __repr__(self) -> str:
        return f"Key(key_id={self.key_id!r}, state={self.state!r})"


def new_key(state: str = "active") -> Key:
    return Key(f"k-{secrets.token_hex(4)}", state, int(time.time()), secrets.token_bytes(32))


@dataclass(frozen=True)
class Keyring:
    keys: tuple[Key, ...]
    active_key_id: str

    def __repr__(self) -> str:
        return f"Keyring(active={self.active_key_id!r}, keys={len(self.keys)})"

    @property
    def active(self) -> Key:
        return self.get(self.active_key_id)

    @property
    def key_ids(self) -> set[str]:
        return {key.key_id for key in self.keys}

    def get(self, key_id: str) -> Key:
        for key in self.keys:
            if key.key_id == key_id:
                return key
        raise KeyringError("unknown key id")

    @classmethod
    def generate(cls) -> "Keyring":
        key = new_key()
        return cls((key,), key.key_id)

    def rotate(self) -> "Keyring":
        """Overlap-first: the new key becomes active, every previous key stays readable as retiring."""
        key = new_key()
        retiring = tuple(Key(k.key_id, "retiring", k.created_at, k.material) for k in self.keys)
        return Keyring((key, *retiring), key.key_id)

    def retire_all_but_active(self) -> "Keyring":
        return Keyring((self.active,), self.active_key_id)

    def to_json(self) -> str:
        return json.dumps({
            "schema": SCHEMA,
            "active_key_id": self.active_key_id,
            "keys": [
                {
                    "key_id": key.key_id,
                    "state": key.state,
                    "created_at": key.created_at,
                    "key_material": base64.b64encode(key.material).decode(),
                }
                for key in self.keys
            ],
        }, indent=2) + "\n"

    def save(self, path: Path) -> None:
        path = Path(path)
        temporary = path.with_name(path.name + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(self.to_json())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)

    @classmethod
    def load(cls, path: Path) -> "Keyring":
        path = Path(path)
        try:
            info = path.lstat()
        except FileNotFoundError as exc:
            raise KeyringError("master key file does not exist") from exc
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise KeyringError("master key file must be a regular file with mode 0600 or 0400")
        try:
            data = json.loads(path.read_text())
            if data["schema"] != SCHEMA:
                raise KeyringError("unsupported keyring schema")
            keys = tuple(
                Key(
                    str(item["key_id"]),
                    str(item["state"]),
                    int(item["created_at"]),
                    base64.b64decode(item["key_material"], validate=True),
                )
                for item in data["keys"]
            )
            active_key_id = str(data["active_key_id"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise KeyringError("master key file is malformed") from exc
        if not keys or any(len(key.material) != 32 or key.state not in STATES for key in keys):
            raise KeyringError("master key file contains an invalid key")
        if len({key.key_id for key in keys}) != len(keys):
            raise KeyringError("duplicate key id")
        keyring = cls(keys, active_key_id)
        if keyring.active.state != "active":
            raise KeyringError("active key is not in state active")
        return keyring
