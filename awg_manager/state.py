"""Schema-versioned JSON state, written atomically (0600 file in a 0700 directory)."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

SCHEMA = 1
MAX_OPERATIONS = 2000


class StateError(RuntimeError):
    """The state file is unreadable or from an unknown schema; the manager refuses to run."""


def atomic_write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


class StateStore:
    """In-memory document plus its file. The caller serialises access."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.path = self.directory / "state.json"
        self.doc: dict = {"schema": SCHEMA, "instances": {}, "peers": {}, "operations": {}}

    def load(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        if not self.path.exists():
            return
        try:
            doc = json.loads(self.path.read_text())
        except (OSError, ValueError) as exc:
            raise StateError(f"cannot read {self.path}") from exc
        if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
            raise StateError("unsupported state schema")
        for key in ("instances", "peers", "operations"):
            if not isinstance(doc.get(key), dict):
                raise StateError(f"state field {key} is malformed")
        self.doc = doc

    def save(self) -> None:
        ops = self.doc["operations"]
        while len(ops) > MAX_OPERATIONS:
            ops.pop(next(iter(ops)))
        atomic_write(self.path, json.dumps(self.doc, indent=1, sort_keys=True).encode())

    @property
    def instances(self) -> dict:
        return self.doc["instances"]

    @property
    def peers(self) -> dict:
        return self.doc["peers"]

    @property
    def operations(self) -> dict:
        return self.doc["operations"]
