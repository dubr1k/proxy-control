#!/usr/bin/env python3
"""Prepare or verify the NaiveProxy manager state and accounting log boundary.

The manager keeps its credentials, paired backups, and accounting database in a
single fixed-identity directory; Caddy writes rotated access logs into a second
directory the manager may only read.  Both boundaries used to be created by an
ad-hoc shell sequence that a restore could silently widen, so this preparer is
the one safe implementation: it validates normalized absolute paths, refuses
symlinks and hardlinked state, refuses to adopt foreign or non-empty state,
fails closed on fixed UID/GID collisions, checks parent ownership, enforces file
modes, and never performs a recursive chown.

Usage:
    prepare-naive-state.py prepare|verify [--state-dir DIR] [--log-dir DIR]
"""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import stat
import sys
from pathlib import Path
from typing import NoReturn

MANAGER_UID = 10002
MANAGER_GID = 101
CADDY_UID = 10003
ACCOUNTING_GID = 10004
CADDY_USER = "naive-caddy"
ACCOUNTING_GROUP = "naive-accounting"

STATE_MODE = 0o700
LOG_MODE = 0o750
DEFAULT_STATE_DIR = "/var/lib/naive-manager"
DEFAULT_LOG_DIR = "/var/log/naive-proxy"

# Files the manager owns inside its state directory.  Everything else is a
# foreign artifact and blocks adoption.
STATE_FILES = {
    "Caddyfile": 0o640,
    "manager-token": 0o400,
    "users.json": 0o600,
    "transaction.json": 0o600,
    "traffic.sqlite3": 0o600,
    "traffic.sqlite3-wal": 0o600,
    "traffic.sqlite3-shm": 0o600,
}
STATE_DIRECTORIES = {"backups": 0o700}


class StateError(RuntimeError):
    """The Naive state boundary cannot be created or adopted safely."""


def _fail(message: str) -> NoReturn:
    raise StateError(message)


def _normalized(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        _fail(f"{label} must be an absolute path")
    if path == Path("/"):
        _fail(f"{label} must not be the filesystem root")
    parts = path.parts[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _fail(f"{label} must be a normalized absolute path without traversal")
    if value != path.as_posix():
        _fail(f"{label} must be a normalized absolute path without traversal")
    return path


def _assert_safe_parents(path: Path, label: str) -> None:
    if path.is_symlink():
        _fail(f"{label} must not be a symlink: {path}")
    cursor = Path(path.root)
    for part in path.parts[1:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            _fail(f"{label} must not traverse a symlink: {cursor}")
        if not cursor.is_dir():
            _fail(f"{label} parent is missing or not a directory: {cursor}")
        metadata = cursor.stat()
        if metadata.st_uid != 0:
            _fail(f"{label} parent must be root-owned: {cursor}")
        if metadata.st_mode & stat.S_IWOTH:
            _fail(f"{label} parent must not be world-writable: {cursor}")


def _assert_identity_free(kind: str, identifier: int, expected: str) -> None:
    """Refuse a fixed production identity already held by a foreign subject."""
    try:
        name = (
            pwd.getpwuid(identifier).pw_name
            if kind == "UID"
            else grp.getgrgid(identifier).gr_name
        )
    except KeyError:
        return
    if name != expected:
        _fail(f"{kind} {identifier} collision: {name}")


def _assert_identities() -> None:
    _assert_identity_free("UID", CADDY_UID, CADDY_USER)
    _assert_identity_free("GID", ACCOUNTING_GID, ACCOUNTING_GROUP)


def _owner(path: Path) -> tuple[int, int]:
    metadata = path.stat()
    return metadata.st_uid, metadata.st_gid


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _assert_directory(
    path: Path,
    *,
    label: str,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    if path.is_symlink() or not path.is_dir():
        _fail(f"{label} must be a real directory, not a symlink: {path}")
    if _owner(path) != (uid, gid):
        _fail(f"{label} must have owner {uid}:{gid}: {path}")
    if _mode(path) != mode:
        _fail(f"{label} must have mode {mode:04o}: {path}")


def _assert_state_entry(path: Path, expected_mode: int, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label} must be a regular file, not a symlink: {path}")
    metadata = path.stat()
    if metadata.st_nlink != 1:
        _fail(f"{label} must not be hardlinked: {path}")
    if (metadata.st_uid, metadata.st_gid) != (MANAGER_UID, MANAGER_GID):
        _fail(f"{label} must have owner {MANAGER_UID}:{MANAGER_GID}: {path}")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        _fail(f"{label} must have mode {expected_mode:04o}: {path}")


def _assert_owned_state(state_dir: Path) -> None:
    """Adopt only a state tree that contains exclusively manager-owned files."""
    for entry in sorted(state_dir.iterdir()):
        name = entry.name
        if name in STATE_DIRECTORIES:
            _assert_directory(
                entry,
                label=f"{name} directory",
                uid=MANAGER_UID,
                gid=MANAGER_GID,
                mode=STATE_DIRECTORIES[name],
            )
            for backup in sorted(entry.iterdir()):
                _assert_state_entry(backup, 0o600, "recovery backup")
            continue
        expected_mode = STATE_FILES.get(name)
        if expected_mode is None:
            _fail(f"foreign entry in manager state: {entry}")
        _assert_state_entry(entry, expected_mode, name)
    transaction = state_dir / "transaction.json"
    users = state_dir / "users.json"
    if transaction.is_file() and not users.is_file():
        _fail("an unfinished transaction requires the paired users.json state")


def _create_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _prepare_directory(
    path: Path,
    *,
    label: str,
    uid: int,
    gid: int,
    mode: int,
    owned_check: bool,
) -> bool:
    """Create or adopt one boundary; returns True when it was created."""
    _assert_safe_parents(path, label)
    if not path.exists():
        _create_directory(path, uid=uid, gid=gid, mode=mode)
        return True
    _assert_directory(path, label=label, uid=uid, gid=gid, mode=mode)
    if owned_check:
        _assert_owned_state(path)
    return False


def _verify_log_dir(log_dir: Path) -> None:
    _assert_safe_parents(log_dir, "log directory")
    _assert_directory(
        log_dir,
        label="log directory",
        uid=CADDY_UID,
        gid=ACCOUNTING_GID,
        mode=LOG_MODE,
    )
    for entry in sorted(log_dir.iterdir()):
        if entry.is_symlink() or not entry.is_file():
            _fail(f"access log must be a regular file, not a symlink: {entry}")
        metadata = entry.stat()
        if (metadata.st_uid, metadata.st_gid) != (CADDY_UID, ACCOUNTING_GID):
            _fail(
                "access log must have owner "
                f"{CADDY_UID}:{ACCOUNTING_GID}: {entry}"
            )
        if stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IRWXO):
            _fail(f"access log must stay group read-only: {entry}")


def prepare(state_dir: Path, log_dir: Path) -> tuple[bool, bool]:
    """Idempotently create or adopt both Naive boundaries."""
    _assert_identities()
    created_state = _prepare_directory(
        state_dir,
        label="state directory",
        uid=MANAGER_UID,
        gid=MANAGER_GID,
        mode=STATE_MODE,
        owned_check=True,
    )
    created_log = _prepare_directory(
        log_dir,
        label="log directory",
        uid=CADDY_UID,
        gid=ACCOUNTING_GID,
        mode=LOG_MODE,
        owned_check=False,
    )
    if not created_log:
        _verify_log_dir(log_dir)
    return created_state, created_log


def verify(state_dir: Path, log_dir: Path) -> None:
    """Prove both boundaries still hold their fixed identity and modes."""
    _assert_identities()
    _assert_safe_parents(state_dir, "state directory")
    if not state_dir.exists():
        _fail("verify requires an existing state directory; run prepare first")
    _assert_directory(
        state_dir,
        label="state directory",
        uid=MANAGER_UID,
        gid=MANAGER_GID,
        mode=STATE_MODE,
    )
    _assert_owned_state(state_dir)
    if not log_dir.exists():
        _fail("verify requires an existing log directory; run prepare first")
    _verify_log_dir(log_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="prepare-naive-state.py",
        description="Prepare or verify the NaiveProxy state and log boundary",
    )
    parser.add_argument("mode", choices=("prepare", "verify"))
    parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    parser.add_argument("--log-dir", default=DEFAULT_LOG_DIR)
    arguments = parser.parse_args(argv)

    try:
        if os.geteuid() != 0:
            _fail("must run as root")
        state_dir = _normalized(arguments.state_dir, "state directory")
        log_dir = _normalized(arguments.log_dir, "log directory")
        if state_dir == log_dir:
            _fail("state and log directories must be distinct")
        if arguments.mode == "prepare":
            prepare(state_dir, log_dir)
            print(f"Prepared Naive manager state directory: {state_dir}")
            print(f"Prepared Naive accounting log directory: {log_dir}")
        else:
            verify(state_dir, log_dir)
            print(f"Verified Naive manager state directory: {state_dir}")
            print(f"Verified Naive accounting log directory: {log_dir}")
    except StateError as exc:
        print(f"prepare-naive-state: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"prepare-naive-state: {exc.strerror}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
