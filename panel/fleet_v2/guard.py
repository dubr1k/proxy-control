"""The one gate every local writer passes before touching a runtime user (spec §5.3)."""
from __future__ import annotations

from fastapi import HTTPException


def require_unmanaged(db, managed, protocol: str, username: str) -> None:
    """ADR 003: a resource the central panel owns has exactly one writer — not this UI."""
    if managed.is_managed(db, protocol, username):
        raise HTTPException(409, "managed by central", headers={"X-Reason": "managed_by_central"})
