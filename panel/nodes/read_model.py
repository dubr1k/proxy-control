"""Derive what an operator sees from stored rows — one place, no scattered guesses."""
from __future__ import annotations

from .models import CertificateInfo, NodeView


def derive(
    row: dict,
    certificates: list[CertificateInfo],
    pending_commands: int,
    now: int,
    stale_after: int = 90,
) -> NodeView:
    active = [certificate for certificate in certificates if certificate.state == "active"]
    if row.get("kind") == "local":
        # The central host has no transport, so "online" and "stale" mean nothing here.
        enrollment, connectivity = "local", "not_applicable"
    elif active:
        enrollment = "enrolled"
        seen = row.get("last_seen_at")
        connectivity = "never" if not seen else ("online" if now - seen <= stale_after else "stale")
    else:
        enrollment = "revoked" if certificates else "unenrolled"
        connectivity = "never" if not row.get("last_seen_at") else "stale"
    inventory = row.get("inventory") or {}
    return NodeView(
        node_id=row["node_id"],
        display_name=row["display_name"],
        kind=row.get("kind", "remote"),
        disabled=bool(row.get("disabled")),
        enrollment_state=enrollment,
        connectivity_state=connectivity,
        daemon_health="reported" if inventory.get("telemt_version") else "unknown",
        inventory={key: value for key, value in inventory.items() if key != "capabilities"},
        capabilities=list(inventory.get("capabilities", [])),
        last_seen_at=row.get("last_seen_at"),
        last_checked_at=row.get("updated_at"),
        certificates=certificates,
        pending_commands=pending_commands,
    )
