"""Derive what an operator sees from stored rows — one place, no scattered guesses."""
from __future__ import annotations

from .models import CertificateInfo, NodeView

# What the operator may see of a link: the connection, its health and the generation
# counters. The secret id stays behind; only `has_api_key` says a key is stored.
LINK_VIEW_KEYS = (
    "panel_url", "tls_verify", "status", "latency_ms", "panel_version", "last_heartbeat_at", "last_error",
    "desired_generation", "acknowledged_generation", "identity", "status_json", "has_api_key",
)


def _link_view(link: dict) -> dict:
    view = {key: link[key] for key in LINK_VIEW_KEYS}
    view["config_dirty"] = bool(link["config_dirty"])
    view["enabled"] = bool(link["enabled"])
    return view


def derive(
    row: dict,
    certificates: list[CertificateInfo],
    pending_commands: int,
    now: int,
    stale_after: int = 90,
) -> NodeView:
    active = [certificate for certificate in certificates if certificate.state == "active"]
    link = row.get("link") if row.get("transport") == "panel" else None
    if row.get("kind") == "local":
        # The central host has no transport, so "online" and "stale" mean nothing here.
        enrollment, connectivity = "local", "not_applicable"
    elif link is not None:
        # A linked panel has no certificate: its heartbeat decides whether it is reachable.
        enrollment, connectivity = "linked", link["status"]
    elif active:
        enrollment = "enrolled"
        seen = row.get("last_seen_at")
        connectivity = "never" if not seen else ("online" if now - seen <= stale_after else "stale")
    else:
        enrollment = "revoked" if certificates else "unenrolled"
        connectivity = "never" if not row.get("last_seen_at") else "stale"
    inventory = row.get("inventory") or {}
    if link is not None:
        reported = bool(link["identity"].get("protocols"))
    else:
        reported = bool(inventory.get("telemt_version"))
    return NodeView(
        node_id=row["node_id"],
        display_name=row["display_name"],
        kind=row.get("kind", "remote"),
        disabled=bool(row.get("disabled")),
        enrollment_state=enrollment,
        connectivity_state=connectivity,
        daemon_health="reported" if reported else "unknown",
        inventory={key: value for key, value in inventory.items() if key != "capabilities"},
        capabilities=list(inventory.get("capabilities", [])),
        last_seen_at=row.get("last_seen_at"),
        last_checked_at=row.get("updated_at"),
        certificates=certificates,
        pending_commands=pending_commands,
        transport=row.get("transport", "v1"),
        link=None if link is None else _link_view(link),
    )
