"""What the version-agent installed after the installer's pin (v0.11): `verify`, `repair`
and the acceptance checks accept either the installer's pinned artifact or the one the
agent recorded in its state, never anything else."""
from __future__ import annotations

import json
from pathlib import Path

STATE_PATH = "/var/lib/proxy-control/version-agent/state.json"


def agent_component(root: Path, component: str, state_path: str = STATE_PATH) -> dict | None:
    """The agent's `components[component]` entry, or `None` when the state file is absent,
    invalid, or records a failed rollback (nothing the agent claims is trusted then)."""
    path = root / state_path.lstrip("/")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    components = raw.get("components") if isinstance(raw, dict) else None
    entry = components.get(component) if isinstance(components, dict) else None
    if not isinstance(entry, dict) or entry.get("status") == "rollback_failed":
        return None
    return entry


def accepted_sha256(root: Path, component: str, member: str | None, pinned: str) -> set[str]:
    """`{pinned}` plus the digest the agent recorded: `sha256` of a single binary, or
    `members[member]` of a multi-file component such as `xray`."""
    entry = agent_component(root, component) or {}
    members = entry.get("members")
    recorded = members.get(member) if member and isinstance(members, dict) else (None if member else entry.get("sha256"))
    return {pinned} | ({recorded} if isinstance(recorded, str) and len(recorded) == 64 else set())


def accepted_caddy_pins(root: Path, pinned: str) -> set[str]:
    """`{pinned}` plus the `runtime_version` of the Caddy the agent built for `naive`."""
    entry = agent_component(root, "naive") or {}
    recorded = entry.get("runtime_version")
    return {pinned} | ({recorded} if isinstance(recorded, str) and recorded else set())
