"""What the panel shows about a node, separated from how the transport works."""
from __future__ import annotations

from dataclasses import dataclass, field

# The central host itself, reserved by migration 5. It is a node so that a grant can name it,
# but it has no fleet transport: no certificates, no command queue, no disable switch.
LOCAL_NODE_ID = "local"


@dataclass(frozen=True)
class CertificateInfo:
    serial: str
    fingerprint_sha256: str
    not_before: int
    not_after: int
    state: str
    issued_at: int
    revoked_at: int | None


@dataclass(frozen=True)
class NodeView:
    node_id: str
    display_name: str
    kind: str
    disabled: bool
    enrollment_state: str
    connectivity_state: str
    daemon_health: str
    inventory: dict
    capabilities: list[str]
    last_seen_at: int | None
    last_checked_at: int | None
    certificates: list[CertificateInfo] = field(default_factory=list)
    pending_commands: int = 0
    # `v1` = the mTLS agent transport; `panel` = a linked panel reached over HTTPS
    # (Fleet v2). `link` describes that connection and never carries the API key.
    transport: str = "v1"
    link: dict | None = None
