"""Two disjoint installation reports: a public one and a root-only handoff.

The public report carries only named, non-secret acceptance facts - health
state, response class, byte counts, versions and digests, listener owners,
certificate SANs and expiry, and route results.  Every credential the install
produced goes to a separate 0600 handoff that the public report never links,
quotes, or summarizes.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from installer.planner import Evidence
from installer.transaction import atomic_write, durable_mkdir


PUBLIC_NAME = "report.json"
CREDENTIALS_DIR = "credentials"
CREDENTIALS_NAME = "handoff.json"
REPORT_SCHEMA = 1

# The only fact names a public report may publish.
ALLOWED_FACTS = frozenset(
    {
        "adjacent_listeners_ok",
        "adjacent_sni_ok",
        "admin_api_loopback",
        "authenticated_connect_ok",
        "certificate_expires",
        "certificate_sans",
        "client_count",
        "compose_config_ok",
        "connect_bytes",
        "cover_https_ok",
        "executable_digest_ok",
        "expected_services",
        "healthy_services",
        "identities_removed",
        "installed",
        "listener_owner",
        "log_boundary_ok",
        "manager_health_ok",
        "mita_status_running",
        "package_digest_ok",
        "panel_health_ok",
        "panel_login_ok",
        "persistent_data_preserved",
        "private_listener_ok",
        "public_host_ok",
        "recorded_bytes",
        "respq_expected",
        "respq_verified",
        "response_status",
        "route_result",
        "routes",
        "send_queue_drained",
        "sensitive_scan_ok",
        "telemt_api_internal",
        "temporary_state_removed",
        "transports_expected",
        "transports_verified",
        "tunnel_closed_ok",
        "uds_boundary_ok",
        "version_pinned",
        "warp_domains",
    }
)

_SAFE_VALUE = re.compile(r"[A-Za-z0-9_.:+@/ -]{1,256}\Z")
_SECRET_NAME = re.compile(
    r"(?:password|passwd|secret|token|private[_ -]?key|api[_ -]?key|cookie|uuid)",
    re.IGNORECASE,
)


class ReportError(ValueError):
    """A report would publish something outside its schema."""


@dataclass(frozen=True)
class AcceptanceReport:
    """Named, non-secret acceptance facts for one completed installation."""

    profile: str
    release_tag: str
    release_digest: str
    actions: tuple[Mapping[str, object], ...] = ()
    operator_notes: tuple[str, ...] = ()

    def with_evidence(self, evidence: Evidence) -> AcceptanceReport:
        return AcceptanceReport(
            profile=self.profile,
            release_tag=self.release_tag,
            release_digest=self.release_digest,
            actions=self.actions + (_public_action(evidence),),
            operator_notes=self.operator_notes,
        )

    @classmethod
    def from_evidence(
        cls,
        *,
        profile: str,
        release_tag: str,
        release_digest: str,
        evidence: Sequence[Evidence],
        operator_notes: Sequence[str] = (),
    ) -> AcceptanceReport:
        report = cls(
            profile=profile,
            release_tag=release_tag,
            release_digest=release_digest,
            operator_notes=tuple(operator_notes),
        )
        for item in evidence:
            report = report.with_evidence(item)
        return report

    def public_document(self) -> dict[str, object]:
        document = {
            "actions": [dict(action) for action in self.actions],
            "operator_notes": list(self.operator_notes),
            "profile": self.profile,
            "release": {
                "digest": self.release_digest,
                "tag": self.release_tag,
            },
            "schema": REPORT_SCHEMA,
        }
        _assert_public(document)
        return document


@dataclass(frozen=True)
class CredentialHandoff:
    """Root-only credentials; never summarized in the public report."""

    entries: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for label, value in self.entries.items():
            if not isinstance(label, str) or not isinstance(value, str) or not value:
                raise ReportError("credential handoff entries must be named strings")

    def document(self) -> dict[str, object]:
        return {"credentials": dict(self.entries), "schema": REPORT_SCHEMA}


class ReportWriter:
    """Write both reports with enforced, disjoint permissions."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    @property
    def public_path(self) -> Path:
        return self.root / PUBLIC_NAME

    @property
    def credentials_path(self) -> Path:
        return self.root / CREDENTIALS_DIR / CREDENTIALS_NAME

    def write_public(self, report: AcceptanceReport) -> Path:
        document = report.public_document()
        durable_mkdir(self.root, mode=0o755)
        atomic_write(
            self.public_path,
            _encode(document),
            mode=0o644,
            owner=self._owner(),
        )
        return self.public_path

    def write_credentials(self, handoff: CredentialHandoff) -> Path:
        directory = self.credentials_path.parent
        durable_mkdir(directory, mode=0o700)
        os.chmod(directory, 0o700)
        atomic_write(
            self.credentials_path,
            _encode(handoff.document()),
            mode=0o600,
            owner=self._owner(),
        )
        return self.credentials_path

    def _owner(self) -> tuple[int, int] | None:
        return (0, 0) if os.geteuid() == 0 else None


def _encode(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()


def _public_action(evidence: Evidence) -> dict[str, object]:
    facts: dict[str, object] = {}
    for key, value in evidence.details.items():
        if key not in ALLOWED_FACTS:
            continue
        if isinstance(value, bool) or isinstance(value, int):
            facts[key] = value
        elif isinstance(value, str) and _SAFE_VALUE.fullmatch(value):
            facts[key] = value
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            items = [
                item
                for item in value
                if isinstance(item, str) and _SAFE_VALUE.fullmatch(item)
            ]
            if len(items) == len(list(value)):
                facts[key] = items
    return {
        "action_id": evidence.action_id,
        "facts": facts,
        "observations": list(evidence.observations),
        "success": evidence.success,
    }


def _assert_public(value: object, *, path: str = "report") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            rendered = str(key)
            if _SECRET_NAME.search(rendered):
                raise ReportError(f"public report must not name {path}.{rendered}")
            _assert_public(item, path=f"{path}.{rendered}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, item in enumerate(value):
            _assert_public(item, path=f"{path}[{index}]")
        return
    if isinstance(value, str) and _SECRET_NAME.search(value):
        raise ReportError(f"public report must not describe a credential at {path}")
