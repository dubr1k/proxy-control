from __future__ import annotations

from typing import TYPE_CHECKING, Mapping, Protocol

if TYPE_CHECKING:
    from installer.model import InstallerConfig
    from installer.planner import Action, AuditFacts, Evidence


class Adapter(Protocol):
    """Plans and verifies mutations inside one ownership boundary."""

    name: str
    requires: frozenset[str]

    def plan(
        self,
        config: InstallerConfig,
        facts: AuditFacts,
    ) -> tuple[Action, ...]: ...

    def verify(self, action: Action) -> Evidence: ...

    def rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Evidence: ...
