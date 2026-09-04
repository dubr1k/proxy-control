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

    def prepare(self, action: Action) -> Mapping[str, object]: ...

    def apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]: ...

    def reconcile_apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]: ...

    def verify(self, action: Action) -> Evidence: ...

    def repair(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]: ...

    def rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence: ...

    def reconcile_rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence: ...
