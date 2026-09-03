from __future__ import annotations

import hashlib
import heapq
import json
import math
import re
from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from installer.model import InstallerConfig

if TYPE_CHECKING:
    from installer.adapters.base import Adapter


PLAN_SCHEMA = 1
_SECRET_NAME = (
    r"(?:password|passwd|secret|token|private[_ -]?key|api[_ -]?key)"
)
_SECRET_ASSIGNMENT = re.compile(
    rf"""
    (?:
        --{_SECRET_NAME}(?:=|\s+)(?:\"[^\"]*\"|'[^']*'|\S+)
        |
        [\"']?{_SECRET_NAME}[\"']?\s*[:=]\s*
        (?:\"[^\"]*\"|'[^']*'|[^\s,\}}\]]+)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_SECRET_KEY_PARTS = frozenset(
    {"password", "passwd", "secret", "token", "privatekey", "apikey"}
)


class PlanError(ValueError):
    """A plan cannot be represented or executed safely."""


class StalePlanError(PlanError):
    """Security-relevant host facts changed after planning."""


@dataclass(frozen=True)
class AuditFacts:
    """Immutable audit snapshot split into stable and transient observations."""

    platform: Mapping[str, object] = field(default_factory=dict)
    listeners: Mapping[str, object] = field(default_factory=dict)
    ownership: Mapping[str, object] = field(default_factory=dict)
    topology: Mapping[str, object] = field(default_factory=dict)
    prerequisites: Mapping[str, object] = field(default_factory=dict)
    transient: Mapping[str, object] = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self) -> None:
        for name in (
            "platform",
            "listeners",
            "ownership",
            "topology",
            "prerequisites",
            "transient",
        ):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise TypeError(f"{name} facts must be a mapping")
            object.__setattr__(self, name, _freeze(value))

    def stable_dict(self) -> dict[str, object]:
        """Return only facts whose drift can invalidate an approved plan."""
        return {
            "listeners": _canonical_fact_value(self.listeners),
            "ownership": _canonical_fact_value(self.ownership),
            "platform": _canonical_fact_value(self.platform),
            "prerequisites": _canonical_fact_value(self.prerequisites),
            "topology": _canonical_fact_value(self.topology),
        }


@dataclass(frozen=True)
class Action:
    """One secret-free, owned, reversible adapter mutation."""

    id: str
    adapter: str
    owner: str
    mutations: tuple[str, ...]
    preconditions: tuple[str, ...]
    verification: tuple[str, ...]
    inverse: tuple[str, ...]
    credentials_required: bool

    def __post_init__(self) -> None:
        for name in ("id", "adapter", "owner"):
            if not _nonempty(getattr(self, name)):
                raise PlanError(f"action {name} must be a non-empty string")
        for name in ("mutations", "preconditions", "verification", "inverse"):
            raw_values = getattr(self, name)
            if not isinstance(raw_values, Sequence) or isinstance(
                raw_values,
                (str, bytes, bytearray),
            ):
                raise PlanError(
                    f"action {self.id} {name} must be a non-string sequence"
                )
            values = tuple(raw_values)
            if not values or any(not _nonempty(value) for value in values):
                raise PlanError(f"action {self.id} must declare non-empty {name}")
            object.__setattr__(self, name, values)
        if not isinstance(self.credentials_required, bool):
            raise PlanError(
                f"action {self.id} credentials_required must be a boolean"
            )
        _assert_secret_free(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "adapter": self.adapter,
            "credentials_required": self.credentials_required,
            "id": self.id,
            "inverse": list(self.inverse),
            "mutations": list(self.mutations),
            "owner": self.owner,
            "preconditions": list(self.preconditions),
            "verification": list(self.verification),
        }


@dataclass(frozen=True)
class Evidence:
    """Sanitized result of verifying or rolling back an action."""

    action_id: str
    success: bool
    observations: tuple[str, ...]
    details: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _nonempty(self.action_id):
            raise PlanError("evidence action_id must be a non-empty string")
        if not isinstance(self.success, bool):
            raise PlanError("evidence success must be a boolean")
        raw_observations = self.observations
        if not isinstance(raw_observations, Sequence) or isinstance(
            raw_observations,
            (str, bytes, bytearray),
        ):
            raise PlanError(
                "evidence observations must be a non-string sequence"
            )
        observations = tuple(raw_observations)
        if any(not _nonempty(item) for item in observations):
            raise PlanError("evidence observations must be non-empty strings")
        if not isinstance(self.details, Mapping):
            raise PlanError("evidence details must be a mapping")
        object.__setattr__(self, "observations", observations)
        object.__setattr__(self, "details", _freeze(self.details))
        _assert_secret_free(
            {
                "action_id": self.action_id,
                "details": self.details,
                "observations": self.observations,
            }
        )


@dataclass(frozen=True)
class ReleaseIdentity:
    """Immutable identity and public digests for the selected release."""

    tag: str
    commit: str
    manifest_sha256: str
    components: Mapping[str, str] = field(default_factory=dict)
    artifacts: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("tag", "commit", "manifest_sha256"):
            if not _nonempty(getattr(self, name)):
                raise PlanError(f"release {name} must be a non-empty string")
        for name in ("components", "artifacts"):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise PlanError(f"release {name} must be a mapping")
            frozen = _freeze(value)
            if any(
                not _nonempty(key) or not _nonempty(item)
                for key, item in frozen.items()
            ):
                raise PlanError(f"release {name} must contain non-empty strings")
            object.__setattr__(self, name, frozen)
        _assert_secret_free(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "artifacts": dict(self.artifacts),
            "commit": self.commit,
            "components": dict(self.components),
            "manifest_sha256": self.manifest_sha256,
            "tag": self.tag,
        }


@dataclass(frozen=True)
class InstallPlan:
    """Canonical, secret-free plan approved and applied by digest."""

    config: Mapping[str, object]
    facts: AuditFacts
    release: ReleaseIdentity
    adapter_order: tuple[str, ...]
    adapter_dependencies: Mapping[str, tuple[str, ...]]
    actions: tuple[Action, ...]
    schema: int = PLAN_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != PLAN_SCHEMA:
            raise PlanError(f"unsupported plan schema: {self.schema}")
        object.__setattr__(self, "config", _freeze(self.config))
        object.__setattr__(self, "adapter_order", tuple(self.adapter_order))
        object.__setattr__(
            self,
            "adapter_dependencies",
            _freeze(self.adapter_dependencies),
        )
        object.__setattr__(self, "actions", tuple(self.actions))
        _assert_secret_free(self._canonical_dict())

    def to_canonical_json(self) -> bytes:
        try:
            rendered = json.dumps(
                self._canonical_dict(),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError) as exc:
            raise PlanError("plan contains a non-canonical JSON value") from exc
        return rendered.encode("utf-8")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.to_canonical_json()).hexdigest()

    def assert_fresh(self, current: AuditFacts) -> None:
        expected = self.facts.stable_dict()
        observed = current.stable_dict()
        labels = {
            "listeners": "listener facts changed",
            "ownership": "ownership facts changed",
            "platform": "platform facts changed",
            "prerequisites": "prerequisite facts changed",
            "topology": "topology facts changed",
        }
        for group in (
            "platform",
            "listeners",
            "ownership",
            "topology",
            "prerequisites",
        ):
            if expected[group] != observed[group]:
                raise StalePlanError(labels[group])

    def _canonical_dict(self) -> dict[str, object]:
        return {
            "actions": [item.to_dict() for item in self.actions],
            "adapter_dependencies": {
                name: list(requires)
                for name, requires in self.adapter_dependencies.items()
            },
            "adapter_order": list(self.adapter_order),
            "audit_facts": self.facts.stable_dict(),
            "config": _canonical_json_value(self.config),
            "release": self.release.to_dict(),
            "schema": self.schema,
        }


def build_plan(
    config: InstallerConfig,
    facts: AuditFacts,
    adapters: Sequence[Adapter],
    release: ReleaseIdentity,
) -> InstallPlan:
    """Plan adapters in a deterministic dependency order."""
    ordered = _topologically_sorted_adapters(adapters)
    actions: list[Action] = []
    action_ids: set[str] = set()
    dependencies: dict[str, tuple[str, ...]] = {}

    for adapter in ordered:
        dependencies[adapter.name] = tuple(sorted(adapter.requires))
        planned = adapter.plan(config, facts)
        if not isinstance(planned, tuple):
            raise PlanError(f"adapter {adapter.name} plan must return a tuple")
        for item in planned:
            if not isinstance(item, Action):
                raise PlanError(f"adapter {adapter.name} returned an invalid action")
            if item.adapter != adapter.name:
                raise PlanError(
                    f"action {item.id} names adapter {item.adapter}, expected {adapter.name}"
                )
            if item.id in action_ids:
                raise PlanError(f"duplicate action id: {item.id}")
            action_ids.add(item.id)
            actions.append(item)

    return InstallPlan(
        config=config.canonical_dict(),
        facts=facts,
        release=release,
        adapter_order=tuple(adapter.name for adapter in ordered),
        adapter_dependencies=dependencies,
        actions=tuple(actions),
    )


def _topologically_sorted_adapters(
    adapters: Sequence[Adapter],
) -> tuple[Adapter, ...]:
    by_name: dict[str, Adapter] = {}
    for adapter in adapters:
        if not _nonempty(adapter.name):
            raise PlanError("adapter name must be a non-empty string")
        if adapter.name in by_name:
            raise PlanError(f"duplicate adapter name: {adapter.name}")
        by_name[adapter.name] = adapter

    dependents: dict[str, list[str]] = {name: [] for name in by_name}
    indegree: dict[str, int] = {}
    for name, adapter in by_name.items():
        requires = frozenset(adapter.requires)
        missing = sorted(requires.difference(by_name))
        if missing:
            raise PlanError(f"adapter {name} requires missing adapter: {missing[0]}")
        indegree[name] = len(requires)
        for requirement in requires:
            dependents[requirement].append(name)

    ready = [name for name, count in indegree.items() if count == 0]
    heapq.heapify(ready)
    ordered: list[Adapter] = []
    while ready:
        name = heapq.heappop(ready)
        ordered.append(by_name[name])
        for dependent in sorted(dependents[name]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, dependent)

    if len(ordered) != len(by_name):
        cyclic = ", ".join(sorted(name for name, count in indegree.items() if count))
        raise PlanError(f"adapter dependency cycle: {cyclic}")
    return tuple(ordered)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            rendered_key = str(key)
            if rendered_key in normalized:
                raise PlanError(f"duplicate canonical mapping key: {rendered_key}")
            normalized[rendered_key] = _freeze(item)
        return MappingProxyType(dict(sorted(normalized.items())))
    if isinstance(value, Set) and not isinstance(value, (str, bytes, bytearray)):
        return frozenset(_freeze(item) for item in value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, Enum):
        return _freeze(value.value)
    if isinstance(value, float) and not math.isfinite(value):
        raise PlanError("non-finite float is forbidden in canonical data")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise PlanError(f"unsupported canonical value: {type(value).__name__}")


def _canonical_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_json_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, Set) and not isinstance(value, (str, bytes, bytearray)):
        items = [_canonical_json_value(item) for item in value]
        return sorted(items, key=_sort_key)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_canonical_json_value(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, float) and not math.isfinite(value):
        raise PlanError("non-finite float is forbidden in canonical data")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise PlanError(f"unsupported canonical value: {type(value).__name__}")


def _canonical_fact_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_fact_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, Set) and not isinstance(value, (str, bytes, bytearray)):
        items = [_canonical_fact_value(item) for item in value]
        return sorted(items, key=_sort_key)
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return [_canonical_fact_value(item) for item in value]
    return _canonical_json_value(value)


def _sort_key(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise PlanError("value cannot be ordered canonically") from exc


def _assert_secret_free(value: object, *, path: str = "plan") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            rendered_key = str(key)
            compact_key = re.sub(r"[^a-z0-9]", "", rendered_key.lower())
            if any(part in compact_key for part in _SECRET_KEY_PARTS):
                raise PlanError(f"secret field is forbidden at {path}.{rendered_key}")
            _assert_secret_free(item, path=f"{path}.{rendered_key}")
        return
    if isinstance(value, (Set, Sequence)) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        for index, item in enumerate(value):
            _assert_secret_free(item, path=f"{path}[{index}]")
        return
    if isinstance(value, str) and _SECRET_ASSIGNMENT.search(value):
        raise PlanError(f"secret material is forbidden at {path}")


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())
