from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any

from installer.adapters.base import Adapter
from installer.planner import (
    Action,
    AuditFacts,
    Evidence,
    InstallPlan,
    PlanError,
    ReleaseIdentity,
)

TRANSACTION_SCHEMA = 1
INSTALLER_PATH = "/var/lib/proxy-control/installer"
LOCK_PATH = "/run/lock/proxy-control.lock"
_CHECKPOINT_PHASES = frozenset(
    {
        "prepared",
        "applying",
        "applied",
        "verified",
        "rollback_in_progress",
        "rolled_back",
    }
)
_STATE_STATUSES = frozenset(
    {
        "applying",
        "active",
        "rolling_back",
        "rollback_failed",
        "uninstalling",
        "rolled_back",
        "uninstalled",
    }
)
_HEX_64 = re.compile(r"[0-9a-f]{64}")


class TransactionError(RuntimeError):
    """A durable installer transaction cannot proceed safely."""


class AcceptedDigestError(TransactionError):
    """The operator did not accept the exact persisted plan."""


class OwnershipError(TransactionError):
    """Owned state no longer matches the transaction journal."""


class TransactionBusyError(TransactionError):
    """Another host mutation currently holds the operation lock."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_parent(path: Path) -> None:
    missing: list[Path] = []
    cursor = path.parent
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    if not cursor.is_dir():
        raise NotADirectoryError(cursor)
    for directory in reversed(missing):
        directory.mkdir()
        fsync_directory(directory.parent)


def durable_mkdir(path: Path, *, mode: int = 0o777) -> None:
    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    if not cursor.is_dir():
        raise NotADirectoryError(cursor)
    for directory in reversed(missing):
        directory.mkdir(mode=mode if directory == path else 0o777)
        fsync_directory(directory)
        fsync_directory(directory.parent)


def fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_tree(path: Path) -> None:
    """Persist a newly copied tree bottom-up before journaling its phase."""
    for directory, names, files in os.walk(path, topdown=False):
        current = Path(directory)
        for name in files:
            child = current / name
            if not child.is_symlink() and child.is_file():
                fsync_file(child)
        for name in names:
            child = current / name
            if not child.is_symlink() and child.is_dir():
                fsync_directory(child)
        fsync_directory(current)
    fsync_directory(path.parent)


def durable_copy2(source: Path, destination: Path) -> None:
    ensure_parent(destination)
    shutil.copy2(source, destination)
    fsync_file(destination)
    fsync_directory(destination.parent)


def durable_symlink(target: str, path: Path) -> None:
    ensure_parent(path)
    os.symlink(target, path)
    fsync_directory(path.parent)


def durable_remove(path: Path, *, missing_ok: bool = False) -> None:
    if not path.exists() and not path.is_symlink():
        if missing_ok:
            return
        raise FileNotFoundError(path)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()
    fsync_directory(path.parent)


def atomic_write(
    path: Path,
    data: bytes,
    *,
    mode: int,
    owner: tuple[int, int] | None = None,
) -> None:
    ensure_parent(path)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            if owner is not None:
                os.fchown(handle.fileno(), *owner)
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def operation_lock(
    root: Path,
    *,
    error_type: type[Exception] = TransactionBusyError,
) -> Iterator[None]:
    lock_path = _root_path(root, LOCK_PATH)
    ensure_parent(lock_path)
    if lock_path.is_symlink():
        raise OwnershipError("operation lock must be a contained regular file")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        if lock_path.is_symlink():
            raise OwnershipError(
                "operation lock must be a contained regular file"
            ) from exc
        raise
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        os.close(descriptor)
        raise OwnershipError("operation lock must be a contained regular file")
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "r+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise error_type("another proxyctl operation is in progress") from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


@dataclass(frozen=True)
class TransactionCheckpoint:
    """Immutable durable progress for one adapter action."""

    action_id: str
    adapter: str
    phase: str
    data: Mapping[str, object] = field(default_factory=dict)
    ownership: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    evidence: Mapping[str, object] | None = None
    rollback_evidence: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if not self.action_id or not self.adapter:
            raise TransactionError("checkpoint identity is invalid")
        if self.phase not in _CHECKPOINT_PHASES:
            raise TransactionError("checkpoint phase is invalid")
        object.__setattr__(self, "data", _freeze_mapping(self.data))
        object.__setattr__(self, "ownership", _freeze_mapping(self.ownership))
        if self.evidence is not None:
            object.__setattr__(self, "evidence", _freeze_mapping(self.evidence))
        if self.rollback_evidence is not None:
            object.__setattr__(
                self,
                "rollback_evidence",
                _freeze_mapping(self.rollback_evidence),
            )
        _canonical_json(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "action_id": self.action_id,
            "adapter": self.adapter,
            "data": _thaw(self.data),
            "ownership": _thaw(self.ownership),
            "phase": self.phase,
        }
        if self.evidence is not None:
            value["evidence"] = _thaw(self.evidence)
        if self.rollback_evidence is not None:
            value["rollback_evidence"] = _thaw(self.rollback_evidence)
        return value

    @classmethod
    def from_dict(cls, value: object) -> TransactionCheckpoint:
        if not isinstance(value, Mapping):
            raise TransactionError("checkpoint is invalid")
        required = {"action_id", "adapter", "data", "ownership", "phase"}
        if not required <= set(value) or not set(value) <= required | {
            "evidence",
            "rollback_evidence",
        }:
            raise TransactionError("checkpoint is invalid")
        try:
            return cls(
                action_id=value["action_id"],
                adapter=value["adapter"],
                phase=value["phase"],
                data=value["data"],
                ownership=value["ownership"],
                evidence=value.get("evidence"),
                rollback_evidence=value.get("rollback_evidence"),
            )
        except (TypeError, ValueError) as exc:
            raise TransactionError("checkpoint is invalid") from exc


@dataclass(frozen=True)
class TransactionState:
    """Immutable transaction journal reconstructed from every durable write."""

    transaction_id: str
    status: str
    plan_digest: str
    accepted_digest: str
    checkpoints: tuple[TransactionCheckpoint, ...] = ()
    purge_data: bool | None = None
    rollback_target: str | None = None
    origin: str = "installer-v1"
    error: str | None = None
    legacy: Mapping[str, object] = field(default_factory=dict, repr=False)
    schema: int = TRANSACTION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != TRANSACTION_SCHEMA:
            raise TransactionError("transaction schema is invalid")
        if not re.fullmatch(r"[0-9a-f]{32}", self.transaction_id):
            raise TransactionError("transaction identity is invalid")
        if self.status not in _STATE_STATUSES:
            raise TransactionError("transaction status is invalid")
        if not _HEX_64.fullmatch(self.plan_digest) or self.accepted_digest != self.plan_digest:
            raise TransactionError("transaction plan digest is invalid")
        if not isinstance(self.checkpoints, tuple):
            object.__setattr__(self, "checkpoints", tuple(self.checkpoints))
        if any(not isinstance(item, TransactionCheckpoint) for item in self.checkpoints):
            raise TransactionError("transaction checkpoints are invalid")
        ids = [item.action_id for item in self.checkpoints]
        if len(ids) != len(set(ids)):
            raise TransactionError("transaction checkpoint actions are duplicated")
        if self.purge_data is not None and not isinstance(self.purge_data, bool):
            raise TransactionError("transaction data policy is invalid")
        if self.rollback_target not in {None, "rolled_back", "uninstalled"}:
            raise TransactionError("transaction rollback target is invalid")
        if not self.origin:
            raise TransactionError("transaction origin is invalid")
        object.__setattr__(self, "legacy", _freeze_mapping(self.legacy))
        _canonical_json(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "accepted_digest": self.accepted_digest,
            "checkpoints": [item.to_dict() for item in self.checkpoints],
            "origin": self.origin,
            "plan_digest": self.plan_digest,
            "schema": self.schema,
            "status": self.status,
            "transaction_id": self.transaction_id,
        }
        if self.error is not None:
            value["error"] = self.error
        if self.legacy:
            value["legacy"] = _thaw(self.legacy)
        if self.purge_data is not None:
            value["purge_data"] = self.purge_data
        if self.rollback_target is not None:
            value["rollback_target"] = self.rollback_target
        return value

    @classmethod
    def from_dict(cls, value: object) -> TransactionState:
        if not isinstance(value, Mapping):
            raise TransactionError("transaction state is invalid")
        required = {
            "accepted_digest",
            "checkpoints",
            "origin",
            "plan_digest",
            "schema",
            "status",
            "transaction_id",
        }
        optional = {"error", "legacy", "purge_data", "rollback_target"}
        if not required <= set(value) or not set(value) <= required | optional:
            raise TransactionError("transaction state is invalid")
        raw_checkpoints = value["checkpoints"]
        if not isinstance(raw_checkpoints, list):
            raise TransactionError("transaction checkpoints are invalid")
        try:
            return cls(
                accepted_digest=value["accepted_digest"],
                checkpoints=tuple(
                    TransactionCheckpoint.from_dict(item) for item in raw_checkpoints
                ),
                error=value.get("error"),
                legacy=value.get("legacy", {}),
                origin=value["origin"],
                plan_digest=value["plan_digest"],
                purge_data=value.get("purge_data"),
                rollback_target=value.get("rollback_target"),
                schema=value["schema"],
                status=value["status"],
                transaction_id=value["transaction_id"],
            )
        except (TypeError, ValueError) as exc:
            raise TransactionError("transaction state is invalid") from exc

    @classmethod
    def from_verified_legacy(
        cls,
        legacy: Mapping[str, object],
        plan: InstallPlan,
        checkpoint: TransactionCheckpoint,
    ) -> TransactionState:
        encoded = _canonical_json(legacy)
        return cls(
            transaction_id=sha256(b"runtime-v2:" + encoded)[:32],
            status="active",
            plan_digest=plan.digest,
            accepted_digest=plan.digest,
            checkpoints=(checkpoint,),
            origin="runtime-v2",
            legacy=legacy,
        )


class TransactionStore:
    """Private, atomic on-disk storage for one installer transaction."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.directory = _root_path(self.root, INSTALLER_PATH)
        self.state_path = self.directory / "state.json"
        self.plan_path = self.directory / "plan.json"
        self.ownership_path = self.directory / "ownership.json"
        self.backups_path = self.directory / "backups"
        self.report_path = self.directory / "report.json"
        self.credentials_path = self.directory / "credentials"

    def initialize(self) -> None:
        for directory in (self.directory, self.backups_path, self.credentials_path):
            _assert_contained(self.root, directory)
        durable_mkdir(self.directory, mode=0o700)
        durable_mkdir(self.backups_path, mode=0o700)
        durable_mkdir(self.credentials_path, mode=0o700)
        for directory in (self.directory, self.backups_path, self.credentials_path):
            os.chmod(directory, 0o700)
            fsync_directory(directory)

    def locked(self) -> Iterator[None]:
        return operation_lock(self.root)

    def write_plan(self, plan: InstallPlan) -> None:
        self.initialize()
        atomic_write(self.plan_path, plan.to_canonical_json(), mode=0o600)

    def read_plan(self) -> InstallPlan:
        try:
            value = json.loads(self.plan_path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise TransactionError("transaction plan is unreadable") from exc
        return _plan_from_dict(value)

    def write_state(self, state: TransactionState) -> None:
        self._write_json(self.state_path, state.to_dict())

    def read_state(self) -> TransactionState:
        return TransactionState.from_dict(self._read_json(self.state_path, "state"))

    def write_ownership(self, ownership: Mapping[str, object]) -> None:
        self._write_json(
            self.ownership_path,
            {"files": _thaw(ownership), "schema": TRANSACTION_SCHEMA},
        )

    def read_ownership(self) -> Mapping[str, Mapping[str, object]]:
        value = self._read_json(self.ownership_path, "ownership journal")
        if set(value) != {"files", "schema"} or value.get("schema") != TRANSACTION_SCHEMA:
            raise OwnershipError("ownership journal is invalid")
        files = value.get("files")
        if not isinstance(files, Mapping):
            raise OwnershipError("ownership journal is invalid")
        return _freeze_mapping(files)

    def write_report(self, report: Mapping[str, object]) -> None:
        self._write_json(self.report_path, report)

    def _write_json(self, path: Path, value: Mapping[str, object]) -> None:
        self.initialize()
        atomic_write(path, _pretty_json(value), mode=0o600)

    @staticmethod
    def _read_json(path: Path, label: str) -> dict[str, object]:
        try:
            value = json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise TransactionError(f"transaction {label} is unreadable") from exc
        if not isinstance(value, dict):
            raise TransactionError(f"transaction {label} is invalid")
        return value


class RuntimeV2Adapter:
    """Lifecycle adapter for an explicitly imported runtime-v2 generation."""

    name = "runtime-v2"
    requires: frozenset[str] = frozenset()

    def __init__(self, root: Path, *, runner: object | None = None):
        self.root = Path(root)
        self.runner = runner

    def prepare(self, action: Action) -> Mapping[str, object]:
        del action
        raise TransactionError("runtime-v2 is import-only")

    def apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        del action, checkpoint
        raise TransactionError("runtime-v2 is import-only")

    def reconcile_apply(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        del action, checkpoint
        raise TransactionError("runtime-v2 is import-only")

    def verify(self, action: Action) -> Evidence:
        state = TransactionStore(self.root).read_state()
        legacy = _thaw(state.legacy)
        validate_legacy_runtime_v2(self.root, legacy)
        manager = self._manager(legacy)
        if manager._read_runtime_state() != legacy:
            raise OwnershipError("runtime-v2 manifest has drifted")
        return Evidence(
            action_id=action.id,
            success=True,
            observations=("runtime-v2 lifecycle ownership verified",),
        )

    def rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        del rollback_target
        legacy = self._legacy(checkpoint)
        manager = self._manager(legacy)
        if manager.state_path.exists():
            runtime_state = manager._read_runtime_state()
            if (
                runtime_state.get("status") == "active"
                and runtime_state != legacy
            ):
                raise OwnershipError("runtime-v2 manifest has drifted")
        manager.uninstall(purge_data=purge_data, _locked=True)
        self._verify_inverse(manager, legacy)
        return Evidence(
            action_id=action.id,
            success=True,
            observations=("runtime-v2 lifecycle completely removed",),
        )

    def reconcile_rollback(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        return self.rollback(
            action,
            checkpoint,
            purge_data=purge_data,
            rollback_target=rollback_target,
        )

    @staticmethod
    def _legacy(
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, object]:
        legacy = checkpoint.get("legacy")
        if not isinstance(legacy, Mapping):
            raise TransactionError("runtime-v2 checkpoint is invalid")
        return legacy

    def _manager(self, legacy: Mapping[str, object]) -> object:
        from scripts.proxyctl import RuntimeInstaller, RuntimePlan

        raw_plan = legacy.get("plan")
        if not isinstance(raw_plan, Mapping):
            raise TransactionError("runtime-v2 plan is invalid")
        fields = set(RuntimePlan.__dataclass_fields__)
        payload = {
            key: _thaw(value)
            for key, value in raw_plan.items()
            if key in fields
        }
        if isinstance(payload.get("users"), list):
            payload["users"] = tuple(payload["users"])
        try:
            plan = RuntimePlan(**payload)
        except (TypeError, ValueError) as exc:
            raise TransactionError("runtime-v2 plan is invalid") from exc
        if plan.to_dict() != _thaw(raw_plan):
            raise TransactionError("runtime-v2 plan is invalid")
        return RuntimeInstaller(plan, root=self.root, runner=self.runner)

    def _verify_inverse(
        self,
        manager: object,
        legacy: Mapping[str, object],
    ) -> None:
        if manager.state_path.exists():
            raise TransactionError("runtime-v2 manifest remains after rollback")
        route_state = _root_path(
            self.root,
            "/var/lib/proxy-control/ownership.json",
        )
        if route_state.exists() or route_state.is_symlink():
            raise TransactionError("runtime-v2 route ownership remains after rollback")
        for raw_path in legacy["managed_files"]:
            host_path, path = _owned_path(self.root, raw_path)
            if path.exists() or path.is_symlink():
                raise OwnershipError(f"owned file remains: {host_path}")
        project = _root_path(
            self.root,
            str(legacy["plan"]["project_dir"]),
        )
        if project.is_dir():
            unexpected = {
                child.name
                for child in project.iterdir()
                if child.name not in {"secrets", ".mtproxy-owned"}
            }
            if unexpected:
                raise TransactionError(
                    "runtime-v2 project artifacts remain after rollback"
                )
        installed = [
            package
            for package in legacy["owned_packages"]
            if manager.runner.package_installed(package)
        ]
        if installed:
            raise TransactionError(
                "runtime-v2 packages remain after rollback: "
                + ", ".join(installed)
            )


class TransactionEngine:
    """Checkpointed adapter executor with fail-closed ownership recovery."""

    def __init__(
        self,
        store: TransactionStore,
        adapters: Mapping[str, Adapter],
    ):
        self.store = store
        self.adapters = dict(adapters)
        self.adapters.setdefault("runtime-v2", RuntimeV2Adapter(store.root))

    def apply(self, plan: InstallPlan, accepted_digest: str) -> TransactionState:
        if accepted_digest != plan.digest:
            raise AcceptedDigestError("accepted plan digest does not match")
        with self.store.locked():
            if self.store.state_path.exists():
                raise TransactionError("an installer transaction already exists")
            self._validate_adapters(plan)
            self.store.write_plan(plan)
            state = TransactionState(
                transaction_id=uuid.uuid4().hex,
                status="applying",
                plan_digest=plan.digest,
                accepted_digest=accepted_digest,
            )
            self._persist(state)
            try:
                return self._continue_apply(plan, state)
            except Exception as exc:
                state = self.store.read_state()
                try:
                    self._rollback(plan, state, final_status="rolled_back", error=exc)
                except Exception:
                    raise
                raise

    def resume(self) -> TransactionState:
        with self.store.locked():
            state = self.store.read_state()
            plan = self._read_matching_plan(state)
            if state.status == "applying":
                self._validate_adapters(plan)
                try:
                    return self._continue_apply(plan, state)
                except Exception as exc:
                    state = self.store.read_state()
                    try:
                        self._rollback(
                            plan,
                            state,
                            final_status="rolled_back",
                            error=exc,
                        )
                    except Exception:
                        raise
                    raise
            if state.status in {"rolling_back", "rollback_failed", "uninstalling"}:
                self._validate_adapters(plan)
                final_status = state.rollback_target
                if final_status is None:
                    final_status = (
                        "uninstalled"
                        if state.status == "uninstalling"
                        else "rolled_back"
                    )
                return self._rollback(plan, state, final_status=final_status)
            if state.status == "active":
                self._validate_adapters(plan)
                self._assert_all_owned(state)
            self._persist(state)
            return state

    def repair(self) -> TransactionState:
        with self.store.locked():
            state = self.store.read_state()
            plan = self._read_matching_plan(state)
            self._validate_adapters(plan)
            if state.status != "active":
                if state.status in {"applying", "rolling_back", "rollback_failed", "uninstalling"}:
                    raise TransactionError("resume the interrupted transaction before repair")
                return state
            self._assert_all_owned(state)
            by_id = {item.action_id: item for item in state.checkpoints}
            for action in plan.actions:
                checkpoint = by_id.get(action.id)
                if checkpoint is None or checkpoint.phase != "verified":
                    raise TransactionError("active transaction has incomplete checkpoints")
                adapter = self._adapter(action)
                repair = getattr(adapter, "repair", None)
                if callable(repair):
                    raw_checkpoint = repair(action, _thaw(checkpoint.data))
                    data = _checkpoint_data(raw_checkpoint, action.adapter)
                    checkpoint = replace(
                        checkpoint,
                        data=data,
                        ownership=self._capture_ownership(action, data),
                    )
                evidence = self._verify(action)
                checkpoint = replace(
                    checkpoint,
                    evidence=_evidence_to_dict(evidence),
                )
                state = self._with_checkpoint(state, checkpoint)
                self._persist_checkpoint(state, checkpoint, action)
                by_id[action.id] = checkpoint
            state = replace(state, error=None)
            self._persist(state)
            return state

    def uninstall(self, purge_data: bool) -> TransactionState:
        if not isinstance(purge_data, bool):
            raise TypeError("purge_data must be a boolean")
        with self.store.locked():
            state = self.store.read_state()
            plan = self._read_matching_plan(state)
            self._validate_adapters(plan)
            if state.status in {"uninstalled", "rolled_back"}:
                self._persist(state)
                return state
            if state.status not in {"active", "uninstalling"}:
                raise TransactionError("resume the interrupted transaction before uninstall")
            if state.status == "uninstalling" and state.purge_data != purge_data:
                required = "with --purge-data" if state.purge_data else "without --purge-data"
                raise TransactionError(f"retry the interrupted uninstall {required}")
            self._assert_all_owned(state)
            state = replace(
                state,
                status="uninstalling",
                purge_data=purge_data,
                rollback_target="uninstalled",
                error=None,
            )
            self._persist(state)
            return self._rollback(plan, state, final_status="uninstalled")

    def _continue_apply(
        self,
        plan: InstallPlan,
        state: TransactionState,
    ) -> TransactionState:
        checkpoints = {item.action_id: item for item in state.checkpoints}
        for action in plan.actions:
            checkpoint = checkpoints.get(action.id)
            adapter = self._adapter(action)
            if checkpoint is None:
                prepare = getattr(adapter, "prepare", None)
                if not callable(prepare):
                    raise TransactionError(
                        f"adapter does not implement prepare: {action.adapter}"
                    )
                raw_checkpoint = prepare(action)
                data = _checkpoint_data(raw_checkpoint, action.adapter)
                checkpoint = TransactionCheckpoint(
                    action_id=action.id,
                    adapter=action.adapter,
                    phase="prepared",
                    data=data,
                )
                state = self._with_checkpoint(state, checkpoint)
                self._persist_checkpoint(state, checkpoint, action)
                checkpoints[action.id] = checkpoint
            if checkpoint.phase == "prepared":
                checkpoint = replace(checkpoint, phase="applying")
                state = self._with_checkpoint(state, checkpoint)
                self._persist_checkpoint(state, checkpoint, action)
                checkpoints[action.id] = checkpoint
                apply_method = getattr(adapter, "apply", None)
                if not callable(apply_method):
                    raise TransactionError(
                        f"adapter does not implement apply: {action.adapter}"
                    )
                raw_checkpoint = apply_method(action, _thaw(checkpoint.data))
                data = _checkpoint_data(raw_checkpoint, action.adapter)
                checkpoint = self._finish_apply(action, checkpoint, data)
                state = self._with_checkpoint(state, checkpoint)
                self._persist_checkpoint(state, checkpoint, action)
                checkpoints[action.id] = checkpoint
            elif checkpoint.phase == "applying":
                reconcile = getattr(adapter, "reconcile_apply", None)
                if not callable(reconcile):
                    raise TransactionError(
                        f"adapter does not implement reconcile_apply: {action.adapter}"
                    )
                raw_checkpoint = reconcile(action, _thaw(checkpoint.data))
                data = _checkpoint_data(raw_checkpoint, action.adapter)
                checkpoint = self._finish_apply(action, checkpoint, data)
                state = self._with_checkpoint(state, checkpoint)
                self._persist_checkpoint(state, checkpoint, action)
                checkpoints[action.id] = checkpoint
            if checkpoint.phase == "applied":
                evidence = self._verify(action)
                checkpoint = replace(
                    checkpoint,
                    phase="verified",
                    evidence=_evidence_to_dict(evidence),
                )
                state = self._with_checkpoint(state, checkpoint)
                self._persist_checkpoint(state, checkpoint, action)
                checkpoints[action.id] = checkpoint
            if checkpoint.phase in {"rollback_in_progress", "rolled_back"}:
                raise TransactionError("cannot apply a rolled-back checkpoint")
        state = replace(state, status="active", error=None)
        self._persist(state)
        return state

    def _finish_apply(
        self,
        action: Action,
        checkpoint: TransactionCheckpoint,
        data: Mapping[str, object],
    ) -> TransactionCheckpoint:
        ownership = self._capture_ownership(action, data)
        return replace(
            checkpoint,
            phase="applied",
            data=data,
            ownership=ownership,
        )

    def _rollback(
        self,
        plan: InstallPlan,
        state: TransactionState,
        *,
        final_status: str,
        error: Exception | None = None,
    ) -> TransactionState:
        if final_status not in {"rolled_back", "uninstalled"}:
            raise ValueError("invalid rollback target")
        try:
            self._assert_all_owned(state)
            state = replace(
                state,
                status="uninstalling" if final_status == "uninstalled" else "rolling_back",
                rollback_target=final_status,
                error=type(error).__name__ if error is not None else state.error,
            )
            self._persist(state)
            by_action = {action.id: action for action in plan.actions}
            purge_data = final_status == "rolled_back" or state.purge_data is True
            for checkpoint in reversed(state.checkpoints):
                if checkpoint.phase == "rolled_back":
                    continue
                action = by_action.get(checkpoint.action_id)
                if action is None or action.adapter != checkpoint.adapter:
                    raise TransactionError("checkpoint does not belong to the persisted plan")
                if checkpoint.phase == "prepared":
                    checkpoint = replace(checkpoint, phase="rolled_back")
                    state = self._with_checkpoint(state, checkpoint)
                    self._persist(state)
                    continue
                adapter = self._adapter(action)
                preserve = {
                    path: entry
                    for path, entry in checkpoint.ownership.items()
                    if entry.get("preserve") is True
                }
                if checkpoint.phase in {"applied", "verified"}:
                    self._assert_owned(checkpoint.ownership)
                    checkpoint = replace(checkpoint, phase="rollback_in_progress")
                    state = self._with_checkpoint(state, checkpoint)
                    self._persist_checkpoint(state, checkpoint, action)
                    rollback = getattr(adapter, "rollback", None)
                    if not callable(rollback):
                        raise TransactionError(
                            f"adapter does not implement rollback: {action.adapter}"
                        )
                    evidence = rollback(
                        action,
                        _thaw(checkpoint.data),
                        purge_data=purge_data,
                        rollback_target=final_status,
                    )
                elif checkpoint.phase in {"applying", "rollback_in_progress"}:
                    if checkpoint.phase == "applying":
                        checkpoint = replace(
                            checkpoint,
                            phase="rollback_in_progress",
                        )
                        state = self._with_checkpoint(state, checkpoint)
                        self._persist_checkpoint(state, checkpoint, action)
                    self._assert_reconcile_safe(
                        checkpoint.ownership,
                        purge_data=purge_data,
                    )
                    reconcile = getattr(adapter, "reconcile_rollback", None)
                    if not callable(reconcile):
                        raise TransactionError(
                            f"adapter does not implement reconcile_rollback: {action.adapter}"
                        )
                    evidence = reconcile(
                        action,
                        _thaw(checkpoint.data),
                        purge_data=purge_data,
                        rollback_target=final_status,
                    )
                else:
                    continue
                if not isinstance(evidence, Evidence) or not evidence.success:
                    raise TransactionError(f"adapter rollback failed: {action.adapter}")
                if not purge_data:
                    self._assert_owned(preserve)
                checkpoint = replace(
                    checkpoint,
                    phase="rolled_back",
                    rollback_evidence=_evidence_to_dict(evidence),
                )
                state = self._with_checkpoint(state, checkpoint)
                self._persist(state)
            state = replace(state, status=final_status)
            self._persist(state)
            return state
        except Exception as exc:
            failed = replace(
                state,
                status="rollback_failed",
                rollback_target=final_status,
                error=type(exc).__name__,
            )
            self._persist(failed)
            raise

    def _verify(self, action: Action) -> Evidence:
        evidence = self._adapter(action).verify(action)
        if not isinstance(evidence, Evidence) or evidence.action_id != action.id:
            raise TransactionError(f"adapter returned invalid evidence: {action.adapter}")
        if not evidence.success:
            raise TransactionError(f"adapter verification failed: {action.adapter}")
        return evidence

    def _capture_ownership(
        self,
        action: Action,
        checkpoint: Mapping[str, object],
    ) -> Mapping[str, Mapping[str, object]]:
        declaration: object = checkpoint.get("ownership")
        if declaration is None:
            declaration = checkpoint.get("owned_files")
        if declaration is None:
            declaration = checkpoint.get("owned_paths", ())
        if isinstance(declaration, Mapping):
            declared = declaration.items()
        elif isinstance(declaration, Sequence) and not isinstance(
            declaration,
            (str, bytes, bytearray),
        ):
            declared = ((item, None) for item in declaration)
        else:
            raise TransactionError(f"adapter ownership is invalid: {action.adapter}")
        ownership: dict[str, Mapping[str, object]] = {}
        for raw_path, expected in declared:
            host_path, path = _owned_path(self.store.root, raw_path)
            actual = _path_identity(path)
            preserve = False
            if isinstance(expected, str):
                if expected != actual["sha256"]:
                    raise OwnershipError(f"owned file drifted: {host_path}")
            elif isinstance(expected, Mapping):
                expected_hash = expected.get("sha256")
                if expected_hash is not None and expected_hash != actual["sha256"]:
                    raise OwnershipError(f"owned file drifted: {host_path}")
                preserve = expected.get("preserve", False)
                if not isinstance(preserve, bool):
                    raise TransactionError("adapter ownership preservation flag is invalid")
            elif expected is not None:
                raise TransactionError(f"adapter ownership is invalid: {action.adapter}")
            ownership[host_path] = MappingProxyType(
                {
                    "action_id": action.id,
                    "adapter": action.adapter,
                    "kind": actual["kind"],
                    "preserve": preserve,
                    "sha256": actual["sha256"],
                }
            )
        return MappingProxyType(ownership)

    def _assert_all_owned(self, state: TransactionState) -> None:
        self._assert_owned(self._ownership_for(state, include_in_progress=False))

    def _assert_owned(self, ownership: Mapping[str, Mapping[str, object]]) -> None:
        for host_path, expected in ownership.items():
            _normalized, path = _owned_path(self.store.root, host_path)
            try:
                actual = _path_identity(path)
            except OwnershipError as exc:
                raise OwnershipError(f"owned file drifted: {host_path}") from exc
            if (
                actual["kind"] != expected.get("kind")
                or actual["sha256"] != expected.get("sha256")
            ):
                raise OwnershipError(f"owned file drifted: {host_path}")


    def _assert_reconcile_safe(
        self,
        ownership: Mapping[str, Mapping[str, object]],
        *,
        purge_data: bool,
    ) -> None:
        for host_path, expected in ownership.items():
            _normalized, path = _owned_path(self.store.root, host_path)
            exists = path.exists() or path.is_symlink()
            if not exists:
                if expected.get("preserve") is True and not purge_data:
                    raise OwnershipError(f"owned file drifted: {host_path}")
                continue
            actual = _path_identity(path)
            if (
                actual["kind"] != expected.get("kind")
                or actual["sha256"] != expected.get("sha256")
            ):
                raise OwnershipError(f"owned file drifted: {host_path}")

    def _ownership_for(
        self,
        state: TransactionState,
        *,
        include_in_progress: bool = True,
    ) -> Mapping[str, Mapping[str, object]]:
        phases = {"applied", "verified"}
        if include_in_progress:
            phases.add("rollback_in_progress")
        ownership: dict[str, Mapping[str, object]] = {}
        for checkpoint in state.checkpoints:
            if checkpoint.phase in phases:
                for path, entry in checkpoint.ownership.items():
                    if path in ownership:
                        raise OwnershipError("ownership journal contains duplicate paths")
                    ownership[path] = entry
        return MappingProxyType(ownership)

    def _persist_checkpoint(
        self,
        state: TransactionState,
        checkpoint: TransactionCheckpoint,
        action: Action,
    ) -> None:
        self._persist(state)
        hook = getattr(self._adapter(action), "checkpoint_committed", None)
        if callable(hook):
            hook(checkpoint.phase, action)

    def _persist(self, state: TransactionState) -> None:
        self.store.write_state(state)
        ownership = self._ownership_for(state)
        self.store.write_ownership(ownership)
        self.store.write_report(
            {
                "checkpoints": [
                    {
                        "action_id": checkpoint.action_id,
                        "evidence": _thaw(checkpoint.evidence)
                        if checkpoint.evidence is not None
                        else None,
                        "phase": checkpoint.phase,
                        "rollback_evidence": _thaw(checkpoint.rollback_evidence)
                        if checkpoint.rollback_evidence is not None
                        else None,
                    }
                    for checkpoint in state.checkpoints
                ],
                "error": state.error,
                "plan_digest": state.plan_digest,
                "schema": TRANSACTION_SCHEMA,
                "status": state.status,
                "transaction_id": state.transaction_id,
            }
        )

    def _with_checkpoint(
        self,
        state: TransactionState,
        replacement: TransactionCheckpoint,
    ) -> TransactionState:
        checkpoints = list(state.checkpoints)
        for index, checkpoint in enumerate(checkpoints):
            if checkpoint.action_id == replacement.action_id:
                checkpoints[index] = replacement
                break
        else:
            checkpoints.append(replacement)
        return replace(state, checkpoints=tuple(checkpoints))

    def _read_matching_plan(self, state: TransactionState) -> InstallPlan:
        plan = self.store.read_plan()
        if plan.digest != state.plan_digest or state.accepted_digest != state.plan_digest:
            raise TransactionError("persisted plan digest does not match transaction state")
        return plan

    def _validate_adapters(self, plan: InstallPlan) -> None:
        for action in plan.actions:
            self._adapter(action)

    def _adapter(self, action: Action) -> Adapter:
        adapter = self.adapters.get(action.adapter)
        if adapter is None or getattr(adapter, "name", None) != action.adapter:
            raise TransactionError(f"adapter is unavailable: {action.adapter}")
        return adapter


def validate_legacy_runtime_v2(root: Path, legacy: Mapping[str, object]) -> None:
    """Validate a complete active runtime-v2 journal without mutating the host."""
    if not isinstance(legacy, Mapping):
        raise TransactionError("legacy runtime manifest is invalid")
    required = {
        "managed_files",
        "managed_hashes",
        "owned_packages",
        "phase",
        "plan",
        "project_created",
        "schema",
        "status",
    }
    if set(legacy) != required or legacy.get("schema") != 2:
        raise TransactionError("legacy runtime manifest is invalid")
    if legacy.get("status") != "active" or legacy.get("phase") != "route_installed":
        raise TransactionError("legacy runtime must be active before import")
    if not isinstance(legacy.get("plan"), Mapping):
        raise TransactionError("legacy runtime plan is invalid")
    packages = legacy.get("owned_packages")
    if (
        not isinstance(packages, list)
        or packages != sorted(set(packages))
        or any(not isinstance(item, str) or not item for item in packages)
    ):
        raise TransactionError("legacy runtime package ownership is invalid")
    if not isinstance(legacy.get("project_created"), bool):
        raise TransactionError("legacy runtime project ownership is invalid")
    managed_files = legacy.get("managed_files")
    managed_hashes = legacy.get("managed_hashes")
    if (
        not isinstance(managed_files, list)
        or any(not isinstance(item, str) for item in managed_files)
        or len(managed_files) != len(set(managed_files))
        or not isinstance(managed_hashes, Mapping)
        or set(managed_hashes) != set(managed_files)
    ):
        raise OwnershipError("legacy managed-file ownership is invalid")
    for host_path in managed_files:
        expected = managed_hashes[host_path]
        if not isinstance(expected, str) or not _HEX_64.fullmatch(expected):
            raise OwnershipError("legacy managed-file ownership is invalid")
        normalized, path = _owned_path(Path(root), host_path)
        if host_path != normalized:
            raise OwnershipError("legacy managed-file paths must be canonical")
        try:
            actual = _path_identity(path)["sha256"]
        except OwnershipError as exc:
            raise OwnershipError(f"legacy managed file drifted: {host_path}") from exc
        if actual != expected:
            raise OwnershipError(f"legacy managed file drifted: {host_path}")


def import_runtime_v2(
    root: Path,
    legacy: Mapping[str, object],
) -> TransactionState:
    """Persist a verified runtime-v2 import without touching managed host bytes."""
    root = Path(root)
    store = TransactionStore(root)
    with store.locked():
        validate_legacy_runtime_v2(root, legacy)
        if store.state_path.exists():
            raise TransactionError("an installer transaction already exists")
        encoded = _canonical_json(legacy)
        legacy_digest = sha256(encoded)
        action = Action(
            id="runtime-v2.import",
            adapter="runtime-v2",
            owner="proxy-control:runtime-v2",
            mutations=("adopt verified runtime-v2 ownership",),
            preconditions=("runtime-v2 journal is active and verified",),
            verification=("runtime-v2 lifecycle retains its verified ownership",),
            inverse=("reverse the complete runtime-v2 lifecycle through its manager",),
            credentials_required=False,
        )
        plan = InstallPlan(
            config={"legacy_runtime_schema": 2},
            facts=AuditFacts(ownership={"imported_runtime": "v2"}),
            release=ReleaseIdentity(
                tag="runtime-v2",
                commit=legacy_digest[:40],
                manifest_sha256=legacy_digest,
            ),
            adapter_order=("runtime-v2",),
            adapter_dependencies={"runtime-v2": ()},
            actions=(action,),
        )
        managed_files = legacy["managed_files"]
        managed_hashes = legacy["managed_hashes"]
        ownership: dict[str, Mapping[str, object]] = {}
        for host_path in managed_files:
            normalized, path = _owned_path(root, host_path)
            identity = _path_identity(path)
            if identity["sha256"] != managed_hashes[host_path]:
                raise OwnershipError(
                    f"legacy managed file drifted: {host_path}"
                )
            ownership[normalized] = MappingProxyType(
                {
                    "action_id": action.id,
                    "adapter": action.adapter,
                    "kind": identity["kind"],
                    "preserve": False,
                    "sha256": identity["sha256"],
                }
            )
        data = {
            "legacy": _thaw(legacy),
            "ownership": {
                host_path: {
                    "preserve": False,
                    "sha256": entry["sha256"],
                }
                for host_path, entry in ownership.items()
            },
        }
        checkpoint = TransactionCheckpoint(
            action_id=action.id,
            adapter=action.adapter,
            phase="verified",
            data=data,
            ownership=ownership,
            evidence={
                "action_id": action.id,
                "details": {},
                "observations": ["runtime-v2 lifecycle ownership verified"],
                "success": True,
            },
        )
        state = TransactionState.from_verified_legacy(legacy, plan, checkpoint)
        store.write_plan(plan)
        TransactionEngine(store, {})._persist(state)
        return state


def _path_identity(path: Path) -> dict[str, str]:
    if path.is_symlink():
        return {
            "kind": "symlink",
            "sha256": sha256(("symlink:" + os.readlink(path)).encode()),
        }
    if not path.is_file():
        raise OwnershipError(f"owned file is missing: {path}")
    return {"kind": "file", "sha256": sha256(path.read_bytes())}


def _owned_path(root: Path, raw_path: object) -> tuple[str, Path]:
    if not isinstance(raw_path, str) or not raw_path.startswith("/"):
        raise OwnershipError("owned path is unsafe")
    pure = Path(raw_path)
    if ".." in pure.parts:
        raise OwnershipError("owned path is unsafe")
    normalized = "/" + "/".join(part for part in pure.parts if part != "/")
    return normalized, _root_path(root, normalized)


def _root_path(root: Path, absolute: str) -> Path:
    if not absolute.startswith("/") or ".." in Path(absolute).parts:
        raise TransactionError("host paths must be absolute and normalized")
    root = Path(root)
    candidate = root / absolute.lstrip("/")
    _assert_contained(root, candidate.parent)
    return candidate


def _assert_contained(root: Path, path: Path) -> None:
    try:
        boundary = Path(root).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise OwnershipError("supplied root is not a safe directory") from exc
    cursor = path
    while not cursor.exists() and not cursor.is_symlink():
        if cursor == cursor.parent:
            raise OwnershipError("rooted path escapes supplied root")
        cursor = cursor.parent
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(boundary)
    except (OSError, RuntimeError, ValueError) as exc:
        raise OwnershipError("rooted path escapes supplied root") from exc


def _checkpoint_data(value: object, adapter: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        value = getattr(value, "data", None)
    if not isinstance(value, Mapping):
        raise TransactionError(
            f"adapter returned an invalid checkpoint: {adapter}"
        )
    return _freeze_mapping(value)


def _evidence_to_dict(evidence: Evidence) -> dict[str, object]:
    return {
        "action_id": evidence.action_id,
        "details": _thaw(evidence.details),
        "observations": list(evidence.observations),
        "success": evidence.success,
    }


def _plan_from_dict(value: object) -> InstallPlan:
    if not isinstance(value, Mapping):
        raise TransactionError("transaction plan is invalid")
    required = {
        "actions",
        "adapter_dependencies",
        "adapter_order",
        "audit_facts",
        "config",
        "release",
        "schema",
    }
    if set(value) != required:
        raise TransactionError("transaction plan is invalid")
    facts = value["audit_facts"]
    release = value["release"]
    actions = value["actions"]
    dependencies = value["adapter_dependencies"]
    if (
        not isinstance(facts, Mapping)
        or not isinstance(release, Mapping)
        or not isinstance(actions, list)
        or not isinstance(dependencies, Mapping)
    ):
        raise TransactionError("transaction plan is invalid")
    try:
        return InstallPlan(
            actions=tuple(Action(**item) for item in actions),
            adapter_dependencies={
                name: tuple(requires) for name, requires in dependencies.items()
            },
            adapter_order=tuple(value["adapter_order"]),
            config=value["config"],
            facts=AuditFacts(
                platform=facts.get("platform", {}),
                listeners=facts.get("listeners", {}),
                ownership=facts.get("ownership", {}),
                topology=facts.get("topology", {}),
                prerequisites=facts.get("prerequisites", {}),
            ),
            release=ReleaseIdentity(**release),
            schema=value["schema"],
        )
    except (KeyError, TypeError, ValueError, PlanError) as exc:
        raise TransactionError("transaction plan is invalid") from exc


def _freeze_mapping(value: Mapping[str, object]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("value must be a mapping")
    return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            _thaw(value),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as exc:
        raise TransactionError("transaction contains a non-JSON value") from exc


def _pretty_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                _thaw(value),
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode()
    except (TypeError, ValueError) as exc:
        raise TransactionError("transaction contains a non-JSON value") from exc


__all__ = [
    "AcceptedDigestError",
    "OwnershipError",
    "RuntimeV2Adapter",
    "TransactionBusyError",
    "TransactionCheckpoint",
    "TransactionEngine",
    "TransactionError",
    "TransactionState",
    "TransactionStore",
    "atomic_write",
    "durable_copy2",
    "durable_mkdir",
    "durable_remove",
    "durable_symlink",
    "ensure_parent",
    "fsync_directory",
    "fsync_file",
    "fsync_tree",
    "import_runtime_v2",
    "operation_lock",
    "sha256",
    "validate_legacy_runtime_v2",
]
