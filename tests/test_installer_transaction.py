from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest

from installer.planner import Action, AuditFacts, Evidence, InstallPlan, ReleaseIdentity
from installer.transaction import (
    AcceptedDigestError,
    OwnershipError,
    TransactionEngine,
    TransactionState,
    TransactionStore,
    import_runtime_v2,
)


class InjectedCrash(BaseException):
    pass


@dataclass
class RecordingAdapter:
    name: str
    root: Path
    crash_after: str | None = None
    fail_apply: bool = False
    log: list[str] | None = None
    requires: frozenset[str] = frozenset()

    @property
    def target(self) -> Path:
        return self.root / f"{self.name}.owned"

    @property
    def counter(self) -> Path:
        return self.root / f"{self.name}.mutations"

    def apply(self, action: Action) -> dict[str, object]:
        if self.log is not None:
            self.log.append(f"apply:{self.name}")
        if self.fail_apply:
            raise RuntimeError(f"{self.name} failed")
        count = int(self.counter.read_text()) if self.counter.exists() else 0
        self.counter.write_text(str(count + 1))
        self.target.write_bytes(f"owned by {action.owner}\n".encode())
        return {"owned_paths": [f"/{self.target.name}"]}

    def verify(self, action: Action) -> Evidence:
        return Evidence(
            action_id=action.id,
            success=self.target.read_bytes() == f"owned by {action.owner}\n".encode(),
            observations=("owned file verified",),
        )

    def rollback(self, action: Action, checkpoint: dict[str, object]) -> Evidence:
        assert checkpoint["owned_paths"] == [f"/{self.target.name}"]
        if self.log is not None:
            self.log.append(f"rollback:{self.name}")
        self.target.unlink(missing_ok=True)
        return Evidence(
            action_id=action.id,
            success=True,
            observations=("owned file removed",),
        )

    def checkpoint_committed(self, phase: str, action: Action) -> None:
        del action
        if phase == self.crash_after:
            self.crash_after = None
            raise InjectedCrash(phase)


def action_for(name: str) -> Action:
    return Action(
        id=f"{name}.install",
        adapter=name,
        owner=f"proxy-control:{name}",
        mutations=(f"write /{name}.owned",),
        preconditions=(f"/{name}.owned is absent",),
        verification=(f"/{name}.owned has the approved content",),
        inverse=(f"remove /{name}.owned",),
        credentials_required=False,
    )


def plan_for(*names: str) -> InstallPlan:
    actions = tuple(action_for(name) for name in names)
    return InstallPlan(
        config={"profile": "test"},
        facts=AuditFacts(platform={"os": "test"}),
        release=ReleaseIdentity(
            tag="v1.2.3",
            commit="a" * 40,
            manifest_sha256="b" * 64,
        ),
        adapter_order=tuple(names),
        adapter_dependencies={name: () for name in names},
        actions=actions,
    )


def engine_for(root: Path, *adapters: RecordingAdapter) -> TransactionEngine:
    return TransactionEngine(
        TransactionStore(root),
        {adapter.name: adapter for adapter in adapters},
    )


@pytest.mark.parametrize("crash_after", ["prepared", "applied", "verified"])
def test_resume_after_each_checkpoint_does_not_repeat_committed_mutation(
    tmp_path: Path,
    crash_after: str,
) -> None:
    adapter = RecordingAdapter("core", tmp_path, crash_after=crash_after)
    plan = plan_for("core")
    with pytest.raises(InjectedCrash, match=crash_after):
        engine_for(tmp_path, adapter).apply(plan, accepted_digest=plan.digest)

    recovered = engine_for(tmp_path, RecordingAdapter("core", tmp_path)).resume()

    assert recovered.status == "active"
    assert adapter.counter.read_text() == "1"


def test_applied_state_is_durable_before_derived_ownership_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = RecordingAdapter("core", tmp_path)
    plan = plan_for("core")
    store = TransactionStore(tmp_path)
    write_ownership = store.write_ownership

    def crash_before_derived_journal(ownership: dict[str, object]) -> None:
        if ownership:
            raise InjectedCrash("ownership")
        write_ownership(ownership)

    monkeypatch.setattr(store, "write_ownership", crash_before_derived_journal)
    with pytest.raises(InjectedCrash, match="ownership"):
        TransactionEngine(store, {"core": adapter}).apply(
            plan,
            accepted_digest=plan.digest,
        )

    recovered = engine_for(tmp_path, RecordingAdapter("core", tmp_path)).resume()

    assert recovered.status == "active"
    assert adapter.counter.read_text() == "1"


def test_rollback_refuses_foreign_drift_before_deletion(tmp_path: Path) -> None:
    adapter = RecordingAdapter("core", tmp_path)
    plan = plan_for("core")
    engine = engine_for(tmp_path, adapter)
    engine.apply(plan, accepted_digest=plan.digest)
    adapter.target.write_text("foreign edit")

    with pytest.raises(OwnershipError, match="owned file drifted"):
        engine.uninstall(purge_data=False)

    assert adapter.target.read_text() == "foreign edit"


def test_normal_failure_rolls_back_committed_actions_in_reverse_order(tmp_path: Path) -> None:
    log: list[str] = []
    first = RecordingAdapter("first", tmp_path, log=log)
    second = RecordingAdapter("second", tmp_path, log=log)
    third = RecordingAdapter("third", tmp_path, fail_apply=True, log=log)
    plan = plan_for("first", "second", "third")

    with pytest.raises(RuntimeError, match="third failed"):
        engine_for(tmp_path, first, second, third).apply(
            plan,
            accepted_digest=plan.digest,
        )

    assert log == [
        "apply:first",
        "apply:second",
        "apply:third",
        "rollback:second",
        "rollback:first",
    ]
    assert not first.target.exists()
    assert not second.target.exists()


def test_store_uses_private_directory_and_file_permissions(tmp_path: Path) -> None:
    adapter = RecordingAdapter("core", tmp_path)
    plan = plan_for("core")
    store = TransactionStore(tmp_path)

    TransactionEngine(store, {"core": adapter}).apply(
        plan,
        accepted_digest=plan.digest,
    )

    for directory in (store.directory, store.backups_path, store.credentials_path):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for path in (
        store.state_path,
        store.plan_path,
        store.ownership_path,
        store.report_path,
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_apply_requires_the_complete_accepted_plan_digest(tmp_path: Path) -> None:
    adapter = RecordingAdapter("core", tmp_path)
    plan = plan_for("core")
    store = TransactionStore(tmp_path)

    with pytest.raises(AcceptedDigestError, match="accepted plan digest does not match"):
        TransactionEngine(store, {"core": adapter}).apply(
            plan,
            accepted_digest=plan.digest[:12],
        )

    assert not adapter.target.exists()
    assert not store.state_path.exists()


def test_repair_refuses_owned_file_drift_before_adapter_verification(tmp_path: Path) -> None:
    adapter = RecordingAdapter("core", tmp_path)
    plan = plan_for("core")
    engine = engine_for(tmp_path, adapter)
    engine.apply(plan, accepted_digest=plan.digest)
    adapter.target.write_text("foreign edit")

    with pytest.raises(OwnershipError, match="owned file drifted"):
        engine.repair()


def test_runtime_v2_import_is_explicit_and_preserves_managed_bytes(tmp_path: Path) -> None:
    credentials = tmp_path / "opt/mtproxy-shared443/secrets/users.conf"
    nginx_route = tmp_path / "etc/nginx/stream.d/routes.conf"
    nginx_site = tmp_path / "etc/nginx/sites-available/proxy-control-panel.conf"
    compose_data = tmp_path / "var/lib/docker/volumes/proxy-data/_data/panel.sqlite3"
    fixtures = {
        credentials: b"alice=0123456789abcdef0123456789abcdef\n",
        nginx_route: b"map $ssl_preread_server_name $upstream { default 127.0.0.1:8443; }\n",
        nginx_site: b"server { listen 127.0.0.1:8443 ssl; }\n",
        compose_data: b"SQLite format 3\x00legacy-data",
    }
    for path, content in fixtures.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    before = {path: path.read_bytes() for path in fixtures}
    legacy = {
        "schema": 2,
        "status": "active",
        "phase": "route_installed",
        "plan": {"project_dir": "/opt/mtproxy-shared443"},
        "owned_packages": ["docker.io"],
        "managed_files": ["/etc/nginx/sites-available/proxy-control-panel.conf"],
        "managed_hashes": {
            "/etc/nginx/sites-available/proxy-control-panel.conf": hashlib.sha256(
                fixtures[nginx_site]
            ).hexdigest(),
        },
        "project_created": True,
    }

    state = import_runtime_v2(tmp_path, legacy)

    assert isinstance(state, TransactionState)
    assert state.status == "active"
    assert state.origin == "runtime-v2"
    assert {path: path.read_bytes() for path in fixtures} == before
    assert json.loads(json.dumps(state.to_dict()))["origin"] == "runtime-v2"


def test_runtime_v2_import_rejects_managed_file_drift_without_writing(tmp_path: Path) -> None:
    managed = tmp_path / "etc/nginx/sites-available/proxy-control-panel.conf"
    managed.parent.mkdir(parents=True)
    managed.write_bytes(b"foreign")
    legacy = {
        "schema": 2,
        "status": "active",
        "phase": "route_installed",
        "plan": {"project_dir": "/opt/mtproxy-shared443"},
        "owned_packages": [],
        "managed_files": ["/etc/nginx/sites-available/proxy-control-panel.conf"],
        "managed_hashes": {
            "/etc/nginx/sites-available/proxy-control-panel.conf": "0" * 64,
        },
        "project_created": False,
    }
    before = managed.read_bytes()

    with pytest.raises(OwnershipError, match="legacy managed file drifted"):
        import_runtime_v2(tmp_path, legacy)

    assert managed.read_bytes() == before
