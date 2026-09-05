from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest
import installer.transaction as transaction_module

from installer.planner import Action, AuditFacts, Evidence, InstallPlan, ReleaseIdentity
from installer.transaction import (
    AcceptedDigestError,
    OwnershipError,
    TransactionEngine,
    TransactionError,
    TransactionState,
    RuntimeV2Adapter,
    TransactionStore,
    TransactionBusyError,
    import_runtime_v2,
)
from scripts.proxyctl import InstallerConflict, RuntimeInstaller, RuntimePlan


class InjectedCrash(BaseException):
    pass


@dataclass
class RecordingAdapter:
    name: str
    root: Path
    crash_after: str | None = None
    fail_apply: bool = False
    crash_during_apply: type[BaseException] | None = None
    crash_during_rollback: type[BaseException] | None = None
    crash_before_rollback: bool = False
    preserve_data: bool = False
    mutable_data: bool = False
    log: list[str] | None = None
    requires: frozenset[str] = frozenset()

    @property
    def target(self) -> Path:
        return self.root / f"{self.name}.owned"

    @property
    def data_path(self) -> Path:
        return self.root / f"{self.name}.data"

    @property
    def counter(self) -> Path:
        return self.root / f"{self.name}.mutations"

    def prepare(self, action: Action) -> dict[str, object]:
        ownership: dict[str, object] = {
            f"/{self.target.name}": {"preserve": False},
        }
        if self.preserve_data:
            ownership[f"/{self.data_path.name}"] = {
                "preserve": True,
                "mutable": self.mutable_data,
            }
        return {"ownership": ownership, "owner": action.owner}

    def apply(
        self,
        action: Action,
        checkpoint: dict[str, object],
    ) -> dict[str, object]:
        if self.log is not None:
            self.log.append(f"apply:{self.name}")
        if self.fail_apply:
            raise RuntimeError(f"{self.name} failed")
        count = int(self.counter.read_text()) if self.counter.exists() else 0
        self.counter.write_text(str(count + 1))
        self.target.write_bytes(f"owned by {action.owner}\n".encode())
        if self.preserve_data:
            self.data_path.write_bytes(b"persistent data\n")
        if self.crash_during_apply is not None:
            error = self.crash_during_apply
            self.crash_during_apply = None
            raise error("apply mutation committed")
        return checkpoint

    def reconcile_apply(
        self,
        action: Action,
        checkpoint: dict[str, object],
    ) -> dict[str, object]:
        if self.target.exists():
            return checkpoint
        return self.apply(action, checkpoint)

    def repair(
        self,
        action: Action,
        checkpoint: dict[str, object],
    ) -> dict[str, object]:
        expected = f"owned by {action.owner}\n".encode()
        if self.target.exists() and self.target.read_bytes() != expected:
            raise OwnershipError("owned file drifted")
        if not self.target.exists():
            self.target.write_bytes(expected)
        if self.preserve_data:
            if (
                not self.mutable_data
                and self.data_path.exists()
                and self.data_path.read_bytes() != b"persistent data\n"
            ):
                raise OwnershipError("owned data drifted")
            if not self.data_path.exists():
                self.data_path.write_bytes(b"persistent data\n")
        return checkpoint


    def verify(self, action: Action) -> Evidence:
        valid = self.target.read_bytes() == f"owned by {action.owner}\n".encode()
        if self.preserve_data and not self.mutable_data:
            valid = valid and self.data_path.read_bytes() == b"persistent data\n"
        return Evidence(
            action_id=action.id,
            success=valid,
            observations=("owned file verified",),
        )

    def rollback(
        self,
        action: Action,
        checkpoint: dict[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        assert f"/{self.target.name}" in checkpoint["ownership"]
        assert rollback_target in {"rolled_back", "uninstalled"}
        if self.crash_before_rollback:
            self.crash_before_rollback = False
            raise InjectedCrash("before rollback deletion")
        if self.log is not None:
            self.log.append(f"rollback:{self.name}")
        self.target.unlink(missing_ok=True)
        if purge_data:
            self.data_path.unlink(missing_ok=True)
        if self.crash_during_rollback is not None:
            error = self.crash_during_rollback
            self.crash_during_rollback = None
            raise error("rollback mutation committed")
        return Evidence(
            action_id=action.id,
            success=True,
            observations=("owned file removed",),
        )

    def reconcile_rollback(
        self,
        action: Action,
        checkpoint: dict[str, object],
        *,
        purge_data: bool = False,
        rollback_target: str = "rolled_back",
    ) -> Evidence:
        if self.target.exists() or (purge_data and self.data_path.exists()):
            return self.rollback(
                action,
                checkpoint,
                purge_data=purge_data,
                rollback_target=rollback_target,
            )
        return Evidence(
            action_id=action.id,
            success=True,
            observations=("rollback already committed",),
        )

    def checkpoint_committed(self, phase: str, action: Action) -> None:
        del action
        if phase == self.crash_after:
            self.crash_after = None
            raise InjectedCrash(phase)



@dataclass
class RuntimeRunner:
    root: Path
    installed: set[str]
    crash_after: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.compose_running = False
        self.volumes_present = False

    def package_installed(self, name: str) -> bool:
        return name in self.installed

    def command_available(self, name: str) -> bool:
        del name
        return False

    def compose_available(self) -> bool:
        return False

    def compose_project_present(self, project_dir: str) -> bool:
        del project_dir
        return self.compose_running

    def compose_project_volumes_present(self, project_dir: str) -> bool:
        del project_dir
        return self.volumes_present

    def run(self, argv, *, stdin_path=None, env=None) -> None:
        del stdin_path, env
        command = tuple(str(item) for item in argv)
        self.calls.append(command)
        if command[:3] == ("apt-get", "install", "-y"):
            self.installed.update(command[3:])
        elif command[:3] == ("apt-get", "purge", "-y"):
            self.installed.difference_update(command[3:])
        if "up" in command:
            self.compose_running = True
            self.volumes_present = True
        elif "down" in command:
            self.compose_running = False
            if command[-1:] == ("--volumes",):
                self.volumes_present = False
                data = (
                    self.root
                    / "var/lib/docker/volumes/proxy-data/_data/panel.sqlite3"
                )
                data.unlink(missing_ok=True)
        if (
            self.crash_after is not None
            and command[: len(self.crash_after)] == self.crash_after
        ):
            self.crash_after = None
            raise InjectedCrash("after command success")

    def capture(self, argv, *, max_chars: int) -> str:
        del argv, max_chars
        return ""


def installed_runtime_v2(root: Path) -> tuple[dict[str, object], RuntimeRunner, bytes]:
    route = root / "etc/nginx/stream.d/routes.conf"
    route.parent.mkdir(parents=True)
    (root / "etc/nginx/sites-enabled").mkdir(parents=True)
    (root / "etc/nginx/nginx.conf").write_text(
        "events {}\nhttp { include /etc/nginx/sites-enabled/*; }\n"
        "stream { include /etc/nginx/stream.d/*.conf; }\n"
    )
    original = (
        "map $ssl_preread_server_name $upstream_443 {\n"
        "    default 127.0.0.1:9443;\n}\n"
        "server { listen 443; ssl_preread on; proxy_pass $upstream_443; }\n"
    ).encode()
    route.write_bytes(original)
    runtime_plan = RuntimePlan(
        proxy_domain="proxy.example.com",
        panel_domain="panel.example.com",
        email="ops@example.com",
        route_file="/etc/nginx/stream.d/routes.conf",
        source_dir=str(Path(__file__).parents[1]),
        protocol_probe="/bin/true",
    )
    runner = RuntimeRunner(root, {"ca-certificates", "python3"})
    RuntimeInstaller(runtime_plan, root=root, runner=runner).install()
    legacy = json.loads(
        (root / "var/lib/proxy-control/runtime.json").read_text()
    )
    return legacy, runner, original



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


def test_resume_reconciles_process_death_after_adapter_mutation(tmp_path: Path) -> None:
    adapter = RecordingAdapter(
        "core",
        tmp_path,
        crash_during_apply=InjectedCrash,
    )
    plan = plan_for("core")

    with pytest.raises(InjectedCrash, match="apply mutation committed"):
        engine_for(tmp_path, adapter).apply(plan, accepted_digest=plan.digest)

    state = TransactionStore(tmp_path).read_state()
    assert state.checkpoints[-1].phase == "applying"
    recovered = engine_for(tmp_path, RecordingAdapter("core", tmp_path)).resume()
    assert recovered.status == "active"
    assert adapter.counter.read_text() == "1"


def test_normal_exception_after_adapter_mutation_rolls_it_back(tmp_path: Path) -> None:
    adapter = RecordingAdapter(
        "core",
        tmp_path,
        crash_during_apply=RuntimeError,
    )
    plan = plan_for("core")

    with pytest.raises(RuntimeError, match="apply mutation committed"):
        engine_for(tmp_path, adapter).apply(plan, accepted_digest=plan.digest)

    assert not adapter.target.exists()
    assert TransactionStore(tmp_path).read_state().status == "rolled_back"


@pytest.mark.parametrize("failure", [InjectedCrash, RuntimeError])
def test_resume_reconciles_death_or_error_after_destructive_rollback(
    tmp_path: Path,
    failure: type[BaseException],
) -> None:
    adapter = RecordingAdapter("core", tmp_path)
    plan = plan_for("core")
    engine = engine_for(tmp_path, adapter)
    engine.apply(plan, accepted_digest=plan.digest)
    adapter.crash_during_rollback = failure

    with pytest.raises(failure, match="rollback mutation committed"):
        engine.uninstall(purge_data=False)

    recovered = engine_for(tmp_path, RecordingAdapter("core", tmp_path)).resume()
    assert recovered.status == "uninstalled"
    assert not adapter.target.exists()


def test_rollback_reconciliation_refuses_foreign_edit_before_deletion(
    tmp_path: Path,
) -> None:
    adapter = RecordingAdapter("core", tmp_path)
    plan = plan_for("core")
    engine = engine_for(tmp_path, adapter)
    engine.apply(plan, accepted_digest=plan.digest)
    adapter.crash_before_rollback = True
    with pytest.raises(InjectedCrash, match="before rollback deletion"):
        engine.uninstall(purge_data=False)
    adapter.target.write_text("foreign edit")

    with pytest.raises(OwnershipError, match="owned file drifted"):
        engine_for(tmp_path, RecordingAdapter("core", tmp_path)).resume()

    assert adapter.target.read_text() == "foreign edit"


@pytest.mark.parametrize("purge_data", [False, True])
def test_uninstall_routes_persisted_data_policy_to_adapter(
    tmp_path: Path,
    purge_data: bool,
) -> None:
    adapter = RecordingAdapter("core", tmp_path, preserve_data=True)
    plan = plan_for("core")
    engine = engine_for(tmp_path, adapter)
    engine.apply(plan, accepted_digest=plan.digest)

    state = engine.uninstall(purge_data=purge_data)

    assert state.status == "uninstalled"
    assert adapter.data_path.exists() is (not purge_data)


def test_failed_install_removes_data_even_when_uninstall_would_preserve_it(
    tmp_path: Path,
) -> None:
    first = RecordingAdapter("first", tmp_path, preserve_data=True)
    second = RecordingAdapter("second", tmp_path, fail_apply=True)
    plan = plan_for("first", "second")

    with pytest.raises(RuntimeError, match="second failed"):
        engine_for(tmp_path, first, second).apply(
            plan,
            accepted_digest=plan.digest,
        )

    assert not first.target.exists()
    assert not first.data_path.exists()


def test_terminal_resume_rebuilds_derived_journals_from_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = RecordingAdapter("core", tmp_path)
    plan = plan_for("core")
    store = TransactionStore(tmp_path)
    write_report = store.write_report

    def die_after_terminal_state(report: dict[str, object]) -> None:
        if report["status"] == "active":
            raise InjectedCrash("terminal report")
        write_report(report)

    monkeypatch.setattr(store, "write_report", die_after_terminal_state)
    with pytest.raises(InjectedCrash, match="terminal report"):
        TransactionEngine(store, {"core": adapter}).apply(
            plan,
            accepted_digest=plan.digest,
        )

    recovered_store = TransactionStore(tmp_path)
    recovered = TransactionEngine(
        recovered_store,
        {"core": RecordingAdapter("core", tmp_path)},
    ).resume()
    assert recovered.status == "active"
    assert json.loads(recovered_store.report_path.read_text())["status"] == "active"


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


def test_store_rejects_symlinked_parent_that_escapes_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "var").symlink_to(outside, target_is_directory=True)
    original_mode = stat.S_IMODE(outside.stat().st_mode)

    with pytest.raises(OwnershipError, match="escapes supplied root"):
        TransactionStore(root).initialize()

    assert stat.S_IMODE(outside.stat().st_mode) == original_mode
    assert not (outside / "lib").exists()


def test_operation_lock_rejects_final_symlink_without_chmod_or_flock(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    lock_dir = root / "run/lock"
    lock_dir.mkdir(parents=True)
    outside = tmp_path / "outside.lock"
    outside.write_text("outside")
    outside.chmod(0o644)
    (lock_dir / "proxy-control.lock").symlink_to(outside)

    with pytest.raises(OwnershipError, match="operation lock"):
        with TransactionStore(root).locked():
            pytest.fail("symlinked lock was acquired")

    assert outside.read_text() == "outside"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644


def test_operation_lock_rejects_hard_link_before_chmod_or_flock(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    lock_dir = root / "run/lock"
    lock_dir.mkdir(parents=True)
    outside = tmp_path / "outside.lock"
    outside.write_text("outside")
    outside.chmod(0o644)
    (lock_dir / "proxy-control.lock").hardlink_to(outside)

    with pytest.raises(OwnershipError, match="operation lock"):
        with TransactionStore(root).locked():
            pytest.fail("hard-linked lock was acquired")

    assert outside.read_text() == "outside"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644


def test_legacy_import_rejects_symlinked_parent_that_escapes_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    managed = outside / "nginx/proxy-control-panel.conf"
    managed.parent.mkdir(parents=True)
    managed.write_bytes(b"outside")
    (root / "etc").symlink_to(outside, target_is_directory=True)
    legacy = {
        "schema": 2,
        "status": "active",
        "phase": "route_installed",
        "plan": {"project_dir": "/opt/mtproxy-shared443"},
        "owned_packages": [],
        "managed_files": ["/etc/nginx/proxy-control-panel.conf"],
        "managed_hashes": {
            "/etc/nginx/proxy-control-panel.conf": hashlib.sha256(
                b"outside"
            ).hexdigest(),
        },
        "project_created": False,
    }

    with pytest.raises(OwnershipError, match="escapes supplied root"):
        import_runtime_v2(root, legacy)

    assert managed.read_bytes() == b"outside"


def test_legacy_import_rejects_noncanonical_managed_path(tmp_path: Path) -> None:
    managed = tmp_path / "etc/nginx.conf"
    managed.parent.mkdir(parents=True)
    managed.write_bytes(b"verified")
    legacy = {
        "schema": 2,
        "status": "active",
        "phase": "route_installed",
        "plan": {"project_dir": "/opt/mtproxy-shared443"},
        "owned_packages": [],
        "managed_files": ["/etc//nginx.conf"],
        "managed_hashes": {
            "/etc//nginx.conf": hashlib.sha256(b"verified").hexdigest(),
        },
        "project_created": False,
    }

    with pytest.raises(OwnershipError, match="canonical"):
        import_runtime_v2(tmp_path, legacy)

    assert managed.read_bytes() == b"verified"
    assert not TransactionStore(tmp_path).state_path.exists()


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


def test_a_service_rewritten_owned_file_is_not_foreign_drift(tmp_path: Path) -> None:
    """A service rewrites some installer-created files — mita's server config,
    the Naive Caddyfile — so their content must not block repair or rollback."""
    adapter = RecordingAdapter("core", tmp_path, preserve_data=True, mutable_data=True)
    plan = plan_for("core")
    engine = engine_for(tmp_path, adapter)
    engine.apply(plan, accepted_digest=plan.digest)
    adapter.data_path.write_text("rewritten by the service")

    engine.repair()

    adapter.target.write_text("foreign edit")
    with pytest.raises(OwnershipError, match="owned file drifted"):
        engine.repair()


def test_repair_refuses_owned_file_drift_before_adapter_verification(tmp_path: Path) -> None:
    adapter = RecordingAdapter("core", tmp_path)
    plan = plan_for("core")
    engine = engine_for(tmp_path, adapter)
    engine.apply(plan, accepted_digest=plan.digest)
    adapter.target.write_text("foreign edit")

    with pytest.raises(OwnershipError, match="owned file drifted"):
        engine.repair()

def test_apply_rejects_adapter_without_checkpoint_aware_repair(
    tmp_path: Path,
) -> None:
    adapter = RecordingAdapter("core", tmp_path)
    setattr(adapter, "repair", None)
    plan = plan_for("core")
    engine = engine_for(tmp_path, adapter)

    with pytest.raises(TransactionError, match="does not implement repair"):
        engine.apply(plan, accepted_digest=plan.digest)

    assert not TransactionStore(tmp_path).state_path.exists()


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
    assert TransactionStore(tmp_path).state_path.is_file()
    assert {path: path.read_bytes() for path in fixtures} == before

    assert json.loads(json.dumps(state.to_dict()))["origin"] == "runtime-v2"


@pytest.mark.parametrize("purge_data", [False, True])
def test_runtime_v2_adapter_reverses_the_complete_legacy_lifecycle(
    tmp_path: Path,
    purge_data: bool,
) -> None:
    root = tmp_path / "root"
    legacy, runner, original_route = installed_runtime_v2(root)
    credentials = root / "opt/mtproxy-shared443/secrets/users.conf"
    credential_bytes = b"keep-these-credentials\n"
    credentials.write_bytes(credential_bytes)
    compose_data = (
        root / "var/lib/docker/volumes/proxy-data/_data/panel.sqlite3"
    )
    compose_data.parent.mkdir(parents=True)
    compose_data.write_bytes(b"database")
    managed_paths = [
        root / str(path).lstrip("/")
        for path in legacy["managed_files"]
    ]

    import_runtime_v2(root, legacy)
    engine = TransactionEngine(
        TransactionStore(root),
        {"runtime-v2": RuntimeV2Adapter(root, runner=runner)},
    )
    state = engine.uninstall(purge_data=purge_data)

    assert state.status == "uninstalled"
    assert all(not path.exists() for path in managed_paths)
    assert not (root / "var/lib/proxy-control/runtime.json").exists()
    assert (
        root / "etc/nginx/stream.d/routes.conf"
    ).read_bytes() == original_route
    assert credentials.read_bytes() == credential_bytes
    assert compose_data.exists() is not purge_data
    assert not set(legacy["owned_packages"]) & runner.installed
    assert any(
        command[:3] == ("apt-get", "purge", "-y")
        for command in runner.calls
    )


@pytest.mark.parametrize(
    ("drift", "message"),
    [
        ("project", "project ownership has drifted"),
        ("package", "owned packages are missing"),
    ],
)
def test_runtime_v2_adapter_fails_closed_before_lifecycle_drift(
    tmp_path: Path,
    drift: str,
    message: str,
) -> None:
    root = tmp_path / "root"
    legacy, runner, _original_route = installed_runtime_v2(root)
    import_runtime_v2(root, legacy)
    if drift == "project":
        (root / "opt/mtproxy-shared443/.mtproxy-owned").unlink()
    else:
        runner.installed.remove(legacy["owned_packages"][0])
    calls_before = list(runner.calls)
    managed_paths = [
        root / str(path).lstrip("/")
        for path in legacy["managed_files"]
    ]

    engine = TransactionEngine(
        TransactionStore(root),
        {"runtime-v2": RuntimeV2Adapter(root, runner=runner)},
    )
    with pytest.raises(InstallerConflict, match=message):
        engine.uninstall(purge_data=False)

    assert runner.calls == calls_before
    assert all(path.exists() or path.is_symlink() for path in managed_paths)


def test_runtime_v2_import_acquires_lock_before_validation(tmp_path: Path) -> None:
    managed = tmp_path / "etc/nginx/sites-available/proxy-control-panel.conf"
    managed.parent.mkdir(parents=True)
    managed.write_bytes(b"verified")
    legacy = {
        "schema": 2,


        "status": "active",
        "phase": "route_installed",
        "plan": {"project_dir": "/opt/mtproxy-shared443"},
        "owned_packages": [],
        "managed_files": ["/etc/nginx/sites-available/proxy-control-panel.conf"],
        "managed_hashes": {
            "/etc/nginx/sites-available/proxy-control-panel.conf": hashlib.sha256(
                b"verified"
            ).hexdigest(),
        },
        "project_created": False,
    }
    store = TransactionStore(tmp_path)

    with store.locked():
        managed.write_bytes(b"foreign")
        with pytest.raises(TransactionBusyError, match="another proxyctl operation"):
            import_runtime_v2(tmp_path, legacy)


@pytest.mark.parametrize(
    ("command", "purge_data", "in_progress_phase"),
    [
        (
            (
                "docker",
                "compose",
                "--project-directory",
                "/opt/mtproxy-shared443",
                "down",
                "--remove-orphans",
            ),
            False,
            "compose_stopping",
        ),
        (
            (
                "docker",
                "compose",
                "--project-directory",
                "/opt/mtproxy-shared443",
                "down",
                "--remove-orphans",
                "--volumes",
            ),
            True,
            "data_purging",
        ),
        (("apt-get", "purge", "-y"), False, "packages_purging"),
    ],
)
def test_runtime_v2_resume_does_not_replay_committed_external_mutation(
    tmp_path: Path,
    command: tuple[str, ...],
    purge_data: bool,
    in_progress_phase: str,
) -> None:
    root = tmp_path / "root"
    legacy, runner, _original_route = installed_runtime_v2(root)
    import_runtime_v2(root, legacy)
    runner.crash_after = command
    engine = TransactionEngine(
        TransactionStore(root),
        {"runtime-v2": RuntimeV2Adapter(root, runner=runner)},
    )

    with pytest.raises(InjectedCrash, match="after command success"):
        engine.uninstall(purge_data=purge_data)

    runtime_state = json.loads(
        (root / "var/lib/proxy-control/runtime.json").read_text()
    )
    assert runtime_state["phase"] == in_progress_phase
    count_after_crash = sum(
        call[: len(command)] == command
        for call in runner.calls
    )
    assert count_after_crash == 1

    resumed = engine.resume()

    assert resumed.status == "uninstalled"
    assert sum(
        call[: len(command)] == command
        for call in runner.calls
    ) == count_after_crash


@pytest.mark.parametrize(
    ("drift", "message"),
    [
        ("marker", "project ownership has drifted"),
        ("marker_symlink", "project ownership has drifted"),
        ("package", "owned packages are missing"),
    ],
)
def test_runtime_v2_resume_revalidates_drift_before_next_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
    message: str,
) -> None:
    root = tmp_path / "root"
    legacy, runner, _original_route = installed_runtime_v2(root)
    import_runtime_v2(root, legacy)
    real_checkpoint = RuntimeInstaller._checkpoint
    crashed = False

    def crash_after_started(self, state, *, status=None, phase=None):
        nonlocal crashed
        real_checkpoint(self, state, status=status, phase=phase)
        if phase == "started" and not crashed:
            crashed = True
            raise InjectedCrash("after started checkpoint")

    monkeypatch.setattr(RuntimeInstaller, "_checkpoint", crash_after_started)
    engine = TransactionEngine(
        TransactionStore(root),
        {"runtime-v2": RuntimeV2Adapter(root, runner=runner)},
    )
    with pytest.raises(InjectedCrash, match="started checkpoint"):
        engine.uninstall(purge_data=False)

    if drift == "marker":
        marker = root / "opt/mtproxy-shared443/.mtproxy-owned"
        marker.write_bytes(b"foreign marker\n")
    elif drift == "marker_symlink":
        marker = root / "opt/mtproxy-shared443/.mtproxy-owned"
        marker.unlink()
        outside = tmp_path / "foreign-marker"
        outside.write_bytes(b"foreign marker\n")
        marker.symlink_to(outside)
    else:
        runner.installed.remove(legacy["owned_packages"][0])
    calls_before_resume = list(runner.calls)

    with pytest.raises(InstallerConflict, match=message):
        engine.resume()

    assert runner.calls == calls_before_resume


def test_runtime_v2_import_rejects_change_between_validation_and_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    managed = tmp_path / "etc/nginx/sites-available/proxy-control-panel.conf"
    managed.parent.mkdir(parents=True)
    managed.write_bytes(b"verified")
    legacy = {
        "schema": 2,
        "status": "active",
        "phase": "route_installed",
        "plan": {"project_dir": "/opt/mtproxy-shared443"},
        "owned_packages": [],
        "managed_files": ["/etc/nginx/sites-available/proxy-control-panel.conf"],
        "managed_hashes": {
            "/etc/nginx/sites-available/proxy-control-panel.conf": hashlib.sha256(
                b"verified"
            ).hexdigest(),
        },
        "project_created": False,
    }
    validate = transaction_module.validate_legacy_runtime_v2

    def mutate_after_validation(root: Path, state: dict[str, object]) -> None:
        validate(root, state)
        managed.write_bytes(b"changed after validation")

    monkeypatch.setattr(
        transaction_module,
        "validate_legacy_runtime_v2",
        mutate_after_validation,
    )

    with pytest.raises(OwnershipError, match="legacy managed file drifted"):
        import_runtime_v2(tmp_path, legacy)

    assert not TransactionStore(tmp_path).state_path.exists()


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
