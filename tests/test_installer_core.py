from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from installer.adapters.core import (
    AcceptanceError,
    CoreAcceptance,
    CoreAdapter,
    CoreError,
    CorePaths,
)
from installer.model import (
    DomainConfig,
    FirewallConfig,
    HostMode,
    InstallerConfig,
    Profile,
    ThreeXuiConfig,
    ThreeXuiMode,
)
from installer.planner import (
    Action,
    AuditFacts,
    Evidence,
    InstallPlan,
    ReleaseIdentity,
)
from installer.transaction import TransactionEngine, TransactionStore


ROOT = Path(__file__).parents[1]


def config() -> InstallerConfig:
    return InstallerConfig(
        schema=1,
        host_mode=HostMode.FRESH,
        profile=Profile.CORE,
        acme_email="ops@example.com",
        initial_user="owner",
        domains=DomainConfig(panel="panel.example.com", mtproxy="proxy.example.com"),
        mieru=None,
        three_xui=ThreeXuiConfig(mode=ThreeXuiMode.NONE),
        firewall=FirewallConfig(manage_ufw=False),
    )


def core_action() -> Action:
    return CoreAdapter(source_dir=ROOT).plan(config(), AuditFacts())[0]


class FakeRunner:
    def __init__(
        self,
        *,
        respq: bool = True,
        panel_health: bool = True,
        panel_login: bool = True,
        adjacent_sni: bool = True,
        sensitive_scan: bool = True,
        api_internal: bool = True,
        fail_on: tuple[str, ...] | None = None,
    ) -> None:
        self.respq = respq
        self.panel_health = panel_health
        self.panel_login = panel_login
        self.adjacent_sni = adjacent_sni
        self.sensitive_scan = sensitive_scan
        self.api_internal = api_internal
        self.fail_on = fail_on
        self.calls: list[tuple[tuple[str, ...], str | None]] = []
        self.compose_present = False
        self.volumes_present = False
        self.probe_present = False
        self.temporary_present = False
        self.cleanup_calls = 0

    def run(self, argv, *, stdin_path=None, env=None):
        del env
        command = tuple(str(value) for value in argv)
        self.calls.append((command, str(stdin_path) if stdin_path else None))
        if self.fail_on and command[: len(self.fail_on)] == self.fail_on:
            raise RuntimeError("injected failure")
        if command[-2:] == ("up", "--wait") or "up" in command:
            self.compose_present = True
            self.volumes_present = True
        if "down" in command:
            self.compose_present = False
            if "--volumes" in command:
                self.volumes_present = False
        if command and command[-1].endswith("probe/install.sh"):
            self.probe_present = True

    def compose_project_present(self, _project_dir):
        return self.compose_present

    def compose_project_volumes_present(self, _project_dir):
        return self.volumes_present

    def core_acceptance(self, **_kwargs):
        self.temporary_present = True
        return {
            "compose_config_ok": True,
            "healthy_services": 3,
            "expected_services": 3,
            "panel_health_ok": self.panel_health,
            "panel_login_ok": self.panel_login,
            "telemt_api_internal": self.api_internal,
            "respq_verified": 1 if self.respq else 0,
            "respq_expected": 1,
            "adjacent_sni_ok": self.adjacent_sni,
            "sensitive_scan_ok": self.sensitive_scan,
        }

    def cleanup_core_acceptance(self, **_kwargs):
        self.cleanup_calls += 1
        self.temporary_present = False


def test_core_render_uses_secret_files_and_internal_telemt_api(tmp_path):
    rendered = CoreAdapter(root=tmp_path, source_dir=ROOT).render(core_action())

    assert rendered.compose_yaml.startswith("name: mtproxy\n")
    assert "9091:" not in rendered.compose_yaml
    assert rendered.mode("secrets/users.conf") == 0o600
    assert rendered.mode("secrets/telemt-api-token") == 0o600
    assert "Bearer " not in rendered.env_text
    assert "token" not in rendered.env_text.casefold()


def test_core_render_is_deterministic_and_plan_owns_pinned_probe(tmp_path):
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT)
    action = core_action()

    assert adapter.render(action) == adapter.render(action)
    assert any("prebuilt-tdlib=0.1008066.0" in item for item in action.mutations)
    assert any("/usr/local/libexec/mtproxy-respq-probe" in item for item in action.mutations)


def test_core_apply_preserves_modes_and_secrets_on_replay(tmp_path):
    runner = FakeRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    checkpoint = adapter.prepare(action)

    applied = adapter.apply(action, checkpoint)
    users = tmp_path / "opt/mtproxy-shared443/secrets/users.conf"
    token = tmp_path / "opt/mtproxy-shared443/secrets/telemt-api-token"
    before = users.read_bytes(), token.read_bytes()
    replayed = adapter.reconcile_apply(action, checkpoint)

    assert before == (users.read_bytes(), token.read_bytes())
    assert stat.S_IMODE(users.stat().st_mode) == 0o600
    assert stat.S_IMODE(token.stat().st_mode) == 0o600
    assert applied["ownership"] == replayed["ownership"]
    install_calls = [call for call, _stdin in runner.calls if call and call[-1].endswith("probe/install.sh")]
    assert len(install_calls) == 1


def test_core_refuses_foreign_project_but_adopts_legacy_credentials(tmp_path):
    project = tmp_path / "opt/mtproxy-shared443"
    project.mkdir(parents=True)
    (project / "compose.yaml").write_text("foreign\n")
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=FakeRunner())
    with pytest.raises(CoreError, match="pre-existing project"):
        adapter.prepare(core_action())

    (project / "compose.yaml").unlink()
    (project / ".mtproxy-owned").write_text("legacy-marker\n")
    (project / ".mtproxy-owned").chmod(0o600)
    secrets = project / "secrets"
    secrets.mkdir()
    secrets.chmod(0o700)
    users = secrets / "users.conf"
    users.write_text("owner=" + "a" * 32 + "\n")
    users.chmod(0o600)
    token = secrets / "telemt-api-token"
    token.write_text("Bearer " + "b" * 48 + "\n")
    token.chmod(0o600)

    checkpoint = adapter.prepare(core_action())
    adapter.apply(core_action(), checkpoint)
    assert users.read_text() == "owner=" + "a" * 32 + "\n"
    assert token.read_text() == "Bearer " + "b" * 48 + "\n"


def test_core_rollback_and_uninstall_preserve_data_unless_purged(tmp_path):
    runner = FakeRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    applied = adapter.apply(action, adapter.prepare(action))
    users = tmp_path / "opt/mtproxy-shared443/secrets/users.conf"
    original = users.read_bytes()

    evidence = adapter.rollback(action, applied, purge_data=False, rollback_target="uninstalled")
    assert isinstance(evidence, Evidence) and evidence.success
    assert users.read_bytes() == original
    assert runner.volumes_present

    # Reinstall then explicitly purge persistent Compose volumes. Reconciliation
    # observes absence and does not repeat the destructive mutation.
    applied = adapter.apply(action, adapter.prepare(action))
    adapter.rollback(action, applied, purge_data=True, rollback_target="uninstalled")
    adapter.reconcile_rollback(action, applied, purge_data=True, rollback_target="uninstalled")
    purge = [call for call, _stdin in runner.calls if "down" in call and "--volumes" in call]
    assert len(purge) == 1
    assert not runner.volumes_present


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"respq": False}, "resPQ"),
        ({"panel_health": False}, "panel health"),
        ({"panel_login": False}, "panel login"),
        ({"api_internal": False}, "Telemt API isolation"),
        ({"adjacent_sni": False}, "adjacent SNI"),
        ({"sensitive_scan": False}, "sensitive scan"),
    ],
)
def test_core_acceptance_fails_closed_and_always_cleans_temporary_state(
    tmp_path, overrides, message
):
    runner = FakeRunner(**overrides)
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    adapter.apply(action, adapter.prepare(action))

    with pytest.raises(AcceptanceError, match=message):
        adapter.verify(action)

    assert runner.cleanup_calls == 1
    assert not runner.temporary_present



def test_core_acceptance_cleans_temporary_state_before_propagating_crash(tmp_path):
    class CrashRunner(FakeRunner):
        def core_acceptance(self, **_kwargs):
            self.temporary_present = True
            raise SystemExit("injected crash")

    runner = CrashRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    adapter.apply(action, adapter.prepare(action))

    with pytest.raises(SystemExit, match="injected crash"):
        adapter.verify(action)

    assert runner.cleanup_calls == 1
    assert not runner.temporary_present

def test_core_acceptance_returns_only_sanitized_counts_and_booleans(tmp_path):
    runner = FakeRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    adapter.apply(action, adapter.prepare(action))

    evidence = adapter.verify(action)
    payload = json.dumps(dict(evidence.details), sort_keys=True)

    assert evidence.success
    assert set(evidence.details) == {
        "adjacent_sni_ok",
        "compose_config_ok",
        "expected_services",
        "healthy_services",
        "panel_health_ok",
        "panel_login_ok",
        "respq_expected",
        "respq_verified",
        "sensitive_scan_ok",
        "telemt_api_internal",
        "temporary_state_removed",
    }
    assert "Bearer " not in payload
    assert "tg://" not in payload
    assert runner.cleanup_calls == 1


def test_acceptance_dataclass_rejects_inconsistent_counts():
    with pytest.raises(ValueError, match="counts"):
        CoreAcceptance(
            compose_config_ok=True,
            healthy_services=4,
            expected_services=3,
            panel_health_ok=True,
            panel_login_ok=True,
            telemt_api_internal=True,
            respq_verified=1,
            respq_expected=1,
            adjacent_sni_ok=True,
            sensitive_scan_ok=True,
        )


def test_core_paths_keep_fixed_project_and_probe_locations():
    paths = CorePaths()
    assert paths.project_dir == "/opt/mtproxy-shared443"
    assert paths.probe_path == "/usr/local/libexec/mtproxy-respq-probe"


def test_core_runs_through_transaction_apply_repair_and_uninstall(tmp_path):
    runner = FakeRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    release_digest = "a" * 64
    plan = InstallPlan(
        config=config().canonical_dict(),
        facts=AuditFacts(),
        release=ReleaseIdentity(
            tag="v-test",
            commit="b" * 40,
            manifest_sha256=release_digest,
        ),
        adapter_order=("core",),
        adapter_dependencies={"core": ()},
        actions=(action,),
    )
    engine = TransactionEngine(TransactionStore(tmp_path), {"core": adapter})

    applied = engine.apply(plan, accepted_digest=plan.digest)
    repaired = engine.repair()
    removed = engine.uninstall(purge_data=False)

    assert applied.status == repaired.status == "active"
    assert removed.status == "uninstalled"
    assert runner.cleanup_calls == 3
    assert runner.volumes_present
