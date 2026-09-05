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
    _DefaultCoreRunner,
    _AcceptanceCollision,
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
        compose_health: bool = True,
        image_id: str | None = None,
        image_compatible: bool = True,
        cleanup_fails: bool = False,
        fail_on: tuple[str, ...] | None = None,
    ) -> None:
        self.respq = respq
        self.panel_health = panel_health
        self.panel_login = panel_login
        self.adjacent_sni = adjacent_sni
        self.sensitive_scan = sensitive_scan
        self.api_internal = api_internal
        self.compose_health = compose_health
        self.image_id = image_id
        self.image_compatible = image_compatible
        self.cleanup_fails = cleanup_fails
        self.fail_on = fail_on
        self.calls: list[tuple[tuple[str, ...], str | None]] = []
        self.compose_present = False
        self.volumes_present = False
        self.probe_present = False
        self.temporary_present = False
        self.cleanup_calls = 0
        self.acceptance_names: list[str] = []
        self.image_owner: str | None = None

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
        if any(value.endswith("probe/install.sh") for value in command):
            self.probe_present = True
            self.image_id = "sha256:created-probe-image"
            owner_index = command.index("--owner-id") + 1
            self.image_owner = command[owner_index]
        if command[:3] == ("docker", "image", "rm"):
            self.image_owner = None
            self.image_id = None

    def compose_project_present(self, _project_dir):
        return self.compose_present

    def compose_project_volumes_present(self, _project_dir):
        return self.volumes_present

    def probe_image_identity(self, _image):
        return self.image_id

    def core_acceptance(self, **kwargs):
        self.temporary_present = True
        self.acceptance_names.append(kwargs["acceptance_name"])
        expected = kwargs["configured_credentials"] + 1
        return {
            "compose_config_ok": True,
            "healthy_services": 3 if self.compose_health else 0,
            "expected_services": 3,
            "panel_health_ok": self.panel_health,
            "panel_login_ok": self.panel_login,
            "telemt_api_internal": self.api_internal,
            "respq_verified": expected if self.respq else expected - 1,
            "respq_expected": expected,
            "adjacent_sni_ok": self.adjacent_sni,
            "sensitive_scan_ok": self.sensitive_scan,
        }

    def probe_image_compatible(self, _image):
        return self.image_compatible

    def probe_image_owner(self, _image):
        return self.image_owner

    def cleanup_core_acceptance(self, **_kwargs):
        self.cleanup_calls += 1
        if self.cleanup_fails:
            raise RuntimeError("cleanup failed")
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
    install_calls = [call for call, _stdin in runner.calls if any(value.endswith("probe/install.sh") for value in call)]
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
        ({"compose_health": False}, "Compose health checks"),
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
    assert runner.cleanup_calls == 2


def test_automatic_rollback_never_purges_volumes_or_credentials(tmp_path):
    runner = FakeRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    applied = adapter.apply(action, adapter.prepare(action))
    users = tmp_path / "opt/mtproxy-shared443/secrets/users.conf"
    before = users.read_bytes()

    adapter.rollback(action, applied, purge_data=True, rollback_target="rolled_back")

    assert users.read_bytes() == before
    assert runner.volumes_present
    assert not any("--volumes" in call for call, _stdin in runner.calls)


def test_rollback_cleanup_failure_is_recorded_without_blocking_rollback(tmp_path):
    runner = FakeRunner(cleanup_fails=True)
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    checkpoint = adapter.prepare(action)
    pending = tmp_path / "opt/mtproxy-shared443/.core-acceptance-pending"
    pending.parent.mkdir(parents=True)
    pending.write_text(str(checkpoint["acceptance_name"]) + "\n")
    pending.chmod(0o600)

    evidence = adapter.rollback(
        action,
        checkpoint,
        purge_data=False,
        rollback_target="rolled_back",
    )

    # The rollback completes - an unreachable runtime must never trap the host
    # in a half-installed state - and records the pending cleanup instead.
    assert evidence.success
    assert evidence.details["temporary_cleanup_pending"] is True
    assert pending.is_file()
    assert (tmp_path / "opt/mtproxy-shared443/.core-acceptance-owner").is_file()
    assert runner.cleanup_calls == 1


def test_rollback_preserves_foreign_project_additions(tmp_path):
    runner = FakeRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    applied = adapter.apply(action, adapter.prepare(action))
    foreign = tmp_path / "opt/mtproxy-shared443/operator-note.txt"
    foreign.write_text("preserve me\n")

    adapter.rollback(action, applied, rollback_target="uninstalled")

    assert foreign.read_text() == "preserve me\n"


def test_explicit_uninstall_purge_removes_credentials_marker_and_empty_project(tmp_path):
    runner = FakeRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    applied = adapter.apply(action, adapter.prepare(action))

    evidence = adapter.rollback(
        action,
        applied,
        purge_data=True,
        rollback_target="uninstalled",
    )

    assert evidence.details["persistent_data_preserved"] is False
    assert not (tmp_path / "opt/mtproxy-shared443").exists()
    assert not runner.volumes_present


def test_preexisting_identical_probe_and_image_are_preserved(tmp_path):
    probe = tmp_path / "usr/local/libexec/mtproxy-respq-probe"
    probe.parent.mkdir(parents=True)
    probe.write_bytes((ROOT / "probe/mtproxy-respq-probe").read_bytes())
    probe.chmod(0o750)
    runner = FakeRunner(image_id="sha256:preexisting")
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()

    checkpoint = adapter.prepare(action)
    applied = adapter.apply(action, checkpoint)
    adapter.rollback(action, applied, rollback_target="uninstalled")

    assert probe.is_file()
    assert runner.image_id == "sha256:preexisting"


def test_applying_checkpoint_removes_only_probe_and_image_created_after_prepare(tmp_path):
    runner = FakeRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    checkpoint = adapter.prepare(action)
    probe = tmp_path / "usr/local/libexec/mtproxy-respq-probe"
    probe.parent.mkdir(parents=True)
    probe.write_bytes((ROOT / "probe/mtproxy-respq-probe").read_bytes())
    probe.chmod(0o750)
    runner.image_id = "sha256:created-probe-image"
    runner.image_owner = str(checkpoint["probe_image_owner"])

    adapter.reconcile_rollback(
        action,
        checkpoint,
        rollback_target="rolled_back",
    )

    assert not probe.exists()
    assert runner.image_id is None


def test_plan_persists_audited_adjacent_sni_routes():
    facts = AuditFacts(
        topology={
            "nginx": {
                "sni_routes": {
                    "vpn.example.com": "127.0.0.1:10443",
                    "proxy.example.com": "127.0.0.1:9999",
                }
            }
        }
    )

    action = CoreAdapter(source_dir=ROOT).plan(config(), facts)[0]

    assert "adjacent-sni=vpn.example.com|127.0.0.1:10443" in action.mutations
    assert not any("9999" in mutation for mutation in action.mutations)


def test_acceptance_uses_transaction_unique_name_and_all_configured_credentials(tmp_path):
    runner = FakeRunner()
    adapter = CoreAdapter(
        root=tmp_path,
        source_dir=ROOT,
        runner=runner,
        users=("owner", "phone"),
    )
    action = adapter.plan(config(), AuditFacts())[0]
    applied = adapter.apply(action, adapter.prepare(action))

    evidence = adapter.verify(action)

    assert runner.acceptance_names[0].startswith("pc-acceptance-")
    # The panel caps a username at 32 characters.
    assert len(runner.acceptance_names[0]) <= 32
    assert evidence.details["respq_expected"] == 3
    assert evidence.details["respq_verified"] == 3
    assert applied["acceptance_name"] in runner.acceptance_names


def test_verification_fails_when_final_temporary_cleanup_fails(tmp_path):
    runner = FakeRunner(cleanup_fails=True)
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    adapter.apply(action, adapter.prepare(action))

    with pytest.raises(AcceptanceError, match="cleanup"):
        adapter.verify(action)


def test_default_runner_rejects_running_but_unhealthy_compose_service(monkeypatch):
    runner = _DefaultCoreRunner()
    output = json.dumps(
        [
            {"Service": "mask", "State": "running", "Health": "healthy"},
            {"Service": "mtproxy", "State": "running", "Health": "unhealthy"},
            {"Service": "panel", "State": "running", "Health": "healthy"},
        ]
    )
    monkeypatch.setattr(runner, "_capture_checked", lambda _argv: output)

    with pytest.raises(AcceptanceError, match="Compose health checks"):
        runner._healthy_compose_services(("docker", "compose"))


def test_default_runner_accepts_the_adjacent_protocol_services(monkeypatch):
    """A repair re-verifies Core while Naive and Mieru run in the same shared
    project, so their services must not read as a failed health check."""
    runner = _DefaultCoreRunner()
    healthy = [
        {"Service": name, "State": "running", "Health": "healthy"}
        for name in ("mask", "mtproxy", "panel", "naive-manager", "mieru-manager")
    ]
    monkeypatch.setattr(runner, "_capture_checked", lambda _argv: json.dumps(healthy))
    assert runner._healthy_compose_services(("docker", "compose")) == 3

    foreign = healthy + [
        {"Service": "someone-elses", "State": "running", "Health": "healthy"}
    ]
    monkeypatch.setattr(runner, "_capture_checked", lambda _argv: json.dumps(foreign))
    with pytest.raises(AcceptanceError, match="Compose health checks"):
        runner._healthy_compose_services(("docker", "compose"))

    missing = [row for row in healthy if row["Service"] != "panel"]
    monkeypatch.setattr(runner, "_capture_checked", lambda _argv: json.dumps(missing))
    with pytest.raises(AcceptanceError, match="Compose health checks"):
        runner._healthy_compose_services(("docker", "compose"))


def test_prepare_refuses_unlabeled_preexisting_probe_image(tmp_path):
    runner = FakeRunner(
        image_id="sha256:foreign",
        image_compatible=False,
    )
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)

    with pytest.raises(CoreError, match="not safely adoptable"):
        adapter.prepare(core_action())


def test_preexisting_unowned_acceptance_collision_is_not_deleted(tmp_path):
    class CollisionRunner(FakeRunner):
        def core_acceptance(self, **_kwargs):
            raise _AcceptanceCollision(
                "Core acceptance failed: temporary-user collision"
            )

    runner = CollisionRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    adapter.apply(action, adapter.prepare(action))

    with pytest.raises(AcceptanceError, match="collision"):
        adapter.verify(action)

    assert runner.cleanup_calls == 0


def test_applying_rollback_removes_matching_generation_only(tmp_path):
    project = "/opt/mtproxy-shared443"
    runner = FakeRunner(
        fail_on=(
            "docker",
            "compose",
            "--project-directory",
            project,
            "config",
        )
    )
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    checkpoint = adapter.prepare(action)

    with pytest.raises(RuntimeError, match="injected failure"):
        adapter.apply(action, checkpoint)
    project_path = tmp_path / project.lstrip("/")
    foreign = project_path / "operator-note.txt"
    foreign.write_text("preserve me\n")

    adapter.rollback(action, checkpoint, rollback_target="rolled_back")

    assert not (project_path / "compose.yaml").exists()
    assert (project_path / "secrets/users.conf").is_file()
    assert (project_path / ".mtproxy-owned").is_file()
    assert not (tmp_path / "var/www/proxy.example.com/index.html").exists()
    assert not (tmp_path / "var/www/panel.example.com/index.html").exists()
    assert foreign.read_text() == "preserve me\n"


def test_compose_presence_query_uses_only_fixed_project_labels(monkeypatch):
    runner = _DefaultCoreRunner()
    calls: list[tuple[str, ...]] = []

    def capture(argv):
        calls.append(tuple(argv))
        return "container-id\n" if argv[:3] == ("docker", "container", "ls") else ""

    monkeypatch.setattr(runner, "_capture_checked", capture)

    assert runner.compose_project_present("/missing/project")
    assert all("compose" not in call for call in calls)
    assert all("/missing/project" not in call for call in calls)


def test_failed_rollback_cleanup_retains_tombstone_until_later_success(tmp_path):
    runner = FakeRunner(cleanup_fails=True)
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    applied = adapter.apply(action, adapter.prepare(action))
    project = tmp_path / "opt/mtproxy-shared443"
    pending = project / ".core-acceptance-pending"
    pending.write_text(str(applied["acceptance_name"]) + "\n")
    pending.chmod(0o600)

    evidence = adapter.rollback(action, applied, rollback_target="rolled_back")

    # The generation is gone, but the tombstone survives so the pending
    # temporary user is retried instead of forgotten.
    assert evidence.success
    assert evidence.details["temporary_cleanup_pending"] is True
    assert pending.is_file()
    assert (project / ".core-acceptance-owner").is_file()

    runner.cleanup_fails = False
    adapter.reconcile_rollback(action, applied, rollback_target="rolled_back")
    assert not pending.exists()
    assert not (project / ".core-acceptance-owner").exists()
    assert not runner.compose_present


def test_preexisting_probe_requires_owned_metadata_and_is_repair_checked(tmp_path):
    probe = tmp_path / "usr/local/libexec/mtproxy-respq-probe"
    probe.parent.mkdir(parents=True)
    probe.write_bytes((ROOT / "probe/mtproxy-respq-probe").read_bytes())
    probe.chmod(0o755)
    runner = FakeRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()

    with pytest.raises(CoreError, match="metadata"):
        adapter.prepare(action)

    probe.chmod(0o750)
    applied = adapter.apply(action, adapter.prepare(action))
    entry = applied["ownership"]["/usr/local/libexec/mtproxy-respq-probe"]
    assert entry["preserve"] is True

    probe.chmod(0o755)
    with pytest.raises(CoreError, match="probe"):
        adapter.repair(action, applied)


def test_adjacent_sni_mapping_must_still_match_audited_backend(monkeypatch):
    runner = _DefaultCoreRunner()
    effective = """
stream {
    map $ssl_preread_server_name $backend {
        vpn.example.com 127.0.0.1:10443;
        default 127.0.0.1:8443;
    }
    server {
        listen 443;
        ssl_preread on;
        proxy_pass $backend;
    }
}
"""
    monkeypatch.setattr(runner, "_capture_effective_nginx", lambda: effective)

    with pytest.raises(AcceptanceError, match="adjacent SNI mapping"):
        runner._verify_adjacent_routes(
            (("vpn.example.com", "127.0.0.1:11443"),)
        )


@pytest.mark.parametrize(
    ("relative", "mode"),
    [
        ("secrets", 0o755),
        ("secrets/users.conf", 0o644),
        ("secrets/telemt-api-token", 0o644),
        ("secrets/panel-bootstrap-password", 0o644),
    ],
)
def test_repair_revalidates_credential_metadata(tmp_path, relative, mode):
    runner = FakeRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    applied = adapter.apply(action, adapter.prepare(action))
    target = tmp_path / "opt/mtproxy-shared443" / relative
    target.chmod(mode)

    with pytest.raises(CoreError, match="credentials"):
        adapter.repair(action, applied)


def test_absent_filesystem_adoption_refuses_active_fixed_label_resources(tmp_path):
    runner = FakeRunner()
    runner.compose_present = True
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)

    with pytest.raises(CoreError, match="active mtproxy"):
        adapter.prepare(core_action())

    runner.compose_present = False
    runner.volumes_present = True
    checkpoint = adapter.prepare(core_action())
    assert checkpoint["adoption"] == "absent"


def test_explicit_purge_can_discard_failed_temporary_cleanup(tmp_path):
    runner = FakeRunner(cleanup_fails=True)
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()
    applied = adapter.apply(action, adapter.prepare(action))
    pending = tmp_path / "opt/mtproxy-shared443/.core-acceptance-pending"
    pending.write_text(str(applied["acceptance_name"]) + "\n")
    pending.chmod(0o600)

    evidence = adapter.rollback(
        action,
        applied,
        purge_data=True,
        rollback_target="uninstalled",
    )

    assert evidence.success
    assert not pending.exists()
    assert not runner.volumes_present


def test_core_owns_the_panel_tls_listener_the_router_forwards_to(tmp_path):
    """The shared 443 router forwards raw TLS; the panel speaks plain HTTP."""
    from installer.adapters.core import _PANEL_TLS_PORT, _PANEL_VHOST

    runner = FakeRunner()
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    action = core_action()

    rendered = adapter.render(action)
    assert f"listen 127.0.0.1:{_PANEL_TLS_PORT} ssl" in rendered.panel_vhost
    assert "server_name panel.example.com" in rendered.panel_vhost
    assert "proxy_pass http://127.0.0.1:8787" in rendered.panel_vhost
    assert "/etc/letsencrypt/live/proxy.example.com/fullchain.pem" in (
        rendered.panel_vhost
    )
    assert rendered.mode(_PANEL_VHOST) == 0o644

    checkpoint = adapter.apply(action, adapter.prepare(action))

    vhost = tmp_path / _PANEL_VHOST.lstrip("/")
    assert vhost.read_text() == rendered.panel_vhost
    assert stat.S_IMODE(vhost.stat().st_mode) == 0o644
    assert _PANEL_VHOST in checkpoint["ownership"]
    # Nginx is validated and reloaded so the listener actually exists.
    joined = [" ".join(call) for call, _ in runner.calls]
    assert any("nginx -t" in call for call in joined)
    assert any("systemctl reload nginx" in call for call in joined)

    adapter.rollback(action, checkpoint)
    assert not vhost.exists()


def test_core_refuses_an_occupied_panel_vhost_path(tmp_path):
    from installer.adapters.core import _PANEL_VHOST

    occupied = tmp_path / _PANEL_VHOST.lstrip("/")
    occupied.parent.mkdir(parents=True)
    occupied.symlink_to(tmp_path / "elsewhere")
    adapter = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=FakeRunner())
    action = core_action()

    with pytest.raises(CoreError, match="panel TLS vhost"):
        adapter.apply(action, adapter.prepare(action))


def test_adjacent_handshake_reads_the_report_not_the_exit_status(monkeypatch):
    """openssl exits non-zero after a verified handshake; the report decides."""
    import subprocess as sp

    from installer.adapters.core import _DefaultCoreRunner

    runner = _DefaultCoreRunner()
    calls: list[tuple[str, ...]] = []

    def fake_run(argv, **kwargs):
        calls.append(tuple(argv))
        assert kwargs["stdin"] is sp.DEVNULL
        return sp.CompletedProcess(
            argv,
            1,
            "Verification: OK\nVerified peername: old.example.com\n",
            "",
        )

    monkeypatch.setattr(sp, "run", fake_run)
    assert runner.verified_adjacent_handshake("old.example.com") is True
    assert "-verify_return_error" in calls[0]

    monkeypatch.setattr(
        sp,
        "run",
        lambda argv, **kwargs: sp.CompletedProcess(argv, 0, "Verification error\n", ""),
    )
    assert runner.verified_adjacent_handshake("old.example.com") is False

    monkeypatch.setattr(
        sp,
        "run",
        lambda argv, **kwargs: sp.CompletedProcess(
            argv, 0, "Verification: OK\nVerified peername: other.example.com\n", ""
        ),
    )
    assert runner.verified_adjacent_handshake("old.example.com") is False


def test_the_project_directory_carries_every_compose_overlay(tmp_path):
    """Naive and Mieru run Compose from the project, so the overlays live there."""
    instance = CoreAdapter(root=tmp_path, source_dir=ROOT, runner=FakeRunner())
    action = core_action()

    instance.apply(action, instance.prepare(action))

    project = tmp_path / "opt/mtproxy-shared443"
    for name in ("compose.yaml", "compose.naive.yaml", "compose.mieru.yaml"):
        assert (project / name).is_file(), name
        assert (project / name).read_bytes() == (ROOT / name).read_bytes()
    # The overlays build their managers from this same context.
    for directory in ("naive_manager", "mieru_manager", "panel"):
        assert (project / directory / "Dockerfile").is_file(), directory


def test_panel_client_accepts_a_full_reveal_payload():
    """A reveal carries per-client configs and base64 SVG QR images, so the
    acceptance client must not reject it as an oversized response."""
    import io

    from installer.adapters.core import _MAX_RESPONSE_BYTES

    body = json.dumps({"proxy_url": "https://u:p@naive.example.com", "pad": "x" * 300_000}).encode()
    assert len(body) > 65536

    class _Response(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            self.close()
            return False

    class _Opener:
        def open(self, _request, timeout=None):
            return _Response(body)

    revealed = _DefaultCoreRunner._json_request(
        _Opener(), "panel.example.com", "/api/reveal/token"
    )
    assert revealed["proxy_url"] == "https://u:p@naive.example.com"

    oversized = json.dumps({"pad": "x" * (_MAX_RESPONSE_BYTES + 10)}).encode()

    class _HugeOpener:
        def open(self, _request, timeout=None):
            return _Response(oversized)

    with pytest.raises(AcceptanceError, match="too large"):
        _DefaultCoreRunner._json_request(
            _HugeOpener(), "panel.example.com", "/api/reveal/token"
        )


def test_core_tolerates_the_naive_compose_secret_in_the_shared_project(tmp_path):
    """Naive owns its manager token inside the shared project's secrets
    directory, so Core must not read it as foreign residue."""
    from installer.adapters.core import _ADJACENT_CREDENTIALS, _PRESERVED_CREDENTIALS

    instance = CoreAdapter(root=tmp_path, source_dir=ROOT)
    secrets = tmp_path / "opt/mtproxy-shared443/secrets"
    secrets.mkdir(parents=True)
    secrets.chmod(0o700)
    written = {
        "users.conf": "acceptance=" + "0" * 32 + "\n",
        "telemt-api-token": "Bearer " + "a" * 43 + "\n",
        "panel-bootstrap-password": "bootstrap-password\n",
        **{Path(value).name: "0" * 64 + "\n" for value in _ADJACENT_CREDENTIALS},
    }
    for name, body in written.items():
        path = secrets / name
        path.write_text(body)
        path.chmod(0o600)

    instance._validate_existing_credentials(secrets, require_all=True)

    (secrets / "unexpected").write_text("residue\n")
    with pytest.raises(CoreError, match="credentials are unsafe"):
        instance._validate_existing_credentials(secrets, require_all=True)

    (secrets / "unexpected").unlink()
    (secrets / Path(_PRESERVED_CREDENTIALS[0]).name).unlink()
    with pytest.raises(CoreError, match="credentials are unsafe"):
        instance._validate_existing_credentials(secrets, require_all=True)
