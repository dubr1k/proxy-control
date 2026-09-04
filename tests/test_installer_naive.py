from __future__ import annotations

import importlib.util
import stat
from pathlib import Path

import pytest

from installer.adapters.naive import (
    _ACCOUNTING_GID,
    _CADDY_UID,
    _CADDY_VERSION,
    AcceptanceError,
    NaiveAcceptance,
    NaiveAdapter,
    NaiveError,
    NaivePaths,
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
from installer.planner import Action, AuditFacts, PlanError


ROOT = Path(__file__).parents[1]
PATHS = NaivePaths()


def full_config(profile: Profile = Profile.CORE_NAIVE) -> InstallerConfig:
    return InstallerConfig(
        schema=1,
        host_mode=HostMode.FRESH,
        profile=profile,
        acme_email="ops@example.com",
        initial_user="owner",
        domains=DomainConfig(
            panel="panel.example.com",
            mtproxy="proxy.example.com",
            naive="naive.example.com",
        ),
        mieru=None,
        three_xui=ThreeXuiConfig(mode=ThreeXuiMode.NONE),
        firewall=FirewallConfig(manage_ufw=False),
    )


def facts_with_uid(identifier: int, name: str) -> AuditFacts:
    kind = "uid" if identifier < _ACCOUNTING_GID else "gid"
    return AuditFacts(ownership={"identities": {kind: {str(identifier): name}}})


def naive_action() -> Action:
    return NaiveAdapter(source_dir=ROOT).plan(full_config(), AuditFacts())[0]


class FakeNaiveRunner:
    def __init__(
        self,
        *,
        admin: bool = True,
        private: bool = True,
        cover: bool = True,
        connect_bytes: int = 4096,
        recorded_bytes: int | None = None,
        tunnel_closed: bool = True,
        manager_health: bool = True,
        panel_health: bool = True,
        adjacent: bool = True,
        log_boundary: bool = True,
        caddy_version: str = _CADDY_VERSION,
        forward_proxy: bool = True,
        identities: dict[tuple[str, int], str] | None = None,
        cleanup_fails: bool = False,
        fail_on: tuple[str, ...] | None = None,
    ) -> None:
        self.admin = admin
        self.private = private
        self.cover = cover
        self.connect_bytes = connect_bytes
        self.recorded_bytes = (
            connect_bytes if recorded_bytes is None else recorded_bytes
        )
        self.tunnel_closed = tunnel_closed
        self.manager_health = manager_health
        self.panel_health = panel_health
        self.adjacent = adjacent
        self.log_boundary = log_boundary
        self.caddy_version = caddy_version
        self.forward_proxy = forward_proxy
        self.identities = dict(identities or {})
        self.cleanup_fails = cleanup_fails
        self.fail_on = fail_on
        self.calls: list[tuple[str, ...]] = []
        self.compose_present = False
        self.unit_enabled = False
        self.built = False
        self.cleanup_calls = 0
        self.acceptance_names: list[str] = []

    # -- command boundary ------------------------------------------------

    def run(self, argv, *, stdin_path=None):
        del stdin_path
        command = tuple(str(value) for value in argv)
        self.calls.append(command)
        if self.fail_on and command[: len(self.fail_on)] == self.fail_on:
            raise RuntimeError("injected failure")
        if command[:1] == ("groupadd",):
            self.identities[("gid", _ACCOUNTING_GID)] = command[-1]
        if command[:1] == ("useradd",):
            self.identities[("uid", _CADDY_UID)] = command[-1]
        if command[:1] == ("groupdel",):
            self.identities.pop(("gid", _ACCOUNTING_GID), None)
        if command[:1] == ("userdel",):
            self.identities.pop(("uid", _CADDY_UID), None)
        if command[:2] == ("systemctl", "enable"):
            self.unit_enabled = True
        if command[:2] == ("systemctl", "disable"):
            self.unit_enabled = False
        if "up" in command:
            self.compose_present = True
        if "rm" in command and "--stop" in command:
            self.compose_present = False

    def identity_owner(self, kind, identifier):
        return self.identities.get((kind, identifier))

    def build_caddy(self, source_dir, destination):
        del source_dir
        Path(destination).write_bytes(b"pinned-caddy\n")
        self.built = True

    def caddy_identity(self, binary):
        del binary
        return self.caddy_version, self.forward_proxy

    def loopback_listener(self, port):
        return self.admin if port == 2019 else self.private

    def compose_project_present(self, _project_dir):
        return self.compose_present

    # -- acceptance ------------------------------------------------------

    def naive_acceptance(self, **kwargs):
        self.acceptance_names.append(kwargs["acceptance_name"])
        return {
            "admin_api_loopback": self.admin,
            "private_listener_ok": self.private,
            "cover_https_ok": self.cover,
            "authenticated_connect_ok": self.connect_bytes > 0,
            "tunnel_closed_ok": self.tunnel_closed,
            "connect_bytes": self.connect_bytes,
            "recorded_bytes": self.recorded_bytes,
            "manager_health_ok": self.manager_health,
            "panel_health_ok": self.panel_health,
            "adjacent_sni_ok": self.adjacent,
            "log_boundary_ok": self.log_boundary,
        }

    def cleanup_naive_acceptance(self, **kwargs):
        del kwargs
        self.cleanup_calls += 1
        if self.cleanup_fails:
            raise RuntimeError("cleanup unavailable")


def adapter(tmp_path: Path, runner: FakeNaiveRunner | None = None) -> NaiveAdapter:
    return NaiveAdapter(
        root=tmp_path,
        source_dir=ROOT,
        runner=runner or FakeNaiveRunner(),
    )


def applied(instance: NaiveAdapter, action: Action):
    return instance.apply(action, instance.prepare(action))


def host(tmp_path: Path, absolute: str) -> Path:
    return tmp_path / absolute.lstrip("/")


# ----------------------------------------------------------------------
# planning
# ----------------------------------------------------------------------


def test_naive_plan_stops_on_fixed_identity_collision():
    facts = facts_with_uid(10003, "foreign-service")
    with pytest.raises(PlanError, match="UID 10003 collision"):
        NaiveAdapter(source_dir=ROOT).plan(full_config(), facts)


def test_naive_plan_stops_on_fixed_accounting_group_collision():
    facts = facts_with_uid(10004, "foreign-group")
    with pytest.raises(PlanError, match="GID 10004 collision"):
        NaiveAdapter(source_dir=ROOT).plan(full_config(), facts)


def test_naive_plan_adopts_its_own_reserved_identities():
    facts = facts_with_uid(10003, "naive-caddy")
    assert NaiveAdapter(source_dir=ROOT).plan(full_config(), facts)


def test_naive_plan_is_empty_without_the_naive_profile():
    assert NaiveAdapter(source_dir=ROOT).plan(full_config(Profile.CORE), AuditFacts()) == ()


def test_naive_plan_requires_an_explicit_public_domain():
    config = full_config()
    broken = InstallerConfig(
        **{
            **{
                field: getattr(config, field)
                for field in config.__dataclass_fields__
            },
            "domains": DomainConfig(
                panel="panel.example.com",
                mtproxy="proxy.example.com",
            ),
        }
    )
    with pytest.raises(PlanError, match="Naive public domain"):
        NaiveAdapter(source_dir=ROOT).plan(broken, AuditFacts())


def test_naive_plan_action_is_secret_free_and_pins_the_build():
    action = naive_action()
    assert action.id == "naive.runtime"
    assert f"caddy-build={_CADDY_VERSION}" in action.mutations
    assert "private-port=4443" in action.mutations
    assert action.credentials_required is True


def test_naive_plan_keeps_only_audited_adjacent_routes():
    facts = AuditFacts(
        topology={
            "nginx": {
                "sni_routes": {
                    "naive.example.com": "127.0.0.1:4443",
                    "panel.example.com": "127.0.0.1:8787",
                    "other.example.com": "127.0.0.1:9443",
                }
            }
        }
    )
    action = NaiveAdapter(source_dir=ROOT).plan(full_config(), facts)[0]
    assert "adjacent-sni=other.example.com|127.0.0.1:9443" in action.mutations


# ----------------------------------------------------------------------
# rendering
# ----------------------------------------------------------------------


def test_naive_render_stages_a_private_listener_without_managed_markers():
    rendered = NaiveAdapter(source_dir=ROOT).render(naive_action())
    assert "admin 127.0.0.1:2019" in rendered.caddyfile_template
    assert "bind 127.0.0.1" in rendered.caddyfile_template
    assert "NAIVE-MANAGER USERS" not in rendered.caddyfile_template
    assert rendered.caddyfile_template.count("forward_proxy {") == 1
    assert "__PROXY_CONTROL_BOOTSTRAP_PASSWORD__" in rendered.caddyfile_template
    assert rendered.mode(PATHS.manager_token) == 0o400
    assert rendered.mode(PATHS.caddyfile) == 0o640
    assert rendered.mode(PATHS.secret_token) == 0o600
    assert "NAIVE_PUBLIC_HOST=naive.example.com" in rendered.env_text
    assert "password" not in rendered.env_text


# ----------------------------------------------------------------------
# acceptance
# ----------------------------------------------------------------------


def test_naive_acceptance_requires_closed_connect_accounting(tmp_path):
    runner = FakeNaiveRunner(connect_bytes=4096, recorded_bytes=0)
    instance = adapter(tmp_path, runner)
    action = naive_action()
    applied(instance, action)
    with pytest.raises(AcceptanceError, match="accounting"):
        instance.verify(action)


@pytest.mark.parametrize(
    ("keyword", "options"),
    (
        ("loopback listeners", {"admin": False}),
        ("loopback listeners", {"private": False}),
        ("cover HTTPS", {"cover": False}),
        ("authenticated CONNECT", {"connect_bytes": 0}),
        ("tunnel close", {"tunnel_closed": False}),
        ("manager and panel health", {"manager_health": False}),
        ("manager and panel health", {"panel_health": False}),
        ("adjacent SNI", {"adjacent": False}),
        ("accounting log boundary", {"log_boundary": False}),
    ),
)
def test_naive_acceptance_requires_every_end_to_end_fact(tmp_path, keyword, options):
    runner = FakeNaiveRunner(**options)
    instance = adapter(tmp_path, runner)
    action = naive_action()
    if options.get("admin") is False or options.get("private") is False:
        # A private listener that never came up fails before acceptance runs.
        with pytest.raises(NaiveError, match="loopback"):
            applied(instance, action)
        return
    applied(instance, action)
    with pytest.raises(AcceptanceError, match=keyword):
        instance.verify(action)


def test_naive_verify_removes_temporary_state_and_reports_sanitized_facts(tmp_path):
    runner = FakeNaiveRunner()
    instance = adapter(tmp_path, runner)
    action = naive_action()
    applied(instance, action)

    evidence = instance.verify(action)

    assert evidence.success
    assert runner.cleanup_calls == 1
    assert evidence.details["temporary_state_removed"] is True
    assert not host(tmp_path, PATHS.acceptance_pending).exists()
    assert all("password" not in key for key in evidence.details)


def test_naive_verify_refuses_a_drifted_temporary_owner(tmp_path):
    instance = adapter(tmp_path)
    action = naive_action()
    applied(instance, action)
    pending = host(tmp_path, PATHS.acceptance_pending)
    pending.write_text("proxy-control-naive-0000000000000000\n")
    pending.chmod(0o600)

    with pytest.raises(NaiveError, match="temporary-user ownership"):
        instance.verify(action)


def test_naive_acceptance_result_rejects_unknown_fields(tmp_path):
    instance = adapter(tmp_path)
    action = naive_action()
    applied(instance, action)
    instance.runner.naive_acceptance = lambda **_kwargs: {"surprise": True}

    with pytest.raises(AcceptanceError, match="acceptance result is invalid"):
        instance.verify(action)


def test_naive_acceptance_counts_must_be_non_negative():
    with pytest.raises(ValueError):
        NaiveAcceptance(
            admin_api_loopback=True,
            private_listener_ok=True,
            cover_https_ok=True,
            authenticated_connect_ok=True,
            tunnel_closed_ok=True,
            connect_bytes=-1,
            recorded_bytes=0,
            manager_health_ok=True,
            panel_health_ok=True,
            adjacent_sni_ok=True,
            log_boundary_ok=True,
        )


# ----------------------------------------------------------------------
# apply
# ----------------------------------------------------------------------


def test_naive_apply_orders_artifact_identities_bootstrap_and_overlay(tmp_path):
    runner = FakeNaiveRunner()
    instance = adapter(tmp_path, runner)

    applied(instance, naive_action())

    order = [" ".join(command) for command in runner.calls]
    def index(fragment: str) -> int:
        return next(i for i, value in enumerate(order) if fragment in value)

    assert runner.built
    assert index("groupadd") < index("useradd")
    assert index("useradd") < index("prepare-naive-state")
    assert index("prepare-naive-state") < index("systemctl enable")
    assert index("systemctl enable") < index("--bootstrap-only")
    assert index("--bootstrap-only") < index("systemctl reload")
    assert index("systemctl reload") < index("up -d --build --wait")


def test_naive_apply_installs_root_owned_helpers_and_pin(tmp_path):
    instance = adapter(tmp_path)

    applied(instance, naive_action())

    for host_path, mode in (
        (PATHS.checker, 0o755),
        (PATHS.adapt_script, 0o755),
        (PATHS.state_preparer, 0o755),
        (PATHS.unit, 0o644),
        (PATHS.deploy_hook, 0o755),
    ):
        path = host(tmp_path, host_path)
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == mode
    assert host(tmp_path, PATHS.pin).read_text().strip() == _CADDY_VERSION


def test_naive_apply_writes_credentials_outside_the_plan(tmp_path):
    instance = adapter(tmp_path)

    applied(instance, naive_action())

    secret = host(tmp_path, PATHS.secret_token)
    copy = host(tmp_path, PATHS.manager_token)
    caddyfile = host(tmp_path, PATHS.caddyfile)
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    assert stat.S_IMODE(copy.stat().st_mode) == 0o400
    assert secret.read_text() == copy.read_text()
    assert stat.S_IMODE(caddyfile.stat().st_mode) == 0o640
    assert "__PROXY_CONTROL_BOOTSTRAP_PASSWORD__" not in caddyfile.read_text()
    assert "NAIVE-MANAGER USERS" not in caddyfile.read_text()


def test_naive_apply_preserves_restored_credentials(tmp_path):
    instance = adapter(tmp_path)
    action = naive_action()
    applied(instance, action)
    original = host(tmp_path, PATHS.caddyfile).read_text()
    token = host(tmp_path, PATHS.secret_token).read_text()

    second = adapter(tmp_path, FakeNaiveRunner())
    applied(second, action)

    assert host(tmp_path, PATHS.caddyfile).read_text() == original
    assert host(tmp_path, PATHS.secret_token).read_text() == token


def test_naive_apply_refuses_an_unpinned_caddy_build(tmp_path):
    runner = FakeNaiveRunner(caddy_version="v2.10.0 h1:other")
    instance = adapter(tmp_path, runner)

    with pytest.raises(NaiveError, match="unpinned Caddy"):
        applied(instance, naive_action())


def test_naive_apply_refuses_a_build_without_forward_proxy(tmp_path):
    runner = FakeNaiveRunner(forward_proxy=False)
    instance = adapter(tmp_path, runner)

    with pytest.raises(NaiveError, match="unpinned Caddy"):
        applied(instance, naive_action())


def test_naive_prepare_refuses_a_live_identity_collision(tmp_path):
    runner = FakeNaiveRunner(identities={("uid", _CADDY_UID): "foreign-service"})
    instance = adapter(tmp_path, runner)

    with pytest.raises(NaiveError, match="UID 10003 collision"):
        instance.prepare(naive_action())


def test_naive_prepare_refuses_absent_adoption_with_active_resources(tmp_path):
    runner = FakeNaiveRunner()
    runner.compose_present = True
    instance = adapter(tmp_path, runner)

    with pytest.raises(NaiveError, match="active Naive resources"):
        instance.prepare(naive_action())


def test_naive_prepare_adopts_only_a_proven_owned_marker(tmp_path):
    instance = adapter(tmp_path)
    action = naive_action()
    applied(instance, action)

    checkpoint = instance.prepare(action)
    assert checkpoint["adoption"] == "recovery"
    assert checkpoint["marker_value"] is None

    marker = host(tmp_path, PATHS.marker)
    marker.chmod(0o644)
    with pytest.raises(NaiveError, match="ownership has drifted"):
        instance.prepare(action)


def test_naive_checkpoint_rejects_foreign_fields(tmp_path):
    instance = adapter(tmp_path)
    action = naive_action()
    checkpoint = dict(instance.prepare(action))
    checkpoint["surprise"] = True

    with pytest.raises(NaiveError, match="checkpoint is invalid"):
        instance.apply(action, checkpoint)


# ----------------------------------------------------------------------
# repair and rollback
# ----------------------------------------------------------------------


def test_naive_repair_detects_owned_drift(tmp_path):
    instance = adapter(tmp_path)
    action = naive_action()
    checkpoint = applied(instance, action)
    host(tmp_path, PATHS.pin).write_text("v0.0.0 h1:tampered\n")

    with pytest.raises(NaiveError, match="has drifted"):
        instance.repair(action, checkpoint)


def test_naive_repair_revalidates_the_state_boundary(tmp_path):
    runner = FakeNaiveRunner(fail_on=(str(PATHS.state_preparer), "verify"))
    instance = adapter(tmp_path, runner)
    action = naive_action()
    checkpoint = applied(instance, action)

    with pytest.raises(NaiveError, match="command failed|injected"):
        instance.repair(action, checkpoint)


def test_naive_rollback_preserves_state_and_credentials(tmp_path):
    runner = FakeNaiveRunner()
    instance = adapter(tmp_path, runner)
    action = naive_action()
    checkpoint = applied(instance, action)

    evidence = instance.rollback(action, checkpoint)

    assert evidence.success
    assert evidence.details["persistent_data_preserved"] is True
    assert host(tmp_path, PATHS.secret_token).is_file()
    assert host(tmp_path, PATHS.manager_token).is_file()
    assert host(tmp_path, PATHS.caddyfile).is_file()
    assert host(tmp_path, PATHS.marker).is_file()
    assert not host(tmp_path, PATHS.unit).exists()
    assert not host(tmp_path, PATHS.pin).exists()
    assert not host(tmp_path, PATHS.caddy_binary).exists()
    assert runner.unit_enabled is False
    assert runner.compose_present is False
    assert ("uid", _CADDY_UID) in runner.identities


def test_naive_explicit_purge_removes_state_and_owned_identities(tmp_path):
    runner = FakeNaiveRunner()
    instance = adapter(tmp_path, runner)
    action = naive_action()
    checkpoint = applied(instance, action)

    evidence = instance.rollback(
        action,
        checkpoint,
        purge_data=True,
        rollback_target="uninstalled",
    )

    assert evidence.details["persistent_data_preserved"] is False
    assert not host(tmp_path, PATHS.secret_token).exists()
    assert not host(tmp_path, PATHS.manager_token).exists()
    assert not host(tmp_path, PATHS.caddyfile).exists()
    assert not host(tmp_path, PATHS.marker).exists()
    assert ("uid", _CADDY_UID) not in runner.identities
    assert ("gid", _ACCOUNTING_GID) not in runner.identities


def test_naive_rollback_keeps_a_preexisting_caddy_binary(tmp_path):
    binary = host(tmp_path, PATHS.caddy_binary)
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"operator-caddy\n")
    instance = adapter(tmp_path)
    action = naive_action()
    checkpoint = applied(instance, action)

    instance.rollback(action, checkpoint)

    assert binary.read_bytes() == b"operator-caddy\n"


def test_naive_rollback_cleanup_failure_remains_retryable(tmp_path):
    runner = FakeNaiveRunner(cleanup_fails=True)
    instance = adapter(tmp_path, runner)
    action = naive_action()
    checkpoint = applied(instance, action)
    pending = host(tmp_path, PATHS.acceptance_pending)
    pending.write_text(str(checkpoint["acceptance_name"]) + "\n")
    pending.chmod(0o600)

    with pytest.raises(NaiveError, match="cleanup"):
        instance.rollback(action, checkpoint)

    assert pending.is_file()
    assert host(tmp_path, PATHS.acceptance_owner).is_file()

    runner.cleanup_fails = False
    instance.rollback(action, checkpoint)
    assert not pending.exists()


def test_naive_purge_discards_a_failed_temporary_cleanup(tmp_path):
    runner = FakeNaiveRunner(cleanup_fails=True)
    instance = adapter(tmp_path, runner)
    action = naive_action()
    checkpoint = applied(instance, action)
    pending = host(tmp_path, PATHS.acceptance_pending)
    pending.write_text(str(checkpoint["acceptance_name"]) + "\n")
    pending.chmod(0o600)

    evidence = instance.rollback(
        action,
        checkpoint,
        purge_data=True,
        rollback_target="uninstalled",
    )

    assert evidence.success
    assert not pending.exists()


def test_naive_rollback_rejects_an_unknown_target(tmp_path):
    instance = adapter(tmp_path)
    action = naive_action()
    checkpoint = applied(instance, action)

    with pytest.raises(ValueError):
        instance.rollback(action, checkpoint, rollback_target="deleted")


# ----------------------------------------------------------------------
# state preparer
# ----------------------------------------------------------------------


def _preparer():
    spec = importlib.util.spec_from_file_location(
        "prepare_naive_state",
        ROOT / "scripts/prepare-naive-state.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_state_preparer_refuses_unnormalized_and_relative_paths():
    module = _preparer()
    for value in ("relative/path", "/", "/var/lib/../etc", "/var/lib/naive/"):
        with pytest.raises(module.StateError):
            module._normalized(value, "state directory")
    assert module._normalized("/var/lib/naive-manager", "state directory") == Path(
        "/var/lib/naive-manager"
    )


def test_state_preparer_refuses_a_symlinked_boundary(tmp_path):
    module = _preparer()
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(module.StateError, match="symlink"):
        module._assert_safe_parents(link, "state directory")


@pytest.mark.skipif(
    __import__("os").geteuid() == 0,
    reason="the non-root refusal is only observable unprivileged",
)
def test_state_preparer_requires_root():
    module = _preparer()
    assert module.main(["prepare", "--state-dir", "/var/lib/naive-manager"]) == 1
