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

    def compose_service_present(self, service):
        assert service == "naive-manager"
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
    # Without this the cover site answers 407 and fingerprints the tunnel.
    assert "probe_resistance" in rendered.caddyfile_template
    # A named site address would install a Host matcher, and a tunnelled
    # CONNECT carries the destination as its Host, so it would never reach
    # forward_proxy.
    assert "https://:443 {" in rendered.caddyfile_template
    assert "https://naive.example.com {" not in rendered.caddyfile_template
    assert "__PROXY_CONTROL_BOOTSTRAP_PASSWORD__" in rendered.caddyfile_template
    assert rendered.mode(PATHS.manager_token) == 0o400
    assert rendered.mode(PATHS.caddyfile) == 0o640
    assert rendered.mode(PATHS.secret_token) == 0o600
    assert "NAIVE_PUBLIC_HOST=naive.example.com" in rendered.env_text
    assert "password" not in rendered.env_text


def _file_writer_options(text: str, path: str) -> set[str]:
    """Collect the options of every `output file <path> { ... }` block."""
    options: set[str] = set()
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != f"output file {path} {{":
            continue
        for entry in lines[index + 1:]:
            if entry.strip() == "}":
                break
            options.add(entry.strip())
    return options


def test_naive_bootstrap_log_matches_the_manager_accounting_writer():
    """Caddy shares one writer per filename: mismatched options lock the
    accounting group out of the log and gzip the rotations the manager reads."""
    from naive_manager.service import NaiveCredentialManager

    rendered = NaiveAdapter(source_dir=ROOT).render(naive_action())
    bootstrap = _file_writer_options(rendered.caddyfile_template, PATHS.access_log)
    accounting = _file_writer_options(
        "\n".join(NaiveCredentialManager._accounting_lines("    ")), PATHS.access_log
    )
    assert bootstrap, "bootstrap Caddyfile must open the accounting log"
    assert accounting, "manager accounting block must open the accounting log"
    assert bootstrap == accounting
    assert "mode 0640" in bootstrap


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


def test_naive_apply_seeds_a_cover_page_without_replacing_one(tmp_path):
    instance = adapter(tmp_path)
    action = naive_action()
    applied(instance, action)
    cover = host(tmp_path, "/var/www/naive.example.com/index.html")
    assert cover.is_file()
    assert oct(cover.stat().st_mode & 0o777) == "0o644"

    cover.write_bytes(b"operator page\n")
    applied(instance, action)
    assert cover.read_bytes() == b"operator page\n"


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

    evidence = instance.rollback(action, checkpoint)

    # The rollback completes and records the pending cleanup instead of
    # trapping the host in a half-installed state.
    assert evidence.success
    assert evidence.details["temporary_cleanup_pending"] is True
    # The owner tombstone survives so a later run retries the cleanup.
    assert host(tmp_path, PATHS.acceptance_owner).is_file()

    runner.cleanup_fails = False
    evidence = instance.rollback(action, checkpoint)
    assert evidence.details["temporary_cleanup_pending"] is False
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


def test_naive_sends_every_tunnel_through_warp_when_it_is_enabled():
    """Unlike Xray, Naive has no per-domain split: WARP takes everything."""
    config = full_config()
    with_warp = InstallerConfig(
        **{
            **{
                field: getattr(config, field)
                for field in config.__dataclass_fields__
            },
            "three_xui": ThreeXuiConfig(
                mode=ThreeXuiMode.MANAGED_NEW,
                panel_domain="xui.example.com",
                vless_tcp_domain="vless.example.com",
                vless_xhttp_domain="xhttp.example.com",
                hysteria_domain="hy2.example.com",
                warp=True,
                warp_domains=("openai.com",),
            ),
        }
    )
    action = NaiveAdapter(source_dir=ROOT).plan(with_warp, AuditFacts())[0]
    assert "egress=proxy" in action.mutations

    rendered = NaiveAdapter(source_dir=ROOT).render(action)
    assert "upstream socks5://127.0.0.1:45000" in rendered.caddyfile_template
    # The upstream belongs inside the single managed forward_proxy block.
    forward = rendered.caddyfile_template.split("forward_proxy {", 1)[1]
    assert "upstream socks5://127.0.0.1:45000" in forward.split("}", 1)[0]


def test_naive_stays_direct_without_warp():
    action = naive_action()
    assert "egress=direct" in action.mutations
    rendered = NaiveAdapter(source_dir=ROOT).render(action)
    assert "upstream" not in rendered.caddyfile_template


def test_a_failed_identity_lookup_is_not_a_collision():
    """`getent` reports a missing entry as diagnostic text, not as a holder."""
    from installer.adapters.naive import _identity_from_entry

    assert _identity_from_entry("exit=2 ", 10003) is None
    assert _identity_from_entry("diagnostic unavailable: OSError", 10003) is None
    assert _identity_from_entry("", 10003) is None
    assert (
        _identity_from_entry(
            "naive-caddy:x:10003:10004::/nonexistent:/usr/sbin/nologin\n",
            10003,
        )
        == "naive-caddy"
    )
    # A line for another identifier is never taken as this one's holder.
    assert (
        _identity_from_entry("other:x:10009:10009::/nonexistent:/bin/false\n", 10003)
        is None
    )


def test_the_shared_core_project_is_not_mistaken_for_naive_resources(tmp_path):
    """Core owns the `mtproxy` project; only the Naive manager blocks adoption."""

    class CoreOnlyRunner(FakeNaiveRunner):
        def compose_project_present(self, _project_dir):
            return True  # Core is already installed in the shared project.

        def compose_service_present(self, service):
            assert service == "naive-manager"
            return False

    instance = adapter(tmp_path, CoreOnlyRunner())
    checkpoint = instance.prepare(naive_action())
    assert checkpoint["adoption"] == "absent"


def test_the_rendered_caddyfile_uses_valid_block_syntax():
    """Caddy rejects a block whose directives share the opening brace's line."""
    rendered = NaiveAdapter(source_dir=ROOT).render(naive_action())
    for line in rendered.caddyfile_template.splitlines():
        stripped = line.strip()
        if stripped.endswith("{"):
            continue
        assert "{" not in stripped or stripped.startswith("#"), stripped
    assert "root * /var/www/naive.example.com" in rendered.caddyfile_template
    assert "        file_server\n" in rendered.caddyfile_template


def test_the_renewal_hook_publishes_only_this_keypair_for_caddy(tmp_path):
    """The Certbot tree stays root-only; Caddy reads one published keypair."""
    from installer.adapters.naive import _TLS_DIR, _deploy_hook_text

    hook = _deploy_hook_text("naive.example.com")
    assert "/etc/letsencrypt/live/naive.example.com" in hook
    assert _TLS_DIR in hook
    assert "install -d -m 0750 -o root -g naive-accounting" in hook
    assert "install -m 0640 -o root -g naive-accounting" in hook
    # It never widens the Certbot tree itself.
    assert "chmod 0750 /etc/letsencrypt" not in hook
    assert "chgrp" not in hook

    rendered = NaiveAdapter(source_dir=ROOT).render(naive_action())
    assert f"tls {_TLS_DIR}/fullchain.pem {_TLS_DIR}/privkey.pem" in (
        rendered.caddyfile_template
    )
    assert "/etc/letsencrypt" not in rendered.caddyfile_template


def test_publishing_the_keypair_fails_closed(tmp_path):
    from installer.adapters.naive import _DEPLOY_HOOK

    # The fake host path is prefixed by the adapter root.
    runner = FakeNaiveRunner(fail_on=(str(tmp_path / _DEPLOY_HOOK.lstrip("/")),))
    instance = adapter(tmp_path, runner)
    with pytest.raises(NaiveError, match="command failed"):
        applied(instance, naive_action())


def test_naive_acceptance_reads_the_url_from_the_native_client_entry():
    """The panel publishes the proxy URL inside the Native client config, not
    as a top-level reveal field."""
    from installer.adapters.naive import _DefaultNaiveRunner

    revealed = {
        "service": "naive",
        "username": "pc-acceptance-abcd",
        "clients": {
            "native": {
                "config": {
                    "listen": "socks://127.0.0.1:1080",
                    "proxy": "https://pc-acceptance-abcd:secret@naive.example.com",
                }
            }
        },
    }
    assert (
        _DefaultNaiveRunner._native_proxy_url(revealed)
        == "https://pc-acceptance-abcd:secret@naive.example.com"
    )

    for broken in ({}, {"proxy_url": "https://u:p@naive.example.com"}, {"clients": {}}):
        with pytest.raises(AcceptanceError, match="access"):
            _DefaultNaiveRunner._native_proxy_url(broken)


def test_naive_acceptance_tunnels_a_real_inner_tls_session(tmp_path, monkeypatch):
    """The inner panel session runs inside the CONNECT tunnel. Wrapping the
    outer SSLSocket again would send the inner ClientHello in the clear and the
    peer would answer UNEXPECTED_MESSAGE."""
    import socket as socket_module
    import ssl as ssl_module
    import subprocess
    import threading

    from installer.adapters import naive as naive_module
    from installer.adapters.naive import _DefaultNaiveRunner

    key = tmp_path / "key.pem"
    certificate = tmp_path / "cert.pem"
    completed = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(certificate), "-days", "1",
            "-subj", "/CN=naive.example.com",
            "-addext", "subjectAltName=DNS:naive.example.com,DNS:panel.example.com",
        ],
        capture_output=True,
    )
    if completed.returncode != 0:
        pytest.skip("openssl is unavailable")

    server_context = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, key)
    listener = socket_module.socket()
    listener.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen: dict[str, object] = {}

    def serve() -> None:
        raw, _address = listener.accept()
        outer = server_context.wrap_socket(raw, server_side=True)
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = outer.recv(1024)
            if not chunk:
                return
            header += chunk
        seen["connect"] = header.split(b"\r\n", 1)[0]
        seen["authorized"] = b"Proxy-Authorization: Basic " in header
        outer.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        incoming = ssl_module.MemoryBIO()
        outgoing = ssl_module.MemoryBIO()
        inner = server_context.wrap_bio(incoming, outgoing, server_side=True)

        def relay(operation):
            while True:
                try:
                    result = operation()
                except ssl_module.SSLWantReadError:
                    pending = outgoing.read()
                    if pending:
                        outer.sendall(pending)
                    data = outer.recv(65536)
                    if not data:
                        incoming.write_eof()
                        raise
                    incoming.write(data)
                    continue
                pending = outgoing.read()
                if pending:
                    outer.sendall(pending)
                return result

        relay(inner.do_handshake)
        seen["request"] = relay(lambda: inner.read(65536))
        relay(lambda: inner.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        try:
            inner.unwrap()
        except ssl_module.SSLWantReadError:
            pass  # close_notify sent; the peer's reply is not awaited here.
        pending = outgoing.read()
        if pending:
            outer.sendall(pending)
        outer.close()

    def permissive_context():
        context = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl_module.CERT_NONE
        return context

    monkeypatch.setattr(naive_module.ssl, "create_default_context", permissive_context)
    connect = socket_module.create_connection
    monkeypatch.setattr(
        naive_module.socket,
        "create_connection",
        lambda _address, timeout=None: connect(("127.0.0.1", port), timeout=timeout),
    )

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        connect_bytes, closed, panel_ok = _DefaultNaiveRunner()._authenticated_connect(
            "https://user:secret@naive.example.com",
            naive_domain="naive.example.com",
            panel_domain="panel.example.com",
        )
    finally:
        worker.join(timeout=10)
        listener.close()

    assert seen["connect"] == b"CONNECT panel.example.com:443 HTTP/1.1"
    assert seen["authorized"] is True
    assert seen["request"].startswith(b"GET /healthz HTTP/1.1")
    assert panel_ok is True
    assert closed is True
    assert connect_bytes > 0


def test_naive_verify_mints_a_fresh_temporary_user_each_run(tmp_path):
    """The manager tombstones a deleted user, so re-creating the same name
    always conflicts: every acceptance run must own a new one."""
    instance = adapter(tmp_path)
    action = naive_action()
    applied(instance, action)

    instance.verify(action)
    first = host(tmp_path, PATHS.acceptance_owner).read_text().strip()
    instance.verify(action)
    second = host(tmp_path, PATHS.acceptance_owner).read_text().strip()

    assert first != second
    assert {first, second} <= set(instance.runner.acceptance_names)
    assert not host(tmp_path, PATHS.acceptance_pending).exists()


def test_naive_purge_removes_a_service_rewritten_file(tmp_path):
    """The manager rewrites the Caddyfile, so it never matches the digest the
    installer recorded; a purge must still take it out."""
    instance = adapter(tmp_path)
    action = naive_action()
    checkpoint = applied(instance, action)
    caddyfile = host(tmp_path, PATHS.caddyfile)
    caddyfile.write_text("# rewritten by the manager\n")

    instance.rollback(
        action, checkpoint, purge_data=True, rollback_target="uninstalled"
    )

    assert not caddyfile.exists()
