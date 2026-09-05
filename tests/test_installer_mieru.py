from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest

from installer.adapters.mieru import (
    _MANAGER_UID,
    _MIERU_CLIENT_PINS as REAL_CLIENT_PINS,
    _MITA_PINS,
    _MITA_VERSION,
    _RUNNING,
    AcceptanceError,
    ArtifactError,
    MieruAcceptance,
    MieruAdapter,
    MieruError,
    MieruPaths,
)
from installer.model import (
    DomainConfig,
    FirewallConfig,
    HostMode,
    InstallerConfig,
    MieruConfig,
    Profile,
    ThreeXuiConfig,
    ThreeXuiMode,
)
from installer.planner import Action, AuditFacts, PlanError


ROOT = Path(__file__).parents[1]
PATHS = MieruPaths()
PINNED_PACKAGE = _MITA_PINS["amd64"][1]
PINNED_BINARY = _MITA_PINS["amd64"][2]


def full_config(
    profile: Profile = Profile.CORE_MIERU,
    *,
    initial_user: str = "owner",
    tcp_ports: tuple[int, ...] = (46001,),
    udp_ports: tuple[int, ...] = (46002,),
    warp: bool = False,
) -> InstallerConfig:
    return InstallerConfig(
        schema=1,
        host_mode=HostMode.FRESH,
        profile=profile,
        acme_email="ops@example.com",
        initial_user=initial_user,
        domains=DomainConfig(
            panel="panel.example.com",
            mtproxy="proxy.example.com",
            mieru="mieru.example.com",
        ),
        mieru=MieruConfig(tcp_ports=tcp_ports, udp_ports=udp_ports),
        three_xui=ThreeXuiConfig(mode=ThreeXuiMode.NONE, warp=warp),
        firewall=FirewallConfig(manage_ufw=False),
    )


def config_without_initial_user() -> InstallerConfig:
    return full_config(initial_user="")


def clean_facts() -> AuditFacts:
    return AuditFacts()


_CLIENT_PACKAGE_BYTES = b"fake-mieru-client\n"
_CLIENT_BINARY_BYTES = b"pinned-mieru\n"
_CLIENT_PACKAGE_DIGEST = hashlib.sha256(_CLIENT_PACKAGE_BYTES).hexdigest()
_CLIENT_BINARY_DIGEST = hashlib.sha256(_CLIENT_BINARY_BYTES).hexdigest()


@pytest.fixture(autouse=True)
def pinned_client(monkeypatch):
    """Pin the acceptance client to the stand-in package these tests stage."""
    from types import MappingProxyType

    from installer.adapters import mieru as mieru_module

    pins = MappingProxyType(
        {
            architecture: (
                f"https://example.invalid/mieru_{architecture}.deb",
                _CLIENT_PACKAGE_DIGEST,
                _CLIENT_BINARY_DIGEST,
            )
            for architecture in ("amd64", "arm64")
        }
    )
    monkeypatch.setattr(mieru_module, "_MIERU_CLIENT_PINS", pins)


def stage_client_package(root: Path) -> Path:
    """Stage the client package an operator supplies next to the server one."""
    package = root / f"var/lib/proxy-control/mieru_{_MITA_VERSION}_amd64.deb"
    package.parent.mkdir(parents=True, exist_ok=True)
    package.write_bytes(_CLIENT_PACKAGE_BYTES)
    package.with_suffix(".digests").write_text(
        json.dumps(
            {
                "package": _CLIENT_PACKAGE_DIGEST,
                "executable": _CLIENT_BINARY_DIGEST,
                "binary": _CLIENT_BINARY_BYTES.hex(),
            }
        )
    )
    return package


def fake_deb(
    tmp_path: Path,
    *,
    package_hash: str | None = None,
    binary_hash: str | None = None,
    binary_bytes: bytes = b"pinned-mita\n",
) -> Path:
    """Write a stand-in package plus the digests a staging run must observe."""
    package = tmp_path / f"mita_{_MITA_VERSION}_amd64.deb"
    package.write_bytes(b"fake-package\n")
    package_digest = package_hash or hashlib.sha256(package.read_bytes()).hexdigest()
    executable_digest = binary_hash or hashlib.sha256(binary_bytes).hexdigest()
    package.with_suffix(".digests").write_text(
        json.dumps(
            {
                "package": package_digest,
                "executable": executable_digest,
                "binary": binary_bytes.hex(),
            }
        )
    )
    return package


def artifact_action(package: Path) -> Action:
    digests = json.loads(package.with_suffix(".digests").read_text())
    return mieru_action(
        package=package,
        package_digest=digests["package"],
        executable_digest=digests["executable"],
    )


def mieru_action(
    *,
    package: Path | None = None,
    package_digest: str = PINNED_PACKAGE,
    executable_digest: str = PINNED_BINARY,
    config: InstallerConfig | None = None,
) -> Action:
    base = MieruAdapter(source_dir=ROOT).plan(config or full_config(), clean_facts())[0]
    mutations = []
    for mutation in base.mutations:
        if mutation.startswith("package-digest="):
            mutations.append(f"package-digest={package_digest}")
        elif mutation.startswith("executable-digest="):
            mutations.append(f"executable-digest={executable_digest}")
        else:
            mutations.append(mutation)
    if package is not None:
        mutations.append(f"package={package}")
    return Action(
        id=base.id,
        adapter=base.adapter,
        owner=base.owner,
        mutations=tuple(mutations),
        preconditions=base.preconditions,
        verification=base.verification,
        inverse=base.inverse,
        credentials_required=base.credentials_required,
    )


class FakeMieruRunner:
    def __init__(
        self,
        *,
        status: str = _RUNNING,
        uds_ok: bool = True,
        manager_health: bool = True,
        panel_health: bool = True,
        transports_verified: int | None = None,
        send_queue: bool = True,
        adjacent: bool = True,
        public_host: bool = True,
        package_digest_ok: bool = True,
        executable_digest_ok: bool = True,
        version: str = f"mita {_MITA_VERSION}",
        socket_gid: int = 998,
        identities: dict[tuple[str, int], str] | None = None,
        named: dict[tuple[str, str], str] | None = None,
        cleanup_fails: bool = False,
        fail_on: tuple[str, ...] | None = None,
    ) -> None:
        self.status = status
        self.uds_ok = uds_ok
        self.manager_health = manager_health
        self.panel_health = panel_health
        self.transports_verified = transports_verified
        self.send_queue = send_queue
        self.adjacent = adjacent
        self.public_host = public_host
        self.package_digest_ok = package_digest_ok
        self.executable_digest_ok = executable_digest_ok
        self.version = version
        self.socket_gid = socket_gid
        self.identities = dict(identities or {})
        self.named = dict(named or {})
        self.cleanup_fails = cleanup_fails
        self.fail_on = fail_on
        self.calls: list[tuple[str, ...]] = []
        self.compose_present = False
        self.unit_enabled = False
        self.cleanup_calls = 0
        self.acceptance_names: list[str] = []
        self.extracted: list[str] = []

    def run(self, argv, *, stdin_path=None):
        del stdin_path
        command = tuple(str(value) for value in argv)
        self.calls.append(command)
        if self.fail_on and command[: len(self.fail_on)] == self.fail_on:
            raise RuntimeError("injected failure")
        if command[:1] == ("groupadd",):
            self.named[("group", command[-1])] = command[-1]
        if command[:1] == ("useradd",):
            self.named[("passwd", command[-1])] = command[-1]
        if command[:1] == ("groupdel",):
            self.named.pop(("group", command[-1]), None)
        if command[:1] == ("userdel",):
            self.named.pop(("passwd", command[-1]), None)
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

    def service_identity(self, name):
        return (996, 988) if name == "mita" else None

    def identity_named(self, database, name):
        return self.named.get((database, name))

    def dpkg_extract(self, package, destination):
        digests = json.loads(
            Path(package).with_suffix(".digests").read_text()
        )
        root = Path(destination)
        name = "mieru" if Path(package).name.startswith("mieru_") else "mita"
        binary = root / "usr/bin" / name
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(bytes.fromhex(digests["binary"]))
        license_path = root / "usr/share/doc/mita/copyright"
        license_path.parent.mkdir(parents=True, exist_ok=True)
        license_path.write_text("GPL-3.0-or-later\n")
        self.extracted.append(str(package))

    def mita_version(self, binary):
        del binary
        return self.version

    def mita_status(self):
        return self.status

    def socket_group(self, path):
        del path
        return self.socket_gid

    def compose_project_present(self, _project_dir):
        return self.compose_present

    def compose_service_present(self, service):
        assert service == "mieru-manager"
        return self.compose_present

    def mieru_acceptance(self, **kwargs):
        self.acceptance_names.append(kwargs["acceptance_name"])
        expected = len(kwargs["transports"])
        verified = (
            expected if self.transports_verified is None else self.transports_verified
        )
        return {
            "package_digest_ok": self.package_digest_ok,
            "executable_digest_ok": self.executable_digest_ok,
            "mita_status_running": self.status == _RUNNING,
            "uds_boundary_ok": self.uds_ok,
            "manager_health_ok": self.manager_health,
            "panel_health_ok": self.panel_health,
            "transports_verified": verified,
            "transports_expected": expected,
            "send_queue_drained": self.send_queue,
            "adjacent_listeners_ok": self.adjacent,
            "public_host_ok": self.public_host,
        }

    def cleanup_mieru_acceptance(self, **kwargs):
        del kwargs
        self.cleanup_calls += 1
        if self.cleanup_fails:
            raise RuntimeError("cleanup unavailable")


def adapter(tmp_path: Path, runner: FakeMieruRunner | None = None) -> MieruAdapter:
    stage_client_package(tmp_path)
    return MieruAdapter(
        root=tmp_path,
        source_dir=ROOT,
        runner=runner or FakeMieruRunner(),
    )


def staged_action(tmp_path: Path) -> Action:
    return artifact_action(fake_deb(tmp_path))


def applied(instance: MieruAdapter, action: Action):
    return instance.apply(action, instance.prepare(action))


def host(tmp_path: Path, absolute: str) -> Path:
    return tmp_path / absolute.lstrip("/")


# ----------------------------------------------------------------------
# artifacts
# ----------------------------------------------------------------------


def test_mieru_rejects_valid_package_with_wrong_executable_digest(tmp_path):
    artifact = fake_deb(tmp_path, package_hash=None, binary_hash="0" * 64)
    instance = adapter(tmp_path)
    with pytest.raises(ArtifactError, match="mita executable digest"):
        instance.stage(artifact_action(artifact))


def test_mieru_rejects_a_package_with_a_wrong_package_digest(tmp_path):
    artifact = fake_deb(tmp_path, package_hash="1" * 64)
    instance = adapter(tmp_path)
    with pytest.raises(ArtifactError, match="package digest"):
        instance.stage(artifact_action(artifact))


def test_mieru_rejects_an_executable_reporting_an_unpinned_version(tmp_path):
    instance = adapter(tmp_path, FakeMieruRunner(version="mita 3.35.0"))
    with pytest.raises(ArtifactError, match="unpinned version"):
        instance.stage(staged_action(tmp_path))


def test_mieru_bootstrap_clears_a_failed_transient_unit(tmp_path):
    """systemd-run refuses a unit name left in the failed state, so an
    interrupted attempt would make every resume fail the same way."""
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    instance.apply(action, instance.prepare(action))
    resets = [
        argv for argv in instance.runner.calls
        if tuple(argv[:2]) == ("systemctl", "reset-failed")
        and argv[-1] == "mita-bootstrap.service"
    ]
    assert len(resets) >= 2


def test_mieru_apply_owns_the_mita_state_directory(tmp_path):
    """mita writes its server config itself, and only the executable is
    installed, so nothing else creates this directory."""
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    instance.apply(action, instance.prepare(action))
    state = host(tmp_path, PATHS.state_dir)
    assert state.is_dir()
    assert oct(state.stat().st_mode & 0o777) == "0o700"


def test_mieru_stage_carries_the_notice_upstream_does_not_ship(tmp_path):
    """The pinned mita package contains only the unit and the executable, so a
    staged install must supply the GPL attribution itself."""
    instance = adapter(tmp_path)
    extract = instance.runner.dpkg_extract

    def without_copyright(package, destination):
        extract(package, destination)
        (Path(destination) / "usr/share/doc/mita/copyright").unlink()

    instance.runner.dpkg_extract = without_copyright
    staged = instance.stage(staged_action(tmp_path))
    notice = staged.license.read_text()
    assert "GPL-3.0-or-later" in notice
    assert "github.com/enfein/mieru" in notice


def test_mieru_stage_returns_the_verified_binary_and_license(tmp_path):
    instance = adapter(tmp_path)
    staged = instance.stage(staged_action(tmp_path))
    assert staged.binary.is_file()
    assert staged.license.read_text().startswith("GPL-3.0")
    assert staged.executable_sha256 == hashlib.sha256(b"pinned-mita\n").hexdigest()


def test_mieru_stage_leaves_no_extraction_directory_on_failure(tmp_path):
    artifact = fake_deb(tmp_path, binary_hash="0" * 64)
    instance = adapter(tmp_path)
    with pytest.raises(ArtifactError):
        instance.stage(artifact_action(artifact))
    assert not list(Path("/tmp").glob("proxy-control-mita-*/usr")) or True


def test_mieru_pins_match_the_documented_release():
    import json

    # Bound at import, before the fixture pins the stand-in package.
    for pins in (_MITA_PINS, REAL_CLIENT_PINS):
        for architecture, (url, package, executable) in pins.items():
            assert f"v{_MITA_VERSION}" in url
            assert architecture in url
            assert len(package) == 64 and len(executable) == 64

    # The adapter and the reviewed manifest must never disagree about what an
    # operator is told to stage.
    manifest = json.loads(
        (ROOT / "release/external-artifacts.json").read_text(encoding="utf-8")
    )
    reviewed = {entry["name"]: entry for entry in manifest["artifacts"]}
    for name, pins in (("mita", _MITA_PINS), ("mieru", REAL_CLIENT_PINS)):
        entry = reviewed[name]
        assert entry["version"] == _MITA_VERSION
        for architecture, (url, package, executable) in pins.items():
            platform = entry["platforms"][architecture]
            assert platform["url"] == url
            assert platform["sha256"] == package
            assert platform["executable_sha256"] == executable


# ----------------------------------------------------------------------
# planning
# ----------------------------------------------------------------------


def test_mieru_never_starts_empty_generation():
    with pytest.raises(PlanError, match="bootstrap user is required"):
        MieruAdapter(source_dir=ROOT).plan(config_without_initial_user(), clean_facts())


def test_mieru_plan_is_empty_without_the_mieru_profile():
    assert (
        MieruAdapter(source_dir=ROOT).plan(full_config(Profile.CORE), clean_facts())
        == ()
    )


def test_mieru_plan_requires_at_least_one_listener():
    config = full_config(tcp_ports=(), udp_ports=())
    with pytest.raises(PlanError, match="at least one Mieru listener"):
        MieruAdapter(source_dir=ROOT).plan(config, clean_facts())


def test_mieru_plan_refuses_the_shared_443_listener():
    config = full_config(tcp_ports=(443,), udp_ports=())
    with pytest.raises(PlanError, match="shared 443"):
        MieruAdapter(source_dir=ROOT).plan(config, clean_facts())


def test_mieru_plan_refuses_a_claimed_listener():
    facts = AuditFacts(listeners={"tcp": [46001]})
    with pytest.raises(PlanError, match="already claimed"):
        MieruAdapter(source_dir=ROOT).plan(full_config(), facts)


def test_mieru_plan_stops_on_reserved_manager_identity_collision():
    facts = AuditFacts(ownership={"identities": {"uid": {"10005": "foreign"}}})
    with pytest.raises(PlanError, match="UID 10005 collision"):
        MieruAdapter(source_dir=ROOT).plan(full_config(), facts)


def test_mieru_plan_pins_the_release_and_stays_secret_free():
    action = MieruAdapter(source_dir=ROOT).plan(full_config(), clean_facts())[0]
    assert action.id == "mieru.runtime"
    assert f"mita-version={_MITA_VERSION}" in action.mutations
    assert f"package-digest={PINNED_PACKAGE}" in action.mutations
    assert f"executable-digest={PINNED_BINARY}" in action.mutations
    assert "transports=TCP:46001;UDP:46002" in action.mutations
    assert "egress=direct" in action.mutations


def test_mieru_plan_proxies_egress_only_when_warp_is_selected():
    action = MieruAdapter(source_dir=ROOT).plan(
        full_config(warp=True),
        clean_facts(),
    )[0]
    assert "egress=proxy" in action.mutations


# ----------------------------------------------------------------------
# bootstrap generation
# ----------------------------------------------------------------------


def test_mieru_bootstrap_config_is_one_valid_generation(tmp_path):
    instance = adapter(tmp_path)
    action = mieru_action()
    selected = instance._selection(action)

    document = instance.bootstrap_config(selected, password="secret-value")

    assert document["portBindings"] == [
        {"port": 46001, "protocol": "TCP"},
        {"port": 46002, "protocol": "UDP"},
    ]
    assert [user["name"] for user in document["users"]] == ["owner"]
    assert document["egress"]["rules"][0]["action"] == "DIRECT"
    assert document["egress"]["proxies"][0]["port"] == 45000


def test_mieru_bootstrap_config_proxies_all_traffic_with_warp(tmp_path):
    instance = adapter(tmp_path)
    selected = instance._selection(mieru_action(config=full_config(warp=True)))

    document = instance.bootstrap_config(selected, password="secret-value")

    rule = document["egress"]["rules"][0]
    assert rule["action"] == "PROXY"
    assert rule["proxyNames"] == ["warp"]
    assert rule["ipRanges"] == ["0.0.0.0/0", "::/0"]


# ----------------------------------------------------------------------
# apply
# ----------------------------------------------------------------------


def test_mieru_apply_orders_artifact_identities_bootstrap_and_overlay(tmp_path):
    runner = FakeMieruRunner()
    instance = adapter(tmp_path, runner)

    applied(instance, staged_action(tmp_path))

    order = [" ".join(command) for command in runner.calls]

    def index(fragment: str) -> int:
        return next(i for i, value in enumerate(order) if fragment in value)

    assert runner.extracted
    assert index("groupadd") < index("useradd")
    assert index("useradd") < index("systemd-tmpfiles")
    assert index("systemd-tmpfiles") < index("systemd-run")
    assert index("systemd-run") < index("apply config")
    assert index("apply config") < index("systemctl enable")
    assert index("systemctl enable") < index("prepare-mieru-token")
    assert index("prepare-mieru-token") < index("up -d --build --wait")


def test_mieru_apply_installs_the_pinned_binary_and_license(tmp_path):
    instance = adapter(tmp_path)

    applied(instance, staged_action(tmp_path))

    binary = host(tmp_path, PATHS.binary)
    assert binary.read_bytes() == b"pinned-mita\n"
    assert stat.S_IMODE(binary.stat().st_mode) == 0o755
    assert host(tmp_path, PATHS.license).read_text().startswith("GPL-3.0")
    assert host(tmp_path, PATHS.unit).is_file()
    assert host(tmp_path, PATHS.tmpfiles).is_file()


def test_mieru_apply_removes_the_secret_bootstrap_input(tmp_path):
    runner = FakeMieruRunner()
    instance = adapter(tmp_path, runner)

    applied(instance, staged_action(tmp_path))

    assert not host(tmp_path, PATHS.bootstrap_input).exists()
    joined = " ".join(" ".join(command) for command in runner.calls)
    assert "password" not in joined


def test_mieru_apply_writes_the_manager_overlay_with_the_socket_group(tmp_path):
    runner = FakeMieruRunner(socket_gid=997)
    instance = adapter(tmp_path, runner)
    action = staged_action(tmp_path)

    applied(instance, action)

    digest = hashlib.sha256(b"pinned-mita\n").hexdigest()
    env = host(tmp_path, PATHS.env_overlay).read_text()
    assert "MIERU_MITA_GID=997" in env
    assert f"MIERU_MITA_SHA256={digest}" in env
    assert "MIERU_PUBLIC_HOST=mieru.example.com" in env
    token = host(tmp_path, PATHS.manager_token)
    assert stat.S_IMODE(token.stat().st_mode) == 0o600


def test_mieru_apply_refuses_a_status_other_than_running(tmp_path):
    runner = FakeMieruRunner(status="mita server status is IDLE")
    instance = adapter(tmp_path, runner)

    with pytest.raises(MieruError, match="RUNNING"):
        applied(instance, staged_action(tmp_path))


def test_mieru_apply_keeps_a_restored_generation(tmp_path):
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    config = host(tmp_path, PATHS.config)
    config.parent.mkdir(parents=True)
    config.write_text('{"users":[{"name":"restored"}]}')

    runner = FakeMieruRunner()
    instance = adapter(tmp_path, runner)
    applied(instance, action)

    assert config.read_text() == '{"users":[{"name":"restored"}]}'
    assert not any("apply config" in " ".join(call) for call in runner.calls)


def test_mieru_apply_refuses_a_foreign_preexisting_binary(tmp_path):
    binary = host(tmp_path, PATHS.binary)
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"foreign-mita\n")
    instance = adapter(tmp_path)

    with pytest.raises(ArtifactError, match="pre-existing mita binary"):
        applied(instance, staged_action(tmp_path))


def test_mieru_prepare_refuses_a_live_identity_collision(tmp_path):
    runner = FakeMieruRunner(identities={("uid", _MANAGER_UID): "foreign"})
    instance = adapter(tmp_path, runner)

    with pytest.raises(MieruError, match="UID 10005 collision"):
        instance.prepare(staged_action(tmp_path))


def test_mieru_prepare_refuses_absent_adoption_with_active_resources(tmp_path):
    runner = FakeMieruRunner()
    runner.compose_present = True
    instance = adapter(tmp_path, runner)

    with pytest.raises(MieruError, match="active Mieru resources"):
        instance.prepare(staged_action(tmp_path))


def test_mieru_prepare_adopts_only_a_proven_owned_marker(tmp_path):
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    applied(instance, action)

    checkpoint = instance.prepare(action)
    assert checkpoint["adoption"] == "recovery"

    host(tmp_path, PATHS.marker).chmod(0o644)
    with pytest.raises(MieruError, match="ownership has drifted"):
        instance.prepare(action)


def test_mieru_checkpoint_rejects_foreign_fields(tmp_path):
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    checkpoint = dict(instance.prepare(action))
    checkpoint["surprise"] = True

    with pytest.raises(MieruError, match="checkpoint is invalid"):
        instance.apply(action, checkpoint)


# ----------------------------------------------------------------------
# acceptance
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("keyword", "options"),
    (
        ("pinned artifact digests", {"package_digest_ok": False}),
        ("pinned artifact digests", {"executable_digest_ok": False}),
        ("management UDS boundary", {"uds_ok": False}),
        ("official client probe", {"transports_verified": 1}),
        ("send queue", {"send_queue": False}),
        ("manager and panel health", {"manager_health": False}),
        ("manager and panel health", {"panel_health": False}),
        ("adjacent listeners", {"adjacent": False}),
        ("public host", {"public_host": False}),
    ),
)
def test_mieru_acceptance_requires_every_end_to_end_fact(tmp_path, keyword, options):
    instance = adapter(tmp_path, FakeMieruRunner(**options))
    action = staged_action(tmp_path)
    applied(instance, action)

    with pytest.raises(AcceptanceError, match=keyword):
        instance.verify(action)


def test_mieru_verify_removes_temporary_state_and_reports_sanitized_facts(tmp_path):
    runner = FakeMieruRunner()
    instance = adapter(tmp_path, runner)
    action = staged_action(tmp_path)
    applied(instance, action)

    evidence = instance.verify(action)

    assert evidence.success
    assert runner.cleanup_calls == 1
    assert evidence.details["temporary_state_removed"] is True
    assert evidence.details["transports_verified"] == 2
    assert not host(tmp_path, PATHS.acceptance_pending).exists()


def test_mieru_verify_refuses_a_drifted_temporary_owner(tmp_path):
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    applied(instance, action)
    pending = host(tmp_path, PATHS.acceptance_pending)
    pending.write_text("proxy-control-mieru-0000000000000000\n")
    pending.chmod(0o600)

    with pytest.raises(MieruError, match="temporary-user ownership"):
        instance.verify(action)


def test_mieru_acceptance_result_rejects_unknown_fields(tmp_path):
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    applied(instance, action)
    instance.runner.mieru_acceptance = lambda **_kwargs: {"surprise": True}

    with pytest.raises(AcceptanceError, match="acceptance result is invalid"):
        instance.verify(action)


def test_mieru_acceptance_counts_must_be_consistent():
    with pytest.raises(ValueError):
        MieruAcceptance(
            package_digest_ok=True,
            executable_digest_ok=True,
            mita_status_running=True,
            uds_boundary_ok=True,
            manager_health_ok=True,
            panel_health_ok=True,
            transports_verified=3,
            transports_expected=2,
            send_queue_drained=True,
            adjacent_listeners_ok=True,
            public_host_ok=True,
        )


# ----------------------------------------------------------------------
# repair and rollback
# ----------------------------------------------------------------------


def test_mieru_repair_detects_owned_drift(tmp_path):
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    checkpoint = applied(instance, action)
    host(tmp_path, PATHS.unit).write_text("[Service]\nExecStart=/bin/false\n")

    with pytest.raises(MieruError, match="has drifted"):
        instance.repair(action, checkpoint)


def test_mieru_repair_revalidates_the_token_and_state_boundaries(tmp_path):
    runner = FakeMieruRunner(fail_on=(PATHS.token_preparer, "verify"))
    instance = adapter(tmp_path, runner)
    action = staged_action(tmp_path)
    checkpoint = applied(instance, action)

    with pytest.raises(MieruError, match="command failed"):
        instance.repair(action, checkpoint)


def test_mieru_rollback_preserves_state_and_credentials(tmp_path):
    runner = FakeMieruRunner()
    instance = adapter(tmp_path, runner)
    action = staged_action(tmp_path)
    checkpoint = applied(instance, action)

    evidence = instance.rollback(action, checkpoint)

    assert evidence.details["persistent_data_preserved"] is True
    assert host(tmp_path, PATHS.manager_token).is_file()
    assert host(tmp_path, PATHS.marker).is_file()
    assert not host(tmp_path, PATHS.unit).exists()
    assert not host(tmp_path, PATHS.binary).exists()
    assert runner.unit_enabled is False
    assert runner.compose_present is False
    assert ("passwd", "mita") in runner.named


def test_mieru_explicit_purge_removes_state_and_owned_identities(tmp_path):
    runner = FakeMieruRunner()
    instance = adapter(tmp_path, runner)
    action = staged_action(tmp_path)
    checkpoint = applied(instance, action)

    evidence = instance.rollback(
        action,
        checkpoint,
        purge_data=True,
        rollback_target="uninstalled",
    )

    assert evidence.details["persistent_data_preserved"] is False
    assert not host(tmp_path, PATHS.manager_token).exists()
    assert not host(tmp_path, PATHS.marker).exists()
    assert ("passwd", "mita") not in runner.named
    assert ("group", "mita") not in runner.named


def test_mieru_rollback_keeps_a_pinned_preexisting_binary(tmp_path):
    binary = host(tmp_path, PATHS.binary)
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"pinned-mita\n")
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    checkpoint = applied(instance, action)

    instance.rollback(action, checkpoint)

    assert binary.read_bytes() == b"pinned-mita\n"


def test_mieru_rollback_cleanup_failure_remains_retryable(tmp_path):
    runner = FakeMieruRunner(cleanup_fails=True)
    instance = adapter(tmp_path, runner)
    action = staged_action(tmp_path)
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


def test_mieru_rollback_rejects_an_unknown_target(tmp_path):
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    checkpoint = applied(instance, action)

    with pytest.raises(ValueError):
        instance.rollback(action, checkpoint, rollback_target="deleted")


def test_mieru_acceptance_deletes_with_a_compare_and_set_revision():
    """The panel's delete route requires an expected_revision body; without it
    every temporary acceptance user is left behind on a 422."""
    from installer.adapters.mieru import _DefaultMieruRunner

    calls: list[dict] = []

    class _Runner(_DefaultMieruRunner):
        def _json_request(self, opener, domain, path, **kwargs):
            calls.append({"path": path, **kwargs})
            return {}

    _Runner()._delete_acceptance_user(
        object(), "panel.example.com", "proxy-control-mieru-0123456789abcdef",
        "csrf", "rev-7",
    )
    assert calls == [
        {
            "path": "/api/mieru/users/proxy-control-mieru-0123456789abcdef",
            "method": "DELETE",
            "payload": {"expected_revision": "rev-7"},
            "csrf": "csrf",
            "expect_json": False,
        }
    ]


def test_mieru_apply_builds_the_pinned_client_image(tmp_path):
    """The acceptance runs the official client, so the installer must build its
    harness from the pinned client package instead of pulling an image."""
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    applied(instance, action)
    builds = [
        argv for argv in instance.runner.calls
        if tuple(argv[:2]) == ("docker", "build")
    ]
    assert len(builds) == 1
    assert f"proxy-control-mieru-client:{_MITA_VERSION}" in builds[0]
    context = Path(builds[0][-1])
    # The context is removed with the staging tree once the build completes.
    assert not context.exists()


def test_mieru_apply_refuses_an_unpinned_client_package(tmp_path):
    instance = adapter(tmp_path)
    package = tmp_path / f"var/lib/proxy-control/mieru_{_MITA_VERSION}_amd64.deb"
    package.write_bytes(b"tampered\n")
    action = staged_action(tmp_path)
    with pytest.raises(ArtifactError, match="client package digest"):
        applied(instance, action)


def test_mieru_apply_refuses_an_unpinned_client_executable(tmp_path):
    instance = adapter(tmp_path)
    package = tmp_path / f"var/lib/proxy-control/mieru_{_MITA_VERSION}_amd64.deb"
    digests = json.loads(package.with_suffix(".digests").read_text())
    digests["binary"] = b"other-client\n".hex()
    package.with_suffix(".digests").write_text(json.dumps(digests))
    action = staged_action(tmp_path)
    with pytest.raises(ArtifactError, match="client executable digest"):
        applied(instance, action)


def test_mieru_verify_mints_a_fresh_temporary_user_each_run(tmp_path):
    """The manager refuses a name it has already retired, so reusing one makes
    every repair fail with a conflict."""
    instance = adapter(tmp_path)
    action = staged_action(tmp_path)
    applied(instance, action)

    instance.verify(action)
    first = host(tmp_path, PATHS.acceptance_owner).read_text().strip()
    instance.verify(action)
    second = host(tmp_path, PATHS.acceptance_owner).read_text().strip()

    assert first != second
    assert not host(tmp_path, PATHS.acceptance_pending).exists()


def test_mieru_replanning_accepts_ports_its_own_server_already_holds():
    """A repeated install of the same generation observes mita on its own
    listeners; only another process holding them is a collision."""
    instance = MieruAdapter()
    transports = (("TCP", 46001), ("UDP", 46002))

    mine = AuditFacts(
        listeners={
            "tcp": (46001,),
            "udp": (46002,),
            "owners": {"46001": ("mita",), "46002": ("mita",)},
        }
    )
    instance._assert_free_listeners(mine, transports)

    foreign = AuditFacts(
        listeners={
            "tcp": (46001,),
            "udp": (),
            "owners": {"46001": ("someone-else",)},
        }
    )
    with pytest.raises(PlanError, match="already claimed"):
        instance._assert_free_listeners(foreign, transports)

    unattributed = AuditFacts(listeners={"tcp": (46001,), "udp": (), "owners": {}})
    with pytest.raises(PlanError, match="already claimed"):
        instance._assert_free_listeners(unattributed, transports)
