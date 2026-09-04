from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from installer.adapters.three_xui import (
    _VERSION,
    AcceptanceError,
    ArtifactError,
    ThreeXuiAdapter,
    ThreeXuiAudit,
    ThreeXuiError,
    ThreeXuiPaths,
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
from installer.planner import AuditFacts, PlanError
from installer.release import ArtifactPin


ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests/fixtures/three_xui"
PATHS = ThreeXuiPaths()

TEST_UUID = "6f2c1d4e-6a2b-4c8f-9f0d-2a7b5c8e1d33"
TEST_PRIVATE_KEY = "wPJ8Zk1TLbQ0YyC7mF3sJd9nR2vX5hK8aE4uG6iO1cQ"
TEST_SHORT_ID = "0123456789abcdef"
TEST_CLIENT_PASSWORD = "hysteria-client-password"


def config_with_clients_and_reality_secret() -> dict:
    return {
        "inbounds": [
            {
                "tag": "inbound-vless-tcp",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": 8449,
                "settings": {
                    "clients": [
                        {"id": TEST_UUID, "email": "one@example.com", "flow": ""},
                        {"id": TEST_UUID, "email": "two@example.com", "flow": ""},
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverNames": ["www.microsoft.com"],
                        "target": "www.microsoft.com:443",
                        "privateKey": TEST_PRIVATE_KEY,
                        "shortIds": [TEST_SHORT_ID],
                    },
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
            {
                "tag": "inbound-hysteria",
                "protocol": "hysteria2",
                "listen": "0.0.0.0",
                "port": 8452,
                "settings": json.dumps(
                    {"clients": [{"password": TEST_CLIENT_PASSWORD}]}
                ),
                "streamSettings": {
                    "network": "quic",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [
                            {
                                "certificateFile": (
                                    "/etc/letsencrypt/live/"
                                    "hysteria.example.com/fullchain.pem"
                                ),
                                "keyFile": (
                                    "/etc/letsencrypt/live/"
                                    "hysteria.example.com/privkey.pem"
                                ),
                            }
                        ]
                    },
                },
            },
        ],
        "outbounds": [{"tag": "direct"}, {"tag": "blocked"}],
        "routing": {
            "balancers": [{"tag": "balancer-a"}],
            "rules": [
                {"inboundTag": ["api"], "outboundTag": "direct"},
                {"protocol": ["bittorrent"], "outboundTag": "blocked"},
            ],
        },
    }


def write_xray_config(root: Path, document: dict) -> None:
    config = root / PATHS.config.lstrip("/")
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps(document))


def existing_config() -> InstallerConfig:
    return InstallerConfig(
        schema=1,
        host_mode=HostMode.COEXIST,
        profile=Profile.CORE,
        acme_email="ops@example.com",
        initial_user="owner",
        domains=DomainConfig(panel="panel.example.com", mtproxy="proxy.example.com"),
        mieru=None,
        three_xui=ThreeXuiConfig(
            mode=ThreeXuiMode.EXISTING,
            vless_tcp_domain="vless.example.com",
        ),
        firewall=FirewallConfig(manage_ufw=False),
    )


def managed_config(warp: bool = False) -> InstallerConfig:
    return InstallerConfig(
        schema=1,
        host_mode=HostMode.FRESH,
        profile=Profile.CORE,
        acme_email="ops@example.com",
        initial_user="owner",
        domains=DomainConfig(panel="panel.example.com", mtproxy="proxy.example.com"),
        mieru=None,
        three_xui=ThreeXuiConfig(
            mode=ThreeXuiMode.MANAGED_NEW,
            panel_domain="xui.example.com",
            vless_tcp_domain="vless.example.com",
            vless_xhttp_domain="xhttp.example.com",
            hysteria_domain="hysteria.example.com",
            warp=warp,
        ),
        firewall=FirewallConfig(manage_ufw=False),
    )


def existing_facts() -> AuditFacts:
    return AuditFacts(ownership={"three_xui": {"mode": "existing", "present": True}})


class FakeThreeXuiRunner:
    def __init__(
        self,
        *,
        version: str = f"x-ui {_VERSION}",
        named: dict[tuple[str, str], str] | None = None,
        unit_active: bool = False,
        migration_fails: bool = False,
        fail_on: tuple[str, ...] | None = None,
    ) -> None:
        self.version = version
        self.named = dict(named or {})
        self._unit_active = unit_active
        self.migration_fails = migration_fails
        self.fail_on = fail_on
        self.calls: list[tuple[str, ...]] = []
        self.rehearsals: list[str] = []

    def run(self, argv, *, stdin_path=None):
        del stdin_path
        command = tuple(str(value) for value in argv)
        self.calls.append(command)
        if self.fail_on and command[: len(self.fail_on)] == self.fail_on:
            raise RuntimeError("injected failure")
        if command[:2] == ("systemctl", "enable"):
            self._unit_active = True
        if command[:2] in {("systemctl", "disable"), ("systemctl", "stop")}:
            self._unit_active = False

    def identity_named(self, database, name):
        return self.named.get((database, name))

    def x_ui_version(self, binary):
        del binary
        return self.version

    def unit_active(self, unit):
        del unit
        return self._unit_active

    def bootstrap_session(self, *, namespace, binary, payload_path):
        self.calls.append(("ip", "netns", "add", namespace))
        self.calls.append(
            (
                "systemd-run",
                f"--property=NetworkNamespacePath=/run/netns/{namespace}",
                binary,
                "run",
            )
        )
        self.calls.append(("bootstrap-dialogue", payload_path))
        self.calls.append(("systemctl", "stop", "x-ui-bootstrap.service"))
        self.calls.append(("ip", "netns", "delete", namespace))

    def migration_rehearsal(self, binary, database):
        del binary
        self.rehearsals.append(database)
        if self.migration_fails:
            raise RuntimeError("migration rehearsal failed")


def adapter(
    tmp_path: Path,
    runner: FakeThreeXuiRunner | None = None,
) -> ThreeXuiAdapter:
    return ThreeXuiAdapter(
        root=tmp_path,
        source_dir=ROOT,
        runner=runner or FakeThreeXuiRunner(),
        layout=FIXTURES / "release-layout.json",
    )


def build_release(tmp_path: Path, *, binary: bytes = b"x-ui-binary\n") -> Path:
    """Build a synthetic release archive matching the reviewed layout."""
    archive = tmp_path / f"x-ui-linux-amd64-{_VERSION}.tar.gz"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as handle:
        def add_dir(name: str) -> None:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            handle.addfile(info)

        def add_file(name: str, payload: bytes, mode: int) -> None:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = mode
            handle.addfile(info, io.BytesIO(payload))

        add_dir("x-ui")
        add_file("x-ui/x-ui", binary, 0o755)
        add_file("x-ui/x-ui.sh", b"#!/bin/sh\n", 0o755)
        add_file("x-ui/x-ui.service", b"[Service]\nExecStart=/usr/local/x-ui/x-ui\n", 0o644)
        add_dir("x-ui/bin")
        add_file("x-ui/bin/config.json", b"{}\n", 0o644)
    archive.write_bytes(buffer.getvalue())
    return archive


def managed_action(tmp_path: Path, config: InstallerConfig | None = None):
    instance = adapter(tmp_path)
    actions = instance.plan(config or managed_config(), AuditFacts())
    return next(action for action in actions if action.id == "three_xui.runtime")


def pinned_action(tmp_path: Path, archive: Path):
    from installer.planner import Action

    base = managed_action(tmp_path)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    mutations = tuple(
        f"release-digest={digest}"
        if mutation.startswith("release-digest=")
        else mutation
        for mutation in base.mutations
    )
    return Action(
        id=base.id,
        adapter=base.adapter,
        owner=base.owner,
        mutations=mutations,
        preconditions=base.preconditions,
        verification=base.verification,
        inverse=base.inverse,
        credentials_required=base.credentials_required,
    )


# ----------------------------------------------------------------------
# existing-state preservation
# ----------------------------------------------------------------------


def test_existing_mode_never_serializes_clients_or_private_keys(tmp_path):
    write_xray_config(tmp_path, config_with_clients_and_reality_secret())
    audit = adapter(tmp_path).audit_existing()
    encoded = json.dumps(dataclasses.asdict(audit), sort_keys=True)
    assert "clients" not in encoded
    assert TEST_UUID not in encoded
    assert TEST_PRIVATE_KEY not in encoded
    assert TEST_SHORT_ID not in encoded
    assert TEST_CLIENT_PASSWORD not in encoded


def test_existing_install_plan_has_no_three_xui_mutation(tmp_path):
    write_xray_config(tmp_path, config_with_clients_and_reality_secret())
    actions = adapter(tmp_path).plan(existing_config(), existing_facts())
    assert {action.owner for action in actions} == {"nginx.routes.three_xui"}
    assert all(action.id == "three_xui.routes" for action in actions)
    assert all(
        mutation.startswith(("mode=", "route="))
        for action in actions
        for mutation in action.mutations
    )


def test_existing_audit_matches_the_reviewed_sanitized_shape(tmp_path):
    write_xray_config(tmp_path, config_with_clients_and_reality_secret())
    expected = json.loads((FIXTURES / "config-sanitized.json").read_text())

    audit = adapter(tmp_path).audit_existing()

    assert audit.installed is expected["installed"]
    assert audit.client_total == expected["client_total"]
    assert list(audit.outbound_tags) == expected["outbound_tags"]
    assert list(audit.balancer_tags) == expected["balancer_tags"]
    assert list(audit.routing_selectors) == expected["routing_selectors"]
    observed = [
        {**dataclasses.asdict(item)}
        for item in audit.inbounds
    ]
    for item in observed:
        for key in ("reality_server_names", "tls_certificate_paths",
                    "sniffing_dest_override"):
            item[key] = list(item[key])
    assert observed == expected["inbounds"]


def test_existing_audit_hashes_the_byte_identity_of_the_install(tmp_path):
    write_xray_config(tmp_path, config_with_clients_and_reality_secret())
    database = tmp_path / PATHS.database.lstrip("/")
    database.parent.mkdir(parents=True)
    database.write_bytes(b"sqlite\n")

    audit = adapter(tmp_path).audit_existing()

    assert set(audit.digests) >= {"config", "database", "binary_tree"}
    assert audit.digests["database"] == hashlib.sha256(b"sqlite\n").hexdigest()


def test_existing_audit_reports_an_absent_installation(tmp_path):
    audit = adapter(tmp_path).audit_existing()
    assert audit.installed is False
    assert audit.inbounds == ()


def test_existing_audit_refuses_an_oversized_configuration(tmp_path):
    config = tmp_path / PATHS.config.lstrip("/")
    config.parent.mkdir(parents=True)
    config.write_text("{}" + " " * (4 * 1024 * 1024))
    with pytest.raises(ThreeXuiError, match="audit bound"):
        adapter(tmp_path).audit_existing()


def test_existing_plan_requires_a_loopback_inbound(tmp_path):
    document = config_with_clients_and_reality_secret()
    document["inbounds"][0]["listen"] = "0.0.0.0"
    write_xray_config(tmp_path, document)
    with pytest.raises(PlanError, match="loopback"):
        adapter(tmp_path).plan(existing_config(), existing_facts())


def test_existing_plan_requires_an_installed_three_xui(tmp_path):
    with pytest.raises(PlanError, match="requires an installed"):
        adapter(tmp_path).plan(existing_config(), existing_facts())


def test_existing_route_verification_requires_an_audited_backend(tmp_path):
    write_xray_config(tmp_path, config_with_clients_and_reality_secret())
    instance = adapter(tmp_path)
    action = instance.plan(existing_config(), existing_facts())[0]

    assert instance.verify(action).success

    document = config_with_clients_and_reality_secret()
    document["inbounds"][0]["port"] = 9999
    write_xray_config(tmp_path, document)
    with pytest.raises(AcceptanceError, match="loopback inbound"):
        instance.verify(action)


def test_no_mode_plans_nothing(tmp_path):
    config = existing_config()
    none_config = InstallerConfig(
        **{
            **{
                name: getattr(config, name)
                for name in config.__dataclass_fields__
            },
            "three_xui": ThreeXuiConfig(mode=ThreeXuiMode.NONE),
        }
    )
    assert adapter(tmp_path).plan(none_config, AuditFacts()) == ()


# ----------------------------------------------------------------------
# managed-new staging
# ----------------------------------------------------------------------


def test_managed_plan_routes_every_selected_domain_to_loopback(tmp_path):
    actions = adapter(tmp_path).plan(managed_config(), AuditFacts())
    routes = [
        mutation
        for action in actions
        if action.id == "three_xui.routes"
        for mutation in action.mutations
        if mutation.startswith("route=")
    ]
    assert routes == [
        "route=vless.example.com 127.0.0.1:8449",
        "route=xhttp.example.com 127.0.0.1:8450",
        "route=xui.example.com 127.0.0.1:8451",
    ]
    runtime = next(action for action in actions if action.id == "three_xui.runtime")
    assert f"version={_VERSION}" in runtime.mutations
    assert "warp=false" in runtime.mutations


def test_managed_plan_requires_every_selected_domain(tmp_path):
    config = managed_config()
    broken = InstallerConfig(
        **{
            **{
                name: getattr(config, name)
                for name in config.__dataclass_fields__
            },
            "three_xui": ThreeXuiConfig(
                mode=ThreeXuiMode.MANAGED_NEW,
                panel_domain="xui.example.com",
                hysteria_domain="hysteria.example.com",
            ),
        }
    )
    with pytest.raises(PlanError, match="every selected domain"):
        adapter(tmp_path).plan(broken, AuditFacts())


def test_managed_stage_rejects_a_wrong_release_digest(tmp_path):
    archive = build_release(tmp_path)
    instance = adapter(tmp_path)
    with pytest.raises(ArtifactError, match="release digest"):
        instance.stage(managed_action(tmp_path), archive)


def test_managed_stage_rejects_an_unpinned_binary_version(tmp_path):
    archive = build_release(tmp_path)
    instance = adapter(tmp_path, FakeThreeXuiRunner(version="x-ui 2.0.0"))
    with pytest.raises(ArtifactError, match="unpinned version"):
        instance.stage(pinned_action(tmp_path, archive), archive)


def test_managed_stage_extracts_only_the_reviewed_layout(tmp_path):
    archive = build_release(tmp_path)
    instance = adapter(tmp_path)

    staging, tree = instance.stage(pinned_action(tmp_path, archive), archive)

    assert (tree / "x-ui").read_bytes() == b"x-ui-binary\n"
    assert (tree / "x-ui.service").is_file()
    assert staging.is_dir()


def test_managed_stage_refuses_an_archive_outside_the_layout(tmp_path):
    archive = tmp_path / "rogue.tar.gz"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as handle:
        info = tarfile.TarInfo("x-ui/../escape")
        info.size = 2
        handle.addfile(info, io.BytesIO(b"no"))
    archive.write_bytes(buffer.getvalue())
    instance = adapter(tmp_path)

    with pytest.raises(Exception):
        instance.stage(pinned_action(tmp_path, archive), archive)


def test_managed_apply_refuses_a_preexisting_footprint(tmp_path):
    archive = build_release(tmp_path)
    database = tmp_path / PATHS.database.lstrip("/")
    database.parent.mkdir(parents=True)
    database.write_bytes(b"existing\n")
    instance = adapter(tmp_path)
    action = pinned_action(tmp_path, archive)

    with pytest.raises(ThreeXuiError, match="pre-existing database"):
        instance.prepare(action)


def test_managed_apply_refuses_a_preexisting_service_user(tmp_path):
    runner = FakeThreeXuiRunner(named={("passwd", "x-ui"): "x-ui"})
    instance = adapter(tmp_path, runner)
    with pytest.raises(ThreeXuiError, match="service user"):
        instance.prepare(managed_action(tmp_path))


def test_managed_apply_installs_and_rolls_back_one_generation(tmp_path):
    archive = build_release(tmp_path)
    runner = FakeThreeXuiRunner()
    instance = adapter(tmp_path, runner)
    action = pinned_action(tmp_path, archive)

    checkpoint = instance.apply(action, instance.prepare(action), archive=archive)

    assert (tmp_path / PATHS.binary.lstrip("/")).read_bytes() == b"x-ui-binary\n"
    assert (tmp_path / PATHS.unit.lstrip("/")).is_file()
    assert (tmp_path / PATHS.marker.lstrip("/")).is_file()
    assert instance.verify(action).success

    evidence = instance.rollback(action, checkpoint)

    assert evidence.success
    assert not (tmp_path / PATHS.root_dir.lstrip("/")).exists()
    assert not (tmp_path / PATHS.unit.lstrip("/")).exists()
    assert not (tmp_path / PATHS.marker.lstrip("/")).exists()


def test_managed_verify_rejects_an_unpinned_installed_version(tmp_path):
    archive = build_release(tmp_path)
    runner = FakeThreeXuiRunner()
    instance = adapter(tmp_path, runner)
    action = pinned_action(tmp_path, archive)
    instance.apply(action, instance.prepare(action), archive=archive)

    runner.version = "x-ui 2.0.0"
    with pytest.raises(AcceptanceError, match="pinned version"):
        instance.verify(action)


# ----------------------------------------------------------------------
# separate upgrade transaction
# ----------------------------------------------------------------------


def upgrade_target() -> ArtifactPin:
    return ArtifactPin(
        name="three_xui",
        version="3.8.0",
        tag="v3.8.0",
        repository="MHSanaei/3x-ui",
        spdx_license="GPL-3.0-only",
        architecture="amd64",
        url="https://github.com/MHSanaei/3x-ui/releases/download/v3.8.0/x-ui-linux-amd64.tar.gz",
        sha256="b" * 64,
    )


def installed_host(tmp_path: Path) -> ThreeXuiAdapter:
    write_xray_config(tmp_path, config_with_clients_and_reality_secret())
    database = tmp_path / PATHS.database.lstrip("/")
    database.parent.mkdir(parents=True, exist_ok=True)
    database.write_bytes(b"sqlite-generation-1\n")
    unit = tmp_path / PATHS.unit.lstrip("/")
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text("[Service]\nExecStart=/usr/local/x-ui/x-ui\n")
    binary = tmp_path / PATHS.binary.lstrip("/")
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(b"old-x-ui\n")
    return adapter(tmp_path)


def test_upgrade_plan_is_separate_and_never_part_of_a_normal_install(tmp_path):
    instance = installed_host(tmp_path)
    audit = instance.audit_existing()

    plan = instance.plan_existing_upgrade(upgrade_target(), audit)

    assert [action.id for action in plan.actions] == ["three_xui.upgrade"]
    assert plan.actions[0].owner == "proxy-control:three-xui-upgrade"
    normal = instance.plan(existing_config(), existing_facts())
    assert {action.owner for action in normal} == {"nginx.routes.three_xui"}


def test_upgrade_plan_requires_complete_byte_identity(tmp_path):
    instance = adapter(tmp_path)
    audit = ThreeXuiAudit(installed=True, digests={"config": "a" * 64})
    with pytest.raises(PlanError, match="byte identity"):
        instance.plan_existing_upgrade(upgrade_target(), audit)


def test_upgrade_plan_requires_an_existing_installation(tmp_path):
    with pytest.raises(PlanError, match="required to upgrade"):
        adapter(tmp_path).plan_existing_upgrade(
            upgrade_target(),
            ThreeXuiAudit(installed=False),
        )


def test_upgrade_snapshot_and_rehearsal_never_touch_the_live_database(tmp_path):
    instance = installed_host(tmp_path)
    audit = instance.audit_existing()

    snapshot = instance.snapshot_upgrade(audit)
    instance.rehearse_migration(tmp_path / "staged-x-ui", snapshot)

    live = tmp_path / PATHS.database.lstrip("/")
    assert live.read_bytes() == b"sqlite-generation-1\n"
    assert instance.runner.rehearsals
    assert PATHS.database not in instance.runner.rehearsals[0]
    assert (snapshot / "rehearsal").is_dir()


def test_upgrade_rehearsal_failure_stops_before_any_switch(tmp_path):
    instance = installed_host(tmp_path)
    instance.runner.migration_fails = True
    audit = instance.audit_existing()
    snapshot = instance.snapshot_upgrade(audit)

    with pytest.raises(ThreeXuiError, match="migration rehearsal"):
        instance.rehearse_migration(tmp_path / "staged-x-ui", snapshot)

    assert (tmp_path / PATHS.binary.lstrip("/")).read_bytes() == b"old-x-ui\n"


@pytest.mark.parametrize(
    "failure",
    ("binary_switch", "database_migration", "first_start", "acceptance"),
)
def test_upgrade_rollback_restores_a_byte_identical_generation(tmp_path, failure):
    instance = installed_host(tmp_path)
    audit = instance.audit_existing()
    snapshot = instance.snapshot_upgrade(audit)

    # Simulate each late failure by mutating exactly what that stage touches.
    if failure in {"binary_switch", "acceptance"}:
        (tmp_path / PATHS.binary.lstrip("/")).write_bytes(b"new-x-ui\n")
    if failure in {"database_migration", "first_start"}:
        (tmp_path / PATHS.database.lstrip("/")).write_bytes(b"migrated\n")

    instance.restore_upgrade(snapshot, audit)

    assert (tmp_path / PATHS.binary.lstrip("/")).read_bytes() == b"old-x-ui\n"
    assert (
        tmp_path / PATHS.database.lstrip("/")
    ).read_bytes() == b"sqlite-generation-1\n"
    assert instance.audit_existing().digests == audit.digests


def test_upgrade_restore_fails_closed_when_identity_cannot_be_restored(tmp_path):
    instance = installed_host(tmp_path)
    audit = instance.audit_existing()
    snapshot = instance.snapshot_upgrade(audit)
    (snapshot / "database").write_bytes(b"corrupted-snapshot\n")

    with pytest.raises(ThreeXuiError, match="byte-identical"):
        instance.restore_upgrade(snapshot, audit)


# ----------------------------------------------------------------------
# managed inbounds, WARP, and acceptance clients
# ----------------------------------------------------------------------


class FakeApi:
    """Records the managed dialogue without opening a socket."""

    def __init__(self, *, keep_acceptance: bool = False) -> None:
        self.added: list[str] = []
        self.deleted: list[tuple[int, str]] = []
        self.emails: list[str] = []
        self.keep_acceptance = keep_acceptance
        self._next_id = 1

    def add_inbound(self, inbound, client=None):
        del client
        self.added.append(inbound.tag)
        for item in inbound.clients:
            self.emails.append(item.email)
        identifier = self._next_id
        self._next_id += 1
        return identifier

    def delete_client(self, inbound_id, client_id):
        self.deleted.append((inbound_id, client_id))
        if not self.keep_acceptance:
            self.emails = [
                email for email in self.emails if not email.startswith("acceptance-")
            ]

    def effective_config(self):
        return {"inbounds": [], "client_emails": sorted(set(self.emails))}


class SequentialSecrets:
    def __init__(self) -> None:
        self._counter = 0

    def _next(self, label: str) -> str:
        self._counter += 1
        return f"{label}-{self._counter}"

    def client_id(self) -> str:
        self._counter += 1
        return f"00000000-0000-4000-8000-{self._counter:012d}"

    def password(self) -> str:
        return self._next("password")

    def reality_keypair(self) -> tuple[str, str]:
        return self._next("private"), self._next("public")

    def short_id(self) -> str:
        return self._next("shortid")


def test_managed_configuration_removes_every_acceptance_client(tmp_path):
    api = FakeApi()
    report = adapter(tmp_path).configure_managed(
        managed_config(),
        api,
        generator=SequentialSecrets(),
    )
    assert report["inbounds"] == 3
    assert report["acceptance_clients_removed"] == 3
    assert len(api.deleted) == 3
    assert not any(email.startswith("acceptance-") for email in api.emails)


def test_managed_configuration_fails_closed_on_a_surviving_acceptance_client(tmp_path):
    api = FakeApi(keep_acceptance=True)
    with pytest.raises(AcceptanceError, match="acceptance client is still present"):
        adapter(tmp_path).configure_managed(
            managed_config(),
            api,
            generator=SequentialSecrets(),
        )


def test_warp_is_a_separate_opt_in_action(tmp_path):
    without = adapter(tmp_path).plan(managed_config(), AuditFacts())
    assert not any(action.id == "three_xui.warp" for action in without)

    config = managed_config(warp=True)
    with_warp = InstallerConfig(
        **{
            **{name: getattr(config, name) for name in config.__dataclass_fields__},
            "three_xui": ThreeXuiConfig(
                mode=ThreeXuiMode.MANAGED_NEW,
                panel_domain="xui.example.com",
                vless_tcp_domain="vless.example.com",
                vless_xhttp_domain="xhttp.example.com",
                hysteria_domain="hysteria.example.com",
                warp=True,
                warp_domains=("openai.com",),
            ),
        }
    )
    actions = adapter(tmp_path).plan(with_warp, AuditFacts())
    warp = next(action for action in actions if action.id == "three_xui.warp")
    assert warp.owner == "proxy-control:three-xui-warp"
    assert "warp-domain=openai.com" in warp.mutations
    assert adapter(tmp_path).verify(warp).success


def test_warp_requires_confirmed_domains(tmp_path):
    with pytest.raises(PlanError, match="operator-confirmed domains"):
        adapter(tmp_path).plan(managed_config(warp=True), AuditFacts())


def test_bootstrap_rotates_credentials_inside_a_private_namespace(tmp_path):
    runner = FakeThreeXuiRunner()
    instance = adapter(tmp_path, runner)
    password = tmp_path / "password"
    password.write_text("generated-password\n")

    instance.bootstrap_credentials(
        username="operator",
        password_path=password,
        web_path="/managed/",
        port=8451,
    )

    joined = [" ".join(call) for call in runner.calls]
    assert any("ip netns add" in call for call in joined)
    assert any("NetworkNamespacePath" in call for call in joined)
    assert any("systemctl stop x-ui-bootstrap.service" in call for call in joined)
    assert not any("generated-password" in call for call in joined)
