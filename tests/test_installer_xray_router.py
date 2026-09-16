"""The installer's Xray-router adapter (v0.5): a staged, pinned archive becomes the
router's binaries, identity, secrets, state and Compose service — and nothing else."""
from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path
from types import MappingProxyType

import pytest

from installer.adapters import xray_router as module
from installer.adapters.xray_router import (
    _XRAY_PINS,
    ArtifactError,
    XrayRouterAdapter,
    XrayRouterError,
    XrayRouterPaths,
    ingress_credential,
)
from installer.model import (
    DomainConfig,
    EgressChoice,
    EgressConfig,
    FirewallConfig,
    HostMode,
    InstallerConfig,
    MieruConfig,
    Profile,
    ThreeXuiConfig,
    ThreeXuiMode,
)
from installer.planner import Action, AuditFacts, PlanError
from installer.release import MemberPin, ReleaseManifest

ROOT = Path(__file__).resolve().parents[1]
PATHS = XrayRouterPaths()
MEMBER_BYTES = {"xray": b"#!/bin/sh\nexit 0\n", "geoip.dat": b"geoip\n", "geosite.dat": b"geosite\n"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def config(*, profile: Profile = Profile.FULL, warp: bool = False, router: bool = True) -> InstallerConfig:
    return InstallerConfig(
        schema=1, host_mode=HostMode.FRESH, profile=profile, acme_email="ops@example.com", initial_user="owner",
        domains=DomainConfig(panel="panel.example.com", mtproxy="proxy.example.com",
                             naive="edge.example.com" if profile.includes_naive else None,
                             mieru="mieru.example.com" if profile.includes_mieru else None),
        mieru=MieruConfig(tcp_ports=(46001,), udp_ports=(46002,)) if profile.includes_mieru else None,
        three_xui=ThreeXuiConfig(mode=ThreeXuiMode.NONE, warp=warp), firewall=FirewallConfig(manage_ufw=False),
        egress=EgressConfig(warp=warp, router=router, naive=EgressChoice.ROUTER if router and profile.includes_naive else EgressChoice.DIRECT),
    )


@pytest.fixture(autouse=True)
def pinned_archive(monkeypatch):
    """Pin the adapter to the stand-in archive these tests stage."""
    members = MappingProxyType({name: MemberPin(_sha(data), len(data), 0o755 if name == "xray" else 0o644)
                                for name, data in MEMBER_BYTES.items()})
    archive = _archive_bytes()
    monkeypatch.setattr(module, "_XRAY_PINS", MappingProxyType(
        {"amd64": ("https://example.invalid/Xray-linux-64.zip", _sha(archive), members)}))


def _archive_bytes(members: dict[str, bytes] | None = None) -> bytes:
    """A reproducible archive: fixed member timestamps, so the digest the fixture pins is
    the digest of every archive these tests stage."""
    import io
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name, data in {**(members or MEMBER_BYTES), "README.md": b"# never extracted"}.items():
            bundle.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), data)
    return buffer.getvalue()


def stage_archive(root: Path, data: bytes | None = None) -> Path:
    archive = root / "var/lib/proxy-control/Xray-linux-64.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(data if data is not None else _archive_bytes())
    return archive


class FakeRunner:
    def __init__(self, *, status: dict | None = None, listener: bool = True, probe: bool = True,
                 identities: dict[tuple[str, int], str] | None = None, fail_on: tuple[str, ...] | None = None):
        self.status = status if status is not None else {
            "xray_version": "Xray 26.3.27", "phase": "idle",
            "artifacts": {name: {"verified": True} for name in ("xray", "geoip", "geosite")},
            "running": {"generation": 1, "digest": "a" * 64},
        }
        self.listener = listener
        self.probe = probe
        self.identities = dict(identities or {})
        self.fail_on = fail_on
        self.named: dict[tuple[str, str], str] = {}
        self.calls: list[tuple[str, ...]] = []
        self.compose_present = False
        self.probed: list[tuple[int, str]] = []

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
        if command[:1] == ("userdel",):
            self.named.pop(("passwd", command[-1]), None)
        if command[:1] == ("groupdel",):
            self.named.pop(("group", command[-1]), None)
        if "up" in command:
            self.compose_present = True
        if "rm" in command and "--stop" in command:
            self.compose_present = False

    def identity_owner(self, kind, identifier):
        return self.identities.get((kind, identifier))

    def identity_named(self, database, name):
        return self.named.get((database, name))

    def compose_service_present(self, service):
        return self.compose_present and service == "xray-router"

    def router_status(self):
        return self.status

    def loopback_listener(self, port):
        return self.listener

    def ingress_probe(self, port, credential_file):
        self.probed.append((port, credential_file))
        return self.probe


def adapter(tmp_path: Path, runner: FakeRunner | None = None) -> XrayRouterAdapter:
    return XrayRouterAdapter(root=tmp_path, source_dir=ROOT, runner=runner or FakeRunner())


def action_for(tmp_path: Path, **kwargs) -> Action:
    (actions,) = adapter(tmp_path).plan(config(**kwargs), AuditFacts())
    return actions


def host(tmp_path: Path, absolute: str) -> Path:
    return tmp_path / absolute.lstrip("/")


# -- pins ----------------------------------------------------------------------


def test_hardcoded_pins_match_the_release_catalogue():
    # `_XRAY_PINS` was bound at import, before the fixture replaced the module attribute.
    manifest = ReleaseManifest.from_bytes((ROOT / "release/external-artifacts.json").read_bytes())
    pin = manifest.external_artifact("xray", "amd64")
    url, digest, members = _XRAY_PINS["amd64"]
    assert (pin.url, pin.sha256) == (url, digest)
    assert dict(pin.members) == dict(members)
    from installer.model import ROUTER_PORTS
    from xray_router_manager.intent import PORTS

    assert ROUTER_PORTS == PORTS


# -- planning ------------------------------------------------------------------


def test_plan_is_deterministic_and_secret_free(tmp_path):
    first = adapter(tmp_path).plan(config(warp=True), AuditFacts())
    second = adapter(tmp_path).plan(config(warp=True), AuditFacts())
    assert first == second and len(first) == 1
    action = first[0]
    assert action.id == "xray_router.runtime" and action.adapter == "xray_router"
    values = dict(item.split("=", 1) for item in action.mutations)
    assert values["archive"] == "/var/lib/proxy-control/Xray-linux-64.zip"
    assert values["port-naive"] == "45101" and values["port-mieru"] == "45102"
    assert values["warp-provider"] == "socks5://127.0.0.1:40000"
    assert values["router-uid"] == "10006"
    assert not any("token" in item or "password" in item for item in action.mutations)
    assert adapter(tmp_path).plan(config(router=False), AuditFacts()) == ()


def test_plan_refuses_foreign_identity_and_claimed_ports(tmp_path):
    facts = AuditFacts(ownership={"identities": {"uid": {"10006": "someone"}}})
    with pytest.raises(PlanError, match="UID 10006 collision"):
        adapter(tmp_path).plan(config(), facts)
    facts = AuditFacts(listeners={"tcp": [45101], "owners": {"45101": ["nginx"]}})
    with pytest.raises(PlanError, match="45101 is already claimed"):
        adapter(tmp_path).plan(config(), facts)
    facts = AuditFacts(listeners={"tcp": [45101], "owners": {"45101": ["xray"]}})
    assert len(adapter(tmp_path).plan(config(), facts)) == 1


# -- prepare -------------------------------------------------------------------


def test_prepare_refuses_missing_or_mismatched_archive(tmp_path):
    action = action_for(tmp_path)
    with pytest.raises(ArtifactError, match="stage the pinned Xray archive as /var/lib/proxy-control/Xray-linux-64.zip"):
        adapter(tmp_path).prepare(action)
    stage_archive(tmp_path, _archive_bytes({**MEMBER_BYTES, "xray": b"tampered\n"}))
    with pytest.raises(ArtifactError, match="digest does not match"):
        adapter(tmp_path).prepare(action)


# -- apply ---------------------------------------------------------------------


def test_apply_installs_binaries_state_secrets_env_and_starts_service(tmp_path):
    stage_archive(tmp_path)
    runner = FakeRunner()
    instance = adapter(tmp_path, runner)
    action = action_for(tmp_path, warp=True)
    checkpoint = instance.prepare(action)
    assert checkpoint["adoption"] == "absent" and checkpoint["secrets_preexisting"]["manager_token"] is False
    applied = instance.apply(action, checkpoint)

    bin_dir = host(tmp_path, PATHS.bin_dir)
    for name, data in MEMBER_BYTES.items():
        assert (bin_dir / name).read_bytes() == data
    assert stat.S_IMODE((bin_dir / "xray").stat().st_mode) == 0o755
    assert stat.S_IMODE((bin_dir / "geosite.dat").stat().st_mode) == 0o644
    assert stat.S_IMODE(bin_dir.stat().st_mode) == 0o755
    assert not (bin_dir / "README.md").exists()

    token = host(tmp_path, PATHS.manager_token)
    assert len(token.read_text().strip()) == 64 and stat.S_IMODE(token.stat().st_mode) == 0o600
    for service in ("naive", "mieru"):
        credential = host(tmp_path, PATHS.ingress(service)).read_text().strip()
        assert module._CREDENTIAL.fullmatch(credential) and credential.startswith(f"{service}-")
    env = host(tmp_path, PATHS.env_overlay).read_text()
    assert f"XRAY_ROUTER_XRAY_SHA256={_sha(MEMBER_BYTES['xray'])}" in env
    assert "XRAY_ROUTER_EGRESS_WARP=socks5://127.0.0.1:40000" in env
    assert host(tmp_path, PATHS.marker).read_text().strip() == checkpoint["marker_value"]
    assert host(tmp_path, PATHS.state_preparer).is_file() and host(tmp_path, PATHS.rotator).is_file()

    assert ("groupadd", "--system", "--gid", "10006", "xray-router") in runner.calls
    assert any(call[:1] == ("useradd",) and call[-1] == "xray-router" and "10006" in call for call in runner.calls)
    assert (PATHS.state_preparer, "prepare", PATHS.state_dir) in runner.calls
    compose = [call for call in runner.calls if call[:2] == ("docker", "compose")]
    assert compose and compose[-1][-5:] == ("up", "-d", "--build", "--wait", "xray-router")
    assert f"{PATHS.project_dir}/compose.xray-router.yaml" in compose[-1]
    assert applied["identities_created"] == {"group": True, "user": True}
    assert set(applied["ownership"]) >= {PATHS.env_overlay, PATHS.marker, f"{PATHS.bin_dir}/xray"}


def test_apply_keeps_existing_secrets_and_rides_the_sibling_overlays(tmp_path):
    stage_archive(tmp_path)
    for name in ("manager-token", "ingress-naive", "ingress-mieru"):
        path = host(tmp_path, f"{PATHS.project_dir}/secrets/xray-router-{name}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(("f" * 64 if name == "manager-token" else "naive-cafe0001:" + "k" * 43) + "\n")
        path.chmod(0o600)
    host(tmp_path, f"{PATHS.project_dir}/.env.naive").write_text("NAIVE_PUBLIC_HOST=edge.example.com\n")
    runner = FakeRunner()
    instance = adapter(tmp_path, runner)
    action = action_for(tmp_path)
    checkpoint = instance.prepare(action)
    assert checkpoint["secrets_preexisting"] == {"manager_token": True, "ingress_naive": True, "ingress_mieru": True}
    instance.apply(action, checkpoint)
    assert host(tmp_path, PATHS.manager_token).read_text().strip() == "f" * 64
    assert host(tmp_path, PATHS.ingress("naive")).read_text().strip().startswith("naive-cafe0001:")
    compose = [call for call in runner.calls if call[:2] == ("docker", "compose")][-1]
    assert f"{PATHS.project_dir}/compose.naive.yaml" in compose and f"{PATHS.project_dir}/compose.mieru.yaml" not in compose
    assert "XRAY_ROUTER_EGRESS_WARP=\n" in host(tmp_path, PATHS.env_overlay).read_text()


def test_apply_refuses_a_world_readable_secret(tmp_path):
    stage_archive(tmp_path)
    path = host(tmp_path, PATHS.manager_token)
    path.parent.mkdir(parents=True)
    path.write_text("f" * 64 + "\n")
    path.chmod(0o644)
    instance = adapter(tmp_path)
    action = action_for(tmp_path)
    with pytest.raises(XrayRouterError, match="secrets are unsafe"):
        instance.apply(action, instance.prepare(action))


def test_apply_rejects_a_foreign_checkpoint(tmp_path):
    stage_archive(tmp_path)
    instance = adapter(tmp_path)
    action = action_for(tmp_path)
    checkpoint = dict(instance.prepare(action))
    with pytest.raises(XrayRouterError, match="checkpoint is invalid"):
        instance.apply(action, {**checkpoint, "marker_value": "not-hex"})
    with pytest.raises(XrayRouterError, match="checkpoint is invalid"):
        instance.apply(action, {**checkpoint, "extra": True})


# -- verify --------------------------------------------------------------------


def _applied(tmp_path: Path, runner: FakeRunner) -> tuple[XrayRouterAdapter, Action]:
    stage_archive(tmp_path)
    instance = adapter(tmp_path, runner)
    action = action_for(tmp_path)
    instance.apply(action, instance.prepare(action))
    return instance, action


def test_verify_reads_status_over_uds(tmp_path):
    runner = FakeRunner()
    instance, action = _applied(tmp_path, runner)
    evidence = instance.verify(action)
    assert evidence.success and evidence.details["generation"] == 1
    assert evidence.details["ports"] == {"naive": 45101, "mieru": 45102}
    assert runner.probed == [(45101, str(host(tmp_path, PATHS.ingress("naive"))))]


@pytest.mark.parametrize("change, message", [
    ({"phase": "broken"}, "not running a committed generation"),
    ({"running": None}, "not running a committed generation"),
    ({"artifacts": {"xray": {"verified": False}, "geoip": {"verified": True}, "geosite": {"verified": True}}}, "has not verified its artifacts"),
])
def test_verify_refuses_an_unhealthy_manager(tmp_path, change, message):
    runner = FakeRunner()
    instance, action = _applied(tmp_path, runner)
    runner.status = {**runner.status, **change}
    with pytest.raises(XrayRouterError, match=message):
        instance.verify(action)


def test_verify_refuses_public_listener_or_dead_ingress(tmp_path):
    runner = FakeRunner(listener=False)
    instance, action = _applied(tmp_path, runner)
    with pytest.raises(XrayRouterError, match="loopback only"):
        instance.verify(action)
    runner = FakeRunner(probe=False)
    instance, action = _applied(tmp_path, runner)
    with pytest.raises(XrayRouterError, match="did not reach the Internet"):
        instance.verify(action)


def test_verify_refuses_a_drifted_member(tmp_path):
    instance, action = _applied(tmp_path, FakeRunner())
    (host(tmp_path, PATHS.bin_dir) / "geoip.dat").write_bytes(b"drift\n")
    with pytest.raises(ArtifactError, match="does not match its pin: geoip.dat"):
        instance.verify(action)


# -- rollback / repair ---------------------------------------------------------


def test_rollback_purges_only_owned_paths(tmp_path):
    runner = FakeRunner()
    stage_archive(tmp_path)
    instance = adapter(tmp_path, runner)
    action = action_for(tmp_path)
    checkpoint = instance.apply(action, instance.prepare(action))
    state = host(tmp_path, PATHS.state_dir)
    state.mkdir(parents=True, exist_ok=True)
    (state / "current.json").write_text("{}")
    foreign = host(tmp_path, f"{PATHS.project_dir}/secrets/panel-master-key")
    foreign.write_text("keep\n")

    evidence = instance.rollback(action, checkpoint)
    assert evidence.success and evidence.details["persistent_data_preserved"] is True
    assert ("docker", "compose") == [call for call in runner.calls if "rm" in call][-1][:2]
    assert not host(tmp_path, PATHS.bin_dir).exists()
    assert not host(tmp_path, PATHS.env_overlay).exists() and not host(tmp_path, PATHS.marker).exists()
    assert not host(tmp_path, PATHS.state_preparer).exists()
    assert host(tmp_path, PATHS.manager_token).exists() and (state / "current.json").exists()
    assert foreign.read_text() == "keep\n"
    assert host(tmp_path, PATHS.archive).exists()  # the operator's staged artifact is theirs

    evidence = instance.rollback(action, checkpoint, purge_data=True, rollback_target="uninstalled")
    assert evidence.details["identities_removed"] is True
    assert not host(tmp_path, PATHS.manager_token).exists() and not state.exists()
    assert ("userdel", "xray-router") in runner.calls and ("groupdel", "xray-router") in runner.calls
    assert foreign.read_text() == "keep\n"


def test_repair_verifies_state_and_restarts_the_service(tmp_path):
    runner = FakeRunner()
    stage_archive(tmp_path)
    instance = adapter(tmp_path, runner)
    action = action_for(tmp_path)
    checkpoint = instance.apply(action, instance.prepare(action))
    runner.calls.clear()
    instance.repair(action, checkpoint)
    assert (PATHS.state_preparer, "verify", PATHS.state_dir) in runner.calls
    assert runner.calls[-1][-4:] == ("up", "-d", "--wait", "xray-router")


def test_ingress_credential_shape():
    for service in ("naive", "mieru"):
        value = ingress_credential(service)
        assert module._CREDENTIAL.fullmatch(value) and value.startswith(f"{service}-")
        user, _, password = value.partition(":")
        assert len(user) == len(service) + 9 and len(password) == 43


def test_healthcheck_status_flag_prints_the_manager_status(tmp_path, monkeypatch):
    """`docker exec … healthcheck --status` is what the installer's verify parses."""
    import socket
    import threading

    from xray_router_manager import healthcheck

    sock = tmp_path / "manager.sock"
    token = tmp_path / "token"
    token.write_text("t" * 40 + "\n")
    body = json.dumps({"phase": "idle", "running": {"generation": 1}}).encode()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock))
    server.listen(1)
    seen: list[bytes] = []

    def serve():
        with server:
            client, _ = server.accept()
            with client:
                seen.append(client.recv(4096))
                client.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + body)

    thread = threading.Thread(target=serve)
    thread.start()
    monkeypatch.setenv("XRAY_ROUTER_SOCKET", str(sock))
    monkeypatch.setenv("XRAY_ROUTER_MANAGER_TOKEN_FILE", str(token))
    import io
    import sys

    buffer = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(buffer))
    with pytest.raises(SystemExit) as raised:
        healthcheck.main(["--status"])
    thread.join(timeout=5)
    assert raised.value.code == 0
    assert b"GET /v1/status" in seen[0] and b"X-Xray-Router-Token: " + b"t" * 40 in seen[0]
    sys.stdout.flush()
    assert json.loads(buffer.getvalue()) == {"phase": "idle", "running": {"generation": 1}}
    assert healthcheck.status(sock, token) is None  # nobody listens any more
