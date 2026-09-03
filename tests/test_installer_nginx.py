from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Sequence

import pytest

from installer.adapters.nginx import (
    NginxAdapter,
    TopologyError,
    parse_effective_nginx,
    select_route_target,
)
from installer.audit import CommandRunner
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
    AuditFacts,
    InstallPlan as TransactionPlan,
    ReleaseIdentity,
)
from installer.transaction import TransactionEngine, TransactionStore

FIXTURES = Path(__file__).parent / "fixtures/nginx"
MULTI_MAP = FIXTURES / "multi-map.conf"
AMBIGUOUS_MAP = FIXTURES / "ambiguous-map.conf"


def config(host_mode: HostMode = HostMode.COEXIST) -> InstallerConfig:
    return InstallerConfig(
        schema=1,
        host_mode=host_mode,
        profile=Profile.CORE,
        acme_email="ops@example.com",
        initial_user="operator",
        domains=DomainConfig(panel="panel.example.com", mtproxy="mt.example.com"),
        mieru=None,
        three_xui=ThreeXuiConfig(mode=ThreeXuiMode.NONE),
        firewall=FirewallConfig(manage_ufw=False),
    )


def facts(observation: str = "observed") -> AuditFacts:
    return AuditFacts(topology={"nginx": {"observation": observation}})


class RecordingExecutor:
    def __init__(self, effective: str) -> None:
        self.effective = effective
        self.calls: list[tuple[str, ...]] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        max_output: int,
    ) -> subprocess.CompletedProcess[str]:
        del timeout, max_output
        command = tuple(argv)
        self.calls.append(command)
        stdout = self.effective if command == ("nginx", "-T") else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


def runner_for(text: str) -> tuple[CommandRunner, RecordingExecutor]:
    executor = RecordingExecutor(text)
    return CommandRunner(executor=executor), executor


def materialize_route(root: Path, effective: str, *, symlink: bool = False) -> Path:
    topology = parse_effective_nginx(effective)
    target = select_route_target(topology)
    route = root / target.source_file.lstrip("/")
    route.parent.mkdir(parents=True, exist_ok=True)
    route_text = effective.split(f"# configuration file {target.source_file}:\n", 1)[1]
    marker = route_text.find("# configuration file ")
    if marker >= 0:
        route_text = route_text[:marker]
    if not symlink:
        route.write_text(route_text)
        return route
    real = route.with_name("routes-real.conf")
    real.write_text(route_text)
    route.symlink_to(real.name)
    return route


def test_selects_only_map_feeding_active_443_proxy_pass() -> None:
    topology = parse_effective_nginx(MULTI_MAP.read_text())

    target = select_route_target(topology, listener_port=443)

    assert target.variable == "$proxy_control_backend"
    assert target.source_variable == "$ssl_preread_server_name"
    assert target.source_file == "/etc/nginx/stream.d/routes.conf"
    assert len(topology.maps) == 3


def test_tokenizer_ignores_comments_and_honors_quotes_and_source_markers() -> None:
    text = '''# configuration file /etc/nginx/stream.d/quoted.conf:\nmap "$ssl_preread_server_name" "$chosen" {\n  # fake } ; proxy_pass $wrong;\n  "semi;brace}" "127.0.0.1:1";\n  default "127.0.0.1:2";\n}\nserver { listen "443"; ssl_preread "on"; proxy_pass "$chosen"; }\n'''

    target = select_route_target(parse_effective_nginx(text))

    assert target.variable == "$chosen"
    assert target.source_file == "/etc/nginx/stream.d/quoted.conf"
    assert dict(target.routes)["semi;brace}"] == "127.0.0.1:1"


def test_ambiguous_active_data_path_is_hard_stop_and_byte_preserving(tmp_path: Path) -> None:
    effective = AMBIGUOUS_MAP.read_text()
    root = tmp_path / "root"
    first = root / "etc/nginx/stream.d/routes.conf"
    first.parent.mkdir(parents=True)
    first.write_text("unchanged\n")
    before = first.read_bytes()
    runner, _ = runner_for(effective)

    with pytest.raises(TopologyError, match="more than one effective map"):
        NginxAdapter(root=root, runner=runner).plan(config(), facts())

    assert first.read_bytes() == before


def test_dynamic_or_unresolved_active_proxy_pass_fails_closed() -> None:
    dynamic = """# configuration file /etc/nginx/stream.d/routes.conf:\nmap $ssl_preread_server_name $backend { default 127.0.0.1:1; }\nserver { listen 443; ssl_preread on; proxy_pass $backend:$server_port; }\n"""
    with pytest.raises(TopologyError, match="dynamic or unresolved"):
        select_route_target(parse_effective_nginx(dynamic))


def test_coexist_owns_exact_marked_block_is_idempotent_and_preserves_adjacent_routes(
    tmp_path: Path,
) -> None:
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    route = materialize_route(root, effective)
    original = route.read_bytes()
    runner, executor = runner_for(effective)
    adapter = NginxAdapter(root=root, runner=runner)
    action = adapter.plan(config(), facts())[0]
    checkpoint = adapter.prepare(action)

    applied = adapter.apply(action, checkpoint)
    first = route.read_bytes()
    adapter.reconcile_apply(action, applied)

    assert route.read_bytes() == first
    assert first.count(b"# BEGIN PROXY-CONTROL ROUTES") == 1
    assert b'"vpn.example.com" "127.0.0.1:10443";' in first
    assert b"mt.example.com 127.0.0.1:8445;" in first
    assert b"panel.example.com 127.0.0.1:8787;" in first
    assert executor.calls[-2:] == [("nginx", "-t"), ("systemctl", "reload", "nginx")]

    evidence = adapter.rollback(action, applied, rollback_target="uninstalled")
    assert evidence.success is True
    assert route.read_bytes() == original

def test_transaction_engine_allows_adjacent_foreign_route_and_removes_only_owned_block(
    tmp_path: Path,
) -> None:
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    route = materialize_route(root, effective)
    original = route.read_text()
    runner, _ = runner_for(effective)
    adapter = NginxAdapter(root=root, runner=runner)
    selected_config = config()
    selected_facts = facts()
    action = adapter.plan(selected_config, selected_facts)[0]
    plan = TransactionPlan(
        config=selected_config.canonical_dict(),
        facts=selected_facts,
        release=ReleaseIdentity(
            tag="v1.0.0",
            commit="1" * 40,
            manifest_sha256="2" * 64,
        ),
        adapter_order=("nginx",),
        adapter_dependencies={"nginx": ()},
        actions=(action,),
    )
    engine = TransactionEngine(TransactionStore(root), {"nginx": adapter})
    active = engine.apply(plan, accepted_digest=plan.digest)
    assert active.status == "active"

    route.write_text(
        route.read_text().replace(
            "    default 127.0.0.1:8443;",
            "    foreign.example.com 127.0.0.1:9443;\n"
            "    default 127.0.0.1:8443;",
        )
    )
    uninstalled = engine.uninstall(purge_data=False)

    assert uninstalled.status == "uninstalled"
    assert route.read_text() == original.replace(
        "    default 127.0.0.1:8443;",
        "    foreign.example.com 127.0.0.1:9443;\n"
        "    default 127.0.0.1:8443;",
    )
    assert "# BEGIN PROXY-CONTROL ROUTES" not in route.read_text()


def test_rollback_restores_mode_owner_content_and_symlink_identity(tmp_path: Path) -> None:
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    link = materialize_route(root, effective, symlink=True)
    target = link.resolve()
    os.chmod(target, 0o640)
    before = target.read_bytes()
    before_stat = target.stat()
    link_target = os.readlink(link)
    runner, _ = runner_for(effective)
    adapter = NginxAdapter(root=root, runner=runner)
    action = adapter.plan(config(), facts())[0]
    checkpoint = adapter.prepare(action)

    applied = adapter.apply(action, checkpoint)
    assert link.is_symlink()
    adapter.rollback(action, applied)

    restored = target.stat()
    assert link.is_symlink()
    assert os.readlink(link) == link_target
    assert target.read_bytes() == before
    assert stat.S_IMODE(restored.st_mode) == 0o640
    assert (restored.st_uid, restored.st_gid) == (before_stat.st_uid, before_stat.st_gid)
    ownership = checkpoint["route_identity"]
    assert ownership["symlink_target"] == link_target
    assert ownership["mode"] == 0o640
    assert ownership["uid"] == before_stat.st_uid
    assert ownership["gid"] == before_stat.st_gid


def test_validation_failure_restores_exact_bytes_without_reload(tmp_path: Path) -> None:
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    route = materialize_route(root, effective)
    before = route.read_bytes()

    class RejectingExecutor(RecordingExecutor):
        def __call__(self, argv: Sequence[str], *, timeout: float, max_output: int) -> subprocess.CompletedProcess[str]:
            result = super().__call__(argv, timeout=timeout, max_output=max_output)
            if tuple(argv) == ("nginx", "-t"):
                return subprocess.CompletedProcess(tuple(argv), 1, stdout="private", stderr="secret")
            return result

    executor = RejectingExecutor(effective)
    adapter = NginxAdapter(root=root, runner=CommandRunner(executor=executor))
    action = adapter.plan(config(), facts())[0]
    checkpoint = adapter.prepare(action)

    with pytest.raises(RuntimeError, match="nginx configuration test failed") as raised:
        adapter.apply(action, checkpoint)

    assert "private" not in str(raised.value)
    assert "secret" not in str(raised.value)
    assert route.read_bytes() == before
    assert ("systemctl", "reload", "nginx") not in executor.calls


def test_fresh_mode_owns_complete_generated_stream_router(tmp_path: Path) -> None:
    root = tmp_path / "root"
    runner, executor = runner_for("")
    adapter = NginxAdapter(root=root, runner=runner)
    action = adapter.plan(config(HostMode.FRESH), facts("unavailable"))[0]
    checkpoint = adapter.prepare(action)

    adapter.apply(action, checkpoint)

    generated = root / "etc/nginx/stream.d/proxy-control.conf"
    text = generated.read_text()
    assert text.startswith("# BEGIN PROXY-CONTROL GENERATED STREAM ROUTER\n")
    assert "listen 443;" in text
    assert "proxy_pass $proxy_control_backend;" in text
    assert ("nginx", "-T") not in executor.calls
    adapter.rollback(action, checkpoint)
    assert not generated.exists()
