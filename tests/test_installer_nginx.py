from __future__ import annotations

import os
import hashlib
import stat
import re
import subprocess
from pathlib import Path
from typing import Sequence

import pytest

from installer.adapters.nginx import (
    CertificatePlan,
    NginxAdapter,
    TopologyError,
    parse_effective_nginx,
    patch_owned_map,
    remove_owned_map_block,
    select_route_target,
)
from installer.audit import CommandRunner, parse_nginx_observation
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
    def __init__(self, effective: str, *, root: Path | None = None) -> None:
        self.effective = effective
        self.root = root
        self.version_output = ""
        self.calls: list[tuple[str, ...]] = []

    def _render_effective(self) -> str:
        if self.root is None:
            return self.effective
        marker = re.compile(
            r"^# configuration file (/[^:\r\n]+):(?:\r?\n|\Z)",
            re.MULTILINE,
        )
        matches = tuple(marker.finditer(self.effective))
        rendered = self.effective
        for index in range(len(matches) - 1, -1, -1):
            match = matches[index]
            path = self.root / match.group(1).lstrip("/")
            if not path.is_file():
                continue
            end = (
                matches[index + 1].start()
                if index + 1 < len(matches)
                else len(rendered)
            )
            rendered = rendered[:match.end()] + path.read_text() + rendered[end:]
        return rendered

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
        stdout = self._render_effective() if command == ("nginx", "-T") else ""
        stderr = self.version_output if command == ("nginx", "-V") else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=stderr)

class FreshExecutor(RecordingExecutor):
    def __init__(self, effective: str, *, root: Path) -> None:
        super().__init__(effective)
        self.generated_root = root

    def _render_effective(self) -> str:
        generated = (
            self.generated_root
            / "etc/nginx/stream.d/proxy-control.conf"
        )
        if not generated.is_file():
            return self.effective
        return (
            self.effective
            + "# configuration file "
            + "/etc/nginx/stream.d/proxy-control.conf:\n"
            + generated.read_text()
        )


def runner_for(
    text: str,
    *,
    root: Path | None = None,
) -> tuple[CommandRunner, RecordingExecutor]:
    executor = RecordingExecutor(text, root=root)
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
    text = '''# configuration file /etc/nginx/stream.d/quoted.conf:\nstream {\nmap "$ssl_preread_server_name" "$chosen" {\n  # fake } ; proxy_pass $wrong;\n  "semi;brace}" "127.0.0.1:1";\n  default "127.0.0.1:2";\n}\nserver { listen "443"; ssl_preread "on"; proxy_pass "$chosen"; }\n}\n'''

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
    dynamic = """stream {\nmap $ssl_preread_server_name $backend { default 127.0.0.1:1; }\nserver { listen 443; ssl_preread on; proxy_pass $backend:$server_port; }\n}\n"""
    with pytest.raises(TopologyError, match="dynamic or unresolved"):
        select_route_target(parse_effective_nginx(dynamic))


def test_coexist_owns_exact_marked_block_is_idempotent_and_preserves_adjacent_routes(
    tmp_path: Path,
) -> None:
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    route = materialize_route(root, effective)
    original = route.read_bytes()
    runner, executor = runner_for(effective, root=root)
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
    assert b"panel.example.com 127.0.0.1:8443;" in first
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
    runner, _ = runner_for(effective, root=root)
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
    runner, _ = runner_for(effective, root=root)
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

    executor = RejectingExecutor(effective, root=root)
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
    effective = (
        "# configuration file /etc/nginx/nginx.conf:\n"
        "events {}\nstream { include /etc/nginx/stream.d/*.conf; }\n"
    )
    executor = FreshExecutor(effective, root=root)
    runner = CommandRunner(executor=executor)
    adapter = NginxAdapter(root=root, runner=runner)
    action = adapter.plan(config(HostMode.FRESH), facts())[0]
    checkpoint = adapter.prepare(action)

    adapter.apply(action, checkpoint)

    generated = root / "etc/nginx/stream.d/proxy-control.conf"
    text = generated.read_text()
    assert text.startswith("# BEGIN PROXY-CONTROL GENERATED STREAM ROUTER\n")
    assert "listen 443;" in text
    assert "proxy_pass $proxy_control_backend;" in text
    assert ("nginx", "-T") in executor.calls
    adapter.rollback(action, checkpoint)
    assert not generated.exists()


def test_parser_excludes_http_maps_and_servers_from_stream_topology() -> None:
    text = """# configuration file /etc/nginx/nginx.conf:
events {}
http {
    map $host $backend { default 127.0.0.1:9000; }
    server { listen 443 ssl; proxy_pass http://app; }
}
stream { include /etc/nginx/stream.d/*.conf; }
# configuration file /etc/nginx/stream.d/routes.conf:
map $ssl_preread_server_name $backend {
    default 127.0.0.1:8443;
}
server { listen 443; ssl_preread on; proxy_pass $backend; }
"""
    topology = parse_effective_nginx(text)

    assert len(topology.maps) == 1
    assert len(topology.servers) == 1
    assert select_route_target(topology).variable == "$backend"


@pytest.mark.parametrize(
    "destination",
    ["$fallback_backend", "127.0.0.1:$dynamic_port", "named_upstream"],
)
def test_selected_map_rejects_unresolved_destination(destination: str) -> None:
    text = f"""stream {{
map $ssl_preread_server_name $backend {{ default {destination}; }}
server {{ listen 443; ssl_preread on; proxy_pass $backend; }}
}}
"""
    with pytest.raises(TopologyError, match="dynamic or unresolved"):
        select_route_target(parse_effective_nginx(text))


def test_fresh_mode_rejects_preexisting_active_stream_router(tmp_path: Path) -> None:
    runner, _ = runner_for(MULTI_MAP.read_text())
    observed = AuditFacts(
        topology={
            "nginx": {
                "observation": "observed",
                "route_target": {"source_file": "/etc/nginx/stream.d/routes.conf"},
                "stream_enabled": True,
            }
        }
    )
    with pytest.raises(TopologyError, match="active stream router"):
        NginxAdapter(root=tmp_path, runner=runner).plan(
            config(HostMode.FRESH),
            observed,
        )

def test_replanning_accepts_only_the_routes_this_generation_installs(
    tmp_path: Path,
) -> None:
    """A second install of the same generation observes its own routes, so
    planning stays possible; a route to any other backend is still foreign."""
    instance = NginxAdapter(root=tmp_path, runner=runner_for(MULTI_MAP.read_text())[0])
    generated = tmp_path / instance.fresh_path.lstrip("/")
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_text("# generated by a previous install\n")
    selected = config(HostMode.FRESH)
    intended = {
        selected.domains.mtproxy: "127.0.0.1:8445",
        selected.domains.panel: "127.0.0.1:8443",
    }
    observed = AuditFacts(
        topology={
            "nginx": {
                "observation": "observed",
                "route_target": {"source_file": instance.fresh_path},
                "sni_routes": intended,
                "stream_enabled": True,
            }
        }
    )

    actions = instance.plan(selected, observed)
    assert len(actions) == 1

    moved = AuditFacts(
        topology={
            "nginx": {
                "observation": "observed",
                "route_target": {"source_file": instance.fresh_path},
                "sni_routes": {**intended, selected.domains.panel: "127.0.0.1:9999"},
                "stream_enabled": True,
            }
        }
    )
    with pytest.raises(TopologyError, match="already routed"):
        instance.plan(selected, moved)


def test_audit_collision_routes_come_only_from_selected_active_map() -> None:
    effective = MULTI_MAP.read_text().replace(
        "default 127.0.0.1:9001;",
        "mt.example.com 127.0.0.1:9999;\n    "
        "mt.example.com 127.0.0.1:9999;\n    default 127.0.0.1:9001;",
    )

    observed = parse_nginx_observation(effective)

    assert observed["sni_routes"] == {"vpn.example.com": "127.0.0.1:10443"}
    assert observed["duplicate_sni_domains"] == ()


def test_reconcile_apply_replays_validation_reload_and_owns_backup(tmp_path: Path) -> None:
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    route = materialize_route(root, effective)
    runner, executor = runner_for(effective, root=root)
    adapter = NginxAdapter(root=root, runner=runner)
    action = adapter.plan(config(), facts())[0]
    prepared = adapter.prepare(action)
    adapter.apply(action, prepared)
    executor.calls.clear()

    reconciled = adapter.reconcile_apply(action, prepared)

    assert executor.calls == [
        ("nginx", "-T"),
        ("nginx", "-t"),
        ("systemctl", "reload", "nginx"),
    ]
    backup = root / str(reconciled["backup_path"]).lstrip("/")
    assert backup.read_bytes() != route.read_bytes()
    assert reconciled["ownership"][str(reconciled["backup_path"])]["sha256"] == hashlib.sha256(
        backup.read_bytes()
    ).hexdigest()


def test_reconcile_rollback_completes_validation_reload_and_backup_cleanup(
    tmp_path: Path,
) -> None:
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    route = materialize_route(root, effective)
    runner, executor = runner_for(effective, root=root)
    adapter = NginxAdapter(root=root, runner=runner)
    action = adapter.plan(config(), facts())[0]
    applied = adapter.apply(action, adapter.prepare(action))
    route.write_bytes(
        remove_owned_map_block(
            route.read_bytes(),
            routes=(
                ("mt.example.com", "127.0.0.1:8445"),
                ("panel.example.com", "127.0.0.1:8443"),
            ),
            ownership_id=action.id,
        )
    )
    executor.calls.clear()

    evidence = adapter.reconcile_rollback(action, applied)

    assert evidence.success is True
    assert executor.calls == [
        ("nginx", "-T"),
        ("nginx", "-t"),
        ("systemctl", "reload", "nginx"),
    ]
    assert not (root / str(applied["backup_path"]).lstrip("/")).exists()


def test_verify_and_rollback_fail_when_active_route_target_changes(tmp_path: Path) -> None:
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    route = materialize_route(root, effective)
    runner, executor = runner_for(effective, root=root)
    adapter = NginxAdapter(root=root, runner=runner)
    action = adapter.plan(config(), facts())[0]
    applied = adapter.apply(action, adapter.prepare(action))
    route.write_text(
        route.read_text().replace(
            'proxy_pass "$proxy_control_backend";',
            "proxy_pass $unused_backend;",
        )
    )
    before = route.read_bytes()

    assert adapter.verify(action).success is False
    with pytest.raises(TopologyError, match="active"):
        adapter.rollback(action, applied)
    assert route.read_bytes() == before


def test_symlink_identity_drift_is_rejected_before_verify_or_rollback(tmp_path: Path) -> None:
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    link = materialize_route(root, effective, symlink=True)
    runner, _ = runner_for(effective, root=root)
    adapter = NginxAdapter(root=root, runner=runner)
    action = adapter.plan(config(), facts())[0]
    applied = adapter.apply(action, adapter.prepare(action))
    owned = link.read_bytes()
    link.unlink()
    link.write_bytes(owned)

    assert adapter.verify(action).success is False
    with pytest.raises(TopologyError, match="path identity"):
        adapter.rollback(action, applied)


def test_checkpoint_validation_rejects_types_and_unbound_target_without_mutation(
    tmp_path: Path,
) -> None:
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    route = materialize_route(root, effective)
    runner, _ = runner_for(effective)
    adapter = NginxAdapter(root=root, runner=runner)
    action = adapter.plan(config(), facts())[0]
    checkpoint = dict(adapter.prepare(action))
    identity = dict(checkpoint["route_identity"])
    identity["mode"] = "0640"
    identity["resolved_path"] = "/etc/nginx/nginx.conf"
    checkpoint["route_identity"] = identity
    before = route.read_bytes()

    with pytest.raises(TopologyError, match="checkpoint"):
        adapter.apply(action, checkpoint)
    assert route.read_bytes() == before


def test_fresh_parent_symlink_escape_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "etc/nginx").mkdir(parents=True)
    (root / "etc/nginx/stream.d").symlink_to(outside, target_is_directory=True)
    effective = (
        "# configuration file /etc/nginx/nginx.conf:\n"
        "events {}\nstream { include /etc/nginx/stream.d/*.conf; }\n"
    )
    runner, _ = runner_for(effective)
    adapter = NginxAdapter(root=root, runner=runner)
    with pytest.raises(TopologyError, match="escapes"):
        adapter.plan(config(HostMode.FRESH), facts())
    assert list(outside.iterdir()) == []

def test_balanced_source_marker_must_match_named_file_bytes(
    tmp_path: Path,
) -> None:
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    route = materialize_route(root, effective)
    before = route.read_bytes()
    spoofed = effective.replace(
        '"vpn.example.com" "127.0.0.1:10443";',
        '"spoof.example.com" "127.0.0.1:10443";',
    )
    runner, _ = runner_for(spoofed)

    with pytest.raises(TopologyError, match="source marker"):
        NginxAdapter(root=root, runner=runner).plan(config(), facts())
    assert route.read_bytes() == before

def test_source_authentication_preserves_crlf_bytes(tmp_path: Path) -> None:
    source_file = "/etc/nginx/stream.d/routes.conf"
    source = (
        "map $ssl_preread_server_name $backend {\r\n"
        "    default 127.0.0.1:8443;\r\n"
        "}\r\n"
        "server {\r\n"
        "    listen 443;\r\n"
        "    ssl_preread on;\r\n"
        "    proxy_pass $backend;\r\n"
        "}\r\n"
    )
    effective = (
        "# configuration file /etc/nginx/nginx.conf:\r\n"
        "events {}\r\n"
        "stream { include /etc/nginx/stream.d/*.conf; }\r\n"
        f"# configuration file {source_file}:\r\n"
        f"{source}"
    )
    root = tmp_path / "root"
    route = root / source_file.lstrip("/")
    route.parent.mkdir(parents=True)
    route.write_bytes(source.encode())
    runner, _ = runner_for(effective)

    action = NginxAdapter(root=root, runner=runner).plan(config(), facts())[0]

    assert f"target={source_file}" in action.mutations


def test_fresh_requires_included_path_and_proves_post_write_active_route(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    effective = """# configuration file /etc/nginx/nginx.conf:
events {}
stream { include /etc/nginx/stream.d/*.conf; }
"""

    executor = FreshExecutor(effective, root=root)
    adapter = NginxAdapter(
        root=root,
        runner=CommandRunner(executor=executor),
    )
    observed = AuditFacts(
        topology={
            "nginx": {
                "observation": "observed",
                "route_target": None,
                "stream_enabled": True,
            }
        }
    )
    action = adapter.plan(config(HostMode.FRESH), observed)[0]
    checkpoint = adapter.prepare(action)

    adapter.apply(action, checkpoint)

    assert executor.calls[-3:] == [
        ("nginx", "-T"),
        ("nginx", "-t"),
        ("systemctl", "reload", "nginx"),
    ]
    assert adapter.verify(action).success is True

def test_fresh_restores_file_when_generated_route_is_not_effective(
    tmp_path: Path,
) -> None:
    effective = (
        "# configuration file /etc/nginx/nginx.conf:\n"
        "events {}\nstream { include /etc/nginx/stream.d/*.conf; }\n"
    )
    runner, executor = runner_for(effective)
    adapter = NginxAdapter(root=tmp_path, runner=runner)
    action = adapter.plan(config(HostMode.FRESH), facts())[0]
    checkpoint = adapter.prepare(action)

    with pytest.raises(TopologyError, match="active 443 path"):
        adapter.apply(action, checkpoint)

    generated = tmp_path / "etc/nginx/stream.d/proxy-control.conf"
    assert not generated.exists()
    assert ("nginx", "-t") not in executor.calls


@pytest.mark.parametrize(
    ("observation", "effective"),
    [
        ("unavailable", ""),
        (
            "observed",
            "# configuration file /etc/nginx/nginx.conf:\n"
            "events {}\nstream {}\n",
        ),
    ],
)
def test_fresh_rejects_unproven_or_ignored_generated_path(
    tmp_path: Path,
    observation: str,
    effective: str,
) -> None:
    runner, _ = runner_for(effective)
    observed = AuditFacts(
        topology={
            "nginx": {
                "observation": observation,
                "route_target": None,
                "stream_enabled": observation == "observed",
            }
        }
    )
    with pytest.raises(TopologyError, match="included"):
        NginxAdapter(root=tmp_path, runner=runner).plan(
            config(HostMode.FRESH),
            observed,
        )


def test_embedded_source_marker_cannot_redirect_selected_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    real = root / "etc/nginx/nginx.conf"
    decoy = root / "tmp/decoy.conf"
    real.parent.mkdir(parents=True)
    decoy.parent.mkdir(parents=True)
    real.write_text(
        "events {}\nstream {\n"
        "map $ssl_preread_server_name $backend { default 127.0.0.1:8443; }\n"
        "server { listen 443; ssl_preread on; proxy_pass $backend; }\n"
        "}\n"
    )
    decoy.write_text(
        "map $ssl_preread_server_name $backend { default 127.0.0.1:8443; }\n"
    )
    effective = (
        "# configuration file /etc/nginx/nginx.conf:\n"
        "events {}\nstream {\n"
        "# configuration file /tmp/decoy.conf:\n"
        "map $ssl_preread_server_name $backend { default 127.0.0.1:8443; }\n"
        "server { listen 443; ssl_preread on; proxy_pass $backend; }\n"
        "}\n"
    )
    runner, _ = runner_for(effective)
    before = decoy.read_bytes()

    with pytest.raises(TopologyError, match="source marker"):
        NginxAdapter(root=root, runner=runner).plan(config(), facts())
    assert decoy.read_bytes() == before


def test_stream_globs_are_segment_aware_and_relative_to_nginx_prefix() -> None:
    effective = """# configuration file /etc/nginx/nginx.conf:
events {}
stream { include stream.d/*.conf; }
http { include /etc/nginx/stream.d/nested/*.conf; }
# configuration file /etc/nginx/stream.d/routes.conf:
map $ssl_preread_server_name $stream_backend { default 127.0.0.1:8443; }
server { listen 443; ssl_preread on; proxy_pass $stream_backend; }
# configuration file /etc/nginx/stream.d/nested/http.conf:
map $host $http_backend { default 127.0.0.1:9000; }
server { listen 443 ssl; }
"""
    topology = parse_effective_nginx(effective)


    assert len(topology.maps) == 1
    assert len(topology.servers) == 1
    assert select_route_target(topology).variable == "$stream_backend"


def test_relative_include_with_multiple_possible_prefixes_fails_closed() -> None:
    effective = """# configuration file /etc/nginx/nginx.conf:
events {}
stream { include stream.d/*.conf; }
http { include /etc/http/stream.d/*.conf; }
# configuration file /opt/nginx/stream.d/routes.conf:
map $ssl_preread_server_name $stream_backend { default 127.0.0.1:8443; }
server { listen 443; ssl_preread on; proxy_pass $stream_backend; }
# configuration file /etc/http/stream.d/http.conf:
map $host $http_backend { default 127.0.0.1:9000; }
"""

    with pytest.raises(TopologyError, match="prefix is ambiguous"):
        parse_effective_nginx(effective)


def test_fresh_relative_include_uses_reported_nginx_prefix(
    tmp_path: Path,
) -> None:
    effective = (
        "# configuration file /etc/nginx/nginx.conf:\n"
        "events {}\nstream { include stream.d/*.conf; }\n"
    )
    executor = RecordingExecutor(effective)
    executor.version_output = (
        "nginx version: nginx/1.26.0\n"
        "configure arguments: --prefix=/opt/nginx "
        "--conf-path=/etc/nginx/nginx.conf"
    )
    adapter = NginxAdapter(
        root=tmp_path,
        runner=CommandRunner(executor=executor),
        fresh_path="/opt/nginx/stream.d/proxy-control.conf",
    )

    action = adapter.plan(config(HostMode.FRESH), facts())[0]

    assert "target=/opt/nginx/stream.d/proxy-control.conf" in action.mutations
    assert ("nginx", "-V") in executor.calls


def test_patch_targets_sni_map_when_http_map_shares_destination_variable() -> None:
    text = """http {
map $host $backend { default 127.0.0.1:9000; }
}
stream {
map $ssl_preread_server_name $backend { default 127.0.0.1:8443; }
server { listen 443; ssl_preread on; proxy_pass $backend; }
}
"""
    changed = patch_owned_map(
        text,
        variable="$backend",
        routes=(("mt.example.com", "127.0.0.1:8445"),),
        ownership_id="selected",
    )

    http, stream = changed.split("stream {", 1)
    assert "# BEGIN PROXY-CONTROL ROUTES" not in http
    assert "# BEGIN PROXY-CONTROL ROUTES selected" in stream


def test_source_authentication_tolerates_only_the_separator_nginx_adds(
    tmp_path: Path,
) -> None:
    """`nginx -T` prints a blank line after each file; nothing else may differ."""
    source_file = "/etc/nginx/stream.d/routes.conf"
    body = (
        "map $ssl_preread_server_name $shared_backend {\n"
        "    old-xray.lab.test 127.0.0.1:9443;\n"
        "    default 127.0.0.1:9443;\n"
        "}\n"
        "server { listen 443; proxy_pass $shared_backend; ssl_preread on; }\n"
    )
    root = tmp_path / "root"
    route = root / source_file.lstrip("/")
    route.parent.mkdir(parents=True)
    route.write_text(body)

    def effective(section: str) -> str:
        return (
            "# configuration file /etc/nginx/nginx.conf:\n"
            "events {}\nstream { include /etc/nginx/stream.d/*.conf; }\n"
            "\n"
            f"# configuration file {source_file}:\n"
            f"{section}"
            "# configuration file /etc/nginx/sites-enabled/default:\n"
            "server { listen 8080; }\n"
        )

    adapter = NginxAdapter(root=root, runner=runner_for(effective(body + "\n"))[0])
    adapter._authenticate_source(effective(body + "\n"), source_file)
    adapter._authenticate_source(effective(body), source_file)

    with pytest.raises(TopologyError, match="source marker"):
        adapter._authenticate_source(effective(body + "\n\n"), source_file)
    with pytest.raises(TopologyError, match="source marker"):
        adapter._authenticate_source(
            effective(body.replace("9443", "9444") + "\n"),
            source_file,
        )


def test_route_specification_accepts_every_profile_route_set(tmp_path: Path) -> None:
    """A profile with NaiveProxy plans three routes; the parser must take them."""
    from installer.adapters.nginx import _action_specification
    from installer.planner import Action

    def action_with(routes: tuple[tuple[str, str], ...]) -> Action:
        return Action(
            id="nginx.routes",
            adapter="nginx",
            owner="proxy-control:nginx",
            mutations=(
                "mode=coexist",
                "target=/etc/nginx/stream.d/routes.conf",
                "variable=$shared_backend",
                "path_kind=file",
                "resolved_path=/etc/nginx/stream.d/routes.conf",
                "symlink_target=-",
                *(f"route={domain} {backend}" for domain, backend in routes),
            ),
            preconditions=("effective topology is observed",),
            verification=("configuration test passes",),
            inverse=("restore content",),
            credentials_required=False,
        )

    two = (
        ("proxy.example.com", "127.0.0.1:8445"),
        ("panel.example.com", "127.0.0.1:8787"),
    )
    three = two + (("naive.example.com", "127.0.0.1:4443"),)
    assert len(_action_specification(action_with(two))["routes"]) == 2
    assert len(_action_specification(action_with(three))["routes"]) == 3

    with pytest.raises(TopologyError, match="malformed"):
        _action_specification(action_with(two[:1]))
    with pytest.raises(TopologyError, match="malformed"):
        _action_specification(action_with(two + (two[0],)))


def test_owned_http01_vhost_accepts_only_the_separator_nginx_adds(
    tmp_path: Path,
) -> None:
    """The same `nginx -T` separator rule applies to the HTTP-01 vhost."""
    host_path = "/etc/nginx/conf.d/proxy-control-acme-proxy-control.conf"
    body = (
        "server {\n"
        "    listen 80;\n"
        "    server_name proxy.example.com;\n"
        "    root /var/www/proxy.example.com;\n"
        "}\n"
    )

    def effective(section: str) -> str:
        return (
            "# configuration file /etc/nginx/nginx.conf:\n"
            "events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\n"
            "\n"
            f"# configuration file {host_path}:\n"
            f"{section}"
        )

    plan = CertificatePlan(root=tmp_path, runner=runner_for(effective(body))[0])
    plan._assert_vhost_effective(host_path, body.encode())

    plan.runner = runner_for(effective(body + "\n"))[0]
    plan._assert_vhost_effective(host_path, body.encode())

    plan.runner = runner_for(effective(body + "\n\n"))[0]
    with pytest.raises(TopologyError, match="absent from effective"):
        plan._assert_vhost_effective(host_path, body.encode())


def test_replanning_rejects_a_domain_served_only_over_http(tmp_path: Path) -> None:
    """A foreign HTTP vhost for one of our domains has no route of ours behind
    it, and must still stop a plan."""
    instance = NginxAdapter(root=tmp_path, runner=runner_for(MULTI_MAP.read_text())[0])
    selected = config(HostMode.COEXIST)
    observed = AuditFacts(
        topology={
            "nginx": {
                "observation": "observed",
                "route_target": {"source_file": "/etc/nginx/stream.d/routes.conf"},
                "sni_routes": {},
                "http_domains": (selected.domains.panel,),
                "stream_enabled": True,
            }
        }
    )
    with pytest.raises(TopologyError, match="already routed"):
        instance.plan(selected, observed)


def test_apply_re_entered_after_its_own_write_is_a_no_op(tmp_path: Path) -> None:
    """A resume can re-enter apply after the write landed: the file then holds
    this action's own output, and the original backup must survive."""
    effective = MULTI_MAP.read_text()
    root = tmp_path / "root"
    route = materialize_route(root, effective)
    runner, _executor = runner_for(effective, root=root)
    adapter = NginxAdapter(root=root, runner=runner)
    action = adapter.plan(config(), facts())[0]
    checkpoint = adapter.prepare(action)
    applied = adapter.apply(action, checkpoint)

    written = route.read_bytes()
    backup = root / str(applied["backup_path"]).lstrip("/")
    saved = backup.read_bytes()

    adapter.apply(action, checkpoint)

    assert route.read_bytes() == written
    assert backup.read_bytes() == saved

    # Content outside the owned block is preserved by the patch, so a shared
    # file may legitimately change; losing the owned block is real drift.
    route.write_bytes(written + b"\n# appended by someone else\n")
    adapter.apply(action, checkpoint)
    assert b"# appended by someone else" in route.read_bytes()

    # An edit inside the owned block is still refused rather than overwritten.
    route.write_bytes(written.replace(b"127.0.0.1:8445", b"127.0.0.1:9999"))
    with pytest.raises(TopologyError):
        adapter.apply(action, checkpoint)
