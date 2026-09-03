from __future__ import annotations

import fcntl
import json
import os
import stat
from pathlib import Path

import pytest

from installer.audit import AuditFacts, parse_nginx_observation

from scripts.proxyctl import (
    InstallPlan,
    InstallerConflict,
    apply_plan,
    repair_installation,
    uninstall_installation,
)


def host_root(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "root"
    route = root / "etc/nginx/stream.d/routes.conf"
    route.parent.mkdir(parents=True)
    (root / "etc/nginx/sites-enabled").mkdir(parents=True)
    (root / "etc/nginx/nginx.conf").write_text(
        "events {}\nhttp { include /etc/nginx/sites-enabled/*; }\n"
        "stream { include /etc/nginx/stream.d/*.conf; }\n"
    )
    route.write_text(
        "map $ssl_preread_server_name $upstream_443 {\n"
        "    vpn.example.com 127.0.0.1:10443;\n"
        "    default 127.0.0.1:8443;\n}\n"
        "server { listen 443; ssl_preread on; proxy_pass $upstream_443; }\n"
    )
    return root, route


def facts_from_root(
    root: Path,
    *,
    listening_ports: set[int],
    listener_owners: dict[int, list[str]] | None = None,
    docker_available: bool,
    dns_records: dict[str, dict[str, list[str]]] | None = None,
    local_addresses: set[str] | None = None,
    tls_names: set[str] | None = None,
) -> AuditFacts:
    candidates: list[Path] = [root / "etc/nginx/nginx.conf"]
    for relative in (
        "etc/nginx/stream.d",
        "etc/nginx/stream-conf.d",
        "etc/nginx/conf.d",
        "etc/nginx/sites-enabled",
    ):
        directory = root / relative
        if directory.is_dir():
            candidates.extend(sorted(directory.iterdir()))
    chunks: list[str] = []
    seen: set[tuple[int, int]] = set()
    for candidate in candidates:
        if not candidate.is_file():
            continue
        metadata = candidate.stat()
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in seen:
            continue
        seen.add(identity)
        canonical = candidate.resolve()
        chunks.append(
            f"# configuration file /{canonical.relative_to(root.resolve())}:\n"
            + canonical.read_text()
        )
    local = local_addresses or set()
    dns: dict[str, object] = {}
    certificates: dict[str, object] = {}
    for domain, record in sorted((dns_records or {}).items()):
        ipv4 = tuple(sorted(set(record.get("A", []))))
        ipv6 = tuple(sorted(set(record.get("AAAA", []))))
        dns[domain] = {
            "a": ipv4,
            "aaaa": ipv6,
            "a_matches_local": bool(set(ipv4) & local),
            "aaaa_handled": not ipv6 or set(ipv6) <= local,
            "caa": (),
            "caa_compatible": True,
            "caa_source": None,
        }
        covered = domain in (tls_names or set())
        certificates[domain] = {"covers_domain": covered, "present": covered}
    nginx = parse_nginx_observation("".join(chunks))
    map_files = nginx["sni_map_files"]
    assert isinstance(map_files, dict)
    for candidate in candidates:
        if not candidate.is_symlink():
            continue
        canonical_name = "/" + str(candidate.resolve().relative_to(root.resolve()))
        if map_files.get(canonical_name) == 1:
            map_files["/" + str(candidate.relative_to(root))] = 1
    return AuditFacts(
        listeners={
            "owners": {
                str(port): tuple(sorted(names))
                for port, names in sorted((listener_owners or {}).items())
            },
            "ports": tuple(sorted(listening_ports)),
            "tcp": tuple(sorted(listening_ports)),
            "udp": (),
        },
        ownership={"docker": {"available": docker_available}},
        topology={
            "certificates": certificates,
            "dns": dns,
            "nginx": nginx,
            "three_xui": {"installed": False, "inbounds": ()},
        },
    )


def make_plan(root: Path, route: Path) -> InstallPlan:
    report = facts_from_root(
        root=root,
        listening_ports={80, 443, 10443},
        docker_available=True,
        dns_records={
            "mt.example.com": {"A": ["203.0.113.10"], "AAAA": []},
            "panel-mt.example.com": {"A": ["203.0.113.10"], "AAAA": []},
        },
        local_addresses={"203.0.113.10"},
        tls_names={"mt.example.com", "panel-mt.example.com"},
    )
    return InstallPlan.from_audit(
        report,
        proxy_domain="mt.example.com",
        panel_domain="panel-mt.example.com",
        route_file="/etc/nginx/stream.d/routes.conf",
    )


def test_audit_domain_checks_are_sorted_secret_safe_and_detect_dns_tls_failures(tmp_path):
    root, _ = host_root(tmp_path)
    report = facts_from_root(
        root=root,
        listening_ports={443},
        docker_available=True,
        dns_records={
            "z.example.com": {"A": ["198.51.100.7"], "AAAA": ["2001:db8::7"]},
            "a.example.com": {"A": ["203.0.113.10"], "AAAA": []},
        },
        local_addresses={"203.0.113.10"},
        tls_names={"a.example.com"},
    )

    encoded = json.dumps(report.stable_dict(), sort_keys=True)
    dns = report.topology["dns"]
    certificates = report.topology["certificates"]
    assert list(dns) == ["a.example.com", "z.example.com"]
    assert dns["a.example.com"]["a_matches_local"] is True
    assert certificates["a.example.com"]["covers_domain"] is True
    assert dns["z.example.com"]["a_matches_local"] is False
    assert dns["z.example.com"]["aaaa_handled"] is False
    assert "secret" not in encoded.lower()
    assert "private" not in encoded.lower()


def test_plan_is_deterministic_and_blocks_failed_domain_preflight(tmp_path):
    root, route = host_root(tmp_path)
    plan = make_plan(root, route)

    first = plan.to_json()
    second = make_plan(root, route).to_json()
    assert first == second
    assert json.loads(first) == {
        "actions": [
            {"kind": "nginx_route", "target": "/etc/nginx/stream.d/routes.conf"},
            {"kind": "ownership_manifest", "target": "/var/lib/proxy-control/ownership.json"},
        ],
        "panel_backend": "127.0.0.1:8787",
        "panel_domain": "panel-mt.example.com",
        "proxy_backend": "127.0.0.1:8445",
        "proxy_domain": "mt.example.com",
        "route_file": "/etc/nginx/stream.d/routes.conf",
        "route_variable": "$upstream_443",
        "schema": 1,
    }

    failed = facts_from_root(
        root=root,
        listening_ports={443},
        docker_available=True,
        dns_records={
            "mt.example.com": {"A": ["198.51.100.9"], "AAAA": []},
            "panel-mt.example.com": {"A": ["203.0.113.10"], "AAAA": []},
        },
        local_addresses={"203.0.113.10"},
        tls_names={"mt.example.com", "panel-mt.example.com"},
    )
    with pytest.raises(InstallerConflict, match="DNS does not resolve to this host"):
        InstallPlan.from_audit(
            failed,
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/etc/nginx/stream.d/routes.conf",
        )

    empty = facts_from_root(root=root, listening_ports={443}, docker_available=True)
    with pytest.raises(InstallerConflict, match="domain preflight evidence is incomplete"):
        InstallPlan.from_audit(
            empty,
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/etc/nginx/stream.d/routes.conf",
        )


def test_plan_selects_active_map_and_fails_closed_on_ambiguous_paths_and_direct_listener(tmp_path):
    root, route = host_root(tmp_path)
    route.write_text(
        route.read_text()
        + "\nmap $ssl_preread_server_name $other { default 127.0.0.1:9; }\n"
    )
    report = facts_from_root(root=root, listening_ports={443}, docker_available=True)
    selected = InstallPlan.from_audit(
        report,
        proxy_domain="mt.example.com",
        panel_domain="panel-mt.example.com",
        route_file="/etc/nginx/stream.d/routes.conf",
        require_domain_preflight=False,
    )
    assert selected.route_variable == "$upstream_443"

    route.write_text(
        route.read_text()
        + "server { listen 443; ssl_preread on; proxy_pass $other; }\n"
    )
    ambiguous = facts_from_root(root=root, listening_ports={443}, docker_available=True)
    with pytest.raises(InstallerConflict, match="more than one effective map"):
        InstallPlan.from_audit(
            ambiguous,
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/etc/nginx/stream.d/routes.conf",
            require_domain_preflight=False,
        )

    root2 = tmp_path / "direct"
    root2.mkdir()
    direct = facts_from_root(root=root2, listening_ports={443}, docker_available=True)
    with pytest.raises(InstallerConflict, match="occupied without an Nginx stream router"):
        InstallPlan.from_audit(
            direct,
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/etc/nginx/stream.d/routes.conf",
            require_domain_preflight=False,
        )


    root3, _ = host_root(tmp_path / "stale")
    stale = facts_from_root(
        root=root3,
        listening_ports={443},
        listener_owners={443: ["xray"]},
        docker_available=True,
    )
    with pytest.raises(InstallerConflict, match="not owned by Nginx"):
        InstallPlan.from_audit(
            stale,
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/etc/nginx/stream.d/routes.conf",
            require_domain_preflight=False,
        )

    root4, route4 = host_root(tmp_path / "duplicate")
    route4.write_text(route4.read_text().replace(
        "    default", "    vpn.example.com 127.0.0.1:10443;\n    default"
    ))
    duplicate = facts_from_root(root=root4, listening_ports={443}, docker_available=True)
    assert duplicate.topology["nginx"]["duplicate_sni_domains"] == (
        "vpn.example.com",
    )

    root5, _ = host_root(tmp_path / "foreign")
    foreign = root5 / "tmp/foreign.conf"
    foreign.parent.mkdir()
    foreign.write_text("map $ssl_preread_server_name $x { default 127.0.0.1:9; }\n")
    with pytest.raises(InstallerConflict, match="active audited SNI map file"):
        InstallPlan.from_audit(
            facts_from_root(root=root5, listening_ports={443}, docker_available=True),
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/tmp/foreign.conf",
            require_domain_preflight=False,
        )


def test_apply_is_transactional_preserves_metadata_and_writes_private_manifest(tmp_path):
    root, route = host_root(tmp_path)
    os.chmod(route, 0o640)
    original = route.read_text()
    plan = make_plan(root, route)
    calls: list[str] = []

    manifest = apply_plan(
        plan,
        root=root,
        validate=lambda: calls.append("validate"),
        reload=lambda: calls.append("reload"),
    )

    assert calls == ["validate", "reload"]
    assert "vpn.example.com 127.0.0.1:10443;" in route.read_text()
    assert route.read_text().count("# BEGIN PROXY-CONTROL ROUTES ") == 1
    assert stat.S_IMODE(route.stat().st_mode) == 0o640
    manifest_path = root / "var/lib/proxy-control/ownership.json"
    assert manifest_path == manifest
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
    state = json.loads(manifest_path.read_text())
    assert state["route_sha256_before"]
    assert state["route_sha256_owned"]
    backup = root / state["backup_file"].lstrip("/")
    assert backup.read_text() == original
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600


def test_apply_rolls_back_exactly_when_validation_or_reload_fails(tmp_path):
    root, route = host_root(tmp_path)
    original = route.read_bytes()
    plan = make_plan(root, route)

    validation_calls = 0

    def reject_candidate_once() -> None:
        nonlocal validation_calls
        validation_calls += 1
        if validation_calls == 1:
            raise RuntimeError("bad nginx")

    rollback_reload_calls = 0

    def record_rollback_reload() -> None:
        nonlocal rollback_reload_calls
        rollback_reload_calls += 1

    with pytest.raises(RuntimeError, match="bad nginx"):
        apply_plan(
            plan,
            root=root,
            validate=reject_candidate_once,
            reload=record_rollback_reload,
        )
    assert rollback_reload_calls == 1
    assert route.read_bytes() == original
    assert not (root / "var/lib/proxy-control/ownership.json").exists()

    reload_calls = 0

    def reject_reload_once() -> None:
        nonlocal reload_calls
        reload_calls += 1
        if reload_calls == 1:
            raise RuntimeError("reload failed")

    with pytest.raises(RuntimeError, match="reload failed"):
        apply_plan(
            plan,
            root=root,
            validate=lambda: None,
            reload=reject_reload_once,
        )
    assert route.read_bytes() == original
    assert not (root / "var/lib/proxy-control/ownership.json").exists()


def test_repair_and_uninstall_are_idempotent_and_refuse_foreign_drift(tmp_path):
    root, route = host_root(tmp_path)
    original = route.read_text()
    plan = make_plan(root, route)

    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)

    repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert route.read_text().count("# BEGIN PROXY-CONTROL ROUTES ") == 1

    route.write_text(route.read_text().replace("127.0.0.1:8445", "127.0.0.1:9445"))
    with pytest.raises(InstallerConflict, match="owned route file has drifted"):
        repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    with pytest.raises(InstallerConflict, match="owned route file has drifted"):
        uninstall_installation(root=root, validate=lambda: None, reload=lambda: None)

    # Restore the exact owned generation and remove only our marked block.
    route.write_text(route.read_text().replace("127.0.0.1:9445", "127.0.0.1:8445"))
    uninstall_installation(root=root, validate=lambda: None, reload=lambda: None)
    uninstall_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert route.read_text() == original
    assert not (root / "var/lib/proxy-control/ownership.json").exists()

def test_repair_durably_migrates_legacy_schema_one_manifest(tmp_path):
    root, route = host_root(tmp_path)
    plan = make_plan(root, route)
    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)
    manifest = root / "var/lib/proxy-control/ownership.json"
    legacy = json.loads(manifest.read_text())
    legacy["plan"].pop("route_variable")
    manifest.write_text(json.dumps(legacy))
    calls: list[str] = []

    repair_installation(
        root=root,
        validate=lambda: calls.append("validate"),
        reload=lambda: calls.append("reload"),
    )

    migrated = json.loads(manifest.read_text())
    assert migrated["plan"]["route_variable"] == "$upstream_443"
    assert calls == ["validate"]

def test_repair_and_uninstall_preserve_foreign_routes_added_after_install(tmp_path):
    root, route = host_root(tmp_path)
    original = route.read_text()
    plan = InstallPlan(
        proxy_domain="mt.example.com",
        panel_domain="panel-mt.example.com",
        route_file="/etc/nginx/stream.d/routes.conf",
    )
    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)
    route.write_text(
        route.read_text().replace(
            "    default 127.0.0.1:8443;",
            "    edge.example.com 127.0.0.1:4443;\n    default 127.0.0.1:8443;",
        )
    )
    expected = original.replace(
        "    default 127.0.0.1:8443;",
        "    edge.example.com 127.0.0.1:4443;\n    default 127.0.0.1:8443;",
    )

    repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    uninstall_installation(root=root, validate=lambda: None, reload=lambda: None)

    assert route.read_text() == expected
    assert "edge.example.com 127.0.0.1:4443;" in route.read_text()
    assert "mt.example.com 127.0.0.1:8445;" not in route.read_text()
    assert "panel-mt.example.com 127.0.0.1:8443;" not in route.read_text()


def test_interrupted_apply_and_uninstall_recover_from_durable_manifest(tmp_path):
    root, route = host_root(tmp_path)
    original = route.read_bytes()
    plan = make_plan(root, route)
    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)
    manifest = root / "var/lib/proxy-control/ownership.json"
    state = json.loads(manifest.read_text())
    owned = route.read_bytes()

    state["status"] = "applying"
    manifest.write_text(json.dumps(state))
    repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert route.read_bytes() == original
    assert not manifest.exists()

    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)
    state = json.loads(manifest.read_text())
    backup = root / state["backup_file"].lstrip("/")
    state["status"] = "uninstalling"
    manifest.write_text(json.dumps(state))
    route.write_bytes(original)
    repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert route.read_bytes() == original
    assert not manifest.exists()
    assert not backup.exists()
    assert owned != original

    # Cleanup is recoverable even if an older generation removed backup first.
    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)
    state = json.loads(manifest.read_text())
    backup = root / state["backup_file"].lstrip("/")
    state["status"] = "uninstalling"
    manifest.write_text(json.dumps(state))
    route.write_bytes(original)
    backup.unlink()
    repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert not manifest.exists()


def test_failed_rollback_keeps_recoverable_manifest(tmp_path):
    root, route = host_root(tmp_path)
    plan = make_plan(root, route)
    validations = 0

    def validate() -> None:
        nonlocal validations
        validations += 1
        if validations == 1:
            raise RuntimeError("candidate invalid")

    with pytest.raises(RuntimeError, match="rollback reload failed"):
        apply_plan(
            plan,
            root=root,
            validate=validate,
            reload=lambda: (_ for _ in ()).throw(RuntimeError("rollback reload failed")),
        )
    state = json.loads((root / "var/lib/proxy-control/ownership.json").read_text())
    assert state["status"] == "applying"


def test_manifest_rejects_generation_mismatch_before_touching_route(tmp_path):
    root, route = host_root(tmp_path)
    plan = make_plan(root, route)
    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)
    before = route.read_bytes()
    manifest = root / "var/lib/proxy-control/ownership.json"
    state = json.loads(manifest.read_text())
    state["install_id"] = "f" * 32
    manifest.write_text(json.dumps(state))

    with pytest.raises(InstallerConflict, match="generation"):
        repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert route.read_bytes() == before


def test_mutations_refuse_a_concurrent_operation_lock(tmp_path):
    root, route = host_root(tmp_path)
    plan = make_plan(root, route)
    lock = root / "run/lock/proxy-control.lock"
    lock.parent.mkdir(parents=True)
    with lock.open("w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(InstallerConflict, match="another proxyctl operation"):
            apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)


def test_symlink_route_is_canonicalized_but_symlink_survives(tmp_path):
    root, route = host_root(tmp_path)
    alias = root / "etc/nginx/stream.d/current.conf"
    alias.symlink_to(route.name)
    report = facts_from_root(root=root, listening_ports={443}, docker_available=True)
    plan = InstallPlan.from_audit(
        report,
        proxy_domain="mt.example.com",
        panel_domain="panel-mt.example.com",
        route_file="/etc/nginx/stream.d/current.conf",
        require_domain_preflight=False,
    )
    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)

    state = json.loads((root / "var/lib/proxy-control/ownership.json").read_text())
    assert state["route_file"] == "/etc/nginx/stream.d/routes.conf"
    assert alias.is_symlink()
