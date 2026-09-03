from __future__ import annotations

import json
from pathlib import Path

import pytest
from installer.adapters.nginx import TopologyError, patch_owned_map

from installer.audit import (
    AuditFacts,
    parse_nginx_observation,
    parse_xray_inbounds,
    validate_domain,
)
from installer.model import HostMode

from scripts.proxyctl import InstallPlan, InstallerConflict


def fixture_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "etc/nginx/stream.d").mkdir(parents=True)
    (root / "etc/nginx/sites-enabled").mkdir(parents=True)
    (root / "usr/local/x-ui/bin").mkdir(parents=True)
    (root / "etc/nginx/nginx.conf").write_text(
        "events {}\nhttp { include /etc/nginx/sites-enabled/*; }\nstream { include /etc/nginx/stream.d/*.conf; }\n"
    )
    (root / "etc/nginx/stream.d/sni.conf").write_text(
        "map $ssl_preread_server_name $upstream_443 {\n"
        "    vpn.example.com 127.0.0.1:10443;\n"
        "    default 127.0.0.1:8443;\n"
        "}\nserver { listen 443; ssl_preread on; proxy_pass $upstream_443; }\n"
    )
    (root / "etc/nginx/sites-enabled/existing.conf").write_text(
        "server { listen 127.0.0.1:8443 ssl; server_name panel.example.com; }\n"
    )
    (root / "usr/local/x-ui/bin/config.json").write_text(json.dumps({
        "inbounds": [{
            "tag": "in-443-tcp", "protocol": "vless", "listen": "127.0.0.1", "port": 10443,
            "streamSettings": {"security": "reality", "realitySettings": {"serverNames": ["vpn.example.com"]}},
        }],
        "outbounds": [{"tag": "WARP", "protocol": "socks"}],
    }))
    return root


def facts_from_root(
    root: Path,
    *,
    listening_ports: set[int],
    listener_owners: dict[int, list[str]] | None = None,
    docker_available: bool,
) -> AuditFacts:
    chunks: list[str] = []
    for relative in (
        "etc/nginx/nginx.conf",
        "etc/nginx/stream.d",
        "etc/nginx/stream-conf.d",
        "etc/nginx/conf.d",
        "etc/nginx/sites-enabled",
    ):
        path = root / relative
        files = [path] if path.is_file() else sorted(path.iterdir()) if path.is_dir() else []
        for config_file in files:
            if config_file.is_file():
                chunks.append(
                    f"# configuration file /{config_file.relative_to(root)}:\n"
                    + config_file.read_text()
                )
    xray_path = root / "usr/local/x-ui/bin/config.json"
    inbounds = parse_xray_inbounds(json.loads(xray_path.read_text())) if xray_path.is_file() else ()
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
            "certificates": {},
            "dns": {},
            "nginx": parse_nginx_observation("".join(chunks)),
            "three_xui": {"installed": xray_path.is_file(), "inbounds": inbounds},
        },
    )


def test_audit_reports_existing_shared_443_without_dumping_secrets(tmp_path):
    root = fixture_root(tmp_path)
    report = facts_from_root(
        root,
        listening_ports={22, 80, 443, 10443, 45000},
        docker_available=False,
    )

    assert report.topology["nginx"]["stream_enabled"] is True
    assert report.topology["nginx"]["sni_routes"] == {
        "vpn.example.com": "127.0.0.1:10443"
    }
    assert report.topology["three_xui"]["inbounds"] == (
        {
            "tag": "in-443-tcp",
            "protocol": "vless",
            "listen": "127.0.0.1",
            "port": 10443,
            "transport_security": "reality",
            "reality_server_names": ("vpn.example.com",),
        },
    )
    assert report.ownership["docker"]["available"] is False
    assert report.listeners["ports"] == (22, 80, 443, 10443, 45000)
    assert "privateKey" not in json.dumps(report.stable_dict())


def test_audit_discovers_stream_conf_d_routes(tmp_path):
    root = tmp_path / "root"
    (root / "etc/nginx/stream-conf.d").mkdir(parents=True)
    (root / "etc/nginx/nginx.conf").write_text(
        "events {}\nstream { include /etc/nginx/stream-conf.d/*.conf; }\n"
    )
    (root / "etc/nginx/stream-conf.d/routes.conf").write_text(
        "map $ssl_preread_server_name $backend {\n"
        "    relay.example.com 127.0.0.1:8445;\n"
        "    default 127.0.0.1:8443;\n"
        "}\n"
        "server { listen 443; ssl_preread on; proxy_pass $backend; }\n"
    )

    report = facts_from_root(
        root,
        listening_ports={443},
        docker_available=True,
    )

    assert report.topology["nginx"]["sni_routes"] == {
        "relay.example.com": "127.0.0.1:8445"
    }


def test_install_plan_rejects_domain_and_port_collisions(tmp_path):
    report = facts_from_root(
        fixture_root(tmp_path),
        listening_ports={443, 8445, 8787},
        docker_available=True,
    )

    with pytest.raises(InstallerConflict, match="domain already routed"):
        InstallPlan.from_audit(report, proxy_domain="vpn.example.com", panel_domain="new-panel.example.com")
    with pytest.raises(InstallerConflict, match="backend port 8445"):
        InstallPlan.from_audit(report, proxy_domain="proxy-new.example.com", panel_domain="new-panel.example.com")


def test_install_plan_rejects_unknown_nginx_and_gates_unavailable_by_mode(tmp_path):
    observed = facts_from_root(
        tmp_path,
        listening_ports=set(),
        docker_available=True,
    )

    def with_observation(value: str) -> AuditFacts:
        nginx = dict(observed.topology["nginx"])
        nginx.update({"available": False, "observation": value})
        topology = dict(observed.topology)
        topology["nginx"] = nginx
        return AuditFacts(
            platform=observed.platform,
            listeners=observed.listeners,
            ownership=observed.ownership,
            topology=topology,
            prerequisites=observed.prerequisites,
        )

    arguments = {
        "proxy_domain": "proxy-new.example.com",
        "panel_domain": "new-panel.example.com",
        "require_domain_preflight": False,
    }
    with pytest.raises(InstallerConflict, match="Nginx topology is unknown"):
        InstallPlan.from_audit(with_observation("unknown"), **arguments)
    with pytest.raises(InstallerConflict, match="Nginx is unavailable in coexist mode"):
        InstallPlan.from_audit(
            with_observation("unavailable"),
            host_mode=HostMode.COEXIST,
            **arguments,
        )

    plan = InstallPlan.from_audit(
        with_observation("unavailable"),
        host_mode=HostMode.FRESH,
        **arguments,
    )

    assert plan.proxy_domain == "proxy-new.example.com"


def test_stream_patch_is_owned_idempotent_and_preserves_unrelated_routes():
    original = (
        "map $ssl_preread_server_name $upstream_443 {\n"
        "    vpn.example.com 127.0.0.1:10443;\n"
        "    default 127.0.0.1:8443;\n}\n"
    )
    changed = patch_owned_map(
        original,
        variable="$upstream_443",
        routes=(
            ("mt.example.com", "127.0.0.1:8445"),
            ("panel-mt.example.com", "127.0.0.1:8443"),
        ),
        ownership_id="test",
    )

    assert changed.count("# BEGIN PROXY-CONTROL ROUTES") == 1
    assert "vpn.example.com 127.0.0.1:10443;" in changed
    assert changed.index("mt.example.com") < changed.index("default")
    assert patch_owned_map(
        changed,
        variable="$upstream_443",
        routes=(
            ("mt.example.com", "127.0.0.1:8445"),
            ("panel-mt.example.com", "127.0.0.1:8443"),
        ),
        ownership_id="test",
    ) == changed


def test_stream_patch_rejects_ambiguous_or_foreign_owned_input():
    with pytest.raises(TopologyError, match="exactly one effective map"):
        patch_owned_map(
            "map $ssl_preread_server_name $a { default x; }\n"
            "map $ssl_preread_server_name $a { default y; }",
            variable="$a",
            routes=(("mt.example.com", "127.0.0.1:8445"),),
            ownership_id="test",
        )
    with pytest.raises(TopologyError, match="domain already routed"):
        patch_owned_map(
            "map $ssl_preread_server_name $upstream_443 { mt.example.com 127.0.0.1:9999; default 127.0.0.1:8443; }",
            variable="$upstream_443",
            routes=(("mt.example.com", "127.0.0.1:8445"),),
            ownership_id="test",
        )


@pytest.mark.parametrize("value", ["", "https://example.com", "bad_name.example.com", "*.example.com", "localhost", "a..b.com"])
def test_domain_validation_rejects_unsafe_values(value):
    with pytest.raises(ValueError):
        validate_domain(value)


def test_domain_validation_normalizes_valid_hostname():
    assert validate_domain("Panel-NL2.Example.COM") == "panel-nl2.example.com"
