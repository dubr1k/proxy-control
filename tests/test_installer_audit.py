from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import replace

import pytest

from installer.audit import (
    AuditError,
    CommandRunner,
    HardStop,
    OperatorPrerequisite,
    audit_host,
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

HOST_V4 = "203.0.113.10"
HOST_V6 = "2001:db8::10"
FOREIGN_V6 = "2001:db8::99"


def config(
    *,
    host_mode: HostMode = HostMode.FRESH,
    profile: Profile = Profile.FULL,
    three_xui_mode: ThreeXuiMode = ThreeXuiMode.EXISTING,
) -> InstallerConfig:
    return InstallerConfig(
        schema=1,
        host_mode=host_mode,
        profile=profile,
        acme_email="admin@example.com",
        initial_user="owner",
        domains=DomainConfig(
            panel="panel.example.com",
            mtproxy="relay.example.com",
            naive="naive.example.com" if profile.includes_naive else None,
            mieru="mieru.example.com" if profile.includes_mieru else None,
        ),
        mieru=MieruConfig(tcp_ports=(4567,), udp_ports=(4567,))
        if profile.includes_mieru
        else None,
        three_xui=ThreeXuiConfig(
            mode=three_xui_mode,
            panel_domain="xui.example.com"
            if three_xui_mode is not ThreeXuiMode.NONE
            else None,
            vless_tcp_domain="reality.example.com"
            if three_xui_mode is not ThreeXuiMode.NONE
            else None,
        ),
        firewall=FirewallConfig(manage_ufw=host_mode is HostMode.FRESH),
    )


class ScriptedExecutor:
    def __init__(self, responses: dict[tuple[str, ...], tuple[int, str, str]] | None = None):
        self.responses = responses or {}
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
        returncode, stdout, stderr = self.responses.get(command, (127, "", "missing"))
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def resolver(records: dict[str, tuple[list[str], list[str]]]):
    def getaddrinfo(
        host: str,
        port: int,
        *,
        type: socket.SocketKind,
    ) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
        assert port == 443
        assert type == socket.SOCK_STREAM
        a, aaaa = records.get(host.rstrip("."), ([], []))
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
            for address in a
        ] + [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 443, 0, 0))
            for address in aaaa
        ]

    return getaddrinfo


def host_responses(
    domains: Sequence[str],
    *,
    caa: str = '0 issue "letsencrypt.org"\n',
    xray: dict[str, object] | None = None,
) -> dict[tuple[str, ...], tuple[int, str, str]]:
    responses: dict[tuple[str, ...], tuple[int, str, str]] = {
        ("uname", "-m"): (0, "x86_64\n", ""),
        ("df", "-Pk"): (
            0,
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/vda1 100000 25000 75000 25% /\n",
            "",
        ),
        ("free", "-b"): (
            0,
            "              total used free shared buff/cache available\n"
            "Mem:     8589934592 1 2 3 4 6442450944\n",
            "",
        ),
        ("ip", "-j", "address"): (
            0,
            json.dumps(
                [
                    {
                        "ifname": "eth0",
                        "addr_info": [
                            {"family": "inet", "local": HOST_V4, "scope": "global"},
                            {"family": "inet6", "local": HOST_V6, "scope": "global"},
                        ],
                    }
                ]
            ),
            "",
        ),
        ("ss", "-H", "-lntup"): (
            0,
            'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=4,fd=3))\n'
            'tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=5,fd=4))\n'
            'udp UNCONN 0 0 0.0.0.0:4567 0.0.0.0:* users:(("mieru",pid=6,fd=5))\n',
            "",
        ),
        ("nginx", "-T"): (
            0,
            "# configuration file /etc/nginx/nginx.conf:\n"
            "events {}\nstream { map $ssl_preread_server_name $upstream {\n"
            "old.example.com 127.0.0.1:10443;\ndefault 127.0.0.1:8443;\n} }\n"
            "server { server_name old-panel.example.com; }\n",
            "",
        ),
        ("docker", "--version"): (0, "Docker version 28.0.0, build abc\n", ""),
        ("docker", "compose", "version", "--short"): (0, "2.35.0\n", ""),
        (
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--no-legend",
            "--no-pager",
        ): (0, "nginx.service enabled\nssh.service enabled\nx-ui.service enabled\n", ""),
        (
            "systemctl",
            "show",
            "ssh.socket",
            "--property=Listen",
            "--value",
            "--no-pager",
        ): (0, "[::]:22 (Stream)\n", ""),
        ("cat", "/etc/default/ufw"): (0, "IPV6=yes\n", ""),
        ("ufw", "status", "verbose"): (0, "Status: active\n22/tcp ALLOW IN Anywhere\n", ""),
    }
    for domain in domains:
        responses[("dig", "+short", "CAA", domain)] = (0, caa, "")
        responses[
            (
                "openssl",
                "x509",
                "-in",
                f"/etc/letsencrypt/live/{domain}/fullchain.pem",
                "-noout",
                "-dates",
                "-ext",
                "subjectAltName",
            )
        ] = (1, "", "not found")
    if xray is None:
        responses[("test", "-f", "/usr/local/x-ui/bin/config.json")] = (1, "", "")
    else:
        responses[("test", "-f", "/usr/local/x-ui/bin/config.json")] = (0, "", "")
        responses[("cat", "/usr/local/x-ui/bin/config.json")] = (
            0,
            json.dumps(xray),
            "",
        )
    responses[("test", "-f", "/var/lib/proxy-control/ownership.json")] = (1, "", "")
    return responses


def scripted_audit(
    *,
    dns: dict[str, tuple[list[str], list[str]]],
    caa: str = '0 issue "letsencrypt.org"\n',
    host_config: InstallerConfig | None = None,
    xray: dict[str, object] | None = None,
):
    selected = host_config or config()
    executor = ScriptedExecutor(
        host_responses(selected.required_domains(), caa=caa, xray=xray)
    )
    runner = CommandRunner(executor=executor, resolver=resolver(dns))
    return audit_host(selected, runner), executor


def test_command_runner_uses_argv_without_shell_and_parses_json():
    runner = CommandRunner(timeout=1, max_output=1024)

    literal = runner.capture(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", "$(echo injected)"]
    )
    parsed = runner.json([sys.executable, "-c", 'print("{\\"value\\": 7}")'])

    assert literal == "$(echo injected)\n"
    assert parsed == {"value": 7}


def test_command_runner_redacts_failed_output_and_argv():
    runner = CommandRunner(timeout=1, max_output=1024)
    secret = "Authorization: Bearer header-secret password=hunter2"

    with pytest.raises(AuditError) as caught:
        runner.capture(
            [
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1], file=sys.stderr); raise SystemExit(9)",
                secret,
            ]
        )

    text = str(caught.value)
    assert "header-secret" not in text
    assert "hunter2" not in text
    assert "Authorization" not in text
    assert "exit status 9" in text


def test_command_runner_bounds_output_timeout_and_malformed_json():
    bounded = CommandRunner(timeout=1, max_output=64)
    with pytest.raises(AuditError, match="output limit") as oversized:
        bounded.capture([sys.executable, "-c", "print('sensitive-value-' * 1000)"])
    assert "sensitive-value" not in str(oversized.value)

    timed = CommandRunner(timeout=0.02, max_output=1024)
    with pytest.raises(AuditError, match="timed out"):
        timed.run([sys.executable, "-c", "import time; time.sleep(2)"])

    with pytest.raises(AuditError, match="malformed JSON") as malformed:
        bounded.json([sys.executable, "-c", "print('{password: hunter2}')"])
    assert "hunter2" not in str(malformed.value)


def test_audit_error_redacts_headers_passwords_tokens_uuid_keys_and_panel_paths(
    monkeypatch,
):
    environment_secret = "environment-secret-specimen"
    monkeypatch.setenv("AUDIT_API_TOKEN", environment_secret)

    class FailingRunner:
        def run(self, *args, **kwargs):
            del args, kwargs
            raise RuntimeError(
                "Authorization: Bearer abc Cookie: sid=cookie-secret "
                "password=hunter2 token=tok-value "
                "id=deadbeef-dead-beef-dead-beefdeadbeef "
                "privateKey=priv-key shortId=short-secret panelPath=/hidden-panel "
                + environment_secret
            )

    with pytest.raises(AuditError) as caught:
        audit_host(config(), FailingRunner())  # type: ignore[arg-type]

    text = str(caught.value)
    for secret in (
        "abc",
        "cookie-secret",
        "hunter2",
        "tok-value",
        "deadbeef",
        "priv-key",
        "/hidden-panel",
        "short-secret",
        environment_secret,
    ):
        assert secret not in text
    assert text.count("[REDACTED]") >= 6


def test_audit_facts_cover_all_categories_and_are_deterministic():
    records = {
        domain: ([HOST_V4], [HOST_V6])
        for domain in config().required_domains()
    }
    first, _ = scripted_audit(dns=records)
    second, _ = scripted_audit(dns=dict(reversed(list(records.items()))))

    assert first.stable_dict() == second.stable_dict()
    assert set(first.platform) == {"addresses", "architecture", "disks", "memory", "os"}
    assert set(first.listeners) == {
        "owners",
        "ports",
        "ssh_socket_tcp",
        "tcp",
        "udp",
    }
    assert first.listeners["ssh_socket_tcp"] == (22,)
    assert set(first.topology) == {"certificates", "dns", "nginx", "three_xui"}
    assert set(first.ownership) == {
        "compose",
        "docker",
        "installer",
        "systemd",
        "three_xui",
        "ufw",
    }
    assert first.ownership["ufw"]["ipv6_enabled"] is True
    assert all(isinstance(stop, HardStop) for stop in first.hard_stops)
    assert all(
        isinstance(item, OperatorPrerequisite)
        for item in first.operator_prerequisites
    )
    assert {item.code for item in first.operator_prerequisites} == {
        "cloud_firewall.reachability"
    }
    assert first.operator_prerequisites[0].status == "operator_required"


@pytest.mark.parametrize(
    ("config_response", "expected"),
    [
        ((0, "IPV6=no\n", ""), False),
        ((0, "IPV6=maybe\n", ""), None),
        ((1, "", "permission denied"), None),
    ],
)
def test_audit_uses_authoritative_ufw_ipv6_mode_not_observed_rules(
    config_response: tuple[int, str, str],
    expected: bool | None,
) -> None:
    selected = config()
    records = {
        domain: ([HOST_V4], [HOST_V6])
        for domain in selected.required_domains()
    }
    responses = host_responses(selected.required_domains())
    responses[("cat", "/etc/default/ufw")] = config_response
    responses[("ufw", "status", "verbose")] = (
        0,
        "Status: active\n22/tcp (v6) ALLOW IN Anywhere (v6)\n",
        "",
    )
    executor = ScriptedExecutor(responses)
    runner = CommandRunner(executor=executor, resolver=resolver(records))

    facts = audit_host(selected, runner)

    assert facts.ownership["ufw"]["ipv6_enabled"] is expected


def test_injected_dns_a_aaaa_and_caa_accept_local_addresses():
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    records = {
        domain: ([HOST_V4], [HOST_V6])
        for domain in selected.required_domains()
    }

    facts, _ = scripted_audit(dns=records, host_config=selected)

    assert facts.hard_stops == ()
    assert facts.topology["dns"] == {
        domain: {
            "a": (HOST_V4,),
            "aaaa": (HOST_V6,),
            "a_matches_local": True,
            "aaaa_handled": True,
            "caa": ({"flags": 0, "issuer": "letsencrypt.org", "tag": "issue"},),
            "caa_compatible": True,
            "caa_source": domain,
        }
        for domain in sorted(selected.required_domains())
    }


def test_unhandled_aaaa_and_incompatible_caa_are_exact_hard_stops():
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    records = {
        domain: ([HOST_V4], [FOREIGN_V6])
        for domain in selected.required_domains()
    }

    facts, _ = scripted_audit(
        dns=records,
        caa='0 issue "sectigo.com"\n',
        host_config=selected,
    )

    assert {stop.code for stop in facts.hard_stops} == {
        "dns.unhandled_aaaa",
        "dns.caa_mismatch",
    }
    assert tuple(stop.code for stop in facts.hard_stops) == tuple(
        sorted(stop.code for stop in facts.hard_stops)
    )


def test_three_xui_facts_whitelist_only_non_secret_inbound_fields():
    xray = {
        "inbounds": [
            {
                "tag": "vless-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": 10443,
                "settings": {
                    "clients": [
                        {
                            "id": "deadbeef-dead-beef-dead-beefdeadbeef",
                            "password": "hunter2",
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverNames": ["reality.example.com"],
                        "privateKey": "private-material",
                        "shortIds": ["0123456789abcdef"],
                    },
                },
            }
        ],
        "api": {"tag": "api", "services": ["HandlerService"]},
        "webBasePath": "/hidden-panel-path",
        "authorization": "Bearer panel-token",
        "cookies": ["session=cookie-secret"],
    }
    records = {
        domain: ([HOST_V4], [HOST_V6])
        for domain in config().required_domains()
    }

    facts, _ = scripted_audit(dns=records, xray=xray)
    encoded = json.dumps(facts.stable_dict(), sort_keys=True)

    assert facts.topology["three_xui"]["inbounds"] == (
        {
            "listen": "127.0.0.1",
            "port": 10443,
            "protocol": "vless",
            "reality_server_names": ("reality.example.com",),
            "tag": "vless-in",
            "transport_security": "reality",
        },
    )
    for forbidden in (
        "deadbeef",
        "hunter2",
        "private-material",
        "0123456789abcdef",
        "hidden-panel-path",
        "panel-token",
        "cookie-secret",
        "clients",
        "shortIds",
    ):
        assert forbidden not in encoded


def test_malformed_and_unbounded_three_xui_json_fail_closed_without_content():
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.EXISTING)
    domains = selected.required_domains()
    malformed_responses = host_responses(domains)
    malformed_responses[("test", "-f", "/usr/local/x-ui/bin/config.json")] = (0, "", "")
    malformed_responses[("cat", "/usr/local/x-ui/bin/config.json")] = (
        0,
        '{"password":"hunter2"',
        "",
    )
    malformed = CommandRunner(
        executor=ScriptedExecutor(malformed_responses),
        resolver=resolver({domain: ([HOST_V4], [HOST_V6]) for domain in domains}),
    )

    with pytest.raises(AuditError, match="malformed JSON") as caught:
        audit_host(selected, malformed)
    assert "hunter2" not in str(caught.value)

    huge_responses = host_responses(domains)
    huge_responses[("test", "-f", "/usr/local/x-ui/bin/config.json")] = (0, "", "")
    huge_responses[("cat", "/usr/local/x-ui/bin/config.json")] = (
        0,
        json.dumps({"clients": ["secret-value" * 200]}),
        "",
    )
    huge = CommandRunner(
        executor=ScriptedExecutor(huge_responses),
        resolver=resolver({domain: ([HOST_V4], [HOST_V6]) for domain in domains}),
        max_output=256,
    )

    with pytest.raises(AuditError, match="output limit") as oversized:
        audit_host(selected, huge)
    assert "secret-value" not in str(oversized.value)


def test_audit_uses_only_read_only_commands_and_coexist_never_inspects_firewall_mutably():
    selected = config(
        host_mode=HostMode.COEXIST,
        profile=Profile.CORE,
        three_xui_mode=ThreeXuiMode.NONE,
    )
    domains = selected.required_domains()
    facts, executor = scripted_audit(
        dns={domain: ([HOST_V4], [HOST_V6]) for domain in domains},
        host_config=selected,
    )

    assert facts.ownership["ufw"]["mode"] == "read_only"
    forbidden = {
        "add",
        "allow",
        "apply",
        "create",
        "delete",
        "disable",
        "enable",
        "install",
        "reload",
        "remove",
        "restart",
        "set",
        "start",
        "stop",
        "write",
    }
    for command in executor.calls:
        assert not (set(part.lower() for part in command) & forbidden), command


class MissingOptionalExecutor(ScriptedExecutor):
    def __init__(
        self,
        responses: dict[tuple[str, ...], tuple[int, str, str]],
        missing: set[str],
    ) -> None:
        super().__init__(responses)
        self.missing = missing

    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        max_output: int,
    ) -> subprocess.CompletedProcess[str]:
        if argv[0] in self.missing:
            raise FileNotFoundError(argv[0])
        return super().__call__(argv, timeout=timeout, max_output=max_output)


def test_missing_optional_tools_are_explicit_facts_not_audit_failures():
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    domains = selected.required_domains()
    executor = MissingOptionalExecutor(
        host_responses(domains),
        {"docker", "nginx", "systemctl", "ufw"},
    )
    runner = CommandRunner(
        executor=executor,
        resolver=resolver({domain: ([HOST_V4], [HOST_V6]) for domain in domains}),
    )

    facts = audit_host(selected, runner)

    assert facts.topology["nginx"] == {
        "available": False,
        "http_domains": (),
        "observation": "unavailable",
        "route_target": None,
        "sni_map_count": 0,
        "sni_map_files": {},
        "sni_routes": {},
        "stream_enabled": False,
        "duplicate_sni_domains": (),
        "topology_error": None,
    }
    assert facts.ownership["docker"] == {
        "available": False,
        "observation": "unavailable",
    }
    assert facts.ownership["compose"] == {
        "available": False,
        "observation": "unavailable",
    }
    assert facts.ownership["systemd"] == {
        "available": False,
        "observation": "unavailable",
        "services": (),
    }
    assert facts.ownership["ufw"]["observation"] == "unavailable"


def test_required_base_tool_absence_fails_closed_distinctly():
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    domains = selected.required_domains()
    runner = CommandRunner(
        executor=MissingOptionalExecutor(host_responses(domains), {"ip"}),
        resolver=resolver({domain: ([HOST_V4], [HOST_V6]) for domain in domains}),
    )

    with pytest.raises(AuditError, match="required audit command is unavailable"):
        audit_host(selected, runner)


def test_failed_optional_observations_are_explicitly_unknown():
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    domains = selected.required_domains()
    responses = host_responses(domains)
    for command in (
        ("nginx", "-T"),
        ("docker", "--version"),
        ("docker", "compose", "version", "--short"),
        (
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--no-legend",
            "--no-pager",
        ),
        ("ufw", "status", "verbose"),
    ):
        responses[command] = (1, "", "failed")
    runner = CommandRunner(
        executor=ScriptedExecutor(responses),
        resolver=resolver({domain: ([HOST_V4], [HOST_V6]) for domain in domains}),
    )

    facts = audit_host(selected, runner)

    assert facts.topology["nginx"]["observation"] == "unknown"
    assert facts.ownership["docker"]["observation"] == "unknown"
    assert facts.ownership["compose"]["observation"] == "unknown"
    assert facts.ownership["systemd"]["observation"] == "unknown"
    assert facts.ownership["ufw"]["observation"] == "unknown"


def test_dns_resolution_transient_failure_and_timeout_fail_closed():
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    responses = host_responses(selected.required_domains())

    def transient(*args, **kwargs):
        del args, kwargs
        raise socket.gaierror(socket.EAI_AGAIN, "temporary resolver failure")

    transient_runner = CommandRunner(
        executor=ScriptedExecutor(responses),
        resolver=transient,
    )
    with pytest.raises(AuditError, match="DNS resolution failed"):
        audit_host(selected, transient_runner)

    def stalled(*args, **kwargs):
        del args, kwargs
        time.sleep(2)
        return []

    stalled_runner = CommandRunner(
        executor=ScriptedExecutor(responses),
        resolver=stalled,
        timeout=0.03,
    )
    with pytest.raises(AuditError, match="DNS resolution timed out"):
        audit_host(selected, stalled_runner)


@pytest.mark.parametrize("overflow", [False, True])
def test_command_runner_kills_descendants_after_leader_exit(tmp_path, overflow):
    marker = tmp_path / ("overflow-leak" if overflow else "timeout-leak")
    child_lines = []
    if overflow:
        child_lines.append("    os.write(1, b'x' * 4096)")
    child_lines.extend(
        (
            "    time.sleep(0.3)",
            f"    pathlib.Path({str(marker)!r}).write_text('leaked')",
            "    os._exit(0)",
        )
    )
    script = "\n".join(
        (
            "import os, pathlib, time",
            "pid = os.fork()",
            "if pid == 0:",
            *child_lines,
            "os._exit(0)",
        )
    )
    runner = CommandRunner(timeout=0.03, max_output=64)

    with pytest.raises(AuditError, match="output limit" if overflow else "timed out"):
        runner.capture((sys.executable, "-c", script))
    time.sleep(0.4)

    assert not marker.exists()


def test_dns_resolution_uses_absolute_name_and_rejects_oversized_results():
    def absolute_name(host, port, *, type):
        assert host == "panel.example.com."
        assert port == 443
        assert type == socket.SOCK_STREAM
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (HOST_V4, 443))]

    runner = CommandRunner(resolver=absolute_name)
    assert runner.resolve("panel.example.com") == ((HOST_V4,), ())

    def oversized(host, port, *, type):
        assert host.endswith(".")
        assert port == 443
        assert type == socket.SOCK_STREAM
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (HOST_V6, 443, 0, 0))
            for _ in range(256)
        ] + [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (FOREIGN_V6, 443, 0, 0))
        ]

    with pytest.raises(AuditError, match="DNS resolution result limit exceeded"):
        CommandRunner(resolver=oversized).resolve("panel.example.com")


def test_failed_caa_query_is_not_treated_as_empty_rrset():
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    domains = selected.required_domains()
    responses = host_responses(domains)
    responses[("dig", "+short", "CAA", domains[0])] = (9, "", "query failed")
    runner = CommandRunner(
        executor=ScriptedExecutor(responses),
        resolver=resolver({domain: ([HOST_V4], [HOST_V6]) for domain in domains}),
    )

    with pytest.raises(AuditError, match="CAA query failed"):
        audit_host(selected, runner)


def test_successful_empty_caa_rrsets_remain_distinct_from_query_failure():
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    domains = selected.required_domains()
    responses = host_responses(domains, caa="")
    responses[("dig", "+short", "CAA", "example.com")] = (0, "", "")
    responses[("dig", "+short", "CAA", "com")] = (0, "", "")
    executor = ScriptedExecutor(responses)
    runner = CommandRunner(
        executor=executor,
        resolver=resolver({domain: ([HOST_V4], [HOST_V6]) for domain in domains}),
    )

    facts = audit_host(selected, runner)

    assert not facts.hard_stops
    assert all(facts.topology["dns"][domain]["caa"] == () for domain in domains)
    assert all(
        facts.topology["dns"][domain]["caa_source"] is None for domain in domains
    )
    dig_calls = [
        call for call in executor.calls if call[:3] == ("dig", "+short", "CAA")
    ]
    assert len(dig_calls) <= len(domains) + 2


@pytest.mark.parametrize(
    ("parent_caa", "expected_codes"),
    [
        ('0 issue "sectigo.com"\n', {"dns.caa_mismatch"}),
        ('0 issue "letsencrypt.org"\n', set()),
        ('0 issue ";"\n', {"dns.caa_mismatch"}),
    ],
)
def test_caa_policy_is_inherited_from_first_parent_rrset(parent_caa, expected_codes):
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    domains = selected.required_domains()
    responses = host_responses(domains, caa="")
    responses[("dig", "+short", "CAA", "example.com")] = (0, parent_caa, "")
    executor = ScriptedExecutor(responses)
    runner = CommandRunner(
        executor=executor,
        resolver=resolver({domain: ([HOST_V4], [HOST_V6]) for domain in domains}),
    )

    facts = audit_host(selected, runner)

    assert {stop.code for stop in facts.hard_stops} == expected_codes
    assert all(
        facts.topology["dns"][domain]["caa_source"] == "example.com"
        for domain in domains
    )
    dig_calls = [
        call for call in executor.calls if call[:3] == ("dig", "+short", "CAA")
    ]
    assert len(dig_calls) <= len(domains) + 1


def test_caa_alias_result_is_followed_within_the_query_bound():
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    domains = selected.required_domains()
    responses = host_responses(domains)
    responses[("dig", "+short", "CAA", domains[0])] = (0, "caa-policy.example.net.\n", "")
    responses[("dig", "+short", "CAA", "caa-policy.example.net")] = (
        0,
        '0 issue "letsencrypt.org"\n',
        "",
    )
    runner = CommandRunner(
        executor=ScriptedExecutor(responses),
        resolver=resolver({domain: ([HOST_V4], [HOST_V6]) for domain in domains}),
    )

    facts = audit_host(selected, runner)

    assert facts.topology["dns"][domains[0]]["caa_source"] == "caa-policy.example.net"
    assert not facts.hard_stops


@pytest.mark.parametrize(
    ("caa", "mismatch"),
    [
        ('0 issue "letsencrypt.org; validationmethods=dns-01"\n', True),
        ('0 issue "letsencrypt.org; validationmethods=http-01"\n', False),
        (
            '0 issue "letsencrypt.org; '
            'accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/12345"\n',
            True,
        ),
    ],
)
def test_caa_issuer_restrictions_are_strictly_evaluated(caa, mismatch):
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    domains = selected.required_domains()
    facts, _ = scripted_audit(
        dns={domain: ([HOST_V4], [HOST_V6]) for domain in domains},
        caa=caa,
        host_config=selected,
    )

    assert ("dns.caa_mismatch" in {stop.code for stop in facts.hard_stops}) is mismatch
    encoded = json.dumps(facts.stable_dict(), sort_keys=True)
    assert "acme/acct/12345" not in encoded


@pytest.mark.parametrize(
    "caa",
    [
        '0 issue "letsencrypt.org; unknown=value"\n',
        '0 issue "letsencrypt.org; validationmethods=http-01; '
        'validationmethods=dns-01"\n',
        '0 issue "letsencrypt.org; validationmethods"\n',
        '0 issue "letsencrypt.org; '
        'validationmethods=http-01,0123456789abcdef"\n',
        '0 issue "deadbeef-dead-beef-dead-beefdeadbeef"\n',
        '0 issue "0123456789abcdef"\n',
    ],
)
def test_unsafe_or_malformed_caa_issuer_policy_fails_closed(caa):
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    domains = selected.required_domains()

    with pytest.raises(AuditError, match="CAA issuer"):
        scripted_audit(
            dns={domain: ([HOST_V4], [HOST_V6]) for domain in domains},
            caa=caa,
            host_config=selected,
        )


def test_caa_facts_never_serialize_raw_iodef_values():
    selected = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    domains = selected.required_domains()
    facts, _ = scripted_audit(
        dns={domain: ([HOST_V4], [HOST_V6]) for domain in domains},
        caa=(
            '0 issue "letsencrypt.org"\n'
            '0 iodef "https://report.example/?token=caa-secret"\n'
        ),
        host_config=selected,
    )

    encoded = json.dumps(facts.stable_dict(), sort_keys=True)
    assert "caa-secret" not in encoded
    assert "https://report.example" not in encoded
    assert all(
        {record["tag"] for record in facts.topology["dns"][domain]["caa"]}
        == {"iodef", "issue"}
        for domain in domains
    )


@pytest.mark.parametrize(
    ("domain", "covered"),
    [("panel.example.com", True), ("a.b.example.com", False)],
)
def test_certificate_wildcard_san_covers_exactly_one_label(domain, covered):
    original = config(profile=Profile.CORE, three_xui_mode=ThreeXuiMode.NONE)
    selected = replace(original, domains=replace(original.domains, panel=domain))
    domains = selected.required_domains()
    responses = host_responses(domains)
    responses[
        (
            "openssl",
            "x509",
            "-in",
            f"/etc/letsencrypt/live/{domain}/fullchain.pem",
            "-noout",
            "-dates",
            "-ext",
            "subjectAltName",
        )
    ] = (0, "X509v3 Subject Alternative Name:\n    DNS:*.example.com\n", "")
    runner = CommandRunner(
        executor=ScriptedExecutor(responses),
        resolver=resolver({name: ([HOST_V4], [HOST_V6]) for name in domains}),
    )

    facts = audit_host(selected, runner)

    assert facts.topology["certificates"][domain]["covers_domain"] is covered


def test_no_legacy_audit_model_or_proxyctl_collector_remains():
    import installer.audit as audit_module
    import scripts.proxyctl as proxyctl

    assert not hasattr(audit_module, "AuditReport")
    assert not hasattr(audit_module, "legacy_audit_host")
    assert not hasattr(proxyctl, "audit_host")
