from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Sequence

import pytest

from installer.adapters.firewall import FirewallAdapter, FirewallError, parse_ufw_status
from installer.adapters.nginx import CertificatePlan, TopologyError
from installer.adapters.packages import PackageError, PackagesAdapter
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
from installer.planner import AuditFacts


def config(
    *,
    mode: HostMode = HostMode.FRESH,
    profile: Profile = Profile.CORE,
    manage_ufw: bool = True,
) -> InstallerConfig:
    return InstallerConfig(
        schema=1,
        host_mode=mode,
        profile=profile,
        acme_email="ops@example.com",
        initial_user="operator",
        domains=DomainConfig(
            panel="panel.example.com",
            mtproxy="mt.example.com",
            naive="naive.example.com" if profile.includes_naive else None,
            mieru="mieru.example.com" if profile.includes_mieru else None,
        ),
        mieru=MieruConfig(tcp_ports=(46001,), udp_ports=(46001,))
        if profile.includes_mieru
        else None,
        three_xui=ThreeXuiConfig(mode=ThreeXuiMode.NONE),
        firewall=FirewallConfig(manage_ufw=manage_ufw),
    )


class AptRunner:
    def __init__(self, installed: dict[str, str]) -> None:
        self.installed = dict(installed)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command = tuple(argv)
        self.calls.append(command)
        if command[:2] == ("dpkg-query", "--show"):
            package = command[-1]
            version = self.installed.get(package)
            if version is None:
                return subprocess.CompletedProcess(command, 1, "", "not installed")
            return subprocess.CompletedProcess(
                command,
                0,
                f"{package}\tii \t{version}\n",
                "",
            )
        if command[:5] == (
            "apt-get",
            "install",
            "--yes",
            "--no-install-recommends",
            "--no-upgrade",
        ):
            for package in command[5:]:
                self.installed.setdefault(package, "1.0")
            return subprocess.CompletedProcess(command, 0, "installed details", "")
        if command[:3] == ("apt-get", "purge", "--yes"):
            for package in command[3:]:
                self.installed.pop(package, None)
            return subprocess.CompletedProcess(command, 0, "purged details", "")
        raise AssertionError(command)


def package_action(adapter: PackagesAdapter, selected: InstallerConfig | None = None):
    return adapter.plan(selected or config(), AuditFacts())[0]


def test_packages_adapter_purges_only_packages_it_installed() -> None:
    runner = AptRunner({"curl": "8.0"})
    adapter = PackagesAdapter(runner=runner, packages=("curl", "nginx-full"))
    action = package_action(adapter)
    prepared = adapter.prepare(action)

    applied = adapter.apply(action, prepared)
    adapter.rollback(action, applied)

    assert runner.installed == {"curl": "8.0"}
    purge = [call for call in runner.calls if call[:2] == ("apt-get", "purge")]
    assert purge == [("apt-get", "purge", "--yes", "nginx-full")]


def test_packages_mixed_preexisting_versions_are_preserved() -> None:
    runner = AptRunner({"curl": "8.1", "openssl": "3.0"})
    adapter = PackagesAdapter(
        runner=runner,
        packages=("openssl", "certbot", "curl"),
    )
    action = package_action(adapter)

    applied = adapter.apply(action, adapter.prepare(action))
    assert applied["preexisting"] == {"curl": "8.1", "openssl": "3.0"}
    assert applied["installer_added"] == {"certbot": "1.0"}

    adapter.rollback(action, applied)
    assert runner.installed == {"curl": "8.1", "openssl": "3.0"}


def test_packages_crash_replay_is_idempotent_and_claims_exact_missing_package() -> None:
    runner = AptRunner({"curl": "8.0"})
    adapter = PackagesAdapter(runner=runner, packages=("curl", "nginx-full"))
    action = package_action(adapter)
    prepared = adapter.prepare(action)
    runner.installed["nginx-full"] = "1.0"  # apt completed before journal commit

    reconciled = adapter.reconcile_apply(action, prepared)
    replayed = adapter.reconcile_apply(action, reconciled)

    assert reconciled == replayed
    assert reconciled["installer_added"] == {"nginx-full": "1.0"}
    assert not any(call[:2] == ("apt-get", "install") for call in runner.calls)

def test_packages_crash_rollback_recovers_unjournaled_install() -> None:
    runner = AptRunner({"curl": "8.0"})
    adapter = PackagesAdapter(runner=runner, packages=("curl", "nginx-full"))
    action = package_action(adapter)
    prepared = adapter.prepare(action)
    runner.installed["nginx-full"] = "1.0"

    evidence = adapter.reconcile_rollback(action, prepared)

    assert evidence.success is True
    assert runner.installed == {"curl": "8.0"}



def test_package_rollback_refuses_version_drift() -> None:
    runner = AptRunner({})
    adapter = PackagesAdapter(runner=runner, packages=("certbot",))
    action = package_action(adapter)
    applied = adapter.apply(action, adapter.prepare(action))
    runner.installed["certbot"] = "2.0"

    with pytest.raises(PackageError, match="version drift"):
        adapter.rollback(action, applied)

def test_package_status_must_name_exact_installed_package() -> None:
    class MalformedRunner(AptRunner):
        def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
            command = tuple(argv)
            if command[:2] == ("dpkg-query", "--show"):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "different-package\tii \t1.0\n",
                    "",
                )
            return super().run(argv)

    adapter = PackagesAdapter(
        runner=MalformedRunner({"curl": "1.0"}),
        packages=("curl",),
    )

    with pytest.raises(PackageError, match="malformed"):
        adapter.prepare(package_action(adapter))



def test_coexist_emits_no_package_action() -> None:
    runner = AptRunner({})
    adapter = PackagesAdapter(runner=runner, packages=("curl",))

    assert adapter.plan(config(mode=HostMode.COEXIST), AuditFacts()) == ()
    assert runner.calls == []


def dns_facts(*, bad: str | None = None) -> AuditFacts:
    names = ("mt.example.com", "panel.example.com", "naive.example.com")
    dns: dict[str, object] = {}
    certificates: dict[str, object] = {}
    for name in names:
        item = {
            "a": ("192.0.2.10",),
            "aaaa": (),
            "a_matches_local": True,
            "aaaa_handled": True,
            "caa": (),
            "caa_compatible": True,
            "caa_source": None,
        }
        if name == "panel.example.com" and bad is not None:
            item[bad] = False
        dns[name] = item
        certificates[name] = {"covers_domain": False, "present": False}
    return AuditFacts(topology={"dns": dns, "certificates": certificates})


class CertRunner:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[tuple[str, ...]] = []
        self.groups: dict[str, tuple[str, ...]] = {}

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command = tuple(argv)
        self.calls.append(command)
        if command[:2] == ("certbot", "certonly"):
            cert_name = command[command.index("--cert-name") + 1]
            names = tuple(command[index + 1] for index, part in enumerate(command) if part == "-d")
            self.groups[cert_name] = names
            live = self.root / "etc/letsencrypt/live" / cert_name
            live.mkdir(parents=True, exist_ok=True)
            key = live / "privkey.pem"
            key.write_text("not-a-real-key")
            key.chmod(0o600)
            (live / "fullchain.pem").write_text("not-a-real-certificate")
            return subprocess.CompletedProcess(command, 0, "certificate details", "")
        if command[:2] == ("openssl", "x509"):
            cert_name = Path(command[command.index("-in") + 1]).parent.name
            names = self.groups.get(cert_name, ())
            sans = ", ".join(f"DNS:{name}" for name in names)
            return subprocess.CompletedProcess(command, 0, f"X509v3 Subject Alternative Name:\n    {sans}\n", "")
        if command == ("certbot", "renew", "--dry-run", "--no-random-sleep-on-renew"):
            return subprocess.CompletedProcess(command, 0, "renewal details", "")
        raise AssertionError(command)


def test_certificate_plan_groups_service_names_and_uses_webroot(tmp_path: Path) -> None:
    runner = CertRunner(tmp_path)
    adapter = CertificatePlan(
        root=tmp_path,
        runner=runner,
        expected_key_owner=(os.getuid(), tmp_path.stat().st_gid),
    )
    actions = adapter.plan(config(profile=Profile.CORE_NAIVE), dns_facts())

    assert [(action.id, action.owner) for action in actions] == [
        ("certificate.naive", "proxy-control:certificate:naive"),
        ("certificate.proxy-control", "proxy-control:certificate:proxy-control"),
    ]
    core = next(action for action in actions if action.id == "certificate.proxy-control")
    applied = adapter.apply(core, adapter.prepare(core))

    certbot = next(call for call in runner.calls if call[:2] == ("certbot", "certonly"))
    assert certbot.count("--webroot") == 1
    assert certbot.count("-w") == 2
    assert {certbot[index + 1] for index, part in enumerate(certbot) if part == "-d"} == {
        "mt.example.com",
        "panel.example.com",
    }
    assert applied["certificate"] == "mt.example.com"
    assert runner.calls[-1] == (
        "certbot",
        "renew",
        "--dry-run",
        "--no-random-sleep-on-renew",
    )


@pytest.mark.parametrize("fact", ["a_matches_local", "aaaa_handled", "caa_compatible"])
def test_certificate_plan_fails_closed_on_domain_facts(fact: str, tmp_path: Path) -> None:
    adapter = CertificatePlan(root=tmp_path, runner=CertRunner(tmp_path))

    with pytest.raises(TopologyError, match="domain preflight"):
        adapter.plan(config(profile=Profile.CORE_NAIVE), dns_facts(bad=fact))


def test_certificate_commands_and_checkpoint_are_secret_free(tmp_path: Path) -> None:
    runner = CertRunner(tmp_path)
    adapter = CertificatePlan(
        root=tmp_path,
        runner=runner,
        expected_key_owner=(os.getuid(), tmp_path.stat().st_gid),
    )
    action = adapter.plan(config(), dns_facts())[0]

    applied = adapter.apply(action, adapter.prepare(action))
    serialized = json.dumps(applied, sort_keys=True)
    calls = json.dumps(runner.calls)

    assert "not-a-real-key" not in serialized + calls
    assert "password" not in serialized.lower()
    assert all("not-a-real-key" not in part for call in runner.calls for part in call)


def test_certificate_verification_checks_private_key_permissions_and_sans(tmp_path: Path) -> None:
    runner = CertRunner(tmp_path)
    adapter = CertificatePlan(
        root=tmp_path,
        runner=runner,
        expected_key_owner=(os.getuid(), tmp_path.stat().st_gid),
    )
    action = adapter.plan(config(), dns_facts())[0]
    applied = adapter.apply(action, adapter.prepare(action))
    assert adapter.verify(action).success is True
    wrong_owner = CertificatePlan(
        root=tmp_path,
        runner=runner,
        expected_key_owner=(os.getuid() + 1, tmp_path.stat().st_gid),
    )
    assert wrong_owner.verify(action).success is False

    cert_name = str(applied["certificate"])
    key = tmp_path / "etc/letsencrypt/live" / cert_name / "privkey.pem"
    key.chmod(0o640)
    assert adapter.verify(action).success is False
    key.chmod(0o600)
    runner.groups[cert_name] = ("mt.example.com",)
    assert adapter.verify(action).success is False

def test_certificate_renewal_dry_run_is_mandatory_and_output_is_suppressed(
    tmp_path: Path,
) -> None:
    class FailingRenewRunner(CertRunner):
        def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
            command = tuple(argv)
            if command == (
                "certbot",
                "renew",
                "--dry-run",
                "--no-random-sleep-on-renew",
            ):
                self.calls.append(command)
                return subprocess.CompletedProcess(
                    command,
                    1,
                    "credential=must-not-escape",
                    "",
                )
            return super().run(argv)

    runner = FailingRenewRunner(tmp_path)
    adapter = CertificatePlan(
        root=tmp_path,
        runner=runner,
        expected_key_owner=(os.getuid(), tmp_path.stat().st_gid),
    )
    action = adapter.plan(config(), dns_facts())[0]

    with pytest.raises(TopologyError, match="renewal dry run failed") as caught:
        adapter.apply(action, adapter.prepare(action))

    assert "must-not-escape" not in str(caught.value)



def canonical_ufw(*rules: str, active: bool = True) -> str:
    status = "active" if active else "inactive"
    if not active:
        return f"Status: {status}\n"
    lines = [
        f"Status: {status}",
        "",
        "     To                         Action      From",
        "     --                         ------      ----",
    ]
    lines.extend(f"[{index:2}] {rule}" for index, rule in enumerate(rules, 1))
    return "\n".join(lines) + "\n"


class UfwRunner:
    def __init__(self, rules: list[str], *, active: bool = True) -> None:
        self.rules = list(rules)
        self.active = active
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command = tuple(argv)
        self.calls.append(command)
        if command == ("ufw", "status", "numbered"):
            return subprocess.CompletedProcess(
                command,
                0,
                canonical_ufw(*self.rules, active=self.active),
                "",
            )
        if command[:2] == ("ufw", "allow"):
            protocol = command[command.index("proto") + 1]
            port = command[command.index("port") + 1]
            comment = command[command.index("comment") + 1]
            rendered = f"{port}/{protocol} ALLOW IN Anywhere # {comment}"
            if rendered not in self.rules:
                self.rules.append(rendered)
            return subprocess.CompletedProcess(command, 0, "rule details", "")
        if command[:4] == ("ufw", "--force", "delete", "allow"):
            protocol = command[command.index("proto") + 1]
            port = command[command.index("port") + 1]
            comment = command[command.index("comment") + 1]
            rendered = f"{port}/{protocol} ALLOW IN Anywhere # {comment}"
            self.rules.remove(rendered)
            return subprocess.CompletedProcess(command, 0, "rule details", "")
        raise AssertionError(command)


def firewall_facts(*, ssh_ports: tuple[int, ...] = (22,)) -> AuditFacts:
    return AuditFacts(
        listeners={
            "tcp": ssh_ports,
            "udp": (),
            "ports": ssh_ports,
            "owners": {str(port): ("sshd",) for port in ssh_ports},
        },
        ownership={
            "ufw": {
                "active": True,
                "available": True,
                "mode": "managed",
                "observation": "observed",
            }
        },
    )


def test_fresh_ufw_rules_preserve_ssh_and_are_exactly_reversible() -> None:
    runner = UfwRunner(["22/tcp ALLOW IN Anywhere # operator:ssh"])
    adapter = FirewallAdapter(runner=runner, ssh_ports={22})
    selected = config(profile=Profile.CORE_MIERU)
    action = adapter.plan(selected, firewall_facts())[0]
    original = list(runner.rules)

    applied = adapter.apply(action, adapter.prepare(action))
    adapter.rollback(action, applied)

    assert runner.rules == original
    mutations = [call for call in runner.calls if call != ("ufw", "status", "numbered")]
    assert all("reset" not in call and "default" not in call for call in mutations)
    assert all("operator:ssh" not in call for call in mutations)


def test_ufw_duplicate_or_preexisting_rule_is_not_claimed_or_deleted() -> None:
    runner = UfwRunner(
        [
            "22/tcp ALLOW IN Anywhere # operator:ssh",
            "80/tcp ALLOW IN Anywhere # foreign:web",
        ]
    )
    adapter = FirewallAdapter(runner=runner, ssh_ports={22})
    action = adapter.plan(config(), firewall_facts())[0]

    applied = adapter.apply(action, adapter.prepare(action))
    assert "tcp:80" not in applied["installer_added"]
    adapter.rollback(action, applied)

    assert "80/tcp ALLOW IN Anywhere # foreign:web" in runner.rules
    assert runner.rules == [
        "22/tcp ALLOW IN Anywhere # operator:ssh",
        "80/tcp ALLOW IN Anywhere # foreign:web",
    ]


def test_ufw_crash_replay_claims_only_exact_owned_rule() -> None:
    runner = UfwRunner(["22/tcp ALLOW IN Anywhere # operator:ssh"])
    adapter = FirewallAdapter(runner=runner, ssh_ports={22})
    action = adapter.plan(config(), firewall_facts())[0]
    prepared = adapter.prepare(action)
    runner.rules.append(
        "80/tcp ALLOW IN Anywhere # proxy-control:firewall:tcp:80"
    )

    reconciled = adapter.reconcile_apply(action, prepared)
    assert "tcp:80" in reconciled["installer_added"]
    assert runner.rules.count(
        "80/tcp ALLOW IN Anywhere # proxy-control:firewall:tcp:80"
    ) == 1

    adapter.rollback(action, reconciled)
    replay = adapter.reconcile_rollback(action, reconciled)
    assert replay.success is True
    assert runner.rules == ["22/tcp ALLOW IN Anywhere # operator:ssh"]

def test_ufw_crash_rollback_recovers_unjournaled_owned_rule() -> None:
    runner = UfwRunner(["22/tcp ALLOW IN Anywhere # operator:ssh"])
    adapter = FirewallAdapter(runner=runner, ssh_ports={22})
    action = adapter.plan(config(), firewall_facts())[0]
    prepared = adapter.prepare(action)
    runner.rules.append(
        "80/tcp ALLOW IN Anywhere # proxy-control:firewall:tcp:80"
    )

    evidence = adapter.reconcile_rollback(action, prepared)

    assert evidence.success is True
    assert runner.rules == ["22/tcp ALLOW IN Anywhere # operator:ssh"]



@pytest.mark.parametrize(
    "text",
    [
        canonical_ufw(active=False),
        "Status: active\nnonstandard output\n",
        canonical_ufw("OpenSSH ALLOW IN Anywhere"),
        canonical_ufw("22/tcp MAYBE Anywhere"),
    ],
)
def test_ufw_parser_rejects_inactive_or_noncanonical_output(text: str) -> None:
    with pytest.raises(FirewallError):
        parse_ufw_status(text)


def test_firewall_refuses_absent_or_ambiguous_ssh_listener() -> None:
    runner = UfwRunner(["22/tcp ALLOW IN Anywhere # operator:ssh"])
    adapter = FirewallAdapter(runner=runner)

    with pytest.raises(FirewallError, match="SSH listener"):
        adapter.plan(config(), firewall_facts(ssh_ports=()))
    with pytest.raises(FirewallError, match="ambiguous"):
        adapter.plan(config(), firewall_facts(ssh_ports=(22, 2222)))


def test_firewall_refuses_ambiguous_ssh_preservation() -> None:
    runner = UfwRunner(
        [
            "22/tcp ALLOW IN Anywhere # first",
            "22/tcp ALLOW IN Anywhere # duplicate",
        ]
    )
    adapter = FirewallAdapter(runner=runner, ssh_ports={22})

    with pytest.raises(FirewallError, match="ambiguous"):
        adapter.plan(config(), firewall_facts())


def test_coexist_emits_no_firewall_action_or_ufw_command() -> None:
    runner = UfwRunner([])
    adapter = FirewallAdapter(runner=runner, ssh_ports={22})

    assert adapter.plan(config(mode=HostMode.COEXIST), firewall_facts()) == ()
    assert runner.calls == []


def test_firewall_rejects_foreign_backend_ownership() -> None:
    runner = UfwRunner(["22/tcp ALLOW IN Anywhere # operator:ssh"])
    adapter = FirewallAdapter(runner=runner, ssh_ports={22})
    facts = firewall_facts()
    facts = AuditFacts(
        listeners=facts.listeners,
        ownership={**facts.ownership, "firewall": {"backend": "nftables"}},
    )

    with pytest.raises(FirewallError, match="firewall ownership"):
        adapter.plan(config(), facts)
