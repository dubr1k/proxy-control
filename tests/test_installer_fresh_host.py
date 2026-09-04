from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Sequence

import pytest

from installer.adapters.firewall import FirewallAdapter, FirewallError, parse_ufw_status
from installer.adapters.nginx import CertificatePlan, TopologyError
from installer.adapters.packages import (
    DEFAULT_PACKAGES,
    PackageError,
    PackagesAdapter,
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
from installer.planner import AuditFacts, InstallPlan, ReleaseIdentity
from installer.transaction import TransactionEngine, TransactionStore


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
            for specification in command[5:]:
                package, separator, version = specification.partition("=")
                self.installed.setdefault(
                    package,
                    version if separator else "1.0",
                )
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




def test_default_packages_exist_in_ubuntu_2404_repositories() -> None:
    assert "docker.io" in DEFAULT_PACKAGES
    assert "docker-compose-v2" in DEFAULT_PACKAGES
    assert not {"docker-ce", "docker-ce-cli", "docker-compose-plugin"} & set(
        DEFAULT_PACKAGES
    )


@pytest.mark.parametrize(
    ("status", "preexisting"),
    [("hi ", True), ("rc ", False)],
)
def test_dpkg_valid_held_and_residual_states_are_handled(
    status: str,
    preexisting: bool,
) -> None:
    class StateRunner(AptRunner):
        def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
            command = tuple(argv)
            if command[:2] == ("dpkg-query", "--show") and not any(
                call[:2] == ("apt-get", "install") for call in self.calls
            ):
                self.calls.append(command)
                return subprocess.CompletedProcess(
                    command,
                    0,
                    f"curl\t{status}\t8.0\n",
                    "",
                )
            return super().run(argv)

    runner = StateRunner({"curl": "8.0"})
    adapter = PackagesAdapter(runner=runner, packages=("curl",))
    action = package_action(adapter)
    prepared = adapter.prepare(action)

    assert ("curl" in prepared["preexisting"]) is preexisting
    if not preexisting:
        adapter.apply(action, prepared)
        assert any(call[:2] == ("apt-get", "install") for call in runner.calls)


def test_mutation_runners_have_operation_length_timeouts(tmp_path: Path) -> None:
    assert PackagesAdapter().runner.timeout >= 300
    assert CertificatePlan(root=tmp_path).runner.timeout >= 300


def test_transaction_repair_reinstalls_only_missing_owned_package(
    tmp_path: Path,
) -> None:
    runner = AptRunner({"curl": "8.0"})
    adapter = PackagesAdapter(runner=runner, packages=("curl", "nginx-full"))
    selected_config = config()
    selected_facts = AuditFacts()
    action = package_action(adapter, selected_config)
    plan = InstallPlan(
        config=selected_config.canonical_dict(),
        facts=selected_facts,
        release=ReleaseIdentity(
            tag="v1.0.0",
            commit="1" * 40,
            manifest_sha256="2" * 64,
        ),
        adapter_order=("packages",),
        adapter_dependencies={"packages": ()},
        actions=(action,),
    )
    engine = TransactionEngine(TransactionStore(tmp_path), {"packages": adapter})
    assert engine.apply(plan, accepted_digest=plan.digest).status == "active"
    runner.installed.pop("nginx-full")

    repaired = engine.repair()

    assert repaired.status == "active"
    assert runner.installed == {"curl": "8.0", "nginx-full": "1.0"}
    repair_install = [
        call for call in runner.calls if call[:2] == ("apt-get", "install")
    ][-1]
    assert "curl" not in repair_install
    assert "nginx-full=1.0" in repair_install

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
        self.dates_valid = True
        self.key_valid = True
        self.key_matches = True
        self.chain_valid = True
        self.effective_vhost = True

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command = tuple(argv)
        self.calls.append(command)
        if command[:2] == ("certbot", "certonly"):
            cert_name = command[command.index("--cert-name") + 1]
            names = tuple(
                command[index + 1]
                for index, part in enumerate(command)
                if part == "-d"
            )
            self.groups[cert_name] = names
            live = self.root / "etc/letsencrypt/live" / cert_name
            live.mkdir(parents=True, exist_ok=True)
            key = live / "privkey.pem"
            key.write_text("not-a-real-key")
            key.chmod(0o600)
            for name in ("cert.pem", "chain.pem", "fullchain.pem"):
                (live / name).write_text("not-a-real-certificate")
            return subprocess.CompletedProcess(command, 0, "certificate details", "")
        if command[:2] == ("openssl", "pkey"):
            return subprocess.CompletedProcess(
                command,
                0 if self.key_valid else 1,
                "PUBLIC-KEY\n" if self.key_matches else "OTHER-PUBLIC-KEY\n",
                "",
            )
        if command[:2] == ("openssl", "x509"):
            if "-checkend" in command:
                return subprocess.CompletedProcess(
                    command,
                    0 if self.dates_valid else 1,
                    "",
                    "",
                )
            if "-pubkey" in command:
                return subprocess.CompletedProcess(command, 0, "PUBLIC-KEY\n", "")
            cert_name = Path(command[command.index("-in") + 1]).parent.name
            names = self.groups.get(cert_name, ())
            sans = ", ".join(f"DNS:{name}" for name in names)
            return subprocess.CompletedProcess(
                command,
                0,
                f"X509v3 Subject Alternative Name:\n    {sans}\n",
                "",
            )
        if command[:2] == ("openssl", "verify"):
            return subprocess.CompletedProcess(
                command,
                0 if self.chain_valid else 1,
                "verified\n",
                "",
            )
        if command == ("nginx", "-T"):
            rendered = "# configuration file /etc/nginx/nginx.conf:\nevents {}\n"
            if self.effective_vhost:
                confd = self.root / "etc/nginx/conf.d"
                for path in sorted(confd.glob("proxy-control-acme-*.conf")):
                    rendered += (
                        f"# configuration file /etc/nginx/conf.d/{path.name}:\n"
                        + path.read_text()
                    )
            return subprocess.CompletedProcess(command, 0, rendered, "")
        if command in {
            ("nginx", "-t"),
            ("systemctl", "reload", "nginx"),
        }:
            return subprocess.CompletedProcess(command, 0, "", "")
        if (
            len(command) >= 2
            and command[:2] == ("certbot", "renew")
            and "--dry-run" in command
        ):
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
        "--cert-name",
        "mt.example.com",
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
                "--cert-name",
                "mt.example.com",
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

def test_certificate_owns_http01_vhost_before_certbot_and_removes_only_it(
    tmp_path: Path,
) -> None:
    runner = CertRunner(tmp_path)
    adapter = CertificatePlan(
        root=tmp_path,
        runner=runner,
        expected_key_owner=(os.getuid(), tmp_path.stat().st_gid),
    )
    action = adapter.plan(config(), dns_facts())[0]
    foreign = tmp_path / "etc/nginx/conf.d/foreign.conf"
    foreign.parent.mkdir(parents=True)
    foreign.write_text("server { listen 80; server_name foreign.example.com; }\n")

    applied = adapter.apply(action, adapter.prepare(action))

    owned = tmp_path / "etc/nginx/conf.d/proxy-control-acme-proxy-control.conf"
    assert owned.is_file()
    assert "server_name mt.example.com;" in owned.read_text()
    assert "server_name panel.example.com;" in owned.read_text()
    assert runner.calls.index(("systemctl", "reload", "nginx")) < next(
        index
        for index, call in enumerate(runner.calls)
        if call[:2] == ("certbot", "certonly")
    )

    adapter.rollback(action, applied)
    assert not owned.exists()
    assert foreign.is_file()

def test_certificate_refuses_when_owned_vhost_is_absent_from_effective_nginx(
    tmp_path: Path,
) -> None:
    runner = CertRunner(tmp_path)
    runner.effective_vhost = False
    adapter = CertificatePlan(
        root=tmp_path,
        runner=runner,
        expected_key_owner=(os.getuid(), tmp_path.stat().st_gid),
    )
    action = adapter.plan(config(), dns_facts())[0]

    with pytest.raises(TopologyError, match="effective Nginx"):
        adapter.apply(action, adapter.prepare(action))

    assert not any(call[:2] == ("certbot", "certonly") for call in runner.calls)



def test_certificate_refuses_to_modify_preexisting_invalid_lineage(
    tmp_path: Path,
) -> None:
    runner = CertRunner(tmp_path)
    live = tmp_path / "etc/letsencrypt/live/mt.example.com"
    live.mkdir(parents=True)
    key = live / "privkey.pem"
    key.write_text("existing-key")
    key.chmod(0o600)
    for name in ("cert.pem", "chain.pem", "fullchain.pem"):
        (live / name).write_text("existing-certificate")
    runner.groups["mt.example.com"] = ("mt.example.com",)
    adapter = CertificatePlan(
        root=tmp_path,
        runner=runner,
        expected_key_owner=(os.getuid(), tmp_path.stat().st_gid),
    )
    action = adapter.plan(config(), dns_facts())[0]

    with pytest.raises(TopologyError, match="pre-existing certificate lineage"):
        adapter.apply(action, adapter.prepare(action))

    assert not any(call[:2] == ("certbot", "certonly") for call in runner.calls)


def test_certificate_validation_requires_exact_sans_dates_key_pair_and_chain(
    tmp_path: Path,
) -> None:
    runner = CertRunner(tmp_path)
    adapter = CertificatePlan(
        root=tmp_path,
        runner=runner,
        expected_key_owner=(os.getuid(), tmp_path.stat().st_gid),
    )
    action = adapter.plan(config(), dns_facts())[0]
    adapter.apply(action, adapter.prepare(action))
    certificate = "mt.example.com"

    assert any(call[:2] == ("openssl", "pkey") for call in runner.calls)
    assert any(
        call[:2] == ("openssl", "x509") and "-checkend" in call
        for call in runner.calls
    )
    assert any(call[:2] == ("openssl", "verify") for call in runner.calls)

    runner.groups[certificate] = (
        "extra.example.com",
        "mt.example.com",
        "panel.example.com",
    )
    assert adapter.verify(action).success is False
    runner.groups[certificate] = ("mt.example.com", "panel.example.com")

    runner.dates_valid = False
    assert adapter.verify(action).success is False
    runner.dates_valid = True
    runner.key_valid = False
    assert adapter.verify(action).success is False
    runner.key_valid = True
    runner.key_matches = False
    assert adapter.verify(action).success is False
    runner.key_matches = True
    runner.chain_valid = False
    assert adapter.verify(action).success is False




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
    def __init__(
        self,
        rules: list[str],
        *,
        active: bool = True,
        ipv6_enabled: bool = False,
    ) -> None:
        self.rules = list(rules)
        self.active = active
        self.ipv6_enabled = ipv6_enabled
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
            if self.ipv6_enabled:
                rendered_v6 = (
                    f"{port}/{protocol} (v6) ALLOW IN Anywhere (v6) # {comment}"
                )
                if rendered_v6 not in self.rules:
                    self.rules.append(rendered_v6)
            return subprocess.CompletedProcess(command, 0, "rule details", "")
        if command[:4] == ("ufw", "--force", "delete", "allow"):
            protocol = command[command.index("proto") + 1]
            port = command[command.index("port") + 1]
            comment = command[command.index("comment") + 1]
            rendered = f"{port}/{protocol} ALLOW IN Anywhere # {comment}"
            self.rules.remove(rendered)
            rendered_v6 = (
                f"{port}/{protocol} (v6) ALLOW IN Anywhere (v6) # {comment}"
            )
            if rendered_v6 in self.rules:
                self.rules.remove(rendered_v6)
            return subprocess.CompletedProcess(command, 0, "rule details", "")
        raise AssertionError(command)


def firewall_facts(
    *,
    ssh_ports: tuple[int, ...] = (22,),
    owner: str = "sshd",
    ssh_socket_tcp: tuple[int, ...] = (),
    ipv6_enabled: bool = False,
) -> AuditFacts:
    return AuditFacts(
        listeners={
            "tcp": ssh_ports,
            "udp": (),
            "ports": ssh_ports,
            "owners": {str(port): (owner,) for port in ssh_ports},
            "ssh_socket_tcp": ssh_socket_tcp,
        },
        ownership={
            "ufw": {
                "active": True,
                "available": True,
                "ipv6_enabled": ipv6_enabled,
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

def test_ufw_lone_ipv6_rule_does_not_cover_required_ipv4() -> None:
    runner = UfwRunner(
        [
            "22/tcp ALLOW IN Anywhere # operator:ssh",
            "80/tcp (v6) ALLOW IN Anywhere (v6) # foreign:web6",
        ]
    )
    adapter = FirewallAdapter(runner=runner, ssh_ports={22})
    action = adapter.plan(config(), firewall_facts())[0]

    applied = adapter.apply(action, adapter.prepare(action))

    assert "tcp:80" in applied["installer_added"]
    assert (
        "80/tcp ALLOW IN Anywhere # proxy-control:firewall:tcp:80"
        in runner.rules
    )


def test_ufw_requires_both_families_when_ipv6_is_enabled() -> None:
    runner = UfwRunner(
        [
            "22/tcp ALLOW IN Anywhere # operator:ssh",
            "22/tcp (v6) ALLOW IN Anywhere (v6) # operator:ssh",
        ],
        ipv6_enabled=True,
    )
    adapter = FirewallAdapter(runner=runner, ssh_ports={22})
    action = adapter.plan(config(), firewall_facts(ipv6_enabled=True))[0]

    applied = adapter.apply(action, adapter.prepare(action))

    assert "ipv6=true" in action.mutations
    assert "tcp:80" in applied["installer_added"]
    assert any(
        rule.startswith("80/tcp (v6)") for rule in runner.rules
    )


def test_firewall_accepts_explicit_audited_ssh_socket_port() -> None:
    runner = UfwRunner(["22/tcp ALLOW IN Anywhere # operator:ssh"])
    adapter = FirewallAdapter(runner=runner)
    facts = firewall_facts(
        owner="systemd",
        ssh_socket_tcp=(22,),
    )

    action = adapter.plan(config(), facts)[0]

    assert "ssh=22" in action.mutations



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
