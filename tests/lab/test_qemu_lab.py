from __future__ import annotations

import importlib.util
import inspect
import json
import os
import re
import socket
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE = Path(__file__).parents[2] / "scripts" / "lab" / "qemu_lab.py"
spec = importlib.util.spec_from_file_location("qemu_lab", MODULE)
lab = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(lab)


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert seconds > 0
        self.sleeps.append(seconds)
        self.now += seconds


class QemuLabTests(unittest.TestCase):
    def test_full_install_probes_panel_through_final_tls_sni_route(self):
        runner = (MODULE.parent / "guest-runner.sh").read_text()
        self.assertIn("--resolve \"$PANEL:443:127.0.0.1\"", runner)
        self.assertIn("\"https://$PANEL/healthz\"", runner)
        self.assertIn("jq -e '.status == \"ok\"'", runner)

    def test_fake_certbot_issues_a_complete_locally_trusted_lineage(self):
        runner = MODULE.parent / "guest-runner.sh"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certbot = root / "certbot"
            generated = subprocess.run(
                ["bash", "-c", f"source {runner!s}; write_fake_certbot {certbot!s}"],
                capture_output=True,
                text=True,
                env={**os.environ, "GUEST_RUNNER_LIB_ONLY": "1"},
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)

            completed = subprocess.run(
                [
                    str(certbot), "certonly",
                    "-d", "proxy.lab.test", "-d", "panel.lab.test",
                    "--cert-name", "proxy.lab.test",
                ],
                capture_output=True,
                text=True,
                env={**os.environ, "LETSENCRYPT_ROOT": str(root / "letsencrypt")},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            source = root / "letsencrypt" / "live" / "proxy.lab.test"
            panel = root / "letsencrypt" / "live" / "panel.lab.test"
            for filename in ("fullchain.pem", "privkey.pem"):
                self.assertTrue((source / filename).is_file())
                self.assertEqual((source / filename).read_bytes(), (panel / filename).read_bytes())
                self.assertEqual(
                    (source / filename).stat().st_mode & 0o777,
                    (panel / filename).stat().st_mode & 0o777,
                )
            certificate = subprocess.run(
                ["openssl", "x509", "-in", str(source / "fullchain.pem"), "-noout", "-ext", "subjectAltName"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("DNS:proxy.lab.test", certificate.stdout)
            self.assertIn("DNS:panel.lab.test", certificate.stdout)

            # The installer requires a complete Certbot-shaped lineage.
            for filename in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"):
                self.assertTrue((source / filename).is_file(), filename)
            self.assertEqual((source / "privkey.pem").stat().st_mode & 0o777, 0o600)
            self.assertTrue(
                (root / "letsencrypt" / "renewal" / "proxy.lab.test.conf").is_file()
            )
            self.assertTrue(
                (root / "letsencrypt" / "archive" / "proxy.lab.test").is_dir()
            )
            # The leaf verifies against the lab CA, so trust checks pass.
            verified = subprocess.run(
                [
                    "openssl", "verify",
                    "-CAfile", str(root / "letsencrypt" / "lab-ca" / "ca.crt"),
                    "-untrusted", str(source / "chain.pem"),
                    str(source / "cert.pem"),
                ],
                capture_output=True, text=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            # The key belongs to the leaf.
            key_public = subprocess.run(
                ["openssl", "pkey", "-in", str(source / "privkey.pem"), "-pubout"],
                capture_output=True, text=True, check=True,
            ).stdout
            leaf_public = subprocess.run(
                ["openssl", "x509", "-in", str(source / "cert.pem"), "-pubkey", "-noout"],
                capture_output=True, text=True, check=True,
            ).stdout
            self.assertEqual(key_public.strip(), leaf_public.strip())

    def test_case_run_preserves_failure_output_and_does_not_swallow_early_failure(self):
        runner = MODULE.parent / "guest-runner.sh"
        script = f"""
source {runner!s}
fails_early() {{ printf 'first useful error\\n' >&2; false; printf 'must not run\\n' >&2; }}
captured_failure() {{ run_captured /tmp/lab-test-captured.log fails_early; }}
case_run install captured_failure
"""
        completed = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True,
            env={**os.environ, "GUEST_RUNNER_LIB_ONLY": "1"},
        )
        self.assertIn("LAB_RESULT\tinstall\tfailed", completed.stdout)
        self.assertIn("first useful error", completed.stdout)
        self.assertNotIn("must not run", completed.stdout)

    def test_case_run_skips_scenario_when_explicit_prerequisite_failed(self):
        runner = MODULE.parent / "guest-runner.sh"
        script = f"""
source {runner!s}
fails() {{ false; }}
must_not_run() {{ printf 'prerequisite was ignored\\n' >&2; return 0; }}
case_run install fails
case_run repair must_not_run install
"""
        completed = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True,
            env={**os.environ, "GUEST_RUNNER_LIB_ONLY": "1"},
        )
        self.assertIn("LAB_RESULT\trepair\tskipped", completed.stdout)
        self.assertIn("prerequisite failed: install", completed.stdout)
        self.assertNotIn("prerequisite was ignored", completed.stdout)

    def test_allocate_port_returns_bindable_loopback_port(self):
        port = lab.allocate_port()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))

    def qemu_command(self, mode):
        return lab.qemu_command(
            Path("disk.qcow2"), Path("seed.img"), Path("lab.key"), 22022,
            Path("pid"), Path("serial.log"), mode,
        )

    def test_smoke_qemu_command_has_no_guest_outbound(self):
        rendered = " ".join(self.qemu_command("smoke"))
        self.assertIn("-accel tcg", rendered)
        self.assertIn("-smp 2", rendered)
        self.assertIn("-m 3072", rendered)
        self.assertIn("restrict=on", rendered)
        self.assertIn("hostfwd=tcp:127.0.0.1:22022-:22", rendered)
        self.assertNotIn("tap", rendered)

    def test_full_qemu_command_uses_user_nat_for_policy_bounded_outbound(self):
        rendered = " ".join(self.qemu_command("full"))
        self.assertIn("restrict=off", rendered)
        self.assertIn("hostfwd=tcp:127.0.0.1:22022-:22", rendered)
        self.assertNotIn("tap", rendered)
        self.assertNotIn("bridge", rendered)

    def test_qemu_command_rejects_missing_or_unknown_mode(self):
        for mode in (None, "", "default", "typo"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.qemu_command(mode)

    def test_full_egress_policy_is_valid_and_rejects_non_public_destinations(self):
        policy = lab.full_egress_policy()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".nft") as stream:
            stream.write(policy)
            stream.flush()
            checked = subprocess.run(["nft", "--check", "--file", stream.name], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("ip daddr 10.0.2.3 udp dport 53 accept", policy)
        self.assertIn("ip daddr 10.0.2.3 tcp dport 53 accept", policy)
        for blocked in ("10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"):
            self.assertIn(blocked, policy)
        self.assertIn("tcp dport { 80, 443 } accept", policy)
        self.assertLess(policy.index("ct state established,related accept"), policy.index("10.0.0.0/8"))

    def test_full_cloud_init_installs_egress_policy_before_readiness(self):
        user_data = lab.user_data("full", "ssh-ed25519 test")
        self.assertIn("/etc/nftables.d/mtproxy-lab-egress.nft", user_data)
        self.assertLess(user_data.index("nft -f"), user_data.index("lab-ready"))
        self.assertLess(user_data.index("systemctl enable nftables.service"), user_data.index("lab-ready"))

    def test_start_requires_explicit_mode_and_smoke_cloud_init_has_no_egress_policy(self):
        mode = inspect.signature(lab.start).parameters["mode"]
        self.assertIs(mode.default, inspect.Parameter.empty)
        self.assertNotIn("nft -f", lab.user_data("smoke", "ssh-ed25519 test"))
        for invalid in (None, "", "default"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                lab.user_data(invalid, "ssh-ed25519 test")

    def test_ssh_command_bounds_connection_and_unresponsive_server(self):
        with mock.patch.object(lab, "_state_port", return_value=22022):
            command = lab.ssh_command("true")
        self.assertIn("BatchMode=yes", command)
        self.assertIn("ConnectTimeout=5", command)
        self.assertIn("ServerAliveInterval=5", command)
        self.assertIn("ServerAliveCountMax=1", command)

    def test_readiness_retries_after_timed_out_probe_and_later_succeeds(self):
        clock = FakeClock()
        probe_timeouts = []

        def probe(command, **kwargs):
            probe_timeouts.append(kwargs["timeout"])
            if len(probe_timeouts) == 1:
                clock.now += kwargs["timeout"]
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])
            return subprocess.CompletedProcess(command, 0)

        with (
            mock.patch.object(lab.subprocess, "run", side_effect=probe),
            mock.patch.object(lab.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(lab.time, "sleep", side_effect=clock.sleep),
            mock.patch.object(lab, "_state_port", return_value=22022),
        ):
            lab.wait_for_readiness(timeout=30)

        self.assertEqual(probe_timeouts, [10, 10])
        self.assertEqual(clock.sleeps, [5])

    def test_readiness_hung_probes_cannot_exceed_overall_deadline(self):
        clock = FakeClock()
        probe_timeouts = []

        def hung_probe(command, **kwargs):
            probe_timeouts.append(kwargs["timeout"])
            clock.now += kwargs["timeout"]
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        with (
            mock.patch.object(lab.subprocess, "run", side_effect=hung_probe),
            mock.patch.object(lab.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(lab.time, "sleep", side_effect=clock.sleep),
            mock.patch.object(lab, "_state_port", return_value=22022),
            self.assertRaisesRegex(TimeoutError, "last SSH readiness probe timed out"),
        ):
            lab.wait_for_readiness(timeout=17)

        self.assertEqual(probe_timeouts, [10, 2])
        self.assertEqual(clock.sleeps, [5])
        self.assertEqual(clock.now, 17)

    def test_readiness_failed_probes_sleep_without_busy_loop_until_deadline(self):
        clock = FakeClock()
        attempts = []

        def failed_probe(command, **kwargs):
            attempts.append(kwargs["timeout"])
            return subprocess.CompletedProcess(command, 255)

        with (
            mock.patch.object(lab.subprocess, "run", side_effect=failed_probe),
            mock.patch.object(lab.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(lab.time, "sleep", side_effect=clock.sleep),
            mock.patch.object(lab, "_state_port", return_value=22022),
            self.assertRaisesRegex(TimeoutError, "last SSH readiness probe exited 255"),
        ):
            lab.wait_for_readiness(timeout=11)

        self.assertEqual(attempts, [10, 6, 1])
        self.assertEqual(clock.sleeps, [5, 5, 1])

    def test_sanitize_removes_proxy_links_and_credentials(self):
        text = "password=hello telemt-api-token=abc tg://proxy?server=x&secret=ee123"
        clean = lab.sanitize(text)
        self.assertNotIn("hello", clean)
        self.assertNotIn("abc", clean)
        self.assertNotIn("ee123", clean)
        self.assertIn("[REDACTED]", clean)

    def test_junit_represents_failure(self):
        xml = lab.junit_xml([{"name": "audit", "status": "passed", "seconds": 1.0}, {"name": "install", "status": "failed", "seconds": 2.0, "message": "boom"}])
        self.assertIn('tests="2"', xml)
        self.assertIn('failures="1"', xml)
        self.assertIn("<failure", xml)

    def test_full_preflight_failure_is_named_and_remaining_scenarios_fail_closed(self):
        results = lab.finalize_results("full", [], returncode=100, elapsed=2.5)
        self.assertEqual(results[0], {
            "name": "environment-preflight", "status": "failed", "seconds": 2.5,
            "message": "guest setup failed before scenarios (exit 100)",
        })
        missing = {item["name"] for item in results if item["message"].startswith("result missing")}
        self.assertEqual(missing, set(lab.SCENARIOS["full"]) - {"environment-preflight"})

    def test_full_scenario_catalog_covers_lifecycle_and_faults(self):
        names = set(lab.SCENARIOS["full"])
        self.assertTrue({
            "environment-preflight", "audit", "plan", "install", "repair", "idempotence", "uninstall",
            "interrupted-install-recovery", "interrupted-uninstall-recovery",
            "coexistence", "dns-tls-preflight", "docker-build", "secrets-scan",
        } <= names)

    def test_guest_runner_is_invoked_through_bash_for_archived_mode_bits(self):
        remote = lab.guest_remote("smoke", "a" * 64)
        self.assertIn("sudo bash /tmp/mtproxy-source/scripts/lab/guest-runner.sh", remote)

    def test_pinned_image_metadata_has_sha256(self):
        document = json.loads((MODULE.parent / "image.json").read_text())
        self.assertEqual(document["schema"], 2)
        amd64 = document["images"]["amd64"]
        self.assertRegex(amd64["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("ubuntu-24.04", amd64["url"])
        for architecture, image in document["images"].items():
            self.assertEqual(image["architecture"], architecture)
            self.assertIn("cloud-images.ubuntu.com", image["url"])
            self.assertIn(architecture, image["url"])



REQUIRED_RELEASE_SCENARIOS = {
    "environment-preflight",
    "release-artifact-integrity",
    "audit",
    "plan",
    "docker-build",
    "repair",
    "idempotence",
    "secrets-scan",
    "dns-tls-preflight",
    "uninstall",
    "interrupted-install-recovery",
    "interrupted-uninstall-recovery",
    "coexistence",
    "reboot-recovery",
    "nginx-multi-map",
}


def _passing_report(mode="release-amd64", names=None):
    names = names if names is not None else lab.release_scenarios()
    return {
        "schema": 2,
        "mode": mode,
        "results": [
            {"name": name, "status": "passed", "seconds": 0.1} for name in names
        ],
    }


def report_without(scenario):
    return _passing_report(
        names=[name for name in lab.release_scenarios() if name != scenario]
    )


class ReleaseMatrixTests(unittest.TestCase):
    def test_release_matrix_contains_required_lifecycle_and_protocol_cases(self):
        names = set(lab.release_scenarios())
        self.assertLessEqual(REQUIRED_RELEASE_SCENARIOS, names)
        self.assertLessEqual(
            {
                "install-full-xui",
                "coexist-existing-xui",
                "crash-every-phase",
                "uninstall-foreign-identity",
            },
            names,
        )

    def test_missing_scenario_result_fails_report_even_when_guest_exits_zero(self):
        report = report_without("crash-every-phase")
        self.assertEqual(lab.validate_report(report).exit_code, 1)
        self.assertEqual(
            lab.validate_report(report).missing, ("crash-every-phase",)
        )

    def test_complete_passing_report_validates(self):
        verdict = lab.validate_report(_passing_report())
        self.assertEqual(verdict.exit_code, 0)
        self.assertTrue(verdict.ok)

    def test_failed_scenario_fails_the_report(self):
        report = _passing_report()
        report["results"][3]["status"] = "failed"
        verdict = lab.validate_report(report)
        self.assertEqual(verdict.exit_code, 1)
        self.assertTrue(verdict.failed)

    def test_filtered_run_is_only_valid_against_what_it_declared(self):
        report = _passing_report(names=["audit", "plan"])
        report["filtered_scenarios"] = ["audit", "plan"]
        self.assertEqual(lab.validate_report(report).exit_code, 0)
        # A filtered report never stands in for the full release matrix.
        self.assertEqual(
            lab.validate_report(report, required=lab.release_scenarios()).exit_code,
            1,
        )

    def test_release_modes_are_selectable_and_architecture_scoped(self):
        self.assertIn("release-amd64", lab.SCENARIOS)
        self.assertIn("release-arm64", lab.SCENARIOS)
        self.assertEqual(lab.mode_architecture("release-arm64"), "arm64")
        self.assertEqual(lab.mode_architecture("smoke"), "amd64")

    def test_finalize_marks_a_missing_release_result_failed(self):
        results = lab.finalize_results("release-amd64", [], 0, 1.0)
        statuses = {item["name"]: item["status"] for item in results}
        self.assertEqual(set(statuses), set(lab.release_scenarios()))
        self.assertTrue(all(status == "failed" for status in statuses.values()))


class ReleaseArtifactTests(unittest.TestCase):
    def test_release_archive_must_match_the_named_checksum(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "release.tar.gz"
            archive.write_bytes(b"release-bytes\n")
            digest = lab.sha256(archive)
            self.assertEqual(lab.verify_release_archive(archive, digest), digest)
            with self.assertRaises(ValueError):
                lab.verify_release_archive(archive, "0" * 64)
            with self.assertRaises(ValueError):
                lab.verify_release_archive(archive, "not-a-digest")

    def test_release_run_requires_an_archive_and_checksum(self):
        with self.assertRaises(ValueError):
            lab.run_scenarios("release-amd64", Path("/tmp/unused-lab-output"))

    def test_unknown_scenario_filter_is_refused(self):
        with self.assertRaises(ValueError):
            lab.guest_remote("release-amd64", "a" * 64, ("rm -rf /",))


class ImageMetadataTests(unittest.TestCase):
    def test_each_architecture_declares_a_machine_and_binary(self):
        image = lab.metadata("amd64")
        self.assertEqual(image["architecture"], "amd64")
        self.assertEqual(len(image["sha256"]), 64)
        self.assertTrue(image["qemu_binary"].startswith("qemu-system-"))
        self.assertTrue(image["machine"])
        self.assertTrue(image["minimum_qemu"])

    def test_every_shipped_architecture_is_pinned(self):
        document = json.loads((MODULE.parent / "image.json").read_text())
        for architecture in document["images"]:
            image = lab.metadata(architecture)
            self.assertRegex(image["sha256"], r"^[0-9a-f]{64}$")

    def test_an_unpinned_image_fails_closed(self):
        """The controller refuses an image without a recorded digest rather
        than trusting whatever the download returns."""
        document = json.loads((MODULE.parent / "image.json").read_text())
        document["images"]["arm64"]["sha256"] = None
        path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "image.json"
        path.write_text(json.dumps(document))
        with mock.patch.object(lab, "HERE", path.parent):
            with self.assertRaises(ValueError) as caught:
                lab.metadata("arm64")
        self.assertIn("not pinned", str(caught.exception))

    def test_qemu_command_follows_the_declared_architecture(self):
        command = lab.qemu_command(
            Path("disk"), Path("seed"), Path("key"), 2222,
            Path("pid"), Path("serial"), "release-amd64",
        )
        self.assertEqual(command[0], "qemu-system-x86_64")
        self.assertIn("q35", command)


class ReleaseFixtureTests(unittest.TestCase):
    def test_guest_runner_declares_every_release_scenario(self):
        runner = (MODULE.parent / "guest-runner.sh").read_text()
        for name in lab.release_scenarios():
            if name == "environment-preflight":
                continue
            self.assertIn(f"case_run {name} ", runner, name)

    def test_client_compose_pins_every_protocol_probe(self):
        compose = (
            Path(__file__).parent / "clients" / "compose.yaml"
        ).read_text()
        for service in (
            "telemt:",
            "naive:",
            "mieru:",
            "vless-tcp:",
            "vless-xhttp:",
            "hysteria2:",
            "https-cover:",
        ):
            self.assertIn(service, compose)
        self.assertIn("read_only: true", compose)
        self.assertIn("cap_drop: [ALL]", compose)
        self.assertNotIn("privileged", compose)

    def test_foreign_three_xui_fixture_is_never_installer_owned(self):
        fixture = (
            Path(__file__).parent / "fixtures" / "three-xui-existing.sh"
        ).read_text()
        self.assertIn("/usr/local/x-ui", fixture)
        self.assertIn("/etc/x-ui/x-ui.db", fixture)
        self.assertIn("FOREIGN-PRIVATE-KEY-NEVER-READ", fixture)

    def test_multi_map_fixture_adds_a_second_candidate_map_and_listener(self):
        """It is added beside the shared 443 router, so it must not reuse 443."""
        fixture = (
            Path(__file__).parent / "fixtures" / "nginx-multi-map.conf"
        ).read_text()
        self.assertEqual(fixture.count("map $ssl_preread_server_name"), 1)
        self.assertIn("$legacy_backend", fixture)
        self.assertIn("listen 8443;", fixture)
        self.assertNotIn("listen 443;", fixture)

if __name__ == "__main__":
    unittest.main()


class GuestRunnerPreflightScripts(unittest.TestCase):
    """Each preflight runs in a fresh shell built from `declare -f`.

    A helper the listed functions call but the list omits is not a syntax
    error: the subshell only fails at run time with "command not found",
    which is how the release lab broke without any local check noticing.
    """

    RUNNER = MODULE.parent / "guest-runner.sh"

    def setUp(self):
        self.text = self.RUNNER.read_text()
        self.defined = set(
            re.findall(r"^([a-z_][a-z0-9_]*)\(\) \{", self.text, re.MULTILINE)
        )
        self.assertIn("host_ip", self.defined)

    def _body(self, name: str) -> str:
        start = self.text.index(f"\n{name}() {{")
        end = self.text.index("\n}\n", start)
        return self.text[start:end]

    def test_every_composed_script_carries_the_helpers_it_calls(self):
        lists = re.findall(r"declare -f ([a-z_0-9 ]+)\)", self.text)
        self.assertGreaterEqual(len(lists), 4)
        for group in lists:
            declared = set(group.split())
            missing = {}
            for name in declared:
                body = self._body(name)
                for candidate in self.defined:
                    if candidate in declared:
                        continue
                    if re.search(rf"(^|[^\w-]){re.escape(candidate)}(\s|$|\))", body, re.M):
                        missing.setdefault(candidate, []).append(name)
            self.assertEqual(missing, {}, f"declare -f {group}")


class Aarch64Firmware(unittest.TestCase):
    """`qemu-system-aarch64 -machine virt` has no built-in firmware.

    Without one the guest boots to nothing, and the only symptom is an SSH
    readiness timeout that names neither the cause nor the missing package.
    """

    def test_arm64_declares_firmware_and_amd64_does_not(self):
        document = json.loads((MODULE.parent / "image.json").read_text())
        self.assertIsNone(document["images"]["amd64"]["firmware"])
        arm64 = document["images"]["arm64"]
        self.assertTrue(arm64["firmware"].startswith("/"))
        self.assertTrue(arm64["firmware_package"])

    def test_a_missing_firmware_fails_closed_and_names_the_package(self):
        with self.assertRaises(ValueError) as caught:
            lab.qemu_command(
                Path("disk"), Path("seed"), Path("key"), 2222,
                Path("pid"), Path("serial"), "release-arm64",
            )
        message = str(caught.exception)
        self.assertIn("qemu-efi-aarch64", message)
        self.assertIn("UEFI firmware", message)

    def test_the_release_workflow_installs_that_package(self):
        workflow = (MODULE.parents[2] / ".github/workflows/release.yml").read_text()
        document = json.loads((MODULE.parent / "image.json").read_text())
        self.assertIn(document["images"]["arm64"]["firmware_package"], workflow)

    def test_firmware_precedes_the_machine_it_boots(self):
        document = json.loads((MODULE.parent / "image.json").read_text())
        firmware = Path(self.enterContext(tempfile.TemporaryDirectory())) / "efi.fd"
        firmware.write_bytes(b"firmware")
        document["images"]["arm64"]["firmware"] = str(firmware)
        path = firmware.parent / "image.json"
        path.write_text(json.dumps(document))
        with mock.patch.object(lab, "HERE", path.parent):
            command = lab.qemu_command(
                Path("disk"), Path("seed"), Path("key"), 2222,
                Path("pid"), Path("serial"), "release-arm64",
            )
        self.assertEqual(command[0], "qemu-system-aarch64")
        self.assertIn("-bios", command)
        self.assertEqual(command[command.index("-bios") + 1], str(firmware))
        self.assertLess(command.index("-bios"), command.index("-machine"))


class ReleaseRootLayout(unittest.TestCase):
    """The archive carries a prefix; the tree the installer runs from is inside
    it. Getting this wrong killed the preflight through `set -e` with no
    message at all."""

    RUNNER = MODULE.parent / "guest-runner.sh"

    def test_release_root_accounts_for_the_archive_prefix(self):
        text = self.RUNNER.read_text()
        build = (MODULE.parents[2] / "release" / "build.py").read_text()
        prefix = re.search(r'ARCHIVE_PREFIX = "([^"]+)"', build).group(1)
        root = re.search(r"^RELEASE_ROOT=(\S+)$", text, re.MULTILINE).group(1)
        self.assertEqual(root, f"$RELEASE_STAGE/{prefix}")
        self.assertIn('tar -xf "$RELEASE" -C "$RELEASE_STAGE"', text)

    def test_every_preflight_names_the_command_that_failed(self):
        text = self.RUNNER.read_text()
        composed = text.count('if bash -Eeuo pipefail -c "$script"')
        self.assertGreaterEqual(composed, 4)
        self.assertEqual(text.count("PREFLIGHT FAILED"), composed)

    def test_every_composed_script_declares_the_variables_it_reads(self):
        text = self.RUNNER.read_text()
        defined = set(re.findall(r"^([a-z_][a-z0-9_]*)\(\) \{", text, re.MULTILINE))
        globals_ = set(re.findall(r"^([A-Z][A-Z0-9_]*)=", text, re.MULTILINE))
        for match in re.finditer(
            r"declare -p ([A-Z0-9_ ]+)\); \$\(declare -f ([a-z_0-9 ]+)\)", text
        ):
            declared_vars = set(match.group(1).split())
            functions = match.group(2).split()
            for name in functions:
                start = text.index(f"\n{name}() {{")
                body = text[start:text.index("\n}\n", start)]
                used = {
                    variable
                    for variable in re.findall(r"\$\{?([A-Z][A-Z0-9_]*)\b", body)
                    if variable in globals_
                }
                missing = used - declared_vars
                self.assertEqual(
                    missing, set(), f"{name} needs {sorted(missing)}"
                )
            self.assertTrue(set(functions) <= defined)


class ReleaseConfigMatchesItsFixture(unittest.TestCase):
    """The release fixture builds a shared-443 stream router and a foreign
    3x-ui. `fresh` is refused against an active router, and `managed-new`
    requires `fresh`, so that pair could never plan on this host."""

    RUNNER = MODULE.parent / "guest-runner.sh"

    def _config(self, function: str) -> str:
        text = self.RUNNER.read_text()
        start = text.index(f"\n{function}() {{")
        body = text[start:text.index("\n}\n", start)]
        return body[body.index('cat > "$CONFIG" <<TOML'):body.index("\nTOML")]

    def test_the_release_lab_describes_a_coexisting_host(self):
        config = self._config("release_setup")
        self.assertIn('host_mode = "coexist"', config)
        self.assertNotIn('mode = "managed-new"', config)

    def test_the_fixture_really_installs_a_stream_router(self):
        text = self.RUNNER.read_text()
        start = text.index("\nsetup_full_host() {")
        # Stop at the next top-level function: a heredoc in the body contains
        # closing braces of its own.
        following = re.search(r"\n[a-z_][a-z0-9_]*\(\) \{", text[start + 1:])
        body = text[start:start + 1 + following.start()]
        self.assertIn("ssl_preread", body)
        self.assertIn('cat > "$ROUTE"', body)


class LabConfigurationsAreValid(unittest.TestCase):
    """Each lab writes an installer configuration inline. Loading it through the
    real loader and adapter selection catches an unknown key or an impossible
    mode here, instead of thirty minutes into a QEMU run."""

    RUNNER = MODULE.parent / "guest-runner.sh"

    def _toml(self, function: str) -> str:
        text = self.RUNNER.read_text()
        start = text.index(f"\n{function}() {{")
        body = text[start:]
        opening = body.index('cat > "$CONFIG" <<TOML') + len('cat > "$CONFIG" <<TOML')
        return (
            body[opening:body.index("\nTOML")]
            .replace('"$PANEL"', '"panel.lab.test"')
            .replace('"$PROXY"', '"proxy.lab.test"')
        )

    def test_every_lab_configuration_loads_and_selects_adapters(self):
        sys.path.insert(0, str(MODULE.parents[2]))
        from installer.config import load_config
        from installer.planner import adapters_for

        for function in ("release_setup", "container_write_configs"):
            with self.subTest(function):
                directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
                path = directory / "install.toml"
                path.write_text(self._toml(function))
                config = load_config(path)
                adapters = adapters_for(config)
                self.assertTrue(adapters)
