from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

MODULE = Path(__file__).parents[2] / "scripts" / "lab" / "docker_lab.py"
spec = importlib.util.spec_from_file_location("docker_lab", MODULE)
assert spec is not None and spec.loader is not None
lab = importlib.util.module_from_spec(spec)
sys.modules["docker_lab"] = lab
spec.loader.exec_module(lab)


class ContainerScenarioTests(unittest.TestCase):
    def test_container_matrix_is_a_declared_subset_of_the_release_matrix(self):
        release = set(lab.qemu_lab.release_scenarios())
        container = set(lab.CONTAINER_SCENARIOS)
        self.assertTrue(container)
        self.assertLessEqual(container, release)

    def test_container_matrix_excludes_what_a_container_cannot_prove(self):
        """Nested Docker and public network scenarios are never claimed."""
        container = set(lab.CONTAINER_SCENARIOS)
        for name in (
            "install-full-xui",
            "telemt-official-client",
            "naive-official-client",
            "mieru-official-client",
            "vless-tcp-client",
            "vless-xhttp-client",
            "hysteria2-client",
            "docker-build",
            "crash-every-phase",
            "reboot-recovery",
            "uninstall",
        ):
            self.assertNotIn(name, container, name)

    def test_a_container_report_never_stands_in_for_a_full_release_report(self):
        report = {
            "mode": lab.MODE,
            "filtered_scenarios": list(lab.CONTAINER_SCENARIOS),
            "results": [
                {"name": name, "status": "passed"}
                for name in lab.CONTAINER_SCENARIOS
            ],
        }
        self.assertEqual(lab.qemu_lab.validate_report(report).exit_code, 0)
        verdict = lab.qemu_lab.validate_report(
            report,
            required=lab.qemu_lab.release_scenarios(),
        )
        self.assertEqual(verdict.exit_code, 1)
        self.assertIn("install-full-xui", verdict.missing)

    def test_a_missing_container_result_fails_the_report(self):
        report = {
            "mode": lab.MODE,
            "filtered_scenarios": list(lab.CONTAINER_SCENARIOS),
            "results": [
                {"name": name, "status": "passed"}
                for name in lab.CONTAINER_SCENARIOS
                if name != "secrets-scan"
            ],
        }
        self.assertEqual(lab.qemu_lab.validate_report(report).exit_code, 1)


class ContainerInputTests(unittest.TestCase):
    def test_an_unknown_scenario_filter_is_refused(self):
        with self.assertRaises(lab.DockerLabError):
            lab.guest_command("/opt/acceptance/proxy-control", "a" * 64, ("rm -rf /",))

    def test_the_guest_command_runs_the_runner_from_the_release(self):
        command = lab.guest_command(
            "/opt/acceptance/proxy-control",
            "a" * 64,
            ("audit",),
        )
        self.assertEqual(command[:3], ("docker", "exec", lab.CONTAINER))
        script = command[-1]
        self.assertIn(
            "/opt/acceptance/proxy-control/scripts/lab/guest-runner.sh container",
            script,
        )
        self.assertNotIn("/tmp/mtproxy-source", script)

    def test_the_release_archive_and_checksum_are_both_required(self):
        with self.assertRaises(SystemExit):
            lab.main(["--release-archive", "x"])


class ContainerImageTests(unittest.TestCase):
    def test_the_acceptance_image_pins_its_base_by_digest_and_runs_systemd(self):
        dockerfile = (MODULE.parent / "Dockerfile.acceptance").read_text()
        base = next(
            line for line in dockerfile.splitlines() if line.startswith("FROM ")
        )
        self.assertIn("@sha256:", base)
        self.assertEqual(len(base.split("@sha256:")[1].strip()), 64)
        self.assertIn('CMD ["/sbin/init"]', dockerfile)
        for package in ("nginx-full", "libnginx-mod-stream", "dnsmasq", "dnsutils"):
            self.assertIn(package, dockerfile)
        # Nothing from the developer's machine is baked in.
        self.assertNotIn("COPY", dockerfile)
        self.assertNotIn("ADD", dockerfile)

    def test_the_runner_declares_every_container_scenario(self):
        runner = (MODULE.parent / "guest-runner.sh").read_text()
        for name in lab.CONTAINER_SCENARIOS:
            if name == "environment-preflight":
                continue
            self.assertIn(f"case_run {name} ", runner, name)


class RecordedRunTests(unittest.TestCase):
    """The report this lab writes is the record a reviewer reads."""

    def test_report_shape_is_the_shared_schema(self):
        results = [
            {"name": name, "status": "passed", "seconds": 0.1}
            for name in lab.CONTAINER_SCENARIOS
        ]
        document = json.loads(
            json.dumps(
                {
                    "schema": 2,
                    "mode": lab.MODE,
                    "architecture": "arm64",
                    "filtered_scenarios": list(lab.CONTAINER_SCENARIOS),
                    "results": results,
                }
            )
        )
        self.assertEqual(document["schema"], 2)
        self.assertEqual(lab.qemu_lab.validate_report(document).exit_code, 0)
        xml = lab.qemu_lab.junit_xml(results)
        self.assertIn('failures="0"', xml)

    def test_docker_is_the_only_external_dependency(self):
        source = MODULE.read_text()
        self.assertIn('shutil.which("docker")', source)
        for command in ("qemu-system", "cloud-localds", "ssh "):
            self.assertNotIn(command, source)


@unittest.skipUnless(
    subprocess.run(
        ("docker", "version"), capture_output=True, check=False
    ).returncode
    == 0,
    "docker is unavailable",
)
class DockerAvailableTests(unittest.TestCase):
    def test_the_acceptance_image_builds(self):
        self.assertTrue(lab.build_image().startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
