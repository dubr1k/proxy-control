from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_the_guest_command_runs_the_source_runner_with_separate_release(self):
        command = lab.guest_command(
            "/opt/acceptance/proxy-control",
            "a" * 64,
            ("audit",),
        )
        self.assertEqual(command[:3], ("docker", "exec", lab.CONTAINER))
        script = command[-1]
        self.assertIn(
            "/tmp/mtproxy-source/scripts/lab/guest-runner.sh container",
            script,
        )
        self.assertIn("LAB_RELEASE_ROOT=/opt/acceptance/proxy-control", script)
        self.assertNotIn("/opt/acceptance/proxy-control/scripts/lab", script)

    def test_copy_inputs_stages_current_tracked_harness_separately(self):
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary) / "source"
            tree.mkdir()
            subprocess.run(["git", "init", "-q", str(tree)], check=True)
            included = (
                "scripts/lab/guest-runner.sh", "scripts/dev/helper.sh",
                "tests/lab/fixtures/topology.conf", "panel/src/main.rs",
                "tests/fixtures/host-golden/secrets/synthetic-token",
            )
            excluded = (
                "secrets/token", ".env.local", "graphify-out/graph.json",
                ".lab-state/key", ".venv/cache", "panel/target/output",
                "tests/__pycache__/cache.pyc", ".superpowers/private",
                ".pi/config", ".agents/private", ".codex/private", "AGENTS.md", "CLAUDE.md",
            )
            for name in (*included, *excluded):
                path = tree / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("indexed bytes")
            subprocess.run(["git", "-C", str(tree), "add", "."], check=True)
            runner = tree / included[0]
            runner.write_text("current working-tree runner")
            (tree / "untracked-private").write_text("not source")
            staging = Path(temporary) / "output"
            staging.mkdir()
            release = Path(temporary) / "release.tar.gz"
            with tarfile.open(release, "w:gz") as package:
                package.add(tree / "panel/src/main.rs", arcname="proxy-control/install.sh")
            original = release.read_bytes()
            with mock.patch.object(lab, "REPO", tree), mock.patch.object(lab, "run") as run:
                root = lab.copy_inputs(release, "a" * 64, staging)
            self.assertEqual(root, "/tmp/proxy-control-release/proxy-control")
            with tarfile.open(staging / "source.tar.gz") as package:
                self.assertEqual(set(package.getnames()), set(included))
                self.assertEqual(package.extractfile(included[0]).read(),
                                 b"current working-tree runner")
            commands = [call.args[0] for call in run.call_args_list]
            self.assertIn(("docker", "cp", str(staging / "source.tar.gz"),
                           f"{lab.CONTAINER}:/tmp/mtproxy-source.tar.gz"), commands)
            extraction = commands[-1][-1]
            self.assertIn("tar -xzf /tmp/mtproxy-source.tar.gz -C /tmp/mtproxy-source", extraction)
            self.assertIn("tar -xzf /tmp/proxy-control-release.tar.gz -C /tmp/proxy-control-release", extraction)
            self.assertEqual(release.read_bytes(), original)

    def test_source_archive_refuses_symlinks_to_private_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary) / "source"
            tree.mkdir()
            subprocess.run(["git", "init", "-q", str(tree)], check=True)
            tracked = tree / "runner.sh"
            tracked.write_text("tracked source")
            subprocess.run(["git", "-C", str(tree), "add", "."], check=True)
            private = Path(temporary) / "private"
            private.write_text("private bytes")
            tracked.unlink()
            tracked.symlink_to(private)
            with mock.patch.object(lab, "REPO", tree):
                with self.assertRaisesRegex(lab.DockerLabError, "unsafe source path"):
                    lab.source_archive(Path(temporary) / "source.tar.gz")

    def test_guest_runner_roots_do_not_depend_on_mode(self):
        runner = MODULE.with_name("guest-runner.sh")
        for mode in ("container", "host", "smoke", "full", "release-amd64"):
            for override in ("", "/tmp/explicit-release/proxy-control"):
                with self.subTest(mode=mode, override=override):
                    result = subprocess.run(
                        ["bash", "-c", 'source "$1" "$2" digest; printf "%s\\n" "$ROOT" "$RELEASE_ROOT"',
                         "test", str(runner), mode],
                        env={**os.environ, "GUEST_RUNNER_LIB_ONLY": "1", "LAB_RELEASE_ROOT": override},
                        check=True, capture_output=True, text=True,
                    )
                    self.assertEqual(result.stdout.splitlines(), [
                        str(MODULE.parents[2].resolve()),
                        override or "/tmp/proxy-control-release/proxy-control",
                    ])

    def test_release_integrity_allows_git_in_harness_but_not_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = root / "harness"
            runner = harness / "scripts/lab/guest-runner.sh"
            runner.parent.mkdir(parents=True)
            runner.write_text(MODULE.with_name("guest-runner.sh").read_text())
            (harness / ".git").mkdir()
            payload = root / "payload"
            (payload / "installer/bin/linux-amd64").mkdir(parents=True)
            binary = payload / "installer/bin/linux-amd64/proxy-control-installer"
            binary.write_text("synthetic binary")
            binary.chmod(0o755)
            (payload / "install.sh").touch()
            (payload / "release").mkdir()
            (payload / "release/release.json").write_text(json.dumps(
                {"tag": "test", "commit": "test", "manifest_sha256": "a" * 64}
            ))
            archive = root / "release.tar.gz"
            archive.write_bytes(b"synthetic release")
            digest = root / "release.sha256"
            digest.write_text(lab.qemu_lab.sha256(archive))
            for function in ("container_artifact_integrity", "release_artifact_integrity"):
                for metadata in (False, True):
                    if metadata:
                        (payload / ".git").mkdir()
                    result = subprocess.run(
                        ["bash", "-c", 'source "$1" container digest; RELEASE=$2; RELEASE_SHA=$3; "$4"',
                         "test", str(runner), str(archive), str(digest), function],
                        env={**os.environ, "GUEST_RUNNER_LIB_ONLY": "1", "LAB_RELEASE_ROOT": str(payload)},
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode == 0, not metadata, result.stderr)
                    if metadata:
                        (payload / ".git").rmdir()

    def test_remote_host_gate_uses_source_runner_and_explicit_release(self):
        gate = MODULE.parents[1] / "dev/remote-gate.sh"
        host = gate.read_text().split("  lab-host)\n", 1)[1].split("  fleet)", 1)[0]
        launch = next(line for line in host.splitlines() if "setsid nohup" in line)
        self.assertIn("LAB_RELEASE_ROOT=/tmp/proxy-control-release/proxy-control", launch)
        self.assertIn("bash scripts/lab/guest-runner.sh host", launch)
        self.assertNotIn("/proxy-control/scripts/lab/guest-runner.sh", launch)

    def test_the_release_archive_and_checksum_are_both_required(self):
        with self.assertRaises(SystemExit):
            lab.main(["--release-archive", "x"])


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
