"""Executable host helpers: idempotence, symlink-safe adaptation, and kernel permissions."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DeployCliTests(unittest.TestCase):
    def test_mieru_mss_clamp_is_idempotent_reversible_and_service_managed(self):
        helper = ROOT / "scripts/mieru-mss-clamp.sh"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state = root / "installed"
            log = root / "calls.jsonl"
            fake = root / "iptables"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "args = sys.argv[1:]\n"
                "state = Path(os.environ['IPTABLES_STATE'])\n"
                "with Path(os.environ['IPTABLES_LOG']).open('a') as out:\n"
                "    out.write(json.dumps(args) + '\\n')\n"
                "operation = next(value for value in ('-C', '-I', '-D') if value in args)\n"
                "if operation == '-C':\n"
                "    raise SystemExit(0 if state.exists() else 1)\n"
                "if operation == '-I':\n"
                "    state.write_text('installed')\n"
                "elif operation == '-D':\n"
                "    state.unlink()\n"
            )
            fake.chmod(0o755)
            env = {
                **os.environ,
                "IPTABLES": str(fake),
                "IPTABLES_STATE": str(state),
                "IPTABLES_LOG": str(log),
            }
            for action in ("apply", "apply", "remove", "remove"):
                result = subprocess.run(
                    [helper, action, "46001", "1100"],
                    env=env,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            inserts = [call for call in calls if "-I" in call]
            deletes = [call for call in calls if "-D" in call]
            self.assertEqual(len(inserts), 1)
            self.assertEqual(len(deletes), 1)
            self.assertIn("--dport", inserts[0])
            self.assertIn("46001", inserts[0])
            self.assertIn("--set-mss", inserts[0])
            self.assertIn("1100", inserts[0])
            self.assertIn("proxy-control-mieru-mss-clamp", inserts[0])
            invalid = subprocess.run(
                [helper, "apply", "0", "1100"],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(invalid.returncode, 0)

    def test_caddy_naive_adapter_rewrites_only_private_https_listeners(self):
        helper = ROOT / "scripts/caddy-naive-adapt"
        self.assertTrue(os.access(helper, os.X_OK))
        jq = shutil.which("jq")
        self.assertIsNotNone(jq, "jq is required by caddy-naive-adapt")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.Caddyfile"
            source.write_text(":443 {}\n")
            runtime = root / "run"
            runtime.mkdir()
            victim = root / "must-not-change"
            victim.write_text("protected\n")
            (runtime / "config.json").symlink_to(victim)
            fake_caddy = root / "caddy"
            adapted = {
                "apps": {
                    "http": {
                        "servers": {
                            "naive": {
                                "listen": [
                                    ":443",
                                    "127.0.0.1:443",
                                    "0.0.0.0:443",
                                    "[::]:443",
                                    ":4443",
                                    "127.0.0.1:8443",
                                ]
                            },
                            "admin": {"listen": ["127.0.0.1:2019"]},
                        }
                    }
                },
                "unchanged": ":443",
            }
            fake_caddy.write_text(
                "#!/usr/bin/env python3\n"
                "import json\n"
                f"print({json.dumps(json.dumps(adapted))})\n"
            )
            fake_caddy.chmod(0o755)
            env = os.environ | {
                "NAIVE_CADDYFILE": str(source),
                "CADDY_NAIVE_RUNTIME_DIR": str(runtime),
                "CADDY_BIN": str(fake_caddy),
                "JQ_BIN": jq,
                "CADDY_NAIVE_OWNER": str(os.getuid()),
                "CADDY_NAIVE_GROUP": str(os.getgid()),
            }

            completed = subprocess.run(
                [str(helper)],
                text=True,
                capture_output=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual((runtime / "Caddyfile").read_text(), source.read_text())
            self.assertEqual(victim.read_text(), "protected\n")
            self.assertFalse((runtime / "config.json").is_symlink())
            config = json.loads((runtime / "config.json").read_text())
            self.assertEqual(
                config["apps"]["http"]["servers"]["naive"]["listen"],
                [
                    ":4443",
                    "127.0.0.1:4443",
                    "0.0.0.0:443",
                    "[::]:443",
                    ":4443",
                    "127.0.0.1:8443",
                ],
            )
            self.assertEqual(
                config["apps"]["http"]["servers"]["naive"]["automatic_https"],
                {"disable_redirects": True},
            )
            self.assertEqual(
                config["apps"]["http"]["servers"]["admin"]["listen"],
                ["127.0.0.1:2019"],
            )
            self.assertEqual(config["unchanged"], ":443")
            self.assertEqual((runtime / "Caddyfile").stat().st_mode & 0o777, 0o400)
            self.assertEqual((runtime / "config.json").stat().st_mode & 0o777, 0o400)
            for path in (runtime / "Caddyfile", runtime / "config.json"):
                self.assertEqual(path.stat().st_uid, os.getuid())
                self.assertEqual(path.stat().st_gid, os.getgid())

            config_before = (runtime / "config.json").read_bytes()
            fake_caddy.write_text("#!/bin/sh\nexit 1\n")
            failed = subprocess.run(
                [str(helper)],
                text=True,
                capture_output=True,
                env=env,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual((runtime / "config.json").read_bytes(), config_before)
            self.assertEqual(list(root.glob("run.config.json.*")), [])
            self.assertEqual(list(root.glob("run.Caddyfile.*")), [])

    def test_naive_log_permissions_allow_caddy_write_and_manager_read_only(self):
        """Catch shared UID/GID or writable-group regressions with real kernel checks."""
        with tempfile.TemporaryDirectory(dir="/tmp") as td:
            root = Path(td)
            root.chmod(0o755)
            log_dir = root / "naive-proxy"
            log_dir.mkdir(mode=0o750)
            os.chown(log_dir, 10003, 10004)
            access = log_dir / "access.json"
            access.write_text("record\n")
            os.chown(access, 10003, 10004)
            access.chmod(0o640)

            def attempt(uid, gid, groups, script):
                def demote():
                    os.setgroups(groups)
                    os.setgid(gid)
                    os.setuid(uid)
                return subprocess.run(
                    ["/usr/bin/python3", "-c", script, str(access)],
                    text=True,
                    capture_output=True,
                    preexec_fn=demote,
                )

            self.assertEqual(
                attempt(10003, 10003, [10004], "import pathlib,sys; pathlib.Path(sys.argv[1]).open('a').write('caddy\\n')").returncode,
                0,
            )
            manager_read = attempt(10002, 101, [10004], "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())")
            self.assertEqual(manager_read.returncode, 0, manager_read.stderr)
            manager_write = attempt(10002, 101, [10004], "import pathlib,sys; pathlib.Path(sys.argv[1]).open('a').write('manager\\n')")
            self.assertNotEqual(manager_write.returncode, 0)
