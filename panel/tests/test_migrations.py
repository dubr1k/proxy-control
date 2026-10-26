"""Migration concurrency across independent invocations of the actual panel CLI."""
import json
import sqlite3
import subprocess

from panel.tests.harness.server import RUST_BIN


def test_two_processes_initialising_concurrently_are_safe(tmp_path):
    database = tmp_path / "concurrent.db"
    argv = [RUST_BIN, "cli", "--database", str(database), "db-migrate"]
    children = [subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
    try:
        applied = []
        for child in children:
            out, err = child.communicate(timeout=30)
            assert child.returncode == 0, err
            applied.append(json.loads(out)["applied"])
        assert sum(bool(versions) for versions in applied) == 1
        with sqlite3.connect(database) as db:
            versions = [row[0] for row in db.execute("SELECT version FROM schema_migrations ORDER BY version")]
            assert sorted(version for run in applied for version in run) == versions
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait()
