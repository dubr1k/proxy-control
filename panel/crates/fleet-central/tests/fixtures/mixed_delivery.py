"""Python 3.3 ↔ native Rust candidate Fleet v2 interoperability over actual HTTPS.

Run only on ams-test, from the repository root, with PANEL_RUST_BIN pointing to
its test-hooks build and PYTHONPATH=.; requires an external, unmodified v3.3.0
source export and its isolated venv (install that export's panel/requirements.txt).

    python panel/crates/fleet-central/tests/fixtures/mixed_delivery.py \
        --legacy-source /root/dev/remove-runtime-python-reference-v3.3.0

Source identity is checked against cc9a227 before any process starts. The parent
imports only the native external harness; the legacy application runs in a child
with only the verified source as PYTHONPATH and its own interpreter/dependencies.
The native implementation and its reported version are reported separately: the
candidate may still carry 3.3.0 until the final release-version cutover.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

import httpx

from panel.tests.harness.server import PanelServer, start_panel
from native_tls_delivery import delivery

HERE = Path(__file__).resolve().parent
LEGACY_COMMIT = "cc9a2272573bbc25d104f3a49c086a607f132816"


def verify_source(source: Path):
    manifest = json.loads((HERE / "legacy-v3.3-source.json").read_text())
    if manifest["commit"] != LEGACY_COMMIT or manifest["version"] != "3.3.0":
        raise ValueError("unexpected legacy provenance manifest")
    if (source / "VERSION").read_text().strip() != "3.3.0":
        raise ValueError("--legacy-source must be the v3.3.0 export")
    for relative, expected in manifest["git_blobs"].items():
        content = (source / relative).read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        if actual != expected:
            raise ValueError(f"legacy source differs from {LEGACY_COMMIT}: {relative}")
    return manifest


class LegacyPanel(PanelServer):
    source: Path
    python: Path

    def _start_rust(self, node_routes):
        if node_routes:
            raise ValueError("mixed fixture routes nodes through real TLS, not hostname remapping")
        self.socket = os.path.join(self.managers.directory, "panel.sock")
        self.env = {**self._rust_env({}), "PYTHONPATH": str(self.source), "PYTHONNOUSERSITE": "1",
                    "PANEL_VNEXT_WRITER": "domain"}
        self.log_path = self.workdir / f"{self.name}-python-3.3.log"
        with self.log_path.open("ab") as output:
            self.process = subprocess.Popen(
                [str(self.python), str(HERE / "legacy_panel_process.py"),
                 "--source", str(self.source), "--socket", self.socket],
                cwd=self.source, env=self.env, stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        with self._sync_http() as http:
            while True:
                if self.process.poll() is not None:
                    self.close()
                    raise RuntimeError(f"legacy panel exited: {self._log_tail()}")
                try:
                    if http.get("/healthz").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() > deadline:
                    self.close()
                    raise RuntimeError(f"legacy panel did not become healthy: {self._log_tail()}")
                time.sleep(0.05)
        self.client = self.http("testserver")

    def cli(self, *argv, stdin=""):
        done = subprocess.run(
            [str(self.python), "-m", "panel.cli", "--database", str(self.db_path), *argv],
            cwd=self.source, env=self.env, input=stdin, capture_output=True, text=True, timeout=60)
        return done.returncode, done.stdout, done.stderr


def start_legacy(workdir, *, name, hosts=("testserver",), **settings):
    memories = {kind: settings.pop(kind, None)
                for kind in ("telemt", "naive", "mieru", "amneziawg", "trusttunnel", "router", "versions")}
    return LegacyPanel(workdir, name=name, hosts=tuple(hosts), db_name=f"{name}.sqlite3",
                       key_name=f"{name}-key", memories=memories, settings=settings,
                       node_routes=None, keyring=True)


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-source", type=Path, required=True)
    parser.add_argument("--legacy-python", type=Path,
                        help="isolated legacy interpreter; defaults to SOURCE/.venv/bin/python")
    args = parser.parse_args()
    source = args.legacy_source.resolve()
    manifest = verify_source(source)
    python = args.legacy_python.absolute() if args.legacy_python else source / ".venv/bin/python"
    if not python.is_file():
        parser.error("create the isolated legacy venv and install its panel/requirements.txt first")
    if not os.environ.get("PANEL_RUST_BIN"):
        parser.error("PANEL_RUST_BIN must identify the native test-hooks build")
    LegacyPanel.source, LegacyPanel.python = source, python
    print(json.dumps({"legacy_source_commit": manifest["commit"],
                      "verified_source_blobs": len(manifest["git_blobs"])}), flush=True)
    with tempfile.TemporaryDirectory(prefix="fleet-real-mixed-") as temporary:
        root = Path(temporary)
        await delivery(root / "native-central", central_factory=start_panel, node_factory=start_legacy,
                       central_impl="rust", node_impl="python-3.3")
        await delivery(root / "legacy-central", central_factory=start_legacy, node_factory=start_panel,
                       central_impl="python-3.3", node_impl="rust")


if __name__ == "__main__":
    asyncio.run(main())
