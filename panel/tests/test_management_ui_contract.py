"""Static contract of the versions screen (v0.11): the upstream check bar, the source label
on every candidate, the upstream risk note, the Xray-router card and the Caddy build state."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parent.parent / "static"
JS = (STATIC / "js/management.js").read_text()





















NODE = shutil.which("node")


def _run_common(script: str):
    tmp = Path(tempfile.mkdtemp())
    (tmp / "common.mjs").write_text((STATIC / "js/common.js").read_text())
    (tmp / "run.mjs").write_text('import * as c from "./common.mjs";\n' + script)
    done = subprocess.run([NODE, str(tmp / "run.mjs")], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_installed_version_and_ordering_behave():
    digest = "7c843f370ec5"
    out = _run_common(f"""
const available = [{{ version: "3.5.14", image: "ghcr.io/x/telemt@sha256:{digest}aa" }}, {{ version: "3.5.9" }}];
console.log(JSON.stringify({{
  hit: c.installedVersion("sha256:{digest}", available).label,
  miss: c.installedVersion("sha256:{'0' * 12}", available).label,
  plain: c.installedVersion("3.38.1", available).label,
  a: c.versionIsNewer("3.5.14", "3.5.9"), b: c.versionIsNewer("3.5.9", "3.5.14"),
  c: c.versionIsNewer("3.1.20260828", "3.1.20260814"), d: c.versionIsNewer("3.1.20260814", "3.1.20260828"),
  v: c.versionIsNewer("v3.38.1", "3.38.0"), v2: c.versionIsNewer("v3.38.1", "3.38.1"),
  pre: c.versionIsNewer("26.10.17-beta", "26.10.17"), rel: c.versionIsNewer("26.10.17", "26.10.17-beta"),
}}));""")
    assert out["hit"] == "3.5.14" and out["miss"] == f"сборка sha256:{'0' * 12}" and out["plain"] == "3.38.1"
    assert out["a"] is True and out["b"] is False and out["c"] is True and out["d"] is False
    assert out["v"] is True and out["v2"] is False
    assert out["pre"] is False and out["rel"] is True


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_the_update_request_carries_the_raw_current_not_the_label():
    out = _run_common("""
console.log(JSON.stringify([c.updateRequestBody("3.5.14", "sha256:7c843f370ec5"), c.updateRequestBody("1.0", "не определена")]));""")
    assert out[0] == {"version": "3.5.14", "expected_current": "sha256:7c843f370ec5"}
    assert out[1]["expected_current"] is None
    # the button keeps the raw value, the label is for display only, and the POST uses the helper
    assert 'data-current="${esc(raw)}" data-current-label="${esc(current)}"' in JS
    assert "JSON.stringify(updateRequestBody(version, raw))" in JS
