"""Versions-screen JavaScript fetched from the Rust panel and executed by Node."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

NODE = shutil.which("node")


def _run_common(source: str, script: str, tmp: Path):
    (tmp / "common.mjs").write_text(source)
    (tmp / "run.mjs").write_text('import * as c from "./common.mjs";\n' + script)
    assert NODE is not None
    done = subprocess.run([NODE, str(tmp / "run.mjs")], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


pytestmark = pytest.mark.anyio


async def test_installed_version_and_ordering_behave(server, tmp_path):
    source = (await server.client.get("/static/js/common.js")).text
    digest = "7c843f370ec5"
    out = _run_common(source, f"""
const available = [{{ version: "3.5.14", image: "ghcr.io/x/telemt@sha256:{digest}aa" }}, {{ version: "3.5.9" }}];
console.log(JSON.stringify({{
  hit: c.installedVersion("sha256:{digest}", available).label,
  miss: c.installedVersion("sha256:{'0' * 12}", available).label,
  plain: c.installedVersion("3.38.1", available).label,
  a: c.versionIsNewer("3.5.14", "3.5.9"), b: c.versionIsNewer("3.5.9", "3.5.14"),
  c: c.versionIsNewer("3.1.20260828", "3.1.20260814"), d: c.versionIsNewer("3.1.20260814", "3.1.20260828"),
  v: c.versionIsNewer("v3.38.1", "3.38.0"), v2: c.versionIsNewer("v3.38.1", "3.38.1"),
  pre: c.versionIsNewer("26.10.17-beta", "26.10.17"), rel: c.versionIsNewer("26.10.17", "26.10.17-beta"),
  rollbackOfferedAsUpdate: c.offeredVersions({{current:"3.5.14", available:[{{version:"3.5.9"}}]}}).hasNewer,
}}));""", tmp_path)
    assert out["hit"] == "3.5.14" and out["miss"] == f"сборка sha256:{'0' * 12}" and out["plain"] == "3.38.1"
    assert out["a"] is True and out["b"] is False and out["c"] is True and out["d"] is False
    assert out["v"] is True and out["v2"] is False
    assert out["pre"] is False and out["rel"] is True
    assert out["rollbackOfferedAsUpdate"] is False


async def test_the_update_request_carries_the_raw_current_not_the_label(server, tmp_path):
    source = (await server.client.get("/static/js/common.js")).text
    out = _run_common(source, """
console.log(JSON.stringify([c.updateRequestBody("3.5.14", "sha256:7c843f370ec5"), c.updateRequestBody("1.0", "не определена")]));""", tmp_path)
    assert out[0] == {"version": "3.5.14", "expected_current": "sha256:7c843f370ec5"}
    assert out[1]["expected_current"] is None


async def test_bulk_candidate_is_newest_installable_update_and_never_a_rollback(server, tmp_path):
    source = (await server.client.get("/static/js/common.js")).text
    out = _run_common(source, """
const older = {version: "3.5.9", newer: false};
const current = {version: "3.5.14", image: "example@sha256:7c843f370ec5aa"};
const next = {version: "3.5.15", newer: true};
const latest = {version: "3.5.16", newer: true};
console.log(JSON.stringify([
  c.newestUpdate({current: "3.5.14", available: [older, latest, next]}),
  c.newestUpdate({current: "sha256:7c843f370ec5", available: [older, current, next]}),
  c.newestUpdate({current: "3.5.14", available: [older]}),
  c.newestUpdate({current: "3.5.14", available: [{version:"3.5.9"}]}),
  c.newestUpdate({current: "3.5.14", available: [], upstream: {latest: "3.5.16", reason:"no_published_digest"}}),
  c.newestUpdate({current: "sha256:000000000000", available: [latest]}),
  c.newestUpdate({current: "3.5.14", status: "updating", available: [latest]}),
  c.newestUpdate({current: "4.1.0-rc.1", available: [{version:"4.1.0-rc.2", newer:true}, {version:"4.1.0-rc.10", newer:true}]}),
  c.newestUpdate({current: "sha256:7c843f370ec5", available: [{...older, newer:true}, current]}),
]));""", tmp_path)
    # The agent compares two release suffixes as strings, so rc.2 sorts after rc.10.
    assert [entry and entry['version'] for entry in out] == ['3.5.16', '3.5.15', None, None, None, None, None, '4.1.0-rc.2', None]
