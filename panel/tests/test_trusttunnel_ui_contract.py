"""The TrustTunnel screen and every protocol map that learned about it (v1.6).

Static contract: the wiring a browser cannot be asked about in a unit test. The pure placement
module is also exercised in Node, as shipped.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "panel" / "static"
JS = STATIC / "js"
NODE = shutil.which("node")





























@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_placement_has_a_fixed_trusttunnel_column_that_issues_plain_grants():
    tmp = Path(tempfile.mkdtemp())
    shutil.copy(JS / "common.js", tmp / "common.mjs")
    (tmp / "placement.mjs").write_text((JS / "placement.js").read_text().replace("./common.js", "./common.mjs"))
    code = (
        f'import * as p from {json.dumps((tmp / "placement.mjs").as_uri())};'
        'const nodes=[{node_id:"local",display_name:"s",transport:"local"}];'
        'const rows=p.placementRows(nodes,[]);'
        'const diff=p.placementDiff(rows,new Set(["local:trusttunnel"]),"alice");'
        'console.log(JSON.stringify({cols:p.columnsFor(rows).map(c=>c.key),diff,name:p.columnName({protocol:"trusttunnel",version:null})}));'
    )
    out = json.loads(subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, text=True, check=True).stdout)
    assert out["cols"] == ["mtproxy", "naive", "mieru", "trusttunnel"]
    assert out["diff"]["create"] == [{"protocol": "trusttunnel", "node_id": "local", "runtime_username": "alice", "options": {}}]
    assert out["name"] == "TrustTunnel"






