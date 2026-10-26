"""The TrustTunnel screen and every protocol map that learned about it (v1.6).

Static contract: the wiring a browser cannot be asked about in a unit test. The pure placement
module is also exercised in Node, as shipped.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.anyio
NODE = shutil.which("node")





























async def test_placement_has_a_fixed_trusttunnel_column_that_issues_plain_grants(server, tmp_path):
    for name in ("common", "placement"):
        response = await server.client.get(f"/static/js/{name}.js")
        assert response.status_code == 200, name
        (tmp_path / f"{name}.mjs").write_text(response.text.replace("./common.js", "./common.mjs"))
    code = (
        f'import * as p from {json.dumps((tmp_path / "placement.mjs").as_uri())};'
        'const nodes=[{node_id:"local",display_name:"s",transport:"local"}];'
        'const rows=p.placementRows(nodes,[]);'
        'const diff=p.placementDiff(rows,new Set(["local:trusttunnel"]),"alice");'
        'console.log(JSON.stringify({cols:p.columnsFor(rows).map(c=>c.key),diff,name:p.columnName({protocol:"trusttunnel",version:null})}));'
    )
    assert NODE is not None
    out = json.loads(subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, text=True, check=True).stdout)
    assert out["cols"] == ["mtproxy", "naive", "mieru", "trusttunnel"]
    assert out["diff"]["create"] == [{"protocol": "trusttunnel", "node_id": "local", "runtime_username": "alice", "options": {}}]
    assert out["name"] == "TrustTunnel"






