import json
from pathlib import Path


def test_release_contains_reviewed_three_xui_amd64_layout():
    root=Path(__file__).resolve().parents[1]
    layout=json.loads((root/'release/three-xui-layout-amd64.json').read_text())
    assert layout['entries']
    assert any(x['path']=='x-ui/x-ui' and x['kind']=='file' for x in layout['entries'])
