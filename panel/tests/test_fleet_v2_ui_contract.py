# panel/tests/test_fleet_v2_ui_contract.py
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"


def test_index_declares_key_and_link_dialogs():
    html = (STATIC / "index.html").read_text()
    for anchor in ('id="key-modal"', 'id="key-reveal"', 'id="link-modal"', 'id="link-test"', 'id="link-fingerprint"',
                   'name="tls_verify"', 'id="node-import-list"', 'data-node-action="unlink"'):
        assert anchor in html, anchor


def test_js_uses_only_the_documented_endpoints():
    keys = (STATIC / "js/keys.js").read_text()
    nodes = (STATIC / "js/nodes.js").read_text()
    clients = (STATIC / "js/clients.js").read_text()
    assert '"/api/keys"' in keys and "/enabled" in keys
    for path in ("/api/nodes/fingerprint", "/api/nodes/test", "/api/nodes/link", "/import", "/pause", "/resume", "/probe", "/versions/"):
        assert path in nodes, path
    assert "/api/clients/grants/" in clients and 'name="node_id"' in (STATIC / "index.html").read_text()


def test_no_plaintext_key_is_kept_after_the_reveal_closes():
    keys = (STATIC / "js/keys.js").read_text()
    assert "state.keyPlaintext = null" in keys or "keyPlaintext = \"\"" in keys
