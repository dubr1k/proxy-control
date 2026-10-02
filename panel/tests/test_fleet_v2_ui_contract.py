# panel/tests/test_fleet_v2_ui_contract.py
from pathlib import Path
import json
import shutil
import subprocess

STATIC = Path(__file__).resolve().parent.parent / "static"


def test_fingerprint_fetch_with_empty_pin_uses_private_checkbox_without_link_validation(tmp_path):
    shutil.copytree(STATIC / "js", tmp_path / "js")
    (tmp_path / "package.json").write_text('{"type":"module"}')
    script = """
      import { bindNodes } from './js/nodes.js';
      const results = [];
      for (const allowPrivate of [false, true]) {
        const elements = new Map();
        const root = { querySelector(selector) {
          if (!elements.has(selector)) elements.set(selector, {
            value: '', checked: false, textContent: '', listeners: new Map(),
            addEventListener(name, fn) { this.listeners.set(name, fn); },
          });
          return elements.get(selector);
        } };
        root.querySelector('#link-url').value = 'https://node.example';
        root.querySelector('input[name="tls_verify"]:checked').value = 'pin';
        root.querySelector('#link-pinned').value = '';
        root.querySelector('#link-private').checked = allowPrivate;
        const calls = [];
        bindNodes({ root, state: {}, ui: { setBusy() {}, toast() {} },
          api: async (path, options) => {
            calls.push({ path, method: options.method, body: JSON.parse(options.body) });
            return { sha256: 'a'.repeat(64) };
          },
        });
        const button = root.querySelector('#link-fingerprint');
        await button.listeners.get('click')({ currentTarget: button });
        results.push({ calls, pin: root.querySelector('#link-pinned').value,
                       error: root.querySelector('#link-error').textContent });
      }
      console.log(JSON.stringify(results));
    """
    result = subprocess.run(["node", "--input-type=module", "-e", script], cwd=tmp_path,
                            capture_output=True, text=True, check=True)
    for actual, private in zip(json.loads(result.stdout), (False, True)):
        assert actual == {"calls": [{"path": "/api/nodes/fingerprint", "method": "POST",
                                     "body": {"url": "https://node.example", "allow_private_address": private}}],
                          "pin": "a" * 64, "error": ""}


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


def test_unlink_dialog_tells_the_truth_about_re_mastering():
    """Unlinking releases ownership only: the same central re-masters the panel on its next
    heartbeat unless its key is disabled or the node is deleted there (FLEET, «Unlink on the node»)."""
    html = (STATIC / "index.html").read_text()
    dialog = html[html.index('id="unlink-modal"'):html.index('id="key-modal"')]
    assert "перестанет принимать поколения" not in dialog
    assert 'id="unlink-master"' in dialog and "node-sync" in dialog and "удалите узел на центре" in dialog
