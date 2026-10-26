"""Fleet UI request and secret-handling flows in JavaScript served by the Rust panel."""
import json
import subprocess

import pytest

pytestmark = pytest.mark.anyio


async def _served_modules(server, tmp_path):
    js = tmp_path / "js"
    js.mkdir()
    for name in ("nodes", "routing", "common", "state", "api", "routing-guide", "placement"):
        response = await server.client.get(f"/static/js/{name}.js")
        assert response.status_code == 200, name
        (js / f"{name}.js").write_text(response.text)
    (tmp_path / "package.json").write_text('{"type":"module"}')


async def test_fingerprint_fetch_with_empty_pin_uses_private_checkbox_without_link_validation(server, tmp_path):
    await _served_modules(server, tmp_path)
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



async def test_center_key_is_created_through_the_keys_api_and_cleared_on_close(server, login_user, tmp_path):
    await _served_modules(server, tmp_path)
    script = """
      import { handleNodesClick, bindNodes } from './js/nodes.js';
      globalThis.window = { location: { origin: 'https://panel.example' } };
      const elements = new Map();
      const root = { querySelector(selector) {
        if (!elements.has(selector)) elements.set(selector, {
          value: '', listeners: new Map(),
          addEventListener(name, fn) { this.listeners.set(name, fn); },
        });
        return elements.get(selector);
      } };
      const calls = []; const opened = [];
      const context = { root, state: {}, api: async (path, options) => {
          calls.push({ path, method: options.method, body: JSON.parse(options.body) });
          return { plaintext: 'pc_secret', key: { name: 'x', scope: 'node-sync' } };
        },
        ui: { setBusy() {}, toast() {}, openModal(selector) { opened.push(selector); } } };
      bindNodes(context);
      const handled = handleNodesClick(context, { dataset: { nodeAction: 'center-key' }, closest: () => null });
      await new Promise((resolve) => setTimeout(resolve, 20));
      const shown = { url: root.querySelector('#center-url').value, key: root.querySelector('#center-key').value };
      root.querySelector('#center-key-modal').listeners.get('close')();
      console.log(JSON.stringify({ handled, calls, opened, shown, after: root.querySelector('#center-key').value }));
    """
    result = subprocess.run(["node", "--input-type=module", "-e", script], cwd=tmp_path,
                            capture_output=True, text=True, check=True)
    actual = json.loads(result.stdout)
    assert actual["handled"] is True and actual["opened"] == ["#center-key-modal"]
    assert [(c["path"], c["method"], c["body"]["scope"], c["body"]["expires_at"]) for c in actual["calls"]] == [("/api/keys", "POST", "node-sync", None)]
    assert actual["shown"] == {"url": "https://panel.example", "key": "pc_secret"} and actual["after"] == ""
    await login_user(server.client)
    html = (await server.client.get("/")).text
    for needle in ('id="center-key-modal"', 'id="copy-center-key"', 'id="copy-center-url"'):
        assert needle in html
