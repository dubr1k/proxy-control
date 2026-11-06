"""Real protocol UI against synthetic APIs: layout, permissions, actions and defaults."""
from __future__ import annotations

import json
import mimetypes
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import test_monitoring_layout as layout

browser = layout.browser
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def demo_server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            name = self.path.split("?", 1)[0]
            if name == "/":
                text = (ROOT / "panel/static/index.html").read_text()
                text = re.sub(r'<script[^>]*src="/static/app.js"[^>]*></script>', '<script type="module" src="/demo.js"></script>', text)
                body, kind = text.encode(), "text/html"
            elif name == "/demo.js":
                body, kind = Path(__file__).with_name("protocol-consistency-demo.js").read_bytes(), "text/javascript"
            elif name.startswith("/static/"):
                path = (ROOT / "panel" / name.lstrip("/")).resolve()
                if ROOT / "panel/static" not in path.parents or not path.is_file():
                    self.send_error(404)
                    return
                body, kind = path.read_bytes(), mimetypes.guess_type(path)[0] or "application/octet-stream"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", kind + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'")
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _eval(browser, expression):
    result = browser.call("Runtime.evaluate", {"expression": expression, "returnByValue": True, "awaitPromise": True})
    assert "exceptionDetails" not in result, result.get("exceptionDetails")
    return result["result"].get("value")


def run(browser, source):
    return _eval(browser, "(async()=>{" + source + "})()")


def open_demo(browser, port, width, height):
    browser.call("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": width < 700})
    browser.call("Page.navigate", {"url": f"http://127.0.0.1:{port}/"})
    deadline = time.monotonic() + 15
    while not _eval(browser, "!!window.demoReady") and time.monotonic() < deadline:
        time.sleep(0.1)
    assert _eval(browser, "!!window.demoReady"), _eval(browser, "JSON.stringify(window.__errs)")


@pytest.mark.parametrize(("width", "height"), [(390, 844), (1024, 768), (1440, 900)])
def test_five_protocol_rows_actions_filters_and_roles(demo_server, browser, width, height, tmp_path):
    open_demo(browser, demo_server, width, height)
    for protocol in ("users", "naive", "mieru", "amneziawg", "trusttunnel"):
        run(browser, f"await demo.open('{protocol}');true")
        assert _eval(browser, "document.querySelector('[data-protocol-row] .identity b').textContent").startswith("Анна")
        assert _eval(browser, "[...document.querySelectorAll('[data-protocol-row] button')].some(b=>b.textContent==='Удалить доступ')")
        _eval(browser, "document.querySelector('.protocol-settings').open=true;true")
        report = _eval(browser, "JSON.stringify({overflow:document.documentElement.scrollWidth>innerWidth+1,escaping:[...document.querySelectorAll('[data-protocol-row] button,.protocol-settings summary')].filter(e=>{const r=e.getBoundingClientRect();return r.width&&r.right>innerWidth+1}).length,errors:window.__errs,csp:window.__csp})")
        assert json.loads(report) == {"overflow": False, "escaping": 0, "errors": [], "csp": []}, report
        _eval(browser, "{const s=document.querySelector('[data-protocol-search]');s.value='unmapped';s.dispatchEvent(new Event('input',{bubbles:true}));}true")
        assert _eval(browser, "document.querySelectorAll('[data-protocol-row]:not([hidden])').length") == 1
        run(browser, f"await demo.open('{protocol}','viewer');true")
        assert not _eval(browser, "!!document.querySelector('.protocol-settings')")
        assert not _eval(browser, "[...document.querySelectorAll('[data-protocol-row] button')].some(b=>b.textContent==='Удалить доступ')")
    run(browser, "await demo.open('users');")
    _eval(browser, "{const s=document.querySelector('[data-protocol-search]');s.value='';s.dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('.protocol-settings').open=true;document.querySelector('[data-protocol-row]').scrollIntoView({block:'start'});}true")
    # A screenshot of synthetic values only is safe; no credentials are rendered in this fixture.
    shot = browser.call("Page.captureScreenshot", {"format": "png"})
    import base64
    (tmp_path / f"protocol-{width}.png").write_bytes(base64.b64decode(shot["data"]))


def test_delete_cancel_then_confirm_and_unlimited_creation(demo_server, browser):
    open_demo(browser, demo_server, 1440, 900)
    run(browser, "await demo.open('naive');window.requests=[];document.querySelector('[data-naive-action=delete]').click();true")
    assert _eval(browser, "requests.length") == 0
    _eval(browser, "window.confirmNext=true;document.querySelector('[data-naive-action=delete]').click();true")
    time.sleep(0.1)
    assert _eval(browser, "requests.filter(r=>r.method==='DELETE').length") == 1
    for page, prefix, button in (("users", "new-user", "create-user"), ("naive", "new-naive-user", "create-naive"), ("mieru", "new-mieru-user", "create-mieru")):
        run(browser, f"await demo.create('{page}');await new Promise(r=>setTimeout(r,50));true")
        assert _eval(browser, "document.querySelectorAll('dialog[open] [data-limit-toggle]:checked').length") == 0
        _eval(browser, f"{{window.requests=[];const input=document.getElementById('{prefix}');input.value='created';input.dispatchEvent(new Event('input',{{bubbles:true}}));document.getElementById('{button}').click();}}true")
        time.sleep(0.1)
        requests = _eval(browser, "JSON.stringify(requests)")
        rows = json.loads(requests)
        create = next(r for r in rows if r["path"] in ("/api/users", "/api/naive/users", "/api/mieru/users"))
        assert not create["body"].get("valid_until")
        assert not create["body"].get("quota_bytes")
        assert not create["body"].get("quotas")


def test_node_contract():
    result = subprocess.run(["node", str(Path(__file__).with_name("protocol_consistency_contract.mjs"))], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_manual_gb_days_and_grant_lifetime_payloads(demo_server, browser):
    open_demo(browser, demo_server, 1440, 900)
    for page, prefix, name, button, key in (("users", "new-user", "new-user", "create-user", "data_quota_bytes"), ("naive", "new-naive", "new-naive-user", "create-naive", "quota_bytes"), ("mieru", "new-mieru", "new-mieru-user", "create-mieru", "quotas")):
        run(browser, f"await demo.create('{page}');")
        script = f"""{{
          window.requests=[];
          document.getElementById('{name}').value='manual';
          for (const kind of ['traffic','validity']) {{
            const toggle=document.getElementById('{prefix}-'+kind+'-enabled');toggle.checked=true;toggle.dispatchEvent(new Event('change',{{bubbles:true}}));
          }}
          document.getElementById('{prefix}-traffic-gb').value='1.25';
          document.getElementById('{prefix}-validity-days').value='7';
          if ('{page}'==='mieru') document.getElementById('mieru-days').value='30';
          document.getElementById('{name}').dispatchEvent(new Event('input',{{bubbles:true}}));
          document.getElementById('{button}').click();
        }}true"""
        before = int(time.time())
        _eval(browser, script)
        time.sleep(0.1)
        rows = json.loads(_eval(browser, "JSON.stringify(requests)"))
        request = next(r for r in rows if r["path"].endswith("/grants"))
        grant = request["body"]["grants"][0]
        assert before + 7 * 86400 <= grant["valid_until"] <= int(time.time()) + 7 * 86400
        if key == "quotas":
            assert grant["options"][key] == [{"days": 30, "megabytes": 1193}]
        else:
            assert grant["options"][key] == 1250000000
    run(browser, "await demo.open('naive');")
    _eval(browser, "document.querySelector('.protocol-settings').open=true;document.querySelector('[data-protocol-validity]').click();true")
    time.sleep(0.1)
    assert _eval(browser, "document.querySelector('#grant-window').open")
    _eval(browser, "{const t=document.querySelector('#grant-limit-validity-enabled');t.checked=true;t.dispatchEvent(new Event('change',{bubbles:true}));document.querySelector('#grant-limit-validity-days').value='7';window.requests=[];document.querySelector('[data-grant-action=save-validity]').click();}true")
    time.sleep(0.1)
    request = json.loads(_eval(browser, "JSON.stringify(requests)"))[0]
    assert request["path"] == "/api/clients/grants/g1/validity"
    assert request["body"]["valid_until"] > time.time() + 6 * 86400


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_english_labels_and_manual_form_fit_phone(demo_server, browser, theme):
    open_demo(browser, demo_server, 390, 844)
    run(browser, "await demo.open('users');await (await import('/static/js/i18n.js')).applyLanguage('en');")
    _eval(browser, f"document.documentElement.dataset.theme='{theme}';true")
    assert _eval(browser, "document.querySelector('.protocol-settings summary').textContent") == "Configure"
    assert _eval(browser, "[...document.querySelectorAll('[data-protocol-row] button')].some(b=>b.textContent==='Delete access')")
    run(browser, "await demo.create('naive');")
    assert _eval(browser, "document.querySelector('#new-naive-traffic-enabled').checked") is False
    assert _eval(browser, "document.querySelector('#new-naive-validity-enabled').checked") is False
    report = json.loads(_eval(browser, "JSON.stringify({overflow:document.documentElement.scrollWidth>innerWidth+1,errors:window.__errs,csp:window.__csp})"))
    assert report == {"overflow": False, "errors": [], "csp": []}, report
    _eval(browser, "document.querySelector('#naive-modal').close();true")
