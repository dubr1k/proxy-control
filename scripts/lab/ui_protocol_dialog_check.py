"""Isolated AWG/TrustTunnel browser smoke; never connects to an installed panel.

Run from the checkout with its venv Python:
  python scripts/lab/ui_protocol_dialog_check.py --screenshots /tmp/protocol-dialog-shots

Fresh SQLite databases, keys and Chrome profile live in a temporary directory. The
central serves the real application on an ephemeral loopback port; linked panels
use real Fleet APIs over ASGITransport and the existing memory protocol managers.
Only empty screens and unsubmitted creation dialogs may be photographed. No
reveal, bundle, credential, HTTP body or browser exception payload is printed.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import contextmanager
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx
import uvicorn

from panel.amneziawg import MemoryAmneziawg
from panel.app import Settings, create_app
from panel.fleet_v2.client import NodeClient
from panel.keyring import Keyring
from panel.mieru import MemoryMieru
from panel.naive import MemoryNaive
from panel.telemt import MemoryTelemt
from panel.tests.test_mobile_layout import DevTools, _browser
from panel.trusttunnel import MemoryTrusttunnel
from panel.versions import VersionClient

ACTOR = {"id": 1, "username": "owner"}
PROTOCOLS = {"amneziawg": "awg", "trusttunnel": "tt"}


def require(ok, message):
    # Do not let pytest assertion introspection expose credentials held by a fixture.
    if not ok:
        raise AssertionError(message)


def make_panel(work, name, versions, port):
    key = work / f"{name}.key"
    Keyring.generate().save(key)
    absent = str(work / "absent.sock")
    settings = Settings(
        database_path=work / f"{name}.sqlite3", master_key_file=key,
        allowed_hosts=("127.0.0.1", f"127.0.0.1:{port}", f"{name}.example"),
        session_cookie_secure=False, vnext_writer="domain",
        telemt_token="", naive_token="", mieru_token="", amneziawg_token="",
        trusttunnel_token="", xray_router_token="", xray_router_enabled=False,
        naive_enabled=False, mieru_enabled=False, metrics_enabled=False,
        amneziawg_enabled=True, amneziawg_public_host=f"awg.{name}.example",
        trusttunnel_enabled=True, trusttunnel_public_host=f"tt.{name}.example",
        mtproxy_public_host=f"{name}.example", naive_public_host="",
        subscription_url="", subscription_host="", version_agent_socket=absent,
    )
    return create_app(
        settings, telemt=MemoryTelemt(public_host=f"{name}.example"),
        naive=MemoryNaive(), mieru=MemoryMieru(),
        amneziawg=MemoryAmneziawg(versions=versions),
        trusttunnel=MemoryTrusttunnel(hostname=f"tt.{name}.example"),
        version_client=VersionClient(absent),
    )


class ProtocolFixture:
    def __init__(self, work, port):
        self.base = f"http://127.0.0.1:{port}"
        self.central = make_panel(work, "central", ("1.5", "2.0"), port)
        self.remote = make_panel(work, "remote", ("3.1",), port)
        self.paused = make_panel(work, "paused", ("1.5",), port)
        nodes = {"remote.example": self.remote, "paused.example": self.paused}
        self.central.state.links.client_factory = lambda url, key, **kw: NodeClient(
            url, key, transport=httpx.ASGITransport(app=nodes[urllib.parse.urlsplit(url).hostname]), **kw,
        )
        self.remote_id, self.paused_id = asyncio.run(self._link())
        self.central.state.fleet.register_node("legacy-edge", "Legacy agent", {})
        self.central.state.links.set_enabled(self.paused_id, False, actor=ACTOR, ip="127.0.0.1")
        self.http = httpx.Client(base_url=self.base, timeout=20, trust_env=False)

    async def _link(self):
        ids = []
        for name, node in (("remote", self.remote), ("paused", self.paused)):
            _, key = node.state.api_keys.create("isolated-central", "node-sync", None, actor=ACTOR, ip="127.0.0.1")
            ids.append(await self.central.state.links.add(
                f"{name.title()} panel", f"https://{name}.example", key, "verify", None, False,
                actor=ACTOR, ip="127.0.0.1", auto_import=False,
            ))
        return ids

    def login(self):
        password = secrets.token_urlsafe(32)
        self.central.state.store.create_admin("owner", password, "owner")
        require(self.http.get("/login").status_code == 200, "fixture login page unavailable")
        response = self.http.post("/api/auth/login", json={"username": "owner", "password": password},
                                  headers={"X-CSRF-Token": self.http.cookies["panel_csrf"]})
        require(response.status_code in (200, 204), "fixture authentication failed")
        self.http.headers["X-CSRF-Token"] = self.http.cookies["panel_csrf"]
        self.client_id = self.api("/api/clients", "POST", {"display_name": "remote-tt", "subscription": False})["id"]

    def api(self, path, method="GET", payload=None):
        response = self.http.request(method, path, json=payload)
        require(200 <= response.status_code < 300, f"fixture API refused {method}: HTTP {response.status_code}")
        return response.json() if response.content else {}


@contextmanager
def isolated_panel(work):
    # Keep the listening socket reserved: there is no free-port/rebind race.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        fixture = ProtocolFixture(work, listener.getsockname()[1])
        # Explicit ticks below make remote delivery deterministic. No background jobs,
        # manager sockets, DNS lookups or production services are needed.
        server = uvicorn.Server(uvicorn.Config(
            fixture.central, host="127.0.0.1", lifespan="off", log_level="critical", access_log=False,
        ))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 20
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.05)
            require(server.started, "isolated application did not start")
            fixture.login()
            yield fixture
        finally:
            fixture.http.close()
            server.should_exit = True
            thread.join(timeout=10)
            require(not thread.is_alive(), "isolated application did not stop")


INSTRUMENT = """
window.__protocolNodesReads = 0;
window.__protocolErrors = 0;
window.__protocolCsp = 0;
addEventListener('error', () => window.__protocolErrors++);
addEventListener('unhandledrejection', () => window.__protocolErrors++);
document.addEventListener('securitypolicyviolation', () => window.__protocolCsp++);
const originalFetch = window.fetch;
window.fetch = (...args) => {
  const path = new URL(typeof args[0] === 'string' ? args[0] : args[0].url, location.href).pathname;
  if (path === '/api/nodes') window.__protocolNodesReads++;
  return originalFetch(...args);
};
"""


class ProtocolBrowser:
    def __init__(self, devtools, fixture, screenshots):
        self.dt = devtools
        self.fixture = fixture
        self.screenshots = screenshots
        self.can_capture = True

    def js(self, expression):
        result = self.dt.call("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": True,
        })
        require("exceptionDetails" not in result, "browser evaluation failed (payload withheld)")
        return result["result"].get("value")

    def wait(self, expression, label):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.js(expression):
                return
            time.sleep(0.05)
        raise AssertionError(f"browser timed out: {label}")

    def click(self, selector):
        self.js(f"document.querySelector({json.dumps(selector)}).click(); true")

    def set_value(self, selector, value):
        self.js(f"""(() => {{ const el = document.querySelector({json.dumps(selector)});
            el.value = {json.dumps(value)};
            el.dispatchEvent(new Event('input', {{bubbles: true}}));
            el.dispatchEvent(new Event('change', {{bubbles: true}})); return true; }})()""")

    def open_screen(self, protocol, width=1440):
        self.dt.call("Emulation.setDeviceMetricsOverride", {
            "width": width, "height": 900 if width > 600 else 844,
            "deviceScaleFactor": 1, "mobile": width < 600,
        })
        # A query change forces a complete reload, not merely a hash navigation.
        nonce = secrets.token_hex(4)
        self.dt.call("Page.navigate", {"url": f"{self.fixture.base}/?isolated={nonce}#{protocol}"})
        self.wait(f"location.search === '?isolated={nonce}' && location.hash === '#{protocol}' && !!document.querySelector('#view .empty-state')", "direct protocol navigation")
        self.wait("!!document.querySelector('#add') && !document.querySelector('#add').hidden", "protocol add button")
        require(self.js("window.__protocolNodesReads") == 0, "direct navigation must start without a populated node cache")

    def open_dialog(self, protocol, expected_reads):
        short = PROTOCOLS[protocol]
        self.click("#add")
        self.wait(f"document.querySelector('#{short}-modal')?.open === true", "creation dialog")
        self.wait(f"window.__protocolNodesReads === {expected_reads}", "fresh /api/nodes on every open")
        self.wait(f"document.querySelectorAll('#{short}-node option').length === 2", "local and enabled remote options")
        if short == "tt":
            self.wait("!document.querySelector('#create-tt').disabled", "client choices loaded")

    def options(self, short):
        return self.js(f"[...document.querySelectorAll('#{short}-node option')].map(e => e.value).sort()")

    def healthy(self):
        require(self.js("window.__protocolErrors === 0 && window.__protocolCsp === 0"), "browser error or CSP violation")

    def shot(self, name):
        if self.screenshots is None:
            return
        require(self.can_capture, "screenshots are forbidden after issuance")
        require(self.js("""![...document.querySelectorAll('dialog[open]')].some(
            d => !['awg-modal', 'tt-modal'].includes(d.id)) &&
            !document.querySelector('#bundle-body textarea, #bundle-body .link-qr, #grant-link-body textarea')"""),
            "refusing to photograph an access/reveal dialog")
        self.screenshots.mkdir(parents=True, exist_ok=True)
        image = self.dt.call("Page.captureScreenshot", {"format": "png"})
        (self.screenshots / name).write_bytes(base64.b64decode(image["data"]))


@contextmanager
def isolated_browser(work, fixture, screenshots=None):
    profile = work / "chrome"
    process = subprocess.Popen([
        _browser(), "--headless", "--no-sandbox", "--disable-gpu", "--remote-allow-origins=*",
        "--remote-debugging-port=0", f"--user-data-dir={profile}", "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dt = None
    try:
        deadline = time.monotonic() + 90
        port = None
        while time.monotonic() < deadline and process.poll() is None:
            try:
                lines = (profile / "DevToolsActivePort").read_text().splitlines()
                if len(lines) >= 2:
                    port = int(lines[0])
                    break
            except (OSError, ValueError, IndexError):
                pass
            time.sleep(0.05)
        require(port is not None, "Chromium DevTools did not start")
        target = None
        while target is None and time.monotonic() < deadline:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5) as response:
                target = next((t["webSocketDebuggerUrl"] for t in json.load(response) if t.get("type") == "page"), None)
            if target is None:
                time.sleep(0.05)
        if target is None:
            raise AssertionError("Chromium page did not start")
        dt = DevTools(target)
        dt.call("Page.enable")
        dt.call("Network.enable")
        dt.call("Page.addScriptToEvaluateOnNewDocument", {"source": INSTRUMENT})
        for name in ("panel_session", "panel_csrf"):
            require(dt.call("Network.setCookie", {
                "name": name, "value": fixture.http.cookies[name], "url": fixture.base,
            }).get("success"), "browser session cookie was rejected")
        yield ProtocolBrowser(dt, fixture, screenshots)
    finally:
        if dt is not None:
            dt.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def check_empty_state(browser, protocol, width):
    browser.open_screen(protocol, width)
    geometry = browser.js("""(() => {
      const root = document.querySelector('#view .empty-state');
      const heading = root.querySelector('h3'); const description = root.querySelector('p');
      if (!heading || !description) return {blocks: false};
      const h = heading.getBoundingClientRect(), p = description.getBoundingClientRect();
      return {blocks: getComputedStyle(heading).display === 'block' && getComputedStyle(description).display === 'block',
        content: !!heading.textContent.trim() && !!description.textContent.trim(),
        separate: h.height > 0 && p.height > 0 && p.top >= h.bottom,
        aligned: Math.abs(h.left - p.left) < 1 && Math.abs(h.right - p.right) < 1,
        inside: h.left >= 0 && p.left >= 0 && h.right <= innerWidth && p.right <= innerWidth,
        noOverflow: document.documentElement.scrollWidth <= innerWidth + 1};
    })()""")
    require(all(geometry.get(key) for key in ("blocks", "content", "separate", "aligned", "inside", "noOverflow")),
            f"{protocol} empty-state headline/description must occupy separate non-overlapping block rows at {width}px")
    browser.healthy()
    browser.shot(f"{protocol}-empty-{width}.png")


def check_node_dialog(browser, protocol):
    fixture = browser.fixture
    short = PROTOCOLS[protocol]
    browser.open_screen(protocol)
    browser.open_dialog(protocol, 1)
    require(browser.options(short) == sorted(["local", fixture.remote_id]), "paused or legacy node offered, or enabled remote missing")
    require(browser.js(f"document.querySelector('#{short}-node').value") == "local", "local must remain the default")
    browser.set_value(f"#{short}-node", fixture.remote_id)
    if short == "awg":
        require(browser.js("[...document.querySelectorAll('[data-awg-version]:not(:disabled)')].map(e=>e.dataset.awgVersion)") == ["3.1"],
                "AWG must offer the selected remote's identity versions only")
        require(browser.js("!document.querySelector('[data-awg-version=\"2.0\"]').checked"), "unsupported AWG default must be cleared")
        browser.click('[data-awg-version="3.1"]')
        browser.set_value("#awg-node", "local")
        require(browser.js("[...document.querySelectorAll('[data-awg-version]:not(:disabled)')].map(e=>e.dataset.awgVersion)") == ["1.5", "2.0"],
                "switching back must restore local AWG versions")
        require(browser.js("!document.querySelector('[data-awg-version=\"3.1\"]').checked"), "switching nodes must clear unsupported selections")
        browser.set_value("#awg-node", fixture.remote_id)
    browser.shot(f"{protocol}-remote-dialog-1440.png")
    browser.dt.call("Emulation.setDeviceMetricsOverride", {"width": 390, "height": 844, "deviceScaleFactor": 1, "mobile": True})
    browser.shot(f"{protocol}-remote-dialog-390.png")
    browser.js(f"document.querySelector('#{short}-modal').close(); true")
    # Change the real inventory between opens, not a mocked fetch response.
    fixture.api(f"/api/nodes/{fixture.remote_id}/pause", "POST")
    fixture.api(f"/api/nodes/{fixture.paused_id}/resume", "POST")
    try:
        browser.open_dialog(protocol, 2)
        require(browser.options(short) == sorted(["local", fixture.paused_id]), "reopening reused stale node inventory")
        if short == "awg":
            browser.set_value("#awg-node", fixture.paused_id)
            require(browser.js("[...document.querySelectorAll('[data-awg-version]:not(:disabled)')].map(e=>e.dataset.awgVersion)") == ["1.5"],
                    "reopened AWG dialog reused stale capabilities")
        browser.healthy()
    finally:
        fixture.api(f"/api/nodes/{fixture.remote_id}/resume", "POST")
        fixture.api(f"/api/nodes/{fixture.paused_id}/pause", "POST")
        browser.js(f"document.querySelector('#{short}-modal').close(); true")


def check_remote_issuance(browser, protocol):
    fixture = browser.fixture
    short = PROTOCOLS[protocol]
    browser.open_screen(protocol)
    browser.open_dialog(protocol, 1)
    browser.set_value(f"#{short}-node", fixture.remote_id)
    if short == "awg":
        browser.set_value("#new-awg-user", "remote-awg")
        browser.click('[data-awg-version="3.1"]')
        username = "remote-awg-awg31"
    else:
        browser.set_value("#tt-client", fixture.client_id)
        browser.set_value("#tt-name", "Remote smoke")
        username = "remote-tt"
    browser.wait(f"!document.querySelector('#create-{short}').disabled", "issuance enabled")
    # Never take screenshots, DOM dumps or exception payloads after this boundary.
    browser.can_capture = False
    browser.click(f"#create-{short}")
    browser.wait(f"document.querySelector('#{short}-modal')?.open === false", "grant request accepted")
    asyncio.run(fixture.central.state.pusher.tick())
    if short == "awg":
        remote_table = fixture.remote.state.amneziawg.peer_table
        local_table = fixture.central.state.amneziawg.peer_table
    else:
        remote_table = fixture.remote.state.trusttunnel.client_table
        local_table = fixture.central.state.trusttunnel.client_table
    require(username in remote_table and username not in local_table,
            f"{protocol} issuance must reach the chosen remote manager, not the local manager")
    entries = fixture.api("/api/clients")["items"]
    grants = [grant for entry in entries for grant in entry["grants"]
              if grant["protocol"] == protocol and grant["runtime_username"] == username]
    require(len(grants) == 1, "issued grant missing from real application state")
    grant = grants[0]
    require(grant["node_id"] == fixture.remote_id and grant["observed_state"] == "enabled",
            "real Fleet reconciliation did not confirm the selected remote grant")
    if short == "awg":
        require(grant["options"]["version"] == "3.1", "wrong AWG version reached remote")
    else:
        require(grant["options"]["hostname"] == "tt.remote.example", "TrustTunnel endpoint was not learned from the remote")
    browser.healthy()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screenshots", type=Path, help="empty states and unsubmitted dialogs only")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="protocol-dialog-smoke-") as directory:
        work = Path(directory)
        with isolated_panel(work) as fixture, isolated_browser(work, fixture, args.screenshots) as browser:
            for protocol in PROTOCOLS:
                for width in (1440, 390):
                    check_empty_state(browser, protocol, width)
                check_node_dialog(browser, protocol)
            for protocol in PROTOCOLS:
                check_remote_issuance(browser, protocol)
    print("PROTOCOL_DIALOG_SMOKE_OK: AWG+TrustTunnel; fresh nodes; capability selection; remote issuance; desktop/mobile rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
