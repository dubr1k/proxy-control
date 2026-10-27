"""Isolated AWG/TrustTunnel browser smoke; never connects to an installed panel.

Run from the checkout with its venv Python:
  python scripts/lab/ui_protocol_dialog_check.py --screenshots /tmp/protocol-dialog-shots

Fresh SQLite databases, keys and Chrome profile live in a temporary directory. The
central serves the actual Rust panel binary through an ephemeral loopback byte relay;
linked panels and test-owned manager doubles communicate over real HTTP sockets.
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
import select
import socket
import subprocess
import socketserver
import sys
import tempfile
import threading
import time
import urllib.request

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx
from panel.tests.harness.memories.amneziawg import MemoryAmneziawg
from panel.tests.harness.memories.fakes import MemoryAgentMetrics
from panel.tests.harness.memories.mieru import MemoryMieru
from panel.tests.harness.memories.naive import MemoryNaive
from panel.tests.harness.memories.telemt import MemoryTelemt
from panel.tests.harness.memories.trusttunnel import MemoryTrusttunnel
from panel.tests.harness.memories.versions import MemoryVersions
from panel.tests.harness.memories.xray_router import MemoryXrayRouter
from panel.tests.harness.server import start_panel
from panel.tests.test_mobile_layout import DevTools, _browser

ACTOR = {"id": 1, "username": "owner"}
PROTOCOLS = {"amneziawg": "awg", "trusttunnel": "tt"}


def require(ok, message):
    # Do not let pytest assertion introspection expose credentials held by a fixture.
    if not ok:
        raise AssertionError(message)


# A browser test that needs client links sets this before opening the panel: no subscription URL, no links.
SUBSCRIPTION_URL = ""
# The host `/s/{token}` answers on; the end-user page test sets it to the loopback address it browses.
SUBSCRIPTION_HOST = ""


def make_panel(work, name, versions, port, **options):
    return start_panel(
        work, name=name,
        hosts=("testserver", "127.0.0.1", f"127.0.0.1:{port}", f"{name}.example"),
        naive_enabled=False, mieru_enabled=False, metrics_enabled=False,
        amneziawg_enabled=True, amneziawg_public_host=f"awg.{name}.example",
        trusttunnel_enabled=True, trusttunnel_public_host=f"tt.{name}.example",
        mtproxy_public_host=f"{name}.example", naive_public_host="",
        subscription_url=SUBSCRIPTION_URL, subscription_host=SUBSCRIPTION_HOST,
        telemt=MemoryTelemt(public_host=f"{name}.example"),
        naive=MemoryNaive(), mieru=MemoryMieru(),
        amneziawg=MemoryAmneziawg(versions=versions),
        trusttunnel=MemoryTrusttunnel(hostname=f"tt.{name}.example"), **options,
    )


class ProtocolFixture:
    def __init__(self, work, listener):
        port = listener.getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.panels = []
        try:
            asyncio.run_coroutine_threadsafe(self._start(work, port), self.loop).result(60)
            target = self.central.socket

            class Relay(socketserver.BaseRequestHandler):
                def handle(self):
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
                        upstream.connect(target)
                        sockets = [self.request, upstream]
                        while True:
                            ready, _, _ = select.select(sockets, [], [], 30)
                            if not ready:
                                return
                            for source in ready:
                                try:
                                    data = source.recv(65536)
                                except ConnectionResetError:
                                    if source is self.request:
                                        return
                                    raise
                                if not data:
                                    return
                                destination = upstream if source is self.request else self.request
                                try:
                                    destination.sendall(data)
                                except (ConnectionResetError, BrokenPipeError):
                                    if destination is self.request:
                                        return
                                    raise

            self.relay = socketserver.ThreadingTCPServer(listener.getsockname(), Relay, bind_and_activate=False)
            self.relay.socket.close()
            self.relay.socket = listener
            self.relay.daemon_threads = True
            self.relay.server_activate()
            self.relay_thread = threading.Thread(target=self.relay.serve_forever, daemon=True)
            self.relay_thread.start()
            self.http = httpx.Client(base_url=self.base, timeout=20, trust_env=False)
        except BaseException:
            self.close()
            raise

    async def _start(self, work, port):
        self.remote = make_panel(work, "remote", ("3.1",), port)
        self.panels.append(self.remote)
        self.paused = make_panel(work, "paused", ("1.5",), port)
        self.panels.append(self.paused)
        self.central = make_panel(work, "central", ("1.5", "2.0"), port,
                                  node_routes={"remote.example": self.remote, "paused.example": self.paused})
        self.panels.append(self.central)
        self.central.client.headers["Authorization"] = "Bearer " + self.central.create_api_key("browser-seed", "admin")
        ids = []
        for name, node in (("remote", self.remote), ("paused", self.paused)):
            key = node.create_api_key("isolated-central", "node-sync")
            response = await self.central.client.post("/api/nodes/link", json={
                "display_name": f"{name.title()} panel", "url": f"https://{name}.example",
                "api_key": key, "auto_import": False,
            })
            require(response.status_code == 201, "isolated node link failed")
            ids.append(response.json()["node_id"])
        self.remote_id, self.paused_id = ids
        response = await self.central.client.post(f"/api/nodes/{self.paused_id}/pause")
        require(response.status_code == 200, "isolated node pause failed")

    def close(self):
        if hasattr(self, "http"):
            self.http.close()
        if hasattr(self, "relay"):
            self.relay.shutdown()
            self.relay.server_close()
            self.relay_thread.join(timeout=10)

        async def stop():
            for panel in reversed(self.panels):
                await panel.aclose()

        asyncio.run_coroutine_threadsafe(stop(), self.loop).result(30)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=10)
        self.loop.close()

    def login(self, role="owner"):
        password = secrets.token_urlsafe(32)
        self.central.create_admin("owner", password, role)
        require(self.http.get("/login").status_code == 200, "fixture login page unavailable")
        response = self.http.post("/api/auth/login", json={"username": "owner", "password": password},
                                  headers={"X-CSRF-Token": self.http.cookies["panel_csrf"]})
        require(response.status_code in (200, 204), "fixture authentication failed")
        self.http.headers["X-CSRF-Token"] = self.http.cookies["panel_csrf"]
        if role == "owner":
            self.client_id = self.api("/api/clients", "POST", {"display_name": "remote-tt", "subscription": False})["id"]

    def api(self, path, method="GET", payload=None):
        response = self.http.request(method, path, json=payload)
        require(200 <= response.status_code < 300, f"fixture API refused {method}: HTTP {response.status_code}")
        return response.json() if response.content else {}


class OverviewFixture(ProtocolFixture):
    """One native panel, with independently controllable host-agent and collector samples."""

    def __init__(self, work, listener, *, monitoring=True, trusttunnel=True):
        self.monitoring, self.trusttunnel_enabled = monitoring, trusttunnel
        super().__init__(work, listener)

    async def _start(self, work, port):
        self.agent = MemoryAgentMetrics()
        agent = self.agent

        class VersionsAndMetrics(MemoryVersions):
            async def metrics(self):
                return await agent.metrics()

        self.versions = VersionsAndMetrics()
        panel = self.versions.components.pop("panel")
        for component, version in (("amneziawg", "0.2.18"), ("trusttunnel", "1.1.7")):
            self.versions.components[component] = {
                "current": version, "available": [{"version": version, "kind": "build"}],
            }
        # Deliberately last on the wire: the screen, not insertion order, must put it first.
        self.versions.components["panel"] = panel
        self.central = start_panel(
            work, name="overview", hosts=("testserver", "127.0.0.1", f"127.0.0.1:{port}"),
            naive_enabled=True, mieru_enabled=True, amneziawg_enabled=True,
            trusttunnel_enabled=self.trusttunnel_enabled, metrics_enabled=self.monitoring,
            naive_public_host="naive.example", amneziawg_public_host="awg.example",
            trusttunnel_public_host="tt.example", mtproxy_public_host="mt.example",
            telemt=MemoryTelemt(), naive=MemoryNaive(), mieru=MemoryMieru(),
            amneziawg=MemoryAmneziawg(), trusttunnel=MemoryTrusttunnel(hostname="tt.example"),
            versions=self.versions, router=MemoryXrayRouter(),
        )
        self.panels.append(self.central)
        self.central.clock.set(self.agent.clock.now)
        if self.monitoring:
            await self.central.tick("metrics")

    def sample(self, cpu, memory, disk):
        async def collect():
            self.agent.cpu, self.agent.mem, self.agent.disk = cpu, memory, disk
            self.agent.clock.advance(2)
            self.central.clock.set(self.agent.clock.now)
            await self.central.tick("metrics")

        asyncio.run_coroutine_threadsafe(collect(), self.loop).result(30)



@contextmanager
def isolated_panel(work, fixture_type=ProtocolFixture, *, role="owner", **options):
    # Keep the listening socket reserved: there is no free-port/rebind race.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        fixture = fixture_type(work, listener, **options)
        try:
            fixture.login(role)
            yield fixture
        finally:
            fixture.close()


INSTRUMENT = """
window.__protocolNodesReads = 0;
window.__protocolErrors = 0;
window.__protocolCsp = 0;
window.__protocolConsoleErrors = 0;
const originalConsoleError = console.error.bind(console);
console.error = (...args) => {
  window.__protocolConsoleErrors++;
  originalConsoleError(...args);
};
window.__hostReads = 0;
window.__snapshotCpus = [];
const NativeEventSource = window.EventSource;
window.EventSource = class extends NativeEventSource {
  constructor(...args) {
    super(...args);
    this.addEventListener('snapshot', event => {
      const snapshot = JSON.parse(event.data);
      const local = snapshot.nodes?.find(node => node.node_id === 'local');
      if (local?.host) window.__snapshotCpus.push(local.host.cpu_percent);
    });
  }
};
addEventListener('error', () => window.__protocolErrors++);
addEventListener('unhandledrejection', () => window.__protocolErrors++);
document.addEventListener('securitypolicyviolation', () => window.__protocolCsp++);
const originalFetch = window.fetch;
window.fetch = (...args) => {
  const path = new URL(typeof args[0] === 'string' ? args[0] : args[0].url, location.href).pathname;
  if (path === '/api/nodes') window.__protocolNodesReads++;
  if (path === '/api/host') window.__hostReads++;
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

    def open_view(self, view, ready, width=1440):
        self.dt.call("Emulation.setDeviceMetricsOverride", {
            "width": width, "height": 900 if width > 600 else 844,
            "deviceScaleFactor": 1, "mobile": width < 600,
        })
        nonce = secrets.token_hex(4)
        self.dt.call("Page.navigate", {"url": f"{self.fixture.base}/?isolated={nonce}#{view}"})
        self.wait(f"location.search === '?isolated={nonce}' && ({ready})", "native view rendered")

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
        # The app may load the node inventory while painting the screen. Record its
        # current request count; opening each modal must still issue a fresh request.
        self.wait("window.__protocolNodesReads >= 1", "initial node inventory request")
        self.node_reads = self.js("window.__protocolNodesReads")

    def open_dialog(self, protocol, expected_reads):
        short = PROTOCOLS[protocol]
        self.click("#add")
        self.wait(f"document.querySelector('#{short}-modal')?.open === true", "creation dialog")
        self.wait(f"window.__protocolNodesReads === {self.node_reads + expected_reads}", "fresh /api/nodes on every open")
        self.wait(f"document.querySelectorAll('#{short}-node option').length === 2", "local and enabled remote options")
        if short == "tt":
            self.wait("!document.querySelector('#create-tt').disabled", "client choices loaded")

    def options(self, short):
        return self.js(f"[...document.querySelectorAll('#{short}-node option')].map(e => e.value).sort()")

    def healthy(self):
        require(self.js("window.__protocolErrors === 0 && window.__protocolCsp === 0 && window.__protocolConsoleErrors === 0"),
                "browser error, console error or CSP violation")

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
    require(browser.options(short) == sorted(["local", fixture.remote_id]), "paused node offered, or enabled remote missing")
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
    asyncio.run_coroutine_threadsafe(fixture.central.tick("pusher"), fixture.loop).result(30)
    asyncio.run_coroutine_threadsafe(fixture.remote.settle(), fixture.loop).result(30)
    asyncio.run_coroutine_threadsafe(fixture.central.tick("pusher"), fixture.loop).result(30)
    if short == "awg":
        remote_table = fixture.remote.amneziawg.peer_table
        local_table = fixture.central.amneziawg.peer_table
    else:
        remote_table = fixture.remote.trusttunnel.client_table
        local_table = fixture.central.trusttunnel.client_table
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


def check_overview_attention(browser):
    """«Требует внимания» lists the paused node and links to Nodes; with nothing to report the
    block is gone; «Выдать доступ» opens the new-client dialog of the Clients screen."""
    fixture = browser.fixture
    nonce = secrets.token_hex(4)
    browser.dt.call("Emulation.setDeviceMetricsOverride", {"width": 1440, "height": 900, "deviceScaleFactor": 1, "mobile": False})

    def open_overview():
        browser.dt.call("Page.navigate", {"url": f"{fixture.base}/?isolated={nonce}{secrets.token_hex(2)}#dashboard"})
        browser.wait("!!document.querySelector('#view .host-card')", "overview painted")

    open_overview()
    lines = browser.js("[...document.querySelectorAll('[data-attention] a.attention-link')].map(a => [a.querySelector('b').textContent, a.querySelector('small').textContent, a.getAttribute('href')])")
    require(lines == [["Paused panel", "на паузе", "#fleet"]], f"the paused node must be the one attention line, linking to Nodes: {lines}")
    fixture.api(f"/api/nodes/{fixture.paused_id}/resume", "POST")
    try:
        open_overview()
        require(browser.js("document.querySelector('[data-attention]') === null"), "the block must hide when nothing needs attention")
        browser.wait("!!document.querySelector('#add') && !document.querySelector('#add').hidden", "header button")
        require(browser.js("document.querySelector('#add-label').textContent") == "Выдать доступ", "header button label")
        browser.click("#add")
        browser.wait("location.hash === '#clients' && document.querySelector('#client-modal')?.open === true", "new-client dialog opened on Clients")
        browser.healthy()
    finally:
        fixture.api(f"/api/nodes/{fixture.paused_id}/pause", "POST")


def check_english_grant_node_label(browser):
    """Render the shipped grant row in English without rewriting the operator's account name."""
    browser.js("localStorage.setItem('proxy-control.lang', 'en')")
    browser.dt.call("Page.navigate", {"url": f"{browser.fixture.base}/?i18n={secrets.token_hex(4)}#clients"})
    browser.wait("document.documentElement.lang === 'en' && !!document.querySelector('#view')", "English panel loaded")
    translated = browser.js("""(async () => {
        const { grantRowHtml } = await import('/static/js/grant.js');
        const list = document.createElement('ul');
        list.innerHTML = grantRowHtml({
          id: 'i18n-probe', protocol: 'naive', runtime_username: 'Имя клиента',
          node_id: 'local', desired_state: 'enabled', observed_state: 'enabled',
          secret_ref: null
        });
        document.body.append(list);
        await new Promise(resolve => setTimeout(resolve, 100));
        const label = list.querySelector('.grant-node [data-translate]')?.textContent;
        const account = list.querySelector('.grant-account > span')?.textContent;
        list.remove();
        return label === 'This server' && account === 'Имя клиента';
    })()""")
    require(translated is True, "local node label must translate without changing the account name")
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
            check_overview_attention(browser)
            for protocol in PROTOCOLS:
                check_remote_issuance(browser, protocol)
            check_english_grant_node_label(browser)
    print("PROTOCOL_DIALOG_SMOKE_OK: AWG+TrustTunnel; fresh nodes; capability selection; remote issuance; desktop/mobile rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
