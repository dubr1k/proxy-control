#!/usr/bin/env python3
"""The panel's screen in a real browser (v0.6, tier `ui`): every view driven over CDP in a
headless Chrome as the owner (and once as a viewer), through the real login form, the real
dialogs and the real confirmations — the way an operator uses it. Every claim is a DOM
state, a status code or a byte the browser received; every console error or uncaught
exception fails the run; no secret may appear in any frame that is captured.

    ui-acceptance.py --node-url https://panel.lab.test --password-file … --output lab-results/ui
                     [--views login,dashboard,users,naive,mieru,clients,versions,fleet,routing,admins,audit]
                     [--ca-file /etc/letsencrypt/lab-ca/ca.crt] [--stub] [--no-shots]
    ui-acceptance.py --api-only …   # no browser: the same views through the API the screen uses
                                    # (a production node: read, one throw-away user per protocol)

Runs on the lab host itself (Chrome, the node's loopback). Everything it creates carries the
run's own prefix and is deleted at the end; the runtime user lists must equal the initial ones.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import http.cookiejar
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VIEWS = ("login", "dashboard", "users", "naive", "mieru", "clients", "versions", "fleet", "routing", "admins", "audit")
# What must never be in a frame or a report (the fleet acceptance's shapes, kept in step).
SECRET_SHAPES = [
    re.compile(r"tg://proxy\?[^\s\"']*secret=", re.I),
    re.compile(r"https://t\.me/proxy\?[^\s\"']*secret=", re.I),
    re.compile(r"mierus?://[^\s\"']+@"),
    re.compile(r"https://[^\s\"'/@]+:[^\s\"'/@]+@"),
    re.compile(r"socks5://[^\s\"'/@]+:[^\s\"'/@]+@"),
    re.compile(r"\bpc_[0-9a-f]{8}_[A-Za-z0-9_-]{43}\b"),
    re.compile(r"\b(?:naive|mieru)-[0-9a-f]{8}:[A-Za-z0-9._~-]{16,}"),
    # a relay account inside a rendered intent (v0.7): a chain hop's uuid
    re.compile(r'"uuid":\s*"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"'),
]
PASSWORD_SHAPE = re.compile(r"\"password\"\s*:\s*\"[^\"]+\"")


def redact(text: str) -> str:
    for shape in SECRET_SHAPES:
        text = shape.sub("[REDACTED]", text)
    return PASSWORD_SHAPE.sub('"password": "[REDACTED]"', text)


# ---------------------------------------------------------------------------
# CDP over a stdlib websocket (the shape routing-shots.py proved on the lab host)
# ---------------------------------------------------------------------------


def _recv_exact(connection, size):
    buffer = bytearray()
    while len(buffer) < size:
        chunk = connection.recv(size - len(buffer))
        if not chunk:
            raise RuntimeError("websocket closed")
        buffer.extend(chunk)
    return bytes(buffer)


class CDP:
    def __init__(self, url: str):
        parts = urllib.parse.urlsplit(url)
        self.connection = socket.create_connection((parts.hostname, parts.port), timeout=60)
        key = base64.b64encode(os.urandom(16)).decode()
        self.connection.sendall((f"GET {parts.path} HTTP/1.1\r\nHost: {parts.netloc}\r\nUpgrade: websocket\r\n"
                                 f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                                 "Origin: http://localhost\r\n\r\n").encode())
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(self.connection.recv(4096))
        if not response.startswith(b"HTTP/1.1 101"):
            raise RuntimeError(f"websocket handshake refused: {response[:80]!r}")
        self.sequence = 1
        self.events: list[dict] = []

    def _send(self, payload: dict) -> None:
        data = json.dumps(payload).encode()
        mask = os.urandom(4)
        if len(data) < 126:
            header = bytes((0x81, 0x80 | len(data)))
        elif len(data) <= 0xFFFF:
            header = bytes((0x81, 0x80 | 126)) + struct.pack("!H", len(data))
        else:
            header = bytes((0x81, 0x80 | 127)) + struct.pack("!Q", len(data))
        self.connection.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def _recv(self) -> dict:
        first, second = _recv_exact(self.connection, 2)
        opcode, length = first & 0x0F, second & 0x7F
        if length == 126:
            length = struct.unpack("!H", _recv_exact(self.connection, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", _recv_exact(self.connection, 8))[0]
        payload = _recv_exact(self.connection, length)
        if opcode == 0x8:
            raise RuntimeError("websocket closed")
        if opcode != 0x1:
            return self._recv()
        return json.loads(payload)

    def call(self, method: str, params: dict | None = None) -> dict:
        identifier = self.sequence
        self.sequence += 1
        self._send({"id": identifier, "method": method, "params": params or {}})
        while True:
            message = self._recv()
            if message.get("id") == identifier:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})
            if "method" in message:
                self.events.append(message)

    def drain(self, seconds: float) -> None:
        self.connection.settimeout(seconds)
        try:
            while True:
                message = self._recv()
                if "method" in message:
                    self.events.append(message)
        except (socket.timeout, TimeoutError):
            pass
        finally:
            self.connection.settimeout(60)

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.connection.close()


class Browser:
    """One headless Chrome page: navigation, evaluation, waiting, clicking, typing, shots."""

    def __init__(self, work: Path, shots: Path | None):
        self.profile = work / "chrome-profile"
        shutil.rmtree(self.profile, ignore_errors=True)
        self.shots_dir = shots
        self.process = subprocess.Popen(
            ["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", "--ignore-certificate-errors",
             "--remote-allow-origins=*", "--remote-debugging-port=0", f"--user-data-dir={self.profile}",
             "--window-size=1440,1000", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        port = None
        for _ in range(600):
            try:
                port = int((self.profile / "DevToolsActivePort").read_text().splitlines()[0])
                break
            except (OSError, ValueError, IndexError):
                time.sleep(0.1)
        if not port:
            raise RuntimeError("chrome did not start")
        target = None
        for _ in range(100):
            targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5))
            target = next((t["webSocketDebuggerUrl"] for t in targets if t.get("type") == "page"), None)
            if target:
                break
            time.sleep(0.1)
        self.cdp = CDP(target)
        for domain in ("Runtime", "Log", "Page"):
            self.cdp.call(f"{domain}.enable")
        self.desktop()
        self.shots: list[dict] = []

    def close(self) -> None:
        self.cdp.close()
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()

    def desktop(self) -> None:
        self.cdp.call("Emulation.setDeviceMetricsOverride", {"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": False})

    def goto(self, url: str) -> None:
        self.cdp.call("Page.navigate", {"url": url})

    def js(self, expression: str, *, await_promise: bool = False):
        result = self.cdp.call("Runtime.evaluate", {"expression": expression, "returnByValue": True, "awaitPromise": await_promise})
        if result.get("exceptionDetails"):
            raise RuntimeError(json.dumps(result["exceptionDetails"])[:400])
        return result["result"].get("value")

    def wait(self, expression: str, seconds: float = 20) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if self.js(expression):
                    return True
            except RuntimeError:
                pass
            time.sleep(0.2)
        return False

    def click(self, selector: str) -> bool:
        return bool(self.js(f"(() => {{ const e = document.querySelector({json.dumps(selector)}); if (!e) return false; e.click(); return true; }})()"))

    def type(self, selector: str, value: str) -> bool:
        return bool(self.js(f"(() => {{ const i = document.querySelector({json.dumps(selector)}); if (!i) return false;"
                            f" i.value = {json.dumps(value)}; i.dispatchEvent(new Event('input', {{bubbles: true}}));"
                            f" i.dispatchEvent(new Event('change', {{bubbles: true}})); return true; }})()"))

    def select(self, selector: str, value: str) -> bool:
        return self.type(selector, value)

    def text(self, selector: str) -> str:
        return self.js(f"document.querySelector({json.dumps(selector)})?.textContent ?? ''") or ""

    def value(self, selector: str) -> str:
        return self.js(f"document.querySelector({json.dumps(selector)})?.value ?? ''") or ""

    def exists(self, selector: str) -> bool:
        return bool(self.js(f"!!document.querySelector({json.dumps(selector)})"))

    def dialog_open(self, selector: str) -> bool:
        return bool(self.js(f"document.querySelector({json.dumps(selector)})?.open === true"))

    def close_dialog(self, selector: str) -> None:
        self.js(f"document.querySelector({json.dumps(selector)})?.close(); true")

    def confirm(self, seconds: float = 10) -> bool:
        """The shared confirm dialog: wait for it, press its OK."""
        if not self.wait("document.querySelector('#confirm')?.open === true", seconds):
            return False
        self.click("#confirm-ok")
        return True

    def page_text(self) -> str:
        return self.js("document.body.innerText") or ""

    def shot(self, name: str, width: int = 1440) -> None:
        if self.shots_dir is None:
            return
        self.cdp.call("Emulation.setDeviceMetricsOverride", {"width": width, "height": 1000, "deviceScaleFactor": 1, "mobile": width < 600})
        time.sleep(0.5)
        height = self.js("Math.min(document.documentElement.scrollHeight, 2400)") or 1000
        self.cdp.call("Emulation.setDeviceMetricsOverride", {"width": width, "height": int(height), "deviceScaleFactor": 1, "mobile": width < 600})
        time.sleep(0.3)
        data = self.cdp.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})["data"]
        path = self.shots_dir / name
        path.write_bytes(base64.b64decode(data))
        self.shots.append({"name": name, "bytes": path.stat().st_size, "width": width, "text_scanned": True})
        self.desktop()

    def errors(self) -> tuple[list[str], list[str]]:
        self.cdp.drain(1.5)
        exceptions, console = [], []
        for event in self.cdp.events:
            if event["method"] == "Runtime.exceptionThrown":
                exceptions.append(redact(json.dumps(event["params"].get("exceptionDetails", {}))[:300]))
            elif event["method"] == "Log.entryAdded" and event["params"]["entry"].get("level") == "error":
                entry = event["params"]["entry"]
                console.append(redact(f"{entry.get('text', '')[:200]} @ {entry.get('url', '')[:160]}"))
            elif event["method"] == "Runtime.consoleAPICalled" and event["params"].get("type") == "error":
                console.append(redact(json.dumps(event["params"].get("args", []))[:300]))
        self.cdp.events.clear()
        return exceptions, console


# ---------------------------------------------------------------------------
# The panel's API, for setup, cross-checks and cleanup (the screen's own endpoints)
# ---------------------------------------------------------------------------


class Api:
    def __init__(self, base: str, ca_file: str | None):
        self.base = base.rstrip("/")
        # A lab CA when given; otherwise the system's trust store (a production node has a
        # public certificate) — never a disabled verification.
        context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                                  urllib.request.HTTPSHandler(context=context))
        self.bearer: str | None = None

    def csrf(self) -> str:
        return next((c.value for c in self.jar if c.name == "panel_csrf"), "")

    def request(self, path: str, method: str = "GET", payload=None, *, bearer: str | None = None) -> tuple[int, dict | list | str]:
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"}
        token = bearer or self.bearer
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif method != "GET":
            headers["X-CSRF-Token"] = self.csrf()
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=60) as response:
                body, status = response.read(), response.status
        except urllib.error.HTTPError as error:
            body, status = error.read(), error.code
        except urllib.error.URLError as error:  # nothing listens yet, or the socket dropped
            return 0, {"error": str(error.reason)}
        try:
            return status, json.loads(body) if body else {}
        except ValueError:
            return status, body[:200].decode(errors="replace")

    def json(self, path: str, method: str = "GET", payload=None):
        status, body = self.request(path, method, payload)
        if status >= 400:
            raise RuntimeError(f"{method} {path} -> {status} {redact(json.dumps(body))[:200]}")
        return body

    def login(self, username: str, password: str) -> None:
        self.request("/login")
        status, body = self.request("/api/auth/login", "POST", {"username": username, "password": password})
        if status not in (200, 204):
            raise RuntimeError(f"login as {username} refused: {status}")


# ---------------------------------------------------------------------------
# The acceptance
# ---------------------------------------------------------------------------


class Acceptance:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.run_id = secrets.token_hex(3)
        self.prefix = f"ui-{self.run_id}"
        self.output = Path(args.output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.report: dict = {"run_id": self.run_id, "checks": {}, "details": {}, "facts": {}, "durations": {}, "shots": [],
                             "console": [], "exceptions": [], "failed": []}
        self.password = Path(args.password_file).read_text().strip().splitlines()[-1].split("=")[-1].strip()
        self.api = Api(args.node_url, args.ca_file)
        self.browser: Browser | None = None
        self.work = Path(tempfile.mkdtemp(prefix="ui-acceptance-"))
        self.stub: subprocess.Popen | None = None
        self.initial_users: dict[str, list[str]] = {}
        self.created: dict[str, list[str]] = {"users": [], "naive": [], "mieru": [], "admins": [], "keys": [], "clients": []}
        self.viewer = (f"{self.prefix}-viewer", "viewer-" + secrets.token_urlsafe(12))

    # -- bookkeeping ------------------------------------------------------------

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.report["checks"][name] = bool(ok)
        if not ok:
            self.report["details"][name] = redact(str(detail))[:400]
            self.report["failed"].append(name)
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {redact(str(detail))[:200]}"), flush=True)
        return bool(ok)

    def frame_is_secret_free(self, name: str) -> None:
        text = self.browser.page_text() if self.browser else ""
        hits = [shape.pattern for shape in SECRET_SHAPES if shape.search(text)]
        self.check(f"{name}.frame_secret_free", not hits, str(hits))

    def cells_do_not_overlap(self, name: str, row: str, cells: str, limit: int = 12) -> None:
        """No two visible cells of one row share pixels (a stale grid rule once squeezed the
        journal's `.audit-main` into a 150 px track over the «Детали и IP» disclosure).
        A one-pixel tolerance forgives borders; hidden cells (`display:none`) are ignored."""
        overlaps = self.browser.js(f"""(() => {{
          const out = [];
          for (const row of [...document.querySelectorAll({json.dumps(row)})].slice(0, {limit})) {{
            const rects = [...row.querySelectorAll({json.dumps(cells)})]
              .map(e => [e.tagName.toLowerCase() + (e.className ? '.' + String(e.className).split(' ')[0] : ''), e.getBoundingClientRect()])
              .filter(([, r]) => r.width > 0 && r.height > 0);
            for (let i = 0; i < rects.length; i++) for (let j = i + 1; j < rects.length; j++) {{
              const [a, ra] = rects[i], [b, rb] = rects[j];
              if (ra.left < rb.right - 1 && rb.left < ra.right - 1 && ra.top < rb.bottom - 1 && rb.top < ra.bottom - 1) out.push(a + ' × ' + b);
            }}
          }}
          return [...new Set(out)];
        }})()""")
        self.check(name, not overlaps, str(overlaps))

    def users(self) -> dict[str, list[str]]:
        return {protocol: sorted(u["username"] for u in self.api.json(path)["items"])
                for protocol, path in (("mtproxy", "/api/users"), ("naive", "/api/naive/users"), ("mieru", "/api/mieru/users"))}

    # -- browser helpers -------------------------------------------------------------

    def login(self, username: str, password: str, base: str | None = None) -> bool:
        b = self.browser
        b.goto(f"{base or self.args.node_url}/login")
        if not b.wait("!!document.querySelector('#login input[name=username]')"):
            return False
        # The module binds the submit handler after paint: its first visible effect is the transport line.
        b.wait("(document.querySelector('#transport-state')?.textContent || '').includes('соединение') && "
               "!(document.querySelector('#transport-state')?.textContent || '').includes('Проверка')", 30)
        b.js(f"(() => {{ const f = document.querySelector('#login'); f.querySelector('input[name=username]').value = {json.dumps(username)};"
             f" f.querySelector('input[name=password]').value = {json.dumps(password)}; f.requestSubmit(); return true; }})()")
        return b.wait("location.pathname === '/' && !!document.querySelector('#view') && "
                      f"document.querySelector('#profile-name')?.textContent === {json.dumps(username)}", 30)

    def goto_view(self, view: str, ready: str = "!!document.querySelector('#view')", seconds: float = 20) -> bool:
        self.browser.js(f"document.querySelector('.nav-item[data-view={view}]').click(); true")
        return self.browser.wait(ready, seconds)

    def open_add(self, dialog: str) -> bool:
        self.browser.click("#add")
        return self.browser.wait(f"document.querySelector('{dialog}')?.open === true")

    def row_action(self, attribute: str, action: str, username: str) -> bool:
        return self.browser.click(f"[{attribute}={json.dumps(action)}][data-user={json.dumps(username)}]")

    # -- views --------------------------------------------------------------------------

    def view_login(self) -> None:
        b = self.browser
        b.goto(f"{self.args.node_url}/login")
        self.check("login.form_rendered", b.wait("!!document.querySelector('#login input[name=username]')"))
        b.wait("(document.querySelector('#transport-state')?.textContent || '').includes('соединение')", 30)
        b.js("(() => { const f = document.querySelector('#login'); f.querySelector('input[name=username]').value = 'owner';"
             " f.querySelector('input[name=password]').value = 'definitely-not-the-password'; f.requestSubmit(); return true; })()")
        self.check("login.wrong_password_refused", b.wait("(document.querySelector('#error')?.textContent || '').length > 0 && location.pathname === '/login' && !!document.querySelector('#login input[name=username]')", 15))
        error = b.text("#error")
        self.check("login.refusal_is_the_servers_word_not_a_reload", "Сессия завершена" not in error and error.strip() != "", error)
        self.check("login.right_password_lands_on_overview", self.login("owner", self.password))
        self.check("login.session_cookie_is_httponly", "panel_session" not in (b.js("document.cookie") or ""))
        b.shot("login-overview.png")
        b.click("#logout")
        self.check("login.logout_returns_to_form", b.wait("location.pathname === '/login' && !!document.querySelector('#login')", 15))
        status, _ = self.api.request("/api/auth/me")
        self.check("login.relogin_works", self.login("owner", self.password))

    def view_dashboard(self) -> None:
        b = self.browser
        self.check("dashboard.rendered", self.goto_view("dashboard", "!!document.querySelector('.host-card') && document.querySelectorAll('.protocol-card').length >= 3"))
        text = b.page_text()
        self.check("dashboard.host_card_has_resources_or_reason", "Ресурсы сервера" in text and ("CPU" in text or "Недоступны" in text))
        self.check("dashboard.protocol_cards_rendered", all(name in text for name in ("MTProxy", "Mieru", "NaiveProxy")))
        # The profile button's chevron opens a real menu (v0.6 finding): the account, its screens, sign-out.
        b.click("#profile-button")
        self.check("dashboard.profile_menu_opens_and_closes",
                   b.wait("(() => { const m = document.querySelector('#profile-menu'); return m && !m.hidden && m.textContent.includes('Выйти') && document.querySelector('#profile-button').getAttribute('aria-expanded') === 'true'; })()", 5)
                   and b.js("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape', bubbles: true})); document.querySelector('#profile-menu').hidden === true"))
        counts = {k: b.text(f"#{k}-count").strip() for k in ("users", "naive", "mieru")}
        api = {"users": len(self.api.json("/api/users")["items"]), "naive": len(self.api.json("/api/naive/users")["items"]),
               "mieru": len(self.api.json("/api/mieru/users")["items"])}
        self.check("dashboard.sidebar_counters_match_api", all(counts[k] == str(api[k]) for k in counts), f"{counts} vs {api}")
        self.frame_is_secret_free("dashboard")
        b.shot("dashboard.png")

    def view_users(self) -> None:
        b = self.browser
        name = f"{self.prefix}-tg"
        self.check("users.rendered", self.goto_view("users", "!!document.querySelector('#user-list') && !!document.querySelector('#user-search')"))
        self.check("users.create_dialog_opens", self.open_add("#user-modal"))
        self.check("users.create_dialog_offers_node", b.wait("!!document.querySelector('#user-node option[value=local]')", 5))
        b.type("#new-user", name)
        self.check("users.create_button_enabled_after_input", b.wait("!document.querySelector('#create-user').disabled"))
        b.click("#create-user")
        self.check("users.create_reveals_link_and_qr", b.wait("document.querySelector('#access-modal')?.open === true && "
                   "/^(tg:\\/\\/proxy|https:\\/\\/t\\.me\\/proxy)/.test(document.querySelector('#access-link')?.value || '') && "
                   "!!document.querySelector('#qr-image')?.getAttribute('src')", 30))
        first_link = b.value("#access-link")
        self.created["users"].append(name)
        b.close_dialog("#access-modal")
        self.check("users.reveal_cleared_on_close", b.wait("(document.querySelector('#access-link')?.value || '') === ''"))
        self.check("users.row_listed_without_reload", b.wait(f"!!document.querySelector('[data-user-action=limits][data-user={json.dumps(name)}]')", 20))
        b.type("#user-search", name)
        self.check("users.search_filters_rows", b.wait("document.querySelectorAll('#user-list .data-row').length === 1"))
        b.type("#user-search", "")
        self.row_action("data-user-action", "limits", name)
        self.check("users.limits_dialog_opens", b.wait("document.querySelector('#limits-modal')?.open === true"))
        b.type("#limit-quota", "1")
        b.type("#limit-connections", "3")
        b.click("#save-limits")
        self.check("users.limits_saved", b.wait("document.querySelector('#limits-modal')?.open !== true", 20))
        stored = next(u for u in self.api.json("/api/users")["items"] if u["username"] == name)
        self.check("users.limits_reach_the_api", stored.get("data_quota_bytes") == 1_073_741_824 and stored.get("max_tcp_conns") == 3, json.dumps({k: stored.get(k) for k in ("data_quota_bytes", "max_tcp_conns")}))
        b.wait(f"!!document.querySelector('[data-user-action=disable][data-user={json.dumps(name)}]')", 20)
        self.row_action("data-user-action", "disable", name)
        self.check("users.disable_asks_and_blocks", b.confirm() and b.wait(f"!!document.querySelector('[data-user-action=enable][data-user={json.dumps(name)}]')", 20))
        self.row_action("data-user-action", "enable", name)
        self.check("users.enable_restores", b.confirm() and b.wait(f"!!document.querySelector('[data-user-action=disable][data-user={json.dumps(name)}]')", 20))
        self.row_action("data-user-action", "rotate", name)
        self.check("users.rotate_reveals_a_new_link", b.confirm() and b.wait("document.querySelector('#access-modal')?.open === true && "
                   f"(document.querySelector('#access-link')?.value || '').length > 0 && document.querySelector('#access-link').value !== {json.dumps(first_link)}", 30))
        b.close_dialog("#access-modal")
        b.wait(f"!!document.querySelector('[data-user-action=share][data-user={json.dumps(name)}]')", 20)
        self.row_action("data-user-action", "share", name)
        self.check("users.share_reopens_the_link", b.wait("document.querySelector('#access-modal')?.open === true && (document.querySelector('#access-link')?.value || '').startsWith('tg://') || (document.querySelector('#access-link')?.value || '').startsWith('https://t.me/')", 20))
        b.close_dialog("#access-modal")
        listing = json.dumps(self.api.json("/api/users"))
        self.check("users.list_carries_no_secret", "secret=" not in listing and "tg://" not in listing)
        b.shot("users.png")
        self.frame_is_secret_free("users")
        b.wait(f"!!document.querySelector('[data-user-action=delete][data-user={json.dumps(name)}]')", 20)
        self.row_action("data-user-action", "delete", name)
        self.check("users.delete_asks_and_removes_row", b.confirm() and b.wait(f"!document.querySelector('[data-user={json.dumps(name)}]')", 20))
        if name not in [u["username"] for u in self.api.json("/api/users")["items"]]:
            self.created["users"].remove(name)

    def view_naive(self) -> None:
        b = self.browser
        name = f"{self.prefix}-nv"
        self.check("naive.rendered", self.goto_view("naive", "!!document.querySelector('#naive-list')"))
        self.check("naive.create_dialog_opens", self.open_add("#naive-modal"))
        self.check("naive.create_dialog_offers_node", b.wait("!!document.querySelector('#naive-node option[value=local]')", 5))
        b.type("#new-naive-user", name)
        b.type("#new-naive-quota", "100")
        self.check("naive.create_button_enabled", b.wait("!document.querySelector('#create-naive').disabled"))
        b.click("#create-naive")
        self.check("naive.create_reveals_client_tabs", b.wait("document.querySelector('#naive-access-modal')?.open === true && "
                   "document.querySelectorAll('#naive-client-tabs button[data-client]').length >= 2 && "
                   "(document.querySelector('#naive-payload')?.value || '').length > 0", 40))
        self.created["naive"].append(name)
        tabs = b.js("[...document.querySelectorAll('#naive-client-tabs button[data-client]')].map(b => b.dataset.client)") or []
        self.check("naive.reveal_offers_native_karing_nekobox", {"native", "karing", "nekobox"} <= set(tabs), str(tabs))
        native_payload = b.value("#naive-payload")
        b.click("#naive-client-tabs button[data-client=karing]")
        self.check("naive.karing_tab_switches_payload", b.wait(f"(document.querySelector('#naive-payload')?.value || '') !== {json.dumps(native_payload)} && (document.querySelector('#naive-payload')?.value || '').length > 0", 10))
        b.close_dialog("#naive-access-modal")
        self.check("naive.row_listed_with_quota", b.wait(f"!!document.querySelector('[data-naive-name={json.dumps(name)}]') && (document.querySelector('[data-naive-name={json.dumps(name)}]')?.textContent || '').includes('квота')", 20))
        self.row_action("data-naive-action", "quota", name)
        self.check("naive.quota_dialog_opens_with_current", b.wait("document.querySelector('#naive-quota-modal')?.open === true && document.querySelector('#naive-quota-mib')?.value === '100'"))
        b.type("#naive-quota-mib", "200")
        b.click("#save-naive-quota")
        self.check("naive.quota_saved", b.wait("document.querySelector('#naive-quota-modal')?.open !== true", 20))
        stored = next(u for u in self.api.json("/api/naive/users")["items"] if u["username"] == name)
        self.check("naive.quota_reaches_the_api", str(stored.get("quota_bytes_decimal")) == str(200 * 1_048_576), str(stored.get("quota_bytes_decimal")))
        b.wait(f"!!document.querySelector('[data-naive-action=reset-traffic][data-user={json.dumps(name)}]')", 20)
        self.row_action("data-naive-action", "reset-traffic", name)
        self.check("naive.traffic_reset_confirmed", b.confirm() and b.wait(f"!!document.querySelector('[data-naive-action=disable][data-user={json.dumps(name)}]')", 20))
        self.row_action("data-naive-action", "disable", name)
        self.check("naive.disable_asks_and_marks", b.confirm() and b.wait(f"!!document.querySelector('[data-naive-action=enable][data-user={json.dumps(name)}]')", 30))
        self.row_action("data-naive-action", "enable", name)
        self.check("naive.enable_restores", b.confirm() and b.wait(f"!!document.querySelector('[data-naive-action=disable][data-user={json.dumps(name)}]')", 30))
        self.row_action("data-naive-action", "rotate", name)
        self.check("naive.rotate_reveals_again", b.confirm() and b.wait("document.querySelector('#naive-access-modal')?.open === true && (document.querySelector('#naive-payload')?.value || '').length > 0", 40))
        rotated = b.value("#naive-payload")
        self.check("naive.rotated_payload_differs", rotated != native_payload)
        b.close_dialog("#naive-access-modal")
        b.wait(f"!!document.querySelector('[data-naive-action=access][data-user={json.dumps(name)}]')", 20)
        self.row_action("data-naive-action", "access", name)
        self.check("naive.access_reopens_configuration", b.wait("document.querySelector('#naive-access-modal')?.open === true && (document.querySelector('#naive-payload')?.value || '').length > 0", 20))
        b.close_dialog("#naive-access-modal")
        listing = json.dumps(self.api.json("/api/naive/users"))
        self.check("naive.list_carries_no_secret", not any(s.search(listing) for s in SECRET_SHAPES) and "proxy_url" not in listing)
        b.shot("naive.png")
        self.frame_is_secret_free("naive")
        b.wait(f"!!document.querySelector('[data-naive-action=delete][data-user={json.dumps(name)}]')", 20)
        self.row_action("data-naive-action", "delete", name)
        self.check("naive.delete_asks_and_removes_row", b.confirm() and b.wait(f"!document.querySelector('[data-naive-name={json.dumps(name)}]')", 30))
        if name not in [u["username"] for u in self.api.json("/api/naive/users")["items"]]:
            self.created["naive"].remove(name)

    def view_mieru(self) -> None:
        b = self.browser
        name = f"{self.prefix}-mr"
        self.check("mieru.rendered", self.goto_view("mieru", "!!document.querySelector('.naive-overview') && (document.body.innerText || '').includes('revision')"))
        self.check("mieru.create_dialog_opens", self.open_add("#mieru-modal"))
        self.check("mieru.create_dialog_offers_node", b.wait("!!document.querySelector('#mieru-node option[value=local]')", 5))
        b.type("#new-mieru-user", name)
        b.type("#mieru-days", "30")
        b.type("#mieru-mib", "1024")
        self.check("mieru.create_button_enabled", b.wait("!document.querySelector('#create-mieru').disabled"))
        b.click("#create-mieru")
        self.check("mieru.create_reveals_client_tabs", b.wait("document.querySelector('#mieru-access-modal')?.open === true && "
                   "document.querySelectorAll('#mieru-client-tabs button[data-client]').length >= 2 && "
                   "(document.querySelector('#mieru-payload')?.value || '').length > 0", 60))
        self.created["mieru"].append(name)
        tabs = b.js("[...document.querySelectorAll('#mieru-client-tabs button[data-client]')].map(b => b.dataset.client)") or []
        self.check("mieru.reveal_offers_native_and_karing", {"native", "karing"} <= set(tabs), str(tabs))
        native_payload = b.value("#mieru-payload")
        self.check("mieru.native_payload_is_client_json", native_payload.lstrip().startswith("{") and "profiles" in native_payload, native_payload[:60])
        b.close_dialog("#mieru-access-modal")
        self.check("mieru.row_listed_with_quota", b.wait(f"[...document.querySelectorAll('.data-row')].some(r => r.textContent.includes({json.dumps(name)}) && r.textContent.includes('30'))", 30))
        self.row_action("data-mieru-action", "quotas", name)
        self.check("mieru.quota_dialog_opens_with_rows", b.wait("document.querySelector('#mieru-quota-modal')?.open === true && document.querySelectorAll('[data-mieru-quota-row]').length === 1"))
        b.type("[data-mieru-quota-days]", "7")
        b.type("[data-mieru-quota-mib]", "512")
        b.click("#save-mieru-quota")
        self.check("mieru.quota_saved", b.wait("document.querySelector('#mieru-quota-modal')?.open !== true", 30))
        stored = next(u for u in self.api.json("/api/mieru/users")["items"] if u["username"] == name)
        self.check("mieru.quota_reaches_the_api", stored.get("quotas") == [{"days": 7, "megabytes": 512}], json.dumps(stored.get("quotas")))
        b.wait(f"!!document.querySelector('[data-mieru-action=disable][data-user={json.dumps(name)}]')", 30)
        self.row_action("data-mieru-action", "disable", name)
        self.check("mieru.disable_asks_and_marks", b.confirm() and b.wait(f"!!document.querySelector('[data-mieru-action=enable][data-user={json.dumps(name)}]')", 60))
        self.row_action("data-mieru-action", "enable", name)
        self.check("mieru.enable_restores", b.confirm() and b.wait(f"!!document.querySelector('[data-mieru-action=disable][data-user={json.dumps(name)}]')", 60))
        self.row_action("data-mieru-action", "rotate", name)
        self.check("mieru.rotate_reveals_again", b.confirm() and b.wait("document.querySelector('#mieru-access-modal')?.open === true && (document.querySelector('#mieru-payload')?.value || '').length > 0", 60))
        self.check("mieru.rotated_payload_differs", b.value("#mieru-payload") != native_payload)
        b.close_dialog("#mieru-access-modal")
        listing = json.dumps(self.api.json("/api/mieru/users"))
        self.check("mieru.list_carries_no_secret", not any(s.search(listing) for s in SECRET_SHAPES) and "share_url" not in listing)
        b.shot("mieru.png")
        self.frame_is_secret_free("mieru")
        b.wait(f"!!document.querySelector('[data-mieru-action=delete][data-user={json.dumps(name)}]')", 30)
        self.row_action("data-mieru-action", "delete", name)
        self.check("mieru.delete_asks_and_removes_row", b.confirm() and b.wait(f"![...document.querySelectorAll('.data-row')].some(r => r.textContent.includes({json.dumps(name)}))", 60))
        if name not in [u["username"] for u in self.api.json("/api/mieru/users")["items"]]:
            self.created["mieru"].remove(name)

    def view_clients(self) -> None:
        b = self.browser
        client_name = f"{self.prefix}-client"
        grant_user = f"{self.prefix}-cl"
        imported_user = f"{self.prefix}-imp"
        self.check("clients.rendered", self.goto_view("clients", "!!document.querySelector('.client-list') && !!document.querySelector('[data-client-action=import]')"))
        self.check("clients.create_dialog_opens", self.open_add("#client-modal"))
        # One dialog: the node the grants will live on and the protocols to issue at once;
        # the account name appears only once a protocol is ticked, proposed from the name.
        self.check("clients.create_dialog_offers_node_and_protocols", b.wait("!!document.querySelector('#client-node option[value=local]') && document.querySelectorAll('#client-form .grant-protocol input').length === 3 && document.querySelector('#client-username-row')?.hidden === true", 5))
        b.type("#client-name", client_name)
        b.js("(() => { const i = document.querySelector('#client-form .grant-protocol input[value=naive]'); i.checked = true; i.dispatchEvent(new Event('change', {bubbles: true})); return true; })()")
        self.check("clients.protocol_tick_proposes_username", b.wait(f"document.querySelector('#client-username-row')?.hidden === false && document.querySelector('#client-username')?.value === {json.dumps(client_name.lower())}", 5), b.value("#client-username"))
        b.js("(() => { const i = document.querySelector('#client-form .grant-protocol input[value=naive]'); i.checked = false; i.dispatchEvent(new Event('change', {bubbles: true})); return true; })()")
        self.check("clients.untick_hides_username", b.wait("document.querySelector('#client-username-row')?.hidden === true", 5))
        b.click("#create-client")
        self.check("clients.card_listed", b.wait(f"[...document.querySelectorAll('[data-client-id]')].some(c => c.querySelector('.client-identity b')?.textContent === {json.dumps(client_name)})", 20))
        client = next(e for e in self.api.json("/api/clients")["items"] if e["client"]["display_name"] == client_name)
        client_id = client["client"]["id"]
        self.created["clients"].append(client_id)
        card = f"[data-client-id={json.dumps(client_id)}]"
        b.click(f"{card} [data-client-action=grant]")
        self.check("clients.grant_dialog_opens", b.wait("document.querySelector('#grant-modal')?.open === true"))
        b.type("#grant-username", grant_user)
        b.js("[...document.querySelectorAll('#grant-form .grant-protocol input')].forEach(i => { i.checked = true; }); true")
        b.click("#create-grants")
        self.check("clients.grants_issue_and_bundle_reveals", b.wait("document.querySelector('#bundle-modal')?.open === true && (document.querySelector('#bundle-body')?.textContent || '').length > 0", 90),
                   f"grant-error: {b.text('#grant-error')!r}")
        bundle = b.text("#bundle-body")
        self.check("clients.bundle_names_three_protocols", all(word in bundle for word in ("mtproxy", "naive", "mieru")), bundle[:200])
        b.close_dialog("#bundle-modal")
        self.check("clients.three_grant_chips", b.wait(f"document.querySelectorAll('{card} .grant-chip[data-grant-id]').length === 3", 30))
        for protocol in ("mtproxy", "naive", "mieru"):
            self.created[{"mtproxy": "users", "naive": "naive", "mieru": "mieru"}[protocol]].append(grant_user)
        chip = f"{card} .grant-chip[data-grant-protocol=naive]"
        b.click(f"{chip} [data-client-action=grant-disable]")
        self.check("clients.grant_disable_marks_chip", b.wait(f"!!document.querySelector('{chip} [data-client-action=grant-enable]')", 30))
        b.click(f"{chip} [data-client-action=grant-enable]")
        self.check("clients.grant_enable_restores", b.wait(f"!!document.querySelector('{chip} [data-client-action=grant-disable]')", 30))
        b.click(f"{chip} [data-client-action=grant-rotate]")
        self.check("clients.grant_rotate_asks", b.confirm() and b.wait(f"!!document.querySelector('{chip} [data-client-action=grant-rotate]')", 30))
        # The subscription: the URL shown once, rotated, revoked — each state proven at the public endpoint.
        b.click(f"{card} [data-client-action=subscription]")
        self.check("clients.subscription_dialog_opens", b.wait("document.querySelector('#subscription-modal')?.open === true && !!document.querySelector('#subscription-actions button')", 20))
        configured = "не настроен" not in b.text("#subscription-status")
        self.check("clients.subscription_domain_configured", configured, b.text("#subscription-status")[:120])
        if configured:
            b.click("[data-subscription-action=create]")
            self.check("clients.subscription_url_revealed_once", b.wait("document.querySelector('#subscription-reveal')?.hidden === false && (document.querySelector('#subscription-url')?.value || '').startsWith('https://')", 20))
            first_url = b.value("#subscription-url")
            self.report["facts"]["subscription_host"] = urllib.parse.urlsplit(first_url).hostname
            self.check("clients.subscription_url_serves", self.fetch(first_url) == 200)
            b.click("[data-subscription-action=rotate]")
            self.check("clients.subscription_rotate_moves_url", b.confirm() and b.wait(f"(document.querySelector('#subscription-url')?.value || '').startsWith('https://') && document.querySelector('#subscription-url').value !== {json.dumps(first_url)}", 20))
            second_url = b.value("#subscription-url")
            self.check("clients.old_subscription_url_is_404", self.fetch(first_url) == 404)
            self.check("clients.new_subscription_url_serves", self.fetch(second_url) == 200)
            b.click("[data-subscription-action=revoke]")
            self.check("clients.subscription_revoke_offers_create_again", b.confirm() and b.wait("!!document.querySelector('[data-subscription-action=create]')", 20))
            self.check("clients.revoked_subscription_url_is_404", self.fetch(second_url) == 404)
        b.close_dialog("#subscription-modal")
        # Import: a runtime user the panel did not create is adopted without touching the manager.
        self.api.json("/api/naive/users", "POST", {"username": imported_user})
        self.created["naive"].append(imported_user)
        self.goto_view("clients", "!!document.querySelector('[data-client-action=import]')")
        b.click("[data-client-action=import]")
        self.check("clients.import_dialog_lists_runtime_users", b.wait(f"document.querySelector('#client-import-modal')?.open === true && !!document.querySelector('#client-import-rows tr[data-import-username={json.dumps(imported_user)}]')", 30))
        b.js(f"[...document.querySelectorAll('#client-import-rows tr')].forEach(r => {{ const p = r.querySelector('.import-pick'); if (p && !p.disabled) p.checked = r.dataset.importUsername === {json.dumps(imported_user)}; }}); true")
        b.click("#confirm-client-import")
        self.check("clients.import_creates_a_client_without_a_secret", b.wait(f"document.querySelector('#client-import-modal')?.open !== true && [...document.querySelectorAll('[data-client-id]')].some(c => c.querySelector('.client-identity b')?.textContent === {json.dumps(imported_user)} && !!c.querySelector('[data-client-action=adopt]'))", 30))
        imported = next(e for e in self.api.json("/api/clients")["items"] if e["client"]["display_name"] == imported_user)
        self.created["clients"].append(imported["client"]["id"])
        icard = f"[data-client-id={json.dumps(imported['client']['id'])}]"
        b.click(f"{icard} [data-client-action=adopt]")
        self.check("clients.adopt_captures_the_credential", b.wait(f"!document.querySelector('{icard} [data-client-action=adopt]') && !!document.querySelector('{icard} .grant-chip[data-grant-id]')", 30))
        b.click(f"{card} [data-client-action=suspend]")
        self.check("clients.suspend_marks_card", b.wait(f"!!document.querySelector('{card} [data-client-action=resume]')", 30))
        b.click(f"{card} [data-client-action=resume]")
        self.check("clients.resume_restores", b.wait(f"!!document.querySelector('{card} [data-client-action=suspend]')", 30))
        b.shot("clients.png")
        self.frame_is_secret_free("clients")
        # Every grant deleted through its chip, both clients archived: the runtime is as before.
        for target in (card, icard):
            for _ in range(4):
                if not b.exists(f"{target} .grant-chip [data-client-action=grant-delete]"):
                    break
                b.click(f"{target} .grant-chip [data-client-action=grant-delete]")
                b.confirm()
                b.wait("document.querySelector('#confirm')?.open !== true", 10)
                time.sleep(1.5)
                b.wait(f"!!document.querySelector('{target}')", 30)
        self.check("clients.grant_delete_empties_the_card", b.wait(f"document.querySelectorAll('{card} .grant-chip[data-grant-id]').length === 0 && document.querySelectorAll('{icard} .grant-chip[data-grant-id]').length === 0", 60))
        for target in (card, icard):
            b.wait(f"!!document.querySelector('{target} [data-client-action=archive]')", 30)
            b.click(f"{target} [data-client-action=archive]")
            b.confirm()
            b.wait(f"!document.querySelector('{target} [data-client-action=archive]')", 30)
        wanted = (client_id, imported["client"]["id"])
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            states = {e["client"]["id"]: e["client"]["state"] for e in self.api.json("/api/clients")["items"]}
            if all(states.get(i) == "archived" for i in wanted):
                break
            time.sleep(1)
        self.check("clients.archive_after_grants_gone", all(states.get(i) == "archived" for i in wanted),
                   json.dumps({i: states.get(i) for i in wanted}) + " toasts: " + str(b.js("[...document.querySelectorAll('#toast-region *')].map(t => t.textContent).slice(0, 3)")))
        for protocol, key in (("mtproxy", "users"), ("naive", "naive"), ("mieru", "mieru")):
            listed = [u["username"] for u in self.api.json({"users": "/api/users", "naive": "/api/naive/users", "mieru": "/api/mieru/users"}[key])["items"]]
            for name in list(self.created[key]):
                if name.startswith(self.prefix) and name not in listed:
                    self.created[key].remove(name)

    def fetch(self, url: str) -> int:
        argv = ["curl", "--silent", "--output", "/dev/null", "--write-out", "%{http_code}", "--max-time", "20"]
        if self.args.ca_file:
            argv += ["--cacert", self.args.ca_file]
        else:
            argv += ["--insecure"]
        try:
            return int(subprocess.run(argv + [url], capture_output=True, text=True, timeout=30).stdout.strip() or 0)
        except (subprocess.SubprocessError, ValueError):
            return 0

    def view_versions(self) -> None:
        b = self.browser
        self.check("versions.rendered", self.goto_view("versions", "!!document.querySelector('.version-card') || (document.body.innerText || '').includes('Агент обновлений недоступен')"))
        agent = self.api.json("/api/versions")
        if agent.get("enabled"):
            cards = b.js("[...document.querySelectorAll('.version-card h2')].map(h => h.textContent)") or []
            self.check("versions.components_listed", len(cards) >= 3 and "Текущая версия" in b.page_text(), str(cards))
            self.check("versions.update_needs_a_chosen_version", b.js("[...document.querySelectorAll('.version-update')].every(x => x.disabled)"))
        else:
            self.check("versions.agent_absence_is_honest", "Агент обновлений недоступен" in b.page_text())
        self.report["facts"]["version_agent"] = bool(agent.get("enabled"))
        self.frame_is_secret_free("versions")
        b.shot("versions.png")

    def view_fleet(self) -> None:
        b = self.browser
        self.check("fleet.rendered", self.goto_view("fleet", "!!document.querySelector('.local-node')"))
        card = b.text(".local-node")
        self.check("fleet.local_card_has_manager_health_and_routing_line", "Маршрутизация" in card and any(word in card for word in ("Telemt", "MTProxy", "NaiveProxy", "Mieru")), card[:200])
        self.check("fleet.link_dialog_opens", self.open_add("#link-modal") and b.exists("#link-url") and b.exists("#link-key"))
        b.close_dialog("#link-modal")
        self.frame_is_secret_free("fleet")
        b.shot("fleet.png")

    def add_rule(self, **fields) -> None:
        """v0.8: a rule is made in its modal — the fields by name (domains, geosites, cidrs,
        geoips, ports as text; protocols as a list; action, egress); the row count grows by one."""
        b = self.browser
        rows = int(b.js("document.querySelectorAll('.routing-rule').length") or 0)
        b.click("[data-routing-action=rule-add]")
        b.wait("document.querySelector('#rule-modal')?.open === true", 10)
        for key in ("domains", "geosites", "cidrs", "geoips", "ports"):
            if key in fields:
                b.type(f"#rule-{key}", fields[key])
        if "action" in fields:
            b.select("#rule-action", fields["action"])
            b.js("document.querySelector('#rule-egress-row').hidden = document.querySelector('#rule-action').value !== 'egress'; true")
        if "egress" in fields:
            b.select("#rule-egress", fields["egress"])
            self.report["facts"]["rule_modal_last_egress"] = {
                "wanted": fields["egress"], "value": b.value("#rule-egress"),
                "options": b.js("[...document.querySelectorAll('#rule-egress option')].map(o => o.value)")}
        if "protocols" in fields:
            b.js(f"[...document.querySelectorAll('[data-rule-protocol]')].forEach(i => {{ i.checked = {json.dumps(fields['protocols'])}.includes(i.value); }}); true")
        b.click("#rule-save")
        b.wait(f"document.querySelector('#rule-modal')?.open !== true && document.querySelectorAll('.routing-rule').length === {rows + 1}", 10)

    def view_routing(self) -> None:
        b = self.browser
        loaded = "!!document.querySelector('#routing-preview .status-pill') && !(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('загружается')"
        self.check("routing.rendered", self.goto_view("routing", f"!!document.querySelector('#routing-form') && !!document.querySelector('#routing-node') && {loaded}"))
        self.check("routing.naive_tab_active", b.js("document.querySelector('[data-routing-action=protocol].active')?.dataset.protocol") == "naive")
        targets = {i["protocol"]: i for i in self.api.json("/api/routing/targets")["items"] if i["node_id"] == "local"}
        router = bool((targets.get("naive") or {}).get("router"))
        self.report["facts"]["router_installed"] = router
        # v0.4: a block rule beside a WARP default is refused by Caddy, honestly, at the rule.
        b.select("#routing-form select[name=default_action]", "egress")
        self.add_rule(domains="example.com, *.example.com")
        self.check("routing.rule_row_added", b.wait("document.querySelectorAll('.routing-rule').length === 1"))
        self.check("routing.rule_row_shows_what_and_where", "example.com" in b.text(".routing-rule .routing-rule-what") and "блок" in b.text(".routing-rule .routing-rule-where"))
        self.check("routing.native_preview_refuses_block_beside_warp", b.wait("document.querySelector('#routing-preview .status-pill')?.textContent.includes('не применимо') && !!document.querySelector('.routing-reason')", 15))
        b.select("#routing-form select[name=default_action]", "direct")
        self.check("routing.native_preview_supports_direct_block", b.wait("document.querySelector('#routing-preview .status-pill')?.textContent.includes('поддерживается')", 15))
        b.click("#routing-save")
        self.check("routing.saved_as_draft", b.wait(f"(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('черновик') && !document.querySelector('[data-routing-action=apply]').disabled && {loaded}", 20))
        b.click("[data-routing-action=apply]")
        self.check("routing.apply_asks", b.confirm())
        self.check("routing.native_applied_badge", b.wait(f"(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('применено (rev') && {loaded}", 40))
        b.click("[data-routing-action=history]")
        self.check("routing.history_table", b.wait("!!document.querySelector('#routing-history table tbody tr')", 15))
        b.shot("routing-naive-native-applied.png")
        b.click("[data-routing-action=rollback]")
        self.check("routing.rollback_asks_and_badge", b.confirm() and b.wait(f"(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('откачено') && {loaded}", 60))
        b.click("[data-routing-action=delete]")
        self.check("routing.native_policy_deleted", b.confirm() and b.wait("(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('политика не задана')", 30))
        if router:
            self.routing_router(loaded)
        self.frame_is_secret_free("routing")
        b.shot("routing-mobile.png", width=390)

    def routing_router(self, loaded: str) -> None:
        b = self.browser
        line = b.text(".routing-router-line")
        self.check("routing.router_line_not_attached_with_version", "Xray-router: сервис не подключён" in line and "Xray" in line, line)
        b.click("[data-routing-action=attach]")
        self.check("routing.attach_asks", b.wait("document.querySelector('#confirm')?.open === true && (document.querySelector('#confirm')?.textContent || '').includes('Подключить NaiveProxy к Xray-router')"))
        b.click("#confirm-ok")
        self.check("routing.router_line_attached", b.wait(f"(document.querySelector('.routing-router-line')?.textContent || '').includes('сервис подключён') && !!document.querySelector('[data-routing-action=detach]') && {loaded}", 40))
        self.check("routing.backend_badge_router", b.text(".routing-backend") == "Xray-router")
        b.select("#routing-form select[name=default_action]", "egress")
        self.add_rule(geosites="category-ads-all")
        self.add_rule(ports="25")
        self.check("routing.router_preview_supports_geosite_and_port", b.wait("document.querySelector('#routing-preview .status-pill')?.textContent.includes('поддерживается') && !document.querySelector('.routing-reason')", 15))
        # v0.8: a quick setting is a marked rule at the top; the sniffed protocol is a selector the router takes.
        b.js("(() => { const i = document.querySelector('[data-routing-preset=torrent]'); i.checked = true; i.dispatchEvent(new Event('change', {bubbles: true})); return true; })()")
        self.check("routing.preset_adds_a_marked_rule_first", b.wait("document.querySelectorAll('.routing-rule').length === 3 && !!document.querySelector('.routing-rule[data-rule-index=\"0\"] .routing-preset-mark') && (document.querySelector('.routing-rule[data-rule-index=\"0\"] .routing-rule-what')?.textContent || '').includes('bittorrent')", 10))
        self.check("routing.router_preview_supports_protocol_selector", b.wait("document.querySelector('#routing-preview .status-pill')?.textContent.includes('поддерживается') && (document.querySelector('.routing-document pre')?.textContent || '').includes('bittorrent')", 15))
        b.js("(() => { const i = document.querySelector('[data-routing-preset=torrent]'); i.checked = false; i.dispatchEvent(new Event('change', {bubbles: true})); return true; })()")
        self.check("routing.preset_off_removes_its_rule", b.wait("document.querySelectorAll('.routing-rule').length === 2", 10))
        self.routing_exits_and_geodata(loaded)
        b.click("#routing-save")
        b.wait(f"(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('черновик') && !document.querySelector('[data-routing-action=apply]').disabled && {loaded}", 20)
        b.click("[data-routing-action=apply]")
        b.confirm()
        self.check("routing.router_policy_applied_badge", b.wait(f"(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('применено (rev') && {loaded}", 60))
        b.shot("routing-naive-router-applied.png")
        self.routing_lanes(loaded)
        self.goto_view("fleet", "!!document.querySelector('.local-node')")
        self.check("routing.node_card_names_the_router", b.wait("(document.querySelector('.local-node')?.textContent || '').includes('[Xray-router]')", 20))
        self.goto_view("routing", f"!!document.querySelector('#routing-form') && {loaded}")
        b.wait(f"(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('применено') && !document.querySelector('[data-routing-action=rollback]').disabled && {loaded}", 30)
        b.click("[data-routing-action=rollback]")
        self.check("routing.router_rollback_badge", b.confirm() and b.wait(f"(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('откачено') && {loaded}", 60))
        b.click("[data-routing-action=detach]")
        self.check("routing.detach_asks", b.wait("document.querySelector('#confirm')?.open === true && (document.querySelector('#confirm')?.textContent || '').includes('Отключить NaiveProxy от Xray-router')"))
        b.click("#confirm-ok")
        self.check("routing.router_line_detached", b.wait(f"(document.querySelector('.routing-router-line')?.textContent || '').includes('сервис не подключён') && !!document.querySelector('[data-routing-action=attach]') && {loaded}", 40))
        b.click("[data-routing-action=delete]")
        self.check("routing.policy_deleted_right_after_detach", b.confirm() and b.wait("(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('политика не задана')", 30))

    def routing_exits_and_geodata(self, loaded: str) -> None:
        """v0.8 on the attached service: a custom exit made from the screen, tested on the
        router, offered in «Куда», refused for deletion while a rule uses it; the geodata block
        with its source dialog — never a credential in a frame."""
        b = self.browser
        self.check("routing.geodata_block", b.wait("!!document.querySelector('#routing-geodata') && (document.querySelector('#routing-geodata')?.textContent || '').includes('geosite')", 15))
        b.click("[data-routing-action=geodata-settings]")
        self.check("routing.geodata_dialog_opens", b.wait("document.querySelector('#geodata-modal')?.open === true && !!document.querySelector('#geodata-source option[value=loyalsoldier]')", 10))
        b.close_dialog("#geodata-modal")
        b.click("[data-routing-action=exit-add]")
        self.check("routing.exit_dialog_opens", b.wait("document.querySelector('#exit-modal')?.open === true", 10))
        b.type("#exit-name", "lab socks")
        b.select("#exit-protocol", "socks")
        b.js("document.querySelector('#exit-protocol').dispatchEvent(new Event('change', {bubbles: true})); true")
        b.type("#exit-address", "127.0.0.1")
        b.type("#exit-port", "45000")
        b.click("#exit-save")
        self.check("routing.exit_listed", b.wait("document.querySelector('#exit-modal')?.open !== true && [...document.querySelectorAll('#routing-custom-exits tbody tr')].some(r => r.textContent.includes('lab socks'))", 30), b.text("#exit-error"))
        exit_id = b.js("[...document.querySelectorAll('#routing-custom-exits tbody tr')].find(r => r.textContent.includes('lab socks'))?.dataset.exitId")
        self.check("routing.exit_has_id", bool(exit_id))
        b.click(f"[data-routing-action=exit-test][data-exit-id={json.dumps(exit_id)}]")
        self.check("routing.exit_test_answers", b.wait(f"!!document.querySelector('#routing-custom-exits tr[data-exit-id={json.dumps(exit_id)}] td:nth-child(4)') && !(document.querySelector('#routing-custom-exits tr[data-exit-id={json.dumps(exit_id)}] td:nth-child(4)')?.textContent || '').includes('не проверялся')", 40),
                   b.text(f"#routing-custom-exits tr[data-exit-id={json.dumps(exit_id)}]"))
        self.report["facts"]["exit_test"] = b.text(f"#routing-custom-exits tr[data-exit-id={json.dumps(exit_id)}] td:nth-child(4)")
        # The probe's result is painted by the screen's first render; the policy load that
        # follows it rerenders the table — a rule added in between would be lost.
        b.wait(loaded, 30)
        self.add_rule(domains="ifconfig.co", action="egress", egress=f"exit:{exit_id}")
        self.check("routing.rule_leaves_through_the_exit", b.wait("(document.querySelector('.routing-rule:last-child .routing-rule-where')?.textContent || '').includes('lab socks')", 10),
                   json.dumps({"where": b.js("[...document.querySelectorAll('.routing-rule .routing-rule-where')].map(c => c.textContent)"),
                               "modal": self.report["facts"].get("rule_modal_last_egress")}, ensure_ascii=False)[:600])
        self.check("routing.router_preview_supports_custom_exit", b.wait("document.querySelector('#routing-preview .status-pill')?.textContent.includes('поддерживается') && (document.querySelector('.routing-document pre')?.textContent || '').includes('\"exits\"')", 20),
                   (b.js("document.querySelector('#routing-preview')?.innerText") or "")[:300])
        b.click("#routing-save")
        b.wait(f"(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('черновик') && {loaded}", 20)
        status, refused = self.api.request(f"/api/routing/exits/{exit_id}/delete", "POST")
        self.check("routing.exit_in_use_refuses_delete", status == 409 and refused.get("code") == "exit_in_use", f"{status} {str(refused)[:200]}")
        self.frame_is_secret_free("routing-exits")
        # The rule goes, then the exit — through the API, so the cleanup never depends on the
        # screen's timing; the screen is then reopened (another view first: a fresh state,
        # a fresh revision) and must show neither.
        rows = int(b.js("document.querySelectorAll('.routing-rule').length") or 0)
        policy = self.api.json("/api/routing/policies/local/naive")
        kept = [{k: v for k, v in rule.items() if k != "position"} for rule in policy.get("rules", []) if rule.get("egress") != f"exit:{exit_id}"]
        if len(kept) != len(policy.get("rules", [])):
            policy = self.api.json("/api/routing/policies/local/naive", "PUT",
                                   {"backend": policy["backend"], "default_action": policy["default_action"], "default_egress": policy.get("default_egress"),
                                    "fallback": policy["fallback"], "rules": kept, "expected_revision": policy["revision"]})
        self.check("routing.saved_policy_no_longer_names_the_exit", not any(r.get("egress") == f"exit:{exit_id}" for r in policy.get("rules", [])))
        self.api.json(f"/api/routing/exits/{exit_id}/delete", "POST")
        self.goto_view("dashboard", "!!document.querySelector('#view') && !document.querySelector('#routing-form')")
        self.goto_view("routing", f"!!document.querySelector('#routing-form') && {loaded}")
        self.check("routing.rule_with_the_exit_gone_from_the_table", b.wait(f"document.querySelectorAll('.routing-rule').length === {rows - 1} && ![...document.querySelectorAll('.routing-rule-where')].some(c => c.textContent.includes('lab socks'))", 20))
        self.check("routing.exit_deleted", b.wait("![...document.querySelectorAll('#routing-custom-exits tbody tr')].some(r => r.textContent.includes('lab socks'))", 20))

    def routing_lanes(self, loaded: str) -> None:
        """Lanes and chains (v0.7) on the attached NaiveProxy: the node's exits as chips, a
        client's own lane created from the screen (tab, draft, apply), «Куда пойдёт…», the
        lane's flag on «Клиенты», and the way back — never a lane key in a frame."""
        b = self.browser
        chips = b.js("[...document.querySelectorAll('#routing-exits .routing-exit-chip')].map(c => c.dataset.exit)") or []
        self.check("routing.exits_chips", {"direct", "warp", "block"} <= set(chips), str(chips))
        self.report["facts"]["routing_exits"] = chips
        client_name, grant_user = f"{self.prefix}-lane", f"{self.prefix}-lane"
        client_id = self.api.json("/api/clients", "POST", {"display_name": client_name})["id"]
        self.created["clients"].append(client_id)
        self.api.json(f"/api/clients/{client_id}/grants", "POST",
                      {"grants": [{"protocol": "naive", "node_id": "local", "runtime_username": grant_user, "options": {}}]})
        self.created["naive"].append(grant_user)
        grant = next((g for g in self.api.json(f"/api/clients/{client_id}")["grants"] if g["protocol"] == "naive"), None)
        self.check("routing.lane_grant_ready", grant is not None and grant["observed_state"] == "enabled", str(grant and grant["observed_state"]))
        lane = f"grant:{grant['id']}"
        self.goto_view("routing", f"!!document.querySelector('#routing-form') && {loaded}")
        b.click("[data-routing-action=lane-add]")
        self.check("routing.lane_dialog_offers_the_grant", b.wait(f"document.querySelector('#choose')?.open === true && [...document.querySelectorAll('#choose-select option')].some(o => o.value === {json.dumps(grant['id'])})", 20))
        b.select("#choose-select", grant["id"])
        b.click("#choose-ok")
        self.check("routing.lane_tab_appears_active", b.wait(f"document.querySelector('[data-routing-action=lane].active')?.dataset.lane === {json.dumps(lane)} && !!document.querySelector('.routing-lane-badge') && {loaded}", 40))
        self.check("routing.lane_policy_is_a_draft", "черновик" in b.text(".routing-head .status-pill"), b.text(".routing-head .status-pill"))
        # The lane's own rules: everything through WARP by default, ads blocked — applied as one
        # intent with the service. The draft came as a copy of the service's policy (rules included),
        # so the new rule is the last row.
        b.select("#routing-form select[name=default_action]", "egress")
        self.add_rule(geosites="category-ads-all")
        self.check("routing.lane_preview_folds_the_service", b.wait("document.querySelector('#routing-preview .status-pill')?.textContent.includes('поддерживается') && (document.querySelector('.routing-document pre')?.textContent || '').includes('\"schema\": 2')", 20),
                   (b.js("document.querySelector('#routing-preview')?.innerText") or "")[:300])
        b.click("#routing-save")
        b.wait(f"(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('черновик') && !document.querySelector('[data-routing-action=apply]').disabled && {loaded}", 20)
        b.click("[data-routing-action=apply]")
        b.confirm()
        self.check("routing.lane_policy_applied", b.wait(f"(document.querySelector('.routing-head .status-pill')?.textContent || '').includes('применено (rev') && {loaded}", 60),
                   b.text(".routing-head .status-pill") + " | " + b.text("#routing-preview")[:200])
        b.type("#routing-explain input[name=host]", "example.org")
        b.click("#routing-explain button[type=submit]")
        self.check("routing.explain_names_the_lane_and_the_exit", b.wait(f"((document.querySelector('#routing-explain-answer')?.textContent) || '').includes({json.dumps('полоса ' + lane)}) && (document.querySelector('#routing-explain-answer')?.textContent || '').includes('WARP')", 20), b.text("#routing-explain-answer"))
        b.shot("routing-lane-applied.png")
        # «Клиенты»: the grant says it has its own lane; the toggle brings it back to the service.
        self.goto_view("clients", "!!document.querySelector('.client-list')")
        chip = f"[data-client-id={json.dumps(client_id)}] .grant-chip[data-grant-protocol=naive]"
        self.check("clients.lane_flag_on_the_chip", b.wait(f"document.querySelector('{chip} .grant-lane')?.dataset.lane === 'own'", 20))
        b.click(f"{chip} [data-client-action=grant-lane]")
        self.check("clients.lane_toggle_asks", b.wait("document.querySelector('#confirm')?.open === true && (document.querySelector('#confirm')?.textContent || '').includes('Вернуть к маршруту сервиса')"))
        b.click("#confirm-ok")
        self.check("clients.lane_toggle_returns_to_service", b.wait(f"document.querySelector('{chip} .grant-lane')?.dataset.lane === 'service'", 40))
        targets = {i["protocol"]: i for i in self.api.json("/api/routing/targets")["items"] if i["node_id"] == "local"}
        self.check("routing.lane_gone_from_targets", not [item for item in targets["naive"]["lanes"] if item["lane"] == lane], str(targets["naive"]["lanes"]))
        self.goto_view("routing", f"!!document.querySelector('#routing-form') && {loaded}")
        self.frame_is_secret_free("routing-lanes")

    def view_admins(self) -> None:
        b = self.browser
        admin_name, admin_password = self.viewer
        key_name = f"{self.prefix}-monitor"
        self.check("admins.rendered", self.goto_view("admins", "!!document.querySelector('#api-keys') && document.querySelectorAll('.admin-grid.data-row').length >= 1 && !!document.querySelector('[data-key-action=create]')", 30))
        self.check("admins.create_dialog_opens", self.open_add("#admin-modal"))
        b.type("#admin-user", admin_name)
        b.type("#admin-password", admin_password)
        b.select("#admin-role", "viewer")
        b.click("#save-admin")
        self.check("admins.viewer_created_and_listed", b.wait(f"document.querySelector('#admin-modal')?.open !== true && [...document.querySelectorAll('.admin-grid.data-row')].some(r => r.textContent.includes({json.dumps(admin_name)}))", 20))
        self.created["admins"].append(admin_name)
        admin = next(a for a in self.api.json("/api/admins")["items"] if a["username"] == admin_name)
        b.click(f"[data-management-action=toggle-admin][data-admin-id=\"{admin['id']}\"]")
        self.check("admins.toggle_asks_and_disables", b.confirm() and b.wait(f"(document.querySelector('[data-management-action=toggle-admin][data-admin-id=\"{admin['id']}\"]')?.textContent || '').includes('Включить')", 20))
        b.click(f"[data-management-action=toggle-admin][data-admin-id=\"{admin['id']}\"]")
        self.check("admins.toggle_enables_again", b.confirm() and b.wait(f"(document.querySelector('[data-management-action=toggle-admin][data-admin-id=\"{admin['id']}\"]')?.textContent || '').includes('Отключить')", 20))
        # API keys: the plaintext once, then only its prefix; a monitor key reads and never writes.
        b.wait("!!document.querySelector('#api-keys .keys-head [data-key-action=create]')", 20)
        b.click("[data-key-action=create]")
        self.check("admins.key_dialog_opens", b.wait("document.querySelector('#key-modal')?.open === true"))
        b.type("#key-name", key_name)
        b.select("#key-scope", "monitor")
        b.click("#create-key")
        self.check("admins.key_plaintext_shown_once", b.wait("document.querySelector('#key-reveal')?.open === true && (document.querySelector('#key-plaintext')?.value || '').startsWith('pc_')", 20))
        plaintext = b.value("#key-plaintext")
        b.close_dialog("#key-reveal")
        self.check("admins.key_plaintext_cleared_on_close", b.wait("(document.querySelector('#key-plaintext')?.value || '') === ''"))
        self.check("admins.key_listed_by_prefix_only", b.wait(f"[...document.querySelectorAll('[data-key-id]')].some(r => r.textContent.includes({json.dumps(key_name)}) && !r.textContent.includes({json.dumps(plaintext)}))", 20))
        key = next(k for k in self.api.json("/api/keys")["items"] if k["name"] == key_name)
        self.created["keys"].append(key["id"])
        reads, _ = self.api.request("/api/dashboard", bearer=plaintext)
        writes, _ = self.api.request("/api/users", "POST", {"username": f"{self.prefix}-never"}, bearer=plaintext)
        self.check("admins.monitor_key_reads_and_cannot_write", reads == 200 and writes == 403, f"read {reads} write {writes}")
        b.click(f"[data-key-id=\"{key['id']}\"] [data-key-action=toggle]")
        self.check("admins.key_disabled_from_the_row", b.wait(f"(document.querySelector('[data-key-id=\"{key['id']}\"]')?.textContent || '').includes('Выключен')", 20))
        refused, _ = self.api.request("/api/dashboard", bearer=plaintext)
        self.check("admins.disabled_key_is_401", refused == 401, str(refused))
        self.frame_is_secret_free("admins")
        b.shot("admins.png")
        b.click(f"[data-key-id=\"{key['id']}\"] [data-key-action=delete]")
        self.check("admins.key_delete_asks_and_removes", b.confirm() and b.wait(f"!document.querySelector('[data-key-id=\"{key['id']}\"]')", 20))
        self.created["keys"].remove(key["id"])
        # The viewer sees, and only sees.
        b.click("#logout")
        b.wait("location.pathname === '/login'", 15)
        self.check("admins.viewer_can_log_in", self.login(admin_name, admin_password))
        self.goto_view("users", "!!document.querySelector('#user-list')")
        self.check("admins.viewer_has_no_add_button", b.js("document.querySelector('#add')?.hidden === true"))
        self.goto_view("routing", "!!document.querySelector('#routing-form')")
        self.check("admins.viewer_cannot_apply_routing", b.js("document.querySelector('[data-routing-action=apply]')?.disabled === true && document.querySelector('#routing-save')?.disabled === true"))
        b.click("#logout")
        b.wait("location.pathname === '/login'", 15)
        self.login("owner", self.password)
        self.goto_view("admins", "!!document.querySelector('#api-keys') && !!document.querySelector('[data-key-action=create]')", 30)
        b.click(f"[data-management-action=edit-admin][data-admin-id=\"{admin['id']}\"]")
        self.check("admins.edit_dialog_offers_delete", b.wait("document.querySelector('#admin-modal')?.open === true && document.querySelector('#delete-admin')?.hidden === false"))
        b.click("#delete-admin")
        self.check("admins.delete_asks_and_removes", b.confirm() and b.wait(f"![...document.querySelectorAll('.admin-grid.data-row')].some(r => r.textContent.includes({json.dumps(admin_name)}))", 20))
        if admin_name not in [a["username"] for a in self.api.json("/api/admins")["items"]]:
            self.created["admins"].remove(admin_name)

    def view_audit(self) -> None:
        b = self.browser
        self.check("audit.rendered", self.goto_view("audit", "!!document.querySelector('#audit-filter-form') && document.querySelectorAll('.audit-row').length >= 1", 30))
        b.type("#audit-target", f"{self.prefix}-tg")
        b.js("document.querySelector('#audit-filter-form').requestSubmit(); true")
        self.check("audit.filter_by_target_finds_this_run", b.wait(f"document.querySelectorAll('.audit-row').length >= 1 && [...document.querySelectorAll('.audit-row')].every(r => r.textContent.includes({json.dumps(self.prefix + '-tg')}))", 20))
        b.type("#audit-target", "")
        b.type("#audit-action", "user.create")
        b.js("document.querySelector('#audit-filter-form').requestSubmit(); true")
        # The journal names actions in the operator's words («Создан доступ» for user.create).
        self.check("audit.filter_by_action", b.wait("document.querySelectorAll('.audit-row').length >= 1 && [...document.querySelectorAll('.audit-row')].every(r => r.textContent.includes('Создан доступ') || r.textContent.includes('user.create'))", 20))
        b.click("[data-audit-action=clear]")
        self.check("audit.clear_restores_the_journal", b.wait("document.querySelectorAll('.audit-row').length >= 3 && (document.querySelector('#audit-action')?.value || '') === ''", 20))
        self.cells_do_not_overlap("audit.cells_do_not_overlap", ".audit-row", ".audit-main > *")
        # One line per entry at desktop width: the toggle sits on the line, nothing wraps underneath.
        self.check("audit.rows_are_one_line", b.js("[...document.querySelectorAll('.audit-row > .audit-main')].slice(0, 12).every(m => m.getBoundingClientRect().height <= 56 && m.getBoundingClientRect().height >= 36)"))
        b.click(".audit-row summary.audit-main")
        self.check("audit.details_open_below_the_line", b.wait("(() => { const r = document.querySelector('details.audit-row[open]'); if (!r) return false; const m = r.querySelector('.audit-main').getBoundingClientRect(), d = r.querySelector('.audit-body').getBoundingClientRect(); return d.top >= m.bottom - 1 && d.height > 0; })()", 5))
        b.click(".audit-row[open] summary.audit-main")
        self.frame_is_secret_free("audit")
        b.shot("audit.png")

    # -- the central (v0.3): a second panel from this tree, linked to the node in the browser --

    def view_central(self) -> None:
        """The central's screens against the live node: link through the dialog (fingerprint,
        test, import), the node card (tabs, probe, pause/resume, edit), a grant on the node
        from the central's Clients screen delivered by the pusher, the node's own card saying
        it is managed, and the unlink."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("fleet_acceptance", ROOT / "scripts/lab/fleet-acceptance.py")
        fleet = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fleet)
        b = self.browser
        central_url = f"http://127.0.0.1:{self.args.central_port}"
        central_args = argparse.Namespace(central_dir=self.args.central_dir, central_host="127.0.0.1", central_port=self.args.central_port,
                                          python=sys.executable, source=ROOT, heartbeat_seconds=2)
        process = fleet.CentralProcess(central_args)
        central_password = secrets.token_urlsafe(24)
        central = Api(central_url, None)
        node_key_id = None
        imported_user = f"{self.prefix}-nodeimp"
        remote_user = f"{self.prefix}-remote"
        try:
            process.start(central_password)
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and central.request("/healthz")[0] != 200:
                time.sleep(0.5)
            self.check("central.started", central.request("/healthz")[0] == 200)
            central.login("owner", central_password)
            # What the node offers the central: a node-sync key and one runtime user to import.
            key = self.api.json("/api/keys", "POST", {"name": f"{self.prefix}-sync", "scope": "node-sync", "expires_at": None})
            node_key_id = key["key"]["id"]
            self.api.json("/api/naive/users", "POST", {"username": imported_user})
            self.created["naive"].append(imported_user)
            self.check("central.owner_login_in_browser", self.login("owner", central_password, central_url))
            self.check("central.nodes_screen_empty", self.goto_view("fleet", "!!document.querySelector('.local-node') && !document.querySelector('.linked-node')"))
            self.check("central.link_dialog_opens", self.open_add("#link-modal"))
            b.type("#link-name", "Lab node")
            b.type("#link-url", self.args.node_url)
            b.type("#link-key", key["plaintext"])
            if self.args.allow_private_address:
                b.js("document.querySelector('#link-private').checked = true; true")
            b.click("#link-fingerprint")
            self.check("central.fingerprint_fetched_and_pinned", b.wait("/^[0-9a-f]{64}$/.test(document.querySelector('#link-pinned')?.value || '') && document.querySelector('input[name=tls_verify][value=pin]')?.checked === true", 20))
            b.click("#link-test")
            self.check("central.test_shows_identity_and_import_candidates", b.wait(f"document.querySelector('#link-result')?.hidden === false && !!document.querySelector('#node-import-list tr[data-import-username={json.dumps(imported_user)}]')", 30), b.text("#link-error"))
            b.js(f"const r = document.querySelector('#node-import-list tr[data-import-username={json.dumps(imported_user)}]'); const p = r && r.querySelector('input[type=checkbox]'); if (p) p.checked = true; true")
            b.click("#link-save")
            self.check("central.link_created", b.wait("document.querySelector('#link-modal')?.open !== true && !!document.querySelector('.linked-node')", 30), b.text("#link-error"))
            node = next((n for n in central.json("/api/nodes")["items"] if n.get("transport") == "panel"), None)
            self.check("central.node_registered", node is not None)
            node_id = node["node_id"] if node else ""
            card = f"[data-node-id={json.dumps(node_id)}]"
            # The card does not poll: the first heartbeat lands within seconds, the screen shows it on reload.
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and (central.json(f"/api/nodes/{node_id}").get("link") or {}).get("status") != "online":
                time.sleep(1)
            self.goto_view("fleet", f"!!document.querySelector('{card}')")
            self.check("central.link_created_and_online", b.wait(f"(document.querySelector('{card} .status-pill')?.textContent || '').includes('На связи')", 20))
            imported = next((e for e in central.json("/api/clients")["items"] if e["client"]["display_name"] == imported_user), None)
            self.check("central.import_at_link_created_a_client", imported is not None and any(g["origin"] == "imported" for g in imported["grants"]), json.dumps(imported)[:200] if imported else "no client")
            b.click(f"{card} [data-node-action=tab-users]")
            self.check("central.users_tab_lists_node_accounts", b.wait(f"!!document.querySelector('{card} tr[data-import-username={json.dumps(imported_user)}]') && (document.querySelector('{card} tr[data-import-username={json.dumps(imported_user)}]')?.textContent || '').includes('привязан')", 30))
            b.click(f"{card} [data-node-action=tab-updates]")
            self.check("central.updates_tab_lists_node_components", b.wait(f"document.querySelectorAll('{card} .node-component').length >= 3 || (document.querySelector('{card} .node-tab-body')?.textContent || '').includes('недоступен')", 20))
            b.wait(f"!!document.querySelector('{card} [data-node-action=probe]')", 20)
            b.click(f"{card} [data-node-action=probe]")
            self.check("central.probe_answers", b.wait("[...document.querySelectorAll('#toast-region *')].some(t => t.textContent.includes('Узел опрошен'))", 20))
            time.sleep(1.5)  # the view reloads after the action; click the card that is back
            b.wait(f"!!document.querySelector('{card} [data-node-action=pause]')", 20)
            b.click(f"{card} [data-node-action=pause]")
            self.check("central.pause_marks_the_card", b.wait(f"(document.querySelector('{card} .node-identity small')?.textContent || '').includes('пауза') && !!document.querySelector('{card} [data-node-action=resume]')", 30))
            time.sleep(1.5)
            b.wait(f"!!document.querySelector('{card} [data-node-action=resume]')", 20)
            b.click(f"{card} [data-node-action=resume]")
            self.check("central.resume_restores", b.wait(f"!!document.querySelector('{card} [data-node-action=pause]') && !(document.querySelector('{card} .node-identity small')?.textContent || '').includes('пауза')", 30))
            time.sleep(1.5)
            b.wait(f"!!document.querySelector('{card} [data-node-action=edit]')", 20)
            b.click(f"{card} [data-node-action=edit]")
            self.check("central.edit_dialog_carries_the_link", b.wait("document.querySelector('#link-modal')?.open === true && (document.querySelector('#link-node-id')?.value || '') !== '' && document.querySelector('#link-name')?.value === 'Lab node'", 20))
            b.type("#link-name", "Lab node renamed")
            b.click("#link-save")
            self.check("central.edit_renames", b.wait(f"(document.querySelector('{card} .node-identity b')?.textContent || '') === 'Lab node renamed'", 30), b.text("#link-error"))
            b.shot("central-nodes.png")
            # A grant on the node from the central's Clients screen: delivered by the pusher.
            self.goto_view("clients", "!!document.querySelector('.client-list')")
            self.open_add("#client-modal")
            b.type("#client-name", remote_user)
            b.click("#create-client")
            b.wait(f"[...document.querySelectorAll('[data-client-id]')].some(c => c.querySelector('.client-identity b')?.textContent === {json.dumps(remote_user)})", 20)
            client = next(e for e in central.json("/api/clients")["items"] if e["client"]["display_name"] == remote_user)
            ccard = f"[data-client-id={json.dumps(client['client']['id'])}]"
            b.click(f"{ccard} [data-client-action=grant]")
            self.check("central.grant_dialog_offers_the_node", b.wait(f"document.querySelector('#grant-modal')?.open === true && !!document.querySelector('#grant-node option[value={json.dumps(node_id)}]')", 20))
            b.type("#grant-username", remote_user)
            b.select("#grant-node", node_id)
            b.js("[...document.querySelectorAll('#grant-form .grant-protocol input')].forEach(i => { i.checked = i.value === 'naive'; }); true")
            b.click("#create-grants")
            self.check("central.remote_grant_accepted", b.wait("document.querySelector('#grant-modal')?.open !== true", 30), b.text("#grant-error"))
            deadline = time.monotonic() + 90
            delivered = False
            while time.monotonic() < deadline and not delivered:
                delivered = remote_user in [u["username"] for u in self.api.json("/api/naive/users")["items"]]
                time.sleep(2)
            self.check("central.grant_reaches_the_node", delivered)
            self.created["naive"].append(remote_user)
            self.goto_view("clients", "!!document.querySelector('.client-list')")
            self.check("central.chip_says_delivered", b.wait(f"(document.querySelector('{ccard} .grant-chip')?.textContent || '').includes('включён')", 60))
            b.click(f"{ccard} .grant-chip [data-client-action=grant-delete]")
            b.confirm()
            deadline = time.monotonic() + 90
            gone = False
            while time.monotonic() < deadline and not gone:
                gone = remote_user not in [u["username"] for u in self.api.json("/api/naive/users")["items"]]
                time.sleep(2)
            self.check("central.grant_delete_reaches_the_node", gone)
            if gone:
                self.created["naive"].remove(remote_user)
            b.shot("central-clients.png")
            # The node's own screen while linked: the local card says who manages it.
            self.check("central.node_owner_login_again", self.login("owner", self.password))
            self.goto_view("fleet", "!!document.querySelector('.local-node')")
            self.check("central.node_card_says_managed", b.wait("(document.querySelector('.local-node')?.textContent || '').includes('управляется центром')", 20))
            self.goto_view("routing", "!!document.querySelector('#routing-form')")
            self.check("central.node_routing_refuses_local_changes", "маршрутизацией управляет центральная панель" in b.page_text() or b.js("document.querySelector('#routing-save')?.disabled === true"))
            b.shot("node-managed.png")
            # Unlink from the central: the node forgets its master.
            self.check("central.owner_login_back", self.login("owner", central_password, central_url))
            self.goto_view("fleet", f"!!document.querySelector('{card}')")
            b.click(f"{card} [data-node-action=remove]")
            self.check("central.remove_asks_and_forgets", b.confirm() and b.wait(f"!document.querySelector('{card}')", 30))
            local = next((n for n in self.api.json("/api/nodes")["items"] if n["node_id"] == "local"), {})
            self.check("central.node_master_cleared", not (local.get("identity") or {}).get("master_guid"), json.dumps(local.get("identity"))[:120])
            self.frame_is_secret_free("central")
        finally:
            with contextlib.suppress(Exception):
                for entry in central.json("/api/clients")["items"]:
                    if entry["client"]["state"] != "archived":
                        for grant in entry["grants"]:
                            central.request(f"/api/clients/grants/{grant['id']}/delete", "POST")
                        central.request(f"/api/clients/{entry['client']['id']}/state", "POST", {"state": "archived"})
            with contextlib.suppress(Exception):
                for n in central.json("/api/nodes")["items"]:
                    if n.get("transport") == "panel":
                        central.request(f"/api/nodes/{n['node_id']}", "DELETE")
            process.stop()
            with contextlib.suppress(Exception):
                self.api.login("owner", self.password)
                self.api.request("/api/nodes/local/unlink", "POST")
                if node_key_id:
                    self.api.request(f"/api/keys/{node_key_id}", "DELETE")

    # -- api-only (a production node) ---------------------------------------------------

    def api_only(self) -> None:
        prefix = f"live-ui-{self.run_id}"
        self.api.login("owner", self.password)
        me = self.api.json("/api/auth/me")
        self.check("live.login_owner", me.get("role") == "owner")
        for name, path in (("dashboard", "/api/dashboard"), ("users", "/api/users"), ("naive", "/api/naive/users"), ("mieru", "/api/mieru/users"),
                           ("clients", "/api/clients"), ("versions", "/api/versions"), ("fleet", "/api/nodes"), ("routing", "/api/routing/targets"),
                           ("admins", "/api/admins"), ("keys", "/api/keys"), ("audit", "/api/audit"), ("events", "/api/events"),
                           ("compatibility", "/api/subscriptions/compatibility")):
            status, body = self.api.request(path)
            secret = any(shape.search(json.dumps(body)) for shape in SECRET_SHAPES) if isinstance(body, (dict, list)) else False
            self.check(f"live.{name}_answers_secret_free", status == 200 and not secret, f"{status}")
        before = self.users()
        self.report["facts"]["users_initial"] = {k: len(v) for k, v in before.items()}
        if not self.args.read_only:
            created = self.api.json("/api/users", "POST", {"username": f"{prefix}-tg"})
            reveal = self.api.json(f"/api/reveal/{created['reveal_token']}")
            self.check("live.mtproxy_create_and_reveal", str(reveal.get("link", reveal.get("proxy_url", ""))).startswith(("tg://", "https://t.me/")) or "qr" in reveal)
            status, _ = self.api.request(f"/api/users/{prefix}-tg", "DELETE")
            self.check("live.mtproxy_delete", status in (200, 204))
            created = self.api.json("/api/naive/users", "POST", {"username": f"{prefix}-nv"})
            reveal = self.api.json(f"/api/reveal/{created['reveal_token']}")
            self.check("live.naive_create_and_reveal", "native" in (reveal.get("clients") or {}))
            status, _ = self.api.request(f"/api/naive/users/{prefix}-nv", "DELETE")
            self.check("live.naive_delete", status in (200, 204))
            revision = self.api.json("/api/mieru/users")["service"]["revision"]
            created = self.api.json("/api/mieru/users", "POST", {"username": f"{prefix}-mr", "quotas": [], "expected_revision": revision})
            reveal = self.api.json(f"/api/reveal/{created['reveal_token']}")
            self.check("live.mieru_create_and_reveal", "native" in (reveal.get("clients") or {}))
            revision = self.api.json("/api/mieru/users")["service"]["revision"]
            status, _ = self.api.request(f"/api/mieru/users/{prefix}-mr", "DELETE", {"expected_revision": revision})
            self.check("live.mieru_delete", status in (200, 204))
        after = self.users()
        self.check("live.runtime_users_equal_initial", after == before, json.dumps({"before": before, "after": after})[:400])

    # -- the run ----------------------------------------------------------------------

    def cleanup(self) -> None:
        """Whatever the run created and did not remove — by the run's prefix, never by guess."""
        with contextlib.suppress(Exception):
            self.api.login("owner", self.password)
        for key in list(self.api.json("/api/keys")["items"]) if self.created["keys"] else []:
            if key["id"] in self.created["keys"]:
                self.api.request(f"/api/keys/{key['id']}", "DELETE")
        for admin in self.api.json("/api/admins")["items"]:
            if admin["username"].startswith(self.prefix):
                self.api.request(f"/api/admins/{admin['id']}", "DELETE")
        for entry in self.api.json("/api/clients")["items"]:
            if entry["client"]["display_name"].startswith(self.prefix) and entry["client"]["state"] != "archived":
                for grant in entry["grants"]:
                    if grant.get("desired_state") != "deleted":
                        self.api.request(f"/api/clients/grants/{grant['id']}/delete", "POST")
                time.sleep(2)
                self.api.request(f"/api/clients/{entry['client']['id']}/state", "POST", {"state": "archived"})
        for user in self.api.json("/api/users")["items"]:
            if user["username"].startswith(self.prefix):
                self.api.request(f"/api/users/{user['username']}", "DELETE")
        for user in self.api.json("/api/naive/users")["items"]:
            if user["username"].startswith(self.prefix):
                self.api.request(f"/api/naive/users/{user['username']}", "DELETE")
        listing = self.api.json("/api/mieru/users")
        for user in listing["items"]:
            if user["username"].startswith(self.prefix):
                revision = self.api.json("/api/mieru/users")["service"]["revision"]
                self.api.request(f"/api/mieru/users/{user['username']}", "DELETE", {"expected_revision": revision})
        with contextlib.suppress(Exception):
            for protocol in ("naive", "mieru"):
                target = next((i for i in self.api.json("/api/routing/targets")["items"] if i["node_id"] == "local" and i["protocol"] == protocol), None)
                if target and target.get("policy"):
                    self.api.request(f"/api/routing/policies/local/{protocol}", "DELETE")

    def start_stub(self) -> None:
        if not self.args.stub:
            return
        self.stub = subprocess.Popen([sys.executable, str(ROOT / "scripts/lab/socks5-stub.py"), "--listen", "127.0.0.1:45000",
                                      "--log", str(self.output / "socks5-stub.log")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)

    def run(self) -> bool:
        started = time.monotonic()
        views = VIEWS if self.args.views == "all" else tuple(v.strip() for v in self.args.views.split(",") if v.strip())
        try:
            if self.args.api_only:
                self.api_only()
            else:
                self.api.login("owner", self.password)
                self.initial_users = self.users()
                self.report["facts"]["users_initial"] = {k: len(v) for k, v in self.initial_users.items()}
                self.start_stub()
                self.browser = Browser(self.work, None if self.args.no_shots else self.output)
                if "login" in views:
                    self.timed("login", self.view_login)
                    # The refused login is a 401 the browser logs as a failed resource: expected.
                    _, console = self.browser.errors()
                    self.report["facts"]["login_console"] = [c for c in console if "401" not in c]
                    self.check("login.no_console_error_but_the_refusal", not self.report["facts"]["login_console"], self.report["facts"]["login_console"])
                else:
                    self.check("login.session", self.login("owner", self.password))
                for view in views:
                    if view == "login":
                        continue
                    self.timed(view, getattr(self, f"view_{view}"))
                if self.args.central_dir:
                    self.timed("central", self.view_central)
                exceptions, console = self.browser.errors()
                if self.args.central_dir:
                    # The lab central manages the node's runtimes and has none of its own: its
                    # overview and MTProxy list answer 502 (no Telemt) — honest, and expected here.
                    central_origin = f"http://127.0.0.1:{self.args.central_port}/api/"
                    expected = [c for c in console if "502" in c and (central_origin + "dashboard" in c or central_origin + "users" in c)]
                    self.report["facts"]["central_console_expected"] = expected
                    console = [c for c in console if c not in expected]
                self.report["exceptions"], self.report["console"] = exceptions, console
                self.check("final.no_uncaught_exceptions", not exceptions, exceptions)
                self.check("final.no_console_errors", not console, console)
        except Exception as error:  # a crash is a failed check, not a lost report
            self.check("final.run_completed", False, f"{type(error).__name__}: {error}")
            import traceback
            self.report["traceback"] = redact(traceback.format_exc())[-1500:]
        finally:
            if self.browser:
                with contextlib.suppress(Exception):
                    self.browser.close()
                self.report["shots"] = self.browser.shots
            if self.stub:
                self.stub.terminate()
            if not self.args.api_only:
                with contextlib.suppress(Exception):
                    self.cleanup()
                with contextlib.suppress(Exception):
                    final = self.users()
                    self.check("final.runtime_users_equal_initial", final == self.initial_users,
                               json.dumps({"initial": self.initial_users, "final": final})[:400])
            shutil.rmtree(self.work, ignore_errors=True)
        self.report["elapsed_seconds"] = round(time.monotonic() - started, 1)
        self.report["ok"] = not self.report["failed"]
        text = json.dumps(self.report, indent=2, ensure_ascii=False, sort_keys=True)
        if any(shape.search(text) for shape in SECRET_SHAPES):
            text = redact(text)
            self.report["ok"] = False
            self.report["failed"].append("final.report_secret_free")
        (self.output / "report.json").write_text(text + "\n")
        print(("UI_ACCEPTANCE_OK" if self.report["ok"] else "UI_ACCEPTANCE_FAILED " + str(self.report["failed"])) + f" ({len(self.report['checks'])} checks, {self.report['elapsed_seconds']} s)")
        return self.report["ok"]

    def timed(self, name: str, function) -> None:
        started = time.monotonic()
        try:
            function()
        except Exception as error:
            self.check(f"{name}.scenario_completed", False, f"{type(error).__name__}: {error}")
        self.report["durations"][name] = round(time.monotonic() - started, 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ca-file", default=None)
    parser.add_argument("--views", default="all")
    parser.add_argument("--stub", action="store_true", help="start the SOCKS5 stub the routing tier uses as WARP")
    parser.add_argument("--no-shots", action="store_true")
    parser.add_argument("--api-only", action="store_true")
    parser.add_argument("--read-only", action="store_true")
    parser.add_argument("--central-dir", default=None, help="run a second panel from this tree there and drive its screens too (Task 3)")
    parser.add_argument("--central-port", type=int, default=8791)
    parser.add_argument("--allow-private-address", action="store_true", help="the node URL is a private/lab address")
    args = parser.parse_args()
    return 0 if Acceptance(args).run() else 1


if __name__ == "__main__":
    raise SystemExit(main())
