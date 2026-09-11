from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import struct
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _browser() -> str:
    executable = next(
        (
            path
            for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable")
            if (path := shutil.which(name))
        ),
        None,
    )
    if executable is None:
        # macOS ships Chrome inside a bundle, so it is never on PATH.
        bundled = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        executable = str(bundled) if bundled.exists() else None
    if executable is None:
        pytest.fail("Chromium-compatible browser is required for the mobile layout gate")
    return executable


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("Chromium closed the DevTools WebSocket")
        chunks.extend(chunk)
    return bytes(chunks)


class DevTools:
    def __init__(self, url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        # Every DevTools read inherits this timeout. A busy CI runner can take
        # far longer than ten seconds to answer while Chromium is still warming
        # up, and the render loop below already bounds the wait.
        self.connection = socket.create_connection((parsed.hostname, parsed.port), timeout=60)
        key = base64.b64encode(os.urandom(16)).decode()
        target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            "Origin: http://localhost\r\n\r\n"
        )
        self.connection.sendall(request.encode())
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(self.connection.recv(4096))
        if not response.startswith(b"HTTP/1.1 101"):
            raise RuntimeError(f"DevTools WebSocket upgrade failed: {response[:200]!r}")
        self.next_id = 1

    def close(self) -> None:
        self.connection.close()

    def _send(self, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode()
        mask = os.urandom(4)
        if len(data) < 126:
            header = bytes((0x81, 0x80 | len(data)))
        elif len(data) <= 0xFFFF:
            header = bytes((0x81, 0x80 | 126)) + struct.pack("!H", len(data))
        else:
            header = bytes((0x81, 0x80 | 127)) + struct.pack("!Q", len(data))
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
        self.connection.sendall(header + mask + masked)

    def _receive(self) -> dict[str, Any]:
        first, second = _recv_exact(self.connection, 2)
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", _recv_exact(self.connection, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", _recv_exact(self.connection, 8))[0]
        if second & 0x80:
            mask = _recv_exact(self.connection, 4)
            payload = bytes(
                byte ^ mask[index % 4] for index, byte in enumerate(_recv_exact(self.connection, length))
            )
        else:
            payload = _recv_exact(self.connection, length)
        if opcode == 0x8:
            raise RuntimeError("Chromium closed the DevTools WebSocket")
        if opcode != 0x1:
            return self._receive()
        return json.loads(payload)

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        message_id = self.next_id
        self.next_id += 1
        self._send({"id": message_id, "method": method, "params": params or {}})
        while True:
            response = self._receive()
            if response.get("id") == message_id:
                if "error" in response:
                    raise RuntimeError(f"DevTools {method} failed: {response['error']}")
                return response.get("result", {})


def _render_at_phone_viewport(page: Path, profile: Path) -> dict[str, Any]:
    process = subprocess.Popen(
        [
            _browser(),
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--remote-allow-origins=*",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        # Chromium's own reason for not starting is the only useful evidence
        # when the readiness wait expires, so keep it instead of discarding it.
        stderr=subprocess.PIPE,
    )
    try:
        # A cold Chromium on a loaded CI runner regularly needs more than the
        # twenty seconds this used to allow, and the loop already exits early
        # when the process dies, so a longer budget only costs time on a real
        # failure.
        deadline = time.monotonic() + 90
        active_port = profile / "DevToolsActivePort"
        port = None
        while time.monotonic() < deadline:
            try:
                lines = active_port.read_text().splitlines()
                candidate = int(lines[0])
                if len(lines) >= 2 and lines[1].startswith("/devtools/browser/"):
                    port = candidate
                    break
            except (FileNotFoundError, IndexError, OSError, ValueError):
                pass
            if process.poll() is not None:
                raise RuntimeError(f"Chromium exited before DevTools was ready: {process.returncode}")
            time.sleep(0.05)
        if port is None:
            process.terminate()
            try:
                complaint = (process.communicate(timeout=5)[1] or b"").decode(
                    "utf-8", "replace"
                )
            except subprocess.TimeoutExpired:
                complaint = ""
            tail = " | ".join(complaint.strip().splitlines()[-5:])
            raise RuntimeError(
                f"Chromium DevTools endpoint did not become ready: {tail or 'no output'}"
            )
        # DevTools answers before it has published a page target, so the first
        # listing on a slow runner can legitimately be empty.
        deadline = time.monotonic() + 30
        target_url = None
        while target_url is None and time.monotonic() < deadline:
            try:
                targets = json.load(
                    urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/json/list", timeout=5
                    )
                )
            except OSError:
                targets = []
            target_url = next(
                (
                    target["webSocketDebuggerUrl"]
                    for target in targets
                    if target.get("type") == "page"
                ),
                None,
            )
            if target_url is None:
                time.sleep(0.1)
        if target_url is None:
            raise RuntimeError("Chromium published no page target to drive")
        devtools = DevTools(target_url)
        try:
            devtools.call(
                "Emulation.setDeviceMetricsOverride",
                {"width": 390, "height": 844, "deviceScaleFactor": 1, "mobile": True},
            )
            devtools.call("Page.navigate", {"url": page.as_uri()})
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                result = devtools.call(
                    "Runtime.evaluate",
                    {
                        "expression": "({result:document.body?.dataset.result,errors:document.body?.dataset.errors,innerWidth})",
                        "returnByValue": True,
                    },
                )["result"].get("value", {})
                if result.get("result"):
                    return result
                time.sleep(0.05)
            raise RuntimeError("Mobile layout assertions did not finish")
        finally:
            devtools.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_access_cards_and_navigation_do_not_collide_on_phone(tmp_path: Path) -> None:
    """Real card variants must stack cleanly in an emulated 390 CSS-pixel viewport."""
    css = (ROOT / "static" / "style.css").read_text()
    buttons = "".join(
        f'<button><span class="mobile-icon">◇</span><small>{label}</small></button>'
        for label in ("Обзор", "Клиенты", "MTProxy", "Mieru", "Naive", "Версии", "Узлы", "Админы", "Журнал", "Выйти")
    )

    def card(classes: str, glyph: str, username: str, protocol: str, configuration: str) -> str:
        return f"""
          <div class="{classes}">
            <div class="identity"><span class="user-glyph">{glyph}</span><span><b>{username}</b><small>{protocol}</small></span></div>
            <div class="cell"><span class="status-pill active"><i></i>Активен</span></div>
            <div class="cell"><b>↑ 56 Б · ↓ 868 Б · Σ 924 Б</b><small>квота без квоты</small></div>
            <div class="row-actions">
              <button class="action-button">{configuration}</button><button class="action-button">Квота</button>
              <button class="action-button">Сбросить трафик</button><button class="action-button">Отключить</button>
              <button class="action-button">Новая ссылка + QR</button><button class="action-button danger-text">Удалить</button>
            </div>
          </div>
        """

    def node_card(node_id: str) -> str:
        """The node card has its own grid areas, so it is measured as its own variant."""
        return f"""
          <article class="data-row node-card">
            <span class="user-glyph">ND</span>
            <div class="node-identity"><b>{node_id}</b><small>{node_id} · Удалённый узел</small></div>
            <span class="status-pill active"><i></i>Enrolled</span>
            <dl class="node-facts">
              <div><dt>Транспорт</dt><dd>На связи · 10.09.2026, 12:00</dd></div>
              <div><dt>Демон</dt><dd>Telemt 3.4.25 · агент 0.1.0</dd></div>
              <div><dt>Команды в очереди</dt><dd>0</dd></div>
            </dl>
            <ul class="node-certificates"><li><code>AA01</code> <small>до 10.10.2026, 12:00</small></li></ul>
            <div class="node-actions">
              <button class="secondary">Переименовать</button><button class="secondary">Отключить</button>
              <button class="danger ghost">Отозвать все сертификаты</button>
            </div>
            <div class="advanced-drawer"><button class="ghost">Advanced: транспорт v1</button></div>
          </article>
        """

    def local_node_card() -> str:
        """The local card drops actions and the drawer and shows manager health instead."""
        return """
          <article class="data-row node-card local-node">
            <span class="user-glyph">LO</span>
            <div class="node-identity"><b>Этот сервер</b><small>local · Этот сервер</small></div>
            <span class="status-pill active"><i></i>Этот сервер</span>
            <dl class="node-facts">
              <div><dt>Транспорт</dt><dd>Транспорт не используется</dd></div>
              <div><dt>Демон</dt><dd>Telemt не определён · агент не определён</dd></div>
              <div><dt>Команды в очереди</dt><dd>0</dd></div>
            </dl>
            <div class="node-services">
              <ul>
                <li><span class="status-pill"><i></i>Telemt · работает</span></li>
                <li><span class="status-pill blocked"><i></i>NaiveProxy · недоступен</span></li>
                <li><span class="status-pill muted"><i></i>Mieru · выключен</span></li>
              </ul>
              <p class="form-hint">Локальные протоколы управляются напрямую: у этого узла нет ни очереди команд, ни сертификатов.</p>
            </div>
          </article>
        """

    def client_card() -> str:
        """The client card carries grant chips instead of traffic cells, so it is its own variant."""
        return """
          <article class="data-row client-card">
            <span class="user-glyph">СД</span>
            <div class="client-identity"><b>Ноутбук Сергея с очень длинным именем</b><small>Доступов: 3</small></div>
            <span class="status-pill active"><i></i>Активен</span>
            <ul class="client-grants">
              <li class="grant-chip"><b>MTProxy</b><span>alice</span><small>включён</small></li>
              <li class="grant-chip"><b>NaiveProxy</b><span>alice</span><small>включён</small><em>· без секрета</em></li>
              <li class="grant-chip"><b>Mieru</b><span>alice-with-a-very-long-runtime-name</span><small>выключен</small></li>
            </ul>
            <p class="form-hint">Нет сохранённого секрета у доступов: 1. Такой доступ не попадает в подписку.
              <button class="secondary" disabled>Принять доступ</button></p>
            <div class="client-actions">
              <button class="secondary">Выдать доступ</button><button class="secondary">Подписка</button>
              <button class="secondary">Приостановить</button><button class="danger ghost">Архивировать</button>
            </div>
          </article>
        """

    cards = "".join(
        (
            card("data-row", "MT", "mt-user-with-a-very-long-name", "MTProto · FakeTLS", "Подключение"),
            card("data-row naive-grid", "MI", "mieru-user-with-a-very-long-name", "Mieru · native AEAD", "Конфигурация"),
            card("data-row naive-grid", "NP", "naive-user-with-a-very-long-name", "HTTPS · HTTP/2 CONNECT", "Конфигурация"),
            node_card("edge-node-with-a-very-long-name"),
            local_node_card(),
            client_card(),
        )
    )
    script = """
      addEventListener("load", () => {
        const errors = [];
        const tolerance = 1;
        if (innerWidth !== 390) errors.push(`viewport is ${innerWidth}px instead of 390px`);
        for (const row of document.querySelectorAll(".data-row:not(.node-card):not(.client-card)")) {
          const [identity, status, traffic, actions] = row.children;
          const boxes = [identity, status, traffic, actions].map((node) => node.getBoundingClientRect());
          if (boxes[1].top + tolerance < boxes[0].bottom) errors.push("status overlaps identity");
          if (boxes[2].top + tolerance < boxes[1].bottom) errors.push("traffic overlaps status");
          if (boxes[3].top + tolerance < boxes[2].bottom) errors.push("actions overlap traffic");
          const rowBox = row.getBoundingClientRect();
          for (const region of row.children) {
            const box = region.getBoundingClientRect();
            if (box.left < rowBox.left - tolerance || box.right > rowBox.right + tolerance || region.scrollWidth > region.clientWidth + tolerance) {
              errors.push("card content escapes horizontally");
            }
          }
          const actionButtons = [...actions.querySelectorAll("button")];
          for (const button of actionButtons) {
            const box = button.getBoundingClientRect();
            if (box.left < rowBox.left - tolerance || box.right > rowBox.right + tolerance) errors.push("action escapes card");
          }
          const buttonBoxes = actionButtons.map((button) => button.getBoundingClientRect());
          if (Math.abs(buttonBoxes[0].top - buttonBoxes[1].top) > tolerance || buttonBoxes[2].top <= buttonBoxes[0].bottom) {
            errors.push("actions are not a compact two-column grid");
          }
        }
        // The node card uses its own grid areas, so it gets its own stacking check.
        for (const card of document.querySelectorAll(".node-card:not(.local-node)")) {
          const cardBox = card.getBoundingClientRect();
          for (const region of card.children) {
            const box = region.getBoundingClientRect();
            if (box.left < cardBox.left - tolerance || box.right > cardBox.right + tolerance || region.scrollWidth > region.clientWidth + tolerance) {
              errors.push("node card content escapes horizontally");
            }
          }
          for (const button of card.querySelectorAll("button")) {
            const box = button.getBoundingClientRect();
            if (box.left < cardBox.left - tolerance || box.right > cardBox.right + tolerance) errors.push("node action escapes card");
          }
          const identity = card.querySelector(".node-identity").getBoundingClientRect();
          const facts = card.querySelector(".node-facts").getBoundingClientRect();
          const actions = card.querySelector(".node-actions").getBoundingClientRect();
          const drawer = card.querySelector(".advanced-drawer").getBoundingClientRect();
          if (facts.top + tolerance < identity.bottom) errors.push("node facts overlap identity");
          if (actions.top + tolerance < facts.bottom) errors.push("node actions overlap facts");
          if (drawer.top + tolerance < actions.bottom) errors.push("advanced drawer overlaps actions");
        }
        // The local card has no enrollment actions and no transport drawer, so it stacks
        // identity → facts → services and is measured on its own terms.
        for (const card of document.querySelectorAll(".local-node")) {
          const cardBox = card.getBoundingClientRect();
          for (const region of card.children) {
            const box = region.getBoundingClientRect();
            if (box.left < cardBox.left - tolerance || box.right > cardBox.right + tolerance || region.scrollWidth > region.clientWidth + tolerance) {
              errors.push("local node card content escapes horizontally");
            }
          }
          if (card.querySelector(".node-actions") || card.querySelector(".advanced-drawer")) {
            errors.push("local node card offers enrollment controls");
          }
          const identity = card.querySelector(".node-identity").getBoundingClientRect();
          const facts = card.querySelector(".node-facts").getBoundingClientRect();
          const services = card.querySelector(".node-services").getBoundingClientRect();
          if (facts.top + tolerance < identity.bottom) errors.push("local node facts overlap identity");
          if (services.top + tolerance < facts.bottom) errors.push("local node services overlap facts");
          for (const pill of card.querySelectorAll(".node-services .status-pill")) {
            const box = pill.getBoundingClientRect();
            if (box.left < cardBox.left - tolerance || box.right > cardBox.right + tolerance) {
              errors.push("service pill escapes card");
            }
          }
        }
        // The client card stacks identity → grants → note → actions and must not
        // let a long runtime username push a chip out of the card.
        for (const card of document.querySelectorAll(".client-card")) {
          const cardBox = card.getBoundingClientRect();
          for (const region of card.children) {
            const box = region.getBoundingClientRect();
            if (box.left < cardBox.left - tolerance || box.right > cardBox.right + tolerance || region.scrollWidth > region.clientWidth + tolerance) {
              errors.push("client card content escapes horizontally");
            }
          }
          const identity = card.querySelector(".client-identity").getBoundingClientRect();
          const grants = card.querySelector(".client-grants").getBoundingClientRect();
          const actions = card.querySelector(".client-actions").getBoundingClientRect();
          if (grants.top + tolerance < identity.bottom) errors.push("client grants overlap identity");
          if (actions.top + tolerance < grants.bottom) errors.push("client actions overlap grants");
          for (const chip of card.querySelectorAll(".grant-chip")) {
            const box = chip.getBoundingClientRect();
            if (box.left < cardBox.left - tolerance || box.right > cardBox.right + tolerance) {
              errors.push("grant chip escapes card");
            }
          }
          for (const button of card.querySelectorAll("button")) {
            const box = button.getBoundingClientRect();
            if (box.left < cardBox.left - tolerance || box.right > cardBox.right + tolerance) {
              errors.push("client action escapes card");
            }
          }
        }
        const nav = document.querySelector(".mobile-nav");
        const navButtons = [...nav.querySelectorAll("button")];
        if (!navButtons.every((button) => {
          const box = button.getBoundingClientRect();
          return box.width >= 60 && box.height >= 60;
        })) errors.push("navigation target is smaller than 60px");
        if (nav.scrollWidth <= nav.clientWidth) errors.push("navigation does not scroll");
        document.body.dataset.result = errors.length ? "fail" : "pass";
        document.body.dataset.errors = JSON.stringify(errors);
      });
    """
    page = tmp_path / "mobile-layout.html"
    page.write_text(
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<style>{css}</style></head><body><main>{cards}</main>"
        f"<nav class='mobile-nav'>{buttons}</nav><script>{script}</script></body></html>"
    )

    rendered = _render_at_phone_viewport(page, tmp_path / "chromium-profile")
    errors = json.loads(rendered["errors"])
    assert rendered["innerWidth"] == 390
    assert rendered["result"] == "pass", errors


def test_subscription_dialog_fits_the_phone_viewport_when_open(tmp_path: Path) -> None:
    """The dialog is the real markup from index.html, opened and filled the way subscriptions.js fills it."""
    import re

    css = (ROOT / "static" / "style.css").read_text()
    html = (ROOT / "static" / "index.html").read_text()
    dialog = re.search(r'<dialog id="subscription-modal".*?</dialog>', html, re.DOTALL).group(0)
    grants = "".join(
        f"""<li class="grant-chip"><b>{protocol}</b><span>{user}</span>
            <span class="auto-refresh" data-auto-refresh><small class="refresh-supported">karing</small><small class="refresh-unsupported">singbox</small><small class="refresh-unproven">mihomo</small></span>{note}</li>"""
        for protocol, user, note in (
            ("MTProxy", "alice-with-a-very-long-runtime-name", ""),
            ("NaiveProxy", "alice", "<em>без секрета — в подписке как unsupported</em>"),
            ("Mieru", "alice", "<em>выключен — в подписку не попадает</em>"),
        )
    )
    variants = "".join(
        f"""<label class="subscription-variant"><input type="radio" name="subscription-format" value="{name}"{" checked" if name == "singbox" else ""}>
            <span><b>{name}</b> <small>Karing, sing-box ≥ 1.13</small><small>Попадёт: NaiveProxy и Mieru как outbound'ы. Не попадёт: MTProxy — в unsupported (в sing-box нет MTProto); Mieru с диапазоном портов — тоже.</small></span></label>"""
        for name in ("singbox", "clash", "raw")
    )
    token = "A" * 43
    script = f"""
      addEventListener("load", () => {{
        const errors = [];
        const tolerance = 1;
        if (innerWidth !== 390) errors.push(`viewport is ${{innerWidth}}px instead of 390px`);
        const dialog = document.querySelector("#subscription-modal");
        document.querySelector("#subscription-status").textContent = "URL выдан 11.09.2026, 12:00, поколение 3. Последнее обновление клиентом: никогда. Интервал автообновления: 12 ч.";
        document.querySelector("#subscription-grants").innerHTML = {json.dumps(grants)};
        document.querySelector("#subscription-variants").innerHTML = {json.dumps(variants)};
        document.querySelector("#subscription-url").value = "https://eclipse.sky.dubr1kkk.uk/s/{token}?format=singbox";
        document.querySelector("#subscription-qr").src = "data:image/svg+xml;base64," + btoa('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>');
        document.querySelector("#subscription-reveal").hidden = false;
        document.querySelector("#subscription-actions").innerHTML = '<button type="button" class="secondary">Ротировать URL</button><button type="button" class="danger ghost">Отозвать</button>';
        dialog.showModal();
        const form = dialog.querySelector("form");
        const formBox = form.getBoundingClientRect();
        if (formBox.right > innerWidth + tolerance || formBox.left < -tolerance) errors.push("dialog wider than the viewport");
        for (const node of dialog.querySelectorAll(".grant-chip, .subscription-variant, .subscription-reveal, .copy-field, .subscription-qr, footer button, #subscription-actions button, .subscription-warning")) {{
          const box = node.getBoundingClientRect();
          if (box.left < formBox.left - tolerance || box.right > formBox.right + tolerance) errors.push(`${{node.className || node.tagName}} escapes the dialog`);
          if (node.scrollWidth > node.clientWidth + tolerance && !node.matches("input")) errors.push(`${{node.className || node.tagName}} overflows horizontally`);
        }}
        const reveal = document.querySelector("#subscription-reveal").getBoundingClientRect();
        const variantsBox = document.querySelector(".subscription-formats").getBoundingClientRect();
        if (reveal.top + tolerance < variantsBox.bottom) errors.push("reveal overlaps the variants");
        if (form.scrollWidth > form.clientWidth + tolerance) errors.push("dialog scrolls horizontally");
        document.body.dataset.result = errors.length ? "fail" : "pass";
        document.body.dataset.errors = JSON.stringify(errors);
      }});
    """
    page = tmp_path / "subscription-dialog.html"
    page.write_text(
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<style>{css}</style></head><body><main></main>{dialog}<script>{script}</script></body></html>"
    )

    rendered = _render_at_phone_viewport(page, tmp_path / "chromium-profile")
    errors = json.loads(rendered["errors"])
    assert rendered["innerWidth"] == 390
    assert rendered["result"] == "pass", errors


def test_host_resource_card_stacks_and_stays_inside_the_phone_viewport(tmp_path: Path) -> None:
    """The fourth overview card must not reintroduce horizontal scroll on a phone."""
    css = (ROOT / "static" / "style.css").read_text()

    def row(label: str, value: str, percent: str, detail: str) -> str:
        return f"""
          <span><small>{label}</small><b>{value}</b>
            <span class="usage-bar"><i style="width:{percent}"></i></span>
            <em>{detail}</em></span>
        """

    card = f"""
      <div class="protocol-overview">
        <article class="protocol-card host-card">
          <div class="protocol-head"><span><small>CPU · RAM · Диск</small><h2>Ресурсы сервера</h2></span><span class="status-pill active"><i></i>В норме</span></div>
          <p class="protocol-note">8 ядер · load 12.75 · 11.20 · 9.80</p>
          <div class="protocol-metrics host-metrics">
            {row("Загрузка CPU", "99.9 %", "99.9%", "Мгновенная утилизация, окно 150 мс")}
            {row("Оперативная память", "88.4 %", "88.4%", "13.8 ГБ из 15.6 ГБ")}
            {row("Диск (корень)", "94.1 %", "94.1%", "20 ГБ свободно из 348 ГБ")}
          </div>
        </article>
      </div>
    """
    script = """
      addEventListener("load", () => {
        const errors = [];
        const tolerance = 1;
        if (innerWidth !== 390) errors.push(`viewport is ${innerWidth}px instead of 390px`);
        const card = document.querySelector(".host-card");
        const cardBox = card.getBoundingClientRect();
        const rows = [...document.querySelectorAll(".host-metrics > span")];
        if (rows.length !== 3) errors.push("expected three resource rows");
        rows.forEach((row, index) => {
          const box = row.getBoundingClientRect();
          if (box.left < cardBox.left - tolerance || box.right > cardBox.right + tolerance) {
            errors.push(`row ${index} escapes the card horizontally`);
          }
          if (index > 0) {
            const previous = rows[index - 1].getBoundingClientRect();
            if (box.top + tolerance < previous.bottom) errors.push(`row ${index} overlaps row ${index - 1}`);
          }
          const bar = row.querySelector(".usage-bar");
          const barBox = bar.getBoundingClientRect();
          if (barBox.width <= 0) errors.push(`row ${index} has no usage bar`);
          if (barBox.right > cardBox.right + tolerance) errors.push(`row ${index} bar escapes the card`);
        });
        if (document.documentElement.scrollWidth > document.documentElement.clientWidth + tolerance) {
          errors.push("page scrolls horizontally");
        }
        document.body.dataset.result = errors.length ? "fail" : "pass";
        document.body.dataset.errors = JSON.stringify(errors);
      });
    """
    page = tmp_path / "host-card.html"
    page.write_text(
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<style>{css}</style></head><body><main>{card}</main><script>{script}</script></body></html>"
    )

    rendered = _render_at_phone_viewport(page, tmp_path / "chromium-profile")
    errors = json.loads(rendered["errors"])
    assert rendered["innerWidth"] == 390
    assert rendered["result"] == "pass", errors
