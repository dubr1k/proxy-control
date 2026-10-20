"""«Как подключить» and the manual-setup card (v2.1): the apps that take a TrustTunnel access, how each
imports it, and the fields for those that import neither the link nor the TOML.

The panel's JS (grant window, bundle) lists every app, the unverified ones marked; the subscription page's
Python lists only the verified ones (owner rule, 3.0.0) — a test keeps the two in step. No inline `style=`, links open in a new tab without an opener."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from panel.subscriptions.renderers.html import TRUSTTUNNEL_APPS

STATIC = Path(__file__).resolve().parent.parent / "static"
JS = STATIC / "js"
SOURCE = (JS / "trusttunnel-clients.js").read_text()
NODE = shutil.which("node")


def test_the_grant_window_and_the_bundle_use_the_shared_module():
    grant, access = (JS / "grant.js").read_text(), (JS / "access.js").read_text()
    assert 'from "./trusttunnel-clients.js"' in grant and 'from "./trusttunnel-clients.js"' in access
    assert 'kind === "trusttunnel_manual"' in grant and "appsHtml()" in grant and "manualHtml(" in grant
    assert 'media_type === "application/json"' in access and "bindReveal(root)" in access
    assert "style=" not in SOURCE


def test_every_external_link_is_https_and_opens_without_an_opener():
    assert 'target="_blank" rel="noopener noreferrer"' in SOURCE and "HTTPS.test(url)" in SOURCE
    urls = re.findall(r'"(https://[^"]+)"', SOURCE)
    assert urls and all(url.startswith("https://") for url in urls)


def test_the_subscription_page_lists_exactly_the_verified_apps_of_the_panel():
    entries = re.findall(r'\{\n    name: "([^"]+)".*?verified: (true|false),\s*links: \[(.*?)\],?\n  \}', SOURCE, re.S)
    verified = [(name, set(re.findall(r'"(https://[^"]+)"', links))) for name, flag, links in entries if flag == "true"]
    assert len(entries) == 7 and len(verified) == len(TRUSTTUNNEL_APPS) == 3
    for (js_name, js_urls), (py_name, _, _, py_links) in zip(verified, TRUSTTUNNEL_APPS):
        assert js_urls == {url for _, url in py_links}
        assert js_name == py_name or ("mihomo" in py_name and "Clash" in js_name)


def test_unverified_claims_are_worded_as_unverified():
    unverified = [app for app in re.findall(r"\{\n    name:.*?verified: (true|false)", SOURCE, re.S)]
    assert unverified.count("true") == 3  # the two official clients and the mihomo core (v1.19.32)
    assert "не проверено нами" in SOURCE and "не проверено: проверьте импорт ссылки tt:// или TOML" in SOURCE


def test_mobile_css_stacks_the_app_rows_and_never_scrolls_sideways():
    css = (STATIC / "style.css").read_text()
    block = css[css.index("/* TrustTunnel clients (v2.1)"):]
    assert ".tt-app{display:grid" in block and "overflow-wrap:anywhere" in block
    assert "@media(max-width:640px)" in block and "style=" not in block


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_the_markup_escapes_masks_the_password_and_drops_a_malformed_artifact():
    tmp = Path(tempfile.mkdtemp())
    shutil.copy(JS / "common.js", tmp / "common.mjs")
    (tmp / "tt.mjs").write_text(SOURCE.replace("./common.js", "./common.mjs"))
    code = """
import * as tt from %s;
const good = JSON.stringify({ server: "gate.example.com", port: 443, username: "al<ice>", password: "pw-CANARY-1", sni: "gate.example.com",
  protocol: "HTTP/2", quic: false, certificate_pem: "-----BEGIN CERTIFICATE-----\\nAA\\n-----END CERTIFICATE-----\\n",
  surge: "trust-tunnel, gate.example.com, 443, username=al<ice>, password=pw-CANARY-1" });
const manual = tt.parseManual(good);
const html = tt.manualHtml(manual);
const apps = tt.appsHtml();
console.log(JSON.stringify({
  parsed: manual && [manual.server, manual.port, manual.username],
  badJson: tt.parseManual("{"), noPort: tt.parseManual(JSON.stringify({ server: "a", username: "b", password: "c" })), huge: tt.parseManual("x".repeat(70000)),
  escaped: html.includes("al&lt;ice&gt;") && !html.includes("al<ice>"),
  masked: html.includes('class="tt-secret" data-tt-secret="pw-CANARY-1">••••••••</code>') && !html.replace(/data-(tt-secret|copy)="[^"]*"/g, "").includes("pw-CANARY-1"),
  surgeMasked: html.includes('data-tt-secret="Proxy-TrustTunnel = trust-tunnel'),
  copyButtons: (html.match(/data-copy=/g) || []).length,
  labels: ["Сервер", "Порт", "Логин", "Пароль", "SNI", "Протокол", "Сертификат (PEM)", "Строка политики Surge"].filter((l) => html.includes(l)).length,
  quicOff: html.includes("HTTP/2, QUIC выключен"),
  surge: html.includes("Proxy-TrustTunnel = trust-tunnel, gate.example.com, 443"),
  appRows: (apps.match(/class="tt-app"/g) || []).length, safeLinks: (apps.match(/target="_blank" rel="noopener noreferrer"/g) || []).length,
  inlineStyle: /style=/.test(html + apps),
  heading: apps.includes("Как подключить"),
}));
""" % json.dumps((tmp / "tt.mjs").as_uri())
    out = json.loads(subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, text=True, check=True).stdout)
    assert out["parsed"] == ["gate.example.com", "443", "al<ice>"]
    assert out["badJson"] is None and out["noPort"] is None and out["huge"] is None
    assert out["surgeMasked"]  # the policy line carries the password: masked until pressed
    assert out["escaped"] and out["masked"] and out["quicOff"] and out["surge"] and out["heading"]
    assert out["labels"] == 8 and out["copyButtons"] == 7 and out["inlineStyle"] is False
    assert out["appRows"] == 7 and out["safeLinks"] == 8
