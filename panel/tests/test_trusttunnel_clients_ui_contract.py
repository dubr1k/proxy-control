"""Exercise the TrustTunnel access consumer JavaScript served by the Rust panel."""

from __future__ import annotations

import json

import shutil
import subprocess

import pytest

pytestmark = pytest.mark.anyio

NODE = shutil.which("node")


async def test_the_markup_escapes_shows_every_value_and_drops_a_malformed_artifact(server, tmp_path):
    (tmp_path / "common.mjs").write_text((await server.client.get("/static/js/common.js")).text)
    source = (await server.client.get("/static/js/trusttunnel-clients.js")).text
    (tmp_path / "tt.mjs").write_text(source.replace("./common.js", "./common.mjs"))
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
  shown: html.includes("<code>pw-CANARY-1</code>") && !html.includes("••••") && !html.includes("data-tt-"),
  copyButtons: (html.match(/data-copy=/g) || []).length,
  labels: ["Сервер", "Порт", "Логин", "Пароль", "SNI", "Протокол", "Сертификат (PEM)", "Строка политики Surge"].filter((l) => html.includes(l)).length,
  quicOff: html.includes("HTTP/2, QUIC выключен"),
  surge: html.includes("Proxy-TrustTunnel = trust-tunnel, gate.example.com, 443"),
  appRows: (apps.match(/class="tt-app"/g) || []).length, safeLinks: (apps.match(/target="_blank" rel="noopener noreferrer"/g) || []).length,
  inlineStyle: /style=/.test(html + apps),
  heading: apps.includes("Как подключить"),
}));
""" % json.dumps((tmp_path / "tt.mjs").as_uri())
    assert NODE is not None
    out = json.loads(subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, text=True, check=True).stdout)
    assert out["parsed"] == ["gate.example.com", "443", "al<ice>"]
    assert out["badJson"] is None and out["noPort"] is None and out["huge"] is None
    # the password and the policy line are shown as they are: the same secret is in the link and the TOML next to them
    assert out["escaped"] and out["shown"] and out["quicOff"] and out["surge"] and out["heading"]
    assert out["labels"] == 8 and out["copyButtons"] == 7 and out["inlineStyle"] is False
    assert out["appRows"] == 7 and out["safeLinks"] == 8
