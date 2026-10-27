"""AWG browser smoke against an isolated native test-hooks panel and Chromium.

Run with the external lab venv on ams-test, setting PANEL_RUST_BIN if needed:
  python scripts/lab/ui_awg_check.py

Manager doubles are test-owned HTTP fixtures. No installed panel is contacted.
Only booleans/counts are returned from secret-bearing browser expressions; no
screenshots, DOM/accessibility dumps, configs or exception payloads are emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.lab.ui_protocol_dialog_check import (  # noqa: E402
    ProtocolFixture, isolated_browser, make_panel, require,
)


class AwgFixture(ProtocolFixture):
    async def _start(self, work, port):
        self.central = make_panel(work, "central", ("1.5", "2.0", "3.1"), port)
        self.panels.append(self.central)


def check_awg(browser, fixture):
    cid = fixture.api("/api/clients", "POST", {"display_name": "samsung", "subscription": False})["id"]
    js, wait, click = browser.js, browser.wait, browser.click
    browser.dt.call("Emulation.setDeviceMetricsOverride", {
        "width": 1280, "height": 900, "deviceScaleFactor": 1, "mobile": False,
    })
    browser.dt.call("Page.navigate", {"url": fixture.base + "/#clients"})
    card = f'[data-client-id="{cid}"] [data-client-action="placement"]'
    wait(f"!!document.querySelector({json.dumps(card)})", "client placement action")
    click(card)
    wait("document.querySelectorAll('#placement-body input[data-node=local][data-protocol^=\"amneziawg:\"]').length === 3", "three AWG version cells")
    require(js("[...document.querySelectorAll('#placement-body input[data-node=local][data-protocol^=\"amneziawg:\"]')].every(e => !e.disabled)"), "served versions selectable")
    if js("!document.querySelector('#placement-username-row').hidden"):
        browser.set_value("#placement-username", "samsung")
    click('#placement-body input[data-node=local][data-protocol="amneziawg:1.5"]')
    click('#placement-body input[data-node=local][data-protocol="amneziawg:3.1"]')
    # Never capture any frame after the first issuance, including on failures.
    browser.can_capture = False
    click("#placement-actions button[data-placement-action=apply]")
    wait("document.querySelector('#bundle-modal')?.open && document.querySelectorAll('#bundle-body textarea.awg-conf').length === 2", "placement bundle")
    grants = fixture.api(f"/api/clients/{cid}")["grants"]
    awg = {g["options"]["version"]: g for g in grants if g["protocol"] == "amneziawg"}
    require(set(awg) == {"1.5", "3.1"}, "only selected AWG versions issued")
    require(all(g["observed_state"] == "enabled" and g["runtime_username"] == "samsung-awg" + v.replace(".", "") for v, g in awg.items()), "issued grants match placement")
    require(js("document.querySelectorAll('#bundle-body img.link-qr').length === 2 && [...document.querySelectorAll('#bundle-body textarea.awg-conf')].every(e => e.value.startsWith('[Interface]\\nPrivateKey = ') && e.value.includes('\\n[Peer]\\n'))"), "bundle configs and QR present")
    wait("document.querySelectorAll('#bundle-body img.link-qr').length === 2 && [...document.querySelectorAll('#bundle-body img.link-qr')].every(e => e.complete && e.naturalWidth > 0)", "bundle QR images decoded")
    require(js("""(() => {
        const configs = [...document.querySelectorAll('#bundle-body textarea.awg-conf')].map(t => t.value);
        return ['samsung-awg15.conf', 'samsung-awg31.conf'].every(name => {
            const link = [...document.querySelectorAll('#bundle-body a[download]')].find(a => a.download === name);
            return !!link && configs.includes(decodeURIComponent(link.href.slice(link.href.indexOf(',') + 1)));
        });
    })()"""), "bundle config downloads match displayed configs")
    js("[...document.querySelectorAll('dialog[open]')].forEach(d => d.close()); true")
    browser.dt.call("Page.navigate", {"url": fixture.base + "/?grant=awg#clients"})
    grant_selector = f'[data-grant-open="{awg["3.1"]["id"]}"]'
    wait(f"!!document.querySelector({json.dumps(grant_selector)})", "issued grant row")
    click(grant_selector)
    wait("document.querySelector('#grant-window')?.open && !!document.querySelector('[data-grant-action=show]')", "grant window")
    require(js("(() => { const facts = document.querySelector('#grant-facts').textContent; return facts.includes('AmneziaWG 3.1') && facts.includes('10.66.31.') && facts.includes('51822/udp') && !document.querySelector('[data-grant-action=label]'); })()"), "AWG grant facts and actions")
    click("[data-grant-action=show]")
    wait("!!document.querySelector('#grant-link-body textarea.awg-conf')", "grant config reveal")
    require(js("(() => { const text = document.querySelector('#grant-link-body textarea.awg-conf').value; const link = document.querySelector('#grant-link-body a[download=\"samsung-awg31.conf\"]'); window.__awgBeforeRotation = text; return text.startsWith('[Interface]\\nPrivateKey = ') && text.includes('Endpoint = awg.central.example:51822') && text.includes('HeaderProtectionKey') && !!document.querySelector('#grant-link-body img.link-qr') && !!link && decodeURIComponent(link.href.split(',').slice(1).join(',')) === text; })()"), "AWG 3.1 config, QR and downloadable content")
    wait("document.querySelector('#grant-link-body img.link-qr')?.complete && document.querySelector('#grant-link-body img.link-qr')?.naturalWidth > 0", "grant QR image decoded")
    downloads = fixture.central.workdir / "downloads"
    downloads.mkdir()
    browser.dt.call("Browser.setDownloadBehavior", {"behavior": "allow", "downloadPath": str(downloads)})
    click('#grant-link-body a[download="samsung-awg31.conf"]')
    downloaded = downloads / "samsung-awg31.conf"
    deadline = time.monotonic() + 20
    while not downloaded.is_file() and time.monotonic() < deadline:
        time.sleep(0.1)
    require(downloaded.is_file(), "Chromium config download completed")
    digest = hashlib.sha256(downloaded.read_bytes()).hexdigest()
    require(js(f"""(async () => {{
        const bytes = new TextEncoder().encode(document.querySelector('#grant-link-body textarea.awg-conf').value);
        const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
          .map(v => v.toString(16).padStart(2, '0')).join('');
        return digest === {json.dumps(digest)};
    }})()"""), "downloaded file matches displayed config")
    rotate_path = f"/api/clients/grants/{awg['3.1']['id']}/rotate"
    js(f"""(() => {{
        window.__awgRotationStatus = 0;
        const originalFetch = window.fetch;
        window.fetch = async (...args) => {{
            const response = await originalFetch(...args);
            const url = typeof args[0] === 'string' ? args[0] : args[0].url;
            if (new URL(url, location.href).pathname === {json.dumps(rotate_path)})
                window.__awgRotationStatus = response.status;
            return response;
        }};
        return true;
    }})()""")
    click("[data-grant-action=rotate]")
    wait("document.querySelector('#confirm')?.open", "rotation confirmation")
    click("#confirm-ok")
    wait("window.__awgRotationStatus === 200", "native rotation response")
    wait("!document.querySelector('#confirm')?.open && !document.querySelector('#grant-link-body textarea.awg-conf') && !!document.querySelector('[data-grant-action=show]')", "rotation cleared old reveal")
    click("[data-grant-action=show]")
    wait("!!document.querySelector('#grant-link-body textarea.awg-conf') && document.querySelector('#grant-link-body textarea.awg-conf').value !== window.__awgBeforeRotation", "rotated config differs")
    js("delete window.__awgBeforeRotation; [...document.querySelectorAll('dialog[open]')].forEach(d => d.close()); true")
    click('.nav-item[data-view=amneziawg]')
    wait("document.querySelectorAll('.data-row.naive-grid').length === 2", "AWG screen grants")
    require(js("['51820/udp', '51821/udp', '51822/udp'].every(port => [...document.querySelectorAll('.awg-overview article strong')].some(e => e.textContent.trim() === port))"), "AWG screen version ports")
    click("[data-awg-action=open]")
    wait("document.querySelector('#grant-window')?.open && !!document.querySelector('[data-grant-action=show]')", "grant window from AWG screen")
    js("[...document.querySelectorAll('dialog[open]')].forEach(d => d.close()); true")
    click("#add")
    wait("document.querySelector('#awg-modal')?.open", "AWG creation dialog")
    browser.set_value("#new-awg-user", "screen-made")
    js("document.querySelectorAll('[data-awg-version]').forEach(e => { e.checked = ['2.0', '3.1'].includes(e.dataset.awgVersion); e.dispatchEvent(new Event('input', {bubbles:true})); }); true")
    wait("!document.querySelector('#create-awg').disabled", "AWG creation enabled")
    click("#create-awg")
    wait("document.querySelector('#bundle-modal')?.open && document.querySelectorAll('#bundle-body textarea.awg-conf').length === 2", "screen creation bundle")
    require(js("['screen-made-awg20.conf', 'screen-made-awg31.conf'].every(name => !!document.querySelector('#bundle-body a[download=\"' + name + '\"]'))"), "screen-selected versions downloaded")
    js("[...document.querySelectorAll('dialog[open]')].forEach(d => d.close()); true")
    wait("['screen-made-awg20', 'screen-made-awg31'].every(name => [...document.querySelectorAll('.data-row .identity b')].some(e => e.textContent.trim() === name))", "screen-created grant rows")
    browser.healthy()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="awg-browser-") as directory, socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        fixture = AwgFixture(Path(directory), listener)
        try:
            fixture.login()
            with isolated_browser(Path(directory), fixture) as browser:
                check_awg(browser, fixture)
        finally:
            fixture.close()
    print("UI_AWG_OK placement_versions=3 issued=2 rotation=true screen_created=2 browser_errors=0 captures=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
