"""Public subscription landing regressions using fresh, synthetic Rust-panel state only.

Optional SUBSCRIPTION_LANDING_SHOTS writes synthetic screenshots outside the checkout.
Only boolean comparisons leave the page: URLs, credentials and QR payloads stay private.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
from urllib.parse import quote, urlsplit

import pytest

from scripts.lab import ui_protocol_dialog_check as lab
from scripts.lab.ui_protocol_dialog_check import isolated_browser, isolated_panel, require


@pytest.fixture
def landing_browser(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "SUBSCRIPTION_URL", "https://sub.example")
    monkeypatch.setattr(lab, "SUBSCRIPTION_HOST", "127.0.0.1")
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        yield browser


def seed_page(browser, name, username, *, grants=True):
    api = browser.fixture.api
    client = api("/api/clients", "POST", {"display_name": name, "subscription": False})
    if grants:
        issued = api(f"/api/clients/{client['id']}/grants", "POST", {"grants": [
            {"protocol": "trusttunnel", "node_id": "local", "runtime_username": username, "options": {}},
            {"protocol": "mtproxy", "node_id": "local", "runtime_username": username + "-tg", "options": {}},
        ]})
        require(issued.get("status") == "succeeded", "synthetic grants were not issued")
    created = api(f"/api/clients/{client['id']}/subscription", "POST")
    # This is a test-owned reveal in a fresh temporary panel, never an installed node.
    payload = api(f"/api/reveal/{created['reveal_token']}")
    return client["id"], payload


def navigate(browser, payload, lang, width=390, theme="light"):
    browser.dt.call("Emulation.setDeviceMetricsOverride", {
        "width": width, "height": 900 if width > 600 else 844,
        "deviceScaleFactor": 1, "mobile": width < 600,
    })
    browser.dt.call("Emulation.setEmulatedMedia", {
        "features": [{"name": "prefers-color-scheme", "value": theme}],
    })
    path = urlsplit(payload["url"]).path
    query = f"?format=html&lang={lang}&isolated={secrets.token_hex(4)}"
    browser.dt.call("Page.navigate", {"url": f"{browser.fixture.base}{path}{query}"})
    browser.wait("document.readyState === 'complete' && !!document.querySelector('header h1') && "
                 f"location.search === {json.dumps(query)} && "
                 f"document.documentElement.lang === {json.dumps(lang)}", "public landing rendered")


def fits(browser):
    require(browser.js("""(() => {
      const root = document.documentElement;
      return root.scrollWidth <= root.clientWidth + 1 &&
        [...document.body.querySelectorAll('*')].filter(n => n.getClientRects().length).every(n => {
          const r = n.getBoundingClientRect();
          return r.left >= -1 && r.right <= innerWidth + 1;
        });
    })()"""), "landing has horizontal overflow")


def screenshot(browser, name):
    destination = os.environ.get("SUBSCRIPTION_LANDING_SHOTS")
    if not destination:
        return
    # Deliberately bypass ProtocolBrowser.shot: this fixture contains synthetic access
    # credentials, which that helper correctly forbids photographing in real dialogs.
    directory = Path(destination)
    directory.mkdir(parents=True, exist_ok=True)
    browser.js("window.scrollTo(0, 0); true")
    browser.js("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve(true))))")
    image = browser.dt.call("Page.captureScreenshot", {"format": "png"})
    (directory / name).write_bytes(base64.b64decode(image["data"]))


def test_public_landing_is_compact_localized_and_preserves_connection_actions(landing_browser):
    browser = landing_browser
    name = "Мамин телефон & Phone"
    _, payload = seed_page(browser, name, "landing-phone")
    catalogue = browser.fixture.api("/api/subscriptions/compatibility")
    for lang in ("ru", "en"):
        for width in (320, 390, 1440):
            for theme in ("light", "dark"):
                navigate(browser, payload, lang, width, theme)
                require(browser.js("document.querySelector('header h1').textContent === " + json.dumps(name)),
                        "hero must show the client name without a technical prefix")
                require(browser.js("!!document.querySelector('nav a[href=\"#connect\"]') && "
                                   "!!document.querySelector('nav a[href=\"#accesses\"]') && "
                                   "!!document.querySelector('#connect .connect-card, #connect.connect-card') && "
                                   "!!document.querySelector('#accesses')"), "main navigation or connect section missing")
                require(browser.js("document.querySelector('[data-available-count]')?.dataset.availableCount === '2'"),
                        "hero available count does not match usable grants")
                require(browser.js("document.querySelectorAll('.apps-grid details.app').length > 0 && "
                                   "document.querySelectorAll('details.card').length === 2 && "
                                   "![...document.querySelectorAll('details')].some(d => d.open)"),
                        "apps, accesses and QR disclosures must start folded")
                expected = "Доступен" if lang == "ru" else "Available"
                require(browser.js("document.querySelectorAll('details.card .access-summary').length === 2 && "
                                   "[...document.querySelectorAll('details.card .access-summary')].every(s => "
                                   "(/MTProxy|TrustTunnel/).test(s.textContent) && "
                                   "s.querySelector('.access-state')?.textContent === " + json.dumps(expected) + ")"),
                        "access summaries must include protocol and localized state")
                fits(browser)
                require(browser.js("matchMedia('(prefers-color-scheme: dark)').matches === "
                                   + str(theme == "dark").lower()), "browser color scheme was not applied")
                screenshot(browser, f"landing-{lang}-{width}-{theme}.png")
                browser.healthy()

    # Compare actual import schemes against the compatibility catalogue, without
    # returning any URL to pytest assertion introspection or browser logs.
    checked = 0
    for app in catalogue["apps"]:
        variant = payload["variants"].get(app["variant"])
        if not variant or not app.get("deeplink"):
            continue
        href = (app["deeplink"].replace("{url_enc}", quote(variant["url"], safe=""))
                .replace("{name_enc}", quote(name, safe="")).replace("{url}", variant["url"]))
        present = browser.js("[...document.querySelectorAll('.apps-grid details.app')].some(a => "
                             "a.querySelector('summary')?.textContent.includes(" + json.dumps(app["name"]) + "))")
        if present:
            require(browser.js("[...document.querySelectorAll('.apps-grid details.app a[href]')].some(a => "
                               "a.getAttribute('href') === " + json.dumps(href) + ")"),
                    "app import scheme or variant changed")
            checked += 1
    # TrustTunnel currently has one proven direct-import app (FlClash); the
    # other eligible apps require pasting the subscription. Pin completeness
    # against the catalogue rather than inventing a minimum app count.
    expected = [app for app in catalogue["apps"]
                if app["variant"] in payload["variants"]
                and app["protocols"].get("trusttunnel") in ("works", "unverified")]
    expected_imports = sum(bool(app.get("deeplink")) for app in expected)
    require(checked == expected_imports and checked > 0, "not every catalogue import was verified")
    for app in expected:
        if app.get("deeplink"):
            continue
        link = payload["variants"][app["variant"]]["url"]
        require(browser.js("[...document.querySelectorAll('.apps-grid details.app')].some(a => "
                           "a.querySelector('summary')?.textContent.includes(" + json.dumps(app["name"]) + ") && "
                           "[...a.querySelectorAll('[data-copy]')].some(b => "
                           "document.getElementById(b.dataset.copy)?.textContent === " + json.dumps(link) + "))"),
                "a manual-import app lost its subscription URL")
    require(browser.js("!!document.querySelector('details.card a[href^=\"tg://proxy?\"]') && "
                       "!!document.querySelector('details.card a[href^=\"tt://?\"]')"),
            "native Telegram or TrustTunnel action missing")
    browser.click('nav a[href="#connect"]')
    browser.wait("location.hash === '#connect'", "connect navigation")
    browser.click("#connect details.qr > summary")
    require(browser.js("document.querySelector('#connect details.qr')?.open === true && "
                       "document.querySelector('#connect details.qr img')?.getBoundingClientRect().height > 0"),
            "QR should become visible only after explicit disclosure")
    browser.js("window.__landingCopied = null; Object.defineProperty(navigator, 'clipboard', "
               "{configurable:true,value:{writeText:async text => {window.__landingCopied = text;}}}); true")
    browser.click("#connect [data-copy]")
    browser.wait("(() => { const b = document.querySelector('#connect [data-copy]'); "
                 "return window.__landingCopied === document.getElementById(b.dataset.copy).textContent && "
                 "b.textContent === b.dataset.done; })()", "copy uses the correct source and reports success")
    browser.js("document.querySelectorAll('details').forEach(d => d.open = true); true")
    for width in (320, 390, 1440):
        browser.dt.call("Emulation.setDeviceMetricsOverride", {
            "width": width, "height": 844, "deviceScaleFactor": 1, "mobile": width < 600,
        })
        fits(browser)
    browser.healthy()


def test_unavailable_disabled_and_empty_accesses_never_claim_to_be_ready(landing_browser):
    browser = landing_browser
    client_id, payload = seed_page(browser, "State check", "landing-state")
    # Seed failures the UI must explain; do not alter or reveal any live-node state.
    with browser.fixture.central.db(write=True) as db:
        db.execute("UPDATE access_grants SET secret_id=NULL,secret_version=NULL "
                   "WHERE client_id=? AND protocol='trusttunnel'", (client_id,))
        db.execute("UPDATE access_grants SET desired_state='disabled' "
                   "WHERE client_id=? AND protocol='mtproxy'", (client_id,))
    for lang, states in (("ru", ["Недоступен", "Отключён"]), ("en", ["Unavailable", "Off"])):
        navigate(browser, payload, lang, 320, "dark")
        require(browser.js("document.querySelector('[data-available-count]')?.dataset.availableCount === '0' && "
                           "document.querySelectorAll('details.card').length === 2"),
                "unusable grants must remain visible without inflating available count")
        require(browser.js("JSON.stringify([...document.querySelectorAll('details.card .access-state')]"
                           ".map(s => s.textContent).sort()) === JSON.stringify(" + json.dumps(sorted(states)) + ")"),
                "missing credentials and disabled access need different localized states")
        require(browser.js("!document.querySelector('details.card a[href^=\"tt://\"], details.card a[href^=\"tg://\"]')"),
                "unusable access must not offer a native connect action")
        fits(browser)
        browser.healthy()
    _, empty_payload = seed_page(browser, "Empty phone", "landing-empty", grants=False)
    for lang in ("ru", "en"):
        navigate(browser, empty_payload, lang)
        require(browser.js("document.querySelector('[data-available-count]')?.dataset.availableCount === '0' && "
                           "document.querySelectorAll('details.card').length === 0"),
                "empty subscription must have zero usable grants")
        fits(browser)
        browser.healthy()


def test_amnezia_page_download_and_copy_match_the_escrowed_config(landing_browser, tmp_path):
    browser = landing_browser
    api = browser.fixture.api
    client = api('/api/clients', 'POST', {'display_name': 'Tunnel', 'subscription': False})
    issued = api(f"/api/clients/{client['id']}/grants", 'POST', {'grants': [
        {'protocol': 'amneziawg', 'node_id': 'local', 'runtime_username': 'tunnel', 'options': {'version': '2.0'}},
    ]})
    require(issued['status'] == 'succeeded', 'tunnel issuance failed')
    links = api(f"/api/clients/{client['id']}/links?protocol=amneziawg", 'POST')
    conf = api(f"/api/reveal/{links['reveal_token']}")['grants'][0]['artifacts'][0]['value']
    created = api(f"/api/clients/{client['id']}/subscription", 'POST')
    payload = api(f"/api/reveal/{created['reveal_token']}")
    navigate(browser, payload, 'ru', 390, 'dark')
    browser.click('details.card > summary')
    require(browser.js("!!document.querySelector('details.card details.config-source:not([open])')"),
            'full tunnel config must start collapsed')
    browser.js("window.__copiedConfig = null; Object.defineProperty(navigator, 'clipboard', "
               "{configurable:true,value:{writeText:async text => {window.__copiedConfig = text;}}}); true")
    browser.click('details.card button[data-copy]')
    browser.wait('window.__copiedConfig === ' + json.dumps(conf), 'correct config copied')
    downloads = tmp_path / 'downloads'
    downloads.mkdir()
    browser.dt.call('Browser.setDownloadBehavior', {'behavior': 'allow', 'downloadPath': str(downloads)})
    browser.click('details.card a[download="amneziawg.conf"]')
    deadline = time.monotonic() + 10
    downloaded = downloads / 'amneziawg.conf'
    while not downloaded.is_file() and time.monotonic() < deadline:
        time.sleep(0.05)
    require(downloaded.is_file(), 'configuration download did not complete')
    require(hashlib.sha256(downloaded.read_bytes()).digest() == hashlib.sha256(conf.encode()).digest(),
            'downloaded configuration differs from escrow')
    require(browser.js("!!document.querySelector('details.card details.qr img')"), 'configuration QR missing')
    fits(browser)
    browser.healthy()
