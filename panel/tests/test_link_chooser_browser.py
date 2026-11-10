"""Real-browser checks of «На чём клиент?»: the chooser in the client window and in the access
bundle (isolated stand, Chrome over DevTools, a subscription domain configured)."""
import json
import secrets

from urllib.parse import quote
from pathlib import Path

import pytest

from scripts.lab import ui_protocol_dialog_check as lab
from scripts.lab.ui_protocol_dialog_check import isolated_browser, isolated_panel

BASE = "https://sub.example"


@pytest.fixture
def chooser_browser(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(lab, "SUBSCRIPTION_URL", BASE)
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        yield browser


def open_clients(browser):
    nonce = secrets.token_hex(4)
    browser.dt.call("Page.navigate", {"url": f"{browser.fixture.base}/?clients={nonce}#clients"})
    browser.wait(f"location.search === '?clients={nonce}' && location.hash === '#clients' && !!document.querySelector('#view .client-list, #view .empty-state')", "clients screen, with or without existing clients")
    browser.wait("!!document.querySelector('#add') && !document.querySelector('#add').hidden", "add button")


def client_with_trusttunnel(browser, name="Мама"):
    client_id = browser.fixture.api("/api/clients", "POST", {"display_name": name})["id"]
    result = browser.fixture.api(f"/api/clients/{client_id}/grants", "POST", {
        "grants": [{"protocol": "trusttunnel", "node_id": "local", "runtime_username": "mama", "options": {}}],
    })
    assert result["status"] == "succeeded", result
    return client_id


def key(browser, kind, name, code):
    browser.dt.call("Input.dispatchKeyEvent", {"type": kind, "key": name, "code": name, "windowsVirtualKeyCode": code, "nativeVirtualKeyCode": code})


def press_escape(browser, expression, label):
    # A real click first: the browser lets a page cancel Esc only after a user gesture.
    x, y = browser.js("""(() => { const r = document.querySelector('#bundle-title').getBoundingClientRect(); return [r.left + 4, r.top + r.height / 2]; })()""")
    for kind in ("mousePressed", "mouseReleased"):
        browser.dt.call("Input.dispatchMouseEvent", {"type": kind, "x": x, "y": y, "button": "left", "clickCount": 1})
    key(browser, "rawKeyDown", "Escape", 27)
    key(browser, "keyUp", "Escape", 27)
    browser.wait(expression, label)


def pick(browser, value):
    browser.js(f"document.querySelector('#subscription-chooser input[value=\"{value}\"]').click(); true")


def chooser_text(browser, selector):
    return browser.js(f"document.querySelector({json.dumps(selector)})?.textContent.replace(/\\s+/g, ' ').trim() ?? null")


def test_android_hiddify_gives_the_hiddify_link_and_its_deep_link(chooser_browser):
    browser = chooser_browser
    client_id = client_with_trusttunnel(browser)
    open_clients(browser)
    browser.click(f'[data-client-id="{client_id}"] [data-client-action="subscription"]')
    browser.wait("!document.querySelector('#subscription-reveal').hidden", "link shown")
    assert browser.js("!!document.querySelector('#subscription-chooser [data-client-page-url]')")
    browser.click('#subscription-chooser [data-delivery-mode="import"]')
    assert chooser_text(browser, "#subscription-chooser legend") == "На чём клиент?"
    # The six raw variants are folded away.
    assert browser.js("document.querySelector('.subscription-all').open") is False
    assert browser.js("document.querySelectorAll('#subscription-variants input[name=\"subscription-format\"]').length") == 6
    # No platform chosen, no link shown yet.
    assert browser.js("document.querySelector('#subscription-chooser [data-chooser-url]')") is None
    pick(browser, "android")
    browser.wait("!!document.querySelector('#subscription-chooser [data-chooser-url]')", "link for the recommended app")
    names = browser.js("[...document.querySelectorAll('#subscription-chooser input[name$=\"-app\"]')].map(i => i.value)")
    assert "hiddify" in names and "flclash" in names and "karing" not in names  # Karing delivers no TrustTunnel
    pick(browser, "hiddify")
    browser.wait("document.querySelector('#subscription-chooser .chooser-result h4').textContent === 'Hiddify'", "Hiddify result")
    assert browser.js("""(() => { const link = document.querySelector('#subscription-chooser [data-chooser-url]').value;
      const href = document.querySelector('#subscription-chooser [data-chooser-open]').getAttribute('href');
      return link.startsWith('https://sub.example/s/') && link.endsWith('?format=singbox&client=hiddify')
        && href === 'hiddify://import/' + link + '#%D0%9C%D0%B0%D0%BC%D0%B0'; })()""")
    assert chooser_text(browser, "#subscription-chooser .chooser-gets") == "В выпусках приложения пока нет: TrustTunnel."
    # A client whose only protocol is TrustTunnel is not promised Hiddify first: FlClash really carries it.
    assert chooser_text(browser, "#subscription-chooser .chooser-chip:has(em)") == "FlClash рекомендуем"
    assert browser.js("document.querySelector('#subscription-chooser .subscription-qr').src.startsWith('data:image/svg+xml')")
    # The Clash family: its own variant; Clash Mi has no verified scheme, so no button.
    pick(browser, "clashmi")
    browser.wait("document.querySelector('#subscription-chooser .chooser-result h4').textContent === 'Clash Mi'", "Clash Mi result")
    assert browser.js("document.querySelector('#subscription-chooser [data-chooser-url]').value.endsWith('?format=clash')")
    assert browser.js("document.querySelector('#subscription-chooser [data-chooser-open]')") is None
    pick(browser, "flclash")
    browser.wait("document.querySelector('#subscription-chooser .chooser-result h4').textContent === 'FlClash'", "FlClash result")
    assert browser.js("""(() => {const href = document.querySelector('#subscription-chooser [data-chooser-open]').getAttribute('href');
      return href.startsWith('clash://install-config?url=https%3A%2F%2Fsub.example%2Fs%2F') && href.endsWith('%3Fformat%3Dclash'); })()""")
    # An app of another platform goes away with the platform.
    pick(browser, "ios")
    browser.wait("!!document.querySelector('#subscription-chooser input[value=\"ios\"]:checked')", "iOS chosen")
    assert "karing" not in browser.js("[...document.querySelectorAll('#subscription-chooser input[name$=\"-app\"]')].map(i => i.value)")
    # On a phone nothing leaves the window sideways, even with the longest app name and the link open.
    browser.dt.call("Emulation.setDeviceMetricsOverride", {"width": 390, "height": 844, "deviceScaleFactor": 1, "mobile": True})
    pick(browser, "android")
    browser.js("document.querySelector('.subscription-all').open = true; true")
    sideways = browser.js("""(() => { const form = document.querySelector('#subscription-modal form');
      return [form.scrollWidth <= form.clientWidth + 1, [...form.querySelectorAll('#subscription-reveal *')].filter(n => n.getBoundingClientRect().right > form.getBoundingClientRect().right + 1).length]; })()""")
    assert sideways == [True, 0], sideways
    # The expert text stays one click away, inside the folded block.
    assert "singbox-hiddify" in browser.js("[...document.querySelectorAll('#subscription-variants input')].map(i => i.value)")
    browser.healthy()


def test_creation_opens_the_same_client_page_as_repeat_connection(chooser_browser):
    browser = chooser_browser
    open_clients(browser)
    browser.click("#add")
    browser.wait("document.querySelector('#client-modal')?.open === true", "client dialog")
    browser.wait("!!document.querySelector('#client-placement input[data-node=\"local\"][data-protocol=\"trusttunnel\"]')", "placement")
    browser.set_value("#client-name", "Мама")
    browser.js("""(() => { const box = document.querySelector('#client-placement input[data-node="local"][data-protocol="trusttunnel"]');
      box.checked = true; box.dispatchEvent(new Event('change', {bubbles: true})); return true; })()""")
    browser.click("#create-client")
    browser.wait("document.querySelector('#subscription-modal').open && !!document.querySelector('#subscription-chooser [data-client-page-url]')", "client page")
    assert browser.js("!document.querySelector('#bundle-modal').open")
    assert browser.js("document.querySelector('#subscription-chooser').textContent.includes('Откройте камерой телефона')")
    browser.click('#subscription-modal [value="cancel"]')
    browser.wait("!document.querySelector('#subscription-modal').open", "client page closed")
    assert browser.js("!document.querySelector('#confirm').open")
    browser.healthy()


# The chooser module is driven directly with a crafted catalogue and a hostile display name.
RENDER = """(async (patch, name, protocols) => {
  const module = await import('/static/js/link-chooser.js');
  const catalogue = await (await fetch('/api/subscriptions/compatibility')).json();
  for (const app of catalogue.apps) if (patch[app.id] !== undefined) app.deeplink = patch[app.id];
  const qr = 'data:image/svg+xml;base64,AAAA';
  const variants = Object.fromEntries(['singbox', 'singbox-official', 'singbox-hiddify', 'clash'].map(
    (key) => [key, {url: 'https://sub.example/s/tok?format=' + key + '&x=a b', qr}]));
  document.querySelector('#probe')?.remove();
  const host = document.createElement('div');
  host.id = 'probe';
  document.body.append(host);
  module.renderChooser(host, {catalogue, payload: {url: variants.singbox.url, qr, variants,
    page_url: 'https://sub.example/s/tok?format=html', page_qr: qr}, protocols, name});
  host.querySelector('[data-delivery-mode="import"]').click();
  return true;
})"""

HOSTILE_NAME = "x\"><img id=pwn src=y onerror=1> & 'q' <b>"


def render(browser, app, platform, protocols, name="Мама", patch=None):
    browser.js(f"{RENDER}({json.dumps(patch or {})}, {json.dumps(name)}, {json.dumps(protocols)})")
    browser.js(f"document.querySelector('#probe input[value=\"{platform}\"]').click(); true")
    browser.js(f"document.querySelector('#probe input[value=\"{app}\"]').click(); true")
    browser.wait("document.querySelector('#probe .chooser-result h4')?.textContent !== undefined", "result")


def open_href(browser):
    return browser.js("document.querySelector('#probe [data-chooser-open]')?.getAttribute('href') ?? null")


def test_karing_and_singbox_deep_links_percent_encode_the_link_and_the_name(chooser_browser):
    browser = chooser_browser
    open_clients(browser)
    link = "https://sub.example/s/tok?format={}&x=a b"
    # Karing: name as a query parameter; the name's own & ' < " cannot split or close anything.
    render(browser, "karing", "ios", ["naive", "mieru"], HOSTILE_NAME)
    assert open_href(browser) == f"karing://install-config?url={quote(link.format('singbox'), safe='')}&name={quote(HOSTILE_NAME, safe='')}"
    # sing-box: name after the hash.
    render(browser, "singbox", "ios", ["naive"], HOSTILE_NAME)
    assert open_href(browser) == f"sing-box://import-remote-profile?url={quote(link.format('singbox-official'), safe='')}#{quote(HOSTILE_NAME, safe='')}"
    # Nothing of the name became markup: no injected element, the button keeps its three attributes.
    assert browser.js("document.querySelector('#pwn')") is None
    assert browser.js("[...document.querySelector('#probe [data-chooser-open]').getAttributeNames()]") == ["class", "href", "data-chooser-open"]
    assert browser.js("document.querySelector('#probe').textContent.includes('onerror')") is False
    browser.healthy()


@pytest.mark.parametrize("template", [
    "javascript://x/%0Aalert(1)", "JavaScript://x", "data://text/html,x", "vbscript://x",
    "app://has space", 'app://x"onmouseover="y', "app://x'y", "app://x>y", "app://x<y", "//no-scheme", "app:no-slashes",
])
def test_a_hostile_deep_link_template_gives_no_open_button(chooser_browser, template):
    browser = chooser_browser
    open_clients(browser)
    render(browser, "karing", "ios", ["naive", "mieru"], HOSTILE_NAME, {"karing": template})
    assert open_href(browser) is None
    # The link itself and the copy button are still there.
    assert browser.js("document.querySelector('#probe [data-chooser-url]').value").endswith("&x=a b")
    assert browser.js("document.querySelector('#pwn')") is None
    browser.healthy()


def test_a_name_with_an_apostrophe_still_gets_its_button(chooser_browser):
    browser = chooser_browser
    open_clients(browser)
    render(browser, "karing", "ios", ["naive"], "O'Brien (мама)!")
    assert open_href(browser).endswith("&name=O%27Brien%20%28%D0%BC%D0%B0%D0%BC%D0%B0%29%21")
