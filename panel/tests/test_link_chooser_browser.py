"""Real-browser checks of «На чём клиент?»: the chooser in the client window and in the access
bundle (isolated stand, Chrome over DevTools, a subscription domain configured)."""
import json
import secrets
import time
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
    browser.wait(f"location.search === '?clients={nonce}' && !!document.querySelector('.client-list')", "clients screen")
    browser.wait("!!document.querySelector('#add') && !document.querySelector('#add').hidden", "add button")


def client_with_trusttunnel(browser, name="Мама"):
    client_id = browser.fixture.api("/api/clients", "POST", {"display_name": name})["id"]
    result = browser.fixture.api(f"/api/clients/{client_id}/grants", "POST", {
        "grants": [{"protocol": "trusttunnel", "node_id": "local", "runtime_username": "mama", "options": {}}],
    })
    assert result["status"] == "succeeded", result
    return client_id


def pick(browser, value):
    browser.js(f"document.querySelector('#subscription-chooser input[value=\"{value}\"]').click(); true")


def chooser_text(browser, selector):
    return browser.js(f"document.querySelector({json.dumps(selector)})?.textContent.replace(/\\s+/g, ' ').trim() ?? null")


def test_android_hiddify_gives_the_hiddify_link_and_its_deep_link(chooser_browser):
    browser = chooser_browser
    client_id = client_with_trusttunnel(browser)
    open_clients(browser)
    browser.click(f'[data-client-id="{client_id}"] [data-client-action="open"]')
    browser.wait("!!document.querySelector('#subscription-actions [data-subscription-action=\"show\"]')", "show button")
    # Nothing of the link is on the screen before «Показать».
    assert browser.js("document.querySelector('#subscription-reveal').hidden")
    browser.click('#subscription-actions [data-subscription-action="show"]')
    browser.wait("!document.querySelector('#subscription-reveal').hidden", "link shown")
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
    link = browser.js("document.querySelector('#subscription-chooser [data-chooser-url]').value")
    assert link.startswith(f"{BASE}/s/") and link.endswith("?format=singbox&client=hiddify"), link
    href = browser.js("document.querySelector('#subscription-chooser [data-chooser-open]').getAttribute('href')")
    assert href == f"hiddify://import/{link}#%D0%9C%D0%B0%D0%BC%D0%B0", href
    assert "Должен получить, но мы это не проверяли: TrustTunnel." in chooser_text(browser, "#subscription-chooser .chooser-gets")
    assert browser.js("document.querySelector('#subscription-chooser .subscription-qr').src.startsWith('data:image/svg+xml')")
    # The Clash family: its own variant; Clash Mi has no verified scheme, so no button.
    pick(browser, "clashmi")
    browser.wait("document.querySelector('#subscription-chooser .chooser-result h4').textContent === 'Clash Mi'", "Clash Mi result")
    assert browser.js("document.querySelector('#subscription-chooser [data-chooser-url]').value").endswith("?format=clash")
    assert browser.js("document.querySelector('#subscription-chooser [data-chooser-open]')") is None
    pick(browser, "flclash")
    browser.wait("document.querySelector('#subscription-chooser .chooser-result h4').textContent === 'FlClash'", "FlClash result")
    flclash = browser.js("document.querySelector('#subscription-chooser [data-chooser-open]').getAttribute('href')")
    assert flclash.startswith("clash://install-config?url=https%3A%2F%2Fsub.example%2Fs%2F") and flclash.endswith("%3Fformat%3Dclash"), flclash
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


def test_the_bundle_opens_on_the_link_folds_the_rest_and_asks_before_closing(chooser_browser):
    browser = chooser_browser
    open_clients(browser)
    browser.click("#add")
    browser.wait("document.querySelector('#client-modal')?.open === true", "client dialog")
    browser.wait("!!document.querySelector('#client-placement input[data-node=\"local\"][data-protocol=\"trusttunnel\"]')", "placement")
    browser.set_value("#client-name", "Мама")
    browser.js("""(() => { const box = document.querySelector('#client-placement input[data-node="local"][data-protocol="trusttunnel"]');
      box.checked = true; box.dispatchEvent(new Event('change', {bubbles: true})); return true; })()""")
    browser.click("#create-client")
    browser.wait("document.querySelector('#bundle-modal').open === true", "bundle")
    # Order: the link block on top, the per-protocol data folded below it.
    order = browser.js("""(() => { const top = (s) => document.querySelector(s).getBoundingClientRect().top;
      return [top('#bundle-subscription') < top('#bundle-details'), document.querySelector('#bundle-details').open,
        document.querySelector('#bundle-details').getBoundingClientRect().height < 80]; })()""")
    assert order == [True, False, True], order
    assert chooser_text(browser, "#bundle-details summary") == "Отдельные ссылки и данные для ручной настройки"
    # Closing with nothing taken asks once; «Отмена» keeps the window.
    browser.click("#bundle-modal .modal-head-actions button.primary")
    browser.wait("document.querySelector('#confirm').open === true", "close confirm")
    assert chooser_text(browser, "#confirm-title") == "Ссылки больше не покажутся. Закрыть?"
    browser.js("document.querySelector('#confirm button[value=\"cancel\"]').click(); true")
    browser.wait("document.querySelector('#confirm').open === false", "confirm dismissed")
    assert browser.js("document.querySelector('#bundle-modal').open")
    # Esc asks the same way (the dialog's `close` event, which ends the first question, is a task behind `open`).
    time.sleep(0.3)
    assert browser.js("""(() => { const event = new Event('cancel', {cancelable: true});
      document.querySelector('#bundle-modal').dispatchEvent(event); return event.defaultPrevented; })()""")
    browser.wait("document.querySelector('#confirm').open === true", "confirm after Esc")
    browser.js("document.querySelector('#confirm button[value=\"cancel\"]').click(); true")
    browser.wait("document.querySelector('#confirm').open === false", "confirm dismissed again")
    # The folded data are all there, secrets in the open.
    browser.js("document.querySelector('#bundle-details').open = true; true")
    assert browser.js("document.querySelectorAll('#bundle-body .bundle-grant').length") >= 1
    assert browser.js("!document.querySelector('#bundle-body').textContent.includes('••••') && !document.querySelector('#bundle-body [data-tt-reveal]')")
    # Taking the link (a copy) lets the window close without a question.
    browser.js("document.querySelector('#bundle-details').open = false; true")
    pick_bundle = "document.querySelector('#bundle-chooser input[value=\"windows\"]').click(); true"
    browser.js(pick_bundle)
    browser.wait("!!document.querySelector('#bundle-chooser button[data-copy]')", "copy button")
    browser.click("#bundle-chooser button[data-copy]")
    browser.click("#bundle-modal .modal-head-actions button.primary")
    browser.wait("document.querySelector('#bundle-modal').open === false", "closed without a question")
    assert browser.js("document.querySelector('#confirm').open") is False
    browser.healthy()
