"""Real-browser check of the end-user subscription page at 390 px: styled, no sideways scroll,
the strict CSP lets the copy script run, sections are folded, the QR is behind a button."""
import base64
import os
import time
from pathlib import Path

import pytest

from scripts.lab import ui_protocol_dialog_check as lab
from scripts.lab.ui_protocol_dialog_check import isolated_browser, isolated_panel

ACTOR = {"id": 1, "username": "owner"}


@pytest.fixture
def page_browser(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(lab, "SUBSCRIPTION_URL", "https://sub.example")
    monkeypatch.setattr(lab, "SUBSCRIPTION_HOST", "127.0.0.1")
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        yield browser


def open_page(browser, width=390):
    fixture = browser.fixture
    client_id = fixture.api("/api/clients", "POST", {"display_name": "Мама", "subscription": False})["id"]
    result = fixture.api(f"/api/clients/{client_id}/grants", "POST", {"grants": [
        {"protocol": "trusttunnel", "node_id": "local", "runtime_username": "mama", "options": {}},
        {"protocol": "mtproxy", "node_id": "local", "runtime_username": "mama-tg", "options": {}},
    ]})
    assert result["status"] == "succeeded", result
    token = fixture.central.state.subscriptions.create(client_id, actor=ACTOR, ip="127.0.0.1", request_id="r")[1]
    browser.dt.call("Emulation.setDeviceMetricsOverride", {"width": width, "height": 844, "deviceScaleFactor": 2, "mobile": True})
    browser.dt.call("Page.navigate", {"url": f"{fixture.base}/s/{token}"})
    browser.wait("document.readyState === 'complete' && !!document.querySelector('footer')", "subscription page")


def test_the_page_fits_a_phone_and_its_copy_script_runs_under_the_strict_policy(page_browser):
    browser = page_browser
    open_page(browser)
    assert browser.js("document.documentElement.lang") == "ru"
    # Styled: the stylesheet was admitted by hash, the cards have a border and the buttons are tall enough to tap.
    assert browser.js("getComputedStyle(document.querySelector('.card')).borderTopWidth") == "1px"
    assert browser.js("document.querySelector('.btn').getBoundingClientRect().height >= 44")
    # The first screen is the update block with its buttons; the QR and every access are folded.
    assert browser.js("document.querySelector('main section h2').textContent") == "Подписка обновляется сама"
    assert browser.js("[...document.querySelectorAll('details')].some(d => d.open)") is False
    assert browser.js("[...document.querySelectorAll('.btn')].some(b => b.textContent.startsWith('Добавить в FlClash'))")
    for width in (390, 320):
        browser.dt.call("Emulation.setDeviceMetricsOverride", {"width": width, "height": 844, "deviceScaleFactor": 2, "mobile": True})
        browser.js("document.querySelectorAll('details').forEach(d => d.open = true); true")
        assert browser.js("document.documentElement.scrollWidth <= document.documentElement.clientWidth") is True, width
        assert browser.js("[...document.body.querySelectorAll('*')].filter(n => n.getBoundingClientRect().right > innerWidth + 1).length") == 0, width
    # «Копировать ссылку подписки» runs through the hashed inline script: its label flips, then comes back.
    first = browser.js("document.querySelector('main section [data-copy]').dataset.copy")
    browser.click(f"[data-copy=\"{first}\"]")
    assert browser.js(f"document.querySelector('[data-copy=\"{first}\"]').textContent") in ("Скопировано", "Не получилось — выделите вручную")
    assert browser.js("window.__protocolCsp") == 0 and browser.js("window.__protocolErrors") == 0
    shot = os.environ.get("SUBSCRIPTION_PAGE_SHOT")
    if shot:  # an operator's look at the page; never written into the repository
        browser.js("document.querySelectorAll('details').forEach(d => d.open = false); window.scrollTo(0, 0); true")
        time.sleep(0.3)
        image = browser.dt.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})
        Path(shot).write_bytes(base64.b64decode(image["data"]))
