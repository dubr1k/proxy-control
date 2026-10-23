"""Real-browser regressions for the «Новый клиент» dialog and archiving (isolated stand).

Fresh databases and memory managers as in test_protocol_dialog_browser.py; the central is
the real application, Chrome is driven over DevTools.
"""
import re
import secrets
from pathlib import Path

import pytest

from scripts.lab.ui_protocol_dialog_check import isolated_browser, isolated_panel


@pytest.fixture
def clients_browser(tmp_path: Path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        yield browser


def open_clients(browser):
    nonce = secrets.token_hex(4)
    browser.dt.call("Page.navigate", {"url": f"{browser.fixture.base}/?clients={nonce}#clients"})
    browser.wait(f"location.search === '?clients={nonce}' && !!document.querySelector('.client-list')", "clients screen")
    browser.wait("!!document.querySelector('#add') && !document.querySelector('#add').hidden", "add button")


def open_dialog(browser):
    browser.click("#add")
    browser.wait("document.querySelector('#client-modal')?.open === true", "client dialog")
    browser.wait("!!document.querySelector('#client-placement input[data-node=\"local\"][data-protocol=\"mtproxy\"]')", "placement")


def tick_mtproxy(browser):
    browser.js("""(() => { const box = document.querySelector('#client-placement input[data-node="local"][data-protocol="mtproxy"]');
      box.checked = true; box.dispatchEvent(new Event('change', {bubbles: true})); return true; })()""")


def type_name(browser, name):
    browser.set_value("#client-name", name)


def username(browser):
    return browser.js("document.querySelector('#client-username').value")


def grant_mtproxy(browser, client_id, account):
    return browser.fixture.api(f"/api/clients/{client_id}/grants", "POST", {
        "grants": [{"protocol": "mtproxy", "node_id": "local", "runtime_username": account, "options": {}}],
    })


def clients_named(browser, name):
    return [entry for entry in browser.fixture.api("/api/clients")["items"] if entry["client"]["display_name"] == name]


def test_create_button_gets_its_label_back_after_two_busy_steps(clients_browser):
    browser = clients_browser
    open_clients(browser)
    open_dialog(browser)
    type_name(browser, "Брат")
    tick_mtproxy(browser)
    browser.click("#create-client")
    browser.wait("document.querySelector('#client-modal').open === false", "dialog closed after creation")
    browser.wait("!document.querySelector('#create-client').hasAttribute('aria-busy')", "button idle")
    assert browser.js("document.querySelector('#create-client').textContent.trim()") == "Создать"
    assert len(clients_named(browser, "Брат")) == 1
    browser.healthy()


def test_account_name_follows_the_display_name_typed_after_the_ticks(clients_browser):
    browser = clients_browser
    open_clients(browser)
    open_dialog(browser)
    tick_mtproxy(browser)
    assert username(browser) == "client"
    type_name(browser, "Сестра — телефон")
    assert username(browser) == "sestra-telefon"
    # an own name is never overwritten
    browser.set_value("#client-username", "mine")
    browser.js("document.querySelector('#client-username').dispatchEvent(new Event('input', {bubbles: true})); true")
    type_name(browser, "Другое имя")
    assert username(browser) == "mine"
    browser.healthy()


def test_proposal_skips_a_name_already_in_use_on_the_ticked_node_and_protocol(clients_browser):
    browser = clients_browser
    first = browser.fixture.api("/api/clients", "POST", {"display_name": "Первая", "subscription": False})["id"]
    grant_mtproxy(browser, first, "sestra-telefon")
    second = browser.fixture.api("/api/clients", "POST", {"display_name": "Вторая", "subscription": False})["id"]
    grant_mtproxy(browser, second, "sestra-telefon-2")
    open_clients(browser)
    open_dialog(browser)
    type_name(browser, "Сестра — телефон")
    tick_mtproxy(browser)
    assert username(browser) == "sestra-telefon-3"
    browser.healthy()


def test_retry_after_refused_grants_does_not_create_a_second_client(clients_browser):
    browser = clients_browser
    holder = browser.fixture.api("/api/clients", "POST", {"display_name": "Занявший", "subscription": False})["id"]
    grant_mtproxy(browser, holder, "taken-name")
    open_clients(browser)
    open_dialog(browser)
    type_name(browser, "Новичок")
    tick_mtproxy(browser)
    browser.set_value("#client-username", "taken-name")
    browser.js("document.querySelector('#client-username').dispatchEvent(new Event('input', {bubbles: true})); true")
    browser.click("#create-client")
    browser.wait("!!document.querySelector('#client-error').textContent && !document.querySelector('#create-client').hasAttribute('aria-busy')", "refusal shown")
    error = browser.js("document.querySelector('#client-error').textContent")
    assert "создан, но доступы не выданы" in error and "Имя учётной записи уже занято на узле" in error, error
    assert not re.search(r"runtime[ _]username", error), error
    assert browser.js("document.querySelector('#client-modal').open")
    assert len(clients_named(browser, "Новичок")) == 1
    browser.set_value("#client-username", "fresh-name")
    browser.click("#create-client")
    browser.wait("document.querySelector('#client-modal').open === false", "retry accepted")
    created = clients_named(browser, "Новичок")
    assert len(created) == 1, "the retry must not create a second client"
    assert [grant["runtime_username"] for grant in created[0]["grants"]] == ["fresh-name"]
    browser.healthy()


def test_archive_offers_to_delete_the_accesses_first(clients_browser):
    browser = clients_browser
    client_id = browser.fixture.api("/api/clients", "POST", {"display_name": "Уходящий", "subscription": False})["id"]
    grant_mtproxy(browser, client_id, "leaving")
    open_clients(browser)
    browser.wait("!!document.querySelector('[data-client-id] [data-client-action=\"archive\"]')", "archive button")
    browser.click('[data-client-id="%s"] [data-client-action="archive"]' % client_id)
    browser.wait("document.querySelector('#confirm').open === true", "confirm dialog")
    assert "Удалить доступы (1) и архивировать" in browser.js("document.querySelector('#confirm-ok').textContent")
    browser.click("#confirm-ok")
    browser.wait("document.querySelector('#confirm').open === false", "confirm closed")
    toasts = "[...document.querySelectorAll('.toast')].map(t => t.textContent).join('|')"
    browser.wait(f"({toasts}).includes('Состояние клиента обновлено')", "archived toast")
    entry = browser.fixture.api(f"/api/clients/{client_id}")
    assert entry["client"]["state"] == "archived" and entry["grants"] == []
    browser.healthy()


def test_an_archived_client_is_deleted_from_its_menu_after_a_confirm(clients_browser):
    browser = clients_browser
    api = browser.fixture.api
    client_id = api("/api/clients", "POST", {"display_name": "Лишний", "subscription": False})["id"]
    api(f"/api/clients/{client_id}/state", "POST", {"state": "archived"})
    open_clients(browser)
    browser.click("[data-client-filter-state=archived]")
    card = '[data-client-id="%s"]' % client_id
    browser.wait(f"!!document.querySelector('{card} .client-menu-button')", "archived card menu")
    browser.click(f"{card} .client-menu-button")
    browser.click(f'{card} [data-client-action="delete"]')
    browser.wait("document.querySelector('#confirm').open === true", "confirm dialog")
    assert browser.js("document.querySelector('#confirm-ok').textContent").strip() == "Удалить навсегда"
    browser.click("#confirm-ok")
    toasts = "[...document.querySelectorAll('.toast')].map(t => t.textContent).join('|')"
    browser.wait(f"({toasts}).includes('Клиент удалён')", "deleted toast")
    assert all(entry["client"]["id"] != client_id for entry in api("/api/clients")["items"])
    browser.healthy()


def test_known_server_refusals_read_in_russian(clients_browser):
    browser = clients_browser
    open_clients(browser)
    shown = browser.js("""import('/static/js/api.js').then(({problemText}) => [
      problemText({detail: 'invalid credentials'}),
      problemText({detail: 'client still has grants that are not deleted'}),
      problemText({detail: 'naive: runtime username already exists'}),
      problemText({detail: 'something unknown'}),
    ])""")
    assert shown == [
        "Неверный логин или пароль",
        "У клиента остались неудалённые доступы",
        "Имя учётной записи уже занято на узле: NaiveProxy",
        "something unknown",
    ]


def test_clients_open_on_active_and_the_badge_skips_the_archive(clients_browser):
    browser = clients_browser
    api = browser.fixture.api
    live = api("/api/clients", "POST", {"display_name": "Рабочий", "subscription": False})["id"]
    gone = api("/api/clients", "POST", {"display_name": "Ушедший", "subscription": False})["id"]
    api(f"/api/clients/{gone}/state", "POST", {"state": "archived"})
    open_clients(browser)
    browser.wait("document.querySelectorAll('.client-card').length >= 1", "cards")
    ids = browser.js("[...document.querySelectorAll('.client-card')].map(c => c.dataset.clientId)")
    assert live in ids and gone not in ids
    assert browser.js("document.querySelector('[data-client-filter-state=active]').getAttribute('aria-pressed')") == "true"
    active = len([e for e in api("/api/clients")["items"] if e["client"]["state"] != "archived"])
    browser.wait(f"document.querySelector('#clients-count').textContent === '{active}'", "badge without the archive")
    browser.healthy()


def test_card_menu_opens_closes_and_acts_on_a_phone(clients_browser):
    browser = clients_browser
    client_id = browser.fixture.api("/api/clients", "POST", {"display_name": "Меню", "subscription": False})["id"]
    browser.dt.call("Emulation.setDeviceMetricsOverride", {"width": 390, "height": 844, "deviceScaleFactor": 1, "mobile": True})
    open_clients(browser)
    card = '[data-client-id="%s"]' % client_id
    browser.wait(f"!!document.querySelector('{card} .client-menu-button')", "menu button")
    state = f"""(() => {{ const b = document.querySelector('{card} .client-menu-button');
      return [b.getAttribute('aria-expanded'), document.querySelector('{card} .client-menu-list').hidden]; }})()"""
    assert browser.js(state) == ["false", True]
    # the card is only «Открыть», «Узлы и доступы» and «⋯»; nothing runs out of a 390 px screen
    assert browser.js(f"document.querySelectorAll('{card} .client-actions > button').length") == 2
    assert browser.js("document.documentElement.scrollWidth <= window.innerWidth + 1") is True
    browser.click(f"{card} .client-menu-button")
    assert browser.js(state) == ["true", False]
    assert browser.js("document.activeElement.dataset.clientAction") == "rename"
    assert browser.js(f"""(() => {{ const r = document.querySelector('{card} .client-menu-list').getBoundingClientRect();
      return r.left >= 0 && r.right <= window.innerWidth; }})()""") is True
    browser.js("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape', bubbles: true})); true")
    assert browser.js(state) == ["false", True]
    assert browser.js(f"document.activeElement === document.querySelector('{card} .client-menu-button')") is True
    browser.click(f"{card} .client-menu-button")
    browser.js("document.body.click(); true")
    assert browser.js(state) == ["false", True]
    # an item runs the same action as before: suspending goes through the lifecycle call
    browser.click(f"{card} .client-menu-button")
    browser.click(f'{card} [data-client-action="suspend"]')
    toasts = "[...document.querySelectorAll('.toast')].map(t => t.textContent).join('|')"
    browser.wait(f"({toasts}).includes('Состояние клиента обновлено')", "suspended toast")
    assert browser.fixture.api(f"/api/clients/{client_id}")["client"]["state"] == "suspended"
    browser.healthy()
