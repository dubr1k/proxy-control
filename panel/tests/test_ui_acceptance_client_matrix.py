"""The maintained UI tier selects its three protocols, never unrelated/disabled cells."""
import importlib.util

from pathlib import Path
from types import SimpleNamespace

from scripts.lab.ui_protocol_dialog_check import OverviewFixture, isolated_browser, isolated_panel

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ui_acceptance_matrix', ROOT / 'scripts/lab/ui-acceptance.py')
assert spec is not None and spec.loader is not None
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


def test_ui_tier_client_matrix_selects_only_enabled_requested_protocols(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = fixture.api('/api/clients', 'POST', {'display_name': 'Matrix check', 'subscription': False})
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="open"]')
        browser.wait("document.querySelectorAll('#placement-body input[data-node=local]').length > 3", 'all protocol cells')
        caller = SimpleNamespace(browser=browser)
        selected = acceptance.Acceptance.select_client_protocols(caller)
        assert set(selected) == {'mtproxy', 'naive', 'mieru'}
        assert browser.js("[...document.querySelectorAll('#placement-body input[data-node=local]:checked')].every(i => !i.disabled)")
        browser.js("document.querySelector('#placement-body input[data-node=local][data-protocol=naive]').disabled = true; true")
        selected = acceptance.Acceptance.select_client_protocols(caller)
        assert set(selected) == {'mtproxy', 'mieru'}
        assert browser.js("!document.querySelector('#placement-body input[data-node=local][data-protocol=naive]').checked")


def test_ui_tier_client_management_opens_the_accesses_tab(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = fixture.api('/api/clients', 'POST', {'display_name': 'Details check', 'subscription': False})
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        caller = acceptance.Acceptance.__new__(acceptance.Acceptance)
        caller.browser = acceptance.Browser.__new__(acceptance.Browser)
        caller.browser.cdp = browser.dt
        card = f'.client-card[data-client-id="{client["id"]}"]'
        assert caller.open_client_window(card)
        assert browser.js("document.querySelector('#subscription-modal [data-client-panel=accesses]').getAttribute('aria-selected') === 'true'")


def test_import_shows_the_new_client_without_a_manual_refresh(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        fixture.central.naive.public_host = 'naive.example'
        name = 'import-check'
        caller = acceptance.Acceptance.__new__(acceptance.Acceptance)
        caller.args = SimpleNamespace(
            naive_manager_socket=fixture.central.env['NAIVE_MANAGER_SOCKET'],
            naive_manager_token_file=fixture.central.env['NAIVE_MANAGER_TOKEN_FILE'],
        )
        caller.seed_unmanaged_naive(name)
        assert not any(e['client']['display_name'] == name for e in fixture.api('/api/clients')['items'])
        browser.open_view('clients', "!!document.querySelector('[data-client-action=import]')", width=390)
        browser.click('[data-client-action=import]')
        browser.wait(f"!!document.querySelector('#client-import-rows tr[data-import-username=\"{name}\"]')", 'import inventory')
        browser.js(f"document.querySelector('#client-import-rows tr[data-import-username=\"{name}\"] .import-pick').checked = true; true")

        browser.click('#confirm-client-import')
        try:
            browser.wait(f"!document.querySelector('#client-import-modal').open && [...document.querySelectorAll('.client-identity b')].some(e => e.textContent === '{name}')", 'new imported client')
        except AssertionError:
            facts = browser.js("""({hash:location.hash,importOpen:document.querySelector('#client-import-modal').open,
              cards:document.querySelectorAll('.client-card').length,
              filter:document.querySelector('[data-client-filter-state][aria-pressed=true]')?.dataset.clientFilterState,
              searchLength:document.querySelector('#client-search')?.value.length,
              title:document.querySelector('#title')?.textContent,
              importErrorLength:document.querySelector('#client-import-error')?.textContent.length,
              skeleton:!!document.querySelector('#view .skeleton-grid')})""")
            facts['created_in_api'] = any(e['client']['display_name'] == name for e in fixture.api('/api/clients')['items'])
            raise AssertionError(str(facts)) from None
