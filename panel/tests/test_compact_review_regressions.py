"""Real-browser regressions from the independent compact UI review."""
import importlib.util
import json
from pathlib import Path

from scripts.lab.ui_protocol_dialog_check import isolated_browser, isolated_panel, require


def test_subscription_copy_has_a_fallback_and_does_not_claim_failed_copies(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('clients', "!!document.querySelector('.client-list')", width=390)
        catalogue = {'platforms': [{'id': 'android', 'name': 'Android'}], 'apps': [{
            'id': 'demo', 'name': 'Demo', 'variant': 'singbox', 'platforms': ['android'],
            'protocols': {'naive': 'works'}, 'deeplink': 'demo://import/{url_enc}', 'downloads': [],
        }]}
        payload = {'url': 'https://sub.example/s/DEMO', 'qr': '', 'variants': {
            'singbox': {'url': 'https://sub.example/s/DEMO?format=singbox', 'qr': ''},
        }}
        data = json.dumps({'catalogue': catalogue, 'payload': payload, 'protocols': ['naive'], 'name': 'Demo'})
        browser.js("(async()=>{const {renderChooser}=await import('/static/js/link-chooser.js'); const host=document.createElement('div'); host.id='review-chooser'; document.querySelector('#view').append(host); renderChooser(host," + data + "); return true;})()")
        browser.click('#review-chooser input[value="android"]')
        browser.js("Object.defineProperty(navigator,'clipboard',{configurable:true,value:undefined}); window.__copyAttempts=0; document.execCommand=cmd=>{if(cmd==='copy'){window.__copyAttempts++;return true;}return false;};true")
        browser.click('#review-chooser [data-copy]')
        browser.wait('window.__copyAttempts === 1', 'clipboard fallback used')
        browser.js("Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async()=>{throw Error('denied');}}}); document.execCommand=()=>false; true")
        browser.click('#review-chooser [data-copy]')
        browser.wait("document.querySelector('#toast-region .toast:last-child')?.classList.contains('error')", 'copy failure reported')
        require(browser.js('window.__protocolErrors === 0'), 'clipboard rejection escaped the handler')


def test_unknown_grant_observation_remains_visible_in_card_and_main_details(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = fixture.api('/api/clients', 'POST', {'display_name': 'Review phone', 'subscription': False})
        fixture.api(f"/api/clients/{client['id']}/grants", 'POST', {'grants': [
            {'protocol': 'trusttunnel', 'node_id': 'local', 'runtime_username': 'review-phone', 'options': {}},
        ]})
        with fixture.central.db(write=True) as db:
            db.execute("UPDATE access_grants SET observed_state='unknown' WHERE client_id=?", (client['id'],))
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        card = f'.client-card[data-client-id="{client["id"]}"]'
        assert browser.js(f'!!document.querySelector({json.dumps(card + " .card-warning")})')
        browser.click(card + ' [data-client-action="open"]')
        browser.wait("!!document.querySelector('#subscription-grants [data-grant-open]')", 'access loaded')
        browser.click('#subscription-grants [data-grant-open]')
        browser.wait("document.querySelector('#grant-window').open", 'grant opened')
        assert browser.js("document.querySelector('#grant-facts [data-grant-state]').dataset.grantState") == 'unknown'
        assert browser.js("document.querySelector('#grant-facts').textContent.includes('ещё не сообщал')")
        assert browser.js("document.querySelector('#grant-technical').open") is False


def test_replacing_key_creation_with_reveal_does_not_leave_dead_history_entries(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('clients', "!!document.querySelector('.client-list')", width=390)
        browser.open_view('admins', "!!document.querySelector('[data-key-action=create]')", width=390)
        browser.click('[data-key-action="create"]')
        browser.wait("document.querySelector('#key-modal').open", 'key dialog')
        browser.set_value('#key-name', 'review-key')
        browser.click('#create-key')
        browser.wait("document.querySelector('#key-reveal').open", 'key reveal')
        # Do not read or capture the key; only modal/history metadata is inspected.
        browser.click('#key-reveal [value="cancel"]')
        browser.wait("!document.querySelector('#key-reveal').open && !history.state?.panelModal", 'replacement history consumed')
        browser.js('history.back(); true')
        browser.wait("location.hash === '#clients'", 'one Back reaches prior screen')


def test_node_routing_shortcut_returns_to_the_list_without_a_dead_modal_entry(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('clients', "!!document.querySelector('.client-list')", width=390)
        browser.open_view('fleet', "!!document.querySelector('.local-node')", width=390)
        browser.click('.local-node [data-node-action="open"]')
        browser.wait("document.querySelector('#node-window').open", 'node opened')
        browser.click('#node-window [data-node-action="tab-routing"]')
        browser.click('#node-window [data-node-action="routing"]')
        browser.wait("location.hash === '#routing'", 'routing shortcut')
        browser.js('history.back(); true')
        browser.wait("location.hash === '#fleet'", 'return to nodes')
        browser.wait("!document.querySelector('#node-window').open && !history.state?.panelModal", 'no dead modal state')
        browser.js('history.back(); true')
        browser.wait("location.hash === '#clients'", 'next Back reaches previous screen')


def test_live_ui_fleet_scenario_checks_health_and_routing_in_their_own_tabs(tmp_path):
    path = Path(__file__).resolve().parents[2] / 'scripts/lab/ui-acceptance.py'
    spec = importlib.util.spec_from_file_location('review_ui_acceptance', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        class Adapter:
            def click(self, selector):
                browser.click(selector)
                return True
            def wait(self, expression, seconds=20):
                try:
                    browser.wait(expression, 'live scenario condition')
                    return True
                except AssertionError:
                    return False
            def text(self, selector):
                return browser.js(f'document.querySelector({json.dumps(selector)})?.textContent || ""')
            def exists(self, selector):
                return browser.js(f'!!document.querySelector({json.dumps(selector)})')
            def close_dialog(self, selector):
                browser.js(f'document.querySelector({json.dumps(selector)}).close(); true')
            def shot(self, name):
                pass
        run = module.Acceptance.__new__(module.Acceptance)
        run.browser = Adapter()
        def goto(view, ready):
            browser.open_view(view, ready, width=390)
            return True
        def check(name, ok, *details):
            assert ok, name
        run.goto_view = goto
        run.check = check
        run.frame_is_secret_free = lambda name: None
        run.view_fleet()
