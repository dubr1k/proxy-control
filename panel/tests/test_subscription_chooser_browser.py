"""Subscription presentation preserves every app-specific URL and downloaded profile."""
import json
from urllib.parse import quote, urlsplit

from scripts.lab import ui_protocol_dialog_check as lab
from scripts.lab.ui_protocol_dialog_check import isolated_browser, isolated_panel, require


def test_subscription_chooser_is_compact_and_preserves_all_client_variants(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, 'SUBSCRIPTION_URL', 'https://sub.example')
    monkeypatch.setattr(lab, 'SUBSCRIPTION_HOST', '127.0.0.1')
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = fixture.api('/api/clients', 'POST', {'display_name': 'Phone', 'subscription': False})
        issued = fixture.api(f"/api/clients/{client['id']}/grants", 'POST', {'grants': [
            {'protocol': 'trusttunnel', 'node_id': 'local', 'runtime_username': 'phone', 'options': {}},
        ]})
        assert issued['status'] == 'succeeded'
        created = fixture.api(f"/api/clients/{client['id']}/subscription", 'POST')
        payload = fixture.api(f"/api/reveal/{created['reveal_token']}")
        catalogue = fixture.api('/api/subscriptions/compatibility')

        def profiles():
            snapshots = {}
            for variant, item in payload['variants'].items():
                url = urlsplit(item['url'])
                response = fixture.http.get(url.path + ('?' + url.query if url.query else ''))
                snapshots[variant] = (response.status_code, response.content,
                                      response.headers.get('etag'), response.headers.get('content-type'))
            return snapshots

        before = profiles()
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="subscription"]')
        browser.wait("!!document.querySelector('#subscription-chooser [data-client-page-url]')", 'delivery modes')
        browser.click('#subscription-chooser [data-delivery-mode="import"]')
        browser.wait("!!document.querySelector('#subscription-chooser .chooser-chip input')", 'chooser')
        checked = 0
        for platform in catalogue['platforms']:
            browser.click(f'#subscription-chooser input[value="{platform["id"]}"]')
            for app in catalogue['apps']:
                selector = f'#subscription-chooser input[value="{app["id"]}"]'
                if not browser.js(f'!!document.querySelector({json.dumps(selector)})'):
                    continue
                browser.click('#subscription-chooser .chooser-app-select summary')
                browser.click(selector)
                expected = payload['variants'].get(app['variant'])
                if not expected:
                    continue
                # Only boolean aggregates leave a secret-bearing window.
                require(browser.js('document.querySelector("#subscription-chooser [data-chooser-url]").value === '
                                   + json.dumps(expected['url'])), 'app-specific subscription URL changed')
                require(browser.js('document.querySelector("#subscription-chooser .chooser-qr img")?.getBoundingClientRect().height >= 210'),
                        'QR must be readable after revealing the subscription')
                for width in (320, 390, 1440):
                    browser.dt.call('Emulation.setDeviceMetricsOverride', {'width': width, 'height': 844,
                                                                         'deviceScaleFactor': 1, 'mobile': width < 600})
                    require(browser.js("(() => { const form = document.querySelector('#subscription-modal form'); return form.scrollWidth <= form.clientWidth + 1; })()"),
                            'subscription dialog scrolls horizontally')
                if app.get('deeplink'):
                    href = (app['deeplink'].replace('{url_enc}', quote(expected['url'], safe=''))
                            .replace('{name_enc}', quote('Phone', safe='')).replace('{url}', expected['url']))
                    require(browser.js('document.querySelector("#subscription-chooser [data-chooser-open]").getAttribute("href") === '
                                       + json.dumps(href)), 'application import scheme changed')
                checked += 1
        require(checked >= 6, 'not enough client/platform combinations were checked')
        require(profiles() == before, 'profile bytes, media types or ETags changed after UI interactions')
        browser.click('#subscription-modal [value="cancel"]')
        browser.wait("!document.querySelector('#subscription-modal').open", 'close subscription')
        browser.wait("!document.querySelector('#subscription-chooser [data-chooser-url]')", 'secret link cleared')


def test_connect_opens_the_stable_page_and_clears_it_on_close(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, 'SUBSCRIPTION_URL', 'https://sub.example')
    monkeypatch.setattr(lab, 'SUBSCRIPTION_HOST', '127.0.0.1')
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = fixture.api('/api/clients', 'POST', {'display_name': 'Phone', 'subscription': False})
        issued = fixture.api(f"/api/clients/{client['id']}/grants", 'POST', {'grants': [
            {'protocol': 'trusttunnel', 'node_id': 'local', 'runtime_username': 'phone', 'options': {}},
        ]})
        assert issued['status'] == 'succeeded'
        created = fixture.api(f"/api/clients/{client['id']}/subscription", 'POST')
        payload = fixture.api(f"/api/reveal/{created['reveal_token']}")
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        selector = f'.client-card[data-client-id="{client["id"]}"] [data-client-action="subscription"]'
        browser.click(selector)
        browser.wait("!!document.querySelector('#subscription-chooser [data-client-page-url]')", 'client page')
        require(browser.js("!document.querySelector('#subscription-modal [data-client-panel=accesses]') && "
                           "!document.querySelector('#subscription-modal [data-subscription-action=show]')"),
                'connection window must not duplicate management or the already shown link action')
        require(browser.js('document.querySelector("#subscription-chooser [data-client-page-url]").value === '
                           + json.dumps(payload['page_url'])), 'page URL was not shown by default')
        require(browser.js('document.querySelector("#subscription-chooser [data-client-page-qr]").getAttribute("src") === '
                           + json.dumps(payload['page_qr'])), 'page QR does not match the page URL')
        browser.js("window.__copiedPage = null; Object.defineProperty(navigator, 'clipboard', "
                   "{configurable:true,value:{writeText:async text => {window.__copiedPage = text;}}}); true")
        browser.click('#subscription-chooser .delivery-page button[data-copy]')
        browser.wait('window.__copiedPage === ' + json.dumps(payload['page_url']), 'page URL copied')
        require(browser.js("document.querySelector('#subscription-chooser').textContent.includes('Откройте камерой телефона')"),
                'camera instruction is missing')
        browser.click('#subscription-chooser [data-delivery-mode="import"]')
        browser.click('#subscription-chooser .chooser-step:first-of-type input')
        browser.wait("!!document.querySelector('#subscription-chooser .chooser-step:nth-of-type(2) input')", 'application choice')
        require(browser.js("!!document.querySelector('#subscription-chooser details.chooser-app-select:not([open])')"),
                'application list must start collapsed')
        browser.click('#subscription-chooser .chooser-app-select summary')
        browser.click('#subscription-chooser .chooser-step:nth-of-type(2) input:last-of-type')
        platform = browser.js('document.querySelector("#subscription-chooser input[name$=-platform]:checked").value')
        app = browser.js('document.querySelector("#subscription-chooser input[name$=-app]:checked").value')
        require(browser.js("""(() => {
          const box = document.querySelector('#subscription-chooser .chooser-result');
          return box.querySelector('.qr-card figcaption').textContent.includes(box.querySelector('h4').textContent);
        })()"""), 'import QR caption must name its destination app')
        require(browser.js('!JSON.stringify(localStorage).includes(' + json.dumps(payload['url']) + ')'),
                'browser settings contain a secret URL')
        browser.click('#subscription-modal [value="cancel"]')
        browser.wait("!document.querySelector('#subscription-modal').open", 'close connection')
        browser.wait("!document.querySelector('#subscription-chooser [data-client-page-url]')", 'page secret cleared')
        browser.click(selector)
        browser.wait("!!document.querySelector('#subscription-chooser [data-client-page-url]')", 'reopen client page')
        require(browser.js('document.querySelector("#subscription-chooser [data-client-page-url]").value === '
                           + json.dumps(payload['page_url'])), 'reopening changed the client page URL')
        browser.click('#subscription-chooser [data-delivery-mode="import"]')
        require(browser.js('document.querySelector("#subscription-chooser input[name$=-platform]:checked")?.value === '
                           + json.dumps(platform)), 'platform choice was not restored')
        require(browser.js('document.querySelector("#subscription-chooser input[name$=-app]:checked")?.value === '
                           + json.dumps(app)), 'application choice was not restored')


def test_client_with_only_amnezia_can_create_a_page_once(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, 'SUBSCRIPTION_URL', 'https://sub.example')
    monkeypatch.setattr(lab, 'SUBSCRIPTION_HOST', '127.0.0.1')
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = fixture.api('/api/clients', 'POST', {'display_name': 'Tunnel', 'subscription': False})
        issued = fixture.api(f"/api/clients/{client['id']}/grants", 'POST', {'grants': [
            {'protocol': 'amneziawg', 'node_id': 'local', 'runtime_username': 'tunnel', 'options': {'version': '2.0'}},
        ]})
        assert issued['status'] == 'succeeded'
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="subscription"]')
        browser.wait("!!document.querySelector('[data-subscription-action=create]')", 'create page action')
        assert fixture.api(f"/api/clients/{client['id']}/subscription")['subscription'] is None
        browser.click('[data-subscription-action="create"]')
        browser.wait("!!document.querySelector('#subscription-chooser [data-client-page-url]')", 'created page')
        first = fixture.api(f"/api/clients/{client['id']}/subscription")['subscription']
        browser.click('#subscription-modal [value="cancel"]')
        browser.wait("!document.querySelector('#subscription-modal').open", 'close')
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="subscription"]')
        browser.wait("!!document.querySelector('#subscription-chooser [data-client-page-url]')", 'reopened page')
        second = fixture.api(f"/api/clients/{client['id']}/subscription")['subscription']
        assert first['id'] == second['id'] and first['generation'] == second['generation']


def test_legacy_link_is_not_rotated_when_its_escrowed_copy_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, 'SUBSCRIPTION_URL', 'https://sub.example')
    monkeypatch.setattr(lab, 'SUBSCRIPTION_HOST', '127.0.0.1')
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = fixture.api('/api/clients', 'POST', {'display_name': 'Legacy'})
        payload = fixture.api(f"/api/reveal/{client['subscription_reveal_token']}")
        before = fixture.api(f"/api/clients/{client['id']}/subscription")['subscription']
        with fixture.central.db(write=True) as db:
            db.execute('UPDATE client_subscriptions SET secret_id=NULL,secret_version=NULL WHERE client_id=?',
                       (client['id'],))
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="subscription"]')
        browser.wait("document.querySelector('#subscription-actions')?.textContent.includes('невозможно извлечь')",
                     'legacy link explanation')
        require(browser.js("!document.querySelector('#subscription-chooser [data-client-page-url]')"),
                'unrecoverable URL must not be shown')
        after = fixture.api(f"/api/clients/{client['id']}/subscription")['subscription']
        require(before['id'] == after['id'] and before['generation'] == after['generation'],
                'opening the legacy link rotated it')
        page = urlsplit(payload['page_url'])
        require(fixture.http.get(page.path + '?' + page.query).status_code == 200,
                'legacy page no longer works')


def test_connection_with_a_long_name_fits_and_can_close_at_each_size(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, 'SUBSCRIPTION_URL', 'https://sub.example')
    monkeypatch.setattr(lab, 'SUBSCRIPTION_HOST', '127.0.0.1')
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = fixture.api('/api/clients', 'POST', {'display_name': 'Д' * 120})
        fixture.api(f"/api/reveal/{client['subscription_reveal_token']}")
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        selector = f'.client-card[data-client-id="{client["id"]}"] [data-client-action="subscription"]'
        for width in (320, 390, 768, 1440):
            browser.dt.call('Emulation.setDeviceMetricsOverride', {'width': width, 'height': 844,
                                                                   'deviceScaleFactor': 1, 'mobile': width < 600})
            browser.click(selector)
            browser.wait("!!document.querySelector('#subscription-chooser [data-client-page-url]')", 'client page')
            geometry = browser.js("""(() => { const dialog = document.querySelector('#subscription-modal');
              const form = dialog.querySelector('form'); const close = dialog.querySelector('.modal-head .close');
              const r = close.getBoundingClientRect();
              return {viewport:innerWidth, content:form.scrollWidth, available:form.clientWidth,
                closeWidth:r.width, closeHeight:r.height, closeRight:r.right}; })()""")
            require(geometry['content'] <= geometry['available'] + 1 and geometry['closeWidth'] >= 44
                    and geometry['closeHeight'] >= 44 and geometry['closeRight'] <= width + 1,
                    f'connection dialog overflow or close button inaccessible: {geometry}')
            browser.click('#subscription-modal .modal-head .close')
            browser.wait("!document.querySelector('#subscription-modal').open", 'close connection')


def test_retry_after_a_failed_grant_shows_the_original_client_page(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, 'SUBSCRIPTION_URL', 'https://sub.example')
    monkeypatch.setattr(lab, 'SUBSCRIPTION_HOST', '127.0.0.1')
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('clients', "!!document.querySelector('#view .client-list')", width=390)
        browser.click('#add')
        browser.wait("!!document.querySelector('#client-placement input[data-node=local][data-protocol=\"amneziawg:2.0\"]')", 'placement')
        browser.set_value('#client-name', 'Retry')
        browser.js("""(() => {const input = document.querySelector('#client-placement input[data-node=local][data-protocol="amneziawg:2.0"]');
          input.checked = true; input.dispatchEvent(new Event('change', {bubbles:true}));
          const original = window.fetch.bind(window); let failed = false;
          window.fetch = async (url, options) => {
            if (!failed && /\\/api\\/clients\\/[^/]+\\/grants$/.test(String(url)) && options?.method === 'POST') {
              failed = true; return new Response(JSON.stringify({detail:'test refusal'}),
                {status:409, headers:{'content-type':'application/json'}});
            }
            return original(url, options);
          }; return true; })()""")
        browser.click('#create-client')
        browser.wait("document.querySelector('#client-error').textContent.includes('test refusal')", 'first failure')
        browser.wait("!document.querySelector('#create-client').disabled", 'retry enabled')
        browser.click('#create-client')
        try:
            browser.wait("document.querySelector('#subscription-modal').open && !!document.querySelector('#subscription-chooser [data-client-page-url]')", 'original page')
        except AssertionError as error:
            state = browser.js("""(() => {const form = document.querySelector('#client-form');
              const message = document.querySelector('#client-error').textContent;
              return {formOpen:document.querySelector('#client-modal').open, bundleOpen:document.querySelector('#bundle-modal').open,
                connectionOpen:document.querySelector('#subscription-modal').open, valid:form.checkValidity(),
                hasError:!!message, refusal:message.includes('test refusal'), buttonDisabled:document.querySelector('#create-client').disabled,
                usernameLength:document.querySelector('#client-username').value.length}; })()""")
            raise AssertionError(f'retry state: {state}') from error
        clients = fixture.api('/api/clients')['items']
        assert len([entry for entry in clients if entry['client']['display_name'] == 'Retry']) == 1


def test_client_page_does_not_depend_on_the_app_catalogue(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, 'SUBSCRIPTION_URL', 'https://sub.example')
    monkeypatch.setattr(lab, 'SUBSCRIPTION_HOST', '127.0.0.1')
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = fixture.api('/api/clients', 'POST', {'display_name': 'No catalogue'})
        payload = fixture.api(f"/api/reveal/{client['subscription_reveal_token']}")
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        browser.js("""(() => {const original = window.fetch.bind(window);
          window.fetch = (url, options) => String(url).includes('/api/subscriptions/compatibility')
            ? Promise.resolve(new Response('{}', {status:503, headers:{'content-type':'application/json'}}))
            : original(url, options); return true; })()""")
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="subscription"]')
        browser.wait("!!document.querySelector('#subscription-chooser [data-client-page-url]')", 'client page')
        require(browser.js('document.querySelector("#subscription-chooser [data-client-page-url]").value === '
                           + json.dumps(payload['page_url'])), 'page link unavailable without catalogue')
