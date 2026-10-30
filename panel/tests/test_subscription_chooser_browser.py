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
        browser.wait("!!document.querySelector('[data-subscription-action=show]')", 'show subscription')
        browser.click('[data-subscription-action="show"]')
        browser.wait("!!document.querySelector('#subscription-chooser .chooser-chip input')", 'chooser')
        checked = 0
        for platform in catalogue['platforms']:
            browser.click(f'#subscription-chooser input[value="{platform["id"]}"]')
            for app in catalogue['apps']:
                selector = f'#subscription-chooser input[value="{app["id"]}"]'
                if not browser.js(f'!!document.querySelector({json.dumps(selector)})'):
                    continue
                browser.click(selector)
                expected = payload['variants'].get(app['variant'])
                if not expected:
                    continue
                # Only boolean aggregates leave a secret-bearing window.
                require(browser.js('document.querySelector("#subscription-chooser [data-chooser-url]").value === '
                                   + json.dumps(expected['url'])), 'app-specific subscription URL changed')
                require(browser.js('document.querySelector("#subscription-chooser .chooser-qr")?.open === false'),
                        'QR must be behind an explicit disclosure')
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
