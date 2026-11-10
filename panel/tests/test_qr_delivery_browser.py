"""QR delivery uses readable squares and the same presentation in both client flows."""
import base64
import json
import os
from pathlib import Path

import pytest

from scripts.lab.ui_protocol_dialog_check import isolated_browser, isolated_panel


def test_delivery_qr_is_large_square_and_can_expand_without_losing_parent(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('clients', "!!document.querySelector('#add')", width=1440)
        # Public, inert visual fixture: no access credentials in screenshots or diagnostics.
        svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><path fill="white" d="M0 0h100v100H0z"/><path d="M10 10h30v30H10zM60 10h30v30H60zM10 60h30v30H10zM60 60h10v10H60z"/></svg>'
        qr = 'data:image/svg+xml;base64,' + base64.b64encode(svg.encode()).decode()
        browser.js("""(async (qr) => {
            const {renderChooser} = await import('/static/js/link-chooser.js');
            const catalogue = await (await fetch('/api/subscriptions/compatibility')).json();
            window.renderDeliveryProbe = (id) => {
                renderChooser(document.querySelector('#' + id + '-chooser'), {
                    catalogue, payload: {url: 'https://sub.example/visual-fixture', qr,
                        page_url: 'https://sub.example/visual-fixture?format=html', page_qr: qr},
                    protocols: ['naive', 'mieru'], name: 'Visual fixture',
                });
                document.querySelector(id === 'bundle' ? '#bundle-subscription' : '#subscription-reveal').hidden = false;
                document.querySelector('#subscription-box').hidden = false;
            };
            document.querySelector('#bundle-subscription').hidden = false;
            document.querySelector('#subscription-reveal').hidden = false;
            return true;
        })(""" + json.dumps(qr) + ')')
        widths = {}
        for width in (320, 390, 768, 1440):
            browser.dt.call('Emulation.setDeviceMetricsOverride', {
                'width': width, 'height': 900, 'deviceScaleFactor': 1, 'mobile': width < 600,
            })
            for flow in ('bundle', 'subscription'):
                selector = '#' + flow + '-modal'
                browser.js(f'window.renderDeliveryProbe({json.dumps(flow)}); document.querySelector({json.dumps(selector)}).showModal(); true')
                result = browser.js("""((selector) => {
                    const modal = document.querySelector(selector);
                    const image = modal.querySelector('[data-client-page-qr]');
                    const r = image.getBoundingClientRect();
                    const dialog = modal.getBoundingClientRect();
                    return {size: r.width, square: Math.abs(r.width - r.height) < 1,
                        visible: r.height > 0, overflow: modal.scrollWidth > modal.clientWidth + 1,
                        dialogWidth: dialog.width, dialogHeight: dialog.height};
                })(""" + json.dumps(selector) + ')')
                assert result['visible'] and result['square'], (width, flow, result)
                assert result['size'] >= (210 if width == 320 else 260), (width, flow, result)
                assert not result['overflow'], (width, flow, result)
                assert result['dialogWidth'] <= 900, (width, flow, result)
                if width < 600:
                    assert abs(result['dialogWidth'] - width) < 1 and abs(result['dialogHeight'] - 900) < 1, (width, flow, result)
                if width == 1440:
                    assert abs(result['size'] - 320) < 1, (width, flow, result)
                widths[flow] = result['size']
                if os.environ.get('QR_UI_SHOTS'):
                    folder = Path(os.environ['QR_UI_SHOTS'])
                    folder.mkdir(parents=True, exist_ok=True)
                    shot = browser.dt.call('Page.captureScreenshot', {'format': 'png'})
                    (folder / f'{flow}-{width}.png').write_bytes(base64.b64decode(shot['data']))
                browser.click(selector + ' [data-qr-expand]')
                assert browser.js("document.querySelector('#qr-modal').open")
                assert browser.js('document.querySelector("#qr-modal img").src === ' + json.dumps(qr))
                assert browser.js("""(() => {const d = document.querySelector('#qr-modal');
                    const r = d.querySelector('img').getBoundingClientRect();
                    return Math.abs(r.width-r.height)<1 && d.scrollWidth <= d.clientWidth+1;})()""")
                browser.click('#qr-modal [value="cancel"]')
                browser.wait("!document.querySelector('#qr-modal img').hasAttribute('src')", 'QR cleared')
                assert browser.js(f'document.querySelector({json.dumps(selector)}).open')
                browser.js(f'document.querySelector({json.dumps(selector)}).close(); true')
            assert abs(widths['bundle'] - widths['subscription']) <= 1, (width, widths)
        browser.healthy()


@pytest.mark.parametrize('protocol', ['mtproxy', 'trusttunnel'])
def test_creation_bundle_uses_shared_qr_for_link_artifacts(tmp_path, protocol):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('clients', "!!document.querySelector('#view .client-list')", width=390)
        browser.click('#add')
        browser.wait("document.querySelector('#client-modal').open", 'client dialog')
        browser.wait("!!document.querySelector('#client-placement input[data-node=" + '"local"' + "][data-protocol=" + json.dumps(protocol) + "]')", 'placement')
        browser.set_value('#client-name', 'QR link')
        browser.js("""((protocol) => {
            for (const input of document.querySelectorAll('#client-placement input[data-protocol]')) {
                input.checked = input.dataset.node === 'local' && input.dataset.protocol === protocol;
                input.dispatchEvent(new Event('change', {bubbles:true}));
            }
            return true;
        })(""" + json.dumps(protocol) + ')')
        browser.click('#create-client')
        browser.wait("document.querySelector('#bundle-modal').open", 'issued links')
        assert browser.js("!!document.querySelector('#bundle-body .qr-card [data-qr-expand]')")
        browser.js("document.querySelector('#bundle-details').open = true; true")
        browser.click('#bundle-body [data-qr-expand]')
        assert browser.js("document.querySelector('#qr-modal').open")
        browser.click('#qr-modal [value="cancel"]')
        browser.wait("!document.querySelector('#qr-large').hasAttribute('src')", 'QR cleared')
        browser.healthy()


def test_escrowed_bundle_can_close_without_a_one_time_warning(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_screen('amneziawg', width=390)
        browser.click('#add')
        browser.wait("document.querySelector('#awg-modal').open", 'Amnezia form')
        browser.set_value('#new-awg-user', 'recoverable')
        browser.wait("!document.querySelector('#create-awg').disabled", 'Amnezia ready')
        browser.click('#create-awg')
        browser.wait("document.querySelector('#bundle-modal').open", 'bundle')
        assert browser.js("!document.querySelector('#bundle-modal').textContent.includes('показываются один раз')")
        browser.click('#bundle-modal .modal-head-actions button.primary')
        browser.wait("!document.querySelector('#bundle-modal').open", 'bundle closed')
        assert browser.js("!document.querySelector('#confirm').open")


def test_amnezia_issuance_and_reveal_share_qr_and_fold_the_config(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_screen('amneziawg', width=390)
        browser.click('#add')
        browser.wait("document.querySelector('#awg-modal').open", 'Amnezia form')
        browser.set_value('#new-awg-user', 'qr-phone')
        browser.wait("!document.querySelector('#create-awg').disabled", 'Amnezia ready')
        browser.click('#create-awg')
        browser.wait("document.querySelector('#bundle-modal').open", 'Amnezia bundle')
        assert browser.js("!!document.querySelector('#bundle-body .qr-card [data-qr-expand]')")
        assert browser.js("document.querySelector('#bundle-body .config-source').open") is False
        digest = """(async (selector) => {
            const bytes = new TextEncoder().encode(document.querySelector(selector).src);
            return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
                .map(n => n.toString(16).padStart(2, '0')).join('');
        })"""
        issued_digest = browser.js(digest + "('#bundle-body .qr-card img')")
        browser.click('#bundle-body [data-qr-expand]')
        browser.click('#qr-large-download')
        browser.click('#qr-modal [value="cancel"]')
        browser.wait("!document.querySelector('#qr-modal').open", 'large QR closed')
        browser.click('#bundle-modal .modal-head-actions button.primary')
        browser.wait("!document.querySelector('#bundle-modal').open", 'bundle closed')
        assert browser.js("document.querySelector('#confirm').open") is False
        # Closing the modal consumes its browser-history entry asynchronously.
        # Do not start a forced page navigation until that traversal has finished.
        browser.wait("!history.state?.panelModal", 'modal history settled')
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        # Keep the comparison inside the browser; do not return secret data.
        entries = fixture.api('/api/clients')['items']
        client_id = next(row['client']['id'] for row in entries
                         if any(g['runtime_username'].startswith('qr-phone') for g in row['grants']))
        browser.click(f'.client-card[data-client-id="{client_id}"] [data-client-action="open"]')
        browser.wait("!!document.querySelector('#subscription-grants [data-grant-open]')", 'client accesses')
        browser.click('#subscription-grants [data-grant-open]')
        browser.wait("!!document.querySelector('[data-grant-action=" + '"show"' + "]')", 'show config')
        browser.click('[data-grant-action="show"]')
        browser.wait("!!document.querySelector('#grant-link-body .qr-card img')", 'config revealed')
        assert browser.js(digest + "('#grant-link-body .qr-card img')") == issued_digest
        assert browser.js("document.querySelector('#grant-link-body .config-source').open") is False
        browser.click('#grant-link-body [data-qr-expand]')
        assert browser.js("document.querySelector('#qr-modal').open")
        browser.js("document.querySelector('#qr-modal').close(); true")
        browser.wait("!document.querySelector('#qr-large').hasAttribute('src')", 'QR cleared')
        browser.healthy()
