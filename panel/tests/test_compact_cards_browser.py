"""Compact overview lists retain status, detail actions and keyboard/mobile access."""
import base64
import os
from pathlib import Path

from scripts.lab.ui_protocol_dialog_check import OverviewFixture, isolated_browser, isolated_panel


def seed_client(fixture):
    client = fixture.api('/api/clients', 'POST', {'display_name': 'Phone', 'subscription': False})
    result = fixture.api(f"/api/clients/{client['id']}/grants", 'POST', {'grants': [
        {'protocol': 'trusttunnel', 'node_id': 'local', 'runtime_username': 'phone', 'options': {}},
    ]})
    assert result['status'] == 'succeeded'
    return client


def test_new_client_hides_limits_in_additional_settings(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('clients', "!!document.querySelector('.client-list')", width=390)
        browser.click('#add')
        browser.wait("document.querySelector('#client-modal').open", 'new client')
        assert browser.js("!!document.querySelector('#client-modal details#client-additional:not([open]) #new-client-traffic-enabled')")
        assert browser.js("!!document.querySelector('#client-modal details#client-additional:not([open]) #new-client-validity-enabled')")


def test_node_overview_is_short_and_details_preserve_the_list(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        for width in (390, 1440):
            browser.open_view('fleet', "!!document.querySelector('.local-node')", width=width)
            assert browser.js("document.querySelectorAll('#view .node-facts, #view .node-tabs, #view .node-local-link').length") == 0
            assert browser.js("document.querySelector('.local-node').getBoundingClientRect().height < 210")
            browser.js('window.scrollTo(0, 40); true')
            before = browser.js('window.scrollY')
            browser.click('.local-node [data-node-action="open"]')
            browser.wait("document.querySelector('#node-window')?.open === true", 'node details')
            assert browser.js("document.querySelector('#node-window').textContent.includes('GUID')")
            assert browser.js("document.querySelector('#node-window').getBoundingClientRect().right <= innerWidth")
            browser.click('#node-window [data-node-action="tab-routing"]')
            browser.wait("!!document.querySelector('#node-window [data-node-action=" + '"routing"' + "]')", 'routing shortcut')
            browser.click('#node-window [value="cancel"]')
            browser.wait("!document.querySelector('#node-window').open", 'close details')
            assert abs(browser.js('window.scrollY') - before) <= 1
            assert browser.js("document.activeElement?.matches('.local-node [data-node-action=" + '"open"' + "]')")
        assert browser.js("document.querySelector('.node-list').textContent.includes('Пауза')")


def test_client_overview_hides_accounts_but_details_keep_access_and_technical_facts(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = seed_client(fixture)
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        assert browser.js("document.querySelectorAll('.client-card .client-grants').length") == 0
        assert browser.js('document.querySelector(' + repr(f'.client-card[data-client-id="{client["id"]}"]')
                          + ').textContent.includes("TrustTunnel")')
        assert browser.js('''(() => {const actions = [...document.querySelector('.client-card .client-actions').children]
          .filter(e => e.tagName === 'BUTTON'); return actions[0]?.textContent.trim() === 'Подключить'
          && actions[0].classList.contains('primary') && actions[1]?.textContent.trim() === 'Управление';})()''')
        assert browser.js('''(() => [...document.querySelectorAll('.client-card .client-actions > button, .client-card .client-menu-button')]
          .filter(e => e.getClientRects().length).every(e => {const r = e.getBoundingClientRect(); return r.width >= 44 && r.height >= 44;}))()''')
        assert browser.js("document.querySelector('.client-card').getBoundingClientRect().height < 210")
        assert browser.js("!!document.querySelector('.client-card [data-client-action=" + '"subscription"' + "]')")
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="open"]')
        browser.wait("!!document.querySelector('#subscription-grants [data-grant-open]')", 'client accesses')
        assert browser.js("""(() => {
            const grant = document.querySelector('#subscription-grants .grant-row');
            const box = grant.getBoundingClientRect();
            return parseFloat(getComputedStyle(grant).borderTopLeftRadius) <= 12
                && grant.scrollWidth <= grant.clientWidth + 1 && box.right <= innerWidth + 1;
        })()""")
        browser.click('#subscription-grants [data-grant-open]')
        browser.wait("document.querySelector('#grant-window').open", 'grant details')
        assert browser.js("document.querySelectorAll('#grant-facts > div').length <= 5")
        assert browser.js("document.querySelector('#grant-technical').open") is False
        assert browser.js("document.querySelector('#grant-technical').textContent.includes('ID доступа')")
        browser.click('#grant-technical > summary')
        assert browser.js("document.querySelector('#grant-technical').open") is True
        browser.click('#grant-window [value="cancel"]')
        browser.wait("!document.querySelector('#grant-window').open", 'grant closed')
        assert browser.js("!!document.querySelector('#client-management')")


def test_linked_node_detail_tabs_keep_actions_and_clear_the_dialog_on_close(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('fleet', "!!document.querySelector('.linked-node')", width=320)
        browser.click('.linked-node [data-node-action="open"]')
        browser.wait("document.querySelector('#node-window').open", 'linked node')
        browser.click('#node-window [data-node-action="tab-users"]')
        browser.wait("!!document.querySelector('#node-window .import-table')", 'node inventory')
        browser.click('#node-window [data-node-action="tab-updates"]')
        browser.wait("document.querySelector('#node-window [data-node-action=" + '"tab-updates"' + "]').getAttribute('aria-selected') === 'true'", 'maintenance tab')
        browser.dt.call('Input.dispatchKeyEvent', {'type': 'keyDown', 'key': 'Escape', 'code': 'Escape', 'windowsVirtualKeyCode': 27})
        browser.wait("!document.querySelector('#node-window').open", 'escape closes details')
        browser.wait("document.querySelector('#node-window-body').childElementCount === 0", 'details cleaned')


def test_protocol_rows_keep_the_primary_action_and_group_secondary_controls(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = fixture.api('/api/clients', 'POST', {'display_name': 'Phone', 'subscription': False})
        result = fixture.api(f"/api/clients/{client['id']}/grants", 'POST', {'grants': [
            {'protocol': protocol, 'node_id': 'local', 'runtime_username': 'phone', 'options': {}}
            for protocol in ('mtproxy', 'naive', 'mieru', 'trusttunnel')
        ]})
        assert result['status'] == 'succeeded'
        for view in ('users', 'naive', 'mieru', 'trusttunnel'):
            browser.open_view(view, "!!document.querySelector('.row-actions button')", width=390)
            assert browser.js("document.querySelectorAll('.row-actions > button').length <= 2"), view
            assert browser.js("!!document.querySelector('.row-actions .actions-menu')"), view
            browser.click('.row-actions .actions-menu > summary')
            assert browser.js("document.querySelector('.row-actions .actions-menu').open"), view
            assert browser.js("document.querySelector('.row-actions .actions-menu').getBoundingClientRect().right <= innerWidth"), view
            browser.dt.call('Input.dispatchKeyEvent', {'type': 'keyDown', 'key': 'Escape', 'code': 'Escape', 'windowsVirtualKeyCode': 27})
            browser.wait("!document.querySelector('.row-actions .actions-menu').open", 'menu dismissed')


def test_browser_back_closes_nested_details_without_losing_the_client_list(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = seed_client(fixture)
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="open"]')
        browser.wait("!!document.querySelector('#subscription-grants [data-grant-open]')", 'client ready')
        browser.click('#subscription-grants [data-grant-open]')
        browser.wait("document.querySelector('#grant-window').open", 'grant ready')
        browser.js('history.back(); true')
        browser.wait("!document.querySelector('#grant-window').open", 'back closes grant')
        assert browser.js("!!document.querySelector('#client-management')")
        browser.js('history.back(); true')
        browser.wait("!document.querySelector('#client-management')", 'back closes client')
        assert browser.js("location.hash") == '#clients'
        browser.wait("!!document.querySelector('.client-card')", 'list restored')


def test_viewer_sees_node_details_without_mutation_controls(tmp_path):
    with isolated_panel(tmp_path, role='viewer') as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('fleet', "!!document.querySelector('.local-node')", width=390)
        assert browser.js("document.querySelectorAll('#view .node-actions button').length") == 0
        browser.click('.local-node [data-node-action="open"]')
        browser.wait("document.querySelector('#node-window').open", 'viewer details')
        browser.click('#node-window [data-node-action="tab-updates"]')
        browser.wait("!!document.querySelector('#node-window .node-local-link')", 'viewer maintenance')
        assert browser.js("document.querySelectorAll('#node-window [data-node-action=" + '"center-key"' + "]').length") == 0
        assert browser.js("document.querySelectorAll('#node-window [data-node-action=" + '"unlink"' + "]').length") == 0


def test_routing_secondary_actions_and_version_help_are_collapsed(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('routing', "!!document.querySelector('.routing-actions')", width=390)
        assert browser.js("document.querySelectorAll('.routing-actions > button').length") == 2
        assert browser.js("!!document.querySelector('.routing-actions .actions-menu [data-routing-action=rollback]')")
        assert browser.js("!!document.querySelector('.routing-actions .actions-menu [data-routing-action=delete]')")
        browser.open_view('versions', "!!document.querySelector('.version-card')", width=390)
        assert browser.js("document.querySelector('#view > .page-help').open") is False
        assert browser.js("!!document.querySelector('[data-version-check]')")


def test_client_details_return_to_the_same_filtered_list_position_and_focus(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        for index in range(12):
            fixture.api('/api/clients', 'POST', {'display_name': f'Device {index}', 'subscription': False})
        browser.open_view('clients', "document.querySelectorAll('.client-card').length >= 12", width=390)
        browser.set_value('#client-search', 'Device')
        browser.wait("document.querySelectorAll('.client-card').length === 12", 'filtered list')
        browser.js("document.querySelector('.client-card:last-child').scrollIntoView({block:'center'}); true")
        before = browser.js('window.scrollY')
        assert before > 50
        browser.click('.client-card:last-child [data-client-action="open"]')
        browser.wait("!!document.querySelector('#client-management')", 'client opened')
        browser.click('#client-management [data-management-back]')
        browser.wait("!document.querySelector('#client-management')", 'client closed')
        browser.wait("document.querySelectorAll('.client-card').length === 12 && Math.abs(window.scrollY - " + str(before) + ") <= 1", 'position restored')
        assert browser.js("document.querySelector('#client-search').value") == 'Device'
        browser.wait("document.activeElement?.matches('.client-card:last-child [data-client-action=" + '"open"' + "]')", 'focus restored')


def test_client_management_is_a_page_and_returns_to_the_filtered_list(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        clients = [fixture.api('/api/clients', 'POST', {'display_name': f'Device {index}', 'subscription': False})
                   for index in range(12)]
        client = clients[-1]
        result = fixture.api(f"/api/clients/{client['id']}/grants", 'POST', {'grants': [
            {'protocol': 'trusttunnel', 'node_id': 'local', 'runtime_username': 'phone', 'options': {}},
        ]})
        assert result['status'] == 'succeeded'
        browser.open_view('clients', "document.querySelectorAll('.client-card').length >= 12", width=390)
        browser.set_value('#client-search', 'Device')
        browser.wait("document.querySelectorAll('.client-card').length === 12", 'filtered list')
        selector = f'.client-card[data-client-id="{client["id"]}"] [data-client-action="open"]'
        browser.js('document.querySelector(' + repr(selector) + ').scrollIntoView({block:"center"}); true')
        before = browser.js('window.scrollY')
        browser.click(selector)
        browser.wait("!!document.querySelector('#client-management #subscription-grants [data-grant-open]')", 'management page')
        assert browser.js("!document.querySelector('#subscription-modal').open")
        assert browser.js("document.querySelector('#client-management').textContent.includes('Device 11')")
        assert browser.js("document.querySelector('#client-management').textContent.includes('без ограничений')")
        assert browser.js('''(() => [...document.querySelectorAll('#client-management button')]
          .filter(e => e.getClientRects().length).every(e => {const r = e.getBoundingClientRect(); return r.width >= 44 && r.height >= 44;}))()''')
        browser.click('#client-management [data-management-back]')
        browser.wait("!document.querySelector('#client-management')", 'return to list')
        assert browser.js("document.querySelector('#client-search').value") == 'Device'
        browser.wait('Math.abs(window.scrollY - ' + str(before) + ') <= 1', 'scroll restored')


def test_management_grant_rows_fit_with_multiple_nodes_and_app_labels(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = seed_client(fixture)
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=1440)
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="open"]')
        browser.wait("!!document.querySelector('#client-management #subscription-grants [data-grant-open]')", 'management')
        browser.js("""(async () => {
          const {grantRowHtml} = await import('/static/js/grant.js');
          const nodes = Array.from({length: 4}, (_, i) => ({node_id: `node-${i}`, display_name: `Узел ${i + 1}`}));
          const protocols = ['mtproxy', 'naive', 'mieru', 'trusttunnel'];
          const rows = nodes.flatMap((node, n) => protocols.map((protocol, p) => ({
            id: `sample-${n}-${p}`, node_id: node.node_id, protocol,
            runtime_username: n === 3 ? 'very-long-synthetic-client-name-for-layout' : 'sample-client',
            desired_state: 'enabled', observed_state: 'enabled', secret_ref: 'synthetic', options: {}
          })));
          const extra = '<span class="grant-restrictions">без ограничений</span>' +
            '<span class="auto-refresh"><small>karing</small><small>singbox</small><small>mihomo</small><small>throne</small></span>';
          document.querySelector('#subscription-grants').innerHTML = rows.map(grant => grantRowHtml(grant, {nodes, extra})).join('');
          const matrix = document.querySelector('#placement-body tbody');
          while (matrix.children.length < 4) {
            const row = matrix.firstElementChild.cloneNode(true);
            row.querySelector('th').textContent = `Узел ${matrix.children.length + 1}`;
            matrix.append(row);
          }
          return true;
        })()""")
        for width in (320, 390, 768, 1440):
            browser.dt.call('Emulation.setDeviceMetricsOverride', {
                'width': width, 'height': 900, 'deviceScaleFactor': 1, 'mobile': width < 600,
            })
            result = browser.js("""(() => {
              const page = document.querySelector('#client-management');
              const title = page.querySelector('h2').getBoundingClientRect();
              const placement = page.querySelector('.placement-box').getBoundingClientRect();
              const rows = [...page.querySelectorAll('.grant-row')];
              return {
                count: rows.length,
                nodes: page.querySelectorAll('#placement-body tbody tr').length,
                horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
                headingGap: placement.top - title.bottom,
                maxRowHeight: Math.max(...rows.map(row => row.getBoundingClientRect().height)),
                escaped: rows.some(row => {
                  const outer = row.getBoundingClientRect();
                  return [...row.children].some(child => {
                    const r = child.getBoundingClientRect();
                    return r.width && (r.left < outer.left - 1 || r.right > outer.right + 1 || r.bottom > outer.bottom + 1);
                  });
                }),
              };
            })()""")
            assert result['count'] == 16 and result['nodes'] == 4 and not result['horizontalOverflow'] and not result['escaped'], (width, result)
            assert result['headingGap'] <= 64, (width, result)
            if width == 1440:
                assert result['maxRowHeight'] <= 100, (width, result)
            if os.environ.get('UI_MANAGEMENT_SHOTS'):
                folder = Path(os.environ['UI_MANAGEMENT_SHOTS'])
                folder.mkdir(parents=True, exist_ok=True)
                shot = browser.dt.call('Page.captureScreenshot', {'format': 'png'})
                (folder / f'management-{width}.png').write_bytes(base64.b64decode(shot['data']))
        browser.healthy()


def test_management_displays_a_failed_change_on_the_page(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = seed_client(fixture)
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="open"]')
        browser.wait("!!document.querySelector('#client-management #placement-body input[data-protocol=\"amneziawg:2.0\"]')", 'management')
        browser.js("""(() => {const input = document.querySelector('#client-management input[data-node=local][data-protocol="amneziawg:2.0"]');
          input.checked = true; input.dispatchEvent(new Event('change', {bubbles:true}));
          const original = window.fetch.bind(window);
          window.fetch = (url, options) => /\\/api\\/clients\\/[^/]+\\/grants$/.test(String(url)) && options?.method === 'POST'
            ? Promise.resolve(new Response(JSON.stringify({detail:'test management refusal'}), {status:409,headers:{'content-type':'application/json'}}))
            : original(url, options); return true; })()""")
        browser.click('#client-management [data-placement-action=apply]')
        browser.wait("document.querySelector('#client-management [role=alert]').textContent.includes('test management refusal')", 'visible error')


def test_late_management_response_does_not_reopen_a_secret_dialog(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = seed_client(fixture)
        browser.open_view('clients', "!!document.querySelector('.client-card')", width=390)
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="open"]')
        browser.wait("!!document.querySelector('#client-management input[data-protocol=\"amneziawg:2.0\"]')", 'management')
        browser.js("""(() => {const input = document.querySelector('#client-management input[data-node=local][data-protocol="amneziawg:2.0"]');
          input.checked = true; input.dispatchEvent(new Event('change', {bubbles:true}));
          window.__applyButton = document.querySelector('#client-management [data-placement-action=apply]');
          const original = window.fetch.bind(window);
          window.fetch = async (url, options) => {
            if (/\\/api\\/clients\\/[^/]+\\/grants$/.test(String(url)) && options?.method === 'POST') {
              await new Promise(resolve => {window.__resumeGrant = resolve;});
              const response = await original(url, options); window.__grantReply = true; return response;
            }
            return original(url, options);
          }; return true; })()""")
        browser.click('#client-management [data-placement-action=apply]')
        browser.wait("typeof window.__resumeGrant === 'function'", 'operation delayed')
        browser.click('#client-management [data-management-back]')
        browser.wait("!document.querySelector('#client-management')", 'returned to list')
        browser.js('window.__resumeGrant(); true')
        browser.wait("window.__grantReply && !window.__applyButton.disabled", 'request completed')
        assert browser.js("!document.querySelector('#bundle-modal').open && !document.querySelector('#subscription-modal').open")
        assert browser.js("!document.querySelector('#bundle-body').childElementCount && !document.querySelector('#subscription-chooser [data-client-page-url]')")
