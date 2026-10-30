"""Compact overview lists retain status, detail actions and keyboard/mobile access."""
from scripts.lab.ui_protocol_dialog_check import OverviewFixture, isolated_browser, isolated_panel


def seed_client(fixture):
    client = fixture.api('/api/clients', 'POST', {'display_name': 'Phone', 'subscription': False})
    result = fixture.api(f"/api/clients/{client['id']}/grants", 'POST', {'grants': [
        {'protocol': 'trusttunnel', 'node_id': 'local', 'runtime_username': 'phone', 'options': {}},
    ]})
    assert result['status'] == 'succeeded'
    return client


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
        assert browser.js("document.querySelector('#subscription-modal').open")


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
        assert browser.js("document.querySelector('#subscription-modal').open")
        browser.js('history.back(); true')
        browser.wait("!document.querySelector('#subscription-modal').open", 'back closes client')
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
        browser.wait("document.querySelector('#subscription-modal').open", 'client opened')
        browser.click('#subscription-modal [value="cancel"]')
        browser.wait("!document.querySelector('#subscription-modal').open", 'client closed')
        browser.wait("document.querySelectorAll('.client-card').length === 12 && Math.abs(window.scrollY - " + str(before) + ") <= 1", 'position restored')
        assert browser.js("document.querySelector('#client-search').value") == 'Device'
        browser.wait("document.activeElement?.matches('.client-card:last-child [data-client-action=" + '"open"' + "]')", 'focus restored')
