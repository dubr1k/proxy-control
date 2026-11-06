"""Owner's release UI requests against real Rust HTTP and Chromium, synthetic state only."""
import pytest

from scripts.lab.ui_protocol_dialog_check import OverviewFixture, isolated_browser, isolated_panel


def test_dashboard_last_row_fills_available_width(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        for width in (390, 1000, 1440, 1920):
            browser.open_view('dashboard', "document.querySelectorAll('.protocol-traffic').length === 5", width=width)
            assert browser.js("document.querySelectorAll('.protocol-traffic > em, .service-list, .system-mini').length") == 0
            assert browser.js("""(() => {
                const cards = [...document.querySelectorAll('.protocol-overview > .protocol-card:not(.host-card)')];
                const last = cards.at(-1).getBoundingClientRect();
                const group = document.querySelector('.protocol-overview').getBoundingClientRect();
                return Math.abs(last.right - group.right) <= 1 && document.documentElement.scrollWidth <= innerWidth + 1;
            })()"""), width


@pytest.mark.parametrize('view', ['users', 'mieru', 'amneziawg', 'trusttunnel'])
def test_protocol_summary_uses_accent_and_keeps_status_on_mobile(tmp_path, view):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        for width in (390, 1440):
            browser.open_view(view, "!!document.querySelector('#view .data-panel')", width=width)
            assert browser.js("!!document.querySelector('.service-overview .service-summary .status-pill')"), view
            before = browser.js("getComputedStyle(document.querySelector('.service-summary')).backgroundImage")
            browser.click('#accent-button')
            browser.click('.accent-swatch[data-accent="emerald"]')
            after = browser.js("getComputedStyle(document.querySelector('.service-summary')).backgroundImage")
            assert before != after
            assert browser.js('document.documentElement.scrollWidth <= innerWidth + 1')
            browser.js("localStorage.removeItem('proxy-control.accent'); document.documentElement.removeAttribute('data-accent'); true")


def test_node_status_and_actions_share_a_row(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        for width in (390, 1440):
            browser.open_view('fleet', "!!document.querySelector('.linked-node')", width=width)
            assert browser.js("""[...document.querySelectorAll('.compact-node')].every(card => {
                const pill = card.querySelector(':scope > .status-pill').getBoundingClientRect();
                const button = card.querySelector('.node-card-actions > button').getBoundingClientRect();
                return Math.abs((pill.top + pill.bottom - button.top - button.bottom) / 2) <= 1;
            })"""), width


def test_mobile_node_menu_does_not_overlap_warning(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        for width in (320, 390):
            browser.open_view('fleet', "!!document.querySelector('.compact-node .card-warning')", width=width)
            browser.click('.compact-node:has(.card-warning) .actions-menu > summary')
            assert browser.js("""(() => {
                const card = document.querySelector('.compact-node:has(.card-warning)');
                const warning = card.querySelector('.card-warning').getBoundingClientRect();
                const menu = card.querySelector('.node-card-actions').getBoundingClientRect();
                return (warning.bottom <= menu.top || menu.bottom <= warning.top)
                    && card.scrollWidth <= card.clientWidth + 1;
            })()"""), width


def test_routing_lists_are_visible_and_sources_open_prefilled_settings(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        for width in (390, 1440):
            browser.open_view('routing', "!!document.querySelector('.routing-card')", width=width)
            assert browser.js("""(() => {
                const lists = document.querySelector('.routing-lists');
                return lists && lists.getBoundingClientRect().height > 0 && !lists.closest('.routing-node-setup');
            })()""")
            browser.wait("!!document.querySelector('[data-geodata-source=" + '"runetfreedom"' + "]:not(:disabled)')", 'list settings loaded')
            browser.click('[data-geodata-source="runetfreedom"]')
            browser.wait("document.querySelector('#geodata-modal').open", 'list source settings')
            assert browser.js("document.querySelector('#geodata-source').value") == 'runetfreedom'
            browser.click('#geodata-modal [value="cancel"]')
            assert browser.js('document.documentElement.scrollWidth <= innerWidth + 1')


def test_extra_accent_colours_persist_across_reload(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('dashboard', "!!document.querySelector('.host-card')", width=390)
        browser.click('#accent-button')
        assert browser.js("document.querySelectorAll('.accent-swatch').length") >= 13
        browser.click('.accent-swatch[data-accent="amber"]')
        browser.open_view('dashboard', "!!document.querySelector('.host-card')", width=390)
        assert browser.js('document.documentElement.dataset.accent') == 'amber'
        browser.click('#accent-button')
        assert browser.js("document.querySelector('.accent-swatch[data-accent=" + '"amber"' + "]').getAttribute('aria-checked')") == 'true'


@pytest.mark.parametrize('source,repository', [
    ('metacubex', 'MetaCubeX/meta-rules-dat/releases/download/latest'),
    ('refilter', '1andrevich/Re-filter-lists/releases/latest/download'),
])
def test_catalogue_source_saves_https_pair_and_auto_update_schedule(tmp_path, source, repository):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('routing', "!!document.querySelector('.routing-lists')", width=390)
        assert browser.js("document.querySelectorAll('[data-geodata-source]').length") >= 9
        browser.wait("!!document.querySelector('[data-geodata-source=" + '"' + source + '"' + "]:not(:disabled)')", 'catalogue settings loaded')
        browser.click(f'[data-geodata-source="{source}"]')
        browser.wait("document.querySelector('#geodata-modal').open", 'catalogue source')
        assert browser.js("document.querySelector('#geodata-source').value") == source
        browser.js("document.querySelector('#geodata-auto').checked = true; true")
        browser.set_value('#geodata-interval', '48')
        browser.set_value('#geodata-hour', '4')
        browser.click('#geodata-save')
        browser.wait("!document.querySelector('#geodata-modal').open", 'source saved')
        view = fixture.api('/api/routing/geodata?node=local')
        assert view['source'] == {
            'kind': 'custom',
            'geosite_url': f'https://github.com/{repository}/geosite.dat',
            'geoip_url': f'https://github.com/{repository}/geoip.dat',
        }
        assert (view['auto_update'], view['interval_hours'], view['update_hour']) == (True, 48, 4)
        browser.wait("!!document.querySelector('[data-geodata-source=" + '"' + source + '"' + "].selected')", 'saved catalogue selection')
        browser.click('[data-routing-action="geodata-settings"]:not([data-geodata-source])')
        browser.wait("document.querySelector('#geodata-modal').open", 'saved settings reopened')
        assert browser.js("document.querySelector('#geodata-source').value") == source
        assert browser.js("document.querySelector('#geodata-hour').value") == '4'


def test_versions_show_updates_and_bulk_confirmation_can_be_cancelled(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('versions', "!!document.querySelector('.version-card')", width=390)
        assert browser.js("document.querySelectorAll('.version-available').length") == 4
        browser.click('[data-version-update-all]')
        browser.wait("document.querySelector('#confirm').open", 'bulk confirmation')
        assert browser.js("document.querySelector('#confirm-text').textContent.includes('3.36.0')")
        browser.click('#confirm [value="cancel"]')
        assert fixture.versions.calls == []


def test_bulk_update_is_sequential_uses_raw_current_and_updates_panel_last(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('versions', "!!document.querySelector('.version-card')", width=1440)
        browser.click('[data-version-update-all]')
        browser.wait("document.querySelector('#confirm').open", 'bulk confirmation')
        browser.click('#confirm-ok')
        browser.wait("document.querySelector('[data-version-update-all]')?.disabled === true && !document.querySelector('#confirm').open", 'updates started')
        browser.wait("document.querySelectorAll('.version-card').length > 0 && document.querySelectorAll('.version-available').length === 0", 'updates completed')
        assert fixture.versions.calls == [
            ('telemt', '3.4.25', '3.4.24'), ('mita', '3.36.0', '3.34.0'),
            ('naive', '2.11.4', '2.11.3'), ('panel', '0.11.0-beta.1', '0.10.0-beta.1'),
        ]


def test_bulk_update_stops_after_failure(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('versions', "!!document.querySelector('.version-card')", width=1440)
        browser.click('[data-version-update-all]')
        browser.wait("document.querySelector('#confirm').open", 'bulk confirmation')
        fixture.versions.components['telemt']['current'] = '3.4.26'
        browser.click('#confirm-ok')
        browser.wait("document.querySelector('.toast.error') !== null", 'version conflict')
        assert len(fixture.versions.calls) == 1
        assert fixture.versions.calls[0] == ('telemt', '3.4.25', '3.4.24')
