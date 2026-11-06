"""Direct updates and secondary version selection in real Chromium/Rust HTTP."""
import pytest

from scripts.lab.ui_protocol_dialog_check import OverviewFixture, isolated_browser, isolated_panel


@pytest.mark.parametrize('width', [390, 1440])
def test_direct_update_uses_latest_without_selecting_a_version(tmp_path, width):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('versions', "!!document.querySelector('.version-card')", width=width)
        button = '[data-version-update="mita"][data-version-target]'
        assert browser.js(f"document.querySelector('{button}')?.textContent") == 'Обновить до 3.36.0'
        assert browser.js("document.querySelector('[data-version-select=\"mita\"]').value") == ''
        assert browser.js("!document.querySelector('[data-version-select=\"mita\"]').closest('details').open")
        assert browser.js('document.documentElement.scrollWidth <= innerWidth + 1')
        browser.click(button)
        browser.wait("document.querySelector('#confirm').open", 'direct update confirmation')
        browser.click('#confirm-ok')
        browser.wait("!document.querySelector('[data-version-update=\"mita\"][data-version-target]')", 'update completed')
        assert fixture.versions.calls == [('mita', '3.36.0', '3.34.0')]


def test_secondary_selection_does_not_change_direct_target_and_keeps_rollback(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        fixture.versions.components['telemt']['available'].append({'version': '3.4.23', 'kind': 'image', 'newer': False})
        browser.open_view('versions', "!!document.querySelector('.version-card')", width=390)
        browser.click('.version-card:has([data-version-select="telemt"]) details > summary')
        browser.js("""(() => {
            const select = document.querySelector('[data-version-select="telemt"]');
            select.value = '3.4.23'; select.dispatchEvent(new Event('change', {bubbles:true})); return true;
        })()""")
        assert browser.js("document.querySelector('[data-version-update=\"telemt\"][data-version-target]').textContent") == 'Обновить до 3.4.25'
        browser.click('[data-version-update="telemt"]:not([data-version-target])')
        browser.wait("document.querySelector('#confirm').open", 'rollback confirmation')
        assert browser.js("document.querySelector('#confirm-ok').textContent") == 'Откатить'
        browser.click('#confirm-ok')
        browser.wait("document.querySelector('.toast')?.textContent.includes('3.4.23')", 'rollback completed')
        assert fixture.versions.calls == [('telemt', '3.4.23', '3.4.24')]


def test_uninstallable_and_busy_components_have_no_direct_update(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        fixture.versions.components['telemt'].update(available=[], upstream={'latest': '3.4.25', 'reason': 'no_published_digest'})
        fixture.versions.components['naive']['status'] = 'updating'
        browser.open_view('versions', "!!document.querySelector('.version-card')", width=1440)
        assert browser.js("!document.querySelector('[data-version-update=\"telemt\"][data-version-target]')")
        assert browser.js("!document.querySelector('[data-version-update=\"naive\"][data-version-target]')")
        assert browser.js("document.querySelector('[data-version-update=\"mita\"][data-version-target]').disabled")


def test_direct_build_preserves_warning_raw_identity_and_cancellation(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        fixture.versions.components['telemt'].update(current='sha256:123456789abc', available=[
            {'version': '3.4.24', 'image': 'example@sha256:123456789abc'},
            {'version': '3.4.25', 'kind': 'build'},
            {'version': '3.4.23', 'kind': 'image', 'newer': False},
        ])
        browser.open_view('versions', "!!document.querySelector('.version-card')", width=390)
        browser.js("""(() => {
            const select = document.querySelector('[data-version-select="telemt"]');
            select.value = '3.4.23'; select.dispatchEvent(new Event('change', {bubbles:true})); return true;
        })()""")
        browser.click('[data-version-update="telemt"][data-version-target]')
        browser.wait("document.querySelector('#confirm').open", 'build confirmation')
        assert browser.js("document.querySelector('#confirm-text').textContent.includes('3.4.24 → 3.4.25')")
        assert browser.js("document.querySelector('#confirm-text').textContent.includes('из бинарника релиза')")
        assert browser.js("document.querySelector('#confirm-ok').textContent") == 'Обновить'
        browser.click('#confirm [value="cancel"]')
        assert fixture.versions.calls == []
        browser.click('[data-version-update="telemt"][data-version-target]')
        browser.wait("document.querySelector('#confirm').open", 'build confirmation again')
        browser.click('#confirm-ok')
        browser.wait("!document.querySelector('[data-version-update=\"telemt\"][data-version-target]')", 'build completed')
        assert fixture.versions.calls == [('telemt', '3.4.25', 'sha256:123456789abc')]


def test_direct_panel_update_and_english_labels(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view('versions', "!!document.querySelector('.version-card')", width=1440)
        browser.js("localStorage.setItem('proxy-control.lang', 'en'); true")
        browser.open_view('versions', "document.querySelector('[data-version-update=\"panel\"][data-version-target]')?.textContent.includes('Update to')", width=390)
        assert browser.js("document.querySelector('.version-choice summary').textContent") == 'Choose version'
        browser.click('[data-version-update="panel"][data-version-target]')
        browser.wait("document.querySelector('#confirm').open", 'panel confirmation')
        browser.click('#confirm-ok')
        browser.wait("!document.querySelector('[data-version-update=\"panel\"][data-version-target]')", 'panel update completed')
        assert fixture.versions.calls == [('panel', '0.11.0-beta.1', '0.10.0-beta.1')]
