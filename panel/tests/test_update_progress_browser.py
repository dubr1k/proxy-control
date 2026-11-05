"""Persisted agent operation is readable after a real page reload, including rollback."""
from scripts.lab.ui_protocol_dialog_check import OverviewFixture, isolated_browser, isolated_panel


def test_update_progress_survives_refresh_and_poll_shows_rollback(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        fixture.versions.components['telemt']['operation'] = {
            'from_version': '3.4.24', 'target_version': '3.4.25',
            'status': 'running', 'stage': 'building', 'started_at': 1700000000,
        }
        for width in (390, 1440):
            browser.open_view('versions', "!!document.querySelector('.version-operation')", width=width)
            assert browser.js("document.querySelector('.version-operation').textContent.includes('Сборка')")
            assert browser.js("document.querySelector('[data-version-update-all]').disabled")
            assert browser.js('document.documentElement.scrollWidth <= innerWidth + 1')
        fixture.versions.components['telemt']['operation'].update(
            status='rolled_back', stage='finished', finished_at=1700000001,
            error='Update failed; previous generation was restored and verified',
        )
        browser.wait("document.querySelector('.version-operation')?.textContent.includes('выполнен откат')", 'rollback appears by polling')
        browser.open_view('versions', "document.querySelector('.version-operation')?.textContent.includes('выполнен откат')", width=390)
        assert browser.js("document.querySelector('.version-operation').textContent.includes('3.4.25')")
        assert browser.js("document.querySelector('.version-operation').textContent.includes('3.4.24')")
        for status, label in (
            ('update_failed', 'Обновление не удалось'),
            ('rollback_failed', 'Откат не подтверждён'),
            ('interrupted', 'Обновление прервано'),
            ('succeeded', 'Обновление завершено'),
        ):
            fixture.versions.components['telemt']['operation']['status'] = status
            browser.open_view('versions', f"document.querySelector('.version-operation')?.textContent.includes('{label}')", width=390)
        browser.js("localStorage.setItem('proxy-control.lang', 'en'); true")
        browser.open_view('versions', "document.querySelector('.version-operation')?.textContent.includes('Update completed')", width=1440)


def test_known_update_recovers_after_repeated_agent_unavailability(tmp_path):
    with isolated_panel(tmp_path, OverviewFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        operation = {
            'from_version': '3.4.24', 'target_version': '3.4.25',
            'status': 'running', 'stage': 'verifying', 'started_at': 1700000000,
        }
        fixture.versions.components['telemt']['operation'] = operation
        browser.open_view('versions', "!!document.querySelector('.version-operation')", width=390)
        original = fixture.versions.list_versions
        failures = {'remaining': 2, 'served': 0}

        async def temporarily_unavailable():
            if failures['remaining']:
                failures['remaining'] -= 1
                failures['served'] += 1
                return {'enabled': False, 'components': {}}
            return await original()

        fixture.versions.list_versions = temporarily_unavailable
        operation.update(status='succeeded', stage='finished', finished_at=1700000001)
        browser.wait("document.querySelector('.version-operation')?.textContent.includes('Обновление завершено')", 'result recovers automatically after two degraded polls')
        assert failures['served'] == 2
