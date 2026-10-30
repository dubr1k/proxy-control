"""Access names and node glyphs as rendered in an isolated real browser."""
from scripts.lab.ui_protocol_dialog_check import isolated_browser, isolated_panel


def test_mobile_node_and_client_glyphs_are_centered(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        fixture.api("/api/clients", "POST", {"display_name": "Phone", "subscription": False})
        for width in (390, 320, 1440):
            for view, selector in (("fleet", ".node-card > .user-glyph"),
                                   ("clients", ".client-card > .user-glyph")):
                browser.open_view(view, f"!!document.querySelector('{selector}')", width=width)
                assert browser.js("""(() => {
                    return [...document.querySelectorAll('""" + selector + """')].every(tile => {
                        const outer = tile.getBoundingClientRect();
                        const inner = tile.querySelector('svg').getBoundingClientRect();
                        return Math.abs((outer.left + outer.right - inner.left - inner.right) / 2) <= 1
                            && Math.abs((outer.top + outer.bottom - inner.top - inner.bottom) / 2) <= 1;
                    });
                })()"""), (width, view)


def test_local_node_uses_components_instead_of_missing_legacy_inventory(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        browser.open_view("fleet", "!!document.querySelector('.local-node')", width=390)
        assert browser.js("document.querySelector('.local-node').textContent.includes('Telemt не определён')") is False
        assert browser.js("document.querySelector('.local-node').textContent.includes('Локальные протоколы управляются напрямую')") is False
        browser.click('.local-node [data-node-action="open"]')
        browser.wait("document.querySelector('#node-window').open", "node details")
        assert browser.js("!!document.querySelector('#node-window .node-services')") is True


def test_grant_window_shows_the_protocol_after_a_custom_subscription_name(tmp_path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        client = fixture.api("/api/clients", "POST", {"display_name": "Phone", "subscription": False})
        issued = fixture.api(f"/api/clients/{client['id']}/grants", "POST", {"grants": [
            {"protocol": "trusttunnel", "node_id": "local", "runtime_username": "phone", "options": {}},
        ]})
        assert issued["status"] == "succeeded"
        grant = fixture.api(f"/api/clients/{client['id']}")["grants"][0]
        fixture.api(f"/api/clients/grants/{grant['id']}/label", "POST", {"label": "Ams-server"})
        browser.open_view("clients", "!!document.querySelector('.client-card')", width=390)
        browser.click(f'.client-card[data-client-id="{client["id"]}"] [data-client-action="open"]')
        browser.wait("!!document.querySelector('#subscription-grants [data-grant-open]')", "client accesses")
        browser.click("#subscription-grants [data-grant-open]")
        browser.wait("!!document.querySelector('#grant-facts dd')", "grant details")
        assert browser.js("""[...document.querySelectorAll('#grant-technical-facts > div')]
            .find(row => row.querySelector('dt').textContent === 'Название в подписке')
            .querySelector('dd').textContent""") == "Ams-server · TrustTunnel"
