"""Static contract of the overview (v0.11): one host row, three protocol cards, no Mieru
application-bytes tile, a phone layout without horizontal scroll, and the clients badge."""

from __future__ import annotations

from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"
DASHBOARD = (STATIC / "js/dashboard.js").read_text()
CSS = (STATIC / "style.css").read_text()


def test_mieru_card_has_no_application_bytes_tile():
    assert "Application bytes" not in DASHBOARD
    assert "rolling admission" not in DASHBOARD


def test_host_card_is_one_full_width_row_and_protocols_are_three_columns():
    assert 'class="protocol-card host-card host-row' in DASHBOARD
    assert ".protocol-overview{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))" in CSS
    assert ".host-row{grid-column:1/-1" in CSS


def test_overview_has_phone_breakpoints():
    assert "@media(max-width:1040px){.protocol-overview{grid-template-columns:repeat(2,minmax(0,1fr))}" in CSS
    assert "@media(max-width:900px){.protocol-overview{grid-template-columns:1fr}" in CSS
    # The host row's own three-column rule is more specific, so the phone rule names it too.
    assert "@media(max-width:560px){.host-metrics,.host-row .host-metrics{grid-template-columns:1fr}" in CSS


def test_panel_version_is_on_screen_for_every_role_and_on_a_phone():
    """v0.13 (owner, 2026-09-22): which panel is open must be visible in the UI. The sidebar
    is hidden on a phone, so the overview's own row carries it too — and it is read from
    `/api/auth/me`, not from the owner-only «Версии» screen."""
    index = (STATIC / "index.html").read_text()
    main = (STATIC / "js/main.js").read_text()
    nodes = (STATIC / "js/nodes.js").read_text()
    assert 'id="profile-menu-version"' in index
    assert "panel_version" in main and "#profile-menu-version" in main
    assert "state.me?.panel_version" in DASHBOARD
    # And the same measure for the nodes: each node's own components, from its report.
    assert "function componentsLine(versions)" in nodes and "Компоненты" in nodes


def test_host_card_follows_the_host_while_the_overview_is_open():
    """v0.15 (owner: the resources never moved): the card is replaced from `/api/host` every
    few seconds, only for the render that is on screen and only while the tab is visible."""
    assert "const HOST_REFRESH_MS = 5000;" in DASHBOARD
    assert 'api("/api/host")' in DASHBOARD
    assert "void followHost(context, generation);" in DASHBOARD
    assert 'isCurrent(state, generation, "dashboard")' in DASHBOARD and "document.hidden" in DASHBOARD
    assert "data-host-updated=" in DASHBOARD and "обновлено" in DASHBOARD


def test_overview_placeholder_has_the_overviews_own_shape():
    """Owner (2026-09-28): the overview's tiles went 3, then 4, then 1 + 3 while loading.
    The first paint and every later navigation draw the real grid: the resources row and
    three protocol cards."""
    index = (STATIC / "index.html").read_text()
    ui = (STATIC / "js/ui.js").read_text()
    main = (STATIC / "js/main.js").read_text()
    shape = '<div class="protocol-overview skeleton-overview"><i class="host-row"></i><i></i><i></i><i></i></div>'
    assert shape in index and shape in ui
    assert '<div class="skeleton-grid"><i></i><i></i><i></i></div>' not in index
    assert "context.ui.renderSkeleton(name);" in main


def test_swap_is_shown_under_ram_and_an_old_agent_costs_nothing():
    assert "function swapLine(swap)" in DASHBOARD and "swapLine(swap)" in DASHBOARD
    assert "if (!swap) return \"\";" in DASHBOARD and "выключен на сервере" in DASHBOARD
    assert ".host-swap{" in CSS


def test_accent_is_one_variable_and_a_per_browser_choice():
    theme = (STATIC / "js/theme.js").read_text()
    index = (STATIC / "index.html").read_text()
    main = (STATIC / "js/main.js").read_text()
    # Every accent tint derives from --accent: no indigo literal is left outside :root.
    assert "110,107,234" not in CSS
    for name in ("blue", "cyan", "emerald", "violet", "rose", "orange"):
        assert f":root[data-accent={name}]" in CSS and f'"{name}"' in theme
    assert 'id="accent-button"' in index and 'id="accent-menu"' in index
    assert "localStorage" in theme and "  applyAccent();" in main


def test_clients_badge_is_painted_from_the_clients_list():
    common = (STATIC / "js/common.js").read_text()
    assert "export function paintClientsCount(context, total)" in common
    assert '"/api/clients"' in DASHBOARD and "paintClientsCount(context" in DASHBOARD
    # The paginated list's badge is exercised against the rendered DOM in
    # test_clients_filters_ui, including a search returning only one row.
    assert 'id="clients-count"' in (STATIC / "index.html").read_text()
