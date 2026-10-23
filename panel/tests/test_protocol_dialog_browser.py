"""Real-browser regressions for protocol-screen issuance, without production state.

The same helpers power scripts/lab/ui_protocol_dialog_check.py. Tests deliberately
navigate straight to each protocol with a fresh JS state, never via Clients/Nodes.
"""
import json
from pathlib import Path

import pytest

from scripts.lab.ui_protocol_dialog_check import (
    check_empty_state,
    check_node_dialog,
    check_remote_issuance,
    isolated_browser,
    isolated_panel,
)


@pytest.fixture
def protocol_browser(tmp_path: Path):
    with isolated_panel(tmp_path) as fixture, isolated_browser(tmp_path, fixture) as browser:
        yield browser


@pytest.mark.parametrize("protocol", ["amneziawg", "trusttunnel"])
def test_direct_protocol_dialog_refreshes_eligible_nodes_and_versions(protocol_browser, protocol):
    check_node_dialog(protocol_browser, protocol)


@pytest.mark.parametrize("protocol", ["amneziawg", "trusttunnel"])
@pytest.mark.parametrize("width", [1440, 390])
def test_protocol_empty_state_has_separate_nonoverlapping_rows(protocol_browser, protocol, width):
    check_empty_state(protocol_browser, protocol, width)


@pytest.mark.parametrize("protocol", ["amneziawg", "trusttunnel"])
def test_protocol_dialog_issues_on_selected_real_remote_panel(protocol_browser, protocol):
    check_remote_issuance(protocol_browser, protocol)


def hold_first_real_responses(browser, paths):
    """Delay delivery, never replace either the real request or its real response."""
    browser.js(f"""(() => {{
      const paths = new Set({json.dumps(paths)});
      const fetch = window.fetch;
      window.__heldProtocolResponses = {{}};
      window.fetch = async (...args) => {{
        const path = new URL(typeof args[0] === 'string' ? args[0] : args[0].url, location.href).pathname;
        if (!paths.has(path) || window.__heldProtocolResponses[path]) return fetch(...args);
        const held = {{arrived: false, consumed: false}};
        window.__heldProtocolResponses[path] = held;
        const gate = new Promise(resolve => {{ held.release = resolve; }});
        const response = await fetch(...args);
        // Buffer a clone before holding: network/body arrival is not a timing assumption.
        await response.clone().arrayBuffer();
        held.arrived = true;
        const parse = response.json.bind(response);
        response.json = async () => {{
          try {{ return await parse(); }} finally {{ held.consumed = true; }}
        }};
        await gate;
        return response;
      }};
      return true;
    }})()""")


def wait_for_held_responses(browser, paths):
    browser.wait(
        f"{json.dumps(paths)}.every(path => window.__heldProtocolResponses[path]?.arrived)",
        "first real responses waiting at delivery barrier",
    )


def release_held_responses(browser, paths):
    browser.js(f"{json.dumps(paths)}.forEach(path => window.__heldProtocolResponses[path].release()); true")
    browser.wait(
        f"{json.dumps(paths)}.every(path => window.__heldProtocolResponses[path]?.consumed)",
        "released real response bodies consumed",
    )
    # Promise continuations (API parser, helper and modal) finish before this next task.
    browser.js("new Promise(resolve => setTimeout(() => resolve(true), 0))")


def test_awg_create_stays_disabled_until_node_capabilities_arrive(protocol_browser):
    browser = protocol_browser
    browser.open_screen("amneziawg")
    hold_first_real_responses(browser, ["/api/nodes"])
    browser.click("#add")
    browser.wait("document.querySelector('#awg-modal')?.open === true", "AWG dialog")
    wait_for_held_responses(browser, ["/api/nodes"])
    browser.set_value("#new-awg-user", "loading-awg")
    assert browser.js("document.querySelector('#create-awg').disabled"), (
        "typing a valid name must not enable issuance while node capabilities are loading"
    )
    release_held_responses(browser, ["/api/nodes"])
    browser.wait("!document.querySelector('#create-awg').disabled", "AWG issuance ready after capabilities")
    assert browser.js(
        "[...document.querySelectorAll('[data-awg-version]:not(:disabled)')].map(e=>e.dataset.awgVersion)"
    ) == ["1.5", "2.0"]
    browser.healthy()


@pytest.mark.parametrize("protocol", ["amneziawg", "trusttunnel"])
def test_reopened_protocol_dialog_ignores_earlier_load_responses(protocol_browser, protocol):
    browser = protocol_browser
    short = "awg" if protocol == "amneziawg" else "tt"
    paths = ["/api/nodes"]
    if short == "tt":
        browser.fixture.api("/api/clients", "POST", {"display_name": "second-tt", "subscription": False})
        paths.append("/api/clients")
    browser.open_screen(protocol)
    hold_first_real_responses(browser, paths)
    browser.click("#add")
    browser.wait(f"document.querySelector('#{short}-modal')?.open === true", "first dialog opening")
    wait_for_held_responses(browser, paths)
    browser.js(f"document.querySelector('#{short}-modal').close(); true")
    # The second opening gets unmodified real responses while the first stays held.
    browser.open_dialog(protocol, 2)
    browser.set_value(f"#{short}-node", browser.fixture.remote_id)
    selected_client = None
    if short == "tt":
        selected_client = browser.js(
            "[...document.querySelectorAll('#tt-client option')].find(e=>e.value !== document.querySelector('#tt-client').value).value"
        )
        browser.set_value("#tt-client", selected_client)
    else:
        browser.set_value("#new-awg-user", "reopened-awg")
        browser.click('[data-awg-version="3.1"]')
    release_held_responses(browser, paths)
    assert browser.js(f"document.querySelector('#{short}-node').value") == browser.fixture.remote_id, (
        "an earlier opening's response must not reset the selected remote"
    )
    if short == "tt":
        assert browser.js("document.querySelector('#tt-client').value") == selected_client, (
            "an earlier opening's clients response must not overwrite the newer client choice"
        )
    else:
        assert browser.js(
            "[...document.querySelectorAll('[data-awg-version]:not(:disabled)')].map(e=>e.dataset.awgVersion)"
        ) == ["3.1"]
        assert browser.js("document.querySelector('[data-awg-version=\"3.1\"]').checked")
    browser.healthy()
