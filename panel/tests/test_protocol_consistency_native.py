"""Bounded real-Rust UI acceptance; test-owned managers only, no production or reveal dumps."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from scripts.lab.ui_protocol_dialog_check import (
    OverviewFixture, isolated_browser, isolated_panel, require,
)


class ConsistencyFixture(OverviewFixture):
    async def _start(self, work, port):
        await super()._start(work, port)
        # OverviewFixture uses a different panel hostname from MemoryNaive's default.
        # Align the manager fixture before testing direct-create reveal validation.
        self.central.naive.public_host = "naive.example"
        self.central.client.headers["Authorization"] = "Bearer " + self.central.create_api_key("ui-consistency-seed", "admin")
        made = await self.central.client.post("/api/clients", json={"display_name": "Анна — проверка клиента", "subscription": False})
        require(made.status_code == 201, "fixture client creation failed")
        self.holder_id = made.json()["id"]
        issued = await self.central.client.post(f"/api/clients/{self.holder_id}/grants", json={"grants": [
            {"protocol": protocol, "runtime_username": f"anna-{protocol}", "options": {"version": "2.0"} if protocol == "amneziawg" else {}}
            for protocol in ("mtproxy", "naive", "mieru", "amneziawg", "trusttunnel")
        ]})
        require(issued.status_code == 200 and issued.json()["status"] == "succeeded", "fixture five-protocol issuance failed")


def static_matches(fixture):
    static = Path(os.environ.get("PANEL_STATIC_DIR", Path(__file__).resolve().parents[1] / "static"))
    for name in ("js/users.js", "js/protocol-users.js", "js/access-limits.js", "js/grant.js", "style.css", "i18n/en.json"):
        response = fixture.http.get("/static/" + name)
        require(response.status_code == 200, "current static asset not served")
        require(hashlib.sha256(response.content).digest() == hashlib.sha256((static / name).read_bytes()).digest(), "HTTP asset differs from current source")


def geometry(browser):
    require(browser.js("document.documentElement.scrollWidth <= innerWidth + 1"), "native page horizontal overflow")
    require(browser.js("""![...document.querySelectorAll('#view [data-protocol-row] button, #view .protocol-settings summary')].some(e => {
      const r=e.getBoundingClientRect(); return r.width && (r.left < -1 || r.right > innerWidth+1);
    })"""), "native protocol action escapes viewport")
    browser.healthy()


@pytest.mark.parametrize("role", ["owner", "viewer"])
def test_native_five_protocol_client_identity_actions_and_layout(tmp_path, role):
    shots = Path(os.environ.get("PANEL_UI_EVIDENCE_SHOTS", tmp_path / "shots"))
    with isolated_panel(tmp_path, ConsistencyFixture, role=role) as fixture, isolated_browser(tmp_path, fixture, shots) as browser:
        static_matches(fixture)
        for width in (390, 1024, 1440):
            for view in ("users", "naive", "mieru", "amneziawg", "trusttunnel"):
                browser.open_view(view, "!!document.querySelector('[data-protocol-row]')", width)
                require(browser.js("document.querySelector('[data-protocol-row] .identity b').textContent === 'Анна — проверка клиента'"), "native holder is not primary identity")
                require(browser.js("document.querySelector('[data-protocol-row] .identity').textContent.includes('anna-')"), "native runtime account missing")
                if role == "owner":
                    require(browser.js("!!document.querySelector('.protocol-settings')"), "native settings missing")
                    require(browser.js("[...document.querySelectorAll('[data-protocol-row] button')].some(b=>b.textContent==='Удалить доступ')"), "native delete missing")
                    browser.js("document.querySelector('.protocol-settings').open=true;true")
                else:
                    require(browser.js("!document.querySelector('.protocol-settings')"), "viewer has settings")
                    require(browser.js("![...document.querySelectorAll('[data-protocol-row] button')].some(b=>b.textContent==='Удалить доступ')"), "viewer has delete")
                geometry(browser)
                if role == "owner" and view == "users":
                    browser.js("document.querySelector('[data-protocol-row]').scrollIntoView({block:'start'});true")
                    browser.shot(f"native-protocol-{width}.png")
                browser.set_value("[data-protocol-search]", "not-present")
                require(browser.js("document.querySelectorAll('[data-protocol-row]:not([hidden])').length===0 && !document.querySelector('[data-protocol-empty]').hidden"), "native no-result filter broken")


def holder_grant(fixture, username, protocol=None):
    entries = fixture.api("/api/clients")["items"]
    grants = [g for entry in entries for g in entry["grants"] if g["runtime_username"] == username and g["desired_state"] != "deleted" and (protocol is None or g["protocol"] == protocol)]
    return grants[0] if grants else None


def wait_grant(fixture, username, protocol=None):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        found = holder_grant(fixture, username, protocol)
        if found is not None:
            return found
        time.sleep(0.05)
    raise AssertionError("native creation did not persist grant")


def close_dialogs(browser):
    # Never inspect the contents of bundles, QR or credential dialogs.
    browser.js("document.querySelectorAll('dialog[open]').forEach(d=>d.close());true")
    browser.wait("!document.querySelector('dialog[open]')", "dialogs closed")
    time.sleep(0.1)


def test_native_default_and_manual_create_then_edit_lifetime(tmp_path):
    with isolated_panel(tmp_path, ConsistencyFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        static_matches(fixture)
        browser.dt.call("Page.addScriptToEvaluateOnNewDocument", {"source": """
          window.__qaRequests=[];
          const qaFetch=window.fetch;
          window.fetch=async (...args)=>{
            const response=await qaFetch(...args);
            const path=new URL(typeof args[0]==='string'?args[0]:args[0].url,location.href).pathname;
            if((args[1]?.method||'GET')!=='GET')window.__qaRequests.push({method:args[1]?.method,status:response.status,family:path.startsWith('/api/reveal/')?'reveal':path});
            return response;
          };
        """})
        observations = []
        for manual in (False, True):
            for view, prefix, name, submit, protocol in (
                ("users", "new-user", "new-user", "create-user", "mtproxy"),
                ("naive", "new-naive", "new-naive-user", "create-naive", "naive"),
                ("mieru", "new-mieru", "new-mieru-user", "create-mieru", "mieru"),
            ):
                browser.open_view(view, "!!document.querySelector('[data-protocol-row]')")
                browser.click("#add")
                modal = {"users": "user", "naive": "naive", "mieru": "mieru"}[view]
                browser.wait(f"document.querySelector('#{modal}-modal').open", "native creation dialog")
                require(browser.js(f"!document.querySelector('#{prefix}-traffic-enabled').checked && !document.querySelector('#{prefix}-validity-enabled').checked"), "native create default is finite")
                username = f"qa-{'manual' if manual else 'unlimited'}-{protocol}"
                browser.set_value("#" + name, username)
                if manual:
                    for kind in ("traffic", "validity"):
                        browser.click(f"#{prefix}-{kind}-enabled")
                    browser.set_value(f"#{prefix}-traffic-gb", "1.25")
                    browser.set_value(f"#{prefix}-validity-days", "7")
                    if protocol == "mieru":
                        browser.set_value("#mieru-days", "30")
                browser.wait(f"!document.querySelector('#{submit}').disabled", f"native {protocol} create button ready")
                if protocol in ("naive", "mieru"):
                    browser.wait(f"!document.querySelector('#{protocol}-node').disabled", "node choices loaded")
                before = int(time.time())
                browser.can_capture = False
                browser.click("#" + submit)
                try:
                    browser.wait(f"!document.querySelector('#{modal}-modal').open", f"native {protocol} {'manual' if manual else 'default'} creation accepted")
                except AssertionError:
                    diagnostic = browser.js(f"""({{
                      disabled:document.querySelector('#{submit}').disabled,
                      invalid:[...document.querySelectorAll('#{modal}-form :invalid')].map(e=>e.id),
                      error:!!document.querySelector('#{modal}-error')?.textContent,
                      requests:window.__qaRequests
                    }})""")
                    raise AssertionError(f"native {protocol} creation failed; nonsecret aggregates: {diagnostic}") from None
                grant = wait_grant(fixture, username)
                options = grant["options"]
                if manual:
                    require(before + 7 * 86400 <= grant["valid_until"] <= int(time.time()) + 7 * 86400, "native validity day conversion failed")
                    key = {"mtproxy": "data_quota_bytes", "naive": "quota_bytes"}.get(protocol)
                    require(options.get(key) == 1250000000 if key else options.get("quotas") == [{"days": 30, "megabytes": 1193}], "native GB/rolling conversion failed")
                else:
                    require(grant["valid_until"] is None, "native default expiry must be unlimited")
                    require(not options.get("data_quota_bytes") and not options.get("quota_bytes") and not options.get("quotas"), "native default quota must be unlimited")
                observations.append({"protocol": protocol, "manual": manual, "requests": browser.js("window.__qaRequests"), "unlimited_validity": grant["valid_until"] is None})
                close_dialogs(browser)
        evidence = os.environ.get("PANEL_UI_EVIDENCE_REPORT")
        if evidence:
            Path(evidence).write_text(json.dumps(observations, indent=2) + "\n")
        # Open the seeded access without revealing credentials; save shared lifetime via actual UI.
        browser.open_view("naive", "!!document.querySelector('[data-protocol-row]')")
        browser.click(".protocol-settings summary")
        browser.click("[data-protocol-validity]")
        browser.wait("document.querySelector('#grant-window').open && document.querySelector('#grant-settings').open", "native lifetime editor opened")
        browser.click("#grant-limit-validity-enabled")
        browser.set_value("#grant-limit-validity-days", "9")
        browser.click("[data-grant-action=save-validity]")
        seed = wait_grant(fixture, "anna-naive")
        deadline = time.monotonic() + 10
        while seed["valid_until"] is None and time.monotonic() < deadline:
            time.sleep(0.05)
            seed = wait_grant(fixture, "anna-naive")
        require(seed["valid_until"] is not None, "native lifetime edit did not persist")
        require(browser.js("document.querySelector('#grant-validity-current').textContent.includes('Окно панели')"), "native generic window label misleading")
        close_dialogs(browser)
        browser.healthy()


def test_native_other_main_pages_navigation_and_scoped_css_smoke(tmp_path):
    with isolated_panel(tmp_path, ConsistencyFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        static_matches(fixture)
        pages = (
            ("dashboard", "!!document.querySelector('.host-card')"),
            ("clients", "!!document.querySelector('.client-card')"),
            ("monitoring", "!!document.querySelector('[data-mon]')"),
            ("fleet", "!!document.querySelector('.node-list')"),
            ("routing", "!!document.querySelector('.routing-layout,.routing-empty,.routing-toolbar')"),
            ("versions", "!!document.querySelector('.version-card')"),
            ("admins", "!!document.querySelector('.admin-grid') && !!document.querySelector('#api-keys .data-panel')"),
            ("audit", "!!document.querySelector('#audit-filter-form')"),
        )
        for width in (390, 1440):
            for page, ready in pages:
                browser.open_view(page, ready, width)
                require(browser.js(f"location.hash==='#{page}'"), "native navigation changed screen unexpectedly")
                geometry(browser)
        # Read-only client details, then back to list, without revealing any access.
        browser.open_view("clients", "!!document.querySelector('.client-card')", 390)
        browser.click("[data-client-action=open]")
        browser.wait("!!document.querySelector('#client-management')", "native client details")
        require(browser.js("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1"), "native client detail overflow")
        browser.click('#client-management [data-management-back]')
        browser.wait("!document.querySelector('#client-management')", "client list restored")
        browser.healthy()


def test_native_new_client_matrix_default_and_manual_limits(tmp_path):
    with isolated_panel(tmp_path, ConsistencyFixture) as fixture, isolated_browser(tmp_path, fixture) as browser:
        static_matches(fixture)
        for manual in (False, True):
            browser.open_view("clients", "!!document.querySelector('.client-card')")
            browser.click("#add")
            browser.wait("document.querySelector('#client-modal').open && !!document.querySelector('#client-placement input[data-node=local][data-protocol=mtproxy]')", "native client matrix ready")
            require(browser.js("!document.querySelector('#new-client-traffic-enabled').checked && !document.querySelector('#new-client-validity-enabled').checked"), "new client defaults must be unlimited")
            username = "qa-matrix-manual" if manual else "qa-matrix-unlimited"
            browser.set_value("#client-name", username)
            for protocol in ("mtproxy", "naive", "mieru"):
                browser.click(f'#client-placement input[data-node="local"][data-protocol="{protocol}"]')
            browser.set_value("#client-username", username)
            if manual:
                browser.click('#client-additional > summary')
                browser.click("#new-client-traffic-enabled")
                browser.click("#new-client-validity-enabled")
                browser.set_value("#new-client-traffic-gb", "1.25")
                browser.set_value("#new-client-validity-days", "7")
                browser.set_value("#new-client-rolling-days", "30")
            browser.can_capture = False
            browser.click("#create-client")
            browser.wait("!document.querySelector('#client-modal').open", "native client matrix creation accepted")
            for protocol in ("mtproxy", "naive", "mieru"):
                grant = wait_grant(fixture, username, protocol)
                options = grant["options"]
                require((grant["valid_until"] is not None) == manual, "native client matrix lifetime default/manual mismatch")
                if manual:
                    key = {"mtproxy": "data_quota_bytes", "naive": "quota_bytes"}.get(protocol)
                    require(options.get(key) == 1250000000 if key else options.get("quotas") == [{"days": 30, "megabytes": 1193}], "native client matrix GB limit mismatch")
                else:
                    require(not options.get("data_quota_bytes") and not options.get("quota_bytes") and not options.get("quotas"), "native client matrix must default unlimited")
            close_dialogs(browser)
            browser.healthy()
