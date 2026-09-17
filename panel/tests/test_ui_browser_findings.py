"""What the real-browser acceptance (v0.6, tier `ui`) found on its first run — each kept
here so the fixes cannot quietly regress: an inline style the CSP drops, a login form that
reloaded instead of saying «wrong password», a grant dialog whose Mieru body the API refused."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from panel.clients.models import PROTOCOL_OPTIONS, GrantIntent, MieruOptions

pytestmark = pytest.mark.anyio

STATIC = Path(__file__).resolve().parents[1] / "static"


def test_no_module_renders_an_inline_style_attribute():
    """`style-src 'self'` (the panel's CSP) drops `style="…"` from any markup a module
    builds: the overview's usage bars never filled in a real browser. Widths and the like
    go through the CSSOM after the paint, never through the attribute."""
    offenders = []
    for path in sorted(STATIC.glob("js/*.js")) + [STATIC / "index.html", STATIC / "login.html"]:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"""\bstyle\s*=\s*["'`]""", line) or 'setAttribute("style"' in line or "setAttribute('style'" in line:
                offenders.append(f"{path.name}:{line_number}")
    assert offenders == [], offenders
    dashboard = (STATIC / "js/dashboard.js").read_text(encoding="utf-8")
    assert "data-usage-percent" in dashboard and "bar.style.width" in dashboard


def test_the_login_form_shows_a_refusal_instead_of_reloading():
    """A 401 to the login form's own POST is the answer «wrong password»; `api()` used to
    treat every 401 as an expired session and send the browser back to /login — the form
    reloaded blank and the operator never saw why."""
    api = (STATIC / "js/api.js").read_text(encoding="utf-8")
    assert re.search(r"response\.status === 401 && window\.location\.pathname !== \"/login\"", api)
    main = (STATIC / "js/main.js").read_text(encoding="utf-8")
    assert "error.textContent = exception.message" in main


def test_a_mieru_grant_without_options_means_no_quota():
    """The grant dialog sends `options: {}` for every protocol; Mieru's options required
    `quotas` and the API answered 422 — a Mieru grant could not be issued from the screen."""
    assert MieruOptions().quotas == []
    # The route validates the options by the protocol named beside them (never by shape).
    options = PROTOCOL_OPTIONS["mieru"].model_validate({})
    intent = GrantIntent(protocol="mieru", runtime_username="phone", options=options)
    assert intent.options.quotas == []
    with pytest.raises(ValueError):
        MieruOptions.model_validate({"quotas": [], "unknown": 1})


async def test_the_grant_dialog_body_issues_a_mieru_grant(client, login_user, telemt, naive, mieru):
    """Exactly what the screen sends: `options: {}` for all three protocols."""
    await login_user(client)
    headers = {"X-CSRF-Token": client.cookies["panel_csrf"]}
    created = await client.post("/api/clients", json={"display_name": "Phone"}, headers=headers)
    body = {"grants": [{"protocol": p, "node_id": "local", "runtime_username": "phone", "options": {}} for p in ("mtproxy", "naive", "mieru")]}
    started = await client.post(f"/api/clients/{created.json()['id']}/grants", json=body, headers=headers)
    assert started.status_code == 200, started.text
    assert started.json()["status"] == "succeeded"
    assert "phone" in mieru.users and mieru.users["phone"]["quotas"] == []


def test_the_grant_dialog_reads_only_its_own_protocol_boxes():
    """The link dialog (v0.3) reuses `.grant-protocol` for its TLS radios; a document-wide
    `:checked` query handed «verify» to the API as a protocol, so issuing grants from the
    Clients screen answered 422 every time. The collection is scoped to the grant form."""
    clients = (STATIC / "js/clients.js").read_text(encoding="utf-8")
    assert '"#grant-form .grant-protocol input:checked"' in clients
    assert re.search(r'queryAll\("\.grant-protocol input', clients) is None
    index = (STATIC / "index.html").read_text(encoding="utf-8")
    assert index.count('class="grant-protocol"') >= 5  # the class is shared on purpose; the scope is not


def test_an_audit_row_stacks_its_main_line_and_its_details():
    """The v0.1 stylesheet laid a journal row out as four grid columns of its own
    (`150px 150px 1fr 1fr`); v0.2 moved the columns into `.audit-main` and put the
    «Детали и IP» disclosure beside it as a second child — but the old declaration stayed,
    so the row still had four tracks: `.audit-main` was squeezed into the first 150 px and
    spilled over the disclosure in the second (seen on AMS_Z after v0.6). The row's own grid
    is a single column at every width; the columns belong to `.audit-main` alone."""
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    multi_track = re.compile(r"grid-template-columns\s*:\s*[^;}]*\s[^;}]*[;}]")
    row_rules = re.findall(r"(?<![\w-])\.audit-row\s*\{[^}]*\}", css)
    assert row_rules, "the journal row lost its stylesheet"
    assert [rule for rule in row_rules if multi_track.search(rule)] == []
    assert re.search(r"\.audit-row\s*>\s*\*:nth-child", css) is None  # the row has two children, not four
    main_rules = re.findall(r"(?<![\w-])\.audit-main\s*\{[^}]*\}", css)
    assert any(multi_track.search(rule) for rule in main_rules)
