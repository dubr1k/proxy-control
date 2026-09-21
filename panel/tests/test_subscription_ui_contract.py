"""The client window's contract with the API and with the operator.

The UI is plain ES modules without a build step, so this checks the source it ships:
the reveal path behind the «Показать» button, the destructive actions going through
confirmation, the node × protocol matrix and its diff, the per-client link variants,
and the warning that some clients never refresh on their own.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_the_client_window_shows_the_url_on_request_and_never_keeps_it():
    javascript = (ROOT / "static/js/subscriptions.js").read_text()
    html = (ROOT / "static/index.html").read_text()
    assert 'id="subscription-modal"' in html and 'id="placement-body"' in html and 'id="placement-username"' in html
    assert "не обновляют подписку автоматически" in html
    assert "показывается один раз" not in html[html.index('id="subscription-modal"'):html.index('id="client-import-modal"')]
    # Shown through a reveal, consumed once, cleared on close; rotate/revoke confirmed, reveal not.
    assert "subscription/reveal" in javascript and "/api/reveal/" in javascript
    assert "subscription/rotate" in javascript and "subscription/revoke" in javascript
    assert "localStorage" not in javascript and "sessionStorage" not in javascript
    assert javascript.count("ui.confirmed(") == 3  # rotate, revoke, delete a cell — never show/apply
    assert 'data-subscription-action="show"' in javascript and "state.reveal = null" in javascript
    assert "ротируйте" in javascript and "показывает ссылку один раз" in javascript
    # The matrix and its diff come from placement.js; the diff goes to the existing endpoints.
    assert 'from "./placement.js"' in javascript and "placementDiff(" in javascript
    assert "/grants`" in javascript and "/enable`" in javascript and "/disable`" in javascript and "/delete`" in javascript
    # The variants of owner decision 2 (the sing-box JSON cut twice: Karing takes mieru,
    # the official core does not), each with what it carries and what it leaves out.
    for name in ("singbox", "singbox-official", "clash", "raw"):
        assert re.search(rf'format: "{name}"', javascript), name
    assert javascript.count("carries:") == 4 and javascript.count("leaves:") == 4
    assert 'name="subscription-format"' in javascript
    # Every grant carries its auto-refresh marks from the compatibility matrix.
    assert "/api/subscriptions/compatibility" in javascript and "data-auto-refresh" in javascript
    # The delayed `close` (one task after dialog.close()) must not wipe a window that open()
    # already reopened in that gap — the guard sits right after the listener is registered.
    close_listener = javascript.index('dialog.addEventListener("close"')
    assert 'if (dialog.open) return;' in javascript[close_listener : close_listener + 500]


def test_open_clears_the_previous_client_before_reopening_the_modal():
    javascript = (ROOT / "static/js/subscriptions.js").read_text()
    # A reopen whose load() fails must never show the previous client's URL/matrix under
    # the new title — reset() runs right after the generation bump, before openModal().
    open_start = javascript.index("async function open(clientId")
    open_body = javascript[open_start : javascript.index("async function issue(", open_start)]
    assert "reset()" in open_body
    assert open_body.index("reset()") < open_body.index("ui.openModal(")


def test_the_client_card_opens_the_window_and_main_wires_it():
    clients = (ROOT / "static/js/clients.js").read_text()
    main = (ROOT / "static/js/main.js").read_text()
    assert 'data-client-action="open"' in clients and "context.subscriptions.open(" in clients
    assert 'data-client-action="grant"' not in clients and "openGrantModal" not in clients
    assert "createSubscriptionDialog" in main and "context.subscriptions.bind()" in main
    # v0.11: «Узлы и доступы» on the card opens the same window on its matrix, for writers
    # of a live client only (it sits after the viewer/archived early return).
    assert 'data-client-action="placement"' in clients and "Узлы и доступы" in clients
    assert clients.index('data-client-action="placement"') > clients.index('role === "viewer" || client.state === "archived"')
    assert '{ focus: action === "placement" ? "placement" : null }' in clients
    subscriptions = (ROOT / "static/js/subscriptions.js").read_text()
    assert 'focus !== "placement"' in subscriptions and ".placement-box" in subscriptions and "scrollIntoView" in subscriptions


def test_the_window_is_reachable_by_viewers_but_only_writers_get_the_buttons():
    javascript = (ROOT / "static/js/subscriptions.js").read_text()
    clients = (ROOT / "static/js/clients.js").read_text()
    # The card button is emitted before the viewer early-return...
    assert clients.index('data-client-action="open"') < clients.index('role === "viewer" || client.state === "archived"')
    # ...and the window itself hides create/show/rotate/revoke and the matrix controls from viewers.
    assert 'role !== "viewer"' in javascript and "canWrite" in javascript
    assert "renderPlacement(rows, { canWrite" in javascript


def test_the_audit_screen_names_the_reveal():
    audit = (ROOT / "static/js/audit.js").read_text()
    assert '"subscription.reveal": "Ссылка подписки показана"' in audit


def test_new_client_places_grants_by_matrix_and_hands_the_subscription_over():
    clients = (ROOT / "static/js/clients.js").read_text()
    access = (ROOT / "static/js/access.js").read_text()
    html = (ROOT / "static/index.html").read_text()
    dialog = html[html.index('id="client-modal"'):html.index('id="bundle-modal"')]
    assert 'id="client-placement"' in dialog and 'id="client-node"' not in dialog
    assert 'id="grant-modal"' not in html
    assert 'from "./placement.js"' in clients and "placementDiff(" in clients
    assert "subscription_reveal_token" in clients and "openOperationBundle(" in clients
    # The bundle dialog carries the subscription block when a reveal came with the client.
    assert 'id="bundle-subscription"' in html and "bundle-subscription" in access and "subscription.qr" in access


def test_service_screens_issue_clients_without_a_subscription():
    clients = (ROOT / "static/js/clients.js").read_text()
    # MTProxy/NaiveProxy/Mieru screens issue clients through issueOnNode; the client
    # window offers «Создать URL» later, so this call must not issue one up front.
    start = clients.index("export async function issueOnNode")
    body = clients[start : clients.index("export function bindClients")]
    assert "subscription: false" in body
