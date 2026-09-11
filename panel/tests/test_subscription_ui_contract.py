"""The subscription dialog's contract with the API and with the operator.

The UI is plain ES modules without a build step, so this checks the source it ships:
the one-time reveal path, the destructive actions going through confirmation, the
per-client link variants, and the warning that some clients never refresh on their own.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_subscription_dialog_shows_url_once_and_warns_about_clients_without_auto_refresh():
    javascript = (ROOT / "static/js/subscriptions.js").read_text()
    html = (ROOT / "static/index.html").read_text()
    assert 'id="subscription-modal"' in html
    assert "не обновляют подписку автоматически" in html
    assert "показывается один раз" in html
    # The URL comes out of a one-time reveal and is never re-fetched or persisted.
    assert "/api/reveal/" in javascript and "subscription/rotate" in javascript and "subscription/revoke" in javascript
    assert "localStorage" not in javascript and "sessionStorage" not in javascript
    assert javascript.count("ui.confirmed(") == 2  # rotate and revoke, never create
    # Every grant carries its auto-refresh marks from the compatibility matrix.
    assert "/api/subscriptions/compatibility" in javascript and "data-auto-refresh" in javascript
    # The variants of owner decision 2 (the sing-box JSON cut twice: Karing takes mieru,
    # the official core does not), each with what it carries and what it leaves out.
    for name in ("singbox", "singbox-official", "clash", "raw"):
        assert re.search(rf'format: "{name}"', javascript), name
    assert javascript.count("carries:") == 4 and javascript.count("leaves:") == 4
    assert 'name="subscription-format"' in javascript


def test_the_client_card_offers_the_dialog_and_main_wires_it():
    clients = (ROOT / "static/js/clients.js").read_text()
    main = (ROOT / "static/js/main.js").read_text()
    assert 'data-client-action="subscription"' in clients
    assert "context.subscriptions.open(" in clients
    assert "createSubscriptionDialog" in main and "context.subscriptions.bind()" in main


def test_the_dialog_is_reachable_by_viewers_but_only_writers_get_the_buttons():
    javascript = (ROOT / "static/js/subscriptions.js").read_text()
    clients = (ROOT / "static/js/clients.js").read_text()
    # The card button is emitted before the viewer early-return...
    assert clients.index('data-client-action="subscription"') < clients.index('role === "viewer" || client.state === "archived"')
    # ...and the dialog itself hides create/rotate/revoke from viewers.
    assert 'role !== "viewer"' in javascript and "canWrite" in javascript
