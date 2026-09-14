"""Static contract of the «Маршрутизация» screen (spec §8.4): the endpoints it speaks,
the words it uses for the states and refusals, and the guard that data never reaches
the DOM unescaped."""

from __future__ import annotations

import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"
ROUTING = (STATIC / "js/routing.js").read_text()


def test_index_and_main_register_the_routing_view():
    html = (STATIC / "index.html").read_text()
    assert html.count('data-view="routing"') == 2  # sidebar and the mobile bar
    main = (STATIC / "js/main.js").read_text()
    assert "routing: renderRouting" in main and 'routing: ["Маршрутизация"' in main
    for handler in ("handleRoutingInput", "handleRoutingChange", "handleRoutingSubmit", "handleRoutingClick", "bindRouting"):
        assert handler in main, handler
    state = (STATIC / "js/state.js").read_text()
    assert "routingTargets: []" in state and "routingNode: null" in state


def test_routing_js_speaks_only_the_documented_endpoints():
    assert '"/api/routing/targets"' in ROUTING
    for fragment in ("/api/routing/policies/", "/preview", "/history", "${base}/${action}"):
        assert fragment in ROUTING, fragment
    # apply and rollback share one POST path builder; the actions are the two spelled here.
    assert 'action === "apply" || action === "rollback" || action === "delete"' in ROUTING
    assert 'method: "PUT"' in ROUTING and 'method: "DELETE"' in ROUTING and 'method: "POST"' in ROUTING
    assert "expected_revision" in ROUTING and "PREVIEW_DEBOUNCE_MS = 400" in ROUTING


def test_routing_js_names_the_states_and_refusals_in_the_operator_words():
    for text in ("Напрямую", "Через WARP", "отказать", "напрямую", "вне области маршрутизации",
                 "узел нужно обновить до v0.4", "есть неприменённые изменения", "применено (rev",
                 "маршрутизацией управляет центральная панель", "перезапуск не требуется", "Сбросить",
                 "Применить", "Откатить", "История", "Добавить правило"):
        assert text in ROUTING, text
    for code in ("backend_capability_missing", "rule_kind_unsupported", "private_destination", "provider_unavailable",
                 "provider_unreachable", "node_lacks_egress_v1", "protocol_out_of_scope", "policy_conflict",
                 "policy_applied", "egress_unreachable", "egress_readback_mismatch", "manual_intervention_required",
                 "adopts_unmanaged_upstream", "adopts_unmanaged_egress", "policy_empty"):
        assert code in ROUTING, code


def test_apply_is_enabled_only_for_a_saved_supported_policy():
    assert 'compiled?.status === "supported"' in ROUTING and "!dirty" in ROUTING
    assert "canRollback" in ROUTING and "applied_revision !== null" in ROUTING


def _interpolations(source: str) -> list[str]:
    """Every `${…}` of every template literal, nested ones included (brace-matched)."""
    found = []
    position = 0
    while (start := source.find("${", position)) != -1:
        depth, index = 0, start + 1
        while index < len(source):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        found.append(source[start + 2:index].strip())
        position = start + 2
    return found


# What may reach a template without `esc()`: literal-only ternaries, our own HTML-building
# helpers, URL-encoded path parts, counters and flags — never a bare API string.
_ALLOWED = (
    re.compile(r"^(esc|number|encodeURIComponent)\("),
    re.compile(r"^(cardActions|editor|previewPanel|nodeOptions|protocolTabs|targetCard|historyTable)\("),
    re.compile(r"^[\w+\- ]+$"),  # a local composed of escaped pieces, or index arithmetic
    re.compile(r'^.+\?\s*("[^"]*"|\'[^\']*\'|`.*`)\s*:\s*("[^"]*"|\'[^\']*\'|`.*`|.+\?.+:.+)$', re.S),  # literal branches
    re.compile(r"^\w+\s*\|\|\s*('[^']*'|\"[^\"]*\")$"),  # a composed template, or a literal placeholder
    re.compile(r"^marker\[[01]\]$"),  # our own data-attribute values, into a selector
    re.compile(r"^reasonText\("),  # a bounded vocabulary, later passed through esc() by the caller
    re.compile(r"^item\.protocol$"),  # plain text for the node card, escaped there by facts()
)


def test_every_interpolated_value_from_the_api_is_escaped():
    """Templates interpolate only escaped strings, numbers, flags or other templates;
    a raw API field would be an injection point."""
    for expression in _interpolations(ROUTING):
        assert any(rule.match(expression) for rule in _ALLOWED), expression
    # Strings that come from the API are escaped where they are interpolated.
    for field in ("meta.name", "protocol", "backend", "message", "note", "actor", "digest", "domains.join", "cidrs.join"):
        assert re.search(rf"esc\([^)]*{re.escape(field)}", ROUTING), field


def test_node_card_carries_the_routing_line():
    nodes = (STATIC / "js/nodes.js").read_text()
    assert "routingSummary" in nodes and '"/api/routing/targets"' in nodes and "Маршрутизация" in nodes
    assert "не настроена" in ROUTING and "блокир." in ROUTING


def test_style_has_the_routing_grid_and_its_phone_breakpoint():
    css = (STATIC / "style.css").read_text()
    for selector in (".routing-layout{", ".routing-rule{", ".routing-preview{", ".routing-diff", ".routing-toolbar{"):
        assert selector in css, selector
    assert "@media(max-width:900px){.routing-layout{grid-template-columns:1fr}}" in css
