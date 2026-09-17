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
    for text in ("Напрямую", "Через выход", "отказать", "напрямую", "вне области маршрутизации",
                 "узел нужно обновить до v0.4", "есть неприменённые изменения", "применено (rev",
                 "маршрутизацией управляет центральная панель", "перезапуск не требуется", "Сбросить",
                 "Применить", "Откатить", "История", "Добавить правило"):
        assert text in ROUTING, text
    for code in ("backend_capability_missing", "rule_kind_unsupported", "private_destination", "provider_unavailable",
                 "provider_unreachable", "node_lacks_egress_v1", "protocol_out_of_scope", "policy_conflict",
                 "policy_applied", "egress_unreachable", "egress_readback_mismatch", "manual_intervention_required",
                 "adopts_unmanaged_upstream", "adopts_unmanaged_egress", "policy_empty"):
        assert code in ROUTING, code


def test_routing_js_speaks_the_router():
    """v0.5: the Xray-router — attach/detach as explicit actions, the three selectors only
    the router enforces, the words for its states and refusals."""
    for fragment in ("/attach", "/detach", 'action === "attach" || action === "detach"'):
        assert fragment in ROUTING, fragment
    for text in ("Подключить к Xray-router", "Отключить от Xray-router", "Xray-router: не установлен",
                 "сессии сервиса прервутся", "Xray-router", "Caddy", "mita", "geosite", "geoip"):
        assert text in ROUTING, text
    for field in ('data-rule-field="geosites"', 'data-rule-field="geoips"', 'data-rule-field="ports"'):
        assert field in ROUTING, field
    for code in ("router_unavailable", "router_unreachable", "not_attached", "node_lacks_router", "artifact_mismatch",
                 "geosite_unknown", "geoip_unknown", "router_credential_stale"):
        assert code in ROUTING, code
    # The router intent travels with the policy body: geosites and geoips beside domains and cidrs.
    assert "geosites: rule.match.geosites, geoips: rule.match.geoips" in ROUTING
    nodes = (STATIC / "js/nodes.js").read_text()
    assert "routingSummary" in nodes


def test_routing_js_speaks_lanes_chains_and_the_relay():
    """v0.7: the node's exits as chips, a lane tab per client, «Куда» with chains, the
    «Куда пойдёт…» check, the node's relay — every call lane-aware, every refusal named."""
    for fragment in ("/api/routing/lanes/", "/explain", "/api/routing/relay/", "/enable", "laneQuery(context)",
                     'data-routing-action="lane"', 'data-routing-action="lane-add"', 'data-routing-action="lane-remove"',
                     'data-routing-action="relay-enable"', 'id="routing-exits"', 'id="routing-lanes"', 'id="routing-explain"',
                     'data-rule-field="egress"', 'exitSelect(target, "default_egress"', "routingLane"):
        assert fragment in ROUTING, fragment
    for text in ("Выходы узла", "Сервис", "Добавить полосу для клиента…", "Вернуть в полосу сервиса", "Куда пойдёт…",
                 "Через выход", "WARP этого узла", "→ напрямую", "Включить relay", "relay включён", "relay выключен",
                 "ссылка Mieru изменится"):
        assert text in ROUTING, text
    for code in ("lane_requires_router", "lane_not_attached", "lane_slots_exhausted", "node_lacks_lanes", "node_lacks_relay",
                 "relay_disabled", "relay_credential_pending", "relay_no_warp", "chain_loop", "node_unknown"):
        assert code in ROUTING, code
    # the exit travels with the rule and the default, never hard-wired to WARP any more
    assert 'rule.action === "egress" ? rule.egress || "warp" : null' in ROUTING
    assert 'draft.default_action === "egress" ? draft.default_egress || "warp" : null' in ROUTING
    state = (STATIC / "js/state.js").read_text()
    assert 'routingLane: "svc"' in state
    clients = (STATIC / "js/clients.js").read_text()
    for fragment in ('data-client-action="grant-lane"', "/api/routing/lanes/", "своя полоса", "как у сервиса", "Ссылка Mieru изменится"):
        assert fragment in clients, fragment
    html = (STATIC / "index.html").read_text()
    assert 'id="choose"' in html and 'id="choose-select"' in html
    css = (STATIC / "style.css").read_text()
    for selector in (".routing-exits{", ".routing-exit-chip{", ".routing-lanes{", ".routing-explain{", ".grant-lane{"):
        assert selector in css, selector


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
    re.compile(r"^(cardActions|editor|previewPanel|nodeOptions|protocolTabs|targetCard|historyTable|routerLine|exitsLine|relayLine|laneTabs|explainPanel|exitSelect)\("),
    re.compile(r"^(policyPath|laneQuery)\("),  # URL builders: encoded path parts and a `?lane=` query
    re.compile(r"^(chips|tabs)\.join\(\"\"\)$"),  # our own escaped pieces
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


def test_routing_card_forgets_the_previous_policy_before_it_paints():
    """A card painted with the last visit's policy while its own was loading answered a
    click with silence (the browser smoke of v0.5 hit it on «Откатить» after a view
    change): the state is reset before the first paint, the badge says it is loading and
    no action is enabled until the current policy is there."""
    render = ROUTING[ROUTING.index("export async function renderRouting"):]
    render = render[:render.index("\n}\n")]
    assert render.index("resetPolicy(context)") < render.index("context.ui.view.innerHTML = screen(context)")
    assert "загружается…" in ROUTING
    assert re.search(r"policyState\(policy, state\.loading\)", ROUTING)
    assert re.search(r"const editable = .*&& !state\.loading;", ROUTING)
    load = ROUTING[ROUTING.index("async function loadPolicy"):]
    load = load[:load.index("\n}\n")]
    assert "state.loading = false;" in load and load.index("state.loading = false;\n  await previewNow") > 0
