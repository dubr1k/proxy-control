"""Quick settings and the sniffed-protocol selector (v0.8): a preset is a rule with a mark
that the store keeps, the router compiles `protocols` into Xray's `protocol` and the
native backends refuse it honestly, the definitions come from one place."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from panel.database import Database
from panel.migrations import apply_migrations
from panel.protocols.base import EgressTarget
from panel.routing.compiler import compile as compile_policy
from panel.routing.compiler import explain
from panel.routing.models import COMPILER_VERSION, PolicyInput, RoutingPolicy, RoutingRule, RuleMatch
from panel.routing.presets import PRESET_IDS, PRESETS, rule_for
from panel.routing.store import RoutingStore
from xray_router_manager.intent import CAPABILITIES, EgressInvalid, validate_document
from xray_router_manager.render import _rule

pytestmark = pytest.mark.anyio


def test_a_rule_may_stand_on_the_sniffed_protocol_alone_and_carries_its_preset():
    rule = RoutingRule.model_validate(rule_for("torrent"))
    assert rule.match.protocols == ["bittorrent"] and rule.preset == "torrent" and rule.action == "block"
    assert RuleMatch(protocols=[" TLS ", "http", "tls"]).protocols == ["tls", "http"]
    with pytest.raises(ValidationError, match="invalid protocol selector"):
        RuleMatch(protocols=["ssh"])
    with pytest.raises(ValidationError, match="invalid preset name"):
        RoutingRule(match=RuleMatch(domains=["x.com"]), action="block", preset="Bad Name")
    assert RoutingRule(match=RuleMatch(domains=["x.com"]), action="block", preset="").preset is None
    assert COMPILER_VERSION == "3"


def test_every_preset_is_a_valid_rule_and_the_ids_are_distinct():
    assert len(set(PRESET_IDS)) == len(PRESETS) == 3
    for item in PRESETS:
        rule = RoutingRule.model_validate(rule_for(item["id"]))
        assert rule.preset == item["id"] and item["placement"] in ("first", "last")
    with pytest.raises(KeyError):
        rule_for("nope")


def _policy(rules, backend="naive_native"):
    return RoutingPolicy(id="p", node_id="local", protocol="naive", backend=backend, revision=1,
                         default_action="direct", rules=rules)


def test_native_backends_refuse_the_protocol_selector_and_explain_leaves_it_to_the_router():
    torrent = RoutingRule.model_validate({**rule_for("torrent"), "id": "a" * 36})
    target = EgressTarget(protocol="naive", backend="naive_native", capabilities=frozenset({"whole_direct", "block_domain"}),
                          providers={}, revision="r", applied=None, mode="direct", restart_required=False, warnings=())
    compiled = compile_policy(_policy([torrent]), target)
    assert compiled.status == "unsupported" and compiled.reasons[0].code == "rule_kind_unsupported"
    assert "protocol" in compiled.reasons[0].message
    verdict = explain(_policy([torrent]), "example.com", 443)
    assert verdict["rule_id"] is None and verdict["uncertain"] == ["a" * 36]


def test_the_router_intent_and_the_xray_rule_carry_the_protocol_selector():
    document = validate_document({"schema": 1, "default": {"action": "direct", "egress": None},
                                  "rules": [{"protocols": ["bittorrent", "bittorrent"], "action": "block"}]})
    assert document["rules"][0]["protocols"] == ["bittorrent"]
    assert "protocols" not in validate_document({"schema": 1, "default": {"action": "direct", "egress": None},
                                                 "rules": [{"domains": ["x.com"], "action": "block"}]})["rules"][0]
    with pytest.raises(EgressInvalid, match="protocol selector"):
        validate_document({"schema": 1, "default": {"action": "direct", "egress": None},
                           "rules": [{"protocols": ["ssh"], "action": "block"}]})
    rendered = _rule("naive", {**document["rules"][0], "domains": [], "geosites": [], "cidrs": [], "geoips": [], "ports": []})
    assert rendered["protocol"] == ["bittorrent"] and rendered["outboundTag"] == "block" and "domain" not in rendered
    assert {"block_protocol", "selective_protocol"} <= set(CAPABILITIES)


def test_the_store_keeps_the_preset_mark_across_a_save(tmp_path):
    database = Database(tmp_path / "panel.sqlite3")
    apply_migrations(database)
    store = RoutingStore(database)
    draft = PolicyInput.model_validate({"default_action": "direct", "backend": "naive_native",
                                        "rules": [rule_for("ads"), {"action": "block", "match": {"domains": ["x.com"]}}]})
    with database.transaction() as db:
        policy = store.upsert(db, "local", "naive", draft, expected_revision=None, now=1)
    assert [rule.preset for rule in policy.rules] == ["ads", None]
    assert policy.rules[0].match.geosites == ["category-ads-all"]
    with database.connect() as db:
        again = store.get(db, "local", "naive")
    assert again.rules[0].preset == "ads" and again.rules[1].preset is None


async def test_the_presets_endpoint_lists_the_definitions(client, login_user):
    await login_user(client)
    response = await client.get("/api/routing/presets")
    assert response.status_code == 200
    items = response.json()["items"]
    assert [item["id"] for item in items] == list(PRESET_IDS)
    assert items[0]["rule"]["match"] == {"protocols": ["bittorrent"]} and items[0]["placement"] == "first"
