//! `test_routing_presets.py`: preset validation, protocol selectors and persistence.

use std::collections::BTreeSet;

use panel_model::routing::models::{
    Action, CompileStatus, PolicyInput, RoutingRule, RuleMatch, COMPILER_VERSION, LANE_SERVICE,
};
use panel_model::validate::Model;
use panel_model::Backend;
use serde_json::{json, Value};

use super::support::*;
use crate::compiler;
use crate::presets::{preset, preset_ids, presets, rule_for};
use crate::store;

#[test]
fn a_rule_may_stand_on_the_sniffed_protocol_alone_and_carries_its_preset() {
    let rule = RoutingRule::validate(&rule_for("torrent").unwrap()).unwrap();
    assert_eq!(rule.matcher.protocols, ["bittorrent"]);
    assert_eq!(rule.preset.as_deref(), Some("torrent"));
    assert_eq!(rule.action, Action::Block);
    assert_eq!(
        RuleMatch::validate(&json!({"protocols": [" TLS ", "http", "tls"]})).unwrap().protocols,
        ["tls", "http"]
    );
    let error = RuleMatch::validate(&json!({"protocols": ["ssh"]})).unwrap_err().to_string();
    assert!(error.contains("invalid protocol selector"), "{error}");
    let error = RoutingRule::validate(&json!({
        "match": {"domains": ["x.com"]}, "action": "block", "preset": "Bad Name",
    }))
    .unwrap_err()
    .to_string();
    assert!(error.contains("invalid preset name"), "{error}");
    assert_eq!(
        RoutingRule::validate(&json!({
            "match": {"domains": ["x.com"]}, "action": "block", "preset": "",
        }))
        .unwrap()
        .preset,
        None
    );
    assert_eq!(COMPILER_VERSION, "3");
}

#[test]
fn every_preset_is_a_valid_rule_and_the_ids_are_distinct() {
    let ids = preset_ids();
    let distinct: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
    assert_eq!(distinct.len(), ids.len());
    assert_eq!(ids.len(), presets().len());
    assert_eq!(ids.len(), 6);
    for item in presets() {
        let id = item["id"].as_str().unwrap();
        let rule = RoutingRule::validate(&rule_for(id).unwrap()).unwrap();
        assert_eq!(rule.preset.as_deref(), Some(id));
        assert!(["first", "last"].contains(&item["placement"].as_str().unwrap()));
    }
    assert!(rule_for("nope").is_none());
}

#[test]
fn native_backends_refuse_the_protocol_selector_and_explain_leaves_it_to_the_router() {
    let mut torrent = RoutingRule::validate(&rule_for("torrent").unwrap()).unwrap();
    torrent.id = Some("a".repeat(36));
    let policy = with_rules(native_policy("naive"), vec![torrent]);
    let mut target = native_target("naive");
    target.capabilities = capabilities(&["whole_direct", "block_domain"]);
    target.providers.clear();
    target.revision = "r".into();
    let compiled = compile_native(&policy, Some(&target));
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(compiled.reasons[0].code, "rule_kind_unsupported");
    assert!(compiled.reasons[0].message.contains("protocol"));
    let verdict = compiler::explain(&policy, "example.com", 443);
    assert!(verdict["rule_id"].is_null());
    assert_eq!(verdict["uncertain"], json!(["a".repeat(36)]));
}

#[test]
fn the_router_announces_the_protocol_selector() {
    let contract: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/fixtures/xray-router-contract.json"
    )))
    .unwrap();
    let announced: BTreeSet<&str> =
        contract["capabilities"].as_array().unwrap().iter().map(|item| item.as_str().unwrap()).collect();
    assert!(BTreeSet::from(["block_protocol", "selective_protocol"]).is_subset(&announced));
}

#[test]
fn the_store_keeps_the_preset_mark_across_a_save() {
    let (_scratch, database) = database("preset-store");
    let connection = database.connect().unwrap();
    let draft = PolicyInput {
        intent: panel_model::routing::models::Intent {
            rules: vec![
                RoutingRule::validate(&rule_for("ads").unwrap()).unwrap(),
                rule(Action::Block, json!({"domains": ["x.com"]})),
            ],
            ..Default::default()
        },
        backend: Some(Backend::NaiveNative),
    };
    let policy = store::upsert(&connection, "local", "naive", &draft, None, 1, LANE_SERVICE).unwrap();
    assert_eq!(policy.intent.rules.iter().map(|rule| rule.preset.as_deref()).collect::<Vec<_>>(), [Some("ads"), None]);
    assert_eq!(policy.intent.rules[0].matcher.geosites, ["category-ads-all"]);
    let again = store::get(&connection, "local", "naive", LANE_SERVICE).unwrap().unwrap();
    assert_eq!(again.intent.rules[0].preset.as_deref(), Some("ads"));
    assert_eq!(again.intent.rules[1].preset, None);
}

#[test]
fn the_presets_endpoint_lists_the_definitions() {
    // The HTTP status belongs to the service route; these are its public preset data.
    let items = presets();
    assert_eq!(items.iter().map(|item| item["id"].as_str().unwrap().to_string()).collect::<Vec<_>>(), preset_ids());
    assert_eq!(items[0]["rule"]["match"], json!({"protocols": ["bittorrent"]}));
    assert_eq!(items[0]["placement"], "first");
}

#[test]
fn regional_presets_name_the_geodata_source_their_codes_need() {
    let blocked = RoutingRule::validate(&rule_for("ru_blocked_warp").unwrap()).unwrap();
    assert_eq!(blocked.action, Action::Egress);
    assert_eq!(blocked.egress.as_deref(), Some("warp"));
    assert_eq!(blocked.matcher.geosites, ["ru-blocked"]);
    assert_eq!(blocked.matcher.geoips, ["ru-blocked"]);
    assert_eq!(preset("ru_blocked_warp").unwrap()["geodata"], "runetfreedom");
    assert!(preset("cn_direct").unwrap().get("geodata").is_none());
    assert!(preset("ir_direct").unwrap().get("geodata").is_none());
    assert_eq!(RoutingRule::validate(&rule_for("cn_direct").unwrap()).unwrap().matcher.geoips, ["cn"]);
    assert_eq!(RoutingRule::validate(&rule_for("ir_direct").unwrap()).unwrap().matcher.geosites, ["category-ir"]);
}

#[test]
fn the_panel_knows_every_geodata_source_the_router_manager_does() {
    let contract: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/fixtures/xray-router-contract.json"
    )))
    .unwrap();
    let source_kinds: BTreeSet<&str> =
        contract["geodata_source_kinds"].as_array().unwrap().iter().map(|item| item.as_str().unwrap()).collect();
    let panel_kinds: BTreeSet<&str> = panel_managers::xray_router::GEODATA_SOURCE_KINDS.iter().copied().collect();
    assert_eq!(panel_kinds, source_kinds);
    let html = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../static/index.html"));
    for kind in source_kinds {
        assert!(html.contains(&format!("<option value=\"{kind}\">")), "missing {kind}");
    }
}
