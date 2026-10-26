//! `test_routing_chains_compiler.py`: schema-2 intents, relay refusals and explain.

use panel_model::routing::models::{Action, CompileStatus, DefaultAction, Fallback, Reason, COMPILER_VERSION};
use serde_json::{json, Value};

use super::support::*;
use crate::compiler::{self, Options};

#[test]
fn a_service_without_lanes_or_node_exits_still_compiles_to_schema_1() {
    let mut policy = with_rules(router_policy("naive"), vec![rule(Action::Block, json!({"domains": ["a.example"]}))]);
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let target = attached_target("naive");
    let router = router("naive");
    let mut chains = Resolver::new();
    let compiled = compiler::compile(
        &policy,
        Some(&target),
        Options { router: Some(&router), lanes: &[], chains: Some(&mut chains), ..Options::default() },
    )
    .unwrap();
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(document(&compiled)["schema"], 1);
    assert_eq!(compiled.compiler_version, COMPILER_VERSION);
}

#[test]
fn lanes_fold_into_one_schema_2_intent_with_the_service_lane_and_chains() {
    let service = with_rules(router_policy("naive"), vec![rule(Action::Block, json!({"domains": ["ads.example"]}))]);
    let mut lane = with_rules(
        lane("grant:7f3a"),
        vec![
            egress_rule(json!({"geosites": ["category-ads-all"]}), &format!("node:{GUID_B}:warp")),
            rule(Action::Direct, json!({"geoips": ["ru"]})),
            egress_rule(json!({"domains": ["*.example.net"]}), &format!("node:{GUID_B},{GUID_C}")),
        ],
    );
    set_default(&mut lane, DefaultAction::Egress, Some("warp"));
    let target = attached_target("naive");
    let router = router("naive");
    let mut chains = Resolver::new();
    let compiled = compiler::compile(
        &service,
        Some(&target),
        Options { router: Some(&router), lanes: &[lane], chains: Some(&mut chains), ..Options::default() },
    )
    .unwrap();
    assert_eq!(compiled.status, CompileStatus::Supported, "{:?}", compiled.reasons);
    let intent = document(&compiled);
    assert_eq!(intent["schema"], 2);
    assert_eq!(
        intent["lanes"].as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>(),
        ["svc:naive", "grant:7f3a"]
    );
    assert_eq!(intent["lanes"]["svc:naive"]["default"], json!({"action": "direct", "egress": null}));
    assert_eq!(intent["lanes"]["svc:naive"]["rules"][0]["action"], "block");
    let grant = &intent["lanes"]["grant:7f3a"];
    assert_eq!(grant["default"], json!({"action": "egress", "egress": "warp"}));
    assert_eq!(
        grant["rules"].as_array().unwrap().iter().map(|rule| rule["egress"].clone()).collect::<Vec<_>>(),
        [json!("chain:c1"), Value::Null, json!("chain:c2"),]
    );
    assert_eq!(
        intent["chains"]["c1"],
        json!({"hops": [{
        "guid": GUID_B,
        "address": "panel.node-b.example.org",
        "port": 45443,
        "server_name": "panel.node-b.example.org",
        "public_key": hop_b().public_key,
        "short_id": "0123abcd",
        "uuid": hop_b().uuid_warp,
    }], "exit": "warp"})
    );
    assert_eq!(
        intent["chains"]["c2"]["hops"]
            .as_array()
            .unwrap()
            .iter()
            .map(|hop| hop["guid"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [GUID_B, GUID_C]
    );
    assert_eq!(intent["chains"]["c2"]["exit"], "direct");
    assert_eq!(intent["chains"]["c2"]["hops"][0]["uuid"], hop_b().uuid_direct);
    assert_eq!(intent["chains"]["c2"]["hops"][1]["uuid"], hop_c().uuid_direct);
    assert!(compiled.attach.is_some());
    assert!(compiled.digest.is_some());
}

#[test]
fn compiling_a_lane_policy_folds_the_service_and_the_other_lanes() {
    let service = router_policy("naive");
    let mut mine = lane("grant:7f3a");
    set_default(&mut mine, DefaultAction::Egress, Some(&format!("node:{GUID_B}")));
    let other = with_rules(lane("grant:0000"), vec![rule(Action::Block, json!({"ports": [25]}))]);
    let target = attached_target("naive");
    let router = router("naive");
    let mut chains = Resolver::new();
    let compiled = compiler::compile(
        &mine,
        Some(&target),
        Options { router: Some(&router), lanes: &[service, other], chains: Some(&mut chains), ..Options::default() },
    )
    .unwrap();
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(
        document(&compiled)["lanes"].as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>(),
        ["svc:naive", "grant:7f3a", "grant:0000",]
    );
    assert_eq!(document(&compiled)["lanes"]["grant:7f3a"]["default"]["egress"], "chain:c1");
}

#[test]
fn node_exit_refusals_are_named() {
    let mut service = router_policy("naive");
    set_default(&mut service, DefaultAction::Egress, Some(&format!("node:{GUID_B}")));
    let target = attached_target("naive");
    let router = router("naive");

    let mut pending = Resolver::new();
    pending.reasons.insert(
        GUID_B.into(),
        Reason::new("relay_credential_pending", None, "the node has not confirmed the relay account"),
    );
    let compiled = compiler::compile(
        &service,
        Some(&target),
        Options { router: Some(&router), lanes: &[], chains: Some(&mut pending), ..Options::default() },
    )
    .unwrap();
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(codes(&compiled), ["relay_credential_pending"]);

    for code in ["node_lacks_relay", "relay_disabled", "node_unknown"] {
        let mut resolver = Resolver::new();
        resolver.reasons.insert(GUID_B.into(), Reason::new(code, None, code));
        let compiled = compiler::compile(
            &service,
            Some(&target),
            Options { router: Some(&router), lanes: &[], chains: Some(&mut resolver), ..Options::default() },
        )
        .unwrap();
        assert_eq!(codes(&compiled), [code]);
    }

    let mut selective = egress_rule(json!({"domains": ["a.example"]}), &format!("node:{GUID_C}"));
    selective.id = Some("11111111-0000-4000-8000-111111111111".into());
    let ruled = with_rules(router_policy("naive"), vec![selective]);
    let mut resolver = Resolver::new();
    resolver.reasons.insert(GUID_C.into(), Reason::new("relay_disabled", None, "off"));
    let compiled = compiler::compile(
        &ruled,
        Some(&target),
        Options { router: Some(&router), lanes: &[], chains: Some(&mut resolver), ..Options::default() },
    )
    .unwrap();
    assert_eq!(compiled.reasons[0].rule_id.as_deref(), Some("11111111-0000-4000-8000-111111111111"));

    set_default(&mut service, DefaultAction::Egress, Some(&format!("node:{GUID_C}:warp")));
    let mut resolver = Resolver::new();
    let no_warp = compiler::compile(
        &service,
        Some(&target),
        Options { router: Some(&router), lanes: &[], chains: Some(&mut resolver), ..Options::default() },
    )
    .unwrap();
    assert_eq!(codes(&no_warp), ["relay_no_warp"]);

    set_default(&mut service, DefaultAction::Egress, Some(&format!("node:{GUID_B},local")));
    let mut resolver = Resolver::new();
    let chained_loop = compiler::compile(
        &service,
        Some(&target),
        Options { router: Some(&router), lanes: &[], chains: Some(&mut resolver), ..Options::default() },
    )
    .unwrap();
    assert_eq!(codes(&chained_loop), ["chain_loop"]);
}

#[test]
fn lanes_and_node_exits_need_the_router_and_the_attachment() {
    let lane = lane("grant:7f3a");
    let target = native_target("naive");
    let router = router("naive");
    let service = router_policy("naive");
    let mut chains = Resolver::new();
    let unattached = compiler::compile(
        &lane,
        Some(&target),
        Options {
            router: Some(&router),
            lanes: std::slice::from_ref(&service),
            chains: Some(&mut chains),
            ..Options::default()
        },
    )
    .unwrap();
    assert_eq!(codes(&unattached), ["lane_not_attached"]);

    let mut chains = Resolver::new();
    let no_router = compiler::compile(
        &lane,
        Some(&target),
        Options { router: None, lanes: &[service], chains: Some(&mut chains), ..Options::default() },
    )
    .unwrap();
    assert_eq!(codes(&no_router), ["lane_requires_router"]);

    let mut native = native_policy("naive");
    set_default(&mut native, DefaultAction::Egress, Some(&format!("node:{GUID_B}")));
    let compiled = compile_native(&native, Some(&target));
    assert!(codes(&compiled).contains(&"rule_kind_unsupported"));

    let mut native_lane = lane;
    native_lane.backend = panel_model::Backend::NaiveNative;
    let compiled = compile_native(&native_lane, Some(&target));
    assert_eq!(codes(&compiled), ["lane_requires_router"]);
}

#[test]
fn this_nodes_warp_is_only_needed_by_lanes_that_use_it() {
    let mut service = router_policy("naive");
    set_default(&mut service, DefaultAction::Egress, Some(&format!("node:{GUID_B}:warp")));
    let target = attached_target("naive");
    let mut router = router("naive");
    router.providers.clear();
    let mut chains = Resolver::new();
    let compiled = compiler::compile(
        &service,
        Some(&target),
        Options { router: Some(&router), lanes: &[], chains: Some(&mut chains), ..Options::default() },
    )
    .unwrap();
    assert_eq!(compiled.status, CompileStatus::Supported);

    let mut lane = lane("grant:1");
    set_default(&mut lane, DefaultAction::Egress, Some("warp"));
    let mut chains = Resolver::new();
    let compiled = compiler::compile(
        &service,
        Some(&target),
        Options { router: Some(&router), lanes: &[lane.clone()], chains: Some(&mut chains), ..Options::default() },
    )
    .unwrap();
    assert_eq!(codes(&compiled), ["provider_unavailable"]);

    lane.intent.fallback = Fallback::ApprovedDirect;
    router.providers = providers(&[("warp", Some(false))]);
    let mut chains = Resolver::new();
    let compiled = compiler::compile(
        &service,
        Some(&target),
        Options { router: Some(&router), lanes: &[lane], chains: Some(&mut chains), ..Options::default() },
    )
    .unwrap();
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert!(compiled.warnings.iter().any(|warning| warning == "provider_unreachable"));
    assert_eq!(document(&compiled)["lanes"]["grant:1"]["default"], json!({"action": "direct", "egress": null}));
}

#[test]
fn explain_walks_a_lanes_rules_for_a_destination() {
    let mut block = rule(Action::Block, json!({"domains": ["ads.example", "*.ads.example"]}));
    block.id = Some("11111111-0000-4000-8000-111111111111".into());
    let mut geosite = egress_rule(json!({"geosites": ["youtube"]}), &format!("node:{GUID_B}:warp"));
    geosite.id = Some("22222222-0000-4000-8000-222222222222".into());
    let mut direct = rule(Action::Direct, json!({"cidrs": ["203.0.113.0/24"], "ports": [443]}));
    direct.id = Some("33333333-0000-4000-8000-333333333333".into());
    let mut lane = with_rules(lane("grant:7f3a"), vec![block, geosite, direct]);
    set_default(&mut lane, DefaultAction::Egress, Some("warp"));

    assert_eq!(
        Value::Object(compiler::explain(&lane, "tracker.ads.example", 443)),
        json!({
            "lane": "grant:7f3a",
            "rule_id": "11111111-0000-4000-8000-111111111111",
            "action": "block",
            "exit": null,
            "hops": [],
            "via": null,
            "uncertain": [],
        })
    );
    assert_eq!(
        Value::Object(compiler::explain(&lane, "203.0.113.9", 443)),
        json!({
            "lane": "grant:7f3a",
            "rule_id": "33333333-0000-4000-8000-333333333333",
            "action": "direct",
            "exit": null,
            "hops": [],
            "via": null,
            "uncertain": ["22222222-0000-4000-8000-222222222222"],
        })
    );
    assert!(compiler::explain(&lane, "203.0.113.9", 80)["rule_id"].is_null());
    assert_eq!(
        Value::Object(compiler::explain(&lane, "example.org", 443)),
        json!({
            "lane": "grant:7f3a",
            "rule_id": null,
            "action": "egress",
            "exit": "warp",
            "hops": [],
            "via": null,
            "uncertain": ["22222222-0000-4000-8000-222222222222"],
        })
    );

    let chained_exit = format!("node:{GUID_B},{GUID_C}:warp");
    set_default(&mut lane, DefaultAction::Egress, Some(&chained_exit));
    let result = compiler::explain(&lane, "example.org", 443);
    assert_eq!(result["hops"], json!([GUID_B, GUID_C]));
    assert_eq!(result["via"], "warp");
    assert_eq!(result["exit"], chained_exit);
}
