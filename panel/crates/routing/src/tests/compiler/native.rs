//! Compiler/document/store cases from the AmneziaWG, TrustTunnel and MTProxy Python tests.

use panel_model::protocols::{EgressMode, EgressTarget};
use panel_model::routing::document::{
    attach_document, attached_to_router, canonical, document_digest, router_direct_intent, ATTACH_PROTOCOLS,
};
use panel_model::routing::models::{
    backend_for, backends_for, Action, CompileStatus, DefaultAction, RoutingRule, LANE_PROTOCOLS, ROUTING_PROTOCOLS,
};
use panel_model::validate::Model;
use panel_model::Backend;
use serde_json::{json, Value};

use super::support::*;
use crate::compiler::{self, direct_document, Options};

fn amneziawg_target(reachable: Option<bool>) -> EgressTarget {
    let mut target = native_target("amneziawg");
    target.revision = "0".into();
    target.providers = providers(&[("warp", reachable)]);
    target.applied = Some(applied("0", &direct_document(Backend::AmneziawgNative)));
    target
}

fn trusttunnel_target(attached: bool) -> EgressTarget {
    let mut target = native_target("trusttunnel");
    target.revision = "r1".into();
    target.providers = providers(&[("router", Some(true))]);
    let document =
        if attached { attach_document("trusttunnel").unwrap() } else { direct_document(Backend::TrusttunnelNative) };
    target.applied = Some(applied("r1", &document));
    target.mode = if attached { EgressMode::Proxy } else { EgressMode::Direct };
    target.router_attached = attached;
    target
}

#[test]
fn amneziawg_is_a_routing_service_with_its_own_backend_and_the_router() {
    assert_eq!(backend_for("amneziawg"), Some(Backend::AmneziawgNative));
    assert!(ROUTING_PROTOCOLS.contains(&"amneziawg"));
    assert_eq!(backends_for("amneziawg"), [Backend::AmneziawgNative, Backend::XrayRouter]);
    assert!(!LANE_PROTOCOLS.contains(&"amneziawg"));
    assert_eq!(direct_document(Backend::AmneziawgNative), json!({"schema": 1, "upstream": null}));
    assert_eq!(attach_document("amneziawg"), Some(json!({"schema": 1, "upstream": {"provider": "router"}})));
    let attached = json!({"schema": 1, "upstream": {"provider": "router"}});
    assert!(attached_to_router("amneziawg", &attached));
    assert!(!attached_to_router("amneziawg", &json!({"schema": 1, "upstream": {"provider": "warp"}})));
    assert!(!attached_to_router("amneziawg", &json!({"schema": 1, "upstream": null})));
}

#[test]
fn the_whole_tunnel_compiles_to_direct_or_warp() {
    let direct = compile_native(&native_policy("amneziawg"), Some(&amneziawg_target(Some(true))));
    assert_eq!(direct.status, CompileStatus::Supported);
    assert_eq!(document(&direct), &json!({"schema": 1, "upstream": null}));
    assert_eq!(direct.backend.as_deref(), Some("amneziawg_native"));
    assert_eq!(canonical(document(&direct)), r#"{"schema":1,"upstream":null}"#);
    assert_eq!(direct.digest.as_deref(), Some("35c19df74c30d320cca413219c4582401b11a8cf848a51a3b09143d61f0772ab"));

    let mut policy = native_policy("amneziawg");
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let warp = compile_native(&policy, Some(&amneziawg_target(Some(true))));
    assert_eq!(warp.status, CompileStatus::Supported);
    assert_eq!(document(&warp), &json!({"schema": 1, "upstream": {"provider": "warp"}}));
    assert_eq!(canonical(document(&warp)), r#"{"schema":1,"upstream":{"provider":"warp"}}"#);
    assert_eq!(warp.digest.as_deref(), Some("664488495d35f2e19b2ae6d5c7b3de92e163954ab1909121c66f595e5e018851"));
    assert!(!warp.restart_required);
}

#[test]
fn on_its_own_rules_lanes_and_other_exits_are_refused_with_the_reason() {
    let ruled = with_rules(native_policy("amneziawg"), vec![rule(Action::Block, json!({"domains": ["example.com"]}))]);
    let ruled = compile_native(&ruled, Some(&amneziawg_target(Some(true))));
    assert_eq!(ruled.status, CompileStatus::Unsupported);
    assert_eq!(ruled.reasons[0].code, "rule_kind_unsupported");
    assert!(ruled.reasons[0].message.contains("attach it to the node's Xray-router"));

    let mut lane = native_policy("amneziawg");
    lane.lane = "grant:abc".into();
    let lane = compile_native(&lane, Some(&amneziawg_target(Some(true))));
    assert_eq!(lane.status, CompileStatus::Unsupported);
    assert_eq!(lane.reasons[0].code, "lanes_unsupported");

    let router = compile_native(&router_policy("amneziawg"), Some(&amneziawg_target(Some(true))));
    assert_eq!(router.status, CompileStatus::Unsupported);
    assert_eq!(router.reasons[0].code, "router_unavailable");

    let mut chain = native_policy("amneziawg");
    set_default(&mut chain, DefaultAction::Egress, Some(&format!("node:{}", "a".repeat(32))));
    let chain = compile_native(&chain, Some(&amneziawg_target(Some(true))));
    assert_eq!(chain.status, CompileStatus::Unsupported);
    assert_eq!(chain.reasons[0].code, "rule_kind_unsupported");
}

#[test]
fn an_unreachable_warp_stays_fail_closed_or_falls_back_when_approved() {
    let mut policy = native_policy("amneziawg");
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let closed = compile_native(&policy, Some(&amneziawg_target(Some(false))));
    assert_eq!(closed.status, CompileStatus::Unsupported);
    assert_eq!(closed.reasons[0].code, "provider_unreachable");

    policy.intent.fallback = panel_model::routing::models::Fallback::ApprovedDirect;
    let approved = compile_native(&policy, Some(&amneziawg_target(Some(false))));
    assert_eq!(approved.status, CompileStatus::Supported);
    assert_eq!(document(&approved), &json!({"schema": 1, "upstream": null}));
    assert!(approved.warnings.iter().any(|warning| warning == "provider_unreachable"));

    policy.intent.fallback = panel_model::routing::models::Fallback::FailClosed;
    let unknown = compile_native(&policy, Some(&amneziawg_target(None)));
    assert_eq!(unknown.status, CompileStatus::Supported);
}

#[test]
fn attach_steers_the_tunnels_into_the_router_and_rules_apply_there() {
    // Only the compiler-visible documents: steering and persistence belong to RoutingService.
    let target = attached_target("amneziawg");
    let router = router("amneziawg");
    assert_eq!(target.applied.as_ref().unwrap().document, json!({"schema": 1, "upstream": {"provider": "router"}}));
    let direct = compiler::compile(
        &router_policy("amneziawg"),
        Some(&target),
        Options { router: Some(&router), ..Options::default() },
    )
    .unwrap();
    assert_eq!(document(&direct), &router_direct_intent());

    let mut policy =
        with_rules(router_policy("amneziawg"), vec![rule(Action::Direct, json!({"domains": ["cloudflare.com"]}))]);
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let compiled =
        compiler::compile(&policy, Some(&target), Options { router: Some(&router), ..Options::default() }).unwrap();
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(document(&compiled)["default"]["egress"], "warp");
    assert_eq!(document(&compiled)["rules"][0]["domains"], json!(["cloudflare.com"]));
}

#[test]
fn trusttunnel_is_a_routing_service_without_lanes() {
    assert_eq!(backend_for("trusttunnel"), Some(Backend::TrusttunnelNative));
    assert!(ROUTING_PROTOCOLS.contains(&"trusttunnel"));
    assert!(!LANE_PROTOCOLS.contains(&"trusttunnel"));
    assert_eq!(backend_for("mtproxy"), Some(Backend::MtproxyNative));
    assert_eq!(direct_document(Backend::TrusttunnelNative), json!({"mode": "direct"}));
}

#[test]
fn the_attach_document_is_the_managers_own_socks5_upstream() {
    let attached = json!({"mode": "socks5", "address": "127.0.0.1:45104"});
    assert_eq!(attach_document("trusttunnel"), Some(attached.clone()));
    assert!(ATTACH_PROTOCOLS.contains(&"trusttunnel"));
    assert!(attached_to_router("trusttunnel", &attached));
    assert!(!attached_to_router("trusttunnel", &json!({"mode": "direct"})));
    assert!(!attached_to_router("trusttunnel", &json!({"mode": "socks5", "address": "127.0.0.1:41001"})));
    assert!(!attached_to_router("trusttunnel", &Value::Null));
}

#[test]
fn the_native_backend_compiles_direct_only_and_asks_for_the_router_otherwise() {
    let direct = compile_native(&native_policy("trusttunnel"), Some(&trusttunnel_target(false)));
    assert_eq!(direct.status, CompileStatus::Supported);
    assert_eq!(document(&direct), &json!({"mode": "direct"}));
    assert_eq!(direct.backend.as_deref(), Some("trusttunnel_native"));

    let blocked =
        with_rules(native_policy("trusttunnel"), vec![rule(Action::Block, json!({"domains": ["example.com"]}))]);
    let blocked = compile_native(&blocked, Some(&trusttunnel_target(false)));
    assert_eq!(blocked.status, CompileStatus::Unsupported);
    assert_eq!(blocked.reasons[0].code, "not_attached");

    let mut warp = native_policy("trusttunnel");
    set_default(&mut warp, DefaultAction::Egress, Some("warp"));
    let warp = compile_native(&warp, Some(&trusttunnel_target(false)));
    assert_eq!(warp.status, CompileStatus::Unsupported);
    assert_eq!(warp.reasons[0].code, "not_attached");
}

#[test]
fn on_the_router_a_service_policy_compiles_to_the_service_intent() {
    let mut router = router("trusttunnel");
    router.capabilities = capabilities(&[
        "whole_direct",
        "whole_warp",
        "block_domain",
        "selective_domain",
        "block_geosite",
        "block_protocol",
        "selective_protocol",
    ]);
    let torrent = RoutingRule::validate(&crate::presets::rule_for("torrent").unwrap()).unwrap();
    let policy = with_rules(
        router_policy("trusttunnel"),
        vec![torrent, rule(Action::Block, json!({"domains": ["example.com"]}))],
    );
    let compiled = compiler::compile(
        &policy,
        Some(&trusttunnel_target(true)),
        Options { router: Some(&router), ..Options::default() },
    )
    .unwrap();
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(compiled.backend.as_deref(), Some("xray_router"));
    assert_eq!(document(&compiled)["schema"], 1);
    assert_eq!(document(&compiled)["rules"].as_array().unwrap().len(), 2);

    let detached = compiler::compile(
        &policy,
        Some(&trusttunnel_target(false)),
        Options { router: Some(&router), ..Options::default() },
    )
    .unwrap();
    assert_eq!(detached.status, CompileStatus::Unsupported);
    assert_eq!(detached.reasons[0].code, "not_attached");
}

#[test]
fn a_client_lane_is_refused_for_trusttunnel() {
    let mut router = router("trusttunnel");
    router.capabilities = capabilities(&["whole_direct"]);
    let mut lane = router_policy("trusttunnel");
    lane.lane = "grant:abc".into();
    let compiled = compiler::compile(
        &router_policy("trusttunnel"),
        Some(&trusttunnel_target(true)),
        Options { router: Some(&router), lanes: &[lane], ..Options::default() },
    )
    .unwrap();
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(compiled.reasons[0].code, "lanes_unsupported");
    assert!(compiled.reasons[0].message.contains("TrustTunnel"));
}

#[test]
fn explain_works_like_any_service() {
    let policy =
        with_rules(native_policy("trusttunnel"), vec![rule(Action::Block, json!({"domains": ["example.com"]}))]);
    let result = compiler::explain(&policy, "a.example.com", 443);
    assert_eq!(result["action"], "block");
    assert_eq!(result["lane"], "svc");
    assert_eq!(compiler::explain(&native_policy("trusttunnel"), "a.example.com", 443)["action"], "direct");
}

#[test]
fn a_policy_applies_through_the_router_and_rolls_back() {
    // Preview/explain and the direct rollback intent are compiler-visible; apply/history are not.
    let target = trusttunnel_target(true);
    let router = router("trusttunnel");
    let mut torrent = RoutingRule::validate(&crate::presets::rule_for("torrent").unwrap()).unwrap();
    torrent.id = Some("aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa".into());
    let policy = with_rules(router_policy("trusttunnel"), vec![torrent]);
    let compiled =
        compiler::compile(&policy, Some(&target), Options { router: Some(&router), ..Options::default() }).unwrap();
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(compiled.backend.as_deref(), Some("xray_router"));
    assert_eq!(document(&compiled)["rules"][0]["protocols"], json!(["bittorrent"]));
    let explained = compiler::explain(&policy, "tracker.example.com", 6881);
    assert_eq!(explained["lane"], "svc");
    assert_eq!(explained["uncertain"], json!(["aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa"]));
    let reset = compiler::compile(
        &router_policy("trusttunnel"),
        Some(&target),
        Options { router: Some(&router), ..Options::default() },
    )
    .unwrap();
    assert_eq!(document(&reset), &router_direct_intent());
}

#[test]
fn a_native_policy_other_than_direct_must_attach_first() {
    let mut policy = native_policy("mtproxy");
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let compiled = compile_native(&policy, Some(&native_target("mtproxy")));
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(codes(&compiled), ["not_attached"]);

    let compiled = compile_native(&native_policy("mtproxy"), Some(&native_target("mtproxy")));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(document(&compiled), &json!({"schema": 1, "upstream": null}));
    assert_eq!(compiled.digest, Some(document_digest(document(&compiled))));
}

#[test]
fn attach_then_warp_then_detach() {
    // The router intent and native reset document can be asserted without an adapter.
    let target = attached_target("mtproxy");
    assert_eq!(target.applied.as_ref().unwrap().document, attach_document("mtproxy").unwrap());
    let router = router("mtproxy");
    let mut policy = router_policy("mtproxy");
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let compiled =
        compiler::compile(&policy, Some(&target), Options { router: Some(&router), ..Options::default() }).unwrap();
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(document(&compiled)["default"], json!({"action": "egress", "egress": "warp"}));
    assert_eq!(direct_document(Backend::MtproxyNative), json!({"schema": 1, "upstream": null}));
}

#[test]
fn domain_geosite_and_protocol_rules_are_refused_on_mtproxy() {
    let unsupported = vec![
        rule(Action::Block, json!({"domains": ["example.com"]})),
        rule(Action::Block, json!({"geosites": ["category-ads-all"]})),
        rule(Action::Block, json!({"protocols": ["bittorrent"]})),
    ];
    let supported = vec![
        egress_rule(json!({"cidrs": ["149.154.160.0/20"]}), "warp"),
        rule(Action::Block, json!({"geoips": ["cn"], "ports": [443]})),
    ];
    let policy = with_rules(router_policy("mtproxy"), unsupported.into_iter().chain(supported.clone()).collect());
    let target = attached_target("mtproxy");
    let router = router("mtproxy");
    let compiled =
        compiler::compile(&policy, Some(&target), Options { router: Some(&router), ..Options::default() }).unwrap();
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(codes(&compiled), ["rule_kind_unsupported", "rule_kind_unsupported", "rule_kind_unsupported"]);

    let supported = compiler::compile(
        &with_rules(router_policy("mtproxy"), supported),
        Some(&target),
        Options { router: Some(&router), ..Options::default() },
    )
    .unwrap();
    assert_eq!(supported.status, CompileStatus::Supported);
    assert_eq!(document(&supported)["rules"].as_array().unwrap().len(), 2);
}

#[test]
fn migration_21_widens_the_checks() {
    let scratch = Scratch::new("migration-21");
    let database = migrated(&scratch);
    let connection = database.connect().unwrap();
    connection
        .execute(
            "INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('mtproxy',1,'converged',0)",
            [],
        )
        .unwrap();
    let sql: String = connection
        .query_row("SELECT sql FROM sqlite_master WHERE name='routing_policies'", [], |row| row.get(0))
        .unwrap();
    assert!(sql.contains("'mtproxy'"));
    assert!(sql.contains("'mtproxy_native'"));
}
