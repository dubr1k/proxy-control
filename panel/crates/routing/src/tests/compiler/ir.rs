//! `test_routing_ir.py`: models, native compilation and the policy store.

use std::collections::BTreeSet;

use panel_core::migrations::{apply, apply_migrations, MIGRATIONS};
use panel_model::routing::document::{canonical, document_digest};
use panel_model::routing::models::{
    Action, CompileStatus, DefaultAction, Fallback, PolicyInput, PolicyState, Port, RoutingRule, RuleMatch,
    COMPILER_VERSION, LANE_SERVICE, MAX_RULES,
};
use panel_model::validate::Model;
use panel_model::{Backend, Protocol};
use serde_json::json;

use super::support::*;
use crate::compiler::{self, Options};
use crate::store::{self, ApplyRecord, Mark, StoreError};

#[test]
fn rule_match_normalizes_domains_and_cidrs() {
    let matcher = RuleMatch::validate(&json!({
        "domains": ["Example.COM.", "*.CDN.example", "пример.рф", "example.com"],
        "cidrs": ["10.1.2.3", "192.168.1.0/24", "2001:db8::1", "10.0.0.5/8"],
        "ports": [443, "80", "1000-2000"],
    }))
    .unwrap();
    assert_eq!(matcher.domains, ["example.com", "*.cdn.example", "xn--e1afmkfd.xn--p1ai"]);
    assert_eq!(matcher.cidrs, ["10.1.2.3/32", "192.168.1.0/24", "2001:db8::1/128", "10.0.0.0/8"]);
    assert_eq!(matcher.ports, [Port::One(443), Port::One(80), Port::Range("1000-2000".into())]);
}

#[test]
fn rule_match_rejects_bad_selectors() {
    for bad in [
        json!({"domains": ["exa mple.com"]}),
        json!({"domains": ["*"]}),
        json!({"domains": ["a.*.com"]}),
        json!({"domains": ["-bad.com"]}),
        json!({"cidrs": ["300.1.1.1"]}),
        json!({"cidrs": ["10.0.0.0/33"]}),
        json!({"domains": ["ok.com"], "ports": [0]}),
        json!({"domains": ["ok.com"], "ports": ["9-1"]}),
        json!({"domains": ["ok.com"], "ports": [true]}),
        json!({"domains": ["ok.com"], "extra": 1}),
    ] {
        assert!(RuleMatch::validate(&bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn rule_match_rejects_empty() {
    assert!(RuleMatch::validate(&json!({})).is_err());
    assert_eq!(RuleMatch::validate(&json!({"ports": [443]})).unwrap().ports, [Port::One(443)]);
}

#[test]
fn egress_required_for_egress_action_only() {
    assert!(RoutingRule::validate(&json!({"action": "egress", "match": {"domains": ["a.com"]}})).is_err());
    assert!(RoutingRule::validate(&json!({
        "action": "block", "egress": "warp", "match": {"domains": ["a.com"]}
    }))
    .is_err());
    assert_eq!(egress_rule(json!({"domains": ["a.com"]}), "warp").egress.as_deref(), Some("warp"));
    assert!(PolicyInput::validate(&json!({"default_action": "egress"})).is_err());
    assert!(PolicyInput::validate(&json!({"default_action": "direct", "default_egress": "warp"})).is_err());
    assert!(PolicyInput::validate(&json!({"default_action": "egress", "default_egress": "tor"})).is_err());
}

#[test]
fn policy_limits() {
    let rule = rule(Action::Block, json!({"domains": ["a.com"]}));
    let accepted = PolicyInput::validate(&json!({"rules": vec![rule.dump(); MAX_RULES]})).unwrap();
    assert_eq!(accepted.intent.rules.len(), MAX_RULES);
    assert!(PolicyInput::validate(&json!({"rules": vec![rule.dump(); MAX_RULES + 1]})).is_err());
    let domains: Vec<String> = (0..65).map(|index| format!("h{index}.com")).collect();
    assert!(RuleMatch::validate(&json!({"domains": domains})).is_err());
    let cidrs: Vec<String> = (0..65).map(|index| format!("10.0.{index}.0/24")).collect();
    assert!(RuleMatch::validate(&json!({"cidrs": cidrs})).is_err());
    let ports: Vec<i64> = (1..=33).collect();
    assert!(RuleMatch::validate(&json!({"domains": ["a.com"], "ports": ports})).is_err());
    assert!(RoutingRule::validate(&json!({
        "action": "block", "match": {"domains": ["a.com"]}, "note": "x".repeat(121)
    }))
    .is_err());
}

#[test]
fn policy_input_ignores_server_fields() {
    let id = "00000000-0000-4000-8000-000000000000";
    let mut stored = with_rules(
        native_policy("naive"),
        vec![{
            let mut rule = rule(Action::Block, json!({"domains": ["a.com"]}));
            rule.id = Some(id.into());
            rule
        }],
    );
    stored.revision = 7;
    stored.state = PolicyState::Applied;
    stored.applied_revision = Some(7);
    stored.applied_digest = Some("d".into());
    let draft = PolicyInput::from_policy(&stored);
    let dumped = draft.dump();
    let keys: BTreeSet<&str> = dumped.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, BTreeSet::from(["backend", "default_action", "default_egress", "fallback", "rules"]));
    assert_eq!(draft.intent.rules[0].id.as_deref(), Some(id));
    assert!(PolicyInput::validate(&json!({"revision": 3})).is_err());
    assert!(PolicyInput::validate(&json!({"state": "applied"})).is_err());
}

#[test]
fn compile_naive_whole_warp() {
    let mut policy = native_policy("naive");
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let compiled = compile_native(&policy, Some(&native_target("naive")));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert!(compiled.reasons.is_empty());
    assert_eq!(document(&compiled), &json!({"schema": 1, "upstream": {"provider": "warp"}, "acl": []}));
    assert_eq!(canonical(document(&compiled)), r#"{"acl":[],"schema":1,"upstream":{"provider":"warp"}}"#);
    assert_eq!(compiled.digest.as_deref(), Some("1838a7f7e1420f168620d1ac102d4e5d8dab58a2faa86286ad87115504a0997e"));
    assert_eq!(compiled.digest, Some(document_digest(document(&compiled))));
    assert!(!compiled.restart_required);
    assert_eq!(compiled.backend.as_deref(), Some("naive_native"));
    assert_eq!(compiled.compiler_version, COMPILER_VERSION);
    assert!(compiled.rollback.is_none());
}

#[test]
fn compile_naive_direct() {
    let compiled = compile_native(&native_policy("naive"), Some(&native_target("naive")));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(document(&compiled), &json!({"schema": 1, "upstream": null, "acl": []}));
    assert_eq!(canonical(document(&compiled)), r#"{"acl":[],"schema":1,"upstream":null}"#);
    assert_eq!(compiled.digest.as_deref(), Some("9f5718930896ccc791e379e4c9b162de3e22268602715a2fcf0f3937b523f9e0"));
    assert!(compiled.warnings.iter().any(|warning| warning == "policy_empty"));
}

#[test]
fn compile_naive_block_domain_and_cidr_into_one_acl() {
    let mut first = rule(Action::Block, json!({"domains": ["example.com", "*.example.com"]}));
    first.id = Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into());
    let mut disabled = rule(Action::Block, json!({"domains": ["skip.me"]}));
    disabled.enabled = false;
    let policy = with_rules(
        native_policy("naive"),
        vec![
            first,
            rule(Action::Block, json!({"cidrs": ["10.0.0.0/8"]})),
            disabled,
            rule(Action::Block, json!({"domains": ["z.example"]})),
        ],
    );
    let compiled = compile_native(&policy, Some(&native_target("naive")));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(
        document(&compiled),
        &json!({
            "schema": 1,
            "upstream": null,
            "acl": [{"deny": ["example.com", "*.example.com", "10.0.0.0/8", "z.example"]}],
        })
    );
    assert!(!compiled.warnings.iter().any(|warning| warning == "policy_empty"));
}

#[test]
fn compile_naive_chunks_a_long_acl_by_forwardproxy_line_limit() {
    let domains: Vec<String> = (0..64).map(|index| format!("h{index}.example")).collect();
    let cidrs: Vec<String> = (0..10).map(|index| format!("10.0.{index}.0/24")).collect();
    let policy =
        with_rules(native_policy("naive"), vec![rule(Action::Block, json!({"domains": domains, "cidrs": cidrs}))]);
    let compiled = compile_native(&policy, Some(&native_target("naive")));
    assert_eq!(compiled.status, CompileStatus::Supported);
    let lengths: Vec<usize> = document(&compiled)["acl"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["deny"].as_array().unwrap().len())
        .collect();
    assert_eq!(lengths, [64, 10]);
}

#[test]
fn compile_naive_selective_rule_is_unsupported_with_rule_id() {
    let id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let mut selective = egress_rule(json!({"domains": ["a.com"]}), "warp");
    selective.id = Some(id.into());
    let policy =
        with_rules(native_policy("naive"), vec![selective, rule(Action::Direct, json!({"cidrs": ["1.2.3.0/24"]}))]);
    let compiled = compile_native(&policy, Some(&native_target("naive")));
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert!(compiled.document.is_none() && compiled.digest.is_none());
    let codes_and_rules: Vec<(&str, Option<&str>)> =
        compiled.reasons.iter().map(|reason| (reason.code.as_str(), reason.rule_id.as_deref())).collect();
    assert_eq!(codes_and_rules, [("backend_capability_missing", Some(id)), ("backend_capability_missing", None)]);
    assert!(compiled.reasons[0].message.contains("selective_domain"));
}

#[test]
fn compile_naive_block_port_unsupported() {
    let policy =
        with_rules(native_policy("naive"), vec![rule(Action::Block, json!({"domains": ["a.com"], "ports": [25]}))]);
    let compiled = compile_native(&policy, Some(&native_target("naive")));
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(codes(&compiled), ["rule_kind_unsupported"]);
}

#[test]
fn compile_naive_block_beside_warp_default_is_unsupported() {
    let mut policy = with_rules(native_policy("naive"), vec![rule(Action::Block, json!({"domains": ["a.com"]}))]);
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let compiled = compile_native(&policy, Some(&native_target("naive")));
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(codes(&compiled), ["rule_kind_unsupported"]);
    assert!(compiled.reasons[0].message.contains("upstream"));
}

#[test]
fn compile_mieru_selective_rules_in_order() {
    let mut disabled = rule(Action::Block, json!({"domains": ["off.example"]}));
    disabled.enabled = false;
    let policy = with_rules(
        native_policy("mieru"),
        vec![
            egress_rule(json!({"domains": ["*.stream.example", "stream.example"]}), "warp"),
            rule(Action::Block, json!({"cidrs": ["203.0.113.0/24"]})),
            rule(Action::Direct, json!({"domains": ["bank.example"]})),
            disabled,
        ],
    );
    let compiled = compile_native(&policy, Some(&native_target("mieru")));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert!(compiled.restart_required);
    assert_eq!(
        document(&compiled),
        &json!({
            "schema": 1,
            "proxies": [{"name": "warp", "provider": "warp"}],
            "rules": [
                {"domains": ["stream.example"], "cidrs": [], "action": "PROXY", "proxy": "warp"},
                {"domains": [], "cidrs": ["203.0.113.0/24"], "action": "REJECT", "proxy": null},
                {"domains": ["bank.example"], "cidrs": [], "action": "DIRECT", "proxy": null},
            ],
        })
    );
}

#[test]
fn compile_mieru_default_proxy_with_direct_exception() {
    let mut policy =
        with_rules(native_policy("mieru"), vec![rule(Action::Direct, json!({"domains": ["bank.example"]}))]);
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let compiled = compile_native(&policy, Some(&native_target("mieru")));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(
        document(&compiled)["rules"],
        json!([
            {"domains": ["bank.example"], "cidrs": [], "action": "DIRECT", "proxy": null},
            {"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"},
        ])
    );
    assert_eq!(document(&compiled)["proxies"], json!([{"name": "warp", "provider": "warp"}]));
}

#[test]
fn compile_mieru_direct_without_rules_has_no_proxies() {
    let compiled = compile_native(&native_policy("mieru"), Some(&native_target("mieru")));
    assert_eq!(document(&compiled), &json!({"schema": 1, "proxies": [], "rules": []}));
    assert_eq!(canonical(document(&compiled)), r#"{"proxies":[],"rules":[],"schema":1}"#);
    assert_eq!(compiled.digest.as_deref(), Some("53fadc90aed6753169e1bd8e88b97ce20a93def86d51400d40834e22a9b6b282"));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert!(compiled.warnings.iter().any(|warning| warning == "policy_empty"));
}

#[test]
fn compile_private_destination_rejected() {
    for cidr in ["127.0.0.1", "10.1.2.0/24", "192.168.0.0/16", "169.254.1.1", "::1", "fd00::/8"] {
        let policy = with_rules(native_policy("mieru"), vec![rule(Action::Direct, json!({"cidrs": [cidr]}))]);
        let compiled = compile_native(&policy, Some(&native_target("mieru")));
        assert_eq!(codes(&compiled), ["private_destination"], "{cidr}");
        let policy = with_rules(native_policy("mieru"), vec![rule(Action::Block, json!({"cidrs": [cidr]}))]);
        let blocked = compile_native(&policy, Some(&native_target("mieru")));
        assert_eq!(blocked.status, CompileStatus::Supported, "{cidr}");
        assert!(crate::net::is_private_network(&policy.intent.rules[0].matcher.cidrs[0]), "{cidr}");
    }
}

#[test]
fn compile_private_domain_rejected() {
    let policy = with_rules(native_policy("mieru"), vec![egress_rule(json!({"domains": ["localhost"]}), "warp")]);
    let compiled = compile_native(&policy, Some(&native_target("mieru")));
    assert_eq!(codes(&compiled), ["private_destination"]);
}

#[test]
fn compile_provider_unavailable_fail_closed() {
    for fallback in [Fallback::FailClosed, Fallback::ApprovedDirect] {
        let mut policy = native_policy("naive");
        set_default(&mut policy, DefaultAction::Egress, Some("warp"));
        policy.intent.fallback = fallback;
        let mut target = native_target("naive");
        target.providers.clear();
        let compiled = compile_native(&policy, Some(&target));
        assert_eq!(compiled.status, CompileStatus::Unsupported);
        assert_eq!(codes(&compiled), ["provider_unavailable"]);
    }
}

#[test]
fn compile_provider_unreachable_warning_and_approved_direct_fallback() {
    let mut down = native_target("mieru");
    down.providers = providers(&[("warp", Some(false))]);
    let mut policy = native_policy("mieru");
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let closed = compile_native(&policy, Some(&down));
    assert_eq!(closed.status, CompileStatus::Unsupported);
    assert_eq!(codes(&closed), ["provider_unreachable"]);

    policy.intent.fallback = Fallback::ApprovedDirect;
    policy.intent.rules = vec![
        egress_rule(json!({"domains": ["a.example"]}), "warp"),
        rule(Action::Block, json!({"domains": ["b.example"]})),
    ];
    let opened = compile_native(&policy, Some(&down));
    assert_eq!(opened.status, CompileStatus::Supported);
    assert!(opened.warnings.iter().any(|warning| warning == "provider_unreachable"));
    assert_eq!(
        document(&opened),
        &json!({"schema": 1, "proxies": [], "rules": [
            {"domains": ["a.example"], "cidrs": [], "action": "DIRECT", "proxy": null},
            {"domains": ["b.example"], "cidrs": [], "action": "REJECT", "proxy": null},
        ]})
    );

    let mut unknown = native_target("mieru");
    unknown.providers = providers(&[("warp", None)]);
    policy.intent.fallback = Fallback::FailClosed;
    policy.intent.rules.clear();
    let compiled = compile_native(&policy, Some(&unknown));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert!(!compiled.warnings.iter().any(|warning| warning == "provider_unreachable"));
}

#[test]
fn compile_node_lacks_egress_v1() {
    let compiled = compiler::compile(
        &native_policy("naive"),
        Some(&native_target("naive")),
        Options { old_node: true, ..Options::default() },
    )
    .unwrap();
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(codes(&compiled), ["node_lacks_egress_v1"]);
    let disabled = compile_native(&native_policy("naive"), None);
    assert_eq!(codes(&disabled), ["protocol_disabled_on_node"]);
}

#[test]
fn compile_capability_missing_from_target() {
    let mut target = native_target("naive");
    target.capabilities = capabilities(&["whole_direct", "whole_warp", "block_domain"]);
    let policy = with_rules(
        native_policy("naive"),
        vec![rule(Action::Block, json!({"cidrs": ["1.2.3.0/24"]})), rule(Action::Block, json!({"domains": ["a.com"]}))],
    );
    let compiled = compile_native(&policy, Some(&target));
    let reasons: Vec<(&str, &str)> =
        compiled.reasons.iter().map(|reason| (reason.code.as_str(), reason.message.as_str())).collect();
    assert_eq!(reasons, [("backend_capability_missing", "naive_native lacks block_cidr")]);

    let mut target = native_target("naive");
    target.capabilities = capabilities(&["whole_direct", "block_domain", "block_cidr"]);
    let mut whole = native_policy("naive");
    set_default(&mut whole, DefaultAction::Egress, Some("warp"));
    assert_eq!(codes(&compile_native(&whole, Some(&target))), ["backend_capability_missing"]);

    let mismatch = compile_native(&native_policy("naive"), Some(&native_target("mieru")));
    assert_eq!(codes(&mismatch), ["backend_capability_missing"]);
    assert!(mismatch.reasons[0].message.contains("mieru_native"));
}

#[test]
fn compile_disabled_rules_skipped() {
    let mut port = rule(Action::Block, json!({"domains": ["a.com"], "ports": [25]}));
    port.enabled = false;
    let mut selective = egress_rule(json!({"domains": ["b.com"]}), "warp");
    selective.enabled = false;
    let policy = with_rules(native_policy("naive"), vec![port, selective]);
    let mut target = native_target("naive");
    target.providers.clear();
    let compiled = compile_native(&policy, Some(&target));
    assert_eq!(compiled.status, CompileStatus::Supported);
    assert_eq!(document(&compiled)["acl"], json!([]));
}

#[test]
fn compile_digest_is_canonical() {
    let first = compile_native(
        &with_rules(
            native_policy("naive"),
            vec![rule(Action::Block, json!({"domains": ["a.com"], "cidrs": ["10.0.0.0/8"]}))],
        ),
        Some(&native_target("naive")),
    );
    let second = compile_native(
        &with_rules(
            native_policy("naive"),
            vec![rule(Action::Block, json!({"cidrs": ["10.0.0.0/8"], "domains": ["a.com"]}))],
        ),
        Some(&native_target("naive")),
    );
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.digest, Some(document_digest(document(&first))));
    let changed = compile_native(
        &with_rules(native_policy("naive"), vec![rule(Action::Block, json!({"domains": ["b.com"]}))]),
        Some(&native_target("naive")),
    );
    assert_ne!(changed.digest, first.digest);
}

#[test]
fn compile_diff_against_applied() {
    let applied_document = json!({"schema": 1, "upstream": null, "acl": []});
    let mut target = native_target("naive");
    target.applied = Some(applied("rev-a", &applied_document));
    target.warnings = vec!["adopts_unmanaged_upstream".into()];
    let mut policy = native_policy("naive");
    set_default(&mut policy, DefaultAction::Egress, Some("warp"));
    let compiled = compile_native(&policy, Some(&target));
    assert_eq!(
        compiled.rollback,
        Some(json!({
            "to_revision": "rev-a", "to_digest": document_digest(&applied_document),
        }))
    );
    assert!(compiled.diff.iter().any(|line| line.starts_with('+') && line.contains("warp")));
    assert!(compiled.diff.iter().any(|line| line.starts_with('-') && line.contains("null")));
    assert!(compiled.warnings.iter().any(|warning| warning == "adopts_unmanaged_upstream"));
    assert!(compile_native(&native_policy("naive"), Some(&target)).diff.is_empty());
}

#[test]
fn compile_document_size_limit() {
    let rules = (0..3)
        .map(|_| {
            let domains: Vec<String> =
                (0..64).map(|index| format!("{}{index:03}.{}.example", "x".repeat(60), "y".repeat(60))).collect();
            rule(Action::Block, json!({"domains": domains}))
        })
        .collect();
    let compiled = compile_native(&with_rules(native_policy("naive"), rules), Some(&native_target("naive")));
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(codes(&compiled), ["document_too_large"]);
}

#[test]
fn upsert_creates_with_revision_1() {
    let (_scratch, database) = database("upsert-create");
    let connection = database.connect().unwrap();
    let draft = input(vec![rule(Action::Block, json!({"domains": ["a.com"]}))]);
    let policy = store::upsert(&connection, "local", "naive", &draft, None, 10, LANE_SERVICE).unwrap();
    assert_eq!(policy.revision, 1);
    assert_eq!(policy.state, PolicyState::Draft);
    assert_eq!(policy.backend, Backend::NaiveNative);
    assert_eq!(policy.protocol, Protocol::Naive);
    assert_eq!(policy.node_id, "local");
    assert_eq!(policy.created_at, 10);
    assert_eq!(policy.intent.rules.len(), 1);
    assert!(policy.intent.rules[0].id.is_some());
    assert_eq!(policy.intent.rules[0].position, 0);
    assert_eq!(store::get(&connection, "local", "naive", LANE_SERVICE).unwrap(), Some(policy.clone()));
    assert_eq!(store::get(&connection, "local", "mieru", LANE_SERVICE).unwrap(), None);
    assert_eq!(
        store::list(&connection, None).unwrap().iter().map(|item| item.id.as_str()).collect::<Vec<_>>(),
        [policy.id.as_str()]
    );
    assert!(store::list(&connection, Some("n1")).unwrap().is_empty());
    assert!(matches!(store::get_by_id(&connection, "missing"), Err(StoreError::NotFound(id)) if id == "missing"));
}

#[test]
fn upsert_conflict() {
    let (_scratch, database) = database("upsert-conflict");
    let connection = database.connect().unwrap();
    let draft = PolicyInput::default();
    store::upsert(&connection, "local", "naive", &draft, None, 0, LANE_SERVICE).unwrap();
    assert!(matches!(
        store::upsert(&connection, "local", "naive", &draft, Some(5), 0, LANE_SERVICE),
        Err(StoreError::Conflict(1))
    ));
    assert_eq!(store::upsert(&connection, "local", "naive", &draft, Some(1), 0, LANE_SERVICE).unwrap().revision, 2);
    assert_eq!(store::upsert(&connection, "local", "naive", &draft, None, 0, LANE_SERVICE).unwrap().revision, 3);
    assert!(matches!(
        store::upsert(&connection, "local", "mieru", &draft, Some(1), 0, LANE_SERVICE),
        Err(StoreError::Conflict(_))
    ));
    let wrong = PolicyInput { backend: Some(Backend::NaiveNative), ..PolicyInput::default() };
    assert!(matches!(
        store::upsert(&connection, "local", "mieru", &wrong, None, 0, LANE_SERVICE),
        Err(StoreError::Invalid(_))
    ));
}

#[test]
fn upsert_preserves_rule_ids_and_reorders() {
    let (_scratch, database) = database("upsert-reorder");
    let connection = database.connect().unwrap();
    let first = store::upsert(
        &connection,
        "local",
        "mieru",
        &input(vec![
            rule(Action::Block, json!({"domains": ["a.com"]})),
            rule(Action::Block, json!({"domains": ["b.com"]})),
            rule(Action::Block, json!({"domains": ["c.com"]})),
        ]),
        None,
        0,
        LANE_SERVICE,
    )
    .unwrap();
    let a = first.intent.rules[0].clone();
    let b = first.intent.rules[1].clone();
    let mut c = first.intent.rules[2].clone();
    c.note = "moved up".into();
    let foreign = store::upsert(
        &connection,
        "n1",
        "mieru",
        &input(vec![rule(Action::Block, json!({"domains": ["x.com"]}))]),
        None,
        0,
        LANE_SERVICE,
    )
    .unwrap();
    let second = store::upsert(
        &connection,
        "local",
        "mieru",
        &input(vec![
            c.clone(),
            rule(Action::Block, json!({"domains": ["new.com"]})),
            a.clone(),
            foreign.intent.rules[0].clone(),
            b.clone(),
            b.clone(),
        ]),
        Some(1),
        0,
        LANE_SERVICE,
    )
    .unwrap();
    assert_eq!(second.revision, 2);
    assert_eq!(second.intent.rules.iter().map(|rule| rule.position).collect::<Vec<_>>(), [0, 1, 2, 3, 4, 5]);
    assert_eq!(second.intent.rules[0].id, c.id);
    assert_eq!(second.intent.rules[0].note, "moved up");
    assert_eq!(second.intent.rules[2].id, a.id);
    assert_eq!(second.intent.rules[4].id, b.id);
    assert_ne!(second.intent.rules[1].id, a.id);
    assert_ne!(second.intent.rules[1].id, b.id);
    assert_ne!(second.intent.rules[1].id, c.id);
    assert_ne!(second.intent.rules[3].id, foreign.intent.rules[0].id);
    assert_ne!(second.intent.rules[5].id, b.id);
    assert_eq!(
        store::get(&connection, "n1", "mieru", LANE_SERVICE).unwrap().unwrap().intent.rules[0].id,
        foreign.intent.rules[0].id
    );
}

#[test]
fn delete_cascades_rules() {
    let (_scratch, database) = database("delete-cascade");
    let connection = database.connect().unwrap();
    let policy = store::upsert(
        &connection,
        "local",
        "naive",
        &input(vec![rule(Action::Block, json!({"domains": ["a.com"]}))]),
        None,
        0,
        LANE_SERVICE,
    )
    .unwrap();
    store::record_apply(&connection, &policy.id, &ApplyRecord::new(1, Some("d"), "naive_native", "applied"), 0)
        .unwrap();
    store::delete(&connection, &policy.id).unwrap();
    assert_eq!(count(&connection, "routing_rules"), 0);
    assert_eq!(count(&connection, "routing_applies"), 0);
    assert!(matches!(store::delete(&connection, &policy.id), Err(StoreError::NotFound(_))));
    store::upsert(
        &connection,
        "n1",
        "naive",
        &input(vec![rule(Action::Block, json!({"domains": ["a.com"]}))]),
        None,
        0,
        LANE_SERVICE,
    )
    .unwrap();
    connection.execute("DELETE FROM fleet_nodes WHERE node_id='n1'", []).unwrap();
    assert_eq!(count(&connection, "routing_policies"), 0);
    assert_eq!(count(&connection, "routing_rules"), 0);
}

#[test]
fn mark_and_history_limit() {
    let (_scratch, database) = database("mark-history");
    let connection = database.connect().unwrap();
    let policy = store::upsert(&connection, "local", "naive", &PolicyInput::default(), None, 0, LANE_SERVICE).unwrap();
    for index in 0..60 {
        let digest = format!("d{index}");
        let mut record =
            ApplyRecord::new(index, Some(&digest), "naive_native", if index % 2 == 0 { "applied" } else { "failed" });
        record.actor = "owner";
        record.runtime_version = Some("2.11.4");
        store::record_apply(&connection, &policy.id, &record, index).unwrap();
    }
    store::mark(
        &connection,
        &policy.id,
        PolicyState::Applied,
        Mark { applied_revision: Some(1), applied_digest: Some("d1".into()), ..Mark::default() },
        99,
    )
    .unwrap();
    let marked = store::get_by_id(&connection, &policy.id).unwrap();
    assert_eq!(marked.state, PolicyState::Applied);
    assert_eq!(marked.applied_revision, Some(1));
    assert_eq!(marked.applied_digest.as_deref(), Some("d1"));
    assert_eq!(marked.applied_at, Some(99));
    assert!(marked.applied_current());
    store::mark(
        &connection,
        &policy.id,
        PolicyState::Failed,
        Mark { last_error: Some("egress_unreachable".into()), ..Mark::default() },
        100,
    )
    .unwrap();
    let failed = store::get_by_id(&connection, &policy.id).unwrap();
    assert_eq!(failed.state, PolicyState::Failed);
    assert_eq!(failed.last_error.as_deref(), Some("egress_unreachable"));
    assert_eq!(failed.applied_revision, Some(1));
    assert!(!failed.applied_current());
    let history = store::history(&connection, &policy.id, store::HISTORY_LIMIT).unwrap();
    assert_eq!(history.len(), 50);
    assert_eq!(history[0]["revision"], 59);
    assert_eq!(history[49]["revision"], 10);
    assert_eq!(history[0]["actor"], "owner");
    assert_eq!(history[0]["runtime_version"], "2.11.4");
    assert_eq!(store::history(&connection, &policy.id, 2).unwrap()[1]["outcome"], "applied");
    assert_eq!(store::last_applied(&connection, &policy.id).unwrap().unwrap()["revision"], 56);
    assert!(store::record_apply(&connection, &policy.id, &ApplyRecord::new(1, Some("d"), "naive_native", "bogus"), 0,)
        .is_err());
}

#[test]
fn routing_v14_on_populated_db() {
    let scratch = Scratch::new("migration-14");
    let database = scratch.database();
    assert_eq!(apply(&database, &MIGRATIONS[..13]).unwrap(), (1..=13).collect::<Vec<_>>());
    let connection = database.connect().unwrap();
    connection
        .execute(
            "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at,kind) \
         VALUES('n1','Node','pending','{}',1,1,'remote')",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO managed_resources(protocol,runtime_username,ref,generation,state,updated_at) \
         VALUES('naive','alice','r1',1,'converged',1)",
            [],
        )
        .unwrap();
    connection.commit().unwrap();
    assert_eq!(apply_migrations(&database).unwrap(), (14..=26).collect::<Vec<_>>());
    assert!(apply_migrations(&database).unwrap().is_empty());
    assert_eq!(count(&connection, "managed_resources"), 1);
    let mut statement = connection.prepare("SELECT name FROM sqlite_master WHERE type='table'").unwrap();
    let tables: BTreeSet<String> = statement.query_map([], |row| row.get(0)).unwrap().map(|row| row.unwrap()).collect();
    for table in ["routing_policies", "routing_rules", "routing_applies", "managed_egress"] {
        assert!(tables.contains(table), "missing {table}");
    }
    connection
        .execute(
            "INSERT INTO managed_egress(protocol,generation,revision,digest,state,updated_at) \
         VALUES('naive',3,'r','d','converged',1)",
            [],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                "INSERT INTO managed_egress(protocol,generation,state,updated_at) VALUES('socks',3,'converged',1)",
                [],
            )
            .is_err()
    );
    assert!(connection
        .execute(
            "INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at) \
         VALUES('p','ghost','naive','naive_native','direct','fail_closed',1,1)",
            [],
        )
        .is_err());
    let policy = store::upsert(&connection, "n1", "naive", &PolicyInput::default(), None, 0, LANE_SERVICE).unwrap();
    assert!(connection
        .execute(
            "INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,fallback,created_at,updated_at) \
         VALUES('p2','n1','naive','naive_native','direct','fail_closed',1,1)",
            [],
        )
        .is_err());
    assert_ne!(policy.id, "p2");
}
