//! The model parts of `panel/tests/test_routing_ir.py` and `test_routing_lanes_models.py`, and the
//! model tests of `test_routing_presets.py` and `test_xray_routing_compiler.py`. (The compiler and
//! store tests of those files belong to WP10.)

use serde_json::{json, Value};

use super::*;

fn rule(
    action: &str,
    domains: &[&str],
    cidrs: &[&str],
    ports: Value,
    egress: Option<&str>,
) -> Result<RoutingRule, crate::ValidationError> {
    RoutingRule::validate(&json!({"action": action, "egress": egress,
                                  "match": {"domains": domains, "cidrs": cidrs, "ports": ports}}))
}

fn block(domains: &[&str]) -> Value {
    json!({"action": "block", "match": {"domains": domains}})
}

const GUID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GUID_C: &str = "cccccccccccccccccccccccccccccccc";

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
        assert!(RuleMatch::validate(&bad).is_err(), "{bad}");
    }
}

#[test]
fn rule_match_rejects_empty() {
    assert!(RuleMatch::validate(&json!({})).is_err());
    assert_eq!(RuleMatch::validate(&json!({"ports": [443]})).unwrap().ports, [Port::One(443)]);
}

#[test]
fn egress_required_for_egress_action_only() {
    assert!(rule("egress", &[], &[], json!([]), None).is_err());
    assert!(rule("block", &["a.com"], &[], json!([]), Some("warp")).is_err());
    assert_eq!(rule("egress", &["a.com"], &[], json!([]), Some("warp")).unwrap().egress.as_deref(), Some("warp"));
    assert!(PolicyInput::validate(&json!({"default_action": "egress"})).is_err());
    assert!(PolicyInput::validate(&json!({"default_action": "direct", "default_egress": "warp"})).is_err());
    assert!(PolicyInput::validate(&json!({"default_action": "egress", "default_egress": "tor"})).is_err());
}

#[test]
fn policy_limits() {
    let rules = vec![block(&["a.com"]); MAX_RULES];
    assert_eq!(PolicyInput::validate(&json!({"rules": rules})).unwrap().intent.rules.len(), MAX_RULES);
    let rules = vec![block(&["a.com"]); MAX_RULES + 1];
    assert!(PolicyInput::validate(&json!({"rules": rules})).is_err());
    let domains: Vec<String> = (0..65).map(|i| format!("h{i}.com")).collect();
    assert!(RuleMatch::validate(&json!({"domains": domains})).is_err());
    let cidrs: Vec<String> = (0..65).map(|i| format!("10.0.{i}.0/24")).collect();
    assert!(RuleMatch::validate(&json!({"cidrs": cidrs})).is_err());
    let ports: Vec<i64> = (1..34).collect();
    assert!(RuleMatch::validate(&json!({"domains": ["a.com"], "ports": ports})).is_err());
    assert!(RoutingRule::validate(
        &json!({"action": "block", "match": {"domains": ["a.com"]}, "note": "x".repeat(121)})
    )
    .is_err());
}

#[test]
fn policy_input_ignores_server_fields() {
    let rule_id = format!("{}-0000-4000-8000-{}", "0".repeat(8), "0".repeat(12));
    let mut policy = RoutingPolicy::validate(&json!({
        "id": "p1", "node_id": "local", "protocol": "naive", "backend": "naive_native", "revision": 7,
        "rules": [{"id": rule_id, "action": "block", "match": {"domains": ["a.com"]}}],
    }))
    .unwrap();
    policy.state = PolicyState::Applied;
    policy.applied_revision = Some(7);
    policy.applied_digest = Some("d".into());
    let draft = PolicyInput::from_policy(&policy);
    let keys: Vec<String> = draft.dump().as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["default_action", "default_egress", "fallback", "rules", "backend"]);
    assert_eq!(draft.intent.rules[0].id, policy.intent.rules[0].id);
    assert!(PolicyInput::validate(&json!({"revision": 3})).is_err());
    assert!(PolicyInput::validate(&json!({"state": "applied"})).is_err());
    assert!(policy.applied_current());
}

/// `test_routing_lanes_models.py`.
#[test]
fn an_exit_is_warp_or_a_chain_of_nodes_with_the_last_hops_exit() {
    assert_eq!(normalise_exit("warp").unwrap(), "warp");
    assert_eq!(normalise_exit(&format!("node:{GUID_B}")).unwrap(), format!("node:{GUID_B}"));
    assert_eq!(normalise_exit(&format!("NODE:{GUID_B}:WARP")).unwrap(), format!("node:{GUID_B}:warp"));
    assert_eq!(
        normalise_exit(&format!("node:{GUID_B},{GUID_C}:warp")).unwrap(),
        format!("node:{GUID_B},{GUID_C}:warp")
    );
    assert_eq!(exit_hops(Some("warp")), (Vec::new(), None));
    assert_eq!(exit_hops(Some(&format!("node:{GUID_B}"))), (vec![GUID_B.to_string()], Some("direct")));
    assert_eq!(
        exit_hops(Some(&format!("node:{GUID_B},{GUID_C}:warp"))),
        (vec![GUID_B.to_string(), GUID_C.to_string()], Some("warp"))
    );
    assert!(is_node_exit(&format!("node:{GUID_B}")) && !is_node_exit("warp"));
    let four = format!("node:{GUID_B},{GUID_C},{},{}", "d".repeat(32), "e".repeat(32));
    for bad in [
        "direct".to_string(),
        "node:".into(),
        "node:has space".into(),
        format!("node:{GUID_B}:direct"),
        format!("node:{GUID_B},{GUID_B}"),
        four,
        "socks5://x".into(),
        String::new(),
    ] {
        assert!(normalise_exit(&bad).is_err(), "{bad}");
    }
}

#[test]
fn rules_and_defaults_accept_node_exits_and_refuse_the_rest() {
    let egress_rule = |egress: &str, action: &str| {
        RoutingRule::validate(&json!({"match": {"domains": ["a.example"]}, "action": action, "egress": egress}))
    };
    let first = egress_rule(&format!("node:{GUID_B}:warp"), "egress").unwrap();
    assert_eq!(first.egress, Some(format!("node:{GUID_B}:warp")));
    assert_eq!(first.action, Action::Egress);
    let policy = PolicyInput::validate(&json!({
        "default_action": "egress", "default_egress": format!("node:{GUID_B},{GUID_C}"),
        "rules": [first.dump(), egress_rule("warp", "egress").unwrap().dump()],
    }))
    .unwrap();
    assert_eq!(policy.intent.default_egress, Some(format!("node:{GUID_B},{GUID_C}")));
    assert_eq!(
        policy.intent.exits(),
        [format!("node:{GUID_B},{GUID_C}"), format!("node:{GUID_B}:warp"), "warp".into()]
    );
    assert_eq!(policy.intent.node_exits(), [format!("node:{GUID_B},{GUID_C}"), format!("node:{GUID_B}:warp")]);
    assert!(egress_rule("node:nope!", "egress").is_err());
    assert!(PolicyInput::validate(&json!({"default_action": "egress", "default_egress": "direct"})).is_err());
    assert!(egress_rule("warp", "direct").is_err());
}

/// `test_routing_presets.py::test_a_rule_may_stand_on_the_sniffed_protocol_alone_and_carries_its_preset`.
#[test]
fn a_rule_may_stand_on_the_sniffed_protocol_alone_and_carries_its_preset() {
    let torrent =
        RoutingRule::validate(&json!({"match": {"protocols": ["bittorrent"]}, "action": "block", "preset": "torrent"}))
            .unwrap();
    assert_eq!(torrent.matcher.protocols, ["bittorrent"]);
    assert_eq!(torrent.preset.as_deref(), Some("torrent"));
    assert_eq!(torrent.action, Action::Block);
    assert_eq!(
        RuleMatch::validate(&json!({"protocols": [" TLS ", "http", "tls"]})).unwrap().protocols,
        ["tls", "http"]
    );
    let error = RuleMatch::validate(&json!({"protocols": ["ssh"]})).unwrap_err();
    assert!(error.to_string().contains("invalid protocol selector"));
    let error =
        RoutingRule::validate(&json!({"match": {"domains": ["x.com"]}, "action": "block", "preset": "Bad Name"}))
            .unwrap_err();
    assert!(error.to_string().contains("invalid preset name"));
    let cleared =
        RoutingRule::validate(&json!({"match": {"domains": ["x.com"]}, "action": "block", "preset": ""})).unwrap();
    assert_eq!(cleared.preset, None);
    assert_eq!(COMPILER_VERSION, "3");
}

/// `test_xray_routing_compiler.py::test_rule_match_geo_codes_normalised_and_private_rejected`.
#[test]
fn rule_match_geo_codes_normalised_and_private_rejected() {
    let matcher = RuleMatch::validate(&json!({
        "geosites": ["geosite:Category-Ads-All", "category-ads-all", "cn"], "geoips": ["GeoIP:CN", "cloudflare"],
    }))
    .unwrap();
    assert_eq!(matcher.geosites, ["category-ads-all", "cn"]);
    assert_eq!(matcher.geoips, ["cn", "cloudflare"]);
    assert!(RuleMatch::validate(&json!({"geoips": ["private"]})).unwrap_err().to_string().contains("bypass"));
    assert!(RuleMatch::validate(&json!({"geosites": ["not a code"]})).is_err());
    assert!(matcher.selectors());
}

/// `test_xray_routing_compiler.py::test_rule_match_ports_only_is_allowed_and_empty_is_not`.
#[test]
fn rule_match_ports_only_is_allowed_and_empty_is_not() {
    let matcher = RuleMatch::validate(&json!({"ports": [25, "80-90"]})).unwrap();
    assert_eq!(matcher.ports, [Port::One(25), Port::Range("80-90".into())]);
    assert!(!matcher.selectors());
    assert!(RuleMatch::validate(&json!({})).is_err());
}

/// `test_xray_routing_compiler.py::test_backend_accepts_xray_router_and_backends_for`.
#[test]
fn backend_accepts_xray_router_and_backends_for() {
    assert_eq!(backends_for("naive"), [Backend::NaiveNative, Backend::XrayRouter]);
    assert_eq!(backends_for("mieru"), [Backend::MieruNative, Backend::XrayRouter]);
    assert_eq!(backends_for("mtproxy"), [Backend::MtproxyNative, Backend::XrayRouter]);
    assert_eq!(PolicyInput::validate(&json!({"backend": "xray_router"})).unwrap().backend, Some(Backend::XrayRouter));
    assert!(PolicyInput::validate(&json!({"backend": "sing_box"})).is_err());
}

#[test]
fn lanes_are_the_service_or_a_grant() {
    assert_eq!(normalise_lane(None).unwrap(), LANE_SERVICE);
    assert_eq!(normalise_lane(Some("")).unwrap(), LANE_SERVICE);
    assert_eq!(normalise_lane(Some("grant:g1")).unwrap(), "grant:g1");
    assert!(normalise_lane(Some("grant:a b")).is_err());
}

#[test]
fn extended_request_bodies_add_their_own_fields() {
    // How WP10's `PolicyPut` (the intent plus `expected_revision`) composes the policy input.
    let extended = |input: Value| {
        let mut cx = Cx::new(crate::validate::Entry::Body);
        let result = PolicyInput::validate_extended(&input, &[], &mut cx, "PolicyPut", |fields, cx| {
            fields.optional(
                cx,
                "expected_revision",
                || None,
                |v, l, cx| nullable(v, l, cx, |v, l, cx| Int::LAX.validate(v, l, cx)),
            )
        });
        (result, cx.into_issues())
    };
    let (ok, issues) = extended(json!({"default_action": "egress", "default_egress": "warp", "expected_revision": 3}));
    assert!(issues.is_empty());
    let (policy, expected) = ok.unwrap();
    assert_eq!(expected, Some(Some(3)));
    assert_eq!(policy.intent.default_egress.as_deref(), Some("warp"));
    let (failed, issues) = extended(json!({"expected_revision": "x", "unknown": 1}));
    assert!(failed.is_none());
    let kinds: Vec<&str> = issues.iter().map(|issue| issue.kind.as_str()).collect();
    assert_eq!(kinds, ["int_parsing", "extra_forbidden"]);
}
