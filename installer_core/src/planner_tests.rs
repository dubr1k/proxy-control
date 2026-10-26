//! Ported from `tests/test_installer_plan.py` and `tests/test_installer_profiles.py`.

use std::collections::BTreeMap;

use super::*;
use crate::model::*;

fn config() -> InstallerConfig {
    InstallerConfig {
        schema: 1,
        host_mode: HostMode::Fresh,
        profile: Profile::Core,
        acme_email: "admin@example.com".into(),
        initial_user: "owner".into(),
        domains: DomainConfig::new("panel.example.com", "relay.example.com"),
        mieru: None,
        three_xui: ThreeXuiConfig::new(ThreeXuiMode::None),
        firewall: FirewallConfig { manage_ufw: false },
        egress: None,
        ingress: None,
        amneziawg: None,
        trusttunnel: None,
    }
}

fn map(items: Vec<(&str, Fact)>) -> Fact {
    Fact::Map(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn s(text: &str) -> Fact {
    Fact::Str(text.into())
}

fn facts_with(free_ports: Vec<i64>, topology: Fact, transient: Fact) -> AuditFacts {
    AuditFacts::from_groups(
        map(vec![("os", s("ubuntu")), ("version", s("24.04")), ("arch", s("arm64"))]),
        map(vec![
            ("free_ports", Fact::Set(free_ports.into_iter().map(Fact::Int).collect())),
            ("owners", map(vec![("443", s("nginx")), ("22", s("sshd"))])),
        ]),
        map(vec![("/etc/nginx/nginx.conf", s("foreign"))]),
        topology,
        map(vec![("dns", Fact::Set(vec![s("relay.example.com"), s("panel.example.com")]))]),
        transient,
    )
    .unwrap()
}

fn default_topology() -> Fact {
    map(vec![
        ("systemd_units", Fact::Set(vec![s("ssh.service"), s("nginx.service")])),
        ("nginx_stream", map(vec![("includes", Fact::List(vec![s("/etc/nginx/streams-enabled/*")]))])),
    ])
}

fn facts() -> AuditFacts {
    facts_with(
        vec![443, 8443],
        default_topology(),
        map(vec![("scan_sequence", Fact::List(vec![Fact::Int(1), Fact::Int(2)])), ("elapsed_ms", Fact::Int(17))]),
    )
}

fn release() -> ReleaseIdentity {
    ReleaseIdentity::new(
        "v1.2.3",
        "0123456789abcdef",
        &"a".repeat(64),
        BTreeMap::from([("proxy-control".into(), "1.2.3".into()), ("nginx".into(), "1.26.3".into())]),
        BTreeMap::from([("proxy-control-arm64.tar.gz".into(), "b".repeat(64))]),
    )
    .unwrap()
}

fn action(id: &str, adapter: &str, mutation: Option<&str>) -> Result<Action> {
    Action::new(
        id,
        adapter,
        &format!("proxy-control:{adapter}"),
        vec![mutation.map(str::to_string).unwrap_or_else(|| format!("create {adapter} state"))],
        vec![format!("{adapter} state is absent")],
        vec![format!("{adapter} state is healthy")],
        vec![format!("remove {adapter} state")],
        mutation.is_some(),
    )
}

struct FakeAdapter {
    name: String,
    requires: Vec<String>,
    action_id: Option<String>,
    leaked: Option<String>,
}

fn fake(name: &str, requires: &[&str]) -> FakeAdapter {
    FakeAdapter {
        name: name.into(),
        requires: requires.iter().map(|r| r.to_string()).collect(),
        action_id: None,
        leaked: None,
    }
}

impl PlanAdapter for FakeAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn requires(&self) -> Vec<String> {
        self.requires.clone()
    }

    fn plan(&self, _config: &InstallerConfig, _facts: &AuditFacts) -> Result<Vec<Action>> {
        let id = self.action_id.clone().unwrap_or_else(|| format!("{}.install", self.name));
        Ok(vec![action(&id, &self.name, self.leaked.as_deref())?])
    }
}

fn adapters(reverse: bool) -> Vec<FakeAdapter> {
    let mut values = vec![fake("nginx", &["packages"]), fake("packages", &[]), fake("core", &["nginx"])];
    if reverse {
        values.reverse();
    }
    values
}

fn refs(adapters: &[FakeAdapter]) -> Vec<&dyn PlanAdapter> {
    adapters.iter().map(|a| a as &dyn PlanAdapter).collect()
}

#[test]
fn equivalent_unordered_inputs_have_identical_plan_bytes_and_digest() {
    let first = build_plan(&config(), &facts(), &refs(&adapters(false)), &release()).unwrap();
    let reversed_topology = map(vec![
        ("nginx_stream", map(vec![("includes", Fact::List(vec![s("/etc/nginx/streams-enabled/*")]))])),
        ("systemd_units", Fact::Set(vec![s("nginx.service"), s("ssh.service")])),
    ]);
    let reversed = facts_with(
        vec![8443, 443],
        reversed_topology,
        map(vec![("elapsed_ms", Fact::Int(17)), ("scan_sequence", Fact::List(vec![Fact::Int(1), Fact::Int(2)]))]),
    );
    let second = build_plan(&config(), &reversed, &refs(&adapters(true)), &release()).unwrap();
    assert_eq!(first.to_canonical_json(), second.to_canonical_json());
    assert_eq!(first.digest(), second.digest());
    assert!(first.to_canonical_json().starts_with("{\"actions\":"));
    assert!(!first.to_canonical_json().to_lowercase().contains("password"));
}

#[test]
fn transient_audit_facts_do_not_affect_plan_or_freshness() {
    let initial = facts();
    let mut current = initial.clone();
    current.transient = serde_json::from_str(r#"{"elapsed_ms": 999, "scan_sequence": [9, 8, 7]}"#).unwrap();
    let first = build_plan(&config(), &initial, &refs(&adapters(false)), &release()).unwrap();
    let second = build_plan(&config(), &current, &refs(&adapters(false)), &release()).unwrap();
    assert_eq!(first.to_canonical_json(), second.to_canonical_json());
    assert_eq!(first.digest(), second.digest());
    first.assert_fresh(&current).unwrap();
}

#[test]
fn apply_rejects_changed_relevant_fact() {
    let plan = build_plan(
        &config(),
        &facts_with(vec![8443], default_topology(), map(vec![])),
        &refs(&adapters(false)),
        &release(),
    )
    .unwrap();
    let err = plan.assert_fresh(&facts_with(vec![], default_topology(), map(vec![]))).unwrap_err();
    assert!(err.is_stale());
    assert_eq!(err.message(), "listener facts changed");
}

#[test]
fn adapter_dependencies_are_topologically_sorted_in_declared_order() {
    let unordered = vec![
        fake("core", &["nginx", "firewall"]),
        fake("nginx", &["packages"]),
        fake("packages", &[]),
        fake("firewall", &["packages"]),
    ];
    let plan = build_plan(&config(), &facts(), &refs(&unordered), &release()).unwrap();
    assert_eq!(plan.adapter_order, vec!["packages", "nginx", "firewall", "core"]);
    assert_eq!(plan.actions.iter().map(|a| a.adapter.clone()).collect::<Vec<_>>(), plan.adapter_order);
    let reordered: Vec<&dyn PlanAdapter> = vec![&unordered[2], &unordered[3], &unordered[1], &unordered[0]];
    assert_eq!(
        build_plan(&config(), &facts(), &reordered, &release()).unwrap().adapter_order,
        vec!["packages", "firewall", "nginx", "core"]
    );
}

#[test]
fn adapter_dependency_cycle_fails_closed() {
    let cyclic = vec![fake("first", &["second"]), fake("second", &["first"])];
    let err = build_plan(&config(), &facts(), &refs(&cyclic), &release()).unwrap_err();
    assert_eq!(err.message(), "adapter dependency cycle: first, second");
}

#[test]
fn missing_adapter_dependency_fails_closed() {
    let err = build_plan(&config(), &facts(), &refs(&[fake("core", &["nginx"])]), &release()).unwrap_err();
    assert_eq!(err.message(), "adapter core requires missing adapter: nginx");
}

#[test]
fn duplicate_action_ids_fail_closed() {
    let mut first = fake("first", &[]);
    first.action_id = Some("shared.install".into());
    let mut second = fake("second", &[]);
    second.action_id = Some("shared.install".into());
    let err = build_plan(&config(), &facts(), &refs(&[first, second]), &release()).unwrap_err();
    assert_eq!(err.message(), "duplicate action id: shared.install");
}

#[test]
fn action_declares_transaction_and_credential_metadata() {
    let plan = build_plan(&config(), &facts(), &refs(&[fake("packages", &[])]), &release()).unwrap();
    let planned = &plan.actions[0];
    assert_eq!(planned.owner, "proxy-control:packages");
    assert_eq!(planned.mutations, vec!["create packages state"]);
    assert_eq!(planned.preconditions, vec!["packages state is absent"]);
    assert_eq!(planned.verification, vec!["packages state is healthy"]);
    assert_eq!(planned.inverse, vec!["remove packages state"]);
    assert!(!planned.credentials_required);
}

fn leaking(mutation: &str) -> Result<InstallPlan> {
    let mut adapter = fake("packages", &[]);
    adapter.leaked = Some(mutation.into());
    build_plan(&config(), &facts(), &refs(&[adapter]), &release())
}

#[test]
fn secret_assignment_is_rejected_before_canonical_serialization() {
    assert_eq!(
        leaking("write password=hunter2").unwrap_err().message(),
        "secret material is forbidden at plan.mutations[0]"
    );
}

#[test]
fn reordered_topology_rules_make_plan_stale() {
    let rules = |items: [&str; 2]| map(vec![("nginx_rules", Fact::List(items.iter().map(|i| s(i)).collect()))]);
    let planned = facts_with(vec![443, 8443], rules(["route-a", "route-b"]), map(vec![]));
    let reordered = facts_with(vec![443, 8443], rules(["route-b", "route-a"]), map(vec![]));
    let plan = build_plan(&config(), &planned, &refs(&adapters(false)), &release()).unwrap();
    assert_eq!(plan.assert_fresh(&reordered).unwrap_err().message(), "topology facts changed");
}

#[test]
fn secret_flag_and_quoted_key_forms_are_rejected() {
    for mutation in ["bootstrap --password hunter2", "write settings {\"token\":\"abc\"}"] {
        assert!(leaking(mutation).unwrap_err().message().starts_with("secret material"), "{mutation}");
    }
}

#[test]
fn secret_words_in_innocent_prose_are_allowed() {
    leaking("verify the password login mechanism is disabled").unwrap();
}

#[test]
fn action_operation_fields_reject_scalar_strings() {
    for field in ["mutations", "preconditions", "verification", "inverse"] {
        let mut value = action("packages.install", "packages", None).unwrap().to_value();
        value[field] = serde_json::json!("not-a-sequence-of-operations");
        let err = Action::from_value(&value).unwrap_err();
        assert_eq!(err.message(), format!("action packages.install {field} must be a non-string sequence"));
    }
}

#[test]
fn nonfinite_stable_audit_facts_are_rejected() {
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let err = AuditFacts::from_groups(
            map(vec![]),
            map(vec![]),
            map(vec![]),
            map(vec![("capacity_ratio", Fact::Float(value))]),
            map(vec![]),
            map(vec![]),
        )
        .unwrap_err();
        assert_eq!(err.message(), "non-finite float is forbidden in canonical data");
    }
}

#[test]
fn nonfinite_adapter_evidence_is_rejected() {
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let err = Evidence::new(
            "packages.install",
            true,
            vec!["checked".into()],
            map(vec![("capacity_ratio", Fact::Float(value))]),
        )
        .unwrap_err();
        assert_eq!(err.message(), "non-finite float is forbidden in canonical data");
    }
}

#[test]
fn evidence_details_reject_non_mapping_values() {
    let err = Evidence::new("packages.install", true, vec!["healthy".into()], Fact::List(vec![s("not")])).unwrap_err();
    assert_eq!(err.message(), "evidence details must be a mapping");
}

#[test]
fn evidence_normalizes_valid_observations_and_freezes_details() {
    let evidence = Evidence::new(
        "packages.install",
        true,
        vec!["healthy".into()],
        map(vec![("checks", Fact::List(vec![s("listener"), s("service")]))]),
    )
    .unwrap();
    assert_eq!(evidence.observations, vec!["healthy"]);
    assert_eq!(evidence.details["checks"], serde_json::json!(["listener", "service"]));
}

#[test]
fn sets_are_ordered_by_their_compact_json_text() {
    let set =
        Fact::Set(vec![Fact::Int(9), Fact::Int(10), s("10"), s("9"), Fact::Int(100), Fact::Null, Fact::Bool(true)]);
    assert_eq!(pc_host::json::canonical(&set.canonical().unwrap()), r#"["10","9",10,100,9,null,true]"#);
}

#[test]
fn stored_plans_are_read_back_strictly() {
    let plan = build_plan(&config(), &facts(), &refs(&adapters(false)), &release()).unwrap();
    let again = InstallPlan::from_json(plan.to_canonical_json().as_bytes()).unwrap();
    assert_eq!(again.digest(), plan.digest());
    let mut value = plan.canonical_value();
    value.as_object_mut().unwrap().insert("extra".into(), serde_json::json!(1));
    assert!(InstallPlan::from_value(&value).is_err());
    let mut value = plan.canonical_value();
    value["schema"] = serde_json::json!(2);
    assert_eq!(InstallPlan::from_value(&value).unwrap_err().message(), "unsupported plan schema: 2");
    let mut value = plan.canonical_value();
    value["audit_facts"]["ownership"]["api_token_file"] = serde_json::json!("/x");
    assert_eq!(
        InstallPlan::from_value(&value).unwrap_err().message(),
        "secret field is forbidden at plan.audit_facts.ownership.api_token_file"
    );
}

// --- tests/test_installer_profiles.py ---

fn config_for(profile: Profile, three_xui: ThreeXuiMode, host_mode: HostMode, manage_ufw: bool) -> InstallerConfig {
    let mut domains = DomainConfig::new("panel.example.com", "proxy.example.com");
    let mut mieru = None;
    if profile.includes_naive() {
        domains.naive = Some("naive.example.com".into());
    }
    if profile.includes_mieru() {
        domains.mieru = Some("mieru.example.com".into());
        mieru = Some(MieruConfig { tcp_ports: vec![46001], udp_ports: vec![46002], lane_slots: 0 });
    }
    let mut xui = ThreeXuiConfig::new(three_xui);
    match three_xui {
        ThreeXuiMode::ManagedNew => {
            xui.panel_domain = Some("xui.example.com".into());
            xui.vless_tcp_domain = Some("vless.example.com".into());
            xui.vless_xhttp_domain = Some("xhttp.example.com".into());
            xui.hysteria_domain = Some("hysteria.example.com".into());
        }
        ThreeXuiMode::Existing => xui.vless_tcp_domain = Some("vless.example.com".into()),
        ThreeXuiMode::None => {}
    }
    InstallerConfig {
        schema: 1,
        host_mode,
        profile,
        acme_email: "ops@example.com".into(),
        initial_user: "owner".into(),
        domains,
        mieru,
        three_xui: xui,
        firewall: FirewallConfig { manage_ufw },
        egress: None,
        ingress: None,
        amneziawg: None,
        trusttunnel: None,
    }
}

fn basic(profile: Profile, xui: ThreeXuiMode) -> InstallerConfig {
    config_for(profile, xui, HostMode::Fresh, true)
}

#[test]
fn profile_selects_exact_adapters() {
    let base = ["packages", "nginx", "firewall", "certificates", "core"];
    let matrix: [(Profile, ThreeXuiMode, &[&str]); 6] = [
        (Profile::Core, ThreeXuiMode::None, &["version_agent"]),
        (Profile::CoreNaive, ThreeXuiMode::None, &["naive", "version_agent"]),
        (Profile::CoreMieru, ThreeXuiMode::None, &["mieru", "version_agent"]),
        (Profile::Full, ThreeXuiMode::None, &["naive", "mieru", "version_agent"]),
        (Profile::Core, ThreeXuiMode::Existing, &["three_xui", "version_agent"]),
        (Profile::Full, ThreeXuiMode::Existing, &["naive", "mieru", "three_xui", "version_agent"]),
    ];
    for (profile, xui, tail) in matrix {
        let expected: Vec<&str> = base.iter().chain(tail.iter()).copied().collect();
        assert_eq!(adapters_for(&basic(profile, xui)).unwrap(), expected);
    }
}

#[test]
fn firewall_is_selected_only_for_a_managed_fresh_host() {
    assert!(adapters_for(&basic(Profile::Core, ThreeXuiMode::None)).unwrap().contains(&"firewall"));
    assert!(!adapters_for(&config_for(Profile::Core, ThreeXuiMode::None, HostMode::Coexist, true))
        .unwrap()
        .contains(&"firewall"));
    assert!(!adapters_for(&config_for(Profile::Core, ThreeXuiMode::None, HostMode::Fresh, false))
        .unwrap()
        .contains(&"firewall"));
}

#[test]
fn profile_order_is_the_documented_installation_order() {
    assert_eq!(
        adapters_for(&basic(Profile::Full, ThreeXuiMode::Existing)).unwrap(),
        vec!["packages", "nginx", "firewall", "certificates", "core", "naive", "mieru", "three_xui", "version_agent"]
    );
}

#[test]
fn selection_rejects_a_naive_profile_without_a_domain() {
    let mut broken = basic(Profile::CoreNaive, ThreeXuiMode::None);
    broken.domains = DomainConfig::new("panel.example.com", "proxy.example.com");
    assert!(adapters_for(&broken).unwrap_err().message().contains("NaiveProxy domain"));
}

#[test]
fn selection_rejects_a_mieru_profile_without_listeners() {
    let mut broken = basic(Profile::CoreMieru, ThreeXuiMode::None);
    broken.mieru = None;
    assert!(adapters_for(&broken).unwrap_err().message().contains("Mieru listeners"));
}

#[test]
fn selection_rejects_mieru_listeners_outside_a_mieru_profile() {
    let mut broken = basic(Profile::Core, ThreeXuiMode::None);
    broken.mieru = Some(MieruConfig { tcp_ports: vec![46001], udp_ports: vec![], lane_slots: 0 });
    assert!(adapters_for(&broken).unwrap_err().message().contains("outside a Mieru profile"));
}

#[test]
fn selection_rejects_managed_three_xui_on_a_coexisting_host() {
    let broken = config_for(Profile::Core, ThreeXuiMode::ManagedNew, HostMode::Coexist, true);
    assert!(adapters_for(&broken).unwrap_err().message().contains("fresh host"));
}

#[test]
fn every_selected_adapter_declares_satisfiable_dependencies() {
    let mut available: Vec<&str> = Vec::new();
    for name in adapters_for(&basic(Profile::Full, ThreeXuiMode::Existing)).unwrap() {
        for requirement in adapter_requires(name) {
            assert!(available.contains(requirement), "{name}");
        }
        available.push(name);
    }
    for name in ADAPTER_NAMES {
        assert!(PROFILE_ORDER.contains(&name));
    }
}

#[test]
fn adapters_for_includes_xray_router_after_warp() {
    let base = basic(Profile::Full, ThreeXuiMode::None);
    let mut routed = base.clone();
    routed.egress = Some(EgressConfig {
        warp: true,
        router: true,
        naive: EgressChoice::Router,
        mieru: EgressChoice::Warp,
        ..Default::default()
    });
    assert_eq!(
        adapters_for(&routed).unwrap(),
        vec![
            "packages",
            "nginx",
            "firewall",
            "certificates",
            "core",
            "warp",
            "xray_router",
            "naive",
            "mieru",
            "version_agent"
        ]
    );
    let mut only_router = base.clone();
    only_router.egress = Some(EgressConfig { router: true, naive: EgressChoice::Router, ..Default::default() });
    assert_eq!(
        adapters_for(&only_router).unwrap(),
        vec!["packages", "nginx", "firewall", "certificates", "core", "xray_router", "naive", "mieru", "version_agent"]
    );
    assert!(!adapters_for(&base).unwrap().contains(&"xray_router"));
}

#[test]
fn the_mcp_adapter_is_selected_only_with_its_domain_and_sits_before_the_agent() {
    let base = basic(Profile::Full, ThreeXuiMode::None);
    assert!(!adapters_for(&base).unwrap().contains(&"mcp"));
    assert!(!compose_file_list(&base).contains(&"compose.mcp.yaml"));
    let mut central = base.clone();
    central.domains.mcp = Some("mcp.example.com".into());
    assert_eq!(
        adapters_for(&central).unwrap(),
        vec!["packages", "nginx", "firewall", "certificates", "core", "naive", "mieru", "mcp", "version_agent"]
    );
    assert_eq!(
        compose_file_list(&central),
        vec!["compose.yaml", "compose.naive.yaml", "compose.mieru.yaml", "compose.mcp.yaml"]
    );
    let mut core = basic(Profile::Core, ThreeXuiMode::None);
    core.domains = DomainConfig {
        mcp: Some("mcp.example.com".into()),
        ..DomainConfig::new("panel.example.com", "relay.example.com")
    };
    let names = adapters_for(&core).unwrap();
    assert_eq!(&names[names.len() - 2..], &["mcp", "version_agent"]);
    assert_eq!(compose_file_list(&core), vec!["compose.yaml", "compose.mcp.yaml"]);
}

#[test]
fn compose_file_list_with_router() {
    let mut routed = basic(Profile::CoreNaive, ThreeXuiMode::None);
    routed.egress = Some(EgressConfig { router: true, ..Default::default() });
    assert_eq!(compose_file_list(&routed), vec!["compose.yaml", "compose.naive.yaml", "compose.xray-router.yaml"]);
}

#[test]
fn compose_file_list_is_canonical_per_profile() {
    assert_eq!(compose_file_list(&basic(Profile::Core, ThreeXuiMode::None)), vec!["compose.yaml"]);
    assert_eq!(
        compose_file_list(&basic(Profile::CoreNaive, ThreeXuiMode::None)),
        vec!["compose.yaml", "compose.naive.yaml"]
    );
    assert_eq!(
        compose_file_list(&basic(Profile::Full, ThreeXuiMode::None)),
        vec!["compose.yaml", "compose.naive.yaml", "compose.mieru.yaml"]
    );
}

#[test]
fn the_firewall_opens_its_ports_before_certificates_are_issued() {
    let order = adapters_for(&basic(Profile::Full, ThreeXuiMode::Existing)).unwrap();
    let position = |name: &str| order.iter().position(|n| *n == name).unwrap();
    assert!(position("firewall") < position("certificates"));
}

// ------------------------------------------------------------------------------------------
// Ported from the installer crate's former `plan.rs` (host WP2), now that the engine reads its
// journal plans through this module.
// ------------------------------------------------------------------------------------------

fn engine_action() -> Action {
    Action {
        id: "core.install".into(),
        adapter: "core".into(),
        owner: "proxy-control:core".into(),
        mutations: vec!["write /core.owned".into()],
        preconditions: vec!["/core.owned is absent".into()],
        verification: vec!["/core.owned has the approved content".into()],
        inverse: vec!["remove /core.owned".into()],
        credentials_required: false,
    }
}

#[test]
fn secret_assignments_follow_the_python_pattern() {
    use crate::secret::plan_text_has_secret;
    for text in [
        "--password=x",
        "--token abc",
        "--API-KEY  'a b'",
        "password: hunter2",
        "\"secret\" = \"x\"",
        "private_key=abc",
        "privatekey:1",
        "api key = z",
        "TOKEN=a",
        "my_token=a",
        "pa\u{17f}\u{17f}word=x",
    ] {
        assert!(plan_text_has_secret(text), "{text}");
    }
    for text in [
        "--password",
        "password:",
        "password: ,",
        "token=}",
        "token=]",
        "write /core.owned",
        "the token file is private",
        "secret",
        "privat key=x",
        "--tokens x",
    ] {
        assert!(!plan_text_has_secret(text), "{text}");
    }
}

#[test]
fn secret_keys_and_paths() {
    assert_eq!(
        assert_secret_free(&json!({"a": {"Api-Key": 1}}), "plan"),
        Err(PlanError::new("secret field is forbidden at plan.a.Api-Key"))
    );
    assert_eq!(
        assert_secret_free(&json!({"a": ["ok", "token=x"]}), "plan"),
        Err(PlanError::new("secret material is forbidden at plan.a[1]"))
    );
    assert!(assert_secret_free(&json!({"tokenless": false}), "plan").is_err());
    assert!(assert_secret_free(&json!({"owner": "x", "n": [1, null, true]}), "plan").is_ok());
}

#[test]
fn action_checks_match_post_init() {
    assert!(engine_action().checked().is_ok());
    let mut bad = engine_action();
    bad.owner = "  ".into();
    assert_eq!(bad.validate(), Err(PlanError::new("action owner must be a non-empty string")));
    let mut bad = engine_action();
    bad.inverse = vec![];
    assert_eq!(bad.validate(), Err(PlanError::new("action core.install must declare non-empty inverse")));
    let mut bad = engine_action();
    bad.mutations = vec!["--password=x".into()];
    assert_eq!(bad.validate(), Err(PlanError::new("secret material is forbidden at plan.mutations[0]")));
    assert_eq!(Action::from_value(&engine_action().to_value()).unwrap(), engine_action());
    let mut extra = engine_action().to_value();
    extra["more"] = json!(1);
    assert_eq!(Action::from_value(&extra), Err(PlanError::new("action got an unexpected field: more")));
}

#[test]
fn evidence_checks_and_round_trip() {
    let evidence = Evidence::ok("a", &["verified"]).unwrap();
    assert_eq!(Evidence::from_map(&evidence.to_map()).unwrap(), evidence);
    assert!(Evidence::ok(" ", &["x"]).is_err());
    assert!(Evidence::ok("a", &[""]).is_err());
    assert!(!Evidence::failed("a", &["x"]).unwrap().success);
    assert_eq!(
        pc_host::json::canonical(&Value::Object(evidence.to_map())),
        r#"{"action_id":"a","details":{},"observations":["verified"],"success":true}"#
    );
    let mut details = Map::new();
    details.insert("port".into(), json!(443));
    let detailed = Evidence::with_details("a", true, vec!["x".into()], details).unwrap();
    assert_eq!(Evidence::from_map(&detailed.to_map()).unwrap(), detailed);
    let mut broken = detailed.to_map();
    broken.remove("success");
    assert_eq!(Evidence::from_map(&broken), Err(PlanError::new("evidence is invalid")));
}

#[test]
fn plan_bytes_and_digests() {
    let mut facts = AuditFacts::default();
    facts.platform.insert("os".into(), json!("test"));
    let build = |facts: AuditFacts, schema: i64| {
        InstallPlan::new(
            json!({"profile": "test"}),
            facts,
            ReleaseIdentity::new("v1.2.3", &"a".repeat(40), &"b".repeat(64), BTreeMap::new(), BTreeMap::new()).unwrap(),
            vec!["core".into()],
            BTreeMap::from([("core".to_string(), vec![])]),
            vec![engine_action()],
            schema,
        )
    };
    let plan = build(facts.clone(), 1).unwrap();
    let text = plan.to_canonical_json();
    assert!(text.starts_with(r#"{"actions":[{"adapter":"core","credentials_required":false,"id":"core.install""#));
    assert!(text.contains(
        r#""audit_facts":{"listeners":{},"ownership":{},"platform":{"os":"test"},"prerequisites":{},"topology":{}}"#
    ));
    let reread = InstallPlan::from_value(&pc_host::json::loads(text.as_bytes()).unwrap()).unwrap();
    assert_eq!(reread.to_canonical_json(), text);
    assert_eq!(reread.digest(), plan.digest());
    let mut replanned = plan.clone();
    replanned.facts.platform.insert("changed".into(), json!("1"));
    assert_ne!(replanned.digest(), plan.digest());
    assert_eq!(replanned.intent_digest(), plan.intent_digest());
    assert_eq!(build(facts, 2).unwrap_err(), PlanError::new("unsupported plan schema: 2"));
}
