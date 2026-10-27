//! Ported from `tests/test_installer_config.py`.

use std::path::{Path, PathBuf};

use super::*;

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/installer")
}

const FULL_MANAGED_TOML: &str = r#"
schema = 1
host_mode = "fresh"
profile = "full"
acme_email = "admin@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "relay.example.com"
naive = "edge.example.com"
mieru = "mieru.example.com"

[mieru]
tcp_ports = [46001]
udp_ports = [46001]

[three_xui]
mode = "managed-new"
panel_domain = "xui.example.com"
vless_tcp_domain = "vless.example.com"
vless_xhttp_domain = "xhttp.example.com"
hysteria_domain = "hy2.example.com"
warp = false
warp_domains = []

[firewall]
manage_ufw = true
"#;

const COEXIST_WITH_UFW_TOML: &str = r#"
schema = 1
host_mode = "coexist"
profile = "core"
acme_email = "admin@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "relay.example.com"

[three_xui]
mode = "none"

[firewall]
manage_ufw = true
"#;

const CORE_TOML: &str = r#"
schema = 1
host_mode = "fresh"
profile = "core"
acme_email = "admin@example.com"
initial_user = "owner"

[domains]
panel = "panel.example.com"
mtproxy = "relay.example.com"

[three_xui]
mode = "none"

[firewall]
manage_ufw = false
"#;

fn error(text: &str) -> String {
    parse_config(text).unwrap_err().0
}

fn round_trips(config: &InstallerConfig) {
    assert_eq!(&parse_config(&render_config(config)).unwrap(), config);
}

#[test]
fn full_managed_config_collects_every_domain() {
    let config = parse_config(FULL_MANAGED_TOML).unwrap();
    assert_eq!(config.host_mode, HostMode::Fresh);
    assert_eq!(config.profile, Profile::Full);
    assert_eq!(config.three_xui.mode, ThreeXuiMode::ManagedNew);
    assert_eq!(
        config.required_domains(),
        vec![
            "edge.example.com",
            "hy2.example.com",
            "mieru.example.com",
            "panel.example.com",
            "relay.example.com",
            "vless.example.com",
            "xhttp.example.com",
            "xui.example.com",
        ]
    );
    round_trips(&config);
}

#[test]
fn subscription_domain_is_optional_distinct_and_round_trips() {
    let with_subscription = CORE_TOML.replace(
        "mtproxy = \"relay.example.com\"",
        "mtproxy = \"relay.example.com\"\nsubscription = \"sub.example.com\"",
    );
    let config = parse_config(&with_subscription).unwrap();
    assert_eq!(config.domains.subscription.as_deref(), Some("sub.example.com"));
    assert!(config.required_domains().contains(&"sub.example.com".to_string()));
    round_trips(&config);
    assert!(render_config(&config).contains("subscription = \"sub.example.com\""));
    assert_eq!(parse_config(CORE_TOML).unwrap().domains.subscription, None);
    assert!(!render_config(&parse_config(CORE_TOML).unwrap()).contains("subscription"));
    assert!(error(
        &with_subscription.replace("subscription = \"sub.example.com\"", "subscription = \"panel.example.com\"")
    )
    .contains("duplicate TCP SNI domain: panel.example.com"));
}

#[test]
fn mcp_domain_is_optional_distinct_and_round_trips() {
    let with_mcp = CORE_TOML
        .replace("mtproxy = \"relay.example.com\"", "mtproxy = \"relay.example.com\"\nmcp = \"mcp.example.com\"");
    let config = parse_config(&with_mcp).unwrap();
    assert_eq!(config.domains.mcp.as_deref(), Some("mcp.example.com"));
    assert!(config.required_domains().contains(&"mcp.example.com".to_string()));
    round_trips(&config);
    assert!(render_config(&config).contains("mcp = \"mcp.example.com\""));
    assert_eq!(parse_config(CORE_TOML).unwrap().domains.mcp, None);
    assert!(!render_config(&parse_config(CORE_TOML).unwrap()).contains("mcp"));
    assert!(error(&with_mcp.replace("mcp = \"mcp.example.com\"", "mcp = \"panel.example.com\""))
        .contains("duplicate TCP SNI domain: panel.example.com"));
}

#[test]
fn proxy_protocol_bridge_is_opt_in_loopback_only_and_round_trips() {
    let document = CORE_TOML.replace("host_mode = \"fresh\"", "host_mode = \"coexist\"").replace(
        "[three_xui]",
        "[ingress]\nproxy_protocol_bridge = \"127.0.0.1:10443\"\npanel_tls_port = 10446\nskip_renewal_dry_run = true\n\n[three_xui]",
    );
    let config = parse_config(&document).unwrap();
    let ingress = config.ingress.as_ref().unwrap();
    assert_eq!(ingress.proxy_protocol_bridge.as_deref(), Some("127.0.0.1:10443"));
    assert_eq!(ingress.panel_tls_port, 10446);
    assert_eq!(config.panel_tls_port(), 10446);
    assert!(ingress.skip_renewal_dry_run);
    round_trips(&config);
    assert!(error(&document.replace("127.0.0.1:10443", "10.0.0.1:10443")).contains("loopback TCP endpoint"));
    assert!(
        error(&document.replace("host_mode = \"coexist\"", "host_mode = \"fresh\"")).contains("requires coexist mode")
    );
    assert!(error(&document.replace("panel_tls_port = 10446", "panel_tls_port = 10443"))
        .contains("distinct unprivileged TCP port"));
}

#[test]
fn coexist_rejects_ufw_mutation() {
    assert_eq!(error(COEXIST_WITH_UFW_TOML), "UFW can be managed only in fresh mode");
}

#[test]
fn config_rejects_irrelevant_and_unknown_fields() {
    let with_secret = FULL_MANAGED_TOML
        .replace("mode = \"managed-new\"", "mode = \"managed-new\"\nprivate_key = \"do-not-store-secrets\"");
    assert_eq!(error(&with_secret), "unknown key: three_xui.private_key");
}

const EXAMPLES: [&str; 7] = [
    "core.toml",
    "core-naive.toml",
    "core-mieru.toml",
    "full-three-xui.toml",
    "managed-three-xui.toml",
    "existing-three-xui.toml",
    "core-amneziawg.toml",
];

#[test]
fn example_configs_load_and_round_trip() {
    for name in EXAMPLES.iter().chain(["core-trusttunnel.toml"].iter()) {
        let config = load_config(&examples().join(name)).unwrap();
        round_trips(&config);
    }
}

#[test]
fn generated_model_and_canonical_form_have_no_secret_fields() {
    let config = parse_config(FULL_MANAGED_TOML).unwrap();
    let canonical = pc_host::json::canonical(&config.canonical_dict()).to_lowercase();
    let rendered = render_config(&config).to_lowercase();
    for word in ["password", "secret", "private_key", "token", "credential"] {
        assert!(!canonical.contains(word) && !rendered.contains(word), "{word}");
    }
    let keys: Vec<String> = config.canonical_dict().as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        keys,
        vec![
            "acme_email",
            "amneziawg",
            "domains",
            "egress",
            "firewall",
            "host_mode",
            "ingress",
            "initial_user",
            "mieru",
            "profile",
            "schema",
            "three_xui",
            "trusttunnel",
        ]
    );
}

#[test]
fn config_rejects_invalid_scalar_values() {
    for (text, message) in [
        (CORE_TOML.replace("schema = 1", "schema = 2"), "unsupported schema: 2"),
        (CORE_TOML.replace("profile = \"core\"", "profile = \"unknown\""), "invalid profile"),
        (CORE_TOML.replace("panel = \"panel.example.com\"", "panel = \"not a domain\""), "invalid domain"),
        (CORE_TOML.replace("initial_user = \"owner\"", "initial_user = \"bad user\""), "unsafe initial user"),
        (CORE_TOML.replace("manage_ufw = false", "manage_ufw = \"false\""), "firewall.manage_ufw must be a boolean"),
        (format!("{CORE_TOML}\nunexpected = true\n"), "unknown key: firewall.unexpected"),
    ] {
        assert!(error(&text).contains(message), "{message}");
    }
}

#[test]
fn profile_requires_and_rejects_conditional_sections_and_domains() {
    assert!(error(&CORE_TOML.replace("profile = \"core\"", "profile = \"core-naive\""))
        .contains("domains.naive is required for profile core-naive"));
    assert!(error(
        &CORE_TOML.replace(
            "mtproxy = \"relay.example.com\"",
            "mtproxy = \"relay.example.com\"\nnaive = \"edge.example.com\""
        )
    )
    .contains("unknown key: domains.naive"));
    let mieru = CORE_TOML
        .replace("profile = \"core\"", "profile = \"core-mieru\"")
        .replace("mtproxy = \"relay.example.com\"", "mtproxy = \"relay.example.com\"\nmieru = \"mieru.example.com\"");
    assert!(error(&mieru).contains("mieru section is required for profile core-mieru"));
}

#[test]
fn mieru_ports_are_validated_and_immutable() {
    let invalid = FULL_MANAGED_TOML.replace("tcp_ports = [46001]", "tcp_ports = [0, 46001]");
    assert_eq!(error(&invalid), "mieru.tcp_ports contains invalid port: 0");
}

#[test]
fn managed_three_xui_requires_all_fields() {
    let missing = FULL_MANAGED_TOML.replace("panel_domain = \"xui.example.com\"\n", "");
    assert_eq!(error(&missing), "missing key: three_xui.panel_domain");
}

#[test]
fn none_three_xui_rejects_irrelevant_fields() {
    let invalid = CORE_TOML.replace("mode = \"none\"", "mode = \"none\"\npanel_domain = \"xui.example.com\"");
    assert_eq!(error(&invalid), "unknown key: three_xui.panel_domain");
}

#[test]
fn duplicate_tcp_sni_domains_are_rejected() {
    let duplicate = FULL_MANAGED_TOML.replace("xui.example.com", "panel.example.com");
    assert_eq!(error(&duplicate), "duplicate TCP SNI domain: panel.example.com");
}

#[test]
fn udp_or_dedicated_port_domains_may_reuse_tcp_dns() {
    for text in [
        FULL_MANAGED_TOML.replace("hy2.example.com", "panel.example.com"),
        FULL_MANAGED_TOML.replace("mieru.example.com", "panel.example.com"),
    ] {
        let config = parse_config(&text).unwrap();
        assert!(config.required_domains().contains(&"panel.example.com".to_string()));
    }
}

#[test]
fn domains_are_normalized_before_duplicate_checks() {
    let config = parse_config(&FULL_MANAGED_TOML.replace("panel.example.com", "Panel.Example.COM.")).unwrap();
    assert_eq!(config.domains.panel, "panel.example.com");
}

#[test]
fn invalid_toml_is_reported_as_config_error() {
    assert!(error("schema = [").starts_with("invalid TOML"));
}

#[test]
fn every_example_configuration_selects_adapters() {
    for name in EXAMPLES {
        let config = load_config(&examples().join(name)).unwrap();
        assert!(!crate::planner::adapters_for(&config).unwrap().is_empty(), "{name}");
    }
}

fn warp_document(mode: &str, profile: &str, extra_three_xui: &str, mieru: bool) -> String {
    let mut text = format!(
        "schema = 1\nhost_mode = \"coexist\"\nprofile = \"{profile}\"\nacme_email = \"ops@example.com\"\n\
         initial_user = \"owner\"\n\n[domains]\npanel = \"panel.example.com\"\nmtproxy = \"proxy.example.com\"\n"
    );
    if mieru {
        text.push_str("mieru = \"mieru.example.com\"\n\n[mieru]\ntcp_ports = [46001]\nudp_ports = [46002]\n");
    }
    text.push_str(&format!(
        "\n[three_xui]\nmode = \"{mode}\"\nwarp = true\n{extra_three_xui}\n[firewall]\nmanage_ufw = false\n"
    ));
    text
}

#[test]
fn warp_is_configurable_without_a_managed_three_xui() {
    for mode in ["none", "existing"] {
        let config = parse_config(&warp_document(mode, "core-mieru", "", true)).unwrap();
        assert!(config.three_xui.warp);
        round_trips(&config);
    }
}

#[test]
fn warp_domains_stay_confined_to_the_managed_mode() {
    for mode in ["none", "existing"] {
        let text = warp_document(mode, "core", "warp_domains = [\"example.com\"]\n", false);
        assert_eq!(error(&text), "unknown key: three_xui.warp_domains");
    }
}

#[test]
fn domain_rule_refuses_a_digit_in_the_top_level_label() {
    // Deliberate difference from Python's `_DOMAIN_RE` (DIFFERENCES.md).
    assert_eq!(normalize_domain("panel.example.c0m"), None);
    assert_eq!(normalize_domain("xn--d1acufc.xn--p1ai").as_deref(), Some("xn--d1acufc.xn--p1ai"));
    assert_eq!(normalize_domain("a.example.1com"), None);
}

#[test]
fn awg_dns_refuses_a_scope_id() {
    // Deliberate difference from Python's `ipaddress.ip_address` (DIFFERENCES.md).
    let text = format!("{CORE_TOML}\n[amneziawg]\nenabled = true\ndns = [\"fe80::1%eth0\"]\n");
    assert_eq!(error(&text), "amneziawg.dns contains an invalid address");
    let text = format!("{CORE_TOML}\n[amneziawg]\nenabled = true\ndns = [\"2001:DB8::1\", 7]\n");
    assert_eq!(error(&text), "amneziawg.dns contains an invalid address");
}

#[test]
fn router_relay_and_mieru_lane_defaults_round_trip_and_require_the_router() {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/plans/kitchen-sink/config.toml"),
    )
    .unwrap();
    let selected = parse_config(&source).unwrap();
    assert_eq!(selected.effective_egress().relay_port, crate::model::DEFAULT_RELAY_PORT);
    assert_eq!(selected.mieru.as_ref().unwrap().lane_slots, 4);
    assert_eq!(selected.mieru.as_ref().unwrap().slot_ports(), [46101, 46102, 46103, 46104]);
    let rendered = render_config(&selected);
    assert_eq!(parse_config(&rendered).unwrap(), selected);

    let explicit = source
        .replace("[mieru]\n", "[mieru]\nlane_slots = 2\n")
        .replace("[egress]\n", "[egress]\nrelay_port = 45444\n");
    let configured = parse_config(&explicit).unwrap();
    assert_eq!(configured.mieru.as_ref().unwrap().slot_ports(), [46101, 46102]);
    assert_eq!(configured.effective_egress().relay_port, 45444);
    assert_eq!(parse_config(&render_config(&configured)).unwrap(), configured);

    let plain = source.replace("router = true", "router = false").replace("naive = \"router\"", "naive = \"direct\"");
    let configured = parse_config(&plain).unwrap();
    assert_eq!(configured.effective_egress().relay_port, 0);
    assert_eq!(configured.mieru.as_ref().unwrap().lane_slots, 0);
    assert!(parse_config(&plain.replace("[egress]\n", "[egress]\nrelay_port = 45443\n")).is_err());
    assert!(parse_config(&plain.replace("[mieru]\n", "[mieru]\nlane_slots = 2\n")).is_err());
    assert!(parse_config(&source.replace("[mieru]\n", "[mieru]\nlane_slots = 9\n")).is_err());
    assert!(parse_config(&source.replace("[egress]\n", "[egress]\nrelay_port = 45101\n")).is_err());
    assert!(parse_config(&source.replace("tcp_ports = [46001, 46003]", "tcp_ports = [46102]")).is_err());
}
