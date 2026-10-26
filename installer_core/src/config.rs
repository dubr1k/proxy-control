//! TOML → [`InstallerConfig`] with the validation, messages and order of `installer/config.py`,
//! plus `render_config` (the wizard's writer) and the port reservation tables.
//!
//! Deliberate differences from Python (recorded in DIFFERENCES.md):
//! - the last label of a domain must be letters only or an IDN A-label (`xn--…`):
//!   `panel.example.c0m` and `example.co-m` were accepted by Python's regex;
//! - an `amneziawg.dns` address with an IPv6 scope (`fe80::1%eth0`) is refused (Python kept it);
//! - with several invalid 3x-ui domain keys the first in a fixed order is named (Python iterated
//!   a `set`, so the reported key depended on the hash seed).

use std::collections::BTreeMap;
use std::path::Path;

use crate::ipaddr::{ip_address, ipv4_address};
use crate::model::*;
use crate::pystr::{char_len, is_space, lower, read_text, strip};
use crate::toml::{self, PyInt, Table, Value};

/// `ConfigError`: the configuration is malformed or inconsistent (also used for the file-level
/// `OSError`/`UnicodeDecodeError` texts of [`load_config`], which reach the same `BLOCKED:` line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl ConfigError {
    pub fn new(message: impl Into<String>) -> ConfigError {
        ConfigError(message.into())
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

type Result<T> = std::result::Result<T, ConfigError>;

fn fail<T>(message: impl Into<String>) -> Result<T> {
    Err(ConfigError(message.into()))
}

/// `load_config(path)`: `read_text(encoding="utf-8")` then [`parse_config`].
pub fn load_config(path: &Path) -> Result<InstallerConfig> {
    parse_config(&read_text(path).map_err(ConfigError)?)
}

/// `parse_config(text)`.
pub fn parse_config(text: &str) -> Result<InstallerConfig> {
    let root = toml::loads(text).map_err(|err| ConfigError(format!("invalid TOML: {err}")))?;
    keys(
        &root,
        "",
        &["schema", "host_mode", "profile", "acme_email", "initial_user", "domains", "three_xui", "firewall"],
        &["mieru", "egress", "ingress", "amneziawg", "trusttunnel"],
    )?;
    let schema = integer(get(&root, "schema"), "schema")?;
    if schema.as_str() != "1" {
        return fail(format!("unsupported schema: {}", schema.as_str()));
    }
    let host_mode = enumeration(get(&root, "host_mode"), &HostMode::ALL, HostMode::value, "host_mode")?;
    let profile = enumeration(get(&root, "profile"), &Profile::ALL, Profile::value, "profile")?;
    let acme_email = string(get(&root, "acme_email"), "acme_email")?;
    if !email_ok(&acme_email) {
        return fail("invalid ACME email");
    }
    let initial_user = string(get(&root, "initial_user"), "initial_user")?;
    if !safe_name(&initial_user) {
        return fail("unsafe initial user");
    }

    let domains = parse_domains(get(&root, "domains"), profile)?;
    let mut mieru = parse_mieru(root.get("mieru"), profile)?;
    let mut three_xui = parse_three_xui(get(&root, "three_xui"), root.contains_key("egress"))?;
    let trusttunnel = parse_trusttunnel(root.get("trusttunnel"), &domains)?;
    let three_xui_raw = table(get(&root, "three_xui"), "three_xui")?;
    let egress = parse_egress(root.get("egress"), &three_xui, profile, three_xui_raw, trusttunnel.is_some())?;
    if let Some(parsed) = mieru.as_mut() {
        let router = egress.as_ref().is_some_and(|e| e.router);
        match parsed.1 {
            None => parsed.0.lane_slots = if router { DEFAULT_LANE_SLOTS } else { 0 },
            Some(slots) if slots > 0 && !router => return fail("mieru.lane_slots requires egress.router = true"),
            Some(slots) => parsed.0.lane_slots = slots,
        }
    }
    let mieru = mieru.map(|(config, _)| config);
    if let Some(e) = &egress {
        three_xui.warp = e.warp;
        three_xui.warp_port = e.warp_port;
    }
    let firewall = parse_firewall(get(&root, "firewall"))?;
    let ingress = parse_ingress(root.get("ingress"))?;
    let amneziawg = parse_amneziawg(root.get("amneziawg"), &domains)?;

    if host_mode == HostMode::Coexist && firewall.manage_ufw {
        return fail("UFW can be managed only in fresh mode");
    }
    if ingress.is_some() && host_mode != HostMode::Coexist {
        return fail("ingress.proxy_protocol_bridge requires coexist mode");
    }
    let config = InstallerConfig {
        schema: 1,
        host_mode,
        profile,
        acme_email,
        initial_user,
        domains,
        mieru,
        three_xui,
        firewall,
        egress,
        ingress,
        amneziawg,
        trusttunnel,
    };
    reject_duplicate_tcp_sni_domains(&config)?;
    reject_trusttunnel_collisions(&config)?;
    reject_mieru_port_collisions(&config)?;
    reject_amneziawg_port_collisions(&config)?;
    Ok(config)
}

/// A key the caller has already checked for presence.
fn get<'a>(table: &'a Table, key: &str) -> &'a Value {
    table.get(key).expect("required keys are checked first")
}

/// `render_config(config)`: the line-based TOML the wizard saves.
pub fn render_config(config: &InstallerConfig) -> String {
    let mut lines = vec![
        format!("schema = {}", config.schema),
        format!("host_mode = {}", toml_string(config.host_mode.value())),
        format!("profile = {}", toml_string(config.profile.value())),
        format!("acme_email = {}", toml_string(&config.acme_email)),
        format!("initial_user = {}", toml_string(&config.initial_user)),
        String::new(),
        "[domains]".into(),
        format!("panel = {}", toml_string(&config.domains.panel)),
        format!("mtproxy = {}", toml_string(&config.domains.mtproxy)),
    ];
    let d = &config.domains;
    for (name, value) in [
        ("naive", &d.naive),
        ("mieru", &d.mieru),
        ("subscription", &d.subscription),
        ("mcp", &d.mcp),
        ("trusttunnel", &d.trusttunnel),
    ] {
        if let Some(value) = value {
            lines.push(format!("{name} = {}", toml_string(value)));
        }
    }
    if let Some(mieru) = &config.mieru {
        lines.extend([
            String::new(),
            "[mieru]".into(),
            format!("tcp_ports = {}", toml_ints(&mieru.tcp_ports)),
            format!("udp_ports = {}", toml_ints(&mieru.udp_ports)),
        ]);
        if config.egress.as_ref().is_some_and(|e| e.router) {
            lines.push(format!("lane_slots = {}", mieru.lane_slots));
        }
    }
    if let Some(egress) = &config.egress {
        lines.extend([String::new(), "[egress]".into(), format!("warp = {}", toml_bool(egress.warp))]);
        if egress.warp_port != 40000 {
            lines.push(format!("warp_port = {}", egress.warp_port));
        }
        if egress.router {
            lines.push("router = true".into());
            lines.push(format!("relay_port = {}", egress.relay_port));
        }
        if config.profile.includes_naive() {
            lines.push(format!("naive = {}", toml_string(egress.naive.value())));
        }
        if config.profile.includes_mieru() {
            lines.push(format!("mieru = {}", toml_string(egress.mieru.value())));
        }
    }
    if let Some(ingress) = &config.ingress {
        lines.extend([
            String::new(),
            "[ingress]".into(),
            format!("proxy_protocol_bridge = {}", toml_string(ingress.proxy_protocol_bridge.as_deref().unwrap_or(""))),
            format!("panel_tls_port = {}", ingress.panel_tls_port),
            format!("skip_renewal_dry_run = {}", toml_bool(ingress.skip_renewal_dry_run)),
        ]);
    }
    if let Some(awg) = &config.amneziawg {
        let ports: Vec<String> = awg
            .port_map()
            .into_iter()
            .filter(|(_, port)| *port != 0)
            .map(|(version, port)| format!("{} = {port}", toml_string(&version)))
            .collect();
        lines.extend([
            String::new(),
            "[amneziawg]".into(),
            "enabled = true".into(),
            format!("versions = {}", toml_strings(&awg.versions)),
            format!("host = {}", toml_string(&awg.host)),
        ]);
        if !ports.is_empty() {
            lines.push(format!("ports = {{ {} }}", ports.join(", ")));
        }
        lines.push(format!("mtu = {}", awg.mtu));
        lines.push(format!("dns = {}", toml_strings(&awg.dns)));
    }
    if let Some(tt) = &config.trusttunnel {
        lines.extend([
            String::new(),
            "[trusttunnel]".into(),
            "enabled = true".into(),
            format!("listen_port = {}", tt.listen_port),
        ]);
    }
    let x = &config.three_xui;
    lines.extend([String::new(), "[three_xui]".into(), format!("mode = {}", toml_string(x.mode.value()))]);
    for (name, value) in [
        ("panel_domain", &x.panel_domain),
        ("vless_tcp_domain", &x.vless_tcp_domain),
        ("vless_xhttp_domain", &x.vless_xhttp_domain),
        ("hysteria_domain", &x.hysteria_domain),
    ] {
        if let Some(value) = value {
            lines.push(format!("{name} = {}", toml_string(value)));
        }
    }
    if let Some(value) = &x.subscription_domain {
        lines.push(format!("subscription_domain = {}", toml_string(value)));
    }
    if x.warp || x.mode == ThreeXuiMode::ManagedNew {
        lines.push(format!("warp = {}", toml_bool(x.warp)));
    }
    if x.warp_port != 40000 {
        lines.push(format!("warp_port = {}", x.warp_port));
    }
    if x.mode == ThreeXuiMode::ManagedNew {
        lines.push(format!("warp_domains = {}", toml_strings(&x.warp_domains)));
    }
    lines.extend([
        String::new(),
        "[firewall]".into(),
        format!("manage_ufw = {}", toml_bool(config.firewall.manage_ufw)),
    ]);
    lines.join("\n") + "\n"
}

fn parse_domains(value: &Value, profile: Profile) -> Result<DomainConfig> {
    let raw = table(value, "domains")?;
    if profile.includes_naive() && !raw.contains_key("naive") {
        return fail(format!("domains.naive is required for profile {}", profile.value()));
    }
    if profile.includes_mieru() && !raw.contains_key("mieru") {
        return fail(format!("domains.mieru is required for profile {}", profile.value()));
    }
    let mut required = vec!["panel", "mtproxy"];
    if profile.includes_naive() {
        required.push("naive");
    }
    if profile.includes_mieru() {
        required.push("mieru");
    }
    keys(raw, "domains", &required, &["subscription", "mcp", "trusttunnel"])?;
    let optional = |name: &str| -> Result<Option<String>> {
        raw.get(name).map(|value| domain(value, &format!("domains.{name}"))).transpose()
    };
    Ok(DomainConfig {
        panel: domain(get(raw, "panel"), "domains.panel")?,
        mtproxy: domain(get(raw, "mtproxy"), "domains.mtproxy")?,
        naive: optional("naive")?,
        mieru: optional("mieru")?,
        subscription: optional("subscription")?,
        mcp: optional("mcp")?,
        trusttunnel: optional("trusttunnel")?,
    })
}

/// The section with `lane_slots` still unresolved (`None` = absent).
fn parse_mieru(value: Option<&Value>, profile: Profile) -> Result<Option<(MieruConfig, Option<u32>)>> {
    if !profile.includes_mieru() {
        if value.is_some() {
            return fail("unknown key: mieru");
        }
        return Ok(None);
    }
    let Some(value) = value else {
        return fail(format!("mieru section is required for profile {}", profile.value()));
    };
    let raw = table(value, "mieru")?;
    keys(raw, "mieru", &["tcp_ports", "udp_ports"], &["lane_slots"])?;
    let tcp_ports = ports(get(raw, "tcp_ports"), "mieru.tcp_ports")?;
    let udp_ports = ports(get(raw, "udp_ports"), "mieru.udp_ports")?;
    if tcp_ports.is_empty() && udp_ports.is_empty() {
        return fail("mieru requires at least one TCP or UDP port");
    }
    let mut lane_slots = None;
    if let Some(value) = raw.get("lane_slots") {
        let slots = integer(value, "mieru.lane_slots")?;
        let slots = match slots.to_i64() {
            Some(n) if (0..=i64::from(MAX_LANE_SLOTS)).contains(&n) => n as u32,
            _ => return fail(format!("mieru.lane_slots must be between 0 and {MAX_LANE_SLOTS}")),
        };
        if (1..=slots).map(lane_slot_port).any(|port| tcp_ports.contains(&port)) {
            return fail("mieru.tcp_ports collide with the lane slot ports");
        }
        lane_slots = Some(slots);
    }
    Ok(Some((MieruConfig { tcp_ports, udp_ports, lane_slots: 0 }, lane_slots)))
}

const XUI_DOMAINS: [&str; 4] = ["panel_domain", "vless_tcp_domain", "vless_xhttp_domain", "hysteria_domain"];

fn parse_three_xui(value: &Value, explicit_egress: bool) -> Result<ThreeXuiConfig> {
    let raw = table(value, "three_xui")?;
    let Some(mode_value) = raw.get("mode") else {
        return fail("missing key: three_xui.mode");
    };
    let mode = enumeration(mode_value, &ThreeXuiMode::ALL, ThreeXuiMode::value, "three_xui.mode")?;
    match mode {
        ThreeXuiMode::None => keys(raw, "three_xui", &["mode"], &["warp", "warp_port"])?,
        ThreeXuiMode::Existing => {
            let mut optional = XUI_DOMAINS.to_vec();
            optional.extend(["warp", "warp_port"]);
            keys(raw, "three_xui", &["mode"], &optional)?
        }
        ThreeXuiMode::ManagedNew => {
            let mut required = vec!["mode", "warp_domains"];
            required.extend(XUI_DOMAINS);
            let mut optional = vec!["warp_port", "subscription_domain"];
            if explicit_egress {
                optional.push("warp");
            } else {
                required.push("warp");
            }
            keys(raw, "three_xui", &required, &optional)?
        }
    }
    let parsed: Vec<Option<String>> = XUI_DOMAINS
        .iter()
        .map(|name| raw.get(name).map(|value| domain(value, &format!("three_xui.{name}"))).transpose())
        .collect::<Result<_>>()?;
    let warp = match raw.get("warp") {
        Some(value) => boolean(value, "three_xui.warp")?,
        None => false,
    };
    let warp_domains = match raw.get("warp_domains") {
        Some(value) => parse_warp_domains(value)?,
        None => Vec::new(),
    };
    if !warp && !warp_domains.is_empty() && !(explicit_egress && !raw.contains_key("warp")) {
        return fail("three_xui.warp_domains requires warp = true");
    }
    let warp_port = port_in_range(raw.get("warp_port"), 40000, "three_xui.warp_port")?
        .ok_or_else(|| ConfigError::new("three_xui.warp_port must be between 1024 and 65535"))?;
    let subscription_domain =
        raw.get("subscription_domain").map(|value| domain(value, "three_xui.subscription_domain")).transpose()?;
    let mut parsed = parsed.into_iter();
    Ok(ThreeXuiConfig {
        mode,
        panel_domain: parsed.next().flatten(),
        vless_tcp_domain: parsed.next().flatten(),
        vless_xhttp_domain: parsed.next().flatten(),
        hysteria_domain: parsed.next().flatten(),
        warp,
        warp_domains,
        warp_port,
        subscription_domain,
    })
}

/// `_integer(raw.get(key, default), path)` then `1024 <= n <= 65535`: `Ok(None)` when out of range.
fn port_in_range(value: Option<&Value>, default: i64, path: &str) -> Result<Option<u16>> {
    let number = match value {
        Some(value) => integer(value, path)?,
        None => PyInt::from_i64(default),
    };
    Ok(number.to_i64().filter(|n| (1024..=65535).contains(n)).map(|n| n as u16))
}

fn parse_egress(
    value: Option<&Value>,
    three_xui: &ThreeXuiConfig,
    profile: Profile,
    three_xui_raw: &Table,
    trusttunnel: bool,
) -> Result<Option<EgressConfig>> {
    let Some(value) = value else { return Ok(None) };
    let raw = table(value, "egress")?;
    keys(raw, "egress", &[], &["warp", "warp_port", "naive", "mieru", "router", "relay_port"])?;
    let warp = match raw.get("warp") {
        Some(value) => boolean(value, "egress.warp")?,
        None => false,
    };
    let router = match raw.get("router") {
        Some(value) => boolean(value, "egress.router")?,
        None => false,
    };
    if router && !(profile.includes_naive() || profile.includes_mieru() || trusttunnel) {
        return fail("egress.router requires NaiveProxy, Mieru or TrustTunnel (in the profile or [trusttunnel])");
    }
    let relay = match raw.get("relay_port") {
        Some(value) => integer(value, "egress.relay_port")?,
        None => PyInt::from_i64(if router { i64::from(DEFAULT_RELAY_PORT) } else { 0 }),
    };
    let relay_number = relay.to_i64();
    if relay.as_str() != "0" && !router {
        return fail("egress.relay_port requires router = true");
    }
    if relay.as_str() != "0" && !relay_number.is_some_and(|n| (1024..=65535).contains(&n)) {
        return fail("egress.relay_port must be between 1024 and 65535");
    }
    let relay_port = relay_number.unwrap_or(0) as u16;
    if [443, 80].contains(&relay_port) || ROUTER_PORTS.iter().any(|(_, port)| *port == relay_port) {
        return fail("egress.relay_port collides with a listener the host already runs");
    }
    let warp_port = port_in_range(raw.get("warp_port"), 40000, "egress.warp_port")?
        .ok_or_else(|| ConfigError::new("egress.warp_port must be between 1024 and 65535"))?;
    if three_xui_raw.contains_key("warp") && three_xui.warp != warp {
        return fail("three_xui.warp disagrees with egress.warp");
    }
    if three_xui_raw.contains_key("warp_port") && three_xui.warp_port != warp_port {
        return fail("three_xui.warp_port disagrees with egress.warp_port");
    }
    if !three_xui.warp_domains.is_empty() && !warp {
        return fail("three_xui.warp_domains requires egress.warp = true");
    }
    let default = if warp { EgressChoice::Warp } else { EgressChoice::Direct };
    let mut choices = [EgressChoice::Direct; 2];
    for (index, (service, present)) in
        [("naive", profile.includes_naive()), ("mieru", profile.includes_mieru())].into_iter().enumerate()
    {
        let Some(value) = raw.get(service) else {
            choices[index] = if present { default } else { EgressChoice::Direct };
            continue;
        };
        if !present {
            return fail(format!("egress.{service} is not part of profile {}", profile.value()));
        }
        let choice = enumeration(value, &EgressChoice::ALL, EgressChoice::value, &format!("egress.{service}"))?;
        if choice == EgressChoice::Warp && !warp {
            return fail(format!("egress.{service} requires warp = true"));
        }
        if choice == EgressChoice::Router && !router {
            return fail(format!("egress.{service} requires router = true"));
        }
        choices[index] = choice;
    }
    Ok(Some(EgressConfig { warp, warp_port, naive: choices[0], mieru: choices[1], router, relay_port }))
}

fn parse_warp_domains(value: &Value) -> Result<Vec<String>> {
    let Value::Array(items) = value else {
        return fail("three_xui.warp_domains must be an array");
    };
    let mut result = Vec::new();
    for item in items {
        let item = string(item, "three_xui.warp_domains")?;
        if let Some(selector) = item.strip_prefix("geosite:") {
            let valid = !selector.is_empty()
                && selector.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
            if !valid {
                return fail("invalid WARP geosite selector");
            }
        } else {
            let name = item.strip_prefix("domain:").unwrap_or(&item);
            normalize_domain(name).ok_or_else(|| ConfigError::new("invalid domain: three_xui.warp_domains"))?;
        }
        result.push(item);
    }
    result.sort();
    result.dedup();
    Ok(result)
}

fn parse_ingress(value: Option<&Value>) -> Result<Option<IngressConfig>> {
    let Some(value) = value else { return Ok(None) };
    let raw = table(value, "ingress")?;
    keys(raw, "ingress", &["proxy_protocol_bridge"], &["panel_tls_port", "skip_renewal_dry_run"])?;
    let bridge = string(get(raw, "proxy_protocol_bridge"), "ingress.proxy_protocol_bridge")?;
    let bridge_port = bridge
        .strip_prefix("127.0.0.1:")
        .filter(|digits| (1..=5).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit()))
        .map(|digits| digits.parse::<u32>().expect("1-5 ASCII digits"))
        .filter(|port| (1024..=65535).contains(port));
    let Some(bridge_port) = bridge_port else {
        return fail("ingress.proxy_protocol_bridge must be a loopback TCP endpoint");
    };
    let panel_tls_port = port_in_range(raw.get("panel_tls_port"), 8443, "ingress.panel_tls_port")?
        .filter(|port| u32::from(*port) != bridge_port)
        .ok_or_else(|| ConfigError::new("ingress.panel_tls_port must be a distinct unprivileged TCP port"))?;
    let skip_renewal_dry_run = match raw.get("skip_renewal_dry_run") {
        Some(value) => boolean(value, "ingress.skip_renewal_dry_run")?,
        None => false,
    };
    Ok(Some(IngressConfig { proxy_protocol_bridge: Some(bridge), panel_tls_port, skip_renewal_dry_run }))
}

fn parse_amneziawg(value: Option<&Value>, domains: &DomainConfig) -> Result<Option<AmneziaWgConfig>> {
    let Some(value) = value else { return Ok(None) };
    let raw = table(value, "amneziawg")?;
    keys(raw, "amneziawg", &[], &["enabled", "versions", "host", "ports", "mtu", "dns"])?;
    let enabled = match raw.get("enabled") {
        Some(value) => boolean(value, "amneziawg.enabled")?,
        None => false,
    };
    if !enabled {
        if raw.keys().any(|key| key != "enabled") {
            return fail("amneziawg settings are given while amneziawg.enabled is false");
        }
        return Ok(None);
    }
    let default_versions: Vec<Value> = AWG_VERSIONS.iter().map(|v| Value::String((*v).into())).collect();
    let versions_raw = match raw.get("versions") {
        Some(Value::Array(items)) if !items.is_empty() => items.as_slice(),
        Some(_) => return fail("amneziawg.versions must be a non-empty array"),
        None => default_versions.as_slice(),
    };
    let mut versions: Vec<String> = Vec::new();
    for item in versions_raw {
        let version = string(item, "amneziawg.versions")?;
        if !AWG_VERSIONS.contains(&version.as_str()) {
            return fail(format!("unknown amneziawg version: {version}"));
        }
        if versions.contains(&version) {
            return fail("amneziawg.versions must not contain duplicates");
        }
        versions.push(version);
    }
    let selected: Vec<String> =
        AWG_VERSIONS.iter().filter(|v| versions.iter().any(|s| s == *v)).map(|v| (*v).to_string()).collect();
    let host = match raw.get("host") {
        Some(value) => awg_host(value, "amneziawg.host")?,
        None => domains.panel.clone(),
    };
    let empty = Table::new();
    let ports_raw = match raw.get("ports") {
        Some(Value::Table(table)) => table,
        Some(_) => return fail("amneziawg.ports must be a table"),
        None => &empty,
    };
    for version in ports_raw.keys() {
        if !AWG_VERSIONS.contains(&version) {
            return fail(format!("unknown amneziawg version in amneziawg.ports: {version}"));
        }
        if !selected.iter().any(|s| s == version) {
            return fail(format!("amneziawg.ports names version {version}, which is not enabled"));
        }
    }
    let mut ports = Vec::new();
    for version in &selected {
        let Some(value) = ports_raw.get(version) else {
            ports.push(0);
            continue;
        };
        let path = format!("amneziawg.ports.{version}");
        let port = port_in_range(Some(value), 0, &path)?
            .ok_or_else(|| ConfigError(format!("amneziawg.ports.{version} must be between 1024 and 65535")))?;
        ports.push(port);
    }
    let given: Vec<u16> = ports.iter().copied().filter(|p| *p != 0).collect();
    let mut unique = given.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != given.len() {
        return fail("amneziawg.ports must be distinct");
    }
    let mtu = match raw.get("mtu") {
        Some(value) => integer(value, "amneziawg.mtu")?,
        None => PyInt::from_i64(i64::from(AWG_DEFAULT_MTU)),
    };
    let Some(mtu) = mtu.to_i64().filter(|n| (1280..=1420).contains(n)) else {
        return fail("amneziawg.mtu must be between 1280 and 1420");
    };
    let default_dns: Vec<Value> = AWG_DEFAULT_DNS.iter().map(|v| Value::String((*v).into())).collect();
    let dns_raw = match raw.get("dns") {
        Some(Value::Array(items)) if (1..=4).contains(&items.len()) => items.as_slice(),
        Some(_) => return fail("amneziawg.dns must list one to four addresses"),
        None => default_dns.as_slice(),
    };
    let mut dns = Vec::new();
    for item in dns_raw {
        // `_string` raises ConfigError, a ValueError: Python's `except ValueError` turns a
        // non-string entry into the same message as an invalid address.
        let address = match item {
            Value::String(text) if !text.contains('%') => ip_address(text).ok(),
            _ => None,
        };
        let Some(address) = address else {
            return fail("amneziawg.dns contains an invalid address");
        };
        dns.push(address);
    }
    let mut unique = dns.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != dns.len() {
        return fail("amneziawg.dns must not contain duplicates");
    }
    Ok(Some(AmneziaWgConfig { host, versions: selected, ports, mtu: mtu as u32, dns }))
}

fn parse_trusttunnel(value: Option<&Value>, domains: &DomainConfig) -> Result<Option<TrustTunnelConfig>> {
    let empty = Table::new();
    let raw = match value {
        Some(value) => table(value, "trusttunnel")?,
        None => &empty,
    };
    keys(raw, "trusttunnel", &[], &["enabled", "listen_port"])?;
    let enabled = match raw.get("enabled") {
        Some(value) => boolean(value, "trusttunnel.enabled")?,
        None => false,
    };
    if !enabled {
        if raw.keys().any(|key| key != "enabled") {
            return fail("trusttunnel settings are given while trusttunnel.enabled is false");
        }
        if domains.trusttunnel.is_some() {
            return fail("domains.trusttunnel is set but [trusttunnel] is not enabled");
        }
        return Ok(None);
    }
    let Some(hostname) = domains.trusttunnel.clone() else {
        return fail("domains.trusttunnel is required when trusttunnel.enabled is true");
    };
    let listen_port =
        port_in_range(raw.get("listen_port"), i64::from(TT_DEFAULT_LISTEN_PORT), "trusttunnel.listen_port")?
            .ok_or_else(|| ConfigError::new("trusttunnel.listen_port must be between 1024 and 65535"))?;
    Ok(Some(TrustTunnelConfig { hostname, listen_port }))
}

/// A DNS name or an IPv4 address (what a client puts in its `Endpoint`).
fn awg_host(value: &Value, path: &str) -> Result<String> {
    let raw = string(value, path)?;
    let text = lower(strip(&raw)).trim_end_matches('.').to_string();
    if let Ok(address) = ipv4_address(&text) {
        return Ok(address);
    }
    if !domain_shape_ok(&text) {
        return fail(format!("{path} must be a DNS name or an IPv4 address"));
    }
    Ok(text)
}

fn parse_firewall(value: &Value) -> Result<FirewallConfig> {
    let raw = table(value, "firewall")?;
    keys(raw, "firewall", &["manage_ufw"], &[])?;
    Ok(FirewallConfig { manage_ufw: boolean(get(raw, "manage_ufw"), "firewall.manage_ufw")? })
}

fn reject_duplicate_tcp_sni_domains(config: &InstallerConfig) -> Result<()> {
    let d = &config.domains;
    let x = &config.three_xui;
    let mut seen: Vec<&String> = Vec::new();
    for domain in [
        Some(&d.panel),
        Some(&d.mtproxy),
        d.naive.as_ref(),
        d.subscription.as_ref(),
        d.mcp.as_ref(),
        x.panel_domain.as_ref(),
        x.vless_tcp_domain.as_ref(),
        x.vless_xhttp_domain.as_ref(),
        x.subscription_domain.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if seen.contains(&domain) {
            return fail(format!("duplicate TCP SNI domain: {domain}"));
        }
        seen.push(domain);
    }
    Ok(())
}

const MTPROXY_BACKEND_PORT: u16 = 8445;
const PANEL_APP_PORT: u16 = 8787;
const MCP_PORT: u16 = 8793;
const NAIVE_PRIVATE_PORT: u16 = 4443;
const MANAGED_XUI_PORTS: [(u16, &str); 5] = [
    (8449, "the managed 3x-ui VLESS Reality TCP inbound"),
    (8450, "the managed 3x-ui VLESS Reality XHTTP inbound"),
    (8451, "the managed 3x-ui panel"),
    (2053, "a fresh 3x-ui's panel before the installer moves it"),
    (2096, "the managed 3x-ui subscription"),
];
const TT_LISTEN_OWNER: &str = "TrustTunnel's loopback listener (trusttunnel.listen_port)";
const TT_METRICS_OWNER: &str = "TrustTunnel's loopback metrics listener";

/// Port → owner (Python `dict` semantics: a later owner replaces an earlier one).
pub type PortTable = BTreeMap<u16, String>;

/// `reserved_tcp_ports(config)`: every TCP port the installer itself binds besides 80/443.
pub fn reserved_tcp_ports(config: &InstallerConfig) -> PortTable {
    let mut reserved = PortTable::new();
    reserved.insert(config.panel_tls_port(), "the panel's private TLS listener (ingress.panel_tls_port)".into());
    reserved.insert(MTPROXY_BACKEND_PORT, "the MTProxy backend".into());
    reserved.insert(PANEL_APP_PORT, "the panel application".into());
    if config.domains.mcp.is_some() {
        reserved.insert(MCP_PORT, "the MCP server".into());
    }
    if let Some(tt) = &config.trusttunnel {
        reserved.entry(tt.listen_port).or_insert_with(|| TT_LISTEN_OWNER.into());
        reserved.entry(TT_METRICS_PORT).or_insert_with(|| TT_METRICS_OWNER.into());
    }
    if config.profile.includes_naive() {
        reserved.insert(NAIVE_PRIVATE_PORT, "NaiveProxy's private listener".into());
    }
    let egress = config.effective_egress();
    if egress.warp {
        reserved.insert(egress.warp_port, "the WARP SOCKS5 endpoint (egress.warp_port)".into());
    }
    if egress.router {
        for (service, port) in ROUTER_PORTS {
            reserved.insert(port, format!("the Xray-router ingress for {service}"));
        }
        reserved.insert(TRUSTTUNNEL_ROUTER_PORT, "the Xray-router ingress for trusttunnel".into());
        if egress.relay_port != 0 {
            reserved.insert(egress.relay_port, "the Xray-router relay (egress.relay_port)".into());
        }
    }
    if let Some(mieru) = &config.mieru {
        for port in mieru.slot_ports() {
            reserved.insert(port, "a Mieru lane slot (mieru.lane_slots)".into());
        }
    }
    if config.three_xui.mode == ThreeXuiMode::ManagedNew {
        for (port, owner) in MANAGED_XUI_PORTS {
            reserved.insert(port, owner.into());
        }
    }
    reserved
}

/// `planned_ports(config)`: every port (TCP or UDP) the installer binds except AmneziaWG's.
pub fn planned_ports(config: &InstallerConfig) -> PortTable {
    let mut planned = reserved_tcp_ports(config);
    planned.insert(80, "HTTP (ACME)".into());
    planned.insert(443, "the shared TLS router".into());
    if let Some(mieru) = &config.mieru {
        for port in &mieru.tcp_ports {
            planned.insert(*port, "a Mieru TCP port".into());
        }
        for port in &mieru.udp_ports {
            planned.insert(*port, "a Mieru UDP port".into());
        }
    }
    planned
}

fn reject_trusttunnel_collisions(config: &InstallerConfig) -> Result<()> {
    let Some(tt) = &config.trusttunnel else { return Ok(()) };
    let d = &config.domains;
    let x = &config.three_xui;
    let others = [
        ("domains.panel", Some(&d.panel)),
        ("domains.mtproxy", Some(&d.mtproxy)),
        ("domains.naive", d.naive.as_ref()),
        ("domains.mieru", d.mieru.as_ref()),
        ("domains.subscription", d.subscription.as_ref()),
        ("domains.mcp", d.mcp.as_ref()),
        ("three_xui.panel_domain", x.panel_domain.as_ref()),
        ("three_xui.vless_tcp_domain", x.vless_tcp_domain.as_ref()),
        ("three_xui.vless_xhttp_domain", x.vless_xhttp_domain.as_ref()),
        ("three_xui.hysteria_domain", x.hysteria_domain.as_ref()),
        ("three_xui.subscription_domain", x.subscription_domain.as_ref()),
    ];
    for (key, value) in others {
        if value == Some(&tt.hostname) {
            return fail(format!("domains.trusttunnel duplicates {key}: {}", tt.hostname));
        }
    }
    let without = InstallerConfig { trusttunnel: None, ..config.clone() };
    let taken = planned_ports(&without);
    if let Some(owner) = taken.get(&tt.listen_port) {
        return fail(format!("trusttunnel.listen_port: {} is taken by {owner}", tt.listen_port));
    }
    if let Some(owner) = taken.get(&TT_METRICS_PORT) {
        return fail(format!("port {TT_METRICS_PORT} (TrustTunnel's metrics listener) is taken by {owner}"));
    }
    if tt.listen_port == TT_METRICS_PORT {
        return fail("trusttunnel.listen_port collides with TrustTunnel's metrics listener");
    }
    Ok(())
}

fn reject_mieru_port_collisions(config: &InstallerConfig) -> Result<()> {
    let Some(mieru) = &config.mieru else { return Ok(()) };
    let reserved = reserved_tcp_ports(config);
    for port in &mieru.tcp_ports {
        if let Some(owner) = reserved.get(port) {
            return fail(format!("mieru.tcp_ports: {port} is taken by {owner}"));
        }
    }
    Ok(())
}

fn reject_amneziawg_port_collisions(config: &InstallerConfig) -> Result<()> {
    let Some(awg) = &config.amneziawg else { return Ok(()) };
    let planned = planned_ports(config);
    for (version, port) in awg.port_map() {
        if port != 0 {
            if let Some(owner) = planned.get(&port) {
                return fail(format!("amneziawg.ports.{version}: {port} is taken by {owner}"));
            }
        }
    }
    Ok(())
}

fn keys(table: &Table, path: &str, required: &[&str], optional: &[&str]) -> Result<()> {
    for key in table.keys() {
        if !required.contains(&key) && !optional.contains(&key) {
            return fail(format!("unknown key: {}", qualified(path, key)));
        }
    }
    let mut sorted: Vec<&&str> = required.iter().collect();
    sorted.sort();
    for key in sorted {
        if !table.contains_key(key) {
            return fail(format!("missing key: {}", qualified(path, key)));
        }
    }
    Ok(())
}

fn qualified(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

fn table<'a>(value: &'a Value, path: &str) -> Result<&'a Table> {
    match value {
        Value::Table(table) => Ok(table),
        _ => fail(format!("{path} must be a table")),
    }
}

fn string(value: &Value, path: &str) -> Result<String> {
    match value {
        Value::String(text) => Ok(text.clone()),
        _ => fail(format!("{path} must be a string")),
    }
}

fn integer(value: &Value, path: &str) -> Result<PyInt> {
    match value {
        Value::Integer(number) => Ok(number.clone()),
        _ => fail(format!("{path} must be an integer")),
    }
}

fn boolean(value: &Value, path: &str) -> Result<bool> {
    match value {
        Value::Boolean(flag) => Ok(*flag),
        _ => fail(format!("{path} must be a boolean")),
    }
}

fn enumeration<T: Copy>(value: &Value, all: &[T], name: fn(T) -> &'static str, path: &str) -> Result<T> {
    let raw = string(value, path)?;
    all.iter().copied().find(|item| name(*item) == raw).ok_or_else(|| ConfigError(format!("invalid {path}: {raw}")))
}

fn domain(value: &Value, path: &str) -> Result<String> {
    let raw = string(value, path)?;
    normalize_domain(&raw).ok_or_else(|| ConfigError(format!("invalid domain: {path}")))
}

fn ports(value: &Value, path: &str) -> Result<Vec<u16>> {
    let Value::Array(items) = value else {
        return fail(format!("{path} must be an array"));
    };
    let mut result: Vec<u16> = Vec::new();
    for item in items {
        let number = integer(item, path)?;
        match number.to_i64().filter(|n| (1024..=65535).contains(n)) {
            Some(port) => result.push(port as u16),
            None => return fail(format!("{path} contains invalid port: {}", number.as_str())),
        }
    }
    let mut unique = result.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != result.len() {
        return fail(format!("{path} must not contain duplicates"));
    }
    Ok(result)
}

/// `_domain` without the error: `strip().lower().rstrip(".")`, then the domain rule.
pub fn normalize_domain(raw: &str) -> Option<String> {
    let normalized = lower(strip(raw)).trim_end_matches('.').to_string();
    domain_shape_ok(&normalized).then_some(normalized)
}

/// `_DOMAIN_RE.fullmatch`: 4..253 code points, at least two dot-separated labels of
/// `[a-z0-9-]{1,63}` that neither start nor end with `-`; the last label is letters only or an
/// IDN A-label (`xn--…`; Python also took a letter followed by digits or hyphens, e.g. `c0m`,
/// `co-m`).
pub fn domain_shape_ok(text: &str) -> bool {
    let length = char_len(text);
    if !(4..=253).contains(&length) || text.contains('\n') {
        return false;
    }
    let labels: Vec<&str> = text.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    let (last, rest) = labels.split_last().expect("two labels");
    if !rest.iter().all(|label| label_ok(label)) || !label_ok(last) {
        return false;
    }
    last.bytes().all(|b| b.is_ascii_lowercase()) || (last.starts_with("xn--") && last.len() > 4)
}

/// `[^\s@]+@[^\s@]+\.[^\s@]+\Z` (full match; nothing stripped or lowered).
fn email_ok(text: &str) -> bool {
    if text.chars().any(is_space) {
        return false;
    }
    let mut parts = text.split('@');
    let (Some(local), Some(host), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let host: Vec<char> = host.chars().collect();
    !local.is_empty() && host.len() >= 3 && host[1..host.len() - 1].contains(&'.')
}

/// `[A-Za-z0-9_-]{1,64}\Z`.
pub fn safe_name(text: &str) -> bool {
    (1..=64).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `json.dumps(value, ensure_ascii=False)` as a TOML basic string.
fn toml_string(value: &str) -> String {
    pc_host::json::dumps(&serde_json::Value::String(value.to_string()), &pc_host::json::Options::CANONICAL)
}

fn toml_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn toml_ints(values: &[u16]) -> String {
    let rendered: Vec<String> = values.iter().map(u16::to_string).collect();
    format!("[{}]", rendered.join(", "))
}

fn toml_strings(values: &[String]) -> String {
    let rendered: Vec<String> = values.iter().map(|value| toml_string(value)).collect();
    format!("[{}]", rendered.join(", "))
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
