//! `validate_config`: the mita server config this manager will write or accept from mita,
//! bounded by mita's protobuf schema (v3.35) and the manager's own safety rules.

use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::pyip;

const TOP_FIELDS: &[&str] =
    &["portBindings", "users", "advancedSettings", "loggingLevel", "mtu", "egress", "dns", "trafficPattern"];
const USER_FIELDS: &[&str] = &["name", "password", "hashedPassword", "quotas", "allowPrivateIP", "allowLoopbackIP"];
const PORT_FIELDS: &[&str] = &["port", "protocol", "portRange"];
const QUOTA_FIELDS: &[&str] = &["days", "megabytes"];
const LOG_LEVELS: &[&str] = &["DEFAULT", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];
const DUAL_STACK: &[&str] = &["USE_FIRST_IP", "PREFER_IPv4", "PREFER_IPv6", "ONLY_IPv4", "ONLY_IPv6"];
pub const MAX_QUOTA_DAYS: i128 = (1 << 31) - 1;
pub const MAX_QUOTA_MIB: i128 = (1 << 31) - 1;

fn invalid(message: impl Into<String>) -> Error {
    Error::validation(message)
}

/// `_object`: a dict whose keys are all in `fields`.
fn object<'a>(value: &'a Value, fields: &[&str], name: &str) -> Result<&'a Map<String, Value>> {
    let Value::Object(map) = value else { return Err(invalid(format!("{name} must be an object"))) };
    if map.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(invalid(format!("{name} contains unknown fields")));
    }
    Ok(map)
}

/// `_positive_int`: an int (not a bool) within `low..=high`.
fn bounded_int(value: Option<&Value>, low: i128, high: i128, name: &str) -> Result<i128> {
    match value.and_then(pc_common::pyvalue::strict_int) {
        Some(n) if (low..=high).contains(&n) => Ok(n),
        _ => Err(invalid(format!("invalid {name}"))),
    }
}

fn str_in(value: Option<&Value>, default: &str, allowed: &[&str]) -> bool {
    match value {
        None => allowed.contains(&default),
        Some(Value::String(s)) => allowed.contains(&s.as_str()),
        Some(_) => false,
    }
}

fn is_bool(value: &Value) -> bool {
    matches!(value, Value::Bool(_))
}

/// An integer of the duration with exact decimal arithmetic: whole nanoseconds plus a
/// fraction in units of 1e-24 ns, carried as it overflows.
const FRACTION_DIGITS: usize = 24;
const FRACTION_ONE: i128 = 1_000_000_000_000_000_000_000_000;

/// `_go_duration_ns`: Go's `time.ParseDuration` grammar without the bare `0`, in nanoseconds.
pub fn go_duration_ns(value: &Value) -> Result<i64> {
    let bad = || invalid("invalid metrics interval");
    let Value::String(text) = value else { return Err(bad()) };
    if text.is_empty() {
        return Err(bad());
    }
    let (sign, body) = match text.chars().next() {
        Some('-') => (-1i128, &text[1..]),
        Some('+') => (1, &text[1..]),
        _ => (1, text.as_str()),
    };
    const UNITS: &[(&str, i128)] = &[
        ("ns", 1),
        ("us", 1_000),
        ("µs", 1_000),
        ("μs", 1_000),
        ("ms", 1_000_000),
        ("s", 1_000_000_000),
        ("m", 60_000_000_000),
        ("h", 3_600_000_000_000),
    ];
    let limit = 1i128 << 63;
    let (mut whole, mut fraction) = (0i128, 0i128);
    let mut rest = body;
    if rest.is_empty() {
        return Err(bad());
    }
    while !rest.is_empty() {
        let int_len = rest.bytes().take_while(u8::is_ascii_digit).count();
        let mut cursor = int_len;
        let mut frac_len = 0;
        if rest.as_bytes().get(cursor) == Some(&b'.') {
            frac_len = rest[cursor + 1..].bytes().take_while(u8::is_ascii_digit).count();
            if int_len == 0 && frac_len == 0 {
                return Err(bad());
            }
            cursor += 1 + frac_len;
        } else if int_len == 0 {
            return Err(bad());
        }
        let after = &rest[cursor..];
        let Some((unit, scale)) = UNITS.iter().find(|(unit, _)| after.starts_with(unit)) else { return Err(bad()) };
        let digits = rest[..int_len].trim_start_matches('0');
        if digits.len() > 20 {
            return Err(bad());
        }
        let integer: i128 = if digits.is_empty() { 0 } else { digits.parse().map_err(|_| bad())? };
        whole += integer * scale;
        if frac_len > 0 {
            let mut frac: String = rest[int_len + 1..int_len + 1 + frac_len].chars().take(FRACTION_DIGITS).collect();
            while frac.len() < FRACTION_DIGITS {
                frac.push('0');
            }
            let numerator: i128 = frac.parse().map_err(|_| bad())?;
            // numerator / 1e24 of a unit, as ns: numerator * scale / 1e24, kept exact in parts.
            let scaled = numerator * scale;
            whole += scaled / FRACTION_ONE;
            fraction += scaled % FRACTION_ONE;
            whole += fraction / FRACTION_ONE;
            fraction %= FRACTION_ONE;
        }
        if whole > limit {
            return Err(bad());
        }
        rest = &after[unit.len()..];
    }
    let nanoseconds = sign * whole;
    if !(-limit..limit).contains(&nanoseconds) {
        return Err(bad());
    }
    Ok(nanoseconds as i64)
}

fn validate_traffic(value: &Value) -> Result<()> {
    let traffic =
        object(value, &["seed", "unlockAll", "tcpFragment", "nonce", "padding", "lowEntropy"], "trafficPattern")?;
    if let Some(seed) = traffic.get("seed") {
        if !pc_common::pyvalue::strict_int(seed).is_some_and(|n| (-(1i128 << 31)..=(1 << 31) - 1).contains(&n)) {
            return Err(invalid("invalid traffic pattern seed"));
        }
    }
    if traffic.get("unlockAll").is_some_and(|v| !is_bool(v)) {
        return Err(invalid("invalid traffic pattern unlockAll"));
    }
    if let Some(fragment) = traffic.get("tcpFragment") {
        let node = object(fragment, &["enable", "maxSleepMs"], "tcpFragment")?;
        if node.get("enable").is_some_and(|v| !is_bool(v)) {
            return Err(invalid("invalid traffic pattern fragment"));
        }
        if let Some(delay) = node.get("maxSleepMs") {
            bounded_int(Some(delay), 0, 100, "traffic fragment delay")?;
        }
    }
    if let Some(nonce) = traffic.get("nonce") {
        let node = object(nonce, &["type", "applyToAllUDPPacket", "minLen", "maxLen", "customHexStrings"], "nonce")?;
        let types = ["NONCE_TYPE_RANDOM", "NONCE_TYPE_PRINTABLE", "NONCE_TYPE_PRINTABLE_SUBSET", "NONCE_TYPE_FIXED"];
        if !str_in(node.get("type"), "NONCE_TYPE_RANDOM", &types) {
            return Err(invalid("invalid traffic nonce type"));
        }
        if node.get("applyToAllUDPPacket").is_some_and(|v| !is_bool(v)) {
            return Err(invalid("invalid traffic nonce UDP setting"));
        }
        for key in ["minLen", "maxLen"] {
            if let Some(length) = node.get(key) {
                bounded_int(Some(length), 0, 12, &format!("nonce {key}"))?;
            }
        }
        let min = node.get("minLen").and_then(pc_common::pyvalue::strict_int).unwrap_or(0);
        let max = node.get("maxLen").and_then(pc_common::pyvalue::strict_int).unwrap_or(12);
        if min > max {
            return Err(invalid("invalid traffic nonce length range"));
        }
        let custom_ok = match node.get("customHexStrings") {
            None => true,
            Some(Value::Array(items)) => {
                items.len() <= 64
                    && items.iter().all(|item| {
                        item.as_str().is_some_and(|s| {
                            s.chars().count() <= 24 && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                    })
            }
            Some(_) => false,
        };
        if !custom_ok {
            return Err(invalid("invalid traffic nonce custom strings"));
        }
    }
    if let Some(padding) = traffic.get("padding") {
        let node = object(padding, &["maxMiddlePaddingLen", "maxEndPaddingLen"], "padding")?;
        for (key, item) in node {
            bounded_int(Some(item), 0, 255, &format!("padding {key}"))?;
        }
    }
    if let Some(low) = traffic.get("lowEntropy") {
        let node = object(low, &["mode", "maskRotation"], "lowEntropy")?;
        let modes = [
            "LOW_ENTROPY_MODE_OFF",
            "LOW_ENTROPY_MODE_32",
            "LOW_ENTROPY_MODE_40",
            "LOW_ENTROPY_MODE_48",
            "LOW_ENTROPY_MODE_56",
        ];
        if !str_in(node.get("mode"), "LOW_ENTROPY_MODE_OFF", &modes) {
            return Err(invalid("invalid low entropy mode"));
        }
        let rotation_ok = match node.get("maskRotation") {
            None => true,
            Some(Value::String(s)) => {
                s == "LOW_ENTROPY_MASK_NO_ROTATION"
                    || ["RIGHT", "LEFT"].iter().any(|direction| {
                        s.strip_prefix(&format!("LOW_ENTROPY_MASK_ROTATE_{direction}_"))
                            .is_some_and(|amount| (1..16).any(|n| amount == n.to_string()))
                    })
            }
            Some(_) => false,
        };
        if !rotation_ok {
            return Err(invalid("invalid mask rotation"));
        }
    }
    Ok(())
}

/// `[0-9]{1,5}-[0-9]{1,5}` over `str(value)`: only a string can match.
fn port_range(value: &Value) -> Option<(u32, u32)> {
    let text = value.as_str()?;
    let (start, end) = text.split_once('-')?;
    let digits = |s: &str| (1..=5).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    (digits(start) && digits(end)).then(|| (start.parse().ok(), end.parse().ok())).and_then(|(a, b)| Some((a?, b?)))
}

fn dns_host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.trim_matches('.') == host
        && host.chars().count() <= 253
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// `validate_config(config, elevated=…)`; the messages are the Python ones.
pub fn validate_config(config: &Value, elevated: bool) -> Result<()> {
    let config = object(config, TOP_FIELDS, "config")?;
    let bindings = match config.get("portBindings") {
        Some(Value::Array(items)) if !items.is_empty() => items,
        _ => return Err(invalid("at least one port binding is required")),
    };
    let mut occupied: [Vec<(u32, u32)>; 2] = [Vec::new(), Vec::new()];
    for binding in bindings {
        let binding = object(binding, PORT_FIELDS, "port binding")?;
        let slot = match binding.get("protocol").and_then(Value::as_str) {
            Some("TCP") => 0,
            Some("UDP") => 1,
            _ => return Err(invalid("invalid transport protocol")),
        };
        if binding.contains_key("port") == binding.contains_key("portRange") {
            return Err(invalid("binding requires exactly one port or range"));
        }
        let (start, end) = if binding.contains_key("port") {
            let port = bounded_int(binding.get("port"), 1, 65535, "port")? as u32;
            (port, port)
        } else {
            match port_range(&binding["portRange"]) {
                Some((start, end)) if 1 <= start && start <= end && end <= 65535 => (start, end),
                _ => return Err(invalid("invalid port range")),
            }
        };
        if occupied[slot].iter().any(|(lo, hi)| start <= *hi && *lo <= end) {
            return Err(invalid("port bindings overlap"));
        }
        occupied[slot].push((start, end));
    }

    let empty = Vec::new();
    let users = match config.get("users") {
        None => &empty,
        Some(Value::Array(items)) => items,
        Some(_) => return Err(invalid("users must be a list")),
    };
    let mut names: Vec<&str> = Vec::new();
    for user in users {
        let user = object(user, USER_FIELDS, "user")?;
        let name = match user.get("name") {
            Some(Value::String(name)) if !name.is_empty() && name.len() <= 64 => name.as_str(),
            _ => return Err(invalid("user name must be nonempty and at most 64 bytes")),
        };
        if names.contains(&name) {
            return Err(invalid("duplicate user name"));
        }
        names.push(name);
        let (raw, hashed) = (user.get("password"), user.get("hashedPassword"));
        if raw.is_some_and(pc_common::pyvalue::truthy) == hashed.is_some_and(pc_common::pyvalue::truthy) {
            return Err(invalid("user requires exactly one credential"));
        }
        if let Some(raw) = raw.filter(|v| !v.is_null()) {
            if !raw.as_str().is_some_and(|s| s.len() <= 64) {
                return Err(invalid("password must be at most 64 bytes"));
            }
        }
        if let Some(hashed) = hashed.filter(|v| !v.is_null()) {
            if !hashed.as_str().is_some_and(crate::util::is_hex64) {
                return Err(invalid("invalid hashed password"));
            }
        }
        let quotas = match user.get("quotas") {
            None => &empty,
            Some(Value::Array(items)) => items,
            Some(_) => return Err(invalid("invalid quota list")),
        };
        for quota in quotas {
            let quota = object(quota, QUOTA_FIELDS, "quota")?;
            if quota.len() != QUOTA_FIELDS.len() {
                return Err(invalid("quota requires days and megabytes"));
            }
            bounded_int(quota.get("days"), 1, MAX_QUOTA_DAYS, "quota days")?;
            bounded_int(quota.get("megabytes"), 1, MAX_QUOTA_MIB, "quota MiB")?;
        }
        for flag in ["allowPrivateIP", "allowLoopbackIP"] {
            if user.get(flag).is_some_and(|v| !is_bool(v)) {
                return Err(invalid(format!("invalid {flag}")));
            }
            if user.get(flag).is_some_and(pc_common::pyvalue::truthy) && !elevated {
                return Err(invalid("private/loopback SSRF flags require elevated approval"));
            }
        }
    }

    match config.get("mtu") {
        None => {}
        Some(mtu) if pc_common::pyvalue::strict_int(mtu).is_some_and(|n| (1280..=1500).contains(&n)) => {}
        Some(_) => return Err(invalid("MTU must be 1280 through 1500")),
    }
    if !str_in(config.get("loggingLevel"), "DEFAULT", LOG_LEVELS) {
        return Err(invalid("invalid logging level"));
    }
    if let Some(advanced) = config.get("advancedSettings") {
        let node = object(advanced, &["metricsLoggingInterval", "userHintIsMandatory"], "advanced settings")?;
        if let Some(interval) = node.get("metricsLoggingInterval") {
            if go_duration_ns(interval)? < 1_000_000_000 {
                return Err(invalid("invalid metrics interval"));
            }
        }
        if node.get("userHintIsMandatory").is_some_and(|v| !is_bool(v)) {
            return Err(invalid("invalid user hint setting"));
        }
    }
    if let Some(dns) = config.get("dns") {
        let dns = object(dns, &["dualStack", "hosts"], "DNS")?;
        if !str_in(dns.get("dualStack"), "USE_FIRST_IP", DUAL_STACK) {
            return Err(invalid("invalid DNS dual-stack mode"));
        }
        let hosts = match dns.get("hosts") {
            None => None,
            Some(Value::Object(hosts)) => Some(hosts),
            Some(_) => return Err(invalid("invalid DNS hosts")),
        };
        for (host, address) in hosts.into_iter().flatten() {
            if !dns_host_ok(host) {
                return Err(invalid("invalid DNS host"));
            }
            if !pyip::is_address(address) {
                return Err(invalid("invalid DNS address"));
            }
        }
    }
    if let Some(egress) = config.get("egress") {
        validate_egress(object(egress, &["proxies", "rules"], "egress")?)?;
    }
    if let Some(traffic) = config.get("trafficPattern") {
        validate_traffic(traffic)?;
    }
    Ok(())
}

fn validate_egress(egress: &Map<String, Value>) -> Result<()> {
    let empty = Vec::new();
    let (proxies, rules) = match (egress.get("proxies"), egress.get("rules")) {
        (p, r) if p.is_none_or(Value::is_array) && r.is_none_or(Value::is_array) => {
            (p.and_then(Value::as_array).unwrap_or(&empty), r.and_then(Value::as_array).unwrap_or(&empty))
        }
        _ => return Err(invalid("invalid egress lists")),
    };
    let mut proxy_names: Vec<&str> = Vec::new();
    for proxy in proxies {
        let proxy = object(proxy, &["name", "protocol", "host", "port", "socks5Authentication"], "egress proxy")?;
        let name = match proxy.get("name") {
            Some(Value::String(name)) if !name.is_empty() && !proxy_names.contains(&name.as_str()) => name.as_str(),
            _ => return Err(invalid("invalid egress proxy name")),
        };
        proxy_names.push(name);
        let host_ok = proxy.get("host").and_then(Value::as_str).is_some_and(|h| !h.is_empty());
        if proxy.get("protocol").and_then(Value::as_str) != Some("SOCKS5_PROXY_PROTOCOL") || !host_ok {
            return Err(invalid("invalid egress proxy"));
        }
        bounded_int(proxy.get("port"), 1, 65535, "egress port")?;
        if let Some(auth) = proxy.get("socks5Authentication") {
            let auth = object(auth, &["user", "password"], "egress authentication")?;
            if auth.len() != 2 || !auth.values().all(|item| item.as_str().is_some_and(|s| !s.is_empty())) {
                return Err(invalid("invalid egress authentication"));
            }
        }
    }
    for rule in rules {
        let rule = object(rule, &["ipRanges", "domainNames", "action", "proxyNames"], "egress rule")?;
        let action = match rule.get("action") {
            None => "PROXY",
            Some(Value::String(a)) if ["PROXY", "DIRECT", "REJECT"].contains(&a.as_str()) => a.as_str(),
            Some(_) => return Err(invalid("invalid egress action")),
        };
        let names: Vec<&str> = match rule.get("proxyNames") {
            None => Vec::new(),
            Some(Value::Array(items)) if items.iter().all(Value::is_string) => {
                items.iter().filter_map(Value::as_str).collect()
            }
            Some(_) => return Err(invalid("invalid egress proxy name list")),
        };
        if action == "PROXY" && names.is_empty() {
            return Err(invalid("egress rule proxy name list is empty"));
        }
        if action != "PROXY" && !names.is_empty() {
            return Err(invalid("egress rule proxy names must be empty for non-PROXY action"));
        }
        if names.iter().any(|name| !proxy_names.contains(name)) {
            return Err(invalid("egress rule names unknown proxy"));
        }
        let ranges = rule.get("ipRanges");
        let domains = rule.get("domainNames");
        if !ranges.is_none_or(Value::is_array) || !domains.is_none_or(Value::is_array) {
            return Err(invalid("invalid egress match list"));
        }
        for value in ranges.and_then(Value::as_array).unwrap_or(&empty) {
            if value.as_str() != Some("*") && !pyip::is_network(value) {
                return Err(invalid("invalid egress CIDR"));
            }
        }
        for value in domains.and_then(Value::as_array).unwrap_or(&empty) {
            if !value.as_str().is_some_and(|d| !d.is_empty() && d.trim_matches('.') == d) {
                return Err(invalid("invalid egress domain"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{base, with};
    use serde_json::json;

    fn message(config: &Value, elevated: bool) -> String {
        match validate_config(config, elevated) {
            Err(Error::Validation(message)) => message,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn validation_rejects_overlapping_ports_and_unknown_fields() {
        let overlapping = with(
            base(),
            "portBindings",
            json!([{"portRange": "8000-8010", "protocol": "TCP"}, {"port": 8005, "protocol": "TCP"}]),
        );
        assert!(message(&overlapping, false).contains("overlap"));
        assert!(message(&with(base(), "futureDangerousField", json!(true)), false).contains("unknown"));
        // The same port on the other transport is no overlap.
        let both =
            with(base(), "portBindings", json!([{"port": 8443, "protocol": "TCP"}, {"port": 8443, "protocol": "UDP"}]));
        validate_config(&both, false).unwrap();
        for bad in [json!([{"portRange": 8000, "protocol": "TCP"}]), json!([{"portRange": "9-8", "protocol": "TCP"}])] {
            assert_eq!(message(&with(base(), "portBindings", bad), false), "invalid port range");
        }
    }

    #[test]
    fn validation_traffic_pattern_matches_mita_v335_schema() {
        let valid = with(
            base(),
            "trafficPattern",
            json!({
                "seed": 42,
                "unlockAll": true,
                "tcpFragment": {"enable": true, "maxSleepMs": 100},
                "nonce": {"type": "NONCE_TYPE_PRINTABLE_SUBSET", "applyToAllUDPPacket": true, "minLen": 0, "maxLen": 12},
                "padding": {"maxMiddlePaddingLen": 0, "maxEndPaddingLen": 255},
                "lowEntropy": {"mode": "LOW_ENTROPY_MODE_56", "maskRotation": "LOW_ENTROPY_MASK_ROTATE_LEFT_15"},
            }),
        );
        validate_config(&valid, false).unwrap();
        for pattern in [
            json!({"seed": "42"}),
            json!({"tcpFragment": {"maxSleepMs": 101}}),
            json!({"nonce": {"type": "RANDOM"}}),
            json!({"nonce": {"type": "NONCE_TYPE_FIXED", "customHexStrings": ["00".repeat(13)]}}),
            json!({"padding": {"maxEndPaddingLen": 256}}),
            json!({"lowEntropy": {"mode": "LOW_ENTROPY_56"}}),
            json!({"lowEntropy": {"maskRotation": 7}}),
        ] {
            assert!(validate_config(&with(base(), "trafficPattern", pattern.clone()), false).is_err(), "{pattern}");
        }
    }

    #[test]
    fn validation_enforces_user_quota_mtu_dns_and_privileged_flags() {
        let long_name = with(base(), "users", json!([{"name": "é".repeat(33), "hashedPassword": "a".repeat(64)}]));
        assert!(message(&long_name, false).contains("64 bytes"));
        let zero_days = with(
            base(),
            "users",
            json!([{"name": "a", "hashedPassword": "a".repeat(64), "quotas": [{"days": 0, "megabytes": 1}]}]),
        );
        assert!(message(&zero_days, false).contains("quota"));
        assert!(message(&with(base(), "mtu", json!(1501)), false).contains("MTU"));
        let dns = with(base(), "dns", json!({"dualStack": "ONLY_IPv4", "hosts": {"bad host": "127.0.0.1"}}));
        assert!(message(&dns, false).contains("DNS"));
        let loopback =
            with(base(), "users", json!([{"name": "a", "hashedPassword": "a".repeat(64), "allowLoopbackIP": true}]));
        assert!(message(&loopback, false).contains("elevated"));
        validate_config(&loopback, true).unwrap();
    }

    #[test]
    fn validation_rejects_metrics_intervals_outside_go_duration_contract() {
        for interval in ["1ms", "999ms", "0.999999999s", "1 s", "1d", "2562047h47m16.854775808s"] {
            let config = with(base(), "advancedSettings", json!({"metricsLoggingInterval": interval}));
            assert!(message(&config, false).contains("metrics interval"), "{interval}");
        }
    }

    #[test]
    fn validation_accepts_go_durations_at_least_one_second() {
        for interval in ["1s", "1000ms", "1.5s", "1m30s", "+2s"] {
            validate_config(&with(base(), "advancedSettings", json!({"metricsLoggingInterval": interval})), false)
                .unwrap();
        }
    }

    #[test]
    fn validation_matches_egress_proxy_action_and_proto_int32_bounds() {
        let proxy = json!({"name": "out", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 1080});
        let empty_names = with(base(), "egress", json!({"proxies": [proxy], "rules": [{"action": "PROXY"}]}));
        assert!(message(&empty_names, false).contains("proxy name"));
        let direct_named =
            with(base(), "egress", json!({"proxies": [proxy], "rules": [{"action": "DIRECT", "proxyNames": ["out"]}]}));
        assert!(message(&direct_named, false).contains("non-PROXY"));
        let max = (1i64 << 31) - 1;
        let quotas =
            json!([{"name": "alice", "hashedPassword": "a".repeat(64), "quotas": [{"days": max, "megabytes": max}]}]);
        validate_config(&with(base(), "users", quotas), false).unwrap();
    }
}
