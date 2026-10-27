//! The routing intent of one service on the dedicated Xray router (v0.5, ADR 007).
//!
//! The panel compiles a policy into this document and nothing else: no Xray JSON, no file
//! paths, no list URLs. It names what the operator wants for one ingress tag — a default for
//! the whole service, then ordered first-match rules over domains, `geosite` codes, CIDRs,
//! `geoip` codes and ports — and the manager alone turns it into the config Xray runs.
//!
//! ```text
//! {"schema": 1,
//!  "default": {"action": "direct" | "egress", "egress": "warp" | null},
//!  "rules": [{"domains": [...], "geosites": [...], "cidrs": [...], "geoips": [...],
//!             "ports": [...], "action": "direct" | "block" | "egress", "egress": "warp" | null}]}
//! ```
//!
//! Limits are the routing spec's (128 rules, 64 selectors of each kind and 32 ports per rule,
//! 16 KiB per document); `geoip:private` is the router's own bypass and never a rule.
//!
//! Schema 2 (v0.7, docs/spikes/CHAINS_PER_CLIENT.md) carries the same vocabulary per *lane* — the
//! service's own lane `svc:<service>` and one `grant:<id>` lane per client with its own routing —
//! and *chains*: an egress may be `chain:<id>`, a list of up to three hops (another node's relay
//! inbound, VLESS+Reality) and what the last hop does with the connection (`direct` or its
//! `warp`). v0.8 adds `exits`, the operator's own outbounds (`exit:<id>`).
//!
//! A schema-1 document is one service lane; [`lanes_of`] presents either form the same way.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::errors::{Error, Result};
use crate::ipaddr;
use crate::pyjson;
use crate::util::{py_decimal, py_eq_int, py_int, sha256_hex};
use pc_common::pytext::{is_space as py_isspace, strip as py_strip};
use pc_common::pyvalue::{strict_int as json_int, truthy as py_truthy};

pub const SCHEMA: i64 = 1;
pub const SERVICES: [&str; 5] = ["naive", "mieru", "mtproxy", "trusttunnel", "amneziawg"];
pub const PORTS: [(&str, i64); 2] = [("naive", 45101), ("mieru", 45102)];
/// v1.6: TrustTunnel's endpoint forwards through a plain SOCKS5 client that offers no credentials,
/// so its ingress is a no-auth SOCKS inbound on the host loopback — served only when the router's
/// environment names the port, and without client lanes.
#[cfg(test)]
pub const TRUSTTUNNEL_PORT: i64 = 45104;
pub const NOAUTH_SERVICES: [&str; 1] = ["trusttunnel"];
pub const NO_LANE_SERVICES: [&str; 3] = ["mtproxy", "trusttunnel", "amneziawg"];
/// v3.0.0: AmneziaWG's ingress is a `tun` inbound on a device the AWG manager creates; its `warp`
/// is a WireGuard outbound to WARP with an account of the router's own.
pub const TUN_SERVICES: [&str; 1] = ["amneziawg"];
pub const WARP_WG_TAG: &str = "warp-wg";
/// v1.1: MTProxy's ingress is a `vless` inbound on a Unix socket shared with the bridge.
pub const MTPROXY_SOCKET: &str = "/run/xray-router/ingress-mtproxy.sock";
pub const MTPROXY_BRIDGE_ADDRESS: &str = "xray-router-ingress:45103";
pub const PROVIDERS: [&str; 1] = ["warp"];
pub const ACTIONS: [&str; 3] = ["direct", "block", "egress"];
pub const DEFAULT_ACTIONS: [&str; 2] = ["direct", "egress"];
/// What the spike proved this router enforces (docs/spikes/XRAY_EGRESS_ROUTER.md).
pub const CAPABILITIES: [&str; 16] = [
    "whole_direct",
    "whole_warp",
    "block_domain",
    "block_cidr",
    "block_port",
    "block_geosite",
    "block_geoip",
    "selective_domain",
    "selective_cidr",
    "selective_port",
    "selective_geosite",
    "selective_geoip",
    "geodata",
    "block_protocol",
    "selective_protocol",
    "custom_exits",
];
pub const EXIT_PROTOCOLS: [&str; 5] = ["socks", "http", "vless", "trojan", "shadowsocks"];
pub const EXIT_NETWORKS: [&str; 4] = ["tcp", "ws", "grpc", "xhttp"];
pub const EXIT_SECURITY: [&str; 3] = ["none", "tls", "reality"];
pub const EXIT_FLOWS: [&str; 2] = ["", "xtls-rprx-vision"];
pub const SS_METHODS: [&str; 7] = [
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
];
pub const MAX_EXITS: usize = 16;
const FINGERPRINTS: [&str; 10] =
    ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"];
pub const SNIFFED_PROTOCOLS: [&str; 4] = ["http", "tls", "quic", "bittorrent"];
pub const MAX_PROTOCOLS: usize = 4;
pub const MAX_RULES: usize = 128;
pub const MAX_SELECTORS: usize = 64;
pub const MAX_PORTS: usize = 32;
pub const MAX_DOCUMENT_BYTES: usize = 16384;
pub const SCHEMA_V2: i64 = 2;
pub const MAX_LANES: usize = 32;
pub const MAX_CHAINS: usize = 16;
pub const MAX_HOPS: usize = 3;
pub const MAX_DOCUMENT_BYTES_V2: usize = 65536;
pub const CHAIN_EXITS: [&str; 2] = ["direct", "warp"];

fn is_in(value: Option<&Value>, set: &[&str]) -> bool {
    value.and_then(Value::as_str).is_some_and(|text| set.contains(&text))
}

fn word(text: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `[A-Za-z0-9_-]{1,32}`: an exit or chain id.
pub fn is_short_word(text: &str) -> bool {
    word(text, 1, 32)
}

/// `(?:svc:(?:naive|mieru|mtproxy|trusttunnel|amneziawg)|grant:[A-Za-z0-9_-]{1,64})`
pub fn is_lane(text: &str) -> bool {
    match text.strip_prefix("svc:") {
        Some(service) => SERVICES.contains(&service),
        None => text.strip_prefix("grant:").is_some_and(|id| word(id, 1, 64)),
    }
}

/// `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
pub fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, len)| {
            group.len() == len && group.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// `[A-Za-z0-9_-]{43}`: an X25519 public key, base64url.
pub fn is_public_key(text: &str) -> bool {
    word(text, 43, 43)
}

/// `(?:[0-9a-f]{2}){0,8}`
pub fn is_short_id(text: &str) -> bool {
    text.len() <= 16 && text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The `_DOMAIN` pattern: 1–253 characters, dot-separated labels of `[a-z0-9-]`, 1–63 long, no
/// hyphen at either end.
pub fn is_dns_name(host: &str) -> bool {
    let count = host.chars().count();
    if !(1..=253).contains(&count) || host.contains('\n') {
        return false;
    }
    host.split('.').all(|label| {
        let bytes = label.as_bytes();
        (1..=63).contains(&bytes.len())
            && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-'
    })
}

/// `[a-z0-9][a-z0-9@!_-]{0,63}`
fn is_geo_code(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'@' | b'!' | b'_' | b'-'))
}

pub fn canonical(document: &Value) -> Vec<u8> {
    pyjson::dumps(document, &pyjson::SORTED).into_bytes()
}

pub fn document_digest(document: &Value) -> String {
    sha256_hex(&canonical(document))
}

/// The floor of every service: pass-through, no rules — what a fresh router runs.
pub fn direct_document() -> Value {
    json!({"schema": SCHEMA, "default": {"action": "direct", "egress": null}, "rules": []})
}

fn domain(value: Option<&Value>) -> Result<String> {
    let invalid = || Error::invalid("invalid domain");
    let text = value.and_then(Value::as_str).ok_or_else(invalid)?;
    if text.is_empty() || text.chars().count() > 255 || text.chars().any(py_isspace) {
        return Err(invalid());
    }
    let candidate = text.to_lowercase().trim_end_matches('.').to_string();
    let host = candidate.strip_prefix("*.").unwrap_or(&candidate);
    if host.is_empty() || host.contains('*') || host.contains('/') || !is_dns_name(host) {
        return Err(invalid());
    }
    Ok(candidate)
}

fn cidr(value: &Value) -> Result<Value> {
    let invalid = || Error::invalid("invalid cidr");
    let text = value.as_str().map(py_strip).filter(|text| !text.is_empty()).ok_or_else(invalid)?;
    ipaddr::network(text).map(Value::String).ok_or_else(invalid)
}

fn geo_code(value: &Value, kind: &str) -> Result<Value> {
    match value.as_str() {
        Some(text) if is_geo_code(text) => {
            if kind == "geoip" && text == "private" {
                return Err(Error::invalid("geoip:private is the router's bypass, not a rule"));
            }
            Ok(value.clone())
        }
        _ => Err(Error::invalid(format!("invalid {kind} code"))),
    }
}

fn protocol_name(value: &Value) -> Result<Value> {
    if is_in(Some(value), &SNIFFED_PROTOCOLS) {
        Ok(value.clone())
    } else {
        Err(Error::invalid("invalid protocol selector"))
    }
}

fn port_number(value: i128) -> Result<Value> {
    if (1..=65535).contains(&value) {
        Ok(Value::from(value as u64))
    } else {
        Err(Error::invalid("invalid port"))
    }
}

/// `([0-9]{1,5})-([0-9]{1,5})`
fn port_range(text: &str) -> Option<(u32, u32)> {
    let (low, high) = text.split_once('-')?;
    let ok = |part: &str| (1..=5).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit());
    (ok(low) && ok(high)).then(|| (low.parse().unwrap_or(0), high.parse().unwrap_or(0)))
}

fn port(value: &Value) -> Result<Value> {
    let invalid = || Error::invalid("invalid port");
    match value {
        Value::Bool(_) => Err(invalid()),
        Value::Number(_) => match json_int(value) {
            Some(number) => port_number(number),
            None => Err(invalid()),
        },
        Value::String(text) => {
            let text = py_strip(text);
            // `str.isdigit()` then `int()`: Unicode decimal digits read as numbers.
            if !text.is_empty() && text.chars().all(|c| py_decimal(c).is_some()) {
                return port_number(py_int(text, 10).unwrap_or(i128::MAX));
            }
            match port_range(text) {
                Some((low, high)) if 1 <= low && low <= high && high <= 65535 => {
                    Ok(Value::String(format!("{low}-{high}")))
                }
                _ => Err(invalid()),
            }
        }
        _ => Err(invalid()),
    }
}

fn unique(items: Vec<Value>) -> Vec<Value> {
    let mut seen: Vec<Value> = Vec::new();
    for item in items {
        if !seen.contains(&item) {
            seen.push(item);
        }
    }
    seen
}

fn selectors(
    rule: &Map<String, Value>,
    key: &str,
    convert: impl Fn(&Value) -> Result<Value>,
    limit: usize,
) -> Result<Vec<Value>> {
    let values = match rule.get(key) {
        None => return Ok(Vec::new()),
        Some(Value::Array(values)) if values.len() <= limit => values,
        _ => return Err(Error::invalid(format!("invalid {key} list"))),
    };
    Ok(unique(values.iter().map(convert).collect::<Result<Vec<_>>>()?))
}

fn egress(action: &str, egress: Option<&Value>, label: &str, chains: &[String], exits: &[String]) -> Result<Value> {
    let egress = egress.filter(|value| !value.is_null());
    if action == "egress" {
        if let Some(text) = egress.and_then(Value::as_str) {
            let known = PROVIDERS.contains(&text)
                || text.strip_prefix("chain:").is_some_and(|id| chains.iter().any(|c| c == id))
                || text.strip_prefix("exit:").is_some_and(|id| exits.iter().any(|e| e == id));
            if known {
                return Ok(Value::String(text.to_string()));
            }
        }
        return Err(Error::invalid(format!("{label} must name its egress provider")));
    }
    if egress.is_some() {
        return Err(Error::invalid(format!("only an egress {label} names an egress provider")));
    }
    Ok(Value::Null)
}

fn only_keys(map: &Map<String, Value>, allowed: &[&str]) -> bool {
    map.keys().all(|key| allowed.contains(&key.as_str()))
}

/// The intent, normalised, or `EgressInvalid`. Bounded, secret-free, nothing raw.
pub fn validate_document(document: &Value) -> Result<Value> {
    if let Value::Object(map) = document {
        if py_eq_int(map.get("schema"), SCHEMA_V2) {
            return validate_v2(map);
        }
    }
    let map = match document {
        Value::Object(map) if only_keys(map, &["schema", "default", "rules"]) => map,
        _ => return Err(Error::invalid("unknown field in routing intent")),
    };
    if !py_eq_int(map.get("schema"), SCHEMA) {
        return Err(Error::invalid("unsupported routing intent schema"));
    }
    let lane = validate_lane(document, &[], &[])?;
    if canonical(&lane).len() > MAX_DOCUMENT_BYTES {
        return Err(Error::invalid("routing intent too large"));
    }
    let mut out = Map::new();
    out.insert("schema".into(), SCHEMA.into());
    out.extend(lane.as_object().expect("a lane is an object").clone());
    Ok(Value::Object(out))
}

/// One lane's body — a default and its first-match rules — normalised.
fn validate_lane(document: &Value, chains: &[String], exits: &[String]) -> Result<Value> {
    let map = match document {
        Value::Object(map) if only_keys(map, &["schema", "default", "rules"]) => map,
        _ => return Err(Error::invalid("unknown field in routing intent")),
    };
    let default = match map.get("default") {
        Some(Value::Object(default))
            if only_keys(default, &["action", "egress"]) && is_in(default.get("action"), &DEFAULT_ACTIONS) =>
        {
            default
        }
        _ => return Err(Error::invalid("invalid default")),
    };
    let default_action = default["action"].as_str().expect("checked above").to_string();
    let default_egress = egress(&default_action, default.get("egress"), "default", chains, exits)?;
    let no_rules = Vec::new();
    let rules = match map.get("rules") {
        None => &no_rules,
        Some(Value::Array(rules)) if rules.len() <= MAX_RULES => rules,
        _ => return Err(Error::invalid("invalid rules list")),
    };
    let mut normalised = Vec::with_capacity(rules.len());
    for rule in rules {
        let rule = match rule {
            Value::Object(rule)
                if only_keys(
                    rule,
                    &["domains", "geosites", "cidrs", "geoips", "ports", "protocols", "action", "egress"],
                ) =>
            {
                rule
            }
            _ => return Err(Error::invalid("invalid rule")),
        };
        if !is_in(rule.get("action"), &ACTIONS) {
            return Err(Error::invalid("invalid rule action"));
        }
        let action = rule["action"].as_str().expect("checked above");
        let mut entry = Map::new();
        entry.insert(
            "domains".into(),
            Value::Array(selectors(rule, "domains", |v| domain(Some(v)).map(Value::String), MAX_SELECTORS)?),
        );
        entry.insert(
            "geosites".into(),
            Value::Array(selectors(rule, "geosites", |v| geo_code(v, "geosite"), MAX_SELECTORS)?),
        );
        entry.insert("cidrs".into(), Value::Array(selectors(rule, "cidrs", cidr, MAX_SELECTORS)?));
        entry
            .insert("geoips".into(), Value::Array(selectors(rule, "geoips", |v| geo_code(v, "geoip"), MAX_SELECTORS)?));
        entry.insert("ports".into(), Value::Array(selectors(rule, "ports", port, MAX_PORTS)?));
        entry.insert("action".into(), Value::String(action.to_string()));
        entry.insert("egress".into(), egress(action, rule.get("egress"), "rule", chains, exits)?);
        let protocols = selectors(rule, "protocols", protocol_name, MAX_PROTOCOLS)?;
        if !protocols.is_empty() {
            entry.insert("protocols".into(), Value::Array(protocols));
        }
        let named = ["domains", "geosites", "cidrs", "geoips", "ports", "protocols"]
            .iter()
            .any(|key| entry.get(*key).is_some_and(py_truthy));
        if !named {
            return Err(Error::invalid("a rule must name at least one selector"));
        }
        normalised.push(Value::Object(entry));
    }
    Ok(json!({"default": {"action": default_action, "egress": default_egress}, "rules": normalised}))
}

fn hop(value: &Value) -> Result<Value> {
    const FIELDS: [&str; 7] = ["guid", "address", "port", "server_name", "public_key", "short_id", "uuid"];
    let map = match value {
        Value::Object(map) if map.len() == FIELDS.len() && only_keys(map, &FIELDS) => map,
        _ => return Err(Error::invalid("invalid chain hop")),
    };
    let text = |key: &str| map[key].as_str();
    if !text("guid").is_some_and(|guid| word(guid, 1, 64)) {
        return Err(Error::invalid("invalid hop guid"));
    }
    let address = match text("address") {
        Some(address) if !address.is_empty() => address,
        _ => return Err(Error::invalid("invalid hop address")),
    };
    let address = if ipaddr::is_ip_address(address) {
        address.to_string()
    } else {
        let host = domain(Some(&map["address"]))?;
        if host.starts_with("*.") {
            return Err(Error::invalid("invalid hop address"));
        }
        host
    };
    if !json_int(&map["port"]).is_some_and(|port| (1..=65535).contains(&port)) {
        return Err(Error::invalid("invalid hop port"));
    }
    let server_name = domain(Some(&map["server_name"]))?;
    if server_name.starts_with("*.") {
        return Err(Error::invalid("invalid hop server name"));
    }
    if !text("public_key").is_some_and(is_public_key) {
        return Err(Error::invalid("invalid hop public key"));
    }
    if !text("short_id").is_some_and(is_short_id) {
        return Err(Error::invalid("invalid hop short id"));
    }
    if !text("uuid").is_some_and(is_uuid) {
        return Err(Error::invalid("invalid hop credential"));
    }
    Ok(json!({"guid": map["guid"], "address": address, "port": map["port"], "server_name": server_name,
              "public_key": map["public_key"], "short_id": map["short_id"], "uuid": map["uuid"]}))
}

fn host(value: Option<&Value>, label: &str) -> Result<String> {
    let invalid = || Error::invalid(format!("invalid {label}"));
    let text = value.and_then(Value::as_str).filter(|text| !text.is_empty()).ok_or_else(invalid)?;
    if ipaddr::is_ip_address(text) {
        return Ok(text.to_string());
    }
    let host = domain(value)?;
    if host.starts_with("*.") {
        return Err(invalid());
    }
    Ok(host)
}

fn text(value: Option<&Value>, label: &str, limit: usize, allow_empty: bool) -> Result<Value> {
    match value.and_then(Value::as_str) {
        Some(text)
            if text.chars().count() <= limit
                && (allow_empty || !text.is_empty())
                && !text.contains(['\r', '\n', '\0']) =>
        {
            Ok(Value::String(text.to_string()))
        }
        _ => Err(Error::invalid(format!("invalid {label}"))),
    }
}

/// `value or default`: Python's falsy values give way.
fn or_default<'a>(value: Option<&'a Value>, default: &'a Value) -> &'a Value {
    match value {
        Some(value) if py_truthy(value) => value,
        _ => default,
    }
}

/// `value not in (None, "")`
fn present(value: Option<&Value>) -> bool {
    !matches!(value, None | Some(Value::Null)) && value.and_then(Value::as_str) != Some("")
}

/// One custom outbound of the intent: protocol, where to dial, the credential, the transport and
/// the security layer — bounded, and nothing Xray would not understand.
pub fn validate_exit(value: &Value) -> Result<Value> {
    let map = match value {
        Value::Object(map)
            if only_keys(
                map,
                &["protocol", "address", "port", "credential", "transport", "security", "method", "flow"],
            ) =>
        {
            map
        }
        _ => return Err(Error::invalid("invalid exit")),
    };
    if !is_in(map.get("protocol"), &EXIT_PROTOCOLS) {
        return Err(Error::invalid("invalid exit protocol"));
    }
    let protocol = map["protocol"].as_str().expect("checked above");
    let tcp_only = matches!(protocol, "socks" | "http" | "shadowsocks");
    let address = host(map.get("address"), "exit address")?;
    let port = map.get("port").filter(|port| json_int(port).is_some_and(|p| (1..=65535).contains(&p)));
    let port = port.ok_or_else(|| Error::invalid("invalid exit port"))?.clone();
    let empty = json!({});
    let credential = match or_default(map.get("credential"), &empty) {
        Value::Object(credential) if only_keys(credential, &["username", "password", "uuid"]) => credential,
        _ => return Err(Error::invalid("invalid exit credential")),
    };
    let given = |key: &str| credential.get(key).filter(|value| !value.is_null());
    let mut out_credential = Map::new();
    match protocol {
        "socks" | "http" => {
            if given("username").is_some() != given("password").is_some() {
                return Err(Error::invalid("exit credential needs both username and password"));
            }
            if given("username").is_some() {
                out_credential.insert("username".into(), text(given("username"), "exit username", 128, false)?);
                out_credential.insert("password".into(), text(given("password"), "exit password", 256, false)?);
            }
        }
        "vless" => match given("uuid").and_then(Value::as_str) {
            Some(uuid) if is_uuid(uuid) => {
                out_credential.insert("uuid".into(), Value::String(uuid.to_string()));
            }
            _ => return Err(Error::invalid("invalid exit uuid")),
        },
        _ => {
            out_credential.insert("password".into(), text(credential.get("password"), "exit password", 256, false)?);
        }
    }
    let mut entry = Map::new();
    entry.insert("protocol".into(), Value::String(protocol.to_string()));
    entry.insert("address".into(), Value::String(address));
    entry.insert("port".into(), port);
    entry.insert("credential".into(), Value::Object(out_credential));
    if protocol == "shadowsocks" {
        if !is_in(map.get("method"), &SS_METHODS) {
            return Err(Error::invalid("invalid shadowsocks method"));
        }
        entry.insert("method".into(), map["method"].clone());
    }
    let none = Value::String(String::new());
    let flow = or_default(map.get("flow"), &none);
    if protocol == "vless" {
        if !is_in(Some(flow), &EXIT_FLOWS) {
            return Err(Error::invalid("invalid exit flow"));
        }
        entry.insert("flow".into(), flow.clone());
    }
    let tcp = json!({"network": "tcp"});
    let transport = match or_default(map.get("transport"), &tcp) {
        Value::Object(transport) if only_keys(transport, &["network", "path", "host", "service_name"]) => transport,
        _ => return Err(Error::invalid("invalid exit transport")),
    };
    let network = transport.get("network").unwrap_or(&tcp["network"]);
    if !is_in(Some(network), &EXIT_NETWORKS) {
        return Err(Error::invalid("invalid exit transport network"));
    }
    let network = network.as_str().expect("checked above");
    if tcp_only && network != "tcp" {
        return Err(Error::invalid("this exit protocol runs over tcp only"));
    }
    let mut out_transport = Map::new();
    out_transport.insert("network".into(), Value::String(network.to_string()));
    for key in ["path", "host", "service_name"] {
        if present(transport.get(key)) {
            out_transport.insert(key.into(), text(transport.get(key), &format!("exit transport {key}"), 512, false)?);
        }
    }
    entry.insert("transport".into(), Value::Object(out_transport));
    let plain = json!({"kind": "none"});
    let security = match or_default(map.get("security"), &plain) {
        Value::Object(security)
            if only_keys(
                security,
                &["kind", "server_name", "fingerprint", "alpn", "public_key", "short_id", "insecure"],
            ) =>
        {
            security
        }
        _ => return Err(Error::invalid("invalid exit security")),
    };
    let kind = security.get("kind").unwrap_or(&plain["kind"]);
    if !is_in(Some(kind), &EXIT_SECURITY) {
        return Err(Error::invalid("invalid exit security kind"));
    }
    let kind = kind.as_str().expect("checked above");
    if tcp_only && kind == "reality" {
        return Err(Error::invalid("reality needs vless or trojan"));
    }
    let mut out_security = Map::new();
    out_security.insert("kind".into(), Value::String(kind.to_string()));
    if kind != "none" {
        if present(security.get("server_name")) {
            out_security
                .insert("server_name".into(), Value::String(host(security.get("server_name"), "exit server name")?));
        }
        let chrome = Value::String("chrome".into());
        let fingerprint = or_default(security.get("fingerprint"), &chrome);
        if !is_in(Some(fingerprint), &FINGERPRINTS) {
            return Err(Error::invalid("invalid exit fingerprint"));
        }
        out_security.insert("fingerprint".into(), fingerprint.clone());
        if present(security.get("alpn")) {
            match &security["alpn"] {
                Value::Array(items)
                    if items.len() <= 4
                        && items
                            .iter()
                            .all(|item| item.as_str().is_some_and(|t| (1..=16).contains(&t.chars().count()))) =>
                {
                    out_security.insert("alpn".into(), Value::Array(items.clone()));
                }
                _ => return Err(Error::invalid("invalid exit alpn")),
            }
        }
        if kind == "tls" && security.get("insecure") == Some(&Value::Bool(true)) {
            out_security.insert("insecure".into(), Value::Bool(true));
        }
    }
    if kind == "reality" {
        let short_id = or_default(security.get("short_id"), &none);
        if !security.get("public_key").and_then(Value::as_str).is_some_and(is_public_key) {
            return Err(Error::invalid("invalid exit public key"));
        }
        if !short_id.as_str().is_some_and(|id| id.is_empty() || is_short_id(id)) {
            return Err(Error::invalid("invalid exit short id"));
        }
        if !out_security.contains_key("server_name") {
            return Err(Error::invalid("reality needs a server name"));
        }
        out_security.insert("public_key".into(), security["public_key"].clone());
        out_security.insert("short_id".into(), short_id.clone());
    }
    if protocol == "vless" && py_truthy(&entry["flow"]) && (network != "tcp" || kind == "none") {
        return Err(Error::invalid("xtls-rprx-vision needs tcp with tls or reality"));
    }
    entry.insert("security".into(), Value::Object(out_security));
    Ok(Value::Object(entry))
}

fn validate_v2(document: &Map<String, Value>) -> Result<Value> {
    if !only_keys(document, &["schema", "lanes", "chains", "exits"]) {
        return Err(Error::invalid("unknown field in routing intent"));
    }
    let (no_exits, no_chains) = (Map::new(), Map::new());
    let exits = match document.get("exits") {
        None => &no_exits,
        Some(Value::Object(exits)) if exits.len() <= MAX_EXITS => exits,
        _ => return Err(Error::invalid("invalid exits list")),
    };
    let mut normalised_exits = Map::new();
    for (exit_id, exit) in exits {
        if !is_short_word(exit_id) {
            return Err(Error::invalid("invalid exit id"));
        }
        normalised_exits.insert(exit_id.clone(), validate_exit(exit)?);
    }
    let chains = match document.get("chains") {
        None => &no_chains,
        Some(Value::Object(chains)) if chains.len() <= MAX_CHAINS => chains,
        _ => return Err(Error::invalid("invalid chains list")),
    };
    let mut normalised_chains = Map::new();
    for (chain_id, chain) in chains {
        if !is_short_word(chain_id) {
            return Err(Error::invalid("invalid chain id"));
        }
        let chain = match chain {
            Value::Object(chain) if chain.len() == 2 && only_keys(chain, &["hops", "exit"]) => chain,
            _ => return Err(Error::invalid("invalid chain")),
        };
        let hops = match &chain["hops"] {
            Value::Array(hops) if (1..=MAX_HOPS).contains(&hops.len()) => hops,
            _ => return Err(Error::invalid("a chain has one to three hops")),
        };
        if !is_in(chain.get("exit"), &CHAIN_EXITS) {
            return Err(Error::invalid("a chain exits direct or through its last hop's warp"));
        }
        let hops = hops.iter().map(hop).collect::<Result<Vec<_>>>()?;
        normalised_chains.insert(chain_id.clone(), json!({"hops": hops, "exit": chain["exit"]}));
    }
    let lanes = match document.get("lanes") {
        Some(Value::Object(lanes)) if !lanes.is_empty() && lanes.len() <= MAX_LANES => lanes,
        _ => return Err(Error::invalid("invalid lanes list")),
    };
    let chain_ids: Vec<String> = normalised_chains.keys().cloned().collect();
    let exit_ids: Vec<String> = normalised_exits.keys().cloned().collect();
    let mut normalised_lanes = Map::new();
    for (lane_id, lane) in lanes {
        if !is_lane(lane_id) {
            return Err(Error::invalid("invalid lane id"));
        }
        normalised_lanes.insert(lane_id.clone(), validate_lane(lane, &chain_ids, &exit_ids)?);
    }
    if normalised_lanes.keys().filter(|lane| lane.starts_with("svc:")).count() != 1 {
        return Err(Error::invalid("exactly one service lane is required"));
    }
    let mut normalised = Map::new();
    normalised.insert("schema".into(), SCHEMA_V2.into());
    normalised.insert("lanes".into(), Value::Object(normalised_lanes));
    normalised.insert("chains".into(), Value::Object(normalised_chains));
    if !normalised_exits.is_empty() {
        // Only when named: a v0.7 router refuses an unknown key, and a document without exits
        // hashes as it always did.
        normalised.insert("exits".into(), Value::Object(normalised_exits));
    }
    let normalised = Value::Object(normalised);
    if canonical(&normalised).len() > MAX_DOCUMENT_BYTES_V2 {
        return Err(Error::invalid("routing intent too large"));
    }
    Ok(normalised)
}

pub fn is_v2(document: &Value) -> bool {
    py_eq_int(document.get("schema"), SCHEMA_V2)
}

/// Either schema as lanes: a schema-1 document is the service's own lane.
pub fn lanes_of(document: &Value, service: &str) -> Map<String, Value> {
    if is_v2(document) {
        return document.get("lanes").and_then(Value::as_object).cloned().unwrap_or_default();
    }
    let mut lanes = Map::new();
    lanes.insert(
        format!("svc:{service}"),
        json!({"default": document.get("default").cloned().unwrap_or(Value::Null),
               "rules": document.get("rules").cloned().unwrap_or(Value::Null)}),
    );
    lanes
}

#[cfg(test)]
pub fn chain_ids(document: &Value) -> Vec<String> {
    if !is_v2(document) {
        return Vec::new();
    }
    document.get("chains").and_then(Value::as_object).map(|chains| chains.keys().cloned().collect()).unwrap_or_default()
}

fn lane_egresses(lane: &Value) -> impl Iterator<Item = &Value> {
    let default = lane.get("default").and_then(|d| d.get("egress"));
    let rules = lane.get("rules").and_then(Value::as_array).into_iter().flatten().filter_map(|rule| rule.get("egress"));
    default.into_iter().chain(rules)
}

fn uses_egress(document: &Value, target: &str) -> bool {
    lanes_of(document, "").values().any(|lane| lane_egresses(lane).any(|egress| egress.as_str() == Some(target)))
}

#[cfg(test)]
pub fn uses_chain(document: &Value, chain_id: &str) -> bool {
    uses_egress(document, &format!("chain:{chain_id}"))
}

pub fn uses_provider(document: &Value) -> bool {
    uses_egress(document, "warp")
}

/// The intent with every hop credential and exit credential masked — what may reach a log, a
/// diff or an API answer.
pub fn redact_intent(document: &Value) -> Value {
    let mut masked = document.clone();
    if !is_v2(document) {
        return masked;
    }
    if let Some(chains) = masked.get_mut("chains").and_then(Value::as_object_mut) {
        for chain in chains.values_mut() {
            for hop in chain.get_mut("hops").and_then(Value::as_array_mut).into_iter().flatten() {
                if let Some(hop) = hop.as_object_mut() {
                    hop.insert("uuid".into(), Value::String("***".into()));
                }
            }
        }
    }
    if let Some(exits) = masked.get_mut("exits").and_then(Value::as_object_mut) {
        for exit in exits.values_mut() {
            if let Some(exit) = exit.as_object_mut() {
                let keys: Vec<String> = exit
                    .get("credential")
                    .and_then(Value::as_object)
                    .map(|c| c.keys().cloned().collect())
                    .unwrap_or_default();
                let credential: Map<String, Value> =
                    keys.into_iter().map(|key| (key, Value::String("***".into()))).collect();
                exit.insert("credential".into(), Value::Object(credential));
            }
        }
    }
    masked
}

/// `urllib.parse.urlsplit(url)`: its scheme and the `hostname`/`port` properties.
pub struct UrlParts {
    pub scheme: String,
    pub hostname: Option<String>,
    pub port: Option<u16>,
}

/// What `urlsplit` and `.port` raise `ValueError` for comes back as `Err`.
pub fn urlsplit(url: &str) -> std::result::Result<UrlParts, String> {
    let url: String =
        url.trim_start_matches(|c: char| c <= ' ').chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let (scheme, rest) = match url.find(':') {
        Some(index)
            if index > 0
                && url.as_bytes()[0].is_ascii_alphabetic()
                && url[..index].bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')) =>
        {
            (url[..index].to_ascii_lowercase(), &url[index + 1..])
        }
        _ => (String::new(), url.as_str()),
    };
    let netloc = match rest.strip_prefix("//") {
        Some(after) => &after[..after.find(['/', '?', '#']).unwrap_or(after.len())],
        None => "",
    };
    if netloc.contains('[') != netloc.contains(']') {
        return Err("Invalid IPv6 URL".into());
    }
    let hostinfo = netloc.rsplit_once('@').map(|(_, host)| host).unwrap_or(netloc);
    let (hostname, port) = match hostinfo.split_once('[') {
        Some((_, bracketed)) => {
            let (hostname, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !hostname.starts_with('v') && ipaddr::parse_v6(hostname).is_none() {
                return Err(format!("'{hostname}' does not appear to be an IPv4 or IPv6 address"));
            }
            (hostname, after.split_once(':').map(|(_, port)| port).unwrap_or(""))
        }
        None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
    };
    let hostname = (!hostname.is_empty()).then(|| match hostname.split_once('%') {
        Some((host, zone)) => format!("{}%{zone}", host.to_lowercase()),
        None => hostname.to_lowercase(),
    });
    let port = if port.is_empty() {
        None
    } else {
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("Port could not be cast to integer value as '{port}'"));
        }
        match port.parse::<u32>() {
            Ok(port) if port <= 65535 => Some(port as u16),
            _ => return Err("Port out of range 0-65535".into()),
        }
    };
    Ok(UrlParts { scheme, hostname, port })
}

/// Host and port of the provider's SOCKS5 endpoint; the router's `socks` outbound.
pub fn provider_endpoint(provider_url: Option<&str>) -> Result<(String, u16)> {
    let url = provider_url.filter(|url| !url.is_empty());
    let url = url.ok_or_else(|| Error::invalid("egress provider warp is not configured on this node"))?;
    let parts = urlsplit(url).map_err(Error::Internal)?;
    match (parts.scheme.as_str(), parts.hostname, parts.port) {
        ("socks5" | "socks5h", Some(host), Some(port)) if port != 0 => Ok((host, port)),
        _ => Err(Error::invalid("egress provider warp must be a socks5:// endpoint")),
    }
}

/// A SOCKS5 greeting without authentication; never fails — the answer is the fact.
pub fn check_reachable(url: Option<&str>, timeout: f64) -> bool {
    let Ok((host, port)) = provider_endpoint(url) else { return false };
    let timeout = Duration::from_secs_f64(timeout);
    let Ok(addresses) = (host.as_str(), port).to_socket_addrs() else { return false };
    for address in addresses {
        let Ok(mut stream) = TcpStream::connect_timeout(&address, timeout) else { continue };
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        if stream.write_all(b"\x05\x01\x00").is_err() {
            return false;
        }
        let mut reply = [0u8; 2];
        return matches!(stream.read(&mut reply), Ok(2) if reply == [5, 0]);
    }
    false
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const HOP: &str = r#"{"guid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "address": "panel.node-b.example.org", "port": 45443,
        "server_name": "panel.node-b.example.org", "public_key": "SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s",
        "short_id": "0123abcd", "uuid": "3f0d9c6e-1b4e-4a6b-9a1e-2c8f5d7e9a10"}"#;

    pub fn hop() -> Value {
        serde_json::from_str(HOP).unwrap()
    }

    pub fn with(value: &Value, changes: Value) -> Value {
        let mut out = value.clone();
        for (key, item) in changes.as_object().unwrap() {
            out[key] = item.clone();
        }
        out
    }

    fn doc(rules: Value, default: Option<Value>) -> Value {
        json!({"schema": 1, "default": default.unwrap_or(json!({"action": "direct", "egress": null})), "rules": rules})
    }

    fn v2(lanes: Option<Value>, chains: Option<Value>) -> Value {
        json!({"schema": 2,
               "lanes": lanes.unwrap_or(json!({"svc:naive": {"default": {"action": "direct", "egress": null}, "rules": []}})),
               "chains": chains.unwrap_or(json!({}))})
    }

    fn message(result: Result<Value>) -> String {
        result.unwrap_err().to_string()
    }

    #[test]
    fn validate_document_normalises_and_orders() {
        let document = validate_document(&doc(
            json!([
                {"domains": ["Example.COM.", "*.Example.com", "example.com"], "cidrs": ["10.0.0.1", "10.0.0.0/8"],
                 "geosites": ["category-ads-all"], "geoips": ["cloudflare"], "ports": ["80", 443, "1000-2000"],
                 "action": "egress", "egress": "warp"},
                {"ports": [25], "action": "block"}
            ]),
            Some(json!({"action": "egress", "egress": "warp"})),
        ))
        .unwrap();
        let (first, second) = (&document["rules"][0], &document["rules"][1]);
        assert_eq!(first["domains"], json!(["example.com", "*.example.com"]));
        assert_eq!(first["cidrs"], json!(["10.0.0.1/32", "10.0.0.0/8"]));
        assert_eq!((&first["geosites"], &first["geoips"]), (&json!(["category-ads-all"]), &json!(["cloudflare"])));
        assert_eq!((&first["ports"], &first["egress"]), (&json!([80, 443, "1000-2000"]), &json!("warp")));
        assert_eq!(
            second,
            &json!({"domains": [], "geosites": [], "cidrs": [], "geoips": [], "ports": [25], "action": "block", "egress": null})
        );
        assert_eq!(document["default"], json!({"action": "egress", "egress": "warp"}));
        assert!(uses_provider(&document) && !uses_provider(&direct_document()));
        assert_eq!(document_digest(&document).len(), 64);
    }

    #[test]
    fn validate_document_rejects_unknown_fields_schema_and_raw_json() {
        let d = json!({"action": "direct"});
        for document in [
            json!({"schema": 1, "default": d, "rules": [], "inbounds": []}),
            json!({"schema": 2, "default": d, "rules": []}),
            json!({"schema": 1, "default": {"action": "block"}, "rules": []}),
            json!({"schema": 1, "default": {"action": "egress"}, "rules": []}),
            json!({"schema": 1, "default": {"action": "direct", "egress": "warp"}, "rules": []}),
            json!({"schema": 1, "default": d, "rules": [{"domains": ["a.example"], "action": "egress"}]}),
            json!({"schema": 1, "default": d, "rules": [{"domains": ["a.example"], "action": "direct", "egress": "warp"}]}),
            json!({"schema": 1, "default": d, "rules": [{"domains": ["a.example"], "action": "direct", "path": "/x"}]}),
            json!({"schema": 1, "default": d, "rules": [{"domains": ["not a host"], "action": "direct"}]}),
            json!({"schema": 1, "default": d, "rules": [{"cidrs": ["300.1.1.1"], "action": "direct"}]}),
            json!({"schema": 1, "default": d, "rules": [{"geosites": ["Bad Code"], "action": "direct"}]}),
            json!({"schema": 1, "default": d, "rules": [{"ports": [0], "action": "direct"}]}),
            json!({"schema": 1, "default": d, "rules": [{"ports": [true], "action": "direct"}]}),
            json!({"schema": 1, "default": d, "rules": [{"ports": ["9-3"], "action": "direct"}]}),
            json!(["not", "an", "object"]),
            json!({"inbounds": [{"protocol": "socks"}]}),
        ] {
            assert!(matches!(validate_document(&document), Err(Error::EgressInvalid { .. })), "{document}");
        }
    }

    #[test]
    fn validate_document_rejects_private_geoip_and_empty_rule() {
        assert!(message(validate_document(&doc(json!([{"geoips": ["private"], "action": "block"}]), None)))
            .contains("bypass"));
        assert!(message(validate_document(&doc(json!([{"action": "block"}]), None))).contains("selector"));
        let empty = json!([{"domains": [], "cidrs": [], "action": "block"}]);
        assert!(message(validate_document(&doc(empty, None))).contains("selector"));
    }

    #[test]
    fn validate_document_limits_and_size() {
        let one = json!({"domains": ["a.example"], "action": "block"});
        assert!(validate_document(&doc(Value::Array(vec![one; 129]), None)).is_err());
        let domains: Vec<String> = (0..65).map(|i| format!("h{i}.example")).collect();
        assert!(validate_document(&doc(json!([{"domains": domains, "action": "block"}]), None)).is_err());
        let ports: Vec<u32> = (1..34).collect();
        assert!(validate_document(&doc(json!([{"ports": ports, "action": "block"}]), None)).is_err());
        let long: Vec<String> =
            (0..64).map(|i| format!("{}{i:03}.{}.example", "x".repeat(60), "y".repeat(60))).collect();
        let rule = json!({"domains": long, "action": "block"});
        assert!(message(validate_document(&doc(json!([rule, rule, rule]), None))).contains("too large"));
        assert_eq!(MAX_DOCUMENT_BYTES, 16384);
    }

    #[test]
    fn direct_document_is_the_floor() {
        assert_eq!(validate_document(&direct_document()).unwrap(), direct_document());
        assert_eq!(direct_document()["rules"], json!([]));
        assert_eq!(direct_document()["default"]["action"], "direct");
        assert_eq!(CAPABILITIES.len(), 16);
        assert!(["block_port", "geodata", "block_protocol"].iter().all(|c| CAPABILITIES.contains(c)));
    }

    #[test]
    fn provider_endpoint_accepts_socks5_only() {
        assert_eq!(provider_endpoint(Some("socks5://127.0.0.1:45000")).unwrap(), ("127.0.0.1".to_string(), 45000));
        for url in [None, Some(""), Some("http://127.0.0.1:8118"), Some("socks5://127.0.0.1")] {
            assert!(matches!(provider_endpoint(url), Err(Error::EgressInvalid { .. })), "{url:?}");
        }
        assert_eq!(provider_endpoint(Some("SOCKS5h://u:p@[::1]:45000/x")).unwrap(), ("::1".to_string(), 45000));
        assert!(matches!(provider_endpoint(Some("socks5://h:port")), Err(Error::Internal(_))));
    }

    #[test]
    fn schema_2_normalises_lanes_chains_and_keeps_the_service_lane_last() {
        let document = validate_document(&v2(
            Some(json!({
                "grant:7f3a": {"default": {"action": "egress", "egress": "chain:c1"},
                               "rules": [{"geosites": ["category-ads-all"], "action": "block"},
                                         {"geoips": ["ru"], "action": "direct"},
                                         {"domains": ["*.Example.NET"], "action": "egress", "egress": "warp"}]},
                "svc:naive": {"default": {"action": "direct", "egress": null}, "rules": []}
            })),
            Some(json!({"c1": {"hops": [hop()], "exit": "warp"}})),
        ))
        .unwrap();
        assert_eq!(document["schema"], 2);
        let lanes: Vec<&String> = document["lanes"].as_object().unwrap().keys().collect();
        assert_eq!(lanes, ["grant:7f3a", "svc:naive"]);
        let lane = &document["lanes"]["grant:7f3a"];
        assert_eq!(lane["default"], json!({"action": "egress", "egress": "chain:c1"}));
        assert_eq!(
            (&lane["rules"][2]["domains"], &lane["rules"][2]["egress"]),
            (&json!(["*.example.net"]), &json!("warp"))
        );
        assert_eq!(document["chains"]["c1"]["hops"][0]["address"], "panel.node-b.example.org");
        assert_eq!(document["chains"]["c1"]["exit"], "warp");
        assert!(uses_provider(&document) && uses_chain(&document, "c1") && chain_ids(&document) == ["c1"]);
        assert_eq!(
            lanes_of(&direct_document(), "mieru")["svc:mieru"]["default"],
            json!({"action": "direct", "egress": null})
        );
        assert_eq!(&Value::Object(lanes_of(&document, "naive")), &document["lanes"]);
    }

    #[test]
    fn schema_2_rejects_bad_lanes_chains_and_hops() {
        let d = json!({"default": {"action": "direct", "egress": null}, "rules": []});
        let h = hop();
        for document in [
            v2(
                Some(json!({"svc:naive": {"default": {"action": "egress", "egress": "chain:missing"}, "rules": []}})),
                None,
            ),
            v2(Some(json!({"grant:1": d})), None),
            v2(Some(json!({"svc:naive": d, "svc:mieru": d})), None),
            v2(Some(json!({"svc:naive": {"default": {"action": "block", "egress": null}, "rules": []}})), None),
            v2(
                Some(json!({"svc:naive": {"default": {"action": "direct", "egress": null},
                                          "rules": [{"domains": ["a.example"], "action": "egress", "egress": "node-b"}]}})),
                None,
            ),
            v2(Some(json!({"lane with space": d})), None),
            v2(None, Some(json!({"c1": {"hops": [], "exit": "direct"}}))),
            v2(None, Some(json!({"c1": {"hops": [h, h, h, h], "exit": "direct"}}))),
            v2(None, Some(json!({"c1": {"hops": [with(&h, json!({"uuid": "not-a-uuid"}))], "exit": "direct"}}))),
            v2(None, Some(json!({"c1": {"hops": [with(&h, json!({"port": 70000}))], "exit": "direct"}}))),
            v2(None, Some(json!({"c1": {"hops": [with(&h, json!({"public_key": "short"}))], "exit": "direct"}}))),
            v2(None, Some(json!({"c1": {"hops": [with(&h, json!({"short_id": "xyz"}))], "exit": "direct"}}))),
            v2(None, Some(json!({"c1": {"hops": [h], "exit": "block"}}))),
            v2(None, Some(json!({"c1": {"hops": [h], "exit": "direct", "extra": 1}}))),
            v2(None, Some(json!({"bad id!": {"hops": [h], "exit": "direct"}}))),
            json!({"schema": 2, "lanes": {}, "chains": {}, "default": {"action": "direct"}}),
        ] {
            assert!(matches!(validate_document(&document), Err(Error::EgressInvalid { .. })), "{document}");
        }
    }

    #[test]
    fn schema_2_limits() {
        assert_eq!((MAX_LANES, MAX_CHAINS, MAX_HOPS, MAX_DOCUMENT_BYTES_V2), (32, 16, 3, 65536));
        let d = json!({"default": {"action": "direct", "egress": null}, "rules": []});
        let mut lanes: Map<String, Value> = (0..32).map(|i| (format!("grant:{i}"), d.clone())).collect();
        lanes.insert("svc:naive".into(), d.clone());
        assert!(message(validate_document(&v2(Some(Value::Object(lanes)), None))).contains("lanes"));
        let chains: Map<String, Value> =
            (0..17).map(|i| (format!("c{i}"), json!({"hops": [hop()], "exit": "direct"}))).collect();
        assert!(message(validate_document(&v2(None, Some(Value::Object(chains))))).contains("chains"));
        let h = hop();
        let chains: Map<String, Value> =
            (0..16).map(|i| (format!("c{i}"), json!({"hops": [h, h, h], "exit": "direct"}))).collect();
        assert_eq!(validate_document(&v2(None, Some(Value::Object(chains)))).unwrap()["schema"], 2);
    }

    #[test]
    fn schema_2_redaction_masks_every_hop_secret() {
        let second = with(&hop(), json!({"guid": "c".repeat(32)}));
        let document =
            validate_document(&v2(None, Some(json!({"c1": {"hops": [hop(), second], "exit": "direct"}})))).unwrap();
        let masked = redact_intent(&document);
        assert!(masked["chains"]["c1"]["hops"].as_array().unwrap().iter().all(|h| h["uuid"] == "***"));
        assert_eq!(document["chains"]["c1"]["hops"][0]["uuid"], hop()["uuid"]);
        assert_eq!(masked["chains"]["c1"]["hops"][0]["public_key"], hop()["public_key"]);
        assert_eq!(redact_intent(&direct_document()), direct_document());
    }

    /// Ported from `panel/tests/test_routing_presets.py`: the router side of the sniffed-protocol
    /// selector.
    #[test]
    fn the_router_intent_and_the_xray_rule_carry_the_protocol_selector() {
        let d = json!({"action": "direct", "egress": null});
        let document =
            validate_document(&json!({"schema": 1, "default": d, "rules": [{"protocols": ["bittorrent", "bittorrent"], "action": "block"}]}))
                .unwrap();
        assert_eq!(document["rules"][0]["protocols"], json!(["bittorrent"]));
        let plain = validate_document(
            &json!({"schema": 1, "default": d, "rules": [{"domains": ["x.com"], "action": "block"}]}),
        )
        .unwrap();
        assert!(plain["rules"][0].get("protocols").is_none());
        let refused = validate_document(
            &json!({"schema": 1, "default": d, "rules": [{"protocols": ["ssh"], "action": "block"}]}),
        );
        assert!(message(refused).contains("protocol selector"));
        let rendered = crate::render::rule("naive", &document["rules"][0], None, &Default::default());
        assert_eq!((&rendered["protocol"], &rendered["outboundTag"]), (&json!(["bittorrent"]), &json!("block")));
        assert!(rendered.get("domain").is_none());
        assert!(CAPABILITIES.contains(&"block_protocol") && CAPABILITIES.contains(&"selective_protocol"));
    }

    const GOLDEN: &str = include_str!("../testdata/intent.json");

    /// Every document and exit of the golden set gives what Python 3.13 gave: the same normal form
    /// (key order included), the same digest, the same message and code.
    #[test]
    fn golden_validation_matches_the_python_manager() {
        let golden: Value = serde_json::from_str(GOLDEN).unwrap();
        let mut checked = 0;
        for entry in golden["validation"].as_array().unwrap() {
            let result = validate_document(&entry["input"]);
            let input = &entry["input"];
            if entry.get("crash").is_some() {
                // `int("²")`: Python's handler died; this manager answers `invalid port`.
                assert_eq!(message(result), "invalid port", "{input}");
                continue;
            }
            match (result, entry.get("error")) {
                (Ok(document), None) => {
                    if let Some(output) = entry["output"].as_str() {
                        assert_eq!(pyjson::dumps(&document, &pyjson::COMPACT), output, "{input}");
                        let redacted = pyjson::dumps(&redact_intent(&document), &pyjson::COMPACT);
                        assert_eq!(redacted, entry["redacted"].as_str().unwrap());
                    }
                    assert_eq!(document_digest(&document), entry["digest"].as_str().unwrap(), "{input}");
                    assert_eq!(uses_provider(&document), entry["uses_provider"].as_bool().unwrap());
                }
                (Err(Error::EgressInvalid { message, code }), Some(error)) => {
                    assert_eq!(
                        (message.as_str(), code.as_str()),
                        (error.as_str().unwrap(), entry["code"].as_str().unwrap())
                    );
                }
                (other, _) => panic!("{input}: {other:?} vs {entry}"),
            }
            checked += 1;
        }
        assert!(checked > 250);
        for entry in golden["exits"].as_array().unwrap() {
            let input = &entry["input"];
            match (validate_exit(input), entry.get("error")) {
                (Ok(exit), None) => {
                    assert_eq!(pyjson::dumps(&exit, &pyjson::COMPACT), entry["output"].as_str().unwrap(), "{input}");
                    let outbound = crate::render::config_bytes(&crate::render::exit_outbound("exit:naive:e", &exit));
                    assert_eq!(String::from_utf8(outbound).unwrap(), entry["outbound"].as_str().unwrap());
                }
                (Err(Error::EgressInvalid { message, code }), Some(error)) => {
                    assert_eq!(
                        (message.as_str(), code.as_str()),
                        (error.as_str().unwrap(), entry["code"].as_str().unwrap())
                    );
                }
                (other, _) => panic!("{input}: {other:?} vs {entry}"),
            }
        }
    }
}
