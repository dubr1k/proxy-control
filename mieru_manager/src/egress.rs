//! The `egress` section of the mita config as the panel's compiled document (v0.4, ADR 007).
//!
//! The panel sends `{"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}], "rules":
//! [{"domains": […], "cidrs": […], "action": "DIRECT|PROXY|REJECT", "proxy": "warp"|null}, …]}`
//! — never an address: the provider's endpoint is this host's own configuration
//! (`MIERU_EGRESS_WARP`, `MIERU_EGRESS_ROUTER`). `to_mita` renders that into mita's `egress`
//! (first match wins, DIRECT when nothing matches) and `from_mita` reads it back; a section
//! naming a proxy this host has no provider for reads back as `None` — a `custom` egress the
//! panel shows but does not claim to own. A change takes effect only after mita restarts, so
//! the manager applies egress in `restart` mode.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::{pyip, pyjson, pyurl, util};

pub const SCHEMA: i64 = 1;
/// `warp`: the host's WARP proxy-mode endpoint. `router`: this service's private ingress on
/// the node's Xray-router — SOCKS5 with a credential the manager reads from its own state
/// directory when it renders the section, never from the panel.
pub const PROVIDERS: [&str; 2] = ["warp", "router"];
pub const CAPABILITIES: [&str; 6] =
    ["whole_direct", "whole_warp", "block_domain", "block_cidr", "selective_domain", "selective_cidr"];
pub const ACTIONS: [&str; 3] = ["DIRECT", "PROXY", "REJECT"];
pub const MAX_RULES: usize = 128;
pub const MAX_SELECTORS: usize = 64;
pub const MAX_DOCUMENT_BYTES: usize = 16384;

/// The provider endpoints of this host (`None` or empty = not configured).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Providers {
    pub warp: Option<String>,
    pub router: Option<String>,
}

impl Providers {
    #[cfg(test)]
    pub fn warp(url: Option<&str>) -> Self {
        Self { warp: url.map(str::to_string), router: None }
    }

    fn get(&self, name: &str) -> Option<&str> {
        match name {
            "warp" => self.warp.as_deref(),
            "router" => self.router.as_deref(),
            _ => None,
        }
    }
}

pub type Credential = (String, String);

fn invalid(message: impl Into<String>) -> Error {
    Error::egress_invalid(message)
}

pub fn document_digest(document: &Value) -> String {
    util::hash(document)
}

fn domain(value: &Value) -> Result<String> {
    let bad = || invalid("invalid domain selector");
    let Some(text) = value.as_str().filter(|t| !t.is_empty()) else { return Err(bad()) };
    if text == "*" {
        return Ok(text.into());
    }
    let candidate = text.to_lowercase();
    let candidate = candidate.trim_end_matches('.');
    let label_ok = |label: &str| {
        let bytes = label.as_bytes();
        (1..=63).contains(&bytes.len())
            && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-'
    };
    if !(1..=253).contains(&candidate.chars().count()) || !candidate.split('.').all(label_ok) {
        return Err(bad());
    }
    Ok(candidate.into())
}

fn cidr(value: &Value) -> Result<String> {
    let bad = || invalid("invalid cidr selector");
    let Some(text) = value.as_str().filter(|t| !t.is_empty()) else { return Err(bad()) };
    if text == "*" {
        return Ok(text.into());
    }
    pyip::network_str(text).ok_or_else(bad)
}

fn list_of(value: Option<&Value>) -> Option<&Vec<Value>> {
    match value {
        None => Some(EMPTY.get_or_init(Vec::new)),
        Some(Value::Array(items)) => Some(items),
        Some(_) => None,
    }
}

static EMPTY: std::sync::OnceLock<Vec<Value>> = std::sync::OnceLock::new();

/// The compiled document, normalised, or `EgressInvalid`. Bounded and secret-free.
pub fn validate_document(document: &Value) -> Result<Value> {
    let Some(map) =
        document.as_object().filter(|m| m.keys().all(|k| ["schema", "proxies", "rules"].contains(&k.as_str())))
    else {
        return Err(invalid("unknown field in egress document"));
    };
    if !map.get("schema").is_some_and(|s| pyjson::eq_int(s, SCHEMA)) {
        return Err(invalid("unsupported egress document schema"));
    }
    let proxies = match list_of(map.get("proxies")) {
        Some(items) if items.len() <= PROVIDERS.len() => items,
        _ => return Err(invalid("invalid proxy list")),
    };
    let mut declared: Vec<String> = Vec::new();
    for proxy in proxies {
        let ok = proxy.as_object().is_some_and(|p| {
            p.len() == 2
                && p.contains_key("name")
                && p.contains_key("provider")
                && p["provider"].as_str().is_some_and(|provider| PROVIDERS.contains(&provider))
                && pyjson::eq(&p["name"], &p["provider"])
                && !declared.iter().any(|d| p["name"].as_str() == Some(d))
        });
        if !ok {
            return Err(invalid("unknown egress provider"));
        }
        declared.push(proxy["name"].as_str().unwrap_or_default().to_string());
    }
    let rules = match list_of(map.get("rules")) {
        Some(items) if items.len() <= MAX_RULES => items,
        _ => return Err(invalid("invalid rule list")),
    };
    let mut normalised_rules = Vec::new();
    for rule in rules {
        let Some(rule) = rule
            .as_object()
            .filter(|r| r.keys().all(|k| ["domains", "cidrs", "action", "proxy"].contains(&k.as_str())))
        else {
            return Err(invalid("invalid egress rule"));
        };
        let (Some(domains), Some(cidrs)) = (list_of(rule.get("domains")), list_of(rule.get("cidrs"))) else {
            return Err(invalid("invalid egress rule"));
        };
        if domains.len() > MAX_SELECTORS || cidrs.len() > MAX_SELECTORS || (domains.is_empty() && cidrs.is_empty()) {
            return Err(invalid("invalid egress rule selectors"));
        }
        let action = match rule.get("action").and_then(Value::as_str) {
            Some(action) if ACTIONS.contains(&action) => action,
            _ => return Err(invalid("invalid egress action")),
        };
        let proxy = rule.get("proxy").cloned().unwrap_or(Value::Null);
        if action == "PROXY" {
            if !declared.iter().any(|d| proxy.as_str() == Some(d)) {
                return Err(invalid("egress rule names an undeclared proxy"));
            }
        } else if !proxy.is_null() {
            return Err(invalid("egress rule proxy must be null for a non-PROXY action"));
        }
        let domains: Vec<Value> = domains.iter().map(|d| domain(d).map(Value::String)).collect::<Result<_>>()?;
        let cidrs: Vec<Value> = cidrs.iter().map(|c| cidr(c).map(Value::String)).collect::<Result<_>>()?;
        normalised_rules.push(json!({"domains": domains, "cidrs": cidrs, "action": action, "proxy": proxy}));
    }
    let proxies: Vec<Value> = declared.iter().map(|name| json!({"name": name, "provider": name})).collect();
    let normalised = json!({"schema": SCHEMA, "proxies": proxies, "rules": normalised_rules});
    if pyjson::canonical(&normalised).len() > MAX_DOCUMENT_BYTES {
        return Err(invalid("egress document too large"));
    }
    Ok(normalised)
}

/// Host and port of the provider's SOCKS5 endpoint; mita speaks SOCKS5 only.
pub fn provider_endpoint(url: Option<&str>, name: &str) -> Result<(String, u32)> {
    let Some(url) = url.filter(|u| !u.is_empty()) else {
        return Err(invalid(format!("egress provider {name} is not configured on this node")));
    };
    let wrong = || invalid(format!("egress provider {name} must be a socks5:// endpoint for mita"));
    // A port Python could not read raised a plain ValueError; here it is the same refusal.
    let parts = pyurl::urlsplit(url).map_err(|_| wrong())?;
    match (parts.scheme.as_str(), parts.hostname, parts.port) {
        ("socks5" | "socks5h", Some(host), Some(port)) if port != 0 => Ok((host, port)),
        _ => Err(wrong()),
    }
}

/// The `user:password` line of the router ingress credential file, or `EgressInvalid`.
pub fn read_credential(path: &Path) -> Result<Credential> {
    let raw =
        std::fs::read(path).map_err(|_| invalid("egress provider router credential is unavailable on this node"))?;
    let malformed = || invalid("egress provider router credential is malformed");
    let text = String::from_utf8(raw).map_err(|_| malformed())?;
    let (user, password) = pc_common::pytext::strip(&text).split_once(':').ok_or_else(malformed)?;
    let user_ok = (1..=64).contains(&user.len())
        && user.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    let password_ok = (16..=128).contains(&password.len())
        && password.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'));
    if !user_ok || !password_ok {
        return Err(malformed());
    }
    Ok((user.into(), password.into()))
}

/// A mita `egress` section with every `socks5Authentication` masked: what a `raw` (custom)
/// view may show.
pub fn redact_section(section: Option<&Value>) -> Value {
    let Some(section) = section else { return Value::Null };
    let mut masked = section.clone();
    if let Some(Value::Array(proxies)) = masked.get_mut("proxies") {
        for proxy in proxies.iter_mut().filter_map(Value::as_object_mut) {
            if proxy.contains_key("socks5Authentication") {
                proxy.insert("socks5Authentication".into(), json!({"user": "***", "password": "***"}));
            }
        }
    }
    masked
}

/// mita's `egress` section for a validated document. Empty repeated fields are left out, as
/// mita's protobuf JSON renders them, so the readback hash matches; `{}` means "no egress key
/// at all" (direct). The `router` proxy carries the ingress credential.
pub fn to_mita(document: &Value, providers: &Providers, router: Option<&Credential>) -> Result<Value> {
    let mut proxies = Vec::new();
    for proxy in document["proxies"].as_array().into_iter().flatten() {
        let name = proxy["name"].as_str().unwrap_or_default();
        let (host, port) = provider_endpoint(providers.get(name), name)?;
        let mut rendered = json!({"name": name, "protocol": "SOCKS5_PROXY_PROTOCOL", "host": host, "port": port});
        if name == "router" {
            let Some((user, password)) = router else {
                return Err(invalid("egress provider router credential is unavailable on this node"));
            };
            rendered["socks5Authentication"] = json!({"user": user, "password": password});
        }
        proxies.push(rendered);
    }
    let mut rules = Vec::new();
    for rule in document["rules"].as_array().into_iter().flatten() {
        let mut rendered = Map::new();
        rendered.insert("action".into(), rule["action"].clone());
        if rule["cidrs"].as_array().is_some_and(|c| !c.is_empty()) {
            rendered.insert("ipRanges".into(), rule["cidrs"].clone());
        }
        if rule["domains"].as_array().is_some_and(|d| !d.is_empty()) {
            rendered.insert("domainNames".into(), rule["domains"].clone());
        }
        if rule["action"] == "PROXY" {
            rendered.insert("proxyNames".into(), json!([rule["proxy"]]));
        }
        rules.push(Value::Object(rendered));
    }
    let mut section = Map::new();
    if !proxies.is_empty() {
        section.insert("proxies".into(), Value::Array(proxies));
    }
    if !rules.is_empty() {
        section.insert("rules".into(), Value::Array(rules));
    }
    Ok(Value::Object(section))
}

fn endpoints(providers: &Providers) -> Vec<(&'static str, (String, u32))> {
    PROVIDERS
        .iter()
        .filter_map(|name| {
            let url = providers.get(name).filter(|u| !u.is_empty())?;
            provider_endpoint(Some(url), name).ok().map(|endpoint| (*name, endpoint))
        })
        .collect()
}

/// Python's `list(value or [])` over a section field: a list as is, a string as its
/// characters, a dict as its keys; `None` for what Python could not iterate.
fn py_list(value: Option<&Value>) -> Option<Vec<Value>> {
    match value {
        None => Some(Vec::new()),
        Some(v) if !pc_common::pyvalue::truthy(v) => Some(Vec::new()),
        Some(Value::Array(items)) => Some(items.clone()),
        Some(Value::String(s)) => Some(s.chars().map(|c| Value::String(c.to_string())).collect()),
        Some(Value::Object(map)) => Some(map.keys().map(|k| Value::String(k.clone())).collect()),
        Some(_) => None,
    }
}

/// The document a mita `egress` section amounts to, or `None` when it names something this
/// host's providers do not — `custom`. The `router` proxy must carry a credential (any: the
/// file's is the truth), the `warp` proxy none.
pub fn from_mita(section: Option<&Value>, providers: &Providers) -> Option<Value> {
    let Some(section) = section.filter(|s| !s.is_null()) else {
        return Some(json!({"schema": SCHEMA, "proxies": [], "rules": []}));
    };
    let section = section.as_object()?;
    let proxies = py_list(section.get("proxies"))?;
    let rules = py_list(section.get("rules"))?;
    let endpoints = endpoints(providers);
    let mut declared: Vec<&str> = Vec::new();
    for proxy in &proxies {
        let proxy = proxy.as_object()?;
        if proxy.get("protocol").and_then(Value::as_str) != Some("SOCKS5_PROXY_PROTOCOL") {
            return None;
        }
        let name = proxy.get("name").and_then(Value::as_str).and_then(|n| PROVIDERS.iter().find(|p| **p == n))?;
        if declared.contains(name) {
            return None;
        }
        let (host, port) = &endpoints.iter().find(|(n, _)| n == name)?.1;
        let port_matches = proxy.get("port").is_some_and(|p| pyjson::eq_int(p, i64::from(*port)));
        if proxy.get("host").and_then(Value::as_str) != Some(host.as_str()) || !port_matches {
            return None;
        }
        if proxy.contains_key("socks5Authentication") != (*name == "router") {
            return None;
        }
        declared.push(name);
    }
    let mut document_rules = Vec::new();
    for rule in &rules {
        let rule = rule.as_object()?;
        let action = rule.get("action").cloned().unwrap_or_else(|| json!("PROXY"));
        let action = action.as_str().filter(|a| ACTIONS.contains(a))?.to_string();
        let names = py_list(rule.get("proxyNames"))?;
        let proxy = if action == "PROXY" {
            if names.len() != 1 || !declared.iter().any(|d| names[0].as_str() == Some(d)) {
                return None;
            }
            names[0].clone()
        } else {
            Value::Null
        };
        document_rules.push(json!({
            "domains": py_list(rule.get("domainNames"))?,
            "cidrs": py_list(rule.get("ipRanges"))?,
            "action": action,
            "proxy": proxy,
        }));
    }
    let proxies: Vec<Value> = declared.iter().map(|name| json!({"name": name, "provider": name})).collect();
    validate_document(&json!({"schema": SCHEMA, "proxies": proxies, "rules": document_rules})).ok()
}

/// The `router` proxy of the running section carries a credential other than the file's (a
/// rotation happened while this manager was down).
pub fn router_credential_stale(section: Option<&Value>, credential: &Credential) -> bool {
    let Some(section) = section.and_then(Value::as_object) else { return false };
    let Some(Value::Array(proxies)) = section.get("proxies") else { return false };
    for proxy in proxies.iter().filter_map(Value::as_object) {
        if proxy.get("name").and_then(Value::as_str) == Some("router") {
            let auth = proxy.get("socks5Authentication").filter(|a| pc_common::pyvalue::truthy(a));
            let Some(auth) = auth.map(|a| a.as_object()) else { return true };
            let Some(auth) = auth else { return true };
            let field = |key: &str| auth.get(key).and_then(Value::as_str);
            return (field("user"), field("password")) != (Some(credential.0.as_str()), Some(credential.1.as_str()));
        }
    }
    false
}

/// A SOCKS5 greeting — offering no authentication, or (`auth`) the username/password method
/// the router ingress demands, without completing it; never fails — the answer is the fact.
pub fn check_reachable(url: Option<&str>, timeout: f64, auth: bool) -> bool {
    let Ok((host, port)) = provider_endpoint(url, "warp") else { return false };
    let timeout = Duration::from_secs_f64(timeout);
    let method = if auth { 0x02 } else { 0x00 };
    let Ok(addresses) = (host.as_str(), port as u16).to_socket_addrs() else { return false };
    for address in addresses {
        let Ok(mut stream) = TcpStream::connect_timeout(&address, timeout) else { continue };
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        if stream.write_all(&[0x05, 0x01, method]).is_err() {
            return false;
        }
        let mut reply = [0u8; 2];
        return matches!(stream.read(&mut reply), Ok(2)) && reply == [0x05, method];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_answers_the_offered_method() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("socks5://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for reply in [[5u8, 0u8], [5, 0]] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut greeting = [0u8; 3];
                stream.read_exact(&mut greeting).unwrap();
                stream.write_all(&reply).unwrap();
            }
        });
        assert!(check_reachable(Some(&url), 2.0, false));
        assert!(!check_reachable(Some(&url), 2.0, true)); // answered "no auth" to a password offer
        server.join().unwrap();
        assert!(!check_reachable(None, 1.0, false));
        assert!(!check_reachable(Some("http://127.0.0.1:1"), 1.0, false));
    }

    const WARP: &str = "socks5://127.0.0.1:45000";
    const ROUTER: &str = "socks5://127.0.0.1:45102";

    fn warp() -> Providers {
        Providers::warp(Some(WARP))
    }

    fn both() -> Providers {
        Providers { warp: Some(WARP.into()), router: Some(ROUTER.into()) }
    }

    fn direct_doc() -> Value {
        json!({"schema": 1, "proxies": [], "rules": []})
    }

    fn warp_doc() -> Value {
        json!({"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}],
               "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"}]})
    }

    fn selective_doc() -> Value {
        json!({"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}], "rules": [
            {"domains": ["example.com"], "cidrs": [], "action": "REJECT", "proxy": null},
            {"domains": ["api.ipify.org"], "cidrs": ["10.0.0.0/8"], "action": "DIRECT", "proxy": null},
            {"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"},
        ]})
    }

    fn router_doc() -> Value {
        json!({"schema": 1, "proxies": [{"name": "router", "provider": "router"}],
               "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "router"}]})
    }

    fn credential(user: &str, password: &str) -> Credential {
        (user.into(), password.into())
    }

    fn message(result: Result<Value>) -> String {
        match result {
            Err(Error::EgressInvalid(message)) => message,
            other => panic!("expected EgressInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_document_normalises_and_bounds() {
        let normalised =
            validate_document(&json!({"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}], "rules": [
            {"domains": ["Example.COM."], "cidrs": ["10.1.2.3/8"], "action": "PROXY", "proxy": "warp"}]}))
            .unwrap();
        assert_eq!(
            normalised["rules"],
            json!([{"domains": ["example.com"], "cidrs": ["10.0.0.0/8"], "action": "PROXY", "proxy": "warp"}])
        );
        let reject = |domains: Value, cidrs: Value, action: &str, proxy: Value| json!({"schema": 1, "proxies": [], "rules": [{"domains": domains, "cidrs": cidrs, "action": action, "proxy": proxy}]});
        let too_many: Vec<Value> = (0..=MAX_RULES)
            .map(|_| json!({"domains": ["a.example"], "cidrs": [], "action": "REJECT", "proxy": null}))
            .collect();
        for bad in [
            json!({"schema": 2, "proxies": [], "rules": []}),
            json!({"schema": 1, "proxies": [], "rules": [], "extra": 1}),
            json!({"schema": 1, "proxies": [{"name": "other", "provider": "warp"}], "rules": []}),
            json!({"schema": 1, "proxies": [{"name": "warp", "provider": "warp", "host": "x"}], "rules": []}),
            reject(json!(["a.example"]), json!([]), "PROXY", json!("warp")),
            reject(json!(["a.example"]), json!([]), "DIRECT", json!("warp")),
            reject(json!([]), json!([]), "REJECT", Value::Null),
            reject(json!(["bad host"]), json!([]), "REJECT", Value::Null),
            reject(json!([]), json!(["10.0.0.0/33"]), "REJECT", Value::Null),
            reject(json!(["a.example"]), json!([]), "ALLOW", Value::Null),
            json!({"schema": 1, "proxies": [], "rules": too_many}),
        ] {
            assert!(matches!(validate_document(&bad), Err(Error::EgressInvalid(_))), "{bad}");
        }
    }

    #[test]
    fn to_mita_renders_first_match_rules_and_the_provider_endpoint() {
        let none = Providers::default();
        assert_eq!(to_mita(&validate_document(&direct_doc()).unwrap(), &none, None).unwrap(), json!({}));
        let section = to_mita(&validate_document(&selective_doc()).unwrap(), &warp(), None).unwrap();
        assert_eq!(
            section,
            json!({
                "proxies": [{"name": "warp", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45000}],
                "rules": [
                    {"action": "REJECT", "domainNames": ["example.com"]},
                    {"action": "DIRECT", "ipRanges": ["10.0.0.0/8"], "domainNames": ["api.ipify.org"]},
                    {"action": "PROXY", "ipRanges": ["*"], "domainNames": ["*"], "proxyNames": ["warp"]},
                ],
            })
        );
        let warp_doc = validate_document(&warp_doc()).unwrap();
        assert!(message(to_mita(&warp_doc, &none, None)).contains("not configured"));
        assert!(message(to_mita(&warp_doc, &Providers::warp(Some("http://127.0.0.1:8118")), None)).contains("socks5"));
    }

    #[test]
    fn from_mita_round_trips_and_reports_a_foreign_proxy_as_custom() {
        for document in [direct_doc(), warp_doc(), selective_doc()] {
            let normalised = validate_document(&document).unwrap();
            let section = to_mita(&normalised, &warp(), None).unwrap();
            assert_eq!(from_mita(Some(&section), &warp()), Some(normalised));
        }
        assert_eq!(from_mita(None, &warp()), Some(validate_document(&direct_doc()).unwrap()));
        let seed = json!({"proxies": [{"name": "warp", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 40000}],
                          "rules": [{"ipRanges": ["0.0.0.0/0", "::/0"], "action": "DIRECT"}]});
        let expected = validate_document(&json!({"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}],
            "rules": [{"domains": [], "cidrs": ["0.0.0.0/0", "::/0"], "action": "DIRECT", "proxy": null}]}))
        .unwrap();
        assert_eq!(from_mita(Some(&seed), &Providers::warp(Some("socks5://127.0.0.1:40000"))), Some(expected));
        assert_eq!(from_mita(Some(&seed), &warp()), None); // another port: not this host's provider
        let with_auth = json!({"proxies": [{"name": "warp", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1",
            "port": 45000, "socks5Authentication": {"user": "u", "password": "p"}}], "rules": []});
        assert_eq!(from_mita(Some(&with_auth), &warp()), None);
        let unknown = json!({"proxies": [], "rules": [{"action": "PROXY", "proxyNames": ["x"]}]});
        assert_eq!(from_mita(Some(&unknown), &warp()), None);
    }

    #[test]
    fn to_mita_router_proxy_has_socks5_authentication() {
        let document = validate_document(&router_doc()).unwrap();
        let section = to_mita(&document, &both(), Some(&credential("mieru-e5f6a7b8", &"K".repeat(40)))).unwrap();
        assert_eq!(
            section["proxies"],
            json!([{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45102,
                    "socks5Authentication": {"user": "mieru-e5f6a7b8", "password": "K".repeat(40)}}])
        );
        assert_eq!(
            section["rules"],
            json!([{"action": "PROXY", "ipRanges": ["*"], "domainNames": ["*"], "proxyNames": ["router"]}])
        );
        assert!(message(to_mita(&document, &both(), None)).contains("credential"));
        let no_router = Providers { warp: Some(WARP.into()), router: None };
        let found = to_mita(&document, &no_router, Some(&credential("u", &"p".repeat(16))));
        assert!(message(found).contains("router is not configured"));
    }

    #[test]
    fn from_mita_router_with_auth_is_the_router_document() {
        let document = validate_document(&router_doc()).unwrap();
        let secret = credential("u", &"p".repeat(16));
        let section = to_mita(&document, &both(), Some(&secret)).unwrap();
        assert_eq!(from_mita(Some(&section), &both()), Some(document));
        // Without a credential the router proxy is somebody else's; with one, warp is not warp.
        let bare = json!({"proxies": [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45102}],
                          "rules": []});
        assert_eq!(from_mita(Some(&bare), &both()), None);
        assert_eq!(from_mita(Some(&section), &warp()), None); // a v0.4 host without a router
        assert!(!router_credential_stale(Some(&section), &secret));
        assert!(router_credential_stale(Some(&section), &credential("u", &"q".repeat(16))));
        let masked = redact_section(Some(&section));
        assert_eq!(masked["proxies"][0]["socks5Authentication"], json!({"user": "***", "password": "***"}));
        assert_eq!(section["proxies"][0]["socks5Authentication"]["password"], "p".repeat(16));
    }

    #[test]
    fn the_router_credential_file_is_read_strictly() {
        let dir = crate::tests::tempdir("credential-file");
        let path = dir.join("cred");
        assert!(message(read_credential(&path).map(|_| Value::Null)).contains("unavailable"));
        for bad in ["nouser", "u:short", "bad user:pppppppppppppppp", ":pppppppppppppppp"] {
            std::fs::write(&path, bad).unwrap();
            assert!(message(read_credential(&path).map(|_| Value::Null)).contains("malformed"), "{bad}");
        }
        std::fs::write(&path, format!("  mieru-e5f6a7b8:{}\n", "K".repeat(40))).unwrap();
        assert_eq!(read_credential(&path).unwrap(), credential("mieru-e5f6a7b8", &"K".repeat(40)));
    }
}
