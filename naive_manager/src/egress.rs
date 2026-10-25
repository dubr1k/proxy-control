//! The egress block of the NaiveProxy Caddyfile (v0.4 routing, ADR 007).
//!
//! The manager owns exactly one block inside `forward_proxy`:
//!
//! ```text
//! # BEGIN NAIVE-MANAGER EGRESS
//! upstream socks5://127.0.0.1:45000
//! acl {
//!     deny example.com *.example.com 10.0.0.0/8
//! }
//! # END NAIVE-MANAGER EGRESS
//! ```
//!
//! What the panel sends is a *compiled document* — `{"schema": 1, "upstream": {"provider":
//! "warp"} | null, "acl": [{"deny": [...]}, ...]}` — never an address, a path or a raw
//! directive: the provider's URL is this host's own configuration. The pinned forwardproxy
//! skips its ACL when an upstream is set, so a document carrying both is refused.
//!
//! A Caddyfile written before v0.4 (or by hand) has an `upstream` line without markers:
//! `parse` reports it as `custom` (or as the provider's when the URL matches), and the first
//! `render` moves it into the managed block, keeping the original lines beside the journal so
//! a rollback puts them back byte for byte. Everything outside the block is left untouched.

use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::pyutil::{join_lines, leading_space, quote, sha256_hex, splitlines, strip};
use crate::text::{
    deny_subjects, is_acl_open, is_forward_proxy_block, is_probe_resistance, sub_userinfo, upstream_target,
};

pub const EGRESS_BEGIN: &str = "# BEGIN NAIVE-MANAGER EGRESS";
pub const EGRESS_END: &str = "# END NAIVE-MANAGER EGRESS";
pub const SCHEMA: i64 = 1;
/// `warp`: the host's WARP proxy-mode endpoint (v0.4). `router`: this service's private
/// ingress on the node's Xray-router (v0.5), whose credential the manager reads from its own
/// state directory when it renders the line.
pub const PROVIDERS: [&str; 2] = ["warp", "router"];
pub const CAPABILITIES: [&str; 4] = ["whole_direct", "whole_warp", "block_domain", "block_cidr"];
pub const MAX_RULES: usize = 128;
pub const MAX_SUBJECTS: usize = 64;
pub const MAX_DOCUMENT_BYTES: usize = 16384;

fn invalid(message: impl Into<String>) -> Error {
    Error::EgressInvalid(message.into())
}

/// The block (or the adopted unmanaged lines) as the Caddyfile has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEgress {
    /// `direct`, `proxy` or `custom`.
    pub mode: String,
    pub upstream: Option<String>,
    pub acl_deny: Vec<String>,
    pub managed: bool,
    pub revision: String,
    /// The lines the manager will replace: the managed block, or the unmanaged `upstream` /
    /// `acl` lines a first apply adopts (kept for the rollback to restore them verbatim).
    pub raw_lines: Vec<String>,
}

/// The URL per provider name; `None` when the host does not have it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Providers {
    pub warp: Option<String>,
    pub router: Option<String>,
}

impl Providers {
    /// The v0.4 shape: only a WARP URL.
    pub fn warp(url: Option<&str>) -> Self {
        Self { warp: url.filter(|u| !u.is_empty()).map(String::from), router: None }
    }

    fn get(&self, name: &str) -> Option<&str> {
        match name {
            "warp" => self.warp.as_deref(),
            "router" => self.router.as_deref(),
            _ => None,
        }
    }
}

/// Start and end line indexes of the service's own `forward_proxy { … }` block — the one
/// outside the lanes block (v0.7).
pub fn forward_proxy_bounds(lines: &[&str]) -> Result<(usize, usize)> {
    let outside = crate::lanes::outside_lanes(lines).map_err(|err| invalid(err.message()))?;
    let directives: Vec<usize> = outside.into_iter().filter(|&i| crate::lanes::is_forward_proxy(lines[i])).collect();
    if directives.len() != 1 {
        return Err(invalid("exactly one forward_proxy block is required"));
    }
    let start = directives[0];
    if !is_forward_proxy_block(lines[start]) {
        return Err(invalid("forward_proxy must use managed block form"));
    }
    let mut depth: i64 = 0;
    for (index, line) in lines.iter().enumerate().skip(start) {
        depth += line.matches('{').count() as i64 - line.matches('}').count() as i64;
        if index > start && depth == 0 {
            return Ok((start, index));
        }
    }
    Err(invalid("unterminated forward_proxy block"))
}

/// `_DOMAIN`: labels of `[a-z0-9-]`, 1–63 long, no hyphen at either end, 253 at most.
fn is_domain(host: &str) -> bool {
    let length = host.chars().count();
    if !(1..=253).contains(&length) {
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

/// One ACL subject: a domain, a `*.` suffix, or a CIDR — as forwardproxy parses them.
pub fn valid_subject(value: &Value) -> Result<String> {
    let Some(value) = value.as_str() else { return Err(invalid("invalid acl subject")) };
    if value.is_empty() || value.chars().count() > 253 || value.chars().any(crate::pyutil::is_space) {
        return Err(invalid("invalid acl subject"));
    }
    let candidate = value.to_lowercase();
    if let Some(network) = crate::ipnet::ip_network(&candidate) {
        return Ok(network);
    }
    if candidate.contains('/') {
        return Err(invalid("invalid acl subject"));
    }
    let host = candidate.strip_prefix("*.").unwrap_or(&candidate);
    if !is_domain(host) {
        return Err(invalid("invalid acl subject"));
    }
    Ok(candidate)
}

fn document_keys_ok(map: &Map<String, Value>) -> bool {
    map.keys().all(|key| matches!(key.as_str(), "schema" | "upstream" | "acl"))
}

/// `document.get("schema") != SCHEMA` as Python compares it (`1.0` and `True` equal 1).
fn is_schema(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Number(n)) => n.as_i64() == Some(SCHEMA) || n.as_f64() == Some(SCHEMA as f64),
        Some(Value::Bool(b)) => *b,
        _ => false,
    }
}

/// The compiled document, normalised, or `EgressInvalid`. Bounded and secret-free.
pub fn validate_document(document: &Value) -> Result<Value> {
    let document = match document.as_object() {
        Some(map) if document_keys_ok(map) => map,
        _ => return Err(invalid("unknown field in egress document")),
    };
    if !is_schema(document.get("schema")) {
        return Err(invalid("unsupported egress document schema"));
    }
    let upstream = match document.get("upstream").unwrap_or(&Value::Null) {
        Value::Null => Value::Null,
        Value::Object(map) if map.len() == 1 => match map.get("provider").and_then(Value::as_str) {
            Some(provider) if PROVIDERS.contains(&provider) => json!({"provider": provider}),
            _ => return Err(invalid("unknown egress provider")),
        },
        _ => return Err(invalid("unknown egress provider")),
    };
    let empty = Value::Array(Vec::new());
    let acl = match document.get("acl").unwrap_or(&empty) {
        Value::Array(rules) if rules.len() <= MAX_RULES => rules,
        _ => return Err(invalid("invalid acl list")),
    };
    let mut rules = Vec::new();
    for rule in acl {
        let deny = match rule.as_object() {
            Some(map) if map.len() == 1 => match map.get("deny") {
                Some(Value::Array(deny)) if !deny.is_empty() => deny,
                _ => return Err(invalid("invalid acl rule")),
            },
            _ => return Err(invalid("invalid acl rule")),
        };
        if deny.len() > MAX_SUBJECTS {
            return Err(invalid("too many acl subjects"));
        }
        let subjects = deny.iter().map(valid_subject).collect::<Result<Vec<_>>>()?;
        rules.push(json!({"deny": subjects}));
    }
    if !upstream.is_null() && !rules.is_empty() {
        return Err(invalid("acl is not enforced by forwardproxy when an upstream is set"));
    }
    let normalised = json!({"schema": SCHEMA, "upstream": upstream, "acl": rules});
    if canonical(&normalised).len() > MAX_DOCUMENT_BYTES {
        return Err(invalid("egress document too large"));
    }
    Ok(normalised)
}

pub fn canonical(document: &Value) -> String {
    crate::pyjson::dumps(document, crate::pyjson::CANONICAL)
}

#[cfg(test)]
pub fn document_digest(document: &Value) -> String {
    sha256_hex(canonical(document).as_bytes())
}

/// The revision the panel pins an apply to: the managed block (or the adopted lines).
pub fn revision_of_lines<S: AsRef<str>>(raw: &[S]) -> String {
    let joined = join_lines(raw);
    sha256_hex(if joined.is_empty() { "direct" } else { &joined }.as_bytes())
}

pub fn revision_of(text: &str) -> Result<String> {
    Ok(parse(text)?.revision)
}

pub fn parse(text: &str) -> Result<ParsedEgress> {
    let lines = splitlines(text);
    let (start, end) = forward_proxy_bounds(&lines)?;
    let begins: Vec<usize> = (start + 1..end).filter(|&i| strip(lines[i]) == EGRESS_BEGIN).collect();
    let ends: Vec<usize> = (start + 1..end).filter(|&i| strip(lines[i]) == EGRESS_END).collect();
    if begins.len() > 1 || ends.len() > 1 || begins.len() != ends.len() {
        return Err(invalid("managed egress block must have exactly one marker pair"));
    }
    let (body, outside, managed): (Vec<usize>, Vec<usize>, bool) =
        if let (Some(&b), Some(&e)) = (begins.first(), ends.first()) {
            if b >= e {
                return Err(invalid("managed egress block markers are out of order"));
            }
            ((b + 1..e).collect(), (start + 1..end).filter(|i| !(b..=e).contains(i)).collect(), true)
        } else {
            (Vec::new(), (start + 1..end).collect(), false)
        };
    for &index in &outside {
        if (upstream_target(lines[index]).is_some() || is_acl_open(lines[index])) && managed {
            return Err(invalid("upstream or acl directive outside the managed egress block"));
        }
    }
    let raw_indexes: Vec<usize> =
        if managed { (begins[0]..=ends[0]).collect() } else { unmanaged_egress_lines(&lines, &outside)? };
    let scan: Vec<&str> = if managed { &body } else { &raw_indexes }.iter().map(|&i| lines[i]).collect();
    let mut upstream: Option<String> = None;
    let mut deny: Vec<String> = Vec::new();
    let mut index = 0;
    while index < scan.len() {
        let line = scan[index];
        if let Some(target) = upstream_target(line) {
            if upstream.is_some() {
                return Err(invalid("more than one upstream directive"));
            }
            upstream = Some(target.to_string());
        } else if is_acl_open(line) {
            index += 1;
            while index < scan.len() && strip(scan[index]) != "}" {
                if let Some(subjects) = deny_subjects(scan[index]) {
                    deny.extend(subjects.into_iter().map(String::from));
                } else if !strip(scan[index]).is_empty() && !strip(scan[index]).starts_with('#') {
                    return Err(invalid("unsupported acl directive"));
                }
                index += 1;
            }
        } else if !strip(line).is_empty() && !strip(line).starts_with('#') && managed {
            return Err(invalid("unsupported directive in the managed egress block"));
        }
        index += 1;
    }
    let raw: Vec<String> = raw_indexes.iter().map(|&i| lines[i].to_string()).collect();
    let mode = match (&upstream, managed) {
        (Some(_), false) => "custom",
        (Some(_), true) => "proxy",
        (None, _) => "direct",
    };
    // `"proxy" if upstream` — an empty upstream cannot be matched, so `Some` is truthy here.
    Ok(ParsedEgress {
        mode: mode.into(),
        upstream,
        acl_deny: deny,
        managed,
        revision: revision_of_lines(&raw),
        raw_lines: raw,
    })
}

/// The indexes of unmanaged `upstream` lines and whole `acl { … }` blocks.
fn unmanaged_egress_lines(lines: &[&str], indexes: &[usize]) -> Result<Vec<usize>> {
    let mut found = Vec::new();
    let mut skip_until: i64 = -1;
    for &index in indexes {
        if index as i64 <= skip_until {
            found.push(index);
            continue;
        }
        if upstream_target(lines[index]).is_some() {
            found.push(index);
        } else if is_acl_open(lines[index]) {
            let last = *indexes.last().expect("iterating a non-empty list");
            let mut depth: i64 = 0;
            let mut closed = false;
            for (probe, line) in lines.iter().enumerate().take(last + 1).skip(index) {
                depth += line.matches('{').count() as i64 - line.matches('}').count() as i64;
                if depth == 0 {
                    skip_until = probe as i64;
                    closed = true;
                    break;
                }
            }
            if !closed {
                return Err(invalid("unterminated acl block"));
            }
            found.push(index);
        }
    }
    Ok(found)
}

/// Every `scheme://user:pass@host` in `text` with its userinfo masked.
pub fn redact_userinfo(text: &str) -> String {
    sub_userinfo(text, "***@")
}

/// The endpoint without its credential: what views and comparisons use.
pub fn strip_userinfo(url: &str) -> String {
    sub_userinfo(url, "")
}

/// The upstream URL the document names, or `None` for direct; `EgressInvalid` when the
/// provider is not configured on this host.
pub fn resolve_provider(document: &Value, providers: &Providers) -> Result<Option<String>> {
    let upstream = document.get("upstream").unwrap_or(&Value::Null);
    if upstream.is_null() {
        return Ok(None);
    }
    let name = upstream.get("provider").and_then(Value::as_str).unwrap_or("");
    match providers.get(name) {
        Some(url) if !url.is_empty() => Ok(Some(url.to_string())),
        _ => Err(invalid(format!("egress provider {name} is not configured on this node"))),
    }
}

/// `user:password` of the router ingress credential file, or `EgressInvalid`.
pub fn read_credential(path: &Path) -> Result<(String, String)> {
    let text = match std::fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| Error::value("'utf-8' codec can't decode the file"))?,
        Err(_) => return Err(invalid("egress provider router credential is unavailable on this node")),
    };
    let text = strip(&text);
    let malformed = || invalid("egress provider router credential is malformed");
    let (user, password) = text.split_once(':').ok_or_else(malformed)?;
    if !crate::lanes::is_account_user(user) || !crate::lanes::is_account_password(password) {
        return Err(malformed());
    }
    Ok((user.to_string(), password.to_string()))
}

/// `urllib.parse.urlsplit(url)`: scheme and network location.
pub fn split_url(url: &str) -> (String, String) {
    let url: String = url.chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let url = url.trim_start_matches(|c: char| c <= ' ');
    let mut scheme = String::new();
    let mut rest = url;
    if let Some(colon) = url.find(':') {
        let candidate = &url[..colon];
        if colon > 0
            && candidate.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && candidate.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            scheme = candidate.to_ascii_lowercase();
            rest = &url[colon + 1..];
        }
    }
    let netloc = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            after[..end].to_string()
        }
        None => String::new(),
    };
    (scheme, netloc)
}

/// `socks5://user:pass@host:port` for the router ingress (RFC 3986 userinfo, escaped).
pub fn with_credential(url: &str, credential: &(String, String)) -> String {
    let (scheme, netloc) = split_url(&strip_userinfo(url));
    format!("{scheme}://{}:{}@{netloc}", quote(&credential.0), quote(&credential.1))
}

pub fn block_lines(document: &Value, providers: &Providers, indent: &str) -> Result<Vec<String>> {
    let upstream = resolve_provider(document, providers)?;
    let mut lines = vec![format!("{indent}{EGRESS_BEGIN}")];
    if let Some(upstream) = upstream {
        lines.push(format!("{indent}upstream {upstream}"));
    }
    for rule in document.get("acl").and_then(Value::as_array).into_iter().flatten() {
        let deny: Vec<&str> =
            rule.get("deny").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
        lines.extend([
            format!("{indent}acl {{"),
            format!("{indent}    deny {}", deny.join(" ")),
            format!("{indent}}}"),
        ]);
    }
    lines.push(format!("{indent}{EGRESS_END}"));
    Ok(lines)
}

/// The Caddyfile with the managed block carrying `document`, everything else verbatim.
pub fn render(text: &str, document: &Value, providers: &Providers) -> Result<String> {
    let parsed = parse(text)?;
    let lines = splitlines(text);
    let indent = indent_of(&lines)?;
    let block = block_lines(document, providers, &indent)?;
    replace(&lines, &parsed, block)
}

/// The Caddyfile with the managed block replaced by `raw_lines` verbatim (a rollback to the
/// lines a first apply adopted).
pub fn render_raw(text: &str, raw_lines: &[String]) -> Result<String> {
    let parsed = parse(text)?;
    let lines = splitlines(text);
    replace(&lines, &parsed, raw_lines.to_vec())
}

fn indent_of(lines: &[&str]) -> Result<String> {
    let (start, end) = forward_proxy_bounds(lines)?;
    for line in &lines[start + 1..end] {
        if !strip(line).is_empty() {
            return Ok(leading_space(line).to_string());
        }
    }
    Ok(format!("{}    ", leading_space(lines[start])))
}

fn replace(lines: &[&str], parsed: &ParsedEgress, block: Vec<String>) -> Result<String> {
    let (start, end) = forward_proxy_bounds(lines)?;
    let mut owned: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    if parsed.managed {
        let begin = (start + 1..end).find(|&i| strip(lines[i]) == EGRESS_BEGIN).expect("parsed as managed");
        let finish = (start + 1..end).find(|&i| strip(lines[i]) == EGRESS_END).expect("parsed as managed");
        owned.splice(begin..=finish, block);
        return Ok(join_lines(&owned) + "\n");
    }
    // Adoption: the unmanaged lines go, the block lands after `probe_resistance` (or at the
    // end of the handler) — where the installer's template would have put it.
    let drop: std::collections::HashSet<usize> =
        unmanaged_egress_lines(lines, &(start + 1..end).collect::<Vec<_>>())?.into_iter().collect();
    let mut kept: Vec<String> =
        owned.into_iter().enumerate().filter(|(i, _)| !drop.contains(i)).map(|(_, line)| line).collect();
    let borrowed: Vec<&str> = kept.iter().map(String::as_str).collect();
    let (start, end) = forward_proxy_bounds(&borrowed)?;
    let anchor = (start + 1..end).find(|&i| is_probe_resistance(borrowed[i]));
    let position = anchor.map(|a| a + 1).unwrap_or(end);
    kept.splice(position..position, block);
    Ok(join_lines(&kept) + "\n")
}

/// `urlsplit(url).hostname` and `.port`; a malformed port is a `ValueError`.
fn host_and_port(url: &str) -> Result<(Option<String>, Option<u16>)> {
    let (_, netloc) = split_url(url);
    let hostinfo = netloc.rsplit_once('@').map(|(_, h)| h).unwrap_or(&netloc);
    let (hostname, port) = match hostinfo.split_once('[') {
        Some((_, bracketed)) => {
            let (host, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (host, after.split_once(':').map(|(_, p)| p).unwrap_or(""))
        }
        None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
    };
    let hostname = if hostname.is_empty() {
        None
    } else {
        let (host, zone) = hostname.split_once('%').map(|(h, z)| (h, Some(z))).unwrap_or((hostname, None));
        Some(match zone {
            Some(zone) => format!("{}%{zone}", host.to_lowercase()),
            None => host.to_lowercase(),
        })
    };
    let port = if port.is_empty() {
        None
    } else if port.bytes().all(|b| b.is_ascii_digit()) {
        match port.parse::<u32>() {
            Ok(value) if value <= 65535 => Some(value as u16),
            _ => return Err(Error::value("Port out of range 0-65535")),
        }
    } else {
        return Err(Error::value("Port could not be cast to integer value"));
    };
    Ok((hostname, port))
}

/// A SOCKS5 greeting for `socks5://` — offering no authentication, or (`auth`) the
/// username/password method the router ingress demands, without completing it; a TCP connect
/// for `http(s)://`. The answer is the fact; only a malformed port is an error.
pub fn check_reachable(url: &str, timeout: f64, auth: bool) -> Result<bool> {
    use std::io::{Read, Write};
    let (scheme, _) = split_url(url);
    let (host, port) = host_and_port(url)?;
    let (Some(host), Some(port)) = (host, port.filter(|p| *p != 0)) else { return Ok(false) };
    let timeout = Duration::from_secs_f64(timeout);
    let method = if auth { 0x02 } else { 0x00 };
    let Ok(addresses) = (host.as_str(), port).to_socket_addrs() else { return Ok(false) };
    for address in addresses {
        let Ok(mut stream) = TcpStream::connect_timeout(&address, timeout) else { continue };
        if scheme != "socks5" && scheme != "socks5h" {
            return Ok(true);
        }
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        if stream.write_all(&[0x05, 0x01, method]).is_err() {
            return Ok(false);
        }
        let mut reply = [0u8; 2];
        return Ok(match stream.read(&mut reply) {
            Ok(n) => reply[..n] == [0x05, method],
            Err(_) => false,
        });
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WARP: &str = "socks5://127.0.0.1:45000";
    const LEGACY: &str = "{
    admin 127.0.0.1:2019
}
:4443 {
    bind 127.0.0.1
    route {
        forward_proxy {
            # BEGIN NAIVE-MANAGER USERS
            basic_auth alice pw-alice
            # END NAIVE-MANAGER USERS
            hide_ip
            hide_via
            probe_resistance
            upstream http://127.0.0.1:8118
        }
        file_server { root /var/www/naive }
    }
}
";

    fn direct() -> String {
        LEGACY.replace("            upstream http://127.0.0.1:8118\n", "")
    }

    fn block(text: &str) -> Vec<String> {
        let lines = splitlines(text);
        let begin = lines.iter().position(|l| strip(l) == EGRESS_BEGIN).unwrap();
        let end = lines.iter().position(|l| strip(l) == EGRESS_END).unwrap();
        lines[begin..=end].iter().map(|l| l.to_string()).collect()
    }

    fn doc(value: Value) -> Result<Value> {
        validate_document(&value)
    }

    fn message(result: Result<Value>) -> String {
        result.unwrap_err().message().to_string()
    }

    fn warp() -> Providers {
        Providers::warp(Some(WARP))
    }

    #[test]
    fn validate_document_rejects_unknown_fields_and_schema() {
        assert!(
            message(doc(json!({"schema": 1, "upstream": null, "acl": [], "path": "/etc"}))).contains("unknown field")
        );
        assert!(message(doc(json!({"schema": 2, "upstream": null, "acl": []}))).contains("schema"));
        assert!(message(doc(json!({"schema": 1, "upstream": {"provider": "socks5://evil"}, "acl": []})))
            .contains("provider"));
        assert!(message(doc(json!({"schema": 1, "upstream": {"provider": "warp", "url": "x"}, "acl": []})))
            .contains("provider"));
        assert!(message(doc(
            json!({"schema": 1, "upstream": {"provider": "warp"}, "acl": [{"deny": ["example.com"]}]})
        ))
        .contains("not enforced"));
    }

    #[test]
    fn validate_document_normalises_subjects_and_bounds() {
        let normalised = doc(json!({"schema": 1, "upstream": null,
            "acl": [{"deny": ["Example.COM", "*.Example.com", "10.1.2.3/8", "2001:db8::1"]}]}))
        .unwrap();
        assert_eq!(
            normalised["acl"],
            json!([{"deny": ["example.com", "*.example.com", "10.0.0.0/8", "2001:db8::1/128"]}])
        );
        let long = "a".repeat(260);
        for bad in ["not a host", "example.com/24", "*.", "-bad.example", long.as_str(), ""] {
            assert!(doc(json!({"schema": 1, "upstream": null, "acl": [{"deny": [bad]}]})).is_err(), "{bad}");
        }
        let many_rules: Vec<Value> = (0..=MAX_RULES).map(|_| json!({"deny": ["a.example"]})).collect();
        assert!(message(doc(json!({"schema": 1, "upstream": null, "acl": many_rules}))).contains("invalid acl list"));
        let many: Vec<String> = (0..=MAX_SUBJECTS).map(|i| format!("h{i}.example")).collect();
        assert!(message(doc(json!({"schema": 1, "upstream": null, "acl": [{"deny": many}]}))).contains("too many"));
        assert!(message(doc(json!({"schema": 1, "upstream": null, "acl": [{"allow": ["example.com"]}]})))
            .contains("invalid acl rule"));
        assert_eq!(
            document_digest(&doc(json!({"schema": 1, "upstream": null, "acl": []})).unwrap()),
            document_digest(&json!({"acl": [], "schema": 1, "upstream": null}))
        );
    }

    #[test]
    fn subjects_normalise_exactly_like_python_ipaddress() {
        // egress.valid_subject(value) from python:3.13.5 (None = EgressInvalid).
        let vectors: Value = serde_json::from_str(include_str!("testdata/subjects.json")).unwrap();
        for pair in vectors.as_array().unwrap() {
            let (input, expected) = (&pair[0], pair[1].as_str());
            assert_eq!(valid_subject(input).ok().as_deref(), expected, "{input}");
        }
    }

    #[test]
    fn parse_reports_an_unmanaged_upstream_as_custom_and_a_bare_handler_as_direct() {
        let parsed = parse(LEGACY).unwrap();
        assert_eq!(
            (parsed.mode.as_str(), parsed.upstream.as_deref(), parsed.managed),
            ("custom", Some("http://127.0.0.1:8118"), false)
        );
        assert_eq!(parsed.raw_lines, ["            upstream http://127.0.0.1:8118"]);
        let bare = parse(&direct()).unwrap();
        assert_eq!((bare.mode.as_str(), bare.upstream.as_deref(), bare.managed), ("direct", None, false));
        assert!(bare.raw_lines.is_empty());
        assert!(bare.revision != parsed.revision && revision_of(&direct()).unwrap() == bare.revision);
    }

    #[test]
    fn render_adopts_the_unmanaged_upstream_into_a_block_and_keeps_the_rest() {
        let document = doc(json!({"schema": 1, "upstream": {"provider": "warp"}, "acl": []})).unwrap();
        let rendered = render(LEGACY, &document, &warp()).unwrap();
        assert!(!rendered.contains("upstream http://127.0.0.1:8118"));
        assert_eq!(
            block(&rendered),
            [
                format!("            {EGRESS_BEGIN}"),
                format!("            upstream {WARP}"),
                format!("            {EGRESS_END}")
            ]
        );
        // The block lands right after probe_resistance; every other line is untouched.
        assert_eq!(rendered.replace(&(block(&rendered).join("\n") + "\n"), ""), direct());
        let parsed = parse(&rendered).unwrap();
        assert_eq!((parsed.mode.as_str(), parsed.upstream.as_deref(), parsed.managed), ("proxy", Some(WARP), true));
        // Rolling back to the adopted lines restores the original bytes.
        assert_eq!(render_raw(&rendered, &parse(LEGACY).unwrap().raw_lines).unwrap(), LEGACY);
    }

    #[test]
    fn render_replaces_an_existing_block_and_direct_has_no_upstream_line() {
        let warp_text = render(
            &direct(),
            &doc(json!({"schema": 1, "upstream": {"provider": "warp"}, "acl": []})).unwrap(),
            &warp(),
        )
        .unwrap();
        let direct_text =
            render(&warp_text, &doc(json!({"schema": 1, "upstream": null, "acl": []})).unwrap(), &warp()).unwrap();
        assert_eq!(block(&direct_text), [format!("            {EGRESS_BEGIN}"), format!("            {EGRESS_END}")]);
        assert!(!direct_text.contains("upstream"));
        let parsed = parse(&direct_text).unwrap();
        assert!(parsed.mode == "direct" && parsed.managed);
        assert_eq!(direct_text.replace(&(block(&direct_text).join("\n") + "\n"), ""), direct());
        let (a, b, c) =
            (revision_of(&direct_text).unwrap(), revision_of(&warp_text).unwrap(), revision_of(&direct()).unwrap());
        assert!(a != b && a != c);
    }

    #[test]
    fn render_acl_deny_lines_and_parse_reads_them_back() {
        let document = doc(json!({"schema": 1, "upstream": null,
            "acl": [{"deny": ["example.com", "*.example.com"]}, {"deny": ["10.0.0.0/8"]}]}))
        .unwrap();
        let rendered = render(&direct(), &document, &Providers::default()).unwrap();
        assert_eq!(
            block(&rendered),
            [
                format!("            {EGRESS_BEGIN}"),
                "            acl {".to_string(),
                "                deny example.com *.example.com".to_string(),
                "            }".to_string(),
                "            acl {".to_string(),
                "                deny 10.0.0.0/8".to_string(),
                "            }".to_string(),
                format!("            {EGRESS_END}"),
            ]
        );
        let parsed = parse(&rendered).unwrap();
        assert_eq!(parsed.acl_deny, ["example.com", "*.example.com", "10.0.0.0/8"]);
        assert_eq!(parsed.mode, "direct");
    }

    #[test]
    fn render_refuses_a_provider_this_host_does_not_have() {
        let document = doc(json!({"schema": 1, "upstream": {"provider": "warp"}, "acl": []})).unwrap();
        let err = render(&direct(), &document, &Providers::default()).unwrap_err();
        assert!(matches!(&err, Error::EgressInvalid(m) if m.contains("not configured")));
    }

    #[test]
    fn parse_refuses_directives_outside_the_managed_block_or_broken_markers() {
        let managed =
            render(&direct(), &doc(json!({"schema": 1, "upstream": null, "acl": []})).unwrap(), &Providers::default())
                .unwrap();
        let outside = managed
            .replace("            hide_via\n", "            hide_via\n            upstream socks5://127.0.0.1:1\n");
        assert!(parse(&outside).unwrap_err().message().contains("outside the managed"));
        let unpaired = managed.replace(&format!("            {EGRESS_END}\n"), "");
        assert!(parse(&unpaired).unwrap_err().message().contains("marker pair"));
        assert!(parse("{\n}\n:4443 {\n}\n").unwrap_err().message().contains("forward_proxy"));
    }

    #[test]
    fn check_reachable_socks5_greeting_and_refused() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            if stream.read_exact(&mut greeting).is_ok() && greeting == [5, 1, 0] {
                stream.write_all(&[5, 0]).unwrap();
            }
        });
        assert!(check_reachable(&format!("socks5://127.0.0.1:{port}"), 2.0, false).unwrap());
        server.join().unwrap();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        assert!(!check_reachable(&format!("socks5://127.0.0.1:{port}"), 1.0, false).unwrap());
        assert!(!check_reachable("socks5://127.0.0.1", 1.0, false).unwrap());
    }

    #[test]
    fn check_reachable_http_is_a_tcp_connect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::thread::spawn(move || drop(listener.accept()));
        assert!(check_reachable(&format!("http://127.0.0.1:{port}"), 2.0, false).unwrap());
        accepted.join().unwrap();
    }

    #[test]
    fn redact_userinfo_masks_credentials_in_urls() {
        let line = "    upstream socks5://alice:s3cret@127.0.0.1:1080 # https://bob:pw@proxy.example:443/x";
        assert_eq!(redact_userinfo(line), "    upstream socks5://***@127.0.0.1:1080 # https://***@proxy.example:443/x");
        assert_eq!(redact_userinfo("upstream socks5://127.0.0.1:45000"), "upstream socks5://127.0.0.1:45000");
        assert_eq!(redact_userinfo(""), "");
    }

    #[test]
    fn credentials_and_urls_follow_urllib() {
        let credential = ("naive-a1b2c3d4".to_string(), "K".repeat(40));
        assert_eq!(
            with_credential("socks5://old:key@127.0.0.1:45101", &credential),
            format!("socks5://naive-a1b2c3d4:{}@127.0.0.1:45101", "K".repeat(40))
        );
        assert_eq!(split_url("SOCKS5://h:1/x?y"), ("socks5".to_string(), "h:1".to_string()));
        assert!(host_and_port("socks5://h:99999").is_err());
        assert_eq!(host_and_port("socks5://U@[::1]:5").unwrap(), (Some("::1".to_string()), Some(5)));
    }
}
