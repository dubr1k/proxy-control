//! The MTProxy page (`panel/telemt_routes.py`): Telemt's user rows and the host agent's telemetry
//! mapped through allow-lists — a future upstream field never reaches the UI — and the check of a
//! `tg://proxy` link before the panel turns it into a QR code.

use panel_core::pytext;
use serde_json::{json, Map, Value};

use crate::py::{self, as_dict, non_negative_int};
use crate::{Fault, PageResult};

const STRING_FIELDS: &[&str] = &["username", "expiration_rfc3339"];
const BOOL_FIELDS: &[&str] = &["enabled", "in_runtime"];
const INTEGER_FIELDS: &[&str] = &[
    "max_tcp_conns",
    "data_quota_bytes",
    "rate_limit_up_bps",
    "rate_limit_down_bps",
    "max_unique_ips",
    "current_connections",
    "active_unique_ips",
    "recent_unique_ips",
];

/// `safe_user(data, quota)`: Telemt's user view in the panel's contract.
pub fn safe_user(data: &Value, quota: Option<&Value>) -> Value {
    let Some(data) = data.as_object() else {
        return json!({});
    };
    let mut result = Map::new();
    for key in STRING_FIELDS {
        match data.get(*key) {
            Some(value @ Value::String(_)) => {
                result.insert((*key).into(), value.clone());
            }
            Some(Value::Null) if *key == "expiration_rfc3339" => {
                result.insert((*key).into(), Value::Null);
            }
            _ => {}
        }
    }
    for key in BOOL_FIELDS {
        if let Some(value @ Value::Bool(_)) = data.get(*key) {
            result.insert((*key).into(), value.clone());
        }
    }
    for key in INTEGER_FIELDS {
        match data.get(*key) {
            Some(Value::Null) => {
                result.insert((*key).into(), Value::Null);
            }
            value => {
                if let Some(value) = non_negative_int(value) {
                    result.insert((*key).into(), value.clone());
                }
            }
        }
    }
    if let Some(total) = non_negative_int(data.get("total_octets")) {
        result.insert("runtime_total_octets".into(), total.clone());
    }
    if let Some(quota) = as_dict(quota) {
        if let Some(used) = non_negative_int(quota.get("used_bytes")) {
            result.insert("quota_used_bytes".into(), used.clone());
        }
        if let Some(reset) = non_negative_int(quota.get("last_reset_epoch_secs")) {
            result.insert("quota_last_reset_epoch_secs".into(), reset.clone());
        }
    }
    Value::Object(result)
}

/// `_safe_usage(data, extra)`: byte totals plus the percentage (clamped, one decimal), or `None`.
fn safe_usage(data: Option<&Map<String, Value>>, extra: &[&str]) -> Option<Map<String, Value>> {
    let data = data?;
    let mut result = Map::new();
    for key in ["total_bytes", "available_bytes", "used_bytes"].iter().chain(extra) {
        if let Some(value) = non_negative_int(data.get(*key)) {
            result.insert((*key).into(), value.clone());
        }
    }
    if let Some(percent) = py::number(data.get("used_percent")) {
        // `min(100.0, max(0.0, percent))`: Python keeps the first argument unless the other wins.
        let floor = if percent > 0.0 { percent } else { 0.0 };
        let clamped = if floor < 100.0 { floor } else { 100.0 };
        result.insert("used_percent".into(), py::float_value(py::round_to(clamped, 1)));
    }
    (!result.is_empty()).then_some(result)
}

fn usage_value(usage: Option<Map<String, Value>>) -> Value {
    usage.map_or(Value::Null, Value::Object)
}

/// `safe_host(data)`: the host agent's telemetry; each section stands alone.
pub fn safe_host(data: &Value) -> Value {
    let Some(data) = data.as_object() else {
        return json!({"available": false, "reason": "invalid_host_metrics"});
    };
    let empty = Map::new();
    let cpu_raw = as_dict(data.get("cpu")).unwrap_or(&empty);
    let mut cpu = safe_usage(Some(cpu_raw), &["cores"]).unwrap_or_default();
    if let Some(Value::Array(load)) = cpu_raw.get("load_average") {
        let numbers: Vec<f64> = load.iter().filter_map(|value| py::number(Some(value))).collect();
        if load.len() == 3 && numbers.len() == 3 && numbers.iter().all(|value| *value >= 0.0) {
            let rounded: Vec<Value> = numbers.iter().map(|value| py::float_value(py::round_to(*value, 2))).collect();
            cpu.insert("load_average".into(), Value::Array(rounded));
        }
    }
    json!({
        "available": true,
        "cpu": if cpu.is_empty() { Value::Null } else { Value::Object(cpu) },
        "memory": usage_value(safe_usage(as_dict(data.get("memory")), &[])),
        // An agent older than v1.0 has no swap section: null, and the card says nothing.
        "swap": usage_value(safe_usage(as_dict(data.get("swap")), &[])),
        "disk": usage_value(safe_usage(as_dict(data.get("disk")), &[])),
    })
}

/// What `/api/host` (and the dashboard's `host`) answers when the agent cannot be asked.
pub fn host_unavailable() -> Value {
    json!({"available": false, "reason": "version_agent_unavailable"})
}

/// `safe_quota_reset(data)`.
pub fn safe_quota_reset(data: &Value) -> Value {
    let Some(data) = data.as_object() else {
        return json!({});
    };
    let mut result = Map::new();
    if let Some(username @ Value::String(_)) = data.get("username") {
        result.insert("username".into(), username.clone());
    }
    for key in ["used_bytes", "last_reset_epoch_secs"] {
        if let Some(value) = non_negative_int(data.get(key)) {
            result.insert(key.into(), value.clone());
        }
    }
    Value::Object(result)
}

/// `quota_by_username(data)`: the quota rows by user name (a later row wins).
pub fn quota_by_username(data: &Value) -> PageResult<Map<String, Value>> {
    let rows = match data.as_object() {
        Some(map) => map.get("users").cloned().unwrap_or_else(|| json!([])),
        None => json!([]),
    };
    let mut out = Map::new();
    for row in py::dict_items(&rows)? {
        if let Some(Value::String(username)) = row.get("username") {
            out.insert(username.clone(), Value::Object(row.clone()));
        }
    }
    Ok(out)
}

/// `GET /api/users`: every user row through [`safe_user`], with its quota row.
pub fn user_items(items: &Value, quota_data: &Value) -> PageResult<Value> {
    let quotas = quota_by_username(quota_data)?;
    let mut out = Vec::new();
    for item in py::dict_items(items)? {
        let quota = py::key_of(item.get("username"))?.and_then(|name| quotas.get(name));
        out.push(safe_user(&Value::Object(item.clone()), quota));
    }
    Ok(json!({"items": out}))
}

/// `candidates[0]` of a truthy value: a list's first item, a string's first character.
fn first_of(candidates: &Value) -> PageResult<Value> {
    match candidates {
        Value::Array(items) => Ok(items[0].clone()),
        Value::String(text) => Ok(Value::String(text.chars().next().map(String::from).unwrap_or_default())),
        Value::Object(_) => Err(Fault::crash("KeyError: 0")),
        other => Err(Fault::crash(format!(
            "TypeError: '{}' object is not subscriptable",
            pc_common::pyvalue::type_name(other)
        ))),
    }
}

/// `secret_reveal(data)`: `{"secret", "link", "qr"?}` of a create/rotate answer or a user row —
/// the QR only for a link [`proxy_link`] accepts.
pub fn secret_reveal(data: &Value) -> PageResult<Value> {
    let map = py::dict(data)?;
    let user = match map.get("user") {
        Some(user @ Value::Object(_)) => user,
        _ => data,
    };
    let links = user.get("links").cloned().unwrap_or_else(|| json!({}));
    let candidates = match &links {
        Value::Object(links) => links.get("tls").cloned().unwrap_or_else(|| json!([])),
        _ => json!([]),
    };
    let link = if py::truthy(Some(&candidates)) {
        first_of(&candidates)?
    } else {
        map.get("link").cloned().unwrap_or(Value::Null)
    };
    let mut result = Map::new();
    result.insert("secret".into(), map.get("secret").cloned().unwrap_or(Value::Null));
    result.insert("link".into(), link.clone());
    if let Ok(checked) = proxy_link(&link) {
        result.insert("qr".into(), Value::String(qr(&checked)?));
    }
    Ok(Value::Object(result))
}

/// `qr_data(link)`; a payload too large for a QR code is Python's `ValueError` (a 500).
pub fn qr(link: &str) -> PageResult<String> {
    panel_protocols::reveals::qr_data(link).map_err(|_| Fault::crash("ValueError: the data is too large for a QR code"))
}

/// `parse_qs(query, keep_blank_values=True)` as ordered `(name, values)`.
pub fn parse_qs(query: &str) -> Vec<(String, Vec<String>)> {
    let decode = |text: &str| pytext::unquote(&text.replace('+', " "));
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for field in query.split('&').filter(|field| !field.is_empty()) {
        let (name, value) = match field.split_once('=') {
            Some((name, value)) => (decode(name), decode(value)),
            None => (decode(field), String::new()),
        };
        match out.iter_mut().find(|(key, _)| *key == name) {
            Some((_, values)) => values.push(value),
            None => out.push((name, vec![value])),
        }
    }
    out
}

fn ascii_class(text: &str, min: usize, max: usize, allowed: impl Fn(char) -> bool) -> bool {
    let count = text.chars().count();
    (min..=max).contains(&count) && text.chars().all(allowed)
}

/// `proxy_link(value)`: only a canonical Telegram MTProxy link (`tg://proxy?…` or
/// `https://t.me/proxy?…`) with exactly `server`, `port` and `secret`; anything else is 409
/// "connection link unavailable".
pub fn proxy_link(value: &Value) -> PageResult<String> {
    let refused = || Fault::detail(409, "connection link unavailable");
    let Value::String(text) = value else {
        return Err(refused());
    };
    if text.chars().count() > 2048 {
        return Err(refused());
    }
    let Ok(parts) = pytext::urlsplit(text) else {
        return Err(refused());
    };
    let telegram = (parts.scheme == "tg" && parts.netloc == "proxy" && matches!(parts.path.as_str(), "" | "/"))
        || (parts.scheme == "https"
            && matches!(parts.netloc.as_str(), "t.me" | "telegram.me")
            && parts.path == "/proxy");
    let query = parse_qs(&parts.query);
    let values = |name: &str| query.iter().find(|(key, _)| key == name).map(|(_, values)| values.as_slice());
    let names: std::collections::BTreeSet<&str> = query.iter().map(|(key, _)| key.as_str()).collect();
    let (server, port, secret) = (values("server"), values("port"), values("secret"));
    let one = |values: Option<&[String]>| values.filter(|values| values.len() == 1).map(|values| values[0].clone());
    let server_valid = one(server).is_some_and(|server| {
        pytext::ip_address(&server).is_ok()
            || ascii_class(&server, 1, 253, |ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
    });
    let port_valid = one(port).is_some_and(|port| {
        ascii_class(&port, 1, 5, |ch| ch.is_ascii_digit()) && (1..=65535).contains(&port.parse::<u32>().unwrap_or(0))
    });
    let secret_valid = one(secret).is_some_and(|secret| ascii_class(&secret, 32, 512, |ch| ch.is_ascii_hexdigit()));
    let valid = telegram
        && parts.fragment.is_empty()
        && parts.username().is_none_or(str::is_empty)
        && parts.password().is_none_or(str::is_empty)
        && names == ["port", "secret", "server"].into_iter().collect()
        && server_valid
        && port_valid
        && secret_valid;
    if valid {
        Ok(text.clone())
    } else {
        Err(refused())
    }
}

/// The first row whose `username` matches, with Python's iteration and `.get` failures intact.
/// Used after domain creation and by `/access`, where a missing row becomes `None` / 404.
pub fn find_user(items: &Value, username: &str) -> PageResult<Option<Value>> {
    let username = Value::String(username.to_string());
    let matches = |candidate: &Value| -> PageResult<bool> {
        let row = py::dict(candidate)?;
        Ok(row.get("username").is_some_and(|found| py::eq(found, &username)))
    };
    match items {
        Value::Array(rows) => {
            for candidate in rows {
                if matches(candidate)? {
                    return Ok(Some(candidate.clone()));
                }
            }
        }
        Value::Object(rows) => {
            for key in rows.keys() {
                let candidate = Value::String(key.clone());
                if matches(&candidate)? {
                    return Ok(Some(candidate));
                }
            }
        }
        Value::String(text) => {
            for ch in text.chars() {
                let candidate = Value::String(ch.to_string());
                if matches(&candidate)? {
                    return Ok(Some(candidate));
                }
            }
        }
        other => {
            return Err(Fault::crash(format!(
                "TypeError: '{}' object is not iterable",
                pc_common::pyvalue::type_name(other)
            )))
        }
    }
    Ok(None)
}

/// `POST /api/users/{username}/access`: the link and QR of the user row, 409 without a valid link.
pub fn user_access(username: &str, selected: &Value) -> PageResult<Value> {
    let access = secret_reveal(selected)?;
    if !py::truthy(access.get("link")) {
        return Err(Fault::detail(409, "connection link unavailable"));
    }
    let link = proxy_link(&access["link"])?;
    Ok(json!({"username": username, "link": link, "qr": qr(&link)?}))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "tg://proxy?server=proxy.example.com&port=443&secret=ee0123456789abcdef0123456789abcdef";

    #[test]
    fn user_api_allowlist_drops_unknown_and_nested_future_secret_fields() {
        let row = json!({
            "username": "alice", "enabled": true, "total_octets": 12, "current_connections": 2,
            "links": {"tls": [LINK]}, "secret": "x", "future": {"secret": "y"}, "max_tcp_conns": null,
            "data_quota_bytes": -1, "in_runtime": 1, "expiration_rfc3339": null,
        });
        let quota = json!({"used_bytes": 4, "last_reset_epoch_secs": true});
        assert_eq!(
            safe_user(&row, Some(&quota)),
            json!({
                "username": "alice", "expiration_rfc3339": null, "enabled": true, "max_tcp_conns": null,
                "current_connections": 2, "runtime_total_octets": 12, "quota_used_bytes": 4,
            })
        );
        assert_eq!(safe_user(&json!([1]), None), json!({}));
        let listed = user_items(&json!([row, 5]), &json!({"users": [{"username": "alice", "used_bytes": 1}]})).unwrap();
        assert_eq!(listed["items"][0]["quota_used_bytes"], 1);
        assert!(user_items(&json!(null), &json!({})).is_err());
    }

    #[test]
    fn overview_reports_host_resources_from_the_agent() {
        let host = safe_host(&json!({
            "cpu": {"used_percent": 12.5, "cores": 4, "load_average": [0.5, 0.4, 0.3], "secret_field": "never"},
            "memory": {"total_bytes": 10, "used_percent": 27.35},
            "disk": {"available_bytes": 71_940_702_208u64, "used_percent": 150},
            "swap": "nope",
        }));
        assert_eq!(
            host,
            json!({
                "available": true,
                "cpu": {"cores": 4, "used_percent": 12.5, "load_average": [0.5, 0.4, 0.3]},
                "memory": {"total_bytes": 10, "used_percent": 27.4},
                "swap": null,
                "disk": {"available_bytes": 71_940_702_208u64, "used_percent": 100.0},
            })
        );
        assert_eq!(
            panel_core::pyjson::compact_utf8(&host["disk"]),
            r#"{"available_bytes":71940702208,"used_percent":100.0}"#
        );
        assert_eq!(safe_host(&json!({}))["cpu"], Value::Null);
        assert_eq!(safe_host(&json!(3)), json!({"available": false, "reason": "invalid_host_metrics"}));
    }

    #[test]
    fn access_returns_sanitized_conflict_for_malformed_upstream_url() {
        assert_eq!(proxy_link(&json!(LINK)).unwrap(), LINK);
        let https = "https://t.me/proxy?server=1.2.3.4&port=1&secret=ee0123456789abcdef0123456789abcdef";
        assert!(proxy_link(&json!(https)).is_ok());
        let v6 = "tg://proxy?server=2001:db8::1&port=443&secret=ee0123456789abcdef0123456789abcdef";
        assert!(proxy_link(&json!(v6)).is_ok());
        for bad in [
            "javascript:alert(document.domain)",
            "tg://proxy?server=proxy.example.com&port=%C2%B2&secret=ee0123456789abcdef0123456789abcdef",
            "https://[invalid/proxy?server=x&port=443&secret=ee0123456789abcdef0123456789abcdef",
            "tg://proxy?server=proxy.example.com&port=0&secret=ee0123456789abcdef0123456789abcdef",
            "tg://proxy?server=proxy.example.com&port=443&secret=ee0123456789abcdef0123456789abcdef&x=1",
            "tg://proxy?server=a&server=b&port=443&secret=ee0123456789abcdef0123456789abcdef",
            "tg://u@proxy?server=a&port=443&secret=ee0123456789abcdef0123456789abcdef",
            "tg://proxy?server=a&port=443&secret=ee0123456789abcdef0123456789abcdef#x",
            "tg://proxy?server=a&port=443&secret=0123",
        ] {
            let refused = proxy_link(&json!(bad)).unwrap_err();
            assert_eq!(refused, Fault::detail(409, "connection link unavailable"), "{bad}");
        }
        assert!(proxy_link(&Value::Null).is_err());
    }

    #[test]
    fn created_and_rotated_reveals_carry_the_qr_the_access_dialog_requires() {
        let created = json!({"user": {"links": {"tls": [LINK]}}, "secret": "0123456789abcdef0123456789abcdef"});
        let reveal = secret_reveal(&created).unwrap();
        assert_eq!(reveal["link"], LINK);
        assert!(reveal["qr"].as_str().unwrap().starts_with("data:image/svg+xml;base64,"));
        let bare = secret_reveal(&json!({"user": null, "secret": "s"})).unwrap();
        assert_eq!(bare, json!({"secret": "s", "link": null}));
        assert!(secret_reveal(&json!([])).is_err());
        let access = user_access("alice", &json!({"username": "alice", "links": {"tls": ["tg://secret"]}}));
        assert_eq!(access.unwrap_err(), Fault::detail(409, "connection link unavailable"));
    }

    #[test]
    fn limit_and_reset_responses_use_allowlists() {
        let changed =
            safe_user(&json!({"username": "alice", "enabled": false, "future": {"secret": "operation-secret"}}), None);
        assert_eq!(changed, json!({"username": "alice", "enabled": false}));
        let reset = safe_quota_reset(&json!({"username": "a", "used_bytes": 0, "last_reset_epoch_secs": 5, "x": 1}));
        assert_eq!(reset, json!({"username": "a", "used_bytes": 0, "last_reset_epoch_secs": 5}));
    }

    #[test]
    fn host_resources_report_a_reason_when_the_agent_is_silent() {
        assert_eq!(host_unavailable(), json!({"available": false, "reason": "version_agent_unavailable"}));
    }

    #[test]
    fn admin_can_reopen_share_link_and_qr_without_exposing_it_in_lists_or_audit() {
        let row = json!({"username": "alice", "enabled": true, "links": {"tls": [LINK]}});
        assert_eq!(find_user(&json!([row.clone()]), "alice").unwrap(), Some(row.clone()));
        assert_eq!(find_user(&json!([]), "alice").unwrap(), None);
        let first = user_access("alice", &row).unwrap();
        let second = user_access("alice", &row).unwrap();
        assert_eq!(first, second);
        assert_eq!(first["link"], LINK);
        assert!(first["qr"].as_str().unwrap().starts_with("data:image/svg+xml;base64,"));
        assert_eq!(safe_user(&row, None), json!({"username": "alice", "enabled": true}));
    }
}
