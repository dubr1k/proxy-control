//! Mieru's page (`panel/mieru_routes.py`): its native and Karing reveals, the per-user traffic
//! map, live lane templates and the secret-free listing.

use std::collections::{BTreeMap, BTreeSet};

use panel_core::pytext;
use panel_managers::{Manager, ManagerError};
use panel_protocols::mieru::{self, parse_share_url};
use panel_protocols::reveals::{karing_client, qr_data};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::py::{self, account_name, dict_items};
use crate::{Fault, PageResult};

/// The panel cannot show a password mita issued before escrow existed.
pub const NOT_KEPT: &str = "Панель не хранит ключ этого пользователя: он был выдан до того, как ключи Mieru стали сохраняться. Выпустите новую ссылку один раз — дальше ключ будет показываться без ротации.";

/// `username -> (upload_bytes, download_bytes)`; values remain JSON integers (Python also
/// accepts booleans here because `isinstance(True, int)`).
pub type Traffic = BTreeMap<String, (Value, Value)>;

fn qr(link: &str) -> PageResult<String> {
    qr_data(link).map_err(|_| Fault::crash("ValueError: the data is too large for a QR code"))
}

fn karing(config: &Value, name: &str, filename: &str) -> PageResult<Value> {
    karing_client(config, name, filename).map_err(|_| Fault::crash("ValueError: the data is too large for a QR code"))
}

/// `mieru_access(value)`: the native mieru configuration, and Karing only when every port is
/// exact (a range cannot be turned into a sing-box endpoint).
pub fn access(value: &Value) -> PageResult<Value> {
    let refused = || Fault::detail(409, "Mieru connection link unavailable");
    let Some(value) = value.as_str() else {
        return Err(refused());
    };
    let share = parse_share_url(value).map_err(|_| refused())?;
    let mut server = Map::new();
    server.insert("portBindings".into(), json!(share.bindings));
    server.insert(if share.is_ip { "ipAddress".into() } else { "domainName".into() }, json!(share.host));
    let profile_name = share.profile.clone();
    let native_config = json!({
        "profiles": [{
            "profileName": profile_name,
            "user": {"name": share.username, "password": share.password},
            "servers": [server],
            "mtu": share.mtu,
        }],
        "activeProfile": profile_name,
        "rpcPort": 50000,
        "socks5Port": 1080,
        "socks5ListenLAN": false,
        "loggingLevel": "INFO",
    });
    let native = json!({
        "label": "Mieru",
        "type": "config",
        "config": native_config,
        "filename": "mieru-client.json",
        "apply_command": "mieru apply config mieru-client.json",
        "simple_share_url": value,
        "qr": {"payload": value, "image": qr(value)?},
    });
    let mut clients = Map::new();
    clients.insert("native".into(), native);
    let mut unsupported = Map::new();
    unsupported.insert("nekobox".into(), json!("Проверенный формат импорта Mieru для NekoBox+ отсутствует."));
    unsupported.insert("shadowrocket".into(), json!("Проверенный формат импорта Mieru для Shadowrocket отсутствует."));
    if let Some(outbounds) = mieru::singbox_outbounds(&share, |port, protocol| format!("mieru-{protocol}-{port}")) {
        let digest = format!("{:x}", Sha256::digest(share.password.as_bytes()));
        let generation = &digest[..8];
        clients.insert(
            "karing".into(),
            karing(
                &json!({"outbounds": outbounds}),
                &format!("Mieru · {profile_name} · {generation}"),
                &format!("karing-mieru-{profile_name}.json"),
            )?,
        );
    } else {
        unsupported
            .insert("karing".into(), json!("Профиль Karing доступен только для точных портов Mieru, не диапазонов."));
    }
    Ok(json!({
        "service": "mieru",
        "username": profile_name,
        "clients": clients,
        "unsupported_clients": unsupported,
    }))
}

/// The pure half of `mieru_traffic(app)`: an old manager's failure and a malformed traffic
/// response both mean unavailable, never zero. The route turns a `MieruError` into `None` too.
pub fn traffic_map(data: &Value) -> Option<Traffic> {
    let rows = data.as_object()?.get("users")?.as_array()?;
    let mut traffic = Traffic::new();
    for row in rows.iter().filter_map(Value::as_object) {
        let Some(username) = row.get("username").and_then(Value::as_str) else {
            continue;
        };
        let integer = |value: Option<&Value>| {
            matches!(value, Some(Value::Bool(_))) || matches!(value, Some(Value::Number(number)) if !number.is_f64())
        };
        let (Some(upload), Some(download)) = (row.get("upload_bytes"), row.get("download_bytes")) else {
            continue;
        };
        if integer(Some(upload)) && integer(Some(download)) {
            traffic.insert(username.to_string(), (upload.clone(), download.clone()));
        }
    }
    Some(traffic)
}

/// `GET /api/mieru/users`: kept-credential state, mita counters and rolling quotas; typed quota
/// histories deliberately remain unavailable.
pub fn users(
    health: &Value,
    items: &Value,
    metrics: &Value,
    traffic: Option<&Traffic>,
    credential_kept: &BTreeSet<String>,
) -> PageResult<Value> {
    // Python builds metric_map before checking the exact unavailable document. Keep that order:
    // malformed containers/keys crash instead of becoming the later manager-error response.
    let metric_data = py::dict(metrics)?.get("users").cloned().unwrap_or_else(|| json!([]));
    let metric_rows = dict_items(&metric_data)?;
    for row in &metric_rows {
        py::key_of(row.get("username"))?;
    }
    let expected = panel_managers::mieru::metrics_unavailable();
    if !py::eq(metrics, &expected) {
        return Err(ManagerError::plain(Manager::Mieru, "Invalid Mieru metrics response").into());
    }
    let mut safe = Vec::new();
    for item in dict_items(items)? {
        let username_value = item.get("username").unwrap_or(&Value::Null);
        let username_text = item.get("username").map_or_else(String::new, py::py_str);
        if !account_name(&username_text) {
            continue;
        }
        let kept = username_value.as_str().is_some_and(|username| credential_kept.contains(username));
        let quotas = item.get("quotas").filter(|quotas| quotas.is_array()).cloned().unwrap_or_else(|| json!([]));
        let mut row = json!({
            "username": username_value,
            "enabled": py::is_true(item.get("enabled")),
            "credential_kept": kept,
            "traffic_available": false,
            "quotas": quotas,
        });
        if let Some(traffic) = traffic {
            let carried = username_value.as_str().and_then(|username| traffic.get(username));
            let (upload, download) = carried.map_or((json!(0), json!(0)), |(up, down)| (up.clone(), down.clone()));
            row["traffic_available"] = json!(true);
            row["upload_bytes"] = upload;
            row["download_bytes"] = download;
        }
        if let Some(metric) = metric_rows.iter().rev().find(|metric| py::eq(&metric["username"], username_value)) {
            for key in ["upload_bytes", "download_bytes", "application_bytes", "stale"] {
                if let Some(value) = metric.get(key) {
                    row[key] = value.clone();
                }
            }
        }
        safe.push(row);
    }
    let health = py::dict(health)?;
    Ok(json!({
        "items": safe,
        "metrics": {"capability": "unavailable", "reason": "typed_histories_unavailable"},
        "service": {
            "ready": py::is_true(health.get("ready")),
            "status": health.get("status").cloned().unwrap_or(Value::Null),
            "revision": health.get("revision").cloned().unwrap_or(Value::Null),
        },
        "traffic": {"available": traffic.is_some(), "since": "mita_start"},
        "quota_semantics": "rolling application-byte admission quota (approximate)",
    }))
}

/// `live_template(username)` applied to a `GET /v1/lanes` answer: the user's lane slot first,
/// then the service-wide template. A manager failure is handled by the route as `None`.
pub fn live_template(view: &Value, username: &str) -> PageResult<Option<String>> {
    let Some(view) = view.as_object() else {
        return Ok(None);
    };
    let empty = json!([]);
    for entry in dict_items(view.get("lanes").unwrap_or(&empty))? {
        let empty_templates = Map::new();
        let raw = entry.get("share_templates");
        let templates = if py::truthy(raw) { py::dict(raw.unwrap_or(&Value::Null))? } else { &empty_templates };
        if let Some(Value::String(template)) = templates.get(username) {
            return Ok(Some(template.clone()));
        }
    }
    Ok(view.get("service_share_template").and_then(Value::as_str).map(str::to_string))
}

/// Format a live template with exactly the three fields Python supplies. Any other or malformed
/// placeholder makes the caller fall back to the adapter's learned template.
pub fn format_live_template(template: &str, username: &str, password: &str) -> Option<String> {
    mieru::format(
        template,
        &[
            ("username", pytext::quote(username, "")),
            ("password", pytext::quote(password, "")),
            ("profile", pytext::quote(username, "")),
        ],
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mieru_ipv6_reveal_canonicalizes_native_and_karing_addresses() {
        let reveal =
            access(&json!("mierus://phone:secret@[2001:0db8::1]?profile=phone&port=8443&protocol=TCP")).unwrap();
        let server = &reveal["clients"]["native"]["config"]["profiles"][0]["servers"][0];
        assert_eq!(server["ipAddress"], "2001:db8::1");
        assert_eq!(reveal["clients"]["karing"]["config"]["outbounds"][0]["server"], "2001:db8::1");
    }

    #[test]
    fn mieru_range_reveal_keeps_native_link_and_does_not_fabricate_karing_endpoint() {
        let reveal =
            access(&json!("mierus://phone:secret@mieru.example.com?profile=phone&port=8000-8010&protocol=TCP"))
                .unwrap();
        let clients = reveal["clients"].as_object().unwrap();
        assert!(clients.len() == 1 && clients.contains_key("native"));
        assert_eq!(
            reveal["clients"]["native"]["config"]["profiles"][0]["servers"][0]["portBindings"],
            json!([{"portRange": "8000-8010", "protocol": "TCP"}])
        );
        assert_eq!(
            reveal["unsupported_clients"]["karing"],
            "Профиль Karing доступен только для точных портов Mieru, не диапазонов."
        );
    }

    #[test]
    fn mieru_reveal_rejects_invalid_authority_port_as_a_controlled_conflict() {
        let error =
            access(&json!("mierus://phone:secret@mieru.example.com:99999?profile=phone&port=8443&protocol=TCP"))
                .unwrap_err();
        assert_eq!(error, Fault::detail(409, "Mieru connection link unavailable"));
    }

    #[test]
    fn traffic_unavailability_is_not_a_zero() {
        assert!(traffic_map(&json!({"users": []})).unwrap().is_empty());
        assert!(traffic_map(&json!({})).is_none());
        let mapped = traffic_map(&json!({"users": [
            {"username": "a", "upload_bytes": 1, "download_bytes": 2},
            {"username": "b", "upload_bytes": "1", "download_bytes": 2},
        ]}))
        .unwrap();
        assert_eq!(mapped["a"], (json!(1), json!(2)));
        assert!(!mapped.contains_key("b"));
    }
}
