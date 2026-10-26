//! NaiveProxy's page (`panel/naive_routes.py`): strict traffic and quota allow-lists, the
//! secret-free user rows, and the client configurations handed to a one-time reveal.

use panel_core::pytext;
use panel_managers::{Manager, ManagerError};
use panel_protocols::reveals::{karing_client, qr_data};
use serde_json::{json, Map, Value};

use crate::py::{self, account_name, dict_items, member};
use crate::{Fault, PageResult};

const INVALID_TRAFFIC: &str = "Invalid NaiveProxy traffic response";
const INVALID_QUOTA: &str = "Invalid NaiveProxy quota response";
const COUNTERS: &[&str] = &["upload_bytes", "download_bytes", "total_bytes"];
const SEMANTICS: &[&str] = &[
    "closed_connect_tunnels_only",
    "active_tunnels_appear_on_close",
    "crash_can_lose_active_tunnel",
    "completed_records_survive_restart",
    "excludes_tls_ip_overhead",
    "reset_is_local_baseline_only",
];

fn invalid_traffic() -> Fault {
    ManagerError::plain(Manager::Naive, INVALID_TRAFFIC).into()
}

fn strict_int(value: Option<&Value>, minimum: i64) -> Option<i64> {
    let Some(Value::Number(number)) = value else {
        return None;
    };
    if number.is_f64() {
        return None;
    }
    number
        .as_i64()
        .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
        .filter(|value| *value >= minimum)
}

/// `safe_naive_traffic(data)`: only well-formed per-user counters cross into the panel. Bad rows
/// are dropped; a bad envelope or an aggregate beyond a signed 64-bit integer is `NaiveError`.
pub fn safe_naive_traffic(data: &Value) -> PageResult<Value> {
    let Some(data) = data.as_object() else {
        return Err(invalid_traffic());
    };
    let empty = json!([]);
    let source_rows = data.get("users").unwrap_or(&empty);
    let mut rows = Vec::new();
    for row in dict_items(source_rows)? {
        let username_value = row.get("username").unwrap_or(&Value::Null);
        let username_text = row.get("username").map_or_else(String::new, py::py_str);
        if !account_name(&username_text) {
            continue;
        }
        let mut values = [0_i64; 3];
        let mut decimals = Vec::with_capacity(3);
        let mut valid = true;
        for (index, key) in COUNTERS.iter().enumerate() {
            let Some(value) = strict_int(row.get(*key), 0) else {
                valid = false;
                break;
            };
            values[index] = value;
            let decimal = row.get(&format!("{key}_decimal"));
            let expected = value.to_string();
            if decimal.is_some_and(|decimal| decimal.as_str() != Some(expected.as_str())) {
                valid = false;
                break;
            }
            decimals.push(decimal.and_then(Value::as_str).unwrap_or(&expected).to_string());
        }
        if !valid || i128::from(values[0]) + i128::from(values[1]) != i128::from(values[2]) {
            continue;
        }
        if !matches!(row.get("period_start"), Some(Value::String(_)))
            || !matches!(row.get("updated_at"), Some(Value::String(_)))
        {
            continue;
        }
        rows.push(json!({
            "username": username_value,
            "upload_bytes": values[0],
            "download_bytes": values[1],
            "total_bytes": values[2],
            "upload_bytes_decimal": decimals[0],
            "download_bytes_decimal": decimals[1],
            "total_bytes_decimal": decimals[2],
            "period_start": row["period_start"],
            "updated_at": row["updated_at"],
        }));
    }
    let directions = json!({
        "upload_bytes": "client_to_proxy",
        "download_bytes": "proxy_to_client",
    });
    if data.get("source") != Some(&json!("caddy_connect_access_log"))
        || data.get("unit") != Some(&json!("bytes"))
        || !data.get("directions").is_some_and(|value| py::eq(value, &directions))
    {
        return Err(invalid_traffic());
    }
    let empty_semantics = Map::new();
    let semantics = data.get("semantics").and_then(Value::as_object).unwrap_or(&empty_semantics);
    let mut safe_semantics = Map::new();
    for key in SEMANTICS {
        if let Some(value @ Value::Bool(_)) = semantics.get(*key) {
            safe_semantics.insert((*key).into(), value.clone());
        }
    }
    let sums = rows.iter().fold([0_i128; 3], |mut sums, row| {
        for (index, key) in COUNTERS.iter().enumerate() {
            sums[index] += i128::from(row[*key].as_i64().unwrap_or(0));
        }
        sums
    });
    if sums[2] > i128::from(i64::MAX) {
        return Err(invalid_traffic());
    }
    Ok(json!({
        "source": "caddy_connect_access_log",
        "unit": "bytes",
        "directions": directions,
        "pending": py::is_true(data.get("pending")),
        "aggregate": {
            "upload_bytes": sums[0] as i64,
            "download_bytes": sums[1] as i64,
            "total_bytes": sums[2] as i64,
            "upload_bytes_decimal": sums[0].to_string(),
            "download_bytes_decimal": sums[1].to_string(),
            "total_bytes_decimal": sums[2].to_string(),
        },
        "users": rows,
        "semantics": safe_semantics,
    }))
}

/// `safe_naive_quota(value)`: `None`, or a strict positive signed 64-bit integer.
pub fn safe_naive_quota(value: Option<&Value>) -> PageResult<Option<i64>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        value => {
            strict_int(value, 1).map(Some).ok_or_else(|| ManagerError::plain(Manager::Naive, INVALID_QUOTA).into())
        }
    }
}

fn zero_traffic() -> Value {
    json!({
        "upload_bytes": 0,
        "download_bytes": 0,
        "total_bytes": 0,
        "upload_bytes_decimal": "0",
        "download_bytes_decimal": "0",
        "total_bytes_decimal": "0",
        "period_start": "",
        "updated_at": "",
    })
}

/// `GET /api/naive/users`: the manager's rows with their traffic and derived quota fields.
pub fn users(health: &Value, items: &Value, traffic_raw: &Value, public_host: &str) -> PageResult<Value> {
    let traffic = safe_naive_traffic(traffic_raw)?;
    let traffic_rows = traffic["users"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let mut safe_items = Vec::new();
    for item in dict_items(items)? {
        let username_value = item.get("username").unwrap_or(&Value::Null);
        let username_text = item.get("username").map_or_else(String::new, py::py_str);
        if !account_name(&username_text) {
            continue;
        }
        let disabled_reason =
            member(item.get("disabled_reason"), &["manual", "quota"])?.cloned().unwrap_or(Value::Null);
        let quota = safe_naive_quota(item.get("quota_bytes"))?;
        let mut row = Map::new();
        row.insert("username".into(), username_value.clone());
        row.insert("enabled".into(), json!(py::is_true(item.get("enabled"))));
        row.insert("disabled_reason".into(), disabled_reason);
        row.insert("quota_bytes".into(), quota.map_or(Value::Null, |quota| json!(quota)));
        let carried = traffic_rows
            .iter()
            .rev()
            .find(|candidate| py::eq(&candidate["username"], username_value))
            .cloned()
            .unwrap_or_else(zero_traffic);
        for (key, value) in carried.as_object().into_iter().flatten() {
            row.insert(key.clone(), value.clone());
        }
        let used = row["total_bytes"].as_i64().unwrap_or(0);
        let remaining = quota.map(|quota| (i128::from(quota) - i128::from(used)).max(0) as i64);
        row.insert("quota_bytes_decimal".into(), quota.map_or(Value::Null, |quota| json!(quota.to_string())));
        row.insert("quota_used_bytes".into(), json!(used));
        row.insert("quota_used_bytes_decimal".into(), json!(used.to_string()));
        row.insert("quota_remaining_bytes".into(), remaining.map_or(Value::Null, |remaining| json!(remaining)));
        row.insert(
            "quota_remaining_bytes_decimal".into(),
            remaining.map_or(Value::Null, |remaining| json!(remaining.to_string())),
        );
        row.insert("quota_exhausted".into(), json!(quota.is_some_and(|quota| used >= quota)));
        safe_items.push(Value::Object(row));
    }
    let health = py::dict(health)?;
    Ok(json!({
        "items": safe_items,
        "service": {"ready": py::is_true(health.get("ready")), "host": public_host},
        "traffic": {
            "source": traffic["source"],
            "unit": traffic["unit"],
            "directions": traffic["directions"],
            "pending": traffic["pending"],
        },
    }))
}

/// The allow-listed answer of `POST …/quota`.
pub fn quota_result(username: &str, result: &Value) -> PageResult<Value> {
    let Some(result) = result.as_object() else {
        return Err(Fault::detail(502, INVALID_QUOTA));
    };
    let quota = safe_naive_quota(result.get("quota_bytes"))?;
    let mut payload = json!({"username": username, "quota_bytes": quota});
    if result.contains_key("enabled") {
        payload["enabled"] = json!(py::is_true(result.get("enabled")));
        payload["disabled_reason"] =
            member(result.get("disabled_reason"), &["manual", "quota"])?.cloned().unwrap_or(Value::Null);
    }
    Ok(payload)
}

/// The single sanitized row returned by `POST …/traffic/reset`.
pub fn traffic_reset(data: &Value) -> PageResult<Value> {
    let traffic = safe_naive_traffic(&json!({
        "source": "caddy_connect_access_log",
        "unit": "bytes",
        "directions": {"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"},
        "pending": false,
        "users": [data],
        "semantics": {},
    }))?;
    traffic["users"][0]
        .as_object()
        .map(|_| traffic["users"][0].clone())
        .ok_or_else(|| Fault::detail(502, INVALID_TRAFFIC))
}

fn qr(link: &str) -> PageResult<String> {
    qr_data(link).map_err(|_| Fault::crash("ValueError: the data is too large for a QR code"))
}

/// `naive_reveal(value, username)`: validate the manager's current HTTPS URL before putting its
/// password into any client configuration.
pub fn reveal(value: &Value, username: &str, public_host: &str) -> PageResult<Value> {
    let refused = || Fault::detail(409, "NaiveProxy access unavailable");
    let Some(raw) = value.as_object().and_then(|value| value.get("proxy_url")).and_then(Value::as_str) else {
        return Err(refused());
    };
    let mut password = None;
    let valid = match pytext::urlsplit(raw) {
        Ok(parts) => {
            let port = parts.port();
            let decoded_username = pytext::unquote(parts.username().unwrap_or_default());
            let decoded_password = pytext::unquote(parts.password().unwrap_or_default());
            password = Some(decoded_password.clone());
            parts.scheme == "https"
                && parts.hostname().as_deref() == Some(public_host)
                && matches!(port, Ok(None | Some(443)))
                && decoded_username == username
                && !decoded_password.is_empty()
                && matches!(parts.path.as_str(), "" | "/")
                && parts.query.is_empty()
                && parts.fragment.is_empty()
                && pytext::len(raw) <= 2048
        }
        Err(_) => false,
    };
    if !valid {
        return Err(refused());
    }
    let password = password.unwrap_or_default();
    let native_config = json!({"listen": "socks://127.0.0.1:1080", "proxy": raw});
    let karing_config = json!({
        "outbounds": [{
            "type": "naive",
            "tag": format!("naive-{username}"),
            "server": public_host,
            "server_port": 443,
            "username": username,
            "password": password,
            "tls": {"enabled": true, "server_name": public_host},
        }]
    });
    let nekobox_url = format!(
        "naive+https://{}:{}@{}:443#{}",
        pytext::quote(username, ""),
        pytext::quote(&password, ""),
        public_host,
        pytext::quote(&format!("Naive · {username}"), ""),
    );
    Ok(json!({
        "service": "naive",
        "username": username,
        "clients": {
            "native": {
                "label": "NaiveProxy",
                "type": "config",
                "config": native_config,
                "filename": format!("naive-{username}.json"),
            },
            "nekobox": {
                "label": "NekoBox",
                "type": "link",
                "share_url": nekobox_url,
                "qr": {"payload": nekobox_url, "image": qr(&nekobox_url)?},
            },
            "karing": karing_client(
                &karing_config,
                &format!("Naive · {username}"),
                &format!("karing-naive-{username}.json"),
            ).map_err(|_| Fault::crash("ValueError: the data is too large for a QR code"))?,
            "shadowrocket": {
                "label": "Shadowrocket",
                "type": "manual",
                "fields": {
                    "proxy_type": "HTTPS",
                    "server": public_host,
                    "port": 443,
                    "username": username,
                    "password": password,
                },
            },
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn traffic(rows: Value) -> Value {
        json!({
            "source": "caddy_connect_access_log", "unit": "bytes",
            "directions": {"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"},
            "users": rows,
        })
    }

    #[test]
    fn traffic_rows_are_allowlisted_and_aggregated_exactly() {
        let safe = safe_naive_traffic(&traffic(json!([
            {"username": "phone", "upload_bytes": 2, "download_bytes": 3, "total_bytes": 5,
             "period_start": "now", "updated_at": "now", "password": "never"},
            {"username": "bad", "upload_bytes": 1, "download_bytes": 2, "total_bytes": 4,
             "period_start": "now", "updated_at": "now"},
        ])))
        .unwrap();
        assert_eq!(safe["aggregate"]["total_bytes_decimal"], "5");
        assert_eq!(safe["users"].as_array().unwrap().len(), 1);
        assert!(safe_naive_traffic(&json!([])).is_err());
        assert!(safe_naive_traffic(&traffic(json!([{
            "username": "a", "upload_bytes": i64::MAX, "download_bytes": 1, "total_bytes": 0,
            "period_start": "", "updated_at": ""
        }])))
        .unwrap()["users"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn quotas_are_strict_positive_integers() {
        assert_eq!(safe_naive_quota(Some(&json!(null))).unwrap(), None);
        assert_eq!(safe_naive_quota(Some(&json!(1))).unwrap(), Some(1));
        for bad in [json!(0), json!(true), json!(1.0), json!("1")] {
            assert!(safe_naive_quota(Some(&bad)).is_err());
        }
    }

    #[test]
    fn reveal_rejects_a_foreign_or_malformed_proxy_url() {
        for bad in [
            "http://phone:secret@naive.example.com",
            "https://other:secret@naive.example.com",
            "https://phone:secret@naive.example.com:444",
            "https://phone:secret@naive.example.com/path",
        ] {
            assert_eq!(
                reveal(&json!({"proxy_url": bad}), "phone", "naive.example.com").unwrap_err(),
                Fault::detail(409, "NaiveProxy access unavailable")
            );
        }
    }
}
