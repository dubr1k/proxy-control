//! Bytes per protocol for `GET /api/fleet/v2/status` (`node_routes.py:_traffic`), best effort:
//! what each manager exposes, `None` where it exposes nothing (mita) or cannot answer right now.

use serde_json::{json, Value};

const MAX: i128 = i64::MAX as i128;

/// Python's `int(value or 0)`, as far as JSON values go; `Err` where Python raised (a 500).
pub fn py_int(value: Option<&Value>) -> Result<i128, String> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Bool(flag)) => Ok(i128::from(*flag)),
        Some(Value::Number(number)) => {
            if let Some(int) = number.as_i64() {
                Ok(i128::from(int))
            } else if let Some(int) = number.as_u64() {
                Ok(i128::from(int))
            } else {
                let float = number.as_f64().unwrap_or(0.0);
                if float.is_finite() {
                    Ok(float.trunc() as i128)
                } else {
                    Err("cannot convert float infinity to integer".into())
                }
            }
        }
        Some(Value::String(text)) if text.is_empty() => Ok(0),
        Some(Value::String(text)) => panel_core::pytext::int_from_str(text)
            .map(i128::from)
            .map_err(|_| format!("invalid literal for int() with base 10: {}", panel_core::pytext::repr(text))),
        Some(Value::Array(items)) if items.is_empty() => Ok(0),
        Some(Value::Object(map)) if map.is_empty() => Ok(0),
        Some(other) => Err(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            pc_common::pyvalue::type_name(other)
        )),
    }
}

fn saturate(value: i128) -> i64 {
    value.clamp(i128::from(i64::MIN), MAX) as i64
}

/// Telemt: one counter per user, no direction split (`total_octets`, non-negative ints only).
pub fn telemt(users: &Value) -> Value {
    let total: i128 = users
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_object()?.get("total_octets"))
        .filter_map(|value| match value {
            Value::Number(number) if !number.is_f64() => {
                number.as_i64().map(i128::from).or(number.as_u64().map(i128::from))
            }
            _ => None,
        })
        .filter(|value| *value >= 0)
        .sum();
    json!({"upload_bytes": null, "download_bytes": null, "total_bytes": saturate(total)})
}

/// `int(row.get("rx") or 0)` summed over the dict rows: rx is what clients uploaded, tx what they
/// downloaded (TrustTunnel's endpoint and AmneziaWG's server interface alike).
pub fn rx_tx(rows: &Value) -> Result<Value, String> {
    let (mut up, mut down) = (0i128, 0i128);
    for row in rows.as_array().into_iter().flatten().filter(|row| row.is_object()) {
        up += py_int(row.get("rx"))?;
        down += py_int(row.get("tx"))?;
    }
    Ok(json!({"upload_bytes": saturate(up), "download_bytes": saturate(down), "total_bytes": saturate(up + down)}))
}

fn is_username(text: &str) -> bool {
    (1..=64).contains(&text.chars().count())
        && text.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
}

/// An exact Python `int` (not a bool) in `0..=2**63-1`.
fn counter(value: Option<&Value>) -> Option<i128> {
    match value {
        Some(Value::Number(number)) if !number.is_f64() => {
            let value = number.as_i64().map(i128::from).or(number.as_u64().map(i128::from))?;
            (0..=MAX).contains(&value).then_some(value)
        }
        _ => None,
    }
}

/// `safe_naive_traffic(data)["aggregate"]`'s three counters, or `None` where it raised
/// `NaiveError` (an answer that is not the manager's traffic envelope).
pub fn naive(data: &Value) -> Option<Value> {
    let map = data.as_object()?;
    let (mut up, mut down, mut total) = (0i128, 0i128, 0i128);
    if let Some(Value::Array(rows)) = map.get("users") {
        for row in rows {
            let Some(row) = row.as_object() else { continue };
            let name = row.get("username").map_or_else(String::new, pyrepr::str);
            if !is_username(&name) {
                continue;
            }
            let keys = ["upload_bytes", "download_bytes", "total_bytes"];
            let values: Vec<Option<i128>> = keys.iter().map(|key| counter(row.get(*key))).collect();
            let [Some(u), Some(d), Some(t)] = values[..] else { continue };
            if u + d != t {
                continue;
            }
            let decimals_match =
                keys.iter().zip([u, d, t]).all(|(key, value)| match row.get(&format!("{key}_decimal")) {
                    None => true,
                    Some(Value::String(text)) => *text == value.to_string(),
                    Some(_) => false,
                });
            if !decimals_match
                || !row.get("period_start").is_some_and(Value::is_string)
                || !row.get("updated_at").is_some_and(Value::is_string)
            {
                continue;
            }
            up += u;
            down += d;
            total += t;
        }
    }
    let directions = json!({"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"});
    if map.get("source") != Some(&json!("caddy_connect_access_log"))
        || map.get("unit") != Some(&json!("bytes"))
        || !map.get("directions").is_some_and(|value| pyrepr::eq(value, &directions))
        || total > MAX
    {
        return None;
    }
    Some(json!({"upload_bytes": saturate(up), "download_bytes": saturate(down), "total_bytes": saturate(total)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(users: Value) -> Value {
        json!({"source": "caddy_connect_access_log", "unit": "bytes", "pending": false,
               "directions": {"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"},
               "users": users})
    }

    #[test]
    fn naive_traffic_keeps_only_consistent_rows() {
        let row = |name: &str, up: i64, down: i64| {
            json!({"username": name, "upload_bytes": up, "download_bytes": down, "total_bytes": up + down,
                   "period_start": "p", "updated_at": "u"})
        };
        let mut wrong_total = row("eve", 1, 2);
        wrong_total["total_bytes"] = json!(4);
        let mut wrong_decimal = row("mallory", 1, 2);
        wrong_decimal["total_bytes_decimal"] = json!("4");
        let data = envelope(json!([row("bob", 10, 20), row("carol", 1, 2), wrong_total, wrong_decimal,
                                   row("bad name", 5, 5), {"username": "x", "upload_bytes": true}]));
        assert_eq!(naive(&data), Some(json!({"upload_bytes": 11, "download_bytes": 22, "total_bytes": 33})));
        assert_eq!(naive(&json!({"source": "other"})), None);
        assert_eq!(naive(&json!([])), None);
    }

    #[test]
    fn counters_sum_like_python() {
        assert_eq!(
            telemt(&json!([{"total_octets": 7}, {"total_octets": true}, {"total_octets": -1}, "x"]))["total_bytes"],
            7
        );
        let rows = json!([{"rx": 5, "tx": "7"}, {"rx": null, "tx": 2.9}, "ignored"]);
        assert_eq!(rx_tx(&rows).unwrap(), json!({"upload_bytes": 5, "download_bytes": 9, "total_bytes": 14}));
        assert!(rx_tx(&json!([{"rx": "abc"}])).is_err());
        assert!(rx_tx(&json!([{"rx": [1]}])).is_err());
    }
}
