//! `GET /api/dashboard` (`panel/telemt_routes.py:252-458`): one card per protocol, built from what
//! each manager answered. A protocol switched off is `{"available": false, "status": "disabled"}`;
//! a manager that failed is a degraded card, never a failed page (Telemt excepted: the dashboard is
//! its page, and a Telemt failure is the app's 502).

use serde_json::{json, Map, Value};

use crate::py::{self, dict_items, int_value};
use crate::PageResult;

/// The card of a protocol that is switched off.
pub fn disabled() -> Value {
    json!({"available": false, "status": "disabled"})
}

/// The MTProxy card and the runtime total (`traffic.runtime_total_octets`).
pub fn mtproxy(health: &Value, connections: &Value, active_ips: &Value, items: &Value) -> PageResult<(Value, Value)> {
    let rows = dict_items(items)?;
    let total: i128 =
        rows.iter().filter_map(|item| py::non_negative_int(item.get("total_octets"))).filter_map(py::integer).sum();
    let active = rows.iter().filter(|item| !py::is_false(item.get("enabled"))).count();
    let disabled = rows.iter().filter(|item| py::is_false(item.get("enabled"))).count();
    let ready = py::is_true(py::dict(health)?.get("ready"));
    let current = py::dict(connections)?.get("active").cloned().unwrap_or_else(|| json!(0));
    let card = json!({
        "status": if ready { "ready" } else { "degraded" },
        "ready": ready,
        "credentials": {"active": active, "disabled": disabled, "total": active + disabled},
        "runtime": {
            "traffic_octets": int_value(total),
            "current_connections": current,
            "active_ips": py::py_len(active_ips)?,
        },
    });
    Ok((card, int_value(total)))
}

/// The NaiveProxy card when the manager could not be read (or answered nonsense).
pub fn naive_degraded(public_host: &str) -> Value {
    json!({
        "available": true,
        "status": "degraded",
        "ready": false,
        "host": public_host,
        "credentials": {"available": false},
        "traffic": {"available": false, "reason": "manager_unavailable"},
    })
}

/// The NaiveProxy card from its health, its users and the allow-listed traffic.
pub fn naive(public_host: &str, health: &Value, items: &Value, traffic: &Value) -> PageResult<Value> {
    let rows = dict_items(items)?;
    let active = rows.iter().filter(|item| py::is_true(item.get("enabled"))).count();
    let disabled = rows.len() - active;
    let ready = py::is_true(py::dict(health)?.get("ready"));
    let mut traffic_card = Map::new();
    traffic_card.insert("available".into(), Value::Bool(true));
    for (key, value) in traffic.as_object().into_iter().flatten() {
        traffic_card.insert(key.clone(), value.clone());
    }
    Ok(json!({
        "available": true,
        "status": if ready { "ready" } else { "degraded" },
        "ready": ready,
        "host": public_host,
        "credentials": {"active": active, "disabled": disabled, "total": active + disabled},
        "traffic": traffic_card,
    }))
}

/// The Mieru card when the manager could not be read.
pub fn mieru_degraded() -> Value {
    json!({
        "available": true,
        "status": "degraded",
        "ready": false,
        "credentials": {"available": false},
        "traffic": {"available": false, "label": "application bytes"},
    })
}

/// The Mieru card; `traffic` is the per-user byte map of [`crate::mieru::traffic_map`] (`None`
/// from a manager without the traffic route).
pub fn mieru(health: &Value, users: &Value, traffic: Option<&crate::mieru::Traffic>) -> PageResult<Value> {
    let rows = dict_items(users)?;
    let active = rows.iter().filter(|item| py::is_true(item.get("enabled"))).count();
    let disabled = rows.len() - active;
    let health = py::dict(health)?;
    let ready = py::is_true(health.get("ready"));
    let traffic = match traffic {
        Some(traffic) => {
            let upload: i128 = traffic.values().map(|(up, _)| py::integer(up).unwrap_or(0)).sum();
            let download: i128 = traffic.values().map(|(_, down)| py::integer(down).unwrap_or(0)).sum();
            json!({"available": true, "label": "application bytes", "since": "mita_start",
                   "upload_bytes": int_value(upload), "download_bytes": int_value(download)})
        }
        None => json!({"available": false, "capability": "unavailable",
                       "reason": "typed_histories_unavailable", "label": "application bytes"}),
    };
    Ok(json!({
        "available": true,
        "status": if ready { "ready" } else { "degraded" },
        "ready": ready,
        "revision": health.get("revision").cloned().unwrap_or(Value::Null),
        "credentials": {"active": active, "disabled": disabled, "total": active + disabled},
        "traffic": traffic,
    }))
}

/// The AmneziaWG or TrustTunnel card when its manager could not be read.
pub fn tunnel_degraded() -> Value {
    json!({"available": true, "status": "degraded", "ready": false,
           "credentials": {"available": false}, "traffic": {"available": false}})
}

/// `(active, rows, upload, download)` of the peers or clients a tunnel manager lists (`rx` is what
/// the client uploaded, `tx` what it downloaded).
fn tunnel_rows(items: &Value) -> PageResult<(usize, usize, i128, i128)> {
    let rows = dict_items(items)?;
    let active = rows.iter().filter(|item| py::is_true(item.get("enabled"))).count();
    let mut upload = 0;
    let mut download = 0;
    for item in &rows {
        upload += py::int_or_zero(item.get("rx"))?;
    }
    for item in &rows {
        download += py::int_or_zero(item.get("tx"))?;
    }
    Ok((active, rows.len(), upload, download))
}

/// The AmneziaWG card: peers per version, credentials, traffic.
pub fn amneziawg(health: &Value, peers: &Value) -> PageResult<Value> {
    let mut versions = Map::new();
    for item in dict_items(peers)? {
        let version = py::py_str(item.get("version").unwrap_or(&Value::Null));
        let count = versions.get(&version).and_then(Value::as_i64).unwrap_or(0);
        versions.insert(version, json!(count + 1));
    }
    let (active, total, upload, download) = tunnel_rows(peers)?;
    let ready = py::dict(health)?.get("status").is_some_and(|status| py::eq(status, &json!("ok")));
    Ok(json!({
        "available": true, "status": if ready { "ready" } else { "degraded" }, "ready": ready,
        "versions": versions,
        "credentials": {"active": active, "disabled": total - active, "total": total},
        "traffic": {"available": true, "upload_bytes": int_value(upload), "download_bytes": int_value(download)},
    }))
}

/// The TrustTunnel card: credentials and traffic.
pub fn trusttunnel(health: &Value, clients: &Value) -> PageResult<Value> {
    let (active, total, upload, download) = tunnel_rows(clients)?;
    let ready = py::dict(health)?.get("status").is_some_and(|status| py::eq(status, &json!("ok")));
    Ok(json!({
        "available": true, "status": if ready { "ready" } else { "degraded" }, "ready": ready,
        "credentials": {"active": active, "disabled": total - active, "total": total},
        // measured: rx is what the client uploaded, tx what it downloaded
        "traffic": {"available": true, "upload_bytes": int_value(upload), "download_bytes": int_value(download)},
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_summarizes_both_protocols_without_naive_traffic_invention() {
        let items = json!([
            {"username": "mt-on", "enabled": true, "total_octets": 1024},
            {"username": "mt-off", "enabled": false, "total_octets": 2048},
            {"username": "odd", "total_octets": -5},
            "not a row",
        ]);
        let (card, total) = mtproxy(&json!({"ready": true}), &json!({}), &json!([]), &items).unwrap();
        assert_eq!(total, json!(3072));
        assert_eq!(
            card,
            json!({"status": "ready", "ready": true, "credentials": {"active": 2, "disabled": 1, "total": 3},
                   "runtime": {"traffic_octets": 3072, "current_connections": 0, "active_ips": 0}})
        );
        assert!(mtproxy(&json!([]), &json!({}), &json!([]), &items).is_err());

        let naive = naive(
            "naive.example.com",
            &json!({"ready": true}),
            &json!([{"enabled": true}, {"enabled": false}]),
            &json!({"source": "caddy_connect_access_log"}),
        )
        .unwrap();
        assert_eq!(
            naive,
            json!({
                "available": true, "status": "ready", "ready": true, "host": "naive.example.com",
                "credentials": {"active": 1, "disabled": 1, "total": 2},
                "traffic": {"available": true, "source": "caddy_connect_access_log"},
            })
        );
    }

    #[test]
    fn dashboard_stays_available_when_enabled_naive_manager_is_degraded() {
        assert_eq!(
            naive_degraded("naive.example.com"),
            json!({
                "available": true, "status": "degraded", "ready": false, "host": "naive.example.com",
                "credentials": {"available": false},
                "traffic": {"available": false, "reason": "manager_unavailable"},
            })
        );
    }

    #[test]
    fn dashboard_reports_mieru_disabled_ready_and_degraded() {
        assert_eq!(disabled(), json!({"available": false, "status": "disabled"}));
        let empty = crate::mieru::traffic_map(&json!({"users": []})).unwrap();
        let ready = mieru(&json!({"ready": true, "revision": "rev-1"}), &json!([]), Some(&empty)).unwrap();
        assert_eq!(ready["status"], "ready");
        assert_eq!(
            ready["traffic"],
            json!({"available": true, "label": "application bytes", "since": "mita_start",
                   "upload_bytes": 0, "download_bytes": 0})
        );
        assert_eq!(mieru_degraded()["status"], "degraded");
        assert_eq!(
            mieru(&json!({"ready": true}), &json!([]), None).unwrap()["traffic"]["reason"],
            "typed_histories_unavailable"
        );
    }

    #[test]
    fn tunnel_cards_sum_rx_and_tx() {
        let peers = json!([
            {"version": "2.0", "enabled": true, "rx": 5, "tx": "7"},
            {"version": "2.0", "enabled": false, "rx": null},
            {"version": null, "enabled": true, "rx": 1.9, "tx": 1},
        ]);
        let card = amneziawg(&json!({"status": "ok"}), &peers).unwrap();
        assert_eq!(card["versions"], json!({"2.0": 2, "None": 1}));
        assert_eq!(card["credentials"], json!({"active": 2, "disabled": 1, "total": 3}));
        assert_eq!(card["traffic"], json!({"available": true, "upload_bytes": 6, "download_bytes": 8}));
        let tt = trusttunnel(&json!({"status": "down"}), &json!([{"enabled": true, "rx": 500, "tx": 2000}])).unwrap();
        assert_eq!(tt["status"], "degraded");
        assert_eq!(tt["traffic"], json!({"available": true, "upload_bytes": 500, "download_bytes": 2000}));
    }
}
