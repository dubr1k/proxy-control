//! The secret-free AmneziaWG and TrustTunnel screens (`amneziawg_routes.py` and
//! `trusttunnel_routes.py`). The web routes gather manager and database data; these helpers do the
//! same joins and Python-shaped projections without doing I/O.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::py;
use crate::{Fault, PageResult};

/// Access holders by runtime username. Each value has only the public fields of the corresponding
/// Python `_holders()` row; the routes construct it from typed grants, never from stored options.
pub type Holders = BTreeMap<String, Value>;

type LiveRows<'a> = BTreeMap<String, &'a Map<String, Value>>;

fn value_or_null(value: Option<&Value>) -> Value {
    value.cloned().unwrap_or(Value::Null)
}

fn truthy_or_null(value: Option<&Value>) -> Value {
    if py::truthy(value) {
        value_or_null(value)
    } else {
        Value::Null
    }
}

fn required<'a>(row: &'a Map<String, Value>, key: &str) -> PageResult<&'a Value> {
    row.get(key).ok_or_else(|| Fault::crash(format!("KeyError: '{key}'")))
}

fn holder_field(holder: Option<&Value>, key: &str) -> Value {
    holder.and_then(Value::as_object).and_then(|row| row.get(key)).cloned().unwrap_or(Value::Null)
}

fn pending(holders: &Holders, live: impl Fn(&str) -> bool) -> Vec<Value> {
    holders
        .iter()
        .filter(|(username, _)| !live(username))
        .map(|(username, holder)| {
            let mut row = Map::new();
            row.insert("username".into(), json!(username));
            if let Some(fields) = holder.as_object() {
                for (key, value) in fields {
                    row.insert(key.clone(), value.clone());
                }
            }
            Value::Object(row)
        })
        .collect()
}

fn live_rows(rows: &Value) -> PageResult<LiveRows<'_>> {
    let rows: &[Value] = match rows {
        Value::Array(rows) => rows,
        // Iterating a dict or string yields keys or characters, never dict rows.
        Value::Object(_) | Value::String(_) => &[],
        other => {
            return Err(Fault::crash(format!(
                "TypeError: '{}' object is not iterable",
                panel_model::pyrepr::type_name(other)
            )));
        }
    };
    let mut live = BTreeMap::new();
    for row in rows {
        let Some(row) = row.as_object() else { continue };
        if let Some(Value::String(username)) = row.get("username") {
            live.insert(username.clone(), row);
        }
    }
    Ok(live)
}

fn mapping_key(value: &Value) -> PageResult<Option<&str>> {
    match value {
        Value::String(text) => Ok(Some(text)),
        Value::Array(_) | Value::Object(_) => {
            Err(Fault::crash(format!("TypeError: unhashable type: '{}'", panel_model::pyrepr::type_name(value))))
        }
        _ => Ok(None),
    }
}

/// `bool((running.get(version) or {}).get("running"))`.
fn version_running(running: Option<&Value>, version: &Value) -> PageResult<bool> {
    let key = mapping_key(version)?;
    let empty = Map::new();
    let running = match running {
        Some(value) if py::truthy(Some(value)) => py::dict(value)?,
        _ => &empty,
    };
    let item = key.and_then(|key| running.get(key));
    if !py::truthy(item) {
        return Ok(false);
    }
    Ok(py::truthy(py::dict(item.expect("truthy"))?.get("running")))
}

/// `bool((health.get("endpoint") or {}).get("running"))`.
fn endpoint_running(health: &Map<String, Value>) -> PageResult<bool> {
    let endpoint = health.get("endpoint");
    if !py::truthy(endpoint) {
        return Ok(false);
    }
    Ok(py::truthy(py::dict(endpoint.expect("truthy"))?.get("running")))
}

/// The `AmneziawgError` answer: manager data is empty, while every panel-held access is pending.
pub fn amneziawg_down(public_host: &str, holders: &Holders) -> Value {
    json!({
        "status": "down",
        "ip_forward": null,
        "public_host": public_host,
        "versions": [],
        "peers": [],
        "pending": pending(holders, |_| false),
    })
}

/// Join AmneziaWG health, instances and peers with the panel's grant holders.
///
/// The returned object has an `egress: null` placeholder in its final position. The route replaces
/// it after calling the manager's optional egress endpoint, preserving the Python evaluation and
/// key order.
pub fn amneziawg(
    public_host: &str,
    health: &Value,
    instances: &Value,
    peers: &Value,
    holders: &Holders,
) -> PageResult<Value> {
    let health = py::dict(health)?;
    let running = health.get("instances").filter(|value| py::truthy(Some(*value)));
    let live = live_rows(peers)?;
    let mut versions = Vec::new();

    // Unlike the live-peer comprehension, Python does not filter instance rows: malformed rows
    // are an unhandled route error rather than silently disappearing.
    let items: &[Value] = match instances {
        Value::Array(items) => items,
        Value::Object(map) if map.is_empty() => &[],
        Value::String(text) if text.is_empty() => &[],
        Value::Object(_) | Value::String(_) => {
            return Err(Fault::crash("TypeError: string indices must be integers"));
        }
        other => {
            return Err(Fault::crash(format!(
                "TypeError: '{}' object is not iterable",
                panel_model::pyrepr::type_name(other)
            )));
        }
    };
    for item in items {
        let item = py::dict(item)?;
        let version = required(item, "version")?;
        let mut peer_count = 0_usize;
        let mut active = 0_usize;
        for row in live.values().filter(|row| py::eq(row.get("version").unwrap_or(&Value::Null), version)) {
            peer_count += 1;
            active += usize::from(py::is_true(row.get("enabled")));
        }
        versions.push(json!({
            "version": version,
            "interface": required(item, "interface")?,
            "port": required(item, "port")?,
            "subnet": required(item, "subnet")?,
            "mtu": value_or_null(item.get("mtu")),
            "dns": py::list_or_empty(item.get("dns"))?,
            "running": version_running(running, version)?,
            "peers": peer_count,
            "active": active,
        }));
    }

    let mut rows = Vec::new();
    for (username, row) in &live {
        let holder = holders.get(username);
        rows.push(json!({
            "username": username,
            "version": value_or_null(row.get("version")),
            "address": value_or_null(row.get("address")),
            "enabled": py::is_true(row.get("enabled")),
            "latest_handshake": truthy_or_null(row.get("latest_handshake")),
            "rx": py::int_value(py::int_or_zero(row.get("rx"))?),
            "tx": py::int_value(py::int_or_zero(row.get("tx"))?),
            "grant_id": holder_field(holder, "grant_id"),
            "client_id": holder_field(holder, "client_id"),
            "client_name": holder_field(holder, "client_name"),
        }));
    }
    let pending = pending(holders, |username| live.contains_key(username));
    Ok(json!({
        "status": if py::truthy(health.get("status")) { value_or_null(health.get("status")) } else { json!("degraded") },
        "ip_forward": value_or_null(health.get("ip_forward")),
        "public_host": public_host,
        "versions": versions,
        "peers": rows,
        "pending": pending,
        "egress": null,
    }))
}

/// The public egress projection. WARP credentials and tokens in the manager response are never
/// copied. An old manager's endpoint error is turned into `null` by the web route.
pub fn amneziawg_egress(view: &Value) -> PageResult<Value> {
    let view = py::dict(view)?;
    let empty = Map::new();
    let warp = py::as_dict(view.get("warp")).unwrap_or(&empty);
    let document = py::as_dict(view.get("document")).unwrap_or(&empty);
    let provider = py::as_dict(document.get("upstream")).and_then(|upstream| upstream.get("provider"));
    if provider.and_then(Value::as_str) == Some("router") {
        let router = py::as_dict(view.get("router"));
        return Ok(json!({
            "mode": "proxy",
            "provider": "router",
            "tunnel": if router.is_some_and(|router| py::truthy(router.get("attached"))) { "up" } else { "down" },
            "registered": py::is_true(warp.get("registered")),
            "address": null,
            "endpoint": null,
            "latest_handshake": null,
            "rx": 0,
            "tx": 0,
        }));
    }
    Ok(json!({
        "mode": value_or_null(view.get("mode")),
        "provider": value_or_null(provider),
        "tunnel": value_or_null(warp.get("tunnel")),
        "registered": py::is_true(warp.get("registered")),
        "address": value_or_null(warp.get("address")),
        "endpoint": value_or_null(warp.get("endpoint")),
        "latest_handshake": value_or_null(warp.get("latest_handshake")),
        "rx": py::int_value(py::int_or_zero(warp.get("rx"))?),
        "tx": py::int_value(py::int_or_zero(warp.get("tx"))?),
    }))
}

/// The `TrusttunnelError` answer, with zero totals and all panel-held accesses pending.
pub fn trusttunnel_down(public_host: &str, holders: &Holders) -> Value {
    json!({
        "status": "down",
        "public_host": public_host,
        "endpoint": null,
        "clients": [],
        "totals": {
            "clients": 0,
            "active": 0,
            "sessions": 0,
            "upload_bytes": 0,
            "download_bytes": 0,
        },
        "pending": pending(holders, |_| false),
    })
}

/// Join TrustTunnel health, endpoint and clients with the panel's grant holders. Manager `rx` is
/// client upload and manager `tx` is client download, as on the real endpoint.
pub fn trusttunnel(
    public_host: &str,
    health: &Value,
    endpoint: &Value,
    clients: &Value,
    holders: &Holders,
) -> PageResult<Value> {
    let live = live_rows(clients)?;
    let mut rows = Vec::new();
    let mut active = 0_usize;
    let mut sessions = 0_i128;
    let mut upload = 0_i128;
    let mut download = 0_i128;
    for (username, row) in &live {
        let holder = holders.get(username);
        let enabled = py::is_true(row.get("enabled"));
        let row_sessions = py::int_or_zero(row.get("sessions"))?;
        let row_download = py::int_or_zero(row.get("tx"))?;
        let row_upload = py::int_or_zero(row.get("rx"))?;
        active += usize::from(enabled);
        sessions += row_sessions;
        upload += row_upload;
        download += row_download;
        rows.push(json!({
            "username": username,
            "enabled": enabled,
            "sessions": py::int_value(row_sessions),
            "download_bytes": py::int_value(row_download),
            "upload_bytes": py::int_value(row_upload),
            "grant_id": holder_field(holder, "grant_id"),
            "client_id": holder_field(holder, "client_id"),
            "client_name": holder_field(holder, "client_name"),
            "name": holder_field(holder, "name"),
        }));
    }
    let health = py::dict(health)?;
    let running = endpoint_running(health)?;
    let pending = pending(holders, |username| live.contains_key(username));
    let endpoint = py::dict(endpoint)?;
    let totals = json!({
        "clients": rows.len(),
        "active": active,
        "sessions": py::int_value(sessions),
        "upload_bytes": py::int_value(upload),
        "download_bytes": py::int_value(download),
    });
    Ok(json!({
        "status": if py::truthy(health.get("status")) { value_or_null(health.get("status")) } else { json!("degraded") },
        "public_host": public_host,
        "endpoint": {
            "hostname": value_or_null(endpoint.get("hostname")),
            "port": if py::truthy(endpoint.get("public_port")) { value_or_null(endpoint.get("public_port")) } else { json!(443) },
            "version": value_or_null(endpoint.get("version")),
            "running": running,
            "certificate_trusted": py::is_true(endpoint.get("certificate_trusted")),
            "fingerprint": value_or_null(endpoint.get("fingerprint")),
        },
        "clients": rows,
        "totals": totals,
        "pending": pending,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod amneziawg {
        use super::*;

        fn holders() -> Holders {
            BTreeMap::from([
                (
                    "alice-awg20".into(),
                    json!({
                        "grant_id": "g20", "client_id": "c1", "client_name": "Alice",
                        "desired_state": "enabled", "version": "2.0",
                    }),
                ),
                (
                    "alice-awg31".into(),
                    json!({
                        "grant_id": "g31", "client_id": "c1", "client_name": "Alice",
                        "desired_state": "enabled", "version": "3.1",
                    }),
                ),
            ])
        }

        #[test]
        fn the_overview_joins_the_manager_with_the_clients_that_hold_the_accesses() {
            let health = json!({"status": "ok", "ip_forward": true, "instances": {
                "1.5": {"running": true}, "2.0": {"running": true}, "3.1": {"running": true},
            }});
            let instances = json!([
                {"version": "1.5", "interface": "awg15", "port": 51820, "subnet": "10.15.0.0/24"},
                {"version": "2.0", "interface": "awg20", "port": 51821, "subnet": "10.20.0.0/24"},
                {"version": "3.1", "interface": "awg31", "port": 51822, "subnet": "10.31.0.0/24"},
            ]);
            let peers = json!([
                {"username": "stranger", "version": "1.5", "enabled": true, "public_key": "public", "preshared_key": "secret"},
                {"username": "alice-awg20", "version": "2.0", "enabled": true, "latest_handshake": 1_700_000_000,
                 "private_key": "private", "rx": "500", "tx": 2000},
                {"username": "alice-awg31", "version": "3.1", "enabled": false},
            ]);
            let data = amneziawg("vpn.example.com", &health, &instances, &peers, &holders()).unwrap();
            assert_eq!(data["status"], "ok");
            assert_eq!(data["ip_forward"], true);
            assert_eq!(data["public_host"], "vpn.example.com");
            assert_eq!(
                data["versions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| {
                        (row["version"].clone(), row["port"].clone(), row["peers"].clone(), row["running"].clone())
                    })
                    .collect::<Vec<_>>(),
                vec![
                    (json!("1.5"), json!(51820), json!(1), json!(true)),
                    (json!("2.0"), json!(51821), json!(1), json!(true)),
                    (json!("3.1"), json!(51822), json!(1), json!(true)),
                ]
            );
            let alice = data["peers"].as_array().unwrap().iter().find(|row| row["username"] == "alice-awg20").unwrap();
            assert_eq!(alice["client_name"], "Alice");
            assert_eq!(alice["client_id"], "c1");
            assert_eq!(alice["grant_id"], "g20");
            assert_eq!(alice["latest_handshake"], 1_700_000_000);
            assert_eq!(alice["rx"], 500);
            assert_eq!(alice["tx"], 2000);
            let stranger = data["peers"].as_array().unwrap().iter().find(|row| row["username"] == "stranger").unwrap();
            assert_eq!(stranger["client_id"], Value::Null);
            assert_eq!(stranger["grant_id"], Value::Null);
            assert_eq!(data["pending"], json!([]));
            let rendered = data.to_string();
            assert!(!rendered.contains("HeaderProtectionKey"));
            assert!(!rendered.to_lowercase().contains("private"));
            assert!(!rendered.contains("preshared"));
        }

        #[test]
        fn the_overview_says_so_when_the_manager_is_down_or_the_feature_is_off() {
            assert_eq!(
                amneziawg_down("naive.example.com", &holders()),
                json!({
                    "status": "down", "ip_forward": null, "public_host": "naive.example.com",
                    "versions": [], "peers": [], "pending": [
                        {"username": "alice-awg20", "grant_id": "g20", "client_id": "c1", "client_name": "Alice",
                         "desired_state": "enabled", "version": "2.0"},
                        {"username": "alice-awg31", "grant_id": "g31", "client_id": "c1", "client_name": "Alice",
                         "desired_state": "enabled", "version": "3.1"},
                    ],
                })
            );
        }

        #[test]
        fn egress_is_secret_free_and_projects_router_attachment() {
            let warp = amneziawg_egress(&json!({
                "mode": "proxy", "document": {"upstream": {"provider": "warp"}},
                "warp": {"tunnel": "up", "registered": true, "address": "172.16.0.2/32",
                         "endpoint": "engage.cloudflareclient.com:2408", "latest_handshake": 12,
                         "rx": "500", "tx": 2000, "private_key": "private", "token": "token"},
            }))
            .unwrap();
            assert_eq!(warp["mode"], "proxy");
            assert_eq!(warp["provider"], "warp");
            assert_eq!(warp["rx"], 500);
            assert_eq!(warp["tx"], 2000);
            assert!(!warp.to_string().contains("private"));
            assert!(!warp.to_string().contains("token"));
            assert_eq!(
                amneziawg_egress(&json!({
                    "mode": "proxy", "document": {"upstream": {"provider": "router"}},
                    "router": {"attached": true}, "warp": {"registered": true, "token": "secret"},
                }))
                .unwrap(),
                json!({"mode": "proxy", "provider": "router", "tunnel": "up", "registered": true,
                       "address": null, "endpoint": null, "latest_handshake": null, "rx": 0, "tx": 0})
            );
        }
    }

    mod trusttunnel {
        use super::*;

        fn holders() -> Holders {
            BTreeMap::from([(
                "alice-tt".into(),
                json!({"grant_id": "g1", "client_id": "c1", "client_name": "Alice",
                       "desired_state": "enabled", "name": "Alice phone"}),
            )])
        }

        #[test]
        fn the_overview_joins_the_manager_with_the_clients_that_hold_the_accesses() {
            let health = json!({"status": "ok", "endpoint": {"running": true}});
            let endpoint = json!({"hostname": "gate.example.com", "version": "1.1.0",
                                  "certificate_trusted": true, "fingerprint": "abc", "certificate": "secret"});
            let clients = json!([
                {"username": "stranger", "enabled": true, "password": "stranger-password"},
                {"username": "alice-tt", "enabled": true, "sessions": 2, "rx": 500, "tx": 2000,
                 "password": "alice-password", "link": "tt://secret"},
            ]);
            let data = trusttunnel("gate.example.com", &health, &endpoint, &clients, &holders()).unwrap();
            assert_eq!(data["status"], "ok");
            assert_eq!(data["public_host"], "gate.example.com");
            assert_eq!(
                data["endpoint"],
                json!({
                    "hostname": "gate.example.com", "port": 443, "version": "1.1.0", "running": true,
                    "certificate_trusted": true, "fingerprint": "abc",
                })
            );
            let alice = data["clients"].as_array().unwrap().iter().find(|row| row["username"] == "alice-tt").unwrap();
            assert_eq!(alice["client_name"], "Alice");
            assert_eq!(alice["client_id"], "c1");
            assert_eq!(alice["grant_id"], "g1");
            assert_eq!(alice["download_bytes"], 2000);
            assert_eq!(alice["upload_bytes"], 500);
            assert_eq!(alice["sessions"], 2);
            assert_eq!(alice["name"], "Alice phone");
            assert_eq!(
                data["totals"],
                json!({"clients": 2, "active": 2, "sessions": 2,
                                               "upload_bytes": 500, "download_bytes": 2000})
            );
            assert_eq!(data["pending"], json!([]));
            let rendered = data.to_string().to_lowercase();
            assert!(!rendered.contains("password"));
            assert!(!rendered.contains("tt://"));
            assert!(!rendered.contains("certificate\""));
        }

        #[test]
        fn the_overview_lists_accesses_the_manager_lost_as_pending() {
            let data = trusttunnel(
                "gate.example.com",
                &json!({"status": "ok", "endpoint": {"running": true}}),
                &json!({"hostname": "gate.example.com"}),
                &json!([]),
                &holders(),
            )
            .unwrap();
            assert_eq!(data["clients"], json!([]));
            assert_eq!(data["pending"].as_array().unwrap().len(), 1);
            assert_eq!(data["pending"][0]["username"], "alice-tt");
        }

        #[test]
        fn the_overview_says_so_when_the_manager_is_down_or_the_feature_is_off() {
            assert_eq!(
                trusttunnel_down("gate.example.com", &holders()),
                json!({
                    "status": "down", "public_host": "gate.example.com", "endpoint": null, "clients": [],
                    "totals": {"clients": 0, "active": 0, "sessions": 0, "upload_bytes": 0, "download_bytes": 0},
                    "pending": [{"username": "alice-tt", "grant_id": "g1", "client_id": "c1",
                                 "client_name": "Alice", "desired_state": "enabled", "name": "Alice phone"}],
                })
            );
        }
    }
}
