//! Derive what an operator sees from stored rows — one place, no scattered guesses
//! (`nodes/read_model.py`).

use serde_json::{Map, Value};

use crate::registry::NodeRow;
use crate::{certificates, CertificateInfo, NodeView};

/// A v1 node unheard of for longer than this many seconds is `stale`.
pub const STALE_AFTER: i64 = 90;

/// What the operator may see of a link: the connection, its health and the generation counters.
/// The secret id stays behind; only `has_api_key` says a key is stored.
pub const LINK_VIEW_KEYS: [&str; 12] = [
    "panel_url",
    "tls_verify",
    "status",
    "latency_ms",
    "panel_version",
    "last_heartbeat_at",
    "last_error",
    "desired_generation",
    "acknowledged_generation",
    "identity",
    "status_json",
    "has_api_key",
];

/// Python's `bool(value)` of a JSON value.
pub fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

fn field<'a>(map: &'a Map<String, Value>, key: &str) -> &'a Value {
    map.get(key).unwrap_or(&Value::Null)
}

/// `_link_view(link)`: [`LINK_VIEW_KEYS`], then `config_dirty`, `enabled`, `auto_import` as bools
/// (`auto_import` defaults to on) and what the node last reported (`observed_generation`,
/// `observed_state`, null without a report).
pub fn link_view(link: &Map<String, Value>) -> Map<String, Value> {
    let mut view: Map<String, Value> =
        LINK_VIEW_KEYS.iter().map(|key| ((*key).to_string(), field(link, key).clone())).collect();
    view.insert("config_dirty".into(), py_truthy(field(link, "config_dirty")).into());
    view.insert("enabled".into(), py_truthy(field(link, "enabled")).into());
    view.insert("auto_import".into(), link.get("auto_import").is_none_or(py_truthy).into());
    view.insert("observed_generation".into(), field(link, "observed_generation").clone());
    view.insert("observed_state".into(), field(link, "observed_state").clone());
    view
}

/// `derive(row, certificates, pending_commands, now, stale_after)`.
pub fn derive(
    row: &NodeRow,
    certificates: Vec<CertificateInfo>,
    pending_commands: i64,
    now: i64,
    stale_after: i64,
) -> NodeView {
    let link = if row.transport == "panel" { row.link.as_ref() } else { None };
    let seen = row.last_seen_at.filter(|seen| *seen != 0);
    let (enrollment, connectivity) = if row.kind == "local" {
        // The central host has no transport, so "online" and "stale" mean nothing here.
        ("local".to_string(), "not_applicable".to_string())
    } else if let Some(link) = link {
        // A linked panel has no certificate: its heartbeat decides whether it is reachable.
        let status = match field(link, "status") {
            Value::String(status) => status.clone(),
            other => other.to_string(),
        };
        ("linked".to_string(), status)
    } else if certificates.iter().any(|certificate| certificate.state == "active") {
        let connectivity = match seen {
            None => "never",
            Some(seen) if now - seen <= stale_after => "online",
            Some(_) => "stale",
        };
        ("enrolled".to_string(), connectivity.to_string())
    } else {
        let enrollment = if certificates.is_empty() { "unenrolled" } else { "revoked" };
        (enrollment.to_string(), if seen.is_none() { "never" } else { "stale" }.to_string())
    };
    let reported = match link {
        // A non-object identity has no protocols to report.
        Some(link) => match field(link, "identity") {
            Value::Object(identity) => py_truthy(field(identity, "protocols")),
            _ => false,
        },
        None => py_truthy(field(&row.inventory, "telemt_version")),
    };
    let capabilities = match row.inventory.get("capabilities") {
        Some(Value::Array(items)) => items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    };
    NodeView {
        node_id: row.node_id.clone(),
        display_name: row.display_name.clone(),
        kind: row.kind.clone(),
        // One flag per node: a linked panel is "disabled" exactly when its link is paused.
        disabled: match link {
            Some(link) => !py_truthy(field(link, "enabled")),
            None => row.disabled,
        },
        enrollment_state: enrollment,
        connectivity_state: connectivity,
        daemon_health: if reported { "reported" } else { "unknown" }.to_string(),
        inventory: row
            .inventory
            .iter()
            .filter(|(key, _)| *key != "capabilities")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        capabilities,
        last_seen_at: row.last_seen_at,
        last_checked_at: Some(row.updated_at),
        certificates,
        pending_commands,
        transport: row.transport.clone(),
        link: link.map(link_view),
    }
}

/// `dataclasses.asdict(view)`: every field in declaration order — what the API and the CLI print.
pub fn view_to_value(view: &NodeView) -> Value {
    let mut out = Map::new();
    out.insert("node_id".into(), view.node_id.clone().into());
    out.insert("display_name".into(), view.display_name.clone().into());
    out.insert("kind".into(), view.kind.clone().into());
    out.insert("disabled".into(), view.disabled.into());
    out.insert("enrollment_state".into(), view.enrollment_state.clone().into());
    out.insert("connectivity_state".into(), view.connectivity_state.clone().into());
    out.insert("daemon_health".into(), view.daemon_health.clone().into());
    out.insert("inventory".into(), Value::Object(view.inventory.clone()));
    out.insert("capabilities".into(), view.capabilities.clone().into());
    out.insert("last_seen_at".into(), view.last_seen_at.into());
    out.insert("last_checked_at".into(), view.last_checked_at.into());
    out.insert("certificates".into(), view.certificates.iter().map(certificates::to_value).collect());
    out.insert("pending_commands".into(), view.pending_commands.into());
    out.insert("transport".into(), view.transport.clone().into());
    out.insert("link".into(), view.link.clone().map_or(Value::Null, Value::Object));
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn cert(state: &str, now: i64) -> CertificateInfo {
        CertificateInfo {
            serial: "AA01".into(),
            fingerprint_sha256: "f".repeat(64),
            not_before: now - 10,
            not_after: now + 86400 * 30,
            state: state.into(),
            issued_at: now - 10,
            revoked_at: None,
        }
    }

    fn row(now: i64) -> NodeRow {
        let inventory = json!({"telemt_version": "3.4.25", "capabilities": ["telemt.inventory.refresh"]});
        NodeRow {
            node_id: "edge-01".into(),
            display_name: "edge".into(),
            auth_state: "unenrolled".into(),
            created_at: now,
            updated_at: now,
            next_sequence: 1,
            last_result_sequence: 0,
            last_seen_at: None,
            kind: "remote".into(),
            disabled: false,
            transport: "v1".into(),
            inventory: inventory.as_object().unwrap().clone(),
            link: None,
        }
    }

    #[test]
    fn read_model_derives_enrollment_and_connectivity() {
        let now = 1_793_000_000;
        let view = derive(&row(now), vec![], 0, now, STALE_AFTER);
        assert_eq!(
            (view.enrollment_state.as_str(), view.connectivity_state.as_str(), view.daemon_health.as_str()),
            ("unenrolled", "never", "reported")
        );
        let seen = |at: i64| NodeRow { last_seen_at: Some(at), ..row(now) };
        let view = derive(&seen(now - 10), vec![cert("active", now)], 2, now, STALE_AFTER);
        assert_eq!(
            (view.enrollment_state.as_str(), view.connectivity_state.as_str(), view.pending_commands),
            ("enrolled", "online", 2)
        );
        assert_eq!(
            derive(&seen(now - 600), vec![cert("active", now)], 0, now, STALE_AFTER).connectivity_state,
            "stale"
        );
        assert_eq!(
            derive(&seen(now - 10), vec![cert("revoked", now)], 0, now, STALE_AFTER).enrollment_state,
            "revoked"
        );
        let local = NodeRow { kind: "local".into(), ..row(now) };
        assert_eq!(derive(&local, vec![], 0, now, STALE_AFTER).connectivity_state, "not_applicable");
    }

    #[test]
    fn truthiness_is_pythons() {
        for falsy in [json!(null), json!(false), json!(0), json!(0.0), json!(""), json!([]), json!({})] {
            assert!(!py_truthy(&falsy), "{falsy}");
        }
        for truthy in [json!(true), json!(-1), json!(0.5), json!("0"), json!([0]), json!({"a": null})] {
            assert!(py_truthy(&truthy), "{truthy}");
        }
    }

    #[test]
    fn a_link_without_auto_import_column_defaults_to_on() {
        let link = json!({"enabled": 1, "config_dirty": 0, "status": "online"});
        let view = link_view(link.as_object().unwrap());
        assert_eq!(view["auto_import"], json!(true));
        assert_eq!(view["identity"], json!(null));
        assert_eq!(view["observed_state"], json!(null));
    }
}
