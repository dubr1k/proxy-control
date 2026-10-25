//! Reads the endpoint's per-client metrics and folds counter resets into running totals.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reading {
    pub inbound: u64,
    pub outbound: u64,
    pub sessions: u64,
}

/// GET /clients from the loopback metrics listener; `None` when it is unreachable.
pub fn fetch_clients(address: &str) -> Option<Vec<Value>> {
    let response = pc_common::client::tcp_get(address, "/clients", Duration::from_secs(3), 4 * 1024 * 1024).ok()?;
    if !(200..300).contains(&response.status) {
        return None;
    }
    match response.json().ok()? {
        Value::Array(rows) => Some(rows),
        _ => None,
    }
}

/// Sums rows per username (the endpoint lists one row per client address).
pub fn aggregate(rows: &[Value]) -> BTreeMap<String, Reading> {
    let mut out: BTreeMap<String, Reading> = BTreeMap::new();
    for row in rows {
        let Some(name) = row.get("username").and_then(Value::as_str) else { continue };
        let slot = out.entry(name.to_string()).or_default();
        let count = |key: &str| row.get(key).and_then(Value::as_u64).unwrap_or(0);
        slot.inbound = slot.inbound.saturating_add(count("inbound"));
        slot.outbound = slot.outbound.saturating_add(count("outbound"));
        slot.sessions = slot.sessions.saturating_add(count("sessions"));
    }
    out
}

/// Returns `(new_total, new_last_raw)`. A lower reading means the counter was reset.
pub fn fold(total: u64, last_raw: u64, reading: u64) -> (u64, u64) {
    let delta = if reading >= last_raw { reading - last_raw } else { reading };
    (total.saturating_add(delta), reading)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_lower_reading_without_restart_is_a_counter_reset() {
        assert_eq!(fold(500, 300, 350), (550, 350));
        assert_eq!(fold(500, 300, 40), (540, 40));
        let rows = vec![
            json!({"username": "a", "inbound": 1, "outbound": 2, "sessions": 1}),
            json!({"username": "a", "inbound": 3, "outbound": 4, "sessions": 1}),
            json!({"username": 7, "inbound": 1}),
            json!("junk"),
            json!({"username": "b", "inbound": -1, "outbound": true, "sessions": 1.5}),
        ];
        let got = aggregate(&rows);
        assert_eq!(got["a"], Reading { inbound: 4, outbound: 6, sessions: 2 });
        assert_eq!(got["b"], Reading::default());
        assert_eq!(got.len(), 2);
    }
}
