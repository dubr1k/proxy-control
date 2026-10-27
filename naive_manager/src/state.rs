//! The manager state (`users.json`): its validation on every read and its encoding, exactly
//! as the Python manager wrote it (`json.dumps(state, ensure_ascii=False, indent=2) + "\n"`,
//! insertion order kept), so a file written by either version is read by the other.

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::lanes::is_lane_id;
use crate::traffic::{MAX_COUNTER, REDACTION_SENTINEL};

/// How long a completed operation stays replayable: long enough for a retry after an
/// outage, short enough that the state file does not grow without bound.
pub const OPERATION_RETENTION_SECONDS: f64 = 7.0 * 86400.0;
const STATE_KEYS: [&str; 7] = ["version", "host", "users", "tombstones", "operations", "egress", "lanes"];
const USER_KEYS: [&str; 8] =
    ["username", "password", "enabled", "quota_bytes", "disabled_reason", "created_at", "updated_at", "lane"];

/// `[A-Za-z0-9_.-]{1,64}\Z`, never the accounting redaction sentinel.
pub fn valid_username(value: &Value) -> Result<()> {
    let name = value.as_str().ok_or_else(|| Error::value("invalid username"))?;
    let ok = (1..=64).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if !ok {
        return Err(Error::value("invalid username"));
    }
    if name == REDACTION_SENTINEL {
        return Err(Error::value("reserved username"));
    }
    Ok(())
}

/// `^[A-Za-z0-9_.~-]{16,128}$`; `None` lets the manager choose.
pub fn validate_password(password: Option<&str>) -> Result<()> {
    match password {
        None => Ok(()),
        Some(p)
            if (16..=128).contains(&p.len())
                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.~-".contains(&b)) =>
        {
            Ok(())
        }
        Some(_) => Err(Error::value("invalid password")),
    }
}

/// `^[A-Za-z0-9_:.-]{1,128}$`.
pub fn is_operation_id(text: &str) -> bool {
    (1..=128).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_alphanumeric() || b"_:.-".contains(&b))
}

/// `type(value) is int and 1 <= value <= MAX_COUNTER`.
pub fn exact_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

pub fn is_quota(value: &Value) -> bool {
    value.is_null() || exact_int(value).is_some_and(|q| (1..=MAX_COUNTER).contains(&q))
}

pub fn validate_quota(value: &Value) -> Result<()> {
    if is_quota(value) {
        Ok(())
    } else {
        Err(Error::value("invalid quota bytes"))
    }
}

/// `json.dumps(state, ensure_ascii=False, indent=2) + "\n"`.
pub fn encode_state(state: &Value) -> Vec<u8> {
    let mut text = pc_common::json::dumps(state, &crate::pyjson::STATE);
    text.push('\n');
    text.into_bytes()
}

/// `value == 1` as Python compares it (`1.0` and `True` are equal to 1).
fn equals_one(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Number(n)) => n.as_i64() == Some(1) || n.as_f64() == Some(1.0),
        Some(Value::Bool(b)) => *b,
        _ => false,
    }
}

fn conflict(message: &str) -> Error {
    Error::conflict(message)
}

/// Records are kept only long enough for a retry; a state file must not grow forever.
pub fn pruned_operations(operations: Option<&Value>, now: f64) -> Result<Map<String, Value>> {
    let operations = match operations {
        None | Some(Value::Null) => return Ok(Map::new()),
        Some(Value::Object(map)) => map,
        Some(_) => return Err(conflict("invalid operation state")),
    };
    let cutoff = now - OPERATION_RETENTION_SECONDS;
    let mut kept = Map::new();
    for (key, record) in operations {
        let valid = super::state::is_operation_id(key)
            && record.as_object().is_some_and(|r| {
                r.len() == 4
                    && ["operation", "username", "completed_at", "result"].iter().all(|k| r.contains_key(*k))
                    && matches!(r["operation"].as_str(), Some("create" | "rotate"))
                    && r["result"].is_object()
                    && r["completed_at"].is_string()
            });
        if !valid {
            return Err(conflict("invalid operation state"));
        }
        let completed = crate::pyutil::fromisoformat_timestamp(record["completed_at"].as_str().unwrap_or(""))
            .ok_or_else(|| conflict("invalid operation state"))?;
        if completed >= cutoff {
            kept.insert(key.clone(), record.clone());
        }
    }
    Ok(kept)
}

/// Validates a parsed state document the way `_read_state` did, filling the defaults an
/// older manager's file lacks (in Python's insertion order).
pub fn normalise(mut state: Value, public_host: &str, now: f64) -> Result<Value> {
    let root = match state.as_object_mut() {
        Some(root) => root,
        None => return Err(Error::Other("'list' object has no attribute 'get'".into())),
    };
    let users_ok = matches!(root.get("users"), Some(Value::Array(_)));
    if !equals_one(root.get("version")) || root.get("host").and_then(Value::as_str) != Some(public_host) || !users_ok {
        return Err(conflict("unsupported manager state"));
    }
    if root.keys().any(|key| !STATE_KEYS.contains(&key.as_str())) {
        return Err(conflict("unsupported manager state"));
    }
    // Lanes (v0.7) are optional: a state file from an older manager has none.
    let lanes = root.entry("lanes").or_insert_with(|| Value::Object(Map::new()));
    let lane_ids: HashSet<String> = match lanes.as_object() {
        Some(map)
            if map.iter().all(|(lane, entry)| {
                is_lane_id(lane)
                    && entry
                        .as_object()
                        .is_some_and(|e| e.len() == 1 && e.get("upstream").is_some_and(Value::is_string))
            }) =>
        {
            map.keys().cloned().collect()
        }
        _ => return Err(conflict("invalid lanes state")),
    };
    let operations = pruned_operations(root.get("operations"), now)?;
    root.insert("operations".into(), Value::Object(operations));
    root.entry("tombstones").or_insert_with(|| Value::Array(Vec::new()));
    // The egress journal (v0.4) is optional too.
    let journal =
        root.entry("egress").or_insert_with(|| serde_json::json!({"current": null, "previous": null, "history": []}));
    let journal_ok = journal.as_object().is_some_and(|j| {
        j.len() == 3 && ["current", "previous", "history"].iter().all(|k| j.contains_key(*k)) && j["history"].is_array()
    });
    if !journal_ok {
        return Err(conflict("invalid egress journal"));
    }
    if !root["tombstones"].is_array() {
        return Err(conflict("invalid tombstone state"));
    }
    let mut seen: HashSet<String> = HashSet::new();
    for row in root.get_mut("users").and_then(Value::as_array_mut).expect("checked above") {
        let row = row.as_object_mut().ok_or_else(|| conflict("invalid user state"))?;
        row.entry("quota_bytes").or_insert(Value::Null);
        row.entry("disabled_reason").or_insert(Value::Null);
        row.entry("lane").or_insert(Value::Null);
        if row.keys().any(|key| !USER_KEYS.contains(&key.as_str())) {
            return Err(conflict("invalid user state"));
        }
        let lane = &row["lane"];
        if !lane.is_null() && !lane.as_str().is_some_and(|l| lane_ids.contains(l)) {
            return Err(conflict("invalid user state"));
        }
        let username = row.get("username").cloned().unwrap_or(Value::String(String::new()));
        if valid_username(&username).is_err() {
            if username.as_str() == Some(REDACTION_SENTINEL) {
                return Err(conflict("reserved accounting username in manager state"));
            }
            return Err(conflict("invalid user state"));
        }
        let name = username.as_str().expect("validated").to_string();
        let enabled = row.get("enabled").and_then(Value::as_bool);
        let reason = &row["disabled_reason"];
        let reason_ok = reason.is_null() || matches!(reason.as_str(), Some("manual" | "quota"));
        let invalid = seen.contains(&name)
            || !row.get("password").and_then(Value::as_str).is_some_and(|p| !p.is_empty())
            || enabled.is_none()
            || !is_quota(&row["quota_bytes"])
            || !reason_ok
            || (enabled == Some(true) && !reason.is_null())
            || (reason.as_str() == Some("quota") && row["quota_bytes"].is_null());
        if invalid {
            return Err(conflict("invalid user state"));
        }
        seen.insert(name);
    }
    let mut retired: HashSet<String> = HashSet::new();
    for row in root["tombstones"].as_array().expect("checked above") {
        let valid_shape = row.as_object().is_some_and(|r| {
            r.len() == 2 && r.contains_key("username") && r.get("deleted_at").is_some_and(Value::is_string)
        });
        if !valid_shape {
            return Err(conflict("invalid tombstone state"));
        }
        let username = &row["username"];
        if valid_username(username).is_err() {
            if username.as_str() == Some(REDACTION_SENTINEL) {
                return Err(conflict("reserved accounting username in manager state"));
            }
            return Err(conflict("invalid tombstone state"));
        }
        let name = username.as_str().expect("validated").to_string();
        if seen.contains(&name) || retired.contains(&name) {
            return Err(conflict("invalid tombstone state"));
        }
        retired.insert(name);
    }
    Ok(state)
}

/// Parses the state file's text; unreadable JSON is a conflict, not a crash.
pub fn parse_state(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes).map_err(|_| conflict("invalid manager state"))?;
    serde_json::from_str(text).map_err(|_| conflict("invalid manager state"))
}

/// The usernames of a validated state.
pub fn usernames(state: &Value) -> HashSet<String> {
    state["users"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["username"].as_str().map(String::from))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validators_follow_the_python_patterns() {
        assert!(valid_username(&Value::from("invaliduser")).is_ok());
        assert_eq!(valid_username(&Value::from("invalid")).unwrap_err().message(), "reserved username");
        assert!(valid_username(&Value::from("a b")).is_err() && valid_username(&Value::from(1)).is_err());
        assert!(validate_password(Some("caller-supplied-password-01")).is_ok());
        assert!(
            validate_password(Some("short")).is_err()
                && validate_password(Some("has spaces in it and is long")).is_err()
        );
        assert!(is_operation_id("routing:p1:1") && !is_operation_id("") && !is_operation_id("a b"));
        for bad in [
            Value::from(0),
            Value::from(-1),
            Value::from(true),
            serde_json::json!(9223372036854775808u64),
            Value::from(1.5),
        ] {
            assert!(validate_quota(&bad).is_err(), "{bad}");
        }
        assert!(validate_quota(&Value::from(i64::MAX)).is_ok() && validate_quota(&Value::Null).is_ok());
    }
}
