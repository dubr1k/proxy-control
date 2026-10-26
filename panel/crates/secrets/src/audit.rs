//! Audit rows written inside the caller's transaction, never with secret values (`panel/audit.py`).
//!
//! The row goes in through the same connection as the change it describes, so a rolled-back change
//! leaves no audit trail claiming it happened. Scrubbing is recursive and key-based: a secret
//! nested in a list inside a dict is dropped just like a top-level one.
//!
//! `detail_json` is `json.dumps(scrub(detail or {}), ensure_ascii=True)` with Python's **default**
//! separators (`", "`, `": "`), in the detail's insertion order.

use panel_core::db::{Conn, Database, DbError};
use panel_core::pyjson;
use panel_core::pytext;
use panel_core::rusqlite::{self, params_from_iter, types::Value as SqlValue};
use panel_core::serde_json::{self, Map, Value};

use crate::casefold::casefold_for_ascii_match;

/// Key fragments that mark a value as secret-bearing.
pub const FORBIDDEN_FRAGMENTS: [&str; 7] =
    ["secret", "password", "token", "credential", "link", "url", "authorization"];

/// Lists keep this many items.
pub const MAX_LIST_ITEMS: usize = 100;
/// Strings keep this many code points.
pub const MAX_STRING_CHARS: usize = 512;

/// `_forbidden(key)`: the casefolded key, `-` read as `_`, contains a forbidden fragment.
pub fn forbidden(key: &str) -> bool {
    let normalized = casefold_for_ascii_match(key).replace('-', "_");
    FORBIDDEN_FRAGMENTS.iter().any(|fragment| normalized.contains(fragment))
}

/// `scrub(value)`: drop forbidden keys at every depth, keep the first 100 list items and the first
/// 512 code points of every string.
pub fn scrub(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(scrub_map(map)),
        Value::Array(items) => Value::Array(items.iter().take(MAX_LIST_ITEMS).map(scrub).collect()),
        Value::String(text) => Value::String(pytext::truncate(text, MAX_STRING_CHARS).to_string()),
        other => other.clone(),
    }
}

/// [`scrub`] of a dict.
pub fn scrub_map(map: &Map<String, Value>) -> Map<String, Value> {
    map.iter().filter(|(key, _)| !forbidden(key)).map(|(key, child)| (key.clone(), scrub(child))).collect()
}

/// `digest(value)`: sha256 hex of `json.dumps(value, sort_keys=True, separators=(",", ":"))`.
pub fn digest(value: &Value) -> String {
    panel_core::ids::sha256_hex(pyjson::canonical(value))
}

/// `json.dumps(scrub(detail or {}), ensure_ascii=True)` — the stored `detail_json`.
pub fn detail_json(detail: Option<&Map<String, Value>>) -> String {
    let scrubbed = detail.map(scrub_map).unwrap_or_default();
    pyjson::dumps_default(&Value::Object(scrubbed))
}

/// Who did it: `actor.get("admin_id") or actor.get("id")` and `actor["username"]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub id: Option<i64>,
    pub username: String,
}

impl Actor {
    pub fn new(id: Option<i64>, username: impl Into<String>) -> Self {
        Self { id, username: username.into() }
    }

    /// `SYSTEM_ACTOR` of the event bus and background work.
    pub fn system() -> Self {
        Self::new(None, "system")
    }
}

/// One audit row: the keyword arguments of `audit.record`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Record {
    pub actor_id: Option<i64>,
    pub actor_username: String,
    pub action: String,
    pub target: String,
    pub ip: String,
    pub detail: Option<Map<String, Value>>,
    pub request_id: Option<String>,
    pub correlation_id: Option<String>,
    pub reason_code: Option<String>,
    pub generation: Option<i64>,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
}

impl Record {
    /// A row with the four required fields; the rest stay empty.
    pub fn new(actor: &Actor, action: impl Into<String>, target: impl Into<String>, ip: impl Into<String>) -> Self {
        Self {
            actor_id: actor.id,
            actor_username: actor.username.clone(),
            action: action.into(),
            target: target.into(),
            ip: ip.into(),
            ..Self::default()
        }
    }

    pub fn detail(mut self, detail: Map<String, Value>) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn request_id(mut self, request_id: Option<impl Into<String>>) -> Self {
        self.request_id = request_id.map(Into::into);
        self
    }
}

/// `audit.record(db, …)` at the current time; the new row id.
pub fn record(db: &Conn, record: &Record) -> Result<i64, DbError> {
    record_at(db, record, crate::now())
}

/// [`record`] with `happened_at` given.
pub fn record_at(db: &Conn, record: &Record, happened_at: i64) -> Result<i64, DbError> {
    db.insert(
        "INSERT INTO audit_log(happened_at,actor_id,actor_username,action,target,detail_json,ip,
           request_id,correlation_id,reason_code,generation,before_digest,after_digest)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        rusqlite::params![
            happened_at,
            record.actor_id,
            record.actor_username,
            record.action,
            record.target,
            detail_json(record.detail.as_ref()),
            record.ip,
            record.request_id,
            record.correlation_id,
            record.reason_code,
            record.generation,
            record.before_digest,
            record.after_digest,
        ],
    )
}

/// The filters of `Store.audits(...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuery {
    pub limit: i64,
    pub before_id: Option<i64>,
    /// Compared `COLLATE NOCASE`.
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub request_id: Option<String>,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self { limit: 200, before_id: None, actor: None, action: None, target: None, request_id: None }
    }
}

/// Why the audit listing failed.
#[derive(Debug)]
pub enum ListError {
    Db(DbError),
    /// A stored `detail_json` is not JSON this port can hold (Python would read `NaN`).
    Detail(serde_json::Error),
}

impl std::fmt::Display for ListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListError::Db(error) => write!(f, "{error}"),
            ListError::Detail(error) => write!(f, "audit detail_json is not valid JSON: {error}"),
        }
    }
}

impl std::error::Error for ListError {}

impl From<DbError> for ListError {
    fn from(error: DbError) -> Self {
        ListError::Db(error)
    }
}

impl From<rusqlite::Error> for ListError {
    fn from(error: rusqlite::Error) -> Self {
        ListError::Db(error.into())
    }
}

/// `Store.audits(...)`: newest first, every column of `audit_log` in table order plus `detail`
/// (the parsed `detail_json`).
pub fn list(database: &Database, query: &AuditQuery) -> Result<Vec<Map<String, Value>>, ListError> {
    let mut clauses: Vec<&str> = Vec::new();
    let mut values: Vec<SqlValue> = Vec::new();
    if let Some(before_id) = query.before_id {
        clauses.push("id < ?");
        values.push(SqlValue::Integer(before_id));
    }
    for (clause, value) in [
        ("actor_username = ? COLLATE NOCASE", &query.actor),
        ("action = ?", &query.action),
        ("target = ?", &query.target),
        ("request_id = ?", &query.request_id),
    ] {
        if let Some(value) = value {
            clauses.push(clause);
            values.push(SqlValue::Text(value.clone()));
        }
    }
    let filter = if clauses.is_empty() { String::new() } else { format!(" WHERE {}", clauses.join(" AND ")) };
    values.push(SqlValue::Integer(query.limit));
    database.with_connection(|db| {
        let mut statement = db.prepare(&format!("SELECT * FROM audit_log{filter} ORDER BY id DESC LIMIT ?"))?;
        let mut rows = statement.query(params_from_iter(values.iter()))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let mut item = panel_core::db::row_to_json(row)?;
            let detail_text: String = row.get("detail_json")?;
            let detail: Value = serde_json::from_str(&detail_text).map_err(ListError::Detail)?;
            item.insert("detail".into(), detail);
            out.push(item);
        }
        Ok(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_core::serde_json::json;

    #[test]
    fn scrub_drops_nested_secret_keys_and_caps_sizes() {
        let detail =
            json!({"keep": "x", "Share-URL": "u", "nested": [{"api_token": 1, "n": 2}], "long": "é".repeat(600)});
        let scrubbed = scrub(&detail);
        assert_eq!(scrubbed["nested"], json!([{"n": 2}]));
        assert!(scrubbed.get("Share-URL").is_none());
        assert_eq!(scrubbed["long"].as_str().unwrap().chars().count(), 512);
        let many = scrub(&json!((0..150).collect::<Vec<_>>()));
        assert_eq!(many.as_array().unwrap().len(), 100);
    }

    #[test]
    fn detail_json_uses_default_separators() {
        let detail = json!({"quota_bytes": 5, "password": "CANARY", "clients": [{"share_url": "x"}]});
        assert_eq!(detail_json(detail.as_object()), r#"{"quota_bytes": 5, "clients": [{}]}"#);
        assert_eq!(detail_json(None), "{}");
    }
}
