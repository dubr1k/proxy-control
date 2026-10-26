//! Subscription and node events (`panel/events.py`): facts the panel recorded, never a promise it
//! delivered.
//!
//! Every event is an `audit_log` row written inside the caller's transaction (a rolled-back change
//! leaves no event behind), mirrored into a bounded in-memory ring for cheap polling. The payload
//! passes through the audit scrubber, so a token, a link or a credential cannot end up in it.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;

use panel_core::clock::{SharedClock, SystemClock};
use panel_core::db::{Conn, Database, DbError};
use panel_core::rusqlite::{self, params_from_iter, types::Value as SqlValue};
use panel_core::serde_json::{self, Map, Value};

use crate::audit::{self, Actor, Record};
use crate::pyvalue::py_truthy;

/// The event names.
pub const NAMES: [&str; 5] =
    ["subscription.generation.changed", "subscription.fetched", "subscription.revoked", "node.up", "node.down"];
/// The largest page `GET /api/events` serves.
pub const MAX_PAGE: i64 = 500;
/// The ring's default capacity.
pub const DEFAULT_CAPACITY: usize = 500;

/// Why an event was not recorded.
#[derive(Debug)]
pub enum EventError {
    /// `unknown event name: <name>`.
    UnknownName(String),
    /// The payload names neither a subscription nor a node.
    NoTarget,
    Db(DbError),
}

impl EventError {
    pub const NO_TARGET: &'static str = "an event names the subscription or node it is about";
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventError::UnknownName(name) => write!(f, "unknown event name: {name}"),
            EventError::NoTarget => f.write_str(Self::NO_TARGET),
            EventError::Db(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for EventError {}

impl From<DbError> for EventError {
    fn from(error: DbError) -> Self {
        EventError::Db(error)
    }
}

/// Why the event listing failed.
#[derive(Debug)]
pub enum SinceError {
    Db(DbError),
    Detail(serde_json::Error),
}

impl fmt::Display for SinceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SinceError::Db(error) => write!(f, "{error}"),
            SinceError::Detail(error) => write!(f, "event detail_json is not valid JSON: {error}"),
        }
    }
}

impl std::error::Error for SinceError {}

impl From<DbError> for SinceError {
    fn from(error: DbError) -> Self {
        SinceError::Db(error)
    }
}

impl From<rusqlite::Error> for SinceError {
    fn from(error: rusqlite::Error) -> Self {
        SinceError::Db(error.into())
    }
}

/// The event bus: the durable trail in `audit_log` plus the recent ring.
pub struct EventBus {
    database: Database,
    clock: SharedClock,
    capacity: usize,
    recent: Mutex<VecDeque<Map<String, Value>>>,
}

impl fmt::Debug for EventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBus").field("capacity", &self.capacity).finish_non_exhaustive()
    }
}

impl EventBus {
    /// `EventBus(database)` with the default capacity and the system clock.
    pub fn new(database: Database) -> Self {
        Self::with_options(database, DEFAULT_CAPACITY, SystemClock::shared())
    }

    /// `EventBus(database, capacity=…, clock=…)`.
    pub fn with_options(database: Database, capacity: usize, clock: SharedClock) -> Self {
        Self { database, clock, capacity, recent: Mutex::new(VecDeque::with_capacity(capacity)) }
    }

    /// `emit(db, name, payload)`: record one event in the caller's transaction, append it to the
    /// ring, and return its row id. The target is `payload["subscription_id"] or
    /// payload["node_id"]` and must be a non-empty string.
    pub fn emit(&self, db: &Conn, name: &str, payload: &Map<String, Value>) -> Result<i64, EventError> {
        if !NAMES.contains(&name) {
            return Err(EventError::UnknownName(name.to_string()));
        }
        let target = match payload.get("subscription_id").filter(|value| py_truthy(value)) {
            Some(value) => Some(value),
            None => payload.get("node_id"),
        };
        let target = match target {
            Some(Value::String(text)) if !text.is_empty() => text.clone(),
            _ => return Err(EventError::NoTarget),
        };
        let clean = audit::scrub_map(payload);
        let now = self.clock.now();
        let row_id =
            audit::record_at(db, &Record::new(&Actor::system(), name, target, "local").detail(clean.clone()), now)?;
        let mut entry = Map::new();
        entry.insert("id".into(), row_id.into());
        entry.insert("name".into(), name.into());
        entry.insert("at".into(), now.into());
        for (key, value) in clean {
            entry.insert(key, value);
        }
        let mut recent = self.recent.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.capacity == 0 {
            return Ok(row_id);
        }
        if recent.len() == self.capacity {
            recent.pop_front();
        }
        recent.push_back(entry);
        Ok(row_id)
    }

    /// The ring, oldest first.
    pub fn recent(&self) -> Vec<Map<String, Value>> {
        self.recent.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).iter().cloned().collect()
    }

    /// `since(after, limit)`: events with an id above `after`, oldest first — the durable trail,
    /// not the ring. Each is `{"id", "name", "at", "node_id"|"subscription_id", **detail}`.
    pub fn since(&self, after: i64, limit: i64) -> Result<Vec<Map<String, Value>>, SinceError> {
        let placeholders = vec!["?"; NAMES.len()].join(",");
        let sql = format!(
            "SELECT id, happened_at, action, target, detail_json FROM audit_log WHERE id > ? AND action IN ({placeholders}) ORDER BY id LIMIT ?"
        );
        let mut values = vec![SqlValue::Integer(after)];
        values.extend(NAMES.iter().map(|name| SqlValue::Text((*name).into())));
        values.push(SqlValue::Integer(limit));
        let rows: Vec<(i64, i64, String, String, String)> = self.database.with_connection(|db| {
            let mut statement = db.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(SinceError::from)
        })?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, happened_at, action, target, detail_json) in rows {
            let mut entry = Map::new();
            entry.insert("id".into(), id.into());
            entry.insert("name".into(), action.clone().into());
            entry.insert("at".into(), happened_at.into());
            let target_key = if action.starts_with("node.") { "node_id" } else { "subscription_id" };
            entry.insert(target_key.into(), target.into());
            let detail: Value = serde_json::from_str(&detail_json).map_err(SinceError::Detail)?;
            if let Value::Object(detail) = detail {
                for (key, value) in detail {
                    entry.insert(key, value);
                }
            }
            out.push(entry);
        }
        Ok(out)
    }
}
