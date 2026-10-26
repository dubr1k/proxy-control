//! Who asked, from where, under which request id — the `actor`/`ip`/`request_id` keyword
//! arguments every Python service method takes.

use panel_core::db::{Conn, DbError};
use panel_secrets::audit::{self, Actor, Record};
use serde_json::{Map, Value};

/// The caller's audit context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditContext {
    pub actor: Actor,
    pub ip: String,
    pub request_id: Option<String>,
}

impl AuditContext {
    pub fn new(actor: Actor, ip: impl Into<String>, request_id: Option<String>) -> Self {
        Self { actor, ip: ip.into(), request_id }
    }

    /// The saga's own rows: `{"id": None, "username": "system"}`, ip `local`, no request id.
    pub fn system() -> Self {
        Self::new(Actor::system(), "local", None)
    }

    /// An audit row of this caller (the remaining fields set by the caller).
    pub fn row(&self, action: &str, target: &str) -> Record {
        Record::new(&self.actor, action, target, self.ip.clone()).request_id(self.request_id.clone())
    }
}

/// Builds and writes one audit row (`audit.record`).
pub(crate) struct Audit {
    record: Record,
}

impl Audit {
    pub(crate) fn new(context: &AuditContext, action: impl Into<String>, target: impl Into<String>) -> Self {
        let action = action.into();
        let target = target.into();
        Self { record: context.row(&action, &target) }
    }

    pub(crate) fn detail(mut self, detail: Value) -> Self {
        self.record.detail = match detail {
            Value::Object(map) => Some(map),
            _ => Some(Map::new()),
        };
        self
    }

    pub(crate) fn reason(mut self, reason_code: &str) -> Self {
        self.record.reason_code = Some(reason_code.to_string());
        self
    }

    pub(crate) fn before(mut self, digest: String) -> Self {
        self.record.before_digest = Some(digest);
        self
    }

    pub(crate) fn after(mut self, digest: String) -> Self {
        self.record.after_digest = Some(digest);
        self
    }

    /// Written at `int(time.time())` like Python's `audit.record`.
    pub(crate) fn write(self, db: &Conn) -> Result<i64, DbError> {
        audit::record(db, &self.record)
    }
}
