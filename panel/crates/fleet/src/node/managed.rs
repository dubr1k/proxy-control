//! The node's view of fleet v2 (`fleet_v2/managed.py`): the generations it accepted and the
//! resources it owns for the central panel. Every method runs inside the caller's connection or
//! transaction (spec §4, §5.3).
//!
//! Stored bytes are Python's: `managed_generations.document_json` is pydantic's
//! `model_dump_json()` of the document (declaration order, every default), `learned_json` and the
//! `fleet_lanes_json`/`fleet_relay_json` settings are `json.dumps(…, sort_keys=True)`.

use indexmap::IndexMap;
use panel_core::clock::SharedClock;
use panel_core::db::{row_to_json, Conn, DbError};
use panel_core::pyjson;
use panel_core::rusqlite::{params, OptionalExtension as _};
use panel_model::fleet::{ConflictCode, GenerationConflict, GenerationDocument, ObservedGeneration};
use panel_model::validate::{Model, ValidationError};
use panel_secrets::identity::{read_setting, write_setting_at, MASTER_KEY};
use serde_json::{json, Map, Value};

/// `panel_settings` key of the lanes the node built (`{protocol: {lane: [users]}}`).
pub const LANES_KEY: &str = "fleet_lanes_json";
/// `panel_settings` key of what the relay section came to.
pub const RELAY_KEY: &str = "fleet_relay_json";

/// A `managed_resources` row as `dict(row)` (column order of the table).
pub type Row = Map<String, Value>;
/// `(protocol, runtime_username)`.
pub type Key = (String, String);

/// What can go wrong reading or writing the store.
#[derive(Debug)]
pub enum StoreError {
    Db(DbError),
    /// A stored document or report that no longer validates (pydantic's `ValidationError`).
    Invalid(ValidationError),
    /// Stored JSON that does not parse.
    Json(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Db(error) => write!(f, "{error}"),
            StoreError::Invalid(error) => write!(f, "{error}"),
            StoreError::Json(error) => f.write_str(error),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<DbError> for StoreError {
    fn from(error: DbError) -> Self {
        StoreError::Db(error)
    }
}

impl From<panel_core::rusqlite::Error> for StoreError {
    fn from(error: panel_core::rusqlite::Error) -> Self {
        StoreError::Db(error.into())
    }
}

/// Why `accept` refused or failed.
#[derive(Debug)]
pub enum AcceptError {
    Conflict(GenerationConflict),
    Store(StoreError),
}

impl From<StoreError> for AcceptError {
    fn from(error: StoreError) -> Self {
        AcceptError::Store(error)
    }
}

impl From<DbError> for AcceptError {
    fn from(error: DbError) -> Self {
        AcceptError::Store(error.into())
    }
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::Conflict(conflict) => write!(f, "{conflict}"),
            AcceptError::Store(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AcceptError {}

/// `ManagedStore.latest(db)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Latest {
    pub generation: i64,
    pub digest: String,
    /// `received`, `applying`, `converged` or `failed`.
    pub state: String,
    pub master_guid: String,
    pub document: GenerationDocument,
}

/// One `upsert_resource` call. `credential_ref` and `learned` keep the previous row's values when
/// `None` (a state change does not forget what create/rotate established).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResourceUpdate {
    pub protocol: String,
    pub username: String,
    pub reference: String,
    pub generation: i64,
    pub state: String,
    pub error: Option<String>,
    pub revision: Option<String>,
    pub credential_ref: Option<String>,
    pub learned: Option<Map<String, Value>>,
}

/// One `upsert_egress` call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressUpdate {
    pub protocol: String,
    pub generation: i64,
    pub state: String,
    pub revision: Option<String>,
    pub digest: Option<String>,
    pub error: Option<String>,
    pub router_revision: Option<String>,
    pub router_digest: Option<String>,
}

fn loads(text: &str) -> Result<Value, StoreError> {
    serde_json::from_str(text).map_err(|error| StoreError::Json(error.to_string()))
}

/// `json.loads(read_setting(db, key) or default)`.
pub fn setting_json(db: &Conn, key: &str, default: &str) -> Result<Value, StoreError> {
    match read_setting(db, key)?.filter(|text| !text.is_empty()) {
        Some(text) => loads(&text),
        None => loads(default),
    }
}

/// The node's store of generations and central-owned resources.
#[derive(Clone)]
pub struct ManagedStore {
    clock: SharedClock,
}

impl std::fmt::Debug for ManagedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ManagedStore")
    }
}

impl ManagedStore {
    pub fn new(clock: SharedClock) -> Self {
        Self { clock }
    }

    fn now(&self) -> i64 {
        self.clock.now()
    }

    /// `write_setting(db, key, value)` on this store's clock.
    pub fn write_setting(&self, db: &Conn, key: &str, value: Option<&str>) -> Result<(), DbError> {
        write_setting_at(db, key, value, self.now())
    }

    /// The central that manages this node, if any.
    pub fn master_guid(&self, db: &Conn) -> Result<Option<String>, DbError> {
        read_setting(db, MASTER_KEY)
    }

    /// Records a pushed generation: refuses another node's, another central's, an older one, or
    /// the same number with another digest (409 codes); the same number and digest is a no-op.
    /// The first accepted push records the central.
    pub fn accept(
        &self,
        db: &Conn,
        document: &GenerationDocument,
        digest: &str,
        node_guid: &str,
    ) -> Result<(), AcceptError> {
        let conflict = |code| Err(AcceptError::Conflict(GenerationConflict::new(code, "")));
        if document.node_guid != node_guid {
            return conflict(ConflictCode::GuidMismatch);
        }
        let master = self.master_guid(db)?;
        if let Some(master) = master.as_deref().filter(|master| !master.is_empty()) {
            if master != document.master_guid {
                return conflict(ConflictCode::ForeignMaster);
            }
        }
        if let Some(latest) = self.latest(db)? {
            if document.generation < latest.generation {
                return conflict(ConflictCode::StaleGeneration);
            }
            if document.generation == latest.generation {
                if latest.digest != digest {
                    return conflict(ConflictCode::DigestConflict);
                }
                return Ok(());
            }
        }
        if master.is_none() {
            self.write_setting(db, MASTER_KEY, Some(&document.master_guid))?;
        }
        db.execute(
            "INSERT INTO managed_generations(generation,digest,master_guid,document_json,received_at,state)
               VALUES(?,?,?,?,?,'received')",
            params![document.generation, digest, document.master_guid, document.dump_json(), self.now()],
        )?;
        Ok(())
    }

    /// The highest generation, its document re-validated (`model_validate_json`).
    pub fn latest(&self, db: &Conn) -> Result<Option<Latest>, StoreError> {
        let row = db
            .query_row(
                "SELECT generation, digest, state, master_guid, document_json FROM managed_generations
                 ORDER BY generation DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((generation, digest, state, master_guid, document_json)) = row else {
            return Ok(None);
        };
        let document = GenerationDocument::validate(&loads(&document_json)?).map_err(StoreError::Invalid)?;
        Ok(Some(Latest { generation, digest, state, master_guid, document }))
    }

    /// `set_state`: `applied_at` moves only on `converged`.
    pub fn set_state(&self, db: &Conn, generation: i64, state: &str) -> Result<(), DbError> {
        let applied = (state == "converged").then(|| self.now());
        db.execute(
            "UPDATE managed_generations SET state=?, applied_at=COALESCE(?, applied_at) WHERE generation=?",
            params![state, applied, generation],
        )?;
        Ok(())
    }

    /// Every `managed_resources` row by `(protocol, runtime_username)`, in table order.
    pub fn resources(&self, db: &Conn) -> Result<IndexMap<Key, Row>, StoreError> {
        let mut statement = db.prepare("SELECT * FROM managed_resources")?;
        let rows = statement.query_map([], row_to_json)?;
        let mut out = IndexMap::new();
        for row in rows {
            let row = row?;
            let key = (text(&row, "protocol"), text(&row, "runtime_username"));
            out.insert(key, row);
        }
        Ok(out)
    }

    /// `upsert_resource(db, …)`.
    pub fn upsert_resource(&self, db: &Conn, update: &ResourceUpdate) -> Result<(), DbError> {
        let learned = update.learned.as_ref().map(|learned| pyjson::sorted(&Value::Object(learned.clone())));
        db.execute(
            "INSERT INTO managed_resources(protocol,runtime_username,ref,credential_ref,generation,state,
               last_error,revision,updated_at,learned_json) VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(protocol,runtime_username) DO UPDATE SET
               ref=excluded.ref, credential_ref=COALESCE(excluded.credential_ref, managed_resources.credential_ref),
               generation=excluded.generation, state=excluded.state,
               last_error=excluded.last_error, revision=excluded.revision, updated_at=excluded.updated_at,
               learned_json=COALESCE(excluded.learned_json, managed_resources.learned_json)",
            params![
                update.protocol,
                update.username,
                update.reference,
                update.credential_ref,
                update.generation,
                update.state,
                update.error,
                update.revision,
                self.now(),
                learned
            ],
        )?;
        Ok(())
    }

    /// What a later step taught about the link (a lane's port) joins the row's `learned`.
    pub fn merge_learned(
        &self,
        db: &Conn,
        protocol: &str,
        username: &str,
        learned: &Map<String, Value>,
    ) -> Result<(), StoreError> {
        let row: Option<Option<String>> = db
            .query_row(
                "SELECT learned_json FROM managed_resources WHERE protocol=? AND runtime_username=?",
                params![protocol, username],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored) = row else {
            return Ok(());
        };
        let mut merged = match loads(stored.as_deref().filter(|text| !text.is_empty()).unwrap_or("{}"))? {
            Value::Object(map) => map,
            _ => return Err(StoreError::Json("learned_json is not an object".into())),
        };
        for (key, value) in learned {
            merged.insert(key.clone(), value.clone());
        }
        db.execute(
            "UPDATE managed_resources SET learned_json=? WHERE protocol=? AND runtime_username=?",
            params![pyjson::sorted(&Value::Object(merged)), protocol, username],
        )?;
        Ok(())
    }

    pub fn remove_resource(&self, db: &Conn, protocol: &str, username: &str) -> Result<(), DbError> {
        db.execute(
            "DELETE FROM managed_resources WHERE protocol=? AND runtime_username=?",
            params![protocol, username],
        )?;
        Ok(())
    }

    /// The resources the central owns right now: [`ManagedStore::resources`] without the rows
    /// left `missing` (a confirmed deletion kept only so the report can be repeated).
    pub fn owned(&self, db: &Conn) -> Result<IndexMap<Key, Row>, StoreError> {
        let mut rows = self.resources(db)?;
        rows.retain(|_, row| row.get("state").and_then(Value::as_str) != Some("missing"));
        Ok(rows)
    }

    /// The one question every local writer asks first (ADR 003).
    pub fn is_managed(&self, db: &Conn, protocol: &str, username: &str) -> Result<bool, DbError> {
        Ok(db
            .query_row(
                "SELECT 1 FROM managed_resources WHERE protocol=? AND runtime_username=? AND state<>'missing'",
                params![protocol, username],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// `managed_egress` rows by protocol, in table order.
    pub fn egress_rows(&self, db: &Conn) -> Result<IndexMap<String, Row>, StoreError> {
        let mut statement = db.prepare("SELECT * FROM managed_egress")?;
        let rows = statement.query_map([], row_to_json)?;
        let mut out = IndexMap::new();
        for row in rows {
            let row = row?;
            out.insert(text(&row, "protocol"), row);
        }
        Ok(out)
    }

    pub fn upsert_egress(&self, db: &Conn, update: &EgressUpdate) -> Result<(), DbError> {
        db.execute(
            "INSERT INTO managed_egress(protocol,generation,revision,digest,state,last_error,updated_at,
               router_revision,router_digest)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(protocol) DO UPDATE SET generation=excluded.generation, revision=excluded.revision,
               digest=excluded.digest, state=excluded.state, last_error=excluded.last_error,
               updated_at=excluded.updated_at, router_revision=excluded.router_revision,
               router_digest=excluded.router_digest",
            params![
                update.protocol,
                update.generation,
                update.revision,
                update.digest,
                update.state,
                update.error,
                self.now(),
                update.router_revision,
                update.router_digest
            ],
        )?;
        Ok(())
    }

    /// The node's report of its latest generation, `None` before any push.
    ///
    /// Unlike Python (whose `observed` goes through `latest()`), the stored document is not
    /// re-validated here: the report needs only the generation, digest and state.
    pub fn observed(&self, db: &Conn) -> Result<Option<ObservedGeneration>, StoreError> {
        let latest = db
            .query_row(
                "SELECT generation, digest, state FROM managed_generations ORDER BY generation DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
            )
            .optional()?;
        let Some((generation, digest, state)) = latest else {
            return Ok(None);
        };
        struct Head {
            generation: i64,
            digest: String,
            state: String,
        }
        let latest = Head { generation, digest, state };
        let state = match latest.state.as_str() {
            "received" | "applying" => "applying",
            other => other,
        };
        let lanes = setting_json(db, LANES_KEY, "{}")?;
        let relay = setting_json(db, RELAY_KEY, "null")?;
        let mut resources = Vec::new();
        for row in self.resources(db)?.values() {
            let learned = match row.get("learned_json").and_then(Value::as_str).filter(|text| !text.is_empty()) {
                Some(text) => loads(text)?,
                None => json!({}),
            };
            resources.push(json!({
                "ref": row.get("ref"), "protocol": row.get("protocol"),
                "runtime_username": row.get("runtime_username"), "state": row.get("state"),
                "error": row.get("last_error"), "revision": row.get("revision"), "learned": learned,
            }));
        }
        let mut egress = Map::new();
        for (protocol, row) in self.egress_rows(db)? {
            let router = match row.get("router_revision") {
                None | Some(Value::Null) => Value::Null,
                Some(revision) => json!({"revision": revision, "digest": row.get("router_digest")}),
            };
            let mut names: Vec<String> = match lanes.get(&protocol) {
                Some(Value::Object(map)) => map.keys().cloned().collect(),
                _ => Vec::new(),
            };
            names.sort();
            egress.insert(
                protocol,
                json!({"state": row.get("state"), "revision": row.get("revision"), "digest": row.get("digest"),
                       "error": row.get("last_error"), "router": router, "lanes": names}),
            );
        }
        let value = json!({
            "applied_generation": latest.generation, "digest": latest.digest, "reconcile_state": state,
            "resources": resources, "egress": egress, "relay": relay, "reported_at": self.now(),
        });
        ObservedGeneration::validate(&value).map(Some).map_err(StoreError::Invalid)
    }

    /// Forgets the master; runtime users stay and become local (spec §5.2), and so do the egress
    /// each service runs, its lanes and the relay — only the bookkeeping goes. How many resources
    /// were released.
    pub fn unlink(&self, db: &Conn) -> Result<i64, DbError> {
        let released: i64 = db.query_row("SELECT count(*) FROM managed_resources", [], |row| row.get(0))?;
        db.execute("DELETE FROM managed_resources", [])?;
        db.execute("DELETE FROM managed_egress", [])?;
        db.execute("DELETE FROM managed_generations", [])?;
        self.write_setting(db, MASTER_KEY, None)?;
        self.write_setting(db, LANES_KEY, None)?;
        self.write_setting(db, RELAY_KEY, None)?;
        Ok(released)
    }
}

fn text(row: &Row, key: &str) -> String {
    row.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}
