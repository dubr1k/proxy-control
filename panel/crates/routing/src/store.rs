//! Routing policies at rest (`routing/store.py`, migration 14 and later): reads and writes a caller
//! composes into one transaction, like the other stores — the audit row commits with the change.

use panel_core::db::{row_to_json, Conn};
use panel_core::ids::uuid4;
use panel_core::pyjson;
use panel_core::rusqlite::{self, params, OptionalExtension};
use panel_model::routing::models::{
    backend_for, backends_for, normalise_lane, Action, DefaultAction, Fallback, Intent, PolicyInput, PolicyState,
    RoutingPolicy, RoutingRule, RuleMatch, COMPILER_VERSION, LANE_SERVICE,
};
use panel_model::validate::Model;
use panel_model::{Backend, Protocol};
use serde_json::{Map, Value};

use crate::error::{Result, RoutingFailure};

pub const HISTORY_LIMIT: i64 = 50;

/// Why a store write was refused.
#[derive(Debug)]
pub enum StoreError {
    /// `PolicyConflict`: `expected_revision` is not the stored one.
    Conflict(i64),
    /// `ValueError`: a backend the protocol cannot run on.
    Invalid(String),
    /// `PolicyNotFound`.
    NotFound(String),
    /// Anything Python let escape.
    Failure(RoutingFailure),
}

impl From<RoutingFailure> for StoreError {
    fn from(error: RoutingFailure) -> Self {
        StoreError::Failure(error)
    }
}

impl From<panel_core::db::DbError> for StoreError {
    fn from(error: panel_core::db::DbError) -> Self {
        StoreError::Failure(error.into())
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        StoreError::Failure(error.into())
    }
}

impl StoreError {
    /// The failure for a caller that does not translate this refusal.
    pub fn into_failure(self) -> RoutingFailure {
        match self {
            StoreError::Conflict(revision) => RoutingFailure::internal(format!("policy revision is {revision}")),
            StoreError::Invalid(message) => RoutingFailure::internal(message),
            StoreError::NotFound(id) => RoutingFailure::internal(format!("policy not found: {id}")),
            StoreError::Failure(failure) => failure,
        }
    }
}

fn rules(db: &Conn, policy_id: &str) -> Result<Vec<RoutingRule>> {
    let mut statement = db.prepare(
        "SELECT id, position, enabled, match_json, action, egress, note, preset FROM routing_rules WHERE policy_id=? ORDER BY position",
    )?;
    let raw = statement
        .query_map([policy_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    raw.into_iter()
        .map(|(id, position, enabled, match_json, action, egress, note, preset)| {
            let matcher = RuleMatch::validate(&serde_json::from_str(&match_json)?)
                .map_err(|error| RoutingFailure::internal(error.to_string()))?;
            Ok(RoutingRule {
                id: Some(id),
                position,
                enabled: enabled != 0,
                matcher,
                action: Action::from_wire(&action).ok_or_else(|| RoutingFailure::internal("stored rule action"))?,
                egress,
                note,
                preset,
            })
        })
        .collect()
}

struct PolicyRow {
    id: String,
    node_id: String,
    protocol: String,
    lane: String,
    backend: String,
    default_action: String,
    default_egress: Option<String>,
    fallback: String,
    revision: i64,
    state: String,
    applied_revision: Option<i64>,
    applied_digest: Option<String>,
    applied_at: Option<i64>,
    last_error: Option<String>,
    created_at: i64,
    updated_at: i64,
}

const POLICY_COLUMNS: &str =
    "id, node_id, protocol, lane, backend, default_action, default_egress, fallback, revision, state, \
     applied_revision, applied_digest, applied_at, last_error, created_at, updated_at";

fn policy_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PolicyRow> {
    Ok(PolicyRow {
        id: row.get(0)?,
        node_id: row.get(1)?,
        protocol: row.get(2)?,
        lane: row.get(3)?,
        backend: row.get(4)?,
        default_action: row.get(5)?,
        default_egress: row.get(6)?,
        fallback: row.get(7)?,
        revision: row.get(8)?,
        state: row.get(9)?,
        applied_revision: row.get(10)?,
        applied_digest: row.get(11)?,
        applied_at: row.get(12)?,
        last_error: row.get(13)?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
    })
}

fn policy(db: &Conn, row: PolicyRow) -> Result<RoutingPolicy> {
    let invalid = |what: &str| RoutingFailure::internal(format!("stored policy {what} is invalid"));
    Ok(RoutingPolicy {
        intent: Intent {
            default_action: DefaultAction::from_wire(&row.default_action).ok_or_else(|| invalid("default_action"))?,
            default_egress: row.default_egress,
            fallback: Fallback::from_wire(&row.fallback).ok_or_else(|| invalid("fallback"))?,
            rules: rules(db, &row.id)?,
        },
        protocol: Protocol::from_wire(&row.protocol).ok_or_else(|| invalid("protocol"))?,
        backend: Backend::from_wire(&row.backend).ok_or_else(|| invalid("backend"))?,
        state: PolicyState::from_wire(&row.state).ok_or_else(|| invalid("state"))?,
        id: row.id,
        node_id: row.node_id,
        lane: row.lane,
        revision: row.revision,
        applied_revision: row.applied_revision,
        applied_digest: row.applied_digest,
        applied_at: row.applied_at,
        last_error: row.last_error,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn policies(db: &Conn, sql: &str, params: impl rusqlite::Params) -> Result<Vec<RoutingPolicy>> {
    let mut statement = db.prepare(sql)?;
    let rows = statement.query_map(params, policy_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter().map(|row| policy(db, row)).collect()
}

fn lane_of(lane: &str) -> Result<String> {
    normalise_lane(Some(lane)).map_err(|error| RoutingFailure::internal(error.0))
}

/// `get(db, node_id, protocol, lane)`.
pub fn get(db: &Conn, node_id: &str, protocol: &str, lane: &str) -> Result<Option<RoutingPolicy>> {
    let lane = lane_of(lane)?;
    let sql = format!("SELECT {POLICY_COLUMNS} FROM routing_policies WHERE node_id=? AND protocol=? AND lane=?");
    Ok(policies(db, &sql, params![node_id, protocol, lane])?.into_iter().next())
}

/// `lanes_of(db, node_id, protocol)`: every policy of one service — its own first, then the lanes.
pub fn lanes_of(db: &Conn, node_id: &str, protocol: &str) -> Result<Vec<RoutingPolicy>> {
    let sql = format!(
        "SELECT {POLICY_COLUMNS} FROM routing_policies WHERE node_id=? AND protocol=? ORDER BY lane='svc' DESC, created_at, lane"
    );
    policies(db, &sql, params![node_id, protocol])
}

/// `get_by_id(db, policy_id)`; `None` is Python's `PolicyNotFound`.
pub fn find_by_id(db: &Conn, policy_id: &str) -> Result<Option<RoutingPolicy>> {
    let sql = format!("SELECT {POLICY_COLUMNS} FROM routing_policies WHERE id=?");
    Ok(policies(db, &sql, params![policy_id])?.into_iter().next())
}

/// `get_by_id(db, policy_id)` for a policy that must exist.
pub fn get_by_id(db: &Conn, policy_id: &str) -> std::result::Result<RoutingPolicy, StoreError> {
    find_by_id(db, policy_id)?.ok_or_else(|| StoreError::NotFound(policy_id.to_string()))
}

/// `list(db, node_id=None)`.
pub fn list(db: &Conn, node_id: Option<&str>) -> Result<Vec<RoutingPolicy>> {
    let order = "ORDER BY node_id, protocol, lane='svc' DESC, created_at";
    match node_id {
        Some(node_id) => {
            policies(db, &format!("SELECT {POLICY_COLUMNS} FROM routing_policies WHERE node_id=? {order}"), [node_id])
        }
        None => policies(db, &format!("SELECT {POLICY_COLUMNS} FROM routing_policies {order}"), []),
    }
}

fn match_json(rule: &RoutingRule) -> String {
    pyjson::sorted(&rule.matcher.dump())
}

/// `upsert(db, node_id, protocol, policy, expected_revision, now, lane)`: the whole policy — head
/// and every rule — as one revision. Rule ids the caller sends back are kept; anything else (or an
/// id seen twice, or another policy's) is a new rule.
pub fn upsert(
    db: &Conn,
    node_id: &str,
    protocol: &str,
    policy: &PolicyInput,
    expected_revision: Option<i64>,
    now: i64,
    lane: &str,
) -> std::result::Result<RoutingPolicy, StoreError> {
    let lane = lane_of(lane)?;
    if let Some(backend) = policy.backend {
        if !backends_for(protocol).contains(&backend) {
            return Err(StoreError::Invalid(format!("{protocol} cannot run on {backend}")));
        }
    }
    let current = db
        .query_row(
            "SELECT id, revision, backend FROM routing_policies WHERE node_id=? AND protocol=? AND lane=?",
            params![node_id, protocol, lane],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?)),
        )
        .optional()?;
    let intent = &policy.intent;
    let (policy_id, known) = match current {
        None => {
            if !matches!(expected_revision, None | Some(0)) {
                return Err(StoreError::Conflict(0));
            }
            let backend = match policy.backend.or_else(|| backend_for(protocol)) {
                Some(backend) => backend,
                None => return Err(StoreError::Failure(RoutingFailure::internal(format!("KeyError: {protocol}")))),
            };
            let policy_id = uuid4();
            db.execute(
                "INSERT INTO routing_policies(id,node_id,protocol,lane,backend,default_action,default_egress,fallback,revision,\
                 state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,'draft',?,?)",
                params![
                    policy_id,
                    node_id,
                    protocol,
                    lane,
                    backend.as_str(),
                    intent.default_action.as_str(),
                    intent.default_egress,
                    intent.fallback.as_str(),
                    1,
                    now,
                    now
                ],
            )?;
            (policy_id, Vec::new())
        }
        Some((policy_id, revision, backend)) => {
            if expected_revision.is_some_and(|expected| expected != revision) {
                return Err(StoreError::Conflict(revision));
            }
            let backend = policy.backend.map_or(backend, |backend| backend.as_str().to_string());
            db.execute(
                "UPDATE routing_policies SET backend=?, default_action=?, default_egress=?, fallback=?, revision=?, updated_at=? WHERE id=?",
                params![
                    backend,
                    intent.default_action.as_str(),
                    intent.default_egress,
                    intent.fallback.as_str(),
                    revision + 1,
                    now,
                    policy_id
                ],
            )?;
            let known: Vec<String> = db
                .prepare("SELECT id FROM routing_rules WHERE policy_id=?")?
                .query_map([&policy_id], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            db.execute("DELETE FROM routing_rules WHERE policy_id=?", [&policy_id])?;
            (policy_id, known)
        }
    };
    let mut used: Vec<String> = Vec::new();
    for (position, rule) in intent.rules.iter().enumerate() {
        let rule_id = match &rule.id {
            Some(id) if known.contains(id) && !used.contains(id) => id.clone(),
            _ => uuid4(),
        };
        used.push(rule_id.clone());
        db.execute(
            "INSERT INTO routing_rules(id,policy_id,position,enabled,match_json,action,egress,note,preset,created_at,updated_at) \
             VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            params![
                rule_id,
                policy_id,
                position as i64,
                i64::from(rule.enabled),
                match_json(rule),
                rule.action.as_str(),
                rule.egress,
                rule.note,
                rule.preset,
                now,
                now
            ],
        )?;
    }
    get_by_id(db, &policy_id)
}

/// `retarget(db, policy_id, backend, now)`: the policy on another backend — a new revision in
/// `draft`, the rules kept.
pub fn retarget(
    db: &Conn,
    policy_id: &str,
    backend: Backend,
    now: i64,
) -> std::result::Result<RoutingPolicy, StoreError> {
    let policy = get_by_id(db, policy_id)?;
    if !backends_for(policy.protocol.as_str()).contains(&backend) {
        return Err(StoreError::Invalid(format!("{} cannot run on {backend}", policy.protocol)));
    }
    db.execute(
        "UPDATE routing_policies SET backend=?, revision=revision+1, state='draft', last_error=NULL, updated_at=? WHERE id=?",
        params![backend.as_str(), now, policy_id],
    )?;
    get_by_id(db, policy_id)
}

/// `delete(db, policy_id)`.
pub fn delete(db: &Conn, policy_id: &str) -> std::result::Result<(), StoreError> {
    if db.execute("DELETE FROM routing_policies WHERE id=?", [policy_id])? == 0 {
        return Err(StoreError::NotFound(policy_id.to_string()));
    }
    Ok(())
}

/// The keyword arguments of `mark`.
#[derive(Debug, Clone, Default)]
pub struct Mark {
    pub applied_revision: Option<i64>,
    pub applied_digest: Option<String>,
    pub last_error: Option<String>,
}

/// `mark(db, policy_id, state, …)`: where the policy stands on the node. `applied` records what
/// runs there; `rolled_back`/`draft` set the applied fields as given; anything else keeps them.
pub fn mark(db: &Conn, policy_id: &str, state: PolicyState, fields: Mark, now: i64) -> Result<()> {
    match state {
        PolicyState::Applied => db.execute(
            "UPDATE routing_policies SET state=?, applied_revision=?, applied_digest=?, applied_at=?, last_error=NULL, updated_at=? WHERE id=?",
            params![state.as_str(), fields.applied_revision, fields.applied_digest, now, now, policy_id],
        )?,
        PolicyState::RolledBack | PolicyState::Draft => db.execute(
            "UPDATE routing_policies SET state=?, applied_revision=?, applied_digest=?, applied_at=?, last_error=?, updated_at=? WHERE id=?",
            params![state.as_str(), fields.applied_revision, fields.applied_digest, now, fields.last_error, now, policy_id],
        )?,
        _ => db.execute(
            "UPDATE routing_policies SET state=?, last_error=?, updated_at=? WHERE id=?",
            params![state.as_str(), fields.last_error, now, policy_id],
        )?,
    };
    Ok(())
}

/// One `routing_applies` row to write.
#[derive(Debug, Clone)]
pub struct ApplyRecord<'a> {
    pub revision: i64,
    pub digest: Option<&'a str>,
    pub backend: &'a str,
    pub outcome: &'a str,
    pub detail: Option<String>,
    pub actor: &'a str,
    pub runtime_version: Option<&'a str>,
    pub compiler_version: &'a str,
    pub document: Option<&'a Value>,
}

impl<'a> ApplyRecord<'a> {
    pub fn new(revision: i64, digest: Option<&'a str>, backend: &'a str, outcome: &'a str) -> Self {
        Self {
            revision,
            digest,
            backend,
            outcome,
            detail: None,
            actor: "system",
            runtime_version: None,
            compiler_version: COMPILER_VERSION,
            document: None,
        }
    }
}

/// `record_apply(db, policy_id, …)`.
pub fn record_apply(db: &Conn, policy_id: &str, record: &ApplyRecord<'_>, now: i64) -> Result<()> {
    db.execute(
        "INSERT INTO routing_applies(policy_id,revision,digest,backend,compiler_version,runtime_version,outcome,detail,\
         document_json,actor,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        params![
            policy_id,
            record.revision,
            record.digest,
            record.backend,
            record.compiler_version,
            record.runtime_version,
            record.outcome,
            record.detail,
            record.document.map(pyjson::sorted),
            record.actor,
            now
        ],
    )?;
    Ok(())
}

fn apply_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Map<String, Value>> {
    row_to_json(row)
}

fn apply_rows(db: &Conn, sql: &str, params: impl rusqlite::Params) -> Result<Vec<Map<String, Value>>> {
    let raw = db.prepare(sql)?.query_map(params, apply_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    raw.into_iter()
        .map(|mut value| {
            let document = match value.shift_remove("document_json") {
                Some(Value::String(text)) => serde_json::from_str(&text)?,
                _ => Value::Null,
            };
            value.insert("document".into(), document);
            Ok(value)
        })
        .collect()
}

/// `history(db, policy_id, limit)`: newest first, `document_json` parsed into `document` (last).
pub fn history(db: &Conn, policy_id: &str, limit: i64) -> Result<Vec<Map<String, Value>>> {
    apply_rows(
        db,
        "SELECT * FROM routing_applies WHERE policy_id=? ORDER BY id DESC LIMIT ?",
        params![policy_id, limit],
    )
}

/// `last_applied(db, policy_id)`: the successful apply before the current one.
pub fn last_applied(db: &Conn, policy_id: &str) -> Result<Option<Map<String, Value>>> {
    let rows = apply_rows(
        db,
        "SELECT * FROM routing_applies WHERE policy_id=? AND outcome='applied' ORDER BY id DESC LIMIT 2",
        [policy_id],
    )?;
    Ok(if rows.len() < 2 { None } else { rows.into_iter().nth(1) })
}

/// `set_desired(db, policy_id, desired, now)`: the egress section a linked node should run.
pub fn set_desired(db: &Conn, policy_id: &str, desired: Option<&Value>, now: i64) -> Result<()> {
    db.execute(
        "UPDATE routing_policies SET desired_json=?, updated_at=? WHERE id=?",
        params![desired.map(pyjson::sorted), now, policy_id],
    )?;
    Ok(())
}

/// `desired_for_node(db, node_id)`: one section per service, held on the service's own policy.
pub fn desired_for_node(db: &Conn, node_id: &str) -> Result<Map<String, Value>> {
    let rows: Vec<(String, String)> = db
        .prepare(
            "SELECT protocol, desired_json FROM routing_policies WHERE node_id=? AND desired_json IS NOT NULL AND lane='svc' ORDER BY protocol",
        )?
        .query_map([node_id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut out = Map::new();
    for (protocol, desired) in rows {
        out.insert(protocol, serde_json::from_str(&desired)?);
    }
    Ok(out)
}

/// The service lane's name (re-exported for callers that build lane keys).
pub const SERVICE_LANE: &str = LANE_SERVICE;
