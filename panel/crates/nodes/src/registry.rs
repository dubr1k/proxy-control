//! Node rows: reads and writes a caller composes into one transaction (`nodes/registry.py`, plus
//! `FleetStore._node` and `NodeLinkService.write_enabled`, which the lifecycle service and the CLI
//! use without a link service).
//!
//! Every function takes the caller's [`Conn`]; writes take `now` (whole epoch seconds) instead of
//! reading the wall clock, so one clock drives a request.

use panel_core::db::{row_to_json, Conn};
use panel_core::pytext;
use panel_core::rusqlite::{self, OptionalExtension};
use panel_secrets::audit::{self, Actor, Record};
use serde_json::{Map, Value};

use crate::error::NodesError;
use crate::fleet_compat::{is_operation, valid_node_id, INVENTORY_KEYS};
use crate::LOCAL_NODE_ID;

/// A link with what the node last reported beside it (the view tells "not applied yet" from
/// "applied, a credential still to be captured" by these two columns).
pub const LINK_WITH_OBSERVED: &str =
    "SELECT l.*, o.applied_generation AS observed_generation, o.reconcile_state AS observed_state
                        FROM node_links l LEFT JOIN observed_generations o ON o.node_id=l.node_id";

/// One `fleet_nodes` row as the services see it (`FleetStore._node` plus the `link` the registry
/// attaches): the inventory parsed and narrowed to [`INVENTORY_KEYS`], `disabled` as a bool.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeRow {
    pub node_id: String,
    pub display_name: String,
    pub auth_state: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub next_sequence: i64,
    pub last_result_sequence: i64,
    pub last_seen_at: Option<i64>,
    /// `local` or `remote`.
    pub kind: String,
    pub disabled: bool,
    /// `v1` or `panel`.
    pub transport: String,
    pub inventory: Map<String, Value>,
    /// The `node_links` row ([`link_row`]) when there is one.
    pub link: Option<Map<String, Value>>,
}

impl NodeRow {
    /// The Python dict, keys in its order: the columns of `SELECT *` (without `inventory_json`),
    /// then `inventory`, then `link`.
    pub fn to_value(&self) -> Value {
        let mut out = Map::new();
        out.insert("node_id".into(), self.node_id.clone().into());
        out.insert("display_name".into(), self.display_name.clone().into());
        out.insert("auth_state".into(), self.auth_state.clone().into());
        out.insert("created_at".into(), self.created_at.into());
        out.insert("updated_at".into(), self.updated_at.into());
        out.insert("next_sequence".into(), self.next_sequence.into());
        out.insert("last_result_sequence".into(), self.last_result_sequence.into());
        out.insert("last_seen_at".into(), self.last_seen_at.into());
        out.insert("kind".into(), self.kind.clone().into());
        out.insert("disabled".into(), self.disabled.into());
        out.insert("transport".into(), self.transport.clone().into());
        out.insert("inventory".into(), Value::Object(self.inventory.clone()));
        out.insert("link".into(), self.link.clone().map_or(Value::Null, Value::Object));
        Value::Object(out)
    }
}

/// `FleetStore._node(row)` of a `SELECT * FROM fleet_nodes` row.
fn node_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(NodeRow, String)> {
    let node = NodeRow {
        node_id: row.get("node_id")?,
        display_name: row.get("display_name")?,
        auth_state: row.get("auth_state")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        next_sequence: row.get("next_sequence")?,
        last_result_sequence: row.get("last_result_sequence")?,
        last_seen_at: row.get("last_seen_at")?,
        kind: row.get("kind")?,
        disabled: row.get::<_, i64>("disabled")? != 0,
        transport: row.get("transport")?,
        inventory: Map::new(),
        link: None,
    };
    Ok((node, row.get("inventory_json")?))
}

/// The stored inventory as the API may show it: only [`INVENTORY_KEYS`] (in stored order), and
/// `capabilities` narrowed to the known operations (a non-list becomes `[]`). Anything but an
/// object is `{}`.
pub fn narrow_inventory(raw: &Value) -> Map<String, Value> {
    let Value::Object(raw) = raw else {
        return Map::new();
    };
    let mut inventory: Map<String, Value> = raw
        .iter()
        .filter(|(key, _)| INVENTORY_KEYS.contains(&key.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if let Some(capabilities) = inventory.get_mut("capabilities") {
        *capabilities = match capabilities {
            Value::Array(items) => {
                Value::Array(items.iter().filter(|item| item.as_str().is_some_and(is_operation)).cloned().collect())
            }
            _ => Value::Array(Vec::new()),
        };
    }
    inventory
}

fn finish_node((mut node, inventory_json): (NodeRow, String)) -> Result<NodeRow, NodesError> {
    node.inventory = narrow_inventory(&serde_json::from_str(&inventory_json)?);
    Ok(node)
}

/// `NodeRegistry.link_row(row)`: a `node_links` row (optionally with the observed columns) with
/// `identity_json` parsed into `identity` (moved to the end), `status_json` parsed in place and
/// `has_api_key: true` — the key itself lives encrypted in `secret_versions`.
pub fn link_row(mut value: Map<String, Value>) -> Result<Map<String, Value>, NodesError> {
    let identity = match value.shift_remove("identity_json") {
        Some(Value::String(text)) => serde_json::from_str(&text)?,
        Some(other) => other,
        None => Value::Null,
    };
    if let Some(status) = value.get_mut("status_json") {
        if let Value::String(text) = status {
            *status = serde_json::from_str(text)?;
        }
    }
    value.insert("identity".into(), identity);
    value.insert("has_api_key".into(), Value::Bool(true));
    Ok(value)
}

fn link_rows(db: &Conn, sql: &str, params: impl rusqlite::Params) -> Result<Vec<Map<String, Value>>, NodesError> {
    let mut statement = db.prepare(sql)?;
    let raw = statement.query_map(params, row_to_json)?.collect::<rusqlite::Result<Vec<_>>>()?;
    raw.into_iter().map(link_row).collect()
}

/// Every node, the local one first (the operator's own host is what they look at first), the rest
/// by `node_id`, each with its link.
pub fn rows(db: &Conn) -> Result<Vec<NodeRow>, NodesError> {
    let mut links: Map<String, Value> = Map::new();
    for link in link_rows(db, LINK_WITH_OBSERVED, [])? {
        let node_id = link.get("node_id").and_then(Value::as_str).unwrap_or_default().to_string();
        links.insert(node_id, Value::Object(link));
    }
    let mut statement =
        db.prepare("SELECT * FROM fleet_nodes ORDER BY CASE WHEN kind='local' THEN 0 ELSE 1 END, node_id")?;
    let raw = statement.query_map([], node_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    raw.into_iter()
        .map(|parts| {
            let mut node = finish_node(parts)?;
            node.link = match links.get(&node.node_id) {
                Some(Value::Object(link)) => Some(link.clone()),
                _ => None,
            };
            Ok(node)
        })
        .collect()
}

/// One node with its link; [`NodesError::NotFound`] when there is no such row.
pub fn row(db: &Conn, node_id: &str) -> Result<NodeRow, NodesError> {
    let parts = db
        .query_row("SELECT * FROM fleet_nodes WHERE node_id=?", [node_id], node_row)
        .optional()?
        .ok_or_else(|| NodesError::NotFound(node_id.to_string()))?;
    let mut node = finish_node(parts)?;
    node.link = link_rows(db, &format!("{LINK_WITH_OBSERVED} WHERE l.node_id=?"), [node_id])?.into_iter().next();
    Ok(node)
}

/// The display-name rule of `insert` and `rename`: a string, not blank after Python's `strip()`,
/// at most 128 code points as given. Answers the stripped name.
fn checked_display_name(display_name: &str) -> Result<&str, NodesError> {
    let stripped = pytext::strip(display_name);
    if stripped.is_empty() || pytext::len(display_name) > 128 {
        return Err(NodesError::Protocol("display_name is invalid".into()));
    }
    Ok(stripped)
}

/// `NodeRegistry.insert`: a new unenrolled node in the caller's transaction (registration and its
/// audit row commit together). A duplicate id is a constraint violation ([`NodesError::is_integrity`]).
pub fn insert(
    db: &Conn,
    node_id: &str,
    display_name: &str,
    kind: &str,
    transport: &str,
    now: i64,
) -> Result<(), NodesError> {
    if !valid_node_id(node_id) {
        return Err(NodesError::Protocol("node_id is invalid".into()));
    }
    if node_id == LOCAL_NODE_ID {
        return Err(NodesError::Protocol(format!(
            "node_id {} is reserved for this server",
            pytext::repr(LOCAL_NODE_ID)
        )));
    }
    let display_name = checked_display_name(display_name)?;
    db.execute(
        "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at,kind,transport)
               VALUES(?,?,'unenrolled','{}',?,?,?,?)",
        rusqlite::params![node_id, display_name, now, now, kind, transport],
    )?;
    Ok(())
}

/// `NodeRegistry.rename`: the name is checked first, then a missing node is
/// [`NodesError::NotFound`].
pub fn rename(db: &Conn, node_id: &str, display_name: &str, now: i64) -> Result<(), NodesError> {
    let display_name = checked_display_name(display_name)?;
    let changed = db.execute(
        "UPDATE fleet_nodes SET display_name=?,updated_at=? WHERE node_id=?",
        rusqlite::params![display_name, now, node_id],
    )?;
    if changed != 1 {
        return Err(NodesError::NotFound(node_id.to_string()));
    }
    Ok(())
}

/// `NodeRegistry.set_disabled`: the v1 operator switch (`fleet_nodes.disabled`).
pub fn set_disabled(db: &Conn, node_id: &str, disabled: bool, now: i64) -> Result<(), NodesError> {
    let changed = db.execute(
        "UPDATE fleet_nodes SET disabled=?,updated_at=? WHERE node_id=?",
        rusqlite::params![i64::from(disabled), now, node_id],
    )?;
    if changed != 1 {
        return Err(NodesError::NotFound(node_id.to_string()));
    }
    Ok(())
}

fn count(db: &Conn, sql: &str, node_id: &str) -> Result<i64, NodesError> {
    Ok(db.query_row(sql, [node_id], |row| row.get(0))?)
}

/// Grants still pointing at this node (any state but `deleted`).
pub fn active_grants(db: &Conn, node_id: &str) -> Result<i64, NodesError> {
    count(db, "SELECT count(*) FROM access_grants WHERE node_id=? AND desired_state<>'deleted'", node_id)
}

/// Grants this panel created on the node, in any state (a `deleted` row is a deletion the node has
/// not confirmed yet, so the account is still live there); imported ones existed before the link.
pub fn provisioned_grants(db: &Conn, node_id: &str) -> Result<i64, NodesError> {
    count(db, "SELECT count(*) FROM access_grants WHERE node_id=? AND origin<>'imported'", node_id)
}

/// Fleet v1 commands still `queued` or `dispatched` for the node (rows a retired v1 node left
/// behind; the statuses are compared as plain strings).
pub fn pending_commands(db: &Conn, node_id: &str) -> Result<i64, NodesError> {
    count(db, "SELECT count(*) FROM fleet_commands WHERE node_id=? AND status IN ('queued','dispatched')", node_id)
}

/// Who changed something, from where, under which request: the audit fields of a node write.
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

    /// The CLI's context: actor `{"username": "cli"}`, ip `cli`.
    pub fn cli() -> Self {
        Self::new(Actor::new(None, "cli"), "cli", None)
    }

    /// An audit row with this context, written at `now`.
    pub fn record(
        &self,
        db: &Conn,
        action: &str,
        target: &str,
        detail: Option<Map<String, Value>>,
        now: i64,
    ) -> Result<i64, NodesError> {
        let mut record = Record::new(&self.actor, action, target, self.ip.clone()).request_id(self.request_id.clone());
        record.detail = detail;
        Ok(audit::record_at(db, &record, now)?)
    }
}

/// `NodeLinkService.write_enabled`: pause/resume a linked panel with its audit row, inside the
/// caller's transaction — `node_links.enabled` is the one flag a linked panel has
/// (`fleet_nodes.disabled` is v1's). [`NodesError::NotFound`] when the node has no link.
pub fn write_link_enabled(
    db: &Conn,
    node_id: &str,
    enabled: bool,
    context: &AuditContext,
    now: i64,
) -> Result<(), NodesError> {
    let changed = db.execute(
        "UPDATE node_links SET enabled=?,updated_at=? WHERE node_id=?",
        rusqlite::params![i64::from(enabled), now, node_id],
    )?;
    if changed != 1 {
        return Err(NodesError::NotFound(node_id.to_string()));
    }
    context.record(db, if enabled { "node.resume" } else { "node.pause" }, node_id, None, now)?;
    Ok(())
}
