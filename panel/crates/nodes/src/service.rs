//! Node lifecycle as an application service: every mutation and its audit row commit together
//! (`nodes/service.py`).
//!
//! What it owns: the node views (list, one, the local node), renaming, and the operator's
//! disable switch — which for a linked panel (fleet v2) is pausing its link. Registration of fleet
//! v1 nodes and the revocation of their certificates went with fleet v1 (owner decision,
//! 2026-10-25); a linked panel is created by the link service (`registry::insert` with transport
//! `panel`).
//!
//! Everything here blocks on SQLite: call it from `spawn_blocking`.

use panel_core::clock::SharedClock;
use panel_core::db::{Conn, Database};
use panel_core::pyjson;
use serde_json::{Map, Value};

use crate::error::NodesError;
use crate::read_model::{derive, view_to_value, STALE_AFTER};
use crate::registry::{self, AuditContext, NodeRow};
use crate::{certificates, NodeView, LOCAL_NODE_ID};

/// `NodeLifecycleService`: the node views and lifecycle writes over one database and clock.
#[derive(Clone)]
pub struct NodeLifecycleService {
    database: Database,
    clock: SharedClock,
}

impl NodeLifecycleService {
    pub fn new(database: Database, clock: SharedClock) -> Self {
        Self { database, clock }
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    fn now(&self) -> i64 {
        self.clock.now()
    }

    fn view(&self, db: &Conn, row: &NodeRow) -> Result<NodeView, NodesError> {
        Ok(derive(
            row,
            certificates::list(db, &row.node_id)?,
            registry::pending_commands(db, &row.node_id)?,
            self.now(),
            STALE_AFTER,
        ))
    }

    /// Every node, the local one first.
    pub fn list(&self) -> Result<Vec<NodeView>, NodesError> {
        self.database.with_connection(|db| registry::rows(db)?.iter().map(|row| self.view(db, row)).collect())
    }

    /// One node; [`NodesError::NotFound`] when there is no such node.
    pub fn get(&self, node_id: &str) -> Result<NodeView, NodesError> {
        self.database.with_connection(|db| self.view(db, &registry::row(db, node_id)?))
    }

    /// The reserved row migration 5 created; it exists in every database.
    pub fn local(&self) -> Result<NodeView, NodesError> {
        self.get(LOCAL_NODE_ID)
    }

    /// Renames a node (the local one too) and audits `node.rename` with the name as given.
    pub fn rename(&self, node_id: &str, display_name: &str, context: &AuditContext) -> Result<NodeView, NodesError> {
        let now = self.now();
        self.database.transaction(|db| {
            registry::rename(db, node_id, display_name, now)?;
            let mut detail = Map::new();
            detail.insert("display_name".into(), Value::String(display_name.to_string()));
            context.record(db, "node.rename", node_id, Some(detail), now)?;
            self.view(db, &registry::row(db, node_id)?)
        })
    }

    /// The operator's disable switch.
    ///
    /// A linked panel (transport `panel`) has no v1 transport to switch off: disabling it pauses
    /// its link (`node.pause`/`node.resume`), and `fleet_nodes.disabled` is never touched. A v1
    /// row is refused while it has pending commands, for the local node, and while grants still
    /// point at it; otherwise `node.disable`/`node.enable` is audited.
    pub fn set_disabled(&self, node_id: &str, disabled: bool, context: &AuditContext) -> Result<NodeView, NodesError> {
        let transport = self.database.with_connection(|db| registry::row(db, node_id).map(|row| row.transport))?;
        let now = self.now();
        if transport == "panel" {
            self.database.transaction(|db| registry::write_link_enabled(db, node_id, !disabled, context, now))?;
            return self.get(node_id);
        }
        self.database.transaction(|db| {
            let row = registry::row(db, node_id)?;
            if disabled && registry::pending_commands(db, node_id)? != 0 {
                // Disabling mid-flight would strand commands the node can no longer fetch.
                return Err(NodesError::Conflict("node has pending commands".into()));
            }
            if row.kind == "local" && disabled {
                return Err(NodesError::Conflict("the local node cannot be disabled".into()));
            }
            if disabled && registry::active_grants(db, node_id)? != 0 {
                // Cutting the node off would silently strand every subscriber whose access lives on it.
                return Err(NodesError::Conflict("node still carries active grants".into()));
            }
            registry::set_disabled(db, node_id, disabled, now)?;
            context.record(db, if disabled { "node.disable" } else { "node.enable" }, node_id, None, now)?;
            self.view(db, &registry::row(db, node_id)?)
        })
    }
}

/// `node-list`: `json.dumps([asdict(view) for view in service.list()], sort_keys=True, default=str)`.
pub fn cli_node_list(views: &[NodeView]) -> String {
    pyjson::sorted(&Value::Array(views.iter().map(view_to_value).collect()))
}

/// `node-disable`/`node-enable`: `json.dumps({"node_id", "disabled"}, sort_keys=True)`.
pub fn cli_toggle_line(view: &NodeView) -> String {
    let mut out = Map::new();
    out.insert("node_id".into(), view.node_id.clone().into());
    out.insert("disabled".into(), view.disabled.into());
    pyjson::sorted(&Value::Object(out))
}

/// The CLI's message for a failed `node-disable`/`node-enable` (`parser.error(...)`, exit 2):
/// `NodeConflict`'s text, or `unknown node <id>`; `None` for an internal failure.
pub fn cli_error_message(node_id: &str, error: &NodesError) -> Option<String> {
    match error {
        NodesError::Conflict(message) => Some(message.clone()),
        NodesError::NotFound(_) => Some(format!("unknown node {node_id}")),
        _ => None,
    }
}
