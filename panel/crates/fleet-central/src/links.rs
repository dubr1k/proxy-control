//! Linked-panel state and handshakes.
//!
//! Node API keys live in `SecretStore` under `node-api-key`, one fresh secret id per rotation.
//! Public link maps never include that secret id; network clients are built only after the database
//! connection and its revealed plaintext have left the connection scope. Network calls never run
//! inside a transaction.

use std::sync::Arc;

use panel_clients::{AuditContext, ProvisioningService};
use panel_core::clock::SharedClock;
use panel_core::db::{row_to_json, Conn, Database};
use panel_core::ids;
use panel_core::pyjson;
use panel_core::rusqlite::types::Value as Sql;
use panel_core::rusqlite::{self, params, params_from_iter, OptionalExtension as _};
use panel_fleet::central::{NodeClientFactory, NodeLink, TLS_MODES};
use panel_model::seams::{NodeClient, NodeError, SeamError};
use panel_nodes::registry;
use panel_nodes::NodesError;
use panel_secrets::audit;
use panel_secrets::secrets_store::{Identity, SecretRef, SecretStore};
use serde_json::{Map, Value};

use crate::client::validate_panel_url;
use crate::error::{CentralError, CentralResult};

pub const KEY_PURPOSE: &str = "node-api-key";

/// Optional fields of `NodeLinkService.update`; `None` leaves the stored value unchanged.
#[derive(Clone, Default)]
pub struct LinkUpdate {
    pub display_name: Option<String>,
    pub url: Option<String>,
    pub api_key: Option<String>,
    pub tls_verify: Option<String>,
    pub pinned_sha256: Option<String>,
    pub auto_import: Option<bool>,
}

fn nodes_error(error: NodesError) -> CentralError {
    match error {
        NodesError::NotFound(id) => CentralError::NotFound(id),
        NodesError::Conflict(message) => CentralError::LinkConflict(message),
        NodesError::Protocol(message) => CentralError::Invalid(message),
        NodesError::Db(error) => CentralError::Db(error),
        NodesError::Json(error) => CentralError::Json(error),
    }
}

fn factory_error(error: SeamError) -> CentralError {
    match error.downcast::<CentralError>() {
        Ok(error) => *error,
        Err(error) => match error.downcast::<NodeError>() {
            Ok(error) => CentralError::Node(*error),
            Err(error) => CentralError::Internal(error.to_string()),
        },
    }
}

fn text(map: &Map<String, Value>, key: &str) -> CentralResult<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| CentralError::Internal(format!("stored node link has no string {key}")))
}

fn flag(map: &Map<String, Value>, key: &str) -> bool {
    match map.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_i64() != Some(0),
        _ => false,
    }
}

fn connection(link: &Map<String, Value>) -> CentralResult<NodeLink> {
    Ok(NodeLink {
        node_id: text(link, "node_id")?,
        panel_url: text(link, "panel_url")?,
        tls_verify: text(link, "tls_verify")?,
        pinned_cert_sha256: link.get("pinned_cert_sha256").and_then(Value::as_str).map(str::to_string),
        allow_private_address: flag(link, "allow_private_address"),
    })
}

fn object_json(value: &Map<String, Value>) -> String {
    pyjson::dumps_default(&Value::Object(value.clone()))
}

/// Operator API for linked panels. Cheap to clone; the factory, database and secret store are
/// shared, and the optional provisioning service is itself a cheap clone.
#[derive(Clone)]
pub struct NodeLinkService {
    database: Database,
    secrets: SecretStore,
    own_guid: String,
    factory: Arc<dyn NodeClientFactory>,
    clock: SharedClock,
    provisioning: Option<ProvisioningService>,
}

impl NodeLinkService {
    pub fn new(
        database: Database,
        secrets: SecretStore,
        own_guid: impl Into<String>,
        factory: Arc<dyn NodeClientFactory>,
        clock: SharedClock,
    ) -> Self {
        Self { database, secrets, own_guid: own_guid.into(), factory, clock, provisioning: None }
    }

    /// Forced deletion also settles operations still waiting for the removed node.
    pub fn with_provisioning(mut self, provisioning: ProvisioningService) -> Self {
        self.provisioning = Some(provisioning);
        self
    }

    pub fn set_provisioning(&mut self, provisioning: Option<ProvisioningService>) {
        self.provisioning = provisioning;
    }

    pub fn own_guid(&self) -> &str {
        &self.own_guid
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    fn raw_link(db: &Conn, node_id: &str) -> CentralResult<Map<String, Value>> {
        let row = db
            .query_row("SELECT * FROM node_links WHERE node_id=?", [node_id], row_to_json)
            .optional()?
            .ok_or_else(|| CentralError::NotFound(node_id.to_string()))?;
        registry::link_row(row).map_err(nodes_error)
    }

    fn public(mut link: Map<String, Value>) -> Map<String, Value> {
        link.shift_remove("api_key_secret_id");
        link
    }

    /// One secret-free `NodeRegistry.link_row` map for routes and other callers.
    pub fn link(&self, db: &Conn, node_id: &str) -> CentralResult<Map<String, Value>> {
        Self::raw_link(db, node_id).map(Self::public)
    }

    /// Every link by node id, with no escrow identifier exposed.
    pub fn links(&self, db: &Conn) -> CentralResult<Vec<Map<String, Value>>> {
        let rows = {
            let mut statement = db.prepare("SELECT * FROM node_links ORDER BY node_id")?;
            statement.query_map([], row_to_json)?.collect::<rusqlite::Result<Vec<_>>>()?
        };
        rows.into_iter().map(|row| registry::link_row(row).map(Self::public).map_err(nodes_error)).collect()
    }

    fn reveal_key(&self, db: &Conn, link: &Map<String, Value>) -> CentralResult<String> {
        let node_id = text(link, "node_id")?;
        let secret_id = text(link, "api_key_secret_id")?;
        let plaintext = self.secrets.reveal(
            db,
            &SecretRef::new(secret_id, 1),
            KEY_PURPOSE,
            None,
            Some(&node_id),
        )?;
        String::from_utf8(plaintext).map_err(|_| CentralError::Internal("stored node API key is not UTF-8".into()))
    }

    fn store_key(&self, db: &Conn, node_id: &str, api_key: &str) -> CentralResult<String> {
        // Rotation is a new row, never an overwrite of a secret other operations may still name.
        let secret_id = format!("node-key:{node_id}:{}", ids::token_hex(4));
        self.secrets.store(
            db,
            &Identity {
                secret_id: &secret_id,
                version: 1,
                purpose: KEY_PURPOSE,
                grant_id: None,
                permitted_node_id: Some(node_id),
            },
            api_key.as_bytes(),
            "active",
        )?;
        Ok(secret_id)
    }

    fn client(&self, link: &Map<String, Value>, key: &str) -> CentralResult<Arc<dyn NodeClient>> {
        self.factory.client(&connection(link)?, key).map_err(factory_error)
    }

    pub fn client_for(&self, node_id: &str) -> CentralResult<Arc<dyn NodeClient>> {
        let (link, key) = self.database.with_connection(|db| {
            let link = Self::raw_link(db, node_id)?;
            let key = self.reveal_key(db, &link)?;
            Ok((link, key))
        })?;
        self.client(&link, &key)
    }

    /// Probe identity, status and inventory without storing anything.
    pub async fn test(
        &self,
        url: &str,
        api_key: &str,
        tls_verify: &str,
        pinned_sha256: Option<&str>,
        allow_private: bool,
    ) -> CentralResult<Map<String, Value>> {
        let url = validate_panel_url(url, allow_private)?;
        let link = NodeLink {
            node_id: String::new(),
            panel_url: url.clone(),
            tls_verify: tls_verify.to_string(),
            pinned_cert_sha256: pinned_sha256.map(str::to_string),
            allow_private_address: allow_private,
        };
        let client = self.factory.client(&link, api_key).map_err(factory_error)?;
        let started = self.clock.monotonic();
        let (identity, status, inventory) = async {
            let identity = client.identity().await?;
            let status = client.status().await?;
            let inventory = client.inventory().await?;
            Ok::<_, NodeError>((identity, status, inventory))
        }
        .await
        .map_err(|error| match error {
            NodeError::AuthFailed => CentralError::LinkConflict("the node refused the API key".into()),
            NodeError::Unreachable(kind) => CentralError::LinkConflict(format!("the node is unreachable: {kind}")),
            NodeError::Rejected { status, .. } => {
                CentralError::LinkConflict(format!("the node answered {status}: {error}"))
            }
            other => CentralError::Node(other),
        })?;
        let latency_ms = ((self.clock.monotonic() - started) * 1000.0) as i64;
        let mut probe = Map::new();
        probe.insert("identity".into(), Value::Object(identity));
        probe.insert("status".into(), Value::Object(status));
        probe.insert("inventory".into(), Value::Object(inventory));
        probe.insert("latency_ms".into(), latency_ms.into());
        probe.insert("url".into(), url.into());
        Ok(probe)
    }

    /// Probe first, then insert the node, link, escrowed key and audit in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn add(
        &self,
        display_name: &str,
        url: &str,
        api_key: &str,
        tls_verify: &str,
        pinned_sha256: Option<&str>,
        allow_private: bool,
        context: &AuditContext,
        auto_import: bool,
    ) -> CentralResult<String> {
        let probe = self.test(url, api_key, tls_verify, pinned_sha256, allow_private).await?;
        let identity = probe["identity"].as_object().expect("test inserts an object");
        if identity.get("api_version").and_then(Value::as_i64) != Some(2)
            || identity.get("guid").and_then(Value::as_str).is_none_or(str::is_empty)
        {
            return Err(CentralError::LinkConflict("the panel does not speak Fleet API v2".into()));
        }
        if identity.get("master_guid").is_some_and(|master| !master.is_null() && master.as_str() != Some(self.own_guid.as_str())) {
            return Err(CentralError::LinkConflict("the panel is already managed by another central panel".into()));
        }
        let node_id = identity["guid"].as_str().expect("checked").to_string();
        if node_id == self.own_guid {
            return Err(CentralError::LinkConflict("a panel cannot manage itself".into()));
        }
        let now = self.clock.now();
        self.database.transaction(|db| {
            let exists: Option<i64> = db
                .query_row("SELECT 1 FROM fleet_nodes WHERE node_id=?", [&node_id], |row| row.get(0))
                .optional()?;
            if exists.is_some() {
                return Err(CentralError::LinkConflict("this panel is already linked".into()));
            }
            registry::insert(db, &node_id, display_name, "remote", "panel", now).map_err(nodes_error)?;
            db.execute("UPDATE fleet_nodes SET auth_state='linked' WHERE node_id=?", [&node_id])?;
            let secret_id = self.store_key(db, &node_id, api_key)?;
            let panel_version = identity.get("panel_version").and_then(Value::as_str);
            let status = probe["status"].as_object().expect("test inserts an object");
            db.execute(
                "INSERT INTO node_links(node_id,panel_url,tls_verify,pinned_cert_sha256,api_key_secret_id,
                 allow_private_address,latency_ms,panel_version,identity_json,status_json,created_at,updated_at,auto_import)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                params![
                    node_id,
                    probe["url"].as_str().expect("test inserts a URL"),
                    tls_verify,
                    pinned_sha256,
                    secret_id,
                    i64::from(allow_private),
                    probe["latency_ms"].as_i64().expect("test inserts latency"),
                    panel_version,
                    object_json(identity),
                    object_json(status),
                    now,
                    now,
                    i64::from(auto_import)
                ],
            )?;
            let detail = serde_json::json!({
                "display_name": display_name,
                "panel": probe["url"],
                "tls_verify": tls_verify,
                "auto_import": auto_import,
            })
            .as_object()
            .unwrap()
            .clone();
            Self::audit(db, context, "node.link", &node_id, Some(detail), now)?;
            Ok(node_id.clone())
        })
    }

    fn audit(
        db: &Conn,
        context: &AuditContext,
        action: &str,
        target: &str,
        detail: Option<Map<String, Value>>,
        now: i64,
    ) -> CentralResult<()> {
        let mut record = context.row(action, target);
        record.detail = detail;
        audit::record_at(db, &record, now)?;
        Ok(())
    }

    /// Change only named fields. A replacement key gets a fresh secret row and revokes the old one.
    pub fn update(&self, node_id: &str, update: LinkUpdate, context: &AuditContext) -> CentralResult<()> {
        let now = self.clock.now();
        self.database.transaction(|db| {
            let link = Self::raw_link(db, node_id)?;
            let mut changes: Vec<(&str, Sql)> = Vec::new();
            let mut changed: Vec<String> = Vec::new();
            if let Some(display_name) = update.display_name {
                registry::rename(db, node_id, &display_name, now).map_err(nodes_error)?;
                changed.push("display_name".into());
            }
            if let Some(url) = update.url {
                let normalized = validate_panel_url(&url, flag(&link, "allow_private_address"))?;
                changes.push(("panel_url", normalized.into()));
            }
            let mode = update.tls_verify.clone().unwrap_or(text(&link, "tls_verify")?);
            let pin = update.pinned_sha256.clone().or_else(|| {
                link.get("pinned_cert_sha256").and_then(Value::as_str).map(str::to_string)
            });
            if !TLS_MODES.contains(&mode.as_str()) {
                return Err(CentralError::Invalid("tls_verify must be verify or pin".into()));
            }
            if mode == "pin" && pin.as_deref().is_none_or(str::is_empty) {
                return Err(CentralError::Invalid("pin mode needs pinned_sha256".into()));
            }
            if let Some(mode) = update.tls_verify {
                changes.push(("tls_verify", mode.into()));
            }
            if let Some(pin) = update.pinned_sha256 {
                changes.push(("pinned_cert_sha256", pin.into()));
            }
            if let Some(auto_import) = update.auto_import {
                changes.push(("auto_import", i64::from(auto_import).into()));
            }
            if let Some(api_key) = update.api_key {
                let secret_id = self.store_key(db, node_id, &api_key)?;
                self.secrets.transition(
                    db,
                    &SecretRef::new(text(&link, "api_key_secret_id")?, 1),
                    "revoked",
                )?;
                changes.push(("api_key_secret_id", secret_id.into()));
                changed.push("api_key".into());
            }
            changed.extend(changes.iter().map(|(column, _)| (*column).to_string()).filter(|column| column != "api_key_secret_id"));
            if !changes.is_empty() {
                let assignments = changes.iter().map(|(column, _)| format!("{column}=?")).collect::<Vec<_>>().join(",");
                let values = changes.into_iter().map(|(_, value)| value).chain([Sql::from(now), Sql::from(node_id)]);
                db.execute(
                    &format!("UPDATE node_links SET {assignments},updated_at=? WHERE node_id=?"),
                    params_from_iter(values),
                )?;
            }
            changed.sort();
            Self::audit(
                db,
                context,
                "node.link.update",
                node_id,
                Some(serde_json::json!({"changed":changed}).as_object().unwrap().clone()),
                now,
            )
        })
    }

    pub fn set_enabled(&self, node_id: &str, enabled: bool, context: &AuditContext) -> CentralResult<()> {
        let now = self.clock.now();
        self.database.transaction(|db| Self::write_enabled(db, node_id, enabled, context, now))
    }

    /// Pause/resume with its audit in the caller's transaction.
    pub fn write_enabled(
        db: &Conn,
        node_id: &str,
        enabled: bool,
        context: &AuditContext,
        now: i64,
    ) -> CentralResult<()> {
        let changed = db.execute(
            "UPDATE node_links SET enabled=?,updated_at=? WHERE node_id=?",
            params![i64::from(enabled), now, node_id],
        )?;
        if changed != 1 {
            return Err(CentralError::NotFound(node_id.to_string()));
        }
        Self::audit(db, context, if enabled { "node.resume" } else { "node.pause" }, node_id, None, now)
    }

    fn refuse_provisioned(db: &Conn, node_id: &str) -> CentralResult<()> {
        let remaining = registry::provisioned_grants(db, node_id).map_err(nodes_error)?;
        if remaining == 0 {
            return Ok(());
        }
        let pending: i64 = db.query_row(
            "SELECT count(*) FROM access_grants WHERE node_id=? AND origin<>'imported' AND desired_state='deleted'",
            [node_id],
            |row| row.get(0),
        )?;
        if pending == remaining {
            return Err(CentralError::LinkConflict(format!(
                "wait until the node confirms the deletion of {pending} grant(s)"
            )));
        }
        Err(CentralError::LinkConflict(format!(
            "{remaining} provisioned grant(s) still exist on the node: delete the clients' accesses first and wait until the node confirms"
        )))
    }

    /// Best-effort remote unlink, then local credential revocation and removal. Imported grants
    /// are released; forced deletion abandons provisioned grants and says so in its audit detail.
    pub async fn delete(&self, node_id: &str, context: &AuditContext, force: bool) -> CentralResult<()> {
        let (link, key) = self.database.with_connection(|db| {
            let link = Self::raw_link(db, node_id)?;
            if !force {
                Self::refuse_provisioned(db, node_id)?;
            }
            let key = self.reveal_key(db, &link)?;
            Ok((link, key))
        })?;
        let client = self.client(&link, &key)?;
        let (released, node_error) = match client.unlink().await {
            Ok(_) => (true, None),
            Err(error @ (NodeError::Unreachable(_) | NodeError::AuthFailed | NodeError::Rejected { .. })) => {
                (false, Some(Self::describe(&error)))
            }
            Err(error) => return Err(CentralError::Node(error)),
        };
        self.database.transaction(|db| {
            let abandoned = if force {
                registry::provisioned_grants(db, node_id).map_err(nodes_error)?
            } else {
                Self::refuse_provisioned(db, node_id)?;
                0
            };
            let imported = Self::grant_ids(
                db,
                "SELECT id FROM access_grants WHERE node_id=? AND origin='imported' AND desired_state<>'deleted'",
                node_id,
            )?;
            let let_go = if force {
                Self::grant_ids(db, "SELECT id FROM access_grants WHERE node_id=?", node_id)?
            } else {
                imported.clone()
            };
            for grant_id in let_go {
                let versions = {
                    let mut statement = db.prepare(
                        "SELECT version FROM secret_versions WHERE secret_id=? AND state<>'revoked'",
                    )?;
                    statement
                        .query_map([format!("grant:{grant_id}")], |row| row.get::<_, i64>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                };
                for version in versions {
                    self.secrets.transition(db, &SecretRef::new(format!("grant:{grant_id}"), version), "revoked")?;
                }
                if force {
                    if let Some(provisioning) = &self.provisioning {
                        provisioning.withdraw_remote(db, &grant_id, "node unlinked (forced)")?;
                    }
                }
            }
            db.execute("DELETE FROM access_grants WHERE node_id=?", [node_id])?;
            db.execute(
                "DELETE FROM secret_versions WHERE secret_id=? AND purpose=?",
                params![text(&link, "api_key_secret_id")?, KEY_PURPOSE],
            )?;
            db.execute("DELETE FROM fleet_nodes WHERE node_id=?", [node_id])?;
            let mut detail = Map::new();
            detail.insert("node_released".into(), released.into());
            detail.insert("released_imported".into(), (imported.len() as i64).into());
            if let Some(error) = node_error {
                detail.insert("node_error".into(), error.into());
            }
            if force {
                detail.insert("forced".into(), true.into());
                detail.insert("abandoned_provisioned".into(), abandoned.into());
            }
            Self::audit(db, context, "node.unlink", node_id, Some(detail), self.clock.now())
        })
    }

    fn grant_ids(db: &Conn, sql: &str, node_id: &str) -> CentralResult<Vec<String>> {
        let mut statement = db.prepare(sql)?;
        Ok(statement.query_map([node_id], |row| row.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Only the error class and a rejection status/code; never a response detail that might echo a key.
    fn describe(error: &NodeError) -> String {
        let description = match error {
            NodeError::Unreachable(_) => "NodeUnreachable".to_string(),
            NodeError::AuthFailed => "NodeAuthFailed".to_string(),
            NodeError::Rejected { status, code, .. } => match code.as_deref().filter(|code| !code.is_empty()) {
                Some(code) => format!("NodeRejected: {code}"),
                None => format!("NodeRejected: {status}"),
            },
            NodeError::InvalidAnswer(_) => "NodeInvalidAnswer".to_string(),
        };
        description.chars().take(100).collect()
    }

    /// Update heartbeat bookkeeping and return `node.up`/`node.down` only on an actual transition.
    #[allow(clippy::too_many_arguments)]
    pub fn record_heartbeat(
        &self,
        db: &Conn,
        node_id: &str,
        online: bool,
        identity: Option<&Map<String, Value>>,
        status: Option<&Map<String, Value>>,
        latency_ms: Option<i64>,
        error: Option<&str>,
    ) -> CentralResult<Option<String>> {
        let previous = db
            .query_row("SELECT status FROM node_links WHERE node_id=?", [node_id], |row| row.get::<_, String>(0))
            .optional()?
            .ok_or_else(|| CentralError::NotFound(node_id.to_string()))?;
        let now = self.clock.now();
        let current = if online { "online" } else { "offline" };
        let mut fields: Vec<(&str, Sql)> = vec![("status", current.into())];
        if online {
            fields.push(("last_heartbeat_at", now.into()));
            fields.push(("last_error", Sql::Null));
            if let Some(latency) = latency_ms {
                fields.push(("latency_ms", latency.into()));
            }
            if let Some(identity) = identity {
                fields.push(("identity_json", object_json(identity).into()));
                fields.push((
                    "panel_version",
                    identity.get("panel_version").and_then(Value::as_str).map_or(Sql::Null, Sql::from),
                ));
            }
            if let Some(status) = status {
                fields.push(("status_json", object_json(status).into()));
            }
        } else {
            fields.push(("last_error", error.map_or(Sql::Null, Sql::from)));
        }
        fields.push(("updated_at", now.into()));
        let assignments = fields.iter().map(|(column, _)| format!("{column}=?")).collect::<Vec<_>>().join(",");
        let values = fields.into_iter().map(|(_, value)| value).chain([Sql::from(node_id)]);
        db.execute(&format!("UPDATE node_links SET {assignments} WHERE node_id=?"), params_from_iter(values))?;
        if previous == current {
            Ok(None)
        } else {
            Ok(Some(if online { "node.up" } else { "node.down" }.to_string()))
        }
    }
}

impl panel_model::seams::NodeClientProvider for NodeLinkService {
    fn client_for(&self, node_id: &str) -> Result<Arc<dyn NodeClient>, SeamError> {
        NodeLinkService::client_for(self, node_id).map_err(|error| Box::new(error) as SeamError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_core::clock::FakeClock;
    use panel_secrets::audit::Actor;

    struct FailingFactory;

    impl NodeClientFactory for FailingFactory {
        fn client(&self, _link: &NodeLink, _api_key: &str) -> Result<Arc<dyn NodeClient>, SeamError> {
            Err(Box::new(std::io::Error::other("no test network client")))
        }
    }

    struct TempDatabase {
        database: Database,
        path: std::path::PathBuf,
    }

    impl TempDatabase {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("fleet-links-{}-{}.db", std::process::id(), ids::token_hex(6)));
            let database = Database::open(&path).unwrap();
            database.connect().unwrap().execute_batch(
                r#"CREATE TABLE node_links(node_id TEXT PRIMARY KEY,panel_url TEXT NOT NULL,tls_verify TEXT NOT NULL,
                    pinned_cert_sha256 TEXT,api_key_secret_id TEXT NOT NULL,allow_private_address INTEGER NOT NULL DEFAULT 0,
                    enabled INTEGER NOT NULL DEFAULT 1,status TEXT NOT NULL DEFAULT 'unknown',latency_ms INTEGER,panel_version TEXT,
                    identity_json TEXT NOT NULL DEFAULT '{}',status_json TEXT NOT NULL DEFAULT '{}',last_heartbeat_at INTEGER,last_error TEXT,
                    config_dirty INTEGER NOT NULL DEFAULT 0,desired_generation INTEGER NOT NULL DEFAULT 0,acknowledged_generation INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,auto_import INTEGER NOT NULL DEFAULT 1);
                   CREATE TABLE audit_log(id INTEGER PRIMARY KEY,happened_at INTEGER NOT NULL,actor_id INTEGER,actor_username TEXT NOT NULL,
                    action TEXT NOT NULL,target TEXT NOT NULL,detail_json TEXT,ip TEXT NOT NULL,request_id TEXT,correlation_id TEXT,
                    reason_code TEXT,generation INTEGER,before_digest TEXT,after_digest TEXT);"#,
            ).unwrap();
            Self { database, path }
        }

        fn insert_link(&self) {
            let db = self.database.connect().unwrap();
            db.execute(
                "INSERT INTO node_links(node_id,panel_url,tls_verify,api_key_secret_id,identity_json,status_json,created_at,updated_at)
                 VALUES('n','https://node.example','verify','node-key:n:deadbeef',?, ?,0,0)",
                params![r#"{"guid":"n"}"#, r#"{"managed_resources":0}"#],
            ).unwrap();
            db.commit().unwrap();
        }
    }

    impl Drop for TempDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
            let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
        }
    }

    fn service(temp: &TempDatabase, clock: SharedClock) -> NodeLinkService {
        NodeLinkService::new(temp.database.clone(), SecretStore::new(None), "central", Arc::new(FailingFactory), clock)
    }

    fn context() -> AuditContext {
        AuditContext::new(Actor::new(Some(1), "owner"), "test", None)
    }

    #[test]
    fn rows_are_secret_free_but_internal_client_link_retains_escrow_id() {
        let temp = TempDatabase::new();
        temp.insert_link();
        let service = service(&temp, Arc::new(FakeClock::new(10.0)));
        let db = temp.database.connect().unwrap();
        let public = service.link(&db, "n").unwrap();
        assert!(!public.contains_key("api_key_secret_id"));
        assert_eq!(public["has_api_key"], true);
        assert_eq!(public["identity"]["guid"], "n");
        assert_eq!(public["status_json"]["managed_resources"], 0);
        assert_eq!(NodeLinkService::raw_link(&db, "n").unwrap()["api_key_secret_id"], "node-key:n:deadbeef");
        assert!(matches!(service.link(&db, "missing"), Err(CentralError::NotFound(id)) if id == "missing"));
    }

    #[test]
    fn heartbeat_records_good_reports_and_only_transition_events() {
        let temp = TempDatabase::new();
        temp.insert_link();
        let clock = Arc::new(FakeClock::new(10.0));
        let service = service(&temp, clock.clone());
        let db = temp.database.connect().unwrap();
        let identity = serde_json::json!({"guid":"n","panel_version":"9.9"}).as_object().unwrap().clone();
        let status = serde_json::json!({"managed_resources":2}).as_object().unwrap().clone();
        assert_eq!(service.record_heartbeat(&db, "n", true, Some(&identity), Some(&status), Some(11), None).unwrap(), Some("node.up".into()));
        clock.advance(1.0);
        assert_eq!(service.record_heartbeat(&db, "n", true, None, None, Some(12), None).unwrap(), None);
        let link = service.link(&db, "n").unwrap();
        assert_eq!(link["status"], "online");
        assert_eq!(link["panel_version"], "9.9");
        assert_eq!(link["latency_ms"], 12);
        assert_eq!(link["status_json"]["managed_resources"], 2);
        assert_eq!(link["last_heartbeat_at"], 11);
        clock.advance(1.0);
        assert_eq!(service.record_heartbeat(&db, "n", false, None, None, None, Some("NodeUnreachable")).unwrap(), Some("node.down".into()));
        let link = service.link(&db, "n").unwrap();
        assert_eq!(link["status"], "offline");
        assert_eq!(link["last_error"], "NodeUnreachable");
        assert_eq!(link["panel_version"], "9.9");
        assert_eq!(link["last_heartbeat_at"], 11);
        assert!(matches!(service.record_heartbeat(&db, "missing", true, None, None, None, None), Err(CentralError::NotFound(_))));
    }

    #[test]
    fn pause_resume_use_events_compatible_audits() {
        let temp = TempDatabase::new();
        temp.insert_link();
        let service = service(&temp, Arc::new(FakeClock::new(10.0)));
        service.set_enabled("n", false, &context()).unwrap();
        service.set_enabled("n", true, &context()).unwrap();
        let db = temp.database.connect().unwrap();
        let actions = db.prepare("SELECT action FROM audit_log ORDER BY id").unwrap()
            .query_map([], |row| row.get::<_, String>(0)).unwrap()
            .collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(actions, ["node.pause", "node.resume"]);
        assert_eq!(service.link(&db, "n").unwrap()["enabled"], 1);
    }

    #[test]
    fn describe_never_includes_rejected_detail() {
        let error = NodeError::Rejected { status: 502, code: Some("bad_generation".into()), detail: "secret echo".into() };
        assert_eq!(NodeLinkService::describe(&error), "NodeRejected: bad_generation");
    }
}
