//! Lanes, relays and chains on the panel side (v0.7, `routing/lanes.py`).
//!
//! - [`RelayRegistry`] — what each node's router reports about its relay inbound (`router_relays`)
//!   and the relay accounts this panel issued to a node for a *source* node (`relay_peers`, the
//!   UUIDs escrowed under `relay-account`).
//! - [`ChainResolver`] — a node exit's guid → the [`ChainHop`] the compiler renders, or the
//!   [`Reason`] it cannot.
//! - [`LaneService`] — a grant's own lane on this node's router, and the way back.
//!
//! Nothing here prints a UUID or a lane key: they travel router → manager → generation and appear
//! in no view, audit row or report.

use std::collections::BTreeSet;
use std::sync::Arc;

use panel_clients::{store as clients_store, AuditContext};
use panel_core::clock::SharedClock;
use panel_core::db::{row_to_json, Conn, Database};
use panel_core::errors::ApiError;
use panel_core::ids::uuid4;
use panel_core::pytext::urlsplit;
use panel_core::rusqlite::{self, params, OptionalExtension};
use panel_model::clients::{AccessGrant, MieruOptions, ProtocolOptions};
use panel_model::protocols::{AdapterError, BoxFuture};
use panel_model::routing::document::{document_digest, without_lane};
use panel_model::routing::models::{
    PolicyInput, Reason, RoutingPolicy, LANES_UNSUPPORTED_TRUSTTUNNEL, LANE_SERVICE, ROUTER_BACKEND,
};
use panel_model::seams::{GenerationPublisher, RelayConfirmation, SeamError};
use panel_model::validate::Model;
use panel_model::Protocol;
use panel_nodes::NodeRow;
use panel_protocols::error::runtime_failure;
use panel_secrets::secrets_store::{Identity, SecretError, SecretRef, SecretStore};
use serde_json::{json, Map, Value};

use crate::compiler::{ChainHop, HopResolver, Lookup};
use crate::error::{blocking, Refusal, Result, RoutingFailure};
use crate::runtime::{RoutingAdapters, RoutingRouter};
use crate::store;

pub const RELAY_PURPOSE: &str = "relay-account";
pub const DEFAULT_RELAY_PORT: i64 = 45443;
pub const EXITS: [&str; 2] = ["direct", "warp"];

pub fn relay_email(source_guid: &str, exit_kind: &str) -> String {
    format!("relay:{source_guid}:{exit_kind}")
}

/// Python's truthiness of a column value.
pub(crate) fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
    }
}

/// The two relay tables; secrets through the panel's store.
#[derive(Clone)]
pub struct RelayRegistry {
    pub secrets: SecretStore,
}

impl std::fmt::Debug for RelayRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayRegistry")
    }
}

impl RelayRegistry {
    pub fn new(secrets: SecretStore) -> Self {
        Self { secrets }
    }

    /// `record(db, node_id, view, now)`: the router's relay view (`{enabled, port, server_name,
    /// public_key, short_ids}`); a non-object forgets it.
    pub fn record(db: &Conn, node_id: &str, view: Option<&Value>, now: i64) -> Result<()> {
        let Some(view) = view.filter(|view| view.is_object()) else {
            db.execute("DELETE FROM router_relays WHERE node_id=?", [node_id])?;
            return Ok(());
        };
        let short_id = view.get("short_ids").and_then(Value::as_array).and_then(|ids| ids.first()).cloned();
        db.execute(
            "INSERT INTO router_relays(node_id,port,public_key,short_id,server_name,enabled,updated_at) VALUES(?,?,?,?,?,?,?) \
             ON CONFLICT(node_id) DO UPDATE SET port=excluded.port, public_key=excluded.public_key, short_id=excluded.short_id, \
             server_name=excluded.server_name, enabled=excluded.enabled, updated_at=excluded.updated_at",
            params![
                node_id,
                sql(view.get("port")),
                sql(view.get("public_key")),
                sql(short_id.as_ref()),
                sql(view.get("server_name")),
                i64::from(truthy(view.get("enabled"))),
                now
            ],
        )?;
        Ok(())
    }

    /// `observe(db, node_id, report, now)`: a linked node's word on its relay — the public part
    /// joins the row, `enabled` stays what this panel asked for.
    pub fn observe(db: &Conn, node_id: &str, report: &Map<String, Value>, now: i64) -> Result<()> {
        if !matches!(report.get("state"), None | Some(Value::Null)) && report.get("state") != Some(&json!("converged"))
        {
            return Ok(());
        }
        let short_id = match report.get("short_ids") {
            None | Some(Value::Null) => report.get("short_id").cloned(),
            Some(ids) => ids.as_array().and_then(|ids| ids.first()).cloned(),
        };
        let current: Option<i64> = db
            .query_row("SELECT enabled FROM router_relays WHERE node_id=?", [node_id], |row| row.get(0))
            .optional()?;
        let enabled = current.unwrap_or_else(|| i64::from(truthy(report.get("enabled"))));
        db.execute(
            "INSERT INTO router_relays(node_id,port,public_key,short_id,server_name,enabled,updated_at) VALUES(?,?,?,?,?,?,?) \
             ON CONFLICT(node_id) DO UPDATE SET port=excluded.port, public_key=excluded.public_key, short_id=excluded.short_id, \
             server_name=excluded.server_name, updated_at=excluded.updated_at",
            params![
                node_id,
                sql(report.get("port")),
                sql(report.get("public_key")),
                sql(short_id.as_ref()),
                sql(report.get("server_name")),
                enabled,
                now
            ],
        )?;
        Ok(())
    }

    /// `desire(db, node_id, enabled, port, server_name, now)`: what this panel asks of a linked
    /// node's relay; the public part comes with its report.
    pub fn desire(db: &Conn, node_id: &str, enabled: bool, port: i64, server_name: &str, now: i64) -> Result<()> {
        db.execute(
            "INSERT INTO router_relays(node_id,port,public_key,short_id,server_name,enabled,updated_at) VALUES(?,?,NULL,NULL,?,?,?) \
             ON CONFLICT(node_id) DO UPDATE SET port=excluded.port, server_name=excluded.server_name, enabled=excluded.enabled, \
             updated_at=excluded.updated_at",
            params![node_id, port, server_name, i64::from(enabled), now],
        )?;
        Ok(())
    }

    /// `relay(db, node_id)`: the row as a dict.
    pub fn relay(db: &Conn, node_id: &str) -> Result<Option<Map<String, Value>>> {
        Ok(db.query_row("SELECT * FROM router_relays WHERE node_id=?", [node_id], row_to_json).optional()?)
    }

    /// `peers(db, node_id)`.
    pub fn peers(db: &Conn, node_id: &str) -> Result<Vec<Map<String, Value>>> {
        Ok(db
            .prepare("SELECT * FROM relay_peers WHERE node_id=? ORDER BY source_node_id, exit")?
            .query_map([node_id], row_to_json)?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// `issue(db, node_id, source_guid, exit_kind, now)`: the UUID of the account, minted and
    /// escrowed if missing.
    pub fn issue(&self, db: &Conn, node_id: &str, source_guid: &str, exit_kind: &str, now: i64) -> Result<String> {
        if !EXITS.contains(&exit_kind) {
            return Err(RoutingFailure::internal("a relay account exits direct or warp"));
        }
        if let Some(row) = Self::account_row(db, node_id, source_guid, exit_kind)? {
            return self.reveal(db, &text(&row, "secret_id"), node_id);
        }
        let secret_id = uuid4();
        let account = uuid4();
        let identity = Identity {
            secret_id: &secret_id,
            version: 1,
            purpose: RELAY_PURPOSE,
            grant_id: None,
            permitted_node_id: Some(node_id),
        };
        self.secrets.store(db, &identity, account.as_bytes(), "active")?;
        db.execute(
            "INSERT INTO relay_peers(node_id,source_node_id,exit,secret_id,created_at) VALUES(?,?,?,?,?)",
            params![node_id, source_guid, exit_kind, secret_id, now],
        )?;
        Ok(account)
    }

    /// `reveal(db, secret_id, node_id)`.
    pub fn reveal(&self, db: &Conn, secret_id: &str, node_id: &str) -> Result<String> {
        let plaintext = self.secrets.reveal(db, &SecretRef::new(secret_id, 1), RELAY_PURPOSE, None, Some(node_id))?;
        Ok(String::from_utf8_lossy(&plaintext).into_owned())
    }

    /// `accounts(db, node_id)`: every account the node's relay must know, `[{email, uuid}]`.
    pub fn accounts(&self, db: &Conn, node_id: &str) -> Result<Value> {
        let mut out = Vec::new();
        for row in Self::peers(db, node_id)? {
            let email = relay_email(&text(&row, "source_node_id"), &text(&row, "exit"));
            out.push(json!({"email": email, "uuid": self.reveal(db, &text(&row, "secret_id"), node_id)?}));
        }
        Ok(Value::Array(out))
    }

    /// `account_row(db, node_id, source_guid, exit_kind)`.
    pub fn account_row(
        db: &Conn,
        node_id: &str,
        source_guid: &str,
        exit_kind: &str,
    ) -> Result<Option<Map<String, Value>>> {
        Ok(db
            .query_row(
                "SELECT * FROM relay_peers WHERE node_id=? AND source_node_id=? AND exit=?",
                params![node_id, source_guid, exit_kind],
                row_to_json,
            )
            .optional()?)
    }

    /// `rotate(db, node_id, now)`: new UUIDs for every account of the node, the old secrets
    /// revoked; the count.
    pub fn rotate(&self, db: &Conn, node_id: &str, now: i64) -> Result<i64> {
        let mut count = 0;
        for row in Self::peers(db, node_id)? {
            let (source, exit) = (text(&row, "source_node_id"), text(&row, "exit"));
            match self.secrets.transition(db, &SecretRef::new(text(&row, "secret_id"), 1), "revoked") {
                Ok(()) | Err(SecretError::Refused(_)) => {}
                Err(error) => return Err(error.into()),
            }
            db.execute(
                "DELETE FROM relay_peers WHERE node_id=? AND source_node_id=? AND exit=?",
                params![node_id, source, exit],
            )?;
            self.issue(db, node_id, &source, &exit, now)?;
            count += 1;
        }
        Ok(count)
    }
}

fn text(row: &Map<String, Value>, key: &str) -> String {
    row.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

/// A JSON value as an SQL parameter (the types a relay view carries).
fn sql(value: Option<&Value>) -> rusqlite::types::Value {
    use rusqlite::types::Value as Sql;
    match value {
        None | Some(Value::Null) => Sql::Null,
        Some(Value::Bool(flag)) => Sql::Integer(i64::from(*flag)),
        Some(Value::Number(number)) => match number.as_i64() {
            Some(int) => Sql::Integer(int),
            None => Sql::Real(number.as_f64().unwrap_or_default()),
        },
        Some(Value::String(text)) => Sql::Text(text.clone()),
        Some(other) => Sql::Text(other.to_string()),
    }
}

/// `confirmed(node_id, email)` when the panel has no fleet: only this node.
pub fn local_only(node_id: &str, _email: &str) -> std::result::Result<bool, SeamError> {
    Ok(node_id == "local")
}

/// One preview or apply: hops for a source node, against what the panel knows now. `issue` is set
/// on apply (a missing account is minted then); on preview a missing account is «pending».
pub struct ChainResolver<'a> {
    pub db: &'a Conn,
    pub registry: &'a RelayRegistry,
    pub source_guid: String,
    pub nodes_by_guid: Vec<NodeRow>,
    pub own_guid: String,
    pub local_host: String,
    pub confirmed: Arc<dyn RelayConfirmation>,
    pub issue: bool,
    pub now: i64,
    /// The nodes an account was minted for.
    pub issued: BTreeSet<String>,
}

impl ChainResolver<'_> {
    fn address(&self, node_id: &str, row: &NodeRow) -> Option<String> {
        if node_id == "local" {
            return (!self.local_host.is_empty()).then(|| self.local_host.clone());
        }
        let url = row.link.as_ref().and_then(|link| link.get("panel_url")).and_then(Value::as_str)?;
        urlsplit(url).ok()?.hostname()
    }
}

impl HopResolver for ChainResolver<'_> {
    fn resolve(&mut self, guid: &str) -> Lookup<ChainHop> {
        let node_id = if guid == self.own_guid { "local".to_string() } else { guid.to_string() };
        let Some(row) = self.nodes_by_guid.iter().find(|row| row.node_id == node_id).cloned() else {
            return Ok(Err(Reason::new("node_unknown", None, format!("no node {guid} on this panel"))));
        };
        let relay = RelayRegistry::relay(self.db, &node_id)?;
        let Some(relay) = relay.filter(|relay| truthy(relay.get("public_key"))) else {
            return Ok(Err(Reason::new(
                "node_lacks_relay",
                None,
                format!("node {guid} has no relay (update its panel and enable the relay)"),
            )));
        };
        if !truthy(relay.get("enabled")) {
            return Ok(Err(Reason::new("relay_disabled", None, format!("the relay of node {guid} is disabled"))));
        }
        let address = self.address(&node_id, &row).filter(|address| !address.is_empty());
        let (Some(address), true, true) = (address, truthy(relay.get("server_name")), truthy(relay.get("port"))) else {
            return Ok(Err(Reason::new("node_lacks_relay", None, format!("node {guid} has no relay address"))));
        };
        let mut uuids: Vec<Option<String>> = Vec::new();
        for exit_kind in EXITS {
            let mut account = RelayRegistry::account_row(self.db, &node_id, &self.source_guid, exit_kind)?;
            if account.is_none() {
                if !self.issue {
                    uuids.push(None);
                    continue;
                }
                self.registry.issue(self.db, &node_id, &self.source_guid, exit_kind, self.now)?;
                self.issued.insert(node_id.clone());
                account = RelayRegistry::account_row(self.db, &node_id, &self.source_guid, exit_kind)?;
            }
            let email = relay_email(&self.source_guid, exit_kind);
            let confirmed = self.confirmed.confirmed(&node_id, &email).map_err(RoutingFailure::internal)?;
            if !confirmed {
                uuids.push(if exit_kind == "warp" { None } else { Some("pending".into()) });
                continue;
            }
            let secret_id = account.as_ref().map(|row| text(row, "secret_id")).unwrap_or_default();
            uuids.push(Some(self.registry.reveal(self.db, &secret_id, &node_id)?));
        }
        let direct = match uuids[0].clone() {
            Some(uuid) if uuid != "pending" => uuid,
            _ => {
                return Ok(Err(Reason::new(
                    "relay_credential_pending",
                    None,
                    format!("node {guid} has not confirmed this node's relay account yet"),
                )))
            }
        };
        let port = relay.get("port").and_then(Value::as_i64).unwrap_or_default();
        Ok(Ok(ChainHop {
            guid: guid.to_string(),
            address,
            port,
            server_name: text(&relay, "server_name"),
            public_key: text(&relay, "public_key"),
            short_id: relay.get("short_id").and_then(Value::as_str).unwrap_or("").to_string(),
            uuid_direct: direct,
            uuid_warp: uuids[1].clone(),
        }))
    }
}

/// `lane_policies(store, db, node_id, protocol)`: every policy the router runs for the service — its
/// own and the lanes of grants that still have one.
pub fn lane_policies(db: &Conn, node_id: &str, protocol: &str) -> Result<Vec<RoutingPolicy>> {
    let active: Vec<String> = db
        .prepare(
            "SELECT id FROM access_grants WHERE node_id=? AND protocol=? AND routing_lane='own' AND desired_state<>'deleted'",
        )?
        .query_map(params![node_id, protocol], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .map(|id| format!("grant:{id}"))
        .collect();
    Ok(store::lanes_of(db, node_id, protocol)?
        .into_iter()
        .filter(|policy| policy.lane == LANE_SERVICE || active.contains(&policy.lane))
        .collect())
}

/// An audit row of this caller in the open transaction (`audit.record`).
pub(crate) fn audit(db: &Conn, context: &AuditContext, action: &str, target: &str, detail: Value) -> Result<()> {
    let mut record = context.row(action, target);
    record.detail = Some(match detail {
        Value::Object(map) => map,
        _ => Map::new(),
    });
    panel_secrets::audit::record(db, &record)?;
    Ok(())
}

/// `LaneError(409 if exc.code else 502, exc.code or fallback, str(exc))`.
fn lane_refusal(error: AdapterError, fallback: &str) -> RoutingFailure {
    if runtime_failure(&error).is_some() {
        return RoutingFailure::Adapter(error);
    }
    let status = if error.code.is_some() { 409 } else { 502 };
    let code = error.code.clone().filter(|code| !code.is_empty()).unwrap_or_else(|| fallback.to_string());
    RoutingFailure::refused(status, code, error.message)
}

/// Python's `issued["user"]` and `issued["password"]`: a missing key is an internal error;
/// an explicitly present null is passed through to the manager.
fn lane_account(issued: &Value) -> Result<Value> {
    let user = issued.get("user").ok_or_else(|| RoutingFailure::internal("'user'"))?;
    let password = issued.get("password").ok_or_else(|| RoutingFailure::internal("'password'"))?;
    Ok(json!({"user": user, "password": password}))
}

/// A grant's own lane on this node (spec §6.2): the router's account, the manager's handler or
/// slot, a draft policy — and the way back.
#[derive(Clone)]
pub struct LaneService {
    database: Database,
    adapters: Arc<dyn RoutingAdapters>,
    router: Option<Arc<dyn RoutingRouter>>,
    clock: SharedClock,
    /// A linked node's lane travels in its generation (`publisher(db, node_id)`).
    publisher: Option<Arc<dyn GenerationPublisher>>,
}

impl std::fmt::Debug for LaneService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneService").field("router", &self.router.is_some()).finish_non_exhaustive()
    }
}

/// `lane_of(grant_id)`.
pub fn lane_of(grant_id: &str) -> String {
    format!("grant:{grant_id}")
}

/// The service's draft for a new lane: its policy (or an empty one) on the router, the rules
/// without their ids.
fn lane_draft(service_policy: Option<&RoutingPolicy>) -> PolicyInput {
    let mut draft = service_policy.map(PolicyInput::from_policy).unwrap_or_default();
    draft.backend = Some(ROUTER_BACKEND);
    for rule in &mut draft.intent.rules {
        rule.id = None;
    }
    draft
}

fn routing_lane(db: &Conn, grant_id: &str) -> Result<Option<String>> {
    Ok(db
        .query_row("SELECT routing_lane FROM access_grants WHERE id=?", [grant_id], |row| {
            row.get::<_, Option<String>>(0)
        })
        .optional()?
        .flatten())
}

fn lane_grants(db: &Conn, node_id: &str, protocol: &str) -> Result<Vec<(String, String)>> {
    Ok(db
        .prepare(
            "SELECT id, runtime_username FROM access_grants WHERE node_id=? AND protocol=? AND routing_lane='own' \
             AND desired_state<>'deleted' ORDER BY created_at, id",
        )?
        .query_map(params![node_id, protocol], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?)
}

impl LaneService {
    pub fn new(
        database: Database,
        adapters: Arc<dyn RoutingAdapters>,
        router: Option<Arc<dyn RoutingRouter>>,
        clock: SharedClock,
        publisher: Option<Arc<dyn GenerationPublisher>>,
    ) -> Self {
        Self { database, adapters, router, clock, publisher }
    }

    fn now(&self) -> i64 {
        self.clock.now()
    }

    fn grant(db: &Conn, grant_id: &str) -> Result<AccessGrant> {
        match clients_store::grant(db, grant_id) {
            Ok(grant) => Ok(grant),
            Err(panel_clients::ClientsError::NotFound(_)) => {
                Err(RoutingFailure::refused(404, "grant_not_found", "grant not found"))
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn read(&self, grant_id: &str) -> Result<(AccessGrant, Option<String>)> {
        let (database, id) = (self.database.clone(), grant_id.to_string());
        blocking(move || database.with_connection(|db| Ok((Self::grant(db, &id)?, routing_lane(db, &id)?)))).await
    }

    /// `PUT /v1/lanes` to the service's manager with every lane of the service; the router
    /// accounts (`{lane: {user, password}}`) are never stored here.
    async fn push_lanes(&self, node_id: &str, protocol: Protocol, accounts: &Map<String, Value>) -> Result<Value> {
        let (database, node, service) = (self.database.clone(), node_id.to_string(), protocol.as_str().to_string());
        let rows = blocking(move || database.with_connection(|db| lane_grants(db, &node, &service))).await?;
        let mut lanes = Vec::new();
        for (id, username) in rows {
            let lane = lane_of(&id);
            if let Some(upstream) = accounts.get(&lane) {
                lanes.push(json!({"lane": lane, "users": [username], "upstream": upstream}));
            }
        }
        self.adapters.set_lanes(protocol, &Value::Array(lanes)).await.map_err(|error| {
            if runtime_failure(&error).is_some() {
                RoutingFailure::manager(protocol, error)
            } else {
                AdapterFailure(error).into()
            }
        })
    }

    /// `_push_existing`: this lane with its fresh account (`None` when it is leaving), every other
    /// lane of the service re-issued by the router — the manager needs every upstream on every PUT.
    async fn push_existing(
        &self,
        node_id: &str,
        protocol: Protocol,
        lane: &str,
        account: Option<Value>,
    ) -> std::result::Result<Value, LaneFailure> {
        let router = self.router.clone().ok_or_else(|| LaneFailure::Other(RoutingFailure::internal("no router")))?;
        let (database, node, service) = (self.database.clone(), node_id.to_string(), protocol.as_str().to_string());
        let rows = blocking(move || database.with_connection(|db| lane_grants(db, &node, &service))).await?;
        let mut accounts = Map::new();
        if let Some(account) = account {
            accounts.insert(lane.to_string(), account);
        }
        for (id, _) in rows {
            let other = lane_of(&id);
            if !accounts.contains_key(&other) {
                let issued = router.lane_issue(protocol.as_str(), &other).await.map_err(LaneFailure::Adapter)?;
                let account = lane_account(&issued).map_err(LaneFailure::Other)?;
                accounts.insert(other, account);
            }
        }
        self.push_lanes(node_id, protocol, &accounts).await.map_err(LaneFailure::from)
    }

    /// `enable(grant_id, …)`.
    pub async fn enable(&self, grant_id: &str, context: &AuditContext) -> Result<Value> {
        let (grant, current) = self.read(grant_id).await?;
        if grant.protocol == Protocol::Trusttunnel {
            return Err(RoutingFailure::refused(422, "lanes_unsupported", LANES_UNSUPPORTED_TRUSTTUNNEL));
        }
        if !matches!(grant.protocol, Protocol::Naive | Protocol::Mieru) {
            return Err(RoutingFailure::refused(
                422,
                "protocol_out_of_scope",
                format!("{} is outside routing", grant.protocol),
            ));
        }
        let lane = lane_of(grant_id);
        if current.as_deref() == Some("own") {
            return self.view(grant_id).await;
        }
        if grant.node_id != "local" {
            return self.set_remote(grant, "own", context.clone()).await;
        }
        let Some(router) = self.router.clone() else {
            return Err(RoutingFailure::refused(
                409,
                "lane_requires_router",
                "a client lane runs only on the node's Xray-router",
            ));
        };
        // 1. the router mints the lane's account (handed straight to the manager)
        let issued = router
            .lane_issue(grant.protocol.as_str(), &lane)
            .await
            .map_err(|error| lane_refusal(error, "router_unavailable"))?;
        // 2. the manager moves the user into the lane's handler / slot
        let now = self.now();
        self.transaction({
            let id = grant_id.to_string();
            move |db| {
                db.execute("UPDATE access_grants SET routing_lane='own', updated_at=? WHERE id=?", params![now, id])?;
                Ok(())
            }
        })
        .await?;
        let account = lane_account(&issued)?;
        let view = match self.push_existing(&grant.node_id, grant.protocol, &lane, Some(account)).await {
            Ok(view) => view,
            Err(LaneFailure::Adapter(error)) => {
                if runtime_failure(&error).is_some() {
                    return Err(RoutingFailure::Adapter(error));
                }
                self.transaction({
                    let id = grant_id.to_string();
                    move |db| {
                        db.execute("UPDATE access_grants SET routing_lane=NULL WHERE id=?", [id])?;
                        Ok(())
                    }
                })
                .await?;
                let _ = router.lane_forget(grant.protocol.as_str(), &lane).await;
                return Err(lane_refusal(error, "manager_unavailable"));
            }
            Err(LaneFailure::Other(error)) => return Err(error),
        };
        // 3. a draft policy for the lane, copied from the service's
        let now = self.now();
        let (grant_for_tx, view_for_tx, lane_for_tx, context) =
            (grant.clone(), view.clone(), lane.clone(), context.clone());
        self.transaction(move |db| {
            learn_share(db, &grant_for_tx, &view_for_tx, Some(&lane_for_tx), now)?;
            let node = grant_for_tx.node_id.as_str();
            let protocol = grant_for_tx.protocol.as_str();
            let service_policy = store::get(db, node, protocol, LANE_SERVICE)?;
            let draft = lane_draft(service_policy.as_ref());
            if store::get(db, node, protocol, &lane_for_tx)?.is_none() {
                store::upsert(db, node, protocol, &draft, None, now, &lane_for_tx)
                    .map_err(store::StoreError::into_failure)?;
            }
            audit(
                db,
                &context,
                "grant.lane.enable",
                &grant_for_tx.id,
                json!({"node_id": node, "protocol": protocol, "lane": lane_for_tx}),
            )
        })
        .await?;
        let mut answer = match view {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        answer.insert("grant_id".into(), json!(grant_id));
        answer.insert("lane".into(), json!(lane));
        answer.insert("mode".into(), json!("own"));
        Ok(Value::Object(answer))
    }

    /// `disable(grant_id, …)`.
    pub async fn disable(&self, grant_id: &str, context: &AuditContext) -> Result<Value> {
        let (grant, current) = self.read(grant_id).await?;
        let lane = lane_of(grant_id);
        if current.as_deref() != Some("own") {
            return self.view(grant_id).await;
        }
        if grant.node_id != "local" {
            return self.set_remote(grant, "service", context.clone()).await;
        }
        let now = self.now();
        self.transaction({
            let id = grant_id.to_string();
            move |db| {
                db.execute("UPDATE access_grants SET routing_lane=NULL, updated_at=? WHERE id=?", params![now, id])?;
                Ok(())
            }
        })
        .await?;
        let mut view = Value::Object(Map::new());
        if self.router.is_some() {
            match self.push_existing(&grant.node_id, grant.protocol, &lane, None).await {
                Ok(answer) => view = answer,
                Err(LaneFailure::Adapter(error)) => {
                    if runtime_failure(&error).is_some() {
                        return Err(RoutingFailure::Adapter(error));
                    }
                    self.transaction({
                        let id = grant_id.to_string();
                        move |db| {
                            db.execute("UPDATE access_grants SET routing_lane='own' WHERE id=?", [id])?;
                            Ok(())
                        }
                    })
                    .await?;
                    return Err(lane_refusal(error, "manager_unavailable"));
                }
                Err(LaneFailure::Other(error)) => return Err(error),
            }
        }
        let now = self.now();
        let (grant_for_tx, lane_for_tx, context) = (grant.clone(), lane.clone(), context.clone());
        self.transaction(move |db| {
            learn_share(db, &grant_for_tx, &view, None, now)?;
            let node = grant_for_tx.node_id.as_str();
            let protocol = grant_for_tx.protocol.as_str();
            if let Some(policy) = store::get(db, node, protocol, &lane_for_tx)? {
                store::delete(db, &policy.id).map_err(store::StoreError::into_failure)?;
            }
            audit(
                db,
                &context,
                "grant.lane.disable",
                &grant_for_tx.id,
                json!({"node_id": node, "protocol": protocol, "lane": lane_for_tx}),
            )
        })
        .await?;
        if let Some(router) = &self.router {
            let _ = router.lane_forget(grant.protocol.as_str(), &lane).await;
        }
        self.view(grant_id).await
    }

    /// `_set_remote(grant, mode, …)`: a lane on a linked node travels in its next generation; the
    /// node builds the lane itself (the key never leaves it).
    async fn set_remote(&self, grant: AccessGrant, mode: &'static str, context: AuditContext) -> Result<Value> {
        let lane = lane_of(&grant.id);
        let Some(publisher) = self.publisher.clone() else {
            return Err(RoutingFailure::refused(409, "node_not_local", "this panel sets lanes locally only"));
        };
        let (database, node_id) = (self.database.clone(), grant.node_id.clone());
        let identity: Value = blocking(move || {
            database.with_connection(|db| {
                let row: Option<Option<String>> = db
                    .query_row("SELECT identity_json FROM node_links WHERE node_id=?", [&node_id], |row| row.get(0))
                    .optional()?;
                Ok(match row.flatten().filter(|text| !text.is_empty()) {
                    Some(text) => serde_json::from_str(&text)?,
                    None => Value::Object(Map::new()),
                })
            })
        })
        .await?;
        let capable = identity
            .get("capabilities")
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(|item| item == "egress.lanes.v1"));
        if !capable {
            return Err(RoutingFailure::refused(
                422,
                "node_lacks_lanes",
                "the node needs an up-to-date panel and an Xray-router",
            ));
        }
        let now = self.now();
        let lane_for_tx = lane.clone();
        let policy = self
            .transaction(move |db| {
                let node = grant.node_id.as_str();
                let protocol = grant.protocol.as_str();
                if mode == "own" {
                    db.execute(
                        "UPDATE access_grants SET routing_lane='own', updated_at=? WHERE id=?",
                        params![now, grant.id],
                    )?;
                    let service_policy = store::get(db, node, protocol, LANE_SERVICE)?;
                    let draft = lane_draft(service_policy.as_ref());
                    if store::get(db, node, protocol, &lane_for_tx)?.is_none() {
                        store::upsert(db, node, protocol, &draft, None, now, &lane_for_tx)
                            .map_err(store::StoreError::into_failure)?;
                    }
                } else {
                    db.execute(
                        "UPDATE access_grants SET routing_lane=NULL, updated_at=? WHERE id=?",
                        params![now, grant.id],
                    )?;
                    if let Some(policy) = store::get(db, node, protocol, &lane_for_tx)? {
                        store::delete(db, &policy.id).map_err(store::StoreError::into_failure)?;
                    }
                    // The service's section still names the lane (and its chains): the next
                    // generation carries it without them.
                    if let Some(service) = store::get(db, node, protocol, LANE_SERVICE)? {
                        let desired = store::desired_for_node(db, node)?.get(protocol).cloned();
                        let names_lane = desired
                            .as_ref()
                            .and_then(|desired| desired.get("document"))
                            .filter(|document| document.is_object())
                            .and_then(|document| document.get("lanes"))
                            .and_then(Value::as_object)
                            .is_some_and(|lanes| lanes.contains_key(&lane_for_tx));
                        if let (true, Some(Value::Object(mut desired))) = (names_lane, desired) {
                            let document = without_lane(&desired["document"], &lane_for_tx);
                            desired.insert("digest".into(), json!(document_digest(&document)));
                            desired.insert("document".into(), document);
                            store::set_desired(db, &service.id, Some(&Value::Object(desired)), now)?;
                        }
                    }
                }
                let generation = publisher.publish(db, node).map_err(RoutingFailure::internal)?;
                let action = if mode == "own" { "grant.lane.enable" } else { "grant.lane.disable" };
                audit(
                    db,
                    &context,
                    action,
                    &grant.id,
                    json!({"node_id": node, "protocol": protocol, "lane": lane_for_tx, "generation": generation}),
                )?;
                store::get(db, node, protocol, &lane_for_tx)
            })
            .await?;
        Ok(json!({"grant_id": lane.strip_prefix("grant:").unwrap_or_default(),
                  "lane": if mode == "own" { lane.clone() } else { LANE_SERVICE.to_string() },
                  "mode": mode, "pending": true,
                  "policy": policy.map(|policy| json!({"id": policy.id, "revision": policy.revision,
                                                       "state": policy.state.as_str()}))}))
    }

    /// `view(grant_id)`.
    pub async fn view(&self, grant_id: &str) -> Result<Value> {
        let (database, id) = (self.database.clone(), grant_id.to_string());
        blocking(move || {
            database.with_connection(|db| {
                let grant = Self::grant(db, &id)?;
                let current = routing_lane(db, &id)?;
                let lane = lane_of(&id);
                let own = current.as_deref() == Some("own");
                let policy = if own { store::get(db, &grant.node_id, grant.protocol.as_str(), &lane)? } else { None };
                Ok(json!({"grant_id": id, "lane": if own { lane } else { LANE_SERVICE.to_string() },
                          "mode": current.unwrap_or_else(|| "service".into()),
                          "policy": policy.map(|policy| json!({"id": policy.id, "revision": policy.revision,
                                                               "state": policy.state.as_str()}))}))
            })
        })
        .await
    }

    async fn transaction<T, F>(&self, work: F) -> Result<T>
    where
        F: FnOnce(&Conn) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let database = self.database.clone();
        blocking(move || database.transaction(work)).await
    }
}

/// `_learn_share`: a Mieru lane user connects to the slot's port, so the manager's template for the
/// user becomes the grant's `share_template`; leaving the lane returns the service's template.
fn learn_share(db: &Conn, grant: &AccessGrant, view: &Value, lane: Option<&str>, now: i64) -> Result<()> {
    if grant.protocol != Protocol::Mieru {
        return Ok(());
    }
    let mut template = view.get("service_share_template").cloned().unwrap_or(Value::Null);
    if let Some(lane) = lane {
        for entry in view.get("lanes").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
            if entry.get("lane").and_then(Value::as_str) == Some(lane) {
                template = entry
                    .get("share_templates")
                    .and_then(Value::as_object)
                    .and_then(|templates| templates.get(&grant.runtime_username))
                    .cloned()
                    .unwrap_or(Value::Null);
            }
        }
    }
    let mut options = match grant.options.dump() {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    options.insert("share_template".into(), template);
    let typed = match MieruOptions::validate(&Value::Object(options.clone())) {
        Ok(typed) => typed,
        Err(_) => {
            options.insert("share_template".into(), Value::Null);
            MieruOptions::validate(&Value::Object(options))
                .map_err(|error| RoutingFailure::internal(error.to_string()))?
        }
    };
    let json = ProtocolOptions::Mieru(typed).dump_json();
    clients_store::update_grant(db, &grant.id, &clients_store::GrantUpdate::new().options_json(json).at(now))?;
    Ok(())
}

/// An adapter error carried through a [`RoutingFailure`]-typed helper.
struct AdapterFailure(AdapterError);

impl From<AdapterFailure> for RoutingFailure {
    fn from(error: AdapterFailure) -> Self {
        RoutingFailure::Adapter(error.0)
    }
}

/// What `_push_existing` failed with: an adapter's refusal (the caller undoes and answers it), or
/// anything else.
enum LaneFailure {
    Adapter(AdapterError),
    Other(RoutingFailure),
}

impl From<RoutingFailure> for LaneFailure {
    fn from(error: RoutingFailure) -> Self {
        match error {
            RoutingFailure::Adapter(error) => LaneFailure::Adapter(error),
            other => LaneFailure::Other(other),
        }
    }
}

/// The lanes service as the grant lifecycle sees it: a refusal travels as the API error the client
/// routes answer (`LaneError` → `{"detail", "code"}`).
impl panel_clients::lifecycle::GrantLanes for LaneService {
    fn disable<'a>(
        &'a self,
        grant_id: &'a str,
        context: &'a AuditContext,
    ) -> BoxFuture<'a, std::result::Result<(), SeamError>> {
        Box::pin(async move {
            match LaneService::disable(self, grant_id, context).await {
                Ok(_) => Ok(()),
                Err(error) => Err(seam_error(error)),
            }
        })
    }
}

/// A routing failure as a seam error: a refusal is the API error it answers with.
pub fn seam_error(error: RoutingFailure) -> SeamError {
    match error.app_error() {
        Some(answer) => Box::new(answer),
        None => Box::new(InternalSeam(error.to_string())),
    }
}

#[derive(Debug)]
struct InternalSeam(String);

impl std::fmt::Display for InternalSeam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InternalSeam {}

/// `Refusal` as the API error (kept for callers that answer it themselves).
pub fn api_error(refusal: &Refusal) -> ApiError {
    refusal.to_api_error()
}
