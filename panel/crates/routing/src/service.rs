//! Routing policies end to end: targets, preview, save, apply and rollback.
//!
//! Manager I/O never runs inside `BEGIN IMMEDIATE`: the policy is read, the manager is asked,
//! and only then the outcome and its audit row are written in one transaction. A linked panel
//! receives its desired egress section through the fleet publisher in that same transaction.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use panel_clients::AuditContext;
use panel_core::clock::{SharedClock, SystemClock};
use panel_core::db::{row_to_json, Conn, Database};
use panel_core::pyjson;
use panel_core::pytext::urlsplit;
use panel_core::rusqlite::{params, OptionalExtension as _};
use panel_model::protocols::{AdapterError, AppliedDocument, AppliedEgress, EgressMode, EgressTarget, RouterTarget};
use panel_model::routing::document::{attach_document, document_digest, router_direct_intent};
use panel_model::routing::models::{
    backend_for, backends_for, exit_hops, normalise_lane, CompileStatus, Compiled, Intent, PolicyInput, PolicyState,
    Reason, RoutingPolicy, LANES_UNSUPPORTED_AMNEZIAWG, LANES_UNSUPPORTED_TRUSTTUNNEL, LANE_SERVICE, ROUTER_BACKEND,
};
use panel_model::seams::{
    GenerationPublisher, NodeClientProvider, NodeError, ProtocolSwitch, RelayConfirmation, SeamError,
};
use panel_model::{Backend, Protocol};
use panel_nodes::error::NodesError;
use panel_nodes::{registry as nodes, NodeRow};
use panel_protocols::error::runtime_failure;
use serde_json::{json, Map, Value};

use crate::compiler::{self, HopResolver as _};
use crate::error::{blocking, Refusal, Result, RoutingFailure};
use crate::exits::{ExitError, ExitInput, ExitStore};
use crate::lanes::{self, ChainResolver, RelayRegistry};
use crate::runtime::{GeodataAction, RoutingAdapters, RoutingRouter};
use crate::store::{self, ApplyRecord, Mark, StoreError, HISTORY_LIMIT};

pub const GEODATA_REFUSALS: [&str; 4] = ["geodata_invalid", "geodata_corrupt", "geodata_rejected", "geodata_busy"];
pub const PROTOCOLS: [&str; 5] = ["mtproxy", "naive", "mieru", "trusttunnel", "amneziawg"];
/// What an apply failure costs the caller. Every other manager refusal is a conflict.
pub const ERROR_STATUS: [(&str, u16); 3] =
    [("manual_intervention_required", 503), ("manager_unavailable", 502), ("artifact_mismatch", 503)];

fn error_status(code: &str) -> u16 {
    ERROR_STATUS.iter().find_map(|(candidate, status)| (*candidate == code).then_some(*status)).unwrap_or(409)
}

fn adapter_code(error: &AdapterError, fallback: &str) -> String {
    error.code.as_deref().filter(|code| !code.is_empty()).unwrap_or(fallback).to_string()
}

fn adapter_refusal(error: AdapterError, fallback: &str) -> RoutingFailure {
    if runtime_failure(&error).is_some() {
        return RoutingFailure::Adapter(error);
    }
    let code = adapter_code(&error, fallback);
    RoutingFailure::refused(error_status(&code), code, error.message)
}

fn manager_refusal(protocol: Protocol, error: AdapterError, fallback: &str) -> RoutingFailure {
    if runtime_failure(&error).is_some() {
        RoutingFailure::manager(protocol, error)
    } else {
        adapter_refusal(error, fallback)
    }
}

fn object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}

fn strings(value: Option<&Value>) -> impl Iterator<Item = String> + '_ {
    value.and_then(Value::as_array).into_iter().flatten().filter_map(|item| item.as_str().map(str::to_string))
}

fn revision_of(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) if number.as_f64() == Some(0.0) => String::new(),
        Some(Value::Array(items)) if items.is_empty() => String::new(),
        Some(Value::Object(map)) if map.is_empty() => String::new(),
        Some(other) => panel_model::pyrepr::str(other),
    }
}

fn providers(value: Option<&Value>) -> Map<String, Value> {
    object(value)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|(name, entry)| {
                    Some((
                        name.clone(),
                        json!({"reachable": object(Some(entry))?.get("reachable").cloned().unwrap_or(Value::Null)}),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A linked panel's `identity.protocols[p].egress` as the compiler's target. The node reports
/// only the applied digest, so the diff is against that digest alone.
pub fn target_from_identity(protocol: &str, entry: Option<&Map<String, Value>>) -> Option<EgressTarget> {
    let entry = entry?;
    let backend = Backend::from_wire(entry.get("backend")?.as_str()?)?;
    let revision = revision_of(entry.get("revision"));
    let applied = entry.get("applied_digest").and_then(Value::as_str).map(|digest| AppliedDocument {
        revision: revision.clone(),
        digest: digest.to_string(),
        document: Value::Null,
    });
    Some(EgressTarget {
        protocol: protocol.to_string(),
        backend,
        capabilities: strings(entry.get("capabilities")).collect(),
        providers: providers(entry.get("providers")),
        revision,
        applied,
        mode: EgressMode::from_wire(entry.get("mode").and_then(Value::as_str).unwrap_or("custom"))
            .unwrap_or(EgressMode::Custom),
        restart_required: entry.get("restart_required") == Some(&Value::Bool(true)),
        warnings: strings(entry.get("warnings")).collect(),
        runtime_version: None,
        router_attached: entry.get("router_attached") == Some(&Value::Bool(true)),
    })
}

/// A linked panel's `identity.router` as the compiler's router target for one service.
pub fn router_target_from_identity(protocol: &str, router: Option<&Map<String, Value>>) -> Option<RouterTarget> {
    let router = router?;
    if !lanes::truthy(router.get("available")) {
        let reason = router.get("reason").and_then(Value::as_str).unwrap_or("router_unavailable");
        return Some(RouterTarget::unavailable(protocol, reason));
    }
    let services = object(router.get("services"));
    for (service, code) in [
        ("mtproxy", "router_lacks_mtproxy"),
        ("trusttunnel", "router_lacks_trusttunnel"),
        ("amneziawg", "router_lacks_amneziawg"),
    ] {
        if protocol == service && !services.is_some_and(|services| services.contains_key(protocol)) {
            return Some(RouterTarget::unavailable(protocol, code));
        }
    }
    let section = services.and_then(|services| services.get(protocol)).and_then(Value::as_object);
    let revision = revision_of(section.and_then(|section| section.get("revision")));
    let applied = section.and_then(|section| section.get("applied_digest")).and_then(Value::as_str).map(|digest| {
        AppliedDocument { revision: revision.clone(), digest: digest.to_string(), document: Value::Null }
    });
    Some(RouterTarget {
        available: true,
        service: protocol.to_string(),
        capabilities: strings(router.get("capabilities")).collect(),
        providers: providers(router.get("providers")),
        revision,
        applied,
        xray_version: router.get("xray_version").and_then(Value::as_str).map(str::to_string),
        restart_required: true,
        reason: None,
    })
}

/// The ADR-003 gate, normally a closure over the fleet node's managed store.
pub trait CentralManagement: Send + Sync {
    fn master_guid(&self, db: &Conn) -> std::result::Result<Option<String>, SeamError>;
}

impl<F> CentralManagement for F
where
    F: Fn(&Conn) -> std::result::Result<Option<String>, SeamError> + Send + Sync,
{
    fn master_guid(&self, db: &Conn) -> std::result::Result<Option<String>, SeamError> {
        self(db)
    }
}

/// The result of a local apply/rollback or a linked-panel publication.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingOutcome {
    pub policy: RoutingPolicy,
    pub applied: Option<AppliedEgress>,
    pub compiled: Compiled,
}

/// The routing application service. Synchronous methods mirror Python's synchronous methods and
/// are intended for a blocking web worker; async methods move every database section off-runtime.
#[derive(Clone)]
pub struct RoutingService {
    database: Database,
    adapters: Arc<dyn RoutingAdapters>,
    enabled: Arc<dyn ProtocolSwitch>,
    publisher: Option<Arc<dyn GenerationPublisher>>,
    managed: Option<Arc<dyn CentralManagement>>,
    clock: SharedClock,
    router: Option<Arc<dyn RoutingRouter>>,
    relays: Option<RelayRegistry>,
    own_guid: String,
    local_host: String,
    confirmed: Arc<dyn RelayConfirmation>,
    node_client: Option<Arc<dyn NodeClientProvider>>,
}

impl std::fmt::Debug for RoutingService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingService")
            .field("router", &self.router.is_some())
            .field("relays", &self.relays.is_some())
            .field("publisher", &self.publisher.is_some())
            .finish_non_exhaustive()
    }
}

impl RoutingService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database: Database,
        adapters: Arc<dyn RoutingAdapters>,
        enabled: Arc<dyn ProtocolSwitch>,
        publisher: Option<Arc<dyn GenerationPublisher>>,
        managed: Option<Arc<dyn CentralManagement>>,
        clock: SharedClock,
        router: Option<Arc<dyn RoutingRouter>>,
        relays: Option<RelayRegistry>,
        own_guid: impl Into<String>,
        local_host: impl Into<String>,
        confirmed: Arc<dyn RelayConfirmation>,
        node_client: Option<Arc<dyn NodeClientProvider>>,
    ) -> Self {
        Self {
            database,
            adapters,
            enabled,
            publisher,
            managed,
            clock,
            router,
            relays,
            own_guid: own_guid.into(),
            local_host: local_host.into(),
            confirmed,
            node_client,
        }
    }

    /// A local-only service with every protocol enabled and no relay registry.
    pub fn local(database: Database, adapters: Arc<dyn RoutingAdapters>) -> Self {
        Self::new(
            database,
            adapters,
            Arc::new(|_: &str| true),
            None,
            None,
            SystemClock::shared(),
            None,
            None,
            "local",
            "",
            Arc::new(lanes::local_only),
            None,
        )
    }

    fn now(&self) -> i64 {
        self.clock.now()
    }

    async fn read<T, F>(&self, work: F) -> Result<T>
    where
        F: FnOnce(&Self, &Conn) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let this = self.clone();
        blocking(move || this.database.with_connection(|db| work(&this, db))).await
    }

    async fn transaction_async<T, F>(&self, work: F) -> Result<T>
    where
        F: FnOnce(&Self, &Conn) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let this = self.clone();
        blocking(move || this.database.transaction(|db| work(&this, db))).await
    }

    fn master(&self, db: &Conn) -> Result<Option<String>> {
        self.managed
            .as_ref()
            .map(|managed| managed.master_guid(db).map_err(RoutingFailure::internal))
            .transpose()
            .map(Option::flatten)
    }

    fn kind(row: &NodeRow) -> &'static str {
        if row.kind == "local" {
            "local"
        } else if row.link.is_some() {
            "remote"
        } else {
            "v1"
        }
    }

    fn capabilities(row: &NodeRow) -> Vec<String> {
        if Self::kind(row) != "remote" {
            return Vec::new();
        }
        row.link
            .as_ref()
            .and_then(|link| object(link.get("identity")))
            .map(|identity| strings(identity.get("capabilities")).collect())
            .unwrap_or_default()
    }

    fn identity(row: &NodeRow) -> Option<&Map<String, Value>> {
        row.link.as_ref().and_then(|link| object(link.get("identity")))
    }

    fn protocol(protocol: &str) -> Result<Protocol> {
        if backend_for(protocol).is_none() {
            return Err(RoutingFailure::refused(
                422,
                "protocol_out_of_scope",
                format!("{protocol} is outside routing"),
            ));
        }
        Protocol::from_wire(protocol).ok_or_else(|| RoutingFailure::internal("routing protocol disappeared"))
    }

    fn node(db: &Conn, node_id: &str) -> Result<NodeRow> {
        match nodes::row(db, node_id) {
            Ok(row) => Ok(row),
            Err(NodesError::NotFound(_)) => Err(RoutingFailure::refused(404, "node_not_found", "node not found")),
            Err(error) => Err(error.into()),
        }
    }

    fn lane(lane: Option<&str>) -> Result<String> {
        normalise_lane(lane).map_err(|error| RoutingFailure::refused(422, "lane_invalid", error.0))
    }

    async fn local_target(&self, protocol: Protocol) -> std::result::Result<Option<EgressTarget>, AdapterError> {
        let Some(adapter) = self.adapters.adapter(protocol) else { return Ok(None) };
        if !self.enabled.enabled(protocol.as_str()) {
            return Ok(None);
        }
        adapter.egress_target().await
    }

    /// `(target, node has egress.v1)`.
    async fn target(
        &self,
        row: &NodeRow,
        protocol: Protocol,
    ) -> std::result::Result<(Option<EgressTarget>, bool), AdapterError> {
        match Self::kind(row) {
            "local" => Ok((self.local_target(protocol).await?, true)),
            "remote" => {
                let identity = Self::identity(row);
                let capabilities = Self::capabilities(row);
                if !capabilities.iter().any(|capability| capability == "egress.v1") {
                    return Ok((None, false));
                }
                for (service, capability, code, message) in [
                    (
                        Protocol::Mtproxy,
                        "egress.mtproxy.v1",
                        "node_lacks_mtproxy_egress",
                        "the node must be updated to v1.1 to route MTProxy",
                    ),
                    (
                        Protocol::Trusttunnel,
                        "egress.trusttunnel.v1",
                        "node_lacks_trusttunnel_egress",
                        "the node must be updated to v1.6 to route TrustTunnel",
                    ),
                    (
                        Protocol::Amneziawg,
                        "egress.amneziawg.v1",
                        "node_lacks_amneziawg_egress",
                        "the node must be updated to v3.0.0 to route AmneziaWG",
                    ),
                ] {
                    if protocol == service && !capabilities.iter().any(|item| item == capability) {
                        return Err(AdapterError::with_code(message, code));
                    }
                }
                let entry = identity
                    .and_then(|identity| object(identity.get("protocols")))
                    .and_then(|protocols| protocols.get(protocol.as_str()))
                    .and_then(Value::as_object)
                    .and_then(|section| object(section.get("egress")));
                Ok((target_from_identity(protocol.as_str(), entry), true))
            }
            _ => Ok((None, false)),
        }
    }

    async fn router_target(&self, row: &NodeRow, protocol: Protocol) -> Option<RouterTarget> {
        match Self::kind(row) {
            "local" => match &self.router {
                Some(router) => Some(router.target(protocol.as_str()).await),
                None => None,
            },
            "remote" => {
                if !Self::capabilities(row).iter().any(|capability| capability == "egress.router.v1") {
                    return None;
                }
                router_target_from_identity(
                    protocol.as_str(),
                    Self::identity(row).and_then(|identity| object(identity.get("router"))),
                )
            }
            _ => None,
        }
    }

    fn router_view(router: Option<&RouterTarget>, target: Option<&EgressTarget>) -> Option<Map<String, Value>> {
        let router = router?;
        Some(
            json!({"available": router.available, "attached": target.is_some_and(|target| target.router_attached),
                   "xray_version": router.xray_version, "restart_required": router.restart_required,
                   "reason": router.reason})
            .as_object()
            .expect("literal object")
            .clone(),
        )
    }

    async fn refresh_local_relay(&self) -> Result<()> {
        let (Some(router), Some(_)) = (&self.router, &self.relays) else { return Ok(()) };
        let view = router.relay().await;
        if !view.as_ref().is_some_and(Value::is_object) {
            return Ok(());
        }
        let now = self.now();
        self.transaction_async(move |this, db| {
            RelayRegistry::record(db, "local", view.as_ref(), now)?;
            let _ = this;
            Ok(())
        })
        .await
    }

    fn policy_view(policy: &RoutingPolicy) -> Map<String, Value> {
        let mut rules = Map::new();
        for action in ["block", "direct", "egress"] {
            let count =
                policy.intent.rules.iter().filter(|rule| rule.enabled && rule.action.as_str() == action).count();
            rules.insert(action.into(), json!(count));
        }
        json!({"id": policy.id, "lane": policy.lane, "revision": policy.revision, "state": policy.state.as_str(),
               "backend": policy.backend.as_str(), "applied_revision": policy.applied_revision,
               "applied_current": policy.applied_current(), "matches_node": null, "last_error": policy.last_error,
               "default_action": policy.intent.default_action.as_str(), "default_egress": policy.intent.default_egress,
               "rules": rules, "node_exits": policy.intent.node_exits()})
        .as_object()
        .expect("literal object")
        .clone()
    }

    fn relay_view(&self, db: &Conn, node_id: &str) -> Result<Option<Map<String, Value>>> {
        if self.relays.is_none() {
            return Ok(None);
        }
        Ok(Some(
            match RelayRegistry::relay(db, node_id)? {
                None => json!({"enabled": false, "port": null, "pending": false, "known": false}),
                Some(relay) => json!({"enabled": lanes::truthy(relay.get("enabled")), "port": relay.get("port"),
                                  "pending": !lanes::truthy(relay.get("public_key")), "known": true}),
            }
            .as_object()
            .expect("literal object")
            .clone(),
        ))
    }

    fn fleet_exits(&self, db: &Conn, rows: &[NodeRow]) -> Result<Vec<Map<String, Value>>> {
        if self.relays.is_none() {
            return Ok(Vec::new());
        }
        let mut exits = Vec::new();
        for row in rows {
            let Some(relay) = RelayRegistry::relay(db, &row.node_id)? else { continue };
            let guid = if row.node_id == "local" { &self.own_guid } else { &row.node_id };
            let online = row.node_id == "local"
                || row.link.as_ref().and_then(|link| link.get("status")).and_then(Value::as_str) == Some("online");
            exits.push(
                json!({"kind": "node", "node_id": row.node_id, "guid": guid, "display_name": row.display_name,
                       "enabled": lanes::truthy(relay.get("enabled")), "port": relay.get("port"), "online": online,
                       "pending": !lanes::truthy(relay.get("public_key")), "via": ["direct", "warp"],
                       "exit": format!("node:{guid}")})
                .as_object()
                .expect("literal object")
                .clone(),
            );
        }
        Ok(exits)
    }

    /// Nodes × protocols, with each service policy, grant lanes, relay and available exits.
    pub async fn targets(&self) -> Result<Vec<Map<String, Value>>> {
        self.refresh_local_relay().await?;
        struct Snapshot {
            rows: Vec<NodeRow>,
            policies: Vec<RoutingPolicy>,
            lanes: BTreeMap<(String, String), Vec<Map<String, Value>>>,
            master: Option<String>,
            exits: Vec<Map<String, Value>>,
            relays: BTreeMap<String, Option<Map<String, Value>>>,
            custom: BTreeMap<String, Vec<Map<String, Value>>>,
        }
        let snapshot = self
            .read(|this, db| {
                let rows: Vec<NodeRow> = nodes::rows(db)?.into_iter().filter(|row| Self::kind(row) != "v1").collect();
                let policies = store::list(db, None)?;
                let service: BTreeMap<(String, String), RoutingPolicy> = policies
                    .iter()
                    .filter(|policy| policy.lane == LANE_SERVICE)
                    .map(|policy| ((policy.node_id.clone(), policy.protocol.as_str().to_string()), policy.clone()))
                    .collect();
                let mut grants = BTreeMap::new();
                let mut statement = db.prepare(
                    "SELECT g.id, g.runtime_username, g.client_id, c.display_name FROM access_grants g \
                     JOIN clients c ON c.id=g.client_id WHERE g.routing_lane='own'",
                )?;
                for grant in statement.query_map([], row_to_json)?.collect::<panel_core::rusqlite::Result<Vec<_>>>()? {
                    grants.insert(grant.get("id").and_then(Value::as_str).unwrap_or_default().to_string(), grant);
                }
                let mut lane_views: BTreeMap<(String, String), Vec<Map<String, Value>>> = BTreeMap::new();
                for policy in policies.iter().filter(|policy| policy.lane != LANE_SERVICE) {
                    let grant = grants.get(policy.lane.strip_prefix("grant:").unwrap_or_default()).map(|grant| {
                        json!({"id": grant.get("id"), "runtime_username": grant.get("runtime_username"),
                               "client_id": grant.get("client_id"), "client_name": grant.get("display_name")})
                    });
                    let mut view = Self::policy_view(policy);
                    view.insert("grant".into(), grant.unwrap_or(Value::Null));
                    lane_views
                        .entry((policy.node_id.clone(), policy.protocol.as_str().to_string()))
                        .or_default()
                        .push(view);
                }
                let master = this.master(db)?;
                let exits = this.fleet_exits(db, &rows)?;
                let mut relays = BTreeMap::new();
                let mut custom = BTreeMap::new();
                for row in &rows {
                    relays.insert(row.node_id.clone(), this.relay_view(db, &row.node_id)?);
                    if this.relays.is_some() {
                        custom.insert(row.node_id.clone(), ExitStore::list(db, &row.node_id)?);
                    }
                }
                Ok(Snapshot {
                    rows,
                    policies: service.into_values().collect(),
                    lanes: lane_views,
                    master,
                    exits,
                    relays,
                    custom,
                })
            })
            .await?;
        let policies: BTreeMap<(String, String), RoutingPolicy> = snapshot
            .policies
            .into_iter()
            .map(|policy| ((policy.node_id.clone(), policy.protocol.as_str().to_string()), policy))
            .collect();
        let mut items = Vec::new();
        for row in &snapshot.rows {
            for protocol in PROTOCOLS {
                let kind = Self::kind(row);
                let key = (row.node_id.clone(), protocol.to_string());
                let policy = policies.get(&key).cloned();
                let mut item = json!({"node_id": row.node_id, "node_name": row.display_name, "kind": kind,
                    "protocol": protocol, "backend": null, "capabilities": [], "providers": {},
                    "egress_v1": kind == "local", "mode": null, "policy": policy.as_ref().map(Self::policy_view),
                    "reason": null, "router": null, "lanes": snapshot.lanes.get(&key).cloned().unwrap_or_default(),
                    "exits": snapshot.exits.iter().filter(|exit| exit.get("node_id").and_then(Value::as_str) != Some(row.node_id.as_str())).cloned().collect::<Vec<_>>(),
                    "custom_exits": snapshot.custom.get(&row.node_id).cloned().unwrap_or_default(),
                    "relay": snapshot.relays.get(&row.node_id).cloned().flatten().map_or(Value::Null, Value::Object)})
                    .as_object()
                    .expect("literal object")
                    .clone();
                let Ok(typed) = Self::protocol(protocol) else {
                    item.insert("reason".into(), json!("protocol_out_of_scope"));
                    items.push(item);
                    continue;
                };
                if kind == "remote"
                    && row.link.as_ref().and_then(|link| link.get("status")).and_then(Value::as_str) != Some("online")
                {
                    item.insert("reason".into(), json!("node_offline"));
                } else if kind == "local" && snapshot.master.is_some() {
                    item.insert("reason".into(), json!("managed_by_central"));
                }
                let (target, egress_v1) = match self.target(row, typed).await {
                    Ok(found) => found,
                    Err(error) => {
                        if runtime_failure(&error).is_some() {
                            return Err(RoutingFailure::manager(typed, error));
                        }
                        item.insert("reason".into(), json!(adapter_code(&error, "manager_unavailable")));
                        (None, true)
                    }
                };
                item.insert("egress_v1".into(), json!(egress_v1));
                let router = self.router_target(row, typed).await;
                item.insert(
                    "router".into(),
                    Self::router_view(router.as_ref(), target.as_ref()).map_or(Value::Null, Value::Object),
                );
                match target.as_ref() {
                    None => {
                        if item.get("reason") == Some(&Value::Null) {
                            item.insert(
                                "reason".into(),
                                json!(if egress_v1 { "protocol_disabled_on_node" } else { "node_lacks_egress_v1" }),
                            );
                        }
                    }
                    Some(target) if target.router_attached => {
                        item.insert("backend".into(), json!(ROUTER_BACKEND.as_str()));
                        item.insert("mode".into(), json!(target.mode.as_str()));
                        item.insert("providers".into(), Value::Object(target.providers.clone()));
                        item.insert(
                            "capabilities".into(),
                            json!(router
                                .as_ref()
                                .filter(|router| router.available)
                                .map(|router| router.capabilities.iter().cloned().collect::<Vec<_>>())
                                .unwrap_or_default()),
                        );
                        if item.get("reason") == Some(&Value::Null)
                            && router.as_ref().is_none_or(|router| !router.available)
                        {
                            item.insert(
                                "reason".into(),
                                json!(router
                                    .as_ref()
                                    .and_then(|router| router.reason.as_deref())
                                    .unwrap_or("router_unavailable")),
                            );
                        }
                    }
                    Some(target) => {
                        item.insert("backend".into(), json!(target.backend.as_str()));
                        item.insert(
                            "capabilities".into(),
                            json!(target.capabilities.iter().cloned().collect::<Vec<_>>()),
                        );
                        item.insert("providers".into(), Value::Object(target.providers.clone()));
                        item.insert("mode".into(), json!(target.mode.as_str()));
                    }
                }
                if let Some(policy) = policy {
                    let matches = self.matches_node(&policy, row, target.as_ref(), egress_v1, router.as_ref()).await?;
                    if let Some(Value::Object(view)) = item.get_mut("policy") {
                        view.insert("matches_node".into(), matches.map_or(Value::Null, Value::Bool));
                    }
                }
                items.push(item);
            }
        }
        Ok(items)
    }

    async fn matches_node(
        &self,
        policy: &RoutingPolicy,
        row: &NodeRow,
        target: Option<&EgressTarget>,
        egress_v1: bool,
        router: Option<&RouterTarget>,
    ) -> Result<Option<bool>> {
        if target.is_none() {
            return Ok(None);
        }
        let policy = policy.clone();
        let row = row.clone();
        let target = target.cloned();
        let router = router.cloned();
        let compiled = self
            .read(move |this, db| this.compile(db, &policy, &row, target.as_ref(), egress_v1, router.as_ref(), false))
            .await?;
        Ok((compiled.status == CompileStatus::Supported).then_some(compiled.diff.is_empty()))
    }

    async fn target_item(&self, node_id: &str, protocol: &str) -> Result<Map<String, Value>> {
        self.targets()
            .await?
            .into_iter()
            .find(|item| {
                item.get("node_id").and_then(Value::as_str) == Some(node_id)
                    && item.get("protocol").and_then(Value::as_str) == Some(protocol)
            })
            .ok_or_else(|| RoutingFailure::refused(404, "node_not_found", "node not found"))
    }

    // -- custom exits -----------------------------------------------------------------

    fn exit_store(&self) -> Result<ExitStore> {
        self.relays.as_ref().map(|relays| ExitStore::new(relays.secrets.clone())).ok_or_else(|| {
            RoutingFailure::refused(
                409,
                "secret_store_disabled",
                "custom exits need the secret store (PANEL_MASTER_KEY_FILE)",
            )
        })
    }

    fn audit(db: &Conn, context: &AuditContext, action: &str, target: &str, detail: Value) -> Result<()> {
        let mut record = context.row(action, target);
        record.detail = Some(detail.as_object().cloned().unwrap_or_default());
        panel_secrets::audit::record(db, &record)?;
        Ok(())
    }

    fn exit_audit(db: &Conn, context: &AuditContext, action: &str, exit_id: &str, detail: Value) -> Result<()> {
        Self::audit(db, context, &format!("routing.exit.{action}"), exit_id, detail)
    }

    pub fn list_exits(&self, node_id: &str) -> Result<Vec<Map<String, Value>>> {
        let _ = self.exit_store()?;
        self.database.with_connection(|db| {
            Self::node(db, node_id)?;
            let mut items = ExitStore::list(db, node_id)?;
            for item in &mut items {
                let id = item.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
                item.insert("used_by".into(), Value::Array(ExitStore::usage(db, &id)?));
            }
            Ok(items)
        })
    }

    pub fn create_exit(
        &self,
        node_id: &str,
        data: &ExitInput,
        context: &AuditContext,
        imported: bool,
    ) -> Result<Map<String, Value>> {
        let store = self.exit_store()?;
        let now = self.now();
        self.database.transaction(|db| {
            let row = Self::node(db, node_id)?;
            if Self::kind(&row) == "v1" {
                return Err(RoutingFailure::refused(409, "node_lacks_egress_v1", "the node must be updated"));
            }
            let created = store.create(db, node_id, data, now).map_err(exit_failure)?;
            Self::exit_audit(
                db,
                context,
                if imported { "import" } else { "create" },
                created.get("id").and_then(Value::as_str).unwrap_or_default(),
                json!({"node_id": node_id, "name": created.get("name"), "protocol": created.get("protocol"),
                       "address": created.get("address"), "port": created.get("port")}),
            )?;
            Ok(created)
        })
    }

    pub fn import_exit(
        &self,
        node_id: &str,
        link: &str,
        name: Option<&str>,
        context: &AuditContext,
    ) -> Result<Map<String, Value>> {
        let mut data = crate::exits::parse_share_link(link)
            .map_err(|error| RoutingFailure::refused(422, "exit_link_invalid", error))?;
        if let Some(name) = name.filter(|name| !name.is_empty()) {
            data.name = panel_core::pytext::strip(name).chars().take(48).collect();
        }
        self.create_exit(node_id, &data, context, true)
    }

    pub fn update_exit(&self, exit_id: &str, data: &ExitInput, context: &AuditContext) -> Result<Map<String, Value>> {
        let store = self.exit_store()?;
        let now = self.now();
        self.database.transaction(|db| {
            let updated = store.update(db, exit_id, data, now).map_err(exit_failure)?;
            Self::exit_audit(
                db,
                context,
                "update",
                exit_id,
                json!({"node_id": updated.get("node_id"), "name": updated.get("name"),
                       "credential_rotated": data.credential_bytes().is_some()}),
            )?;
            for usage in ExitStore::usage(db, exit_id)? {
                if let Some(policy_id) = usage.get("policy_id").and_then(Value::as_str) {
                    Self::unsettle(db, policy_id, now)?;
                }
            }
            Ok(updated)
        })
    }

    fn unsettle(db: &Conn, policy_id: &str, now: i64) -> Result<()> {
        let policy = store::get_by_id(db, policy_id).map_err(StoreError::into_failure)?;
        store::mark(
            db,
            policy_id,
            PolicyState::Draft,
            Mark { applied_revision: policy.applied_revision, applied_digest: policy.applied_digest, last_error: None },
            now,
        )
    }

    pub fn exit_action(&self, exit_id: &str, action: &str, context: &AuditContext) -> Result<Map<String, Value>> {
        let store = self.exit_store()?;
        let now = self.now();
        self.database.transaction(|db| {
            let found = ExitStore::get(db, exit_id)?
                .ok_or_else(|| RoutingFailure::refused(404, "exit_not_found", "exit not found"))?;
            if action == "delete" {
                if !ExitStore::usage(db, exit_id)?.is_empty() {
                    return Err(RoutingFailure::refused(409, "exit_in_use", "policies still leave through this exit"));
                }
                store.delete(db, exit_id).map_err(exit_failure)?;
                Self::exit_audit(
                    db,
                    context,
                    "delete",
                    exit_id,
                    json!({"node_id": found.get("node_id"), "name": found.get("name")}),
                )?;
                return Ok(json!({"ok": true}).as_object().expect("literal object").clone());
            }
            let updated = ExitStore::set_enabled(db, exit_id, action == "enable", now).map_err(exit_failure)?;
            Self::exit_audit(
                db,
                context,
                action,
                exit_id,
                json!({"node_id": found.get("node_id"), "name": found.get("name")}),
            )?;
            if action == "disable" {
                for usage in ExitStore::usage(db, exit_id)? {
                    if let Some(policy_id) = usage.get("policy_id").and_then(Value::as_str) {
                        Self::unsettle(db, policy_id, now)?;
                    }
                }
            }
            Ok(updated)
        })
    }

    pub fn exit_usage(&self, exit_id: &str) -> Result<Vec<Value>> {
        let _ = self.exit_store()?;
        self.database.with_connection(|db| ExitStore::usage(db, exit_id))
    }

    pub async fn test_exit(&self, exit_id: &str, context: &AuditContext) -> Result<Map<String, Value>> {
        let _ = self.exit_store()?;
        let exit_id_owned = exit_id.to_string();
        let (found, row, spec) = self
            .read(move |_this, db| {
                let found = ExitStore::get(db, &exit_id_owned)?
                    .ok_or_else(|| RoutingFailure::refused(404, "exit_not_found", "exit not found"))?;
                let node_id = found.get("node_id").and_then(Value::as_str).unwrap_or_default().to_string();
                let row = Self::node(db, &node_id)?;
                let store = ExitStore::new(_this.relays.as_ref().expect("checked above").secrets.clone());
                let spec = match store.spec(db, &exit_id_owned, &node_id)? {
                    Ok(Value::Object(spec)) => spec,
                    Ok(_) => return Err(RoutingFailure::internal("exit spec is not an object")),
                    Err(reason) => return Err(RoutingFailure::Refused(Refusal::new(409, reason.code, reason.message))),
                };
                Ok((found, row, spec))
            })
            .await?;
        let node_id = found.get("node_id").and_then(Value::as_str).unwrap_or_default().to_string();
        let result = match Self::kind(&row) {
            "local" => {
                let router = self.router.as_ref().ok_or_else(|| {
                    RoutingFailure::refused(404, "router_unavailable", "this server runs no Xray-router")
                })?;
                router.exit_test(&Value::Object(spec.clone())).await.map_err(|error| {
                    if runtime_failure(&error).is_some() {
                        return RoutingFailure::Adapter(error);
                    }
                    let code = adapter_code(&error, "router_unavailable");
                    let status = if code == "egress_invalid" { 422 } else { 502 };
                    RoutingFailure::refused(status, code, error.message)
                })?
            }
            "remote" => {
                let provider = self
                    .node_client
                    .as_ref()
                    .ok_or_else(|| RoutingFailure::refused(404, "router_unavailable", "no client for linked panels"))?;
                if !Self::capabilities(&row).iter().any(|capability| capability == "geodata.v1") {
                    return Err(RoutingFailure::refused(
                        409,
                        "node_lacks_exits",
                        "the node's panel does not test exits yet (update it)",
                    ));
                }
                let client = provider.client_for(&node_id).map_err(RoutingFailure::internal)?;
                Value::Object(client.exit_test(&spec).await.map_err(node_failure)?)
            }
            _ => return Err(RoutingFailure::refused(404, "router_unavailable", "this node has no Xray-router")),
        };
        let Value::Object(mut result) = result else {
            return Err(RoutingFailure::internal("exit test answer is not an object"));
        };
        let now = self.now();
        let audit_result = result.clone();
        let exit_id_owned = exit_id.to_string();
        let context = context.clone();
        self.transaction_async(move |_this, db| {
            ExitStore::record_test(db, &exit_id_owned, &audit_result, now)?;
            Self::exit_audit(
                db,
                &context,
                "test",
                &exit_id_owned,
                json!({"node_id": found.get("node_id"), "name": found.get("name"),
                       "ok": audit_result.get("ok"), "code": audit_result.get("code")}),
            )?;
            Ok(())
        })
        .await?;
        result.insert("at".into(), json!(now));
        Ok(result)
    }

    // -- geodata ----------------------------------------------------------------------

    pub async fn geodata(
        &self,
        node_id: &str,
        action: &str,
        body: Option<&Map<String, Value>>,
        context: Option<&AuditContext>,
    ) -> Result<Map<String, Value>> {
        let node = node_id.to_string();
        let row = self.read(move |_this, db| Self::node(db, &node)).await?;
        let result = match Self::kind(&row) {
            "local" => {
                let router = self.router.as_ref().ok_or_else(|| {
                    RoutingFailure::refused(404, "router_unavailable", "this server runs no Xray-router")
                })?;
                let parsed = GeodataAction::parse(action)
                    .ok_or_else(|| RoutingFailure::internal(format!("unknown geodata action {action}")))?;
                let body_value = body.cloned().map(Value::Object);
                router.geodata(parsed, body_value.as_ref()).await.map_err(|error| {
                    if runtime_failure(&error).is_some() {
                        return RoutingFailure::Adapter(error);
                    }
                    let code = adapter_code(&error, "router_unavailable");
                    let status = if GEODATA_REFUSALS.contains(&code.as_str()) { 422 } else { 502 };
                    RoutingFailure::refused(status, code, error.message)
                })?
            }
            "remote" => {
                let provider = self
                    .node_client
                    .as_ref()
                    .ok_or_else(|| RoutingFailure::refused(404, "router_unavailable", "no client for linked panels"))?;
                if !Self::capabilities(&row).iter().any(|capability| capability == "geodata.v1") {
                    return Err(RoutingFailure::refused(
                        409,
                        "node_lacks_geodata",
                        "the node's panel does not manage geodata yet (update it)",
                    ));
                }
                let client = provider.client_for(node_id).map_err(RoutingFailure::internal)?;
                Value::Object(client.geodata(action, body).await.map_err(node_failure)?)
            }
            _ => return Err(RoutingFailure::refused(404, "router_unavailable", "this node has no Xray-router")),
        };
        let Value::Object(result) = result else {
            return Err(RoutingFailure::internal("geodata answer is not an object"));
        };
        if ["settings", "update", "restore"].contains(&action) {
            if let Some(context) = context {
                let context = context.clone();
                let mut detail = json!({"node_id": node_id}).as_object().expect("literal object").clone();
                if action == "settings" {
                    if let Some(body) = body {
                        detail.extend(body.clone());
                    }
                } else {
                    for key in ["origin", "version", "changed"] {
                        detail.insert(key.into(), result.get(key).cloned().unwrap_or(Value::Null));
                    }
                }
                let node = node_id.to_string();
                let action = action.to_string();
                self.transaction_async(move |_this, db| {
                    Self::audit(db, &context, &format!("routing.geodata.{action}"), &node, Value::Object(detail))
                })
                .await?;
            }
        }
        Ok(result)
    }

    // -- policies ---------------------------------------------------------------------

    fn policy(&self, db: &Conn, node_id: &str, protocol: &str, lane: Option<&str>) -> Result<RoutingPolicy> {
        Self::protocol(protocol)?;
        Self::node(db, node_id)?;
        let lane = Self::lane(lane)?;
        for (service, detail) in
            [(Protocol::Trusttunnel, LANES_UNSUPPORTED_TRUSTTUNNEL), (Protocol::Amneziawg, LANES_UNSUPPORTED_AMNEZIAWG)]
        {
            if Self::protocol(protocol)? == service && lane != LANE_SERVICE {
                return Err(RoutingFailure::refused(422, "lanes_unsupported", detail));
            }
        }
        store::get(db, node_id, protocol, &lane)?.ok_or_else(|| {
            RoutingFailure::refused(404, "policy_not_found", "no routing policy for this node, protocol and lane")
        })
    }

    pub fn get(&self, node_id: &str, protocol: &str, lane: &str) -> Result<RoutingPolicy> {
        self.database.with_connection(|db| self.policy(db, node_id, protocol, Some(lane)))
    }

    pub fn history(&self, node_id: &str, protocol: &str, lane: &str) -> Result<Vec<Map<String, Value>>> {
        self.database.with_connection(|db| {
            let policy = self.policy(db, node_id, protocol, Some(lane))?;
            store::history(db, &policy.id, HISTORY_LIMIT)
        })
    }

    fn lane_allowed(db: &Conn, node_id: &str, protocol: Protocol, lane: &str) -> Result<()> {
        if lane == LANE_SERVICE {
            return Ok(());
        }
        if protocol == Protocol::Trusttunnel {
            return Err(RoutingFailure::refused(422, "lanes_unsupported", LANES_UNSUPPORTED_TRUSTTUNNEL));
        }
        if protocol == Protocol::Amneziawg {
            return Err(RoutingFailure::refused(422, "lanes_unsupported", LANES_UNSUPPORTED_AMNEZIAWG));
        }
        let routing_lane = db
            .query_row(
                "SELECT routing_lane FROM access_grants WHERE id=? AND node_id=? AND protocol=?",
                params![lane.strip_prefix("grant:").unwrap_or_default(), node_id, protocol.as_str()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        if routing_lane.as_deref() != Some("own") {
            return Err(RoutingFailure::refused(404, "lane_not_found", "the grant has no lane on this node"));
        }
        Ok(())
    }

    pub fn save(
        &self,
        node_id: &str,
        protocol: &str,
        draft: &PolicyInput,
        expected_revision: Option<i64>,
        lane: &str,
        context: &AuditContext,
    ) -> Result<RoutingPolicy> {
        let typed = Self::protocol(protocol)?;
        let lane = Self::lane(Some(lane))?;
        let now = self.now();
        self.database.transaction(|db| {
            Self::node(db, node_id)?;
            Self::lane_allowed(db, node_id, typed, &lane)?;
            let policy =
                store::upsert(db, node_id, protocol, draft, expected_revision, now, &lane).map_err(save_failure)?;
            Self::audit(
                db,
                context,
                "routing.policy.update",
                &policy.id,
                json!({"node_id": node_id, "protocol": protocol, "lane": lane, "revision": policy.revision,
                       "rules": policy.intent.rules.len(), "default_action": policy.intent.default_action.as_str(),
                       "node_exits": policy.intent.node_exits()}),
            )?;
            Ok(policy)
        })
    }

    pub fn delete(&self, node_id: &str, protocol: &str, lane: &str, context: &AuditContext) -> Result<()> {
        self.database.transaction(|db| {
            let policy = self.policy(db, node_id, protocol, Some(lane))?;
            if policy.lane != LANE_SERVICE {
                return Err(RoutingFailure::refused(
                    409,
                    "lane_policy",
                    "a lane's policy is removed by taking the lane away from its grant",
                ));
            }
            let reset = document_digest(&compiler::direct_document(policy.backend));
            if policy.applied_digest.as_ref().is_some_and(|digest| digest != &reset) {
                return Err(RoutingFailure::refused(
                    409,
                    "policy_applied",
                    "reset the policy to direct and apply it before deleting",
                ));
            }
            store::delete(db, &policy.id).map_err(StoreError::into_failure)?;
            Self::audit(
                db,
                context,
                "routing.policy.delete",
                &policy.id,
                json!({"node_id": node_id, "protocol": protocol, "revision": policy.revision}),
            )
        })
    }

    pub fn explain_destination(
        &self,
        node_id: &str,
        protocol: &str,
        host: &str,
        port: i64,
        lane: &str,
    ) -> Result<Map<String, Value>> {
        self.database.with_connection(|db| {
            let policy = self.policy(db, node_id, protocol, Some(lane))?;
            let names: BTreeMap<String, String> =
                nodes::rows(db)?.into_iter().map(|row| (row.node_id, row.display_name)).collect();
            let mut result = compiler::explain(&policy, host, port);
            let hops = result.get("hops").and_then(Value::as_array).cloned().unwrap_or_default();
            let hop_names = hops
                .iter()
                .map(|guid| {
                    let guid = guid.as_str().unwrap_or_default();
                    let node = if guid == self.own_guid { "local" } else { guid };
                    json!(names.get(node).cloned().unwrap_or_else(|| guid.to_string()))
                })
                .collect::<Vec<_>>();
            result.insert("hop_names".into(), Value::Array(hop_names));
            Ok(result)
        })
    }

    // -- preview and apply ------------------------------------------------------------

    fn unavailable(policy: &RoutingPolicy, error: AdapterError) -> Compiled {
        let mut compiled = Compiled::new(CompileStatus::Unsupported);
        compiled.backend = Some(policy.backend.as_str().to_string());
        compiled.reasons.push(Reason::new(adapter_code(&error, "manager_unavailable"), None, error.message));
        compiled
    }

    fn own_guids(&self, row: &NodeRow) -> Vec<String> {
        if row.node_id == "local" {
            vec![row.node_id.clone(), self.own_guid.clone()]
        } else {
            vec![row.node_id.clone()]
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compile(
        &self,
        db: &Conn,
        policy: &RoutingPolicy,
        row: &NodeRow,
        target: Option<&EgressTarget>,
        egress_v1: bool,
        router: Option<&RouterTarget>,
        issue: bool,
    ) -> Result<Compiled> {
        let others: Vec<RoutingPolicy> = lanes::lane_policies(db, &policy.node_id, policy.protocol.as_str())?
            .into_iter()
            .filter(|other| other.id != policy.id)
            .collect();
        let nodes = if self.relays.is_some() { nodes::rows(db)? } else { Vec::new() };
        let source_guid = if row.node_id == "local" { self.own_guid.clone() } else { row.node_id.clone() };
        let mut resolver = self.relays.as_ref().map(|relays| ChainResolver {
            db,
            registry: relays,
            source_guid,
            nodes_by_guid: nodes,
            own_guid: self.own_guid.clone(),
            local_host: self.local_host.clone(),
            confirmed: self.confirmed.clone(),
            issue,
            now: self.now(),
            issued: BTreeSet::new(),
        });
        let exit_store = self.relays.as_ref().map(|relays| ExitStore::new(relays.secrets.clone()));
        let mut exit_lookup = |exit_id: &str| {
            exit_store.as_ref().expect("exit lookup only when the store exists").spec(db, exit_id, &policy.node_id)
        };
        compiler::compile(
            policy,
            target,
            compiler::Options {
                old_node: !egress_v1,
                router,
                lanes: &others,
                chains: resolver.as_mut().map(|resolver| resolver as &mut dyn compiler::HopResolver),
                own_guids: self.own_guids(row),
                exits: exit_store.as_ref().map(|_| &mut exit_lookup as &mut dyn FnMut(&str) -> compiler::Lookup<Value>),
            },
        )
    }

    pub async fn preview(
        &self,
        node_id: &str,
        protocol: &str,
        draft: Option<PolicyInput>,
        lane: &str,
    ) -> Result<Compiled> {
        let typed = Self::protocol(protocol)?;
        let lane = Self::lane(Some(lane))?;
        let requested_lane = lane.clone();
        let node = node_id.to_string();
        let protocol_name = protocol.to_string();
        let (row, stored) = self
            .read(move |_this, db| {
                let row = Self::node(db, &node)?;
                let stored = store::get(db, &node, &protocol_name, &lane)?;
                Ok((row, stored))
            })
            .await?;
        let policy = match draft {
            None => stored.ok_or_else(|| {
                RoutingFailure::refused(404, "policy_not_found", "no routing policy for this node, protocol and lane")
            })?,
            Some(draft) => {
                if draft.backend.is_some_and(|backend| !backends_for(protocol).contains(&backend)) {
                    return Err(RoutingFailure::refused(
                        422,
                        "backend_mismatch",
                        format!("{protocol} cannot run on {}", draft.backend.expect("checked").as_str()),
                    ));
                }
                let backend = draft
                    .backend
                    .or_else(|| stored.as_ref().map(|stored| stored.backend))
                    .or_else(|| backend_for(protocol))
                    .expect("protocol checked");
                RoutingPolicy {
                    intent: draft.intent,
                    id: stored.as_ref().map(|stored| stored.id.clone()).unwrap_or_else(|| "draft".into()),
                    node_id: node_id.to_string(),
                    protocol: typed,
                    lane: stored.as_ref().map(|stored| stored.lane.clone()).unwrap_or(requested_lane),
                    backend,
                    revision: stored.as_ref().map(|stored| stored.revision).unwrap_or(1),
                    state: stored.as_ref().map(|stored| stored.state).unwrap_or(PolicyState::Draft),
                    applied_revision: stored.as_ref().and_then(|stored| stored.applied_revision),
                    applied_digest: stored.as_ref().and_then(|stored| stored.applied_digest.clone()),
                    applied_at: stored.as_ref().and_then(|stored| stored.applied_at),
                    last_error: stored.as_ref().and_then(|stored| stored.last_error.clone()),
                    created_at: stored.as_ref().map(|stored| stored.created_at).unwrap_or_default(),
                    updated_at: stored.as_ref().map(|stored| stored.updated_at).unwrap_or_default(),
                }
            }
        };
        let (target, egress_v1) = match self.target(&row, typed).await {
            Ok(found) => found,
            Err(error) if runtime_failure(&error).is_some() => return Err(RoutingFailure::manager(typed, error)),
            Err(error) => return Ok(Self::unavailable(&policy, error)),
        };
        let router = self.router_target(&row, typed).await;
        self.read(move |this, db| this.compile(db, &policy, &row, target.as_ref(), egress_v1, router.as_ref(), false))
            .await
    }

    fn operation_id(policy: &RoutingPolicy) -> String {
        format!("routing:{}:{}", policy.id, policy.revision)
    }

    #[allow(clippy::too_many_arguments)]
    async fn record(
        &self,
        policy: RoutingPolicy,
        compiled: Compiled,
        outcome: &'static str,
        applied: Option<AppliedEgress>,
        error: Option<String>,
        context: AuditContext,
        action: &'static str,
    ) -> Result<RoutingPolicy> {
        let now = self.now();
        self.transaction_async(move |_this, db| {
            let mut detail = Map::new();
            match outcome {
                "applied" => {
                    let applied = applied.as_ref().expect("applied outcome carries its answer");
                    store::mark(
                        db,
                        &policy.id,
                        PolicyState::Applied,
                        Mark {
                            applied_revision: Some(policy.revision),
                            applied_digest: compiled.digest.clone(),
                            last_error: None,
                        },
                        now,
                    )?;
                    if compiled.document.as_ref().and_then(|document| document.get("schema")) == Some(&json!(2)) {
                        for other in lanes::lane_policies(db, &policy.node_id, policy.protocol.as_str())? {
                            if other.id != policy.id {
                                store::mark(
                                    db,
                                    &other.id,
                                    PolicyState::Applied,
                                    Mark {
                                        applied_revision: Some(other.revision),
                                        applied_digest: compiled.digest.clone(),
                                        last_error: None,
                                    },
                                    now,
                                )?;
                            }
                        }
                    }
                    detail.insert("manager_revision".into(), json!(applied.revision));
                    detail.insert("readback_sha256".into(), json!(applied.readback_sha256));
                    detail.insert("replayed".into(), json!(applied.replayed));
                }
                "rolled_back" => {
                    let applied = applied.as_ref().expect("rollback outcome carries its answer");
                    let previous = store::last_applied(db, &policy.id)?;
                    let revision = previous
                        .filter(|previous| {
                            previous.get("digest").cloned().unwrap_or(Value::Null)
                                == applied.digest.as_ref().map_or(Value::Null, |digest| json!(digest))
                        })
                        .and_then(|previous| previous.get("revision").and_then(Value::as_i64));
                    store::mark(
                        db,
                        &policy.id,
                        PolicyState::RolledBack,
                        Mark { applied_revision: revision, applied_digest: applied.digest.clone(), last_error: None },
                        now,
                    )?;
                    detail.insert("manager_revision".into(), json!(applied.revision));
                    detail.insert("to_revision".into(), json!(revision));
                }
                _ => {
                    store::mark(
                        db,
                        &policy.id,
                        PolicyState::Failed,
                        Mark { applied_revision: None, applied_digest: None, last_error: error.clone() },
                        now,
                    )?;
                    detail.insert("error".into(), json!(error));
                }
            }
            let digest = match applied.as_ref() {
                Some(applied) => applied.digest.as_deref(),
                None => compiled.digest.as_deref(),
            };
            let document = (outcome == "applied").then_some(compiled.document.as_ref()).flatten();
            let mut record = ApplyRecord::new(policy.revision, digest, policy.backend.as_str(), outcome);
            record.detail = Some(pyjson::sorted(&Value::Object(detail.clone())));
            record.actor = &context.actor.username;
            record.runtime_version = compiled.runtime_version.as_deref();
            record.document = document;
            store::record_apply(db, &policy.id, &record, now)?;
            let mut audit =
                json!({"node_id": policy.node_id, "protocol": policy.protocol.as_str(), "lane": policy.lane,
                                   "revision": policy.revision, "outcome": outcome, "digest": compiled.digest})
                .as_object()
                .expect("literal object")
                .clone();
            audit.extend(detail);
            Self::audit(db, &context, action, &policy.id, Value::Object(audit))?;
            store::get_by_id(db, &policy.id).map_err(StoreError::into_failure)
        })
        .await
    }

    // -- attach / detach --------------------------------------------------------------

    async fn attachment_context(
        &self,
        node_id: &str,
        protocol: Protocol,
    ) -> Result<(NodeRow, Option<RoutingPolicy>, EgressTarget, RouterTarget)> {
        let node = node_id.to_string();
        let service = protocol.as_str().to_string();
        let (row, policy, master) = self
            .read(move |this, db| {
                let row = Self::node(db, &node)?;
                let policy = store::get(db, &node, &service, LANE_SERVICE)?;
                let master = this.master(db)?;
                Ok((row, policy, master))
            })
            .await?;
        if Self::kind(&row) == "local" && master.is_some() {
            return Err(RoutingFailure::refused(
                409,
                "managed_by_central",
                "a central panel manages this node's egress",
            ));
        }
        if Self::kind(&row) == "v1" {
            return Err(RoutingFailure::refused(
                409,
                "node_lacks_egress_v1",
                "the node's panel does not support egress policies — update it",
            ));
        }
        let (target, egress_v1) = self
            .target(&row, protocol)
            .await
            .map_err(|error| manager_refusal(protocol, error, "manager_unavailable"))?;
        if !egress_v1 {
            return Err(RoutingFailure::refused(
                409,
                "node_lacks_egress_v1",
                "the node's panel does not support egress policies — update it",
            ));
        }
        let target = target.ok_or_else(|| {
            RoutingFailure::refused(422, "protocol_disabled_on_node", format!("{protocol} reports no egress target"))
        })?;
        let router = self.router_target(&row, protocol).await;
        match router {
            Some(router) if router.available => Ok((row, policy, target, router)),
            router => {
                let code = router.and_then(|router| router.reason).unwrap_or_else(|| "router_unavailable".into());
                Err(RoutingFailure::refused(error_status(&code), code, "the node has no Xray-router that answers"))
            }
        }
    }

    fn stamp(&self) -> String {
        ((self.clock.time() * 1000.0) as i64).to_string()
    }

    #[allow(clippy::too_many_arguments)]
    async fn retarget(
        &self,
        node_id: &str,
        protocol: Protocol,
        policy: Option<RoutingPolicy>,
        backend: Backend,
        action: &'static str,
        context: AuditContext,
        mut detail: Map<String, Value>,
    ) -> Result<RoutingPolicy> {
        let node = node_id.to_string();
        self.transaction_async(move |_this, db| {
            let now = _this.now();
            let moved = policy.as_ref().is_none_or(|policy| policy.backend != backend);
            let mut policy = match policy {
                None => store::upsert(
                    db,
                    &node,
                    protocol.as_str(),
                    &PolicyInput { intent: Intent::default(), backend: Some(backend) },
                    None,
                    now,
                    LANE_SERVICE,
                )
                .map_err(StoreError::into_failure)?,
                Some(policy) if policy.backend != backend => {
                    store::retarget(db, &policy.id, backend, now).map_err(StoreError::into_failure)?
                }
                Some(policy) => policy,
            };
            if moved {
                store::mark(
                    db,
                    &policy.id,
                    PolicyState::Draft,
                    Mark {
                        applied_revision: None,
                        applied_digest: Some(document_digest(&compiler::direct_document(backend))),
                        last_error: None,
                    },
                    now,
                )?;
                policy = store::get_by_id(db, &policy.id).map_err(StoreError::into_failure)?;
            }
            let mut audit = json!({"node_id": node, "protocol": protocol.as_str(), "backend": backend.as_str(),
                                   "revision": policy.revision})
            .as_object()
            .expect("literal object")
            .clone();
            audit.append(&mut detail);
            Self::audit(db, &context, action, &policy.id, Value::Object(audit))?;
            Ok(policy)
        })
        .await
    }

    pub async fn attach(&self, node_id: &str, protocol: &str, context: &AuditContext) -> Result<Map<String, Value>> {
        let typed = Self::protocol(protocol)?;
        let (row, policy, target, router) = self.attachment_context(node_id, typed).await?;
        let provider = target.providers.get("router").ok_or_else(|| {
            RoutingFailure::refused(
                409,
                "router_unavailable",
                format!("the {protocol} manager knows no router ingress"),
            )
        })?;
        if provider.get("reachable") == Some(&Value::Bool(false)) {
            return Err(RoutingFailure::refused(
                409,
                "router_unreachable",
                format!("the router ingress does not answer the {protocol} manager"),
            ));
        }
        if policy.as_ref().is_some_and(|policy| {
            policy.backend != ROUTER_BACKEND
                && policy
                    .applied_digest
                    .as_ref()
                    .is_some_and(|digest| digest != &document_digest(&compiler::direct_document(policy.backend)))
        }) {
            return Err(RoutingFailure::refused(
                409,
                "policy_applied",
                "reset the native policy to direct and apply it before attaching",
            ));
        }
        if Self::kind(&row) != "local" {
            return self.attach_remote(node_id, typed, policy, context.clone()).await;
        }
        let stamp = self.stamp();
        let result = async {
            if !target.router_attached {
                let direct = router_direct_intent();
                if router.applied.as_ref().is_none_or(|applied| applied.document != direct) {
                    self.router
                        .as_ref()
                        .expect("available local router")
                        .apply(
                            protocol,
                            &direct,
                            &router.revision,
                            &format!("routing:attach:{protocol}:{stamp}:router"),
                        )
                        .await
                        .map_err(|error| adapter_refusal(error, "manager_unavailable"))?;
                }
                let document = attach_document(protocol).expect("routing protocol attaches");
                let adapter = self.adapters.adapter(typed).expect("target implies adapter");
                adapter
                    .apply_egress(
                        document.as_object().expect("attach document is an object"),
                        &target.revision,
                        &format!("routing:attach:{protocol}:{stamp}:native"),
                    )
                    .await
                    .map_err(|error| manager_refusal(typed, error, "manager_unavailable"))?;
            }
            Ok::<(), RoutingFailure>(())
        }
        .await;
        result?;
        self.retarget(
            node_id,
            typed,
            policy,
            ROUTER_BACKEND,
            "routing.target.attach",
            context.clone(),
            json!({"outcome": "attached"}).as_object().expect("literal object").clone(),
        )
        .await?;
        self.target_item(node_id, protocol).await
    }

    pub async fn detach(&self, node_id: &str, protocol: &str, context: &AuditContext) -> Result<Map<String, Value>> {
        let typed = Self::protocol(protocol)?;
        let (row, policy, target, router) = self.attachment_context(node_id, typed).await?;
        let native = backend_for(protocol).expect("protocol checked");
        if Self::kind(&row) != "local" {
            return self.detach_remote(node_id, typed, policy, context.clone()).await;
        }
        let stamp = self.stamp();
        let result = async {
            if target.router_attached {
                let document = compiler::direct_document(native);
                let adapter = self.adapters.adapter(typed).expect("target implies adapter");
                adapter
                    .apply_egress(
                        document.as_object().expect("direct document is an object"),
                        &target.revision,
                        &format!("routing:detach:{protocol}:{stamp}:native"),
                    )
                    .await
                    .map_err(|error| manager_refusal(typed, error, "manager_unavailable"))?;
            }
            let direct = router_direct_intent();
            if router.applied.as_ref().is_none_or(|applied| applied.document != direct) {
                self.router
                    .as_ref()
                    .expect("available local router")
                    .apply(protocol, &direct, &router.revision, &format!("routing:detach:{protocol}:{stamp}:router"))
                    .await
                    .map_err(|error| adapter_refusal(error, "manager_unavailable"))?;
            }
            Ok::<(), RoutingFailure>(())
        }
        .await;
        result?;
        self.retarget(
            node_id,
            typed,
            policy,
            native,
            "routing.target.detach",
            context.clone(),
            json!({"outcome": "detached"}).as_object().expect("literal object").clone(),
        )
        .await?;
        self.target_item(node_id, protocol).await
    }

    async fn retargeted(
        &self,
        node_id: &str,
        protocol: Protocol,
        policy: Option<RoutingPolicy>,
        backend: Backend,
    ) -> Result<RoutingPolicy> {
        let node = node_id.to_string();
        self.transaction_async(move |_this, db| {
            let now = _this.now();
            match policy {
                None => store::upsert(
                    db,
                    &node,
                    protocol.as_str(),
                    &PolicyInput { intent: Intent::default(), backend: Some(backend) },
                    None,
                    now,
                    LANE_SERVICE,
                )
                .map_err(StoreError::into_failure),
                Some(policy) if policy.backend != backend => {
                    store::retarget(db, &policy.id, backend, now).map_err(StoreError::into_failure)
                }
                Some(policy) => Ok(policy),
            }
        })
        .await
    }

    async fn attach_remote(
        &self,
        node_id: &str,
        protocol: Protocol,
        policy: Option<RoutingPolicy>,
        context: AuditContext,
    ) -> Result<Map<String, Value>> {
        let policy = self.retargeted(node_id, protocol, policy, ROUTER_BACKEND).await?;
        let intent = router_direct_intent();
        let desired = json!({"backend": ROUTER_BACKEND.as_str(), "policy_id": policy.id,
            "policy_revision": policy.revision, "document": intent, "digest": document_digest(&intent),
            "companion": attach_document(protocol.as_str()), "passthrough": true});
        self.publish_desired(
            policy,
            desired,
            "routing.target.attach",
            json!({"backend": ROUTER_BACKEND.as_str(), "outcome": "applying"})
                .as_object()
                .expect("literal object")
                .clone(),
            context,
        )
        .await?;
        self.target_item(node_id, protocol.as_str()).await
    }

    async fn detach_remote(
        &self,
        node_id: &str,
        protocol: Protocol,
        policy: Option<RoutingPolicy>,
        context: AuditContext,
    ) -> Result<Map<String, Value>> {
        let native = backend_for(protocol.as_str()).expect("protocol checked");
        let policy = self.retargeted(node_id, protocol, policy, native).await?;
        let document = compiler::direct_document(native);
        let desired = json!({"backend": native.as_str(), "policy_id": policy.id, "policy_revision": policy.revision,
            "document": document, "digest": document_digest(&document), "companion": router_direct_intent(),
            "passthrough": true});
        self.publish_desired(
            policy,
            desired,
            "routing.target.detach",
            json!({"backend": native.as_str(), "outcome": "applying"}).as_object().expect("literal object").clone(),
            context,
        )
        .await?;
        self.target_item(node_id, protocol.as_str()).await
    }

    async fn for_change(
        &self,
        node_id: &str,
        protocol: &str,
        expected_revision: i64,
        lane: &str,
    ) -> Result<(RoutingPolicy, NodeRow)> {
        let node = node_id.to_string();
        let protocol = protocol.to_string();
        let lane = lane.to_string();
        let (policy, row, master) = self
            .read(move |this, db| {
                let policy = this.policy(db, &node, &protocol, Some(lane.as_str()))?;
                let row = Self::node(db, &node)?;
                let master = this.master(db)?;
                Ok((policy, row, master))
            })
            .await?;
        if expected_revision != policy.revision {
            return Err(RoutingFailure::refused(
                409,
                "policy_conflict",
                format!("policy revision is {}", policy.revision),
            ));
        }
        if Self::kind(&row) == "local" && master.is_some() {
            return Err(RoutingFailure::refused(
                409,
                "managed_by_central",
                "a central panel manages this node's egress",
            ));
        }
        Ok((policy, row))
    }

    async fn deliver_relay_accounts(&self, issued: BTreeSet<String>) -> Result<()> {
        for node_id in issued {
            if node_id == "local" {
                if let Some(router) = &self.router {
                    let accounts = self
                        .read(|_this, db| _this.relays.as_ref().expect("issued implies registry").accounts(db, "local"))
                        .await?;
                    router.relay_set_accounts(&accounts).await.map_err(RoutingFailure::Adapter)?;
                }
            } else if self.publisher.is_some() {
                self.transaction_async(move |_this, db| {
                    _this
                        .publisher
                        .as_ref()
                        .expect("checked")
                        .publish(db, &node_id)
                        .map_err(RoutingFailure::internal)?;
                    Ok(())
                })
                .await?;
            }
        }
        Ok(())
    }

    pub async fn apply(
        &self,
        node_id: &str,
        protocol: &str,
        expected_revision: i64,
        lane: &str,
        context: &AuditContext,
    ) -> Result<RoutingOutcome> {
        let typed = Self::protocol(protocol)?;
        let (policy, row) = self.for_change(node_id, protocol, expected_revision, lane).await?;
        let (target, egress_v1) =
            self.target(&row, typed).await.map_err(|error| manager_refusal(typed, error, "manager_unavailable"))?;
        let router = self.router_target(&row, typed).await;
        let other_lanes = self.other_lanes(&policy).await?;
        if !policy.intent.node_exits().is_empty()
            || other_lanes.iter().any(|other| !other.intent.node_exits().is_empty())
        {
            let values: BTreeSet<String> = policy
                .intent
                .node_exits()
                .into_iter()
                .chain(other_lanes.iter().flat_map(|other| other.intent.node_exits()))
                .collect();
            let row_for_issue = row.clone();
            let issued = self
                .transaction_async(move |this, db| {
                    let nodes = if this.relays.is_some() { nodes::rows(db)? } else { Vec::new() };
                    let source_guid = if row_for_issue.node_id == "local" {
                        this.own_guid.clone()
                    } else {
                        row_for_issue.node_id.clone()
                    };
                    let mut resolver = this.relays.as_ref().map(|relays| ChainResolver {
                        db,
                        registry: relays,
                        source_guid,
                        nodes_by_guid: nodes,
                        own_guid: this.own_guid.clone(),
                        local_host: this.local_host.clone(),
                        confirmed: this.confirmed.clone(),
                        issue: true,
                        now: this.now(),
                        issued: BTreeSet::new(),
                    });
                    if let Some(resolver) = resolver.as_mut() {
                        for value in values {
                            for guid in exit_hops(Some(&value)).0 {
                                let _ = resolver.resolve(&guid)?;
                            }
                        }
                    }
                    Ok(resolver.map(|resolver| resolver.issued).unwrap_or_default())
                })
                .await?;
            self.deliver_relay_accounts(issued).await?;
        }
        let policy_for_compile = policy.clone();
        let row_for_compile = row.clone();
        let target_for_compile = target.clone();
        let router_for_compile = router.clone();
        let compiled = self
            .read(move |this, db| {
                this.compile(
                    db,
                    &policy_for_compile,
                    &row_for_compile,
                    target_for_compile.as_ref(),
                    egress_v1,
                    router_for_compile.as_ref(),
                    false,
                )
            })
            .await?;
        if compiled.status != CompileStatus::Supported {
            if compiled.reasons.iter().any(|reason| reason.code == "not_attached") {
                return Err(RoutingFailure::Refused(
                    Refusal::new(409, "not_attached", format!("{protocol} is not attached to the node's Xray-router"))
                        .with_compiled(compiled),
                ));
            }
            if Self::kind(&row) == "remote" && router.is_none() && policy.backend == ROUTER_BACKEND {
                return Err(RoutingFailure::Refused(
                    Refusal::new(
                        422,
                        "node_lacks_router",
                        "the node has no Xray-router — update its panel and install the router",
                    )
                    .with_compiled(compiled),
                ));
            }
            return Err(RoutingFailure::Refused(
                Refusal::new(422, "unsupported", "the policy cannot be enforced on this node").with_compiled(compiled),
            ));
        }
        if Self::kind(&row) != "local" {
            if compiled.document.as_ref().and_then(|document| document.get("schema")) == Some(&json!(2))
                && !Self::capabilities(&row).iter().any(|capability| capability == "egress.lanes.v1")
            {
                return Err(RoutingFailure::Refused(
                    Refusal::new(
                        422,
                        "node_lacks_lanes",
                        "the node's panel does not support lanes and chains — update it",
                    )
                    .with_compiled(compiled),
                ));
            }
            return self.apply_remote(policy, compiled, context.clone()).await;
        }
        let applied = async {
            if policy.backend == ROUTER_BACKEND {
                let manager = self.router.as_ref().expect("supported router policy implies router");
                let target = router.as_ref().expect("supported router policy implies router target");
                let document = compiled.document.as_ref().expect("supported compilation has a document");
                manager.plan(protocol, document, &target.revision).await?;
                manager.apply(protocol, document, &target.revision, &Self::operation_id(&policy)).await
            } else {
                let adapter = self.adapters.adapter(typed).expect("supported native policy implies adapter");
                let document = compiled
                    .document
                    .as_ref()
                    .and_then(Value::as_object)
                    .expect("supported native document is an object");
                let target = target.as_ref().expect("supported native policy implies target");
                adapter.plan_egress(document, &target.revision).await?;
                adapter.apply_egress(document, &target.revision, &Self::operation_id(&policy)).await
            }
        }
        .await;
        let applied = match applied {
            Ok(applied) => applied,
            Err(error) => {
                if runtime_failure(&error).is_some() {
                    return Err(if policy.backend == ROUTER_BACKEND {
                        RoutingFailure::Adapter(error)
                    } else {
                        RoutingFailure::manager(typed, error)
                    });
                }
                let code = adapter_code(&error, "manager_unavailable");
                self.record(
                    policy.clone(),
                    compiled.clone(),
                    "failed",
                    None,
                    Some(code.clone()),
                    context.clone(),
                    "routing.policy.apply",
                )
                .await?;
                return Err(adapter_refusal(error, "manager_unavailable"));
            }
        };
        let updated = self
            .record(
                policy,
                compiled.clone(),
                "applied",
                Some(applied.clone()),
                None,
                context.clone(),
                "routing.policy.apply",
            )
            .await?;
        Ok(RoutingOutcome { policy: updated, applied: Some(applied), compiled })
    }

    async fn publish_desired(
        &self,
        policy: RoutingPolicy,
        desired: Value,
        action: &'static str,
        mut detail: Map<String, Value>,
        context: AuditContext,
    ) -> Result<RoutingPolicy> {
        if self.publisher.is_none() {
            return Err(RoutingFailure::refused(409, "node_not_local", "this panel applies routing locally only"));
        }
        let now = self.now();
        self.transaction_async(move |this, db| {
            let holder = if policy.lane == LANE_SERVICE {
                policy.id.clone()
            } else {
                store::get(db, &policy.node_id, policy.protocol.as_str(), LANE_SERVICE)?
                    .ok_or_else(|| {
                        RoutingFailure::refused(409, "lane_not_attached", "the service has no policy on this node")
                    })?
                    .id
            };
            store::set_desired(db, &holder, Some(&desired), now)?;
            store::mark(db, &policy.id, PolicyState::Applying, Mark::default(), now)?;
            if action == "routing.policy.rollback" {
                let mut record = ApplyRecord::new(
                    policy.revision,
                    desired.get("digest").and_then(Value::as_str),
                    policy.backend.as_str(),
                    "rolled_back",
                );
                record.detail = Some(pyjson::sorted(&Value::Object(detail.clone())));
                record.actor = &context.actor.username;
                store::record_apply(db, &policy.id, &record, now)?;
            }
            let generation = this
                .publisher
                .as_ref()
                .expect("checked")
                .publish(db, &policy.node_id)
                .map_err(RoutingFailure::internal)?;
            let mut audit = json!({"node_id": policy.node_id, "protocol": policy.protocol.as_str(),
                                   "revision": policy.revision, "outcome": "applying", "generation": generation})
            .as_object()
            .expect("literal object")
            .clone();
            audit.append(&mut detail);
            Self::audit(db, &context, action, &policy.id, Value::Object(audit))?;
            store::get_by_id(db, &policy.id).map_err(StoreError::into_failure)
        })
        .await
    }

    async fn apply_remote(
        &self,
        policy: RoutingPolicy,
        compiled: Compiled,
        context: AuditContext,
    ) -> Result<RoutingOutcome> {
        let mut desired = json!({"backend": policy.backend.as_str(), "policy_id": policy.id,
            "policy_revision": policy.revision, "document": compiled.document, "digest": compiled.digest});
        if let Some(attach) = &compiled.attach {
            desired["companion"] = attach.clone();
        }
        let updated = self
            .publish_desired(
                policy,
                desired,
                "routing.policy.apply",
                json!({"digest": compiled.digest}).as_object().expect("literal object").clone(),
                context,
            )
            .await?;
        Ok(RoutingOutcome { policy: updated, applied: None, compiled })
    }

    async fn rollback_remote(&self, policy: RoutingPolicy, context: AuditContext) -> Result<RoutingOutcome> {
        let id = policy.id.clone();
        let previous = self.read(move |_this, db| store::last_applied(db, &id)).await?;
        let previous = previous.filter(|previous| previous.get("document").is_some_and(|document| !document.is_null()));
        let Some(previous) = previous else {
            return Err(RoutingFailure::refused(
                409,
                "egress_no_previous",
                "no previous applied document to return to",
            ));
        };
        let revision = previous.get("revision").and_then(Value::as_i64).unwrap_or_default();
        let digest = previous.get("digest").and_then(Value::as_str).unwrap_or_default().to_string();
        let document = previous.get("document").cloned().unwrap_or(Value::Null);
        let mut desired = json!({"backend": policy.backend.as_str(), "policy_id": policy.id,
                                 "policy_revision": revision, "document": document, "digest": digest});
        if policy.backend == ROUTER_BACKEND {
            desired["companion"] = attach_document(policy.protocol.as_str()).expect("routing protocol attaches");
        }
        let updated = self
            .publish_desired(
                policy.clone(),
                desired,
                "routing.policy.rollback",
                json!({"to_revision": revision, "digest": digest}).as_object().expect("literal object").clone(),
                context,
            )
            .await?;
        let mut compiled = Compiled::new(CompileStatus::Supported);
        compiled.backend = Some(policy.backend.as_str().to_string());
        compiled.digest = Some(digest);
        compiled.document = Some(document);
        Ok(RoutingOutcome { policy: updated, applied: None, compiled })
    }

    async fn other_lanes(&self, policy: &RoutingPolicy) -> Result<Vec<RoutingPolicy>> {
        let policy = policy.clone();
        self.read(move |_this, db| {
            Ok(lanes::lane_policies(db, &policy.node_id, policy.protocol.as_str())?
                .into_iter()
                .filter(|other| other.id != policy.id)
                .collect())
        })
        .await
    }

    // -- relay ------------------------------------------------------------------------

    pub async fn relay_enable(&self, node_id: &str, port: i64, context: &AuditContext) -> Result<Map<String, Value>> {
        if self.relays.is_none() {
            return Err(RoutingFailure::refused(409, "relay_unavailable", "this panel keeps no relay registry"));
        }
        let node = node_id.to_string();
        let row = self.read(move |_this, db| Self::node(db, &node)).await?;
        if Self::kind(&row) == "v1" {
            return Err(RoutingFailure::refused(422, "node_lacks_relay", "a v1 node runs no relay"));
        }
        if Self::kind(&row) == "remote" {
            return self.relay_enable_remote(node_id, &row, port, context.clone()).await;
        }
        let router = self
            .router
            .as_ref()
            .ok_or_else(|| RoutingFailure::refused(409, "router_unavailable", "this node runs no Xray-router"))?;
        let view = router
            .relay_enable(&self.local_host, port)
            .await
            .map_err(|error| adapter_refusal(error, "router_unavailable"))?;
        let now = self.now();
        let audit_view = view.clone();
        let node = node_id.to_string();
        let context = context.clone();
        self.transaction_async(move |_this, db| {
            RelayRegistry::record(db, "local", Some(&view), now)?;
            Self::audit(
                db,
                &context,
                "routing.relay.enable",
                &node,
                json!({"port": view.get("port"), "server_name": view.get("server_name")}),
            )
        })
        .await?;
        let mut result = json!({"node_id": node_id, "pending": false}).as_object().expect("literal object").clone();
        for key in ["enabled", "port", "server_name", "public_key", "short_ids", "accounts"] {
            result.insert(key.into(), audit_view.get(key).cloned().unwrap_or(Value::Null));
        }
        Ok(result)
    }

    async fn relay_enable_remote(
        &self,
        node_id: &str,
        row: &NodeRow,
        port: i64,
        context: AuditContext,
    ) -> Result<Map<String, Value>> {
        if !Self::capabilities(row).iter().any(|capability| capability == "relay.v1") {
            return Err(RoutingFailure::refused(
                422,
                "node_lacks_relay",
                "the node needs an up-to-date panel and an Xray-router",
            ));
        }
        if self.publisher.is_none() {
            return Err(RoutingFailure::refused(409, "node_not_local", "this panel applies routing locally only"));
        }
        let panel_url =
            row.link.as_ref().and_then(|link| link.get("panel_url")).and_then(Value::as_str).unwrap_or_default();
        let server_name = urlsplit(panel_url).ok().and_then(|url| url.hostname()).filter(|host| !host.is_empty());
        let Some(server_name) = server_name else {
            return Err(RoutingFailure::refused(409, "node_lacks_relay", "the node's panel address is unknown"));
        };
        let now = self.now();
        let node = node_id.to_string();
        let server_name_for_tx = server_name.clone();
        let (relay, accounts) = self
            .transaction_async(move |this, db| {
                RelayRegistry::desire(db, &node, true, port, &server_name_for_tx, now)?;
                let generation =
                    this.publisher.as_ref().expect("checked").publish(db, &node).map_err(RoutingFailure::internal)?;
                let relay = RelayRegistry::relay(db, &node)?.expect("desire creates relay");
                let accounts = RelayRegistry::peers(db, &node)?.len();
                Self::audit(
                    db,
                    &context,
                    "routing.relay.enable",
                    &node,
                    json!({"port": port, "server_name": server_name_for_tx, "generation": generation}),
                )?;
                Ok((relay, accounts))
            })
            .await?;
        Ok(json!({"node_id": node_id, "enabled": true, "port": port, "server_name": server_name,
            "public_key": if lanes::truthy(relay.get("public_key")) { relay.get("public_key").cloned().unwrap_or(Value::Null) } else { Value::Null },
            "short_ids": if lanes::truthy(relay.get("short_id")) { vec![relay.get("short_id").cloned().unwrap_or(Value::Null)] } else { Vec::new() },
            "accounts": accounts, "pending": !lanes::truthy(relay.get("public_key"))})
            .as_object()
            .expect("literal object")
            .clone())
    }

    pub async fn relay_rotate(&self, node_id: &str, context: &AuditContext) -> Result<Map<String, Value>> {
        if self.relays.is_none() {
            return Err(RoutingFailure::refused(409, "relay_unavailable", "this panel keeps no relay registry"));
        }
        let now = self.now();
        let node = node_id.to_string();
        let context = context.clone();
        let (count, accounts) = self
            .transaction_async(move |this, db| {
                Self::node(db, &node)?;
                let count = this.relays.as_ref().expect("checked").rotate(db, &node, now)?;
                let accounts = if node == "local" {
                    Some(this.relays.as_ref().expect("checked").accounts(db, &node)?)
                } else {
                    None
                };
                Self::audit(db, &context, "routing.relay.rotate", &node, json!({"accounts": count}))?;
                Ok((count, accounts))
            })
            .await?;
        if let (true, Some(router)) = (node_id == "local", &self.router) {
            router
                .relay_set_accounts(accounts.as_ref().expect("local accounts"))
                .await
                .map_err(|error| adapter_refusal(error, "router_unavailable"))?;
        } else if self.publisher.is_some() {
            let node = node_id.to_string();
            self.transaction_async(move |this, db| {
                this.publisher.as_ref().expect("checked").publish(db, &node).map_err(RoutingFailure::internal)?;
                Ok(())
            })
            .await?;
        }
        Ok(json!({"node_id": node_id, "rotated": count}).as_object().expect("literal object").clone())
    }

    pub async fn rollback(
        &self,
        node_id: &str,
        protocol: &str,
        expected_revision: i64,
        lane: &str,
        context: &AuditContext,
    ) -> Result<RoutingOutcome> {
        let typed = Self::protocol(protocol)?;
        let (policy, row) = self.for_change(node_id, protocol, expected_revision, lane).await?;
        if Self::kind(&row) != "local" {
            return self.rollback_remote(policy, context.clone()).await;
        }
        let result = async {
            let target = self.local_target(typed).await?;
            let target = target.ok_or_else(|| {
                AdapterError::with_code(format!("{protocol} reports no egress target"), "protocol_disabled_on_node")
            })?;
            if policy.backend == ROUTER_BACKEND {
                let router_target = self.router_target(&row, typed).await;
                if !router_target.as_ref().is_some_and(|router| router.available) {
                    return Err(AdapterError::with_code(
                        "the node's Xray-router does not answer",
                        router_target.and_then(|router| router.reason).unwrap_or_else(|| "router_unavailable".into()),
                    ));
                }
                let router_target = router_target.expect("checked available");
                let applied = self
                    .router
                    .as_ref()
                    .expect("available local router")
                    .rollback(protocol, &router_target.revision)
                    .await?;
                Ok((applied, router_target.xray_version, true))
            } else {
                let adapter = self.adapters.adapter(typed).expect("target implies adapter");
                let applied = adapter.rollback_egress(&target.revision).await?;
                Ok((applied, target.runtime_version, target.restart_required))
            }
        }
        .await;
        let (applied, runtime_version, restart_required) = match result {
            Ok(result) => result,
            Err(error) => {
                if error.code.as_deref() == Some("protocol_disabled_on_node") {
                    return Err(RoutingFailure::refused(422, "protocol_disabled_on_node", error.message));
                }
                return Err(if policy.backend == ROUTER_BACKEND {
                    adapter_refusal(error, "manager_unavailable")
                } else {
                    manager_refusal(typed, error, "manager_unavailable")
                });
            }
        };
        let mut compiled = Compiled::new(CompileStatus::Supported);
        compiled.backend = Some(policy.backend.as_str().to_string());
        compiled.digest = applied.digest.clone();
        compiled.runtime_version = runtime_version;
        compiled.restart_required = restart_required;
        let updated = self
            .record(
                policy,
                compiled.clone(),
                "rolled_back",
                Some(applied.clone()),
                None,
                context.clone(),
                "routing.policy.rollback",
            )
            .await?;
        Ok(RoutingOutcome { policy: updated, applied: Some(applied), compiled })
    }
}

fn save_failure(error: StoreError) -> RoutingFailure {
    match error {
        StoreError::Conflict(revision) => {
            RoutingFailure::refused(409, "policy_conflict", format!("policy revision is {revision}"))
        }
        StoreError::Invalid(message) => RoutingFailure::refused(422, "backend_mismatch", message),
        other => other.into_failure(),
    }
}

fn exit_failure(error: ExitError) -> RoutingFailure {
    match error {
        ExitError::NotFound => RoutingFailure::refused(404, "exit_not_found", "exit not found"),
        ExitError::Invalid(message) => RoutingFailure::refused(422, "exit_invalid", message),
        ExitError::Failure(error) => error,
    }
}

fn node_failure(error: NodeError) -> RoutingFailure {
    match error {
        NodeError::Rejected { status, code, detail } => RoutingFailure::refused(
            status,
            code.filter(|code| !code.is_empty()).unwrap_or_else(|| "router_unavailable".into()),
            detail,
        ),
        NodeError::Unreachable(_) => RoutingFailure::refused(502, "node_unreachable", "NodeUnreachable"),
        NodeError::AuthFailed => RoutingFailure::refused(502, "node_unreachable", "NodeAuthFailed"),
        NodeError::InvalidAnswer(error) => RoutingFailure::internal(error),
    }
}
