//! What a node answers its central (`fleet_v2/node_routes.py`, `metrics_node.py`): one method per
//! route, free of HTTP. The web shell (`panel-web`, `routes/fleet_node.rs`) runs the gates, reads
//! the request, writes the audit rows and renders these answers.

use std::sync::Arc;
use std::time::Duration;

use indexmap::IndexMap;
use panel_core::clock::SharedClock;
use panel_core::db::{Conn, Database};
use panel_core::errors::{ApiError, ValidationIssue};
use panel_core::settings::Settings;
use panel_metrics::Metrics;
use panel_model::fleet::ObservedGeneration;
use panel_model::fleet::{PushRequest, PushResponse, BASE_CAPABILITIES, METRICS_CAPABILITY, ROUTER_CAPABILITIES};
use panel_model::metrics::{POINTS_DEFAULT, POINTS_MAX, POINTS_MIN};
use panel_model::protocols::{BoxFuture, GrantRef};
use panel_model::validate::Model;
use panel_model::Protocol;
use panel_protocols::xray_router::GeodataAction;
use panel_secrets::secrets_store::SecretError;
use serde_json::{json, Map, Value};

use super::managed::{AcceptError, ManagedStore, StoreError};
use super::models::CaptureRequest;
use super::reconcile::{truthy, ReconcileError, Reconciler};
use super::runtime::{NodeRuntime, VersionAgent};
use super::traffic;

/// The central reads a push for 30 s: the node answers 202 before that and the reconcile keeps
/// running in the background.
pub const APPLY_DEADLINE: Duration = Duration::from_secs(25);
/// What `status` reports while the version-agent cannot be asked.
pub fn versions_unavailable() -> Value {
    json!({"enabled": false, "components": {}, "reason": "version_agent_unavailable"})
}
/// The router manager's own refusals of a geodata action: the caller's 422 (else 502).
pub const GEODATA_REFUSALS: [&str; 4] = ["geodata_invalid", "geodata_corrupt", "geodata_rejected", "geodata_busy"];
/// The protocols of the node's tables, in `app.state.adapters` order.
pub const PROTOCOLS: [&str; 5] = ["mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"];

/// A route's failure: an answer of the API, or Python's unhandled exception (the bare 500).
#[derive(Debug)]
pub enum NodeFailure {
    /// Boxed: the answer travels in every `Result` of this module.
    Api(Box<ApiError>),
    Internal(String),
}

impl From<ApiError> for NodeFailure {
    fn from(error: ApiError) -> Self {
        NodeFailure::Api(Box::new(error))
    }
}

impl From<StoreError> for NodeFailure {
    fn from(error: StoreError) -> Self {
        NodeFailure::Internal(error.to_string())
    }
}

impl From<panel_core::db::DbError> for NodeFailure {
    fn from(error: panel_core::db::DbError) -> Self {
        NodeFailure::Internal(error.to_string())
    }
}

impl From<ReconcileError> for NodeFailure {
    fn from(error: ReconcileError) -> Self {
        NodeFailure::Internal(error.to_string())
    }
}

impl std::fmt::Display for NodeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeFailure::Api(error) => write!(f, "{error}"),
            NodeFailure::Internal(message) => f.write_str(message),
        }
    }
}

pub type NodeResult<T> = Result<T, NodeFailure>;

/// `JSONResponse({"detail": detail or code, "code": code}, 409)`.
pub fn conflict(code: &str, detail: &str) -> ApiError {
    ApiError::coded(409, code, if detail.is_empty() { code } else { detail })
}

/// The settings the node routes read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    pub naive_enabled: bool,
    pub mieru_enabled: bool,
    pub amneziawg_enabled: bool,
    pub trusttunnel_enabled: bool,
    pub metrics_enabled: bool,
    /// `settings.mtproxy_host`: `MTPROXY_DOMAIN`, else the first allowed host.
    pub mtproxy_host: String,
    pub naive_public_host: String,
    pub amneziawg_public_host: String,
    pub trusttunnel_public_host: String,
}

impl NodeConfig {
    pub fn from_settings(settings: &Settings) -> Self {
        let mtproxy_host = if settings.mtproxy_public_host.is_empty() {
            settings.allowed_hosts.first().cloned().unwrap_or_default()
        } else {
            settings.mtproxy_public_host.clone()
        };
        Self {
            naive_enabled: settings.naive_enabled,
            mieru_enabled: settings.mieru_enabled,
            amneziawg_enabled: settings.amneziawg_enabled,
            trusttunnel_enabled: settings.trusttunnel_enabled,
            metrics_enabled: settings.metrics_enabled,
            mtproxy_host,
            naive_public_host: settings.naive_public_host.clone(),
            amneziawg_public_host: settings.amneziawg_public_host.clone(),
            trusttunnel_public_host: settings.trusttunnel_public_host.clone(),
        }
    }

    /// `_enabled(protocol)`: the protocol switches; MTProxy has none.
    pub fn enabled(&self, protocol: &str) -> bool {
        match protocol {
            "naive" => self.naive_enabled,
            "mieru" => self.mieru_enabled,
            "amneziawg" => self.amneziawg_enabled,
            "trusttunnel" => self.trusttunnel_enabled,
            _ => true,
        }
    }

    fn or_naive(&self, host: &str) -> String {
        if host.is_empty() {
            self.naive_public_host.clone()
        } else {
            host.to_string()
        }
    }
}

/// A push the node accepted: what the audit row records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub generation: i64,
    pub digest: String,
    pub resources: usize,
}

impl Accepted {
    /// The `fleet.generation.accept` audit detail.
    pub fn audit_detail(&self) -> Map<String, Value> {
        let mut detail = Map::new();
        detail.insert("digest".into(), json!(self.digest));
        detail.insert("resources".into(), json!(self.resources));
        detail
    }
}

/// An answer with an audit detail for the route to record.
#[derive(Debug, Clone, PartialEq)]
pub struct Audited {
    pub body: Value,
    pub audit: Map<String, Value>,
}

/// The node side of fleet v2 for one panel: cheap to clone.
#[derive(Clone)]
pub struct FleetNode {
    inner: Arc<Inner>,
}

struct Inner {
    database: Database,
    managed: ManagedStore,
    reconciler: Arc<Reconciler>,
    runtime: Arc<dyn NodeRuntime>,
    versions: Arc<dyn VersionAgent>,
    config: NodeConfig,
    guid: String,
    panel_version: String,
}

impl std::fmt::Debug for FleetNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetNode").field("guid", &self.inner.guid).finish_non_exhaustive()
    }
}

/// The parameters of `GET /api/fleet/v2/metrics/history`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryQuery {
    pub series: String,
    pub range: String,
    pub points: i64,
}

impl HistoryQuery {
    /// FastAPI's reading of `series: str = Query(...)`, `range: str = Query("1h")`,
    /// `points: int = Query(240, ge=10, le=2000)`: one 422 list.
    pub fn parse(raw: &str) -> Result<Self, Vec<ValidationIssue>> {
        let query = panel_metrics::query::Query::parse(Some(raw));
        let mut issues = Vec::new();
        let series = panel_metrics::query::required(&query, "series", &mut issues);
        let range = query.get("range").unwrap_or("1h").to_string();
        let points =
            panel_metrics::query::bounded_int(&query, "points", POINTS_DEFAULT, POINTS_MIN, POINTS_MAX, &mut issues);
        match (series, points) {
            (Some(series), Some(points)) if issues.is_empty() => Ok(Self { series, range, points }),
            _ => Err(issues),
        }
    }
}

/// `range: str = Query("24h")` of `GET /api/fleet/v2/metrics/summary`.
pub fn summary_range(raw: &str) -> String {
    panel_metrics::query::Query::parse(Some(raw)).get("range").unwrap_or("24h").to_string()
}

impl FleetNode {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database: Database,
        secrets: panel_secrets::secrets_store::SecretStore,
        runtime: Arc<dyn NodeRuntime>,
        versions: Arc<dyn VersionAgent>,
        config: NodeConfig,
        guid: impl Into<String>,
        panel_version: impl Into<String>,
        clock: SharedClock,
    ) -> Self {
        let guid = guid.into();
        let managed = ManagedStore::new(clock.clone());
        let reconciler =
            Arc::new(Reconciler::new(database.clone(), secrets, runtime.clone(), managed.clone(), guid.clone(), clock));
        Self {
            inner: Arc::new(Inner {
                database,
                managed,
                reconciler,
                runtime,
                versions,
                config,
                guid,
                panel_version: panel_version.into(),
            }),
        }
    }

    pub fn reconciler(&self) -> &Arc<Reconciler> {
        &self.inner.reconciler
    }

    pub fn managed(&self) -> &ManagedStore {
        &self.inner.managed
    }

    pub fn database(&self) -> &Database {
        &self.inner.database
    }

    pub fn runtime(&self) -> &Arc<dyn NodeRuntime> {
        &self.inner.runtime
    }

    pub fn config(&self) -> &NodeConfig {
        &self.inner.config
    }

    pub fn guid(&self) -> &str {
        &self.inner.guid
    }

    async fn read<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Conn, &ManagedStore) -> Result<T, NodeFailure> + Send + 'static,
    ) -> NodeResult<T> {
        let (database, managed) = (self.inner.database.clone(), self.inner.managed.clone());
        tokio::task::spawn_blocking(move || database.with_connection(|db| work(db, &managed)))
            .await
            .map_err(|error| NodeFailure::Internal(error.to_string()))?
    }

    // -- tables ----------------------------------------------------------------------------------

    async fn daemon(&self, protocol: Protocol) -> &'static str {
        if !self.inner.config.enabled(protocol.as_str()) {
            return "off";
        }
        if self.inner.runtime.healthy(protocol).await {
            "ok"
        } else {
            "down"
        }
    }

    /// The egress target of one protocol as the central's compiler reads it: secret-free. A
    /// manager that cannot answer contributes no target (`daemon` already says it is down).
    async fn egress_entry(&self, protocol: &str) -> Value {
        let Some(adapter) = Protocol::from_wire(protocol).and_then(|protocol| self.inner.runtime.adapter(protocol))
        else {
            return Value::Null;
        };
        if !self.inner.config.enabled(protocol) {
            return Value::Null;
        }
        let Ok(Some(target)) = adapter.egress_target().await else {
            return Value::Null;
        };
        json!({
            "backend": target.backend.as_str(),
            "capabilities": target.capabilities.iter().collect::<Vec<_>>(),
            "providers": target.providers,
            "revision": target.revision,
            "mode": target.mode.as_str(),
            "restart_required": target.restart_required,
            "applied_digest": target.applied.as_ref().map(|applied| applied.digest.clone()),
            "warnings": target.warnings,
            "router_attached": target.router_attached,
        })
    }

    /// `_protocol_table(egress=…)`.
    async fn protocol_table(&self, egress: bool) -> Map<String, Value> {
        let (telemt, naive, mieru, amneziawg, trusttunnel) = tokio::join!(
            self.daemon(Protocol::Mtproxy),
            self.daemon(Protocol::Naive),
            self.daemon(Protocol::Mieru),
            self.daemon(Protocol::Amneziawg),
            self.daemon(Protocol::Trusttunnel),
        );
        let config = &self.inner.config;
        let mut awg_versions: Vec<String> = Vec::new();
        if config.amneziawg_enabled && amneziawg == "ok" {
            awg_versions = self.inner.runtime.amneziawg_versions().await.unwrap_or_default();
        }
        let mut table = Map::new();
        table.insert(
            "mtproxy".into(),
            json!({"enabled": true, "public_host": config.mtproxy_host, "public_port": 443, "daemon": telemt}),
        );
        table.insert(
            "naive".into(),
            json!({"enabled": config.naive_enabled, "public_host": config.naive_public_host, "public_port": 443,
                   "daemon": naive}),
        );
        table.insert(
            "mieru".into(),
            json!({"enabled": config.mieru_enabled, "public_host": config.naive_public_host, "public_port": 8443,
                   "daemon": mieru}),
        );
        table.insert(
            "amneziawg".into(),
            json!({"enabled": config.amneziawg_enabled, "public_host": config.or_naive(&config.amneziawg_public_host),
                   "public_port": 0, "daemon": amneziawg, "versions": awg_versions}),
        );
        table.insert(
            "trusttunnel".into(),
            json!({"enabled": config.trusttunnel_enabled,
                   "public_host": config.or_naive(&config.trusttunnel_public_host), "public_port": 443,
                   "daemon": trusttunnel}),
        );
        if egress {
            let (a, b, c, d, e) = tokio::join!(
                self.egress_entry("mtproxy"),
                self.egress_entry("naive"),
                self.egress_entry("mieru"),
                self.egress_entry("amneziawg"),
                self.egress_entry("trusttunnel"),
            );
            for (protocol, entry) in PROTOCOLS.iter().zip([a, b, c, d, e]) {
                if let Some(Value::Object(row)) = table.get_mut(*protocol) {
                    row.insert("egress".into(), entry);
                }
            }
        }
        table
    }

    /// The node's Xray-router as the central's compiler reads it: `None` without a router,
    /// unavailable with its reason, else the cells, the WARP provider, per service the section's
    /// revision and applied digest, the relay's public part and the lanes.
    async fn router_entry(&self) -> Value {
        let Some(router) = self.inner.runtime.router() else {
            return Value::Null;
        };
        let (mut sections, mut lanes) = (Map::new(), Map::new());
        let (mut capabilities, mut providers, mut xray_version) = (Vec::new(), Map::new(), None);
        for service in ["naive", "mieru", "mtproxy", "trusttunnel", "amneziawg"] {
            let target = router.target(service).await;
            let lacks = format!("router_lacks_{service}");
            if matches!(service, "mtproxy" | "trusttunnel" | "amneziawg") && target.reason.as_deref() == Some(&lacks) {
                continue; // a router not rebuilt since that service joined still serves the rest
            }
            if !target.available {
                let reason =
                    target.reason.filter(|reason| !reason.is_empty()).unwrap_or_else(|| "router_unavailable".into());
                return json!({"available": false, "reason": reason});
            }
            sections.insert(
                service.into(),
                json!({"revision": target.revision,
                       "applied_digest": target.applied.as_ref().map(|applied| applied.digest.clone())}),
            );
            capabilities = target.capabilities.iter().cloned().collect();
            providers = target.providers.clone();
            xray_version = target.xray_version.clone();
            if matches!(service, "mtproxy" | "trusttunnel" | "amneziawg") {
                continue; // no lanes on MTProxy, TrustTunnel or AmneziaWG
            }
            let mut names: Vec<Value> = match router.lanes(service).await {
                Ok(view) => match view.get("lanes") {
                    Some(Value::Array(items)) => items.clone(),
                    _ => Vec::new(),
                },
                Err(_) => Vec::new(),
            };
            names.sort_by(|a, b| a.as_str().unwrap_or("").cmp(b.as_str().unwrap_or("")));
            lanes.insert(service.into(), Value::Array(names));
        }
        // The relay's public part: what another node needs to dial it; never a key.
        let relay = router.relay().await.map_or(Value::Null, |relay| {
            let field = |key: &str| relay.get(key).cloned().unwrap_or(Value::Null);
            let accounts = match relay.get("accounts") {
                Some(value @ Value::Bool(_)) => value.clone(),
                Some(Value::Number(number)) if !number.is_f64() => Value::Number(number.clone()),
                Some(Value::Array(items)) => json!(items.len()),
                Some(Value::Object(map)) => json!(map.len()),
                Some(Value::String(text)) => json!(text.chars().count()),
                _ => json!(0),
            };
            let short_ids = match relay.get("short_ids") {
                Some(Value::Array(items)) => Value::Array(items.clone()),
                _ => json!([]),
            };
            json!({"enabled": truthy(relay.get("enabled")), "port": field("port"),
                   "server_name": field("server_name"), "public_key": field("public_key"),
                   "short_ids": short_ids, "accounts": accounts})
        });
        capabilities.sort();
        json!({"available": true, "xray_version": xray_version, "capabilities": capabilities,
               "providers": providers, "services": sections, "relay": relay, "lanes": lanes})
    }

    /// Runtime users per protocol and who owns each; a dead manager contributes no rows.
    async fn inventory_table(&self) -> NodeResult<Map<String, Value>> {
        let managed = self.read(|db, managed| Ok(managed.owned(db)?)).await?;
        let mut table = Map::new();
        for protocol in PROTOCOLS {
            table.insert(protocol.into(), json!([]));
        }
        for protocol in PROTOCOLS {
            if !self.inner.config.enabled(protocol) {
                continue;
            }
            let Some(adapter) = Protocol::from_wire(protocol).and_then(|protocol| self.inner.runtime.adapter(protocol))
            else {
                continue;
            };
            let Ok(observed) = adapter.discover().await else {
                continue; // /status already reports the daemon as down
            };
            let rows: Vec<Value> = observed
                .items
                .iter()
                .map(|item| {
                    let record = managed.get(&(protocol.to_string(), item.runtime_username.clone()));
                    json!({"runtime_username": item.runtime_username, "enabled": item.enabled,
                           "options": item.options, "ownership": if record.is_some() { "central" } else { "local" },
                           "ref": record.and_then(|row| row.get("ref").cloned())})
                })
                .collect();
            table.insert(protocol.into(), Value::Array(rows));
        }
        Ok(table)
    }

    async fn traffic(&self) -> NodeResult<Vec<(&'static str, Value)>> {
        let config = &self.inner.config;
        let runtime = &self.inner.runtime;
        let mtproxy = async { runtime.telemt_users().await.map_or(Value::Null, |users| traffic::telemt(&users)) };
        let naive = async {
            if !config.naive_enabled {
                return Value::Null;
            }
            runtime.naive_traffic().await.and_then(|data| traffic::naive(&data)).unwrap_or(Value::Null)
        };
        let amneziawg = async {
            if !config.amneziawg_enabled {
                return Ok(Value::Null);
            }
            match runtime.amneziawg_peers().await {
                None => Ok(Value::Null),
                Some(peers) => traffic::rx_tx(&peers),
            }
        };
        let (mtproxy, naive, amneziawg) = tokio::join!(mtproxy, naive, amneziawg);
        let trusttunnel = if config.trusttunnel_enabled {
            match runtime.trusttunnel_clients().await {
                None => Value::Null,
                Some(rows) => traffic::rx_tx(&rows).map_err(NodeFailure::Internal)?,
            }
        } else {
            Value::Null
        };
        Ok(vec![
            ("mtproxy", mtproxy),
            ("naive", naive),
            ("mieru", Value::Null),
            ("amneziawg", amneziawg.map_err(NodeFailure::Internal)?),
            ("trusttunnel", trusttunnel),
        ])
    }

    // -- routes ----------------------------------------------------------------------------------

    /// `GET /api/fleet/v2/identity`.
    pub async fn identity(&self) -> NodeResult<Value> {
        let master = self.read(|db, managed| Ok(managed.master_guid(db)?)).await?;
        let router = self.router_entry().await;
        let mut capabilities: Vec<&str> = BASE_CAPABILITIES.to_vec();
        if self.inner.config.metrics_enabled {
            capabilities.push(METRICS_CAPABILITY);
        }
        if !router.is_null() {
            capabilities.extend(ROUTER_CAPABILITIES);
        }
        Ok(json!({"guid": self.inner.guid, "panel_version": self.inner.panel_version, "api_version": 2,
                  "master_guid": master, "protocols": self.protocol_table(true).await,
                  "capabilities": capabilities, "router": router}))
    }

    /// `GET /api/fleet/v2/status`.
    pub async fn status(&self) -> NodeResult<Value> {
        let (mut versions, mut host) = (versions_unavailable(), json!({}));
        if let Ok(found) = self.inner.versions.list_versions().await {
            versions = found;
            if let Ok(found) = self.inner.versions.host().await {
                host = found;
            }
        }
        let inventory = self.inventory_table().await?;
        let mut users = Map::new();
        for (protocol, rows) in &inventory {
            let rows = rows.as_array().cloned().unwrap_or_default();
            let central = rows.iter().filter(|row| row["ownership"] == "central").count();
            let local = rows.iter().filter(|row| row["ownership"] == "local").count();
            users.insert(protocol.clone(), json!({"central": central, "local": local}));
        }
        let managed = self.read(|db, managed| Ok(managed.owned(db)?.len())).await?;
        let (mut protocols, traffic) = tokio::join!(self.protocol_table(false), self.traffic());
        for (protocol, counters) in traffic? {
            if let Some(Value::Object(row)) = protocols.get_mut(protocol) {
                row.insert("traffic".into(), counters);
            }
        }
        Ok(json!({"versions": versions, "host": host, "managed_resources": managed, "users": users,
                  "protocols": protocols}))
    }

    /// `GET /api/fleet/v2/inventory`.
    pub async fn inventory(&self) -> NodeResult<Value> {
        Ok(json!({"protocols": self.inventory_table().await?}))
    }

    /// `PUT /api/fleet/v2/generation`, first half: checks the GUID, records the generation and
    /// escrows its secrets in one transaction. The route audits `fleet.generation.accept`, then
    /// calls [`FleetNode::apply_pushed`].
    pub async fn accept(&self, request: PushRequest) -> NodeResult<Accepted> {
        if request.expected_guid != self.inner.guid {
            return Err(conflict("guid_mismatch", "").into());
        }
        let accepted = Accepted {
            generation: request.generation.generation,
            digest: request.generation.canonical_digest(),
            resources: request.generation.resources.len(),
        };
        let (database, reconciler, guid, digest) = (
            self.inner.database.clone(),
            self.inner.reconciler.clone(),
            self.inner.guid.clone(),
            accepted.digest.clone(),
        );
        enum Refusal {
            Accept(AcceptError),
            Reconcile(ReconcileError),
        }
        impl From<panel_core::db::DbError> for Refusal {
            fn from(error: panel_core::db::DbError) -> Self {
                Refusal::Accept(AcceptError::from(error))
            }
        }
        let outcome = tokio::task::spawn_blocking(move || {
            database.transaction(|db| {
                reconciler.managed().accept(db, &request.generation, &digest, &guid).map_err(Refusal::Accept)?;
                reconciler.store_secrets(db, &request).map_err(Refusal::Reconcile)
            })
        })
        .await
        .map_err(|error| NodeFailure::Internal(error.to_string()))?;
        match outcome {
            Ok(()) => Ok(accepted),
            Err(Refusal::Accept(AcceptError::Conflict(conflict_error))) => {
                Err(conflict(conflict_error.code.as_str(), &conflict_error.message).into())
            }
            Err(Refusal::Accept(AcceptError::Store(error))) => Err(error.into()),
            // No master key (ADR 005): the transaction rolled the generation back with it; a code,
            // so the central stops retrying.
            Err(Refusal::Reconcile(ReconcileError::Secret(SecretError::Refused(message)))) => {
                Err(conflict("secret_store_disabled", message).into())
            }
            Err(Refusal::Reconcile(error)) => Err(error.into()),
        }
    }

    /// `PUT /api/fleet/v2/generation`, second half: the reconcile runs as background work
    /// (`spawn` hands it to the web shell's tracker so it outlives the request); the answer waits
    /// up to [`APPLY_DEADLINE`]. `(status, body)`: 200 with the report and the runtime's
    /// credentials, 202 with the report so far, or 409 `stale_generation` when a newer
    /// generation superseded this one.
    pub async fn apply_pushed(
        &self,
        generation: i64,
        spawn: impl FnOnce(BoxFuture<'static, ()>),
    ) -> NodeResult<(u16, Value)> {
        self.apply_with_deadline(generation, APPLY_DEADLINE, spawn).await
    }

    /// [`FleetNode::apply_pushed`] with another deadline (tests).
    pub async fn apply_with_deadline(
        &self,
        generation: i64,
        deadline: Duration,
        spawn: impl FnOnce(BoxFuture<'static, ()>),
    ) -> NodeResult<(u16, Value)> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let reconciler = self.inner.reconciler.clone();
        spawn(Box::pin(async move {
            let result = reconciler.apply(generation).await;
            if let Err(Err(error)) = sender.send(result) {
                log::warn!("fleet: background reconcile failed: {error}");
            }
        }));
        let push_response = |observed: ObservedGeneration, credentials: IndexMap<String, String>| {
            PushResponse { observed, credentials }.dump()
        };
        match tokio::time::timeout(deadline, receiver).await {
            Err(_) => {
                let observed = self.read(|db, managed| Ok(managed.observed(db)?)).await?;
                let observed = observed.ok_or_else(|| NodeFailure::Internal("no generation to report".into()))?;
                Ok((202, push_response(observed, IndexMap::new())))
            }
            Ok(Err(_)) => Err(NodeFailure::Internal("the reconcile task ended without an answer".into())),
            Ok(Ok(Ok((observed, credentials)))) => Ok((200, push_response(observed, credentials))),
            // A newer generation was accepted while this one waited for the reconcile lock.
            Ok(Ok(Err(ReconcileError::Superseded(_)))) => {
                Err(conflict("stale_generation", "superseded by a newer generation").into())
            }
            Ok(Ok(Err(error))) => Err(error.into()),
        }
    }

    /// `GET /api/fleet/v2/observed`: the report, or the initial one before any push.
    pub async fn observed(&self) -> NodeResult<Value> {
        let found = self.read(|db, managed| Ok(managed.observed(db)?)).await?;
        Ok(found.unwrap_or_else(ObservedGeneration::initial).dump())
    }

    /// `POST /api/fleet/v2/credentials/capture`: per `"<protocol>:<user>"` the live credential or
    /// `null`; unsupported protocols and (unless importing) users the central does not own are
    /// listed apart. The audit detail names labels only, never a value.
    pub async fn capture(&self, request: &CaptureRequest) -> NodeResult<Audited> {
        let managed = self.read(|db, managed| Ok(managed.owned(db)?)).await?;
        let mut credentials: IndexMap<String, Value> = IndexMap::new();
        let (mut unsupported, mut refused) = (Vec::new(), Vec::new());
        for item in &request.resources {
            let label = format!("{}:{}", item.protocol, item.runtime_username);
            let protocol = Protocol::from_wire(&item.protocol).expect("a validated protocol");
            let adapter = self.inner.runtime.adapter(protocol);
            let Some(adapter) =
                adapter.filter(|adapter| self.inner.config.enabled(&item.protocol) && adapter.capture_supported())
            else {
                unsupported.push(label);
                continue;
            };
            if request.purpose != "import"
                && !managed.contains_key(&(item.protocol.clone(), item.runtime_username.clone()))
            {
                refused.push(label);
                continue;
            }
            let reference = GrantRef { protocol, runtime_username: item.runtime_username.clone(), revision: None };
            let value = adapter.capture(&reference).await.ok().flatten();
            let value = match value {
                None => Value::Null,
                Some(bytes) => {
                    Value::String(String::from_utf8(bytes).map_err(|error| NodeFailure::Internal(error.to_string()))?)
                }
            };
            credentials.insert(label, value);
        }
        let mut answered: Vec<&String> =
            credentials.iter().filter(|(_, value)| truthy(Some(value))).map(|(label, _)| label).collect();
        let mut unanswered: Vec<&String> =
            credentials.iter().filter(|(_, value)| !truthy(Some(value))).map(|(label, _)| label).collect();
        answered.sort();
        unanswered.sort();
        let mut audit = Map::new();
        audit.insert("purpose".into(), json!(request.purpose));
        audit.insert("requested".into(), json!(request.resources.len()));
        audit.insert("answered".into(), json!(answered));
        audit.insert("unanswered".into(), json!(unanswered));
        audit.insert("unsupported".into(), json!(unsupported));
        audit.insert("refused".into(), json!(refused));
        let credentials: Map<String, Value> = credentials.into_iter().collect();
        Ok(Audited { body: json!({"credentials": credentials, "unsupported": unsupported, "refused": refused}), audit })
    }

    fn no_router() -> ApiError {
        ApiError::coded(404, "router_unavailable", "this node runs no Xray-router")
    }

    /// `_geodata(action, body)`: the router's answer, or its refusal (422 for the manager's own
    /// `geodata_*` refusals, else 502), or 404 without a router.
    pub async fn geodata(&self, action: GeodataAction, body: Option<Map<String, Value>>) -> NodeResult<Value> {
        let Some(router) = self.inner.runtime.router() else {
            return Err(Self::no_router().into());
        };
        let body = body.map(Value::Object);
        router.geodata(action, body.as_ref()).await.map_err(|error| {
            let code = error.code.filter(|code| !code.is_empty()).unwrap_or_else(|| "router_unavailable".into());
            let status = if GEODATA_REFUSALS.contains(&code.as_str()) { 422 } else { 502 };
            ApiError::coded(status, code, error.message).into()
        })
    }

    /// `POST /api/fleet/v2/exits/test`: the router's verdict on an exit (the spec carries its
    /// credential, so the answer is `no-store` and the audit names protocol and address only).
    pub async fn exit_test(&self, spec: &Map<String, Value>) -> NodeResult<Audited> {
        let Some(router) = self.inner.runtime.router() else {
            return Err(Self::no_router().into());
        };
        let result = router.exit_test(&Value::Object(spec.clone())).await.map_err(|error| {
            let code = error.code.filter(|code| !code.is_empty()).unwrap_or_else(|| "router_unavailable".into());
            let status = if code == "egress_invalid" { 422 } else { 502 };
            NodeFailure::from(ApiError::coded(status, code, error.message))
        })?;
        let mut audit = Map::new();
        audit.insert("protocol".into(), spec.get("protocol").cloned().unwrap_or(Value::Null));
        audit.insert("address".into(), spec.get("address").cloned().unwrap_or(Value::Null));
        audit.insert("ok".into(), result.get("ok").cloned().unwrap_or(Value::Null));
        Ok(Audited { body: result, audit })
    }

    /// `POST /api/fleet/v2/versions/update`: the agent's answer passed through.
    pub async fn update_version(
        &self,
        component: &str,
        version: &str,
        expected_current: Option<&str>,
    ) -> NodeResult<Value> {
        self.inner.versions.update(component, version, expected_current).await.map_err(|error| error.app_error().into())
    }

    /// `POST /api/fleet/v2/versions/check`.
    pub async fn check_versions(&self) -> NodeResult<Value> {
        self.inner.versions.check().await.map_err(|error| error.app_error().into())
    }

    /// `POST /api/fleet/v2/unlink` and `POST /api/nodes/local/unlink`: how many resources became
    /// local (the runtime is left alone).
    pub async fn unlink(&self) -> NodeResult<i64> {
        Ok(self.inner.reconciler.unlink().await?)
    }

    // -- metrics (`metrics_node.py`, capability `metrics.v1`) -----------------------------------

    fn metrics_ready<'m>(&self, metrics: Option<&'m Metrics>) -> NodeResult<&'m Metrics> {
        match metrics {
            Some(metrics) if self.inner.config.metrics_enabled && metrics.collector().is_some() => Ok(metrics),
            _ => Err(ApiError::detail(404, "metrics_disabled").into()),
        }
    }

    async fn warmed_up(metrics: &Metrics) -> NodeResult<Value> {
        let latest = match metrics.collector() {
            Some(collector) => collector.latest().await,
            None => None,
        };
        latest.ok_or_else(|| ApiError::detail(503, "metrics_warming_up").into())
    }

    /// `GET /api/fleet/v2/metrics`: the collector's latest node entry.
    pub async fn metrics_live(&self, metrics: Option<&Metrics>) -> NodeResult<Value> {
        let metrics = self.metrics_ready(metrics)?;
        Self::warmed_up(metrics).await
    }

    /// `GET /api/fleet/v2/metrics/history`.
    pub async fn metrics_history(&self, metrics: Option<&Metrics>, query: &HistoryQuery) -> NodeResult<Value> {
        let metrics = self.metrics_ready(metrics)?;
        panel_metrics::routes::check_range(&query.range)?;
        let names = panel_metrics::routes::parse_series(&query.series)?;
        Self::warmed_up(metrics).await?;
        let history = metrics
            .store()
            .history(&names, &query.range, query.points)
            .await
            .map_err(|error| NodeFailure::Internal(error.to_string()))?;
        let mut body = Map::new();
        body.insert("status".into(), json!("ok"));
        if let Value::Object(history) = history {
            body.extend(history);
        }
        Ok(Value::Object(body))
    }

    /// `GET /api/fleet/v2/metrics/summary`.
    pub async fn metrics_summary(&self, metrics: Option<&Metrics>, range: &str) -> NodeResult<Value> {
        let metrics = self.metrics_ready(metrics)?;
        panel_metrics::routes::check_range(range)?;
        Self::warmed_up(metrics).await?;
        metrics.local_summary(range).await.map_err(|error| NodeFailure::Internal(error.to_string()))
    }
}
