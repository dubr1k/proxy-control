//! Heartbeats, generation delivery and observation absorption (`fleet_v2/pusher.py`).
//!
//! A node is synchronised by at most one task, while overlapping ticks share one global
//! concurrency limit. Every network call happens outside a database transaction. A report is
//! absorbed atomically with credential escrow, grant readback and provisioning operations.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::join_all;
use indexmap::IndexMap;
use panel_clients::store::{self, GrantFilter, GrantUpdate};
use panel_clients::{ClientService, ProvisioningService, CREDENTIAL_PURPOSE};
use panel_core::clock::SharedClock;
use panel_core::db::{Conn, Database};
use panel_core::rusqlite::{params, OptionalExtension as _};
use panel_core::{ids, pyjson};
use panel_fleet::central::Pusher;
use panel_model::clients::{AccessGrant, GrantDesiredState, GrantObservedState};
use panel_model::fleet::{
    DesiredState, GenerationDocument, ObservedGeneration, ObservedRelay, ObservedState,
    PushRequest, ReconcileState, CAPTURE_MAX_RESOURCES,
};
use panel_model::protocols::{BoxFuture, CredentialOrigin};
use panel_model::seams::{CaptureItem, CapturePurpose, NodeClient, NodeError, SeamError};
use panel_model::validate::Model as _;
use panel_secrets::events::EventBus;
use panel_secrets::secrets_store::{SecretRef, SecretStore};
use serde_json::{json, Map, Value};
use tokio::sync::{watch, Semaphore};

use crate::generations::{self, DesiredGeneration, DesiredRouting, DesiredStore};
use crate::importing::FleetImporter;
use crate::links::NodeLinkService;
use crate::{CentralError, CentralResult};

pub const STALE_APPLY_SECONDS: i64 = 600;
pub const BACKOFF_FIRST_SECONDS: f64 = 30.0;
pub const BACKOFF_CAP_SECONDS: f64 = 600.0;
pub const WITHHELD_TICKS_BEFORE_BACKOFF: u32 = 4;
pub const NOT_CAPTURED: &str = "credential not captured yet";
pub const RELAY_PURPOSE: &str = "relay-account";
const RESYNC_CODES: [&str; 2] = ["stale_generation", "digest_conflict"];

/// WP10's observation side, kept out of this crate while the routing package is merged.
///
/// `absorb_egress` must implement the routing store's idempotent applied/failed/draft and
/// pass-through rules, including schema-2 companion lanes. `observe_relay` must implement
/// `RelayRegistry.observe`: preserve the desired enabled flag on an existing row and ignore
/// failed/unsupported reports. Both run inside the pusher's absorption transaction.
pub trait ObservationSink: Send + Sync {
    fn absorb_egress(
        &self,
        _db: &Conn,
        _node_id: &str,
        _latest: &GenerationDocument,
        _observed: &ObservedGeneration,
        _now: i64,
    ) -> CentralResult<()> {
        Ok(())
    }

    fn observe_relay(
        &self,
        _db: &Conn,
        _node_id: &str,
        _relay: &ObservedRelay,
        _now: i64,
    ) -> CentralResult<()> {
        Ok(())
    }
}

/// Explicit no-op for a central compiled without routing/relay observation.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopObservationSink;
impl ObservationSink for NoopObservationSink {}

/// Delivery-loop settings. Routing is optional so this crate has no WP10 dependency.
#[derive(Clone)]
pub struct PusherOptions {
    pub interval: Duration,
    pub max_concurrent: usize,
    pub desired_routing: Option<Arc<dyn DesiredRouting>>,
    pub observations: Option<Arc<dyn ObservationSink>>,
}

impl Default for PusherOptions {
    fn default() -> Self {
        Self { interval: Duration::from_secs(15), max_concurrent: 8, desired_routing: None, observations: None }
    }
}

#[derive(Debug, Clone, Copy)]
struct Backoff {
    generation: i64,
    failures: u32,
    until: f64,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn truncate(text: String, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// The failure class and node code only: a rejection detail can echo secret-bearing input.
fn describe(error: &NodeError) -> String {
    let text = match error {
        NodeError::Unreachable(kind) => format!("NodeUnreachable: {kind}"),
        NodeError::AuthFailed => "NodeAuthFailed: ".to_string(),
        NodeError::Rejected { status, code, .. } => {
            let code = code.as_deref().filter(|code| !code.is_empty()).map(str::to_string).unwrap_or_else(|| status.to_string());
            format!("NodeRejected: {code}")
        }
        NodeError::InvalidAnswer(error) => format!("NodeInvalidAnswer: {error}"),
    };
    truncate(text, 200)
}

/// 429 and panel-authored 5xx mean up-but-refusing; a bare proxy 5xx means offline.
fn refusing(error: &NodeError) -> bool {
    match error {
        NodeError::Rejected { status: 429, .. } => true,
        NodeError::Rejected { status: 500..=599, code, detail, .. } => {
            !detail.is_empty() || code.as_deref().is_some_and(|code| !code.is_empty())
        }
        _ => false,
    }
}

fn client_error(error: &NodeError) -> bool {
    matches!(error, NodeError::Unreachable(_) | NodeError::AuthFailed | NodeError::Rejected { .. })
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|number| number != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
    }
}

fn integer(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Bool(flag)) => i64::from(*flag),
        Some(value) => value.as_i64().unwrap_or(0),
        None => 0,
    }
}

fn inventory_digest(inventory: &Map<String, Value>) -> String {
    ids::sha256_hex(pyjson::canonical(&Value::Object(inventory.clone())))
}

fn parse_secret_ref(reference: &str) -> CentralResult<SecretRef> {
    let (secret_id, version) = reference
        .rsplit_once(':')
        .ok_or_else(|| CentralError::Invalid("credential_ref has no version".into()))?;
    let version = version
        .parse::<i64>()
        .map_err(|_| CentralError::Invalid("credential_ref has an invalid version".into()))?;
    Ok(SecretRef::new(secret_id, version))
}

fn backoff_wait(failures: u32) -> f64 {
    (BACKOFF_FIRST_SECONDS * 2.0_f64.powi(failures.saturating_sub(1).min(31) as i32)).min(BACKOFF_CAP_SECONDS)
}

fn backoff_active(current: Option<Backoff>, generation: i64, now: f64) -> bool {
    current.is_some_and(|current| current.generation == generation && now < current.until)
}

fn in_flight_at(latest: &DesiredGeneration, observed: Option<&ObservedGeneration>, now: f64) -> bool {
    let Some(observed) = observed else { return false };
    let Some(pushed_at) = latest.pushed_at else { return false };
    observed.applied_generation == latest.generation
        && observed.reconcile_state == ReconcileState::Applying
        && now - (pushed_at as f64) < STALE_APPLY_SECONDS as f64
}

/// The central heartbeat and delivery service. Cheap references are shared; clones are not
/// provided so lifecycle ownership remains explicit (`Arc<FleetPusher>`).
pub struct FleetPusher {
    database: Database,
    links: Arc<NodeLinkService>,
    desired: DesiredStore,
    secrets: SecretStore,
    importer: FleetImporter,
    clients: ClientService,
    provisioning: ProvisioningService,
    events: Arc<EventBus>,
    clock: SharedClock,
    interval: Duration,
    routing: Option<Arc<dyn DesiredRouting>>,
    observations: Option<Arc<dyn ObservationSink>>,
    stop: watch::Sender<bool>,
    locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    slots: Arc<Semaphore>,
    adopted: Mutex<HashMap<String, String>>,
    backoff: Mutex<HashMap<String, Backoff>>,
    withheld: Mutex<HashMap<String, (i64, u32)>>,
}

impl FleetPusher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database: Database,
        links: Arc<NodeLinkService>,
        desired: DesiredStore,
        secrets: SecretStore,
        importer: FleetImporter,
        clients: ClientService,
        provisioning: ProvisioningService,
        events: Arc<EventBus>,
        clock: SharedClock,
    ) -> Self {
        Self::with_options(
            database,
            links,
            desired,
            secrets,
            importer,
            clients,
            provisioning,
            events,
            clock,
            PusherOptions::default(),
        )
        .expect("default pusher options are valid")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_options(
        database: Database,
        links: Arc<NodeLinkService>,
        desired: DesiredStore,
        secrets: SecretStore,
        importer: FleetImporter,
        clients: ClientService,
        provisioning: ProvisioningService,
        events: Arc<EventBus>,
        clock: SharedClock,
        options: PusherOptions,
    ) -> CentralResult<Self> {
        if options.max_concurrent == 0 {
            return Err(CentralError::Invalid("max_concurrent must be positive".into()));
        }
        let (stop, _) = watch::channel(false);
        Ok(Self {
            database,
            links,
            desired,
            secrets,
            importer,
            clients,
            provisioning,
            events,
            clock,
            interval: options.interval,
            routing: options.desired_routing,
            observations: options.observations,
            stop,
            locks: tokio::sync::Mutex::new(HashMap::new()),
            slots: Arc::new(Semaphore::new(options.max_concurrent)),
            adopted: Mutex::new(HashMap::new()),
            backoff: Mutex::new(HashMap::new()),
            withheld: Mutex::new(HashMap::new()),
        })
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn desired(&self) -> &DesiredStore {
        &self.desired
    }

    async fn run_blocking<T, F>(work: F) -> CentralResult<T>
    where
        F: FnOnce() -> CentralResult<T> + Send + 'static,
        T: Send + 'static,
    {
        match tokio::task::spawn_blocking(work).await {
            Ok(result) => result,
            Err(error) => Err(CentralError::Internal(format!("fleet database task failed: {error}"))),
        }
    }

    /// Tick on `interval` until [`stop`](Self::stop). A failed tick is logged, not fatal.
    pub async fn run_forever(self: Arc<Self>) {
        let mut stopped = self.stop.subscribe();
        while !*stopped.borrow_and_update() {
            if let Err(error) = self.tick().await {
                log::error!("fleet: tick failed: {error}");
            }
            tokio::select! {
                _ = tokio::time::sleep(self.interval) => {}
                _ = stopped.wait_for(|stop| *stop) => {}
            }
        }
    }

    /// External-stop variant for a thin `BackgroundLoop` adapter.
    pub async fn run_until<S>(self: Arc<Self>, stopped: S)
    where
        S: Future<Output = ()> + Send,
    {
        tokio::pin!(stopped);
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                result = self.tick() => {
                    if let Err(error) = result {
                        log::error!("fleet: tick failed: {error}");
                    }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(self.interval) => {}
                _ = &mut stopped => break,
            }
        }
    }

    pub fn stop(&self) {
        self.stop.send_replace(true);
    }

    /// Visit every enabled link. Each node failure is isolated from all the others.
    pub async fn tick(&self) -> CentralResult<()> {
        let database = self.database.clone();
        let links = self.links.clone();
        let node_ids = Self::run_blocking(move || {
            database.with_connection(|db| {
                Ok(links
                    .links(db)?
                    .into_iter()
                    .filter(|link| truthy(link.get("enabled")))
                    .filter_map(|link| link.get("node_id").and_then(Value::as_str).map(str::to_string))
                    .collect::<Vec<_>>())
            })
        })
        .await?;
        join_all(node_ids.into_iter().map(|node_id| async move {
            if let Err(error) = self.sync_node(&node_id).await {
                log::error!("fleet: sync of node {node_id} failed: {error}");
            }
        }))
        .await;
        Ok(())
    }

    /// Heartbeat then deliver/poll one node, serialised against ticks and manual probes.
    pub async fn sync_node(&self, node_id: &str) -> CentralResult<()> {
        let node_lock = {
            let mut locks = self.locks.lock().await;
            locks.entry(node_id.to_string()).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone()
        };
        let _node = node_lock.lock().await;
        // Waiting for a node's own mutex must not consume a global slot.
        let _slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| CentralError::Internal(format!("fleet concurrency limiter closed: {error}")))?;
        let links = self.links.clone();
        let id = node_id.to_string();
        let client_id = id.clone();
        let client = Self::run_blocking(move || links.client_for(&client_id)).await?;
        self.sync_client(&id, client).await
    }

    async fn sync_client(&self, node_id: &str, client: Arc<dyn NodeClient>) -> CentralResult<()> {
        let started = self.clock.monotonic();
        let (identity, status) = match client.identity().await {
            Ok(identity) => match client.status().await {
                Ok(status) => (identity, status),
                Err(error) => return self.heartbeat_error(node_id, error).await,
            },
            Err(error) => return self.heartbeat_error(node_id, error).await,
        };
        let latency = ((self.clock.monotonic() - started) * 1000.0) as i64;
        let database = self.database.clone();
        let links = self.links.clone();
        let events = self.events.clone();
        let id = node_id.to_string();
        let heartbeat = Self::run_blocking(move || {
            database.transaction(|db| {
                let transition = links.record_heartbeat(
                    db,
                    &id,
                    true,
                    Some(&identity),
                    Some(&status),
                    Some(latency),
                    None,
                )?;
                Self::emit(db, &*events, transition.as_deref(), &id)?;
                let link = links.link(db, &id)?;
                let latest = DesiredStore::latest(db, &id)?;
                let observed = DesiredStore::observed(db, &id)?;
                Ok((link, latest, observed))
            })
        })
        .await;
        let (link, mut latest, mut observed) = match heartbeat {
            Ok(values) => values,
            Err(CentralError::NotFound(_)) => {
                log::info!("fleet: node {node_id} was unlinked during its heartbeat");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if truthy(link.get("enabled")) && link.get("auto_import").map_or(true, |value| truthy(Some(value))) {
            if self.adopt(&*client, node_id).await? {
                let database = self.database.clone();
                let id = node_id.to_string();
                (latest, observed) = Self::run_blocking(move || {
                    database.with_connection(|db| Ok((DesiredStore::latest(db, &id)?, DesiredStore::observed(db, &id)?)))
                })
                .await?;
            }
        }
        let Some(latest) = latest else { return Ok(()) };
        if !truthy(link.get("enabled")) {
            return Ok(());
        }
        if in_flight_at(&latest, observed.as_ref(), self.clock.time()) {
            self.poll_observed(&*client, node_id).await
        } else if self.deferred(node_id, latest.generation) {
            Ok(())
        } else if truthy(link.get("config_dirty")) || integer(link.get("acknowledged_generation")) < latest.generation {
            self.push(&*client, node_id, latest).await
        } else if latest.document.resources.iter().any(|resource| resource.valid_from.is_some() || resource.valid_until.is_some()) {
            // Deadline enforcement changes runtime state without changing the generation.
            self.poll_observed(&*client, node_id).await
        } else {
            Ok(())
        }
    }

    async fn heartbeat_error(&self, node_id: &str, error: NodeError) -> CentralResult<()> {
        if matches!(error, NodeError::Rejected { .. }) && refusing(&error) {
            return self.refusing(node_id, &error).await;
        }
        if client_error(&error) {
            return self.offline(node_id, &error).await;
        }
        Err(error.into())
    }

    async fn adopt(&self, client: &dyn NodeClient, node_id: &str) -> CentralResult<bool> {
        let inventory = match client.inventory().await {
            Ok(body) => body.get("protocols").and_then(Value::as_object).cloned().unwrap_or_default(),
            Err(error) if client_error(&error) => {
                log::info!("fleet: node {node_id}: inventory unavailable for auto-import ({})", describe(&error));
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        let digest = inventory_digest(&inventory);
        if lock(&self.adopted).get(node_id) == Some(&digest) {
            return Ok(false);
        }
        match self.importer.auto_import(node_id, Some(inventory)).await {
            Ok(result) => {
                lock(&self.adopted).insert(node_id.to_string(), digest);
                let imported = result
                    .as_ref()
                    .and_then(|result| result.get("imported"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if !imported.is_empty() {
                    let without = result
                        .as_ref()
                        .and_then(|result| result.get("without_credential"))
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len);
                    log::info!(
                        "fleet: node {node_id}: adopted {} account(s), {without} without credential",
                        imported.len()
                    );
                    return Ok(true);
                }
                Ok(false)
            }
            Err(error @ (CentralError::Invalid(_) | CentralError::NotFound(_) | CentralError::Node(_))) => {
                let description = match &error {
                    CentralError::Node(error) => describe(error),
                    other => truncate(other.to_string(), 200),
                };
                log::warn!("fleet: node {node_id}: auto-import failed: {description}");
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn defer(&self, node_id: &str, generation: i64) {
        let now = self.clock.monotonic();
        let mut backoffs = lock(&self.backoff);
        let failures = backoffs
            .get(node_id)
            .filter(|current| current.generation == generation)
            .map_or(1, |current| current.failures.saturating_add(1));
        let wait = backoff_wait(failures);
        backoffs.insert(node_id.to_string(), Backoff { generation, failures, until: now + wait });
        log::info!("fleet: node {node_id}: generation {generation} deferred for {wait:.0} s (failure {failures})");
    }

    fn deferred(&self, node_id: &str, generation: i64) -> bool {
        let mut backoffs = lock(&self.backoff);
        let Some(current) = backoffs.get(node_id).copied() else { return false };
        if current.generation != generation {
            backoffs.remove(node_id);
            return false;
        }
        backoff_active(Some(current), generation, self.clock.monotonic())
    }

    fn emit(db: &Conn, events: &EventBus, name: Option<&str>, node_id: &str) -> CentralResult<()> {
        if let Some(name) = name {
            events
                .emit(db, name, json!({"node_id": node_id}).as_object().expect("an object"))
                .map_err(|error| CentralError::Internal(error.to_string()))?;
        }
        Ok(())
    }

    async fn offline(&self, node_id: &str, error: &NodeError) -> CentralResult<()> {
        let database = self.database.clone();
        let links = self.links.clone();
        let events = self.events.clone();
        let id = node_id.to_string();
        let description = describe(error);
        Self::run_blocking(move || {
            database.transaction(|db| {
                let transition = links.record_heartbeat(db, &id, false, None, None, None, Some(&description))?;
                Self::emit(db, &*events, transition.as_deref(), &id)
            })
        })
        .await
    }

    async fn refusing(&self, node_id: &str, error: &NodeError) -> CentralResult<()> {
        let database = self.database.clone();
        let id = node_id.to_string();
        let description = describe(error);
        let now = self.clock.now();
        Self::run_blocking(move || {
            database.transaction(|db| {
                db.execute(
                    "UPDATE node_links SET last_error=?,updated_at=? WHERE node_id=?",
                    params![description, now, id],
                )?;
                Ok(())
            })
        })
        .await
    }

    async fn secrets_for(&self, node_id: &str, document: &GenerationDocument) -> CentralResult<IndexMap<String, String>> {
        let database = self.database.clone();
        let secrets = self.secrets.clone();
        let id = node_id.to_string();
        let document = document.clone();
        Self::run_blocking(move || {
            database.with_connection(|db| {
                let mut plaintext = IndexMap::new();
                for resource in &document.resources {
                    if resource.desired_state == DesiredState::Deleted {
                        continue;
                    }
                    let reference = parse_secret_ref(&resource.credential_ref)?;
                    let grant_id = resource.reference.strip_prefix("grant:").unwrap_or(&resource.reference);
                    match secrets.reveal(
                        db,
                        &reference,
                        CREDENTIAL_PURPOSE,
                        Some(grant_id),
                        Some(&id),
                    ) {
                        Ok(value) => {
                            let value = String::from_utf8(value)
                                .map_err(|_| CentralError::Invalid("grant credential is not UTF-8".into()))?;
                            plaintext.insert(resource.credential_ref.clone(), value);
                        }
                        Err(_) => {}
                    }
                }
                if let Some(relay) = &document.relay {
                    for account in &relay.accounts {
                        let reference = parse_secret_ref(&account.credential_ref)?;
                        match secrets.reveal(db, &reference, RELAY_PURPOSE, None, Some(&id)) {
                            Ok(value) => {
                                let value = String::from_utf8(value)
                                    .map_err(|_| CentralError::Invalid("relay credential is not UTF-8".into()))?;
                                plaintext.insert(account.credential_ref.clone(), value);
                            }
                            Err(_) => {}
                        }
                    }
                }
                Ok(plaintext)
            })
        })
        .await
    }

    async fn push(&self, client: &dyn NodeClient, node_id: &str, latest: DesiredGeneration) -> CentralResult<()> {
        let document = latest.document.clone();
        let request = PushRequest {
            expected_guid: node_id.to_string(),
            generation: document.clone(),
            secrets: self.secrets_for(node_id, &document).await?,
        };
        let response = match client.push(&request).await {
            Ok((_, response)) => response,
            Err(error @ NodeError::Rejected { status, ref code, .. }) => {
                let database = self.database.clone();
                let id = node_id.to_string();
                let now = self.clock.now();
                let message = truncate(
                    format!("push {status}: {}", code.as_deref().filter(|code| !code.is_empty()).unwrap_or("rejected")),
                    200,
                );
                Self::run_blocking(move || {
                    database.transaction(|db| {
                        db.execute(
                            "UPDATE node_links SET last_error=?,updated_at=? WHERE node_id=?",
                            params![message, now, id],
                        )?;
                        Ok(())
                    })
                })
                .await?;
                if code.as_deref().is_some_and(|code| RESYNC_CODES.contains(&code)) {
                    self.resync(client, node_id, latest).await?;
                } else {
                    self.defer(node_id, document.generation);
                }
                return Ok(());
            }
            Err(error) if client_error(&error) => return self.offline(node_id, &error).await,
            Err(error) => return Err(error.into()),
        };
        let database = self.database.clone();
        let id = node_id.to_string();
        let generation = document.generation;
        let now = self.clock.now();
        Self::run_blocking(move || {
            database.transaction(|db| DesiredStore::mark_pushed(db, &id, generation, now))
        })
        .await?;
        self.absorb(node_id, response.observed, response.credentials).await
    }

    async fn resync(&self, client: &dyn NodeClient, node_id: &str, latest: DesiredGeneration) -> CentralResult<()> {
        let observed = match client.observed().await {
            Ok(observed) => observed,
            Err(error) if client_error(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let database = self.database.clone();
        let links = self.links.clone();
        let routing = self.routing.clone();
        let id = node_id.to_string();
        let now = self.clock.now();
        let observed_generation = observed.applied_generation;
        let document = Self::run_blocking(move || {
            database.transaction(|db| {
                let current = DesiredStore::latest(db, &id)?;
                if current.as_ref().is_none_or(|current| current.generation != latest.generation)
                    || observed.applied_generation < current.as_ref().map_or(0, |current| current.generation)
                {
                    return Ok(None);
                }
                let document = generations::compile(
                    db,
                    &id,
                    &id,
                    links.own_guid(),
                    observed_generation,
                    observed_generation + 1,
                    now,
                    "system",
                    routing.as_deref(),
                )?;
                DesiredStore::insert(db, &id, &document, &document.canonical_digest(), &document.content_digest(), now)?;
                Ok(Some(document))
            })
        })
        .await?;
        if let Some(document) = document {
            log::warn!(
                "fleet: node {node_id} holds generation {}; republished as {}",
                observed_generation,
                document.generation
            );
        }
        Ok(())
    }

    async fn poll_observed(&self, client: &dyn NodeClient, node_id: &str) -> CentralResult<()> {
        let observed = match client.observed().await {
            Ok(observed) => observed,
            Err(error) if client_error(&error) => return self.offline(node_id, &error).await,
            Err(error) => return Err(error.into()),
        };
        let credentials = if matches!(observed.reconcile_state, ReconcileState::Converged | ReconcileState::Failed) {
            self.capture_pending(client, node_id, &observed).await?
        } else {
            IndexMap::new()
        };
        self.absorb(node_id, observed, credentials).await
    }

    async fn capture_pending(
        &self,
        client: &dyn NodeClient,
        node_id: &str,
        observed: &ObservedGeneration,
    ) -> CentralResult<IndexMap<String, String>> {
        let present: HashSet<&str> = observed
            .resources
            .iter()
            .filter(|item| matches!(item.state, ObservedState::Enabled | ObservedState::Disabled | ObservedState::Drifted))
            .map(|item| item.reference.as_str())
            .collect();
        let database = self.database.clone();
        let id = node_id.to_string();
        let generation = observed.applied_generation;
        let present: HashSet<String> = present.into_iter().map(str::to_string).collect();
        let wanted = Self::run_blocking(move || {
            database.with_connection(|db| {
                let latest = DesiredStore::latest(db, &id)?;
                if latest.as_ref().is_none_or(|latest| latest.generation != generation) {
                    return Ok(IndexMap::new());
                }
                let mut wanted = IndexMap::new();
                for resource in &latest.expect("checked above").document.resources {
                    if !present.contains(&resource.reference) || resource.desired_state == DesiredState::Deleted {
                        continue;
                    }
                    let reference = parse_secret_ref(&resource.credential_ref)?;
                    let state: Option<String> = db
                        .query_row(
                            "SELECT state FROM secret_versions WHERE secret_id=? AND version=?",
                            params![reference.secret_id, reference.version],
                            |row| row.get(0),
                        )
                        .optional()?;
                    if state.is_none() || state.as_deref() == Some("pending") {
                        let label = format!("{}:{}", resource.protocol.as_str(), resource.runtime_username);
                        wanted.insert(
                            label,
                            (
                                resource.credential_ref.clone(),
                                CaptureItem {
                                    protocol: resource.protocol.as_str().to_string(),
                                    runtime_username: resource.runtime_username.clone(),
                                },
                            ),
                        );
                    }
                }
                Ok(wanted)
            })
        })
        .await?;
        let labels: Vec<String> = wanted.keys().cloned().collect();
        let mut returned = Map::new();
        for (batch_index, batch) in labels.chunks(CAPTURE_MAX_RESOURCES).enumerate() {
            let resources: Vec<CaptureItem> = batch
                .iter()
                .map(|label| wanted.get(label).expect("a wanted label").1.clone())
                .collect();
            match client.capture(&resources, CapturePurpose::Escrow).await {
                Ok(answer) => {
                    if let Some(credentials) = answer.get("credentials").and_then(Value::as_object) {
                        returned.extend(credentials.clone());
                    }
                }
                Err(error) if client_error(&error) => {
                    log::warn!(
                        "fleet: node {node_id}: credential capture failed ({}); {} of {} answered, the rest is asked again",
                        describe(&error),
                        batch_index * CAPTURE_MAX_RESOURCES,
                        labels.len()
                    );
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(wanted
            .into_iter()
            .filter_map(|(label, (credential_ref, _))| {
                returned
                    .get(&label)
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(|value| (credential_ref, value.to_string()))
            })
            .collect())
    }

    fn names(grant: &AccessGrant, credential_ref: &str) -> bool {
        grant.secret_ref.as_ref().is_none_or(|reference| {
            credential_ref == format!("{}:{}", reference.secret_id, reference.version)
        })
    }


    async fn absorb(
        &self,
        node_id: &str,
        observed: ObservedGeneration,
        credentials: IndexMap<String, String>,
    ) -> CentralResult<()> {
        let generation = observed.applied_generation;
        let converged = observed.reconcile_state == ReconcileState::Converged;
        let failed = observed.reconcile_state == ReconcileState::Failed;
        let database = self.database.clone();
        let absorber = Absorber {
            clients: self.clients.clone(),
            provisioning: self.provisioning.clone(),
            clock: self.clock.clone(),
            observations: self.observations.clone(),
        };
        let id = node_id.to_string();
        let (current, withheld) = Self::run_blocking(move || {
            database.transaction(|db| absorber.absorb(db, &id, &observed, &credentials))
        })
        .await?;
        if converged {
            lock(&self.backoff).remove(node_id);
        } else if current && failed {
            self.defer(node_id, generation);
        }
        if !current || withheld.is_empty() {
            lock(&self.withheld).remove(node_id);
            return Ok(());
        }
        let ticks = {
            let mut states = lock(&self.withheld);
            let ticks = states
                .get(node_id)
                .filter(|previous| previous.0 == generation)
                .map_or(1, |previous| previous.1.saturating_add(1));
            states.insert(node_id.to_string(), (generation, ticks));
            ticks
        };
        log::warn!(
            "fleet: node {node_id}: {} credential(s) not captured yet ({ticks} tick(s)); generation {generation} is delivered again",
            withheld.len()
        );
        if ticks >= WITHHELD_TICKS_BEFORE_BACKOFF {
            self.defer(node_id, generation);
        }
        Ok(())
    }
}

// Kept separate only to give spawn_blocking an owned, 'static set of service references.
struct Absorber {
    clients: ClientService,
    provisioning: ProvisioningService,
    clock: SharedClock,
    observations: Option<Arc<dyn ObservationSink>>,
}

impl Absorber {
    fn absorb(
        &self,
        db: &Conn,
        node_id: &str,
        observed: &ObservedGeneration,
        credentials: &IndexMap<String, String>,
    ) -> CentralResult<(bool, HashSet<String>)> {
        let now = self.clock.now();
        let latest = DesiredStore::latest(db, node_id)?;
        let settled = matches!(observed.reconcile_state, ReconcileState::Converged | ReconcileState::Failed);
        let current = settled && latest.as_ref().is_some_and(|latest| latest.generation == observed.applied_generation);
        let grants: HashMap<String, AccessGrant> = store::grants(
            db,
            &GrantFilter { node_id: Some(node_id), include_deleted: true, ..GrantFilter::default() },
        )?
        .into_iter()
        .map(|grant| (grant.id.clone(), grant))
        .collect();
        let sent: HashMap<&str, &panel_model::fleet::Resource> = if current {
            latest.as_ref().expect("current implies latest").document.resources.iter().map(|r| (r.reference.as_str(), r)).collect()
        } else {
            HashMap::new()
        };
        let mut withheld = HashSet::new();
        for item in &observed.resources {
            let grant_id = item.reference.strip_prefix("grant:").unwrap_or(&item.reference);
            let Some(grant) = grants.get(grant_id) else { continue };
            let state = match item.state {
                ObservedState::Drifted => {
                    let Some(resource) = sent.get(item.reference.as_str()) else { continue };
                    match resource.desired_state {
                        DesiredState::Disabled => GrantObservedState::Disabled,
                        DesiredState::Enabled if resource.valid_from.is_none() && resource.valid_until.is_none() => GrantObservedState::Enabled,
                        _ => {
                            store::update_grant(db, &grant.id, &GrantUpdate::new().observed(GrantObservedState::Pending).at(now))?;
                            continue;
                        }
                    }
                }
                ObservedState::Enabled => GrantObservedState::Enabled,
                ObservedState::Disabled => GrantObservedState::Disabled,
                ObservedState::Missing => GrantObservedState::Missing,
                ObservedState::Failed => continue,
            };
            if state == GrantObservedState::Missing && grant.desired_state == GrantDesiredState::Deleted {
                self.clients.purge_grant(db, &grant.id)?;
                continue;
            }
            let returned = credentials.keys().find(|reference| reference.strip_prefix(&item.reference).is_some_and(|suffix| suffix.starts_with(':')));
            if current {
                if let Some(returned) = returned.filter(|returned| FleetPusher::names(grant, returned)) {
                    self.provisioning.escrow_returned_credential(db, &grant.id, returned, &credentials[returned])?;
                }
            }
            if !item.learned.is_empty() && state != GrantObservedState::Missing {
                let learned: Map<String, Value> = item.learned.iter().map(|(key, value)| (key.clone(), value.to_value())).collect();
                self.provisioning.remember_template(db, grant, &learned)?;
            }
            if current && state != GrantObservedState::Missing {
                if Self::uncaptured(&self.clients, db, grant)? {
                    withheld.insert(grant.id.clone());
                } else {
                    self.provisioning.confirm_credential(db, &grant.id)?;
                }
            }
            store::update_grant(db, &grant.id, &GrantUpdate::new().observed(state).at(now))?;
        }
        if current {
            self.provisioning.remote_applied(db, observed, &withheld, Some(NOT_CAPTURED))?;
            if let Some(sink) = &self.observations {
                sink.absorb_egress(db, node_id, &latest.as_ref().expect("current implies latest").document, observed, now)?;
            }
        }
        DesiredStore::record_observed(db, node_id, observed, withheld.is_empty(), now)?;
        if let Some(relay) = &observed.relay {
            let dumped = relay.dump();
            DesiredStore::record_relay(db, node_id, Some(dumped.as_object().expect("a relay report object")))?;
            if let Some(sink) = &self.observations {
                sink.observe_relay(db, node_id, relay, now)?;
            }
        }
        Ok((current, withheld))
    }

    fn uncaptured(clients: &ClientService, db: &Conn, grant: &AccessGrant) -> CentralResult<bool> {
        let Some(reference) = &grant.secret_ref else { return Ok(false) };
        if clients.adapters().get(grant.protocol).is_none_or(|adapter| adapter.credential_origin() != CredentialOrigin::Manager) {
            return Ok(false);
        }
        let state: Option<String> = db.query_row(
            "SELECT state FROM secret_versions WHERE secret_id=? AND version=?",
            params![reference.secret_id, reference.version],
            |row| row.get(0),
        ).optional()?;
        Ok(state.as_deref() == Some("pending"))
    }
}



impl Pusher for FleetPusher {
    fn tick(&self) -> BoxFuture<'_, Result<(), SeamError>> {
        Box::pin(async move { FleetPusher::tick(self).await.map_err(|error| Box::new(error) as SeamError) })
    }

    fn stop(&self) {
        FleetPusher::stop(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_core::clock::{Clock as _, FakeClock};

    fn latest(generation: i64, pushed_at: Option<i64>) -> DesiredGeneration {
        DesiredGeneration {
            generation,
            digest: "d".into(),
            content_digest: "c".into(),
            document: GenerationDocument {
                schema_version: 1,
                node_guid: "n".into(),
                master_guid: "m".into(),
                generation,
                previous_generation: generation - 1,
                created_at: 1,
                created_by: "system".into(),
                resources: Vec::new(),
                egress: None,
                relay: None,
            },
            pushed_at,
            acknowledged_at: None,
        }
    }

    fn observed(generation: i64, state: ReconcileState) -> ObservedGeneration {
        ObservedGeneration {
            applied_generation: generation,
            digest: "d".into(),
            reconcile_state: state,
            resources: Vec::new(),
            reported_at: 1,
            egress: IndexMap::new(),
            relay: None,
        }
    }

    #[test]
    fn in_flight_only_covers_the_current_unexpired_apply() {
        let desired = latest(7, Some(100));
        let applying = observed(7, ReconcileState::Applying);
        assert!(in_flight_at(&desired, Some(&applying), 699.0));
        assert!(!in_flight_at(&desired, Some(&applying), 700.0));
        assert!(!in_flight_at(&desired, Some(&observed(6, ReconcileState::Applying)), 101.0));
        assert!(!in_flight_at(&desired, Some(&observed(7, ReconcileState::Converged)), 101.0));
        assert!(!in_flight_at(&latest(7, None), Some(&applying), 101.0));
    }

    #[test]
    fn descriptions_hide_rejection_details_and_refusals_distinguish_proxy_errors() {
        let rejected = NodeError::Rejected {
            status: 422,
            code: Some("bad_request".into()),
            detail: "a secret echoed by the manager".into(),
        };
        assert_eq!(describe(&rejected), "NodeRejected: bad_request");
        assert!(!describe(&rejected).contains("secret echoed"));
        assert!(refusing(&NodeError::Rejected { status: 429, code: None, detail: String::new() }));
        assert!(refusing(&NodeError::Rejected { status: 503, code: Some("manager_down".into()), detail: String::new() }));
        assert!(!refusing(&NodeError::Rejected { status: 502, code: None, detail: String::new() }));
        assert!(!refusing(&NodeError::Rejected { status: 404, code: Some("not_found".into()), detail: String::new() }));
        let long = NodeError::Unreachable("x".repeat(300));
        assert_eq!(describe(&long).chars().count(), 200);
    }

    #[test]
    fn inventory_digest_is_canonical() {
        let left = json!({"naive": [{"runtime_username":"a"}], "mieru": []}).as_object().unwrap().clone();
        let right = json!({"mieru": [], "naive": [{"runtime_username":"a"}]}).as_object().unwrap().clone();
        assert_eq!(inventory_digest(&left), inventory_digest(&right));
        assert_eq!(inventory_digest(&left).len(), 64);
    }

    #[test]
    fn backoff_doubles_then_caps_at_ten_minutes() {
        let waits: Vec<f64> = (1..=7).map(backoff_wait).collect();
        assert_eq!(waits, [30.0, 60.0, 120.0, 240.0, 480.0, 600.0, 600.0]);
        assert_eq!(backoff_wait(u32::MAX), 600.0);
        let clock = FakeClock::default();
        let slot = Backoff { generation: 1, failures: 1, until: clock.monotonic() + backoff_wait(1) };
        assert_eq!(slot.until - clock.monotonic(), 30.0);
        assert!(backoff_active(Some(slot), 1, clock.monotonic() + 29.0));
        assert!(!backoff_active(Some(slot), 1, clock.monotonic() + 30.0));
        assert!(!backoff_active(Some(slot), 2, clock.monotonic()));
        assert!(!backoff_active(None, 1, clock.monotonic()));
    }
}
