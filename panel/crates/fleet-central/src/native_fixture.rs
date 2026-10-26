//! Native central tests reuse the clients package's complete in-memory protocol adapters.
#![allow(dead_code)]

#[path = "../../clients/tests/common/mod.rs"]
pub mod domain;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use indexmap::IndexMap;
use panel_clients::hooks::PublishForClient;
use panel_clients::store::{self, GrantFilter};
use panel_fleet::central::{NodeClientFactory, NodeLink};
use panel_model::clients::AccessGrant;
use panel_model::fleet::{
    DesiredState, ObservedGeneration, ObservedResource, ObservedState, PushRequest, PushResponse, ReconcileState,
};
use panel_model::protocols::BoxFuture;
use panel_model::seams::{CaptureItem, CapturePurpose, NodeClient, NodeError, SeamError};
use panel_model::validate::Model;
use panel_model::Protocol;
use panel_secrets::events::EventBus;
use panel_secrets::secrets_store::SecretRef;
use serde_json::{json, Map, Value};

use crate::generations::{DesiredGeneration, DesiredStore, PublishService};
use crate::importing::FleetImporter;
use crate::links::NodeLinkService;
use crate::pusher::{FleetPusher, PusherOptions};
use crate::CentralError;

pub const EDGE: &str = "edge";
pub const KEY: &str = "pc_synthetic_node_key";
pub const MASTER: &str = "central";

pub fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

pub struct NodeState {
    pub identity: Map<String, Value>,
    pub key: String,
    pub errors: HashMap<&'static str, NodeError>,
    pub inventory: Map<String, Value>,
    pub credentials: HashMap<String, String>,
    pub captures: Vec<(CapturePurpose, Vec<CaptureItem>)>,
    pub capture_null: HashSet<String>,
    pub fail_capture_on_call: Option<usize>,
    pub pushes: Vec<PushRequest>,
    pub report: ObservedGeneration,
    pub push_state: ReconcileState,
    pub failed_names: HashSet<String>,
    pub learned: Map<String, Value>,
    pub lose_push_reply_once: bool,
    pub applied: usize,
    pub released: usize,
    pub identity_delay: Duration,
    pub identity_barrier: Option<Arc<tokio::sync::Barrier>>,
}

pub struct Node {
    pub state: Mutex<NodeState>,
    pub identity_calls: AtomicUsize,
    pub status_calls: AtomicUsize,
    pub observed_calls: AtomicUsize,
    pub active: AtomicUsize,
    pub peak: AtomicUsize,
}

impl Node {
    pub fn new(guid: &str) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(NodeState {
                identity: object(json!({"guid": guid, "api_version": 2, "master_guid": null,
                    "panel_version": "native-test", "capabilities": ["generation.v1", "credentials.capture", "metrics.v1"],
                    "protocols": {"naive": {"public_host": "edge.example"}, "mtproxy": {"public_host": "proxy.edge.example"}}})),
                key: KEY.into(),
                errors: HashMap::new(),
                inventory: Map::new(),
                credentials: HashMap::new(),
                captures: Vec::new(),
                capture_null: HashSet::new(),
                fail_capture_on_call: None,
                pushes: Vec::new(),
                report: ObservedGeneration {
                    applied_generation: 0,
                    digest: String::new(),
                    reconcile_state: ReconcileState::Idle,
                    resources: Vec::new(),
                    reported_at: 0,
                    egress: IndexMap::new(),
                    relay: None,
                },
                push_state: ReconcileState::Converged,
                failed_names: HashSet::new(),
                learned: Map::new(),
                lose_push_reply_once: false,
                applied: 0,
                released: 0,
                identity_delay: Duration::ZERO,
                identity_barrier: None,
            }),
            identity_calls: AtomicUsize::new(0),
            status_calls: AtomicUsize::new(0),
            observed_calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        })
    }

    pub fn seed(&self, protocol: Protocol, name: &str, credential: Option<&str>) {
        let mut state = self.state.lock().unwrap();
        state
            .inventory
            .entry(protocol.as_str())
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .unwrap()
            .push(json!({"runtime_username": name, "enabled": true, "ownership": "local", "options": {}}));
        if let Some(credential) = credential {
            state.credentials.insert(format!("{protocol}:{name}"), credential.into());
        }
    }

    pub fn complete(&self) {
        let mut state = self.state.lock().unwrap();
        state.report.reconcile_state = ReconcileState::Converged;
        state.push_state = ReconcileState::Converged;
    }
}

#[derive(Default)]
pub struct Counters {
    pub active: AtomicUsize,
    pub peak: AtomicUsize,
}

#[derive(Default)]
pub struct Factory {
    pub nodes: Mutex<HashMap<String, Arc<Node>>>,
    pub seen: Mutex<Vec<NodeLink>>,
    pub created: Arc<AtomicUsize>,
    pub dropped: Arc<AtomicUsize>,
    pub global: Arc<Counters>,
}

impl Factory {
    pub fn insert(&self, id: &str, node: Arc<Node>) {
        self.nodes.lock().unwrap().insert(format!("https://{id}.example"), node);
    }
}

struct Session {
    node: Arc<Node>,
    key: String,
    dropped: Arc<AtomicUsize>,
    global: Arc<Counters>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

impl Session {
    fn check(&self, method: &'static str) -> Result<(), NodeError> {
        let state = self.node.state.lock().unwrap();
        if self.key != state.key {
            return Err(NodeError::AuthFailed);
        }
        match state.errors.get(method) {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

impl NodeClientFactory for Factory {
    fn client(&self, link: &NodeLink, key: &str) -> Result<Arc<dyn NodeClient>, SeamError> {
        self.seen.lock().unwrap().push(link.clone());
        let node = self
            .nodes
            .lock()
            .unwrap()
            .get(&link.panel_url)
            .cloned()
            .ok_or_else(|| std::io::Error::other("unknown synthetic node"))?;
        self.created.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(Session { node, key: key.into(), dropped: self.dropped.clone(), global: self.global.clone() }))
    }
}

struct Active<'a> {
    node: &'a Node,
    global: &'a Counters,
}
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.node.active.fetch_sub(1, Ordering::SeqCst);
        self.global.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl NodeClient for Session {
    fn identity(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.node.identity_calls.fetch_add(1, Ordering::SeqCst);
            self.check("identity")?;
            let active = self.node.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.node.peak.fetch_max(active, Ordering::SeqCst);
            let active = self.global.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.global.peak.fetch_max(active, Ordering::SeqCst);
            let _active = Active { node: &self.node, global: &self.global };
            let delay = self.node.state.lock().unwrap().identity_delay;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let barrier = self.node.state.lock().unwrap().identity_barrier.clone();
            if let Some(barrier) = barrier {
                barrier.wait().await;
            }
            Ok(self.node.state.lock().unwrap().identity.clone())
        })
    }
    fn status(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.node.status_calls.fetch_add(1, Ordering::SeqCst);
            self.check("status")?;
            Ok(Map::new())
        })
    }
    fn inventory(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.check("inventory")?;
            Ok(object(json!({"protocols": self.node.state.lock().unwrap().inventory})))
        })
    }
    fn metrics(&self, _: Duration) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.check("metrics")?;
            Ok(object(json!({"status":"ok"})))
        })
    }
    fn metrics_history<'a>(
        &'a self,
        _: &'a [String],
        _: &'a str,
        _: i64,
        _: Duration,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.check("history")?;
            Ok(Map::new())
        })
    }
    fn metrics_summary<'a>(&'a self, _: &'a str, _: Duration) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.check("summary")?;
            Ok(Map::new())
        })
    }
    fn push<'a>(&'a self, request: &'a PushRequest) -> BoxFuture<'a, Result<(u16, PushResponse), NodeError>> {
        Box::pin(async move {
            self.check("push")?;
            let mut state = self.node.state.lock().unwrap();
            state.pushes.push(request.clone());
            if state.report.applied_generation != request.generation.generation {
                state.applied += 1;
            }
            let mut credentials = IndexMap::new();
            let mut resources = Vec::new();
            for resource in &request.generation.resources {
                let label = format!("{}:{}", resource.protocol, resource.runtime_username);
                let failed = state.failed_names.contains(&resource.runtime_username);
                let observed = if failed {
                    ObservedState::Failed
                } else {
                    match resource.desired_state {
                        DesiredState::Enabled => ObservedState::Enabled,
                        DesiredState::Disabled => ObservedState::Disabled,
                        DesiredState::Deleted => ObservedState::Missing,
                    }
                };
                if observed != ObservedState::Missing && !failed {
                    if let Some(value) = request.secrets.get(&resource.credential_ref) {
                        let value = if resource.protocol == Protocol::Mtproxy && !value.starts_with("ee") {
                            format!("ee{value}")
                        } else {
                            value.clone()
                        };
                        state.credentials.insert(label.clone(), value);
                    }
                    if let Some(value) = state.credentials.get(&label) {
                        if !state.capture_null.contains(&label) {
                            credentials.insert(resource.credential_ref.clone(), value.clone());
                        }
                    }
                }
                resources.push(
                    ObservedResource::validate(
                        &json!({"ref":resource.reference, "protocol":resource.protocol.as_str(),
                    "runtime_username":resource.runtime_username, "state":observed.as_str(),
                    "error": if failed { Some("not managed") } else { None }, "learned":state.learned}),
                    )
                    .unwrap(),
                );
                if let Some(rows) = state.inventory.get_mut(resource.protocol.as_str()).and_then(Value::as_array_mut) {
                    for row in rows {
                        if row["runtime_username"] == resource.runtime_username {
                            row["ownership"] = json!("central");
                        }
                    }
                }
            }
            state.report = ObservedGeneration {
                applied_generation: request.generation.generation,
                digest: request.generation.canonical_digest(),
                reconcile_state: if state.failed_names.is_empty() { state.push_state } else { ReconcileState::Failed },
                resources,
                reported_at: 1,
                egress: IndexMap::new(),
                relay: None,
            };
            if state.lose_push_reply_once {
                state.lose_push_reply_once = false;
                return Err(NodeError::Unreachable("ReadError".into()));
            }
            let applying = state.report.reconcile_state == ReconcileState::Applying;
            Ok((
                if applying { 202 } else { 200 },
                PushResponse {
                    observed: state.report.clone(),
                    credentials: if applying { IndexMap::new() } else { credentials },
                },
            ))
        })
    }
    fn observed(&self) -> BoxFuture<'_, Result<ObservedGeneration, NodeError>> {
        Box::pin(async move {
            self.node.observed_calls.fetch_add(1, Ordering::SeqCst);
            self.check("observed")?;
            Ok(self.node.state.lock().unwrap().report.clone())
        })
    }
    fn capture<'a>(
        &'a self,
        resources: &'a [CaptureItem],
        purpose: CapturePurpose,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.node.state.lock().unwrap().captures.push((purpose, resources.to_vec()));
            self.check("capture")?;
            assert!(
                resources.len() <= panel_model::fleet::CAPTURE_MAX_RESOURCES,
                "central exceeded node's capture bound"
            );
            let state = self.node.state.lock().unwrap();
            if state.fail_capture_on_call == Some(state.captures.len()) {
                return Err(NodeError::Unreachable("ReadTimeout".into()));
            }
            let credentials = resources
                .iter()
                .map(|item| {
                    let label = format!("{}:{}", item.protocol, item.runtime_username);
                    let value = if state.capture_null.contains(&label) {
                        Value::Null
                    } else {
                        state.credentials.get(&label).map_or(Value::Null, |value| json!(value))
                    };
                    (label, value)
                })
                .collect::<Map<_, _>>();
            Ok(object(json!({"credentials":credentials})))
        })
    }
    fn update_version<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.check("version")?;
            Ok(Map::new())
        })
    }
    fn check_versions(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.check("versions")?;
            Ok(Map::new())
        })
    }
    fn unlink(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.check("unlink")?;
            let mut state = self.node.state.lock().unwrap();
            state.released += 1;
            state.identity.insert("master_guid".into(), Value::Null);
            Ok(object(json!({"released":state.report.resources.len()})))
        })
    }
    fn exit_test<'a>(&'a self, _: &'a Map<String, Value>) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.check("exit")?;
            Ok(Map::new())
        })
    }
    fn geodata<'a>(
        &'a self,
        _: &'a str,
        _: Option<&'a Map<String, Value>>,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.check("geodata")?;
            Ok(Map::new())
        })
    }
}

pub struct Rig {
    pub env: domain::Env,
    pub factory: Arc<Factory>,
    pub node: Arc<Node>,
    pub links: Arc<NodeLinkService>,
    pub desired: DesiredStore,
    pub publisher: Arc<PublishService>,
    pub importer: FleetImporter,
    pub events: Arc<EventBus>,
    pub pusher: Arc<FleetPusher>,
}

impl Rig {
    pub fn new() -> Self {
        let env = domain::Env::new("fleet-native");
        let factory = Arc::new(Factory::default());
        let node = Node::new(EDGE);
        factory.insert(EDGE, node.clone());
        let links = Arc::new(
            NodeLinkService::new(env.database.clone(), env.secrets.clone(), MASTER, factory.clone(), env.clock.clone())
                .with_provisioning(env.provisioning.clone()),
        );
        let desired = DesiredStore::new(env.database.clone());
        let publisher = Arc::new(PublishService::new(MASTER, env.clock.clone(), None));
        env.clients.add_hook(Arc::new(PublishForClient::new(publisher.clone())));
        let importer = FleetImporter::new(
            env.database.clone(),
            env.secrets.clone(),
            env.clients.clone(),
            links.clone(),
            env.clock.clone(),
        );
        let events = Arc::new(EventBus::with_options(env.database.clone(), 500, env.clock.clone()));
        let pusher = Self::make_pusher(&env, &links, &desired, &importer, &events, PusherOptions::default());
        Self { env, factory, node, links, desired, publisher, importer, events, pusher }
    }
    fn make_pusher(
        env: &domain::Env,
        links: &Arc<NodeLinkService>,
        desired: &DesiredStore,
        importer: &FleetImporter,
        events: &Arc<EventBus>,
        options: PusherOptions,
    ) -> Arc<FleetPusher> {
        Arc::new(
            FleetPusher::with_options(
                env.database.clone(),
                links.clone(),
                desired.clone(),
                env.secrets.clone(),
                importer.clone(),
                env.clients.clone(),
                env.provisioning.clone(),
                events.clone(),
                env.clock.clone(),
                options,
            )
            .unwrap(),
        )
    }
    pub fn rebuilt_pusher(&self, options: PusherOptions) -> Arc<FleetPusher> {
        Self::make_pusher(&self.env, &self.links, &self.desired, &self.importer, &self.events, options)
    }
    pub async fn link(&self, auto_import: bool) {
        self.links
            .add("Edge", "https://edge.example", KEY, "verify", None, false, &domain::ctx(), auto_import)
            .await
            .unwrap();
    }
    pub async fn add_node(&self, id: &str) -> Arc<Node> {
        let node = Node::new(id);
        self.factory.insert(id, node.clone());
        self.links
            .add(id, &format!("https://{id}.example"), KEY, "verify", None, false, &domain::ctx(), false)
            .await
            .unwrap();
        node
    }
    pub async fn provision(&self, protocol: Protocol, name: &str) -> (String, AccessGrant) {
        let client = self.env.clients.create_client(name, &domain::ctx()).unwrap();
        let operation = self
            .env
            .provisioning
            .start(&client.id, vec![domain::intent_on(protocol, name, EDGE)], &domain::ctx())
            .await
            .unwrap();
        (operation, self.env.grants(&client.id).remove(0))
    }
    pub fn latest(&self) -> DesiredGeneration {
        self.env.database.with_connection(|db| DesiredStore::latest(db, EDGE)).unwrap().unwrap()
    }
    pub fn link_row(&self) -> Map<String, Value> {
        self.env.database.with_connection(|db| self.links.link(db, EDGE)).unwrap()
    }
    pub fn grants(&self) -> Vec<AccessGrant> {
        self.env
            .database
            .with_connection(|db| {
                store::grants(db, &GrantFilter { node_id: Some(EDGE), include_deleted: true, ..GrantFilter::default() })
            })
            .unwrap()
    }
    pub fn plaintext(&self, grant: &AccessGrant) -> String {
        self.env
            .database
            .with_connection(|db| {
                self.env.secrets.reveal(
                    db,
                    &SecretRef::new(
                        grant.secret_ref.as_ref().unwrap().secret_id.clone(),
                        grant.secret_ref.as_ref().unwrap().version,
                    ),
                    panel_clients::CREDENTIAL_PURPOSE,
                    Some(&grant.id),
                    Some(EDGE),
                )
            })
            .map(String::from_utf8)
            .unwrap()
            .unwrap()
    }
    pub fn audit(&self, action: &str) -> Value {
        self.env
            .database
            .with_connection(|db| {
                let text: String = db.query_row(
                    "SELECT detail_json FROM audit_log WHERE action=? ORDER BY id DESC LIMIT 1",
                    [action],
                    |row| row.get(0),
                )?;
                Ok::<_, CentralError>(serde_json::from_str(&text).unwrap())
            })
            .unwrap()
    }
    pub fn clear_desired(&self) {
        self.env.database.transaction(|db|{db.execute("DELETE FROM desired_generations WHERE node_id=?",[EDGE])?;db.execute("UPDATE node_links SET desired_generation=0,acknowledged_generation=0,config_dirty=0 WHERE node_id=?",[EDGE])?;Ok::<_,CentralError>(())}).unwrap();
    }
    pub fn current_grant(&self, id: &str) -> AccessGrant {
        self.env.database.with_connection(|db| store::grant(db, id)).unwrap()
    }
    pub fn nonce_row(&self, id: &str) -> (String, i64, Vec<u8>) {
        self.env
            .database
            .with_connection(|db| {
                db.query_row(
                    "SELECT state,created_at,nonce FROM secret_versions WHERE secret_id=? AND version=1",
                    [format!("grant:{id}")],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(CentralError::from)
            })
            .unwrap()
    }
    pub fn assert_acked(&self, generation: i64) {
        let link = self.link_row();
        assert_eq!(link["config_dirty"], 0);
        assert_eq!(link["acknowledged_generation"], generation);
        assert!(self.latest().acknowledged_at.is_some());
    }
}
