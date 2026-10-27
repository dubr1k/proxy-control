//! Node-consumer ports of test_routing_fleet.py, test_routing_fleet_router.py and
//! test_routing_fleet_chains.py. Resource calls use the existing real protocol adapters;
//! the routing runtime records enforced documents, account tables, ordering and refusals.
mod support;

use panel_fleet::node::runtime::{FleetRouter, GeodataAction, NodeRuntime};
use panel_fleet::node::{FleetNode, NodeConfig};
use panel_model::clients::{AccessGrant, GrantIntent};
use panel_model::fleet::{CredentialOrigin, ObservedGeneration, PushRequest};
use panel_model::protocols::{
    AccessArtifact, AdapterError, AppliedDocument, AppliedEgress, AppliedGrant, BoxFuture, CredentialPlan,
    EgressTarget, GrantRef, ObservedInventory, Preflight, ProtocolAdapter, RouterTarget,
};
use panel_model::routing::document::{attach_document, attached_to_router, document_digest, router_direct_intent};
use panel_model::validate::Model;
use panel_model::{Backend, Protocol};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use support::{Node, StaticVersions, TestRuntime};

const NODE: &str = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";
const MASTER: &str = "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
const UUID: &str = "3f0d9c6e-1b4e-4a6b-9a1e-2c8f5d7e9a10";
const UUID_WARP: &str = "9a1e2c8f-5d7e-4a10-8b6e-3f0d9c6e1b4e";
const SECRET: &str = "7d1b2c3e-4f50-4a6b-8c7d-9e0f1a2b3c4d";
type Events = Arc<Mutex<Vec<String>>>;
fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap()
}
fn direct() -> Value {
    json!({"schema":1,"upstream":null,"acl":[]})
}
fn warp() -> Value {
    json!({"schema":1,"upstream":{"provider":"warp"},"acl":[]})
}
fn warp_intent() -> Value {
    json!({"schema":1,"default":{"action":"egress","egress":"warp"},"rules":[]})
}
fn block() -> Value {
    json!({"schema":1,"upstream":null,"acl":[{"deny":["example.com"]}]})
}

struct NativeState {
    document: Value,
    fail: Option<AdapterError>,
    reachable: bool,
}
struct Native {
    inner: Arc<dyn ProtocolAdapter>,
    state: Mutex<NativeState>,
    events: Events,
}
impl Native {
    fn new(inner: Arc<dyn ProtocolAdapter>, events: Events) -> Arc<Self> {
        let document =
            if inner.protocol() == Protocol::Mieru { json!({"schema":1,"proxies":[],"rules":[]}) } else { direct() };
        Arc::new(Self { inner, state: Mutex::new(NativeState { document, fail: None, reachable: true }), events })
    }
}
impl ProtocolAdapter for Native {
    fn protocol(&self) -> Protocol {
        self.inner.protocol()
    }
    fn credential_origin(&self) -> CredentialOrigin {
        self.inner.credential_origin()
    }
    fn capture_supported(&self) -> bool {
        self.inner.capture_supported()
    }
    fn accepts_caller_credential(&self) -> bool {
        self.inner.accepts_caller_credential()
    }
    fn discover(&self) -> BoxFuture<'_, Result<ObservedInventory, AdapterError>> {
        self.inner.discover()
    }
    fn preflight<'a>(&'a self, intent: &'a GrantIntent) -> BoxFuture<'a, Result<Preflight, AdapterError>> {
        self.inner.preflight(intent)
    }
    fn create<'a>(
        &'a self,
        op: &'a str,
        intent: &'a GrantIntent,
        credential: &'a CredentialPlan,
    ) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        Box::pin(async move {
            let applied = self.inner.create(op, intent, credential).await?;
            lock(&self.events).push(format!("create:{}", intent.runtime_username));
            Ok(applied)
        })
    }
    fn enable<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        self.inner.enable(grant)
    }
    fn disable<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        self.inner.disable(grant)
    }
    fn rotate<'a>(
        &'a self,
        op: &'a str,
        grant: &'a GrantRef,
        credential: &'a CredentialPlan,
    ) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        self.inner.rotate(op, grant, credential)
    }
    fn delete<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<(), AdapterError>> {
        self.inner.delete(grant)
    }
    fn capture<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<Option<Vec<u8>>, AdapterError>> {
        self.inner.capture(grant)
    }
    fn update_options<'a>(
        &'a self,
        grant: &'a GrantRef,
        options: &'a Map<String, Value>,
    ) -> BoxFuture<'a, Result<Option<AppliedGrant>, AdapterError>> {
        self.inner.update_options(grant, options)
    }
    fn render_artifacts(
        &self,
        grant: &AccessGrant,
        credential: &[u8],
        host: &str,
    ) -> Result<Vec<AccessArtifact>, AdapterError> {
        self.inner.render_artifacts(grant, credential, host)
    }
    fn egress_target(&self) -> BoxFuture<'_, Result<Option<EgressTarget>, AdapterError>> {
        Box::pin(async move {
            let state = lock(&self.state);
            let backend = if self.protocol() == Protocol::Naive { Backend::NaiveNative } else { Backend::MieruNative };
            let revision = document_digest(&state.document);
            let mut target = EgressTarget::new(self.protocol().as_str(), backend, revision.clone());
            target.capabilities =
                ["whole_direct", "whole_warp", "block_domain", "block_cidr"].into_iter().map(str::to_string).collect();
            target.providers =
                json!({"warp":{"reachable":state.reachable},"router":{"reachable":true}}).as_object().unwrap().clone();
            target.applied = Some(AppliedDocument {
                revision,
                digest: document_digest(&state.document),
                document: state.document.clone(),
            });
            target.router_attached = attached_to_router(self.protocol().as_str(), &state.document);
            Ok(Some(target))
        })
    }
    fn plan_egress<'a>(
        &'a self,
        document: &'a Map<String, Value>,
        revision: &'a str,
    ) -> BoxFuture<'a, Result<Map<String, Value>, AdapterError>> {
        self.inner.plan_egress(document, revision)
    }
    fn apply_egress<'a>(
        &'a self,
        document: &'a Map<String, Value>,
        revision: &'a str,
        op: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>> {
        Box::pin(async move {
            let mut state = lock(&self.state);
            lock(&self.events).push(format!("native:{}:{op}", self.protocol()));
            if let Some(error) = state.fail.take() {
                return Err(error);
            }
            if !state.reachable
                && document.get("upstream").and_then(|value| value.get("provider")).and_then(Value::as_str)
                    == Some("warp")
            {
                return Err(AdapterError::with_code("unreachable", "egress_unreachable"));
            }
            if revision != document_digest(&state.document) {
                return Err(AdapterError::with_code("changed", "egress_conflict"));
            }
            state.document = Value::Object(document.clone());
            Ok(AppliedEgress {
                revision: document_digest(&state.document),
                digest: Some(document_digest(&state.document)),
                readback_sha256: None,
                replayed: false,
            })
        })
    }
    fn rollback_egress<'a>(&'a self, revision: &'a str) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>> {
        self.inner.rollback_egress(revision)
    }
}

struct RouterState {
    documents: BTreeMap<String, Value>,
    lanes: BTreeMap<String, BTreeMap<String, Value>>,
    relay: Value,
    accounts: Vec<Value>,
    fail: Option<AdapterError>,
    warp: bool,
}
struct Router {
    state: Mutex<RouterState>,
    events: Events,
}
impl Router {
    fn new(events: Events) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(RouterState {
                documents: [("naive".into(), router_direct_intent()), ("mieru".into(), router_direct_intent())].into(),
                lanes: BTreeMap::new(),
                relay: json!({"enabled":false,"port":45443,"server_name":null,"public_key":"public-key","short_ids":["0123abcd"]}),
                accounts: vec![],
                fail: None,
                warp: true,
            }),
            events,
        })
    }
    fn view(state: &RouterState) -> Value {
        let mut view = state.relay.clone();
        view["emails"] = json!(state.accounts.iter().map(|row| row["email"].as_str().unwrap()).collect::<Vec<_>>());
        view
    }
}
impl FleetRouter for Router {
    fn target<'a>(&'a self, service: &'a str) -> BoxFuture<'a, RouterTarget> {
        Box::pin(async move {
            let state = lock(&self.state);
            let Some(document) = state.documents.get(service).cloned() else {
                return RouterTarget::unavailable(service, format!("router_lacks_{service}"));
            };
            let revision = document_digest(&document);
            RouterTarget {
                available: true,
                service: service.into(),
                capabilities: panel_managers::xray_router::ROUTER_CAPABILITIES
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                providers: json!({"warp":{"reachable":true}}).as_object().unwrap().clone(),
                revision: revision.clone(),
                applied: Some(AppliedDocument { revision, digest: document_digest(&document), document }),
                xray_version: Some("Xray 26.3.27".into()),
                restart_required: true,
                reason: None,
            }
        })
    }
    fn apply<'a>(
        &'a self,
        service: &'a str,
        document: &'a Value,
        revision: &'a str,
        op: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>> {
        Box::pin(async move {
            let mut state = lock(&self.state);
            lock(&self.events).push(format!("router:{service}:{op}"));
            if let Some(error) = state.fail.take() {
                return Err(error);
            }
            assert_eq!(revision, document_digest(&state.documents[service]));
            state.documents.insert(service.into(), document.clone());
            Ok(AppliedEgress {
                revision: document_digest(document),
                digest: Some(document_digest(document)),
                readback_sha256: None,
                replayed: false,
            })
        })
    }
    fn lanes<'a>(&'a self, service: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async move {
            Ok(
                json!({"lanes":lock(&self.state).lanes.get(service).map(|rows|rows.keys().cloned().collect::<Vec<_>>()).unwrap_or_default()}),
            )
        })
    }
    fn lane_issue<'a>(&'a self, service: &'a str, lane: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async move {
            lock(&self.events).push(format!("lane_issue:{service}:{lane}"));
            let mut state = lock(&self.state);
            Ok(state
                .lanes
                .entry(service.into())
                .or_default()
                .entry(lane.into())
                .or_insert_with(|| json!({"user":lane.replace(':',"-"),"password":"lane-secret-password"}))
                .clone())
        })
    }
    fn lane_forget<'a>(&'a self, service: &'a str, lane: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async move {
            lock(&self.events).push(format!("lane_forget:{service}:{lane}"));
            lock(&self.state).lanes.entry(service.into()).or_default().remove(lane);
            Ok(json!({"forgotten":true}))
        })
    }
    fn relay(&self) -> BoxFuture<'_, Option<Value>> {
        Box::pin(async move { Some(Self::view(&lock(&self.state))) })
    }
    fn relay_enable<'a>(&'a self, name: &'a str, port: i64) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async move {
            lock(&self.events).push("relay_enable".into());
            let mut state = lock(&self.state);
            state.relay["enabled"] = json!(true);
            state.relay["server_name"] = json!(name);
            state.relay["port"] = json!(port);
            Ok(Self::view(&state))
        })
    }
    fn relay_disable(&self) -> BoxFuture<'_, Result<Value, AdapterError>> {
        Box::pin(async move {
            lock(&self.events).push("relay_disable".into());
            let mut state = lock(&self.state);
            state.relay["enabled"] = json!(false);
            Ok(Self::view(&state))
        })
    }
    fn relay_set_accounts<'a>(&'a self, accounts: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async move {
            lock(&self.events).push("relay_accounts".into());
            let mut state = lock(&self.state);
            state.accounts = accounts
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| state.warp || !row["email"].as_str().unwrap().ends_with(":warp"))
                .cloned()
                .collect();
            Ok(Self::view(&state))
        })
    }
    fn exit_test<'a>(&'a self, _: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        panic!("not used by node routing regressions")
    }
    fn geodata<'a>(&'a self, _: GeodataAction, _: Option<&'a Value>) -> BoxFuture<'a, Result<Value, AdapterError>> {
        panic!("not used by node routing regressions")
    }
}

struct Runtime {
    inner: Arc<TestRuntime>,
    naive: Arc<Native>,
    mieru: Arc<Native>,
    router: Mutex<Option<Arc<Router>>>,
    lanes: Mutex<BTreeMap<String, Value>>,
    lane_failure: Mutex<Option<AdapterError>>,
    events: Events,
}
impl NodeRuntime for Runtime {
    fn adapter(&self, protocol: Protocol) -> Option<Arc<dyn ProtocolAdapter>> {
        match protocol {
            Protocol::Naive => Some(self.naive.clone()),
            Protocol::Mieru => self.inner.adapter(protocol).map(|_| self.mieru.clone() as Arc<dyn ProtocolAdapter>),
            other => self.inner.adapter(other),
        }
    }
    fn router(&self) -> Option<Arc<dyn FleetRouter>> {
        lock(&self.router).clone().map(|router| router as Arc<dyn FleetRouter>)
    }
    fn has_lanes(&self, protocol: Protocol) -> bool {
        matches!(protocol, Protocol::Naive | Protocol::Mieru)
    }
    fn set_lanes<'a>(&'a self, protocol: Protocol, lanes: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async move {
            lock(&self.events).push(format!("set_lanes:{protocol}"));
            if let Some(error) = lock(&self.lane_failure).take() {
                return Err(error);
            }
            lock(&self.lanes).insert(protocol.as_str().into(), lanes.clone());
            let views=lanes.as_array().unwrap().iter().enumerate().map(|(index,lane)| {
            let mut view=lane.clone();if protocol==Protocol::Mieru {view["share_templates"]=Value::Object(lane["users"].as_array().unwrap().iter().map(|user|(user.as_str().unwrap().into(),json!(format!("mierus://{{username}}:{{password}}@mieru.example.com?port={}&protocol=TCP&mtu=1400",46102+index)))).collect());}view
        }).collect::<Vec<_>>();
            Ok(
                json!({"lanes":views,"service_share_template":"mierus://{username}:{password}@mieru.example.com?port=8443&protocol=TCP&mtu=1400"}),
            )
        })
    }
    fn healthy(&self, protocol: Protocol) -> BoxFuture<'_, bool> {
        self.inner.healthy(protocol)
    }
    fn amneziawg_versions(&self) -> BoxFuture<'_, Result<Vec<String>, AdapterError>> {
        self.inner.amneziawg_versions()
    }
    fn telemt_users(&self) -> BoxFuture<'_, Option<Value>> {
        self.inner.telemt_users()
    }
    fn naive_traffic(&self) -> BoxFuture<'_, Option<Value>> {
        self.inner.naive_traffic()
    }
    fn trusttunnel_clients(&self) -> BoxFuture<'_, Option<Value>> {
        self.inner.trusttunnel_clients()
    }
    fn amneziawg_peers(&self) -> BoxFuture<'_, Option<Value>> {
        self.inner.amneziawg_peers()
    }
}
struct Stand {
    base: Node,
    node: FleetNode,
    runtime: Arc<Runtime>,
    router: Arc<Router>,
    events: Events,
}
fn stand() -> Stand {
    let base = Node::default_node();
    let events = Arc::new(Mutex::new(vec![]));
    let router = Router::new(events.clone());
    let runtime = Arc::new(Runtime {
        inner: base.runtime.clone(),
        naive: Native::new(base.runtime.adapter(Protocol::Naive).unwrap(), events.clone()),
        mieru: Native::new(base.runtime.adapter(Protocol::Mieru).unwrap(), events.clone()),
        router: Mutex::new(Some(router.clone())),
        lanes: Mutex::new(BTreeMap::new()),
        lane_failure: Mutex::new(None),
        events: events.clone(),
    });
    let node = FleetNode::new(
        base.database.clone(),
        base.node.reconciler().secrets(),
        runtime.clone(),
        Arc::new(StaticVersions { versions: None, host: None }),
        NodeConfig {
            naive_enabled: true,
            mieru_enabled: true,
            amneziawg_enabled: false,
            trusttunnel_enabled: false,
            metrics_enabled: false,
            mtproxy_host: "node.example".into(),
            naive_public_host: "node.example".into(),
            amneziawg_public_host: String::new(),
            trusttunnel_public_host: String::new(),
        },
        NODE,
        "test",
        base.clock.clone(),
    );
    Stand { base, node, runtime, router, events }
}
fn egress(document: Value, backend: &str, revision: i64, companion: Option<Value>) -> Value {
    let mut value = json!({"backend":backend,"policy_id":"p1","policy_revision":revision,"digest":document_digest(&document),"document":document});
    if let Some(companion) = companion {
        value["companion"] = companion;
    }
    value
}
fn resource(protocol: &str, user: &str, reference: &str, lane: bool) -> Value {
    let mut value = json!({"ref":reference,"protocol":protocol,"runtime_username":user,"desired_state":"enabled","credential_ref":format!("{reference}:1"),"credential_origin":"caller"});
    if lane {
        value["lane"] = json!("own");
    }
    value
}
fn relay(warp: bool, enabled: bool) -> Value {
    let mut accounts = vec![json!({"email":format!("relay:{MASTER}:direct"),"credential_ref":format!("{SECRET}:1")})];
    if warp {
        accounts.push(json!({"email":format!("relay:{MASTER}:warp"),"credential_ref":format!("{SECRET}:2")}));
    }
    json!({"enabled":enabled,"port":45443,"server_name":"node.example","accounts":accounts})
}
fn push(generation: i64, resources: Vec<Value>, sections: Option<Value>, relay: Option<Value>) -> PushRequest {
    let mut secrets = Map::new();
    for resource in &resources {
        secrets.insert(resource["credential_ref"].as_str().unwrap().into(), json!("correct horse battery staple"));
    }
    if let Some(relay) = &relay {
        for account in relay["accounts"].as_array().unwrap() {
            let key = account["credential_ref"].as_str().unwrap();
            secrets.insert(key.into(), json!(if key.ends_with(":1") { UUID } else { UUID_WARP }));
        }
    }
    PushRequest::validate(&json!({"expected_guid":NODE,"generation":{"node_guid":NODE,"master_guid":MASTER,"generation":generation,"previous_generation":generation-1,"created_at":1,"created_by":"central","resources":resources,"egress":sections,"relay":relay},"secrets":secrets})).unwrap()
}
async fn apply(stand: &Stand, request: PushRequest) -> ObservedGeneration {
    let generation = request.generation.generation;
    stand.node.accept(request).await.unwrap();
    stand.node.reconciler().apply(generation).await.unwrap().0
}
fn lane_intent(lane: &str) -> Value {
    json!({"schema":2,"lanes":{"svc:naive":{"default":{"action":"direct","egress":null},"rules":[]},lane:{"default":{"action":"egress","egress":"warp"},"rules":[]}},"chains":{}})
}

#[tokio::test]
async fn egress_applied_after_resources_and_reported() {
    let stand = stand();
    let observed = apply(
        &stand,
        push(
            1,
            vec![resource("naive", "alice", "grant:alice", false)],
            Some(json!({"naive":egress(warp(),"naive_native",1,None)})),
            None,
        ),
    )
    .await;
    assert_eq!(observed.reconcile_state.as_str(), "converged");
    assert_eq!(*lock(&stand.events), ["create:alice".to_string(), format!("native:naive:{NODE}:1:egress:naive")]);
    let report = &observed.egress["naive"];
    assert_eq!(report.state.as_str(), "converged");
    assert_eq!(report.digest.as_deref(), Some(document_digest(&warp()).as_str()));
    assert!(report.revision.is_some() && report.error.is_none());
    assert!(!observed.egress.contains_key("mieru"));
}
#[tokio::test]
async fn egress_failure_marks_generation_failed_but_resources_applied() {
    let stand = stand();
    lock(&stand.runtime.naive.state).reachable = false;
    let request = push(
        1,
        vec![resource("naive", "alice", "grant:alice", false)],
        Some(json!({"naive":egress(warp(),"naive_native",1,None)})),
        None,
    );
    let observed = apply(&stand, request).await;
    assert_eq!(observed.reconcile_state.as_str(), "failed");
    assert_eq!(observed.resources[0].state.as_str(), "enabled");
    assert_eq!(observed.egress["naive"].error.as_deref(), Some("egress_unreachable"));
    assert_eq!(lock(&stand.runtime.naive.state).document, direct());
    lock(&stand.runtime.naive.state).reachable = true;
    let observed = stand.node.reconciler().apply(1).await.unwrap().0;
    assert_eq!(observed.reconcile_state.as_str(), "converged");
    assert_eq!(observed.egress["naive"].state.as_str(), "converged");
}
#[tokio::test]
async fn egress_skipped_when_digest_matches() {
    let stand = stand();
    apply(&stand, push(1, vec![], Some(json!({"naive":egress(block(),"naive_native",1,None)})), None)).await;
    lock(&stand.events).clear();
    let observed =
        apply(&stand, push(2, vec![], Some(json!({"naive":egress(block(),"naive_native",2,None)})), None)).await;
    assert!(lock(&stand.events).is_empty());
    assert_eq!(observed.egress["naive"].digest.as_deref(), Some(document_digest(&block()).as_str()));
    assert_eq!(observed.reconcile_state.as_str(), "converged");
}
#[tokio::test]
async fn egress_absent_leaves_manager_untouched() {
    let stand = stand();
    apply(&stand, push(1, vec![], Some(json!({"naive":egress(warp(),"naive_native",1,None)})), None)).await;
    lock(&stand.events).clear();
    let observed = apply(&stand, push(2, vec![], None, None)).await;
    assert!(lock(&stand.events).is_empty());
    assert_eq!(lock(&stand.runtime.naive.state).document, warp());
    assert_eq!(observed.egress["naive"].state.as_str(), "converged");
    stand.node.unlink().await.unwrap();
    let db = stand.base.database.connect().unwrap();
    assert!(stand.node.managed().egress_rows(&db).unwrap().is_empty());
    assert_eq!(lock(&stand.runtime.naive.state).document, warp());
}
#[tokio::test]
async fn egress_for_a_protocol_without_a_target_is_unsupported() {
    let stand = stand();
    stand.runtime.inner.remove_adapter(Protocol::Mieru);
    let document = json!({"schema":1,"proxies":[],"rules":[]});
    let observed =
        apply(&stand, push(1, vec![], Some(json!({"mieru":egress(document.clone(),"mieru_native",1,None)})), None))
            .await;
    assert_eq!(observed.reconcile_state.as_str(), "failed");
    assert_eq!(observed.egress["mieru"].state.as_str(), "unsupported");
    assert_eq!(observed.egress["mieru"].error.as_deref(), Some("egress_unsupported"));
    let observed =
        apply(&stand, push(2, vec![], Some(json!({"naive":egress(document,"mieru_native",1,None)})), None)).await;
    assert_eq!(observed.egress["naive"].state.as_str(), "unsupported");
    assert!(lock(&stand.events).is_empty());
}
#[tokio::test]
async fn router_section_applies_router_then_native_attach() {
    let stand = stand();
    let observed = apply(
        &stand,
        push(1, vec![], Some(json!({"naive":egress(warp_intent(),"xray_router",1,attach_document("naive"))})), None),
    )
    .await;
    assert_eq!(
        *lock(&stand.events),
        [format!("router:naive:{NODE}:1:router:naive"), format!("native:naive:{NODE}:1:egress:naive")]
    );
    assert_eq!(observed.reconcile_state.as_str(), "converged");
    let report = &observed.egress["naive"];
    assert_eq!(report.digest.as_deref(), Some(document_digest(&warp_intent()).as_str()));
    assert!(report.revision.is_some());
    assert_eq!(report.router.as_ref().unwrap()["digest"], document_digest(&warp_intent()));
    assert_eq!(lock(&stand.runtime.naive.state).document, attach_document("naive").unwrap());
    lock(&stand.events).clear();
    let observed = apply(
        &stand,
        push(2, vec![], Some(json!({"naive":egress(warp_intent(),"xray_router",1,attach_document("naive"))})), None),
    )
    .await;
    assert!(lock(&stand.events).is_empty());
    assert_eq!(observed.egress["naive"].state.as_str(), "converged");
}
#[tokio::test]
async fn native_section_with_companion_applies_native_then_router() {
    let stand = stand();
    apply(
        &stand,
        push(1, vec![], Some(json!({"naive":egress(warp_intent(),"xray_router",1,attach_document("naive"))})), None),
    )
    .await;
    lock(&stand.events).clear();
    let mut section = egress(direct(), "naive_native", 2, Some(router_direct_intent()));
    section["passthrough"] = json!(true);
    let observed = apply(&stand, push(2, vec![], Some(json!({"naive":section})), None)).await;
    assert_eq!(
        *lock(&stand.events),
        [format!("native:naive:{NODE}:2:egress:naive"), format!("router:naive:{NODE}:2:router:naive")]
    );
    assert_eq!(lock(&stand.runtime.naive.state).document, direct());
    assert_eq!(lock(&stand.router.state).documents["naive"], router_direct_intent());
    assert_eq!(observed.egress["naive"].digest.as_deref(), Some(document_digest(&direct()).as_str()));
    assert_eq!(observed.egress["naive"].router.as_ref().unwrap()["digest"], document_digest(&router_direct_intent()));
}
#[tokio::test]
async fn router_section_without_router_is_unsupported_and_native_untouched() {
    let stand = stand();
    *lock(&stand.runtime.router) = None;
    let observed = apply(
        &stand,
        push(1, vec![], Some(json!({"naive":egress(warp_intent(),"xray_router",1,attach_document("naive"))})), None),
    )
    .await;
    assert_eq!(observed.reconcile_state.as_str(), "failed");
    assert_eq!(observed.egress["naive"].error.as_deref(), Some("router_unavailable"));
    assert_eq!(observed.egress["naive"].state.as_str(), "failed");
    assert_eq!(lock(&stand.runtime.naive.state).document, direct());
    assert!(lock(&stand.events).is_empty());
}
#[tokio::test]
async fn router_apply_failure_marks_failed_but_native_untouched() {
    let stand = stand();
    lock(&stand.router.state).fail = Some(AdapterError::with_code("unknown geosite", "geosite_unknown"));
    let observed = apply(
        &stand,
        push(1, vec![], Some(json!({"naive":egress(warp_intent(),"xray_router",1,attach_document("naive"))})), None),
    )
    .await;
    assert_eq!(observed.reconcile_state.as_str(), "failed");
    assert_eq!(observed.egress["naive"].error.as_deref(), Some("geosite_unknown"));
    assert_eq!(lock(&stand.runtime.naive.state).document, direct());
    assert!(lock(&stand.events).iter().all(|event| !event.starts_with("native:")));
}
#[tokio::test]
async fn identity_reports_router_capability_and_attachment() {
    let stand = stand();
    let identity = stand.node.identity().await.unwrap();
    for capability in ["egress.router.v1", "egress.lanes.v1", "relay.v1"] {
        assert!(identity["capabilities"].as_array().unwrap().contains(&json!(capability)));
    }
    assert_eq!(identity["router"]["available"], true);
    assert!(identity["router"]["xray_version"].as_str().unwrap().starts_with("Xray"));
    assert!(identity["router"]["capabilities"].as_array().unwrap().contains(&json!("block_geosite")));
    assert_eq!(identity["router"]["services"]["naive"]["applied_digest"], document_digest(&router_direct_intent()));
    assert_eq!(identity["protocols"]["naive"]["egress"]["router_attached"], false);
    assert_eq!(identity["router"]["lanes"], json!({"naive":[],"mieru":[]}));
    assert_eq!(identity["router"]["relay"]["enabled"], false);
    assert!(!serde_json::to_string(&identity).unwrap().contains("socks5://"));
    apply(
        &stand,
        push(1, vec![], Some(json!({"naive":egress(warp_intent(),"xray_router",1,attach_document("naive"))})), None),
    )
    .await;
    assert_eq!(stand.node.identity().await.unwrap()["protocols"]["naive"]["egress"]["router_attached"], true);
}
#[tokio::test]
async fn relay_section_enables_the_relay_and_sets_accounts_before_the_egress() {
    let stand = stand();
    let sections = Some(json!({"naive":egress(warp_intent(),"xray_router",1,attach_document("naive"))}));
    let observed = apply(&stand, push(1, vec![], sections.clone(), Some(relay(false, true)))).await;
    assert_eq!(
        &lock(&stand.events)[..3],
        ["relay_enable", "relay_accounts", &format!("router:naive:{NODE}:1:router:naive")]
    );
    let report = observed.relay.as_ref().unwrap();
    assert_eq!(report.state.as_str(), "converged");
    assert_eq!(report.accounts, [format!("relay:{MASTER}:direct")]);
    assert_eq!(report.public_key.as_deref(), Some("public-key"));
    assert_eq!(report.short_id.as_deref(), Some("0123abcd"));
    assert_eq!(report.port, Some(45443));
    assert_eq!(report.server_name.as_deref(), Some("node.example"));
    assert!(!observed.dump_json().contains(UUID));
    lock(&stand.events).clear();
    apply(&stand, push(2, vec![], sections, Some(relay(false, true)))).await;
    assert!(lock(&stand.events).is_empty());
    let observed = apply(&stand, push(3, vec![], None, None)).await;
    assert!(lock(&stand.events).is_empty());
    assert_eq!(observed.relay.unwrap().accounts, [format!("relay:{MASTER}:direct")]);
    let mut disabled = relay(false, false);
    disabled["accounts"] = json!([]);
    let observed = apply(&stand, push(4, vec![], None, Some(disabled))).await;
    assert!(!observed.relay.unwrap().enabled);
    assert_eq!(lock(&stand.router.state).relay["enabled"], false);
}
#[tokio::test]
async fn a_node_without_warp_carries_the_direct_account_and_reports_only_what_it_carries() {
    let stand = stand();
    lock(&stand.router.state).warp = false;
    let observed = apply(&stand, push(1, vec![], None, Some(relay(true, true)))).await;
    assert_eq!(observed.reconcile_state.as_str(), "converged");
    assert_eq!(observed.relay.unwrap().accounts, [format!("relay:{MASTER}:direct")]);
    assert_eq!(lock(&stand.router.state).accounts, vec![json!({"email":format!("relay:{MASTER}:direct"),"uuid":UUID})]);
    lock(&stand.events).clear();
    let observed = apply(&stand, push(2, vec![], None, Some(relay(true, true)))).await;
    assert!(lock(&stand.events).is_empty());
    assert_eq!(observed.relay.unwrap().accounts, [format!("relay:{MASTER}:direct")]);
}
#[tokio::test]
async fn relay_section_without_a_router_fails_the_generation() {
    let stand = stand();
    *lock(&stand.runtime.router) = None;
    let observed = apply(&stand, push(1, vec![], None, Some(relay(false, true)))).await;
    assert_eq!(observed.reconcile_state.as_str(), "failed");
    let report = observed.relay.unwrap();
    assert_eq!(report.state.as_str(), "failed");
    assert_eq!(report.error.as_deref(), Some("router_unavailable"));
}
#[tokio::test]
async fn a_resource_with_its_own_lane_gets_a_router_account_and_a_manager_lane_before_the_egress() {
    let stand = stand();
    let lane = "grant:g1";
    let resources = vec![resource("naive", "alice", lane, true)];
    let sections = Some(json!({"naive":egress(lane_intent(lane),"xray_router",1,attach_document("naive"))}));
    let observed = apply(&stand, push(1, resources.clone(), sections.clone(), None)).await;
    assert_eq!(observed.reconcile_state.as_str(), "converged");
    let events = lock(&stand.events).clone();
    let issue = events.iter().position(|event| event.starts_with("lane_issue:")).unwrap();
    let set = events.iter().position(|event| event == "set_lanes:naive").unwrap();
    let router_apply = events.iter().position(|event| event.starts_with("router:")).unwrap();
    assert!(issue < set && set < router_apply);
    assert_eq!(lock(&stand.runtime.lanes)["naive"][0]["users"], json!(["alice"]));
    assert_eq!(observed.egress["naive"].lanes, [lane]);
    assert!(!observed.dump_json().contains("lane-secret-password"));
    lock(&stand.events).clear();
    let observed = apply(&stand, push(2, resources, sections, None)).await;
    assert!(lock(&stand.events).is_empty());
    assert_eq!(observed.egress["naive"].lanes, [lane]);
    let observed = apply(
        &stand,
        push(
            3,
            vec![resource("naive", "alice", lane, false)],
            Some(json!({"naive":egress(warp_intent(),"xray_router",1,attach_document("naive"))})),
            None,
        ),
    )
    .await;
    assert!(lock(&stand.router.state).lanes["naive"].is_empty());
    assert_eq!(lock(&stand.runtime.lanes)["naive"], json!([]));
    assert!(observed.egress["naive"].lanes.is_empty());
}
#[tokio::test]
async fn a_mieru_lane_teaches_the_slot_ports_link_template_and_the_service_one_on_return() {
    let stand = stand();
    let lane = "grant:g2";
    let observed = apply(&stand, push(1, vec![resource("mieru", "phone", lane, true)], None, None)).await;
    assert_eq!(observed.reconcile_state.as_str(), "converged");
    let learned = observed.resources[0].learned["share_template"].to_value();
    assert!(learned.as_str().unwrap().ends_with("port=46102&protocol=TCP&mtu=1400"));
    let observed = apply(&stand, push(2, vec![resource("mieru", "phone", lane, false)], None, None)).await;
    let learned = observed.resources[0].learned["share_template"].to_value();
    assert!(learned.as_str().unwrap().contains("port=8443") && learned.as_str().unwrap().contains("{password}"));
}
#[tokio::test]
async fn a_lane_the_manager_refuses_fails_its_resource_and_leaves_the_router_clean() {
    let stand = stand();
    *lock(&stand.runtime.lane_failure) = Some(AdapterError::with_code("invalid lanes", "lanes_invalid"));
    let observed = apply(&stand, push(1, vec![resource("naive", "alice", "grant:g1", true)], None, None)).await;
    assert_eq!(observed.reconcile_state.as_str(), "failed");
    assert_eq!(observed.resources[0].state.as_str(), "failed");
    assert_eq!(observed.resources[0].error.as_deref(), Some("lane: lanes_invalid"));
    assert!(lock(&stand.router.state).lanes["naive"].is_empty());
    assert_eq!(stand.base.runtime.naive.password("alice").as_deref(), Some("correct horse battery staple"));
}

#[test]
fn observed_egress_is_ignored_by_an_older_central_and_tolerates_new_fields() {
    let observed=ObservedGeneration::validate(&json!({"applied_generation":1,"digest":"d","reconcile_state":"converged","reported_at":1,"resources":[],"egress":{"naive":{"state":"converged","revision":"r","digest":"x","error":null,"future":1}}})).unwrap();
    assert_eq!(observed.egress["naive"].state.as_str(), "converged");
    assert_eq!(observed.egress["naive"].revision.as_deref(), Some("r"));
    let absent = ObservedGeneration::validate(
        &json!({"applied_generation":1,"digest":"d","reconcile_state":"converged","reported_at":1,"resources":[]}),
    )
    .unwrap();
    assert!(absent.egress.is_empty());
}
