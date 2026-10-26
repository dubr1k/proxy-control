//! Ports of `test_routing_service.py` and `test_routing_router_service.py` over Rust fakes.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use panel_clients::AuditContext;
use panel_core::clock::FakeClock;
use panel_core::db::Database;
use panel_managers::xray_router::ROUTER_CAPABILITIES;
use panel_model::clients::{AccessGrant, GrantIntent};
use panel_model::fleet::CredentialOrigin;
use panel_model::protocols::{
    AdapterError, AppliedDocument, AppliedEgress, AppliedGrant, BoxFuture, EgressMode, EgressTarget, GrantRef,
    ObservedInventory, Preflight, ProtocolAdapter, RouterTarget,
};
use panel_model::routing::document::{attach_document, document_digest, router_direct_intent};
use panel_model::routing::models::{
    backend_for, CompileStatus, PolicyInput, PolicyState, RoutingPolicy, LANE_SERVICE, ROUTER_BACKEND,
};
use panel_model::validate::Model;
use panel_model::{Backend, Protocol};
use panel_secrets::audit::Actor;
use serde_json::{json, Map, Value};

use crate::compiler;
use crate::error::RoutingFailure;
use crate::runtime::{GeodataAction, RoutingAdapters, RoutingRouter};
use crate::service::{
    router_target_from_identity, target_from_identity, RoutingService, ERROR_STATUS, GEODATA_REFUSALS,
};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "panel-routing-service-{label}-{}-{}",
            std::process::id(),
            panel_core::ids::token_hex(6)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct FakeAdapter {
    state: Arc<Mutex<AdapterState>>,
    events: Arc<Mutex<Vec<String>>>,
}

struct AdapterState {
    protocol: Protocol,
    target: EgressTarget,
    history: Vec<AppliedDocument>,
    calls: Vec<String>,
    broken: bool,
    fail_next: Option<AdapterError>,
    reachable: bool,
    router_configured: bool,
    router_reachable: bool,
    next_revision: u64,
    touch_db: Option<Database>,
}

impl FakeAdapter {
    fn new(protocol: Protocol, router: bool, events: Arc<Mutex<Vec<String>>>) -> Self {
        let backend = backend_for(protocol.as_str()).unwrap();
        let document = compiler::direct_document(backend);
        let capabilities: &[&str] = match protocol {
            Protocol::Naive => &["whole_direct", "whole_warp", "block_domain", "block_cidr"],
            Protocol::Mieru => {
                &["whole_direct", "whole_warp", "block_domain", "block_cidr", "selective_domain", "selective_cidr"]
            }
            _ => &["whole_direct"],
        };
        let mut target = EgressTarget::new(protocol.as_str(), backend, "r0");
        target.capabilities = capabilities.iter().map(|cell| cell.to_string()).collect();
        target.providers.insert("warp".into(), json!({"reachable": true}));
        if router {
            target.providers.insert("router".into(), json!({"reachable": true}));
        }
        target.applied = Some(AppliedDocument { revision: "r0".into(), digest: document_digest(&document), document });
        Self {
            state: Arc::new(Mutex::new(AdapterState {
                protocol,
                target,
                history: Vec::new(),
                calls: Vec::new(),
                broken: false,
                fail_next: None,
                reachable: true,
                router_configured: router,
                router_reachable: true,
                next_revision: 1,
                touch_db: None,
            })),
            events,
        }
    }

    fn state(&self) -> MutexGuard<'_, AdapterState> {
        lock(&self.state)
    }

    fn fail_next(&self, code: &str) {
        self.state().fail_next = Some(AdapterError::with_code(format!("manager refused: {code}"), code));
    }

    fn fail_with(&self, error: AdapterError) {
        self.state().fail_next = Some(error);
    }

    fn adopt(&self, document: Value) {
        let mut state = self.state();
        let revision = state.target.revision.clone();
        state.target.applied = Some(AppliedDocument { revision, digest: document_digest(&document), document });
        state.target.router_attached = false;
        state.target.mode = EgressMode::Custom;
    }

    fn take_error(state: &mut AdapterState) -> Result<(), AdapterError> {
        if state.broken {
            return Err(AdapterError::with_code("manager is down", "manager_unavailable"));
        }
        if let Some(error) = state.fail_next.take() {
            return Err(error);
        }
        Ok(())
    }

    fn applied(state: &AdapterState, replayed: bool) -> AppliedEgress {
        AppliedEgress {
            revision: state.target.revision.clone(),
            digest: state.target.applied.as_ref().map(|applied| applied.digest.clone()),
            readback_sha256: Some("readback".into()),
            replayed,
        }
    }

    fn grant_error<T>() -> Result<T, AdapterError> {
        Err(AdapterError::new("grant operations are outside routing service tests"))
    }
}

impl ProtocolAdapter for FakeAdapter {
    fn protocol(&self) -> Protocol {
        self.state().protocol
    }
    fn credential_origin(&self) -> CredentialOrigin {
        CredentialOrigin::Caller
    }
    fn capture_supported(&self) -> bool {
        false
    }
    fn accepts_caller_credential(&self) -> bool {
        true
    }
    fn discover(&self) -> BoxFuture<'_, Result<ObservedInventory, AdapterError>> {
        Box::pin(async { Ok(ObservedInventory::default()) })
    }
    fn preflight<'a>(&'a self, _intent: &'a GrantIntent) -> BoxFuture<'a, Result<Preflight, AdapterError>> {
        Box::pin(async { Self::grant_error() })
    }
    fn create<'a>(
        &'a self,
        _operation_id: &'a str,
        _intent: &'a GrantIntent,
        _credential: &'a panel_model::protocols::CredentialPlan,
    ) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        Box::pin(async { Self::grant_error() })
    }
    fn enable<'a>(&'a self, _grant: &'a GrantRef) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        Box::pin(async { Self::grant_error() })
    }
    fn disable<'a>(&'a self, _grant: &'a GrantRef) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        Box::pin(async { Self::grant_error() })
    }
    fn rotate<'a>(
        &'a self,
        _operation_id: &'a str,
        _grant: &'a GrantRef,
        _credential: &'a panel_model::protocols::CredentialPlan,
    ) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        Box::pin(async { Self::grant_error() })
    }
    fn delete<'a>(&'a self, _grant: &'a GrantRef) -> BoxFuture<'a, Result<(), AdapterError>> {
        Box::pin(async { Self::grant_error() })
    }
    fn capture<'a>(&'a self, _grant: &'a GrantRef) -> BoxFuture<'a, Result<Option<Vec<u8>>, AdapterError>> {
        Box::pin(async { Self::grant_error() })
    }
    fn update_options<'a>(
        &'a self,
        _grant: &'a GrantRef,
        _options: &'a Map<String, Value>,
    ) -> BoxFuture<'a, Result<Option<AppliedGrant>, AdapterError>> {
        Box::pin(async { Self::grant_error() })
    }
    fn render_artifacts(
        &self,
        _grant: &AccessGrant,
        _credential: &[u8],
        _public_host: &str,
    ) -> Result<Vec<panel_model::protocols::AccessArtifact>, AdapterError> {
        Self::grant_error()
    }

    fn egress_target(&self) -> BoxFuture<'_, Result<Option<EgressTarget>, AdapterError>> {
        Box::pin(async {
            let state = self.state();
            if state.broken {
                return Err(AdapterError::with_code("manager is down", "manager_unavailable"));
            }
            let mut target = state.target.clone();
            target.providers.insert("warp".into(), json!({"reachable": state.reachable}));
            if state.router_configured {
                target.providers.insert("router".into(), json!({"reachable": state.router_reachable}));
            } else {
                target.providers.shift_remove("router");
            }
            Ok(Some(target))
        })
    }

    fn plan_egress<'a>(
        &'a self,
        _document: &'a Map<String, Value>,
        _expected_revision: &'a str,
    ) -> BoxFuture<'a, Result<Map<String, Value>, AdapterError>> {
        Box::pin(async {
            Self::take_error(&mut self.state())?;
            Ok(Map::new())
        })
    }

    fn apply_egress<'a>(
        &'a self,
        document: &'a Map<String, Value>,
        _expected_revision: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>> {
        Box::pin(async move {
            let mut state = self.state();
            if let Some(database) = state.touch_db.clone() {
                drop(state);
                database
                    .transaction(|db| {
                        let _: i64 = db.query_row("SELECT count(*) FROM routing_policies", [], |row| row.get(0))?;
                        Ok::<(), panel_core::db::DbError>(())
                    })
                    .unwrap();
                state = self.state();
            }
            Self::take_error(&mut state)?;
            if state.calls.iter().any(|call| call == &format!("apply:{operation_id}")) {
                return Ok(Self::applied(&state, true));
            }
            if let Some(applied) = state.target.applied.clone() {
                state.history.push(applied);
            }
            let document = Value::Object(document.clone());
            let revision = format!("r{}", state.next_revision);
            state.next_revision += 1;
            state.target.revision = revision;
            state.target.applied = Some(AppliedDocument {
                revision: state.target.revision.clone(),
                digest: document_digest(&document),
                document: document.clone(),
            });
            state.target.mode = if document.get("upstream").is_some_and(|upstream| !upstream.is_null()) {
                EgressMode::Proxy
            } else {
                EgressMode::Direct
            };
            state.target.router_attached =
                panel_model::routing::document::attached_to_router(state.protocol.as_str(), &document);
            state.calls.push(format!("apply:{operation_id}"));
            lock(&self.events).push(format!("native:{}", state.protocol.as_str()));
            Ok(Self::applied(&state, false))
        })
    }

    fn rollback_egress<'a>(
        &'a self,
        _expected_revision: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>> {
        Box::pin(async {
            let mut state = self.state();
            Self::take_error(&mut state)?;
            let Some(previous) = state.history.pop() else {
                return Err(AdapterError::with_code("no previous egress", "egress_no_previous"));
            };
            state.target.revision = previous.revision.clone();
            state.target.applied = Some(previous.clone());
            state.target.router_attached =
                panel_model::routing::document::attached_to_router(state.protocol.as_str(), &previous.document);
            Ok(Self::applied(&state, false))
        })
    }
}

#[derive(Clone)]
struct FakeAdapters {
    naive: FakeAdapter,
    mieru: FakeAdapter,
    mtproxy: FakeAdapter,
}

impl RoutingAdapters for FakeAdapters {
    fn adapter(&self, protocol: Protocol) -> Option<Arc<dyn ProtocolAdapter>> {
        match protocol {
            Protocol::Naive => Some(Arc::new(self.naive.clone())),
            Protocol::Mieru => Some(Arc::new(self.mieru.clone())),
            Protocol::Mtproxy => Some(Arc::new(self.mtproxy.clone())),
            _ => None,
        }
    }

    fn set_lanes<'a>(&'a self, _protocol: Protocol, _lanes: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async { Ok(Value::Null) })
    }
}

#[derive(Clone)]
struct FakeRouter {
    state: Arc<Mutex<RouterState>>,
    events: Arc<Mutex<Vec<String>>>,
}

struct RouterState {
    available: bool,
    artifact_error: bool,
    fail_next: Option<String>,
    documents: BTreeMap<String, Value>,
    history: BTreeMap<String, Vec<AppliedDocument>>,
    revision: BTreeMap<String, String>,
    calls: Vec<String>,
    next_revision: u64,
}

impl FakeRouter {
    fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        let documents = ["naive", "mieru", "mtproxy"]
            .into_iter()
            .map(|service| (service.to_string(), router_direct_intent()))
            .collect();
        let revision = ["naive", "mieru", "mtproxy"]
            .into_iter()
            .map(|service| (service.to_string(), "router0".to_string()))
            .collect();
        Self {
            state: Arc::new(Mutex::new(RouterState {
                available: true,
                artifact_error: false,
                fail_next: None,
                documents,
                history: BTreeMap::new(),
                revision,
                calls: Vec::new(),
                next_revision: 1,
            })),
            events,
        }
    }

    fn state(&self) -> MutexGuard<'_, RouterState> {
        lock(&self.state)
    }

    fn fail_next(&self, code: &str) {
        self.state().fail_next = Some(code.into());
    }

    fn take_error(state: &mut RouterState) -> Result<(), AdapterError> {
        if state.artifact_error {
            return Err(AdapterError::with_code("router artifact differs", "artifact_mismatch"));
        }
        if let Some(code) = state.fail_next.take() {
            return Err(AdapterError::with_code(format!("router refused: {code}"), code));
        }
        Ok(())
    }

    fn applied(state: &RouterState, service: &str, replayed: bool) -> AppliedEgress {
        let document = state.documents.get(service).unwrap();
        AppliedEgress {
            revision: state.revision.get(service).cloned().unwrap_or_default(),
            digest: Some(document_digest(document)),
            readback_sha256: Some("router-readback".into()),
            replayed,
        }
    }
}

impl RoutingRouter for FakeRouter {
    fn target<'a>(&'a self, service: &'a str) -> BoxFuture<'a, RouterTarget> {
        Box::pin(async move {
            let state = self.state();
            if !state.available || state.artifact_error {
                return RouterTarget::unavailable(
                    service,
                    if state.artifact_error { "artifact_mismatch" } else { "router_unavailable" },
                );
            }
            let document = state.documents.get(service).cloned().unwrap_or_else(router_direct_intent);
            RouterTarget {
                available: true,
                service: service.into(),
                capabilities: ROUTER_CAPABILITIES.iter().map(|cell| cell.to_string()).collect(),
                providers: json!({"warp": {"reachable": true}}).as_object().unwrap().clone(),
                revision: state.revision.get(service).cloned().unwrap_or_default(),
                applied: Some(AppliedDocument {
                    revision: state.revision.get(service).cloned().unwrap_or_default(),
                    digest: document_digest(&document),
                    document,
                }),
                xray_version: Some("Xray 26.3.27 (memory)".into()),
                restart_required: true,
                reason: None,
            }
        })
    }

    fn plan<'a>(
        &'a self,
        _service: &'a str,
        _document: &'a Value,
        _expected_revision: &'a str,
    ) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async {
            Self::take_error(&mut self.state())?;
            Ok(Value::Null)
        })
    }

    fn apply<'a>(
        &'a self,
        service: &'a str,
        document: &'a Value,
        _expected_revision: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>> {
        Box::pin(async move {
            let mut state = self.state();
            Self::take_error(&mut state)?;
            if state.calls.iter().any(|call| call == &format!("apply:{operation_id}")) {
                return Ok(Self::applied(&state, service, true));
            }
            let old = state.documents.get(service).cloned().unwrap_or_else(router_direct_intent);
            let previous_revision = state.revision.get(service).cloned().unwrap_or_default();
            state.history.entry(service.into()).or_default().push(AppliedDocument {
                revision: previous_revision,
                digest: document_digest(&old),
                document: old,
            });
            let revision = format!("router{}", state.next_revision);
            state.next_revision += 1;
            state.revision.insert(service.into(), revision);
            state.documents.insert(service.into(), document.clone());
            state.calls.push(format!("apply:{operation_id}"));
            lock(&self.events).push(format!("router:{service}"));
            Ok(Self::applied(&state, service, false))
        })
    }

    fn rollback<'a>(
        &'a self,
        service: &'a str,
        _expected_revision: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>> {
        Box::pin(async move {
            let mut state = self.state();
            Self::take_error(&mut state)?;
            let Some(previous) = state.history.entry(service.into()).or_default().pop() else {
                return Err(AdapterError::with_code("no previous intent", "egress_no_previous"));
            };
            state.revision.insert(service.into(), previous.revision.clone());
            state.documents.insert(service.into(), previous.document);
            state.calls.push(format!("rollback:{service}"));
            Ok(Self::applied(&state, service, false))
        })
    }

    fn lane_issue<'a>(&'a self, _service: &'a str, _lane: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async { Err(AdapterError::new("lanes are outside this test stand")) })
    }
    fn lane_forget<'a>(&'a self, _service: &'a str, _lane: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async { Ok(Value::Null) })
    }
    fn relay(&self) -> BoxFuture<'_, Option<Value>> {
        Box::pin(async { None })
    }
    fn relay_enable<'a>(&'a self, _server_name: &'a str, _port: i64) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async { Err(AdapterError::new("relay is outside this test stand")) })
    }
    fn relay_set_accounts<'a>(&'a self, _accounts: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async { Ok(Value::Null) })
    }
    fn exit_test<'a>(&'a self, _spec: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async { Err(AdapterError::new("exits are outside this test stand")) })
    }
    fn geodata<'a>(
        &'a self,
        _action: GeodataAction,
        _body: Option<&'a Value>,
    ) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async { Err(AdapterError::new("geodata is outside this test stand")) })
    }
}

struct Stand {
    _scratch: Scratch,
    database: Database,
    service: RoutingService,
    clock: Arc<FakeClock>,
    naive: FakeAdapter,
    mieru: FakeAdapter,
    router: Option<FakeRouter>,
    enabled: Arc<Mutex<BTreeMap<String, bool>>>,
    events: Arc<Mutex<Vec<String>>>,
}

fn stand(label: &str, with_router: bool) -> Stand {
    let scratch = Scratch::new(label);
    let database = Database::open(scratch.0.join("panel.sqlite3")).unwrap();
    panel_core::migrations::apply_migrations(&database).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let naive = FakeAdapter::new(Protocol::Naive, with_router, events.clone());
    let mieru = FakeAdapter::new(Protocol::Mieru, with_router, events.clone());
    let mtproxy = FakeAdapter::new(Protocol::Mtproxy, with_router, events.clone());
    let adapters = FakeAdapters { naive: naive.clone(), mieru: mieru.clone(), mtproxy: mtproxy.clone() };
    let router = with_router.then(|| FakeRouter::new(events.clone()));
    let enabled = Arc::new(Mutex::new(BTreeMap::from([("naive".into(), true), ("mieru".into(), true)])));
    let switch = enabled.clone();
    let clock = Arc::new(FakeClock::default());
    let service = RoutingService::new(
        database.clone(),
        Arc::new(adapters),
        Arc::new(move |protocol: &str| lock(&switch).get(protocol).copied().unwrap_or(true)),
        None,
        None,
        clock.clone(),
        router.clone().map(|router| Arc::new(router) as Arc<dyn RoutingRouter>),
        None,
        "local",
        "",
        Arc::new(crate::lanes::local_only),
        None,
    );
    Stand { _scratch: scratch, database, service, clock, naive, mieru, router, enabled, events }
}

fn context() -> AuditContext {
    AuditContext::new(Actor::new(Some(1), "owner"), "127.0.0.1", Some("req-1".into()))
}

fn input(value: Value) -> PolicyInput {
    PolicyInput::validate(&value).unwrap()
}

fn warp() -> PolicyInput {
    input(json!({"default_action": "egress", "default_egress": "warp"}))
}

fn block(domains: &[&str]) -> PolicyInput {
    input(json!({"rules": [{"match": {"domains": domains}, "action": "block"}]}))
}

fn save(service: &RoutingService, protocol: &str, draft: &PolicyInput, expected: Option<i64>) -> RoutingPolicy {
    service.save("local", protocol, draft, expected, LANE_SERVICE, &context()).unwrap()
}

async fn apply(service: &RoutingService, protocol: &str, revision: i64) -> crate::service::RoutingOutcome {
    service.apply("local", protocol, revision, LANE_SERVICE, &context()).await.unwrap()
}

fn refusal(error: RoutingFailure) -> (u16, String) {
    let refusal = error.refusal().expect("expected an API refusal");
    (refusal.status, refusal.code.clone())
}

fn audits(database: &Database, action: &str) -> Vec<(String, Map<String, Value>)> {
    database
        .with_connection(|db| {
            let rows = db
                .prepare("SELECT target, detail_json FROM audit_log WHERE action=? ORDER BY id")?
                .query_map([action], |row| {
                    Ok((row.get::<_, String>(0)?, serde_json::from_str(&row.get::<_, String>(1)?).unwrap()))
                })?
                .collect::<panel_core::rusqlite::Result<Vec<(String, Map<String, Value>)>>>()?;
            Ok::<_, RoutingFailure>(rows)
        })
        .unwrap()
}

fn item<'a>(items: &'a [Map<String, Value>], protocol: &str) -> &'a Map<String, Value> {
    items.iter().find(|item| item.get("protocol").and_then(Value::as_str) == Some(protocol)).unwrap()
}

#[test]
fn linked_identity_becomes_digest_only_targets() {
    let entry = json!({"backend": "naive_native", "capabilities": ["whole_direct", 7, "whole_warp"],
        "providers": {"warp": {"reachable": true, "address": "never copied"}}, "revision": "r7",
        "applied_digest": "abc", "mode": "proxy", "restart_required": true, "router_attached": true});
    let target = target_from_identity("naive", entry.as_object()).unwrap();
    assert_eq!(target.backend, Backend::NaiveNative);
    assert_eq!(target.mode, EgressMode::Proxy);
    assert_eq!(target.applied.unwrap().document, Value::Null);
    assert_eq!(target.providers, json!({"warp": {"reachable": true}}).as_object().unwrap().clone());
}

#[test]
fn linked_router_reports_missing_service_generations() {
    let router = json!({"available": true, "services": {"naive": {}}});
    for (protocol, reason) in [
        ("mtproxy", "router_lacks_mtproxy"),
        ("trusttunnel", "router_lacks_trusttunnel"),
        ("amneziawg", "router_lacks_amneziawg"),
    ] {
        assert_eq!(router_target_from_identity(protocol, router.as_object()).unwrap().reason.as_deref(), Some(reason));
    }
    assert!(router_target_from_identity("naive", router.as_object()).unwrap().available);
}

#[test]
fn refusal_tables_keep_python_statuses() {
    assert_eq!(
        ERROR_STATUS,
        [("manual_intervention_required", 503), ("manager_unavailable", 502), ("artifact_mismatch", 503)]
    );
    assert_eq!(GEODATA_REFUSALS, ["geodata_invalid", "geodata_corrupt", "geodata_rejected", "geodata_busy"]);
}

#[tokio::test]
async fn targets_lists_local_protocols_with_backends_and_mtproxy_direct_only() {
    let stand = stand("targets", false);
    stand.mieru.state().reachable = false;
    save(&stand.service, "naive", &warp(), None);
    let items = stand.service.targets().await.unwrap();
    assert_eq!(
        items.iter().map(|item| item["protocol"].as_str().unwrap()).collect::<Vec<_>>(),
        ["mtproxy", "naive", "mieru", "trusttunnel", "amneziawg"]
    );
    assert_eq!(item(&items, "amneziawg")["reason"], "protocol_disabled_on_node");
    assert_eq!(item(&items, "trusttunnel")["reason"], "protocol_disabled_on_node");
    assert_eq!(item(&items, "mtproxy")["backend"], "mtproxy_native");
    assert_eq!(item(&items, "naive")["policy"]["state"], "draft");
    assert_eq!(item(&items, "mieru")["providers"]["warp"]["reachable"], false);
    lock(&stand.enabled).insert("mieru".into(), false);
    assert_eq!(item(&stand.service.targets().await.unwrap(), "mieru")["reason"], "protocol_disabled_on_node");
    stand.naive.state().broken = true;
    assert_eq!(item(&stand.service.targets().await.unwrap(), "naive")["reason"], "manager_unavailable");
}

#[tokio::test]
async fn targets_say_whether_the_node_already_runs_the_policy() {
    let stand = stand("matches", false);
    stand.naive.adopt(json!({"schema": 1, "upstream": {"provider": "warp"}, "acl": []}));
    save(&stand.service, "naive", &warp(), None);
    save(&stand.service, "mieru", &warp(), None);
    let items = stand.service.targets().await.unwrap();
    assert_eq!(item(&items, "naive")["policy"]["matches_node"], true);
    assert_eq!(item(&items, "mieru")["policy"]["matches_node"], false);
    apply(&stand.service, "mieru", 1).await;
    assert_eq!(item(&stand.service.targets().await.unwrap(), "mieru")["policy"]["matches_node"], true);
    stand.mieru.adopt(json!({"schema": 1, "proxies": [], "rules": []}));
    assert_eq!(item(&stand.service.targets().await.unwrap(), "mieru")["policy"]["matches_node"], false);
    stand.naive.state().broken = true;
    assert_eq!(item(&stand.service.targets().await.unwrap(), "naive")["policy"]["matches_node"], Value::Null);
}

#[tokio::test]
async fn preview_of_a_draft_never_saves_and_reports_unsupported_rules() {
    let stand = stand("preview", false);
    assert_eq!(
        refusal(stand.service.preview("local", "naive", None, LANE_SERVICE).await.unwrap_err()),
        (404, "policy_not_found".into())
    );
    let draft = input(json!({"rules": [{"match": {"domains": ["a.com"]}, "action": "egress", "egress": "warp"}]}));
    let naive = stand.service.preview("local", "naive", Some(draft.clone()), LANE_SERVICE).await.unwrap();
    assert_eq!(naive.status, CompileStatus::Unsupported);
    assert_eq!(naive.reasons[0].code, "backend_capability_missing");
    assert_eq!(
        stand.service.preview("local", "mieru", Some(draft.clone()), LANE_SERVICE).await.unwrap().status,
        CompileStatus::Supported
    );
    assert_eq!(
        stand.service.preview("local", "mtproxy", Some(draft.clone()), LANE_SERVICE).await.unwrap().reasons[0].code,
        "not_attached"
    );
    assert_eq!(
        refusal(stand.service.preview("local", "socks", Some(draft.clone()), LANE_SERVICE).await.unwrap_err()),
        (422, "protocol_out_of_scope".into())
    );
    assert_eq!(
        refusal(stand.service.preview("ghost", "naive", Some(draft.clone()), LANE_SERVICE).await.unwrap_err()),
        (404, "node_not_found".into())
    );
    let wrong = input(json!({"backend": "mieru_native"}));
    assert_eq!(
        refusal(stand.service.preview("local", "naive", Some(wrong), LANE_SERVICE).await.unwrap_err()),
        (422, "backend_mismatch".into())
    );
    assert_eq!(
        refusal(stand.service.get("local", "naive", LANE_SERVICE).unwrap_err()),
        (404, "policy_not_found".into())
    );
    stand.naive.state().broken = true;
    assert_eq!(
        stand.service.preview("local", "naive", Some(draft), LANE_SERVICE).await.unwrap().reasons[0].code,
        "manager_unavailable"
    );
}

#[tokio::test]
async fn apply_local_calls_manager_and_records_applied() {
    let stand = stand("apply-local", false);
    let policy = save(&stand.service, "naive", &warp(), None);
    let result = apply(&stand.service, "naive", 1).await;
    assert_eq!(result.policy.state, PolicyState::Applied);
    assert_eq!(result.policy.applied_revision, Some(1));
    assert_eq!(result.policy.applied_digest, result.compiled.digest);
    assert_eq!(result.applied.as_ref().unwrap().digest, result.compiled.digest);
    assert!(stand.naive.state().calls.contains(&format!("apply:routing:{}:1", policy.id)));
    let history = stand.service.history("local", "naive", LANE_SERVICE).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["outcome"], "applied");
    let detail = audits(&stand.database, "routing.policy.apply");
    assert_eq!(detail[0].1["manager_revision"], result.applied.as_ref().unwrap().revision.as_str());
    let again = apply(&stand.service, "naive", 1).await;
    assert!(again.applied.unwrap().replayed);
    assert!(stand.service.preview("local", "naive", None, LANE_SERVICE).await.unwrap().diff.is_empty());
    let edited = save(&stand.service, "naive", &block(&["x.example"]), Some(1));
    assert_eq!(edited.revision, 2);
    assert!(!edited.applied_current());
}

#[tokio::test]
async fn apply_unsupported_is_422_without_manager_call() {
    let stand = stand("apply-unsupported", false);
    let mut draft = warp();
    draft.intent.rules = block(&["a.com"]).intent.rules;
    save(&stand.service, "naive", &draft, None);
    let error = stand.service.apply("local", "naive", 1, LANE_SERVICE, &context()).await.unwrap_err();
    assert_eq!(refusal(error), (422, "unsupported".into()));
    assert!(stand.naive.state().calls.is_empty());
    assert_eq!(stand.service.get("local", "naive", LANE_SERVICE).unwrap().state, PolicyState::Draft);
    assert_eq!(
        refusal(stand.service.apply("local", "naive", 7, LANE_SERVICE, &context()).await.unwrap_err()),
        (409, "policy_conflict".into())
    );
}

#[tokio::test]
async fn apply_manager_conflict_marks_failed() {
    let stand = stand("apply-failure", false);
    save(&stand.service, "naive", &warp(), None);
    stand.naive.fail_next("egress_readback_mismatch");
    assert_eq!(
        refusal(stand.service.apply("local", "naive", 1, LANE_SERVICE, &context()).await.unwrap_err()),
        (409, "egress_readback_mismatch".into())
    );
    let failed = stand.service.get("local", "naive", LANE_SERVICE).unwrap();
    assert_eq!(failed.state, PolicyState::Failed);
    assert_eq!(failed.last_error.as_deref(), Some("egress_readback_mismatch"));
    stand.naive.fail_next("manual_intervention_required");
    assert_eq!(refusal(stand.service.apply("local", "naive", 1, LANE_SERVICE, &context()).await.unwrap_err()).0, 503);
    stand.naive.state().broken = true;
    assert_eq!(
        refusal(stand.service.apply("local", "naive", 1, LANE_SERVICE, &context()).await.unwrap_err()),
        (502, "manager_unavailable".into())
    );
}

#[tokio::test]
async fn apply_runtime_crash_escapes_without_history_audit_or_failed_state() {
    let stand = stand("apply-crash", false);
    save(&stand.service, "naive", &warp(), None);
    stand.naive.fail_with(panel_protocols::error::crash("unexpected manager answer"));
    let error = stand.service.apply("local", "naive", 1, LANE_SERVICE, &context()).await.unwrap_err();
    assert!(matches!(error, RoutingFailure::Manager { protocol: Protocol::Naive, .. }));
    assert!(error.app_error().is_none());
    let policy = stand.service.get("local", "naive", LANE_SERVICE).unwrap();
    assert_eq!(policy.state, PolicyState::Draft);
    assert_eq!(policy.last_error, None);
    let (applies, audit_rows) = stand
        .database
        .with_connection(|db| {
            let applies = db.query_row("SELECT count(*) FROM routing_applies", [], |row| row.get::<_, i64>(0))?;
            let audit_rows =
                db.query_row("SELECT count(*) FROM audit_log WHERE action='routing.policy.apply'", [], |row| {
                    row.get::<_, i64>(0)
                })?;
            Ok::<_, panel_core::db::DbError>((applies, audit_rows))
        })
        .unwrap();
    assert_eq!((applies, audit_rows), (0, 0));
}

#[tokio::test]
async fn escaped_manager_failure_keeps_protocol_status_and_does_not_mark_failed() {
    for (protocol, manager, detail) in [
        (Protocol::Naive, panel_managers::Manager::Naive, "NaiveProxy manager unavailable"),
        (Protocol::Mieru, panel_managers::Manager::Mieru, "Mieru manager unavailable"),
    ] {
        let stand = stand(protocol.as_str(), false);
        save(&stand.service, protocol.as_str(), &warp(), None);
        let adapter = if protocol == Protocol::Naive { &stand.naive } else { &stand.mieru };
        adapter.fail_with(panel_protocols::error::raw_manager(panel_managers::ManagerError::new(
            manager,
            "manager refused",
            422,
            None,
        )));
        let error = stand.service.apply("local", protocol.as_str(), 1, LANE_SERVICE, &context()).await.unwrap_err();
        let answer = error.app_error().expect("manager handler");
        assert_eq!(answer.status(), 422);
        assert_eq!(serde_json::from_slice::<Value>(&answer.body_bytes()).unwrap(), json!({"detail": detail}));
        assert_eq!(stand.service.get("local", protocol.as_str(), LANE_SERVICE).unwrap().state, PolicyState::Draft);
        assert!(stand.service.history("local", protocol.as_str(), LANE_SERVICE).unwrap().is_empty());
    }
}

#[tokio::test]
async fn apply_unreachable_provider_leaves_policy_unchanged() {
    let stand = stand("provider", false);
    save(&stand.service, "mieru", &block(&["a.example"]), None);
    apply(&stand.service, "mieru", 1).await;
    save(&stand.service, "mieru", &warp(), Some(1));
    stand.mieru.state().reachable = false;
    let error = stand.service.apply("local", "mieru", 2, LANE_SERVICE, &context()).await.unwrap_err();
    assert_eq!(error.refusal().unwrap().compiled.as_ref().unwrap().reasons[0].code, "provider_unreachable");
    stand.mieru.state().reachable = true;
    stand.mieru.fail_next("egress_unreachable");
    assert_eq!(
        refusal(stand.service.apply("local", "mieru", 2, LANE_SERVICE, &context()).await.unwrap_err()),
        (409, "egress_unreachable".into())
    );
    let policy = stand.service.get("local", "mieru", LANE_SERVICE).unwrap();
    assert_eq!(policy.applied_revision, Some(1));
    assert_eq!(policy.state, PolicyState::Failed);
}

#[tokio::test]
async fn rollback_local() {
    let stand = stand("rollback-local", false);
    assert_eq!(
        refusal(stand.service.rollback("local", "naive", 1, LANE_SERVICE, &context()).await.unwrap_err()).0,
        404
    );
    save(&stand.service, "naive", &block(&["a.example"]), None);
    let first = apply(&stand.service, "naive", 1).await;
    save(&stand.service, "naive", &warp(), Some(1));
    apply(&stand.service, "naive", 2).await;
    assert_eq!(
        refusal(stand.service.rollback("local", "naive", 1, LANE_SERVICE, &context()).await.unwrap_err()),
        (409, "policy_conflict".into())
    );
    let result = stand.service.rollback("local", "naive", 2, LANE_SERVICE, &context()).await.unwrap();
    assert_eq!(result.policy.state, PolicyState::RolledBack);
    assert_eq!(result.policy.applied_revision, Some(1));
    assert_eq!(result.applied.as_ref().unwrap().digest, first.applied.unwrap().digest);
    let floor = stand.service.rollback("local", "naive", 2, LANE_SERVICE, &context()).await.unwrap();
    assert_eq!(floor.policy.applied_revision, None);
    assert_eq!(
        refusal(stand.service.rollback("local", "naive", 2, LANE_SERVICE, &context()).await.unwrap_err()),
        (409, "egress_no_previous".into())
    );
}

#[tokio::test]
async fn delete_refuses_an_applied_policy_until_reset() {
    let stand = stand("delete", false);
    save(&stand.service, "mieru", &block(&["a.example"]), None);
    apply(&stand.service, "mieru", 1).await;
    assert_eq!(
        refusal(stand.service.delete("local", "mieru", LANE_SERVICE, &context()).unwrap_err()),
        (409, "policy_applied".into())
    );
    save(&stand.service, "mieru", &PolicyInput::default(), Some(1));
    assert!(stand.service.delete("local", "mieru", LANE_SERVICE, &context()).is_err());
    apply(&stand.service, "mieru", 2).await;
    stand.service.delete("local", "mieru", LANE_SERVICE, &context()).unwrap();
    save(&stand.service, "naive", &warp(), None);
    stand.service.delete("local", "naive", LANE_SERVICE, &context()).unwrap();
}

#[tokio::test]
async fn apply_io_outside_transaction() {
    let stand = stand("outside-transaction", false);
    stand.naive.state().touch_db = Some(stand.database.clone());
    save(&stand.service, "naive", &warp(), None);
    assert_eq!(apply(&stand.service, "naive", 1).await.policy.state, PolicyState::Applied);
}

#[tokio::test]
async fn targets_show_router_available_and_not_attached() {
    let stand = stand("router-targets", true);
    let items = stand.service.targets().await.unwrap();
    assert_eq!(
        item(&items, "naive")["router"],
        json!({"available": true, "attached": false,
        "xray_version": "Xray 26.3.27 (memory)", "restart_required": true, "reason": null})
    );
    assert_eq!(item(&items, "naive")["backend"], "naive_native");
    assert!(item(&items, "naive")["capabilities"].as_array().unwrap().iter().all(|cell| cell != "block_geosite"));
}

#[tokio::test]
async fn router_none_means_targets_report_no_router() {
    let stand = stand("router-none", false);
    assert_eq!(item(&stand.service.targets().await.unwrap(), "naive")["router"], Value::Null);
    assert_eq!(
        refusal(stand.service.attach("local", "naive", &context()).await.unwrap_err()),
        (409, "router_unavailable".into())
    );
}

#[tokio::test]
async fn attach_naive_applies_router_direct_then_native_upstream_and_retargets_policy() {
    let stand = stand("attach", true);
    save(&stand.service, "naive", &block(&["example.com"]), None);
    let item = stand.service.attach("local", "naive", &context()).await.unwrap();
    assert_eq!(item["backend"], "xray_router");
    assert_eq!(item["router"]["attached"], true);
    assert_eq!(item["policy"]["revision"], 2);
    assert_eq!(stand.naive.state().target.applied.as_ref().unwrap().document, attach_document("naive").unwrap());
    assert!(stand.router.as_ref().unwrap().state().calls.is_empty());
    let calls = stand.naive.state().calls.len();
    stand.service.attach("local", "naive", &context()).await.unwrap();
    assert_eq!(stand.naive.state().calls.len(), calls);
}

#[tokio::test]
async fn attach_creates_empty_draft_policy_when_none() {
    let stand = stand("attach-create", true);
    let item = stand.service.attach("local", "mieru", &context()).await.unwrap();
    assert_eq!(item["policy"]["revision"], 1);
    let policy = stand.service.get("local", "mieru", LANE_SERVICE).unwrap();
    assert_eq!(policy.backend, ROUTER_BACKEND);
    assert!(policy.intent.rules.is_empty());
}

#[tokio::test]
async fn attach_refuses_applied_native_policy_with_rules() {
    let stand = stand("attach-applied", true);
    save(&stand.service, "naive", &warp(), None);
    apply(&stand.service, "naive", 1).await;
    assert_eq!(
        refusal(stand.service.attach("local", "naive", &context()).await.unwrap_err()),
        (409, "policy_applied".into())
    );
}

#[tokio::test]
async fn attach_refuses_when_router_unreachable_from_manager_or_absent() {
    let stand = stand("attach-refusals", true);
    stand.naive.state().router_reachable = false;
    assert_eq!(
        refusal(stand.service.attach("local", "naive", &context()).await.unwrap_err()),
        (409, "router_unreachable".into())
    );
    stand.naive.state().router_reachable = true;
    stand.naive.state().router_configured = false;
    assert_eq!(
        refusal(stand.service.attach("local", "naive", &context()).await.unwrap_err()),
        (409, "router_unavailable".into())
    );
    stand.naive.state().router_configured = true;
    stand.router.as_ref().unwrap().state().artifact_error = true;
    assert_eq!(
        refusal(stand.service.attach("local", "naive", &context()).await.unwrap_err()),
        (503, "artifact_mismatch".into())
    );
    let router = stand.router.as_ref().unwrap();
    router.state().artifact_error = false;
    router.state().available = false;
    assert_eq!(
        refusal(stand.service.attach("local", "naive", &context()).await.unwrap_err()),
        (409, "router_unavailable".into())
    );
}

#[tokio::test]
async fn apply_router_policy_calls_router_and_records_applied() {
    let stand = stand("router-apply", true);
    stand.service.attach("local", "naive", &context()).await.unwrap();
    let mut draft = warp();
    draft.intent.rules = input(json!({"rules": [
        {"match": {"domains": ["example.com"]}, "action": "block"},
        {"match": {"geosites": ["category-ads-all"]}, "action": "block"}
    ]}))
    .intent
    .rules;
    save(&stand.service, "naive", &draft, Some(1));
    let result = apply(&stand.service, "naive", 2).await;
    assert_eq!(result.compiled.backend.as_deref(), Some("xray_router"));
    assert_eq!(result.compiled.attach, attach_document("naive"));
    assert_eq!(result.policy.state, PolicyState::Applied);
    assert_eq!(
        stand.service.history("local", "naive", LANE_SERVICE).unwrap()[0]["runtime_version"],
        "Xray 26.3.27 (memory)"
    );
}

#[tokio::test]
async fn apply_router_policy_on_detached_service_is_409_not_attached() {
    let stand = stand("not-attached", true);
    save(
        &stand.service,
        "naive",
        &input(json!({"backend": "xray_router", "default_action": "egress", "default_egress": "warp"})),
        None,
    );
    let error = stand.service.apply("local", "naive", 1, LANE_SERVICE, &context()).await.unwrap_err();
    assert_eq!(refusal(error), (409, "not_attached".into()));
    assert!(stand.router.as_ref().unwrap().state().calls.is_empty());
}

#[tokio::test]
async fn native_block_drift_shows_detached() {
    let stand = stand("drift", true);
    stand.service.attach("local", "naive", &context()).await.unwrap();
    stand.naive.adopt(json!({"schema": 1, "upstream": null, "acl": []}));
    let items = stand.service.targets().await.unwrap();
    assert_eq!(item(&items, "naive")["router"]["attached"], false);
    assert_eq!(item(&items, "naive")["policy"]["backend"], "xray_router");
    save(
        &stand.service,
        "naive",
        &input(json!({"backend": "xray_router", "default_action": "egress", "default_egress": "warp"})),
        Some(1),
    );
    assert_eq!(
        refusal(stand.service.apply("local", "naive", 2, LANE_SERVICE, &context()).await.unwrap_err()),
        (409, "not_attached".into())
    );
    // A second operator action has a fresh operation id, not the original attach's replay.
    stand.clock.advance(1.0);
    stand.service.attach("local", "naive", &context()).await.unwrap();
    apply(&stand.service, "naive", 2).await;
    assert_eq!(stand.service.get("local", "naive", LANE_SERVICE).unwrap().state, PolicyState::Applied);
}

#[tokio::test]
async fn apply_router_failure_marks_failed_and_maps_codes() {
    let stand = stand("router-failure", true);
    stand.service.attach("local", "naive", &context()).await.unwrap();
    save(&stand.service, "naive", &block(&["example.com"]), Some(1));
    stand.router.as_ref().unwrap().fail_next("geosite_unknown");
    assert_eq!(
        refusal(stand.service.apply("local", "naive", 2, LANE_SERVICE, &context()).await.unwrap_err()),
        (409, "geosite_unknown".into())
    );
    assert_eq!(stand.service.get("local", "naive", LANE_SERVICE).unwrap().state, PolicyState::Failed);
    stand.router.as_ref().unwrap().fail_next("manual_intervention_required");
    assert_eq!(refusal(stand.service.apply("local", "naive", 2, LANE_SERVICE, &context()).await.unwrap_err()).0, 503);
}

#[tokio::test]
async fn rollback_router_policy() {
    let stand = stand("router-rollback", true);
    stand.service.attach("local", "naive", &context()).await.unwrap();
    save(&stand.service, "naive", &warp(), Some(1));
    apply(&stand.service, "naive", 2).await;
    save(&stand.service, "naive", &block(&["example.com"]), Some(2));
    apply(&stand.service, "naive", 3).await;
    let result = stand.service.rollback("local", "naive", 3, LANE_SERVICE, &context()).await.unwrap();
    assert_eq!(result.policy.applied_revision, Some(2));
    assert_eq!(stand.router.as_ref().unwrap().state().documents["naive"]["default"]["action"], "egress");
}

#[tokio::test]
async fn detach_applies_native_direct_then_router_direct() {
    let stand = stand("detach", true);
    stand.service.attach("local", "naive", &context()).await.unwrap();
    save(&stand.service, "naive", &warp(), Some(1));
    apply(&stand.service, "naive", 2).await;
    lock(&stand.events).clear();
    let item = stand.service.detach("local", "naive", &context()).await.unwrap();
    assert_eq!(item["backend"], "naive_native");
    assert_eq!(item["policy"]["state"], "draft");
    assert_eq!(lock(&stand.events).as_slice(), ["native:naive", "router:naive"]);
    assert_eq!(stand.router.as_ref().unwrap().state().documents["naive"], router_direct_intent());
}

#[tokio::test]
async fn apply_native_policy_on_attached_service_is_422() {
    let stand = stand("native-attached", true);
    stand.service.attach("local", "naive", &context()).await.unwrap();
    save(
        &stand.service,
        "naive",
        &input(json!({"backend": "naive_native", "default_action": "egress", "default_egress": "warp"})),
        Some(1),
    );
    let error = stand.service.apply("local", "naive", 2, LANE_SERVICE, &context()).await.unwrap_err();
    assert_eq!(error.status(), 422);
    assert_eq!(error.refusal().unwrap().compiled.as_ref().unwrap().reasons[0].code, "backend_capability_missing");
}

#[tokio::test]
async fn delete_router_policy_only_when_reset() {
    let stand = stand("router-delete", true);
    stand.service.attach("local", "naive", &context()).await.unwrap();
    save(&stand.service, "naive", &warp(), Some(1));
    apply(&stand.service, "naive", 2).await;
    assert_eq!(
        refusal(stand.service.delete("local", "naive", LANE_SERVICE, &context()).unwrap_err()),
        (409, "policy_applied".into())
    );
    save(&stand.service, "naive", &PolicyInput::default(), Some(2));
    apply(&stand.service, "naive", 3).await;
    stand.service.delete("local", "naive", LANE_SERVICE, &context()).unwrap();
    assert_eq!(item(&stand.service.targets().await.unwrap(), "naive")["policy"], Value::Null);
}

#[tokio::test]
async fn attach_and_detach_record_the_pass_through_the_node_now_runs() {
    let stand = stand("pass-through", true);
    stand.service.attach("local", "naive", &context()).await.unwrap();
    let policy = stand.service.get("local", "naive", LANE_SERVICE).unwrap();
    assert_eq!(
        policy.applied_digest.as_deref(),
        Some(document_digest(&compiler::direct_document(ROUTER_BACKEND)).as_str())
    );
    stand.service.delete("local", "naive", LANE_SERVICE, &context()).unwrap();
    stand.service.attach("local", "naive", &context()).await.unwrap();
    save(&stand.service, "naive", &warp(), Some(1));
    apply(&stand.service, "naive", 2).await;
    stand.service.rollback("local", "naive", 2, LANE_SERVICE, &context()).await.unwrap();
    stand.service.detach("local", "naive", &context()).await.unwrap();
    let policy = stand.service.get("local", "naive", LANE_SERVICE).unwrap();
    assert_eq!(
        policy.applied_digest.as_deref(),
        Some(document_digest(&compiler::direct_document(Backend::NaiveNative)).as_str())
    );
    stand.service.delete("local", "naive", LANE_SERVICE, &context()).unwrap();
}

mod remote_regressions;
