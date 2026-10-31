//! `FleetMetricsSource` against migrated SQLite state and scripted linked-node clients.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use panel_core::clock::{FakeClock, SharedClock};
use panel_core::db::Database;
use panel_core::migrations::apply_migrations;
use panel_core::rusqlite::params;
use panel_fleet::central::{NodeClientFactory, NodeLink};
use panel_fleet_central::links::{NodeLinkService, KEY_PURPOSE};
use panel_fleet_central::metrics_source::{FleetMetricsSource, CALL_TIMEOUT, CONCURRENCY, HISTORY_TIMEOUT, STALE, TTL};
use panel_metrics::FleetMeters;
use panel_model::fleet::{ObservedGeneration, PushRequest, PushResponse};
use panel_model::metrics::{MetricsNode, NodeMetricsSource};
use panel_model::protocols::BoxFuture;
use panel_model::seams::{CaptureItem, CapturePurpose, NodeClient, NodeError, SeamError};
use panel_secrets::keyring::Keyring;
use panel_secrets::secrets_store::{Identity, SecretError, SecretStore};
use serde_json::{json, Map, Value};
use tokio::sync::Semaphore;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().expect("JSON object").clone()
}

fn live_entry(cpu: f64, status: &str, age: f64) -> Map<String, Value> {
    object(json!({
        "node_id": "local",
        "name": "local",
        "status": status,
        "age_seconds": age,
        "host": {"cpu_percent": cpu},
        "protocols": {},
        "top_clients": [],
        "kernel_counters": "ok",
        "alerts": []
    }))
}

#[derive(Clone, Copy)]
enum AnswerKind {
    Live,
    History,
    Summary,
}

struct NodeState {
    live_body: Map<String, Value>,
    history_body: Option<Map<String, Value>>,
    summary_body: Map<String, Value>,
    failure: Option<NodeError>,
    delay: Duration,
    calls: usize,
    timeouts: Vec<Duration>,
}

struct FakeNode {
    state: Mutex<NodeState>,
    gate: Option<Arc<Semaphore>>,
}

impl FakeNode {
    fn new() -> Self {
        Self::with_body(live_entry(10.0, "ok", 0.0))
    }

    fn with_body(live_body: Map<String, Value>) -> Self {
        Self {
            state: Mutex::new(NodeState {
                live_body,
                history_body: None,
                summary_body: object(json!({
                    "range": "1h",
                    "host": {"cpu": {"avg": 5.0}},
                    "protocols": {},
                    "hours_of_day": {},
                    "alerts": []
                })),
                failure: None,
                delay: Duration::ZERO,
                calls: 0,
                timeouts: Vec::new(),
            }),
            gate: None,
        }
    }

    fn delayed(mut self, delay: Duration) -> Self {
        self.state.get_mut().unwrap_or_else(|poisoned| poisoned.into_inner()).delay = delay;
        self
    }

    fn gated(mut self, gate: Arc<Semaphore>) -> Self {
        self.gate = Some(gate);
        self
    }

    fn set_delay(&self, delay: Duration) {
        lock(&self.state).delay = delay;
    }

    fn set_failure(&self, error: NodeError) {
        lock(&self.state).failure = Some(error);
    }

    fn calls(&self) -> usize {
        lock(&self.state).calls
    }

    fn timeouts(&self) -> Vec<Duration> {
        lock(&self.state).timeouts.clone()
    }
}

#[derive(Default)]
struct Counters {
    active: AtomicUsize,
    peak: AtomicUsize,
    clients_built: AtomicUsize,
}

impl Counters {
    fn start(self: &Arc<Self>) -> ActiveCall {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        ActiveCall { counters: self.clone() }
    }
}

struct ActiveCall {
    counters: Arc<Counters>,
}

impl Drop for ActiveCall {
    fn drop(&mut self) {
        self.counters.active.fetch_sub(1, Ordering::SeqCst);
    }
}

struct FakeClient {
    node: Arc<FakeNode>,
    counters: Arc<Counters>,
}

impl FakeClient {
    async fn answer(
        &self,
        kind: AnswerKind,
        timeout: Duration,
        history_default: Option<Map<String, Value>>,
    ) -> Result<Map<String, Value>, NodeError> {
        let delay = {
            let mut state = lock(&self.node.state);
            state.calls += 1;
            state.timeouts.push(timeout);
            state.delay
        };
        let _active = self.counters.start();
        if let Some(gate) = &self.node.gate {
            gate.acquire().await.expect("test gate remains open").forget();
        }
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let state = lock(&self.node.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        Ok(match kind {
            AnswerKind::Live => state.live_body.clone(),
            AnswerKind::History => state.history_body.clone().or(history_default).expect("history default"),
            AnswerKind::Summary => state.summary_body.clone(),
        })
    }
}

fn unused_method() -> NodeError {
    NodeError::Unreachable("method not used by FleetMetricsSource tests".into())
}

impl NodeClient for FakeClient {
    fn identity(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async { Err(unused_method()) })
    }

    fn status(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async { Err(unused_method()) })
    }

    fn inventory(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async { Err(unused_method()) })
    }

    fn metrics(&self, timeout: Duration) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move { self.answer(AnswerKind::Live, timeout, None).await })
    }

    fn metrics_history<'a>(
        &'a self,
        series: &'a [String],
        range: &'a str,
        _points: i64,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        let series = series.iter().map(|name| (name.clone(), json!([[1, 2.0, 3.0]]))).collect::<Map<_, _>>();
        let default = object(json!({
            "node_id": "local",
            "range": range,
            "step": 60,
            "series": series
        }));
        Box::pin(async move { self.answer(AnswerKind::History, timeout, Some(default)).await })
    }

    fn metrics_summary<'a>(
        &'a self,
        _range: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move { self.answer(AnswerKind::Summary, timeout, None).await })
    }

    fn push<'a>(&'a self, _request: &'a PushRequest) -> BoxFuture<'a, Result<(u16, PushResponse), NodeError>> {
        Box::pin(async { Err(unused_method()) })
    }

    fn observed(&self) -> BoxFuture<'_, Result<ObservedGeneration, NodeError>> {
        Box::pin(async { Err(unused_method()) })
    }

    fn capture<'a>(
        &'a self,
        _resources: &'a [CaptureItem],
        _purpose: CapturePurpose,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async { Err(unused_method()) })
    }

    fn update_version<'a>(
        &'a self,
        _component: &'a str,
        _version: &'a str,
        _expected_current: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async { Err(unused_method()) })
    }

    fn check_versions(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async { Err(unused_method()) })
    }

    fn unlink(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async { Err(unused_method()) })
    }

    fn exit_test<'a>(&'a self, _spec: &'a Map<String, Value>) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async { Err(unused_method()) })
    }

    fn geodata<'a>(
        &'a self,
        _action: &'a str,
        _body: Option<&'a Map<String, Value>>,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async { Err(unused_method()) })
    }
}

struct FakeFactory {
    nodes: HashMap<String, Arc<FakeNode>>,
    counters: Arc<Counters>,
}

impl NodeClientFactory for FakeFactory {
    fn client(&self, link: &NodeLink, api_key: &str) -> Result<Arc<dyn NodeClient>, SeamError> {
        assert_eq!(api_key, "test-key");
        self.counters.clients_built.fetch_add(1, Ordering::SeqCst);
        let node = self.nodes.get(&link.node_id).expect("registered fake node").clone();
        Ok(Arc::new(FakeClient { node, counters: self.counters.clone() }))
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "fleet-metrics-source-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temporary directory");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone)]
struct SourceOptions {
    ttl: Duration,
    call_timeout: Duration,
    history_timeout: Duration,
    stale: Duration,
    concurrency: usize,
}

impl Default for SourceOptions {
    fn default() -> Self {
        Self {
            ttl: TTL,
            call_timeout: CALL_TIMEOUT,
            history_timeout: HISTORY_TIMEOUT,
            stale: STALE,
            concurrency: CONCURRENCY,
        }
    }
}

struct Harness {
    _dir: TempDir,
    clock: Arc<FakeClock>,
    nodes: HashMap<String, Arc<FakeNode>>,
    counters: Arc<Counters>,
    source: FleetMetricsSource,
}

impl Harness {
    fn new<S: Into<String>>(nodes: Vec<(S, FakeNode)>) -> Self {
        Self::with(nodes, true, &["metrics.v1"], SourceOptions::default())
    }

    fn with<S: Into<String>>(
        nodes: Vec<(S, FakeNode)>,
        online: bool,
        capabilities: &[&str],
        options: SourceOptions,
    ) -> Self {
        let dir = TempDir::new();
        let database = Database::open(dir.path.join("panel.sqlite3")).expect("open test database");
        apply_migrations(&database).expect("migrate test database");
        let clock = Arc::new(FakeClock::default());
        let shared_clock: SharedClock = clock.clone();
        let nodes =
            nodes.into_iter().map(|(node_id, node)| (node_id.into(), Arc::new(node))).collect::<HashMap<_, _>>();
        let counters = Arc::new(Counters::default());
        let factory = Arc::new(FakeFactory { nodes: nodes.clone(), counters: counters.clone() });
        let secrets = SecretStore::with_clock(Some(Keyring::generate()), shared_clock.clone());
        let links =
            Arc::new(NodeLinkService::new(database.clone(), secrets.clone(), "central", factory, shared_clock.clone()));

        database
            .transaction(|db| {
                for node_id in nodes.keys() {
                    let name = display_name(node_id);
                    let secret_id = format!("node-key:{node_id}:test");
                    db.execute(
                        "INSERT INTO fleet_nodes(
                            node_id,display_name,auth_state,inventory_json,created_at,updated_at,transport
                         ) VALUES(?,?,'enrolled','{}',0,0,'panel')",
                        params![node_id, name],
                    )?;
                    secrets.store(
                        db,
                        &Identity {
                            secret_id: &secret_id,
                            version: 1,
                            purpose: KEY_PURPOSE,
                            grant_id: None,
                            permitted_node_id: Some(node_id),
                        },
                        b"test-key",
                        "active",
                    )?;
                    let identity = json!({"guid": node_id, "capabilities": capabilities}).to_string();
                    let status = if online { "online" } else { "offline" };
                    db.execute(
                        "INSERT INTO node_links(
                            node_id,panel_url,tls_verify,api_key_secret_id,status,identity_json,
                            status_json,created_at,updated_at
                         ) VALUES(?,?,'verify',?,?,?,'{}',0,0)",
                        params![node_id, format!("https://{node_id}.example"), secret_id, status, identity],
                    )?;
                }
                Ok::<(), SecretError>(())
            })
            .expect("seed linked nodes");

        let source = FleetMetricsSource::with_options(
            database,
            links,
            shared_clock,
            options.ttl,
            options.call_timeout,
            options.history_timeout,
            options.stale,
            options.concurrency,
        );
        Self { _dir: dir, clock, nodes, counters, source }
    }

    fn node(&self, node_id: &str) -> &FakeNode {
        self.nodes.get(node_id).expect("fake node")
    }
}

fn display_name(node_id: &str) -> String {
    let mut chars = node_id.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn metrics_nodes(node_ids: &[&str]) -> Vec<MetricsNode> {
    node_ids
        .iter()
        .map(|node_id| MetricsNode { node_id: (*node_id).to_string(), name: display_name(node_id) })
        .collect()
}

async fn live(harness: &Harness, node_id: &str) -> Value {
    harness.source.live(node_id).await.expect("fleet source always answers")
}

async fn history(harness: &Harness, node_id: &str, series: &[&str], range: &str, points: i64) -> Value {
    let series = series.iter().map(|name| (*name).to_string()).collect::<Vec<_>>();
    harness.source.history(node_id, &series, range, points).await.expect("fleet source always answers")
}

async fn summary(harness: &Harness, node_id: &str, range: &str) -> Value {
    harness.source.summary(node_id, range).await.expect("fleet source always answers")
}

async fn live_many(harness: &Harness, node_ids: &[&str], budget: Duration) -> Vec<Value> {
    harness
        .source
        .live_many(&metrics_nodes(node_ids), budget)
        .await
        .into_iter()
        .map(|entry| entry.expect("fleet source always answers"))
        .collect()
}

#[tokio::test]
async fn missing_capability_or_link_is_unsupported_without_calling_a_client() {
    let harness = Harness::with(vec![("berlin", FakeNode::new())], true, &["generation.v1"], SourceOptions::default());

    let got = live(&harness, "berlin").await;
    assert_eq!(got["status"], "unsupported");
    assert_eq!(got["node_id"], "berlin");
    assert!(got["host"].is_null());
    assert_eq!(history(&harness, "berlin", &["host.cpu"], "1h", 240).await["status"], "unsupported");
    assert_eq!(summary(&harness, "berlin", "1h").await["status"], "unsupported");
    assert_eq!(live(&harness, "stranger").await["status"], "unsupported");
    assert_eq!(harness.node("berlin").calls(), 0);
    assert_eq!(harness.counters.clients_built.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn offline_link_is_unavailable_without_calling_a_client() {
    let harness = Harness::with(vec![("berlin", FakeNode::new())], false, &["metrics.v1"], SourceOptions::default());

    assert_eq!(live(&harness, "berlin").await["status"], "unavailable");
    assert_eq!(history(&harness, "berlin", &["host.cpu"], "1h", 240).await["status"], "unavailable");
    assert_eq!(summary(&harness, "berlin", "1h").await["status"], "unavailable");
    assert_eq!(harness.node("berlin").calls(), 0);
}

#[tokio::test]
async fn live_entries_use_registry_identity_and_three_second_timeout() {
    let harness = Harness::new(vec![("berlin", FakeNode::with_body(live_entry(33.0, "ok", 0.0)))]);

    let got = live(&harness, "berlin").await;
    assert_eq!(got["node_id"], "berlin");
    assert_eq!(got["name"], "Berlin");
    assert_eq!(got["status"], "ok");
    assert_eq!(got["host"], json!({"cpu_percent": 33.0}));
    assert_eq!(harness.node("berlin").timeouts(), vec![Duration::from_secs(3)]);
}

#[tokio::test]
async fn node_supplied_stale_status_and_age_are_preserved() {
    let harness = Harness::new(vec![("berlin", FakeNode::with_body(live_entry(10.0, "stale", 12.0)))]);

    let got = live(&harness, "berlin").await;
    assert_eq!(got["status"], "stale");
    assert_eq!(got["age_seconds"], json!(12.0));
}

#[tokio::test]
async fn live_404_is_unsupported() {
    let harness = Harness::new(vec![("berlin", FakeNode::new())]);
    harness.node("berlin").set_failure(NodeError::Rejected {
        status: 404,
        code: Some("metrics_disabled".into()),
        detail: "metrics_disabled".into(),
    });

    assert_eq!(live(&harness, "berlin").await["status"], "unsupported");
}

#[tokio::test]
async fn live_answers_are_cached_per_node_for_two_seconds() {
    let harness = Harness::new(vec![("berlin", FakeNode::new()), ("oslo", FakeNode::new())]);

    live(&harness, "berlin").await;
    harness.clock.advance(1.9);
    live(&harness, "berlin").await;
    assert_eq!(harness.node("berlin").calls(), 1);
    assert_eq!(harness.node("oslo").calls(), 0);

    harness.clock.advance(0.2);
    live(&harness, "berlin").await;
    assert_eq!(harness.node("berlin").calls(), 2);
}

#[tokio::test]
async fn concurrent_identical_live_calls_share_one_request() {
    let harness = Harness::new(vec![("berlin", FakeNode::new().delayed(Duration::from_millis(50)))]);

    let results = join_all((0..20).map(|_| harness.source.live("berlin"))).await;
    assert_eq!(harness.node("berlin").calls(), 1);
    assert_eq!(harness.counters.clients_built.load(Ordering::SeqCst), 1);
    assert!(results.iter().all(|entry| entry.as_ref().expect("live entry")["status"] == "ok"));
}

#[tokio::test]
async fn cancelling_one_caller_does_not_cancel_the_shared_request() {
    let harness = Harness::new(vec![("berlin", FakeNode::new().delayed(Duration::from_millis(100)))]);
    let source = harness.source.clone();
    let waiter = tokio::spawn(async move { source.live("berlin").await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    waiter.abort();
    assert!(waiter.await.expect_err("caller was aborted").is_cancelled());

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(live(&harness, "berlin").await["status"], "ok");
    assert_eq!(harness.node("berlin").calls(), 1);
}

#[tokio::test]
async fn live_fan_out_caps_node_calls_at_eight() {
    assert_eq!(CONCURRENCY, 8, "the production metrics concurrency contract is eight");
    // Hold calls until all slots are occupied; elapsed time cannot prove saturation
    // when SQLite metadata/client setup runs on the blocking pool before each call.
    let gate = Arc::new(Semaphore::new(0));
    let nodes = (0..20).map(|index| (format!("n{index}"), FakeNode::new().gated(gate.clone()))).collect::<Vec<_>>();
    let harness = Harness::with(
        nodes,
        true,
        &["metrics.v1"],
        SourceOptions { call_timeout: Duration::from_secs(30), ..SourceOptions::default() },
    );
    let node_ids = harness.nodes.keys().map(String::as_str).collect::<Vec<_>>();
    let items = metrics_nodes(&node_ids);
    let source = harness.source.clone();
    let request = tokio::spawn(async move { source.live_many(&items, Duration::from_secs(30)).await });

    tokio::time::timeout(Duration::from_secs(10), async {
        while harness.counters.active.load(Ordering::SeqCst) < 8 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all eight metrics slots must become active");
    assert_eq!(harness.counters.active.load(Ordering::SeqCst), 8);
    assert_eq!(harness.counters.peak.load(Ordering::SeqCst), 8);
    gate.add_permits(20);

    let got = tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .expect("all node calls must finish after opening the gate")
        .expect("fan-out task completes");
    assert_eq!(got.len(), 20);
    assert!(got.iter().all(|entry| entry.as_ref().expect("live entry")["status"] == "ok"));
    assert_eq!(harness.counters.peak.load(Ordering::SeqCst), 8);
    assert_eq!(harness.nodes.values().map(|node| node.calls()).sum::<usize>(), 20);
    assert_eq!(harness.counters.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn live_many_budget_leaves_slow_call_running_to_fill_cache() {
    let options = SourceOptions { call_timeout: Duration::from_secs(1), ..SourceOptions::default() };
    let harness = Harness::with(
        vec![("fast", FakeNode::new()), ("slow", FakeNode::new().delayed(Duration::from_millis(500)))],
        true,
        &["metrics.v1"],
        options,
    );

    let started = Instant::now();
    let got = live_many(&harness, &["fast", "slow"], Duration::from_millis(50)).await;
    assert!(started.elapsed() < Duration::from_millis(300), "slow node exceeded caller budget");
    assert_eq!(
        got.iter()
            .map(|entry| (entry["node_id"].as_str().unwrap(), entry["status"].as_str().unwrap()))
            .collect::<Vec<_>>(),
        vec![("fast", "ok"), ("slow", "unavailable")]
    );

    tokio::time::sleep(Duration::from_millis(600)).await;
    let again = live_many(&harness, &["slow"], Duration::from_millis(50)).await;
    assert_eq!(again[0]["status"], "ok");
    assert_eq!(harness.node("slow").calls(), 1);
}

#[tokio::test]
async fn live_many_budget_returns_recent_good_sample_as_stale() {
    let options = SourceOptions { call_timeout: Duration::from_secs(1), ..SourceOptions::default() };
    let harness = Harness::with(vec![("slow", FakeNode::new())], true, &["metrics.v1"], options);
    assert_eq!(live(&harness, "slow").await["status"], "ok");
    harness.clock.advance(30.0);
    harness.node("slow").set_delay(Duration::from_millis(500));

    let got = live_many(&harness, &["slow"], Duration::from_millis(50)).await;
    assert_eq!(got[0]["status"], "stale");
    assert_eq!(got[0]["age_seconds"], json!(30.0));
    assert_eq!(got[0]["host"], json!({"cpu_percent": 10.0}));
}

#[tokio::test]
async fn last_good_sample_expires_after_120_seconds() {
    let harness = Harness::new(vec![("berlin", FakeNode::with_body(live_entry(44.0, "ok", 1.0)))]);
    assert_eq!(live(&harness, "berlin").await["status"], "ok");
    harness.node("berlin").set_failure(NodeError::Unreachable("ConnectTimeout".into()));

    harness.clock.advance(30.0);
    let got = live(&harness, "berlin").await;
    assert_eq!(got["status"], "stale");
    assert_eq!(got["age_seconds"], json!(31.0));
    assert_eq!(got["host"], json!({"cpu_percent": 44.0}));
    assert_eq!(got["node_id"], "berlin");
    assert_eq!(got["name"], "Berlin");

    harness.clock.advance(100.0);
    let got = live(&harness, "berlin").await;
    assert_eq!(got["status"], "unavailable");
    assert!(got["host"].is_null());
    assert!(got["age_seconds"].is_null());
}

#[tokio::test]
async fn node_without_a_good_sample_is_unavailable_on_failure() {
    let harness = Harness::new(vec![("berlin", FakeNode::new())]);
    harness.node("berlin").set_failure(NodeError::Rejected {
        status: 503,
        code: Some("metrics_warming_up".into()),
        detail: "metrics_warming_up".into(),
    });

    assert_eq!(live(&harness, "berlin").await["status"], "unavailable");
}

#[tokio::test]
async fn live_call_slower_than_its_timeout_is_cut_off() {
    let options = SourceOptions { call_timeout: Duration::from_millis(30), ..SourceOptions::default() };
    let harness = Harness::with(
        vec![("berlin", FakeNode::new().delayed(Duration::from_millis(200)))],
        true,
        &["metrics.v1"],
        options,
    );

    assert_eq!(live(&harness, "berlin").await["status"], "unavailable");
}

#[tokio::test]
async fn history_and_summary_are_tagged_and_map_node_errors() {
    let harness = Harness::new(vec![("berlin", FakeNode::new())]);

    let history_answer = history(&harness, "berlin", &["host.cpu"], "6h", 120).await;
    assert_eq!(history_answer["node_id"], "berlin");
    assert_eq!(history_answer["status"], "ok");
    assert_eq!(history_answer["range"], "6h");
    assert_eq!(history_answer["series"], json!({"host.cpu": [[1, 2.0, 3.0]]}));
    let summary_answer = summary(&harness, "berlin", "1h").await;
    assert_eq!(summary_answer["node_id"], "berlin");
    assert_eq!(summary_answer["name"], "Berlin");
    assert_eq!(summary_answer["status"], "ok");
    assert_eq!(summary_answer["host"], json!({"cpu": {"avg": 5.0}}));
    assert_eq!(harness.node("berlin").timeouts(), vec![Duration::from_secs(10), Duration::from_secs(10)]);

    harness.node("berlin").set_failure(NodeError::Unreachable("offline".into()));
    assert_eq!(history(&harness, "berlin", &["host.cpu"], "1h", 120).await["status"], "unavailable");
    assert_eq!(summary(&harness, "berlin", "1h").await["status"], "unavailable");
}

#[tokio::test]
async fn concurrent_identical_history_calls_share_one_request() {
    let harness = Harness::new(vec![("berlin", FakeNode::new().delayed(Duration::from_millis(50)))]);
    let series = vec!["host.cpu".to_string()];

    let results = join_all((0..5).map(|_| harness.source.history("berlin", &series, "1h", 240))).await;
    assert!(results.iter().all(|entry| entry.as_ref().expect("history entry")["status"] == "ok"));
    assert_eq!(harness.node("berlin").calls(), 1);
    assert_eq!(harness.counters.clients_built.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn completed_shared_future_is_retired_before_immediate_same_key_reentry() {
    let harness = Harness::new(vec![("berlin", FakeNode::new())]);
    for round in 0..50 {
        lock(&harness.node("berlin").state).history_body = Some(object(json!({"round": round})));
        lock(&harness.node("berlin").state).summary_body = object(json!({"round": round}));
        assert_eq!(history(&harness, "berlin", &["host.cpu"], "1h", 240).await["round"], round);
        assert_eq!(summary(&harness, "berlin", "1h").await["round"], round);
        lock(&harness.node("berlin").state).live_body = live_entry(f64::from(round), "ok", 0.0);
        assert_eq!(live(&harness, "berlin").await["host"]["cpu_percent"], f64::from(round));
        harness.clock.advance(2.1);
    }
    assert_eq!(harness.node("berlin").calls(), 150);
}

#[tokio::test]
async fn failed_history_and_summary_do_not_poison_the_next_shared_future() {
    let harness = Harness::new(vec![("berlin", FakeNode::new())]);
    for error in [
        NodeError::Unreachable("ReadTimeout".into()),
        NodeError::Rejected { status: 404, code: None, detail: "missing".into() },
        NodeError::Rejected { status: 503, code: Some("warming_up".into()), detail: "private".into() },
    ] {
        harness.node("berlin").set_failure(error.clone());
        let expected =
            if matches!(error, NodeError::Rejected { status: 404, .. }) { "unsupported" } else { "unavailable" };
        assert_eq!(history(&harness, "berlin", &["host.cpu"], "6h", 60).await["status"], expected);
        assert_eq!(summary(&harness, "berlin", "6h").await["status"], expected);
        lock(&harness.node("berlin").state).failure = None;
        assert_eq!(history(&harness, "berlin", &["host.cpu"], "6h", 60).await["status"], "ok");
        assert_eq!(summary(&harness, "berlin", "6h").await["status"], "ok");
    }
    assert_eq!(harness.node("berlin").calls(), 12);
}

#[tokio::test]
async fn history_deduplication_distinguishes_series_range_and_point_count() {
    let harness = Harness::new(vec![("berlin", FakeNode::new().delayed(Duration::from_millis(20)))]);
    let cpu = vec!["host.cpu".to_owned()];
    let memory = vec!["host.mem".to_owned()];
    let (a, b, c, d) = tokio::join!(
        harness.source.history("berlin", &cpu, "1h", 60),
        harness.source.history("berlin", &memory, "1h", 60),
        harness.source.history("berlin", &cpu, "6h", 60),
        harness.source.history("berlin", &cpu, "1h", 120),
    );
    for answer in [a, b, c, d] {
        assert_eq!(answer.unwrap()["status"], "ok");
    }
    assert_eq!(harness.node("berlin").calls(), 4);
}
