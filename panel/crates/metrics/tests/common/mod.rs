//! Test rig: a migrated temporary database, the fake clock, and meter sources that replay the
//! answers recorded from Python (`fixtures/record.py`) or answer what a test sets.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use panel_core::clock::{FakeClock, SharedClock};
use panel_core::db::Database;
use panel_core::migrations::apply_migrations;
use panel_metrics::{CollectorConfig, MeterSources, Metrics};
use panel_model::protocols::BoxFuture;
use serde_json::Value;

pub const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// A scratch directory removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "panel-metrics-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Answers per source (`agent`, `trusttunnel`, …), consumed in order.
#[derive(Default)]
pub struct Replay {
    queues: Mutex<HashMap<String, VecDeque<Result<Value, String>>>>,
    unexpected: Mutex<Vec<String>>,
    pub local_name: Mutex<Option<String>>,
    /// Answers given when a queue is empty (tests that do not replay).
    pub fixed: Mutex<HashMap<String, Result<Value, String>>>,
    pub calls: Mutex<HashMap<String, usize>>,
}

impl Replay {
    /// Loads one step's recorded calls: `{"agent": [{"ok": …}], "trusttunnel": [{"error": …}]}`.
    pub fn load(&self, calls: &Value) {
        let mut queues = self.queues.lock().unwrap();
        for (source, answers) in calls.as_object().expect("calls") {
            let queue = queues.entry(source.clone()).or_default();
            for answer in answers.as_array().expect("answers") {
                queue.push_back(match answer.get("error") {
                    Some(error) => Err(error.as_str().unwrap_or("error").to_string()),
                    None => Ok(answer.get("ok").cloned().unwrap_or(Value::Null)),
                });
            }
        }
    }

    /// Panics when a recorded answer was not asked for or a call had no recorded answer.
    pub fn assert_consumed(&self, context: &str) {
        let unexpected = std::mem::take(&mut *self.unexpected.lock().unwrap());
        assert!(unexpected.is_empty(), "{context}: calls Python did not make: {unexpected:?}");
        let queues = self.queues.lock().unwrap();
        for (source, queue) in queues.iter() {
            assert!(queue.is_empty(), "{context}: {source} was not asked {} more time(s)", queue.len());
        }
    }

    fn next(&self, source: &str) -> Result<Value, String> {
        *self.calls.lock().unwrap().entry(source.to_string()).or_default() += 1;
        if let Some(answer) = self.queues.lock().unwrap().get_mut(source).and_then(VecDeque::pop_front) {
            return answer;
        }
        if let Some(answer) = self.fixed.lock().unwrap().get(source) {
            return answer.clone();
        }
        self.unexpected.lock().unwrap().push(source.to_string());
        Err("no recorded answer".into())
    }

    pub fn set(&self, source: &str, answer: Result<Value, String>) {
        self.fixed.lock().unwrap().insert(source.to_string(), answer);
    }

    pub fn count(&self, source: &str) -> usize {
        self.calls.lock().unwrap().get(source).copied().unwrap_or(0)
    }
}

impl MeterSources for Replay {
    fn agent_metrics(&self) -> BoxFuture<'_, Option<Value>> {
        Box::pin(async move { self.next("agent").ok().filter(|v| !v.is_null()) })
    }

    fn poll(&self, protocol: &'static str) -> BoxFuture<'_, Result<Value, String>> {
        Box::pin(async move { self.next(protocol) })
    }

    fn local_node_name(&self) -> BoxFuture<'_, Option<String>> {
        Box::pin(async move { self.local_name.lock().unwrap().clone() })
    }
}

/// Settings flags of a recorded rig.
pub fn config(flags: &Value) -> (bool, CollectorConfig) {
    let flag = |name: &str| flags.get(name).and_then(Value::as_bool).unwrap_or(false);
    let enabled = flags.get("metrics_enabled").and_then(Value::as_bool).unwrap_or(true);
    let config = CollectorConfig {
        interval: 2.0,
        trusttunnel_enabled: flag("trusttunnel_enabled"),
        amneziawg_enabled: flag("amneziawg_enabled"),
        naive_enabled: flag("naive_enabled"),
        mieru_enabled: flag("mieru_enabled"),
    };
    (enabled, config)
}

pub struct Rig {
    pub dir: TempDir,
    pub clock: Arc<FakeClock>,
    pub sources: Arc<Replay>,
    pub database: Database,
    pub metrics: Arc<Metrics>,
}

impl Rig {
    pub fn new(flags: &Value, start: f64) -> Self {
        let dir = TempDir::new();
        let database = Database::open(dir.0.join("panel.db")).expect("database");
        apply_migrations(&database).expect("migrations");
        let clock = Arc::new(FakeClock::new(start));
        let shared: SharedClock = clock.clone();
        let sources = Arc::new(Replay::default());
        let (enabled, config) = config(flags);
        let metrics = Metrics::new(enabled, 900, config, database.clone(), sources.clone(), shared);
        Self { dir, clock, sources, database, metrics }
    }

    /// `MetricsRig(tmp, **flags)` of `panel/metrics/fakes.py`.
    pub fn with(flags: Value) -> Self {
        Self::new(&flags, 1_800_000_000.0)
    }

    pub fn collector(&self) -> &Arc<panel_metrics::MetricsCollector> {
        self.metrics.collector().expect("metrics are on")
    }

    /// `rig.step(seconds)`: advance, tick, wait for the manager polls.
    pub async fn step(&self, seconds: f64) {
        self.clock.advance(seconds);
        self.collector().tick().await.expect("tick");
        self.collector().drain().await;
    }

    pub async fn latest(&self) -> Value {
        self.collector().latest().await.expect("a tick happened")
    }

    pub fn sql(&self, statement: &str) {
        self.database.transaction(|db| db.execute(statement, []).map(|_| ())).expect("sql");
    }
}

/// The agent sample `MemoryAgentMetrics` would return (for tests that do not replay).
pub struct Agent {
    pub clock: Arc<FakeClock>,
    pub state: Mutex<AgentState>,
}

pub struct AgentState {
    pub broken: bool,
    pub kernel_counters: String,
    pub cpu: f64,
    pub mem: f64,
    pub swap: f64,
    pub disk: f64,
    pub rx_bps: f64,
    pub tx_bps: f64,
    /// name → (up_bytes, down_bytes, up_bps, down_bps, source)
    pub protocols: Vec<(String, i64, i64, f64, f64, String)>,
    pub at: f64,
}

impl Agent {
    pub fn new(clock: Arc<FakeClock>) -> Self {
        let at = panel_core::clock::Clock::time(&*clock);
        Self {
            clock,
            state: Mutex::new(AgentState {
                broken: false,
                kernel_counters: "ok".into(),
                cpu: 12.5,
                mem: 40.0,
                swap: 5.0,
                disk: 30.0,
                rx_bps: 5000.0,
                tx_bps: 7000.0,
                protocols: Vec::new(),
                at,
            }),
        }
    }

    pub fn set_protocol(&self, name: &str, up_bps: f64, down_bps: f64, source: &str) {
        let mut state = self.state.lock().unwrap();
        match state.protocols.iter_mut().find(|p| p.0 == name) {
            Some(row) => {
                row.3 = up_bps;
                row.4 = down_bps;
                row.5 = source.into();
            }
            None => state.protocols.push((name.into(), 0, 0, up_bps, down_bps, source.into())),
        }
    }

    pub fn sample(&self) -> Option<Value> {
        let now = panel_core::clock::Clock::time(&*self.clock);
        let mut state = self.state.lock().unwrap();
        if state.broken {
            return None;
        }
        let elapsed = now - state.at;
        state.at = now;
        let mut protocols = serde_json::Map::new();
        for row in state.protocols.iter_mut() {
            row.1 += (row.3 * elapsed) as i64;
            row.2 += (row.4 * elapsed) as i64;
            protocols.insert(
                row.0.clone(),
                serde_json::json!({"up_bytes": row.1, "down_bytes": row.2, "up_bps": row.3, "down_bps": row.4, "source": row.5}),
            );
        }
        Some(serde_json::json!({
            "ts": now, "interval": 1.0,
            "host": {"cpu_percent": state.cpu, "cores": 4, "load": [0.42, 0.4, 0.3],
                     "mem": {"used": 1000, "total": 4000, "percent": state.mem, "available": 3000},
                     "swap": {"used": 10, "total": 200, "percent": state.swap},
                     "disk": {"used": 3, "total": 10, "percent": state.disk, "read_bps": 1000.0, "write_bps": 2000.0, "busy_percent": 4.0},
                     "net": {"rx_bps": state.rx_bps, "tx_bps": state.tx_bps, "interfaces": []},
                     "uptime_seconds": 1234, "containers": []},
            "protocols": protocols,
            "kernel_counters": state.kernel_counters,
        }))
    }
}

/// Live sources: the [`Agent`] double plus fixed manager answers.
pub struct LiveSources {
    pub agent: Agent,
    pub managers: Replay,
}

impl MeterSources for LiveSources {
    fn agent_metrics(&self) -> BoxFuture<'_, Option<Value>> {
        Box::pin(async move { self.agent.sample() })
    }

    fn poll(&self, protocol: &'static str) -> BoxFuture<'_, Result<Value, String>> {
        Box::pin(async move { self.managers.next(protocol) })
    }
}
