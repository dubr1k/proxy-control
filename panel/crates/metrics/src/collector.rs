//! The panel-side sampler (`metrics/collector.py`, inventory §5.2): the host agent's
//! `/v1/metrics` every tick, the protocol managers on their own slower cadence, the ring, the
//! rollup flush, the hourly prune and the latest node entry the API serves.
//!
//! One tick, in order: refresh the client names (every 60 s) → fetch the agent sample (3.5 s
//! budget) → derive per-protocol rates from the agent's cumulative counters → launch the due
//! manager polls (one in flight per protocol, each on its own task) → prune the client rates →
//! build the node entry → record the ring sample → compute the alerts → publish the entry
//! (version + 1, wake the SSE streams) → flush every 30 s → prune every hour.
//!
//! The collector state sits behind one async mutex. A tick holds it from "derive" to "publish",
//! so a manager poll that answers meanwhile is applied right after the tick, exactly where the
//! Python event loop applies it (a task only runs once the tick yields).

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use futures_util::FutureExt;
use indexmap::IndexMap;
use panel_core::clock::SharedClock;
use panel_core::db::Database;
use panel_core::settings::Settings;
use panel_model::metrics::{LOCAL_NODE, PROTOCOLS};
use serde_json::{json, Map, Value};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use crate::pyfloat::{self, float, num, opt_float, opt_int, round_to};
use crate::rates::{fold, ClientRates, Reading};
use crate::ring::SeriesRing;
use crate::sources::MeterSources;
use crate::store::{MetricsStore, StoreError};

pub const AGENT_TIMEOUT: f64 = 3.5;
pub const MANAGER_TIMEOUT: f64 = 4.0;
pub const NAIVE_TIMEOUT: f64 = 15.0;
/// Seconds between manager polls, in Python's dict order.
pub const CADENCE: [(&str, f64); 5] =
    [("trusttunnel", 5.0), ("amneziawg", 5.0), ("mieru", 5.0), ("mtproxy", 15.0), ("naive", 15.0)];
/// NaiveProxy's access log is written when a CONNECT closes: its rate is averaged over this window.
pub const NAIVE_WINDOW: f64 = 60.0;
pub const FLUSH_SECONDS: f64 = 30.0;
pub const PRUNE_SECONDS: f64 = 3600.0;
pub const REFRESH_NAMES_SECONDS: f64 = 60.0;
pub const HANDSHAKE_FRESH_SECONDS: f64 = 180.0;
pub const TOP_CLIENTS: usize = 10;

fn cadence(protocol: &str) -> f64 {
    CADENCE.iter().find(|(p, _)| *p == protocol).map(|(_, every)| *every).unwrap_or(f64::INFINITY)
}

/// What the collector needs from the settings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CollectorConfig {
    /// `max(0.5, PANEL_METRICS_INTERVAL_SECONDS)`.
    pub interval: f64,
    pub trusttunnel_enabled: bool,
    pub amneziawg_enabled: bool,
    pub naive_enabled: bool,
    pub mieru_enabled: bool,
}

impl CollectorConfig {
    pub fn from_settings(settings: &Settings) -> Self {
        Self {
            interval: settings.metrics_interval(),
            trusttunnel_enabled: settings.trusttunnel_enabled,
            amneziawg_enabled: settings.amneziawg_enabled,
            naive_enabled: settings.naive_enabled,
            mieru_enabled: settings.mieru_enabled,
        }
    }

    /// `_wanted` (= `enabled` in `_protocol_entry`): MTProxy is always asked.
    pub fn wanted(&self, protocol: &str) -> bool {
        match protocol {
            "trusttunnel" => self.trusttunnel_enabled,
            "amneziawg" => self.amneziawg_enabled,
            "naive" => self.naive_enabled,
            "mieru" => self.mieru_enabled,
            _ => true,
        }
    }
}

/// The host series of one agent sample; a field the agent does not report stays missing.
pub fn host_values(host: Option<&Value>) -> IndexMap<String, Option<f64>> {
    let mut out = IndexMap::new();
    let Some(Value::Object(host)) = host else {
        return out;
    };
    let section = |name: &str| match host.get(name) {
        Some(Value::Object(map)) => Some(map),
        _ => None,
    };
    let field = |name: &str, key: &str| num(section(name).and_then(|map| map.get(key)));
    let load = match host.get("load") {
        Some(Value::Array(items)) if !items.is_empty() => num(items.first()),
        _ => None,
    };
    out.insert("host.cpu".into(), num(host.get("cpu_percent")));
    out.insert("host.mem".into(), field("mem", "percent"));
    out.insert("host.swap".into(), field("swap", "percent"));
    out.insert("host.disk".into(), field("disk", "percent"));
    out.insert("host.disk_read_bps".into(), field("disk", "read_bps"));
    out.insert("host.disk_write_bps".into(), field("disk", "write_bps"));
    out.insert("host.load1".into(), load);
    out.insert("net.rx_bps".into(), field("net", "rx_bps"));
    out.insert("net.tx_bps".into(), field("net", "tx_bps"));
    out
}

/// The aggregate of one manager poll.
#[derive(Debug, Clone, Copy, PartialEq)]
struct PollResult {
    up_bps: Option<f64>,
    down_bps: Option<f64>,
    total_bps: f64,
    directional: bool,
    sessions: Option<i64>,
    clients: Option<i64>,
}

#[derive(Debug, Clone)]
struct ManagerState {
    cum_up: f64,
    cum_down: f64,
    pending_up: f64,
    pending_down: f64,
    ok: bool,
    at: f64,
    result: Option<PollResult>,
}

/// One protocol of the node entry.
#[derive(Debug, Clone, PartialEq)]
struct Entry {
    available: bool,
    live: bool,
    source: Option<String>,
    up_bps: Option<f64>,
    down_bps: Option<f64>,
    total_bps: Option<f64>,
    up_bytes: Option<i64>,
    down_bytes: Option<i64>,
    sessions: Option<i64>,
    clients: Option<i64>,
    connections: Option<i64>,
    reason: Option<&'static str>,
}

impl Entry {
    fn empty() -> Self {
        Self {
            available: false,
            live: false,
            source: None,
            up_bps: None,
            down_bps: None,
            total_bps: None,
            up_bytes: None,
            down_bytes: None,
            sessions: None,
            clients: None,
            connections: None,
            reason: None,
        }
    }

    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("available".into(), Value::Bool(self.available));
        map.insert("live".into(), Value::Bool(self.live));
        map.insert("source".into(), self.source.clone().map(Value::String).unwrap_or(Value::Null));
        map.insert("up_bps".into(), opt_float(self.up_bps));
        map.insert("down_bps".into(), opt_float(self.down_bps));
        map.insert("total_bps".into(), opt_float(self.total_bps));
        map.insert("up_bytes".into(), opt_int(self.up_bytes));
        map.insert("down_bytes".into(), opt_int(self.down_bytes));
        map.insert("sessions".into(), opt_int(self.sessions));
        map.insert("clients".into(), opt_int(self.clients));
        map.insert("connections".into(), opt_int(self.connections));
        if let Some(reason) = self.reason {
            map.insert("reason".into(), json!(reason));
        }
        Value::Object(map)
    }
}

struct State {
    latest: Option<Map<String, Value>>,
    rates: ClientRates,
    last_agent: Option<Value>,
    agent_now: Option<Value>,
    last_agent_wall: Option<f64>,
    kernel_prev: HashMap<String, (f64, f64)>,
    kernel_seen: HashMap<String, (f64, f64, f64)>,
    derived: HashMap<String, (f64, f64)>,
    manager: HashMap<&'static str, ManagerState>,
    last_poll: HashMap<&'static str, f64>,
    names: HashMap<(String, String), Option<String>>,
    node_name: String,
    names_at: f64,
    last_flush: f64,
    last_prune: f64,
}

/// A failed tick (the alerts' database read); logged by `run_forever`, retried next interval.
pub type TickError = StoreError;

pub struct MetricsCollector {
    config: CollectorConfig,
    clock: SharedClock,
    store: Arc<MetricsStore>,
    ring: Arc<StdMutex<SeriesRing>>,
    sources: Arc<dyn MeterSources>,
    database: Database,
    state: Mutex<State>,
    inflight: StdMutex<HashMap<&'static str, JoinHandle<()>>>,
    version: AtomicU64,
    events: watch::Sender<u64>,
    stop: watch::Sender<bool>,
    agent_calls: AtomicU64,
    flushes: AtomicU64,
}

impl std::fmt::Debug for MetricsCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsCollector").field("config", &self.config).finish()
    }
}

fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Python's iteration of a manager answer keeping the dicts: a list gives its dict items, a
/// dict or a string iterates keys/characters (no dicts), anything else cannot be iterated.
fn dict_items(value: &Value) -> Result<Vec<&Map<String, Value>>, ()> {
    match value {
        Value::Array(items) => Ok(items.iter().filter_map(Value::as_object).collect()),
        Value::Object(_) | Value::String(_) => Ok(Vec::new()),
        _ => Err(()),
    }
}

/// `data.get("users") if isinstance(data, dict) else None`, then `for r in users or []`.
fn users_of(data: &Value) -> Result<Vec<&Map<String, Value>>, ()> {
    let users = match data {
        Value::Object(map) => map.get("users").unwrap_or(&Value::Null),
        _ => &Value::Null,
    };
    if !pyfloat::truthy(users) {
        return Ok(Vec::new());
    }
    dict_items(users)
}

/// `(username, up, down, total)` rows of the dicts whose `username` is a string.
type Row<'a> = (&'a str, Option<&'a Value>, Option<&'a Value>, Option<&'a Value>);

impl MetricsCollector {
    pub fn new(
        config: CollectorConfig,
        store: Arc<MetricsStore>,
        sources: Arc<dyn MeterSources>,
        clock: SharedClock,
    ) -> Arc<Self> {
        let config = CollectorConfig { interval: config.interval.max(0.5), ..config };
        let now = clock.monotonic();
        let state = State {
            latest: None,
            rates: ClientRates::default(),
            last_agent: None,
            agent_now: None,
            last_agent_wall: None,
            kernel_prev: HashMap::new(),
            kernel_seen: HashMap::new(),
            derived: HashMap::new(),
            manager: HashMap::new(),
            last_poll: HashMap::new(),
            names: HashMap::new(),
            node_name: LOCAL_NODE.to_string(),
            names_at: -1e9,
            last_flush: now,
            last_prune: now,
        };
        Arc::new(Self {
            config,
            database: store.database().clone(),
            ring: store.ring().clone(),
            store,
            sources,
            clock,
            state: Mutex::new(state),
            inflight: StdMutex::new(HashMap::new()),
            version: AtomicU64::new(0),
            events: watch::channel(0).0,
            stop: watch::channel(false).0,
            agent_calls: AtomicU64::new(0),
            flushes: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &CollectorConfig {
        &self.config
    }

    pub fn interval(&self) -> f64 {
        self.config.interval
    }

    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }

    pub fn store(&self) -> &Arc<MetricsStore> {
        &self.store
    }

    /// Bumped once per published tick.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    /// Changes after every published tick (`next_event`).
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.events.subscribe()
    }

    /// How many times the agent was asked / the ring was flushed (`calls`).
    pub fn agent_calls(&self) -> u64 {
        self.agent_calls.load(Ordering::Relaxed)
    }

    pub fn flushes(&self) -> u64 {
        self.flushes.load(Ordering::Relaxed)
    }

    // ---- lifecycle --------------------------------------------------------------------------
    /// Ticks every interval until [`stop`](Self::stop); a failed (or panicking) tick is logged
    /// and retried. Polls still in flight are cancelled on the way out.
    pub async fn run_forever(self: Arc<Self>) {
        let mut stop = self.stop.subscribe();
        while !*stop.borrow_and_update() {
            match AssertUnwindSafe(self.tick()).catch_unwind().await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("metrics tick failed; retrying: {error}"),
                Err(_) => log::warn!("metrics tick failed; retrying: panic"),
            }
            let wait = Duration::from_secs_f64(self.config.interval);
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = stop.wait_for(|stopped| *stopped) => {}
            }
        }
        let handles: Vec<_> = lock(&self.inflight).drain().map(|(_, handle)| handle).collect();
        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            let _ = handle.await;
        }
    }

    pub fn stop(&self) {
        self.stop.send_replace(true);
    }

    // ---- readers ----------------------------------------------------------------------------
    /// This panel's node entry (`latest`), or `None` before the first tick.
    pub async fn latest(&self) -> Option<Value> {
        self.state.lock().await.latest.clone().map(Value::Object)
    }

    /// The live envelope for this panel's node, or `None` before the first tick.
    pub async fn snapshot(&self) -> Option<Value> {
        let latest = self.latest().await?;
        Some(
            json!({"ts": float(round_to(self.clock.time(), 3)), "interval": float(self.config.interval), "nodes": [latest]}),
        )
    }

    /// Waits for the manager polls in flight (tests and shutdown).
    pub async fn drain(&self) {
        let handles: Vec<_> = lock(&self.inflight).drain().map(|(_, handle)| handle).collect();
        for handle in handles {
            let _ = handle.await;
        }
    }

    /// Every client of a protocol with a fresh rate (idle ones included, at zero), in
    /// first-rated order. Empty when the protocol is not measured per client.
    pub async fn client_rates(&self, protocol: &str) -> Map<String, Value> {
        let mut out = Map::new();
        if !CADENCE.iter().any(|(p, _)| *p == protocol) || !self.config.wanted(protocol) {
            return out;
        }
        let state = self.state.lock().await;
        let mono = self.clock.monotonic();
        let window = 3.0 * cadence(protocol).max(self.config.interval);
        for (username, rate) in state.rates.current(protocol, mono, window) {
            out.insert(
                username,
                json!({"up_bps": opt_float(rate.up_bps.filter(|v| *v >= 0.0)),
                       "down_bps": opt_float(rate.down_bps.filter(|v| *v >= 0.0)),
                       "total_bps": float(rate.total_bps)}),
            );
        }
        out
    }

    // ---- one tick ---------------------------------------------------------------------------
    pub async fn tick(self: &Arc<Self>) -> Result<(), TickError> {
        let mono = self.clock.monotonic();
        let wall = self.clock.time();
        let refresh = {
            let mut state = self.state.lock().await;
            let due = mono - state.names_at >= REFRESH_NAMES_SECONDS;
            if due {
                state.names_at = mono;
            }
            due
        };
        if refresh {
            self.refresh_names().await;
        }
        let agent = self.fetch_agent().await;
        let mut state = self.state.lock().await;
        state.agent_now = agent.clone();
        state.derived = match &agent {
            Some(agent) => Self::derive_rates(&mut state.kernel_seen, agent),
            None => HashMap::new(),
        };
        if agent.is_some() {
            state.last_agent = agent.clone();
            state.last_agent_wall = Some(wall);
        }
        self.launch_due(&mut state, mono);
        state.rates.prune(mono);
        let mut node = self.build(&state, agent.as_ref(), wall, mono);
        let values = self.record(&mut state, agent.as_ref(), mono);
        lock(&self.ring).add_sample(wall, &values);
        let status = node.get("status").and_then(Value::as_str).unwrap_or("unavailable").to_string();
        let age = node.get("age_seconds").and_then(Value::as_f64);
        let alerts = self.store.alerts(&status, age).await?;
        node.insert("alerts".into(), Value::Array(alerts));
        state.latest = Some(node);
        let version = self.version.fetch_add(1, Ordering::SeqCst) + 1;
        self.events.send_replace(version);
        let flush_due = mono - state.last_flush >= FLUSH_SECONDS;
        if flush_due {
            state.last_flush = mono;
        }
        let prune_due = mono - state.last_prune >= PRUNE_SECONDS;
        if prune_due {
            state.last_prune = mono;
        }
        drop(state);
        if flush_due {
            match self.store.flush().await {
                Ok(_) => {
                    self.flushes.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => log::warn!("metrics flush failed; retrying: {error}"),
            }
        }
        if prune_due {
            if let Err(error) = self.store.prune(None).await {
                log::warn!("metrics prune failed; retrying: {error}");
            }
        }
        Ok(())
    }

    async fn fetch_agent(&self) -> Option<Value> {
        self.agent_calls.fetch_add(1, Ordering::Relaxed);
        let sample = tokio::time::timeout(Duration::from_secs_f64(AGENT_TIMEOUT), self.sources.agent_metrics())
            .await
            .ok()
            .flatten()?;
        matches!(sample.get("host"), Some(Value::Object(_))).then_some(sample)
    }

    /// Protocol rates from the cumulative counters between this read and the previous one.
    fn derive_rates(seen_by: &mut HashMap<String, (f64, f64, f64)>, agent: &Value) -> HashMap<String, (f64, f64)> {
        let mut out = HashMap::new();
        let (Some(ts), Some(Value::Object(protocols))) = (num(agent.get("ts")), agent.get("protocols")) else {
            return out;
        };
        for (protocol, row) in protocols {
            let (up, down) = match row {
                Value::Object(row) => (num(row.get("up_bytes")), num(row.get("down_bytes"))),
                _ => (None, None),
            };
            let (Some(up), Some(down)) = (up, down) else {
                continue;
            };
            let mut seen = seen_by.get(protocol).copied();
            if let Some(previous) = seen {
                if ts - previous.0 < 0.5 {
                    if ts - previous.0 >= 0.0 {
                        continue; // the same sample again: keep the older baseline
                    }
                    seen = None; // the agent's clock went back: start over
                }
            }
            seen_by.insert(protocol.clone(), (ts, up, down));
            if let Some(previous) = seen {
                let span = ts - previous.0;
                let rate_up = fold(Some(previous.1), up).unwrap_or(0.0) / span;
                let rate_down = fold(Some(previous.2), down).unwrap_or(0.0) / span;
                out.insert(protocol.clone(), (rate_up, rate_down));
            }
        }
        out
    }

    async fn refresh_names(&self) {
        let database = self.database.clone();
        let read = tokio::task::spawn_blocking(move || {
            database.with_connection(|db| {
                let mut statement = db.prepare(
                    "SELECT g.protocol,g.runtime_username,c.display_name FROM access_grants g
                                     JOIN clients c ON c.id=g.client_id WHERE g.node_id=?",
                )?;
                let rows = statement
                    .query_map([LOCAL_NODE], |row| Ok(((row.get(0)?, row.get(1)?), row.get(2)?)))?
                    .collect::<Result<HashMap<(String, String), Option<String>>, _>>()?;
                Ok::<_, StoreError>(rows)
            })
        })
        .await;
        let Ok(Ok(names)) = read else {
            return; // names are decoration
        };
        let name = self.sources.local_node_name().await.filter(|name| !name.is_empty());
        let mut state = self.state.lock().await;
        state.names = names;
        state.node_name = name.unwrap_or_else(|| LOCAL_NODE.to_string());
    }

    // ---- manager polls ----------------------------------------------------------------------
    fn kernel_has(protocol: &str, agent: Option<&Value>) -> bool {
        let Some(agent) = agent else {
            return false;
        };
        if agent.get("kernel_counters").and_then(Value::as_str) != Some("ok") {
            return false;
        }
        match agent.get("protocols").and_then(|p| p.get(protocol)) {
            Some(Value::Object(entry)) => num(entry.get("up_bps")).is_some(),
            _ => false,
        }
    }

    fn launch_due(self: &Arc<Self>, state: &mut State, mono: f64) {
        let mut inflight = lock(&self.inflight);
        for (protocol, every) in CADENCE {
            let busy = inflight.get(protocol).is_some_and(|task| !task.is_finished());
            if busy || !self.config.wanted(protocol) {
                continue;
            }
            if mono - state.last_poll.get(protocol).copied().unwrap_or(-1e9) < every.max(self.config.interval) {
                continue;
            }
            state.last_poll.insert(protocol, mono);
            let me = Arc::clone(self);
            inflight.insert(protocol, tokio::spawn(async move { me.poll(protocol, mono).await }));
        }
    }

    async fn poll(self: Arc<Self>, protocol: &'static str, mono: f64) {
        self.state.lock().await.manager.entry(protocol).or_insert(ManagerState {
            cum_up: 0.0,
            cum_down: 0.0,
            pending_up: 0.0,
            pending_down: 0.0,
            ok: false,
            at: mono,
            result: None,
        });
        let timeout = if protocol == "naive" { NAIVE_TIMEOUT } else { MANAGER_TIMEOUT };
        let answer = tokio::time::timeout(Duration::from_secs_f64(timeout), self.sources.poll(protocol)).await;
        let mut state = self.state.lock().await;
        let read = match &answer {
            Ok(Ok(value)) => self.read(&mut state, protocol, value, mono),
            _ => Err(()),
        };
        let manager = state.manager.get_mut(protocol).expect("set above");
        match read {
            Err(()) => manager.ok = false,
            Ok((result, delta_up, delta_down)) => {
                manager.result = Some(result);
                manager.ok = true;
                manager.at = mono;
                manager.cum_up += delta_up;
                manager.cum_down += delta_down;
                manager.pending_up += delta_up;
                manager.pending_down += delta_down;
            }
        }
        self.refresh_latest(&mut state);
    }

    /// `_read_<protocol>`: the poll's aggregate and its byte deltas, or `Err` when the answer
    /// has a shape Python could not iterate.
    fn read(&self, state: &mut State, protocol: &str, value: &Value, mono: f64) -> Result<(PollResult, f64, f64), ()> {
        match protocol {
            "trusttunnel" => {
                let clients = dict_items(value)?;
                // `tx` is the endpoint's inbound (the CLIENT'S DOWNLOAD), `rx` its outbound (upload).
                let rows: Vec<Row> = clients
                    .iter()
                    .filter_map(|c| {
                        c.get("username").and_then(Value::as_str).map(|u| (u, c.get("rx"), c.get("tx"), None))
                    })
                    .collect();
                let (mut out, up, down) = Self::fold_rows(&mut state.rates, protocol, &rows, mono, None);
                out.sessions = Some(clients.iter().map(|c| pyfloat::int(c.get("sessions")).unwrap_or(0)).sum());
                out.clients =
                    Some(clients.iter().filter(|c| pyfloat::int(c.get("sessions")).unwrap_or(0) > 0).count() as i64);
                Ok((out, up, down))
            }
            "amneziawg" => {
                let peers = dict_items(value)?;
                let rows: Vec<Row> = peers
                    .iter()
                    .filter_map(|p| {
                        p.get("username").and_then(Value::as_str).map(|u| (u, p.get("rx"), p.get("tx"), None))
                    })
                    .collect();
                let (mut out, up, down) = Self::fold_rows(&mut state.rates, protocol, &rows, mono, None);
                let now = self.clock.time();
                let active = peers
                    .iter()
                    .filter(|p| {
                        pyfloat::int(p.get("latest_handshake"))
                            .is_some_and(|at| at != 0 && now - (at as f64) < HANDSHAKE_FRESH_SECONDS)
                    })
                    .count() as i64;
                out.sessions = Some(active);
                out.clients = Some(active);
                Ok((out, up, down))
            }
            "mtproxy" => {
                let users = dict_items(value)?;
                let rows: Vec<Row> = users
                    .iter()
                    .filter_map(|u| {
                        u.get("username").and_then(Value::as_str).map(|n| (n, None, None, u.get("total_octets")))
                    })
                    .collect();
                let (mut out, up, down) = Self::fold_rows(&mut state.rates, protocol, &rows, mono, None);
                let connections: Vec<i64> =
                    users.iter().map(|u| pyfloat::int(u.get("current_connections")).unwrap_or(0)).collect();
                out.sessions = Some(connections.iter().sum());
                out.clients = Some(connections.iter().filter(|n| **n > 0).count() as i64);
                Ok((out, up, down))
            }
            "mieru" | "naive" => {
                let users = users_of(value)?;
                let rows: Vec<Row> = users
                    .iter()
                    .filter_map(|r| {
                        r.get("username")
                            .and_then(Value::as_str)
                            .map(|u| (u, r.get("upload_bytes"), r.get("download_bytes"), None))
                    })
                    .collect();
                let window = (protocol == "naive").then_some(NAIVE_WINDOW);
                let (out, up, down) = Self::fold_rows(&mut state.rates, protocol, &rows, mono, window);
                Ok((out, up, down))
            }
            _ => Err(()),
        }
    }

    /// Feeds `(username, up, down, total)` readings; the poll's aggregate and byte deltas.
    fn fold_rows(
        rates: &mut ClientRates,
        protocol: &str,
        rows: &[Row],
        mono: f64,
        window: Option<f64>,
    ) -> (PollResult, f64, f64) {
        let (mut up_bps, mut down_bps, mut total_bps) = (0.0, 0.0, 0.0);
        let (mut delta_up, mut delta_down) = (0.0, 0.0);
        let mut directional = true;
        for (username, up, down, total) in rows {
            let Some(rate) =
                rates.update(protocol, username, mono, Reading { up: *up, down: *down, total: *total }, window)
            else {
                continue;
            };
            total_bps += rate.total_bps;
            delta_up += rate.up_delta;
            delta_down += rate.down_delta;
            match (rate.up_bps, rate.down_bps) {
                (Some(up), Some(down)) => {
                    up_bps += up;
                    down_bps += down;
                }
                _ => directional = false,
            }
        }
        let result = PollResult {
            up_bps: directional.then_some(up_bps),
            down_bps: directional.then_some(down_bps),
            total_bps,
            directional,
            sessions: None,
            clients: None,
        };
        (result, delta_up, delta_down)
    }

    // ---- snapshot ---------------------------------------------------------------------------
    /// A manager answered (or failed): show it now instead of at the next tick.
    fn refresh_latest(&self, state: &mut State) {
        if state.latest.is_none() {
            return;
        }
        let mono = self.clock.monotonic();
        let agent = state.agent_now.clone();
        let protocols = self.protocols_json(state, agent.as_ref(), mono);
        let top = self.top_clients(state, mono);
        let latest = state.latest.as_mut().expect("checked");
        latest.insert("protocols".into(), protocols);
        latest.insert("top_clients".into(), top);
    }

    fn fresh<'a>(&self, state: &'a State, protocol: &str, mono: f64) -> Option<&'a ManagerState> {
        let manager = state.manager.get(protocol)?;
        if !manager.ok || manager.result.is_none() {
            return None;
        }
        (mono - manager.at <= 3.0 * cadence(protocol).max(self.config.interval)).then_some(manager)
    }

    fn protocol_entry(&self, state: &State, protocol: &str, agent: Option<&Value>, mono: f64) -> Entry {
        let mut entry = Entry::empty();
        let manager = self.fresh(state, protocol, mono);
        if Self::kernel_has(protocol, agent) {
            let kernel = agent.and_then(|a| a.get("protocols")).and_then(|p| p.get(protocol)).expect("kernel_has");
            let (mut up, mut down) = (num(kernel.get("up_bps")), num(kernel.get("down_bps")));
            if let Some((d_up, d_down)) = state.derived.get(protocol) {
                up = Some(round_to(*d_up, 1));
                down = Some(round_to(*d_down, 1));
            }
            // `source` when it is "kernel" or "interface", else "kernel"
            let interface = kernel.get("source").and_then(Value::as_str) == Some("interface");
            let source = if interface { "interface" } else { "kernel" };
            entry.available = true;
            entry.live = true;
            entry.source = Some(source.to_string());
            entry.up_bps = up;
            entry.down_bps = down;
            entry.total_bps = Some(up.unwrap_or(0.0) + down.unwrap_or(0.0));
            entry.up_bytes = pyfloat::int(kernel.get("up_bytes"));
            entry.down_bytes = pyfloat::int(kernel.get("down_bytes"));
            entry.connections = pyfloat::int(kernel.get("connections"));
        } else if let Some(manager) = manager {
            let result = manager.result.expect("fresh");
            entry.available = true;
            entry.live = protocol != "naive";
            entry.source = Some("manager".into());
            entry.up_bps = result.up_bps;
            entry.down_bps = result.down_bps;
            entry.total_bps = Some(result.total_bps);
            if result.directional {
                entry.up_bytes = Some(pyfloat::trunc(manager.cum_up));
                entry.down_bytes = Some(pyfloat::trunc(manager.cum_down));
            }
        } else if !self.config.wanted(protocol) {
            entry.reason = Some("disabled");
        } else if CADENCE.iter().any(|(p, _)| *p == protocol) {
            entry.reason = Some(if state.manager.contains_key(protocol) { "manager_unavailable" } else { "pending" });
        }
        if let (Some(manager), Some(status)) = (manager, state.manager.get(protocol)) {
            if status.ok {
                let result = manager.result.expect("fresh");
                entry.sessions = result.sessions;
                entry.clients = result.clients;
            }
        }
        entry
    }

    fn protocols_json(&self, state: &State, agent: Option<&Value>, mono: f64) -> Value {
        let mut map = Map::new();
        for protocol in PROTOCOLS {
            map.insert(protocol.to_string(), self.protocol_entry(state, protocol, agent, mono).to_json());
        }
        Value::Object(map)
    }

    fn top_clients(&self, state: &State, mono: f64) -> Value {
        let mut rows: Vec<(f64, Value)> = Vec::new();
        for (protocol, every) in CADENCE {
            if !self.config.wanted(protocol) {
                continue;
            }
            for (username, rate) in state.rates.current(protocol, mono, 3.0 * every.max(self.config.interval)) {
                if rate.total_bps <= 0.0 {
                    continue;
                }
                let name = state.names.get(&(protocol.to_string(), username.clone())).cloned().flatten();
                let row = json!({
                    "protocol": protocol, "username": username, "client_name": name,
                    "up_bps": opt_float(rate.up_bps.filter(|v| *v >= 0.0)),
                    "down_bps": opt_float(rate.down_bps.filter(|v| *v >= 0.0)),
                    "total_bps": float(rate.total_bps), "live": protocol != "naive",
                });
                rows.push((rate.total_bps, row));
            }
        }
        rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        Value::Array(rows.into_iter().take(TOP_CLIENTS).map(|(_, row)| row).collect())
    }

    fn build(&self, state: &State, agent: Option<&Value>, wall: f64, mono: f64) -> Map<String, Value> {
        let used = agent.or(state.last_agent.as_ref());
        let (status, age) = if agent.is_some() {
            ("ok", Some(0.0))
        } else if let Some(at) = state.last_agent_wall {
            ("stale", Some((wall - at).max(0.0)))
        } else {
            ("unavailable", None)
        };
        let mut node = Map::new();
        node.insert("node_id".into(), json!(LOCAL_NODE));
        node.insert("name".into(), json!(state.node_name));
        node.insert("status".into(), json!(status));
        node.insert("age_seconds".into(), opt_float(age.map(|a| round_to(a, 1))));
        node.insert("host".into(), used.and_then(|a| a.get("host")).cloned().unwrap_or(Value::Null));
        node.insert("protocols".into(), self.protocols_json(state, agent, mono));
        node.insert("top_clients".into(), self.top_clients(state, mono));
        node.insert(
            "kernel_counters".into(),
            used.and_then(|a| a.get("kernel_counters")).cloned().unwrap_or(Value::Null),
        );
        node
    }

    // ---- the numbers that go into the ring ---------------------------------------------------
    fn record(&self, state: &mut State, agent: Option<&Value>, mono: f64) -> IndexMap<String, Option<f64>> {
        let mut values = IndexMap::new();
        if let Some(agent) = agent {
            values.extend(host_values(agent.get("host")));
        }
        for protocol in PROTOCOLS {
            let entry = self.protocol_entry(state, protocol, agent, mono);
            if !entry.available {
                continue;
            }
            values.insert(format!("{protocol}.up_bps"), entry.up_bps);
            values.insert(format!("{protocol}.down_bps"), entry.down_bps);
            values.insert(format!("{protocol}.sessions"), entry.sessions.map(|v| v as f64));
            values.insert(format!("{protocol}.clients"), entry.clients.map(|v| v as f64));
            values.insert(format!("{protocol}.connections"), entry.connections.map(|v| v as f64));
            match entry.source.as_deref() {
                Some("kernel" | "interface") => {
                    let kernel = agent.and_then(|a| a.get("protocols")).and_then(|p| p.get(protocol));
                    let up = num(kernel.and_then(|k| k.get("up_bytes")));
                    let down = num(kernel.and_then(|k| k.get("down_bytes")));
                    let previous = state.kernel_prev.get(*protocol).copied();
                    if let (Some(up), Some(down)) = (up, down) {
                        state.kernel_prev.insert(protocol.to_string(), (up, down));
                        if let Some(previous) = previous {
                            values.insert(format!("{protocol}.up_bytes"), fold(Some(previous.0), up));
                            values.insert(format!("{protocol}.down_bytes"), fold(Some(previous.1), down));
                        }
                    }
                }
                Some("manager") => {
                    let manager = state.manager.get_mut(protocol).expect("a fresh manager");
                    if manager.result.is_some_and(|r| r.directional) {
                        values.insert(format!("{protocol}.up_bytes"), Some(manager.pending_up));
                        values.insert(format!("{protocol}.down_bytes"), Some(manager.pending_down));
                        manager.pending_up = 0.0;
                        manager.pending_down = 0.0;
                    }
                }
                _ => {}
            }
        }
        values
    }
}
