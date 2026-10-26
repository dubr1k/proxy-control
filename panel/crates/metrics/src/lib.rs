//! Live monitoring of the Proxy Control panel (work package WP13, Python `panel/metrics/**`):
//! the collector samples the host agent and the protocol managers every 2 s, keeps a ring of
//! recent points, rolls them up into SQLite (`metric_rollups`) and serves live, history,
//! summary and an SSE stream under `/api/metrics/*`.
//!
//! # Wiring (WP4 shell / WP14)
//!
//! ```ignore
//! // setup_metrics(app, settings, source=build_fleet_metrics_source(app))
//! let metrics = Metrics::setup(&settings, database.clone(), Arc::new(manager_meters), SystemClock::shared());
//! metrics.set_source(Some(fleet_meters));            // WP12; until then linked nodes are "unsupported"
//! // lifespan: only when metrics are on
//! if let Some(collector) = metrics.collector() {
//!     let task = tokio::spawn(collector.clone().run_forever());
//!     // shutdown: collector.stop(); wait up to 5 s for `task`, then abort it
//! }
//! // routes (registered where app.py:318 registers them): the shell runs `context.current`, then
//! // calls the handler with the caller and the request head
//! let caller = Caller { token_hash, via_api_key };
//! let response = panel_metrics::routes::live(&app_state, caller, &parts).await;
//! ```
//!
//! `AppState: MetricsState` supplies the re-check of a long stream's session/key, the list of
//! linked nodes (`nodes.list()` minus `local` and disabled ones) and the shared [`Metrics`]; the
//! caller check (`context.current`: session cookie or API key → [`routes::Caller`]) is the
//! shell's. [`routes::router`] serves the same handlers as a stand-alone axum router over
//! [`routes::MetricsHttp`] (this crate's tests). The fleet node routes `/api/fleet/v2/metrics*` (WP12) reuse
//! [`Metrics::local_entry`], [`Metrics::local_summary`], [`routes::parse_series`] and
//! [`MetricsStore::history`].

pub mod collector;
pub mod pyfloat;
pub mod query;
pub mod rates;
pub mod ring;
pub mod routes;
pub mod sources;
pub mod sse;
pub mod store;

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use futures_util::future::join_all;
use panel_core::clock::SharedClock;
use panel_core::db::Database;
use panel_core::settings::Settings;
use panel_model::metrics::{MetricsNode, NodeMetricsSource, LOCAL_NODE};
use panel_model::protocols::BoxFuture;
use serde_json::{json, Map, Value};

pub use collector::{CollectorConfig, MetricsCollector};
pub use rates::{fold, ClientRate, ClientRates};
pub use ring::SeriesRing;
#[cfg(feature = "managers")]
pub use sources::ManagerMeters;
pub use sources::MeterSources;
pub use sse::{Lease, StreamRegistry};
pub use store::{MetricsStore, StoreError};

/// The linked nodes' meters (`NodeMetricsSource` of WP2) plus the optional budgeted fan-out
/// Python looks up with `getattr(source, "live_many", None)`. The default fans `live` out to
/// every node without a budget, as Python does for a source without `live_many`; WP12's
/// `FleetMetricsSource` overrides it (late nodes answered from the last good entry as `stale`).
pub trait FleetMeters: NodeMetricsSource {
    fn live_many<'a>(&'a self, items: &'a [MetricsNode], budget: Duration) -> BoxFuture<'a, Vec<Option<Value>>> {
        let _ = budget;
        Box::pin(async move { join_all(items.iter().map(|item| self.live(&item.node_id))).await })
    }
}

/// The node keys of an entry that has nothing to show (`PLACEHOLDER`).
pub fn placeholder(node_id: &str, name: &str, status: &str) -> Value {
    json!({"node_id": node_id, "name": name, "status": status, "age_seconds": null, "host": null,
           "protocols": {}, "top_clients": [], "kernel_counters": null, "alerts": []})
}

/// What `setup_metrics` attaches to `app.state`: the ring, the store, the collector (only when
/// metrics are on), the stream registry and the optional fleet source.
pub struct Metrics {
    enabled: bool,
    ring: Arc<Mutex<SeriesRing>>,
    store: Arc<MetricsStore>,
    collector: Option<Arc<MetricsCollector>>,
    streams: Arc<StreamRegistry>,
    source: RwLock<Option<Arc<dyn FleetMeters>>>,
    clock: SharedClock,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics").field("enabled", &self.enabled).finish()
    }
}

impl Metrics {
    /// `setup_metrics(app, settings, clock=…)`.
    pub fn setup(
        settings: &Settings,
        database: Database,
        sources: Arc<dyn MeterSources>,
        clock: SharedClock,
    ) -> Arc<Self> {
        Self::new(
            settings.metrics_enabled,
            settings.metrics_ring_points,
            CollectorConfig::from_settings(settings),
            database,
            sources,
            clock,
        )
    }

    /// The same with explicit values (tests).
    pub fn new(
        enabled: bool,
        ring_points: i64,
        config: CollectorConfig,
        database: Database,
        sources: Arc<dyn MeterSources>,
        clock: SharedClock,
    ) -> Arc<Self> {
        let config = CollectorConfig { interval: config.interval.max(0.5), ..config };
        let ring = Arc::new(Mutex::new(SeriesRing::new(ring_points)));
        let store = Arc::new(MetricsStore::new(database, ring.clone(), config.interval, clock.clone()));
        let collector = enabled.then(|| MetricsCollector::new(config, store.clone(), sources, clock.clone()));
        Arc::new(Self {
            enabled,
            ring,
            store,
            collector,
            streams: Arc::new(StreamRegistry::default()),
            source: RwLock::new(None),
            clock,
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn ring(&self) -> &Arc<Mutex<SeriesRing>> {
        &self.ring
    }

    pub fn store(&self) -> &Arc<MetricsStore> {
        &self.store
    }

    pub fn collector(&self) -> Option<&Arc<MetricsCollector>> {
        self.collector.as_ref()
    }

    pub fn streams(&self) -> &Arc<StreamRegistry> {
        &self.streams
    }

    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }

    /// `app.state.metrics_source = …` (WP12 plugs the fleet in after the app is built).
    pub fn set_source(&self, source: Option<Arc<dyn FleetMeters>>) {
        *self.source.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = source;
    }

    pub fn source(&self) -> Option<Arc<dyn FleetMeters>> {
        self.source.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    /// This panel's node entry (the collector's latest), or an `unavailable` placeholder.
    pub async fn local_entry(&self) -> Value {
        let latest = match &self.collector {
            Some(collector) => collector.latest().await,
            None => None,
        };
        latest.unwrap_or_else(|| placeholder(LOCAL_NODE, LOCAL_NODE, "unavailable"))
    }

    /// The summary row of this panel's node: the store's summary plus name, status, age and
    /// alerts of the latest entry (`local_summary`).
    pub async fn local_summary(&self, range_name: &str) -> Result<Value, StoreError> {
        let mut body = match self.store.summary(range_name).await? {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        let entry = self.local_entry().await;
        for key in ["name", "status", "age_seconds"] {
            body.insert(key.into(), entry.get(key).cloned().unwrap_or(Value::Null));
        }
        body.insert("alerts".into(), entry.get("alerts").cloned().unwrap_or_else(|| json!([])));
        Ok(Value::Object(body))
    }
}
