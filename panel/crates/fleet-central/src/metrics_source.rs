//! `FleetMetricsSource`: on-demand live, history and summary fan-in for linked panels.
//!
//! Live reads have a two-second per-node cache and one shared request per key. At most eight node
//! calls run concurrently. A slow caller's budget never cancels the shared request: a late answer
//! still fills the cache, while the caller receives the last good sample as `stale` (or an
//! `unavailable` placeholder).

use std::collections::HashMap;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::future::{BoxFuture, FutureExt};
use futures_util::stream::{FuturesUnordered, StreamExt};
use panel_core::clock::SharedClock;
use panel_core::db::Database;
use panel_core::rusqlite::OptionalExtension as _;
use panel_metrics::{placeholder, FleetMeters};
use panel_model::metrics::{MetricsNode, NodeMetricsSource};
use panel_model::seams::NodeError;
use serde_json::{json, Map, Value};
use tokio::sync::Semaphore;

use crate::links::NodeLinkService;

pub const CAPABILITY: &str = "metrics.v1";
pub const TTL: Duration = Duration::from_secs(2);
pub const CALL_TIMEOUT: Duration = Duration::from_secs(3);
pub const HISTORY_TIMEOUT: Duration = Duration::from_secs(10);
pub const STALE: Duration = Duration::from_secs(120);
pub const LIVE_BUDGET: Duration = Duration::from_secs(4);
pub const CONCURRENCY: usize = 8;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone, Eq)]
enum FlightKey {
    Live(String),
    History(String, Vec<String>, String, i64),
    Summary(String, String),
}

impl PartialEq for FlightKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Live(a), Self::Live(b)) => a == b,
            (Self::History(a, as_, ar, ap), Self::History(b, bs, br, bp)) => {
                a == b && as_ == bs && ar == br && ap == bp
            }
            (Self::Summary(a, ar), Self::Summary(b, br)) => a == b && ar == br,
            _ => false,
        }
    }
}

impl Hash for FlightKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Self::Live(node) => node.hash(state),
            Self::History(node, series, range, points) => (node, series, range, points).hash(state),
            Self::Summary(node, range) => (node, range).hash(state),
        }
    }
}

type SharedValue = futures_util::future::Shared<BoxFuture<'static, Value>>;
type LinkState = Option<(bool, Vec<String>)>;

struct Inner {
    database: Database,
    links: Arc<NodeLinkService>,
    clock: SharedClock,
    ttl: Duration,
    call_timeout: Duration,
    history_timeout: Duration,
    stale: Duration,
    slots: Arc<Semaphore>,
    cache: Mutex<HashMap<String, (f64, Value)>>,
    good: Mutex<HashMap<String, (f64, Value)>>,
    inflight: Arc<Mutex<HashMap<FlightKey, SharedValue>>>,
}

/// The central's source of linked-node meters. Cheap to clone; all clones share its caches.
#[derive(Clone)]
pub struct FleetMetricsSource {
    inner: Arc<Inner>,
}

impl FleetMetricsSource {
    pub fn new(database: Database, links: Arc<NodeLinkService>, clock: SharedClock) -> Self {
        Self::with_options(database, links, clock, TTL, CALL_TIMEOUT, HISTORY_TIMEOUT, STALE, CONCURRENCY)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_options(
        database: Database,
        links: Arc<NodeLinkService>,
        clock: SharedClock,
        ttl: Duration,
        call_timeout: Duration,
        history_timeout: Duration,
        stale: Duration,
        concurrency: usize,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                database,
                links,
                clock,
                ttl,
                call_timeout,
                history_timeout,
                stale,
                slots: Arc::new(Semaphore::new(concurrency.max(1))),
                cache: Mutex::new(HashMap::new()),
                good: Mutex::new(HashMap::new()),
                inflight: Arc::new(Mutex::new(HashMap::new())),
            }),
        }
    }

    fn name(&self, node_id: &str) -> String {
        self.inner
            .database
            .with_connection(|db| {
                db.query_row("SELECT display_name FROM fleet_nodes WHERE node_id=?", [node_id], |row| {
                    row.get::<_, String>(0)
                })
                .optional()
                .map_err(panel_core::db::DbError::from)
            })
            .ok()
            .flatten()
            .unwrap_or_else(|| node_id.to_string())
    }

    /// `(online, capabilities)` of the current v2 link. Any damaged/missing row is unsupported,
    /// as Python's broad `_link_state` failure guard specified.
    fn state(&self, node_id: &str) -> LinkState {
        let row = self.inner.database.with_connection(|db| {
            db.query_row("SELECT status,identity_json FROM node_links WHERE node_id=?", [node_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .optional()
            .map_err(panel_core::db::DbError::from)
        });
        let (status, identity) = row.ok().flatten()?;
        let identity: Value = serde_json::from_str(&identity).ok()?;
        let capabilities = identity
            .get("capabilities")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        Some((status == "online", capabilities))
    }

    async fn metadata(&self, node_id: &str) -> (String, LinkState) {
        let this = self.clone();
        let node = node_id.to_owned();
        tokio::task::spawn_blocking(move || (this.name(&node), this.state(&node)))
            .await
            .unwrap_or_else(|_| (node_id.to_owned(), None))
    }

    fn nodes_blocking(&self) -> Vec<MetricsNode> {
        self.inner
            .database
            .with_connection(|db| {
                let mut statement = db.prepare(
                    "SELECT node_id,display_name FROM fleet_nodes
                     WHERE node_id<>'local' AND disabled=0 ORDER BY node_id",
                )?;
                let rows =
                    statement.query_map([], |row| Ok(MetricsNode { node_id: row.get(0)?, name: row.get(1)? }))?;
                rows.collect::<Result<Vec<_>, _>>().map_err(panel_core::db::DbError::from)
            })
            .unwrap_or_default()
    }

    fn failed(&self, node_id: &str, name: &str) -> Value {
        let now = self.inner.clock.monotonic();
        let good = lock(&self.inner.good).get(node_id).cloned();
        if let Some((at, mut entry)) = good {
            let age = now - at;
            if age <= self.inner.stale.as_secs_f64() {
                let previous = entry.get("age_seconds").and_then(Value::as_f64).unwrap_or(0.0);
                entry["status"] = json!("stale");
                entry["age_seconds"] = json!(panel_metrics::pyfloat::round_to(age + previous, 1));
                entry["node_id"] = json!(node_id);
                entry["name"] = json!(name);
                return entry;
            }
        }
        placeholder(node_id, name, "unavailable")
    }

    fn missing(error: &NodeError) -> bool {
        matches!(error, NodeError::Rejected { status: 404, .. })
    }

    async fn client(&self, node_id: &str) -> Result<Arc<dyn panel_model::seams::NodeClient>, NodeError> {
        let links = self.inner.links.clone();
        let node_id = node_id.to_string();
        tokio::task::spawn_blocking(move || links.client_for(&node_id))
            .await
            .map_err(|error| NodeError::Unreachable(error.to_string()))?
            .map_err(|error| match error {
                crate::CentralError::Node(node) => node,
                other => NodeError::Unreachable(other.to_string()),
            })
    }

    async fn guarded<F>(&self, timeout: Duration, fetch: F) -> Result<Value, NodeError>
    where
        F: Future<Output = Result<Map<String, Value>, NodeError>>,
    {
        let slots = self.inner.slots.clone();
        let work = async move {
            let _slot = slots.acquire_owned().await.map_err(|error| NodeError::Unreachable(error.to_string()))?;
            fetch.await.map(Value::Object)
        };
        tokio::time::timeout(timeout, work).await.map_err(|_| NodeError::Unreachable("TimeoutError".into()))?
    }

    async fn pull(&self, node_id: &str, name: &str) -> Value {
        let timeout = self.inner.call_timeout;
        let result = self.guarded(timeout, async { self.client(node_id).await?.metrics(timeout).await }).await;
        let body = match result {
            Ok(Value::Object(body)) if body.contains_key("status") => body,
            Ok(_) => return self.failed(node_id, name),
            Err(error) if Self::missing(&error) => return placeholder(node_id, name, "unsupported"),
            Err(_) => return self.failed(node_id, name),
        };
        let mut entry = placeholder(node_id, name, "unavailable");
        let map = entry.as_object_mut().expect("a placeholder object");
        for (key, value) in body {
            map.insert(key, value);
        }
        map.insert("node_id".into(), json!(node_id));
        map.insert("name".into(), json!(name));
        lock(&self.inner.good).insert(node_id.to_string(), (self.inner.clock.monotonic(), entry.clone()));
        entry
    }

    async fn refresh(&self, node_id: &str) -> Value {
        let (name, state) = self.metadata(node_id).await;
        let entry = match state {
            None => placeholder(node_id, &name, "unsupported"),
            Some((_, capabilities)) if !capabilities.iter().any(|item| item == CAPABILITY) => {
                placeholder(node_id, &name, "unsupported")
            }
            Some((false, _)) => placeholder(node_id, &name, "unavailable"),
            Some((true, _)) => self.pull(node_id, &name).await,
        };
        lock(&self.inner.cache).insert(node_id.to_string(), (self.inner.clock.monotonic(), entry.clone()));
        entry
    }

    fn finish_flight(flights: &Mutex<HashMap<FlightKey, SharedValue>>, key: &FlightKey, shared: &SharedValue) {
        let mut flights = lock(flights);
        if flights.get(key).is_some_and(|current| current.ptr_eq(shared)) {
            flights.remove(key);
        }
    }

    async fn flight(&self, key: FlightKey, work: impl Future<Output = Value> + Send + 'static) -> Value {
        let (shared, start) = {
            let mut flights = lock(&self.inner.inflight);
            match flights.get(&key) {
                Some(existing) => (existing.clone(), false),
                None => {
                    let shared = work.boxed().shared();
                    flights.insert(key.clone(), shared.clone());
                    (shared, true)
                }
            }
        };
        if start {
            // A caller's budget/cancellation must not stop the cache refresh. Keep an unpolled
            // handle for pointer identity: a polled-to-completion Shared loses its identity.
            let flights = self.inner.inflight.clone();
            let key = key.clone();
            let shared = shared.clone();
            tokio::spawn(async move {
                shared.clone().await;
                Self::finish_flight(&flights, &key, &shared);
            });
        }
        let answer = shared.clone().await;
        // Remove before returning as well: the driver may not have been scheduled yet. Otherwise
        // an immediately expired cache can reuse the completed request as if it were in flight.
        Self::finish_flight(&self.inner.inflight, &key, &shared);
        answer
    }

    async fn live_inner(&self, node_id: &str) -> Value {
        let now = self.inner.clock.monotonic();
        if let Some((at, entry)) = lock(&self.inner.cache).get(node_id).cloned() {
            if now - at < self.inner.ttl.as_secs_f64() {
                return entry;
            }
        }
        let this = self.clone();
        let node = node_id.to_string();
        self.flight(FlightKey::Live(node.clone()), async move { this.refresh(&node).await }).await
    }

    async fn history_inner(&self, node_id: &str, series: &[String], range: &str, points: i64) -> Value {
        let (name, capable) = self.metadata(node_id).await;
        let mut base = json!({"node_id": node_id, "name": name, "range": range, "series": {}});
        match &capable {
            None => {
                base["status"] = json!("unsupported");
                return base;
            }
            Some((_, capabilities)) if !capabilities.iter().any(|item| item == CAPABILITY) => {
                base["status"] = json!("unsupported");
                return base;
            }
            Some((false, _)) => {
                base["status"] = json!("unavailable");
                return base;
            }
            _ => {}
        }
        let timeout = self.inner.history_timeout;
        let budget = timeout + Duration::from_secs(1);
        let key = FlightKey::History(node_id.to_string(), series.to_vec(), range.to_string(), points);
        let this = self.clone();
        let node = node_id.to_string();
        let series_owned = series.to_vec();
        let range_owned = range.to_string();
        let result = self
            .flight(key, async move {
                match this
                    .guarded(budget, async {
                        this.client(&node).await?.metrics_history(&series_owned, &range_owned, points, timeout).await
                    })
                    .await
                {
                    Ok(body) => body,
                    Err(error) => json!({"__metrics_error": Self::missing(&error)}),
                }
            })
            .await;
        if let Some(Value::Bool(missing)) = result.get("__metrics_error") {
            base["status"] = json!(if *missing { "unsupported" } else { "unavailable" });
            return base;
        }
        if let Value::Object(body) = result {
            let status = body.get("status").cloned().unwrap_or_else(|| json!("ok"));
            let map = base.as_object_mut().expect("an object");
            for (key, value) in body {
                map.insert(key, value);
            }
            map.insert("node_id".into(), json!(node_id));
            map.insert("name".into(), json!(name));
            map.insert("status".into(), json!(status));
        }
        base
    }

    async fn summary_inner(&self, node_id: &str, range: &str) -> Value {
        let (name, state) = self.metadata(node_id).await;
        let mut base = json!({"node_id": node_id, "name": name, "host": null, "protocols": {},
                              "hours_of_day": {}, "alerts": []});
        match state {
            None => {
                base["status"] = json!("unsupported");
                return base;
            }
            Some((_, capabilities)) if !capabilities.iter().any(|item| item == CAPABILITY) => {
                base["status"] = json!("unsupported");
                return base;
            }
            Some((false, _)) => {
                base["status"] = json!("unavailable");
                return base;
            }
            _ => {}
        }
        let timeout = self.inner.history_timeout;
        let budget = timeout + Duration::from_secs(1);
        let this = self.clone();
        let node = node_id.to_string();
        let range_owned = range.to_string();
        let result = self
            .flight(FlightKey::Summary(node_id.to_string(), range.to_string()), async move {
                match this
                    .guarded(budget, async { this.client(&node).await?.metrics_summary(&range_owned, timeout).await })
                    .await
                {
                    Ok(body) => body,
                    Err(error) => json!({"__metrics_error": Self::missing(&error)}),
                }
            })
            .await;
        if let Some(Value::Bool(missing)) = result.get("__metrics_error") {
            base["status"] = json!(if *missing { "unsupported" } else { "unavailable" });
            return base;
        }
        base["status"] = json!("ok");
        if let Value::Object(body) = result {
            let map = base.as_object_mut().expect("an object");
            for (key, value) in body {
                map.insert(key, value);
            }
            map.insert("node_id".into(), json!(node_id));
            map.insert("name".into(), json!(name));
        }
        base
    }
}

impl NodeMetricsSource for FleetMetricsSource {
    fn live<'a>(&'a self, node_id: &'a str) -> BoxFuture<'a, Option<Value>> {
        Box::pin(async move { Some(self.live_inner(node_id).await) })
    }

    fn history<'a>(
        &'a self,
        node_id: &'a str,
        series: &'a [String],
        range: &'a str,
        points: i64,
    ) -> BoxFuture<'a, Option<Value>> {
        Box::pin(async move { Some(self.history_inner(node_id, series, range, points).await) })
    }

    fn summary<'a>(&'a self, node_id: &'a str, range: &'a str) -> BoxFuture<'a, Option<Value>> {
        Box::pin(async move { Some(self.summary_inner(node_id, range).await) })
    }

    fn nodes(&self) -> BoxFuture<'_, Vec<MetricsNode>> {
        Box::pin(async move {
            let this = self.clone();
            tokio::task::spawn_blocking(move || this.nodes_blocking()).await.unwrap_or_default()
        })
    }
}

impl FleetMeters for FleetMetricsSource {
    fn live_many<'a>(&'a self, items: &'a [MetricsNode], budget: Duration) -> BoxFuture<'a, Vec<Option<Value>>> {
        Box::pin(async move {
            let mut running = FuturesUnordered::new();
            for (index, item) in items.iter().enumerate() {
                let this = self.clone();
                let node = item.node_id.clone();
                running.push(async move {
                    let answer = tokio::spawn(async move { this.live_inner(&node).await }).await;
                    (index, answer)
                });
            }
            let mut out = items.iter().map(|_| None).collect::<Vec<Option<Value>>>();
            let _ = tokio::time::timeout(budget, async {
                while let Some((index, answer)) = running.next().await {
                    out[index] = answer.ok();
                }
            })
            .await;
            for (index, item) in items.iter().enumerate() {
                if out[index].is_none() {
                    // Dropping the still-running JoinHandles with `running` detaches them. Their
                    // shared requests continue and fill the cache for the next tick.
                    out[index] = Some(self.failed(&item.node_id, &item.name));
                }
            }
            out
        })
    }
}
