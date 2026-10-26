//! Rollups in SQLite and the read side: history, summary and alerts (`metrics/store.py`).
//!
//! The ring holds the newest points at the native step; `metric_rollups` holds 60 s, 900 s and
//! 3600 s buckets. A read merges both: the database has every point up to `flushed_until`, the
//! ring has the rest. Database work runs on tokio's blocking pool; one flush is one
//! `BEGIN IMMEDIATE` transaction (the fleet-ingress process writes the same file).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use indexmap::IndexMap;
use panel_core::clock::SharedClock;
use panel_core::db::{Database, DbError};
use panel_core::rusqlite::{params_from_iter, types::Value as SqlValue};
use panel_model::metrics::{
    all_series, is_bytes_series, range_seconds, resolution_for, LOCAL_NODE, PROTOCOLS, RANGES, RETENTION,
};
use serde_json::{json, Map, Value};

use crate::pyfloat::{self, float, floordiv, opt_float, round_to, trunc};
use crate::ring::SeriesRing;

pub const EPS: f64 = 1e-6;
pub const UPSERT: &str = "INSERT INTO metric_rollups(resolution,bucket,node_id,series,sum,count,max,last)
  VALUES(?,?,?,?,?,?,?,?)
  ON CONFLICT(resolution,bucket,node_id,series) DO UPDATE SET
    sum=sum+excluded.sum, count=count+excluded.count, max=max(max,excluded.max), last=excluded.last";

pub const SUMMARY_HOST: &[(&str, &str)] = &[
    ("cpu", "host.cpu"),
    ("mem", "host.mem"),
    ("swap", "host.swap"),
    ("disk", "host.disk"),
    ("load1", "host.load1"),
    ("net_rx_bps", "net.rx_bps"),
    ("net_tx_bps", "net.tx_bps"),
];
/// Alert thresholds: warn above the first number, critical above the second.
pub const CPU_AVG: (f64, f64) = (85.0, 95.0);
pub const MEM: (f64, f64) = (90.0, 97.0);
pub const DISK: (f64, f64) = (90.0, 95.0);
pub const SWAP: (f64, f64) = (50.0, 80.0);
pub const STALE_SECONDS: (f64, f64) = (60.0, 300.0);
pub const SPIKE_FACTOR: (f64, f64) = (3.0, 6.0);
pub const SPIKE_FLOOR_BPS: f64 = 256.0 * 1024.0;

/// A store failure (the database, or its worker thread).
#[derive(Debug)]
pub enum StoreError {
    Db(DbError),
    Worker(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Db(error) => write!(f, "{error}"),
            StoreError::Worker(error) => write!(f, "metrics store worker failed: {error}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<DbError> for StoreError {
    fn from(error: DbError) -> Self {
        StoreError::Db(error)
    }
}

impl From<panel_core::rusqlite::Error> for StoreError {
    fn from(error: panel_core::rusqlite::Error) -> Self {
        StoreError::Db(error.into())
    }
}

/// `math.floor(ts / step) * step` with an integer step.
fn bucket(ts: f64, step: i64) -> i64 {
    (ts / step as f64).floor() as i64 * step
}

/// `_num`: `round(value, 3)` or `None`.
fn num3(value: Option<f64>) -> Value {
    opt_float(value.map(|v| round_to(v, 3)))
}

/// Nearest-rank percentile.
pub fn percentile(values: &[f64], q: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let rank = ((q * ordered.len() as f64).ceil() as usize).max(1);
    Some(ordered[rank - 1])
}

/// One bucket being merged: `[sum, count, max, last]`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Slot {
    pub sum: f64,
    pub count: i64,
    pub max: f64,
    pub last: f64,
}

impl Slot {
    const EMPTY: Slot = Slot { sum: 0.0, count: 0, max: f64::NEG_INFINITY, last: 0.0 };

    fn add(&mut self, total: f64, count: i64, peak: f64, last: f64) {
        self.sum += total;
        self.count += count;
        if peak > self.max {
            self.max = peak;
        }
        self.last = last;
    }
}

/// A rollup row key: (resolution, bucket, series).
pub type RollupKey = (i64, i64, String);

/// Per series, bucket start → slot, in the order the buckets were first seen.
pub type Gathered = IndexMap<String, IndexMap<i64, Slot>>;

/// Where `gather` read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Ring,
    Rollup,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Ring => "ring",
            Source::Rollup => "rollup",
        }
    }
}

#[derive(Debug, Default)]
struct StoreState {
    flushed_until: f64,
    last_prune: f64,
    baseline_memo: Option<(i64, Option<f64>)>,
}

pub struct MetricsStore {
    database: Database,
    ring: Arc<Mutex<SeriesRing>>,
    interval: f64,
    clock: SharedClock,
    node_id: String,
    state: Mutex<StoreState>,
    day_reads: AtomicU64,
}

impl std::fmt::Debug for MetricsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsStore").field("interval", &self.interval).field("node_id", &self.node_id).finish()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    tokio::task::spawn_blocking(work).await.map_err(|error| StoreError::Worker(error.to_string()))?
}

impl MetricsStore {
    pub fn new(database: Database, ring: Arc<Mutex<SeriesRing>>, interval: f64, clock: SharedClock) -> Self {
        Self {
            database,
            ring,
            interval,
            clock,
            node_id: LOCAL_NODE.to_string(),
            state: Mutex::new(StoreState::default()),
            day_reads: AtomicU64::new(0),
        }
    }

    pub fn interval(&self) -> f64 {
        self.interval
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    pub fn ring(&self) -> &Arc<Mutex<SeriesRing>> {
        &self.ring
    }

    /// The newest point already in the database.
    pub fn flushed_until(&self) -> f64 {
        lock(&self.state).flushed_until
    }

    /// When the last prune ran (wall seconds).
    pub fn last_prune(&self) -> f64 {
        lock(&self.state).last_prune
    }

    /// How many times the spike baseline read the last day from the database.
    pub fn day_reads(&self) -> u64 {
        self.day_reads.load(Ordering::Relaxed)
    }

    // ---- write side -------------------------------------------------------------------------
    /// The ring points the database has not got yet, oldest first.
    pub fn pending(&self) -> Vec<(String, f64, f64)> {
        let since = self.flushed_until() + EPS;
        let ring = lock(&self.ring);
        let mut points = Vec::new();
        for series in ring.series_names() {
            points.extend(
                ring.points_of(&series, since, f64::INFINITY).into_iter().map(|(ts, v)| (series.clone(), ts, v)),
            );
        }
        points.sort_by(|a, b| a.1.total_cmp(&b.1));
        points
    }

    /// The rollup rows of some points at every resolution.
    pub fn aggregate(points: &[(String, f64, f64)]) -> IndexMap<RollupKey, Slot> {
        let mut rows: IndexMap<RollupKey, Slot> = IndexMap::new();
        for (series, ts, value) in points {
            for (resolution, _) in RETENTION {
                let res = *resolution as f64;
                let key = (*resolution, trunc(floordiv(*ts, res) * res), series.clone());
                match rows.get_mut(&key) {
                    None => {
                        rows.insert(key, Slot { sum: *value, count: 1, max: *value, last: *value });
                    }
                    Some(row) => row.add(*value, 1, *value, *value),
                }
            }
        }
        rows
    }

    /// All rows of one flush in ONE transaction (two processes write this file). Synchronous.
    pub fn write(&self, rows: &IndexMap<RollupKey, Slot>) -> Result<(), StoreError> {
        write_rows(&self.database, &self.node_id, rows)
    }

    /// Writes the pending points; the number of rows written.
    pub async fn flush(&self) -> Result<usize, StoreError> {
        let points = self.pending();
        if points.is_empty() {
            return Ok(0);
        }
        let rows = Self::aggregate(&points);
        let count = rows.len();
        let (database, node_id) = (self.database.clone(), self.node_id.clone());
        blocking(move || write_rows(&database, &node_id, &rows)).await?;
        let newest = points.iter().map(|p| p.1).fold(f64::NEG_INFINITY, f64::max);
        lock(&self.state).flushed_until = newest;
        Ok(count)
    }

    /// Drops the buckets past each resolution's retention; the number of rows removed.
    pub async fn prune(&self, now: Option<f64>) -> Result<usize, StoreError> {
        let now = now.unwrap_or_else(|| self.clock.time());
        lock(&self.state).last_prune = now;
        let database = self.database.clone();
        blocking(move || {
            database.transaction(|db| {
                let mut removed = 0;
                for (resolution, keep) in RETENTION {
                    removed += db.execute(
                        "DELETE FROM metric_rollups WHERE resolution=? AND bucket<?",
                        (resolution, trunc(now - *keep as f64)),
                    )?;
                }
                Ok::<_, StoreError>(removed)
            })
        })
        .await
    }

    // ---- read side --------------------------------------------------------------------------
    async fn read(&self, series: Vec<String>, resolution: i64, start: i64, end: i64) -> Result<Vec<Row>, StoreError> {
        let (database, node_id) = (self.database.clone(), self.node_id.clone());
        blocking(move || read_rows(&database, &node_id, &series, resolution, start, end)).await
    }

    async fn stored_before(&self, start: f64, oldest: f64) -> Result<bool, StoreError> {
        let (database, node_id) = (self.database.clone(), self.node_id.clone());
        blocking(move || {
            database.with_connection(|db| {
                let mut statement = db.prepare(
                    "SELECT 1 FROM metric_rollups WHERE resolution=60 AND bucket>=? AND bucket<? AND node_id=? LIMIT 1",
                )?;
                let found = statement.exists((bucket(start, 60), bucket(oldest, 60), node_id))?;
                Ok::<_, StoreError>(found)
            })
        })
        .await
    }

    /// The ring answers a short range when it reaches back to its start, or when the database
    /// has nothing older in that window (a fresh process, not a wrapped ring).
    async fn ring_covers(&self, start: f64) -> Result<bool, StoreError> {
        let Some(oldest) = lock(&self.ring).oldest(None) else {
            return Ok(false);
        };
        if oldest <= start + 2.0 * self.interval {
            return Ok(true);
        }
        Ok(!self.stored_before(start, oldest).await?)
    }

    /// Buckets for the series over the last `range_seconds`: (source, step, start, end, data).
    pub async fn gather(
        &self,
        series: &[String],
        range_seconds: i64,
        points: i64,
    ) -> Result<(Source, i64, f64, f64, Gathered), StoreError> {
        let end = self.clock.time();
        let start = end - range_seconds as f64;
        let mut data: Gathered = series.iter().map(|name| (name.clone(), IndexMap::new())).collect();
        if range_seconds <= 3600 && self.ring_covers(start).await? {
            let per = (range_seconds as f64 / self.interval / points as f64).ceil().max(1.0);
            let step = pyfloat::round_int(self.interval * per).max(1);
            let ring = lock(&self.ring);
            for name in series {
                add_points(data.get_mut(name).expect("series slot"), &ring.points_of(name, start, end), step);
            }
            return Ok((Source::Ring, step, start, end, data));
        }
        let resolution = resolution_for(range_seconds);
        let step = resolution * ((range_seconds as f64 / resolution as f64 / points as f64).ceil() as i64).max(1);
        let rows = self.read(series.to_vec(), resolution, bucket(start, resolution), trunc(end)).await?;
        for (name, stored, total, count, peak, last) in rows {
            if let Some(slots) = data.get_mut(&name) {
                slots.entry(bucket(stored as f64, step)).or_insert(Slot::EMPTY).add(total, count, peak, last);
            }
        }
        let since = start.max(self.flushed_until() + EPS);
        let ring = lock(&self.ring);
        for name in series {
            add_points(data.get_mut(name).expect("series slot"), &ring.points_of(name, since, end), step);
        }
        Ok((Source::Rollup, step, start, end, data))
    }

    /// The body of `/api/metrics/history` for this node (without `status`).
    pub async fn history(&self, series: &[String], range_name: &str, points: i64) -> Result<Value, StoreError> {
        let seconds = range_seconds(range_name).expect("a checked range");
        let (mode, step, start, end, data) = self.gather(series, seconds, points).await?;
        let mut grid = Vec::new();
        let mut at = bucket(start, step);
        while (at as f64) <= end {
            grid.push(at);
            at += step;
        }
        let mut out = Map::new();
        for name in series {
            let slots = &data[name];
            let rows: Vec<Value> = grid
                .iter()
                .map(|at| match slots.get(at) {
                    None => json!([at, null, null]),
                    Some(slot) => {
                        let value = if is_bytes_series(name) { slot.sum } else { slot.sum / slot.count as f64 };
                        json!([at, num3(Some(value)), num3(Some(slot.max))])
                    }
                })
                .collect();
            out.insert(name.clone(), Value::Array(rows));
        }
        let mut body = Map::new();
        body.insert("node_id".into(), json!(self.node_id));
        body.insert("range".into(), json!(range_name));
        body.insert("step".into(), json!(step));
        body.insert("from".into(), json!(trunc(start)));
        body.insert("to".into(), json!(trunc(end)));
        body.insert("source".into(), json!(mode.as_str()));
        body.insert("resolution".into(), json!(if mode == Source::Ring { 0 } else { resolution_for(seconds) }));
        body.insert("series".into(), Value::Object(out));
        Ok(Value::Object(body))
    }

    /// The summary of this node over a range (`/api/metrics/summary` row without name/status).
    pub async fn summary(&self, range_name: &str) -> Result<Value, StoreError> {
        let seconds = range_seconds(range_name).expect("a checked range");
        let names = all_series();
        let (mode, step, start, end, data) = self.gather(&names, seconds, 2000).await?;
        let empty = IndexMap::new();
        let slots_of = |name: &str| data.get(name).unwrap_or(&empty);

        let stats = |name: &str| -> Value {
            let slots = slots_of(name);
            if slots.is_empty() {
                return json!({"avg": null, "p95": null, "max": null, "max_at": null});
            }
            let count: i64 = slots.values().map(|s| s.count).sum();
            let total = slots.values().fold(0.0, |sum, s| sum + s.sum);
            let (top_at, top) = first_max(slots.iter().map(|(at, s)| (*at, s.max))).expect("non-empty");
            let averages: Vec<f64> = slots.values().map(|s| s.sum / s.count as f64).collect();
            let mut row = Map::new();
            row.insert("avg".into(), num3(Some(total / count as f64)));
            row.insert("p95".into(), num3(percentile(&averages, 0.95)));
            row.insert("max".into(), num3(Some(top)));
            row.insert("max_at".into(), json!(top_at));
            Value::Object(row)
        };
        let avg = |name: &str| -> Option<f64> {
            let slots = slots_of(name);
            let count: i64 = slots.values().map(|s| s.count).sum();
            (count != 0).then(|| slots.values().fold(0.0, |sum, s| sum + s.sum) / count as f64)
        };

        let mut host = Map::new();
        for (key, series) in SUMMARY_HOST {
            host.insert((*key).into(), stats(series));
        }
        let mut totals: Vec<(&str, Map<String, Value>, Option<i64>)> = Vec::new();
        for proto in PROTOCOLS {
            let up = slots_of(&format!("{proto}.up_bytes"));
            let down = slots_of(&format!("{proto}.down_bytes"));
            let up_b = up.values().fold(0.0, |sum, s| sum + s.sum);
            let down_b = down.values().fold(0.0, |sum, s| sum + s.sum);
            let has_bytes = !up.is_empty() || !down.is_empty();
            let rate_parts: Vec<f64> =
                [avg(&format!("{proto}.up_bps")), avg(&format!("{proto}.down_bps"))].into_iter().flatten().collect();
            let mut peaks: IndexMap<i64, f64> = IndexMap::new();
            for direction in ["up_bps", "down_bps"] {
                for (at, slot) in slots_of(&format!("{proto}.{direction}")) {
                    *peaks.entry(*at).or_insert(0.0) += slot.max;
                }
            }
            let peak = first_max(peaks.iter().map(|(at, v)| (*at, *v)));
            let sessions = slots_of(&format!("{proto}.sessions"));
            let connections = slots_of(&format!("{proto}.connections"));
            let total_bytes = has_bytes.then(|| trunc(up_b + down_b));
            let mut row = Map::new();
            row.insert("up_bytes".into(), opt_int(has_bytes.then(|| trunc(up_b))));
            row.insert("down_bytes".into(), opt_int(has_bytes.then(|| trunc(down_b))));
            row.insert("total_bytes".into(), opt_int(total_bytes));
            row.insert(
                "avg_bps".into(),
                if rate_parts.is_empty() { Value::Null } else { num3(Some(rate_parts.iter().fold(0.0, |s, v| s + v))) },
            );
            row.insert("peak_bps".into(), num3(peak.map(|p| p.1)));
            row.insert("peak_at".into(), opt_int(peak.map(|p| p.0)));
            row.insert("share_percent".into(), Value::Null);
            row.insert("sessions_peak".into(), opt_int(first_max_value(sessions).map(trunc)));
            row.insert("connections_peak".into(), opt_int(first_max_value(connections).map(trunc)));
            totals.push((proto, row, total_bytes));
        }
        let grand: i64 = totals.iter().map(|(_, _, total)| total.unwrap_or(0)).sum();
        let mut protocols = Map::new();
        for (proto, mut row, total) in totals {
            if let (Some(total), true) = (total, grand > 0) {
                row.insert("share_percent".into(), float(round_to(total as f64 * 100.0 / grand as f64, 1)));
            }
            protocols.insert(proto.to_string(), Value::Object(row));
        }
        let mut hours = Map::new();
        if seconds >= range_seconds("7d").expect("7d") {
            for proto in PROTOCOLS {
                let mut cells: IndexMap<i64, IndexMap<&str, (f64, i64)>> = IndexMap::new();
                for direction in ["up_bps", "down_bps"] {
                    for (at, slot) in slots_of(&format!("{proto}.{direction}")) {
                        let cell = cells
                            .entry(at.div_euclid(3600).rem_euclid(24))
                            .or_default()
                            .entry(direction)
                            .or_insert((0.0, 0));
                        cell.0 += slot.sum;
                        cell.1 += slot.count;
                    }
                }
                let row: Vec<Value> = (0..24)
                    .map(|h| match cells.get(&h) {
                        Some(cell) => num3(Some(cell.values().fold(0.0, |s, c| s + c.0 / c.1 as f64))),
                        None => Value::Null,
                    })
                    .collect();
                hours.insert(proto.to_string(), Value::Array(row));
            }
        }
        let mut body = Map::new();
        body.insert("node_id".into(), json!(self.node_id));
        body.insert("range".into(), json!(range_name));
        body.insert("from".into(), json!(trunc(start)));
        body.insert("to".into(), json!(trunc(end)));
        body.insert("step".into(), json!(step));
        body.insert("source".into(), json!(mode.as_str()));
        body.insert("host".into(), Value::Object(host));
        body.insert("protocols".into(), Value::Object(protocols));
        body.insert("hours_of_day".into(), Value::Object(hours));
        Ok(Value::Object(body))
    }

    // ---- alerts -----------------------------------------------------------------------------
    fn tail_since(points: &[(f64, f64)], over: f64) -> Option<f64> {
        let mut since = None;
        for (ts, value) in points.iter().rev() {
            if *value <= over {
                break;
            }
            since = Some(*ts);
        }
        since
    }

    /// The alerts of this node now (`status`/`age_seconds` of the latest tick).
    pub async fn alerts(&self, status: &str, age_seconds: Option<f64>) -> Result<Vec<Value>, StoreError> {
        let now = self.clock.time();
        let mut found = Vec::new();
        let add = |found: &mut Vec<Value>, kind: &str, level: &str, since: f64, detail: String| {
            found.push(json!({"kind": kind, "severity": level, "since": trunc(since), "detail": detail}));
        };
        if matches!(status, "stale" | "unavailable") && age_seconds.is_none_or(|age| age > STALE_SECONDS.0) {
            let level = if age_seconds.is_none_or(|age| age > STALE_SECONDS.1) { "critical" } else { "warn" };
            let age = age_seconds.unwrap_or(0.0);
            add(&mut found, "stale", level, now - age, format!("no host sample for {} s", trunc(age)));
        }
        let (cpu, recent, rx, tx) = {
            let ring = lock(&self.ring);
            let recent: Vec<_> =
                ["host.mem", "host.disk", "host.swap"].iter().map(|s| ring.points_of(s, now - 3600.0, now)).collect();
            (
                ring.points_of("host.cpu", now - 300.0, now),
                recent,
                ring.points_of("net.rx_bps", now - 30.0, now),
                ring.points_of("net.tx_bps", now - 30.0, now),
            )
        };
        if !cpu.is_empty() && cpu[0].0 <= now - 300.0 + 2.0 * self.interval {
            let mean = cpu.iter().fold(0.0, |s, p| s + p.1) / cpu.len() as f64;
            if mean > CPU_AVG.0 {
                let since = Self::tail_since(&cpu, CPU_AVG.0).unwrap_or(cpu[0].0);
                let level = if mean > CPU_AVG.1 { "critical" } else { "warn" };
                add(&mut found, "cpu", level, since, format!("cpu {}% average over 5 min", pyfloat::fixed(mean, 1)));
            }
        }
        for ((kind, (warn, crit)), points) in [("mem", MEM), ("disk", DISK), ("swap", SWAP)].into_iter().zip(&recent) {
            if let Some(&(last_ts, last)) = points.last() {
                if last > warn {
                    let since = Self::tail_since(points, warn).unwrap_or(last_ts);
                    let level = if last > crit { "critical" } else { "warn" };
                    add(&mut found, kind, level, since, format!("{kind} {}%", pyfloat::fixed(last, 1)));
                }
            }
        }
        if !rx.is_empty() && !tx.is_empty() {
            let mean = |points: &[(f64, f64)]| points.iter().fold(0.0, |s, p| s + p.1) / points.len() as f64;
            let current = mean(&rx) + mean(&tx);
            if current > SPIKE_FLOOR_BPS {
                let baseline = self.baseline(trunc(now)).await?;
                if let Some(baseline) = baseline.filter(|b| *b != 0.0) {
                    if current > SPIKE_FACTOR.0 * baseline {
                        let level = if current > SPIKE_FACTOR.1 * baseline { "critical" } else { "warn" };
                        let detail = format!(
                            "network {} B/s against p95 {} B/s of the last 24 h",
                            pyfloat::fixed(current, 0),
                            pyfloat::fixed(baseline, 0)
                        );
                        add(&mut found, "net_spike", level, now - 30.0, detail);
                    }
                }
            }
        }
        Ok(found)
    }

    /// p95 of the last 24 h of rx+tx from the 60 s rollups; `None` until there is a day-ish of
    /// shape. Read once a minute, not every tick.
    async fn baseline(&self, now: i64) -> Result<Option<f64>, StoreError> {
        let minute = now.div_euclid(60);
        if let Some((memo_minute, value)) = lock(&self.state).baseline_memo {
            if memo_minute == minute {
                return Ok(value);
            }
        }
        self.day_reads.fetch_add(1, Ordering::Relaxed);
        let series = vec!["net.rx_bps".to_string(), "net.tx_bps".to_string()];
        let rows = self.read(series, 60, (now - 86400).div_euclid(60) * 60, now).await?;
        let mut by_bucket: IndexMap<i64, f64> = IndexMap::new();
        for (_name, at, total, count, _peak, _last) in rows {
            *by_bucket.entry(at).or_insert(0.0) += total / count as f64;
        }
        let values: Vec<f64> = by_bucket.values().copied().collect();
        let value = if by_bucket.len() >= 60 { percentile(&values, 0.95) } else { None };
        lock(&self.state).baseline_memo = Some((minute, value));
        Ok(value)
    }
}

/// `(series, bucket, sum, count, max, last)`.
type Row = (String, i64, f64, i64, f64, f64);

fn opt_int(value: Option<i64>) -> Value {
    pyfloat::opt_int(value)
}

/// Python's `max(items, key=…)`: the first item with the largest key.
fn first_max(items: impl Iterator<Item = (i64, f64)>) -> Option<(i64, f64)> {
    let mut best: Option<(i64, f64)> = None;
    for item in items {
        if best.is_none_or(|b| item.1 > b.1) {
            best = Some(item);
        }
    }
    best
}

fn first_max_value(slots: &IndexMap<i64, Slot>) -> Option<f64> {
    first_max(slots.iter().map(|(at, s)| (*at, s.max))).map(|best| best.1)
}

fn add_points(target: &mut IndexMap<i64, Slot>, points: &[(f64, f64)], step: i64) {
    for (ts, value) in points {
        target.entry(bucket(*ts, step)).or_insert(Slot::EMPTY).add(*value, 1, *value, *value);
    }
}

fn write_rows(database: &Database, node_id: &str, rows: &IndexMap<RollupKey, Slot>) -> Result<(), StoreError> {
    database.transaction(|db| {
        let mut statement = db.prepare(UPSERT)?;
        for ((resolution, at, series), slot) in rows {
            statement.execute((resolution, at, node_id, series, slot.sum, slot.count, slot.max, slot.last))?;
        }
        Ok(())
    })
}

fn read_rows(
    database: &Database,
    node_id: &str,
    series: &[String],
    resolution: i64,
    start: i64,
    end: i64,
) -> Result<Vec<Row>, StoreError> {
    let marks = vec!["?"; series.len()].join(",");
    let sql = format!(
        "SELECT series,bucket,sum,count,max,last FROM metric_rollups WHERE node_id=? AND resolution=? \
         AND bucket>=? AND bucket<=? AND series IN ({marks})"
    );
    let mut params: Vec<SqlValue> = vec![node_id.to_string().into(), resolution.into(), start.into(), end.into()];
    params.extend(series.iter().map(|name| SqlValue::from(name.clone())));
    database.with_connection(|db| {
        let mut statement = db.prepare(&sql)?;
        let rows = statement
            .query_map(params_from_iter(params), |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
            })?
            .collect::<Result<Vec<Row>, _>>()?;
        Ok(rows)
    })
}

/// Every range name, for error messages: `15m, 1h, …`.
pub fn range_names() -> String {
    RANGES.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(", ")
}
