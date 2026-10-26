//! `/api/metrics/*` (`metrics/routes.py`): live snapshot, per-client rates, SSE stream, history
//! and summary. Reads only; any signed-in role. Nodes other than `local` are served by the
//! optional fleet source.
//!
//! Order of checks, as FastAPI runs them: the caller (`Depends(context.current)`) → the query
//! parameters (pydantic, 422 list) → the handler (`metrics_disabled` 404, then its own 422s).
//! HEAD on these GET routes and wrong methods are the shell's fallback layer (WP4).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, request::Parts, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::future::join_all;
use panel_core::errors::{ApiError, ValidationIssue};
use panel_core::pyjson;
use panel_model::metrics::{
    is_series, range_seconds, MetricsNode, LOCAL_NODE, POINTS_DEFAULT, POINTS_MAX, POINTS_MIN, PROTOCOLS,
};
use panel_model::protocols::BoxFuture;
use serde_json::{json, Map, Value};

use crate::pyfloat::{float, round_to};
use crate::query::{self, Query};
use crate::sse::{EventStream, Timing};
use crate::store::range_names;
use crate::{placeholder, Metrics, StoreError};

pub const MAX_SERIES: usize = 40;
/// Remote nodes are pulled on demand; the budget bounds how long one answer waits for them.
pub const LIVE_BUDGET: f64 = 4.0;
/// A stream tick must not wait for a slow node: late nodes go out as stale.
pub const STREAM_BUDGET: f64 = 0.75;

/// The signed-in caller (`context.current`'s user): `token_hash` keys the stream limit (the
/// session's or the API key's hash, as Python's `user["token_hash"]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub token_hash: String,
    pub via_api_key: bool,
}

/// What the routes need from the application state (implemented by the shell's `AppState`).
pub trait MetricsState: Clone + Send + Sync + 'static {
    fn metrics(&self) -> &Arc<Metrics>;

    /// `Depends(context.current)`: the caller, or the response to send instead (401/403/429…).
    fn current<'a>(&'a self, parts: &'a Parts) -> BoxFuture<'a, Result<Caller, Response>>;

    /// A long stream's re-check: the session cookie (or the bearer key for API-key callers) of
    /// the original request is still valid.
    fn still_valid<'a>(&'a self, caller: &'a Caller, headers: &'a HeaderMap) -> BoxFuture<'a, bool>;

    /// Every node but this one that the panel knows and has not disabled, in `nodes.list()` order.
    fn linked_nodes(&self) -> BoxFuture<'_, Result<Vec<MetricsNode>, Response>>;

    /// An unexpected failure (a database error): Starlette's plain 500 unless the shell renders
    /// it otherwise.
    fn internal_error(&self, error: &dyn std::error::Error) -> Response {
        log::error!("metrics route failed: {error}");
        let mut response = Response::new(Body::from("Internal Server Error"));
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
        response
    }
}

pub fn router<S: MetricsState>() -> Router<S> {
    Router::new()
        .route("/api/metrics/live", get(live::<S>))
        .route("/api/metrics/clients", get(clients::<S>))
        .route("/api/metrics/stream", get(stream::<S>))
        .route("/api/metrics/history", get(history::<S>))
        .route("/api/metrics/summary", get(summary::<S>))
}

/// A JSON answer rendered like Starlette's `JSONResponse`, with `Cache-Control: no-store`.
pub fn json_response(status: u16, body: &Value) -> Response {
    let mut response = Response::new(Body::from(pyjson::compact_utf8(body)));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// An `HTTPException`/validation error. `Cache-Control: no-store` is what the panel's security
/// middleware puts on every answer (`web_context.py`); set here too so the router alone answers
/// like the Python app.
pub fn error_response(error: &ApiError) -> Response {
    let mut response = Response::new(Body::from(error.body_bytes()));
    *response.status_mut() = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Why a handler stopped early.
enum Stop {
    Api(Box<ApiError>),
    Response(Box<Response>),
    Store(StoreError),
}

impl From<ApiError> for Stop {
    fn from(error: ApiError) -> Self {
        Stop::Api(Box::new(error))
    }
}

impl From<StoreError> for Stop {
    fn from(error: StoreError) -> Self {
        Stop::Store(error)
    }
}

fn finish<S: MetricsState>(state: &S, result: Result<Response, Stop>) -> Response {
    match result {
        Ok(response) => response,
        Err(Stop::Response(response)) => *response,
        Err(Stop::Api(error)) => error_response(&error),
        Err(Stop::Store(error)) => state.internal_error(&error),
    }
}

/// The caller and the parsed query; validation issues become one 422.
async fn begin<S: MetricsState>(state: &S, request: Request) -> Result<(Parts, Caller, Query), Stop> {
    let (parts, _body) = request.into_parts();
    let caller = state.current(&parts).await.map_err(|response| Stop::Response(Box::new(response)))?;
    let query = Query::parse(parts.uri.query());
    Ok((parts, caller, query))
}

fn validated(issues: Vec<ValidationIssue>) -> Result<(), Stop> {
    if issues.is_empty() {
        Ok(())
    } else {
        Err(ApiError::Validation(issues).into())
    }
}

fn enabled(metrics: &Metrics) -> Result<(), Stop> {
    if metrics.enabled() {
        Ok(())
    } else {
        Err(ApiError::detail(404, "metrics_disabled").into())
    }
}

/// `check_range` (`HTTPException(422, "range must be one of …")`).
#[allow(clippy::result_large_err)] // panel-core's error body, as every route returns it
pub fn check_range(value: &str) -> Result<(), ApiError> {
    if range_seconds(value).is_some() {
        Ok(())
    } else {
        Err(ApiError::detail(422, format!("range must be one of {}", range_names())))
    }
}

/// `parse_series`: comma-separated, stripped, de-duplicated in order, 1..=40 known names.
#[allow(clippy::result_large_err)] // panel-core's error body, as every route returns it
pub fn parse_series(series: &str) -> Result<Vec<String>, ApiError> {
    let mut names: Vec<String> = Vec::new();
    for part in series.split(',') {
        let part = panel_core::pytext::strip(part);
        if !part.is_empty() && !names.iter().any(|name| name == part) {
            names.push(part.to_string());
        }
    }
    if names.is_empty() || names.len() > MAX_SERIES || names.iter().any(|name| !is_series(name)) {
        return Err(ApiError::detail(422, "unknown series"));
    }
    Ok(names)
}

/// `NODE_ID.fullmatch`: 1–64 of `[A-Za-z0-9_.:-]`.
pub fn valid_node_id(node: &str) -> bool {
    (1..=64).contains(&node.chars().count())
        && node.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

/// The node ids a request addresses: `all` is this panel and every linked node.
async fn check_node<S: MetricsState>(state: &S, node: &str) -> Result<(String, Vec<MetricsNode>), Stop> {
    if node == "all" {
        return Ok(("all".into(), state.linked_nodes().await.map_err(|response| Stop::Response(Box::new(response)))?));
    }
    if !valid_node_id(node) {
        return Err(ApiError::detail(422, "unknown node").into());
    }
    if node == LOCAL_NODE {
        return Ok((node.into(), Vec::new()));
    }
    let known: Vec<MetricsNode> = state
        .linked_nodes()
        .await
        .map_err(|response| Stop::Response(Box::new(response)))?
        .into_iter()
        .filter(|n| n.node_id == node)
        .collect();
    if known.is_empty() {
        return Err(ApiError::detail(422, "unknown node").into());
    }
    Ok((node.into(), known))
}

fn includes_local(node: &str) -> bool {
    node == LOCAL_NODE || node == "all"
}

/// The linked nodes' entries, in order. One node never costs the whole answer.
pub async fn remote_entries(metrics: &Metrics, others: &[MetricsNode], budget: f64) -> Vec<Value> {
    let Some(source) = metrics.source() else {
        return others.iter().map(|n| placeholder(&n.node_id, &n.name, "unsupported")).collect();
    };
    let results = source.live_many(others, Duration::from_secs_f64(budget)).await;
    others
        .iter()
        .zip(results)
        .map(|(item, entry)| match entry {
            Some(entry @ Value::Object(_)) => entry,
            _ => placeholder(&item.node_id, &item.name, "unavailable"),
        })
        .collect()
}

/// The live envelope for `node`, or `None` while this panel has no sample yet.
pub async fn live_payload(metrics: &Metrics, node: &str, others: &[MetricsNode], budget: f64) -> Option<Value> {
    let collector = metrics.collector()?;
    if includes_local(node) && collector.latest().await.is_none() {
        return None;
    }
    let mut entries = Vec::new();
    if includes_local(node) {
        entries.push(metrics.local_entry().await);
    }
    entries.extend(remote_entries(metrics, others, budget).await);
    Some(envelope(metrics, entries))
}

fn envelope(metrics: &Metrics, entries: Vec<Value>) -> Value {
    let interval = metrics.collector().map(|c| c.interval()).unwrap_or(0.0);
    json!({"ts": float(round_to(metrics.clock().time(), 3)), "interval": float(interval), "nodes": entries})
}

async fn live<S: MetricsState>(State(state): State<S>, request: Request) -> Response {
    let result: Result<Response, Stop> = async {
        let (_parts, _caller, query) = begin(&state, request).await?;
        let metrics = state.metrics();
        enabled(metrics)?;
        let (node, others) = check_node(&state, query.get("node").unwrap_or(LOCAL_NODE)).await?;
        let payload = match live_payload(metrics, &node, &others, LIVE_BUDGET).await {
            Some(payload) => payload,
            None => {
                // before the first tick: say so rather than invent a snapshot
                let mut entries = Vec::new();
                if includes_local(&node) {
                    entries.push(metrics.local_entry().await);
                }
                entries.extend(remote_entries(metrics, &others, LIVE_BUDGET).await);
                envelope(metrics, entries)
            }
        };
        Ok(json_response(200, &payload))
    }
    .await;
    finish(&state, result)
}

async fn clients<S: MetricsState>(State(state): State<S>, request: Request) -> Response {
    let result: Result<Response, Stop> = async {
        let (_parts, _caller, query) = begin(&state, request).await?;
        let mut issues = Vec::new();
        let protocol = query::required(&query, "protocol", &mut issues);
        validated(issues)?;
        let protocol = protocol.expect("validated");
        let metrics = state.metrics();
        enabled(metrics)?;
        if !PROTOCOLS.contains(&protocol.as_str()) {
            return Err(ApiError::detail(422, "unknown protocol").into());
        }
        let (rows, ts) = match metrics.collector() {
            Some(collector) => (collector.client_rates(&protocol).await, float(round_to(collector.clock().time(), 3))),
            None => (Map::new(), Value::Null),
        };
        let body = json!({"protocol": protocol, "live": protocol != "naive", "clients": rows, "ts": ts});
        Ok(json_response(200, &body))
    }
    .await;
    finish(&state, result)
}

async fn stream<S: MetricsState>(State(state): State<S>, request: Request) -> Response {
    let result: Result<Response, Stop> = async {
        let (parts, caller, query) = begin(&state, request).await?;
        let metrics = state.metrics().clone();
        enabled(&metrics)?;
        let (node, others) = check_node(&state, query.get("node").unwrap_or(LOCAL_NODE)).await?;
        let Some(lease) = metrics.streams().acquire(&caller.token_hash) else {
            let mut response = json_response(429, &json!({"detail": "too many metric streams"}));
            response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
            return Ok(response);
        };
        let collector = metrics.collector().expect("metrics are enabled").clone();
        let others = Arc::new(others);
        let build_metrics = metrics.clone();
        let build = Box::new(move || {
            let (metrics, node, others) = (build_metrics.clone(), node.clone(), others.clone());
            Box::pin(async move { live_payload(&metrics, &node, &others, STREAM_BUDGET).await })
                as BoxFuture<'static, _>
        });
        let headers = parts.headers.clone();
        let alive_state = state.clone();
        let alive = Box::new(move || {
            let (state, caller, headers) = (alive_state.clone(), caller.clone(), headers.clone());
            Box::pin(async move { state.still_valid(&caller, &headers).await }) as BoxFuture<'static, bool>
        });
        let events =
            EventStream::new(lease, build, alive, collector.subscribe(), collector.clock().clone(), Timing::default());
        let mut response = Response::new(Body::from_stream(events.into_stream()));
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream; charset=utf-8"));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        Ok(response)
    }
    .await;
    finish(&state, result)
}

async fn history<S: MetricsState>(State(state): State<S>, request: Request) -> Response {
    let result: Result<Response, Stop> = async {
        let (_parts, _caller, query) = begin(&state, request).await?;
        let mut issues = Vec::new();
        let series = query::required(&query, "series", &mut issues);
        let points = query::bounded_int(&query, "points", POINTS_DEFAULT, POINTS_MIN, POINTS_MAX, &mut issues);
        validated(issues)?;
        let (series, points) = (series.expect("validated"), points.expect("validated"));
        let node = query.get("node").unwrap_or(LOCAL_NODE);
        let range = query.get("range").unwrap_or("1h");
        let metrics = state.metrics();
        enabled(metrics)?;
        check_range(range)?;
        let names = parse_series(&series)?;
        if node == "all" {
            return Err(ApiError::detail(422, "history is served for one node at a time").into());
        }
        let (node, _others) = check_node(&state, node).await?;
        if node != LOCAL_NODE {
            let source = metrics.source();
            let body = match &source {
                Some(source) => source.history(&node, &names, range, points).await,
                None => None,
            };
            let body = body.unwrap_or_else(|| {
                let status = if source.is_some() { "unavailable" } else { "unsupported" };
                json!({"node_id": node, "range": range, "status": status, "series": {}})
            });
            return Ok(json_response(200, &body));
        }
        let mut body = Map::new();
        body.insert("status".into(), json!("ok"));
        if let Value::Object(history) = metrics.store().history(&names, range, points).await? {
            body.extend(history);
        }
        Ok(json_response(200, &Value::Object(body)))
    }
    .await;
    finish(&state, result)
}

fn summary_placeholder(item: &MetricsNode, status: &str) -> Map<String, Value> {
    let value = json!({"node_id": item.node_id, "name": item.name, "status": status, "host": null,
                       "protocols": {}, "hours_of_day": {}, "alerts": []});
    match value {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

/// The linked nodes' summary rows (8 s budget for all of them).
pub async fn remote_summaries(metrics: &Metrics, others: &[MetricsNode], range_name: &str) -> Vec<Value> {
    let Some(source) = metrics.source() else {
        return others.iter().map(|item| Value::Object(summary_placeholder(item, "unsupported"))).collect();
    };
    let calls = join_all(others.iter().map(|item| source.summary(&item.node_id, range_name)));
    let results = tokio::time::timeout(Duration::from_secs_f64(LIVE_BUDGET * 2.0), calls)
        .await
        .unwrap_or_else(|_| vec![None; others.len()]);
    others
        .iter()
        .zip(results)
        .map(|(item, row)| match row {
            Some(Value::Object(row)) => {
                let mut merged = summary_placeholder(item, "ok");
                merged.extend(row);
                merged.insert("node_id".into(), json!(item.node_id));
                merged.insert("name".into(), json!(item.name));
                Value::Object(merged)
            }
            _ => Value::Object(summary_placeholder(item, "unavailable")),
        })
        .collect()
}

/// A JSON number as Python sees it for `sum`/`max`: an int stays an int.
#[derive(Debug, Clone, Copy, PartialEq)]
enum PyNum {
    Int(i64),
    Float(f64),
}

impl PyNum {
    fn of(value: &Value) -> Option<PyNum> {
        let number = value.as_number()?;
        if number.is_f64() {
            number.as_f64().map(PyNum::Float)
        } else {
            number.as_i64().map(PyNum::Int).or_else(|| number.as_f64().map(PyNum::Float))
        }
    }

    fn as_f64(self) -> f64 {
        match self {
            PyNum::Int(v) => v as f64,
            PyNum::Float(v) => v,
        }
    }

    fn add(self, other: PyNum) -> PyNum {
        match (self, other) {
            (PyNum::Int(a), PyNum::Int(b)) => {
                a.checked_add(b).map(PyNum::Int).unwrap_or(PyNum::Float(a as f64 + b as f64))
            }
            (a, b) => PyNum::Float(a.as_f64() + b.as_f64()),
        }
    }

    fn to_json(self) -> Value {
        match self {
            PyNum::Int(v) => json!(v),
            PyNum::Float(v) => float(v),
        }
    }
}

/// `value or 0` for a JSON number (a falsy or non-numeric value counts as the int 0).
fn or_zero(value: Option<&Value>) -> PyNum {
    match value.and_then(PyNum::of) {
        Some(number) if number.as_f64() != 0.0 => number,
        _ => PyNum::Int(0),
    }
}

/// The `compare` table of `?node=all`: one row per node, sorted by traffic (largest first).
fn compare(nodes: &[Value]) -> Value {
    let mut rows: Vec<(f64, Value)> = Vec::new();
    for row in nodes {
        let protocols: Vec<&Value> = match row.get("protocols") {
            Some(Value::Object(map)) => map.values().collect(),
            _ => Vec::new(),
        };
        let has_protocols = !protocols.is_empty();
        let total = has_protocols
            .then(|| protocols.iter().fold(PyNum::Int(0), |sum, p| sum.add(or_zero(p.get("total_bytes")))));
        let peak = has_protocols.then(|| {
            protocols
                .iter()
                .map(|p| or_zero(p.get("peak_bps")))
                .reduce(|best, next| if next.as_f64() > best.as_f64() { next } else { best })
                .expect("non-empty")
        });
        let avg = |key: &str| {
            row.get("host")
                .and_then(Value::as_object)
                .and_then(|host| host.get(key))
                .and_then(Value::as_object)
                .and_then(|stats| stats.get("avg"))
                .cloned()
                .unwrap_or(Value::Null)
        };
        let alerts = match row.get("alerts") {
            Some(Value::Array(items)) => items.len(),
            Some(Value::Object(map)) => map.len(),
            _ => 0,
        };
        let total_value = total.map(PyNum::to_json).unwrap_or(Value::Null);
        let key = total.map(|t| t.as_f64()).filter(|t| *t != 0.0).unwrap_or(-1.0);
        rows.push((
            key,
            json!({"node_id": row.get("node_id"), "name": row.get("name"), "status": row.get("status"),
                   "total_bytes": total_value, "peak_bps": peak.map(PyNum::to_json).unwrap_or(Value::Null),
                   "cpu_avg": avg("cpu"), "mem_avg": avg("mem"), "alerts": alerts}),
        ));
    }
    rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    Value::Array(rows.into_iter().map(|(_, row)| row).collect())
}

async fn summary<S: MetricsState>(State(state): State<S>, request: Request) -> Response {
    let result: Result<Response, Stop> = async {
        let (_parts, _caller, query) = begin(&state, request).await?;
        let node = query.get("node").unwrap_or(LOCAL_NODE);
        let range = query.get("range").unwrap_or("24h");
        let metrics = state.metrics();
        enabled(metrics)?;
        check_range(range)?;
        let (node, others) = check_node(&state, node).await?;
        let mut nodes = Vec::new();
        if includes_local(&node) {
            nodes.push(metrics.local_summary(range).await?);
        }
        nodes.extend(remote_summaries(metrics, &others, range).await);
        let mut body = Map::new();
        body.insert("range".into(), json!(range));
        if node == "all" {
            let table = compare(&nodes);
            body.insert("nodes".into(), Value::Array(nodes));
            body.insert("compare".into(), table);
        } else {
            body.insert("nodes".into(), Value::Array(nodes));
        }
        Ok(json_response(200, &Value::Object(body)))
    }
    .await;
    finish(&state, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn series_are_stripped_deduplicated_and_capped() {
        assert_eq!(parse_series(" host.cpu ,,host.cpu,net.tx_bps").unwrap(), vec!["host.cpu", "net.tx_bps"]);
        assert!(parse_series("").is_err());
        assert!(parse_series("host.nope").is_err());
        let many: Vec<String> = panel_model::metrics::all_series().into_iter().take(41).collect();
        assert!(parse_series(&many.join(",")).is_err());
        assert_eq!(parse_series(&many[..40].join(",")).unwrap().len(), 40);
    }

    #[test]
    fn node_ids_follow_the_python_pattern() {
        assert!(valid_node_id("local") && valid_node_id("a.b:c-d_e9"));
        assert!(!valid_node_id("") && !valid_node_id("bad id") && !valid_node_id(&"a".repeat(65)));
        assert!(!valid_node_id("узел"));
    }

    #[test]
    fn compare_keeps_python_number_types_and_order() {
        let nodes = vec![
            json!({"node_id": "a", "name": "A", "status": "ok", "host": {"cpu": {"avg": 1.5}},
                   "protocols": {"naive": {"total_bytes": 10, "peak_bps": 0.0}}, "alerts": [{}]}),
            json!({"node_id": "b", "name": "B", "status": "ok", "host": null,
                   "protocols": {"naive": {"total_bytes": 4000, "peak_bps": 2.5}, "mieru": {"total_bytes": 1.5}}, "alerts": []}),
            json!({"node_id": "c", "name": "C", "status": "unavailable", "host": null, "protocols": {}, "alerts": []}),
        ];
        let table = compare(&nodes);
        assert_eq!(
            pyjson::compact(&table),
            concat!(
                r#"[{"node_id":"b","name":"B","status":"ok","total_bytes":4001.5,"peak_bps":2.5,"cpu_avg":null,"mem_avg":null,"alerts":0},"#,
                r#"{"node_id":"a","name":"A","status":"ok","total_bytes":10,"peak_bps":0,"cpu_avg":1.5,"mem_avg":null,"alerts":1},"#,
                r#"{"node_id":"c","name":"C","status":"unavailable","total_bytes":null,"peak_bps":null,"cpu_avg":null,"mem_avg":null,"alerts":0}]"#
            )
        );
    }
}
