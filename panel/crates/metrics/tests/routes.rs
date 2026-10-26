//! `/api/metrics/*` against the Python app: the recorded requests (`fixtures/routes.json`) are
//! replayed through `routes::router()` with the same collector inputs and must give the same
//! status, headers and body bytes. The named tests then check the assertions of
//! `test_metrics_api.py` on those answers.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{request::Parts, HeaderMap, StatusCode};
use axum::response::Response;
use common::{fixture, Rig};
use futures_util::StreamExt;
use panel_core::pyjson;
use panel_metrics::routes::{self, Caller, MetricsHttp, MetricsState};
use panel_metrics::{FleetMeters, Metrics};
use panel_model::metrics::{MetricsNode, NodeMetricsSource};
use panel_model::protocols::BoxFuture;
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "session-hash";

#[derive(Clone)]
struct TestState {
    metrics: Arc<Metrics>,
    linked: Arc<Mutex<Vec<MetricsNode>>>,
    valid: Arc<Mutex<bool>>,
}

impl TestState {
    fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics, linked: Arc::default(), valid: Arc::new(Mutex::new(true)) }
    }
}

impl MetricsState for TestState {
    fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    fn still_valid<'a>(&'a self, _caller: &'a Caller, _headers: &'a HeaderMap) -> BoxFuture<'a, bool> {
        Box::pin(async move { *self.valid.lock().unwrap() })
    }

    fn linked_nodes(&self) -> BoxFuture<'_, Result<Vec<MetricsNode>, Response>> {
        Box::pin(async move { Ok(self.linked.lock().unwrap().clone()) })
    }
}

impl MetricsHttp for TestState {
    fn current<'a>(&'a self, parts: &'a Parts) -> BoxFuture<'a, Result<Caller, Response>> {
        Box::pin(async move {
            if parts.headers.get("cookie").is_none() {
                return Err(routes::error_response(&panel_core::errors::ApiError::detail(401, "Not authenticated")));
            }
            Ok(Caller { token_hash: TOKEN.into(), via_api_key: false })
        })
    }
}

/// The node metrics source of `test_a_node_metrics_source_serves_the_linked_nodes` (and the
/// recorder's `Source`).
struct RecordedSource;

impl NodeMetricsSource for RecordedSource {
    fn live<'a>(&'a self, node_id: &'a str) -> BoxFuture<'a, Option<Value>> {
        Box::pin(async move {
            (node_id == "amsterdam").then(|| {
                json!({"node_id": node_id, "name": "Amsterdam", "status": "ok", "age_seconds": 1.0,
                       "host": {"cpu_percent": 3.0}, "protocols": {}, "top_clients": [], "kernel_counters": "ok"})
            })
        })
    }

    fn history<'a>(
        &'a self,
        node_id: &'a str,
        series: &'a [String],
        range: &'a str,
        _points: i64,
    ) -> BoxFuture<'a, Option<Value>> {
        Box::pin(async move {
            let series: serde_json::Map<String, Value> = series.iter().map(|s| (s.clone(), json!([]))).collect();
            Some(json!({"node_id": node_id, "range": range, "series": series}))
        })
    }

    fn summary<'a>(&'a self, node_id: &'a str, range: &'a str) -> BoxFuture<'a, Option<Value>> {
        Box::pin(async move {
            (node_id != "berlin").then(|| {
                json!({"range": range, "host": {"cpu": {"avg": 5.0}, "mem": {"avg": 7.5}},
                       "protocols": {"naive": {"total_bytes": 4000, "peak_bps": 0.0}, "mieru": {"total_bytes": 1.5, "peak_bps": null}},
                       "hours_of_day": {}, "alerts": [{}, {}], "name": "ignored", "extra": "x"})
            })
        })
    }

    fn nodes(&self) -> BoxFuture<'_, Vec<MetricsNode>> {
        Box::pin(async { vec![MetricsNode { node_id: "amsterdam".into(), name: "Amsterdam".into() }] })
    }
}

impl FleetMeters for RecordedSource {}

async fn get(state: &TestState, path: &str) -> (StatusCode, HeaderMap, String) {
    let request = Request::builder().uri(path).header("cookie", "panel_session=x").body(Body::empty()).unwrap();
    let response = routes::router::<TestState>().with_state(state.clone()).oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    (parts.status, parts.headers, String::from_utf8(bytes.to_vec()).unwrap())
}

/// One recorded answer, replayed.
struct Answer {
    path: String,
    status: u16,
    body: Value,
}

async fn replay(name: &str) -> Vec<Answer> {
    let all: Value = serde_json::from_str(&fixture("routes.json")).unwrap();
    let recorded = all.as_array().unwrap().iter().find(|s| s["name"] == name).expect("recorded rig");
    let rig = Rig::new(&recorded["flags"], recorded["start"].as_f64().unwrap());
    *rig.sources.local_name.lock().unwrap() = recorded["local_name"].as_str().map(String::from);
    let state = TestState::new(rig.metrics.clone());
    if name == "source" {
        rig.metrics.set_source(Some(Arc::new(RecordedSource)));
    }
    let mut answers = Vec::new();
    for (index, op) in recorded["ops"].as_array().unwrap().iter().enumerate() {
        let context = format!("{name} op {index}");
        match op["op"].as_str().unwrap() {
            "sql" => rig.sql(op["sql"].as_str().unwrap()),
            "step" => {
                rig.sources.load(&op["calls"]);
                rig.step(op["advance"].as_f64().unwrap()).await;
                rig.sources.assert_consumed(&context);
                let latest = rig.latest().await;
                assert_eq!(pyjson::compact_utf8(&latest), op["latest"].as_str().unwrap(), "{context}: latest");
            }
            "get" => {
                let path = op["path"].as_str().unwrap();
                *state.linked.lock().unwrap() = op["linked"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| MetricsNode {
                        node_id: n["node_id"].as_str().unwrap().into(),
                        name: n["name"].as_str().unwrap().into(),
                    })
                    .collect();
                let held: Vec<_> = if op["status"] == 429 {
                    (0..4).map(|_| rig.metrics.streams().acquire(TOKEN).unwrap()).collect()
                } else {
                    Vec::new()
                };
                let (status, headers, body) = get(&state, path).await;
                drop(held);
                let context = format!("{context} GET {path}");
                assert_eq!(status.as_u16() as u64, op["status"].as_u64().unwrap(), "{context}: status; body {body}");
                for (name, want) in op["headers"].as_object().unwrap() {
                    assert_eq!(
                        headers.get(name).and_then(|v| v.to_str().ok()),
                        want.as_str(),
                        "{context}: header {name}"
                    );
                }
                for name in ["cache-control", "retry-after"] {
                    if op["headers"].get(name).is_none() {
                        assert!(headers.get(name).is_none(), "{context}: unexpected header {name}");
                    }
                }
                assert_eq!(body, op["body"].as_str().unwrap(), "{context}: body");
                answers.push(Answer {
                    path: path.into(),
                    status: status.as_u16(),
                    body: serde_json::from_str(&body).unwrap(),
                });
            }
            other => panic!("{context}: unknown op {other}"),
        }
    }
    answers
}

fn answer<'a>(answers: &'a [Answer], path: &str, nth: usize) -> &'a Answer {
    answers.iter().filter(|a| a.path == path).nth(nth).unwrap_or_else(|| panic!("no answer #{nth} for {path}"))
}

#[tokio::test]
async fn every_recorded_answer_of_the_main_app_is_identical() {
    replay("main").await;
}

#[tokio::test]
async fn every_metrics_route_needs_a_session() {
    let rig = Rig::with(json!({}));
    let state = TestState::new(rig.metrics.clone());
    for path in [
        "/api/metrics/clients?protocol=mieru",
        "/api/metrics/live",
        "/api/metrics/stream",
        "/api/metrics/history",
        "/api/metrics/summary?range=2d",
    ] {
        let request = Request::builder().uri(path).body(Body::empty()).unwrap();
        let response = routes::router::<TestState>().with_state(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn live_snapshot_shape_and_no_store() {
    let answers = replay("main").await;
    let body = &answer(&answers, "/api/metrics/live", 1).body;
    let node = &body["nodes"][0];
    let keys: Vec<&str> = node.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["node_id", "name", "status", "age_seconds", "host", "protocols", "top_clients", "kernel_counters", "alerts"]
    );
    assert_eq!((&node["status"], &node["host"]["mem"]["percent"]), (&json!("ok"), &json!(40.0)));
    let tt = &node["protocols"]["trusttunnel"];
    assert_eq!((&tt["source"], &tt["up_bps"], &tt["down_bps"]), (&json!("kernel"), &json!(1000.0), &json!(3000.0)));
    assert_eq!(node["protocols"]["amneziawg"]["source"], json!("interface"));
    assert_eq!(node["protocols"]["naive"]["available"], json!(false));
}

#[tokio::test]
async fn client_rates_of_one_protocol_for_the_protocol_pages() {
    let answers = replay("main").await;
    let body = &answer(&answers, "/api/metrics/clients?protocol=trusttunnel", 1).body;
    assert_eq!((&body["protocol"], &body["live"]), (&json!("trusttunnel"), &json!(true)));
    assert_eq!(body["clients"]["alice"]["total_bps"].as_f64().unwrap().round(), 889.0);
    let naive = &answer(&answers, "/api/metrics/clients?protocol=naive", 0).body;
    assert_eq!((&naive["live"], &naive["clients"]), (&json!(false), &json!({})));
    assert_eq!(answer(&answers, "/api/metrics/clients?protocol=nope", 0).status, 422);
    assert_eq!(answer(&answers, "/api/metrics/clients", 0).status, 422);
}

#[tokio::test]
async fn history_and_summary_answer_for_the_local_node() {
    let answers = replay("main").await;
    let history =
        &answer(&answers, "/api/metrics/history?series=host.cpu,trusttunnel.down_bps&range=15m&points=450", 0).body;
    assert_eq!(
        (&history["status"], &history["node_id"], &history["range"]),
        (&json!("ok"), &json!("local"), &json!("15m"))
    );
    assert_eq!(history["series"]["host.cpu"].as_array().unwrap().last().unwrap()[1], json!(12.5));
    let summary = &answer(&answers, "/api/metrics/summary?range=1h", 1).body;
    assert_eq!(summary["nodes"][0]["host"]["cpu"]["avg"], json!(12.5));
    assert!(summary.get("compare").is_none());
}

#[tokio::test]
async fn unknown_node_range_or_series_is_422() {
    let answers = replay("main").await;
    for path in [
        "/api/metrics/live?node=ghost",
        "/api/metrics/live?node=bad%20id",
        "/api/metrics/summary?range=2d",
        "/api/metrics/history?series=host.cpu&range=2d",
        "/api/metrics/history?series=host.nope",
        "/api/metrics/history?series=",
        "/api/metrics/history",
        "/api/metrics/history?series=host.cpu&points=5",
        "/api/metrics/history?series=host.cpu&points=99999",
        "/api/metrics/history?series=host.cpu&node=all",
        "/api/metrics/summary?node=ghost",
        "/api/metrics/stream?node=ghost",
    ] {
        assert_eq!(answer(&answers, path, 0).status, 422, "{path}");
    }
}

#[tokio::test]
async fn linked_nodes_are_unsupported_until_a_source_is_plugged_in() {
    let answers = replay("main").await;
    let live = &answer(&answers, "/api/metrics/live?node=amsterdam", 0).body;
    assert_eq!(
        live["nodes"],
        json!([{"node_id": "amsterdam", "name": "Amsterdam", "status": "unsupported", "age_seconds": null, "host": null,
                "protocols": {}, "top_clients": [], "kernel_counters": null, "alerts": []}])
    );
    let both = &answer(&answers, "/api/metrics/live?node=all", 1).body["nodes"];
    assert_eq!((&both[0]["node_id"], &both[1]["status"]), (&json!("local"), &json!("unsupported")));
    let history = &answer(&answers, "/api/metrics/history?node=amsterdam&series=host.cpu", 0).body;
    assert_eq!(history, &json!({"node_id": "amsterdam", "range": "1h", "status": "unsupported", "series": {}}));
    let summary = &answer(&answers, "/api/metrics/summary?node=all&range=1h", 1).body;
    let ids: Vec<&str> =
        summary["compare"].as_array().unwrap().iter().map(|r| r["node_id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["local", "amsterdam"]);
}

#[tokio::test]
async fn a_node_metrics_source_serves_the_linked_nodes() {
    let answers = replay("source").await;
    let nodes = &answer(&answers, "/api/metrics/live?node=all", 0).body["nodes"];
    let got: Vec<(&str, &str)> = nodes
        .as_array()
        .unwrap()
        .iter()
        .map(|n| (n["node_id"].as_str().unwrap(), n["status"].as_str().unwrap()))
        .collect();
    assert_eq!(got, [("local", "ok"), ("amsterdam", "ok"), ("berlin", "unavailable")]);
    let history = &answer(&answers, "/api/metrics/history?node=amsterdam&series=host.cpu&range=6h", 0).body;
    assert_eq!((&history["range"], &history["series"]), (&json!("6h"), &json!({"host.cpu": []})));
}

#[tokio::test]
async fn disabled_monitoring_answers_404() {
    let answers = replay("off").await;
    for path in [
        "/api/metrics/clients?protocol=mieru",
        "/api/metrics/live",
        "/api/metrics/stream",
        "/api/metrics/history?series=host.cpu",
        "/api/metrics/summary",
    ] {
        let found = answer(&answers, path, 0);
        assert_eq!((found.status, &found.body), (404, &json!({"detail": "metrics_disabled"})), "{path}");
    }
}

#[tokio::test]
async fn stale_agent_is_reported_not_hidden() {
    let answers = replay("main").await;
    let node = &answer(&answers, "/api/metrics/live", 2).body["nodes"][0];
    assert_eq!((&node["status"], &node["age_seconds"]), (&json!("stale"), &json!(10.0)));
}

#[tokio::test]
async fn stream_route_answers_429_beyond_the_session_limit() {
    let answers = replay("main").await;
    let found = answer(&answers, "/api/metrics/stream", 0);
    assert_eq!((found.status, &found.body), (429, &json!({"detail": "too many metric streams"})));
}

#[tokio::test]
async fn stream_route_sends_event_stream_headers_and_frees_its_slot_on_disconnect() {
    let rig = Rig::with(json!({}));
    rig.sources
        .set("agent", Ok(json!({"ts": 1.0, "host": {"cpu_percent": 1.0}, "protocols": {}, "kernel_counters": "ok"})));
    rig.sources.set("mtproxy", Err("down".into()));
    rig.step(2.0).await;
    let state = TestState::new(rig.metrics.clone());
    let request =
        Request::builder().uri("/api/metrics/stream").header("cookie", "panel_session=x").body(Body::empty()).unwrap();
    let response = routes::router::<TestState>().with_state(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(headers["content-type"], "text/event-stream; charset=utf-8");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["x-accel-buffering"], "no");
    assert_eq!(headers["connection"], "keep-alive");
    assert_eq!(rig.metrics.streams().open_streams(), 1);
    let mut body = response.into_body().into_data_stream();
    assert_eq!(body.next().await.unwrap().unwrap(), "retry: 3000\n\n");
    let snapshot = body.next().await.unwrap().unwrap();
    assert!(snapshot.starts_with(b"event: snapshot\ndata: {\"ts\":"));
    drop(body); // the client leaves
    assert_eq!(rig.metrics.streams().open_streams(), 0);
}

#[tokio::test]
async fn the_all_stream_carries_the_remote_nodes_each_tick() {
    let rig = Rig::with(json!({}));
    rig.sources
        .set("agent", Ok(json!({"ts": 1.0, "host": {"cpu_percent": 1.0}, "protocols": {}, "kernel_counters": "ok"})));
    rig.sources.set("mtproxy", Err("down".into()));
    rig.step(2.0).await;
    rig.metrics.set_source(Some(Arc::new(RecordedSource)));
    let state = TestState::new(rig.metrics.clone());
    *state.linked.lock().unwrap() = vec![MetricsNode { node_id: "amsterdam".into(), name: "Amsterdam".into() }];
    let request =
        Request::builder().uri("/api/metrics/stream?node=all").header("cookie", "c").body(Body::empty()).unwrap();
    let response = routes::router::<TestState>().with_state(state).oneshot(request).await.unwrap();
    let mut body = response.into_body().into_data_stream();
    body.next().await;
    let frame = body.next().await.unwrap().unwrap();
    let text = std::str::from_utf8(&frame).unwrap();
    let data: Value = serde_json::from_str(text.strip_prefix("event: snapshot\ndata: ").unwrap().trim_end()).unwrap();
    let nodes: Vec<(&str, &str)> = data["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| (n["node_id"].as_str().unwrap(), n["status"].as_str().unwrap()))
        .collect();
    assert_eq!(nodes, [("local", "ok"), ("amsterdam", "ok")]);
    let _ = tokio::time::timeout(Duration::from_millis(10), body.next()).await;
}
