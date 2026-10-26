//! `fleet_v2/node_routes.py` and `metrics_node.py` (row 3): what a panel exposes to the central
//! panel that manages it, behind a `node-sync` or `admin` API key (`context.fleet_key`), plus the
//! owner's `POST /api/nodes/local/unlink`. The logic is `panel_fleet::node::FleetNode`; this module
//! is FastAPI's part: body, gate, validation, audit, the answer.
//!
//! Routes, in Python's registration order (Starlette first match: a `POST` to
//! `/api/fleet/v2/geodata/codes` or `…/settings` falls through to `…/geodata/{action}` and is a 422
//! there).

use axum::extract::State;
use axum::response::Response;
use http::header::{HeaderValue, CACHE_CONTROL};
use panel_core::errors::LocItem;
use panel_fleet::node::models::{CaptureRequest, ExitTestRequest, GeodataSettings, VersionUpdateRequest};
use panel_fleet::node::runtime::GeodataAction;
use panel_fleet::node::service::{summary_range, HistoryQuery};
use panel_fleet::node::{FleetNode, NodeFailure};
use panel_metrics::Metrics;
use panel_model::fleet::PushRequest;
use panel_model::validate::{literal, Cx, Entry};
use serde_json::{json, Map, Value};
use std::sync::Arc;

use crate::http::request::{Call, Issues};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::state::AppState;

pub fn routes() -> Routes {
    Routes::new()
        .get("/api/fleet/v2/identity", identity)
        .get("/api/fleet/v2/status", status)
        .get("/api/fleet/v2/metrics", metrics_live)
        .get("/api/fleet/v2/metrics/history", metrics_history)
        .get("/api/fleet/v2/metrics/summary", metrics_summary)
        .get("/api/fleet/v2/inventory", inventory)
        .put("/api/fleet/v2/generation", push)
        .get("/api/fleet/v2/observed", observed)
        .post("/api/fleet/v2/credentials/capture", capture)
        .post("/api/fleet/v2/exits/test", exit_test)
        .get("/api/fleet/v2/geodata", geodata_view)
        .get("/api/fleet/v2/geodata/codes", geodata_codes)
        .put("/api/fleet/v2/geodata/settings", geodata_settings)
        .post("/api/fleet/v2/geodata/{action}", geodata_action)
        .post("/api/fleet/v2/versions/update", update_version)
        .post("/api/fleet/v2/versions/check", check_versions)
        .post("/api/fleet/v2/unlink", unlink)
        .post("/api/nodes/local/unlink", unlink_by_owner)
}

fn failure(error: NodeFailure) -> Failure {
    match error {
        NodeFailure::Api(error) => Failure::from(*error),
        NodeFailure::Internal(message) => Failure::internal(message),
    }
}

fn node(app: &AppState) -> FleetNode {
    app.service::<FleetNode>().clone()
}

fn metrics(app: &AppState) -> Option<Arc<Metrics>> {
    app.try_service::<Arc<Metrics>>().cloned()
}

/// `JSONResponse(…, headers={"Cache-Control": "no-store"})`.
fn no_store(status: u16, body: &Value) -> Response {
    let mut answer = response::json(status, body);
    answer.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    answer
}

async fn identity(State(app): State<AppState>, call: Call) -> Handled {
    app.fleet_key(&call).await?;
    Ok(response::json(200, &node(&app).identity().await.map_err(failure)?))
}

async fn status(State(app): State<AppState>, call: Call) -> Handled {
    app.fleet_key(&call).await?;
    Ok(response::json(200, &node(&app).status().await.map_err(failure)?))
}

async fn metrics_live(State(app): State<AppState>, call: Call) -> Handled {
    app.fleet_key(&call).await?;
    let body = node(&app).metrics_live(metrics(&app).as_deref()).await.map_err(failure)?;
    Ok(no_store(200, &body))
}

async fn metrics_history(State(app): State<AppState>, call: Call) -> Handled {
    app.fleet_key(&call).await?;
    let query = HistoryQuery::parse(&call.meta.query).map_err(Failure::validation)?;
    let body = node(&app).metrics_history(metrics(&app).as_deref(), &query).await.map_err(failure)?;
    Ok(no_store(200, &body))
}

async fn metrics_summary(State(app): State<AppState>, call: Call) -> Handled {
    app.fleet_key(&call).await?;
    let range = summary_range(&call.meta.query);
    let body = node(&app).metrics_summary(metrics(&app).as_deref(), &range).await.map_err(failure)?;
    Ok(no_store(200, &body))
}

async fn inventory(State(app): State<AppState>, call: Call) -> Handled {
    app.fleet_key(&call).await?;
    Ok(response::json(200, &node(&app).inventory().await.map_err(failure)?))
}

async fn push(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.fleet_key(&call).await?;
    let mut issues = Issues::new();
    let body = issues.body::<PushRequest>(&input);
    issues.finish()?;
    let node = node(&app);
    let accepted = node.accept(body.expect("validated")).await.map_err(failure)?;
    let target = accepted.generation.to_string();
    app.audit(&user, "fleet.generation.accept", &target, &call, Some(accepted.audit_detail())).await?;
    // Adapter I/O never runs inside a transaction, and never gets cancelled by the deadline.
    let background = app.background.clone();
    let (status, body) =
        node.apply_pushed(accepted.generation, |work| background.spawn(work)).await.map_err(failure)?;
    Ok(no_store(status, &body))
}

async fn observed(State(app): State<AppState>, call: Call) -> Handled {
    app.fleet_key(&call).await?;
    Ok(response::json(200, &node(&app).observed().await.map_err(failure)?))
}

async fn capture(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.fleet_key(&call).await?;
    let mut issues = Issues::new();
    let body = issues.body::<CaptureRequest>(&input);
    issues.finish()?;
    let node = node(&app);
    let answer = node.capture(&body.expect("validated")).await.map_err(failure)?;
    // Usernames are what the inventory already shows; no value ever lands in the audit row.
    app.audit(&user, "fleet.credentials.capture", node.guid(), &call, Some(answer.audit)).await?;
    Ok(no_store(200, &answer.body))
}

async fn exit_test(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.fleet_key(&call).await?;
    let mut issues = Issues::new();
    let body = issues.body::<ExitTestRequest>(&input);
    issues.finish()?;
    let node = node(&app);
    let answer = node.exit_test(&body.expect("validated").exit).await.map_err(failure)?;
    app.audit(&user, "fleet.exit.test", node.guid(), &call, Some(answer.audit)).await?;
    Ok(no_store(200, &answer.body))
}

async fn geodata_view(State(app): State<AppState>, call: Call) -> Handled {
    app.fleet_key(&call).await?;
    Ok(response::json(200, &node(&app).geodata(GeodataAction::View, None).await.map_err(failure)?))
}

async fn geodata_codes(State(app): State<AppState>, call: Call) -> Handled {
    app.fleet_key(&call).await?;
    Ok(response::json(200, &node(&app).geodata(GeodataAction::Codes, None).await.map_err(failure)?))
}

async fn geodata_settings(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.fleet_key(&call).await?;
    let mut issues = Issues::new();
    let body = issues.body::<GeodataSettings>(&input);
    issues.finish()?;
    let forwarded = body.expect("validated").forwarded();
    let node = node(&app);
    let result = node.geodata(GeodataAction::Settings, Some(forwarded.clone())).await.map_err(failure)?;
    app.audit(&user, "fleet.geodata.settings", node.guid(), &call, Some(forwarded)).await?;
    Ok(response::json(200, &result))
}

async fn geodata_action(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.fleet_key(&call).await?;
    let action = call.param("action").to_string();
    let mut cx = Cx::new(Entry::Body);
    let loc: Vec<LocItem> = vec!["path".into(), "action".into()];
    let parsed = literal(&json!(action), &loc, &mut cx, &["update", "restore"]);
    let mut issues = Issues::new();
    for issue in cx.into_issues() {
        issues.push(issue);
    }
    issues.finish()?;
    let action = if parsed == Some("update") { GeodataAction::Update } else { GeodataAction::Restore };
    let node = node(&app);
    let result = node.geodata(action, None).await.map_err(failure)?;
    let field = |key: &str| result.get(key).cloned().unwrap_or(Value::Null);
    let mut detail = Map::new();
    detail.insert("origin".into(), field("origin"));
    detail.insert("version".into(), field("version"));
    detail.insert("changed".into(), field("changed"));
    let name = format!("fleet.geodata.{}", parsed.unwrap_or("restore"));
    app.audit(&user, &name, node.guid(), &call, Some(detail)).await?;
    Ok(response::json(200, &result))
}

async fn update_version(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.fleet_key(&call).await?;
    let mut issues = Issues::new();
    let body = issues.body::<VersionUpdateRequest>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let result = node(&app)
        .update_version(&body.component, &body.version, body.expected_current.as_deref())
        .await
        .map_err(failure)?;
    let mut detail = Map::new();
    detail.insert("version".into(), json!(body.version));
    app.audit(&user, "runtime.version.update", &body.component, &call, Some(detail)).await?;
    Ok(response::json(200, &result))
}

async fn check_versions(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.fleet_key(&call).await?;
    let result = node(&app).check_versions().await.map_err(failure)?;
    let mut detail = Map::new();
    detail.insert("checked_at".into(), result.get("checked_at").cloned().unwrap_or(Value::Null));
    app.audit(&user, "runtime.version.check", "upstream", &call, Some(detail)).await?;
    Ok(response::json(200, &result))
}

async fn unlink_as(app: &AppState, user: &crate::auth::Principal, call: &Call) -> Handled {
    let node = node(app);
    let released = node.unlink().await.map_err(failure)?;
    let mut detail = Map::new();
    detail.insert("released".into(), json!(released));
    app.audit(user, "fleet.unlink", node.guid(), call, Some(detail)).await?;
    Ok(response::json(200, &json!({"released": released})))
}

async fn unlink(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.fleet_key(&call).await?;
    unlink_as(&app, &user, &call).await
}

/// The node's owner cuts the link from the UI; the runtime is left alone (spec §5.2).
async fn unlink_by_owner(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, &["owner"]).await?;
    unlink_as(&app, &user, &call).await
}
