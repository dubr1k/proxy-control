//! `panel/version_routes.py`: host component inventory, upstream checks, updates and the deferred
//! manager rebuild after a panel update. Only listing degrades to `enabled: false`; agent errors
//! from the three mutations keep their own status and detail through the app error handler.

use axum::extract::State;
use panel_model::validate::{literal, Cx, Entry};
use panel_pages::models::{VersionUpdate, VERSION_COMPONENTS};
use serde_json::{json, Map, Value};

use crate::http::request::{Call, Issues};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::state::AppState;

/// The routes in `register_version_routes` order.
pub fn routes() -> Routes {
    Routes::new()
        .get("/api/versions", list_versions)
        .post("/api/versions/check", check_versions)
        .post("/api/versions/{component}/update", update_version)
        .post("/api/versions/panel/rebuild-managers", rebuild_managers)
}

fn agent_failure(error: panel_managers::VersionAgentError) -> Failure {
    Failure::from(error.app_error())
}

async fn list_versions(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let result = app
        .managers
        .versions
        .list_versions()
        .await
        .unwrap_or_else(|_| json!({"enabled": false, "components": {}, "reason": "version_agent_unavailable"}));
    Ok(response::json(200, &result))
}

async fn check_versions(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, &["owner"]).await?;
    let result = app.managers.versions.check().await.map_err(agent_failure)?;
    if !result.is_object() {
        return Err(Failure::internal("AttributeError: result has no attribute 'get'"));
    }
    let mut detail = Map::new();
    detail.insert("checked_at".into(), result.get("checked_at").cloned().unwrap_or(Value::Null));
    app.audit(&user, "runtime.version.check", "upstream", &call, Some(detail)).await?;
    Ok(response::json(200, &result))
}

async fn update_version(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, &["owner"]).await?;
    let mut issues = Issues::new();
    let mut cx = Cx::new(Entry::Body);
    let component = literal(
        &Value::String(call.param("component").to_string()),
        &["path".into(), "component".into()],
        &mut cx,
        VERSION_COMPONENTS,
    );
    for issue in cx.into_issues() {
        issues.push(issue);
    }
    let body = issues.body::<VersionUpdate>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let component = component.expect("validated");
    let result = app
        .managers
        .versions
        .update(component, &body.version, body.expected_current.as_deref())
        .await
        .map_err(agent_failure)?;
    let mut detail = Map::new();
    detail.insert("version".into(), json!(body.version));
    app.audit(&user, "runtime.version.update", component, &call, Some(detail)).await?;
    Ok(response::json(200, &result))
}

async fn rebuild_managers(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, &["owner"]).await?;
    let result = app.managers.versions.rebuild_managers().await.map_err(agent_failure)?;
    if !result.is_object() {
        return Err(Failure::internal("AttributeError: result has no attribute 'get'"));
    }
    let mut detail = Map::new();
    detail.insert("pending".into(), result.get("pending_rebuild").cloned().unwrap_or(Value::Null));
    app.audit(&user, "runtime.version.managers_rebuild", "panel", &call, Some(detail)).await?;
    Ok(response::json(200, &result))
}
