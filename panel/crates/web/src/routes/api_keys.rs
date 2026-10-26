//! `panel/api_key_routes.py`: owner-only management of scoped API keys; the plaintext leaves
//! once, at creation.

use axum::extract::State;
use panel_secrets::api_keys::ApiKeyError;
use serde_json::{json, Value};

use crate::auth::blocking;
use crate::http::request::{Call, Issues};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::models::{ApiKeyCreate, ApiKeyEnabled};
use crate::state::AppState;

pub fn routes() -> Routes {
    Routes::new()
        .get("/api/keys", list_keys)
        .post("/api/keys", create_key)
        .post("/api/keys/{key_id}/enabled", set_enabled)
        .delete("/api/keys/{key_id}", delete_key)
}

fn key_error(error: ApiKeyError) -> Failure {
    match error {
        ApiKeyError::Invalid(message) => Failure::detail(422, message),
        ApiKeyError::NotFound(_) => Failure::detail(404, "key not found"),
        ApiKeyError::Db(error) => Failure::internal(error),
    }
}

async fn list_keys(State(app): State<AppState>, call: Call) -> Handled {
    app.read_roles(&call, &["owner"]).await?;
    let keys = app.api_keys.clone();
    let items = blocking(move || keys.list()).await?;
    let items: Vec<Value> = items.iter().map(|key| Value::Object(key.to_json())).collect();
    Ok(response::json(200, &json!({"items": items})))
}

async fn create_key(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, &["owner"]).await?;
    let mut issues = Issues::new();
    let body = issues.body::<ApiKeyCreate>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    let (keys, actor) = (app.api_keys.clone(), user.actor());
    let (ip, request_id) = (call.client_ip().to_string(), call.request_id().to_string());
    let created = tokio::task::spawn_blocking(move || {
        keys.create(&body.name, &body.scope, body.expires_at, &actor, &ip, Some(&request_id))
    })
    .await
    .map_err(Failure::internal)?;
    let (key, plaintext) = created.map_err(key_error)?;
    Ok(response::json(201, &json!({"key": Value::Object(key.to_json()), "plaintext": plaintext})))
}

async fn set_enabled(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, &["owner"]).await?;
    let mut issues = Issues::new();
    let key_id = issues.path_int(&call, "key_id");
    let body = issues.body::<ApiKeyEnabled>(&input);
    issues.finish()?;
    let (key_id, enabled) = (key_id.expect("validated"), body.expect("validated").enabled);
    let (keys, actor) = (app.api_keys.clone(), user.actor());
    let (ip, request_id) = (call.client_ip().to_string(), call.request_id().to_string());
    tokio::task::spawn_blocking(move || keys.set_enabled(key_id, enabled, &actor, &ip, Some(&request_id)))
        .await
        .map_err(Failure::internal)?
        .map_err(key_error)?;
    Ok(response::json(200, &json!({"ok": true})))
}

async fn delete_key(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, &["owner"]).await?;
    let mut issues = Issues::new();
    let key_id = issues.path_int(&call, "key_id");
    issues.finish()?;
    let key_id = key_id.expect("validated");
    let (keys, actor) = (app.api_keys.clone(), user.actor());
    let (ip, request_id) = (call.client_ip().to_string(), call.request_id().to_string());
    tokio::task::spawn_blocking(move || keys.delete(key_id, &actor, &ip, Some(&request_id)))
        .await
        .map_err(Failure::internal)?
        .map_err(key_error)?;
    Ok(response::json(200, &json!({"ok": true})))
}
