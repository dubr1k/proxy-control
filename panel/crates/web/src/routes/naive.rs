//! `panel/naive_routes.py`: NaiveProxy's seven protocol-page endpoints. Runtime writes go first;
//! the domain facade records the credential, effective access and grant lifecycle around them.

use axum::extract::State;
use http::HeaderName;
use panel_clients::error::runtime_answer;
use panel_clients::{AuditContext, ClientsError, DomainFacade};
use panel_core::pytext;
use panel_managers::ManagerError;
use panel_model::validate::{literal, Cx, Entry};
use panel_model::Protocol;
use panel_pages::{naive as page, py, Fault};
use panel_protocols::error::raw_manager;
use serde_json::{json, Map, Value};

use crate::auth::Principal;
use crate::http::request::{Call, Issues};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::state::AppState;

use super::clients::ClientsDomain;
use super::gather::{gathering, GatherError};

const OWNER_ADMIN: &[&str] = &["owner", "admin"];

/// The routes in `register_naive_routes` order.
pub fn routes() -> Routes {
    Routes::new()
        .get("/api/naive/users", users)
        .post("/api/naive/users", create)
        .post("/api/naive/users/{username}/access", access)
        .post("/api/naive/users/{username}/quota", quota)
        .post("/api/naive/users/{username}/{operation}", operation)
        .post("/api/naive/users/{username}/traffic/reset", traffic_reset)
        .delete("/api/naive/users/{username}", delete)
}

fn facade(app: &AppState) -> DomainFacade {
    app.service::<ClientsDomain>().facade.clone()
}

fn audit_context(user: &Principal, call: &Call) -> AuditContext {
    AuditContext::new(user.actor(), call.client_ip(), Some(call.request_id().to_string()))
}

fn manager_failure(error: ManagerError) -> Failure {
    error.app_error().map_or_else(|| Failure::internal(error), Failure::from)
}

fn gather_failure(error: GatherError<ManagerError>) -> Failure {
    match error {
        GatherError::Task(error) => error,
        GatherError::Call(error) => manager_failure(error),
    }
}

fn page_failure(error: Fault) -> Failure {
    match error {
        Fault::Api(error) => Failure::from(*error),
        Fault::Manager(error) => manager_failure(error),
        Fault::Crash(message) => Failure::internal(message),
    }
}

/// Exceptions the protocol route itself does not catch: the central-management gate, an escaped
/// manager error, a seam's API refusal, or Python's bare 500.
fn domain_failure(error: ClientsError, conflict: bool) -> Failure {
    if conflict {
        if let ClientsError::Conflict(message) = &error {
            return Failure::detail(409, message.clone());
        }
    }
    if let ClientsError::ManagedByCentral = error {
        return Failure::detail(409, "managed by central")
            .with_header(HeaderName::from_static("x-reason"), "managed_by_central");
    }
    if let Some((protocol, failure)) = error.runtime() {
        return runtime_answer(protocol, &failure).map_or_else(|| Failure::internal(error), Failure::from);
    }
    if let ClientsError::Seam(seam) = &error {
        if let Some(api) = seam.downcast_ref::<panel_core::errors::ApiError>() {
            return Failure::from(api.clone());
        }
    }
    Failure::internal(error)
}

fn require_naive(app: &AppState) -> Result<(), Failure> {
    if app.settings.naive_enabled {
        Ok(())
    } else {
        Err(Failure::detail(404, "feature unavailable"))
    }
}

async fn local_only(app: &AppState, username: &str) -> Result<(), Failure> {
    let (facade, username) = (facade(app), username.to_string());
    panel_clients::blocking(move || facade.local_only(Protocol::Naive, &username))
        .await
        .map_err(|error| domain_failure(error, false))
}

/// Escrow is best-effort after the manager has issued the credential. Failures Python logs and
/// suppresses stay suppressed; a database or injected crash still escapes.
fn escrow_error(error: ClientsError) -> Result<(), Failure> {
    match error {
        ClientsError::NotFound(_)
        | ClientsError::Conflict(_)
        | ClientsError::ManagedByCentral
        | ClientsError::Invalid(_)
        | ClientsError::Validation(_)
        | ClientsError::Secret(_) => Ok(()),
        other => Err(domain_failure(other, false)),
    }
}

async fn escrow(
    app: &AppState,
    username: &str,
    value: &Value,
    quota_bytes: Option<i64>,
    action: &str,
    context: &AuditContext,
) -> Result<(), Failure> {
    let password = value
        .as_object()
        .and_then(|value| value.get("proxy_url"))
        .and_then(Value::as_str)
        .and_then(|raw| pytext::urlsplit(raw).ok())
        .map(|parts| pytext::unquote(parts.password().unwrap_or_default()));
    let Some(password) = password else {
        return Ok(());
    };
    let (facade, username, action, context) = (facade(app), username.to_string(), action.to_string(), context.clone());
    let observed = Map::from_iter([("quota_bytes".into(), json!(quota_bytes))]);
    let result = panel_clients::blocking(move || {
        facade.escrow(Protocol::Naive, &username, password.as_bytes(), None, &observed, &action, false, &context)
    })
    .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) => escrow_error(error),
    }
}

async fn users(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    require_naive(&app)?;
    let naive = app.managers.naive.clone();
    let health = tokio::spawn({
        let client = naive.clone();
        async move { client.health().await }
    });
    let items = tokio::spawn({
        let client = naive.clone();
        async move { client.list_users().await }
    });
    let traffic = tokio::spawn(async move { naive.traffic().await });
    let (health, items, traffic) =
        tokio::try_join!(gathering(health), gathering(items), gathering(traffic)).map_err(gather_failure)?;
    let body = page::users(&health, &items, &traffic, &app.settings.naive_public_host).map_err(page_failure)?;
    Ok(response::json(200, &body))
}

async fn create(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<panel_pages::models::NaiveUserCreate>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    require_naive(&app)?;
    local_only(&app, &body.username).await?;
    let context = audit_context(&user, &call);
    let options = Map::from_iter([("quota_bytes".into(), json!(body.quota_bytes))]);
    facade(&app)
        .create(Protocol::Naive, &body.username, &options, &context)
        .await
        .map_err(|error| domain_failure(error, true))?;
    let created = app.managers.naive.reveal(&body.username).await.map_err(manager_failure)?;
    let data = page::reveal(&created, &body.username, &app.settings.naive_public_host).map_err(page_failure)?;
    app.audit(
        &user,
        "naive.create",
        &body.username,
        &call,
        Some(Map::from_iter([("quota_bytes".into(), json!(body.quota_bytes))])),
    )
    .await?;
    let reveal_token = app.create_reveal(data, &user);
    Ok(response::json(201, &json!({"username": body.username, "reveal_token": reveal_token})))
}

async fn access(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    require_naive(&app)?;
    let username = call.param("username");
    let created = app.managers.naive.reveal(username).await.map_err(manager_failure)?;
    let data = page::reveal(&created, username, &app.settings.naive_public_host).map_err(page_failure)?;
    app.audit(&user, "naive.access", username, &call, None).await?;
    Ok(response::json(200, &data))
}

async fn quota(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<panel_pages::models::NaiveQuotaUpdate>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    require_naive(&app)?;
    let username = call.param("username");
    local_only(&app, username).await?;
    let result = app.managers.naive.set_quota(username, body.quota_bytes).await.map_err(manager_failure)?;
    let payload = page::quota_result(username, &result).map_err(page_failure)?;
    app.audit(
        &user,
        "naive.quota",
        username,
        &call,
        Some(Map::from_iter([("quota_bytes".into(), payload["quota_bytes"].clone())])),
    )
    .await?;
    Ok(response::json(200, &payload))
}

async fn operation(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let mut cx = Cx::new(Entry::Body);
    let operation = literal(
        &json!(call.param("operation")),
        &["path".into(), "operation".into()],
        &mut cx,
        panel_pages::models::OPERATIONS,
    );
    for issue in cx.into_issues() {
        issues.push(issue);
    }
    issues.finish()?;
    let operation = operation.expect("validated");
    require_naive(&app)?;
    let username = call.param("username");
    local_only(&app, username).await?;
    let context = audit_context(&user, &call);
    let result = if operation == "rotate" {
        let rotated = app.managers.naive.rotate(username, None, None).await.map_err(manager_failure)?;
        let data = page::reveal(&rotated, username, &app.settings.naive_public_host).map_err(page_failure)?;
        escrow(&app, username, &rotated, None, "grant.rotate", &context).await?;
        let reveal_token = app.create_reveal(data, &user);
        json!({"username": username, "reveal_token": reveal_token})
    } else {
        let requested = operation == "enable";
        let (worker, name) = (facade(&app), username.to_string());
        let effective = panel_clients::blocking(move || worker.effective_operation(Protocol::Naive, &name, requested))
            .await
            .map_err(|error| domain_failure(error, false))?;
        let changed = app.managers.naive.set_enabled(username, effective).await.map_err(manager_failure)?;
        let changed_map = py::dict(&changed).map_err(page_failure)?;
        let result = json!({"username": username, "enabled": py::is_true(changed_map.get("enabled"))});
        let observed =
            Map::from_iter([("quota_bytes".into(), changed_map.get("quota_bytes").cloned().unwrap_or(Value::Null))]);
        facade(&app)
            .set_enabled(Protocol::Naive, username, requested, &observed, &context)
            .await
            .map_err(|error| domain_failure(error, false))?;
        result
    };
    app.audit(&user, &format!("naive.{operation}"), username, &call, None).await?;
    Ok(response::json(200, &result))
}

async fn traffic_reset(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    require_naive(&app)?;
    let username = call.param("username");
    local_only(&app, username).await?;
    let data = app.managers.naive.reset_traffic(username).await.map_err(manager_failure)?;
    let data = page::traffic_reset(&data).map_err(page_failure)?;
    app.audit(&user, "naive.traffic.reset", username, &call, None).await?;
    Ok(response::json(200, &data))
}

async fn delete(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    require_naive(&app)?;
    let username = call.param("username");
    local_only(&app, username).await?;
    let lifecycle = app.service::<ClientsDomain>().lifecycle.clone();
    let manager = app.managers.naive.clone();
    let name = username.to_string();
    let context = audit_context(&user, &call);
    lifecycle
        .delete_from_protocol_page(
            Protocol::Naive,
            username,
            async move {
                manager.delete(&name).await.map_err(|error| ClientsError::adapter(Protocol::Naive, raw_manager(error)))
            },
            &context,
        )
        .await
        .map_err(|error| domain_failure(error, false))?;
    app.audit(&user, "naive.delete", username, &call, None).await?;
    Ok(response::empty(204))
}
