//! `panel/mieru_routes.py`: Mieru's seven protocol-page endpoints, including escrowed-key access
//! without rotation, lane-aware link rendering and revision-forwarded runtime mutations.

use std::collections::BTreeSet;

use axum::extract::State;
use http::HeaderName;
use panel_clients::error::runtime_answer;
use panel_clients::{AuditContext, ClientsError, DomainFacade};
use panel_managers::ManagerError;
use panel_model::clients::AccessGrant;
use panel_model::validate::{literal, Cx, Entry, Model};
use panel_model::Protocol;
use panel_pages::{mieru as page, models::dump_quotas, py, Fault};
use panel_protocols::error::raw_manager;
use panel_protocols::mieru::{parse_share_url, template_from};
use serde_json::{json, Map, Value};

use crate::auth::Principal;
use crate::http::request::{Call, Issues};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::state::AppState;

use super::clients::ClientsDomain;
use super::gather::{gathering, GatherError};

const OWNER_ADMIN: &[&str] = &["owner", "admin"];

/// The routes in `register_mieru_routes` order.
pub fn routes() -> Routes {
    Routes::new()
        .get("/api/mieru/users", users)
        .post("/api/mieru/users", create)
        .post("/api/mieru/users/{username}/quotas", quotas)
        .post("/api/mieru/users/{username}/reset-metrics", reset_metrics)
        .post("/api/mieru/users/{username}/access", access)
        .post("/api/mieru/users/{username}/{operation}", operation)
        .delete("/api/mieru/users/{username}", delete)
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

fn require_mieru(app: &AppState) -> Result<(), Failure> {
    if app.settings.mieru_enabled {
        Ok(())
    } else {
        Err(Failure::detail(404, "feature unavailable"))
    }
}

async fn local_only(app: &AppState, username: &str) -> Result<(), Failure> {
    let (facade, username) = (facade(app), username.to_string());
    panel_clients::blocking(move || facade.local_only(Protocol::Mieru, &username))
        .await
        .map_err(|error| domain_failure(error, false))
}

async fn grant_result(app: &AppState, username: &str) -> Result<Option<AccessGrant>, ClientsError> {
    let (facade, username) = (facade(app), username.to_string());
    panel_clients::blocking(move || facade.grant(Protocol::Mieru, &username)).await
}

async fn grant(app: &AppState, username: &str) -> Result<Option<AccessGrant>, Failure> {
    grant_result(app, username).await.map_err(|error| domain_failure(error, false))
}

fn escrow_error(error: ClientsError) -> Result<(), Failure> {
    match error {
        ClientsError::Conflict(_)
        | ClientsError::ManagedByCentral
        | ClientsError::Invalid(_)
        | ClientsError::Validation(_)
        | ClientsError::Secret(_) => Ok(()),
        other => Err(domain_failure(other, false)),
    }
}

/// Keep a newly issued password and, on first contact, adopt the account. Failure to keep a key
/// does not take away the reveal the operator is already owed.
async fn escrow(
    app: &AppState,
    username: &str,
    share_url: &Value,
    quotas: Option<Value>,
    action: &str,
    context: &AuditContext,
) -> Result<(), Failure> {
    let Ok(share) = share_url.as_str().ok_or(()).and_then(|value| parse_share_url(value).map_err(|_| ())) else {
        return Ok(());
    };
    let quotas = match quotas {
        Some(quotas) => quotas,
        None => {
            let existing = match grant_result(app, username).await {
                Ok(grant) => grant,
                Err(error) => return escrow_error(error),
            };
            if existing.is_none() {
                let listed = match app.managers.mieru.list_users().await {
                    Ok(listed) => listed,
                    Err(_) => return Ok(()),
                };
                let mut found = json!([]);
                for row in py::dict_items(&listed).map_err(page_failure)? {
                    if row.get("username").is_some_and(|name| py::eq(name, &json!(username))) {
                        found = row.get("quotas").cloned().unwrap_or_else(|| json!([]));
                        break;
                    }
                }
                found
            } else {
                json!([])
            }
        }
    };
    let quotas = if py::truthy(Some(&quotas)) { quotas } else { json!([]) };
    let learned = template_from(share_url, &share.username, &share.password)
        .map(|template| Map::from_iter([("share_template".into(), json!(template))]));
    let observed = Map::from_iter([("quotas".into(), quotas)]);
    let (facade, username, action, context) = (facade(app), username.to_string(), action.to_string(), context.clone());
    let result = panel_clients::blocking(move || {
        facade.escrow(
            Protocol::Mieru,
            &username,
            share.password.as_bytes(),
            learned.as_ref(),
            &observed,
            &action,
            true,
            &context,
        )
    })
    .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) => escrow_error(error),
    }
}

/// The kept key rendered against the lane slot mita serves now, else the adapter's learned
/// template. No runtime mutation is performed by this read.
async fn kept_share_url(app: &AppState, username: &str) -> Result<String, Failure> {
    let grant = grant(app, username).await?;
    let Some(grant) = grant.filter(|grant| grant.secret_ref.is_some()) else {
        return Err(Failure::detail(409, page::NOT_KEPT));
    };
    let (facade, name) = (facade(app), username.to_string());
    let credential = match panel_clients::blocking(move || facade.credential(Protocol::Mieru, &name)).await {
        Ok(credential) => credential,
        Err(error @ (ClientsError::Conflict(_) | ClientsError::Secret(_))) => {
            let _ = error;
            return Err(Failure::detail(409, page::NOT_KEPT));
        }
        Err(error) => return Err(domain_failure(error, false)),
    };
    let password = String::from_utf8(credential).map_err(|_| Failure::detail(409, page::NOT_KEPT))?;
    if let Ok(view) = app.managers.mieru.lanes().await {
        if let Some(template) = page::live_template(&view, username).map_err(page_failure)? {
            if let Some(rendered) = page::format_live_template(&template, username, &password) {
                return Ok(rendered);
            }
        }
    }
    let adapters = app.service::<ClientsDomain>().adapters.clone();
    let adapter = adapters.require(Protocol::Mieru).map_err(|error| domain_failure(error, false))?;
    let artifacts = adapter.render_artifacts(&grant, password.as_bytes(), "").map_err(Failure::internal)?;
    artifacts
        .first()
        .map(|artifact| artifact.value.clone())
        .ok_or_else(|| Failure::internal("IndexError: list index out of range"))
}

async fn users(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    require_mieru(&app)?;
    let mieru = app.managers.mieru.clone();
    let health = tokio::spawn({
        let client = mieru.clone();
        async move { client.health().await }
    });
    let items = tokio::spawn({
        let client = mieru.clone();
        async move { client.list_users().await }
    });
    let metrics = tokio::spawn({
        let client = mieru.clone();
        async move { client.metrics().await }
    });
    let traffic = tokio::spawn(async move {
        let mapped = match mieru.traffic().await {
            Ok(data) => page::traffic_map(&data),
            Err(_) => None,
        };
        Ok::<_, ManagerError>(mapped)
    });
    let (health, items, metrics, traffic) =
        tokio::try_join!(gathering(health), gathering(items), gathering(metrics), gathering(traffic))
            .map_err(gather_failure)?;
    let mut kept = BTreeSet::new();
    for item in py::dict_items(&items).map_err(page_failure)? {
        let name = item.get("username").map_or_else(String::new, py::py_str);
        if !py::account_name(&name) {
            continue;
        }
        if let Some(username) = item.get("username").and_then(Value::as_str) {
            if grant(&app, username).await?.is_some_and(|grant| grant.secret_ref.is_some()) {
                kept.insert(username.to_string());
            }
        }
    }
    let body = page::users(&health, &items, &metrics, traffic.as_ref(), &kept).map_err(page_failure)?;
    Ok(response::json(200, &body))
}

/// `_domain_created`: provision with a caller credential, then rebuild the manager-shaped link
/// from the grant and the adapter's learned template.
async fn domain_created(
    app: &AppState,
    username: &str,
    quotas: &Value,
    context: &AuditContext,
) -> Result<Value, Failure> {
    let options = Map::from_iter([("quotas".into(), quotas.clone())]);
    let credential = facade(app)
        .create(Protocol::Mieru, username, &options, context)
        .await
        .map_err(|error| domain_failure(error, true))?;
    let grant = grant(app, username)
        .await?
        .ok_or_else(|| Failure::internal("AttributeError: 'NoneType' object has no attribute 'options'"))?;
    let health = app.managers.mieru.health().await.map_err(manager_failure)?;
    let revision = py::dict(&health).map_err(page_failure)?.get("revision").cloned().unwrap_or(Value::Null);
    let adapters = app.service::<ClientsDomain>().adapters.clone();
    let adapter = adapters.require(Protocol::Mieru).map_err(|error| domain_failure(error, false))?;
    let artifacts = adapter.render_artifacts(&grant, &credential, "").map_err(Failure::internal)?;
    let share_url = artifacts.first().map(|artifact| artifact.value.clone()).unwrap_or_default();
    Ok(json!({"username": username, "revision": revision, "share_url": share_url}))
}

async fn create(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<panel_pages::models::MieruUserCreate>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    require_mieru(&app)?;
    local_only(&app, &body.username).await?;
    let quotas = dump_quotas(&body.quotas);
    let elevated = user.role == "owner" && (body.allow_private_ip || body.allow_loopback_ip);
    let context = audit_context(&user, &call);
    let data = if !elevated {
        domain_created(&app, &body.username, &quotas, &context).await?
    } else {
        let mut payload = body.dump();
        payload["elevated"] = json!(true);
        let data = app.managers.mieru.create(&payload).await.map_err(manager_failure)?;
        let map = py::dict(&data).map_err(page_failure)?;
        let share_url = map.get("share_url").cloned().unwrap_or(Value::Null);
        escrow(&app, &body.username, &share_url, Some(quotas.clone()), "grant.credential.capture", &context).await?;
        data
    };
    let map = py::dict(&data).map_err(page_failure)?;
    let revision = map.get("revision").cloned().unwrap_or(Value::Null);
    app.audit(
        &user,
        "mieru.create",
        &body.username,
        &call,
        Some(Map::from_iter([("quotas".into(), quotas), ("ssrf_flags".into(), json!(elevated))])),
    )
    .await?;
    // Python audits before rendering the reveal: an invalid manager link is a 409 with the
    // successful runtime mutation already present in the audit log.
    let reveal = page::access(map.get("share_url").unwrap_or(&Value::Null)).map_err(page_failure)?;
    let reveal_token = app.create_reveal(reveal, &user);
    Ok(response::json(201, &json!({"username": body.username, "revision": revision, "reveal_token": reveal_token})))
}

async fn quotas(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<panel_pages::models::MieruQuotaUpdate>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    require_mieru(&app)?;
    let username = call.param("username");
    local_only(&app, username).await?;
    let quotas = dump_quotas(&body.quotas);
    let payload = json!({"expected_revision": body.expected_revision, "quotas": quotas});
    let data = app.managers.mieru.set_quotas(username, &payload).await.map_err(manager_failure)?;
    app.audit(&user, "mieru.quotas", username, &call, Some(Map::from_iter([("quotas".into(), quotas)]))).await?;
    Ok(response::json(200, &data))
}

async fn reset_metrics(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    require_mieru(&app)?;
    let username = call.param("username");
    local_only(&app, username).await?;
    let data = app.managers.mieru.reset_metrics(username).await.map_err(manager_failure)?;
    app.audit(&user, "mieru.metrics.baseline", username, &call, None).await?;
    Ok(response::json(200, &data))
}

async fn access(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    require_mieru(&app)?;
    let username = call.param("username");
    local_only(&app, username).await?;
    let share_url = kept_share_url(&app, username).await?;
    let data = page::access(&json!(share_url)).map_err(page_failure)?;
    app.audit(&user, "mieru.access", username, &call, None).await?;
    Ok(response::json(200, &data))
}

async fn operation(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
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
    let body = issues.body::<panel_pages::models::MieruRevision>(&input);
    issues.finish()?;
    let operation = operation.expect("validated");
    let body = body.expect("validated");
    require_mieru(&app)?;
    let username = call.param("username");
    local_only(&app, username).await?;
    let context = audit_context(&user, &call);
    let effective = if operation == "rotate" {
        operation
    } else {
        let requested = operation == "enable";
        let (facade, name) = (facade(&app), username.to_string());
        let enabled = panel_clients::blocking(move || facade.effective_operation(Protocol::Mieru, &name, requested))
            .await
            .map_err(|error| domain_failure(error, false))?;
        if enabled {
            "enable"
        } else {
            "disable"
        }
    };
    let data =
        app.managers.mieru.operation(username, effective, &body.expected_revision).await.map_err(manager_failure)?;
    if operation != "rotate" {
        let observed = Map::from_iter([("quotas".into(), json!([]))]);
        facade(&app)
            .set_enabled(Protocol::Mieru, username, operation == "enable", &observed, &context)
            .await
            .map_err(|error| domain_failure(error, false))?;
    }
    if operation == "rotate" {
        let map = py::dict(&data).map_err(page_failure)?;
        let share_url = map.get("share_url").cloned().unwrap_or(Value::Null);
        escrow(&app, username, &share_url, None, "grant.rotate", &context).await?;
        app.audit(&user, "mieru.rotate", username, &call, None).await?;
        // As in Python, the audit survives a subsequent invalid-link 409.
        let reveal = page::access(&share_url).map_err(page_failure)?;
        let reveal_token = app.create_reveal(reveal, &user);
        return Ok(response::json(
            200,
            &json!({
                "username": username,
                "revision": map.get("revision").cloned().unwrap_or(Value::Null),
                "reveal_token": reveal_token,
            }),
        ));
    }
    app.audit(&user, &format!("mieru.{operation}"), username, &call, None).await?;
    Ok(response::json(200, &data))
}

async fn delete(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<panel_pages::models::MieruRevision>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    require_mieru(&app)?;
    let username = call.param("username");
    local_only(&app, username).await?;
    let lifecycle = app.service::<ClientsDomain>().lifecycle.clone();
    let manager = app.managers.mieru.clone();
    let name = username.to_string();
    let context = audit_context(&user, &call);
    let data = lifecycle
        .delete_from_protocol_page(
            Protocol::Mieru,
            username,
            async move {
                manager
                    .delete(&name, &body.expected_revision)
                    .await
                    .map_err(|error| ClientsError::adapter(Protocol::Mieru, raw_manager(error)))
            },
            &context,
        )
        .await
        .map_err(|error| domain_failure(error, false))?;
    app.audit(&user, "mieru.delete", username, &call, None).await?;
    Ok(response::json(200, &data))
}
