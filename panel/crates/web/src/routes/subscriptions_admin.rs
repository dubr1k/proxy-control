//! `register_subscription_admin_routes` (`panel/subscription_routes.py`, row 15): the operator's
//! side — one subscription per client, its URL shown at creation and, with a keyring, again on an
//! audited request; the compatibility catalogue; the subscription and node events. Plus the
//! package's wiring: the [`SubscriptionService`], the generation hook on the client service and the
//! issuer `POST /api/clients` uses.

use std::sync::Arc;

use axum::extract::State;
use panel_clients::{AuditContext, ClientsError};
use panel_model::validate::Int;
use panel_subscriptions::{apps, compatibility, BumpGeneration, SubscriptionService};
use serde_json::{json, Value};

use crate::auth::Principal;
use crate::http::request::{Call, Issues};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::routes::clients::ClientsDomain;
use crate::state::{AppState, Core, Services};

/// The routes, in `register_subscription_admin_routes` order.
pub fn routes() -> Routes {
    Routes::new()
        .get("/api/subscriptions/compatibility", compatibility)
        .get("/api/events", events)
        .get("/api/clients/{client_id}/subscription", read)
        .post("/api/clients/{client_id}/subscription", create)
        .post("/api/clients/{client_id}/subscription/rotate", rotate)
        .post("/api/clients/{client_id}/subscription/reveal", reveal)
        .post("/api/clients/{client_id}/subscription/revoke", revoke)
}

/// `app.state.subscriptions`.
#[derive(Clone, Debug)]
pub struct Subscriptions(pub SubscriptionService);

/// `app.state.subscriptions = SubscriptionService(…)` and
/// `app.state.clients.on_change.append(app.state.subscriptions.bump_generation)` (`app.py:188-194`),
/// plus the issuer the client API takes for `POST /api/clients` with `subscription: true`.
pub fn wire(core: &Arc<Core>, services: &mut Services) {
    let Some(domain) = services.get::<ClientsDomain>().cloned() else {
        return;
    };
    let service = SubscriptionService::new(
        core.database.clone(),
        domain.clients.clone(),
        core.secrets.clone(),
        core.clock.clone(),
        core.settings.subscription_url.clone(),
        Some(core.events.clone()),
    );
    // Every grant mutation funnels through `ClientService::notify` inside its own transaction.
    domain.clients.add_hook(Arc::new(BumpGeneration(service.clone())));
    services.insert(crate::routes::clients::Subscriptions(Arc::new(service.clone())));
    services.insert(Subscriptions(service));
}

pub(crate) fn service(app: &AppState) -> SubscriptionService {
    app.service::<Subscriptions>().0.clone()
}

fn audit_context(user: &Principal, call: &Call) -> AuditContext {
    AuditContext::new(user.actor(), call.client_ip(), Some(call.request_id().to_string()))
}

const OWNER_ADMIN: &[&str] = &["owner", "admin"];

/// Runs blocking work; the error goes to `translate`.
async fn blocking<T, F>(work: F) -> Result<T, ClientsError>
where
    F: FnOnce() -> Result<T, ClientsError> + Send + 'static,
    T: Send + 'static,
{
    panel_clients::blocking(work).await
}

/// `KeyError` → 404 with the route's text, `ClientConflict` → 409, `SecretError` → 409 (where the
/// route catches it); anything else escapes to the bare 500.
fn translate(error: ClientsError, not_found: &str, secret: bool) -> Failure {
    match error {
        ClientsError::NotFound(_) => Failure::detail(404, not_found),
        ClientsError::Conflict(message) => Failure::detail(409, message),
        ClientsError::Secret(message) if secret => Failure::detail(409, message),
        other => Failure::internal(other),
    }
}

async fn compatibility(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let mut body = serde_json::Map::new();
    body.insert("matrix".into(), compatibility::matrix_json());
    body.insert("notes".into(), compatibility::notes_json());
    body.extend(apps::catalogue());
    Ok(response::json(200, &Value::Object(body)))
}

async fn events(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let mut issues = Issues::new();
    let after = issues.query_int(&call, "after", Int::lax(Some(0), None), Some(0));
    let limit =
        issues.query_int(&call, "limit", Int::lax(Some(1), Some(panel_secrets::events::MAX_PAGE.into())), Some(100));
    issues.finish()?;
    let after = after.flatten().unwrap_or(0);
    let limit = limit.flatten().unwrap_or(100);
    let bus = app.events.clone();
    let items = crate::auth::blocking(move || bus.since(after, limit)).await?;
    let next_after = items.last().and_then(|item| item.get("id").cloned()).unwrap_or(Value::from(after));
    Ok(response::json(200, &json!({"items": items, "next_after": next_after})))
}

async fn read(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let (service, client_id) = (service(&app), call.param("client_id").to_string());
    let body = blocking(move || service.overview(&client_id))
        .await
        .map_err(|error| translate(error, "client not found", false))?;
    Ok(response::json(200, &body))
}

/// `issue(operation, …)`: refused without a subscription domain; the plaintext token lives only in
/// the one-time reveal.
async fn issue(app: &AppState, call: &Call, user: &Principal, rotate: bool) -> Result<Value, Failure> {
    let service = service(app);
    if service.public_base().is_empty() {
        return Err(Failure::detail(409, "PANEL_SUBSCRIPTION_URL is not configured: there is no URL to hand out"));
    }
    let (client_id, context) = (call.param("client_id").to_string(), audit_context(user, call));
    let payload = blocking(move || {
        let (subscription, token) =
            if rotate { service.rotate(&client_id, &context)? } else { service.create(&client_id, &context)? };
        service.reveal_payload(&subscription, &token)
    })
    .await
    .map_err(|error| translate(error, "client not found", false))?;
    Ok(json!({"reveal_token": app.create_reveal(payload, user)}))
}

async fn create(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let body = issue(&app, &call, &user, false).await?;
    Ok(response::json(201, &body))
}

async fn rotate(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let body = issue(&app, &call, &user, true).await?;
    Ok(response::json(200, &body))
}

async fn reveal(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let (service, client_id, context) =
        (service(&app), call.param("client_id").to_string(), audit_context(&user, &call));
    let payload = blocking(move || {
        let (subscription, token) = service.reveal_token(&client_id, &context)?;
        service.reveal_payload(&subscription, &token)
    })
    .await
    .map_err(|error| translate(error, "client or subscription not found", true))?;
    Ok(response::json(200, &json!({"reveal_token": app.create_reveal(payload, &user)})))
}

async fn revoke(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let (service, client_id, context) =
        (service(&app), call.param("client_id").to_string(), audit_context(&user, &call));
    let existed = blocking(move || {
        let existed = service.get(&client_id)?.is_some();
        service.revoke(&client_id, &context)?;
        Ok(existed)
    })
    .await
    .map_err(Failure::internal)?;
    Ok(response::json(200, &json!({"revoked": existed})))
}
