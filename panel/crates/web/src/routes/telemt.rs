//! `panel/telemt_routes.py`: host telemetry, the all-protocol dashboard and the nine MTProxy
//! endpoints, in registration order. Telemt failures keep the application's fixed 502; the other
//! protocol managers cost only their dashboard card. All creates go through the domain writer.

use axum::extract::State;
use http::HeaderName;
use panel_clients::error::runtime_answer;
use panel_clients::{AuditContext, ClientsError, DomainFacade};
use panel_managers::{ManagerError, TelemtError};
use panel_model::validate::{literal, Cx, Entry};
use panel_model::Protocol;
use panel_pages::models::{UserCreate, UserLimits, OPERATIONS};
use panel_pages::{dashboard, telemt, Fault};
use panel_protocols::error::raw_telemt;
use serde_json::{json, Map, Value};

use crate::auth::Principal;
use crate::http::request::{Call, Issues};
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::state::AppState;

use super::clients::ClientsDomain;
use super::gather::{gathering, GatherError};

const OWNER_ADMIN: &[&str] = &["owner", "admin"];

pub fn routes() -> Routes {
    Routes::new()
        .get("/api/host", host)
        .get("/api/dashboard", dashboard_route)
        .get("/api/users", users)
        .post("/api/users", add_user)
        .post("/api/users/{username}/access", user_access)
        .delete("/api/users/{username}", delete_user)
        .post("/api/users/{username}/limits", user_limits)
        .post("/api/users/{username}/reset-quota", user_reset_quota)
        .post("/api/users/{username}/{operation}", user_operation)
}

fn page_fault(fault: Fault) -> Failure {
    match fault {
        Fault::Api(error) => Failure::from(*error),
        Fault::Manager(error) => match error.app_error() {
            Some(answer) => Failure::from(answer),
            None => Failure::internal(error),
        },
        Fault::Crash(message) => Failure::internal(message),
    }
}

fn telemt_fault(error: TelemtError) -> Failure {
    Failure::from(error.app_error())
}

/// An error the route did not catch: the ADR 003 gate and escaped manager failures keep their
/// application responses; everything else is Starlette's bare 500.
fn domain_uncaught(error: ClientsError) -> Failure {
    if let ClientsError::ManagedByCentral = error {
        return Failure::detail(409, "managed by central")
            .with_header(HeaderName::from_static("x-reason"), "managed_by_central");
    }
    if let Some((protocol, failure)) = error.runtime() {
        return match runtime_answer(protocol, &failure) {
            Some(answer) => Failure::from(answer),
            None => Failure::internal(error),
        };
    }
    Failure::internal(error)
}

fn domain_create_fault(error: ClientsError) -> Failure {
    match error {
        ClientsError::Conflict(message) => Failure::detail(409, message),
        other => domain_uncaught(other),
    }
}

fn facade(app: &AppState) -> DomainFacade {
    app.service::<ClientsDomain>().facade.clone()
}

fn audit_context(user: &Principal, call: &Call) -> AuditContext {
    AuditContext::new(user.actor(), call.client_ip(), Some(call.request_id().to_string()))
}

async fn local_only(app: &AppState, username: &str) -> Result<(), Failure> {
    let facade = facade(app);
    let username = username.to_string();
    panel_clients::blocking(move || facade.local_only(Protocol::Mtproxy, &username)).await.map_err(domain_uncaught)
}

fn telemt_gather_error(error: GatherError<TelemtError>) -> Failure {
    match error {
        GatherError::Task(error) => error,
        GatherError::Call(error) => telemt_fault(error),
    }
}

async fn host_resources(app: &AppState) -> Value {
    match app.managers.versions.host().await {
        Ok(data) => telemt::safe_host(&data),
        Err(_) => telemt::host_unavailable(),
    }
}

async fn host(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    Ok(response::json(200, &host_resources(&app).await))
}

type TelemtSnapshot = (Value, Value, Value, Value, Value);

async fn telemt_snapshot(app: &AppState) -> Result<TelemtSnapshot, Failure> {
    let telemt = app.managers.telemt.clone();
    let health = tokio::spawn({
        let client = telemt.clone();
        async move { client.health().await }
    });
    let stats = tokio::spawn({
        let client = telemt.clone();
        async move { client.stats().await }
    });
    let connections = tokio::spawn({
        let client = telemt.clone();
        async move { client.connections().await }
    });
    let active_ips = tokio::spawn({
        let client = telemt.clone();
        async move { client.active_ips().await }
    });
    let items = tokio::spawn(async move { telemt.list_users().await });
    tokio::try_join!(
        gathering(health),
        gathering(stats),
        gathering(connections),
        gathering(active_ips),
        gathering(items),
    )
    .map_err(telemt_gather_error)
}

type NaiveSnapshot = (Value, Value, Value);

async fn naive_snapshot(app: &AppState) -> Result<NaiveSnapshot, GatherError<ManagerError>> {
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
    tokio::try_join!(gathering(health), gathering(items), gathering(traffic))
}

type MieruSnapshot = (Value, Value, Value, Option<panel_pages::mieru::Traffic>);

async fn mieru_snapshot(app: &AppState) -> Result<MieruSnapshot, GatherError<ManagerError>> {
    let mieru = app.managers.mieru.clone();
    let health = tokio::spawn({
        let client = mieru.clone();
        async move { client.health().await }
    });
    let users = tokio::spawn({
        let client = mieru.clone();
        async move { client.list_users().await }
    });
    let metrics = tokio::spawn({
        let client = mieru.clone();
        async move { client.metrics().await }
    });
    let traffic = tokio::spawn(async move {
        // `mieru_traffic(app)`: every manager failure, and a response without a users list,
        // means unavailable rather than zero.
        let bytes = match mieru.traffic().await {
            Ok(data) => panel_pages::mieru::traffic_map(&data),
            Err(_) => None,
        };
        Ok::<_, ManagerError>(bytes)
    });
    tokio::try_join!(gathering(health), gathering(users), gathering(metrics), gathering(traffic))
}

type TunnelSnapshot = (Value, Value);

async fn amneziawg_snapshot(app: &AppState) -> Result<TunnelSnapshot, GatherError<ManagerError>> {
    let manager = app.managers.amneziawg.clone();
    let health = tokio::spawn({
        let client = manager.clone();
        async move { client.health().await }
    });
    let peers = tokio::spawn(async move { manager.peers().await });
    tokio::try_join!(gathering(health), gathering(peers))
}

async fn trusttunnel_snapshot(app: &AppState) -> Result<TunnelSnapshot, GatherError<ManagerError>> {
    let manager = app.managers.trusttunnel.clone();
    let health = tokio::spawn({
        let client = manager.clone();
        async move { client.health().await }
    });
    let clients = tokio::spawn(async move { manager.clients().await });
    tokio::try_join!(gathering(health), gathering(clients))
}

async fn dashboard_route(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let (health, stats, connections, active_ips, items) = telemt_snapshot(&app).await?;
    let (mtproxy, runtime_total) =
        dashboard::mtproxy(&health, &connections, &active_ips, &items).map_err(page_fault)?;
    let mut protocols = Map::new();
    protocols.insert("mtproxy".into(), mtproxy);

    if app.settings.naive_enabled {
        let card = match naive_snapshot(&app).await {
            Err(GatherError::Call(_)) => dashboard::naive_degraded(&app.settings.naive_public_host),
            Err(GatherError::Task(error)) => return Err(error),
            Ok((naive_health, naive_items, raw_traffic)) => {
                match panel_pages::naive::safe_naive_traffic(&raw_traffic) {
                    Ok(traffic) => {
                        dashboard::naive(&app.settings.naive_public_host, &naive_health, &naive_items, &traffic)
                            .map_err(page_fault)?
                    }
                    Err(Fault::Manager(_)) => dashboard::naive_degraded(&app.settings.naive_public_host),
                    Err(other) => return Err(page_fault(other)),
                }
            }
        };
        protocols.insert("naive".into(), card);
    } else {
        protocols.insert("naive".into(), dashboard::disabled());
    }

    if app.settings.mieru_enabled {
        let card = match mieru_snapshot(&app).await {
            Err(GatherError::Call(_)) => dashboard::mieru_degraded(),
            Err(GatherError::Task(error)) => return Err(error),
            Ok((mieru_health, mieru_users, metrics, bytes)) => {
                if !panel_pages::py::eq(&metrics, &panel_managers::mieru::metrics_unavailable()) {
                    // This raise is in asyncio.gather's `else` block, outside the route's `except
                    // MieruError`: the application handler fails the whole dashboard.
                    return Err(Failure::detail(502, "Mieru manager unavailable"));
                } else {
                    dashboard::mieru(&mieru_health, &mieru_users, bytes.as_ref()).map_err(page_fault)?
                }
            }
        };
        protocols.insert("mieru".into(), card);
    } else {
        protocols.insert("mieru".into(), dashboard::disabled());
    }

    if app.settings.amneziawg_enabled {
        let card = match amneziawg_snapshot(&app).await {
            Err(GatherError::Call(_)) => dashboard::tunnel_degraded(),
            Err(GatherError::Task(error)) => return Err(error),
            Ok((awg_health, peers)) => dashboard::amneziawg(&awg_health, &peers).map_err(page_fault)?,
        };
        protocols.insert("amneziawg".into(), card);
    } else {
        protocols.insert("amneziawg".into(), dashboard::disabled());
    }

    if app.settings.trusttunnel_enabled {
        let card = match trusttunnel_snapshot(&app).await {
            Err(GatherError::Call(_)) => dashboard::tunnel_degraded(),
            Err(GatherError::Task(error)) => return Err(error),
            Ok((tt_health, clients)) => dashboard::trusttunnel(&tt_health, &clients).map_err(page_fault)?,
        };
        protocols.insert("trusttunnel".into(), card);
    } else {
        protocols.insert("trusttunnel".into(), dashboard::disabled());
    }

    let host = host_resources(&app).await;
    Ok(response::json(
        200,
        &json!({
            "health": health,
            "stats": stats,
            "connections": connections,
            "active_ips": active_ips,
            "traffic": {"runtime_total_octets": runtime_total},
            "protocols": protocols,
            "host": host,
        }),
    ))
}

async fn users(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    let client = app.managers.telemt.clone();
    let items = tokio::spawn({
        let client = client.clone();
        async move { client.list_users().await }
    });
    let quotas = tokio::spawn(async move { client.quota_stats().await });
    let (items, quota_data) = tokio::try_join!(gathering(items), gathering(quotas)).map_err(telemt_gather_error)?;
    let body = telemt::user_items(&items, &quota_data).map_err(page_fault)?;
    Ok(response::json(200, &body))
}

/// `_domain_created`: provision and escrow first, then rebuild the old create response from the
/// live Telemt row. The plaintext only enters the one-time reveal, never the route response.
async fn domain_created(app: &AppState, username: &str, call: &Call, user: &Principal) -> Result<Value, Failure> {
    let context = audit_context(user, call);
    let secret =
        facade(app).create(Protocol::Mtproxy, username, &Map::new(), &context).await.map_err(domain_create_fault)?;
    let items = app.managers.telemt.list_users().await.map_err(telemt_fault)?;
    let row = telemt::find_user(&items, username).map_err(page_fault)?.unwrap_or(Value::Null);
    let secret = String::from_utf8(secret).map_err(Failure::internal)?;
    Ok(json!({"user": row, "secret": panel_managers::api_secret(&secret)}))
}

async fn add_user(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<UserCreate>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    local_only(&app, &body.username).await?;
    let data = domain_created(&app, &body.username, &call, &user).await?;
    app.audit(&user, "user.create", &body.username, &call, None).await?;
    let reveal = telemt::secret_reveal(&data).map_err(page_fault)?;
    let token = app.create_reveal(reveal, &user);
    Ok(response::json(201, &json!({"username": body.username, "reveal_token": token})))
}

async fn user_access(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let username = call.param("username");
    let items = app.managers.telemt.list_users().await.map_err(telemt_fault)?;
    let selected = telemt::find_user(&items, username).map_err(page_fault)?;
    let Some(selected) = selected else {
        return Err(Failure::detail(404, "user not found"));
    };
    let access = telemt::user_access(username, &selected).map_err(page_fault)?;
    app.audit(&user, "user.access", username, &call, None).await?;
    Ok(response::json(200, &access))
}

async fn delete_user(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let username = call.param("username");
    local_only(&app, username).await?;
    let lifecycle = app.service::<ClientsDomain>().lifecycle.clone();
    let manager = app.managers.telemt.clone();
    let name = username.to_string();
    lifecycle
        .delete_from_protocol_page(
            Protocol::Mtproxy,
            username,
            async move {
                manager
                    .delete_user(&name)
                    .await
                    .map_err(|error| ClientsError::adapter(Protocol::Mtproxy, raw_telemt(error)))
            },
            &audit_context(&user, &call),
        )
        .await
        .map_err(domain_uncaught)?;
    app.audit(&user, "user.delete", username, &call, None).await?;
    Ok(response::empty(204))
}

async fn user_limits(State(app): State<AppState>, call: Call) -> Handled {
    let input = call.body_input()?;
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let body = issues.body::<UserLimits>(&input);
    issues.finish()?;
    let body = body.expect("validated");
    if body.set.is_empty() {
        return Err(Failure::detail(422, "at least one limit is required"));
    }
    let username = call.param("username");
    local_only(&app, username).await?;
    let fields = Value::Object(body.set);
    let data = app.managers.telemt.update_user(username, &fields).await.map_err(telemt_fault)?;
    let detail = fields.as_object().cloned();
    app.audit(&user, "user.limits", username, &call, detail).await?;
    Ok(response::json(200, &telemt::safe_user(&data, None)))
}

async fn user_reset_quota(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let username = call.param("username");
    local_only(&app, username).await?;
    let data = app.managers.telemt.reset_quota(username).await.map_err(telemt_fault)?;
    app.audit(&user, "user.reset_quota", username, &call, None).await?;
    Ok(response::json(200, &telemt::safe_quota_reset(&data)))
}

async fn user_operation(State(app): State<AppState>, call: Call) -> Handled {
    let user = app.roles(&call, OWNER_ADMIN).await?;
    let mut issues = Issues::new();
    let mut cx = Cx::new(Entry::Body);
    let operation = literal(
        &Value::String(call.param("operation").to_string()),
        &["path".into(), "operation".into()],
        &mut cx,
        OPERATIONS,
    );
    for issue in cx.into_issues() {
        issues.push(issue);
    }
    issues.finish()?;
    let operation = operation.expect("validated");
    let username = call.param("username");
    local_only(&app, username).await?;

    let data = if operation == "rotate" {
        // The domain owns every credential in 4.0: rotating only Telemt would leave links and
        // subscriptions serving the revoked key. Use the existing adapter/escrow transaction.
        let secret = facade(&app)
            .rotate(Protocol::Mtproxy, username, &Map::new(), &audit_context(&user, &call))
            .await
            .map_err(|error| {
                if error.is_adapter_error() {
                    Failure::detail(502, "Telemt service unavailable")
                } else {
                    domain_uncaught(error)
                }
            })?;
        let items = app.managers.telemt.list_users().await.map_err(telemt_fault)?;
        let row = telemt::find_user(&items, username).map_err(page_fault)?.unwrap_or(Value::Null);
        let secret = String::from_utf8(secret).map_err(Failure::internal)?;
        let result = json!({"user": row, "secret": panel_managers::api_secret(&secret)});
        let reveal = telemt::secret_reveal(&result).map_err(page_fault)?;
        json!({"username": username, "reveal_token": app.create_reveal(reveal, &user)})
    } else {
        let enabled = operation == "enable";
        let worker = facade(&app);
        let name = username.to_string();
        let effective = panel_clients::blocking(move || worker.effective_operation(Protocol::Mtproxy, &name, enabled))
            .await
            .map_err(domain_uncaught)?;
        let changed = app.managers.telemt.set_enabled(username, effective).await.map_err(telemt_fault)?;
        let data = telemt::safe_user(&changed, None);

        let worker = facade(&app);
        let name = username.to_string();
        let known = panel_clients::blocking(move || worker.grant(Protocol::Mtproxy, &name))
            .await
            .map_err(domain_uncaught)?
            .is_some();
        if known {
            facade(&app)
                .set_enabled(Protocol::Mtproxy, username, enabled, &Map::new(), &audit_context(&user, &call))
                .await
                .map_err(domain_uncaught)?;
        }
        data
    };
    app.audit(&user, &format!("user.{operation}"), username, &call, None).await?;
    Ok(response::json(200, &data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemt_adapter_does_not_leak_secret_in_errors() {
        let secret = "0123456789abcdef0123456789abcdef";
        let Failure::Api(failure) = telemt_fault(TelemtError::new(format!("upstream replied {secret}"))) else {
            panic!("Telemt errors use the application error response");
        };
        assert_eq!(failure.error.status(), 502);
        assert_eq!(failure.error.body(), json!({"detail": "Telemt service unavailable"}));
        assert!(!failure.error.body().to_string().contains(secret));
    }
}
