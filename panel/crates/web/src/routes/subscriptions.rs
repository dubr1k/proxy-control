//! `register_subscription_routes` (`panel/subscription_routes.py`, row 16): `GET|HEAD /s/{token}`,
//! the one endpoint a subscriber's client talks to.
//!
//! It answers only on the subscription host; every refusal — wrong host, malformed token, unknown
//! format or client, unknown or revoked token — is the same 404 from [`refuse`]; the rate limit
//! (per client address, across all tokens, misses included) runs after the validation and before
//! the token lookup. The ETag is the effective set of grants, not the fetch time; `If-None-Match`
//! is compared exactly (no `W/`). HEAD renders in full and answers with an empty body and
//! `Content-Length: 0`. The header order is Starlette's: the route's headers, then
//! `content-length` and `content-type` (the server adds the security headers after them).

use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use http::header::{HeaderName, HeaderValue};
use http::{Method, StatusCode};
use panel_core::pytext;
use panel_subscriptions::public::{self, FETCHES_PER_MINUTE};
use panel_subscriptions::renderers::{self, resolve_artifacts};
use panel_subscriptions::{Format, RenderOptions, SubscriptionService};
use serde_json::json;

use crate::http::request::Call;
use crate::http::response::{Failure, Handled};
use crate::http::router::Routes;
use crate::routes::clients::ClientsDomain;
use crate::routes::subscriptions_admin::service;
use crate::state::AppState;

/// The route (`include_in_schema=False`).
pub fn routes() -> Routes {
    Routes::new().route(&[Method::GET, Method::HEAD], "/s/{token}", subscription).hidden()
}

/// A response with these headers, in this order (`content-length` and `content-type` last).
fn answer(
    status: u16,
    headers: &[(&'static str, String)],
    body: Vec<u8>,
    length: Option<usize>,
    media_type: Option<&str>,
) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let target = response.headers_mut();
    let mut put = |name: &'static str, value: &str| {
        if let Ok(value) = HeaderValue::from_str(value) {
            target.insert(HeaderName::from_static(name), value);
        }
    };
    for (name, value) in headers {
        put(name, value);
    }
    if let Some(length) = length {
        put("content-length", &length.to_string());
    }
    if let Some(media_type) = media_type {
        put("content-type", media_type);
    }
    response
}

/// `refuse(status, detail)`: one body and one branch for every refusal.
fn refuse(status: u16, detail: &str) -> Response {
    let body = panel_core::pyjson::compact_utf8(&json!({"detail": detail})).into_bytes();
    let length = body.len();
    let headers = [
        ("cache-control", "private, no-cache".to_string()),
        ("vary", "Accept".to_string()),
        ("x-robots-tag", "noindex".to_string()),
    ];
    answer(status, &headers, body, Some(length), Some("application/json"))
}

fn not_found() -> Handled {
    Ok(refuse(404, "not found"))
}

async fn blocking<T, F>(work: F) -> Result<T, Failure>
where
    F: FnOnce() -> Result<T, panel_clients::ClientsError> + Send + 'static,
    T: Send + 'static,
{
    panel_clients::blocking(work).await.map_err(Failure::internal)
}

async fn subscription(State(app): State<AppState>, call: Call) -> Handled {
    let settings = &app.settings;
    let host_header = call.header("host").unwrap_or_default();
    let host = pytext::lower(host_header.rsplit_once(':').map_or(host_header.as_str(), |(host, _)| host));
    if settings.subscription_host.is_empty() || host != settings.subscription_host {
        return not_found();
    }
    let token = call.param("token").to_string();
    if !public::is_token(&token) {
        return not_found();
    }
    let explicit = call.query("format");
    let user_agent = call.header("user-agent").unwrap_or_default();
    let forked = match explicit.as_deref() {
        None | Some("singbox") => public::fork_client(&user_agent, &settings.singbox_fork_clients),
        Some(_) => None,
    };
    // `explicit or (…)`: an empty `format=` negotiates like an absent one.
    let name = match explicit.as_deref() {
        Some(text) if !text.is_empty() => text.to_string(),
        _ if forked.is_some() => "singbox".to_string(),
        _ => public::negotiate(&call.header("accept").unwrap_or_default()).to_string(),
    };
    let Some(format) = Format::from_name(&name) else {
        return not_found();
    };
    let mut client = call.query("client");
    if client.as_deref().is_some_and(|client| !public::format_clients(&name).contains(&client)) {
        return not_found();
    }
    if client.is_none() && name == "singbox" {
        client = forked.map(str::to_string);
    }
    let client = client.map(|client| public::client_alias(&client).to_string());

    let (store, scope) = (app.store.clone(), format!("subscription:{}", call.client_ip()));
    let reservation =
        crate::auth::blocking(move || store.reserve_login_attempt(&[scope], FETCHES_PER_MINUTE, 60)).await?;
    if reservation.is_none() {
        return Ok(refuse(429, "too many requests"));
    }
    let subscriptions = service(&app);
    let lookup = subscriptions.clone();
    let Some(found) = blocking(move || lookup.resolve(&token)).await? else {
        return not_found();
    };

    let now = app.clock.now();
    let worker = (subscriptions.clone(), found.clone());
    let manifest = blocking(move || worker.0.effective_manifest(&worker.1, now)).await?;
    // The page shows its own address, its language and when the set last moved: part of its body.
    let mut options = RenderOptions { client: client.clone(), ..RenderOptions::default() };
    let mut variant = client.clone().unwrap_or_default();
    if format == Format::Html {
        let lang = if call.query("lang").as_deref() == Some("en") { "en" } else { "ru" };
        let url = if subscriptions.public_base().is_empty() {
            String::new()
        } else {
            subscriptions.public_url(call.param("token"))
        };
        options =
            RenderOptions { url, lang: lang.into(), updated_at: Some(found.updated_at), ..RenderOptions::default() };
        variant = format!("{lang}:{}", found.updated_at);
    }
    let etag = SubscriptionService::etag(&manifest, format.version(), &variant).map_err(Failure::internal)?;
    let etag = format!("\"{etag}\"");
    let headers = [
        ("cache-control", "private, no-cache".to_string()),
        ("vary", "Accept, User-Agent".to_string()),
        ("profile-update-interval", found.update_interval_hours.to_string()),
        ("x-robots-tag", "noindex".to_string()),
        ("etag", etag.clone()),
    ];
    let conditional = call.header("if-none-match").unwrap_or_default();
    if conditional.split(',').any(|value| pytext::strip(value) == etag) {
        let (recorder, subscription) = (subscriptions.clone(), found.clone());
        blocking(move || recorder.record_fetch(&subscription, now, 304, format.name())).await?;
        return Ok(answer(304, &headers, Vec::new(), None, None));
    }
    let domain = app.service::<ClientsDomain>().clone();
    let renderer = subscriptions.clone();
    // Reveal and render in one blocking call: the plaintext never outlives it.
    let body = blocking(move || {
        let hosts = domain.hosts.clone();
        let artifacts = renderer.database().with_connection(|db| {
            resolve_artifacts(&manifest, renderer.secrets(), &domain.adapters, db, hosts.as_ref())
        })?;
        renderers::render(format, &manifest, &artifacts, &options)
            .map_err(|error| panel_clients::ClientsError::Internal(error.to_string()))
    })
    .await?;
    let (recorder, subscription) = (subscriptions.clone(), found.clone());
    blocking(move || recorder.record_fetch(&subscription, now, 200, format.name())).await?;
    let body = if call.parts.method == Method::HEAD { Vec::new() } else { body };
    let length = body.len();
    Ok(answer(200, &headers, body, Some(length), Some(format.media_type())))
}
