//! The operator-facing node API (`node_routes.py`): read for everyone signed in, lifecycle for the
//! owner, never raw transport plumbing.
//!
//! | Route | Gate | Answer |
//! |---|---|---|
//! | `GET /api/nodes` | `current` | `{"items": [view…]}`, the local node first, with `services` and `identity` |
//! | `GET /api/nodes/{node_id}` | `current` | the view (the local one with `services` and `identity`); 404 |
//! | `POST /api/nodes/{node_id}/rename` | `roles("owner")` | body `NodeRename`; the plain view; 404/422 |
//! | `POST /api/nodes/{node_id}/disable` | `roles("owner")` | the plain view; 404/409 |
//! | `POST /api/nodes/{node_id}/enable` | `roles("owner")` | the plain view; 404/409 |
//!
//! Retired with fleet v1 (owner decision, 2026-10-25) and not served: `POST /api/nodes` (v1
//! registration with its enrollment checklist), `POST /api/nodes/{node_id}/certificates/revoke-all`
//! and every `/api/fleet/nodes*` route ([`RETIRED_ROUTES`]).
//!
//! The web shell (WP4) owns authentication, CSRF, the request id, the client address and FastAPI's
//! body decoding; it hands them in through [`NodesState`]. Precedence is FastAPI's: a body that is
//! not JSON is refused (422) before authentication, the model's own errors (422) after it.

// `ApiError` (panel-core) is the answer itself; boxing it on every error path would buy nothing.
#![allow(clippy::result_large_err)]

use std::error::Error;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use panel_core::errors::{ApiError, LocItem};
use panel_core::pyjson;
use panel_model::protocols::BoxFuture;
use panel_model::seams::SeamError;
use panel_model::validate::{Cx, Extra, Fields, Model, Str};
use panel_secrets::identity::{read_setting, MASTER_KEY};
use serde_json::{json, Map, Value};

use crate::error::NodesError;
use crate::read_model::view_to_value;
use crate::registry::AuditContext;
use crate::service::NodeLifecycleService;
use crate::NodeView;

/// The routes this module serves, `(method, path)` in registration order (for the web shell's
/// route-set == OpenAPI test).
pub const ROUTES: [(&str, &str); 5] = [
    ("GET", "/api/nodes"),
    ("GET", "/api/nodes/{node_id}"),
    ("POST", "/api/nodes/{node_id}/rename"),
    ("POST", "/api/nodes/{node_id}/disable"),
    ("POST", "/api/nodes/{node_id}/enable"),
];

/// Operations of the recorded OpenAPI document that fleet v1's retirement removes: the v1 node
/// API (`fleet_routes.py`) and the v1 lifecycle actions of `node_routes.py`.
pub const RETIRED_ROUTES: [(&str, &str); 6] = [
    ("GET", "/api/fleet/nodes"),
    ("POST", "/api/fleet/nodes"),
    ("GET", "/api/fleet/nodes/{node_id}/commands"),
    ("POST", "/api/fleet/nodes/{node_id}/commands"),
    ("POST", "/api/nodes"),
    ("POST", "/api/nodes/{node_id}/certificates/revoke-all"),
];

/// Which dependency guards a route (`web_context.RequestContext`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// `context.current`: a session or an API key (a `node-sync` key only on the fleet API).
    Current,
    /// `context.roles(*allowed)`: `current`, the CSRF check of a cookie session, then the role.
    Roles(&'static [&'static str]),
}

/// `roles("owner")`.
pub const OWNER: Gate = Gate::Roles(&["owner"]);

/// The local services whose health the local node's card shows (`_local_services`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalManager {
    Telemt,
    Naive,
    Mieru,
    Amneziawg,
    Trusttunnel,
}

impl LocalManager {
    /// The key in `services`, in the order Python builds the dict.
    pub const ALL: [LocalManager; 5] = [
        LocalManager::Telemt,
        LocalManager::Naive,
        LocalManager::Mieru,
        LocalManager::Amneziawg,
        LocalManager::Trusttunnel,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            LocalManager::Telemt => "telemt",
            LocalManager::Naive => "naive",
            LocalManager::Mieru => "mieru",
            LocalManager::Amneziawg => "amneziawg",
            LocalManager::Trusttunnel => "trusttunnel",
        }
    }
}

/// What the node routes need from the application (WP4's `AppState` implements it).
pub trait NodesState: Clone + Send + Sync + 'static {
    /// The node lifecycle service (`app.state.nodes`).
    fn nodes(&self) -> &NodeLifecycleService;

    /// This panel's GUID (`app.state.panel_guid`).
    fn panel_guid(&self) -> String;

    /// Runs the gate on the request head: the caller's audit context (actor, client address,
    /// request id) or the gate's refusal (401/403/429 with FastAPI's `detail`).
    fn authorize<'a>(&'a self, parts: &'a Parts, gate: Gate) -> BoxFuture<'a, Result<AuditContext, ApiError>>;

    /// FastAPI's reading of a JSON request body: the value (`Null` for an empty body), or the 422
    /// `json_invalid` answer for malformed JSON.
    fn decode_body(&self, parts: &Parts, body: &Bytes) -> Result<Value, ApiError>;

    /// The protocol switch of `settings` (`naive_enabled`, …); Telemt is always probed.
    fn manager_enabled(&self, manager: LocalManager) -> bool;

    /// The manager's health call: `true` when it answered, `false` when it raised its client
    /// error (`TelemtError`, `NaiveError`, …).
    fn manager_healthy(&self, manager: LocalManager) -> BoxFuture<'_, bool>;

    /// `adapters["amneziawg"].versions()` (only asked when AmneziaWG is enabled); an
    /// `AdapterError` becomes `[]`.
    fn amneziawg_versions(&self) -> BoxFuture<'_, Result<Vec<String>, SeamError>>;

    /// The answer to an unexpected failure (Starlette's 500), logged by the shell.
    fn internal_error(&self, error: Box<dyn Error + Send + Sync>) -> Response;
}

/// The node routes, generic over the application state.
pub fn router<S: NodesState>() -> Router<S> {
    Router::new()
        .route("/api/nodes", get(list::<S>))
        .route("/api/nodes/{node_id}", get(one::<S>))
        .route("/api/nodes/{node_id}/rename", post(rename::<S>))
        .route("/api/nodes/{node_id}/disable", post(disable::<S>))
        .route("/api/nodes/{node_id}/enable", post(enable::<S>))
}

/// `NodeRename`: `display_name: str = Field(min_length=1, max_length=128)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRename {
    pub display_name: String,
}

impl Model for NodeRename {
    const TITLE: &'static str = "NodeRename";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut fields = Fields::open(input, loc, cx, Self::TITLE)?;
        let display_name = fields.required(cx, "display_name", |v, l, cx| Str::len(1, 128).validate(v, l, cx));
        if !fields.finish(cx, Extra::Ignore) {
            return None;
        }
        Some(NodeRename { display_name: display_name? })
    }

    fn dump(&self) -> Value {
        json!({"display_name": self.display_name})
    }
}

// -- plumbing ------------------------------------------------------------------------------------

enum RouteError {
    Api(ApiError),
    Internal(Box<dyn Error + Send + Sync>),
}

impl From<ApiError> for RouteError {
    fn from(error: ApiError) -> Self {
        RouteError::Api(error)
    }
}

impl From<NodesError> for RouteError {
    fn from(error: NodesError) -> Self {
        match error.to_api_error() {
            Some(api) => RouteError::Api(api),
            None => RouteError::Internal(Box::new(error)),
        }
    }
}

/// A Starlette `JSONResponse`: compact, raw UTF-8, `application/json`.
pub fn json_response(status: u16, value: &Value) -> Response {
    let mut response = Response::new(Body::from(pyjson::compact_utf8(value)));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// An [`ApiError`] as the panel answers it.
pub fn error_response(error: &ApiError) -> Response {
    json_response(error.status(), &error.body())
}

fn finish<S: NodesState>(state: &S, result: Result<Response, RouteError>) -> Response {
    match result {
        Ok(response) => response,
        Err(RouteError::Api(error)) => error_response(&error),
        Err(RouteError::Internal(error)) => state.internal_error(error),
    }
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, NodesError> + Send + 'static,
) -> Result<T, RouteError> {
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result.map_err(RouteError::from),
        Err(error) => Err(RouteError::Internal(Box::new(error))),
    }
}

async fn probe<S: NodesState>(state: &S, manager: LocalManager) -> &'static str {
    if manager != LocalManager::Telemt && !state.manager_enabled(manager) {
        return "disabled";
    }
    if state.manager_healthy(manager).await {
        "ok"
    } else {
        "unavailable"
    }
}

/// `_local_services`: the local node has no transport, so its health is its managers' (asked
/// concurrently; a switched-off protocol is `disabled` and never asked).
async fn local_services<S: NodesState>(state: &S) -> Map<String, Value> {
    let (telemt, naive, mieru, amneziawg, trusttunnel) = tokio::join!(
        probe(state, LocalManager::Telemt),
        probe(state, LocalManager::Naive),
        probe(state, LocalManager::Mieru),
        probe(state, LocalManager::Amneziawg),
        probe(state, LocalManager::Trusttunnel),
    );
    let mut services = Map::new();
    for (manager, answer) in LocalManager::ALL.into_iter().zip([telemt, naive, mieru, amneziawg, trusttunnel]) {
        services.insert(manager.key().into(), Value::String(answer.into()));
    }
    services
}

/// `_rendered(node)`: the view, and for the local node its managers' health and who this panel is
/// (`{"guid", "master_guid", "awg_versions"}`: what the owner types into a central to link it,
/// the central that manages it, the AmneziaWG versions its manager runs).
async fn rendered<S: NodesState>(state: &S, view: &NodeView) -> Result<Value, RouteError> {
    let mut value = view_to_value(view);
    if view.kind == "local" {
        let services = local_services(state).await;
        let database = state.nodes().database().clone();
        let master = blocking(move || Ok(database.with_connection(|db| read_setting(db, MASTER_KEY))?)).await?;
        let versions = if state.manager_enabled(LocalManager::Amneziawg) {
            state.amneziawg_versions().await.unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut identity = Map::new();
        identity.insert("guid".into(), Value::String(state.panel_guid()));
        identity.insert("master_guid".into(), master.map_or(Value::Null, Value::String));
        identity.insert("awg_versions".into(), versions.into());
        let object = value.as_object_mut().expect("a view is an object");
        object.insert("services".into(), Value::Object(services));
        object.insert("identity".into(), Value::Object(identity));
    }
    Ok(value)
}

async fn authorized<S: NodesState>(state: &S, parts: &Parts, gate: Gate) -> Result<AuditContext, RouteError> {
    Ok(state.authorize(parts, gate).await?)
}

// -- handlers ------------------------------------------------------------------------------------

async fn list<S: NodesState>(State(state): State<S>, request: Request) -> Response {
    let result = async {
        let (parts, _) = request.into_parts();
        authorized(&state, &parts, Gate::Current).await?;
        let service = state.nodes().clone();
        let views = blocking(move || service.list()).await?;
        let mut items = Vec::with_capacity(views.len());
        for view in &views {
            items.push(rendered(&state, view).await?);
        }
        Ok(json_response(200, &json!({"items": items})))
    }
    .await;
    finish(&state, result)
}

async fn one<S: NodesState>(State(state): State<S>, Path(node_id): Path<String>, request: Request) -> Response {
    let result = async {
        let (parts, _) = request.into_parts();
        authorized(&state, &parts, Gate::Current).await?;
        let service = state.nodes().clone();
        let view = blocking(move || service.get(&node_id)).await?;
        Ok(json_response(200, &rendered(&state, &view).await?))
    }
    .await;
    finish(&state, result)
}

async fn rename<S: NodesState>(State(state): State<S>, Path(node_id): Path<String>, request: Request) -> Response {
    let result = async {
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(body, usize::MAX)
            .await
            .map_err(|_| ApiError::detail(400, "There was an error parsing the body"))?;
        let value = state.decode_body(&parts, &bytes)?;
        let context = authorized(&state, &parts, OWNER).await?;
        let body = NodeRename::validate_body(&value).map_err(|error| error.to_api_error())?;
        let service = state.nodes().clone();
        let view = blocking(move || service.rename(&node_id, &body.display_name, &context)).await?;
        Ok(json_response(200, &view_to_value(&view)))
    }
    .await;
    finish(&state, result)
}

async fn set_disabled<S: NodesState>(state: S, node_id: String, disabled: bool, request: Request) -> Response {
    let result = async {
        let (parts, _) = request.into_parts();
        let context = authorized(&state, &parts, OWNER).await?;
        let service = state.nodes().clone();
        let view = blocking(move || service.set_disabled(&node_id, disabled, &context)).await?;
        Ok(json_response(200, &view_to_value(&view)))
    }
    .await;
    finish(&state, result)
}

async fn disable<S: NodesState>(State(state): State<S>, Path(node_id): Path<String>, request: Request) -> Response {
    set_disabled(state, node_id, true, request).await
}

async fn enable<S: NodesState>(State(state): State<S>, Path(node_id): Path<String>, request: Request) -> Response {
    set_disabled(state, node_id, false, request).await
}
