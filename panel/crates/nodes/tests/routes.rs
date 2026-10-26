#![allow(clippy::result_large_err)]
//! The node routes against the exchanges recorded from the Python panel (`tests/fixtures/http.db` +
//! `http.json`): same status, content type and body bytes, same audit rows. The web shell's part
//! (sessions, CSRF, the request id) is played by a fake state with the Python panel's answers.

mod common;

use std::error::Error;

use axum::body::{to_bytes, Body, Bytes};
use axum::http::request::Parts;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use common::{fixture_database, fixture_json, service_at, table, TempDir};
use panel_core::errors::{ApiError, ValidationIssue};
use panel_core::serde_json::{self, json, Value};
use panel_model::protocols::BoxFuture;
use panel_model::seams::SeamError;
use panel_nodes::registry::AuditContext;
use panel_nodes::routes::{self, Gate, LocalManager, NodesState};
use panel_nodes::NodeLifecycleService;
use panel_secrets::audit::Actor;
use tower::ServiceExt as _;

#[derive(Clone)]
struct FakeState {
    nodes: NodeLifecycleService,
    guid: String,
    master_guid: Option<String>,
}

impl NodesState for FakeState {
    fn nodes(&self) -> &NodeLifecycleService {
        &self.nodes
    }

    fn panel_guid(&self) -> String {
        self.guid.clone()
    }

    fn authorize<'a>(&'a self, parts: &'a Parts, gate: Gate) -> BoxFuture<'a, Result<AuditContext, ApiError>> {
        let who =
            parts.headers.get("x-test-as").and_then(|value| value.to_str().ok()).unwrap_or("anonymous").to_string();
        Box::pin(async move {
            let mutation = matches!(gate, Gate::Roles(_));
            let actor = match who.as_str() {
                "owner" => Actor::new(Some(1), "owner"),
                "viewer" if !mutation => Actor::new(Some(2), "viewer"),
                "viewer" => return Err(ApiError::detail(403, "insufficient role")),
                "no-csrf" if !mutation => Actor::new(Some(1), "owner"),
                "no-csrf" => return Err(ApiError::detail(403, "CSRF validation failed")),
                _ => return Err(ApiError::detail(401, "authentication required")),
            };
            Ok(AuditContext::new(actor, "127.0.0.1", None))
        })
    }

    fn decode_body(&self, _parts: &Parts, body: &Bytes) -> Result<Value, ApiError> {
        if body.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(body).map_err(|error| {
            ApiError::Validation(vec![ValidationIssue::json_invalid(error.column() as i64, error.to_string())])
        })
    }

    fn manager_enabled(&self, manager: LocalManager) -> bool {
        manager != LocalManager::Trusttunnel
    }

    fn manager_healthy(&self, manager: LocalManager) -> BoxFuture<'_, bool> {
        assert_ne!(manager, LocalManager::Trusttunnel, "a switched-off protocol was asked for its health");
        Box::pin(async move { manager != LocalManager::Mieru })
    }

    fn amneziawg_versions(&self) -> BoxFuture<'_, Result<Vec<String>, SeamError>> {
        Box::pin(async { Ok(vec!["1.5".to_string(), "2.0".to_string()]) })
    }

    fn internal_error(&self, error: Box<dyn Error + Send + Sync>) -> Response {
        panic!("internal error: {error}")
    }
}

fn app(state: FakeState) -> Router {
    routes::router::<FakeState>().with_state(state)
}

async fn call(router: &Router, who: &str, method: &str, path: &str, payload: Option<&Value>) -> Response {
    let mut request = Request::builder().method(method).uri(path).header("x-test-as", who);
    let body = match payload {
        Some(payload) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(payload).unwrap())
        }
        None => Body::empty(),
    };
    router.clone().oneshot(request.body(body).unwrap()).await.unwrap()
}

#[tokio::test]
async fn recorded_exchanges_are_answered_byte_for_byte() {
    let golden = fixture_json("http.json");
    let dir = TempDir::new("http");
    let database = fixture_database("http.db", &dir);
    let state = FakeState {
        nodes: service_at(database.clone(), golden["now"].as_i64().unwrap()),
        guid: golden["panel_guid"].as_str().unwrap().to_string(),
        master_guid: None,
    };
    let router = app(state);
    for exchange in golden["exchanges"].as_array().unwrap() {
        let payload = (!exchange["json"].is_null()).then_some(&exchange["json"]);
        let response = call(
            &router,
            exchange["as"].as_str().unwrap(),
            exchange["method"].as_str().unwrap(),
            exchange["path"].as_str().unwrap(),
            payload,
        )
        .await;
        let label = format!("{} {} as {}", exchange["method"], exchange["path"], exchange["as"]);
        assert_eq!(response.status().as_u16() as i64, exchange["status"].as_i64().unwrap(), "{label}");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()),
            exchange["content_type"].as_str(),
            "{label}"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), exchange["body"].as_str().unwrap(), "{label}");
    }
    let audits: Vec<Value> = table(&database, "SELECT * FROM audit_log WHERE action LIKE 'node.%' ORDER BY id")
        .into_iter()
        .map(|mut row| {
            let object = row.as_object_mut().unwrap();
            object.shift_remove("id");
            object.shift_remove("request_id");
            row
        })
        .collect();
    assert_eq!(audits, golden["audit_log"].as_array().unwrap().clone());
}

#[tokio::test]
async fn the_local_identity_names_the_managing_central() {
    let dir = TempDir::new("master");
    let database = common::migrated(&dir);
    database
        .connect()
        .unwrap()
        .raw()
        .execute(
            "INSERT INTO panel_settings(key,value,updated_at) VALUES('fleet_master_guid','c0ffee00-0000-4000-8000-000000000000',1)",
            [],
        )
        .unwrap();
    let state = FakeState {
        nodes: service_at(database, common::NOW),
        guid: "0d8f06ed-a24c-4189-9d02-e2b30e32f3cc".into(),
        master_guid: Some("c0ffee00-0000-4000-8000-000000000000".into()),
    };
    let expected = state.master_guid.clone();
    let response = call(&app(state), "owner", "GET", "/api/nodes/local", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(
        body["identity"],
        json!({"guid": "0d8f06ed-a24c-4189-9d02-e2b30e32f3cc", "master_guid": expected, "awg_versions": ["1.5", "2.0"]})
    );
    assert_eq!(
        body["services"],
        json!({"telemt": "ok", "naive": "ok", "mieru": "unavailable", "amneziawg": "ok", "trusttunnel": "disabled"})
    );
}

#[tokio::test]
async fn malformed_json_is_refused_before_authentication() {
    let dir = TempDir::new("malformed");
    let state =
        FakeState { nodes: service_at(common::migrated(&dir), common::NOW), guid: String::new(), master_guid: None };
    let request = Request::builder()
        .method("POST")
        .uri("/api/nodes/local/rename")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let response = app(state).oneshot(request).await.unwrap();
    // Anonymous, yet the body is judged first: 422, not 401.
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn retired_fleet_v1_routes_are_not_served() {
    let dir = TempDir::new("retired");
    let state =
        FakeState { nodes: service_at(common::migrated(&dir), common::NOW), guid: String::new(), master_guid: None };
    let router = app(state);
    let payload = json!({"node_id": "edge-01", "display_name": "Edge"});
    // POST on the list path is a method the path does not take; the rest are unknown paths.
    assert_eq!(
        call(&router, "owner", "POST", "/api/nodes", Some(&payload)).await.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    for (method, path) in [
        ("POST", "/api/nodes/edge-01/certificates/revoke-all"),
        ("GET", "/api/fleet/nodes"),
        ("POST", "/api/fleet/nodes"),
        ("GET", "/api/fleet/nodes/edge-01/commands"),
        ("POST", "/api/fleet/nodes/edge-01/commands"),
    ] {
        assert_eq!(
            call(&router, "owner", method, path, Some(&json!({}))).await.status(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    let served: Vec<(&str, &str)> = routes::ROUTES.to_vec();
    for retired in routes::RETIRED_ROUTES {
        assert!(!served.contains(&retired));
    }
}
