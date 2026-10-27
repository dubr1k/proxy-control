//! Authenticated, body-bounded HTTP API on a local Unix socket (the panel's only door).
//!
//! Answers are what the Python handler sent: compact JSON in the order the manager built it, the
//! error classes mapped to the same statuses, and the bare `{"detail": …}` bodies it used for an
//! unknown route, a wrong token and a refused request.

use std::sync::Arc;

use pc_common::server::Handler;
use pc_common::{Request, Response};
use serde_json::{json, Map, Value};

use crate::errors::Error;
use crate::intent::NO_LANE_SERVICES;
use crate::pyjson;
use crate::service::XrayRouterManager;
use crate::util::{first_chars, py_truthy};

pub const TOKEN_HEADER: &str = "X-Xray-Router-Token";
pub const MAX_BODY: usize = 32_768;

/// `json.dumps(value, separators=(",", ":"))` with the manager's headers.
pub fn send(status: u16, value: &Value) -> Response {
    let mut response = Response::json(status, &Value::Null);
    response.body = pc_common::json::dumps(value, &pyjson::COMPACT).into_bytes();
    response
}

fn not_found() -> Response {
    send(404, &json!({"detail": "not found"}))
}

/// The status and body each of the Python manager's exceptions answered.
pub fn error_response(error: &Error) -> Response {
    let text = error.to_string();
    match error {
        Error::EgressInvalid { code, .. } => send(422, &json!({"detail": first_chars(&text, 400), "code": code})),
        Error::Geodata { code, .. } => {
            let status = if matches!(code.as_str(), "geodata_invalid" | "geodata_corrupt" | "geodata_rejected") {
                422
            } else {
                502
            };
            send(status, &json!({"detail": first_chars(&text, 400), "code": code}))
        }
        Error::EgressUnreachable(_) => send(409, &json!({"detail": text, "code": "egress_unreachable"})),
        Error::Conflict { code, .. } => send(409, &json!({"detail": text, "code": code})),
        Error::Validation(_) => send(422, &json!({"detail": "invalid request"})),
        Error::ArtifactMismatch(_) => send(503, &json!({"detail": text, "code": "artifact_mismatch"})),
        Error::Manual(_) => {
            send(503, &json!({"detail": first_chars(&text, 400), "code": "manual_intervention_required"}))
        }
        Error::Xray(_) => send(502, &json!({"detail": first_chars(&text, 400), "code": "egress_readback_mismatch"})),
        Error::Internal(_) => {
            // The Python handler died here and the panel saw the connection close; this one says
            // so without the reason, which stays in the log.
            log::warn!("manager request failed: {text}");
            pc_common::ApiError::internal().into_response()
        }
    }
}

/// The request handler; refuses a token shorter than 32 characters.
pub fn handler(manager: Arc<XrayRouterManager>, token: String) -> Result<Arc<Handler>, String> {
    if token.chars().count() < 32 {
        return Err("manager token is too short".into());
    }
    Ok(Arc::new(move |request: &Request| {
        if !matches!(request.method.as_str(), "GET" | "POST" | "PUT" | "DELETE") {
            return send(501, &json!({"detail": format!("Unsupported method ('{}')", request.method)}));
        }
        let supplied = request.header(TOKEN_HEADER).unwrap_or("");
        if supplied.is_empty() || !pc_common::constant_time_eq(supplied.as_bytes(), token.as_bytes()) {
            return send(401, &json!({"detail": "unauthorized"}));
        }
        route(&manager, request).unwrap_or_else(|error| error_response(&error))
    }))
}

fn body(request: &Request) -> Result<Map<String, Value>, Error> {
    request.json_object().map_err(|_| Error::Validation("invalid body".into()))
}

fn exact(body: &Map<String, Value>, required: &[&str]) -> Result<(), Error> {
    if body.len() != required.len() || !required.iter().all(|key| body.contains_key(*key)) {
        return Err(Error::Validation("invalid request fields".into()));
    }
    Ok(())
}

fn route(manager: &XrayRouterManager, request: &Request) -> Result<Response, Error> {
    let ok = |value: Value| Ok(send(200, &value));
    let (method, path) = (request.method.as_str(), request.path.as_str());
    if method == "GET" && (path == "/v1/health" || path == "/healthz") {
        let status = manager.status()?;
        if py_truthy(&status["artifact_error"]) || status["phase"] == "broken" {
            let (detail, code) = if py_truthy(&status["artifact_error"]) {
                (status["artifact_error"].clone(), "artifact_mismatch")
            } else {
                (json!("router is broken"), "manual_intervention_required")
            };
            return Ok(send(503, &json!({"detail": detail, "code": code})));
        }
        let running = !status["running"].is_null();
        return Ok(send(if running { 200 } else { 503 }, &json!({"ready": running})));
    }
    if method == "GET" && path == "/v1/status" {
        let status = manager.status()?;
        return Ok(send(if py_truthy(&status["artifact_error"]) { 503 } else { 200 }, &status));
    }
    // v0.8: the geodata files and their source
    match (path, method) {
        ("/v1/geodata", "GET") => return ok(manager.geodata_view()),
        ("/v1/geodata/codes", "GET") => return ok(manager.geodata_codes()),
        ("/v1/geodata/settings", "PUT") => {
            let body = body(request)?;
            if body.is_empty()
                || !body.keys().all(|key| matches!(key.as_str(), "source" | "auto_update" | "interval_hours"))
            {
                return Err(Error::Validation("invalid request fields".into()));
            }
            return ok(manager.geodata_settings(&body)?);
        }
        ("/v1/geodata/update", "POST") => return ok(manager.geodata_update(None)?),
        ("/v1/geodata/restore", "POST") => return ok(manager.geodata_restore()?),
        ("/v1/exits/test", "POST") => {
            let body = body(request)?;
            exact(&body, &["exit"])?;
            return ok(manager.exit_test(&body["exit"])?);
        }
        _ => {}
    }
    // v0.7: lane accounts and the relay inbound (spec §4.3)
    if let Some(rest) = path.strip_prefix("/v1/lanes/") {
        let tail: Vec<&str> = rest.split('/').collect();
        let service = tail[0];
        if !manager.services.contains(&service) || NO_LANE_SERVICES.contains(&service) {
            return Ok(not_found());
        }
        return match (method, tail.len()) {
            ("GET", 1) => ok(manager.lanes(service)?),
            ("POST", 1) => {
                let body = body(request)?;
                exact(&body, &["lane"])?;
                ok(manager.lane_issue(service, &body["lane"])?)
            }
            ("DELETE", 2) => ok(manager.lane_forget(service, tail[1])?),
            _ => Ok(not_found()),
        };
    }
    if path == "/v1/relay" {
        return match method {
            "GET" => ok(manager.relay()?),
            "POST" => {
                let body = body(request)?;
                exact(&body, &["server_name", "port"])?;
                ok(manager.relay_enable(&body["server_name"], &body["port"])?)
            }
            "DELETE" => ok(manager.relay_disable()?),
            _ => Ok(not_found()),
        };
    }
    // v1.1: what the panel writes into Telemt — the bridge's address and Telemt's login.
    if path == "/v1/ingress/mtproxy" && method == "GET" {
        if !manager.services.contains(&"mtproxy") {
            return Ok(not_found());
        }
        return ok(manager.ingress("mtproxy")?);
    }
    if path == "/v1/relay/accounts" && method == "PUT" {
        let body = body(request)?;
        exact(&body, &["accounts"])?;
        return ok(manager.relay_set_accounts(&body["accounts"])?);
    }
    if let Some(rest) = path.strip_prefix("/v1/egress/") {
        let tail: Vec<&str> = rest.split('/').collect();
        let service = tail[0];
        if !manager.services.contains(&service) {
            return Ok(not_found());
        }
        if method == "GET" && tail.len() == 1 {
            return ok(manager.egress(service)?);
        }
        if method == "POST" && tail.len() == 2 {
            let body = body(request)?;
            match tail[1] {
                "plan" => {
                    exact(&body, &["expected_revision", "document"])?;
                    return ok(manager.egress_plan(service, &body["expected_revision"], &body["document"])?);
                }
                "apply" => {
                    exact(&body, &["expected_revision", "document", "operation_id"])?;
                    return ok(manager.egress_apply(
                        service,
                        &body["expected_revision"],
                        &body["document"],
                        &body["operation_id"],
                    )?);
                }
                "rollback" => {
                    exact(&body, &["expected_revision"])?;
                    return ok(manager.egress_rollback(service, &body["expected_revision"])?);
                }
                _ => {}
            }
        }
    }
    Ok(not_found())
}
