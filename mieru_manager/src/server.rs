//! Authenticated, body-bounded HTTP API on a local Unix socket.
//!
//! The routes, status codes and error bodies are the Python manager's: `401 {"detail":
//! "unauthorized"}`, `404 {"detail": "not found"}`, `422 {"detail": "invalid request"}` for any
//! validation failure, `409 {"detail": "configuration conflict", "code": …}` with a code only
//! for the conflicts a client can act on, `503 {"detail": "manager operation failed"}` when mita
//! failed. Bodies are compact JSON with ASCII escapes, as `json.dumps` wrote them.

use std::sync::Arc;

use pc_common::server::Handler;
use pc_common::{Request, Response};
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::pyjson;
use crate::service::MieruManager;

pub const TOKEN_HEADER: &str = "X-Mieru-Token";
pub const MAX_BODY: usize = 32_768;

fn send(status: u16, value: &Value) -> Response {
    let mut response = Response::json(status, &Value::Null);
    response.body = pyjson::dumps(value, false, None).into_bytes();
    response
}

/// The bounded reason a client can act on, for the conflicts the egress and lanes APIs raise.
fn conflict_code(message: &str) -> Value {
    if message.contains("revision does not match") {
        json!("egress_conflict")
    } else if message.contains("no previous egress") {
        json!("egress_no_previous")
    } else if message.contains("operation id") {
        json!("operation_conflict")
    } else if message.starts_with("lanes_invalid") {
        json!("lanes_invalid")
    } else if message == "lane_slots_exhausted" {
        json!("lane_slots_exhausted")
    } else {
        Value::Null
    }
}

pub fn error_response(error: &Error) -> Response {
    match error {
        Error::EgressInvalid(message) => send(422, &json!({"detail": message, "code": "egress_invalid"})),
        Error::EgressUnreachable(message) => send(409, &json!({"detail": message, "code": "egress_unreachable"})),
        Error::Conflict(message) => {
            send(409, &json!({"detail": "configuration conflict", "code": conflict_code(message)}))
        }
        Error::Validation(_) | Error::LanesInvalid(_) => send(422, &json!({"detail": "invalid request"})),
        Error::Mita(message) => {
            // A transaction that could not restore mita is the one case a person must finish.
            let mut payload = json!({"detail": "manager operation failed"});
            if message.contains("requires recovery") {
                payload["code"] = json!("manual_intervention_required");
            } else if message.contains("readback") {
                payload["code"] = json!("egress_readback_mismatch");
            }
            send(503, &payload)
        }
        Error::Internal(message) => {
            log::warn!("manager request failed: {message}");
            send(500, &json!({"detail": "manager operation failed", "code": "internal_error"}))
        }
    }
}

/// `_body()`: a JSON object of at most 32 KiB; an empty body is `{}`.
fn body(request: &Request) -> Result<Map<String, Value>> {
    let bytes = request.body_bytes().map_err(|_| Error::validation("invalid body"))?;
    if bytes.is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_slice(bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(Error::validation("invalid body")),
    }
}

/// `_exact`: every required field, nothing beyond the optional ones.
fn exact(body: &Map<String, Value>, required: &[&str], optional: &[&str]) -> Result<()> {
    let complete = required.iter().all(|key| body.contains_key(*key));
    let extra = body.keys().any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()));
    if !complete || extra {
        return Err(Error::validation("invalid request fields"));
    }
    Ok(())
}

/// The request handler; refuses a token shorter than 32 characters.
pub fn handler(manager: Arc<MieruManager>, token: String) -> std::result::Result<Arc<Handler>, String> {
    if token.chars().count() < 32 {
        return Err("manager token is too short".into());
    }
    Ok(Arc::new(move |request: &Request| {
        if !matches!(request.method.as_str(), "GET" | "POST" | "PUT" | "DELETE") {
            return send(501, &json!({"detail": "unsupported method"}));
        }
        let supplied = request.header(TOKEN_HEADER).unwrap_or("");
        if supplied.is_empty() || !pc_common::constant_time_eq(supplied.as_bytes(), token.as_bytes()) {
            return send(401, &json!({"detail": "unauthorized"}));
        }
        match route(&manager, request) {
            Ok((status, value)) => send(status, &value),
            Err(error) => error_response(&error),
        }
    }))
}

fn not_found() -> Result<(u16, Value)> {
    Ok((404, json!({"detail": "not found"})))
}

fn field<'a>(body: &'a Map<String, Value>, key: &str) -> &'a Value {
    body.get(key).unwrap_or(&Value::Null)
}

fn route(manager: &MieruManager, request: &Request) -> Result<(u16, Value)> {
    let method = request.method.as_str();
    let path = request.path.as_str();
    let ok = |value: Value| Ok((200, value));
    match (method, path) {
        ("GET", "/v1/health") => return ok(manager.inspect()?),
        ("GET", "/v1/users") => return ok(manager.list_users()?),
        ("GET", "/v1/metrics") => return ok(manager.metrics()?),
        ("GET", "/v1/traffic") => return ok(manager.traffic()?),
        ("GET", "/v1/egress") => return ok(manager.egress()?),
        ("GET", "/v1/lanes") => return ok(manager.lanes()?),
        ("PUT", "/v1/lanes") => return ok(manager.set_lanes(&Value::Object(body(request)?))?),
        ("POST", "/v1/egress/plan") => {
            let body = body(request)?;
            exact(&body, &["expected_revision", "document"], &[])?;
            return ok(manager.egress_plan(&body["expected_revision"], &body["document"])?);
        }
        ("POST", "/v1/egress/apply") => {
            let body = body(request)?;
            exact(&body, &["expected_revision", "document", "operation_id"], &[])?;
            return ok(manager.egress_apply(&body["expected_revision"], &body["document"], &body["operation_id"])?);
        }
        ("POST", "/v1/egress/rollback") => {
            let body = body(request)?;
            exact(&body, &["expected_revision"], &[])?;
            return ok(manager.egress_rollback(&body["expected_revision"])?);
        }
        _ => {}
    }
    if method == "POST" {
        if let Some(action) = path.strip_prefix("/v1/lifecycle/") {
            if !matches!(action, "start" | "stop" | "restart") {
                return not_found();
            }
            exact(&body(request)?, &[], &[])?;
            return ok(manager.lifecycle(action)?);
        }
        if path == "/v1/users" {
            let body = body(request)?;
            exact(
                &body,
                &["username", "quotas", "expected_revision"],
                &["elevated", "allow_private_ip", "allow_loopback_ip", "password", "operation_id"],
            )?;
            let flag = |key: &str| body.get(key).cloned().unwrap_or(Value::Bool(false));
            let created = manager.create_user(
                &body["username"],
                &body["quotas"],
                &body["expected_revision"],
                &flag("elevated"),
                &flag("allow_private_ip"),
                &flag("allow_loopback_ip"),
                body.get("password"),
                body.get("operation_id"),
            )?;
            return Ok((201, created));
        }
    }
    if let Some(tail) = path.strip_prefix("/v1/users/") {
        let tail: Vec<&str> = tail.split('/').collect();
        let username = pc_common::http::percent_decode(tail[0]);
        if method == "DELETE" && tail.len() == 1 {
            let body = body(request)?;
            exact(&body, &["expected_revision"], &[])?;
            return ok(manager.delete_user(&username, field(&body, "expected_revision"))?);
        }
        if method == "POST" && tail.len() == 2 {
            let body = body(request)?;
            match tail[1] {
                "quotas" => {
                    exact(&body, &["quotas", "expected_revision"], &[])?;
                    return ok(manager.set_quotas(&username, &body["quotas"], &body["expected_revision"])?);
                }
                "reset-metrics" => {
                    exact(&body, &[], &[])?;
                    return ok(manager.reset_metric_baseline(&username)?);
                }
                "rotate" => {
                    exact(&body, &["expected_revision"], &["password", "operation_id"])?;
                    return ok(manager.rotate_user(
                        &username,
                        &body["expected_revision"],
                        body.get("password"),
                        body.get("operation_id"),
                    )?);
                }
                operation => {
                    exact(&body, &["expected_revision"], &[])?;
                    match operation {
                        "enable" => return ok(manager.enable_user(&username, &body["expected_revision"])?),
                        "disable" => return ok(manager.disable_user(&username, &body["expected_revision"])?),
                        _ => {}
                    }
                }
            }
        }
    }
    not_found()
}
