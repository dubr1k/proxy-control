//! Authenticated, body-bounded HTTP API on a local Unix socket.

use std::sync::Arc;

use pc_common::server::Handler;
use pc_common::{ApiError, Request, Response};

use crate::service::TrusttunnelManager;

pub const TOKEN_HEADER: &str = "X-Trusttunnel-Token";
pub const MAX_BODY: usize = 32_768;

/// The request handler; refuses a token shorter than 32 characters.
pub fn handler(manager: Arc<TrusttunnelManager>, token: String) -> Result<Arc<Handler>, String> {
    if token.len() < 32 {
        return Err("manager token is too short".into());
    }
    Ok(Arc::new(move |request: &Request| {
        if let Err(denied) = pc_common::check_token(request, TOKEN_HEADER, &token) {
            return denied;
        }
        route(&manager, request).unwrap_or_else(ApiError::into_response)
    }))
}

fn empty_body(request: &Request) -> Result<(), ApiError> {
    if !request.json_object()?.is_empty() {
        return Err(ApiError::invalid_request("invalid request fields"));
    }
    Ok(())
}

fn route(manager: &TrusttunnelManager, request: &Request) -> Result<Response, ApiError> {
    let ok = |value| Ok(Response::json(200, &value));
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/v1/health") => return ok(manager.health()),
        ("GET", "/v1/endpoint") => return ok(manager.endpoint()),
        ("GET", "/v1/clients") => return ok(manager.list_clients()),
        ("POST", "/v1/clients") => return ok(manager.create_client(&request.json_object()?)?),
        ("GET", "/v1/egress") => return ok(manager.egress()),
        ("POST", "/v1/egress/plan") => return ok(manager.egress_plan(&request.json_object()?)?),
        ("POST", "/v1/egress/apply") => return ok(manager.egress_apply(&request.json_object()?)?),
        ("POST", "/v1/egress/rollback") => {
            empty_body(request)?;
            return ok(manager.egress_rollback()?);
        }
        _ => {}
    }
    if let Some(tail) = request.segments_after("/v1/clients/") {
        let username = tail[0].as_str();
        match (request.method.as_str(), &tail[1..]) {
            ("DELETE", []) => {
                manager.delete_client(username)?;
                return Ok(Response::empty(204));
            }
            ("POST", [action]) if action == "enable" || action == "disable" => {
                empty_body(request)?;
                return ok(manager.set_enabled(username, action == "enable")?);
            }
            ("POST", [action]) if action == "rotate" => return ok(manager.rotate(username, &request.json_object()?)?),
            _ => {}
        }
    }
    Err(ApiError::not_found())
}
