//! Authenticated, body-bounded HTTP API on a local Unix socket.

use std::sync::Arc;

use pc_common::server::Handler;
use pc_common::{ApiError, Request, Response};

use crate::service::AwgManager;

pub const TOKEN_HEADER: &str = "X-Awg-Token";
pub const MAX_BODY: usize = 32_768;

/// The request handler; refuses a token shorter than 32 characters.
pub fn handler(manager: Arc<AwgManager>, token: String) -> Result<Arc<Handler>, String> {
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

fn route(manager: &AwgManager, request: &Request) -> Result<Response, ApiError> {
    let ok = |value| Ok(Response::json(200, &value));
    let method = request.method.as_str();
    match (method, request.path.as_str()) {
        ("GET", "/v1/health") => return ok(manager.health()),
        ("GET", "/v1/instances") => return ok(manager.list_instances()),
        ("GET", "/v1/peers") => return ok(manager.list_peers()),
        ("POST", "/v1/peers") => {
            let (status, payload) = manager.create_peer(&request.json_object()?)?;
            return Ok(Response::json(status, &payload));
        }
        ("GET", "/v1/egress") => return ok(manager.egress_view()),
        ("POST", "/v1/egress/plan") => return ok(manager.egress_plan(&request.json_object()?)?),
        ("POST", "/v1/egress/apply") => return ok(manager.egress_apply(&request.json_object()?)?),
        ("POST", "/v1/egress/rollback") => return ok(manager.egress_rollback(&request.json_object()?)?),
        _ => {}
    }
    // Only the name is percent-decoded, as `unquote(tail[0])` did; the action is compared raw.
    if let Some(rest) = request.path.strip_prefix("/v1/peers/") {
        let tail: Vec<&str> = rest.split('/').collect();
        let username = pc_common::http::percent_decode(tail[0]);
        match (method, tail.as_slice()) {
            ("DELETE", [_]) => {
                manager.delete_peer(&username)?;
                return Ok(Response::empty(204));
            }
            ("POST", [_, action]) if *action == "enable" || *action == "disable" => {
                if !request.json_object()?.is_empty() {
                    return Err(ApiError::invalid_request("invalid request fields"));
                }
                return ok(manager.set_enabled(&username, *action == "enable")?);
            }
            ("POST", [_, "rotate"]) => return ok(manager.rotate(&username, &request.json_object()?)?),
            _ => {}
        }
    }
    Err(ApiError::not_found())
}
