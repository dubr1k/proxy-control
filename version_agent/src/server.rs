//! The agent's HTTP API on its Unix socket (`version_agent/server.py`), served by
//! `pc_common::UdsServer`, with the Python contract kept: `{"detail"}` error bodies without a
//! `code`, exact-path routing (a query string is a 404), 413 for a missing or bad
//! `Content-Length` where Python answered it, compact sorted ASCII JSON, `Cache-Control:
//! no-store`. There is no token: access is the socket's mode 0660 and its group.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pc_common::http::{Body, Request, Response};
use pc_common::{ServerOptions, UdsServer};
use serde_json::{json, Value};

use crate::errors::{failure_line, AgentError, UpdateState};
use crate::hostmetrics::{metrics_response, MetricsSampler};
use crate::py;
use crate::service::VersionAgent;

/// `_MAX_BODY`.
pub const MAX_BODY: usize = 16 * 1024;
pub const DEFAULT_SOCKET: &str = "/run/proxy-control/version-agent.sock";
pub const DEFAULT_SOCKET_GID: &str = "10001";
/// `AUTO_CHECK_INTERVAL`: six hours.
pub const AUTO_CHECK_INTERVAL: i64 = 6 * 3600;
/// `AUTO_CHECK_MIN_DELAY`: never sooner than a minute after start.
pub const AUTO_CHECK_MIN_DELAY: f64 = 60.0;
/// `AUTO_CHECK_RETRY`: after a failed automatic check.
pub const AUTO_CHECK_RETRY: f64 = 900.0;

/// What the routes ask of the agent (tests serve fakes through it).
pub trait Api: Send + Sync {
    fn list_versions(&self) -> Result<Value, AgentError>;
    fn update(&self, component: &str, version: &str, expected: Option<&str>) -> Result<Value, AgentError>;
    fn check_upstream(&self) -> Result<Value, AgentError>;
    fn rebuild_managers(&self) -> Result<Value, AgentError>;
    fn ack_managers(&self, names: &Value) -> Result<Value, AgentError>;
}

impl Api for Arc<VersionAgent> {
    fn list_versions(&self) -> Result<Value, AgentError> {
        VersionAgent::list_versions(self, true)
    }

    fn update(&self, component: &str, version: &str, expected: Option<&str>) -> Result<Value, AgentError> {
        VersionAgent::update(self, component, version, expected)
    }

    fn check_upstream(&self) -> Result<Value, AgentError> {
        VersionAgent::check_upstream(self, false)
    }

    fn rebuild_managers(&self) -> Result<Value, AgentError> {
        VersionAgent::rebuild_managers(self)
    }

    fn ack_managers(&self, names: &Value) -> Result<Value, AgentError> {
        VersionAgent::ack_managers(self, names)
    }
}

/// Accepted requests still running when the listener stops. Closing admission before waiting
/// closes the race with a connection thread that was accepted but has not entered its handler.
#[derive(Default)]
pub struct RequestActivity {
    state: std::sync::Mutex<(bool, usize)>,
    idle: std::sync::Condvar,
}

impl RequestActivity {
    fn begin(self: &Arc<Self>) -> Option<RequestGuard> {
        let mut state = self.state.lock().ok()?;
        if state.0 {
            return None;
        }
        state.1 += 1;
        Some(RequestGuard(self.clone()))
    }

    /// Refuse requests that have not entered their handler, then drain every accepted request.
    /// The caller invokes this after `UdsServer::serve` stops admission and before joining
    /// background update workers.
    pub fn stop_and_wait(&self) {
        let Ok(mut state) = self.state.lock() else { return };
        state.0 = true;
        while state.1 != 0 {
            let Ok(next) = self.idle.wait(state) else { return };
            state = next;
        }
    }
}

struct RequestGuard(Arc<RequestActivity>);

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.1 -= 1;
            if state.1 == 0 {
                self.0.idle.notify_all();
            }
        }
    }
}

/// The routes and what they read.
#[derive(Clone)]
pub struct Routes {
    pub api: Option<Arc<dyn Api>>,
    /// `host_metrics()` for `GET /v1/host`.
    pub host: Arc<dyn Fn() -> Value + Send + Sync>,
    pub metrics: Option<Arc<MetricsSampler>>,
    pub activity: Arc<RequestActivity>,
}

/// A JSON answer the way `Handler._send` wrote it.
pub fn reply(status: u16, value: &Value) -> Response {
    let mut response = Response::empty(status);
    response.body = py::body(value);
    response
}

fn detail(status: u16, message: &str) -> Response {
    reply(status, &json!({"detail": message}))
}

fn failed(status: u16, message: &str, state: UpdateState) -> Response {
    reply(status, &json!({"detail": message, "state": state.as_str()}))
}

/// What Python let escape as a traceback (no answer at all); here a 500 with the message.
fn internal(error: &AgentError) -> Response {
    detail(500, error.message())
}

/// `int(self.headers.get("Content-Length", default))`, `None` on `ValueError`.
fn content_length(request: &Request, default: i64) -> Option<i64> {
    match request.header("content-length") {
        None => Some(default),
        Some(value) => py::int(value),
    }
}

/// The body pc_common read, when its length is the one Python would have read.
fn body_of(request: &Request, length: i64) -> Option<&[u8]> {
    match &request.body {
        Body::Read(bytes) if bytes.len() as i64 == length => Some(bytes),
        _ => None,
    }
}

impl Routes {
    pub fn handle(&self, request: &Request) -> Response {
        let Some(_request) = self.activity.begin() else {
            return detail(503, "version agent is stopping");
        };
        match request.method.as_str() {
            "GET" => self.get(request),
            "POST" => self.post(request),
            // BaseHTTPRequestHandler answered other methods with its 501 page.
            _ => detail(501, "unsupported method"),
        }
    }

    fn get(&self, request: &Request) -> Response {
        match request.target.as_str() {
            // `implementation` tells the 4.0 installer that the agent was migrated (§9.4).
            "/v1/health" => reply(200, &json!({"status": "ok", "implementation": "rust"})),
            // Read-only telemetry: no input, no command.
            "/v1/host" => reply(200, &(self.host)()),
            "/v1/metrics" => {
                let (status, body) = metrics_response(self.metrics.as_deref());
                reply(status, &body)
            }
            "/v1/versions" => match self.api.as_ref().map(|api| api.list_versions()) {
                Some(Ok(listed)) => reply(200, &listed),
                Some(Err(error @ AgentError::Internal(_))) => internal(&error),
                Some(Err(_)) => detail(503, "version catalog unavailable"),
                None => detail(500, "version agent is not configured"),
            },
            _ => detail(404, "not found"),
        }
    }

    fn post(&self, request: &Request) -> Response {
        let Some(api) = self.api.as_ref() else {
            return match request.target.as_str() {
                "/v1/upstream/check" | "/v1/panel/managers/rebuild" | "/v1/panel/managers/ack" | "/v1/update" => {
                    detail(500, "version agent is not configured")
                }
                _ => detail(404, "not found"),
            };
        };
        match request.target.as_str() {
            "/v1/upstream/check" => self.check_upstream(api.as_ref(), request),
            "/v1/panel/managers/rebuild" => self.rebuild(api.as_ref(), request),
            "/v1/panel/managers/ack" => self.ack(api.as_ref(), request),
            "/v1/update" => self.update(api.as_ref(), request),
            _ => detail(404, "not found"),
        }
    }

    /// The check takes no input: a body is drained (bounded) and ignored; an unreadable
    /// length counts as none.
    fn ignored_body_too_large(request: &Request) -> bool {
        let length = content_length(request, 0).unwrap_or(0);
        !(0..=MAX_BODY as i64).contains(&length)
    }

    fn check_upstream(&self, api: &dyn Api, request: &Request) -> Response {
        if Self::ignored_body_too_large(request) {
            return detail(413, "request body too large");
        }
        match api.check_upstream() {
            Ok(listed) => reply(200, &listed),
            Err(error) => match error.update_state() {
                Some(state) => failed(502, error.message(), state),
                None if matches!(error, AgentError::Catalog(_)) => {
                    failed(502, error.message(), UpdateState::UpdateFailed)
                }
                None => internal(&error),
            },
        }
    }

    fn rebuild(&self, api: &dyn Api, request: &Request) -> Response {
        if Self::ignored_body_too_large(request) {
            return detail(413, "request body too large");
        }
        match api.rebuild_managers() {
            Ok(state) => reply(200, &state),
            Err(AgentError::Conflict(message)) => detail(409, &message),
            Err(AgentError::Update(error)) => failed(502, &error.message, error.state),
            Err(error) => internal(&error),
        }
    }

    /// `_read_json`: the body as JSON (an empty body is `null`), or the answer to send.
    fn read_json(request: &Request) -> Result<Value, Response> {
        let too_large = || detail(413, "request body too large");
        let length = content_length(request, 0).unwrap_or(-1);
        if !(0..=MAX_BODY as i64).contains(&length) {
            return Err(too_large());
        }
        let body = body_of(request, length).ok_or_else(too_large)?;
        if body.is_empty() {
            return Ok(Value::Null);
        }
        pc_host::json::loads(body).map_err(|_| detail(422, "invalid JSON"))
    }

    fn ack(&self, api: &dyn Api, request: &Request) -> Response {
        let body = match Self::read_json(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let Some(names) = body.as_object().filter(|map| map.len() == 1).and_then(|map| map.get("names")) else {
            return detail(422, "invalid acknowledge request");
        };
        match api.ack_managers(names) {
            Ok(state) => reply(200, &state),
            Err(AgentError::Invalid(message)) => detail(422, &message),
            Err(error) => internal(&error),
        }
    }

    fn update(&self, api: &dyn Api, request: &Request) -> Response {
        let length = content_length(request, -1).unwrap_or(-1);
        if !(0..=MAX_BODY as i64).contains(&length) {
            return detail(413, "request body too large");
        }
        let Some(body) = body_of(request, length) else {
            return detail(413, "request body too large");
        };
        let Ok(body) = pc_host::json::loads(body) else {
            return detail(422, "invalid JSON");
        };
        let invalid = || detail(422, "invalid update request");
        let Some(body) = body.as_object() else { return invalid() };
        if body.len() != 3 || !["component", "version", "expected_current"].iter().all(|key| body.contains_key(*key)) {
            return invalid();
        }
        let (Some(component), Some(version)) = (body["component"].as_str(), body["version"].as_str()) else {
            return invalid();
        };
        let expected = match &body["expected_current"] {
            Value::Null => None,
            Value::String(text) => Some(text.as_str()),
            _ => return invalid(),
        };
        match api.update(component, version, expected) {
            Ok(result) => reply(200, &result),
            Err(AgentError::Conflict(message)) => detail(409, &message),
            Err(AgentError::Catalog(error)) => detail(422, &error.0),
            Err(AgentError::Update(error)) => {
                log::error!(target: "version_agent", "{}", failure_line(component, version, &error));
                let message = match error.state {
                    UpdateState::RollbackFailed => "update failed and the previous generation could not be verified",
                    UpdateState::RolledBack => "update failed and the previous generation was restored",
                    UpdateState::UpdateFailed => "update failed",
                };
                failed(502, message, error.state)
            }
            Err(error) => internal(&error),
        }
    }
}

/// The socket options: mode 0660, owner root (when `uid` is given) and the panel's group.
pub fn server_options(socket: impl Into<PathBuf>, uid: Option<u32>, gid: u32) -> ServerOptions {
    let mut options = ServerOptions::new(socket);
    options.mode = 0o660;
    options.uid = uid;
    options.gid = Some(gid);
    options.max_body = MAX_BODY;
    options
}

/// Binds the socket and serves the routes until the handle stops it.
pub fn serve(server: UdsServer, routes: Routes) {
    server.serve(Arc::new(move |request: &Request| routes.handle(request)));
}

// --- the automatic upstream check ------------------------------------------------------------

/// What the automatic check needs of the agent.
pub trait Checked: Send + Sync {
    fn upstream_checked_at(&self) -> Option<i64>;
    fn check_upstream(&self) -> Result<Value, AgentError>;
}

impl Checked for Arc<VersionAgent> {
    fn upstream_checked_at(&self) -> Option<i64> {
        // An unreadable state is "never checked" (Python's thread died on it).
        VersionAgent::upstream_checked_at(self).ok().flatten()
    }

    fn check_upstream(&self) -> Result<Value, AgentError> {
        VersionAgent::check_upstream(self, false)
    }
}

/// `upstream_due_in`: seconds until the next automatic check.
pub fn upstream_due_in(agent: &dyn Checked, interval: i64, now: f64) -> f64 {
    match agent.upstream_checked_at() {
        None => AUTO_CHECK_MIN_DELAY,
        Some(last) => AUTO_CHECK_MIN_DELAY.max((last + interval) as f64 - now),
    }
}

/// `auto_check_upstream`: poll upstream on a schedule so a node's versions reach the central
/// fresh. `wait(seconds)` returns true when the agent stops.
pub fn auto_check_upstream(agent: &dyn Checked, interval: i64, wait: &dyn Fn(f64) -> bool, clock: &dyn Fn() -> f64) {
    while !wait(upstream_due_in(agent, interval, clock())) {
        if let Err(error) = agent.check_upstream() {
            log::warn!(target: "version_agent", "automatic upstream check failed: {}", error.message());
            if wait(AUTO_CHECK_RETRY) {
                return;
            }
        }
    }
}

/// A stop flag the background threads wait on.
#[derive(Default)]
pub struct StopSignal {
    stopped: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}

impl StopSignal {
    pub fn stop(&self) {
        if let Ok(mut stopped) = self.stopped.lock() {
            *stopped = true;
            self.wake.notify_all();
        }
    }

    /// `Event.wait(seconds)`: true when stopped.
    pub fn wait(&self, seconds: f64) -> bool {
        let Ok(guard) = self.stopped.lock() else { return true };
        let timeout = Duration::from_secs_f64(seconds.clamp(0.0, 1e9));
        match self.wake.wait_timeout_while(guard, timeout, |stopped| !*stopped) {
            Ok((stopped, _)) => *stopped,
            Err(_) => true,
        }
    }
}

#[cfg(test)]
mod tests;
