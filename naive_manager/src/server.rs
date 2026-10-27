//! The authenticated API on the Unix socket, with the Python handler's routes, status codes
//! and bodies, and the quota enforcer that runs beside it.

use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use pc_common::http::{percent_decode, Body};
use pc_common::server::Handler;
use pc_common::{Request, Response};
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::service::NaiveManager;

pub const TOKEN_HEADER: &str = "X-Naive-Token";
pub const MAX_BODY: usize = 8192;

/// A JSON body as `json.dumps(payload, separators=(",", ":"))` wrote it.
pub fn json_response(status: u16, payload: &Value) -> Response {
    let mut response = Response::empty(status);
    response.body = pc_common::json::dumps(payload, &crate::pyjson::COMPACT).into_bytes();
    response
}

/// `urlsplit(self.path).path` after `http.server` reduced a leading `//` to one slash.
pub fn request_path(target: &str) -> String {
    let target =
        if target.starts_with("//") { format!("/{}", target.trim_start_matches('/')) } else { target.to_string() };
    let target: String = target.chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let target = target.trim_start_matches(|c: char| c <= ' ');
    let mut rest = target;
    if let Some(colon) = target.find(':') {
        let scheme = &target[..colon];
        if colon > 0
            && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            rest = &target[colon + 1..];
        }
    }
    if let Some(after) = rest.strip_prefix("//") {
        rest = &after[after.find(['/', '?', '#']).unwrap_or(after.len())..];
    }
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    rest[..end].to_string()
}

/// `_body()`: at most 8192 bytes of JSON object; an empty body is `{}`.
fn body(request: &Request) -> Result<Map<String, Value>> {
    let bytes = match &request.body {
        Body::Read(bytes) => bytes,
        Body::Invalid => return Err(Error::value("invalid request body")),
    };
    if bytes.is_empty() {
        return Ok(Map::new());
    }
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(Error::value("object expected")),
        Err(_) => Err(Error::value("invalid JSON")),
    }
}

/// Absent means "manager decides"; a wrong type is a client bug, not a default.
fn optional_text<'a>(body: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(Error::value(format!("{key} must be a string"))),
    }
}

fn error_response(err: Error) -> Response {
    match err {
        Error::NotFound(_) => json_response(404, &json!({"detail": "not found"})),
        Error::EgressInvalid(message) => json_response(422, &json!({"detail": message, "code": "egress_invalid"})),
        Error::EgressUnreachable(message) => {
            json_response(409, &json!({"detail": message, "code": "egress_unreachable"}))
        }
        Error::Recovery(message) => {
            json_response(503, &json!({"detail": message, "code": "manual_intervention_required"}))
        }
        Error::Conflict { code, .. } => {
            let status = if code == "egress_readback_mismatch" { 502 } else { 409 };
            json_response(status, &json!({"detail": "configuration conflict", "code": code}))
        }
        Error::Value(_) | Error::LanesInvalid(_) => json_response(422, &json!({"detail": "invalid request"})),
        other => {
            log::warn!("manager operation failed: {other}");
            json_response(500, &json!({"detail": "manager operation failed"}))
        }
    }
}

/// The request handler. The token is compared in constant time; `main` refuses a short one.
pub fn handler(manager: Arc<NaiveManager>, token: String) -> Arc<Handler> {
    Arc::new(move |request: &Request| {
        if !matches!(request.method.as_str(), "GET" | "POST" | "PUT" | "DELETE") {
            return json_response(501, &json!({"detail": format!("Unsupported method ('{}')", request.method)}));
        }
        dispatch(&manager, &token, request).unwrap_or_else(error_response)
    })
}

fn dispatch(manager: &NaiveManager, token: &str, request: &Request) -> Result<Response> {
    let supplied = request.header(TOKEN_HEADER).unwrap_or("");
    if supplied.is_empty() || !crate::pyutil::compare_digest(supplied, token)? {
        return Ok(json_response(401, &json!({"detail": "unauthorized"})));
    }
    let ok = |status: u16, value: Value| Ok(json_response(status, &value));
    let method = request.method.as_str();
    let path = request_path(&request.target);
    match (method, path.as_str()) {
        ("GET", "/v1/health") => {
            let health = manager.health();
            let status = if health["ready"] == Value::Bool(true) { 200 } else { 503 };
            return ok(status, health);
        }
        ("GET", "/v1/users") => return ok(200, manager.list_users()?),
        ("GET", "/v1/traffic") => return ok(200, manager.traffic_report()?),
        ("GET", "/v1/egress") => return ok(200, manager.egress()?),
        ("GET", "/v1/lanes") => return ok(200, manager.lanes()?),
        ("PUT", "/v1/lanes") => return ok(200, manager.set_lanes(&Value::Object(body(request)?))?),
        ("POST", "/v1/egress/plan" | "/v1/egress/apply" | "/v1/egress/rollback") => {
            let body = body(request)?;
            let Some(revision) = body.get("expected_revision").and_then(Value::as_str) else {
                return Err(Error::value("expected_revision is required"));
            };
            let document = body.get("document").unwrap_or(&Value::Null);
            if path.ends_with("/plan") {
                return ok(200, manager.egress_plan(revision, document)?);
            }
            if path.ends_with("/apply") {
                let operation_id = optional_text(&body, "operation_id")?.unwrap_or("");
                return ok(200, manager.egress_apply(revision, document, operation_id)?);
            }
            return ok(200, manager.egress_rollback(revision)?);
        }
        ("POST", "/v1/users") => {
            let body = body(request)?;
            let username = body.get("username").cloned().unwrap_or_else(|| Value::from(""));
            let quota = body.get("quota_bytes").cloned().unwrap_or(Value::Null);
            let password = optional_text(&body, "password")?;
            let operation_id = optional_text(&body, "operation_id")?;
            return ok(201, manager.create(&username, &quota, password, operation_id)?);
        }
        _ => {}
    }
    if let Some(rest) = path.strip_prefix("/v1/users/") {
        let tail: Vec<&str> = rest.split('/').collect();
        let username = percent_decode(tail[0]);
        if method == "DELETE" && tail.len() == 1 {
            manager.delete(&username)?;
            return Ok(Response::empty(204));
        }
        if method == "POST" && tail.len() == 2 {
            let body = body(request)?;
            match tail[1] {
                "access" => return ok(200, manager.reveal(&username)?),
                "rotate" => {
                    let password = optional_text(&body, "password")?;
                    let operation_id = optional_text(&body, "operation_id")?;
                    return ok(200, manager.rotate(&username, password, operation_id)?);
                }
                "enable" => return ok(200, manager.set_enabled(&username, true)?),
                "disable" => return ok(200, manager.set_enabled(&username, false)?),
                "quota" => {
                    let Some(quota) = body.get("quota_bytes") else {
                        return Err(Error::value("quota_bytes is required"));
                    };
                    return ok(200, manager.set_quota(&username, quota)?);
                }
                _ => {}
            }
        }
        if method == "POST" && tail.len() == 3 && tail[1] == "traffic" && tail[2] == "reset" {
            body(request)?;
            return ok(200, manager.reset_traffic(&username)?);
        }
    }
    ok(404, json!({"detail": "not found"}))
}

pub type Enforce = Arc<dyn Fn() -> Result<Vec<String>> + Send + Sync>;

/// Disables quota-exhausted users even when nobody has the panel open, on its own thread so
/// the control socket stays answerable while a pass hashes the log or reloads Caddy.
pub struct QuotaEnforcer {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn seconds(value: f64) -> Option<Duration> {
    if value.is_nan() || value <= 0.0 {
        Some(Duration::ZERO)
    } else {
        Duration::try_from_secs_f64(value).ok()
    }
}

impl QuotaEnforcer {
    pub fn start(enforce: Enforce, interval: f64, max_backoff: f64) -> std::io::Result<Self> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let flag = stop.clone();
        let thread = std::thread::Builder::new().name("naive-quota-enforcer".into()).spawn(move || {
            let mut delay = interval;
            loop {
                let (lock, wake) = &*flag;
                let stopped = lock.lock().unwrap_or_else(PoisonError::into_inner);
                let stopped = match seconds(delay) {
                    Some(timeout) => {
                        wake.wait_timeout_while(stopped, timeout, |stopped| !*stopped)
                            .unwrap_or_else(PoisonError::into_inner)
                            .0
                    }
                    None => wake.wait_while(stopped, |stopped| !*stopped).unwrap_or_else(PoisonError::into_inner),
                };
                if *stopped {
                    return;
                }
                drop(stopped);
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| enforce())) {
                    Ok(Ok(mut disabled)) => {
                        if !disabled.is_empty() {
                            disabled.sort();
                            log::info!("disabled after quota exhaustion: {}", disabled.join(", "));
                        }
                        delay = interval;
                    }
                    failed => {
                        delay = (delay * 2.0).min(max_backoff);
                        let reason = match failed {
                            Ok(Err(err)) => err.to_string(),
                            _ => "panicked".into(),
                        };
                        log::warn!("quota enforcement failed; next attempt in {delay:.0}s ({reason})");
                    }
                }
            }
        })?;
        Ok(Self { stop, thread: Some(thread) })
    }

    pub fn stop(&self) {
        (self.stopper())();
    }

    /// Stops the enforcer from another thread (the signal handler).
    pub fn stopper(&self) -> impl Fn() + Send + 'static {
        let stop = self.stop.clone();
        move || {
            let (lock, wake) = &*stop;
            *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
            wake.notify_all();
        }
    }

    pub fn join(mut self, timeout: Duration) -> bool {
        let Some(thread) = self.thread.take() else { return true };
        let deadline = std::time::Instant::now() + timeout;
        while !thread.is_finished() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = thread.join();
        true
    }
}

impl Drop for QuotaEnforcer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_paths_follow_http_server_and_urlsplit() {
        assert_eq!(request_path("/v1/users?x=1"), "/v1/users");
        assert_eq!(request_path("/v1/health#frag"), "/v1/health");
        assert_eq!(request_path("http://manager/v1/health"), "/v1/health");
        assert_eq!(request_path("//foo/v1/health"), "/foo/v1/health");
        assert_eq!(request_path("/v1/users/a%2Fb/access"), "/v1/users/a%2Fb/access");
    }

    #[test]
    fn quota_enforcer_survives_failures_and_backs_off_before_retrying() {
        let attempts = Arc::new(Mutex::new(0));
        let released = Arc::new((Mutex::new(false), Condvar::new()));
        let (counter, signal) = (attempts.clone(), released.clone());
        let enforcer = QuotaEnforcer::start(
            Arc::new(move || {
                let mut count = counter.lock().unwrap();
                *count += 1;
                if *count == 1 {
                    return Err(Error::runtime("apply failed"));
                }
                *signal.0.lock().unwrap() = true;
                signal.1.notify_all();
                Ok(vec!["old-user".to_string()])
            }),
            0.01,
            0.05,
        )
        .unwrap();
        let done = released.0.lock().unwrap();
        let (done, _) = released.1.wait_timeout_while(done, Duration::from_secs(5), |done| !*done).unwrap();
        assert!(*done);
        drop(done);
        enforcer.stop();
        assert!(enforcer.join(Duration::from_secs(5)));
        assert!(*attempts.lock().unwrap() >= 2);
    }
}
