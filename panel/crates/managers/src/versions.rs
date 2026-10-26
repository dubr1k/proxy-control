//! `panel/versions.py`: the client of the host's version-agent. No token: the socket's file
//! permissions are the access control.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use crate::error::VersionAgentError;
use crate::uds::{call, json_body};

/// `GET /v1/host` and `GET /v1/metrics`: a slow or wedged agent costs the dashboard a card, not
/// the page.
pub const HOST_TIMEOUT: Duration = Duration::from_secs(3);
/// `POST /v1/upstream/check`: several upstream sources in a row.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(90);
/// `POST /v1/panel/managers/rebuild`: the agent starts the rebuild and answers at once.
pub const REBUILD_TIMEOUT: Duration = Duration::from_secs(30);
/// `POST /v1/update`: a `naive` update rebuilds Caddy on the host (up to 15 min).
pub const UPDATE_TIMEOUT: Duration = Duration::from_secs(1200);

/// `VersionClient` (20 s by default).
#[derive(Debug, Clone)]
pub struct VersionClient {
    socket: PathBuf,
    timeout: Duration,
}

type Result<T> = std::result::Result<T, VersionAgentError>;

impl VersionClient {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self { socket: socket_path.into(), timeout: Self::DEFAULT_TIMEOUT }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// `_request`: transport failure → "version agent unavailable" (502); ≥ 400 → "version agent
    /// rejected request" with 409/422 kept, else 502; a body that is not JSON (a 204 included) →
    /// "invalid version agent response" (502).
    pub async fn request(
        &self,
        method: &'static str,
        path: &str,
        payload: Option<&Value>,
        timeout: Option<Duration>,
    ) -> Result<Value> {
        let reply =
            call(&self.socket, method, path, Vec::new(), payload.map(json_body), timeout.unwrap_or(self.timeout))
                .await
                .map_err(|_| VersionAgentError::new("version agent unavailable", 502))?;
        if reply.status >= 400 {
            let status = if matches!(reply.status, 409 | 422) { reply.status } else { 502 };
            return Err(VersionAgentError::new("version agent rejected request", status));
        }
        serde_json::from_slice(&reply.body).map_err(|_| VersionAgentError::new("invalid version agent response", 502))
    }

    pub async fn list_versions(&self) -> Result<Value> {
        self.request("GET", "/v1/versions", None, None).await
    }

    pub async fn host(&self) -> Result<Value> {
        self.request("GET", "/v1/host", None, Some(HOST_TIMEOUT)).await
    }

    /// The agent's latest meter sample (host, protocol counters); `None` when it cannot be had.
    pub async fn metrics(&self) -> Option<Value> {
        self.request("GET", "/v1/metrics", None, Some(HOST_TIMEOUT)).await.ok()
    }

    pub async fn check(&self) -> Result<Value> {
        self.request("POST", "/v1/upstream/check", None, Some(CHECK_TIMEOUT)).await
    }

    pub async fn rebuild_managers(&self) -> Result<Value> {
        self.request("POST", "/v1/panel/managers/rebuild", Some(&json!({})), Some(REBUILD_TIMEOUT)).await
    }

    pub async fn update(&self, component: &str, version: &str, expected_current: Option<&str>) -> Result<Value> {
        let payload = json!({"component": component, "version": version, "expected_current": expected_current});
        self.request("POST", "/v1/update", Some(&payload), Some(UPDATE_TIMEOUT)).await
    }
}
