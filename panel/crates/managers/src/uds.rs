//! One HTTP/1.1 request over a Unix socket, the way the Python clients make it with a fresh
//! `httpx.AsyncClient` per call: `pc_common::client::request` on the blocking pool, the body as
//! httpx's `json=` writes it (compact, raw UTF-8), the per-call timeout applied to every read and
//! write, and the common answer handling of the five managers (`naive.py:44-64` and its twins).

use std::path::{Path, PathBuf};
use std::time::Duration;

use panel_core::pyjson;
use pc_common::client::ClientResponse;
use serde_json::Value;

use crate::error::{Manager, ManagerError};
use crate::pyvalue::httpx_target;

/// The body httpx 0.28 sends for `json=payload`: `json.dumps(payload, ensure_ascii=False,
/// separators=(",", ":"), allow_nan=False)` as UTF-8.
pub(crate) fn json_body(payload: &Value) -> Vec<u8> {
    pyjson::compact_utf8(payload).into_bytes()
}

/// Sends one request and reads the whole answer. Any failure (no socket, refused, timed out,
/// malformed answer, a panicked worker) is an `Err`: the Python clients treat every
/// `httpx.HTTPError` alike.
pub(crate) async fn call(
    socket: &Path,
    method: &'static str,
    target: &str,
    headers: Vec<(&'static str, String)>,
    body: Option<Vec<u8>>,
    timeout: Duration,
) -> std::io::Result<ClientResponse> {
    let socket = socket.to_path_buf();
    let target = httpx_target(target);
    tokio::task::spawn_blocking(move || {
        let headers: Vec<(&str, &str)> = headers.iter().map(|(name, value)| (*name, value.as_str())).collect();
        pc_common::client::request(&socket, method, &target, &headers, body.as_deref(), timeout)
    })
    .await
    .map_err(std::io::Error::other)?
}

/// The shared core of the five manager clients: socket, token, default timeout.
#[derive(Clone)]
pub struct ManagerClient {
    manager: Manager,
    socket: PathBuf,
    token: String,
    timeout: Duration,
}

impl std::fmt::Debug for ManagerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagerClient")
            .field("manager", &self.manager)
            .field("socket", &self.socket)
            .field("token", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl ManagerClient {
    pub fn new(manager: Manager, socket: impl Into<PathBuf>, token: impl Into<String>, timeout: Duration) -> Self {
        Self { manager, socket: socket.into(), token: token.into(), timeout }
    }

    pub fn manager(&self) -> Manager {
        self.manager
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(crate) fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// `_request(method, path, payload)`: the decoded JSON answer, `Value::Null` for a 204 (and
    /// for a JSON `null`), or the manager's error.
    pub async fn request(
        &self,
        method: &'static str,
        path: &str,
        payload: Option<&Value>,
        timeout: Option<Duration>,
    ) -> Result<Value, ManagerError> {
        let manager = self.manager;
        let headers = vec![(manager.token_header(), self.token.clone())];
        let reply = call(&self.socket, method, path, headers, payload.map(json_body), timeout.unwrap_or(self.timeout))
            .await
            .map_err(|_| ManagerError::plain(manager, manager.unavailable()))?;
        if reply.status >= 400 {
            let status = if manager.passes_status(reply.status) { reply.status } else { 502 };
            let code = serde_json::from_slice::<Value>(&reply.body)
                .ok()
                .and_then(|payload| payload.get("code").and_then(|code| manager.reason(code)));
            return Err(ManagerError::new(manager, manager.rejected(), status, code.as_deref()));
        }
        if reply.status == 204 && manager.no_content_is_none() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&reply.body).map_err(|_| ManagerError::plain(manager, manager.invalid()))
    }
}

/// `urllib.parse.quote(segment, safe='')`.
pub(crate) fn segment(text: &str) -> String {
    panel_core::pytext::quote(text, "")
}

/// `urllib.parse.quote(segment)` (`safe='/'`).
pub(crate) fn segment_slash(text: &str) -> String {
    panel_core::pytext::quote_path(text)
}

macro_rules! client_wrapper {
    ($(#[$doc:meta])* $name:ident, $manager:expr, $timeout_ms:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone)]
        pub struct $name {
            inner: $crate::uds::ManagerClient,
        }

        impl $name {
            /// The Python default timeout of this client.
            pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis($timeout_ms);

            pub fn new(socket_path: impl Into<std::path::PathBuf>, token: impl Into<String>) -> Self {
                Self { inner: $crate::uds::ManagerClient::new($manager, socket_path, token, Self::DEFAULT_TIMEOUT) }
            }

            /// `timeout=` of the Python constructor.
            pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
                self.inner.set_timeout(timeout);
                self
            }

            /// The transport shared by the methods (`_request`).
            pub fn raw(&self) -> &$crate::uds::ManagerClient {
                &self.inner
            }

            async fn call(
                &self,
                method: &'static str,
                path: &str,
                payload: Option<serde_json::Value>,
            ) -> std::result::Result<serde_json::Value, $crate::error::ManagerError> {
                self.inner.request(method, path, payload.as_ref(), None).await
            }
        }
    };
}

pub(crate) use client_wrapper;
