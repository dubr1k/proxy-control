//! `panel/telemt.py` (without the in-memory twin): the client of Telemt's own HTTP API.
//!
//! Telemt has no operation id, so a request whose reply was lost is not retryable: the client
//! tells a connection that was never made ([`TelemtError`], safe to retry) from one whose reply
//! never came ([`TelemtError::indeterminate`]); the caller then reads the user back
//! ([`TelemtClient::current_access`]) — the live link is the credential.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

pub use reqwest::Method;
use serde_json::{json, Value};

use crate::error::TelemtError;
use crate::pyvalue::{httpx_target, parse_qs_first, truthy};
use crate::uds::json_body;

/// Telemt's API reports the bare secret; the Fake-TLS link prefixes it with `ee`.
pub const FAKE_TLS_PREFIX: &str = "ee";

/// `api_secret(link_secret)`: the link form without the Fake-TLS prefix.
pub fn api_secret(link_secret: &str) -> &str {
    link_secret.strip_prefix(FAKE_TLS_PREFIX).unwrap_or(link_secret)
}

/// The current link of a Telemt user, the secret inside it and the endpoint it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemtAccess {
    pub link: String,
    pub secret: Option<String>,
    pub server: Option<String>,
    pub port: Option<u16>,
}

impl TelemtAccess {
    /// The Python dict `{"link", "secret", "server", "port"}`.
    pub fn to_value(&self) -> Value {
        json!({"link": self.link, "secret": self.secret, "server": self.server, "port": self.port})
    }
}

/// `access_from_user(row)`: Telemt owns the public host and port, so the only place to learn them
/// is the first `links.tls` link of the user row.
pub fn access_from_user(row: &Value) -> Option<TelemtAccess> {
    let row = row.as_object()?;
    let link = row
        .get("links")
        .and_then(Value::as_object)
        .and_then(|links| links.get("tls"))
        .and_then(Value::as_array)
        .and_then(|candidates| candidates.iter().find_map(Value::as_str))
        .filter(|link| !link.is_empty())?;
    // Python raises ValueError on a link urlsplit refuses (a 500); no access here.
    let query = panel_core::pytext::urlsplit(link).ok()?.query;
    let port = parse_qs_first(&query, "port").unwrap_or_default();
    Some(TelemtAccess {
        link: link.to_string(),
        secret: parse_qs_first(&query, "secret"),
        server: parse_qs_first(&query, "server").filter(|server| !server.is_empty()),
        port: port_number(&port),
    })
}

/// `int(port) if port.isdigit() and 1 <= int(port) <= 65535 else None` (Unicode decimal digits
/// count, like `str.isdigit` and `int`).
fn port_number(text: &str) -> Option<u16> {
    if text.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for ch in text.chars() {
        value = value.saturating_mul(10).saturating_add(panel_core::pytext::decimal(ch)?);
    }
    u16::try_from(value).ok().filter(|port| *port >= 1)
}

#[derive(Debug, Default)]
struct BatchState {
    batching: bool,
    inventory: Option<Value>,
}

/// `TelemtClient` (timeout 5 s, `Authorization: <the token file's content>`).
pub struct TelemtClient {
    base_url: String,
    auth_header: String,
    timeout: Duration,
    http: std::result::Result<reqwest::Client, String>,
    batch: Arc<Mutex<BatchState>>,
}

impl std::fmt::Debug for TelemtClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemtClient")
            .field("base_url", &self.base_url)
            .field("auth_header", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Inside a batch one read of the user table serves every `list_users`/`current_access` until a
/// call that changes a user drops the snapshot; dropping the guard ends the batch.
#[must_use = "the batch ends when the guard is dropped"]
pub struct TelemtBatch {
    state: Arc<Mutex<BatchState>>,
}

impl Drop for TelemtBatch {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *state = BatchState::default();
    }
}

type Result<T> = std::result::Result<T, TelemtError>;

impl TelemtClient {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

    pub fn new(base_url: &str, auth_header: impl Into<String>) -> Self {
        Self::with_timeout(base_url, auth_header, Self::DEFAULT_TIMEOUT)
    }

    /// One HTTP client for the life of this object (the CA store is loaded once); no
    /// connection is kept between calls, no proxy from the environment, no redirects.
    pub fn with_timeout(base_url: &str, auth_header: impl Into<String>, timeout: Duration) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_header: auth_header.into(),
            timeout,
            http: http_client(timeout),
            batch: Arc::new(Mutex::new(BatchState::default())),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// `async with client.batch():`.
    pub fn batch(&self) -> TelemtBatch {
        *self.state() = BatchState { batching: true, inventory: None };
        TelemtBatch { state: self.batch.clone() }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, BatchState> {
        self.batch.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn forget(&self) {
        self.state().inventory = None;
    }

    /// `_request` → `(data, revision)` of Telemt's envelope `{"ok", "data", "revision"}`.
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        json: Option<&Value>,
        if_match: Option<&str>,
    ) -> Result<(Value, Value)> {
        let http = self.http.as_ref().map_err(|_| TelemtError::new("Telemt API unavailable"))?;
        let url = format!("{}{}", self.base_url, httpx_target(path));
        let mut request = http.request(method, url).header("Authorization", &self.auth_header);
        if let Some(revision) = if_match {
            request = request.header("If-Match", revision);
        }
        if let Some(json) = json {
            request = request.header("Content-Type", "application/json").body(json_body(json));
        }
        let response = request.send().await.map_err(classify)?;
        let status = response.status().as_u16();
        // Losing the connection while the body streams in is a lost reply, like httpx's ReadError.
        let body = response.bytes().await.map_err(|_| TelemtError::indeterminate("Telemt API reply was lost"))?;
        if status >= 400 {
            return Err(TelemtError::with_status(format!("Telemt API error ({status})"), status));
        }
        let Ok(Value::Object(mut body)) = serde_json::from_slice::<Value>(&body) else {
            return Err(TelemtError::new("Invalid Telemt API response"));
        };
        if !body.get("ok").is_some_and(truthy) {
            return Err(TelemtError::new("Telemt API rejected request"));
        }
        Ok((body.remove("data").unwrap_or(Value::Null), body.remove("revision").unwrap_or(Value::Null)))
    }

    async fn data(&self, method: Method, path: &str, json: Option<&Value>) -> Result<Value> {
        Ok(self.request(method, path, json, None).await?.0)
    }

    pub async fn list_users(&self) -> Result<Value> {
        {
            let state = self.state();
            if let (true, Some(inventory)) = (state.batching, &state.inventory) {
                return Ok(inventory.clone());
            }
        }
        let rows = self.data(Method::GET, "/v1/users", None).await?;
        let mut state = self.state();
        if state.batching {
            state.inventory = Some(rows.clone());
        }
        Ok(rows)
    }

    pub async fn create_user(&self, username: &str, secret: Option<&str>) -> Result<Value> {
        let mut body = json!({"username": username});
        if let Some(secret) = secret {
            body["secret"] = json!(secret);
        }
        self.forget();
        self.data(Method::POST, "/v1/users", Some(&body)).await
    }

    pub async fn delete_user(&self, username: &str) -> Result<Value> {
        self.forget();
        self.data(Method::DELETE, &format!("/v1/users/{}", quote(username)), None).await
    }

    pub async fn set_enabled(&self, username: &str, enabled: bool) -> Result<Value> {
        self.forget();
        let action = if enabled { "enable" } else { "disable" };
        self.data(Method::POST, &format!("/v1/users/{}/{action}", quote(username)), None).await
    }

    pub async fn rotate(&self, username: &str, secret: Option<&str>) -> Result<Value> {
        let body = match secret {
            Some(secret) => json!({"secret": secret}),
            None => json!({}),
        };
        self.forget();
        self.data(Method::POST, &format!("/v1/users/{}/rotate-secret", quote(username)), Some(&body)).await
    }

    pub async fn update_user(&self, username: &str, fields: &Value) -> Result<Value> {
        self.forget();
        self.data(Method::PATCH, &format!("/v1/users/{}", quote(username)), Some(fields)).await
    }

    pub async fn reset_quota(&self, username: &str) -> Result<Value> {
        self.data(Method::POST, &format!("/v1/users/{}/reset-quota", quote(username)), Some(&json!({}))).await
    }

    pub async fn health(&self) -> Result<Value> {
        self.data(Method::GET, "/v1/health/ready", None).await
    }

    pub async fn stats(&self) -> Result<Value> {
        self.data(Method::GET, "/v1/stats/summary", None).await
    }

    pub async fn connections(&self) -> Result<Value> {
        self.data(Method::GET, "/v1/runtime/connections/summary", None).await
    }

    pub async fn active_ips(&self) -> Result<Value> {
        self.data(Method::GET, "/v1/stats/users/active-ips", None).await
    }

    pub async fn quota_stats(&self) -> Result<Value> {
        self.data(Method::GET, "/v1/stats/users/quota", None).await
    }

    /// Read back what the runtime holds now — the recovery step after a lost reply.
    pub async fn current_access(&self, username: &str) -> Result<Option<TelemtAccess>> {
        let rows = self.list_users().await?;
        let found = rows
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row.get("username").and_then(Value::as_str) == Some(username)));
        Ok(found.and_then(access_from_user))
    }

    /// `(data, revision)` of `GET /v1/config`; the revision is the whole config's.
    pub async fn config(&self) -> Result<(Value, Value)> {
        self.request(Method::GET, "/v1/config", None, None).await
    }

    pub async fn patch_config(&self, body: &Value, revision: &str) -> Result<(Value, Value)> {
        self.request(Method::PATCH, "/v1/config", Some(body), Some(revision)).await
    }

    pub async fn reload(&self, revision: &str) -> Result<Value> {
        Ok(self.request(Method::POST, "/v1/system/reload", Some(&json!({})), Some(revision)).await?.0)
    }

    pub async fn reload_status(&self, reload_id: i64) -> Result<Value> {
        self.data(Method::GET, &format!("/v1/system/reload/{reload_id}"), None).await
    }
}

/// `quote(username)` (`safe='/'`).
fn quote(text: &str) -> String {
    panel_core::pytext::quote_path(text)
}

/// A connection that was never established sent nothing: a plain failure, safe to retry. Any
/// other transport failure may have happened after the request left: indeterminate.
fn classify(error: reqwest::Error) -> TelemtError {
    if error.is_connect() || error.is_builder() {
        TelemtError::new("Telemt API unavailable")
    } else {
        TelemtError::indeterminate("Telemt API reply was lost")
    }
}

fn http_client(timeout: Duration) -> std::result::Result<reqwest::Client, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| err.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout)
        .read_timeout(timeout)
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_secret_strips_the_fake_tls_prefix() {
        assert_eq!(api_secret("eeabcd"), "abcd");
        assert_eq!(api_secret("abcd"), "abcd");
    }

    #[test]
    fn access_is_read_from_the_first_tls_link() {
        let link = "tg://proxy?server=proxy.example.com&port=443&secret=ee0011";
        let row = json!({"username": "a", "links": {"tls": [5, link, "tg://other"]}});
        let access = access_from_user(&row).unwrap();
        assert_eq!(
            access.to_value(),
            json!({"link": link, "secret": "ee0011", "server": "proxy.example.com", "port": 443})
        );
        assert_eq!(access_from_user(&json!({"links": {"tls": []}})), None);
        assert_eq!(access_from_user(&json!({"links": {"tls": [""]}})), None);
        assert_eq!(access_from_user(&json!({"links": []})), None);
        assert_eq!(access_from_user(&json!([1])), None);
        let odd = access_from_user(&json!({"links": {"tls": ["tg://proxy?port=0&server="]}})).unwrap();
        assert_eq!((odd.secret, odd.server, odd.port), (None, None, None));
        assert_eq!(port_number("65536"), None);
        assert_eq!(port_number("+1"), None);
        assert_eq!(port_number("\u{0661}"), Some(1));
        assert_eq!(port_number("\u{00b2}"), None);
    }
}
