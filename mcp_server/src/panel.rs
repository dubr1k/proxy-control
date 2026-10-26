//! The panel as the MCP server sees it: one HTTP client inside the Compose network with the
//! panel's own `Host` and an admin API key. A refusal from the panel is a [`PanelError`] that
//! carries the panel's `{detail, code}` — the tools turn it into an error result, never into a
//! crash of the MCP session.

use std::time::Duration;

use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, USER_AGENT};
use serde_json::{json, Value};

use crate::config::Config;
use crate::py;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub struct PanelError {
    pub status: u16,
    pub detail: String,
    pub code: Value,
}

impl PanelError {
    pub fn new(status: u16, detail: impl Into<String>, code: Option<&str>) -> Self {
        Self { status, detail: detail.into(), code: code.map_or(Value::Null, |code| Value::String(code.into())) }
    }

    pub fn payload(&self) -> Value {
        json!({"status": self.status, "detail": self.detail, "code": self.code})
    }
}

/// `/api/clients/{client_id}` with its parameters substituted, each one URL-encoded so a value
/// can never add a path segment.
pub fn encode_path(template: &str, values: &[(&str, &Value)]) -> String {
    let mut path = template.to_string();
    for (name, value) in values {
        path = path.replace(&format!("{{{name}}}"), &py::quote(&py::str_of(value)));
    }
    path
}

/// The class name httpx would have raised for a transport failure.
fn failure_name(err: &reqwest::Error) -> &'static str {
    if err.is_connect() {
        if err.is_timeout() {
            "ConnectTimeout"
        } else {
            "ConnectError"
        }
    } else if err.is_timeout() {
        "ReadTimeout"
    } else if err.is_body() || err.is_decode() {
        "ReadError"
    } else if err.is_builder() {
        "UnsupportedProtocol"
    } else {
        "RemoteProtocolError"
    }
}

fn unreachable(name: &str) -> PanelError {
    PanelError::new(502, format!("panel unreachable: {name}"), Some("panel_unreachable"))
}

pub struct PanelClient {
    http: reqwest::Client,
    base: String,
    host: HeaderValue,
    authorization: HeaderValue,
}

impl PanelClient {
    pub fn new(config: &Config) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| format!("cannot build the panel client: {err}"))?;
        let header = |value: String, name: &str| {
            HeaderValue::from_str(&value).map_err(|_| format!("{name} is not a valid header value"))
        };
        Ok(Self {
            http,
            base: config.panel_url.clone(),
            host: header(config.panel_host.clone(), "MCP_PANEL_HOST")?,
            authorization: header(format!("Bearer {}", config.panel_key), "MCP_PANEL_KEY_FILE")?,
        })
    }

    /// The decoded JSON of a 2xx answer (`Null` for an empty body); anything else is a
    /// [`PanelError`] with the panel's own words. `params` of `None` (or empty) sends no query.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        params: &[(String, Value)],
        body: Option<&Value>,
    ) -> Result<Value, PanelError> {
        let mut url = format!("{}/{}", self.base, path.trim_start_matches('/'));
        if !params.is_empty() {
            url.push('?');
            url.push_str(&py::urlencode(params));
        }
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| unreachable("UnsupportedProtocol"))?;
        let mut request = self
            .http
            .request(method, url.as_str())
            .header(HOST, self.host.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, "proxy-control-mcp");
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(compact(body));
        }
        let response = request.send().await.map_err(|err| unreachable(failure_name(&err)))?;
        let status = response.status();
        let reason = response
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .map(|phrase| String::from_utf8_lossy(phrase.as_bytes()).into_owned())
            .unwrap_or_else(|| status.canonical_reason().unwrap_or("").to_string());
        let content = response.bytes().await.map_err(|err| unreachable(failure_name(&err)))?;
        let decoded = if content.is_empty() {
            Value::Null
        } else {
            let json = content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&content);
            serde_json::from_slice(json)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&content).into_owned()))
        };
        if status.is_success() {
            return Ok(decoded);
        }
        let (detail, code) = match &decoded {
            Value::Object(map) => (
                map.get("detail").cloned().unwrap_or(Value::String(reason)),
                map.get("code").cloned().unwrap_or(Value::Null),
            ),
            other if py::truthy(other) => (other.clone(), Value::Null),
            _ => (Value::String(reason), Value::Null),
        };
        let detail = match detail {
            Value::String(text) => text,
            other => py::dumps(&other, false),
        };
        Err(PanelError { status: status.as_u16(), detail, code })
    }

    /// `GET` with the non-null parameters as the query.
    pub async fn get(&self, path: &str, params: &[(&str, Value)]) -> Result<Value, PanelError> {
        self.request("GET", path, &present(params), None).await
    }

    /// `POST` with a JSON body (none for `None`) and the non-null parameters as the query.
    pub async fn post(&self, path: &str, body: Option<&Value>, params: &[(&str, Value)]) -> Result<Value, PanelError> {
        self.request("POST", path, &present(params), body).await
    }
}

fn present(params: &[(&str, Value)]) -> Vec<(String, Value)> {
    params.iter().filter(|(_, value)| !value.is_null()).map(|(key, value)| (key.to_string(), value.clone())).collect()
}

/// The request body as httpx writes it: compact JSON, non-ASCII kept.
fn compact(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("a JSON value always serialises")
}
