//! The Streamable HTTP edges of the Python SDK's stateless JSON transport that the Rust SDK
//! answers differently: the `Accept` and `Content-Type` rules of a POST, the JSON-RPC error
//! bodies of a parse or validation failure, `GET` (an event stream that only carries pings),
//! `DELETE` and other methods, and the shape of "method not found" / "invalid parameters".
//! Everything between a valid request and its answer is the Rust SDK's.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Frame;
use hyper::header::{HeaderValue, ALLOW, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Response, StatusCode};
use serde_json::{json, Value};

use crate::server::Body;

/// Protocol versions negotiated with `initialize`; any other `MCP-Protocol-Version` is the
/// stateless 2026 envelope, served by the SDK as it is.
pub const HANDSHAKE_VERSIONS: [&str; 4] = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
/// Requests the Python server had handlers for: a malformed one is "invalid parameters".
const HANDLED_METHODS: [&str; 7] =
    ["initialize", "ping", "server/discover", "resources/list", "resources/read", "tools/list", "tools/call"];
const INVALID_REQUEST: i64 = -32600;
const PING_INTERVAL: Duration = Duration::from_secs(15);

/// A JSON-RPC error without a request id, as the transport writes it.
pub fn jsonrpc_error(status: StatusCode, code: i64, message: &str) -> Response<Body> {
    let body = json!({"jsonrpc": "2.0", "id": null, "error": {"code": code, "message": message}});
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())).boxed());
    *response.status_mut() = status;
    response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

pub fn not_acceptable(message: &str) -> Response<Body> {
    jsonrpc_error(StatusCode::NOT_ACCEPTABLE, INVALID_REQUEST, message)
}

pub fn session_termination() -> Response<Body> {
    jsonrpc_error(
        StatusCode::METHOD_NOT_ALLOWED,
        INVALID_REQUEST,
        "Method Not Allowed: Session termination not supported",
    )
}

pub fn unsupported_method() -> Response<Body> {
    let mut response = jsonrpc_error(StatusCode::METHOD_NOT_ALLOWED, INVALID_REQUEST, "Method Not Allowed");
    response.headers_mut().insert(ALLOW, HeaderValue::from_static("GET, POST, DELETE"));
    response
}

pub fn unsupported_media_type() -> Response<Body> {
    jsonrpc_error(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        INVALID_REQUEST,
        "Unsupported Media Type: Content-Type must be application/json",
    )
}

pub fn parse_error(err: &serde_json::Error) -> Response<Body> {
    jsonrpc_error(StatusCode::BAD_REQUEST, -32700, &format!("Parse error: {err}"))
}

pub fn validation_error(err: &serde_json::Error) -> Response<Body> {
    jsonrpc_error(StatusCode::BAD_REQUEST, -32602, &format!("Validation error: {err}"))
}

/// `(has_json, has_sse)` of an `Accept` header, wildcards included.
pub fn accepts(accept: &str) -> (bool, bool) {
    let types: Vec<String> =
        accept.split(',').map(|part| part.trim().split(';').next().unwrap_or("").trim().to_lowercase()).collect();
    let any = types.iter().any(|t| t == "*/*");
    let json = any || types.iter().any(|t| t == "application/json" || t == "application/*");
    let sse = any || types.iter().any(|t| t == "text/event-stream" || t == "text/*");
    (json, sse)
}

/// The transport's own `Content-Type` rule (stricter than the security check's prefix).
pub fn is_json_content_type(content_type: &str) -> bool {
    content_type.split(';').next().unwrap_or("").split(',').any(|part| part.trim() == "application/json")
}

/// Rewrites the JSON-RPC message of a JSON answer; `edit` says whether it changed anything.
async fn edit_json(response: Response<Body>, edit: impl FnOnce(&mut Value) -> bool) -> Response<Body> {
    let (mut parts, body) = response.into_parts();
    let json = parts.headers.get(CONTENT_TYPE).is_some_and(|value| value.as_bytes().starts_with(b"application/json"));
    if !json {
        return Response::from_parts(parts, body);
    }
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(never) => match never {},
    };
    let mut message = match serde_json::from_slice::<Value>(&bytes) {
        Ok(message) => message,
        Err(_) => return Response::from_parts(parts, Full::new(bytes).boxed()),
    };
    if !edit(&mut message) {
        return Response::from_parts(parts, Full::new(bytes).boxed());
    }
    parts.headers.remove(CONTENT_LENGTH);
    Response::from_parts(parts, Full::new(Bytes::from(message.to_string())).boxed())
}

/// The SDK's answer in the Python shapes: a notification's 202 carries `Content-Type`, and
/// "method not found" names the method in `data` — or, for a method the server handles, says
/// "invalid request parameters" (the request did not parse as that method's).
pub async fn python_shaped(mut response: Response<Body>) -> Response<Body> {
    if response.status() == StatusCode::ACCEPTED && !response.headers().contains_key(CONTENT_TYPE) {
        response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    edit_json(response, |message| {
        let error = message.get_mut("error").and_then(Value::as_object_mut);
        let Some(error) =
            error.filter(|error| error.get("code") == Some(&json!(-32601)) && !error.contains_key("data"))
        else {
            return false;
        };
        let method = error.get("message").cloned().unwrap_or(Value::Null);
        if method.as_str().is_some_and(|method| HANDLED_METHODS.contains(&method)) {
            error.insert("code".into(), json!(-32602));
            error.insert("message".into(), json!("Invalid request parameters"));
            error.insert("data".into(), json!(""));
        } else {
            error.insert("message".into(), json!("Method not found"));
            error.insert("data".into(), method);
        }
        true
    })
    .await
}

/// A 2026-envelope answer in the Python shapes: a result is stamped with the server's identity
/// in `_meta`, and a handler failure is a bare internal error (no exception text on the wire).
pub async fn modern_shaped(response: Response<Body>, server_info: Value) -> Response<Body> {
    edit_json(response, |message| {
        if let Some(error) = message.get_mut("error").and_then(Value::as_object_mut) {
            if error.get("code") != Some(&json!(0)) {
                return false;
            }
            error.clear();
            error.insert("code".into(), json!(-32603));
            error.insert("message".into(), json!("Internal server error"));
            return true;
        }
        let Some(result) = message.get_mut("result").and_then(Value::as_object_mut) else { return false };
        let meta = result.entry("_meta").or_insert_with(|| json!({}));
        let Some(meta) = meta.as_object_mut() else { return false };
        if meta.get("io.modelcontextprotocol/serverInfo").is_some_and(|info| !info.is_null()) {
            return false;
        }
        meta.insert("io.modelcontextprotocol/serverInfo".into(), server_info);
        true
    })
    .await
}

/// A response body fed by a channel: ends when the sender is dropped.
struct ChannelBody(tokio::sync::mpsc::Receiver<Bytes>);

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|item| item.map(|bytes| Ok(Frame::data(bytes))))
    }
}

/// `datetime.now(timezone.utc)` as `str()` prints it.
fn utc_now() -> String {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs() as i64;
    let (year, month, day) = pc_common::logger::civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    let micros = since.subsec_micros();
    let fraction = if micros == 0 { String::new() } else { format!(".{micros:06}") };
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}{fraction}+00:00", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// `GET /mcp`: the standalone event stream of a stateless server. Nothing is ever sent on it but
/// the keep-alive comment every 15 seconds; it ends when the client leaves or the server stops.
pub fn event_stream(mut stop: tokio::sync::watch::Receiver<bool>) -> Response<Body> {
    let (sender, receiver) = tokio::sync::mpsc::channel::<Bytes>(1);
    tokio::spawn(async move {
        if *stop.borrow_and_update() {
            return;
        }
        loop {
            tokio::select! {
                _ = tokio::time::sleep(PING_INTERVAL) => {
                    let ping = format!(": ping - {}\r\n\r\n", utc_now());
                    if sender.send(Bytes::from(ping)).await.is_err() {
                        break;
                    }
                }
                _ = sender.closed() => break,
                _ = stop.changed() => break,
            }
        }
    });
    let mut response = Response::new(ChannelBody(receiver).boxed());
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache, no-transform"));
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_and_content_type_follow_the_python_transport() {
        assert_eq!(accepts("application/json, text/event-stream"), (true, true));
        assert_eq!(accepts("Application/JSON;q=0.9"), (true, false));
        assert_eq!(accepts("*/*"), (true, true));
        assert_eq!(accepts("text/*"), (false, true));
        assert_eq!(accepts(""), (false, false));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        assert!(!is_json_content_type("Application/JSON"));
        assert!(!is_json_content_type("application/jsonx"));
    }

    #[test]
    fn the_ping_time_is_pythons_str_of_an_aware_datetime() {
        let now = utc_now();
        assert!(now.ends_with("+00:00") && now.len() >= 25, "{now}");
    }
}
