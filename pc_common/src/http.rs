use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::ApiError;

/// Whether the declared body was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Read(Vec<u8>),
    /// `Content-Length` was missing a number, negative or above the server's limit: the body
    /// was left unread, and a route that needs it answers 422 like the Python managers did.
    Invalid,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// The request target as sent, query included.
    pub target: String,
    /// The path part of the target, still percent-encoded.
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl Request {
    /// The first header with this name, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    pub fn body_bytes(&self) -> Result<&[u8], ApiError> {
        match &self.body {
            Body::Read(bytes) => Ok(bytes),
            Body::Invalid => Err(ApiError::invalid_request("invalid body")),
        }
    }

    /// The body as a JSON object; an empty body is `{}`. Anything else answers 422
    /// `invalid_request` / `invalid body`.
    pub fn json_object(&self) -> Result<Map<String, Value>, ApiError> {
        let bytes = self.body_bytes()?;
        if bytes.is_empty() {
            return Ok(Map::new());
        }
        match serde_json::from_slice::<Value>(bytes) {
            Ok(Value::Object(map)) => Ok(map),
            _ => Err(ApiError::invalid_request("invalid body")),
        }
    }

    /// The query parameters, percent-decoded (`+` is a space, as in form encoding).
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        let Some(query) = &self.query else { return Vec::new() };
        query
            .split('&')
            .filter(|part| !part.is_empty())
            .map(|part| {
                let (key, value) = part.split_once('=').unwrap_or((part, ""));
                (form_decode(key), form_decode(value))
            })
            .collect()
    }

    /// The path split into percent-decoded segments after `prefix`, or `None` when the path
    /// does not start with it.
    pub fn segments_after(&self, prefix: &str) -> Option<Vec<String>> {
        let tail = self.path.strip_prefix(prefix)?;
        Some(tail.split('/').map(percent_decode).collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// A compact JSON body with the headers every manager sends.
    pub fn json<T: Serialize + ?Sized>(status: u16, value: &T) -> Self {
        let body = serde_json::to_vec(value).expect("a JSON value always serialises");
        Self { status, headers: json_headers(), body }
    }

    /// A status with no body (204 and the like), still with the manager's headers.
    pub fn empty(status: u16) -> Self {
        Self { status, headers: json_headers(), body: Vec::new() }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.retain(|(key, _)| !key.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status)).into_bytes();
        for (name, value) in &self.headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\nConnection: close\r\n\r\n", self.body.len()).as_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

fn json_headers() -> Vec<(String, String)> {
    vec![
        ("Content-Type".into(), "application/json".into()),
        ("Cache-Control".into(), "no-store".into()),
        ("X-Content-Type-Options".into(), "nosniff".into()),
    ]
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        423 => "Locked",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

/// Percent-decodes a path segment the way `urllib.parse.unquote` does: invalid escapes stay as
/// they are, and invalid UTF-8 becomes U+FFFD.
pub fn percent_decode(text: &str) -> String {
    decode(text, false)
}

fn form_decode(text: &str) -> String {
    decode(text, true)
}

fn decode(text: &str, plus_is_space: bool) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(high), Some(low)) => {
                    out.push(high * 16 + low);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(target: &str, body: Body) -> Request {
        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path.to_string(), Some(query.to_string())),
            None => (target.to_string(), None),
        };
        Request { method: "POST".into(), target: target.into(), path, query, headers: vec![], body }
    }

    #[test]
    fn percent_decoding_matches_unquote() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%D0%B8"), "и");
        assert_eq!(percent_decode("bad%zz"), "bad%zz");
        assert_eq!(percent_decode("tail%2"), "tail%2");
        assert_eq!(percent_decode("tail%"), "tail%");
        assert_eq!(percent_decode("a+b"), "a+b");
    }

    #[test]
    fn json_object_accepts_objects_and_empty_bodies_only() {
        assert!(request("/", Body::Read(vec![])).json_object().unwrap().is_empty());
        assert_eq!(request("/", Body::Read(b"{\"a\":1}".to_vec())).json_object().unwrap()["a"], 1);
        for bad in [&b"[]"[..], b"null", b"{", b"1"] {
            let err = request("/", Body::Read(bad.to_vec())).json_object().unwrap_err();
            assert_eq!((err.status, err.code.as_str(), err.detail.as_str()), (422, "invalid_request", "invalid body"));
        }
        assert_eq!(request("/", Body::Invalid).json_object().unwrap_err().status, 422);
    }

    #[test]
    fn query_and_segments_are_decoded() {
        let req = request("/v1/users/al%20ice/rotate?x=1&y=a+b&flag", Body::Read(vec![]));
        assert_eq!(req.segments_after("/v1/users/").unwrap(), vec!["al ice", "rotate"]);
        assert_eq!(
            req.query_pairs(),
            vec![("x".into(), "1".into()), ("y".into(), "a b".into()), ("flag".into(), String::new())]
        );
        assert!(req.segments_after("/v2/").is_none());
    }

    #[test]
    fn responses_carry_manager_headers_and_length() {
        let encoded = String::from_utf8(Response::json(200, &serde_json::json!({"ok": true})).encode()).unwrap();
        assert!(encoded.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(encoded.contains("Content-Type: application/json\r\n"));
        assert!(encoded.contains("Cache-Control: no-store\r\n"));
        assert!(encoded.contains("Content-Length: 11\r\n"));
        assert!(encoded.ends_with("\r\n\r\n{\"ok\":true}"));
        let empty = String::from_utf8(Response::empty(204).encode()).unwrap();
        assert!(empty.contains("Content-Length: 0\r\n"));
    }
}
