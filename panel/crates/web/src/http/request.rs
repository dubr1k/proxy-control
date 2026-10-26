//! What a handler sees of a request, read the way Starlette/FastAPI read it.
//!
//! [`Call`] is the extractor every panel handler takes (after `State`): the request head, the
//! body (already read whole by the body-limit stage), the matched path parameters and the
//! per-request facts of the outer stages ([`RequestMeta`]: request id, client IP, scheme, decoded
//! path, raw query).
//!
//! FastAPI's order of checks — which decides which error a client sees — is the handler's to
//! follow, with these helpers:
//!
//! 1. [`Call::body_input`] first (only on routes with a body model): a body that is not JSON is
//!    422 `json_invalid` (or 400 "There was an error parsing the body") **before** any auth;
//! 2. the auth gate (`crate::auth`), which raises 401/403/429;
//! 3. [`Issues`]: path parameters, then query parameters, then the body model, all collected
//!    into one 422;
//! 4. the handler's own work.

use std::collections::HashMap;

use axum::extract::FromRequest;
use bytes::Bytes;
use http::request::Parts;
use panel_core::errors::{LocItem, ValidationIssue};
use panel_model::validate::{Cx, Entry, Int, Model, Str};
use serde_json::Value;

use super::json_loads::{self, LoadsError};
use super::response::Failure;

/// Facts the outer stages establish once per request.
#[derive(Debug, Clone)]
pub struct RequestMeta {
    /// `secrets.token_hex(8)`, echoed as `X-Request-Id` and stored on audit rows.
    pub request_id: String,
    /// The client address after the proxy-header rule, or `"unknown"` (no TCP peer).
    pub client_ip: String,
    /// `http`, or what a trusted proxy said in `X-Forwarded-Proto`.
    pub scheme: String,
    /// The local address of the connection (`scope["server"]`), when it has one.
    pub server: Option<(String, u16)>,
    /// `scope["path"]`: the percent-decoded path.
    pub path: String,
    /// The raw query string (after `?`, undecoded).
    pub query: String,
}

/// The parameters of the matched path template, in template order.
#[derive(Debug, Clone, Default)]
pub struct PathParams(pub Vec<(String, String)>);

/// One request as a handler reads it.
#[derive(Debug)]
pub struct Call {
    pub parts: Parts,
    pub body: Bytes,
    pub meta: RequestMeta,
    pub params: PathParams,
}

impl<S: Send + Sync> FromRequest<S> for Call {
    type Rejection = Failure;

    async fn from_request(request: axum::extract::Request, _state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = request.into_parts();
        let meta = parts.extensions.remove::<RequestMeta>().ok_or_else(|| Failure::internal("no request meta"))?;
        let params = parts.extensions.remove::<PathParams>().unwrap_or_default();
        let body = axum::body::to_bytes(body, usize::MAX).await.map_err(Failure::internal)?;
        Ok(Call { parts, body, meta, params })
    }
}

/// Header bytes as Starlette decodes them (latin-1).
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

/// `Headers.get(name)`: the first value, latin-1.
pub fn header(parts: &Parts, name: &str) -> Option<String> {
    parts.headers.get(name).map(|value| latin1(value.as_bytes()))
}

impl Call {
    /// `request.headers.get(name)`.
    pub fn header(&self, name: &str) -> Option<String> {
        header(&self.parts, name)
    }

    /// `request.cookies`.
    pub fn cookies(&self) -> HashMap<String, String> {
        self.header("cookie").map(|value| parse_cookies(&value)).unwrap_or_default()
    }

    /// `request.cookies.get(name)`.
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.cookies().remove(name)
    }

    /// The client address for limiters and audit rows (`RequestContext.client_ip`).
    pub fn client_ip(&self) -> &str {
        &self.meta.client_ip
    }

    /// The request id for audit rows.
    pub fn request_id(&self) -> &str {
        &self.meta.request_id
    }

    /// `request.url.path` (decoded).
    pub fn path(&self) -> &str {
        &self.meta.path
    }

    /// A parameter of the matched template (always present for a declared name).
    pub fn param(&self, name: &str) -> &str {
        self.params.0.iter().find(|(key, _)| key == name).map_or("", |(_, value)| value.as_str())
    }

    /// `request.query_params` as pairs, in order.
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        parse_qsl(&self.meta.query)
    }

    /// `request.query_params.get(name)`: the last value.
    pub fn query(&self, name: &str) -> Option<String> {
        self.query_pairs().into_iter().rev().find(|(key, _)| key == name).map(|(_, value)| value)
    }

    /// How FastAPI reads a body for a route with a body model (`get_request_handler`): nothing
    /// read is [`BodyInput::Missing`]; with no `Content-Type` (strict content type) or a type
    /// other than `application/json`/`application/*+json` the raw bytes are the input; otherwise
    /// `json.loads` — whose failure answers here, before any dependency runs.
    pub fn body_input(&self) -> Result<BodyInput, Failure> {
        if self.body.is_empty() {
            return Ok(BodyInput::Missing);
        }
        let is_json = self.header("content-type").is_some_and(|value| {
            let (main, sub) = content_type(&value);
            main == "application" && (sub == "json" || sub.ends_with("+json"))
        });
        if !is_json {
            return Ok(BodyInput::Bytes(String::from_utf8_lossy(&self.body).into_owned()));
        }
        match json_loads::loads(&self.body) {
            Ok(value) => Ok(BodyInput::Json(value)),
            Err(LoadsError::Decode { msg, pos }) => {
                Err(Failure::validation(vec![ValidationIssue::json_invalid(pos as i64, msg)]))
            }
            Err(LoadsError::Unrepresentable { msg, pos }) => {
                Err(Failure::validation(vec![ValidationIssue::json_invalid(pos as i64, msg)]))
            }
            Err(LoadsError::Other(_)) => Err(Failure::detail(400, "There was an error parsing the body")),
        }
    }
}

/// A request body as FastAPI hands it to validation.
#[derive(Debug, Clone, PartialEq)]
pub enum BodyInput {
    /// No body at all.
    Missing,
    /// Parsed JSON.
    Json(Value),
    /// A body that was not parsed as JSON (shown as text in an issue's `input`).
    Bytes(String),
}

/// `email.message.Message` content type: `(maintype, subtype)` lower-cased, `text/plain` when the
/// value is not `type/subtype`.
pub fn content_type(value: &str) -> (String, String) {
    let first = value.split(';').next().unwrap_or("");
    let ctype = panel_core::pytext::lower(panel_core::pytext::strip(first));
    let mut pieces = ctype.split('/');
    match (pieces.next(), pieces.next(), pieces.next()) {
        (Some(main), Some(sub), None) => (main.to_string(), sub.to_string()),
        _ => ("text".into(), "plain".into()),
    }
}

/// Starlette's `cookie_parser`.
pub fn parse_cookies(header: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for chunk in header.split(';') {
        let (key, value) = match chunk.split_once('=') {
            Some((key, value)) => (key, value),
            None => ("", chunk),
        };
        let (key, value) = (panel_core::pytext::strip(key), panel_core::pytext::strip(value));
        if !key.is_empty() || !value.is_empty() {
            out.insert(key.to_string(), unquote_cookie(value));
        }
    }
    out
}

/// `http.cookies._unquote`.
pub fn unquote_cookie(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 2 || chars[0] != '"' || chars[chars.len() - 1] != '"' {
        return value.to_string();
    }
    let inner = &chars[1..chars.len() - 1];
    let mut out = String::new();
    let mut index = 0;
    while index < inner.len() {
        if inner[index] == '\\' && index + 1 < inner.len() {
            let octal = index + 3 < inner.len()
                && ('0'..='3').contains(&inner[index + 1])
                && ('0'..='7').contains(&inner[index + 2])
                && ('0'..='7').contains(&inner[index + 3]);
            if octal {
                let code = inner[index + 1..index + 4].iter().fold(0u32, |acc, digit| acc * 8 + (*digit as u32 - 48));
                out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                index += 4;
                continue;
            }
            if inner[index + 1] != '\n' {
                out.push(inner[index + 1]);
                index += 2;
                continue;
            }
        }
        out.push(inner[index]);
        index += 1;
    }
    out
}

/// `urllib.parse.parse_qsl(query, keep_blank_values=True)` over the latin-1 query string.
pub fn parse_qsl(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|item| !item.is_empty())
        .map(|item| {
            let (name, value) = item.split_once('=').unwrap_or((item, ""));
            let decode = |text: &str| panel_core::pytext::unquote(&text.replace('+', " "));
            (decode(name), decode(value))
        })
        .collect()
}

/// Request-validation issues collected in FastAPI's order: path, query, body.
#[derive(Debug)]
pub struct Issues {
    cx: Cx,
}

impl Default for Issues {
    fn default() -> Self {
        Self::new()
    }
}

impl Issues {
    pub fn new() -> Self {
        Self { cx: Cx::new(Entry::Body) }
    }

    fn loc(kind: &str, name: &str) -> Vec<LocItem> {
        vec![kind.into(), name.into()]
    }

    /// A path parameter declared `int`.
    pub fn path_int(&mut self, call: &Call, name: &str) -> Option<i64> {
        Int::LAX.validate(&Value::String(call.param(name).to_string()), &Self::loc("path", name), &mut self.cx)
    }

    /// An `int` query parameter with a default (absent → `default`).
    pub fn query_int(&mut self, call: &Call, name: &str, rule: Int, default: Option<i64>) -> Option<Option<i64>> {
        match call.query(name) {
            None => Some(default),
            Some(text) => rule.validate(&Value::String(text), &Self::loc("query", name), &mut self.cx).map(Some),
        }
    }

    /// An optional `str` query parameter.
    pub fn query_str(&mut self, call: &Call, name: &str, rule: Str) -> Option<Option<String>> {
        match call.query(name) {
            None => Some(None),
            Some(text) => rule.validate(&Value::String(text), &Self::loc("query", name), &mut self.cx).map(Some),
        }
    }

    /// The body model.
    pub fn body<M: Model>(&mut self, input: &BodyInput) -> Option<M> {
        let value = match input {
            BodyInput::Missing => {
                self.cx.push(ValidationIssue::missing(vec!["body".into()], Value::Null));
                return None;
            }
            BodyInput::Bytes(text) => {
                self.cx.push(ValidationIssue::model_attributes_type(vec!["body".into()], Value::String(text.clone())));
                return None;
            }
            BodyInput::Json(value) => value,
        };
        match M::validate_body(value) {
            Ok(model) => Some(model),
            Err(error) => {
                for issue in error.body_issues() {
                    self.cx.push(issue);
                }
                None
            }
        }
    }

    /// Records an issue built elsewhere.
    pub fn push(&mut self, issue: ValidationIssue) {
        self.cx.push(issue);
    }

    /// `Ok` when nothing failed, else the 422.
    pub fn finish(self) -> Result<(), Failure> {
        let issues = self.cx.into_issues();
        if issues.is_empty() {
            Ok(())
        } else {
            Err(Failure::validation(issues))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_parse_like_starlette() {
        let cookies = parse_cookies("junk; panel_session=\"a\\\"b\\012\"; =x; a=b=c;  ");
        assert_eq!(cookies["panel_session"], "a\"b\n");
        // `junk` and `=x` both have the empty name; the last one wins, as in a dict.
        assert_eq!(cookies[""], "x");
        assert_eq!(cookies["a"], "b=c");
    }

    #[test]
    fn query_strings_parse_like_parse_qsl() {
        assert_eq!(
            parse_qsl("a=1&&b&c=%20x+y&a=2"),
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "".into()),
                ("c".into(), " x y".into()),
                ("a".into(), "2".into())
            ]
        );
    }

    #[test]
    fn content_types_parse_like_email() {
        assert_eq!(content_type("Application/JSON; charset=utf-8"), ("application".into(), "json".into()));
        assert_eq!(content_type("json"), ("text".into(), "plain".into()));
        assert_eq!(content_type("a/b/c"), ("text".into(), "plain".into()));
    }
}
