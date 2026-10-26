//! Responses as Starlette renders them: `JSONResponse` (compact, raw UTF-8, `application/json`),
//! `PlainTextResponse`/`HTMLResponse` (`; charset=utf-8`), `RedirectResponse` (empty body,
//! `location` quoted with Starlette's safe set), `Response(status_code=204)` (no type, no length),
//! and the handler failures FastAPI turns into bodies (`HTTPException` → `{"detail": …}`, request
//! validation → the pydantic list, an unhandled exception → the bare 500 of
//! `ServerErrorMiddleware`, which carries no security headers).

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::header::{HeaderName, HeaderValue, CONTENT_TYPE, LOCATION};
use http::StatusCode;
use panel_core::errors::{ApiError, ValidationIssue};
use serde_json::Value;

/// Marks the bare 500 of an unhandled error: the security-headers stage leaves it alone, as
/// Starlette's `ServerErrorMiddleware` sits outside `SecurityHeadersMiddleware`.
#[derive(Debug, Clone, Copy)]
pub struct UnhandledError;

/// Starlette's `quote(url, safe=":/%#?=@[]!$&'()*+,;")` of a redirect target.
pub const REDIRECT_SAFE: &str = ":/%#?=@[]!$&'()*+,;";

fn status(code: u16) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// `JSONResponse(value, status)`.
pub fn json(code: u16, value: &Value) -> Response {
    json_bytes(code, panel_core::pyjson::compact_utf8(value).into_bytes())
}

/// A JSON body already rendered.
pub fn json_bytes(code: u16, body: impl Into<Body>) -> Response {
    let mut response = Response::new(body.into());
    *response.status_mut() = status(code);
    response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// `PlainTextResponse(text, status)`.
pub fn plain(code: u16, text: impl Into<String>) -> Response {
    let mut response = Response::new(Body::from(text.into()));
    *response.status_mut() = status(code);
    response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    response
}

/// `HTMLResponse(text)`.
pub fn html(text: String) -> Response {
    let mut response = Response::new(Body::from(text));
    response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    response
}

/// `RedirectResponse(url, status)`: the target quoted like Starlette, an empty body.
pub fn redirect(code: u16, url: &str) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status(code);
    let quoted = panel_core::pytext::quote(url, REDIRECT_SAFE);
    if let Ok(value) = HeaderValue::from_str(&quoted) {
        response.headers_mut().insert(LOCATION, value);
    }
    response.headers_mut().insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
}

/// `Response(status_code=…)` with no body and no media type (204, 304).
pub fn empty(code: u16) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status(code);
    response
}

/// Starlette's bare `500 Internal Server Error` (plain text, no security headers).
pub fn unhandled() -> Response {
    let mut response = plain(500, "Internal Server Error");
    response.extensions_mut().insert(UnhandledError);
    response
}

/// An `HTTPException` or a validation error, with extra headers (`Retry-After`, `Allow`).
#[derive(Debug)]
pub struct ApiFailure {
    pub error: ApiError,
    pub headers: Vec<(HeaderName, String)>,
}

/// Why a handler did not answer normally.
#[derive(Debug)]
pub enum Failure {
    /// An answer of the API (boxed: handlers return it in a `Result`).
    Api(Box<ApiFailure>),
    /// An unhandled exception: logged, answered with the bare 500.
    Internal(String),
}

/// What handlers return.
pub type Handled = Result<Response, Failure>;

impl Failure {
    /// `HTTPException(status, detail)`.
    pub fn detail(code: u16, detail: impl Into<String>) -> Self {
        Failure::from(ApiError::detail(code, detail))
    }

    /// An unexpected error (database, I/O): Python let it escape to `ServerErrorMiddleware`.
    pub fn internal(error: impl std::fmt::Display) -> Self {
        Failure::Internal(error.to_string())
    }

    /// FastAPI's 422 for these issues.
    pub fn validation(issues: Vec<ValidationIssue>) -> Self {
        Failure::from(ApiError::Validation(issues))
    }

    /// Adds a response header.
    pub fn with_header(mut self, name: HeaderName, value: impl Into<String>) -> Self {
        if let Failure::Api(failure) = &mut self {
            failure.headers.push((name, value.into()));
        }
        self
    }
}

impl From<ApiError> for Failure {
    fn from(error: ApiError) -> Self {
        Failure::Api(Box::new(ApiFailure { error, headers: Vec::new() }))
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        match self {
            Failure::Api(failure) => {
                let ApiFailure { error, headers } = *failure;
                let mut response = json_bytes(error.status(), error.body_bytes());
                for (name, value) in headers {
                    if let Ok(value) = HeaderValue::from_str(&value) {
                        response.headers_mut().insert(name, value);
                    }
                }
                response
            }
            Failure::Internal(message) => {
                eprintln!("ERROR unhandled error while serving a request: {message}");
                unhandled()
            }
        }
    }
}

/// `Set-Cookie` as `http.cookies.Morsel` renders Starlette's `set_cookie` (attributes in sorted
/// key order: `expires`, `HttpOnly`, `Max-Age`, `Path`, `SameSite`, `Secure`).
#[derive(Debug, Clone, Default)]
pub struct Cookie<'a> {
    pub name: &'a str,
    pub value: &'a str,
    pub max_age: Option<i64>,
    pub expires: Option<&'a str>,
    pub path: Option<&'a str>,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: Option<&'a str>,
}

impl Cookie<'_> {
    /// The header value.
    pub fn render(&self) -> String {
        let mut out = format!("{}={}", self.name, quote_cookie_value(self.value));
        if let Some(expires) = self.expires {
            out.push_str(&format!("; expires={expires}"));
        }
        if self.httponly {
            out.push_str("; HttpOnly");
        }
        if let Some(max_age) = self.max_age {
            out.push_str(&format!("; Max-Age={max_age}"));
        }
        if let Some(path) = self.path {
            out.push_str(&format!("; Path={path}"));
        }
        if let Some(samesite) = self.samesite {
            out.push_str(&format!("; SameSite={samesite}"));
        }
        if self.secure {
            out.push_str("; Secure");
        }
        out
    }

    /// Starlette's `delete_cookie(name, path="/")`.
    pub fn deletion(name: &str) -> String {
        Cookie {
            name,
            value: "",
            max_age: Some(0),
            expires: Some("Thu, 01 Jan 1970 00:00:00 GMT"),
            path: Some("/"),
            samesite: Some("lax"),
            ..Cookie::default()
        }
        .render()
    }
}

/// `http.cookies._quote`: unchanged when every character is legal, else double-quoted with `"`
/// and `\` escaped and other characters below 256 that are not printable as `\ooo`.
pub fn quote_cookie_value(value: &str) -> String {
    const LEGAL: &str = "!#$%&'*+-.^_`|~:";
    let legal = |ch: char| ch.is_ascii_alphanumeric() || LEGAL.contains(ch);
    if !value.is_empty() && value.chars().all(legal) {
        return value.to_string();
    }
    const UNESCAPED: &str = " ()/<=>?@[]{}";
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if legal(ch) || UNESCAPED.contains(ch) || ch as u32 >= 256 => out.push(ch),
            ch => out.push_str(&format!("\\{:03o}", ch as u32)),
        }
    }
    out.push('"');
    out
}

/// Appends a `Set-Cookie` header.
pub fn add_cookie(response: &mut Response, header: &str) {
    if let Ok(value) = HeaderValue::from_str(header) {
        response.headers_mut().append(http::header::SET_COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_render_like_morsel() {
        let session = Cookie {
            name: "panel_session",
            value: "abc",
            max_age: Some(43200),
            path: Some("/"),
            secure: true,
            httponly: true,
            samesite: Some("strict"),
            ..Cookie::default()
        };
        assert_eq!(session.render(), "panel_session=abc; HttpOnly; Max-Age=43200; Path=/; SameSite=strict; Secure");
        assert_eq!(
            Cookie::deletion("panel_csrf"),
            "panel_csrf=\"\"; expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; SameSite=lax"
        );
        assert_eq!(quote_cookie_value("a b\"\n"), "\"a b\\\"\\012\"");
    }
}
