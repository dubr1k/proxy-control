//! Starlette's router, reproduced: an ordered list of routes, **first match wins** in
//! registration order (not "static segments before parameters" as in axum's `matchit`).
//!
//! For each request (method, decoded path):
//! - the first route whose template matches the path *and* whose methods include the request's
//!   method handles it (a `{param}` matches `[^/]+`; Python's `$` also matches before one final
//!   `\n`);
//! - otherwise the first route whose template matches (any method) answers 405
//!   `{"detail":"Method Not Allowed"}` with `Allow` = **that route's** methods (FastAPI routes do not
//!   add HEAD to GET);
//! - otherwise, unless the path is `/`, the path with its trailing slashes stripped (or with one
//!   added) is tried against every route regardless of method; a hit is a 307 to that URL built
//!   from the request (`scheme://Host` + path + query);
//! - otherwise 404 `{"detail":"Not Found"}`.
//!
//! A [`Routes`] value is one module's routes in its Python registration order; the app joins the
//! modules in `app.py`'s order (see `crate::routes`). Handlers are axum handlers on
//! [`crate::state::AppState`]; path parameters are read with [`super::request::Call::param`] (the
//! axum `Path` extractor is not available: the template matching is this module's).

use std::sync::Arc;

use axum::body::Body;
use axum::handler::Handler;
use axum::response::Response;
use axum::routing::MethodRouter;
use http::{HeaderValue, Method, Request};

use super::request::{PathParams, RequestMeta};
use super::response;
use crate::state::AppState;

/// One piece of a compiled template.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Literal(String),
    Param(String),
}

#[derive(Clone)]
enum Target {
    Handler(Box<MethodRouter<AppState>>),
    /// `Mount("/static", StaticFiles(directory=…))`.
    Static,
}

/// One route: its methods, its template, what serves it, and whether OpenAPI lists it.
#[derive(Clone)]
pub struct Route {
    methods: Vec<Method>,
    template: &'static str,
    pieces: Vec<Piece>,
    target: Target,
    in_schema: bool,
}

impl Route {
    pub fn methods(&self) -> &[Method] {
        &self.methods
    }

    pub fn template(&self) -> &'static str {
        self.template
    }

    /// Whether the route is part of the OpenAPI document.
    pub fn in_schema(&self) -> bool {
        self.in_schema
    }

    /// The path parameters when `path` matches the template.
    fn matches(&self, path: &str) -> Option<Vec<(String, String)>> {
        match self.target {
            Target::Static => {
                // `^/static/(?P<path>.*)$`: `.` stops at a newline; `$` allows one final `\n`.
                let rest = path.strip_prefix("/static/")?;
                let rest = rest.strip_suffix('\n').unwrap_or(rest);
                (!rest.contains('\n')).then(|| vec![("path".to_string(), rest.to_string())])
            }
            Target::Handler(_) => match_template(&self.pieces, path).or_else(|| {
                let trimmed = path.strip_suffix('\n')?;
                matches!(self.pieces.last(), Some(Piece::Literal(_))).then(|| match_template(&self.pieces, trimmed))?
            }),
        }
    }
}

/// Splits `/a/{b}/c` into literal and parameter pieces (parameters are whole segments in every
/// panel template).
fn compile(template: &str) -> Vec<Piece> {
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        literal.push_str(&rest[..open]);
        let close = rest[open..].find('}').map(|offset| open + offset).expect("unclosed template parameter");
        if !literal.is_empty() {
            pieces.push(Piece::Literal(std::mem::take(&mut literal)));
        }
        pieces.push(Piece::Param(rest[open + 1..close].to_string()));
        rest = &rest[close + 1..];
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        pieces.push(Piece::Literal(literal));
    }
    pieces
}

/// The template regex `^…$` (without the final-newline allowance): literals exact, parameters
/// `[^/]+` (greedy; the next literal starts with `/`, or the parameter ends the template).
fn match_template(pieces: &[Piece], path: &str) -> Option<Vec<(String, String)>> {
    let mut params = Vec::new();
    let mut rest = path;
    for (index, piece) in pieces.iter().enumerate() {
        match piece {
            Piece::Literal(text) => rest = rest.strip_prefix(text.as_str())?,
            Piece::Param(name) => {
                let end = rest.find('/').unwrap_or(rest.len());
                if end == 0 {
                    return None;
                }
                let is_last = index + 1 == pieces.len();
                if is_last && end != rest.len() {
                    return None;
                }
                params.push((name.clone(), rest[..end].to_string()));
                rest = &rest[end..];
            }
        }
    }
    rest.is_empty().then_some(params)
}

/// One module's routes, in registration order.
#[derive(Clone, Default)]
pub struct Routes {
    routes: Vec<Route>,
}

impl Routes {
    pub fn new() -> Self {
        Self::default()
    }

    /// A route answering `methods` (FastAPI's `api_route`).
    pub fn route<H, T>(mut self, methods: &[Method], template: &'static str, handler: H) -> Self
    where
        H: Handler<T, AppState>,
        T: 'static,
    {
        self.routes.push(Route {
            methods: methods.to_vec(),
            template,
            pieces: compile(template),
            target: Target::Handler(Box::new(axum::routing::any(handler))),
            in_schema: true,
        });
        self
    }

    pub fn get<H: Handler<T, AppState>, T: 'static>(self, template: &'static str, handler: H) -> Self {
        self.route(&[Method::GET], template, handler)
    }

    pub fn post<H: Handler<T, AppState>, T: 'static>(self, template: &'static str, handler: H) -> Self {
        self.route(&[Method::POST], template, handler)
    }

    pub fn put<H: Handler<T, AppState>, T: 'static>(self, template: &'static str, handler: H) -> Self {
        self.route(&[Method::PUT], template, handler)
    }

    pub fn patch<H: Handler<T, AppState>, T: 'static>(self, template: &'static str, handler: H) -> Self {
        self.route(&[Method::PATCH], template, handler)
    }

    pub fn delete<H: Handler<T, AppState>, T: 'static>(self, template: &'static str, handler: H) -> Self {
        self.route(&[Method::DELETE], template, handler)
    }

    /// Marks the last route `include_in_schema=False`.
    pub fn hidden(mut self) -> Self {
        if let Some(route) = self.routes.last_mut() {
            route.in_schema = false;
        }
        self
    }

    /// `app.mount("/static", StaticFiles(…))`.
    pub fn static_mount(mut self) -> Self {
        self.routes.push(Route {
            methods: Vec::new(),
            template: "/static",
            pieces: Vec::new(),
            target: Target::Static,
            in_schema: false,
        });
        self
    }

    /// Appends another module's routes after these.
    pub fn merge(mut self, other: Routes) -> Self {
        self.routes.extend(other.routes);
        self
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Binds the handlers to the state.
    pub fn into_dispatcher(self, state: AppState) -> Dispatcher {
        let routes = self
            .routes
            .into_iter()
            .map(|route| {
                let target = match route.target.clone() {
                    Target::Handler(handler) => Bound::Handler(Box::new(handler.with_state(state.clone()))),
                    Target::Static => Bound::Static,
                };
                (route, target)
            })
            .collect();
        Dispatcher { inner: Arc::new(DispatcherInner { routes, state }) }
    }
}

enum Bound {
    Handler(Box<MethodRouter<()>>),
    Static,
}

struct DispatcherInner {
    routes: Vec<(Route, Bound)>,
    state: AppState,
}

/// The bound route table.
#[derive(Clone)]
pub struct Dispatcher {
    inner: Arc<DispatcherInner>,
}

impl Dispatcher {
    /// Routes one request (the inner end of the stages).
    pub async fn dispatch(&self, mut request: Request<Body>) -> Response {
        let meta = request.extensions().get::<RequestMeta>().cloned().expect("request meta is set by the server");
        let method = request.method().clone();
        let mut partial: Option<&Route> = None;
        for (route, bound) in &self.inner.routes {
            let Some(params) = route.matches(&meta.path) else {
                continue;
            };
            let full = matches!(bound, Bound::Static) || route.methods.contains(&method);
            if !full {
                partial = partial.or(Some(route));
                continue;
            }
            request.extensions_mut().insert(PathParams(params.clone()));
            return match bound {
                Bound::Handler(handler) => {
                    let mut handler = (**handler).clone();
                    match tower_service::Service::<Request<Body>>::call(&mut handler, request).await {
                        Ok(response) => response,
                        Err(never) => match never {},
                    }
                }
                Bound::Static => {
                    let relative = params.into_iter().next().map(|(_, value)| value).unwrap_or_default();
                    let (parts, _) = request.into_parts();
                    super::static_files::serve(&self.inner.state, &parts.method, &parts.headers, &relative).await
                }
            };
        }
        if let Some(route) = partial {
            let allow = route.methods.iter().map(Method::as_str).collect::<Vec<_>>().join(", ");
            let mut answer = response::json(405, &serde_json::json!({"detail": "Method Not Allowed"}));
            if let Ok(value) = HeaderValue::from_str(&allow) {
                answer.headers_mut().insert(http::header::ALLOW, value);
            }
            return answer;
        }
        if meta.path != "/" {
            let other = match meta.path.strip_suffix('/') {
                Some(_) => meta.path.trim_end_matches('/').to_string(),
                None => format!("{}/", meta.path),
            };
            if self.inner.routes.iter().any(|(route, _)| route.matches(&other).is_some()) {
                let url = request_url(&request, &meta, &other);
                return response::redirect(307, &url);
            }
        }
        response::json(404, &serde_json::json!({"detail": "Not Found"}))
    }
}

/// Starlette's `_HOST_RE`: `^([a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9.:]+\])(?::[0-9]+)?$`, any case.
pub fn is_url_host(host: &str) -> bool {
    let (name, port) = if let Some(rest) = host.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return false;
        };
        let inner = &rest[..close];
        let Some(colon) = inner.find(':') else {
            return false;
        };
        let (head, tail) = (&inner[..colon], &inner[colon + 1..]);
        let hex = |ch: char| ch.is_ascii_hexdigit();
        if !head.chars().all(hex) || tail.is_empty() || !tail.chars().all(|ch| hex(ch) || ch == '.' || ch == ':') {
            return false;
        }
        (true, &rest[close + 1..])
    } else {
        let end = host.find(':').unwrap_or(host.len());
        let name = &host[..end];
        let valid = !name.is_empty() && name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-');
        (valid, &host[end..])
    };
    name && (port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit())))
}

/// `str(URL(scope=…))` with `path` in place of the request's: `scheme://netloc/path?query`, the
/// netloc from a well-formed `Host` header, else from the server address, else only the path.
pub fn request_url<B>(request: &Request<B>, meta: &RequestMeta, path: &str) -> String {
    let host = request.headers().get(http::header::HOST).map(|value| super::request::latin1(value.as_bytes()));
    let netloc = match host {
        Some(host) if is_url_host(&host) => Some(host),
        _ => meta.server.as_ref().map(|(host, port)| {
            let default = if meta.scheme == "https" || meta.scheme == "wss" { 443 } else { 80 };
            if *port == default {
                host.clone()
            } else {
                format!("{host}:{port}")
            }
        }),
    };
    let query = &meta.query;
    let mut url = match netloc {
        Some(netloc) => format!("{}://{netloc}{path}", meta.scheme),
        None => path.to_string(),
    };
    if !query.is_empty() {
        url.push('?');
        url.push_str(query);
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_match_like_starlette_regexes() {
        let pieces = compile("/api/users/{username}/{operation}");
        assert_eq!(
            match_template(&pieces, "/api/users/a b/x"),
            Some(vec![("username".into(), "a b".into()), ("operation".into(), "x".into())])
        );
        assert_eq!(match_template(&pieces, "/api/users//x"), None);
        assert_eq!(match_template(&pieces, "/api/users/a/x/"), None);
        let healthz = Route {
            methods: vec![Method::GET],
            template: "/healthz",
            pieces: compile("/healthz"),
            target: Target::Handler(Box::new(axum::routing::any(|| async {}))),
            in_schema: true,
        };
        assert!(healthz.matches("/healthz\n").is_some());
        assert!(healthz.matches("/healthz\n\n").is_none());
        let reveal =
            Route { template: "/api/reveal/{token}", pieces: compile("/api/reveal/{token}"), ..healthz.clone() };
        assert_eq!(reveal.matches("/api/reveal/abc\n"), Some(vec![("token".into(), "abc\n".into())]));
    }

    #[test]
    fn hosts_follow_starlettes_pattern() {
        for good in ["testserver", "a.b-c:8080", "[::1]:80", "[fe80::1]", "TESTSERVER"] {
            assert!(is_url_host(good), "{good}");
        }
        for bad in ["", "a_b", "a:", "a:x", "[::1", "[1]", "a b"] {
            assert!(!is_url_host(bad), "{bad}");
        }
    }
}
