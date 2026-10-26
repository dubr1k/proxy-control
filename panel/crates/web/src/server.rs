//! The HTTP server: uvicorn's role (HTTP/1.1, proxy headers, no access log) and the ASGI middleware
//! stack of `create_app`, outermost first:
//!
//! 1. `ServerErrorMiddleware` — a panic (an unhandled exception) is the bare
//!    `500 Internal Server Error`, without security headers;
//! 2. uvicorn's `ProxyHeadersMiddleware` (`--proxy-headers --forwarded-allow-ips 172.16.0.0/12`) —
//!    the client address from `X-Forwarded-For` and the scheme from `X-Forwarded-Proto`, only when the
//!    TCP peer is in 172.16.0.0/12;
//! 3. `SecurityHeadersMiddleware` — request id (`token_hex(8)`) and the fixed headers on every
//!    response, the subscription CSP (and no forced `Cache-Control`) under `/s/`;
//! 4. `BoundedBodyMiddleware` — the body read whole up to 64 KiB: a `Content-Length` that is not
//!    decimal or over the limit, or a longer streamed body, is 413; an interrupted body is 400;
//! 5. `TrustedHostMiddleware` — `PANEL_ALLOWED_HOSTS` (`*.suffix` wildcards, `www.` redirect),
//!    else 400 `Invalid host header`;
//! 6. the router ([`crate::http::router`]).
//!
//! Listeners: `0.0.0.0:8787` by default; `PANEL_LISTEN=unix:<path>` (tests, ops) or
//! `PANEL_LISTEN=tcp:<host>:<port>`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::time::Duration;

use axum::body::Body;
use axum::response::Response;
use bytes::{Bytes, BytesMut};
use futures_util::FutureExt as _;
use http::header::{HeaderName, HeaderValue};
use http::Request;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};

use crate::http::request::{latin1, RequestMeta};
use crate::http::response::{self, UnhandledError};
use crate::http::router::{self, Dispatcher};
use crate::state::AppState;

/// The CSP of the subscription page (`subscriptions/page_assets.py` `CSP`): sha256 of its inline
/// style and script. Recorded from Python; the subscription package (WP9) must keep its page
/// byte-identical to these hashes (`tests/python_constants.rs` checks the value).
pub const SUBSCRIPTION_CSP: &str = "default-src 'none'; style-src 'sha256-7zrdh6FLXrs4+7ooaZeyFT55YBE79eotFOMQmu4tyvQ='; script-src 'sha256-prNdb/NLfe2hab7XNPF7XOM4DZuWYWGhoq4UthMMFQ0='; img-src data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const PANEL_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// Where to listen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listen {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Listen {
    /// `PANEL_LISTEN`: unset → `0.0.0.0:8787`; `unix:<path>`; `tcp:<host>:<port>`.
    pub fn from_env(value: Option<&str>) -> Result<Self, String> {
        match value.filter(|value| !value.is_empty()) {
            None => Ok(Listen::Tcp(SocketAddr::from(([0, 0, 0, 0], 8787)))),
            Some(value) => {
                if let Some(path) = value.strip_prefix("unix:") {
                    if path.is_empty() {
                        return Err("PANEL_LISTEN=unix:<path> needs a path".into());
                    }
                    Ok(Listen::Unix(PathBuf::from(path)))
                } else if let Some(address) = value.strip_prefix("tcp:") {
                    address.parse().map(Listen::Tcp).map_err(|_| format!("PANEL_LISTEN: bad address {address:?}"))
                } else {
                    Err(format!("PANEL_LISTEN must be unix:<path> or tcp:<host>:<port>, not {value:?}"))
                }
            }
        }
    }
}

/// The connection a request came on.
#[derive(Debug, Clone)]
pub struct Peer {
    /// The TCP peer (none on a Unix socket).
    pub remote: Option<SocketAddr>,
    /// The local address (`scope["server"]`).
    pub local: Option<SocketAddr>,
}

/// The whole stack for one request.
#[derive(Clone)]
pub struct Stack {
    state: AppState,
    dispatcher: Dispatcher,
}

impl Stack {
    pub fn new(state: AppState, dispatcher: Dispatcher) -> Self {
        Self { state, dispatcher }
    }

    /// Serves one request (`ServerErrorMiddleware` outermost).
    pub async fn handle<B>(&self, peer: &Peer, request: Request<B>) -> Response
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::fmt::Display,
    {
        match AssertUnwindSafe(self.handle_inner(peer, request)).catch_unwind().await {
            Ok(response) => response,
            Err(_) => {
                eprintln!("ERROR a request handler panicked");
                response::unhandled()
            }
        }
    }

    async fn handle_inner<B>(&self, peer: &Peer, request: Request<B>) -> Response
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::fmt::Display,
    {
        let (client_ip, scheme) = proxy_headers(peer, request.headers());
        let path = panel_core::pytext::unquote(request.uri().path());
        let meta = RequestMeta {
            request_id: panel_core::ids::token_hex(8),
            client_ip,
            scheme,
            server: peer.local.map(|address| (address.ip().to_string(), address.port())),
            query: request.uri().query().unwrap_or_default().to_string(),
            path,
        };
        let subscription = meta.path.starts_with("/s/");
        let request_id = meta.request_id.clone();
        let mut response = self.bounded(meta, request).await;
        if response.extensions().get::<UnhandledError>().is_none() {
            let headers = response.headers_mut();
            let csp = if subscription { SUBSCRIPTION_CSP } else { PANEL_CSP };
            headers.insert(http::header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(csp));
            headers.insert(http::header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
            headers.insert(http::header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
            headers.insert(http::header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
            headers.insert(
                HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
            );
            if !subscription {
                headers.insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            }
            if let Ok(value) = HeaderValue::from_str(&request_id) {
                headers.insert(HeaderName::from_static("x-request-id"), value);
            }
        }
        response
    }

    /// `BoundedBodyMiddleware`, then the host check and the router.
    async fn bounded<B>(&self, meta: RequestMeta, request: Request<B>) -> Response
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::fmt::Display,
    {
        let limit = usize::try_from(self.state.settings.body_limit_bytes.max(0)).unwrap_or(usize::MAX);
        let too_large = || response::json(413, &serde_json::json!({"detail": "request body too large"}));
        for value in request.headers().get_all(http::header::CONTENT_LENGTH) {
            let text = latin1(value.as_bytes());
            let decimal = !text.is_empty() && text.chars().all(|ch| panel_core::pytext::decimal(ch).is_some());
            let fits = decimal
                && text
                    .chars()
                    .filter_map(panel_core::pytext::decimal)
                    .try_fold(0usize, |total, digit| {
                        total.checked_mul(10).and_then(|total| total.checked_add(digit as usize))
                    })
                    .is_some_and(|length| length <= limit);
            if !fits {
                return too_large();
            }
        }
        let (parts, body) = request.into_parts();
        let mut body = Box::pin(body);
        let mut collected = BytesMut::new();
        loop {
            match body.frame().await {
                None => break,
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if collected.len() + data.len() > limit {
                            return too_large();
                        }
                        collected.extend_from_slice(&data);
                    }
                }
                Some(Err(_)) => {
                    return response::json(400, &serde_json::json!({"detail": "incomplete request body"}));
                }
            }
        }
        let mut request = Request::from_parts(parts, Body::from(collected.freeze()));
        if let Some(refused) = self.trusted_host(&meta, &request) {
            return refused;
        }
        request.extensions_mut().insert(meta);
        self.dispatcher.dispatch(request).await
    }

    /// `TrustedHostMiddleware(allowed_hosts=PANEL_ALLOWED_HOSTS)`.
    fn trusted_host(&self, meta: &RequestMeta, request: &Request<Body>) -> Option<Response> {
        let allowed = &self.state.settings.allowed_hosts;
        if allowed.iter().any(|pattern| pattern == "*") {
            return None;
        }
        let header =
            request.headers().get(http::header::HOST).map(|value| latin1(value.as_bytes())).unwrap_or_default();
        let host = header.split(':').next().unwrap_or_default();
        let mut www = false;
        for pattern in allowed {
            if host == pattern || (pattern.starts_with('*') && host.ends_with(&pattern[1..])) {
                return None;
            }
            if format!("www.{host}") == *pattern {
                www = true;
            }
        }
        if www {
            let url = router::request_url(request, meta, &meta.path);
            let target = match url.split_once("://") {
                Some((scheme, rest)) => format!("{scheme}://www.{rest}"),
                None => format!("//www.{url}"),
            };
            return Some(response::redirect(307, &target));
        }
        Some(response::plain(400, "Invalid host header"))
    }
}

/// Starlette's pattern rule for `allowed_hosts` (an `AssertionError` at start-up in Python).
pub fn check_allowed_hosts(hosts: &[String]) -> Result<(), String> {
    const ENFORCE: &str = "Domain wildcard patterns must be like '*.example.com'.";
    for pattern in hosts {
        if pattern.chars().skip(1).any(|ch| ch == '*')
            || (pattern.starts_with('*') && pattern != "*" && !pattern.starts_with("*."))
        {
            return Err(ENFORCE.to_string());
        }
    }
    Ok(())
}

/// uvicorn's `ProxyHeadersMiddleware` with `trusted_hosts="172.16.0.0/12"`: the client host and
/// scheme. Without a TCP peer the client is `"unknown"` (`RequestContext.client_ip`).
pub fn proxy_headers(peer: &Peer, headers: &http::HeaderMap) -> (String, String) {
    let mut client = peer.remote.map(|address| address.ip().to_string());
    let mut scheme = "http".to_string();
    let trusted = |host: &str| -> bool {
        if host.is_empty() {
            return false;
        }
        match panel_core::pytext::ip_address(host) {
            Ok(panel_core::pytext::IpAddress::V4(value)) => (value & 0xfff0_0000) == 0xac10_0000,
            _ => false,
        }
    };
    if client.as_deref().is_some_and(trusted) {
        // `dict(scope["headers"])`: the last value of a repeated header wins.
        let last = |name: &str| headers.get_all(name).iter().next_back().map(|value| latin1(value.as_bytes()));
        if let Some(proto) = last("x-forwarded-proto") {
            let proto = panel_core::pytext::strip(&proto);
            if matches!(proto, "http" | "https" | "ws" | "wss") {
                scheme = proto.to_string();
            }
        }
        if let Some(forwarded) = last("x-forwarded-for") {
            let hosts: Vec<&str> = forwarded.split(',').map(panel_core::pytext::strip).collect();
            let chosen = hosts.iter().rev().find(|host| !trusted(host)).copied().unwrap_or(hosts[0]);
            if !chosen.is_empty() {
                client = Some(chosen.to_string());
            }
        }
    }
    (client.unwrap_or_else(|| "unknown".into()), scheme)
}

/// Accepts connections until `shutdown` resolves, then lets open requests finish (up to 10 s).
pub async fn serve(
    stack: Stack,
    listen: Listen,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> std::io::Result<()> {
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let builder = {
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder.timer(TokioTimer::new());
        builder
    };
    enum Acceptor {
        Tcp(tokio::net::TcpListener),
        Unix(tokio::net::UnixListener, PathBuf),
    }
    let acceptor = match &listen {
        Listen::Tcp(address) => Acceptor::Tcp(tokio::net::TcpListener::bind(address).await?),
        Listen::Unix(path) => {
            use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
            if std::fs::symlink_metadata(path).is_ok_and(|info| info.file_type().is_socket()) {
                std::fs::remove_file(path)?;
            }
            let listener = tokio::net::UnixListener::bind(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
            Acceptor::Unix(listener, path.clone())
        }
    };
    tokio::pin!(shutdown);
    loop {
        let accepted = tokio::select! {
            _ = &mut shutdown => break,
            accepted = async {
                match &acceptor {
                    Acceptor::Tcp(listener) => listener.accept().await.map(|(stream, remote)| {
                        let local = stream.local_addr().ok();
                        let _ = stream.set_nodelay(true);
                        (Conn::Tcp(stream), Peer { remote: Some(remote), local })
                    }),
                    Acceptor::Unix(listener, _) => listener
                        .accept()
                        .await
                        .map(|(stream, _)| (Conn::Unix(stream), Peer { remote: None, local: None })),
                }
            } => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("WARNING accept failed: {error}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let stack = stack.clone();
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            let (stack, peer) = (stack.clone(), peer.clone());
            async move { Ok::<_, Infallible>(stack.handle(&peer, request).await) }
        });
        match stream {
            Conn::Tcp(stream) => {
                let connection = builder.serve_connection(TokioIo::new(stream), service);
                let watched = graceful.watch(connection);
                tokio::spawn(async move {
                    let _ = watched.await;
                });
            }
            Conn::Unix(stream) => {
                let connection = builder.serve_connection(TokioIo::new(stream), service);
                let watched = graceful.watch(connection);
                tokio::spawn(async move {
                    let _ = watched.await;
                });
            }
        }
    }
    if let Acceptor::Unix(_, path) = &acceptor {
        let _ = std::fs::remove_file(path);
    }
    drop(acceptor);
    let _ = tokio::time::timeout(Duration::from_secs(10), graceful.shutdown()).await;
    Ok(())
}

enum Conn {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(remote: &str) -> Peer {
        Peer { remote: Some(remote.parse().unwrap()), local: None }
    }

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (name, value) in pairs {
            map.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn forwarded_headers_count_only_from_the_docker_network() {
        let forwarded =
            headers(&[("x-forwarded-for", "198.51.100.1, 203.0.113.7, 172.18.0.9"), ("x-forwarded-proto", " https ")]);
        assert_eq!(proxy_headers(&peer("172.18.0.2:5000"), &forwarded), ("203.0.113.7".into(), "https".into()));
        assert_eq!(proxy_headers(&peer("192.0.2.1:5000"), &forwarded), ("192.0.2.1".into(), "http".into()));
        assert_eq!(proxy_headers(&Peer { remote: None, local: None }, &forwarded), ("unknown".into(), "http".into()));
        let trailing_empty = headers(&[("x-forwarded-for", "203.0.113.7, ")]);
        assert_eq!(proxy_headers(&peer("172.31.255.1:1"), &trailing_empty).0, "172.31.255.1");
        let all_trusted = headers(&[("x-forwarded-for", "172.16.0.5, 172.17.0.1"), ("x-forwarded-proto", "ftp")]);
        assert_eq!(proxy_headers(&peer("172.20.0.1:1"), &all_trusted), ("172.16.0.5".into(), "http".into()));
        let literal = headers(&[("x-forwarded-for", "unknown"), ("x-forwarded-for", "10.0.0.1")]);
        assert_eq!(proxy_headers(&peer("172.20.0.1:1"), &literal).0, "10.0.0.1");
        assert_eq!(proxy_headers(&peer("172.32.0.1:1"), &literal).0, "172.32.0.1");
    }

    #[test]
    fn allowed_host_patterns_are_checked() {
        assert!(check_allowed_hosts(&["*".into(), "*.a.example".into(), "b".into()]).is_ok());
        assert!(check_allowed_hosts(&["*a.example".into()]).is_err());
        assert!(check_allowed_hosts(&["a.*.example".into()]).is_err());
    }

    #[test]
    fn listen_addresses_parse() {
        assert_eq!(Listen::from_env(None), Ok(Listen::Tcp("0.0.0.0:8787".parse().unwrap())));
        assert_eq!(Listen::from_env(Some("unix:/tmp/p.sock")), Ok(Listen::Unix("/tmp/p.sock".into())));
        assert_eq!(Listen::from_env(Some("tcp:127.0.0.1:9")), Ok(Listen::Tcp("127.0.0.1:9".parse().unwrap())));
        assert!(Listen::from_env(Some("8787")).is_err());
    }
}
