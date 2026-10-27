//! The HTTP application: `/healthz` open for the container's health check, `/mcp` — Streamable
//! HTTP, stateless, JSON responses — behind a bearer token compared in constant time, with the
//! DNS-rebinding protection limited to the hosts the installer named.
//!
//! The order of the checks is the Python server's: the bearer gate first (everything but
//! `/healthz`), then the routes, then on `/mcp` the body limit, the `Content-Type` of a POST, the
//! `Host` and the `Origin`, then the transport's own rules (`crate::transport`); only then does
//! the MCP SDK see the request.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, ACCEPT, ALLOW, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, WWW_AUTHENTICATE};
use hyper::{Method, Request, Response, StatusCode};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ClientJsonRpcMessage, CompleteRequestParams,
    CompleteResult, ContentBlock, ErrorCode, ExperimentalCapabilities, Implementation, ListPromptsResult,
    ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Resource, ResourceContents,
    ResourcesCapability, ServerCapabilities, ServerConfig, Tool, ToolsCapability,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use tower_service::Service;

use crate::py::PyErr;
use crate::tools::{Fail, ToolRegistry, ToolResult};
use crate::transport;

pub const SERVER_NAME: &str = "proxy-control";
pub const SERVER_VERSION: &str = "0.11";
pub const INSTRUCTIONS: &str =
    "Proxy Control panel over MCP. Curated tools (overview, create_client, client_subscription, \
set_client_placement, versions_check, versions_update, routing_preview, routing_apply, audit_tail) cover \
the everyday moves; every other panel operation is a generated tool named <method>_<path>. Operations \
that cannot be undone take `confirm: true` and only describe themselves without it. Errors from the panel \
come back as error results with the panel's own `detail`/`code`.";
/// The SDK's request body limit (4 MiB).
pub const MAX_BODY: u64 = 4 * 1024 * 1024;
pub const LOG: &str = "proxy-control-mcp";

pub type Body = BoxBody<Bytes, Infallible>;

/// The MCP side: the registry behind the SDK's server handler.
#[derive(Clone)]
pub struct Handler {
    registry: Arc<ToolRegistry>,
}

/// A Python exception escaping a handler: the SDK answered JSON-RPC code 0 with `str(exc)`.
fn handler_error(method: &str, err: &PyErr) -> ErrorData {
    log::error!(target: "mcp.shared.jsonrpc_dispatcher", "handler for '{method}' raised {}: {}", err.kind, err.message);
    ErrorData::new(ErrorCode(0), err.message.clone(), None)
}

fn tool_result(result: ToolResult) -> CallToolResult {
    let content = vec![ContentBlock::text(result.text)];
    if result.is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    }
}

/// A method the Python server had no handler for.
fn method_not_found(method: &str) -> ErrorData {
    ErrorData::new(ErrorCode::METHOD_NOT_FOUND, "Method not found", Some(serde_json::json!(method)))
}

impl ServerHandler for Handler {
    async fn complete(
        &self,
        _request: CompleteRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, ErrorData> {
        Err(method_not_found("completion/complete"))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        Err(method_not_found("prompts/list"))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Err(method_not_found("resources/templates/list"))
    }

    fn get_info(&self) -> ServerConfig {
        let mut tools = ToolsCapability::default();
        tools.list_changed = Some(false);
        let mut resources = ResourcesCapability::default();
        resources.subscribe = Some(false);
        resources.list_changed = Some(false);
        let mut capabilities = ServerCapabilities::default();
        capabilities.experimental = Some(ExperimentalCapabilities::default());
        capabilities.tools = Some(tools);
        capabilities.resources = Some(resources);
        ServerConfig::new(capabilities)
            .with_server_info(Implementation::new(SERVER_NAME, SERVER_VERSION))
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = self
            .registry
            .tools()
            .into_iter()
            .map(|tool| Tool::new(tool.name, tool.description, Arc::new(tool.input_schema)))
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        match self.registry.call(&request.name, request.arguments).await {
            Ok(result) => Ok(tool_result(result).into()),
            Err(err) => Err(handler_error("tools/call", &err)),
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let resources = self
            .registry
            .resources()
            .into_iter()
            .map(|resource| {
                let mut entry = Resource::new(resource.uri, resource.name);
                entry.description = Some(resource.description.into());
                entry.mime_type = Some("application/json".into());
                entry
            })
            .collect();
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        match self.registry.read_resource(&request.uri).await {
            Ok(text) => {
                let contents = ResourceContents::text(text, request.uri.clone()).with_mime_type("application/json");
                Ok(ReadResourceResult::new(vec![contents]).into())
            }
            // The Python server raised ValueError(f"{detail} ({status})") for a panel refusal.
            Err(Fail::Panel(err)) => Err(handler_error(
                "resources/read",
                &PyErr::new("ValueError", format!("{} ({})", err.detail, err.status)),
            )),
            Err(Fail::Py(err)) => Err(handler_error("resources/read", &err)),
        }
    }
}

/// Everything one HTTP request needs.
pub struct App {
    token: Vec<u8>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    mcp: StreamableHttpService<Handler, NeverSessionManager>,
    /// Set when the server stops: open event streams end so the connections can close.
    shutdown: tokio::sync::watch::Sender<bool>,
}

fn full(status: StatusCode, body: impl Into<Bytes>) -> Response<Body> {
    let mut response = Response::new(Full::new(body.into()).boxed());
    *response.status_mut() = status;
    response
}

fn json_response(status: StatusCode, body: &'static str) -> Response<Body> {
    let mut response = full(status, body);
    response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn text_response(status: StatusCode, body: &'static str) -> Response<Body> {
    let mut response = full(status, body);
    response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    response
}

/// A header the way Starlette reads it: the raw bytes as latin-1 text.
fn header_text(request: &Request<Incoming>, name: impl hyper::header::AsHeaderName) -> Option<String> {
    request.headers().get(name).map(|value| value.as_bytes().iter().map(|&b| char::from(b)).collect())
}

/// An exact entry, or `name:*` for any port.
fn listed(value: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|entry| {
        entry == value || entry.strip_suffix(":*").is_some_and(|base| value.starts_with(&format!("{base}:")))
    })
}

impl App {
    pub fn new(registry: Arc<ToolRegistry>, token: &str, allowed_hosts: &[String]) -> Self {
        let handler = Handler { registry };
        let config = StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_sse_keep_alive(None)
            .with_max_request_body_bytes(MAX_BODY as usize)
            // Host and Origin are checked here, with the Python server's rules and status codes.
            .disable_allowed_hosts()
            .disable_allowed_origins();
        let mcp =
            StreamableHttpService::new(move || Ok(handler.clone()), Arc::new(NeverSessionManager::default()), config);
        let allowed_origins = allowed_hosts
            .iter()
            .map(|host| format!("https://{host}"))
            .chain(allowed_hosts.iter().map(|host| format!("http://{host}")))
            .collect();
        Self {
            token: token.as_bytes().to_vec(),
            allowed_hosts: allowed_hosts.to_vec(),
            allowed_origins,
            mcp,
            shutdown: tokio::sync::watch::channel(false).0,
        }
    }

    /// `Authorization: Bearer <token>`: the scheme case-insensitive, the credential stripped.
    fn authorized(&self, request: &Request<Incoming>) -> bool {
        let header = header_text(request, hyper::header::AUTHORIZATION).unwrap_or_default();
        let (scheme, credential) = header.split_once(' ').unwrap_or((header.as_str(), ""));
        let presented = pc_common::pytext::strip(credential);
        scheme.to_lowercase() == "bearer"
            && !presented.is_empty()
            && pc_common::constant_time_eq(presented.as_bytes(), &self.token)
    }

    pub async fn handle(&self, request: Request<Incoming>) -> Response<Body> {
        let path = request.uri().path().to_string();
        if path != "/healthz" && !self.authorized(&request) {
            let mut response = json_response(StatusCode::UNAUTHORIZED, "{\"error\":\"unauthorized\"}");
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer realm=\"proxy-control-mcp\""));
            return response;
        }
        match path.as_str() {
            "/healthz" => {
                if request.method() == Method::GET || request.method() == Method::HEAD {
                    return json_response(StatusCode::OK, "{\"status\":\"ok\"}");
                }
                let mut response = text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
                response.headers_mut().insert(ALLOW, HeaderValue::from_static("HEAD, GET"));
                response
            }
            "/mcp" => self.mcp(request).await,
            _ => self.not_found(&request, &path),
        }
    }

    /// Starlette's router: a path that matches a route once its trailing slash is removed (or
    /// added) is redirected there; anything else is 404.
    fn not_found(&self, request: &Request<Incoming>, path: &str) -> Response<Body> {
        if path != "/" {
            let other = if path.ends_with('/') { path.trim_end_matches('/').to_string() } else { format!("{path}/") };
            if other == "/healthz" || other == "/mcp" {
                let host = header_text(request, HOST).unwrap_or_default();
                let query = request.uri().query().map(|query| format!("?{query}")).unwrap_or_default();
                let mut response = full(StatusCode::TEMPORARY_REDIRECT, Bytes::new());
                if let Ok(location) = HeaderValue::from_str(&format!("http://{host}{other}{query}")) {
                    response.headers_mut().insert(LOCATION, location);
                }
                return response;
            }
        }
        text_response(StatusCode::NOT_FOUND, "Not Found")
    }

    async fn mcp(&self, request: Request<Incoming>) -> Response<Body> {
        let declared = request
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        if declared.is_some_and(|length| length > MAX_BODY) {
            return full(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large");
        }
        if request.method() == Method::POST {
            let content_type = header_text(&request, CONTENT_TYPE);
            if !content_type.is_some_and(|value| value.to_lowercase().starts_with("application/json")) {
                return full(StatusCode::BAD_REQUEST, "Invalid Content-Type header");
            }
        }
        let host = header_text(&request, HOST).unwrap_or_default();
        if host.is_empty() {
            log::warn!(target: "mcp.server.transport_security", "Missing Host header in request");
            return full(StatusCode::MISDIRECTED_REQUEST, "Invalid Host header");
        }
        if !listed(&host, &self.allowed_hosts) {
            log::warn!(target: "mcp.server.transport_security", "Invalid Host header: {host}");
            return full(StatusCode::MISDIRECTED_REQUEST, "Invalid Host header");
        }
        let origin = header_text(&request, hyper::header::ORIGIN).unwrap_or_default();
        if !origin.is_empty() && !listed(&origin, &self.allowed_origins) {
            log::warn!(target: "mcp.server.transport_security", "Invalid Origin header: {origin}");
            return full(StatusCode::FORBIDDEN, "Invalid Origin header");
        }
        let version = header_text(&request, "mcp-protocol-version");
        if version.is_some_and(|version| !transport::HANDSHAKE_VERSIONS.contains(&version.as_str())) {
            // The 2026 per-request envelope: the SDK's own stateless path.
            let server_info = serde_json::json!({"name": SERVER_NAME, "version": SERVER_VERSION});
            return transport::modern_shaped(self.forward(request).await, server_info).await;
        }
        match *request.method() {
            Method::POST => self.post(request).await,
            Method::GET => {
                let (_, sse) = transport::accepts(&header_text(&request, ACCEPT).unwrap_or_default());
                if !sse {
                    return transport::not_acceptable("Not Acceptable: Client must accept text/event-stream");
                }
                transport::event_stream(self.shutdown.subscribe())
            }
            Method::DELETE => transport::session_termination(),
            _ => transport::unsupported_method(),
        }
    }

    /// A JSON-RPC POST: checked and parsed the way the Python transport did, then handed to the SDK.
    async fn post(&self, request: Request<Incoming>) -> Response<Body> {
        let (json, _) = transport::accepts(&header_text(&request, ACCEPT).unwrap_or_default());
        if !json {
            return transport::not_acceptable("Not Acceptable: Client must accept application/json");
        }
        if !transport::is_json_content_type(&header_text(&request, CONTENT_TYPE).unwrap_or_default()) {
            return transport::unsupported_media_type();
        }
        let (mut parts, body) = request.into_parts();
        let bytes = match http_body_util::Limited::new(body, MAX_BODY as usize).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) if err.is::<http_body_util::LengthLimitError>() => {
                return full(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large")
            }
            Err(_) => return full(StatusCode::BAD_REQUEST, "Bad Request"),
        };
        let message: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(message) => message,
            Err(err) => return transport::parse_error(&err),
        };
        if let Err(err) = serde_json::from_value::<ClientJsonRpcMessage>(message) {
            return transport::validation_error(&err);
        }
        // JSON responses only: the SDK asks for both media types, the Python transport for JSON alone.
        parts.headers.insert(ACCEPT, HeaderValue::from_static("application/json, text/event-stream"));
        parts.headers.remove(CONTENT_LENGTH);
        let response = self.forward(Request::from_parts(parts, Full::new(bytes))).await;
        transport::python_shaped(response).await
    }

    async fn forward<B>(&self, request: Request<B>) -> Response<Body>
    where
        B: hyper::body::Body + Send + 'static,
        B::Data: Send + 'static,
        B::Error: std::fmt::Display,
    {
        match self.mcp.clone().call(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        }
    }

    /// Ends the open event streams.
    pub fn stop(&self) {
        self.shutdown.send_replace(true);
    }
}

/// How long a keep-alive connection may wait for its next request (uvicorn's default).
const KEEP_ALIVE: Duration = Duration::from_secs(5);

/// Serves until SIGTERM or SIGINT, then lets the requests in flight finish.
pub async fn serve(app: Arc<App>, listener: tokio::net::TcpListener) {
    use hyper_util::rt::{TokioIo, TokioTimer};
    use hyper_util::server::graceful::GracefulShutdown;

    let graceful = GracefulShutdown::new();
    let mut terminate = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(err) => {
            log::error!(target: LOG, "cannot watch SIGTERM: {err}");
            return;
        }
    };
    loop {
        let (stream, _) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    log::warn!(target: LOG, "accept failed: {err}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = terminate.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        };
        let app = app.clone();
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            let app = app.clone();
            async move { Ok::<_, Infallible>(app.handle(request).await) }
        });
        let connection = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(KEEP_ALIVE)
            .auto_date_header(false)
            .serve_connection(TokioIo::new(stream), service);
        let watched = graceful.watch(connection);
        tokio::spawn(async move {
            let _ = watched.await;
        });
    }
    log::info!(target: LOG, "shutting down");
    app.stop();
    graceful.shutdown().await;
}
