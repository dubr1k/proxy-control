//! The MCP server against a fake panel, ported from the Python suite: tools built from the
//! OpenAPI schema by the naming rule, `confirm` on irreversible operations, the curated tools,
//! the bearer gate on `/mcp` and the open `/healthz`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use serde_json::{json, Map, Value};

use crate::config::tests::{PANEL_HOST, PANEL_KEY, TOKEN};
use crate::config::Config;
use crate::panel::{PanelClient, PanelError};
use crate::server::App;
use crate::tools::{build_operations, is_irreversible, tool_name, Fail, ToolRegistry, ToolResult};

fn openapi() -> Value {
    let path_param = |name: &str| json!({"name": name, "in": "path", "required": true, "schema": {"type": "string"}});
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Proxy Control API", "version": "0.1.0"},
        "paths": {
            "/api/openapi.json": {"get": {"summary": "Openapi Schema", "operationId": "openapi"}},
            "/healthz": {"get": {"summary": "Health", "operationId": "healthz"}},
            "/login": {"get": {"summary": "Login Page", "operationId": "login_page"}},
            "/api/auth/login": {"post": {"summary": "Login", "operationId": "login"}},
            "/api/reveal/{token}": {"get": {"summary": "Get Reveal", "operationId": "reveal", "parameters": [path_param("token")]}},
            "/s/{token}": {"get": {"summary": "Subscription", "operationId": "sub", "parameters": [path_param("token")]}},
            "/api/fleet/v2/identity": {"get": {"summary": "Identity", "operationId": "identity"}},
            "/api/clients": {
                "get": {"summary": "Clients", "operationId": "clients"},
                "post": {"summary": "Create", "description": "Create a client.", "operationId": "create_client",
                         "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ClientCreate"}}}}},
            },
            "/api/clients/{client_id}": {
                "delete": {"summary": "Delete Client", "operationId": "delete_client", "parameters": [path_param("client_id")]},
            },
            "/api/clients/{client_id}/grants": {
                "post": {"summary": "Create Grants", "operationId": "create_grants", "parameters": [path_param("client_id")],
                         "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GrantsCreate"}}}}},
            },
            "/api/clients/grants/{grant_id}/{action}": {
                "post": {"summary": "Grant Action", "operationId": "grant_action",
                         "parameters": [path_param("grant_id"),
                                        {"name": "action", "in": "path", "required": true,
                                         "schema": {"type": "string", "enum": ["enable", "disable", "rotate", "delete"]}}]},
            },
            "/api/audit": {
                "get": {"summary": "Audit Log", "operationId": "audit",
                        "parameters": [{"name": "limit", "in": "query", "required": false, "schema": {"type": "integer", "default": 200}},
                                       {"name": "actor", "in": "query", "required": false, "schema": {"type": "string"}}]},
            },
            "/api/versions/{component}/update": {
                "post": {"summary": "Update Version", "operationId": "update_version", "parameters": [path_param("component")],
                         "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/VersionUpdate"}}}}},
            },
            "/api/keys/{key_id}": {
                "delete": {"summary": "Delete Key", "operationId": "delete_key",
                           "parameters": [{"name": "key_id", "in": "path", "required": true, "schema": {"type": "integer"}}]},
            },
            "/api/routing/policies/{node_id}/{protocol}/preview": {
                "post": {"summary": "Preview", "operationId": "preview",
                         "parameters": [path_param("node_id"), path_param("protocol"),
                                        {"name": "lane", "in": "query", "required": false, "schema": {"type": "string", "default": "svc"}}],
                         "requestBody": {"content": {"application/json": {"schema": {"anyOf": [{"$ref": "#/components/schemas/PolicyInput"}, {"type": "null"}]}}}}},
            },
        },
        "components": {"schemas": {
            "ClientCreate": {"type": "object", "properties": {"display_name": {"type": "string", "maxLength": 128},
                                                              "subscription": {"type": "boolean", "default": true}},
                             "required": ["display_name"]},
            "GrantRequest": {"type": "object", "properties": {"protocol": {"type": "string", "enum": ["mtproxy", "naive", "mieru"]},
                                                              "node_id": {"type": "string", "default": "local"},
                                                              "runtime_username": {"type": "string"}},
                             "required": ["protocol", "runtime_username"]},
            "GrantsCreate": {"type": "object", "properties": {"grants": {"type": "array", "items": {"$ref": "#/components/schemas/GrantRequest"}}},
                             "required": ["grants"]},
            "VersionUpdate": {"type": "object", "properties": {"version": {"type": "string"}, "expected_current": {"type": "string"}},
                              "required": ["version", "expected_current"]},
            "PolicyInput": {"type": "object", "properties": {"mode": {"type": "string"}}},
        }},
    })
}

fn metrics_live() -> Value {
    json!({
        "ts": 1760000000.5, "interval": 2,
        "nodes": [
            {"node_id": "local", "name": "central", "status": "ok", "age_seconds": 0.0, "kernel_counters": "ok",
             "host": {"cpu_percent": 12.5, "cores": 4, "load": [0.5, 0.4, 0.3], "uptime_seconds": 99,
                      "mem": {"used": 1, "total": 2, "percent": 41.2, "available": 1},
                      "disk": {"percent": 33.0, "read_bps": 1.0, "write_bps": 2.0},
                      "net": {"rx_bps": 1000.0, "tx_bps": 2000.0, "interfaces": [{"name": "eth0"}]},
                      "containers": [{"name": "panel", "cpu_percent": 1.0, "mem_bytes": 5}]},
             "protocols": {
                 "trusttunnel": {"available": true, "live": true, "source": "kernel", "up_bps": 10.0, "down_bps": 20.0,
                                 "up_bytes": 5, "down_bytes": 6, "sessions": 2, "clients": 1},
                 "mieru": {"available": false, "live": false, "reason": "disabled"}},
             "top_clients": [{"protocol": "trusttunnel", "username": "alice", "total_bps": 30.0}],
             "alerts": [{"kind": "cpu", "severity": "warn", "since": 1, "detail": "cpu 90% average over 5 min"}]},
            {"node_id": "n2", "name": "edge", "status": "stale", "age_seconds": 75.0, "host": null, "protocols": {},
             "top_clients": [], "alerts": [{"kind": "stale", "severity": "warn", "since": 2, "detail": "no host sample"}]},
        ],
    })
}

/// One request the fake panel saw: method, raw path with query, decoded body.
type Call = (String, String, Value);

/// The routes the curated tools use, with a log of every request.
#[derive(Default)]
struct FakeState {
    openapi: Value,
    calls: Vec<Call>,
    grants: HashMap<String, Vec<Value>>,
    clients: HashMap<String, Value>,
    reveals: HashMap<String, Value>,
    next_id: u32,
    metrics_status: u16,
    bad_headers: Vec<String>,
    /// A raw answer for the next request: status, reason, body.
    raw_answer: Option<(u16, &'static str, &'static str)>,
}

/// `parse_qs` decoding of one value: `+` is a space, `%XX` a byte.
fn decode(text: &str) -> String {
    let bytes = text.replace('+', " ").into_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let escaped = (bytes[at] == b'%' && at + 2 < bytes.len())
            .then(|| std::str::from_utf8(&bytes[at + 1..at + 3]).ok().and_then(|hex| u8::from_str_radix(hex, 16).ok()))
            .flatten();
        match escaped {
            Some(byte) => {
                out.push(byte);
                at += 3;
            }
            None => {
                out.push(bytes[at]);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl FakeState {
    fn handle(&mut self, method: &str, raw: &str, body: Value) -> (u16, Value) {
        let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
        let path = path.to_string();
        self.calls.push((method.to_string(), raw.to_string(), body.clone()));
        let parts: Vec<&str> = path.split('/').collect();
        let not_found = |detail: &str| (404, json!({"detail": detail}));
        if path == "/api/openapi.json" {
            return (200, self.openapi.clone());
        }
        if path == "/api/dashboard" {
            return (200, json!({"users": 3}));
        }
        if path == "/api/metrics/live" {
            if self.metrics_status != 200 {
                return (self.metrics_status, json!({"detail": "metrics_disabled"}));
            }
            return (200, metrics_live());
        }
        if path == "/api/versions" {
            return (200, json!({"enabled": true, "components": {"panel": {"current": "0.11.0"}}}));
        }
        if path == "/api/versions/check" {
            return (200, json!({"checked_at": 1}));
        }
        if path == "/api/versions/telemt/update" {
            return (409, json!({"detail": "expected_current does not match", "code": "stale"}));
        }
        if path == "/api/nodes" {
            return (200, json!({"items": [{"node_id": "local"}]}));
        }
        if path == "/api/audit" {
            return (200, json!({"items": [{"id": 1, "action": "api_key.create"}]}));
        }
        if path == "/api/clients" && method == "POST" {
            self.next_id += 1;
            let client_id = format!("c{}", self.next_id);
            self.clients.insert(client_id.clone(), json!({"id": client_id, "display_name": body["display_name"]}));
            self.grants.insert(client_id.clone(), Vec::new());
            let mut reveal = Value::Null;
            if body.get("subscription").and_then(Value::as_bool).unwrap_or(true) {
                let token = format!("reveal-{client_id}");
                self.reveals.insert(
                    token.clone(),
                    json!({"url": format!("https://sub.example.com/s/tok-{client_id}"), "qr": "data:...",
                           "variants": {"clash": {"url": format!("https://sub.example.com/s/tok-{client_id}?format=clash"), "qr": "x"}}}),
                );
                reveal = json!(token);
            }
            let mut client = self.clients[&client_id].clone();
            client["subscription_reveal_token"] = reveal;
            return (201, client);
        }
        if path.starts_with("/api/clients/") && path.ends_with("/grants") && method == "POST" {
            let client_id = parts[3].to_string();
            let Some(grants) = self.grants.get_mut(&client_id) else { return not_found("client not found") };
            for item in body["grants"].as_array().unwrap() {
                let mut grant =
                    json!({"id": format!("g{}", grants.len() + 1), "client_id": client_id, "desired_state": "enabled"});
                for (key, value) in item.as_object().unwrap() {
                    grant[key] = value.clone();
                }
                grants.push(grant);
            }
            return (200, json!({"operation_id": "op1", "status": "succeeded"}));
        }
        if path.starts_with("/api/clients/grants/") && method == "POST" {
            let (grant_id, action) = (parts[4], parts[parts.len() - 1]);
            for grants in self.grants.values_mut() {
                for grant in grants.iter_mut() {
                    if grant["id"] == grant_id {
                        grant["desired_state"] = json!(if action == "enable" { "enabled" } else { "disabled" });
                        return (200, grant.clone());
                    }
                }
            }
            return not_found("grant not found");
        }
        if path.starts_with("/api/clients/") && path.ends_with("/subscription/reveal") {
            let client_id = parts[3];
            if !self.clients.contains_key(client_id) {
                return not_found("client or subscription not found");
            }
            self.reveals.insert(
                "again".into(),
                json!({"url": format!("https://sub.example.com/s/tok-{client_id}"), "qr": "x", "variants": {}}),
            );
            return (200, json!({"reveal_token": "again"}));
        }
        if path.starts_with("/api/reveal/") {
            return match self.reveals.remove(parts[3]) {
                Some(payload) => (200, payload),
                None => (410, json!({"detail": "reveal expired or consumed"})),
            };
        }
        if path.starts_with("/api/clients/") && method == "GET" {
            let client_id = parts[3];
            let Some(client) = self.clients.get(client_id) else { return not_found("client not found") };
            return (200, json!({"client": client, "grants": self.grants[client_id]}));
        }
        if path.starts_with("/api/routing/policies/") && path.ends_with("/preview") {
            let lanes: Vec<String> = query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .filter(|(key, _)| *key == "lane")
                .map(|(_, value)| decode(value))
                .collect();
            let lane = if lanes.is_empty() { Value::Null } else { json!(lanes) };
            return (200, json!({"node_id": parts[4], "body": body, "lane": lane}));
        }
        if path.starts_with("/api/routing/policies/") && path.ends_with("/apply") {
            return (200, json!({"applied": body}));
        }
        if path.starts_with("/api/keys/") && method == "DELETE" {
            return (200, json!({"ok": true}));
        }
        (404, json!({"detail": format!("no fake route for {method} {path}")}))
    }
}

#[derive(Clone)]
struct Fake {
    state: Arc<Mutex<FakeState>>,
    url: String,
}

impl Fake {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap()
    }

    fn calls(&self) -> Vec<Call> {
        self.state().calls.clone()
    }

    fn last_call(&self) -> Call {
        let state = self.state();
        assert!(state.bad_headers.is_empty(), "{:?}", state.bad_headers);
        state.calls.last().cloned().unwrap()
    }
}

async fn fake_answer(
    state: Arc<Mutex<FakeState>>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = request.method().to_string();
    let raw = request.uri().path_and_query().map(|pq| pq.as_str().to_string()).unwrap_or_default();
    let host = request.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let auth = request.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let content = request.into_body().collect().await.map(|body| body.to_bytes()).unwrap_or_default();
    let body = if content.is_empty() { Value::Null } else { serde_json::from_slice(&content).unwrap() };
    let mut state = state.lock().unwrap();
    if host != PANEL_HOST || auth != format!("Bearer {PANEL_KEY}") {
        state.bad_headers.push(format!("{host} / {auth}"));
    }
    if let Some((status, reason, text)) = state.raw_answer.take() {
        state.calls.push((method, raw, body));
        let mut response = Response::new(Full::new(Bytes::from_static(text.as_bytes())));
        *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
        response.extensions_mut().insert(hyper::ext::ReasonPhrase::from_static(reason.as_bytes()));
        return Ok(response);
    }
    let (status, answer) = state.handle(&method, &raw, body);
    let mut response = Response::new(Full::new(Bytes::from(serde_json::to_vec(&answer).unwrap())));
    *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    response.headers_mut().insert("content-type", "application/json".parse().unwrap());
    Ok(response)
}

/// Serves `serve(listener)` on a thread of its own for the rest of the test process.
fn background<F: Future<Output = ()> + 'static>(make: impl FnOnce() -> F + Send + 'static) {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(make());
    });
}

fn start_fake() -> Fake {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(FakeState { openapi: openapi(), metrics_status: 200, ..Default::default() }));
    let shared = state.clone();
    background(move || async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let state = shared.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request| fake_answer(state.clone(), request));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Fake { state, url }
}

fn config(panel_url: &str) -> Config {
    Config {
        panel_url: panel_url.to_string(),
        panel_host: PANEL_HOST.into(),
        panel_key: PANEL_KEY.into(),
        token: TOKEN.into(),
        bind_host: "0.0.0.0".into(),
        bind_port: 8793,
        allowed_hosts: vec!["mcp.example.com".into(), "127.0.0.1:8793".into()],
        public_url: "https://mcp.example.com/mcp".into(),
    }
}

fn run<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(future)
}

async fn registry(fake: &Fake) -> ToolRegistry {
    let registry = ToolRegistry::new(PanelClient::new(&config(&fake.url)).unwrap());
    registry.reload().await.unwrap();
    registry
}

async fn call(registry: &ToolRegistry, name: &str, arguments: Value) -> ToolResult {
    let Value::Object(arguments) = arguments else { panic!("arguments must be an object") };
    registry.call(name, Some(arguments)).await.unwrap()
}

fn operations() -> HashMap<String, crate::tools::Operation> {
    build_operations(&openapi()).unwrap().into_iter().map(|op| (op.name.clone(), op)).collect()
}

fn names(schema: &Map<String, Value>, key: &str) -> Vec<String> {
    match &schema[key] {
        Value::Object(map) => map.keys().cloned().collect(),
        Value::Array(items) => items.iter().map(|item| item.as_str().unwrap().to_string()).collect(),
        other => panic!("{other}"),
    }
}

// --- tools from OpenAPI -------------------------------------------------------------------

#[test]
fn tool_names_follow_the_rule() {
    assert_eq!(tool_name("post", "/api/clients/{client_id}/grants"), "post_clients_by_client_id_grants");
    assert_eq!(tool_name("get", "/api/audit"), "get_audit");
    assert_eq!(
        tool_name("delete", "/api/routing/policies/{node_id}/{protocol}"),
        "delete_routing_policies_by_node_id_by_protocol"
    );
    let segments: Vec<String> = (0..12).map(|i| format!("segment{i}")).collect();
    let long = tool_name("post", &format!("/api/{}", segments.join("/")));
    assert!(long.len() <= 64 && long.starts_with("post_segment0_"));
    // The Python regex rules: `{}` stays (then becomes `_`), `{a{b}` is one parameter; edges are stripped.
    assert_eq!(tool_name("get", "/api/x/{}/y"), "get_x____y");
    assert_eq!(tool_name("get", "/api/{a{b}/c"), "get_by_a_b_c");
    assert_eq!(tool_name("post", "/api/clients/grants/adopt-batch"), "post_clients_grants_adopt-batch");
    assert_eq!(tool_name("get", "relative/ü"), "get_relative");
}

#[test]
fn operations_are_built_from_the_schema_and_the_excluded_paths_are_absent() {
    let operations = operations();
    assert!(!operations.contains_key("get_openapi_json") && !operations.contains_key("get_healthz"));
    assert!(!operations.keys().any(|name| ["get_login", "post_auth", "get_reveal", "get_s_", "get_fleet"]
        .iter()
        .any(|prefix| name.starts_with(prefix))));
    let create = &operations["post_clients"];
    assert_eq!((create.method.as_str(), create.path.as_str()), ("POST", "/api/clients"));
    assert!(create.description.contains("Create a client.") && create.description.contains("POST /api/clients"));
    assert_eq!(create.input_schema["properties"]["display_name"]["type"], "string");
    assert_eq!(create.input_schema["required"], json!(["display_name"]));
    assert!(create.input_schema["properties"].get("confirm").is_none());
    let grants = &operations["post_clients_by_client_id_grants"];
    assert_eq!(names(&grants.input_schema, "properties"), ["client_id", "grants"]);
    assert_eq!(grants.input_schema["required"], json!(["client_id", "grants"]));
    // The body's `$ref` is resolved, nested refs included.
    assert_eq!(
        grants.input_schema["properties"]["grants"]["items"]["properties"]["protocol"]["enum"],
        json!(["mtproxy", "naive", "mieru"])
    );
    let audit = &operations["get_audit"];
    assert_eq!(names(&audit.input_schema, "properties"), ["limit", "actor"]);
    assert!(audit.input_schema.get("required").is_none());
    let preview = &operations["post_routing_policies_by_node_id_by_protocol_preview"];
    assert_eq!(names(&preview.input_schema, "properties"), ["node_id", "protocol", "lane", "mode"]);
}

/// Moved from the panel's metrics suite: an endless SSE answer cannot be a tool call.
#[test]
fn the_endless_stream_is_not_an_mcp_tool_but_the_snapshots_are() {
    assert!(crate::tools::is_excluded("/api/metrics/stream"));
    assert!(!["/api/metrics/live", "/api/metrics/history", "/api/metrics/summary"]
        .iter()
        .any(|path| crate::tools::is_excluded(path)));
}

#[test]
fn irreversible_operations_require_confirm() {
    let operations = operations();
    let update = &operations["post_versions_by_component_update"];
    assert_eq!(update.input_schema["properties"]["confirm"]["type"], "boolean");
    assert!(names(&update.input_schema, "required").contains(&"confirm".to_string()));
    assert!(names(&operations["delete_keys_by_key_id"].input_schema, "required").contains(&"confirm".to_string()));
    // Deleting a client is permanent: the generated tool asks for confirm like any DELETE.
    assert!(names(&operations["delete_clients_by_client_id"].input_schema, "required").contains(&"confirm".to_string()));
    // A path whose parameter may take an irreversible value gets an optional `confirm`.
    let action = &operations["post_clients_grants_by_grant_id_by_action"];
    assert!(action.input_schema["properties"].get("confirm").is_some());
    assert!(!names(&action.input_schema, "required").contains(&"confirm".to_string()));
    // Installing a version on a managed node is an update even though the path says `versions/{component}`.
    assert!(is_irreversible("POST", "/api/nodes/{node_id}/versions/{component}"));
    assert!(is_irreversible("POST", "/api/nodes/{node_id}/versions/check")); // `/check` is on the list
    assert!(!is_irreversible("GET", "/api/versions"));
}

#[test]
fn odd_schemas_fail_with_the_python_messages() {
    let broken = |operation: Value| {
        let schema = json!({"paths": {"/api/x": {"post": operation}}});
        build_operations(&schema).unwrap_err().message
    };
    assert_eq!(broken(json!({"parameters": null})), "'NoneType' object is not iterable");
    assert_eq!(broken(json!({"summary": null})), "'NoneType' object has no attribute 'strip'");
    assert_eq!(broken(json!({"parameters": ["x"]})), "'str' object has no attribute 'get'");
    assert_eq!(
        broken(json!({"requestBody": {"content": {"application/json": {"schema": true}}}})),
        "argument of type 'bool' is not iterable"
    );
    // A cycle is cut after eight hops; siblings of a `$ref` are kept unresolved.
    let cyclic = json!({"paths": {"/api/x": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/A"}}}}}}},
                        "components": {"schemas": {"A": {"type": "object", "properties": {"a": {"$ref": "#/components/schemas/A", "x": {"$ref": "#/components/schemas/A"}}}}}}});
    let operation = &build_operations(&cyclic).unwrap()[0];
    let mut node = &operation.input_schema["properties"]["a"];
    for _ in 0..7 {
        assert_eq!(node["x"], json!({"$ref": "#/components/schemas/A"}));
        node = &node["properties"]["a"];
    }
    assert_eq!(node, &json!({"type": "object"}));
}

#[test]
fn confirm_false_refuses_without_calling_the_panel() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let before = fake.calls().len();
        let body = call(
            &registry,
            "post_versions_by_component_update",
            json!({"component": "telemt", "version": "1", "expected_current": "0"}),
        )
        .await
        .json();
        assert_eq!(body["refused"], true);
        assert_eq!(body["would"], "POST /api/versions/telemt/update");
        let body =
            call(&registry, "post_clients_grants_by_grant_id_by_action", json!({"grant_id": "g1", "action": "delete"}))
                .await;
        assert_eq!(body.json()["would"], "POST /api/clients/grants/g1/delete");
        // Only `true` confirms: `1` and `"yes"` are not `True`.
        let body = call(&registry, "delete_keys_by_key_id", json!({"key_id": 3, "confirm": 1})).await;
        assert_eq!(body.json()["refused"], true);
        assert_eq!(fake.calls().len(), before);
    });
}

#[test]
fn a_confirmed_call_reaches_the_panel_and_its_error_comes_back_as_tool_text() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let result = call(
            &registry,
            "post_versions_by_component_update",
            json!({"component": "telemt", "version": "1", "expected_current": "0", "confirm": true}),
        )
        .await;
        assert!(result.is_error);
        assert_eq!(result.json(), json!({"status": 409, "detail": "expected_current does not match", "code": "stale"}));
        assert_eq!(
            result.text,
            "{\n \"status\": 409,\n \"detail\": \"expected_current does not match\",\n \"code\": \"stale\"\n}"
        );
        assert_eq!(
            fake.last_call(),
            ("POST".into(), "/api/versions/telemt/update".into(), json!({"version": "1", "expected_current": "0"}))
        );
    });
}

#[test]
fn path_params_are_encoded_and_get_params_travel_as_query() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let result = call(&registry, "get_audit", json!({"limit": 5, "actor": "key:mcp"})).await;
        assert!(!result.is_error && result.json()["items"][0]["action"] == "api_key.create");
        assert_eq!(fake.last_call().1, "/api/audit?limit=5&actor=key%3Amcp");
        call(&registry, "post_clients_grants_by_grant_id_by_action", json!({"grant_id": "g/1", "action": "enable"}))
            .await;
        assert_eq!(fake.last_call().1, "/api/clients/grants/g%2F1/enable");
        // httpx's encoding: a list repeats its key, None is empty, booleans are JSON-style, `~` stays.
        call(
            &registry,
            "get_audit",
            json!({"limit": null, "actor": ["a", "b"], "extra": "x y~*", "n": null, "t": true, "d": {"k": "v"}}),
        )
        .await;
        assert_eq!(
            fake.last_call().1,
            "/api/audit?limit=&actor=a&actor=b&extra=x+y~%2A&t=true&d=%7B%27k%27%3A+%27v%27%7D"
        );
        call(&registry, "get_audit", json!({"actor": []})).await;
        assert_eq!(fake.last_call().1, "/api/audit?");
        let missing = call(&registry, "post_clients_grants_by_grant_id_by_action", json!({"grant_id": "g1"})).await;
        assert!(missing.is_error && missing.json() == json!({"error": "missing path parameter(s): action"}));
        // An empty answer is "no content"; an optional body of a POST with body keys is still sent.
        let deleted = call(&registry, "delete_keys_by_key_id", json!({"key_id": 3, "confirm": true})).await;
        assert_eq!(fake.last_call().1, "/api/keys/3");
        assert_eq!(deleted.json(), json!({"ok": true}));
        call(
            &registry,
            "post_routing_policies_by_node_id_by_protocol_preview",
            json!({"node_id": "local", "protocol": "naive"}),
        )
        .await;
        assert_eq!(fake.last_call(), ("POST".into(), "/api/routing/policies/local/naive/preview".into(), json!({})));
    });
}

#[test]
fn unknown_tool_is_an_error() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let result = call(&registry, "no_such_tool", json!({})).await;
        assert!(result.is_error);
        assert_eq!(result.json(), json!({"error": "unknown tool 'no_such_tool'"}));
        assert_eq!(call(&registry, "it's", json!({})).await.json(), json!({"error": "unknown tool \"it's\""}));
    });
}

#[test]
fn listing_has_generated_and_curated_tools_and_reload_rebuilds() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let names: Vec<String> = registry.tools().into_iter().map(|tool| tool.name).collect();
        for name in [
            "overview",
            "create_client",
            "client_subscription",
            "set_client_placement",
            "versions_check",
            "versions_update",
            "routing_preview",
            "routing_apply",
            "audit_tail",
            "reload_tools",
            "post_clients",
            "get_audit",
        ] {
            assert!(names.contains(&name.to_string()), "{name}");
        }
        assert!(names.iter().all(|name| name.len() <= 64));
        assert_eq!(&names[..2], ["overview", "create_client"]);
        let schema_calls = || fake.calls().iter().filter(|call| call.1 == "/api/openapi.json").count();
        let before = schema_calls();
        let result = call(&registry, "reload_tools", json!({})).await;
        assert_eq!(result.json(), json!({"reloaded": true, "tools": registry.tools().len()}));
        assert_eq!(schema_calls(), before + 1);
        // A panel that answers something else than an OpenAPI document keeps the old tools.
        fake.state().openapi = json!({"nope": true});
        let result = call(&registry, "reload_tools", json!({})).await;
        assert!(result.is_error);
        assert_eq!(
            result.json(),
            json!({"status": 502, "detail": "the panel did not return an OpenAPI document", "code": "bad_schema"})
        );
        assert_eq!(registry.tools().len(), names.len());
    });
}

// --- curated ------------------------------------------------------------------------------

#[test]
fn overview_joins_dashboard_versions_and_nodes() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let body = call(&registry, "overview", json!({})).await.json();
        assert_eq!(body["dashboard"], json!({"users": 3}));
        assert_eq!(body["versions"]["components"]["panel"]["current"], "0.11.0");
        assert_eq!(body["nodes"], json!([{"node_id": "local"}]));
        let sequence: Vec<String> = fake.calls().into_iter().skip(1).map(|call| call.1).collect();
        assert_eq!(sequence, ["/api/nodes", "/api/dashboard", "/api/versions", "/api/metrics/live?node=all"]);
    });
}

#[test]
fn overview_carries_a_compact_metrics_section() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let body = call(&registry, "overview", json!({})).await.json();
        assert!(fake.calls().contains(&("GET".into(), "/api/metrics/live?node=all".into(), Value::Null)));
        let nodes = body["metrics"]["nodes"].as_array().unwrap();
        assert_eq!(
            nodes[0],
            json!({
                "node_id": "local", "name": "central", "status": "ok", "age_seconds": 0.0,
                "cpu_percent": 12.5, "mem_percent": 41.2, "disk_percent": 33.0, "load1": 0.5,
                "net_rx_bps": 1000.0, "net_tx_bps": 2000.0,
                "protocols": {"trusttunnel": {"up_bps": 10.0, "down_bps": 20.0, "sessions": 2}},
                "alerts": [{"kind": "cpu", "severity": "warn", "detail": "cpu 90% average over 5 min"}],
            })
        );
        let edge = &nodes[1];
        assert!(edge["status"] == "stale" && edge["cpu_percent"].is_null() && edge["protocols"] == json!({}));
        let text = body["metrics"].to_string();
        assert!(!text.contains("containers") && !text.contains("top_clients"));
    });
}

#[test]
fn overview_metrics_is_null_when_the_call_fails() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        fake.state().metrics_status = 404;
        let body = call(&registry, "overview", json!({})).await.json();
        assert!(body["metrics"].is_null());
        assert_eq!(body["dashboard"], json!({"users": 3}));
    });
}

#[test]
fn create_client_creates_places_and_returns_the_subscription_url() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let result = call(
            &registry,
            "create_client",
            json!({"display_name": "Alice Example", "subscription": true,
                   "placement": [{"node_id": "local", "protocol": "naive"}, {"node_id": "node-1", "protocol": "mieru"}]}),
        )
        .await;
        let body = result.json();
        assert_eq!(body["client"]["id"], "c1");
        assert_eq!(body["subscription_url"], "https://sub.example.com/s/tok-c1");
        assert_eq!(body["grants"], json!({"operation_id": "op1", "status": "succeeded"}));
        let calls: Vec<Call> = fake.calls().into_iter().filter(|call| call.1 != "/api/openapi.json").collect();
        let sequence: Vec<(&str, &str)> = calls.iter().map(|(m, p, _)| (m.as_str(), p.as_str())).collect();
        assert_eq!(
            sequence,
            [("POST", "/api/clients"), ("POST", "/api/clients/c1/grants"), ("GET", "/api/reveal/reveal-c1")]
        );
        let grants = calls[1].2["grants"].as_array().unwrap();
        let placed: Vec<(&str, &str)> =
            grants.iter().map(|g| (g["node_id"].as_str().unwrap(), g["protocol"].as_str().unwrap())).collect();
        assert_eq!(placed, [("local", "naive"), ("node-1", "mieru")]);
        assert!(grants.iter().all(|g| g["runtime_username"] == "alice-example"));
        assert!(!result.text.contains("qr"));
        assert_eq!(body["subscription"]["variants"], json!({"clash": "https://sub.example.com/s/tok-c1?format=clash"}));
    });
}

#[test]
fn create_client_without_subscription_or_placement() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let body = call(&registry, "create_client", json!({"display_name": "Bob", "subscription": false})).await.json();
        assert!(body["subscription_url"].is_null() && body["grants"].is_null());
        let sequence: Vec<(String, String)> =
            fake.calls().into_iter().filter(|call| call.1 != "/api/openapi.json").map(|(m, p, _)| (m, p)).collect();
        assert_eq!(sequence, [("POST".to_string(), "/api/clients".to_string())]);
        let missing = call(&registry, "create_client", json!({"display_name": "   "})).await;
        assert!(missing.is_error && missing.json() == json!({"error": "display_name is required"}));
    });
}

#[test]
fn client_subscription_reveals_the_url_again() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        call(&registry, "create_client", json!({"display_name": "Carol", "subscription": true, "placement": []})).await;
        let body = call(&registry, "client_subscription", json!({"client_id": "c1"})).await.json();
        assert_eq!(body["url"], "https://sub.example.com/s/tok-c1");
        let missing = call(&registry, "client_subscription", json!({"client_id": "nope"})).await;
        assert!(missing.is_error && missing.json()["status"] == 404);
        // `str(None)` is "None", as the Python tool sent it.
        call(&registry, "client_subscription", json!({"client_id": null})).await;
        assert_eq!(fake.last_call().1, "/api/clients/None/subscription/reveal");
    });
}

#[test]
fn set_client_placement_plans_and_executes_only_with_confirm() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        call(
            &registry,
            "create_client",
            json!({"display_name": "Dave", "subscription": false,
                   "placement": [{"node_id": "local", "protocol": "naive"}, {"node_id": "local", "protocol": "mieru"}]}),
        )
        .await;
        let desired = json!([{"node_id": "local", "protocol": "naive"}, {"node_id": "node-2", "protocol": "mtproxy"}]);
        let plan =
            call(&registry, "set_client_placement", json!({"client_id": "c1", "placement": desired})).await.json();
        assert_eq!(plan["refused"], true);
        assert_eq!(plan["would"], "PLAN /api/clients/c1");
        assert_eq!(plan["plan"]["issue"], json!([{"node_id": "node-2", "protocol": "mtproxy"}]));
        assert_eq!(plan["plan"]["disable"], json!([{"grant_id": "g2", "node_id": "local", "protocol": "mieru"}]));
        assert_eq!(plan["plan"]["keep"], json!([{"grant_id": "g1", "node_id": "local", "protocol": "naive"}]));
        let mutations = fake.calls().into_iter().filter(|c| c.0 == "POST" && c.1 != "/api/clients").count();
        assert_eq!(mutations, 1); // the original placement only
        let done =
            call(&registry, "set_client_placement", json!({"client_id": "c1", "placement": desired, "confirm": true}))
                .await
                .json();
        assert_eq!(done["refused"], false);
        {
            let state = fake.state();
            let grants = &state.grants["c1"];
            assert_eq!(grants[1]["desired_state"], "disabled");
            assert_eq!(
                (grants[2]["node_id"].as_str(), grants[2]["protocol"].as_str()),
                (Some("node-2"), Some("mtproxy"))
            );
            assert_eq!(grants[2]["runtime_username"], "dave");
        }
        // Re-enabling a disabled grant instead of issuing a second one.
        let again = call(
            &registry,
            "set_client_placement",
            json!({"client_id": "c1", "placement": [{"node_id": "local", "protocol": "mieru"}], "confirm": true}),
        )
        .await
        .json();
        assert_eq!(again["plan"]["enable"], json!([{"grant_id": "g2", "node_id": "local", "protocol": "mieru"}]));
        assert_eq!(fake.state().grants["c1"][1]["desired_state"], "enabled");
    });
}

#[test]
fn versions_and_routing_and_audit_curated_tools() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        assert_eq!(call(&registry, "versions_check", json!({})).await.json()["checked_at"], 1);
        let refused =
            call(&registry, "versions_update", json!({"component": "telemt", "version": "1", "expected_current": "0"}))
                .await
                .json();
        assert!(refused["refused"] == true && refused["would"].as_str().unwrap().contains("telemt"));
        assert_eq!(refused["detail"], "Would install telemt 1 (expecting 0 now). Call again with confirm=true.");
        let stale = call(
            &registry,
            "versions_update",
            json!({"component": "telemt", "version": "1", "expected_current": "0", "confirm": true}),
        )
        .await;
        assert!(stale.is_error && stale.json()["code"] == "stale");
        let preview = call(
            &registry,
            "routing_preview",
            json!({"node_id": "local", "protocol": "naive", "policy": {"mode": "direct"}}),
        )
        .await
        .json();
        assert!(preview["body"] == json!({"mode": "direct"}) && preview["lane"] == json!(["svc"]));
        assert_eq!(fake.last_call().1, "/api/routing/policies/local/naive/preview?lane=svc");
        let refused =
            call(&registry, "routing_apply", json!({"node_id": "local", "protocol": "naive", "expected_revision": 3}))
                .await
                .json();
        assert_eq!(refused["refused"], true);
        assert_eq!(refused["would"], "POST /api/routing/policies/local/naive/apply?lane=svc");
        let applied = call(
            &registry,
            "routing_apply",
            json!({"node_id": "local", "protocol": "naive", "expected_revision": 3, "lane": "grant:g1", "confirm": true}),
        )
        .await
        .json();
        assert_eq!(applied, json!({"applied": {"expected_revision": 3}}));
        assert_eq!(fake.last_call().1, "/api/routing/policies/local/naive/apply?lane=grant%3Ag1");
        let tail = call(&registry, "audit_tail", json!({"limit": 10})).await.json();
        assert!(tail["items"][0]["action"] == "api_key.create" && fake.last_call().1 == "/api/audit?limit=10");
        call(&registry, "audit_tail", json!({"limit": " 7 ", "actor": "a b", "action": null, "target": false})).await;
        assert_eq!(fake.last_call().1, "/api/audit?limit=7&actor=a+b&target=false");
        let bad =
            registry.call("audit_tail", Some(json!({"limit": "abc"}).as_object().unwrap().clone())).await.unwrap_err();
        assert_eq!(bad.message, "invalid literal for int() with base 10: 'abc'");
    });
}

#[test]
fn the_curated_routing_tools_accept_trusttunnel() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        for name in ["routing_preview", "routing_apply"] {
            let tool = registry.tools().into_iter().find(|tool| tool.name == name).unwrap();
            assert_eq!(
                tool.input_schema["properties"]["protocol"]["enum"],
                json!(["naive", "mieru", "mtproxy", "trusttunnel", "amneziawg"])
            );
        }
        let preview =
            call(&registry, "routing_preview", json!({"node_id": "local", "protocol": "trusttunnel"})).await.json();
        assert_eq!(fake.last_call().1, "/api/routing/policies/local/trusttunnel/preview?lane=svc");
        assert_eq!(preview["lane"], json!(["svc"]));
    });
}

#[test]
fn resources_are_json_text() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let uris: Vec<&str> = registry.resources().iter().map(|resource| resource.uri).collect();
        assert_eq!(uris, ["proxy-control://overview", "proxy-control://versions", "proxy-control://nodes"]);
        let versions = registry.read_resource("proxy-control://versions").await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(&versions).unwrap()["enabled"], true);
        let nodes = registry.read_resource("proxy-control://nodes").await.unwrap();
        assert_eq!(nodes, "[\n {\n  \"node_id\": \"local\"\n }\n]");
        match registry.read_resource("proxy-control://nothing").await {
            Err(Fail::Panel(err)) => {
                assert_eq!(
                    err,
                    PanelError::new(404, "unknown resource proxy-control://nothing", Some("unknown_resource"))
                )
            }
            other => panic!("{:?}", other.map(|_| ())),
        }
    });
}

#[test]
fn amneziawg_versions_are_separate_accesses_in_a_placement() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        call(
            &registry,
            "create_client",
            json!({"display_name": "Eve", "subscription": false, "placement": [
                {"node_id": "local", "protocol": "amneziawg", "options": {"version": "1.5"}},
                {"node_id": "local", "protocol": "amneziawg", "options": {"version": "3.1"}},
                {"node_id": "local", "protocol": "amneziawg"},
            ]}),
        )
        .await;
        let grants = fake.calls()[2].2["grants"].clone();
        let accounts: Vec<&str> =
            grants.as_array().unwrap().iter().map(|g| g["runtime_username"].as_str().unwrap()).collect();
        assert_eq!(accounts, ["eve-awg15", "eve-awg31", "eve-awg20"]);
        let versions: Vec<Value> = grants
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["options"].get("version").cloned().unwrap_or(Value::Null))
            .collect();
        assert_eq!(versions, [json!("1.5"), json!("3.1"), Value::Null]);
        let desired = json!([{"node_id": "local", "protocol": "amneziawg", "options": {"version": "3.1"}},
                             {"node_id": "local", "protocol": "amneziawg", "options": {"version": "2.0"}}]);
        let plan = call(&registry, "set_client_placement", json!({"client_id": "c1", "placement": desired}))
            .await
            .json()["plan"]
            .clone();
        assert_eq!(
            plan["keep"],
            json!([{"grant_id": "g2", "node_id": "local", "protocol": "amneziawg:3.1"},
                   {"grant_id": "g3", "node_id": "local", "protocol": "amneziawg:2.0"}])
        );
        assert_eq!(plan["disable"], json!([{"grant_id": "g1", "node_id": "local", "protocol": "amneziawg:1.5"}]));
        assert_eq!(plan["issue"], json!([]));
    });
}

#[test]
fn handler_errors_are_the_python_exceptions() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let error = |result: Result<ToolResult, crate::py::PyErr>| result.unwrap_err().message;
        let args = |value: Value| Some(value.as_object().unwrap().clone());
        assert_eq!(
            error(registry.call("create_client", args(json!({"display_name": "D", "placement": 5}))).await),
            "'int' object is not iterable"
        );
        assert_eq!(
            error(registry.call("create_client", args(json!({"display_name": "D", "placement": {"a": 1}}))).await),
            "string indices must be integers, not 'str'"
        );
        assert_eq!(
            error(
                registry
                    .call("create_client", args(json!({"display_name": "D", "placement": [{"node_id": "n"}]})))
                    .await
            ),
            "'protocol'"
        );
        call(&registry, "create_client", json!({"display_name": "Zed", "subscription": false})).await;
        let last = fake.calls().iter().rfind(|c| c.1 == "/api/clients").unwrap().2["display_name"].clone();
        assert_eq!(last, "Zed");
        let unhashable = registry
            .call(
                "set_client_placement",
                args(json!({"client_id": "c3", "placement": [{"node_id": ["x"], "protocol": "naive"}]})),
            )
            .await;
        assert_eq!(error(unhashable), "unhashable type: 'list'");
    });
}

#[test]
fn panel_failures_keep_the_panels_words() {
    let fake = start_fake();
    run(async {
        let registry = registry(&fake).await;
        let update = json!({"component": "x", "version": "1", "expected_current": "0", "confirm": true});
        fake.state().raw_answer =
            Some((422, "Unprocessable Content", "{\"detail\": [{\"msg\": \"bad ü\"}], \"code\": 5}"));
        let result = call(&registry, "versions_update", update.clone()).await;
        assert_eq!(result.json(), json!({"status": 422, "detail": "[{\"msg\": \"bad ü\"}]", "code": 5}));
        fake.state().raw_answer = Some((500, "Internal Server Error", ""));
        assert_eq!(call(&registry, "versions_update", update.clone()).await.json()["detail"], "Internal Server Error");
        fake.state().raw_answer = Some((422, "Unprocessable Content", "{\"code\": \"x\"}"));
        assert_eq!(call(&registry, "versions_update", update.clone()).await.json()["detail"], "Unprocessable Content");
        fake.state().raw_answer = Some((503, "Service Unavailable", "plain text failure"));
        assert_eq!(call(&registry, "versions_update", update).await.json()["detail"], "plain text failure");
        let dead = ToolRegistry::new(PanelClient::new(&config("http://127.0.0.1:9")).unwrap());
        let result = call(&dead, "versions_check", json!({})).await;
        assert!(result.is_error);
        assert_eq!(
            result.json(),
            json!({"status": 502, "detail": "panel unreachable: ConnectError", "code": "panel_unreachable"})
        );
    });
}

// --- HTTP surface -------------------------------------------------------------------------

/// The server on a loopback port of its own, its registry loaded from the fake panel.
fn start_server(fake: &Fake) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let url = fake.url.clone();
    background(move || async move {
        let registry = ToolRegistry::new(PanelClient::new(&config(&url)).unwrap());
        registry.reload().await.unwrap();
        let app = Arc::new(App::new(Arc::new(registry), TOKEN, &["mcp.example.com".into(), "127.0.0.1:8793".into()]));
        crate::server::serve(app, tokio::net::TcpListener::from_std(listener).unwrap()).await;
    });
    format!("http://{address}")
}

fn rpc(method: &str, params: Value, id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn initialize() -> Value {
    rpc(
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        1,
    )
}

struct Http {
    client: reqwest::Client,
    base: String,
}

impl Http {
    fn new(base: String) -> Self {
        Self { client: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap(), base }
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        host: &str,
        headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> (u16, reqwest::header::HeaderMap, String) {
        let mut request = self
            .client
            .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), format!("{}{path}", self.base))
            .header("host", host);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request.body(serde_json::to_vec(body).unwrap());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        (status, headers, response.text().await.unwrap())
    }

    async fn mcp(&self, body: &Value, auth: Option<&str>) -> (u16, reqwest::header::HeaderMap, String) {
        let mut headers = vec![("accept", "application/json, text/event-stream"), ("content-type", "application/json")];
        if let Some(auth) = auth {
            headers.push(("authorization", auth));
        }
        self.send("POST", "/mcp", "mcp.example.com", &headers, Some(body)).await
    }
}

#[test]
fn healthz_is_open_and_mcp_needs_the_bearer() {
    let fake = start_fake();
    let http = Http::new(start_server(&fake));
    run(async {
        let (status, headers, body) = http.send("GET", "/healthz", "mcp.example.com", &[], None).await;
        assert_eq!((status, body.as_str()), (200, "{\"status\":\"ok\"}"));
        assert_eq!(headers["content-type"], "application/json");
        assert!(headers.get("date").is_none() && headers.get("server").is_none());
        let (status, headers, body) = http.mcp(&initialize(), None).await;
        assert_eq!((status, body.as_str()), (401, "{\"error\":\"unauthorized\"}"));
        assert_eq!(headers["www-authenticate"], "Bearer realm=\"proxy-control-mcp\"");
        let wrong = format!("Bearer {}x", &TOKEN[..TOKEN.len() - 1]);
        assert_eq!(http.mcp(&initialize(), Some(&wrong)).await.0, 401);
        assert_eq!(http.send("GET", "/mcp", "mcp.example.com", &[("authorization", "Basic abc")], None).await.0, 401);
        assert_eq!(http.mcp(&initialize(), Some("Bearer")).await.0, 401);
        // The scheme is case-insensitive and the credential is stripped.
        let spaced = format!("bearer   {TOKEN}  ");
        assert_eq!(http.mcp(&rpc("ping", json!({}), 1), Some(&spaced)).await.0, 200);
        // Everything but /healthz is behind the gate, unknown paths included.
        assert_eq!(http.send("GET", "/nope", "mcp.example.com", &[], None).await.0, 401);
        let bearer = format!("Bearer {TOKEN}");
        let auth = [("authorization", bearer.as_str())];
        let (status, _, body) = http.send("GET", "/nope", "mcp.example.com", &auth, None).await;
        assert_eq!((status, body.as_str()), (404, "Not Found"));
        let (status, headers, _) = http.send("POST", "/mcp/", "mcp.example.com", &auth, None).await;
        assert_eq!((status, headers["location"].to_str().unwrap()), (307, "http://mcp.example.com/mcp"));
        let (status, headers, _) = http.send("POST", "/healthz", "mcp.example.com", &[], None).await;
        assert_eq!((status, headers["allow"].to_str().unwrap()), (405, "HEAD, GET"));
    });
}

#[test]
fn initialize_and_tool_calls_over_http() {
    let fake = start_fake();
    let http = Http::new(start_server(&fake));
    run(async {
        let bearer = format!("Bearer {TOKEN}");
        let (status, _, body) = http.mcp(&initialize(), Some(&bearer)).await;
        assert_eq!(status, 200, "{body}");
        let answer: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(answer["result"]["serverInfo"], json!({"name": "proxy-control", "version": "0.11"}));
        assert_eq!(answer["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(
            answer["result"]["capabilities"],
            json!({"experimental": {}, "resources": {"listChanged": false, "subscribe": false}, "tools": {"listChanged": false}})
        );
        let (_, _, listed) = http.mcp(&rpc("tools/list", json!({}), 2), Some(&bearer)).await;
        let listed: Value = serde_json::from_str(&listed).unwrap();
        let tools = listed["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|tool| tool["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"overview") && names.contains(&"post_clients"));
        let overview = tools.iter().find(|tool| tool["name"] == "overview").unwrap();
        assert_eq!(overview["inputSchema"], json!({"type": "object", "properties": {}, "additionalProperties": false}));
        let (_, _, called) =
            http.mcp(&rpc("tools/call", json!({"name": "overview", "arguments": {}}), 3), Some(&bearer)).await;
        let called: Value = serde_json::from_str(&called).unwrap();
        assert_eq!(called["result"]["isError"], false);
        let text: Value = serde_json::from_str(called["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text["dashboard"], json!({"users": 3}));
        let (_, _, failed) = http.mcp(&rpc("tools/call", json!({"name": "no_such_tool"}), 4), Some(&bearer)).await;
        assert_eq!(serde_json::from_str::<Value>(&failed).unwrap()["result"]["isError"], true);
        let (_, _, raised) = http
            .mcp(&rpc("tools/call", json!({"name": "audit_tail", "arguments": {"limit": [1]}}), 5), Some(&bearer))
            .await;
        assert_eq!(
            serde_json::from_str::<Value>(&raised).unwrap()["error"],
            json!({"code": 0, "message": "int() argument must be a string, a bytes-like object or a real number, not 'list'"})
        );
        let (_, _, resources) = http.mcp(&rpc("resources/list", json!({}), 6), Some(&bearer)).await;
        assert_eq!(
            serde_json::from_str::<Value>(&resources).unwrap()["result"]["resources"][1],
            json!({"uri": "proxy-control://versions", "name": "versions", "description": "Installed and available component versions (GET /api/versions).", "mimeType": "application/json"})
        );
        let (_, _, read) =
            http.mcp(&rpc("resources/read", json!({"uri": "proxy-control://nothing"}), 7), Some(&bearer)).await;
        assert_eq!(
            serde_json::from_str::<Value>(&read).unwrap()["error"],
            json!({"code": 0, "message": "unknown resource proxy-control://nothing (404)"})
        );
    });
}

/// The Python SDK's stateless JSON transport, edge by edge.
#[test]
fn the_transport_edges_follow_the_python_sdk() {
    let fake = start_fake();
    let http = Http::new(start_server(&fake));
    run(async {
        let bearer = format!("Bearer {TOKEN}");
        // reqwest sends `Accept: */*` unless told otherwise, so every call names its Accept.
        let post = |accept: &'static str, content_type: &'static str, body: Vec<u8>| {
            let request = http
                .client
                .post(format!("{}/mcp", http.base))
                .header("host", "mcp.example.com")
                .header("authorization", bearer.clone())
                .header("accept", accept)
                .header("content-type", content_type)
                .body(body);
            async move {
                let response = request.send().await.unwrap();
                let status = response.status().as_u16();
                let headers = response.headers().clone();
                (status, headers, response.text().await.unwrap())
            }
        };
        let both = "application/json, text/event-stream";
        let ping = serde_json::to_vec(&rpc("ping", json!({}), 1)).unwrap();
        // JSON responses only need `application/json` in Accept.
        let (status, _, body) = post("application/json", "application/json", ping.clone()).await;
        assert_eq!((status, body.as_str()), (200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"));
        let (status, headers, body) = post("text/html", "application/json", ping.clone()).await;
        assert_eq!(status, 406);
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(
            body,
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Not Acceptable: Client must accept application/json\"}}"
        );
        let (status, _, _) = post(both, "application/jsonx", ping.clone()).await;
        assert_eq!(status, 415);
        let (status, _, body) = post(both, "application/json", b"{not json".to_vec()).await;
        assert_eq!(status, 400);
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["error"]["code"], -32700);
        assert!(body.contains("Parse error: key must be a string at line 1 column 2"), "{body}");
        let (status, _, body) = post(both, "application/json", b"{\"hello\": 1}".to_vec()).await;
        assert_eq!(
            (status, serde_json::from_str::<Value>(&body).unwrap()["error"]["code"].clone()),
            (400, json!(-32602))
        );
        let error = |body: &str| serde_json::from_str::<Value>(body).unwrap()["error"].clone();
        let unknown = serde_json::to_vec(&rpc("no/such/method", json!({}), 1)).unwrap();
        let (_, _, body) = post(both, "application/json", unknown).await;
        assert_eq!(error(&body), json!({"code": -32601, "message": "Method not found", "data": "no/such/method"}));
        for method in ["prompts/list", "resources/templates/list"] {
            let (_, _, body) =
                post(both, "application/json", serde_json::to_vec(&rpc(method, json!({}), 1)).unwrap()).await;
            assert_eq!(error(&body), json!({"code": -32601, "message": "Method not found", "data": method}));
        }
        for params in [json!({"arguments": {}}), json!({"name": "overview", "arguments": [1]})] {
            let (_, _, body) =
                post(both, "application/json", serde_json::to_vec(&rpc("tools/call", params, 1)).unwrap()).await;
            assert_eq!(error(&body), json!({"code": -32602, "message": "Invalid request parameters", "data": ""}));
        }
        let note = serde_json::to_vec(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).unwrap();
        let (status, headers, body) = post(both, "application/json", note).await;
        assert_eq!((status, body.as_str(), headers["content-type"].to_str().unwrap()), (202, "", "application/json"));
        let auth = [("authorization", bearer.as_str())];
        let (status, headers, body) = http.send("DELETE", "/mcp", "mcp.example.com", &auth, None).await;
        assert_eq!(status, 405);
        assert_eq!(headers["content-type"], "application/json");
        assert!(body.contains("Method Not Allowed: Session termination not supported"));
        let (status, headers, _) = http.send("PUT", "/mcp", "mcp.example.com", &auth, None).await;
        assert_eq!((status, headers["allow"].to_str().unwrap()), (405, "GET, POST, DELETE"));
        let json_only = [("authorization", bearer.as_str()), ("accept", "application/json")];
        assert_eq!(http.send("GET", "/mcp", "mcp.example.com", &json_only, None).await.0, 406);
        // GET opens the standalone stream: headers now, then only keep-alive comments.
        let stream = http
            .client
            .get(format!("{}/mcp", http.base))
            .header("host", "mcp.example.com")
            .header("authorization", bearer.clone())
            .header("accept", "text/event-stream")
            .send()
            .await
            .unwrap();
        assert_eq!(stream.status().as_u16(), 200);
        assert_eq!(stream.headers()["content-type"], "text/event-stream");
        assert_eq!(stream.headers()["cache-control"], "no-cache, no-transform");
        drop(stream);
    });
}

#[test]
fn a_host_outside_the_allowlist_is_refused() {
    let fake = start_fake();
    let http = Http::new(start_server(&fake));
    run(async {
        let bearer = format!("Bearer {TOKEN}");
        let send = |host: &'static str, content_type: &'static str, origin: Option<&'static str>| {
            let mut headers = vec![
                ("accept", "application/json, text/event-stream"),
                ("content-type", content_type),
                ("authorization", bearer.as_str()),
            ];
            if let Some(origin) = origin {
                headers.push(("origin", origin));
            }
            let http = &http;
            async move { http.send("POST", "/mcp", host, &headers, Some(&initialize())).await }
        };
        let json = "application/json";
        let (status, _, body) = send("evil.example.com", json, None).await;
        assert_eq!((status, body.as_str()), (421, "Invalid Host header"));
        // Exact names only: the public name with a port is not on the list.
        assert_eq!(send("mcp.example.com:443", json, None).await.0, 421);
        assert_eq!(send("127.0.0.1:8793", json, None).await.0, 200);
        let (status, _, body) = send("mcp.example.com", json, Some("https://evil.example.com")).await;
        assert_eq!((status, body.as_str()), (403, "Invalid Origin header"));
        assert_eq!(send("mcp.example.com", json, Some("https://mcp.example.com")).await.0, 200);
        assert_eq!(send("mcp.example.com", json, Some("http://127.0.0.1:8793")).await.0, 200);
        let (status, _, body) = send("mcp.example.com", "text/plain", None).await;
        assert_eq!((status, body.as_str()), (400, "Invalid Content-Type header"));
        assert_eq!(send("mcp.example.com", "application/json; charset=utf-8", None).await.0, 200);
        // Without the bearer the gate answers first, whatever the host.
        assert_eq!(http.mcp(&initialize(), None).await.0, 401);
    });
}
