//! The curated tools (spec §9a): the operator's everyday moves in one call each, with
//! hand-written descriptions — a client with its placement and its subscription link, a
//! version check and update, a routing preview and apply, the audit tail — and the three
//! resources. Every mutation that cannot be undone asks for `confirm`.

use serde_json::{json, Map, Value};

use crate::panel::{encode_path, PanelClient};
use crate::py::{self, PyErr};
use crate::tools::{confirm_schema, refusal, text_result, Fail, ToolResult};

pub struct Curated {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Map<String, Value>,
}

fn placement_item() -> Value {
    json!({
        "type": "object",
        "properties": {
            "node_id": {"type": "string", "description": "The node: `local` for this panel, or a linked panel's id."},
            "protocol": {"type": "string", "enum": ["mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"]},
            "runtime_username": {"type": "string", "description": "Account name on the runtime; derived from the display name when omitted."},
            "options": {"type": "object", "description": "Protocol options (quota, limits…); the panel validates them. For `amneziawg` set `{\"version\": \"1.5\"|\"2.0\"|\"3.1\"}` (default 2.0); each version is its own access, the account is named `<name>-awg<ver>`. For `trusttunnel` options are optional (`{\"name\": \"<label shown in the app>\"}`); the node teaches the rest."},
        },
        "required": ["node_id", "protocol"],
        "additionalProperties": false,
    })
}

fn placement() -> Value {
    json!({"type": "array", "items": placement_item(), "description": "The node×protocol matrix the client should have."})
}

fn schema(properties: Value, required: &[&str]) -> Map<String, Value> {
    let mut schema = Map::new();
    schema.insert("type".into(), json!("object"));
    schema.insert("properties".into(), properties);
    schema.insert("additionalProperties".into(), json!(false));
    if !required.is_empty() {
        schema.insert("required".into(), json!(required));
    }
    schema
}

pub fn curated() -> Vec<Curated> {
    let routing_protocol = json!({"type": "string", "enum": ["naive", "mieru", "mtproxy", "trusttunnel", "amneziawg"]});
    vec![
        Curated {
            name: "overview",
            description: "One picture of the panel: the dashboard (runtimes, clients, server resources), the installed and available \
component versions, the nodes with their status and a compact `metrics` section (per node: status, CPU/RAM/disk %, \
network rates, per-protocol up/down bytes per second and sessions, alerts; `null` if monitoring is unavailable). \
GET /api/dashboard + /api/versions + /api/nodes + /api/metrics/live?node=all.",
            input_schema: schema(json!({}), &[]),
        },
        Curated {
            name: "create_client",
            description: "Create a client, place it on nodes and protocols, and return its subscription URL in one go: \
POST /api/clients, then POST /api/clients/{id}/grants with the placement, then the one-shot reveal. \
`placement` is a list of {node_id, protocol}; the account name defaults to the display name in lower case.",
            input_schema: schema(
                json!({
                    "display_name": {"type": "string", "minLength": 1, "maxLength": 128},
                    "placement": placement(),
                    "subscription": {"type": "boolean", "default": true, "description": "Issue a subscription URL (needs the panel's subscription domain)."},
                }),
                &["display_name"],
            ),
        },
        Curated {
            name: "client_subscription",
            description: "Show a client's subscription URL again (and its client-format variants). The panel opens the escrowed \
token for one reveal and records it in the audit log.",
            input_schema: schema(json!({"client_id": {"type": "string"}}), &["client_id"]),
        },
        Curated {
            name: "set_client_placement",
            description: "Bring a client's node×protocol matrix to the desired one: issue the missing grants, enable the disabled \
ones that are wanted, disable the enabled ones that are not (nothing is deleted). Without confirm the tool \
only reports the plan; with confirm=true it runs it.",
            input_schema: schema(
                json!({"client_id": {"type": "string"}, "placement": placement(), "confirm": confirm_schema()}),
                &["client_id", "placement"],
            ),
        },
        Curated {
            name: "versions_check",
            description: "Ask the version-agent to poll upstream (GitHub Releases, image registries) for newer component versions. \
POST /api/versions/check; the result lands in `overview`/`proxy-control://versions`.",
            input_schema: schema(json!({}), &[]),
        },
        Curated {
            name: "versions_update",
            description: "Install a component version through the version-agent, with rollback on failure. \
POST /api/versions/{component}/update; `expected_current` must match the installed version. Irreversible: \
requires confirm=true.",
            input_schema: schema(
                json!({
                    "component": {"type": "string", "enum": ["telemt", "naive", "mita", "xray", "panel", "amneziawg", "trusttunnel"]},
                    "version": {"type": "string"},
                    "expected_current": {"type": "string"},
                    "confirm": confirm_schema(),
                }),
                &["component", "version", "expected_current", "confirm"],
            ),
        },
        Curated {
            name: "routing_preview",
            description: "Preview what a node's backend would enforce for a routing policy without saving or applying anything. \
POST /api/routing/policies/{node_id}/{protocol}/preview; `policy` is the policy body (omit it to preview \
the saved one); `lane` is `svc` (default) or `grant:<grant_id>`.",
            input_schema: schema(
                json!({
                    "node_id": {"type": "string"}, "protocol": routing_protocol.clone(),
                    "policy": {"type": ["object", "null"], "description": "The policy to preview; null = the saved policy."},
                    "lane": {"type": "string", "default": "svc"},
                }),
                &["node_id", "protocol"],
            ),
        },
        Curated {
            name: "routing_apply",
            description: "Apply the saved routing policy revision to the node's backend (transactional, with rollback). \
POST /api/routing/policies/{node_id}/{protocol}/apply with `expected_revision`. Requires confirm=true.",
            input_schema: schema(
                json!({
                    "node_id": {"type": "string"}, "protocol": routing_protocol,
                    "expected_revision": {"type": "integer", "minimum": 1},
                    "lane": {"type": "string", "default": "svc"},
                    "confirm": confirm_schema(),
                }),
                &["node_id", "protocol", "expected_revision", "confirm"],
            ),
        },
        Curated {
            name: "audit_tail",
            description: "The newest audit rows (who did what, from where, under which request id). GET /api/audit; \
MCP actions appear with `via: api-key` and the key's name.",
            input_schema: schema(
                json!({
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
                    "actor": {"type": "string"}, "action": {"type": "string"}, "target": {"type": "string"},
                    "request_id": {"type": "string"}, "before_id": {"type": "integer", "minimum": 1},
                }),
                &[],
            ),
        },
        Curated {
            name: "reload_tools",
            description: "Fetch the panel's OpenAPI schema again and rebuild the generated tools (after a panel update).",
            input_schema: schema(json!({}), &[]),
        },
    ]
}

pub const RESOURCES: [(&str, &str); 3] = [
    ("proxy-control://overview", "Dashboard, versions, nodes and live metrics in one JSON document."),
    ("proxy-control://versions", "Installed and available component versions (GET /api/versions)."),
    ("proxy-control://nodes", "This panel's nodes with their status (GET /api/nodes)."),
];

pub async fn read_resource(uri: &str, panel: &PanelClient) -> Result<Value, Fail> {
    match uri {
        "proxy-control://overview" => overview_data(panel).await,
        "proxy-control://versions" => Ok(panel.get("/api/versions", &[]).await?),
        _ => nodes_data(panel).await,
    }
}

pub async fn run(name: &str, panel: &PanelClient, arguments: &Map<String, Value>) -> Result<ToolResult, Fail> {
    match name {
        "overview" => Ok(text_result(&overview_data(panel).await?, false)),
        "create_client" => create_client(panel, arguments).await,
        "client_subscription" => client_subscription(panel, arguments).await,
        "set_client_placement" => set_client_placement(panel, arguments).await,
        "versions_check" => Ok(text_result(&panel.post("/api/versions/check", None, &[]).await?, false)),
        "versions_update" => versions_update(panel, arguments).await,
        "routing_preview" => routing_preview(panel, arguments).await,
        "routing_apply" => routing_apply(panel, arguments).await,
        "audit_tail" => audit_tail(panel, arguments).await,
        // `reload_tools` is answered by the registry before it gets here.
        _ => Err(Fail::Py(PyErr::new("PanelError", "reload_tools is handled by the registry"))),
    }
}

/// `arguments.get(key)` (None when absent).
fn arg(arguments: &Map<String, Value>, key: &str) -> Value {
    arguments.get(key).cloned().unwrap_or(Value::Null)
}

/// `arguments.get(key, default)`.
fn arg_or(arguments: &Map<String, Value>, key: &str, default: Value) -> Value {
    arguments.get(key).cloned().unwrap_or(default)
}

/// `Alice Example` → `alice-example`: what the panel's dialog proposes, within the runtime
/// username rule `[A-Za-z0-9_.-]{1,64}`.
pub fn derive_username(display_name: &str) -> String {
    let lowered = py::strip(display_name).to_lowercase();
    let mut value = String::new();
    let mut in_run = false;
    for c in lowered.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
            value.push(c);
            in_run = false;
        } else if !in_run {
            value.push('-');
            in_run = true;
        }
    }
    let value = value.trim_matches(['-', '.']);
    let value = if value.is_empty() { "client" } else { value };
    value.chars().take(64).collect()
}

/// The reveal payload without its QR images: a model reads the link, not a picture.
fn strip_qr(payload: &Value) -> Result<Value, PyErr> {
    let field = |key: &str| -> Result<Value, PyErr> { Ok(py::get(payload, key)?.cloned().unwrap_or(Value::Null)) };
    let subscription_id = field("subscription_id")?;
    let generation = field("generation")?;
    let url = field("url")?;
    let variants_value = field("variants")?;
    let variants_value = if py::truthy(&variants_value) { variants_value } else { json!({}) };
    let mut variants = Map::new();
    for (name, item) in py::items(&variants_value)? {
        if item.is_object() {
            variants.insert(name, item.get("url").cloned().unwrap_or(Value::Null));
        }
    }
    Ok(json!({"subscription_id": subscription_id, "generation": generation, "url": url, "variants": variants}))
}

async fn reveal(panel: &PanelClient, token: &Value) -> Result<Value, Fail> {
    let answer = panel.get(&encode_path("/api/reveal/{token}", &[("token", token)]), &[]).await?;
    Ok(strip_qr(&answer)?)
}

// --- overview ---------------------------------------------------------------------------

/// One node of `/api/metrics/live` cut down to what a status report needs.
fn metrics_node(entry: &Value) -> Result<Value, PyErr> {
    let field =
        |value: &Value, key: &str| -> Result<Value, PyErr> { Ok(py::get(value, key)?.cloned().unwrap_or(Value::Null)) };
    let host = field(entry, "host")?;
    let host = if host.is_object() { host } else { json!({}) };
    let net = field(&host, "net")?;
    let net = if net.is_object() { net } else { json!({}) };
    let load = field(&host, "load")?;
    let protocols_value = field(entry, "protocols")?;
    let protocols_value = if py::truthy(&protocols_value) { protocols_value } else { json!({}) };
    let mut protocols = Map::new();
    for (name, item) in py::items(&protocols_value)? {
        if item.is_object() && py::truthy(item.get("available").unwrap_or(&Value::Null)) {
            protocols.insert(
                name,
                json!({
                    "up_bps": item.get("up_bps").cloned().unwrap_or(Value::Null),
                    "down_bps": item.get("down_bps").cloned().unwrap_or(Value::Null),
                    "sessions": item.get("sessions").cloned().unwrap_or(Value::Null),
                }),
            );
        }
    }
    let or_empty = |value: Value| if py::truthy(&value) { value } else { json!({}) };
    let mut out = Map::new();
    out.insert("node_id".into(), field(entry, "node_id")?);
    out.insert("name".into(), field(entry, "name")?);
    out.insert("status".into(), field(entry, "status")?);
    out.insert("age_seconds".into(), field(entry, "age_seconds")?);
    out.insert("cpu_percent".into(), field(&host, "cpu_percent")?);
    out.insert("mem_percent".into(), field(&or_empty(field(&host, "mem")?), "percent")?);
    out.insert("disk_percent".into(), field(&or_empty(field(&host, "disk")?), "percent")?);
    out.insert(
        "load1".into(),
        match &load {
            Value::Array(items) if !items.is_empty() => items[0].clone(),
            _ => Value::Null,
        },
    );
    out.insert("net_rx_bps".into(), field(&net, "rx_bps")?);
    out.insert("net_tx_bps".into(), field(&net, "tx_bps")?);
    out.insert("protocols".into(), Value::Object(protocols));
    let alerts_value = field(entry, "alerts")?;
    let alerts_value = if py::truthy(&alerts_value) { alerts_value } else { json!([]) };
    let mut alerts = Vec::new();
    for alert in py::iterate(&alerts_value)? {
        if alert.is_object() {
            alerts.push(json!({
                "kind": alert.get("kind").cloned().unwrap_or(Value::Null),
                "severity": alert.get("severity").cloned().unwrap_or(Value::Null),
                "detail": alert.get("detail").cloned().unwrap_or(Value::Null),
            }));
        }
    }
    out.insert("alerts".into(), Value::Array(alerts));
    Ok(Value::Object(out))
}

/// Live meters of every node, reduced; `None` when the panel has no monitoring to give.
async fn metrics_data(panel: &PanelClient) -> Value {
    let Ok(live) = panel.get("/api/metrics/live", &[("node", json!("all"))]).await else {
        return Value::Null;
    };
    // AttributeError and TypeError (an answer of the wrong shape) also mean "no metrics".
    let reduce = || -> Result<Value, PyErr> {
        let ts = py::get(&live, "ts")?.cloned().unwrap_or(Value::Null);
        let nodes_value = py::get(&live, "nodes")?.cloned().unwrap_or(Value::Null);
        let nodes_value = if py::truthy(&nodes_value) { nodes_value } else { json!([]) };
        let mut nodes = Vec::new();
        for node in py::iterate(&nodes_value)? {
            if node.is_object() {
                nodes.push(metrics_node(&node)?);
            }
        }
        Ok(json!({"ts": ts, "nodes": nodes}))
    };
    reduce().unwrap_or(Value::Null)
}

/// `nodes.get("items", nodes) if isinstance(nodes, dict) else nodes`.
fn node_items(nodes: Value) -> Value {
    match &nodes {
        Value::Object(map) => map.get("items").cloned().unwrap_or(nodes),
        _ => nodes,
    }
}

pub async fn overview_data(panel: &PanelClient) -> Result<Value, Fail> {
    let nodes = panel.get("/api/nodes", &[]).await?;
    let dashboard = panel.get("/api/dashboard", &[]).await?;
    let versions = panel.get("/api/versions", &[]).await?;
    let nodes = node_items(nodes);
    let metrics = metrics_data(panel).await;
    Ok(json!({"dashboard": dashboard, "versions": versions, "nodes": nodes, "metrics": metrics}))
}

async fn nodes_data(panel: &PanelClient) -> Result<Value, Fail> {
    Ok(node_items(panel.get("/api/nodes", &[]).await?))
}

// --- clients ----------------------------------------------------------------------------

/// `str((options or {}).get("version") or "2.0")`.
fn awg_version(options: &Value) -> Result<String, PyErr> {
    let options = if py::truthy(options) { options.clone() } else { json!({}) };
    let version = py::get(&options, "version")?.cloned().unwrap_or(Value::Null);
    Ok(if py::truthy(&version) { py::str_of(&version) } else { "2.0".into() })
}

/// AmneziaWG versions are different accesses on one node, so the version is part of the key.
fn placement_key(node_id: &Value, protocol: &Value, options: &Value) -> Result<(Value, Value), PyErr> {
    let protocol = if protocol.as_str() == Some("amneziawg") {
        Value::String(format!("amneziawg:{}", awg_version(options)?))
    } else {
        protocol.clone()
    };
    Ok((node_id.clone(), protocol))
}

/// The key of a placement item: `(item["node_id"], item["protocol"], item.get("options"))`.
fn item_key(item: &Value) -> Result<(Value, Value), PyErr> {
    let node_id = py::getitem(item, "node_id")?;
    let protocol = py::getitem(item, "protocol")?;
    let options = py::get(item, "options")?.cloned().unwrap_or(Value::Null);
    placement_key(node_id, protocol, &options)
}

fn key_eq(a: &(Value, Value), b: &(Value, Value)) -> bool {
    py::eq(&a.0, &b.0) && py::eq(&a.1, &b.1)
}

/// A tuple key used in a dict must be hashable: a list or dict inside raises TypeError.
fn hashable(key: &(Value, Value)) -> Result<(), PyErr> {
    for part in [&key.0, &key.1] {
        if part.is_array() || part.is_object() {
            return Err(PyErr::type_error(format!("unhashable type: '{}'", py::type_name(part))));
        }
    }
    Ok(())
}

fn account(item: &Value, username: &str) -> Result<Value, PyErr> {
    let runtime = py::get(item, "runtime_username")?.cloned().unwrap_or(Value::Null);
    if py::truthy(&runtime) {
        return Ok(py::getitem(item, "runtime_username")?.clone());
    }
    if py::getitem(item, "protocol")?.as_str() == Some("amneziawg") {
        let options = py::get(item, "options")?.cloned().unwrap_or(Value::Null);
        let short: String = username.chars().take(56).collect();
        return Ok(Value::String(format!("{short}-awg{}", awg_version(&options)?.replace('.', ""))));
    }
    Ok(Value::String(username.to_string()))
}

fn grants_body(placement: &[Value], username: &str) -> Result<Value, PyErr> {
    let mut grants = Vec::new();
    for item in placement {
        let protocol = py::getitem(item, "protocol")?.clone();
        let node_id = py::get(item, "node_id")?.cloned().unwrap_or_else(|| json!("local"));
        let runtime_username = account(item, username)?;
        let options = py::get(item, "options")?.cloned().unwrap_or(Value::Null);
        let options = if py::truthy(&options) { options } else { json!({}) };
        grants.push(
            json!({"protocol": protocol, "node_id": node_id, "runtime_username": runtime_username, "options": options}),
        );
    }
    Ok(json!({"grants": grants}))
}

async fn create_client(panel: &PanelClient, arguments: &Map<String, Value>) -> Result<ToolResult, Fail> {
    let display_name = py::strip(&py::str_of(&arg_or(arguments, "display_name", json!("")))).to_string();
    if display_name.is_empty() {
        return Ok(text_result(&json!({"error": "display_name is required"}), true));
    }
    let placement = arg(arguments, "placement");
    let placement = if py::truthy(&placement) { py::iterate(&placement)? } else { Vec::new() };
    let subscription = arg_or(arguments, "subscription", json!(true)) != Value::Bool(false);
    let client = panel
        .post("/api/clients", Some(&json!({"display_name": display_name, "subscription": subscription})), &[])
        .await?;
    let shown: Map<String, Value> =
        py::items(&client)?.into_iter().filter(|(key, _)| key != "subscription_reveal_token").collect();
    let mut result = Map::new();
    result.insert("client".into(), Value::Object(shown));
    result.insert("grants".into(), Value::Null);
    result.insert("subscription_url".into(), Value::Null);
    result.insert("subscription".into(), Value::Null);
    if !placement.is_empty() {
        let path = encode_path("/api/clients/{client_id}/grants", &[("client_id", py::getitem(&client, "id")?)]);
        let body = grants_body(&placement, &derive_username(&display_name))?;
        result.insert("grants".into(), panel.post(&path, Some(&body), &[]).await?);
    }
    let token = py::get(&client, "subscription_reveal_token")?.cloned().unwrap_or(Value::Null);
    if py::truthy(&token) {
        let revealed = reveal(panel, &token).await?;
        result.insert("subscription_url".into(), revealed["url"].clone());
        result.insert("subscription".into(), revealed);
    } else if subscription {
        result.insert("subscription".into(), json!({"note": "no subscription domain is configured on this panel"}));
    }
    Ok(text_result(&Value::Object(result), false))
}

async fn client_subscription(panel: &PanelClient, arguments: &Map<String, Value>) -> Result<ToolResult, Fail> {
    let client_id = Value::String(py::str_of(&arg_or(arguments, "client_id", json!(""))));
    let path = encode_path("/api/clients/{client_id}/subscription/reveal", &[("client_id", &client_id)]);
    let answer = panel.post(&path, None, &[]).await?;
    let token = py::getitem(&answer, "reveal_token")?.clone();
    Ok(text_result(&reveal(panel, &token).await?, false))
}

fn step(grant_id: Option<&Value>, key: &(Value, Value)) -> Value {
    let mut entry = Map::new();
    if let Some(grant_id) = grant_id {
        entry.insert("grant_id".into(), grant_id.clone());
    }
    entry.insert("node_id".into(), key.0.clone());
    entry.insert("protocol".into(), key.1.clone());
    Value::Object(entry)
}

async fn set_client_placement(panel: &PanelClient, arguments: &Map<String, Value>) -> Result<ToolResult, Fail> {
    let client_id = py::str_of(&arg_or(arguments, "client_id", json!("")));
    let placement_value = arg(arguments, "placement");
    let placement = if py::truthy(&placement_value) { py::iterate(&placement_value)? } else { Vec::new() };
    let desired: Vec<(Value, Value)> = placement.iter().map(item_key).collect::<Result<_, _>>()?;
    let client_value = Value::String(client_id.clone());
    let current = panel.get(&encode_path("/api/clients/{client_id}", &[("client_id", &client_value)]), &[]).await?;
    let mut grants = Vec::new();
    for grant in py::iterate(&py::get_or(&current, "grants", json!([]))?)? {
        let state = py::get(&grant, "desired_state")?.cloned().unwrap_or(Value::Null);
        if !py::eq(&state, &json!("deleted")) {
            grants.push(grant);
        }
    }
    let mut by_key: Vec<((Value, Value), Value)> = Vec::new();
    for grant in &grants {
        let key = item_key(grant)?;
        hashable(&key)?;
        py::dict_set(&mut by_key, key, grant.clone(), key_eq);
    }
    let lookup = |key: &(Value, Value)| -> Result<Option<Value>, PyErr> {
        hashable(key)?;
        Ok(by_key.iter().find(|(known, _)| key_eq(known, key)).map(|(_, grant)| grant.clone()))
    };
    let (mut issue, mut enable, mut disable, mut keep) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for key in &desired {
        match lookup(key)? {
            None => issue.push(step(None, key)),
            Some(grant) => {
                let enabled = py::eq(py::get(&grant, "desired_state")?.unwrap_or(&Value::Null), &json!("enabled"));
                let entry = step(Some(py::getitem(&grant, "id")?), key);
                if enabled {
                    keep.push(entry);
                } else {
                    enable.push(entry);
                }
            }
        }
    }
    for (key, grant) in &by_key {
        let wanted = desired.iter().any(|candidate| key_eq(candidate, key));
        if !wanted && py::eq(py::get(grant, "desired_state")?.unwrap_or(&Value::Null), &json!("enabled")) {
            disable.push(step(Some(py::getitem(grant, "id")?), key));
        }
    }
    let plan = json!({"issue": issue, "enable": enable, "disable": disable, "keep": keep});
    if arg(arguments, "confirm") != Value::Bool(true) {
        return Ok(refusal(
            "PLAN",
            &format!("/api/clients/{client_id}"),
            Some("Placement change planned; call again with confirm=true to run it."),
            Some(("plan", plan)),
        ));
    }
    let mut username = Value::Null;
    for grant in &grants {
        let runtime = py::get(grant, "runtime_username")?.cloned().unwrap_or(Value::Null);
        if py::truthy(&runtime) {
            username = runtime;
            break;
        }
    }
    let username = if py::truthy(&username) {
        py::str_of(&username)
    } else {
        let client = py::get_or(&current, "client", json!({}))?;
        let name = py::get(&client, "display_name")?.cloned().unwrap_or(Value::Null);
        derive_username(&if py::truthy(&name) { py::str_of(&name) } else { client_id.clone() })
    };
    let (mut enabled, mut disabled) = (Vec::new(), Vec::new());
    for entry in &disable {
        let path = encode_path("/api/clients/grants/{grant_id}/disable", &[("grant_id", &entry["grant_id"])]);
        panel.post(&path, None, &[]).await?;
        disabled.push(entry["grant_id"].clone());
    }
    for entry in &enable {
        let path = encode_path("/api/clients/grants/{grant_id}/enable", &[("grant_id", &entry["grant_id"])]);
        panel.post(&path, None, &[]).await?;
        enabled.push(entry["grant_id"].clone());
    }
    let mut issued = Value::Null;
    if !issue.is_empty() {
        let mut wanted: Vec<((Value, Value), Value)> = Vec::new();
        for item in &placement {
            let key = item_key(item)?;
            hashable(&key)?;
            py::dict_set(&mut wanted, key, item.clone(), key_eq);
        }
        let mut items = Vec::new();
        for entry in &issue {
            let key = (entry["node_id"].clone(), entry["protocol"].clone());
            let found = wanted.iter().find(|(known, _)| key_eq(known, &key)).map(|(_, item)| item.clone());
            items.push(found.ok_or_else(|| PyErr::new("KeyError", py::repr(&json!([key.0, key.1]))))?);
        }
        let path = encode_path("/api/clients/{client_id}/grants", &[("client_id", &client_value)]);
        issued = panel.post(&path, Some(&grants_body(&items, &username)?), &[]).await?;
    }
    let results = json!({"issued": issued, "enabled": enabled, "disabled": disabled});
    Ok(text_result(&json!({"refused": false, "plan": plan, "results": results}), false))
}

// --- versions, routing, audit -----------------------------------------------------------

async fn versions_update(panel: &PanelClient, arguments: &Map<String, Value>) -> Result<ToolResult, Fail> {
    let component = arg_or(arguments, "component", json!(""));
    let path = encode_path("/api/versions/{component}/update", &[("component", &component)]);
    if arg(arguments, "confirm") != Value::Bool(true) {
        let detail = format!(
            "Would install {} {} (expecting {} now). Call again with confirm=true.",
            py::str_of(&arg(arguments, "component")),
            py::str_of(&arg(arguments, "version")),
            py::str_of(&arg(arguments, "expected_current")),
        );
        return Ok(refusal("POST", &path, Some(&detail), None));
    }
    let body = json!({"version": arg(arguments, "version"), "expected_current": arg(arguments, "expected_current")});
    Ok(text_result(&panel.post(&path, Some(&body), &[]).await?, false))
}

fn routing_path(arguments: &Map<String, Value>, action: &str) -> String {
    let node_id = arg_or(arguments, "node_id", json!(""));
    let protocol = arg_or(arguments, "protocol", json!(""));
    encode_path(
        &format!("/api/routing/policies/{{node_id}}/{{protocol}}/{action}"),
        &[("node_id", &node_id), ("protocol", &protocol)],
    )
}

/// `arguments.get("lane") or "svc"`.
fn lane(arguments: &Map<String, Value>) -> Value {
    let lane = arg(arguments, "lane");
    if py::truthy(&lane) {
        lane
    } else {
        json!("svc")
    }
}

async fn routing_preview(panel: &PanelClient, arguments: &Map<String, Value>) -> Result<ToolResult, Fail> {
    let path = routing_path(arguments, "preview");
    let policy = arg(arguments, "policy");
    let body = (!policy.is_null()).then_some(&policy);
    Ok(text_result(&panel.post(&path, body, &[("lane", lane(arguments))]).await?, false))
}

async fn routing_apply(panel: &PanelClient, arguments: &Map<String, Value>) -> Result<ToolResult, Fail> {
    let path = routing_path(arguments, "apply");
    let lane = lane(arguments);
    if arg(arguments, "confirm") != Value::Bool(true) {
        return Ok(refusal(
            "POST",
            &format!("{path}?lane={}", py::str_of(&lane)),
            Some("Would apply the saved policy to the node's backend. Call again with confirm=true."),
            None,
        ));
    }
    let body = json!({"expected_revision": arg(arguments, "expected_revision")});
    Ok(text_result(&panel.post(&path, Some(&body), &[("lane", lane)]).await?, false))
}

async fn audit_tail(panel: &PanelClient, arguments: &Map<String, Value>) -> Result<ToolResult, Fail> {
    let mut params: Vec<(&str, Value)> = Vec::new();
    let limit = arg(arguments, "limit");
    let limit = if py::truthy(&limit) { limit } else { json!(50) };
    params.push(("limit", Value::String(py::int_of(&limit)?)));
    for key in ["actor", "action", "target", "request_id", "before_id"] {
        params.push((key, arg(arguments, key)));
    }
    Ok(text_result(&panel.get("/api/audit", &params).await?, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_username_follows_the_panel_dialog() {
        assert_eq!(derive_username("Alice Example"), "alice-example");
        assert_eq!(derive_username("  Ünïcode Name!! x "), "n-code-name-x");
        assert_eq!(derive_username("...---"), "client");
        assert_eq!(derive_username(&"a".repeat(80)).len(), 64);
        assert_eq!(derive_username("x.y_z-1"), "x.y_z-1");
    }
}
