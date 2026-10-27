//! Tools from the panel's OpenAPI schema (spec §9a): one per operation, named `<method>_<path>`
//! (`/api/` dropped, `{x}` → `by_x`), the input schema merged from path parameters, query
//! parameters and the request body; irreversible operations carry a required `confirm` and
//! refuse without it — before the panel is ever called.
//!
//! The builder copies the Python one statement by statement, including what it does with odd
//! schemas: a body property named like a required path parameter, a `confirm` already in the
//! body (its name then appears twice in `required`), a cut `$ref` cycle.

use std::sync::{Arc, RwLock};

use serde_json::{json, Map, Value};

use crate::curated::{self, Curated};
use crate::panel::{encode_path, PanelClient, PanelError};
use crate::py::{self, PyErr};

pub const METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];
const BODY_METHODS: [&str; 3] = ["POST", "PUT", "PATCH"];
pub const NAME_LIMIT: usize = 64;
// Paths the MCP server does not expose: its own schema and health, the login surface, the
// one-shot reveal (consumed by the curated tools), the subscriber endpoint and the node API
// behind a fleet key. Anything outside `/api/` is the browser's, not the API's.
// `/api/metrics/stream` is an endless SSE response: a tool call waits for a finished answer.
const EXCLUDED_EXACT: [&str; 5] =
    ["/api/openapi.json", "/healthz", "/login", "/api/reveal/{token}", "/api/metrics/stream"];
const EXCLUDED_PREFIXES: [&str; 3] = ["/api/auth/", "/s/", "/api/fleet/"];
// Mutations that cannot be undone: a `DELETE`, or a POST/PUT on one of these paths.
const IRREVERSIBLE_MARKERS: [&str; 11] = [
    "/update",
    "/rollback",
    "/unlink",
    "/revoke",
    "/rotate",
    "/delete",
    "/archive",
    "/check",
    "/exits/test",
    "/reset-quota",
    "/reset-metrics",
];
// `POST /api/nodes/{node_id}/versions/{component}` installs a version on a node.
const VERSION_INSTALL_MARKER: &str = "/versions/{component}";

pub fn confirm_schema() -> Value {
    json!({
        "type": "boolean",
        "description": "This operation cannot be undone. Pass true to run it; without it the tool only describes what it would do.",
    })
}

/// A failed call: the panel refused (an error result) or the handler hit what was a Python
/// exception (a JSON-RPC error with code 0 and `str(exc)`).
#[derive(Debug)]
pub enum Fail {
    Panel(PanelError),
    Py(PyErr),
}

impl From<PanelError> for Fail {
    fn from(err: PanelError) -> Self {
        Fail::Panel(err)
    }
}

impl From<PyErr> for Fail {
    fn from(err: PyErr) -> Self {
        Fail::Py(err)
    }
}

/// What a tool answers: one text block with indented JSON and the error flag.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolResult {
    pub text: String,
    pub is_error: bool,
}

impl ToolResult {
    /// The text as JSON, for tests.
    #[cfg(test)]
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap()
    }
}

pub fn text_result(value: &Value, is_error: bool) -> ToolResult {
    ToolResult { text: py::dumps(value, true), is_error }
}

pub fn refusal(method: &str, path: &str, detail: Option<&str>, extra: Option<(&str, Value)>) -> ToolResult {
    let mut body = Map::new();
    body.insert("refused".into(), Value::Bool(true));
    body.insert("would".into(), Value::String(format!("{method} {path}")));
    body.insert(
        "detail".into(),
        Value::String(
            detail.unwrap_or("This operation cannot be undone. Call again with confirm=true to run it.").into(),
        ),
    );
    if let Some((key, value)) = extra {
        body.insert(key.into(), value);
    }
    text_result(&Value::Object(body), false)
}

pub fn tool_name(method: &str, path: &str) -> String {
    let stem = match path.strip_prefix("/api/") {
        Some(rest) => rest,
        None => path.trim_start_matches('/'),
    };
    // re.sub(r"\{([^}]+)\}", r"by_\1", stem)
    let chars: Vec<char> = stem.chars().collect();
    let mut replaced = String::new();
    let mut at = 0;
    while at < chars.len() {
        if chars[at] == '{' {
            if let Some(close) = chars[at + 1..].iter().position(|&c| c == '}') {
                if close > 0 {
                    replaced.push_str("by_");
                    replaced.extend(&chars[at + 1..at + 1 + close]);
                    at += close + 2;
                    continue;
                }
            }
        }
        replaced.push(chars[at]);
        at += 1;
    }
    let name = format!("{}_{}", method.to_lowercase(), replaced).replace('/', "_");
    let name: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect();
    let name: String = name.trim_matches('_').chars().take(NAME_LIMIT).collect();
    name.trim_end_matches('_').to_string()
}

pub fn is_excluded(path: &str) -> bool {
    !path.starts_with("/api/")
        || EXCLUDED_EXACT.contains(&path)
        || EXCLUDED_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

pub fn is_irreversible(method: &str, path: &str) -> bool {
    let method = method.to_uppercase();
    if method == "DELETE" {
        return true;
    }
    (method == "POST" || method == "PUT")
        && (IRREVERSIBLE_MARKERS.iter().any(|marker| path.contains(marker)) || path.contains(VERSION_INSTALL_MARKER))
}

/// The schema with every `$ref` into `components/schemas` inlined (bounded depth, so a
/// recursive model cannot spin the builder). The siblings of a `$ref` are kept as they are.
pub fn resolve_refs(schema: &Value, components: &Value, depth: usize) -> Result<Value, PyErr> {
    match schema {
        Value::Array(items) => items.iter().map(|item| resolve_refs(item, components, depth)).collect(),
        Value::Object(map) if map.contains_key("$ref") => {
            let reference = &map["$ref"];
            let Value::String(reference) = reference else {
                return Err(PyErr::attribute(reference, "rsplit"));
            };
            let name = reference.rsplit('/').next().unwrap_or("");
            let target = py::get(components, name)?;
            match target {
                Some(target) if !target.is_null() && depth < 8 => {
                    let resolved = resolve_refs(target, components, depth + 1)?;
                    let siblings: Map<String, Value> =
                        map.iter().filter(|(key, _)| *key != "$ref").map(|(k, v)| (k.clone(), v.clone())).collect();
                    Ok(Value::Object(py::merge_mapping(&resolved, &siblings)?))
                }
                _ => Ok(json!({"type": "object"})),
            }
        }
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, value) in map {
                out.insert(key.clone(), resolve_refs(value, components, depth)?);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

fn request_body(operation: &Value) -> Result<Value, PyErr> {
    py::get_or(operation, "requestBody", json!({}))
}

fn body_schema(operation: &Value, components: &Value) -> Result<Option<Value>, PyErr> {
    let content = py::get_or(&request_body(operation)?, "content", json!({}))?;
    let media = py::get_or(&content, "application/json", json!({}))?;
    let schema = match py::get(&media, "schema")? {
        None | Some(Value::Null) => return Ok(None),
        Some(schema) => schema.clone(),
    };
    let mut schema = resolve_refs(&schema, components, 0)?;
    for key in ["anyOf", "oneOf"] {
        if py::contains(&schema, key)? {
            let mut objects = Vec::new();
            for item in py::iterate(py::getitem(&schema, key)?)? {
                if item.is_object() && !py::eq(item.get("type").unwrap_or(&Value::Null), &json!("null")) {
                    objects.push(item);
                }
            }
            schema = objects.into_iter().next().unwrap_or_else(|| json!({}));
            break;
        }
    }
    if py::contains(&schema, "allOf")? {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for item in py::iterate(py::getitem(&schema, "allOf")?)? {
            py::dict_update(&mut properties, &py::get_or(&item, "properties", json!({}))?)?;
            required.extend(py::iterate(&py::get_or(&item, "required", json!([]))?)?);
        }
        schema = json!({"type": "object", "properties": properties, "required": required});
    }
    Ok(Some(schema))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    None,
    Required,
    Optional,
}

#[derive(Debug, Clone)]
pub struct Operation {
    pub name: String,
    pub method: String,
    pub path: String,
    pub description: String,
    pub input_schema: Map<String, Value>,
    pub path_params: Vec<String>,
    pub query_params: Vec<String>,
    pub body_keys: Vec<String>,
    pub body_is_raw: bool,
    pub confirm: Confirm,
    pub required_body: bool,
}

impl Operation {
    pub fn needs_confirm(&self, concrete_path: &str) -> bool {
        self.confirm == Confirm::Required
            || (self.confirm == Confirm::Optional && is_irreversible(&self.method, concrete_path))
    }
}

pub fn build_operations(schema: &Value) -> Result<Vec<Operation>, PyErr> {
    let components = py::get_or(&py::get_or(schema, "components", json!({}))?, "schemas", json!({}))?;
    let mut paths = py::items(&py::get_or(schema, "paths", json!({}))?)?;
    paths.sort_by(|a, b| a.0.cmp(&b.0));
    let mut operations = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (path, methods) in paths {
        if is_excluded(&path) {
            continue;
        }
        for method in METHODS {
            let operation = match py::get(&methods, method)? {
                None | Some(Value::Null) => continue,
                Some(operation) => operation.clone(),
            };
            let name = tool_name(method, &path);
            if !seen.insert(name.clone()) {
                continue; // two operations collapsing to one name: the first wins
            }
            operations.push(build(name, &method.to_uppercase(), &path, &operation, &components)?);
        }
    }
    Ok(operations)
}

/// The name a parameter goes by: FastAPI only writes strings; anything else is used by its
/// `str()`.
fn parameter_name(value: &Value) -> String {
    py::str_of(value)
}

fn build(name: String, method: &str, path: &str, operation: &Value, components: &Value) -> Result<Operation, PyErr> {
    let mut properties = Map::new();
    let mut required: Vec<Value> = Vec::new();
    let mut path_params = Vec::new();
    let mut query_params = Vec::new();
    let mut param_enums: Vec<(String, Vec<Value>)> = Vec::new();
    for parameter in py::iterate(&py::get_or(operation, "parameters", json!([]))?)? {
        let parameter = resolve_refs(&parameter, components, 0)?;
        let location = py::get(&parameter, "in")?.cloned().unwrap_or(Value::Null);
        let pname = py::get(&parameter, "name")?.cloned().unwrap_or(Value::Null);
        let location = match location.as_str() {
            Some(location @ ("path" | "query")) => location.to_string(),
            _ => continue,
        };
        if !pc_common::pyvalue::truthy(&pname) {
            continue;
        }
        let pname = parameter_name(&pname);
        let mut pschema = py::get_or(&parameter, "schema", json!({"type": "string"}))?;
        let description = py::get(&parameter, "description")?.cloned().unwrap_or(Value::Null);
        if pc_common::pyvalue::truthy(&description) && !py::contains(&pschema, "description")? {
            match &mut pschema {
                Value::Object(map) => {
                    map.insert("description".into(), description);
                }
                Value::Array(_) => return Err(PyErr::type_error("list indices must be integers or slices, not str")),
                other => {
                    return Err(PyErr::type_error(format!(
                        "'{}' object does not support item assignment",
                        pc_common::pyvalue::type_name(other)
                    )))
                }
            }
        }
        properties.insert(pname.clone(), pschema.clone());
        if location == "path" {
            path_params.push(pname.clone());
        } else {
            query_params.push(pname.clone());
        }
        if location == "path" || pc_common::pyvalue::truthy(py::get(&parameter, "required")?.unwrap_or(&Value::Null)) {
            required.push(Value::String(pname.clone()));
        }
        let mut enumeration = py::get(&pschema, "enum")?.cloned().unwrap_or(Value::Null);
        if !pc_common::pyvalue::truthy(&enumeration) {
            enumeration = Value::Null;
            for item in py::iterate(&py::get_or(&pschema, "anyOf", json!([]))?)? {
                let found = py::get(&item, "enum")?.cloned().unwrap_or(Value::Null);
                if pc_common::pyvalue::truthy(&found) {
                    enumeration = found;
                    break;
                }
            }
        }
        if location == "path" && pc_common::pyvalue::truthy(&enumeration) {
            py::dict_set(&mut param_enums, pname, py::iterate(&enumeration)?, |a, b| a == b);
        }
    }
    let body = body_schema(operation, components)?;
    let mut body_keys: Vec<String> = Vec::new();
    let mut body_is_raw = false;
    if let Some(body) = body {
        let is_object = py::eq(py::get(&body, "type")?.unwrap_or(&Value::Null), &json!("object"))
            || py::contains(&body, "properties")?;
        if is_object {
            for (key, value) in py::items(&py::get_or(&body, "properties", json!({}))?)? {
                if properties.contains_key(&key) {
                    continue; // a path/query parameter of the same name wins
                }
                properties.insert(key.clone(), value);
                body_keys.push(key);
            }
            for key in py::iterate(&py::get_or(&body, "required", json!([]))?)? {
                if key.as_str().is_some_and(|key| body_keys.iter().any(|known| known == key)) {
                    required.push(key);
                }
            }
        } else {
            let Value::Object(mut raw) = body.clone() else { unreachable!("`.get` succeeded on a dict") };
            let description = raw.get("description").cloned().unwrap_or_else(|| json!("The request body."));
            raw.insert("description".into(), description);
            properties.insert("body".into(), Value::Object(raw));
            body_keys = vec!["body".into()];
            body_is_raw = true;
            if pc_common::pyvalue::truthy(py::get(&request_body(operation)?, "required")?.unwrap_or(&Value::Null)) {
                required.push(json!("body"));
            }
        }
    }
    let mut confirm = Confirm::None;
    if is_irreversible(method, path) {
        confirm = Confirm::Required;
    } else if method == "POST" || method == "PUT" {
        'search: for (pname, values) in &param_enums {
            for value in values {
                let Value::String(value) = value else {
                    return Err(PyErr::type_error(format!(
                        "replace() argument 2 must be str, not {}",
                        pc_common::pyvalue::type_name(value)
                    )));
                };
                if is_irreversible(method, &path.replace(&format!("{{{pname}}}"), value)) {
                    confirm = Confirm::Optional;
                    break 'search;
                }
            }
        }
    }
    if confirm != Confirm::None {
        properties.insert("confirm".into(), confirm_schema());
        if confirm == Confirm::Required {
            required.push(json!("confirm"));
        }
    }
    let mut input_schema = Map::new();
    input_schema.insert("type".into(), json!("object"));
    input_schema.insert("properties".into(), Value::Object(properties));
    input_schema.insert("additionalProperties".into(), json!(false));
    if !required.is_empty() {
        input_schema.insert("required".into(), Value::Array(required));
    }
    let parts = [
        py::strip_method(&py::get_or(operation, "summary", json!(""))?)?,
        py::strip_method(&py::get_or(operation, "description", json!(""))?)?,
    ];
    let joined = parts.iter().filter(|part| !part.is_empty()).cloned().collect::<Vec<_>>().join("\n\n");
    let mut description =
        if joined.is_empty() { format!("{method} {path}") } else { format!("{joined}\n\n{method} {path}") };
    if confirm == Confirm::Required {
        description.push_str("\n\nIrreversible: requires confirm=true.");
    }
    let required_body =
        pc_common::pyvalue::truthy(py::get(&request_body(operation)?, "required")?.unwrap_or(&Value::Null));
    Ok(Operation {
        name,
        method: method.to_string(),
        path: path.to_string(),
        description,
        input_schema,
        path_params,
        query_params,
        body_keys,
        body_is_raw,
        confirm,
        required_body,
    })
}

pub async fn run_operation(
    panel: &PanelClient,
    operation: &Operation,
    mut arguments: Map<String, Value>,
) -> Result<ToolResult, PyErr> {
    let confirmed = arguments.shift_remove("confirm") == Some(Value::Bool(true));
    let missing: Vec<&str> =
        operation.path_params.iter().filter(|name| !arguments.contains_key(*name)).map(String::as_str).collect();
    if !missing.is_empty() {
        let error = format!("missing path parameter(s): {}", missing.join(", "));
        return Ok(text_result(&json!({"error": error}), true));
    }
    let mut values: Vec<(&str, Value)> = Vec::new();
    for name in &operation.path_params {
        // A parameter listed twice is popped twice: Python raised KeyError on the second pop.
        let value = arguments.shift_remove(name).ok_or_else(|| PyErr::key(name))?;
        values.push((name.as_str(), value));
    }
    let pairs: Vec<(&str, &Value)> = values.iter().map(|(name, value)| (*name, value)).collect();
    let path = encode_path(&operation.path, &pairs);
    if operation.needs_confirm(&path) && !confirmed {
        return Ok(refusal(&operation.method, &path, None, None));
    }
    let mut query: Vec<(String, Value)> = Vec::new();
    for name in &operation.query_params {
        if let Some(value) = arguments.shift_remove(name) {
            query.push((name.clone(), value));
        }
    }
    let mut body: Option<Value> = None;
    if BODY_METHODS.contains(&operation.method.as_str()) {
        if operation.body_is_raw {
            body = arguments.shift_remove("body").filter(|value| !value.is_null());
        } else {
            let object: Map<String, Value> = arguments
                .iter()
                .filter(|(key, _)| operation.body_keys.contains(key))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            if !(object.is_empty() && !operation.required_body && operation.body_keys.is_empty()) {
                body = Some(Value::Object(object));
            }
        }
    } else {
        for (key, value) in arguments {
            if !value.is_null() {
                py::dict_set(&mut query, key, value, |a, b| a == b);
            }
        }
    }
    match panel.request(&operation.method, &path, &query, body.as_ref()).await {
        Err(err) => Ok(text_result(&err.payload(), true)),
        Ok(Value::Null) => Ok(text_result(&json!({"ok": true, "status": "no content"}), false)),
        Ok(answer) => Ok(text_result(&answer, false)),
    }
}

/// Everything `tools/list`, `tools/call`, `resources/list` and `resources/read` answer: the
/// generated operations (rebuilt by `reload`), the curated tools and the resources.
pub struct ToolRegistry {
    pub panel: PanelClient,
    operations: RwLock<Arc<Vec<Operation>>>,
    pub curated: Vec<Curated>,
}

pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub input_schema: Map<String, Value>,
}

pub struct ResourceInfo {
    pub uri: &'static str,
    pub name: &'static str,
    pub description: &'static str,
}

impl ToolRegistry {
    pub fn new(panel: PanelClient) -> Self {
        Self { panel, operations: RwLock::new(Arc::new(Vec::new())), curated: curated::curated() }
    }

    fn operations(&self) -> Arc<Vec<Operation>> {
        self.operations.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    pub async fn reload(&self) -> Result<usize, Fail> {
        let schema = self.panel.get("/api/openapi.json", &[]).await?;
        if !(schema.is_object() && schema.get("paths").is_some()) {
            return Err(PanelError::new(502, "the panel did not return an OpenAPI document", Some("bad_schema")).into());
        }
        let mut operations: Vec<Operation> = Vec::new();
        for operation in build_operations(&schema)? {
            if self.curated.iter().any(|tool| tool.name == operation.name) {
                continue;
            }
            // `{op.name: op for op in …}`: a later operation of the same name replaces the earlier one in place.
            match operations.iter_mut().find(|known| known.name == operation.name) {
                Some(slot) => *slot = operation,
                None => operations.push(operation),
            }
        }
        let count = operations.len();
        *self.operations.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(operations);
        Ok(count)
    }

    pub fn tools(&self) -> Vec<ToolInfo> {
        let curated = self.curated.iter().map(|tool| ToolInfo {
            name: tool.name.to_string(),
            description: tool.description.to_string(),
            input_schema: tool.input_schema.clone(),
        });
        let operations = self.operations();
        let generated: Vec<ToolInfo> = operations
            .iter()
            .map(|op| ToolInfo {
                name: op.name.clone(),
                description: op.description.clone(),
                input_schema: op.input_schema.clone(),
            })
            .collect();
        curated.chain(generated).collect()
    }

    pub async fn call(&self, name: &str, arguments: Option<Map<String, Value>>) -> Result<ToolResult, PyErr> {
        let arguments = arguments.unwrap_or_default();
        if name == "reload_tools" {
            return match self.reload().await {
                Err(Fail::Panel(err)) => Ok(text_result(&err.payload(), true)),
                Err(Fail::Py(err)) => Err(err),
                Ok(_) => Ok(text_result(&json!({"reloaded": true, "tools": self.tools().len()}), false)),
            };
        }
        if let Some(tool) = self.curated.iter().find(|tool| tool.name == name) {
            return match curated::run(tool.name, &self.panel, &arguments).await {
                Err(Fail::Panel(err)) => Ok(text_result(&err.payload(), true)),
                Err(Fail::Py(err)) => Err(err),
                Ok(result) => Ok(result),
            };
        }
        let operations = self.operations();
        let Some(operation) = operations.iter().find(|op| op.name == name) else {
            return Ok(text_result(&json!({"error": format!("unknown tool {}", py::repr_str(name))}), true));
        };
        run_operation(&self.panel, operation, arguments).await
    }

    pub fn resources(&self) -> Vec<ResourceInfo> {
        curated::RESOURCES
            .iter()
            .map(|(uri, description)| ResourceInfo {
                uri,
                name: uri.split_once("//").map_or(*uri, |(_, name)| name),
                description,
            })
            .collect()
    }

    pub async fn read_resource(&self, uri: &str) -> Result<String, Fail> {
        if !curated::RESOURCES.iter().any(|(known, _)| *known == uri) {
            return Err(PanelError::new(404, format!("unknown resource {uri}"), Some("unknown_resource")).into());
        }
        let value = curated::read_resource(uri, &self.panel).await?;
        Ok(py::dumps(&value, true))
    }
}
