//! Custom exits (v0.8, `routing/exits.py`): the operator's own outbounds a policy may leave
//! through.
//!
//! An exit belongs to one node — an outbound of that node's Xray-router — and is named by a policy
//! as `exit:<id>`. The row keeps everything but the credential; the credential is escrowed in the
//! secret store under `exit.credential`, permitted to the exit's node, and revealed only into the
//! intent compiled for that node. A share link is never kept or logged.

use panel_core::db::Conn;
use panel_core::errors::LocItem;
use panel_core::ids::uuid4;
use panel_core::pyjson;
use panel_core::pytext::{self, ip_address, unquote, urlsplit, SplitResult};
use panel_core::rusqlite::{self, params, OptionalExtension};
use panel_model::routing::models::{normalise_domain, Reason};
use panel_model::validate::{
    boolean, list, nullable, string, value_error, Cx, Extra, Fields, Int, Model, Str, ValidationError,
};
use panel_secrets::secrets_store::{Identity, SecretRef, SecretStore};
use serde_json::{json, Map, Value};

use crate::error::{Result, RoutingFailure};

pub const EXIT_PURPOSE: &str = "exit.credential";
pub const EXIT_PROTOCOLS: &[&str] = &["socks", "http", "vless", "trojan", "shadowsocks"];
pub const EXIT_NETWORKS: &[&str] = &["tcp", "ws", "grpc", "xhttp"];
pub const EXIT_SECURITY: &[&str] = &["none", "tls", "reality"];
pub const SS_METHODS: &[&str] = &[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
];
pub const FINGERPRINTS: &[&str] =
    &["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"];
pub const MAX_EXITS_PER_NODE: i64 = 16;

/// `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z` (on the lower-cased text).
fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, width)| {
            group.len() == width && group.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// `[A-Za-z0-9_-]{43}\Z`.
fn is_public_key(text: &str) -> bool {
    text.len() == 43 && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `(?:[0-9a-f]{2}){0,8}\Z`.
fn is_short_id(text: &str) -> bool {
    text.len() % 2 == 0 && text.len() <= 16 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `[^\r\n\x00]{1,48}\Z`.
fn is_name(text: &str) -> bool {
    (1..=48).contains(&pytext::len(text)) && !text.contains(['\r', '\n', '\0'])
}

/// `_host(value)`: an address (kept as given) or one host name (normalised, no wildcard).
fn host(value: &str) -> std::result::Result<String, String> {
    let text = pytext::strip(value);
    if ip_address(text).is_ok() {
        return Ok(text.to_string());
    }
    let host = normalise_domain(text).map_err(|error| error.0)?;
    if host.starts_with("*.") {
        return Err("an exit address is one host, not a wildcard".into());
    }
    Ok(host)
}

fn literal_text(input: &Value, loc: &[LocItem], cx: &mut Cx, choices: &[&'static str]) -> Option<String> {
    panel_model::validate::literal(input, loc, cx, choices).map(str::to_string)
}

fn optional_text(input: &Value, loc: &[LocItem], cx: &mut Cx, max: usize) -> Option<Option<String>> {
    nullable(input, loc, cx, |v, l, cx| Str::max(max).validate(v, l, cx))
}

/// `ExitTransport`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitTransport {
    pub network: String,
    pub path: Option<String>,
    pub host: Option<String>,
    pub service_name: Option<String>,
}

impl Default for ExitTransport {
    fn default() -> Self {
        Self { network: "tcp".into(), path: None, host: None, service_name: None }
    }
}

impl ExitTransport {
    pub fn wire(&self) -> Value {
        let mut out = Map::new();
        out.insert("network".into(), json!(self.network));
        for (key, value) in [("path", &self.path), ("host", &self.host), ("service_name", &self.service_name)] {
            if let Some(value) = value.as_ref().filter(|value| !value.is_empty()) {
                out.insert(key.into(), json!(value));
            }
        }
        Value::Object(out)
    }
}

impl Model for ExitTransport {
    const TITLE: &'static str = "ExitTransport";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let network = f.optional(cx, "network", || "tcp".into(), |v, l, cx| literal_text(v, l, cx, EXIT_NETWORKS));
        let path = f.optional(cx, "path", || None, |v, l, cx| optional_text(v, l, cx, 512));
        let host = f.optional(cx, "host", || None, |v, l, cx| optional_text(v, l, cx, 253));
        let service_name = f.optional(cx, "service_name", || None, |v, l, cx| optional_text(v, l, cx, 512));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(Self { network: network?, path: path?, host: host?, service_name: service_name? })
    }

    fn dump(&self) -> Value {
        json!({"network": self.network, "path": self.path, "host": self.host, "service_name": self.service_name})
    }
}

/// `ExitSecurity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSecurity {
    pub kind: String,
    pub server_name: Option<String>,
    pub fingerprint: String,
    pub alpn: Option<Vec<String>>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub insecure: bool,
}

impl Default for ExitSecurity {
    fn default() -> Self {
        Self {
            kind: "none".into(),
            server_name: None,
            fingerprint: "chrome".into(),
            alpn: None,
            public_key: None,
            short_id: None,
            insecure: false,
        }
    }
}

impl ExitSecurity {
    pub fn wire(&self) -> Value {
        let mut out = Map::new();
        out.insert("kind".into(), json!(self.kind));
        if self.kind == "none" {
            return Value::Object(out);
        }
        if let Some(server_name) = self.server_name.as_ref().filter(|name| !name.is_empty()) {
            out.insert("server_name".into(), json!(server_name));
        }
        out.insert("fingerprint".into(), json!(self.fingerprint));
        if let Some(alpn) = self.alpn.as_ref().filter(|alpn| !alpn.is_empty()) {
            out.insert("alpn".into(), json!(alpn));
        }
        if self.kind == "tls" && self.insecure {
            out.insert("insecure".into(), json!(true));
        }
        if self.kind == "reality" {
            out.insert("public_key".into(), json!(self.public_key));
            out.insert("short_id".into(), json!(self.short_id.clone().unwrap_or_default()));
        }
        Value::Object(out)
    }
}

impl Model for ExitSecurity {
    const TITLE: &'static str = "ExitSecurity";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let kind = f.optional(cx, "kind", || "none".into(), |v, l, cx| literal_text(v, l, cx, EXIT_SECURITY));
        let server_name = f.optional(
            cx,
            "server_name",
            || None,
            |v, l, cx| {
                let value = optional_text(v, l, cx, 253)?;
                match value.as_deref() {
                    None | Some("") => Some(None),
                    Some(text) => match host(text) {
                        Ok(host) => Some(Some(host)),
                        Err(message) => {
                            cx.push(value_error(l.to_vec(), v, message));
                            None
                        }
                    },
                }
            },
        );
        let fingerprint = f.optional(
            cx,
            "fingerprint",
            || "chrome".into(),
            |v, l, cx| {
                let text = string(v, l, cx)?;
                if !FINGERPRINTS.contains(&text.as_str()) {
                    cx.push(value_error(l.to_vec(), v, "invalid fingerprint"));
                    return None;
                }
                Some(text)
            },
        );
        let alpn =
            f.optional(cx, "alpn", || None, |v, l, cx| nullable(v, l, cx, |v, l, cx| list(v, l, cx, Some(4), string)));
        let public_key = f.optional(cx, "public_key", || None, |v, l, cx| optional_text(v, l, cx, 64));
        let short_id = f.optional(cx, "short_id", || None, |v, l, cx| optional_text(v, l, cx, 16));
        let insecure = f.optional(cx, "insecure", || false, boolean);
        let whole = f.input();
        let at_root = f.loc().to_vec();
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        let security = Self {
            kind: kind?,
            server_name: server_name?,
            fingerprint: fingerprint?,
            alpn: alpn?,
            public_key: public_key?,
            short_id: short_id?,
            insecure: insecure?,
        };
        if security.kind == "reality" {
            let problem = if !security.public_key.as_deref().is_some_and(|key| !key.is_empty() && is_public_key(key)) {
                Some("reality needs a public key")
            } else if security.short_id.as_deref().is_some_and(|id| !id.is_empty() && !is_short_id(id)) {
                Some("invalid short id")
            } else if security.server_name.as_deref().is_none_or(str::is_empty) {
                Some("reality needs a server name")
            } else {
                None
            };
            if let Some(message) = problem {
                cx.push(value_error(at_root, whole, message));
                return None;
            }
        }
        Some(security)
    }

    fn dump(&self) -> Value {
        json!({"kind": self.kind, "server_name": self.server_name, "fingerprint": self.fingerprint, "alpn": self.alpn,
               "public_key": self.public_key, "short_id": self.short_id, "insecure": self.insecure})
    }
}

/// `ExitCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExitCredential {
    pub username: Option<String>,
    pub password: Option<String>,
    pub uuid: Option<String>,
}

impl Model for ExitCredential {
    const TITLE: &'static str = "ExitCredential";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let username = f.optional(cx, "username", || None, |v, l, cx| optional_text(v, l, cx, 128));
        let password = f.optional(cx, "password", || None, |v, l, cx| optional_text(v, l, cx, 256));
        let uuid = f.optional(cx, "uuid", || None, |v, l, cx| optional_text(v, l, cx, 36));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(Self { username: username?, password: password?, uuid: uuid? })
    }

    fn dump(&self) -> Value {
        json!({"username": self.username, "password": self.password, "uuid": self.uuid})
    }
}

/// `ExitInput`: what `POST /api/routing/exits` and the link importer produce; on an update a
/// missing `credential` keeps the escrowed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInput {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: i64,
    pub credential: Option<ExitCredential>,
    pub method: Option<String>,
    pub flow: String,
    pub transport: ExitTransport,
    pub security: ExitSecurity,
}

impl ExitInput {
    /// The fields of `ExitInput` into `f`, and its model check; `declare` reads a subclass's own
    /// fields (declared after these, like `ExitCreateBody.node_id`).
    pub fn validate_extended<X>(
        input: &Value,
        loc: &[LocItem],
        cx: &mut Cx,
        title: &str,
        declare: impl FnOnce(&mut Fields<'_>, &mut Cx) -> X,
    ) -> Option<(Self, X)> {
        let mut f = Fields::open(input, loc, cx, title)?;
        let name = f.required(cx, "name", |v, l, cx| {
            let text = Str::len(1, 48).validate(v, l, cx)?;
            let stripped = pytext::strip(&text).to_string();
            if !is_name(&stripped) {
                cx.push(value_error(l.to_vec(), v, "invalid exit name"));
                return None;
            }
            Some(stripped)
        });
        let protocol = f.required(cx, "protocol", |v, l, cx| literal_text(v, l, cx, EXIT_PROTOCOLS));
        let address = f.required(cx, "address", |v, l, cx| {
            let text = Str::len(1, 253).validate(v, l, cx)?;
            match host(&text) {
                Ok(host) => Some(host),
                Err(message) => {
                    cx.push(value_error(l.to_vec(), v, message));
                    None
                }
            }
        });
        let port = f.required(cx, "port", |v, l, cx| Int::lax(Some(1), Some(65535)).validate(v, l, cx));
        let credential =
            f.optional(cx, "credential", || None, |v, l, cx| nullable(v, l, cx, ExitCredential::validate_at));
        let method = f.optional(cx, "method", || None, |v, l, cx| optional_text(v, l, cx, 40));
        let flow = f.optional(cx, "flow", String::new, |v, l, cx| literal_text(v, l, cx, &["", "xtls-rprx-vision"]));
        let transport = f.optional(cx, "transport", ExitTransport::default, ExitTransport::validate_at);
        let security = f.optional(cx, "security", ExitSecurity::default, ExitSecurity::validate_at);
        let own = declare(&mut f, cx);
        let whole = f.input();
        let at_root = f.loc().to_vec();
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        let mut exit = Self {
            name: name?,
            protocol: protocol?,
            address: address?,
            port: port?,
            credential: credential?,
            method: method?,
            flow: flow?,
            transport: transport?,
            security: security?,
        };
        if let Err(message) = exit.shape() {
            cx.push(value_error(at_root, whole, message));
            return None;
        }
        Some((exit, own))
    }

    /// `_shape`: the combinations no router accepts. Lower-cases a vless UUID.
    fn shape(&mut self) -> std::result::Result<(), String> {
        let protocol = self.protocol.as_str();
        if protocol == "shadowsocks" {
            if !self.method.as_deref().is_some_and(|method| SS_METHODS.contains(&method)) {
                return Err("shadowsocks needs a method".into());
            }
        } else if self.method.is_some() {
            return Err("only shadowsocks names a method".into());
        }
        if protocol != "vless" && !self.flow.is_empty() {
            return Err("only vless names a flow".into());
        }
        let plain = matches!(protocol, "socks" | "http" | "shadowsocks");
        if plain && self.transport.network != "tcp" {
            return Err("this exit protocol runs over tcp only".into());
        }
        if plain && self.security.kind == "reality" {
            return Err("reality needs vless or trojan".into());
        }
        if protocol == "vless" && !self.flow.is_empty() && (self.transport.network != "tcp" || self.security.kind == "none")
        {
            return Err("xtls-rprx-vision needs tcp with tls or reality".into());
        }
        if let Some(credential) = self.credential.as_mut() {
            match protocol {
                "socks" | "http" => {
                    if credential.username.is_none() != credential.password.is_none() {
                        return Err("username and password go together".into());
                    }
                    if credential.uuid.is_some() {
                        return Err("socks and http carry a username and password, not a uuid".into());
                    }
                }
                "vless" => {
                    let lowered = credential.uuid.as_deref().map(pytext::lower);
                    match lowered {
                        Some(uuid) if !uuid.is_empty() && is_uuid(&uuid) => credential.uuid = Some(uuid),
                        _ => return Err("vless needs a uuid".into()),
                    }
                }
                _ => {
                    if credential.password.as_deref().is_none_or(str::is_empty) {
                        return Err(format!("{protocol} needs a password"));
                    }
                }
            }
        }
        Ok(())
    }

    /// The secret to escrow: `None` when nothing was given (an update keeping the old one, or an
    /// unauthenticated socks/http exit).
    pub fn credential_bytes(&self) -> Option<Vec<u8>> {
        let credential = self.credential.as_ref()?;
        let text = match self.protocol.as_str() {
            "socks" | "http" => {
                credential.username.as_ref()?;
                pyjson::dumps_default(&json!({"username": credential.username, "password": credential.password}))
            }
            "vless" => pyjson::dumps_default(&json!({"uuid": credential.uuid})),
            _ => pyjson::dumps_default(&json!({"password": credential.password})),
        };
        Some(text.into_bytes())
    }

    pub fn needs_credential(&self) -> bool {
        !matches!(self.protocol.as_str(), "socks" | "http")
    }

    /// Everything but the credential, as the row keeps it and the intent carries it.
    pub fn settings(&self) -> Value {
        let mut out = Map::new();
        out.insert("protocol".into(), json!(self.protocol));
        out.insert("address".into(), json!(self.address));
        out.insert("port".into(), json!(self.port));
        out.insert("transport".into(), self.transport.wire());
        out.insert("security".into(), self.security.wire());
        if self.protocol == "shadowsocks" {
            out.insert("method".into(), json!(self.method));
        }
        if self.protocol == "vless" {
            out.insert("flow".into(), json!(self.flow));
        }
        Value::Object(out)
    }
}

impl Model for ExitInput {
    const TITLE: &'static str = "ExitInput";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        Self::validate_extended(input, loc, cx, Self::TITLE, |_, _| ()).map(|(exit, ())| exit)
    }

    fn dump(&self) -> Value {
        json!({"name": self.name, "protocol": self.protocol, "address": self.address, "port": self.port,
               "credential": self.credential.as_ref().map(Model::dump), "method": self.method, "flow": self.flow,
               "transport": self.transport.dump(), "security": self.security.dump()})
    }
}

// -- share links ------------------------------------------------------------------------------

/// `{key: values[-1] for key, values in parse_qs(query, keep_blank_values=True).items()}`.
fn query_of(parts: &SplitResult) -> Map<String, Value> {
    let mut out = Map::new();
    for item in parts.query.split('&').filter(|item| !item.is_empty()) {
        let (name, value) = item.split_once('=').unwrap_or((item, ""));
        let decode = |text: &str| unquote(&text.replace('+', " "));
        out.insert(decode(name), Value::String(decode(value)));
    }
    out
}

fn query_get<'a>(query: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    query.get(key).and_then(Value::as_str)
}

/// `(text or default)[:48]`.
fn first_48(text: &str) -> String {
    pytext::truncate(text, 48).to_string()
}

fn name_from(parts: &SplitResult, default: &str) -> String {
    let fragment = unquote(&parts.fragment);
    let fragment = pytext::strip(&fragment);
    first_48(if fragment.is_empty() { default } else { fragment })
}

fn transport_from(query: &Map<String, Value>) -> std::result::Result<Value, String> {
    let mut network = query_get(query, "type").filter(|text| !text.is_empty()).unwrap_or("tcp");
    if network == "raw" {
        network = "tcp";
    }
    if !EXIT_NETWORKS.contains(&network) {
        return Err(format!("unsupported transport in link: {network}"));
    }
    let mut out = Map::new();
    out.insert("network".into(), json!(network));
    for (key, name) in [("path", "path"), ("host", "host"), ("serviceName", "service_name")] {
        if let Some(value) = query_get(query, key).filter(|value| !value.is_empty()) {
            out.insert(name.into(), json!(value));
        }
    }
    Ok(Value::Object(out))
}

fn security_from(query: &Map<String, Value>, default: &str) -> std::result::Result<Value, String> {
    let kind = query_get(query, "security").filter(|text| !text.is_empty()).unwrap_or(default);
    if !EXIT_SECURITY.contains(&kind) {
        return Err(format!("unsupported security in link: {kind}"));
    }
    let mut out = Map::new();
    out.insert("kind".into(), json!(kind));
    if kind == "none" {
        return Ok(Value::Object(out));
    }
    if let Some(sni) = query_get(query, "sni").filter(|value| !value.is_empty()) {
        out.insert("server_name".into(), json!(sni));
    }
    if let Some(fp) = query_get(query, "fp").filter(|value| !value.is_empty()) {
        out.insert("fingerprint".into(), json!(fp));
    }
    if let Some(alpn) = query_get(query, "alpn").filter(|value| !value.is_empty()) {
        let items: Vec<&str> = alpn.split(',').filter(|item| !item.is_empty()).take(4).collect();
        out.insert("alpn".into(), json!(items));
    }
    if matches!(query_get(query, "allowInsecure"), Some("1" | "true")) && kind == "tls" {
        out.insert("insecure".into(), json!(true));
    }
    if kind == "reality" {
        out.insert("public_key".into(), json!(query_get(query, "pbk").unwrap_or("")));
        out.insert("short_id".into(), json!(query_get(query, "sid").unwrap_or("")));
    }
    Ok(Value::Object(out))
}

/// `binascii.a2b_base64` without strict mode (the same port as `panel_protocols::util`).
fn b64decode_lenient(data: &[u8]) -> Option<Vec<u8>> {
    let digit = |byte: u8| -> Option<u8> {
        Some(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let (mut quad, mut left, mut pads) = (0u8, 0u8, 0u8);
    for &byte in data {
        if byte == b'=' {
            if quad >= 2 {
                pads += 1;
                if quad + pads >= 4 {
                    return Some(out);
                }
            }
            continue;
        }
        let Some(value) = digit(byte) else { continue };
        pads = 0;
        match quad {
            0 => {
                quad = 1;
                left = value;
            }
            1 => {
                quad = 2;
                out.push((left << 2) | (value >> 4));
                left = value & 0x0f;
            }
            2 => {
                quad = 3;
                out.push((left << 4) | (value >> 2));
                left = value & 0x03;
            }
            _ => {
                quad = 0;
                out.push((left << 6) | value);
            }
        }
    }
    (quad == 0).then_some(out)
}

/// `_b64(value)`: url-safe base64 first, the standard alphabet second, UTF-8 text.
fn b64(value: &str) -> std::result::Result<String, String> {
    let padded = format!("{value}{}", "=".repeat((4 - value.len() % 4) % 4));
    let urlsafe: Vec<u8> = padded
        .bytes()
        .map(|byte| match byte {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        })
        .collect();
    if let Some(text) = b64decode_lenient(&urlsafe).and_then(|bytes| String::from_utf8(bytes).ok()) {
        return Ok(text);
    }
    b64decode_lenient(padded.as_bytes())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| "a shadowsocks link is not valid base64".into())
}

/// The input of a link, validated: a `ValueError`'s text when the link is not one.
fn validated(data: Value) -> std::result::Result<ExitInput, String> {
    ExitInput::validate(&data).map_err(|error: ValidationError| error.to_string())
}

fn port_of(parts: &SplitResult) -> std::result::Result<Option<i64>, String> {
    parts.port().map(|port| port.map(i64::from).filter(|port| *port != 0)).map_err(|error| error.0)
}

/// `parse_share_link(link)`: `vless://`, `trojan://`, `ss://`, `socks://`, `http://`/`https://` →
/// an [`ExitInput`]; `Err` with the `ValueError` text for anything else.
pub fn parse_share_link(link: &str) -> std::result::Result<ExitInput, String> {
    let text = pytext::strip(link);
    if pytext::len(text) > 4096 || text.is_empty() {
        return Err("empty or oversized link".into());
    }
    let parts = urlsplit(text).map_err(|error| error.0)?;
    let scheme = parts.scheme.to_lowercase();
    let query = query_of(&parts);
    let username = parts.username().filter(|name| !name.is_empty()).map(str::to_string);
    let hostname = parts.hostname();
    match scheme.as_str() {
        "vless" | "trojan" => {
            let usage = if scheme == "vless" {
                "a vless link is vless://<uuid>@host:port"
            } else {
                "a trojan link is trojan://<password>@host:port"
            };
            let (Some(user), Some(host)) = (username, hostname) else { return Err(usage.into()) };
            let Some(port) = port_of(&parts)? else { return Err(usage.into()) };
            let mut data = Map::new();
            data.insert("name".into(), json!(name_from(&parts, &host)));
            data.insert("protocol".into(), json!(scheme));
            data.insert("address".into(), json!(host));
            data.insert("port".into(), json!(port));
            if scheme == "vless" {
                data.insert("credential".into(), json!({"uuid": unquote(&user)}));
                data.insert("flow".into(), json!(query_get(&query, "flow").unwrap_or("")));
                data.insert("transport".into(), transport_from(&query)?);
                data.insert("security".into(), security_from(&query, "none")?);
            } else {
                data.insert("credential".into(), json!({"password": unquote(&user)}));
                data.insert("transport".into(), transport_from(&query)?);
                data.insert("security".into(), security_from(&query, "tls")?);
            }
            validated(Value::Object(data))
        }
        "ss" => {
            let mut body = text.get(5..).unwrap_or("").to_string();
            let mut fragment = String::new();
            if let Some((before, after)) = body.split_once('#') {
                fragment = after.to_string();
                body = before.to_string();
            }
            let body = body.split('?').next().unwrap_or("").to_string();
            let invalid = || "a shadowsocks link carries method:password@host:port".to_string();
            let (decoded, hostport) = match body.rsplit_once('@') {
                Some((userinfo, hostport)) => {
                    let userinfo = unquote(userinfo);
                    let decoded = if userinfo.contains(':') { userinfo } else { b64(&userinfo)? };
                    (decoded, hostport.to_string())
                }
                None => {
                    let decoded = b64(&body)?;
                    let (decoded, hostport) = decoded.rsplit_once('@').ok_or_else(invalid)?;
                    (decoded.to_string(), hostport.to_string())
                }
            };
            if !decoded.contains(':') || !hostport.contains(':') {
                return Err(invalid());
            }
            let (method, password) = decoded.split_once(':').expect("checked");
            let (host, port) = hostport.rsplit_once(':').expect("checked");
            let port = pytext::int_from_str(port).map_err(|error| error.0)?;
            let name = unquote(&fragment);
            let name = pytext::strip(&name);
            let data = json!({"name": first_48(if name.is_empty() { host } else { name }), "protocol": "shadowsocks",
                              "address": host.trim_matches(['[', ']']), "port": port,
                              "credential": {"password": password}, "method": method});
            validated(data)
        }
        "socks" | "socks5" | "http" | "https" => {
            let usage = || format!("a {scheme} link is {scheme}://[user:pass@]host:port");
            let Some(host) = hostname else { return Err(usage()) };
            let Some(port) = port_of(&parts)? else { return Err(usage()) };
            let credential = parts.username().map(|user| {
                json!({"username": unquote(user), "password": unquote(parts.password().unwrap_or(""))})
            });
            let security =
                if scheme == "https" { json!({"kind": "tls", "server_name": host}) } else { json!({"kind": "none"}) };
            let data = json!({"name": name_from(&parts, &host),
                              "protocol": if scheme.starts_with("socks") { "socks" } else { "http" },
                              "address": host, "port": port, "credential": credential, "security": security});
            validated(data)
        }
        _ => Err("supported links: vless://, trojan://, ss://, socks://, http://, https://".into()),
    }
}

// -- the store ----------------------------------------------------------------------------------

/// What an exit store write refused.
#[derive(Debug)]
pub enum ExitError {
    /// `KeyError`: no such exit.
    NotFound,
    /// `ValueError`: the text the API shows.
    Invalid(String),
    Failure(RoutingFailure),
}

macro_rules! exit_failure {
    ($($source:ty),*) => {
        $(impl From<$source> for ExitError {
            fn from(error: $source) -> Self {
                ExitError::Failure(error.into())
            }
        })*
    };
}

exit_failure!(RoutingFailure, panel_core::db::DbError, rusqlite::Error, serde_json::Error,
    panel_secrets::secrets_store::SecretError);

struct ExitRow {
    id: String,
    node_id: String,
    name: String,
    protocol: String,
    settings_json: String,
    secret_id: Option<String>,
    secret_version: Option<i64>,
    enabled: i64,
    last_test_json: Option<String>,
    created_at: i64,
    updated_at: i64,
}

const EXIT_COLUMNS: &str =
    "id, node_id, name, protocol, settings_json, secret_id, secret_version, enabled, last_test_json, created_at, updated_at";

fn exit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ExitRow> {
    Ok(ExitRow {
        id: row.get(0)?,
        node_id: row.get(1)?,
        name: row.get(2)?,
        protocol: row.get(3)?,
        settings_json: row.get(4)?,
        secret_id: row.get(5)?,
        secret_version: row.get(6)?,
        enabled: row.get(7)?,
        last_test_json: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn view(row: &ExitRow) -> Result<Map<String, Value>> {
    let settings: Value = serde_json::from_str(&row.settings_json)?;
    let mut out = Map::new();
    out.insert("id".into(), json!(row.id));
    out.insert("node_id".into(), json!(row.node_id));
    out.insert("name".into(), json!(row.name));
    out.insert("protocol".into(), json!(row.protocol));
    out.insert("enabled".into(), json!(row.enabled != 0));
    out.insert("has_credential".into(), json!(row.secret_id.is_some()));
    let last_test = match row.last_test_json.as_deref().filter(|text| !text.is_empty()) {
        Some(text) => serde_json::from_str(text)?,
        None => Value::Null,
    };
    out.insert("last_test".into(), last_test);
    out.insert("created_at".into(), json!(row.created_at));
    out.insert("updated_at".into(), json!(row.updated_at));
    if let Value::Object(settings) = settings {
        for (key, value) in settings {
            out.insert(key, value);
        }
    }
    Ok(out)
}

fn read(db: &Conn, exit_id: &str) -> Result<Option<ExitRow>> {
    Ok(db
        .query_row(&format!("SELECT {EXIT_COLUMNS} FROM egress_exits WHERE id=?"), [exit_id], exit_row)
        .optional()?)
}

/// `ExitStore`: the rows and their escrowed credentials.
#[derive(Clone)]
pub struct ExitStore {
    secrets: SecretStore,
}

impl std::fmt::Debug for ExitStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExitStore")
    }
}

impl ExitStore {
    pub fn new(secrets: SecretStore) -> Self {
        Self { secrets }
    }

    /// `list(db, node_id)`.
    pub fn list(db: &Conn, node_id: &str) -> Result<Vec<Map<String, Value>>> {
        let rows = db
            .prepare(&format!("SELECT {EXIT_COLUMNS} FROM egress_exits WHERE node_id=? ORDER BY created_at, rowid"))?
            .query_map([node_id], exit_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.iter().map(view).collect()
    }

    /// `get(db, exit_id)`.
    pub fn get(db: &Conn, exit_id: &str) -> Result<Option<Map<String, Value>>> {
        read(db, exit_id)?.as_ref().map(view).transpose()
    }

    fn escrow(&self, db: &Conn, exit_id: &str, node_id: &str, plaintext: &[u8], version: i64) -> Result<String> {
        let secret_id = format!("exit:{exit_id}");
        let identity = Identity {
            secret_id: &secret_id,
            version,
            purpose: EXIT_PURPOSE,
            grant_id: None,
            permitted_node_id: Some(node_id),
        };
        self.secrets.store(db, &identity, plaintext, "active")?;
        Ok(secret_id)
    }

    fn revoke(&self, db: &Conn, secret_id: Option<&String>, version: Option<i64>) {
        if let (Some(secret_id), Some(version)) = (secret_id, version.filter(|version| *version != 0)) {
            let _ = self.secrets.transition(db, &SecretRef::new(secret_id.clone(), version), "revoked");
        }
    }

    /// `create(db, node_id, data, now)`.
    pub fn create(&self, db: &Conn, node_id: &str, data: &ExitInput, now: i64) -> Result<Map<String, Value>, ExitError> {
        let count: i64 = db.query_row("SELECT COUNT(*) FROM egress_exits WHERE node_id=?", [node_id], |row| row.get(0))?;
        if count >= MAX_EXITS_PER_NODE {
            return Err(ExitError::Invalid(format!("a node has at most {MAX_EXITS_PER_NODE} exits")));
        }
        let clash = db
            .query_row("SELECT 1 FROM egress_exits WHERE node_id=? AND name=?", params![node_id, data.name], |_| Ok(()))
            .optional()?;
        if clash.is_some() {
            return Err(ExitError::Invalid("an exit with this name exists on the node".into()));
        }
        let plaintext = data.credential_bytes();
        if data.needs_credential() && plaintext.is_none() {
            return Err(ExitError::Invalid(format!("{} needs a credential", data.protocol)));
        }
        let exit_id = uuid4();
        let secret_id = match &plaintext {
            None => None,
            Some(plaintext) => Some(self.escrow(db, &exit_id, node_id, plaintext, 1)?),
        };
        db.execute(
            "INSERT INTO egress_exits(id,node_id,name,protocol,settings_json,secret_id,secret_version,enabled,created_at,updated_at) \
             VALUES(?,?,?,?,?,?,?,1,?,?)",
            params![
                exit_id,
                node_id,
                data.name,
                data.protocol,
                pyjson::sorted(&data.settings()),
                secret_id,
                secret_id.as_ref().map(|_| 1i64),
                now,
                now
            ],
        )?;
        Ok(Self::get(db, &exit_id)?.expect("just inserted"))
    }

    /// `update(db, exit_id, data, now)`.
    pub fn update(&self, db: &Conn, exit_id: &str, data: &ExitInput, now: i64) -> Result<Map<String, Value>, ExitError> {
        let row = read(db, exit_id)?.ok_or(ExitError::NotFound)?;
        if data.protocol != row.protocol {
            return Err(ExitError::Invalid("an exit keeps its protocol; create another for a different one".into()));
        }
        let clash = db
            .query_row(
                "SELECT 1 FROM egress_exits WHERE node_id=? AND name=? AND id<>?",
                params![row.node_id, data.name, exit_id],
                |_| Ok(()),
            )
            .optional()?;
        if clash.is_some() {
            return Err(ExitError::Invalid("an exit with this name exists on the node".into()));
        }
        let plaintext = data.credential_bytes();
        let (mut secret_id, mut version) = (row.secret_id.clone(), row.secret_version);
        if let Some(plaintext) = &plaintext {
            let next = version.unwrap_or(0) + 1;
            secret_id = Some(self.escrow(db, exit_id, &row.node_id, plaintext, next)?);
            version = Some(next);
            self.revoke(db, row.secret_id.as_ref(), row.secret_version);
        } else if data.credential.is_some() && matches!(data.protocol.as_str(), "socks" | "http") {
            // An explicit empty credential on socks/http: the exit becomes unauthenticated.
            self.revoke(db, row.secret_id.as_ref(), row.secret_version);
            (secret_id, version) = (None, None);
        }
        if data.needs_credential() && secret_id.is_none() {
            return Err(ExitError::Invalid(format!("{} needs a credential", data.protocol)));
        }
        db.execute(
            "UPDATE egress_exits SET name=?, settings_json=?, secret_id=?, secret_version=?, updated_at=? WHERE id=?",
            params![data.name, pyjson::sorted(&data.settings()), secret_id, version, now, exit_id],
        )?;
        Ok(Self::get(db, exit_id)?.expect("just updated"))
    }

    /// `set_enabled(db, exit_id, enabled, now)`.
    pub fn set_enabled(db: &Conn, exit_id: &str, enabled: bool, now: i64) -> Result<Map<String, Value>, ExitError> {
        let changed = db.execute(
            "UPDATE egress_exits SET enabled=?, updated_at=? WHERE id=?",
            params![i64::from(enabled), now, exit_id],
        )?;
        if changed != 1 {
            return Err(ExitError::NotFound);
        }
        Ok(Self::get(db, exit_id)?.expect("just updated"))
    }

    /// `delete(db, exit_id)`.
    pub fn delete(&self, db: &Conn, exit_id: &str) -> Result<(), ExitError> {
        let row = read(db, exit_id)?.ok_or(ExitError::NotFound)?;
        self.revoke(db, row.secret_id.as_ref(), row.secret_version);
        db.execute("DELETE FROM egress_exits WHERE id=?", [exit_id])?;
        Ok(())
    }

    /// `record_test(db, exit_id, result, now)`: the probe's outcome without anything else.
    pub fn record_test(db: &Conn, exit_id: &str, result: &Map<String, Value>, now: i64) -> Result<()> {
        let mut kept = Map::new();
        for key in ["ok", "ip", "colo", "latency_ms", "error", "code"] {
            if let Some(value) = result.get(key) {
                kept.insert(key.into(), value.clone());
            }
        }
        kept.insert("at".into(), json!(now));
        db.execute(
            "UPDATE egress_exits SET last_test_json=? WHERE id=?",
            params![pyjson::sorted(&Value::Object(kept)), exit_id],
        )?;
        Ok(())
    }

    /// `spec(db, exit_id, node_id)`: the exit as the router's intent carries it (credential
    /// revealed for its node), or why it cannot be used from this policy.
    pub fn spec(&self, db: &Conn, exit_id: &str, node_id: &str) -> crate::compiler::Lookup<Value> {
        let Some(row) = read(db, exit_id)? else {
            return Ok(Err(Reason::new("exit_unknown", None, "the policy names an exit that does not exist")));
        };
        if row.node_id != node_id {
            return Ok(Err(Reason::new(
                "exit_other_node",
                None,
                "an exit belongs to the node whose router dials it",
            )));
        }
        if row.enabled == 0 {
            return Ok(Err(Reason::new("exit_disabled", None, format!("exit «{}» is disabled", row.name))));
        }
        let settings: Value = serde_json::from_str(&row.settings_json)?;
        let mut credential = Value::Object(Map::new());
        if let Some(secret_id) = &row.secret_id {
            let reference = SecretRef::new(secret_id.clone(), row.secret_version.unwrap_or_default());
            match self.secrets.reveal(db, &reference, EXIT_PURPOSE, None, Some(&row.node_id)) {
                Ok(plaintext) => credential = serde_json::from_slice(&plaintext)?,
                Err(_) => {
                    return Ok(Err(Reason::new(
                        "exit_secret_pending",
                        None,
                        format!("exit «{}» has no readable credential", row.name),
                    )))
                }
            }
        }
        let mut spec = match settings {
            Value::Object(settings) => settings,
            _ => Map::new(),
        };
        spec.insert("credential".into(), credential);
        Ok(Ok(Value::Object(spec)))
    }

    /// `usage(db, exit_id)`: every policy (node, protocol, lane, rule) that leaves through the exit.
    pub fn usage(db: &Conn, exit_id: &str) -> Result<Vec<Value>> {
        let needle = format!("exit:{exit_id}");
        let policies: Vec<(String, String, String, String, Option<String>)> = db
            .prepare("SELECT id, node_id, protocol, lane, default_egress FROM routing_policies")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut found = Vec::new();
        for (id, node_id, protocol, lane, default_egress) in policies {
            if default_egress.as_deref() == Some(needle.as_str()) {
                found.push(json!({"policy_id": id, "node_id": node_id, "protocol": protocol, "lane": lane, "rule": null}));
            }
            let positions: Vec<i64> = db
                .prepare("SELECT position FROM routing_rules WHERE policy_id=? AND egress=? ORDER BY position")?
                .query_map(params![id, needle], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for position in positions {
                found.push(json!({"policy_id": id, "node_id": node_id, "protocol": protocol, "lane": lane,
                                  "rule": position + 1}));
            }
        }
        Ok(found)
    }
}
