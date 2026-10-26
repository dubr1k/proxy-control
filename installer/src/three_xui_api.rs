//! Bounded loopback 3x-ui client. Errors never include bodies, cookies or credentials.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::error::Error;
use base64::Engine;
use serde_json::{json, Map, Value};

const LIMIT: usize = 4 * 1024 * 1024;
const CONTRACT: &str = include_str!("../../tests/fixtures/three_xui/api-contract-3.10.2.json");
fn failure(message: &str) -> Error {
    Error::other("ThreeXuiApiError", message)
}
fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 256
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_.{}-".contains(&b))
}

#[derive(Debug)]
struct LeafPin {
    der: Vec<u8>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}
impl rustls::client::danger::ServerCertVerifier for LeafPin {
    fn verify_server_cert(
        &self,
        end: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.der.len() != end.as_ref().len()
            || self.der.iter().zip(end.as_ref()).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0
        {
            return Err(rustls::Error::General("managed panel certificate pin mismatch".into()));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub struct ApiResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub cookies: Vec<String>,
}
pub trait Transport {
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        headers: &BTreeMap<String, String>,
    ) -> Result<ApiResponse, Error>;
}

pub struct ThreeXuiClient {
    host: String,
    port: u16,
    pin: Option<Vec<u8>>,
}
impl ThreeXuiClient {
    pub fn new(host: &str, port: u16, certificate: Option<&Path>) -> Result<Self, Error> {
        if !["127.0.0.1", "::1", "localhost"].contains(&host) {
            return Err(failure("the 3x-ui API is only reachable on loopback"));
        }
        if port == 0 {
            return Err(failure("the 3x-ui API port is invalid"));
        }
        let pin = certificate
            .map(|path| {
                let pem = std::fs::read_to_string(path).map_err(|_| failure("invalid managed panel certificate"))?;
                let leaf = pem
                    .split_once("-----BEGIN CERTIFICATE-----")
                    .and_then(|(_, tail)| tail.split_once("-----END CERTIFICATE-----"))
                    .map(|(leaf, _)| leaf.split_whitespace().collect::<String>())
                    .ok_or_else(|| failure("invalid managed panel certificate"))?;
                base64::engine::general_purpose::STANDARD
                    .decode(leaf)
                    .map_err(|_| failure("invalid managed panel certificate"))
            })
            .transpose()?;
        Ok(Self { host: host.into(), port, pin })
    }
}
trait Socket: Read + Write {}
impl<T: Read + Write> Socket for T {}
impl Transport for ThreeXuiClient {
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        headers: &BTreeMap<String, String>,
    ) -> Result<ApiResponse, Error> {
        if !safe_path(path) {
            return Err(failure("the 3x-ui request path is invalid"));
        }
        if !["GET", "POST"].contains(&method)
            || headers.iter().any(|(k, v)| k.contains(['\r', '\n']) || v.contains(['\r', '\n']))
        {
            return Err(failure("the local 3x-ui request failed"));
        }
        let result = (|| -> Result<ApiResponse, Box<dyn std::error::Error>> {
            let address = (self.host.as_str(), self.port).to_socket_addrs()?.next().ok_or("no address")?;
            let socket = TcpStream::connect_timeout(&address, Duration::from_secs(30))?;
            socket.set_read_timeout(Some(Duration::from_secs(30)))?;
            socket.set_write_timeout(Some(Duration::from_secs(30)))?;
            let mut stream: Box<dyn Socket> = if let Some(pin) = &self.pin {
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let config = rustls::ClientConfig::builder_with_provider(provider.clone())
                    .with_safe_default_protocol_versions()?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(LeafPin { der: pin.clone(), provider }))
                    .with_no_client_auth();
                let name = rustls::pki_types::ServerName::try_from(self.host.clone())?;
                let connection = rustls::ClientConnection::new(Arc::new(config), name)?;
                let mut tls = rustls::StreamOwned::new(connection, socket);
                // Authenticate the exact leaf and handshake signatures before writing HTTP.
                while tls.conn.is_handshaking() {
                    tls.conn.complete_io(&mut tls.sock)?;
                }
                Box::new(tls)
            } else {
                Box::new(socket)
            };
            let authority = if self.host.contains(':') {
                format!("[{}]:{}", self.host, self.port)
            } else {
                format!("{}:{}", self.host, self.port)
            };
            let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n");
            for (name, value) in headers {
                request.push_str(&format!("{name}: {value}\r\n"));
            }
            request.push_str("\r\n");
            stream.write_all(request.as_bytes())?;
            if let Some(body) = body {
                stream.write_all(body)?;
            }
            stream.flush()?;
            let mut raw = Vec::new();
            let read = stream.take((LIMIT + 65536 + 1) as u64).read_to_end(&mut raw);
            if let Err(error) = read {
                // HTTP/1.1 content-length authenticates completion even when a server
                // closes TCP without TLS close_notify (the upstream Go server can do so).
                if error.kind() != std::io::ErrorKind::UnexpectedEof {
                    return Err(error.into());
                }
            }
            let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("invalid headers")?;
            if split > 65536 {
                return Err("large headers".into());
            }
            let head = std::str::from_utf8(&raw[..split])?;
            let status =
                head.lines().next().and_then(|line| line.split_whitespace().nth(1)).ok_or("invalid status")?.parse()?;
            let mut cookies = Vec::new();
            let mut chunked = false;
            let mut length = None;
            for line in head.lines().skip(1) {
                let (name, value) = line.split_once(':').ok_or("invalid header")?;
                if name.eq_ignore_ascii_case("set-cookie") {
                    cookies.push(value.trim().into());
                }
                if name.eq_ignore_ascii_case("transfer-encoding") {
                    if value.trim() != "chunked" {
                        return Err("invalid transfer encoding".into());
                    }
                    chunked = true;
                }
                if name.eq_ignore_ascii_case("content-length") {
                    if length.is_some() {
                        return Err("duplicate length".into());
                    }
                    length = Some(value.trim().parse::<usize>()?);
                }
            }
            let encoded = &raw[split + 4..];
            let body = if chunked {
                if length.is_some() {
                    return Err("ambiguous framing".into());
                }
                let mut remaining = encoded;
                let mut decoded = Vec::new();
                loop {
                    let end = remaining.windows(2).position(|w| w == b"\r\n").ok_or("invalid chunk")?;
                    let line = std::str::from_utf8(&remaining[..end])?.split(';').next().ok_or("invalid chunk")?;
                    let size = usize::from_str_radix(line, 16)?;
                    remaining = &remaining[end + 2..];
                    if size == 0 {
                        break;
                    }
                    if size > LIMIT.saturating_sub(decoded.len())
                        || size.checked_add(2).is_none_or(|n| n > remaining.len())
                        || &remaining[size..size + 2] != b"\r\n"
                    {
                        return Err("invalid chunk".into());
                    }
                    decoded.extend_from_slice(&remaining[..size]);
                    remaining = &remaining[size + 2..];
                }
                decoded
            } else {
                if length.is_some_and(|length| length != encoded.len()) {
                    return Err("truncated response".into());
                }
                encoded.to_vec()
            };
            if body.len() > LIMIT {
                return Err("large response".into());
            }
            Ok(ApiResponse { status, body, cookies })
        })();
        result.map_err(|_| failure("the local 3x-ui request failed"))
    }
}

/// Python str/repr semantics for the JSON-shaped setting values returned upstream.
pub(super) fn python_repr(value: &Value, nested: bool) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(value) => if *value { "True" } else { "False" }.into(),
        Value::String(value) if !nested => value.clone(),
        Value::String(value) => pc_host::pytext::py_repr(value),
        Value::Number(value) => {
            if value.is_f64() {
                pc_host::json::float_repr(value.as_f64().unwrap())
            } else {
                value.to_string()
            }
        }
        Value::Array(values) => {
            format!("[{}]", values.iter().map(|v| python_repr(v, true)).collect::<Vec<_>>().join(", "))
        }
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(k, v)| format!("{}: {}", python_repr(&Value::String(k.clone()), true), python_repr(v, true)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}
fn form_value(value: &Value) -> String {
    if let Some(value) = value.as_bool() {
        return if value { "true" } else { "false" }.into();
    }
    python_repr(value, false)
}
fn quote_plus(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn parse_csrf_token(page: &str) -> Result<String, Error> {
    let lower = page.to_ascii_lowercase();
    let mut offset = 0;
    while let Some(start) = lower[offset..].find("<meta") {
        let start = offset + start + 5;
        let Some(end) = lower[start..].find('>') else { break };
        let tag = &page[start..start + end];
        let mut attrs = BTreeMap::new();
        let mut rest = tag;
        while !rest.trim_start().is_empty() {
            rest = rest.trim_start();
            let Some(eq) = rest.find('=') else { break };
            let key = rest[..eq].trim().to_ascii_lowercase();
            rest = rest[eq + 1..].trim_start();
            let Some(quote) = rest.chars().next().filter(|q| *q == '\'' || *q == '"') else { break };
            rest = &rest[1..];
            let Some(end) = rest.find(quote) else { break };
            attrs.insert(key, &rest[..end]);
            rest = &rest[end + 1..];
        }
        if attrs.get("name").is_some_and(|v| v.eq_ignore_ascii_case("csrf-token")) {
            if let Some(token) = attrs.get("content").filter(|token| {
                (16..=256).contains(&token.len())
                    && token.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-+/=".contains(&b))
            }) {
                return Ok((*token).into());
            }
        }
        offset = start + end + 1;
    }
    Err(failure("the 3x-ui page carried no usable CSRF token"))
}

pub struct ThreeXuiApi<T: Transport> {
    client: T,
    contract: Value,
    base_path: String,
    cookie: Option<String>,
    csrf: Option<String>,
    setting_forms: BTreeMap<String, (Value, String)>,
}
impl<T: Transport> ThreeXuiApi<T> {
    pub fn new(client: T, base_path: &str) -> Result<Self, Error> {
        if !safe_path(base_path) {
            return Err(failure("the 3x-ui base path is invalid"));
        }
        let contract: Value =
            serde_json::from_str(CONTRACT).map_err(|_| failure("the 3x-ui API contract is unavailable"))?;
        if contract["version"] != "3.10.2" {
            return Err(failure("the 3x-ui API contract is not the pinned version"));
        }
        Ok(Self {
            client,
            contract,
            base_path: base_path.into(),
            cookie: None,
            csrf: None,
            setting_forms: BTreeMap::new(),
        })
    }
    fn endpoint(&self, name: &str, parameters: &BTreeMap<String, String>) -> Result<(String, String, String), Error> {
        let entry =
            self.contract["endpoints"].get(name).ok_or_else(|| failure("the 3x-ui endpoint is not in the contract"))?;
        let mut path = entry["path"].as_str().ok_or_else(|| failure("invalid endpoint contract"))?.to_owned();
        for (key, value) in parameters {
            if value.is_empty()
                || value.len() > 128
                || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            {
                return Err(failure("a 3x-ui path parameter is invalid"));
            }
            path = path.replace(&format!("{{{key}}}"), value);
        }
        if path.contains('{') {
            return Err(failure("a 3x-ui path parameter is missing"));
        }
        if self.base_path != "/" {
            path = format!("{}{path}", self.base_path.trim_end_matches('/'));
        }
        Ok((entry["method"].as_str().unwrap_or("").into(), path, entry["encoding"].as_str().unwrap_or("").into()))
    }
    pub fn call(
        &mut self,
        name: &str,
        payload: &Map<String, Value>,
        parameters: &BTreeMap<String, String>,
        authenticated: bool,
    ) -> Result<Value, Error> {
        let (method, path, encoding) = self.endpoint(name, parameters)?;
        if authenticated && self.cookie.is_none() {
            return Err(failure("the 3x-ui session is not authenticated"));
        }
        let mut headers = BTreeMap::from([("Accept".into(), "application/json".into())]);
        if let Some(cookie) = &self.cookie {
            headers.insert("Cookie".into(), cookie.clone());
        }
        if let Some(csrf) = &self.csrf {
            headers.insert("X-CSRF-Token".into(), csrf.clone());
        }
        let body = match encoding.as_str() {
            "json" => {
                headers.insert("Content-Type".into(), "application/json".into());
                Some(
                    pc_host::json::dumps(
                        &Value::Object(payload.clone()),
                        &pc_host::json::Options { ensure_ascii: true, ..pc_host::json::Options::CANONICAL },
                    )
                    .into_bytes(),
                )
            }
            "form" => {
                headers.insert("Content-Type".into(), "application/x-www-form-urlencoded".into());
                Some(
                    payload
                        .iter()
                        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(&python_repr(v, false))))
                        .collect::<Vec<_>>()
                        .join("&")
                        .into_bytes(),
                )
            }
            "empty" if payload.is_empty() => None,
            _ => return Err(failure("this 3x-ui endpoint takes no body")),
        };
        if let Some(body) = &body {
            headers.insert("Content-Length".into(), body.len().to_string());
        }
        let response = self.client.request(&method, &path, body.as_deref(), &headers)?;
        if response.status != 200 {
            return Err(failure(&format!("the local 3x-ui request to {path} returned status {}", response.status)));
        }
        if response.body.len() > LIMIT {
            return Err(failure("the 3x-ui response exceeded its bound"));
        }
        let document: Value = serde_json::from_slice(&response.body)
            .map_err(|_| failure(&format!("the local 3x-ui response for {path} was not valid JSON")))?;
        if !document.is_object() || document.get("success").is_none() {
            return Err(failure(&format!("the local 3x-ui response for {path} did not match the contract")));
        }
        if document["success"] != true {
            let message = document.get("msg").and_then(Value::as_str).unwrap_or("").to_lowercase();
            let hints: Vec<_> = [
                (&["cert", "certificate"][..], "the panel names a certificate file it cannot read"),
                (&["key file", "keyfile", "private key"][..], "the panel names a key file it cannot read"),
                (&["port"][..], "the panel objects to a port"),
                (&["validation", "invalid"][..], "the panel says the form failed its validation"),
                (&["path"][..], "the panel objects to a path"),
            ]
            .into_iter()
            .filter(|(words, _)| words.iter().any(|word| message.contains(word)))
            .map(|(_, hint)| hint)
            .collect();
            let suffix = if hints.is_empty() { String::new() } else { format!(" ({})", hints.join("; ")) };
            return Err(failure(&format!("the local 3x-ui request to {path} was rejected{suffix}")));
        }
        if name == "all_settings" {
            let ordered: crate::three_xui_ordered::Ordered = serde_json::from_slice(&response.body)
                .map_err(|_| failure("the 3x-ui settings did not match the contract"))?;
            self.setting_forms.clear();
            if let Some(crate::three_xui_ordered::Ordered::Object(fields)) = ordered.get("obj") {
                for (key, value) in fields {
                    let parsed = document["obj"][key].clone();
                    let rendered = if parsed.is_boolean() { form_value(&parsed) } else { value.repr(false) };
                    self.setting_forms.insert(key.clone(), (parsed, rendered));
                }
            }
        }
        if name == "login" {
            let cookie = response
                .cookies
                .iter()
                .find(|v| v.split('=').next().unwrap_or("").to_ascii_lowercase().contains("session"))
                .or(response.cookies.first())
                .ok_or_else(|| failure("the local 3x-ui login returned no session cookie"))?;
            self.cookie = Some(cookie.split(';').next().unwrap_or("").trim().into());
        }
        Ok(document)
    }
    fn simple(&mut self, name: &str, payload: Value) -> Result<Value, Error> {
        self.call(name, payload.as_object().ok_or_else(|| failure("invalid request payload"))?, &BTreeMap::new(), true)
    }
    pub fn authenticated(&self) -> bool {
        self.cookie.is_some()
    }
    pub fn login(&mut self, username: &str, password: &str) -> Result<(), Error> {
        self.cookie = None;
        self.csrf = None;
        let (method, path, _) = self.endpoint("csrf_page", &BTreeMap::new())?;
        let response =
            self.client.request(&method, &path, None, &BTreeMap::from([("Accept".into(), "text/html".into())]))?;
        if response.status != 200 {
            return Err(failure("the 3x-ui panel did not serve its login page"));
        }
        if response.body.len() > LIMIT {
            return Err(failure("the 3x-ui response exceeded its bound"));
        }
        self.csrf = Some(parse_csrf_token(&String::from_utf8_lossy(&response.body))?);
        self.cookie = response.cookies.first().map(|v| v.split(';').next().unwrap_or("").trim().into());
        self.call(
            "login",
            json!({"username":username,"password":password}).as_object().unwrap(),
            &BTreeMap::new(),
            false,
        )?;
        Ok(())
    }
    pub fn rotate_credentials(
        &mut self,
        old_username: &str,
        old_password: &str,
        new_username: &str,
        new_password: &str,
    ) -> Result<(), Error> {
        self.simple("update_user",json!({"oldUsername":old_username,"oldPassword":old_password,"newUsername":new_username,"newPassword":new_password}))?;
        self.cookie = None;
        self.csrf = None;
        Ok(())
    }
    fn settings(&mut self) -> Result<Map<String, Value>, Error> {
        self.simple("all_settings", json!({}))?["obj"]
            .as_object()
            .cloned()
            .ok_or_else(|| failure("the 3x-ui settings did not match the contract"))
    }
    fn update_settings(&mut self, settings: Map<String, Value>) -> Result<(), Error> {
        let settings = settings
            .into_iter()
            .filter(|(key, _)| !key.starts_with("has"))
            .map(|(key, value)| {
                let rendered = self
                    .setting_forms
                    .get(&key)
                    .filter(|(original, _)| original == &value)
                    .map(|(_, rendered)| rendered.clone())
                    .unwrap_or_else(|| form_value(&value));
                (key, Value::String(rendered))
            })
            .collect();
        self.simple("update_settings", Value::Object(settings))?;
        Ok(())
    }
    pub fn configure_panel(
        &mut self,
        web_path: &str,
        port: u16,
        listen: &str,
        certificate: Option<&str>,
        private_key: Option<&str>,
    ) -> Result<(), Error> {
        if !safe_path(web_path) {
            return Err(failure("the 3x-ui web path is invalid"));
        }
        if !["127.0.0.1", "::1", "localhost"].contains(&listen) {
            return Err(failure("the 3x-ui panel must listen on loopback"));
        }
        if port == 0 {
            return Err(failure("the 3x-ui panel port is invalid"));
        }
        if certificate.is_some_and(|v| !v.starts_with('/')) || private_key.is_some_and(|v| !v.starts_with('/')) {
            return Err(failure("the 3x-ui panel certificate/key path must be absolute"));
        }
        let mut settings = self.settings()?;
        settings.extend(
            json!({"webListen":listen,"webPort":port,"webBasePath":web_path,"subListen":listen})
                .as_object()
                .unwrap()
                .clone(),
        );
        if let (Some(cert), Some(key)) = (certificate, private_key) {
            settings.insert("webCertFile".into(), json!(cert));
            settings.insert("webKeyFile".into(), json!(key));
        }
        self.update_settings(settings)
    }
    pub fn configure_subscription(&mut self, domain: &str, certificate: &str, private_key: &str) -> Result<(), Error> {
        let desired = json!({"subEnable":true,"subListen":"127.0.0.1","subPort":2096,"subPath":"/sub/","subURI":format!("https://{domain}/sub/"),"subDomain":domain,"subCertFile":certificate,"subKeyFile":private_key,"subJsonEnable":false,"subEncrypt":false});
        let mut settings = self.settings()?;
        settings.extend(desired.as_object().unwrap().clone());
        self.update_settings(settings)?;
        let observed = self.settings()?;
        if desired
            .as_object()
            .unwrap()
            .iter()
            .any(|(key, value)| form_value(observed.get(key).unwrap_or(&Value::Null)) != form_value(value))
        {
            return Err(failure("subscription settings read-back mismatch"));
        }
        Ok(())
    }
    pub fn add_inbound(&mut self, inbound: Value) -> Result<i64, Error> {
        self.simple("add_inbound", inbound)?["obj"]["id"]
            .as_i64()
            .ok_or_else(|| failure("the local 3x-ui add-inbound response carried no inbound id"))
    }
    pub fn delete_acceptance_client(&mut self, email: &str, acceptance: bool) -> Result<(), Error> {
        if !acceptance || !email.starts_with("acceptance-") {
            return Err(failure("only an acceptance client may be deleted"));
        }
        self.call("delete_client", &Map::new(), &BTreeMap::from([("email".into(), email.into())]), true)?;
        Ok(())
    }
    pub fn effective_config(&mut self) -> Result<Value, Error> {
        let document = self.simple("list_inbounds", json!({}))?;
        let rows = document["obj"]
            .as_array()
            .ok_or_else(|| failure("the local 3x-ui inbound list did not match the contract"))?;
        let mut inbounds = Vec::new();
        let mut emails = std::collections::BTreeSet::new();
        for row in rows.iter().filter(|row| row.is_object()) {
            let settings = match &row["settings"] {
                Value::String(s) => serde_json::from_str(s).unwrap_or(Value::Null),
                value => value.clone(),
            };
            let clients = settings["clients"].as_array();
            if let Some(clients) = clients {
                for email in clients.iter().filter_map(|c| c["email"].as_str()) {
                    emails.insert(email.to_owned());
                }
            }
            inbounds.push(json!({"tag":row["remark"],"protocol":row["protocol"],"port":row["port"],"listen":row["listen"],"client_count":clients.map_or(0,Vec::len)}));
        }
        Ok(json!({"inbounds":inbounds,"client_emails":emails}))
    }
    pub fn configure_warp(&mut self, port: u16, domains: &[String]) -> Result<(), Error> {
        if domains.is_empty() {
            return Err(failure("WARP requires operator-confirmed domains"));
        }
        let mut current = self.simple("xray_settings", json!({}))?["obj"].clone();
        if let Some(encoded) = current.as_str() {
            current = serde_json::from_str(encoded).map_err(|_| failure("invalid Xray settings response"))?;
        }
        let template = current
            .get_mut("xraySetting")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| failure("Xray settings response has no template"))?;
        let outbounds = template
            .entry("outbounds")
            .or_insert(json!([]))
            .as_array_mut()
            .ok_or_else(|| failure("invalid Xray outbound/routing template"))?;
        if outbounds.iter().any(|outbound| outbound["tag"] == "WARP") {
            return Err(failure("pre-existing WARP outbound requires explicit migration"));
        }
        outbounds.push(
            json!({"tag":"WARP","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":port}]}}),
        );
        let routing = template
            .entry("routing")
            .or_insert(json!({}))
            .as_object_mut()
            .ok_or_else(|| failure("invalid Xray outbound/routing template"))?;
        let rules = routing
            .entry("rules")
            .or_insert(json!([]))
            .as_array_mut()
            .ok_or_else(|| failure("invalid Xray outbound/routing template"))?;
        let final_rule = json!({"outboundTag":"direct","network":"tcp,udp"});
        rules.retain(|rule| rule != &final_rule);
        rules.push(json!({"type":"field","domain":domains.iter().map(|domain| if domain.starts_with("domain:") || domain.starts_with("geosite:") {domain.clone()} else {format!("domain:{domain}")}).collect::<Vec<_>>(),"outboundTag":"WARP"}));
        rules.push(final_rule);
        let candidate = Value::Object(template.clone());
        self.simple("update_xray_settings",json!({"xraySetting":pc_host::json::canonical(&candidate),"outboundTestUrl":current.get("outboundTestUrl").unwrap_or(&json!("https://www.google.com/generate_204"))}))?;
        let mut observed = self.simple("xray_settings", json!({}))?["obj"].clone();
        if let Some(encoded) = observed.as_str() {
            observed = serde_json::from_str(encoded).map_err(|_| failure("invalid Xray settings response"))?;
        }
        if observed["xraySetting"] != candidate {
            return Err(failure("WARP template read-back mismatch"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "three_xui_api_tests.rs"]
mod tests;
