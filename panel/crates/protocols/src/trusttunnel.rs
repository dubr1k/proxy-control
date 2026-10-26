//! TrustTunnel: the panel chooses the password, the node's manager keeps the endpoint's account
//! list (`protocols/trusttunnel.py`).
//!
//! The credential is the password itself (`token_urlsafe(24)`), generated and escrowed by the
//! panel; the manager receives it too (the endpoint authenticates by Basic credentials from a
//! file). What a client needs besides the account (the endpoint's domain, the public port, a
//! certificate the system store does not trust) is learned at issue time into the grant's options:
//! the deep link, the TOML and the manual fields are built from escrow alone. TCP only (HTTP/2).

use std::sync::Arc;

use base64::Engine as _;
use panel_core::pyjson;
use panel_managers::{ManagerError, TrusttunnelClient, XrayRouterClient};
use panel_model::clients::{AccessGrant, GrantIntent, ProtocolOptions, TrusttunnelOptions};
use panel_model::fleet::CredentialOrigin;
use panel_model::protocols::{
    applied_egress_from_view, egress_error, egress_target_from_view, AccessArtifact, AdapterError, AppliedEgress,
    AppliedGrant, AutoRefresh, CredentialPlan, EgressTarget, GrantRef, ObservedGrant, ObservedInventory, Preflight,
};
use panel_model::{Backend, Protocol};
use serde_json::{json, Map, Value};

use crate::api::{RouterApi, TrusttunnelApi};
use crate::error::crash;
use crate::trusttunnel_link::{encode_deeplink, DeepLinkSpec};
use crate::util::{as_object, b64decode_lenient, b64decode_strict, py_str, rows, truthy};
use crate::xray_router::RouterAdapter;

pub const LINK_KIND: &str = "trusttunnel_link";
pub const TOML_KIND: &str = "trusttunnel_toml";
pub const MANUAL_KIND: &str = "trusttunnel_manual";
pub const LINK_MEDIA_TYPE: &str = "text/uri-list";
pub const TOML_MEDIA_TYPE: &str = "application/toml";
pub const MANUAL_MEDIA_TYPE: &str = "application/json";
pub const EGRESS_CAPABILITIES: &[&str] = &["whole_direct"];

/// A fresh password, as the escrowed secret (`token_urlsafe(24)`, 32 characters).
pub fn new_credential() -> Vec<u8> {
    panel_core::ids::token_urlsafe(24).into_bytes()
}

/// The manager's rule: printable ASCII without spaces (`[\x21-\x7e]{8,128}`).
pub fn parse_credential(plaintext: &[u8]) -> Result<String, AdapterError> {
    if !(8..=128).contains(&plaintext.len()) || !plaintext.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return Err(AdapterError::new("the TrustTunnel credential is malformed"));
    }
    Ok(String::from_utf8(plaintext.to_vec()).expect("printable ASCII"))
}

/// The option fields the deep link and the client config are built from, as the manager's
/// endpoint reported them. A certificate the system store trusts is not stored.
pub fn learned_options(endpoint: &Map<String, Value>) -> Map<String, Value> {
    let certificate = if endpoint.get("certificate_trusted") == Some(&Value::Bool(true)) {
        None
    } else {
        endpoint.get("certificate_der_b64").filter(|value| truthy(Some(value))).cloned()
    };
    let port = endpoint.get("public_port").filter(|value| truthy(Some(value))).cloned().unwrap_or(json!(443));
    Map::from_iter([
        ("hostname".to_string(), endpoint.get("hostname").cloned().unwrap_or(Value::Null)),
        ("port".to_string(), port),
        ("certificate_der_b64".to_string(), certificate.unwrap_or(Value::Null)),
    ])
}

/// The certificates of a concatenated DER chain (each is a DER SEQUENCE).
pub fn split_der(chain: &[u8]) -> Result<Vec<&[u8]>, AdapterError> {
    let not_der = || AdapterError::new("the endpoint certificate is not DER");
    let (mut certificates, mut offset) = (Vec::new(), 0usize);
    while offset < chain.len() {
        if chain[offset] != 0x30 || offset + 2 > chain.len() {
            return Err(not_der());
        }
        let first = chain[offset + 1];
        let (header, length) = if first < 0x80 {
            (2, usize::from(first))
        } else {
            let count = usize::from(first & 0x7F);
            if count == 0 || count > 4 || offset + 2 + count > chain.len() {
                return Err(not_der());
            }
            let length =
                chain[offset + 2..offset + 2 + count].iter().fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
            (2 + count, length)
        };
        let end = offset + header + length;
        if end > chain.len() {
            return Err(not_der());
        }
        certificates.push(&chain[offset..end]);
        offset = end;
    }
    Ok(certificates)
}

/// The PEM of a base64 DER chain: one block per certificate, 64-character lines, a final newline.
pub fn certificate_pem(certificate_der_b64: &str) -> Result<String, AdapterError> {
    let chain = b64decode_strict(certificate_der_b64)
        .ok_or_else(|| AdapterError::new("the endpoint certificate is malformed"))?;
    let engine = base64::engine::general_purpose::STANDARD;
    let blocks: Vec<String> = split_der(&chain)?
        .into_iter()
        .map(|der| {
            let body = engine.encode(der);
            let mut lines = vec!["-----BEGIN CERTIFICATE-----".to_string()];
            lines.extend(
                body.as_bytes().chunks(64).map(|line| String::from_utf8(line.to_vec()).expect("base64 is ASCII")),
            );
            lines.push("-----END CERTIFICATE-----".to_string());
            lines.join("\n")
        })
        .collect();
    Ok(blocks.join("\n") + "\n")
}

/// A TOML basic string: `"` and `\` escaped, `\n` `\t` `\r` by name, other C0 controls and DEL as
/// `\uXXXX` (uppercase hex).
pub fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            ch if (ch as u32) < 0x20 || ch as u32 == 0x7F => out.push_str(&format!("\\u{:04X}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn options_of(grant: &AccessGrant) -> Result<&TrusttunnelOptions, AdapterError> {
    match &grant.options {
        ProtocolOptions::Trusttunnel(options) => Ok(options),
        _ => Err(crash("this grant carries no TrustTunnel options")),
    }
}

/// The name the client dials and puts in its TLS handshake: the endpoint's own domain as the
/// manager reported it (`public_host` only stands in for an access that predates that).
fn host<'a>(options: &'a TrusttunnelOptions, public_host: &'a str) -> Result<&'a str, AdapterError> {
    let host = options.hostname.as_deref().filter(|host| !host.is_empty()).unwrap_or(public_host);
    if host.is_empty() {
        return Err(AdapterError::new("this TrustTunnel access has not learned its endpoint yet"));
    }
    Ok(host)
}

fn port(options: &TrusttunnelOptions) -> i64 {
    options.port.filter(|port| *port != 0).unwrap_or(443)
}

fn certificate(options: &TrusttunnelOptions) -> Option<&str> {
    options.certificate_der_b64.as_deref().filter(|text| !text.is_empty())
}

fn name(options: &TrusttunnelOptions) -> Option<&str> {
    options.name.as_deref().filter(|name| !name.is_empty())
}

/// The client's `trusttunnel_client.toml`, with the keys the vendor documents for the CLI client.
pub fn render_toml(grant: &AccessGrant, credential: &[u8], public_host: &str) -> Result<String, AdapterError> {
    let options = options_of(grant)?;
    let password = parse_credential(credential)?;
    let host = host(options, public_host)?;
    let mut endpoint = vec![
        format!("hostname = {}", toml_string(host)),
        format!("addresses = [{}]", toml_string(&format!("{host}:{}", port(options)))),
        format!("username = {}", toml_string(&grant.runtime_username)),
        format!("password = {}", toml_string(&password)),
        "skip_verification = false".to_string(),
    ];
    if let Some(certificate) = certificate(options) {
        endpoint.push(format!("certificate = {}", toml_string(&certificate_pem(certificate)?)));
    }
    endpoint.push("upstream_protocol = \"http2\"".to_string());
    if let Some(name) = name(options) {
        endpoint.push(format!("name = {}", toml_string(name)));
    }
    let mut lines: Vec<String> =
        ["loglevel = \"info\"", "vpn_mode = \"general\"", "killswitch_enabled = true", "", "[endpoint]"]
            .map(str::to_string)
            .to_vec();
    lines.extend(endpoint);
    lines.extend(
        ["", "[listener.tun]", "included_routes = [\"0.0.0.0/0\", \"2000::/3\"]", "mtu_size = 1350", ""]
            .map(str::to_string),
    );
    Ok(lines.join("\n"))
}

/// The `tt://?` deep link of an access.
pub fn render_link(grant: &AccessGrant, credential: &[u8], public_host: &str) -> Result<String, AdapterError> {
    let options = options_of(grant)?;
    let password = parse_credential(credential)?;
    let host = host(options, public_host)?;
    let certificate_der = match certificate(options) {
        Some(text) => Some(b64decode_lenient(text.as_bytes()).map_err(crash)?),
        None => None,
    };
    let spec = DeepLinkSpec {
        certificate_der,
        name: options.name.clone(),
        ..DeepLinkSpec::new(host, vec![format!("{host}:{}", port(options))], &grant.runtime_username, &password)
    };
    encode_deeplink(&spec).map_err(|error| crash(error.0))
}

/// The fields a person types into a client that imports neither the link nor the TOML, as one
/// JSON object (`indent=2`, raw UTF-8, no final newline). The Surge line carries no certificate.
pub fn render_manual(grant: &AccessGrant, credential: &[u8], public_host: &str) -> Result<String, AdapterError> {
    let options = options_of(grant)?;
    let password = parse_credential(credential)?;
    let host = host(options, public_host)?;
    let port = port(options);
    let certificate = certificate(options).map(certificate_pem).transpose()?;
    let username = &grant.runtime_username;
    let document = json!({
        "server": host, "port": port, "username": username, "password": password, "sni": host,
        "protocol": "HTTP/2", "quic": false, "certificate_pem": certificate,
        "surge": format!("trust-tunnel, {host}, {port}, username={username}, password={password}"),
    });
    let options = pyjson::Options { indent: Some(2), separators: None, sort_keys: false, ensure_ascii: false };
    Ok(pyjson::dumps(&document, &options))
}

/// The TrustTunnel adapter over the trusttunnel-manager's client.
pub struct TrusttunnelAdapter<C = TrusttunnelClient, R = XrayRouterClient> {
    client: C,
    public_host: String,
    /// The node's Xray-router: the endpoint's SOCKS5 upstream is its loopback ingress, so the
    /// target offers it only while the router serves the `trusttunnel` section.
    router: Option<Arc<RouterAdapter<R>>>,
}

impl<C: TrusttunnelApi, R: RouterApi> TrusttunnelAdapter<C, R> {
    pub fn new(client: C, public_host: impl Into<String>) -> Self {
        Self { client, public_host: public_host.into(), router: None }
    }

    pub fn with_router(mut self, router: Option<Arc<RouterAdapter<R>>>) -> Self {
        self.router = router;
        self
    }

    pub fn client(&self) -> &C {
        &self.client
    }

    pub fn public_host(&self) -> &str {
        &self.public_host
    }

    pub fn router(&self) -> Option<&Arc<RouterAdapter<R>>> {
        self.router.as_ref()
    }

    fn refused(_: ManagerError) -> AdapterError {
        AdapterError::new("TrustTunnel manager refused the request")
    }

    async fn clients(&self) -> Result<Value, AdapterError> {
        self.client.clients().await.map_err(|_| AdapterError::new("TrustTunnel manager unavailable"))
    }

    /// The manager's endpoint view.
    pub async fn endpoint(&self) -> Result<Value, AdapterError> {
        self.client.endpoint().await.map_err(|_| AdapterError::new("TrustTunnel manager unavailable"))
    }

    pub async fn discover(&self) -> Result<ObservedInventory, AdapterError> {
        let clients = self.clients().await?;
        let items = rows(&clients)?
            .into_iter()
            .filter_map(|row| {
                let username = row.get("username")?.as_str()?;
                Some(ObservedGrant {
                    runtime_username: username.to_string(),
                    enabled: row.get("enabled") != Some(&Value::Bool(false)),
                    options: Map::new(),
                    revision: Some(py_str(row.get("revision"))),
                })
            })
            .collect();
        Ok(ObservedInventory { items })
    }

    pub async fn preflight(&self, intent: &GrantIntent) -> Result<Preflight, AdapterError> {
        let endpoint = self.endpoint().await?;
        if !truthy(as_object(&endpoint)?.get("hostname")) {
            return Ok(Preflight { ok: false, reason: Some("TrustTunnel has no hostname on this node".into()) });
        }
        let clients = self.clients().await?;
        let taken = match &clients {
            Value::Array(items) => items.iter().any(|row| row.get("username") == Some(&json!(intent.runtime_username))),
            Value::Object(_) | Value::String(_) => false,
            _ => return Err(crash("the TrustTunnel manager answered clients that are not a list")),
        };
        if taken {
            return Ok(Preflight { ok: false, reason: Some("runtime username already exists".into()) });
        }
        Ok(Preflight { ok: true, reason: None })
    }

    fn password(credential: &CredentialPlan) -> Result<String, AdapterError> {
        if credential.origin() != CredentialOrigin::Caller {
            return Err(AdapterError::new("TrustTunnel needs a caller-supplied password so the panel can escrow it"));
        }
        parse_credential(credential.plaintext().unwrap_or_default())
    }

    fn client_of(result: &Value) -> Result<&Map<String, Value>, AdapterError> {
        as_object(result)?
            .get("client")
            .and_then(Value::as_object)
            .ok_or_else(|| crash("the TrustTunnel manager answered no client"))
    }

    pub async fn create(
        &self,
        operation_id: &str,
        intent: &GrantIntent,
        credential: &CredentialPlan,
    ) -> Result<AppliedGrant, AdapterError> {
        let password = Self::password(credential)?;
        // Learned before anything is written: a node without a usable endpoint refuses cleanly.
        let endpoint = self.endpoint().await?;
        let endpoint = as_object(&endpoint)?;
        if !truthy(endpoint.get("hostname")) {
            return Err(AdapterError::new("TrustTunnel has no hostname on this node"));
        }
        let payload = json!({"operation_id": operation_id, "username": intent.runtime_username, "password": password});
        let (result, recovered) = match self.client.create_client(&payload).await {
            Ok(result) => (result, false),
            Err(error)
                if matches!(error.status_code, 404 | 409 | 422)
                    && error.code.as_deref() != Some("operation_conflict") =>
            {
                return Err(Self::refused(error));
            }
            // The reply may have been lost: the same operation id replays safely.
            Err(_) => (self.client.create_client(&payload).await.map_err(Self::refused)?, true),
        };
        let client = Self::client_of(&result)?;
        let username =
            client.get("username").and_then(Value::as_str).ok_or_else(|| crash("a client without a username"))?;
        Ok(AppliedGrant {
            credential: credential.plaintext().map(<[u8]>::to_vec),
            revision: Some(py_str(client.get("revision"))),
            artifact_template: learned_options(endpoint),
            recovered,
            ..AppliedGrant::new(username, client.get("enabled") != Some(&Value::Bool(false)))
        })
    }

    async fn state(&self, grant: &GrantRef, action: &str) -> Result<AppliedGrant, AdapterError> {
        let result = self.client.client_state(&grant.runtime_username, action).await.map_err(Self::refused)?;
        let client = Self::client_of(&result)?;
        Ok(AppliedGrant {
            revision: Some(py_str(client.get("revision"))),
            ..AppliedGrant::new(&grant.runtime_username, action == "enable")
        })
    }

    pub async fn enable(&self, grant: &GrantRef) -> Result<AppliedGrant, AdapterError> {
        self.state(grant, "enable").await
    }

    pub async fn disable(&self, grant: &GrantRef) -> Result<AppliedGrant, AdapterError> {
        self.state(grant, "disable").await
    }

    pub async fn rotate(
        &self,
        operation_id: &str,
        grant: &GrantRef,
        credential: &CredentialPlan,
    ) -> Result<AppliedGrant, AdapterError> {
        let payload = json!({"operation_id": operation_id, "password": Self::password(credential)?});
        let username = &grant.runtime_username;
        let (result, recovered) = match self.client.rotate_client(username, &payload).await {
            Ok(result) => (result, false),
            Err(error) if matches!(error.status_code, 404 | 409 | 422) => return Err(Self::refused(error)),
            Err(_) => (self.client.rotate_client(username, &payload).await.map_err(Self::refused)?, true),
        };
        let client = Self::client_of(&result)?;
        Ok(AppliedGrant {
            credential: credential.plaintext().map(<[u8]>::to_vec),
            revision: Some(py_str(client.get("revision"))),
            recovered,
            ..AppliedGrant::new(username, client.get("enabled") != Some(&Value::Bool(false)))
        })
    }

    pub async fn delete(&self, grant: &GrantRef) -> Result<(), AdapterError> {
        match self.client.delete_client(&grant.runtime_username).await {
            Ok(_) => Ok(()),
            Err(error) if error.status_code == 404 => {
                Err(AdapterError::already_gone("TrustTunnel manager refused the request"))
            }
            Err(error) => Err(Self::refused(error)),
        }
    }

    /// Always `None`: the manager's account list is write-only for the panel.
    pub async fn capture(&self, _grant: &GrantRef) -> Result<Option<Vec<u8>>, AdapterError> {
        Ok(None)
    }

    /// Always `None`: hostname, port and certificate are the manager's to say; the display name
    /// changes the rendered artifacts, not the node.
    pub async fn update_options(
        &self,
        _grant: &GrantRef,
        _options: &Map<String, Value>,
    ) -> Result<Option<AppliedGrant>, AdapterError> {
        Ok(None)
    }

    pub fn render_artifacts(
        &self,
        grant: &AccessGrant,
        credential: &[u8],
        public_host: &str,
    ) -> Result<Vec<AccessArtifact>, AdapterError> {
        Ok(vec![
            AccessArtifact {
                kind: LINK_KIND.into(),
                label: "Ссылка TrustTunnel".into(),
                media_type: LINK_MEDIA_TYPE.into(),
                value: render_link(grant, credential, public_host)?,
                auto_refresh: AutoRefresh::Supported,
            },
            AccessArtifact {
                kind: TOML_KIND.into(),
                label: "Конфиг TrustTunnel (TOML)".into(),
                media_type: TOML_MEDIA_TYPE.into(),
                value: render_toml(grant, credential, public_host)?,
                auto_refresh: AutoRefresh::Supported,
            },
            AccessArtifact {
                kind: MANUAL_KIND.into(),
                label: "Данные для ручной настройки".into(),
                media_type: MANUAL_MEDIA_TYPE.into(),
                value: render_manual(grant, credential, public_host)?,
                auto_refresh: AutoRefresh::Supported,
            },
        ])
    }

    // Egress (service level): the manager's own document `{mode: direct|socks5, address}`. The
    // manager takes no revision or operation id: the adapter checks the revision against what the
    // manager runs now (an apply of the document it already runs is a no-op there).

    /// `{"mode": "direct"}`, or `{"mode", "address"}` as the manager reports them.
    fn document(view: &Map<String, Value>) -> Value {
        if view.get("mode") == Some(&json!("direct")) {
            return json!({"mode": "direct"});
        }
        json!({"mode": view.get("mode").cloned().unwrap_or(Value::Null),
               "address": view.get("address").cloned().unwrap_or(Value::Null)})
    }

    fn egress_failure(error: ManagerError) -> AdapterError {
        let code = if error.code.as_deref() == Some("no_previous") {
            Some("egress_no_previous")
        } else {
            error.code.as_deref()
        };
        egress_error("TrustTunnel", error.status_code, code)
    }

    async fn egress_view(&self) -> Result<Map<String, Value>, AdapterError> {
        let view = self.client.egress().await.map_err(Self::egress_failure)?;
        Ok(as_object(&view)?.clone())
    }

    async fn egress_current(&self, expected_revision: &str) -> Result<Map<String, Value>, AdapterError> {
        let view = self.egress_view().await?;
        if view.get("revision") != Some(&json!(expected_revision)) {
            return Err(AdapterError::with_code("TrustTunnel egress revision does not match", "egress_conflict"));
        }
        Ok(view)
    }

    pub async fn egress_target(&self) -> Result<Option<EgressTarget>, AdapterError> {
        let view = self.egress_view().await?;
        let mut providers = Map::new();
        if let Some(router) = &self.router {
            if router.target("trusttunnel").await.available {
                providers.insert("router".into(), json!({"reachable": true}));
            }
        }
        // `socks5` is the manager's word for an upstream; the compiler's vocabulary calls it `proxy`.
        let mode = if view.get("mode") == Some(&json!("socks5")) { "proxy" } else { "direct" };
        let target_view = Map::from_iter([
            ("revision".to_string(), view.get("revision").cloned().unwrap_or(Value::Null)),
            ("mode".to_string(), json!(mode)),
            ("document".to_string(), Self::document(&view)),
            ("providers".to_string(), Value::Object(providers)),
            ("capabilities".to_string(), json!(EGRESS_CAPABILITIES)),
        ]);
        Ok(Some(egress_target_from_view("trusttunnel", Backend::TrusttunnelNative, &target_view)))
    }

    pub async fn plan_egress(
        &self,
        document: &Map<String, Value>,
        expected_revision: &str,
    ) -> Result<Map<String, Value>, AdapterError> {
        self.egress_current(expected_revision).await?;
        let plan = self.client.egress_plan(&Value::Object(document.clone())).await.map_err(Self::egress_failure)?;
        let plan = as_object(&plan)?;
        let target = plan
            .get("proposed")
            .and_then(Value::as_object)
            .and_then(|proposed| proposed.get("revision"))
            .cloned()
            .ok_or_else(|| crash("the TrustTunnel manager answered a plan without a proposed revision"))?;
        let diff = if truthy(plan.get("changed")) { json!(["-current", "+planned"]) } else { json!([]) };
        Ok(Map::from_iter([
            ("revision".to_string(), json!(expected_revision)),
            ("target_revision".to_string(), target.clone()),
            ("rendered_sha256".to_string(), target),
            ("diff".to_string(), diff),
            ("warnings".to_string(), json!([])),
            ("reachability".to_string(), json!({})),
            ("restart_required".to_string(), json!(false)),
        ]))
    }

    fn applied(view: &Value) -> Result<AppliedEgress, AdapterError> {
        let view = as_object(view)?;
        let applied = Map::from_iter([
            ("revision".to_string(), view.get("revision").cloned().unwrap_or(Value::Null)),
            ("applied".to_string(), Self::document(view)),
        ]);
        Ok(applied_egress_from_view(&applied))
    }

    pub async fn apply_egress(
        &self,
        document: &Map<String, Value>,
        expected_revision: &str,
        _operation_id: &str,
    ) -> Result<AppliedEgress, AdapterError> {
        self.egress_current(expected_revision).await?;
        let view = self.client.egress_apply(&Value::Object(document.clone())).await.map_err(Self::egress_failure)?;
        Self::applied(&view)
    }

    pub async fn rollback_egress(&self, expected_revision: &str) -> Result<AppliedEgress, AdapterError> {
        self.egress_current(expected_revision).await?;
        let view = self.client.egress_rollback().await.map_err(Self::egress_failure)?;
        Self::applied(&view)
    }
}

crate::protocol_adapter! {
    impl<C: TrusttunnelApi, R: RouterApi> for TrusttunnelAdapter<C, R>;
    protocol: Protocol::Trusttunnel,
    origin: CredentialOrigin::Caller,
    capture: false,
    accepts_caller: true,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_credential_is_a_url_safe_password() {
        let (first, second) = (new_credential(), new_credential());
        assert!(first != second && first.len() == 32);
        assert_eq!(parse_credential(&first).unwrap().as_bytes(), first);
        assert!(first.iter().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(byte)));
    }

    #[test]
    fn a_malformed_credential_is_refused() {
        let long = vec![b'x'; 129];
        for bad in [
            &b""[..],
            b"\xff\xfe",
            b"line\nbreak",
            &long,
            b"del\x7f1234",
            b"short",
            b"has space1",
            "пароль-длинный".as_bytes(),
        ] {
            assert!(parse_credential(bad).is_err());
        }
    }

    #[test]
    fn toml_strings_escape_like_python() {
        assert_eq!(toml_string("a\\b\"c\td\n\r\u{1}\u{7f}é"), "\"a\\\\b\\\"c\\td\\n\\r\\u0001\\u007Fé\"");
    }
}
