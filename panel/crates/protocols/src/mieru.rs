//! Mieru: the caller chooses the password, but the manager keeps no copy of one it made
//! (`protocols/mieru.py`).
//!
//! That asymmetry is why `capture_supported` is false: a grant imported from a running mita cannot
//! be adopted by reading it back, only by rotating, which invalidates the old `mierus://` link.

use panel_core::pytext;
use panel_managers::{ManagerError, MieruClient};
use panel_model::clients::{AccessGrant, GrantIntent, ProtocolOptions};
use panel_model::fleet::CredentialOrigin;
use panel_model::protocols::{
    applied_egress_from_view, egress_error, egress_target_from_view, AccessArtifact, AdapterError, AppliedEgress,
    AppliedGrant, AutoRefresh, CredentialPlan, EgressTarget, GrantRef, ObservedGrant, ObservedInventory, Preflight,
};
use panel_model::validate::Model;
use panel_model::{Backend, Protocol};
use serde_json::{json, Map, Value};

use crate::api::MieruApi;
use crate::error::{crash, raw_manager};
use crate::util::{as_object, decode_utf8, py_str, rows, truthy};

/// The share link mita publishes, with the credential and the endpoint as placeholders.
pub const SHARE_TEMPLATE: &str = "mierus://{username}:{password}@{host}?profile={profile}&port={port}&protocol=TCP";

/// The `mierus://` link of a credential (`share_url`).
pub fn share_url(username: &str, password: &str, host: &str, port: i64) -> String {
    format(SHARE_TEMPLATE, &fields(username, password, host, port)).expect("the default template formats")
}

fn fields(username: &str, password: &str, host: &str, port: i64) -> [(&'static str, String); 5] {
    [
        ("username", pytext::quote(username, "")),
        ("password", pytext::quote(password, "")),
        ("host", host.to_string()),
        ("profile", pytext::quote_path(username)),
        ("port", port.to_string()),
    ]
}

/// Python's `str.format(**fields)` for templates of plain `{name}` fields: `{{` and `}}` are
/// literal braces; a conversion, a format spec, an attribute or an index is refused, like an
/// unknown name (`KeyError`) or an unbalanced brace (`ValueError`) — all a 500 in Python.
pub fn format(template: &str, fields: &[(&str, String)]) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '{' => {
                let mut name = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some('{') => return Err("unexpected '{' in field name".into()),
                        Some(ch) => name.push(ch),
                        None => return Err("expected '}' before end of string".into()),
                    }
                }
                if name.contains(['!', ':', '.', '[']) {
                    return Err(format!("unsupported replacement field {{{name}}}"));
                }
                match fields.iter().find(|(key, _)| *key == name) {
                    Some((_, value)) => out.push_str(value),
                    None => return Err(format!("'{name}'")),
                }
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '}' => return Err("Single '}' encountered in format string".into()),
            ch => out.push(ch),
        }
    }
    Ok(out)
}

/// A `mierus://` link taken apart: what every client config is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruShare {
    pub username: String,
    pub password: String,
    pub host: String,
    pub is_ip: bool,
    pub profile: String,
    /// `{"port": int}` or `{"portRange": "a-b"}`, plus `{"protocol": "TCP"|"UDP"}`: mita's own
    /// `portBindings` shape.
    pub bindings: Vec<Map<String, Value>>,
    pub mtu: i64,
}

impl MieruShare {
    /// Ports as integers, or `None` when any binding is a range.
    pub fn exact_ports(&self) -> Option<Vec<i64>> {
        let ports: Vec<i64> = self.bindings.iter().filter_map(|binding| binding.get("port")?.as_i64()).collect();
        (ports.len() == self.bindings.len()).then_some(ports)
    }
}

/// A link [`parse_share_url`] refuses (Python's `ValueError`, with its message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidShareUrl(pub String);

impl std::fmt::Display for InvalidShareUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidShareUrl {}

/// `urllib.parse.parse_qsl(query, keep_blank_values=True)`.
fn parse_qsl(query: &str) -> Vec<(String, String)> {
    let decode = |text: &str| pytext::unquote(&text.replace('+', " "));
    query
        .split('&')
        .filter(|field| !field.is_empty())
        .map(|field| match field.split_once('=') {
            Some((name, value)) => (decode(name), decode(value)),
            None => (decode(field), String::new()),
        })
        .collect()
}

fn digits(text: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit())
}

/// Validates a `mierus://` link strictly; anything odd is an error, never a guess.
pub fn parse_share_url(value: &str) -> Result<MieruShare, InvalidShareUrl> {
    let invalid = |message: &str| InvalidShareUrl(message.to_string());
    if pytext::len(value) > 4096 {
        return Err(invalid("share url is not a string of sane length"));
    }
    let parts = pytext::urlsplit(value).map_err(|error| InvalidShareUrl(error.0))?;
    let query = parse_qsl(&parts.query);
    let authority_port = parts.port().map_err(|error| InvalidShareUrl(error.0))?;
    let values = |key: &str| query.iter().filter(|(name, _)| name == key).map(|(_, value)| value.as_str()).collect();
    let ports: Vec<&str> = values("port");
    let protocols: Vec<&str> = values("protocol");
    let profiles: Vec<&str> = values("profile");
    let hostname = parts.hostname();
    if parts.scheme != "mierus"
        || parts.username().is_none_or(str::is_empty)
        || parts.password().is_none_or(str::is_empty)
        || hostname.is_none()
        || authority_port.is_some()
        || !matches!(parts.path.as_str(), "" | "/")
        || !parts.fragment.is_empty()
        || profiles.len() != 1
        || profiles[0].is_empty()
        || ports.is_empty()
        || ports.len() != protocols.len()
        || protocols.iter().any(|protocol| !matches!(*protocol, "TCP" | "UDP"))
    {
        return Err(invalid("share url has an unexpected shape"));
    }

    let mut bindings = Vec::with_capacity(ports.len());
    for (port, protocol) in ports.iter().zip(&protocols) {
        if digits(port, 1, 5) && (1..=65535).contains(&port.parse::<u32>().unwrap_or(0)) {
            bindings.push(Map::from_iter([
                ("port".to_string(), json!(port.parse::<u32>().unwrap_or(0))),
                ("protocol".to_string(), json!(protocol)),
            ]));
            continue;
        }
        let range = port.split_once('-').filter(|(low, high)| digits(low, 1, 5) && digits(high, 1, 5));
        let Some((low, high)) = range else {
            return Err(invalid("share url carries an invalid port"));
        };
        let (low, high) = (low.parse::<u32>().unwrap_or(0), high.parse::<u32>().unwrap_or(0));
        if !(1 <= low && low <= high && high <= 65535) {
            return Err(invalid("share url carries an invalid port"));
        }
        bindings
            .push(Map::from_iter([("portRange".to_string(), json!(port)), ("protocol".to_string(), json!(protocol))]));
    }

    let mtu_values: Vec<&str> = values("mtu");
    if mtu_values.len() > 1 || mtu_values.first().is_some_and(|mtu| !digits(mtu, 4, 5)) {
        return Err(invalid("share url carries an invalid mtu"));
    }
    let mtu = mtu_values.first().map_or(1400, |mtu| mtu.parse::<i64>().unwrap_or(0));
    if !(1280..=1500).contains(&mtu) {
        return Err(invalid("share url carries an mtu out of range"));
    }

    let hostname = hostname.unwrap_or_default();
    let (host, is_ip) = match pytext::ip_address(&hostname) {
        Ok(address) => (address.to_string(), true),
        Err(_) => (hostname, false),
    };
    Ok(MieruShare {
        username: pytext::unquote(parts.username().unwrap_or_default()),
        password: pytext::unquote(parts.password().unwrap_or_default()),
        host,
        is_ip,
        profile: profiles[0].to_string(),
        bindings,
        mtu,
    })
}

/// The `mieru` outbounds Karing's sing-box core takes, one per exact port; `None` when a binding
/// is a range (that shape has no place for one).
pub fn singbox_outbounds(share: &MieruShare, tag: impl Fn(i64, &str) -> String) -> Option<Vec<Value>> {
    let ports = share.exact_ports()?;
    Some(
        ports
            .iter()
            .zip(&share.bindings)
            .map(|(port, binding)| {
                let protocol = binding.get("protocol").and_then(Value::as_str).unwrap_or_default();
                json!({
                    "type": "mieru",
                    "tag": tag(*port, protocol),
                    "server": share.host,
                    "server_port": port,
                    "transport": protocol,
                    "username": share.username,
                    "password": share.password,
                })
            })
            .collect(),
    )
}

/// Turns the manager's real share URL into a template the panel can re-render: only the
/// credential is replaced (first occurrence); a URL without it gives `None`.
pub fn template_from(share_url_value: &Value, username: &str, password: &str) -> Option<String> {
    let share = share_url_value.as_str()?;
    let credentials = format!("{}:{}@", pytext::quote(username, ""), pytext::quote(password, ""));
    share.contains(&credentials).then(|| share.replacen(&credentials, "{username}:{password}@", 1))
}

/// A revision as the model carries it (`str` in practice; anything else as its `str()`).
fn revision_text(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(other) => Some(py_str(Some(other))),
    }
}

/// The Mieru adapter over the mieru-manager's client.
pub struct MieruAdapter<C = MieruClient> {
    client: C,
    /// mita owns the public host; it arrives inside the share URL.
    public_host: String,
    port: i64,
}

impl<C: MieruApi> MieruAdapter<C> {
    /// `MieruAdapter(client, public_host="", port=8443)`.
    pub fn new(client: C, public_host: impl Into<String>) -> Self {
        Self { client, public_host: public_host.into(), port: 8443 }
    }

    pub fn with_port(mut self, port: i64) -> Self {
        self.port = port;
        self
    }

    pub fn client(&self) -> &C {
        &self.client
    }

    pub fn public_host(&self) -> &str {
        &self.public_host
    }

    pub fn port(&self) -> i64 {
        self.port
    }

    /// The manager's current revision (`health().get("revision")`).
    async fn revision(&self) -> Result<Value, AdapterError> {
        let health = self.client.health().await.map_err(|_| AdapterError::new("Mieru manager unavailable"))?;
        Ok(as_object(&health)?.get("revision").cloned().unwrap_or(Value::Null))
    }

    /// `grant.revision or await self._revision()`.
    async fn revision_for(&self, grant: &GrantRef) -> Result<Value, AdapterError> {
        match grant.revision.as_deref() {
            Some(revision) if !revision.is_empty() => Ok(json!(revision)),
            _ => self.revision().await,
        }
    }

    pub async fn discover(&self) -> Result<ObservedInventory, AdapterError> {
        let revision = self.revision().await?;
        let listed = self.client.list_users().await.map_err(raw_manager)?;
        let items = rows(&listed)?
            .into_iter()
            .filter_map(|row| {
                let username = row.get("username")?.as_str()?;
                Some(ObservedGrant {
                    runtime_username: username.to_string(),
                    enabled: row.get("enabled") != Some(&Value::Bool(false)),
                    options: Map::from_iter([("quotas".to_string(), row.get("quotas").cloned().unwrap_or(json!([])))]),
                    revision: revision_text(Some(&revision)),
                })
            })
            .collect();
        Ok(ObservedInventory { items })
    }

    pub async fn preflight(&self, intent: &GrantIntent) -> Result<Preflight, AdapterError> {
        let listed = self.client.list_users().await.map_err(raw_manager)?;
        if rows(&listed)?.into_iter().any(|row| row.get("username") == Some(&json!(intent.runtime_username))) {
            return Ok(Preflight { ok: false, reason: Some("runtime username already exists".into()) });
        }
        Ok(Preflight { ok: true, reason: None })
    }

    fn template(&self, share_template: &str) -> Map<String, Value> {
        Map::from_iter([
            ("share_template".to_string(), json!(share_template)),
            ("host".to_string(), json!(self.public_host)),
            ("port".to_string(), json!(self.port)),
        ])
    }

    fn applied(
        &self,
        username: &str,
        password: &str,
        result: &Value,
        recovered: bool,
    ) -> Result<AppliedGrant, AdapterError> {
        let result = as_object(result)?;
        let share = result.get("share_url").filter(|share| truthy(Some(share)));
        let template = share.and_then(|share| template_from(share, username, password));
        Ok(AppliedGrant {
            credential: Some(password.as_bytes().to_vec()),
            revision: revision_text(result.get("revision")),
            artifact_template: self.template(template.as_deref().unwrap_or(SHARE_TEMPLATE)),
            recovered,
            ..AppliedGrant::new(username, true)
        })
    }

    fn unrecoverable(error: &ManagerError) -> AdapterError {
        if matches!(error.code.as_deref(), Some("result_unrecoverable" | "operation_conflict")) {
            return AdapterError::manual_intervention("the Mieru credential must be rotated", None);
        }
        AdapterError::new("Mieru manager refused the request")
    }

    fn password(credential: &CredentialPlan) -> Result<String, AdapterError> {
        if credential.origin() != CredentialOrigin::Caller {
            return Err(AdapterError::new("Mieru needs a caller-supplied password so the panel can escrow it"));
        }
        decode_utf8(credential.plaintext().unwrap_or_default())
    }

    pub async fn create(
        &self,
        operation_id: &str,
        intent: &GrantIntent,
        credential: &CredentialPlan,
    ) -> Result<AppliedGrant, AdapterError> {
        let password = Self::password(credential)?;
        let quotas: Vec<Value> = match &intent.options {
            ProtocolOptions::Mieru(options) => options.quotas.iter().map(Model::dump).collect(),
            _ => Vec::new(),
        };
        let mut payload = Map::new();
        payload.insert("username".into(), json!(intent.runtime_username));
        payload.insert("quotas".into(), json!(quotas));
        payload.insert("expected_revision".into(), self.revision().await?);
        payload.insert("password".into(), json!(password));
        payload.insert("operation_id".into(), json!(operation_id));
        let (result, recovered) = match self.client.create(&Value::Object(payload.clone())).await {
            Ok(result) => (result, false),
            Err(_) => {
                payload.insert("expected_revision".into(), self.revision().await?);
                let result =
                    self.client.create(&Value::Object(payload)).await.map_err(|error| Self::unrecoverable(&error))?;
                (result, true)
            }
        };
        self.applied(&intent.runtime_username, &password, &result, recovered)
    }

    async fn operation(&self, grant: &GrantRef, operation: &str) -> Result<AppliedGrant, AdapterError> {
        let revision = self.revision_for(grant).await?;
        let result = self
            .client
            .operation(&grant.runtime_username, operation, &revision)
            .await
            .map_err(|_| AdapterError::new("Mieru manager refused the request"))?;
        // Enabling and disabling never touch the credential, so none is reported.
        Ok(AppliedGrant {
            revision: revision_text(as_object(&result)?.get("revision")),
            artifact_template: self.template(SHARE_TEMPLATE),
            ..AppliedGrant::new(&grant.runtime_username, operation == "enable")
        })
    }

    pub async fn enable(&self, grant: &GrantRef) -> Result<AppliedGrant, AdapterError> {
        self.operation(grant, "enable").await
    }

    pub async fn disable(&self, grant: &GrantRef) -> Result<AppliedGrant, AdapterError> {
        self.operation(grant, "disable").await
    }

    pub async fn rotate(
        &self,
        operation_id: &str,
        grant: &GrantRef,
        credential: &CredentialPlan,
    ) -> Result<AppliedGrant, AdapterError> {
        let password = Self::password(credential)?;
        let revision = self.revision_for(grant).await?;
        let username = &grant.runtime_username;
        let (result, recovered) = match self.client.rotate(username, &revision, &password, operation_id).await {
            Ok(result) => (result, false),
            Err(_) => {
                let revision = self.revision().await?;
                let result = self
                    .client
                    .rotate(username, &revision, &password, operation_id)
                    .await
                    .map_err(|error| Self::unrecoverable(&error))?;
                (result, true)
            }
        };
        self.applied(username, &password, &result, recovered)
    }

    pub async fn delete(&self, grant: &GrantRef) -> Result<(), AdapterError> {
        let revision = self.revision_for(grant).await?;
        match self.client.delete(&grant.runtime_username, &revision).await {
            Ok(_) => Ok(()),
            Err(error) if error.status_code == 404 => {
                Err(AdapterError::already_gone("Mieru manager refused the request"))
            }
            Err(_) => Err(AdapterError::new("Mieru manager refused the request")),
        }
    }

    /// The `mierus://` link for a credential the panel already holds.
    pub fn share(&self, username: &str, password: &str) -> String {
        share_url(username, password, &self.public_host, self.port)
    }

    /// Always `None`: mita keeps a hash, so the credential cannot be read back.
    pub async fn capture(&self, _grant: &GrantRef) -> Result<Option<Vec<u8>>, AdapterError> {
        Ok(None)
    }

    pub async fn update_options(
        &self,
        grant: &GrantRef,
        options: &Map<String, Value>,
    ) -> Result<Option<AppliedGrant>, AdapterError> {
        let Some(quotas) = options.get("quotas") else { return Ok(None) };
        self.client
            .set_quotas(&grant.runtime_username, &json!({"quotas": quotas}))
            .await
            .map_err(|_| AdapterError::new("Mieru manager refused the request"))?;
        Ok(Some(AppliedGrant {
            credential: Some(Vec::new()),
            revision: revision_text(Some(&self.revision().await?)),
            artifact_template: self.template(SHARE_TEMPLATE),
            ..AppliedGrant::new(&grant.runtime_username, true)
        }))
    }

    pub fn render_artifacts(
        &self,
        grant: &AccessGrant,
        credential: &[u8],
        public_host: &str,
    ) -> Result<Vec<AccessArtifact>, AdapterError> {
        let options = grant.options.dump();
        let template = options.get("share_template").filter(|value| truthy(Some(value)));
        let template = template.map_or_else(|| SHARE_TEMPLATE.to_string(), |value| py_str(Some(value)));
        // A learned template already carries mita's own host and port; the default one still has
        // placeholders. Passing every field suits both.
        let fields = fields(&grant.runtime_username, &decode_utf8(credential)?, public_host, self.port);
        let value = format(&template, &fields).map_err(crash)?;
        Ok(vec![AccessArtifact {
            kind: "share_url".into(),
            label: "Ссылка Mieru".into(),
            media_type: "text/uri-list".into(),
            value,
            auto_refresh: AutoRefresh::Supported,
        }])
    }

    fn egress_failure(error: ManagerError) -> AdapterError {
        egress_error("Mieru", error.status_code, error.code.as_deref())
    }

    pub async fn egress_target(&self) -> Result<Option<EgressTarget>, AdapterError> {
        let view = self.client.egress().await.map_err(Self::egress_failure)?;
        Ok(Some(egress_target_from_view("mieru", Backend::MieruNative, as_object(&view)?)))
    }

    pub async fn plan_egress(
        &self,
        document: &Map<String, Value>,
        expected_revision: &str,
    ) -> Result<Map<String, Value>, AdapterError> {
        let document = Value::Object(document.clone());
        let plan = self.client.egress_plan(expected_revision, &document).await.map_err(Self::egress_failure)?;
        Ok(as_object(&plan)?.clone())
    }

    pub async fn apply_egress(
        &self,
        document: &Map<String, Value>,
        expected_revision: &str,
        operation_id: &str,
    ) -> Result<AppliedEgress, AdapterError> {
        let document = Value::Object(document.clone());
        let view =
            self.client.egress_apply(expected_revision, &document, operation_id).await.map_err(Self::egress_failure)?;
        Ok(applied_egress_from_view(as_object(&view)?))
    }

    pub async fn rollback_egress(&self, expected_revision: &str) -> Result<AppliedEgress, AdapterError> {
        let view = self.client.egress_rollback(expected_revision).await.map_err(Self::egress_failure)?;
        Ok(applied_egress_from_view(as_object(&view)?))
    }

    /// The manager's per-client handlers and slots (v0.7).
    pub async fn lanes(&self) -> Result<Value, AdapterError> {
        self.client.lanes().await.map_err(Self::egress_failure)
    }

    pub async fn set_lanes(&self, lanes: &Value) -> Result<Value, AdapterError> {
        self.client.set_lanes(lanes).await.map_err(Self::egress_failure)
    }
}

crate::protocol_adapter! {
    impl<C: MieruApi> for MieruAdapter<C>;
    protocol: Protocol::Mieru,
    origin: CredentialOrigin::Caller,
    capture: false,
    accepts_caller: true,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_format_like_python() {
        let fields = fields("a b", "p/q", "h", 8443);
        assert_eq!(format("{username}:{password}@{host}:{port}?x={{y}}", &fields).unwrap(), "a%20b:p%2Fq@h:8443?x={y}");
        assert!(format("{oops}", &fields).is_err());
        assert!(format("{port:05d}", &fields).is_err());
        assert!(format("}", &fields).is_err());
        assert!(format("{", &fields).is_err());
        assert_eq!(share_url("a/b", "p", "h", 1), "mierus://a%2Fb:p@h?profile=a/b&port=1&protocol=TCP");
    }
}
