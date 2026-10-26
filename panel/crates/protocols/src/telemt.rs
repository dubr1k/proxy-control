//! MTProxy through Telemt: the manager owns the secret, and the live link carries it
//! (`protocols/telemt.py`).
//!
//! Telemt has no operation id, so a lost reply cannot be replayed. What saves the grant is that the
//! credential is readable back: after an indeterminate call the adapter asks what the runtime holds
//! now rather than guessing or creating a second account.
//!
//! Egress (v1.1): Telemt's upstream is direct, or handed whole to the node's Xray-router through
//! the `xray-router-ingress` SOCKS5 bridge. No manager stands in between: the panel speaks
//! Telemt's config API itself (PATCH `upstreams` → runtime reload → read back) and keeps the
//! journal a manager would keep, secret-free, for «rollback».

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use panel_core::{ids, pytext};
use panel_managers::{
    access_from_user, TelemtAccess, TelemtClient, TelemtEgressJournal, TelemtError, XrayRouterClient,
};
use panel_model::clients::{AccessGrant, GrantIntent};
use panel_model::fleet::CredentialOrigin;
use panel_model::protocols::{
    AccessArtifact, AdapterError, AppliedDocument, AppliedEgress, AppliedGrant, AutoRefresh, BoxFuture, CredentialPlan,
    EgressMode, EgressTarget, GrantRef, ObservedGrant, ObservedInventory, Preflight,
};
use panel_model::pyrepr;
use panel_model::routing::document::{
    attach_document, attached_to_router, canonical, document_digest, telemt_direct_document, MTPROXY_BRIDGE_ADDRESS,
};
use panel_model::{Backend, Protocol};
use serde_json::{json, Map, Value};

use crate::api::{RouterApi, TelemtApi};
use crate::error::{crash, raw_telemt};
use crate::util::{decode_utf8, py_str, rows, truthy};
use crate::xray_router::RouterAdapter;

/// The per-user limits Telemt takes (`OPTION_FIELDS`, also what `update_options` may change).
pub const OPTION_FIELDS: &[&str] =
    &["data_quota_bytes", "rate_limit_up_bps", "rate_limit_down_bps", "max_tcp_conns", "max_unique_ips"];

/// What «direct» puts back when no earlier upstream is on record: the entrypoint's own.
pub fn direct_upstreams() -> Value {
    json!([{"type": "direct", "ipv4": true, "ipv6": false}])
}

/// How the bridge is probed: the ingress (`{"address", "username", "password"}`) → reachable.
pub type BridgeProbe = Arc<dyn Fn(Value) -> BoxFuture<'static, bool> + Send + Sync>;

/// `int(text)` of a `str.isdigit()` port, `None` when Python would not get a usable port.
fn port_number(text: &str) -> Option<u16> {
    if text.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for ch in text.chars() {
        value = value.checked_mul(10)?.checked_add(pytext::decimal(ch)?)?;
    }
    u16::try_from(value).ok()
}

fn exchange(stream: &mut TcpStream, request: &[u8], expected: &[u8]) -> std::io::Result<bool> {
    stream.write_all(request)?;
    let mut reply = [0u8; 2];
    let read = stream.read(&mut reply)?;
    Ok(&reply[..read] == expected)
}

/// The bridge answers a SOCKS5 greeting and takes Telemt's login: what attach needs before Telemt
/// is pointed at it. Blocking; never fails (false on any error).
pub fn probe_bridge(ingress: &Value, timeout: Duration) -> bool {
    let field = |key: &str| ingress.get(key).map_or_else(String::new, |value| py_str(Some(value)));
    let address = field("address");
    let (host, port) = address.rsplit_once(':').unwrap_or(("", address.as_str()));
    let (username, password) = (field("username").into_bytes(), field("password").into_bytes());
    let Some(port) = port_number(port) else { return false };
    if host.is_empty() || !(1..256).contains(&username.len()) || !(1..256).contains(&password.len()) {
        return false;
    }
    let Ok(addresses) = (host, port).to_socket_addrs() else { return false };
    let Some(mut stream) = addresses.into_iter().find_map(|address| TcpStream::connect_timeout(&address, timeout).ok())
    else {
        return false;
    };
    if stream.set_read_timeout(Some(timeout)).is_err() || stream.set_write_timeout(Some(timeout)).is_err() {
        return false;
    }
    let mut login = vec![0x01, username.len() as u8];
    login.extend(&username);
    login.push(password.len() as u8);
    login.extend(&password);
    matches!(exchange(&mut stream, b"\x05\x01\x02", b"\x05\x02"), Ok(true))
        && matches!(exchange(&mut stream, &login, b"\x01\x00"), Ok(true))
}

/// The default probe: [`probe_bridge`] with a 3 s timeout on the blocking pool.
pub fn default_bridge_probe() -> BridgeProbe {
    Arc::new(|ingress| {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || probe_bridge(&ingress, Duration::from_secs(3))).await.unwrap_or(false)
        })
    })
}

/// `tg://proxy?server={quote(host, safe='')}&port={port}&secret={quote(secret, safe='')}`.
pub fn link(host: &str, port: &str, secret: &str) -> String {
    format!("tg://proxy?server={}&port={port}&secret={}", pytext::quote(host, ""), pytext::quote(secret, ""))
}

/// An outcome of a create/rotate attempt: Telemt's answer, or the grant read back after a lost
/// reply.
enum Attempt {
    Answer(Value),
    Recovered(AppliedGrant),
}

#[derive(Clone, Copy)]
enum Mutation {
    Create,
    Rotate,
}

/// A failure inside the adapter: an `AdapterError`, or a Telemt error that escapes as it is.
enum Failure {
    Adapter(AdapterError),
    Raw(TelemtError),
}

impl From<AdapterError> for Failure {
    fn from(error: AdapterError) -> Self {
        Failure::Adapter(error)
    }
}

impl Failure {
    fn into_adapter(self) -> AdapterError {
        match self {
            Failure::Adapter(error) => error,
            Failure::Raw(error) => raw_telemt(error),
        }
    }
}

fn refused(_: TelemtError) -> AdapterError {
    AdapterError::new("Telemt refused the request")
}

fn coded(message: &str, code: &str) -> AdapterError {
    AdapterError::with_code(message, code)
}

/// The Telemt adapter over Telemt's own API client.
pub struct TelemtAdapter<C = TelemtClient, R = XrayRouterClient> {
    client: C,
    /// Telemt owns the public host: it comes back inside the link, so this is only a fallback.
    public_host: String,
    public_port: i64,
    router: Option<Arc<RouterAdapter<R>>>,
    journal: TelemtEgressJournal,
    bridge_probe: BridgeProbe,
    reload_timeout: Duration,
    reload_poll: Duration,
    lock: tokio::sync::Mutex<()>,
}

impl<C: TelemtApi, R: RouterApi> TelemtAdapter<C, R> {
    /// `TelemtAdapter(client)`: no fallback host, port 443, no router, an in-memory journal, the
    /// real bridge probe, a 30 s reload deadline polled every 0.5 s.
    pub fn new(client: C) -> Self {
        Self {
            client,
            public_host: String::new(),
            public_port: 443,
            router: None,
            journal: TelemtEgressJournal::new(None),
            bridge_probe: default_bridge_probe(),
            reload_timeout: Duration::from_secs(30),
            reload_poll: Duration::from_millis(500),
            lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn with_public_host(mut self, public_host: impl Into<String>) -> Self {
        self.public_host = public_host.into();
        self
    }

    pub fn with_public_port(mut self, public_port: i64) -> Self {
        self.public_port = public_port;
        self
    }

    pub fn with_router(mut self, router: Option<Arc<RouterAdapter<R>>>) -> Self {
        self.router = router;
        self
    }

    /// The journal file (`<dirname(PANEL_DATABASE)>/telemt-egress.json`), or `None` for memory.
    pub fn with_journal_path(mut self, path: Option<PathBuf>) -> Self {
        self.journal = TelemtEgressJournal::new(path);
        self
    }

    pub fn with_bridge_probe(mut self, probe: BridgeProbe) -> Self {
        self.bridge_probe = probe;
        self
    }

    /// How long a reload may take, and how often its status is asked.
    pub fn with_reload_timing(mut self, timeout: Duration, poll: Duration) -> Self {
        self.reload_timeout = timeout;
        self.reload_poll = poll;
        self
    }

    pub fn client(&self) -> &C {
        &self.client
    }

    pub fn public_host(&self) -> &str {
        &self.public_host
    }

    pub fn public_port(&self) -> i64 {
        self.public_port
    }

    pub fn router(&self) -> Option<&Arc<RouterAdapter<R>>> {
        self.router.as_ref()
    }

    pub fn journal(&self) -> &TelemtEgressJournal {
        &self.journal
    }

    /// Reuse inventory between mutations; post-write readback is fresh. Dropping the guard ends
    /// the batch.
    pub fn batch(&self) -> C::Batch {
        self.client.batch()
    }

    async fn users(&self) -> Result<Value, AdapterError> {
        self.client.list_users().await.map_err(raw_telemt)
    }

    /// Where the user's link points (`host`/`port` of the options), never its secret.
    fn endpoint(row: &Value) -> Map<String, Value> {
        let mut endpoint = Map::new();
        if let Some(access) = access_from_user(row) {
            if let Some(server) = access.server.filter(|server| !server.is_empty()) {
                endpoint.insert("host".into(), json!(server));
            }
            if let Some(port) = access.port {
                endpoint.insert("port".into(), json!(port));
            }
        }
        endpoint
    }

    pub async fn discover(&self) -> Result<ObservedInventory, AdapterError> {
        let users = self.users().await?;
        let items = rows(&users)?
            .into_iter()
            .filter_map(|row| {
                let username = row.get("username")?.as_str()?;
                let mut options: Map<String, Value> =
                    OPTION_FIELDS.iter().filter_map(|key| Some((key.to_string(), row.get(*key)?.clone()))).collect();
                options.extend(Self::endpoint(&Value::Object(row.clone())));
                Some(ObservedGrant {
                    runtime_username: username.to_string(),
                    enabled: row.get("enabled") != Some(&Value::Bool(false)),
                    options,
                    revision: None,
                })
            })
            .collect();
        Ok(ObservedInventory { items })
    }

    pub async fn preflight(&self, intent: &GrantIntent) -> Result<Preflight, AdapterError> {
        let users = self.users().await?;
        if rows(&users)?.into_iter().any(|row| row.get("username") == Some(&json!(intent.runtime_username))) {
            return Ok(Preflight { ok: false, reason: Some("runtime username already exists".into()) });
        }
        Ok(Preflight { ok: true, reason: None })
    }

    /// Everything a link needs comes out of the link Telemt returned: the host and port are
    /// learned the way Mieru's share template is.
    fn applied(&self, username: &str, access: Option<&TelemtAccess>, enabled: bool, recovered: bool) -> AppliedGrant {
        let secret = access.and_then(|access| access.secret.clone()).unwrap_or_default();
        let host = access.and_then(|access| access.server.clone()).filter(|host| !host.is_empty());
        let port = access.and_then(|access| access.port).filter(|port| *port != 0);
        AppliedGrant {
            credential: Some(secret.into_bytes()),
            artifact_template: Map::from_iter([
                ("host".to_string(), json!(host.unwrap_or_else(|| self.public_host.clone()))),
                ("port".to_string(), port.map_or(json!(self.public_port), |port| json!(port))),
            ]),
            recovered,
            ..AppliedGrant::new(username, enabled)
        }
    }

    /// The credential is what the link carries (with the `ee` Fake-TLS prefix), not the bare
    /// `secret` field.
    fn link_access(result: &Value) -> Option<TelemtAccess> {
        let user = result.as_object().and_then(|result| result.get("user")).cloned().unwrap_or(Value::Null);
        access_from_user(&user).filter(|access| access.secret.as_deref().is_some_and(|secret| !secret.is_empty()))
    }

    /// The link after a mutation; a Telemt failure here is an `AdapterError` like the mutation's.
    async fn read_back(&self, username: &str) -> Result<Option<TelemtAccess>, AdapterError> {
        self.client.current_access(username).await.map_err(refused)
    }

    async fn recover(&self, username: &str) -> Result<Option<AppliedGrant>, TelemtError> {
        let access = self.client.current_access(username).await?;
        Ok(access
            .filter(|access| access.secret.as_deref().is_some_and(|secret| !secret.is_empty()))
            .map(|access| self.applied(username, Some(&access), true, true)))
    }

    async fn call(&self, mutation: Mutation, username: &str, secret: Option<&str>) -> Result<Value, TelemtError> {
        match mutation {
            Mutation::Create => self.client.create_user(username, secret).await,
            Mutation::Rotate => self.client.rotate(username, secret).await,
        }
    }

    async fn attempt(&self, mutation: Mutation, username: &str, secret: Option<&str>) -> Result<Attempt, TelemtError> {
        match self.call(mutation, username, secret).await {
            Ok(answer) => Ok(Attempt::Answer(answer)),
            Err(error) if error.indeterminate => {
                if let Some(applied) = self.recover(username).await? {
                    return Ok(Attempt::Recovered(applied));
                }
                match mutation {
                    // Nothing was created, so a single retry is safe rather than a guess. If this
                    // also comes back indeterminate, the outcome is still unknown: it escapes as it
                    // is, and the saga must resume, not compensate.
                    Mutation::Create => Ok(Attempt::Answer(self.call(mutation, username, secret).await?)),
                    Mutation::Rotate => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Try a caller-chosen secret; on a runtime that refuses it (400/422), fall back to a
    /// manager-generated one and say so via the returned origin. An indeterminate outcome always
    /// escapes as it is.
    async fn with_caller_fallback(
        &self,
        mutation: Mutation,
        username: &str,
        secret: Option<&str>,
    ) -> Result<(Attempt, CredentialOrigin), Failure> {
        let origin = if secret.is_some() { CredentialOrigin::Caller } else { CredentialOrigin::Manager };
        match self.attempt(mutation, username, secret).await {
            Ok(outcome) => Ok((outcome, origin)),
            Err(error) if error.indeterminate => Err(Failure::Raw(error)),
            Err(error) if secret.is_none() || !matches!(error.status_code, 400 | 422) => {
                Err(Failure::Adapter(refused(error)))
            }
            // This build generates its own secret: fall back and report the origin.
            Err(_) => match self.attempt(mutation, username, None).await {
                Ok(outcome) => Ok((outcome, CredentialOrigin::Manager)),
                Err(error) if error.indeterminate => Err(Failure::Raw(error)),
                Err(error) => Err(Failure::Adapter(refused(error))),
            },
        }
    }

    async fn mutate(
        &self,
        mutation: Mutation,
        username: &str,
        credential: &CredentialPlan,
    ) -> Result<AppliedGrant, AdapterError> {
        let secret = match credential.origin() {
            CredentialOrigin::Caller => Some(decode_utf8(credential.plaintext().unwrap_or_default())?),
            CredentialOrigin::Manager => None,
        };
        let (outcome, origin) =
            self.with_caller_fallback(mutation, username, secret.as_deref()).await.map_err(Failure::into_adapter)?;
        let answer = match outcome {
            Attempt::Recovered(applied) => return Ok(applied),
            Attempt::Answer(answer) => answer,
        };
        let access = Self::link_access(&answer)
            .ok_or_else(|| AdapterError::new("Telemt returned a user without a connection link"))?;
        Ok(AppliedGrant { credential_origin: origin, ..self.applied(username, Some(&access), true, false) })
    }

    pub async fn create(
        &self,
        _operation_id: &str,
        intent: &GrantIntent,
        credential: &CredentialPlan,
    ) -> Result<AppliedGrant, AdapterError> {
        self.mutate(Mutation::Create, &intent.runtime_username, credential).await
    }

    async fn set_enabled(&self, grant: &GrantRef, enabled: bool) -> Result<AppliedGrant, AdapterError> {
        self.client.set_enabled(&grant.runtime_username, enabled).await.map_err(refused)?;
        let access = self.read_back(&grant.runtime_username).await?;
        Ok(self.applied(&grant.runtime_username, access.as_ref(), enabled, false))
    }

    pub async fn enable(&self, grant: &GrantRef) -> Result<AppliedGrant, AdapterError> {
        self.set_enabled(grant, true).await
    }

    pub async fn disable(&self, grant: &GrantRef) -> Result<AppliedGrant, AdapterError> {
        self.set_enabled(grant, false).await
    }

    pub async fn rotate(
        &self,
        _operation_id: &str,
        grant: &GrantRef,
        credential: &CredentialPlan,
    ) -> Result<AppliedGrant, AdapterError> {
        self.mutate(Mutation::Rotate, &grant.runtime_username, credential).await
    }

    pub async fn update_options(
        &self,
        grant: &GrantRef,
        options: &Map<String, Value>,
    ) -> Result<Option<AppliedGrant>, AdapterError> {
        let fields: Map<String, Value> =
            OPTION_FIELDS.iter().filter_map(|key| Some((key.to_string(), options.get(*key)?.clone()))).collect();
        if fields.is_empty() {
            return Ok(None);
        }
        self.client.update_user(&grant.runtime_username, &Value::Object(fields)).await.map_err(refused)?;
        let access = self.read_back(&grant.runtime_username).await?;
        Ok(Some(AppliedGrant {
            credential_origin: CredentialOrigin::Manager,
            ..self.applied(&grant.runtime_username, access.as_ref(), true, false)
        }))
    }

    pub async fn delete(&self, grant: &GrantRef) -> Result<(), AdapterError> {
        match self.client.delete_user(&grant.runtime_username).await {
            Ok(_) => Ok(()),
            Err(error) if error.status_code == 404 => Err(AdapterError::already_gone("Telemt refused the request")),
            Err(error) => Err(refused(error)),
        }
    }

    /// The live link is the credential, so an existing account needs no rotation. A Telemt
    /// failure is an `AdapterError` (the node's capture route turns it into `null`).
    pub async fn capture(&self, grant: &GrantRef) -> Result<Option<Vec<u8>>, AdapterError> {
        let access = self.client.current_access(&grant.runtime_username).await.map_err(refused)?;
        Ok(access.and_then(|access| access.secret).filter(|secret| !secret.is_empty()).map(String::into_bytes))
    }

    pub fn render_artifacts(
        &self,
        grant: &AccessGrant,
        credential: &[u8],
        public_host: &str,
    ) -> Result<Vec<AccessArtifact>, AdapterError> {
        let options = grant.options.dump();
        // What the saga learned from Telemt's own link wins over any configured fallback.
        let host = crate::util::text_or(options.get("host"), public_host);
        let port = match options.get("port") {
            Some(port) if truthy(Some(port)) => py_str(Some(port)),
            _ => self.public_port.to_string(),
        };
        Ok(vec![AccessArtifact {
            kind: "link".into(),
            label: "Ссылка Telegram".into(),
            media_type: "text/uri-list".into(),
            value: link(&host, &port, &decode_utf8(credential)?),
            auto_refresh: AutoRefresh::Supported,
        }])
    }

    // -- egress --

    fn journal_read(&self) -> Result<Map<String, Value>, AdapterError> {
        match self.journal.read() {
            Ok(Value::Object(journal)) => Ok(journal),
            _ => Err(coded("the Telemt egress journal is unreadable", "manual_intervention_required")),
        }
    }

    fn journal_write(&self, journal: Map<String, Value>) -> Result<(), AdapterError> {
        self.journal
            .write(&Value::Object(journal))
            .map_err(|error| crash(format!("the Telemt egress journal: {error}")))
    }

    /// (upstreams, the whole config's revision): `telemt_api_unsupported` for a Telemt without the
    /// config API, `manager_unavailable` for one that does not answer.
    async fn config(&self) -> Result<(Vec<Map<String, Value>>, String), AdapterError> {
        let (data, revision) = self.client.config().await.map_err(|error| {
            if error.status_code == 404 {
                return coded("this Telemt has no config API", "telemt_api_unsupported");
            }
            coded("Telemt does not answer", "manager_unavailable")
        })?;
        let upstreams = data.as_object().and_then(|data| data.get("upstreams"));
        match (upstreams, revision) {
            (Some(Value::Array(items)), Value::String(revision)) => {
                Ok((items.iter().filter_map(Value::as_object).cloned().collect(), revision))
            }
            _ => Err(coded("Telemt answered an unexpected config", "manager_unavailable")),
        }
    }

    /// The document Telemt runs, or `None` for upstreams written by hand.
    pub fn document_of(upstreams: &[Map<String, Value>]) -> Option<Value> {
        let live: Vec<&Map<String, Value>> =
            upstreams.iter().filter(|item| item.get("enabled") != Some(&Value::Bool(false))).collect();
        let [upstream] = live.as_slice() else { return None };
        let kind = upstream.get("type").and_then(Value::as_str);
        let scopes = truthy(upstream.get("scopes"));
        if kind == Some("direct")
            && !truthy(upstream.get("interface"))
            && !truthy(upstream.get("bind_addresses"))
            && !scopes
        {
            return Some(telemt_direct_document());
        }
        if kind == Some("socks5") && upstream.get("address") == Some(&json!(MTPROXY_BRIDGE_ADDRESS)) && !scopes {
            return attach_document("mtproxy");
        }
        None
    }

    /// The upstreams' own revision (never the config's: that one moves with every user), without
    /// the password.
    pub fn revision_of(upstreams: &[Map<String, Value>]) -> String {
        let redacted: Vec<Value> = upstreams
            .iter()
            .map(|item| {
                Value::Object(
                    item.iter().filter(|(key, _)| *key != "password").map(|(k, v)| (k.clone(), v.clone())).collect(),
                )
            })
            .collect();
        ids::sha256_hex(canonical(&json!({"upstreams": redacted})))
    }

    async fn router_ingress(&self) -> Option<Value> {
        let ingress = self.router.as_ref()?.ingress("mtproxy").await.ok()?;
        (ingress.get("address") == Some(&json!(MTPROXY_BRIDGE_ADDRESS))).then_some(ingress)
    }

    async fn probe(&self, ingress: &Value) -> bool {
        (self.bridge_probe)(ingress.clone()).await
    }

    pub async fn egress_target(&self) -> Result<Option<EgressTarget>, AdapterError> {
        let (upstreams, _config_revision) = self.config().await?;
        let document = Self::document_of(&upstreams);
        let revision = Self::revision_of(&upstreams);
        let mut providers = Map::new();
        if let Some(ingress) = self.router_ingress().await {
            providers.insert("router".into(), json!({"reachable": self.probe(&ingress).await}));
        }
        let mode = match &document {
            None => EgressMode::Custom,
            Some(document) if truthy(document.get("upstream")) => EgressMode::Proxy,
            Some(_) => EgressMode::Direct,
        };
        let router_attached = document.as_ref().is_some_and(|document| attached_to_router("mtproxy", document));
        Ok(Some(EgressTarget {
            capabilities: ["whole_direct".to_string()].into(),
            providers,
            applied: document.map(|document| AppliedDocument {
                revision: revision.clone(),
                digest: document_digest(&document),
                document,
            }),
            mode,
            router_attached,
            ..EgressTarget::new("mtproxy", Backend::MtproxyNative, revision)
        }))
    }

    fn valid(document: &Value) -> Result<Value, AdapterError> {
        let attach = attach_document("mtproxy").expect("mtproxy attaches");
        if pyrepr::eq(document, &telemt_direct_document()) || pyrepr::eq(document, &attach) {
            return Ok(document.clone());
        }
        Err(coded("Telemt runs direct or through the router, nothing else", "egress_invalid"))
    }

    fn same(current: Option<&Value>, document: &Value) -> bool {
        current.is_some_and(|current| pyrepr::eq(current, document))
    }

    pub async fn plan_egress(
        &self,
        document: &Map<String, Value>,
        expected_revision: &str,
    ) -> Result<Map<String, Value>, AdapterError> {
        let document = Self::valid(&Value::Object(document.clone()))?;
        let (upstreams, _config_revision) = self.config().await?;
        if Self::revision_of(&upstreams) != expected_revision {
            return Err(coded("Telemt's upstreams changed", "egress_conflict"));
        }
        let current = Self::document_of(&upstreams);
        let diff = if Self::same(current.as_ref(), &document) { json!([]) } else { json!(["-current", "+planned"]) };
        Ok(Map::from_iter([
            ("revision".to_string(), json!(expected_revision)),
            ("diff".to_string(), diff),
            ("warnings".to_string(), json!([])),
            ("restart_required".to_string(), json!(false)),
        ]))
    }

    async fn upstreams_for(&self, document: &Value, journal: &Map<String, Value>) -> Result<Value, AdapterError> {
        if document.get("upstream").is_none_or(Value::is_null) {
            return Ok(journal
                .get("direct_upstreams")
                .filter(|value| truthy(Some(value)))
                .cloned()
                .unwrap_or_else(direct_upstreams));
        }
        let Some(router) = &self.router else {
            return Err(coded("this node has no Xray-router", "router_unavailable"));
        };
        let ingress = router.ingress("mtproxy").await?;
        if !self.probe(&ingress).await {
            return Err(coded("the xray-router-ingress bridge does not answer", "ingress_unreachable"));
        }
        let field =
            |key: &str| ingress.get(key).cloned().ok_or_else(|| crash(format!("the router's ingress has no '{key}'")));
        Ok(json!([{"type": "socks5", "address": field("address")?, "username": field("username")?,
                   "password": field("password")?, "weight": 1, "enabled": true}]))
    }

    async fn wait_reload(&self, reload_id: &Value) -> Result<(), AdapterError> {
        let deadline = Instant::now() + self.reload_timeout;
        loop {
            let status = self
                .client
                .reload_status(reload_id)
                .await
                .map_err(|_| coded("Telemt lost the reload", "egress_reload_failed"))?;
            let state = status.as_object().and_then(|status| status.get("state")).cloned().unwrap_or(Value::Null);
            if matches!(state.as_str(), Some("draining" | "succeeded")) {
                return Ok(());
            }
            if matches!(state.as_str(), Some("failed" | "rolled_back")) || Instant::now() >= deadline {
                let state = if truthy(Some(&state)) { py_str(Some(&state)) } else { "unknown".to_string() };
                return Err(coded(
                    &format!("Telemt did not activate the new upstream ({state})"),
                    "egress_reload_failed",
                ));
            }
            tokio::time::sleep(self.reload_poll).await;
        }
    }

    /// PATCH, then the runtime reload, then wait for it. A lost PATCH reply is decided by reading
    /// the upstreams back, never by guessing.
    async fn write(&self, upstreams: &Value, config_revision: &str) -> Result<(), AdapterError> {
        let body = json!({"upstreams": upstreams});
        let revision = match self.client.patch_config(&body, config_revision).await {
            Ok((_data, revision)) => revision,
            Err(error) if error.indeterminate => {
                let (current, revision) = self.config().await?;
                let wanted: Vec<Map<String, Value>> =
                    upstreams.as_array().into_iter().flatten().filter_map(Value::as_object).cloned().collect();
                if Self::revision_of(&current) != Self::revision_of(&wanted) {
                    return Err(coded("Telemt lost the upstream change", "manager_unavailable"));
                }
                json!(revision)
            }
            Err(error) if matches!(error.status_code, 409 | 412) => {
                return Err(coded("Telemt's config changed meanwhile", "egress_conflict"));
            }
            Err(error) => {
                let code =
                    if matches!(error.status_code, 400 | 422) { "egress_invalid" } else { "manager_unavailable" };
                return Err(coded("Telemt refused the upstream", code));
            }
        };
        let accepted = self
            .client
            .reload(&revision)
            .await
            .map_err(|_| coded("Telemt refused the reload", "egress_reload_failed"))?;
        let reload_id =
            accepted.as_object().and_then(|accepted| accepted.get("reload_id")).cloned().unwrap_or(Value::Null);
        self.wait_reload(&reload_id).await
    }

    async fn apply(
        &self,
        document: Value,
        expected_revision: &str,
        operation_id: &str,
        rollback: bool,
    ) -> Result<AppliedEgress, AdapterError> {
        let _guard = self.lock.lock().await;
        let mut journal = self.journal_read()?;
        let (mut upstreams, config_revision) = self.config().await?;
        let current = Self::document_of(&upstreams);
        let revision = Self::revision_of(&upstreams);
        let entry = match journal.get("current") {
            Some(Value::Object(entry)) => entry.clone(),
            Some(value) if truthy(Some(value)) => return Err(crash("the Telemt egress journal has a strange entry")),
            _ => Map::new(),
        };
        if !rollback
            && entry.get("operation_id") == Some(&json!(operation_id))
            && Self::same(current.as_ref(), &document)
            && entry.get("document").is_some_and(|recorded| pyrepr::eq(recorded, &document))
        {
            return Ok(AppliedEgress {
                digest: Some(document_digest(&document)),
                readback_sha256: Some(revision.clone()),
                replayed: true,
                revision,
            });
        }
        if revision != expected_revision {
            return Err(coded("Telemt's upstreams changed", "egress_conflict"));
        }
        let Some(current) = current else {
            return Err(coded(
                "Telemt carries upstreams written by hand: set them back to direct first",
                "manual_intervention_required",
            ));
        };
        if !pyrepr::eq(&current, &document) {
            let upstream_of = |document: &Value| document.get("upstream").cloned().unwrap_or(Value::Null);
            if upstream_of(&current).is_null() && !upstream_of(&document).is_null() {
                // What «direct» goes back to (no secrets in it).
                journal.insert(
                    "direct_upstreams".into(),
                    Value::Array(upstreams.iter().cloned().map(Value::Object).collect()),
                );
            }
            let target = self.upstreams_for(&document, &journal).await?;
            if let Err(error) = self.write(&target, &config_revision).await {
                // Telemt's runtime stays on the old generation; its file goes back with it.
                if let Ok((_now, now_revision)) = self.config().await {
                    let old = json!({"upstreams": upstreams.iter().cloned().map(Value::Object).collect::<Vec<_>>()});
                    let _ = self.client.patch_config(&old, &now_revision).await;
                }
                return Err(error);
            }
            upstreams = self.config().await?.0;
            if !Self::same(Self::document_of(&upstreams).as_ref(), &document) {
                return Err(coded("Telemt reads back another upstream", "egress_readback_mismatch"));
            }
        }
        let revision = Self::revision_of(&upstreams);
        let record = json!({"document": document, "operation_id": operation_id, "revision": revision});
        if rollback {
            journal.insert("current".into(), record);
            journal.insert("previous".into(), Value::Null);
        } else {
            let previous = journal.get("current").cloned().unwrap_or(Value::Null);
            journal.insert("previous".into(), previous);
            journal.insert("current".into(), record);
        }
        self.journal_write(journal)?;
        Ok(AppliedEgress {
            digest: Some(document_digest(&document)),
            readback_sha256: Some(revision.clone()),
            replayed: false,
            revision,
        })
    }

    pub async fn apply_egress(
        &self,
        document: &Map<String, Value>,
        expected_revision: &str,
        operation_id: &str,
    ) -> Result<AppliedEgress, AdapterError> {
        let document = Self::valid(&Value::Object(document.clone()))?;
        self.apply(document, expected_revision, operation_id, false).await
    }

    pub async fn rollback_egress(&self, expected_revision: &str) -> Result<AppliedEgress, AdapterError> {
        let journal = self.journal_read()?;
        let previous = match journal.get("previous") {
            Some(Value::Object(previous)) if previous.get("document").is_some_and(Value::is_object) => previous.clone(),
            Some(value) if truthy(Some(value)) && !value.is_object() => {
                return Err(crash("the Telemt egress journal has a strange entry"));
            }
            _ => return Err(coded("no previous Telemt upstream to roll back to", "egress_no_previous")),
        };
        let document = Self::valid(&previous["document"])?;
        let operation_id = format!("rollback:{}", py_str(previous.get("operation_id")));
        self.apply(document, expected_revision, &operation_id, true).await
    }
}

crate::protocol_adapter! {
    impl<C: TelemtApi, R: RouterApi> for TelemtAdapter<C, R>;
    protocol: Protocol::Mtproxy,
    origin: CredentialOrigin::Manager,
    capture: true,
    accepts_caller: true,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_probe_of_an_unusable_ingress_answers_false_without_dialing() {
        let timeout = Duration::from_millis(10);
        for ingress in [
            json!({}),
            json!({"address": "h:x", "username": "u", "password": "p"}),
            json!({"address": ":1", "username": "u", "password": "p"}),
            json!({"address": "h:1", "username": "", "password": "p"}),
            json!({"address": "h:1", "username": "u".repeat(256), "password": "p"}),
            json!({"address": "h:99999", "username": "u", "password": "p"}),
        ] {
            assert!(!probe_bridge(&ingress, timeout), "{ingress}");
        }
    }

    #[test]
    fn a_probe_speaks_the_socks5_login() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            stream.write_all(b"\x05\x02").unwrap();
            let mut login = [0u8; 2 + 6 + 1 + 6];
            stream.read_exact(&mut login).unwrap();
            stream.write_all(b"\x01\x00").unwrap();
            (greeting, login)
        });
        let ingress = json!({"address": address.to_string(), "username": "telemt", "password": "secret"});
        assert!(probe_bridge(&ingress, Duration::from_secs(2)));
        let (greeting, login) = server.join().unwrap();
        assert_eq!(&greeting, b"\x05\x01\x02");
        assert_eq!(&login, b"\x01\x06telemt\x06secret");
    }
}
