//! One contract for unlike data planes, with their differences stated, not hidden
//! (`protocols/base.py`).
//!
//! Telemt generates the credential itself and has no operation id, Naive and Mieru accept a
//! caller-supplied one, and only some can hand a live credential back without rotating it. The
//! adapter surface names each of those facts ([`ProtocolAdapter::credential_origin`],
//! [`ProtocolAdapter::capture_supported`]) instead of pretending they behave alike.

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use serde_json::{json, Map, Value};

use crate::clients::{AccessGrant, GrantIntent};
use crate::common::{wire_enum, Backend, Protocol};
use crate::fleet::CredentialOrigin;
use crate::pyrepr;
use crate::routing::document::{attached_to_router, document_digest, EGRESS_REASON_CODES};

/// A boxed future, so adapters can live behind `dyn ProtocolAdapter` (one per protocol in a map).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What an egress operation may fail with: the managers' codes ([`EGRESS_REASON_CODES`]) plus
/// the ones only the panel can know (sorted).
pub const EGRESS_ERROR_CODES: &[&str] = &[
    "artifact_mismatch",
    "egress_conflict",
    "egress_invalid",
    "egress_no_previous",
    "egress_readback_mismatch",
    "egress_unreachable",
    "egress_unsupported",
    "geoip_unknown",
    "geosite_unknown",
    "lane_slots_exhausted",
    "lane_unknown",
    "lanes_invalid",
    "manager_unavailable",
    "manual_intervention_required",
    "not_attached",
    "relay_disabled",
    "router_unavailable",
    "router_unreachable",
];

/// A refused or failed protocol operation (`AdapterError`, and its subclass
/// `ManualInterventionRequired` when [`AdapterError::manual_intervention`] is set). Messages never
/// carry a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterError {
    pub message: String,
    /// The runtime answered "no such user" to a delete: the outcome the caller wanted holds.
    pub already_gone: bool,
    /// The bounded reason of an egress failure ([`EGRESS_ERROR_CODES`]); `None` for grant
    /// operations.
    pub code: Option<String>,
    /// `ManualInterventionRequired`: the runtime changed but the credential is unrecoverable; a
    /// human must decide.
    pub manual_intervention: bool,
}

impl AdapterError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), already_gone: false, code: None, manual_intervention: false }
    }

    /// A delete whose user was already missing.
    pub fn already_gone(message: impl Into<String>) -> Self {
        Self { already_gone: true, ..Self::new(message) }
    }

    /// An egress failure with its code.
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self { code: Some(code.into()), ..Self::new(message) }
    }

    /// `ManualInterventionRequired(message, code=…)`.
    pub fn manual_intervention(message: impl Into<String>, code: Option<String>) -> Self {
        Self { code, manual_intervention: true, ..Self::new(message) }
    }

    /// `isinstance(error, ManualInterventionRequired)`.
    pub fn is_manual_intervention(&self) -> bool {
        self.manual_intervention
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AdapterError {}

/// One account a runtime already has.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedGrant {
    pub runtime_username: String,
    pub enabled: bool,
    pub options: Map<String, Value>,
    pub revision: Option<String>,
}

/// Everything a runtime has.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ObservedInventory {
    pub items: Vec<ObservedGrant>,
}

/// Whether an intent can be applied, and why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preflight {
    pub ok: bool,
    pub reason: Option<String>,
}

/// Who chooses the credential; `caller` carries the plaintext it chose.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialPlan {
    origin: CredentialOrigin,
    plaintext: Option<Vec<u8>>,
}

impl fmt::Debug for CredentialPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialPlan").field("origin", &self.origin).finish_non_exhaustive()
    }
}

impl CredentialPlan {
    /// `CredentialPlan(origin, plaintext)` with its checks: a caller's plan needs a non-empty
    /// plaintext, a manager's plan cannot carry one.
    pub fn new(origin: CredentialOrigin, plaintext: Option<Vec<u8>>) -> Result<Self, AdapterError> {
        let has = plaintext.as_ref().is_some_and(|bytes| !bytes.is_empty());
        match origin {
            CredentialOrigin::Caller if !has => {
                Err(AdapterError::new("a caller-supplied credential needs its plaintext"))
            }
            CredentialOrigin::Manager if has => {
                Err(AdapterError::new("a manager-generated credential cannot be supplied"))
            }
            _ => Ok(Self { origin, plaintext }),
        }
    }

    /// The caller chose `plaintext`.
    pub fn caller(plaintext: Vec<u8>) -> Result<Self, AdapterError> {
        Self::new(CredentialOrigin::Caller, Some(plaintext))
    }

    /// The manager generates the credential.
    pub fn manager() -> Self {
        Self { origin: CredentialOrigin::Manager, plaintext: None }
    }

    pub fn origin(&self) -> CredentialOrigin {
        self.origin
    }

    pub fn plaintext(&self) -> Option<&[u8]> {
        self.plaintext.as_deref()
    }
}

/// A grant as the runtime knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRef {
    pub protocol: Protocol,
    pub runtime_username: String,
    pub revision: Option<String>,
}

/// What an operation left on the runtime.
#[derive(Clone, PartialEq)]
pub struct AppliedGrant {
    pub runtime_username: String,
    pub enabled: bool,
    pub credential: Option<Vec<u8>>,
    pub revision: Option<String>,
    pub artifact_template: Map<String, Value>,
    /// The reply was lost and the outcome had to be read back or replayed.
    pub recovered: bool,
    /// Who ended up choosing the credential applied (a runtime may refuse a caller's and generate
    /// its own).
    pub credential_origin: CredentialOrigin,
}

impl AppliedGrant {
    /// An applied grant with the defaults (no credential, no template, caller's credential).
    pub fn new(runtime_username: impl Into<String>, enabled: bool) -> Self {
        Self {
            runtime_username: runtime_username.into(),
            enabled,
            credential: None,
            revision: None,
            artifact_template: Map::new(),
            recovered: false,
            credential_origin: CredentialOrigin::Caller,
        }
    }
}

impl fmt::Debug for AppliedGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppliedGrant")
            .field("runtime_username", &self.runtime_username)
            .field("enabled", &self.enabled)
            .field("credential", &self.credential.as_ref().map(|_| "<redacted>"))
            .field("revision", &self.revision)
            .field("artifact_template", &self.artifact_template)
            .field("recovered", &self.recovered)
            .field("credential_origin", &self.credential_origin)
            .finish()
    }
}

wire_enum! {
    /// How a native backend's egress runs now.
    pub enum EgressMode {
        Direct => "direct",
        Proxy => "proxy",
        Custom => "custom",
    }
}

/// The managed document a runtime runs: `{"revision", "digest", "document"}`.
#[derive(Debug, Clone, PartialEq)]
pub struct AppliedDocument {
    pub revision: String,
    pub digest: String,
    pub document: Value,
}

impl AppliedDocument {
    fn from_view(revision: &str, document: &Value) -> Self {
        Self { revision: revision.to_string(), digest: document_digest(document), document: document.clone() }
    }

    /// The dict the Python panel carries.
    pub fn to_value(&self) -> Value {
        json!({"revision": self.revision, "digest": self.digest, "document": self.document})
    }
}

/// What a backend's egress looks like right now, as the compiler needs it. `providers` names
/// what this host can route through and whether the manager found it reachable — never the
/// endpoint. `applied` is the managed document the runtime runs, or `None` when the runtime
/// carries an upstream somebody wrote by hand (`mode` `custom`).
#[derive(Debug, Clone, PartialEq)]
pub struct EgressTarget {
    pub protocol: String,
    pub backend: Backend,
    pub capabilities: BTreeSet<String>,
    /// `name → {"reachable": <the manager's value>}`.
    pub providers: Map<String, Value>,
    pub revision: String,
    pub applied: Option<AppliedDocument>,
    pub mode: EgressMode,
    pub restart_required: bool,
    pub warnings: Vec<String>,
    pub runtime_version: Option<String>,
    /// The applied native document hands the whole service to the node's Xray-router.
    pub router_attached: bool,
}

impl EgressTarget {
    /// A target with the dataclass defaults (`direct`, nothing applied, no warnings).
    pub fn new(protocol: impl Into<String>, backend: Backend, revision: impl Into<String>) -> Self {
        Self {
            protocol: protocol.into(),
            backend,
            capabilities: BTreeSet::new(),
            providers: Map::new(),
            revision: revision.into(),
            applied: None,
            mode: EgressMode::Direct,
            restart_required: false,
            warnings: Vec::new(),
            runtime_version: None,
            router_attached: false,
        }
    }
}

/// One service's section on the node's Xray-router: its capability cells, the WARP provider as
/// the router sees it, the section's revision and applied intent. `available: false` carries the
/// reason (`router_unavailable`, `artifact_mismatch`, `manual_intervention_required`).
#[derive(Debug, Clone, PartialEq)]
pub struct RouterTarget {
    pub available: bool,
    pub service: String,
    pub capabilities: BTreeSet<String>,
    pub providers: Map<String, Value>,
    pub revision: String,
    pub applied: Option<AppliedDocument>,
    pub xray_version: Option<String>,
    pub restart_required: bool,
    pub reason: Option<String>,
}

impl RouterTarget {
    /// The router cannot serve this service.
    pub fn unavailable(service: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            available: false,
            service: service.into(),
            capabilities: BTreeSet::new(),
            providers: Map::new(),
            revision: String::new(),
            applied: None,
            xray_version: None,
            restart_required: true,
            reason: Some(reason.into()),
        }
    }
}

/// The manager's answer to an apply or a rollback: the revision the runtime is at now and the
/// digest of the document it runs (`None` after a rollback to a hand-written section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedEgress {
    pub revision: String,
    pub digest: Option<String>,
    pub readback_sha256: Option<String>,
    pub replayed: bool,
}

/// `str(view.get(key) or "")`.
fn revision_of(view: &Map<String, Value>) -> String {
    match view.get("revision") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) if number.as_f64() == Some(0.0) => String::new(),
        Some(Value::Array(items)) if items.is_empty() => String::new(),
        Some(Value::Object(map)) if map.is_empty() => String::new(),
        Some(other) => pyrepr::str(other),
    }
}

fn strings(value: Option<&Value>) -> impl Iterator<Item = String> + '_ {
    value.and_then(Value::as_array).into_iter().flatten().filter_map(|item| item.as_str().map(str::to_string))
}

fn providers(view: &Map<String, Value>) -> Map<String, Value> {
    view.get("providers")
        .and_then(Value::as_object)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|(name, entry)| {
                    let entry = entry.as_object()?;
                    Some((name.clone(), json!({"reachable": entry.get("reachable").cloned().unwrap_or(Value::Null)})))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Both managers answer `GET /v1/egress` in the same vocabulary; only the document shapes
/// differ, and those pass through untouched.
pub fn egress_target_from_view(protocol: &str, backend: Backend, view: &Map<String, Value>) -> EgressTarget {
    let revision = revision_of(view);
    let document = view.get("document").filter(|document| !document.is_null());
    let mode = match view.get("mode").and_then(Value::as_str) {
        Some("direct") => EgressMode::Direct,
        Some("proxy") => EgressMode::Proxy,
        _ => EgressMode::Custom,
    };
    EgressTarget {
        protocol: protocol.to_string(),
        backend,
        capabilities: strings(view.get("capabilities")).collect(),
        providers: providers(view),
        applied: document.map(|document| AppliedDocument::from_view(&revision, document)),
        mode,
        restart_required: view.get("restart_required") == Some(&Value::Bool(true)),
        warnings: strings(view.get("warnings")).collect(),
        runtime_version: None,
        router_attached: document.is_some_and(|document| attached_to_router(protocol, document)),
        revision,
    }
}

/// The router manager's `GET /v1/egress/{service}` as the compiler's target.
pub fn router_target_from_view(service: &str, view: &Map<String, Value>) -> RouterTarget {
    let revision = revision_of(view);
    let document = view.get("document").filter(|document| !document.is_null());
    RouterTarget {
        available: true,
        service: service.to_string(),
        capabilities: strings(view.get("capabilities")).collect(),
        providers: providers(view),
        applied: document.map(|document| AppliedDocument::from_view(&revision, document)),
        xray_version: view.get("runtime_version").and_then(Value::as_str).map(str::to_string),
        restart_required: view.get("restart_required") != Some(&Value::Bool(false)),
        reason: None,
        revision,
    }
}

/// A manager's answer to an apply or rollback.
pub fn applied_egress_from_view(view: &Map<String, Value>) -> AppliedEgress {
    AppliedEgress {
        revision: revision_of(view),
        digest: view.get("applied").filter(|document| !document.is_null()).map(document_digest),
        readback_sha256: view.get("readback_sha256").and_then(Value::as_str).map(str::to_string),
        replayed: view.get("replayed") == Some(&Value::Bool(true)),
    }
}

/// A manager's egress refusal as the typed error the routing service acts on: a known code is
/// kept, anything else becomes `egress_conflict` (409), `egress_invalid` (422) or
/// `manager_unavailable`.
pub fn egress_error(runtime: &str, status: u16, code: Option<&str>) -> AdapterError {
    let code = match code {
        Some(code) if EGRESS_REASON_CODES.contains(&code) => code,
        _ => match status {
            409 => "egress_conflict",
            422 => "egress_invalid",
            _ => "manager_unavailable",
        },
    };
    if code == "manual_intervention_required" {
        return AdapterError::manual_intervention(
            format!("{runtime} egress needs recovery by hand"),
            Some(code.into()),
        );
    }
    AdapterError::with_code(format!("{runtime} refused the egress change"), code)
}

wire_enum! {
    /// Whether the panel can re-render an artifact from a stored credential without the manager
    /// (`unsupported`: the operator must rotate to get it again).
    pub enum AutoRefresh {
        Supported => "supported",
        Unsupported => "unsupported",
    }
}

/// One thing a client gets for an access: a link, a config, a QR code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessArtifact {
    pub kind: String,
    pub label: String,
    pub media_type: String,
    pub value: String,
    pub auto_refresh: AutoRefresh,
}

/// The adapter contract over one data plane (`ProtocolAdapter`). Asynchronous methods return a
/// [`BoxFuture`] so adapters can be stored as `Arc<dyn ProtocolAdapter>`.
pub trait ProtocolAdapter: Send + Sync {
    /// The data plane this adapter drives.
    fn protocol(&self) -> Protocol;
    /// Who chooses a new credential by default.
    fn credential_origin(&self) -> CredentialOrigin;
    /// Whether a live credential can be read back without rotating it.
    fn capture_supported(&self) -> bool;
    /// Whether `create`/`rotate` can accept a caller-chosen credential at all.
    fn accepts_caller_credential(&self) -> bool;

    fn discover(&self) -> BoxFuture<'_, Result<ObservedInventory, AdapterError>>;
    fn preflight<'a>(&'a self, intent: &'a GrantIntent) -> BoxFuture<'a, Result<Preflight, AdapterError>>;
    fn create<'a>(
        &'a self,
        operation_id: &'a str,
        intent: &'a GrantIntent,
        credential: &'a CredentialPlan,
    ) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>>;
    fn enable<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>>;
    fn disable<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>>;
    fn rotate<'a>(
        &'a self,
        operation_id: &'a str,
        grant: &'a GrantRef,
        credential: &'a CredentialPlan,
    ) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>>;
    fn delete<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<(), AdapterError>>;
    /// The live credential, or `None` when the runtime cannot hand it back.
    fn capture<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<Option<Vec<u8>>, AdapterError>>;
    fn update_options<'a>(
        &'a self,
        grant: &'a GrantRef,
        options: &'a Map<String, Value>,
    ) -> BoxFuture<'a, Result<Option<AppliedGrant>, AdapterError>>;
    /// The links/configs a client gets, rebuilt from the stored credential.
    fn render_artifacts(
        &self,
        grant: &AccessGrant,
        credential: &[u8],
        public_host: &str,
    ) -> Result<Vec<AccessArtifact>, AdapterError>;

    /// The egress target; `None` for a data plane without egress.
    fn egress_target(&self) -> BoxFuture<'_, Result<Option<EgressTarget>, AdapterError>>;
    fn plan_egress<'a>(
        &'a self,
        document: &'a Map<String, Value>,
        expected_revision: &'a str,
    ) -> BoxFuture<'a, Result<Map<String, Value>, AdapterError>>;
    fn apply_egress<'a>(
        &'a self,
        document: &'a Map<String, Value>,
        expected_revision: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>>;
    fn rollback_egress<'a>(&'a self, expected_revision: &'a str) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_plans_check_who_supplies_the_plaintext() {
        assert!(CredentialPlan::new(CredentialOrigin::Caller, None).is_err());
        assert!(CredentialPlan::new(CredentialOrigin::Caller, Some(Vec::new())).is_err());
        assert!(CredentialPlan::new(CredentialOrigin::Manager, Some(b"x".to_vec())).is_err());
        assert_eq!(CredentialPlan::caller(b"pw".to_vec()).unwrap().plaintext(), Some(&b"pw"[..]));
        assert_eq!(CredentialPlan::manager().origin(), CredentialOrigin::Manager);
        assert!(!format!("{:?}", CredentialPlan::caller(b"secret".to_vec()).unwrap()).contains("secret"));
    }
}
