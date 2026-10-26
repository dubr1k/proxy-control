//! The fleet v2 wire contract (`fleet_v2/protocol.py`, spec §4–5): typed, bounded, secret-free
//! documents a central panel pushes to its linked nodes, and what the nodes report back.
//!
//! What a node validates before acting on it ([`GenerationDocument`], [`PushRequest`] and their
//! parts) refuses unknown fields (a 422 on the node); what a node reports ([`ObservedGeneration`],
//! [`PushResponse`] and their parts) drops them, because nodes are upgraded before their central.
//!
//! Optional sections travel only to nodes that declared the capability and are left out of the
//! wire form when absent ([`GenerationDocument::wire`]), so mixed-version panels agree on every
//! digest ([`GenerationDocument::canonical_digest`]).

use indexmap::IndexMap;
use panel_core::errors::LocItem;
use panel_core::{ids, pyjson};
use serde_json::{json, Map, Value};

use crate::clients::{is_username, USERNAME_PATTERN};
use crate::common::{literal_enum, wire_enum, Backend, Protocol, BACKENDS};
use crate::pyrepr;
use crate::routing::document::{canonical_map, document_digest_map};
use crate::validate::{
    boolean, dict, dict_of, list, literal, literal_int, literal_key, nullable, str_key, string, value_error, Cx, Extra,
    Fields, Int, Model, Str,
};

/// A push (document and secrets) is at most this large.
pub const MAX_PUSH_BYTES: usize = 65536;
/// A compiled egress document per protocol (spec §5 limits).
pub const MAX_EGRESS_BYTES: usize = 16384;
pub const MAX_RESOURCES: usize = 500;
/// A node reads back at most this many credentials per `POST credentials/capture`.
pub const CAPTURE_MAX_RESOURCES: usize = 200;
pub const SCHEMA_VERSION: i64 = 1;

/// The capability strings a node advertises (`fleet_v2/node_routes.py`), in its order: the base
/// set, then `metrics.v1` with metrics on, then the router's four with an Xray-router.
pub const BASE_CAPABILITIES: &[&str] = &[
    "generation.v1",
    "credentials.capture",
    "versions.update",
    "versions.check",
    "unlink",
    "egress.v1",
    "egress.mtproxy.v1",
    "protocol.amneziawg.v1",
    "protocol.trusttunnel.v1",
    "egress.trusttunnel.v1",
    "egress.amneziawg.v1",
];
pub const METRICS_CAPABILITY: &str = "metrics.v1";
pub const ROUTER_CAPABILITIES: &[&str] = &["egress.router.v1", "egress.lanes.v1", "relay.v1", "geodata.v1"];

wire_enum! {
    /// Why a node refuses a generation (409 `code`).
    pub enum ConflictCode {
        GuidMismatch => "guid_mismatch",
        ForeignMaster => "foreign_master",
        StaleGeneration => "stale_generation",
        DigestConflict => "digest_conflict",
        DigestInvalid => "digest_invalid",
    }
}

/// `CONFLICT_CODES`.
pub const CONFLICT_CODES: &[&str] =
    &["guid_mismatch", "foreign_master", "stale_generation", "digest_conflict", "digest_invalid"];

/// `GenerationConflict`: a node's refusal of a generation; the message defaults to the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationConflict {
    pub code: ConflictCode,
    pub message: String,
}

impl GenerationConflict {
    pub fn new(code: ConflictCode, message: impl Into<String>) -> Self {
        let message = message.into();
        let message = if message.is_empty() { code.as_str().to_string() } else { message };
        Self { code, message }
    }
}

impl std::fmt::Display for GenerationConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for GenerationConflict {}

wire_enum! {
    /// What the central wants a resource to be on the node.
    pub enum DesiredState {
        Enabled => "enabled",
        Disabled => "disabled",
        Deleted => "deleted",
    }
}

wire_enum! {
    /// Who chooses a credential.
    pub enum CredentialOrigin {
        Caller => "caller",
        Manager => "manager",
    }
}

wire_enum! {
    /// `provisioned` never adopts a runtime user; `imported` claims one already running.
    pub enum ResourceOrigin {
        Provisioned => "provisioned",
        Imported => "imported",
    }
}

/// The protocols of a resource, in `Resource.protocol`'s order.
const RESOURCE_PROTOCOLS: &[&str] = &["mtproxy", "naive", "mieru", "amneziawg", "trusttunnel"];
/// The protocols of an egress section, in `GenerationDocument.egress`'s order.
const EGRESS_PROTOCOLS: &[&str] = &["naive", "mieru", "mtproxy", "trusttunnel", "amneziawg"];

/// One account the node must run.
#[derive(Debug, Clone, PartialEq)]
pub struct Resource {
    /// `ref` on the wire.
    pub reference: String,
    pub protocol: Protocol,
    pub runtime_username: String,
    pub desired_state: DesiredState,
    /// `"<secret_id>:<version>"`; the plaintext travels in the push's `secrets`.
    pub credential_ref: String,
    pub credential_origin: CredentialOrigin,
    pub origin: ResourceOrigin,
    pub options: Map<String, Value>,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
    /// The client's own lane (`"own"`): absent from the wire when `false`.
    pub own_lane: bool,
}

fn optional_int(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Option<i64>> {
    nullable(input, loc, cx, |v, l, cx| Int::LAX.validate(v, l, cx))
}

fn optional_string(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Option<String>> {
    nullable(input, loc, cx, string)
}

impl Model for Resource {
    const TITLE: &'static str = "Resource";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let reference = f.required(cx, "ref", |v, l, cx| Str::len(1, 128).validate(v, l, cx));
        let protocol = f.required(cx, "protocol", |v, l, cx| literal_enum(v, l, cx, RESOURCE_PROTOCOLS));
        let runtime_username = f.required(cx, "runtime_username", |v, l, cx| USERNAME_PATTERN.validate(v, l, cx));
        let desired_state =
            f.required(cx, "desired_state", |v, l, cx| literal_enum(v, l, cx, &["enabled", "disabled", "deleted"]));
        let credential_ref = f.required(cx, "credential_ref", |v, l, cx| Str::len(1, 160).validate(v, l, cx));
        let credential_origin =
            f.required(cx, "credential_origin", |v, l, cx| literal_enum(v, l, cx, &["caller", "manager"]));
        let origin = f.optional(
            cx,
            "origin",
            || ResourceOrigin::Provisioned,
            |v, l, cx| literal_enum(v, l, cx, &["provisioned", "imported"]),
        );
        let options = f.optional(cx, "options", Map::new, dict);
        let valid_from = f.optional(cx, "valid_from", || None, optional_int);
        let valid_until = f.optional(cx, "valid_until", || None, optional_int);
        let lane =
            f.optional(cx, "lane", || None, |v, l, cx| nullable(v, l, cx, |v, l, cx| literal(v, l, cx, &["own"])));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(Resource {
            reference: reference?,
            protocol: protocol?,
            runtime_username: runtime_username?,
            desired_state: desired_state?,
            credential_ref: credential_ref?,
            credential_origin: credential_origin?,
            origin: origin?,
            options: options?,
            valid_from: valid_from?,
            valid_until: valid_until?,
            own_lane: lane?.is_some(),
        })
    }

    fn dump(&self) -> Value {
        json!({
            "ref": self.reference,
            "protocol": self.protocol.as_str(),
            "runtime_username": self.runtime_username,
            "desired_state": self.desired_state.as_str(),
            "credential_ref": self.credential_ref,
            "credential_origin": self.credential_origin.as_str(),
            "origin": self.origin.as_str(),
            "options": self.options,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "lane": if self.own_lane { json!("own") } else { Value::Null },
        })
    }
}

/// `^relay:[A-Za-z0-9-]{1,64}:(direct|warp)$`.
pub fn is_relay_email(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("relay:") else {
        return false;
    };
    let Some((source, exit)) = rest.split_once(':') else {
        return false;
    };
    (1..=64).contains(&source.len())
        && source.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && (exit == "direct" || exit == "warp")
}

/// One account of the node's relay inbound: the source node and its exit in the email
/// (`relay:<source guid>:<direct|warp>`), the UUID in the push's secrets by this ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAccount {
    pub email: String,
    pub credential_ref: String,
}

impl Model for RelayAccount {
    const TITLE: &'static str = "RelayAccount";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let email = f.required(cx, "email", |v, l, cx| {
            Str::pattern("^relay:[A-Za-z0-9-]{1,64}:(direct|warp)$", is_relay_email).validate(v, l, cx)
        });
        let credential_ref = f.required(cx, "credential_ref", |v, l, cx| Str::len(3, 160).validate(v, l, cx));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(RelayAccount { email: email?, credential_ref: credential_ref? })
    }

    fn dump(&self) -> Value {
        json!({"email": self.email, "credential_ref": self.credential_ref})
    }
}

/// The node's relay inbound: vless+reality on `port` with the node's own panel name as the cover,
/// and the accounts other nodes dial it with. `enabled: false` takes the inbound down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySection {
    pub enabled: bool,
    pub port: i64,
    pub server_name: String,
    pub accounts: Vec<RelayAccount>,
}

impl Model for RelaySection {
    const TITLE: &'static str = "RelaySection";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let enabled = f.required(cx, "enabled", boolean);
        let port = f.required(cx, "port", |v, l, cx| Int::lax(Some(1), Some(65535)).validate(v, l, cx));
        let server_name = f.required(cx, "server_name", |v, l, cx| Str::len(1, 253).validate(v, l, cx));
        let accounts =
            f.optional(cx, "accounts", Vec::new, |v, l, cx| list(v, l, cx, Some(64), RelayAccount::validate_at));
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        Some(RelaySection { enabled: enabled?, port: port?, server_name: server_name?, accounts: accounts? })
    }

    fn dump(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "port": self.port,
            "server_name": self.server_name,
            "accounts": self.accounts.iter().map(Model::dump).collect::<Vec<_>>(),
        })
    }
}

/// What one protocol's egress should be on the node: the compiled document the manager
/// validates, named by the policy revision it came from. With the node's Xray-router, `backend`
/// says which manager `document` is for and `companion` is what the other one gets afterwards.
#[derive(Debug, Clone, PartialEq)]
pub struct EgressDocument {
    pub backend: Backend,
    pub policy_id: String,
    pub policy_revision: i64,
    pub document: Map<String, Value>,
    /// `sha256(canonical(document))`.
    pub digest: String,
    pub companion: Option<Map<String, Value>>,
    /// An attach/detach generation: the backend runs its pass-through. Off the wire when `false`.
    pub passthrough: bool,
}

/// `^[0-9a-f]{64}$`.
pub fn is_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl EgressDocument {
    /// `digest_names_the_document`.
    pub fn check(&self) -> Result<(), &'static str> {
        if canonical_map(&self.document).len() > MAX_EGRESS_BYTES {
            return Err("egress document too large");
        }
        if document_digest_map(&self.document) != self.digest {
            return Err("egress digest does not match the document");
        }
        if self.companion.as_ref().is_some_and(|companion| canonical_map(companion).len() > MAX_EGRESS_BYTES) {
            return Err("egress companion document too large");
        }
        Ok(())
    }

    /// The section's wire form: `companion` and `passthrough` only when set.
    pub fn wire(&self) -> Value {
        let mut value = self.dump();
        let map = value.as_object_mut().expect("an object");
        if self.companion.is_none() {
            map.shift_remove("companion");
        }
        if !self.passthrough {
            map.shift_remove("passthrough");
        }
        value
    }
}

impl Model for EgressDocument {
    const TITLE: &'static str = "EgressDocument";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let backend = f.required(cx, "backend", |v, l, cx| literal_enum(v, l, cx, BACKENDS));
        let policy_id = f.required(cx, "policy_id", |v, l, cx| Str::len(1, 64).validate(v, l, cx));
        let policy_revision = f.required(cx, "policy_revision", |v, l, cx| Int::lax(Some(1), None).validate(v, l, cx));
        let document = f.required(cx, "document", dict);
        let digest = f.required(cx, "digest", |v, l, cx| Str::pattern("^[0-9a-f]{64}$", is_digest).validate(v, l, cx));
        let companion = f.optional(cx, "companion", || None, |v, l, cx| nullable(v, l, cx, dict));
        let passthrough = f.optional(cx, "passthrough", || false, boolean);
        let whole = f.input();
        let at_root = f.loc().to_vec();
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        let section = EgressDocument {
            backend: backend?,
            policy_id: policy_id?,
            policy_revision: policy_revision?,
            document: document?,
            digest: digest?,
            companion: companion?,
            passthrough: passthrough?,
        };
        if let Err(message) = section.check() {
            cx.push(value_error(at_root, whole, message));
            return None;
        }
        Some(section)
    }

    fn dump(&self) -> Value {
        json!({
            "backend": self.backend.as_str(),
            "policy_id": self.policy_id,
            "policy_revision": self.policy_revision,
            "document": self.document,
            "digest": self.digest,
            "companion": self.companion,
            "passthrough": self.passthrough,
        })
    }
}

/// One numbered generation of what a node must run.
#[derive(Debug, Clone, PartialEq)]
pub struct GenerationDocument {
    /// Always [`SCHEMA_VERSION`].
    pub schema_version: i64,
    pub node_guid: String,
    pub master_guid: String,
    pub generation: i64,
    pub previous_generation: i64,
    pub created_at: i64,
    pub created_by: String,
    pub resources: Vec<Resource>,
    /// Egress per protocol (`egress.v1` and the per-protocol capabilities); `None` = leave the
    /// node's egress as it is, and off the wire and the digest.
    pub egress: Option<IndexMap<Protocol, EgressDocument>>,
    /// The node's relay (`relay.v1`); `None` = leave it as it is, and off the wire and the digest.
    pub relay: Option<RelaySection>,
}

impl GenerationDocument {
    /// `resources_do_not_collide_on_the_same_runtime_user`.
    pub fn check(&self) -> Result<(), String> {
        let mut seen: Vec<(Protocol, &str)> = Vec::with_capacity(self.resources.len());
        for resource in &self.resources {
            let key = (resource.protocol, resource.runtime_username.as_str());
            if seen.contains(&key) {
                return Err(format!("duplicate resource for {}/{}", resource.protocol, resource.runtime_username));
            }
            seen.push(key);
        }
        Ok(())
    }

    /// `wire()`: `model_dump()` minus the keys that hold their default — `egress` and `relay` when
    /// `None`, an egress section's `companion` when `None` and `passthrough` when `false`, a
    /// resource's `lane` when `None`. Other defaults (`origin`, `options`, `valid_from: null`) stay.
    pub fn wire(&self) -> Value {
        let mut map = Map::new();
        map.insert("schema_version".into(), json!(self.schema_version));
        map.insert("node_guid".into(), json!(self.node_guid));
        map.insert("master_guid".into(), json!(self.master_guid));
        map.insert("generation".into(), json!(self.generation));
        map.insert("previous_generation".into(), json!(self.previous_generation));
        map.insert("created_at".into(), json!(self.created_at));
        map.insert("created_by".into(), json!(self.created_by));
        let resources = self
            .resources
            .iter()
            .map(|resource| {
                let mut value = resource.dump();
                if !resource.own_lane {
                    value.as_object_mut().expect("an object").shift_remove("lane");
                }
                value
            })
            .collect();
        map.insert("resources".into(), Value::Array(resources));
        if let Some(egress) = &self.egress {
            let sections: Map<String, Value> =
                egress.iter().map(|(protocol, section)| (protocol.as_str().to_string(), section.wire())).collect();
            map.insert("egress".into(), Value::Object(sections));
        }
        if let Some(relay) = &self.relay {
            map.insert("relay".into(), relay.dump());
        }
        Value::Object(map)
    }

    /// `canonical_digest(document)`: sha256 (lowercase hex) of the canonical JSON of [`Self::wire`]
    /// with the resources sorted by `ref` — the digest mixed-version panels compare.
    pub fn canonical_digest(&self) -> String {
        let mut payload = self.wire();
        if let Some(Value::Array(resources)) = payload.get_mut("resources") {
            resources.sort_by(|a, b| a["ref"].as_str().unwrap_or("").cmp(b["ref"].as_str().unwrap_or("")));
        }
        ids::sha256_hex(pyjson::canonical(&payload))
    }

    /// `generations.content_digest`: the digest with the numbering and the timestamp neutralised
    /// (`generation=1, previous_generation=0, created_at=0, created_by=""`) — what the node would
    /// run, deciding whether `publish` needs a new generation.
    pub fn content_digest(&self) -> String {
        let neutral = GenerationDocument {
            generation: 1,
            previous_generation: 0,
            created_at: 0,
            created_by: String::new(),
            ..self.clone()
        };
        neutral.canonical_digest()
    }

    /// Every credential ref the document carries: its resources', then its relay accounts'.
    pub fn credential_refs(&self) -> Vec<&str> {
        let mut refs: Vec<&str> = self.resources.iter().map(|item| item.credential_ref.as_str()).collect();
        if let Some(relay) = &self.relay {
            refs.extend(relay.accounts.iter().map(|account| account.credential_ref.as_str()));
        }
        refs
    }
}

impl Model for GenerationDocument {
    const TITLE: &'static str = "GenerationDocument";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let schema_version =
            f.optional(cx, "schema_version", || SCHEMA_VERSION, |v, l, cx| literal_int(v, l, cx, SCHEMA_VERSION));
        let node_guid = f.required(cx, "node_guid", |v, l, cx| Str::len(1, 64).validate(v, l, cx));
        let master_guid = f.required(cx, "master_guid", |v, l, cx| Str::len(1, 64).validate(v, l, cx));
        let generation = f.required(cx, "generation", |v, l, cx| Int::lax(Some(1), None).validate(v, l, cx));
        let previous = f.required(cx, "previous_generation", |v, l, cx| Int::lax(Some(0), None).validate(v, l, cx));
        let created_at = f.required(cx, "created_at", |v, l, cx| Int::LAX.validate(v, l, cx));
        let created_by = f.required(cx, "created_by", |v, l, cx| Str::max(128).validate(v, l, cx));
        let resources =
            f.required(cx, "resources", |v, l, cx| list(v, l, cx, Some(MAX_RESOURCES), Resource::validate_at));
        let egress = f.optional(
            cx,
            "egress",
            || None,
            |v, l, cx| {
                nullable(v, l, cx, |v, l, cx| {
                    let entries = dict_of(
                        v,
                        l,
                        cx,
                        None,
                        |key, l, cx| literal_key(EGRESS_PROTOCOLS)(key, l, cx).and_then(Protocol::from_wire),
                        EgressDocument::validate_at,
                    )?;
                    Some(entries.into_iter().collect::<IndexMap<_, _>>())
                })
            },
        );
        let relay = f.optional(cx, "relay", || None, |v, l, cx| nullable(v, l, cx, RelaySection::validate_at));
        let whole = f.input();
        let at_root = f.loc().to_vec();
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        let document = GenerationDocument {
            schema_version: schema_version?,
            node_guid: node_guid?,
            master_guid: master_guid?,
            generation: generation?,
            previous_generation: previous?,
            created_at: created_at?,
            created_by: created_by?,
            resources: resources?,
            egress: egress?,
            relay: relay?,
        };
        if let Err(message) = document.check() {
            cx.push(value_error(at_root, whole, message));
            return None;
        }
        Some(document)
    }

    fn dump(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "node_guid": self.node_guid,
            "master_guid": self.master_guid,
            "generation": self.generation,
            "previous_generation": self.previous_generation,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "resources": self.resources.iter().map(Model::dump).collect::<Vec<_>>(),
            "egress": self.egress.as_ref().map(|egress| {
                egress.iter().map(|(protocol, section)| (protocol.as_str().to_string(), section.dump())).collect::<Map<_, _>>()
            }),
            "relay": self.relay.as_ref().map(Model::dump),
        })
    }
}

/// `PUT /api/fleet/v2/generation`: the generation and the plaintext of every credential it names.
#[derive(Debug, Clone, PartialEq)]
pub struct PushRequest {
    pub expected_guid: String,
    pub generation: GenerationDocument,
    /// `credential_ref → plaintext`; only refs the document carries.
    pub secrets: IndexMap<String, String>,
}

impl PushRequest {
    /// `secrets_belong_to_the_document`.
    pub fn check(&self) -> Result<(), String> {
        let refs = self.generation.credential_refs();
        let mut stray: Vec<&str> = self.secrets.keys().map(String::as_str).filter(|key| !refs.contains(key)).collect();
        if stray.is_empty() {
            return Ok(());
        }
        stray.sort_unstable();
        stray.dedup();
        let shown = Value::Array(stray.iter().map(|key| json!(key)).collect());
        Err(format!("secrets for unknown refs: {}", pyrepr::repr(&shown)))
    }

    /// `wire()`: what the central sends.
    pub fn wire(&self) -> Value {
        json!({
            "expected_guid": self.expected_guid,
            "generation": self.generation.wire(),
            "secrets": self.secrets.iter().map(|(k, v)| (k.clone(), json!(v))).collect::<Map<_, _>>(),
        })
    }
}

impl Model for PushRequest {
    const TITLE: &'static str = "PushRequest";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let expected_guid = f.required(cx, "expected_guid", string);
        let generation = f.required(cx, "generation", GenerationDocument::validate_at);
        let secrets = f.optional(cx, "secrets", IndexMap::new, |v, l, cx| {
            dict_of(v, l, cx, None, str_key, string).map(|entries| entries.into_iter().collect())
        });
        let whole = f.input();
        let at_root = f.loc().to_vec();
        if !f.finish(cx, Extra::Forbid) {
            return None;
        }
        let request = PushRequest { expected_guid: expected_guid?, generation: generation?, secrets: secrets? };
        if let Err(message) = request.check() {
            cx.push(value_error(at_root, whole, message));
            return None;
        }
        Some(request)
    }

    fn dump(&self) -> Value {
        json!({
            "expected_guid": self.expected_guid,
            "generation": self.generation.dump(),
            "secrets": self.secrets.iter().map(|(k, v)| (k.clone(), json!(v))).collect::<Map<_, _>>(),
        })
    }
}

wire_enum! {
    /// What the node found for one resource.
    pub enum ObservedState {
        Enabled => "enabled",
        Disabled => "disabled",
        Missing => "missing",
        Failed => "failed",
        Drifted => "drifted",
    }
}

/// A fact the runtime taught the node about a resource (`str | int | list[str] | dict[str, str]`):
/// Telemt's public host and port, mita's share template, AmneziaWG's DNS list and obfuscation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Learned {
    Str(String),
    Int(i64),
    List(Vec<String>),
    Dict(IndexMap<String, String>),
}

impl Learned {
    pub fn to_value(&self) -> Value {
        match self {
            Learned::Str(text) => json!(text),
            Learned::Int(number) => json!(number),
            Learned::List(items) => json!(items),
            Learned::Dict(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), json!(v))).collect()),
        }
    }

    /// pydantic's smart union over the four members: an exact type wins, then lax coercion
    /// (`True` → `1`, `2.0` → `2`); when every member fails, each one's issues under its tag.
    fn validate(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        match input {
            Value::String(text) => return Some(Learned::Str(text.clone())),
            Value::Number(number) if !number.is_f64() => {
                if let Some(value) = number.as_i64() {
                    return Some(Learned::Int(value));
                }
            }
            _ => {}
        }
        let tag = |name: &str| crate::validate::at(loc, name);
        let (int, int_issues) = cx.attempt(|cx| Int::LAX.validate(input, &tag("int"), cx));
        if let Some(value) = int {
            return Some(Learned::Int(value));
        }
        let (items, list_issues) = cx.attempt(|cx| list(input, &tag("list[str]"), cx, None, string));
        if let Some(items) = items {
            return Some(Learned::List(items));
        }
        let (map, dict_issues) = cx.attempt(|cx| dict_of(input, &tag("dict[str,str]"), cx, None, str_key, string));
        if let Some(map) = map {
            return Some(Learned::Dict(map.into_iter().collect()));
        }
        let (_, str_issues) = cx.attempt(|cx| string(input, &tag("str"), cx));
        for issue in str_issues.into_iter().chain(int_issues).chain(list_issues).chain(dict_issues) {
            cx.push(issue);
        }
        None
    }
}

/// What the node did with one resource.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedResource {
    pub reference: String,
    pub protocol: String,
    pub runtime_username: String,
    pub state: ObservedState,
    pub error: Option<String>,
    pub revision: Option<String>,
    /// At most 8 facts; never a credential.
    pub learned: IndexMap<String, Learned>,
}

impl Model for ObservedResource {
    const TITLE: &'static str = "ObservedResource";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let reference = f.required(cx, "ref", string);
        let protocol = f.required(cx, "protocol", string);
        let runtime_username = f.required(cx, "runtime_username", string);
        let state = f.required(cx, "state", |v, l, cx| {
            literal_enum(v, l, cx, &["enabled", "disabled", "missing", "failed", "drifted"])
        });
        let error = f.optional(cx, "error", || None, optional_string);
        let revision = f.optional(cx, "revision", || None, optional_string);
        let learned = f.optional(cx, "learned", IndexMap::new, |v, l, cx| {
            dict_of(v, l, cx, Some(8), str_key, Learned::validate).map(|entries| entries.into_iter().collect())
        });
        if !f.finish(cx, Extra::Ignore) {
            return None;
        }
        Some(ObservedResource {
            reference: reference?,
            protocol: protocol?,
            runtime_username: runtime_username?,
            state: state?,
            error: error?,
            revision: revision?,
            learned: learned?,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "ref": self.reference,
            "protocol": self.protocol,
            "runtime_username": self.runtime_username,
            "state": self.state.as_str(),
            "error": self.error,
            "revision": self.revision,
            "learned": self.learned.iter().map(|(k, v)| (k.clone(), v.to_value())).collect::<Map<_, _>>(),
        })
    }
}

wire_enum! {
    /// The outcome of an egress or relay section on the node.
    pub enum SectionState {
        Converged => "converged",
        Failed => "failed",
        Unsupported => "unsupported",
    }
}

const SECTION_STATES: &[&str] = &["converged", "failed", "unsupported"];

/// What the node did with one protocol's egress section.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedEgress {
    pub state: SectionState,
    pub revision: Option<String>,
    pub digest: Option<String>,
    pub error: Option<String>,
    /// The router's side of the section: its own revision and generation.
    pub router: Option<Map<String, Value>>,
    /// The client lanes the node built for this service.
    pub lanes: Vec<String>,
}

impl Model for ObservedEgress {
    const TITLE: &'static str = "ObservedEgress";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let state = f.required(cx, "state", |v, l, cx| literal_enum(v, l, cx, SECTION_STATES));
        let revision = f.optional(cx, "revision", || None, optional_string);
        let digest = f.optional(cx, "digest", || None, optional_string);
        let error = f.optional(cx, "error", || None, optional_string);
        let router = f.optional(cx, "router", || None, |v, l, cx| nullable(v, l, cx, dict));
        let lanes = f.optional(cx, "lanes", Vec::new, |v, l, cx| list(v, l, cx, None, string));
        if !f.finish(cx, Extra::Ignore) {
            return None;
        }
        Some(ObservedEgress {
            state: state?,
            revision: revision?,
            digest: digest?,
            error: error?,
            router: router?,
            lanes: lanes?,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "state": self.state.as_str(),
            "revision": self.revision,
            "digest": self.digest,
            "error": self.error,
            "router": self.router,
            "lanes": self.lanes,
        })
    }
}

/// What the node did with the `relay` section: the inbound's public part and the accounts it
/// carries (emails only), or the failure code.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedRelay {
    pub state: SectionState,
    pub enabled: bool,
    pub port: Option<i64>,
    pub server_name: Option<String>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub accounts: Vec<String>,
    pub error: Option<String>,
}

impl Model for ObservedRelay {
    const TITLE: &'static str = "ObservedRelay";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let state = f.required(cx, "state", |v, l, cx| literal_enum(v, l, cx, SECTION_STATES));
        let enabled = f.optional(cx, "enabled", || false, boolean);
        let port = f.optional(cx, "port", || None, optional_int);
        let server_name = f.optional(cx, "server_name", || None, optional_string);
        let public_key = f.optional(cx, "public_key", || None, optional_string);
        let short_id = f.optional(cx, "short_id", || None, optional_string);
        let accounts = f.optional(cx, "accounts", Vec::new, |v, l, cx| list(v, l, cx, None, string));
        let error = f.optional(cx, "error", || None, optional_string);
        if !f.finish(cx, Extra::Ignore) {
            return None;
        }
        Some(ObservedRelay {
            state: state?,
            enabled: enabled?,
            port: port?,
            server_name: server_name?,
            public_key: public_key?,
            short_id: short_id?,
            accounts: accounts?,
            error: error?,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "state": self.state.as_str(),
            "enabled": self.enabled,
            "port": self.port,
            "server_name": self.server_name,
            "public_key": self.public_key,
            "short_id": self.short_id,
            "accounts": self.accounts,
            "error": self.error,
        })
    }
}

wire_enum! {
    /// Where the node's reconcile stands.
    pub enum ReconcileState {
        Idle => "idle",
        Applying => "applying",
        Converged => "converged",
        Failed => "failed",
    }
}

/// The node's report of the generation it applied.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedGeneration {
    pub applied_generation: i64,
    pub digest: String,
    pub reconcile_state: ReconcileState,
    pub resources: Vec<ObservedResource>,
    pub reported_at: i64,
    /// Per protocol, the egress the node last applied.
    pub egress: IndexMap<String, ObservedEgress>,
    /// The node's relay as of its last apply.
    pub relay: Option<ObservedRelay>,
}

impl ObservedGeneration {
    /// What a node reports before any push.
    pub fn initial() -> Self {
        Self {
            applied_generation: 0,
            digest: String::new(),
            reconcile_state: ReconcileState::Idle,
            resources: Vec::new(),
            reported_at: 0,
            egress: IndexMap::new(),
            relay: None,
        }
    }
}

impl Model for ObservedGeneration {
    const TITLE: &'static str = "ObservedGeneration";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let applied_generation = f.required(cx, "applied_generation", |v, l, cx| Int::LAX.validate(v, l, cx));
        let digest = f.required(cx, "digest", string);
        let reconcile_state = f.required(cx, "reconcile_state", |v, l, cx| {
            literal_enum(v, l, cx, &["idle", "applying", "converged", "failed"])
        });
        let resources = f.required(cx, "resources", |v, l, cx| list(v, l, cx, None, ObservedResource::validate_at));
        let reported_at = f.required(cx, "reported_at", |v, l, cx| Int::LAX.validate(v, l, cx));
        let egress = f.optional(cx, "egress", IndexMap::new, |v, l, cx| {
            dict_of(v, l, cx, None, str_key, ObservedEgress::validate_at).map(|entries| entries.into_iter().collect())
        });
        let relay = f.optional(cx, "relay", || None, |v, l, cx| nullable(v, l, cx, ObservedRelay::validate_at));
        if !f.finish(cx, Extra::Ignore) {
            return None;
        }
        Some(ObservedGeneration {
            applied_generation: applied_generation?,
            digest: digest?,
            reconcile_state: reconcile_state?,
            resources: resources?,
            reported_at: reported_at?,
            egress: egress?,
            relay: relay?,
        })
    }

    fn dump(&self) -> Value {
        json!({
            "applied_generation": self.applied_generation,
            "digest": self.digest,
            "reconcile_state": self.reconcile_state.as_str(),
            "resources": self.resources.iter().map(Model::dump).collect::<Vec<_>>(),
            "reported_at": self.reported_at,
            "egress": self.egress.iter().map(|(k, v)| (k.clone(), v.dump())).collect::<Map<_, _>>(),
            "relay": self.relay.as_ref().map(Model::dump),
        })
    }
}

/// The node's answer to a push: its report and the credentials its managers generated
/// (`"<protocol>:<runtime_username>" → value`).
#[derive(Debug, Clone, PartialEq)]
pub struct PushResponse {
    pub observed: ObservedGeneration,
    pub credentials: IndexMap<String, String>,
}

impl Model for PushResponse {
    const TITLE: &'static str = "PushResponse";

    fn validate_at(input: &Value, loc: &[LocItem], cx: &mut Cx) -> Option<Self> {
        let mut f = Fields::open(input, loc, cx, Self::TITLE)?;
        let observed = f.required(cx, "observed", ObservedGeneration::validate_at);
        let credentials = f.optional(cx, "credentials", IndexMap::new, |v, l, cx| {
            dict_of(v, l, cx, None, str_key, string).map(|entries| entries.into_iter().collect())
        });
        if !f.finish(cx, Extra::Ignore) {
            return None;
        }
        Some(PushResponse { observed: observed?, credentials: credentials? })
    }

    fn dump(&self) -> Value {
        json!({
            "observed": self.observed.dump(),
            "credentials": self.credentials.iter().map(|(k, v)| (k.clone(), json!(v))).collect::<Map<_, _>>(),
        })
    }
}

/// Whether `name` is a runtime username a resource may carry.
pub fn is_runtime_username(name: &str) -> bool {
    is_username(name)
}

#[cfg(test)]
mod tests;
