//! Node-local reconcile (`fleet_v2/reconcile.py`, spec §5.3): make the runtime match the latest
//! accepted generation.
//!
//! No compensation lives here on purpose: a resource that fails is reported `failed` and retried;
//! a rollback is a new, higher generation from the central (ADR 002).
//!
//! Adapter calls never run inside a database transaction: each resource is planned and applied
//! with no connection open, then recorded in one short transaction of its own (on the blocking
//! pool). One async lock serialises `apply` and `unlink` (a push and the startup retry may
//! overlap; two interleaved applies would race the same runtime users).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use indexmap::{IndexMap, IndexSet};
use panel_core::clock::SharedClock;
use panel_core::db::{Conn, Database, DbError};
use panel_core::pytext;
use panel_model::clients::{within_validity, GrantIntent, ProtocolOptions};
use panel_model::fleet::{
    CredentialOrigin, DesiredState, EgressDocument, ObservedGeneration, ObservedResource, ObservedState, PushRequest,
    RelaySection, Resource, ResourceOrigin,
};
use panel_model::protocols::{AdapterError, AppliedGrant, CredentialPlan, GrantRef, ObservedGrant, ProtocolAdapter};
use panel_model::routing::document::document_digest_map;
use panel_model::{Backend, Protocol};
use panel_secrets::secrets_store::{Identity, SecretError, SecretRef, SecretStore};
use serde_json::{json, Map, Value};

use super::managed::{
    setting_json, EgressUpdate, Key, Latest, ManagedStore, ResourceUpdate, Row, StoreError, LANES_KEY, RELAY_KEY,
};
use super::runtime::NodeRuntime;

/// The purpose of the secrets a push escrows on the node.
pub const MANAGED_PURPOSE: &str = "fleet-managed";
/// Services whose clients may run their own lane (v0.7).
pub const LANE_PROTOCOLS: [&str; 2] = ["naive", "mieru"];
/// Options the runtime teaches the panel (Telemt's endpoint, mita's share link, AmneziaWG's
/// interface, TrustTunnel's domain and certificate, the profile label): never pushed back, so
/// never drift.
pub const LEARNED_OPTIONS: [&str; 11] = [
    "host",
    "port",
    "share_template",
    "address",
    "server_public_key",
    "mtu",
    "dns",
    "obfuscation",
    "hostname",
    "certificate_der_b64",
    "name",
];

const COLLISION: &str = "runtime user exists and is not managed";

/// Why `apply` (or the reconcile around it) did not produce a report.
#[derive(Debug)]
pub enum ReconcileError {
    /// `GenerationSuperseded`: a newer generation was accepted meanwhile; nothing was applied.
    Superseded(i64),
    /// The secret store refused (no master key, …).
    Secret(SecretError),
    Store(StoreError),
    /// Anything else Python let escape (a malformed `credential_ref`, a lane answer without its
    /// account, a join failure).
    Internal(String),
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconcileError::Superseded(generation) => write!(f, "{generation}"),
            ReconcileError::Secret(error) => write!(f, "{error}"),
            ReconcileError::Store(error) => write!(f, "{error}"),
            ReconcileError::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ReconcileError {}

impl From<DbError> for ReconcileError {
    fn from(error: DbError) -> Self {
        ReconcileError::Store(StoreError::Db(error))
    }
}

impl From<StoreError> for ReconcileError {
    fn from(error: StoreError) -> Self {
        ReconcileError::Store(error)
    }
}

impl From<SecretError> for ReconcileError {
    fn from(error: SecretError) -> Self {
        ReconcileError::Secret(error)
    }
}

/// The node's report and the credentials the runtime chose itself (`credential_ref → value`),
/// which the central must escrow.
pub type Applied = (ObservedGeneration, IndexMap<String, String>);

/// Why one resource did not apply.
enum Step {
    /// A runtime user this node never recorded as its own: reported, never persisted.
    Collision,
    Failed(String),
}

impl From<AdapterError> for Step {
    fn from(error: AdapterError) -> Self {
        Step::Failed(error.message)
    }
}

impl From<ReconcileError> for Step {
    fn from(error: ReconcileError) -> Self {
        Step::Failed(error.to_string())
    }
}

/// An egress section's failure: the adapter's coded refusal, or anything else.
enum SectionError {
    Adapter(AdapterError),
    Other(String),
}

impl From<AdapterError> for SectionError {
    fn from(error: AdapterError) -> Self {
        SectionError::Adapter(error)
    }
}

impl From<ReconcileError> for SectionError {
    fn from(error: ReconcileError) -> Self {
        SectionError::Other(error.to_string())
    }
}

/// `credential_ref.rpartition(":")` → `SecretRef(secret_id, int(version))`.
pub fn secret_ref(credential_ref: &str) -> Result<SecretRef, String> {
    let invalid = || "credential_ref must look like <secret_id>:<version>".to_string();
    let (secret_id, version) = credential_ref.rsplit_once(':').unwrap_or(("", credential_ref));
    if secret_id.is_empty() || version.is_empty() {
        return Err(invalid());
    }
    let mut number: i64 = 0;
    for ch in version.chars() {
        let digit = pytext::decimal(ch).ok_or_else(invalid)?;
        number = number.checked_mul(10).and_then(|n| n.checked_add(i64::from(digit))).ok_or_else(invalid)?;
    }
    Ok(SecretRef::new(secret_id, number))
}

fn state_of(enabled: bool) -> &'static str {
    if enabled {
        "enabled"
    } else {
        "disabled"
    }
}

/// Python's truth value of an optional JSON value.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
    }
}

/// `a or b` of two optional revisions (an empty string is falsy).
fn or_revision(first: Option<String>, second: Option<String>) -> Option<String> {
    first.filter(|text| !text.is_empty()).or(second)
}

/// `bytes.decode()` (UTF-8, strict).
fn decode(bytes: &[u8]) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|error| {
        let position = error.utf8_error().valid_up_to();
        format!("'utf-8' codec can't decode byte 0x{:02x} in position {position}: invalid start byte", bytes[position])
    })
}

/// `str(exc)[:200]`.
fn bounded(message: &str) -> String {
    pytext::truncate(message, 200).to_string()
}

/// The facts a runtime reported that the protocol's options model has a field for and that are
/// learned, never pushed (`_learned_from`).
pub fn learned_from(protocol: Protocol, reported: &Map<String, Value>) -> Map<String, Value> {
    let fields = ProtocolOptions::field_names(protocol);
    reported
        .iter()
        .filter(|(key, value)| {
            fields.contains(&key.as_str())
                && LEARNED_OPTIONS.contains(&key.as_str())
                && !value.is_null()
                && value.as_str() != Some("")
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// `_learned_from_inventory`: the same facts off an inventory row, `None` when there are none.
fn learned_from_inventory(resource: &Resource, item: &ObservedGrant) -> Option<Map<String, Value>> {
    Some(learned_from(resource.protocol, &item.options)).filter(|learned| !learned.is_empty())
}

fn row_str(row: &Row, key: &str) -> Option<String> {
    row.get(key).and_then(Value::as_str).map(str::to_string)
}

fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_object().and_then(|map| map.get(key))
}

/// The node-local reconcile.
pub struct Reconciler {
    database: Database,
    secrets: RwLock<SecretStore>,
    runtime: Arc<dyn NodeRuntime>,
    managed: ManagedStore,
    guid: String,
    clock: SharedClock,
    lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Reconciler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reconciler").field("guid", &self.guid).finish_non_exhaustive()
    }
}

impl Reconciler {
    pub fn new(
        database: Database,
        secrets: SecretStore,
        runtime: Arc<dyn NodeRuntime>,
        managed: ManagedStore,
        guid: impl Into<String>,
        clock: SharedClock,
    ) -> Self {
        Self {
            database,
            secrets: RwLock::new(secrets),
            runtime,
            managed,
            guid: guid.into(),
            clock,
            lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn runtime(&self) -> &Arc<dyn NodeRuntime> {
        &self.runtime
    }

    pub fn managed(&self) -> &ManagedStore {
        &self.managed
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    pub fn guid(&self) -> &str {
        &self.guid
    }

    /// The secret store in use.
    pub fn secrets(&self) -> SecretStore {
        self.secrets.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    /// Replaces the secret store (`reconciler.secrets = …`).
    pub fn set_secrets(&self, secrets: SecretStore) {
        *self.secrets.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = secrets;
    }

    // -- database plumbing (blocking pool, never across an adapter call) --------------------

    async fn blocking<T: Send + 'static>(
        &self,
        transaction: bool,
        work: impl FnOnce(&Conn, &ManagedStore) -> Result<T, ReconcileError> + Send + 'static,
    ) -> Result<T, ReconcileError> {
        let (database, managed) = (self.database.clone(), self.managed.clone());
        tokio::task::spawn_blocking(move || {
            if transaction {
                database.transaction(|db| work(db, &managed))
            } else {
                database.with_connection(|db| work(db, &managed))
            }
        })
        .await
        .map_err(|error| ReconcileError::Internal(error.to_string()))?
    }

    async fn tx<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Conn, &ManagedStore) -> Result<T, ReconcileError> + Send + 'static,
    ) -> Result<T, ReconcileError> {
        self.blocking(true, work).await
    }

    async fn read<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Conn, &ManagedStore) -> Result<T, ReconcileError> + Send + 'static,
    ) -> Result<T, ReconcileError> {
        self.blocking(false, work).await
    }

    async fn reveal(&self, credential_ref: &str) -> Result<Vec<u8>, ReconcileError> {
        let secret = secret_ref(credential_ref).map_err(ReconcileError::Internal)?;
        let secrets = self.secrets();
        self.read(move |db, _| Ok(secrets.reveal(db, &secret, MANAGED_PURPOSE, None, Some("local"))?)).await
    }

    /// Escrows the secrets a push carried, once per version, inside the caller's transaction.
    pub fn store_secrets(&self, db: &Conn, request: &PushRequest) -> Result<(), ReconcileError> {
        let secrets = self.secrets();
        for (credential_ref, plaintext) in &request.secrets {
            let secret = secret_ref(credential_ref).map_err(ReconcileError::Internal)?;
            let exists: Option<i64> = panel_core::rusqlite::OptionalExtension::optional(db.query_row(
                "SELECT 1 FROM secret_versions WHERE secret_id=? AND version=?",
                panel_core::rusqlite::params![secret.secret_id, secret.version],
                |row| row.get(0),
            ))
            .map_err(DbError::from)?;
            if exists.is_none() {
                let identity = Identity {
                    secret_id: &secret.secret_id,
                    version: secret.version,
                    purpose: MANAGED_PURPOSE,
                    grant_id: None,
                    permitted_node_id: Some("local"),
                };
                secrets.store(db, &identity, plaintext.as_bytes(), "active")?;
            }
        }
        Ok(())
    }

    // -- the entry points ----------------------------------------------------------------------

    /// Applies the latest generation if it is `generation`; the report and the credentials the
    /// runtime chose itself.
    pub async fn apply(&self, generation: i64) -> Result<Applied, ReconcileError> {
        let _guard = self.lock.lock().await;
        let latest = self.read(|db, managed| Ok(managed.latest(db)?)).await?;
        match latest {
            Some(latest) if latest.generation == generation => self.apply_latest(latest).await,
            _ => Err(ReconcileError::Superseded(generation)),
        }
    }

    /// `apply` of a given latest generation, without re-reading it (tests feed a document that no
    /// longer validates, the way Python stubs `ManagedStore.latest`). Takes the reconcile lock.
    #[doc(hidden)]
    pub async fn apply_stored(&self, latest: Latest) -> Result<Applied, ReconcileError> {
        let _guard = self.lock.lock().await;
        self.apply_latest(latest).await
    }

    /// Forgets the master under the same lock `apply` holds (a reconcile in flight would otherwise
    /// re-register the rows this releases). How many resources became local.
    pub async fn unlink(&self) -> Result<i64, ReconcileError> {
        let _guard = self.lock.lock().await;
        self.tx(|db, managed| Ok(managed.unlink(db)?)).await
    }

    /// Retries failures and elapsed validity windows, including a converged generation whose
    /// resources no longer match what the clock says they should be.
    pub async fn run_pending(&self) -> Result<(), ReconcileError> {
        let (latest, known) = self
            .read(|db, managed| {
                let latest = managed.latest(db)?;
                let known = if latest.is_some() { managed.resources(db)? } else { IndexMap::new() };
                Ok((latest, known))
            })
            .await?;
        let Some(latest) = latest else {
            return Ok(());
        };
        let due = latest.document.resources.iter().any(|resource| {
            let key = (resource.protocol.as_str().to_string(), resource.runtime_username.clone());
            resource.desired_state != DesiredState::Deleted
                && known.get(&key).and_then(|row| row.get("state")).and_then(Value::as_str)
                    != Some(state_of(self.wanted(resource)))
        });
        if latest.state != "converged" || due {
            self.apply(latest.generation).await?;
        }
        Ok(())
    }

    fn wanted(&self, resource: &Resource) -> bool {
        resource.desired_state == DesiredState::Enabled
            && within_validity(resource.valid_from, resource.valid_until, self.clock.now())
    }

    // -- planning -------------------------------------------------------------------------------

    async fn plan(&self, resource: &Resource) -> Result<CredentialPlan, Step> {
        if resource.credential_origin == CredentialOrigin::Manager {
            return Ok(CredentialPlan::manager());
        }
        let plaintext = self.reveal(&resource.credential_ref).await?;
        Ok(CredentialPlan::caller(plaintext)?)
    }

    fn intent(resource: &Resource) -> Result<GrantIntent, Step> {
        let options = ProtocolOptions::validate(resource.protocol, &Value::Object(resource.options.clone()))
            .map_err(|error| Step::Failed(error.to_string()))?;
        let mut intent = GrantIntent::new(resource.protocol, &resource.runtime_username, options)
            .map_err(|error| Step::Failed(error.to_string()))?;
        intent.valid_from = resource.valid_from;
        intent.valid_until = resource.valid_until;
        Ok(intent)
    }

    /// A credential the central does not hold in the form the runtime serves is handed back: one
    /// the manager chose, or the runtime's own framing of the caller's (Telemt's `ee…`).
    fn collect(
        credentials: &mut IndexMap<String, String>,
        resource: &Resource,
        applied: &AppliedGrant,
        plan: &CredentialPlan,
    ) -> Result<(), Step> {
        let manager_chose = applied.credential_origin == CredentialOrigin::Manager
            || resource.credential_origin == CredentialOrigin::Manager;
        let reframed = plan.plaintext().is_some()
            && applied.credential.as_deref().is_some_and(|credential| Some(credential) != plan.plaintext());
        if let Some(credential) = applied.credential.as_deref().filter(|credential| !credential.is_empty()) {
            if manager_chose || reframed {
                credentials.insert(resource.credential_ref.clone(), decode(credential).map_err(Step::Failed)?);
            }
        }
        Ok(())
    }

    // -- recording (the one place that writes managed_resources) ---------------------------------

    #[allow(clippy::too_many_arguments)] // `_record`'s keyword arguments
    async fn record(
        &self,
        generation: i64,
        resource: &Resource,
        state: &str,
        error: Option<String>,
        revision: Option<String>,
        credential_ref: Option<String>,
        learned: Option<Map<String, Value>>,
    ) -> Result<(), ReconcileError> {
        let update = ResourceUpdate {
            protocol: resource.protocol.as_str().to_string(),
            username: resource.runtime_username.clone(),
            reference: resource.reference.clone(),
            generation,
            state: state.to_string(),
            error,
            revision,
            credential_ref,
            learned,
        };
        self.tx(move |db, managed| Ok(managed.upsert_resource(db, &update)?)).await
    }

    async fn record_failed(&self, generation: i64, resource: &Resource, error: &str) -> Result<(), ReconcileError> {
        self.record(generation, resource, "failed", Some(error.to_string()), None, None, None).await
    }

    // -- applying (adapter I/O only, no database connection open) --------------------------------

    /// Brings one runtime user to the resource's desired state: `(state, revision, learned)`.
    ///
    /// Ownership rule (ADR 003): a runtime user this node did not record as its own is never
    /// touched because its name matches a pushed resource — a [`Step::Collision`], never written
    /// to the store. The one deliberate adoption is an `imported` resource. A `create` always
    /// writes a placeholder row first, so a crash after the adapter call is recovered with an
    /// idempotent `rotate` instead of being taken for a collision.
    async fn apply_resource(
        &self,
        adapter: &dyn ProtocolAdapter,
        resource: &Resource,
        item: Option<&ObservedGrant>,
        record: Option<&Row>,
        generation: i64,
        credentials: &mut IndexMap<String, String>,
    ) -> Result<(String, Option<String>, Option<Map<String, Value>>), Step> {
        let reference = GrantRef {
            protocol: resource.protocol,
            runtime_username: resource.runtime_username.clone(),
            revision: None,
        };
        let operation_id = format!("{}:{generation}:{}", self.guid, resource.reference);
        // A `missing` row owns nothing: whatever lives under that name now is someone else's.
        let mut stored: Option<Option<String>> = record
            .filter(|row| row.get("state").and_then(Value::as_str) != Some("missing"))
            .map(|row| row_str(row, "credential_ref"));
        let mut learned: Option<Map<String, Value>> = None;
        if let (Some(item), None) = (item, &stored) {
            if resource.origin != ResourceOrigin::Imported || resource.desired_state == DesiredState::Deleted {
                return Err(Step::Collision);
            }
            // Explicit adoption (spec §6): no adapter call; the pushed ref names the credential the
            // runtime holds today, and the inventory's facts are what the node learned.
            learned = learned_from_inventory(resource, item);
            self.record(
                generation,
                resource,
                state_of(item.enabled),
                None,
                item.revision.clone(),
                Some(resource.credential_ref.clone()),
                learned.clone(),
            )
            .await?;
            stored = Some(Some(resource.credential_ref.clone()));
        }
        if resource.desired_state == DesiredState::Deleted {
            if item.is_some() {
                adapter.delete(&reference).await?;
            }
            return Ok(("missing".into(), None, None));
        }
        let (mut state, mut revision, current) = match item {
            None => {
                self.record_failed(generation, resource, "create in flight; will retry on the next apply").await?;
                let plan = self.plan(resource).await?;
                let intent = Self::intent(resource)?;
                let applied = adapter.create(&operation_id, &intent, &plan).await?;
                Self::collect(credentials, resource, &applied, &plan)?;
                learned = Some(learned_from(resource.protocol, &applied.artifact_template));
                (state_of(applied.enabled).to_string(), applied.revision.clone(), None)
            }
            Some(item) => {
                let mut revision = item.revision.clone();
                if learned.as_ref().is_none_or(Map::is_empty) {
                    learned = learned_from_inventory(resource, item);
                }
                let stored = stored.flatten();
                if stored.as_deref() != Some(resource.credential_ref.as_str())
                    && (stored.is_some() || adapter.accepts_caller_credential())
                {
                    let plan = self.plan(resource).await?;
                    let applied = adapter.rotate(&format!("{operation_id}:rotate"), &reference, &plan).await?;
                    Self::collect(credentials, resource, &applied, &plan)?;
                    learned = Some(learned_from(resource.protocol, &applied.artifact_template));
                    revision = or_revision(applied.revision.clone(), revision);
                } else if adapter.capture_supported()
                    && (resource.credential_origin == CredentialOrigin::Manager
                        || adapter.credential_origin() == CredentialOrigin::Manager)
                {
                    // The runtime holds the credential in its own form: hand it back on every apply,
                    // so a re-PUT after a lost reply still gives the central the form the link needs.
                    if let Some(captured) = adapter.capture(&reference).await?.filter(|value| !value.is_empty()) {
                        credentials.insert(resource.credential_ref.clone(), decode(&captured).map_err(Step::Failed)?);
                    }
                }
                (state_of(item.enabled).to_string(), revision, Some(item.options.clone()))
            }
        };
        let wanted = self.wanted(resource);
        if wanted != (state == "enabled") {
            let applied = if wanted { adapter.enable(&reference).await? } else { adapter.disable(&reference).await? };
            state = state_of(applied.enabled).to_string();
            revision = or_revision(applied.revision, revision);
        }
        if let Some(current) = current {
            // A user created just now already carries the intent's options.
            let desired: Map<String, Value> = resource
                .options
                .iter()
                .filter(|(key, value)| !value.is_null() && !LEARNED_OPTIONS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            let held: Map<String, Value> = current
                .iter()
                .filter(|(key, _)| desired.contains_key(key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            if !desired.is_empty() && !panel_model::pyrepr::eq(&Value::Object(desired.clone()), &Value::Object(held)) {
                match adapter.update_options(&reference, &desired).await? {
                    None => state = "drifted".into(),
                    Some(applied) => revision = or_revision(applied.revision, revision),
                }
            }
        }
        Ok((state, revision, learned))
    }

    /// One protocol's resources and orphans; `true` when anything failed.
    #[allow(clippy::too_many_arguments)]
    async fn apply_protocol(
        &self,
        protocol: &str,
        resources: &[&Resource],
        orphans: &[String],
        known: &IndexMap<Key, Row>,
        generation: i64,
        credentials: &mut IndexMap<String, String>,
        collisions: &mut Vec<ObservedResource>,
    ) -> Result<bool, ReconcileError> {
        let adapter = Protocol::from_wire(protocol).and_then(|protocol| self.runtime.adapter(protocol));
        let discovered = match &adapter {
            None => Err(format!("protocol {protocol} is not enabled on this node")),
            Some(adapter) => adapter.discover().await.map_err(|error| error.message),
        };
        let (adapter, inventory) = match (adapter, discovered) {
            (Some(adapter), Ok(inventory)) => (adapter, inventory),
            (_, discovered) => {
                let message = discovered.err().unwrap_or_default();
                log::warn!("fleet: discover on {protocol} failed: {message}");
                let error = bounded(&message);
                for resource in resources {
                    self.record_failed(generation, resource, &error).await?;
                }
                // Orphans exist only in the store: mark them failed too, or the apply never ends
                // on them (finding I3).
                for username in orphans {
                    let stored = known.get(&(protocol.to_string(), username.clone()));
                    let update = ResourceUpdate {
                        protocol: protocol.to_string(),
                        username: username.clone(),
                        reference: stored.and_then(|row| row_str(row, "ref")).unwrap_or_else(|| username.clone()),
                        generation,
                        state: "failed".into(),
                        error: Some(error.clone()),
                        revision: None,
                        credential_ref: stored.and_then(|row| row_str(row, "credential_ref")),
                        learned: None,
                    };
                    self.tx(move |db, managed| Ok(managed.upsert_resource(db, &update)?)).await?;
                }
                return Ok(true);
            }
        };
        let mut observed: HashMap<&str, &ObservedGrant> = HashMap::new();
        for item in &inventory.items {
            observed.insert(item.runtime_username.as_str(), item);
        }
        let mut failed = false;
        let mut applied_resources: Vec<&Resource> = Vec::new();
        for resource in resources {
            let record = known.get(&(protocol.to_string(), resource.runtime_username.clone()));
            let item = observed.get(resource.runtime_username.as_str()).copied();
            match self.apply_resource(adapter.as_ref(), resource, item, record, generation, credentials).await {
                Err(Step::Collision) => {
                    failed = true;
                    log::warn!(
                        "fleet: {protocol}/{} ({}) failed: {COLLISION}",
                        resource.runtime_username,
                        resource.reference
                    );
                    collisions.push(ObservedResource {
                        reference: resource.reference.clone(),
                        protocol: protocol.to_string(),
                        runtime_username: resource.runtime_username.clone(),
                        state: ObservedState::Failed,
                        error: Some(COLLISION.into()),
                        revision: None,
                        learned: IndexMap::new(),
                    });
                }
                Err(Step::Failed(message)) => {
                    failed = true;
                    log::warn!(
                        "fleet: {protocol}/{} ({}) failed: {message}",
                        resource.runtime_username,
                        resource.reference
                    );
                    self.record_failed(generation, resource, &bounded(&message)).await?;
                }
                Ok((state, revision, learned)) => {
                    self.record(
                        generation,
                        resource,
                        &state,
                        None,
                        revision,
                        Some(resource.credential_ref.clone()),
                        learned,
                    )
                    .await?;
                    applied_resources.push(resource);
                }
            }
        }
        // Confirm the whole protocol once: a manager's successful reply is not runtime evidence.
        if !applied_resources.is_empty() {
            let readback = adapter.discover().await.ok();
            for resource in applied_resources {
                let item = readback.as_ref().and_then(|inventory| {
                    inventory.items.iter().rev().find(|item| item.runtime_username == resource.runtime_username)
                });
                let confirmed = readback.is_some()
                    && if resource.desired_state == DesiredState::Deleted {
                        item.is_none()
                    } else {
                        item.is_some_and(|item| item.enabled == self.wanted(resource))
                    };
                if !confirmed {
                    failed = true;
                    self.record_failed(generation, resource, "runtime access readback did not match").await?;
                }
            }
        }
        // Orphans: central-owned users this generation no longer names (spec §5.3). A row left
        // `missing` owns nothing: a same-named user present now is local.
        for username in orphans {
            let key = (protocol.to_string(), username.clone());
            let lingering = known.get(&key).and_then(|row| row.get("state")).and_then(Value::as_str) == Some("missing");
            let outcome: Result<(), String> = async {
                if observed.contains_key(username.as_str()) && !lingering {
                    let reference =
                        GrantRef { protocol: adapter.protocol(), runtime_username: username.clone(), revision: None };
                    adapter.delete(&reference).await.map_err(|error| error.message)?;
                }
                let (protocol, username) = key.clone();
                self.tx(move |db, managed| Ok(managed.remove_resource(db, &protocol, &username)?))
                    .await
                    .map_err(|error| error.to_string())
            }
            .await;
            if let Err(message) = outcome {
                failed = true;
                log::warn!("fleet: orphan {protocol}/{username} not removed: {message}");
            }
        }
        Ok(failed)
    }

    // -- egress (v0.4, spec §8.3): after the resources, one section per protocol ----------------

    async fn record_egress(&self, update: EgressUpdate) -> Result<(), ReconcileError> {
        self.tx(move |db, managed| Ok(managed.upsert_egress(db, &update)?)).await
    }

    /// The native manager's document, unless it already runs it: `(revision, digest)`.
    async fn apply_native(
        &self,
        protocol: Protocol,
        document: &Map<String, Value>,
        digest: &str,
        generation: i64,
        tag: &str,
    ) -> Result<(String, String), SectionError> {
        let adapter = self.runtime.adapter(protocol);
        let target = match &adapter {
            None => None,
            Some(adapter) => adapter.egress_target().await?,
        };
        let (Some(adapter), Some(target)) = (adapter, target) else {
            return Err(AdapterError::with_code(
                format!("{protocol} has no egress on this node"),
                "egress_unsupported",
            )
            .into());
        };
        if target.applied.as_ref().is_some_and(|applied| applied.digest == digest) {
            return Ok((target.revision, digest.to_string()));
        }
        let operation_id = format!("{}:{generation}:{tag}:{protocol}", self.guid);
        let applied = adapter.apply_egress(document, &target.revision, &operation_id).await?;
        Ok((applied.revision, applied.digest.filter(|text| !text.is_empty()).unwrap_or_else(|| digest.to_string())))
    }

    /// The router's section for the service, unless it already runs it: `(revision, digest)`.
    async fn apply_router(
        &self,
        protocol: Protocol,
        document: &Map<String, Value>,
        digest: &str,
        generation: i64,
        tag: &str,
    ) -> Result<(String, String), SectionError> {
        let Some(router) = self.runtime.router() else {
            return Err(AdapterError::with_code("this node has no Xray-router", "router_unavailable").into());
        };
        let target = router.target(protocol.as_str()).await;
        if !target.available {
            let code = target.reason.filter(|reason| !reason.is_empty()).unwrap_or_else(|| "router_unavailable".into());
            return Err(AdapterError::with_code("the node's Xray-router does not answer", code).into());
        }
        if target.applied.as_ref().is_some_and(|applied| applied.digest == digest) {
            return Ok((target.revision, digest.to_string()));
        }
        let operation_id = format!("{}:{generation}:{tag}:{protocol}", self.guid);
        let applied =
            router.apply(protocol.as_str(), &Value::Object(document.clone()), &target.revision, &operation_id).await?;
        Ok((applied.revision, applied.digest.filter(|text| !text.is_empty()).unwrap_or_else(|| digest.to_string())))
    }

    /// A native section: the native document, then its `companion` on the router. A router
    /// section: the router's intent first, then the native attach `companion` — so the service is
    /// never handed to a router that does not run its policy yet.
    async fn apply_egress_section(
        &self,
        protocol: Protocol,
        entry: &EgressDocument,
        generation: i64,
    ) -> Result<(), SectionError> {
        let update = |revision: Option<String>, digest: String, router: Option<(String, String)>| EgressUpdate {
            protocol: protocol.as_str().to_string(),
            generation,
            state: "converged".into(),
            revision,
            digest: Some(digest),
            error: None,
            router_revision: router.as_ref().map(|(revision, _)| revision.clone()),
            router_digest: router.map(|(_, digest)| digest),
        };
        if entry.backend == Backend::XrayRouter {
            let router = self.apply_router(protocol, &entry.document, &entry.digest, generation, "router").await?;
            let mut revision = None;
            if let Some(companion) = &entry.companion {
                let digest = document_digest_map(companion);
                revision = Some(self.apply_native(protocol, companion, &digest, generation, "egress").await?.0);
            }
            self.record_egress(update(revision, entry.digest.clone(), Some(router))).await?;
            return Ok(());
        }
        let adapter = self.runtime.adapter(protocol);
        let target = match &adapter {
            None => None,
            Some(adapter) => adapter.egress_target().await?,
        };
        let Some(target) = target else {
            return Err(AdapterError::with_code(
                format!("{protocol} has no egress on this node"),
                "egress_unsupported",
            )
            .into());
        };
        if target.backend != entry.backend {
            return Err(AdapterError::with_code(
                format!("{protocol} runs {}, not {}", target.backend, entry.backend),
                "egress_unsupported",
            )
            .into());
        }
        let (revision, digest) =
            self.apply_native(protocol, &entry.document, &entry.digest, generation, "egress").await?;
        let mut router = None;
        if let Some(companion) = &entry.companion {
            let companion_digest = document_digest_map(companion);
            router = Some(self.apply_router(protocol, companion, &companion_digest, generation, "router").await?);
        }
        self.record_egress(update(Some(revision), digest, router)).await?;
        Ok(())
    }

    /// Each protocol's egress section; `true` when any failed. No section at all leaves the node's
    /// egress as it is.
    async fn apply_egress(
        &self,
        egress: Option<&IndexMap<Protocol, EgressDocument>>,
        generation: i64,
    ) -> Result<bool, ReconcileError> {
        let Some(egress) = egress.filter(|egress| !egress.is_empty()) else {
            return Ok(false);
        };
        let mut failed = false;
        for (protocol, entry) in egress {
            let failure = |state: &str, error: String| EgressUpdate {
                protocol: protocol.as_str().to_string(),
                generation,
                state: state.to_string(),
                error: Some(error),
                ..EgressUpdate::default()
            };
            match self.apply_egress_section(*protocol, entry, generation).await {
                Ok(()) => {}
                Err(SectionError::Adapter(error)) => {
                    failed = true;
                    let code =
                        error.code.filter(|code| !code.is_empty()).unwrap_or_else(|| "manager_unavailable".into());
                    log::warn!("fleet: egress for {protocol} failed: {code}");
                    let state = if code == "egress_unsupported" { "unsupported" } else { "failed" };
                    self.record_egress(failure(state, code)).await?;
                }
                Err(SectionError::Other(message)) => {
                    failed = true;
                    log::warn!("fleet: egress for {protocol} failed: {message}");
                    self.record_egress(failure("failed", bounded(&message))).await?;
                }
            }
        }
        Ok(failed)
    }

    // -- lanes (v0.7, spec §7): a client's own lane, built by this node -------------------------

    /// `{lane: [users]}` this generation asks for: a lane per enabled, laned resource whose user
    /// the node runs enabled, named after the resource.
    async fn lane_wanted(&self, resources: &[&Resource]) -> Result<IndexMap<String, Vec<String>>, ReconcileError> {
        let rows = self.read(|db, managed| Ok(managed.resources(db)?)).await?;
        let mut wanted = IndexMap::new();
        for resource in resources {
            if !resource.own_lane || !self.wanted(resource) {
                continue;
            }
            let key = (resource.protocol.as_str().to_string(), resource.runtime_username.clone());
            if rows.get(&key).and_then(|row| row.get("state")).and_then(Value::as_str) == Some("enabled") {
                wanted.insert(resource.reference.clone(), vec![resource.runtime_username.clone()]);
            }
        }
        Ok(wanted)
    }

    /// Brings the service's lanes to what the generation asks: the router mints an account per
    /// lane, the manager moves the users; a lane withdrawn is forgotten on both. A refusal fails the
    /// laned resources, never the users themselves.
    async fn apply_lanes(
        &self,
        protocol: &str,
        resources: &[&Resource],
        generation: i64,
    ) -> Result<bool, ReconcileError> {
        let wanted = self.lane_wanted(resources).await?;
        let mut state = self.read(|db, _| Ok(setting_json(db, LANES_KEY, "{}")?)).await?;
        let current: Map<String, Value> = get(&state, protocol).and_then(Value::as_object).cloned().unwrap_or_default();
        let wanted_value: Map<String, Value> =
            wanted.iter().map(|(lane, users)| (lane.clone(), json!(users))).collect();
        if panel_model::pyrepr::eq(&Value::Object(wanted_value.clone()), &Value::Object(current.clone())) {
            return Ok(false);
        }
        let laned: Vec<&Resource> =
            resources.iter().copied().filter(|resource| wanted.contains_key(&resource.reference)).collect();
        enum LaneError {
            Adapter(AdapterError),
            Internal(String),
        }
        impl From<AdapterError> for LaneError {
            fn from(error: AdapterError) -> Self {
                LaneError::Adapter(error)
            }
        }
        let router = self.runtime.router();
        let attempt: Result<Value, LaneError> = async {
            let Some(router) = &router else {
                return Err(AdapterError::with_code(
                    "a client lane runs only on the node's Xray-router",
                    "lane_requires_router",
                )
                .into());
            };
            let service = Protocol::from_wire(protocol)
                .filter(|service| self.runtime.adapter(*service).is_some() && self.runtime.has_lanes(*service));
            let Some(service) = service else {
                return Err(AdapterError::with_code(
                    format!("{protocol} runs no lanes on this node"),
                    "lane_requires_router",
                )
                .into());
            };
            let mut sorted: Vec<(&String, &Vec<String>)> = wanted.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut lanes = Vec::new();
            for (lane, users) in sorted {
                let issued = router.lane_issue(protocol, lane).await?;
                // Python's `issued["user"]`: a KeyError that escapes the reconcile.
                let (Some(user), Some(password)) = (get(&issued, "user"), get(&issued, "password")) else {
                    return Err(LaneError::Internal("the router's lane answer lacks its account".into()));
                };
                lanes.push(json!({"lane": lane, "users": users, "upstream": {"user": user, "password": password}}));
            }
            let view = self.runtime.set_lanes(service, &Value::Array(lanes)).await?;
            let mut withdrawn: Vec<&String> = current.keys().filter(|lane| !wanted.contains_key(*lane)).collect();
            withdrawn.sort();
            for lane in withdrawn {
                let _ = router.lane_forget(protocol, lane).await;
            }
            Ok(view)
        }
        .await;
        let view = match attempt {
            Ok(view) => view,
            Err(LaneError::Internal(message)) => return Err(ReconcileError::Internal(message)),
            Err(LaneError::Adapter(error)) => {
                let code = error.code.filter(|code| !code.is_empty()).unwrap_or_else(|| "manager_unavailable".into());
                log::warn!("fleet: lanes for {protocol} failed: {code}");
                let mut fresh: Vec<&String> =
                    wanted.keys().filter(|lane| !current.contains_key(lane.as_str())).collect();
                fresh.sort();
                if let Some(router) = &router {
                    for lane in fresh {
                        let _ = router.lane_forget(protocol, lane).await;
                    }
                }
                for resource in laned {
                    self.record(
                        generation,
                        resource,
                        "failed",
                        Some(format!("lane: {code}")),
                        None,
                        Some(resource.credential_ref.clone()),
                        None,
                    )
                    .await?;
                }
                return Ok(true);
            }
        };
        // Mieru: a lane user connects to the slot's port — the manager's template for the user is
        // what the central's link needs; leaving the lane, the service's.
        let mut templates: Map<String, Value> = Map::new();
        if let Some(Value::Array(entries)) = get(&view, "lanes") {
            for entry in entries {
                if let Some(Value::Object(found)) = get(entry, "share_templates") {
                    templates.extend(found.clone());
                }
            }
        }
        let service_template = get(&view, "service_share_template").cloned();
        let mut merges: Vec<(String, Map<String, Value>)> = Vec::new();
        for resource in resources {
            if resource.desired_state == DesiredState::Deleted {
                continue;
            }
            let template = if wanted.contains_key(&resource.reference) {
                templates.get(&resource.runtime_username).cloned()
            } else if current.contains_key(&resource.reference) {
                service_template.clone()
            } else {
                None
            };
            if truthy(template.as_ref()) {
                let mut reported = Map::new();
                reported.insert("share_template".into(), template.expect("truthy"));
                let learned = learned_from(resource.protocol, &reported);
                if !learned.is_empty() {
                    merges.push((resource.runtime_username.clone(), learned));
                }
            }
        }
        if let Value::Object(map) = &mut state {
            map.insert(protocol.to_string(), Value::Object(wanted_value));
        } else {
            let mut map = Map::new();
            map.insert(protocol.to_string(), Value::Object(wanted_value));
            state = Value::Object(map);
        }
        let protocol = protocol.to_string();
        self.tx(move |db, managed| {
            managed.write_setting(db, LANES_KEY, Some(&panel_core::pyjson::sorted(&state)))?;
            for (username, learned) in &merges {
                managed.merge_learned(db, &protocol, username, learned)?;
            }
            Ok(())
        })
        .await?;
        Ok(false)
    }

    // -- relay (v0.7, spec §7): this node's relay inbound for chains from other nodes ------------

    async fn record_relay(&self, report: Value) -> Result<(), ReconcileError> {
        self.tx(move |db, managed| {
            Ok(managed.write_setting(db, RELAY_KEY, Some(&panel_core::pyjson::sorted(&report)))?)
        })
        .await
    }

    /// The relay as the section says: the inbound up with the accounts the central issued (their
    /// UUIDs from the push's secrets), or down. No section leaves it as it is.
    async fn apply_relay(&self, section: Option<&RelaySection>) -> Result<bool, ReconcileError> {
        let Some(section) = section else {
            return Ok(false);
        };
        let mut emails: Vec<&str> = section.accounts.iter().map(|account| account.email.as_str()).collect();
        emails.sort();
        let mut refs: Vec<&str> = section.accounts.iter().map(|account| account.credential_ref.as_str()).collect();
        refs.sort();
        let desired = json!({"enabled": section.enabled, "port": section.port, "server_name": section.server_name,
                             "accounts": emails, "refs": refs});
        let previous = self.read(|db, _| Ok(setting_json(db, RELAY_KEY, "null")?)).await?;
        if truthy(Some(&previous))
            && get(&previous, "state").and_then(Value::as_str) == Some("converged")
            && get(&previous, "desired").is_some_and(|previous| panel_model::pyrepr::eq(previous, &desired))
        {
            return Ok(false);
        }
        enum RelayError {
            Code(String),
            Internal(ReconcileError),
        }
        let attempt: Result<Value, RelayError> = async {
            let adapter = |error: AdapterError| {
                RelayError::Code(
                    error.code.filter(|code| !code.is_empty()).unwrap_or_else(|| "manager_unavailable".into()),
                )
            };
            let Some(router) = self.runtime.router() else {
                return Err(RelayError::Code("router_unavailable".into()));
            };
            let Some(mut current) = router.relay().await else {
                return Err(RelayError::Code("router_unavailable".into()));
            };
            if section.enabled {
                let port_differs =
                    !get(&current, "port").is_some_and(|port| panel_model::pyrepr::eq(port, &json!(section.port)));
                let name_differs =
                    get(&current, "server_name").and_then(Value::as_str) != Some(section.server_name.as_str());
                if !truthy(get(&current, "enabled")) || port_differs || name_differs {
                    // Its answer is superseded by the accounts' below, as in Python.
                    router.relay_enable(&section.server_name, section.port).await.map_err(adapter)?;
                }
                let mut accounts = Vec::new();
                for account in &section.accounts {
                    let plaintext = match self.reveal(&account.credential_ref).await {
                        Ok(plaintext) => plaintext,
                        Err(ReconcileError::Secret(_)) => return Err(RelayError::Code("manager_unavailable".into())),
                        Err(other) => return Err(RelayError::Internal(other)),
                    };
                    let uuid = decode(&plaintext)
                        .map_err(|message| RelayError::Internal(ReconcileError::Internal(message)))?;
                    accounts.push(json!({"email": account.email, "uuid": uuid}));
                }
                current = router.relay_set_accounts(&Value::Array(accounts)).await.map_err(adapter)?;
            } else if truthy(get(&current, "enabled")) {
                current = router.relay_disable().await.map_err(adapter)?;
            }
            Ok(current)
        }
        .await;
        let current = match attempt {
            Ok(current) => current,
            Err(RelayError::Internal(error)) => return Err(error),
            Err(RelayError::Code(code)) => {
                log::warn!("fleet: relay failed: {code}");
                self.record_relay(json!({"state": "failed", "error": code, "desired": desired})).await?;
                return Ok(true);
            }
        };
        let short_id = match get(&current, "short_ids") {
            Some(Value::Array(items)) if !items.is_empty() => items[0].clone(),
            _ => Value::Null,
        };
        // The report confirms the accounts the router says it carries: a node without WARP sets the
        // `:warp` ones aside, and the central must not take them as confirmed.
        let accounts = match get(&current, "emails") {
            Some(Value::Array(carried)) => {
                let mut carried = carried.clone();
                carried.sort_by(|a, b| a.as_str().unwrap_or("").cmp(b.as_str().unwrap_or("")));
                Value::Array(carried)
            }
            _ => desired["accounts"].clone(),
        };
        let field = |key: &str| get(&current, key).cloned().unwrap_or(Value::Null);
        self.record_relay(json!({"state": "converged", "enabled": truthy(get(&current, "enabled")),
                                 "port": field("port"), "server_name": field("server_name"),
                                 "public_key": field("public_key"), "short_id": short_id,
                                 "accounts": accounts, "desired": desired}))
            .await?;
        Ok(false)
    }

    // -- the whole generation --------------------------------------------------------------------

    async fn apply_latest(&self, latest: Latest) -> Result<Applied, ReconcileError> {
        let generation = latest.generation;
        let document = latest.document;
        let mut refs: HashMap<Key, String> = HashMap::new();
        for resource in &document.resources {
            refs.insert(
                (resource.protocol.as_str().to_string(), resource.runtime_username.clone()),
                resource.reference.clone(),
            );
        }
        let retire = refs.clone();
        // A `missing` row lingers so the one-time report survives a 202. A generation naming that
        // user under another ref proves the central saw the report: the row is retired here, before
        // the apply — never afterwards, when the regrant may already have rewritten the same row.
        let known = self
            .tx(move |db, managed| {
                managed.set_state(db, generation, "applying")?;
                let mut known = managed.resources(db)?;
                let stale: Vec<Key> = known
                    .iter()
                    .filter(|(key, row)| {
                        let reference = row_str(row, "ref").unwrap_or_default();
                        row.get("state").and_then(Value::as_str) == Some("missing")
                            && retire.get(*key).map_or(reference.as_str(), String::as_str) != reference
                    })
                    .map(|(key, _)| key.clone())
                    .collect();
                for key in stale {
                    managed.remove_resource(db, &key.0, &key.1)?;
                    known.shift_remove(&key);
                }
                Ok(known)
            })
            .await?;
        let mut credentials = IndexMap::new();
        let mut unmanaged: Vec<ObservedResource> = Vec::new();
        let mut failed = false;
        // Defence in depth (finding I2): two resources naming one runtime user race it; neither is
        // applied, both are reported failed, and the name still counts as wanted.
        let mut counts: HashMap<Key, usize> = HashMap::new();
        for resource in &document.resources {
            *counts.entry((resource.protocol.as_str().to_string(), resource.runtime_username.clone())).or_default() +=
                1;
        }
        let mut applicable: Vec<&Resource> = Vec::new();
        for resource in &document.resources {
            let key = (resource.protocol.as_str().to_string(), resource.runtime_username.clone());
            if counts[&key] > 1 {
                failed = true;
                self.record_failed(generation, resource, "duplicate protocol/runtime_username in this generation")
                    .await?;
            } else {
                applicable.push(resource);
            }
        }
        let mut protocols: IndexSet<String> =
            applicable.iter().map(|resource| resource.protocol.as_str().to_string()).collect();
        protocols.extend(known.keys().map(|key| key.0.clone()));
        let mut protocols: Vec<String> = protocols.into_iter().collect();
        protocols.sort();
        for protocol in &protocols {
            let resources: Vec<&Resource> =
                applicable.iter().copied().filter(|resource| resource.protocol.as_str() == protocol).collect();
            let orphans: Vec<String> = known
                .keys()
                .filter(|key| &key.0 == protocol && !refs.contains_key(*key))
                .map(|key| key.1.clone())
                .collect();
            // An adapter that can batch its inventory reads (Telemt) does so for the whole pass.
            let batch = Protocol::from_wire(protocol).and_then(|protocol| self.runtime.batch(protocol));
            failed |= self
                .apply_protocol(protocol, &resources, &orphans, &known, generation, &mut credentials, &mut unmanaged)
                .await?;
            drop(batch);
            // The service's lanes: after its users, before any egress that names them.
            if LANE_PROTOCOLS.contains(&protocol.as_str()) {
                failed |= self.apply_lanes(protocol, &resources, generation).await?;
            }
        }
        // The relay before the egress: a chain from another node may need it.
        failed |= self.apply_relay(document.relay.as_ref()).await?;
        // Egress after the resources: the users are provisioned whatever the routing outcome.
        failed |= self.apply_egress(document.egress.as_ref(), generation).await?;
        let mut observed = self
            .tx(move |db, managed| {
                managed.set_state(db, generation, if failed { "failed" } else { "converged" })?;
                managed.observed(db)?.ok_or_else(|| ReconcileError::Internal("the generation vanished".into()))
            })
            .await?;
        observed.resources.extend(unmanaged);
        Ok((observed, credentials))
    }
}
