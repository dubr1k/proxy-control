//! Creating several accesses as one operation, with a journal that survives a crash
//! (`clients/provisioning.py`).
//!
//! Every step records what it reached before the next one runs, so a restart resumes instead of
//! repeating, and a failure compensates only what this operation created. Every run ends in one of
//! `succeeded`, `compensated` or `manual_intervention_required` — or, for a grant on a linked
//! panel, waits as `pending_remote` until the fleet pusher reports the node's answer
//! ([`ProvisioningService::remote_applied`]).
//!
//! A manager failure the Python adapter let escape (a manager error from `create`, Telemt's lost
//! reply) is not an `AdapterError` there: `run()` re-raises it, the journal stays where it was and
//! the next run resumes — it never compensates. [`ClientsError::runtime`] recognises those.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use panel_core::clock::SharedClock;
use panel_core::db::{Conn, Database};
use panel_core::pyjson;
use panel_core::rusqlite::{params, OptionalExtension as _};
use panel_model::clients::{
    AccessGrant, GrantDesiredState, GrantIntent, GrantObservedState, GrantOrigin, ProtocolOptions,
};
use panel_model::fleet::{CredentialOrigin, ObservedGeneration, ObservedState};
use panel_model::protocols::{AdapterError, CredentialPlan, GrantRef};
use panel_model::{Protocol, SecretRef};
use panel_secrets::secrets_store::SecretStore;
use serde_json::{json, Map, Value};

use crate::context::{Audit, AuditContext};
use crate::hosts::PublicHosts;
use crate::service::{new_credential, reveal_credential, store_credential, store_ref, Adapters, ClientService};
use crate::store::{self, GrantUpdate};
use crate::{blocking, ClientsError, LOCAL_NODE_ID};

/// `TERMINAL`.
pub const TERMINAL: [&str; 3] = ["succeeded", "compensated", "manual_intervention_required"];
/// `CREATED`: a step never skips backwards; each transition is its own durable checkpoint.
pub const CREATED: [&str; 3] = ["applied", "escrowed", "active"];
/// `SETTLED`: steps `run()` has nothing to do for.
pub const SETTLED: [&str; 2] = ["active", "remote"];

/// `is_remote_node(db, node_id)`: a grant on a linked panel is applied by that panel's reconcile.
pub fn is_remote_node(db: &Conn, node_id: &str) -> Result<bool, ClientsError> {
    let transport: Option<String> = db
        .query_row("SELECT transport FROM fleet_nodes WHERE node_id=?", params![node_id], |row| row.get(0))
        .optional()?;
    Ok(transport.as_deref() == Some("panel"))
}

/// One step of the journal (`{"grant_id", "protocol", "status", "error"}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub grant_id: String,
    pub protocol: String,
    pub status: String,
    pub error: Option<String>,
}

impl Step {
    /// The step as `json.loads(steps_json)` gives it back: keys sorted, as they were written.
    pub fn to_json(&self) -> Value {
        json!({"error": self.error, "grant_id": self.grant_id, "protocol": self.protocol, "status": self.status})
    }

    fn from_json(value: &Value) -> Result<Self, ClientsError> {
        let text = |key: &str| -> Result<String, ClientsError> {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| ClientsError::Internal(format!("provisioning step without {key}")))
        };
        let error = match value.get("error") {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) => Some(text.clone()),
            Some(other) => Some(panel_model::pyrepr::str(other)),
        };
        Ok(Self { grant_id: text("grant_id")?, protocol: text("protocol")?, status: text("status")?, error })
    }
}

/// `json.dumps(steps, sort_keys=True)`.
pub fn steps_json(steps: &[Step]) -> String {
    pyjson::sorted(&Value::Array(steps.iter().map(Step::to_json).collect()))
}

/// A `provisioning_operations` row with its parsed steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    pub operation_id: String,
    pub client_id: String,
    pub status: String,
    pub steps: Vec<Step>,
}

/// One step of an [`OperationResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepResult {
    pub grant_id: String,
    pub protocol: String,
    pub status: String,
    pub error: Option<String>,
}

/// What `run()` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationResult {
    pub operation_id: String,
    pub status: String,
    pub steps: Vec<StepResult>,
}

/// The saga's fault injection (`self.faults`): a test hook only — production never sets one.
#[derive(Debug, Clone, Default)]
pub struct Faults(Arc<Mutex<HashMap<String, String>>>);

impl Faults {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `faults[name] = value` (`before_first_apply`, `after_apply` = protocol,
    /// `during_compensation`, `before_remote_commit`).
    pub fn set(&self, name: &str, value: &str) {
        self.map().insert(name.to_string(), value.to_string());
    }

    pub fn clear(&self) {
        self.map().clear();
    }

    fn pop(&self, name: &str) -> bool {
        self.map().remove(name).is_some_and(|value| !value.is_empty())
    }

    fn get(&self, name: &str) -> Option<String> {
        self.map().get(name).cloned()
    }
}

/// The provisioning saga (`ProvisioningService`). Cheap to clone; clones share the faults.
#[derive(Clone)]
pub struct ProvisioningService {
    database: Database,
    secrets: SecretStore,
    adapters: Adapters,
    clients: ClientService,
    clock: SharedClock,
    pub faults: Faults,
}

impl std::fmt::Debug for ProvisioningService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisioningService").finish_non_exhaustive()
    }
}

fn read_operation(db: &Conn, operation_id: &str) -> Result<Operation, ClientsError> {
    let row: Option<(String, String, String)> = db
        .query_row(
            "SELECT client_id, status, steps_json FROM provisioning_operations WHERE operation_id=?",
            params![operation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (client_id, status, steps_json) = row.ok_or_else(|| ClientsError::NotFound(operation_id.to_string()))?;
    let steps: Value = serde_json::from_str(&steps_json)
        .map_err(|error| ClientsError::Internal(format!("provisioning steps_json: {error}")))?;
    let steps = steps
        .as_array()
        .ok_or_else(|| ClientsError::Internal("provisioning steps_json is not a list".into()))?
        .iter()
        .map(Step::from_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Operation { operation_id: operation_id.to_string(), client_id, status, steps })
}

/// `entry.get(key)` of a JSON object, `None` for anything else.
fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_object().and_then(|map| map.get(key))
}

/// Python's `needle in container` for what a node's identity may hold.
fn contains(container: Option<&Value>, needle: &str) -> bool {
    match container {
        Some(Value::Array(items)) => items.iter().any(|item| item.as_str() == Some(needle)),
        Some(Value::Object(map)) => map.contains_key(needle),
        Some(Value::String(text)) => text.contains(needle),
        _ => false,
    }
}

/// The linked node's identity (`node_links.identity_json`), `{}` without one.
fn node_identity(db: &Conn, node_id: &str) -> Result<Value, ClientsError> {
    let identity: Option<String> = db
        .query_row("SELECT identity_json FROM node_links WHERE node_id=?", params![node_id], |row| row.get(0))
        .optional()?;
    match identity.filter(|text| !text.is_empty()) {
        Some(text) => {
            serde_json::from_str(&text).map_err(|error| ClientsError::Internal(format!("identity_json: {error}")))
        }
        None => Ok(json!({})),
    }
}

/// `(identity.get("protocols") or {}).get(protocol) or {}`.
fn protocol_entry<'a>(identity: &'a Value, protocol: &str) -> Option<&'a Value> {
    get(identity, "protocols").filter(|value| crate::truthy(value)).and_then(|protocols| get(protocols, protocol))
}

impl ProvisioningService {
    pub fn new(
        database: Database,
        secrets: SecretStore,
        adapters: Adapters,
        clients: ClientService,
        clock: SharedClock,
    ) -> Self {
        Self { database, secrets, adapters, clients, clock, faults: Faults::default() }
    }

    pub fn clients(&self) -> &ClientService {
        &self.clients
    }

    fn now(&self) -> i64 {
        self.clock.now()
    }

    // --- journal ---------------------------------------------------------------------------

    fn write(&self, db: &Conn, operation_id: &str, status: &str, steps: &[Step]) -> Result<(), ClientsError> {
        db.execute(
            "UPDATE provisioning_operations SET status=?,steps_json=?,updated_at=? WHERE operation_id=?",
            params![status, steps_json(steps), self.now(), operation_id],
        )?;
        Ok(())
    }

    /// `_mark_step`: one durable checkpoint per transition, in its own transaction.
    fn mark_step(
        &self,
        operation_id: &str,
        grant_id: &str,
        status: &str,
        error: Option<String>,
    ) -> Result<(), ClientsError> {
        self.database.transaction(|db| {
            let mut operation = read_operation(db, operation_id)?;
            for step in operation.steps.iter_mut().filter(|step| step.grant_id == grant_id) {
                step.status = status.to_string();
                step.error = error.clone();
            }
            self.write(db, operation_id, &operation.status, &operation.steps)
        })
    }

    fn mark_operation(&self, operation_id: &str, status: &str) -> Result<(), ClientsError> {
        self.database.transaction(|db| {
            let operation = read_operation(db, operation_id)?;
            self.write(db, operation_id, status, &operation.steps)
        })
    }

    async fn mark_step_async(
        &self,
        operation_id: &str,
        grant_id: &str,
        status: &str,
        error: Option<String>,
    ) -> Result<(), ClientsError> {
        let (this, operation_id, grant_id, status) =
            (self.clone(), operation_id.to_string(), grant_id.to_string(), status.to_string());
        blocking(move || this.mark_step(&operation_id, &grant_id, &status, error)).await
    }

    async fn mark_operation_async(&self, operation_id: &str, status: &str) -> Result<(), ClientsError> {
        let (this, operation_id, status) = (self.clone(), operation_id.to_string(), status.to_string());
        blocking(move || this.mark_operation(&operation_id, &status)).await
    }

    /// The journal row.
    pub fn operation(&self, operation_id: &str) -> Result<Operation, ClientsError> {
        self.database.with_connection(|db| read_operation(db, operation_id))
    }

    /// `status(operation_id)`: `{"operation_id", "client_id", "status", "steps"}`.
    pub fn status(&self, operation_id: &str) -> Result<Value, ClientsError> {
        let operation = self.operation(operation_id)?;
        Ok(json!({
            "operation_id": operation_id,
            "client_id": operation.client_id,
            "status": operation.status,
            "steps": operation.steps.iter().map(Step::to_json).collect::<Vec<_>>(),
        }))
    }

    // --- start -----------------------------------------------------------------------------

    /// `_require_awg_version`: a linked panel applies an AmneziaWG grant only if it declared the
    /// capability, runs the protocol and serves the chosen version.
    fn require_awg_version(db: &Conn, intent: &GrantIntent) -> Result<(), ClientsError> {
        let identity = node_identity(db, &intent.node_id)?;
        if !contains(get(&identity, "capabilities"), "protocol.amneziawg.v1") {
            return Err(ClientsError::Conflict("amneziawg: the node runs a panel version without AmneziaWG".into()));
        }
        let entry = protocol_entry(&identity, "amneziawg");
        if !entry.and_then(|entry| get(entry, "enabled")).is_some_and(crate::truthy) {
            return Err(ClientsError::Conflict("amneziawg: AmneziaWG is not enabled on this node".into()));
        }
        let version = match &intent.options {
            ProtocolOptions::Amneziawg(options) => options.version.as_str(),
            _ => "",
        };
        if !contains(entry.and_then(|entry| get(entry, "versions")), version) {
            return Err(ClientsError::Conflict(format!("amneziawg: version {version} is not served by this node")));
        }
        Ok(())
    }

    /// `_require_trusttunnel`.
    fn require_trusttunnel(db: &Conn, intent: &GrantIntent) -> Result<(), ClientsError> {
        let identity = node_identity(db, &intent.node_id)?;
        if !contains(get(&identity, "capabilities"), "protocol.trusttunnel.v1") {
            return Err(ClientsError::Conflict(
                "trusttunnel: the node runs a panel version without TrustTunnel".into(),
            ));
        }
        let entry = protocol_entry(&identity, "trusttunnel");
        if !entry.and_then(|entry| get(entry, "enabled")).is_some_and(crate::truthy) {
            return Err(ClientsError::Conflict("trusttunnel: TrustTunnel is not enabled on this node".into()));
        }
        Ok(())
    }

    /// `start(client_id, intents, …)`: reserves every row of the operation, or none of them, and
    /// answers the operation id. Each runtime is asked first whether the name is free (a grant on
    /// a linked panel skips that: its node answers through its generation).
    pub async fn start(
        &self,
        client_id: &str,
        intents: Vec<GrantIntent>,
        context: &AuditContext,
    ) -> Result<String, ClientsError> {
        if intents.is_empty() {
            return Err(ClientsError::Conflict("an operation needs at least one grant".into()));
        }
        let remote: HashSet<String> = {
            let (database, intents) = (self.database.clone(), intents.clone());
            blocking(move || {
                database.with_connection(|db| {
                    let mut remote = HashSet::new();
                    for intent in &intents {
                        if is_remote_node(db, &intent.node_id)? {
                            remote.insert(intent.node_id.clone());
                        }
                    }
                    for intent in &intents {
                        if intent.node_id != LOCAL_NODE_ID && !remote.contains(&intent.node_id) {
                            return Err(ClientsError::Conflict(format!(
                                "node {} is not a linked panel",
                                intent.node_id
                            )));
                        }
                        if intent.node_id == LOCAL_NODE_ID
                            && crate::managed::is_managed(db, intent.protocol.as_str(), &intent.runtime_username)?
                        {
                            return Err(ClientsError::Conflict(format!(
                                "{}: runtime_username is managed by central",
                                intent.protocol
                            )));
                        }
                        if intent.protocol == Protocol::Amneziawg && remote.contains(&intent.node_id) {
                            Self::require_awg_version(db, intent)?;
                        }
                        if intent.protocol == Protocol::Trusttunnel && remote.contains(&intent.node_id) {
                            Self::require_trusttunnel(db, intent)?;
                        }
                    }
                    Ok(remote)
                })
            })
            .await?
        };
        for intent in &intents {
            if remote.contains(&intent.node_id) {
                continue;
            }
            let adapter = self.adapters.require(intent.protocol)?;
            let check =
                adapter.preflight(intent).await.map_err(|error| ClientsError::adapter(intent.protocol, error))?;
            if !check.ok {
                let reason = check.reason.unwrap_or_else(|| "None".into());
                return Err(ClientsError::Conflict(format!("{}: {reason}", intent.protocol)));
            }
        }
        let (this, client_id, context) = (self.clone(), client_id.to_string(), context.clone());
        blocking(move || this.reserve(&client_id, &intents, &remote, &context)).await
    }

    fn reserve(
        &self,
        client_id: &str,
        intents: &[GrantIntent],
        remote: &HashSet<String>,
        context: &AuditContext,
    ) -> Result<String, ClientsError> {
        let operation_id = panel_core::ids::uuid4();
        let now = self.now();
        self.database.transaction(|db| {
            store::client(db, client_id)?;
            let mut steps = Vec::new();
            for intent in intents {
                let is_remote = remote.contains(&intent.node_id);
                let origin =
                    if is_remote { None } else { Some(self.adapters.require(intent.protocol)?.credential_origin()) };
                let taken = store::find_grant(
                    db,
                    intent.protocol.as_str(),
                    &intent.node_id,
                    &intent.endpoint_id,
                    &intent.runtime_username,
                )?;
                if taken.is_some() {
                    return Err(ClientsError::Conflict("runtime_username is already granted on this endpoint".into()));
                }
                let grant_id = panel_core::ids::uuid4();
                store::insert_grant(
                    db,
                    &AccessGrant {
                        protocol: intent.protocol,
                        options: intent.options.clone(),
                        id: grant_id.clone(),
                        client_id: client_id.to_string(),
                        node_id: intent.node_id.clone(),
                        endpoint_id: intent.endpoint_id.clone(),
                        runtime_username: intent.runtime_username.clone(),
                        // A remote grant points at its credential from the start: the generation
                        // names that version, and a rotation must retire it.
                        secret_ref: is_remote.then(|| SecretRef::new(format!("grant:{grant_id}"), 1)),
                        desired_state: GrantDesiredState::Enabled,
                        observed_state: GrantObservedState::Pending,
                        valid_from: intent.valid_from,
                        valid_until: intent.valid_until,
                        origin: GrantOrigin::Provisioned,
                        own_lane: false,
                        label: None,
                        created_at: now,
                        updated_at: now,
                    },
                )?;
                if is_remote || origin == Some(CredentialOrigin::Caller) {
                    // Escrowed before the manager ever sees it: a lost reply never costs the
                    // subscriber their access.
                    store_credential(
                        &self.secrets,
                        db,
                        &grant_id,
                        1,
                        &intent.node_id,
                        &new_credential(intent.protocol),
                        "pending",
                    )?;
                }
                steps.push(Step {
                    grant_id,
                    protocol: intent.protocol.as_str().into(),
                    status: if is_remote { "remote" } else { "pending" }.into(),
                    error: None,
                });
            }
            db.execute(
                "INSERT INTO provisioning_operations(operation_id,client_id,status,steps_json,created_at,updated_at)
                   VALUES(?,?,?,?,?,?)",
                params![
                    operation_id,
                    client_id,
                    if remote.is_empty() { "pending" } else { "pending_remote" },
                    steps_json(&steps),
                    now,
                    now
                ],
            )?;
            Audit::new(context, "grant.provision.start", &operation_id)
                .detail(json!({
                    "client_id": client_id,
                    "protocols": intents.iter().map(|intent| intent.protocol.as_str()).collect::<Vec<_>>(),
                }))
                .write(db)?;
            if !remote.is_empty() {
                // The generation that carries the remote grants is published in this same
                // transaction: a rolled-back operation leaves nothing for the pusher.
                self.clients.notify(db, client_id)?;
            }
            if self.faults.pop("before_remote_commit") {
                return Err(ClientsError::Injected("injected before the remote commit".into()));
            }
            Ok(operation_id.clone())
        })
    }

    // --- run -------------------------------------------------------------------------------

    fn grant(&self, grant_id: &str) -> Result<AccessGrant, ClientsError> {
        self.database.with_connection(|db| store::grant(db, grant_id))
    }

    async fn grant_async(&self, grant_id: &str) -> Result<AccessGrant, ClientsError> {
        let (this, grant_id) = (self.clone(), grant_id.to_string());
        blocking(move || this.grant(&grant_id)).await
    }

    /// `_credential(grant)`: the manager chooses, or the escrowed version 1.
    fn credential(&self, grant: &AccessGrant) -> Result<CredentialPlan, ClientsError> {
        let adapter = self.adapters.require(grant.protocol)?;
        if adapter.credential_origin() == CredentialOrigin::Manager {
            return Ok(CredentialPlan::manager());
        }
        let reference = SecretRef::new(format!("grant:{}", grant.id), 1);
        let plaintext = self.database.with_connection(|db| reveal_credential(&self.secrets, db, &reference, grant))?;
        CredentialPlan::caller(plaintext).map_err(|error| ClientsError::adapter(grant.protocol, error))
    }

    fn intent(grant: &AccessGrant) -> GrantIntent {
        GrantIntent {
            protocol: grant.protocol,
            options: grant.options.clone(),
            node_id: grant.node_id.clone(),
            endpoint_id: grant.endpoint_id.clone(),
            runtime_username: grant.runtime_username.clone(),
            valid_from: grant.valid_from,
            valid_until: grant.valid_until,
        }
    }

    fn escrow_manager_credential(&self, grant: &AccessGrant, plaintext: &[u8]) -> Result<(), ClientsError> {
        self.database.transaction(|db| {
            let existing = db
                .query_row(
                    "SELECT 1 FROM secret_versions WHERE secret_id=? AND version=1",
                    params![format!("grant:{}", grant.id)],
                    |_| Ok(()),
                )
                .optional()?;
            if existing.is_none() {
                store_credential(&self.secrets, db, &grant.id, 1, &grant.node_id, plaintext, "pending")?;
            }
            Ok(())
        })
    }

    /// `remember_template(db, grant, artifact_template)`: keep what the runtime reported that the
    /// protocol's options model has a field for (Mieru's share template, Telemt's host and port),
    /// through the model's validators. In the caller's transaction.
    pub fn remember_template(
        &self,
        db: &Conn,
        grant: &AccessGrant,
        template: &Map<String, Value>,
    ) -> Result<(), ClientsError> {
        let fields = ProtocolOptions::field_names(grant.protocol);
        let learned: Vec<(&String, &Value)> = template
            .iter()
            .filter(|(key, value)| fields.contains(&key.as_str()) && !value.is_null() && value.as_str() != Some(""))
            .collect();
        let current = grant.options.dump();
        if learned.is_empty()
            || learned.iter().all(|(key, value)| {
                current.get(key.as_str()).is_some_and(|known| panel_model::pyrepr::eq(known, value))
            })
        {
            return Ok(());
        }
        let mut merged = current.as_object().cloned().unwrap_or_default();
        for (key, value) in &learned {
            merged.insert((*key).clone(), (*value).clone());
        }
        let options = match ProtocolOptions::validate(grant.protocol, &Value::Object(merged)) {
            Ok(options) => options,
            Err(error) => {
                let text = error.to_string();
                let first: String = text.lines().next().unwrap_or("").chars().take(200).collect();
                log::warn!("grant {}: learned options refused, keeping the current ones: {first}", grant.id);
                return Ok(());
            }
        };
        store::update_grant(db, &grant.id, &GrantUpdate::new().options_json(options.dump_json()).at(self.now()))
    }

    fn activate(&self, grant: &AccessGrant) -> Result<(), ClientsError> {
        let reference = SecretRef::new(format!("grant:{}", grant.id), 1);
        self.database.transaction(|db| {
            self.secrets.transition(db, &store_ref(&reference), "active")?;
            let observed = store::grant(db, &grant.id)?.observed_state;
            store::update_grant(
                db,
                &grant.id,
                &GrantUpdate::new().secret(reference.clone()).observed(observed).at(self.now()),
            )?;
            self.clients.notify(db, &grant.client_id)
        })
    }

    /// `run(operation_id)`: advances every unsettled step; an `AdapterError` compensates, a
    /// `ManualInterventionRequired` stops for a person, anything else (an escaped manager failure,
    /// a crash) is re-raised with the journal where it was.
    pub async fn run(&self, operation_id: &str) -> Result<OperationResult, ClientsError> {
        let operation = {
            let (this, id) = (self.clone(), operation_id.to_string());
            blocking(move || this.operation(&id)).await?
        };
        if TERMINAL.contains(&operation.status.as_str()) {
            return self.result(operation_id).await;
        }
        if operation.steps.iter().any(|step| !SETTLED.contains(&step.status.as_str())) {
            self.mark_operation_async(operation_id, "applying").await?;
        }
        for mut step in operation.steps {
            if SETTLED.contains(&step.status.as_str()) {
                continue; // a `remote` step is the node's to finish; see remote_applied()
            }
            match self.advance(operation_id, &mut step).await {
                Ok(()) => {}
                Err(error) if error.is_manual_intervention() => {
                    self.mark_step_async(operation_id, &step.grant_id, "manual", Some(error.to_string())).await?;
                    self.mark_operation_async(operation_id, "manual_intervention_required").await?;
                    return self.result(operation_id).await;
                }
                Err(error) if error.is_adapter_error() => {
                    let status = step.status.clone();
                    self.mark_step_async(operation_id, &step.grant_id, &status, Some(error.to_string())).await?;
                    return self.compensate(operation_id, &error.to_string()).await;
                }
                // An injected or unexpected crash, or a manager failure whose outcome is unknown:
                // the next run resumes from the last durable checkpoint.
                Err(error) => return Err(error),
            }
        }
        // The journal decides, not this loop's snapshot: a node may have reported a remote step
        // applied while the local ones were running.
        let steps = {
            let (this, id) = (self.clone(), operation_id.to_string());
            blocking(move || this.operation(&id)).await?.steps
        };
        let waiting = steps.iter().any(|step| step.status == "remote");
        self.mark_operation_async(operation_id, if waiting { "pending_remote" } else { "succeeded" }).await?;
        self.result(operation_id).await
    }

    async fn advance(&self, operation_id: &str, step: &mut Step) -> Result<(), ClientsError> {
        let grant = self.grant_async(&step.grant_id).await?;
        let adapter = self.adapters.require(grant.protocol)?;
        if step.status == "pending" {
            if self.faults.pop("before_first_apply") {
                return Err(ClientsError::Injected("injected before the first apply".into()));
            }
            let plan = {
                let (this, grant) = (self.clone(), grant.clone());
                blocking(move || this.credential(&grant)).await?
            };
            let intent = Self::intent(&grant);
            let applied = adapter
                .create(&format!("{operation_id}:{}", grant.id), &intent, &plan)
                .await
                .map_err(|error| ClientsError::adapter(grant.protocol, error))?;
            let manager_credential = (adapter.credential_origin() == CredentialOrigin::Manager)
                .then(|| applied.credential.clone().filter(|bytes| !bytes.is_empty()))
                .flatten();
            {
                let (this, grant, template) = (self.clone(), grant.clone(), applied.artifact_template.clone());
                blocking(move || {
                    if let Some(credential) = manager_credential {
                        this.escrow_manager_credential(&grant, &credential)?;
                    }
                    this.database.transaction(|db| this.remember_template(db, &grant, &template))
                })
                .await?;
            }
            self.mark_step_async(operation_id, &grant.id, "applied", None).await?;
            step.status = "applied".into();
            if self.faults.get("after_apply").as_deref() == Some(grant.protocol.as_str()) {
                return Err(ClientsError::adapter(
                    grant.protocol,
                    AdapterError::new(format!("injected after applying {}", grant.protocol)),
                ));
            }
        }
        if step.status == "applied" {
            self.mark_step_async(operation_id, &grant.id, "escrowed", None).await?;
            step.status = "escrowed".into();
        }
        if step.status == "escrowed" {
            self.clients.reconcile_access(Some(&grant.client_id), true).await?;
            if self.grant_async(&grant.id).await?.observed_state == GrantObservedState::Pending {
                return Err(ClientsError::adapter(
                    grant.protocol,
                    AdapterError::new("runtime access could not be confirmed"),
                ));
            }
            {
                let (this, grant) = (self.clone(), grant.clone());
                blocking(move || this.activate(&grant)).await?;
            }
            self.mark_step_async(operation_id, &grant.id, "active", None).await?;
            step.status = "active".into();
        }
        Ok(())
    }

    /// `_compensate`: undo only what this operation created; anything pre-existing is never
    /// touched.
    async fn compensate(&self, operation_id: &str, reason: &str) -> Result<OperationResult, ClientsError> {
        self.mark_operation_async(operation_id, "compensating").await?;
        let operation = {
            let (this, id) = (self.clone(), operation_id.to_string());
            blocking(move || this.operation(&id)).await?
        };
        let mut outcome = "compensated";
        for step in &operation.steps {
            if !CREATED.contains(&step.status.as_str()) {
                // Nothing reached the manager for this step.
                self.mark_step_async(operation_id, &step.grant_id, "compensated", None).await?;
                continue;
            }
            let grant = match self.grant_async(&step.grant_id).await {
                Ok(grant) => grant,
                Err(ClientsError::NotFound(_)) => {
                    // Deleted by an operator and purged once its removal was confirmed.
                    self.mark_step_async(operation_id, &step.grant_id, "compensated", None).await?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let remote = {
                let (database, node_id) = (self.database.clone(), grant.node_id.clone());
                blocking(move || database.with_connection(|db| is_remote_node(db, &node_id))).await?
            };
            if remote {
                // `active` means the node confirmed it; the local runtime may hold an unrelated user
                // of that name. The `deleted` below withdraws it through the next generation.
                self.mark_step_async(operation_id, &grant.id, "compensated", None).await?;
                continue;
            }
            let deleted = if self.faults.pop("during_compensation") {
                Err(ClientsError::adapter(grant.protocol, AdapterError::new("injected during compensation")))
            } else {
                let adapter = self.adapters.require(grant.protocol)?;
                let reference = GrantRef {
                    protocol: grant.protocol,
                    runtime_username: grant.runtime_username.clone(),
                    revision: None,
                };
                adapter.delete(&reference).await.map_err(|error| ClientsError::adapter(grant.protocol, error))
            };
            match deleted {
                Ok(()) => {}
                Err(error) if error.is_adapter_error() => {
                    // The account may still exist; deleting blindly on a retry could remove
                    // something else, so a person gets the operation id.
                    self.mark_step_async(operation_id, &grant.id, "manual", Some(error.to_string())).await?;
                    outcome = "manual_intervention_required";
                    continue;
                }
                Err(error) => return Err(error),
            }
            self.mark_step_async(operation_id, &grant.id, "compensated", None).await?;
            let (this, grant_id) = (self.clone(), grant.id.clone());
            blocking(move || this.database.transaction(|db| this.clients.purge_grant(db, &grant_id))).await?;
        }
        let (this, id, reason, outcome_text) =
            (self.clone(), operation_id.to_string(), reason.to_string(), outcome.to_string());
        blocking(move || {
            this.database.transaction(|db| {
                let operation = read_operation(db, &id)?;
                let compensated: Vec<&Step> =
                    operation.steps.iter().filter(|step| step.status == "compensated").collect();
                for step in &compensated {
                    let node: Option<String> = db
                        .query_row("SELECT node_id FROM access_grants WHERE id=?", params![step.grant_id], |row| {
                            row.get(0)
                        })
                        .optional()?;
                    let Some(node) = node else {
                        continue; // purged: confirmed gone, or removed above
                    };
                    if is_remote_node(db, &node)? {
                        // Withdrawn by the next generation; the pusher purges it once confirmed.
                        store::update_grant(
                            db,
                            &step.grant_id,
                            &GrantUpdate::new().desired(GrantDesiredState::Deleted).at(this.now()),
                        )?;
                    } else {
                        this.clients.purge_grant(db, &step.grant_id)?; // nothing reached the manager
                    }
                }
                if !compensated.is_empty() {
                    this.clients.notify(db, &operation.client_id)?;
                }
                Ok::<(), ClientsError>(())
            })?;
            this.database.transaction(|db| {
                Audit::new(&AuditContext::system(), format!("grant.provision.{outcome_text}"), &id)
                    .detail(json!({"reason": reason}))
                    .write(db)
                    .map_err(ClientsError::from)
            })?;
            this.mark_operation(&id, &outcome_text)
        })
        .await?;
        self.result(operation_id).await
    }

    async fn result(&self, operation_id: &str) -> Result<OperationResult, ClientsError> {
        let (this, id) = (self.clone(), operation_id.to_string());
        let operation = blocking(move || this.operation(&id)).await?;
        Ok(OperationResult {
            operation_id: operation_id.to_string(),
            status: operation.status,
            steps: operation
                .steps
                .into_iter()
                .map(|step| StepResult {
                    grant_id: step.grant_id,
                    protocol: step.protocol,
                    status: step.status,
                    error: step.error,
                })
                .collect(),
        })
    }

    // --- remote (called by the fleet pusher, inside its transaction) ----------------------

    /// `confirm_credential(db, grant_id)`: the node applied the grant with the version it names —
    /// `pending` becomes `active`, and once active the versions a rotation left `retiring` are
    /// revoked. Any other state stands.
    pub fn confirm_credential(&self, db: &Conn, grant_id: &str) -> Result<(), ClientsError> {
        let grant = store::grant(db, grant_id)?;
        let Some(reference) = grant.secret_ref else {
            return Ok(());
        };
        let mut state: Option<String> = db
            .query_row(
                "SELECT state FROM secret_versions WHERE secret_id=? AND version=?",
                params![reference.secret_id, reference.version],
                |row| row.get(0),
            )
            .optional()?;
        if state.as_deref() == Some("pending") {
            self.secrets.transition(db, &store_ref(&reference), "active")?;
            state = Some("active".into());
        }
        if state.as_deref() != Some("active") {
            return Ok(());
        }
        let retiring: Vec<i64> = {
            let mut statement =
                db.prepare("SELECT version FROM secret_versions WHERE secret_id=? AND state='retiring'")?;
            let rows = statement.query_map(params![reference.secret_id], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for version in retiring {
            self.secrets.transition(
                db,
                &store_ref(&SecretRef::new(reference.secret_id.clone(), version)),
                "revoked",
            )?;
        }
        Ok(())
    }

    /// `escrow_returned_credential(db, grant_id, credential_ref, plaintext)`: a credential the
    /// node's runtime chose itself, escrowed under exactly the `secret_id:version` the generation
    /// named, replacing that row in place; `active` from here on.
    pub fn escrow_returned_credential(
        &self,
        db: &Conn,
        grant_id: &str,
        credential_ref: &str,
        plaintext: &str,
    ) -> Result<(), ClientsError> {
        let (secret_id, version) = credential_ref.rsplit_once(':').unwrap_or(("", credential_ref));
        if secret_id != format!("grant:{grant_id}")
            || version.is_empty()
            || !version.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(ClientsError::Invalid("credential_ref does not belong to this grant".into()));
        }
        let version: i64 = version
            .parse()
            .map_err(|_| ClientsError::Invalid("credential_ref does not belong to this grant".into()))?;
        let grant = store::grant(db, grant_id)?;
        let reference = SecretRef::new(secret_id, version);
        if self.holds(db, &reference, &grant, plaintext)? {
            // The value in escrow is the one the node runs: only a `pending` version to activate.
            self.secrets.transition(db, &store_ref(&reference), "active")?;
            return Ok(());
        }
        db.execute("DELETE FROM secret_versions WHERE secret_id=? AND version=?", params![secret_id, version])?;
        let stored =
            store_credential(&self.secrets, db, grant_id, version, &grant.node_id, plaintext.as_bytes(), "active")?;
        if grant.secret_ref.is_none() {
            store::update_grant(
                db,
                &grant.id,
                &GrantUpdate::new().secret(SecretRef::new(stored.secret_id, stored.version)).at(self.now()),
            )?;
        }
        Ok(())
    }

    /// `_holds`: the version already stores this very plaintext for this grant (not revoked).
    fn holds(
        &self,
        db: &Conn,
        reference: &SecretRef,
        grant: &AccessGrant,
        plaintext: &str,
    ) -> Result<bool, ClientsError> {
        let state: Option<String> = db
            .query_row(
                "SELECT state FROM secret_versions WHERE secret_id=? AND version=?",
                params![reference.secret_id, reference.version],
                |row| row.get(0),
            )
            .optional()?;
        if state.is_none() || state.as_deref() == Some("revoked") {
            return Ok(false);
        }
        match reveal_credential(&self.secrets, db, reference, grant) {
            Ok(current) => Ok(crate::same_bytes(&current, plaintext.as_bytes())),
            Err(ClientsError::Secret(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn waiting(db: &Conn) -> Result<Vec<String>, ClientsError> {
        let mut statement = db.prepare(
            "SELECT operation_id FROM provisioning_operations WHERE status IN ('pending_remote','applying')",
        )?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// `_settled(operation)`.
    fn settled(status: &str, steps: &[Step]) -> String {
        if status != "pending_remote" || steps.iter().any(|step| step.status == "remote") {
            return status.to_string();
        }
        if steps.iter().any(|step| step.status == "active") { "succeeded" } else { "compensated" }.to_string()
    }

    /// `remote_applied(db, observed, withheld=…, withheld_error=…)`: what one node reported,
    /// applied to the operations waiting for it.
    pub fn remote_applied(
        &self,
        db: &Conn,
        observed: &ObservedGeneration,
        withheld: &HashSet<String>,
        withheld_error: Option<&str>,
    ) -> Result<(), ClientsError> {
        let reported: HashMap<&str, _> = observed
            .resources
            .iter()
            .map(|item| (item.reference.strip_prefix("grant:").unwrap_or(&item.reference), item))
            .collect();
        for operation_id in Self::waiting(db)? {
            let mut operation = read_operation(db, &operation_id)?;
            let mut changed = false;
            for step in operation.steps.iter_mut() {
                let Some(item) = reported.get(step.grant_id.as_str()) else {
                    continue;
                };
                if step.status != "remote" {
                    continue;
                }
                if withheld.contains(&step.grant_id) {
                    if let Some(error) = withheld_error {
                        if step.error.as_deref() != Some(error) {
                            step.error = Some(error.to_string());
                            changed = true;
                        }
                    }
                    continue;
                }
                match item.state {
                    ObservedState::Enabled | ObservedState::Disabled => {
                        let state = if item.state == ObservedState::Enabled {
                            GrantObservedState::Enabled
                        } else {
                            GrantObservedState::Disabled
                        };
                        let confirmed = self.confirm_credential(db, &step.grant_id).and_then(|()| {
                            store::update_grant(db, &step.grant_id, &GrantUpdate::new().observed(state).at(self.now()))
                        });
                        match confirmed {
                            Ok(()) => {}
                            Err(ClientsError::NotFound(_)) => continue, // purged once its deletion was confirmed
                            Err(error) => return Err(error),
                        }
                        step.status = "active".into();
                        step.error = None;
                        changed = true;
                    }
                    ObservedState::Failed if step.error != item.error => {
                        step.error = item.error.clone();
                        changed = true;
                    }
                    _ => {}
                }
            }
            if changed {
                let status = Self::settled(&operation.status, &operation.steps);
                self.write(db, &operation_id, &status, &operation.steps)?;
            }
        }
        Ok(())
    }

    /// `withdraw_remote(db, grant_id, reason=…)`: the grant was deleted before its node applied it;
    /// its `remote` step ends `compensated` and the operation settles now.
    pub fn withdraw_remote(&self, db: &Conn, grant_id: &str, reason: &str) -> Result<(), ClientsError> {
        for operation_id in Self::waiting(db)? {
            let mut operation = read_operation(db, &operation_id)?;
            let mut changed = false;
            for step in operation.steps.iter_mut() {
                if step.grant_id == grant_id && step.status == "remote" {
                    step.status = "compensated".into();
                    step.error = Some(reason.to_string());
                    changed = true;
                }
            }
            if changed {
                let status = Self::settled(&operation.status, &operation.steps);
                self.write(db, &operation_id, &status, &operation.steps)?;
            }
        }
        Ok(())
    }

    // --- bundle ----------------------------------------------------------------------------

    /// `_live_grant(db, step)`.
    fn live_grant(db: &Conn, step: &Step) -> Result<Option<AccessGrant>, ClientsError> {
        if step.status != "active" {
            return Ok(None);
        }
        match store::grant(db, &step.grant_id) {
            Ok(grant) if grant.desired_state != GrantDesiredState::Deleted => Ok(Some(grant)),
            Ok(_) | Err(ClientsError::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// `_rendered(db, grant, hosts)`: the artifacts rebuilt from escrow with the public hosts of
    /// the grant's node. No manager is called.
    fn rendered(&self, db: &Conn, grant: &AccessGrant, hosts: &dyn PublicHosts) -> Result<Value, ClientsError> {
        let reference =
            grant.secret_ref.clone().ok_or_else(|| ClientsError::Internal("grant without credential".into()))?;
        let plaintext = reveal_credential(&self.secrets, db, &reference, grant)?;
        let adapter = self.adapters.require(grant.protocol)?;
        let host = hosts.hosts(db, &grant.node_id)?.get(grant.protocol.as_str()).cloned().unwrap_or_default();
        let artifacts = adapter
            .render_artifacts(grant, &plaintext, &host)
            .map_err(|error| ClientsError::adapter(grant.protocol, error))?;
        Ok(json!({
            "grant_id": grant.id,
            "protocol": grant.protocol.as_str(),
            "node_id": grant.node_id,
            "runtime_username": grant.runtime_username,
            "artifacts": artifacts.iter().map(|item| json!({
                "kind": item.kind,
                "label": item.label,
                "media_type": item.media_type,
                "value": item.value,
                "auto_refresh": item.auto_refresh.as_str(),
            })).collect::<Vec<_>>(),
        }))
    }

    /// `bundle(operation_id, public_hosts=…)`: every artifact of a succeeded operation.
    pub fn bundle(&self, operation_id: &str, hosts: &dyn PublicHosts) -> Result<Value, ClientsError> {
        let operation = self.operation(operation_id)?;
        if operation.status != "succeeded" {
            return Err(ClientsError::Conflict("only a succeeded operation has a bundle".into()));
        }
        self.database.with_connection(|db| {
            let mut grants = Vec::new();
            for step in &operation.steps {
                let Some(grant) = Self::live_grant(db, step)? else {
                    continue;
                };
                if grant.secret_ref.is_none() {
                    continue;
                }
                grants.push(self.rendered(db, &grant, hosts)?);
            }
            Ok(json!({"operation_id": operation_id, "grants": grants}))
        })
    }

    /// `client_links(client_id, public_hosts=…, protocol=…, grant_id=…)`: everything the client
    /// can be handed right now, rebuilt from escrow, audited as `client.links.reveal`.
    pub fn client_links(
        &self,
        client_id: &str,
        hosts: &dyn PublicHosts,
        protocol: Option<&str>,
        grant_id: Option<&str>,
        context: &AuditContext,
    ) -> Result<Value, ClientsError> {
        self.database.with_connection(|db| {
            store::client(db, client_id)?;
            let grants: Vec<AccessGrant> = store::client_grants(db, client_id)?
                .into_iter()
                .filter(|grant| {
                    grant.desired_state != GrantDesiredState::Deleted
                        && grant.secret_ref.is_some()
                        && protocol.is_none_or(|protocol| grant.protocol.as_str() == protocol)
                        && grant_id.is_none_or(|grant_id| grant.id == grant_id)
                })
                .collect();
            if let (Some(grant_id), true) = (grant_id, grants.is_empty()) {
                return Err(ClientsError::NotFound(grant_id.to_string()));
            }
            let mut rendered = Vec::new();
            for grant in &grants {
                rendered.push(self.rendered(db, grant, hosts)?);
            }
            let ids: Vec<Value> = rendered.iter().map(|item| item["grant_id"].clone()).collect();
            // Showing a link hands out a live secret, like showing the subscription: audited.
            Audit::new(context, "client.links.reveal", client_id)
                .detail(json!({"protocol": protocol, "grants": ids}))
                .write(db)?;
            Ok(json!({"client_id": client_id, "grants": rendered}))
        })
    }
}
