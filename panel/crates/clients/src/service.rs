//! Clients as an application service: one transaction per change, audit included
//! (`clients/service.py`).
//!
//! The change hooks (`on_change`: the subscription generation, the linked nodes' `publish`) run
//! inside the same transaction as the change that triggered them: a rolled-back state change
//! must not leave a bumped generation behind.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use panel_core::clock::SharedClock;
use panel_core::db::{Conn, Database};
use panel_core::rusqlite::{params, OptionalExtension as _};
use panel_model::clients::{
    effective_enabled, AccessGrant, Client, ClientState, GrantDesiredState, GrantObservedState,
};
use panel_model::protocols::{CredentialPlan, GrantRef, ProtocolAdapter};
use panel_model::seams::ClientChangeHook;
use panel_model::{Model as _, Protocol};
use panel_secrets::audit::digest;
use panel_secrets::secrets_store::{Identity, SecretRef as StoreRef, SecretStore};
use serde_json::{json, Map};

use crate::context::{Audit, AuditContext};
use crate::store::{self, GrantFilter, GrantUpdate};
use crate::{blocking, managed, ClientsError, CREDENTIAL_PURPOSE, LOCAL_NODE_ID};

/// `STATES`.
pub const STATES: [&str; 3] = ["active", "suspended", "archived"];

fn lock_read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// `app.state.adapters`: one adapter per protocol, shared by the client service, the saga and
/// the domain writer (filled once the adapters exist, like `clients.adapters = …`).
#[derive(Clone, Default)]
pub struct Adapters(Arc<RwLock<HashMap<Protocol, Arc<dyn ProtocolAdapter>>>>);

impl std::fmt::Debug for Adapters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: BTreeSet<&str> = lock_read(&self.0).keys().map(|protocol| protocol.as_str()).collect();
        f.debug_tuple("Adapters").field(&names).finish()
    }
}

impl Adapters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, protocol: Protocol, adapter: Arc<dyn ProtocolAdapter>) {
        lock_write(&self.0).insert(protocol, adapter);
    }

    pub fn get(&self, protocol: Protocol) -> Option<Arc<dyn ProtocolAdapter>> {
        lock_read(&self.0).get(&protocol).cloned()
    }

    /// `_adapter(protocol)`: `ClientConflict` when none is configured.
    pub fn require(&self, protocol: Protocol) -> Result<Arc<dyn ProtocolAdapter>, ClientsError> {
        self.get(protocol).ok_or_else(|| ClientsError::Conflict(format!("no adapter is configured for {protocol}")))
    }
}

/// `new_credential(protocol)`: one rule for every credential the panel chooses — Telemt's 32 hex
/// characters, an AmneziaWG key pair, a TrustTunnel password, else `token_urlsafe(24)`.
pub fn new_credential(protocol: Protocol) -> Vec<u8> {
    match protocol {
        Protocol::Amneziawg => panel_protocols::amneziawg::new_credential(),
        Protocol::Trusttunnel => panel_protocols::trusttunnel::new_credential(),
        Protocol::Mtproxy => panel_core::ids::token_hex(16).into_bytes(),
        Protocol::Naive | Protocol::Mieru => panel_core::ids::token_urlsafe(24).into_bytes(),
    }
}

/// `secret_store.store(db, …)` for a grant's credential.
pub(crate) fn store_credential(
    secrets: &SecretStore,
    db: &Conn,
    grant_id: &str,
    version: i64,
    node_id: &str,
    plaintext: &[u8],
    state: &str,
) -> Result<StoreRef, ClientsError> {
    let secret_id = format!("grant:{grant_id}");
    let identity = Identity {
        secret_id: &secret_id,
        version,
        purpose: CREDENTIAL_PURPOSE,
        grant_id: Some(grant_id),
        permitted_node_id: Some(node_id),
    };
    Ok(secrets.store(db, &identity, plaintext, state)?)
}

/// `secret_store.reveal(db, ref, purpose="grant.credential", grant_id=…, permitted_node_id=…)`.
pub(crate) fn reveal_credential(
    secrets: &SecretStore,
    db: &Conn,
    reference: &panel_model::SecretRef,
    grant: &AccessGrant,
) -> Result<Vec<u8>, ClientsError> {
    let reference = StoreRef::new(reference.secret_id.clone(), reference.version);
    Ok(secrets.reveal(db, &reference, CREDENTIAL_PURPOSE, Some(&grant.id), Some(&grant.node_id))?)
}

pub(crate) fn store_ref(reference: &panel_model::SecretRef) -> StoreRef {
    StoreRef::new(reference.secret_id.clone(), reference.version)
}

/// The client service (`ClientService`). Cheap to clone; clones share the hooks, the adapters and
/// the access lock.
#[derive(Clone)]
pub struct ClientService {
    database: Database,
    secrets: SecretStore,
    clock: SharedClock,
    hooks: Arc<RwLock<Vec<Arc<dyn ClientChangeHook>>>>,
    adapters: Adapters,
    access_lock: Arc<tokio::sync::Mutex<()>>,
}

impl std::fmt::Debug for ClientService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientService").field("database", &self.database.path()).finish_non_exhaustive()
    }
}

impl ClientService {
    pub fn new(database: Database, secrets: SecretStore, clock: SharedClock, adapters: Adapters) -> Self {
        Self {
            database,
            secrets,
            clock,
            hooks: Arc::new(RwLock::new(Vec::new())),
            adapters,
            access_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    pub fn secrets(&self) -> &SecretStore {
        &self.secrets
    }

    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }

    pub fn adapters(&self) -> &Adapters {
        &self.adapters
    }

    /// `int(self.clock.time())`.
    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// `on_change.append(hook)`.
    pub fn add_hook(&self, hook: Arc<dyn ClientChangeHook>) {
        lock_write(&self.hooks).push(hook);
    }

    /// `notify(db, client_id)`: inside the caller's transaction, so a rolled-back change bumps
    /// nothing.
    pub fn notify(&self, db: &Conn, client_id: &str) -> Result<(), ClientsError> {
        let hooks: Vec<Arc<dyn ClientChangeHook>> = lock_read(&self.hooks).clone();
        for hook in hooks {
            hook.on_change(db, client_id).map_err(ClientsError::Seam)?;
        }
        Ok(())
    }

    /// `new_client(db, display_name, now=…)`: inserted into the caller's transaction.
    pub fn new_client(&self, db: &Conn, display_name: &str, now: i64) -> Result<Client, ClientsError> {
        let client = Client {
            id: panel_core::ids::uuid4(),
            display_name: display_name.to_string(),
            state: ClientState::Active,
            metadata: Map::new(),
            created_at: now,
            updated_at: now,
        };
        store::insert_client(db, &client)?;
        Ok(client)
    }

    /// `create_client(display_name, …)`.
    pub fn create_client(&self, display_name: &str, context: &AuditContext) -> Result<Client, ClientsError> {
        let now = self.now();
        self.database.transaction(|db| {
            let client = self.new_client(db, display_name, now)?;
            Audit::new(context, "client.create", &client.id).after(digest(&client.dump())).write(db)?;
            self.notify(db, &client.id)?;
            Ok(client)
        })
    }

    /// `rename_client(client_id, display_name, …)`: presentation only.
    pub fn rename_client(
        &self,
        client_id: &str,
        display_name: &str,
        context: &AuditContext,
    ) -> Result<Client, ClientsError> {
        let name = panel_core::pytext::collapse_whitespace(display_name);
        if name.is_empty() || panel_core::pytext::len(&name) > 128 {
            return Err(ClientsError::Conflict("display_name must be 1-128 characters".into()));
        }
        let now = self.now();
        self.database.transaction(|db| {
            let before = store::client(db, client_id)?;
            store::rename_client(db, client_id, &name, now)?;
            let after = store::client(db, client_id)?;
            Audit::new(context, "client.rename", client_id)
                .before(digest(&before.dump()))
                .after(digest(&after.dump()))
                .detail(json!({"display_name": name}))
                .write(db)?;
            self.notify(db, client_id)?;
            Ok(after)
        })
    }

    /// `set_grant_label(grant_id, label, …)`: empty puts the default back.
    pub fn set_grant_label(
        &self,
        grant_id: &str,
        label: Option<&str>,
        context: &AuditContext,
    ) -> Result<AccessGrant, ClientsError> {
        let collapsed = panel_core::pytext::collapse_whitespace(label.unwrap_or(""));
        let text = (!collapsed.is_empty()).then_some(collapsed);
        if text.as_deref().is_some_and(|text| panel_core::pytext::len(text) > 64) {
            return Err(ClientsError::Conflict("label must be at most 64 characters".into()));
        }
        let now = self.now();
        self.database.transaction(|db| {
            let before = store::grant(db, grant_id)?;
            if before.desired_state == GrantDesiredState::Deleted {
                return Err(ClientsError::NotFound(grant_id.to_string()));
            }
            store::set_grant_label(db, grant_id, text.as_deref(), now)?;
            let after = store::grant(db, grant_id)?;
            Audit::new(context, "grant.label", grant_id)
                .detail(json!({"client_id": before.client_id, "protocol": before.protocol.as_str(), "label": text}))
                .write(db)?;
            self.notify(db, &before.client_id)?;
            Ok(after)
        })
    }

    /// `set_state(client_id, state, …)`.
    pub fn set_state(&self, client_id: &str, state: &str, context: &AuditContext) -> Result<Client, ClientsError> {
        let Some(wanted) = ClientState::from_wire(state) else {
            return Err(ClientsError::Conflict("state must be one of ('active', 'suspended', 'archived')".into()));
        };
        let now = self.now();
        self.database.transaction(|db| {
            let before = store::client(db, client_id)?;
            if wanted == ClientState::Archived && !store::client_grants(db, client_id)?.is_empty() {
                // Archiving ends the client's life: nothing may still be provisioned in its name.
                return Err(ClientsError::Conflict("client still has grants that are not deleted".into()));
            }
            store::set_client_state(db, client_id, wanted, now)?;
            let after = store::client(db, client_id)?;
            if before.state != wanted {
                for grant in store::client_grants(db, client_id)? {
                    if effective_enabled(&grant, &before, now) != effective_enabled(&grant, &after, now) {
                        store::update_grant(db, &grant.id, &GrantUpdate::new().observed(GrantObservedState::Pending))?;
                    }
                }
            }
            Audit::new(context, format!("client.{}", wanted.as_str()), client_id)
                .before(digest(&before.dump()))
                .after(digest(&after.dump()))
                .write(db)?;
            self.notify(db, client_id)?;
            Ok(after)
        })
    }

    /// `delete_client(client_id, …)`: permanent removal of an archived client with no live grants;
    /// the audit log stays, the client's secret rows go.
    pub fn delete_client(&self, client_id: &str, context: &AuditContext) -> Result<(), ClientsError> {
        self.database.transaction(|db| {
            let before = store::client(db, client_id)?;
            if before.state != ClientState::Archived {
                return Err(ClientsError::Conflict("only an archived client can be deleted".into()));
            }
            if !store::client_grants(db, client_id)?.is_empty() {
                return Err(ClientsError::Conflict("client still has grants that are not deleted".into()));
            }
            let all = store::grants(db, &GrantFilter { client_id: Some(client_id), include_deleted: true, ..Default::default() })?;
            if all.iter().any(|grant| grant.observed_state != GrantObservedState::Missing) {
                return Err(ClientsError::Conflict("node has not confirmed grant deletion yet".into()));
            }
            let exists = |sql: &str| -> Result<bool, ClientsError> {
                Ok(db.query_row(sql, params![client_id], |_| Ok(())).optional()?.is_some())
            };
            if exists(
                "SELECT 1 FROM provisioning_operations WHERE client_id=? AND status='manual_intervention_required' LIMIT 1",
            )? {
                return Err(ClientsError::Conflict("client has an operation waiting for manual intervention".into()));
            }
            if exists(
                "SELECT 1 FROM provisioning_operations WHERE client_id=? AND status NOT IN ('succeeded','compensated') LIMIT 1",
            )? {
                return Err(ClientsError::Conflict("client has an unfinished provisioning operation".into()));
            }
            store::delete_client(db, client_id)?;
            Audit::new(context, "client.delete", client_id)
                .before(digest(&before.dump()))
                .detail(json!({"display_name": before.display_name}))
                .write(db)?;
            self.notify(db, client_id)?;
            Ok(())
        })
    }

    /// `reconcile_access(client_id=None, force=False)`: confirms local access after state or time
    /// changes; a failed write stays `pending`. One protocol's failure never skips another; no
    /// manager I/O holds a database transaction.
    pub async fn reconcile_access(&self, client_id: Option<&str>, force: bool) -> Result<(), ClientsError> {
        let _guard = self.access_lock.lock().await;
        let (grants, clients) = {
            let database = self.database.clone();
            let client_id = client_id.map(str::to_string);
            blocking(move || {
                database.with_connection(|db| {
                    let grants = store::grants(
                        db,
                        &GrantFilter {
                            client_id: client_id.as_deref(),
                            node_id: Some(LOCAL_NODE_ID),
                            ..Default::default()
                        },
                    )?;
                    let clients: HashMap<String, Client> =
                        store::clients(db, None)?.into_iter().map(|client| (client.id.clone(), client)).collect();
                    Ok((grants, clients))
                })
            })
            .await?
        };
        let now = self.now();
        let candidates: Vec<AccessGrant> = grants
            .into_iter()
            .filter(|grant| {
                let wanted = clients.get(&grant.client_id).is_some_and(|client| effective_enabled(grant, client, now));
                let expected = if wanted { GrantObservedState::Enabled } else { GrantObservedState::Disabled };
                force || grant.observed_state != expected
            })
            .collect();
        let protocols: BTreeSet<&str> = candidates.iter().map(|grant| grant.protocol.as_str()).collect();
        for protocol in protocols {
            let protocol = Protocol::from_wire(protocol).expect("a stored protocol");
            let chosen: Vec<AccessGrant> =
                candidates.iter().filter(|grant| grant.protocol == protocol).cloned().collect();
            if self.reconcile_protocol(protocol, chosen).await.is_err() {
                // Deliberately without the error text: a manager's can contain a credential.
                log::warn!("access enforcement pending for protocol {protocol}");
            }
        }
        Ok(())
    }

    async fn reconcile_protocol(&self, protocol: Protocol, grants: Vec<AccessGrant>) -> Result<(), ClientsError> {
        let planned: Vec<(AccessGrant, bool)> = {
            let this = self.clone();
            blocking(move || {
                this.database.transaction(|db| {
                    let mut planned = Vec::new();
                    for grant in &grants {
                        let current = match store::grant(db, &grant.id) {
                            Ok(current) => current,
                            Err(ClientsError::NotFound(_)) => continue,
                            Err(error) => return Err(error),
                        };
                        if current.desired_state == GrantDesiredState::Deleted
                            || managed::is_managed(db, protocol.as_str(), &current.runtime_username)?
                        {
                            continue;
                        }
                        let client = store::client(db, &current.client_id)?;
                        let wanted = effective_enabled(&current, &client, this.now());
                        store::update_grant(db, &grant.id, &GrantUpdate::new().observed(GrantObservedState::Pending))?;
                        planned.push((current, wanted));
                    }
                    Ok(planned)
                })
            })
            .await?
        };
        if planned.is_empty() {
            return Ok(());
        }
        let adapter = self.adapters.require(protocol)?;
        let inventory: HashMap<String, bool> = adapter
            .discover()
            .await
            .map_err(|error| ClientsError::adapter(protocol, error))?
            .items
            .into_iter()
            .map(|item| (item.runtime_username, item.enabled))
            .collect();
        for (grant, wanted) in &planned {
            let Some(enabled) = inventory.get(&grant.runtime_username) else {
                continue; // provisioning owns creation; a missing account stays pending
            };
            if enabled != wanted {
                let reference = GrantRef { protocol, runtime_username: grant.runtime_username.clone(), revision: None };
                let outcome =
                    if *wanted { adapter.enable(&reference).await } else { adapter.disable(&reference).await };
                if outcome.is_err() {
                    // The readback decides, even after a lost reply.
                    log::warn!("access mutation pending for grant {}", grant.id);
                }
            }
        }
        let confirmed: HashMap<String, bool> = adapter
            .discover()
            .await
            .map_err(|error| ClientsError::adapter(protocol, error))?
            .items
            .into_iter()
            .map(|item| (item.runtime_username, item.enabled))
            .collect();
        let this = self.clone();
        blocking(move || {
            this.database.transaction(|db| {
                for (grant, _) in &planned {
                    let fresh = match store::grant(db, &grant.id) {
                        Ok(fresh) => fresh,
                        Err(ClientsError::NotFound(_)) => continue,
                        Err(error) => return Err(error),
                    };
                    let client = store::client(db, &fresh.client_id)?;
                    let wanted = effective_enabled(&fresh, &client, this.now());
                    let observed = confirmed.get(&fresh.runtime_username);
                    if fresh.desired_state != GrantDesiredState::Deleted && observed == Some(&wanted) {
                        let state = if wanted { GrantObservedState::Enabled } else { GrantObservedState::Disabled };
                        store::update_grant(db, &grant.id, &GrantUpdate::new().observed(state))?;
                    }
                }
                Ok(())
            })
        })
        .await
    }

    /// `purge_grant(db, grant_id)`: the runtime account is confirmed gone; every live version of
    /// its credential is revoked (the rows stay as an audit trail) and the row goes, so the name
    /// can be granted again. In the caller's transaction.
    pub fn purge_grant(&self, db: &Conn, grant_id: &str) -> Result<(), ClientsError> {
        let secret_id = format!("grant:{grant_id}");
        let versions: Vec<i64> = {
            let mut statement =
                db.prepare("SELECT version FROM secret_versions WHERE secret_id=? AND state<>'revoked'")?;
            let rows = statement.query_map(params![secret_id], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for version in versions {
            self.secrets.transition(db, &StoreRef::new(secret_id.clone(), version), "revoked")?;
        }
        store::delete_grant(db, grant_id)
    }

    /// `_escrow(grant, plaintext, rotated=…)`: store the credential and point the grant at it.
    fn escrow(
        &self,
        grant: &AccessGrant,
        plaintext: &[u8],
        rotated: bool,
        context: &AuditContext,
    ) -> Result<AccessGrant, ClientsError> {
        self.database.transaction(|db| {
            let current = store::grant(db, &grant.id)?;
            if current.secret_ref.is_some() {
                return Err(ClientsError::Conflict("the grant already has a stored credential".into()));
            }
            let reference = store_credential(&self.secrets, db, &grant.id, 1, &grant.node_id, plaintext, "active")?;
            store::update_grant(
                db,
                &grant.id,
                &GrantUpdate::new()
                    .secret(panel_model::SecretRef::new(reference.secret_id, reference.version))
                    .at(self.now()),
            )?;
            let action = if rotated { "grant.credential.adopt" } else { "grant.credential.capture" };
            Audit::new(context, action, &grant.id)
                .detail(json!({"protocol": grant.protocol.as_str(), "rotated": rotated}))
                .write(db)?;
            self.notify(db, &current.client_id)?;
            store::grant(db, &grant.id)
        })
    }

    /// `_local_writable(grant_id)`: a grant on another node, or one the central owns, is refused
    /// before any adapter I/O.
    fn local_writable(&self, grant_id: &str) -> Result<AccessGrant, ClientsError> {
        self.database.with_connection(|db| {
            let grant = store::grant(db, grant_id)?;
            if grant.node_id != LOCAL_NODE_ID {
                return Err(ClientsError::Conflict(format!(
                    "the grant lives on another node ({}); use its lifecycle",
                    grant.node_id
                )));
            }
            managed::require_unmanaged(db, grant.protocol.as_str(), &grant.runtime_username)?;
            Ok(grant)
        })
    }

    /// `capture_credential(grant_id, …)`: read the live credential and escrow it, without touching
    /// the runtime.
    pub async fn capture_credential(
        &self,
        grant_id: &str,
        context: &AuditContext,
    ) -> Result<AccessGrant, ClientsError> {
        let this = self.clone();
        let id = grant_id.to_string();
        let grant = blocking(move || this.local_writable(&id)).await?;
        let adapter = self.adapters.require(grant.protocol)?;
        if !adapter.capture_supported() {
            return Err(ClientsError::Conflict(format!(
                "{} credential requires rotation: it cannot be read back",
                grant.protocol
            )));
        }
        let reference =
            GrantRef { protocol: grant.protocol, runtime_username: grant.runtime_username.clone(), revision: None };
        let plaintext =
            adapter.capture(&reference).await.map_err(|error| ClientsError::adapter(grant.protocol, error))?;
        let plaintext = plaintext.filter(|bytes| !bytes.is_empty());
        let Some(plaintext) = plaintext else {
            return Err(ClientsError::Conflict("the runtime returned no credential to capture".into()));
        };
        let (this, context) = (self.clone(), context.clone());
        blocking(move || this.escrow(&grant, &plaintext, false, &context)).await
    }

    /// `adopt_credential(grant_id, allow_rotation=…, …)`: make an imported grant renderable,
    /// rotating only when the operator allowed it.
    pub async fn adopt_credential(
        &self,
        grant_id: &str,
        allow_rotation: bool,
        context: &AuditContext,
    ) -> Result<AccessGrant, ClientsError> {
        let this = self.clone();
        let id = grant_id.to_string();
        let grant = blocking(move || this.local_writable(&id)).await?;
        if grant.secret_ref.is_some() {
            return Err(ClientsError::Conflict("the grant already has a stored credential".into()));
        }
        let adapter = self.adapters.require(grant.protocol)?;
        if adapter.capture_supported() {
            return self.capture_credential(grant_id, context).await;
        }
        if !allow_rotation {
            // Rotation invalidates the link the subscriber holds today: never implicit.
            return Err(ClientsError::Conflict(format!(
                "{} credential requires rotation: the current link will stop working",
                grant.protocol
            )));
        }
        let password = new_credential(grant.protocol);
        let plan =
            CredentialPlan::caller(password.clone()).map_err(|error| ClientsError::adapter(grant.protocol, error))?;
        let reference =
            GrantRef { protocol: grant.protocol, runtime_username: grant.runtime_username.clone(), revision: None };
        let applied = adapter
            .rotate(&format!("adopt:{grant_id}"), &reference, &plan)
            .await
            .map_err(|error| ClientsError::adapter(grant.protocol, error))?;
        let credential = applied.credential.filter(|bytes| !bytes.is_empty()).unwrap_or(password);
        let (this, context) = (self.clone(), context.clone());
        blocking(move || this.escrow(&grant, &credential, true, &context)).await
    }

    /// `client_with_grants(client_id)`.
    pub fn client_with_grants(&self, client_id: &str) -> Result<(Client, Vec<AccessGrant>), ClientsError> {
        self.database.with_connection(|db| Ok((store::client(db, client_id)?, store::client_grants(db, client_id)?)))
    }

    /// `list_clients()`.
    pub fn list_clients(&self) -> Result<Vec<Client>, ClientsError> {
        self.database.with_connection(|db| store::clients(db, None))
    }
}
