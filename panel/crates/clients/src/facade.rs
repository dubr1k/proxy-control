//! The old protocol endpoints, served by the domain (`clients/facade.py`) — the panel's only
//! writer since `PANEL_VNEXT_WRITER=legacy` was retired.
//!
//! From outside the protocol pages answer as before; what changes is that the panel keeps a
//! client, a grant and an escrowed credential for every account it touches. A username the panel
//! has never seen is *adopted* (one row, no credential), never recreated and never merged with a
//! same-named account of another protocol.

use panel_core::clock::SharedClock;
use panel_core::db::Conn;
use panel_core::rusqlite::params;
use panel_model::clients::{
    effective_enabled, AccessGrant, GrantDesiredState, GrantIntent, GrantObservedState, GrantOrigin, ProtocolOptions,
};
use panel_model::fleet::CredentialOrigin;
use panel_model::protocols::{CredentialPlan, GrantRef};
use panel_model::{Protocol, SecretRef};
use serde_json::{json, Map, Value};

use crate::context::{Audit, AuditContext};
use crate::provisioning::ProvisioningService;
use crate::service::{new_credential, reveal_credential, store_credential, store_ref, Adapters, ClientService};
use crate::store::{self, GrantUpdate};
use crate::{blocking, managed, ClientsError, DEFAULT_ENDPOINT, LOCAL_NODE_ID};

/// The domain writer (`DomainFacade`). Cheap to clone.
#[derive(Clone)]
pub struct DomainFacade {
    clients: ClientService,
    provisioning: ProvisioningService,
    adapters: Adapters,
    clock: SharedClock,
}

impl std::fmt::Debug for DomainFacade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainFacade").finish_non_exhaustive()
    }
}

impl DomainFacade {
    pub fn new(
        clients: ClientService,
        provisioning: ProvisioningService,
        adapters: Adapters,
        clock: SharedClock,
    ) -> Self {
        Self { clients, provisioning, adapters, clock }
    }

    pub fn clients(&self) -> &ClientService {
        &self.clients
    }

    pub fn provisioning(&self) -> &ProvisioningService {
        &self.provisioning
    }

    pub fn adapters(&self) -> &Adapters {
        &self.adapters
    }

    fn now(&self) -> i64 {
        self.clock.now()
    }

    // --- lookups ---------------------------------------------------------------------------

    /// `grant(protocol, username)`: the local grant of that account, if any.
    pub fn grant(&self, protocol: Protocol, username: &str) -> Result<Option<AccessGrant>, ClientsError> {
        self.clients
            .database()
            .with_connection(|db| store::find_grant(db, protocol.as_str(), LOCAL_NODE_ID, DEFAULT_ENDPOINT, username))
    }

    /// `_local_only`: an account the central owns is not this façade's to write (ADR 003).
    pub fn local_only(&self, protocol: Protocol, username: &str) -> Result<(), ClientsError> {
        self.clients.database().with_connection(|db| managed::require_unmanaged(db, protocol.as_str(), username))
    }

    /// `effective_operation(protocol, username, enabled)`: protocol pages may change intent but
    /// cannot bypass a client's access window.
    pub fn effective_operation(&self, protocol: Protocol, username: &str, enabled: bool) -> Result<bool, ClientsError> {
        let Some(grant) = self.grant(protocol, username)? else {
            return Ok(enabled);
        };
        let client = self.clients.database().with_connection(|db| store::client(db, &grant.client_id))?;
        let mut wanted = grant;
        wanted.desired_state = if enabled { GrantDesiredState::Enabled } else { GrantDesiredState::Disabled };
        Ok(effective_enabled(&wanted, &client, self.clients.now()))
    }

    /// `_client_for(db, display_name)`: the first client of that name, else a new one.
    fn client_for(&self, db: &Conn, display_name: &str) -> Result<String, ClientsError> {
        if let Some(existing) = store::clients(db, None)?.into_iter().find(|client| client.display_name == display_name)
        {
            return Ok(existing.id);
        }
        Ok(self.clients.new_client(db, display_name, self.now())?.id)
    }

    /// `touch_import(protocol, username, enabled=…, options=…)`: record an account the panel did
    /// not create — one row, no credential, no merge.
    pub fn touch_import(
        &self,
        protocol: Protocol,
        username: &str,
        enabled: bool,
        options: &Map<String, Value>,
        context: &AuditContext,
    ) -> Result<AccessGrant, ClientsError> {
        self.local_only(protocol, username)?;
        if let Some(existing) = self.grant(protocol, username)? {
            return Ok(existing);
        }
        let now = self.now();
        let state = if enabled { GrantDesiredState::Enabled } else { GrantDesiredState::Disabled };
        let observed = if enabled { GrantObservedState::Enabled } else { GrantObservedState::Disabled };
        self.clients.database().transaction(|db| {
            let client_id = self.client_for(db, username)?;
            let grant = AccessGrant {
                protocol,
                options: ProtocolOptions::validate(protocol, &Value::Object(options.clone()))?,
                id: panel_core::ids::uuid4(),
                client_id: client_id.clone(),
                node_id: LOCAL_NODE_ID.into(),
                endpoint_id: DEFAULT_ENDPOINT.into(),
                runtime_username: username.to_string(),
                secret_ref: None,
                desired_state: state,
                observed_state: observed,
                valid_from: None,
                valid_until: None,
                origin: GrantOrigin::Imported,
                own_lane: false,
                label: None,
                created_at: now,
                updated_at: now,
            };
            grant.check()?;
            store::insert_grant(db, &grant)?;
            Audit::new(context, "grant.adopt_on_write", &grant.id)
                .reason("domain")
                .detail(json!({"protocol": protocol.as_str(), "runtime_username": username}))
                .write(db)?;
            self.clients.notify(db, &client_id)?;
            Ok(grant)
        })
    }

    // --- writes ----------------------------------------------------------------------------

    /// `create(protocol, username, options)`: provision one account through the saga and return
    /// its credential once.
    pub async fn create(
        &self,
        protocol: Protocol,
        username: &str,
        options: &Map<String, Value>,
        context: &AuditContext,
    ) -> Result<Vec<u8>, ClientsError> {
        let options = ProtocolOptions::validate(protocol, &Value::Object(options.clone()))?;
        let intent = GrantIntent::new(protocol, username, options)?;
        let client_id = {
            let (this, name) = (self.clone(), username.to_string());
            blocking(move || this.clients.database().transaction(|db| this.client_for(db, &name))).await?
        };
        let operation_id = self.provisioning.start(&client_id, vec![intent], context).await?;
        let result = self.provisioning.run(&operation_id).await?;
        if result.status != "succeeded" {
            return Err(ClientsError::Conflict(format!("provisioning {}: operation {operation_id}", result.status)));
        }
        let (this, name) = (self.clone(), username.to_string());
        blocking(move || this.credential(protocol, &name)).await
    }

    /// `credential(protocol, username)`: the escrowed credential of the account.
    pub fn credential(&self, protocol: Protocol, username: &str) -> Result<Vec<u8>, ClientsError> {
        let grant = self.grant(protocol, username)?;
        let Some((grant, reference)) =
            grant.and_then(|grant| grant.secret_ref.clone().map(|reference| (grant, reference)))
        else {
            return Err(ClientsError::Conflict("the panel has no stored credential for this account".into()));
        };
        self.clients.database().with_connection(|db| reveal_credential(self.clients.secrets(), db, &reference, &grant))
    }

    /// `set_enabled(protocol, username, enabled, observed=…)`: mirror a runtime state change into
    /// the grant (adopting the row if needed), then confirm it against the runtime.
    pub async fn set_enabled(
        &self,
        protocol: Protocol,
        username: &str,
        enabled: bool,
        observed: &Map<String, Value>,
        context: &AuditContext,
    ) -> Result<(), ClientsError> {
        let client_id = {
            let (this, name, observed, context) =
                (self.clone(), username.to_string(), observed.clone(), context.clone());
            blocking(move || {
                this.local_only(protocol, &name)?;
                let grant = match this.grant(protocol, &name)? {
                    Some(grant) => grant,
                    None => this.touch_import(protocol, &name, enabled, &observed, &context)?,
                };
                let state = if enabled { GrantDesiredState::Enabled } else { GrantDesiredState::Disabled };
                this.clients.database().transaction(|db| {
                    store::update_grant(
                        db,
                        &grant.id,
                        &GrantUpdate::new().desired(state).observed(GrantObservedState::Pending).at(this.now()),
                    )?;
                    // One name per operator action wherever the account lives.
                    Audit::new(&context, if enabled { "grant.enable" } else { "grant.disable" }, &grant.id)
                        .reason("domain")
                        .detail(json!({"protocol": protocol.as_str(), "runtime_username": name}))
                        .write(db)?;
                    this.clients.notify(db, &grant.client_id)?;
                    Ok(grant.client_id.clone())
                })
            })
            .await?
        };
        self.clients.reconcile_access(Some(&client_id), true).await
    }

    /// `forget(protocol, username)`: the runtime account is gone; the grant follows it.
    pub fn forget(&self, protocol: Protocol, username: &str, context: &AuditContext) -> Result<(), ClientsError> {
        self.local_only(protocol, username)?;
        let Some(grant) = self.grant(protocol, username)? else {
            return Ok(());
        };
        self.clients.database().transaction(|db| {
            store::update_grant(
                db,
                &grant.id,
                &GrantUpdate::new()
                    .desired(GrantDesiredState::Deleted)
                    .observed(GrantObservedState::Missing)
                    .at(self.now()),
            )?;
            Audit::new(context, "grant.delete", &grant.id)
                .reason("domain")
                .detail(json!({"protocol": protocol.as_str(), "runtime_username": username}))
                .write(db)?;
            self.clients.notify(db, &grant.client_id)
        })
    }

    /// `rotate(protocol, username, observed=…)`: through the adapter, so the new credential lands
    /// in escrow; answers it.
    pub async fn rotate(
        &self,
        protocol: Protocol,
        username: &str,
        observed: &Map<String, Value>,
        context: &AuditContext,
    ) -> Result<Vec<u8>, ClientsError> {
        let grant = {
            let (this, name, observed, context) =
                (self.clone(), username.to_string(), observed.clone(), context.clone());
            blocking(move || {
                this.local_only(protocol, &name)?;
                match this.grant(protocol, &name)? {
                    Some(grant) => Ok(grant),
                    None => this.touch_import(protocol, &name, true, &observed, &context),
                }
            })
            .await?
        };
        let adapter = self.adapters.require(protocol)?;
        let plan = if adapter.credential_origin() == CredentialOrigin::Manager {
            CredentialPlan::manager()
        } else {
            CredentialPlan::caller(new_credential(protocol)).map_err(|error| ClientsError::adapter(protocol, error))?
        };
        let reference = GrantRef { protocol, runtime_username: username.to_string(), revision: None };
        let applied = adapter
            .rotate(&format!("rotate:{}:{}", grant.id, self.now()), &reference, &plan)
            .await
            .map_err(|error| ClientsError::adapter(protocol, error))?;
        let credential = applied.credential.clone().unwrap_or_default();
        let (this, stored, template, context) =
            (self.clone(), credential.clone(), applied.artifact_template.clone(), context.clone());
        blocking(move || this.store_credential(&grant, &stored, Some(&template), "grant.rotate", &context)).await?;
        Ok(credential)
    }

    /// `escrow(protocol, username, plaintext, learned=…, observed=…, action=…, adopt=…)`: keep a
    /// credential a protocol route just received from the runtime; `false` when nothing was kept.
    #[allow(clippy::too_many_arguments)]
    pub fn escrow(
        &self,
        protocol: Protocol,
        username: &str,
        plaintext: &[u8],
        learned: Option<&Map<String, Value>>,
        observed: &Map<String, Value>,
        action: &str,
        adopt: bool,
        context: &AuditContext,
    ) -> Result<bool, ClientsError> {
        if plaintext.is_empty() || !self.clients.secrets().enabled() {
            return Ok(false);
        }
        self.local_only(protocol, username)?;
        let grant = match self.grant(protocol, username)? {
            Some(grant) => grant,
            None if !adopt => return Ok(false),
            None => self.touch_import(protocol, username, true, observed, context)?,
        };
        self.store_credential(&grant, plaintext, learned, action, context)?;
        Ok(true)
    }

    /// `_store_credential`: the next version, active at once; the one it replaced revoked.
    fn store_credential(
        &self,
        grant: &AccessGrant,
        plaintext: &[u8],
        learned: Option<&Map<String, Value>>,
        action: &str,
        context: &AuditContext,
    ) -> Result<(), ClientsError> {
        let secret_id = format!("grant:{}", grant.id);
        self.clients.database().transaction(|db| {
            let top: Option<i64> = db.query_row(
                "SELECT max(version) FROM secret_versions WHERE secret_id=?",
                params![secret_id],
                |row| row.get(0),
            )?;
            let stored = store_credential(
                self.clients.secrets(),
                db,
                &grant.id,
                top.unwrap_or(0) + 1,
                &grant.node_id,
                plaintext,
                "active",
            )?;
            // Only the credential moved: a disabled account stays disabled after a rotation.
            store::update_grant(
                db,
                &grant.id,
                &GrantUpdate::new().secret(SecretRef::new(stored.secret_id, stored.version)).at(self.now()),
            )?;
            if let Some(previous) = &grant.secret_ref {
                // The runtime already runs the new credential: the old one is history.
                self.clients.secrets().transition(db, &store_ref(previous), "revoked")?;
            }
            if let Some(learned) = learned.filter(|learned| !learned.is_empty()) {
                // The link shape the runtime reported with it (Mieru: its ports or lane slot).
                self.provisioning.remember_template(db, grant, learned)?;
            }
            Audit::new(context, action, &grant.id)
                .reason("domain")
                .detail(json!({"protocol": grant.protocol.as_str(), "runtime_username": grant.runtime_username}))
                .write(db)?;
            self.clients.notify(db, &grant.client_id)
        })
    }
}
