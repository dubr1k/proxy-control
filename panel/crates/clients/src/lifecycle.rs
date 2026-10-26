//! Enable, disable, rotate and delete one grant, wherever its account lives
//! (`clients/lifecycle.py`, spec §7).
//!
//! A local grant reaches the manager first and the [`DomainFacade`] second, exactly as the
//! protocol routes do. A grant on a linked panel is declarative: only `access_grants` and, for a
//! rotation, `secret_versions` change here, in one transaction with the audit row and
//! `ClientService.notify`; the generation compiled from that change is what the pusher delivers.

use std::future::Future;
use std::sync::{Arc, RwLock};

use panel_core::clock::SharedClock;
use panel_core::db::Conn;
use panel_core::rusqlite::params;
use panel_model::clients::{effective_enabled, AccessGrant, GrantDesiredState, GrantObservedState};
use panel_model::protocols::{BoxFuture, GrantRef};
use panel_model::seams::SeamError;
use panel_model::{Protocol, SecretRef};
use serde_json::{json, Map, Value};

use crate::context::{Audit, AuditContext};
use crate::facade::DomainFacade;
use crate::provisioning::{is_remote_node, ProvisioningService};
use crate::service::{new_credential, store_credential, store_ref, ClientService};
use crate::store::{self, GrantUpdate};
use crate::{blocking, managed, ClientsError, LOCAL_NODE_ID};

/// The reason a withdrawn remote step carries.
pub const WITHDRAWN: &str = "the grant was deleted before the node applied it";

/// The lanes service (WP10, `routing.lanes.LaneService`): a grant with its own lane leaves it
/// before it is deleted. Its refusals travel as the seam error (an `ApiError` the routes answer).
pub trait GrantLanes: Send + Sync {
    fn disable<'a>(&'a self, grant_id: &'a str, context: &'a AuditContext) -> BoxFuture<'a, Result<(), SeamError>>;
}

/// The grant lifecycle (`GrantLifecycle`). Cheap to clone; clones share the lanes service.
#[derive(Clone)]
pub struct GrantLifecycle {
    clients: ClientService,
    facade: DomainFacade,
    provisioning: ProvisioningService,
    clock: SharedClock,
    lanes: Arc<RwLock<Option<Arc<dyn GrantLanes>>>>,
}

impl std::fmt::Debug for GrantLifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantLifecycle").finish_non_exhaustive()
    }
}

/// What the façade would adopt the account with: `options.model_dump(exclude_none=True)`.
fn observed(grant: &AccessGrant) -> Map<String, Value> {
    grant
        .options
        .dump()
        .as_object()
        .map(|map| map.iter().filter(|(_, value)| !value.is_null()).map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

impl GrantLifecycle {
    pub fn new(facade: DomainFacade, clock: SharedClock) -> Self {
        Self {
            clients: facade.clients().clone(),
            provisioning: facade.provisioning().clone(),
            facade,
            clock,
            lanes: Arc::new(RwLock::new(None)),
        }
    }

    /// `lifecycle.lanes = …` (set once routing exists).
    pub fn set_lanes(&self, lanes: Arc<dyn GrantLanes>) {
        *self.lanes.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(lanes);
    }

    fn lanes(&self) -> Option<Arc<dyn GrantLanes>> {
        self.lanes.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    pub fn facade(&self) -> &DomainFacade {
        &self.facade
    }

    fn now(&self) -> i64 {
        self.clock.now()
    }

    /// `is_remote(db, grant)`.
    pub fn is_remote(db: &Conn, grant: &AccessGrant) -> Result<bool, ClientsError> {
        is_remote_node(db, &grant.node_id)
    }

    fn live(db: &Conn, grant_id: &str) -> Result<AccessGrant, ClientsError> {
        let grant = store::grant(db, grant_id)?;
        if grant.desired_state == GrantDesiredState::Deleted {
            return Err(ClientsError::Conflict("the grant is deleted".into()));
        }
        Ok(grant)
    }

    /// `_load(grant_id)`: the grant and whether it lives on a linked panel; a node without a writer
    /// here, or a local account the central owns, is refused before any manager is called.
    fn load(&self, grant_id: &str) -> Result<(AccessGrant, bool), ClientsError> {
        let (grant, remote) = self.clients.database().with_connection(|db| {
            let grant = Self::live(db, grant_id)?;
            let remote = Self::is_remote(db, &grant)?;
            if !remote && grant.node_id == LOCAL_NODE_ID {
                managed::require_unmanaged(db, grant.protocol.as_str(), &grant.runtime_username)?;
            }
            Ok::<_, ClientsError>((grant, remote))
        })?;
        if !remote && grant.node_id != LOCAL_NODE_ID {
            return Err(ClientsError::Conflict(format!("node {} has no writer on this panel", grant.node_id)));
        }
        Ok((grant, remote))
    }

    async fn load_async(&self, grant_id: &str) -> Result<(AccessGrant, bool), ClientsError> {
        let (this, id) = (self.clone(), grant_id.to_string());
        blocking(move || this.load(&id)).await
    }

    fn audit(db: &Conn, grant: &AccessGrant, action: &str, context: &AuditContext) -> Result<(), ClientsError> {
        Audit::new(context, format!("grant.{action}"), &grant.id)
            .detail(json!({
                "protocol": grant.protocol.as_str(),
                "runtime_username": grant.runtime_username,
                "node_id": grant.node_id,
            }))
            .write(db)?;
        Ok(())
    }

    async fn fresh(&self, grant_id: &str) -> Result<AccessGrant, ClientsError> {
        let (database, id) = (self.clients.database().clone(), grant_id.to_string());
        blocking(move || database.with_connection(|db| store::grant(db, &id))).await
    }

    /// `_declare(db, grant, action, **fields)`: what the central now wants of a remote grant, in
    /// the caller's transaction; `observed_state` is `pending` until the node reports.
    fn declare(
        &self,
        db: &Conn,
        grant: &AccessGrant,
        action: &str,
        update: GrantUpdate,
        context: &AuditContext,
    ) -> Result<AccessGrant, ClientsError> {
        let now = self.now();
        let mut observed_state = GrantObservedState::Pending;
        let only_desired = update.desired_state.is_some()
            && GrantUpdate { desired_state: None, ..update.clone() } == GrantUpdate::default();
        if let (true, Some(desired)) = (only_desired, update.desired_state) {
            if desired != GrantDesiredState::Deleted {
                let client = store::client(db, &grant.client_id)?;
                let mut changed = grant.clone();
                changed.desired_state = desired;
                if effective_enabled(grant, &client, now) == effective_enabled(&changed, &client, now) {
                    // Suspension or expiry already blocks it: no generation will change, so do
                    // not wait for a report that cannot arrive.
                    observed_state = grant.observed_state;
                }
            }
        }
        store::update_grant(
            db,
            &grant.id,
            &GrantUpdate { observed_state: Some(observed_state), updated_at: Some(now), ..update },
        )?;
        Self::audit(db, grant, action, context)?;
        self.clients.notify(db, &grant.client_id)?;
        store::grant(db, &grant.id)
    }

    /// `set_enabled(grant_id, enabled, …)`.
    pub async fn set_enabled(
        &self,
        grant_id: &str,
        enabled: bool,
        context: &AuditContext,
    ) -> Result<AccessGrant, ClientsError> {
        let (grant, remote) = self.load_async(grant_id).await?;
        if !remote {
            self.facade
                .set_enabled(grant.protocol, &grant.runtime_username, enabled, &observed(&grant), context)
                .await?;
            return self.fresh(&grant.id).await;
        }
        let (this, id, context) = (self.clone(), grant_id.to_string(), context.clone());
        blocking(move || {
            this.clients.database().transaction(|db| {
                let grant = Self::live(db, &id)?;
                let (action, state) = if enabled {
                    ("enable", GrantDesiredState::Enabled)
                } else {
                    ("disable", GrantDesiredState::Disabled)
                };
                if grant.desired_state == state {
                    // Already what the central wants: nothing to publish, nothing to wait for.
                    return Ok(grant);
                }
                this.declare(db, &grant, action, GrantUpdate::new().desired(state), &context)
            })
        })
        .await
    }

    /// `rotate(grant_id, …)`: through the adapter for a local grant; for a remote one a `pending`
    /// version the next generation names, the current one `retiring` until the node confirms.
    pub async fn rotate(&self, grant_id: &str, context: &AuditContext) -> Result<AccessGrant, ClientsError> {
        let (grant, remote) = self.load_async(grant_id).await?;
        if !remote {
            self.facade.rotate(grant.protocol, &grant.runtime_username, &observed(&grant), context).await?;
            return self.fresh(&grant.id).await;
        }
        let (this, id, context) = (self.clone(), grant_id.to_string(), context.clone());
        blocking(move || {
            this.clients.database().transaction(|db| {
                let grant = Self::live(db, &id)?;
                let secret_id = format!("grant:{}", grant.id);
                let top: Option<i64> = db.query_row(
                    "SELECT max(version) FROM secret_versions WHERE secret_id=?",
                    params![secret_id],
                    |row| row.get(0),
                )?;
                let current = grant.secret_ref.as_ref().map_or(1, |reference| reference.version);
                let version = top.unwrap_or(0).max(current) + 1;
                store_credential(
                    this.clients.secrets(),
                    db,
                    &grant.id,
                    version,
                    &grant.node_id,
                    &new_credential(grant.protocol),
                    "pending",
                )?;
                if let Some(previous) = &grant.secret_ref {
                    this.clients.secrets().transition(db, &store_ref(previous), "retiring")?;
                }
                this.declare(
                    db,
                    &grant,
                    "rotate",
                    GrantUpdate::new().secret(SecretRef::new(secret_id, version)),
                    &context,
                )
            })
        })
        .await
    }

    /// `delete_from_protocol_page(protocol, username, delete_runtime, …)`: a protocol page deletes
    /// the runtime account itself; the grant the panel keeps for it goes with it, its own lane
    /// first. Answers what `delete_runtime` answered.
    pub async fn delete_from_protocol_page<T, E, F>(
        &self,
        protocol: Protocol,
        username: &str,
        delete_runtime: F,
        context: &AuditContext,
    ) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
        E: From<ClientsError>,
    {
        let grant = {
            let (facade, name) = (self.facade.clone(), username.to_string());
            blocking(move || facade.grant(protocol, &name)).await?
        };
        if let (Some(grant), Some(lanes)) = (&grant, self.lanes()) {
            if grant.own_lane {
                lanes.disable(&grant.id, context).await.map_err(ClientsError::Seam)?;
            }
        }
        let result = delete_runtime.await?;
        if let Some(grant) = grant {
            let (this, name, context) = (self.clone(), username.to_string(), context.clone());
            blocking(move || {
                this.facade.forget(protocol, &name, &context)?;
                this.clients.database().transaction(|db| this.clients.purge_grant(db, &grant.id))
            })
            .await?;
        }
        Ok(result)
    }

    /// `delete(grant_id, …)`: local — the account is removed, the grant follows it and the row is
    /// purged at once; remote — the grant is `deleted` for the next generation (an operation still
    /// waiting for the node is settled now) and purged by the pusher once the node confirms.
    pub async fn delete(&self, grant_id: &str, context: &AuditContext) -> Result<(), ClientsError> {
        let (grant, remote) = self.load_async(grant_id).await?;
        if grant.own_lane {
            if let Some(lanes) = self.lanes() {
                // The lane goes first, then the account itself.
                lanes.disable(&grant.id, context).await.map_err(ClientsError::Seam)?;
            }
        }
        if !remote {
            let adapter = self.facade.adapters().require(grant.protocol)?;
            let reference =
                GrantRef { protocol: grant.protocol, runtime_username: grant.runtime_username.clone(), revision: None };
            if let Err(error) = adapter.delete(&reference).await {
                // The runtime no longer has the user: the outcome asked for already holds.
                if !error.already_gone {
                    return Err(ClientsError::adapter(grant.protocol, error));
                }
            }
            let (this, context) = (self.clone(), context.clone());
            return blocking(move || {
                this.facade.forget(grant.protocol, &grant.runtime_username, &context)?;
                this.clients.database().transaction(|db| this.clients.purge_grant(db, &grant.id))
            })
            .await;
        }
        let (this, id, context) = (self.clone(), grant_id.to_string(), context.clone());
        blocking(move || {
            this.clients.database().transaction(|db| {
                let grant = Self::live(db, &id)?;
                this.provisioning.withdraw_remote(db, &grant.id, WITHDRAWN)?;
                this.declare(db, &grant, "delete", GrantUpdate::new().desired(GrantDesiredState::Deleted), &context)?;
                Ok(())
            })
        })
        .await
    }
}
