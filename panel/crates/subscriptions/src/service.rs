//! Subscriptions: a bearer URL the panel can invalidate, and an ETag that means something
//! (`subscriptions/service.py`).
//!
//! The URL is a bearer credential: `/s/{token}` looks up its hash. With a keyring the panel also
//! keeps an encrypted copy so an operator can see the URL again (an audited reveal); a rotated or
//! revoked URL retires its copy in the same transaction, and rotation never leaves two live URLs.
//! `generation` moves inside the transaction of the change that caused it. The ETag is computed
//! from the *effective* grants and deliberately excludes `generation` and `last_fetched_at`.

use std::sync::Arc;

use panel_clients::store as clients_store;
use panel_clients::{AuditContext, ClientService, ClientsError};
use panel_core::clock::SharedClock;
use panel_core::db::{Conn, Database};
use panel_model::clients::{effective_enabled, Client, ClientState};
use panel_model::seams::{ClientChangeHook, SeamError};
use panel_model::subscriptions::{Manifest, ManifestGrant, Subscription};
use panel_model::Model as _;
use panel_secrets::audit::{self, digest, Record};
use panel_secrets::events::EventBus;
use panel_secrets::secrets_store::{Identity, SecretError, SecretRef as StoreRef, SecretStore};
use serde_json::{json, Map, Value};

use crate::apps::SHARE_VARIANTS;
use crate::names::{grant_names, NameCollision};
use crate::store;

/// `TOKEN_BYTES`: `token_urlsafe(32)` is 43 characters.
pub const TOKEN_BYTES: usize = 32;
/// The purpose of an escrowed token in `secret_versions`.
pub const SUBSCRIPTION_PURPOSE: &str = "subscription";
/// `update_interval_hours` of every subscription (the `Profile-Update-Interval` header).
pub const UPDATE_INTERVAL_HOURS: i64 = 12;

/// `sha256(token).hexdigest()`.
pub fn token_hash(token: &str) -> String {
    panel_core::ids::sha256_hex(token.as_bytes())
}

fn internal(error: impl std::fmt::Display) -> ClientsError {
    ClientsError::Internal(error.to_string())
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// The subscription service (`SubscriptionService`). Cheap to clone.
#[derive(Clone)]
pub struct SubscriptionService {
    database: Database,
    clients: ClientService,
    secrets: SecretStore,
    clock: SharedClock,
    public_base: String,
    /// Events ride in the same transaction as the change they report.
    events: Option<Arc<EventBus>>,
}

impl std::fmt::Debug for SubscriptionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionService").field("public_base", &self.public_base).finish_non_exhaustive()
    }
}

impl SubscriptionService {
    pub fn new(
        database: Database,
        clients: ClientService,
        secrets: SecretStore,
        clock: SharedClock,
        public_base: impl Into<String>,
        events: Option<Arc<EventBus>>,
    ) -> Self {
        Self { database, clients, secrets, clock, public_base: public_base.into(), events }
    }

    /// The same service over another secret store (a keyring switched off or rotated).
    pub fn with_secrets(mut self, secrets: SecretStore) -> Self {
        self.secrets = secrets;
        self
    }

    /// The same service with another `public_base` (`PANEL_SUBSCRIPTION_URL`).
    pub fn with_public_base(mut self, public_base: impl Into<String>) -> Self {
        self.public_base = public_base.into();
        self
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    pub fn clients(&self) -> &ClientService {
        &self.clients
    }

    pub fn secrets(&self) -> &SecretStore {
        &self.secrets
    }

    /// `public_base` (empty: no subscription domain configured).
    pub fn public_base(&self) -> &str {
        &self.public_base
    }

    /// `int(clock.time())`.
    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// `escrow_enabled`: a keyring is loaded.
    pub fn escrow_enabled(&self) -> bool {
        self.secrets.enabled()
    }

    fn emit(&self, db: &Conn, name: &str, payload: Value) -> Result<(), ClientsError> {
        if let Some(events) = &self.events {
            events.emit(db, name, &object(payload)).map_err(internal)?;
        }
        Ok(())
    }

    fn record(
        db: &Conn,
        context: &AuditContext,
        action: &str,
        target: &str,
        generation: Option<i64>,
        detail: Value,
    ) -> Result<(), ClientsError> {
        let mut row: Record = context.row(action, target).detail(object(detail));
        row.generation = generation;
        audit::record(db, &row)?;
        Ok(())
    }

    // --- lifecycle ------------------------------------------------------------------------

    /// `_issue(db, client_id, generation=…)`: a fresh token, its hash in the row and, with a
    /// keyring, its escrowed copy bound to the subscription id.
    fn issue(&self, db: &Conn, client_id: &str, generation: i64) -> Result<(Subscription, String), ClientsError> {
        let now = self.now();
        let token = panel_core::ids::token_urlsafe(TOKEN_BYTES);
        let id = panel_core::ids::uuid4();
        let mut secret_ref = None;
        if self.escrow_enabled() {
            let secret_id = format!("subscription:{id}");
            let identity = Identity {
                secret_id: &secret_id,
                version: 1,
                purpose: SUBSCRIPTION_PURPOSE,
                grant_id: None,
                permitted_node_id: None,
            };
            let stored = self.secrets.store(db, &identity, token.as_bytes(), "active")?;
            secret_ref = Some(panel_model::SecretRef { secret_id: stored.secret_id, version: stored.version });
        }
        let subscription = Subscription {
            id,
            client_id: client_id.to_string(),
            generation,
            state: "active".into(),
            update_interval_hours: UPDATE_INTERVAL_HOURS,
            last_fetched_at: None,
            created_at: now,
            updated_at: now,
            revoked_at: None,
            secret_ref,
        };
        store::insert(db, &subscription, &token_hash(&token))?;
        Ok((subscription, token))
    }

    /// `_retire_escrow(db, subscription)`: a rotated or revoked URL must not be showable. Needs no
    /// key, so it runs even after the keyring has been switched off.
    fn retire_escrow(&self, db: &Conn, subscription: &Subscription) -> Result<(), ClientsError> {
        if let Some(reference) = &subscription.secret_ref {
            self.secrets.transition(db, &StoreRef::new(reference.secret_id.clone(), reference.version), "revoked")?;
        }
        Ok(())
    }

    /// `create(client_id, …)`: only an active client without a live subscription gets one.
    pub fn create(&self, client_id: &str, context: &AuditContext) -> Result<(Subscription, String), ClientsError> {
        self.database.transaction(|db| {
            let client = clients_store::client(db, client_id)?;
            if client.state != ClientState::Active {
                return Err(ClientsError::Conflict("only an active client can hold a subscription".into()));
            }
            if store::active(db, client_id)?.is_some() {
                return Err(ClientsError::Conflict("the client already has an active subscription".into()));
            }
            let (subscription, token) = self.issue(db, client_id, 1)?;
            Self::record(
                db,
                context,
                "subscription.create",
                &subscription.id,
                Some(subscription.generation),
                json!({"client_id": client_id}),
            )?;
            Ok((subscription, token))
        })
    }

    /// `create_with_client(display_name, …)`: a client and its URL in one transaction; without a
    /// subscription domain only the client is made.
    pub fn create_with_client(
        &self,
        display_name: &str,
        context: &AuditContext,
    ) -> Result<(Client, Option<(Subscription, String)>), ClientsError> {
        let now = self.now();
        self.database.transaction(|db| {
            let client = self.clients.new_client(db, display_name, now)?;
            let mut row = context.row("client.create", &client.id);
            row.after_digest = Some(digest(&client.dump()));
            audit::record(db, &row)?;
            self.clients.notify(db, &client.id)?;
            if self.public_base.is_empty() {
                return Ok((client, None));
            }
            let (subscription, token) = self.issue(db, &client.id, 1)?;
            Self::record(
                db,
                context,
                "subscription.create",
                &subscription.id,
                Some(subscription.generation),
                json!({"client_id": client.id}),
            )?;
            Ok((client, Some((subscription, token))))
        })
    }

    /// `rotate(client_id, …)`: the new URL and the old one's revocation land together.
    pub fn rotate(&self, client_id: &str, context: &AuditContext) -> Result<(Subscription, String), ClientsError> {
        self.database.transaction(|db| {
            let Some(current) = store::active(db, client_id)? else {
                return Err(ClientsError::Conflict("the client has no active subscription to rotate".into()));
            };
            let now = self.now();
            store::revoke(db, client_id, now)?;
            self.retire_escrow(db, &current)?;
            let (subscription, token) = self.issue(db, client_id, current.generation + 1)?;
            Self::record(
                db,
                context,
                "subscription.rotate",
                &subscription.id,
                Some(subscription.generation),
                json!({"client_id": client_id, "revoked": current.id}),
            )?;
            self.emit(
                db,
                "subscription.revoked",
                json!({"subscription_id": current.id, "client_id": client_id, "reason": "rotated"}),
            )?;
            Ok((subscription, token))
        })
    }

    /// `revoke(client_id, …)`: a no-op without a live subscription.
    pub fn revoke(&self, client_id: &str, context: &AuditContext) -> Result<(), ClientsError> {
        self.database.transaction(|db| {
            let Some(current) = store::active(db, client_id)? else { return Ok(()) };
            store::revoke(db, client_id, self.now())?;
            self.retire_escrow(db, &current)?;
            Self::record(db, context, "subscription.revoke", &current.id, None, json!({"client_id": client_id}))?;
            self.emit(
                db,
                "subscription.revoked",
                json!({"subscription_id": current.id, "client_id": client_id, "reason": "revoked"}),
            )
        })
    }

    /// `reveal_token(client_id, …)`: the escrowed token for an operator — audited, never logged.
    pub fn reveal_token(
        &self,
        client_id: &str,
        context: &AuditContext,
    ) -> Result<(Subscription, String), ClientsError> {
        self.database.transaction(|db| {
            clients_store::client(db, client_id)?;
            let Some(current) = store::active(db, client_id)? else {
                return Err(ClientsError::NotFound(client_id.to_string()));
            };
            if !self.escrow_enabled() {
                return Err(ClientsError::Secret(SecretError::DISABLED));
            }
            let Some(reference) = &current.secret_ref else {
                return Err(ClientsError::Conflict(
                    "subscription is not escrowed: rotate it to get a URL that can be shown".into(),
                ));
            };
            let plaintext = self.secrets.reveal(
                db,
                &StoreRef::new(reference.secret_id.clone(), reference.version),
                SUBSCRIPTION_PURPOSE,
                None,
                None,
            )?;
            let token = String::from_utf8(plaintext).map_err(internal)?;
            Self::record(
                db,
                context,
                "subscription.reveal",
                &current.id,
                Some(current.generation),
                json!({"client_id": client_id}),
            )?;
            Ok((current, token))
        })
    }

    /// `get(client_id)`: the live subscription.
    pub fn get(&self, client_id: &str) -> Result<Option<Subscription>, ClientsError> {
        Ok(self.database.with_connection(|db| store::active(db, client_id))?)
    }

    /// `bump_generation(db, client_id)`: inside the caller's transaction — a rolled-back change
    /// bumps nothing.
    pub fn bump_generation(&self, db: &Conn, client_id: &str) -> Result<(), ClientsError> {
        if store::bump(db, client_id, self.now())? == 0 {
            return Ok(());
        }
        let Some(current) = store::active(db, client_id)? else { return Ok(()) };
        self.emit(
            db,
            "subscription.generation.changed",
            json!({"subscription_id": current.id, "client_id": client_id, "generation": current.generation}),
        )
    }

    /// `resolve(token)`: the live subscription a bearer token names; unknown or revoked is `None`.
    pub fn resolve(&self, token: &str) -> Result<Option<Subscription>, ClientsError> {
        if token.is_empty() {
            return Ok(None);
        }
        Ok(self.database.with_connection(|db| store::by_hash(db, &token_hash(token)))?)
    }

    /// `record_fetch(subscription, now, status=…, format=…)`: the last-fetched mark and the event,
    /// in one transaction.
    pub fn record_fetch(
        &self,
        subscription: &Subscription,
        now: i64,
        status: u16,
        format: &str,
    ) -> Result<(), ClientsError> {
        self.database.transaction(|db| {
            store::record_fetch(db, &subscription.id, now)?;
            self.emit(
                db,
                "subscription.fetched",
                json!({
                    "subscription_id": subscription.id,
                    "client_id": subscription.client_id,
                    "status": status,
                    "format": format,
                }),
            )
        })
    }

    // --- manifest -------------------------------------------------------------------------

    /// `effective_manifest(subscription, now)`: every grant of the client but AmneziaWG (handed out
    /// as a config file, never as a feed entry), effective-enabled at `now`.
    pub fn effective_manifest(&self, subscription: &Subscription, now: i64) -> Result<Manifest, ClientsError> {
        self.database.with_connection(|db| {
            let client = clients_store::client(db, &subscription.client_id)?;
            let grants = clients_store::client_grants(db, &subscription.client_id)?;
            let generation = store::active(db, &subscription.client_id)?
                .map_or(subscription.generation, |current| current.generation);
            let mut node_names = std::collections::HashMap::new();
            {
                let mut statement = db.prepare("SELECT node_id, display_name FROM fleet_nodes")?;
                let rows =
                    statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)))?;
                for row in rows {
                    let (node_id, name) = row?;
                    node_names.insert(node_id, name.unwrap_or_default());
                }
            }
            let items = grants
                .iter()
                .filter(|grant| grant.protocol.as_str() != "amneziawg")
                .map(|grant| ManifestGrant {
                    grant_id: grant.id.clone(),
                    protocol: grant.protocol.as_str().to_string(),
                    node_id: grant.node_id.clone(),
                    endpoint_id: grant.endpoint_id.clone(),
                    runtime_username: grant.runtime_username.clone(),
                    secret_version: grant.secret_ref.as_ref().map_or(0, |reference| reference.version),
                    options: object(grant.options.dump()),
                    enabled: effective_enabled(grant, &client, now),
                    valid_from: grant.valid_from,
                    valid_until: grant.valid_until,
                    node_name: node_names.get(&grant.node_id).cloned().unwrap_or_default(),
                    label: grant.label.clone().unwrap_or_default(),
                })
                .collect();
            Ok(Manifest::new(client.id.clone(), client.display_name.clone(), generation, items))
        })
    }

    /// `etag(manifest, renderer_version, variant)`: what the client would receive, not when it last
    /// asked — sha256 of the canonical JSON of the display names (all grants) and the enabled grants
    /// (by id), the renderer version and the variant (a sing-box cut, or the page's language and
    /// time).
    pub fn etag(manifest: &Manifest, renderer_version: i64, variant: &str) -> Result<String, NameCollision> {
        let names = grant_names(manifest)?;
        let mut grants: Vec<&ManifestGrant> = manifest.grants.iter().filter(|grant| grant.enabled).collect();
        grants.sort_by(|a, b| a.grant_id.cmp(&b.grant_id));
        let grants: Vec<Value> = grants
            .into_iter()
            .map(|item| {
                json!({
                    "grant_id": item.grant_id,
                    "protocol": item.protocol,
                    "node_id": item.node_id,
                    "node_name": item.node_name,
                    "display_name": names[&item.grant_id],
                    "endpoint_id": item.endpoint_id,
                    "runtime_username": item.runtime_username,
                    "secret_version": item.secret_version,
                    "options": item.options,
                    "valid_from": item.valid_from,
                    "valid_until": item.valid_until,
                })
            })
            .collect();
        let payload = json!({
            "client_name": manifest.client_name,
            "display_names": names,
            "grants": grants,
            "renderer": renderer_version,
            "variant": variant,
        });
        Ok(token_hash(&panel_core::pyjson::canonical(&payload)))
    }

    /// `public_url(token)`.
    pub fn public_url(&self, token: &str) -> String {
        format!("{}/s/{token}", self.public_base.trim_end_matches('/'))
    }

    /// `subscription_reveal_payload(app, subscription, token)`: the URL, its variants and their QR
    /// codes — everything the dialog shows.
    pub fn reveal_payload(&self, subscription: &Subscription, token: &str) -> Result<Value, ClientsError> {
        let url = self.public_url(token);
        let qr = |text: &str| panel_protocols::reveals::qr_data(text).map_err(internal);
        let mut variants = Map::new();
        for (name, query) in SHARE_VARIANTS {
            let link = format!("{url}{query}");
            variants.insert(name.to_string(), json!({"url": link, "qr": qr(&link)?}));
        }
        Ok(json!({
            "subscription_id": subscription.id,
            "generation": subscription.generation,
            "url": url,
            "qr": qr(&url)?,
            "variants": variants,
        }))
    }

    /// `overview(client_id)` of `GET /api/clients/{id}/subscription`: the row as the operator sees
    /// it (no secret reference, no token) and the client's grants.
    pub fn overview(&self, client_id: &str) -> Result<Value, ClientsError> {
        let now = self.now();
        let (client, grants, current) = self.database.with_connection(|db| -> Result<_, ClientsError> {
            let client = clients_store::client(db, client_id)?;
            let grants = clients_store::client_grants(db, client_id)?;
            let current = store::active(db, client_id)?;
            Ok((client, grants, current))
        })?;
        let grants: Vec<Value> = grants
            .iter()
            .map(|grant| {
                json!({
                    "grant_id": grant.id,
                    "protocol": grant.protocol.as_str(),
                    "node_id": grant.node_id,
                    "runtime_username": grant.runtime_username,
                    "enabled": effective_enabled(grant, &client, now),
                    "has_credential": grant.secret_ref.is_some(),
                })
            })
            .collect();
        Ok(json!({
            "configured": !self.public_base.is_empty(),
            "secret_store": self.escrow_enabled(),
            "escrowed": current.as_ref().is_some_and(|current| current.secret_ref.is_some()),
            "subscription": current.as_ref().map_or(Value::Null, store::public_json),
            "grants": grants,
        }))
    }
}

/// `clients.on_change.append(subscriptions.bump_generation)`.
pub struct BumpGeneration(pub SubscriptionService);

impl ClientChangeHook for BumpGeneration {
    fn on_change(&self, db: &Conn, client_id: &str) -> Result<(), SeamError> {
        self.0.bump_generation(db, client_id).map_err(|error| -> SeamError { error.to_string().into() })
    }
}

impl panel_clients::subscriptions::SubscriptionIssuer for SubscriptionService {
    fn enabled(&self) -> bool {
        !self.public_base.is_empty()
    }

    fn create_with_client(&self, display_name: &str, context: &AuditContext) -> Result<(Client, Value), ClientsError> {
        let (client, issued) = SubscriptionService::create_with_client(self, display_name, context)?;
        let payload = match issued {
            Some((subscription, token)) => self.reveal_payload(&subscription, &token)?,
            None => Value::Null,
        };
        Ok((client, payload))
    }
}
