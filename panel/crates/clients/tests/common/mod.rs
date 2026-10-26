//! Helpers shared by the integration tests: a migrated database in a temporary directory, the
//! services wired like `create_app`, and an in-memory protocol adapter (the Rust stand-in for the
//! Python tests' `MemoryNaive`/`MemoryMieru`/`MemoryTelemt` behind the real adapters).
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use panel_clients::{Adapters, AuditContext, ClientService, DomainFacade, GrantLifecycle, ProvisioningService};
use panel_core::clock::{FakeClock, SharedClock};
use panel_core::db::Database;
use panel_model::clients::{AccessGrant, GrantIntent, ProtocolOptions};
use panel_model::fleet::CredentialOrigin;
use panel_model::protocols::{
    AccessArtifact, AdapterError, AppliedEgress, AppliedGrant, AutoRefresh, BoxFuture, CredentialPlan, EgressTarget,
    GrantRef, ObservedGrant, ObservedInventory, Preflight, ProtocolAdapter,
};
use panel_model::Protocol;
use panel_secrets::audit::Actor;
use panel_secrets::keyring::Keyring;
use panel_secrets::secrets_store::SecretStore;
use serde_json::{Map, Value};

/// A directory removed when dropped.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "panel-clients-{label}-{}-{}",
            std::process::id(),
            panel_core::ids::token_hex(6)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

pub fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/goldens").join(name)
}

pub fn migrated(dir: &TempDir) -> Database {
    let database = Database::open(dir.join("panel.sqlite3")).unwrap();
    panel_core::migrations::apply_migrations(&database).unwrap();
    database
}

/// `{"id": 1, "username": "owner"}`, ip `127.0.0.1`, request `req-1`.
pub fn ctx() -> AuditContext {
    AuditContext::new(Actor::new(Some(1), "owner"), "127.0.0.1", Some("req-1".into()))
}

/// One account of the in-memory runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeUser {
    pub password: Vec<u8>,
    pub enabled: bool,
}

/// How the next call of an operation misbehaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The manager answers an error (an `AdapterError`).
    Fail,
    /// The manager commits, the reply is lost (an escaped manager failure: resume, never
    /// compensate).
    LoseResponse,
    /// Success is answered but nothing changes.
    Dishonest,
}

/// The in-memory runtime behind one adapter.
pub struct FakeAdapter {
    pub protocol: Protocol,
    pub origin: CredentialOrigin,
    pub capture: bool,
    pub users: Mutex<BTreeMap<String, FakeUser>>,
    pub faults: Mutex<HashMap<&'static str, Fault>>,
    pub calls: Mutex<Vec<String>>,
    pub discovers: AtomicUsize,
    applied: Mutex<HashSet<String>>,
    pub template: Mutex<Map<String, Value>>,
}

impl FakeAdapter {
    pub fn new(protocol: Protocol) -> Arc<Self> {
        let (origin, capture) = match protocol {
            Protocol::Mtproxy => (CredentialOrigin::Manager, true),
            Protocol::Naive => (CredentialOrigin::Caller, true),
            _ => (CredentialOrigin::Caller, false),
        };
        Arc::new(Self {
            protocol,
            origin,
            capture,
            users: Mutex::new(BTreeMap::new()),
            faults: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            discovers: AtomicUsize::new(0),
            applied: Mutex::new(HashSet::new()),
            template: Mutex::new(Map::new()),
        })
    }

    pub fn seed(&self, username: &str, password: &str) {
        self.users
            .lock()
            .unwrap()
            .insert(username.into(), FakeUser { password: password.as_bytes().to_vec(), enabled: true });
    }

    pub fn fault(&self, operation: &'static str, fault: Fault) {
        self.faults.lock().unwrap().insert(operation, fault);
    }

    pub fn clear_faults(&self) {
        self.faults.lock().unwrap().clear();
    }

    pub fn enabled(&self, username: &str) -> Option<bool> {
        self.users.lock().unwrap().get(username).map(|user| user.enabled)
    }

    pub fn names(&self) -> Vec<String> {
        self.users.lock().unwrap().keys().cloned().collect()
    }

    fn take_fault(&self, operation: &'static str) -> Option<Fault> {
        self.faults.lock().unwrap().get(operation).copied()
    }

    fn call(&self, what: impl Into<String>) {
        self.calls.lock().unwrap().push(what.into());
    }

    fn lost() -> AdapterError {
        panel_protocols::error::raw_telemt(panel_managers::TelemtError::indeterminate("the reply was lost"))
    }

    fn set_enabled(&self, grant: &GrantRef, enabled: bool) -> Result<AppliedGrant, AdapterError> {
        let operation = if enabled { "enable" } else { "disable" };
        self.call(format!("{operation}:{}", grant.runtime_username));
        match self.take_fault(operation) {
            Some(Fault::Fail) => return Err(AdapterError::new("manager unavailable")),
            Some(Fault::Dishonest) => return Ok(AppliedGrant::new(grant.runtime_username.clone(), enabled)),
            _ => {}
        }
        let mut users = self.users.lock().unwrap();
        let user = users.get_mut(&grant.runtime_username).ok_or_else(|| AdapterError::new("no such user"))?;
        user.enabled = enabled;
        Ok(AppliedGrant::new(grant.runtime_username.clone(), enabled))
    }

    fn chosen(&self, plan: &CredentialPlan) -> Vec<u8> {
        match plan.plaintext() {
            Some(bytes) => bytes.to_vec(),
            None => format!("mgr{}", panel_core::ids::token_hex(15)).into_bytes(),
        }
    }
}

impl ProtocolAdapter for FakeAdapter {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn credential_origin(&self) -> CredentialOrigin {
        self.origin
    }

    fn capture_supported(&self) -> bool {
        self.capture
    }

    fn accepts_caller_credential(&self) -> bool {
        self.origin == CredentialOrigin::Caller
    }

    fn discover(&self) -> BoxFuture<'_, Result<ObservedInventory, AdapterError>> {
        self.discovers.fetch_add(1, Ordering::SeqCst);
        let items = self
            .users
            .lock()
            .unwrap()
            .iter()
            .map(|(name, user)| ObservedGrant {
                runtime_username: name.clone(),
                enabled: user.enabled,
                options: Map::new(),
                revision: None,
            })
            .collect();
        Box::pin(async move { Ok(ObservedInventory { items }) })
    }

    fn preflight<'a>(&'a self, intent: &'a GrantIntent) -> BoxFuture<'a, Result<Preflight, AdapterError>> {
        let taken = self.users.lock().unwrap().contains_key(&intent.runtime_username);
        Box::pin(async move {
            Ok(if taken {
                Preflight { ok: false, reason: Some("runtime_username already exists".into()) }
            } else {
                Preflight { ok: true, reason: None }
            })
        })
    }

    fn create<'a>(
        &'a self,
        operation_id: &'a str,
        intent: &'a GrantIntent,
        credential: &'a CredentialPlan,
    ) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        Box::pin(async move {
            self.call(format!("create:{}", intent.runtime_username));
            let name = intent.runtime_username.clone();
            let replay = self.applied.lock().unwrap().contains(operation_id);
            let mut users = self.users.lock().unwrap();
            if users.contains_key(&name) && !replay {
                return Err(AdapterError::new("runtime_username already exists"));
            }
            let password = match users.get(&name) {
                Some(user) if replay => user.password.clone(),
                _ => self.chosen(credential),
            };
            users.insert(name.clone(), FakeUser { password: password.clone(), enabled: true });
            self.applied.lock().unwrap().insert(operation_id.to_string());
            drop(users);
            if self.take_fault("create") == Some(Fault::LoseResponse) {
                return Err(Self::lost());
            }
            let mut applied = AppliedGrant::new(name, true);
            applied.credential = Some(password);
            applied.credential_origin = self.origin;
            applied.artifact_template = self.template.lock().unwrap().clone();
            Ok(applied)
        })
    }

    fn enable<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        Box::pin(async move { self.set_enabled(grant, true) })
    }

    fn disable<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        Box::pin(async move { self.set_enabled(grant, false) })
    }

    fn rotate<'a>(
        &'a self,
        _operation_id: &'a str,
        grant: &'a GrantRef,
        credential: &'a CredentialPlan,
    ) -> BoxFuture<'a, Result<AppliedGrant, AdapterError>> {
        Box::pin(async move {
            self.call(format!("rotate:{}", grant.runtime_username));
            let password = self.chosen(credential);
            let mut users = self.users.lock().unwrap();
            let user = users.get_mut(&grant.runtime_username).ok_or_else(|| AdapterError::new("no such user"))?;
            user.password = password.clone();
            let mut applied = AppliedGrant::new(grant.runtime_username.clone(), user.enabled);
            applied.credential = Some(password);
            Ok(applied)
        })
    }

    fn delete<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<(), AdapterError>> {
        Box::pin(async move {
            self.call(format!("delete:{}", grant.runtime_username));
            if self.take_fault("delete") == Some(Fault::Fail) {
                return Err(AdapterError::new("manager unavailable"));
            }
            match self.users.lock().unwrap().remove(&grant.runtime_username) {
                Some(_) => Ok(()),
                None => Err(AdapterError::already_gone("no such user")),
            }
        })
    }

    fn capture<'a>(&'a self, grant: &'a GrantRef) -> BoxFuture<'a, Result<Option<Vec<u8>>, AdapterError>> {
        Box::pin(async move {
            self.call(format!("capture:{}", grant.runtime_username));
            Ok(self.users.lock().unwrap().get(&grant.runtime_username).map(|user| user.password.clone()))
        })
    }

    fn update_options<'a>(
        &'a self,
        _grant: &'a GrantRef,
        _options: &'a Map<String, Value>,
    ) -> BoxFuture<'a, Result<Option<AppliedGrant>, AdapterError>> {
        Box::pin(async { Ok(None) })
    }

    fn render_artifacts(
        &self,
        grant: &AccessGrant,
        credential: &[u8],
        public_host: &str,
    ) -> Result<Vec<AccessArtifact>, AdapterError> {
        let media_type = if grant.protocol == Protocol::Amneziawg { "text/x-amneziawg-conf" } else { "text/uri-list" };
        Ok(vec![AccessArtifact {
            kind: "link".into(),
            label: "Link".into(),
            media_type: media_type.into(),
            value: format!(
                "{}://{}:{}@{public_host}",
                grant.protocol,
                grant.runtime_username,
                String::from_utf8_lossy(credential)
            ),
            auto_refresh: AutoRefresh::Supported,
        }])
    }

    fn egress_target(&self) -> BoxFuture<'_, Result<Option<EgressTarget>, AdapterError>> {
        Box::pin(async { Ok(None) })
    }

    fn plan_egress<'a>(
        &'a self,
        _document: &'a Map<String, Value>,
        _expected_revision: &'a str,
    ) -> BoxFuture<'a, Result<Map<String, Value>, AdapterError>> {
        Box::pin(async { Err(AdapterError::new("unsupported")) })
    }

    fn apply_egress<'a>(
        &'a self,
        _document: &'a Map<String, Value>,
        _expected_revision: &'a str,
        _operation_id: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>> {
        Box::pin(async { Err(AdapterError::new("unsupported")) })
    }

    fn rollback_egress<'a>(
        &'a self,
        _expected_revision: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>> {
        Box::pin(async { Err(AdapterError::new("unsupported")) })
    }
}

/// The services of one panel, wired like `create_app`, over in-memory runtimes.
pub struct Env {
    pub dir: TempDir,
    pub database: Database,
    pub secrets: SecretStore,
    pub clock: Arc<FakeClock>,
    pub adapters: Adapters,
    pub fakes: HashMap<Protocol, Arc<FakeAdapter>>,
    pub clients: ClientService,
    pub provisioning: ProvisioningService,
    pub facade: DomainFacade,
    pub lifecycle: GrantLifecycle,
}

impl Env {
    /// A panel with a keyring and the five in-memory runtimes; the clock at 1_800_000_000.
    pub fn new(label: &str) -> Self {
        Self::with_keyring(label, true)
    }

    pub fn with_keyring(label: &str, keyring: bool) -> Self {
        let dir = TempDir::new(label);
        let database = migrated(&dir);
        let clock = Arc::new(FakeClock::default());
        let shared: SharedClock = clock.clone();
        let secrets = SecretStore::with_clock(keyring.then(Keyring::generate), shared.clone());
        let adapters = Adapters::new();
        let mut fakes = HashMap::new();
        for protocol in
            [Protocol::Mtproxy, Protocol::Naive, Protocol::Mieru, Protocol::Amneziawg, Protocol::Trusttunnel]
        {
            let fake = FakeAdapter::new(protocol);
            adapters.insert(protocol, fake.clone());
            fakes.insert(protocol, fake);
        }
        let clients = ClientService::new(database.clone(), secrets.clone(), shared.clone(), adapters.clone());
        let provisioning = ProvisioningService::new(
            database.clone(),
            secrets.clone(),
            adapters.clone(),
            clients.clone(),
            shared.clone(),
        );
        let facade = DomainFacade::new(clients.clone(), provisioning.clone(), adapters.clone(), shared.clone());
        let lifecycle = GrantLifecycle::new(facade.clone(), shared);
        Self { dir, database, secrets, clock, adapters, fakes, clients, provisioning, facade, lifecycle }
    }

    pub fn fake(&self, protocol: Protocol) -> &Arc<FakeAdapter> {
        &self.fakes[&protocol]
    }

    /// A linked panel (`fleet_nodes.transport = 'panel'`) with a `node_links` row.
    pub fn link_node(&self, node_id: &str, identity: Value) {
        self.database
            .transaction(|db| {
                db.execute(
                    "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at,transport)
                     VALUES(?,'Edge','active','{}',1,1,'panel')",
                    panel_core::rusqlite::params![node_id],
                )?;
                db.execute(
                    "INSERT INTO node_links(node_id,panel_url,tls_verify,api_key_secret_id,identity_json,created_at,updated_at)
                     VALUES(?,'https://node.example','verify','key:x',?,1,1)",
                    panel_core::rusqlite::params![node_id, identity.to_string()],
                )?;
                Ok::<_, panel_core::db::DbError>(())
            })
            .unwrap();
    }

    pub fn count(&self, sql: &str) -> i64 {
        self.database
            .with_connection(|db| db.query_row(sql, [], |row| row.get(0)).map_err(panel_core::db::DbError::from))
            .unwrap()
    }

    pub fn grants(&self, client_id: &str) -> Vec<AccessGrant> {
        self.clients.client_with_grants(client_id).unwrap().1
    }

    pub fn secret_states(&self, grant_id: &str) -> Vec<(i64, String)> {
        self.database
            .with_connection(|db| {
                let mut statement =
                    db.prepare("SELECT version, state FROM secret_versions WHERE secret_id=? ORDER BY version")?;
                let rows = statement.query_map([format!("grant:{grant_id}")], |row| Ok((row.get(0)?, row.get(1)?)))?;
                rows.collect::<Result<Vec<_>, _>>().map_err(panel_core::db::DbError::from)
            })
            .unwrap()
    }

    pub fn actions(&self) -> Vec<String> {
        self.database
            .with_connection(|db| {
                let mut statement = db.prepare("SELECT action FROM audit_log ORDER BY id")?;
                let rows = statement.query_map([], |row| row.get(0))?;
                rows.collect::<Result<Vec<_>, _>>().map_err(panel_core::db::DbError::from)
            })
            .unwrap()
    }
}

/// `GrantIntent(protocol=…, runtime_username=…, options=PROTOCOL_OPTIONS[protocol]())`.
pub fn intent(protocol: Protocol, username: &str) -> GrantIntent {
    GrantIntent::new(protocol, username, ProtocolOptions::default_for(protocol)).unwrap()
}

/// The same on another node, with an optional validity window.
pub fn intent_on(protocol: Protocol, username: &str, node_id: &str) -> GrantIntent {
    let mut intent = intent(protocol, username);
    intent.node_id = node_id.into();
    intent
}
