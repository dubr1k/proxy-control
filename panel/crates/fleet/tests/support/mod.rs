//! Helpers shared by the integration tests: a migrated database in a temporary directory, the
//! memory doubles behind the real adapters, and a [`FleetNode`] on a fake clock.

#![allow(dead_code)]

pub mod doubles;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use panel_core::clock::FakeClock;
use panel_core::db::{row_to_json, Database};
use panel_fleet::node::runtime::{FleetRouter, NodeRuntime, VersionAgent};
use panel_fleet::node::{FleetNode, NodeConfig};
use panel_managers::VersionAgentError;
use panel_model::protocols::{AdapterError, BoxFuture, ProtocolAdapter};
use panel_model::Protocol;
use panel_protocols::{AmneziawgAdapter, MieruAdapter, NaiveAdapter, TelemtAdapter, TrusttunnelAdapter};
use panel_secrets::keyring::Keyring;
use panel_secrets::secrets_store::SecretStore;
use serde_json::Value;

use doubles::{MemoryAmneziawg, MemoryMieru, MemoryNaive, MemoryTelemt, MemoryTrusttunnel};

/// A directory removed when dropped.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "panel-fleet-{label}-{}-{}",
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

pub fn golden(path: &str) -> Value {
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/goldens").join(path);
    serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
}

/// Every row of a query as `dict(row)`.
pub fn table(database: &Database, sql: &str) -> Vec<Value> {
    let conn = database.connect().unwrap();
    let mut statement = conn.prepare(sql).unwrap();
    statement.query_map([], row_to_json).unwrap().map(|row| Value::Object(row.unwrap())).collect()
}

/// `app.state.adapters` over the memory doubles, swappable per test.
pub struct TestRuntime {
    pub telemt: MemoryTelemt,
    pub naive: MemoryNaive,
    pub mieru: MemoryMieru,
    pub amneziawg: MemoryAmneziawg,
    pub trusttunnel: MemoryTrusttunnel,
    pub naive_adapter: Arc<NaiveAdapter<MemoryNaive>>,
    pub mieru_adapter: Arc<MieruAdapter<MemoryMieru>>,
    pub telemt_adapter: Arc<TelemtAdapter<MemoryTelemt>>,
    pub amneziawg_adapter: Arc<AmneziawgAdapter<MemoryAmneziawg>>,
    adapters: Mutex<HashMap<Protocol, Arc<dyn ProtocolAdapter>>>,
    pub router: Mutex<Option<Arc<dyn FleetRouter>>>,
}

pub struct Hosts {
    pub telemt: (&'static str, i64),
    pub naive: &'static str,
    pub amneziawg: &'static str,
    pub trusttunnel: &'static str,
}

impl Default for Hosts {
    fn default() -> Self {
        Self {
            telemt: ("localhost", 443),
            naive: "naive.example.com",
            amneziawg: "naive.example.com",
            trusttunnel: "naive.example.com",
        }
    }
}

impl TestRuntime {
    pub fn new(hosts: &Hosts) -> Arc<Self> {
        let telemt = MemoryTelemt::new(hosts.telemt.0, hosts.telemt.1);
        let naive = MemoryNaive::new("naive.example.com");
        let mieru = MemoryMieru::default();
        let amneziawg = MemoryAmneziawg::default();
        let trusttunnel = MemoryTrusttunnel::new(hosts.trusttunnel);
        let telemt_adapter = Arc::new(TelemtAdapter::new(telemt.clone()).with_public_host(hosts.telemt.0));
        let naive_adapter = Arc::new(NaiveAdapter::new(naive.clone(), hosts.naive));
        let mieru_adapter = Arc::new(MieruAdapter::new(mieru.clone(), ""));
        let amneziawg_adapter = Arc::new(AmneziawgAdapter::new(amneziawg.clone(), hosts.amneziawg));
        let trusttunnel_adapter: Arc<TrusttunnelAdapter<MemoryTrusttunnel>> =
            Arc::new(TrusttunnelAdapter::new(trusttunnel.clone(), hosts.trusttunnel));
        let mut adapters: HashMap<Protocol, Arc<dyn ProtocolAdapter>> = HashMap::new();
        adapters.insert(Protocol::Mtproxy, telemt_adapter.clone());
        adapters.insert(Protocol::Naive, naive_adapter.clone());
        adapters.insert(Protocol::Mieru, mieru_adapter.clone());
        adapters.insert(Protocol::Amneziawg, amneziawg_adapter.clone());
        adapters.insert(Protocol::Trusttunnel, trusttunnel_adapter);
        Arc::new(Self {
            telemt,
            naive,
            mieru,
            amneziawg,
            trusttunnel,
            naive_adapter,
            mieru_adapter,
            telemt_adapter,
            amneziawg_adapter,
            adapters: Mutex::new(adapters),
            router: Mutex::new(None),
        })
    }

    /// `reconciler.adapters[protocol] = adapter`.
    pub fn set_adapter(&self, protocol: Protocol, adapter: Arc<dyn ProtocolAdapter>) {
        self.adapters.lock().unwrap().insert(protocol, adapter);
    }

    /// `del reconciler.adapters[protocol]`.
    pub fn remove_adapter(&self, protocol: Protocol) {
        self.adapters.lock().unwrap().remove(&protocol);
    }
}

impl NodeRuntime for TestRuntime {
    fn adapter(&self, protocol: Protocol) -> Option<Arc<dyn ProtocolAdapter>> {
        self.adapters.lock().unwrap().get(&protocol).cloned()
    }

    fn router(&self) -> Option<Arc<dyn FleetRouter>> {
        self.router.lock().unwrap().clone()
    }

    fn has_lanes(&self, protocol: Protocol) -> bool {
        matches!(protocol, Protocol::Naive | Protocol::Mieru)
    }

    fn set_lanes<'a>(&'a self, protocol: Protocol, lanes: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        match protocol {
            Protocol::Naive => Box::pin(self.naive_adapter.set_lanes(lanes)),
            _ => Box::pin(self.mieru_adapter.set_lanes(lanes)),
        }
    }

    fn healthy(&self, protocol: Protocol) -> BoxFuture<'_, bool> {
        let down = match protocol {
            Protocol::Mtproxy => false,
            Protocol::Naive => self.naive.state().broken,
            Protocol::Mieru => self.mieru.state().broken,
            Protocol::Amneziawg => self.amneziawg.state().broken,
            Protocol::Trusttunnel => self.trusttunnel.state().broken,
        };
        Box::pin(async move { !down })
    }

    fn amneziawg_versions(&self) -> BoxFuture<'_, Result<Vec<String>, AdapterError>> {
        Box::pin(self.amneziawg_adapter.versions())
    }

    fn telemt_users(&self) -> BoxFuture<'_, Option<Value>> {
        use panel_protocols::api::TelemtApi as _;
        Box::pin(async move { self.telemt.list_users().await.ok() })
    }

    fn naive_traffic(&self) -> BoxFuture<'_, Option<Value>> {
        Box::pin(async move { self.naive.traffic().ok() })
    }

    fn trusttunnel_clients(&self) -> BoxFuture<'_, Option<Value>> {
        use panel_protocols::api::TrusttunnelApi as _;
        Box::pin(async move { self.trusttunnel.clients().await.ok() })
    }

    fn amneziawg_peers(&self) -> BoxFuture<'_, Option<Value>> {
        use panel_protocols::api::AmneziawgApi as _;
        Box::pin(async move { self.amneziawg.peers().await.ok() })
    }
}

/// A version-agent with fixed answers; `None` is "unavailable" (502), like a panel without one.
pub struct StaticVersions {
    pub versions: Option<Value>,
    pub host: Option<Value>,
}

fn unavailable() -> VersionAgentError {
    VersionAgentError::new("version agent unavailable", 502)
}

impl VersionAgent for StaticVersions {
    fn list_versions(&self) -> BoxFuture<'_, Result<Value, VersionAgentError>> {
        Box::pin(async move { self.versions.clone().ok_or_else(unavailable) })
    }

    fn host(&self) -> BoxFuture<'_, Result<Value, VersionAgentError>> {
        Box::pin(async move { self.host.clone().ok_or_else(unavailable) })
    }

    fn check(&self) -> BoxFuture<'_, Result<Value, VersionAgentError>> {
        Box::pin(async move { Err(unavailable()) })
    }

    fn update<'a>(
        &'a self,
        _component: &'a str,
        _version: &'a str,
        _expected_current: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Value, VersionAgentError>> {
        Box::pin(async move { Err(unavailable()) })
    }
}

/// One node panel over the doubles.
pub struct Node {
    pub dir: TempDir,
    pub database: Database,
    pub runtime: Arc<TestRuntime>,
    pub node: FleetNode,
    pub clock: Arc<FakeClock>,
}

pub struct NodeOptions {
    pub guid: String,
    pub panel_version: String,
    pub config: NodeConfig,
    pub hosts: Hosts,
    pub versions: StaticVersions,
    pub now: f64,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            guid: "n".repeat(36),
            panel_version: "dev".into(),
            config: NodeConfig {
                naive_enabled: true,
                mieru_enabled: true,
                amneziawg_enabled: false,
                trusttunnel_enabled: false,
                metrics_enabled: true,
                mtproxy_host: "testserver".into(),
                naive_public_host: "naive.example.com".into(),
                amneziawg_public_host: String::new(),
                trusttunnel_public_host: String::new(),
            },
            hosts: Hosts::default(),
            versions: StaticVersions { versions: None, host: None },
            now: 1_800_000_000.0,
        }
    }
}

impl Node {
    pub fn new(options: NodeOptions) -> Self {
        let dir = TempDir::new("node");
        let database = Database::open(dir.join("panel.sqlite3")).unwrap();
        panel_core::migrations::apply_migrations(&database).unwrap();
        let clock = Arc::new(FakeClock::new(options.now));
        let runtime = TestRuntime::new(&options.hosts);
        let node = FleetNode::new(
            database.clone(),
            SecretStore::new(Some(Keyring::generate())),
            runtime.clone(),
            Arc::new(options.versions),
            options.config,
            options.guid,
            options.panel_version,
            clock.clone(),
        );
        Self { dir, database, runtime, node, clock }
    }

    pub fn default_node() -> Self {
        Self::new(NodeOptions::default())
    }
}
