//! Whole-protocol Telemt batching through the production runtime and a real HTTP client.

#[path = "../../managers/tests/common/mod.rs"]
mod http;
mod support;

use std::any::Any;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use panel_core::settings::Settings;
use panel_fleet::node::runtime::{FleetRouter, ManagerRuntime, NodeRuntime};
use panel_fleet::node::FleetNode;
use panel_model::fleet::PushRequest;
use panel_model::protocols::{BoxFuture, ProtocolAdapter};
use panel_model::validate::Model;
use panel_model::Protocol;
use panel_secrets::keyring::Keyring;
use panel_secrets::secrets_store::SecretStore;
use serde_json::{json, Map, Value};
use support::{Node, NodeOptions};

struct BatchGuard {
    inner: Option<Box<dyn Any + Send>>,
    ended: Arc<AtomicUsize>,
}

impl Drop for BatchGuard {
    fn drop(&mut self) {
        drop(self.inner.take());
        self.ended.fetch_add(1, Ordering::SeqCst);
    }
}

struct Runtime {
    inner: ManagerRuntime,
    started: AtomicUsize,
    ended: Arc<AtomicUsize>,
}

impl NodeRuntime for Runtime {
    fn adapter(&self, protocol: Protocol) -> Option<Arc<dyn ProtocolAdapter>> {
        self.inner.adapter(protocol)
    }
    fn router(&self) -> Option<Arc<dyn FleetRouter>> {
        self.inner.router()
    }
    fn batch(&self, protocol: Protocol) -> Option<Box<dyn Any + Send>> {
        self.inner.batch(protocol).map(|inner| {
            assert_eq!(protocol, Protocol::Mtproxy);
            self.started.fetch_add(1, Ordering::SeqCst);
            Box::new(BatchGuard { inner: Some(inner), ended: self.ended.clone() }) as Box<dyn Any + Send>
        })
    }
    fn healthy(&self, protocol: Protocol) -> BoxFuture<'_, bool> {
        self.inner.healthy(protocol)
    }
    fn amneziawg_versions(&self) -> BoxFuture<'_, Result<Vec<String>, panel_model::protocols::AdapterError>> {
        self.inner.amneziawg_versions()
    }
    fn telemt_users(&self) -> BoxFuture<'_, Option<Value>> {
        self.inner.telemt_users()
    }
    fn naive_traffic(&self) -> BoxFuture<'_, Option<Value>> {
        self.inner.naive_traffic()
    }
    fn trusttunnel_clients(&self) -> BoxFuture<'_, Option<Value>> {
        self.inner.trusttunnel_clients()
    }
    fn amneziawg_peers(&self) -> BoxFuture<'_, Option<Value>> {
        self.inner.amneziawg_peers()
    }
}

fn request(generation: i64, state: &str) -> PushRequest {
    let resources = (0..5)
        .map(|i| {
            json!({"ref": format!("grant:u{i}"), "protocol": "mtproxy",
        "runtime_username": format!("u{i}"), "desired_state": state,
        "credential_ref": format!("grant:u{i}:1"), "credential_origin": "caller"})
        })
        .collect::<Vec<_>>();
    let secrets = (0..5).map(|i| (format!("grant:u{i}:1"), json!(format!("{i:032x}")))).collect::<Map<_, _>>();
    PushRequest::validate(&json!({"expected_guid": "n".repeat(36), "generation": {
        "node_guid": "n".repeat(36), "master_guid": "m".repeat(36), "generation": generation,
        "previous_generation": generation - 1, "created_at": 1, "created_by": "test", "resources": resources},
        "secrets": secrets}))
    .unwrap()
}

#[tokio::test]
async fn reconcile_reads_the_telemt_inventory_once_per_pass() {
    let fixture = Node::default_node();
    let server = http::FakeServer::tcp();
    let users = Arc::new(Mutex::new(Map::<String, Value>::new()));
    let remote = users.clone();
    server.respond(move |request| {
        let parts = request.line.split_whitespace().collect::<Vec<_>>();
        let mut users = remote.lock().unwrap();
        let data = match (parts[0], parts[1]) {
            ("GET", "/v1/users") => Value::Array(users.values().cloned().collect()),
            ("POST", "/v1/users") => {
                let body = request.json();
                let name = body["username"].as_str().unwrap();
                let user = json!({"username": name, "enabled": true, "links": {
                    "tls": [format!("tg://proxy?server=edge.example&port=443&secret=ee{}", body["secret"].as_str().unwrap())]}});
                users.insert(name.into(), user.clone());
                json!({"user": user})
            }
            ("POST", path) if path.ends_with("/disable") => {
                let name = path.strip_prefix("/v1/users/").unwrap().strip_suffix("/disable").unwrap();
                users.get_mut(name).unwrap()["enabled"] = json!(false);
                json!({"user": users[name]})
            }
            other => panic!("unexpected Telemt request: {other:?}"),
        };
        http::Reply::json(200, json!({"ok": true, "data": data}))
    });
    let settings = Settings::from_lookup(|name| {
        Ok(match name {
            "TELEMT_API_URL" => Some(server.url()),
            "PANEL_DATABASE" => Some(fixture.database.path().to_string_lossy().into_owned()),
            _ => None,
        })
    })
    .unwrap();
    let runtime = Arc::new(Runtime {
        inner: ManagerRuntime::from_settings(&settings, None),
        started: AtomicUsize::new(0),
        ended: Arc::new(AtomicUsize::new(0)),
    });
    let node = FleetNode::new(
        fixture.database.clone(),
        SecretStore::new(Some(Keyring::generate())),
        runtime.clone(),
        Arc::new(NodeOptions::default().versions),
        NodeOptions::default().config,
        "n".repeat(36),
        "test",
        fixture.clock.clone(),
    );
    node.accept(request(1, "enabled")).await.unwrap();
    assert_eq!(node.reconciler().apply(1).await.unwrap().0.reconcile_state.as_str(), "converged");
    runtime.started.store(0, Ordering::SeqCst);
    runtime.ended.store(0, Ordering::SeqCst);
    server.take();
    node.accept(request(2, "disabled")).await.unwrap();
    assert_eq!(node.reconciler().apply(2).await.unwrap().0.reconcile_state.as_str(), "converged");
    assert_eq!(runtime.started.load(Ordering::SeqCst), 1, "one guard for all five resources");
    assert_eq!(runtime.ended.load(Ordering::SeqCst), 1, "the protocol pass releases its guard");
    assert!(users.lock().unwrap().values().all(|user| user["enabled"] == false));
    server.take();
    node.reconciler().apply(2).await.unwrap();
    let requests = server.take();
    assert_eq!(requests.len(), 1, "an unchanged pass shares one inventory across five credential readbacks");
    assert_eq!(requests[0].parsed().line, "GET /v1/users HTTP/1.1");
    assert_eq!(runtime.started.load(Ordering::SeqCst), 2, "a fresh pass gets a fresh inventory");
    assert_eq!(runtime.ended.load(Ordering::SeqCst), 2);
}
