//! `panel/xray_router.py` (without the in-memory twin): the client of the node's Xray-router
//! manager (`xray_router_manager`). It speaks the egress vocabulary per service, lanes, the relay,
//! geodata and exit tests. Unlike the other managers' clients it never answers `None`: a 204 is
//! parsed like any body and fails as an invalid response (`xray_router.py:64-67`).

use serde_json::{json, Value};

use crate::error::{Manager, ManagerError};
use crate::uds::client_wrapper;

/// The sources the router manager knows (`SOURCE_KINDS` of `xray_router_manager/src/geodata.rs`).
pub const GEODATA_SOURCE_KINDS: &[&str] = &["xray", "loyalsoldier", "runetfreedom", "iran", "v2fly", "custom"];
/// `ROUTER_SERVICES`.
pub const ROUTER_SERVICES: &[&str] = &["naive", "mieru", "mtproxy", "trusttunnel", "amneziawg"];
/// What the router enforces (`ROUTER_CAPABILITIES`).
pub const ROUTER_CAPABILITIES: &[&str] = &[
    "whole_direct",
    "whole_warp",
    "block_domain",
    "block_cidr",
    "block_port",
    "block_geosite",
    "block_geoip",
    "selective_domain",
    "selective_cidr",
    "selective_port",
    "selective_geosite",
    "selective_geoip",
    "geodata",
    "custom_exits",
    "block_protocol",
    "selective_protocol",
];

client_wrapper!(
    /// `XrayRouterClient` (`X-Xray-Router-Token`, 8 s; 503 passes through as well).
    XrayRouterClient,
    Manager::XrayRouter,
    8000
);

type Result<T> = std::result::Result<T, ManagerError>;

impl XrayRouterClient {
    pub async fn status(&self) -> Result<Value> {
        self.call("GET", "/v1/status", None).await
    }

    pub async fn egress(&self, service: &str) -> Result<Value> {
        self.call("GET", &format!("/v1/egress/{service}"), None).await
    }

    pub async fn egress_plan(&self, service: &str, expected_revision: &str, document: &Value) -> Result<Value> {
        let payload = json!({"expected_revision": expected_revision, "document": document});
        self.call("POST", &format!("/v1/egress/{service}/plan"), Some(payload)).await
    }

    pub async fn egress_apply(
        &self,
        service: &str,
        expected_revision: &str,
        document: &Value,
        operation_id: &str,
    ) -> Result<Value> {
        let payload =
            json!({"expected_revision": expected_revision, "document": document, "operation_id": operation_id});
        self.call("POST", &format!("/v1/egress/{service}/apply"), Some(payload)).await
    }

    pub async fn egress_rollback(&self, service: &str, expected_revision: &str) -> Result<Value> {
        let payload = json!({"expected_revision": expected_revision});
        self.call("POST", &format!("/v1/egress/{service}/rollback"), Some(payload)).await
    }

    pub async fn lanes(&self, service: &str) -> Result<Value> {
        self.call("GET", &format!("/v1/lanes/{service}"), None).await
    }

    pub async fn lane_issue(&self, service: &str, lane: &str) -> Result<Value> {
        self.call("POST", &format!("/v1/lanes/{service}"), Some(json!({"lane": lane}))).await
    }

    pub async fn lane_forget(&self, service: &str, lane: &str) -> Result<Value> {
        self.call("DELETE", &format!("/v1/lanes/{service}/{lane}"), None).await
    }

    pub async fn relay(&self) -> Result<Value> {
        self.call("GET", "/v1/relay", None).await
    }

    /// The MTProxy ingress as Telemt must dial it.
    pub async fn ingress(&self, service: &str) -> Result<Value> {
        self.call("GET", &format!("/v1/ingress/{service}"), None).await
    }

    pub async fn relay_enable(&self, server_name: &str, port: i64) -> Result<Value> {
        self.call("POST", "/v1/relay", Some(json!({"server_name": server_name, "port": port}))).await
    }

    pub async fn relay_disable(&self) -> Result<Value> {
        self.call("DELETE", "/v1/relay", None).await
    }

    pub async fn geodata(&self) -> Result<Value> {
        self.call("GET", "/v1/geodata", None).await
    }

    pub async fn geodata_codes(&self) -> Result<Value> {
        self.call("GET", "/v1/geodata/codes", None).await
    }

    pub async fn geodata_settings(&self, body: &Value) -> Result<Value> {
        self.call("PUT", "/v1/geodata/settings", Some(body.clone())).await
    }

    pub async fn geodata_update(&self) -> Result<Value> {
        self.call("POST", "/v1/geodata/update", None).await
    }

    pub async fn geodata_restore(&self) -> Result<Value> {
        self.call("POST", "/v1/geodata/restore", None).await
    }

    pub async fn exit_test(&self, spec: &Value) -> Result<Value> {
        self.call("POST", "/v1/exits/test", Some(json!({"exit": spec}))).await
    }

    pub async fn relay_set_accounts(&self, accounts: &Value) -> Result<Value> {
        self.call("PUT", "/v1/relay/accounts", Some(json!({"accounts": accounts}))).await
    }
}
