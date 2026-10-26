//! `panel/naive.py`: the client of the NaiveProxy manager (`naive_manager`).

use serde_json::{json, Map, Value};

use crate::error::{Manager, ManagerError};
use crate::uds::{client_wrapper, segment_slash};

/// What the pinned forwardproxy build enforces (`NAIVE_EGRESS_CAPABILITIES`).
pub const NAIVE_EGRESS_CAPABILITIES: &[&str] = &["whole_direct", "whole_warp", "block_domain", "block_cidr"];

/// `EGRESS_DIRECT`: the direct egress document.
pub fn egress_direct() -> Value {
    json!({"schema": 1, "upstream": null, "acl": []})
}

client_wrapper!(
    /// `NaiveClient` (`X-Naive-Token`, 8 s).
    NaiveClient,
    Manager::Naive,
    8000
);

type Result<T> = std::result::Result<T, ManagerError>;

impl NaiveClient {
    pub async fn health(&self) -> Result<Value> {
        self.call("GET", "/v1/health", None).await
    }

    pub async fn list_users(&self) -> Result<Value> {
        self.call("GET", "/v1/users", None).await
    }

    pub async fn traffic(&self) -> Result<Value> {
        self.call("GET", "/v1/traffic", None).await
    }

    /// `POST /v1/users {username, quota_bytes, [password], [operation_id]}`: `quota_bytes` is
    /// always sent (`null` when unset), the optional keys only when given.
    pub async fn create(
        &self,
        username: &str,
        quota_bytes: Option<i64>,
        password: Option<&str>,
        operation_id: Option<&str>,
    ) -> Result<Value> {
        let mut payload = Map::new();
        payload.insert("username".into(), json!(username));
        payload.insert("quota_bytes".into(), json!(quota_bytes));
        payload.extend(optional(password, operation_id));
        self.call("POST", "/v1/users", Some(Value::Object(payload))).await
    }

    pub async fn reveal(&self, username: &str) -> Result<Value> {
        self.call("POST", &format!("/v1/users/{}/access", segment_slash(username)), Some(json!({}))).await
    }

    pub async fn rotate(&self, username: &str, password: Option<&str>, operation_id: Option<&str>) -> Result<Value> {
        let payload = Value::Object(optional(password, operation_id));
        self.call("POST", &format!("/v1/users/{}/rotate", segment_slash(username)), Some(payload)).await
    }

    pub async fn set_enabled(&self, username: &str, enabled: bool) -> Result<Value> {
        let action = if enabled { "enable" } else { "disable" };
        self.call("POST", &format!("/v1/users/{}/{action}", segment_slash(username)), Some(json!({}))).await
    }

    pub async fn set_quota(&self, username: &str, quota_bytes: Option<i64>) -> Result<Value> {
        let payload = json!({"quota_bytes": quota_bytes});
        self.call("POST", &format!("/v1/users/{}/quota", segment_slash(username)), Some(payload)).await
    }

    pub async fn delete(&self, username: &str) -> Result<Value> {
        self.call("DELETE", &format!("/v1/users/{}", segment_slash(username)), None).await
    }

    pub async fn reset_traffic(&self, username: &str) -> Result<Value> {
        self.call("POST", &format!("/v1/users/{}/traffic/reset", segment_slash(username)), Some(json!({}))).await
    }

    pub async fn egress(&self) -> Result<Value> {
        self.call("GET", "/v1/egress", None).await
    }

    pub async fn egress_plan(&self, expected_revision: &str, document: &Value) -> Result<Value> {
        let payload = json!({"expected_revision": expected_revision, "document": document});
        self.call("POST", "/v1/egress/plan", Some(payload)).await
    }

    pub async fn egress_apply(&self, expected_revision: &str, document: &Value, operation_id: &str) -> Result<Value> {
        let payload =
            json!({"expected_revision": expected_revision, "document": document, "operation_id": operation_id});
        self.call("POST", "/v1/egress/apply", Some(payload)).await
    }

    pub async fn egress_rollback(&self, expected_revision: &str) -> Result<Value> {
        self.call("POST", "/v1/egress/rollback", Some(json!({"expected_revision": expected_revision}))).await
    }

    pub async fn lanes(&self) -> Result<Value> {
        self.call("GET", "/v1/lanes", None).await
    }

    pub async fn set_lanes(&self, lanes: &Value) -> Result<Value> {
        self.call("PUT", "/v1/lanes", Some(json!({"lanes": lanes}))).await
    }
}

/// `_optional(password, operation_id)`: only what the caller chose; an explicit null would mean
/// something else to the manager.
fn optional(password: Option<&str>, operation_id: Option<&str>) -> Map<String, Value> {
    let mut fields = Map::new();
    if let Some(password) = password {
        fields.insert("password".into(), json!(password));
    }
    if let Some(operation_id) = operation_id {
        fields.insert("operation_id".into(), json!(operation_id));
    }
    fields
}
