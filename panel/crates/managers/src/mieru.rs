//! `panel/mieru.py`: the client of the Mieru manager (`mieru_manager`).

use serde_json::{json, Value};

use crate::error::{Manager, ManagerError};
use crate::pyvalue::py_eq;
use crate::uds::{client_wrapper, segment};

/// What the pinned mita build enforces (`MIERU_EGRESS_CAPABILITIES`).
pub const MIERU_EGRESS_CAPABILITIES: &[&str] =
    &["whole_direct", "whole_warp", "block_domain", "block_cidr", "selective_domain", "selective_cidr"];
/// `EGRESS_ACTIONS`.
pub const EGRESS_ACTIONS: &[&str] = &["DIRECT", "PROXY", "REJECT"];

/// `EGRESS_DIRECT`: the direct egress document.
pub fn egress_direct() -> Value {
    json!({"schema": 1, "proxies": [], "rules": []})
}

/// The only `/v1/metrics` answer the panel accepts (`mieru.py:78-88`).
pub fn metrics_unavailable() -> Value {
    json!({
        "status": "error",
        "stale": true,
        "users": [],
        "capability": "unavailable",
        "reason": "typed_histories_unavailable",
    })
}

/// `POST /v1/lifecycle/{action}`: the allow-listed actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleAction {
    Start,
    Stop,
    Restart,
}

/// `ValueError("invalid Mieru lifecycle action")`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidLifecycleAction;

impl std::fmt::Display for InvalidLifecycleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid Mieru lifecycle action")
    }
}

impl std::error::Error for InvalidLifecycleAction {}

impl LifecycleAction {
    pub fn parse(action: &str) -> std::result::Result<Self, InvalidLifecycleAction> {
        match action {
            "start" => Ok(Self::Start),
            "stop" => Ok(Self::Stop),
            "restart" => Ok(Self::Restart),
            _ => Err(InvalidLifecycleAction),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}

impl std::str::FromStr for LifecycleAction {
    type Err = InvalidLifecycleAction;

    fn from_str(action: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(action)
    }
}

client_wrapper!(
    /// `MieruClient` (`X-Mieru-Token`, 8 s).
    MieruClient,
    Manager::Mieru,
    8000
);

type Result<T> = std::result::Result<T, ManagerError>;

impl MieruClient {
    pub async fn health(&self) -> Result<Value> {
        self.call("GET", "/v1/health", None).await
    }

    pub async fn list_users(&self) -> Result<Value> {
        self.call("GET", "/v1/users", None).await
    }

    /// The manager has no typed histories: anything but [`metrics_unavailable`] (compared with
    /// Python's `==`) is `MieruError("Invalid Mieru metrics response")`.
    pub async fn metrics(&self) -> Result<Value> {
        let value = self.call("GET", "/v1/metrics", None).await?;
        if !py_eq(&value, &metrics_unavailable()) {
            return Err(ManagerError::plain(Manager::Mieru, "Invalid Mieru metrics response"));
        }
        Ok(value)
    }

    /// Cumulative per-user bytes (monitor). A manager older than 2.2 has no such route.
    pub async fn traffic(&self) -> Result<Value> {
        self.call("GET", "/v1/traffic", None).await
    }

    pub async fn lifecycle(&self, action: LifecycleAction) -> Result<Value> {
        self.call("POST", &format!("/v1/lifecycle/{}", action.as_str()), Some(json!({}))).await
    }

    pub async fn create(&self, payload: &Value) -> Result<Value> {
        self.call("POST", "/v1/users", Some(payload.clone())).await
    }

    pub async fn set_quotas(&self, username: &str, payload: &Value) -> Result<Value> {
        self.call("POST", &format!("/v1/users/{}/quotas", segment(username)), Some(payload.clone())).await
    }

    /// `POST /v1/users/{u}/{operation} {expected_revision}` (the operation is not quoted).
    pub async fn operation(&self, username: &str, operation: &str, revision: &str) -> Result<Value> {
        let payload = json!({"expected_revision": revision});
        self.call("POST", &format!("/v1/users/{}/{operation}", segment(username)), Some(payload)).await
    }

    /// Rotation carries the caller's credential so the panel can escrow it first.
    pub async fn rotate(
        &self,
        username: &str,
        revision: &str,
        password: Option<&str>,
        operation_id: Option<&str>,
    ) -> Result<Value> {
        let mut payload = json!({"expected_revision": revision});
        if let Some(password) = password {
            payload["password"] = json!(password);
        }
        if let Some(operation_id) = operation_id {
            payload["operation_id"] = json!(operation_id);
        }
        self.call("POST", &format!("/v1/users/{}/rotate", segment(username)), Some(payload)).await
    }

    /// `DELETE /v1/users/{u}` with the JSON body `{expected_revision}`.
    pub async fn delete(&self, username: &str, revision: &str) -> Result<Value> {
        let payload = json!({"expected_revision": revision});
        self.call("DELETE", &format!("/v1/users/{}", segment(username)), Some(payload)).await
    }

    pub async fn reset_metrics(&self, username: &str) -> Result<Value> {
        self.call("POST", &format!("/v1/users/{}/reset-metrics", segment(username)), Some(json!({}))).await
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
