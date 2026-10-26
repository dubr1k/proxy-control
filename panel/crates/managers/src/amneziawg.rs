//! `panel/amneziawg.py`: the client of the AmneziaWG manager (`awg_manager`).
//!
//! The manager owns the interfaces, the ports and the server keys; the panel owns the client keys.
//! A peer therefore reaches the manager as a public key only.

use std::time::Duration;

use serde_json::{json, Value};

use crate::error::{Manager, ManagerError};
use crate::uds::{client_wrapper, segment};

/// An apply through WARP may register a WARP device and waits for the tunnel's first handshake
/// (up to 12 s on the manager), hence the longer timeout of apply and rollback.
pub const EGRESS_TIMEOUT: Duration = Duration::from_secs(45);

client_wrapper!(
    /// `AmneziawgClient` (`X-Awg-Token`, 10 s; 45 s for egress apply/rollback).
    AmneziawgClient,
    Manager::Amneziawg,
    10000
);

type Result<T> = std::result::Result<T, ManagerError>;

/// `(answer).get(key, [])`. Python fails with `AttributeError` (a 500) when the answer is not an
/// object; here that is the client's "Invalid … response" (see DIFFERENCES.md).
pub(crate) fn listed(manager: Manager, answer: Value, key: &str) -> Result<Value> {
    match answer {
        Value::Object(mut map) => Ok(map.remove(key).unwrap_or_else(|| json!([]))),
        _ => Err(ManagerError::plain(manager, manager.invalid())),
    }
}

impl AmneziawgClient {
    pub async fn health(&self) -> Result<Value> {
        self.call("GET", "/v1/health", None).await
    }

    /// `GET /v1/instances` → its `instances` (`[]` when absent).
    pub async fn instances(&self) -> Result<Value> {
        listed(Manager::Amneziawg, self.call("GET", "/v1/instances", None).await?, "instances")
    }

    /// `GET /v1/peers` → its `peers` (`[]` when absent).
    pub async fn peers(&self) -> Result<Value> {
        listed(Manager::Amneziawg, self.call("GET", "/v1/peers", None).await?, "peers")
    }

    pub async fn create_peer(&self, payload: &Value) -> Result<Value> {
        self.call("POST", "/v1/peers", Some(payload.clone())).await
    }

    /// `POST /v1/peers/{u}/{action} {}` (the action is not quoted).
    pub async fn peer_state(&self, username: &str, action: &str) -> Result<Value> {
        self.call("POST", &format!("/v1/peers/{}/{action}", segment(username)), Some(json!({}))).await
    }

    pub async fn rotate_peer(&self, username: &str, payload: &Value) -> Result<Value> {
        self.call("POST", &format!("/v1/peers/{}/rotate", segment(username)), Some(payload.clone())).await
    }

    pub async fn delete_peer(&self, username: &str) -> Result<Value> {
        self.call("DELETE", &format!("/v1/peers/{}", segment(username)), None).await
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
        self.raw().request("POST", "/v1/egress/apply", Some(&payload), Some(EGRESS_TIMEOUT)).await
    }

    pub async fn egress_rollback(&self, expected_revision: &str) -> Result<Value> {
        let payload = json!({"expected_revision": expected_revision});
        self.raw().request("POST", "/v1/egress/rollback", Some(&payload), Some(EGRESS_TIMEOUT)).await
    }
}
