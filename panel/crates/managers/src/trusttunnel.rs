//! `panel/trusttunnel.py`: the client of the TrustTunnel manager (`trusttunnel_manager`).
//!
//! The manager supervises the pinned endpoint binary and owns its `credentials.toml`; the panel
//! owns the client passwords (escrow) and sends each one to the manager.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::amneziawg::listed;
use crate::error::{Manager, ManagerError};
use crate::uds::{client_wrapper, segment};

/// `EGRESS_DIRECT`: `{mode: "direct", address: null}`.
pub fn egress_direct() -> Value {
    json!({"mode": "direct", "address": null})
}

/// `egress_revision(document)`: sha256 hex of `json.dumps({"mode","address"}, sort_keys=True,
/// separators=(",", ":"))` — what the manager answers as `revision`. `None` when a key is missing
/// (Python raises `KeyError`).
pub fn egress_revision(document: &Value) -> Option<String> {
    let canonical = json!({"mode": document.get("mode")?, "address": document.get("address")?});
    let digest = Sha256::digest(panel_core::pyjson::canonical(&canonical).as_bytes());
    Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

client_wrapper!(
    /// `TrusttunnelClient` (`X-Trusttunnel-Token`, 10 s).
    TrusttunnelClient,
    Manager::Trusttunnel,
    10000
);

type Result<T> = std::result::Result<T, ManagerError>;

impl TrusttunnelClient {
    pub async fn health(&self) -> Result<Value> {
        self.call("GET", "/v1/health", None).await
    }

    pub async fn endpoint(&self) -> Result<Value> {
        self.call("GET", "/v1/endpoint", None).await
    }

    /// `GET /v1/clients` → its `clients` (`[]` when absent).
    pub async fn clients(&self) -> Result<Value> {
        listed(Manager::Trusttunnel, self.call("GET", "/v1/clients", None).await?, "clients")
    }

    pub async fn create_client(&self, payload: &Value) -> Result<Value> {
        self.call("POST", "/v1/clients", Some(payload.clone())).await
    }

    /// `POST /v1/clients/{u}/{action} {}` (the action is not quoted).
    pub async fn client_state(&self, username: &str, action: &str) -> Result<Value> {
        self.call("POST", &format!("/v1/clients/{}/{action}", segment(username)), Some(json!({}))).await
    }

    pub async fn rotate_client(&self, username: &str, payload: &Value) -> Result<Value> {
        self.call("POST", &format!("/v1/clients/{}/rotate", segment(username)), Some(payload.clone())).await
    }

    pub async fn delete_client(&self, username: &str) -> Result<Value> {
        self.call("DELETE", &format!("/v1/clients/{}", segment(username)), None).await
    }

    /// The manager's own egress document `{mode, address, revision}`.
    pub async fn egress(&self) -> Result<Value> {
        self.call("GET", "/v1/egress", None).await
    }

    /// The document itself is the body (no envelope).
    pub async fn egress_plan(&self, document: &Value) -> Result<Value> {
        self.call("POST", "/v1/egress/plan", Some(document.clone())).await
    }

    /// The document itself is the body (no envelope).
    pub async fn egress_apply(&self, document: &Value) -> Result<Value> {
        self.call("POST", "/v1/egress/apply", Some(document.clone())).await
    }

    /// `POST /v1/egress/rollback` without a body.
    pub async fn egress_rollback(&self) -> Result<Value> {
        self.call("POST", "/v1/egress/rollback", None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_revision_is_the_canonical_digest() {
        // sha256(b'{"address":null,"mode":"direct"}') and of the socks5 form, as Python computes them.
        let direct = egress_revision(&egress_direct()).unwrap();
        let expected = Sha256::digest(br#"{"address":null,"mode":"direct"}"#);
        assert_eq!(direct, expected.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let socks = egress_revision(&json!({"address": "127.0.0.1:45103", "mode": "socks5", "x": 1})).unwrap();
        let expected = Sha256::digest(br#"{"address":"127.0.0.1:45103","mode":"socks5"}"#);
        assert_eq!(socks, expected.iter().map(|b| format!("{b:02x}")).collect::<String>());
        assert_eq!(egress_revision(&json!({"mode": "direct"})), None);
    }
}
