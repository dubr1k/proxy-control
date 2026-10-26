//! The node's Xray-router as the routing service drives it (`protocols/xray_router.py`): one
//! adapter over the router manager's client, per service section. Not a protocol adapter (the
//! router owns no grants), but it speaks the egress vocabulary of `ProtocolAdapter` per `service`.

use panel_managers::{ManagerError, XrayRouterClient};
use panel_model::protocols::{
    applied_egress_from_view, egress_error, router_target_from_view, AdapterError, AppliedEgress, RouterTarget,
};
use serde_json::{json, Value};

use crate::api::RouterApi;
use crate::util::as_object;

/// What `geodata` does (`view`, `codes`, `settings` with a body, `update`, `restore`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeodataAction {
    View,
    Codes,
    Settings,
    Update,
    Restore,
}

impl GeodataAction {
    /// The action named by a route; any other name is Python's `ValueError("unknown geodata
    /// action …")`, here `None`.
    pub fn parse(action: &str) -> Option<Self> {
        Some(match action {
            "view" => Self::View,
            "codes" => Self::Codes,
            "settings" => Self::Settings,
            "update" => Self::Update,
            "restore" => Self::Restore,
            _ => return None,
        })
    }
}

/// The router adapter over the xray-router manager's client.
pub struct RouterAdapter<C = XrayRouterClient> {
    client: C,
}

impl<C: RouterApi> RouterAdapter<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &C {
        &self.client
    }

    fn error(error: ManagerError) -> AdapterError {
        egress_error("Xray-router", error.status_code, error.code.as_deref())
    }

    /// The service's section, or an unavailable target with the reason. Never fails: an absent
    /// router is a fact the compiler reports, not an outage of the panel.
    pub async fn target(&self, service: &str) -> RouterTarget {
        let view = match self.client.egress(service).await {
            Ok(view) => view,
            Err(error) => {
                let reason = match (service, error.status_code) {
                    // A router manager from before v1.1: rebuild `xray-router` (and start its bridge).
                    ("mtproxy", 404) => "router_lacks_mtproxy".to_string(),
                    // Before v1.6, or started without the TrustTunnel ingress port.
                    ("trusttunnel", 404) => "router_lacks_trusttunnel".to_string(),
                    // Before v3.0.0, or started without the AmneziaWG device name.
                    ("amneziawg", 404) => "router_lacks_amneziawg".to_string(),
                    _ => match error.code.filter(|code| !code.is_empty()) {
                        Some(code) => code,
                        None if error.status_code == 503 => "manual_intervention_required".to_string(),
                        None => "router_unavailable".to_string(),
                    },
                };
                return RouterTarget::unavailable(service, reason);
            }
        };
        match view.as_object() {
            Some(view) => router_target_from_view(service, view),
            // Python crashed (`AttributeError`) on such an answer; the router is then unusable.
            None => RouterTarget::unavailable(service, "router_unavailable"),
        }
    }

    /// Where a data plane off the host network reaches its ingress (`mtproxy`: the bridge's
    /// address and Telemt's login), which the panel writes into Telemt.
    pub async fn ingress(&self, service: &str) -> Result<Value, AdapterError> {
        self.client.ingress(service).await.map_err(|error| {
            if error.status_code == 404 {
                return AdapterError::with_code(
                    "the Xray-router has no MTProxy ingress: rebuild xray-router",
                    "router_lacks_mtproxy",
                );
            }
            Self::error(error)
        })
    }

    pub async fn status(&self) -> Option<Value> {
        self.client.status().await.ok()
    }

    pub async fn plan(&self, service: &str, document: &Value, expected_revision: &str) -> Result<Value, AdapterError> {
        self.client.egress_plan(service, expected_revision, document).await.map_err(Self::error)
    }

    pub async fn apply(
        &self,
        service: &str,
        document: &Value,
        expected_revision: &str,
        operation_id: &str,
    ) -> Result<AppliedEgress, AdapterError> {
        let view =
            self.client.egress_apply(service, expected_revision, document, operation_id).await.map_err(Self::error)?;
        Ok(applied_egress_from_view(as_object(&view)?))
    }

    pub async fn rollback(&self, service: &str, expected_revision: &str) -> Result<AppliedEgress, AdapterError> {
        let view = self.client.egress_rollback(service, expected_revision).await.map_err(Self::error)?;
        Ok(applied_egress_from_view(as_object(&view)?))
    }

    // -- v0.7: lanes and the relay --

    pub async fn lanes(&self, service: &str) -> Result<Value, AdapterError> {
        self.client.lanes(service).await.map_err(Self::error)
    }

    pub async fn lane_issue(&self, service: &str, lane: &str) -> Result<Value, AdapterError> {
        self.client.lane_issue(service, lane).await.map_err(Self::error)
    }

    pub async fn lane_forget(&self, service: &str, lane: &str) -> Result<Value, AdapterError> {
        self.client.lane_forget(service, lane).await.map_err(Self::error)
    }

    pub async fn relay(&self) -> Option<Value> {
        self.client.relay().await.ok()
    }

    pub async fn relay_enable(&self, server_name: &str, port: i64) -> Result<Value, AdapterError> {
        self.client.relay_enable(server_name, port).await.map_err(Self::error)
    }

    pub async fn relay_disable(&self) -> Result<Value, AdapterError> {
        self.client.relay_disable().await.map_err(Self::error)
    }

    pub async fn relay_set_accounts(&self, accounts: &Value) -> Result<Value, AdapterError> {
        self.client.relay_set_accounts(accounts).await.map_err(Self::error)
    }

    // -- v0.8: exits and geodata --

    pub async fn exit_test(&self, spec: &Value) -> Result<Value, AdapterError> {
        self.client.exit_test(spec).await.map_err(Self::error)
    }

    /// One geodata action; `settings` sends `body` (`{}` when absent). The manager's `geodata_*`
    /// codes are the operator's answer as they are: `egress_error` would fold them.
    pub async fn geodata(&self, action: GeodataAction, body: Option<&Value>) -> Result<Value, AdapterError> {
        let empty = json!({});
        let body = body.filter(|body| crate::util::truthy(Some(body))).unwrap_or(&empty);
        let result = match action {
            GeodataAction::View => self.client.geodata().await,
            GeodataAction::Codes => self.client.geodata_codes().await,
            GeodataAction::Settings => self.client.geodata_settings(body).await,
            GeodataAction::Update => self.client.geodata_update().await,
            GeodataAction::Restore => self.client.geodata_restore().await,
        };
        result.map_err(|error| match error.code.as_deref() {
            Some(code) if code.starts_with("geodata_") => {
                AdapterError::with_code(format!("Xray-router: {}", error.message), code)
            }
            _ => Self::error(error),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ManagerResult;
    use panel_managers::Manager;

    /// A router manager that refuses everything with one status and code.
    struct Refusing(u16, Option<&'static str>);

    impl Refusing {
        fn refuse(&self) -> ManagerResult {
            Err(ManagerError::new(Manager::XrayRouter, "Xray-router manager rejected request", self.0, self.1))
        }
    }

    impl RouterApi for Refusing {
        async fn status(&self) -> ManagerResult {
            self.refuse()
        }
        async fn egress(&self, _: &str) -> ManagerResult {
            self.refuse()
        }
        async fn egress_plan(&self, _: &str, _: &str, _: &Value) -> ManagerResult {
            self.refuse()
        }
        async fn egress_apply(&self, _: &str, _: &str, _: &Value, _: &str) -> ManagerResult {
            self.refuse()
        }
        async fn egress_rollback(&self, _: &str, _: &str) -> ManagerResult {
            self.refuse()
        }
        async fn lanes(&self, _: &str) -> ManagerResult {
            self.refuse()
        }
        async fn lane_issue(&self, _: &str, _: &str) -> ManagerResult {
            self.refuse()
        }
        async fn lane_forget(&self, _: &str, _: &str) -> ManagerResult {
            self.refuse()
        }
        async fn relay(&self) -> ManagerResult {
            self.refuse()
        }
        async fn ingress(&self, _: &str) -> ManagerResult {
            self.refuse()
        }
        async fn relay_enable(&self, _: &str, _: i64) -> ManagerResult {
            self.refuse()
        }
        async fn relay_disable(&self) -> ManagerResult {
            self.refuse()
        }
        async fn relay_set_accounts(&self, _: &Value) -> ManagerResult {
            self.refuse()
        }
        async fn exit_test(&self, _: &Value) -> ManagerResult {
            self.refuse()
        }
        async fn geodata(&self) -> ManagerResult {
            self.refuse()
        }
        async fn geodata_codes(&self) -> ManagerResult {
            self.refuse()
        }
        async fn geodata_settings(&self, _: &Value) -> ManagerResult {
            self.refuse()
        }
        async fn geodata_update(&self) -> ManagerResult {
            self.refuse()
        }
        async fn geodata_restore(&self) -> ManagerResult {
            self.refuse()
        }
    }

    #[tokio::test]
    async fn targets_name_why_the_router_cannot_serve() {
        let reason = |status, code, service| async move {
            RouterAdapter::new(Refusing(status, code)).target(service).await.reason.unwrap()
        };
        assert_eq!(reason(404, None, "mtproxy").await, "router_lacks_mtproxy");
        assert_eq!(reason(404, None, "trusttunnel").await, "router_lacks_trusttunnel");
        assert_eq!(reason(404, None, "amneziawg").await, "router_lacks_amneziawg");
        assert_eq!(reason(404, None, "naive").await, "router_unavailable");
        assert_eq!(reason(503, None, "naive").await, "manual_intervention_required");
        assert_eq!(reason(502, None, "naive").await, "router_unavailable");
        assert_eq!(reason(409, Some("artifact_mismatch"), "mieru").await, "artifact_mismatch");
    }

    #[tokio::test]
    async fn refusals_carry_the_bounded_codes_and_geodata_its_own() {
        let missing = RouterAdapter::new(Refusing(404, None));
        let error = missing.ingress("mtproxy").await.unwrap_err();
        assert_eq!(
            (error.message.as_str(), error.code.as_deref()),
            ("the Xray-router has no MTProxy ingress: rebuild xray-router", Some("router_lacks_mtproxy"))
        );
        assert_eq!(missing.status().await, None);
        assert_eq!(missing.relay().await, None);
        let conflict = RouterAdapter::new(Refusing(409, Some("lane_unknown")));
        assert_eq!(conflict.lane_forget("naive", "x").await.unwrap_err().code.as_deref(), Some("lane_unknown"));
        let manual = RouterAdapter::new(Refusing(503, Some("manual_intervention_required")));
        assert!(manual.relay_disable().await.unwrap_err().is_manual_intervention());
        let geodata = RouterAdapter::new(Refusing(422, Some("geodata_source_invalid")));
        let error = geodata.geodata(GeodataAction::Settings, None).await.unwrap_err();
        assert_eq!(
            (error.message.as_str(), error.code.as_deref()),
            ("Xray-router: Xray-router manager rejected request", Some("geodata_source_invalid"))
        );
        let invalid = RouterAdapter::new(Refusing(422, None));
        assert_eq!(
            invalid.geodata(GeodataAction::Update, None).await.unwrap_err().code.as_deref(),
            Some("egress_invalid")
        );
        assert_eq!(GeodataAction::parse("restore"), Some(GeodataAction::Restore));
        assert_eq!(GeodataAction::parse("drop"), None);
    }
}
