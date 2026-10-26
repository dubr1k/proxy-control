//! Installer-owned 3x-ui routes and runtime.
use super::AdapterContext;
use crate::error::Error;
use installer_core::model::{InstallerConfig, ThreeXuiMode};
use installer_core::planner::PlanError;
mod audit;
mod runtime;
pub use runtime::bootstrap_dialogue;

pub struct ThreeXuiAdapter {
    pub(super) context: AdapterContext,
}
impl ThreeXuiAdapter {
    pub fn new(context: &AdapterContext) -> Self {
        Self { context: context.clone() }
    }
    /// Shared ingress consumes only selected domains and audited loopback VLESS ports.
    pub fn planned_routes(&self, config: &InstallerConfig) -> Result<Vec<(String, String)>, Error> {
        let selected = &config.three_xui;
        let mut routes = Vec::new();
        match selected.mode {
            ThreeXuiMode::None => return Ok(routes),
            ThreeXuiMode::ManagedNew => {
                for (domain, port) in [
                    (&selected.vless_tcp_domain, 8449),
                    (&selected.vless_xhttp_domain, 8450),
                    (&selected.panel_domain, 8451),
                ] {
                    let domain = domain
                        .as_ref()
                        .ok_or_else(|| PlanError::new("managed 3x-ui requires every selected domain"))?;
                    routes.push((domain.to_lowercase(), format!("127.0.0.1:{port}")));
                }
                if let Some(domain) = &selected.subscription_domain {
                    routes.push((domain.clone(), "127.0.0.1:2096".into()));
                }
            }
            ThreeXuiMode::Existing => {
                let audit = self.audit_existing()?;
                if audit["installed"] != true {
                    return Err(PlanError::new("existing 3x-ui mode requires an installed 3x-ui").into());
                }
                let inbounds = audit["inbounds"].as_array().expect("auditor always returns an inbound list");
                for (domain, network) in [(&selected.vless_tcp_domain, "tcp"), (&selected.vless_xhttp_domain, "xhttp")]
                {
                    let Some(domain) = domain else { continue };
                    let inbound = inbounds
                        .iter()
                        .find(|item| item["protocol"] == "vless" && item["network"] == network)
                        .ok_or_else(|| {
                            PlanError::new(format!("no existing VLESS {network} inbound to route {domain}"))
                        })?;
                    if !["127.0.0.1", "::1", "localhost"].contains(&inbound["listen"].as_str().unwrap_or("0.0.0.0")) {
                        return Err(
                            PlanError::new("an existing 3x-ui inbound must listen on loopback to share 443").into()
                        );
                    }
                    routes.push((domain.to_lowercase(), format!("127.0.0.1:{}", inbound["port"])));
                }
                if routes.is_empty() {
                    return Err(PlanError::new("existing 3x-ui mode requires at least one routed domain").into());
                }
            }
        }
        routes.sort();
        Ok(routes)
    }
}
