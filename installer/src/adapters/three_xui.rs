//! Installer-owned 3x-ui routes and runtime.
use std::fs;
use std::io::Read;

use installer_core::model::{InstallerConfig, ThreeXuiMode};
use installer_core::planner::PlanError;
use serde_json::Value;

use super::AdapterContext;
use crate::error::Error;


pub struct ThreeXuiAdapter {
    context: AdapterContext,
}

impl ThreeXuiAdapter {
    pub fn new(context: &AdapterContext) -> Self {
        Self { context: context.clone() }
    }

    /// The shared ingress consumes only selected domains and audited loopback ports.
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
                let path = pc_host::fs::root_path(&self.context.root, "/usr/local/x-ui/bin/config.json")?;
                let metadata = match fs::symlink_metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Err(PlanError::new("existing 3x-ui mode requires an installed 3x-ui").into())
                    }
                    Err(error) => return Err(error.into()),
                };
                if !metadata.is_file() {
                    return Err(Error::other("ThreeXuiError", "3x-ui configuration must be a regular file"));
                }
                let mut options = fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
                }
                let file = options.open(path)?;
                let mut bytes = Vec::new();
                file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
                if bytes.len() > 4 * 1024 * 1024 {
                    return Err(Error::other("ThreeXuiError", "3x-ui configuration exceeds the audit bound"));
                }
                let document: Value = serde_json::from_slice(&bytes)
                    .map_err(|_| Error::other("ThreeXuiError", "3x-ui configuration is not readable JSON"))?;
                if !document.is_object() {
                    return Err(Error::other("ThreeXuiError", "3x-ui configuration is not an object"));
                }
                let mut inbounds = document.get("inbounds").and_then(Value::as_array).cloned().unwrap_or_default();
                if inbounds.len() > 256 {
                    return Err(Error::other("ThreeXuiError", "3x-ui declares more inbounds than the audit bound"));
                }
                inbounds.sort_by_key(|item| {
                    (
                        item.get("port").and_then(Value::as_u64).unwrap_or(0),
                        item.get("tag").and_then(Value::as_str).unwrap_or("").to_owned(),
                    )
                });
                for (domain, network) in [(&selected.vless_tcp_domain, "tcp"), (&selected.vless_xhttp_domain, "xhttp")]
                {
                    let Some(domain) = domain else { continue };
                    let inbound = inbounds
                        .iter()
                        .find(|item| {
                            let port = item.get("port").and_then(Value::as_u64).unwrap_or(0);
                            let raw = item.pointer("/streamSettings/network").and_then(Value::as_str).unwrap_or("tcp");
                            let effective = if ["tcp", "ws", "grpc", "http", "xhttp", "httpupgrade", "kcp", "quic"]
                                .contains(&raw)
                            {
                                raw
                            } else {
                                "tcp"
                            };
                            item.get("protocol").and_then(Value::as_str) == Some("vless")
                                && (1..=65535).contains(&port)
                                && effective == network
                        })
                        .ok_or_else(|| {
                            PlanError::new(format!("no existing VLESS {network} inbound to route {domain}"))
                        })?;
                    if !["127.0.0.1", "::1", "localhost"]
                        .contains(&inbound.get("listen").and_then(Value::as_str).unwrap_or("0.0.0.0"))
                    {
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
