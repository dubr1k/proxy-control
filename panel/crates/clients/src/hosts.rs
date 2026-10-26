//! `public_hosts_for` (`fleet_v2/central_routes.py`): the public host per protocol for the node a
//! grant lives on — a linked panel's from the identity it last reported, the local node's from
//! this panel's settings.

use std::collections::HashMap;

use panel_core::db::Conn;
use panel_core::rusqlite::{params, OptionalExtension as _};
use panel_core::settings::Settings;
use panel_model::clients::PROTOCOLS;
use serde_json::Value;

use crate::{ClientsError, LOCAL_NODE_ID};

/// The public host per protocol of a node, read inside the caller's connection.
pub trait PublicHosts: Send + Sync {
    fn hosts(&self, db: &Conn, node_id: &str) -> Result<HashMap<String, String>, ClientsError>;
}

impl<F> PublicHosts for F
where
    F: Fn(&Conn, &str) -> Result<HashMap<String, String>, ClientsError> + Send + Sync,
{
    fn hosts(&self, db: &Conn, node_id: &str) -> Result<HashMap<String, String>, ClientsError> {
        self(db, node_id)
    }
}

/// One table for every node (`public_hosts` given as a dict in Python).
#[derive(Debug, Clone, Default)]
pub struct FixedHosts(pub HashMap<String, String>);

impl PublicHosts for FixedHosts {
    fn hosts(&self, _db: &Conn, _node_id: &str) -> Result<HashMap<String, String>, ClientsError> {
        Ok(self.0.clone())
    }
}

/// `public_hosts_for(app.state, node_id)` over the settings and `node_links`.
#[derive(Debug, Clone)]
pub struct SettingsHosts {
    local: HashMap<String, String>,
}

impl SettingsHosts {
    pub fn new(settings: &Settings) -> Self {
        let or_naive = |host: &str| if host.is_empty() { settings.naive_public_host.clone() } else { host.to_string() };
        let local = HashMap::from([
            ("naive".to_string(), settings.naive_public_host.clone()),
            ("mtproxy".to_string(), settings.mtproxy_host().to_string()),
            ("mieru".to_string(), settings.naive_public_host.clone()),
            ("amneziawg".to_string(), or_naive(&settings.amneziawg_public_host)),
            ("trusttunnel".to_string(), or_naive(&settings.trusttunnel_public_host)),
        ]);
        Self { local }
    }
}

impl PublicHosts for SettingsHosts {
    fn hosts(&self, db: &Conn, node_id: &str) -> Result<HashMap<String, String>, ClientsError> {
        if node_id != LOCAL_NODE_ID {
            let identity: Option<String> = db
                .query_row("SELECT identity_json FROM node_links WHERE node_id=?", params![node_id], |row| row.get(0))
                .optional()?;
            if let Some(identity) = identity {
                let identity: Value = serde_json::from_str(&identity)
                    .map_err(|error| ClientsError::Internal(format!("node_links.identity_json: {error}")))?;
                let protocols = identity.get("protocols").filter(|value| crate::truthy(value));
                return Ok(PROTOCOLS
                    .iter()
                    .map(|protocol| {
                        let host = protocols
                            .and_then(|protocols| protocols.get(protocol))
                            .and_then(|entry| entry.get("public_host"))
                            .filter(|host| crate::truthy(host));
                        let text = match host {
                            None => String::new(),
                            Some(Value::String(text)) => text.clone(),
                            Some(other) => panel_model::pyrepr::str(other),
                        };
                        (protocol.to_string(), text)
                    })
                    .collect());
            }
        }
        Ok(self.local.clone())
    }
}
