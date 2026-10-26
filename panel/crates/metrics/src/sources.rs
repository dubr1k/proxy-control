//! What the collector reads: the host agent's meter sample and the five protocol managers'
//! per-user counters, behind one trait so tests can replay recorded answers.
//!
//! The panel wires [`ManagerMeters`] (feature `managers`) over the WP5 clients; a manager the
//! panel does not run is simply `None` there (its protocol is then never asked, or answers an
//! error and turns `manager_unavailable`, as in Python).

use panel_model::protocols::BoxFuture;
use serde_json::Value;

/// The protocols in the order of the collector's cadence table.
pub const POLLED: [&str; 5] = ["trusttunnel", "amneziawg", "mieru", "mtproxy", "naive"];

/// The collector's inputs.
pub trait MeterSources: Send + Sync + 'static {
    /// `VersionClient.metrics()`: the agent's `/v1/metrics` sample, `None` when it cannot be had
    /// (never an error).
    fn agent_metrics(&self) -> BoxFuture<'_, Option<Value>>;

    /// One manager poll: `trusttunnel` → `TrusttunnelClient.clients()` (the list), `amneziawg` →
    /// `peers()`, `mtproxy` → Telemt `list_users()`, `mieru`/`naive` → `traffic()` (the body).
    /// An error makes that protocol unavailable until the next good poll.
    fn poll(&self, protocol: &'static str) -> BoxFuture<'_, Result<Value, String>>;

    /// The local node's display name (`nodes.local().display_name`); `None` or empty → `local`.
    fn local_node_name(&self) -> BoxFuture<'_, Option<String>> {
        Box::pin(async { None })
    }
}

#[cfg(feature = "managers")]
mod managers {
    use std::sync::Arc;

    use panel_managers::{AmneziawgClient, MieruClient, NaiveClient, TelemtClient, TrusttunnelClient, VersionClient};
    use panel_model::protocols::BoxFuture;
    use serde_json::Value;

    use super::MeterSources;

    /// The local node's display name, read from the node store (WP11); synchronous, run on the
    /// blocking pool.
    pub type LocalName = Arc<dyn Fn() -> Option<String> + Send + Sync>;

    /// [`MeterSources`] over the panel's manager clients.
    #[derive(Clone, Default)]
    pub struct ManagerMeters {
        pub versions: Option<Arc<VersionClient>>,
        pub trusttunnel: Option<Arc<TrusttunnelClient>>,
        pub amneziawg: Option<Arc<AmneziawgClient>>,
        pub telemt: Option<Arc<TelemtClient>>,
        pub mieru: Option<Arc<MieruClient>>,
        pub naive: Option<Arc<NaiveClient>>,
        pub local_name: Option<LocalName>,
    }

    fn missing() -> Result<Value, String> {
        Err("manager not configured".to_string())
    }

    impl MeterSources for ManagerMeters {
        fn agent_metrics(&self) -> BoxFuture<'_, Option<Value>> {
            Box::pin(async move {
                match &self.versions {
                    Some(client) => client.metrics().await,
                    None => None,
                }
            })
        }

        fn poll(&self, protocol: &'static str) -> BoxFuture<'_, Result<Value, String>> {
            Box::pin(async move {
                match protocol {
                    "trusttunnel" => match &self.trusttunnel {
                        Some(client) => client.clients().await.map_err(|e| e.to_string()),
                        None => missing(),
                    },
                    "amneziawg" => match &self.amneziawg {
                        Some(client) => client.peers().await.map_err(|e| e.to_string()),
                        None => missing(),
                    },
                    "mtproxy" => match &self.telemt {
                        Some(client) => client.list_users().await.map_err(|e| e.to_string()),
                        None => missing(),
                    },
                    "mieru" => match &self.mieru {
                        Some(client) => client.traffic().await.map_err(|e| e.to_string()),
                        None => missing(),
                    },
                    "naive" => match &self.naive {
                        Some(client) => client.traffic().await.map_err(|e| e.to_string()),
                        None => missing(),
                    },
                    _ => missing(),
                }
            })
        }

        fn local_node_name(&self) -> BoxFuture<'_, Option<String>> {
            let read = self.local_name.clone();
            Box::pin(async move {
                let read = read?;
                tokio::task::spawn_blocking(move || read()).await.ok().flatten()
            })
        }
    }
}

#[cfg(feature = "managers")]
pub use managers::{LocalName, ManagerMeters};
