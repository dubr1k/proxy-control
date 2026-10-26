//! What the node side needs from the runtime: the protocol adapters (`app.state.adapters`), the
//! node's Xray-router (`app.state.router`), the managers' health and traffic, and the
//! version-agent — as traits, so the reconcile and the routes run against the real managers in the
//! panel and against in-memory doubles in tests.
//!
//! [`ManagerRuntime`] is the production implementation over the `panel_protocols` adapters and the
//! `panel_managers` clients, built the way `create_app` builds them (`app.py:150-171`).

use std::any::Any;
use std::sync::Arc;

use panel_core::settings::Settings;
use panel_managers::{
    AmneziawgClient, MieruClient, NaiveClient, TelemtClient, TrusttunnelClient, VersionAgentError, VersionClient,
    XrayRouterClient,
};
use panel_model::protocols::{AdapterError, AppliedEgress, BoxFuture, ProtocolAdapter, RouterTarget};
use panel_model::Protocol;
use panel_protocols::api::RouterApi;
use panel_protocols::telemt::BridgeProbe;
pub use panel_protocols::xray_router::GeodataAction;
use panel_protocols::{AmneziawgAdapter, MieruAdapter, NaiveAdapter, RouterAdapter, TelemtAdapter, TrusttunnelAdapter};
use serde_json::Value;

/// The node's Xray-router as fleet v2 drives it (`protocols/xray_router.py`'s `RouterAdapter`).
pub trait FleetRouter: Send + Sync {
    /// The service's section, or an unavailable target with its reason (never fails).
    fn target<'a>(&'a self, service: &'a str) -> BoxFuture<'a, RouterTarget>;
    fn apply<'a>(
        &'a self,
        service: &'a str,
        document: &'a Value,
        expected_revision: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>>;
    fn lanes<'a>(&'a self, service: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>>;
    fn lane_issue<'a>(&'a self, service: &'a str, lane: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>>;
    fn lane_forget<'a>(&'a self, service: &'a str, lane: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>>;
    /// The relay inbound's view, `None` when the router does not answer.
    fn relay(&self) -> BoxFuture<'_, Option<Value>>;
    fn relay_enable<'a>(&'a self, server_name: &'a str, port: i64) -> BoxFuture<'a, Result<Value, AdapterError>>;
    fn relay_disable(&self) -> BoxFuture<'_, Result<Value, AdapterError>>;
    fn relay_set_accounts<'a>(&'a self, accounts: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>>;
    fn exit_test<'a>(&'a self, spec: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>>;
    fn geodata<'a>(
        &'a self,
        action: GeodataAction,
        body: Option<&'a Value>,
    ) -> BoxFuture<'a, Result<Value, AdapterError>>;
}

impl<C: RouterApi + 'static> FleetRouter for RouterAdapter<C> {
    fn target<'a>(&'a self, service: &'a str) -> BoxFuture<'a, RouterTarget> {
        Box::pin(RouterAdapter::target(self, service))
    }

    fn apply<'a>(
        &'a self,
        service: &'a str,
        document: &'a Value,
        expected_revision: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>> {
        Box::pin(RouterAdapter::apply(self, service, document, expected_revision, operation_id))
    }

    fn lanes<'a>(&'a self, service: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(RouterAdapter::lanes(self, service))
    }

    fn lane_issue<'a>(&'a self, service: &'a str, lane: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(RouterAdapter::lane_issue(self, service, lane))
    }

    fn lane_forget<'a>(&'a self, service: &'a str, lane: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(RouterAdapter::lane_forget(self, service, lane))
    }

    fn relay(&self) -> BoxFuture<'_, Option<Value>> {
        Box::pin(RouterAdapter::relay(self))
    }

    fn relay_enable<'a>(&'a self, server_name: &'a str, port: i64) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(RouterAdapter::relay_enable(self, server_name, port))
    }

    fn relay_disable(&self) -> BoxFuture<'_, Result<Value, AdapterError>> {
        Box::pin(RouterAdapter::relay_disable(self))
    }

    fn relay_set_accounts<'a>(&'a self, accounts: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(RouterAdapter::relay_set_accounts(self, accounts))
    }

    fn exit_test<'a>(&'a self, spec: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(RouterAdapter::exit_test(self, spec))
    }

    fn geodata<'a>(
        &'a self,
        action: GeodataAction,
        body: Option<&'a Value>,
    ) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(RouterAdapter::geodata(self, action, body))
    }
}

/// The adapters, the router and the managers' own calls the node side uses.
///
/// The `Option<Value>` calls answer `None` exactly where Python caught the client's own error
/// class (`TelemtError`, `NaiveError`, …) and carried on.
pub trait NodeRuntime: Send + Sync {
    /// `app.state.adapters.get(protocol)`.
    fn adapter(&self, protocol: Protocol) -> Option<Arc<dyn ProtocolAdapter>>;

    /// `app.state.router`: `None` on a node without an Xray-router.
    fn router(&self) -> Option<Arc<dyn FleetRouter>>;

    /// `async with adapter.batch()` for an adapter that can batch its inventory reads (Telemt):
    /// the guard is held for one protocol's pass and dropped after it.
    fn batch(&self, _protocol: Protocol) -> Option<Box<dyn Any + Send>> {
        None
    }

    /// `hasattr(adapter, "set_lanes")`.
    fn has_lanes(&self, _protocol: Protocol) -> bool {
        false
    }

    /// `adapter.set_lanes(lanes)` (asked only when [`NodeRuntime::has_lanes`]).
    fn set_lanes<'a>(&'a self, protocol: Protocol, _lanes: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(async move { Err(AdapterError::new(format!("{protocol} runs no lanes on this node"))) })
    }

    /// `await client.health()` of the protocol's manager: `false` when it raised its error.
    fn healthy(&self, protocol: Protocol) -> BoxFuture<'_, bool>;

    /// `adapters["amneziawg"].versions()`.
    fn amneziawg_versions(&self) -> BoxFuture<'_, Result<Vec<String>, AdapterError>>;

    /// `app.state.telemt.list_users()`.
    fn telemt_users(&self) -> BoxFuture<'_, Option<Value>>;

    /// `app.state.naive.traffic()`.
    fn naive_traffic(&self) -> BoxFuture<'_, Option<Value>>;

    /// `app.state.trusttunnel.clients()`.
    fn trusttunnel_clients(&self) -> BoxFuture<'_, Option<Value>>;

    /// `app.state.amneziawg.peers()`.
    fn amneziawg_peers(&self) -> BoxFuture<'_, Option<Value>>;
}

/// The host's version-agent (`app.state.versions`).
pub trait VersionAgent: Send + Sync {
    fn list_versions(&self) -> BoxFuture<'_, Result<Value, VersionAgentError>>;
    fn host(&self) -> BoxFuture<'_, Result<Value, VersionAgentError>>;
    fn check(&self) -> BoxFuture<'_, Result<Value, VersionAgentError>>;
    fn update<'a>(
        &'a self,
        component: &'a str,
        version: &'a str,
        expected_current: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Value, VersionAgentError>>;
}

impl VersionAgent for VersionClient {
    fn list_versions(&self) -> BoxFuture<'_, Result<Value, VersionAgentError>> {
        Box::pin(VersionClient::list_versions(self))
    }

    fn host(&self) -> BoxFuture<'_, Result<Value, VersionAgentError>> {
        Box::pin(VersionClient::host(self))
    }

    fn check(&self) -> BoxFuture<'_, Result<Value, VersionAgentError>> {
        Box::pin(VersionClient::check(self))
    }

    fn update<'a>(
        &'a self,
        component: &'a str,
        version: &'a str,
        expected_current: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Value, VersionAgentError>> {
        Box::pin(VersionClient::update(self, component, version, expected_current))
    }
}

/// The production runtime: one adapter per protocol over the real manager clients, and the
/// Xray-router when its overlay is part of the stack (`XRAY_ROUTER_ENABLED`). Other packages that
/// need the adapters (clients, routing) should take them from here so the panel keeps one adapter
/// set (and one Telemt egress journal), as `app.state.adapters` is one dict in Python.
pub struct ManagerRuntime {
    pub telemt: Arc<TelemtAdapter>,
    pub naive: Arc<NaiveAdapter>,
    pub mieru: Arc<MieruAdapter>,
    pub amneziawg: Arc<AmneziawgAdapter>,
    pub trusttunnel: Arc<TrusttunnelAdapter>,
    pub router: Option<Arc<RouterAdapter>>,
}

impl std::fmt::Debug for ManagerRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagerRuntime").field("router", &self.router.is_some()).finish_non_exhaustive()
    }
}

impl ManagerRuntime {
    /// `create_app`'s adapters: Telemt with its egress journal next to the database and the
    /// `MTPROXY_DOMAIN` fallback host, Naive with its public host, AmneziaWG and TrustTunnel with
    /// theirs (else NaiveProxy's), the router handed to Telemt and TrustTunnel. `bridge_probe`
    /// replaces the real MTProxy ingress probe (test hooks).
    pub fn from_settings(settings: &Settings, bridge_probe: Option<BridgeProbe>) -> Self {
        let router = settings.xray_router_enabled.then(|| {
            Arc::new(RouterAdapter::new(XrayRouterClient::new(
                &settings.xray_router_socket,
                settings.xray_router_token.clone(),
            )))
        });
        let mut telemt = TelemtAdapter::new(TelemtClient::new(&settings.telemt_url, settings.telemt_token.clone()))
            .with_public_host(settings.mtproxy_public_host.clone())
            .with_journal_path(Some(settings.telemt_egress_journal()))
            .with_router(router.clone());
        if let Some(probe) = bridge_probe {
            telemt = telemt.with_bridge_probe(probe);
        }
        let fallback = |host: &str| if host.is_empty() { settings.naive_public_host.clone() } else { host.to_string() };
        Self {
            telemt: Arc::new(telemt),
            naive: Arc::new(NaiveAdapter::new(
                NaiveClient::new(&settings.naive_socket, settings.naive_token.clone()),
                settings.naive_public_host.clone(),
            )),
            mieru: Arc::new(MieruAdapter::new(
                MieruClient::new(&settings.mieru_socket, settings.mieru_token.clone()),
                "",
            )),
            amneziawg: Arc::new(AmneziawgAdapter::new(
                AmneziawgClient::new(&settings.amneziawg_socket, settings.amneziawg_token.clone()),
                fallback(&settings.amneziawg_public_host),
            )),
            trusttunnel: Arc::new(
                TrusttunnelAdapter::new(
                    TrusttunnelClient::new(&settings.trusttunnel_socket, settings.trusttunnel_token.clone()),
                    fallback(&settings.trusttunnel_public_host),
                )
                .with_router(router.clone()),
            ),
            router,
        }
    }
}

fn ok<T, E>(result: Result<T, E>) -> Option<T> {
    result.ok()
}

impl NodeRuntime for ManagerRuntime {
    fn adapter(&self, protocol: Protocol) -> Option<Arc<dyn ProtocolAdapter>> {
        Some(match protocol {
            Protocol::Mtproxy => self.telemt.clone(),
            Protocol::Naive => self.naive.clone(),
            Protocol::Mieru => self.mieru.clone(),
            Protocol::Amneziawg => self.amneziawg.clone(),
            Protocol::Trusttunnel => self.trusttunnel.clone(),
        })
    }

    fn router(&self) -> Option<Arc<dyn FleetRouter>> {
        self.router.clone().map(|router| router as Arc<dyn FleetRouter>)
    }

    fn batch(&self, protocol: Protocol) -> Option<Box<dyn Any + Send>> {
        (protocol == Protocol::Mtproxy).then(|| Box::new(self.telemt.batch()) as Box<dyn Any + Send>)
    }

    fn has_lanes(&self, protocol: Protocol) -> bool {
        matches!(protocol, Protocol::Naive | Protocol::Mieru)
    }

    fn set_lanes<'a>(&'a self, protocol: Protocol, lanes: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        match protocol {
            Protocol::Naive => Box::pin(self.naive.set_lanes(lanes)),
            Protocol::Mieru => Box::pin(self.mieru.set_lanes(lanes)),
            other => Box::pin(async move { Err(AdapterError::new(format!("{other} runs no lanes on this node"))) }),
        }
    }

    fn healthy(&self, protocol: Protocol) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            match protocol {
                Protocol::Mtproxy => self.telemt.client().health().await.is_ok(),
                Protocol::Naive => self.naive.client().health().await.is_ok(),
                Protocol::Mieru => self.mieru.client().health().await.is_ok(),
                Protocol::Amneziawg => self.amneziawg.client().health().await.is_ok(),
                Protocol::Trusttunnel => self.trusttunnel.client().health().await.is_ok(),
            }
        })
    }

    fn amneziawg_versions(&self) -> BoxFuture<'_, Result<Vec<String>, AdapterError>> {
        Box::pin(self.amneziawg.versions())
    }

    fn telemt_users(&self) -> BoxFuture<'_, Option<Value>> {
        Box::pin(async move { ok(self.telemt.client().list_users().await) })
    }

    fn naive_traffic(&self) -> BoxFuture<'_, Option<Value>> {
        Box::pin(async move { ok(self.naive.client().traffic().await) })
    }

    fn trusttunnel_clients(&self) -> BoxFuture<'_, Option<Value>> {
        Box::pin(async move { ok(self.trusttunnel.client().clients().await) })
    }

    fn amneziawg_peers(&self) -> BoxFuture<'_, Option<Value>> {
        Box::pin(async move { ok(self.amneziawg.client().peers().await) })
    }
}
