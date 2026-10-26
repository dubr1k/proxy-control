//! What routing needs of the runtime: the protocol adapters (`app.state.adapters`), the managers'
//! lane tables (`adapter.set_lanes`) and the node's Xray-router (`app.state.router`) — as traits,
//! so the service runs over the real managers in the panel and over memory doubles in tests.
//!
//! The panel keeps one adapter set (`panel_fleet::node::ManagerRuntime` builds it; the web crate
//! hands its adapters here through [`Managers`]).

use std::sync::Arc;

use panel_clients::Adapters;
use panel_model::protocols::{AdapterError, AppliedEgress, BoxFuture, ProtocolAdapter, RouterTarget};
use panel_model::Protocol;
use panel_protocols::api::{MieruApi, NaiveApi, RouterApi};
pub use panel_protocols::xray_router::GeodataAction;
use panel_protocols::{MieruAdapter, NaiveAdapter, RouterAdapter};
use serde_json::Value;

/// The node's Xray-router as the routing service drives it (`protocols/xray_router.py`).
pub trait RoutingRouter: Send + Sync {
    /// The service's section, or an unavailable target with its reason (never fails).
    fn target<'a>(&'a self, service: &'a str) -> BoxFuture<'a, RouterTarget>;
    fn plan<'a>(
        &'a self,
        service: &'a str,
        document: &'a Value,
        expected_revision: &'a str,
    ) -> BoxFuture<'a, Result<Value, AdapterError>>;
    fn apply<'a>(
        &'a self,
        service: &'a str,
        document: &'a Value,
        expected_revision: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>>;
    fn rollback<'a>(
        &'a self,
        service: &'a str,
        expected_revision: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>>;
    fn lane_issue<'a>(&'a self, service: &'a str, lane: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>>;
    fn lane_forget<'a>(&'a self, service: &'a str, lane: &'a str) -> BoxFuture<'a, Result<Value, AdapterError>>;
    /// The relay inbound's view, `None` when the router does not answer.
    fn relay(&self) -> BoxFuture<'_, Option<Value>>;
    fn relay_enable<'a>(&'a self, server_name: &'a str, port: i64) -> BoxFuture<'a, Result<Value, AdapterError>>;
    fn relay_set_accounts<'a>(&'a self, accounts: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>>;
    fn exit_test<'a>(&'a self, spec: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>>;
    fn geodata<'a>(
        &'a self,
        action: GeodataAction,
        body: Option<&'a Value>,
    ) -> BoxFuture<'a, Result<Value, AdapterError>>;
}

impl<C: RouterApi + 'static> RoutingRouter for RouterAdapter<C> {
    fn target<'a>(&'a self, service: &'a str) -> BoxFuture<'a, RouterTarget> {
        Box::pin(RouterAdapter::target(self, service))
    }

    fn plan<'a>(
        &'a self,
        service: &'a str,
        document: &'a Value,
        expected_revision: &'a str,
    ) -> BoxFuture<'a, Result<Value, AdapterError>> {
        Box::pin(RouterAdapter::plan(self, service, document, expected_revision))
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

    fn rollback<'a>(
        &'a self,
        service: &'a str,
        expected_revision: &'a str,
    ) -> BoxFuture<'a, Result<AppliedEgress, AdapterError>> {
        Box::pin(RouterAdapter::rollback(self, service, expected_revision))
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

/// The adapters routing calls (`self.adapters[protocol]`), and the lane tables of the services
/// that have lanes (`adapter.set_lanes(lanes)`, NaiveProxy and Mieru).
pub trait RoutingAdapters: Send + Sync {
    /// `self.adapters.get(protocol)`.
    fn adapter(&self, protocol: Protocol) -> Option<Arc<dyn ProtocolAdapter>>;
    /// `self.adapters[protocol].set_lanes(lanes)`.
    fn set_lanes<'a>(&'a self, protocol: Protocol, lanes: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>>;
}

/// The production adapter set: the panel's shared [`Adapters`] plus the NaiveProxy and Mieru
/// adapters for their lane tables.
pub struct Managers<N: NaiveApi + 'static, M: MieruApi + 'static> {
    pub adapters: Adapters,
    pub naive: Arc<NaiveAdapter<N>>,
    pub mieru: Arc<MieruAdapter<M>>,
}

impl<N: NaiveApi + 'static, M: MieruApi + 'static> Managers<N, M> {
    pub fn new(adapters: Adapters, naive: Arc<NaiveAdapter<N>>, mieru: Arc<MieruAdapter<M>>) -> Self {
        Self { adapters, naive, mieru }
    }
}

impl<N: NaiveApi + 'static, M: MieruApi + 'static> RoutingAdapters for Managers<N, M> {
    fn adapter(&self, protocol: Protocol) -> Option<Arc<dyn ProtocolAdapter>> {
        self.adapters.get(protocol)
    }

    fn set_lanes<'a>(&'a self, protocol: Protocol, lanes: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        match protocol {
            Protocol::Naive => Box::pin(self.naive.set_lanes(lanes)),
            Protocol::Mieru => Box::pin(self.mieru.set_lanes(lanes)),
            // Python: `AttributeError` — the adapter has no `set_lanes` (never reached: lanes are
            // refused for every other protocol first).
            other => Box::pin(async move { Err(AdapterError::new(format!("{other} has no lanes"))) }),
        }
    }
}
