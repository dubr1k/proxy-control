//! `panel/metrics/routes.py` (WP13): `/api/metrics/live|clients|stream|history|summary`, served by
//! the handlers of `panel_metrics::routes` after this shell's `context.current`, plus the
//! collector's background loop (`metrics`, started by the lifespan only when
//! `PANEL_METRICS_ENABLED`).
//!
//! The routes are `GET` only, as in Python: `HEAD` and other methods are the router's 405. The
//! handlers' JSON answers carry `Cache-Control: no-store` themselves (`NO_STORE`), which the
//! security stage sets on every answer anyway.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use http::HeaderMap;
use panel_metrics::routes::{self as metrics, Caller, MetricsState};
use panel_metrics::{Metrics, MetricsCollector};
use panel_model::metrics::{MetricsNode, LOCAL_NODE};
use panel_model::protocols::BoxFuture;
use panel_nodes::NodeLifecycleService;
use serde_json::Value;

use crate::auth::{blocking, Via};
use crate::http::request::{latin1, parse_cookies, Call};
use crate::http::response::{self, Handled};
use crate::http::router::Routes;
use crate::lifespan::{BackgroundLoop, StopSignal};
use crate::state::AppState;

pub fn routes() -> Routes {
    Routes::new()
        .get("/api/metrics/live", live)
        .get("/api/metrics/clients", clients)
        .get("/api/metrics/stream", stream)
        .get("/api/metrics/history", history)
        .get("/api/metrics/summary", summary)
}

impl MetricsState for AppState {
    fn metrics(&self) -> &Arc<Metrics> {
        self.service::<Arc<Metrics>>()
    }

    /// `alive()`: an API-key caller's bearer key (`authorization[7:]`, stripped) still
    /// authenticates; a session caller's `panel_session` cookie still names a live session.
    fn still_valid<'a>(&'a self, caller: &'a Caller, headers: &'a HeaderMap) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let first = |name: &str| headers.get(name).map(|value| latin1(value.as_bytes()));
            if caller.via_api_key {
                let header = first("authorization").unwrap_or_default();
                let key = panel_core::pytext::strip(&header.chars().skip(7).collect::<String>()).to_string();
                let keys = self.api_keys.clone();
                matches!(blocking(move || keys.authenticate(Some(&key))).await, Ok(Some(_)))
            } else {
                let cookie = first("cookie").and_then(|value| parse_cookies(&value).remove("panel_session"));
                let store = self.store.clone();
                matches!(blocking(move || store.session(cookie.as_deref())).await, Ok(Some(_)))
            }
        })
    }

    /// `linked_nodes()`: every node but this one that is not disabled, in `nodes.list()` order.
    fn linked_nodes(&self) -> BoxFuture<'_, Result<Vec<MetricsNode>, Response>> {
        Box::pin(async move {
            let service = self.service::<NodeLifecycleService>().clone();
            let views = blocking(move || service.list()).await.map_err(|failure| {
                eprintln!("ERROR metrics: cannot list the nodes: {failure:?}");
                response::unhandled()
            })?;
            Ok(views
                .into_iter()
                .filter(|view| view.node_id != LOCAL_NODE && !view.disabled)
                .map(|view| MetricsNode { node_id: view.node_id, name: view.display_name })
                .collect())
        })
    }

    fn internal_error(&self, error: &dyn std::error::Error) -> Response {
        eprintln!("ERROR unhandled error while serving a request: {error}");
        response::unhandled()
    }
}

/// `Depends(context.current)` as the metrics handlers see the user.
async fn caller(app: &AppState, call: &Call) -> Result<Caller, crate::http::response::Failure> {
    let user = app.current(call).await?;
    Ok(Caller { token_hash: user.token_hash, via_api_key: user.via == Via::ApiKey })
}

async fn live(State(app): State<AppState>, call: Call) -> Handled {
    let caller = caller(&app, &call).await?;
    Ok(metrics::live(&app, caller, &call.parts).await)
}

async fn clients(State(app): State<AppState>, call: Call) -> Handled {
    let caller = caller(&app, &call).await?;
    Ok(metrics::clients(&app, caller, &call.parts).await)
}

async fn stream(State(app): State<AppState>, call: Call) -> Handled {
    let caller = caller(&app, &call).await?;
    Ok(metrics::stream(&app, caller, &call.parts).await)
}

async fn history(State(app): State<AppState>, call: Call) -> Handled {
    let caller = caller(&app, &call).await?;
    Ok(metrics::history(&app, caller, &call.parts).await)
}

async fn summary(State(app): State<AppState>, call: Call) -> Handled {
    let caller = caller(&app, &call).await?;
    Ok(metrics::summary(&app, caller, &call.parts).await)
}

/// The collector as the lifespan's `metrics` loop: `run_forever()` until the stop signal, then
/// `stop()` and the end of the run (the supervisor cancels it after the grace); the test hook's
/// tick is `tick()` + `drain()`.
pub struct MetricsLoop(pub Arc<MetricsCollector>);

impl BackgroundLoop for MetricsLoop {
    fn name(&self) -> &'static str {
        "metrics"
    }

    fn run(self: Arc<Self>, mut stop: StopSignal) -> crate::lifespan::BoxFuture<'static, ()> {
        Box::pin(async move {
            let collector = self.0.clone();
            let running = collector.clone().run_forever();
            tokio::pin!(running);
            tokio::select! {
                _ = &mut running => return,
                _ = stop.stopped() => {}
            }
            collector.stop();
            running.await;
        })
    }

    fn tick(&self, _options: Value) -> crate::lifespan::BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.0.tick().await.map_err(|error| error.to_string())?;
            self.0.drain().await;
            Ok(())
        })
    }
}
