//! Deadline enforcement is local to each panel and survives loss of its central
//! (`clients/enforcement.py`).
//!
//! [`AccessEnforcer::tick`] is one pass (the `/__test/tick/enforcer` hook, and the
//! `tick(force=True)` that runs before the panel serves); [`AccessEnforcer::run_until`] is
//! `run_forever`: a tick every `interval` seconds until stopped.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use panel_model::protocols::BoxFuture;
use panel_model::seams::SeamError;

use crate::service::ClientService;

/// The node side's pending-generation reconciler (WP12, `fleet_v2.reconcile.Reconciler.run_pending`).
pub trait PendingReconciler: Send + Sync {
    fn run_pending(&self) -> BoxFuture<'_, Result<(), SeamError>>;
}

/// `ENFORCER_INTERVAL`: 15 s.
pub const INTERVAL: Duration = Duration::from_secs(15);

/// The access enforcer (`AccessEnforcer`).
#[derive(Clone)]
pub struct AccessEnforcer {
    clients: ClientService,
    reconciler: Option<Arc<dyn PendingReconciler>>,
    interval: Duration,
}

impl std::fmt::Debug for AccessEnforcer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessEnforcer").field("interval", &self.interval).finish_non_exhaustive()
    }
}

impl AccessEnforcer {
    pub fn new(clients: ClientService, reconciler: Option<Arc<dyn PendingReconciler>>) -> Self {
        Self { clients, reconciler, interval: INTERVAL }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// `tick(force=…)`: local expiry, then the node's pending generation — independent failure
    /// boundaries, each retried on the next tick.
    pub async fn tick(&self, force: bool) {
        if self.clients.reconcile_access(None, force).await.is_err() {
            log::warn!("access enforcement tick failed; retrying");
        }
        if let Some(reconciler) = &self.reconciler {
            if reconciler.run_pending().await.is_err() {
                log::warn!("access enforcement tick failed; retrying");
            }
        }
    }

    /// `run_forever()`: waits `interval` (or until `stopped` resolves), then ticks.
    pub async fn run_until<S: Future<Output = ()>>(&self, stopped: S) {
        tokio::pin!(stopped);
        loop {
            tokio::select! {
                _ = &mut stopped => return,
                _ = tokio::time::sleep(self.interval) => self.tick(false).await,
            }
        }
    }
}
