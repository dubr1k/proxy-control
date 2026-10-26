//! The adapter contract (`installer/adapters/base.py`, host inventory C1.0). **Frozen at the end
//! of the host WP2/WP3 integration**: the adapter packages (WP5a–e) implement it; changes go
//! through the integrator. The worked example is in the crate documentation (`lib.rs`).
//!
//! # Lifecycle, as the engine drives it
//!
//! ```text
//! plan(config, facts)            → the adapter's actions (secret-free; mutation strings and their
//!                                  order are part of the plan digest)
//! prepare(action)                → checkpoint `prepared` (persisted before anything changes)
//!                                  checkpoint `applying` is persisted BEFORE apply runs
//! apply(action, data)            → checkpoint `applied`; the engine hashes every path the data
//!                                  declares under `ownership` and stores the result
//! verify(action)                 → checkpoint `verified` with the evidence (must be `success` and
//!                                  carry `action.id`)
//! reconcile_apply(action, data)  → `resume` of a checkpoint left `applying` by a crash: finish or
//!                                  redo the mutation idempotently, return the data like `apply`
//! repair(action, data)           → `repair` of an active install: restore drifted owned state,
//!                                  return the data; ownership is re-captured, then `verify`
//! rollback(action, data, purge, target)
//!                                → undo an `applied`/`verified` checkpoint (in reverse plan order);
//!                                  the engine first proved every owned path is untouched
//! reconcile_rollback(action, data, purge, target)
//!                                → undo a checkpoint a crash left `applying` or
//!                                  `rollback_in_progress`; owned paths may already be gone
//! checkpoint_committed(phase, action)
//!                                → optional hook after each persisted checkpoint
//! ```
//!
//! `purge_data` is true for a failed install (everything goes) and for `uninstall
//! --purge-data`; otherwise the adapter keeps what it declared `preserve`.
//!
//! # Checkpoint data and ownership
//!
//! [`CheckpointData`] is the adapter's own JSON object; the engine stores it as is (it lands in
//! `state.json`, so it must never hold a secret) and hands a copy back to the next method. The
//! engine reads one key: the ownership declaration, `data["ownership"]` (else `owned_files`,
//! else `owned_paths`): a map `host path → declaration` or a list of host paths. A declaration is
//!
//! - a SHA-256 string: the file must have exactly these bytes now (`owned file drifted: <p>`);
//! - `{"sha256"?: …, "preserve"?: bool, "mutable"?: bool}`: `preserve` keeps the path on a
//!   rollback without purge; `mutable` means a service rewrites it, so only existence and kind
//!   are compared later;
//! - `null`: owned, nothing declared.
//!
//! The shapes the Python adapters used must keep working, because journals written by 3.x are
//! resumed, repaired and uninstalled by 4.0 (host inventory C1.0 "Ownership").
//!
//! # Errors
//!
//! Return [`Error`]: `Error::Tx` for transaction/ownership failures, `Error::other(class, msg)`
//! for the adapter's own exceptions (the class name is recorded in `state.json:error`, so use
//! the Python name: `CoreError`, `NginxError`, `WarpError`, …), `Error::Plan` for a planning
//! refusal (`PlanError::adapter(class, msg)` keeps the class), `Error::fatal` only for what must
//! not roll back (an interrupt, an unconfirmed process kill — `From<RunError>` maps both).
//!
//! # Commands and tests
//!
//! Adapters run commands only through `pc_host::runner::HostRunner` (one `Arc<dyn HostRunner>`
//! given at construction; `SystemRunner` in production): `bounded` for the audit contract with the
//! adapter's `Bounded::{NGINX, CERTIFICATES, PACKAGES, FIREWALL, WARP}` limits, `run` for mutating
//! commands (`RunOptions`, 900 s), `capture`/`capture_checked` for diagnostics. Tests construct the
//! adapter with `pc_host::runner::RecordingRunner` (rules by argv prefix, one-shot rules, a
//! responder closure; `calls()`/`argvs()` to assert the exact command sequence) and a temporary
//! root, and drive it through [`TransactionEngine`](crate::engine::TransactionEngine) exactly as
//! production does (see `crate::testkit` for the temporary root and the plan helpers).

use std::cell::RefCell;
use std::sync::Arc;

use installer_core::model::InstallerConfig;
use installer_core::planner::{
    adapter_requires, build_plan, Action, AuditFacts, Evidence, InstallPlan, PlanAdapter, PlanError, ReleaseIdentity,
    ADAPTER_NAMES,
};

use crate::error::Error;
use crate::journal::{CheckpointData, Phase, RollbackTarget};

/// One installer adapter (`installer.adapters.base.Adapter`).
///
/// Methods take `&self`: an adapter that keeps state between calls uses interior mutability.
/// An adapter is stateless with respect to the configuration: `resume`, `repair` and
/// `uninstall` run without one, so everything `prepare`…`reconcile_rollback` need must come
/// from the [`Action`] (its mutation strings), the checkpoint data, the host and the adapter's
/// construction context ([`crate::adapters::AdapterContext`]).
pub trait Adapter {
    /// The adapter name the plan's actions carry (`Action.adapter`).
    fn name(&self) -> &str;

    /// Adapters that must come earlier in the plan (`requires`; part of the plan digest as
    /// `adapter_dependencies`). The default is the registry's
    /// [`adapter_requires`](installer_core::planner::adapter_requires) for the 14 known adapter
    /// names and nothing for any other name (test adapters). Do not override it in a real
    /// adapter: the digest of every recorded plan depends on these lists.
    fn requires(&self) -> &[&'static str] {
        if ADAPTER_NAMES.contains(&self.name()) {
            adapter_requires(self.name())
        } else {
            &[]
        }
    }

    /// The actions this adapter contributes for `config` on a host with `facts`.
    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>, Error>;

    /// Record what the adapter needs before mutating anything.
    fn prepare(&self, action: &Action) -> Result<CheckpointData, Error>;

    /// Perform the mutation; return the checkpoint data with the ownership declaration.
    fn apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error>;

    /// Finish a mutation a crash interrupted (checkpoint left `applying`).
    fn reconcile_apply(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error>;

    /// Prove the action's result on the host.
    fn verify(&self, action: &Action) -> Result<Evidence, Error>;

    /// Restore an active installation's owned state.
    fn repair(&self, action: &Action, checkpoint: CheckpointData) -> Result<CheckpointData, Error>;

    /// Undo an applied action.
    fn rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge_data: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error>;

    /// Undo an action a crash left half-applied or half-rolled-back.
    fn reconcile_rollback(
        &self,
        action: &Action,
        checkpoint: CheckpointData,
        purge_data: bool,
        target: RollbackTarget,
    ) -> Result<Evidence, Error>;

    /// Called after every checkpoint of this adapter's action is durably persisted.
    fn checkpoint_committed(&self, _phase: Phase, _action: &Action) -> Result<(), Error> {
        Ok(())
    }
}

/// An [`Adapter`] seen by `installer_core`'s planner. The first error an adapter's `plan`
/// returns is kept whole (class, fatality) and handed back by [`compose_plan`].
struct PlanBridge<'a> {
    adapter: &'a dyn Adapter,
    error: &'a RefCell<Option<Error>>,
}

impl PlanAdapter for PlanBridge<'_> {
    fn name(&self) -> &str {
        self.adapter.name()
    }

    fn requires(&self) -> Vec<String> {
        self.adapter.requires().iter().map(|name| name.to_string()).collect()
    }

    fn plan(&self, config: &InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>, PlanError> {
        self.adapter.plan(config, facts).map_err(|err| {
            let refusal = PlanError::adapter(err.python_class_name().to_string(), err.message());
            self.error.borrow_mut().get_or_insert(err);
            refusal
        })
    }
}

/// `build_plan(config, facts, adapters, release)` over engine adapters: the topological order,
/// each adapter's actions, the canonical plan and its digest (`installer_core::planner`). An
/// adapter's own error comes back unchanged; the planner's refusals (`duplicate action id`,
/// `adapter dependency cycle`, a secret in an action, …) as [`Error::Plan`].
pub fn compose_plan(
    config: &InstallerConfig,
    facts: &AuditFacts,
    adapters: &[Arc<dyn Adapter>],
    release: &ReleaseIdentity,
) -> Result<InstallPlan, Error> {
    let error = RefCell::new(None);
    let bridges: Vec<PlanBridge<'_>> =
        adapters.iter().map(|adapter| PlanBridge { adapter: adapter.as_ref(), error: &error }).collect();
    let planners: Vec<&dyn PlanAdapter> = bridges.iter().map(|bridge| bridge as &dyn PlanAdapter).collect();
    build_plan(config, facts, &planners, release).map_err(|refusal| error.take().unwrap_or(Error::Plan(refusal)))
}
