//! The Proxy Control host installer (the Rust port of `installer/`), library and the
//! `proxy-control-installer` binary.
//!
//! | Module | What | Python it replaces |
//! |---|---|---|
//! | [`journal`] | typed `state.json` / checkpoints / ownership entries with strict readers | `transaction.py:222-404` |
//! | [`store`] | `TransactionStore`: the private journal directory and its files | `transaction.py:407-480` |
//! | [`engine`] | `TransactionEngine`: apply, resume, repair, uninstall, rollback | `transaction.py:870-1410` |
//! | [`adapter`] | the frozen `Adapter` trait the adapter packages implement | `adapters/base.py` |
//! | [`handoff`] | `PanelOwnershipHandoff`: the panel self-update's ownership rebase | `transaction.py:483-699` |
//! | [`migration`] | `AgentMigration`: the 3.x → 4.0 agent swap's ownership rebase | new (host inventory §9.4) |
//! | [`plan`] | actions, evidence, release identity, audit facts, the canonical plan | `planner.py:48-310` |
//! | [`model`] | `InstallerConfig` (placeholder until host WP3) | `model.py` |
//! | [`cli`] | the command-line skeleton (`--version`, argparse-style usage errors) | `cli.py:88-135` |
//! | [`error`] | the installer error with Python class names and the rollback/stop distinction | the exception classes |
//!
//! The file primitives, the operation lock, the byte-exact JSON writers and the command runners
//! are `pc_host`'s.
//!
//! # Public API (frozen at the end of host WP2; the integrator owns changes)
//!
//! - `adapter::Adapter { name, requires, plan, prepare, apply, reconcile_apply, verify, repair,
//!   rollback, reconcile_rollback, checkpoint_committed }`.
//! - `engine::TransactionEngine::{new, register, with_adapter, with_agent_managed, store, apply,
//!   resume, repair, uninstall, persist, ownership_for, assert_all_owned}`,
//!   `AGENT_MANAGED_PATHS`, `agent_managed_paths`.
//! - `store::TransactionStore::{new, root, directory, state_path, plan_path, ownership_path,
//!   report_path, backups_path, credentials_path, state_exists, initialize, locked, write_plan,
//!   read_plan, write_state, read_state, write_ownership, read_ownership, write_report,
//!   remove_state}` (+ `set_fault_hook` with the `test-fakes` feature), `JournalFile`.
//! - `journal::{TransactionState, Checkpoint, OwnershipEntry, Ownership, CheckpointData, Status,
//!   Phase, RollbackTarget, TRANSACTION_SCHEMA, ORIGIN_INSTALLER, ownership_to_value,
//!   ownership_from_value}`.
//! - `handoff::{PanelOwnershipHandoff::{new, prepare, commit, expected}, rebase_panel_ownership,
//!   AGENT_CODE_DIR, CORE_ACTION, AGENT_ACTION}`.
//! - `migration::{AgentMigration::{new, with_rehashed, prepare, commit, expected},
//!   rebase_agent_ownership, AGENT_UNIT, AGENT_ENV, MIGRATION_REHASHED}`.
//! - `plan::{Action, Evidence, ReleaseIdentity, AuditFacts, InstallPlan, PlanError, PLAN_SCHEMA,
//!   assert_secret_free, has_secret_assignment}`.
//! - `error::Error::{Tx, Plan, Other, Fatal}` with `other`, `fatal`, `python_class_name`,
//!   `message`, `is_fatal`, `as_tx`.

pub mod adapter;
pub mod cli;
pub mod engine;
pub mod error;
pub mod handoff;
pub mod journal;
pub mod migration;
pub mod model;
pub mod plan;
pub mod store;

#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

pub use adapter::Adapter;
pub use engine::TransactionEngine;
pub use error::Error;
pub use handoff::PanelOwnershipHandoff;
pub use journal::{Checkpoint, Phase, RollbackTarget, Status, TransactionState};
pub use migration::AgentMigration;
pub use plan::{Action, Evidence, InstallPlan};
pub use store::TransactionStore;
