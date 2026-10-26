//! The Proxy Control host installer (the Rust port of `installer/`), library and the
//! `proxy-control-installer` binary.
//!
//! | Module | What | Python it replaces |
//! |---|---|---|
//! | [`journal`] | typed `state.json` / checkpoints / ownership entries with strict readers | `transaction.py:222-404` |
//! | [`store`] | `TransactionStore`: the private journal directory and its files | `transaction.py:407-480` |
//! | [`engine`] | `TransactionEngine`: apply, resume, repair, uninstall, rollback | `transaction.py:870-1410` |
//! | [`adapter`] | the frozen `Adapter` trait, `compose_plan` | `adapters/base.py`, `planner.build_plan` |
//! | [`adapters`] | the adapter registry and `AdapterContext` (the adapter packages plug in here) | `planner.adapter_factories`, `adapters/*.py` |
//! | [`handoff`] | `PanelOwnershipHandoff`: the panel self-update's ownership rebase | `transaction.py:483-699` |
//! | [`migration`] | `AgentMigration`: the 3.x → 4.0 agent swap's ownership rebase | new (host inventory §9.4) |
//! | [`cli`] | the binary's dispatch of `installer_core::cli::parse` | `cli.py:165-650` |
//! | [`error`] | the installer error with Python class names and the rollback/stop distinction | the exception classes |
//! | [`model`], [`planner`] | re-exports of `installer_core::{model, planner}` | `model.py`, `planner.py` |
//!
//! The configuration, the typed model, the planner and its digest, reports, credentials, the
//! argparse-compatible command line and `verify-release` are `installer_core`'s; the file
//! primitives, the operation lock, the byte-exact JSON writers and the command runners are
//! `pc_host`'s. There is one plan type and one plan reader
//! ([`InstallPlan::from_value`](installer_core::planner::InstallPlan::from_value), whose errors
//! the journal maps to `transaction plan is invalid`) and one secret scanner
//! (`installer_core::planner::assert_secret_free`).
//!
//! # Public API (frozen for the adapter packages, host WP5a–e; the integrator owns changes)
//!
//! What an adapter package uses, and nothing else:
//!
//! - **The trait** [`adapter::Adapter`]: `name`, `requires` (default: the registry's
//!   `installer_core::planner::adapter_requires(name)`; never override it in a real adapter),
//!   `plan(&InstallerConfig, &AuditFacts) -> Result<Vec<Action>, Error>`,
//!   `prepare(&Action) -> Result<CheckpointData, Error>`, `apply`, `reconcile_apply`,
//!   `repair` (`(&Action, CheckpointData) -> Result<CheckpointData, Error>`), `verify(&Action)
//!   -> Result<Evidence, Error>`, `rollback`, `reconcile_rollback` (`(&Action, CheckpointData,
//!   purge_data: bool, RollbackTarget) -> Result<Evidence, Error>`), optional
//!   `checkpoint_committed(Phase, &Action)`. Lifecycle, ownership declaration and error rules:
//!   the [`adapter`] module documentation.
//! - **Construction**: `pub fn new(context: &adapters::AdapterContext) -> Self` with
//!   `AdapterContext { root, tree, runner: Arc<dyn pc_host::runner::HostRunner> }`; register it
//!   with one line in [`adapters::registry`]. MCP's report handoff is [`adapters::mcp_handoff`].
//! - **Configuration** (`installer_core::model`, re-exported as [`model`]): `InstallerConfig {
//!   schema, host_mode: HostMode, profile: Profile, acme_email, initial_user, domains:
//!   DomainConfig, mieru: Option<MieruConfig>, three_xui: ThreeXuiConfig, firewall:
//!   FirewallConfig, egress: Option<EgressConfig>, ingress: Option<IngressConfig>, amneziawg:
//!   Option<AmneziaWgConfig>, trusttunnel: Option<TrustTunnelConfig> }` with `effective_egress()`,
//!   `panel_tls_port()`, `required_domains()`, `canonical_dict()`; the constants `ROUTER_PORTS`,
//!   `TRUSTTUNNEL_ROUTER_PORT`, `DEFAULT_RELAY_PORT`, `AWG_*`, `TT_*`, `LANE_SLOT_BASE_PORT`,
//!   `lane_slot_port`, `awg_interface`. Port tables: `installer_core::config::{reserved_tcp_ports,
//!   planned_ports}`.
//! - **Plan types** (`installer_core::planner`, re-exported as [`planner`]): `Action { id,
//!   adapter, owner, mutations, preconditions, verification, inverse, credentials_required }` with
//!   `Action::new(…) -> Result<Action, PlanError>` (Python's `__post_init__` checks and the secret
//!   scanner; `validate`/`checked` for a struct literal); `Evidence { action_id, success,
//!   observations, details }` with `Evidence::ok(id, &[obs])`, `Evidence::failed`,
//!   `Evidence::with_details(id, success, observations, Map)`, `Evidence::new(…, Fact)`;
//!   `AuditFacts { platform, listeners, ownership, topology, prerequisites, transient }` (JSON
//!   objects; `transient` never enters the plan); `PlanError::{new, adapter(class, msg)}` (a
//!   planning refusal with its Python class, e.g. `PlanError::adapter("NginxError", …)`);
//!   `ReleaseIdentity`, `InstallPlan`, `adapters_for`, `compose_file_list`, `ADAPTER_NAMES`.
//! - **Journal types** ([`journal`]): `CheckpointData` (= `serde_json::Map<String, Value>`),
//!   `Phase`, `RollbackTarget`, `Status`, `TransactionState`, `Checkpoint`.
//! - **Errors** ([`error`]): `Error::{Tx, Plan, Other, Fatal}`, `Error::other(class, msg)`,
//!   `Error::fatal(class, msg)`, `error::transaction(msg)`, `error::ownership(msg)`; `From` for
//!   `TxError`, `io::Error`, `PlanError`, `pc_host::runner::{RunError, BoundedError}`.
//! - **Host plumbing** (`pc_host`, frozen): `fs::{root_path, atomic_write, durable_mkdir,
//!   durable_copy2, durable_remove, sha256_hex, sha256_file, path_identity, …}`, `json::{canonical,
//!   pretty2, …}`, `runner::{HostRunner, SystemRunner, RecordingRunner, Reply, Call, CallKind,
//!   Bounded, RunOptions, Capture, …}`, `archive::{…}`, `net::HttpsClient`.
//! - **The engine** (for tests and the CLI): `engine::TransactionEngine::{new, register,
//!   with_adapter, with_agent_managed, store, adapter_named, adapter_names, apply, resume,
//!   repair, uninstall, persist, ownership_for, assert_all_owned}`, `AGENT_MANAGED_PATHS`,
//!   `agent_managed_paths`; [`adapter::compose_plan`]`(config, facts, &[Arc<dyn Adapter>],
//!   release) -> Result<InstallPlan, Error>`.
//! - **Tests** (`crate::testkit`, `#[cfg(test)]`): `TempDir::{new, path}`, `release()` (the test
//!   `ReleaseIdentity`), `engine_for(root, adapters)`, `action_for(name)`, `plan_for(names)`,
//!   `plan_with(actions, platform)`, `RecordingAdapter` (+ `Failure::{Crash, Runtime}` to inject
//!   a `BaseException`/`RuntimeError`). Commands: `pc_host::runner::RecordingRunner::{new,
//!   with_responder, reply(prefix, Reply), reply_once, reply_for(CallKind, …), calls(), argvs(),
//!   clear()}`; an unmatched call answers exit 0 with empty output.
//!
//! Also public (journal tooling, the agent's handoff): `store::TransactionStore::{new, root,
//! directory, state_path, plan_path, ownership_path, report_path, backups_path,
//! credentials_path, state_exists, initialize, locked, write_plan, read_plan, write_state,
//! read_state, write_ownership, read_ownership, write_report, remove_state}` (+
//! `set_fault_hook` with the `test-fakes` feature), `JournalFile`;
//! `journal::{TRANSACTION_SCHEMA, ORIGIN_INSTALLER, OwnershipEntry, Ownership,
//! ownership_to_value, ownership_from_value}`; `handoff::{PanelOwnershipHandoff::{new, prepare,
//! commit, expected}, rebase_panel_ownership, AGENT_CODE_DIR, CORE_ACTION, AGENT_ACTION}`;
//! `migration::{AgentMigration::{new, with_rehashed, prepare, commit, expected},
//! rebase_agent_ownership, AGENT_UNIT, AGENT_ENV, MIGRATION_REHASHED}`; `cli::{main, run,
//! Services::{system, with_context}, plan, release_tree}`.
//!
//! # Writing an adapter
//!
//! The complete, compiled and tested example is `src/adapters/example.rs` (shown in full at the
//! end of this page); an adapter package is the same shape in `src/adapters/<name>.rs`:
//!
//! 1. **State lives on the host, not in the adapter.** `resume`, `repair` and `uninstall` run
//!    without a configuration, so `plan` writes every value the later methods need into the
//!    action's mutation strings (they are part of the digest the operator approves), and the
//!    methods read them back from the [`Action`](installer_core::planner::Action):
//!
//!    ```rust,ignore
//!    fn plan(&self, config: &InstallerConfig, _facts: &AuditFacts) -> Result<Vec<Action>, Error> {
//!        Ok(vec![Action::new(
//!            "example.marker", "example", "proxy-control:example",
//!            vec![format!("write {MARKER} panel={}", config.domains.panel)],
//!            vec![format!("{MARKER} is absent")],
//!            vec![format!("{MARKER} names the panel domain")],
//!            vec![format!("remove {MARKER}")],
//!            false,
//!        )?])
//!    }
//!    ```
//! 2. **Every host path through the root**: `pc_host::fs::root_path(&self.root, "/etc/…")?`;
//!    write with `pc_host::fs::atomic_write(path, bytes, mode, owner)`.
//! 3. **Every command through the runner**: `self.runner.run(&argv, &RunOptions::default())?`
//!    for a mutation (a `RunError` converts into the right [`Error`]: an interrupt stops the
//!    engine, a timeout rolls back), `bounded(&argv, Bounded::NGINX)` for audit-style checks.
//! 4. **Declare what you own** in the data `apply`/`reconcile_apply`/`repair` return:
//!    `data.insert("ownership".into(), json!({ MARKER: {"sha256": digest, "preserve": false} }))`.
//!    The engine hashes the paths, refuses to roll back or uninstall a drifted file and keeps
//!    `preserve: true` paths unless purging.
//! 5. **Evidence**: `verify` returns `Evidence::ok(&action.id, &["…"])` or `Evidence::failed`
//!    (a failed verification rolls the install back); `rollback`/`reconcile_rollback` return
//!    `Evidence::ok` once the mutation is undone (`reconcile_rollback` must accept a half-done
//!    state: paths may already be gone).
//! 6. **Errors** keep the Python class: `Error::other("NginxError", "…")`.
//! 7. **Test** with a [`TempDir`](crate::testkit::TempDir) root, a `RecordingRunner`, the real
//!    planner and the real engine:
//!
//!    ```rust,ignore
//!    let dir = TempDir::new("example");
//!    let runner = Arc::new(RecordingRunner::new());
//!    let context = AdapterContext { root: dir.path().into(), tree: dir.path().into(), runner: runner.clone() };
//!    let adapter: Arc<dyn Adapter> = Arc::new(ExampleAdapter::new(&context));
//!    let plan = compose_plan(&config(), &AuditFacts::default(), std::slice::from_ref(&adapter), &release()).unwrap();
//!    let engine = engine_for(dir.path(), vec![adapter]);
//!    assert_eq!(engine.apply(&plan, &plan.digest()).unwrap().status, Status::Active);
//!    assert_eq!(runner.calls()[0].argv, ["systemctl", "daemon-reload"]);
//!    assert_eq!(engine.uninstall(false).unwrap().status, Status::Uninstalled);
//!    ```
//!
//!    Golden fixtures (`tests/fixtures/host-golden/installs/<profile>/{commands.json,
//!    root/files/…, journal/}`) give the exact commands, file bytes and checkpoint data the
//!    Python adapter produced; reproduce them byte for byte.
//!
//! The full example (`src/adapters/example.rs`):
//!
//! ```rust,ignore
#![doc = include_str!("adapters/example.rs")]
//! ```

pub mod adapter;
pub mod adapters;
pub mod cli;
pub mod engine;
pub mod error;
pub mod handoff;
pub mod journal;
pub mod migration;
pub mod store;
pub mod three_xui_api;
pub mod three_xui_templates;
mod three_xui_ordered;

pub use installer_core::{model, planner};

#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

pub use adapter::Adapter;
pub use engine::TransactionEngine;
pub use error::Error;
pub use handoff::PanelOwnershipHandoff;
pub use installer_core::planner::{Action, Evidence, InstallPlan};
pub use journal::{Checkpoint, Phase, RollbackTarget, Status, TransactionState};
pub use migration::AgentMigration;
pub use store::TransactionStore;
