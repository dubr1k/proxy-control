//! Proxy Control installer core: the Rust port of `installer/config.py`, `model.py`,
//! `planner.py`, `report.py`, `credentials.py`, `awg_ports.py`, the argument surface and output
//! forms of `cli.py`, and `release/verify.py`. The `installer` crate (the transaction engine, the
//! adapters, the audit and the wizard) links it; nothing here touches the host beyond reading
//! the files it is pointed at and writing reports and credentials.
//!
//! | Module | What | Python |
//! |---|---|---|
//! | [`toml`] | TOML 1.0 exactly as `tomllib` (messages, order, unbounded ints) | `tomllib` |
//! | [`config`] | TOML → [`model::InstallerConfig`], validation in Python's order, `render_config`, port tables | `installer/config.py` |
//! | [`model`] | the typed configuration and its canonical dict | `installer/model.py` |
//! | [`awg_ports`] | host-stable AmneziaWG ports | `installer/awg_ports.py` |
//! | [`planner`] | facts, actions, evidence, release identity, plan + digest, adapter selection and order | `installer/planner.py` |
//! | [`report`] | public report, credential handoff, operator notes | `installer/report.py`, `cli._write_reports` |
//! | [`credentials`] | operator credentials beside the config and their staging | `installer/credentials.py` |
//! | [`argparse`] | Python 3.12 `argparse` behaviour and bytes for the parsers used here | `argparse` |
//! | [`cli`] | the installer's parser, [`cli::Command`], `BLOCKED:` and the output forms | `installer/cli.py` |
//! | [`verify_release`] | `verify-release manifest|artifact` | `release/verify.py` |
//! | [`pystr`], [`ipaddr`], [`secret`] | Python string, `ipaddress` and secret-regex semantics | stdlib, `re` |
//!
//! # Public API
//!
//! - `config`: `load_config(path)`, `parse_config(text)`, `render_config(&config)`,
//!   `reserved_tcp_ports`, `planned_ports` (`PortTable`), `normalize_domain`, `domain_shape_ok`,
//!   `safe_name`, `ConfigError`.
//! - `model`: `InstallerConfig` (+ `effective_egress`, `panel_tls_port`, `required_domains`,
//!   `canonical_dict`), the section structs and enums, `ROUTER_PORTS`, `AWG_*`, `TT_*`, lane slots.
//! - `awg_ports`: `resolve_awg_ports(&config, root, listeners, identity)`, `machine_id`,
//!   `derive_port`, `bound_ports`, `installed_ports`, `pick_ports`.
//! - `planner`: `Fact`, `AuditFacts::{from_groups, stable_dict}`, `Action::{new, from_value,
//!   to_value}`, `Evidence::new`, `ReleaseIdentity::{new, from_tree, from_value, to_value}`,
//!   `InstallPlan::{new, from_value, from_json, canonical_value, to_canonical_json, digest,
//!   intent_digest, assert_fresh}`, trait `PlanAdapter`, `build_plan`, `adapters_for`,
//!   `adapter_requires`, `ADAPTER_NAMES`, `PROFILE_ORDER`, `compose_file_list`,
//!   `assert_secret_free`, `PlanError` (`Plan`, `Stale`, `Adapter{class,message}`).
//! - `report`: `AcceptanceReport`, `CredentialHandoff`, `ReportWriter::{write_public,
//!   write_credentials}`, `evidence_from_checkpoint`, `operator_notes`, `encode`, `ReportError`.
//! - `credentials`: `OperatorCredentials`, `credentials_path`, `write_credentials`,
//!   `read_credentials`, `staged_path`, `stage_credentials`, `stage_operator_credentials`,
//!   `staged_credentials`, `discard_staged_credentials`, `CredentialError`.
//! - `cli`: `installer_parser`, `python_parser`, `parse(argv, width) -> Result<Args, Exit>`,
//!   `Command`, `blocked_line`, `bounded_text`, `check_accepted_digest`, `confirmation_matches`,
//!   `validate_plan`, `render_plan_json`, `render_plan_text`, `plan_summary_lines`,
//!   `StatusView::{from_state, render}`, `render_report_written`, `installed_version`,
//!   `check_archive_digest`, `release_identity`, `CliError`.
//! - `argparse`: `Parser` (+ `add_option`, `add_flag`, `add_positional`, `add_subparsers`,
//!   `parse_args`, `format_usage`, `format_help`), `Exit`, `terminal_width`, `wrap`.
//! - `verify_release`: `Request`, `run(&request) -> (status, stdout, stderr)`.

pub mod argparse;
pub mod awg_ports;
pub mod cli;
pub mod config;
pub mod credentials;
pub mod ipaddr;
pub mod model;
pub mod planner;
pub mod pystr;
pub mod report;
pub mod secret;
pub mod toml;
pub mod verify_release;
