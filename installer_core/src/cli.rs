//! The command line of `proxy-control-installer` (`installer/cli.py`) as a library: the
//! argparse-compatible parser, the typed [`Command`], and the exact output forms (`BLOCKED:`,
//! plan text/JSON, wizard summary, status, report lines). Dispatch to the audit, the engine and
//! the wizard stays with the `installer` binary.
//!
//! Exit codes: 0 success or `-h`; 2 usage errors and `BLOCKED:`. Differences from Python
//! (DIFFERENCES.md): adapter, audit and credential refusals become `BLOCKED:`/2 instead of a
//! traceback; the binary adds `--version` and `verify-release` (formerly `release/verify.py`).

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::argparse::{Arg, Choices, Exit, Help, Namespace, Parser, SubCommand};
use crate::config::ConfigError;
use crate::model::InstallerConfig;
use crate::planner::{AuditFacts, InstallPlan, PlanError};
use crate::pystr::split_whitespace;
use crate::secret::redact;

pub const PROG: &str = "proxy-control-installer";
/// The release version, compiled in from the tree's `VERSION` (nothing reads the clock or the
/// repository, so the binary is reproducible).
pub const VERSION: &str = include_str!("../../VERSION");
pub const DESCRIPTION: &str = "Typed Proxy Control release installer";
pub const DEFAULT_CONFIG_OUTPUT: &str = "proxy-control.toml";
const INSTALLED_VERSION: &str = "opt/mtproxy-shared443/VERSION";
const OWNERSHIP_JOURNAL: &str = "var/lib/proxy-control/ownership.json";

/// `CliError`: a requested lifecycle operation cannot safely proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError(pub String);

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

impl From<ConfigError> for CliError {
    fn from(err: ConfigError) -> Self {
        CliError(err.0)
    }
}

impl From<PlanError> for CliError {
    fn from(err: PlanError) -> Self {
        CliError(blocked_message(err.message(), err.python_class_name()))
    }
}

/// The subcommands of the Python CLI (3.x), in `add_parser` order.
pub const PYTHON_COMMANDS: [&str; 9] =
    ["wizard", "plan", "install", "status", "resume", "repair", "report", "uninstall", "reconcile-panel-update"];

/// The parser of the Python CLI, byte for byte (`installer.cli._parser()`).
pub fn python_parser() -> Parser {
    parser_with(&[])
}

/// The parser of the Rust binary: the Python surface plus `--version` and `verify-release`.
pub fn installer_parser() -> Parser {
    parser_with(&["--version", "verify-release"])
}

/// What `--version` prints: `proxy-control-installer <VERSION>`.
pub fn version_text() -> String {
    format!("{PROG} {}", crate::pystr::strip(VERSION))
}

/// The Python surface plus the named extras (known: the `--version` option and the
/// `verify-release` subcommand).
pub fn parser_with(extra: &[&str]) -> Parser {
    let mut parser = Parser::new(PROG, Some(DESCRIPTION));
    parser.add_option(&["--root"], false, Help::Suppress, true, Arg::Str("/".into()));
    if extra.contains(&"--version") {
        parser.add_version(&["--version"], &version_text());
    }
    let mut commands = Vec::new();
    let mut add = |name: &str, help: &str, build: &dyn Fn(&mut Parser)| {
        let mut sub = Parser::new(&parser.sub_prog(name), None);
        build(&mut sub);
        commands.push(SubCommand { name: name.into(), help: Some(help.into()), parser: sub });
    };
    add("wizard", "start the interactive installer", &|p| {
        p.add_option(&["--lang"], false, Help::None, false, Arg::None).choices = Some(Choices {
            values: vec!["en".into(), "ru".into()],
            reprs: vec!["<Locale.EN: 'en'>".into(), "<Locale.RU: 'ru'>".into()],
            strs: vec!["en".into(), "ru".into()],
        });
        p.add_option(&["--config-output"], false, Help::None, true, Arg::Str(DEFAULT_CONFIG_OUTPUT.into()));
        p.add_flag(&["--json"], Help::None);
    });
    add("plan", "render a deterministic mutation plan", &|p| {
        p.add_option(&["--config"], true, Help::None, true, Arg::None);
        p.add_flag(&["--json"], Help::None);
    });
    add("install", "apply an accepted deterministic plan", &|p| {
        p.add_option(&["--config"], true, Help::None, true, Arg::None);
        p.add_option(&["--accept-plan"], true, Help::None, false, Arg::None);
        p.add_flag(&["--json"], Help::None);
    });
    add("status", "show sanitized transaction status", &|p| p.add_flag(&["--json"], Help::None));
    add("resume", "resume the owned transaction", &|p| p.add_flag(&["--json"], Help::None));
    add("repair", "repair the owned transaction", &|p| p.add_flag(&["--json"], Help::None));
    add("report", "write the public acceptance report and the root-only handoff", &|p| {
        p.add_option(&["--config"], true, Help::None, true, Arg::None);
        p.add_option(&["--output"], true, Help::None, true, Arg::None);
        p.add_flag(&["--json"], Help::None);
    });
    add("uninstall", "remove the owned transaction", &|p| {
        p.add_flag(&["--purge-data"], Help::None);
        p.add_flag(&["--json"], Help::None);
    });
    add(
        "reconcile-panel-update",
        "reconcile Core and version-agent code ownership to a verified release archive",
        &|p| {
            p.add_option(&["--archive"], true, Help::None, true, Arg::None);
            p.add_option(&["--sha256"], true, Help::None, false, Arg::None);
            p.add_flag(&["--json"], Help::None);
        },
    );
    if extra.contains(&"verify-release") {
        let prog = parser.sub_prog("verify-release");
        commands.push(SubCommand {
            name: "verify-release".into(),
            help: Some("verify a release manifest or a pinned artifact offline".into()),
            parser: crate::verify_release::parser(&prog),
        });
    }
    parser.add_subparsers("command", true, commands);
    parser
}

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// The hidden `--root` (default `/`).
    pub root: PathBuf,
    pub command: Command,
}

/// The subcommand and its options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Wizard { lang: Option<String>, config_output: PathBuf, json: bool },
    Plan { config: PathBuf, json: bool },
    Install { config: PathBuf, accept_plan: String, json: bool },
    Status { json: bool },
    Resume { json: bool },
    Repair { json: bool },
    Report { config: PathBuf, output: PathBuf, json: bool },
    Uninstall { purge_data: bool, json: bool },
    ReconcilePanelUpdate { archive: PathBuf, sha256: String, json: bool },
    VerifyRelease(crate::verify_release::Request),
}

/// Parses `argv` (without the program name) for the binary: `Err` carries what argparse would
/// print and the exit status (help 0, usage error 2).
pub fn parse(argv: &[String], width: usize) -> Result<Args, Exit> {
    parse_with(&installer_parser(), argv, width)
}

/// [`parse`] against a given parser (tests use [`python_parser`]).
pub fn parse_with(parser: &Parser, argv: &[String], width: usize) -> Result<Args, Exit> {
    let namespace = parser.parse_args(argv, width)?;
    Ok(Args { root: PathBuf::from(text(&namespace, "root")), command: command(&namespace) })
}

fn text(namespace: &Namespace, key: &str) -> String {
    match namespace.get(key) {
        Some(Arg::Str(value)) => value.clone(),
        _ => String::new(),
    }
}

fn optional(namespace: &Namespace, key: &str) -> Option<String> {
    match namespace.get(key) {
        Some(Arg::Str(value)) => Some(value.clone()),
        _ => None,
    }
}

fn flag(namespace: &Namespace, key: &str) -> bool {
    namespace.get(key) == Some(&Arg::Bool(true))
}

fn command(ns: &Namespace) -> Command {
    let path = |key: &str| PathBuf::from(text(ns, key));
    let json = flag(ns, "json");
    match text(ns, "command").as_str() {
        "wizard" => Command::Wizard { lang: optional(ns, "lang"), config_output: path("config_output"), json },
        "plan" => Command::Plan { config: path("config"), json },
        "install" => Command::Install { config: path("config"), accept_plan: text(ns, "accept_plan"), json },
        "status" => Command::Status { json },
        "resume" => Command::Resume { json },
        "repair" => Command::Repair { json },
        "report" => Command::Report { config: path("config"), output: path("output"), json },
        "uninstall" => Command::Uninstall { purge_data: flag(ns, "purge_data"), json },
        "reconcile-panel-update" => {
            Command::ReconcilePanelUpdate { archive: path("archive"), sha256: text(ns, "sha256"), json }
        }
        _ => Command::VerifyRelease(crate::verify_release::request(ns)),
    }
}

/// `str(exc) or type(exc).__name__`.
pub fn blocked_message(message: &str, class_name: &str) -> String {
    if message.is_empty() {
        class_name.to_string()
    } else {
        message.to_string()
    }
}

/// `_bounded_text`: NUL removed, whitespace collapsed (Python's `split()`), secret assignments
/// redacted, at most 500 code points.
pub fn bounded_text(value: &str) -> String {
    let normalized = split_whitespace(&value.replace('\0', "")).join(" ");
    redact(&normalized).chars().take(500).collect()
}

/// The stderr line of a refused operation (exit 2).
pub fn blocked_line(message: &str) -> String {
    format!("BLOCKED: {}\n", bounded_text(message))
}

/// `[0-9a-f]{64}\Z` (full match).
pub fn is_full_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `install --accept-plan`: the complete digest, compared in constant time.
pub fn check_accepted_digest(accepted: &str, digest: &str) -> Result<(), CliError> {
    if !is_full_digest(accepted) {
        return Err(CliError("--accept-plan requires the complete plan digest".into()));
    }
    if !pc_host::constant_time_eq(accepted.as_bytes(), digest.as_bytes()) {
        return Err(CliError("accepted plan digest does not match".into()));
    }
    Ok(())
}

/// The wizard's confirmation: exactly the first 12 lowercase hex characters of the digest.
pub fn confirmation_matches(confirmation: &str, digest: &str) -> bool {
    confirmation.len() == 12
        && confirmation.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && pc_host::constant_time_eq(confirmation.as_bytes(), &digest.as_bytes()[..12.min(digest.len())])
}

/// `_validate_plan`: the plan is for this configuration and the host has not changed.
pub fn validate_plan(config: &InstallerConfig, facts: &AuditFacts, plan: &InstallPlan) -> Result<(), CliError> {
    if plan.config != config.canonical_dict() {
        return Err(CliError("planner returned a plan for a different configuration".into()));
    }
    plan.assert_fresh(facts).map_err(CliError::from)
}

/// `plan --json`: the canonical plan plus `digest`, indent 2, sorted, raw UTF-8, newline.
pub fn render_plan_json(plan: &InstallPlan) -> String {
    let mut payload = plan.canonical_value();
    payload.as_object_mut().expect("a plan is an object").insert("digest".into(), json!(plan.digest()));
    pc_host::json::pretty2(&payload)
}

/// `plan` (text): the digest, then each action with its mutations.
pub fn render_plan_text(plan: &InstallPlan) -> String {
    let mut out = format!("plan_digest: {}\n", plan.digest());
    for action in &plan.actions {
        out.push_str(&format!("{}: {}\n", action.id, action.mutations.join(", ")));
    }
    out
}

/// The wizard's plan summary, one `io.write` line each.
pub fn plan_summary_lines(plan: &InstallPlan) -> Vec<String> {
    let mut lines = vec!["Plan / План".to_string(), format!("digest | {}", plan.digest())];
    for action in &plan.actions {
        lines.push(format!("{} | {}", action.id, action.mutations.join(", ")));
        lines.push(format!("rollback:{} | {}", action.id, action.inverse.join(", ")));
    }
    lines
}

/// One checkpoint as `status` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointView {
    pub action_id: String,
    pub adapter: String,
    pub phase: String,
    /// `evidence` is a mapping whose `success` is exactly `true`.
    pub success: bool,
}

/// What `status` shows of a transaction (`_sanitized_status`): never the transaction id, the
/// accepted digest, legacy payloads, `purge_data` or the rollback target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusView {
    pub schema: i64,
    pub status: String,
    pub plan_digest: String,
    pub origin: String,
    pub error: Option<String>,
    pub checkpoints: Vec<CheckpointView>,
}

impl StatusView {
    /// From a journal `state.json` document (the fields `status` reads).
    pub fn from_state(state: &Value) -> Option<StatusView> {
        let text = |key: &str| state.get(key).and_then(Value::as_str).map(str::to_string);
        let checkpoints = state
            .get("checkpoints")?
            .as_array()?
            .iter()
            .map(|checkpoint| {
                Some(CheckpointView {
                    action_id: checkpoint.get("action_id")?.as_str()?.to_string(),
                    adapter: checkpoint.get("adapter")?.as_str()?.to_string(),
                    phase: checkpoint.get("phase")?.as_str()?.to_string(),
                    success: checkpoint.get("evidence").and_then(|e| e.get("success")) == Some(&Value::Bool(true)),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(StatusView {
            schema: state.get("schema")?.as_i64()?,
            status: text("status")?,
            plan_digest: text("plan_digest")?,
            origin: text("origin")?,
            error: text("error"),
            checkpoints,
        })
    }

    /// The sanitized payload (`error` bounded and redacted).
    pub fn payload(&self) -> Value {
        let checkpoints: Vec<Value> = self
            .checkpoints
            .iter()
            .map(|c| json!({"action_id": c.action_id, "adapter": c.adapter, "phase": c.phase, "success": c.success}))
            .collect();
        let mut payload = json!({
            "checkpoints": checkpoints,
            "origin": self.origin,
            "plan_digest": self.plan_digest,
            "schema": self.schema,
            "status": self.status,
        });
        if let Some(error) = &self.error {
            payload.as_object_mut().expect("object").insert("error".into(), json!(bounded_text(error)));
        }
        payload
    }

    /// `_write_status`: JSON (indent 2, sorted, raw UTF-8) or the three or four text lines.
    pub fn render(&self, json_output: bool) -> String {
        let payload = self.payload();
        if json_output {
            return pc_host::json::pretty2(&payload);
        }
        let mut out = format!(
            "status: {}\nplan_digest: {}\norigin: {}\n",
            payload["status"].as_str().unwrap_or_default(),
            payload["plan_digest"].as_str().unwrap_or_default(),
            payload["origin"].as_str().unwrap_or_default()
        );
        if let Some(error) = payload.get("error").and_then(Value::as_str) {
            out.push_str(&format!("error: {error}\n"));
        }
        out
    }
}

/// `report` output: `{"report": "<path>"}` (default separators, ASCII) or the sentence.
pub fn render_report_written(path: &Path, json_output: bool) -> String {
    let shown = crate::pystr::py_path_str(&path.to_string_lossy());
    if json_output {
        let options = pc_common::json::Options {
            indent: None,
            separators: None,
            sort_keys: true,
            ensure_ascii: true,
            numbers: pc_common::json::NumberMode::Python(pc_common::json::FloatMode::Python),
        };
        format!("{}\n", pc_common::json::dumps(&json!({"report": shown}), &options))
    } else {
        format!("Wrote the public acceptance report to {shown}\n")
    }
}

/// `_installed_version(root)`: the version of a Proxy Control already on this host (`""` when
/// unknown), or `None` on a clean one.
pub fn installed_version(root: &Path) -> Option<String> {
    let path = root.join(INSTALLED_VERSION);
    if path.is_file() {
        return Some(match std::fs::read(&path) {
            Ok(data) => match crate::pystr::decode_utf8(&data) {
                Ok(text) => crate::pystr::strip(&crate::pystr::universal_newlines(&text)).chars().take(32).collect(),
                Err(_) => String::new(),
            },
            Err(_) => String::new(),
        });
    }
    root.join(OWNERSHIP_JOURNAL).is_file().then(String::new)
}

/// `reconcile-panel-update --sha256`: 64 lowercase hex, and the archive bytes must match.
pub fn check_archive_digest(sha256: &str, payload: &[u8]) -> Result<(), CliError> {
    if !is_full_digest(sha256) {
        return Err(CliError("release archive SHA-256 must be 64 lowercase hex digits".into()));
    }
    if pc_host::fs::sha256_hex(payload) != sha256 {
        return Err(CliError("release archive SHA-256 mismatch".into()));
    }
    Ok(())
}

/// `release_identity(tree)`: the plan identity stamped into a release tree.
pub fn release_identity(tree: &Path) -> Result<crate::planner::ReleaseIdentity, CliError> {
    let identity = pc_host::archive::ReleaseIdentity::read(tree).map_err(|err| CliError(err.to_string()))?;
    crate::planner::ReleaseIdentity::from_tree(&identity).map_err(CliError::from)
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
