//! The `proxy-control-installer` command line (`installer/cli.py:199-635`): parse with
//! [`installer_core::cli::parse`], then dispatch to the configuration, the planner, the
//! transaction engine and the report writer.
//!
//! | Command | What runs |
//! |---|---|
//! | `plan`, `install` | `load_config` → audit → AmneziaWG ports → [`compose_plan`] over the registry → `_validate_plan`; `install` then checks `--accept-plan`, stages the operator credentials and runs [`TransactionEngine::apply`] |
//! | `status` | the journal's sanitized status (or the unimported runtime-v2 summary) |
//! | `report` | the public acceptance report (+ the root-only MCP handoff) from the journal's evidence |
//! | `resume`, `repair`, `uninstall` | the engine |
//! | `reconcile-panel-update` | the panel archive's ownership handoff ([`PanelOwnershipHandoff`], legacy mode) |
//! | `ingress-upgrade` | the bounded pre-client-IP Nginx migration ([`crate::ingress_upgrade`]) |
//! | `verify-release` | [`installer_core::verify_release`] |
//! | `wizard` | the translated terminal wizard, real audit/plan, digest confirmation and credentialed apply |
//!
//! Every refusal prints `BLOCKED: <bounded, redacted message>` on stderr with exit 2. A fatal
//! stop (an interrupt, an unconfirmed process kill: Python's `BaseException`) prints its
//! message with exit 130 (interrupt) or 1 and leaves the journal for `resume`.
//!
//! [`Services::system`] uses the real read-only audit. Adapter availability is determined by the
//! packages registered in [`crate::adapters::registry`].

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use installer_core::argparse::{Arg, Help, Parser, SubCommand};
use installer_core::audit::{
    audit_host, AuditError, CommandRunner as AuditCommandRunner, SystemExecutor, SystemResolver,
};
use installer_core::awg_ports::resolve_awg_ports;
use installer_core::cli::{
    blocked_line, blocked_message, bounded_text, check_accepted_digest, check_archive_digest, is_full_digest,
    release_identity, render_plan_json, render_plan_text, render_report_written, validate_plan, Args, CliError,
    Command, StatusView,
};
use installer_core::config::load_config;
use installer_core::credentials::{discard_staged_credentials, stage_credentials};
use installer_core::i18n::{environment_locale_value, parse_locale, Locale};
use installer_core::model::InstallerConfig;
use installer_core::planner::{adapters_for, AuditFacts, Evidence, InstallPlan};
use installer_core::report::{
    evidence_from_checkpoint, operator_notes, AcceptanceReport, CredentialHandoff, ReportWriter,
};
use installer_core::wizard::{
    pinned_version, run_wizard_command, EngineError as WizardEngineError, TerminalIO, WizardCommand, WizardEngine,
};
use pc_host::archive::{PanelArchive, PANEL_SYNC, PROJECT_DIR};
use pc_host::runner::{HostRunner, SystemRunner, QUERY_TIMEOUT};
use pc_host::TxError;
use serde_json::Value;

use crate::adapter::{compose_plan, Adapter};
use crate::adapters::{self, AdapterContext};
use crate::engine::{read_matching_plan, TransactionEngine};
use crate::error::Error;
use crate::handoff::PanelOwnershipHandoff;
use crate::journal::TransactionState;
use crate::store::TransactionStore;

/// `_LEGACY_STATE`: the runtime-v2 (`scripts/proxyctl.py`) journal.
const LEGACY_STATE: &str = "var/lib/proxy-control/runtime.json";

/// The audit: `None` asks for preliminary facts before the wizard starts.
pub type Audit = Box<dyn Fn(Option<&InstallerConfig>) -> Result<AuditFacts, Error>>;
/// The MCP report handoff (`adapters.mcp.mcp_handoff`).
pub type McpHandoff = Box<dyn Fn(&AdapterContext, &InstallerConfig) -> Result<BTreeMap<String, String>, Error>>;

/// The composition boundary of every command (`CliServices`): tests build their own.
pub struct Services {
    pub context: AdapterContext,
    /// The engine with every registered adapter.
    pub engine: TransactionEngine,
    pub audit: Audit,
    pub mcp_handoff: McpHandoff,
}

impl Services {
    /// Production services for `--root`: the system runner, the release tree of this binary,
    /// the engine with the whole adapter registry.
    pub fn system(root: &Path) -> Result<Services, Error> {
        let context = AdapterContext { root: root.to_path_buf(), tree: release_tree(), runner: Arc::new(SystemRunner) };
        Services::with_context(context, Box::new(system_audit), Box::new(adapters::mcp_handoff))
    }

    /// Services over `context` with every adapter of [`adapters::registry`] registered.
    pub fn with_context(context: AdapterContext, audit: Audit, mcp_handoff: McpHandoff) -> Result<Services, Error> {
        let mut engine = TransactionEngine::new(TransactionStore::new(&context.root)?);
        for adapter in adapters::registry(&context) {
            engine.register(adapter);
        }
        Ok(Services { context, engine, audit, mcp_handoff })
    }

    fn store(&self) -> &TransactionStore {
        self.engine.store()
    }

    fn root(&self) -> &Path {
        &self.context.root
    }
}

/// The real read-only audit; the wizard's preliminary facts are empty, as in Python.
fn system_audit(config: Option<&InstallerConfig>) -> Result<AuditFacts, Error> {
    let Some(config) = config else { return Ok(AuditFacts::default()) };
    let executor = SystemExecutor;
    let resolver = SystemResolver;
    let runner = AuditCommandRunner::new(&executor, &resolver);
    audit_host(config, &runner).map(|audit| audit.facts).map_err(|err| match err {
        AuditError::Interrupted => Error::fatal("KeyboardInterrupt", "command interrupted"),
        other => Error::other(other.python_class_name(), other.message()),
    })
}

/// The release tree of the running binary: `<tree>/installer/bin/linux-amd64/<binary>`.
pub fn release_tree() -> PathBuf {
    std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .ok()
        .and_then(|path| path.ancestors().nth(4).map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Why a command stopped.
#[derive(Debug)]
enum Failure {
    /// `BLOCKED: <message>`, exit 2.
    Blocked(String),
    /// A `BaseException`: the message, exit 130 for an interrupt, else 1.
    Fatal { class: String, message: String },
}

impl From<Error> for Failure {
    fn from(err: Error) -> Self {
        if err.is_fatal() {
            return Failure::Fatal { class: err.python_class_name().to_string(), message: err.message() };
        }
        Failure::Blocked(blocked_message(&err.message(), err.python_class_name()))
    }
}

impl From<TxError> for Failure {
    fn from(err: TxError) -> Self {
        Error::Tx(err).into()
    }
}

impl From<CliError> for Failure {
    fn from(err: CliError) -> Self {
        Failure::Blocked(err.0)
    }
}

impl From<installer_core::config::ConfigError> for Failure {
    fn from(err: installer_core::config::ConfigError) -> Self {
        Failure::Blocked(err.0)
    }
}

impl From<installer_core::planner::PlanError> for Failure {
    fn from(err: installer_core::planner::PlanError) -> Self {
        Error::Plan(err).into()
    }
}

impl From<installer_core::credentials::CredentialError> for Failure {
    fn from(err: installer_core::credentials::CredentialError) -> Self {
        Failure::Blocked(err.0)
    }
}

impl From<installer_core::report::ReportError> for Failure {
    fn from(err: installer_core::report::ReportError) -> Self {
        Failure::Blocked(err.0)
    }
}

impl From<installer_core::report::WriteError> for Failure {
    fn from(err: installer_core::report::WriteError) -> Self {
        Failure::Blocked(err.to_string())
    }
}

type Outcome = Result<String, Failure>;

/// `main()`: the process arguments, the system services, the real streams.
pub fn main() -> i32 {
    let _ = pc_host::runner::install_interrupt_handler();
    let arguments: Vec<String> =
        std::env::args_os().skip(1).map(|argument| argument.to_string_lossy().into_owned()).collect();
    let (mut stdout, mut stderr) = (std::io::stdout().lock(), std::io::stderr().lock());
    run(&arguments, &|root| Services::system(root), &mut stdout, &mut stderr)
}

struct IngressRequest {
    root: PathBuf,
    project: PathBuf,
    apply: bool,
}

/// `ingress_upgrade.py`'s separate module CLI, kept as a binary subcommand without widening the
/// frozen `installer_core::Command` enum. The hidden `--root` is the installer test/recovery seam.
fn parse_ingress(arguments: &[String], width: usize) -> Option<Result<IngressRequest, installer_core::argparse::Exit>> {
    if !arguments.iter().any(|argument| argument == "ingress-upgrade") {
        return None;
    }
    let mut parser = Parser::new(
        installer_core::cli::PROG,
        Some("Bounded host migration for the installer's pre-client-IP Nginx templates.\n\nThe foreign coexist frontend is never edited. Run without --apply to inspect the\nplan; the one-command host updater applies this after its panel update succeeds."),
    );
    parser.add_option(&["--root"], false, Help::Suppress, true, Arg::Str("/".into()));
    let mut sub = Parser::new(&parser.sub_prog("ingress-upgrade"), None);
    sub.add_option(&["--project-dir"], false, Help::None, true, Arg::Str("/opt/mtproxy-shared443".into()));
    sub.add_flag(&["--apply"], Help::None);
    parser.add_subparsers(
        "command",
        true,
        vec![SubCommand { name: "ingress-upgrade".into(), help: None, parser: sub }],
    );
    Some(parser.parse_args(arguments, width).map(|namespace| {
        let text = |key: &str| match namespace.get(key) {
            Some(Arg::Str(value)) => value.clone(),
            _ => String::new(),
        };
        IngressRequest {
            root: PathBuf::from(text("root")),
            project: PathBuf::from(text("project_dir")),
            apply: namespace.get("apply") == Some(&Arg::Bool(true)),
        }
    }))
}

fn run_ingress(
    request: IngressRequest,
    compose: &dyn Fn(&Path) -> Result<Services, Error>,
    stdout: &mut dyn Write,
) -> i32 {
    let result = if request.apply && unsafe { libc::geteuid() } != 0 {
        Err(crate::ingress_upgrade::UpgradeError::new("applying ingress changes requires root"))
    } else {
        compose(&request.root).map_err(|error| crate::ingress_upgrade::UpgradeError::new(error.message())).and_then(
            |services| {
                crate::ingress_upgrade::upgrade(
                    &request.project,
                    &request.root,
                    request.apply,
                    services.context.runner.as_ref(),
                )
            },
        )
    };
    let (status, line) = match result {
        Ok(outcome) => (0, outcome.json()),
        Err(error) => (1, crate::ingress_upgrade::failed_json(&error.to_string())),
    };
    let _ = stdout.write_all(line.as_bytes());
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
    status
}

/// `run(argv, services=…)`: parses `arguments` (without the program name), composes the
/// services for `--root` and runs the command; returns the exit status.
pub fn run(
    arguments: &[String],
    compose: &dyn Fn(&Path) -> Result<Services, Error>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if let Some(status) = crate::proxy_helpers::cli(arguments, stdout, stderr) {
        return status;
    }
    if let Some(result) = crate::vpn_helpers::dispatch(arguments, &release_tree()) {
        return match result {
            Ok(text) => {
                let _ = stdout.write_all(text.as_bytes());
                0
            }
            Err(message) => {
                let _ = writeln!(stderr, "BLOCKED: {message}");
                2
            }
        };
    }
    if let Some(request) = parse_ingress(arguments, installer_core::argparse::terminal_width()) {
        return match request {
            Ok(request) => run_ingress(request, compose, stdout),
            Err(exit) => {
                let _ = stdout.write_all(exit.stdout.as_bytes());
                let _ = stderr.write_all(exit.stderr.as_bytes());
                exit.status
            }
        };
    }
    let args = match installer_core::cli::parse(arguments, installer_core::argparse::terminal_width()) {
        Ok(args) => args,
        Err(exit) => {
            let _ = stdout.write_all(exit.stdout.as_bytes());
            let _ = stderr.write_all(exit.stderr.as_bytes());
            return exit.status;
        }
    };
    if let Command::VerifyRelease(request) = &args.command {
        let (status, out, err) = installer_core::verify_release::run(request);
        let _ = stdout.write_all(out.as_bytes());
        let _ = stderr.write_all(err.as_bytes());
        return status;
    }
    if matches!(&args.command, Command::Wizard { .. }) {
        return match compose(&args.root).map_err(Failure::from) {
            Ok(services) => wizard(&args, &services, stdout, stderr),
            Err(failure) => finish(Err(failure), stdout, stderr),
        };
    }
    let outcome = compose(&args.root).map_err(Failure::from).and_then(|services| dispatch(&args, &services));
    finish(outcome, stdout, stderr)
}

fn finish(outcome: Outcome, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match outcome {
        Ok(text) => {
            let _ = stdout.write_all(text.as_bytes());
            let _ = stdout.flush();
            0
        }
        Err(Failure::Blocked(message)) => {
            let _ = stderr.write_all(blocked_line(&message).as_bytes());
            let _ = stderr.flush();
            2
        }
        Err(Failure::Fatal { class, message }) => {
            let _ = writeln!(stderr, "{}", bounded_text(&blocked_message(&message, &class)));
            if class == "KeyboardInterrupt" {
                130
            } else {
                1
            }
        }
    }
}

struct CliWizardEngine<'a> {
    services: &'a Services,
}

fn wizard_error(err: Error) -> WizardEngineError {
    if err.is_fatal() {
        if err.python_class_name() == "KeyboardInterrupt" {
            WizardEngineError::Interrupted
        } else {
            WizardEngineError::Fatal { class: err.python_class_name().into(), message: err.message() }
        }
    } else {
        WizardEngineError::Blocked(blocked_message(&err.message(), err.python_class_name()))
    }
}

impl WizardEngine for CliWizardEngine<'_> {
    fn initial_facts(&mut self) -> Result<AuditFacts, WizardEngineError> {
        (self.services.audit)(None).map_err(wizard_error)
    }

    fn plan(&mut self, config: &InstallerConfig) -> Result<InstallPlan, WizardEngineError> {
        let facts = (self.services.audit)(Some(config)).map_err(wizard_error)?;
        let resolved = resolve_awg_ports(config, self.services.root(), Some(&facts.listeners), None)
            .map_err(|err| WizardEngineError::Blocked(err.0))?;
        let plan = plan(&resolved, &facts, self.services).map_err(wizard_error)?;
        validate_plan(&resolved, &facts, &plan).map_err(|err| WizardEngineError::Blocked(err.0))?;
        Ok(plan)
    }

    fn apply(&mut self, plan: &InstallPlan) -> Result<StatusView, WizardEngineError> {
        let state = self.services.engine.apply(plan, &plan.digest()).map_err(wizard_error)?;
        StatusView::from_state(&state.to_value())
            .ok_or_else(|| WizardEngineError::Blocked("transaction state is invalid".into()))
    }
}

fn wizard(args: &Args, services: &Services, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let Command::Wizard { lang, config_output, json } = &args.command else { unreachable!("wizard only") };
    let lang = lang.as_deref().and_then(|value| parse_locale(Some(value), Locale::En).ok());
    let command = WizardCommand {
        root: args.root.clone(),
        lang,
        config_output: config_output.clone(),
        json: *json,
        environment_locale: environment_locale_value(),
        xray_version: pinned_version(&services.context.tree, "xray"),
    };
    let mut engine = CliWizardEngine { services };
    let mut io = TerminalIO::new(std::io::stdin().lock(), stdout).with_echo_fd(0);
    run_wizard_command(&mut io, stderr, &command, &mut engine)
}

fn dispatch(args: &Args, services: &Services) -> Outcome {
    match &args.command {
        Command::Wizard { .. } => unreachable!("handled with the terminal streams"),
        Command::Plan { config, json } => {
            let (_config, plan) = plan_from_path(config, services)?;
            Ok(if *json { render_plan_json(&plan) } else { render_plan_text(&plan) })
        }
        Command::Install { config, accept_plan, json } => {
            let (_config, plan) = plan_from_path(config, services)?;
            check_accepted_digest(accept_plan, &plan.digest())?;
            stage_credentials(services.root(), config)?;
            let applied = services.engine.apply(&plan, accept_plan);
            discard_staged_credentials(services.root())?;
            status_text(&applied?, *json)
        }
        Command::Report { config, output, json } => write_reports(config, output, *json, services),
        Command::Status { json } => Ok(read_status(services)?.render(*json)),
        Command::ReconcilePanelUpdate { archive, sha256, json } => {
            status_text(&reconcile_panel_update(archive, sha256, services)?, *json)
        }
        Command::Resume { json } | Command::Repair { json } | Command::Uninstall { json, .. } => {
            refuse_unimported_legacy(services)?;
            let state = match &args.command {
                Command::Resume { .. } => services.engine.resume(),
                Command::Repair { .. } => services.engine.repair(),
                Command::Uninstall { purge_data, .. } => services.engine.uninstall(*purge_data),
                _ => unreachable!("matched above"),
            }?;
            status_text(&state, *json)
        }
        Command::VerifyRelease(_) => unreachable!("handled before the services are composed"),
    }
}

/// `_write_status`.
fn status_text(state: &TransactionState, json: bool) -> Outcome {
    let view = StatusView::from_state(&state.to_value())
        .ok_or_else(|| Failure::Blocked("transaction state is invalid".into()))?;
    Ok(view.render(json))
}

/// `_plan_from_path`: the configuration, audited, with its AmneziaWG ports resolved, planned
/// and checked.
fn plan_from_path(path: &Path, services: &Services) -> Result<(InstallerConfig, InstallPlan), Failure> {
    let config = load_config(path)?;
    let facts = (services.audit)(Some(&config))?;
    let config = resolve_awg_ports(&config, services.root(), Some(&facts.listeners), None)?;
    let plan = plan(&config, &facts, services)?;
    validate_plan(&config, &facts, &plan)?;
    Ok((config, plan))
}

/// `CliServices.plan`: `adapters_for(config)` from the registry, then `build_plan` with the
/// tree's release identity.
pub fn plan(config: &InstallerConfig, facts: &AuditFacts, services: &Services) -> Result<InstallPlan, Error> {
    let adapters: Vec<Arc<dyn Adapter>> = adapters_for(config)?
        .into_iter()
        .map(|name| {
            services
                .engine
                .adapter_named(name)
                .ok_or_else(|| crate::error::transaction(format!("adapter is unavailable: {name}")).into())
        })
        .collect::<Result<_, Error>>()?;
    let release = release_identity(&services.context.tree).map_err(|err| Error::other("CliError", err.0))?;
    compose_plan(config, facts, &adapters, &release)
}

/// `_write_reports`: only named evidence from the durable journal; the release tag is the
/// plan's (Python wrote the journal origin, §12 #2).
fn write_reports(config_path: &Path, output: &Path, json: bool, services: &Services) -> Outcome {
    let config = resolve_awg_ports(&load_config(config_path)?, services.root(), None, None)?;
    let view = read_status(services)?;
    if view.status != "active" {
        return Err(CliError("a report requires a completed installation".into()).into());
    }
    let state = services.store().read_state()?;
    let plan = read_matching_plan(services.store(), &state)?;
    let mut evidence: Vec<Evidence> = Vec::new();
    for checkpoint in &state.checkpoints {
        let recorded = checkpoint.evidence.clone().map(Value::Object).unwrap_or(Value::Null);
        if let Some(item) = evidence_from_checkpoint(&checkpoint.action_id, &recorded)? {
            evidence.push(item);
        }
    }
    let report = AcceptanceReport::from_evidence(
        config.profile.value(),
        &plan.release.tag,
        &state.plan_digest,
        &evidence,
        operator_notes(&config),
    );
    let writer = ReportWriter::new(output);
    let public = writer.write_public(&report)?;
    if config.domains.mcp.is_some() {
        let entries = (services.mcp_handoff)(&services.context, &config)
            .map_err(|err| CliError(format!("the MCP handoff cannot be written: {}", err.message())))?;
        writer.write_credentials(&CredentialHandoff::new(entries)?)?;
    }
    Ok(render_report_written(&public, json))
}

/// `_read_status`: the journal, else the summary of an unimported runtime-v2 installation,
/// else `no installer transaction exists`.
fn read_status(services: &Services) -> Result<StatusView, Failure> {
    match services.store().read_state() {
        Ok(state) => StatusView::from_state(&state.to_value())
            .ok_or_else(|| Failure::Blocked("transaction state is invalid".into())),
        Err(_) => {
            let Some(legacy) = read_legacy(services.root())? else {
                return Err(CliError("no installer transaction exists".into()).into());
            };
            let digest = legacy
                .get("plan_digest")
                .and_then(Value::as_str)
                .filter(|digest| is_full_digest(digest))
                .map_or_else(|| "0".repeat(64), str::to_string);
            const KNOWN: [&str; 7] =
                ["active", "applying", "rolling_back", "rollback_failed", "rolled_back", "uninstalling", "uninstalled"];
            let status = legacy
                .get("status")
                .and_then(Value::as_str)
                .filter(|status| KNOWN.contains(status))
                .unwrap_or("rollback_failed");
            Ok(StatusView {
                schema: crate::journal::TRANSACTION_SCHEMA,
                status: status.into(),
                plan_digest: digest,
                origin: "runtime-v2-unimported".into(),
                error: Some("legacy transaction requires import".into()),
                checkpoints: Vec::new(),
            })
        }
    }
}

/// `_adopt_legacy_if_needed`, without the import (runtime-v2 is not ported, owner decision 10):
/// a host with only a runtime-v2 journal is refused before the engine runs.
fn refuse_unimported_legacy(services: &Services) -> Result<(), Failure> {
    if services.store().read_state().is_ok() {
        return Ok(());
    }
    match read_legacy(services.root())? {
        None => Ok(()),
        Some(_) => {
            Err(CliError("this host has a legacy runtime-v2 installation, which this installer cannot import".into())
                .into())
        }
    }
}

/// `_read_legacy`.
fn read_legacy(root: &Path) -> Result<Option<serde_json::Map<String, Value>>, Failure> {
    let path = root.join(LEGACY_STATE);
    if !path.is_file() {
        return Ok(None);
    }
    let unreadable = || CliError("legacy runtime state is unreadable".into());
    let data = std::fs::read(&path).map_err(|_| unreadable())?;
    match pc_host::json::loads(&data).map_err(|_| unreadable())? {
        Value::Object(map) => Ok(Some(map)),
        _ => Err(CliError("legacy runtime state is invalid".into()).into()),
    }
}

/// `docker exec proxy-control-panel cat /app/VERSION`.
fn running_panel_version(runner: &dyn HostRunner) -> Result<String, CliError> {
    runner
        .capture_checked(&["docker", "exec", "proxy-control-panel", "cat", "/app/VERSION"], QUERY_TIMEOUT)
        .map(|text| installer_core::pystr::strip(&text).to_string())
        .map_err(|_| CliError("running panel version could not be verified".into()))
}

/// `[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.]+)?` (full match).
fn is_release_version(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    for part in 0..3 {
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return false;
        }
        if part < 2 {
            if bytes.get(index) != Some(&b'.') {
                return false;
            }
            index += 1;
        }
    }
    match &bytes[index..] {
        [] => true,
        [b'-' | b'.', tail @ ..] => !tail.is_empty() && tail.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'.'),
        _ => false,
    }
}

/// `[0-9a-f]{40}` (full match).
fn is_commit(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A private temporary directory removed on drop (`tempfile.TemporaryDirectory`).
struct Scratch(PathBuf);

impl Scratch {
    fn new(prefix: &str) -> std::io::Result<Scratch> {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("{prefix}{}", pc_host::fs::token_hex::<8>()));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Scratch(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `_reconcile_panel_update`: verify a release archive the running panel was built from, then
/// rebase Core's and the version-agent's code ownership onto it (legacy handoff).
fn reconcile_panel_update(archive: &Path, sha256: &str, services: &Services) -> Result<TransactionState, Failure> {
    if !is_full_digest(sha256) {
        return Err(CliError("release archive SHA-256 must be 64 lowercase hex digits".into()).into());
    }
    let payload = std::fs::read(archive).map_err(|_| CliError("release archive is unreadable".into()))?;
    check_archive_digest(sha256, &payload)?;
    let store = services.store();
    let _lock = store.locked()?;
    let scratch = Scratch::new("panel-reconcile-").map_err(Error::from)?;
    let staged = scratch.0.join("tree");
    PanelArchive::open(&payload)
        .and_then(|mut archive| archive.extract_to(&staged))
        .map_err(|_| CliError("release archive is unsafe or unreadable".into()))?;
    let missing = || CliError("release archive identity is missing".into());
    let version = std::fs::read(staged.join("VERSION")).map_err(|_| missing())?;
    let version = installer_core::pystr::strip(std::str::from_utf8(&version).map_err(|_| missing())?).to_string();
    let identity = std::fs::read(staged.join("release/release.json")).map_err(|_| missing())?;
    let identity = pc_host::json::loads(&identity).map_err(|_| missing())?;
    let field = |key: &str| identity.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
    let matches = is_release_version(&version)
        && identity.get("version").and_then(Value::as_str) == Some(version.as_str())
        && identity.get("tag").and_then(Value::as_str) == Some(format!("v{version}").as_str())
        && is_commit(&field("commit"))
        && is_full_digest(&field("manifest_sha256"))
        && running_panel_version(services.context.runner.as_ref())? == version;
    if !matches {
        return Err(CliError("archive identity does not match the running panel".into()).into());
    }
    let project = pc_host::fs::root_path(services.root(), PROJECT_DIR)?;
    let names: Vec<&str> = PANEL_SYNC.iter().copied().filter(|name| staged.join(name).exists()).collect();
    let mut handoff = PanelOwnershipHandoff::new(store, &project, &staged, &names, true, None)?;
    handoff.prepare()?;
    handoff.commit()?;
    Ok(store.read_state()?)
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
