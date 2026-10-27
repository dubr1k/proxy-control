//! Host command execution: the three contracts of the Python installer (host inventory C1.1)
//! behind one trait, with the real implementation ([`SystemRunner`]) and a recording fake
//! ([`RecordingRunner`]).
//!
//! | Contract | Python | Method |
//! |---|---|---|
//! | bounded audit command: text output, combined 1 MiB cap, deadline, process-group kill | `installer.audit.CommandRunner` (nginx 5 s, certificates 600 s, packages/WARP 900 s, firewall 30 s, `nginx -T` 30 s) | [`HostRunner::bounded`], [`bounded_capture`], [`bounded_json`] |
//! | mutating command: stdout discarded, stderr captured, 900 s, on timeout or interrupt kill the group and **prove from `/proc` that it is gone** before returning | `_DefaultCoreRunner.run` | [`HostRunner::run`] |
//! | diagnostics: never fails, failures **in band** as `exit=<rc> …` / `diagnostic unavailable: <Class>`, tail of the merged output | `_DefaultCoreRunner.capture` (+ MCP and version-agent overrides) | [`HostRunner::capture`], [`is_in_band_failure`] |
//! | checked stdout query (30 s, 64 Ki characters) | `_DefaultCoreRunner._capture_checked` | [`HostRunner::capture_checked`] |
//!
//! Every child starts in its own session (`start_new_session=True`), so a kill reaches its
//! whole process group and the operator's Ctrl-C does not.

mod fake;
mod system;

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;

pub use fake::{Call, CallKind, RecordingRunner, Reply};
pub use system::{wait_process_group_stopped, SystemRunner};

/// Limits of a bounded (audit-contract) command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounded {
    pub timeout: Duration,
    /// Combined stdout + stderr bytes.
    pub max_output: usize,
}

const MIB: usize = 1024 * 1024;

impl Bounded {
    /// `CommandRunner()`: the audit and the nginx adapter.
    pub const AUDIT: Bounded = Bounded { timeout: Duration::from_secs(5), max_output: MIB };
    /// The nginx adapter's default runner (`nginx.py:517`).
    pub const NGINX: Bounded = Bounded::AUDIT;
    /// Certificate issuance (`nginx.py:1722`).
    pub const CERTIFICATES: Bounded = Bounded { timeout: Duration::from_secs(600), max_output: MIB };
    /// Packages (`packages.py:47`).
    pub const PACKAGES: Bounded = Bounded { timeout: Duration::from_secs(900), max_output: MIB };
    /// Firewall (`firewall.py:76`).
    pub const FIREWALL: Bounded = Bounded { timeout: Duration::from_secs(30), max_output: MIB };
    /// WARP (`warp.py:39`).
    pub const WARP: Bounded = Bounded { timeout: Duration::from_secs(900), max_output: MIB };
    /// Core's `nginx -T` during acceptance (`core.py:581`).
    pub const NGINX_DUMP: Bounded = Bounded { timeout: Duration::from_secs(30), max_output: MIB };

    /// `CommandRunner(timeout=…, max_output=…)`: both must be positive.
    pub fn new(timeout: Duration, max_output: usize) -> Result<Bounded, BoundedError> {
        if timeout.is_zero() {
            return Err(BoundedError::InvalidLimits("timeout must be positive"));
        }
        if max_output == 0 {
            return Err(BoundedError::InvalidLimits("max_output must be positive"));
        }
        Ok(Bounded { timeout, max_output })
    }

    /// `run(argv, timeout=t)`: a per-call timeout can only shorten the runner's
    /// (`min(self.timeout, timeout)`); zero is `ValueError("timeout must be positive and finite")`.
    pub fn with_call_timeout(self, timeout: Option<Duration>) -> Result<Bounded, BoundedError> {
        match timeout {
            None => Ok(self),
            Some(t) if t.is_zero() => Err(BoundedError::InvalidTimeout),
            Some(t) => Ok(Bounded { timeout: self.timeout.min(t), ..self }),
        }
    }
}

/// A finished bounded command: text decoded as UTF-8 with replacement; the exit status is not
/// judged here (`CompletedProcess`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedOutput {
    /// Python's `returncode`: the exit code, or `-signal` when a signal ended the process.
    pub returncode: i32,
    pub stdout: String,
    pub stderr: String,
}

/// `AuditError` (and `CommandUnavailable`, `ValueError`) of the bounded runner; the messages are
/// the exact Python ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedError {
    /// `command argv must be a non-empty sequence` / `command argv contains an invalid argument`.
    InvalidArgv(&'static str),
    /// `ValueError`: `timeout must be positive` / `max_output must be positive`.
    InvalidLimits(&'static str),
    /// `ValueError("timeout must be positive and finite")`.
    InvalidTimeout,
    /// `CommandUnavailable("command is unavailable")`: the program does not exist.
    Unavailable,
    /// `command could not be executed`.
    CouldNotExecute,
    /// `command timed out` (the process group was killed).
    TimedOut,
    /// `command output limit exceeded` (the process group was killed).
    OutputLimit,
    /// The operator interrupted the installer; the group was killed (Python let
    /// `KeyboardInterrupt` through and left the child running).
    Interrupted,
    /// `command failed with exit status <rc>` ([`bounded_capture`]).
    Failed(i32),
    /// `command returned malformed JSON` ([`bounded_json`]).
    MalformedJson,
}

impl BoundedError {
    pub fn python_class_name(&self) -> &'static str {
        match self {
            BoundedError::Unavailable => "CommandUnavailable",
            BoundedError::InvalidLimits(_) | BoundedError::InvalidTimeout => "ValueError",
            BoundedError::Interrupted => "KeyboardInterrupt",
            _ => "AuditError",
        }
    }
}

impl fmt::Display for BoundedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundedError::InvalidArgv(message) | BoundedError::InvalidLimits(message) => f.write_str(message),
            BoundedError::InvalidTimeout => f.write_str("timeout must be positive and finite"),
            BoundedError::Unavailable => f.write_str("command is unavailable"),
            BoundedError::CouldNotExecute => f.write_str("command could not be executed"),
            BoundedError::TimedOut => f.write_str("command timed out"),
            BoundedError::OutputLimit => f.write_str("command output limit exceeded"),
            BoundedError::Interrupted => f.write_str("command interrupted"),
            BoundedError::Failed(code) => write!(f, "command failed with exit status {code}"),
            BoundedError::MalformedJson => f.write_str("command returned malformed JSON"),
        }
    }
}

impl std::error::Error for BoundedError {}

/// `_validated_argv`: a non-empty argv without NUL bytes.
pub fn validate_argv(argv: &[&str]) -> Result<(), BoundedError> {
    if argv.is_empty() {
        return Err(BoundedError::InvalidArgv("command argv must be a non-empty sequence"));
    }
    if argv.iter().any(|part| part.contains('\0')) {
        return Err(BoundedError::InvalidArgv("command argv contains an invalid argument"));
    }
    Ok(())
}

/// Options of a mutating (Core-contract) command.
#[derive(Debug, Clone)]
pub struct RunOptions<'a> {
    /// The file opened as stdin (`/dev/null` when absent).
    pub stdin_path: Option<PathBuf>,
    /// The **whole** environment of the child (`env=dict(env)`); `None` inherits the
    /// installer's.
    pub env: Option<Vec<(String, String)>>,
    /// `_DefaultCoreRunner(timeout=…)`; 900 s by default.
    pub timeout: Duration,
    /// The interrupt flag polled while the command runs; [`interrupt_flag`] by default.
    pub cancel: &'a AtomicBool,
}

/// The Core runner's default timeout.
pub const CORE_TIMEOUT: Duration = Duration::from_secs(900);

impl Default for RunOptions<'static> {
    fn default() -> Self {
        RunOptions { stdin_path: None, env: None, timeout: CORE_TIMEOUT, cancel: interrupt_flag() }
    }
}

/// A finished mutating command (`CompletedProcess(args, rc, None, stderr)`): stdout was never
/// captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub returncode: i32,
    pub stderr: Vec<u8>,
}

/// The message of the fatal stop when a killed process group could not be proven gone
/// (`SystemExit(…)` in Python). The engine must **not** roll back: the journal stays
/// `applying` for an operator.
pub const CLEANUP_UNCONFIRMED: &str = "command cleanup could not be confirmed; do not resume or repair until an operator verifies all command processes have stopped";

/// Why a mutating command did not finish normally.
#[derive(Debug)]
pub enum RunError {
    /// `stdin_path` could not be opened.
    Stdin(io::Error),
    /// The program could not be started (`FileNotFoundError`, `PermissionError`, …).
    Spawn(io::Error),
    /// The deadline passed (`subprocess.TimeoutExpired`); the group was killed and is gone.
    /// Carries the stderr captured until then.
    TimedOut { stderr: Vec<u8> },
    /// The interrupt flag was raised (`KeyboardInterrupt`); the group was killed and is gone.
    Interrupted { stderr: Vec<u8> },
    /// Reading the child's stderr failed; the group was killed and is gone.
    Io(io::Error),
    /// The kill could not be confirmed ([`CLEANUP_UNCONFIRMED`]); fatal, never roll back.
    CleanupUnconfirmed,
}

impl RunError {
    /// What Python raised: `TimeoutExpired`, `KeyboardInterrupt`, `SystemExit` or the
    /// `OSError` subclass.
    pub fn python_class_name(&self) -> &'static str {
        match self {
            RunError::Stdin(err) | RunError::Spawn(err) | RunError::Io(err) => crate::error::os_error_class(err),
            RunError::TimedOut { .. } => "TimeoutExpired",
            RunError::Interrupted { .. } => "KeyboardInterrupt",
            RunError::CleanupUnconfirmed => "SystemExit",
        }
    }

    /// Python's `BaseException` cases that must leave the journal for `resume` instead of
    /// rolling back: an interrupt and an unconfirmed cleanup.
    pub fn stops_the_engine(&self) -> bool {
        matches!(self, RunError::Interrupted { .. } | RunError::CleanupUnconfirmed)
    }

    /// stderr captured before a timeout or interrupt.
    pub fn stderr(&self) -> &[u8] {
        match self {
            RunError::TimedOut { stderr } | RunError::Interrupted { stderr } => stderr,
            _ => &[],
        }
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Stdin(err) | RunError::Spawn(err) | RunError::Io(err) => write!(f, "{err}"),
            RunError::TimedOut { .. } => f.write_str("command timed out"),
            RunError::Interrupted { .. } => f.write_str("command interrupted"),
            RunError::CleanupUnconfirmed => f.write_str(CLEANUP_UNCONFIRMED),
        }
    }
}

impl std::error::Error for RunError {}

/// Bounds of a diagnostic capture: the largest tail any caller may ask for, and the timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capture {
    /// `max_chars` is clamped to this.
    pub max_chars: usize,
    pub timeout: Duration,
}

impl Capture {
    /// `_DefaultCoreRunner.capture`: 4096 characters, 15 s.
    pub const CORE: Capture = Capture { max_chars: 4096, timeout: Duration::from_secs(15) };
    /// `_DefaultMcpRunner.capture`: 4096 characters, 120 s (`compose exec`).
    pub const MCP: Capture = Capture { max_chars: 4096, timeout: Duration::from_secs(120) };
    /// `_DefaultVersionAgentRunner.capture`: 1 MiB (the agent's JSON), 15 s.
    pub const VERSION_AGENT: Capture = Capture { max_chars: 1_048_576, timeout: Duration::from_secs(15) };
}

/// `_capture_checked`: the query timeout (`min(timeout, 30)`).
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
/// `_capture_checked`: the largest stdout in characters.
pub const QUERY_MAX_CHARS: usize = 65_536;

/// `CoreError` of `_capture_checked`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// `Core runtime query failed` (start failure, timeout or non-zero exit).
    Failed,
    /// `Core runtime query exceeded its bound`.
    ExceededBound,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryError::Failed => f.write_str("Core runtime query failed"),
            QueryError::ExceededBound => f.write_str("Core runtime query exceeded its bound"),
        }
    }
}

impl std::error::Error for QueryError {}

/// The host command boundary every adapter and the agent talk to.
pub trait HostRunner: Send + Sync {
    /// The audit contract (`CommandRunner.run`).
    fn bounded(&self, argv: &[&str], limits: Bounded) -> Result<BoundedOutput, BoundedError>;
    /// The mutating contract (`_DefaultCoreRunner.run`).
    fn run(&self, argv: &[&str], options: &RunOptions<'_>) -> Result<RunOutput, RunError>;
    /// The in-band diagnostic contract (`capture(argv, max_chars=…)`); never fails.
    fn capture(&self, argv: &[&str], max_chars: usize, limits: Capture) -> String;
    /// `_capture_checked(argv)` with the timeout already clamped by the caller.
    fn capture_checked(&self, argv: &[&str], timeout: Duration) -> Result<String, QueryError>;
}

/// `CommandRunner.capture`: stdout of a successful bounded command.
pub fn bounded_capture(runner: &dyn HostRunner, argv: &[&str], limits: Bounded) -> Result<String, BoundedError> {
    let output = runner.bounded(argv, limits)?;
    if output.returncode != 0 {
        return Err(BoundedError::Failed(output.returncode));
    }
    Ok(output.stdout)
}

/// `CommandRunner.json`: stdout of a successful bounded command, parsed.
pub fn bounded_json(runner: &dyn HostRunner, argv: &[&str], limits: Bounded) -> Result<Value, BoundedError> {
    let text = bounded_capture(runner, argv, limits)?;
    crate::json::loads(text.as_bytes()).map_err(|_| BoundedError::MalformedJson)
}

/// The in-band failure test MCP and the version-agent apply to a capture
/// (`startswith(("exit=", "diagnostic "))`).
pub fn is_in_band_failure(captured: &str) -> bool {
    captured.starts_with("exit=") || captured.starts_with("diagnostic ")
}

/// Builds the text a capture returns from the merged output and exit status: `exit=<rc> `
/// prefixed on a non-zero status, then the last `limit` characters.
pub fn capture_text(returncode: i32, output: &str, limit: usize) -> String {
    let full = if returncode != 0 { format!("exit={returncode} {output}") } else { output.to_string() };
    if limit == 0 {
        // Python's `output[-0:]` is the whole text.
        return full;
    }
    pc_common::pytext::tail_chars(&full, limit).to_string()
}

/// `"diagnostic unavailable: <Class>"[:limit]`.
pub fn capture_unavailable(class_name: &str, limit: usize) -> String {
    pc_common::pytext::head_chars(&format!("diagnostic unavailable: {class_name}"), limit).to_string()
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// The process-wide interrupt flag the runners poll by default.
pub fn interrupt_flag() -> &'static AtomicBool {
    &INTERRUPTED
}

/// Raises the process-wide interrupt flag (what Ctrl-C does once
/// [`install_interrupt_handler`] ran).
pub fn request_interrupt() {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Whether an interrupt was requested.
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

extern "C" fn on_sigint(_signal: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Turns SIGINT into the interrupt flag instead of killing the process, so a running command's
/// group is killed and proven gone first (Python's `KeyboardInterrupt` path). Binaries call it
/// once at start-up.
pub fn install_interrupt_handler() -> io::Result<()> {
    // SAFETY: the handler only stores into an atomic, which is async-signal-safe.
    let previous = unsafe { libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t) };
    if previous == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_call_timeout_cannot_exceed_runner_limit() {
        let runner = Bounded::new(Duration::from_secs(900), MIB).unwrap();
        assert_eq!(
            runner.with_call_timeout(Some(Duration::from_millis(250))).unwrap().timeout,
            Duration::from_millis(250)
        );
        assert_eq!(
            runner.with_call_timeout(Some(Duration::from_secs(1200))).unwrap().timeout,
            Duration::from_secs(900)
        );
        assert_eq!(runner.with_call_timeout(None).unwrap().timeout, Duration::from_secs(900));
        let err = runner.with_call_timeout(Some(Duration::ZERO)).unwrap_err();
        assert_eq!(err.python_class_name(), "ValueError");
        assert_eq!(Bounded::new(Duration::ZERO, 1).unwrap_err().to_string(), "timeout must be positive");
        assert_eq!(Bounded::new(Duration::from_secs(1), 0).unwrap_err().to_string(), "max_output must be positive");
    }

    #[test]
    fn argv_validation() {
        assert_eq!(validate_argv(&[]).unwrap_err().to_string(), "command argv must be a non-empty sequence");
        assert_eq!(validate_argv(&["a\0b"]).unwrap_err().to_string(), "command argv contains an invalid argument");
        assert!(validate_argv(&["true"]).is_ok());
    }

    #[test]
    fn in_band_protocol() {
        assert_eq!(capture_text(0, "ok\n", 4096), "ok\n");
        assert_eq!(capture_text(1, "boom", 4096), "exit=1 boom");
        assert_eq!(capture_text(-9, "", 4096), "exit=-9 ");
        assert_eq!(capture_text(2, "0123456789", 4), "6789");
        assert_eq!(capture_text(1, "x", 0), "exit=1 x");
        assert_eq!(capture_unavailable("OSError", 0), "");
        assert!(is_in_band_failure("exit=1 x"));
        assert!(is_in_band_failure("diagnostic unavailable: TimeoutExpired"));
        assert!(!is_in_band_failure("{\"status\":\"ok\"}"));
        assert_eq!(capture_unavailable("TimeoutExpired", 4096), "diagnostic unavailable: TimeoutExpired");
        assert_eq!(capture_unavailable("TimeoutExpired", 10), "diagnostic");
    }

    #[test]
    fn error_texts() {
        assert_eq!(BoundedError::Failed(3).to_string(), "command failed with exit status 3");
        assert_eq!(BoundedError::Unavailable.python_class_name(), "CommandUnavailable");
        assert_eq!(QueryError::ExceededBound.to_string(), "Core runtime query exceeded its bound");
        assert!(RunError::CleanupUnconfirmed.stops_the_engine());
        assert!(!RunError::TimedOut { stderr: vec![] }.stops_the_engine());
        assert_eq!(RunError::CleanupUnconfirmed.to_string(), CLEANUP_UNCONFIRMED);
    }
}
