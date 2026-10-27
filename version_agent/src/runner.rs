//! The agent's command runner (`service._run`): `subprocess.run(argv, text=True,
//! capture_output=True, check=True, timeout=…)` returning the stripped stdout.

use std::fmt;
use std::path::PathBuf;
use std::process::Command as Process;
use std::time::Duration;

/// `_run`'s default timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// One command: argv, extra environment (merged over the agent's), working directory, timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    pub timeout: Duration,
    pub stdin: Option<Vec<u8>>,
}

impl Command {
    pub fn new<S: AsRef<str>>(argv: &[S]) -> Command {
        Command {
            argv: argv.iter().map(|part| part.as_ref().to_string()).collect(),
            env: Vec::new(),
            cwd: None,
            timeout: DEFAULT_TIMEOUT,
            stdin: None,
        }
    }

    pub fn timeout(mut self, seconds: u64) -> Command {
        self.timeout = Duration::from_secs(seconds);
        self
    }

    pub fn cwd(mut self, directory: impl Into<PathBuf>) -> Command {
        self.cwd = Some(directory.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Command {
        self.env.push((key.into(), value.into()));
        self
    }
}

/// Why a command did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    /// `OSError`: it could not be started.
    Os(String),
    /// `CalledProcessError`: a non-zero exit.
    Failed { argv: Vec<String>, returncode: i32, stdout: String, stderr: String },
    /// `TimeoutExpired`: killed at the deadline.
    Timeout { argv: Vec<String>, seconds: u64 },
    /// Any other exception a (fake) runner raises.
    Other(String),
}

impl CommandError {
    /// The Python class name, for the failure log line.
    pub fn class_name(&self) -> &'static str {
        match self {
            CommandError::Os(_) => "OSError",
            CommandError::Failed { .. } => "CalledProcessError",
            CommandError::Timeout { .. } => "TimeoutExpired",
            CommandError::Other(_) => "RuntimeError",
        }
    }

    /// The stderr of a failed command.
    pub fn stderr(&self) -> Option<&str> {
        match self {
            CommandError::Failed { stderr, .. } => Some(stderr),
            _ => None,
        }
    }

    /// A cause link for an `UpdateError` raised from this failure.
    pub fn cause(&self) -> crate::errors::Cause {
        crate::errors::Cause {
            class: self.class_name().into(),
            message: self.to_string(),
            stderr: self.stderr().map(str::to_string),
        }
    }
}

fn python_list(argv: &[String]) -> String {
    let items: Vec<String> = argv.iter().map(|part| pc_host::pytext::py_repr(part)).collect();
    format!("[{}]", items.join(", "))
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::Os(message) | CommandError::Other(message) => f.write_str(message),
            CommandError::Failed { argv, returncode, .. } => {
                write!(f, "Command '{}' returned non-zero exit status {returncode}.", python_list(argv))
            }
            CommandError::Timeout { argv, seconds } => {
                write!(f, "Command '{}' timed out after {seconds} seconds", python_list(argv))
            }
        }
    }
}

impl std::error::Error for CommandError {}

/// Runs a command and returns its stdout, stripped (`_run`). Fakes return what they like; the
/// callers strip again where Python did.
pub trait CommandRunner: Send + Sync {
    fn run(&self, command: &Command) -> Result<String, CommandError>;
}

impl<F> CommandRunner for F
where
    F: Fn(&Command) -> Result<String, CommandError> + Send + Sync,
{
    fn run(&self, command: &Command) -> Result<String, CommandError> {
        self(command)
    }
}

/// The real runner: the child inherits the agent's environment plus `env`, its output is
/// decoded as UTF-8 with replacement, and it is killed at the deadline.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, command: &Command) -> Result<String, CommandError> {
        let Some(program) = command.argv.first() else {
            return Err(CommandError::Os("empty command".into()));
        };
        let mut process = Process::new(program);
        process.args(&command.argv[1..]);
        process.envs(command.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        if let Some(directory) = &command.cwd {
            process.current_dir(directory);
        }
        match pc_common::process::run_command(process, command.stdin.as_deref(), command.timeout) {
            Ok(output) => {
                let stdout = output.stdout_text();
                if output.success() {
                    Ok(pc_common::pytext::strip(&stdout).to_string())
                } else {
                    use std::os::unix::process::ExitStatusExt;
                    let returncode = output.status.code().unwrap_or_else(|| -output.status.signal().unwrap_or(0));
                    Err(CommandError::Failed {
                        argv: command.argv.clone(),
                        returncode,
                        stdout,
                        stderr: output.stderr_text(),
                    })
                }
            }
            Err(pc_common::process::RunError::Timeout { .. }) => {
                Err(CommandError::Timeout { argv: command.argv.clone(), seconds: command.timeout.as_secs() })
            }
            Err(pc_common::process::RunError::Spawn(err)) => Err(CommandError::Os(os_error(&err, program))),
            Err(pc_common::process::RunError::Io(err)) => Err(CommandError::Os(err.to_string())),
        }
    }
}

/// `type(exc).__name__` of an `OSError` from a file operation.
pub fn os_class(err: &std::io::Error) -> &'static str {
    match (err.kind(), err.raw_os_error()) {
        (std::io::ErrorKind::NotFound, _) => "FileNotFoundError",
        (std::io::ErrorKind::PermissionDenied, _) => "PermissionError",
        (_, Some(libc::EISDIR)) => "IsADirectoryError",
        (_, Some(libc::ENOTDIR)) => "NotADirectoryError",
        _ => "OSError",
    }
}

/// `str(OSError)` of a failed exec: `[Errno 2] No such file or directory: 'nft'`.
fn os_error(err: &std::io::Error, program: &str) -> String {
    match err.raw_os_error() {
        Some(code) => {
            let text = err.to_string();
            let text = text.split(" (os error").next().unwrap_or(&text);
            format!("[Errno {code}] {text}: {}", pc_host::pytext::py_repr(program))
        }
        None => err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_runner_strips_stdout_and_reports_failures_like_subprocess() {
        let ok = SystemRunner.run(&Command::new(&["sh", "-c", "printf '  out\\n\\n'"])).unwrap();
        assert_eq!(ok, "out");
        let failed = SystemRunner.run(&Command::new(&["sh", "-c", "echo no >&2; exit 3"])).unwrap_err();
        assert_eq!(
            failed.to_string(),
            "Command '['sh', '-c', 'echo no >&2; exit 3']' returned non-zero exit status 3."
        );
        assert_eq!(failed.stderr(), Some("no\n"));
        let missing = SystemRunner.run(&Command::new(&["/nonexistent/program"])).unwrap_err();
        assert_eq!(missing.to_string(), "[Errno 2] No such file or directory: '/nonexistent/program'");
        let slow = SystemRunner.run(&Command::new(&["sleep", "5"]).timeout(0)).unwrap_err();
        assert!(matches!(slow, CommandError::Timeout { .. }));
        let with_env = SystemRunner
            .run(&Command::new(&["sh", "-c", "printf %s \"$PC_TEST_VALUE\"; pwd"]).env("PC_TEST_VALUE", "v").cwd("/"))
            .unwrap();
        assert_eq!(with_env, "v/");
    }
}
