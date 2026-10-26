//! A runner for tests: records every call and answers from rules (default: success with empty
//! output), the role the Python unit tests' fake runners played.

use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use super::{
    capture_text, capture_unavailable, validate_argv, Bounded, BoundedError, BoundedOutput, Capture, HostRunner,
    QueryError, RunError, RunOptions, RunOutput, QUERY_MAX_CHARS,
};

/// Which contract a call used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    Bounded,
    Run,
    Capture,
    CaptureChecked,
}

/// One recorded call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub kind: CallKind,
    pub argv: Vec<String>,
    /// The effective timeout of the call.
    pub timeout: Duration,
    /// [`Bounded::max_output`] or the clamped capture limit.
    pub max_output: Option<usize>,
    pub stdin_path: Option<PathBuf>,
    pub env: Option<Vec<(String, String)>>,
}

/// A scripted answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// The command ran and exited (`returncode`, stdout, stderr).
    Exit { returncode: i32, stdout: String, stderr: String },
    /// The program does not exist.
    Unavailable,
    /// The deadline passed (the stderr captured so far for `run`).
    TimedOut { stderr: String },
    /// The command could not be started for another reason.
    Fail(String),
}

impl Reply {
    pub fn ok(stdout: &str) -> Reply {
        Reply::Exit { returncode: 0, stdout: stdout.into(), stderr: String::new() }
    }

    pub fn exit(returncode: i32, stdout: &str, stderr: &str) -> Reply {
        Reply::Exit { returncode, stdout: stdout.into(), stderr: stderr.into() }
    }
}

struct Rule {
    prefix: Vec<String>,
    kind: Option<CallKind>,
    reply: Reply,
    remaining: Option<usize>,
}

type Responder = Box<dyn Fn(&Call) -> Option<Reply> + Send + Sync>;

/// Records calls and answers them from rules: the responder first, then the first rule whose
/// argv prefix (and kind, when given) matches; a one-shot rule is used up by its first match.
#[derive(Default)]
pub struct RecordingRunner {
    calls: Mutex<Vec<Call>>,
    rules: Mutex<Vec<Rule>>,
    responder: Option<Responder>,
}

impl RecordingRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers every call through `responder` (`None` falls through to the rules).
    pub fn with_responder(responder: impl Fn(&Call) -> Option<Reply> + Send + Sync + 'static) -> Self {
        RecordingRunner { responder: Some(Box::new(responder)), ..Self::default() }
    }

    /// Every call whose argv starts with `prefix` gets `reply`.
    pub fn reply(&self, prefix: &[&str], reply: Reply) -> &Self {
        self.push(prefix, None, reply, None)
    }

    /// Only the next call whose argv starts with `prefix` gets `reply`.
    pub fn reply_once(&self, prefix: &[&str], reply: Reply) -> &Self {
        self.push(prefix, None, reply, Some(1))
    }

    /// Like [`reply`](Self::reply), for one contract only.
    pub fn reply_for(&self, kind: CallKind, prefix: &[&str], reply: Reply) -> &Self {
        self.push(prefix, Some(kind), reply, None)
    }

    fn push(&self, prefix: &[&str], kind: Option<CallKind>, reply: Reply, remaining: Option<usize>) -> &Self {
        self.rules.lock().expect("rules lock").push(Rule {
            prefix: prefix.iter().map(|s| s.to_string()).collect(),
            kind,
            reply,
            remaining,
        });
        self
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("calls lock").clone()
    }

    /// The argv of every call so far.
    pub fn argvs(&self) -> Vec<Vec<String>> {
        self.calls().into_iter().map(|call| call.argv).collect()
    }

    /// Forgets the recorded calls (the rules stay).
    pub fn clear(&self) {
        self.calls.lock().expect("calls lock").clear();
    }

    fn answer(&self, call: Call) -> Reply {
        let reply = self.responder.as_ref().and_then(|responder| responder(&call)).or_else(|| {
            let mut rules = self.rules.lock().expect("rules lock");
            let index = rules.iter().position(|rule| {
                rule.remaining != Some(0)
                    && rule.kind.is_none_or(|kind| kind == call.kind)
                    && call.argv.len() >= rule.prefix.len()
                    && call.argv[..rule.prefix.len()] == rule.prefix[..]
            })?;
            let rule = &mut rules[index];
            if let Some(remaining) = rule.remaining.as_mut() {
                *remaining -= 1;
            }
            Some(rule.reply.clone())
        });
        self.calls.lock().expect("calls lock").push(call);
        reply.unwrap_or_else(|| Reply::ok(""))
    }
}

fn owned(argv: &[&str]) -> Vec<String> {
    argv.iter().map(|s| s.to_string()).collect()
}

impl HostRunner for RecordingRunner {
    fn bounded(&self, argv: &[&str], limits: Bounded) -> Result<BoundedOutput, BoundedError> {
        validate_argv(argv)?;
        let call = Call {
            kind: CallKind::Bounded,
            argv: owned(argv),
            timeout: limits.timeout,
            max_output: Some(limits.max_output),
            stdin_path: None,
            env: None,
        };
        match self.answer(call) {
            Reply::Exit { returncode, stdout, stderr } => {
                if stdout.len() + stderr.len() > limits.max_output {
                    return Err(BoundedError::OutputLimit);
                }
                Ok(BoundedOutput { returncode, stdout, stderr })
            }
            Reply::Unavailable => Err(BoundedError::Unavailable),
            Reply::TimedOut { .. } => Err(BoundedError::TimedOut),
            Reply::Fail(_) => Err(BoundedError::CouldNotExecute),
        }
    }

    fn run(&self, argv: &[&str], options: &RunOptions<'_>) -> Result<RunOutput, RunError> {
        let call = Call {
            kind: CallKind::Run,
            argv: owned(argv),
            timeout: options.timeout,
            max_output: None,
            stdin_path: options.stdin_path.clone(),
            env: options.env.clone(),
        };
        match self.answer(call) {
            Reply::Exit { returncode, stderr, .. } => Ok(RunOutput { returncode, stderr: stderr.into_bytes() }),
            Reply::Unavailable => Err(RunError::Spawn(io::Error::from_raw_os_error(libc::ENOENT))),
            Reply::TimedOut { stderr } => Err(RunError::TimedOut { stderr: stderr.into_bytes() }),
            Reply::Fail(message) => Err(RunError::Spawn(io::Error::other(message))),
        }
    }

    fn capture(&self, argv: &[&str], max_chars: usize, limits: Capture) -> String {
        let limit = max_chars.min(limits.max_chars);
        let call = Call {
            kind: CallKind::Capture,
            argv: owned(argv),
            timeout: limits.timeout,
            max_output: Some(limit),
            stdin_path: None,
            env: None,
        };
        match self.answer(call) {
            Reply::Exit { returncode, stdout, stderr } => capture_text(returncode, &(stdout + &stderr), limit),
            Reply::Unavailable => capture_unavailable("FileNotFoundError", limit),
            Reply::TimedOut { .. } => capture_unavailable("TimeoutExpired", limit),
            Reply::Fail(_) => capture_unavailable("OSError", limit),
        }
    }

    fn capture_checked(&self, argv: &[&str], timeout: Duration) -> Result<String, QueryError> {
        let call = Call {
            kind: CallKind::CaptureChecked,
            argv: owned(argv),
            timeout,
            max_output: Some(QUERY_MAX_CHARS),
            stdin_path: None,
            env: None,
        };
        match self.answer(call) {
            Reply::Exit { returncode: 0, stdout, .. } if stdout.chars().count() <= QUERY_MAX_CHARS => Ok(stdout),
            Reply::Exit { returncode: 0, .. } => Err(QueryError::ExceededBound),
            _ => Err(QueryError::Failed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{bounded_capture, bounded_json, is_in_band_failure};

    #[test]
    fn records_calls_and_answers_from_rules() {
        let runner = RecordingRunner::new();
        runner.reply(&["nginx", "-t"], Reply::exit(1, "", "bad config"));
        runner.reply_once(&["systemctl"], Reply::Unavailable);
        let out = runner.bounded(&["nginx", "-t"], Bounded::NGINX).unwrap();
        assert_eq!((out.returncode, out.stderr.as_str()), (1, "bad config"));
        assert_eq!(runner.bounded(&["systemctl", "reload", "nginx"], Bounded::NGINX), Err(BoundedError::Unavailable));
        assert_eq!(runner.bounded(&["systemctl", "reload", "nginx"], Bounded::NGINX).unwrap().returncode, 0);
        assert_eq!(bounded_capture(&runner, &["nginx", "-t"], Bounded::NGINX), Err(BoundedError::Failed(1)));
        let calls = runner.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].argv, vec!["nginx", "-t"]);
        assert_eq!(calls[0].timeout, Duration::from_secs(5));
        assert_eq!(calls[0].max_output, Some(1024 * 1024));
    }

    #[test]
    fn every_contract_has_a_fake_answer() {
        let runner = RecordingRunner::with_responder(|call| match call.argv[0].as_str() {
            "json" => Some(Reply::ok("{\"a\": 1}")),
            "bad" => Some(Reply::ok("{")),
            "slow" => Some(Reply::TimedOut { stderr: "partial".into() }),
            "fails" => Some(Reply::exit(2, "out", "err")),
            _ => None,
        });
        assert_eq!(bounded_json(&runner, &["json"], Bounded::AUDIT).unwrap(), serde_json::json!({"a": 1}));
        assert_eq!(bounded_json(&runner, &["bad"], Bounded::AUDIT), Err(BoundedError::MalformedJson));
        let options = RunOptions { stdin_path: Some("/x".into()), ..RunOptions::default() };
        match runner.run(&["slow"], &options) {
            Err(RunError::TimedOut { stderr }) => assert_eq!(stderr, b"partial"),
            other => panic!("{other:?}"),
        }
        assert_eq!(runner.run(&["ok"], &RunOptions::default()).unwrap().returncode, 0);
        assert_eq!(runner.capture(&["fails"], 100, Capture::CORE), "exit=2 outerr");
        assert!(is_in_band_failure(&runner.capture(&["slow"], 100, Capture::CORE)));
        assert_eq!(runner.capture_checked(&["fails"], Duration::from_secs(30)), Err(QueryError::Failed));
        assert_eq!(runner.capture_checked(&["json"], Duration::from_secs(30)).unwrap(), "{\"a\": 1}");
        let kinds: Vec<CallKind> = runner.calls().iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            vec![
                CallKind::Bounded,
                CallKind::Bounded,
                CallKind::Run,
                CallKind::Run,
                CallKind::Capture,
                CallKind::Capture,
                CallKind::CaptureChecked,
                CallKind::CaptureChecked
            ]
        );
        assert_eq!(runner.calls()[2].stdin_path, Some(PathBuf::from("/x")));
    }
}
