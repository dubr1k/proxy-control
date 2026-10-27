//! The read-only host audit (`installer/audit.py`): 9 required and 8 optional bounded commands,
//! `dig`/`openssl` per domain, DNS resolution in a forked child, and the deterministic,
//! secret-free [`AuditFacts`] the plan digest is computed from.
//!
//! Commands, their order and every parser follow Python byte for byte; the golden
//! `plans/*/audit-transcript.json` and `installs/*/audit-transcript.json` replay the recorded
//! command outputs and compare the facts.
//!
//! Differences from Python (DIFFERENCES.md):
//! - `free -b` and `ufw status verbose` run with `LC_ALL=C` (and without `LANGUAGE`): their parsers
//!   need the English `Mem:` row and `Status: active`; Python inherited the operator's locale.
//! - Digits in parsed output are ASCII only (`isdigit`/`\d` took other Unicode digits).
//! - The CAA tag and `version` words match ASCII case-insensitively (Python's `re.I` also folded
//!   `ſ`, `ı`, `İ`, which no `dig`/`docker` prints).
//! - An operator interrupt kills the command's process group and surfaces as
//!   [`AuditError::Interrupted`] (Python left the child running behind `KeyboardInterrupt`).
//! - The audit is the only user of an audit error: the CLI prints `BLOCKED: <message>` with exit
//!   2 instead of a traceback (host inventory §12 #1; the binary's dispatch does this).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use pc_host::runner::{Bounded, BoundedError, BoundedOutput, HostRunner, SystemRunner};
use serde_json::{json, Map, Value};

use crate::config::{domain_shape_ok, normalize_domain};
use crate::model::{HostMode, InstallerConfig};
use crate::nginx_topology::{map_files, parse_effective_nginx, select_route_target};
use crate::planner::AuditFacts;
use crate::pystr::{is_space, is_word_char, lower, split_whitespace, strip};

/// `DEFAULT_TIMEOUT`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// `DEFAULT_MAX_OUTPUT`: combined stdout + stderr bytes.
pub const DEFAULT_MAX_OUTPUT: usize = 1024 * 1024;
const XRAY_CONFIG: &str = "/usr/local/x-ui/bin/config.json";
const INSTALLER_STATE: &str = "/var/lib/proxy-control/ownership.json";
/// `UFW_IPV6_CONFIG_COMMAND`.
pub const UFW_IPV6_CONFIG_COMMAND: [&str; 4] = ["grep", "-E", "^IPV6=(yes|no)$", "/etc/default/ufw"];
/// `RESERVED_IDENTITIES["uid"]`: identities the protocol adapters reserve.
pub const RESERVED_UIDS: [u32; 3] = [10002, 10003, 10005];
/// `RESERVED_IDENTITIES["gid"]`.
pub const RESERVED_GIDS: [u32; 3] = [101, 10004, 10005];
/// `_SAFE_ARCHITECTURES`: x86-64 only (every pinned artifact is built for it).
pub const SAFE_ARCHITECTURES: [(&str, &str); 2] = [("amd64", "amd64"), ("x86_64", "amd64")];
const CAA_VALIDATION_METHODS: [&str; 3] = ["dns-01", "http-01", "tls-alpn-01"];
const CAA_QUERY_LIMIT: u32 = 64;
const RESOLVER_RESULT_LIMIT: usize = 256;

/// The messages `audit_host` lets through unchanged (`_safe_audit_error`).
const SAFE_MESSAGES: [&str; 18] = [
    "CAA alias loop detected",
    "CAA issuer is malformed",
    "CAA issuer parameter is duplicated",
    "CAA issuer parameter is malformed",
    "CAA issuer parameter is unsupported",
    "CAA query failed",
    "CAA query limit exceeded",
    "CAA response was malformed",
    "DNS resolution failed",
    "DNS resolution result limit exceeded",
    "DNS resolution timed out",
    "Nginx observation is malformed",
    "command could not be executed",
    "command output limit exceeded",
    "command returned an invalid response",
    "command returned malformed JSON",
    "command timed out",
    "required audit command is unavailable",
];

/// `AuditError` and its subclass `CommandUnavailable`; an operator interrupt is its own case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// `AuditError(message)`.
    Failed(String),
    /// `CommandUnavailable("command is unavailable")`: the executable does not exist.
    Unavailable,
    /// The operator interrupted the audit (Python's `KeyboardInterrupt`).
    Interrupted,
}

impl AuditError {
    fn failed(message: impl Into<String>) -> AuditError {
        AuditError::Failed(message.into())
    }

    /// `str(exc)`.
    pub fn message(&self) -> String {
        match self {
            AuditError::Failed(message) => message.clone(),
            AuditError::Unavailable => "command is unavailable".into(),
            AuditError::Interrupted => "command interrupted".into(),
        }
    }

    /// `type(exc).__name__`.
    pub fn python_class_name(&self) -> &'static str {
        match self {
            AuditError::Failed(_) => "AuditError",
            AuditError::Unavailable => "CommandUnavailable",
            AuditError::Interrupted => "KeyboardInterrupt",
        }
    }
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for AuditError {}

type Result<T> = std::result::Result<T, AuditError>;

/// `HardStop` (ordered by code, message, domains).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HardStop {
    pub code: String,
    pub message: String,
    pub domains: Vec<String>,
}

/// `OperatorPrerequisite` (ordered by code, status, message).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperatorPrerequisite {
    pub code: String,
    pub status: String,
    pub message: String,
}

/// The audit's `AuditFacts` subclass: the facts plus the sorted hard stops and prerequisites.
#[derive(Debug, Clone)]
pub struct Audit {
    pub facts: AuditFacts,
    pub hard_stops: Vec<HardStop>,
    pub operator_prerequisites: Vec<OperatorPrerequisite>,
}

/// The hard stops a plain [`AuditFacts`] carries in `prerequisites.hard_stops` (what an adapter
/// sees when it is handed facts instead of an [`Audit`]), sorted like `AuditFacts.hard_stops`.
pub fn hard_stops(facts: &AuditFacts) -> Vec<HardStop> {
    let mut stops: Vec<HardStop> = facts
        .prerequisites
        .get("hard_stops")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| HardStop {
                    code: item.get("code").and_then(Value::as_str).unwrap_or_default().to_string(),
                    message: item.get("message").and_then(Value::as_str).unwrap_or_default().to_string(),
                    domains: item
                        .get("domains")
                        .and_then(Value::as_array)
                        .map(|names| names.iter().filter_map(Value::as_str).map(str::to_string).collect())
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();
    stops.sort();
    stops
}

/// The command boundary of the audit (`installer.audit.Executor`): one bounded command, its
/// text output decoded with replacement. `c_locale` asks for `LC_ALL=C` (locale-dependent
/// parsers).
pub trait AuditExecutor {
    fn execute(
        &self,
        argv: &[&str],
        limits: Bounded,
        c_locale: bool,
    ) -> std::result::Result<BoundedOutput, BoundedError>;
}

/// An address family of a resolver answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    Inet,
    Inet6,
}

/// A resolver failure; its raw message must not enter the operator's audit error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveError;

/// One bounded DNS lookup result.
pub type ResolveResult = std::result::Result<Vec<(Family, String)>, ResolveError>;

/// `socket.getaddrinfo(name, 443, type=SOCK_STREAM)`: the answers' families and raw address
/// texts (an IPv6 one may carry `%scope`), or `Err` for a resolver error. It runs in a forked
/// child (`_bounded_resolve`).
pub trait Resolver {
    fn getaddrinfo(&self, absolute_name: &str) -> ResolveResult;
}

/// The real host: [`SystemRunner`] for ordinary commands, a C-locale variant of the same
/// bounded contract for the locale-dependent ones.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemExecutor;

impl AuditExecutor for SystemExecutor {
    fn execute(
        &self,
        argv: &[&str],
        limits: Bounded,
        c_locale: bool,
    ) -> std::result::Result<BoundedOutput, BoundedError> {
        if c_locale {
            c_locale_bounded(argv, limits)
        } else {
            SystemRunner.bounded(argv, limits)
        }
    }
}

/// The host resolver (`getaddrinfo(3)`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn getaddrinfo(&self, absolute_name: &str) -> ResolveResult {
        let name = std::ffi::CString::new(absolute_name).map_err(|_| ResolveError)?;
        let service = std::ffi::CString::new("443").expect("no NUL");
        // SAFETY: zeroed addrinfo is a valid "no hints" value; the fields set are plain ints.
        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_family = libc::AF_UNSPEC;
        hints.ai_socktype = libc::SOCK_STREAM;
        let mut result: *mut libc::addrinfo = std::ptr::null_mut();
        // SAFETY: valid C strings, hints and out-pointer; the list is freed below.
        let rc = unsafe { libc::getaddrinfo(name.as_ptr(), service.as_ptr(), &hints, &mut result) };
        if rc != 0 {
            return Err(ResolveError);
        }
        let mut answers = Vec::new();
        let mut cursor = result;
        while !cursor.is_null() {
            // SAFETY: `cursor` walks the list getaddrinfo returned.
            let entry = unsafe { &*cursor };
            if !entry.ai_addr.is_null() {
                if entry.ai_family == libc::AF_INET {
                    // SAFETY: AF_INET entries carry a sockaddr_in.
                    let address = unsafe { &*(entry.ai_addr as *const libc::sockaddr_in) };
                    let ip = std::net::Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
                    answers.push((Family::Inet, ip.to_string()));
                } else if entry.ai_family == libc::AF_INET6 {
                    // SAFETY: AF_INET6 entries carry a sockaddr_in6.
                    let address = unsafe { &*(entry.ai_addr as *const libc::sockaddr_in6) };
                    let ip = std::net::Ipv6Addr::from(address.sin6_addr.s6_addr);
                    answers.push((Family::Inet6, ip.to_string()));
                }
            }
            cursor = entry.ai_next;
        }
        // SAFETY: `result` came from getaddrinfo and is freed once.
        unsafe { libc::freeaddrinfo(result) };
        Ok(answers)
    }
}

/// `CommandRunner`: the shell-free, bounded command and DNS observation boundary.
pub struct CommandRunner<'a> {
    limits: Bounded,
    executor: &'a dyn AuditExecutor,
    resolver: &'a dyn Resolver,
    redactor: Redactor,
}

impl<'a> CommandRunner<'a> {
    /// `CommandRunner(executor=…, resolver=…)` with the default limits; the secret-looking
    /// environment values are read now.
    pub fn new(executor: &'a dyn AuditExecutor, resolver: &'a dyn Resolver) -> CommandRunner<'a> {
        CommandRunner { limits: Bounded::AUDIT, executor, resolver, redactor: Redactor::from_environment() }
    }

    /// `CommandRunner(timeout=…, max_output=…)` (`ValueError` texts for zero values).
    pub fn with_limits(mut self, timeout: Duration, max_output: usize) -> std::result::Result<Self, String> {
        self.limits = Bounded::new(timeout, max_output).map_err(|err| err.to_string())?;
        Ok(self)
    }

    /// Replaces the environment the secret filter reads (tests; Python read `os.environ`).
    pub fn with_environment(mut self, environment: &[(String, String)]) -> Self {
        self.redactor = Redactor::new(environment);
        self
    }

    pub fn limits(&self) -> Bounded {
        self.limits
    }

    /// `run(argv)`: the finished command (any exit status).
    pub fn run(&self, argv: &[&str]) -> Result<BoundedOutput> {
        self.execute(argv, None, false)
    }

    /// `run(argv, timeout=…)`: a per-call timeout can only shorten the runner's.
    pub fn run_with_timeout(&self, argv: &[&str], timeout: Duration) -> Result<BoundedOutput> {
        self.execute(argv, Some(timeout), false)
    }

    fn execute(&self, argv: &[&str], timeout: Option<Duration>, c_locale: bool) -> Result<BoundedOutput> {
        pc_host::runner::validate_argv(argv).map_err(|err| AuditError::failed(err.to_string()))?;
        let limits = self.limits.with_call_timeout(timeout).map_err(|err| AuditError::failed(err.to_string()))?;
        let output = self.executor.execute(argv, limits, c_locale).map_err(|err| match err {
            BoundedError::Unavailable => AuditError::Unavailable,
            BoundedError::Interrupted => AuditError::Interrupted,
            BoundedError::TimedOut => AuditError::failed("command timed out"),
            BoundedError::OutputLimit => AuditError::failed("command output limit exceeded"),
            _ => AuditError::failed("command could not be executed"),
        })?;
        if output.stdout.len() + output.stderr.len() > self.limits.max_output {
            return Err(AuditError::failed("command output limit exceeded"));
        }
        Ok(output)
    }

    /// `capture(argv)`: stdout of a successful command.
    pub fn capture(&self, argv: &[&str]) -> Result<String> {
        let output = self.run(argv)?;
        if output.returncode != 0 {
            return Err(AuditError::failed(format!("command failed with exit status {}", output.returncode)));
        }
        Ok(output.stdout)
    }

    /// `json(argv)`: stdout of a successful command, parsed.
    pub fn json(&self, argv: &[&str]) -> Result<Value> {
        let text = self.capture(argv)?;
        pc_host::json::loads(text.as_bytes()).map_err(|_| AuditError::failed("command returned malformed JSON"))
    }

    /// `resolve(domain)`: the sorted, unique IPv4 and IPv6 answers for `<domain>.`.
    pub fn resolve(&self, domain: &str) -> Result<(Vec<String>, Vec<String>)> {
        let absolute = validate_domain(domain)
            .ok_or_else(|| AuditError::failed("a plain fully-qualified domain name is required"))?
            + ".";
        bounded_resolve(self.resolver, &absolute, self.limits.timeout)
    }
}

// ---------------------------------------------------------------------------------------------
// Secret filtering (`_SENSITIVE_KEY`, `_SENSITIVE_ASSIGNMENT`, `_UUID`, `_PRIVATE_KEY_BLOCK`)
// ---------------------------------------------------------------------------------------------

/// `re.IGNORECASE` for one pattern letter: ASCII case plus Python's extra folds.
fn ci(c: char, lower_ascii: char) -> bool {
    c.to_ascii_lowercase() == lower_ascii
        || matches!((lower_ascii, c), ('k', '\u{212a}') | ('s', '\u{17f}') | ('i', '\u{130}') | ('i', '\u{131}'))
}

fn literal_ci(chars: &[char], pos: usize, word: &str) -> Option<usize> {
    let mut index = pos;
    for expected in word.chars() {
        if !chars.get(index).is_some_and(|c| ci(*c, expected)) {
            return None;
        }
        index += 1;
    }
    Some(index)
}

fn literal(chars: &[char], pos: usize, word: &str) -> Option<usize> {
    let mut index = pos;
    for expected in word.chars() {
        if chars.get(index) != Some(&expected) {
            return None;
        }
        index += 1;
    }
    Some(index)
}

/// Every end of `head[_-]?tail` at `pos`, the optional separator first (greedy).
fn separated(chars: &[char], pos: usize, head: &str, tail: &str) -> Vec<usize> {
    let mut ends = Vec::new();
    if let Some(after) = literal_ci(chars, pos, head) {
        if matches!(chars.get(after), Some('_' | '-')) {
            ends.extend(literal_ci(chars, after + 1, tail));
        }
        ends.extend(literal_ci(chars, after, tail));
    }
    ends
}

/// `_SENSITIVE_KEY.search(name)`.
fn sensitive_key(name: &str) -> bool {
    let chars: Vec<char> = name.chars().collect();
    (0..chars.len()).any(|pos| {
        ["auth", "cookie", "credential", "password", "passwd", "secret", "token", "panelpath", "panel_path"]
            .iter()
            .chain(["webbasepath", "session", "dsn"].iter())
            .any(|word| literal_ci(&chars, pos, word).is_some())
            || !separated(&chars, pos, "private", "key").is_empty()
            || !separated(&chars, pos, "short", "id").is_empty()
            || !separated(&chars, pos, "api", "key").is_empty()
            || !separated(&chars, pos, "access", "key").is_empty()
            || !separated(&chars, pos, "database", "url").is_empty()
    })
}

fn skip_space(chars: &[char], mut pos: usize) -> usize {
    while chars.get(pos).is_some_and(|c| is_space(*c)) {
        pos += 1;
    }
    pos
}

/// `(?:\"[^\"]*\"|'[^']*'|[^\s,}\]]+)` at `pos`: its end.
fn assignment_value(chars: &[char], pos: usize) -> Option<usize> {
    let first = *chars.get(pos)?;
    if first == '"' || first == '\'' {
        if let Some(offset) = chars[pos + 1..].iter().position(|c| *c == first) {
            return Some(pos + offset + 2);
        }
    }
    let mut end = pos;
    while chars.get(end).is_some_and(|c| !is_space(*c) && !matches!(c, ',' | '}' | ']')) {
        end += 1;
    }
    (end > pos).then_some(end)
}

/// `\s*[:=]\s*` + value after a name ending at `end` (`separators` the accepted signs).
fn assignment_tail(chars: &[char], end: usize, separators: &[char]) -> Option<usize> {
    let separator = skip_space(chars, end);
    if !chars.get(separator).is_some_and(|c| separators.contains(c)) {
        return None;
    }
    assignment_value(chars, skip_space(chars, separator + 1))
}

/// `_SENSITIVE_ASSIGNMENT.match(text, pos)`: the end of the match.
fn sensitive_assignment_at(chars: &[char], pos: usize) -> Option<usize> {
    if let Some(after) = literal_ci(chars, pos, "authorization") {
        let separator = skip_space(chars, after);
        if chars.get(separator) != Some(&':') {
            return None;
        }
        let value = skip_space(chars, separator + 1);
        if let Some(bearer) = literal_ci(chars, value, "bearer") {
            if chars.get(bearer).is_some_and(|c| is_space(*c)) {
                if let Some(end) = assignment_value(chars, skip_space(chars, bearer)) {
                    return Some(end);
                }
            }
        }
        return assignment_value(chars, value);
    }
    if let Some(after) = literal_ci(chars, pos, "cookie") {
        return assignment_tail(chars, after, &[':']);
    }
    let mut names: Vec<usize> = Vec::new();
    for word in ["password", "passwd", "secret", "token", "panelpath", "panel_path", "webbasepath"] {
        names.extend(literal_ci(chars, pos, word));
    }
    names.extend(separated(chars, pos, "private", "key"));
    for end in separated(chars, pos, "short", "id") {
        if chars.get(end).is_some_and(|c| ci(*c, 's')) {
            names.push(end + 1);
        }
        names.push(end);
    }
    names.extend(separated(chars, pos, "api", "key"));
    if let Some(end) = literal_ci(chars, pos, "session") {
        names.extend(literal_ci(chars, end, "id"));
        names.push(end);
    }
    names.into_iter().find_map(|end| assignment_tail(chars, end, &[':', '=']))
}

fn count_matches(chars: &[char], at: impl Fn(&[char], usize) -> Option<usize>) -> usize {
    let mut count = 0;
    let mut pos = 0;
    while pos < chars.len() {
        match at(chars, pos) {
            Some(end) if end > pos => {
                count += 1;
                pos = end;
            }
            _ => pos += 1,
        }
    }
    count
}

fn hex_ci(c: char) -> bool {
    c.is_ascii_hexdigit()
}

/// `_UUID.match(text, pos)` (with its `\b`s).
fn uuid_at(chars: &[char], pos: usize) -> Option<usize> {
    if pos > 0 && is_word_char(chars[pos - 1]) {
        return None;
    }
    let mut index = pos;
    for (group, length) in [8, 4, 4, 4, 12].into_iter().enumerate() {
        if group > 0 {
            if chars.get(index) != Some(&'-') {
                return None;
            }
            index += 1;
        }
        for _ in 0..length {
            if !chars.get(index).is_some_and(|c| hex_ci(*c)) {
                return None;
            }
            index += 1;
        }
    }
    if chars.get(index).is_some_and(|c| is_word_char(*c)) {
        return None;
    }
    Some(index)
}

/// `-----BEGIN|END [^-\r\n]*PRIVATE KEY-----` at `pos`: its end.
fn key_marker_at(chars: &[char], pos: usize, word: &str) -> Option<usize> {
    let mut index = literal(chars, pos, "-----")?;
    index = literal(chars, index, word)?;
    index = literal(chars, index, " ")?;
    let run_start = index;
    while chars.get(index).is_some_and(|c| !matches!(c, '-' | '\r' | '\n')) {
        index += 1;
    }
    let run: String = chars[run_start..index].iter().collect();
    if !run.ends_with("PRIVATE KEY") {
        return None;
    }
    literal(chars, index, "-----")
}

/// `_PRIVATE_KEY_BLOCK.match(text, pos)` (`.*?` lazy, DOTALL).
fn private_key_block_at(chars: &[char], pos: usize) -> Option<usize> {
    let after = key_marker_at(chars, pos, "BEGIN")?;
    (after..chars.len()).find_map(|end| key_marker_at(chars, end, "END"))
}

/// The environment's secret-looking values and the redaction rules that use them.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    /// `_environment_secret_values()` over `environment`.
    pub fn new(environment: &[(String, String)]) -> Redactor {
        let mut secrets: Vec<String> = environment
            .iter()
            .filter(|(key, value)| value.chars().count() >= 4 && sensitive_key(key))
            .map(|(_, value)| value.clone())
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        secrets.sort_by_key(|value| std::cmp::Reverse(value.chars().count()));
        Redactor { secrets }
    }

    /// From this process's environment.
    pub fn from_environment() -> Redactor {
        let environment: Vec<(String, String)> = std::env::vars_os()
            .map(|(key, value)| (key.to_string_lossy().into_owned(), value.to_string_lossy().into_owned()))
            .collect();
        Redactor::new(&environment)
    }

    /// `_sanitize_error(text)`: `audit observation failed` plus one ` [REDACTED]` per secret.
    pub fn sanitize_error(&self, text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut redactions = count_matches(&chars, sensitive_assignment_at);
        redactions += count_matches(&chars, uuid_at);
        redactions += count_matches(&chars, private_key_block_at);
        redactions += self.secrets.iter().map(|value| text.matches(value.as_str()).count()).sum::<usize>();
        let mut message = String::from("audit observation failed");
        if redactions > 0 {
            message.push(' ');
            message.push_str(&vec!["[REDACTED]"; redactions].join(" "));
        }
        message
    }

    /// `_safe_audit_error(text)`: a known message, or the sanitized form.
    pub fn safe_audit_error(&self, text: &str) -> String {
        if SAFE_MESSAGES.contains(&text) || exit_status_message(text) {
            return text.to_string();
        }
        self.sanitize_error(text)
    }

    /// `_safe_text(value, maximum)`.
    pub fn safe_text(&self, value: &str, maximum: usize) -> bool {
        let chars: Vec<char> = value.chars().collect();
        !chars.is_empty()
            && chars.len() <= maximum
            && !(0..chars.len()).any(|pos| sensitive_assignment_at(&chars, pos).is_some())
            && !(0..chars.len()).any(|pos| uuid_at(&chars, pos).is_some())
            && !self.secrets.iter().any(|secret| value.contains(secret.as_str()))
    }
}

/// `(?:command failed|required audit command failed) with exit status -?\d+` (full match).
fn exit_status_message(text: &str) -> bool {
    let rest = text
        .strip_prefix("command failed with exit status ")
        .or_else(|| text.strip_prefix("required audit command failed with exit status "));
    let Some(rest) = rest else { return false };
    ascii_digits(rest.strip_prefix('-').unwrap_or(rest))
}

// ---------------------------------------------------------------------------------------------
// Validators and parsers
// ---------------------------------------------------------------------------------------------

/// `validate_domain(value)`: `strip().lower().rstrip(".")` and the domain rule, or `None`
/// (`ValueError("a plain fully-qualified domain name is required")`).
pub fn validate_domain(value: &str) -> Option<String> {
    normalize_domain(value)
}

/// `_SAFE_NAME_RE.fullmatch`: `[A-Za-z0-9_.:@+-]{1,128}`.
fn safe_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'+' | b'-'))
}

fn ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// `int(digits)` of ASCII digits, `None` beyond `u64`.
fn digits_value(value: &str) -> Option<u64> {
    value.parse::<u64>().ok()
}

/// `str.splitlines(keepends)`: Python's line boundaries.
pub fn splitlines(text: &str, keepends: bool) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        let boundary = matches!(
            c,
            '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        );
        if !boundary {
            continue;
        }
        let mut end = index + c.len_utf8();
        if c == '\r' {
            if let Some((_, '\n')) = chars.peek() {
                chars.next();
                end += 1;
            }
        }
        lines.push(if keepends { &text[start..end] } else { &text[start..index] });
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `_canonical_ip(value)`: `str(ip_address(value.split("%", 1)[0]))`.
pub fn canonical_ip(value: &str) -> Option<String> {
    crate::ipaddr::ip_address(value.split('%').next().unwrap_or_default()).ok()
}

/// `parse_http_domains(text)`: every valid name of every `server_name` line.
pub fn parse_http_domains(text: &str) -> BTreeSet<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut domains = BTreeSet::new();
    let mut start = 0;
    while start <= chars.len() {
        if start > 0 && chars[start - 1] != '\n' {
            start += 1;
            continue;
        }
        let name = skip_space(&chars, start);
        let matched = literal(&chars, name, "server_name").and_then(|after| {
            if !chars.get(after).is_some_and(|c| is_space(*c)) {
                return None;
            }
            let value = skip_space(&chars, after);
            let semicolon = value + chars[value..].iter().position(|c| *c == ';')?;
            // `[^;]+` needs one character; with none left the last whitespace of `\s+` gives it.
            if semicolon == value && value - after < 2 {
                return None;
            }
            Some((chars[value.min(semicolon)..semicolon].iter().collect::<String>(), semicolon + 1))
        });
        match matched {
            Some((group, end)) => {
                for value in split_whitespace(&group) {
                    if let Some(domain) = validate_domain(value) {
                        domains.insert(domain);
                    }
                }
                start = end;
            }
            None => start += 1,
        }
    }
    domains
}

/// `parse_xray_inbounds(value)`: only the non-secret inbound fields of a 3x-ui Xray config.
pub fn parse_xray_inbounds(value: &Value, redactor: &Redactor) -> Vec<Value> {
    let Some(raw_inbounds) = value.as_object().and_then(|map| map.get("inbounds")).and_then(Value::as_array) else {
        return Vec::new();
    };
    let empty = Map::new();
    let mut observations: Vec<(String, Value)> = Vec::new();
    for raw in raw_inbounds {
        let Some(raw) = raw.as_object() else { continue };
        let stream = raw.get("streamSettings").and_then(Value::as_object).unwrap_or(&empty);
        let reality = stream.get("realitySettings").and_then(Value::as_object).unwrap_or(&empty);
        let mut names = BTreeSet::new();
        if let Some(raw_names) = reality.get("serverNames").and_then(Value::as_array) {
            for name in raw_names.iter().filter_map(Value::as_str) {
                if let Some(domain) = validate_domain(name) {
                    names.insert(domain);
                }
            }
        }
        let mut observation = Map::new();
        for key in ["tag", "protocol", "listen"] {
            if let Some(candidate) = raw.get(key).and_then(Value::as_str) {
                if safe_name(candidate) && redactor.safe_text(candidate, 128) {
                    observation.insert(key.into(), json!(candidate));
                }
            }
        }
        if let Some(port) = raw.get("port").and_then(Value::as_i64).filter(|port| (1..=65535).contains(port)) {
            observation.insert("port".into(), json!(port));
        }
        if let Some(security) = stream.get("security").and_then(Value::as_str) {
            if safe_name(security) && redactor.safe_text(security, 128) {
                observation.insert("transport_security".into(), json!(security));
            }
        }
        observation.insert("reality_server_names".into(), json!(names.into_iter().collect::<Vec<_>>()));
        let value = Value::Object(observation);
        observations.push((sort_key(&value), value));
    }
    observations.sort_by(|a, b| a.0.cmp(&b.0));
    observations.into_iter().map(|(_, value)| value).collect()
}

/// `json.dumps(item, sort_keys=True)` (default separators, ASCII).
fn sort_key(value: &Value) -> String {
    let options = pc_common::json::Options {
        indent: None,
        separators: None,
        sort_keys: true,
        ensure_ascii: true,
        numbers: pc_common::json::NumberMode::Python(pc_common::json::FloatMode::Python),
    };
    pc_common::json::dumps(value, &options)
}

/// `parse_ufw_ipv6_config(text)`: exactly one `IPV6=yes|no` assignment.
pub fn parse_ufw_ipv6_config(text: &str) -> Option<bool> {
    let assignments: Vec<&str> =
        splitlines(text, false).into_iter().map(strip).filter(|line| !line.is_empty()).collect();
    match assignments.as_slice() {
        ["IPV6=yes"] => Some(true),
        ["IPV6=no"] => Some(false),
        _ => None,
    }
}

fn parse_disks(text: &str, redactor: &Redactor) -> Vec<Value> {
    let mut observations: Vec<(String, Value)> = Vec::new();
    for line in splitlines(text, false).into_iter().skip(1) {
        let fields = split_whitespace(line);
        if fields.len() < 6 || !fields[1..4].iter().all(|value| ascii_digits(value)) {
            continue;
        }
        let (filesystem, mount) = (fields[0], fields[fields.len() - 1]);
        if !redactor.safe_text(filesystem, 256) || !redactor.safe_text(mount, 256) {
            continue;
        }
        let (Some(total), Some(used), Some(available)) =
            (digits_value(fields[1]), digits_value(fields[2]), digits_value(fields[3]))
        else {
            continue;
        };
        observations.push((
            mount.to_string(),
            json!({"available_kib": available, "filesystem": filesystem, "mount": mount,
                   "total_kib": total, "used_kib": used}),
        ));
    }
    observations.sort_by(|a, b| a.0.cmp(&b.0));
    observations.into_iter().map(|(_, value)| value).collect()
}

fn parse_memory(text: &str) -> (u64, u64) {
    for line in splitlines(text, false) {
        let fields = split_whitespace(line);
        if !fields.is_empty() && fields[0].trim_end_matches(':') == "Mem" && fields.len() >= 7 {
            let numbers = &fields[1..7];
            if numbers.iter().all(|value| ascii_digits(value)) {
                if let (Some(total), Some(available)) = (digits_value(numbers[0]), digits_value(numbers[5])) {
                    return (available, total);
                }
            }
        }
    }
    (0, 0)
}

fn parse_addresses(value: &Value) -> Vec<Value> {
    let mut observations: BTreeSet<(String, &'static str, String)> = BTreeSet::new();
    let Some(links) = value.as_array() else { return Vec::new() };
    for link in links.iter().filter_map(Value::as_object) {
        let Some(interface) = link.get("ifname").and_then(Value::as_str).filter(|name| safe_name(name)) else {
            continue;
        };
        let Some(items) = link.get("addr_info").and_then(Value::as_array) else { continue };
        for item in items.iter().filter_map(Value::as_object) {
            if !matches!(item.get("scope").and_then(Value::as_str), Some("global" | "host")) {
                continue;
            }
            let Some(address) = item.get("local").and_then(Value::as_str).and_then(canonical_ip) else { continue };
            let family = if address.contains(':') { "inet6" } else { "inet" };
            observations.insert((address, family, interface.to_string()));
        }
    }
    observations
        .into_iter()
        .map(|(address, family, interface)| json!({"address": address, "family": family, "interface": interface}))
        .collect()
}

/// The digits after the last `:` that ends `field` (`:\d+$`).
fn endpoint_port(field: &str) -> Option<&str> {
    let (_, tail) = field.rsplit_once(':')?;
    ascii_digits(tail).then_some(tail)
}

/// `users:(("name"` occurrences of an `ss` line.
fn ss_owners(line: &str) -> Vec<String> {
    let mut owners = Vec::new();
    let mut rest = line;
    while let Some(index) = rest.find("users:((\"") {
        let after = &rest[index + "users:((\"".len()..];
        if let Some(end) = after.find(['"', '\\']) {
            if after.as_bytes()[end] == b'"' && end > 0 {
                owners.push(after[..end].to_string());
            }
        }
        rest = &rest[index + 1..];
    }
    owners
}

struct Listeners {
    tcp: BTreeSet<u32>,
    udp: BTreeSet<u32>,
    owners: BTreeMap<u32, BTreeSet<String>>,
}

fn parse_listener_lines(text: &str) -> Listeners {
    let mut listeners = Listeners { tcp: BTreeSet::new(), udp: BTreeSet::new(), owners: BTreeMap::new() };
    for line in splitlines(text, false) {
        let fields = split_whitespace(line);
        if fields.is_empty() {
            continue;
        }
        let protocol = lower(fields[0]);
        let Some(port) = fields.iter().find_map(|field| endpoint_port(field)) else { continue };
        let Some(port) = digits_value(port).filter(|port| (1..=65535).contains(port)).map(|port| port as u32) else {
            continue;
        };
        let target = if protocol.starts_with("tcp") {
            &mut listeners.tcp
        } else if protocol.starts_with("udp") {
            &mut listeners.udp
        } else {
            continue;
        };
        target.insert(port);
        for owner in ss_owners(line) {
            if safe_name(&owner) {
                listeners.owners.entry(port).or_default().insert(owner);
            }
        }
    }
    listeners
}

fn listeners_value(listeners: &Listeners) -> Map<String, Value> {
    let ports: BTreeSet<u32> = listeners.tcp.union(&listeners.udp).copied().collect();
    let owners: Map<String, Value> = listeners
        .owners
        .iter()
        .map(|(port, names)| (port.to_string(), json!(names.iter().collect::<Vec<_>>())))
        .collect();
    let mut map = Map::new();
    map.insert("owners".into(), Value::Object(owners));
    map.insert("ports".into(), json!(ports.iter().collect::<Vec<_>>()));
    map.insert("tcp".into(), json!(listeners.tcp.iter().collect::<Vec<_>>()));
    map.insert("udp".into(), json!(listeners.udp.iter().collect::<Vec<_>>()));
    map
}

/// Listening ports and their process owners, sorted for deterministic plan facts.
pub type ListenerInventory = (BTreeSet<u32>, BTreeMap<u32, Vec<String>>);

/// `listener_inventory(runner)`: every listening port and the processes that hold each.
pub fn listener_inventory(runner: &CommandRunner<'_>) -> Result<ListenerInventory> {
    let parsed = parse_listener_lines(&required_capture(runner, &["ss", "-H", "-lntup"], false)?);
    let ports = parsed.tcp.union(&parsed.udp).copied().collect();
    let owners = parsed.owners.into_iter().map(|(port, names)| (port, names.into_iter().collect())).collect();
    Ok((ports, owners))
}

fn parse_ssh_socket_ports(text: &str) -> Vec<u32> {
    let mut ports = BTreeSet::new();
    for raw in splitlines(text, false) {
        let line = strip(raw);
        if line.is_empty() {
            continue;
        }
        if let Some(head) = line.strip_suffix(" (Stream)") {
            let digits =
                ["0.0.0.0:", "[::]:", "*:"].iter().find_map(|prefix| head.strip_prefix(prefix)).unwrap_or(head);
            let shaped = (1..=5).contains(&digits.len())
                && digits.bytes().all(|b| b.is_ascii_digit())
                && !digits.starts_with('0');
            if shaped {
                let port: u32 = digits.parse().expect("ASCII digits");
                if (1..=65535).contains(&port) {
                    ports.insert(port);
                    continue;
                }
            }
            if head.starts_with('/') && head.len() > 1 && !head.chars().any(|c| matches!(c, '\0' | '\r' | '\n' | ' ')) {
                continue;
            }
        }
        return Vec::new();
    }
    ports.into_iter().collect()
}

fn empty_nginx(observation: &str) -> Value {
    json!({
        "available": false,
        "duplicate_sni_domains": [],
        "http_domains": [],
        "observation": observation,
        "route_target": null,
        "sni_map_count": 0,
        "sni_map_files": {},
        "sni_routes": {},
        "stream_enabled": false,
        "topology_error": null,
    })
}

/// `_nginx_sections(text)`: the text of every `# configuration file <path>:` section.
fn nginx_sections(text: &str, redactor: &Redactor) -> Vec<(String, String)> {
    let mut sections: Vec<(String, String)> = vec![("<effective>".into(), String::new())];
    let mut current = 0;
    for line in splitlines(text, true) {
        let marker = line.strip_prefix("# configuration file ").and_then(|rest| {
            let body = rest
                .strip_suffix("\r\n")
                .or_else(|| rest.strip_suffix('\n'))
                .or_else(|| rest.strip_suffix('\r'))
                .unwrap_or(rest);
            let path = body.strip_suffix(':')?;
            (path.starts_with('/') && path.len() > 1 && !path.contains([':', '\r', '\n'])).then_some(path)
        });
        if let Some(path) = marker.filter(|path| redactor.safe_text(path, 512)) {
            current = match sections.iter().position(|(name, _)| name == path) {
                Some(index) => index,
                None => {
                    sections.push((path.to_string(), String::new()));
                    sections.len() - 1
                }
            };
            continue;
        }
        sections[current].1.push_str(line);
    }
    sections.retain(|(_, content)| !content.is_empty());
    sections
}

/// `parse_nginx_observation(text)`: what `nginx -T` says about the stream router and the
/// HTTP names.
pub fn parse_nginx_observation(text: &str, redactor: &Redactor) -> Result<Value> {
    let topology = parse_effective_nginx(text).map_err(|_| AuditError::failed("Nginx observation is malformed"))?;
    let sni_maps = topology.maps.iter().filter(|mapping| mapping.source_variable == "$ssl_preread_server_name").count();
    let files = map_files(&topology, "$ssl_preread_server_name");
    let mut http_domains = BTreeSet::new();
    for (_, section) in nginx_sections(text, redactor) {
        http_domains.extend(parse_http_domains(&section));
    }
    let mut route_values: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut route_counts: BTreeMap<String, usize> = BTreeMap::new();
    let (route_target, topology_error) = match select_route_target(&topology, 443) {
        Err(err) => (Value::Null, Value::String(err.0)),
        Ok(selected) => {
            for (key, backend) in &selected.routes {
                let domain = lower(key);
                if !domain_shape_ok(&domain) {
                    continue;
                }
                route_values.entry(domain.clone()).or_default().insert(backend.clone());
                *route_counts.entry(domain).or_insert(0) += 1;
            }
            (
                json!({"source_file": selected.source_file, "source_variable": selected.source_variable,
                       "variable": selected.variable}),
                Value::Null,
            )
        }
    };
    let routes: Map<String, Value> = route_values
        .into_iter()
        .map(|(domain, backends)| (domain, json!(backends.into_iter().next().expect("one backend"))))
        .collect();
    let duplicates: Vec<&String> =
        route_counts.iter().filter(|(_, count)| **count > 1).map(|(domain, _)| domain).collect();
    let map_files: Map<String, Value> = files.into_iter().map(|(file, count)| (file, json!(count))).collect();
    Ok(json!({
        "available": true,
        "duplicate_sni_domains": duplicates,
        "http_domains": http_domains.into_iter().collect::<Vec<_>>(),
        "observation": "observed",
        "route_target": route_target,
        "sni_map_count": sni_maps,
        "sni_map_files": map_files,
        "sni_routes": routes,
        "stream_enabled": topology.stream_enabled,
        "topology_error": topology_error,
    }))
}

// ---------------------------------------------------------------------------------------------
// CAA and certificates
// ---------------------------------------------------------------------------------------------

/// `^\s*(\d{1,3})\s+(issue|issuewild|iodef)\s+"([^"\r\n]{0,255})"\s*$` on one line.
fn caa_line(line: &str) -> Option<(u32, String, String)> {
    let chars: Vec<char> = line.chars().collect();
    let mut pos = skip_space(&chars, 0);
    let digits_start = pos;
    while chars.get(pos).is_some_and(char::is_ascii_digit) {
        pos += 1;
    }
    let digits = pos - digits_start;
    if !(1..=3).contains(&digits) || !chars.get(pos).is_some_and(|c| is_space(*c)) {
        return None;
    }
    let flags: u32 = chars[digits_start..pos].iter().collect::<String>().parse().ok()?;
    pos = skip_space(&chars, pos);
    let tag_start = pos;
    let tag_end = ["issuewild", "issue", "iodef"]
        .iter()
        .filter_map(|tag| {
            let end = tag_start + tag.len();
            let candidate: String = chars.get(tag_start..end)?.iter().collect();
            (candidate.eq_ignore_ascii_case(tag) && chars.get(end).is_some_and(|c| is_space(*c))).then_some(end)
        })
        .next()?;
    let tag: String = chars[tag_start..tag_end].iter().collect::<String>().to_ascii_lowercase();
    pos = skip_space(&chars, tag_end);
    if chars.get(pos) != Some(&'"') {
        return None;
    }
    let value_start = pos + 1;
    let close = value_start + chars[value_start..].iter().position(|c| matches!(c, '"' | '\r' | '\n'))?;
    if chars[close] != '"' || close - value_start > 255 {
        return None;
    }
    if !chars[close + 1..].iter().all(|c| is_space(*c)) {
        return None;
    }
    Some((flags, tag, chars[value_start..close].iter().collect()))
}

fn canonical_caa_record(flags: u32, tag: &str, value: &str) -> Result<Value> {
    if flags > 255 {
        return Err(AuditError::failed("CAA response was malformed"));
    }
    if tag == "iodef" {
        return Ok(json!({"configured": !value.is_empty(), "flags": flags, "tag": "iodef"}));
    }
    let parts: Vec<&str> = value.split(';').collect();
    let raw_issuer = strip(parts[0]);
    let issuer = if raw_issuer.is_empty() {
        Value::Null
    } else {
        Value::String(validate_domain(raw_issuer).ok_or_else(|| AuditError::failed("CAA issuer is malformed"))?)
    };
    let mut record = Map::new();
    record.insert("flags".into(), json!(flags));
    record.insert("issuer".into(), issuer);
    record.insert("tag".into(), json!(tag));
    let mut parameters = BTreeSet::new();
    for raw in &parts[1..] {
        let parameter = strip(raw);
        if parameter.is_empty() {
            continue;
        }
        if parameter.matches('=').count() != 1 {
            return Err(AuditError::failed("CAA issuer parameter is malformed"));
        }
        let (key, parameter_value) = parameter.split_once('=').expect("one =");
        let key = lower(strip(key));
        let parameter_value = strip(parameter_value);
        if !parameters.insert(key.clone()) {
            return Err(AuditError::failed("CAA issuer parameter is duplicated"));
        }
        if key == "validationmethods" {
            let methods: BTreeSet<String> = parameter_value.split(',').map(|item| lower(strip(item))).collect();
            if methods.iter().any(|method| !CAA_VALIDATION_METHODS.contains(&method.as_str())) {
                return Err(AuditError::failed("CAA issuer parameter is unsupported"));
            }
            record.insert("validation_methods".into(), json!(methods.into_iter().collect::<Vec<_>>()));
        } else if key == "accounturi" {
            if !(parameter_value.starts_with("http://") || parameter_value.starts_with("https://"))
                || parameter_value.chars().count() > 255
                || parameter_value.chars().any(is_space)
            {
                return Err(AuditError::failed("CAA issuer parameter is malformed"));
            }
            record.insert("account_restricted".into(), json!(true));
        } else {
            return Err(AuditError::failed("CAA issuer parameter is unsupported"));
        }
    }
    Ok(Value::Object(record))
}

type CaaAnswer = (Vec<Value>, Vec<String>);

fn parse_caa_answer(text: &str) -> Result<CaaAnswer> {
    let mut records: BTreeMap<String, Value> = BTreeMap::new();
    let mut aliases: Vec<String> = Vec::new();
    for line in splitlines(text, false) {
        if strip(line).is_empty() {
            continue;
        }
        if let Some((flags, tag, value)) = caa_line(line) {
            let record = canonical_caa_record(flags, &tag, &value)?;
            records.insert(sort_key(&record), record);
            continue;
        }
        let alias = validate_domain(line).ok_or_else(|| AuditError::failed("CAA response was malformed"))?;
        if !aliases.contains(&alias) {
            aliases.push(alias);
        }
    }
    Ok((records.into_values().collect(), aliases))
}

struct CaaState {
    cache: BTreeMap<String, CaaAnswer>,
    queries: u32,
}

fn applicable_caa(
    domain: &str,
    runner: &CommandRunner<'_>,
    state: &mut CaaState,
) -> Result<(Vec<Value>, Option<String>)> {
    let mut current = domain.to_string();
    let mut visited = BTreeSet::new();
    while visited.insert(current.clone()) {
        if !state.cache.contains_key(&current) {
            state.queries += 1;
            if state.queries > CAA_QUERY_LIMIT {
                return Err(AuditError::failed("CAA query limit exceeded"));
            }
            let result = required_run(runner, &["dig", "+short", "CAA", &current], false)?;
            if result.returncode != 0 {
                return Err(AuditError::failed("CAA query failed"));
            }
            let answer = parse_caa_answer(&result.stdout)?;
            state.cache.insert(current.clone(), answer);
        }
        let (records, aliases) = state.cache[&current].clone();
        if !records.is_empty() {
            let source = aliases.last().cloned().unwrap_or_else(|| current.clone());
            return Ok((records, Some(source)));
        }
        if let Some(alias) = aliases.last() {
            current = alias.clone();
            continue;
        }
        match current.split_once('.') {
            None => return Ok((Vec::new(), None)),
            Some((_, parent)) => current = parent.to_string(),
        }
    }
    Err(AuditError::failed("CAA alias loop detected"))
}

fn caa_compatible(records: &[Value]) -> bool {
    let issue: Vec<&Value> = records.iter().filter(|record| record.get("tag") == Some(&json!("issue"))).collect();
    if issue.is_empty() {
        return true;
    }
    issue.iter().any(|record| {
        let methods = record.get("validation_methods");
        record.get("issuer") == Some(&json!("letsencrypt.org"))
            && record.get("account_restricted") != Some(&Value::Bool(true))
            && match methods {
                None => true,
                Some(Value::Array(items)) => items.iter().any(|item| item == "http-01"),
                Some(_) => false,
            }
    })
}

/// `DNS:([^,\s]+)` occurrences.
fn san_names(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut names = Vec::new();
    let mut pos = 0;
    while pos < chars.len() {
        if let Some(after) = literal(&chars, pos, "DNS:") {
            let mut end = after;
            while chars.get(end).is_some_and(|c| *c != ',' && !is_space(*c)) {
                end += 1;
            }
            if end > after {
                names.push(chars[after..end].iter().collect());
                pos = end;
                continue;
            }
        }
        pos += 1;
    }
    names
}

/// `(?m)^<key>=([A-Za-z0-9 :]+(?:GMT)?)$`: the first such line's value.
fn certificate_date(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    for line in text.split('\n') {
        let Some(value) = line.strip_prefix(&prefix) else { continue };
        if !value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b' ' || b == b':') {
            return Some(value.to_string());
        }
    }
    None
}

fn san_covers(name: &str, domain: &str) -> bool {
    match name.strip_prefix("*.") {
        None => name == domain,
        Some(suffix) => {
            domain.ends_with(&format!(".{suffix}")) && domain.split('.').count() == suffix.split('.').count() + 1
        }
    }
}

fn certificate_fact(domain: &str, runner: &CommandRunner<'_>) -> Result<Value> {
    let path = format!("/etc/letsencrypt/live/{domain}/fullchain.pem");
    let result =
        required_run(runner, &["openssl", "x509", "-in", &path, "-noout", "-dates", "-ext", "subjectAltName"], false)?;
    if result.returncode != 0 {
        return Ok(json!({"covers_domain": false, "present": false}));
    }
    let mut names = BTreeSet::new();
    for raw in san_names(&result.stdout) {
        let name = match raw.strip_prefix("*.") {
            Some(rest) => validate_domain(rest).map(|domain| format!("*.{domain}")),
            None => validate_domain(&raw),
        };
        names.extend(name);
    }
    let mut fact = Map::new();
    fact.insert("covers_domain".into(), json!(names.iter().any(|name| san_covers(name, domain))));
    fact.insert("names".into(), json!(names.iter().collect::<Vec<_>>()));
    fact.insert("present".into(), json!(true));
    for (key, label) in [("notBefore", "not_before"), ("notAfter", "not_after")] {
        if let Some(value) = certificate_date(&result.stdout, key) {
            fact.insert(label.into(), json!(value));
        }
    }
    Ok(Value::Object(fact))
}

// ---------------------------------------------------------------------------------------------
// Version, systemd and UFW facts
// ---------------------------------------------------------------------------------------------

/// Every end of `\d+(?:\.\d+){1,3}` at `pos`, in the order a backtracking engine tries them.
fn version_ends(chars: &[char], pos: usize) -> Vec<usize> {
    fn digits(chars: &[char], pos: usize) -> usize {
        let mut end = pos;
        while chars.get(end).is_some_and(char::is_ascii_digit) {
            end += 1;
        }
        end
    }
    fn groups(chars: &[char], pos: usize, done: usize, out: &mut Vec<usize>) {
        if done < 3 && chars.get(pos) == Some(&'.') {
            let max = digits(chars, pos + 1);
            for end in (pos + 2..=max).rev() {
                groups(chars, end, done + 1, out);
            }
        }
        if done >= 1 {
            out.push(pos);
        }
    }
    let mut out = Vec::new();
    let max = digits(chars, pos);
    for end in (pos + 1..=max).rev() {
        groups(chars, end, 0, &mut out);
    }
    out
}

fn version_fact(result: Option<&BoundedOutput>, observation: &str, bare: bool) -> Value {
    let Some(result) = result else { return json!({"available": false, "observation": observation}) };
    let chars: Vec<char> = result.stdout.chars().collect();
    let mut found: Option<String> = None;
    if bare {
        // `^\s*(\d+(?:\.\d+){1,3})\s*$`: `$` is the end or the end before a final newline.
        let start = skip_space(&chars, 0);
        if let Some(end) =
            version_ends(&chars, start).into_iter().find(|end| chars[*end..].iter().all(|c| is_space(*c)))
        {
            found = Some(chars[start..end].iter().collect());
        }
    } else {
        // `\bversion\s+(\d+(?:\.\d+){1,3})\b`, case-insensitive.
        'search: for pos in 0..chars.len() {
            if pos > 0 && is_word_char(chars[pos - 1]) {
                continue;
            }
            let Some(after) = literal_ci(&chars, pos, "version") else { continue };
            if !chars.get(after).is_some_and(|c| is_space(*c)) {
                continue;
            }
            let start = skip_space(&chars, after);
            for end in version_ends(&chars, start) {
                let boundary = !chars.get(end).is_some_and(|c| is_word_char(*c));
                if boundary {
                    found = Some(chars[start..end].iter().collect());
                    break 'search;
                }
            }
        }
    }
    let mut fact = json!({"available": true, "observation": observation});
    if let Some(version) = found {
        fact["version"] = json!(version);
    }
    fact
}

fn systemd_fact(result: Option<&BoundedOutput>, observation: &str) -> Value {
    let Some(result) = result else {
        return json!({"available": false, "observation": observation, "services": []});
    };
    let mut services = BTreeSet::new();
    for line in splitlines(&result.stdout, false) {
        let fields = split_whitespace(line);
        let Some(name) = fields.first() else { continue };
        if let Some(stem) = name.strip_suffix(".service") {
            if !stem.is_empty()
                && stem.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'@' | b'-'))
            {
                services.insert(name.to_string());
            }
        }
    }
    json!({"available": true, "observation": observation, "services": services.into_iter().collect::<Vec<_>>()})
}

/// `(?im)^Status:\s+active\s*$`.
fn ufw_active(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    (0..chars.len()).any(|pos| {
        if pos > 0 && chars[pos - 1] != '\n' {
            return false;
        }
        let Some(after) = literal_ci(&chars, pos, "status:") else { return false };
        if !chars.get(after).is_some_and(|c| is_space(*c)) {
            return false;
        }
        let Some(mut end) = literal_ci(&chars, skip_space(&chars, after), "active") else { return false };
        loop {
            match chars.get(end) {
                None | Some('\n') => return true,
                Some(c) if is_space(*c) => end += 1,
                Some(_) => return false,
            }
        }
    })
}

fn ufw_fact(config: &InstallerConfig, result: Option<&BoundedOutput>, observation: &str, ipv6: Option<bool>) -> Value {
    let active = result.is_some_and(|result| ufw_active(&result.stdout));
    let managed = config.host_mode == HostMode::Fresh && config.firewall.manage_ufw;
    json!({
        "active": active,
        "available": result.is_some(),
        "ipv6_enabled": ipv6,
        "mode": if managed { "managed" } else { "read_only" },
        "observation": observation,
    })
}

// ---------------------------------------------------------------------------------------------
// The audit
// ---------------------------------------------------------------------------------------------

fn required_run(runner: &CommandRunner<'_>, argv: &[&str], c_locale: bool) -> Result<BoundedOutput> {
    match runner.execute(argv, None, c_locale) {
        Err(AuditError::Unavailable) => Err(AuditError::failed("required audit command is unavailable")),
        other => other,
    }
}

fn required_capture(runner: &CommandRunner<'_>, argv: &[&str], c_locale: bool) -> Result<String> {
    let result = required_run(runner, argv, c_locale)?;
    if result.returncode != 0 {
        return Err(AuditError::failed(format!(
            "required audit command failed with exit status {}",
            result.returncode
        )));
    }
    Ok(result.stdout)
}

fn required_json(runner: &CommandRunner<'_>, argv: &[&str]) -> Result<Value> {
    let text = required_capture(runner, argv, false)?;
    pc_host::json::loads(text.as_bytes()).map_err(|_| AuditError::failed("command returned malformed JSON"))
}

fn optional_run(
    runner: &CommandRunner<'_>,
    argv: &[&str],
    c_locale: bool,
) -> Result<(Option<BoundedOutput>, &'static str)> {
    match runner.execute(argv, None, c_locale) {
        Err(AuditError::Unavailable) => Ok((None, "unavailable")),
        Err(AuditError::Interrupted) => Err(AuditError::Interrupted),
        Err(AuditError::Failed(_)) => Ok((None, "unknown")),
        Ok(result) if result.returncode != 0 => Ok((None, "unknown")),
        Ok(result) => Ok((Some(result), "observed")),
    }
}

fn identity_facts(runner: &CommandRunner<'_>) -> Result<Value> {
    let mut observed = Map::new();
    for (kind, database, identifiers) in [("uid", "passwd", RESERVED_UIDS), ("gid", "group", RESERVED_GIDS)] {
        let mut holders = Map::new();
        for identifier in identifiers {
            let identifier = identifier.to_string();
            let (result, _) = optional_run(runner, &["getent", database, &identifier], false)?;
            let Some(result) = result else { continue };
            let stripped = strip(&result.stdout);
            let Some(first) = splitlines(stripped, false).into_iter().next() else { continue };
            let name = first.split(':').next().unwrap_or_default();
            if !name.is_empty() && runner.redactor.safe_text(name, 64) {
                holders.insert(identifier, json!(name));
            }
        }
        observed.insert(kind.into(), Value::Object(holders));
    }
    Ok(Value::Object(observed))
}

/// `audit_host(config, runner)`: a deterministic, secret-free, read-only host snapshot. Every
/// failure is an [`AuditError`] whose message is a known one or `audit observation failed` with
/// one `[REDACTED]` per secret-looking match.
pub fn audit_host(config: &InstallerConfig, runner: &CommandRunner<'_>) -> Result<Audit> {
    match audit(config, runner) {
        Ok(audit) => Ok(audit),
        Err(AuditError::Interrupted) => Err(AuditError::Interrupted),
        Err(err) => Err(AuditError::Failed(runner.redactor.safe_audit_error(&err.message()))),
    }
}

fn platform_os() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else {
        std::env::consts::OS
    }
}

fn audit(config: &InstallerConfig, runner: &CommandRunner<'_>) -> Result<Audit> {
    let redactor = &runner.redactor;
    let mut domains = Vec::new();
    for domain in config.required_domains() {
        domains.push(
            validate_domain(&domain)
                .ok_or_else(|| AuditError::failed("a plain fully-qualified domain name is required"))?,
        );
    }

    let machine = required_capture(runner, &["uname", "-m"], false)?;
    let architecture =
        SAFE_ARCHITECTURES.iter().find(|(name, _)| *name == strip(&machine)).map_or("unknown", |(_, value)| *value);
    let disks = parse_disks(&required_capture(runner, &["df", "-Pk"], false)?, redactor);
    let (available_memory, total_memory) = parse_memory(&required_capture(runner, &["free", "-b"], true)?);
    let addresses = parse_addresses(&required_json(runner, &["ip", "-j", "address"])?);
    let local_addresses: BTreeSet<String> =
        addresses.iter().filter_map(|item| item["address"].as_str()).map(str::to_string).collect();
    let mut listeners =
        listeners_value(&parse_listener_lines(&required_capture(runner, &["ss", "-H", "-lntup"], false)?));
    let (ssh_socket, _) = optional_run(
        runner,
        &["systemctl", "show", "ssh.socket", "--property=Listen", "--value", "--no-pager"],
        false,
    )?;
    listeners.insert(
        "ssh_socket_tcp".into(),
        json!(ssh_socket.map(|result| parse_ssh_socket_ports(&result.stdout)).unwrap_or_default()),
    );

    let (nginx_result, nginx_observation) = optional_run(runner, &["nginx", "-T"], false)?;
    let nginx = match &nginx_result {
        Some(result) => parse_nginx_observation(&result.stdout, redactor)?,
        None => empty_nginx(nginx_observation),
    };
    let (docker, docker_observation) = optional_run(runner, &["docker", "--version"], false)?;
    let (compose, compose_observation) = optional_run(runner, &["docker", "compose", "version", "--short"], false)?;
    let (systemd, systemd_observation) =
        optional_run(runner, &["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"], false)?;
    let (ufw, ufw_observation) = optional_run(runner, &["ufw", "status", "verbose"], true)?;
    let (ufw_config, _) = optional_run(runner, &UFW_IPV6_CONFIG_COMMAND, false)?;

    let xray_present = required_run(runner, &["test", "-f", XRAY_CONFIG], false)?.returncode == 0;
    let inbounds = if xray_present {
        parse_xray_inbounds(&required_json(runner, &["cat", XRAY_CONFIG])?, redactor)
    } else {
        Vec::new()
    };
    let installer_present = required_run(runner, &["test", "-f", INSTALLER_STATE], false)?.returncode == 0;

    let mut dns = Map::new();
    let mut certificates = Map::new();
    let mut unhandled_aaaa = Vec::new();
    let mut caa_mismatch = Vec::new();
    let mut caa_state = CaaState { cache: BTreeMap::new(), queries: 0 };
    for domain in &domains {
        let (ipv4, ipv6) = runner.resolve(domain)?;
        let (caa, caa_source) = applicable_caa(domain, runner, &mut caa_state)?;
        let compatible = caa_compatible(&caa);
        let aaaa_handled = ipv6.is_empty() || ipv6.iter().all(|address| local_addresses.contains(address));
        if !aaaa_handled {
            unhandled_aaaa.push(domain.clone());
        }
        if !compatible {
            caa_mismatch.push(domain.clone());
        }
        dns.insert(
            domain.clone(),
            json!({
                "a": ipv4,
                "aaaa": ipv6,
                "a_matches_local": ipv4.iter().any(|address| local_addresses.contains(address)),
                "aaaa_handled": aaaa_handled,
                "caa": caa,
                "caa_compatible": compatible,
                "caa_source": caa_source,
            }),
        );
        certificates.insert(domain.clone(), certificate_fact(domain, runner)?);
    }

    let mut stops = Vec::new();
    if !unhandled_aaaa.is_empty() {
        stops.push(HardStop {
            code: "dns.unhandled_aaaa".into(),
            message: "AAAA records point outside addresses handled by this host".into(),
            domains: unhandled_aaaa,
        });
    }
    if !caa_mismatch.is_empty() {
        stops.push(HardStop {
            code: "dns.caa_mismatch".into(),
            message: "CAA records do not authorize Let's Encrypt".into(),
            domains: caa_mismatch,
        });
    }
    let cloud = OperatorPrerequisite {
        code: "cloud_firewall.reachability".into(),
        status: "operator_required".into(),
        message: "Verify required inbound ports in the external cloud firewall".into(),
    };
    let prerequisites = json!({
        "hard_stops": stops.iter().map(|stop| json!({"code": stop.code, "domains": stop.domains, "message": stop.message}))
            .collect::<Vec<_>>(),
        "operator_prerequisites": [{"code": cloud.code, "message": cloud.message, "status": cloud.status}],
    });

    let stable_disks: Vec<Value> = disks
        .iter()
        .map(|item| json!({"filesystem": item["filesystem"], "mount": item["mount"], "total_kib": item["total_kib"]}))
        .collect();
    let platform = json!({
        "addresses": addresses,
        "architecture": architecture,
        "disks": stable_disks,
        "memory": {"total_bytes": total_memory},
        "os": platform_os(),
    });
    let transient = json!({
        "capacity": {"disks": disks, "memory": {"available_bytes": available_memory, "total_bytes": total_memory}},
    });
    let topology = json!({
        "certificates": certificates,
        "dns": dns,
        "nginx": nginx,
        "three_xui": {"inbounds": inbounds, "installed": xray_present},
    });
    let ownership = json!({
        "identities": identity_facts(runner)?,
        "compose": version_fact(compose.as_ref(), compose_observation, true),
        "docker": version_fact(docker.as_ref(), docker_observation, false),
        "installer": {"present": installer_present},
        "systemd": systemd_fact(systemd.as_ref(), systemd_observation),
        "three_xui": {"mode": config.three_xui.mode.value(), "present": xray_present},
        "ufw": ufw_fact(config, ufw.as_ref(), ufw_observation, ufw_config.and_then(|result| parse_ufw_ipv6_config(&result.stdout))),
    });
    let object = |value: Value| match value {
        Value::Object(map) => map,
        _ => unreachable!("built as an object"),
    };
    let facts = AuditFacts {
        platform: object(platform),
        listeners,
        ownership: object(ownership),
        topology: object(topology),
        prerequisites: object(prerequisites),
        transient: object(transient),
    };
    let mut hard_stops = stops;
    hard_stops.sort();
    Ok(Audit { facts, hard_stops, operator_prerequisites: vec![cloud] })
}

// ---------------------------------------------------------------------------------------------
// The real executor (C locale) and the DNS child
// ---------------------------------------------------------------------------------------------

/// The bounded contract of `SystemRunner::bounded` with `LC_ALL=C` and without `LANGUAGE` (a
/// helper for `pc_host`: `HostRunner::bounded` takes no environment).
fn c_locale_bounded(argv: &[&str], limits: Bounded) -> std::result::Result<BoundedOutput, BoundedError> {
    pc_host::runner::validate_argv(argv)?;
    let cancel = pc_host::runner::interrupt_flag();
    let mut command = Command::new(argv[0]);
    command.args(&argv[1..]).env("LC_ALL", "C").env_remove("LANGUAGE");
    // SAFETY: `setsid` is async-signal-safe; nothing else runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child =
        command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                BoundedError::Unavailable
            } else {
                BoundedError::CouldNotExecute
            }
        })?;
    let kill = |child: &mut std::process::Child| {
        // SAFETY: plain syscall on the child's own process group.
        unsafe {
            libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
        }
        let _ = child.wait();
    };
    let deadline = Instant::now() + limits.timeout;
    let mut streams: [Option<std::fs::File>; 2] = [
        child.stdout.take().map(|s| std::fs::File::from(std::os::fd::OwnedFd::from(s))),
        child.stderr.take().map(|s| std::fs::File::from(std::os::fd::OwnedFd::from(s))),
    ];
    let mut chunks: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    let mut captured = 0usize;
    let mut buffer = vec![0u8; 65536];
    while streams.iter().any(Option::is_some) {
        let now = Instant::now();
        if now >= deadline {
            kill(&mut child);
            return Err(BoundedError::TimedOut);
        }
        if cancel.load(Ordering::SeqCst) {
            kill(&mut child);
            return Err(BoundedError::Interrupted);
        }
        let mut polls: Vec<libc::pollfd> = Vec::new();
        let mut owners = Vec::new();
        for (index, stream) in streams.iter().enumerate() {
            if let Some(stream) = stream {
                polls.push(libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLIN, revents: 0 });
                owners.push(index);
            }
        }
        let wait = (deadline - now).min(Duration::from_millis(20)).as_millis() as i32;
        // SAFETY: `polls` holds valid descriptors owned by `streams`.
        let rc = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, wait) };
        if rc < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            kill(&mut child);
            return Err(BoundedError::CouldNotExecute);
        }
        for (poll, index) in polls.iter().zip(owners) {
            if poll.revents == 0 {
                continue;
            }
            let stream = streams[index].as_mut().expect("polled stream is open");
            let want = (limits.max_output - captured + 1).min(buffer.len());
            let read = loop {
                match stream.read(&mut buffer[..want]) {
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    other => break other,
                }
            };
            let Ok(read) = read else {
                kill(&mut child);
                return Err(BoundedError::CouldNotExecute);
            };
            if read == 0 {
                streams[index] = None;
                continue;
            }
            captured += read;
            if captured > limits.max_output {
                kill(&mut child);
                return Err(BoundedError::OutputLimit);
            }
            chunks[index].extend_from_slice(&buffer[..read]);
        }
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => {
                kill(&mut child);
                return Err(BoundedError::CouldNotExecute);
            }
        }
        if Instant::now() >= deadline {
            kill(&mut child);
            return Err(BoundedError::TimedOut);
        }
        if cancel.load(Ordering::SeqCst) {
            kill(&mut child);
            return Err(BoundedError::Interrupted);
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = String::from_utf8_lossy(&chunks[0]).into_owned();
    let stderr = String::from_utf8_lossy(&chunks[1]).into_owned();
    if stdout.len() + stderr.len() > limits.max_output {
        return Err(BoundedError::OutputLimit);
    }
    let returncode = status.code().unwrap_or_else(|| -status.signal().unwrap_or(0));
    Ok(BoundedOutput { returncode, stdout, stderr })
}

/// `_resolver_worker`: what the child sends back (`o` + `4|6 <address>` lines, `l`, or `e`).
fn resolver_message(resolver: &dyn Resolver, name: &str) -> Vec<u8> {
    let Ok(answers) = resolver.getaddrinfo(name) else { return b"e".to_vec() };
    let mut message = b"o".to_vec();
    let mut count = 0;
    for (family, address) in answers {
        let Some(value) = (!address.is_empty()).then(|| canonical_ip(&address)).flatten() else { continue };
        if count >= RESOLVER_RESULT_LIMIT {
            return b"l".to_vec();
        }
        count += 1;
        message.extend_from_slice(match family {
            Family::Inet => b"4 ",
            Family::Inet6 => b"6 ",
        });
        message.extend_from_slice(value.as_bytes());
        message.push(b'\n');
    }
    message
}

fn alive(pid: libc::pid_t) -> bool {
    let mut status = 0;
    // SAFETY: waitpid on our own child; WNOHANG never blocks.
    unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) == 0 }
}

fn join(pid: libc::pid_t, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !alive(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// `_stop_worker`: terminate, then kill, and reap.
fn stop_worker(pid: libc::pid_t) {
    if !alive(pid) {
        return;
    }
    // SAFETY: signals to our own child.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    if join(pid, Duration::from_millis(200)) {
        return;
    }
    // SAFETY: as above; the blocking wait reaps it.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
}

fn readable(fd: RawFd, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        let wait = deadline.saturating_duration_since(now).as_millis().min(i32::MAX as u128) as i32;
        let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut poll, 1, wait) };
        if rc > 0 {
            return true;
        }
        if rc == 0 || Instant::now() >= deadline {
            return false;
        }
    }
}

/// `_bounded_resolve(resolver, name, timeout)`: `getaddrinfo` in a forked child that is killed
/// when it does not answer in time.
fn bounded_resolve(resolver: &dyn Resolver, name: &str, timeout: Duration) -> Result<(Vec<String>, Vec<String>)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: a two-element array for pipe(2).
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(AuditError::failed(std::io::Error::last_os_error().to_string()));
    }
    // SAFETY: fork(2); the child only resolves, writes to the pipe and `_exit`s.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // SAFETY: closing the pipe we just created.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Err(AuditError::failed(std::io::Error::last_os_error().to_string()));
    }
    if pid == 0 {
        // SAFETY: the child never returns into the caller.
        unsafe { libc::close(fds[0]) };
        let message = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| resolver_message(resolver, name)))
            .unwrap_or_else(|_| b"e".to_vec());
        let mut written = 0;
        while written < message.len() {
            // SAFETY: writing our own buffer to our own pipe end.
            let rc = unsafe { libc::write(fds[1], message[written..].as_ptr().cast(), message.len() - written) };
            if rc <= 0 {
                break;
            }
            written += rc as usize;
        }
        // SAFETY: leave without running the parent's destructors or atexit handlers.
        unsafe { libc::_exit(0) };
    }
    // SAFETY: the parent keeps only the read end.
    unsafe { libc::close(fds[1]) };
    // SAFETY: the read end is ours from here on.
    let mut receiver = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let outcome = (|| {
        if !readable(receiver.as_raw_fd(), timeout) {
            stop_worker(pid);
            return Err(AuditError::failed("DNS resolution timed out"));
        }
        let mut message = Vec::new();
        if receiver.read_to_end(&mut message).is_err() || message.is_empty() {
            stop_worker(pid);
            return Err(AuditError::failed("DNS resolution failed"));
        }
        if !join(pid, Duration::from_millis(200)) {
            stop_worker(pid);
            return Err(AuditError::failed("DNS resolution failed"));
        }
        match message[0] {
            b'o' => Ok(message[1..].to_vec()),
            b'l' => Err(AuditError::failed("DNS resolution result limit exceeded")),
            _ => Err(AuditError::failed("DNS resolution failed")),
        }
    })();
    stop_worker(pid);
    let body = outcome?;
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();
    for line in String::from_utf8_lossy(&body).lines() {
        match line.split_once(' ') {
            Some(("4", address)) => {
                ipv4.insert(address.to_string());
            }
            Some(("6", address)) => {
                ipv6.insert(address.to_string());
            }
            _ => {}
        }
    }
    Ok((ipv4.into_iter().collect(), ipv6.into_iter().collect()))
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
