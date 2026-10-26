//! The interactive installer (`installer/wizard.py` and the `wizard` command of
//! `installer/cli.py`): line reads from stdin, no raw mode, no ANSI, no screen clearing; every
//! question, validator, review row and the save/apply/digest flows in English and Russian,
//! byte for byte (golden `wizard/{en,ru}/*.json`).
//!
//! - [`TerminalIO`] is `TerminalIO`: prompts without a newline and flushed, `write` adds one;
//!   EOF and the answers `quit`/`q`/`выход` (any case, on every prompt) stop the wizard;
//!   hidden input clears `ECHO` with `termios` (`TCSADRAIN`), restores it afterwards and prints a
//!   newline; without a terminal it reads silently.
//! - [`Wizard`] is `TerminalWizard`: [`Wizard::run`] returns the configuration on `apply`,
//!   [`Stop::Saved`] after `save`, [`Stop::Quit`] for every way out.
//! - [`run_wizard_command`] is `cli._wizard`: the run, then the plan through the
//!   [`WizardEngine`] callback the `installer` binary provides, the summary, the digest prompt,
//!   staged credentials around the apply, and the status.
//!
//! Differences from Python (DIFFERENCES.md):
//! - Ctrl-C (and SIGTERM/SIGHUP/SIGQUIT) during a hidden password prompt restores the terminal's
//!   echo before the signal takes its usual course (Python restored it in a `finally`).
//! - `save` writes the configuration atomically (temporary file, `fsync`, `rename`) with the mode
//!   Python's `write_text` gave it (the existing file's, else `0666 & ~umask`); a missing parent
//!   directory is still an error (host inventory §12 #4).
//! - Invalid UTF-8 on stdin is decoded with replacement characters (Python stopped with a
//!   `UnicodeDecodeError`).
//! - Port numbers, AmneziaWG ports and integers are ASCII digits (Python's `int`/`isdigit` also
//!   took other Unicode digits).
//! - `CredentialError` is `BLOCKED: <message>` with exit 2 instead of a Python traceback.
//! - `TerminalIO.routes` is not ported: the wizard never asked for routes.

use std::io::{BufRead, Write};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

use serde_json::{json, Map, Value};

use crate::awg_ports::{bound_ports, machine_id, pick_ports};
use crate::cli::{blocked_line, confirmation_matches, installed_version, plan_summary_lines, StatusView};
use crate::config::{normalize_domain, parse_config, render_config, safe_name, ConfigError};
use crate::credentials::{discard_staged_credentials, stage_operator_credentials, write_credentials, OperatorCredentials};
use crate::i18n::{locale_from_environment, parse_locale, text, try_text, Locale};
use crate::model::{
    AmneziaWgConfig, DomainConfig, EgressChoice, EgressConfig, FirewallConfig, HostMode, InstallerConfig, MieruConfig,
    Profile, ThreeXuiConfig, ThreeXuiMode, TrustTunnelConfig, AWG_DEFAULT_DNS, AWG_DEFAULT_MTU, AWG_VERSIONS,
    DEFAULT_LANE_SLOTS, DEFAULT_RELAY_PORT, TT_DEFAULT_LISTEN_PORT,
};
use crate::planner::{AuditFacts, InstallPlan};
use crate::pystr::{is_space, lower, py_path_str, strip};

/// The Mieru ports the examples and the lab use.
pub const DEFAULT_MIERU_PORTS: [u16; 1] = [46001];

/// Every 3x-ui mode; `managed-new` is offered on a fresh host only.
pub const OFFERED_THREE_XUI_MODES: [ThreeXuiMode; 3] = ThreeXuiMode::ALL;

/// Review rows that carry no operator choice (`_REVIEW_HIDDEN`).
pub const REVIEW_HIDDEN: [&str; 5] =
    ["schema", "amneziawg.dns", "amneziawg.mtu", "trusttunnel.hostname", "trusttunnel.listen_port"];

/// Review rows hidden while they hold their «off» value (`_REVIEW_HIDDEN_WHEN`).
pub const REVIEW_HIDDEN_WHEN: [(&str, &str); 4] = [
    ("egress.relay_port", "0"),
    ("mieru.lane_slots", "0"),
    ("egress.warp_port", "40000"),
    ("three_xui.warp_port", "40000"),
];

/// How the wizard stopped without a configuration to apply.
#[derive(Debug, Clone, PartialEq)]
pub enum Stop {
    /// `WizardQuit`: EOF, `quit`, or the `quit` action; nothing was changed.
    Quit,
    /// `WizardSaved`: the configuration was exported to `path`.
    Saved { config: Box<InstallerConfig>, path: PathBuf },
    /// An error the CLI reports as `BLOCKED: <message>` (exit 2).
    Error(String),
}

type Step<T> = Result<T, Stop>;

/// The text of a refused answer: a catalogue key with its values (`PromptValidationError`), or
/// the generic `invalid_value` (`ValueError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Message(&'static str, Vec<(&'static str, String)>),
    Generic,
}

fn refuse<T>(key: &'static str) -> Result<T, Refusal> {
    Err(Refusal::Message(key, Vec::new()))
}

// ---------------------------------------------------------------------------------------------
// The terminal
// ---------------------------------------------------------------------------------------------

/// `TerminalIO`: line reads from `input`, prompts and lines to `output`.
pub struct TerminalIO<R, W> {
    input: R,
    output: W,
    /// The descriptor whose `ECHO` flag a hidden prompt clears (stdin), when it is a terminal.
    echo_fd: Option<RawFd>,
    pub locale: Locale,
}

impl TerminalIO<std::io::StdinLock<'static>, std::io::Stdout> {
    /// The process's stdin and stdout (the binary's terminal).
    pub fn stdio() -> Self {
        TerminalIO { input: std::io::stdin().lock(), output: std::io::stdout(), echo_fd: Some(0), locale: Locale::En }
    }
}

impl<R: BufRead, W: Write> TerminalIO<R, W> {
    /// A terminal over any streams; hidden prompts read silently (no `termios`), like Python with
    /// a `StringIO`.
    pub fn new(input: R, output: W) -> Self {
        TerminalIO { input, output, echo_fd: None, locale: Locale::En }
    }

    /// Hidden prompts clear `ECHO` on `fd` (when it is a terminal).
    pub fn with_echo_fd(mut self, fd: RawFd) -> Self {
        self.echo_fd = Some(fd);
        self
    }

    pub fn output(&self) -> &W {
        &self.output
    }

    pub fn into_output(self) -> W {
        self.output
    }

    pub fn set_locale(&mut self, locale: Locale) {
        self.locale = locale;
    }

    fn feedback(&mut self, key: &str, values: &[(&str, &str)]) {
        let message = text(self.locale, key, values);
        self.write(&message);
    }

    fn put(&mut self, value: &str) {
        let _ = self.output.write_all(value.as_bytes());
        let _ = self.output.flush();
    }

    /// `write(value)`: the value and a newline, flushed.
    pub fn write(&mut self, value: &str) {
        self.put(&format!("{value}\n"));
    }

    /// One raw line (`readline()`), `None` at EOF.
    fn read_raw(&mut self) -> std::io::Result<Option<String>> {
        let mut buffer = Vec::new();
        let read = self.input.read_until(b'\n', &mut buffer)?;
        if read == 0 {
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(&buffer).into_owned()))
    }

    /// `read_line(prompt, echo=…, strip=…)`.
    pub fn read_line(&mut self, prompt: &str, echo: bool, strip_answer: bool) -> Step<String> {
        self.put(prompt);
        let hidden = if echo { None } else { self.echo_fd.and_then(EchoGuard::hide) };
        let value = self.read_raw();
        if let Some(guard) = hidden {
            drop(guard);
            self.write("");
        }
        let value = value.map_err(|err| Stop::Error(err.to_string()))?;
        let Some(value) = value else { return Err(Stop::Quit) };
        let raw = value.strip_suffix('\n').unwrap_or(&value);
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let result = if strip_answer { strip(raw).to_string() } else { raw.to_string() };
        if matches!(lower(&result).as_str(), "quit" | "q" | "выход") {
            return Err(Stop::Quit);
        }
        Ok(result)
    }

    /// `choose_enum(prompt, choices, default=…)`: the chosen value.
    pub fn choose(&mut self, prompt: &str, choices: &[&'static str], default: Option<&'static str>) -> Step<&'static str> {
        let values = choices.join("/");
        let suffix = default.map(|value| format!(" [{value}]")).unwrap_or_default();
        loop {
            let answer = self.read_line(&format!("{prompt} ({values}){suffix}: "), true, true)?;
            let mut raw = lower(strip(&answer));
            if raw.is_empty() {
                if let Some(default) = default {
                    return Ok(default);
                }
            }
            if raw == "save-config" && choices.contains(&"save") {
                raw = "save".into();
            }
            if let Some(selected) = choices.iter().find(|choice| **choice == raw) {
                return Ok(selected);
            }
            self.feedback("invalid_choice", &[("choices", &values)]);
        }
    }

    /// `validated(prompt, validator, default=…, allow_empty=…)`.
    pub fn validated(
        &mut self,
        prompt: &str,
        validator: &dyn Fn(&str) -> Result<String, Refusal>,
        default: Option<&str>,
        allow_empty: bool,
    ) -> Step<String> {
        let suffix = default.map(|value| format!(" [{value}]")).unwrap_or_default();
        loop {
            let mut raw = self.read_line(&format!("{prompt}{suffix}: "), true, true)?;
            if raw.is_empty() && allow_empty {
                return Ok(String::new());
            }
            if raw.is_empty() {
                if let Some(default) = default {
                    raw = default.to_string();
                }
            }
            match validator(&raw) {
                Ok(value) => return Ok(value),
                Err(Refusal::Message(key, values)) => {
                    let values: Vec<(&str, &str)> = values.iter().map(|(name, value)| (*name, value.as_str())).collect();
                    self.feedback(key, &values);
                }
                Err(Refusal::Generic) => self.feedback("invalid_value", &[]),
            }
        }
    }

    /// `integer(prompt, minimum=…, maximum=…, default=…)`.
    pub fn integer(&mut self, prompt: &str, minimum: i64, maximum: i64, default: Option<i64>) -> Step<i64> {
        let validate = move |value: &str| -> Result<String, Refusal> {
            let Some(parsed) = python_int(value) else { return refuse("invalid_integer") };
            if parsed < i128::from(minimum) || parsed > i128::from(maximum) {
                return Err(Refusal::Message(
                    "invalid_range",
                    vec![("minimum", minimum.to_string()), ("maximum", maximum.to_string())],
                ));
            }
            Ok(parsed.to_string())
        };
        let rendered = default.map(|value| value.to_string());
        let value = self.validated(prompt, &validate, rendered.as_deref(), false)?;
        Ok(value.parse().expect("validated integer"))
    }

    /// `ports(prompt, default=…, minimum=…)`.
    pub fn ports(&mut self, prompt: &str, default: &[u16], minimum: u16) -> Step<Vec<u16>> {
        let rendered: Vec<String> = default.iter().map(u16::to_string).collect();
        let rendered = rendered.join(",");
        let validate = move |value: &str| -> Result<String, Refusal> {
            let parts: Vec<&str> = value.split(',').map(strip).collect();
            if parts.iter().any(|part| part.is_empty()) {
                return refuse("invalid_ports");
            }
            let mut ports: Vec<i128> = Vec::new();
            for part in parts {
                let Some(port) = python_int(part) else { return refuse("invalid_ports") };
                if port < i128::from(minimum) || port > 65535 {
                    return Err(Refusal::Message("invalid_port_range", vec![("minimum", minimum.to_string())]));
                }
                if ports.contains(&port) {
                    return refuse("duplicate_ports");
                }
                ports.push(port);
            }
            Ok(ports.iter().map(i128::to_string).collect::<Vec<_>>().join(","))
        };
        let default = (!rendered.is_empty()).then_some(rendered.as_str());
        let value = self.validated(prompt, &validate, default, false)?;
        Ok(value.split(',').map(|part| part.parse().expect("validated port")).collect())
    }

    /// `yes_no(prompt, default=…)`.
    pub fn yes_no(&mut self, prompt: &str, default: bool) -> Step<bool> {
        let suffix = if default { "Y/n" } else { "y/N" };
        loop {
            let answer = self.read_line(&format!("{prompt} [{suffix}]: "), true, true)?;
            let raw = lower(strip(&answer));
            if raw.is_empty() {
                return Ok(default);
            }
            if matches!(raw.as_str(), "y" | "yes" | "д" | "да") {
                return Ok(true);
            }
            if matches!(raw.as_str(), "n" | "no" | "н" | "нет") {
                return Ok(false);
            }
            self.feedback("invalid_yes_no", &[]);
        }
    }
}

/// `int(value, 10)` for ASCII digits: surrounding whitespace, a sign, `_` between digits.
fn python_int(value: &str) -> Option<i128> {
    let value = strip(value);
    let (negative, digits) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let mut number: i128 = 0;
    for byte in digits.bytes() {
        match byte {
            b'_' => {}
            b'0'..=b'9' => number = number.saturating_mul(10).saturating_add(i128::from(byte - b'0')),
            _ => return None,
        }
    }
    Some(if negative { -number } else { number })
}

/// The descriptor whose echo a signal handler must restore, and its saved settings.
static HIDDEN_FD: AtomicI32 = AtomicI32::new(-1);
static mut SAVED_TERMIOS: std::mem::MaybeUninit<libc::termios> = std::mem::MaybeUninit::uninit();
const RESTORED_SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];
static mut PREVIOUS_ACTIONS: std::mem::MaybeUninit<[libc::sigaction; 4]> = std::mem::MaybeUninit::uninit();

extern "C" fn restore_echo_and_reraise(signal: libc::c_int) {
    let fd = HIDDEN_FD.swap(-1, Ordering::SeqCst);
    // SAFETY: `tcsetattr`, `sigaction` and `raise` are async-signal-safe; the statics were
    // written before the handler was installed and are not written while it is.
    unsafe {
        if fd >= 0 {
            libc::tcsetattr(fd, libc::TCSADRAIN, (*std::ptr::addr_of!(SAVED_TERMIOS)).as_ptr());
        }
        let previous = &*(*std::ptr::addr_of!(PREVIOUS_ACTIONS)).as_ptr();
        if let Some(index) = RESTORED_SIGNALS.iter().position(|candidate| *candidate == signal) {
            libc::sigaction(signal, &previous[index], std::ptr::null_mut());
        }
        libc::raise(signal);
    }
}

/// Echo off for one hidden prompt; dropping it restores the terminal and the signal actions.
struct EchoGuard {
    fd: RawFd,
}

impl EchoGuard {
    /// `tcgetattr` + clear `ECHO` with `TCSADRAIN`; `None` when `fd` is not a terminal.
    fn hide(fd: RawFd) -> Option<EchoGuard> {
        // SAFETY: plain termios and sigaction calls on our own descriptor and statics; the
        // statics are written before the handler that reads them is installed.
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut saved) != 0 {
                return None;
            }
            (*std::ptr::addr_of_mut!(SAVED_TERMIOS)).write(saved);
            let mut previous: [libc::sigaction; 4] = std::mem::zeroed();
            for (index, signal) in RESTORED_SIGNALS.iter().enumerate() {
                libc::sigaction(*signal, std::ptr::null(), &mut previous[index]);
            }
            (*std::ptr::addr_of_mut!(PREVIOUS_ACTIONS)).write(previous);
            HIDDEN_FD.store(fd, Ordering::SeqCst);
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = restore_echo_and_reraise as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            for signal in RESTORED_SIGNALS {
                libc::sigaction(signal, &action, std::ptr::null_mut());
            }
            let mut hidden = saved;
            hidden.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(fd, libc::TCSADRAIN, &hidden) != 0 {
                let guard = EchoGuard { fd };
                drop(guard);
                return None;
            }
        }
        Some(EchoGuard { fd })
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: restoring what `hide` saved; the handler is removed first.
        unsafe {
            let previous = *(*std::ptr::addr_of!(PREVIOUS_ACTIONS)).as_ptr();
            for (index, signal) in RESTORED_SIGNALS.iter().enumerate() {
                libc::sigaction(*signal, &previous[index], std::ptr::null_mut());
            }
            if HIDDEN_FD.swap(-1, Ordering::SeqCst) >= 0 {
                libc::tcsetattr(self.fd, libc::TCSADRAIN, (*std::ptr::addr_of!(SAVED_TERMIOS)).as_ptr());
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------------------------

/// `_domain`: `strip().lower().rstrip(".")` and the domain rule.
pub fn domain(value: &str) -> Result<String, Refusal> {
    normalize_domain(value).ok_or(Refusal::Message("invalid_domain", Vec::new()))
}

/// `_awg_versions`: a comma-separated subset of the AmneziaWG versions, in their canonical order.
pub fn awg_versions(value: &str) -> Result<String, Refusal> {
    let parts: Vec<&str> = value.split(',').map(strip).filter(|part| !part.is_empty()).collect();
    let mut unique = parts.clone();
    unique.sort();
    unique.dedup();
    if parts.is_empty() || unique.len() != parts.len() || parts.iter().any(|part| !AWG_VERSIONS.contains(part)) {
        return refuse("invalid_awg_versions");
    }
    Ok(AWG_VERSIONS.iter().filter(|version| parts.contains(version)).copied().collect::<Vec<_>>().join(","))
}

/// `_awg_ports(count)`: `count` distinct UDP ports from 1024, in the order of the versions.
pub fn awg_ports(count: usize) -> impl Fn(&str) -> Result<String, Refusal> {
    move |value: &str| {
        let fail = || Refusal::Message("invalid_awg_ports", vec![("count", count.to_string())]);
        let parts: Vec<&str> = value.split(',').map(strip).collect();
        if parts.len() != count || !parts.iter().all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())) {
            return Err(fail());
        }
        let ports: Vec<u128> = parts.iter().map(|part| part.parse().unwrap_or(u128::MAX)).collect();
        let mut unique = ports.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != count || !ports.iter().all(|port| (1024..=65535).contains(port)) {
            return Err(fail());
        }
        Ok(ports.iter().map(u128::to_string).collect::<Vec<_>>().join(","))
    }
}

/// `_awg_host`: an IPv4 address (normalised) or a DNS name.
pub fn awg_host(value: &str) -> Result<String, Refusal> {
    let normalized = lower(strip(value)).trim_end_matches('.').to_string();
    if let Ok(address) = crate::ipaddr::ipv4_address(&normalized) {
        return Ok(address);
    }
    if !crate::config::domain_shape_ok(&normalized) {
        return refuse("invalid_awg_host");
    }
    Ok(normalized)
}

/// `_warp_selector`: a domain (optionally `domain:`-prefixed) or a `geosite:` list.
pub fn warp_selector(value: &str) -> Result<String, Refusal> {
    let normalized = lower(strip(value));
    if let Some(name) = normalized.strip_prefix("geosite:") {
        let ok = !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if !ok || name.contains('\n') {
            return refuse("invalid_domains");
        }
        return Ok(normalized);
    }
    if let Some(name) = normalized.strip_prefix("domain:") {
        return Ok(format!("domain:{}", domain(name)?));
    }
    domain(&normalized)
}

/// `_email`: `[^\s@]+@[^\s@]+\.[^\s@]+` after `strip()`.
pub fn email(value: &str) -> Result<String, Refusal> {
    let normalized = strip(value);
    let shape = || {
        if normalized.chars().any(is_space) {
            return false;
        }
        let mut parts = normalized.split('@');
        let (Some(local), Some(host), None) = (parts.next(), parts.next(), parts.next()) else { return false };
        let host: Vec<char> = host.chars().collect();
        !local.is_empty() && host.len() >= 3 && host[1..host.len() - 1].contains(&'.')
    };
    if !shape() {
        return refuse("invalid_email");
    }
    Ok(normalized.to_string())
}

/// `_safe_name`: `[A-Za-z0-9_-]{1,64}` after `strip()`.
pub fn name(value: &str) -> Result<String, Refusal> {
    let normalized = strip(value);
    if !safe_name(normalized) {
        return refuse("invalid_name");
    }
    Ok(normalized.to_string())
}

/// `_domains` (the 3x-ui WARP list): one or more unique selectors.
fn warp_domains(value: &str) -> Result<String, Refusal> {
    let mut domains = Vec::new();
    for part in value.split(',').filter(|part| !strip(part).is_empty()) {
        domains.push(warp_selector(part)?);
    }
    if domains.is_empty() {
        return refuse("invalid_domains");
    }
    let mut unique = domains.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != domains.len() {
        return refuse("duplicate_domains");
    }
    Ok(domains.join(","))
}

/// `pinned_version(name)`: the version `release/external-artifacts.json` of `tree` pins, or `?`.
pub fn pinned_version(tree: &Path, name: &str) -> String {
    let document = std::fs::read(tree.join("release/external-artifacts.json"))
        .ok()
        .and_then(|data| serde_json::from_slice::<Value>(&data).ok());
    let found = document.as_ref().and_then(|document| document.get("artifacts")?.as_array()).and_then(|artifacts| {
        artifacts.iter().find(|artifact| artifact.get("name").and_then(Value::as_str) == Some(name))?.get("version").cloned()
    });
    match found {
        Some(Value::String(version)) => version,
        Some(Value::Null) | None => "?".into(),
        Some(other) => other.to_string(),
    }
}

/// `_optional(value)`: `None` for an absent or empty answer.
fn optional(value: &Option<String>) -> Option<String> {
    value.clone().filter(|value| !value.is_empty())
}

// ---------------------------------------------------------------------------------------------
// The wizard
// ---------------------------------------------------------------------------------------------

/// `EditField`.
const EDIT_PANEL: &str = "domains.panel";
const EDIT_MTPROXY: &str = "domains.mtproxy";
const EDIT_SUBSCRIPTION: &str = "domains.subscription";
const EDIT_MCP: &str = "domains.mcp";
const EDIT_NAIVE: &str = "domains.naive";
const EDIT_MIERU: &str = "domains.mieru";
const EDIT_ACME_EMAIL: &str = "acme_email";
const EDIT_INITIAL_USER: &str = "initial_user";
const EDIT_MIERU_TCP: &str = "mieru.tcp_ports";
const EDIT_MIERU_UDP: &str = "mieru.udp_ports";
const EDIT_XUI_PANEL: &str = "three_xui.panel_domain";
const EDIT_XUI_TCP: &str = "three_xui.vless_tcp_domain";
const EDIT_XUI_XHTTP: &str = "three_xui.vless_xhttp_domain";
const EDIT_XUI_HYSTERIA: &str = "three_xui.hysteria_domain";
const EDIT_AMNEZIAWG: &str = "amneziawg";
const EDIT_TRUSTTUNNEL: &str = "trusttunnel";
const EDIT_WARP: &str = "three_xui.warp";
const EDIT_FIREWALL: &str = "firewall.manage_ufw";

/// The answers so far (Python's `values` dict: `None` is an absent key).
#[derive(Debug, Clone)]
struct Values {
    host_mode: HostMode,
    profile: Profile,
    xui_mode: ThreeXuiMode,
    panel: String,
    mtproxy: String,
    subscription: Option<String>,
    mcp: Option<String>,
    naive: Option<String>,
    mieru: Option<String>,
    mieru_tcp: Option<Vec<u16>>,
    mieru_udp: Option<Vec<u16>>,
    xui_panel: Option<String>,
    xui_tcp: Option<String>,
    xui_xhttp: Option<String>,
    xui_hysteria: Option<String>,
    warp: Option<bool>,
    warp_domains: Option<Vec<String>>,
    router: Option<bool>,
    router_naive: Option<bool>,
    router_mieru: Option<bool>,
    warp_naive: Option<bool>,
    warp_mieru: Option<bool>,
    awg: Option<bool>,
    awg_versions: Option<String>,
    awg_host: Option<String>,
    awg_ports: Option<String>,
    awg_port_map: Option<Vec<(String, u16)>>,
    tt: Option<bool>,
    tt_domain: Option<String>,
    acme_email: String,
    initial_user: String,
    panel_password: Option<String>,
    xui_username: Option<String>,
    xui_password: Option<String>,
    manage_ufw: bool,
}

impl Values {
    fn services(&self) -> Vec<&'static str> {
        let mut services = Vec::new();
        if self.profile.includes_naive() {
            services.push("naive");
        }
        if self.profile.includes_mieru() {
            services.push("mieru");
        }
        services
    }

    fn router_for(&self, service: &str) -> Option<bool> {
        if service == "naive" {
            self.router_naive
        } else {
            self.router_mieru
        }
    }

    fn set_router_for(&mut self, service: &str, value: Option<bool>) {
        if service == "naive" {
            self.router_naive = value;
        } else {
            self.router_mieru = value;
        }
    }

    fn set_warp_for(&mut self, service: &str, value: Option<bool>) {
        if service == "naive" {
            self.warp_naive = value;
        } else {
            self.warp_mieru = value;
        }
    }

    /// `_egress_choice(values, service)`.
    fn egress_choice(&self, service: &str) -> EgressChoice {
        let (router, warp) =
            if service == "naive" { (self.router_naive, self.warp_naive) } else { (self.router_mieru, self.warp_mieru) };
        if router.unwrap_or(false) {
            EgressChoice::Router
        } else if warp.unwrap_or(false) {
            EgressChoice::Warp
        } else {
            EgressChoice::Direct
        }
    }
}

/// How the wizard is set up (`TerminalWizard(io, locale=…, config_output=…, root=…,
/// language_fixed=…)`), plus what Python read from the process.
#[derive(Debug, Clone)]
pub struct WizardOptions {
    /// `--lang`, or a default language for the language question.
    pub locale: Option<Locale>,
    /// `--lang` was given: the language is not asked.
    pub language_fixed: bool,
    pub config_output: PathBuf,
    /// Where `/etc/machine-id` is read from, for the pre-chosen AmneziaWG ports.
    pub root: PathBuf,
    /// `LC_ALL` or `LANG` ([`crate::i18n::environment_locale_value`]).
    pub environment_locale: Option<String>,
    /// The pinned Xray-core version the router question names ([`pinned_version`]).
    pub xray_version: String,
}

/// `TerminalWizard`.
pub struct Wizard {
    options: WizardOptions,
    /// The language in use once chosen (`None` until then when it is asked).
    pub locale: Option<Locale>,
    listeners: Map<String, Value>,
    /// What the operator typed, handed to the CLI on «apply» (never written there).
    pub credentials: Option<OperatorCredentials>,
}

impl Wizard {
    pub fn new(options: WizardOptions) -> Wizard {
        let locale = options.locale;
        let language_fixed = options.language_fixed && locale.is_some();
        Wizard { options: WizardOptions { language_fixed, ..options }, locale, listeners: Map::new(), credentials: None }
    }

    fn locale(&self) -> Locale {
        self.locale.expect("the language is chosen first")
    }

    fn text(&self, key: &str) -> String {
        text(self.locale(), key, &[])
    }

    /// `run(facts)`: the configuration to apply, or how the wizard stopped.
    pub fn run<R: BufRead, W: Write>(&mut self, io: &mut TerminalIO<R, W>, facts: &AuditFacts) -> Step<InstallerConfig> {
        self.listeners = facts.listeners.clone();
        let default_locale =
            self.locale.unwrap_or_else(|| locale_from_environment(self.options.environment_locale.as_deref()));
        io.set_locale(default_locale);
        if self.options.language_fixed {
            self.locale = Some(default_locale);
        } else {
            let selected = io.choose(&text(default_locale, "language", &[]), &["en", "ru"], Some(default_locale.value()))?;
            self.locale = Some(parse_locale(Some(selected), Locale::En).map_err(Stop::Error)?);
        }
        io.set_locale(self.locale());
        self.warn_if_installed(io, facts)?;
        io.write(&self.text("secrets_notice"));
        let mut values = self.collect(io)?;
        loop {
            let config = match self.config(&values) {
                Ok(config) => config,
                Err(err) => {
                    io.write(&text(self.locale(), "invalid_config", &[("reason", &err.0)]));
                    self.edit(io, &mut values)?;
                    continue;
                }
            };
            self.review(io, &config);
            let action =
                io.choose(&self.text("action"), &["apply", "back", "edit", "save", "quit"], Some("apply"))?;
            match action {
                "apply" => {
                    self.credentials = chosen_credentials(&values)?;
                    return Ok(config);
                }
                "quit" => return Err(Stop::Quit),
                "save" => {
                    save_config(&self.options.config_output, &render_config(&config))?;
                    let shown = py_path_str(&self.options.config_output.to_string_lossy());
                    io.write(&text(self.locale(), "saved", &[("path", &shown)]));
                    self.save_credentials(io, &values)?;
                    return Err(Stop::Saved { config: Box::new(config), path: self.options.config_output.clone() });
                }
                "back" => {
                    let last = *self.editable(&values).last().expect("fields");
                    self.prompt_field(io, &mut values, last)?;
                }
                _ => self.edit(io, &mut values)?,
            }
        }
    }

    /// `_warn_if_installed`: point at `--update`; quit (the default) or reinstall.
    fn warn_if_installed<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, facts: &AuditFacts) -> Step<()> {
        let installed = facts.ownership.get("installed").filter(|value| truthy(value));
        let present = facts.ownership.get("installer").and_then(|value| value.get("present")).is_some_and(truthy);
        if installed.is_none() && !present {
            return Ok(());
        }
        let version = match installed.and_then(|value| value.get("version")) {
            Some(Value::String(version)) => version.clone(),
            Some(value) if truthy(value) => value.to_string(),
            _ => String::new(),
        };
        if version.is_empty() {
            io.write(&self.text("already_installed_unknown"));
        } else {
            io.write(&text(self.locale(), "already_installed", &[("version", &version)]));
        }
        io.write(&self.text("reinstall_help"));
        if io.choose(&self.text("reinstall"), &["quit", "continue"], Some("quit"))? == "quit" {
            return Err(Stop::Quit);
        }
        Ok(())
    }

    fn collect<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>) -> Step<Values> {
        io.write(&self.text("host_mode_help"));
        let host_mode = match io.choose(&self.text("host_mode"), &["fresh", "coexist"], Some("fresh"))? {
            "fresh" => HostMode::Fresh,
            _ => HostMode::Coexist,
        };
        io.write(&self.text("profile_help"));
        let profile = match io.choose(&self.text("profile"), &["core", "core-naive", "core-mieru", "full"], Some("full"))? {
            "core" => Profile::Core,
            "core-naive" => Profile::CoreNaive,
            "core-mieru" => Profile::CoreMieru,
            _ => Profile::Full,
        };
        io.write(&self.text("three_xui_mode_help"));
        let offered: &[&'static str] =
            if host_mode == HostMode::Fresh { &["none", "existing", "managed-new"] } else { &["none", "existing"] };
        let xui_mode = match io.choose(&self.text("three_xui_mode"), offered, Some("none"))? {
            "none" => ThreeXuiMode::None,
            "existing" => ThreeXuiMode::Existing,
            _ => ThreeXuiMode::ManagedNew,
        };
        let panel = io.validated(&self.text("panel_domain"), &domain, None, false)?;
        let mtproxy = io.validated(&self.text("mtproxy_domain"), &domain, None, false)?;
        let subscription = io.validated(&self.text("subscription_domain"), &domain, None, true)?;
        let mcp = io.validated(&self.text("mcp_domain"), &domain, None, true)?;
        let mut values = Values {
            host_mode,
            profile,
            xui_mode,
            panel,
            mtproxy,
            subscription: Some(subscription),
            mcp: Some(mcp),
            naive: None,
            mieru: None,
            mieru_tcp: None,
            mieru_udp: None,
            xui_panel: None,
            xui_tcp: None,
            xui_xhttp: None,
            xui_hysteria: None,
            warp: None,
            warp_domains: None,
            router: None,
            router_naive: None,
            router_mieru: None,
            warp_naive: None,
            warp_mieru: None,
            awg: None,
            awg_versions: None,
            awg_host: None,
            awg_ports: None,
            awg_port_map: None,
            tt: None,
            tt_domain: None,
            acme_email: String::new(),
            initial_user: String::new(),
            panel_password: None,
            xui_username: None,
            xui_password: None,
            manage_ufw: false,
        };
        if profile.includes_naive() {
            values.naive = Some(io.validated(&self.text("naive_domain"), &domain, None, false)?);
        }
        if profile.includes_mieru() {
            values.mieru = Some(io.validated(&self.text("mieru_domain"), &domain, None, false)?);
            values.mieru_tcp = Some(io.ports(&self.text("mieru_tcp_ports"), &DEFAULT_MIERU_PORTS, 1024)?);
            values.mieru_udp = Some(io.ports(&self.text("mieru_udp_ports"), &DEFAULT_MIERU_PORTS, 1024)?);
        }
        match xui_mode {
            ThreeXuiMode::ManagedNew => self.managed_xui(io, &mut values)?,
            ThreeXuiMode::Existing => self.existing_xui(io, &mut values)?,
            ThreeXuiMode::None => {}
        }
        if xui_mode != ThreeXuiMode::ManagedNew && (profile.includes_naive() || profile.includes_mieru()) {
            values.warp = Some(io.yes_no(&self.text("warp"), false)?);
        }
        self.egress_choices(io, &mut values)?;
        self.amneziawg_choices(io, &mut values)?;
        self.trusttunnel_choices(io, &mut values)?;
        self.trusttunnel_router_choice(io, &mut values)?;
        values.acme_email = io.validated(&self.text("acme_email"), &email, None, false)?;
        values.initial_user = io.validated(&self.text("initial_user"), &name, None, false)?;
        values.panel_password = self.password(io, "panel_password", "panel_password_again")?;
        if xui_mode == ThreeXuiMode::ManagedNew {
            values.xui_username = Some(io.validated(&self.text("xui_username"), &name, None, false)?);
            values.xui_password = self.password(io, "xui_password", "xui_password_again")?;
        }
        values.manage_ufw =
            if host_mode == HostMode::Fresh { io.yes_no(&self.text("manage_ufw"), true)? } else { false };
        Ok(values)
    }

    fn save_credentials<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, values: &Values) -> Step<()> {
        let Some(chosen) = chosen_credentials(values)? else { return Ok(()) };
        let path = write_credentials(&self.options.config_output, &chosen).map_err(|err| Stop::Error(err.0))?;
        let shown = py_path_str(&path.to_string_lossy());
        io.write(&text(self.locale(), "credentials_saved", &[("path", &shown)]));
        Ok(())
    }

    /// `_password`: asked twice without echo; a blank answer keeps it generated.
    fn password<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, prompt: &str, repeat: &str) -> Step<Option<String>> {
        loop {
            let first = io.read_line(&format!("{}: ", self.text(prompt)), false, true)?;
            if first.is_empty() {
                return Ok(None);
            }
            let second = io.read_line(&format!("{}: ", self.text(repeat)), false, true)?;
            if first != second {
                io.write(&self.text("password_mismatch"));
                continue;
            }
            if OperatorCredentials::new(Some("owner"), Some(&first), None, None).is_err() {
                io.write(&self.text("invalid_password"));
                continue;
            }
            return Ok(Some(first));
        }
    }

    fn amneziawg_choices<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, values: &mut Values) -> Step<()> {
        io.write(&self.text("amneziawg_help"));
        if !io.yes_no(&self.text("amneziawg"), false)? {
            values.awg_versions = None;
            values.awg_host = None;
            values.awg_ports = None;
            values.awg_port_map = None;
            values.awg = Some(false);
            return Ok(());
        }
        values.awg = Some(true);
        let default_versions = optional(&values.awg_versions).unwrap_or_else(|| AWG_VERSIONS.join(","));
        values.awg_versions =
            Some(io.validated(&self.text("amneziawg_versions"), &awg_versions, Some(&default_versions), false)?);
        let default_host = optional(&values.awg_host).unwrap_or_else(|| values.panel.clone());
        values.awg_host = Some(io.validated(&self.text("amneziawg_host"), &awg_host, Some(&default_host), false)?);
        values.awg_ports = Some(self.awg_port_answer(io, values)?);
        Ok(())
    }

    fn trusttunnel_choices<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, values: &mut Values) -> Step<()> {
        io.write(&self.text("trusttunnel_help"));
        if !io.yes_no(&self.text("trusttunnel"), false)? {
            values.tt_domain = None;
            values.tt = Some(false);
            return Ok(());
        }
        values.tt = Some(true);
        let default = optional(&values.tt_domain);
        values.tt_domain = Some(io.validated(&self.text("trusttunnel_domain"), &domain, default.as_deref(), false)?);
        Ok(())
    }

    fn router_prompt(&self) -> String {
        text(self.locale(), "router", &[("version", &self.options.xray_version)])
    }

    fn trusttunnel_router_choice<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, values: &mut Values) -> Step<()> {
        if values.profile.includes_naive() || values.profile.includes_mieru() {
            return Ok(());
        }
        if values.tt.unwrap_or(false) {
            values.router = Some(io.yes_no(&self.router_prompt(), false)?);
        } else {
            values.router = None;
        }
        Ok(())
    }

    /// `_awg_ports`: the UDP ports in version order; the default is a free host-stable pick.
    fn awg_port_answer<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, values: &mut Values) -> Step<String> {
        let versions: Vec<String> =
            values.awg_versions.clone().unwrap_or_default().split(',').map(str::to_string).collect();
        let kept: Vec<(String, u16)> = values
            .awg_port_map
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|(version, _)| versions.contains(version))
            .collect();
        let mut taken: std::collections::BTreeSet<i64> = values
            .mieru_tcp
            .iter()
            .chain(values.mieru_udp.iter())
            .flatten()
            .map(|port| i64::from(*port))
            .collect();
        taken.extend(bound_ports(&self.listeners));
        let config_error = |err: ConfigError| Stop::Error(err.0);
        let identity = machine_id(&self.options.root).map_err(config_error)?;
        let picks = pick_ports(&versions, &identity, &taken, &kept).map_err(config_error)?;
        io.write(&self.text("amneziawg_ports_help"));
        let prompt = text(
            self.locale(),
            "amneziawg_ports",
            &[("versions", &versions.join(", ")), ("count", &versions.len().to_string())],
        );
        let default: Vec<String> = picks.iter().map(u16::to_string).collect();
        let validator = awg_ports(versions.len());
        let value = io.validated(&prompt, &validator, Some(&default.join(",")), false)?;
        values.awg_port_map = Some(
            versions.iter().cloned().zip(value.split(',').map(|port| port.parse::<u16>().expect("validated"))).collect(),
        );
        Ok(value)
    }

    /// `_egress_choices`: the router first, then WARP for each service not handed to it.
    fn egress_choices<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, values: &mut Values) -> Step<()> {
        let services = values.services();
        if services.is_empty() {
            values.router = None;
        } else {
            values.router = Some(io.yes_no(&self.router_prompt(), false)?);
        }
        for service in ["naive", "mieru"] {
            if values.router.unwrap_or(false) && services.contains(&service) {
                let answer = io.yes_no(&self.text(&format!("router_{service}")), true)?;
                values.set_router_for(service, Some(answer));
            } else {
                values.set_router_for(service, None);
            }
        }
        if !values.warp.unwrap_or(false) {
            values.warp_naive = None;
            values.warp_mieru = None;
            return Ok(());
        }
        let default = values.warp_domains.as_ref().is_none_or(Vec::is_empty);
        for service in services {
            if values.router_for(service).unwrap_or(false) {
                values.set_warp_for(service, None);
                continue;
            }
            let answer = io.yes_no(&self.text(&format!("warp_{service}")), default)?;
            values.set_warp_for(service, Some(answer));
        }
        Ok(())
    }

    fn managed_xui<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, values: &mut Values) -> Step<()> {
        values.xui_panel = Some(io.validated(&self.text("xui_panel_domain"), &domain, None, false)?);
        values.xui_tcp = Some(io.validated(&self.text("xui_vless_tcp_domain"), &domain, None, false)?);
        values.xui_xhttp = Some(io.validated(&self.text("xui_vless_xhttp_domain"), &domain, None, false)?);
        values.xui_hysteria = Some(io.validated(&self.text("xui_hysteria_domain"), &domain, None, false)?);
        let warp = io.yes_no(&self.text("warp"), false)?;
        values.warp = Some(warp);
        values.warp_domains = Some(if warp { self.domains(io)? } else { Vec::new() });
        Ok(())
    }

    /// `_existing_xui`: the two VLESS names, each may stay blank, at least one is needed.
    fn existing_xui<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, values: &mut Values) -> Step<()> {
        loop {
            io.write(&self.text("xui_existing_help"));
            let tcp = io.validated(&self.text("xui_vless_tcp_domain"), &domain, None, true)?;
            let xhttp = io.validated(&self.text("xui_vless_xhttp_domain"), &domain, None, true)?;
            if !tcp.is_empty() || !xhttp.is_empty() {
                if !tcp.is_empty() {
                    values.xui_tcp = Some(tcp);
                }
                if !xhttp.is_empty() {
                    values.xui_xhttp = Some(xhttp);
                }
                return Ok(());
            }
            io.write(&self.text("xui_existing_required"));
        }
    }

    fn domains<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>) -> Step<Vec<String>> {
        let value = io.validated(&self.text("warp_domains"), &warp_domains, None, false)?;
        Ok(value.split(',').map(str::to_string).collect())
    }

    /// `_config(values)`: the typed configuration, round-tripped through the TOML writer and
    /// parser (the parser's checks name what is wrong).
    fn config(&self, values: &Values) -> Result<InstallerConfig, ConfigError> {
        let profile = values.profile;
        let router = values.router.unwrap_or(false);
        let mut domains = DomainConfig::new(&values.panel, &values.mtproxy);
        domains.naive = profile.includes_naive().then(|| values.naive.clone().unwrap_or_default());
        domains.mieru = profile.includes_mieru().then(|| values.mieru.clone().unwrap_or_default());
        domains.subscription = optional(&values.subscription);
        domains.mcp = optional(&values.mcp);
        domains.trusttunnel = values.tt.unwrap_or(false).then(|| values.tt_domain.clone().unwrap_or_default());
        let mut three_xui = ThreeXuiConfig::new(values.xui_mode);
        three_xui.panel_domain = optional(&values.xui_panel);
        three_xui.vless_tcp_domain = optional(&values.xui_tcp);
        three_xui.vless_xhttp_domain = optional(&values.xui_xhttp);
        three_xui.hysteria_domain = optional(&values.xui_hysteria);
        three_xui.warp = values.warp.unwrap_or(false);
        three_xui.warp_domains = values.warp_domains.clone().unwrap_or_default();
        let candidate = InstallerConfig {
            schema: 1,
            host_mode: values.host_mode,
            profile,
            acme_email: values.acme_email.clone(),
            initial_user: values.initial_user.clone(),
            domains,
            mieru: profile.includes_mieru().then(|| MieruConfig {
                tcp_ports: values.mieru_tcp.clone().unwrap_or_default(),
                udp_ports: values.mieru_udp.clone().unwrap_or_default(),
                lane_slots: if router { DEFAULT_LANE_SLOTS } else { 0 },
            }),
            three_xui,
            firewall: FirewallConfig { manage_ufw: values.manage_ufw },
            egress: Some(EgressConfig {
                warp: values.warp.unwrap_or(false),
                router,
                naive: values.egress_choice("naive"),
                mieru: values.egress_choice("mieru"),
                relay_port: if router { DEFAULT_RELAY_PORT } else { 0 },
                ..EgressConfig::default()
            }),
            ingress: None,
            amneziawg: values.awg.unwrap_or(false).then(|| AmneziaWgConfig {
                host: values.awg_host.clone().unwrap_or_default(),
                versions: values.awg_versions.clone().unwrap_or_default().split(',').map(str::to_string).collect(),
                ports: values
                    .awg_ports
                    .clone()
                    .unwrap_or_default()
                    .split(',')
                    .map(|port| port.parse().unwrap_or(0))
                    .collect(),
                mtu: AWG_DEFAULT_MTU,
                dns: AWG_DEFAULT_DNS.iter().map(|value| value.to_string()).collect(),
            }),
            trusttunnel: values.tt.unwrap_or(false).then(|| TrustTunnelConfig {
                hostname: values.tt_domain.clone().unwrap_or_default(),
                listen_port: TT_DEFAULT_LISTEN_PORT,
            }),
        };
        parse_config(&render_config(&candidate))
    }

    fn review<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, config: &InstallerConfig) {
        io.write("");
        io.write(&self.text("review_title"));
        io.write(&self.text("review_header"));
        let without_xui = config.three_xui.mode == ThreeXuiMode::None;
        for (key, value) in flatten(&config.canonical_dict(), "") {
            let hidden_when = REVIEW_HIDDEN_WHEN.iter().any(|(name, off)| *name == key && *off == value);
            if value == "None"
                || REVIEW_HIDDEN.contains(&key.as_str())
                || hidden_when
                || (without_xui && key.starts_with("three_xui.") && key != "three_xui.mode")
            {
                continue;
            }
            let shown = match value.as_str() {
                "true" => self.text("yes"),
                "false" => self.text("no"),
                _ => value,
            };
            io.write(&format!("{} | {shown}", self.review_label(&key)));
        }
        io.write(&self.text("secrets_notice"));
    }

    /// `_review_label`: the operator's name for a key; an unlisted key keeps its own.
    fn review_label(&self, key: &str) -> String {
        try_text(self.locale(), &format!("review_{}", key.replace('.', "_")), &[]).unwrap_or_else(|_| key.to_string())
    }

    /// `_editable(values)`.
    fn editable(&self, values: &Values) -> Vec<&'static str> {
        let mut fields = vec![
            EDIT_PANEL,
            EDIT_MTPROXY,
            EDIT_SUBSCRIPTION,
            EDIT_MCP,
            EDIT_ACME_EMAIL,
            EDIT_INITIAL_USER,
            EDIT_AMNEZIAWG,
            EDIT_TRUSTTUNNEL,
        ];
        if values.profile.includes_naive() {
            fields.push(EDIT_NAIVE);
        }
        if values.profile.includes_mieru() {
            fields.extend([EDIT_MIERU, EDIT_MIERU_TCP, EDIT_MIERU_UDP]);
        }
        match values.xui_mode {
            ThreeXuiMode::ManagedNew => fields.extend([EDIT_XUI_PANEL, EDIT_XUI_TCP, EDIT_XUI_XHTTP, EDIT_XUI_HYSTERIA]),
            ThreeXuiMode::Existing => fields.extend([EDIT_XUI_TCP, EDIT_XUI_XHTTP]),
            ThreeXuiMode::None => {}
        }
        if values.xui_mode == ThreeXuiMode::ManagedNew || values.profile.includes_naive() || values.profile.includes_mieru()
        {
            fields.push(EDIT_WARP);
        }
        if values.host_mode == HostMode::Fresh {
            fields.push(EDIT_FIREWALL);
        }
        fields
    }

    fn edit<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, values: &mut Values) -> Step<()> {
        let fields = self.editable(values);
        let field = io.choose(&self.text("edit_field"), &fields, None)?;
        self.prompt_field(io, values, field)
    }

    fn prompt_field<R: BufRead, W: Write>(&self, io: &mut TerminalIO<R, W>, values: &mut Values, field: &str) -> Step<()> {
        let existing = values.xui_mode == ThreeXuiMode::Existing;
        let domain_field = |io: &mut TerminalIO<R, W>, slot: &mut Option<String>, message: &str, optional_answer: bool| {
            let default = optional(slot);
            let answer = io.validated(&self.text(message), &domain, default.as_deref(), optional_answer)?;
            *slot = Some(answer);
            Ok::<(), Stop>(())
        };
        match field {
            EDIT_PANEL => {
                let mut slot = Some(values.panel.clone());
                domain_field(io, &mut slot, "panel_domain", false)?;
                values.panel = slot.unwrap_or_default();
            }
            EDIT_MTPROXY => {
                let mut slot = Some(values.mtproxy.clone());
                domain_field(io, &mut slot, "mtproxy_domain", false)?;
                values.mtproxy = slot.unwrap_or_default();
            }
            EDIT_SUBSCRIPTION => domain_field(io, &mut values.subscription, "subscription_domain", true)?,
            EDIT_MCP => domain_field(io, &mut values.mcp, "mcp_domain", true)?,
            EDIT_NAIVE => domain_field(io, &mut values.naive, "naive_domain", false)?,
            EDIT_MIERU => domain_field(io, &mut values.mieru, "mieru_domain", false)?,
            EDIT_XUI_PANEL => domain_field(io, &mut values.xui_panel, "xui_panel_domain", existing)?,
            EDIT_XUI_TCP => domain_field(io, &mut values.xui_tcp, "xui_vless_tcp_domain", existing)?,
            EDIT_XUI_XHTTP => domain_field(io, &mut values.xui_xhttp, "xui_vless_xhttp_domain", existing)?,
            EDIT_XUI_HYSTERIA => domain_field(io, &mut values.xui_hysteria, "xui_hysteria_domain", existing)?,
            EDIT_ACME_EMAIL => {
                values.acme_email =
                    io.validated(&self.text("acme_email"), &email, Some(&values.acme_email.clone()), false)?;
            }
            EDIT_INITIAL_USER => {
                values.initial_user =
                    io.validated(&self.text("initial_user"), &name, Some(&values.initial_user.clone()), false)?;
            }
            EDIT_MIERU_TCP => {
                let default = values.mieru_tcp.clone().unwrap_or_default();
                values.mieru_tcp = Some(io.ports(&self.text("mieru_tcp_ports"), &default, 1024)?);
            }
            EDIT_MIERU_UDP => {
                let default = values.mieru_udp.clone().unwrap_or_default();
                values.mieru_udp = Some(io.ports(&self.text("mieru_udp_ports"), &default, 1024)?);
            }
            EDIT_WARP => {
                let warp = io.yes_no(&self.text("warp"), values.warp.unwrap_or(false))?;
                values.warp = Some(warp);
                values.warp_domains = Some(if warp && values.xui_mode == ThreeXuiMode::ManagedNew {
                    self.domains(io)?
                } else {
                    Vec::new()
                });
                self.egress_choices(io, values)?;
                self.trusttunnel_router_choice(io, values)?;
            }
            EDIT_AMNEZIAWG => self.amneziawg_choices(io, values)?,
            EDIT_TRUSTTUNNEL => {
                self.trusttunnel_choices(io, values)?;
                self.trusttunnel_router_choice(io, values)?;
            }
            _ => values.manage_ufw = io.yes_no(&self.text("manage_ufw"), values.manage_ufw)?,
        }
        Ok(())
    }
}

/// Python truthiness of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `_chosen_credentials(values)`: the panel login is always `owner`; `None` when every value is
/// left to the installer.
fn chosen_credentials(values: &Values) -> Step<Option<OperatorCredentials>> {
    let password = optional(&values.panel_password);
    let username = optional(&values.xui_username);
    let xui_password = optional(&values.xui_password);
    let chosen =
        OperatorCredentials::new(Some("owner"), password.as_deref(), username.as_deref(), xui_password.as_deref())
            .map_err(|err| Stop::Error(err.0))?;
    if password.is_none() && username.is_none() && xui_password.is_none() {
        return Ok(None);
    }
    Ok(Some(chosen))
}

/// `_flatten(value)`: dotted keys in sorted order, lists joined with `,`, booleans lowercased,
/// `None` as `None`.
pub fn flatten(value: &Value, prefix: &str) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
                rows.extend(flatten(item, &path));
            }
        }
        Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(python_str).collect();
            rows.push((prefix.to_string(), rendered.join(",")));
        }
        Value::Bool(flag) => rows.push((prefix.to_string(), flag.to_string())),
        other => rows.push((prefix.to_string(), python_str(other))),
    }
    rows
}

/// `str(value)` of a scalar of the canonical configuration.
fn python_str(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The current umask (from `/proc/self/status`, without changing it), else `022`.
fn current_umask() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Umask:"))
                .and_then(|value| u32::from_str_radix(value.trim(), 8).ok())
        })
        .unwrap_or(0o022)
}

/// `config_output.write_text(render_config(config))`, made atomic: the existing file's mode or
/// `0666 & ~umask`, and a missing directory is Python's `FileNotFoundError`.
fn save_config(path: &Path, rendered: &str) -> Step<()> {
    use std::os::unix::fs::PermissionsExt;
    let shown = path.to_string_lossy().into_owned();
    let error = |err: std::io::Error| Stop::Error(crate::pystr::os_error_message(&err, &shown));
    let parent = pc_host::fs::py_parent(path);
    if !parent.is_dir() {
        return Err(error(std::io::Error::from_raw_os_error(if parent.exists() { libc::ENOTDIR } else { libc::ENOENT })));
    }
    let mode = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Err(error(std::io::Error::from_raw_os_error(libc::EISDIR))),
        Ok(metadata) => metadata.permissions().mode() & 0o7777,
        Err(_) => 0o666 & !current_umask(),
    };
    pc_host::fs::atomic_write(path, rendered.as_bytes(), mode, None).map_err(error)
}

// ---------------------------------------------------------------------------------------------
// The `wizard` command
// ---------------------------------------------------------------------------------------------

/// Why the engine side of the wizard stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// A refusal the CLI prints as `BLOCKED: <message>` (exit 2): `str(exc)`, or the class name
    /// when the message is empty.
    Blocked(String),
    /// The operator interrupted the audit or the installation (exit 130).
    Interrupted,
}

/// What the wizard needs from the installer binary: the audit, the planner and the engine
/// (`CliServices.audit/plan/engine`). The binary implements it with the real audit, adapters and
/// `TransactionEngine`; tests replay recorded plans.
pub trait WizardEngine {
    /// `services.audit(config)` → `services.plan(config, facts)` → `_validate_plan(config, facts,
    /// plan)`: the plan whose digest the operator confirms.
    fn plan(&mut self, config: &InstallerConfig) -> Result<InstallPlan, EngineError>;
    /// `services.engine.apply(plan, accepted_digest=plan.digest)`: the journal state after it.
    /// The operator's typed credentials are staged around this call by [`run_wizard_command`].
    fn apply(&mut self, plan: &InstallPlan) -> Result<StatusView, EngineError>;
}

/// The `wizard` subcommand's arguments plus what the binary knows about its host.
#[derive(Debug, Clone)]
pub struct WizardCommand {
    /// `--root`.
    pub root: PathBuf,
    /// `--lang`.
    pub lang: Option<Locale>,
    /// `--config-output`.
    pub config_output: PathBuf,
    /// `--json`: the final status as JSON.
    pub json: bool,
    /// `LC_ALL` or `LANG`.
    pub environment_locale: Option<String>,
    /// The pinned Xray-core version of the release tree.
    pub xray_version: String,
}

/// `cli._wizard` with `run`'s error handling: the exit status (0, 2 for `BLOCKED:` on
/// `stderr`, 130 for an interrupt). The plan summary, the prompts and the status go to the
/// terminal's output.
pub fn run_wizard_command<R: BufRead, W: Write>(
    io: &mut TerminalIO<R, W>,
    stderr: &mut dyn Write,
    command: &WizardCommand,
    engine: &mut dyn WizardEngine,
) -> i32 {
    let blocked = |stderr: &mut dyn Write, message: &str| {
        let _ = stderr.write_all(blocked_line(message).as_bytes());
        let _ = stderr.flush();
        2
    };
    let mut wizard = Wizard::new(WizardOptions {
        locale: command.lang,
        language_fixed: command.lang.is_some(),
        config_output: command.config_output.clone(),
        root: command.root.clone(),
        environment_locale: command.environment_locale.clone(),
        xray_version: command.xray_version.clone(),
    });
    let mut facts = AuditFacts::default();
    if let Some(version) = installed_version(&command.root) {
        facts.ownership.insert("installed".into(), json!({"version": version}));
    }
    let selected = |wizard: &Wizard| wizard.locale.or(command.lang).unwrap_or(Locale::En);
    let config = match wizard.run(io, &facts) {
        Ok(config) => config,
        Err(Stop::Saved { .. }) => return 0,
        Err(Stop::Quit) => {
            io.write(&text(selected(&wizard), "quit", &[]));
            return 0;
        }
        Err(Stop::Error(message)) => return blocked(stderr, &message),
    };
    let locale = selected(&wizard);
    let plan = match engine.plan(&config) {
        Ok(plan) => plan,
        Err(EngineError::Blocked(message)) => return blocked(stderr, &message),
        Err(EngineError::Interrupted) => return 130,
    };
    for line in plan_summary_lines(&plan) {
        io.write(&line);
    }
    let digest = plan.digest();
    let prompt = format!("{}: ", text(locale, "digest", &[("prefix", &digest[..12])]));
    let confirmation = match io.read_line(&prompt, true, false) {
        Ok(confirmation) => confirmation,
        Err(Stop::Error(message)) => return blocked(stderr, &message),
        Err(_) => {
            io.write(&text(locale, "quit", &[]));
            return 0;
        }
    };
    if lower(&confirmation) == "quit" {
        io.write(&text(locale, "quit", &[]));
        return 0;
    }
    if !confirmation_matches(&confirmation, &digest) {
        return blocked(stderr, &text(locale, "digest_mismatch", &[]));
    }
    if let Err(err) = stage_operator_credentials(&command.root, wizard.credentials.as_ref()) {
        return blocked(stderr, &err.0);
    }
    let applied = engine.apply(&plan);
    let discarded = discard_staged_credentials(&command.root);
    let state = match applied {
        Ok(state) => state,
        Err(EngineError::Blocked(message)) => return blocked(stderr, &message),
        Err(EngineError::Interrupted) => return 130,
    };
    if let Err(err) = discarded {
        return blocked(stderr, &err.0);
    }
    io.put(&state.render(command.json));
    0
}

#[cfg(test)]
#[path = "wizard_tests.rs"]
mod tests;
