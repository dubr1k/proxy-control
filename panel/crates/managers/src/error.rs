//! The errors of the manager clients and the answers the panel's handlers make of them
//! (`app.py:260-299`, inventory §2.6).

use panel_core::errors::ApiError;

/// `EGRESS_REASON_CODES` (`routing/document.py:17-34`): the bounded refusal codes a manager may
/// report through the panel. (It belongs to the routing model; it lives here until that crate
/// exists.)
pub const EGRESS_REASON_CODES: &[&str] = &[
    "egress_conflict",
    "egress_invalid",
    "egress_unreachable",
    "egress_readback_mismatch",
    "manual_intervention_required",
    "egress_no_previous",
    "geosite_unknown",
    "geoip_unknown",
    "artifact_mismatch",
    "lane_unknown",
    "lanes_invalid",
    "lane_slots_exhausted",
    "relay_disabled",
];

/// `NAIVE_REASON_CODES` (`naive.py:16`): `quota_exhausted` plus the egress codes.
pub fn is_naive_reason(code: &str) -> bool {
    code == "quota_exhausted" || EGRESS_REASON_CODES.contains(&code)
}

/// One of the five protocol managers on a Unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Manager {
    Naive,
    Mieru,
    Amneziawg,
    Trusttunnel,
    XrayRouter,
}

impl Manager {
    /// The Python error class this manager's failures carry.
    pub const fn error_class(self) -> &'static str {
        match self {
            Manager::Naive => "NaiveError",
            Manager::Mieru => "MieruError",
            Manager::Amneziawg => "AmneziawgError",
            Manager::Trusttunnel => "TrusttunnelError",
            Manager::XrayRouter => "XrayRouterError",
        }
    }

    /// The shared-token header (exact spelling of the Python clients).
    pub const fn token_header(self) -> &'static str {
        match self {
            Manager::Naive => "X-Naive-Token",
            Manager::Mieru => "X-Mieru-Token",
            Manager::Amneziawg => "X-Awg-Token",
            Manager::Trusttunnel => "X-Trusttunnel-Token",
            Manager::XrayRouter => "X-Xray-Router-Token",
        }
    }

    /// The dummy host of the Python client's base URL (`http://naive-manager`, …).
    pub const fn base_host(self) -> &'static str {
        match self {
            Manager::Naive => "naive-manager",
            Manager::Mieru => "mieru-manager",
            Manager::Amneziawg => "awg-manager",
            Manager::Trusttunnel => "trusttunnel-manager",
            Manager::XrayRouter => "xray-router",
        }
    }

    /// The name inside the client's messages ("NaiveProxy manager unavailable", …).
    const fn label(self) -> &'static str {
        match self {
            Manager::Naive => "NaiveProxy manager",
            Manager::Mieru => "Mieru manager",
            Manager::Amneziawg => "AmneziaWG manager",
            Manager::Trusttunnel => "TrustTunnel manager",
            Manager::XrayRouter => "Xray-router manager",
        }
    }

    /// `"<label> unavailable"`: the transport failed.
    pub fn unavailable(self) -> String {
        format!("{} unavailable", self.label())
    }

    /// `"<label> rejected request"`: the manager answered ≥ 400.
    pub fn rejected(self) -> String {
        format!("{} rejected request", self.label())
    }

    /// `"Invalid <label> response"`: the body is not JSON.
    pub fn invalid(self) -> String {
        format!("Invalid {} response", self.label())
    }

    /// Statuses a refusal keeps; any other becomes 502.
    pub(crate) fn passes_status(self, status: u16) -> bool {
        matches!(status, 404 | 409 | 422) || (self == Manager::XrayRouter && status == 503)
    }

    /// Whether the client answers `None` (here `Value::Null`) to a 204. The Xray-router client
    /// does not: it always parses the body (`xray_router.py:64-67`).
    pub(crate) fn no_content_is_none(self) -> bool {
        self != Manager::XrayRouter
    }

    /// The code a refusal body may carry through to the panel (`_reason`/`_code`).
    pub(crate) fn reason(self, code: &serde_json::Value) -> Option<String> {
        let code = code.as_str()?;
        let kept = match self {
            // NaiveError's and XrayRouterError's constructors filter (below); `_reason` keeps any str.
            Manager::Naive | Manager::XrayRouter => true,
            Manager::Mieru => EGRESS_REASON_CODES.contains(&code),
            Manager::Amneziawg | Manager::Trusttunnel => code.chars().count() <= 64,
        };
        kept.then(|| code.to_string())
    }

    /// The constructor's own filter: `NaiveError` keeps only `NAIVE_REASON_CODES`,
    /// `XrayRouterError` the egress codes and `geodata_*`; the others keep what they are given.
    fn constructor_keeps(self, code: &str) -> bool {
        match self {
            Manager::Naive => is_naive_reason(code),
            Manager::XrayRouter => EGRESS_REASON_CODES.contains(&code) || code.starts_with("geodata_"),
            Manager::Mieru | Manager::Amneziawg | Manager::Trusttunnel => true,
        }
    }
}

/// `NaiveError`, `MieruError`, `AmneziawgError`, `TrusttunnelError`, `XrayRouterError`: one type,
/// the manager says which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerError {
    pub manager: Manager,
    /// `str(exc)`.
    pub message: String,
    pub status_code: u16,
    pub code: Option<String>,
}

impl ManagerError {
    /// `<Manager>Error(message, status_code, code)`, with the constructor's code filter.
    pub fn new(manager: Manager, message: impl Into<String>, status_code: u16, code: Option<&str>) -> Self {
        let code = code.filter(|code| manager.constructor_keeps(code)).map(str::to_string);
        Self { manager, message: message.into(), status_code, code }
    }

    /// `<Manager>Error(message)`: status 502, no code.
    pub fn plain(manager: Manager, message: impl Into<String>) -> Self {
        Self::new(manager, message, 502, None)
    }

    /// What the panel answers when this error escapes a route (`app.py:264-295`). The
    /// Xray-router error has no handler: its callers translate it (`None`).
    pub fn app_error(&self) -> Option<ApiError> {
        let detail = match self.manager {
            Manager::Naive if self.code.as_deref() == Some("quota_exhausted") => {
                return Some(ApiError::coded(
                    self.status_code,
                    "quota_exhausted",
                    "Quota exhausted: reset traffic or raise the quota first",
                ));
            }
            Manager::Naive => "NaiveProxy manager unavailable",
            Manager::Mieru => "Mieru manager unavailable",
            Manager::Amneziawg => "AmneziaWG manager unavailable",
            Manager::Trusttunnel => "TrustTunnel manager unavailable",
            Manager::XrayRouter => return None,
        };
        Some(ApiError::detail(self.status_code, detail))
    }
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ManagerError {}

/// `VersionAgentError(message, status_code)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionAgentError {
    pub message: String,
    pub status_code: u16,
}

impl VersionAgentError {
    pub fn new(message: impl Into<String>, status_code: u16) -> Self {
        Self { message: message.into(), status_code }
    }

    /// `{"detail": str(exc)}` with the error's status (`app.py:297-299`).
    pub fn app_error(&self) -> ApiError {
        ApiError::detail(self.status_code, self.message.clone())
    }
}

impl std::fmt::Display for VersionAgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VersionAgentError {}

/// `TelemtError` and its subclass `TelemtIndeterminate` (`indeterminate: true`: the request was
/// sent and the reply never arrived, so the outcome is unknown and the caller reads back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemtError {
    pub message: String,
    pub status_code: u16,
    pub indeterminate: bool,
}

impl TelemtError {
    /// `TelemtError(message)`: the status is parsed back from a trailing `(NNN)` in the message
    /// (`telemt.py:16-24`), else 502.
    pub fn new(message: impl Into<String>) -> Self {
        let message = message.into();
        let status_code = trailing_status(&message).unwrap_or(502);
        Self { message, status_code, indeterminate: false }
    }

    /// `TelemtError(message, status_code=status)`.
    pub fn with_status(message: impl Into<String>, status_code: u16) -> Self {
        Self { message: message.into(), status_code, indeterminate: false }
    }

    /// `TelemtIndeterminate(message)`.
    pub fn indeterminate(message: impl Into<String>) -> Self {
        Self { indeterminate: true, ..Self::new(message) }
    }

    /// Every Telemt failure answers 502 `{"detail": "Telemt service unavailable"}` (`app.py:260-262`).
    pub fn app_error(&self) -> ApiError {
        ApiError::detail(502, "Telemt service unavailable")
    }
}

impl std::fmt::Display for TelemtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TelemtError {}

/// `re.search(r"\((\d{3})\)\s*$", message)` → the three digits (`\d` and `\s` are Unicode classes
/// in a Python `str` pattern; `$` also matches before a final newline, which `\s*` covers).
fn trailing_status(message: &str) -> Option<u16> {
    let trimmed = message.trim_end_matches(panel_core::pytext::is_space);
    let inner = trimmed.strip_suffix(')')?;
    let chars: Vec<char> = inner.chars().collect();
    if chars.len() < 4 || chars[chars.len() - 4] != '(' {
        return None;
    }
    let mut status = 0u16;
    for &ch in &chars[chars.len() - 3..] {
        status = status * 10 + panel_core::pytext::decimal(ch)? as u16;
    }
    Some(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemt_status_is_parsed_from_the_message() {
        assert_eq!(TelemtError::new("Telemt API error (404)").status_code, 404);
        assert_eq!(TelemtError::new("Telemt API error (409)  \n").status_code, 409);
        assert_eq!(TelemtError::new("Telemt API unavailable").status_code, 502);
        assert_eq!(TelemtError::new("x (12)").status_code, 502);
        assert_eq!(TelemtError::new("x (1234)").status_code, 502);
        assert_eq!(TelemtError::new("(503)").status_code, 503);
        // Unicode digits are \d in Python.
        assert_eq!(TelemtError::new("x (\u{0664}\u{0660}\u{0664})").status_code, 404);
        assert!(!TelemtError::new("x").indeterminate && TelemtError::indeterminate("x").indeterminate);
    }

    #[test]
    fn constructors_filter_codes_like_python() {
        let naive = ManagerError::new(Manager::Naive, "x", 409, Some("operation_conflict"));
        assert_eq!(naive.code, None);
        let naive = ManagerError::new(Manager::Naive, "x", 409, Some("quota_exhausted"));
        assert_eq!(naive.code.as_deref(), Some("quota_exhausted"));
        let router = ManagerError::new(Manager::XrayRouter, "x", 422, Some("geodata_source_invalid"));
        assert_eq!(router.code.as_deref(), Some("geodata_source_invalid"));
        assert_eq!(ManagerError::new(Manager::XrayRouter, "x", 409, Some("nope")).code, None);
        assert_eq!(ManagerError::new(Manager::Mieru, "x", 409, Some("anything")).code.as_deref(), Some("anything"));
    }

    #[test]
    fn handlers_answer_like_the_python_app() {
        let quota = ManagerError::new(Manager::Naive, "x", 409, Some("quota_exhausted")).app_error().unwrap();
        assert_eq!(
            quota.body_bytes(),
            br#"{"detail":"Quota exhausted: reset traffic or raise the quota first","code":"quota_exhausted"}"#
        );
        assert_eq!(quota.status(), 409);
        let other = ManagerError::new(Manager::Naive, "x", 404, Some("egress_conflict")).app_error().unwrap();
        assert_eq!(
            (other.status(), other.body_bytes()),
            (404, br#"{"detail":"NaiveProxy manager unavailable"}"#.to_vec())
        );
        for (manager, detail) in [
            (Manager::Mieru, "Mieru manager unavailable"),
            (Manager::Amneziawg, "AmneziaWG manager unavailable"),
            (Manager::Trusttunnel, "TrustTunnel manager unavailable"),
        ] {
            let error = ManagerError::plain(manager, "y").app_error().unwrap();
            assert_eq!((error.status(), error.body()), (502, serde_json::json!({"detail": detail})));
        }
        assert!(ManagerError::plain(Manager::XrayRouter, "z").app_error().is_none());
        let agent = VersionAgentError::new("version agent rejected request", 409).app_error();
        assert_eq!(agent.body_bytes(), br#"{"detail":"version agent rejected request"}"#);
        assert_eq!(TelemtError::new("Telemt API error (404)").app_error().status(), 502);
    }
}
