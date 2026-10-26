//! Failures the Python adapters did not translate into an `AdapterError`.
//!
//! [`ProtocolAdapter`](panel_model::protocols::ProtocolAdapter) answers only `AdapterError`, but a
//! Python adapter let three other kinds of failure escape, and its callers tell them apart:
//!
//! - a manager or Telemt error from a read the adapter did not wrap (`discover`, `preflight`): the
//!   app's exception handler answers it (`NaiveError` → its status with "NaiveProxy manager
//!   unavailable", `TelemtError` → 502 "Telemt service unavailable");
//! - `TelemtIndeterminate` from `create`/`rotate`: the outcome is unknown, so the provisioning saga
//!   must resume, never compensate;
//! - a crash on a malformed manager answer (`KeyError`, `TypeError`, …): a 500.
//!
//! Until the model's error type can say so itself (integrator note), such a failure is an
//! `AdapterError` whose `code` is `runtime_error/<status>[/<manager code>]` or
//! `runtime_indeterminate/<status>` and whose message is the original one; [`runtime_failure`]
//! reads it back. No egress code starts with `runtime_`, so the routing service never mistakes one
//! for a refusal.

use panel_managers::{ManagerError, TelemtError};
use panel_model::protocols::AdapterError;

/// The code prefix of an untranslated failure.
pub const RUNTIME_ERROR: &str = "runtime_error";
/// The code prefix of a Telemt request whose reply was lost (`TelemtIndeterminate`).
pub const RUNTIME_INDETERMINATE: &str = "runtime_indeterminate";

/// An untranslated failure, read back from an [`AdapterError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFailure {
    /// The client error's status (500 for a crash on a malformed answer).
    pub status: u16,
    /// The manager's refusal code the client kept, if any.
    pub code: Option<String>,
    /// `TelemtIndeterminate`: resume, never compensate.
    pub indeterminate: bool,
}

/// A manager error that escaped the Python adapter as it was.
pub fn raw_manager(error: ManagerError) -> AdapterError {
    let code = match &error.code {
        Some(code) => format!("{RUNTIME_ERROR}/{}/{code}", error.status_code),
        None => format!("{RUNTIME_ERROR}/{}", error.status_code),
    };
    AdapterError::with_code(error.message, code)
}

/// A Telemt error that escaped the Python adapter as it was.
pub fn raw_telemt(error: TelemtError) -> AdapterError {
    let prefix = if error.indeterminate { RUNTIME_INDETERMINATE } else { RUNTIME_ERROR };
    AdapterError::with_code(error.message, format!("{prefix}/{}", error.status_code))
}

/// What Python crashed on (a 500): a manager answer of an unexpected shape.
pub fn crash(message: impl Into<String>) -> AdapterError {
    AdapterError::with_code(message, format!("{RUNTIME_ERROR}/500"))
}

/// The untranslated failure an error stands for, or `None` for an ordinary `AdapterError`.
pub fn runtime_failure(error: &AdapterError) -> Option<RuntimeFailure> {
    let code = error.code.as_deref()?;
    let (indeterminate, rest) = if let Some(rest) = code.strip_prefix(RUNTIME_INDETERMINATE) {
        (true, rest)
    } else {
        (false, code.strip_prefix(RUNTIME_ERROR)?)
    };
    let rest = rest.strip_prefix('/')?;
    let (status, manager_code) = match rest.split_once('/') {
        Some((status, manager_code)) => (status, Some(manager_code.to_string())),
        None => (rest, None),
    };
    Some(RuntimeFailure { status: status.parse().ok()?, code: manager_code, indeterminate })
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_managers::Manager;

    #[test]
    fn untranslated_failures_round_trip_through_the_code() {
        let error = raw_manager(ManagerError::new(Manager::Mieru, "Mieru manager rejected request", 409, Some("x")));
        assert_eq!(error.message, "Mieru manager rejected request");
        assert_eq!(
            runtime_failure(&error),
            Some(RuntimeFailure { status: 409, code: Some("x".into()), indeterminate: false })
        );
        let lost = raw_telemt(TelemtError::indeterminate("Telemt API reply was lost"));
        assert_eq!(runtime_failure(&lost), Some(RuntimeFailure { status: 502, code: None, indeterminate: true }));
        assert_eq!(runtime_failure(&crash("boom")).map(|failure| failure.status), Some(500));
        assert_eq!(runtime_failure(&AdapterError::with_code("x", "egress_conflict")), None);
        assert_eq!(runtime_failure(&AdapterError::new("x")), None);
    }
}
