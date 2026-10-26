//! What the clients domain fails with — one variant per Python exception the routes tell apart —
//! and the answer of the app's exception handlers for a manager failure that escaped an adapter.

use std::fmt;

use panel_core::db::DbError;
use panel_core::errors::ApiError;
use panel_core::rusqlite;
use panel_model::protocols::AdapterError;
use panel_model::seams::SeamError;
use panel_model::{Protocol, ValidationError};
use panel_protocols::error::{runtime_failure, RuntimeFailure};
use panel_secrets::secrets_store::SecretError;

/// A failed clients-domain operation.
#[derive(Debug)]
pub enum ClientsError {
    /// Python's `KeyError(key)`: no such client, grant or operation.
    NotFound(String),
    /// `ClientConflict`.
    Conflict(String),
    /// `require_unmanaged`: 409 "managed by central" with `X-Reason: managed_by_central`.
    ManagedByCentral,
    /// A `ValueError` the routes answer with 422 (cursor, filters, unknown import account, …).
    Invalid(String),
    /// pydantic's `ValidationError` (a `ValueError` in Python): `str(exc)` is its text.
    Validation(ValidationError),
    /// An `AdapterError` (or `ManualInterventionRequired`, or a manager/Telemt failure the
    /// Python adapter let escape — see [`ClientsError::runtime`]) of the adapter of `protocol`.
    Adapter { protocol: Protocol, error: AdapterError },
    /// `SecretError` (a refusal with a fixed message).
    Secret(&'static str),
    /// An injected crash (`RuntimeError`, the saga's test faults): the journal stays where it is.
    Injected(String),
    /// A seam implementation (change hook, lane service, reconciler) failed.
    Seam(SeamError),
    /// The database failed.
    Db(DbError),
    /// A stored row this port cannot read (Python would crash on it too).
    Internal(String),
}

impl ClientsError {
    /// The untranslated manager failure an adapter error stands for, if any.
    pub fn runtime(&self) -> Option<(Protocol, RuntimeFailure)> {
        match self {
            ClientsError::Adapter { protocol, error } => runtime_failure(error).map(|failure| (*protocol, failure)),
            _ => None,
        }
    }

    /// `isinstance(exc, ManualInterventionRequired)`.
    pub fn is_manual_intervention(&self) -> bool {
        matches!(self, ClientsError::Adapter { error, .. } if error.is_manual_intervention())
    }

    /// A plain `AdapterError` (neither manual intervention nor an escaped manager failure).
    pub fn is_plain_adapter_error(&self) -> bool {
        matches!(self, ClientsError::Adapter { .. }) && !self.is_manual_intervention() && self.runtime().is_none()
    }

    /// An adapter error that `except AdapterError` catches in Python (manual intervention
    /// included, escaped manager failures not).
    pub fn is_adapter_error(&self) -> bool {
        matches!(self, ClientsError::Adapter { .. }) && self.runtime().is_none()
    }

    /// The adapter's error, wrapped with the protocol whose adapter raised it.
    pub fn adapter(protocol: Protocol, error: AdapterError) -> Self {
        ClientsError::Adapter { protocol, error }
    }
}

impl fmt::Display for ClientsError {
    /// `str(exc)` of the Python exception (`KeyError` quotes its key like `repr`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientsError::NotFound(key) => f.write_str(&panel_core::pytext::repr(key)),
            ClientsError::Conflict(message) | ClientsError::Invalid(message) | ClientsError::Injected(message) => {
                f.write_str(message)
            }
            ClientsError::ManagedByCentral => f.write_str("409: managed by central"),
            ClientsError::Validation(error) => write!(f, "{error}"),
            ClientsError::Adapter { error, .. } => f.write_str(&error.message),
            ClientsError::Secret(message) => f.write_str(message),
            ClientsError::Seam(error) => write!(f, "{error}"),
            ClientsError::Db(error) => write!(f, "{error}"),
            ClientsError::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ClientsError {}

impl From<DbError> for ClientsError {
    fn from(error: DbError) -> Self {
        ClientsError::Db(error)
    }
}

impl From<rusqlite::Error> for ClientsError {
    fn from(error: rusqlite::Error) -> Self {
        ClientsError::Db(DbError::from(error))
    }
}

impl From<SecretError> for ClientsError {
    fn from(error: SecretError) -> Self {
        match error {
            SecretError::Refused(message) => ClientsError::Secret(message),
            SecretError::Db(error) => ClientsError::Db(error),
        }
    }
}

impl From<ValidationError> for ClientsError {
    fn from(error: ValidationError) -> Self {
        ClientsError::Validation(error)
    }
}

/// The body the app's exception handler answers for a manager failure that escaped the adapter
/// of `protocol` (`app.py:260-295`); `None` is a crash on a malformed answer (Starlette's bare
/// 500).
pub fn runtime_answer(protocol: Protocol, failure: &RuntimeFailure) -> Option<ApiError> {
    if failure.status == 500 && failure.code.is_none() && !failure.indeterminate {
        return None;
    }
    Some(match protocol {
        // `TelemtError` (and `TelemtIndeterminate`): always 502.
        Protocol::Mtproxy => ApiError::detail(502, "Telemt service unavailable"),
        Protocol::Naive if failure.code.as_deref() == Some("quota_exhausted") => ApiError::coded(
            failure.status,
            "quota_exhausted",
            "Quota exhausted: reset traffic or raise the quota first",
        ),
        Protocol::Naive => ApiError::detail(failure.status, "NaiveProxy manager unavailable"),
        Protocol::Mieru => ApiError::detail(failure.status, "Mieru manager unavailable"),
        Protocol::Amneziawg => ApiError::detail(failure.status, "AmneziaWG manager unavailable"),
        Protocol::Trusttunnel => ApiError::detail(failure.status, "TrustTunnel manager unavailable"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_protocols::error::{crash, raw_manager, raw_telemt};

    #[test]
    fn escaped_manager_failures_answer_like_the_app_handlers() {
        let naive = raw_manager(panel_managers_error(409, Some("quota_exhausted")));
        let error = ClientsError::adapter(Protocol::Naive, naive);
        let (protocol, failure) = error.runtime().unwrap();
        assert_eq!(
            runtime_answer(protocol, &failure).unwrap().body_bytes(),
            br#"{"detail":"Quota exhausted: reset traffic or raise the quota first","code":"quota_exhausted"}"#
        );
        let mieru = ClientsError::adapter(Protocol::Mieru, raw_manager(panel_managers_error(502, None)));
        let (protocol, failure) = mieru.runtime().unwrap();
        let answer = runtime_answer(protocol, &failure).unwrap();
        assert_eq!(
            (answer.status(), answer.body_bytes()),
            (502, br#"{"detail":"Mieru manager unavailable"}"#.to_vec())
        );
        let lost = raw_telemt(panel_managers::TelemtError::indeterminate("lost"));
        let (protocol, failure) = ClientsError::adapter(Protocol::Mtproxy, lost).runtime().unwrap();
        assert!(failure.indeterminate);
        assert_eq!(runtime_answer(protocol, &failure).unwrap().status(), 502);
        let (protocol, failure) = ClientsError::adapter(Protocol::Naive, crash("KeyError")).runtime().unwrap();
        assert!(runtime_answer(protocol, &failure).is_none());
        let plain = ClientsError::adapter(Protocol::Naive, AdapterError::new("refused"));
        assert!(plain.is_plain_adapter_error() && plain.is_adapter_error() && plain.runtime().is_none());
        let manual = ClientsError::adapter(Protocol::Naive, AdapterError::manual_intervention("x", None));
        assert!(manual.is_manual_intervention() && manual.is_adapter_error() && !manual.is_plain_adapter_error());
        assert_eq!(ClientsError::NotFound("g1".into()).to_string(), "'g1'");
    }

    fn panel_managers_error(status: u16, code: Option<&str>) -> panel_managers::ManagerError {
        panel_managers::ManagerError::new(panel_managers::Manager::Naive, "manager rejected request", status, code)
    }
}
