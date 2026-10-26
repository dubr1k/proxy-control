//! The exceptions of the Python manager, as one error type. The HTTP layer maps them to the
//! same status codes and bodies the Python handler did; the manager's own `except` clauses
//! (`except RuntimeError`, `except ValueError`, …) become matches on these variants.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `ValueError` (also `json.JSONDecodeError`, `UnicodeDecodeError`): 422 `invalid request`.
    Value(String),
    /// `EgressInvalid`, a `ValueError`: 422 with code `egress_invalid`.
    EgressInvalid(String),
    /// `LanesInvalid`, a `ValueError`, where it escapes unconverted: 422 `invalid request`.
    LanesInvalid(String),
    /// `EgressUnreachable`, a `RuntimeError`: 409 `egress_unreachable`.
    EgressUnreachable(String),
    /// `ManagerConflict(message, code)`, a `RuntimeError`.
    Conflict { message: String, code: String },
    /// `ManagerNotFound`, a `RuntimeError`: 404.
    NotFound(String),
    /// `ManagerRecoveryError`, a `RuntimeError`: 503 `manual_intervention_required`.
    Recovery(String),
    /// A plain `RuntimeError` (Caddy, the accounting log, the probe).
    Runtime(String),
    /// `OSError`.
    Os(String),
    /// `KeyError`.
    Key(String),
    /// Any other exception (`sqlite3.Error`, `TypeError`, …): 500.
    Other(String),
}

impl Error {
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::conflict_code(message, "configuration_conflict")
    }

    pub fn conflict_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Error::Conflict { message: message.into(), code: code.into() }
    }

    pub fn value(message: impl Into<String>) -> Self {
        Error::Value(message.into())
    }

    pub fn runtime(message: impl Into<String>) -> Self {
        Error::Runtime(message.into())
    }

    pub fn egress_invalid(message: impl Into<String>) -> Self {
        Error::EgressInvalid(message.into())
    }

    pub fn recovery(message: impl Into<String>) -> Self {
        Error::Recovery(message.into())
    }

    /// `isinstance(exc, RuntimeError)`.
    pub fn is_runtime(&self) -> bool {
        matches!(
            self,
            Error::EgressUnreachable(_)
                | Error::Conflict { .. }
                | Error::NotFound(_)
                | Error::Recovery(_)
                | Error::Runtime(_)
        )
    }

    #[cfg(test)]
    pub fn is_conflict(&self) -> bool {
        matches!(self, Error::Conflict { .. })
    }

    /// The code of a `ManagerConflict`.
    #[cfg(test)]
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Conflict { code, .. } => Some(code),
            _ => None,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Error::Value(m)
            | Error::EgressInvalid(m)
            | Error::LanesInvalid(m)
            | Error::EgressUnreachable(m)
            | Error::NotFound(m)
            | Error::Recovery(m)
            | Error::Runtime(m)
            | Error::Os(m)
            | Error::Key(m)
            | Error::Other(m) => m,
            Error::Conflict { message, .. } => message,
        }
    }

    /// `type(exc).__name__`, what the traffic collector remembers as its last error.
    pub fn class_name(&self) -> &'static str {
        match self {
            Error::Value(_) => "ValueError",
            Error::EgressInvalid(_) => "EgressInvalid",
            Error::LanesInvalid(_) => "LanesInvalid",
            Error::EgressUnreachable(_) => "EgressUnreachable",
            Error::Conflict { .. } => "ManagerConflict",
            Error::NotFound(_) => "ManagerNotFound",
            Error::Recovery(_) => "ManagerRecoveryError",
            Error::Runtime(_) => "RuntimeError",
            Error::Os(_) => "OSError",
            Error::Key(_) => "KeyError",
            Error::Other(_) => "Error",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Os(err.to_string())
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        Error::Other(format!("sqlite: {err}"))
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
