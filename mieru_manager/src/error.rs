//! The manager's failure classes, one per Python exception class the HTTP layer told apart.

/// `ValidationError`, `ConfigConflict`, `MitaError`, `EgressInvalid`, `EgressUnreachable` and
/// `LanesInvalid` of the Python manager, with their messages (the HTTP layer derives codes
/// from some of them). `Internal` is what Python left unhandled — an `OSError` while writing
/// state, a state file of the wrong shape: Python dropped the connection without an answer,
/// this manager answers 500 without detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Validation(String),
    Conflict(String),
    Mita(String),
    EgressInvalid(String),
    EgressUnreachable(String),
    LanesInvalid(String),
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    pub fn mita(message: impl Into<String>) -> Self {
        Self::Mita(message.into())
    }

    pub fn egress_invalid(message: impl Into<String>) -> Self {
        Self::EgressInvalid(message.into())
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Validation(m)
            | Self::Conflict(m)
            | Self::Mita(m)
            | Self::EgressInvalid(m)
            | Self::EgressUnreachable(m)
            | Self::LanesInvalid(m)
            | Self::Internal(m) => m,
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
        Self::Internal(format!("I/O failed: {:?}", err.kind()))
    }
}
