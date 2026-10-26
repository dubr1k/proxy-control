//! The Python manager's exception classes, one variant each; `Display` is `str(exc)`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `EgressInvalid`: the document is outside the schema, or `xray run -test` refused it.
    EgressInvalid { message: String, code: String },
    /// `EgressUnreachable`: a provider or a chain hop did not answer.
    EgressUnreachable(String),
    /// `XrayError`: the binary refused a config or a generation did not come up.
    Xray(String),
    /// `ArtifactMismatch`: a pinned file is not the one the release named.
    ArtifactMismatch(String),
    /// `ManagerConflict`.
    Conflict { message: String, code: String },
    /// `ManualInterventionRequired`.
    Manual(String),
    /// `ValidationError`: the API answers a bare 422.
    Validation(String),
    /// `GeodataError`.
    Geodata { message: String, code: String },
    /// Anything the Python manager did not catch (an unreadable file, a malformed record).
    Internal(String),
}

impl Error {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::EgressInvalid { message: message.into(), code: "egress_invalid".into() }
    }

    pub fn conflict(message: impl Into<String>, code: &str) -> Self {
        Self::Conflict { message: message.into(), code: code.into() }
    }

    pub fn geodata(message: impl Into<String>, code: &str) -> Self {
        Self::Geodata { message: message.into(), code: code.into() }
    }

    pub fn internal(err: impl std::fmt::Display) -> Self {
        Self::Internal(err.to_string())
    }

    /// The `code` of the classes that carry one.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::EgressInvalid { code, .. } | Self::Conflict { code, .. } | Self::Geodata { code, .. } => Some(code),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EgressInvalid { message, .. } | Self::Conflict { message, .. } | Self::Geodata { message, .. } => {
                f.write_str(message)
            }
            Self::EgressUnreachable(message)
            | Self::Xray(message)
            | Self::ArtifactMismatch(message)
            | Self::Manual(message)
            | Self::Validation(message)
            | Self::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Internal(crate::util::py_oserror(&err))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
