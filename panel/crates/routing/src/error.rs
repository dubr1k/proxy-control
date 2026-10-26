//! `RoutingError` and `LaneError` of the Python package, and what escaped them.
//!
//! Both Python exceptions are answered with the same body shape (`{"detail": str(exc), "code"}`,
//! plus the redacted `compiled` of a routing refusal), so one [`Refusal`] carries both. Anything
//! Python let escape (a database error, an adapter error the service did not catch) is
//! [`RoutingFailure::Internal`]: the bare 500 of `ServerErrorMiddleware`.

use std::fmt;

use panel_core::db::DbError;
use panel_core::errors::ApiError;
use panel_model::routing::models::Compiled;
use panel_secrets::secrets_store::SecretError;

/// A refusal answered with its status and code (`RoutingError` / `LaneError`).
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub status: u16,
    pub code: String,
    /// `str(exc)`: the detail, or the code when the detail is empty.
    pub detail: String,
    pub compiled: Option<Box<Compiled>>,
}

impl Refusal {
    pub fn new(status: u16, code: impl Into<String>, detail: impl Into<String>) -> Self {
        let code = code.into();
        let detail = detail.into();
        let detail = if detail.is_empty() { code.clone() } else { detail };
        Self { status, code, detail, compiled: None }
    }

    pub fn with_compiled(mut self, compiled: Compiled) -> Self {
        self.compiled = Some(Box::new(compiled));
        self
    }

    /// The API answer: `{"detail", "code"}` and the redacted `compiled` when there is one.
    pub fn to_api_error(&self) -> ApiError {
        ApiError::routing(self.status, &self.code, &self.detail, self.compiled.as_ref().map(|compiled| compiled.redacted()))
    }
}

/// What a routing operation failed with.
#[derive(Debug)]
pub enum RoutingFailure {
    Refused(Refusal),
    /// An adapter's error the service let escape (Python's uncaught `AdapterError`): a 500 at the
    /// route, but a caller may still act on it.
    Adapter(panel_model::protocols::AdapterError),
    /// Python let it escape: the route answers the bare 500.
    Internal(String),
}

impl RoutingFailure {
    pub fn refused(status: u16, code: impl Into<String>, detail: impl Into<String>) -> Self {
        RoutingFailure::Refused(Refusal::new(status, code, detail))
    }

    pub fn internal(error: impl fmt::Display) -> Self {
        RoutingFailure::Internal(error.to_string())
    }

    /// The refusal, if this is one.
    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            RoutingFailure::Refused(refusal) => Some(refusal),
            _ => None,
        }
    }

    /// The adapter error, if this is one.
    pub fn adapter(self) -> Option<panel_model::protocols::AdapterError> {
        match self {
            RoutingFailure::Adapter(error) => Some(error),
            _ => None,
        }
    }

    /// The code of a refusal (`exc.code`), `None` for an internal failure.
    pub fn code(&self) -> Option<&str> {
        self.refusal().map(|refusal| refusal.code.as_str())
    }

    pub fn status(&self) -> u16 {
        self.refusal().map_or(500, |refusal| refusal.status)
    }
}

impl From<Refusal> for RoutingFailure {
    fn from(refusal: Refusal) -> Self {
        RoutingFailure::Refused(refusal)
    }
}

impl fmt::Display for RoutingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoutingFailure::Refused(refusal) => f.write_str(&refusal.detail),
            RoutingFailure::Adapter(error) => f.write_str(&error.message),
            RoutingFailure::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for RoutingFailure {}

impl From<DbError> for RoutingFailure {
    fn from(error: DbError) -> Self {
        RoutingFailure::internal(error)
    }
}

impl From<panel_core::rusqlite::Error> for RoutingFailure {
    fn from(error: panel_core::rusqlite::Error) -> Self {
        RoutingFailure::internal(error)
    }
}

impl From<SecretError> for RoutingFailure {
    fn from(error: SecretError) -> Self {
        RoutingFailure::internal(error)
    }
}

impl From<serde_json::Error> for RoutingFailure {
    fn from(error: serde_json::Error) -> Self {
        RoutingFailure::internal(error)
    }
}

impl From<panel_nodes::error::NodesError> for RoutingFailure {
    fn from(error: panel_nodes::error::NodesError) -> Self {
        RoutingFailure::internal(error)
    }
}

impl From<panel_clients::ClientsError> for RoutingFailure {
    fn from(error: panel_clients::ClientsError) -> Self {
        RoutingFailure::internal(error)
    }
}

pub type Result<T, E = RoutingFailure> = std::result::Result<T, E>;

/// Runs blocking database work off the runtime; a panic in it is re-raised here.
pub async fn blocking<T, F>(work: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => Err(RoutingFailure::internal(error)),
    }
}
