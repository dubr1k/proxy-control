//! Errors shared by the central-side domain services.

use panel_clients::ClientsError;
use panel_core::db::DbError;
use panel_model::seams::NodeError;
use panel_secrets::secrets_store::SecretError;

pub type CentralResult<T> = Result<T, CentralError>;

#[derive(Debug)]
pub enum CentralError {
    Node(NodeError),
    NotFound(String),
    UnknownClient(String),
    LinkConflict(String),
    Invalid(String),
    Secret(SecretError),
    Clients(ClientsError),
    Db(DbError),
    Json(serde_json::Error),
    Internal(String),
}

impl std::fmt::Display for CentralError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node(error) => error.fmt(f),
            Self::NotFound(id) => write!(f, "{id}"),
            Self::UnknownClient(id) => write!(f, "{id}"),
            Self::LinkConflict(message) | Self::Invalid(message) | Self::Internal(message) => f.write_str(message),
            Self::Secret(error) => error.fmt(f),
            Self::Clients(error) => error.fmt(f),
            Self::Db(error) => error.fmt(f),
            Self::Json(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for CentralError {}

impl From<NodeError> for CentralError {
    fn from(error: NodeError) -> Self {
        Self::Node(error)
    }
}
impl From<SecretError> for CentralError {
    fn from(error: SecretError) -> Self {
        Self::Secret(error)
    }
}
impl From<ClientsError> for CentralError {
    fn from(error: ClientsError) -> Self {
        Self::Clients(error)
    }
}
impl From<DbError> for CentralError {
    fn from(error: DbError) -> Self {
        Self::Db(error)
    }
}
impl From<panel_core::rusqlite::Error> for CentralError {
    fn from(error: panel_core::rusqlite::Error) -> Self {
        Self::Db(error.into())
    }
}
impl From<serde_json::Error> for CentralError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
impl From<panel_nodes::NodesError> for CentralError {
    fn from(error: panel_nodes::NodesError) -> Self {
        match error {
            panel_nodes::NodesError::NotFound(id) => Self::NotFound(id),
            other => Self::Internal(other.to_string()),
        }
    }
}
