//! What the node services fail with, and how the API answers each failure (`node_routes.py`).

use std::fmt;

use panel_core::db::DbError;
use panel_core::errors::ApiError;
use panel_core::rusqlite;

/// A failed node operation. The first three are the Python exceptions the routes translate.
#[derive(Debug)]
pub enum NodesError {
    /// Python's `KeyError(node_id)`: no such node (or no link row for a linked panel).
    NotFound(String),
    /// `NodeConflict`: the operation is refused in the node's current state.
    Conflict(String),
    /// `fleet.ProtocolError`: an invalid node id or display name.
    Protocol(String),
    /// The database refused a statement (a duplicate `node_id` is a constraint violation, see
    /// [`NodesError::is_integrity`]).
    Db(DbError),
    /// A stored JSON column that does not parse (Python's `json.loads` would raise too).
    Json(serde_json::Error),
}

impl NodesError {
    /// True for `sqlite3.IntegrityError` (a node id that already exists).
    pub fn is_integrity(&self) -> bool {
        matches!(self, NodesError::Db(error) if error.is_constraint())
    }

    /// The answer of the node routes: 404 `node not found`, 409/422 with the message as `detail`;
    /// `None` for an internal failure (the web layer answers 500).
    pub fn to_api_error(&self) -> Option<ApiError> {
        match self {
            NodesError::NotFound(_) => Some(ApiError::detail(404, "node not found")),
            NodesError::Conflict(message) => Some(ApiError::detail(409, message.clone())),
            NodesError::Protocol(message) => Some(ApiError::detail(422, message.clone())),
            NodesError::Db(_) | NodesError::Json(_) => None,
        }
    }
}

impl fmt::Display for NodesError {
    /// `str(exc)` of the Python exception (`KeyError` quotes its key like `repr`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodesError::NotFound(key) => f.write_str(&panel_core::pytext::repr(key)),
            NodesError::Conflict(message) | NodesError::Protocol(message) => f.write_str(message),
            NodesError::Db(error) => write!(f, "{error}"),
            NodesError::Json(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for NodesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NodesError::Db(error) => Some(error),
            NodesError::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DbError> for NodesError {
    fn from(error: DbError) -> Self {
        NodesError::Db(error)
    }
}

impl From<rusqlite::Error> for NodesError {
    fn from(error: rusqlite::Error) -> Self {
        NodesError::Db(DbError::from(error))
    }
}

impl From<serde_json::Error> for NodesError {
    fn from(error: serde_json::Error) -> Self {
        NodesError::Json(error)
    }
}
