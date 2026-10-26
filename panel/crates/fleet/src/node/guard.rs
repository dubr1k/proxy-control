//! The one gate every local writer passes before touching a runtime user (`fleet_v2/guard.py`,
//! spec §5.3, ADR 003): a resource the central panel owns has exactly one writer — not this
//! panel's UI, its legacy protocol routes or its own provisioning.

use panel_core::db::{Conn, DbError};
use panel_core::errors::ApiError;

use super::managed::ManagedStore;

/// The refusal's `detail`.
pub const MANAGED_DETAIL: &str = "managed by central";
/// The refusal's `X-Reason` header value.
pub const MANAGED_REASON: &str = "managed_by_central";
/// The header that carries [`MANAGED_REASON`].
pub const REASON_HEADER: &str = "x-reason";

/// Why a local write was refused.
#[derive(Debug)]
pub enum GuardError {
    /// 409 `{"detail": "managed by central"}` with `X-Reason: managed_by_central`.
    Managed,
    Db(DbError),
}

impl GuardError {
    /// The answer of a route (`HTTPException(409, …, headers={"X-Reason": …})`); add the header
    /// [`REASON_HEADER`]: [`MANAGED_REASON`]. `None` for a database error (a bare 500).
    pub fn to_api_error(&self) -> Option<ApiError> {
        match self {
            GuardError::Managed => Some(ApiError::detail(409, MANAGED_DETAIL)),
            GuardError::Db(_) => None,
        }
    }
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::Managed => f.write_str(MANAGED_DETAIL),
            GuardError::Db(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for GuardError {}

impl From<DbError> for GuardError {
    fn from(error: DbError) -> Self {
        GuardError::Db(error)
    }
}

/// `require_unmanaged(db, managed, protocol, username)`.
pub fn require_unmanaged(db: &Conn, managed: &ManagedStore, protocol: &str, username: &str) -> Result<(), GuardError> {
    if managed.is_managed(db, protocol, username)? {
        return Err(GuardError::Managed);
    }
    Ok(())
}
