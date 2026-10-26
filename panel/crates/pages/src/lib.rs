//! The protocol pages of the Proxy Control panel (work package WP8): what the panel answers on its
//! older per-protocol endpoints, kept byte-compatible for the UI and the MCP server.
//!
//! | Python | Rust |
//! |---|---|
//! | `panel/schemas.py` (`UserCreate`, `UserLimits`, `Naive*`, `Mieru*`, `VersionUpdate`) | [`models`] |
//! | `datetime.fromisoformat` (the `UserLimits` validator) | [`isoformat`] |
//! | `panel/telemt_routes.py` (allow-lists, the MTProxy link check, the dashboard sections) | [`telemt`], [`dashboard`] |
//! | `panel/naive_routes.py` (traffic and quota allow-lists, the reveal) | [`naive`] |
//! | `panel/mieru_routes.py` (the reveal, the traffic map, the listing) | [`mieru`] |
//! | `panel/amneziawg_routes.py`, `panel/trusttunnel_routes.py` | [`overview`] |
//!
//! Everything here is pure: the routes (`panel-web`, `routes/{telemt,naive,mieru,amneziawg,
//! trusttunnel,versions}.rs`) call the managers and the clients domain and hand the answers in.
//! A function fails with a [`Fault`]: the `HTTPException` the Python route raised, the manager
//! error class it raised (answered by the app's exception handler), or a crash Python let escape
//! (Starlette's bare 500).

pub mod dashboard;
pub mod isoformat;
pub mod mieru;
pub mod models;
pub mod naive;
pub mod overview;
pub mod py;
pub mod telemt;

use panel_core::errors::ApiError;
use panel_managers::ManagerError;

/// Why a page could not answer normally.
#[derive(Debug, Clone, PartialEq)]
pub enum Fault {
    /// `raise HTTPException(status, detail)`.
    Api(ApiError),
    /// `raise NaiveError(...)`/`MieruError(...)` in the route itself: the app's handler answers.
    Manager(ManagerError),
    /// An exception Python did not handle (`AttributeError`, `TypeError`, …): a bare 500.
    Crash(String),
}

impl Fault {
    /// `HTTPException(status, detail)`.
    pub fn detail(status: u16, detail: impl Into<String>) -> Self {
        Fault::Api(ApiError::detail(status, detail))
    }

    /// An unhandled exception with Python's class name and message.
    pub fn crash(message: impl Into<String>) -> Self {
        Fault::Crash(message.into())
    }
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::Api(error) => write!(f, "{}: {}", error.status(), error.body()),
            Fault::Manager(error) => write!(f, "{error}"),
            Fault::Crash(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Fault {}

impl From<ApiError> for Fault {
    fn from(error: ApiError) -> Self {
        Fault::Api(error)
    }
}

impl From<ManagerError> for Fault {
    fn from(error: ManagerError) -> Self {
        Fault::Manager(error)
    }
}

/// What a page answers or why it could not.
pub type PageResult<T> = Result<T, Fault>;
