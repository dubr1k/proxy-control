use serde_json::json;

use crate::http::Response;

/// An error a manager reports to its caller: HTTP status, a stable machine code and a short,
/// secret-free detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub detail: String,
}

impl ApiError {
    pub fn new(status: u16, code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { status, code: code.into(), detail: detail.into() }
    }

    pub fn invalid_request(detail: impl Into<String>) -> Self {
        Self::new(422, "invalid_request", detail)
    }

    pub fn not_found() -> Self {
        Self::new(404, "not_found", "not found")
    }

    pub fn internal() -> Self {
        Self::new(500, "internal_error", "manager operation failed")
    }

    pub fn into_response(self) -> Response {
        Response::json(self.status, &json!({"detail": self.detail, "code": self.code}))
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.status, self.code, self.detail)
    }
}

impl std::error::Error for ApiError {}

impl From<ApiError> for Response {
    fn from(error: ApiError) -> Self {
        error.into_response()
    }
}
