//! Starlette/FastAPI behaviour the panel's clients can observe: request reading and validation
//! order ([`request`]), Python's `json.loads` ([`json_loads`]), response shapes and cookies
//! ([`response`]), first-match routing with 404/405/307 ([`router`]), and the static mount
//! ([`static_files`]).

pub mod json_loads;
mod mime_table;
pub mod request;
pub mod response;
pub mod router;
pub mod static_files;
