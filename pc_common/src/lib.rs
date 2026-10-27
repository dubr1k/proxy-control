//! Shared plumbing of the Proxy Control managers.
//!
//! Every manager speaks the same small protocol to the panel: HTTP/1.1 with a JSON body on a
//! Unix socket, one request per connection, a shared token in a manager-specific header, and
//! errors as `{"detail": …, "code": …}`. This crate holds that protocol once, together with the
//! few host primitives every manager needs (atomic state files, bounded subprocesses, the log
//! line format), plus byte-contract JSON formatting and shared Python text/value primitives.

pub mod client;
pub mod error;
pub mod fsutil;
pub mod http;
pub mod json;
pub mod logger;
pub mod process;
pub mod pytext;
pub mod pyvalue;
pub mod server;

pub use error::ApiError;
pub use http::{Request, Response};
pub use server::{ServerOptions, ShutdownHandle, UdsServer};

/// Compares two secrets in time that depends only on their lengths.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Checks the shared token a manager expects in `header`; on a mismatch returns the 401 the
/// panel recognises.
pub fn check_token(request: &Request, header: &str, token: &str) -> Result<(), Response> {
    let supplied = request.header(header).unwrap_or("");
    if supplied.is_empty() || !constant_time_eq(supplied.as_bytes(), token.as_bytes()) {
        return Err(ApiError::new(401, "unauthorized", "unauthorized").into_response());
    }
    Ok(())
}

/// Reads a manager token file: trimmed, 32–512 characters, no line breaks.
pub fn read_token(path: &std::path::Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|err| format!("cannot read API token: {err}"))?;
    let token = raw.trim().to_string();
    if !(32..=512).contains(&token.len()) || token.contains(['\r', '\n']) {
        return Err("API token must be 32-512 characters".into());
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_compares_bytes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
