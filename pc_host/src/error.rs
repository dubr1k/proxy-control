//! The installer's exception classes as one error type.
//!
//! Python raised `TransactionError` and its subclasses (`installer/transaction.py:56-74`); the
//! journal stores the **class name** of the exception that triggered a rollback in
//! `state.json:error` (`type(exc).__name__`), so the Rust port keeps those names as strings.

use std::fmt;
use std::io;

/// `TransactionError` and its subclasses, plus the `OSError`s the same code paths let through.
#[derive(Debug)]
pub enum TxError {
    /// `TransactionError` — a durable installer transaction cannot proceed safely.
    Transaction(String),
    /// `AcceptedDigestError` — the operator did not accept the exact persisted plan.
    AcceptedDigest(String),
    /// `OwnershipError` — owned state no longer matches the transaction journal.
    Ownership(String),
    /// `OwnershipRecoveryFailed` — a handoff could not restore the previous ownership generation.
    OwnershipRecoveryFailed(String),
    /// `TransactionBusyError` — another host mutation holds the operation lock.
    Busy(String),
    /// An `OSError` (file system, lock file) that Python did not wrap.
    Io(io::Error),
}

impl TxError {
    /// The Python class name, as `type(exc).__name__` wrote it into `state.json:error`.
    pub fn python_class_name(&self) -> &'static str {
        match self {
            TxError::Transaction(_) => "TransactionError",
            TxError::AcceptedDigest(_) => "AcceptedDigestError",
            TxError::Ownership(_) => "OwnershipError",
            TxError::OwnershipRecoveryFailed(_) => "OwnershipRecoveryFailed",
            TxError::Busy(_) => "TransactionBusyError",
            TxError::Io(err) => os_error_class(err),
        }
    }

    /// The message alone (`str(exc)`), without the class name.
    pub fn message(&self) -> String {
        match self {
            TxError::Transaction(m)
            | TxError::AcceptedDigest(m)
            | TxError::Ownership(m)
            | TxError::OwnershipRecoveryFailed(m)
            | TxError::Busy(m) => m.clone(),
            TxError::Io(err) => err.to_string(),
        }
    }

    pub fn is_busy(&self) -> bool {
        matches!(self, TxError::Busy(_))
    }

    pub(crate) fn transaction(message: impl Into<String>) -> Self {
        TxError::Transaction(message.into())
    }

    pub(crate) fn ownership(message: impl Into<String>) -> Self {
        TxError::Ownership(message.into())
    }
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for TxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TxError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for TxError {
    fn from(err: io::Error) -> Self {
        TxError::Io(err)
    }
}

/// The `OSError` subclass CPython raises for this error (`PEP 3151` errno mapping), e.g.
/// `FileNotFoundError` for `ENOENT`. Used where Python wrote `type(exc).__name__`.
pub fn os_error_class(err: &io::Error) -> &'static str {
    let Some(code) = err.raw_os_error() else {
        return match err.kind() {
            io::ErrorKind::NotFound => "FileNotFoundError",
            io::ErrorKind::PermissionDenied => "PermissionError",
            io::ErrorKind::AlreadyExists => "FileExistsError",
            io::ErrorKind::TimedOut => "TimeoutError",
            io::ErrorKind::Interrupted => "InterruptedError",
            io::ErrorKind::WouldBlock => "BlockingIOError",
            io::ErrorKind::BrokenPipe => "BrokenPipeError",
            io::ErrorKind::ConnectionRefused => "ConnectionRefusedError",
            io::ErrorKind::ConnectionReset => "ConnectionResetError",
            io::ErrorKind::ConnectionAborted => "ConnectionAbortedError",
            _ => "OSError",
        };
    };
    match code {
        libc::ENOENT => "FileNotFoundError",
        libc::EACCES | libc::EPERM => "PermissionError",
        libc::EEXIST => "FileExistsError",
        libc::ENOTDIR => "NotADirectoryError",
        libc::EISDIR => "IsADirectoryError",
        libc::EINTR => "InterruptedError",
        libc::ETIMEDOUT => "TimeoutError",
        libc::ECHILD => "ChildProcessError",
        libc::ESRCH => "ProcessLookupError",
        libc::EPIPE | libc::ESHUTDOWN => "BrokenPipeError",
        libc::ECONNABORTED => "ConnectionAbortedError",
        libc::ECONNREFUSED => "ConnectionRefusedError",
        libc::ECONNRESET => "ConnectionResetError",
        libc::EAGAIN | libc::EALREADY | libc::EINPROGRESS => "BlockingIOError",
        _ => "OSError",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_names_follow_python() {
        assert_eq!(TxError::Busy("x".into()).python_class_name(), "TransactionBusyError");
        assert_eq!(TxError::Ownership("x".into()).python_class_name(), "OwnershipError");
        let missing = io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(TxError::Io(missing).python_class_name(), "FileNotFoundError");
        assert_eq!(os_error_class(&io::Error::from_raw_os_error(libc::ENOTDIR)), "NotADirectoryError");
        assert_eq!(os_error_class(&io::Error::from_raw_os_error(libc::EIO)), "OSError");
        assert_eq!(os_error_class(&io::Error::new(io::ErrorKind::TimedOut, "t")), "TimeoutError");
    }

    #[test]
    fn display_is_the_message_alone() {
        assert_eq!(
            TxError::Busy("another proxyctl operation is in progress".into()).to_string(),
            "another proxyctl operation is in progress"
        );
    }
}
