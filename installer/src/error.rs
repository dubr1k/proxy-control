//! The installer's error: what Python raised, as one type.
//!
//! Python told two kinds of failure apart by class: an `Exception` made the engine roll back
//! (`installer/transaction.py:922`), a `BaseException` (`KeyboardInterrupt`, the `SystemExit` of
//! an unconfirmed process-group kill, a test's injected crash) left the journal where it was for
//! `resume`. [`Error::is_fatal`] is that distinction. Every error also keeps the Python class
//! name, because `state.json:error` stores `type(exc).__name__` and the 3.x tools read it.

use std::borrow::Cow;
use std::fmt;
use std::io;

use pc_host::runner::{BoundedError, RunError};
use pc_host::TxError;

use installer_core::planner::PlanError;

/// `TransactionError(message)` (pc_host keeps its own constructor crate-private).
pub fn transaction(message: impl Into<String>) -> TxError {
    TxError::Transaction(message.into())
}

/// `OwnershipError(message)`.
pub fn ownership(message: impl Into<String>) -> TxError {
    TxError::Ownership(message.into())
}

/// An installer failure with the Python class name it had.
#[derive(Debug)]
pub enum Error {
    /// `TransactionError` and its subclasses, and the `OSError`s the journal code lets through.
    Tx(TxError),
    /// `PlanError` (a `ValueError`): a plan cannot be represented or executed safely.
    Plan(PlanError),
    /// Any other `Exception` an adapter raised (`CoreError`, `WarpError`, `AuditError`,
    /// `ValueError`, …): the engine rolls back and records `class`.
    Other { class: Cow<'static, str>, message: String },
    /// A `BaseException`: the engine stops at once and leaves the journal for `resume`.
    Fatal { class: Cow<'static, str>, message: String },
}

impl Error {
    /// An ordinary failure (`Exception` subclass `class`).
    pub fn other(class: impl Into<Cow<'static, str>>, message: impl Into<String>) -> Error {
        Error::Other { class: class.into(), message: message.into() }
    }

    /// A failure that must not trigger a rollback (`BaseException` subclass `class`).
    pub fn fatal(class: impl Into<Cow<'static, str>>, message: impl Into<String>) -> Error {
        Error::Fatal { class: class.into(), message: message.into() }
    }

    /// `type(exc).__name__`, as `state.json:error` records it.
    pub fn python_class_name(&self) -> &str {
        match self {
            Error::Tx(err) => err.python_class_name(),
            Error::Plan(err) => err.python_class_name(),
            Error::Other { class, .. } | Error::Fatal { class, .. } => class,
        }
    }

    /// `str(exc)`.
    pub fn message(&self) -> String {
        match self {
            Error::Tx(err) => err.message(),
            Error::Plan(err) => err.message().to_string(),
            Error::Other { message, .. } | Error::Fatal { message, .. } => message.clone(),
        }
    }

    /// Whether the engine must stop without rolling back (Python's `BaseException`).
    pub fn is_fatal(&self) -> bool {
        matches!(self, Error::Fatal { .. })
    }

    /// The transaction error inside, if this is one.
    pub fn as_tx(&self) -> Option<&TxError> {
        match self {
            Error::Tx(err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Tx(err) => Some(err),
            _ => None,
        }
    }
}

impl From<TxError> for Error {
    fn from(err: TxError) -> Self {
        Error::Tx(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Tx(TxError::Io(err))
    }
}

impl From<PlanError> for Error {
    fn from(err: PlanError) -> Self {
        Error::Plan(err)
    }
}

/// A mutating command: an interrupt or an unconfirmed cleanup stops the engine
/// ([`RunError::stops_the_engine`]); a timeout or a start failure is an ordinary error.
impl From<RunError> for Error {
    fn from(err: RunError) -> Self {
        let class = err.python_class_name();
        if err.stops_the_engine() {
            Error::fatal(class, err.to_string())
        } else {
            Error::other(class, err.to_string())
        }
    }
}

/// A bounded (audit-contract) command; an interrupt stops the engine.
impl From<BoundedError> for Error {
    fn from(err: BoundedError) -> Self {
        let class = err.python_class_name();
        if matches!(err, BoundedError::Interrupted) {
            Error::fatal(class, err.to_string())
        } else {
            Error::other(class, err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_names_and_fatality() {
        let tx: Error = crate::error::ownership("owned file drifted: /x").into();
        assert_eq!(
            (tx.python_class_name(), tx.message().as_str(), tx.is_fatal()),
            ("OwnershipError", "owned file drifted: /x", false)
        );
        let io: Error = io::Error::from_raw_os_error(libc_enoent()).into();
        assert_eq!(io.python_class_name(), "FileNotFoundError");
        assert_eq!(Error::from(PlanError::new("bad")).python_class_name(), "PlanError");
        let refused = Error::from(PlanError::adapter("NginxError", "port 80 is taken"));
        assert_eq!((refused.python_class_name(), refused.message().as_str()), ("NginxError", "port 80 is taken"));
        let crash = Error::from(RunError::CleanupUnconfirmed);
        assert!(crash.is_fatal());
        assert_eq!(crash.python_class_name(), "SystemExit");
        let timeout = Error::from(RunError::TimedOut { stderr: Vec::new() });
        assert!(!timeout.is_fatal());
        assert_eq!(timeout.python_class_name(), "TimeoutExpired");
        assert!(Error::from(BoundedError::Interrupted).is_fatal());
        assert_eq!(Error::from(BoundedError::TimedOut).python_class_name(), "AuditError");
        assert_eq!(Error::other("CoreError", "boom").to_string(), "boom");
    }

    fn libc_enoent() -> i32 {
        2
    }
}
