//! The agent's exceptions (`service.py:31-50`, `catalog.CatalogError`) and how the HTTP layer
//! reports them.

use std::fmt;

/// `UpdateError.state` and its subclasses' states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateState {
    /// `UpdateError` (also `ConflictError`, which inherits it).
    UpdateFailed,
    /// `RolledBackError`: the update failed, the previous generation was verified.
    RolledBack,
    /// `RollbackFailedError`: the update failed and the previous generation could not be verified.
    RollbackFailed,
}

impl UpdateState {
    pub fn as_str(self) -> &'static str {
        match self {
            UpdateState::UpdateFailed => "update_failed",
            UpdateState::RolledBack => "rolled_back",
            UpdateState::RollbackFailed => "rollback_failed",
        }
    }

    /// The Python class name used in the failure log line.
    pub fn class_name(self) -> &'static str {
        match self {
            UpdateState::UpdateFailed => "UpdateError",
            UpdateState::RolledBack => "RolledBackError",
            UpdateState::RollbackFailed => "RollbackFailedError",
        }
    }
}

/// One link of an exception chain (`__cause__`/`__context__`), for the failure log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cause {
    /// The Python class name it stands for (`CalledProcessError`, `ArtifactError`, …).
    pub class: String,
    pub message: String,
    /// The captured stderr of a failed command.
    pub stderr: Option<String>,
}

/// `UpdateError` and its subclasses `RolledBackError` / `RollbackFailedError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateError {
    pub message: String,
    pub state: UpdateState,
    /// What caused it, nearest first.
    pub causes: Vec<Cause>,
}

impl UpdateError {
    pub fn new(message: impl Into<String>) -> Self {
        UpdateError { message: message.into(), state: UpdateState::UpdateFailed, causes: Vec::new() }
    }

    pub fn rolled_back(message: impl Into<String>) -> Self {
        UpdateError { state: UpdateState::RolledBack, ..UpdateError::new(message) }
    }

    pub fn rollback_failed(message: impl Into<String>) -> Self {
        UpdateError { state: UpdateState::RollbackFailed, ..UpdateError::new(message) }
    }

    /// `raise … from cause`.
    pub fn caused_by(mut self, cause: Cause) -> Self {
        self.causes.push(cause);
        self
    }

    /// `raise … from other` where `other` is itself an agent error: its chain follows.
    pub fn caused_by_update(mut self, other: &UpdateError) -> Self {
        self.causes.push(Cause {
            class: other.state.class_name().into(),
            message: other.message.clone(),
            stderr: None,
        });
        self.causes.extend(other.causes.iter().cloned());
        self
    }
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UpdateError {}

/// `CatalogError`: the trusted catalog (or a cached candidate) is malformed or unsafe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogError(pub String);

impl CatalogError {
    pub fn new(message: impl Into<String>) -> Self {
        CatalogError(message.into())
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CatalogError {}

/// Everything a request into the agent can end in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    /// `ConflictError` (409 on update and rebuild; an `UpdateError` everywhere else).
    Conflict(String),
    Catalog(CatalogError),
    Update(UpdateError),
    /// `ValueError` of the managers acknowledgement (422).
    Invalid(String),
    /// Anything Python let escape as a traceback (the connection closed without an answer);
    /// answered 500 here.
    Internal(String),
}

impl AgentError {
    pub fn conflict(message: impl Into<String>) -> Self {
        AgentError::Conflict(message.into())
    }

    pub fn update(message: impl Into<String>) -> Self {
        AgentError::Update(UpdateError::new(message))
    }

    /// `str(exc)`.
    pub fn message(&self) -> &str {
        match self {
            AgentError::Conflict(message) | AgentError::Invalid(message) | AgentError::Internal(message) => message,
            AgentError::Catalog(error) => &error.0,
            AgentError::Update(error) => &error.message,
        }
    }

    /// `exc.state` for what Python caught as an `UpdateError` (a conflict included).
    pub fn update_state(&self) -> Option<UpdateState> {
        match self {
            AgentError::Conflict(_) => Some(UpdateState::UpdateFailed),
            AgentError::Update(error) => Some(error.state),
            _ => None,
        }
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for AgentError {}

impl From<CatalogError> for AgentError {
    fn from(error: CatalogError) -> Self {
        AgentError::Catalog(error)
    }
}

impl From<UpdateError> for AgentError {
    fn from(error: UpdateError) -> Self {
        AgentError::Update(error)
    }
}

/// `str(text).strip().replace("\n", " ")[:300]` and the stderr tail: one link of the failure log.
fn link(class: &str, message: &str, stderr: Option<&str>) -> String {
    let text: String = crate::py::strip(message).replace('\n', " ").chars().take(300).collect();
    let mut text = format!("{class}: {text}");
    if let Some(stderr) = stderr {
        let stderr = crate::py::strip(stderr).replace('\n', " ");
        if !stderr.is_empty() {
            let count = stderr.chars().count();
            let tail: String = stderr.chars().skip(count.saturating_sub(400)).collect();
            text.push_str(" | stderr: ");
            text.push_str(&tail);
        }
    }
    text
}

/// `_log_failure` (`server.py:25-37`): the exception chain's types and messages (at most six
/// links) and the stderr tail of a failed command — never a request body or an artifact.
pub fn failure_line(component: &str, version: &str, error: &UpdateError) -> String {
    let mut chain = vec![link(error.state.class_name(), &error.message, None)];
    for cause in &error.causes {
        if chain.len() >= 6 {
            break;
        }
        chain.push(link(&cause.class, &cause.message, cause.stderr.as_deref()));
    }
    format!("update {component} -> {version} failed: {}", chain.join(" <- "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_line_has_the_chain_and_the_stderr_tail() {
        let error = UpdateError::rolled_back("naive update failed; previous generation was restored and verified")
            .caused_by(Cause {
                class: "CalledProcessError".into(),
                message: "Command '['systemctl', 'restart', 'caddy-naive']' returned non-zero exit status 1.".into(),
                stderr: Some("Job for caddy-naive.service failed\nsee journal\n".into()),
            });
        assert_eq!(
            failure_line("naive", "2.11.8", &error),
            "update naive -> 2.11.8 failed: RolledBackError: naive update failed; previous generation was restored \
             and verified <- CalledProcessError: Command '['systemctl', 'restart', 'caddy-naive']' returned non-zero \
             exit status 1. | stderr: Job for caddy-naive.service failed see journal"
        );
        let mut long = UpdateError::new("x".repeat(400));
        for _ in 0..10 {
            long =
                long.caused_by(Cause { class: "OSError".into(), message: "y".into(), stderr: Some("z".repeat(500)) });
        }
        let line = failure_line("mita", "1", &long);
        assert_eq!(line.matches(" <- ").count(), 5);
        assert!(line.contains(&format!("UpdateError: {} <-", "x".repeat(300))));
        assert!(line.ends_with(&format!("| stderr: {}", "z".repeat(400))));
    }
}
