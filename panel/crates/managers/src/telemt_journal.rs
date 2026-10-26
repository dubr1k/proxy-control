//! The Telemt egress journal (`protocols/telemt.py:330-347`): no manager stands between the panel
//! and Telemt, so the panel keeps, secret-free, the journal a manager would keep for «rollback» —
//! `<dirname(PANEL_DATABASE)>/telemt-egress.json` with the keys `current`, `previous` and
//! `direct_upstreams`.
//!
//! Written as Python's `json.dumps(journal, sort_keys=True)` (default separators, ASCII) to
//! `.telemt-egress.json.tmp` beside it, `chmod 0600`, then renamed over the journal (no fsync,
//! as in Python). Without a path the journal lives in memory (the tests' adapter).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde_json::{json, Value};

/// The journal before anything was applied.
pub fn empty_journal() -> Value {
    json!({"current": null, "previous": null, "direct_upstreams": null})
}

/// `AdapterError("the Telemt egress journal is unreadable", code="manual_intervention_required")`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalUnreadable;

impl JournalUnreadable {
    pub const CODE: &'static str = "manual_intervention_required";
}

impl std::fmt::Display for JournalUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the Telemt egress journal is unreadable")
    }
}

impl std::error::Error for JournalUnreadable {}

#[derive(Debug)]
pub struct TelemtEgressJournal {
    path: Option<PathBuf>,
    memory: Mutex<Value>,
}

impl TelemtEgressJournal {
    /// The journal file `path`, or an in-memory journal (`journal_path=None`).
    pub fn new(path: Option<PathBuf>) -> Self {
        Self { path, memory: Mutex::new(empty_journal()) }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// `_journal_read()`: a missing file is the empty journal; an unreadable one, or one that is
    /// not a JSON object, needs a human.
    pub fn read(&self) -> Result<Value, JournalUnreadable> {
        let Some(path) = &self.path else {
            return Ok(self.memory.lock().unwrap_or_else(PoisonError::into_inner).clone());
        };
        let text = match std::fs::read(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(empty_journal()),
            Err(_) => return Err(JournalUnreadable),
        };
        match serde_json::from_slice::<Value>(&text) {
            Ok(journal @ Value::Object(_)) => Ok(journal),
            _ => Err(JournalUnreadable),
        }
    }

    /// `_journal_write(journal)`.
    pub fn write(&self, journal: &Value) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            *self.memory.lock().unwrap_or_else(PoisonError::into_inner) = journal.clone();
            return Ok(());
        };
        let name = path.file_name().ok_or_else(|| std::io::Error::other("journal path has no file name"))?;
        let mut temporary_name = std::ffi::OsString::from(".");
        temporary_name.push(name);
        temporary_name.push(".tmp");
        let temporary = path.with_file_name(temporary_name);
        std::fs::write(&temporary, panel_core::pyjson::sorted(journal))?;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&temporary, path)
    }
}
