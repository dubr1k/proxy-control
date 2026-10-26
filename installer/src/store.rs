//! Private, atomic on-disk storage of one installer transaction (`TransactionStore`,
//! `installer/transaction.py:407-480`).
//!
//! | File (under `<root>/var/lib/proxy-control/installer/`, dir 0700) | Mode | Bytes |
//! |---|---|---|
//! | `state.json` (authoritative) | 0600 | `pretty2` (indent 2, sorted, raw UTF-8, `\n`) |
//! | `plan.json` | 0600 | the canonical plan, no newline |
//! | `ownership.json` (derived) | 0600 | `pretty2` of `{"files": …, "schema": 1}` |
//! | `report.json` (derived) | 0600 | `pretty2` |
//!
//! `backups/` and `credentials/` (0700) are created empty. Every write goes through
//! `pc_host::fs::atomic_write` and re-asserts the directories first, as Python did.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use pc_host::fs::{assert_contained, atomic_write, durable_mkdir, fsync_directory, root_path};
use pc_host::json;
use pc_host::{OperationLock, TxError, INSTALLER_PATH};
use serde_json::{Map, Value};

use crate::error::Error;
use crate::journal::{ownership_from_value, ownership_to_value, Ownership, TransactionState, TRANSACTION_SCHEMA};
use crate::plan::InstallPlan;

/// Which journal file a write targets (for the test fault hook).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalFile {
    State,
    Plan,
    Ownership,
    Report,
}

/// A test hook run before every journal write (`set_fault_hook`).
#[cfg(any(test, feature = "test-fakes"))]
pub type FaultHook = Box<dyn FnMut(JournalFile, &Value) -> Result<(), Error> + Send>;

/// The journal of `<root>/var/lib/proxy-control/installer`.
pub struct TransactionStore {
    root: PathBuf,
    directory: PathBuf,
    state_path: PathBuf,
    plan_path: PathBuf,
    ownership_path: PathBuf,
    backups_path: PathBuf,
    report_path: PathBuf,
    credentials_path: PathBuf,
    #[cfg(any(test, feature = "test-fakes"))]
    fault: std::sync::Mutex<Option<FaultHook>>,
}

impl std::fmt::Debug for TransactionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionStore").field("root", &self.root).finish_non_exhaustive()
    }
}

impl TransactionStore {
    /// `TransactionStore(root)`: the journal paths under `root`, whose existing ancestors must
    /// resolve inside `root` (`OwnershipError("rooted path escapes supplied root")`).
    pub fn new(root: &Path) -> Result<TransactionStore, TxError> {
        let directory = root_path(root, INSTALLER_PATH)?;
        Ok(TransactionStore {
            root: root.to_path_buf(),
            state_path: directory.join("state.json"),
            plan_path: directory.join("plan.json"),
            ownership_path: directory.join("ownership.json"),
            backups_path: directory.join("backups"),
            report_path: directory.join("report.json"),
            credentials_path: directory.join("credentials"),
            directory,
            #[cfg(any(test, feature = "test-fakes"))]
            fault: std::sync::Mutex::new(None),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub fn plan_path(&self) -> &Path {
        &self.plan_path
    }

    pub fn ownership_path(&self) -> &Path {
        &self.ownership_path
    }

    pub fn report_path(&self) -> &Path {
        &self.report_path
    }

    pub fn backups_path(&self) -> &Path {
        &self.backups_path
    }

    pub fn credentials_path(&self) -> &Path {
        &self.credentials_path
    }

    /// Whether a journal exists (`state_path.exists()`).
    pub fn state_exists(&self) -> bool {
        self.state_path.exists()
    }

    /// Creates the journal, backup and credential directories 0700 (and re-narrows them).
    pub fn initialize(&self) -> Result<(), TxError> {
        for directory in [&self.directory, &self.backups_path, &self.credentials_path] {
            assert_contained(&self.root, directory)?;
        }
        for directory in [&self.directory, &self.backups_path, &self.credentials_path] {
            durable_mkdir(directory, 0o700)?;
        }
        for directory in [&self.directory, &self.backups_path, &self.credentials_path] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            fsync_directory(directory)?;
        }
        Ok(())
    }

    /// The host operation lock (`operation_lock(root)`).
    pub fn locked(&self) -> Result<OperationLock, TxError> {
        pc_host::operation_lock(&self.root)
    }

    /// Writes `plan.json` (the canonical bytes the digest covers).
    pub fn write_plan(&self, plan: &InstallPlan) -> Result<(), Error> {
        self.fault(JournalFile::Plan, &plan.canonical_value())?;
        self.initialize()?;
        atomic_write(&self.plan_path, plan.to_canonical_json().as_bytes(), 0o600, None)?;
        Ok(())
    }

    /// Reads `plan.json`: `transaction plan is unreadable` / `transaction plan is invalid`.
    pub fn read_plan(&self) -> Result<InstallPlan, TxError> {
        let bytes =
            fs::read(&self.plan_path).map_err(|_| crate::error::transaction("transaction plan is unreadable"))?;
        let value = json::loads(&bytes).map_err(|_| crate::error::transaction("transaction plan is unreadable"))?;
        InstallPlan::from_value(&value).map_err(|_| crate::error::transaction("transaction plan is invalid"))
    }

    /// Writes the authoritative `state.json` (after checking the state's invariants).
    pub fn write_state(&self, state: &TransactionState) -> Result<(), Error> {
        state.validate()?;
        self.write_json(JournalFile::State, &self.state_path, &state.to_value())
    }

    /// Reads `state.json` with the strict reader.
    pub fn read_state(&self) -> Result<TransactionState, TxError> {
        TransactionState::from_value(&Value::Object(self.read_json(&self.state_path, "state")?))
    }

    /// Writes the derived `ownership.json`.
    pub fn write_ownership(&self, ownership: &Ownership) -> Result<(), Error> {
        let mut map = Map::new();
        map.insert("files".into(), ownership_to_value(ownership));
        map.insert("schema".into(), Value::from(TRANSACTION_SCHEMA));
        self.write_json(JournalFile::Ownership, &self.ownership_path, &Value::Object(map))
    }

    /// Reads `ownership.json`: exactly `{"files", "schema": 1}`, else
    /// `OwnershipError("ownership journal is invalid")`.
    pub fn read_ownership(&self) -> Result<Ownership, TxError> {
        let map = self.read_json(&self.ownership_path, "ownership journal")?;
        let journal_invalid = || crate::error::ownership("ownership journal is invalid");
        if map.len() != 2 || !map.contains_key("files") || map.get("schema") != Some(&Value::from(TRANSACTION_SCHEMA)) {
            return Err(journal_invalid());
        }
        ownership_from_value(&map["files"]).ok_or_else(journal_invalid)
    }

    /// Writes the derived `report.json`.
    pub fn write_report(&self, report: &Value) -> Result<(), Error> {
        self.write_json(JournalFile::Report, &self.report_path, report)
    }

    /// Removes `state.json` (a finished rollback or uninstall before a new install).
    pub fn remove_state(&self) -> Result<(), TxError> {
        match fs::remove_file(&self.state_path) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err.into()),
            _ => Ok(()),
        }
    }

    fn write_json(&self, file: JournalFile, path: &Path, value: &Value) -> Result<(), Error> {
        self.fault(file, value)?;
        self.initialize()?;
        atomic_write(path, json::pretty2(value).as_bytes(), 0o600, None)?;
        Ok(())
    }

    fn read_json(&self, path: &Path, label: &str) -> Result<Map<String, Value>, TxError> {
        let unreadable = || crate::error::transaction(format!("transaction {label} is unreadable"));
        let bytes = fs::read(path).map_err(|_| unreadable())?;
        match json::loads(&bytes).map_err(|_| unreadable())? {
            Value::Object(map) => Ok(map),
            _ => Err(crate::error::transaction(format!("transaction {label} is invalid"))),
        }
    }

    #[cfg(any(test, feature = "test-fakes"))]
    fn fault(&self, file: JournalFile, value: &Value) -> Result<(), Error> {
        match self.fault.lock().expect("fault hook lock").as_mut() {
            Some(hook) => hook(file, value),
            None => Ok(()),
        }
    }

    #[cfg(not(any(test, feature = "test-fakes")))]
    fn fault(&self, _file: JournalFile, _value: &Value) -> Result<(), Error> {
        Ok(())
    }

    /// Test seam: `hook` runs before every journal write and can fail it (an `Error::Fatal`
    /// simulates the process dying there). `None` removes it.
    #[cfg(any(test, feature = "test-fakes"))]
    pub fn set_fault_hook(&self, hook: Option<FaultHook>) {
        *self.fault.lock().expect("fault hook lock") = hook;
    }
}
