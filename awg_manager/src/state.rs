//! Schema-versioned JSON state, written atomically (0600 file in a 0700 directory).
//!
//! The document stays a JSON value, as the Python manager's dict was: every field it holds survives
//! a load and a save, maps keep their order (operations are pruned oldest first), and the file is
//! written exactly as `json.dumps(doc, indent=1, sort_keys=True)` wrote it.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

pub const SCHEMA: u64 = 1;
pub const MAX_OPERATIONS: usize = 2000;

/// The state file is unreadable or from an unknown schema; the manager refuses to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateError(pub String);

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StateError {}

/// In-memory document plus its file. The caller serialises access.
pub struct StateStore {
    pub directory: PathBuf,
    pub path: PathBuf,
    pub doc: Value,
    /// Tests: make the next saves fail as a full disk would.
    #[cfg(test)]
    pub fail_save: bool,
}

impl StateStore {
    pub fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_path_buf(),
            path: directory.join("state.json"),
            doc: json!({"schema": SCHEMA, "instances": {}, "peers": {}, "operations": {}}),
            #[cfg(test)]
            fail_save: false,
        }
    }

    pub fn load(&mut self) -> Result<(), StateError> {
        let prepare = |err: std::io::Error| StateError(format!("cannot prepare {}: {err}", self.directory.display()));
        std::fs::create_dir_all(&self.directory).map_err(prepare)?;
        std::fs::set_permissions(&self.directory, std::fs::Permissions::from_mode(0o700)).map_err(prepare)?;
        let text = match std::fs::read(&self.path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(StateError(format!("cannot read {}", self.path.display()))),
        };
        let doc: Value =
            serde_json::from_slice(&text).map_err(|_| StateError(format!("cannot read {}", self.path.display())))?;
        if !doc.is_object() || doc.get("schema").and_then(Value::as_f64) != Some(SCHEMA as f64) {
            return Err(StateError("unsupported state schema".into()));
        }
        for key in ["instances", "peers", "operations"] {
            if !doc.get(key).is_some_and(Value::is_object) {
                return Err(StateError(format!("state field {key} is malformed")));
            }
        }
        self.doc = doc;
        Ok(())
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        let operations = self.operations_mut();
        while operations.len() > MAX_OPERATIONS {
            let oldest = operations.keys().next().cloned().expect("a non-empty map has a first key");
            operations.shift_remove(&oldest);
        }
        #[cfg(test)]
        if self.fail_save {
            return Err(std::io::Error::other("disk full"));
        }
        pc_common::fsutil::write_atomic(&self.path, crate::pyjson::state(&self.doc).as_bytes(), 0o600)
    }

    fn section_mut(&mut self, key: &str) -> &mut Map<String, Value> {
        self.doc.get_mut(key).and_then(Value::as_object_mut).expect("a loaded document has its sections")
    }

    fn section(&self, key: &str) -> &Map<String, Value> {
        self.doc.get(key).and_then(Value::as_object).expect("a loaded document has its sections")
    }

    pub fn instances(&self) -> &Map<String, Value> {
        self.section("instances")
    }

    pub fn instances_mut(&mut self) -> &mut Map<String, Value> {
        self.section_mut("instances")
    }

    pub fn peers(&self) -> &Map<String, Value> {
        self.section("peers")
    }

    pub fn peers_mut(&mut self) -> &mut Map<String, Value> {
        self.section_mut("peers")
    }

    pub fn operations(&self) -> &Map<String, Value> {
        self.section("operations")
    }

    pub fn operations_mut(&mut self) -> &mut Map<String, Value> {
        self.section_mut("operations")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("awg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn state_is_atomic_private_and_schema_checked() {
        let dir = tempdir("state-atomic").join("s");
        let mut store = StateStore::new(&dir);
        store.load().unwrap();
        store.peers_mut().insert("a".into(), json!({"x": 1}));
        store.save().unwrap();
        assert_eq!(mode_of(&store.path), 0o600);
        assert_eq!(mode_of(&store.directory), 0o700);
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["state.json"]);
        let mut again = StateStore::new(&dir);
        again.load().unwrap();
        assert_eq!(again.peers()["a"], json!({"x": 1}));
        std::fs::write(&store.path, "{not json").unwrap();
        assert!(StateStore::new(&dir).load().is_err());
        std::fs::write(&store.path, r#"{"schema": 99, "instances": {}, "peers": {}, "operations": {}}"#).unwrap();
        assert!(StateStore::new(&dir).load().is_err());
        std::fs::write(&store.path, r#"{"schema": 1, "instances": [], "peers": {}, "operations": {}}"#).unwrap();
        assert_eq!(StateStore::new(&dir).load().unwrap_err().0, "state field instances is malformed");
    }

    #[test]
    fn operations_keep_order_and_the_oldest_are_pruned() {
        let dir = tempdir("state-prune");
        let mut store = StateStore::new(&dir);
        store.load().unwrap();
        for i in 0..MAX_OPERATIONS + 3 {
            store.operations_mut().insert(format!("op-{i}"), json!({"digest": "d", "username": "u"}));
        }
        store.save().unwrap();
        let ops = store.operations();
        assert_eq!(ops.len(), MAX_OPERATIONS);
        assert!(!ops.contains_key("op-0") && !ops.contains_key("op-2") && ops.contains_key("op-3"));
    }
}
