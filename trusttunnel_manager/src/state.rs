//! Schema-versioned JSON state, written atomically (0600 file in a 0700 directory).

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

pub const SCHEMA: u64 = 1;
pub const MAX_OPERATIONS: usize = 2000;

/// The state file is unreadable or from an unknown schema; the manager refuses to run.
#[derive(Debug)]
pub struct StateError(pub String);

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StateError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    pub password: String,
    pub enabled: bool,
    pub revision: u64,
    pub rx: u64,
    pub tx: u64,
    pub last_out: u64,
    pub last_in: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub fingerprint: String,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDocument {
    pub mode: String,
    pub address: Option<String>,
}

impl EgressDocument {
    pub fn direct() -> Self {
        Self { mode: "direct".into(), address: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Egress {
    pub document: EgressDocument,
    pub previous: Option<EgressDocument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Document {
    pub schema: u64,
    pub clients: BTreeMap<String, Client>,
    /// Kept in arrival order, so the oldest operations are the ones pruned.
    pub operations: IndexMap<String, Operation>,
    pub placeholder: Option<String>,
    pub egress: Egress,
}

/// In-memory document plus its file. The caller serialises access.
pub struct StateStore {
    pub directory: PathBuf,
    pub path: PathBuf,
    pub doc: Document,
}

impl StateStore {
    pub fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_path_buf(),
            path: directory.join("state.json"),
            doc: Document {
                schema: SCHEMA,
                clients: BTreeMap::new(),
                operations: IndexMap::new(),
                placeholder: None,
                egress: Egress { document: EgressDocument::direct(), previous: None },
            },
        }
    }

    pub fn load(&mut self) -> Result<(), StateError> {
        let io = |err: std::io::Error| StateError(format!("cannot prepare {}: {err}", self.directory.display()));
        std::fs::create_dir_all(&self.directory).map_err(io)?;
        std::fs::set_permissions(&self.directory, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
        let text = match std::fs::read(&self.path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(StateError(format!("cannot read {}", self.path.display()))),
        };
        let value: serde_json::Value =
            serde_json::from_slice(&text).map_err(|_| StateError(format!("cannot read {}", self.path.display())))?;
        if value.get("schema").and_then(|v| v.as_u64()) != Some(SCHEMA) || !value.is_object() {
            return Err(StateError("unsupported state schema".into()));
        }
        for key in ["clients", "operations", "egress"] {
            if !value.get(key).is_some_and(|v| v.is_object()) {
                return Err(StateError(format!("state field {key} is malformed")));
            }
        }
        // Deserialise from the text, not the parsed value: the operations keep their file order.
        self.doc = serde_json::from_slice(&text).map_err(|_| StateError("state document is malformed".into()))?;
        Ok(())
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        let excess = self.doc.operations.len().saturating_sub(MAX_OPERATIONS);
        if excess > 0 {
            self.doc.operations.drain(..excess);
        }
        // Through a `Value`: its maps sort their keys, as `json.dumps(sort_keys=True)` did.
        let value = serde_json::to_value(&self.doc).map_err(std::io::Error::other)?;
        let mut data = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
        let mut serializer = serde_json::Serializer::with_formatter(&mut data, formatter);
        value.serialize(&mut serializer).map_err(std::io::Error::other)?;
        pc_common::fsutil::write_atomic(&self.path, &data, 0o600)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn corrupt_or_foreign_state_is_refused() {
        let dir = tempdir("state-refused");
        let mut store = StateStore::new(&dir.join("state"));
        std::fs::create_dir_all(&store.directory).unwrap();
        std::fs::write(&store.path, r#"{"schema": 99}"#).unwrap();
        assert!(store.load().is_err());
        std::fs::write(&store.path, "not json").unwrap();
        assert!(store.load().is_err());
        std::fs::write(&store.path, r#"{"schema": 1, "clients": [], "operations": {}, "egress": {}}"#).unwrap();
        assert!(store.load().unwrap_err().0.contains("clients"));
    }

    #[test]
    fn operations_keep_order_and_the_oldest_are_pruned() {
        let dir = tempdir("state-prune");
        let mut store = StateStore::new(&dir);
        store.load().unwrap();
        for i in 0..MAX_OPERATIONS + 3 {
            store.doc.operations.insert(format!("op-{i}"), Operation { fingerprint: "f".into(), username: "u".into() });
        }
        store.save().unwrap();
        assert_eq!(store.doc.operations.len(), MAX_OPERATIONS);
        assert!(!store.doc.operations.contains_key("op-0") && store.doc.operations.contains_key("op-3"));
        let text = std::fs::read_to_string(&store.path).unwrap();
        assert!(text.starts_with("{\n \"clients\": {},\n \"egress\": {"), "{}", &text[..60]);
    }

    pub fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
