//! Helpers shared by the integration tests.
#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use panel_core::db::Database;
use panel_core::serde_json::{self, Value};

/// A directory removed when dropped.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "panel-secrets-{label}-{}-{}",
            std::process::id(),
            panel_core::ids::token_hex(6)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

pub fn fixture_json(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixture_path(name)).unwrap()).unwrap()
}

/// A freshly migrated database in `dir`.
pub fn migrated(dir: &TempDir) -> Database {
    let database = Database::open(dir.join("panel.sqlite3")).unwrap();
    panel_core::migrations::apply_migrations(&database).unwrap();
    database
}

/// A fixture keyring copied into `dir` with mode 0600 (git does not keep file modes).
pub fn private_copy(fixture: &str, dir: &TempDir, name: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::copy(fixture_path(fixture), &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// Bytes of the database file and its WAL.
pub fn database_bytes(database: &Database) -> Vec<u8> {
    let mut bytes = std::fs::read(database.path()).unwrap();
    let mut wal = database.path().as_os_str().to_os_string();
    wal.push("-wal");
    if let Ok(more) = std::fs::read(PathBuf::from(wal)) {
        bytes.extend(more);
    }
    bytes
}
