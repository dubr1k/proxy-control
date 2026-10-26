//! Who this panel is (`panel/fleet_v2/identity.py`): one GUID per database, minted on first use,
//! and the release version it reports to a central panel.

use std::path::Path;

use panel_core::db::{Conn, Database, DbError};
use panel_core::pytext;
use panel_core::rusqlite::{params, OptionalExtension as _};

/// `panel_settings` key of this panel's GUID.
pub const GUID_KEY: &str = "panel_guid";
/// `panel_settings` key of the central panel's GUID (on a linked node).
pub const MASTER_KEY: &str = "fleet_master_guid";

/// `read_setting(db, key)`.
pub fn read_setting(db: &Conn, key: &str) -> Result<Option<String>, DbError> {
    Ok(db.query_row("SELECT value FROM panel_settings WHERE key=?", [key], |row| row.get(0)).optional()?)
}

/// `write_setting(db, key, value)` at the current time: upsert, or delete for `None`.
pub fn write_setting(db: &Conn, key: &str, value: Option<&str>) -> Result<(), DbError> {
    write_setting_at(db, key, value, crate::now())
}

/// [`write_setting`] with `updated_at` given.
pub fn write_setting_at(db: &Conn, key: &str, value: Option<&str>, now: i64) -> Result<(), DbError> {
    match value {
        None => db.execute("DELETE FROM panel_settings WHERE key=?", [key])?,
        Some(value) => db.execute(
            "INSERT INTO panel_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            params![key, value, now],
        )?,
    };
    Ok(())
}

/// `read_panel_version(path)`: the release's VERSION, stripped, or `"dev"` when the file is
/// missing, unreadable, not UTF-8 or empty — a bad file must never keep the panel from starting.
pub fn read_panel_version(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => match pytext::strip(&text) {
            "" => "dev".into(),
            version => version.into(),
        },
        Err(_) => "dev".into(),
    }
}

/// `ensure_guid(database)`: the stored GUID, or a new `uuid4` stored in the same `BEGIN
/// IMMEDIATE` transaction (an empty stored value counts as none).
pub fn ensure_guid(database: &Database) -> Result<String, DbError> {
    database.transaction(|db| {
        if let Some(found) = read_setting(db, GUID_KEY)?.filter(|found| !found.is_empty()) {
            return Ok(found);
        }
        let value = panel_core::ids::uuid4();
        write_setting(db, GUID_KEY, Some(&value))?;
        Ok(value)
    })
}
