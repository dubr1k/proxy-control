//! ADR 003: a runtime user the central panel owns has exactly one writer — the central's
//! generation, not this panel's UI (`fleet_v2/guard.py` and the reads of `fleet_v2/managed.py`
//! that the clients domain needs; the rest of `ManagedStore` is WP12's).

use std::collections::HashSet;

use panel_core::db::Conn;
use panel_core::rusqlite::{params, OptionalExtension as _};

use crate::ClientsError;

/// `ManagedStore.is_managed`: a `managed_resources` row that is not `missing`.
pub fn is_managed(db: &Conn, protocol: &str, username: &str) -> Result<bool, ClientsError> {
    Ok(db
        .query_row(
            "SELECT 1 FROM managed_resources WHERE protocol=? AND runtime_username=? AND state<>'missing'",
            params![protocol, username],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// `ManagedStore.owned(db)`: the `(protocol, runtime_username)` the central owns right now.
pub fn owned(db: &Conn) -> Result<HashSet<(String, String)>, ClientsError> {
    let mut statement = db.prepare("SELECT protocol, runtime_username, state FROM managed_resources")?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))?;
    let mut out = HashSet::new();
    for row in rows {
        let (protocol, username, state) = row?;
        if state != "missing" {
            out.insert((protocol, username));
        }
    }
    Ok(out)
}

/// `require_unmanaged(db, managed, protocol, username)`.
pub fn require_unmanaged(db: &Conn, protocol: &str, username: &str) -> Result<(), ClientsError> {
    if is_managed(db, protocol, username)? {
        return Err(ClientsError::ManagedByCentral);
    }
    Ok(())
}
