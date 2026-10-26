//! Certificate rows of fleet v1 nodes, read inside the caller's transaction
//! (`nodes/certificates.py`). Fleet v1 is retired: nothing issues, binds or revokes certificates any
//! more, but the rows a v1 node left behind still show in its view.

use panel_core::db::Conn;
use panel_core::rusqlite;
use serde_json::{Map, Value};

use crate::error::NodesError;
use crate::CertificateInfo;

/// The node's certificates, newest first.
pub fn list(db: &Conn, node_id: &str) -> Result<Vec<CertificateInfo>, NodesError> {
    let mut statement = db.prepare("SELECT * FROM fleet_certificates WHERE node_id=? ORDER BY issued_at DESC")?;
    let rows = statement.query_map([node_id], |row| {
        Ok(CertificateInfo {
            serial: row.get("serial")?,
            fingerprint_sha256: row.get("fingerprint_sha256")?,
            not_before: row.get("not_before")?,
            not_after: row.get("not_after")?,
            state: row.get("state")?,
            issued_at: row.get("issued_at")?,
            revoked_at: row.get("revoked_at")?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// `asdict(certificate)`: the fields in declaration order.
pub fn to_value(certificate: &CertificateInfo) -> Value {
    let mut out = Map::new();
    out.insert("serial".into(), certificate.serial.clone().into());
    out.insert("fingerprint_sha256".into(), certificate.fingerprint_sha256.clone().into());
    out.insert("not_before".into(), certificate.not_before.into());
    out.insert("not_after".into(), certificate.not_after.into());
    out.insert("state".into(), certificate.state.clone().into());
    out.insert("issued_at".into(), certificate.issued_at.into());
    out.insert("revoked_at".into(), certificate.revoked_at.into());
    Value::Object(out)
}
