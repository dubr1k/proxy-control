//! Subscription rows (`subscriptions/store.py`). The token itself is written only as a hash; its
//! escrowed copy lives in `secret_versions` and the row keeps a reference. Every function runs in
//! the caller's connection or transaction.

use panel_core::db::{Conn, DbError};
use panel_core::rusqlite::{params, OptionalExtension as _, Row};
use panel_model::subscriptions::Subscription;
use panel_model::SecretRef;
use serde_json::{json, Value};

const COLUMNS: &str = "id, client_id, generation, state, update_interval_hours, last_fetched_at, \
                       created_at, updated_at, revoked_at, secret_id, secret_version";

fn read(row: &Row<'_>) -> panel_core::rusqlite::Result<Subscription> {
    let secret_id: Option<String> = row.get(9)?;
    let secret_version: Option<i64> = row.get(10)?;
    Ok(Subscription {
        id: row.get(0)?,
        client_id: row.get(1)?,
        generation: row.get(2)?,
        state: row.get(3)?,
        update_interval_hours: row.get(4)?,
        last_fetched_at: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        revoked_at: row.get(8)?,
        // `SecretRef(secret_id, secret_version) if secret_id else None`.
        secret_ref: secret_id
            .filter(|id| !id.is_empty())
            .map(|secret_id| SecretRef { secret_id, version: secret_version.unwrap_or_default() }),
    })
}

/// `insert(db, subscription, token_hash)`.
pub fn insert(db: &Conn, subscription: &Subscription, token_hash: &str) -> Result<(), DbError> {
    let reference = subscription.secret_ref.as_ref();
    db.execute(
        "INSERT INTO client_subscriptions(id,client_id,public_token_hash,generation,state,
               update_interval_hours,last_fetched_at,created_at,updated_at,revoked_at,secret_id,secret_version)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            subscription.id,
            subscription.client_id,
            token_hash,
            subscription.generation,
            subscription.state,
            subscription.update_interval_hours,
            subscription.last_fetched_at,
            subscription.created_at,
            subscription.updated_at,
            subscription.revoked_at,
            reference.map(|reference| reference.secret_id.clone()),
            reference.map(|reference| reference.version),
        ],
    )?;
    Ok(())
}

/// `active(db, client_id)`: the client's live subscription.
pub fn active(db: &Conn, client_id: &str) -> Result<Option<Subscription>, DbError> {
    Ok(db
        .query_row(
            &format!("SELECT {COLUMNS} FROM client_subscriptions WHERE client_id=? AND state='active'"),
            params![client_id],
            read,
        )
        .optional()?)
}

/// `by_hash(db, token_hash)`: the live subscription a token hash names.
pub fn by_hash(db: &Conn, token_hash: &str) -> Result<Option<Subscription>, DbError> {
    Ok(db
        .query_row(
            &format!("SELECT {COLUMNS} FROM client_subscriptions WHERE public_token_hash=? AND state='active'"),
            params![token_hash],
            read,
        )
        .optional()?)
}

/// `revoke(db, client_id, now=…)`: how many rows went from active to revoked.
pub fn revoke(db: &Conn, client_id: &str, now: i64) -> Result<usize, DbError> {
    db.execute(
        "UPDATE client_subscriptions SET state='revoked',revoked_at=?,updated_at=? WHERE client_id=? AND state='active'",
        params![now, now, client_id],
    )
}

/// `bump(db, client_id, now=…)`: how many live rows moved one generation on.
pub fn bump(db: &Conn, client_id: &str, now: i64) -> Result<usize, DbError> {
    db.execute(
        "UPDATE client_subscriptions SET generation=generation+1,updated_at=? WHERE client_id=? AND state='active'",
        params![now, client_id],
    )
}

/// `record_fetch(db, subscription_id, now)`.
pub fn record_fetch(db: &Conn, subscription_id: &str, now: i64) -> Result<(), DbError> {
    db.execute("UPDATE client_subscriptions SET last_fetched_at=? WHERE id=?", params![now, subscription_id])?;
    Ok(())
}

/// `_public(subscription)`: `dataclasses.asdict` without the secret reference (field order).
pub fn public_json(subscription: &Subscription) -> Value {
    json!({
        "id": subscription.id,
        "client_id": subscription.client_id,
        "generation": subscription.generation,
        "state": subscription.state,
        "update_interval_hours": subscription.update_interval_hours,
        "last_fetched_at": subscription.last_fetched_at,
        "created_at": subscription.created_at,
        "updated_at": subscription.updated_at,
        "revoked_at": subscription.revoked_at,
    })
}
