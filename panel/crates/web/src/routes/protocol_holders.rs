//! Public local access-holder projection. Never loads credentials/options or paginates clients.
use crate::http::response::Failure;
use crate::state::AppState;
use panel_model::Protocol;
use serde_json::{json, Value};
use std::collections::HashMap;

pub async fn enrich(app: &AppState, protocol: Protocol, mut body: Value) -> Result<Value, Failure> {
    let database = app.database.clone();
    let holders = tokio::task::spawn_blocking(move || {
        database.with_connection(|db| {
            let mut statement = db.prepare(
                "SELECT g.runtime_username,g.id,g.client_id,c.display_name,c.state FROM access_grants g \
                 JOIN clients c ON c.id=g.client_id \
                 WHERE g.protocol=?1 AND g.node_id='local' AND g.endpoint_id='default' \
                 AND g.desired_state<>'deleted'",
            )?;
            let rows = statement.query_map([protocol.as_str()], |row| {
                let username: String = row.get(0)?;
                Ok((
                    username,
                    json!({"grant_id": row.get::<_,String>(1)?, "client_id":row.get::<_,String>(2)?,
                    "client_name":row.get::<_,String>(3)?, "client_state":row.get::<_,String>(4)?}),
                ))
            })?;
            Ok::<_, panel_core::db::DbError>(
                rows.collect::<Result<HashMap<String, Value>, panel_core::rusqlite::Error>>()?,
            )
        })
    })
    .await
    .map_err(Failure::internal)?
    .map_err(Failure::internal)?;
    for row in body.get_mut("items").and_then(Value::as_array_mut).into_iter().flatten() {
        let holder = row.get("username").and_then(Value::as_str).and_then(|name| holders.get(name));
        let fields: Vec<_> = ["client_id", "client_name", "grant_id", "client_state"]
            .into_iter()
            .map(|key| (key, holder.and_then(|h| h.get(key)).cloned().unwrap_or(Value::Null)))
            .collect();
        if let Some(row) = row.as_object_mut() {
            for (key, value) in fields {
                row.insert(key.into(), value);
            }
        }
    }
    Ok(body)
}
