//! Client and grant rows (`clients/store.py`). Every function takes the caller's connection, so a
//! write and its audit row commit together — the store never opens a transaction of its own.

use std::collections::HashMap;

use panel_core::db::Conn;
use panel_core::pytext;
use panel_core::rusqlite::functions::FunctionFlags;
use panel_core::rusqlite::types::{Value as Sql, ValueRef};
use panel_core::rusqlite::{self, params, params_from_iter, OptionalExtension as _, Row};
use panel_model::clients::{
    AccessGrant, Client, ClientState, GrantDesiredState, GrantObservedState, GrantOrigin, ProtocolOptions,
};
use panel_model::{Protocol, SecretRef};
use serde_json::{json, Map, Value};

use crate::cursor;
use crate::ClientsError;

/// The columns of `access_grants`, in table order.
const GRANT_COLUMNS: &str = "id,client_id,protocol,node_id,endpoint_id,runtime_username,secret_id,secret_version,\
desired_state,observed_state,valid_from,valid_until,protocol_options_json,origin,created_at,updated_at,routing_lane,label";
const CLIENT_COLUMNS: &str = "id,display_name,state,metadata_json,created_at,updated_at";

/// A `clients` row before it is checked.
struct ClientRow {
    id: String,
    display_name: String,
    state: String,
    metadata_json: String,
    created_at: i64,
    updated_at: i64,
}

fn read_client(row: &Row<'_>) -> rusqlite::Result<ClientRow> {
    Ok(ClientRow {
        id: row.get("id")?,
        display_name: row.get("display_name")?,
        state: row.get("state")?,
        metadata_json: row.get("metadata_json")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

fn corrupt(what: &str, detail: impl std::fmt::Display) -> ClientsError {
    ClientsError::Internal(format!("stored {what} is not readable: {detail}"))
}

impl ClientRow {
    fn into_client(self) -> Result<Client, ClientsError> {
        let metadata = match serde_json::from_str::<Value>(&self.metadata_json) {
            Ok(Value::Object(map)) => map,
            Ok(other) => return Err(corrupt("clients.metadata_json", other)),
            Err(error) => return Err(corrupt("clients.metadata_json", error)),
        };
        Ok(Client {
            state: ClientState::from_wire(&self.state).ok_or_else(|| corrupt("clients.state", &self.state))?,
            id: self.id,
            display_name: self.display_name,
            metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// An `access_grants` row before it is checked.
struct GrantRow {
    id: String,
    client_id: String,
    protocol: String,
    node_id: String,
    endpoint_id: String,
    runtime_username: String,
    secret_id: Option<String>,
    secret_version: Option<i64>,
    desired_state: String,
    observed_state: String,
    valid_from: Option<i64>,
    valid_until: Option<i64>,
    protocol_options_json: String,
    origin: String,
    created_at: i64,
    updated_at: i64,
    routing_lane: Option<String>,
    label: Option<String>,
}

fn read_grant(row: &Row<'_>) -> rusqlite::Result<GrantRow> {
    Ok(GrantRow {
        id: row.get("id")?,
        client_id: row.get("client_id")?,
        protocol: row.get("protocol")?,
        node_id: row.get("node_id")?,
        endpoint_id: row.get("endpoint_id")?,
        runtime_username: row.get("runtime_username")?,
        secret_id: row.get("secret_id")?,
        secret_version: row.get("secret_version")?,
        desired_state: row.get("desired_state")?,
        observed_state: row.get("observed_state")?,
        valid_from: row.get("valid_from")?,
        valid_until: row.get("valid_until")?,
        protocol_options_json: row.get("protocol_options_json")?,
        origin: row.get("origin")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        routing_lane: row.get("routing_lane")?,
        label: row.get("label")?,
    })
}

impl GrantRow {
    /// `_grant(row)`: the options through their protocol's model (`model_validate_json`).
    fn into_grant(self) -> Result<AccessGrant, ClientsError> {
        let protocol =
            Protocol::from_wire(&self.protocol).ok_or_else(|| corrupt("access_grants.protocol", &self.protocol))?;
        let raw: Value = serde_json::from_str(&self.protocol_options_json)
            .map_err(|error| corrupt("access_grants.protocol_options_json", error))?;
        let options = ProtocolOptions::validate(protocol, &raw)?;
        let secret_ref = match (self.secret_id, self.secret_version) {
            (Some(secret_id), Some(version)) => Some(SecretRef::new(secret_id, version)),
            _ => None,
        };
        let own_lane = match self.routing_lane.as_deref() {
            None => false,
            Some("own") => true,
            Some(other) => return Err(corrupt("access_grants.routing_lane", other)),
        };
        Ok(AccessGrant {
            protocol,
            options,
            id: self.id,
            client_id: self.client_id,
            node_id: self.node_id,
            endpoint_id: self.endpoint_id,
            runtime_username: self.runtime_username,
            secret_ref,
            desired_state: GrantDesiredState::from_wire(&self.desired_state)
                .ok_or_else(|| corrupt("access_grants.desired_state", &self.desired_state))?,
            observed_state: GrantObservedState::from_wire(&self.observed_state)
                .ok_or_else(|| corrupt("access_grants.observed_state", &self.observed_state))?,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            origin: GrantOrigin::from_wire(&self.origin)
                .ok_or_else(|| corrupt("access_grants.origin", &self.origin))?,
            own_lane,
            label: self.label,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

fn grants_of(db: &Conn, sql: &str, parameters: &[Sql]) -> Result<Vec<AccessGrant>, ClientsError> {
    let rows = {
        let mut statement = db.prepare(sql)?;
        let rows = statement.query_map(params_from_iter(parameters.iter()), read_grant)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    rows.into_iter().map(GrantRow::into_grant).collect()
}

fn clients_of(db: &Conn, sql: &str, parameters: &[Sql]) -> Result<Vec<Client>, ClientsError> {
    let rows = {
        let mut statement = db.prepare(sql)?;
        let rows = statement.query_map(params_from_iter(parameters.iter()), read_client)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    rows.into_iter().map(ClientRow::into_client).collect()
}

/// `json.dumps(metadata, sort_keys=True, separators=(",", ":"))`.
fn metadata_json(metadata: &Map<String, Value>) -> String {
    panel_core::pyjson::canonical(&Value::Object(metadata.clone()))
}

/// `insert_client(db, client)`.
pub fn insert_client(db: &Conn, client: &Client) -> Result<(), ClientsError> {
    db.execute(
        "INSERT INTO clients(id,display_name,state,metadata_json,created_at,updated_at)
               VALUES(?,?,?,?,?,?)",
        params![
            client.id,
            client.display_name,
            client.state.as_str(),
            metadata_json(&client.metadata),
            client.created_at,
            client.updated_at
        ],
    )?;
    Ok(())
}

/// `client(db, client_id)`: `NotFound` when there is none.
pub fn client(db: &Conn, client_id: &str) -> Result<Client, ClientsError> {
    let row = db
        .query_row(&format!("SELECT {CLIENT_COLUMNS} FROM clients WHERE id=?"), params![client_id], read_client)
        .optional()?;
    row.ok_or_else(|| ClientsError::NotFound(client_id.to_string()))?.into_client()
}

/// `clients(db, state=…)`, oldest first.
pub fn clients(db: &Conn, state: Option<&str>) -> Result<Vec<Client>, ClientsError> {
    match state {
        Some(state) => clients_of(
            db,
            &format!("SELECT {CLIENT_COLUMNS} FROM clients WHERE state=? ORDER BY created_at, id"),
            &[Sql::Text(state.to_string())],
        ),
        None => clients_of(db, &format!("SELECT {CLIENT_COLUMNS} FROM clients ORDER BY created_at, id"), &[]),
    }
}

/// `clients_with_grants(db)`: the legacy full listing, two queries whatever the number of clients.
pub fn clients_with_grants(db: &Conn) -> Result<Vec<(Client, Vec<AccessGrant>)>, ClientsError> {
    let all = clients(db, None)?;
    let mut grouped: HashMap<String, Vec<AccessGrant>> =
        all.iter().map(|client| (client.id.clone(), Vec::new())).collect();
    for grant in grants(db, &GrantFilter::default())? {
        // A concurrent import may create a client between the two reads.
        if let Some(list) = grouped.get_mut(&grant.client_id) {
            list.push(grant);
        }
    }
    Ok(all
        .into_iter()
        .map(|client| {
            let list = grouped.remove(&client.id).unwrap_or_default();
            (client, list)
        })
        .collect())
}

/// The filters of `client_page` (the query parameters of `GET /api/clients`).
#[derive(Debug, Clone)]
pub struct PageFilters {
    pub cursor: Option<String>,
    pub query: String,
    pub state: String,
    pub protocol: String,
    pub node: String,
    pub issue: String,
}

impl Default for PageFilters {
    fn default() -> Self {
        Self {
            cursor: None,
            query: String::new(),
            state: "all".into(),
            protocol: String::new(),
            node: String::new(),
            issue: String::new(),
        }
    }
}

/// One page of the listing.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientPage {
    pub items: Vec<(Client, Vec<AccessGrant>)>,
    pub next_cursor: Option<String>,
    pub matched: i64,
    pub total: i64,
    /// `{"active", "suspended", "archived"}` in that order (then any other state, as SQLite
    /// returns them).
    pub counts: Vec<(String, i64)>,
    pub node_ids: Vec<String>,
}

impl ClientPage {
    /// The page as the API answers it (`items` already rendered by `item`).
    pub fn to_json(&self) -> Value {
        let counts: Map<String, Value> =
            self.counts.iter().map(|(state, count)| (state.clone(), json!(count))).collect();
        json!({
            "items": self.items.iter().map(|(client, grants)| client_json(client, grants)).collect::<Vec<_>>(),
            "next_cursor": self.next_cursor,
            "matched": self.matched,
            "total": self.total,
            "counts": counts,
            "node_ids": self.node_ids,
        })
    }
}

/// `_client(client, grants)` of the routes: `{"client": …, "grants": […]}`.
pub fn client_json(client: &Client, grants: &[AccessGrant]) -> Value {
    use panel_model::Model as _;
    json!({"client": client.dump(), "grants": grants.iter().map(|grant| grant.dump()).collect::<Vec<_>>()})
}

/// Python's `str(value or "").lower()` as the SQL function `client_lower`.
fn register_client_lower(db: &Conn) -> Result<(), ClientsError> {
    db.create_scalar_function(
        "client_lower",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |context| {
            let text = match context.get_raw(0) {
                ValueRef::Null => String::new(),
                ValueRef::Integer(0) => String::new(),
                ValueRef::Integer(value) => value.to_string(),
                ValueRef::Real(value) => {
                    if value == 0.0 {
                        String::new()
                    } else {
                        panel_core::pyjson::float_repr(value)
                    }
                }
                ValueRef::Text(bytes) => pytext::lower(&String::from_utf8_lossy(bytes)),
                ValueRef::Blob(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            };
            Ok(text)
        },
    )?;
    Ok(())
}

const RANK: &str = "CASE c.state WHEN 'active' THEN 0 WHEN 'suspended' THEN 1 ELSE 2 END";

/// `client_page(db, limit=…, cursor=…, query=…, state=…, protocol=…, node=…, issue=…)`: filter
/// before paging, hydrate grants only for the returned clients. `Invalid` for a limit outside
/// 1..=200, an unknown issue filter or a bad cursor.
pub fn client_page(db: &Conn, limit: i64, filters: &PageFilters) -> Result<ClientPage, ClientsError> {
    if !(1..=200).contains(&limit) {
        return Err(ClientsError::Invalid("limit must be between 1 and 200".into()));
    }
    register_client_lower(db)?;
    let mut conditions: Vec<String> = Vec::new();
    let mut parameters: Vec<Sql> = Vec::new();
    if filters.state != "all" {
        conditions.push("c.state=?".into());
        parameters.push(Sql::Text(filters.state.clone()));
    }
    let live = "g.client_id=c.id AND g.desired_state<>'deleted'";
    let lowered = pytext::lower(&filters.query);
    for word in pytext::split(&lowered) {
        conditions.push(format!(
            "(instr(client_lower(c.display_name || char(10) || c.id), ?) > 0
                OR EXISTS (SELECT 1 FROM access_grants g LEFT JOIN fleet_nodes n ON n.node_id=g.node_id
                WHERE {live} AND instr(client_lower(g.runtime_username || char(10) ||
                    CASE g.protocol WHEN 'naive' THEN 'NaiveProxy' WHEN 'mtproxy' THEN 'MTProxy' WHEN 'amneziawg' THEN 'AmneziaWG' WHEN 'trusttunnel' THEN 'TrustTunnel' ELSE 'Mieru' END
                    || char(10) || CASE WHEN g.node_id='local' THEN 'Этот сервер'
                        ELSE COALESCE(NULLIF(n.display_name,''), g.node_id) END), ?) > 0))"
        ));
        parameters.push(Sql::Text(word.to_string()));
        parameters.push(Sql::Text(word.to_string()));
    }
    let mut placement: Vec<String> = vec![live.to_string()];
    for (column, value) in [("protocol", &filters.protocol), ("node_id", &filters.node)] {
        if !value.is_empty() {
            placement.push(format!("g.{column}=?"));
            parameters.push(Sql::Text(value.clone()));
        }
    }
    let orphan = "(g.secret_id IS NULL OR g.secret_version IS NULL)";
    let issue_condition = match filters.issue.as_str() {
        "problem" => Some(format!("(g.observed_state IN ('failed','pending','drifted','missing') OR {orphan})")),
        "pending" => Some("g.observed_state='pending'".to_string()),
        "failed" => Some("g.observed_state='failed'".to_string()),
        "orphan" => Some(orphan.to_string()),
        "disabled" => Some("g.desired_state='disabled'".to_string()),
        "lane" => Some("g.routing_lane='own'".to_string()),
        "" | "empty" => None,
        _ => return Err(ClientsError::Invalid("unknown issue filter".into())),
    };
    if let Some(condition) = issue_condition {
        placement.push(condition);
    }
    if !filters.protocol.is_empty() || !filters.node.is_empty() || !filters.issue.is_empty() {
        let exists = if filters.issue == "empty" { "NOT EXISTS" } else { "EXISTS" };
        conditions.push(format!("{exists} (SELECT 1 FROM access_grants g WHERE {})", placement.join(" AND ")));
    }
    let mut filter = if conditions.is_empty() { "1".to_string() } else { conditions.join(" AND ") };
    let matched: i64 = db.query_row(
        &format!("SELECT COUNT(*) FROM clients c WHERE {filter}"),
        params_from_iter(parameters.iter()),
        |row| row.get(0),
    )?;
    if let Some(text) = filters.cursor.as_deref().filter(|text| !text.is_empty()) {
        let (rank, created_at, id) =
            cursor::decode(text).ok_or_else(|| ClientsError::Invalid("invalid client cursor".into()))?;
        filter.push_str(&format!(" AND ({RANK},c.created_at,c.id) > (?,?,?)"));
        parameters.extend([Sql::Integer(rank), Sql::Integer(created_at), Sql::Text(id)]);
    }
    parameters.push(Sql::Integer(limit + 1));
    let selected = format!(
        "SELECT c.id AS id,c.display_name AS display_name,c.state AS state,c.metadata_json AS metadata_json,\
         c.created_at AS created_at,c.updated_at AS updated_at FROM clients c WHERE {filter} ORDER BY {RANK},c.created_at,c.id LIMIT ?"
    );
    let mut page = clients_of(db, &selected, &parameters)?;
    let more = page.len() as i64 > limit;
    page.truncate(limit as usize);
    let next_cursor = match (more, page.last()) {
        (true, Some(last)) => {
            let rank = match last.state {
                ClientState::Active => 0,
                ClientState::Suspended => 1,
                ClientState::Archived => 2,
            };
            Some(cursor::encode(rank, last.created_at, &last.id))
        }
        _ => None,
    };
    let mut grouped: HashMap<String, Vec<AccessGrant>> =
        page.iter().map(|client| (client.id.clone(), Vec::new())).collect();
    if !page.is_empty() {
        let placeholders = vec!["?"; page.len()].join(",");
        let ids: Vec<Sql> = page.iter().map(|client| Sql::Text(client.id.clone())).collect();
        let sql = format!(
            "SELECT {GRANT_COLUMNS} FROM access_grants WHERE desired_state<>'deleted' AND client_id IN ({placeholders}) ORDER BY created_at,id"
        );
        for grant in grants_of(db, &sql, &ids)? {
            if let Some(list) = grouped.get_mut(&grant.client_id) {
                list.push(grant);
            }
        }
    }
    let mut counts: Vec<(String, i64)> =
        ["active", "suspended", "archived"].iter().map(|state| (state.to_string(), 0)).collect();
    {
        let mut statement = db.prepare("SELECT state,COUNT(*) FROM clients GROUP BY state")?;
        let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (state, count) = row?;
            match counts.iter_mut().find(|(known, _)| *known == state) {
                Some(entry) => entry.1 = count,
                None => counts.push((state, count)),
            }
        }
    }
    let node_ids: Vec<String> = {
        let mut statement =
            db.prepare("SELECT DISTINCT node_id FROM access_grants WHERE desired_state<>'deleted' ORDER BY node_id")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let total = counts.iter().map(|(_, count)| count).sum();
    let items = page
        .into_iter()
        .map(|client| {
            let list = grouped.remove(&client.id).unwrap_or_default();
            (client, list)
        })
        .collect();
    Ok(ClientPage { items, next_cursor, matched, total, counts, node_ids })
}

fn changed_one(changed: usize, key: &str) -> Result<(), ClientsError> {
    if changed != 1 {
        return Err(ClientsError::NotFound(key.to_string()));
    }
    Ok(())
}

/// `set_client_state(db, client_id, state, updated_at=…)`.
pub fn set_client_state(db: &Conn, client_id: &str, state: ClientState, updated_at: i64) -> Result<(), ClientsError> {
    let changed = db.execute(
        "UPDATE clients SET state=?,updated_at=? WHERE id=?",
        params![state.as_str(), updated_at, client_id],
    )?;
    changed_one(changed, client_id)
}

/// `delete_client(db, client_id)`: the client's own rows, children first (the foreign keys
/// restrict); the caller has checked that no live grant is left.
pub fn delete_client(db: &Conn, client_id: &str) -> Result<(), ClientsError> {
    db.execute(
        "DELETE FROM secret_versions WHERE secret_id IN \
         (SELECT secret_id FROM client_subscriptions WHERE client_id=? AND secret_id IS NOT NULL) \
         OR grant_id IN (SELECT id FROM access_grants WHERE client_id=?)",
        params![client_id, client_id],
    )?;
    for table in ["access_grants", "provisioning_operations", "client_subscriptions"] {
        db.execute(&format!("DELETE FROM {table} WHERE client_id=?"), params![client_id])?;
    }
    let changed = db.execute("DELETE FROM clients WHERE id=?", params![client_id])?;
    changed_one(changed, client_id)
}

/// `rename_client(db, client_id, display_name, updated_at=…)`.
pub fn rename_client(db: &Conn, client_id: &str, display_name: &str, updated_at: i64) -> Result<(), ClientsError> {
    let changed = db.execute(
        "UPDATE clients SET display_name=?,updated_at=? WHERE id=?",
        params![display_name, updated_at, client_id],
    )?;
    changed_one(changed, client_id)
}

/// `set_grant_label(db, grant_id, label, updated_at=…)`.
pub fn set_grant_label(db: &Conn, grant_id: &str, label: Option<&str>, updated_at: i64) -> Result<(), ClientsError> {
    let changed =
        db.execute("UPDATE access_grants SET label=?,updated_at=? WHERE id=?", params![label, updated_at, grant_id])?;
    changed_one(changed, grant_id)
}

/// `insert_grant(db, grant)`: a taken `(protocol, node, endpoint, username)` is refused before any
/// SQL runs, so the caller's transaction stays usable.
pub fn insert_grant(db: &Conn, grant: &AccessGrant) -> Result<(), ClientsError> {
    if find_grant(db, grant.protocol.as_str(), &grant.node_id, &grant.endpoint_id, &grant.runtime_username)?.is_some() {
        return Err(ClientsError::Conflict("runtime_username is already granted on this endpoint".into()));
    }
    db.execute(
        "INSERT INTO access_grants(id,client_id,protocol,node_id,endpoint_id,runtime_username,
               secret_id,secret_version,desired_state,observed_state,valid_from,valid_until,
               protocol_options_json,origin,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            grant.id,
            grant.client_id,
            grant.protocol.as_str(),
            grant.node_id,
            grant.endpoint_id,
            grant.runtime_username,
            grant.secret_ref.as_ref().map(|reference| reference.secret_id.clone()),
            grant.secret_ref.as_ref().map(|reference| reference.version),
            grant.desired_state.as_str(),
            grant.observed_state.as_str(),
            grant.valid_from,
            grant.valid_until,
            grant.options.dump_json(),
            grant.origin.as_str(),
            grant.created_at,
            grant.updated_at
        ],
    )?;
    Ok(())
}

/// `grant(db, grant_id)`: `NotFound` when there is none.
pub fn grant(db: &Conn, grant_id: &str) -> Result<AccessGrant, ClientsError> {
    let row = db
        .query_row(&format!("SELECT {GRANT_COLUMNS} FROM access_grants WHERE id=?"), params![grant_id], read_grant)
        .optional()?;
    row.ok_or_else(|| ClientsError::NotFound(grant_id.to_string()))?.into_grant()
}

/// The filters of `grants(db, …)`.
#[derive(Debug, Clone, Default)]
pub struct GrantFilter<'a> {
    pub client_id: Option<&'a str>,
    pub protocol: Option<&'a str>,
    pub node_id: Option<&'a str>,
    pub include_deleted: bool,
}

/// `grants(db, client_id=…, protocol=…, node_id=…, include_deleted=…)`, oldest first.
pub fn grants(db: &Conn, filter: &GrantFilter<'_>) -> Result<Vec<AccessGrant>, ClientsError> {
    let mut conditions: Vec<String> = Vec::new();
    let mut parameters: Vec<Sql> = Vec::new();
    for (column, value) in [("client_id", filter.client_id), ("protocol", filter.protocol), ("node_id", filter.node_id)]
    {
        if let Some(value) = value {
            conditions.push(format!("{column}=?"));
            parameters.push(Sql::Text(value.to_string()));
        }
    }
    if !filter.include_deleted {
        conditions.push("desired_state<>'deleted'".into());
    }
    let filter = if conditions.is_empty() { String::new() } else { format!(" WHERE {}", conditions.join(" AND ")) };
    grants_of(db, &format!("SELECT {GRANT_COLUMNS} FROM access_grants{filter} ORDER BY created_at, id"), &parameters)
}

/// The live (not deleted) grants of one client.
pub fn client_grants(db: &Conn, client_id: &str) -> Result<Vec<AccessGrant>, ClientsError> {
    grants(db, &GrantFilter { client_id: Some(client_id), ..GrantFilter::default() })
}

/// `find_grant(db, protocol, node_id, endpoint_id, runtime_username)`.
pub fn find_grant(
    db: &Conn,
    protocol: &str,
    node_id: &str,
    endpoint_id: &str,
    runtime_username: &str,
) -> Result<Option<AccessGrant>, ClientsError> {
    let row = db
        .query_row(
            &format!(
                "SELECT {GRANT_COLUMNS} FROM access_grants
               WHERE protocol=? AND node_id=? AND endpoint_id=? AND runtime_username=?"
            ),
            params![protocol, node_id, endpoint_id, runtime_username],
            read_grant,
        )
        .optional()?;
    row.map(GrantRow::into_grant).transpose()
}

/// The columns `update_grant` may write (`UPDATABLE`); `None` leaves a column alone.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GrantUpdate {
    pub client_id: Option<String>,
    /// `secret_id` and `secret_version` together.
    pub secret: Option<Option<SecretRef>>,
    pub desired_state: Option<GrantDesiredState>,
    pub observed_state: Option<GrantObservedState>,
    pub valid_from: Option<Option<i64>>,
    pub valid_until: Option<Option<i64>>,
    pub protocol_options_json: Option<String>,
    pub updated_at: Option<i64>,
}

impl GrantUpdate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn secret(mut self, reference: SecretRef) -> Self {
        self.secret = Some(Some(reference));
        self
    }

    pub fn desired(mut self, state: GrantDesiredState) -> Self {
        self.desired_state = Some(state);
        self
    }

    pub fn observed(mut self, state: GrantObservedState) -> Self {
        self.observed_state = Some(state);
        self
    }

    pub fn window(mut self, valid_from: Option<i64>, valid_until: Option<i64>) -> Self {
        self.valid_from = Some(valid_from);
        self.valid_until = Some(valid_until);
        self
    }

    pub fn options_json(mut self, json: String) -> Self {
        self.protocol_options_json = Some(json);
        self
    }

    pub fn at(mut self, updated_at: i64) -> Self {
        self.updated_at = Some(updated_at);
        self
    }
}

/// `update_grant(db, grant_id, **fields)`: nothing to write is a no-op (no existence check, as in
/// Python); otherwise exactly one row must change.
pub fn update_grant(db: &Conn, grant_id: &str, update: &GrantUpdate) -> Result<(), ClientsError> {
    let mut assignments: Vec<&str> = Vec::new();
    let mut values: Vec<Sql> = Vec::new();
    let text = |value: &Option<String>| value.clone().map_or(Sql::Null, Sql::Text);
    let int = |value: Option<i64>| value.map_or(Sql::Null, Sql::Integer);
    if let Some(client_id) = &update.client_id {
        assignments.push("client_id=?");
        values.push(Sql::Text(client_id.clone()));
    }
    if let Some(secret) = &update.secret {
        assignments.push("secret_id=?");
        values.push(text(&secret.as_ref().map(|reference| reference.secret_id.clone())));
        assignments.push("secret_version=?");
        values.push(int(secret.as_ref().map(|reference| reference.version)));
    }
    if let Some(state) = update.desired_state {
        assignments.push("desired_state=?");
        values.push(Sql::Text(state.as_str().into()));
    }
    if let Some(state) = update.observed_state {
        assignments.push("observed_state=?");
        values.push(Sql::Text(state.as_str().into()));
    }
    if let Some(valid_from) = update.valid_from {
        assignments.push("valid_from=?");
        values.push(int(valid_from));
    }
    if let Some(valid_until) = update.valid_until {
        assignments.push("valid_until=?");
        values.push(int(valid_until));
    }
    if let Some(json) = &update.protocol_options_json {
        assignments.push("protocol_options_json=?");
        values.push(Sql::Text(json.clone()));
    }
    if let Some(updated_at) = update.updated_at {
        assignments.push("updated_at=?");
        values.push(Sql::Integer(updated_at));
    }
    if assignments.is_empty() {
        return Ok(());
    }
    values.push(Sql::Text(grant_id.to_string()));
    let changed = db.execute(
        &format!("UPDATE access_grants SET {} WHERE id=?", assignments.join(",")),
        params_from_iter(values.iter()),
    )?;
    changed_one(changed, grant_id)
}

/// `delete_grant(db, grant_id)`: only once the runtime account is confirmed gone; the UNIQUE
/// index frees the name.
pub fn delete_grant(db: &Conn, grant_id: &str) -> Result<(), ClientsError> {
    let changed = db.execute("DELETE FROM access_grants WHERE id=?", params![grant_id])?;
    changed_one(changed, grant_id)
}
