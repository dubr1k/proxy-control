//! Adopt what the managers already run, without touching them (`clients/importer.py`).
//!
//! Every call here is a read of the runtime; import writes only the panel's own rows. A shared
//! username is offered as a hint and nothing more: three managers each having an "alice" is not
//! evidence that they are the same person.

use std::collections::{HashMap, HashSet};

use panel_core::db::Database;
use panel_model::clients::{
    AccessGrant, GrantDesiredState, GrantObservedState, GrantOrigin, MieruOptions, MtproxyOptions, NaiveOptions,
    ProtocolOptions,
};
use panel_model::{Model as _, Protocol};
use serde_json::{json, Map, Value};

use crate::context::{Audit, AuditContext};
use crate::service::ClientService;
use crate::{managed, store, ClientsError, DEFAULT_ENDPOINT, LOCAL_NODE_ID};

/// One runtime account the panel may adopt.
#[derive(Debug, Clone, PartialEq)]
pub struct InventoryItem {
    pub protocol: Protocol,
    pub runtime_username: String,
    pub enabled: bool,
    pub options: Value,
    pub imported_grant_id: Option<String>,
}

impl InventoryItem {
    /// `asdict(item)`.
    pub fn to_json(&self) -> Value {
        json!({
            "protocol": self.protocol.as_str(),
            "runtime_username": self.runtime_username,
            "enabled": self.enabled,
            "options": self.options,
            "imported_grant_id": self.imported_grant_id,
        })
    }
}

/// One proposed client.
#[derive(Debug, Clone, PartialEq)]
pub struct ProposedClient {
    pub display_name: String,
    pub items: Vec<InventoryItem>,
    pub same_username_hint: bool,
}

/// What the operator decided for one client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDecision {
    pub display_name: String,
    pub client_id: Option<String>,
    pub items: Vec<(Protocol, String)>,
}

/// What `confirm` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportResult {
    pub created_clients: i64,
    pub created_grants: i64,
    pub skipped: Vec<String>,
}

impl ImportResult {
    /// `asdict(result)`.
    pub fn to_json(&self) -> Value {
        json!({"created_clients": self.created_clients, "created_grants": self.created_grants, "skipped": self.skipped})
    }
}

/// `_integer(value)`: a positive int (not a bool), else `None`.
fn integer(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Number(number)) if !number.is_f64() && number.as_f64().is_some_and(|value| value > 0.0) => {
            Value::Number(number.clone())
        }
        _ => Value::Null,
    }
}

/// `_mtproxy_options(row)`: limits, and the endpoint from the row or from the link Telemt
/// serves (the panel has no configured value for it).
pub fn mtproxy_options(row: &Map<String, Value>) -> Result<Value, ClientsError> {
    let access = panel_managers_access(&Value::Object(row.clone()));
    let host = match row.get("host").filter(|value| crate::truthy(value)) {
        Some(host) => Some(host.clone()),
        None => access.as_ref().and_then(|(server, _)| server.clone().map(Value::String)),
    };
    let port = match integer(row.get("port")) {
        Value::Null => access.as_ref().and_then(|(_, port)| port.map(|port| json!(port))),
        port => Some(port),
    };
    let host = host
        .and_then(|host| host.as_str().map(str::to_string))
        .filter(|host| (1..=253).contains(&panel_core::pytext::len(host)));
    let port = port.and_then(|port| port.as_i64()).filter(|port| (1..=65535).contains(port));
    let input = json!({
        "data_quota_bytes": integer(row.get("data_quota_bytes")),
        "rate_limit_up_bps": integer(row.get("rate_limit_up_bps")),
        "rate_limit_down_bps": integer(row.get("rate_limit_down_bps")),
        "max_tcp_conns": integer(row.get("max_tcp_conns")),
        "max_unique_ips": integer(row.get("max_unique_ips")),
        "host": host,
        "port": port,
    });
    Ok(MtproxyOptions::validate(&input)?.dump())
}

/// `access_from_user(row)` → `(server, port)` (`panel/telemt.py`, ported in panel-managers).
fn panel_managers_access(row: &Value) -> Option<(Option<String>, Option<u16>)> {
    panel_managers::access_from_user(row).map(|access| (access.server, access.port))
}

/// `_naive_options(row)`.
pub fn naive_options(row: &Map<String, Value>) -> Result<Value, ClientsError> {
    Ok(NaiveOptions::validate(&json!({"quota_bytes": integer(row.get("quota_bytes"))}))?.dump())
}

/// `_mieru_options(row)`.
pub fn mieru_options(row: &Map<String, Value>) -> Result<Value, ClientsError> {
    let quotas = match row.get("quotas") {
        Some(Value::Array(items)) => Value::Array(items.clone()),
        _ => json!([]),
    };
    Ok(MieruOptions::validate(&json!({"quotas": quotas}))?.dump())
}

/// `OPTIONS_FROM_RUNTIME[protocol](row)`: what a runtime reports about a user, reduced to the
/// options the panel may own (`None` for a protocol import does not cover).
pub fn options_from_runtime(protocol: Protocol, row: &Map<String, Value>) -> Option<Result<Value, ClientsError>> {
    match protocol {
        Protocol::Mtproxy => Some(mtproxy_options(row)),
        Protocol::Naive => Some(naive_options(row)),
        Protocol::Mieru => Some(mieru_options(row)),
        Protocol::Amneziawg | Protocol::Trusttunnel => None,
    }
}

/// `inventory(...)`: what the managers run (`rows`: each protocol's `list_users()`, empty when
/// the manager could not be read or is switched off) and this panel may adopt. Accounts the
/// central owns never appear.
pub fn inventory(database: &Database, rows: &[(Protocol, Vec<Value>)]) -> Result<Vec<InventoryItem>, ClientsError> {
    let mut collected: Vec<(Protocol, String, bool, Value)> = Vec::new();
    for (protocol, list) in rows {
        for row in list {
            let Some(map) = row.as_object() else {
                continue;
            };
            let Some(username) = map.get("username").and_then(Value::as_str) else {
                continue;
            };
            let Some(options) = options_from_runtime(*protocol, map) else {
                continue;
            };
            let enabled = map.get("enabled") != Some(&Value::Bool(false));
            collected.push((*protocol, username.to_string(), enabled, options?));
        }
    }
    database.with_connection(|db| {
        let central: HashSet<(String, String)> = managed::owned(db)?;
        let mut items = Vec::new();
        for (protocol, username, enabled, options) in collected {
            if central.contains(&(protocol.as_str().to_string(), username.clone())) {
                continue;
            }
            let imported = store::find_grant(db, protocol.as_str(), LOCAL_NODE_ID, DEFAULT_ENDPOINT, &username)?;
            items.push(InventoryItem {
                protocol,
                runtime_username: username,
                enabled,
                options,
                imported_grant_id: imported.map(|grant| grant.id),
            });
        }
        Ok(items)
    })
}

/// `propose(items)`: one proposal per runtime account; a shared username only raises a flag.
pub fn propose(items: &[InventoryItem]) -> Vec<ProposedClient> {
    let mut protocols: HashMap<&str, HashSet<Protocol>> = HashMap::new();
    for item in items {
        protocols.entry(item.runtime_username.as_str()).or_default().insert(item.protocol);
    }
    items
        .iter()
        .map(|item| ProposedClient {
            display_name: item.runtime_username.clone(),
            items: vec![item.clone()],
            same_username_hint: protocols.get(item.runtime_username.as_str()).is_some_and(|set| set.len() > 1),
        })
        .collect()
}

/// `confirm(service, decisions, known, …)`: every decision commits together — a rejected item
/// leaves no half-imported client.
pub fn confirm(
    service: &ClientService,
    decisions: &[ImportDecision],
    known: &[InventoryItem],
    context: &AuditContext,
) -> Result<ImportResult, ClientsError> {
    let index: HashMap<(Protocol, &str), &InventoryItem> =
        known.iter().map(|item| ((item.protocol, item.runtime_username.as_str()), item)).collect();
    let now = service.now();
    service.database().transaction(|db| {
        let mut result = ImportResult::default();
        for decision in decisions {
            let mut client_id = decision.client_id.clone();
            if let Some(id) = &client_id {
                store::client(db, id)?;
            }
            let mut pending = Vec::new();
            for (protocol, username) in &decision.items {
                let Some(item) = index.get(&(*protocol, username.as_str())) else {
                    return Err(ClientsError::Invalid(format!("unknown runtime account: {protocol}/{username}")));
                };
                if item.imported_grant_id.is_some() {
                    result.skipped.push(format!("{protocol}:{username}"));
                    continue;
                }
                pending.push(*item);
            }
            if pending.is_empty() {
                continue;
            }
            let client_id = match client_id.take() {
                Some(id) => id,
                None => {
                    result.created_clients += 1;
                    service.new_client(db, &decision.display_name, now)?.id
                }
            };
            for item in pending {
                let (desired, observed) = if item.enabled {
                    (GrantDesiredState::Enabled, GrantObservedState::Enabled)
                } else {
                    (GrantDesiredState::Disabled, GrantObservedState::Disabled)
                };
                store::insert_grant(
                    db,
                    &AccessGrant {
                        protocol: item.protocol,
                        options: ProtocolOptions::validate(item.protocol, &item.options)?,
                        id: panel_core::ids::uuid4(),
                        client_id: client_id.clone(),
                        node_id: LOCAL_NODE_ID.into(),
                        endpoint_id: DEFAULT_ENDPOINT.into(),
                        runtime_username: item.runtime_username.clone(),
                        secret_ref: None,
                        desired_state: desired,
                        observed_state: observed,
                        valid_from: None,
                        valid_until: None,
                        origin: GrantOrigin::Imported,
                        own_lane: false,
                        label: None,
                        created_at: now,
                        updated_at: now,
                    },
                )?;
                result.created_grants += 1;
            }
            service.notify(db, &client_id)?;
        }
        let accounts: Vec<String> = decisions
            .iter()
            .flat_map(|decision| decision.items.iter().map(|(protocol, username)| format!("{protocol}:{username}")))
            .collect();
        Audit::new(context, "client.import", "import")
            .detail(json!({
                "created_clients": result.created_clients,
                "created_grants": result.created_grants,
                "skipped": result.skipped,
                // Runtime usernames are already visible in the panel; nothing else is recorded.
                "accounts": accounts,
            }))
            .write(db)?;
        Ok(result)
    })
}
