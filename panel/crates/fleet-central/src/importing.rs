//! Adopt accounts a linked panel already runs (`fleet_v2/importing.py`).
//!
//! Inventory and credential capture happen before any write. Clients, imported grants, captured
//! credentials, the audit row and the next desired generation then commit in one transaction.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use panel_clients::importer::options_from_runtime;
use panel_clients::store;
use panel_clients::{AuditContext, ClientService};
use panel_core::clock::SharedClock;
use panel_core::db::{Conn, Database};
use panel_model::clients::{AccessGrant, GrantDesiredState, GrantObservedState, GrantOrigin, ProtocolOptions};
use panel_model::seams::{CaptureItem, CapturePurpose};
use panel_model::{Protocol, SecretRef};
use panel_secrets::audit;
use panel_secrets::secrets_store::{Identity, SecretStore};
use serde_json::{json, Map, Value};

use crate::links::NodeLinkService;
use crate::{CentralError, CentralResult};

pub const NEW_CLIENT: &str = "new";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportItem {
    pub protocol: Protocol,
    pub runtime_username: String,
    /// [`NEW_CLIENT`], or an existing client id.
    pub client: String,
}

impl ImportItem {
    pub fn label(&self) -> String {
        label(self.protocol, &self.runtime_username)
    }
}

pub fn label(protocol: Protocol, username: &str) -> String {
    format!("{}:{username}", protocol.as_str())
}

type PendingImports = (Vec<(ImportItem, Map<String, Value>)>, Vec<String>);

#[derive(Clone)]
pub struct FleetImporter {
    database: Database,
    secrets: SecretStore,
    clients: ClientService,
    links: Arc<NodeLinkService>,
    clock: SharedClock,
}

impl FleetImporter {
    pub fn new(
        database: Database,
        secrets: SecretStore,
        clients: ClientService,
        links: Arc<NodeLinkService>,
        clock: SharedClock,
    ) -> Self {
        Self { database, secrets, clients, links, clock }
    }

    fn inventory_protocols(body: Map<String, Value>) -> Map<String, Value> {
        body.get("protocols").and_then(Value::as_object).cloned().unwrap_or_default()
    }

    fn known(inventory: &Map<String, Value>) -> HashMap<(String, String), Map<String, Value>> {
        let mut known = HashMap::new();
        for (protocol, rows) in inventory {
            for row in rows.as_array().into_iter().flatten() {
                if let (Some(username), Some(row)) =
                    (row.get("runtime_username").and_then(Value::as_str), row.as_object())
                {
                    known.insert((protocol.clone(), username.to_string()), row.clone());
                }
            }
        }
        known
    }

    fn pending(
        &self,
        db: &Conn,
        node_id: &str,
        decisions: &[ImportItem],
        inventory: &Map<String, Value>,
    ) -> CentralResult<PendingImports> {
        let known = Self::known(inventory);
        let mut pending = Vec::new();
        let mut already_linked = Vec::new();
        for item in decisions {
            let protocol = item.protocol.as_str();
            let Some(row) = known.get(&(protocol.to_string(), item.runtime_username.clone())) else {
                return Err(CentralError::Invalid(format!("the node does not run {}", item.label())));
            };
            if store::find_grant(db, protocol, node_id, panel_clients::DEFAULT_ENDPOINT, &item.runtime_username)?
                .is_some()
            {
                already_linked.push(item.label());
                continue;
            }
            if row.get("ownership").and_then(Value::as_str) == Some("central") {
                return Err(CentralError::Invalid(format!("{} is already managed by a central panel", item.label())));
            }
            if item.client != NEW_CLIENT {
                if let Err(error) = store::client(db, &item.client) {
                    return match error {
                        panel_clients::ClientsError::NotFound(_) => {
                            Err(CentralError::UnknownClient(item.client.clone()))
                        }
                        other => Err(other.into()),
                    };
                }
            }
            pending.push((item.clone(), row.clone()));
        }
        Ok((pending, already_linked))
    }

    pub async fn import_resources(
        &self,
        node_id: &str,
        decisions: &[ImportItem],
        context: &AuditContext,
        inventory: Option<Map<String, Value>>,
        auto: bool,
    ) -> CentralResult<Value> {
        let links = self.links.clone();
        let id = node_id.to_owned();
        let client = crate::blocking(move || links.client_for(&id)).await?;
        let inventory = match inventory {
            Some(inventory) => inventory,
            None => Self::inventory_protocols(client.inventory().await?),
        };
        let this = self.clone();
        let id = node_id.to_owned();
        let choices = decisions.to_vec();
        let table = inventory.clone();
        let (pending, already_linked) =
            crate::blocking(move || this.database.with_connection(|db| this.pending(db, &id, &choices, &table)))
                .await?;
        if pending.is_empty() {
            return Ok(json!({"imported": [], "without_credential": [], "already_linked": already_linked}));
        }
        let resources = pending
            .iter()
            .map(|(item, _)| CaptureItem {
                protocol: item.protocol.as_str().to_string(),
                runtime_username: item.runtime_username.clone(),
            })
            .collect::<Vec<_>>();
        let captured = client.capture(&resources, CapturePurpose::Import).await?;
        let credentials = captured.get("credentials").and_then(Value::as_object).cloned().unwrap_or_default();
        let now = self.clock.now();
        let secrets = self.secrets.clone();
        let clients = self.clients.clone();
        let context = context.clone();
        let database = self.database.clone();
        let node_id = node_id.to_owned();
        crate::blocking(move || {
            database.transaction(move |db| {
                let node_id = node_id.as_str();
                let mut imported = Vec::new();
                let mut without_credential = Vec::new();
                let mut touched = HashSet::new();
                let mut created = 0;
                for (item, row) in &pending {
                    let client_id = if item.client == NEW_CLIENT {
                        created += 1;
                        clients.new_client(db, &item.runtime_username, now)?.id
                    } else {
                        item.client.clone()
                    };
                    let grant_id = panel_core::ids::uuid4();
                    let label = item.label();
                    let plaintext = credentials.get(&label).and_then(Value::as_str).filter(|value| !value.is_empty());
                    let secret_id = format!("grant:{grant_id}");
                    let reference = match plaintext {
                        Some(plaintext) => {
                            let identity = Identity {
                                secret_id: &secret_id,
                                version: 1,
                                purpose: panel_clients::CREDENTIAL_PURPOSE,
                                grant_id: Some(&grant_id),
                                permitted_node_id: Some(node_id),
                            };
                            let stored = secrets.store(db, &identity, plaintext.as_bytes(), "active")?;
                            Some(SecretRef::new(stored.secret_id, stored.version))
                        }
                        None => {
                            without_credential.push(label.clone());
                            None
                        }
                    };
                    let state = if row.get("enabled") == Some(&Value::Bool(false)) {
                        GrantDesiredState::Disabled
                    } else {
                        GrantDesiredState::Enabled
                    };
                    let observed = if state == GrantDesiredState::Disabled {
                        GrantObservedState::Disabled
                    } else {
                        GrantObservedState::Enabled
                    };
                    let raw_options = row.get("options").and_then(Value::as_object).cloned().unwrap_or_default();
                    let converted = options_from_runtime(item.protocol, &raw_options).ok_or_else(|| {
                        CentralError::Internal(format!("no runtime option importer for {}", item.protocol))
                    })??;
                    let options = ProtocolOptions::validate(item.protocol, &converted)
                        .map_err(panel_clients::ClientsError::from)?;
                    store::insert_grant(
                        db,
                        &AccessGrant {
                            protocol: item.protocol,
                            options,
                            id: grant_id.clone(),
                            client_id: client_id.clone(),
                            node_id: node_id.to_string(),
                            endpoint_id: panel_clients::DEFAULT_ENDPOINT.to_string(),
                            runtime_username: item.runtime_username.clone(),
                            secret_ref: reference.clone(),
                            desired_state: state,
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
                    imported.push(json!({"grant_id": grant_id, "client_id": client_id,
                    "protocol": item.protocol.as_str(), "runtime_username": item.runtime_username,
                    "has_credential": reference.is_some()}));
                    touched.insert(client_id);
                }
                let detail = json!({"auto": auto, "created_clients": created,
                "imported": imported.iter().map(|entry| entry["grant_id"].clone()).collect::<Vec<_>>(),
                "accounts": pending.iter().map(|(item, _)| item.label()).collect::<Vec<_>>(),
                "without_credential": without_credential, "already_linked": already_linked});
                let detail = detail.as_object().cloned().unwrap_or_default();
                audit::record(db, &context.row("node.import", node_id).detail(detail))?;
                for client_id in touched {
                    clients.notify(db, &client_id)?;
                }
                Ok(json!({"imported": imported, "without_credential": without_credential,
                      "already_linked": already_linked}))
            })
        })
        .await
    }

    fn client_named(&self, db: &Conn, name: &str) -> CentralResult<Option<String>> {
        for existing in store::clients(db, None)? {
            if existing.display_name == name && existing.state.as_str() != "archived" {
                return Ok(Some(existing.id));
            }
        }
        Ok(None)
    }

    pub fn plan_auto_import(
        &self,
        db: &Conn,
        node_id: &str,
        inventory: &Map<String, Value>,
    ) -> CentralResult<Vec<ImportItem>> {
        let mut decisions = Vec::new();
        let mut assigned = HashMap::<String, String>::new();
        let sorted = inventory.iter().collect::<BTreeMap<_, _>>();
        for (protocol, rows) in sorted {
            let Some(protocol_enum) = Protocol::from_wire(protocol) else {
                continue;
            };
            for row in rows.as_array().into_iter().flatten() {
                let Some(username) =
                    row.get("runtime_username").and_then(Value::as_str).filter(|name| !name.is_empty())
                else {
                    continue;
                };
                if row.get("ownership").and_then(Value::as_str) == Some("central") {
                    continue;
                }
                if store::find_grant(db, protocol, node_id, panel_clients::DEFAULT_ENDPOINT, username)?.is_some() {
                    continue;
                }
                let target = match assigned.get(username) {
                    Some(target) => target.clone(),
                    None => self.client_named(db, username)?.unwrap_or_else(|| NEW_CLIENT.to_string()),
                };
                decisions.push(ImportItem {
                    protocol: protocol_enum,
                    runtime_username: username.to_string(),
                    client: target.clone(),
                });
                if target != NEW_CLIENT {
                    assigned.insert(username.to_string(), target);
                }
            }
        }
        Ok(decisions)
    }

    pub async fn auto_import(
        &self,
        node_id: &str,
        inventory: Option<Map<String, Value>>,
    ) -> CentralResult<Option<Value>> {
        let links = self.links.clone();
        let id = node_id.to_owned();
        let client = crate::blocking(move || links.client_for(&id)).await?;
        let inventory = match inventory {
            Some(inventory) => inventory,
            None => Self::inventory_protocols(client.inventory().await?),
        };
        let this = self.clone();
        let id = node_id.to_owned();
        let table = inventory.clone();
        let decisions =
            crate::blocking(move || this.database.with_connection(|db| this.plan_auto_import(db, &id, &table))).await?;
        if decisions.is_empty() {
            return Ok(None);
        }
        let mut first = HashSet::new();
        let batch = decisions
            .iter()
            .filter(|item| item.client != NEW_CLIENT || first.insert(item.runtime_username.clone()))
            .cloned()
            .collect::<Vec<_>>();
        let context = AuditContext::system();
        let mut result = self.import_resources(node_id, &batch, &context, Some(inventory.clone()), true).await?;
        if batch.len() < decisions.len() {
            let this = self.clone();
            let id = node_id.to_owned();
            let table = inventory.clone();
            let rest =
                crate::blocking(move || this.database.with_connection(|db| this.plan_auto_import(db, &id, &table)))
                    .await?;
            if !rest.is_empty() {
                let more = self.import_resources(node_id, &rest, &context, Some(inventory), true).await?;
                for key in ["imported", "without_credential", "already_linked"] {
                    let mut values = result.get(key).and_then(Value::as_array).cloned().unwrap_or_default();
                    values.extend(more.get(key).and_then(Value::as_array).cloned().unwrap_or_default());
                    result[key] = Value::Array(values);
                }
            }
        }
        Ok(Some(result))
    }

    /// Mark an inventory row with the central's existing grant, for the operator import view.
    pub fn annotate_inventory(&self, node_id: &str, table: &mut Map<String, Value>) -> CentralResult<()> {
        self.database.with_connection(|db| {
            for (protocol, rows) in table.iter_mut() {
                for row in rows.as_array_mut().into_iter().flatten() {
                    let Some(username) = row.get("runtime_username").and_then(Value::as_str).map(str::to_string) else {
                        continue;
                    };
                    let found = store::find_grant(db, protocol, node_id, panel_clients::DEFAULT_ENDPOINT, &username)?;
                    row["linked_grant_id"] = found.map_or(Value::Null, |grant| json!(grant.id));
                }
            }
            Ok(())
        })
    }
}
