//! Desired generations and publication.
//!
//! A generation is compiled from the current grants inside the caller's transaction. Credentials
//! are named by reference only. The stored digest includes numbering and timestamps; the content
//! digest does not, so a change that only renumbers a generation publishes nothing.

use std::collections::HashMap;
use std::sync::Arc;

use indexmap::IndexMap;
use panel_clients::store::{self, GrantFilter};
use panel_core::clock::SharedClock;
use panel_core::db::{Conn, Database};
use panel_core::pyjson;
use panel_core::rusqlite::{self, params, OptionalExtension as _};
use panel_model::clients::{ClientState, GrantDesiredState, GrantObservedState, GrantOrigin};
use panel_model::common::Backend;
use panel_model::fleet::{
    CredentialOrigin, DesiredState, EgressDocument, GenerationDocument, ObservedGeneration, ReconcileState,
    RelayAccount, RelaySection, Resource, ResourceOrigin, SCHEMA_VERSION,
};
use panel_model::seams::SeamError;
use panel_model::validate::Model;
use panel_model::Protocol;
use serde_json::{Map, Value};

use crate::error::{CentralError, CentralResult};

/// The latest row of `desired_generations`, with its checked document.
#[derive(Debug, Clone, PartialEq)]
pub struct DesiredGeneration {
    pub generation: i64,
    pub digest: String,
    pub content_digest: String,
    pub document: GenerationDocument,
    pub pushed_at: Option<i64>,
    pub acknowledged_at: Option<i64>,
}

/// The routing dependency of generation compilation. WP10 implements this with its routing
/// service; this crate deliberately does not depend on that not-yet-merged package.
pub trait DesiredRouting: Send + Sync {
    /// `RoutingService.desired_for_node`: typed egress documents by protocol.
    fn desired_for_node(&self, db: &Conn, node_id: &str) -> CentralResult<IndexMap<Protocol, EgressDocument>>;
}

impl<F> DesiredRouting for F
where
    F: Fn(&Conn, &str) -> CentralResult<IndexMap<Protocol, EgressDocument>> + Send + Sync,
{
    fn desired_for_node(&self, db: &Conn, node_id: &str) -> CentralResult<IndexMap<Protocol, EgressDocument>> {
        self(db, node_id)
    }
}

fn invalid_stored(what: &str, error: impl std::fmt::Display) -> CentralError {
    CentralError::Internal(format!("stored {what} is not readable: {error}"))
}

fn generation_from_json(text: &str) -> CentralResult<GenerationDocument> {
    let value: Value = serde_json::from_str(text).map_err(|error| invalid_stored("desired document", error))?;
    GenerationDocument::validate(&value).map_err(|error| invalid_stored("desired document", error))
}

/// Durable desired and observed generation rows. Cheap to clone.
#[derive(Debug, Clone)]
pub struct DesiredStore {
    database: Database,
}

impl DesiredStore {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    pub fn latest(db: &Conn, node_id: &str) -> CentralResult<Option<DesiredGeneration>> {
        let row = db
            .query_row(
                "SELECT generation,digest,content_digest,document_json,pushed_at,acknowledged_at
                 FROM desired_generations WHERE node_id=? ORDER BY generation DESC LIMIT 1",
                [node_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(generation, digest, content_digest, document, pushed_at, acknowledged_at)| {
            Ok(DesiredGeneration {
                generation,
                digest,
                content_digest,
                document: generation_from_json(&document)?,
                pushed_at,
                acknowledged_at,
            })
        })
        .transpose()
    }

    /// Insert and mark the link dirty in the same caller-owned transaction.
    pub fn insert(
        db: &Conn,
        node_id: &str,
        document: &GenerationDocument,
        digest: &str,
        content_digest: &str,
        now: i64,
    ) -> CentralResult<()> {
        db.execute(
            "INSERT INTO desired_generations(node_id,generation,digest,content_digest,document_json,
                    previous_generation,created_at,created_by) VALUES(?,?,?,?,?,?,?,?)",
            params![
                node_id,
                document.generation,
                digest,
                content_digest,
                document.dump_json(),
                document.previous_generation,
                document.created_at,
                document.created_by
            ],
        )?;
        db.execute(
            "UPDATE node_links SET config_dirty=1,desired_generation=?,updated_at=? WHERE node_id=?",
            params![document.generation, now, node_id],
        )?;
        Ok(())
    }

    pub fn mark_pushed(db: &Conn, node_id: &str, generation: i64, now: i64) -> CentralResult<()> {
        db.execute(
            "UPDATE desired_generations SET pushed_at=? WHERE node_id=? AND generation=?",
            params![now, node_id, generation],
        )?;
        Ok(())
    }

    /// Store the node's report verbatim. A converged report acknowledges its generation unless
    /// the pusher withholds acknowledgement while a credential still needs capturing.
    pub fn record_observed(
        db: &Conn,
        node_id: &str,
        observed: &ObservedGeneration,
        acknowledge: bool,
        now: i64,
    ) -> CentralResult<()> {
        let resources = Value::Array(observed.resources.iter().map(Model::dump).collect());
        db.execute(
            "INSERT INTO observed_generations(node_id,applied_generation,digest,reconcile_state,resources_json,reported_at)
             VALUES(?,?,?,?,?,?)
             ON CONFLICT(node_id) DO UPDATE SET applied_generation=excluded.applied_generation,
             digest=excluded.digest,reconcile_state=excluded.reconcile_state,
             resources_json=excluded.resources_json,reported_at=excluded.reported_at",
            params![
                node_id,
                observed.applied_generation,
                observed.digest,
                observed.reconcile_state.as_str(),
                pyjson::dumps_default(&resources),
                observed.reported_at
            ],
        )?;
        if observed.reconcile_state == ReconcileState::Converged && acknowledge {
            db.execute(
                "UPDATE desired_generations SET acknowledged_at=?
                 WHERE node_id=? AND generation=? AND acknowledged_at IS NULL",
                params![now, node_id, observed.applied_generation],
            )?;
            // A late acknowledgement of an older generation must not clear a newer dirty flag.
            db.execute(
                "UPDATE node_links SET acknowledged_generation=?,
                 config_dirty=CASE WHEN desired_generation=? THEN 0 ELSE config_dirty END WHERE node_id=?",
                params![observed.applied_generation, observed.applied_generation, node_id],
            )?;
        }
        Ok(())
    }

    pub fn record_relay(db: &Conn, node_id: &str, relay: Option<&Map<String, Value>>) -> CentralResult<()> {
        let json = relay.map(|relay| pyjson::sorted(&Value::Object(relay.clone())));
        db.execute("UPDATE observed_generations SET relay_json=? WHERE node_id=?", params![json, node_id])?;
        Ok(())
    }

    pub fn observed_relay(db: &Conn, node_id: &str) -> CentralResult<Option<Map<String, Value>>> {
        let text = db
            .query_row("SELECT relay_json FROM observed_generations WHERE node_id=?", [node_id], |row| {
                row.get::<_, Option<String>>(0)
            })
            .optional()?
            .flatten();
        text.map(|text| {
            let value: Value = serde_json::from_str(&text).map_err(|error| invalid_stored("observed relay", error))?;
            value
                .as_object()
                .cloned()
                .ok_or_else(|| CentralError::Internal("stored observed relay is not an object".into()))
        })
        .transpose()
    }

    /// Whether the node's own last report says its relay carries this account.
    pub fn relay_confirmed(&self, node_id: &str, email: &str) -> CentralResult<bool> {
        self.database.with_connection(|db| {
            Ok(Self::observed_relay(db, node_id)?.is_some_and(|relay| {
                relay
                    .get("accounts")
                    .and_then(Value::as_array)
                    .is_some_and(|accounts| accounts.iter().any(|account| account.as_str() == Some(email)))
            }))
        })
    }

    pub fn observed(db: &Conn, node_id: &str) -> CentralResult<Option<ObservedGeneration>> {
        let row = db
            .query_row(
                "SELECT applied_generation,digest,reconcile_state,resources_json,reported_at
                 FROM observed_generations WHERE node_id=?",
                [node_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(applied_generation, digest, reconcile_state, resources, reported_at)| {
            let resources: Value =
                serde_json::from_str(&resources).map_err(|error| invalid_stored("observed resources", error))?;
            let value = serde_json::json!({
                "applied_generation": applied_generation,
                "digest": digest,
                "reconcile_state": reconcile_state,
                "resources": resources,
                "reported_at": reported_at,
                "egress": {},
                "relay": null,
            });
            ObservedGeneration::validate(&value).map_err(|error| invalid_stored("observed generation", error))
        })
        .transpose()
    }
}

/// The capabilities the node last reported in its identity, or none for an absent/empty identity.
pub fn node_capabilities(db: &Conn, node_id: &str) -> CentralResult<Vec<String>> {
    let identity = db
        .query_row("SELECT identity_json FROM node_links WHERE node_id=?", [node_id], |row| {
            row.get::<_, Option<String>>(0)
        })
        .optional()?
        .flatten();
    let Some(identity) = identity.filter(|identity| !identity.is_empty()) else {
        return Ok(Vec::new());
    };
    let identity: Value = serde_json::from_str(&identity).map_err(|error| invalid_stored("node identity", error))?;
    Ok(identity
        .get("capabilities")
        .and_then(Value::as_array)
        .map(|capabilities| capabilities.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default())
}

fn has(capabilities: &[String], capability: &str) -> bool {
    capabilities.iter().any(|item| item == capability)
}

/// Egress only for nodes that declared its version, with older strict models protected from
/// router, lane and newer-protocol sections they would reject wholesale.
pub fn egress_section(
    db: &Conn,
    routing: Option<&dyn DesiredRouting>,
    node_id: &str,
) -> CentralResult<Option<IndexMap<Protocol, EgressDocument>>> {
    let Some(routing) = routing else {
        return Ok(None);
    };
    let capabilities = node_capabilities(db, node_id)?;
    if !has(&capabilities, "egress.v1") {
        return Ok(None);
    }
    let mut desired = routing.desired_for_node(db, node_id)?;
    if !has(&capabilities, "egress.router.v1") {
        desired
            .retain(|_, entry| entry.backend != Backend::XrayRouter && entry.companion.is_none() && !entry.passthrough);
    }
    if !has(&capabilities, "egress.lanes.v1") {
        desired.retain(|_, entry| entry.document.get("schema").and_then(Value::as_i64) != Some(2));
    }
    for (capability, protocol) in [
        ("egress.mtproxy.v1", Protocol::Mtproxy),
        ("egress.trusttunnel.v1", Protocol::Trusttunnel),
        ("egress.amneziawg.v1", Protocol::Amneziawg),
    ] {
        if !has(&capabilities, capability) {
            desired.shift_remove(&protocol);
        }
    }
    Ok((!desired.is_empty()).then_some(desired))
}

/// The relay row and its peer accounts for a node that declared `relay.v1`.
pub fn relay_section(db: &Conn, node_id: &str, capabilities: &[String]) -> CentralResult<Option<RelaySection>> {
    if !has(capabilities, "relay.v1") {
        return Ok(None);
    }
    let row = db
        .query_row("SELECT port,server_name,enabled FROM router_relays WHERE node_id=?", [node_id], |row| {
            Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, i64>(2)?))
        })
        .optional()?;
    let Some((Some(port), Some(server_name), enabled)) = row else {
        return Ok(None);
    };
    if port == 0 || server_name.is_empty() {
        return Ok(None);
    }
    let enabled = enabled != 0;
    let accounts = if enabled {
        let mut statement = db.prepare(
            "SELECT source_node_id,exit,secret_id FROM relay_peers WHERE node_id=? ORDER BY source_node_id,exit",
        )?;
        let peers = statement
            .query_map([node_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        peers
            .into_iter()
            .map(|(source, exit, secret_id)| RelayAccount {
                email: format!("relay:{source}:{exit}"),
                credential_ref: format!("{secret_id}:1"),
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(Some(RelaySection { enabled, port, server_name, accounts }))
}

/// Compile the node's grants as they are, credentials by reference and resources ordered by ref.
#[allow(clippy::too_many_arguments)]
pub fn compile(
    db: &Conn,
    node_id: &str,
    node_guid: &str,
    master_guid: &str,
    previous: i64,
    generation: i64,
    now: i64,
    created_by: &str,
    routing: Option<&dyn DesiredRouting>,
) -> CentralResult<GenerationDocument> {
    let capabilities = node_capabilities(db, node_id)?;
    let lanes = has(&capabilities, "egress.lanes.v1");
    let clients =
        store::clients(db, None)?.into_iter().map(|client| (client.id.clone(), client)).collect::<HashMap<_, _>>();
    let grants =
        store::grants(db, &GrantFilter { node_id: Some(node_id), include_deleted: true, ..GrantFilter::default() })?;
    let mut resources = Vec::with_capacity(grants.len());
    for grant in grants {
        if grant.desired_state == GrantDesiredState::Deleted && grant.observed_state == GrantObservedState::Missing {
            continue;
        }
        if grant.protocol == Protocol::Amneziawg && !has(&capabilities, "protocol.amneziawg.v1") {
            continue;
        }
        if grant.protocol == Protocol::Trusttunnel && !has(&capabilities, "protocol.trusttunnel.v1") {
            continue;
        }
        let version = grant.secret_ref.as_ref().map_or(1, |secret| secret.version);
        let desired_state = if grant.desired_state == GrantDesiredState::Enabled
            && clients.get(&grant.client_id).map(|client| &client.state) != Some(&ClientState::Active)
        {
            DesiredState::Disabled
        } else {
            match grant.desired_state {
                GrantDesiredState::Enabled => DesiredState::Enabled,
                GrantDesiredState::Disabled => DesiredState::Disabled,
                GrantDesiredState::Deleted => DesiredState::Deleted,
            }
        };
        let mut options = grant.options.dump().as_object().cloned().unwrap_or_default();
        // `exclude_none=True, exclude={"expiration"}`: Telemt never applies expiration remotely.
        options.retain(|key, value| key != "expiration" && !value.is_null());
        resources.push(Resource {
            reference: format!("grant:{}", grant.id),
            protocol: grant.protocol,
            runtime_username: grant.runtime_username,
            desired_state,
            credential_ref: format!("grant:{}:{version}", grant.id),
            credential_origin: CredentialOrigin::Caller,
            origin: match grant.origin {
                GrantOrigin::Provisioned => ResourceOrigin::Provisioned,
                GrantOrigin::Imported => ResourceOrigin::Imported,
            },
            options,
            valid_from: grant.valid_from,
            valid_until: grant.valid_until,
            own_lane: lanes && matches!(grant.protocol, Protocol::Naive | Protocol::Mieru) && grant.own_lane,
        });
    }
    resources.sort_by(|left, right| left.reference.cmp(&right.reference));
    let document = GenerationDocument {
        schema_version: SCHEMA_VERSION,
        node_guid: node_guid.to_string(),
        master_guid: master_guid.to_string(),
        generation,
        previous_generation: previous,
        created_at: now,
        created_by: created_by.to_string(),
        resources,
        egress: egress_section(db, routing, node_id)?,
        relay: relay_section(db, node_id, &capabilities)?,
    };
    // Constructing the pydantic model in Python validates resource bounds, relay accounts and
    // every egress digest too; running the typed model's validator preserves that contract.
    GenerationDocument::validate(&document.dump()).map_err(|error| CentralError::Invalid(error.to_string()))
}

/// The transactional `ClientChangeHook`: compile, compare content, and insert only real changes.
#[derive(Clone)]
pub struct PublishService {
    master_guid: String,
    desired: DesiredStore,
    clock: SharedClock,
    routing: Option<Arc<dyn DesiredRouting>>,
}

impl PublishService {
    pub fn new(
        master_guid: impl Into<String>,
        desired: DesiredStore,
        clock: SharedClock,
        routing: Option<Arc<dyn DesiredRouting>>,
    ) -> Self {
        Self { master_guid: master_guid.into(), desired, clock, routing }
    }

    pub fn publish(&self, db: &Conn, node_id: &str) -> CentralResult<Option<i64>> {
        self.publish_at(db, node_id, "system", self.clock.now())
    }

    /// Deterministic entry point for tests and callers that already fixed one request timestamp.
    pub fn publish_at(&self, db: &Conn, node_id: &str, created_by: &str, now: i64) -> CentralResult<Option<i64>> {
        let latest = DesiredStore::latest(db, node_id)?;
        let previous = latest.as_ref().map_or(0, |latest| latest.generation);
        let document = compile(
            db,
            node_id,
            node_id,
            &self.master_guid,
            previous,
            previous + 1,
            now,
            created_by,
            self.routing.as_deref(),
        )?;
        let content = document.content_digest();
        if latest.as_ref().is_some_and(|latest| latest.content_digest == content) {
            return Ok(None);
        }
        let generation = document.generation;
        DesiredStore::insert(db, node_id, &document, &document.canonical_digest(), &content, now)?;
        Ok(Some(generation))
    }
}

impl panel_model::seams::GenerationPublisher for PublishService {
    fn publish(&self, db: &Conn, node_id: &str) -> Result<Option<i64>, SeamError> {
        PublishService::publish(self, db, node_id).map_err(|error| Box::new(error) as SeamError)
    }
}

impl panel_model::seams::RelayConfirmation for DesiredStore {
    fn confirmed(&self, node_id: &str, email: &str) -> Result<bool, SeamError> {
        self.relay_confirmed(node_id, email).map_err(|error| Box::new(error) as SeamError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_core::clock::FakeClock;
    use panel_core::ids;

    struct TempDatabase {
        database: Database,
        path: std::path::PathBuf,
    }

    impl TempDatabase {
        fn new(schema: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("fleet-generations-{}-{}.db", std::process::id(), ids::token_hex(6)));
            let database = Database::open(&path).unwrap();
            database.connect().unwrap().execute_batch(schema).unwrap();
            Self { database, path }
        }
    }

    impl Drop for TempDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
            let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
        }
    }

    const SCHEMA: &str = r#"
        CREATE TABLE node_links(node_id TEXT PRIMARY KEY,identity_json TEXT,config_dirty INTEGER NOT NULL DEFAULT 0,
            desired_generation INTEGER NOT NULL DEFAULT 0,acknowledged_generation INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE desired_generations(node_id TEXT NOT NULL,generation INTEGER NOT NULL,digest TEXT NOT NULL,
            content_digest TEXT NOT NULL,document_json TEXT NOT NULL,previous_generation INTEGER NOT NULL,
            created_at INTEGER NOT NULL,created_by TEXT NOT NULL,pushed_at INTEGER,acknowledged_at INTEGER,
            PRIMARY KEY(node_id,generation));
        CREATE TABLE observed_generations(node_id TEXT PRIMARY KEY,applied_generation INTEGER NOT NULL,digest TEXT NOT NULL,
            reconcile_state TEXT NOT NULL,resources_json TEXT NOT NULL,reported_at INTEGER NOT NULL,relay_json TEXT);
        CREATE TABLE clients(id TEXT PRIMARY KEY,display_name TEXT NOT NULL,state TEXT NOT NULL,metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
        CREATE TABLE access_grants(id TEXT PRIMARY KEY,client_id TEXT NOT NULL,protocol TEXT NOT NULL,node_id TEXT NOT NULL,
            endpoint_id TEXT NOT NULL DEFAULT 'default',runtime_username TEXT NOT NULL,secret_id TEXT,secret_version INTEGER,
            desired_state TEXT NOT NULL,observed_state TEXT NOT NULL DEFAULT 'unknown',valid_from INTEGER,valid_until INTEGER,
            protocol_options_json TEXT NOT NULL DEFAULT '{}',origin TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,
            routing_lane TEXT,label TEXT);
        CREATE TABLE router_relays(node_id TEXT PRIMARY KEY,port INTEGER,server_name TEXT,enabled INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE relay_peers(node_id TEXT NOT NULL,source_node_id TEXT NOT NULL,exit TEXT NOT NULL,secret_id TEXT NOT NULL);
    "#;

    #[test]
    fn python_golden_digests_match() {
        let golden: Value = serde_json::from_str(include_str!("../../../tests/goldens/fleet/fleet.json")).unwrap();
        for row in golden["desired_generations"].as_array().unwrap() {
            let document = generation_from_json(row["document_json"].as_str().unwrap()).unwrap();
            assert_eq!(document.canonical_digest(), row["digest"].as_str().unwrap());
            assert_eq!(document.content_digest(), row["content_digest"].as_str().unwrap());
        }
    }

    #[test]
    fn compile_applies_states_capabilities_options_and_relay() {
        let temp = TempDatabase::new(SCHEMA);
        let db = temp.database.connect().unwrap();
        db.execute(
            "INSERT INTO node_links(node_id,identity_json) VALUES('n',?)",
            [serde_json::json!({"capabilities":["egress.lanes.v1","relay.v1"]}).to_string()],
        )
        .unwrap();
        db.execute("INSERT INTO clients VALUES('c','Suspended','suspended','{}',0,0)", []).unwrap();
        for (id, protocol, username, desired, observed, options, lane) in [
            ("g2", "mtproxy", "z", "enabled", "unknown", r#"{"expiration":123,"host":"proxy.example"}"#, None),
            ("g1", "naive", "a", "enabled", "unknown", r#"{"quota_bytes":12}"#, Some("own")),
            ("g3", "naive", "gone", "deleted", "missing", "{}", None),
            ("g4", "amneziawg", "unsupported", "enabled", "unknown", r#"{"version":"2.0"}"#, None),
        ] {
            db.execute(
                "INSERT INTO access_grants(id,client_id,protocol,node_id,runtime_username,desired_state,observed_state,
                 protocol_options_json,origin,created_at,updated_at,routing_lane) VALUES(?, 'c', ?, 'n', ?, ?, ?, ?, 'provisioned',0,0,?)",
                params![id, protocol, username, desired, observed, options, lane],
            )
            .unwrap();
        }
        db.execute("INSERT INTO router_relays VALUES('n',443,'cover.example',1)", []).unwrap();
        db.execute("INSERT INTO relay_peers VALUES('n','source','warp','relay:source')", []).unwrap();
        let document = compile(&db, "n", "n", "master", 0, 1, 10, "system", None).unwrap();
        assert_eq!(
            document.resources.iter().map(|r| r.reference.as_str()).collect::<Vec<_>>(),
            ["grant:g1", "grant:g2"]
        );
        assert_eq!(document.resources[0].desired_state, DesiredState::Disabled);
        assert!(document.resources[0].own_lane);
        assert_eq!(
            document.resources[1].options,
            serde_json::json!({"host":"proxy.example"}).as_object().unwrap().clone()
        );
        let relay = document.relay.unwrap();
        assert_eq!(
            relay.accounts,
            vec![RelayAccount { email: "relay:source:warp".into(), credential_ref: "relay:source:1".into() }]
        );

        let desired = DesiredStore::new(temp.database.clone());
        let publish = PublishService::new("master", desired, Arc::new(FakeClock::new(10.0)), None);
        assert_eq!(publish.publish_at(&db, "n", "system", 10).unwrap(), Some(1));
        assert_eq!(publish.publish_at(&db, "n", "system", 11).unwrap(), None);
        let latest = DesiredStore::latest(&db, "n").unwrap().unwrap();
        assert_eq!(latest.document.created_at, 10);
        assert_eq!(
            db.query_row("SELECT config_dirty FROM node_links WHERE node_id='n'", [], |r| r.get::<_, i64>(0)).unwrap(),
            1
        );
    }

    #[test]
    fn egress_sections_follow_every_node_capability() {
        let temp = TempDatabase::new(SCHEMA);
        let db = temp.database.connect().unwrap();
        let section = |backend, schema| EgressDocument {
            backend,
            policy_id: "p".into(),
            policy_revision: 1,
            document: serde_json::json!({"schema":schema}).as_object().unwrap().clone(),
            digest: "d".repeat(64),
            companion: None,
            passthrough: false,
        };
        let desired = || {
            IndexMap::from([
                (Protocol::Naive, section(Backend::NaiveNative, 1)),
                (Protocol::Mieru, section(Backend::XrayRouter, 1)),
                (Protocol::Mtproxy, section(Backend::MtproxyNative, 1)),
                (Protocol::Trusttunnel, section(Backend::TrusttunnelNative, 1)),
                (Protocol::Amneziawg, section(Backend::AmneziawgNative, 1)),
            ])
        };
        let routing =
            move |_db: &Conn, _node: &str| -> CentralResult<IndexMap<Protocol, EgressDocument>> { Ok(desired()) };
        db.execute(
            "INSERT INTO node_links(node_id,identity_json) VALUES('n',?)",
            [serde_json::json!({"capabilities":[]}).to_string()],
        )
        .unwrap();
        assert!(egress_section(&db, Some(&routing), "n").unwrap().is_none());
        db.execute(
            "UPDATE node_links SET identity_json=? WHERE node_id='n'",
            [serde_json::json!({"capabilities":["egress.v1"]}).to_string()],
        )
        .unwrap();
        let limited = egress_section(&db, Some(&routing), "n").unwrap().unwrap();
        assert_eq!(limited.keys().copied().collect::<Vec<_>>(), [Protocol::Naive]);
        db.execute(
            "UPDATE node_links SET identity_json=? WHERE node_id='n'",
            [serde_json::json!({"capabilities":["egress.v1","egress.router.v1","egress.lanes.v1",
                "egress.mtproxy.v1","egress.trusttunnel.v1","egress.amneziawg.v1"]})
            .to_string()],
        )
        .unwrap();
        assert_eq!(egress_section(&db, Some(&routing), "n").unwrap().unwrap().len(), 5);
    }

    #[test]
    fn observed_acknowledgement_and_relay_follow_node_reports() {
        let temp = TempDatabase::new(SCHEMA);
        let db = temp.database.connect().unwrap();
        db.execute(
            "INSERT INTO node_links(node_id,identity_json,desired_generation,config_dirty) VALUES('n','{}',2,1)",
            [],
        )
        .unwrap();
        let empty = GenerationDocument {
            schema_version: 1,
            node_guid: "n".into(),
            master_guid: "m".into(),
            generation: 2,
            previous_generation: 1,
            created_at: 1,
            created_by: "system".into(),
            resources: Vec::new(),
            egress: None,
            relay: None,
        };
        DesiredStore::insert(&db, "n", &empty, "d", "c", 1).unwrap();
        let observed = ObservedGeneration {
            applied_generation: 2,
            digest: "d".into(),
            reconcile_state: ReconcileState::Converged,
            resources: Vec::new(),
            reported_at: 4,
            egress: IndexMap::new(),
            relay: None,
        };
        DesiredStore::record_observed(&db, "n", &observed, false, 5).unwrap();
        assert_eq!(DesiredStore::latest(&db, "n").unwrap().unwrap().acknowledged_at, None);
        assert_eq!(
            db.query_row("SELECT config_dirty FROM node_links WHERE node_id='n'", [], |r| r.get::<_, i64>(0)).unwrap(),
            1
        );
        DesiredStore::record_observed(&db, "n", &observed, true, 5).unwrap();
        assert_eq!(DesiredStore::observed(&db, "n").unwrap().unwrap().reported_at, 4);
        assert_eq!(
            db.query_row("SELECT config_dirty FROM node_links WHERE node_id='n'", [], |r| r.get::<_, i64>(0)).unwrap(),
            0
        );
        let relay = serde_json::json!({"accounts":["relay:source:warp"],"enabled":true}).as_object().unwrap().clone();
        DesiredStore::record_relay(&db, "n", Some(&relay)).unwrap();
        assert_eq!(DesiredStore::observed_relay(&db, "n").unwrap(), Some(relay));
        db.commit().unwrap();
        let store = DesiredStore::new(temp.database.clone());
        assert!(store.relay_confirmed("n", "relay:source:warp").unwrap());
        assert!(!store.relay_confirmed("n", "relay:other:direct").unwrap());
        DesiredStore::mark_pushed(&db, "n", 2, 6).unwrap();
        assert_eq!(DesiredStore::latest(&db, "n").unwrap().unwrap().pushed_at, Some(6));
    }
}
