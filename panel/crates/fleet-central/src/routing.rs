//! The central's routing seams: desired egress and transactional node readback.

use indexmap::IndexMap;
use panel_core::db::Conn;
use panel_core::pyjson;
use panel_model::fleet::{EgressDocument, GenerationDocument, ObservedGeneration, ObservedRelay, SectionState};
use panel_model::routing::models::{DefaultAction, PolicyState};
use panel_model::validate::Model;
use panel_model::Protocol;
use panel_routing::lanes::RelayRegistry;
use panel_routing::store::{self, ApplyRecord, Mark, StoreError};
use serde_json::{json, Value};

use crate::generations::DesiredRouting;
use crate::pusher::ObservationSink;
use crate::{CentralError, CentralResult};

fn failure(error: impl std::fmt::Display) -> CentralError {
    CentralError::Internal(error.to_string())
}

/// Uses the routing store directly: no service cycle, network call or nested transaction.
#[derive(Clone, Copy)]
pub struct FleetRouting;

impl DesiredRouting for FleetRouting {
    fn desired_for_node(&self, db: &Conn, node_id: &str) -> CentralResult<IndexMap<Protocol, EgressDocument>> {
        store::desired_for_node(db, node_id)
            .map_err(failure)?
            .into_iter()
            .map(|(protocol, entry)| {
                let protocol = Protocol::from_wire(&protocol)
                    .ok_or_else(|| CentralError::Internal("stored egress protocol is invalid".into()))?;
                Ok((protocol, EgressDocument::validate(&entry).map_err(failure)?))
            })
            .collect()
    }
}

impl ObservationSink for FleetRouting {
    fn absorb_egress(
        &self,
        db: &Conn,
        _node_id: &str,
        latest: &GenerationDocument,
        observed: &ObservedGeneration,
        now: i64,
    ) -> CentralResult<()> {
        let Some(egress) = &latest.egress else { return Ok(()) };
        for (protocol, entry) in egress {
            let Some(report) = observed.egress.get(protocol.as_str()) else { continue };
            let policy = match store::get_by_id(db, &entry.policy_id) {
                Ok(policy) => policy,
                Err(StoreError::NotFound(_)) => continue,
                Err(other) => return Err(failure(other.into_failure())),
            };
            let mut detail = json!({"generation": latest.generation, "manager_revision": report.revision});
            if let Some(router) = &report.router {
                detail["router"] = Value::Object(router.clone());
            }
            let mut record =
                ApplyRecord::new(entry.policy_revision, Some(&entry.digest), entry.backend.as_str(), "applied");
            record.actor = "node";
            if report.state == SectionState::Converged {
                let empty = policy.intent.default_action == DefaultAction::Direct
                    && !policy.intent.rules.iter().any(|rule| rule.enabled);
                if entry.passthrough && !empty {
                    if policy.state == PolicyState::Draft
                        && policy.applied_digest.as_deref() == Some(&entry.digest)
                        && policy.backend == entry.backend
                    {
                        continue;
                    }
                    store::mark(
                        db,
                        &policy.id,
                        PolicyState::Draft,
                        Mark { applied_digest: Some(entry.digest.clone()), ..Mark::default() },
                        now,
                    )
                    .map_err(failure)?;
                    detail["passthrough"] = json!(true);
                } else {
                    if policy.state == PolicyState::Applied
                        && policy.applied_revision == Some(entry.policy_revision)
                        && policy.applied_digest.as_deref() == Some(&entry.digest)
                    {
                        continue;
                    }
                    store::mark(
                        db,
                        &policy.id,
                        PolicyState::Applied,
                        Mark {
                            applied_revision: Some(entry.policy_revision),
                            applied_digest: Some(entry.digest.clone()),
                            ..Mark::default()
                        },
                        now,
                    )
                    .map_err(failure)?;
                    if entry.document.get("schema").and_then(Value::as_i64) == Some(2) {
                        for other in store::lanes_of(db, &policy.node_id, policy.protocol.as_str()).map_err(failure)? {
                            if other.id != policy.id {
                                store::mark(
                                    db,
                                    &other.id,
                                    PolicyState::Applied,
                                    Mark {
                                        applied_revision: Some(other.revision),
                                        applied_digest: Some(entry.digest.clone()),
                                        ..Mark::default()
                                    },
                                    now,
                                )
                                .map_err(failure)?;
                            }
                        }
                    }
                }
                let document = Value::Object(entry.document.clone());
                record.document = Some(&document);
                record.detail = Some(pyjson::sorted(&detail));
                store::record_apply(db, &policy.id, &record, now).map_err(failure)?;
            } else {
                let error = report.error.as_deref().filter(|error| !error.is_empty()).unwrap_or(report.state.as_str());
                if policy.state == PolicyState::Failed && policy.last_error.as_deref() == Some(error) {
                    continue;
                }
                store::mark(
                    db,
                    &policy.id,
                    PolicyState::Failed,
                    Mark { last_error: Some(error.to_owned()), ..Mark::default() },
                    now,
                )
                .map_err(failure)?;
                detail["error"] = json!(error);
                record.outcome = "failed";
                record.detail = Some(pyjson::sorted(&detail));
                store::record_apply(db, &policy.id, &record, now).map_err(failure)?;
            }
        }
        Ok(())
    }

    fn observe_relay(&self, db: &Conn, node_id: &str, relay: &ObservedRelay, now: i64) -> CentralResult<()> {
        RelayRegistry::observe(db, node_id, relay.dump().as_object().expect("relay is an object"), now).map_err(failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_core::db::Database;
    use panel_core::ids;
    use panel_model::fleet::{ObservedEgress, ReconcileState};
    use panel_model::routing::models::PolicyInput;

    struct Fixture {
        database: Database,
        path: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("fleet-routing-{}.db", ids::token_hex(8)));
            let database = Database::open(&path).unwrap();
            panel_core::migrations::apply_migrations(&database).unwrap();
            database.transaction::<_, CentralError>(|db| {
                db.execute("INSERT INTO fleet_nodes(node_id,display_name,kind,transport,auth_state,inventory_json,created_at,updated_at) VALUES('edge','Edge','remote','panel','linked','{}',0,0)", [])?;
                Ok(())
            }).unwrap();
            Self { database, path }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
            let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
        }
    }

    fn generation(entry: EgressDocument) -> GenerationDocument {
        GenerationDocument {
            schema_version: 1,
            node_guid: "edge".into(),
            master_guid: "central".into(),
            generation: 1,
            previous_generation: 0,
            created_at: 1,
            created_by: "system".into(),
            resources: Vec::new(),
            egress: Some(IndexMap::from([(Protocol::Naive, entry)])),
            relay: None,
        }
    }

    fn observed(state: SectionState) -> ObservedGeneration {
        ObservedGeneration {
            applied_generation: 1,
            digest: "generation".into(),
            reconcile_state: ReconcileState::Converged,
            resources: Vec::new(),
            reported_at: 1,
            relay: None,
            egress: IndexMap::from([(
                "naive".into(),
                ObservedEgress {
                    state,
                    revision: Some("manager-r1".into()),
                    digest: None,
                    error: None,
                    router: Some(json!({"revision": "router-r1"}).as_object().unwrap().clone()),
                    lanes: Vec::new(),
                },
            )]),
        }
    }

    #[test]
    fn desired_and_observation_keep_policy_history_idempotent() {
        let fixture = Fixture::new();
        fixture
            .database
            .transaction::<_, CentralError>(|db| {
                let policy = store::upsert(db, "edge", "naive", &PolicyInput::default(), None, 1, "svc")
                    .map_err(|error| failure(error.into_failure()))?;
                let lane = store::upsert(db, "edge", "naive", &PolicyInput::default(), None, 1, "grant:g")
                    .map_err(|error| failure(error.into_failure()))?;
                let document = json!({"schema": 2, "lanes": []}).as_object().unwrap().clone();
                let entry = EgressDocument {
                    backend: policy.backend,
                    policy_id: policy.id.clone(),
                    policy_revision: policy.revision,
                    digest: panel_model::routing::document::document_digest_map(&document),
                    document,
                    companion: None,
                    passthrough: false,
                };
                store::set_desired(db, &policy.id, Some(&entry.dump()), 1).map_err(failure)?;
                assert_eq!(FleetRouting.desired_for_node(db, "edge")?[&Protocol::Naive], entry);
                let generation = generation(entry.clone());
                let report = observed(SectionState::Converged);
                FleetRouting.absorb_egress(db, "edge", &generation, &report, 2)?;
                FleetRouting.absorb_egress(db, "edge", &generation, &report, 3)?;
                let applied = store::get_by_id(db, &policy.id).map_err(|error| failure(error.into_failure()))?;
                assert_eq!(applied.state, PolicyState::Applied);
                assert_eq!(applied.applied_digest.as_deref(), Some(entry.digest.as_str()));
                assert_eq!(store::get_by_id(db, &lane.id).unwrap().state, PolicyState::Applied);
                assert_eq!(store::history(db, &policy.id, 50).map_err(failure)?.len(), 1);
                let failed = observed(SectionState::Unsupported);
                FleetRouting.absorb_egress(db, "edge", &generation, &failed, 4)?;
                FleetRouting.absorb_egress(db, "edge", &generation, &failed, 5)?;
                let policy = store::get_by_id(db, &policy.id).unwrap();
                assert_eq!(policy.last_error.as_deref(), Some("unsupported"));
                assert_eq!(store::history(db, &policy.id, 50).map_err(failure)?.len(), 2);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn passthrough_keeps_nonempty_policy_draft_and_relay_preserves_desire() {
        let fixture = Fixture::new();
        fixture
            .database
            .transaction::<_, CentralError>(|db| {
                let mut input = PolicyInput::default();
                input.intent.default_action = DefaultAction::Egress;
                input.intent.default_egress = Some("warp".into());
                let policy = store::upsert(db, "edge", "naive", &input, None, 1, "svc")
                    .map_err(|error| failure(error.into_failure()))?;
                let entry = EgressDocument {
                    backend: policy.backend,
                    policy_id: policy.id.clone(),
                    policy_revision: policy.revision,
                    digest: "a".repeat(64),
                    document: json!({"schema": 1}).as_object().unwrap().clone(),
                    companion: None,
                    passthrough: true,
                };
                let generation = generation(entry);
                let report = observed(SectionState::Converged);
                FleetRouting.absorb_egress(db, "edge", &generation, &report, 2)?;
                FleetRouting.absorb_egress(db, "edge", &generation, &report, 3)?;
                let policy = store::get_by_id(db, &policy.id).unwrap();
                assert_eq!(policy.state, PolicyState::Draft);
                assert_eq!(policy.applied_revision, None);
                assert_eq!(store::history(db, &policy.id, 50).map_err(failure)?.len(), 1);
                RelayRegistry::desire(db, "edge", true, 443, "relay.example", 1).map_err(failure)?;
                let mut relay = ObservedRelay {
                    state: SectionState::Converged,
                    enabled: false,
                    port: Some(443),
                    server_name: Some("relay.example".into()),
                    public_key: Some("key".into()),
                    short_id: Some("id".into()),
                    accounts: vec!["relay:source:direct".into()],
                    error: None,
                };
                FleetRouting.observe_relay(db, "edge", &relay, 2)?;
                assert_eq!(RelayRegistry::relay(db, "edge").unwrap().unwrap()["enabled"], 1);
                relay.state = SectionState::Failed;
                relay.public_key = Some("must-not-land".into());
                FleetRouting.observe_relay(db, "edge", &relay, 3)?;
                assert_eq!(RelayRegistry::relay(db, "edge").unwrap().unwrap()["public_key"], "key");
                Ok(())
            })
            .unwrap();
    }
}
