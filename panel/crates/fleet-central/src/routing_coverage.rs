//! Routing consumers exercised through the real publisher, pusher and observation sink.
use std::sync::Arc;

use panel_clients::Adapters;
use panel_core::db::DbError;
use panel_model::fleet::{ObservedEgress, ObservedRelay, ReconcileState, SectionState};
use panel_model::protocols::{AdapterError, BoxFuture, ProtocolAdapter};
use panel_model::routing::document::{attach_document, document_digest, router_direct_intent};
use panel_model::routing::models::{PolicyInput, PolicyState, LANE_SERVICE};
use panel_model::validate::Model;
use panel_model::Protocol;
use panel_routing::lanes::{LaneService, RelayRegistry};
use panel_routing::runtime::RoutingAdapters;
use panel_routing::service::RoutingService;
use panel_routing::store;
use serde_json::{json, Value};

use crate::generations::{self, DesiredStore, PublishService};
use crate::native_fixture::{domain::ctx, object, Rig, EDGE, MASTER};
use crate::pusher::{FleetPusher, PusherOptions};
use crate::routing::FleetRouting;

struct AdaptersOnly(Adapters);
impl RoutingAdapters for AdaptersOnly {
    fn adapter(&self, protocol: Protocol) -> Option<Arc<dyn ProtocolAdapter>> {
        self.0.get(protocol)
    }
    fn set_lanes<'a>(&'a self, _: Protocol, _: &'a Value) -> BoxFuture<'a, Result<Value, AdapterError>> {
        panic!("remote lanes must travel through generations")
    }
}

fn advertised() -> Value {
    json!({"backend":"naive_native","revision":"native-r0","mode":"direct","router_attached":false,
        "capabilities":["whole_direct","whole_warp","block_domain","block_cidr"],
        "providers":{"warp":{"reachable":true},"router":{"reachable":true}}})
}
fn capabilities() -> Value {
    json!(["generation.v1", "credentials.capture", "egress.v1", "egress.router.v1", "egress.lanes.v1", "relay.v1"])
}
fn configure(rig: &Rig) {
    let mut node = rig.node.state.lock().unwrap();
    node.identity.insert("capabilities".into(), capabilities());
    node.identity["protocols"]["naive"]["egress"] = advertised();
    node.identity.insert("router".into(), json!({"available":true,
        "capabilities":panel_managers::xray_router::ROUTER_CAPABILITIES,
        "providers":{"warp":{"reachable":true}},"services":{"naive":{"revision":"router-r0","applied_digest":document_digest(&router_direct_intent())}},
        "lanes":{"naive":[],"mieru":[]},"relay":{"enabled":false}}));
}
fn services(rig: &Rig) -> (RoutingService, LaneService, Arc<FleetPusher>, Arc<PublishService>) {
    let adapters = Arc::new(AdaptersOnly(rig.env.adapters.clone()));
    let publisher = Arc::new(PublishService::new(MASTER, rig.env.clock.clone(), Some(Arc::new(FleetRouting))));
    let routing = RoutingService::new(
        rig.env.database.clone(),
        adapters.clone(),
        Arc::new(|_: &str| true),
        Some(publisher.clone()),
        None,
        rig.env.clock.clone(),
        None,
        Some(RelayRegistry::new(rig.env.secrets.clone())),
        MASTER,
        "central.example",
        Arc::new(DesiredStore::new(rig.env.database.clone())),
        None,
    );
    let lanes =
        LaneService::new(rig.env.database.clone(), adapters, None, rig.env.clock.clone(), Some(publisher.clone()));
    let pusher = rig.rebuilt_pusher(PusherOptions {
        desired_routing: Some(Arc::new(FleetRouting)),
        observations: Some(Arc::new(FleetRouting)),
        ..PusherOptions::default()
    });
    (routing, lanes, pusher, publisher)
}
fn input(value: Value) -> PolicyInput {
    PolicyInput::validate(&value).unwrap()
}
fn warp() -> PolicyInput {
    input(json!({"default_action":"egress","default_egress":"warp"}))
}
fn block() -> PolicyInput {
    input(json!({"rules":[{"action":"block","match":{"domains":["example.com"]}}]}))
}

// A remote node is a controlled protocol boundary, not a second routing implementation. The
// node reconciliation tests separately prove enforcement; here only its authenticated readback
// is supplied, and FleetPusher must consume it transactionally.
async fn report(rig: &Rig, pusher: &FleetPusher, state: SectionState, error: Option<&str>) {
    rig.node.state.lock().unwrap().push_state = ReconcileState::Applying;
    pusher.tick().await.unwrap();
    let latest = rig.latest();
    {
        let mut node = rig.node.state.lock().unwrap();
        node.report.reconcile_state =
            if state == SectionState::Converged { ReconcileState::Converged } else { ReconcileState::Failed };
        node.push_state = node.report.reconcile_state;
        node.report.egress = latest
            .document
            .egress
            .as_ref()
            .unwrap()
            .iter()
            .map(|(protocol, entry)| {
                let router = entry.companion.as_ref().map(|companion| {
                    let intent = if entry.backend == panel_model::Backend::XrayRouter {
                        Value::Object(entry.document.clone())
                    } else {
                        Value::Object(companion.clone())
                    };
                    object(json!({"revision":"router-r1","digest":document_digest(&intent)}))
                });
                (
                    protocol.as_str().into(),
                    ObservedEgress {
                        state,
                        revision: Some("manager-r1".into()),
                        digest: Some(entry.digest.clone()),
                        error: error.map(str::to_string),
                        router,
                        lanes: Vec::new(),
                    },
                )
            })
            .collect();
        if state == SectionState::Converged {
            let digest = &latest.document.egress.as_ref().unwrap()[&Protocol::Naive].digest;
            node.identity["protocols"]["naive"]["egress"]["applied_digest"] = json!(digest);
            let entry = &latest.document.egress.as_ref().unwrap()[&Protocol::Naive];
            if entry.companion.is_some() {
                let router_digest = node.report.egress["naive"].router.as_ref().unwrap()["digest"].clone();
                node.identity["router"]["services"]["naive"]["applied_digest"] = router_digest;
                node.identity["protocols"]["naive"]["egress"]["router_attached"] =
                    json!(entry.backend == panel_model::Backend::XrayRouter);
            }
        }
    }
    pusher.tick().await.unwrap();
}

#[tokio::test]
async fn compile_includes_only_desired_sections_for_an_egress_v1_node() {
    let rig = Rig::new();
    configure(&rig);
    rig.link(false).await;
    let (routing, _, _, publisher) = services(&rig);
    routing.save(EDGE, "naive", &warp(), None, LANE_SERVICE, &ctx()).unwrap();
    rig.env.database.transaction::<_,DbError>(|db| {
        let compile = |routing: Option<&dyn generations::DesiredRouting>| generations::compile(db,EDGE,EDGE,MASTER,0,1,1,"test",routing).unwrap();
        assert!(compile(Some(&FleetRouting)).egress.is_none());
        let policy=store::get(db,EDGE,"naive",LANE_SERVICE).unwrap().unwrap();
        let document=json!({"schema":1,"upstream":{"provider":"warp"},"acl":[]});
        store::set_desired(db,&policy.id,Some(&json!({"backend":"naive_native","policy_id":policy.id,"policy_revision":1,"document":document,"digest":document_digest(&document)})),1).unwrap();
        let compiled=compile(Some(&FleetRouting));
        assert_eq!(compiled.egress.unwrap()[&Protocol::Naive].document,object(document));
        assert!(compile(None).egress.is_none());
        db.execute("UPDATE node_links SET identity_json='{}' WHERE node_id=?",[EDGE])?;
        assert!(compile(Some(&FleetRouting)).egress.is_none());
        publisher.publish(db,EDGE).unwrap();
        Ok(())
    }).unwrap();
}

#[tokio::test]
async fn routing_apply_remote_publishes_generation_and_the_report_marks_it_applied() {
    let rig = Rig::new();
    configure(&rig);
    rig.link(false).await;
    let (routing, _, pusher, publisher) = services(&rig);
    pusher.tick().await.unwrap();
    routing.save(EDGE, "naive", &warp(), None, LANE_SERVICE, &ctx()).unwrap();
    let result = routing.apply(EDGE, "naive", 1, LANE_SERVICE, &ctx()).await.unwrap();
    assert_eq!(result.policy.state, PolicyState::Applying);
    assert!(result.applied.is_none());
    assert_eq!(
        rig.latest().document.egress.as_ref().unwrap()[&Protocol::Naive].digest,
        result.compiled.digest.unwrap()
    );
    report(&rig, &pusher, SectionState::Converged, None).await;
    let policy = routing.get(EDGE, "naive", LANE_SERVICE).unwrap();
    assert_eq!((policy.state, policy.applied_revision), (PolicyState::Applied, Some(1)));
    let history = routing.history(EDGE, "naive", LANE_SERVICE).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["actor"], "node");
    assert_eq!(history[0]["document"], json!({"schema":1,"upstream":{"provider":"warp"},"acl":[]}));
    pusher.tick().await.unwrap();
    assert_eq!(routing.history(EDGE, "naive", LANE_SERVICE).unwrap().len(), 1);
    let preview = routing.preview(EDGE, "naive", None, LANE_SERVICE).await.unwrap();
    assert!(preview.diff.is_empty());
    assert_eq!(preview.rollback.unwrap()["to_digest"], policy.applied_digest.as_ref().unwrap().as_str());
    rig.env.clients.add_hook(Arc::new(panel_clients::hooks::PublishForClient::new(publisher)));
    rig.provision(Protocol::Naive, "alice").await;
    assert_eq!(rig.latest().document.egress.as_ref().unwrap()[&Protocol::Naive].digest, policy.applied_digest.unwrap());
    report(&rig, &pusher, SectionState::Converged, None).await;
    assert_eq!(routing.history(EDGE, "naive", LANE_SERVICE).unwrap().len(), 1);
}

// test_routing_fleet_router.py: the central never applies a router document to the node
// directly; attachment, policy changes, rollback and detachment all travel in generations.
#[tokio::test]
async fn remote_router_attach_apply_rollback_and_detach_follow_observed_generations() {
    let rig = Rig::new();
    configure(&rig);
    rig.node.state.lock().unwrap().identity["protocols"]["naive"]["egress"]["router_attached"] = json!(false);
    rig.link(false).await;
    let (routing, _, pusher, _) = services(&rig);
    pusher.tick().await.unwrap();
    let attached = routing.attach(EDGE, "naive", &ctx()).await.unwrap();
    assert_eq!(attached["policy"]["backend"], "xray_router");
    assert_eq!(attached["policy"]["state"], "applying");
    let latest = rig.latest();
    let section = &latest.document.egress.as_ref().unwrap()[&Protocol::Naive];
    assert_eq!(section.document, object(router_direct_intent()));
    assert_eq!(section.companion, attach_document("naive").and_then(|value| value.as_object().cloned()));
    assert!(section.passthrough);
    report(&rig, &pusher, SectionState::Converged, None).await;
    assert_eq!(routing.get(EDGE, "naive", LANE_SERVICE).unwrap().state, PolicyState::Applied);
    let target = routing
        .targets()
        .await
        .unwrap()
        .into_iter()
        .find(|item| item["node_id"] == EDGE && item["protocol"] == "naive")
        .unwrap();
    assert_eq!(target["backend"], "xray_router");
    assert_eq!(target["router"]["attached"], true);

    routing
        .save(
            EDGE,
            "naive",
            &input(json!({"backend":"xray_router", "default_action":"egress",
        "default_egress":"warp", "rules":[{"action":"block", "match":{"geosites":["category-ads-all"]}}]})),
            Some(1),
            LANE_SERVICE,
            &ctx(),
        )
        .unwrap();
    let applied = routing.apply(EDGE, "naive", 2, LANE_SERVICE, &ctx()).await.unwrap();
    assert_eq!(applied.policy.state, PolicyState::Applying);
    assert_eq!(applied.compiled.document.as_ref().unwrap()["rules"][0]["geosites"], json!(["category-ads-all"]));
    assert_eq!(
        rig.latest().document.egress.as_ref().unwrap()[&Protocol::Naive].companion,
        attach_document("naive").and_then(|value| value.as_object().cloned())
    );
    report(&rig, &pusher, SectionState::Converged, None).await;
    let policy = routing.get(EDGE, "naive", LANE_SERVICE).unwrap();
    assert_eq!((policy.state, policy.applied_revision), (PolicyState::Applied, Some(2)));
    let history = routing.history(EDGE, "naive", LANE_SERVICE).unwrap();
    assert_eq!(history[0]["backend"], "xray_router");
    let detail: Value = serde_json::from_str(history[0]["detail"].as_str().unwrap()).unwrap();
    assert_eq!(detail["router"]["digest"], policy.applied_digest.unwrap());

    let rollback = routing.rollback(EDGE, "naive", 2, LANE_SERVICE, &ctx()).await.unwrap();
    assert_eq!(rollback.compiled.document, Some(router_direct_intent()));
    assert_eq!(
        rig.latest().document.egress.as_ref().unwrap()[&Protocol::Naive].document,
        object(router_direct_intent())
    );
    report(&rig, &pusher, SectionState::Converged, None).await;
    let detached = routing.detach(EDGE, "naive", &ctx()).await.unwrap();
    assert_eq!(detached["policy"]["backend"], "naive_native");
    let latest = rig.latest();
    let section = &latest.document.egress.as_ref().unwrap()[&Protocol::Naive];
    assert_eq!(section.document, object(json!({"schema":1,"upstream":null,"acl":[]})));
    assert_eq!(section.companion, Some(object(router_direct_intent())));
    assert!(section.passthrough);
    report(&rig, &pusher, SectionState::Converged, None).await;
    let policy = routing.get(EDGE, "naive", LANE_SERVICE).unwrap();
    assert_eq!((policy.backend.as_str(), policy.state), ("naive_native", PolicyState::Draft));
    assert_eq!(rig.audit("routing.target.attach")["outcome"], "applying");
    assert_eq!(rig.audit("routing.target.detach")["outcome"], "applying");
}

#[tokio::test]
async fn pusher_marks_policy_failed_with_the_node_error_and_later_recovers() {
    let rig = Rig::new();
    configure(&rig);
    rig.link(false).await;
    let (routing, _, pusher, _) = services(&rig);
    pusher.tick().await.unwrap();
    routing.save(EDGE, "naive", &warp(), None, LANE_SERVICE, &ctx()).unwrap();
    routing.apply(EDGE, "naive", 1, LANE_SERVICE, &ctx()).await.unwrap();
    report(&rig, &pusher, SectionState::Failed, Some("egress_unreachable")).await;
    let policy = routing.get(EDGE, "naive", LANE_SERVICE).unwrap();
    assert_eq!(policy.state, PolicyState::Failed);
    assert_eq!(policy.last_error.as_deref(), Some("egress_unreachable"));
    assert!(policy.applied_revision.is_none());
    pusher.tick().await.unwrap();
    assert_eq!(routing.history(EDGE, "naive", LANE_SERVICE).unwrap().len(), 1);
    // A fresh service instance has no delivery backoff, just as a restarted panel.
    let recovered = services(&rig).2;
    report(&rig, &recovered, SectionState::Converged, None).await;
    assert_eq!(routing.get(EDGE, "naive", LANE_SERVICE).unwrap().state, PolicyState::Applied);
    assert_eq!(routing.history(EDGE, "naive", LANE_SERVICE).unwrap().len(), 2);
}

#[tokio::test]
async fn routing_rollback_remote_publishes_previous_document() {
    let rig = Rig::new();
    configure(&rig);
    rig.link(false).await;
    let (routing, _, pusher, _) = services(&rig);
    pusher.tick().await.unwrap();
    routing.save(EDGE, "naive", &block(), None, LANE_SERVICE, &ctx()).unwrap();
    let error = routing.rollback(EDGE, "naive", 1, LANE_SERVICE, &ctx()).await.unwrap_err();
    assert_eq!(error.code(), Some("egress_no_previous"));
    routing.apply(EDGE, "naive", 1, LANE_SERVICE, &ctx()).await.unwrap();
    report(&rig, &pusher, SectionState::Converged, None).await;
    let previous = rig.latest().document.egress.unwrap()[&Protocol::Naive].document.clone();
    routing.save(EDGE, "naive", &warp(), Some(1), LANE_SERVICE, &ctx()).unwrap();
    routing.apply(EDGE, "naive", 2, LANE_SERVICE, &ctx()).await.unwrap();
    report(&rig, &pusher, SectionState::Converged, None).await;
    let rollback = routing.rollback(EDGE, "naive", 2, LANE_SERVICE, &ctx()).await.unwrap();
    assert_eq!(rollback.policy.state, PolicyState::Applying);
    assert_eq!(rollback.compiled.document, Some(Value::Object(previous.clone())));
    assert_eq!(rig.latest().document.egress.unwrap()[&Protocol::Naive].document, previous);
    report(&rig, &pusher, SectionState::Converged, None).await;
    let policy = routing.get(EDGE, "naive", LANE_SERVICE).unwrap();
    assert_eq!((policy.state, policy.revision, policy.applied_revision), (PolicyState::Applied, 2, Some(1)));
    assert_eq!(
        routing
            .history(EDGE, "naive", LANE_SERVICE)
            .unwrap()
            .iter()
            .map(|row| row["outcome"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["applied", "rolled_back", "applied", "applied"]
    );
    assert_eq!(rig.audit("routing.policy.rollback")["to_revision"], 1);
}

#[tokio::test]
async fn a_grant_on_a_linked_node_gets_its_lane_through_the_generation() {
    let rig = Rig::new();
    configure(&rig);
    rig.link(false).await;
    let (routing, lanes, pusher, _) = services(&rig);
    pusher.tick().await.unwrap();
    let (_, grant) = rig.provision(Protocol::Naive, "alice").await;
    routing.attach(EDGE, "naive", &ctx()).await.unwrap();
    report(&rig, &pusher, SectionState::Converged, None).await;
    let lane = format!("grant:{}", grant.id);
    let enabled = lanes.enable(&grant.id, &ctx()).await.unwrap();
    assert_eq!(enabled["pending"], true);
    assert!(rig.latest().document.resources.iter().find(|item| item.reference == lane).unwrap().own_lane);
    routing
        .save(
            EDGE,
            "naive",
            &input(json!({"backend":"xray_router","default_action":"egress","default_egress":"warp"})),
            Some(1),
            &lane,
            &ctx(),
        )
        .unwrap();
    let applied = routing.apply(EDGE, "naive", 2, &lane, &ctx()).await.unwrap();
    assert_eq!(applied.compiled.document.as_ref().unwrap()["schema"], 2);
    assert_eq!(
        rig.latest().document.egress.as_ref().unwrap()[&Protocol::Naive].document["lanes"][&lane]["default"]["egress"],
        "warp"
    );
    report(&rig, &pusher, SectionState::Converged, None).await;
    assert_eq!(routing.get(EDGE, "naive", &lane).unwrap().state, PolicyState::Applied);
    assert_eq!(routing.get(EDGE, "naive", LANE_SERVICE).unwrap().state, PolicyState::Applied);
    lanes.disable(&grant.id, &ctx()).await.unwrap();
    let latest = rig.latest();
    let entry = &latest.document.egress.as_ref().unwrap()[&Protocol::Naive];
    assert_eq!(
        entry.document["lanes"].as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>(),
        ["svc:naive"]
    );
    assert_eq!(entry.document["chains"], json!({}));
    assert!(!latest.document.resources.iter().find(|item| item.reference == lane).unwrap().own_lane);
}

// test_routing_fleet_router.py: a router-less node must reject the operation and never
// receive a stale section its strict older protocol model could not parse.
#[tokio::test]
async fn older_node_refuses_remote_router_policy_and_filters_stale_sections() {
    let rig = Rig::new();
    configure(&rig);
    {
        let mut node = rig.node.state.lock().unwrap();
        node.identity.insert("capabilities".into(), json!(["generation.v1", "egress.v1"]));
        node.identity.remove("router");
        node.identity["protocols"]["naive"]["egress"]["router_attached"] = json!(false);
    }
    rig.link(false).await;
    let (routing, _, pusher, publisher) = services(&rig);
    pusher.tick().await.unwrap();
    routing
        .save(
            EDGE,
            "naive",
            &input(json!({"backend":"xray_router",
        "default_action":"egress","default_egress":"warp"})),
            None,
            LANE_SERVICE,
            &ctx(),
        )
        .unwrap();
    let refused = routing.apply(EDGE, "naive", 1, LANE_SERVICE, &ctx()).await.unwrap_err();
    assert_eq!((refused.status(), refused.code()), (422, Some("node_lacks_router")));
    assert_eq!(routing.attach(EDGE, "naive", &ctx()).await.unwrap_err().code(), Some("router_unavailable"));
    rig.env
        .database
        .transaction::<_, DbError>(|db| {
            let policy = store::get(db, EDGE, "naive", LANE_SERVICE).unwrap().unwrap();
            let document = json!({"schema":1,"default":{"action":"egress","egress":"warp"},"rules":[]});
            store::set_desired(
                db,
                &policy.id,
                Some(&json!({"backend":"xray_router","policy_id":policy.id,
            "policy_revision":1,"document":document,"digest":document_digest(&document),
            "companion":attach_document("naive")})),
                1,
            )
            .unwrap();
            publisher.publish(db, EDGE).unwrap();
            Ok(())
        })
        .unwrap();
    assert!(rig.latest().document.egress.is_none());
}

#[tokio::test]
async fn a_v06_node_refuses_lanes_and_relay_and_never_receives_schema_two() {
    let rig = Rig::new();
    configure(&rig);
    rig.node
        .state
        .lock()
        .unwrap()
        .identity
        .insert("capabilities".into(), json!(["generation.v1", "egress.v1", "egress.router.v1"]));
    rig.link(false).await;
    let (routing, lanes, pusher, publisher) = services(&rig);
    pusher.tick().await.unwrap();
    assert_eq!(routing.relay_enable(EDGE, 45443, &ctx()).await.unwrap_err().code(), Some("node_lacks_relay"));
    let (_, grant) = rig.provision(Protocol::Naive, "alice").await;
    assert_eq!(lanes.enable(&grant.id, &ctx()).await.unwrap_err().code(), Some("node_lacks_lanes"));
    rig.env.database.transaction::<_,DbError>(|db| {
        db.execute("UPDATE access_grants SET routing_lane='own' WHERE id=?",[&grant.id])?;
        let policy=store::upsert(db,EDGE,"naive",&input(json!({"backend":"xray_router"})),None,1,LANE_SERVICE).unwrap();
        let document=json!({"schema":2,"lanes":{"svc:naive":{"default":{"action":"direct","egress":null},"rules":[]}},"chains":{}});
        store::set_desired(db,&policy.id,Some(&json!({"backend":"xray_router","policy_id":policy.id,"policy_revision":1,"document":document,"digest":document_digest(&document)})),1).unwrap();
        RelayRegistry::desire(db,EDGE,true,45443,"edge.example",1).unwrap();publisher.publish(db,EDGE).unwrap();Ok(())
    }).unwrap();
    let latest = rig.latest();
    assert!(latest.document.egress.is_none());
    assert!(latest.document.relay.is_none());
    assert!(!latest.document.resources[0].own_lane);
}

#[tokio::test]
async fn relay_enable_and_accounts_are_published_and_confirmed_only_after_the_node_report() {
    let rig = Rig::new();
    configure(&rig);
    rig.link(false).await;
    let (routing, _, pusher, publisher) = services(&rig);
    pusher.tick().await.unwrap();
    let enabled = routing.relay_enable(EDGE, 45443, &ctx()).await.unwrap();
    assert_eq!(enabled["pending"], true);
    assert!(enabled["public_key"].is_null());
    let latest = rig.latest();
    let relay = latest.document.relay.unwrap();
    assert!(relay.enabled);
    assert!(relay.accounts.is_empty());
    let registry = RelayRegistry::new(rig.env.secrets.clone());
    rig.env
        .database
        .transaction::<_, DbError>(|db| {
            registry.issue(db, EDGE, MASTER, "direct", 1).unwrap();
            registry.issue(db, EDGE, MASTER, "warp", 1).unwrap();
            publisher.publish(db, EDGE).unwrap();
            Ok(())
        })
        .unwrap();
    let accounts = rig.latest().document.relay.unwrap().accounts;
    assert_eq!(accounts.len(), 2);
    rig.node.state.lock().unwrap().push_state = ReconcileState::Applying;
    pusher.tick().await.unwrap();
    let request = rig.node.state.lock().unwrap().pushes.last().unwrap().clone();
    for account in &accounts {
        assert!(request.secrets.contains_key(&account.credential_ref));
        assert!(!serde_json::to_string(&rig.link_row()).unwrap().contains(&request.secrets[&account.credential_ref]));
    }
    assert!(!rig.desired.relay_confirmed(EDGE, &accounts[0].email).unwrap());
    {
        let mut node = rig.node.state.lock().unwrap();
        node.report.reconcile_state = ReconcileState::Converged;
        node.push_state = ReconcileState::Converged;
        node.report.relay = Some(ObservedRelay {
            state: SectionState::Converged,
            enabled: true,
            port: Some(45443),
            server_name: Some("edge.example".into()),
            public_key: Some("public-key".into()),
            short_id: Some("0123abcd".into()),
            accounts: accounts.iter().map(|row| row.email.clone()).collect(),
            error: None,
        });
    }
    pusher.tick().await.unwrap();
    assert!(rig.desired.relay_confirmed(EDGE, &accounts[0].email).unwrap());
    rig.env
        .database
        .with_connection::<_, DbError>(|db| {
            assert_eq!(RelayRegistry::relay(db, EDGE).unwrap().unwrap()["public_key"], "public-key");
            Ok(())
        })
        .unwrap();
    let old = request.secrets.values().cloned().collect::<Vec<_>>();
    assert_eq!(routing.relay_rotate(EDGE, &ctx()).await.unwrap()["rotated"], 2);
    rig.node.state.lock().unwrap().push_state = ReconcileState::Applying;
    pusher.tick().await.unwrap();
    let fresh = rig.node.state.lock().unwrap().pushes.last().unwrap().clone();
    assert!(fresh.secrets.values().all(|value| !old.contains(value)));
}

#[tokio::test]
async fn a_linked_nodes_chain_waits_for_its_report_and_uses_the_confirmed_direct_account() {
    const EXIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let rig = Rig::new();
    configure(&rig);
    rig.link(false).await;
    let exit = rig.add_node(EXIT).await;
    exit.state.lock().unwrap().identity.insert("capabilities".into(), capabilities());
    let (routing, _, pusher, _) = services(&rig);
    pusher.tick().await.unwrap();
    routing.attach(EDGE, "naive", &ctx()).await.unwrap();
    report(&rig, &pusher, SectionState::Converged, None).await;
    routing.relay_enable(EXIT, 45443, &ctx()).await.unwrap();
    exit.state.lock().unwrap().push_state = ReconcileState::Applying;
    pusher.tick().await.unwrap();
    let public_key = "SbVKOEMjK0sJlbwg4akyBg5mL5TMmyGrv0IVjGtvJ0s";
    {
        let mut state = exit.state.lock().unwrap();
        state.report.reconcile_state = ReconcileState::Converged;
        state.push_state = ReconcileState::Converged;
        state.report.relay = Some(ObservedRelay {
            state: SectionState::Converged,
            enabled: true,
            port: Some(45443),
            server_name: Some("exit.example".into()),
            public_key: Some(public_key.into()),
            short_id: Some("0123abcd".into()),
            accounts: vec![],
            error: None,
        });
    }
    pusher.tick().await.unwrap();
    let targets = routing.targets().await.unwrap();
    let target = targets.iter().find(|target| target["node_id"] == EDGE && target["protocol"] == "naive").unwrap();
    let visible = target["exits"].as_array().unwrap().iter().find(|exit| exit["node_id"] == EXIT).unwrap();
    assert_eq!(visible["enabled"], true);
    assert_eq!(visible["online"], true);
    routing
        .save(
            EDGE,
            "naive",
            &input(json!({
                "backend":"xray_router","default_action":"egress","default_egress":format!("node:{EXIT}")
            })),
            Some(1),
            LANE_SERVICE,
            &ctx(),
        )
        .unwrap();
    let pending = routing.apply(EDGE, "naive", 2, LANE_SERVICE, &ctx()).await.unwrap_err();
    assert_eq!(pending.code(), Some("unsupported"));
    assert_eq!(pending.refusal().unwrap().compiled.as_ref().unwrap().reasons[0].code, "relay_credential_pending");
    exit.state.lock().unwrap().push_state = ReconcileState::Applying;
    pusher.tick().await.unwrap();
    let request = exit.state.lock().unwrap().pushes.last().unwrap().clone();
    let accounts = &request.generation.relay.as_ref().unwrap().accounts;
    assert_eq!(accounts.len(), 2);
    let direct = accounts.iter().find(|row| row.email.ends_with(":direct")).unwrap();
    let uuid = request.secrets[&direct.credential_ref].clone();
    {
        let mut state = exit.state.lock().unwrap();
        state.report.reconcile_state = ReconcileState::Converged;
        state.push_state = ReconcileState::Converged;
        state.report.relay = Some(ObservedRelay {
            state: SectionState::Converged,
            enabled: true,
            port: Some(45443),
            server_name: Some("exit.example".into()),
            public_key: Some(public_key.into()),
            short_id: Some("0123abcd".into()),
            accounts: vec![direct.email.clone()],
            error: None,
        });
    }
    pusher.tick().await.unwrap();
    assert!(
        rig.desired.relay_confirmed(EXIT, &direct.email).unwrap(),
        "confirmed direct account missing from observed relay: {:?}",
        rig.env.database.with_connection(|db| DesiredStore::observed_relay(db, EXIT)).unwrap()
    );
    let applied = routing.apply(EDGE, "naive", 2, LANE_SERVICE, &ctx()).await.unwrap();
    let document = applied.compiled.document.as_ref().unwrap();
    assert_eq!(document["chains"]["c1"]["exit"], "direct");
    let hop = &document["chains"]["c1"]["hops"][0];
    assert_eq!(hop["uuid"], uuid);
    assert_eq!(hop["public_key"], public_key);
    assert_eq!(hop["port"], 45443);
    assert_eq!(hop["address"], format!("{EXIT}.example"));
    assert!(!applied.compiled.redacted().to_string().contains(&uuid));
    assert!(!rig.audit("routing.policy.apply").to_string().contains(&uuid));
}

#[tokio::test]
async fn mieru_lane_readback_updates_the_central_share_template_and_restores_the_service_port() {
    let rig = Rig::new();
    configure(&rig);
    rig.link(false).await;
    let (_, lanes, pusher, _) = services(&rig);
    pusher.tick().await.unwrap();
    let (_, grant) = rig.provision(Protocol::Mieru, "phone").await;
    lanes.enable(&grant.id, &ctx()).await.unwrap();
    let lane_template = "mierus://{username}:{password}@mieru.example?port=46102&protocol=TCP&mtu=1400";
    rig.node.state.lock().unwrap().learned = object(json!({"share_template":lane_template}));
    pusher.tick().await.unwrap();
    let learned = rig.current_grant(&grant.id);
    assert!(learned.own_lane);
    assert_eq!(learned.options.dump()["share_template"], lane_template);
    lanes.disable(&grant.id, &ctx()).await.unwrap();
    let service_template = "mierus://{username}:{password}@mieru.example?port=8443&protocol=TCP&mtu=1400";
    rig.node.state.lock().unwrap().learned = object(json!({"share_template":service_template}));
    pusher.tick().await.unwrap();
    let returned = rig.current_grant(&grant.id);
    assert!(!returned.own_lane);
    assert_eq!(returned.options.dump()["share_template"], service_template);
}
