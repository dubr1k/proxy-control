//! Native routing-service boundaries that the old Python fleet tests exercised through app.state.
use super::*;
use crate::service::CentralManagement;
use crate::store;
use panel_core::db::Conn;
use panel_model::seams::{GenerationPublisher, SeamError};

const EDGE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
type Publications = Arc<Mutex<Vec<Value>>>;

fn identity(router: bool) -> Value {
    let mut capabilities = vec!["generation.v1", "egress.v1", "egress.mtproxy.v1"];
    if router {
        capabilities.push("egress.router.v1");
    }
    let mut value = json!({"capabilities": capabilities, "protocols": {
        "naive":{"egress":{"backend":"naive_native","revision":"native-r","mode":"direct","capabilities":["whole_direct","whole_warp","block_domain","block_cidr"],"providers":{"warp":{"reachable":true},"router":{"reachable":true}}}},
        "mtproxy":{"egress":{"backend":"mtproxy_native","revision":"telemt-r","mode":"direct","capabilities":["whole_direct"],"providers":{}}}
    }});
    if router {
        value["router"] = json!({"available":true,"capabilities":ROUTER_CAPABILITIES,"providers":{"warp":{"reachable":true}},"xray_version":"Xray 26.3.27","services":{"naive":{"revision":"router-r","applied_digest":document_digest(&router_direct_intent())}}});
    }
    value
}

fn remote_service(stand: &Stand, identity: &Value, managed: bool) -> (RoutingService, Publications) {
    stand.database.transaction::<_,panel_core::db::DbError>(|db| {
        panel_nodes::registry::insert(db,EDGE,"Edge","remote","panel",1).unwrap();
        db.execute("INSERT INTO node_links(node_id,panel_url,tls_verify,api_key_secret_id,identity_json,created_at,updated_at) VALUES(?,?,'verify','api-key',?,1,1)",panel_core::rusqlite::params![EDGE,"https://node.example",serde_json::to_string(identity).unwrap()])?;
        Ok(())
    }).unwrap();
    let publications = Arc::new(Mutex::new(Vec::new()));
    let recorded = publications.clone();
    let publisher: Arc<dyn GenerationPublisher> =
        Arc::new(move |db: &Conn, node: &str| -> Result<Option<i64>, SeamError> {
            let desired = store::desired_for_node(db, node).map_err(|error| Box::new(error) as SeamError)?;
            let mut recorded = lock(&recorded);
            recorded.push(Value::Object(desired));
            Ok(Some(recorded.len() as i64))
        });
    let managed: Arc<dyn CentralManagement> =
        Arc::new(move |_: &Conn| -> Result<Option<String>, SeamError> { Ok(managed.then(|| "central-master".into())) });
    let service = RoutingService::new(
        stand.database.clone(),
        Arc::new(FakeAdapters {
            naive: stand.naive.clone(),
            mieru: stand.mieru.clone(),
            mtproxy: FakeAdapter::new(Protocol::Mtproxy, true, stand.events.clone()),
        }),
        Arc::new(|_: &str| true),
        Some(publisher),
        Some(managed),
        stand.clock.clone(),
        stand.router.clone().map(|router| Arc::new(router) as Arc<dyn RoutingRouter>),
        None,
        "local-guid",
        "local.example",
        Arc::new(crate::lanes::local_only),
        None,
    );
    (service, publications)
}
fn online(stand: &Stand) {
    stand
        .database
        .transaction::<_, panel_core::db::DbError>(|db| {
            db.execute("UPDATE node_links SET status='online' WHERE node_id=?", [EDGE])?;
            Ok(())
        })
        .unwrap();
}
fn update_identity(stand: &Stand, identity: &Value) {
    stand
        .database
        .transaction::<_, panel_core::db::DbError>(|db| {
            db.execute(
                "UPDATE node_links SET identity_json=? WHERE node_id=?",
                panel_core::rusqlite::params![serde_json::to_string(identity).unwrap(), EDGE],
            )?;
            Ok(())
        })
        .unwrap();
}
fn remote<'a>(items: &'a [Map<String, Value>], protocol: &str) -> &'a Map<String, Value> {
    items.iter().find(|item| item["node_id"] == EDGE && item["protocol"] == protocol).unwrap()
}

#[tokio::test]
async fn targets_for_remote_node_from_identity_json() {
    let stand = stand("remote-targets", false);
    let (service, _) = remote_service(&stand, &identity(false), false);
    assert_eq!(remote(&service.targets().await.unwrap(), "naive")["reason"], "node_offline");
    online(&stand);
    let items = service.targets().await.unwrap();
    let naive = remote(&items, "naive");
    assert_eq!(naive["kind"], "remote");
    assert_eq!(naive["egress_v1"], true);
    assert_eq!(naive["backend"], "naive_native");
    assert_eq!(naive["providers"], json!({"warp":{"reachable":true},"router":{"reachable":true}}));
    assert!(naive["capabilities"].as_array().unwrap().contains(&json!("block_domain")));
    assert!(naive["reason"].is_null());
    assert_eq!(naive["mode"], "direct");
    assert_eq!(remote(&items, "mieru")["reason"], "protocol_disabled_on_node");
    assert_eq!(remote(&items, "mtproxy")["backend"], "mtproxy_native");
    let mut old = identity(false);
    old["capabilities"] = json!(["generation.v1"]);
    update_identity(&stand, &old);
    let items = service.targets().await.unwrap();
    assert_eq!(remote(&items, "naive")["egress_v1"], false);
    assert_eq!(remote(&items, "naive")["reason"], "node_lacks_egress_v1");
    let compiled = service.preview(EDGE, "naive", Some(warp()), LANE_SERVICE).await.unwrap();
    assert_eq!(compiled.status, CompileStatus::Unsupported);
    assert_eq!(compiled.reasons[0].code, "node_lacks_egress_v1");
}

#[tokio::test]
async fn remote_apply_router_policy_on_node_without_capability_is_422() {
    let stand = stand("old-remote-router", false);
    let (service, publications) = remote_service(&stand, &identity(false), false);
    online(&stand);
    let draft = input(json!({"backend":"xray_router","default_action":"egress","default_egress":"warp"}));
    service.save(EDGE, "naive", &draft, None, LANE_SERVICE, &context()).unwrap();
    assert_eq!(
        refusal(service.apply(EDGE, "naive", 1, LANE_SERVICE, &context()).await.unwrap_err()),
        (422, "node_lacks_router".into())
    );
    assert_eq!(refusal(service.attach(EDGE, "naive", &context()).await.unwrap_err()).1, "router_unavailable");
    assert!(lock(&publications).is_empty());
}

#[tokio::test]
async fn local_apply_is_refused_while_a_central_manages_the_node() {
    let stand = stand("managed-routing", false);
    let (service, _) = remote_service(&stand, &identity(false), true);
    service.save("local", "naive", &block(&["x.example"]), None, LANE_SERVICE, &context()).unwrap();
    assert_eq!(
        refusal(service.apply("local", "naive", 1, LANE_SERVICE, &context()).await.unwrap_err()),
        (409, "managed_by_central".into())
    );
    assert_eq!(item(&service.targets().await.unwrap(), "naive")["reason"], "managed_by_central");
    assert_eq!(service.preview("local", "naive", None, LANE_SERVICE).await.unwrap().status, CompileStatus::Supported);
    assert!(stand.naive.state().calls.is_empty());
}

#[tokio::test]
async fn remote_attach_apply_and_detach_publish_exact_companion_and_passthrough_sections() {
    let stand = stand("remote-sections", false);
    let mut identity = identity(true);
    let (service, publications) = remote_service(&stand, &identity, false);
    online(&stand);
    let attached = service.attach(EDGE, "naive", &context()).await.unwrap();
    assert_eq!(attached["policy"]["backend"], "xray_router");
    assert_eq!(attached["policy"]["state"], "applying");
    let first = lock(&publications)[0]["naive"].clone();
    assert_eq!(first["backend"], "xray_router");
    assert_eq!(first["document"], router_direct_intent());
    assert_eq!(first["companion"], attach_document("naive").unwrap());
    assert_eq!(first["passthrough"], true);
    identity["protocols"]["naive"]["egress"]["router_attached"] = json!(true);
    update_identity(&stand, &identity);
    let items = service.targets().await.unwrap();
    let target = remote(&items, "naive");
    assert_eq!(target["router"]["available"], true);
    assert_eq!(target["router"]["attached"], true);
    assert_eq!(target["backend"], "xray_router");
    let draft = input(
        json!({"default_action":"egress","default_egress":"warp","rules":[{"action":"block","match":{"geosites":["category-ads-all"]}}]}),
    );
    let saved = service.save(EDGE, "naive", &draft, Some(1), LANE_SERVICE, &context()).unwrap();
    let outcome = service.apply(EDGE, "naive", saved.revision, LANE_SERVICE, &context()).await.unwrap();
    assert_eq!(outcome.policy.state, PolicyState::Applying);
    assert_eq!(outcome.compiled.attach, attach_document("naive"));
    let second = lock(&publications)[1]["naive"].clone();
    assert_eq!(second["document"]["rules"][0]["geosites"], json!(["category-ads-all"]));
    assert_eq!(second["companion"], attach_document("naive").unwrap());
    assert!(second.get("passthrough").is_none());
    assert_eq!(second["digest"], document_digest(&second["document"]));
    let detached = service.detach(EDGE, "naive", &context()).await.unwrap();
    assert_eq!(detached["policy"]["backend"], "naive_native");
    let third = lock(&publications)[2]["naive"].clone();
    assert_eq!(third["document"], compiler::direct_document(Backend::NaiveNative));
    assert_eq!(third["companion"], router_direct_intent());
    assert_eq!(third["passthrough"], true);
    assert!(stand.events.lock().unwrap().is_empty(), "remote publication never touches local managers");
}
