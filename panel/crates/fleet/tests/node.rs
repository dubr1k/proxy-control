//! The unit parts of `test_fleet_v2_node_api.py` and `test_fleet_v2_post_merge_node.py`: what the
//! node answers, without the HTTP shell (gates, bodies and audit rows are covered by the Python
//! black-box tests against the `panel` binary).

mod support;

use std::sync::Arc;
use std::time::Duration;

use panel_fleet::node::guard::{require_unmanaged, GuardError, MANAGED_DETAIL};
use panel_fleet::node::models::CaptureRequest;
use panel_fleet::node::service::NodeResult;
use panel_fleet::node::NodeFailure;
use panel_model::fleet::PushRequest;
use panel_model::validate::Model;
use panel_secrets::secrets_store::SecretStore;
use serde_json::{json, Value};
use support::Node;

const NODE: &str = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";
const MASTER: &str = "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";

fn request(guid: &str, generation: i64, users: &[&str], master: &str, state: &str) -> PushRequest {
    let resources: Vec<Value> = users
        .iter()
        .map(|u| {
            json!({"ref": format!("grant:{u}"), "protocol": "naive", "runtime_username": u, "desired_state": state,
                   "credential_ref": format!("grant:{u}:1"), "credential_origin": "caller"})
        })
        .collect();
    let secrets: serde_json::Map<String, Value> = if state == "deleted" {
        serde_json::Map::new()
    } else {
        users.iter().map(|u| (format!("grant:{u}:1"), json!(format!("pw-{u}")))).collect()
    };
    PushRequest::validate(&json!({
        "expected_guid": guid,
        "generation": {"node_guid": NODE, "master_guid": master, "generation": generation,
                       "previous_generation": generation - 1, "created_at": 1, "created_by": "c",
                       "resources": resources},
        "secrets": secrets,
    }))
    .unwrap()
}

/// `_push(client, headers, guid, generation)`: accept, then apply with the deadline.
async fn push(node: &Node, request: PushRequest) -> NodeResult<(u16, Value)> {
    let accepted = node.node.accept(request).await?;
    node.node.apply_pushed(accepted.generation, |work| drop(tokio::spawn(work))).await
}

fn code(result: NodeResult<(u16, Value)>) -> (u16, String) {
    match result {
        Err(NodeFailure::Api(error)) => (error.status(), error.body()["code"].as_str().unwrap_or_default().to_string()),
        other => panic!("not a refusal: {other:?}"),
    }
}

#[tokio::test]
async fn identity_status_and_inventory_are_secret_free() {
    let node = Node::default_node();
    node.runtime.naive.seed("bob", "hunter2");
    let identity = node.node.identity().await.unwrap();
    assert_eq!(identity["api_version"], 2);
    assert_eq!(identity["protocols"]["naive"]["public_host"], "naive.example.com");
    let status = node.node.status().await.unwrap();
    assert!(status.get("versions").is_some());
    assert_eq!(status["versions"]["reason"], "version_agent_unavailable");
    let inventory = node.node.inventory().await.unwrap();
    let bob =
        inventory["protocols"]["naive"].as_array().unwrap().iter().find(|r| r["runtime_username"] == "bob").unwrap();
    assert_eq!(bob["ownership"], "local");
    assert!(!inventory.to_string().contains("hunter2"));
}

#[tokio::test]
async fn identity_reports_egress_v1_and_targets() {
    let node = Node::default_node();
    node.runtime.mieru.state().reachable = false;
    let identity = node.node.identity().await.unwrap();
    let capabilities: Vec<&str> =
        identity["capabilities"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    assert!(capabilities.contains(&"egress.v1") && capabilities.contains(&"egress.mtproxy.v1"));
    assert!(capabilities.contains(&"metrics.v1") && !capabilities.contains(&"egress.router.v1"));
    let naive = &identity["protocols"]["naive"]["egress"];
    assert_eq!(naive["backend"], "naive_native");
    assert!(naive["capabilities"].as_array().unwrap().contains(&json!("whole_warp")));
    assert_eq!(naive["providers"], json!({"warp": {"reachable": true}}));
    assert!(naive["applied_digest"].is_string() && naive["revision"].is_string() && naive["mode"] == "direct");
    assert_eq!(identity["protocols"]["mieru"]["egress"]["providers"], json!({"warp": {"reachable": false}}));
    assert_eq!(identity["protocols"]["mieru"]["egress"]["restart_required"], true);
    let mtproxy = &identity["protocols"]["mtproxy"]["egress"];
    assert_eq!((mtproxy["backend"].as_str(), mtproxy["mode"].as_str()), (Some("mtproxy_native"), Some("direct")));
    assert!(!identity.to_string().contains("socks5://"));
    // A manager that cannot answer contributes no target rather than failing the identity.
    node.runtime.naive.state().broken = true;
    let identity = node.node.identity().await.unwrap();
    assert!(identity["protocols"]["naive"]["egress"].is_null());
    assert_eq!(identity["protocols"]["naive"]["daemon"], "down");
    // Switched-off protocols are `off` and carry no target.
    assert_eq!(identity["protocols"]["amneziawg"]["daemon"], "off");
    assert!(identity["protocols"]["amneziawg"]["egress"].is_null());
}

#[tokio::test]
async fn push_applies_and_answers_with_observed() {
    let node = Node::default_node();
    let (status, body) = push(&node, request(NODE, 1, &["alice"], MASTER, "enabled")).await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        (body["observed"]["applied_generation"].as_i64(), body["observed"]["reconcile_state"].as_str()),
        (Some(1), Some("converged"))
    );
    assert!(node.runtime.naive.usernames().contains(&"alice".to_string()));
    assert_eq!(node.node.observed().await.unwrap()["applied_generation"], 1);
    assert_eq!(node.node.identity().await.unwrap()["master_guid"], MASTER);
}

#[tokio::test]
async fn push_conflicts_are_409_with_a_code() {
    let node = Node::default_node();
    assert_eq!(push(&node, request(NODE, 2, &["alice"], MASTER, "enabled")).await.unwrap().0, 200);
    assert_eq!(
        code(push(&node, request(NODE, 1, &["alice"], MASTER, "enabled")).await),
        (409, "stale_generation".into())
    );
    assert_eq!(code(push(&node, request(NODE, 2, &["zed"], MASTER, "enabled")).await), (409, "digest_conflict".into()));
    assert_eq!(
        code(push(&node, request(NODE, 3, &["alice"], &"o".repeat(36), "enabled")).await),
        (409, "foreign_master".into())
    );
    assert_eq!(
        code(push(&node, request(&"x".repeat(36), 3, &["alice"], MASTER, "enabled")).await),
        (409, "guid_mismatch".into())
    );
}

#[tokio::test]
async fn central_owned_users_refuse_local_mutation_and_leave_local_inventory() {
    let node = Node::default_node();
    push(&node, request(NODE, 1, &["alice"], MASTER, "enabled")).await.unwrap();
    let conn = node.database.connect().unwrap();
    let refusal = require_unmanaged(&conn, node.node.managed(), "naive", "alice").unwrap_err();
    assert!(matches!(refusal, GuardError::Managed));
    let error = refusal.to_api_error().unwrap();
    assert_eq!((error.status(), error.body()), (409, json!({"detail": MANAGED_DETAIL})));
    assert!(require_unmanaged(&conn, node.node.managed(), "naive", "bob").is_ok());
}

#[tokio::test]
async fn owner_unlinks_and_the_users_become_local() {
    let node = Node::default_node();
    push(&node, request(NODE, 1, &["alice"], MASTER, "enabled")).await.unwrap();
    assert_eq!(node.node.unlink().await.unwrap(), 1);
    assert!(node.node.identity().await.unwrap()["master_guid"].is_null());
    let inventory = node.node.inventory().await.unwrap();
    let alice =
        inventory["protocols"]["naive"].as_array().unwrap().iter().find(|r| r["runtime_username"] == "alice").unwrap();
    assert_eq!(alice["ownership"], "local");
}

#[tokio::test]
async fn a_push_landing_during_unlink_cannot_resurrect_managed_rows() {
    let node = Node::default_node();
    let gates: Vec<Arc<tokio::sync::Semaphore>> = (0..2).map(|_| Arc::new(tokio::sync::Semaphore::new(0))).collect();
    let entered = Arc::new(tokio::sync::Notify::new());
    {
        let mut naive = node.runtime.naive.state();
        naive.create_gates.insert("alice".into(), gates[0].clone());
        naive.create_gates.insert("zed".into(), gates[1].clone());
        naive.create_entered.insert("alice".into(), entered.clone());
    }
    let fleet = node.node.clone();
    let first = tokio::spawn({
        let fleet = fleet.clone();
        async move {
            let accepted = fleet.accept(request(NODE, 1, &["alice"], MASTER, "enabled")).await.unwrap();
            fleet.apply_pushed(accepted.generation, |work| drop(tokio::spawn(work))).await
        }
    });
    entered.notified().await; // generation 1 is inside the adapter, placeholder row written
    let unlinking = tokio::spawn({
        let fleet = fleet.clone();
        async move { fleet.unlink().await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!unlinking.is_finished(), "waiting for the reconcile, not racing it");
    let second = tokio::spawn({
        let fleet = fleet.clone();
        async move {
            let accepted = fleet.accept(request(NODE, 2, &["alice", "zed"], MASTER, "enabled")).await.unwrap();
            fleet.apply_pushed(accepted.generation, |work| drop(tokio::spawn(work))).await
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await; // accepted, queued behind the unlink
    gates[0].add_permits(1);
    assert_eq!(first.await.unwrap().unwrap().0, 200);
    assert_eq!(unlinking.await.unwrap().unwrap(), 1);
    gates[1].add_permits(1);
    assert_eq!(code(second.await.unwrap()), (409, "stale_generation".into()));
    assert!(node.node.identity().await.unwrap()["master_guid"].is_null());
    assert_eq!(node.node.observed().await.unwrap()["applied_generation"], 0);
    let inventory = node.node.inventory().await.unwrap();
    assert!(inventory["protocols"]["naive"].as_array().unwrap().iter().all(|r| r["ownership"] == "local"));
    assert!(!node.runtime.naive.usernames().contains(&"zed".to_string()));
}

#[tokio::test]
async fn status_reports_best_effort_traffic_per_protocol() {
    let node = Node::default_node();
    node.runtime.naive.seed("bob", "hunter2");
    node.runtime.naive.seed("eve", "hunter3");
    node.runtime.naive.set_traffic("bob", 10, 20);
    node.runtime.naive.set_traffic("eve", 1, 2);
    {
        use panel_protocols::api::TelemtApi as _;
        node.runtime.telemt.create_user("carl", None).await.unwrap();
    }
    node.runtime.telemt.state().users["carl"]["total_octets"] = json!(7);
    let protocols = node.node.status().await.unwrap()["protocols"].clone();
    assert_eq!(protocols["naive"]["traffic"], json!({"upload_bytes": 11, "download_bytes": 22, "total_bytes": 33}));
    assert_eq!(
        protocols["mtproxy"]["traffic"],
        json!({"upload_bytes": null, "download_bytes": null, "total_bytes": 7})
    );
    assert!(protocols["mieru"]["traffic"].is_null());
    node.runtime.naive.state().traffic_broken = true;
    assert!(node.node.status().await.unwrap()["protocols"]["naive"]["traffic"].is_null());
}

#[tokio::test]
async fn push_without_a_secret_store_is_a_coded_409_and_accepts_nothing() {
    let node = Node::default_node();
    node.node.reconciler().set_secrets(SecretStore::new(None));
    assert_eq!(
        code(push(&node, request(NODE, 1, &["alice"], MASTER, "enabled")).await),
        (409, "secret_store_disabled".into())
    );
    assert_eq!(node.node.observed().await.unwrap()["applied_generation"], 0);
    assert!(node.node.identity().await.unwrap()["master_guid"].is_null());
}

#[tokio::test]
async fn capture_unlink_and_versions_update() {
    let node = Node::default_node();
    node.runtime.naive.seed("bob", "hunter2");
    let capture =
        CaptureRequest::validate_body(&json!({"resources": [{"protocol": "naive", "runtime_username": "bob"}],
                                                        "purpose": "import"}))
        .unwrap();
    assert_eq!(node.node.capture(&capture).await.unwrap().body["credentials"]["naive:bob"], "hunter2");
    push(&node, request(NODE, 1, &["alice"], MASTER, "enabled")).await.unwrap();
    assert_eq!(node.node.unlink().await.unwrap(), 1);
    assert!(node.node.identity().await.unwrap()["master_guid"].is_null());
    assert!(node.runtime.naive.usernames().contains(&"alice".to_string()));
    // No version agent here: the agent's own error (502) passes through.
    for result in [node.node.update_version("telemt", "1.0", None).await, node.node.check_versions().await] {
        match result {
            Err(NodeFailure::Api(error)) => assert!(matches!(error.status(), 502 | 503)),
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn capture_answers_null_not_500_while_telemt_is_down() {
    let node = Node::default_node();
    node.runtime.telemt.state().access_down = true;
    let capture =
        CaptureRequest::validate_body(&json!({"resources": [{"protocol": "mtproxy", "runtime_username": "alice"}],
                                                        "purpose": "import"}))
        .unwrap();
    let answer = node.node.capture(&capture).await.unwrap();
    assert_eq!(answer.body, json!({"credentials": {"mtproxy:alice": null}, "unsupported": [], "refused": []}));
}

// -- test_fleet_v2_post_merge_node.py ---------------------------------------------------------------

#[tokio::test]
async fn only_a_superseded_generation_is_answered_stale() {
    let node = Node::default_node();
    let first = node.node.accept(request(NODE, 1, &[], MASTER, "enabled")).await.unwrap();
    node.node.accept(request(NODE, 2, &[], MASTER, "enabled")).await.unwrap();
    let answer = node.node.apply_pushed(first.generation, |work| drop(tokio::spawn(work))).await;
    match answer {
        Err(NodeFailure::Api(error)) => assert_eq!(
            (error.status(), error.body()),
            (409, json!({"detail": "superseded by a newer generation", "code": "stale_generation"}))
        ),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn capture_is_audited_and_answers_local_users_only_for_an_import() {
    let node = Node::default_node();
    node.runtime.naive.seed("local-bob", "hunter2");
    push(&node, request(NODE, 1, &["alice"], MASTER, "enabled")).await.unwrap();
    let body = json!({"resources": [{"protocol": "naive", "runtime_username": "alice"},
                                    {"protocol": "naive", "runtime_username": "local-bob"}]});
    let escrow = node.node.capture(&CaptureRequest::validate_body(&body).unwrap()).await.unwrap();
    assert_eq!(escrow.body["credentials"], json!({"naive:alice": "pw-alice"}));
    assert_eq!(escrow.body["refused"], json!(["naive:local-bob"]));
    let mut import = body.clone();
    import["purpose"] = json!("import");
    let imported = node.node.capture(&CaptureRequest::validate_body(&import).unwrap()).await.unwrap();
    assert_eq!(imported.body["credentials"], json!({"naive:alice": "pw-alice", "naive:local-bob": "hunter2"}));
    assert_eq!(imported.body["refused"], json!([]));
    let detail = panel_secrets::audit::detail_json(Some(&imported.audit));
    assert!(!detail.contains("hunter2") && !detail.contains("pw-alice"));
    assert!(detail.contains("\"purpose\": \"import\"") && detail.contains("\"naive:local-bob\""));
}

#[test]
fn capture_with_an_unknown_purpose_is_422() {
    let error = CaptureRequest::validate_body(&json!({"resources": [], "purpose": "steal"})).unwrap_err();
    assert_eq!(error.to_api_error().status(), 422);
}

#[tokio::test]
async fn a_slow_reconcile_is_answered_202_and_keeps_running() {
    let node = Node::default_node();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    node.runtime.naive.state().create_gates.insert("alice".into(), gate.clone());
    let accepted = node.node.accept(request(NODE, 1, &["alice"], MASTER, "enabled")).await.unwrap();
    let (status, body) = node
        .node
        .apply_with_deadline(accepted.generation, Duration::from_millis(50), |work| drop(tokio::spawn(work)))
        .await
        .unwrap();
    assert_eq!(status, 202);
    assert_eq!(body["observed"]["reconcile_state"], "applying");
    assert_eq!(body["credentials"], json!({}));
    gate.add_permits(1);
    for _ in 0..100 {
        if node.node.observed().await.unwrap()["reconcile_state"] == "converged" {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the background reconcile never converged");
}
