//! `panel/tests/test_fleet_v2_reconcile.py` and `test_fleet_v2_managed.py`, ported: the reconcile
//! over the real adapters and the memory doubles, the generation store.

mod support;

use indexmap::IndexMap;
use panel_fleet::node::managed::{Latest, ResourceUpdate};
use panel_fleet::node::reconcile::ReconcileError;
use panel_model::fleet::{
    CredentialOrigin, DesiredState, GenerationDocument, ObservedGeneration, PushRequest, Resource, ResourceOrigin,
    SCHEMA_VERSION,
};
use panel_model::validate::Model;
use panel_model::Protocol;
use serde_json::{json, Map, Value};
use support::Node;

const NODE: &str = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";
const MASTER: &str = "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";

/// The Python `world`: Telemt, NaiveProxy and Mieru adapters only, a local user `local-bob`.
fn world() -> Node {
    let node = Node::default_node();
    node.runtime.remove_adapter(Protocol::Amneziawg);
    node.runtime.remove_adapter(Protocol::Trusttunnel);
    node.runtime.naive.seed("local-bob", "pw");
    node
}

fn resource(protocol: &str, user: &str, state: &str, version: i64, options: Option<Value>, origin: &str) -> Value {
    let options = options.unwrap_or_else(|| if protocol == "mieru" { json!({"quotas": []}) } else { json!({}) });
    json!({"ref": format!("grant:{user}"), "protocol": protocol, "runtime_username": user, "desired_state": state,
           "credential_ref": format!("grant:{user}:{version}"), "credential_origin": origin, "options": options})
}

fn enabled(protocol: &str, user: &str) -> Value {
    resource(protocol, user, "enabled", 1, None, "caller")
}

fn push(generation: i64, resources: Vec<Value>, secrets: Value) -> PushRequest {
    PushRequest::validate(&json!({
        "expected_guid": NODE,
        "generation": {"node_guid": NODE, "master_guid": MASTER, "generation": generation,
                       "previous_generation": generation - 1, "created_at": 1, "created_by": "c",
                       "resources": resources},
        "secrets": secrets,
    }))
    .unwrap()
}

async fn accept(node: &Node, request: PushRequest) {
    node.node.accept(request).await.unwrap();
}

async fn apply(node: &Node, generation: i64) -> (ObservedGeneration, IndexMap<String, String>) {
    node.node.reconciler().apply(generation).await.unwrap()
}

fn states(observed: &ObservedGeneration) -> Map<String, Value> {
    observed.resources.iter().map(|r| (r.runtime_username.clone(), json!(r.state.as_str()))).collect()
}

fn is_managed(node: &Node, protocol: &str, user: &str) -> bool {
    let conn = node.database.connect().unwrap();
    node.node.managed().is_managed(&conn, protocol, user).unwrap()
}

fn rows(node: &Node) -> IndexMap<(String, String), Map<String, Value>> {
    let conn = node.database.connect().unwrap();
    node.node.managed().resources(&conn).unwrap()
}

fn without_time(mut observed: ObservedGeneration) -> ObservedGeneration {
    observed.reported_at = 0;
    observed
}

#[tokio::test]
async fn first_generation_creates_users_on_all_protocols_and_never_touches_local_ones() {
    let node = world();
    let request = push(
        1,
        vec![enabled("naive", "alice"), enabled("mieru", "carol"), enabled("mtproxy", "dave")],
        json!({"grant:alice:1": "pw-a", "grant:carol:1": "pw-c", "grant:dave:1": "0".repeat(32)}),
    );
    accept(&node, request).await;
    let (observed, credentials) = apply(&node, 1).await;
    assert_eq!(observed.reconcile_state.as_str(), "converged");
    assert_eq!(
        states(&observed),
        json!({"carol": "enabled", "dave": "enabled", "alice": "enabled"}).as_object().unwrap().clone()
    );
    // Telemt frames the caller's secret as a Fake-TLS one: that form travels back.
    assert_eq!(credentials, IndexMap::from([("grant:dave:1".to_string(), format!("ee{}", "0".repeat(32)))]));
    assert!(node.runtime.naive.usernames().contains(&"local-bob".to_string()));
    assert!(is_managed(&node, "naive", "alice") && !is_managed(&node, "naive", "local-bob"));
}

#[tokio::test]
async fn second_generation_disables_rotates_deletes_and_removes_orphans() {
    let node = world();
    accept(
        &node,
        push(
            1,
            vec![enabled("naive", "alice"), enabled("naive", "erin")],
            json!({"grant:alice:1": "pw-a", "grant:erin:1": "pw-e"}),
        ),
    )
    .await;
    apply(&node, 1).await;
    accept(
        &node,
        push(2, vec![resource("naive", "alice", "disabled", 2, None, "caller")], json!({"grant:alice:2": "pw-a2"})),
    )
    .await;
    let (observed, _) = apply(&node, 2).await;
    let users = node.runtime.naive.state().users.clone();
    assert_eq!(users["alice"]["enabled"], false);
    assert!(!users.contains_key("erin"), "the orphan of generation 1 is gone");
    assert_eq!(node.runtime.naive.password("alice").as_deref(), Some("pw-a2"));
    assert_eq!(Value::Object(states(&observed)), json!({"alice": "disabled"}));
}

#[tokio::test]
async fn explicit_deleted_state_removes_and_reports_missing() {
    let node = world();
    accept(&node, push(1, vec![enabled("naive", "alice")], json!({"grant:alice:1": "pw"}))).await;
    apply(&node, 1).await;
    accept(&node, push(2, vec![resource("naive", "alice", "deleted", 1, None, "caller")], json!({}))).await;
    let (observed, _) = apply(&node, 2).await;
    assert_eq!(observed.resources[0].state.as_str(), "missing");
    assert!(!node.runtime.naive.usernames().contains(&"alice".to_string()));
}

#[tokio::test]
async fn apply_is_idempotent_and_survives_a_restart_mid_apply() {
    let node = world();
    accept(
        &node,
        push(
            1,
            vec![enabled("naive", "alice"), enabled("naive", "erin")],
            json!({"grant:alice:1": "a", "grant:erin:1": "e"}),
        ),
    )
    .await;
    node.runtime.naive.state().lose_next = Some("create".into());
    let (observed, _) = apply(&node, 1).await;
    assert_eq!(observed.reconcile_state.as_str(), "converged");
    let (again, _) = apply(&node, 1).await;
    assert_eq!(without_time(again), without_time(observed));
    assert_eq!(node.runtime.naive.usernames().len(), 3, "alice, erin, local-bob — no duplicates");
}

#[tokio::test]
async fn one_failing_resource_marks_failed_but_applies_the_rest() {
    let node = world();
    node.runtime.mieru.state().broken = true;
    accept(
        &node,
        push(
            1,
            vec![enabled("naive", "alice"), enabled("mieru", "carol")],
            json!({"grant:alice:1": "a", "grant:carol:1": "c"}),
        ),
    )
    .await;
    let (observed, _) = apply(&node, 1).await;
    let states = states(&observed);
    assert_eq!((states["alice"].as_str(), states["carol"].as_str()), (Some("enabled"), Some("failed")));
    assert_eq!(observed.reconcile_state.as_str(), "failed");
}

#[tokio::test]
async fn manager_generated_credentials_come_back_in_the_result() {
    let node = world();
    accept(&node, push(1, vec![resource("mtproxy", "dave", "enabled", 1, None, "manager")], json!({}))).await;
    let (observed, credentials) = apply(&node, 1).await;
    assert_eq!(observed.resources[0].state.as_str(), "enabled");
    assert!(credentials["grant:dave:1"].starts_with("ee"));
    let (_, again) = apply(&node, 1).await;
    assert_eq!(again, credentials, "re-captured from the runtime, not regenerated");
}

#[tokio::test]
async fn present_but_unmanaged_runtime_user_is_never_adopted() {
    let node = world();
    node.runtime.naive.seed("mallory", "local-pw");
    accept(&node, push(1, vec![enabled("naive", "mallory")], json!({"grant:mallory:1": "pw"}))).await;
    let (observed, _) = apply(&node, 1).await;
    assert_eq!(observed.resources[0].state.as_str(), "failed");
    assert_eq!(observed.resources[0].error.as_deref(), Some("runtime user exists and is not managed"));
    assert_eq!(observed.reconcile_state.as_str(), "failed");
    assert_eq!(node.runtime.naive.calls(), Vec::<String>::new(), "never touched");
    assert!(node.runtime.naive.usernames().contains(&"mallory".to_string()));
    assert!(!is_managed(&node, "naive", "mallory"));
}

#[tokio::test]
async fn deleted_naming_an_unmanaged_runtime_user_is_untouched() {
    let node = world();
    node.runtime.naive.seed("mallory", "local-pw");
    accept(&node, push(1, vec![resource("naive", "mallory", "deleted", 1, None, "caller")], json!({}))).await;
    let (observed, _) = apply(&node, 1).await;
    assert_eq!(observed.resources[0].state.as_str(), "failed");
    assert_eq!(observed.resources[0].error.as_deref(), Some("runtime user exists and is not managed"));
    assert!(!node.runtime.naive.calls().contains(&"delete mallory".to_string()));
    assert!(node.runtime.naive.usernames().contains(&"mallory".to_string()));
}

#[tokio::test]
async fn recovers_from_a_crash_between_create_and_record() {
    let node = world();
    accept(&node, push(1, vec![enabled("naive", "frank")], json!({"grant:frank:1": "pw-f"}))).await;
    node.runtime.naive.seed("frank", "orphan-pw"); // adapter.create() had already mutated the runtime
    let conn = node.database.connect().unwrap();
    node.node
        .managed()
        .upsert_resource(
            &conn,
            &ResourceUpdate {
                protocol: "naive".into(),
                username: "frank".into(),
                reference: "grant:frank".into(),
                generation: 1,
                state: "failed".into(),
                error: Some("create in flight".into()),
                ..ResourceUpdate::default()
            },
        )
        .unwrap();
    conn.commit().unwrap();
    drop(conn);
    let (observed, _) = apply(&node, 1).await;
    assert_eq!(observed.resources[0].state.as_str(), "enabled");
    assert!(node.runtime.naive.calls().contains(&"rotate frank".to_string()));
    assert_eq!(node.runtime.naive.password("frank").as_deref(), Some("pw-f"));
}

#[tokio::test]
async fn duplicate_resource_in_one_generation_is_marked_failed_defence_in_depth() {
    let node = world();
    let first = Resource::validate(&enabled("naive", "alice")).unwrap();
    let second =
        Resource { reference: "grant:alice-2".into(), credential_ref: "grant:alice:2".into(), ..first.clone() };
    // A document that no longer validates (the store would refuse it): handed to the reconcile as
    // Python stubs `ManagedStore.latest`.
    let document = GenerationDocument {
        schema_version: SCHEMA_VERSION,
        node_guid: NODE.into(),
        master_guid: MASTER.into(),
        generation: 1,
        previous_generation: 0,
        created_at: 1,
        created_by: "c".into(),
        resources: vec![first, second],
        egress: None,
        relay: None,
    };
    let conn = node.database.connect().unwrap();
    conn.execute(
        "INSERT INTO managed_generations(generation,digest,master_guid,document_json,received_at,state)
         VALUES(1,'deadbeef',?,?,0,'received')",
        panel_core::rusqlite::params![MASTER, document.dump_json()],
    )
    .unwrap();
    conn.commit().unwrap();
    drop(conn);
    let latest = Latest {
        generation: 1,
        digest: "deadbeef".into(),
        state: "received".into(),
        master_guid: MASTER.into(),
        document,
    };
    let (observed, _) = node.node.reconciler().apply_stored(latest).await.unwrap();
    assert!(observed.resources.iter().all(|r| r.state.as_str() == "failed"));
    assert!(!node.runtime.naive.usernames().contains(&"alice".to_string()));
}

#[tokio::test]
async fn orphan_of_a_protocol_with_no_adapter_is_marked_failed_not_left_hanging() {
    let node = world();
    accept(&node, push(1, vec![enabled("mieru", "carol")], json!({"grant:carol:1": "pw-c"}))).await;
    apply(&node, 1).await;
    node.runtime.remove_adapter(Protocol::Mieru);
    accept(&node, push(2, vec![enabled("naive", "alice")], json!({"grant:alice:1": "pw-a"}))).await;
    let (observed, _) = apply(&node, 2).await;
    assert_eq!(Value::Object(states(&observed)), json!({"carol": "failed", "alice": "enabled"}));
    let carol = observed.resources.iter().find(|r| r.runtime_username == "carol").unwrap();
    assert!(carol.error.as_deref().unwrap().contains("not enabled on this node"));
    assert_eq!(observed.reconcile_state.as_str(), "failed");
}

#[tokio::test]
async fn options_drift_when_the_adapter_cannot_apply_a_pushed_option() {
    let node = world();
    accept(&node, push(1, vec![enabled("mtproxy", "dave")], json!({"grant:dave:1": "0".repeat(32)}))).await;
    apply(&node, 1).await;
    let drifted = resource("mtproxy", "dave", "enabled", 1, Some(json!({"expiration": 999})), "caller");
    accept(&node, push(2, vec![drifted], json!({}))).await;
    let (observed, _) = apply(&node, 2).await;
    assert_eq!(observed.resources[0].state.as_str(), "drifted");
    assert_eq!(observed.reconcile_state.as_str(), "converged", "drift is reported, not a failure");
}

#[tokio::test]
async fn option_drift_is_reported_without_reenabling_a_suspended_resource() {
    let node = world();
    accept(&node, push(1, vec![enabled("mtproxy", "dave")], json!({"grant:dave:1": "0".repeat(32)}))).await;
    apply(&node, 1).await;
    let drifted = resource("mtproxy", "dave", "disabled", 1, Some(json!({"expiration": 999})), "caller");
    accept(&node, push(2, vec![drifted], json!({}))).await;
    let (observed, _) = apply(&node, 2).await;
    assert_eq!(node.runtime.telemt.state().users["dave"]["enabled"], false);
    // As in the archived node: keep suspension effective without hiding an unapplied option.
    assert_eq!(observed.resources[0].state.as_str(), "drifted");
}

#[tokio::test]
async fn converged_generation_rechecks_validity_without_a_new_central_generation() {
    let node = world();
    let mut timed = enabled("naive", "alice");
    timed["valid_from"] = json!(1_800_000_001);
    timed["valid_until"] = json!(1_800_000_002);
    accept(&node, push(1, vec![timed], json!({"grant:alice:1": "pw"}))).await;
    apply(&node, 1).await;
    assert_eq!(node.runtime.naive.state().users["alice"]["enabled"], false);
    node.clock.set(1_800_000_001.0);
    node.node.reconciler().run_pending().await.unwrap();
    assert_eq!(node.runtime.naive.state().users["alice"]["enabled"], true);
    node.clock.set(1_800_000_002.0);
    node.node.reconciler().run_pending().await.unwrap();
    assert_eq!(node.runtime.naive.state().users["alice"]["enabled"], false);
    assert_eq!(support::table(&node.database, "SELECT generation FROM managed_generations")[0]["generation"], 1);
}

#[tokio::test]
async fn run_pending_re_applies_a_generation_that_never_converged() {
    let node = world();
    accept(&node, push(1, vec![enabled("naive", "alice")], json!({"grant:alice:1": "pw"}))).await;
    node.node.reconciler().run_pending().await.unwrap();
    let conn = node.database.connect().unwrap();
    assert_eq!(node.node.managed().latest(&conn).unwrap().unwrap().state, "converged");
    assert!(node.runtime.naive.usernames().contains(&"alice".to_string()));
}

#[tokio::test]
async fn one_resource_create_failure_leaves_siblings_applied() {
    let node = world();
    node.runtime.naive.state().create_fails.push("erin".into());
    accept(
        &node,
        push(
            1,
            vec![enabled("naive", "alice"), enabled("naive", "erin")],
            json!({"grant:alice:1": "a", "grant:erin:1": "e"}),
        ),
    )
    .await;
    let (observed, _) = apply(&node, 1).await;
    let states = states(&observed);
    assert_eq!((states["alice"].as_str(), states["erin"].as_str()), (Some("enabled"), Some("failed")));
    assert_eq!(observed.reconcile_state.as_str(), "failed");
}

#[tokio::test]
async fn store_secrets_is_idempotent_on_a_repeat_push() {
    let node = world();
    let request = push(1, vec![enabled("naive", "alice")], json!({"grant:alice:1": "pw"}));
    accept(&node, request.clone()).await;
    accept(&node, request).await;
    let count =
        support::table(&node.database, "SELECT count(*) AS n FROM secret_versions WHERE secret_id='grant:alice'");
    assert_eq!(count[0]["n"], 1);
    let (observed, _) = apply(&node, 1).await;
    assert_eq!(observed.reconcile_state.as_str(), "converged");
    let (again, _) = apply(&node, 1).await;
    assert_eq!(without_time(again), without_time(observed));
    assert_eq!(node.runtime.naive.calls().iter().filter(|call| *call == "create alice").count(), 1);
}

fn imported(protocol: &str, user: &str, state: &str) -> Value {
    let mut value = resource(protocol, user, state, 1, None, "caller");
    value["origin"] = json!("imported");
    value
}

#[tokio::test]
async fn imported_resource_adopts_an_existing_unmanaged_runtime_user_untouched() {
    let node = world();
    node.runtime.naive.seed("bob", "hunter2");
    node.runtime.naive.seed("mallory", "local-pw");
    accept(
        &node,
        push(
            1,
            vec![imported("naive", "bob", "enabled"), enabled("naive", "mallory")],
            json!({"grant:bob:1": "hunter2", "grant:mallory:1": "pw"}),
        ),
    )
    .await;
    let (observed, _) = apply(&node, 1).await;
    assert_eq!(Value::Object(states(&observed)), json!({"bob": "enabled", "mallory": "failed"}));
    assert_eq!(node.runtime.naive.calls(), Vec::<String>::new(), "adoption changes nothing on the runtime");
    assert_eq!(node.runtime.naive.password("bob").as_deref(), Some("hunter2"));
    assert!(is_managed(&node, "naive", "bob") && !is_managed(&node, "naive", "mallory"));
    assert_eq!(rows(&node)[&("naive".to_string(), "bob".to_string())]["credential_ref"], "grant:bob:1");
    accept(&node, push(2, vec![imported("naive", "bob", "disabled")], json!({}))).await;
    let (observed, _) = apply(&node, 2).await;
    assert_eq!(observed.resources[0].state.as_str(), "disabled");
    assert!(node.runtime.naive.calls().contains(&"enabled bob false".to_string()));
}

#[tokio::test]
async fn deleted_imported_resource_never_adopts_and_deletes_in_one_step() {
    let node = world();
    node.runtime.naive.seed("bob", "hunter2");
    accept(&node, push(1, vec![imported("naive", "bob", "deleted")], json!({}))).await;
    let (observed, _) = apply(&node, 1).await;
    assert_eq!(observed.resources[0].state.as_str(), "failed");
    assert!(!node.runtime.naive.calls().contains(&"delete bob".to_string()));
    assert!(node.runtime.naive.usernames().contains(&"bob".to_string()));
}

#[tokio::test]
async fn create_reports_what_the_runtime_taught_about_the_link() {
    let node = world();
    {
        let mut telemt = node.runtime.telemt.state();
        telemt.public_host = "proxy.node.example".into();
        telemt.public_port = 8443;
    }
    let request = push(
        1,
        vec![enabled("mtproxy", "dave"), enabled("mieru", "carol"), enabled("naive", "alice")],
        json!({"grant:dave:1": "0".repeat(32), "grant:carol:1": "pw-c", "grant:alice:1": "pw-a"}),
    );
    accept(&node, request).await;
    let (observed, credentials) = apply(&node, 1).await;
    let learned: Map<String, Value> = observed
        .resources
        .iter()
        .map(|r| {
            (
                r.runtime_username.clone(),
                Value::Object(r.learned.iter().map(|(k, v)| (k.clone(), v.to_value())).collect()),
            )
        })
        .collect();
    assert_eq!(learned["dave"], json!({"host": "proxy.node.example", "port": 8443}));
    assert!(learned["carol"]["share_template"]
        .as_str()
        .unwrap()
        .starts_with("mierus://{username}:{password}@mieru.example.com"));
    assert_eq!(learned["alice"], json!({}), "NaiveProxy's host is panel configuration, not learned");
    assert_eq!(credentials["grant:dave:1"], format!("ee{}", "0".repeat(32)));
    let conn = node.database.connect().unwrap();
    let again = node.node.managed().observed(&conn).unwrap().unwrap();
    drop(conn);
    assert_eq!(
        again.resources.iter().map(|r| r.learned.clone()).collect::<Vec<_>>(),
        observed.resources.iter().map(|r| r.learned.clone()).collect::<Vec<_>>()
    );
    accept(
        &node,
        push(
            2,
            vec![resource("mtproxy", "dave", "enabled", 2, None, "caller")],
            json!({"grant:dave:2": "1".repeat(32)}),
        ),
    )
    .await;
    let (observed, credentials) = apply(&node, 2).await;
    let dave = observed.resources.iter().find(|r| r.runtime_username == "dave").unwrap();
    assert_eq!(dave.learned.get("host").map(|v| v.to_value()), Some(json!("proxy.node.example")));
    assert_eq!(dave.learned.get("port").map(|v| v.to_value()), Some(json!(8443)));
    assert_eq!(credentials["grant:dave:2"], format!("ee{}", "1".repeat(32)));
}

#[tokio::test]
async fn a_missing_row_lingers_for_repeat_reports_and_never_claims_a_new_local_user() {
    let node = world();
    accept(&node, push(1, vec![enabled("naive", "alice")], json!({"grant:alice:1": "pw"}))).await;
    apply(&node, 1).await;
    accept(&node, push(2, vec![resource("naive", "alice", "deleted", 1, None, "caller")], json!({}))).await;
    let (observed, _) = apply(&node, 2).await;
    assert_eq!(observed.resources.iter().map(|r| r.state.as_str()).collect::<Vec<_>>(), ["missing"]);
    assert_eq!(rows(&node)[&("naive".to_string(), "alice".to_string())]["state"], "missing");
    assert!(!is_managed(&node, "naive", "alice"), "the name is the node's again");
    let conn = node.database.connect().unwrap();
    assert!(node.node.managed().owned(&conn).unwrap().is_empty());
    drop(conn);
    let (again, _) = apply(&node, 2).await;
    assert_eq!(again.resources.iter().map(|r| r.state.as_str()).collect::<Vec<_>>(), ["missing"]);
    node.runtime.naive.seed("alice", "local-pw");
    accept(&node, push(3, vec![], json!({}))).await;
    let (observed, _) = apply(&node, 3).await;
    assert!(observed.resources.is_empty());
    assert_eq!(node.runtime.naive.password("alice").as_deref(), Some("local-pw"));
    assert!(rows(&node).is_empty());
    accept(
        &node,
        push(4, vec![resource("naive", "alice", "enabled", 2, None, "caller")], json!({"grant:alice:2": "central-pw"})),
    )
    .await;
    let (observed, _) = apply(&node, 4).await;
    assert_eq!(observed.resources.iter().map(|r| r.state.as_str()).collect::<Vec<_>>(), ["failed"]);
    assert_eq!(node.runtime.naive.password("alice").as_deref(), Some("local-pw"));
}

fn regrant() -> Value {
    json!({"ref": "grant:alice-2", "protocol": "naive", "runtime_username": "alice", "desired_state": "enabled",
           "credential_ref": "grant:alice-2:1", "credential_origin": "caller", "options": {}})
}

fn refs(observed: &ObservedGeneration) -> Vec<(String, String)> {
    observed.resources.iter().map(|r| (r.reference.clone(), r.state.as_str().to_string())).collect()
}

#[tokio::test]
async fn a_regrant_under_a_new_ref_retires_the_missing_row_and_still_respects_a_local_user() {
    let node = world();
    accept(&node, push(1, vec![enabled("naive", "alice")], json!({"grant:alice:1": "pw"}))).await;
    apply(&node, 1).await;
    accept(&node, push(2, vec![resource("naive", "alice", "deleted", 1, None, "caller")], json!({}))).await;
    apply(&node, 2).await;
    node.runtime.naive.seed("alice", "local-pw");
    accept(&node, push(3, vec![regrant()], json!({"grant:alice-2:1": "central-pw"}))).await;
    let (observed, _) = apply(&node, 3).await;
    assert_eq!(refs(&observed), [("grant:alice-2".to_string(), "failed".to_string())]);
    assert_eq!(node.runtime.naive.password("alice").as_deref(), Some("local-pw"));
    assert!(rows(&node).is_empty());
    node.runtime.naive.state().users.shift_remove("alice"); // the owner removes the local user
    let (observed, _) = apply(&node, 3).await;
    assert_eq!(refs(&observed), [("grant:alice-2".to_string(), "enabled".to_string())]);
    assert_eq!(node.runtime.naive.password("alice").as_deref(), Some("central-pw"));
}

#[tokio::test]
async fn a_regrant_under_a_new_ref_is_owned_under_that_ref_after_the_apply() {
    let node = world();
    accept(&node, push(1, vec![enabled("naive", "alice")], json!({"grant:alice:1": "pw"}))).await;
    apply(&node, 1).await;
    accept(&node, push(2, vec![resource("naive", "alice", "deleted", 1, None, "caller")], json!({}))).await;
    apply(&node, 2).await;
    accept(&node, push(3, vec![regrant()], json!({"grant:alice-2:1": "central-pw"}))).await;
    let (observed, _) = apply(&node, 3).await;
    assert_eq!(refs(&observed), [("grant:alice-2".to_string(), "enabled".to_string())]);
    let row = rows(&node)[&("naive".to_string(), "alice".to_string())].clone();
    assert_eq!((row["ref"].as_str(), row["state"].as_str()), (Some("grant:alice-2"), Some("enabled")));
    assert!(is_managed(&node, "naive", "alice"));
    let (again, _) = apply(&node, 3).await;
    assert_eq!(refs(&again), [("grant:alice-2".to_string(), "enabled".to_string())]);
    assert_eq!(node.runtime.naive.password("alice").as_deref(), Some("central-pw"));
}

#[tokio::test]
async fn apply_of_an_older_generation_is_superseded() {
    let node = world();
    accept(&node, push(1, vec![], json!({}))).await;
    accept(&node, push(2, vec![], json!({}))).await;
    assert!(matches!(node.node.reconciler().apply(1).await, Err(ReconcileError::Superseded(1))));
}

// -- test_fleet_v2_managed.py ---------------------------------------------------------------------

fn document(generation: i64, master: &str, users: &[&str]) -> GenerationDocument {
    GenerationDocument::validate(&json!({
        "node_guid": NODE, "master_guid": master, "generation": generation,
        "previous_generation": (generation - 1).max(0), "created_at": 1, "created_by": "x",
        "resources": users.iter().map(|u| json!({"ref": format!("grant:{u}"), "protocol": "naive",
            "runtime_username": u, "desired_state": "enabled", "credential_ref": format!("grant:{u}:1"),
            "credential_origin": "caller"})).collect::<Vec<_>>(),
    }))
    .unwrap()
}

fn code(result: Result<(), panel_fleet::node::managed::AcceptError>) -> String {
    match result {
        Err(panel_fleet::node::managed::AcceptError::Conflict(conflict)) => conflict.code.as_str().to_string(),
        other => panic!("not a conflict: {other:?}"),
    }
}

#[test]
fn accept_records_master_and_rejects_lower_same_digest_and_foreign() {
    let node = Node::default_node();
    let managed = node.node.managed().clone();
    node.database
        .transaction(|db| {
            let accept = |doc: &GenerationDocument, guid: &str| managed.accept(db, doc, &doc.canonical_digest(), guid);
            accept(&document(2, MASTER, &["alice"]), NODE).unwrap();
            assert_eq!(managed.master_guid(db).unwrap().as_deref(), Some(MASTER));
            accept(&document(2, MASTER, &["alice"]), NODE).unwrap(); // the idempotent repeat
            assert_eq!(code(accept(&document(1, MASTER, &["alice"]), NODE)), "stale_generation");
            assert_eq!(code(accept(&document(2, MASTER, &["bob"]), NODE)), "digest_conflict");
            assert_eq!(code(accept(&document(3, &"o".repeat(36), &["alice"]), NODE)), "foreign_master");
            assert_eq!(code(accept(&document(3, MASTER, &["alice"]), &"o".repeat(36))), "guid_mismatch");
            Ok::<(), panel_core::db::DbError>(())
        })
        .unwrap();
}

#[test]
fn resources_ownership_observed_and_unlink() {
    let node = Node::default_node();
    let managed = node.node.managed().clone();
    node.database
        .transaction(|db| {
            let doc = document(1, MASTER, &["alice"]);
            managed.accept(db, &doc, &doc.canonical_digest(), NODE).unwrap();
            managed
                .upsert_resource(
                    db,
                    &ResourceUpdate {
                        protocol: "naive".into(),
                        username: "alice".into(),
                        reference: "grant:alice".into(),
                        generation: 1,
                        state: "enabled".into(),
                        ..ResourceUpdate::default()
                    },
                )
                .unwrap();
            assert!(
                managed.is_managed(db, "naive", "alice").unwrap() && !managed.is_managed(db, "naive", "bob").unwrap()
            );
            managed.set_state(db, 1, "converged").unwrap();
            let observed = managed.observed(db).unwrap().unwrap();
            assert_eq!((observed.applied_generation, observed.reconcile_state.as_str()), (1, "converged"));
            assert_eq!(observed.resources.iter().map(|r| r.runtime_username.as_str()).collect::<Vec<_>>(), ["alice"]);
            assert_eq!(managed.unlink(db).unwrap(), 1);
            assert_eq!(managed.master_guid(db).unwrap(), None);
            assert!(!managed.is_managed(db, "naive", "alice").unwrap());
            assert!(managed.latest(db).unwrap().is_none());
            Ok::<(), panel_core::db::DbError>(())
        })
        .unwrap();
}

#[test]
fn stored_documents_are_pydantic_dumps() {
    // `model_dump_json()`: every default in, declaration order (`lane`, `egress`, `relay` as null).
    let doc = document(1, MASTER, &["alice"]);
    assert_eq!(
        doc.dump_json(),
        concat!(
            r#"{"schema_version":1,"node_guid":"nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn","master_guid":"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm","#,
            r#""generation":1,"previous_generation":0,"created_at":1,"created_by":"x","resources":[{"ref":"grant:alice","#,
            r#""protocol":"naive","runtime_username":"alice","desired_state":"enabled","credential_ref":"grant:alice:1","#,
            r#""credential_origin":"caller","origin":"provisioned","options":{},"valid_from":null,"valid_until":null,"#,
            r#""lane":null}],"egress":null,"relay":null}"#
        )
    );
    let _ = (CredentialOrigin::Caller, DesiredState::Enabled, ResourceOrigin::Provisioned);
}
