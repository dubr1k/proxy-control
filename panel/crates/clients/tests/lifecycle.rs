//! The grant lifecycle, the domain writer and the access enforcer at service level:
//! `test_grant_lifecycle.py`, `test_access_enforcement.py` (local parts) and the unit-level
//! parts of `test_fleet_v2_provisioning_remote.py` (the pusher's calls made directly).

mod common;

use std::collections::HashSet;

use common::{ctx, intent, intent_on, Env, Fault};
use panel_clients::store::{self, GrantUpdate};
use panel_clients::{AccessEnforcer, ClientsError};
use panel_core::db::DbError;
use panel_model::clients::{GrantDesiredState, GrantObservedState};
use panel_model::fleet::ObservedGeneration;
use panel_model::{Model as _, Protocol};
use serde_json::{json, Map};

async fn local(env: &Env, valid_from: Option<i64>, valid_until: Option<i64>) -> (String, String) {
    let person = env.clients.create_client("A", &ctx()).unwrap().id;
    let mut wanted = intent(Protocol::Naive, "alice");
    wanted.valid_from = valid_from;
    wanted.valid_until = valid_until;
    let operation = env.provisioning.start(&person, vec![wanted], &ctx()).await.unwrap();
    env.provisioning.run(&operation).await.unwrap();
    let grant = env.grants(&person)[0].id.clone();
    (person, grant)
}

fn enabled(env: &Env) -> bool {
    env.fake(Protocol::Naive).enabled("alice").unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_grant_lifecycle_reaches_the_manager_and_is_audited() {
    let env = Env::new("local");
    let (_, grant) = local(&env, None, None).await;
    env.lifecycle.set_enabled(&grant, false, &ctx()).await.unwrap();
    assert!(!enabled(&env));
    let before = env.fake(Protocol::Naive).users.lock().unwrap()["alice"].password.clone();
    let rotated = env.lifecycle.rotate(&grant, &ctx()).await.unwrap();
    assert_ne!(env.fake(Protocol::Naive).users.lock().unwrap()["alice"].password, before);
    // Rotation keeps a disabled grant disabled; exactly one live version remains.
    assert_eq!(rotated.desired_state, GrantDesiredState::Disabled);
    assert_eq!(rotated.secret_ref.as_ref().unwrap().version, 2);
    assert_eq!(env.secret_states(&grant), [(1, "revoked".to_string()), (2, "active".to_string())]);
    let enabled_again = env.lifecycle.set_enabled(&grant, true, &ctx()).await.unwrap();
    assert_eq!(enabled_again.desired_state, GrantDesiredState::Enabled);
    assert!(enabled(&env));
    env.lifecycle.delete(&grant, &ctx()).await.unwrap();
    assert!(env.fake(Protocol::Naive).names().is_empty());
    // Purged at once: the name is free, every version revoked.
    assert_eq!(env.count(&format!("SELECT count(*) FROM access_grants WHERE id='{grant}'")), 0);
    assert!(env.secret_states(&grant).iter().all(|(_, state)| state == "revoked"));
    let actions: HashSet<String> = env.actions().into_iter().collect();
    for action in ["grant.disable", "grant.rotate", "grant.enable", "grant.delete"] {
        assert!(actions.contains(action), "{action}");
    }
    assert!(matches!(env.lifecycle.delete(&grant, &ctx()).await, Err(ClientsError::NotFound(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_delete_of_an_account_already_gone_still_purges_the_row() {
    let env = Env::new("gone");
    let (_, grant) = local(&env, None, None).await;
    env.fake(Protocol::Naive).users.lock().unwrap().clear();
    env.lifecycle.delete(&grant, &ctx()).await.unwrap();
    assert_eq!(env.count("SELECT count(*) FROM access_grants"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_lifecycle_and_adoption_refuse_a_central_owned_account_before_any_adapter_call() {
    let env = Env::new("managed");
    env.fake(Protocol::Naive).seed("bob", "pw-bob");
    let grant = env.facade.touch_import(Protocol::Naive, "bob", true, &Map::new(), &ctx()).unwrap();
    env.database
        .transaction(|db| {
            db.execute(
                "INSERT INTO managed_resources(protocol,runtime_username,ref,generation,state,updated_at)
                 VALUES('naive','bob','grant:bob',1,'enabled',1)",
                [],
            )?;
            Ok::<_, DbError>(())
        })
        .unwrap();
    env.fake(Protocol::Naive).calls.lock().unwrap().clear();
    assert!(matches!(env.lifecycle.set_enabled(&grant.id, false, &ctx()).await, Err(ClientsError::ManagedByCentral)));
    assert!(matches!(env.lifecycle.rotate(&grant.id, &ctx()).await, Err(ClientsError::ManagedByCentral)));
    assert!(matches!(env.lifecycle.delete(&grant.id, &ctx()).await, Err(ClientsError::ManagedByCentral)));
    assert!(matches!(env.clients.capture_credential(&grant.id, &ctx()).await, Err(ClientsError::ManagedByCentral)));
    assert!(matches!(env.clients.adopt_credential(&grant.id, true, &ctx()).await, Err(ClientsError::ManagedByCentral)));
    assert!(env.fake(Protocol::Naive).calls.lock().unwrap().is_empty(), "the manager must not be reached");
    let row = env.database.with_connection(|db| store::grant(db, &grant.id)).unwrap();
    assert_eq!((row.desired_state, row.secret_ref), (GrantDesiredState::Enabled, None));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adopting_an_imported_grant_captures_or_rotates_only_when_allowed() {
    let env = Env::new("adopt");
    env.fake(Protocol::Naive).seed("alice", "naive-password-01");
    env.fake(Protocol::Mieru).seed("alice", "mieru-password-01");
    let naive = env.facade.touch_import(Protocol::Naive, "alice", true, &Map::new(), &ctx()).unwrap();
    let mieru = env
        .facade
        .touch_import(Protocol::Mieru, "alice", true, &json!({"quotas": []}).as_object().unwrap().clone(), &ctx())
        .unwrap();
    let captured = env.clients.adopt_credential(&naive.id, false, &ctx()).await.unwrap();
    assert!(captured.secret_ref.is_some());
    assert_eq!(env.facade.credential(Protocol::Naive, "alice").unwrap(), b"naive-password-01");
    match env.clients.adopt_credential(&mieru.id, false, &ctx()).await {
        Err(ClientsError::Conflict(message)) => assert!(message.contains("requires rotation")),
        other => panic!("{other:?}"),
    }
    let rotated = env.clients.adopt_credential(&mieru.id, true, &ctx()).await.unwrap();
    assert!(rotated.secret_ref.is_some());
    assert_ne!(env.fake(Protocol::Mieru).users.lock().unwrap()["alice"].password, b"mieru-password-01");
    assert!(matches!(env.clients.adopt_credential(&mieru.id, true, &ctx()).await, Err(ClientsError::Conflict(_))));
    let actions = env.actions();
    assert!(actions.contains(&"grant.credential.capture".into()) && actions.contains(&"grant.credential.adopt".into()));
}

// --- access enforcement (local) -------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_suspension_is_pending_until_runtime_readback_and_retries() {
    let env = Env::new("pending");
    let enforcer = AccessEnforcer::new(env.clients.clone(), None);
    let (person, _) = local(&env, None, None).await;
    env.clients.set_state(&person, "suspended", &ctx()).unwrap();
    assert_eq!(env.grants(&person)[0].observed_state, GrantObservedState::Pending);
    env.fake(Protocol::Naive).fault("disable", Fault::Fail);
    enforcer.tick(false).await;
    assert_eq!(env.grants(&person)[0].observed_state, GrantObservedState::Pending);
    assert!(enabled(&env));
    env.fake(Protocol::Naive).clear_faults();
    enforcer.tick(false).await;
    assert!(!enabled(&env));
    let observed = env.grants(&person)[0].clone();
    assert_eq!(
        (observed.observed_state, observed.desired_state),
        (GrantObservedState::Disabled, GrantDesiredState::Enabled)
    );
    env.clients.set_state(&person, "active", &ctx()).unwrap();
    enforcer.tick(false).await;
    assert!(enabled(&env));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_provisioning_finishes_disabled_outside_validity_window() {
    for (from, until) in [(None, Some(1)), (Some(9_999_999_999), None)] {
        let env = Env::new("window");
        let (person, _) = local(&env, from, until).await;
        assert!(!enabled(&env));
        assert_eq!(env.grants(&person)[0].observed_state, GrantObservedState::Disabled);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_clock_transition_enables_then_expires_without_request() {
    let env = Env::new("clock");
    let enforcer = AccessEnforcer::new(env.clients.clone(), None);
    let (person, _) = local(&env, Some(9_999_999_998), Some(9_999_999_999)).await;
    env.clock.set(9_999_999_998.0);
    enforcer.tick(false).await;
    assert!(enabled(&env));
    env.clock.set(9_999_999_999.0);
    enforcer.tick(false).await;
    assert!(!enabled(&env));
    assert_eq!(env.grants(&person)[0].desired_state, GrantDesiredState::Enabled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_enable_cannot_bypass_suspension_or_expiry() {
    let env = Env::new("bypass");
    let (person, grant) = local(&env, None, Some(1)).await;
    env.lifecycle.set_enabled(&grant, true, &ctx()).await.unwrap();
    assert!(!enabled(&env));
    env.clients.set_state(&person, "suspended", &ctx()).unwrap();
    env.lifecycle.set_enabled(&grant, true, &ctx()).await.unwrap();
    assert!(!enabled(&env));
    // A protocol page's enable is checked against the window too.
    assert!(!env.facade.effective_operation(Protocol::Naive, "alice", true).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_readback_does_not_accept_a_success_reply_without_runtime_change() {
    let env = Env::new("dishonest");
    let enforcer = AccessEnforcer::new(env.clients.clone(), None);
    let (person, _) = local(&env, None, None).await;
    env.clients.set_state(&person, "suspended", &ctx()).unwrap();
    env.fake(Protocol::Naive).fault("disable", Fault::Dishonest);
    enforcer.tick(false).await;
    assert_eq!(env.grants(&person)[0].observed_state, GrantObservedState::Pending);
    assert!(enabled(&env));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_enforcement_batches_runtime_inventory_per_protocol() {
    let env = Env::new("batch");
    let enforcer = AccessEnforcer::new(env.clients.clone(), None);
    let person = env.clients.create_client("A", &ctx()).unwrap().id;
    let intents = (0..4).map(|index| intent(Protocol::Naive, &format!("user{index}"))).collect();
    let operation = env.provisioning.start(&person, intents, &ctx()).await.unwrap();
    env.provisioning.run(&operation).await.unwrap();
    env.clients.set_state(&person, "suspended", &ctx()).unwrap();
    let fake = env.fake(Protocol::Naive);
    let before = fake.discovers.load(std::sync::atomic::Ordering::SeqCst);
    enforcer.tick(false).await;
    assert!(fake.users.lock().unwrap().values().all(|user| !user.enabled));
    // One plan and one readback, independent of the number of grants.
    assert_eq!(fake.discovers.load(std::sync::atomic::Ordering::SeqCst) - before, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_timer_expires_access_without_a_request() {
    let env = Env::new("timer");
    local(&env, None, Some(9_999_999_999)).await;
    env.clock.set(9_999_999_999.0);
    let enforcer = AccessEnforcer::new(env.clients.clone(), None).with_interval(std::time::Duration::from_millis(1));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = {
        let enforcer = enforcer.clone();
        tokio::spawn(async move {
            enforcer
                .run_until(async {
                    let _ = stopped.await;
                })
                .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while enabled(&env) {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), task).await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pre_serve_tick_enforces_expired_local_access() {
    let env = Env::new("preserve");
    local(&env, None, Some(9_999_999_999)).await;
    env.clock.set(9_999_999_999.0);
    AccessEnforcer::new(env.clients.clone(), None).tick(true).await;
    assert!(!enabled(&env));
}

// --- remote grants (the pusher's side made directly) ----------------------------------------

fn edge(env: &Env) -> String {
    env.link_node("edge-1", json!({"capabilities": ["protocol.amneziawg.v1"], "protocols": {"amneziawg": {"enabled": true, "versions": ["2.0"]}}}));
    "edge-1".into()
}

fn report(resources: serde_json::Value) -> ObservedGeneration {
    ObservedGeneration::validate(&json!({
        "applied_generation": 1, "digest": "d", "reconcile_state": "converged", "reported_at": 1, "resources": resources,
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remote_grant_names_its_pending_credential_and_never_touches_the_local_manager() {
    let env = Env::new("remote");
    let node = edge(&env);
    let person = env.clients.create_client("A", &ctx()).unwrap().id;
    let operation =
        env.provisioning.start(&person, vec![intent_on(Protocol::Mtproxy, "alice", &node)], &ctx()).await.unwrap();
    assert_eq!(env.provisioning.status(&operation).unwrap()["status"], "pending_remote");
    let grant = env.grants(&person)[0].clone();
    assert_eq!(grant.observed_state, GrantObservedState::Pending);
    let reference = grant.secret_ref.clone().unwrap();
    assert_eq!((reference.secret_id.as_str(), reference.version), (format!("grant:{}", grant.id).as_str(), 1));
    let secret = env
        .database
        .with_connection(|db| {
            env.secrets
                .reveal(
                    db,
                    &panel_secrets::secrets_store::SecretRef::new(reference.secret_id.clone(), 1),
                    "grant.credential",
                    Some(&grant.id),
                    Some(&node),
                )
                .map_err(ClientsError::from)
        })
        .unwrap();
    assert_eq!(secret.len(), 32);
    assert!(secret.iter().all(|byte| byte.is_ascii_hexdigit()));
    assert!(env.fake(Protocol::Mtproxy).names().is_empty());
    // run() leaves the remote step to the pusher.
    assert_eq!(env.provisioning.run(&operation).await.unwrap().status, "pending_remote");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_writes_grant_secret_and_generation_atomically() {
    let env = Env::new("atomic");
    let node = edge(&env);
    let person = env.clients.create_client("A", &ctx()).unwrap().id;
    env.provisioning.faults.set("before_remote_commit", "1");
    assert!(matches!(
        env.provisioning.start(&person, vec![intent_on(Protocol::Naive, "alice", &node)], &ctx()).await,
        Err(ClientsError::Injected(_))
    ));
    assert_eq!(env.count("SELECT count(*) FROM access_grants"), 0);
    assert_eq!(env.count("SELECT count(*) FROM secret_versions WHERE purpose='grant.credential'"), 0);
    env.provisioning.start(&person, vec![intent_on(Protocol::Naive, "alice", &node)], &ctx()).await.unwrap();
    assert_eq!(env.count("SELECT count(*) FROM secret_versions WHERE state='pending'"), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_applied_finishes_only_operations_whose_grants_the_node_confirmed() {
    let env = Env::new("applied");
    let node = edge(&env);
    let person = env.clients.create_client("A", &ctx()).unwrap().id;
    let one = env.provisioning.start(&person, vec![intent_on(Protocol::Naive, "alice", &node)], &ctx()).await.unwrap();
    let two = env.provisioning.start(&person, vec![intent_on(Protocol::Naive, "bob", &node)], &ctx()).await.unwrap();
    let grants: std::collections::HashMap<String, String> =
        env.grants(&person).into_iter().map(|grant| (grant.runtime_username.clone(), grant.id)).collect();
    let observed = report(json!([
        {"ref": format!("grant:{}", grants["alice"]), "protocol": "naive", "runtime_username": "alice", "state": "enabled"},
        {"ref": format!("grant:{}", grants["bob"]), "protocol": "naive", "runtime_username": "bob", "state": "failed", "error": "boom"},
    ]));
    env.database.transaction(|db| env.provisioning.remote_applied(db, &observed, &HashSet::new(), None)).unwrap();
    assert_eq!(env.provisioning.status(&one).unwrap()["status"], "succeeded");
    let status = env.provisioning.status(&two).unwrap();
    assert_eq!(status["status"], "pending_remote");
    assert_eq!(
        status["steps"][0],
        json!({"error": "boom", "grant_id": grants["bob"], "protocol": "naive", "status": "remote"})
    );
    assert_eq!(env.secret_states(&grants["alice"]), [(1, "active".into())]);
    assert_eq!(env.secret_states(&grants["bob"]), [(1, "pending".into())]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn escrow_returned_credential_replaces_the_pending_version_in_place() {
    let env = Env::new("returned");
    let node = edge(&env);
    let person = env.clients.create_client("A", &ctx()).unwrap().id;
    env.provisioning.start(&person, vec![intent_on(Protocol::Mtproxy, "alice", &node)], &ctx()).await.unwrap();
    let grant = env.grants(&person)[0].clone();
    let value = format!("ee{}", "a".repeat(32));
    env.database
        .transaction(|db| {
            env.provisioning.escrow_returned_credential(db, &grant.id, &format!("grant:{}:1", grant.id), &value)?;
            // A repeated push of the same version is idempotent.
            env.provisioning.escrow_returned_credential(db, &grant.id, &format!("grant:{}:1", grant.id), &value)
        })
        .unwrap();
    assert_eq!(env.secret_states(&grant.id), [(1, "active".into())]);
    assert!(matches!(
        env.database.transaction(|db| env.provisioning.escrow_returned_credential(
            db,
            &grant.id,
            "grant:other:1",
            &value
        )),
        Err(ClientsError::Invalid(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_lifecycle_only_records_desired_state() {
    let env = Env::new("remotelife");
    let node = edge(&env);
    let person = env.clients.create_client("A", &ctx()).unwrap().id;
    let operation =
        env.provisioning.start(&person, vec![intent_on(Protocol::Naive, "alice", &node)], &ctx()).await.unwrap();
    let grant = env.grants(&person)[0].id.clone();
    let rotated = env.lifecycle.rotate(&grant, &ctx()).await.unwrap();
    assert_eq!((rotated.secret_ref.unwrap().version, rotated.observed_state), (2, GrantObservedState::Pending));
    assert_eq!(env.secret_states(&grant), [(1, "retiring".into()), (2, "pending".into())]);
    // Confirmed by the node: the new version active, the old one revoked.
    env.database.transaction(|db| env.provisioning.confirm_credential(db, &grant)).unwrap();
    assert_eq!(env.secret_states(&grant), [(1, "revoked".into()), (2, "active".into())]);
    let disabled = env.lifecycle.set_enabled(&grant, false, &ctx()).await.unwrap();
    assert_eq!(
        (disabled.desired_state, disabled.observed_state),
        (GrantDesiredState::Disabled, GrantObservedState::Pending)
    );
    // Twice is a no-op: nothing published, nothing audited.
    let audited = env.actions().len();
    env.lifecycle.set_enabled(&grant, false, &ctx()).await.unwrap();
    assert_eq!(env.actions().len(), audited);
    assert!(env.fake(Protocol::Naive).names().is_empty());
    // Deleting before the node applied it settles the operation.
    env.lifecycle.delete(&grant, &ctx()).await.unwrap();
    let status = env.provisioning.status(&operation).unwrap();
    assert_eq!(status["status"], "compensated");
    assert!(status["steps"][0]["error"].as_str().unwrap().contains("deleted"));
    let row = env.database.with_connection(|db| store::grant(db, &grant)).unwrap();
    assert_eq!((row.desired_state, row.observed_state), (GrantDesiredState::Deleted, GrantObservedState::Pending));
    match env.lifecycle.rotate(&grant, &ctx()).await {
        Err(ClientsError::Conflict(message)) => assert!(message.contains("deleted")),
        other => panic!("{other:?}"),
    }
    assert!(matches!(env.lifecycle.set_enabled("no-such-grant", true, &ctx()).await, Err(ClientsError::NotFound(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_local_step_compensates_and_withdraws_the_remote_grant() {
    let env = Env::new("withdraw");
    let node = edge(&env);
    let person = env.clients.create_client("A", &ctx()).unwrap().id;
    let operation = env
        .provisioning
        .start(&person, vec![intent_on(Protocol::Naive, "alice", &node), intent(Protocol::Naive, "bob")], &ctx())
        .await
        .unwrap();
    env.provisioning.faults.set("after_apply", "naive");
    assert_eq!(env.provisioning.run(&operation).await.unwrap().status, "compensated");
    assert!(env.grants(&person).is_empty());
    let states: Vec<(String, String)> = env
        .database
        .with_connection(|db| {
            let mut statement = db.prepare("SELECT runtime_username, desired_state FROM access_grants")?;
            let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
        })
        .unwrap();
    assert_eq!(states, [("alice".to_string(), "deleted".to_string())]);
    assert!(env.fake(Protocol::Naive).names().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remote_amneziawg_grant_needs_the_version_the_node_serves() {
    let env = Env::new("awg");
    let node = edge(&env);
    let person = env.clients.create_client("A", &ctx()).unwrap().id;
    let mut wanted = intent_on(Protocol::Amneziawg, "alice", &node);
    if let panel_model::clients::ProtocolOptions::Amneziawg(options) = &mut wanted.options {
        options.version = panel_model::clients::AwgVersion::V3_1;
    }
    match env.provisioning.start(&person, vec![wanted], &ctx()).await {
        Err(ClientsError::Conflict(message)) => {
            assert_eq!(message, "amneziawg: version 3.1 is not served by this node")
        }
        other => panic!("{other:?}"),
    }
    env.provisioning.start(&person, vec![intent_on(Protocol::Amneziawg, "alice", &node)], &ctx()).await.unwrap();
    match env.provisioning.start(&person, vec![intent_on(Protocol::Trusttunnel, "bob", &node)], &ctx()).await {
        Err(ClientsError::Conflict(message)) => {
            assert_eq!(message, "trusttunnel: the node runs a panel version without TrustTunnel")
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_facade_adopts_on_write_and_escrows_rotations() {
    let env = Env::new("facade");
    env.fake(Protocol::Mieru).seed("carol", "old-password-0001");
    // An unknown account is adopted (one row, no credential), then its rotation escrowed.
    let credential = env
        .facade
        .rotate(Protocol::Mieru, "carol", &json!({"quotas": []}).as_object().unwrap().clone(), &ctx())
        .await
        .unwrap();
    let grant = env.facade.grant(Protocol::Mieru, "carol").unwrap().unwrap();
    assert_eq!(env.facade.credential(Protocol::Mieru, "carol").unwrap(), credential);
    assert_eq!(env.secret_states(&grant.id), [(1, "active".into())]);
    let kept = env
        .facade
        .escrow(Protocol::Mieru, "carol", b"next-password-01", None, &Map::new(), "grant.rotate", true, &ctx())
        .unwrap();
    assert!(kept);
    assert_eq!(env.secret_states(&grant.id), [(1, "revoked".into()), (2, "active".into())]);
    // `adopt=False` keeps nothing for an account the panel does not record.
    assert!(!env
        .facade
        .escrow(Protocol::Naive, "nobody", b"pw", None, &Map::new(), "grant.rotate", false, &ctx())
        .unwrap());
    let actions = env.actions();
    assert!(actions.contains(&"grant.adopt_on_write".into()));
    env.facade.forget(Protocol::Mieru, "carol", &ctx()).unwrap();
    let row = env.database.with_connection(|db| store::grant(db, &grant.id)).unwrap();
    assert_eq!((row.desired_state, row.observed_state), (GrantDesiredState::Deleted, GrantObservedState::Missing));
    // A create through the saga answers the escrowed credential once.
    let created = env.facade.create(Protocol::Naive, "dave", &Map::new(), &ctx()).await.unwrap();
    assert_eq!(env.fake(Protocol::Naive).users.lock().unwrap()["dave"].password, created);
    let unused = GrantUpdate::new();
    assert_eq!(unused, GrantUpdate::default());
}
