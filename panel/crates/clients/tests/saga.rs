//! `panel/tests/test_provisioning_saga.py`: every failure ends in a declared outcome, resuming
//! never creates a second account, and nothing the panel did not create is ever deleted.

mod common;

use common::{ctx, intent, Env, Fault};
use panel_clients::hosts::FixedHosts;
use panel_clients::{ClientsError, ProvisioningService};
use panel_model::clients::{GrantDesiredState, GrantObservedState};
use panel_model::Protocol;

fn client(env: &Env) -> String {
    env.clients.create_client("Sergey", &ctx()).unwrap().id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clean_run_activates_every_grant_with_a_stored_credential() {
    let env = Env::new("clean");
    let client_id = client(&env);
    let intents =
        vec![intent(Protocol::Mtproxy, "alice"), intent(Protocol::Naive, "alice"), intent(Protocol::Mieru, "alice")];
    let operation = env.provisioning.start(&client_id, intents, &ctx()).await.unwrap();
    let result = env.provisioning.run(&operation).await.unwrap();
    assert_eq!(result.status, "succeeded");
    let grants = env.grants(&client_id);
    assert_eq!(grants.len(), 3);
    assert!(grants.iter().all(|grant| grant.secret_ref.is_some()));
    assert!(grants.iter().all(|grant| grant.observed_state == GrantObservedState::Enabled));
    assert_eq!(env.fake(Protocol::Naive).names(), ["alice"]);
    // Telemt chose its own secret: escrowed and active.
    let telemt = grants.iter().find(|grant| grant.protocol == Protocol::Mtproxy).unwrap();
    assert_eq!(env.secret_states(&telemt.id), [(1, "active".to_string())]);
}

/// The faults of the Python test; each must end in a declared outcome, resumable, without
/// touching an account the operation did not create.
async fn every_fault(fault: &str) {
    let env = Env::new("fault");
    let client_id = client(&env);
    env.fake(Protocol::Naive).seed("keep", "pre-existing-password-0001");
    match fault {
        "before_first_apply" => env.provisioning.faults.set("before_first_apply", "1"),
        "after_apply:naive" => env.provisioning.faults.set("after_apply", "naive"),
        "after_apply:mieru" => env.provisioning.faults.set("after_apply", "mieru"),
        "during_compensation" => {
            env.provisioning.faults.set("after_apply", "mieru");
            env.provisioning.faults.set("during_compensation", "1");
        }
        "after_manager_commit_before_response:naive" => env.fake(Protocol::Naive).fault("create", Fault::LoseResponse),
        other => panic!("{other}"),
    }
    let intents =
        vec![intent(Protocol::Mtproxy, "alice"), intent(Protocol::Naive, "alice"), intent(Protocol::Mieru, "alice")];
    let operation = env.provisioning.start(&client_id, intents, &ctx()).await.unwrap();
    if let Err(error) = env.provisioning.run(&operation).await {
        // Crashed mid-flight (an injected crash, or a manager whose reply was lost): never
        // compensated, a fresh process picks the journal up below.
        assert!(matches!(error, ClientsError::Injected(_)) || error.runtime().is_some(), "{error:?}");
    }
    env.provisioning.faults.clear();
    env.fake(Protocol::Naive).clear_faults();
    let fresh = ProvisioningService::new(
        env.database.clone(),
        env.secrets.clone(),
        env.adapters.clone(),
        env.clients.clone(),
        env.clock.clone(),
    );
    let resumed = fresh.run(&operation).await.unwrap();
    assert!(["succeeded", "compensated", "manual_intervention_required"].contains(&resumed.status.as_str()), "{fault}");
    assert!(env.fake(Protocol::Naive).names().contains(&"keep".to_string()));
    if resumed.status == "succeeded" {
        assert_eq!(env.fake(Protocol::Naive).names().iter().filter(|name| *name == "alice").count(), 1);
        assert!(env.grants(&client_id).iter().all(|grant| grant.secret_ref.is_some()));
    }
    if resumed.status == "compensated" {
        assert!(!env.fake(Protocol::Naive).names().contains(&"alice".to_string()));
        assert!(!env.fake(Protocol::Mieru).names().contains(&"alice".to_string()));
        let rows = env
            .database
            .with_connection(|db| {
                panel_clients::store::grants(
                    db,
                    &panel_clients::store::GrantFilter {
                        client_id: Some(&client_id),
                        include_deleted: true,
                        ..Default::default()
                    },
                )
            })
            .unwrap();
        assert!(rows.iter().all(|grant| grant.desired_state == GrantDesiredState::Deleted));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_fault_ends_in_a_declared_outcome_and_resumes() {
    for fault in [
        "before_first_apply",
        "after_apply:naive",
        "after_apply:mieru",
        "during_compensation",
        "after_manager_commit_before_response:naive",
    ] {
        every_fault(fault).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_reply_resumes_and_is_never_compensated() {
    let env = Env::new("lost");
    let client_id = client(&env);
    env.fake(Protocol::Naive).fault("create", Fault::LoseResponse);
    let operation = env.provisioning.start(&client_id, vec![intent(Protocol::Naive, "alice")], &ctx()).await.unwrap();
    let error = env.provisioning.run(&operation).await.unwrap_err();
    let (protocol, failure) = error.runtime().unwrap();
    assert!(failure.indeterminate && protocol == Protocol::Naive);
    let status = env.provisioning.status(&operation).unwrap();
    assert_eq!(status["status"], "applying");
    assert_eq!(status["steps"][0]["status"], "pending");
    env.fake(Protocol::Naive).clear_faults();
    assert_eq!(env.provisioning.run(&operation).await.unwrap().status, "succeeded");
    assert_eq!(env.fake(Protocol::Naive).names(), ["alice"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compensation_never_deletes_what_the_operation_did_not_create() {
    let env = Env::new("never");
    let client_id = client(&env);
    env.fake(Protocol::Naive).seed("keep", "pre-existing-password-0001");
    env.provisioning.faults.set("after_apply", "naive");
    let operation = env
        .provisioning
        .start(&client_id, vec![intent(Protocol::Naive, "alice"), intent(Protocol::Mieru, "alice")], &ctx())
        .await
        .unwrap();
    let result = env.provisioning.run(&operation).await.unwrap();
    assert_eq!(result.status, "compensated");
    assert_eq!(env.fake(Protocol::Naive).names(), ["keep"]);
    assert!(env.actions().contains(&"grant.provision.compensated".to_string()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resuming_a_finished_operation_changes_nothing() {
    let env = Env::new("finished");
    let client_id = client(&env);
    let operation = env.provisioning.start(&client_id, vec![intent(Protocol::Naive, "alice")], &ctx()).await.unwrap();
    assert_eq!(env.provisioning.run(&operation).await.unwrap().status, "succeeded");
    let password = env.fake(Protocol::Naive).users.lock().unwrap()["alice"].password.clone();
    assert_eq!(env.provisioning.run(&operation).await.unwrap().status, "succeeded");
    assert_eq!(env.fake(Protocol::Naive).users.lock().unwrap()["alice"].password, password);
    assert_eq!(env.grants(&client_id).len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_preflight_reserves_nothing() {
    let env = Env::new("preflight");
    let client_id = client(&env);
    env.fake(Protocol::Naive).seed("alice", "x-password-0001");
    match env
        .provisioning
        .start(&client_id, vec![intent(Protocol::Naive, "alice"), intent(Protocol::Mieru, "alice")], &ctx())
        .await
    {
        Err(ClientsError::Conflict(message)) => assert!(message.contains("already"), "{message}"),
        other => panic!("{other:?}"),
    }
    assert!(env.grants(&client_id).is_empty());
    assert_eq!(env.count("SELECT count(*) FROM provisioning_operations"), 0);
    assert_eq!(env.count("SELECT count(*) FROM secret_versions"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_operation_status_is_readable_while_it_runs() {
    let env = Env::new("status");
    let client_id = client(&env);
    let operation = env.provisioning.start(&client_id, vec![intent(Protocol::Naive, "alice")], &ctx()).await.unwrap();
    let pending = env.provisioning.status(&operation).unwrap();
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["steps"][0]["protocol"], "naive");
    // The journal is `json.dumps(steps, sort_keys=True)`.
    let stored: String = env
        .database
        .with_connection(|db| {
            db.query_row("SELECT steps_json FROM provisioning_operations", [], |row| row.get(0))
                .map_err(panel_core::db::DbError::from)
        })
        .unwrap();
    assert!(
        stored.starts_with(r#"[{"error": null, "grant_id": ""#)
            && stored.ends_with(r#""protocol": "naive", "status": "pending"}]"#)
    );
    env.provisioning.run(&operation).await.unwrap();
    assert_eq!(env.provisioning.status(&operation).unwrap()["status"], "succeeded");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_bundle_carries_every_artifact_of_the_operation() {
    let env = Env::new("bundle");
    let client_id = client(&env);
    let operation = env
        .provisioning
        .start(&client_id, vec![intent(Protocol::Mtproxy, "alice"), intent(Protocol::Naive, "alice")], &ctx())
        .await
        .unwrap();
    assert_eq!(env.provisioning.run(&operation).await.unwrap().status, "succeeded");
    let hosts = FixedHosts(
        [("mtproxy".to_string(), "p.example.com".to_string()), ("naive".to_string(), "n.example.com".to_string())]
            .into(),
    );
    let bundle = env.provisioning.bundle(&operation, &hosts).unwrap();
    let protocols: std::collections::BTreeSet<&str> =
        bundle["grants"].as_array().unwrap().iter().map(|grant| grant["protocol"].as_str().unwrap()).collect();
    assert_eq!(protocols, ["mtproxy", "naive"].into());
    for grant in bundle["grants"].as_array().unwrap() {
        let artifacts = grant["artifacts"].as_array().unwrap();
        assert!(
            !artifacts.is_empty() && artifacts.iter().all(|artifact| !artifact["value"].as_str().unwrap().is_empty())
        );
    }
    // Only a succeeded operation has one.
    let other = env.provisioning.start(&client_id, vec![intent(Protocol::Mieru, "bob")], &ctx()).await.unwrap();
    assert!(matches!(env.provisioning.bundle(&other, &hosts), Err(ClientsError::Conflict(_))));
}

/// `test_client_links.py` (service level): only live grants with a stored credential, narrowed by
/// protocol or grant, audited without the secret.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_links_are_rebuilt_from_escrow_and_audited() {
    let env = Env::new("links");
    let client_id = client(&env);
    let operation = env
        .provisioning
        .start(&client_id, vec![intent(Protocol::Mtproxy, "alice"), intent(Protocol::Naive, "alice")], &ctx())
        .await
        .unwrap();
    env.provisioning.run(&operation).await.unwrap();
    let hosts = FixedHosts::default();
    let all = env.provisioning.client_links(&client_id, &hosts, None, None, &ctx()).unwrap();
    assert_eq!(all["grants"].as_array().unwrap().len(), 2);
    let telegram = env.provisioning.client_links(&client_id, &hosts, Some("mtproxy"), None, &ctx()).unwrap();
    assert_eq!(telegram["grants"].as_array().unwrap().len(), 1);
    let detail: String = env
        .database
        .with_connection(|db| {
            db.query_row(
                "SELECT detail_json FROM audit_log WHERE action='client.links.reveal' ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .map_err(panel_core::db::DbError::from)
        })
        .unwrap();
    assert!(detail.starts_with(r#"{"protocol": "mtproxy", "grants": [""#), "{detail}");
    assert!(matches!(
        env.provisioning.client_links(&client_id, &hosts, None, Some("other"), &ctx()),
        Err(ClientsError::NotFound(_))
    ));
    assert!(matches!(
        env.provisioning.client_links("nope", &hosts, None, None, &ctx()),
        Err(ClientsError::NotFound(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_this_panel_cannot_write_is_refused_before_anything_is_written() {
    let env = Env::new("nowhere");
    let client_id = client(&env);
    let mut elsewhere = intent(Protocol::Naive, "alice");
    elsewhere.node_id = "nowhere".into();
    match env.provisioning.start(&client_id, vec![elsewhere], &ctx()).await {
        Err(ClientsError::Conflict(message)) => assert!(message.contains("nowhere")),
        other => panic!("{other:?}"),
    }
    assert!(env.grants(&client_id).is_empty() && env.fake(Protocol::Naive).names().is_empty());
}
