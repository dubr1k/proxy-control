//! Native equivalents of the Python central transaction, replay, error and concurrency tests.
//! The database, escrow, client lifecycle, importer and pusher below are production services;
//! only the remote panel and protocol managers are controlled test doubles.

use super::*;
use crate::links::LinkUpdate;
use crate::native_fixture::{domain, object, Rig, EDGE, KEY, MASTER};
use panel_core::clock::Clock;
use panel_model::clients::{GrantOrigin, ProtocolOptions};
use panel_model::fleet::{Learned, ObservedResource};
use panel_model::Protocol;
use panel_secrets::secrets_store::SecretStore;
use std::sync::atomic::Ordering;

fn rejected(status: u16, detail: &str) -> NodeError {
    NodeError::Rejected { status, code: None, detail: detail.into() }
}
fn resource(grant: &AccessGrant, state: ObservedState) -> ObservedResource {
    ObservedResource {
        reference: format!("grant:{}", grant.id),
        protocol: grant.protocol.as_str().into(),
        runtime_username: grant.runtime_username.clone(),
        state,
        error: None,
        revision: Some("r".into()),
        learned: IndexMap::new(),
    }
}
fn report(generation: i64, state: ReconcileState, resources: Vec<ObservedResource>) -> ObservedGeneration {
    ObservedGeneration {
        applied_generation: generation,
        digest: "node-digest".into(),
        reconcile_state: state,
        resources,
        reported_at: 1,
        egress: IndexMap::new(),
        relay: None,
    }
}
fn credentials(grant: &AccessGrant, value: &str) -> IndexMap<String, String> {
    IndexMap::from([(
        format!("grant:{}:{}", grant.id, grant.secret_ref.as_ref().map_or(1, |r| r.version)),
        value.into(),
    )])
}

#[tokio::test]
async fn link_probe_is_read_only_and_add_commits_encrypted_key_node_and_audit() {
    let rig = Rig::new();
    let probe = rig.links.test("https://edge.example", KEY, "verify", None, false).await.unwrap();
    assert_eq!(probe["identity"]["guid"], EDGE);
    assert_eq!(rig.env.count("SELECT count(*) FROM node_links"), 0);
    assert_eq!(rig.env.count("SELECT count(*) FROM secret_versions"), 0);
    rig.link(false).await;
    rig.env
        .database
        .with_connection(|db| {
            let (kind, auth, transport): (String, String, String) =
                db.query_row("SELECT kind,auth_state,transport FROM fleet_nodes WHERE node_id=?", [EDGE], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
            assert_eq!((kind.as_str(), auth.as_str(), transport.as_str()), ("remote", "linked", "panel"));
            let ciphertext: Vec<u8> =
                db.query_row("SELECT ciphertext FROM secret_versions WHERE purpose='node-api-key'", [], |r| r.get(0))?;
            assert!(!ciphertext.windows(KEY.len()).any(|bytes| bytes == KEY.as_bytes()));
            assert!(!serde_json::to_string(&rig.links.link(db, EDGE)?).unwrap().contains(KEY));
            Ok::<_, CentralError>(())
        })
        .unwrap();
    assert!(!rig.audit("node.link").to_string().contains(KEY));
    assert_eq!(rig.links.client_for(EDGE).unwrap().identity().await.unwrap()["guid"], EDGE);
}

#[tokio::test]
async fn private_address_opt_in_survives_stored_link_and_client_recreation() {
    for allowed in [false, true] {
        let rig = Rig::new();
        rig.links
            .add("Edge", "https://edge.example", KEY, "verify", None, allowed, &domain::ctx(), false)
            .await
            .unwrap();
        rig.links.client_for(EDGE).unwrap().identity().await.unwrap();
        assert_eq!(
            rig.factory.seen.lock().unwrap().iter().map(|link| link.allow_private_address).collect::<Vec<_>>(),
            [allowed, allowed]
        );
    }
}

#[tokio::test]
async fn linking_refuses_bad_key_foreign_master_self_duplicates_and_invalid_url() {
    let rig = Rig::new();
    assert!(matches!(
        rig.links.test("https://edge.example", "wrong", "verify", None, false).await,
        Err(CentralError::LinkConflict(_))
    ));
    rig.node.state.lock().unwrap().identity.insert("master_guid".into(), json!("foreign"));
    assert!(matches!(
        rig.links.add("Edge", "https://edge.example", KEY, "verify", None, false, &domain::ctx(), false).await,
        Err(CentralError::LinkConflict(_))
    ));
    rig.node.state.lock().unwrap().identity.insert("master_guid".into(), Value::Null);
    rig.node.state.lock().unwrap().identity.insert("guid".into(), json!(MASTER));
    assert!(
        matches!(rig.links.add("Self","https://edge.example",KEY,"verify",None,false,&domain::ctx(),false).await,Err(CentralError::LinkConflict(message)) if message.contains("itself"))
    );
    rig.node.state.lock().unwrap().identity.insert("guid".into(), json!(EDGE));
    rig.link(false).await;
    assert!(matches!(
        rig.links.add("Again", "https://edge.example", KEY, "verify", None, false, &domain::ctx(), false).await,
        Err(CentralError::LinkConflict(_))
    ));
    assert!(rig.links.test("http://edge.example", KEY, "verify", None, false).await.is_err());
    assert_eq!(rig.env.count("SELECT count(*) FROM node_links"), 1);
}

#[tokio::test]
async fn key_rotation_revokes_previous_key_and_invalid_changes_roll_back_together() {
    let rig = Rig::new();
    rig.link(false).await;
    let old: String = rig
        .env
        .database
        .with_connection(|db| {
            db.query_row("SELECT api_key_secret_id FROM node_links WHERE node_id=?", [EDGE], |r| r.get(0))
                .map_err(CentralError::from)
        })
        .unwrap();
    rig.node.state.lock().unwrap().key = "pc_replacement".into();
    rig.links
        .update(
            EDGE,
            LinkUpdate {
                display_name: Some("Renamed".into()),
                api_key: Some("pc_replacement".into()),
                ..LinkUpdate::default()
            },
            &domain::ctx(),
        )
        .unwrap();
    assert_eq!(rig.links.client_for(EDGE).unwrap().identity().await.unwrap()["guid"], EDGE);
    rig.env
        .database
        .with_connection(|db| {
            let state: String =
                db.query_row("SELECT state FROM secret_versions WHERE secret_id=?", [old], |r| r.get(0))?;
            assert_eq!(state, "revoked");
            Ok::<_, CentralError>(())
        })
        .unwrap();
    for update in [
        LinkUpdate {
            display_name: Some("Must rollback".into()),
            url: Some("https://10.0.0.1".into()),
            ..LinkUpdate::default()
        },
        LinkUpdate {
            display_name: Some("Must rollback".into()),
            tls_verify: Some("pin".into()),
            ..LinkUpdate::default()
        },
    ] {
        assert!(rig.links.update(EDGE, update, &domain::ctx()).is_err());
    }
    let name: String = rig
        .env
        .database
        .with_connection(|db| {
            db.query_row("SELECT display_name FROM fleet_nodes WHERE node_id=?", [EDGE], |r| r.get(0))
                .map_err(CentralError::from)
        })
        .unwrap();
    assert_eq!(name, "Renamed");
    assert_eq!(rig.env.actions().iter().filter(|action| *action == "node.link.update").count(), 1);
    assert!(!rig.audit("node.link.update").to_string().contains("pc_replacement"));
}

#[tokio::test]
async fn link_update_without_keyring_is_atomic_secret_error() {
    let rig = Rig::new();
    rig.link(false).await;
    let disabled = crate::links::NodeLinkService::new(
        rig.env.database.clone(),
        SecretStore::with_clock(None, rig.env.clock.clone()),
        MASTER,
        rig.factory.clone(),
        rig.env.clock.clone(),
    );
    assert!(matches!(
        disabled.update(
            EDGE,
            LinkUpdate {
                display_name: Some("No commit".into()),
                api_key: Some("replacement".into()),
                ..LinkUpdate::default()
            },
            &domain::ctx()
        ),
        Err(CentralError::Secret(_))
    ));
    assert_eq!(
        rig.env.count("SELECT count(*) FROM secret_versions WHERE purpose='node-api-key' AND state='active'"),
        1
    );
    assert!(!rig.env.actions().contains(&"node.link.update".into()));
    assert_eq!(rig.links.client_for(EDGE).unwrap().identity().await.unwrap()["guid"], EDGE);
}

#[tokio::test]
async fn delete_refuses_provisioned_and_pending_deleted_grants_before_any_unlink() {
    let rig = Rig::new();
    rig.link(false).await;
    let (_, grant) = rig.provision(Protocol::Naive, "alice").await;
    assert!(matches!(rig.links.delete(EDGE, &domain::ctx(), false).await, Err(CentralError::LinkConflict(_))));
    rig.env.lifecycle.delete(&grant.id, &domain::ctx()).await.unwrap();
    assert!(
        matches!(rig.links.delete(EDGE,&domain::ctx(),false).await,Err(CentralError::LinkConflict(message)) if message.contains("confirms the deletion"))
    );
    assert_eq!(rig.node.state.lock().unwrap().released, 0);
    rig.pusher
        .absorb(
            EDGE,
            report(rig.latest().generation, ReconcileState::Converged, vec![resource(&grant, ObservedState::Missing)]),
            IndexMap::new(),
        )
        .await
        .unwrap();
    rig.links.delete(EDGE, &domain::ctx(), false).await.unwrap();
    assert_eq!(rig.node.state.lock().unwrap().released, 1);
    assert_eq!(rig.env.count("SELECT count(*) FROM node_links"), 0);
}

#[tokio::test]
async fn unlink_releases_imported_users_revokes_secrets_and_refusal_preserves_everything() {
    let rig = Rig::new();
    rig.link(false).await;
    rig.node.seed(Protocol::Naive, "legacy", Some("legacy-secret"));
    let decision = crate::importing::ImportItem {
        protocol: Protocol::Naive,
        runtime_username: "legacy".into(),
        client: "new".into(),
    };
    rig.importer.import_resources(EDGE, &[decision], &domain::ctx(), None, false).await.unwrap();
    let imported = rig.grants().remove(0);
    let (_, provisioned) = rig.provision(Protocol::Naive, "new-user").await;
    assert!(rig.links.delete(EDGE, &domain::ctx(), false).await.is_err());
    assert_eq!(rig.plaintext(&imported), "legacy-secret");
    assert_eq!(rig.env.secret_states(&imported.id), [(1, "active".into())]);
    assert_eq!(rig.grants().len(), 2);
    rig.env.lifecycle.delete(&provisioned.id, &domain::ctx()).await.unwrap();
    rig.pusher
        .absorb(
            EDGE,
            report(
                rig.latest().generation,
                ReconcileState::Converged,
                vec![resource(&provisioned, ObservedState::Missing)],
            ),
            IndexMap::new(),
        )
        .await
        .unwrap();
    rig.links.delete(EDGE, &domain::ctx(), false).await.unwrap();
    assert_eq!(rig.env.secret_states(&imported.id), [(1, "revoked".into())]);
    assert_eq!(rig.audit("node.unlink")["released_imported"], 1);
    assert_eq!(rig.node.state.lock().unwrap().credentials["naive:legacy"], "legacy-secret");
}

#[tokio::test]
async fn forced_unlink_with_unconfirmed_deletion_finishes_operations_and_scrubs_failure() {
    let rig = Rig::new();
    rig.link(false).await;
    let (operation, grant) = rig.provision(Protocol::Naive, "alice").await;
    rig.env.lifecycle.delete(&grant.id, &domain::ctx()).await.unwrap();
    rig.node.state.lock().unwrap().errors.insert("unlink", NodeError::Unreachable("ConnectError".into()));
    assert!(rig.links.delete(EDGE, &domain::ctx(), false).await.is_err());
    rig.links.delete(EDGE, &domain::ctx(), true).await.unwrap();
    assert_eq!(rig.env.count("SELECT count(*) FROM access_grants"), 0);
    assert_eq!(rig.env.count("SELECT count(*) FROM secret_versions WHERE purpose='node-api-key'"), 0);
    let audit = rig.audit("node.unlink");
    assert_eq!(audit["forced"], true);
    assert_eq!(audit["abandoned_provisioned"], 1);
    assert_eq!(audit["node_released"], false);
    assert_eq!(audit["node_error"], "NodeUnreachable");
    assert_ne!(rig.env.provisioning.status(&operation).unwrap()["status"], "pending_remote");
}

#[tokio::test]
async fn unlink_rejection_is_audited_without_remote_detail_or_credentials() {
    let rig = Rig::new();
    rig.link(false).await;
    rig.node.state.lock().unwrap().errors.insert("unlink", rejected(503, "secret echoed by remote"));
    rig.links.delete(EDGE, &domain::ctx(), false).await.unwrap();
    assert_eq!(rig.audit("node.unlink")["node_error"], "NodeRejected: 503");
    assert!(!rig.audit("node.unlink").to_string().contains("secret echoed"));
}

#[tokio::test]
async fn deleting_large_generations_cascades_with_memory_temp_store() {
    let rig = Rig::new();
    rig.link(false).await;
    rig.env.database.transaction(|db|{
        assert_eq!(db.query_row("PRAGMA temp_store",[],|r|r.get::<_,i64>(0))?,2);
        let large="x".repeat(32*1024);
        for number in 1..18 {db.execute("INSERT INTO desired_generations(node_id,generation,digest,content_digest,document_json,previous_generation,created_at,created_by) VALUES(?,?,'d','c',?,?,0,'test')",params![EDGE,number,large,number-1])?;}
        db.execute("INSERT INTO observed_generations(node_id,applied_generation,digest,reconcile_state,resources_json,reported_at) VALUES(?,17,'d','converged',?,0)",params![EDGE,large])?;
        Ok::<_,CentralError>(())
    }).unwrap();
    rig.links.delete(EDGE, &domain::ctx(), false).await.unwrap();
    for table in ["node_links", "desired_generations", "observed_generations"] {
        assert_eq!(rig.env.count(&format!("SELECT count(*) FROM {table}")), 0);
    }
}

#[tokio::test]
async fn publishing_and_grant_change_commit_or_roll_back_as_one_transaction() {
    let rig = Rig::new();
    rig.link(false).await;
    let (_, grant) = rig.provision(Protocol::Naive, "alice").await;
    let original = rig.latest();
    let result: Result<(), CentralError> = rig.env.database.transaction(|db| {
        store::update_grant(db, &grant.id, &GrantUpdate::new().desired(GrantDesiredState::Disabled).at(2))?;
        rig.env.clients.notify(db, &grant.client_id)?;
        assert_eq!(DesiredStore::latest(db, EDGE)?.unwrap().generation, original.generation + 1);
        Err(CentralError::Invalid("injected rollback".into()))
    });
    assert!(result.is_err());
    assert_eq!(rig.latest(), original);
    assert_eq!(rig.current_grant(&grant.id).desired_state, GrantDesiredState::Enabled);
}

#[tokio::test]
async fn generations_are_pure_secret_free_content_deduplicated_and_restart_durable() {
    let rig = Rig::new();
    rig.link(false).await;
    let (_, grant) = rig.provision(Protocol::Naive, "alice").await;
    let first = rig.latest();
    let plaintext = rig.plaintext(&grant);
    assert!(!first.document.dump_json().contains(&plaintext));
    rig.env
        .database
        .transaction(|db| {
            let same = generations::compile(db, EDGE, EDGE, MASTER, 3, 4, 99, "another actor", None)?;
            assert_ne!(same.canonical_digest(), first.digest);
            assert_eq!(same.content_digest(), first.content_digest);
            assert_eq!(rig.publisher.publish_at(db, EDGE, "new actor", 100)?, None);
            Ok::<_, CentralError>(())
        })
        .unwrap();
    let reopened = panel_core::db::Database::open(rig.env.database.path()).unwrap();
    assert_eq!(reopened.with_connection(|db| DesiredStore::latest(db, EDGE)).unwrap().unwrap(), first);
    rig.env.lifecycle.set_enabled(&grant.id, false, &domain::ctx()).await.unwrap();
    assert_eq!(rig.latest().generation, 2);
    assert_ne!(rig.latest().content_digest, first.content_digest);
    let fresh = rig.rebuilt_pusher(PusherOptions::default());
    fresh.tick().await.unwrap();
    rig.assert_acked(2);
}

#[tokio::test]
async fn empty_publish_is_durable_and_older_ack_never_clears_newer_dirty_intent() {
    let rig = Rig::new();
    rig.link(false).await;
    rig.env
        .database
        .transaction(|db| {
            assert_eq!(rig.publisher.publish(db, EDGE)?, Some(1));
            assert_eq!(rig.publisher.publish(db, EDGE)?, None);
            Ok::<_, CentralError>(())
        })
        .unwrap();
    assert!(rig.latest().document.resources.is_empty());
    let (_, grant) = rig.provision(Protocol::Naive, "alice").await;
    rig.pusher.absorb(EDGE, report(1, ReconcileState::Converged, Vec::new()), IndexMap::new()).await.unwrap();
    assert_eq!(rig.link_row()["config_dirty"], 1);
    assert_eq!(rig.link_row()["desired_generation"], 2);
    assert_eq!(rig.link_row()["acknowledged_generation"], 1);
    assert_eq!(rig.current_grant(&grant.id).observed_state, GrantObservedState::Pending);
}

#[tokio::test]
async fn compile_keeps_pending_deletions_and_omits_confirmed_missing() {
    let rig = Rig::new();
    rig.link(false).await;
    let (_, first) = rig.provision(Protocol::Naive, "pending-delete").await;
    let (_, second) = rig.provision(Protocol::Naive, "gone").await;
    rig.env
        .database
        .transaction(|db| {
            store::update_grant(
                db,
                &first.id,
                &GrantUpdate::new().desired(GrantDesiredState::Deleted).observed(GrantObservedState::Enabled).at(1),
            )?;
            store::update_grant(
                db,
                &second.id,
                &GrantUpdate::new().desired(GrantDesiredState::Deleted).observed(GrantObservedState::Missing).at(1),
            )?;
            let compiled = generations::compile(db, EDGE, EDGE, MASTER, 0, 1, 1, "test", None)?;
            assert_eq!(compiled.resources.len(), 1);
            assert_eq!(compiled.resources[0].reference, format!("grant:{}", first.id));
            assert_eq!(compiled.resources[0].desired_state, DesiredState::Deleted);
            Ok::<_, CentralError>(())
        })
        .unwrap();
}

#[tokio::test]
async fn remote_grant_push_activates_only_remote_escrow_and_reuses_one_scoped_client() {
    let rig = Rig::new();
    rig.link(false).await;
    let (operation, grant) = rig.provision(Protocol::Mtproxy, "alice").await;
    let before = rig.factory.created.load(Ordering::SeqCst);
    let closed = rig.factory.dropped.load(Ordering::SeqCst);
    rig.pusher.tick().await.unwrap();
    rig.assert_acked(1);
    assert_eq!(rig.factory.created.load(Ordering::SeqCst) - before, 1);
    assert_eq!(rig.factory.dropped.load(Ordering::SeqCst) - closed, 1);
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "succeeded");
    assert!(rig.plaintext(&grant).starts_with("ee"));
    assert_eq!(rig.env.secret_states(&grant.id), [(1, "active".into())]);
    assert!(rig.env.fake(Protocol::Mtproxy).names().is_empty());
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.node.state.lock().unwrap().pushes.len(), 1);
}

#[tokio::test]
async fn offline_early_return_drops_client_and_pending_grant_recovers_without_duplicate_apply() {
    let rig = Rig::new();
    rig.link(false).await;
    let (operation, _) = rig.provision(Protocol::Naive, "alice").await;
    rig.node.state.lock().unwrap().errors.insert("identity", NodeError::AuthFailed);
    let before = rig.factory.created.load(Ordering::SeqCst);
    let closed = rig.factory.dropped.load(Ordering::SeqCst);
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.factory.created.load(Ordering::SeqCst) - before, 1);
    assert_eq!(rig.factory.dropped.load(Ordering::SeqCst) - closed, 1);
    assert_eq!(rig.link_row()["status"], "offline");
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "pending_remote");
    assert!(!serde_json::to_string(&rig.link_row()).unwrap().contains(KEY));
    rig.node.state.lock().unwrap().errors.clear();
    rig.pusher.tick().await.unwrap();
    rig.assert_acked(1);
    assert_eq!(rig.node.state.lock().unwrap().applied, 1);
    let events = rig.env.actions().into_iter().filter(|a| a == "node.down" || a == "node.up").collect::<Vec<_>>();
    assert_eq!(events, ["node.down", "node.up"]);
    rig.pusher.tick().await.unwrap();
    let persisted = rig.events.since(0, 100).unwrap();
    assert_eq!(persisted.len(), 2, "repeated online ticks do not repeat transition events");
    assert!(persisted.iter().all(|event| event["node_id"] == EDGE));
    assert_eq!(persisted.iter().map(|event| event["name"].as_str().unwrap()).collect::<Vec<_>>(), ["node.down", "node.up"]);
}

#[tokio::test]
async fn refused_heartbeat_is_not_offline_and_cannot_deliver_until_recovered() {
    for status in [429, 500, 503] {
        let rig = Rig::new();
        rig.link(false).await;
        rig.pusher.tick().await.unwrap();
        let (_, _) = rig.provision(Protocol::Naive, "alice").await;
        rig.node.state.lock().unwrap().errors.insert("status", rejected(status, "remote busy with sensitive detail"));
        rig.pusher.tick().await.unwrap();
        assert_eq!(rig.link_row()["status"], "online");
        assert!(rig.node.state.lock().unwrap().pushes.is_empty());
        assert!(!rig.link_row()["last_error"].as_str().unwrap().contains("sensitive"));
        assert_eq!(rig.env.actions().iter().filter(|a| *a == "node.down").count(), 0);
        rig.node.state.lock().unwrap().errors.clear();
        rig.pusher.tick().await.unwrap();
        rig.assert_acked(1);
        assert!(rig.link_row()["last_error"].is_null());
    }
}

#[tokio::test]
async fn bare_gateway_404_and_oversized_heartbeat_are_offline_once() {
    for error in [
        rejected(502, ""),
        rejected(503, ""),
        rejected(504, ""),
        rejected(404, "not found"),
        NodeError::Rejected { status: 200, code: Some("response_too_large".into()), detail: String::new() },
    ] {
        let rig = Rig::new();
        rig.link(false).await;
        rig.pusher.tick().await.unwrap();
        rig.node.state.lock().unwrap().errors.insert("identity", error);
        rig.pusher.tick().await.unwrap();
        rig.pusher.tick().await.unwrap();
        assert_eq!(rig.link_row()["status"], "offline");
        assert_eq!(rig.env.actions().iter().filter(|a| *a == "node.down").count(), 1);
    }
}

#[tokio::test]
async fn paused_tick_skips_node_but_manual_probe_only_heartbeats() {
    let rig = Rig::new();
    rig.link(false).await;
    rig.links.set_enabled(EDGE, false, &domain::ctx()).unwrap();
    rig.provision(Protocol::Naive, "alice").await;
    let before = rig.node.identity_calls.load(Ordering::SeqCst);
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.node.identity_calls.load(Ordering::SeqCst), before);
    rig.pusher.sync_node(EDGE).await.unwrap();
    assert_eq!(rig.link_row()["status"], "online");
    assert!(rig.node.state.lock().unwrap().pushes.is_empty());
    rig.links.set_enabled(EDGE, true, &domain::ctx()).unwrap();
    rig.pusher.tick().await.unwrap();
    rig.assert_acked(1);
}

#[tokio::test]
async fn applying_poll_captures_manager_form_before_activation_without_second_push() {
    let rig = Rig::new();
    rig.link(false).await;
    let (operation, grant) = rig.provision(Protocol::Mtproxy, "alice").await;
    let bare = rig.plaintext(&grant);
    rig.node.state.lock().unwrap().push_state = ReconcileState::Applying;
    rig.pusher.tick().await.unwrap();
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.env.secret_states(&grant.id), [(1, "pending".into())]);
    assert_eq!(rig.plaintext(&grant), bare);
    assert!(rig.node.state.lock().unwrap().captures.is_empty());
    rig.node.complete();
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.node.state.lock().unwrap().pushes.len(), 1);
    assert_eq!(rig.plaintext(&grant), format!("ee{bare}"));
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "succeeded");
    rig.assert_acked(1);
}

#[tokio::test]
async fn lost_push_reply_replays_generation_and_escrows_reframed_credential_after_restart() {
    let rig = Rig::new();
    rig.link(false).await;
    let (operation, grant) = rig.provision(Protocol::Mtproxy, "alice").await;
    rig.node.state.lock().unwrap().lose_push_reply_once = true;
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.env.secret_states(&grant.id), [(1, "pending".into())]);
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "pending_remote");
    rig.rebuilt_pusher(PusherOptions::default()).tick().await.unwrap();
    assert_eq!(rig.node.state.lock().unwrap().pushes.len(), 2);
    assert_eq!(rig.node.state.lock().unwrap().applied, 1);
    assert!(rig.plaintext(&grant).starts_with("ee"));
    assert_eq!(rig.env.secret_states(&grant.id), [(1, "active".into())]);
    rig.assert_acked(1);
}

#[tokio::test]
async fn failed_capture_timeout_or_500_keeps_manager_version_pending_and_node_online() {
    for error in [NodeError::Unreachable("ReadTimeout".into()), rejected(500, "sensitive manager response")] {
        let rig = Rig::new();
        rig.link(false).await;
        let (operation, grant) = rig.provision(Protocol::Mtproxy, "alice").await;
        let bare = rig.plaintext(&grant);
        rig.node.state.lock().unwrap().push_state = ReconcileState::Applying;
        rig.pusher.tick().await.unwrap();
        rig.node.complete();
        rig.node.state.lock().unwrap().errors.insert("capture", error);
        rig.pusher.tick().await.unwrap();
        assert_eq!(rig.env.secret_states(&grant.id), [(1, "pending".into())]);
        assert_eq!(rig.plaintext(&grant), bare);
        assert_eq!(rig.link_row()["status"], "online");
        assert_eq!(rig.link_row()["config_dirty"], 1);
        assert_eq!(rig.env.provisioning.status(&operation).unwrap()["steps"][0]["error"], NOT_CAPTURED);
        rig.node.state.lock().unwrap().errors.clear();
        rig.pusher.tick().await.unwrap();
        assert_eq!(rig.plaintext(&grant), format!("ee{bare}"));
        rig.assert_acked(1);
    }
}

#[tokio::test]
async fn null_capture_withholds_only_manager_origin_and_repeated_failure_backs_off() {
    let rig = Rig::new();
    rig.link(false).await;
    let client = rig.env.clients.create_client("mixed", &domain::ctx()).unwrap();
    let operation = rig
        .env
        .provisioning
        .start(
            &client.id,
            vec![domain::intent_on(Protocol::Mtproxy, "alice", EDGE), domain::intent_on(Protocol::Naive, "bob", EDGE)],
            &domain::ctx(),
        )
        .await
        .unwrap();
    let grants = rig.env.grants(&client.id);
    let alice = grants.iter().find(|g| g.protocol == Protocol::Mtproxy).unwrap();
    let bob = grants.iter().find(|g| g.protocol == Protocol::Naive).unwrap();
    rig.node.state.lock().unwrap().capture_null.insert("mtproxy:alice".into());
    rig.node.state.lock().unwrap().push_state = ReconcileState::Applying;
    rig.pusher.tick().await.unwrap();
    rig.node.complete();
    for _ in 0..WITHHELD_TICKS_BEFORE_BACKOFF {
        rig.pusher.tick().await.unwrap();
    }
    assert_eq!(rig.env.secret_states(&alice.id), [(1, "pending".into())]);
    assert_eq!(rig.env.secret_states(&bob.id), [(1, "active".into())]);
    assert!(lock(&rig.pusher.backoff).contains_key(EDGE));
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "pending_remote");
    assert_eq!(rig.link_row()["status"], "online");
    rig.node.state.lock().unwrap().capture_null.clear();
    rig.env.clock.advance(601.0);
    rig.node.state.lock().unwrap().push_state = ReconcileState::Converged;
    rig.pusher.tick().await.unwrap();
    rig.assert_acked(rig.latest().generation);
}

#[tokio::test]
async fn failed_resources_back_off_exponentially_cap_and_new_generation_resets_slot() {
    let rig = Rig::new();
    rig.link(false).await;
    let (operation, grant) = rig.provision(Protocol::Naive, "alice").await;
    rig.node.state.lock().unwrap().failed_names.insert("alice".into());
    for (index, wait) in [30., 60., 120., 240., 480., 600., 600.].into_iter().enumerate() {
        rig.pusher.tick().await.unwrap();
        assert_eq!(rig.node.state.lock().unwrap().pushes.len(), index + 1);
        assert_eq!(rig.env.provisioning.status(&operation).unwrap()["steps"][0]["error"], "not managed");
        assert_eq!(rig.current_grant(&grant.id).observed_state, GrantObservedState::Pending);
        rig.env.clock.advance(wait - 1.);
        rig.pusher.tick().await.unwrap();
        assert_eq!(rig.node.state.lock().unwrap().pushes.len(), index + 1);
        rig.env.clock.advance(1.);
    }
    rig.pusher.tick().await.unwrap();
    let before = rig.node.state.lock().unwrap().pushes.len();
    rig.provision(Protocol::Naive, "bob").await;
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.node.state.lock().unwrap().pushes.len(), before + 1);
    rig.node.state.lock().unwrap().failed_names.clear();
    rig.env.clock.advance(31.0);
    rig.pusher.tick().await.unwrap();
    assert!(!lock(&rig.pusher.backoff).contains_key(EDGE));
    rig.assert_acked(rig.latest().generation);
}

#[tokio::test]
async fn rejected_push_redacts_detail_and_retries_only_after_backoff() {
    let rig = Rig::new();
    rig.link(false).await;
    let (operation, _) = rig.provision(Protocol::Naive, "alice").await;
    rig.node.state.lock().unwrap().errors.insert(
        "push",
        NodeError::Rejected { status: 409, code: Some("guid_mismatch".into()), detail: "sensitive credential".into() },
    );
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.link_row()["last_error"], "push 409: guid_mismatch");
    rig.node.state.lock().unwrap().errors.clear();
    rig.pusher.tick().await.unwrap();
    assert!(rig.node.state.lock().unwrap().pushes.is_empty());
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "pending_remote");
    rig.env.clock.advance(31.0);
    rig.pusher.tick().await.unwrap();
    rig.assert_acked(1);
}

#[tokio::test]
async fn stale_generation_and_digest_conflict_republish_above_node_number() {
    for code in RESYNC_CODES {
        let rig = Rig::new();
        rig.link(false).await;
        rig.provision(Protocol::Naive, "alice").await;
        rig.node.state.lock().unwrap().report = report(5, ReconcileState::Converged, Vec::new());
        rig.node
            .state
            .lock()
            .unwrap()
            .errors
            .insert("push", NodeError::Rejected { status: 409, code: Some(code.into()), detail: String::new() });
        rig.pusher.tick().await.unwrap();
        assert_eq!(rig.latest().generation, 6);
        assert_eq!(rig.latest().document.previous_generation, 5);
        rig.node.state.lock().unwrap().errors.clear();
        rig.rebuilt_pusher(PusherOptions::default()).tick().await.unwrap();
        rig.assert_acked(6);
    }
}

#[tokio::test]
async fn old_or_applying_report_never_escrows_or_confirms_rotated_version() {
    let rig = Rig::new();
    rig.link(false).await;
    let (_, grant) = rig.provision(Protocol::Mtproxy, "alice").await;
    rig.pusher.tick().await.unwrap();
    let previous = rig.plaintext(&grant);
    let rotated = rig.env.lifecycle.rotate(&grant.id, &domain::ctx()).await.unwrap();
    let pending = rig.plaintext(&rotated);
    rig.pusher
        .absorb(
            EDGE,
            report(1, ReconcileState::Converged, vec![resource(&grant, ObservedState::Enabled)]),
            credentials(&grant, "ee-stale"),
        )
        .await
        .unwrap();
    rig.pusher
        .absorb(
            EDGE,
            report(2, ReconcileState::Applying, vec![resource(&rotated, ObservedState::Enabled)]),
            credentials(&rotated, "ee-not-settled"),
        )
        .await
        .unwrap();
    assert_eq!(rig.env.secret_states(&grant.id), [(1, "retiring".into()), (2, "pending".into())]);
    assert_eq!(rig.plaintext(&rotated), pending);
    assert_ne!(previous, pending);
    assert_eq!(rig.link_row()["config_dirty"], 1);
    rig.pusher
        .absorb(
            EDGE,
            report(2, ReconcileState::Converged, vec![resource(&rotated, ObservedState::Enabled)]),
            credentials(&rotated, "ee-current"),
        )
        .await
        .unwrap();
    assert_eq!(rig.env.secret_states(&grant.id), [(1, "revoked".into()), (2, "active".into())]);
    assert_eq!(rig.plaintext(&rotated), "ee-current");
    rig.assert_acked(2);
}

#[tokio::test]
async fn same_credential_replay_preserves_nonce_and_pending_activation_in_place() {
    for protocol in [Protocol::Naive, Protocol::Mtproxy] {
        let rig = Rig::new();
        rig.link(false).await;
        let (_, grant) = rig.provision(protocol, "alice").await;
        let value = rig.plaintext(&grant);
        let pending = rig.nonce_row(&grant.id);
        rig.env
            .database
            .transaction(|db| {
                rig.env.provisioning.escrow_returned_credential(db, &grant.id, &format!("grant:{}:1", grant.id), &value)
            })
            .unwrap();
        let active = rig.nonce_row(&grant.id);
        assert_eq!(active.0, "active");
        assert_eq!(active.1, pending.1);
        assert_eq!(active.2, pending.2);
        rig.env.clock.advance(20.0);
        rig.pusher
            .absorb(
                EDGE,
                report(1, ReconcileState::Converged, vec![resource(&grant, ObservedState::Enabled)]),
                credentials(&grant, &value),
            )
            .await
            .unwrap();
        assert_eq!(rig.nonce_row(&grant.id), active);
        rig.env
            .database
            .transaction(|db| {
                rig.env.provisioning.escrow_returned_credential(
                    db,
                    &grant.id,
                    &format!("grant:{}:1", grant.id),
                    "different",
                )
            })
            .unwrap();
        assert_ne!(rig.nonce_row(&grant.id).2, active.2);
    }
}

#[tokio::test]
async fn refused_learned_options_remain_observable_but_do_not_poison_grants() {
    let rig = Rig::new();
    rig.link(false).await;
    let (operation, grant) = rig.provision(Protocol::Mieru, "alice").await;
    rig.node.state.lock().unwrap().learned =
        object(json!({"share_template":format!("mierus://{{username}}:{{password}}@{}?port=1","x".repeat(600))}));
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "succeeded");
    assert!(rig.current_grant(&grant.id).options.dump()["share_template"].is_null());
    let observed = rig.env.database.with_connection(|db| DesiredStore::observed(db, EDGE)).unwrap().unwrap();
    assert!(matches!(&observed.resources[0].learned["share_template"],Learned::Str(value) if value.len()>512));
}

#[tokio::test]
async fn stale_option_drift_report_cannot_confirm_a_new_suspension() {
    let rig = Rig::new();
    rig.link(false).await;
    let (_, grant) = rig.provision(Protocol::Naive, "alice").await;
    rig.pusher.tick().await.unwrap();
    rig.env
        .database
        .transaction(|db| {
            store::update_grant(db, &grant.id, &GrantUpdate::new().options_json(r#"{"quota_bytes":100}"#.into()))?;
            rig.publisher.publish(db, EDGE)?;
            Ok::<_, CentralError>(())
        })
        .unwrap();
    let drift =
        report(rig.latest().generation, ReconcileState::Converged, vec![resource(&grant, ObservedState::Drifted)]);
    rig.pusher.absorb(EDGE, drift.clone(), IndexMap::new()).await.unwrap();
    rig.env.clients.set_state(&grant.client_id, "suspended", &domain::ctx()).unwrap();
    assert_eq!(rig.current_grant(&grant.id).observed_state, GrantObservedState::Pending);
    rig.pusher.absorb(EDGE, drift, IndexMap::new()).await.unwrap();
    assert_eq!(rig.current_grant(&grant.id).observed_state, GrantObservedState::Pending);
    assert_eq!(rig.link_row()["config_dirty"], 1);
}

#[tokio::test]
async fn drift_report_does_not_infer_runtime_from_the_centrals_clock() {
    for central_now in [0.0, 9_999_999_999.0] {
        let rig = Rig::new();
        rig.link(false).await;
        let (_, grant) = rig.provision(Protocol::Naive, "alice").await;
        rig.pusher.tick().await.unwrap();
        rig.env
            .database
            .transaction(|db| {
                db.execute(
                    "UPDATE access_grants SET valid_from=1,valid_until=9999999999,protocol_options_json=? WHERE id=?",
                    params![r#"{"quota_bytes":100}"#, grant.id],
                )?;
                rig.publisher.publish(db, EDGE)?;
                Ok::<_, CentralError>(())
            })
            .unwrap();
        let drift =
            report(rig.latest().generation, ReconcileState::Converged, vec![resource(&grant, ObservedState::Drifted)]);
        rig.env.clock.set(central_now);
        rig.pusher.absorb(EDGE, drift, IndexMap::new()).await.unwrap();
        assert_eq!(rig.current_grant(&grant.id).observed_state, GrantObservedState::Pending);
    }
}

struct FailAbsorption;
impl ObservationSink for FailAbsorption {
    fn absorb_egress(
        &self,
        _: &Conn,
        _: &str,
        _: &GenerationDocument,
        _: &ObservedGeneration,
        _: i64,
    ) -> CentralResult<()> {
        Err(CentralError::Invalid("injected sink failure".into()))
    }
    fn observe_relay(&self, _: &Conn, _: &str, _: &ObservedRelay, _: i64) -> CentralResult<()> {
        Err(CentralError::Invalid("injected sink failure".into()))
    }
}

#[tokio::test]
async fn absorption_failure_rolls_back_credentials_operation_grant_report_and_ack() {
    let rig = Rig::new();
    rig.link(false).await;
    let (operation, grant) = rig.provision(Protocol::Mtproxy, "alice").await;
    let before = rig.nonce_row(&grant.id);
    let bare = rig.plaintext(&grant);
    let pusher =
        rig.rebuilt_pusher(PusherOptions { observations: Some(Arc::new(FailAbsorption)), ..PusherOptions::default() });
    assert!(pusher
        .absorb(
            EDGE,
            report(1, ReconcileState::Converged, vec![resource(&grant, ObservedState::Enabled)]),
            credentials(&grant, "ee-new")
        )
        .await
        .is_err());
    assert_eq!(rig.nonce_row(&grant.id), before);
    assert_eq!(rig.plaintext(&grant), bare);
    assert_eq!(rig.current_grant(&grant.id).observed_state, GrantObservedState::Pending);
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "pending_remote");
    assert_eq!(rig.link_row()["acknowledged_generation"], 0);
    assert_eq!(rig.env.count("SELECT count(*) FROM observed_generations"), 0);
}

#[tokio::test]
async fn deletion_report_after_202_purges_tombstone_and_frees_name_for_regrant() {
    let rig = Rig::new();
    rig.link(false).await;
    let (_, grant) = rig.provision(Protocol::Naive, "alice").await;
    rig.pusher.tick().await.unwrap();
    rig.env.lifecycle.delete(&grant.id, &domain::ctx()).await.unwrap();
    rig.pusher
        .absorb(
            EDGE,
            report(2, ReconcileState::Applying, vec![resource(&grant, ObservedState::Enabled)]),
            IndexMap::new(),
        )
        .await
        .unwrap();
    assert_eq!(rig.current_grant(&grant.id).desired_state, GrantDesiredState::Deleted);
    rig.node.state.lock().unwrap().report =
        report(2, ReconcileState::Converged, vec![resource(&grant, ObservedState::Missing)]);
    rig.pusher.poll_observed(&*rig.links.client_for(EDGE).unwrap(), EDGE).await.unwrap();
    assert!(rig.grants().is_empty());
    let (operation, again) = rig.provision(Protocol::Naive, "alice").await;
    assert_ne!(again.id, grant.id);
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "succeeded");
    assert_eq!(rig.latest().document.resources[0].reference, format!("grant:{}", again.id));
}

#[tokio::test]
async fn imported_missing_credential_is_captured_after_202_and_import_replay_is_idempotent() {
    let rig = Rig::new();
    rig.link(false).await;
    rig.node.seed(Protocol::Mtproxy, "legacy", Some("ee-imported"));
    rig.node.state.lock().unwrap().capture_null.insert("mtproxy:legacy".into());
    let decision = crate::importing::ImportItem {
        protocol: Protocol::Mtproxy,
        runtime_username: "legacy".into(),
        client: "new".into(),
    };
    rig.importer.import_resources(EDGE, std::slice::from_ref(&decision), &domain::ctx(), None, false).await.unwrap();
    let grant = rig.grants().remove(0);
    assert!(grant.secret_ref.is_none());
    rig.node.state.lock().unwrap().push_state = ReconcileState::Applying;
    rig.pusher.tick().await.unwrap();
    rig.node.complete();
    rig.node.state.lock().unwrap().capture_null.clear();
    rig.pusher.tick().await.unwrap();
    let current = rig.current_grant(&grant.id);
    assert!(current.secret_ref.is_some());
    assert_eq!(rig.plaintext(&current), "ee-imported");
    let replay = rig.importer.import_resources(EDGE, &[decision], &domain::ctx(), None, false).await.unwrap();
    assert_eq!(replay["already_linked"], json!(["mtproxy:legacy"]));
    assert!(replay["imported"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn import_capture_failure_and_mid_transaction_failure_leave_no_partial_clients_or_secrets() {
    let rig = Rig::new();
    rig.link(false).await;
    rig.node.seed(Protocol::Naive, "legacy", Some("password"));
    let decision = crate::importing::ImportItem {
        protocol: Protocol::Naive,
        runtime_username: "legacy".into(),
        client: "new".into(),
    };
    rig.node.state.lock().unwrap().errors.insert("capture", rejected(500, "capture failed"));
    assert!(rig.importer.import_resources(EDGE, std::slice::from_ref(&decision), &domain::ctx(), None, false).await.is_err());
    assert!(rig.grants().is_empty());
    assert_eq!(rig.env.count("SELECT count(*) FROM clients"), 0);
    rig.node.state.lock().unwrap().errors.clear();
    rig.env.database.transaction(|db|{db.execute_batch("CREATE TRIGGER fail_import BEFORE INSERT ON access_grants BEGIN SELECT RAISE(ABORT,'injected grant write failure'); END;")?;Ok::<_,CentralError>(())}).unwrap();
    assert!(rig.importer.import_resources(EDGE, &[decision], &domain::ctx(), None, false).await.is_err());
    assert_eq!(rig.env.count("SELECT count(*) FROM clients"), 0);
    assert_eq!(rig.env.count("SELECT count(*) FROM secret_versions WHERE purpose='grant.credential'"), 0);
    assert!(!rig.env.actions().contains(&"node.import".into()));
}

#[tokio::test]
async fn auto_import_is_inventory_idempotent_switchable_and_reuses_existing_client_names() {
    let rig = Rig::new();
    rig.link(false).await;
    let existing = rig.env.clients.create_client("legacy", &domain::ctx()).unwrap();
    rig.node.seed(Protocol::Naive, "legacy", Some("password"));
    rig.node.seed(Protocol::Mtproxy, "legacy", Some("ee-legacy"));
    rig.pusher.tick().await.unwrap();
    assert!(rig.grants().is_empty());
    rig.links.update(EDGE, LinkUpdate { auto_import: Some(true), ..LinkUpdate::default() }, &domain::ctx()).unwrap();
    rig.pusher.tick().await.unwrap();
    let grants = rig.grants();
    assert_eq!(grants.len(), 2);
    assert!(grants.iter().all(|g| g.client_id == existing.id && g.origin == GrantOrigin::Imported));
    let audit_count = rig.env.actions().iter().filter(|a| *a == "node.import").count();
    rig.pusher.tick().await.unwrap();
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.env.actions().iter().filter(|a| *a == "node.import").count(), audit_count);
    rig.node.seed(Protocol::Naive, "later", Some("later-secret"));
    rig.pusher.tick().await.unwrap();
    assert_eq!(rig.grants().len(), 3);
}

#[tokio::test]
async fn one_invalid_node_report_does_not_stall_a_healthy_nodes_delivery() {
    let rig = Rig::new();
    rig.link(false).await;
    let (operation, _) = rig.provision(Protocol::Naive, "alice").await;
    let broken = rig.add_node("broken").await;
    broken.state.lock().unwrap().errors.insert(
        "identity",
        NodeError::InvalidAnswer(ObservedGeneration::validate(&json!({"reconcile_state":"invalid"})).unwrap_err()),
    );
    rig.pusher.tick().await.unwrap();
    rig.assert_acked(1);
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "succeeded");
}

#[tokio::test]
async fn sync_node_is_serialised_and_overlapping_ticks_visit_all_nodes() {
    let rig = Rig::new();
    rig.link(false).await;
    rig.provision(Protocol::Naive, "alice").await;
    let (a, b) = tokio::join!(rig.pusher.sync_node(EDGE), rig.pusher.sync_node(EDGE));
    a.unwrap();
    b.unwrap();
    assert_eq!(rig.node.state.lock().unwrap().pushes.len(), 1);
    assert_eq!(rig.node.peak.load(Ordering::SeqCst), 1);
    let mut nodes = vec![rig.node.clone()];
    for i in 0..11 {
        nodes.push(rig.add_node(&format!("edge-{i}")).await);
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    for node in &nodes {
        node.identity_calls.store(0, Ordering::SeqCst);
        node.state.lock().unwrap().identity_barrier = Some(barrier.clone());
    }
    rig.factory.global.peak.store(0, Ordering::SeqCst);
    let limited = rig.rebuilt_pusher(PusherOptions { max_concurrent: 2, ..PusherOptions::default() });
    tokio::time::timeout(Duration::from_secs(3), async {
        let (a, b) = tokio::join!(limited.tick(), limited.tick());
        a.unwrap();
        b.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(rig.factory.global.peak.load(Ordering::SeqCst), 2);
    for node in nodes {
        assert_eq!(node.identity_calls.load(Ordering::SeqCst), 2);
        assert_eq!(node.peak.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn run_forever_recovers_after_failed_tick_and_stops_without_cancelling_work() {
    let rig = Rig::new();
    rig.link(false).await;
    rig.env
        .database
        .transaction(|db| {
            db.execute_batch("ALTER TABLE node_links RENAME TO held_node_links")?;
            Ok::<_, CentralError>(())
        })
        .unwrap();
    let pusher = rig.rebuilt_pusher(PusherOptions { interval: Duration::from_millis(2), ..PusherOptions::default() });
    let task = tokio::spawn(pusher.clone().run_forever());
    tokio::time::sleep(Duration::from_millis(10)).await;
    rig.env
        .database
        .transaction(|db| {
            db.execute_batch("ALTER TABLE held_node_links RENAME TO node_links")?;
            Ok::<_, CentralError>(())
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while rig.node.identity_calls.load(Ordering::SeqCst) < 4 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    pusher.stop();
    tokio::time::timeout(Duration::from_secs(3), task).await.unwrap().unwrap();
    assert_eq!(rig.link_row()["status"], "online");
}

#[tokio::test]
async fn capture_is_batched_and_partial_failure_keeps_only_unanswered_manager_secrets_pending() {
    let rig = Rig::new();
    rig.link(false).await;
    let client = rig.env.clients.create_client("bulk", &domain::ctx()).unwrap();
    let intents = (0..250).map(|i| domain::intent_on(Protocol::Mtproxy, &format!("bulk-{i:03}"), EDGE)).collect();
    let operation = rig.env.provisioning.start(&client.id, intents, &domain::ctx()).await.unwrap();
    rig.node.state.lock().unwrap().push_state = ReconcileState::Applying;
    rig.pusher.tick().await.unwrap();
    rig.node.complete();
    rig.node.state.lock().unwrap().fail_capture_on_call = Some(2);
    rig.pusher.tick().await.unwrap();
    assert_eq!(
        rig.node.state.lock().unwrap().captures.iter().map(|(_, items)| items.len()).collect::<Vec<_>>(),
        [200, 50]
    );
    assert_eq!(
        rig.env.count("SELECT count(*) FROM secret_versions WHERE purpose='grant.credential' AND state='active'"),
        200
    );
    assert_eq!(
        rig.env.count("SELECT count(*) FROM secret_versions WHERE purpose='grant.credential' AND state='pending'"),
        50
    );
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "pending_remote");
    assert_eq!(rig.link_row()["status"], "online");
    assert_eq!(rig.link_row()["config_dirty"], 1);
    rig.node.state.lock().unwrap().fail_capture_on_call = None;
    rig.pusher.poll_observed(&*rig.links.client_for(EDGE).unwrap(), EDGE).await.unwrap();
    assert_eq!(
        rig.env.count("SELECT count(*) FROM secret_versions WHERE purpose='grant.credential' AND state='active'"),
        250
    );
    assert_eq!(rig.env.provisioning.status(&operation).unwrap()["status"], "succeeded");
    rig.assert_acked(1);
}

#[tokio::test]
async fn resync_does_not_replace_newer_publication_or_renumber_below_current() {
    let rig = Rig::new();
    rig.link(false).await;
    rig.provision(Protocol::Naive, "alice").await;
    let old = rig.latest();
    rig.provision(Protocol::Naive, "bob").await;
    let newest = rig.latest();
    rig.node.state.lock().unwrap().report = report(99, ReconcileState::Converged, Vec::new());
    rig.pusher.resync(&*rig.links.client_for(EDGE).unwrap(), EDGE, old).await.unwrap();
    assert_eq!(rig.latest(), newest);
    rig.node.state.lock().unwrap().report = report(1, ReconcileState::Converged, Vec::new());
    rig.pusher.resync(&*rig.links.client_for(EDGE).unwrap(), EDGE, newest.clone()).await.unwrap();
    assert_eq!(rig.latest(), newest);
}

#[tokio::test]
async fn concurrent_publishers_deduplicate_content_under_immediate_transactions() {
    let rig = Rig::new();
    rig.link(false).await;
    let mut jobs = Vec::new();
    for _ in 0..8 {
        let database = rig.env.database.clone();
        let publisher = rig.publisher.clone();
        jobs.push(tokio::task::spawn_blocking(move || database.transaction(|db| publisher.publish(db, EDGE))));
    }
    let mut inserted = 0;
    for job in jobs {
        if job.await.unwrap().unwrap().is_some() {
            inserted += 1;
        }
    }
    assert_eq!(inserted, 1);
    assert_eq!(rig.latest().generation, 1);
    assert_eq!(rig.env.count("SELECT count(*) FROM desired_generations"), 1);
}

#[tokio::test]
async fn auto_import_joins_a_name_across_linked_nodes() {
    let rig = Rig::new();
    rig.link(true).await;
    rig.node.seed(Protocol::Naive, "alice", Some("edge-secret"));
    rig.pusher.tick().await.unwrap();
    let client = rig.grants()[0].client_id.clone();
    let second = rig.add_node("second").await;
    second.seed(Protocol::Naive, "alice", Some("second-secret"));
    rig.links
        .update("second", LinkUpdate { auto_import: Some(true), ..LinkUpdate::default() }, &domain::ctx())
        .unwrap();
    rig.pusher.tick().await.unwrap();
    let grants = rig.env.grants(&client);
    assert_eq!(grants.len(), 2);
    assert_eq!(grants.iter().map(|g| g.node_id.as_str()).collect::<HashSet<_>>(), HashSet::from([EDGE, "second"]));
    assert_eq!(rig.env.count("SELECT count(*) FROM clients"), 1);
}

#[tokio::test]
async fn report_for_previous_credential_reference_cannot_resurrect_retiring_version() {
    let rig = Rig::new();
    rig.link(false).await;
    let (_, grant) = rig.provision(Protocol::Mtproxy, "alice").await;
    rig.pusher.tick().await.unwrap();
    let rotated = rig.env.lifecycle.rotate(&grant.id, &domain::ctx()).await.unwrap();
    let pending = rig.plaintext(&rotated);
    rig.pusher
        .absorb(
            EDGE,
            report(2, ReconcileState::Converged, vec![resource(&rotated, ObservedState::Enabled)]),
            credentials(&grant, "ee-obsolete"),
        )
        .await
        .unwrap();
    assert_eq!(rig.env.secret_states(&grant.id), [(1, "retiring".into()), (2, "pending".into())]);
    assert_eq!(rig.plaintext(&rotated), pending);
    assert_eq!(rig.link_row()["acknowledged_generation"], 1);
    assert_eq!(rig.link_row()["config_dirty"], 1);
}

#[tokio::test]
async fn compile_leaves_mtproxy_expiration_out_and_retains_applicable_options() {
    let rig = Rig::new();
    rig.link(false).await;
    let (_, grant) = rig.provision(Protocol::Mtproxy, "alice").await;
    let options = ProtocolOptions::validate(
        Protocol::Mtproxy,
        &json!({"data_quota_bytes":5,"expiration":1234567890,"host":"h","port":443}),
    )
    .unwrap();
    rig.env
        .database
        .transaction(|db| {
            store::update_grant(db, &grant.id, &GrantUpdate::new().options_json(options.dump_json()))?;
            let compiled = generations::compile(db, EDGE, EDGE, MASTER, 0, 1, rig.env.clock.now(), "test", None)?;
            assert_eq!(compiled.resources[0].options, object(json!({"data_quota_bytes":5,"host":"h","port":443})));
            Ok::<_, CentralError>(())
        })
        .unwrap();
}

#[tokio::test]
async fn disable_rotate_and_delete_deliver_successive_generations() {
    let rig = Rig::new();
    rig.link(false).await;
    let (_, grant) = rig.provision(Protocol::Naive, "alice").await;
    rig.pusher.tick().await.unwrap();
    rig.assert_acked(1);
    let original = rig.plaintext(&grant);
    rig.env.lifecycle.set_enabled(&grant.id, false, &domain::ctx()).await.unwrap();
    rig.pusher.tick().await.unwrap();
    rig.assert_acked(2);
    assert_eq!(rig.node.state.lock().unwrap().report.resources[0].state, ObservedState::Disabled);
    let rotated = rig.env.lifecycle.rotate(&grant.id, &domain::ctx()).await.unwrap();
    rig.pusher.tick().await.unwrap();
    rig.assert_acked(3);
    assert_ne!(rig.plaintext(&rotated), original);
    assert_eq!(rig.env.secret_states(&grant.id), [(1, "revoked".into()), (2, "active".into())]);
    rig.env.lifecycle.delete(&grant.id, &domain::ctx()).await.unwrap();
    rig.pusher.tick().await.unwrap();
    rig.assert_acked(4);
    assert!(rig.grants().is_empty());
    let state = rig.node.state.lock().unwrap();
    assert_eq!(state.pushes.iter().map(|push| push.generation.generation).collect::<Vec<_>>(), [1, 2, 3, 4]);
    assert_eq!(state.report.resources[0].state, ObservedState::Missing);
}

#[tokio::test]
async fn failed_link_insert_rolls_back_key_node_and_audit_together() {
    let rig = Rig::new();
    rig.env.database.transaction(|db| {
        db.execute_batch("CREATE TRIGGER refuse_link BEFORE INSERT ON node_links BEGIN SELECT RAISE(ABORT,'injected link failure'); END;")?;
        Ok::<_, CentralError>(())
    }).unwrap();
    assert!(rig
        .links
        .add("Edge", "https://edge.example", KEY, "verify", None, false, &domain::ctx(), false)
        .await
        .is_err());
    assert_eq!(rig.env.count("SELECT count(*) FROM node_links"), 0);
    assert_eq!(rig.env.count("SELECT count(*) FROM fleet_nodes WHERE kind='remote'"), 0);
    assert_eq!(rig.env.count("SELECT count(*) FROM secret_versions WHERE purpose='node-api-key'"), 0);
    assert!(!rig.env.actions().contains(&"node.link".into()));
}
