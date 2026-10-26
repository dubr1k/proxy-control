//! `panel/tests/test_subscription_{lifecycle,events}.py`, against the real migrated schema.

#[path = "../../clients/tests/common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::{ctx, Env};
use panel_clients::hosts::FixedHosts;
use panel_clients::store;
use panel_clients::ClientsError;
use panel_core::clock::Clock;
use panel_core::db::DbError;
use panel_model::clients::{AccessGrant, GrantDesiredState, GrantObservedState, GrantOrigin, ProtocolOptions};
use panel_model::{Protocol, SecretRef};
use panel_secrets::events::EventBus;
use panel_secrets::secrets_store::{Identity, SecretStore};
use panel_subscriptions::renderers::resolve_artifacts;
use panel_subscriptions::{BumpGeneration, SubscriptionService};
use serde_json::{json, Map, Value};

fn grant(client_id: &str, protocol: Protocol, username: &str) -> AccessGrant {
    let now = 1_800_000_000;
    AccessGrant {
        protocol,
        options: ProtocolOptions::default_for(protocol),
        id: panel_core::ids::uuid4(),
        client_id: client_id.into(),
        node_id: "local".into(),
        endpoint_id: "default".into(),
        runtime_username: username.into(),
        secret_ref: None,
        desired_state: GrantDesiredState::Enabled,
        observed_state: GrantObservedState::Unknown,
        valid_from: None,
        valid_until: None,
        origin: GrantOrigin::Provisioned,
        own_lane: false,
        label: None,
        created_at: now,
        updated_at: now,
    }
}

struct World {
    env: Env,
    events: Arc<EventBus>,
    subscriptions: SubscriptionService,
}

impl World {
    fn new(label: &str) -> Self {
        Self::with_keyring(label, true)
    }

    fn with_keyring(label: &str, keyring: bool) -> Self {
        let env = Env::with_keyring(label, keyring);
        let events = Arc::new(EventBus::with_options(env.database.clone(), 500, env.clock.clone()));
        let subscriptions = SubscriptionService::new(
            env.database.clone(),
            env.clients.clone(),
            env.secrets.clone(),
            env.clock.clone(),
            "https://sub.example.com",
            Some(events.clone()),
        );
        env.clients.add_hook(Arc::new(BumpGeneration(subscriptions.clone())));
        Self { env, subscriptions, events }
    }

    fn client(&self) -> String {
        self.env.clients.create_client("Sergey", &ctx()).unwrap().id
    }

    fn seeded_client(&self) -> String {
        let client_id = self.client();
        self.seed(&client_id, Protocol::Naive, "alice", None);
        self.seed(&client_id, Protocol::Mieru, "alice", Some(self.env.clock.now() + 7 * 86400));
        client_id
    }

    fn seed(&self, client_id: &str, protocol: Protocol, username: &str, valid_until: Option<i64>) -> AccessGrant {
        self.seed_on(client_id, protocol, username, valid_until, "local")
    }

    fn seed_on(
        &self,
        client_id: &str,
        protocol: Protocol,
        username: &str,
        valid_until: Option<i64>,
        node_id: &str,
    ) -> AccessGrant {
        let mut grant = grant(client_id, protocol, username);
        grant.node_id = node_id.into();
        grant.observed_state = GrantObservedState::Enabled;
        grant.valid_until = valid_until;
        self.env
            .database
            .transaction(|db| {
                let secret_id = format!("grant:{}", grant.id);
                let identity = Identity {
                    secret_id: &secret_id,
                    version: 1,
                    purpose: panel_clients::CREDENTIAL_PURPOSE,
                    grant_id: Some(&grant.id),
                    permitted_node_id: Some(node_id),
                };
                let stored = self.env.secrets.store(db, &identity, b"caller-supplied-password-01", "active")?;
                grant.secret_ref = Some(SecretRef::new(stored.secret_id, stored.version));
                store::insert_grant(db, &grant)
            })
            .unwrap();
        grant
    }

    fn events(&self) -> Vec<Map<String, Value>> {
        self.events.since(0, 500).unwrap()
    }
}

#[test]
fn token_is_stored_only_as_hash_and_ciphertext() {
    let world = World::new("token-storage");
    let client_id = world.seeded_client();
    let (subscription, token) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    assert!(token.len() >= 43 && subscription.generation == 1);
    let stored: String = world
        .env
        .database
        .with_connection(|db| {
            db.query_row("SELECT public_token_hash FROM client_subscriptions", [], |row| row.get(0))
                .map_err(DbError::from)
        })
        .unwrap();
    assert_ne!(stored, token);
    assert_eq!(stored, panel_subscriptions::service::token_hash(&token));
    let mut disk = std::fs::read(world.env.dir.join("panel.sqlite3")).unwrap();
    let wal = world.env.dir.join("panel.sqlite3-wal");
    if wal.exists() {
        disk.extend(std::fs::read(wal).unwrap());
    }
    assert!(!String::from_utf8_lossy(&disk).contains(&token));
    assert_eq!(world.subscriptions.resolve(&token).unwrap().unwrap().id, subscription.id);
    assert!(world.subscriptions.resolve(&"x".repeat(43)).unwrap().is_none());
}

#[test]
fn rotate_revokes_the_old_url() {
    let world = World::new("rotate");
    let client_id = world.seeded_client();
    let (_, old) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    let (_, new) = world.subscriptions.rotate(&client_id, &ctx()).unwrap();
    assert_ne!(old, new);
    assert!(world.subscriptions.resolve(&old).unwrap().is_none());
    assert!(world.subscriptions.resolve(&new).unwrap().is_some());
    world.subscriptions.revoke(&client_id, &ctx()).unwrap();
    assert!(world.subscriptions.resolve(&new).unwrap().is_none());
    assert!(world.subscriptions.get(&client_id).unwrap().is_none());
}

#[test]
fn generation_increments_with_the_mutation_or_not_at_all() {
    let world = World::new("generation-rollback");
    let client_id = world.seeded_client();
    world.subscriptions.create(&client_id, &ctx()).unwrap();
    world.env.clients.set_state(&client_id, "suspended", &ctx()).unwrap();
    assert_eq!(world.subscriptions.get(&client_id).unwrap().unwrap().generation, 2);
    let result: Result<(), ClientsError> = world.env.database.transaction(|db| {
        world.subscriptions.bump_generation(db, &client_id)?;
        Err(ClientsError::Internal("audit down".into()))
    });
    assert!(result.is_err());
    assert_eq!(world.subscriptions.get(&client_id).unwrap().unwrap().generation, 2);
    assert!(!world
        .events()
        .iter()
        .any(|event| event["name"] == "subscription.generation.changed" && event["generation"] == 3));
}

#[test]
fn etag_follows_the_effective_set_not_the_fetch_time() {
    let world = World::new("etag-effective");
    let client_id = world.seeded_client();
    let (subscription, _) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    let before = SubscriptionService::etag(
        &world.subscriptions.effective_manifest(&subscription, world.env.clock.now()).unwrap(),
        1,
        "",
    )
    .unwrap();
    world.subscriptions.record_fetch(&subscription, world.env.clock.now(), 200, "raw").unwrap();
    let same = SubscriptionService::etag(
        &world.subscriptions.effective_manifest(&subscription, world.env.clock.now()).unwrap(),
        1,
        "",
    )
    .unwrap();
    assert_eq!(before, same);
    world.env.clock.advance((30 * 86400) as f64);
    let manifest = world.subscriptions.effective_manifest(&subscription, world.env.clock.now()).unwrap();
    let after = SubscriptionService::etag(&manifest, 1, "").unwrap();
    assert_ne!(before, after);
    assert!(manifest.grants.iter().any(|grant| grant.protocol == "mieru" && !grant.enabled));
}

#[test]
fn a_suspended_client_renders_nothing_as_enabled() {
    let world = World::new("suspended");
    let client_id = world.seeded_client();
    let (subscription, _) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    world.env.clients.set_state(&client_id, "suspended", &ctx()).unwrap();
    let manifest = world.subscriptions.effective_manifest(&subscription, world.env.clock.now()).unwrap();
    assert!(!manifest.grants.is_empty() && manifest.grants.iter().all(|grant| !grant.enabled));
}

#[test]
fn a_second_active_subscription_cannot_exist() {
    let world = World::new("second");
    let client_id = world.seeded_client();
    world.subscriptions.create(&client_id, &ctx()).unwrap();
    match world.subscriptions.create(&client_id, &ctx()) {
        Err(ClientsError::Conflict(message)) => assert!(message.contains("already")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_public_url_is_built_from_the_configured_base() {
    let world = World::new("public-url");
    let client_id = world.seeded_client();
    let (_, token) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    let service = world.subscriptions.with_public_base("https://eclipse.example.com/");
    assert_eq!(service.public_url(&token), format!("https://eclipse.example.com/s/{token}"));
}

#[test]
fn the_app_wires_the_generation_hook_to_every_change() {
    let world = World::new("wired-hook");
    let client_id = world.seeded_client();
    world.subscriptions.create(&client_id, &ctx()).unwrap();
    world.env.clients.set_state(&client_id, "suspended", &ctx()).unwrap();
    world.env.clients.set_state(&client_id, "active", &ctx()).unwrap();
    assert_eq!(world.subscriptions.get(&client_id).unwrap().unwrap().generation, 3);
}

#[test]
fn a_client_and_its_subscription_are_born_in_one_transaction() {
    let world = World::new("born-together");
    let (client, issued) = world.subscriptions.create_with_client("Together", &ctx()).unwrap();
    let (subscription, token) = issued.unwrap();
    assert_eq!(subscription.client_id, client.id);
    assert_eq!(subscription.generation, 1);
    assert!(token.len() >= 43);
    assert_eq!(world.subscriptions.resolve(&token).unwrap().unwrap().id, subscription.id);
    world
        .env
        .database
        .transaction(|db| {
            db.execute(
                "CREATE TRIGGER fail_subscription_audit BEFORE INSERT ON audit_log WHEN NEW.action='subscription.create' BEGIN SELECT RAISE(ABORT,'audit down'); END",
                [],
            )?;
            Ok::<_, DbError>(())
        })
        .unwrap();
    assert!(world.subscriptions.create_with_client("Half", &ctx()).is_err());
    assert!(world.env.clients.list_clients().unwrap().iter().all(|client| client.display_name != "Half"));
}

#[test]
fn create_with_client_without_a_subscription_domain_makes_only_the_client() {
    let world = World::new("without-domain");
    let service = world.subscriptions.with_public_base("");
    let (client, issued) = service.create_with_client("Alone", &ctx()).unwrap();
    assert!(issued.is_none());
    assert!(service.get(&client.id).unwrap().is_none());
}

#[test]
fn resolve_artifacts_reveals_only_what_will_be_rendered() {
    let world = World::new("resolve-artifacts");
    let client_id = world.seeded_client();
    let disabled = world.seed(&client_id, Protocol::Naive, "erin", None);
    world
        .env
        .database
        .transaction(|db| {
            store::update_grant(
                db,
                &disabled.id,
                &store::GrantUpdate::new().desired(panel_model::clients::GrantDesiredState::Disabled),
            )
        })
        .unwrap();
    let (subscription, _) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    let manifest = world.subscriptions.effective_manifest(&subscription, world.env.clock.now()).unwrap();
    let hosts = FixedHosts(HashMap::from([
        ("naive".into(), "naive.example.com".into()),
        ("mieru".into(), "mieru.example.com".into()),
    ]));
    let artifacts = world
        .env
        .database
        .with_connection(|db| resolve_artifacts(&manifest, &world.env.secrets, &world.env.adapters, db, &hosts))
        .unwrap();
    assert_eq!(artifacts.len(), 2);
    assert!(!artifacts.contains_key(&disabled.id));
    assert!(artifacts.values().flatten().all(|artifact| !artifact.value.contains("CANARY")));
    let mut disk = std::fs::read(world.env.dir.join("panel.sqlite3")).unwrap();
    let wal = world.env.dir.join("panel.sqlite3-wal");
    if wal.exists() {
        disk.extend(std::fs::read(wal).unwrap());
    }
    assert!(!String::from_utf8_lossy(&disk).contains("caller-supplied-password-01"));
}

#[test]
fn a_pending_credential_version_is_not_rendered() {
    let world = World::new("pending-credential-render");
    let client_id = world.client();
    let grant = world.seed(&client_id, Protocol::Naive, "alice", None);
    let secret = grant.secret_ref.as_ref().unwrap();
    let secret = panel_secrets::secrets_store::SecretRef::new(secret.secret_id.clone(), secret.version);
    world.env.database.transaction(|db| world.env.secrets.transition(db, &secret, "pending")).unwrap();
    let (subscription, _) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    let hosts = FixedHosts(HashMap::from([("naive".into(), "naive.example.com".into())]));
    let artifacts = || {
        let manifest = world.subscriptions.effective_manifest(&subscription, world.env.clock.now()).unwrap();
        world
            .env
            .database
            .with_connection(|db| resolve_artifacts(&manifest, &world.env.secrets, &world.env.adapters, db, &hosts))
            .unwrap()
    };
    assert!(artifacts().is_empty(), "a pending secret is not usable on the node yet");
    world.env.database.transaction(|db| world.env.secrets.transition(db, &secret, "active")).unwrap();
    let published = artifacts();
    assert_eq!(published.len(), 1);
    assert!(published[&grant.id].iter().any(|item| item.value.contains("caller-supplied-password-01")));
}

#[test]
fn generation_change_emits_inside_the_transaction_or_not_at_all() {
    let world = World::new("event-generation");
    let client_id = world.seeded_client();
    world.subscriptions.create(&client_id, &ctx()).unwrap();
    world.env.clients.set_state(&client_id, "suspended", &ctx()).unwrap();
    let events = world.events();
    assert!(events.iter().any(|event| event["name"] == "subscription.generation.changed" && event["generation"] == 2));
}

#[test]
fn fetches_emit_with_their_status_and_misses_emit_nothing() {
    let world = World::new("event-fetch");
    let client_id = world.seeded_client();
    let (subscription, token) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    world.subscriptions.record_fetch(&subscription, world.env.clock.now(), 200, "singbox").unwrap();
    world.subscriptions.record_fetch(&subscription, world.env.clock.now(), 304, "singbox").unwrap();
    assert!(world.subscriptions.resolve("missing").unwrap().is_none());
    let statuses: Vec<_> = world
        .events()
        .iter()
        .filter(|event| event["name"] == "subscription.fetched")
        .map(|event| event["status"].as_i64().unwrap())
        .collect();
    assert_eq!(statuses, [200, 304]);
    assert!(!serde_json::to_string(&world.events()).unwrap().contains(&token));
}

#[test]
fn revocation_and_rotation_emit_revoked_for_the_old_url() {
    let world = World::new("event-revoked");
    let client_id = world.seeded_client();
    let (old, _) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    world.subscriptions.rotate(&client_id, &ctx()).unwrap();
    world.subscriptions.revoke(&client_id, &ctx()).unwrap();
    let reasons: Vec<_> = world
        .events()
        .iter()
        .filter(|event| event["name"] == "subscription.revoked")
        .map(|event| event["reason"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(reasons, ["rotated", "revoked"]);
    assert!(world.events().iter().any(|event| event["subscription_id"] == old.id));
}

#[test]
fn no_event_carries_a_token_a_link_or_a_delivery_claim() {
    let world = World::new("event-scrub");
    let client_id = world.seeded_client();
    let (subscription, token) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    world.subscriptions.record_fetch(&subscription, world.env.clock.now(), 200, "raw").unwrap();
    world.subscriptions.rotate(&client_id, &ctx()).unwrap();
    let encoded = serde_json::to_string(&world.events()).unwrap();
    assert!(!encoded.contains(&token));
    assert!(!encoded.contains("https://sub.example.com/s/"));
    assert!(!encoded.contains("delivered"));
}

#[test]
fn the_events_endpoint_pages_by_id_and_serves_only_subscription_events() {
    let world = World::new("event-pages");
    let client_id = world.seeded_client();
    let (subscription, _) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    for status in [200, 304, 200] {
        world.subscriptions.record_fetch(&subscription, world.env.clock.now(), status, "raw").unwrap();
    }
    let first = world.events.since(0, 2).unwrap();
    assert_eq!(first.len(), 2);
    let second = world.events.since(first.last().unwrap()["id"].as_i64().unwrap(), 2).unwrap();
    assert_eq!(second.len(), 1);
    assert!(first.iter().chain(&second).all(|event| event["name"] == "subscription.fetched"));
}

#[test]
fn the_bus_refuses_unknown_names_and_scrubs_payloads() {
    let world = World::new("event-bus");
    world
        .env
        .database
        .transaction(|db| {
            assert!(world
                .events
                .emit(db, "unknown", &json!({"subscription_id": "s"}).as_object().unwrap().clone())
                .is_err());
            let mut payload = Map::new();
            payload.insert("subscription_id".into(), "s".into());
            payload.insert("url".into(), "https://secret.example/s/token".into());
            world.events.emit(db, "subscription.fetched", &payload).unwrap();
            Ok::<_, ClientsError>(())
        })
        .unwrap();
    assert!(!serde_json::to_string(&world.events()).unwrap().contains("secret.example"));
}

#[test]
fn deleting_an_archived_client_ends_its_subscription_url() {
    let world = World::new("event-delete");
    let client_id = world.seeded_client();
    let (_, token) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    world
        .env
        .database
        .transaction(|db| {
            db.execute(
                "UPDATE access_grants SET desired_state='deleted', observed_state='missing' WHERE client_id=?",
                [&client_id],
            )?;
            Ok::<_, DbError>(())
        })
        .unwrap();
    world.env.clients.set_state(&client_id, "archived", &ctx()).unwrap();
    world.env.clients.delete_client(&client_id, &ctx()).unwrap();
    assert!(world.subscriptions.resolve(&token).unwrap().is_none());
}

#[test]
fn the_token_is_escrowed_and_can_be_shown_again_with_an_audit_row() {
    let world = World::new("escrow-reveal");
    let client_id = world.seeded_client();
    let (subscription, token) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    let reference = subscription.secret_ref.clone().unwrap();
    assert_eq!(reference.secret_id, format!("subscription:{}", subscription.id));
    let row: (String, Option<String>, Option<String>, String) = world
        .env
        .database
        .with_connection(|db| {
            db.query_row(
                "SELECT purpose,grant_id,permitted_node_id,state FROM secret_versions WHERE secret_id=?",
                [&reference.secret_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(DbError::from)
        })
        .unwrap();
    assert_eq!(row, ("subscription".into(), None, None, "active".into()));
    let (shown, again) = world.subscriptions.reveal_token(&client_id, &ctx()).unwrap();
    assert_eq!(shown.id, subscription.id);
    assert_eq!(again, token);
    assert_eq!(world.subscriptions.resolve(&again).unwrap().unwrap().id, subscription.id);
    let audits: Vec<(String, String)> = world
        .env
        .database
        .with_connection(|db| {
            let mut statement = db.prepare("SELECT action,detail_json FROM audit_log ORDER BY id")?;
            let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
        })
        .unwrap();
    assert_eq!(audits.last().unwrap().0, "subscription.reveal");
    assert!(audits.iter().all(|(_, detail)| !detail.contains(&token)));
}

#[test]
fn rotate_and_revoke_retire_the_escrowed_copy() {
    let world = World::new("escrow-retire");
    let client_id = world.seeded_client();
    let (first, _) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    let (second, new_token) = world.subscriptions.rotate(&client_id, &ctx()).unwrap();
    let state = |reference: &SecretRef| {
        world
            .env
            .database
            .with_connection(|db| {
                db.query_row("SELECT state FROM secret_versions WHERE secret_id=?", [&reference.secret_id], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(DbError::from)
            })
            .unwrap()
    };
    assert_eq!(state(first.secret_ref.as_ref().unwrap()), "revoked");
    assert_eq!(state(second.secret_ref.as_ref().unwrap()), "active");
    assert_eq!(world.subscriptions.reveal_token(&client_id, &ctx()).unwrap().1, new_token);
    world.subscriptions.revoke(&client_id, &ctx()).unwrap();
    assert_eq!(state(second.secret_ref.as_ref().unwrap()), "revoked");
    assert!(world.subscriptions.reveal_token(&client_id, &ctx()).is_err());
}

#[test]
fn without_a_keyring_nothing_is_escrowed_and_reveal_refuses() {
    let world = World::with_keyring("escrow-disabled", false);
    let client_id = world.client();
    let (subscription, token) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    assert!(subscription.secret_ref.is_none() && token.len() >= 43);
    assert!(!world.subscriptions.escrow_enabled());
    assert!(matches!(world.subscriptions.reveal_token(&client_id, &ctx()), Err(ClientsError::Secret(_))));
}

#[test]
fn a_subscription_issued_before_escrow_is_a_conflict_not_a_crash() {
    let world = World::new("escrow-missing");
    let client_id = world.client();
    let (subscription, _) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    world
        .env
        .database
        .transaction(|db| {
            db.execute(
                "UPDATE client_subscriptions SET secret_id=NULL,secret_version=NULL WHERE id=?",
                [&subscription.id],
            )?;
            Ok::<_, DbError>(())
        })
        .unwrap();
    match world.subscriptions.reveal_token(&client_id, &ctx()) {
        Err(ClientsError::Conflict(message)) => assert!(message.contains("not escrowed")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn grants_without_a_credential_no_longer_block_a_subscription() {
    let world = World::new("escrow-imported");
    let client_id = world.client();
    let imported = grant(&client_id, Protocol::Naive, "imported");
    world.env.database.transaction(|db| store::insert_grant(db, &imported)).unwrap();
    let (subscription, _) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    assert_eq!(subscription.generation, 1);
}

#[test]
fn revoke_retires_the_escrowed_copy_even_after_the_keyring_is_disabled() {
    let world = World::new("escrow-disabled-revoke");
    let client_id = world.client();
    let (subscription, _) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    let service = world.subscriptions.with_secrets(SecretStore::new(None));
    service.revoke(&client_id, &ctx()).unwrap();
    let state: String = world
        .env
        .database
        .with_connection(|db| {
            db.query_row(
                "SELECT state FROM secret_versions WHERE secret_id=?",
                [&subscription.secret_ref.unwrap().secret_id],
                |row| row.get(0),
            )
            .map_err(DbError::from)
        })
        .unwrap();
    assert_eq!(state, "revoked");
}

#[test]
fn rewrap_and_verify_cover_subscription_tokens() {
    let world = World::new("escrow-rewrap");
    let client_id = world.client();
    let (_, token) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    let rotated = world.env.secrets.keyring().unwrap().clone().rotate();
    let fresh = SecretStore::new(Some(rotated));
    let counts = world
        .env
        .database
        .transaction(|db| {
            while fresh.rewrap(db, 10)? != 0 {}
            fresh.verify_all(db)
        })
        .unwrap();
    assert!(counts.values().sum::<u64>() >= 1);
    let service = world.subscriptions.with_secrets(fresh);
    assert_eq!(service.reveal_token(&client_id, &ctx()).unwrap().1, token);
}

#[test]
fn subscription_lists_grants_of_every_node_with_node_public_hosts() {
    let world = World::new("multi-node");
    world.env.link_node("edge", json!({"protocols": {"naive": {"public_host": "node.example"}}}));
    let client_id = world.client();
    world.seed_on(&client_id, Protocol::Naive, "same-user", None, "local");
    world.seed_on(&client_id, Protocol::Naive, "same-user", None, "edge");
    let (subscription, _) = world.subscriptions.create(&client_id, &ctx()).unwrap();
    let manifest = world.subscriptions.effective_manifest(&subscription, world.env.clock.now()).unwrap();
    let hosts = |_db: &panel_core::db::Conn, node_id: &str| -> Result<HashMap<String, String>, ClientsError> {
        let host = if node_id == "edge" { "node.example" } else { "central.example" };
        Ok(HashMap::from([("naive".into(), host.into())]))
    };
    let artifacts = world
        .env
        .database
        .with_connection(|db| resolve_artifacts(&manifest, &world.env.secrets, &world.env.adapters, db, &hosts))
        .unwrap();
    let raw = String::from_utf8(
        panel_subscriptions::renderers::render(
            panel_subscriptions::Format::Raw,
            &manifest,
            &artifacts,
            &panel_subscriptions::RenderOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(raw.contains("@central.example:443"));
    assert!(raw.contains("@node.example:443"));
    assert!(raw.contains("Edge%20%C2%B7%20Naive"));
    let singbox = String::from_utf8(
        panel_subscriptions::renderers::render(
            panel_subscriptions::Format::Singbox,
            &manifest,
            &artifacts,
            &panel_subscriptions::RenderOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();
    let body: Value = serde_json::from_str(&singbox).unwrap();
    let edge = body["outbounds"].as_array().unwrap().iter().find(|item| item["server"] == "node.example").unwrap();
    assert_eq!(edge["tag"], "Edge · Naive");
}
