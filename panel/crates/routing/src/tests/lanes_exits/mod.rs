//! Unit ports of `test_routing_lanes_models.py`, `test_routing_exits.py`, and the lane/relay/store
//! parts of `test_routing_fleet*.py`. HTTP authorization, router probes, generation reconciliation,
//! and service orchestration stay in their owning black-box suites.

mod support;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::compiler::HopResolver;
use crate::exits::{ExitError, ExitInput, ExitStore};
use crate::lanes::{lane_policies, ChainResolver, RelayRegistry};
use crate::store::{self, ApplyRecord, Mark, StoreError};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use panel_core::db::DbError;
use panel_core::migrations::{self, MIGRATIONS};
use panel_model::routing::models::{exit_hops, is_node_exit, normalise_exit, PolicyInput, PolicyState};
use panel_model::seams::{RelayConfirmation, SeamError};
use panel_model::validate::Model;
use panel_model::Backend;
use serde_json::{json, Value};
use support::*;

#[test]
fn an_exit_is_warp_or_a_chain_of_nodes_with_the_last_hops_exit() {
    assert_eq!(normalise_exit("warp").unwrap(), "warp");
    assert_eq!(normalise_exit(&format!("node:{GUID_B}")).unwrap(), format!("node:{GUID_B}"));
    assert_eq!(normalise_exit(&format!("NODE:{GUID_B}:WARP")).unwrap(), format!("node:{GUID_B}:warp"));
    assert_eq!(
        normalise_exit(&format!("node:{GUID_B},{GUID_C}:warp")).unwrap(),
        format!("node:{GUID_B},{GUID_C}:warp")
    );
    assert_eq!(exit_hops(Some("warp")), (vec![], None));
    assert_eq!(exit_hops(Some(&format!("node:{GUID_B}"))), (vec![GUID_B.into()], Some("direct")));
    assert_eq!(
        exit_hops(Some(&format!("node:{GUID_B},{GUID_C}:warp"))),
        (vec![GUID_B.into(), GUID_C.into()], Some("warp"))
    );
    assert_eq!(exit_hops(None), (vec![], None));
    assert!(is_node_exit(&format!("node:{GUID_B}")));
    assert!(!is_node_exit("warp"));

    let bad = vec![
        "direct".into(),
        "node:".into(),
        "node:has space".into(),
        format!("node:{GUID_B}:direct"),
        format!("node:{GUID_B},{GUID_B}"),
        format!("node:{GUID_B},{GUID_C},{},{}", "d".repeat(32), "e".repeat(32)),
        "socks5://x".into(),
        String::new(),
    ];
    for value in bad {
        assert!(normalise_exit(&value).is_err(), "{value}");
    }
    assert!(PolicyInput::validate(&json!({"default_action": "egress", "default_egress": 5})).is_err());
}

#[test]
fn rules_and_defaults_accept_node_exits_and_refuse_the_rest() {
    let node = format!("node:{GUID_B}:warp");
    let parsed_rule = panel_model::routing::models::RoutingRule::validate(&rule(Some(&node), "egress")).unwrap();
    assert_eq!(parsed_rule.egress.as_deref(), Some(node.as_str()));
    let policy = policy_input(json!({
        "default_action": "egress",
        "default_egress": format!("node:{GUID_B},{GUID_C}"),
        "rules": [rule(Some(&node), "egress"), rule(Some("warp"), "egress")]
    }));
    assert_eq!(policy.intent.default_egress.as_deref(), Some(format!("node:{GUID_B},{GUID_C}").as_str()));
    assert_eq!(policy.intent.exits(), vec![format!("node:{GUID_B},{GUID_C}"), node.clone(), "warp".into()]);
    assert_eq!(policy.intent.node_exits(), vec![format!("node:{GUID_B},{GUID_C}"), node]);
    assert!(panel_model::routing::models::RoutingRule::validate(&rule(Some("node:nope!"), "egress")).is_err());
    assert!(PolicyInput::validate(&json!({"default_action": "egress", "default_egress": "direct"})).is_err());
    assert!(panel_model::routing::models::RoutingRule::validate(&rule(Some("warp"), "direct")).is_err());
}

#[test]
fn migration_16_adds_lanes_relay_tables_and_keeps_every_row() {
    let dir = TempDir::new("migration-16");
    let database = panel_core::db::Database::open(dir.join("panel.sqlite3")).unwrap();
    assert_eq!(migrations::apply(&database, &MIGRATIONS[..15]).unwrap(), (1..=15).collect::<Vec<_>>());
    database
        .transaction(|db| {
            db.execute(
                "INSERT INTO routing_policies(id,node_id,protocol,backend,default_action,default_egress,fallback,revision,state,created_at,updated_at) \
                 VALUES('p1','local','naive','xray_router','egress','warp','fail_closed',2,'applied',1,1)",
                [],
            )?;
            db.execute(
                "INSERT INTO routing_rules(id,policy_id,position,enabled,match_json,action,egress,created_at,updated_at) \
                 VALUES('11111111-0000-4000-8000-111111111111','p1',0,1,'{\"domains\":[\"a.example\"]}','egress','warp',1,1)",
                [],
            )?;
            db.execute(
                "INSERT INTO routing_applies(policy_id,revision,digest,backend,compiler_version,outcome,actor,created_at) \
                 VALUES('p1',2,'d','xray_router','2','applied','owner',1)",
                [],
            )?;
            assert!(db
                .execute(&format!("UPDATE routing_policies SET default_egress='node:{GUID_B}' WHERE id='p1'"), [])
                .is_err());
            Ok::<_, DbError>(())
        })
        .unwrap();
    assert_eq!(migrations::apply_migrations(&database).unwrap(), (16..=26).collect::<Vec<_>>());
    database
        .transaction(|db| {
            let row = db.query_row(
                "SELECT id,lane,default_egress,revision,state FROM routing_policies WHERE id='p1'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, i64>(3)?, row.get::<_, String>(4)?)),
            )?;
            assert_eq!(row, ("p1".into(), "svc".into(), Some("warp".into()), 2, "applied".into()));
            for (sql, expected) in [
                ("SELECT count(*) FROM routing_rules WHERE policy_id='p1'", 1),
                ("SELECT count(*) FROM routing_applies WHERE policy_id='p1'", 1),
                ("SELECT count(*) FROM pragma_foreign_key_check", 0),
            ] {
                assert_eq!(db.query_row(sql, [], |row| row.get::<_, i64>(0))?, expected);
            }
            db.execute(&format!("UPDATE routing_policies SET default_egress='node:{GUID_B}' WHERE id='p1'"), [])?;
            db.execute(
                "INSERT INTO routing_policies(id,node_id,protocol,lane,backend,default_action,fallback,revision,state,created_at,updated_at) \
                 VALUES('p2','local','naive','grant:g1','xray_router','direct','fail_closed',1,'draft',1,1)",
                [],
            )?;
            assert!(db.execute(
                "INSERT INTO routing_policies(id,node_id,protocol,lane,backend,default_action,fallback,revision,state,created_at,updated_at) \
                 VALUES('p3','local','naive','svc','xray_router','direct','fail_closed',1,'draft',1,1)",
                [],
            ).is_err());
            for (table, columns) in [
                ("access_grants", &["routing_lane"][..]),
                ("relay_peers", &["node_id", "source_node_id", "exit", "secret_id", "created_at"][..]),
                ("router_relays", &["node_id", "port", "public_key", "short_id", "server_name", "enabled", "updated_at"][..]),
            ] {
                let present: Vec<String> = db
                    .prepare(&format!("PRAGMA table_info({table})"))?
                    .query_map([], |row| row.get(1))?
                    .collect::<Result<_, _>>()?;
                for column in columns {
                    assert!(present.iter().any(|present| present == column), "{table}.{column}");
                }
            }
            db.execute("DELETE FROM routing_policies WHERE id='p1'", [])?;
            assert_eq!(db.query_row("SELECT count(*) FROM routing_rules", [], |row| row.get::<_, i64>(0))?, 0);
            Ok::<_, DbError>(())
        })
        .unwrap();
}

#[test]
fn store_keys_policies_by_lane() {
    let (_dir, database) = migrated("store-lanes");
    database
        .transaction(|db| {
            let service = store::upsert(db, "local", "naive", &PolicyInput::default(), None, 1, "svc").unwrap();
            let lane = store::upsert(
                db,
                "local",
                "naive",
                &policy_input(json!({"default_action": "egress", "default_egress": format!("node:{GUID_B}")})),
                None,
                2,
                "grant:g1",
            )
            .unwrap();
            assert_eq!((service.lane.as_str(), lane.lane.as_str()), ("svc", "grant:g1"));
            assert_ne!(service.id, lane.id);
            assert_eq!(store::get(db, "local", "naive", "svc").unwrap().unwrap().id, service.id);
            assert_eq!(store::get(db, "local", "naive", "grant:g1").unwrap().unwrap().id, lane.id);
            assert!(store::get(db, "local", "naive", "grant:none").unwrap().is_none());
            let lanes = |policies: Vec<panel_model::routing::models::RoutingPolicy>| {
                policies.into_iter().map(|policy| policy.lane).collect::<Vec<String>>()
            };
            assert_eq!(lanes(store::list(db, Some("local")).unwrap()), ["svc", "grant:g1"]);
            assert_eq!(lanes(store::lanes_of(db, "local", "naive").unwrap()), ["svc", "grant:g1"]);
            store::delete(db, &lane.id).unwrap();
            assert!(store::get(db, "local", "naive", "grant:g1").unwrap().is_none());
            assert!(store::get(db, "local", "naive", "svc").unwrap().is_some());
            assert!(matches!(store::delete(db, &lane.id), Err(StoreError::NotFound(_))));
            Ok::<_, DbError>(())
        })
        .unwrap();
}

#[test]
fn share_links_become_exit_inputs_and_the_panel_shape_is_the_routers() {
    let vless = crate::exits::parse_share_link(&format!(
        "vless://{UUID}@vpn.example.org:443?type=tcp&security=reality&sni=www.example.com&pbk={PUBLIC_KEY}&sid=0123abcd&fp=chrome&flow=xtls-rprx-vision#NL%20vless"
    ))
    .unwrap();
    assert_eq!(
        (vless.name.as_str(), vless.protocol.as_str(), vless.security.kind.as_str(), vless.flow.as_str()),
        ("NL vless", "vless", "reality", "xtls-rprx-vision")
    );
    let trojan = crate::exits::parse_share_link(
        "trojan://pw@t.example.org:8443?type=ws&path=%2Fws&host=t.example.org&sni=t.example.org#tr",
    )
    .unwrap();
    assert_eq!(
        (trojan.transport.network.as_str(), trojan.transport.path.as_deref(), trojan.security.kind.as_str()),
        ("ws", Some("/ws"), "tls")
    );
    let ss_new = format!("ss://{}@203.0.113.5:8388#ss1", URL_SAFE_NO_PAD.encode(b"aes-256-gcm:secret"));
    let ss_old = format!("ss://{}#ss2", STANDARD.encode(b"aes-256-gcm:secret@203.0.113.5:8388"));
    let mut ss = None;
    for (link, name) in [(ss_new, "ss1"), (ss_old, "ss2")] {
        let parsed = crate::exits::parse_share_link(&link).unwrap();
        assert_eq!(
            (parsed.protocol.as_str(), parsed.method.as_deref(), parsed.name.as_str()),
            ("shadowsocks", Some("aes-256-gcm"), name)
        );
        assert_eq!(parsed.credential.as_ref().unwrap().password.as_deref(), Some("secret"));
        ss = Some(parsed);
    }
    let socks = crate::exits::parse_share_link("socks://user:pass@10.0.0.2:1080#lab").unwrap();
    assert_eq!(socks.protocol, "socks");
    assert_eq!(socks.credential.as_ref().unwrap().username.as_deref(), Some("user"));
    let plain = crate::exits::parse_share_link("http://10.0.0.3:3128").unwrap();
    assert_eq!(plain.protocol, "http");
    assert!(plain.credential.is_none());
    for bad in [
        "wireguard://x",
        "vless://nope@host",
        "ss://!!!",
        "ss://YWVzLTEyOC1nY206cA==é@203.0.113.5:8388",
        "ftp://x:1",
        "",
    ] {
        assert!(crate::exits::parse_share_link(bad).is_err(), "{bad}");
    }

    let items = [vless, trojan, ss.unwrap(), socks, plain];
    let specs: Vec<Value> = items
        .iter()
        .map(|item| {
            let credential = item
                .credential_bytes()
                .map(|bytes| serde_json::from_slice(&bytes).unwrap())
                .unwrap_or_else(|| json!({}));
            let mut spec = item.settings();
            spec.as_object_mut().unwrap().insert("credential".into(), credential);
            spec
        })
        .collect();
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures/xray-router-contract.json");
    let contract: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(Value::Array(specs), contract["panel_exit_specs"]);
}

#[test]
fn exit_input_refuses_the_impossible() {
    for (value, message) in [
        (
            json!({"name":"x","protocol":"shadowsocks","address":"h.example","port":1,"credential":{"password":"p"}}),
            "needs a method",
        ),
        (
            json!({"name":"x","protocol":"socks","address":"h.example","port":1,"transport":{"network":"ws"}}),
            "tcp only",
        ),
        (
            json!({"name":"x","protocol":"vless","address":"h.example","port":1,"credential":{"uuid":"nope"}}),
            "needs a uuid",
        ),
        (
            json!({"name":"x","protocol":"vless","address":"h.example","port":1,"credential":{"uuid":UUID},"security":{"kind":"reality","server_name":"a.b"}}),
            "public key",
        ),
    ] {
        let error = ExitInput::validate(&value).unwrap_err().to_string();
        assert!(error.contains(message), "{error}");
    }
    assert_eq!(normalise_exit("exit:abc-123").unwrap(), "exit:abc-123");
    assert!(normalise_exit("exit:").is_err());
}

#[test]
fn exits_crud_import_test_and_the_policy_that_uses_one() {
    let (_dir, database) = migrated("exit-store");
    let secrets = secrets();
    let exits = ExitStore::new(secrets);
    database
        .transaction(|db| {
            let created = exits.create(
                db,
                "local",
                &exit_input(json!({"name":"lab socks","protocol":"socks","address":"10.0.0.2","port":1080,
                                   "credential":{"username":"u","password":"p"}})),
                1,
            )
            .unwrap();
            let exit_id = created["id"].as_str().unwrap().to_string();
            assert_eq!(created["has_credential"], true);
            assert!(created.get("credential").is_none() && created.get("password").is_none());
            let imported_input = crate::exits::parse_share_link(&format!(
                "vless://{UUID}@vpn.example.org:443?security=tls&sni=vpn.example.org#NL"
            ))
            .unwrap();
            let imported = exits.create(db, "local", &imported_input, 2).unwrap();
            assert_eq!((imported["protocol"].as_str(), imported["name"].as_str()), (Some("vless"), Some("NL")));
            assert!(!serde_json::to_string(&imported).unwrap().contains(UUID));
            let listed = ExitStore::list(db, "local").unwrap();
            assert_eq!(listed.iter().map(|row| row["name"].as_str()).collect::<Vec<_>>(), [Some("lab socks"), Some("NL")]);
            assert!(!Value::Array(listed.into_iter().map(Value::Object).collect()).to_string().contains("\"p\""));

            ExitStore::record_test(
                db,
                &exit_id,
                json!({"ok":true,"ip":"203.0.113.9","colo":"AMS","latency_ms":12,"credential":"do-not-store"})
                    .as_object()
                    .unwrap(),
                3,
            )
            .unwrap();
            let tested = ExitStore::get(db, &exit_id).unwrap().unwrap();
            assert_eq!(tested["last_test"]["colo"], "AMS");
            assert_eq!(tested["last_test"]["at"], 3);
            assert!(tested["last_test"].get("credential").is_none());

            let spec = exits.spec(db, &exit_id, "local").unwrap().unwrap();
            assert_eq!(spec["credential"], json!({"username":"u","password":"p"}));
            assert_eq!(spec["address"], "10.0.0.2");
            assert_eq!(exits.spec(db, "missing", "local").unwrap().unwrap_err().code, "exit_unknown");
            assert_eq!(exits.spec(db, &exit_id, NODE).unwrap().unwrap_err().code, "exit_other_node");

            let policy = policy_input(json!({
                "backend":"xray_router", "default_action":"egress", "default_egress":format!("exit:{exit_id}"),
                "rules":[{"match":{"geosites":["youtube"]},"action":"egress","egress":format!("exit:{exit_id}")}]
            }));
            let saved = store::upsert(db, "local", "naive", &policy, None, 4, "svc").unwrap();
            assert_eq!(
                ExitStore::usage(db, &exit_id).unwrap(),
                vec![
                    json!({"policy_id":saved.id,"node_id":"local","protocol":"naive","lane":"svc","rule":null}),
                    json!({"policy_id":saved.id,"node_id":"local","protocol":"naive","lane":"svc","rule":1}),
                ]
            );
            assert_eq!(ExitStore::set_enabled(db, &exit_id, false, 5).unwrap()["enabled"], false);
            assert_eq!(exits.spec(db, &exit_id, "local").unwrap().unwrap_err().code, "exit_disabled");
            ExitStore::set_enabled(db, &exit_id, true, 6).unwrap();

            let updated = exits.update(
                db,
                &exit_id,
                &exit_input(json!({"name":"lab socks 2","protocol":"socks","address":"10.0.0.2","port":1081,
                                   "credential":{"username":"u2","password":"p2"}})),
                7,
            )
            .unwrap();
            assert_eq!(updated["port"], 1081);
            let spec = exits.spec(db, &exit_id, "local").unwrap().unwrap();
            assert_eq!(spec["credential"], json!({"username":"u2","password":"p2"}));
            let versions: Vec<(i64, String)> = db
                .prepare("SELECT version,state FROM secret_versions WHERE secret_id=? ORDER BY version")
                .unwrap()
                .query_map([format!("exit:{exit_id}")], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(versions, [(1, "revoked".into()), (2, "active".into())]);
            assert!(!Value::Array(ExitStore::list(db, "local").unwrap().into_iter().map(Value::Object).collect())
                .to_string()
                .contains("p2"));

            assert!(matches!(
                exits.create(db, "local", &exit_input(json!({"name":"lab socks 2","protocol":"http","address":"h.example","port":80})), 8),
                Err(ExitError::Invalid(message)) if message.contains("name exists")
            ));
            assert!(matches!(
                exits.update(db, &exit_id, &exit_input(json!({"name":"other","protocol":"http","address":"h.example","port":80})), 8),
                Err(ExitError::Invalid(message)) if message.contains("keeps its protocol")
            ));
            let imported_id = imported["id"].as_str().unwrap();
            exits.delete(db, imported_id).unwrap();
            assert!(ExitStore::get(db, imported_id).unwrap().is_none());
            assert!(matches!(exits.delete(db, imported_id), Err(ExitError::NotFound)));
            Ok::<_, DbError>(())
        })
        .unwrap();
}

#[test]
fn a_linked_nodes_relay_is_enabled_through_its_generation_and_a_chain_follows_its_report() {
    let (_dir, database) = migrated("relay-chain");
    let registry = RelayRegistry::new(secrets());
    database
        .transaction(|db| {
            insert_node(db, NODE);
            RelayRegistry::desire(db, NODE, true, 45443, "node.example", 1).unwrap();
            let desired = RelayRegistry::relay(db, NODE).unwrap().unwrap();
            assert_eq!((desired["enabled"].as_i64(), desired["port"].as_i64(), desired["public_key"].as_str()),
                       (Some(1), Some(45443), None));
            let report = json!({"state":"converged","enabled":false,"port":45443,"server_name":"node.example",
                                "public_key":PUBLIC_KEY,"short_ids":["0123abcd"],"accounts":[]});
            RelayRegistry::observe(db, NODE, report.as_object().unwrap(), 2).unwrap();
            let relay = RelayRegistry::relay(db, NODE).unwrap().unwrap();
            assert_eq!(relay["public_key"], PUBLIC_KEY);
            assert_eq!(relay["short_id"], "0123abcd");
            assert_eq!(relay["enabled"], 1, "a report does not undo the panel's desired state");

            let unconfirmed: Arc<dyn RelayConfirmation> = Arc::new(|_node: &str, _email: &str| -> Result<bool, SeamError> { Ok(false) });
            let mut pending = ChainResolver {
                db,
                registry: &registry,
                source_guid: MASTER.into(),
                nodes_by_guid: vec![node_row(NODE, Some("https://node.example/path"))],
                own_guid: "own-guid".into(),
                local_host: "local.example".into(),
                confirmed: unconfirmed,
                issue: true,
                now: 3,
                issued: BTreeSet::new(),
            };
            assert_eq!(pending.resolve(NODE).unwrap().unwrap_err().code, "relay_credential_pending");
            assert_eq!(pending.issued, BTreeSet::from([NODE.into()]));
            drop(pending);
            let peers = RelayRegistry::peers(db, NODE).unwrap();
            assert_eq!(peers.iter().map(|row| row["exit"].as_str()).collect::<Vec<_>>(), [Some("direct"), Some("warp")]);
            let accounts = registry.accounts(db, NODE).unwrap();
            assert_eq!(accounts.as_array().unwrap().len(), 2);
            assert!(accounts.as_array().unwrap().iter().all(|account| account["uuid"].as_str().is_some_and(|uuid| uuid.len() == 36)));
            assert!(peers.iter().all(|row| row["secret_id"].as_str().is_some_and(|id| !id.is_empty())));
            assert!(RelayRegistry::account_row(db, NODE, MASTER, "direct").unwrap().is_some());
            assert!(registry.issue(db, NODE, MASTER, "other", 4).is_err());

            let direct_only: Arc<dyn RelayConfirmation> = Arc::new(|_node: &str, email: &str| -> Result<bool, SeamError> {
                Ok(email.ends_with(":direct"))
            });
            let mut resolver = ChainResolver {
                db,
                registry: &registry,
                source_guid: MASTER.into(),
                nodes_by_guid: vec![node_row(NODE, Some("https://node.example"))],
                own_guid: "own-guid".into(),
                local_host: String::new(),
                confirmed: direct_only,
                issue: false,
                now: 4,
                issued: BTreeSet::new(),
            };
            let hop = resolver.resolve(NODE).unwrap().unwrap();
            assert_eq!((hop.address.as_str(), hop.port, hop.server_name.as_str(), hop.public_key.as_str(), hop.short_id.as_str()),
                       ("node.example", 45443, "node.example", PUBLIC_KEY, "0123abcd"));
            assert!(hop.uuid_warp.is_none());
            let direct_uuid = hop.uuid_direct.clone();
            assert_eq!(resolver.resolve("unknown").unwrap().unwrap_err().code, "node_unknown");
            drop(resolver);

            assert_eq!(registry.rotate(db, NODE, 5).unwrap(), 2);
            let rotated = registry.accounts(db, NODE).unwrap();
            assert!(!rotated.to_string().contains(&direct_uuid));
            let states: Vec<String> = db
                .prepare("SELECT state FROM secret_versions WHERE purpose='relay-account' ORDER BY created_at,secret_id,version")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(states.iter().filter(|state| state.as_str() == "revoked").count(), 2);
            assert_eq!(states.iter().filter(|state| state.as_str() == "active").count(), 2);
            Ok::<_, DbError>(())
        })
        .unwrap();
}

#[test]
fn identity_reports_the_lanes_and_relay_capabilities_and_the_relays_public_part() {
    let (_dir, database) = migrated("relay-observation");
    database
        .transaction(|db| {
            let view = json!({"enabled":true,"port":45443,"server_name":"node.example",
                              "public_key":PUBLIC_KEY,"short_ids":["0123abcd","ignored"]});
            RelayRegistry::record(db, "local", Some(&view), 1).unwrap();
            let relay = RelayRegistry::relay(db, "local").unwrap().unwrap();
            assert_eq!(
                (relay["enabled"].as_i64(), relay["port"].as_i64(), relay["short_id"].as_str()),
                (Some(1), Some(45443), Some("0123abcd"))
            );
            let pending = json!({"state":"pending","public_key":"must-not-replace","port":1});
            RelayRegistry::observe(db, "local", pending.as_object().unwrap(), 2).unwrap();
            assert_eq!(RelayRegistry::relay(db, "local").unwrap().unwrap()["public_key"], PUBLIC_KEY);
            RelayRegistry::record(db, "local", Some(&json!([])), 3).unwrap();
            assert!(RelayRegistry::relay(db, "local").unwrap().is_none());
            assert!(RelayRegistry::peers(db, "local").unwrap().is_empty());
            Ok::<_, DbError>(())
        })
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grant_on_a_linked_node_gets_its_lane_through_the_generation() {
    let (_dir, database) = migrated("remote-lanes");
    let calls = Arc::new(Mutex::new(Vec::new()));
    database
        .transaction(|db| {
            seed_remote_grant(db, &["egress.lanes.v1", "relay.v1"]);
            let service =
                store::upsert(db, NODE, "naive", &policy_input(json!({"backend":"xray_router"})), None, 1, "svc")
                    .unwrap();
            let desired = json!({"backend":"xray_router","policy_id":service.id,"policy_revision":1,
                "document":{"schema":2,"lanes":{"svc:naive":{"default":{"action":"direct","egress":null},"rules":[]},
                "grant:g1":{"default":{"action":"egress","egress":"warp"},"rules":[]}},
                "chains":{"c1":{"exit":"direct","hops":[]}}},"digest":"old"});
            store::set_desired(db, &service.id, Some(&desired), 1).unwrap();
            Ok::<_, DbError>(())
        })
        .unwrap();
    let lanes = remote_lanes(database.clone(), calls.clone());
    let enabled = lanes.enable("g1", &context()).await.unwrap();
    assert_eq!(
        (enabled["mode"].as_str(), enabled["lane"].as_str(), enabled["pending"].as_bool()),
        (Some("own"), Some("grant:g1"), Some(true))
    );
    database
        .with_connection(|db| {
            let grant = panel_clients::store::grant(db, "g1").unwrap();
            assert!(grant.own_lane);
            let lane = store::get(db, NODE, "naive", "grant:g1").unwrap().unwrap();
            assert_eq!((lane.state, lane.backend), (PolicyState::Draft, Backend::XrayRouter));
            assert_eq!(
                lane_policies(db, NODE, "naive").unwrap().iter().map(|policy| policy.lane.as_str()).collect::<Vec<_>>(),
                ["svc", "grant:g1"]
            );
            Ok::<_, DbError>(())
        })
        .unwrap();
    let disabled = lanes.disable("g1", &context()).await.unwrap();
    assert_eq!((disabled["mode"].as_str(), disabled["lane"].as_str()), (Some("service"), Some("svc")));
    database
        .with_connection(|db| {
            assert!(!panel_clients::store::grant(db, "g1").unwrap().own_lane);
            assert!(store::get(db, NODE, "naive", "grant:g1").unwrap().is_none());
            let desired = store::desired_for_node(db, NODE).unwrap();
            let lanes = desired["naive"]["document"]["lanes"].as_object().unwrap();
            assert_eq!(lanes.keys().map(String::as_str).collect::<Vec<_>>(), ["svc:naive"]);
            assert_eq!(desired["naive"]["document"]["chains"], json!({}));
            assert_ne!(desired["naive"]["digest"], "old");
            let actions: Vec<String> = db
                .prepare("SELECT action FROM audit_log ORDER BY id")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(actions, ["grant.lane.enable", "grant.lane.disable"]);
            Ok::<_, DbError>(())
        })
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), [NODE, NODE]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_v06_node_refuses_lanes_and_relay_by_code() {
    let (_dir, database) = migrated("old-node-lanes");
    let calls = Arc::new(Mutex::new(Vec::new()));
    database
        .transaction(|db| {
            seed_remote_grant(db, &["generation.v1"]);
            Ok::<_, DbError>(())
        })
        .unwrap();
    let lanes = remote_lanes(database, calls.clone());
    let error = lanes.enable("g1", &context()).await.unwrap_err();
    assert_eq!((error.status(), error.code()), (422, Some("node_lacks_lanes")));
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn compile_includes_only_desired_sections_for_an_egress_v1_node() {
    let (_dir, database) = migrated("desired-store");
    database
        .transaction(|db| {
            insert_node(db, NODE);
            let service = store::upsert(db, NODE, "naive", &PolicyInput::default(), None, 1, "svc").unwrap();
            let lane = store::upsert(db, NODE, "naive", &PolicyInput::default(), None, 1, "grant:g1").unwrap();
            let desired = json!({"backend":"naive_native","policy_id":service.id,"policy_revision":1,
                                 "document":{"schema":1,"upstream":{"provider":"warp"},"acl":[]},"digest":"d"});
            assert!(store::desired_for_node(db, NODE).unwrap().is_empty());
            store::set_desired(db, &service.id, Some(&desired), 2).unwrap();
            store::set_desired(db, &lane.id, Some(&json!({"document":{"lane":"not-published"}})), 2).unwrap();
            let sections = store::desired_for_node(db, NODE).unwrap();
            assert_eq!(sections.len(), 1);
            assert_eq!(sections["naive"], desired);
            store::set_desired(db, &service.id, None, 3).unwrap();
            assert!(store::desired_for_node(db, NODE).unwrap().is_empty());
            Ok::<_, DbError>(())
        })
        .unwrap();
}

#[test]
fn routing_apply_remote_publishes_generation_and_the_report_marks_it_applied() {
    let (_dir, database) = migrated("store-applied");
    database
        .transaction(|db| {
            insert_node(db, NODE);
            let policy = store::upsert(db, NODE, "naive", &PolicyInput::default(), None, 1, "svc").unwrap();
            store::mark(db, &policy.id, PolicyState::Applying, Mark::default(), 2).unwrap();
            store::mark(
                db,
                &policy.id,
                PolicyState::Applied,
                Mark { applied_revision: Some(1), applied_digest: Some("digest".into()), last_error: None },
                3,
            )
            .unwrap();
            let document = json!({"schema":1,"upstream":null,"acl":[]});
            store::record_apply(
                db,
                &policy.id,
                &ApplyRecord {
                    document: Some(&document),
                    actor: "node",
                    ..ApplyRecord::new(1, Some("digest"), "naive_native", "applied")
                },
                3,
            )
            .unwrap();
            let applied = store::get_by_id(db, &policy.id).unwrap();
            assert!(applied.applied_current());
            assert_eq!(applied.applied_digest.as_deref(), Some("digest"));
            let history = store::history(db, &policy.id, 50).unwrap();
            assert_eq!(history.len(), 1);
            assert_eq!(history[0]["outcome"], "applied");
            assert_eq!(history[0]["actor"], "node");
            assert_eq!(history[0]["document"], document);
            Ok::<_, DbError>(())
        })
        .unwrap();
}

#[test]
fn pusher_marks_policy_failed_with_the_node_error() {
    let (_dir, database) = migrated("store-failed");
    database
        .transaction(|db| {
            insert_node(db, NODE);
            let policy = store::upsert(db, NODE, "naive", &PolicyInput::default(), None, 1, "svc").unwrap();
            store::mark(db, &policy.id, PolicyState::Applying, Mark::default(), 2).unwrap();
            store::mark(
                db,
                &policy.id,
                PolicyState::Failed,
                Mark { last_error: Some("egress_unreachable".into()), ..Mark::default() },
                3,
            )
            .unwrap();
            store::record_apply(db, &policy.id, &ApplyRecord::new(1, Some("digest"), "naive_native", "failed"), 3)
                .unwrap();
            let failed = store::get_by_id(db, &policy.id).unwrap();
            assert_eq!(
                (failed.state, failed.last_error.as_deref(), failed.applied_revision),
                (PolicyState::Failed, Some("egress_unreachable"), None)
            );
            assert_eq!(store::history(db, &policy.id, 50).unwrap()[0]["outcome"], "failed");
            store::mark(
                db,
                &policy.id,
                PolicyState::Applied,
                Mark { applied_revision: Some(1), applied_digest: Some("digest".into()), last_error: None },
                4,
            )
            .unwrap();
            assert!(store::get_by_id(db, &policy.id).unwrap().applied_current());
            Ok::<_, DbError>(())
        })
        .unwrap();
}

#[test]
fn routing_rollback_remote_publishes_previous_document() {
    let (_dir, database) = migrated("store-rollback");
    database
        .transaction(|db| {
            insert_node(db, NODE);
            let policy = store::upsert(db, NODE, "naive", &PolicyInput::default(), None, 1, "svc").unwrap();
            store::record_apply(db, &policy.id, &ApplyRecord::new(1, Some("one"), "naive_native", "applied"), 1)
                .unwrap();
            store::record_apply(db, &policy.id, &ApplyRecord::new(2, Some("two"), "naive_native", "applied"), 2)
                .unwrap();
            assert_eq!(store::last_applied(db, &policy.id).unwrap().unwrap()["revision"], 1);
            store::record_apply(db, &policy.id, &ApplyRecord::new(1, Some("one"), "naive_native", "rolled_back"), 3)
                .unwrap();
            store::mark(
                db,
                &policy.id,
                PolicyState::RolledBack,
                Mark { applied_revision: Some(1), applied_digest: Some("one".into()), last_error: None },
                3,
            )
            .unwrap();
            let rolled = store::get_by_id(db, &policy.id).unwrap();
            assert_eq!((rolled.state, rolled.applied_revision), (PolicyState::RolledBack, Some(1)));
            assert!(!rolled.applied_current());
            assert_eq!(
                store::history(db, &policy.id, 50)
                    .unwrap()
                    .iter()
                    .map(|row| row["outcome"].as_str())
                    .collect::<Vec<_>>(),
                [Some("rolled_back"), Some("applied"), Some("applied")]
            );
            Ok::<_, DbError>(())
        })
        .unwrap();
}
