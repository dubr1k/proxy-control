//! `panel/tests/test_client_listing.py` and the client-list cursor golden
//! (`panel/tests/goldens/clients/client_cursor.json`).

mod common;

use common::{golden_path, migrated, Env, TempDir};
use panel_clients::store::{self, ClientPage, PageFilters};
use panel_clients::ClientsError;
use panel_core::db::{Database, DbError};
use panel_core::rusqlite::params;
use panel_model::clients::{
    AccessGrant, Client, ClientState, GrantDesiredState, GrantObservedState, GrantOrigin, ProtocolOptions,
};
use panel_model::{Protocol, SecretRef};
use serde_json::{Map, Value};

fn new_client(env: &Env, name: &str, now: i64) -> Client {
    env.database.transaction(|db| env.clients.new_client(db, name, now)).unwrap()
}

fn grant(client_id: &str, protocol: Protocol, username: &str, node_id: &str) -> AccessGrant {
    AccessGrant {
        protocol,
        options: ProtocolOptions::default_for(protocol),
        id: panel_core::ids::uuid4(),
        client_id: client_id.into(),
        node_id: node_id.into(),
        endpoint_id: "default".into(),
        runtime_username: username.into(),
        secret_ref: None,
        desired_state: GrantDesiredState::Enabled,
        observed_state: GrantObservedState::Unknown,
        valid_from: None,
        valid_until: None,
        origin: GrantOrigin::Imported,
        own_lane: false,
        label: None,
        created_at: 1,
        updated_at: 1,
    }
}

#[test]
fn listing_batches_grants_without_losing_order_or_empty_clients() {
    let env = Env::new("batch");
    let clients: Vec<Client> = env
        .database
        .transaction(|db| {
            let mut clients = Vec::new();
            for index in 0..1000 {
                clients.push(env.clients.new_client(db, &format!("client-{index}"), index + 1)?);
            }
            for client in &clients[..2] {
                store::insert_grant(db, &grant(&client.id, Protocol::Naive, &client.id, "local"))?;
            }
            let mut deleted = grant(&clients[999].id, Protocol::Naive, "removed", "local");
            deleted.desired_state = GrantDesiredState::Deleted;
            store::insert_grant(db, &deleted)?;
            Ok::<_, ClientsError>(clients)
        })
        .unwrap();
    let listing = env.database.with_connection(store::clients_with_grants).unwrap();
    let ids: Vec<&str> = listing.iter().map(|(client, _)| client.id.as_str()).collect();
    assert_eq!(ids, clients.iter().map(|client| client.id.as_str()).collect::<Vec<_>>());
    let counts: Vec<usize> = listing.iter().map(|(_, grants)| grants.len()).collect();
    assert_eq!(&counts[..2], [1, 1]);
    assert!(counts[2..].iter().all(|count| *count == 0));
}

/// `(id, protocol, username, node, desired, observed, has secret, own lane)`.
type FixtureGrant = (&'static str, Protocol, &'static str, &'static str, &'static str, &'static str, bool, bool);
/// `(id, display name, state, grants)`.
type FixtureClient = (&'static str, &'static str, &'static str, Vec<FixtureGrant>);
/// Filters and the client ids they select.
type FilterCase = (Vec<(&'static str, &'static str)>, Vec<&'static str>);

/// The `CLIENTS` fixture of `test_clients_filters_ui.py`, stored like `listing_service`.
fn listing_service(label: &str) -> Env {
    let env = Env::new(label);
    env.database
        .transaction(|db| {
            db.execute(
                "INSERT INTO fleet_nodes(node_id,display_name,auth_state,inventory_json,created_at,updated_at)
                      VALUES('fra','Frankfurt','active','{}',1,1)",
                [],
            )?;
            let fixture: [FixtureClient; 3] = [
                (
                    "c1",
                    "Ноутбук Сергея",
                    "active",
                    vec![
                        ("g1", Protocol::Mtproxy, "laptop", "local", "enabled", "enabled", true, false),
                        ("g2", Protocol::Mieru, "laptop", "fra", "disabled", "disabled", true, true),
                    ],
                ),
                (
                    "c2",
                    "home-iphone",
                    "suspended",
                    vec![("g3", Protocol::Naive, "phone", "fra", "enabled", "pending", false, false)],
                ),
                (
                    "c3",
                    "Старый <b>телефон</b>",
                    "archived",
                    vec![("g4", Protocol::Naive, "old", "local", "deleted", "missing", false, false)],
                ),
            ];
            for (index, (id, name, state, grants)) in fixture.into_iter().enumerate() {
                let client = env.clients.new_client(db, name, index as i64 + 1)?;
                db.execute("UPDATE clients SET id=?,state=? WHERE id=?", params![id, state, client.id])?;
                for (grant_id, protocol, username, node_id, desired, observed, secret, lane) in grants {
                    let mut row = grant(id, protocol, username, node_id);
                    row.id = grant_id.into();
                    row.desired_state = GrantDesiredState::from_wire(desired).unwrap();
                    row.observed_state = GrantObservedState::from_wire(observed).unwrap();
                    row.secret_ref = secret.then(|| SecretRef::new("synthetic", 1));
                    store::insert_grant(db, &row)?;
                    db.execute(
                        "UPDATE access_grants SET routing_lane=? WHERE id=?",
                        params![lane.then_some("own"), grant_id],
                    )?;
                }
            }
            Ok::<_, ClientsError>(())
        })
        .unwrap();
    env
}

fn page(env: &Env, limit: i64, filters: &PageFilters) -> Result<ClientPage, ClientsError> {
    env.database.with_connection(|db| store::client_page(db, limit, filters))
}

#[test]
fn server_filters_match_client_search_semantics() {
    let env = listing_service("filters");
    let filter = |pairs: &[(&str, &str)]| {
        let mut filters = PageFilters::default();
        for (key, value) in pairs {
            let value = value.to_string();
            match *key {
                "query" => filters.query = value,
                "state" => filters.state = value,
                "protocol" => filters.protocol = value,
                "node" => filters.node = value,
                "issue" => filters.issue = value,
                other => panic!("{other}"),
            }
        }
        filters
    };
    let cases: Vec<FilterCase> = vec![
        (vec![], vec!["c1", "c2", "c3"]),
        (vec![("query", "НОУТБУК")], vec!["c1"]),
        (vec![("query", "phone")], vec!["c2"]),
        (vec![("query", "frankfurt")], vec!["c1", "c2"]),
        (vec![("query", "сергея laptop")], vec!["c1"]),
        (vec![("query", "%")], vec![]),
        (vec![("query", "ЭТОТ СЕРВЕР")], vec!["c1"]),
        (vec![("state", "suspended")], vec!["c2"]),
        (vec![("protocol", "mieru")], vec!["c1"]),
        (vec![("protocol", "mieru"), ("node", "local")], vec![]),
        (vec![("node", "fra")], vec!["c1", "c2"]),
        (vec![("issue", "pending")], vec!["c2"]),
        (vec![("issue", "orphan")], vec!["c2"]),
        (vec![("issue", "disabled")], vec!["c1"]),
        (vec![("issue", "lane")], vec!["c1"]),
        (vec![("issue", "problem")], vec!["c2"]),
        (vec![("issue", "empty")], vec!["c3"]),
        (vec![("issue", "empty"), ("protocol", "naive")], vec!["c1", "c3"]),
        (vec![("issue", "orphan"), ("state", "archived")], vec![]),
        (vec![("protocol", "mtproxy"), ("node", "fra"), ("issue", "disabled")], vec![]),
    ];
    for (pairs, expected) in cases {
        let result = page(&env, 50, &filter(&pairs)).unwrap();
        let ids: Vec<&str> = result.items.iter().map(|(client, _)| client.id.as_str()).collect();
        assert_eq!(ids, expected, "{pairs:?}");
        assert_eq!((result.matched, result.total), (expected.len() as i64, 3), "{pairs:?}");
        assert_eq!(
            result.counts,
            vec![("active".to_string(), 1), ("suspended".to_string(), 1), ("archived".to_string(), 1)]
        );
    }
    assert!(matches!(page(&env, 50, &filter(&[("issue", "weird")])), Err(ClientsError::Invalid(_))));
    assert!(matches!(page(&env, 0, &PageFilters::default()), Err(ClientsError::Invalid(_))));
}

#[test]
fn cursor_pages_are_bounded_and_search_covers_clients_after_first_page() {
    let env = listing_service("cursor");
    for index in 0..120 {
        new_client(&env, &format!("extra-{index:03}"), 1);
    }
    let mut cursor: Option<String> = None;
    let mut seen: Vec<String> = Vec::new();
    loop {
        let result = page(&env, 17, &PageFilters { cursor: cursor.clone(), ..PageFilters::default() }).unwrap();
        assert!(result.items.len() <= 17);
        seen.extend(result.items.iter().map(|(client, _)| client.id.clone()));
        cursor = result.next_cursor.clone();
        if cursor.is_none() {
            break;
        }
    }
    let unique: std::collections::HashSet<&String> = seen.iter().collect();
    assert_eq!((seen.len(), unique.len()), (123, 123));
    assert_eq!(&seen[121..], ["c2", "c3"]);
    let found = page(&env, 17, &PageFilters { query: "extra-119".into(), ..PageFilters::default() }).unwrap();
    assert_eq!(found.items.iter().map(|(client, _)| client.display_name.as_str()).collect::<Vec<_>>(), ["extra-119"]);
    match page(&env, 17, &PageFilters { cursor: Some("bad".into()), ..PageFilters::default() }) {
        Err(ClientsError::Invalid(message)) => assert!(message.contains("cursor")),
        other => panic!("{other:?}"),
    }
}

/// The database of the cursor recording: the subscriptions snapshot plus the seven clients the
/// recorder created afterwards (read back from the recorded full page).
fn cursor_database(dir: &TempDir, exchanges: &[Value]) -> Database {
    let path = dir.join("panel.sqlite3");
    std::fs::copy(golden_path("subscriptions/subscriptions.db"), &path).unwrap();
    let database = Database::open(&path).unwrap();
    panel_core::migrations::apply_migrations(&database).unwrap();
    let full = exchanges.iter().find(|exchange| exchange["name"] == "limit=200:page=0").unwrap();
    let body: Value = serde_json::from_str(full["response"]["body"]["text"].as_str().unwrap()).unwrap();
    database
        .transaction(|db| {
            for item in body["items"].as_array().unwrap() {
                let client = &item["client"];
                let known: i64 =
                    db.query_row("SELECT count(*) FROM clients WHERE id=?", [client["id"].as_str().unwrap()], |row| {
                        row.get(0)
                    })?;
                if known == 0 {
                    assert!(item["grants"].as_array().unwrap().is_empty());
                    store::insert_client(
                        db,
                        &Client {
                            id: client["id"].as_str().unwrap().into(),
                            display_name: client["display_name"].as_str().unwrap().into(),
                            state: ClientState::from_wire(client["state"].as_str().unwrap()).unwrap(),
                            metadata: Map::new(),
                            created_at: client["created_at"].as_i64().unwrap(),
                            updated_at: client["updated_at"].as_i64().unwrap(),
                        },
                    )
                    .unwrap();
                }
            }
            Ok::<_, DbError>(())
        })
        .unwrap();
    database
}

/// Every recorded page of `GET /api/clients?limit=…` byte-for-byte (the 422s of the query
/// validation are the web crate's; the cursor refusal is checked here).
#[test]
fn client_cursor_golden_pages_are_byte_identical() {
    let golden: Value =
        serde_json::from_str(&std::fs::read_to_string(golden_path("clients/client_cursor.json")).unwrap()).unwrap();
    let exchanges = golden["exchanges"].as_array().unwrap();
    let dir = TempDir::new("golden");
    let database = cursor_database(&dir, exchanges);
    let mut checked = 0;
    for exchange in exchanges {
        let path = exchange["request"]["path"].as_str().unwrap();
        let status = exchange["response"]["status"].as_i64().unwrap();
        let text = exchange["response"]["body"]["text"].as_str().unwrap();
        let query = path.split_once('?').map(|(_, query)| query).unwrap_or("");
        let mut limit = 0;
        let mut filters = PageFilters::default();
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap();
            let value = panel_core::pytext::unquote(value);
            match key {
                "limit" => limit = value.parse().unwrap_or(-1),
                "cursor" => filters.cursor = Some(value),
                "query" => filters.query = value,
                "state" => filters.state = value,
                "protocol" => filters.protocol = value,
                "issue" => filters.issue = value,
                other => panic!("{other}"),
            }
        }
        if status == 422 && !(1..=200).contains(&limit)
            || filters.cursor.as_ref().is_some_and(|cursor| cursor.len() > 512)
        {
            continue; // query validation: the web crate's golden
        }
        let result = database.with_connection(|db| store::client_page(db, limit, &filters));
        match result {
            Ok(page) => {
                assert_eq!(status, 200, "{path}");
                assert_eq!(panel_core::pyjson::compact_utf8(&page.to_json()), text, "{path}");
            }
            Err(ClientsError::Invalid(message)) => {
                assert_eq!(status, 422, "{path}");
                assert_eq!(panel_core::pyjson::compact_utf8(&serde_json::json!({"detail": message})), text);
            }
            Err(other) => panic!("{path}: {other:?}"),
        }
        checked += 1;
    }
    assert_eq!(checked, 29);
    let _ = migrated; // the shared helper is used by the other suites
}
