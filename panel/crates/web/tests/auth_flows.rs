//! The Python black-box tests of sessions, CSRF, roles, API keys and the audit log
//! (`panel/tests/test_security.py`, `test_api_key_auth.py`, `test_rbac_audit.py`), ported onto the
//! routes this package serves (Python reached for `/api/dashboard`, `/api/users`, `/api/clients`,
//! which other packages port). Names are the Python ones minus `test_`.

mod common;

use common::{Client, Panel};
use serde_json::json;

const OWNER_PASSWORD: &str = "correct horse battery staple";

/// The shared panel of the Python fixture: `login_attempts=3`, `login_window_seconds=60`,
/// `reveal_ttl_seconds=60`, an owner.
fn server(tweak: impl FnOnce(&mut panel_core::settings::Settings)) -> Panel {
    let panel = common::start_with(&[], |settings| {
        settings.login_attempts = 3;
        settings.login_window_seconds = 60;
        settings.reveal_ttl_seconds = 60;
        tweak(settings);
    });
    panel.state.store.create_admin("owner", OWNER_PASSWORD, "owner").unwrap();
    panel
}

fn create_key(panel: &Panel, client: &mut Client, scope: &str) -> serde_json::Value {
    client.login(panel, "owner", OWNER_PASSWORD);
    let csrf = client.csrf();
    let created = client.send(
        panel,
        "POST",
        "/api/keys",
        &[("X-CSRF-Token", &csrf)],
        Some(&json!({"name": "t", "scope": scope}).to_string()),
    );
    assert_eq!(created.status, 201, "{}", String::from_utf8_lossy(&created.body));
    created.json()
}

#[test]
fn unauthenticated_browser_root_redirects_to_login_but_api_stays_json_401() {
    let panel = server(|_| {});
    let mut client = Client::default();
    let root = client.send(&panel, "GET", "/", &[], None);
    assert_eq!((root.status, root.header("location")), (303, Some("/login")));
    assert_eq!(client.send(&panel, "GET", "/login", &[], None).status, 200);
    let api = client.send(&panel, "GET", "/api/auth/me", &[], None);
    assert_eq!((api.status, api.json()), (401, json!({"detail": "authentication required"})));
}

#[test]
fn login_uses_opaque_server_side_session_and_security_headers() {
    let panel = server(|_| {});
    let mut client = Client::default();
    let response = client.login(&panel, "owner", OWNER_PASSWORD);
    assert_eq!(response.status, 204);
    let cookie = response.cookie("panel_session").unwrap();
    assert!(!cookie.contains('.') && cookie.len() >= 40);
    let session_header =
        response.headers.iter().find(|(name, value)| name == "set-cookie" && value.starts_with("panel_session="));
    assert!(session_header.unwrap().1.contains("HttpOnly"));
    let identity = client.send(&panel, "GET", "/api/auth/me", &[], None);
    assert_eq!(
        identity.json(),
        json!({"username": "owner", "role": "owner", "via": "session", "panel_version": "9.9.9",
               "features": {"naive": false, "mieru": false, "amneziawg": false, "trusttunnel": false}})
    );
    assert!(identity.header("content-security-policy").unwrap().starts_with("default-src 'self'"));
    assert!(identity.header("content-security-policy").unwrap().contains("form-action 'self'"));
    assert_eq!(identity.header("x-content-type-options"), Some("nosniff"));
}

#[test]
fn authenticated_login_page_preserves_session_csrf() {
    let panel = server(|_| {});
    let mut client = Client::default();
    client.login(&panel, "owner", OWNER_PASSWORD);
    let csrf = client.csrf();
    assert_eq!(client.send(&panel, "GET", "/login", &[], None).status, 200);
    assert_eq!(client.csrf(), csrf);
    let created =
        client.send(&panel, "POST", "/api/keys", &[("X-CSRF-Token", &csrf)], Some(r#"{"name":"a","scope":"monitor"}"#));
    assert_eq!(created.status, 201);
}

#[test]
fn poisoned_matching_csrf_cookie_invalidates_session_for_relogin() {
    let panel = server(|_| {});
    let mut client = Client::default();
    client.login(&panel, "owner", OWNER_PASSWORD);
    client.set_cookie("panel_csrf", "poisoned-by-stale-login-page");
    let access = client.send(
        &panel,
        "POST",
        "/api/keys",
        &[("X-CSRF-Token", "poisoned-by-stale-login-page")],
        Some(r#"{"name":"a","scope":"monitor"}"#),
    );
    assert_eq!((access.status, access.json()), (401, json!({"detail": "session CSRF state invalid"})));
    assert_eq!(client.send(&panel, "GET", "/api/auth/me", &[], None).status, 401);
}

#[test]
fn csrf_required_for_login_and_authenticated_mutations() {
    let panel = server(|_| {});
    let mut client = Client::default();
    let login = client.send(&panel, "POST", "/api/auth/login", &[], Some(r#"{"username":"owner","password":"x"}"#));
    assert_eq!(login.status, 403);
    client.login(&panel, "owner", OWNER_PASSWORD);
    assert_eq!(client.send(&panel, "POST", "/api/keys", &[], Some(r#"{"name":"a","scope":"monitor"}"#)).status, 403);
}

#[test]
fn logout_invalidates_session() {
    let panel = server(|_| {});
    let mut client = Client::default();
    client.login(&panel, "owner", OWNER_PASSWORD);
    let csrf = client.csrf();
    let session = client.cookie("panel_session").unwrap();
    let logout = client.send(&panel, "POST", "/api/auth/logout", &[("X-CSRF-Token", &csrf)], None);
    assert_eq!(logout.status, 204);
    assert_eq!(client.cookie("panel_session"), None, "the cookie is deleted");
    client.set_cookie("panel_session", &session);
    assert_eq!(client.send(&panel, "GET", "/api/auth/me", &[], None).status, 401, "and the session is gone");
}

#[test]
fn login_rate_limit_is_enforced() {
    let panel = server(|_| {});
    let mut client = Client::default();
    client.send(&panel, "GET", "/login", &[], None);
    let csrf = client.csrf();
    let wrong = r#"{"username":"owner","password":"wrong-password"}"#;
    for _ in 0..3 {
        assert_eq!(client.send(&panel, "POST", "/api/auth/login", &[("X-CSRF-Token", &csrf)], Some(wrong)).status, 401);
    }
    let blocked = client.send(&panel, "POST", "/api/auth/login", &[("X-CSRF-Token", &csrf)], Some(wrong));
    assert_eq!((blocked.status, blocked.header("retry-after")), (429, Some("60")));
}

#[test]
fn concurrent_login_batch_reserves_attempts_and_bounds_argon2() {
    let panel = server(|_| {});
    let mut client = Client::default();
    client.send(&panel, "GET", "/login", &[], None);
    let csrf = client.csrf();
    let wrong = r#"{"username":"owner","password":"wrong-password"}"#;
    let statuses: Vec<u16> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (mut client, csrf, panel) = (client.clone(), csrf.clone(), &panel);
                scope.spawn(move || {
                    client.send(panel, "POST", "/api/auth/login", &[("X-CSRF-Token", &csrf)], Some(wrong)).status
                })
            })
            .collect();
        handles.into_iter().map(|handle| handle.join().unwrap()).collect()
    });
    assert_eq!(statuses.iter().filter(|status| **status == 401).count(), 3);
    assert_eq!(statuses.iter().filter(|status| **status == 429).count(), 5);
    assert_eq!(panel.state.login_slots.available_permits(), 2, "every verification slot was given back");
}

#[test]
fn successful_login_releases_only_its_own_reservation() {
    let panel = server(|_| {});
    let mut client = Client::default();
    client.send(&panel, "GET", "/login", &[], None);
    let csrf = client.csrf();
    let wrong = r#"{"username":"owner","password":"wrong-password"}"#;
    for _ in 0..2 {
        assert_eq!(client.send(&panel, "POST", "/api/auth/login", &[("X-CSRF-Token", &csrf)], Some(wrong)).status, 401);
    }
    assert_eq!(client.login(&panel, "owner", OWNER_PASSWORD).status, 204);
    client.send(&panel, "GET", "/login", &[], None);
    let csrf = client.csrf();
    assert_eq!(client.send(&panel, "POST", "/api/auth/login", &[("X-CSRF-Token", &csrf)], Some(wrong)).status, 401);
    assert_eq!(client.send(&panel, "POST", "/api/auth/login", &[("X-CSRF-Token", &csrf)], Some(wrong)).status, 429);
}

#[test]
fn successful_login_preserves_concurrent_failed_reservation() {
    let panel = server(|_| {});
    let mut client = Client::default();
    client.send(&panel, "GET", "/login", &[], None);
    let csrf = client.csrf();
    let wrong = r#"{"username":"owner","password":"wrong-password"}"#;
    let right = json!({"username": "owner", "password": OWNER_PASSWORD}).to_string();
    let (valid, failed) = std::thread::scope(|scope| {
        let (mut first, mut second) = (client.clone(), client.clone());
        let (csrf_a, csrf_b, panel_a, panel_b, right) = (csrf.clone(), csrf.clone(), &panel, &panel, right.as_str());
        let valid = scope.spawn(move || {
            first.send(panel_a, "POST", "/api/auth/login", &[("X-CSRF-Token", &csrf_a)], Some(right)).status
        });
        let failed = scope.spawn(move || {
            second.send(panel_b, "POST", "/api/auth/login", &[("X-CSRF-Token", &csrf_b)], Some(wrong)).status
        });
        (valid.join().unwrap(), failed.join().unwrap())
    });
    assert_eq!((valid, failed), (204, 401));
    for _ in 0..2 {
        assert_eq!(client.send(&panel, "POST", "/api/auth/login", &[("X-CSRF-Token", &csrf)], Some(wrong)).status, 401);
    }
    assert_eq!(client.send(&panel, "POST", "/api/auth/login", &[("X-CSRF-Token", &csrf)], Some(wrong)).status, 429);
}

#[test]
fn body_limit_and_validation() {
    let panel = server(|_| {});
    let mut client = Client::default();
    client.login(&panel, "owner", OWNER_PASSWORD);
    let csrf = client.csrf();
    let oversized = format!(r#"{{"name":"{}"}}"#, "a".repeat(70000));
    assert_eq!(client.send(&panel, "POST", "/api/keys", &[("X-CSRF-Token", &csrf)], Some(&oversized)).status, 413);
    assert_eq!(
        client
            .send(&panel, "POST", "/api/keys", &[("X-CSRF-Token", &csrf)], Some(r#"{"name":"","scope":"admin"}"#))
            .status,
        422
    );
}

#[test]
fn admin_key_reads_and_mutates_without_a_session() {
    let panel = server(|_| {});
    let mut client = Client::default();
    let body = create_key(&panel, &mut client, "admin");
    let mut bare = Client::default();
    let bearer = format!("Bearer {}", body["plaintext"].as_str().unwrap());
    assert_eq!(bare.send(&panel, "GET", "/api/auth/me", &[("Authorization", &bearer)], None).json()["via"], "api-key");
    let created = bare.send(
        &panel,
        "POST",
        "/api/keys",
        &[("Authorization", &bearer)],
        Some(r#"{"name":"via key","scope":"monitor"}"#),
    );
    assert_eq!(created.status, 201);
    let audit = bare.send(&panel, "GET", "/api/audit", &[("Authorization", &bearer)], None).json();
    assert!(audit["items"].as_array().unwrap().iter().any(|row| row["actor_username"] == "key:t"));
}

#[test]
fn monitor_key_is_read_only() {
    let panel = server(|_| {});
    let mut client = Client::default();
    let body = create_key(&panel, &mut client, "monitor");
    let mut bare = Client::default();
    let bearer = format!("Bearer {}", body["plaintext"].as_str().unwrap());
    assert_eq!(bare.send(&panel, "GET", "/api/audit", &[("Authorization", &bearer)], None).status, 200);
    let create = bare.send(
        &panel,
        "POST",
        "/api/keys",
        &[("Authorization", &bearer)],
        Some(r#"{"name":"x","scope":"monitor"}"#),
    );
    assert_eq!(create.status, 403);
}

#[test]
fn node_sync_key_reaches_only_the_fleet_api() {
    let panel = server(|_| {});
    let mut client = Client::default();
    let body = create_key(&panel, &mut client, "node-sync");
    let mut bare = Client::default();
    let bearer = format!("Bearer {}", body["plaintext"].as_str().unwrap());
    let refused = bare.send(&panel, "GET", "/api/audit", &[("Authorization", &bearer)], None);
    assert_eq!((refused.status, refused.json()), (403, json!({"detail": "node-sync key is limited to the fleet API"})));
    // On `/api/fleet/v2/*` (WP12a) the key goes through.
    assert_eq!(bare.send(&panel, "GET", "/api/fleet/v2/identity", &[("Authorization", &bearer)], None).status, 200);
}

#[test]
fn bad_missing_or_disabled_key_is_401() {
    let panel = server(|_| {});
    let mut client = Client::default();
    let body = create_key(&panel, &mut client, "admin");
    let csrf = client.csrf();
    let path = format!("/api/keys/{}/enabled", body["key"]["id"]);
    assert_eq!(
        client.send(&panel, "POST", &path, &[("X-CSRF-Token", &csrf)], Some(r#"{"enabled":false}"#)).status,
        200
    );
    let mut bare = Client::default();
    let bearer = format!("Bearer {}", body["plaintext"].as_str().unwrap());
    assert_eq!(bare.send(&panel, "GET", "/api/audit", &[("Authorization", &bearer)], None).status, 401);
    assert_eq!(bare.send(&panel, "GET", "/api/audit", &[("Authorization", "Bearer pc_nope_x")], None).status, 401);
}

#[test]
fn key_management_is_owner_only_and_never_lists_plaintext() {
    let panel = server(|_| {});
    let mut client = Client::default();
    let body = create_key(&panel, &mut client, "admin");
    let listed = client.send(&panel, "GET", "/api/keys", &[], None);
    let text = String::from_utf8_lossy(&listed.body).to_string();
    assert!(listed.status == 200 && !text.contains("plaintext") && !text.contains(body["plaintext"].as_str().unwrap()));
    let csrf = client.csrf();
    let admin = json!({"username": "adm", "password": OWNER_PASSWORD, "role": "admin"}).to_string();
    assert_eq!(client.send(&panel, "POST", "/api/admins", &[("X-CSRF-Token", &csrf)], Some(&admin)).status, 201);
    client.send(&panel, "POST", "/api/auth/logout", &[("X-CSRF-Token", &csrf)], None);
    client.login(&panel, "adm", OWNER_PASSWORD);
    let csrf = client.csrf();
    let refused =
        client.send(&panel, "POST", "/api/keys", &[("X-CSRF-Token", &csrf)], Some(r#"{"name":"n","scope":"admin"}"#));
    assert_eq!(refused.status, 403);
}

#[test]
fn key_rate_limit_answers_429() {
    let panel = server(|settings| settings.api_key_rate_per_minute = 3);
    let mut client = Client::default();
    let body = create_key(&panel, &mut client, "monitor");
    let mut bare = Client::default();
    let bearer = format!("Bearer {}", body["plaintext"].as_str().unwrap());
    let codes: Vec<u16> =
        (0..4).map(|_| bare.send(&panel, "GET", "/api/audit", &[("Authorization", &bearer)], None).status).collect();
    assert_eq!(codes, [200, 200, 200, 429]);
}

#[test]
fn viewer_cannot_mutate_and_admin_cannot_manage_admins() {
    let panel = server(|_| {});
    panel.state.store.create_admin("viewer", "viewer password long enough", "viewer").unwrap();
    panel.state.store.create_admin("admin", "admin password long enough", "admin").unwrap();
    let mut client = Client::default();
    client.login(&panel, "viewer", "viewer password long enough");
    let csrf = client.csrf();
    assert_eq!(
        client
            .send(&panel, "POST", "/api/keys", &[("X-CSRF-Token", &csrf)], Some(r#"{"name":"a","scope":"monitor"}"#))
            .status,
        403
    );
    client.send(&panel, "POST", "/api/auth/logout", &[("X-CSRF-Token", &csrf)], None);
    client.login(&panel, "admin", "admin password long enough");
    let csrf = client.csrf();
    let new = json!({"username": "new", "password": "long password for new", "role": "viewer"}).to_string();
    assert_eq!(client.send(&panel, "POST", "/api/admins", &[("X-CSRF-Token", &csrf)], Some(&new)).status, 403);
}

#[test]
fn last_owner_cannot_be_deleted_or_demoted() {
    let panel = server(|_| {});
    let mut client = Client::default();
    client.login(&panel, "owner", OWNER_PASSWORD);
    let csrf = client.csrf();
    let admins = client.send(&panel, "GET", "/api/admins", &[], None).json();
    let owner =
        admins["items"].as_array().unwrap().iter().find(|row| row["username"] == "owner").unwrap()["id"].clone();
    let path = format!("/api/admins/{owner}");
    assert_eq!(
        client.send(&panel, "PATCH", &path, &[("X-CSRF-Token", &csrf)], Some(r#"{"role":"admin"}"#)).status,
        409
    );
    assert_eq!(
        client.send(&panel, "PATCH", &path, &[("X-CSRF-Token", &csrf)], Some(r#"{"active":false}"#)).status,
        409
    );
    assert_eq!(client.send(&panel, "DELETE", &path, &[("X-CSRF-Token", &csrf)], None).status, 409);
}

#[test]
fn mutations_create_secret_free_audit_records() {
    let panel = server(|_| {});
    let mut client = Client::default();
    let body = create_key(&panel, &mut client, "monitor");
    let audit = client.send(&panel, "GET", "/api/audit", &[], None);
    let text = String::from_utf8_lossy(&audit.body).to_string();
    let rows = audit.json()["items"].as_array().unwrap().clone();
    assert!(rows.iter().any(|row| row["action"] == "api_key.create" && row["actor_username"] == "owner"));
    assert!(!text.contains(body["plaintext"].as_str().unwrap()));
}

#[test]
fn viewer_can_read_secret_free_audit() {
    let panel = server(|_| {});
    panel.state.store.create_admin("viewer", "viewer password long enough", "viewer").unwrap();
    let mut client = Client::default();
    client.login(&panel, "viewer", "viewer password long enough");
    let response = client.send(&panel, "GET", "/api/audit", &[], None);
    assert_eq!(response.status, 200);
    assert!(!String::from_utf8_lossy(&response.body).to_lowercase().contains("secret"));
}

#[test]
fn audit_cursor_and_filters_are_backward_compatible() {
    let panel = server(|_| {});
    let mut client = Client::default();
    client.login(&panel, "owner", OWNER_PASSWORD);
    let csrf = client.csrf();
    for name in ["alice", "bob", "carol"] {
        let body = json!({"name": name, "scope": "monitor"}).to_string();
        assert_eq!(client.send(&panel, "POST", "/api/keys", &[("X-CSRF-Token", &csrf)], Some(&body)).status, 201);
    }
    let first = client.send(&panel, "GET", "/api/audit?limit=2&actor=OWNER&action=api_key.create", &[], None).json();
    let targets: Vec<String> =
        first["items"].as_array().unwrap().iter().map(|row| row["target"].as_str().unwrap().to_string()).collect();
    assert_eq!(targets, ["3", "2"]);
    assert_eq!(first["next_cursor"], first["items"][1]["id"]);
    let second = client
        .send(
            &panel,
            "GET",
            &format!("/api/audit?limit=2&before_id={}&actor=owner&action=api_key.create", first["next_cursor"]),
            &[],
            None,
        )
        .json();
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert_eq!(second["items"][0]["target"], "1");
    assert!(second.get("next_cursor").is_none());
    let targeted = client.send(&panel, "GET", "/api/audit?target=1&action=api_key.create", &[], None).json();
    assert_eq!(targeted["items"].as_array().unwrap().len(), 1);
    assert_eq!(targeted["items"][0]["actor_username"], "owner");
}

#[test]
fn reveals_are_bound_to_their_session() {
    let panel = server(|_| {});
    let mut owner = Client::default();
    owner.login(&panel, "owner", OWNER_PASSWORD);
    let session = panel.state.store.session(owner.cookie("panel_session").as_deref()).unwrap().unwrap();
    let token = panel.state.reveals.create(json!({"secret": "s"}), &session.token_hash);
    panel.state.store.create_admin("other", OWNER_PASSWORD, "owner").unwrap();
    let mut other = Client::default();
    other.login(&panel, "other", OWNER_PASSWORD);
    let path = format!("/api/reveal/{token}");
    let foreign = other.send(&panel, "GET", &path, &[], None);
    assert_eq!((foreign.status, foreign.json()), (403, json!({"detail": "reveal belongs to another session"})));
    assert_eq!(owner.send(&panel, "GET", &path, &[], None).json(), json!({"secret": "s"}));
    assert_eq!(owner.send(&panel, "GET", &path, &[], None).status, 410);
}
