//! Runtime authorization evidence for the Python route-coverage audit. The operation inventory
//! comes from the same `routes::all()` table used by the running server, never from OpenAPI labels.
//! Requests go through the real HTTP stack over an isolated Unix socket and synthetic database.
mod common;

use std::collections::BTreeSet;

use common::{Client, Panel};
use serde_json::{json, Value};

const PUBLIC: &[(&str, &str)] = &[
    ("GET", "/"),
    ("GET", "/favicon.ico"),
    ("GET", "/healthz"),
    ("GET", "/login"),
    ("POST", "/api/auth/login"),
    ("GET", "/s/{token}"),
    ("HEAD", "/s/{token}"),
];

fn concrete_path(template: &str) -> String {
    let mut path = String::new();
    let mut remaining = template;
    while let Some(start) = remaining.find('{') {
        path.push_str(&remaining[..start]);
        let end = remaining[start..].find('}').expect("route parameter has a closing brace") + start;
        path.push_str(match &remaining[start + 1..end] {
            "protocol" => "naive",
            "component" => "telemt",
            "action" => "disable",
            "token" => "not-a-token",
            _ => "1",
        });
        remaining = &remaining[end + 1..];
    }
    path.push_str(remaining);
    path
}

fn observed(answer: &common::Answer) -> String {
    serde_json::from_slice::<Value>(&answer.body)
        .ok()
        .and_then(|value| value.get("detail").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default()
}

#[test]
fn audit_registered_route_gates_over_http() {
    let panel: Panel = common::start_with(&[], |settings| settings.api_key_rate_per_minute = 1000);
    panel.state.store.create_admin("owner", "correct horse battery staple", "owner").unwrap();
    panel.state.store.create_admin("viewer", "correct horse battery staple", "viewer").unwrap();
    let mut owner = Client::default();
    assert_eq!(owner.login(&panel, "owner", "correct horse battery staple").status, 204);
    let mut viewer = Client::default();
    assert_eq!(viewer.login(&panel, "viewer", "correct horse battery staple").status, 204);
    let mut admin = Client::default();
    panel.state.store.create_admin("admin", "correct horse battery staple", "admin").unwrap();
    assert_eq!(admin.login(&panel, "admin", "correct horse battery staple").status, 204);
    let routes = panel_web::routes::all();
    let mut keys = BTreeSet::new();
    let mut rows = Vec::new();
    let mut schema_keys = BTreeSet::new();
    let schema: Value = serde_json::from_slice(panel_web::routes::openapi::DOCUMENT).unwrap();
    let csrf = owner.csrf();
    let key_response = owner.send(&panel, "POST", "/api/keys", &[("X-CSRF-Token", &csrf)],
                                  Some(r#"{"name":"route-audit","scope":"node-sync"}"#));
    assert_eq!(key_response.status, 201);
    let bearer = format!("Bearer {}", key_response.json()["plaintext"].as_str().unwrap());
    for route in routes.routes() {
        if route.template() == "/static" {
            continue; // mount, not an operation; static shell is checked by the HTTP tests
        }
        for method in route.methods() {
            let method = method.as_str();
            let template = route.template();
            assert!(keys.insert((method.to_owned(), template.to_owned())), "duplicate route {method} {template}");
            if route.in_schema() {
                schema_keys.insert((method.to_owned(), template.to_owned()));
            }
            let url = concrete_path(template);
            let body = if template == "/api/auth/login" {
                Some(r#"{"username":"owner","password":"wrong password"}"#)
            } else {
                matches!(method, "POST" | "PUT" | "PATCH" | "DELETE").then_some("{}")
            };
            let public = PUBLIC.contains(&(method, template));
            let anonymous = Client::default().send(&panel, method, &url, &[], body);
            let mut row = json!({
                "method": method,
                "path": template,
                "inventory": "panel_web::routes::all",
                "anonymous_status": anonymous.status,
                "anonymous_detail": observed(&anonymous),
                "in_schema": route.in_schema(),
            });
            if !public && body.is_some() {
                let no_csrf = owner.send(&panel, method, &url, &[], body);
                row["session_no_csrf_status"] = json!(no_csrf.status);
                row["session_no_csrf_detail"] = json!(observed(&no_csrf));
                if (method, template) != ("POST", "/api/auth/logout") {
                    let csrf = owner.csrf();
                    let with_csrf = owner.send(&panel, method, &url, &[("X-CSRF-Token", &csrf)], body);
                    row["session_csrf_status"] = json!(with_csrf.status);
                    row["session_csrf_detail"] = json!(observed(&with_csrf));
                    let csrf = viewer.csrf();
                    let viewer_response = viewer.send(&panel, method, &url, &[("X-CSRF-Token", &csrf)], body);
                    row["viewer_status"] = json!(viewer_response.status);
                    row["viewer_detail"] = json!(observed(&viewer_response));
                    let csrf = admin.csrf();
                    let admin_response = admin.send(&panel, method, &url, &[("X-CSRF-Token", &csrf)], body);
                    row["admin_status"] = json!(admin_response.status);
                    row["admin_detail"] = json!(observed(&admin_response));
                }
            } else if !public {
                let viewer_response = viewer.send(&panel, method, &url, &[], None);
                row["viewer_status"] = json!(viewer_response.status);
                row["viewer_detail"] = json!(observed(&viewer_response));
                let owner_response = owner.send(&panel, method, &url, &[], None);
                row["owner_status"] = json!(owner_response.status);
                row["owner_detail"] = json!(observed(&owner_response));
                let admin_response = admin.send(&panel, method, &url, &[], None);
                row["admin_status"] = json!(admin_response.status);
                row["admin_detail"] = json!(observed(&admin_response));
            }
            if !public && template.starts_with("/api/fleet/v2/") {
                let key_response = Client::default().send(&panel, method, &url,
                                                          &[("Authorization", &bearer)], body);
                row["node_key_status"] = json!(key_response.status);
                row["node_key_detail"] = json!(observed(&key_response));
            }
            rows.push(row);
        }
    }
    assert_eq!(keys.iter().filter(|(m, p)| PUBLIC.contains(&(m.as_str(), p.as_str()))).count(), PUBLIC.len());
    let document_keys: BTreeSet<(String, String)> = schema["paths"].as_object().unwrap().iter().flat_map(|(path, ops)| {
        ops.as_object().unwrap().keys().filter(|method| ["get", "post", "put", "patch", "delete", "head"]
            .contains(&method.as_str())).map(|method| (method.to_ascii_uppercase(), path.clone()))
    }).collect();
    assert_eq!(schema_keys, document_keys, "native router and published OpenAPI diverged");
    rows.sort_by(|a, b| (a["path"].as_str(), a["method"].as_str()).cmp(&(b["path"].as_str(), b["method"].as_str())));
    println!("ROUTE_GATE_INVENTORY_BEGIN{}ROUTE_GATE_INVENTORY_END", serde_json::to_string(&rows).unwrap());
}

#[test]
fn scoped_keys_and_admin_role_reach_only_their_http_boundaries() {
    let panel = common::start(&[]);
    panel.state.store.create_admin("owner", "correct horse battery staple", "owner").unwrap();
    panel.state.store.create_admin("admin", "correct horse battery staple", "admin").unwrap();
    let mut owner = Client::default();
    assert_eq!(owner.login(&panel, "owner", "correct horse battery staple").status, 204);
    let mut admin = Client::default();
    assert_eq!(admin.login(&panel, "admin", "correct horse battery staple").status, 204);
    let admin_csrf = admin.csrf();
    let refusal = admin.send(&panel, "POST", "/api/keys", &[("X-CSRF-Token", &admin_csrf)],
                             Some(r#"{"name":"foreign","scope":"admin"}"#));
    assert_eq!((refusal.status, observed(&refusal).as_str()), (403, "insufficient role"));
    let csrf = owner.csrf();
    for scope in ["monitor", "node-sync"] {
        let body = format!(r#"{{"name":"{scope}","scope":"{scope}"}}"#);
        let created = owner.send(&panel, "POST", "/api/keys", &[("X-CSRF-Token", &csrf)], Some(&body));
        assert_eq!(created.status, 201);
        let bearer = format!("Bearer {}", created.json()["plaintext"].as_str().unwrap());
        let read = Client::default().send(&panel, "GET", "/api/host",
                                          &[("Authorization", &bearer)], None);
        if scope == "monitor" {
            assert_eq!(read.status, 200);
            let write = Client::default().send(&panel, "POST", "/api/keys",
                                               &[("Authorization", &bearer)],
                                               Some(r#"{"name":"unauthorized","scope":"admin"}"#));
            assert_eq!((write.status, observed(&write).as_str()), (403, "insufficient role"));
            let fleet = Client::default().send(&panel, "GET", "/api/fleet/v2/identity",
                                               &[("Authorization", &bearer)], None);
            assert_eq!((fleet.status, observed(&fleet).as_str()),
                       (403, "a node-sync or admin API key is required"));
        } else {
            assert_eq!((read.status, observed(&read).as_str()),
                       (403, "node-sync key is limited to the fleet API"));
            let fleet = Client::default().send(&panel, "GET", "/api/fleet/v2/identity",
                                               &[("Authorization", &bearer)], None);
            assert_eq!(fleet.status, 200, "node-sync key must reach the fleet handler");
        }
    }
}
