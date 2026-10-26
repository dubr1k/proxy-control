//! WP8 manager failures and read-only fallbacks through the real HTTP stack, compared with the
//! responses recorded from the Python panel (`errors/error_bodies.json`).

mod common;

use common::Client;
use serde_json::{json, Value};

const OWNER_PASSWORD: &str = "correct horse battery staple";

fn golden() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/goldens/errors/error_bodies.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn manager_error_bodies_and_down_overviews_match_python() {
    let panel = common::start(&[
        ("NAIVE_ENABLED", "true"),
        ("NAIVE_PUBLIC_HOST", "naive.example.com"),
        ("MIERU_ENABLED", "true"),
        ("AMNEZIAWG_ENABLED", "true"),
        ("TRUSTTUNNEL_ENABLED", "true"),
        ("TRUSTTUNNEL_PUBLIC_HOST", "gate.example.com"),
    ]);
    panel.state.store.create_admin("owner", OWNER_PASSWORD, "owner").unwrap();
    let mut client = Client::default();
    assert_eq!(client.login(&panel, "owner", OWNER_PASSWORD).status, 204);
    let names = [
        "502:telemt",
        "502:naive",
        "502:mieru",
        "overview:amneziawg-down",
        "overview:trusttunnel-down",
        "dashboard:managers-down",
    ];
    let mut checked = 0;
    for exchange in golden().as_array().unwrap() {
        let name = exchange["name"].as_str().unwrap();
        if !names.contains(&name) {
            continue;
        }
        let answer = client.send(
            &panel,
            exchange["request"]["method"].as_str().unwrap(),
            exchange["request"]["path"].as_str().unwrap(),
            &[],
            None,
        );
        assert_eq!(answer.status as i64, exchange["response"]["status"].as_i64().unwrap(), "{name}");
        assert_eq!(
            String::from_utf8(answer.body).unwrap(),
            exchange["response"]["body"]["text"].as_str().unwrap(),
            "{name}",
        );
        checked += 1;
    }
    assert_eq!(checked, names.len());
    let fallback = client.send(&panel, "GET", "/api/versions", &[], None);
    assert_eq!(fallback.status, 200);
    assert_eq!(fallback.json(), json!({"enabled": false, "components": {}, "reason": "version_agent_unavailable"}),);
    let host = client.send(&panel, "GET", "/api/host", &[], None);
    assert_eq!(host.status, 200);
    assert_eq!(host.json(), json!({"available": false, "reason": "version_agent_unavailable"}));
}
