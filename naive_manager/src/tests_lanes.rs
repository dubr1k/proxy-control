//! Lanes (v0.7), ported from `tests/test_naive_manager_lanes.py`: one `forward_proxy` handler
//! per grant lane inside the managed LANES block, each with its users and its own upstream,
//! and the service's own handler last with everyone else.

use std::path::Path;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::caddyfile::{BEGIN, END};
use crate::error::Error;
use crate::lanes::{lanes_span, LANES_BEGIN, LANES_END};
use crate::pyutil::{splitlines, strip};
use crate::service::NaiveManager;
use crate::tests::{call, manager_with, parse, read, serve, settings, tempdir, Adapter, TestHooks};
use crate::tests_egress::{router_doc, router_secret, ROUTER, WARP};

fn lane_a() -> Value {
    json!({"lane": "grant:7f3a", "users": ["old-user"], "upstream": {"user": "grant-7f3a", "password": "A".repeat(43)}})
}

fn lane_b() -> Value {
    json!({"lane": "grant:b2c4", "users": ["second"], "upstream": {"user": "grant-b2c4", "password": "B".repeat(43)}})
}

fn lane_manager(dir: &Path, hooks: &TestHooks, router: Option<&str>) -> Arc<NaiveManager> {
    let credential = dir.join("xray-router-ingress");
    std::fs::write(&credential, format!("{}\n", router_secret())).unwrap();
    let mut settings = settings(dir);
    settings.provider_url = Some(WARP.into());
    settings.router_url = router.map(String::from);
    settings.router_credential_file = router.map(|_| credential);
    let instance = manager_with(dir, hooks, settings);
    instance.bootstrap().unwrap();
    instance
}

fn hooks() -> TestHooks {
    TestHooks::new(Adapter::Lanes)
}

fn lanes_block(text: &str) -> Vec<String> {
    let lines = splitlines(text);
    let (start, end) = lanes_span(&lines).unwrap().expect("a lanes block");
    lines[start..=end].iter().map(|l| l.to_string()).collect()
}

fn caddyfile(instance: &NaiveManager) -> String {
    read(&instance.settings.caddyfile)
}

fn lanes_of_users(instance: &NaiveManager) -> Vec<Value> {
    instance.list_users().unwrap().as_array().unwrap().iter().map(|row| row["lane"].clone()).collect()
}

#[test]
fn set_lanes_renders_one_handler_per_lane_before_the_service_handler() {
    let dir = tempdir("lanes-render");
    let hooks = hooks();
    let instance = lane_manager(&dir, &hooks, Some(ROUTER));
    let reloads = hooks.reloads();
    let view = instance.set_lanes(&json!({"lanes": [lane_a()]})).unwrap();
    let text = caddyfile(&instance);
    let block = lanes_block(&text);
    assert!(strip(&block[0]) == LANES_BEGIN && strip(block.last().unwrap()) == LANES_END);
    let body = block.join("\n");
    assert!(body.contains("basic_auth old-user old-password"));
    assert!(body.contains(&format!("upstream socks5://grant-7f3a:{}@127.0.0.1:45101", "A".repeat(43))));
    assert!(body.contains("hide_ip") && body.contains("hide_via") && body.contains("probe_resistance"));
    // The lanes block sits inside `route {` before the service's forward_proxy; the user left
    // the USERS block.
    let lines = splitlines(&text);
    let route = lines.iter().position(|l| crate::text::is_route_start(l)).unwrap();
    let (start, end) = lanes_span(&lines).unwrap().unwrap();
    let service = lines.iter().rposition(|l| crate::text::is_forward_proxy_block(l)).unwrap();
    assert!(route < start && start < end && end < service);
    let users_begin = lines.iter().position(|l| strip(l) == BEGIN).unwrap();
    let users_end = lines.iter().position(|l| strip(l) == END).unwrap();
    let users: Vec<&str> =
        lines[users_begin + 1..users_end].iter().map(|l| l.split_whitespace().nth(1).unwrap()).collect();
    assert_eq!(users, ["second"]);
    assert!(hooks.reloads() == reloads + 1 && hooks.probes() >= 1);
    // The view names lanes and users, masks the upstream, and the state remembers the lane.
    assert_eq!(
        view,
        json!({"lanes": [{"lane": "grant:7f3a", "users": ["old-user"], "upstream": "socks5://***@127.0.0.1:45101", "enabled_users": 1}]})
    );
    assert!(!view.to_string().contains(&"A".repeat(43)));
    let state: Value = serde_json::from_str(&read(&instance.settings.state_file)).unwrap();
    let row = state["users"].as_array().unwrap().iter().find(|row| row["username"] == "old-user").unwrap();
    assert_eq!(row["lane"], "grant:7f3a");
    assert!(read(&instance.settings.state_file).contains(&"A".repeat(43)));
    assert_eq!(lanes_of_users(&instance), [json!("grant:7f3a"), Value::Null]);
    // The service's own egress and users are untouched.
    assert_eq!(crate::egress::parse(&text).unwrap().mode, "custom");
    assert_eq!(instance.egress().unwrap()["mode"], "custom");
}

#[test]
fn lanes_replace_move_and_empty_out() {
    let dir = tempdir("lanes-replace");
    let instance = lane_manager(&dir, &hooks(), Some(ROUTER));
    instance.set_lanes(&json!({"lanes": [lane_a(), lane_b()]})).unwrap();
    let text = caddyfile(&instance);
    assert_eq!(text.matches("forward_proxy {").count(), 3);
    let joined = lanes_block(&text).join("\n");
    assert!(joined.find("grant-7f3a").unwrap() < joined.find("grant-b2c4").unwrap());
    // Moving a user between lanes, dropping a lane.
    let moved = json!({"lane": "grant:b2c4", "users": ["old-user", "second"], "upstream": lane_b()["upstream"]});
    instance.set_lanes(&json!({"lanes": [moved]})).unwrap();
    let text = caddyfile(&instance);
    assert!(text.matches("forward_proxy {").count() == 2 && !text.contains("grant-7f3a"));
    let users_block = lanes_block(&text).join("\n");
    assert!(users_block.contains("basic_auth old-user") && users_block.contains("basic_auth second"));
    assert_eq!(
        instance.lanes().unwrap(),
        json!({"lanes": [{"lane": "grant:b2c4", "users": ["old-user", "second"],
                          "upstream": "socks5://***@127.0.0.1:45101", "enabled_users": 2}]})
    );
    // No lanes at all: the block disappears, everybody is back in the USERS block.
    instance.set_lanes(&json!({"lanes": []})).unwrap();
    let text = caddyfile(&instance);
    assert!(!text.contains(LANES_BEGIN) && text.matches("forward_proxy {").count() == 1);
    assert_eq!(lanes_of_users(&instance), [Value::Null, Value::Null]);
    assert_eq!(instance.lanes().unwrap(), json!({"lanes": []}));
}

#[test]
fn disabled_users_stay_out_of_the_lane_handler_but_keep_their_lane() {
    let dir = tempdir("lanes-disabled");
    let instance = lane_manager(&dir, &hooks(), Some(ROUTER));
    instance.set_lanes(&json!({"lanes": [lane_a()]})).unwrap();
    instance.set_enabled("old-user", false).unwrap();
    assert!(!caddyfile(&instance).contains(LANES_BEGIN)); // a lane with no enabled user renders no handler
    assert_eq!(instance.lanes().unwrap()["lanes"][0]["enabled_users"], 0);
    instance.set_enabled("old-user", true).unwrap();
    assert!(lanes_block(&caddyfile(&instance)).join("\n").contains("basic_auth old-user"));
    // A rotated password lands in the lane handler, not in the USERS block.
    instance.rotate("old-user", None, None).unwrap();
    let state: Value = serde_json::from_str(&read(&instance.settings.state_file)).unwrap();
    let password = state["users"].as_array().unwrap().iter().find(|r| r["username"] == "old-user").unwrap()["password"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(lanes_block(&caddyfile(&instance)).join("\n").contains(&format!("basic_auth old-user {password}")));
    // Taking the user out of the lane removes the handler.
    instance.set_lanes(&json!({"lanes": []})).unwrap();
    assert!(!caddyfile(&instance).contains(LANES_BEGIN));
}

#[test]
fn set_lanes_refuses_bad_requests_before_any_io() {
    let bodies = [
        json!({"lanes": [{"lane": "svc:naive", "users": ["old-user"], "upstream": lane_a()["upstream"]}]}),
        json!({"lanes": [{"lane": "grant:7f3a", "users": ["nobody"], "upstream": lane_a()["upstream"]}]}),
        json!({"lanes": [lane_a(), {"lane": "grant:x", "users": ["old-user"], "upstream": lane_b()["upstream"]}]}),
        json!({"lanes": [{"lane": "grant:7f3a", "users": [], "upstream": lane_a()["upstream"]}]}),
        json!({"lanes": [{"lane": "grant:7f3a", "users": ["old-user"], "upstream": {"user": "grant-7f3a"}}]}),
        json!({"lanes": [{"lane": "grant:7f3a", "users": ["old-user"], "upstream": {"user": "bad user", "password": "A".repeat(43)}}]}),
        json!({"lanes": [{"lane": "grant:7f3a", "users": ["old-user"], "upstream": lane_a()["upstream"], "extra": 1}]}),
        json!({"lanes": [lane_a(), lane_a()]}),
        json!({"lanes": "nope"}),
        json!({}),
    ];
    for (index, body) in bodies.into_iter().enumerate() {
        let dir = tempdir(&format!("lanes-bad-{index}"));
        let hooks = hooks();
        let instance = lane_manager(&dir, &hooks, Some(ROUTER));
        let reloads = hooks.reloads();
        let err = instance.set_lanes(&body).unwrap_err();
        assert!(matches!(&err, Error::Conflict { code, .. } if code == "lanes_invalid"), "{body}: {err:?}");
        assert_eq!(hooks.reloads(), reloads);
        assert!(!caddyfile(&instance).contains(LANES_BEGIN));
    }
}

#[test]
fn lanes_need_the_router_and_a_failed_reload_restores_everything() {
    let dir = tempdir("lanes-router");
    std::fs::create_dir_all(dir.join("no-router")).unwrap();
    let without = lane_manager(&dir.join("no-router"), &hooks(), None);
    let err = without.set_lanes(&json!({"lanes": [lane_a()]})).unwrap_err();
    assert!(matches!(&err, Error::EgressInvalid(m) if m.contains("router")), "{err:?}");
    let hooks = hooks();
    let instance = lane_manager(&dir, &hooks, Some(ROUTER));
    let (before, state) = (caddyfile(&instance), read(&instance.settings.state_file));
    let next = hooks.reloads() + 1;
    hooks.get().fail_reload_calls = [next].into();
    assert!(instance.set_lanes(&json!({"lanes": [lane_a()]})).unwrap_err().is_runtime());
    assert_eq!(caddyfile(&instance), before);
    assert_eq!(read(&instance.settings.state_file), state);
    assert_eq!(instance.lanes().unwrap(), json!({"lanes": []}));
}

#[test]
fn a_lane_handler_changed_outside_the_manager_is_a_conflict() {
    let dir = tempdir("lanes-drift");
    let instance = lane_manager(&dir, &hooks(), Some(ROUTER));
    instance.set_lanes(&json!({"lanes": [lane_a()]})).unwrap();
    let text = caddyfile(&instance).replace("basic_auth old-user old-password", "basic_auth old-user other");
    std::fs::write(&instance.settings.caddyfile, text).unwrap();
    let err = instance.set_enabled("second", false).unwrap_err();
    assert!(err.is_conflict() && err.message().contains("outside manager"), "{err:?}");
}

#[test]
fn egress_readback_and_bootstrap_keep_working_with_lanes() {
    let dir = tempdir("lanes-egress");
    let instance = lane_manager(&dir, &hooks(), Some(ROUTER));
    instance.set_lanes(&json!({"lanes": [lane_a()]})).unwrap();
    let revision = instance.egress().unwrap()["revision"].as_str().unwrap().to_string();
    instance.egress_apply(&revision, &router_doc(), "op-router").unwrap();
    let text = caddyfile(&instance);
    assert_eq!(text.matches("forward_proxy {").count(), 2);
    assert!(text.contains(&format!("upstream socks5://naive-a1b2c3d4:{}@127.0.0.1:45101", "K".repeat(40))));
    assert_eq!(instance.egress().unwrap()["mode"], "proxy");
    // A second manager over the same files (a restart) sees the same lanes and users.
    let mut settings = settings(&dir);
    settings.provider_url = Some(WARP.into());
    settings.router_url = Some(ROUTER.into());
    settings.router_credential_file = Some(dir.join("xray-router-ingress"));
    let again = manager_with(&dir, &hooks(), settings);
    again.bootstrap().unwrap();
    assert_eq!(again.lanes().unwrap()["lanes"][0]["lane"], "grant:7f3a");
    assert_eq!(lanes_of_users(&again), [json!("grant:7f3a"), Value::Null]);
}

#[test]
fn unix_api_lanes_routes() {
    let dir = tempdir("lanes-api");
    let instance = lane_manager(&dir, &hooks(), Some(ROUTER));
    let api = serve(&instance, &dir, "internal-token");
    let token = Some("internal-token");
    assert_eq!(call(&api, "GET", "/v1/lanes", None, None).0, 401);
    assert_eq!(parse(&call(&api, "GET", "/v1/lanes", None, token).1), json!({"lanes": []}));
    let (status, body) = call(&api, "PUT", "/v1/lanes", Some(json!({"lanes": [lane_a()]})), token);
    assert_eq!((status, parse(&body)["lanes"][0]["users"].clone()), (200, json!(["old-user"])));
    assert!(!body.contains(&"A".repeat(43)));
    assert_eq!(parse(&body)["lanes"][0]["upstream"], "socks5://***@127.0.0.1:45101");
    let bad = json!({"lanes": [{"lane": "svc:naive", "users": ["old-user"], "upstream": lane_a()["upstream"]}]});
    let (status, body) = call(&api, "PUT", "/v1/lanes", Some(bad), token);
    assert_eq!((status, parse(&body)["code"].clone()), (409, json!("lanes_invalid")));
    assert_eq!(parse(&call(&api, "GET", "/v1/users", None, token).1)[0]["lane"], "grant:7f3a");
    assert_eq!(parse(&call(&api, "PUT", "/v1/lanes", Some(json!({"lanes": []})), token).1), json!({"lanes": []}));
}
