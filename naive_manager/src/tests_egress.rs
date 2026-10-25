//! The egress API (v0.4/v0.5), ported from `tests/test_naive_manager_egress.py`: get / plan /
//! apply / rollback over the managed block, with the same transaction, read-back and recovery
//! discipline as the user block.

use std::path::Path;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::egress::{EGRESS_BEGIN, EGRESS_END};
use crate::error::Error;
use crate::pyutil::{splitlines, strip};
use crate::service::NaiveManager;
use crate::tests::{bytes, manager_with, read, settings, tempdir, Adapter, TestHooks};

pub const WARP: &str = "socks5://127.0.0.1:45000";
pub const ROUTER: &str = "socks5://127.0.0.1:45101";

pub fn direct_doc() -> Value {
    json!({"schema": 1, "upstream": null, "acl": []})
}

pub fn warp_doc() -> Value {
    json!({"schema": 1, "upstream": {"provider": "warp"}, "acl": []})
}

fn block_doc() -> Value {
    json!({"schema": 1, "upstream": null, "acl": [{"deny": ["example.com", "*.example.com"]}]})
}

pub fn router_doc() -> Value {
    json!({"schema": 1, "upstream": {"provider": "router"}, "acl": []})
}

pub fn router_secret() -> String {
    format!("naive-a1b2c3d4:{}", "K".repeat(40))
}

/// `manager(tmp_path, hooks, provider=…)`, bootstrapped.
fn egress_manager(dir: &Path, hooks: &TestHooks, provider: Option<&str>) -> Arc<NaiveManager> {
    let mut settings = settings(dir);
    settings.provider_url = provider.map(String::from);
    let instance = manager_with(dir, hooks, settings);
    instance.bootstrap().unwrap();
    instance
}

/// A manager that knows its router ingress and the file with its credential.
pub fn router_manager(dir: &Path, hooks: &TestHooks, secret: &str) -> Arc<NaiveManager> {
    let credential = dir.join("xray-router-ingress");
    std::fs::write(&credential, format!("{secret}\n")).unwrap();
    let mut settings = settings(dir);
    settings.provider_url = Some(WARP.into());
    settings.router_url = Some(ROUTER.into());
    settings.router_credential_file = Some(credential);
    hooks.get().greetings.clear();
    let instance = manager_with(dir, hooks, settings);
    instance.bootstrap().unwrap();
    instance
}

fn hooks() -> TestHooks {
    TestHooks::new(Adapter::Egress)
}

pub fn block(text: &str) -> Vec<String> {
    let lines = splitlines(text);
    let begin = lines.iter().position(|l| strip(l) == EGRESS_BEGIN).unwrap();
    let end = lines.iter().position(|l| strip(l) == EGRESS_END).unwrap();
    lines[begin..=end].iter().map(|l| l.to_string()).collect()
}

fn caddyfile(instance: &NaiveManager) -> String {
    read(&instance.settings.caddyfile)
}

fn revision(instance: &NaiveManager) -> String {
    instance.egress().unwrap()["revision"].as_str().unwrap().to_string()
}

#[test]
fn get_reports_the_legacy_upstream_as_the_provider_when_it_matches() {
    let dir = tempdir("egress-legacy");
    let instance = egress_manager(&dir, &hooks(), Some("socks5://127.0.0.1:40000"));
    let view = instance.egress().unwrap();
    // The test Caddyfile carries `upstream socks5://127.0.0.1:40000` outside any marker.
    assert_eq!(
        (view["mode"].clone(), view["upstream"].clone(), view["managed"].clone()),
        (json!("proxy"), json!("socks5://127.0.0.1:40000"), json!(false))
    );
    assert_eq!(view["document"], warp_doc());
    assert_eq!(view["providers"], json!({"warp": {"url": "socks5://127.0.0.1:40000", "reachable": true}}));
    assert_eq!(view["capabilities"], json!(["whole_direct", "whole_warp", "block_domain", "block_cidr"]));
    assert_eq!((view["restart_required"].clone(), view["previous"].clone()), (json!(false), Value::Null));
    assert_eq!(view["revision"].as_str().unwrap().len(), 64);
}

#[test]
fn get_reports_custom_when_the_upstream_is_not_the_provider() {
    let dir = tempdir("egress-custom");
    let instance = egress_manager(&dir, &hooks(), Some(WARP));
    let view = instance.egress().unwrap();
    assert_eq!((view["mode"].clone(), view["document"].clone()), (json!("custom"), Value::Null));
    assert_eq!(view["warnings"], json!(["adopts_unmanaged_upstream"]));
    assert_eq!(egress_manager(&dir, &hooks(), None).egress().unwrap()["providers"], json!({}));
}

#[test]
fn plan_is_read_only_and_reports_the_diff() {
    let dir = tempdir("egress-plan");
    let hooks = hooks();
    let instance = egress_manager(&dir, &hooks, Some(WARP));
    let before = bytes(&instance.settings.caddyfile);
    let current = revision(&instance);
    let plan = instance.egress_plan(&current, &warp_doc()).unwrap();
    assert_eq!(bytes(&instance.settings.caddyfile), before);
    assert_eq!(hooks.reloads(), 0);
    assert!(plan["revision"] == current.as_str() && plan["target_revision"] != current.as_str());
    let diff = plan["diff"].as_array().unwrap();
    assert!(diff.iter().any(|line| line.as_str().unwrap().contains(&format!("upstream {WARP}"))));
    assert_eq!(plan["restart_required"], false);
    assert_eq!(plan["reachability"], json!({"warp": true}));
    assert_eq!(plan["warnings"], json!(["adopts_unmanaged_upstream"]));
    assert_eq!(plan["rendered_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(
        diff,
        &[
            json!("-            upstream socks5://127.0.0.1:40000"),
            json!(format!("+            {EGRESS_BEGIN}")),
            json!(format!("+            upstream {WARP}")),
            json!(format!("+            {EGRESS_END}"))
        ]
    );
}

#[test]
fn apply_writes_the_block_reloads_and_reads_back() {
    let dir = tempdir("egress-apply");
    let hooks = hooks();
    let instance = egress_manager(&dir, &hooks, Some(WARP));
    let current = revision(&instance);
    let result = instance.egress_apply(&current, &warp_doc(), "routing:p1:1").unwrap();
    let text = caddyfile(&instance);
    assert_eq!(
        block(&text),
        [
            format!("            {EGRESS_BEGIN}"),
            format!("            upstream {WARP}"),
            format!("            {EGRESS_END}")
        ]
    );
    assert!(!text.contains("upstream socks5://127.0.0.1:40000"));
    assert!(hooks.reloads() == 1 && hooks.probes() >= 1);
    assert!(result["revision"] != current.as_str() && result["applied"] == warp_doc());
    assert_eq!(result["readback_sha256"].as_str().unwrap().len(), 64);
    let view = instance.egress().unwrap();
    assert_eq!(
        (view["mode"].clone(), view["managed"].clone(), view["document"].clone(), view["revision"].clone()),
        (json!("proxy"), json!(true), warp_doc(), result["revision"].clone())
    );
    assert_eq!(view["previous"]["revision"], current.as_str());
    let state: Value = serde_json::from_str(&read(&dir.join("state/users.json"))).unwrap();
    assert_eq!(state["egress"]["current"]["operation_id"], "routing:p1:1");
    assert_eq!(state["egress"]["previous"]["raw_lines"], json!(["            upstream socks5://127.0.0.1:40000"]));
}

#[test]
fn apply_keeps_every_other_line_byte_for_byte() {
    let dir = tempdir("egress-bytes");
    let instance = egress_manager(&dir, &hooks(), Some(WARP));
    let before = caddyfile(&instance);
    instance.egress_apply(&revision(&instance), &block_doc(), "op-1").unwrap();
    let after = caddyfile(&instance);
    let without = after.replace(&(block(&after).join("\n") + "\n"), "");
    assert_eq!(without, before.replace("            upstream socks5://127.0.0.1:40000\n", ""));
    // Users still work: the user block is untouched and a user change keeps the egress block.
    instance.create(&json!("carol"), &Value::Null, None, None).unwrap();
    assert_eq!(block(&caddyfile(&instance)), block(&after));
    assert_eq!(instance.egress().unwrap()["document"], block_doc());
}

#[test]
fn apply_conflicts_on_a_stale_revision_without_touching_anything() {
    let dir = tempdir("egress-stale");
    let hooks = hooks();
    let instance = egress_manager(&dir, &hooks, Some(WARP));
    let before = bytes(&instance.settings.caddyfile);
    let err = instance.egress_apply(&"0".repeat(64), &warp_doc(), "op-1").unwrap_err();
    assert_eq!(err.code(), Some("egress_conflict"));
    assert_eq!(bytes(&instance.settings.caddyfile), before);
    assert_eq!(hooks.reloads(), 0);
}

#[test]
fn apply_refuses_an_unreachable_provider_and_an_unconfigured_one() {
    let dir = tempdir("egress-unreachable");
    let hooks = hooks();
    hooks.get().reachable = false;
    let instance = egress_manager(&dir, &hooks, Some(WARP));
    let before = bytes(&instance.settings.caddyfile);
    let err = instance.egress_apply(&revision(&instance), &warp_doc(), "op-1").unwrap_err();
    assert!(matches!(err, Error::EgressUnreachable(_)), "{err:?}");
    assert_eq!(bytes(&instance.settings.caddyfile), before);
    assert_eq!(hooks.reloads(), 0);
    // Direct never needs the provider.
    instance.egress_apply(&revision(&instance), &direct_doc(), "op-2").unwrap();
    std::fs::create_dir_all(dir.join("other")).unwrap();
    let without = egress_manager(&dir.join("other"), &self::hooks(), None);
    let err = without.egress_apply(&revision(&without), &warp_doc(), "op-3").unwrap_err();
    assert!(matches!(&err, Error::EgressInvalid(m) if m.contains("not configured")), "{err:?}");
}

#[test]
fn apply_rejects_an_invalid_document_before_any_io() {
    let dir = tempdir("egress-invalid");
    let hooks = hooks();
    let instance = egress_manager(&dir, &hooks, Some(WARP));
    let document = json!({"schema": 1, "upstream": null, "acl": [{"deny": ["bad host"]}]});
    assert!(matches!(instance.egress_apply(&revision(&instance), &document, "op"), Err(Error::EgressInvalid(_))));
    assert_eq!(hooks.reloads(), 0);
}

#[test]
fn a_failed_reload_restores_the_previous_bytes() {
    let dir = tempdir("egress-failed-reload");
    let hooks = hooks();
    hooks.get().fail_reload_calls = [1].into();
    let instance = egress_manager(&dir, &hooks, Some(WARP));
    let before = bytes(&instance.settings.caddyfile);
    let state = bytes(&dir.join("state/users.json"));
    let err = instance.egress_apply(&revision(&instance), &warp_doc(), "op-1").unwrap_err();
    assert_eq!(err, Error::runtime("reload failed"));
    assert_eq!(bytes(&instance.settings.caddyfile), before);
    assert_eq!(bytes(&dir.join("state/users.json")), state);
    assert_eq!(instance.health()["ready"], true);
}

#[test]
fn a_readback_mismatch_rolls_back_with_its_own_code() {
    let dir = tempdir("egress-readback");
    let hooks = hooks();
    let instance = egress_manager(&dir, &hooks, Some(WARP));
    let before = bytes(&instance.settings.caddyfile);
    hooks.get().readback_override = Some(json!({"upstream": "socks5://127.0.0.1:1"}).as_object().unwrap().clone());
    let err = instance.egress_apply(&revision(&instance), &warp_doc(), "op-1").unwrap_err();
    assert_eq!(err.code(), Some("egress_readback_mismatch"));
    hooks.get().readback_override = None;
    assert_eq!(bytes(&instance.settings.caddyfile), before);
    assert_eq!(instance.health()["ready"], true);
}

#[test]
fn apply_is_idempotent_by_operation_id() {
    let dir = tempdir("egress-idempotent");
    let hooks = hooks();
    let instance = egress_manager(&dir, &hooks, Some(WARP));
    let first = instance.egress_apply(&revision(&instance), &warp_doc(), "op-1").unwrap();
    let again = instance.egress_apply(first["revision"].as_str().unwrap(), &warp_doc(), "op-1").unwrap();
    assert_eq!(again["revision"], first["revision"]);
    assert_eq!(again["replayed"], true);
    assert_eq!(hooks.reloads(), 1);
    // Same id, another document.
    assert!(instance
        .egress_apply(first["revision"].as_str().unwrap(), &direct_doc(), "op-1")
        .unwrap_err()
        .is_conflict());
}

#[test]
fn rollback_restores_the_previous_entry_and_then_the_adopted_lines() {
    let dir = tempdir("egress-rollback");
    let instance = egress_manager(&dir, &hooks(), Some(WARP));
    let original = caddyfile(&instance);
    let first = instance.egress_apply(&revision(&instance), &warp_doc(), "op-1").unwrap();
    let second = instance.egress_apply(first["revision"].as_str().unwrap(), &block_doc(), "op-2").unwrap();
    let rolled = instance.egress_rollback(second["revision"].as_str().unwrap()).unwrap();
    assert_eq!(rolled["revision"], first["revision"]);
    assert_eq!(instance.egress().unwrap()["document"], warp_doc());
    let rolled = instance.egress_rollback(rolled["revision"].as_str().unwrap()).unwrap();
    assert_eq!(caddyfile(&instance), original); // the adopted upstream line is back, byte for byte
    let view = instance.egress().unwrap();
    assert_eq!((view["mode"].clone(), view["managed"].clone()), (json!("custom"), json!(false)));
    let err = instance.egress_rollback(rolled["revision"].as_str().unwrap()).unwrap_err();
    assert_eq!(err.code(), Some("egress_no_previous"));
}

#[test]
fn recovery_after_a_crash_between_write_and_reload() {
    let dir = tempdir("egress-crash");
    let hooks = hooks();
    let instance = egress_manager(&dir, &hooks, Some(WARP));
    let before = bytes(&instance.settings.caddyfile);
    hooks.get().reload_override = Some(Box::new(|| Err(Error::Other("KeyboardInterrupt".into()))));
    assert!(instance.egress_apply(&revision(&instance), &warp_doc(), "op-1").is_err());
    // A fresh manager over the same files finds the files restored and settles the journal.
    let fresh = egress_manager(&dir, &self::hooks(), Some(WARP));
    assert_eq!(bytes(&instance.settings.caddyfile), before);
    assert_eq!(fresh.health()["ready"], true);
}

/// A Caddyfile whose hand-written upstream carries a credential: the API must never echo it.
fn with_userinfo(dir: &Path, hooks: &TestHooks) -> Arc<NaiveManager> {
    let instance = egress_manager(dir, hooks, Some(WARP));
    let text = caddyfile(&instance)
        .replace("upstream socks5://127.0.0.1:40000", "upstream socks5://alice:s3cret@127.0.0.1:1080");
    std::fs::write(&instance.settings.caddyfile, text).unwrap();
    instance
}

#[test]
fn egress_view_redacts_custom_upstream_userinfo() {
    let dir = tempdir("egress-redact-view");
    let instance = with_userinfo(&dir, &hooks());
    let view = instance.egress().unwrap();
    assert_eq!((view["mode"].clone(), view["document"].clone()), (json!("custom"), Value::Null));
    assert_eq!(view["upstream"], "socks5://***@127.0.0.1:1080");
    assert!(!view.to_string().contains("s3cret"));
}

#[test]
fn block_lines_router_upstream_carries_credential_from_file() {
    let dir = tempdir("egress-router-block");
    let hooks = hooks();
    let instance = router_manager(&dir, &hooks, &router_secret());
    let result = instance.egress_apply(&revision(&instance), &router_doc(), "op-router").unwrap();
    let text = caddyfile(&instance);
    assert!(block(&text)[1].contains(&format!("upstream socks5://naive-a1b2c3d4:{}@127.0.0.1:45101", "K".repeat(40))));
    assert_eq!(result["applied"], router_doc());
    // The reachability probe offered the password method to the router, never a bare greeting.
    assert!(hooks.get().greetings.contains(&(ROUTER.to_string(), true)));
    let view = instance.egress().unwrap();
    assert_eq!((view["mode"].clone(), view["document"].clone()), (json!("proxy"), router_doc()));
    assert_eq!(view["providers"]["router"], json!({"url": ROUTER, "reachable": true}));
    assert_eq!(view["providers"]["warp"]["url"], WARP);
}

#[test]
fn egress_views_never_contain_router_credential() {
    let dir = tempdir("egress-router-secret");
    let instance = router_manager(&dir, &hooks(), &router_secret());
    let current = revision(&instance);
    let plan = instance.egress_plan(&current, &router_doc()).unwrap();
    instance.egress_apply(&current, &router_doc(), "op-router").unwrap();
    let texts = [
        plan.to_string(),
        instance.egress().unwrap().to_string(),
        instance.egress_plan(&revision(&instance), &warp_doc()).unwrap().to_string(),
    ];
    for text in texts {
        assert!(!text.contains(&"K".repeat(40)) && !text.contains("naive-a1b2c3d4"), "{text}");
    }
    assert_eq!(instance.egress().unwrap()["upstream"], "socks5://***@127.0.0.1:45101");
    assert_eq!(plan["reachability"], json!({"router": true}));
}

#[test]
fn apply_router_without_router_env_is_unsupported() {
    let dir = tempdir("egress-no-router");
    let instance = egress_manager(&dir, &hooks(), Some(WARP));
    let err = instance.egress_apply(&revision(&instance), &router_doc(), "op-1").unwrap_err();
    assert!(matches!(&err, Error::EgressInvalid(m) if m.contains("router")), "{err:?}");
    assert!(instance.egress().unwrap()["providers"].get("router").is_none());
}

#[test]
fn apply_router_unreachable_refuses_without_changes() {
    let dir = tempdir("egress-router-down");
    let hooks = hooks();
    let instance = router_manager(&dir, &hooks, &router_secret());
    hooks.get().reachable = false;
    let before = bytes(&instance.settings.caddyfile);
    let err = instance.egress_apply(&revision(&instance), &router_doc(), "op-1").unwrap_err();
    assert!(matches!(&err, Error::EgressUnreachable(m) if m.contains("router")), "{err:?}");
    assert_eq!(bytes(&instance.settings.caddyfile), before);
}

#[test]
fn bootstrap_rerenders_router_block_after_rotation() {
    let dir = tempdir("egress-rotation");
    let hooks = hooks();
    let instance = router_manager(&dir, &hooks, &router_secret());
    let applied = instance.egress_apply(&revision(&instance), &router_doc(), "op-router").unwrap();
    let previous_revision = instance.egress().unwrap()["previous"]["revision"].clone();
    let rotated = format!("naive-a1b2c3d4:{}", "Z".repeat(40));
    std::fs::write(dir.join("xray-router-ingress"), format!("{rotated}\n")).unwrap();
    assert_eq!(instance.egress().unwrap()["warnings"], json!(["router_credential_stale"]));
    let reloads = hooks.reloads();
    let fresh = router_manager(&dir, &self::hooks(), &rotated);
    let text = caddyfile(&fresh);
    assert!(block(&text)[1].contains(&format!("upstream socks5://naive-a1b2c3d4:{}@127.0.0.1:45101", "Z".repeat(40))));
    assert!(!text.contains(&"K".repeat(40)));
    let view = fresh.egress().unwrap();
    assert_eq!((view["warnings"].clone(), view["document"].clone()), (json!([]), router_doc()));
    assert!(view["revision"] != applied["revision"]);
    assert_eq!(view["previous"]["revision"], previous_revision);
    assert_eq!(view["current"]["operation_id"], "op-router");
    assert_eq!(hooks.reloads(), reloads); // the fresh manager's own hooks reloaded, not the old one's
                                          // A rollback still walks back to the floor, the adopted line restored verbatim.
    fresh.egress_rollback(view["revision"].as_str().unwrap()).unwrap();
    assert!(caddyfile(&fresh).contains("upstream socks5://127.0.0.1:40000"));
}

#[test]
fn hand_written_router_line_with_a_credential_is_the_router_provider() {
    let dir = tempdir("egress-handwritten-router");
    let hooks = hooks();
    let credential = dir.join("xray-router-ingress");
    std::fs::write(&credential, format!("{}\n", router_secret())).unwrap();
    let mut settings = settings(&dir);
    settings.router_url = Some(ROUTER.into());
    settings.router_credential_file = Some(credential);
    let instance = manager_with(&dir, &hooks, settings);
    let text = caddyfile(&instance).replace(
        "upstream socks5://127.0.0.1:40000",
        &format!("upstream socks5://naive-a1b2c3d4:{}@127.0.0.1:45101", "K".repeat(40)),
    );
    std::fs::write(&instance.settings.caddyfile, text).unwrap();
    instance.bootstrap().unwrap();
    let view = instance.egress().unwrap();
    assert_eq!(
        (view["mode"].clone(), view["document"].clone(), view["managed"].clone()),
        (json!("proxy"), router_doc(), json!(false))
    );
    assert!(!view.to_string().contains(&"K".repeat(40)));
}

#[test]
fn egress_plan_diff_redacts_userinfo() {
    let dir = tempdir("egress-redact-plan");
    let instance = with_userinfo(&dir, &hooks());
    let plan = instance.egress_plan(&revision(&instance), &warp_doc()).unwrap();
    assert!(plan["diff"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l.as_str().unwrap().contains("socks5://***@127.0.0.1:1080")));
    assert!(!plan.to_string().contains("s3cret"));
    // The journal keeps the adopted line byte for byte: that is what a rollback restores.
    instance.egress_apply(&revision(&instance), &warp_doc(), "op-redact").unwrap();
    let state: Value = serde_json::from_str(&read(&dir.join("state/users.json"))).unwrap();
    assert_eq!(
        state["egress"]["previous"]["raw_lines"],
        json!(["            upstream socks5://alice:s3cret@127.0.0.1:1080"])
    );
    assert!(!instance.egress().unwrap().to_string().contains("s3cret"));
    instance.egress_rollback(&revision(&instance)).unwrap();
    assert!(caddyfile(&instance).contains("upstream socks5://alice:s3cret@127.0.0.1:1080"));
}

#[test]
fn bootstrap_adopts_the_installer_seed_after_rotation() {
    let dir = tempdir("egress-seed");
    let hooks = hooks();
    let instance = router_manager(&dir, &hooks, &router_secret());
    let seeded = caddyfile(&instance).replace(
        "upstream socks5://127.0.0.1:40000",
        &format!("upstream socks5://naive-a1b2c3d4:{}@127.0.0.1:45101", "K".repeat(40)),
    );
    std::fs::write(&instance.settings.caddyfile, seeded).unwrap();
    let view = instance.egress().unwrap();
    assert_eq!(
        (view["mode"].clone(), view["document"].clone(), view["managed"].clone()),
        (json!("proxy"), router_doc(), json!(false))
    );
    assert_eq!(view["warnings"], json!(["adopts_unmanaged_upstream"]));
    let rotated = format!("naive-a1b2c3d4:{}", "Z".repeat(40));
    std::fs::write(dir.join("xray-router-ingress"), format!("{rotated}\n")).unwrap();
    assert_eq!(instance.egress().unwrap()["warnings"], json!(["adopts_unmanaged_upstream", "router_credential_stale"]));
    let fresh = router_manager(&dir, &self::hooks(), &rotated);
    let text = caddyfile(&fresh);
    assert!(block(&text)[1].contains(&format!("upstream socks5://naive-a1b2c3d4:{}@127.0.0.1:45101", "Z".repeat(40))));
    assert!(!text.contains(&"K".repeat(40)));
    let view = fresh.egress().unwrap();
    assert_eq!(
        (view["managed"].clone(), view["warnings"].clone(), view["document"].clone()),
        (json!(true), json!([]), router_doc())
    );
    assert!(!view["previous"].is_null());
    assert_eq!(view["current"]["operation_id"], Value::Null);
    fresh.egress_rollback(view["revision"].as_str().unwrap()).unwrap();
    assert!(caddyfile(&fresh).contains(&format!("upstream socks5://naive-a1b2c3d4:{}@127.0.0.1:45101", "K".repeat(40))));
}
