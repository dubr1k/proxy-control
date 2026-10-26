use super::{router_host as h, three_xui::ThreeXuiAdapter, xray_router::XrayRouterAdapter, AdapterContext};
use crate::adapter::Adapter;
use crate::testkit::TempDir;
use installer_core::model::ThreeXuiMode;
use installer_core::planner::{Action, AuditFacts};
use pc_host::runner::{RecordingRunner, Reply};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
fn tree() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_owned()
}
fn context(root: &TempDir) -> AdapterContext {
    AdapterContext { root: root.path().into(), tree: tree(), runner: Arc::new(RecordingRunner::new()) }
}
fn config() -> installer_core::model::InstallerConfig {
    installer_core::config::load_config(&tree().join("examples/installer/managed-three-xui.toml")).unwrap()
}
fn existing(context: &AdapterContext, listen: &str, network: &str) {
    let path = h::host(context, "/usr/local/x-ui/bin/config.json").unwrap();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path,serde_json::to_vec(&json!({"inbounds":[{"tag":"a","protocol":"vless","listen":listen,"port":12000,"streamSettings":{"network":network,"security":"reality","realitySettings":{"privateKey":"NEVER-IN-PLAN"}},"settings":{"clients":[{"id":"NEVER-IN-PLAN"}]}}]})).unwrap()).unwrap();
}
#[test]
fn managed_routes_match_pinned_backends() {
    let root = TempDir::new("xui-routes");
    let context = context(&root);
    let config = config();
    let routes = ThreeXuiAdapter::new(&context).planned_routes(&config).unwrap();
    for (domain, port) in [
        (&config.three_xui.panel_domain, 8451),
        (&config.three_xui.vless_tcp_domain, 8449),
        (&config.three_xui.vless_xhttp_domain, 8450),
    ] {
        assert!(routes.contains(&(domain.clone().unwrap(), format!("127.0.0.1:{port}"))));
    }
    assert!(routes.windows(2).all(|w| w[0] < w[1]));
}
#[test]
fn none_mode_is_read_only_and_empty() {
    let root = TempDir::new("xui-none");
    let context = context(&root);
    let mut config = config();
    config.three_xui.mode = ThreeXuiMode::None;
    let adapter = ThreeXuiAdapter::new(&context);
    assert!(adapter.planned_routes(&config).unwrap().is_empty());
    assert!(adapter.plan(&config, &AuditFacts::default()).unwrap().is_empty());
}
#[test]
fn existing_requires_installation() {
    let root = TempDir::new("xui-missing");
    let context = context(&root);
    let mut config = config();
    config.three_xui.mode = ThreeXuiMode::Existing;
    assert_eq!(
        ThreeXuiAdapter::new(&context).planned_routes(&config).unwrap_err().to_string(),
        "existing 3x-ui mode requires an installed 3x-ui"
    );
}
#[test]
fn existing_routes_use_audited_ports_without_secrets() {
    let root = TempDir::new("xui-existing");
    let context = context(&root);
    existing(&context, "127.0.0.1", "tcp");
    let mut config = config();
    config.three_xui.mode = ThreeXuiMode::Existing;
    config.three_xui.vless_xhttp_domain = None;
    let adapter = ThreeXuiAdapter::new(&context);
    let routes = adapter.planned_routes(&config).unwrap();
    assert_eq!(routes[0].1, "127.0.0.1:12000");
    let actions = adapter.plan(&config, &AuditFacts::default()).unwrap();
    assert_eq!(actions.len(), 1);
    assert!(!actions[0].to_value().to_string().contains("NEVER-IN-PLAN"));
}
#[test]
fn existing_rejects_public_listener() {
    let root = TempDir::new("xui-public");
    let context = context(&root);
    existing(&context, "0.0.0.0", "tcp");
    let mut config = config();
    config.three_xui.mode = ThreeXuiMode::Existing;
    config.three_xui.vless_xhttp_domain = None;
    assert!(ThreeXuiAdapter::new(&context)
        .planned_routes(&config)
        .unwrap_err()
        .to_string()
        .contains("must listen on loopback"));
}
#[test]
fn existing_rejects_symlink_configuration() {
    let root = TempDir::new("xui-symlink");
    let context = context(&root);
    let target = root.path().join("foreign");
    fs::write(&target, b"{}").unwrap();
    let path = h::host(&context, "/usr/local/x-ui/bin/config.json").unwrap();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(target, path).unwrap();
    let mut config = config();
    config.three_xui.mode = ThreeXuiMode::Existing;
    assert!(ThreeXuiAdapter::new(&context).planned_routes(&config).is_err());
}
#[test]
fn existing_rejects_oversize_configuration() {
    let root = TempDir::new("xui-oversize");
    let context = context(&root);
    existing(&context, "127.0.0.1", "tcp");
    let path = h::host(&context, "/usr/local/x-ui/bin/config.json").unwrap();
    fs::write(path, vec![b' '; 4 * 1024 * 1024 + 1]).unwrap();
    let mut config = config();
    config.three_xui.mode = ThreeXuiMode::Existing;
    assert!(ThreeXuiAdapter::new(&context).planned_routes(&config).unwrap_err().to_string().contains("audit bound"));
}
#[test]
fn existing_rejects_more_than_256_inbounds() {
    let root = TempDir::new("xui-bound");
    let context = context(&root);
    existing(&context, "127.0.0.1", "tcp");
    fs::write(
        h::host(&context, "/usr/local/x-ui/bin/config.json").unwrap(),
        serde_json::to_vec(&json!({"inbounds":vec![json!({});257]})).unwrap(),
    )
    .unwrap();
    let mut config = config();
    config.three_xui.mode = ThreeXuiMode::Existing;
    assert!(ThreeXuiAdapter::new(&context).planned_routes(&config).unwrap_err().to_string().contains("audit bound"));
}
#[test]
fn managed_prepare_refuses_every_existing_footprint() {
    for path in ["/etc/x-ui/x-ui.db", "/etc/x-ui", "/usr/local/x-ui", "/etc/systemd/system/x-ui.service"] {
        let root = TempDir::new("xui-footprint");
        let context = context(&root);
        let adapter = ThreeXuiAdapter::new(&context);
        let action = adapter
            .plan(&config(), &AuditFacts::default())
            .unwrap()
            .into_iter()
            .find(|a| a.id == "three_xui.runtime")
            .unwrap();
        let path = h::host(&context, path).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        if path.ends_with("x-ui") || path.ends_with("x-ui.db") {
            fs::create_dir_all(&path).unwrap();
        } else {
            fs::write(path, b"foreign").unwrap();
        }
        assert!(adapter.prepare(&action).is_err());
    }
}
#[test]
fn action_pin_substitution_is_rejected() {
    let root = TempDir::new("xui-action");
    let context = context(&root);
    let adapter = ThreeXuiAdapter::new(&context);
    let mut action = adapter
        .plan(&config(), &AuditFacts::default())
        .unwrap()
        .into_iter()
        .find(|a| a.id == "three_xui.runtime")
        .unwrap();
    for mutation in &mut action.mutations {
        if mutation.starts_with("release-digest=") {
            *mutation = format!("release-digest={}", "0".repeat(64));
        }
    }
    assert!(adapter.prepare(&action).is_err());
}
#[test]
fn host_parent_symlinks_are_rejected() {
    let root = TempDir::new("router-parent");
    let context = context(&root);
    fs::create_dir_all(root.path().join("etc")).unwrap();
    let outside = TempDir::new("router-outside");
    std::os::unix::fs::symlink(outside.path(), root.path().join("etc/proxy-control")).unwrap();
    assert!(h::atomic(&context, "/etc/proxy-control/owned", b"bad", 0o600).is_err());
    assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
}
#[test]
fn router_plan_rejects_uid_and_gid_collisions() {
    for kind in ["uid", "gid"] {
        let root = TempDir::new("router-collision");
        let context = context(&root);
        let config = installer_core::config::load_config(
            &tree().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"),
        )
        .unwrap();
        let mut facts = AuditFacts::default();
        facts.ownership.insert("identities".into(), json!({kind:{"10006":"foreign"}}));
        assert!(XrayRouterAdapter::new(&context).plan(&config, &facts).is_err());
    }
}
#[test]
fn router_live_numeric_collision_is_checked_without_optional_hook() {
    let root = TempDir::new("router-live-collision");
    let runner = Arc::new(RecordingRunner::new());
    runner.reply(&["getent", "passwd", "10006"], Reply::ok("foreign:x:10006:10006::/:/bin/false\n"));
    let context = AdapterContext { root: root.path().into(), tree: tree(), runner: runner.clone() };
    let config =
        installer_core::config::load_config(&tree().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"))
            .unwrap();
    let adapter = XrayRouterAdapter::new(&context);
    let action = adapter.plan(&config, &AuditFacts::default()).unwrap().remove(0);
    assert!(adapter.prepare(&action).unwrap_err().to_string().contains("UID 10006 collision"));
    assert!(runner.argvs().iter().any(|argv| argv == &["getent", "passwd", "10006"]));
}
#[test]
fn router_live_named_collision_is_rejected() {
    let root = TempDir::new("router-named-collision");
    let runner = Arc::new(RecordingRunner::new());
    runner.reply(&["getent", "passwd", "xray-router"], Reply::ok("xray-router:x:999:999::/:/bin/false\n"));
    let context = AdapterContext { root: root.path().into(), tree: tree(), runner };
    let config =
        installer_core::config::load_config(&tree().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"))
            .unwrap();
    let adapter = XrayRouterAdapter::new(&context);
    let action = adapter.plan(&config, &AuditFacts::default()).unwrap().remove(0);
    assert!(adapter.prepare(&action).unwrap_err().to_string().contains("unexpected numeric identifier"));
}
#[test]
fn router_plan_rejects_listener_collision() {
    let root = TempDir::new("router-listener");
    let context = context(&root);
    let config =
        installer_core::config::load_config(&tree().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"))
            .unwrap();
    for port in [45101, 45102, 45104, 45443] {
        let facts = AuditFacts {
            listeners: json!({"tcp":[port],"owners":{port.to_string():["foreign"]}}).as_object().unwrap().clone(),
            ..AuditFacts::default()
        };
        assert!(XrayRouterAdapter::new(&context).plan(&config, &facts).is_err());
    }
}
#[test]
fn router_rejects_duplicate_mutation() {
    let root = TempDir::new("router-duplicate");
    let context = context(&root);
    let config =
        installer_core::config::load_config(&tree().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"))
            .unwrap();
    let adapter = XrayRouterAdapter::new(&context);
    let mut action = adapter.plan(&config, &AuditFacts::default()).unwrap().remove(0);
    action.mutations.push(action.mutations[0].clone());
    assert!(adapter.prepare(&action).is_err());
}
#[test]
fn router_rejects_symlink_archive_without_network() {
    let root = TempDir::new("router-archive");
    let context = context(&root);
    let path = h::host(&context, "/var/lib/proxy-control/Xray-linux-64.zip").unwrap();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(root.path().join("foreign"), b"not zip").unwrap();
    std::os::unix::fs::symlink(root.path().join("foreign"), path).unwrap();
    let config =
        installer_core::config::load_config(&tree().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"))
            .unwrap();
    let adapter = XrayRouterAdapter::new(&context);
    let action = adapter.plan(&config, &AuditFacts::default()).unwrap().remove(0);
    assert!(adapter.prepare(&action).unwrap_err().to_string().contains("regular file"));
}
#[test]
fn managed_xui_actions_match_python_goldens() {
    for (name, file) in [("managed-three-xui", "managed-three-xui.toml"), ("full-three-xui", "full-three-xui.toml")] {
        let root = TempDir::new("xui-golden");
        let context = context(&root);
        let config = installer_core::config::load_config(&tree().join("examples/installer").join(file)).unwrap();
        if config.three_xui.mode == ThreeXuiMode::Existing {
            let path = h::host(&context, "/usr/local/x-ui/bin/config.json").unwrap();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, serde_json::to_vec(&json!({"inbounds":[
                {"tag":"tcp","protocol":"vless","listen":"127.0.0.1","port":8449,"streamSettings":{"network":"tcp"}},
                {"tag":"xhttp","protocol":"vless","listen":"127.0.0.1","port":8450,"streamSettings":{"network":"xhttp"}}
            ]})).unwrap()).unwrap();
        }
        let document: Value = serde_json::from_slice(
            &fs::read(tree().join(format!("tests/fixtures/host-golden/plans/{name}/plan.json"))).unwrap(),
        )
        .unwrap();
        let expected: Vec<_> =
            document["actions"].as_array().unwrap().iter().filter(|a| a["adapter"] == "three_xui").cloned().collect();
        let actual: Vec<_> = ThreeXuiAdapter::new(&context)
            .plan(&config, &AuditFacts::default())
            .unwrap()
            .iter()
            .map(Action::to_value)
            .collect();
        assert_eq!(actual, expected, "{name}");
    }
}
#[test]
fn router_action_matches_python_golden() {
    let root = TempDir::new("router-golden");
    let context = context(&root);
    let config =
        installer_core::config::load_config(&tree().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"))
            .unwrap();
    let document: Value = serde_json::from_slice(
        &fs::read(tree().join("tests/fixtures/host-golden/plans/kitchen-sink/plan.json")).unwrap(),
    )
    .unwrap();
    let expected = document["actions"].as_array().unwrap().iter().find(|a| a["adapter"] == "xray_router").unwrap();
    assert_eq!(
        &XrayRouterAdapter::new(&context).plan(&config, &AuditFacts::default()).unwrap()[0].to_value(),
        expected
    );
}

#[test]
fn rollback_does_not_remove_foreign_tree_when_apply_never_staged() {
    let root = TempDir::new("xui-rollback-foreign");
    let context = context(&root);
    let adapter = ThreeXuiAdapter::new(&context);
    let action = adapter.plan(&config(), &AuditFacts::default()).unwrap().into_iter().find(|a| a.id == "three_xui.runtime").unwrap();
    let checkpoint = adapter.prepare(&action).unwrap();
    let tree = h::host(&context, "/usr/local/x-ui").unwrap();
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join("foreign"), b"keep").unwrap();
    adapter.rollback(&action, checkpoint, true, crate::journal::RollbackTarget::Uninstalled).unwrap();
    assert_eq!(fs::read(tree.join("foreign")).unwrap(), b"keep");
}

#[test]
fn managed_templates_use_real_protocol_contract_and_distinct_clients() {
    let selected = BTreeMap::from([
        ("vless-tcp-domain".into(), "tcp.example.com".into()),
        ("vless-xhttp-domain".into(), "xhttp.example.com".into()),
        ("hysteria-domain".into(), "hy.example.com".into()),
    ]);
    let templates = crate::three_xui_templates::managed_inbounds(&selected, &"a".repeat(43), &"b".repeat(43), Some("subscription")).unwrap();
    let mut ids = std::collections::BTreeSet::new();
    for (index, inbound) in templates.iter().enumerate() {
        let settings: Value = serde_json::from_str(inbound["settings"].as_str().unwrap()).unwrap();
        assert_eq!(settings["clients"].as_array().unwrap().len(), 2);
        assert_eq!(settings["clients"][0]["subId"], "subscription");
        assert!(settings["clients"][1].get("subId").is_none());
        let stream: Value = serde_json::from_str(inbound["streamSettings"].as_str().unwrap()).unwrap();
        assert_eq!(stream["externalProxy"][0]["port"], 443);
        if index < 2 {
            assert_eq!(inbound["listen"], "127.0.0.1");
            assert_eq!(stream["security"], "reality");
            assert_eq!(stream["realitySettings"]["dest"], "127.0.0.1:8443");
            for client in settings["clients"].as_array().unwrap() { assert!(ids.insert(client["id"].as_str().unwrap().to_owned())); }
            assert_eq!(settings["clients"][0]["flow"], if index == 0 { "xtls-rprx-vision" } else { "" });
        } else {
            assert_eq!(stream["network"], "hysteria");
            assert_eq!(stream["hysteriaSettings"]["version"], 2);
            assert!(settings["clients"][0].get("auth").is_some());
            assert!(settings["clients"][0].get("password").is_none());
        }
    }
}

#[test]
fn reality_keypair_supports_pinned_xray_output_without_echoing_bad_output() {
    for (private_label, public_label) in [("PrivateKey", "PublicKey"), ("Private key", "Password (PublicKey)")] {
        let pair = crate::three_xui_templates::parse_reality_keypair(&format!("{private_label}: {}\n{public_label}: {}\n", "a".repeat(43), "b".repeat(43))).unwrap();
        assert_eq!(pair, ("a".repeat(43), "b".repeat(43)));
    }
    let error = crate::three_xui_templates::parse_reality_keypair("SECRET invalid private key").unwrap_err();
    assert!(!error.to_string().contains("SECRET"));
}

#[test]
fn compose_preserves_sibling_env_and_overlay_order() {
    let root = TempDir::new("router-compose");
    let runner = Arc::new(RecordingRunner::new());
    let context = AdapterContext { root: root.path().into(), tree: tree(), runner: runner.clone() };
    for sibling in ["naive", "mieru", "amneziawg", "trusttunnel"] {
        h::atomic(&context, &format!("/opt/mtproxy-shared443/.env.{sibling}"), b"SELECTED=1\n", 0o600).unwrap();
    }
    h::compose(&context, &["up", "-d", "--wait", "xray-router"]).unwrap();
    let argv = runner.argvs().pop().unwrap();
    let envs: Vec<_> = argv.windows(2).filter(|pair| pair[0] == "--env-file").map(|pair| pair[1].clone()).collect();
    assert_eq!(envs, [".env", ".env.naive", ".env.mieru", ".env.amneziawg", ".env.trusttunnel", ".env.xray-router"].map(|name| format!("/opt/mtproxy-shared443/{name}")));
    let overlays: Vec<_> = argv.windows(2).filter(|pair| pair[0] == "-f").map(|pair| pair[1].clone()).collect();
    assert_eq!(overlays, ["compose.yaml", "compose.naive.yaml", "compose.mieru.yaml", "compose.amneziawg.yaml", "compose.trusttunnel.yaml", "compose.xray-router.yaml"].map(|name| format!("/opt/mtproxy-shared443/{name}")));
}

#[test]
fn existing_audit_whitelists_facts_and_hashes_complete_tree() {
    let root = TempDir::new("xui-audit");
    let context = context(&root);
    existing(&context, "127.0.0.1", "tcp");
    let tree = h::host(&context, "/usr/local/x-ui").unwrap();
    fs::write(tree.join("extra"), b"binary-content").unwrap();
    std::os::unix::fs::symlink("extra", tree.join("link")).unwrap();
    h::atomic(&context, "/etc/x-ui/x-ui.db", b"database-content", 0o600).unwrap();
    h::atomic(&context, "/etc/systemd/system/x-ui.service", b"unit-content", 0o644).unwrap();
    let audit = ThreeXuiAdapter::new(&context).audit_existing().unwrap();
    let encoded = audit.to_string();
    for secret in ["NEVER-IN-PLAN", "\"privateKey\"", "\"clients\"", "\"settings\""] { assert!(!encoded.contains(secret)); }
    assert_eq!(audit["client_total"], 1);
    assert_eq!(audit["digests"]["database"], pc_host::fs::sha256_hex(b"database-content"));
    assert_eq!(audit["digests"]["unit"], pc_host::fs::sha256_hex(b"unit-content"));
    let config_digest = pc_host::fs::sha256_file(&tree.join("bin/config.json")).unwrap();
    let identity = format!("D bin\nF bin/config.json {config_digest}\nF extra {}\nL link extra\n", pc_host::fs::sha256_hex(b"binary-content"));
    assert_eq!(audit["digests"]["binary_tree"], pc_host::fs::sha256_hex(identity.as_bytes()));
}

#[test]
fn route_verification_rejects_a_public_audited_inbound_even_if_its_port_listens() {
    let root = TempDir::new("xui-route-drift");
    let runner = Arc::new(RecordingRunner::new());
    runner.reply(&["ss", "-lntH"], Reply::ok("LISTEN 0 128 0.0.0.0:12000 0.0.0.0:*\n"));
    let context = AdapterContext { root: root.path().into(), tree: tree(), runner };
    existing(&context, "127.0.0.1", "tcp");
    let mut config = config();
    config.three_xui.mode = ThreeXuiMode::Existing;
    config.three_xui.vless_xhttp_domain = None;
    let adapter = ThreeXuiAdapter::new(&context);
    let action = adapter.plan(&config, &AuditFacts::default()).unwrap().remove(0);
    existing(&context, "0.0.0.0", "tcp");
    assert!(adapter.verify(&action).unwrap_err().to_string().contains("not an audited loopback inbound"));
}
