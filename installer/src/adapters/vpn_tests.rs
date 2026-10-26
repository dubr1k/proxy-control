use crate::{
    adapter::Adapter,
    adapters::{amneziawg::AmneziaWgAdapter, trusttunnel::TrustTunnelAdapter, AdapterContext},
    journal::RollbackTarget,
    testkit::{engine_for, plan_with, TempDir},
};
use installer_core::planner::Action;
use pc_host::runner::{RecordingRunner, Reply};
use serde_json::{json, Value};
use std::{fs, sync::Arc};

pub(super) fn tree() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}
pub(super) fn action(name: &str) -> Action {
    let value: Value = serde_json::from_slice(
        &fs::read(tree().join("tests/fixtures/host-golden/plans/kitchen-sink/plan.json")).unwrap(),
    )
    .unwrap();
    Action::from_value(value["actions"].as_array().unwrap().iter().find(|a| a["adapter"] == name).unwrap()).unwrap()
}
fn setup(awg: bool) -> (TempDir, Arc<RecordingRunner>, Arc<dyn Adapter>, Action) {
    let root = TempDir::new("vpn");
    let runner = Arc::new(RecordingRunner::new());
    fs::create_dir_all(root.path().join("dev/net")).unwrap();
    fs::write(root.path().join("dev/net/tun"), "").unwrap();
    for file in ["fullchain.pem", "privkey.pem"] {
        let path = root.path().join(format!("etc/letsencrypt/live/gate.example.org/{file}"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "certificate").unwrap();
    }
    runner.reply(&["sysctl", "-n"], Reply::ok("0\n"));
    runner.reply(&["docker", "inspect"], Reply::ok("healthy\n"));
    runner.reply(&["ss"], Reply::ok("UNCONN 0 0 0.0.0.0:25076 0.0.0.0:*\n"));
    runner.reply(&["docker","exec"],Reply::ok(if awg {r#"{"status":"ok","ip_forward":true,"instances":{"1.5":{"running":true,"port":25076},"2.0":{"running":true,"port":11892},"3.1":{"running":true,"port":13013}}}"#} else {r#"{"status":"ok","endpoint":{"running":true}}"#}));
    let context = AdapterContext { root: root.path().into(), tree: tree(), runner: runner.clone() };
    let adapter: Arc<dyn Adapter> =
        if awg { Arc::new(AmneziaWgAdapter::new(&context)) } else { Arc::new(TrustTunnelAdapter::new(&context)) };
    let action = action(adapter.name());
    (root, runner, adapter, action)
}
#[test]
fn golden_renders_and_engine_install_repair_uninstall() {
    for awg in [false, true] {
        let (root, runner, adapter, a) = setup(awg);
        let name = adapter.name().to_string();
        let plan = plan_with(vec![a], Default::default());
        let engine = engine_for(root.path(), vec![adapter]);
        engine.apply(&plan, &plan.digest()).unwrap();
        let overlay = root.path().join(format!("opt/mtproxy-shared443/.env.{name}"));
        assert_eq!(
            fs::read(&overlay).unwrap(),
            fs::read(tree().join(format!("tests/fixtures/host-golden/renders/kitchen-sink/{name}/env"))).unwrap()
        );
        engine.repair().unwrap();
        engine.uninstall(false).unwrap();
        assert!(!overlay.exists());
        assert!(root
            .path()
            .join(format!(
                "opt/mtproxy-shared443/secrets/{}-token",
                if awg { "awg-manager" } else { "trusttunnel-manager" }
            ))
            .is_file());
        if awg {
            assert!(runner.argvs().iter().any(|v| v == &["sysctl", "-w", "net.ipv4.ip_forward=0"]));
        }
    }
}
#[test]
fn malformed_selections_and_checkpoints_fail_closed() {
    for awg in [false, true] {
        let (_root, _runner, adapter, a) = setup(awg);
        for (key, value) in if awg {
            vec![("versions", "1.5,1.5"), ("ports", "1.5:80"), ("mtu", "1000"), ("host", "bad/host"), ("dns", "bogus")]
        } else {
            vec![("hostname", "bad/host"), ("listen", "0.0.0.0:4453"), ("sha256", "bad"), ("version", "1;cmd")]
        } {
            let mut bad = a.clone();
            let item = bad.mutations.iter_mut().find(|s| s.starts_with(&format!("{key}="))).unwrap();
            *item = format!("{key}={value}");
            assert!(adapter.prepare(&bad).is_err());
        }
        let mut bad = a.clone();
        bad.mutations.push(a.mutations[0].clone());
        assert!(adapter.prepare(&bad).is_err());
        assert!(adapter.apply(&a, Default::default()).is_err());
    }
}
#[test]
fn token_symlinks_and_world_readable_secrets_are_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for awg in [false, true] {
        let (root, _runner, adapter, a) = setup(awg);
        let token = root.path().join(format!(
            "opt/mtproxy-shared443/secrets/{}-token",
            if awg { "awg-manager" } else { "trusttunnel-manager" }
        ));
        fs::create_dir_all(token.parent().unwrap()).unwrap();
        fs::write(&token, "a".repeat(64)).unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).unwrap();
        let d = adapter.prepare(&a).unwrap();
        assert!(adapter.apply(&a, d).is_err());
        fs::remove_file(&token).unwrap();
        symlink("/dev/null", &token).unwrap();
        let d = adapter.prepare(&a).unwrap();
        assert!(adapter.apply(&a, d).is_err());
    }
}
#[test]
fn rollback_restores_previous_forwarding_and_preserves_foreign_override() {
    let (root, runner, adapter, a) = setup(true);
    let d = adapter.prepare(&a).unwrap();
    assert_eq!(d["ip_forward_previous"], "0");
    let d = adapter.apply(&a, d).unwrap();
    let path = root.path().join("opt/mtproxy-shared443/version-overrides/compose.versions.yaml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "services:\n  awg-manager:\n    build:\n      args: {}\n  telemt:\n    image: keep\n").unwrap();
    adapter.rollback(&a, d, false, RollbackTarget::RolledBack).unwrap();
    assert_eq!(fs::read_to_string(path).unwrap(), "services:\n  telemt:\n    image: keep\n");
    assert!(runner.argvs().iter().any(|v| v == &["sysctl", "-w", "net.ipv4.ip_forward=0"]));
}
#[test]
fn legacy_python_checkpoints_remain_usable_without_guessing_forwarding() {
    let (_root, runner, adapter, a) = setup(true);
    let mut d = adapter.prepare(&a).unwrap();
    d.remove("ip_forward_previous");
    let d = adapter.apply(&a, d).unwrap();
    adapter.rollback(&a, d, false, RollbackTarget::RolledBack).unwrap();
    assert!(!runner.argvs().iter().any(|v| v.starts_with(&["sysctl".into(), "-w".into()])));
}
#[test]
fn bound_foreign_ports_fail_and_owned_ports_pass() {
    use super::amneziawg::assert_free;
    let mut facts = installer_core::planner::AuditFacts {
        listeners: json!({"udp":[25076],"owners":{"25076":["foreign"]}}).as_object().unwrap().clone(),
        ..Default::default()
    };
    assert!(assert_free(&facts, "udp", &[25076], &["amneziawg-go"], "AmneziaWG").is_err());
    facts.listeners["owners"] = json!({"25076":["amneziawg-go"]});
    assert!(assert_free(&facts, "udp", &[25076], &["amneziawg-go"], "AmneziaWG").is_ok());
}
#[test]
fn helper_derivation_pins_and_negatives() {
    let root = TempDir::new("vpn-helpers");
    fs::create_dir_all(root.path().join("etc")).unwrap();
    fs::write(root.path().join("etc/machine-id"), "0123456789abcdef0123456789abcdef\n").unwrap();
    let args = vec![
        "awg-ports".into(),
        "--root".into(),
        root.path().to_string_lossy().into_owned(),
        "".into(),
        "--".into(),
        "1.5".into(),
        "2.0".into(),
        "3.1".into(),
    ];
    let out = crate::vpn_helpers::dispatch(&args, &tree()).unwrap().unwrap();
    for (line, v) in out.lines().zip(["1.5", "2.0", "3.1"]) {
        assert_eq!(
            line,
            format!("{v}={}", installer_core::awg_ports::derive_port("0123456789abcdef0123456789abcdef", v, 0))
        );
    }
    let args = vec!["release-pin".into(), "trusttunnel".into(), "amd64".into()];
    assert_eq!(
        crate::vpn_helpers::dispatch(&args, &tree()).unwrap().unwrap(),
        format!("1.1.0 {}\n", super::trusttunnel::TT_SHA256)
    );
    for args in [
        vec!["awg-ports", "", "--", "bogus"],
        vec!["awg-ports", "nope", "--", "1.5"],
        vec!["release-pin", "trusttunnel", "arm64"],
    ] {
        assert!(crate::vpn_helpers::dispatch(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &tree())
            .unwrap()
            .is_err());
    }
}

#[test]
fn preexisting_forwarding_and_sysctl_are_preserved() {
    let (root, _runner, adapter, a) = setup(true);
    let sysctl = root.path().join("etc/sysctl.d/99-proxy-control-amneziawg.conf");
    fs::create_dir_all(sysctl.parent().unwrap()).unwrap();
    fs::write(&sysctl, super::vpn::SYSCTL_TEXT).unwrap();
    let mut data = adapter.prepare(&a).unwrap();
    data.insert("ip_forward_previous".into(), json!("1"));
    let data = adapter.apply(&a, data).unwrap();
    adapter.rollback(&a, data, false, RollbackTarget::RolledBack).unwrap();
    assert_eq!(fs::read_to_string(sysctl).unwrap(), super::vpn::SYSCTL_TEXT);
}

#[test]
fn failed_health_rolls_back_through_engine() {
    for awg in [false, true] {
        let (root, _runner, _adapter, a) = setup(awg);
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(&["sysctl", "-n"], Reply::ok("0\n"));
        runner.reply(&["docker", "inspect"], Reply::ok("unhealthy\n"));
        let context = AdapterContext { root: root.path().into(), tree: tree(), runner: runner.clone() };
        let adapter: Arc<dyn Adapter> =
            if awg { Arc::new(AmneziaWgAdapter::new(&context)) } else { Arc::new(TrustTunnelAdapter::new(&context)) };
        let name = adapter.name().to_string();
        let plan = plan_with(vec![a], Default::default());
        let engine = engine_for(root.path(), vec![adapter]);
        assert!(engine.apply(&plan, &plan.digest()).is_err());
        assert!(!root.path().join(format!("opt/mtproxy-shared443/.env.{name}")).exists());
        if awg {
            assert!(runner.argvs().iter().any(|v| v == &["sysctl", "-w", "net.ipv4.ip_forward=0"]));
        }
    }
}

#[test]
fn agent_managed_vpn_pins_survive_installer_apply_and_repair_without_becoming_owned() {
    for awg in [false, true] {
        let (root, _runner, adapter, selected) = setup(awg);
        let shared = root.path().join("opt/mtproxy-shared443/version-overrides/compose.versions.yaml");
        fs::create_dir_all(shared.parent().unwrap()).unwrap();
        let installed = b"services:\n  awg-manager:\n    build:\n      args:\n        AWG_GO_VERSION: v1.0.20261001\n  trusttunnel-manager:\n    build:\n      args:\n        TT_VERSION: v9.8.7\n        TT_SHA256_X86_64: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  mtproxy:\n    image: operator/telemt:kept\n";
        fs::write(&shared, installed).unwrap();
        let prepared = adapter.prepare(&selected).unwrap();
        let applied = adapter.apply(&selected, prepared).unwrap();
        assert_eq!(fs::read(&shared).unwrap(), installed);
        assert!(applied["ownership"].get("/opt/mtproxy-shared443/version-overrides/compose.versions.yaml").is_none());
        let updated = String::from_utf8(installed.to_vec()).unwrap().replace("v9.8.7", "v9.8.8");
        fs::write(&shared, &updated).unwrap();
        let repaired = adapter.repair(&selected, applied).unwrap();
        assert_eq!(fs::read(&shared).unwrap(), updated.as_bytes());
        assert!(repaired["ownership"].get("/opt/mtproxy-shared443/version-overrides/compose.versions.yaml").is_none());
        assert!(adapter.verify(&selected).unwrap().success);
    }
}

#[test]
fn trusttunnel_rejects_shared_domains_and_conflicting_loopback_ports() {
    let base = fs::read_to_string(tree().join("examples/installer/core-trusttunnel.toml")).unwrap();
    for (text, field) in [
        (base.replace("gate.example.org", "panel.example.com"), "domains.panel"),
        (base.replace("gate.example.org", "relay.example.com"), "domains.mtproxy"),
        (base.replace("[domains]", "[domains]\nsubscription = \"gate.example.org\""), "domains.subscription"),
    ] {
        let error = installer_core::config::parse_config(&text).unwrap_err();
        assert!(error.0.contains(field), "{error}");
    }
    let mieru = base
        .replace("profile = \"core\"", "profile = \"core-mieru\"")
        .replace("[domains]", "[domains]\nmieru = \"mieru.example.com\"")
        .replace("[trusttunnel]", "[mieru]\ntcp_ports = [4453]\nudp_ports = [46002]\n\n[trusttunnel]");
    assert!(installer_core::config::parse_config(&mieru).unwrap_err().0.contains("4453"));
    let awg = format!(
        "{base}\n[amneziawg]\nenabled = true\nversions = [\"2.0\"]\nports = {{ \"2.0\" = 4453 }}\n"
    );
    assert!(installer_core::config::parse_config(&awg).unwrap_err().0.contains("4453"));
    let metrics = base.replace("[trusttunnel]", "[trusttunnel]\nlisten_port = 1987");
    assert!(installer_core::config::parse_config(&metrics).unwrap_err().0.contains("metrics"));
    let valid = installer_core::config::parse_config(&base).unwrap();
    let reserved = installer_core::config::reserved_tcp_ports(&valid);
    assert!(reserved[&4453].contains("TrustTunnel"));
    assert!(reserved[&1987].contains("TrustTunnel"));
}
