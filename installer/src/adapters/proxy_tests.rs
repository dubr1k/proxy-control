//! Conformance tests ported from test_installer_{naive,mieru} and protocol recovery/command suites.
use super::proxy_acceptance::{client_config_for, require_mieru, require_naive};
use super::proxy_common::*;
use super::{mieru::MieruAdapter, naive::NaiveAdapter, AdapterContext};
use crate::adapter::Adapter;
use crate::journal::RollbackTarget;
use crate::planner::{Action, AuditFacts};
use crate::testkit::{engine_for, plan_with, TempDir};
use pc_host::fs::{atomic_write, sha256_hex};
use pc_host::runner::{CallKind, RecordingRunner, Reply};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
fn tree() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}
fn config() -> crate::model::InstallerConfig {
    installer_core::config::load_config(&tree().join("examples/installer/full-three-xui.toml")).unwrap()
}
fn fixture(case: &str, path: &str) -> PathBuf {
    tree().join("tests/fixtures/host-golden/renders").join(case).join(path)
}
fn read_action(case: &str, name: &str) -> Action {
    let values: Value = serde_json::from_slice(&fs::read(fixture(case, "actions.json")).unwrap()).unwrap();
    let value = values.as_array().unwrap().iter().find(|v| v["adapter"] == name).unwrap();
    Action::from_value(value).unwrap()
}
fn success(name: &str) -> Value {
    if name == "naive" {
        json!({"admin_api_loopback":true,"private_listener_ok":true,"cover_https_ok":true,"authenticated_connect_ok":true,"tunnel_closed_ok":true,"connect_bytes":4096,"recorded_bytes":4096,"manager_health_ok":true,"panel_health_ok":true,"adjacent_sni_ok":true,"log_boundary_ok":true,"temporary_state_removed":true})
    } else {
        json!({"package_digest_ok":true,"executable_digest_ok":true,"mita_status_running":true,"uds_boundary_ok":true,"manager_health_ok":true,"panel_health_ok":true,"transports_verified":2,"transports_expected":2,"send_queue_drained":true,"adjacent_listeners_ok":true,"public_host_ok":true,"temporary_state_removed":true})
    }
}
struct Rig {
    dir: TempDir,
    runner: Arc<RecordingRunner>,
    context: AdapterContext,
    fail: Arc<Mutex<Option<String>>>,
    clean_fail: Arc<Mutex<bool>>,
    acceptance: Arc<Mutex<Value>>,
    cleanup_names: Arc<Mutex<Vec<String>>>,
    _socket: UnixListener,
}
impl Rig {
    fn new() -> Self {
        let dir = TempDir::new("proxy-adapters");
        let root = dir.path().to_path_buf();
        let fail = Arc::new(Mutex::new(None::<String>));
        let flags = fail.clone();
        let path = root.join("run/mita");
        fs::create_dir_all(&path).unwrap();
        let socket = UnixListener::bind(path.join("mita.sock")).unwrap();
        fs::set_permissions(path.join("mita.sock"), fs::Permissions::from_mode(0o770)).unwrap();
        let owner = std::ffi::CString::new(path.join("mita.sock").to_string_lossy().as_bytes()).unwrap();
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(unsafe { libc::chown(owner.as_ptr(), 996, 998) }, 0);
        }
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            let argv = &call.argv;
            let joined = argv.join(" ");
            if flags.lock().unwrap().as_ref().is_some_and(|prefix| joined.contains(prefix)) {
                return Some(Reply::exit(1, "", "password=DO-NOT-LEAK container failed readiness"));
            }
            if argv.first().is_some_and(|s| s == "getent") {
                if argv.get(2).is_some_and(|s| s == "mita") {
                    return Some(Reply::ok(if argv[1] == "passwd" {
                        "mita:x:996:998::/nonexistent:/usr/sbin/nologin\n"
                    } else {
                        "mita:x:998:\n"
                    }));
                }
                return Some(Reply::ok(""));
            }
            if argv.starts_with(&strings(&["docker", "container", "ls"])) {
                return Some(Reply::ok(""));
            }
            if argv.starts_with(&strings(&["docker", "create"])) {
                return Some(Reply::ok(&"a".repeat(64)));
            }
            if argv.starts_with(&strings(&["docker", "cp"])) {
                let path = Path::new(&argv[3]);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, b"pinned-caddy\n").unwrap();
            }
            if argv.first().is_some_and(|s| s == "dpkg-deb") {
                let stage = Path::new(&argv[3]);
                let client = argv[2].contains("/mieru_");
                fs::create_dir_all(stage.join("usr/bin")).unwrap();
                fs::write(
                    stage.join(if client { "usr/bin/mieru" } else { "usr/bin/mita" }),
                    if client { &b"pinned-client\n"[..] } else { &b"pinned-mita\n"[..] },
                )
                .unwrap();
            }
            if argv.first().is_some_and(|s| s == "ss") {
                let port = argv.last().unwrap().split(':').next_back().unwrap();
                return Some(Reply::ok(&format!("LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:*\n")));
            }
            if argv.last().is_some_and(|s| s == "version") {
                return Some(Reply::ok(if argv[0].ends_with("caddy") {
                    super::naive::CADDY_VERSION
                } else {
                    "mita 3.38.1"
                }));
            }
            if argv.last().is_some_and(|s| s == "list-modules") {
                return Some(Reply::ok("http.handlers.forward_proxy\n"));
            }
            if argv.last().is_some_and(|s| s == "status") {
                return Some(Reply::ok("mita server status is \"RUNNING\""));
            }
            if joined.contains("prepare-naive-state prepare") {
                fs::create_dir_all(root.join("var/lib/naive-manager")).unwrap();
                fs::create_dir_all(root.join("var/log/naive-proxy")).unwrap();
            }
            if joined.contains("prepare-mieru-state prepare") {
                fs::create_dir_all(root.join("var/lib/mieru-manager")).unwrap();
            }
            if argv.starts_with(&strings(&["sudo", "-u", "mita", "env"])) && argv.iter().any(|s| s == "apply") {
                fs::write(root.join("var/lib/mita/server_config.json"), b"{\"users\":[{\"name\":\"owner\"}]}\n")
                    .unwrap();
            }
            Some(Reply::ok(""))
        }));
        let context = AdapterContext { root: dir.path().into(), tree: tree(), runner: runner.clone() };
        let rig = Self {
            dir,
            runner,
            context,
            fail,
            clean_fail: Arc::new(Mutex::new(false)),
            acceptance: Arc::new(Mutex::new(Value::Null)),
            cleanup_names: Arc::new(Mutex::new(Vec::new())),
            _socket: socket,
        };
        rig.put("/var/lib/proxy-control/mita_3.38.1_amd64.deb", b"server-package", 0o644);
        rig.put("/var/lib/proxy-control/mieru_3.38.1_amd64.deb", b"client-package", 0o644);
        rig
    }
    fn host(&self, path: &str) -> PathBuf {
        self.dir.path().join(path.trim_start_matches('/'))
    }
    fn put(&self, path: &str, bytes: &[u8], mode: u32) {
        atomic_write(&self.host(path), bytes, mode, None).unwrap();
    }
    fn probe(&self, name: &'static str) -> super::proxy_acceptance::TestAcceptance {
        let clean_fail = self.clean_fail.clone();
        let names = self.cleanup_names.clone();
        let value = self.acceptance.clone();
        Arc::new(move |mode, username, _recover| {
            if mode == "cleanup" {
                names.lock().unwrap().push(username.into());
                if *clean_fail.lock().unwrap() {
                    return Err(crate::Error::other("AcceptanceError", "injected cleanup failure"));
                }
                Ok(json!({}))
            } else {
                let value = value.lock().unwrap();
                Ok(if value.is_null() { success(name) } else { value.clone() })
            }
        })
    }
    fn naive(&self) -> NaiveAdapter {
        let mut adapter = NaiveAdapter::new(&self.context);
        adapter.test_acceptance = Some(self.probe("naive"));
        adapter
    }
    fn mieru(&self) -> MieruAdapter {
        let mut adapter = MieruAdapter::new(&self.context);
        adapter.test_acceptance = Some(self.probe("mieru"));
        adapter.client_pins =
            Some((super::mieru::CLIENT_URL.into(), sha256_hex(b"client-package"), sha256_hex(b"pinned-client\n")));
        adapter
    }
    fn action(&self, name: &str) -> Action {
        let mut action = if name == "naive" {
            self.naive().plan(&config(), &AuditFacts::default()).unwrap().remove(0)
        } else {
            self.mieru().plan(&config(), &AuditFacts::default()).unwrap().remove(0)
        };
        if name == "mieru" {
            set(&mut action, "package-digest", &sha256_hex(b"server-package"));
            set(&mut action, "executable-digest", &sha256_hex(b"pinned-mita\n"));
        }
        action
    }
}
fn set(action: &mut Action, key: &str, value: &str) {
    let prefix = format!("{key}=");
    if let Some(item) = action.mutations.iter_mut().find(|s| s.starts_with(&prefix)) {
        *item = format!("{key}={value}");
    } else {
        action.mutations.push(format!("{key}={value}"));
    }
}
fn apply(adapter: &dyn Adapter, action: &Action) -> crate::journal::CheckpointData {
    adapter.apply(action, adapter.prepare(action).unwrap()).unwrap()
}
#[test]
fn proxy_renders_match_all_python_goldens() {
    let rig = Rig::new();
    for case in [
        "direct",
        "egress-swapped",
        "kitchen-sink",
        "coexist-ingress",
        "managed-three-xui",
        "managed-three-xui-warp",
        "existing-three-xui",
    ] {
        if fixture(case, "naive").is_dir() {
            let naive = rig.naive();
            let action = read_action(case, "naive");
            let rendered = naive.render(&action).unwrap();
            for (name, actual) in [
                ("Caddyfile.template", rendered.caddyfile_template),
                ("env", rendered.env_text),
                ("caddy-naive.service", rendered.unit_text),
                ("caddy-naive.pin", rendered.pin_text),
                ("deploy-hook", super::naive::deploy_hook_text(&naive.selection(&action).unwrap().domain)),
            ] {
                assert_eq!(
                    actual.as_bytes(),
                    fs::read(fixture(case, &format!("naive/{name}"))).unwrap(),
                    "{case}/{name}"
                );
            }
            let expected: Value =
                serde_json::from_slice(&fs::read(fixture(case, "naive/file-modes.json")).unwrap()).unwrap();
            let actual = json!(rendered
                .file_modes
                .iter()
                .map(|(path, mode)| (path.clone(), format!("{mode:04o}")))
                .collect::<std::collections::BTreeMap<_, _>>());
            assert_eq!(actual, expected);
        }
        if fixture(case, "mieru").is_dir() {
            let mieru = rig.mieru();
            let action = read_action(case, "mieru");
            let selected = mieru.selection(&action).unwrap();
            assert_eq!(mieru.env_text(&selected, 998).as_bytes(), fs::read(fixture(case, "mieru/env")).unwrap());
            let bytes = mieru
                .bootstrap_input(
                    &selected,
                    "golden-bootstrap-password",
                    Some(("mieru-0011aabb", "golden-router-password")),
                )
                .unwrap();
            assert_eq!(bytes, fs::read(fixture(case, "mieru/bootstrap-input.json")).unwrap(), "{case}/bootstrap");
        }
    }
}
#[test]
fn naive_plan_action_is_secret_free_and_pins_the_build() {
    let rig = Rig::new();
    let action = rig.action("naive");
    assert!(action.mutations.contains(&format!("caddy-build={}", super::naive::CADDY_VERSION)));
    assert!(action.credentials_required);
    assert!(!action.mutations.join(" ").contains("password"));
}
#[test]
fn mieru_plan_pins_the_release_and_stays_secret_free() {
    let rig = Rig::new();
    let action = rig.mieru().plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    assert!(action.mutations.contains(&format!("package-digest={}", super::mieru::PACKAGE_DIGEST)));
    assert!(!action.mutations.join(" ").contains("password"));
}
#[test]
fn naive_plan_is_empty_without_the_naive_profile() {
    let rig = Rig::new();
    let mut config = config();
    config.profile = crate::model::Profile::Core;
    assert!(rig.naive().plan(&config, &AuditFacts::default()).unwrap().is_empty());
}
#[test]
fn mieru_plan_is_empty_without_the_mieru_profile() {
    let rig = Rig::new();
    let mut config = config();
    config.profile = crate::model::Profile::Core;
    assert!(rig.mieru().plan(&config, &AuditFacts::default()).unwrap().is_empty());
}
#[test]
fn proxy_plans_require_explicit_domains() {
    let rig = Rig::new();
    let mut config = config();
    config.domains.naive = None;
    assert!(rig.naive().plan(&config, &AuditFacts::default()).unwrap_err().message().contains("domain"));
    config.domains.mieru = None;
    assert!(rig.mieru().plan(&config, &AuditFacts::default()).unwrap_err().message().contains("host"));
}
#[test]
fn naive_plan_stops_on_fixed_identity_collision() {
    let rig = Rig::new();
    for (kind, id) in [("uid", "10003"), ("gid", "10004")] {
        let mut facts = AuditFacts::default();
        facts.ownership.insert("identities".into(), json!({(kind):{(id):"foreign"}}));
        assert!(rig.naive().plan(&config(), &facts).is_err());
    }
}
#[test]
fn naive_plan_adopts_its_own_reserved_identities() {
    let rig = Rig::new();
    let mut facts = AuditFacts::default();
    facts
        .ownership
        .insert("identities".into(), json!({"uid":{"10003":"naive-caddy"},"gid":{"10004":"naive-accounting"}}));
    assert!(rig.naive().plan(&config(), &facts).is_ok());
}
#[test]
fn mieru_plan_stops_on_reserved_manager_identity_collision() {
    let rig = Rig::new();
    for kind in ["uid", "gid"] {
        let mut facts = AuditFacts::default();
        facts.ownership.insert("identities".into(), json!({(kind):{"10005":"foreign"}}));
        assert!(rig.mieru().plan(&config(), &facts).is_err());
    }
}
#[test]
fn proxy_plans_reject_malformed_identity_facts() {
    let rig = Rig::new();
    for value in [json!([]), json!({"uid":{"10003":17,"10005":17}})] {
        let mut facts = AuditFacts::default();
        facts.ownership.insert("identities".into(), value);
        assert!(rig.naive().plan(&config(), &facts).is_err());
        assert!(rig.mieru().plan(&config(), &facts).is_err());
    }
}
#[test]
fn naive_plan_keeps_only_audited_adjacent_routes() {
    let rig = Rig::new();
    let config = config();
    let mut facts = AuditFacts::default();
    facts.topology.insert(
        "nginx".into(),
        json!({"sni_routes":{(config.domains.panel.clone()):"127.0.0.1:8443","foreign.example.com":"127.0.0.1:9876"}}),
    );
    let action = rig.naive().plan(&config, &facts).unwrap().remove(0);
    assert_eq!(
        rig.naive().selection(&action).unwrap().adjacent,
        vec![("foreign.example.com".into(), "127.0.0.1:9876".into())]
    );
}
#[test]
fn mieru_never_starts_empty_generation() {
    let rig = Rig::new();
    let mut config = config();
    config.initial_user.clear();
    assert!(rig.mieru().plan(&config, &AuditFacts::default()).is_err());
    config.initial_user = "owner".into();
    config.mieru.as_mut().unwrap().tcp_ports.clear();
    config.mieru.as_mut().unwrap().udp_ports.clear();
    assert!(rig.mieru().plan(&config, &AuditFacts::default()).is_err());
}
#[test]
fn mieru_plan_refuses_the_shared_443_listener() {
    let rig = Rig::new();
    let mut config = config();
    config.mieru.as_mut().unwrap().tcp_ports = vec![443];
    assert!(rig.mieru().plan(&config, &AuditFacts::default()).is_err());
}
#[test]
fn mieru_replanning_accepts_ports_its_own_server_already_holds() {
    let rig = Rig::new();
    let mut facts = AuditFacts::default();
    facts.listeners.insert("tcp".into(), json!([46001]));
    assert!(rig.mieru().plan(&config(), &facts).is_err());
    facts.listeners.insert("owners".into(), json!({"46001":["mita"]}));
    assert!(rig.mieru().plan(&config(), &facts).is_ok());
    facts.listeners.insert("owners".into(), json!({"46001":["mita","foreign"]}));
    assert!(rig.mieru().plan(&config(), &facts).is_err());
}
#[test]
fn proxy_actions_reject_boundary_tampering() {
    let rig = Rig::new();
    for name in ["naive", "mieru"] {
        let action = rig.action(name);
        for key in ["project", "unit", "manager-uid", "egress", "warp-port", "warp-provider", "router-provider"] {
            let mut action = action.clone();
            set(&mut action, key, "untrusted");
            let result = if name == "naive" {
                rig.naive().selection(&action).map(|_| ())
            } else {
                rig.mieru().selection(&action).map(|_| ())
            };
            assert!(result.is_err(), "{name}:{key}");
        }
        let mut action = action.clone();
        action.mutations.push(action.mutations[0].clone());
        assert!(if name == "naive" {
            rig.naive().selection(&action).is_err()
        } else {
            rig.mieru().selection(&action).is_err()
        });
    }
}
#[test]
fn proxy_legacy_actions_retain_the_45000_fallback() {
    let rig = Rig::new();
    for name in ["naive", "mieru"] {
        let mut action = rig.action(name);
        action.mutations.retain(|s| !s.starts_with("warp-"));
        set(&mut action, "egress", "proxy");
        let port = if name == "naive" {
            rig.naive().selection(&action).unwrap().warp_port
        } else {
            rig.mieru().selection(&action).unwrap().warp_port
        };
        assert_eq!(port, 45000);
    }
}
#[test]
fn naive_apply_keeps_the_planned_warp_port_and_provider() {
    let rig = Rig::new();
    let adapter = rig.naive();
    let mut action = rig.action("naive");
    set(&mut action, "egress", "proxy");
    set(&mut action, "warp-port", "41234");
    set(&mut action, "warp-provider", "socks5://127.0.0.1:41234");
    apply(&adapter, &action);
    let env = fs::read_to_string(rig.host("/opt/mtproxy-shared443/.env.naive")).unwrap();
    let caddy = fs::read_to_string(rig.host("/var/lib/naive-manager/Caddyfile")).unwrap();
    assert!(env.contains("NAIVE_EGRESS_WARP=socks5://127.0.0.1:41234"));
    assert!(caddy.contains("upstream socks5://127.0.0.1:41234"));
}
#[test]
fn naive_apply_orders_artifact_identities_bootstrap_and_overlay() {
    let rig = Rig::new();
    apply(&rig.naive(), &rig.action("naive"));
    let calls = rig.runner.argvs().iter().map(|a| a.join(" ")).collect::<Vec<_>>();
    let index = |fragment: &str| calls.iter().position(|s| s.contains(fragment)).unwrap();
    assert!(index("docker build") < index("groupadd"));
    assert!(index("groupadd") < index("useradd"));
    assert!(index("prepare-naive-state prepare") < index("systemctl enable"));
    assert!(index("--bootstrap-only") < index("systemctl reload"));
    assert!(index("systemctl reload") < index("up -d --build --wait"));
}
#[test]
fn naive_apply_installs_root_owned_helpers_and_pin() {
    let rig = Rig::new();
    apply(&rig.naive(), &rig.action("naive"));
    let helper = rig.host("/usr/local/libexec/prepare-naive-state");
    assert_eq!(fs::metadata(&helper).unwrap().mode() & 0o777, 0o755);
    assert!(fs::read_to_string(helper).unwrap().contains("proxy-control-installer prepare-naive-state"));
    assert_eq!(
        fs::read_to_string(rig.host("/etc/proxy-control/caddy-naive.pin")).unwrap(),
        format!("{}\n", super::naive::CADDY_VERSION)
    );
}
#[test]
fn naive_apply_preserves_restored_credentials_and_cover() {
    let rig = Rig::new();
    let adapter = rig.naive();
    let action = rig.action("naive");
    apply(&adapter, &action);
    let paths = ["/var/lib/naive-manager/Caddyfile", "/opt/mtproxy-shared443/secrets/naive-manager-token"];
    let before = paths.map(|p| fs::read(rig.host(p)).unwrap());
    let domain = adapter.selection(&action).unwrap().domain;
    let cover = format!("/var/www/{domain}/index.html");
    rig.put(&cover, b"operator cover", 0o644);
    apply(&rig.naive(), &action);
    for (i, path) in paths.iter().enumerate() {
        assert_eq!(fs::read(rig.host(path)).unwrap(), before[i]);
    }
    assert_eq!(fs::read(rig.host(&cover)).unwrap(), b"operator cover");
}
#[test]
fn naive_apply_refuses_unpinned_caddy_and_missing_forward_proxy() {
    for fail in ["version", "list-modules"] {
        let rig = Rig::new();
        *rig.fail.lock().unwrap() = Some(fail.into());
        assert!(rig.naive().apply(&rig.action("naive"), rig.naive().prepare(&rig.action("naive")).unwrap()).is_err());
    }
}
#[test]
fn publishing_the_keypair_fails_closed() {
    let rig = Rig::new();
    *rig.fail.lock().unwrap() = Some("renewal-hooks/deploy".into());
    let adapter = rig.naive();
    let action = rig.action("naive");
    assert!(adapter.apply(&action, adapter.prepare(&action).unwrap()).is_err());
}
#[test]
fn mieru_stage_returns_verified_binary_and_upstream_notice() {
    let rig = Rig::new();
    let staged = rig.mieru().stage(&rig.action("mieru")).unwrap();
    assert_eq!(fs::read(&staged.binary).unwrap(), b"pinned-mita\n");
    assert_eq!(fs::read(&staged.license).unwrap(), super::mieru::LICENSE_NOTICE);
    let path = staged.binary.clone();
    drop(staged);
    assert!(!path.exists());
}
#[test]
fn mieru_rejects_wrong_package_or_executable_digest() {
    for key in ["package-digest", "executable-digest"] {
        let rig = Rig::new();
        let mut action = rig.action("mieru");
        set(&mut action, key, &"0".repeat(64));
        assert!(rig.mieru().stage(&action).is_err());
        assert!(fs::read_dir(rig.host("/var/tmp")).map(|mut v| v.next().is_none()).unwrap_or(true));
    }
}
#[test]
fn mieru_rejects_an_executable_reporting_an_unpinned_version() {
    let rig = Rig::new();
    *rig.fail.lock().unwrap() = Some(" version".into());
    assert!(rig.mieru().stage(&rig.action("mieru")).is_err());
}
#[test]
fn mieru_apply_orders_artifact_identities_bootstrap_and_overlay() {
    let rig = Rig::new();
    apply(&rig.mieru(), &rig.action("mieru"));
    let calls = rig.runner.argvs().iter().map(|a| a.join(" ")).collect::<Vec<_>>();
    let index = |fragment: &str| calls.iter().position(|s| s.contains(fragment)).unwrap();
    assert!(index("dpkg-deb") < index("systemd-tmpfiles"));
    assert!(index("systemd-tmpfiles") < index("systemd-run"));
    assert!(index("reset-failed mita-bootstrap") < index("systemd-run"));
    assert!(index("apply config") < index("systemctl enable"));
    assert!(index("prepare-mieru-token") < index("up -d --build --wait"));
    assert!(!rig.host("/var/lib/mita/bootstrap-input.json").exists());
    assert!(rig.host("/var/lib/mita").is_dir());
}
#[test]
fn mieru_apply_installs_the_pinned_binary_license_and_client() {
    let rig = Rig::new();
    apply(&rig.mieru(), &rig.action("mieru"));
    assert_eq!(fs::read(rig.host("/usr/bin/mita")).unwrap(), b"pinned-mita\n");
    assert_eq!(fs::metadata(rig.host("/usr/bin/mita")).unwrap().mode() & 0o777, 0o755);
    assert_eq!(fs::read(rig.host("/usr/share/doc/mita/copyright")).unwrap(), super::mieru::LICENSE_NOTICE);
    let calls = rig.runner.argvs();
    let build = calls.iter().find(|argv| argv.starts_with(&strings(&["docker", "build", "--tag"]))).unwrap();
    assert!(build.contains(&super::mieru::CLIENT_IMAGE.into()));
    assert!(!Path::new(build.last().unwrap()).exists());
}
#[test]
fn mieru_apply_refuses_unpinned_client_package_or_executable() {
    let rig = Rig::new();
    rig.put("/var/lib/proxy-control/mieru_3.38.1_amd64.deb", b"wrong", 0o644);
    let adapter = rig.mieru();
    let action = rig.action("mieru");
    assert!(adapter
        .apply(&action, adapter.prepare(&action).unwrap())
        .unwrap_err()
        .message()
        .contains("client package"));
    let rig = Rig::new();
    let mut adapter = rig.mieru();
    adapter.client_pins.as_mut().unwrap().2 = "0".repeat(64);
    let action = rig.action("mieru");
    assert!(adapter
        .apply(&action, adapter.prepare(&action).unwrap())
        .unwrap_err()
        .message()
        .contains("client executable"));
}
#[test]
fn mieru_apply_keeps_a_restored_generation() {
    let rig = Rig::new();
    rig.put("/var/lib/mita/server_config.json", b"{\"users\":[{\"name\":\"restored\"}]}", 0o600);
    apply(&rig.mieru(), &rig.action("mieru"));
    assert_eq!(
        fs::read(rig.host("/var/lib/mita/server_config.json")).unwrap(),
        b"{\"users\":[{\"name\":\"restored\"}]}"
    );
    assert!(!rig.runner.argvs().iter().any(|a| a.contains(&"apply".into())));
}
#[test]
fn mieru_apply_refuses_a_foreign_preexisting_binary() {
    let rig = Rig::new();
    rig.put("/usr/bin/mita", b"foreign", 0o755);
    let adapter = rig.mieru();
    let action = rig.action("mieru");
    assert!(adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap_err().message().contains("pre-existing"));
}
#[test]
fn mieru_apply_writes_overlay_with_socket_group_and_http_text_token() {
    let rig = Rig::new();
    apply(&rig.mieru(), &rig.action("mieru"));
    let env = fs::read_to_string(rig.host("/opt/mtproxy-shared443/.env.mieru")).unwrap();
    assert!(env.contains("MIERU_MITA_GID=998"));
    assert!(env.contains(&sha256_hex(b"pinned-mita\n")));
    let token = fs::read_to_string(rig.host("/etc/mieru-manager/token")).unwrap();
    assert_eq!(token.trim().len(), 64);
    assert!(token.trim().bytes().all(|b| b.is_ascii_hexdigit()));
}
#[test]
fn recovery_verifies_nonempty_manager_state() {
    let rig = Rig::new();
    rig.put("/var/lib/mieru-manager/state.json", b"{}", 0o600);
    apply(&rig.mieru(), &rig.action("mieru"));
    assert!(rig
        .runner
        .argvs()
        .iter()
        .any(|a| a.iter().any(|s| s == "/usr/local/libexec/prepare-mieru-state") && a.iter().any(|s| s == "verify")));
}
#[test]
fn proxy_prepare_refuses_active_unowned_resources() {
    let rig = Rig::new();
    for name in ["naive", "mieru"] {
        let unit = if name == "naive" {
            "/etc/systemd/system/caddy-naive.service"
        } else {
            "/etc/systemd/system/mita.service"
        };
        rig.put(unit, b"foreign", 0o644);
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        assert!(adapter.prepare(&rig.action(name)).unwrap_err().message().contains("active"));
    }
}
#[test]
fn proxy_prepare_adopts_only_proven_markers() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        let action = rig.action(name);
        apply(adapter.as_ref(), &action);
        assert_eq!(adapter.prepare(&action).unwrap()["adoption"], "recovery");
        fs::set_permissions(rig.host(&format!("/etc/proxy-control/{name}-owned")), fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(adapter.prepare(&action).is_err());
    }
}
#[test]
fn proxy_checkpoints_reject_foreign_fields_and_escaping_paths() {
    let rig = Rig::new();
    for name in ["naive", "mieru"] {
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        let action = rig.action(name);
        let mut data = adapter.prepare(&action).unwrap();
        data.insert("surprise".into(), true.into());
        assert!(adapter.apply(&action, data).is_err());
        let mut data = adapter.prepare(&action).unwrap();
        data["planned_ownership"]["/etc/foreign"] = json!({"preserve":false,"sha256":"0".repeat(64)});
        assert!(adapter.rollback(&action, data, true, RollbackTarget::Uninstalled).is_err());
    }
}
#[test]
fn proxy_acceptance_requires_every_end_to_end_fact() {
    for name in ["naive", "mieru"] {
        let value = success(name);
        let validate = if name == "naive" { require_naive } else { require_mieru };
        validate(&value).unwrap();
        for (key, field) in value.as_object().unwrap() {
            if field.is_boolean() && key != "temporary_state_removed" {
                let mut broken = value.clone();
                broken[key] = false.into();
                assert!(validate(&broken).is_err(), "{name}:{key}");
            }
        }
        let mut broken = value.clone();
        broken["surprise"] = true.into();
        assert!(validate(&broken).is_err());
    }
}
#[test]
fn proxy_acceptance_counts_must_be_nonnegative_and_consistent() {
    for name in ["naive", "mieru"] {
        let validate = if name == "naive" { require_naive } else { require_mieru };
        for field in if name == "naive" {
            ["connect_bytes", "recorded_bytes"]
        } else {
            ["transports_verified", "transports_expected"]
        } {
            for value in [json!(-1), json!(true), json!(1.0), Value::Null] {
                let mut broken = success(name);
                broken[field] = value;
                assert!(validate(&broken).is_err());
            }
        }
    }
    let mut value = success("naive");
    value["recorded_bytes"] = 0.into();
    assert!(require_naive(&value).unwrap_err().message().contains("accounting"));
    let mut value = success("mieru");
    value["transports_verified"] = 3.into();
    assert!(require_mieru(&value).is_err());
}
#[test]
fn proxy_verify_removes_temporary_state_and_mints_new_names() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        let action = rig.action(name);
        apply(adapter.as_ref(), &action);
        let first = adapter.verify(&action).unwrap();
        assert_eq!(first.details["temporary_state_removed"], true);
        adapter.verify(&action).unwrap();
        let names = rig.cleanup_names.lock().unwrap();
        assert_eq!(names.len(), 2);
        assert_ne!(names[0], names[1]);
        assert!(!rig.host(&format!("/etc/proxy-control/{name}-acceptance-pending")).exists());
    }
}
#[test]
fn proxy_verify_refuses_drifted_pending_owner() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        let action = rig.action(name);
        apply(adapter.as_ref(), &action);
        rig.put(
            &format!("/etc/proxy-control/{name}-acceptance-pending"),
            format!("proxy-control-{name}-0000000000000000\n").as_bytes(),
            0o600,
        );
        assert!(adapter.verify(&action).is_err());
    }
}
#[test]
fn proxy_verify_keeps_pending_cleanup_on_failure() {
    let rig = Rig::new();
    let adapter = rig.naive();
    let action = rig.action("naive");
    apply(&adapter, &action);
    *rig.clean_fail.lock().unwrap() = true;
    assert!(adapter.verify(&action).is_err());
    assert!(rig.host("/etc/proxy-control/naive-acceptance-pending").exists());
    *rig.clean_fail.lock().unwrap() = false;
    assert!(adapter.verify(&action).is_ok());
}
#[test]
fn proxy_repair_detects_owned_drift() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        let action = rig.action(name);
        let data = apply(adapter.as_ref(), &action);
        rig.put(
            if name == "naive" { "/etc/proxy-control/caddy-naive.pin" } else { "/etc/systemd/system/mita.service" },
            b"tampered",
            0o644,
        );
        assert!(adapter.repair(&action, data).unwrap_err().message().contains("drifted"));
    }
}
#[test]
fn proxy_repair_revalidates_state_and_token_boundaries() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        let action = rig.action(name);
        let data = apply(adapter.as_ref(), &action);
        *rig.fail.lock().unwrap() =
            Some(if name == "naive" { "prepare-naive-state verify" } else { "prepare-mieru-token verify" }.into());
        assert!(adapter.repair(&action, data).is_err());
    }
}
#[test]
fn proxy_rollback_preserves_state_credentials_and_preexisting_binary() {
    for name in ["naive", "mieru"] {
        for preexisting in [false, true] {
            let rig = Rig::new();
            let binary = if name == "naive" { super::naive::CADDY_BINARY } else { super::mieru::BINARY };
            if preexisting {
                rig.put(binary, if name == "naive" { b"operator-caddy\n" } else { b"pinned-mita\n" }, 0o755);
            }
            let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
            let action = rig.action(name);
            let data = apply(adapter.as_ref(), &action);
            let result = adapter.rollback(&action, data, false, RollbackTarget::RolledBack).unwrap();
            assert_eq!(result.details["persistent_data_preserved"], true);
            assert_eq!(rig.host(binary).exists(), preexisting);
            assert!(rig
                .host(if name == "naive" { "/var/lib/naive-manager/manager-token" } else { "/etc/mieru-manager/token" })
                .exists());
            assert!(rig.host(&format!("/etc/proxy-control/{name}-owned")).exists());
        }
    }
}
#[test]
fn proxy_explicit_uninstall_purge_removes_persistent_state() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        let action = rig.action(name);
        let data = apply(adapter.as_ref(), &action);
        adapter.rollback(&action, data, true, RollbackTarget::Uninstalled).unwrap();
        assert!(!rig.host(&format!("/etc/proxy-control/{name}-owned")).exists());
        assert!(!rig
            .host(if name == "naive" { "/var/lib/naive-manager/manager-token" } else { "/etc/mieru-manager/token" })
            .exists());
    }
}
#[test]
fn proxy_failed_install_purge_flag_is_not_destructive_uninstall() {
    let rig = Rig::new();
    let adapter = rig.naive();
    let action = rig.action("naive");
    let data = apply(&adapter, &action);
    adapter.rollback(&action, data, true, RollbackTarget::RolledBack).unwrap();
    assert!(rig.host("/var/lib/naive-manager/manager-token").exists());
}
#[test]
fn proxy_rollback_cleanup_failure_is_retryable_and_purge_can_discard() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        let action = rig.action(name);
        let data = apply(adapter.as_ref(), &action);
        let owner = fs::read(rig.host(&format!("/etc/proxy-control/{name}-acceptance-owner"))).unwrap();
        rig.put(&format!("/etc/proxy-control/{name}-acceptance-pending"), &owner, 0o600);
        *rig.clean_fail.lock().unwrap() = true;
        let result = adapter.rollback(&action, data.clone(), false, RollbackTarget::RolledBack).unwrap();
        assert_eq!(result.details["temporary_cleanup_pending"], true);
        assert!(rig.host(&format!("/etc/proxy-control/{name}-acceptance-owner")).exists());
        adapter.rollback(&action, data, true, RollbackTarget::Uninstalled).unwrap();
        assert!(!rig.host(&format!("/etc/proxy-control/{name}-acceptance-owner")).exists());
    }
}
#[test]
fn proxy_compose_keeps_all_present_sibling_overlays() {
    let rig = Rig::new();
    for name in ["naive", "mieru", "xray-router", "amneziawg", "trusttunnel"] {
        rig.put(&format!("{PROJECT}/.env.{name}"), b"present", 0o600);
    }
    for name in ["naive", "mieru"] {
        let host = Host { context: rig.context.clone(), name, label: if name == "naive" { "Naive" } else { "Mieru" } };
        let argv = host.compose_argv(&["up", "-d", "--wait"]).unwrap();
        for sibling in ["naive", "mieru", "xray-router", "amneziawg", "trusttunnel"] {
            assert!(argv.contains(&format!("{PROJECT}/compose.{sibling}.yaml")));
        }
        assert_eq!(
            argv.iter().rposition(|arg| arg == "-f").map(|i| &argv[i + 1]),
            Some(&format!("{PROJECT}/compose.{name}.yaml"))
        );
    }
}
#[test]
fn compose_runs_to_completion_not_through_diagnostic_capture() {
    let rig = Rig::new();
    *rig.fail.lock().unwrap() = Some(" up ".into());
    let host = Host { context: rig.context.clone(), name: "naive", label: "Naive" };
    let error = host.compose(&["up", "-d", "--build", "--wait"]).unwrap_err().message();
    assert!(error.contains("container failed readiness"));
    assert!(!error.contains("DO-NOT-LEAK"));
    assert!(rig
        .runner
        .calls()
        .iter()
        .filter(|call| call.argv.contains(&"up".into()))
        .all(|call| call.kind == CallKind::Run));
}
#[test]
fn compose_failure_retains_bounded_sanitized_diagnostics() {
    let dir = TempDir::new("proxy-compose-errors");
    let runner = Arc::new(RecordingRunner::with_responder(|call| {
        Some(if call.kind == CallKind::Run {
            Reply::exit(1, "", "sensitive")
        } else if call.argv.contains(&"inspect".into()) {
            Reply::ok("restarting exit=1 oom=false health=unhealthy")
        } else if call.argv.contains(&"logs".into()) {
            Reply::ok("PermissionError: private path\nValueError: PLAIN-SENSITIVE-MATERIAL password=DO-NOT-LEAK")
        } else {
            Reply::ok(&"a".repeat(64))
        })
    }));
    let host = Host {
        context: AdapterContext { root: dir.path().into(), tree: tree(), runner },
        name: "mieru",
        label: "Mieru",
    };
    let message = host.compose(&["up", "-d"]).unwrap_err().message();
    assert!(message.contains("PermissionError"));
    assert!(message.contains("exit=1"));
    assert!(!message.contains("DO-NOT-LEAK"));
    assert!(!message.contains("PLAIN-SENSITIVE"));
    assert!(message.len() < 3200);
}
#[test]
fn a_failed_identity_lookup_is_not_a_collision() {
    for value in ["", "exit=2 ", "diagnostic unavailable: OSError", "other:x:10009:10009::/nonexistent:/bin/false"] {
        assert!(identity_from_entry(value, 10003).is_none());
    }
    assert_eq!(
        identity_from_entry("naive-caddy:x:10003:10004::/nonexistent:/usr/sbin/nologin", 10003),
        Some("naive-caddy".into())
    );
}
#[test]
fn client_config_proves_only_the_selected_transport() {
    let native = json!({"profiles":[{"servers":[{"portBindings":[{"protocol":"TCP","port":46001},{"protocol":"UDP","port":46002}]}]}]});
    let selected = client_config_for(&native, "UDP", 46002).unwrap();
    assert_eq!(selected["profiles"][0]["servers"][0]["portBindings"], json!([{"protocol":"UDP","port":46002}]));
    assert_eq!(native["profiles"][0]["servers"][0]["portBindings"].as_array().unwrap().len(), 2);
    assert!(client_config_for(&native, "TCP", 46009).is_err());
}
#[test]
fn transport_selection_rejects_invalid_and_duplicate_bindings() {
    for value in ["", "TCP:443", "UDP:0", "TCP:65536", "TCP:-1", "TCP:+1", "TCP:1;TCP:1", "tcp:46001", "TCP:no"] {
        assert!(super::mieru::decode_transports(value).is_err(), "{value}");
    }
    assert_eq!(
        super::mieru::decode_transports("UDP:46002;TCP:46001").unwrap(),
        vec![("TCP".into(), 46001), ("UDP".into(), 46002)]
    );
}
#[test]
fn protocol_host_paths_refuse_any_symlink_parent() {
    let rig = Rig::new();
    let real = rig.host("/safe");
    fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(&real, rig.host("/link")).unwrap();
    assert!(rig.naive().host.host("/link/child").is_err());
}
#[test]
fn real_engine_installs_repairs_and_uninstalls_both_protocol_adapters() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let adapter: Arc<dyn Adapter> = if name == "naive" { Arc::new(rig.naive()) } else { Arc::new(rig.mieru()) };
        let action = rig.action(name);
        let plan = plan_with(vec![action], serde_json::Map::new());
        let engine = engine_for(rig.dir.path(), vec![adapter]);
        let digest = plan.digest();
        let state = engine.apply(&plan, &digest).unwrap();
        assert_eq!(state.status, crate::Status::Active);
        assert_eq!(engine.repair().unwrap().status, crate::Status::Active);
        assert_eq!(engine.uninstall(true).unwrap().status, crate::Status::Uninstalled);
    }
}

#[test]
fn a_missing_package_is_fetched_from_its_pin_and_bad_download_is_discarded() {
    let dir = TempDir::new("proxy-download");
    let target = dir.path().join("mita.deb");
    let payload = b"a pinned package\n";
    let digest = sha256_hex(payload);
    super::mieru::ensure_pinned_package(&target, "https://example.invalid/custom-amd64.deb", &digest, |url, path| {
        assert_eq!(url, "https://example.invalid/custom-amd64.deb");
        fs::write(path, payload)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(fs::read(&target).unwrap(), payload);
    super::mieru::ensure_pinned_package(&target, "https://example.invalid/unused", &digest, |_, _| {
        panic!("operator-staged package must not be replaced")
    })
    .unwrap();
    fs::remove_file(&target).unwrap();
    assert!(super::mieru::ensure_pinned_package(&target, "https://example.invalid/custom", &digest, |_, path| {
        fs::write(path, b"wrong bytes")?;
        Ok(())
    })
    .is_err());
    assert!(!target.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}
#[test]
fn concurrent_operator_staging_is_never_replaced_by_download() {
    let dir = TempDir::new("proxy-download-race");
    let path = dir.path().join("mita.deb");
    super::mieru::ensure_pinned_package(
        &path,
        "https://example.invalid/package",
        &sha256_hex(b"download"),
        |_, stage| {
            fs::write(stage, b"download")?;
            fs::write(&path, b"operator")?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(fs::read(path).unwrap(), b"operator");
}
#[test]
fn mieru_release_pin_url_is_preserved_in_planned_and_selected_action() {
    let rig = Rig::new();
    let manifest = pc_host::archive::ReleaseManifest::from_bytes(
        &fs::read(tree().join("release/external-artifacts.json")).unwrap(),
    )
    .unwrap();
    let mut pin = manifest.external_artifact("mita", "amd64").unwrap().clone();
    pin.url = "https://github.com/enfein/mieru/releases/download/v3.38.1/custom-mita_3.38.1_amd64.deb".into();
    let adapter = MieruAdapter::with_pin(&rig.context, pin.clone()).unwrap();
    let action = adapter.plan(&config(), &AuditFacts::default()).unwrap().remove(0);
    assert_eq!(adapter.selection(&action).unwrap().package_url, pin.url);
    assert!(action.mutations.contains(&format!("package-url={}", pin.url)));
    pin.architecture = "arm64".into();
    assert!(MieruAdapter::with_pin(&rig.context, pin).is_err());
}
#[test]
fn router_seeds_refresh_the_manager_copy_without_rewriting_live_state() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let mut action = rig.action(name);
        set(&mut action, "egress", "router");
        set(
            &mut action,
            "router-provider",
            if name == "naive" { "socks5://127.0.0.1:45101" } else { "socks5://127.0.0.1:45102" },
        );
        let secret = format!("{PROJECT}/secrets/xray-router-ingress-{name}");
        rig.put(&secret, format!("{name}-cafe0001:{}\n", "k".repeat(43)).as_bytes(), 0o600);
        rig.put(&format!("{PROJECT}/.env.xray-router"), b"present", 0o600);
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        apply(adapter.as_ref(), &action);
        let state = if name == "naive" { "/var/lib/naive-manager" } else { "/var/lib/mieru-manager" };
        let live =
            if name == "naive" { "/var/lib/naive-manager/Caddyfile" } else { "/var/lib/mita/server_config.json" };
        let original = fs::read(rig.host(live)).unwrap();
        rig.put(&secret, format!("{name}-cafe0002:{}\n", "z".repeat(43)).as_bytes(), 0o600);
        apply(adapter.as_ref(), &action);
        let copy = rig.host(&format!("{state}/xray-router-ingress"));
        assert_eq!(fs::metadata(&copy).unwrap().mode() & 0o777, 0o400);
        assert!(fs::read_to_string(copy).unwrap().starts_with(&format!("{name}-cafe0002:")));
        assert_eq!(fs::read(rig.host(live)).unwrap(), original);
        assert!(!rig.runner.argvs().iter().any(|argv| argv.join(" ").contains(&"k".repeat(43))));
    }
}
#[test]
fn router_seeds_refuse_missing_or_unsafe_credential() {
    for name in ["naive", "mieru"] {
        for unsafe_secret in [false, true] {
            let rig = Rig::new();
            let mut action = rig.action(name);
            set(&mut action, "egress", "router");
            set(
                &mut action,
                "router-provider",
                if name == "naive" { "socks5://127.0.0.1:45101" } else { "socks5://127.0.0.1:45102" },
            );
            if unsafe_secret {
                rig.put(&format!("{PROJECT}/secrets/xray-router-ingress-{name}"), b"malformed", 0o666);
            }
            let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
            assert!(adapter.apply(&action, adapter.prepare(&action).unwrap()).is_err());
        }
    }
}
#[test]
fn version_agent_installed_binary_is_accepted_unless_rollback_failed() {
    let rig = Rig::new();
    rig.put("/usr/bin/mita", b"agent-mita\n", 0o755);
    rig.put(
        "/var/lib/proxy-control/version-agent/state.json",
        json!({"schema":2,"components":{"mita":{"sha256":sha256_hex(b"agent-mita\n")}}}).to_string().as_bytes(),
        0o600,
    );
    apply(&rig.mieru(), &rig.action("mieru"));
    assert_eq!(fs::read(rig.host("/usr/bin/mita")).unwrap(), b"agent-mita\n");
    rig.put(
        "/var/lib/proxy-control/version-agent/state.json",
        json!({"schema":2,"components":{"mita":{"sha256":sha256_hex(b"agent-mita\n"),"status":"rollback_failed"}}})
            .to_string()
            .as_bytes(),
        0o600,
    );
    let adapter = rig.mieru();
    let action = rig.action("mieru");
    assert!(adapter.apply(&action, adapter.prepare(&action).unwrap()).is_err());
}
#[test]
fn lane_slots_require_router_do_not_collide_and_start_each_daemon() {
    let rig = Rig::new();
    let mut action = rig.action("mieru");
    set(&mut action, "lane-slots", "4");
    assert!(rig.mieru().selection(&action).is_err());
    set(&mut action, "router-provider", "socks5://127.0.0.1:45102");
    rig.put(
        &format!("{PROJECT}/secrets/xray-router-ingress-mieru"),
        format!("mieru-cafe0001:{}\n", "k".repeat(43)).as_bytes(),
        0o600,
    );
    let adapter = rig.mieru();
    apply(&adapter, &action);
    let env = fs::read_to_string(rig.host("/opt/mtproxy-shared443/.env.mieru")).unwrap();
    for index in 1..=4 {
        assert!(
            env.contains(&format!("{index}:{}:/run/mita/lane-{index}.sock:/var/lib/mita/lanes/{index}", 46100 + index))
        );
        assert!(rig
            .runner
            .argvs()
            .iter()
            .any(|a| a == &strings(&["systemctl", "enable", "--now", &format!("mita@{index}")])));
    }
    set(&mut action, "transports", "TCP:46101");
    assert!(adapter.selection(&action).is_err());
    set(&mut action, "lane-slots", "9");
    assert!(adapter.selection(&action).is_err());
}
#[test]
fn service_rewritten_state_is_mutable_but_other_ownership_is_not() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        let action = rig.action(name);
        let data = apply(adapter.as_ref(), &action);
        let mutable =
            if name == "naive" { "/var/lib/naive-manager/Caddyfile" } else { "/var/lib/mita/server_config.json" };
        rig.put(mutable, b"rewritten by manager", 0o600);
        adapter.repair(&action, data.clone()).unwrap();
        adapter.rollback(&action, data, true, RollbackTarget::Uninstalled).unwrap();
        assert!(!rig.host(mutable).exists());
    }
}
#[test]
fn h2_connect_uses_private_config_and_rejects_wrong_nested_tls_status() {
    for response in ["200 17 200", "200 559 000", "500 17 200", "200 0 200", "invalid"] {
        let dir = TempDir::new("proxy-h2");
        let root = dir.path().to_path_buf();
        let answer = response.to_string();
        let seen = Arc::new(Mutex::new(None::<PathBuf>));
        let shared = seen.clone();
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            assert_eq!(call.argv[..2], strings(&["curl", "--config"]));
            assert!(!call.argv.join(" ").contains("secret"));
            let path = PathBuf::from(&call.argv[2]);
            let body = fs::read_to_string(&path).unwrap();
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
            assert!(body.contains("proxy-http2"));
            assert!(body.contains("proxy-user = \"alice:secret\""));
            assert!(body.contains("url = \"https://example.com/\""));
            *shared.lock().unwrap() = Some(path);
            Some(Reply::ok(&answer))
        }));
        let adapter = NaiveAdapter::new(&AdapterContext { root, tree: tree(), runner });
        let result = adapter.connect_h2("https://alice:secret@naive.example.com", "naive.example.com");
        match response {
            "200 17 200" => assert_eq!(result.unwrap(), (17, true, true)),
            "200 559 000" => assert_eq!(result.unwrap(), (559, true, true)),
            "500 17 200" => assert_eq!(result.unwrap(), (17, true, false)),
            _ => assert!(result.is_err()),
        }
        assert!(!seen.lock().unwrap().as_ref().unwrap().exists());
    }
}
#[test]
fn h2_connect_refuses_foreign_proxy_and_redacts_execution_failure() {
    let rig = Rig::new();
    let adapter = rig.naive();
    for url in [
        "http://alice:secret@naive.example.com",
        "https://alice:secret@foreign.example.com",
        "https://naive.example.com",
        "https://alice:%0Asecret@naive.example.com",
    ] {
        assert!(adapter.connect_h2(url, "naive.example.com").is_err());
    }
    *rig.fail.lock().unwrap() = Some("curl".into());
    let error =
        adapter.connect_h2("https://alice:secret@naive.example.com", "naive.example.com").unwrap_err().message();
    assert!(!error.contains("secret"));
    assert!(!error.contains("DO-NOT-LEAK"));
}
#[test]
fn real_engine_rolls_back_failed_acceptance_without_removing_credentials() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let mut bad = success(name);
        bad["manager_health_ok"] = false.into();
        *rig.acceptance.lock().unwrap() = bad;
        let adapter: Arc<dyn Adapter> = if name == "naive" { Arc::new(rig.naive()) } else { Arc::new(rig.mieru()) };
        let plan = plan_with(vec![rig.action(name)], serde_json::Map::new());
        let engine = engine_for(rig.dir.path(), vec![adapter]);
        assert!(engine.apply(&plan, &plan.digest()).is_err());
        assert_eq!(engine.store().read_state().unwrap().status, crate::Status::RolledBack);
        assert!(rig
            .host(if name == "naive" { "/var/lib/naive-manager/manager-token" } else { "/etc/mieru-manager/token" })
            .exists());
    }
}

#[test]
fn repair_migrates_checkpoint_owned_python_helpers_and_recovers_an_interrupted_rebase() {
    for name in ["naive", "mieru"] {
        let rig = Rig::new();
        let adapter: Box<dyn Adapter> = if name == "naive" { Box::new(rig.naive()) } else { Box::new(rig.mieru()) };
        let action = rig.action(name);
        let mut data = apply(adapter.as_ref(), &action);
        let path = if name == "naive" {
            "/usr/local/libexec/prepare-naive-state"
        } else {
            "/usr/local/libexec/prepare-mieru-token"
        };
        let bytes =
            b"#!/usr/bin/env python3\n# Previous release-owned helper bytes, covered by the old journal digest.\n"
                .to_vec();
        rig.put(path, &bytes, 0o755);
        data["ownership"][path]["sha256"] = sha256_hex(&bytes).into();
        let repaired = adapter.repair(&action, data.clone()).unwrap();
        let current = fs::read(rig.host(path)).unwrap();
        assert!(current.starts_with(b"#!/bin/sh\nexec "));
        assert_eq!(repaired["ownership"][path]["sha256"], sha256_hex(&current));
        // Simulate losing power after wrapper replacement but before the engine persisted new ownership.
        let recovered = adapter.repair(&action, data).unwrap();
        assert_eq!(recovered["ownership"][path]["sha256"], sha256_hex(&current));
        rig.put(path, b"#!/bin/sh\nexec /untrusted\n", 0o755);
        assert!(adapter.repair(&action, recovered).is_err());
    }
}
#[test]
fn agent_digest_refresh_rebases_only_the_exact_expected_manager_environment() {
    let rig = Rig::new();
    let adapter = rig.mieru();
    let action = rig.action("mieru");
    let data = apply(&adapter, &action);
    rig.put("/usr/bin/mita", b"agent-mita\n", 0o755);
    let digest = sha256_hex(b"agent-mita\n");
    rig.put(
        "/var/lib/proxy-control/version-agent/state.json",
        json!({"schema":2,"components":{"mita":{"sha256":digest}}}).to_string().as_bytes(),
        0o600,
    );
    let mut selected = adapter.selection(&action).unwrap();
    selected.executable_digest = digest;
    rig.put("/opt/mtproxy-shared443/.env.mieru", adapter.env_text(&selected, 998).as_bytes(), 0o600);
    let repaired = adapter.repair(&action, data).unwrap();
    assert_eq!(repaired["ownership"]["/usr/bin/mita"]["sha256"], sha256_hex(b"agent-mita\n"));
    let env = rig.host("/opt/mtproxy-shared443/.env.mieru");
    let body = fs::read_to_string(&env).unwrap().replace("MIERU_PUBLIC_HOST=", "UNTRUSTED_HOST=");
    rig.put("/opt/mtproxy-shared443/.env.mieru", body.as_bytes(), 0o600);
    assert!(adapter.repair(&action, repaired).is_err());
}
#[test]
fn protocol_compose_preserves_agent_version_overrides() {
    let rig = Rig::new();
    let path = format!("{PROJECT}/version-overrides/compose.versions.yaml");
    rig.put(&path, b"services: {}", 0o600);
    for name in ["naive", "mieru"] {
        let host = Host { context: rig.context.clone(), name, label: if name == "naive" { "Naive" } else { "Mieru" } };
        let argv = host.compose_argv(&["up", "-d"]).unwrap();
        assert!(argv.windows(2).any(|pair| pair == ["-f", &path]));
    }
}

#[test]
fn mieru_acceptance_preserves_the_audited_neighbor_baseline() {
    let rig = Rig::new();
    let mut facts = AuditFacts::default();
    facts.listeners.insert("tcp".into(), json!([443, 8787]));
    facts.listeners.insert("udp".into(), json!([50000]));
    let action = rig.mieru().plan(&config(), &facts).unwrap().remove(0);
    let selected = rig.mieru().selection(&action).unwrap();
    assert_eq!(selected.adjacent_listeners, vec![("TCP".into(), 443), ("TCP".into(), 8787), ("UDP".into(), 50000)]);
    let runner = Arc::new(RecordingRunner::new());
    runner.reply(&["ss"], Reply::ok("tcp LISTEN 0 128 127.0.0.1:443 0.0.0.0:*\nudp UNCONN 0 0 *:50000 *:*\n"));
    let adapter = MieruAdapter::new(&AdapterContext { runner, ..rig.context.clone() });
    assert!(adapter.adjacent_listeners_ok(&[("TCP".into(), 443), ("UDP".into(), 50000)]));
    assert!(!adapter.adjacent_listeners_ok(&selected.adjacent_listeners));
}
#[test]
fn interrupted_mieru_apply_removes_proven_partial_license_and_environment() {
    let rig = Rig::new();
    *rig.fail.lock().unwrap() = Some(" up ".into());
    let adapter: Arc<dyn Adapter> = Arc::new(rig.mieru());
    let plan = plan_with(vec![rig.action("mieru")], serde_json::Map::new());
    let engine = engine_for(rig.dir.path(), vec![adapter]);
    assert!(engine.apply(&plan, &plan.digest()).is_err());
    assert_eq!(engine.store().read_state().unwrap().status, crate::Status::RolledBack);
    for path in [
        "/usr/bin/mita",
        "/usr/share/doc/mita/copyright",
        "/opt/mtproxy-shared443/.env.mieru",
        "/etc/systemd/system/mita.service",
    ] {
        assert!(!rig.host(path).exists(), "{path} leaked");
    }
    assert!(rig.host("/etc/mieru-manager/token").exists());
}

#[test]
fn naive_accepts_the_caddy_the_version_agent_built_but_not_a_failed_rollback() {
    let rig = Rig::new();
    rig.put(super::naive::CADDY_BINARY, b"agent-built-caddy", 0o755);
    let runner = Arc::new(RecordingRunner::with_responder(|call| {
        if call.argv.last().is_some_and(|arg| arg == "version") {
            return Some(Reply::ok("v2.12.0 h1:agent="));
        }
        if call.argv.last().is_some_and(|arg| arg == "list-modules") {
            return Some(Reply::ok("http.handlers.forward_proxy\n"));
        }
        Some(Reply::ok(""))
    }));
    let adapter = NaiveAdapter::new(&AdapterContext { runner, ..rig.context.clone() });
    let action = rig.action("naive");
    rig.put(
        "/var/lib/proxy-control/version-agent/state.json",
        json!({"schema":2,"components":{"naive":{"runtime_version":"v2.12.0 h1:agent="}}}).to_string().as_bytes(),
        0o600,
    );
    assert!(adapter.prepare(&action).is_ok());
    rig.put(
        "/var/lib/proxy-control/version-agent/state.json",
        json!({"schema":2,"components":{"naive":{"runtime_version":"v2.12.0 h1:agent=","status":"rollback_failed"}}})
            .to_string()
            .as_bytes(),
        0o600,
    );
    assert!(adapter.prepare(&action).unwrap_err().message().contains("unpinned Caddy"));
}
#[test]
fn live_fixed_identity_collisions_are_rechecked_before_mutation() {
    let rig = Rig::new();
    for (name, database, id) in [
        ("naive", "passwd", "10003"),
        ("naive", "group", "10004"),
        ("mieru", "passwd", "10005"),
        ("mieru", "group", "10005"),
    ] {
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(&["getent", database, id], Reply::ok(&format!("foreign:x:{id}:10004::/nonexistent:/bin/false\n")));
        let context = AdapterContext { runner: runner.clone(), ..rig.context.clone() };
        let adapter: Box<dyn Adapter> =
            if name == "naive" { Box::new(NaiveAdapter::new(&context)) } else { Box::new(MieruAdapter::new(&context)) };
        assert!(adapter.prepare(&rig.action(name)).unwrap_err().message().contains("collision"));
        assert!(runner.calls().iter().all(|call| call.kind != CallKind::Run));
    }
}
