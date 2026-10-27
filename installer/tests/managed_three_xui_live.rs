//! Explicit destructive lab proof, invoked only by managed-xui-acceptance.sh on ams-test.
//! All commands execute real native processes; no fake runner or repinned artifact.
use installer::adapter::Adapter;
use installer::adapters::{three_xui::ThreeXuiAdapter, AdapterContext};
use installer::three_xui_api::{ThreeXuiApi, ThreeXuiClient};
use installer_core::planner::AuditFacts;
use pc_host::runner::{Bounded, BoundedError, BoundedOutput, Capture, HostRunner, QueryError, RunError, RunOptions, RunOutput, SystemRunner};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

// The library's production bootstrap re-execs current_exe (the installer). Here
// current_exe is libtest, so delegate that one command to the actual installer.
// Everything, including the bootstrap's real network namespace, runs unchanged.
struct NativeRunner { installer: String }
impl HostRunner for NativeRunner {
    fn bounded(&self, argv: &[&str], limits: Bounded) -> Result<BoundedOutput, BoundedError> {
        SystemRunner.bounded(argv, limits)
    }
    fn run(&self, argv: &[&str], options: &RunOptions<'_>) -> Result<RunOutput, RunError> {
        if argv.last() == Some(&"three-xui-bootstrap") {
            let mut native = argv.to_vec();
            let index = native.len() - 2;
            native[index] = &self.installer;
            SystemRunner.run(&native, options)
        } else {
            SystemRunner.run(argv, options)
        }
    }
    fn capture(&self, argv: &[&str], max_chars: usize, limits: Capture) -> String {
        SystemRunner.capture(argv, max_chars, limits)
    }
    fn capture_checked(&self, argv: &[&str], timeout: Duration) -> Result<String, QueryError> {
        SystemRunner.capture_checked(argv, timeout)
    }
}

#[test]
#[ignore = "destructive real-host proof: use scripts/lab/managed-xui-acceptance.sh on ams-test"]
fn real_managed_three_xui_native_provision() {
    assert_eq!(std::env::var("PC_MANAGED_XUI_LIVE").as_deref(), Ok("ams-test"));
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let tree = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let installer = std::env::var("PC_INSTALLER_BIN")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_proxy-control-installer").into());
    assert!(Path::new(&installer).is_file(), "native installer unavailable");
    let context = AdapterContext {
        root: PathBuf::from("/"), tree: tree.into(), runner: Arc::new(NativeRunner { installer }),
    };
    let mut config = installer_core::config::load_config(&tree.join("examples/installer/managed-three-xui.toml")).unwrap();
    config.three_xui.panel_domain = Some("xui.lab.test".into());
    config.three_xui.vless_tcp_domain = Some("vless.lab.test".into());
    config.three_xui.vless_xhttp_domain = Some("xhttp.lab.test".into());
    config.three_xui.hysteria_domain = Some("hy2.lab.test".into());
    config.three_xui.subscription_domain = None;
    config.three_xui.warp = false;
    let adapter = ThreeXuiAdapter::new(&context);
    let action = adapter.plan(&config, &AuditFacts::default()).unwrap().into_iter()
        .find(|action| action.id == "three_xui.runtime").unwrap();
    let checkpoint = adapter.prepare(&action).unwrap();
    let checkpoint = adapter.apply(&action, checkpoint).unwrap();
    assert!(checkpoint["staged"] == true);
    adapter.verify(&action).unwrap();
    assert!(fs::metadata("/etc/x-ui/x-ui.db").unwrap().len() > 0, "managed database absent");
    let access = fs::read_to_string("/var/lib/proxy-control/three-xui/panel-access").unwrap();
    let field = |key: &str| -> String {
        let encoded = access.lines().find_map(|line| line.strip_prefix(&format!("{key} = "))).unwrap();
        serde_json::from_str(encoded).unwrap()
    };
    let url = field("url");
    let web_path = url.strip_prefix("https://xui.lab.test").unwrap();
    let cert = Path::new("/etc/letsencrypt/live/xui.lab.test/fullchain.pem");
    let mut api = ThreeXuiApi::new(ThreeXuiClient::new("127.0.0.1", 8451, Some(cert)).unwrap(), web_path).unwrap();
    api.login(&field("username"), &field("password")).unwrap();
    let effective = api.effective_config().unwrap();
    let inbounds = effective["inbounds"].as_array().unwrap();
    for (port, protocol) in [(8449, "vless"), (8450, "vless"), (443, "hysteria")] {
        assert!(inbounds.iter().any(|row| row["port"] == port && row["protocol"] == protocol), "managed API inbound missing");
    }
    assert!(!effective["client_emails"].as_array().unwrap().iter().any(|value| value.as_str().is_some_and(|email| email.starts_with("acceptance-"))));
    let audit = adapter.audit_existing().unwrap();
    assert!(audit["installed"] == true);
    let runtime = audit["inbounds"].as_array().unwrap();
    for port in [8449, 8450, 443] {
        assert!(runtime.iter().any(|row| row["port"] == port), "effective Xray inbound absent");
    }
    println!("MANAGED_XUI_NATIVE_OK database=true tls_http=true inbounds=3 acceptance_clients=0 runtime_config=true");
}
