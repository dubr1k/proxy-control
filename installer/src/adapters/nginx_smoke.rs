//! Explicit lab-only smoke: real isolated Nginx through the durable transaction engine.
use super::*;
use crate::journal::Status;
use crate::planner::InstallPlan;
use crate::testkit::{engine_for, release, TempDir};
use pc_host::runner::{RecordingRunner, Reply};
use std::process::Command;

struct NginxProcess {
    config: PathBuf,
}
impl Drop for NginxProcess {
    fn drop(&mut self) {
        let _ = Command::new("nginx").args(["-c", &self.config.to_string_lossy(), "-s", "quit"]).output();
    }
}
#[test]
#[ignore = "ams-test only: private mount/network namespaces and tmpfs /run required"]
fn real_nginx_engine_install_repair_uninstall() {
    for namespace in ["net", "mnt"] {
        assert_ne!(
            fs::read_link(format!("/proc/self/ns/{namespace}")).unwrap(),
            fs::read_link(format!("/proc/1/ns/{namespace}")).unwrap(),
            "real nginx smoke requires a private {namespace} namespace",
        );
    }
    assert!(
        fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .any(|line| line.contains(" /run ") && line.contains(" - tmpfs ")),
        "real nginx smoke requires tmpfs /run"
    );
    let dir = TempDir::new("real-nginx-engine");
    let root = dir.path().to_path_buf();
    fs::create_dir_all(root.join("etc/nginx/stream.d")).unwrap();
    fs::create_dir_all(root.join("runtime-stream")).unwrap();
    fs::create_dir_all(root.join("run")).unwrap();
    let config_path = root.join("etc/nginx/nginx.conf");
    fs::write(&config_path, format!("load_module /usr/lib/nginx/modules/ngx_stream_module.so;\npid {}/nginx.pid;\nerror_log {}/error.log;\nevents {{}}\nhttp {{ access_log off; }}\nstream {{ include /etc/nginx/stream.d/*.conf; }}\n", root.display(), root.display())).unwrap();
    let runtime_config = root.join("runtime.conf");
    let _process = NginxProcess { config: runtime_config.clone() };
    let responder_root = root.clone();
    let runner = Arc::new(RecordingRunner::with_responder(move |call| {
        let source = fs::read_to_string(responder_root.join("etc/nginx/nginx.conf")).unwrap();
        let runtime_stream = responder_root.join("runtime-stream/proxy-control.conf");
        match fs::read_to_string(responder_root.join("etc/nginx/stream.d/proxy-control.conf")) {
            Ok(router) => fs::write(
                &runtime_stream,
                router.replace("/run/proxy-control-", &format!("{}/run/proxy-control-", responder_root.display())),
            )
            .unwrap(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let _ = fs::remove_file(&runtime_stream);
            }
            Err(error) => panic!("reading isolated router: {error}"),
        }
        fs::write(
            &runtime_config,
            source.replace("/etc/nginx/stream.d/", &format!("{}/runtime-stream/", responder_root.display())),
        )
        .unwrap();
        let mut command = Command::new("nginx");
        command.args(["-c", &runtime_config.to_string_lossy()]);
        if call.argv.first().is_some_and(|name| name == "nginx") {
            command.args(call.argv.iter().skip(1));
        } else if call.argv == ["systemctl", "reload", "nginx"] {
            if fs::read_to_string(responder_root.join("nginx.pid")).is_ok_and(|pid| !pid.trim().is_empty()) {
                command.args(["-s", "reload"]);
            }
        } else {
            panic!("unexpected real smoke command: {:?}", call.argv);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "real nginx {:?}: {}", call.argv, String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8_lossy(&output.stdout)
            .replace(&runtime_config.to_string_lossy().to_string(), "/etc/nginx/nginx.conf")
            .replace(&format!("{}/runtime-stream/", responder_root.display()), "/etc/nginx/stream.d/")
            .replace(&format!("{}/run/proxy-control-", responder_root.display()), "/run/proxy-control-");
        Some(Reply::exit(output.status.code().unwrap_or(-1), &stdout, &String::from_utf8_lossy(&output.stderr)))
    }));
    let adapter: Arc<dyn Adapter> =
        Arc::new(NginxAdapter::new(&AdapterContext { root: root.clone(), tree: root.clone(), runner }));
    let action = Action::new(
        "nginx.routes",
        "nginx",
        "proxy-control:nginx",
        vec![
            "mode=fresh".into(),
            "client_ip=proxy".into(),
            "panel_tls_backend=127.0.0.1:8443".into(),
            "stream_context=present".into(),
            "target=/etc/nginx/stream.d/proxy-control.conf".into(),
            "variable=$proxy_control_backend".into(),
            "path_kind=missing".into(),
            "resolved_path=/etc/nginx/stream.d/proxy-control.conf".into(),
            "symlink_target=-".into(),
            "route=relay.example.com 127.0.0.1:8445".into(),
            "route=panel.example.com 127.0.0.1:8443".into(),
        ],
        vec!["isolated lab topology observed".into()],
        vec!["real nginx syntax and active route verified".into()],
        vec!["remove only owned router".into()],
        false,
    )
    .unwrap();
    let config = installer_core::config::load_config(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/installer/core.toml"),
    )
    .unwrap();
    let plan = InstallPlan::new(
        config.canonical_dict(),
        AuditFacts::default(),
        release(),
        vec!["nginx".into()],
        BTreeMap::new(),
        vec![action],
        1,
    )
    .unwrap();
    let engine = engine_for(&root, vec![adapter]);
    assert_eq!(engine.apply(&plan, &plan.digest()).unwrap().status, Status::Active);
    assert!(root.join("nginx.pid").is_file());
    assert_eq!(engine.repair().unwrap().status, Status::Active);
    assert_eq!(engine.uninstall(false).unwrap().status, Status::Uninstalled);
    assert!(!root.join("etc/nginx/stream.d/proxy-control.conf").exists());
}
