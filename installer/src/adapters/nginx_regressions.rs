//! Safety/lifecycle cases retained from the retired Python adapter tests.
use super::*;
use crate::testkit::TempDir;
use pc_host::runner::{RecordingRunner, Reply};
use std::os::unix::fs::symlink;

const ORIGINAL: &str = "map $ssl_preread_server_name $sni_backend {\n    default 127.0.0.1:9443;\n    foreign.example.com 127.0.0.1:9444;\n}\nserver { listen 443; ssl_preread on; proxy_pass $sni_backend; }\n";
const TARGET: &str = "/etc/nginx/stream.d/foreign.conf";

struct Host {
    _dir: TempDir,
    root: PathBuf,
    runner: Arc<RecordingRunner>,
    adapter: NginxAdapter,
}

impl Host {
    fn new(link: bool) -> Self {
        let dir = TempDir::new("nginx-safety");
        let root = dir.path().to_path_buf();
        fs::create_dir_all(root.join("etc/nginx/stream.d")).unwrap();
        fs::write(root.join("etc/nginx/nginx.conf"), "events {}\nstream { include /etc/nginx/stream.d/*.conf; }\n").unwrap();
        let target = root.join(TARGET.trim_start_matches('/'));
        if link {
            let original = root.join("etc/nginx/original.conf");
            fs::write(&original, ORIGINAL).unwrap();
            symlink("../original.conf", &target).unwrap();
        } else {
            fs::write(&target, ORIGINAL).unwrap();
        }
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        let observed = root.clone();
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            if call.argv == ["nginx", "-T"] {
                let main = fs::read_to_string(observed.join("etc/nginx/nginx.conf")).unwrap();
                let content = fs::read_to_string(observed.join(TARGET.trim_start_matches('/'))).unwrap_or_default();
                Some(Reply::ok(&format!("# configuration file /etc/nginx/nginx.conf:\n{main}\n# configuration file {TARGET}:\n{content}\n")))
            } else {
                None
            }
        }));
        let adapter = NginxAdapter::new(&AdapterContext { root: root.clone(), tree: root.clone(), runner: runner.clone() });
        Self { _dir: dir, root, runner, adapter }
    }

    fn path(&self) -> PathBuf {
        self.root.join(TARGET.trim_start_matches('/'))
    }

    fn action(&self) -> Action {
        let (kind, resolved, link) = self.adapter.planned_path_identity(TARGET, false).unwrap();
        Action::new("nginx.routes", "nginx", "proxy-control:nginx", vec![
            "mode=coexist".into(), "stream_context=present".into(), format!("target={TARGET}"),
            "variable=$sni_backend".into(), format!("path_kind={kind}"), format!("resolved_path={resolved}"),
            format!("symlink_target={}", link.as_deref().unwrap_or("-")),
            "route=panel.example.com 127.0.0.1:8443".into(), "route=relay.example.com 127.0.0.1:8445".into(),
        ], vec!["audited active stream map".into()], vec!["selected routes active".into()], vec!["remove only owned routes".into()], false).unwrap()
    }

    fn applied(&self) -> (Action, CheckpointData) {
        let action = self.action();
        let prepared = self.adapter.prepare(&action).unwrap();
        let applied = self.adapter.apply(&action, prepared).unwrap();
        (action, applied)
    }
}

#[test]
fn coexist_replay_and_rollback_preserve_adjacent_routes_and_symlink_metadata() {
    for link in [false, true] {
        let host = Host::new(link);
        let before = host.path().metadata().unwrap();
        let (action, applied) = host.applied();
        let installed = fs::read(host.path()).unwrap();
        let replayed = host.adapter.repair(&action, applied).unwrap();
        assert_eq!(fs::read(host.path()).unwrap(), installed);
        let adjacent = String::from_utf8(installed).unwrap().replace("foreign.example.com", "neighbor.example.com");
        fs::write(host.path(), &adjacent).unwrap();
        assert!(host.adapter.verify(&action).unwrap().success);
        assert!(host.adapter.rollback(&action, replayed, false, RollbackTarget::Uninstalled).unwrap().success);
        assert_eq!(fs::read_to_string(host.path()).unwrap(), ORIGINAL.replace("foreign.example.com", "neighbor.example.com"));
        let after = host.path().metadata().unwrap();
        assert_eq!((after.mode() & 0o777, after.uid(), after.gid()), (before.mode() & 0o777, before.uid(), before.gid()));
        assert_eq!(host.path().symlink_metadata().unwrap().file_type().is_symlink(), link);
        if link { assert_eq!(fs::read_link(host.path()).unwrap(), Path::new("../original.conf")); }
    }
}

#[test]
fn failed_validation_restores_exact_bytes_without_reload() {
    let host = Host::new(false);
    let action = host.action();
    let prepared = host.adapter.prepare(&action).unwrap();
    host.runner.reply_once(&["nginx", "-t"], Reply::exit(1, "", "bad config"));
    assert!(host.adapter.apply(&action, prepared).is_err());
    assert_eq!(fs::read_to_string(host.path()).unwrap(), ORIGINAL);
    assert!(!host.runner.argvs().iter().any(|argv| argv == &["systemctl", "reload", "nginx"]));
}

#[test]
fn path_identity_changes_refuse_before_apply_verify_or_rollback() {
    for phase in ["apply", "verify", "rollback"] {
        let host = Host::new(true);
        let action = host.action();
        let prepared = host.adapter.prepare(&action).unwrap();
        let checkpoint = if phase == "apply" { prepared } else { host.adapter.apply(&action, prepared).unwrap() };
        let victim = host.root.join("etc/nginx/victim.conf");
        fs::write(&victim, "must not change\n").unwrap();
        fs::remove_file(host.path()).unwrap();
        symlink("../victim.conf", host.path()).unwrap();
        match phase {
            "apply" => assert!(host.adapter.apply(&action, checkpoint).is_err()),
            "verify" => assert!(!host.adapter.verify(&action).unwrap().success),
            _ => assert!(host.adapter.rollback(&action, checkpoint, false, RollbackTarget::RolledBack).is_err()),
        }
        assert_eq!(fs::read_to_string(&victim).unwrap(), "must not change\n");
        assert_eq!(fs::read_link(host.path()).unwrap(), Path::new("../victim.conf"));
    }
}

#[test]
fn active_route_topology_drift_blocks_verify_and_rollback() {
    let host = Host::new(false);
    let (action, applied) = host.applied();
    let drifted = fs::read_to_string(host.path()).unwrap().replace("listen 443;", "listen 8444;");
    fs::write(host.path(), &drifted).unwrap();
    assert!(!host.adapter.verify(&action).unwrap().success);
    assert!(host.adapter.rollback(&action, applied, false, RollbackTarget::RolledBack).is_err());
    assert_eq!(fs::read_to_string(host.path()).unwrap(), drifted);
}

#[test]
fn corrupt_or_unbound_checkpoint_never_mutates_selected_file() {
    for defect in ["route_identity", "owner", "target"] {
        let host = Host::new(false);
        let action = host.action();
        let mut prepared = host.adapter.prepare(&action).unwrap();
        match defect {
            "route_identity" => { prepared.insert("route_identity".into(), json!([])); }
            "owner" => { prepared.insert("owner".into(), json!(42)); }
            _ => { prepared.get_mut("route_identity").unwrap()["original_path"] = json!("/etc/nginx/other.conf"); }
        }
        assert!(host.adapter.apply(&action, prepared).is_err(), "{defect}");
        assert_eq!(fs::read_to_string(host.path()).unwrap(), ORIGINAL);
        assert!(host.runner.calls().is_empty());
    }
}

#[test]
fn interrupted_apply_recovers_backup_but_refuses_a_missing_backup() {
    for remove_backup in [false, true] {
        let host = Host::new(false);
        let action = host.action();
        let prepared = host.adapter.prepare(&action).unwrap();
        host.adapter.apply(&action, prepared.clone()).unwrap();
        if remove_backup {
            let spec = action_specification(&action).unwrap();
            let identity = checkpoint_identity(&prepared, &spec).unwrap();
            fs::remove_file(host.adapter.backup_path(&action, &identity).unwrap()).unwrap();
        }
        let result = host.adapter.reconcile_apply(&action, prepared);
        assert_eq!(result.is_err(), remove_backup);
        if let Ok(applied) = result {
            assert!(host.adapter.rollback(&action, applied, false, RollbackTarget::RolledBack).unwrap().success);
            assert_eq!(fs::read_to_string(host.path()).unwrap(), ORIGINAL);
        }
    }
}

#[test]
fn reentered_apply_preserves_own_write_but_refuses_foreign_edits() {
    let host = Host::new(false);
    let action = host.action();
    let prepared = host.adapter.prepare(&action).unwrap();
    host.adapter.apply(&action, prepared.clone()).unwrap();
    let desired = fs::read(host.path()).unwrap();
    host.adapter.apply(&action, prepared.clone()).unwrap();
    assert_eq!(fs::read(host.path()).unwrap(), desired);
    let drifted = String::from_utf8(desired).unwrap().replace("panel.example.com", "foreign-replacement.example.com");
    fs::write(host.path(), &drifted).unwrap();
    assert!(host.adapter.apply(&action, prepared).is_err());
    assert_eq!(fs::read_to_string(host.path()).unwrap(), drifted);
}

#[test]
fn source_authentication_accepts_only_nginx_separator_not_embedded_markers() {
    let host = Host::new(false);
    for suffix in ["", "\n", "\n\n"] {
        let dump = format!("# configuration file {TARGET}:\n{ORIGINAL}{suffix}");
        let result = host.adapter.authenticate_source(&dump, TARGET);
        assert_eq!(result.is_ok(), suffix.len() <= 1, "separator {suffix:?}");
    }
    let forged = format!("# configuration file {TARGET}:\n# configuration file /etc/nginx/other.conf:\n{ORIGINAL}");
    assert!(host.adapter.authenticate_source(&forged, TARGET).is_err());
    fs::write(host.path(), ORIGINAL.replace('\n', "\r\n")).unwrap();
    let dump = format!("# configuration file {TARGET}:\n{}\n", ORIGINAL.replace('\n', "\r\n"));
    assert!(host.adapter.authenticate_source(&dump, TARGET).is_ok());
}
