use super::*;

fn selected() -> Selection {
    Selection {
        proxy_domain: "relay.example.com".into(),
        panel_domain: "panel.example.com".into(),
        subscription_domain: None,
        mcp_domain: None,
        users: vec!["alice".into()],
        proxy_backend_port: 2443,
        panel_app_port: 8787,
        panel_tls_port: 8443,
        adjacent_sni: Vec::new(),
    }
}
fn golden(name: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/renders/core-vhosts").join(name),
    )
    .unwrap()
}
#[test]
fn core_vhosts_match_python_goldens() {
    let mut selected = selected();
    assert_eq!(panel_vhost(&selected), golden("panel.conf"));
    selected.panel_tls_port = 9443;
    assert_eq!(panel_vhost(&selected), golden("panel-tls-9443.conf"));
    selected.panel_tls_port = 8443;
    selected.subscription_domain = Some("sub.example.com".into());
    assert_eq!(panel_vhost(&selected), format!("{}{}", golden("panel.conf"), golden("subscription.conf")));
    selected.mcp_domain = Some("mcp.example.com".into());
    assert_eq!(
        panel_vhost(&selected),
        format!("{}{}{}", golden("panel.conf"), golden("subscription.conf"), golden("mcp.conf"))
    );
}
#[test]
fn users_file_rejects_duplicate_invalid_or_empty_credentials() {
    assert!(valid_users_file("alice=0123456789abcdef0123456789abcdef\n"));
    for invalid in
        ["", "alice=bad\n", "alice=0123456789abcdef0123456789abcdef\nalice=0123456789abcdef0123456789abcdef\n"]
    {
        assert!(!valid_users_file(invalid));
    }
}
#[test]
fn acceptance_owner_is_strict() {
    assert!(acceptance_name("pc-acceptance-0123456789abcdef"));
    for name in ["alice", "pc-acceptance-", "pc-acceptance-0123456789ABCDEF", "pc-acceptance-0123456789abcdef/../owner"]
    {
        assert!(!acceptance_name(name));
    }
}
#[test]
fn compose_diagnostics_redact_credentials() {
    let clean =
        sanitize_compose_diagnostic("password=hidden token:other Authorization: Bearer private-value\nrest", 900);
    assert!(!clean.contains("hidden"));
    assert!(!clean.contains("other"));
    assert!(!clean.contains("private-value"));
}

fn core_action() -> Action {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/plans/core/plan.json");
    let value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let plan = crate::planner::InstallPlan::from_value(&value).unwrap();
    plan.actions.into_iter().find(|action| action.adapter == "core").unwrap()
}

struct AcceptanceMock {
    collision: bool,
    cleanup_fails: bool,
    cleanups: std::sync::atomic::AtomicUsize,
}
impl TestAcceptance for AcceptanceMock {
    fn run(&self, configured: usize) -> Result<CoreAcceptance, Error> {
        if self.collision {
            return Err(collision());
        }
        Ok(CoreAcceptance {
            compose_config_ok: true,
            healthy_services: 3,
            expected_services: 3,
            panel_health_ok: true,
            panel_login_ok: true,
            telemt_api_internal: true,
            respq_verified: configured + 1,
            respq_expected: configured + 1,
            adjacent_sni_ok: true,
            sensitive_scan_ok: true,
            temporary_state_removed: true,
        })
    }
    fn cleanup(&self) -> Result<(), Error> {
        self.cleanups.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.cleanup_fails {
            Err(acceptance("cleanup failed"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn acceptance_pending_marker_protects_collision_and_failed_cleanup_recovery() {
    for (collision, cleanup_fails, pending_before, expected_cleanups, success, pending_after) in [
        (false, false, false, 1, true, false),
        (true, false, false, 0, false, false),
        (true, false, true, 1, false, false),
        (false, true, false, 1, false, true),
    ] {
        let root = crate::testkit::TempDir::new("core-acceptance");
        let mock =
            Arc::new(AcceptanceMock { collision, cleanup_fails, cleanups: std::sync::atomic::AtomicUsize::new(0) });
        let mut adapter = CoreAdapter::new(&AdapterContext {
            root: root.path().into(),
            tree: root.path().into(),
            runner: Arc::new(pc_host::runner::RecordingRunner::new()),
        });
        adapter.test_acceptance = Some(mock.clone());
        fs::create_dir_all(adapter.host(PROJECT).unwrap()).unwrap();
        let name = "pc-acceptance-0123456789abcdef";
        adapter.write_acceptance_owner(name).unwrap();
        let pending = adapter.host(&format!("{PROJECT}/{ACCEPTANCE_PENDING}")).unwrap();
        if pending_before {
            adapter.atomic(&pending, format!("{name}\n").as_bytes(), 0o600).unwrap();
        }
        assert_eq!(adapter.verify(&core_action()).is_ok(), success);
        assert_eq!(pending.exists(), pending_after);
        assert_eq!(mock.cleanups.load(std::sync::atomic::Ordering::SeqCst), expected_cleanups);
    }
}

#[test]
fn acceptance_refuses_foreign_pending_marker_before_network_or_cleanup() {
    let root = crate::testkit::TempDir::new("core-foreign-pending");
    let mock = Arc::new(AcceptanceMock {
        collision: false,
        cleanup_fails: false,
        cleanups: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut adapter = CoreAdapter::new(&AdapterContext {
        root: root.path().into(),
        tree: root.path().into(),
        runner: Arc::new(pc_host::runner::RecordingRunner::new()),
    });
    adapter.test_acceptance = Some(mock.clone());
    fs::create_dir_all(adapter.host(PROJECT).unwrap()).unwrap();
    adapter.write_acceptance_owner("pc-acceptance-0123456789abcdef").unwrap();
    let pending = adapter.host(&format!("{PROJECT}/{ACCEPTANCE_PENDING}")).unwrap();
    adapter.atomic(&pending, b"pc-acceptance-fedcba9876543210\n", 0o600).unwrap();
    assert!(adapter.verify(&core_action()).unwrap_err().message().contains("ownership has drifted"));
    assert_eq!(mock.cleanups.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(pending.exists());
}

#[test]
fn core_engine_preserves_credentials_and_refuses_foreign_drift() {
    use pc_host::runner::{RecordingRunner, Reply};
    use std::sync::Mutex;
    let root = crate::testkit::TempDir::new("core-engine");
    let image_owner = Arc::new(Mutex::new(None::<String>));
    let observed_owner = image_owner.clone();
    let runner = Arc::new(RecordingRunner::with_responder(move |call| {
        if call.argv.first().is_some_and(|program| program.ends_with("/probe/install.sh")) {
            *observed_owner.lock().unwrap() = call.argv.last().cloned();
            return Some(Reply::ok(""));
        }
        if call.argv.starts_with(&["docker".into(), "image".into(), "inspect".into()]) {
            let owner = observed_owner.lock().unwrap();
            return Some(match owner.as_deref() {
                None => Reply::exit(1, "", "image absent"),
                Some(_) if call.argv[4] == "{{.Id}}" => Reply::ok(&format!("sha256:{}", "a".repeat(64))),
                Some(owner) => Reply::ok(owner),
            });
        }
        if call.argv.starts_with(&["docker".into(), "image".into(), "rm".into()]) {
            *observed_owner.lock().unwrap() = None;
        }
        Some(Reply::ok(""))
    }));
    let mut adapter = CoreAdapter::new(&AdapterContext {
        root: root.path().into(),
        tree: Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().into(),
        runner,
    });
    adapter.test_acceptance = Some(Arc::new(AcceptanceMock {
        collision: false,
        cleanup_fails: false,
        cleanups: std::sync::atomic::AtomicUsize::new(0),
    }));
    let action = core_action();
    let plan = crate::planner::InstallPlan::new(
        json!({}),
        AuditFacts::default(),
        crate::testkit::release(),
        vec!["core".into()],
        BTreeMap::new(),
        vec![action],
        1,
    )
    .unwrap();
    let engine = crate::testkit::engine_for(root.path(), vec![Arc::new(adapter)]);
    assert_eq!(engine.apply(&plan, &plan.digest()).unwrap().status, crate::journal::Status::Active);
    let users = root.path().join("opt/mtproxy-shared443/secrets/users.conf");
    let original = fs::read(&users).unwrap();
    assert_eq!(engine.repair().unwrap().status, crate::journal::Status::Active);
    assert_eq!(fs::read(&users).unwrap(), original);
    let owned = root.path().join("opt/mtproxy-shared443/.env");
    fs::write(&owned, "foreign edit\n").unwrap();
    assert!(engine.uninstall(false).is_err());
    assert_eq!(fs::read(&users).unwrap(), original);
}

#[test]
fn every_acceptance_failure_and_inconsistent_count_is_refused() {
    let good = AcceptanceMock { collision: false, cleanup_fails: false, cleanups: Default::default() }.run(2).unwrap();
    require_acceptance(&good).unwrap();
    let document = serde_json::to_value(&good).unwrap();
    for field in [
        "compose_config_ok",
        "panel_health_ok",
        "panel_login_ok",
        "telemt_api_internal",
        "adjacent_sni_ok",
        "sensitive_scan_ok",
        "temporary_state_removed",
        "healthy_services",
        "respq_verified",
        "expected_services",
        "respq_expected",
    ] {
        let mut bad = document.clone();
        bad[field] = if document[field].is_boolean() { json!(false) } else { json!(0) };
        let bad: CoreAcceptance = serde_json::from_value(bad).unwrap();
        assert!(require_acceptance(&bad).is_err(), "{field}");
    }
    for field in ["healthy_services", "respq_verified"] {
        let mut bad = document.clone();
        bad[field] = json!(100);
        let bad: CoreAcceptance = serde_json::from_value(bad).unwrap();
        assert!(require_acceptance(&bad).is_err(), "{field}");
    }
    assert!(good.details().values().all(|value| value.is_boolean() || value.is_u64()));
}

#[test]
fn source_install_does_not_deploy_local_cargo_artifacts() {
    use std::os::unix::fs::symlink;
    let root = crate::testkit::TempDir::new("core-source-artifacts");
    let source = root.path().join("release");
    let shipped = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    for relative in COPY_FILES {
        let destination = source.join(relative);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(shipped.join(relative), destination).unwrap();
    }
    for directory in COPY_DIRECTORIES {
        fs::create_dir_all(source.join(directory)).unwrap();
    }
    let panel_build = source.join("panel/target/debug");
    fs::create_dir_all(&panel_build).unwrap();
    fs::write(panel_build.join("local-build-state"), b"private development artifact").unwrap();
    let shared_build = root.path().join("shared-build");
    fs::create_dir(&shared_build).unwrap();
    fs::write(shared_build.join("local-build-state"), b"private shared development artifact").unwrap();
    symlink(&shared_build, source.join("installer/target")).unwrap();
    let adapter = CoreAdapter::new(&AdapterContext {
        root: root.path().into(),
        tree: source,
        runner: Arc::new(pc_host::runner::RecordingRunner::new()),
    });
    adapter.write_generation(&selected(), None).unwrap();
    let project = root.path().join("opt/mtproxy-shared443");
    assert!(!project.join("panel/target").exists(), "local Cargo output reached the installed panel");
    assert!(!project.join("installer/target").exists(), "a linked Cargo cache reached the installed host tree");
}

fn owned_core() -> (crate::testkit::TempDir, Arc<CoreAdapter>) {
    use pc_host::runner::{RecordingRunner, Reply};
    use std::sync::Mutex;
    let root = crate::testkit::TempDir::new("core-lifecycle-safety");
    let image_owner = Arc::new(Mutex::new(None::<String>));
    let runner = Arc::new(RecordingRunner::with_responder(move |call| {
        if call.argv.first().is_some_and(|program| program.ends_with("/probe/install.sh")) {
            *image_owner.lock().unwrap() = call.argv.last().cloned();
            return Some(Reply::ok(""));
        }
        if call.argv.starts_with(&["docker".into(), "image".into(), "inspect".into()]) {
            return Some(match image_owner.lock().unwrap().as_deref() {
                None => Reply::exit(1, "", "image absent"),
                Some(_) if call.argv[4] == "{{.Id}}" => Reply::ok(&format!("sha256:{}", "a".repeat(64))),
                Some(owner) => Reply::ok(owner),
            });
        }
        if call.argv.starts_with(&["docker".into(), "image".into(), "rm".into()]) {
            *image_owner.lock().unwrap() = None;
        }
        Some(Reply::ok(""))
    }));
    let mut adapter = CoreAdapter::new(&AdapterContext {
        root: root.path().into(),
        tree: Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().into(),
        runner,
    });
    adapter.test_acceptance =
        Some(Arc::new(AcceptanceMock { collision: false, cleanup_fails: false, cleanups: Default::default() }));
    (root, Arc::new(adapter))
}

#[test]
fn core_rollback_preserves_credentials_and_neighboring_project_files_unless_purged() {
    for purge in [false, true] {
        let (root, adapter) = owned_core();
        let action = core_action();
        let applied = adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap();
        let project = root.path().join("opt/mtproxy-shared443");
        let users = project.join("secrets/users.conf");
        let secret = fs::read(&users).unwrap();
        let neighbor = project.join("neighbor.data");
        fs::write(&neighbor, "operator data\n").unwrap();
        assert!(adapter.rollback(&action, applied, purge, RollbackTarget::Uninstalled).unwrap().success);
        assert_eq!(fs::read_to_string(&neighbor).unwrap(), "operator data\n");
        assert_eq!(users.exists(), !purge);
        if !purge {
            assert_eq!(fs::read(&users).unwrap(), secret);
        }
    }
}

#[test]
fn repair_revalidates_credentials_instead_of_adopting_changed_metadata() {
    use std::os::unix::fs::symlink;
    for defect in ["mode", "symlink", "hardlink"] {
        let (root, adapter) = owned_core();
        let action = core_action();
        let applied = adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap();
        let users = root.path().join("opt/mtproxy-shared443/secrets/users.conf");
        let before = fs::read(&users).unwrap();
        match defect {
            "mode" => fs::set_permissions(&users, fs::Permissions::from_mode(0o644)).unwrap(),
            "hardlink" => fs::hard_link(&users, users.with_file_name("alias")).unwrap(),
            _ => {
                let target = users.with_file_name("target");
                fs::rename(&users, &target).unwrap();
                symlink(&target, &users).unwrap();
            }
        }
        assert!(adapter.repair(&action, applied).is_err(), "{defect}");
        assert_eq!(fs::read(&users).unwrap(), before);
    }
}

#[test]
fn unowned_project_probe_image_and_fixed_label_resources_are_not_adopted() {
    use pc_host::runner::{RecordingRunner, Reply};
    for collision_kind in ["project", "image", "volume", "containers"] {
        let root = crate::testkit::TempDir::new("core-foreign");
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(&["docker", "image", "inspect"], Reply::exit(1, "", "absent"));
        match collision_kind {
            "project" => {
                let project = root.path().join("opt/mtproxy-shared443");
                fs::create_dir_all(&project).unwrap();
                fs::write(project.join("foreign"), "untouched").unwrap();
            }
            "image" => {
                // Rules are first-match, so use a fresh responder for the image case below.
            }
            "volume" => {
                runner.reply(&["docker", "volume", "ls"], Reply::ok("proxy_panel_by_dubr1k_panel-data\n"));
            }
            _ => {
                runner.reply(&["docker", "container", "ls"], Reply::ok("foreign-container\n"));
            }
        }
        let runner = if collision_kind == "image" {
            let responder = RecordingRunner::with_responder(|call| {
                Some(if call.argv.starts_with(&["docker".into(), "image".into(), "inspect".into()]) {
                    Reply::ok(if call.argv[4] == "{{.Id}}" {
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    } else {
                        ""
                    })
                } else {
                    Reply::ok("")
                })
            });
            Arc::new(responder)
        } else {
            runner
        };
        let adapter = CoreAdapter::new(&AdapterContext {
            root: root.path().into(),
            tree: Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().into(),
            runner,
        });
        assert!(adapter.prepare(&core_action()).is_err(), "{collision_kind}");
        assert!(!root.path().join("opt/mtproxy-shared443/secrets/users.conf").exists());
        if collision_kind == "project" {
            assert_eq!(fs::read_to_string(root.path().join("opt/mtproxy-shared443/foreign")).unwrap(), "untouched");
        }
    }
}

#[test]
fn real_shared_ingress_preserves_ip_rejects_spoofed_xff_and_keeps_raw_tls() {
    let root = crate::testkit::TempDir::new("core-ingress-consumer");
    fs::write(root.path().join("panel.conf"), panel_vhost(&selected())).unwrap();
    let routes = vec![
        ("naive.example.com".into(), "127.0.0.1:8445".into()),
        ("panel.example.com".into(), "127.0.0.1:8443".into()),
    ];
    fs::write(
        root.path().join("stream.conf"),
        super::super::nginx::render_fresh(&routes, "proxy", "127.0.0.1:8443").unwrap(),
    )
    .unwrap();
    let probe = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/ingress-client-ip.py");
    let result = std::process::Command::new("python3").arg(probe).arg(root.path()).output().unwrap();
    assert!(result.status.success(), "isolated Nginx consumer: {}", String::from_utf8_lossy(&result.stderr));
}

#[test]
fn runtime_volume_purge_validates_all_names_and_labels_before_removing_anything() {
    use pc_host::runner::{RecordingRunner, Reply};
    for defect in ["none", "name", "project", "volume", "shape", "json"] {
        let root = crate::testkit::TempDir::new("core-volume-ownership");
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            let args = &call.argv;
            if args.starts_with(&["docker".into(), "volume".into(), "ls".into()]) {
                return Some(Reply::ok(
                    if args.last().unwrap() == "label=com.docker.compose.project=proxy_panel_by_dubr1k" {
                        "proxy_panel_by_dubr1k_naive-manager-run\nproxy_panel_by_dubr1k_mieru-manager-run\noperator-volume\nproxy_panel_by_dubr1k_panel-data\n"
                    } else {
                        ""
                    },
                ));
            }
            if args.starts_with(&["docker".into(), "volume".into(), "inspect".into()]) {
                let name = args.last().unwrap();
                let mut record = json!({"Name": name, "Labels": {
                    "com.docker.compose.project": "proxy_panel_by_dubr1k",
                    "com.docker.compose.volume": name.strip_prefix("proxy_panel_by_dubr1k_").unwrap(),
                }});
                if name.ends_with("mieru-manager-run") {
                    match defect {
                        "name" => record["Name"] = json!("operator-volume"),
                        "project" => record["Labels"]["com.docker.compose.project"] = json!("foreign"),
                        "volume" => record["Labels"]["com.docker.compose.volume"] = json!("panel-data"),
                        "shape" => return Some(Reply::ok("{}")),
                        "json" => return Some(Reply::ok("not-json")),
                        _ => {}
                    }
                }
                return Some(Reply::ok(&json!([record]).to_string()));
            }
            Some(Reply::ok(""))
        }));
        let adapter = CoreAdapter::new(&AdapterContext {
            root: root.path().into(),
            tree: root.path().into(),
            runner: runner.clone(),
        });
        assert_eq!(adapter.purge_runtime_volumes().is_ok(), defect == "none", "{defect}");
        let removed: Vec<Vec<String>> = runner
            .argvs()
            .into_iter()
            .filter(|a| a.starts_with(&["docker".into(), "volume".into(), "rm".into()]))
            .collect();
        if defect == "none" {
            assert_eq!(
                removed.iter().map(|a| a.last().unwrap().as_str()).collect::<Vec<_>>(),
                ["proxy_panel_by_dubr1k_naive-manager-run", "proxy_panel_by_dubr1k_mieru-manager-run"]
            );
        } else {
            assert!(removed.is_empty(), "{defect}: {removed:?}");
        }
    }
}

#[test]
fn failed_temporary_cleanup_retains_owned_tombstone_until_success_or_explicit_purge() {
    for purge in [false, true] {
        let (root, mut adapter) = owned_core();
        let action = core_action();
        let applied = adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap();
        let owner = root.path().join("opt/mtproxy-shared443").join(ACCEPTANCE_OWNER);
        let pending = root.path().join("opt/mtproxy-shared443").join(ACCEPTANCE_PENDING);
        fs::copy(&owner, &pending).unwrap();
        Arc::get_mut(&mut adapter).unwrap().test_acceptance =
            Some(Arc::new(AcceptanceMock { collision: false, cleanup_fails: true, cleanups: Default::default() }));
        let evidence = adapter.rollback(&action, applied.clone(), purge, RollbackTarget::RolledBack).unwrap();
        assert_eq!(evidence.details["temporary_cleanup_pending"], true);
        assert!(owner.is_file() && pending.is_file());
        if !purge {
            Arc::get_mut(&mut adapter).unwrap().test_acceptance =
                Some(Arc::new(AcceptanceMock { collision: false, cleanup_fails: false, cleanups: Default::default() }));
        }
        let evidence = adapter
            .reconcile_rollback(
                &action,
                applied,
                purge,
                if purge { RollbackTarget::Uninstalled } else { RollbackTarget::RolledBack },
            )
            .unwrap();
        assert_eq!(evidence.details["temporary_cleanup_pending"], false);
        assert!(!pending.exists());
        assert!(!owner.exists());
    }
}

#[test]
fn corrupt_core_checkpoint_refuses_lifecycle_without_mutating_generation_or_foreign_file() {
    for phase in ["apply", "repair", "rollback"] {
        for defect in ["owner", "unknown", "ownership", "escape"] {
            let (root, adapter) = owned_core();
            let action = core_action();
            let prepared = adapter.prepare(&action).unwrap();
            let mut checkpoint = if phase == "apply" { prepared } else { adapter.apply(&action, prepared).unwrap() };
            let victim = root.path().join("operator-file");
            fs::write(&victim, "operator bytes\n").unwrap();
            match defect {
                "owner" => {
                    checkpoint.insert("owner".into(), json!("foreign"));
                }
                "unknown" => {
                    checkpoint.insert("foreign".into(), json!(true));
                }
                "ownership" => {
                    checkpoint.insert("ownership".into(), json!([]));
                }
                _ => {
                    checkpoint["ownership"].as_object_mut().unwrap().insert(
                        "/operator-file".into(),
                        json!({"sha256": sha256_hex(b"operator bytes\n"), "preserve": false}),
                    );
                }
            }
            let before = root.path().join("opt/mtproxy-shared443/.env");
            let original = fs::read(&before).ok();
            let result = match phase {
                "apply" => adapter.apply(&action, checkpoint).map(|_| ()),
                "repair" => adapter.repair(&action, checkpoint).map(|_| ()),
                _ => adapter.rollback(&action, checkpoint, true, RollbackTarget::Uninstalled).map(|_| ()),
            };
            assert!(result.is_err(), "{phase}/{defect}");
            assert_eq!(fs::read_to_string(&victim).unwrap(), "operator bytes\n");
            assert_eq!(fs::read(&before).ok(), original, "{phase}/{defect}");
        }
    }
}

#[test]
fn forged_checkpoint_ownership_refuses_foreign_project_file_and_off_domain_cover_before_mutation() {
    for phase in ["apply", "repair", "rollback"] {
        for (map, absolute) in [
            ("planned_ownership", "/opt/mtproxy-shared443/operator-file"),
            ("planned_ownership", "/var/www/neighbor.example.com/index.html"),
            ("ownership", "/opt/mtproxy-shared443/operator-file"),
            ("ownership", "/var/www/neighbor.example.com/index.html"),
        ] {
            if phase == "apply" && map == "ownership" {
                continue; // Prepared checkpoints cannot have applied ownership at all.
            }
            let (root, adapter) = owned_core();
            let action = core_action();
            let prepared = adapter.prepare(&action).unwrap();
            let mut checkpoint = if phase == "apply" { prepared } else { adapter.apply(&action, prepared).unwrap() };
            let foreign = root.path().join(absolute.trim_start_matches('/'));
            fs::create_dir_all(foreign.parent().unwrap()).unwrap();
            fs::write(&foreign, b"operator bytes\n").unwrap();
            checkpoint[map]
                .as_object_mut()
                .unwrap()
                .insert(absolute.into(), json!({"sha256": sha256_hex(b"operator bytes\n"), "preserve": false}));
            let generation = root.path().join("opt/mtproxy-shared443/.env");
            let original = fs::read(&generation).ok();
            let result = match phase {
                "apply" => adapter.apply(&action, checkpoint).map(|_| ()),
                "repair" => adapter.repair(&action, checkpoint).map(|_| ()),
                _ => adapter.rollback(&action, checkpoint, true, RollbackTarget::Uninstalled).map(|_| ()),
            };
            assert!(result.is_err(), "{phase}/{map}/{absolute}");
            assert_eq!(fs::read(&foreign).unwrap(), b"operator bytes\n", "{phase}/{map}/{absolute}");
            assert_eq!(fs::read(&generation).ok(), original, "{phase}/{map}/{absolute}");
        }
    }
}

#[test]
fn recorded_legacy_core_journal_keeps_exact_retired_script_but_refuses_other_scripts() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/installs/core/journal/state.json");
    let journal: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let data = journal["checkpoints"].as_array().unwrap().iter().find(|entry| entry["adapter"] == "core").unwrap()
        ["data"]
        .as_object()
        .unwrap()
        .clone();
    let retired = format!("{PROJECT}/scripts/proxyctl.py");
    assert!(data["ownership"].get(&retired).is_some());
    let action = core_action();
    CoreCheckpoint::read(&data, &action, true).unwrap().validate_paths(&selected()).unwrap();

    let mut forged = data;
    let neighbor = format!("{PROJECT}/scripts/operator.py");
    let record = forged["planned_ownership"][&retired].clone();
    forged["planned_ownership"].as_object_mut().unwrap().insert(neighbor, record);
    assert!(CoreCheckpoint::read(&forged, &action, true).unwrap().validate_paths(&selected()).is_err());
}

#[test]
fn ingress_upgrade_hands_predecessor_ownership_to_actual_engine_repair() {
    use crate::ingress_upgrade::{upgrade_with_reload, UpgradeOutcome};
    use crate::journal::Status;
    use pc_host::runner::{RecordingRunner, Reply};
    use std::sync::Mutex;

    let root = crate::testkit::TempDir::new("ingress-engine-handoff");
    let observed_root = root.path().to_path_buf();
    let image_owner = Arc::new(Mutex::new(None::<String>));
    let observed_owner = image_owner.clone();
    let runner = Arc::new(RecordingRunner::with_responder(move |call| {
        if call.argv == ["nginx", "-T"] {
            let stream =
                fs::read_to_string(observed_root.join("etc/nginx/stream.d/proxy-control.conf")).unwrap_or_default();
            return Some(Reply::ok(&format!(
                "# configuration file /etc/nginx/nginx.conf:\nstream {{ include /etc/nginx/stream.d/*.conf; }}\n# configuration file /etc/nginx/stream.d/proxy-control.conf:\n{stream}"
            )));
        }
        if call.argv.first().is_some_and(|program| program.ends_with("/probe/install.sh")) {
            *observed_owner.lock().unwrap() = call.argv.last().cloned();
        }
        if call.argv.starts_with(&["docker".into(), "image".into(), "inspect".into()]) {
            return Some(match observed_owner.lock().unwrap().as_deref() {
                None => Reply::exit(1, "", "image absent"),
                Some(_) if call.argv[4] == "{{.Id}}" => Reply::ok(&format!("sha256:{}", "a".repeat(64))),
                Some(owner) => Reply::ok(owner),
            });
        }
        Some(Reply::ok(""))
    }));
    let context = AdapterContext {
        root: root.path().into(),
        tree: Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().into(),
        runner: runner.clone(),
    };
    let mut core = CoreAdapter::new(&context);
    core.test_acceptance =
        Some(Arc::new(AcceptanceMock { collision: false, cleanup_fails: false, cleanups: Default::default() }));
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/installs/core/journal/plan.json");
    let mut plan =
        crate::planner::InstallPlan::from_value(&serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap()).unwrap();
    plan.actions.retain(|action| ["core", "nginx"].contains(&action.adapter.as_str()));
    plan.adapter_order.retain(|name| ["core", "nginx"].contains(&name.as_str()));
    plan.adapter_dependencies.retain(|name, _| ["core", "nginx"].contains(&name.as_str()));
    let nginx = plan.actions.iter_mut().find(|action| action.adapter == "nginx").unwrap();
    // Before client-IP preservation these two mutations were absent, not explicit "legacy".
    nginx.mutations.retain(|entry| !entry.starts_with("client_ip=") && !entry.starts_with("panel_tls_backend="));
    let engine = crate::testkit::engine_for(
        root.path(),
        vec![Arc::new(core), Arc::new(super::super::nginx::NginxAdapter::new(&context))],
    );
    let mut predecessor = engine.apply(&plan, &plan.digest()).unwrap();
    let panel = root.path().join(PANEL_VHOST.trim_start_matches('/'));
    let old_panel = fs::read_to_string(&panel)
        .unwrap()
        .replace("listen unix:/run/proxy-control-panel-tls.sock ssl proxy_protocol; set_real_ip_from unix:; real_ip_header proxy_protocol; ", "")
        .replace("X-Forwarded-For $remote_addr;", "X-Forwarded-For $proxy_add_x_forwarded_for;");
    fs::write(&panel, &old_panel).unwrap();
    let core = predecessor.checkpoints.iter_mut().find(|checkpoint| checkpoint.adapter == "core").unwrap();
    let old_digest = sha256_hex(old_panel.as_bytes());
    core.ownership.get_mut(PANEL_VHOST).unwrap().sha256 = old_digest.clone();
    for declaration in ["ownership", "planned_ownership"] {
        core.data.get_mut(declaration).unwrap()[PANEL_VHOST]["sha256"] = json!(old_digest);
    }
    engine.persist(&predecessor).unwrap();
    engine.assert_all_owned(&predecessor).unwrap();
    let before_config = plan.config.clone();
    let before_actions: Vec<_> = plan.actions.iter().filter(|action| action.adapter != "nginx").cloned().collect();
    let reload = |_runner: &dyn pc_host::runner::HostRunner| Ok(());
    let project = root.path().join("opt/mtproxy-shared443");
    assert!(matches!(
        upgrade_with_reload(&project, root.path(), true, runner.as_ref(), &reload).unwrap(),
        UpgradeOutcome::Applied { .. }
    ));
    assert_eq!(engine.repair().unwrap().status, Status::Active);
    let upgraded = engine.store().read_state().unwrap();
    engine.assert_all_owned(&upgraded).unwrap();
    let migrated = engine.store().read_plan().unwrap();
    assert_eq!(migrated.digest(), upgraded.plan_digest);
    assert_eq!(upgraded.accepted_digest, upgraded.plan_digest);
    assert_eq!(migrated.config, before_config);
    assert_eq!(
        migrated.actions.iter().filter(|action| action.adapter != "nginx").cloned().collect::<Vec<_>>(),
        before_actions
    );
    let repaired = engine.store().read_state().unwrap();
    assert_eq!(
        upgrade_with_reload(&project, root.path(), true, runner.as_ref(), &reload).unwrap(),
        UpgradeOutcome::Current
    );
    assert_eq!(engine.store().read_state().unwrap(), repaired);
    fs::copy(root.path().join("etc/nginx/stream.d/proxy-control.conf"), root.path().join("stream.conf")).unwrap();
    fs::copy(&panel, root.path().join("panel.conf")).unwrap();
    let consumer = std::process::Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/ingress-client-ip.py"))
        .arg(root.path())
        .arg("relay.example.com")
        .output()
        .unwrap();
    assert!(consumer.status.success(), "real upgraded ingress consumer: {}", String::from_utf8_lossy(&consumer.stderr));
}
