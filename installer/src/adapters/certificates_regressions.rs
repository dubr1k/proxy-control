//! Certificate ownership, crash recovery and validation regressions from the Python suite.
use super::*;
use crate::testkit::TempDir;
use pc_host::runner::{RecordingRunner, Reply};
use std::os::unix::fs::symlink;

type Faults = Arc<std::sync::Mutex<Vec<(Vec<String>, Reply)>>>;

fn action() -> Action {
    Action::new(
        "certificate.proxy-control",
        "certificates",
        "proxy-control:certificate:proxy-control",
        vec![
            "service=proxy-control".into(),
            "certificate=relay.example.com".into(),
            "email=owner@example.com".into(),
            "name=panel.example.com".into(),
            "name=relay.example.com".into(),
            "webroot=/var/www/panel.example.com".into(),
            "webroot=/var/www/relay.example.com".into(),
        ],
        vec!["audited ACME lineage and vhost".into()],
        vec!["exact certificate and SANs".into()],
        vec!["remove only owned lineage".into()],
        false,
    )
    .unwrap()
}

fn seed(root: &Path) {
    let live = root.join("etc/letsencrypt/live/relay.example.com");
    fs::create_dir_all(&live).unwrap();
    fs::create_dir_all(root.join("etc/letsencrypt/archive/relay.example.com")).unwrap();
    fs::create_dir_all(root.join("etc/letsencrypt/renewal")).unwrap();
    fs::write(root.join("etc/letsencrypt/renewal/relay.example.com.conf"), "renewal\n").unwrap();
    for name in ["cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"] {
        fs::write(live.join(name), name).unwrap();
    }
    fs::set_permissions(live.join("privkey.pem"), fs::Permissions::from_mode(0o600)).unwrap();
}

struct Host {
    _dir: TempDir,
    root: PathBuf,
    runner: Arc<RecordingRunner>,
    adapter: CertificatePlan,
    faults: Faults,
}

impl Host {
    fn new() -> Self {
        let dir = TempDir::new("certificate-safety");
        let root = dir.path().to_path_buf();
        let observed = root.clone();
        let faults: Faults = Arc::default();
        let injected = faults.clone();
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            let args = &call.argv;
            if let Some((_, reply)) = injected.lock().unwrap().iter().find(|(prefix, _)| args.starts_with(prefix)) {
                return Some(reply.clone());
            }
            if args == &["nginx", "-T"] {
                let content =
                    fs::read_to_string(observed.join("etc/nginx/conf.d/proxy-control-acme-proxy-control.conf"))
                        .unwrap_or_default();
                return Some(Reply::ok(&if content.is_empty() {
                    String::new()
                } else {
                    format!(
                        "# configuration file /etc/nginx/conf.d/proxy-control-acme-proxy-control.conf:\n{content}\n"
                    )
                }));
            }
            if args.starts_with(&["certbot".into(), "certonly".into()]) {
                seed(&observed);
            }
            if args.first().is_some_and(|a| a == "openssl") {
                if args.contains(&"-pubout".into()) || args.contains(&"-pubkey".into()) {
                    return Some(Reply::ok("PUBLIC KEY\n"));
                }
                if args.contains(&"subjectAltName".into()) {
                    return Some(Reply::ok(
                        "X509v3 Subject Alternative Name:\nDNS:panel.example.com, DNS:relay.example.com\n",
                    ));
                }
            }
            Some(Reply::ok(""))
        }));
        let adapter =
            CertificatePlan::new(&AdapterContext { root: root.clone(), tree: root.clone(), runner: runner.clone() });
        Self { _dir: dir, root, runner, adapter, faults }
    }
    fn live(&self) -> PathBuf {
        self.root.join("etc/letsencrypt/live/relay.example.com")
    }
    fn vhost(&self) -> PathBuf {
        self.root.join("etc/nginx/conf.d/proxy-control-acme-proxy-control.conf")
    }
    fn applied(&self) -> CheckpointData {
        self.adapter.apply(&action(), self.adapter.prepare(&action()).unwrap()).unwrap()
    }
    fn reply(&self, prefix: &[&str], reply: Reply) {
        self.faults.lock().unwrap().push((prefix.iter().map(|s| s.to_string()).collect(), reply));
    }
}

#[test]
fn invalid_private_key_or_certificate_contract_never_verifies() {
    for defect in ["key-mode", "key-owner", "missing", "key-pair", "expired", "chain", "sans", "extra-san"] {
        let mut host = Host::new();
        host.applied();
        match defect {
            "key-mode" => {
                fs::set_permissions(host.live().join("privkey.pem"), fs::Permissions::from_mode(0o644)).unwrap()
            }
            "key-owner" => {
                host.adapter.expected_key_owner = (10003, 10004);
            }
            "missing" => fs::remove_file(host.live().join("chain.pem")).unwrap(),
            "key-pair" => host.reply(&["openssl", "pkey"], Reply::ok("DIFFERENT KEY\n")),
            "expired" => host.reply(&["openssl", "x509"], Reply::exit(1, "", "expired")),
            "chain" => host.reply(&["openssl", "verify"], Reply::exit(1, "", "untrusted")),
            _ => {
                let cert = host.live().join("cert.pem");
                host.reply(
                    &["openssl", "x509", "-in", &cert.to_string_lossy(), "-noout", "-ext", "subjectAltName"],
                    Reply::ok(if defect == "sans" {
                        "DNS:relay.example.com\n"
                    } else {
                        "DNS:panel.example.com, DNS:relay.example.com, DNS:foreign.example.com\n"
                    }),
                );
            }
        }
        assert!(!host.adapter.verify(&action()).unwrap().success, "{defect}");
    }
}

#[test]
fn foreign_incomplete_lineage_and_post_prepare_appearance_are_never_adopted() {
    let host = Host::new();
    fs::create_dir_all(host.live()).unwrap();
    fs::write(host.live().join("privkey.pem"), "foreign key").unwrap();
    assert!(host.adapter.prepare(&action()).is_err());
    assert_eq!(fs::read_to_string(host.live().join("privkey.pem")).unwrap(), "foreign key");
    let host = Host::new();
    let prepared = host.adapter.prepare(&action()).unwrap();
    seed(&host.root);
    assert!(host.adapter.apply(&action(), prepared).is_err());
    assert!(host.live().join("privkey.pem").is_file());
    assert!(!host.vhost().exists());
}

#[test]
fn completed_interrupted_issuance_is_reused_and_partial_issuance_replaced() {
    for complete in [false, true] {
        let host = Host::new();
        let prepared = host.adapter.prepare(&action()).unwrap();
        host.applied();
        if !complete {
            fs::remove_file(host.live().join("cert.pem")).unwrap();
        }
        host.runner.clear();
        let recovered = host.adapter.reconcile_apply(&action(), prepared).unwrap();
        assert_eq!(
            host.runner.argvs().iter().any(|a| a.starts_with(&["certbot".into(), "certonly".into()])),
            !complete
        );
        assert!(host.adapter.verify(&action()).unwrap().success);
        assert!(host.adapter.rollback(&action(), recovered, false, RollbackTarget::RolledBack).unwrap().success);
        assert!(host.live().join("fullchain.pem").exists());
    }
}

#[test]
fn rollback_cleans_only_incomplete_action_lineage_and_refuses_symlink_escape() {
    for unsafe_path in [false, true] {
        let host = Host::new();
        let prepared = host.adapter.prepare(&action()).unwrap();
        fs::create_dir_all(host.live()).unwrap();
        fs::write(host.live().join("privkey.pem"), "partial").unwrap();
        let neighbor = host.root.join("etc/letsencrypt/live/neighbor.example.com");
        fs::create_dir_all(&neighbor).unwrap();
        fs::write(neighbor.join("privkey.pem"), "neighbor").unwrap();
        if unsafe_path {
            fs::remove_dir_all(host.live()).unwrap();
            symlink(&neighbor, host.live()).unwrap();
        }
        let result = host.adapter.rollback(&action(), prepared, false, RollbackTarget::RolledBack);
        assert_eq!(result.is_err(), unsafe_path);
        assert_eq!(fs::read_to_string(neighbor.join("privkey.pem")).unwrap(), "neighbor");
        if !unsafe_path {
            assert!(!host.live().exists());
        }
    }
}

#[test]
fn rollback_restores_removed_vhost_on_validation_failure_but_does_not_create_absent_vhost() {
    for present in [true, false] {
        let host = Host::new();
        let applied = host.applied();
        let desired = fs::read(host.vhost()).unwrap();
        if !present {
            fs::remove_file(host.vhost()).unwrap();
        }
        host.reply(&["nginx", "-t"], Reply::exit(1, "", "invalid"));
        assert!(host.adapter.rollback(&action(), applied, false, RollbackTarget::RolledBack).is_err());
        assert_eq!(host.vhost().exists(), present);
        if present {
            assert_eq!(fs::read(host.vhost()).unwrap(), desired);
        }
    }
}

#[test]
fn renewal_failure_is_fatal_and_diagnostics_do_not_leak_acme_output() {
    let host = Host::new();
    let prepared = host.adapter.prepare(&action()).unwrap();
    host.reply(&["certbot", "renew"], Reply::exit(1, "PRIVATE-ACME-OUTPUT", "password=private-secret"));
    let error = host.adapter.apply(&action(), prepared).unwrap_err();
    assert!(!error.to_string().contains("PRIVATE-ACME-OUTPUT"));
    assert!(!error.to_string().contains("private-secret"));
    assert!(host.runner.argvs().iter().any(|a| a.contains(&"--dry-run".into())
        && a.contains(&"--cert-name".into())
        && a.contains(&"relay.example.com".into())));
}

#[test]
fn renewal_retries_only_known_acme_races_once_and_never_exposes_certbot_diagnostics() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let spec = certificate_action(&action()).unwrap();
    for (diagnostic, attempts, succeeds) in [
        ("Unable to update challenge :: authorization must be pending", 2, true),
        ("urn:ietf:params:acme:error:orderNotReady :: not ready to be finalized", 2, true),
        ("The order is not acceptable for finalization", 2, true),
        ("Detail: DNS problem: NXDOMAIN looking up A for relay.example.com", 1, false),
        ("authorization must be pending", 2, false),
    ] {
        let root = TempDir::new("acme-retry");
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let runner = Arc::new(RecordingRunner::with_responder(move |call| {
            if call.argv.starts_with(&["certbot".into(), "renew".into()]) {
                let number = observed.fetch_add(1, Ordering::SeqCst);
                return Some(if number == 0 || !succeeds { Reply::exit(1, "", diagnostic) } else { Reply::ok("") });
            }
            Some(Reply::ok(""))
        }));
        let adapter = CertificatePlan::new(&AdapterContext {
            root: root.path().into(),
            tree: root.path().into(),
            runner: runner.clone(),
        });
        let result = adapter.run_renewal(&spec);
        assert_eq!(result.is_ok(), succeeds, "{diagnostic}");
        assert_eq!(calls.load(Ordering::SeqCst), attempts, "{diagnostic}");
        assert!(
            runner.argvs().iter().all(|argv| argv.iter().map(String::as_str).eq([
                "certbot",
                "renew",
                "--cert-name",
                "relay.example.com",
                "--dry-run",
                "--no-random-sleep-on-renew",
            ])),
            "{diagnostic}"
        );
        if let Err(error) = result {
            assert!(error.to_string().contains("certificate renewal dry run failed"));
            assert!(!error.to_string().contains(diagnostic));
        }
    }
}

#[test]
fn successful_renewal_evidence_is_consumed_once_and_invalidated_by_lineage_change() {
    let host = Host::new();
    let spec = certificate_action(&action()).unwrap();
    seed(&host.root);
    host.adapter.run_renewal(&spec).unwrap();
    host.adapter.run_renewal(&spec).unwrap();
    assert_eq!(
        host.runner.argvs().iter().filter(|argv| argv.starts_with(&["certbot".into(), "renew".into()])).count(),
        1
    );
    fs::write(host.root.join("etc/letsencrypt/renewal/relay.example.com.conf"), "changed renewal\n").unwrap();
    host.adapter.run_renewal(&spec).unwrap();
    assert_eq!(
        host.runner.argvs().iter().filter(|argv| argv.starts_with(&["certbot".into(), "renew".into()])).count(),
        2
    );
    let other = CertificatePlan::new(&AdapterContext {
        root: host.root.clone(),
        tree: host.root.clone(),
        runner: host.runner.clone(),
    });
    other.run_renewal(&spec).unwrap();
    assert_eq!(
        host.runner.argvs().iter().filter(|argv| argv.starts_with(&["certbot".into(), "renew".into()])).count(),
        3
    );
}

#[test]
fn valid_existing_lineage_may_defer_renewal_but_still_must_pass_local_validation() {
    let host = Host::new();
    seed(&host.root);
    let mut action = action();
    action.mutations.push("skip-renewal-dry-run=true".into());
    let prepared = host.adapter.prepare(&action).unwrap();
    assert_eq!(prepared["lineage_preexisting"], true);
    host.adapter.apply(&action, prepared).unwrap();
    host.runner.clear();
    assert!(host.adapter.verify(&action).unwrap().success);
    assert!(!host.runner.argvs().iter().any(|argv| argv.starts_with(&["certbot".into(), "renew".into()])));
    host.reply(&["openssl", "verify"], Reply::exit(1, "", "untrusted"));
    assert!(!host.adapter.verify(&action).unwrap().success);
    assert!(!host.runner.argvs().iter().any(|argv| argv.starts_with(&["certbot".into(), "renew".into()])));
}

#[test]
fn ineffective_or_drifted_owned_vhost_never_verifies_or_is_deleted() {
    let host = Host::new();
    let applied = host.applied();
    host.reply(&["nginx", "-T"], Reply::ok(""));
    assert!(!host.adapter.verify(&action()).unwrap().success);
    let drifted = b"operator-owned replacement\n";
    fs::write(host.vhost(), drifted).unwrap();
    assert!(host.adapter.rollback(&action(), applied, false, RollbackTarget::Uninstalled).is_err());
    assert_eq!(fs::read(host.vhost()).unwrap(), drifted);
}
