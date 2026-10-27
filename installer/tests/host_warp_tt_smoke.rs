//! Explicit Ubuntu lab proofs. Never run against production or without the required isolation.
//! TrustTunnel uses a real OpenSSL private CA, not public ACME; its Certbot-compatible issuer
//! checks HTTP-01 delivery before signing real PEMs. All other commands use real host binaries.
use installer::adapter::Adapter;
use installer::adapters::{
    certificates::CertificatePlan, nginx::NginxAdapter, trusttunnel::TrustTunnelAdapter, warp::WarpAdapter,
    AdapterContext,
};
use installer::engine::TransactionEngine;
use installer::store::TransactionStore;
use installer_core::planner::{Action, AuditFacts, InstallPlan, ReleaseIdentity, PLAN_SCHEMA};
use pc_host::runner::{
    Bounded, BoundedError, BoundedOutput, Capture, HostRunner, QueryError, RunError, RunOptions, RunOutput,
    SystemRunner,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("pc-host-proof-{}", pc_host::fs::token_hex::<8>()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().into()
}
fn checked(args: &[&str]) -> Output {
    let output = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(output.status.success(), "real {} failed: {}", args[0], String::from_utf8_lossy(&output.stderr));
    output
}
fn namespace(kind: &str) {
    assert_ne!(
        fs::read_link(format!("/proc/self/ns/{kind}")).unwrap(),
        fs::read_link(format!("/proc/1/ns/{kind}")).unwrap(),
        "private {kind} namespace required"
    );
}
fn plan(actions: Vec<Action>) -> InstallPlan {
    let names = actions.iter().map(|a| a.adapter.clone()).collect::<Vec<_>>();
    InstallPlan::new(
        json!({"native_lab":true}),
        AuditFacts::default(),
        ReleaseIdentity::new("v4.0.0", &"a".repeat(40), &"b".repeat(64), BTreeMap::new(), BTreeMap::new()).unwrap(),
        names.clone(),
        names.into_iter().map(|n| (n, vec![])).collect(),
        actions,
        PLAN_SCHEMA,
    )
    .unwrap()
}
struct Cleanup {
    container: String,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new("nginx").args(["-s", "quit"]).output();
        let _ = Command::new("docker").args(["rm", "-f", &self.container]).output();
    }
}

struct PrivateIssuer {
    root: PathBuf,
    project: String,
    container: String,
    issued: AtomicUsize,
    renewed: AtomicUsize,
}
impl PrivateIssuer {
    fn argv(&self, args: &[&str]) -> Vec<String> {
        if args == ["systemctl", "reload", "nginx"] {
            return vec!["nginx".into(), "-s".into(), "reload".into()];
        }
        args.iter()
            .map(|s| {
                if s.starts_with("/opt/mtproxy-shared443") {
                    return self.root.join(s.trim_start_matches('/')).to_string_lossy().into_owned();
                }
                if *s == "proxy-control-trusttunnel-manager" {
                    return self.container.clone();
                }
                if s.starts_with("label=com.docker.compose.project=") {
                    return format!("label=com.docker.compose.project={}", self.project);
                }
                if *s == "/etc/ssl/certs" {
                    return self.root.join("ca/trust").to_string_lossy().into_owned();
                }
                s.to_string()
            })
            .collect()
    }
    fn issue(&self, args: &[&str]) -> BoundedOutput {
        let name = args.windows(2).find(|w| w[0] == "--cert-name").unwrap()[1];
        let names = args.windows(2).filter(|w| w[0] == "-d").map(|w| w[1]).collect::<Vec<_>>();
        assert_eq!(names, ["gate.example.org"], "issuer must receive the dedicated TT SAN only");
        // This lab issuer really consumes the adapter's installed HTTP-01 vhost, not merely
        // its command arguments. An unreachable or misrouted challenge fails issuance.
        let challenge = self.root.join("var/www/gate.example.org/.well-known/acme-challenge/native-proof");
        fs::write(&challenge, "native-tt-http01").unwrap();
        let response = checked(&[
            "curl",
            "--fail",
            "--silent",
            "--noproxy",
            "*",
            "--resolve",
            "gate.example.org:80:127.0.0.1",
            "http://gate.example.org/.well-known/acme-challenge/native-proof",
        ]);
        assert_eq!(response.stdout, b"native-tt-http01");
        fs::remove_file(challenge).unwrap();
        let live = self.root.join(format!("etc/letsencrypt/live/{name}"));
        let archive = self.root.join(format!("etc/letsencrypt/archive/{name}"));
        fs::create_dir_all(&live).unwrap();
        fs::create_dir_all(&archive).unwrap();
        let key = archive.join("privkey1.pem");
        let csr = archive.join("request.pem");
        let cert = archive.join("cert1.pem");
        checked(&[
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=gate.example.org",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            csr.to_str().unwrap(),
        ]);
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let ext = archive.join("extensions.cnf");
        fs::write(&ext, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:gate.example.org\n").unwrap();
        checked(&[
            "openssl",
            "x509",
            "-req",
            "-in",
            csr.to_str().unwrap(),
            "-CA",
            self.root.join("ca/ca.pem").to_str().unwrap(),
            "-CAkey",
            self.root.join("ca/ca.key").to_str().unwrap(),
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            ext.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
        ]);
        let chain = fs::read(self.root.join("ca/ca.pem")).unwrap();
        fs::write(archive.join("chain1.pem"), &chain).unwrap();
        let mut full = fs::read(&cert).unwrap();
        full.extend(&chain);
        fs::write(archive.join("fullchain1.pem"), full).unwrap();
        for (target, source) in [
            ("cert.pem", "cert1.pem"),
            ("chain.pem", "chain1.pem"),
            ("fullchain.pem", "fullchain1.pem"),
            ("privkey.pem", "privkey1.pem"),
        ] {
            std::os::unix::fs::symlink(format!("../../archive/{name}/{source}"), live.join(target)).unwrap();
        }
        fs::create_dir_all(self.root.join("etc/letsencrypt/renewal")).unwrap();
        fs::write(
            self.root.join(format!("etc/letsencrypt/renewal/{name}.conf")),
            format!("# Lab OpenSSL private CA; not public ACME\ncert = {}/cert.pem\n", live.display()),
        )
        .unwrap();
        self.issued.fetch_add(1, Ordering::SeqCst);
        BoundedOutput { returncode: 0, stdout: String::new(), stderr: String::new() }
    }
}
impl HostRunner for PrivateIssuer {
    fn bounded(&self, a: &[&str], l: Bounded) -> Result<BoundedOutput, BoundedError> {
        if a.starts_with(&["certbot", "certonly"]) {
            return Ok(self.issue(a));
        }
        if a.starts_with(&["certbot", "renew"]) {
            // This is a local renewal rehearsal only: actually verify the signed chain,
            // hostname and key. Do not label this a public Certbot/ACME dry-run success.
            self.renewed.fetch_add(1, Ordering::SeqCst);
            return SystemRunner.bounded(
                &[
                    "openssl",
                    "verify",
                    "-CAfile",
                    self.root.join("ca/ca.pem").to_str().unwrap(),
                    "-verify_hostname",
                    "gate.example.org",
                    self.root.join("etc/letsencrypt/live/gate.example.org/cert.pem").to_str().unwrap(),
                ],
                l,
            );
        }
        let a = self.argv(a);
        SystemRunner.bounded(&a.iter().map(String::as_str).collect::<Vec<_>>(), l)
    }
    fn run(&self, a: &[&str], o: &RunOptions<'_>) -> Result<RunOutput, RunError> {
        let a = self.argv(a);
        SystemRunner.run(&a.iter().map(String::as_str).collect::<Vec<_>>(), o)
    }
    fn capture(&self, a: &[&str], m: usize, l: Capture) -> String {
        let a = self.argv(a);
        SystemRunner.capture(&a.iter().map(String::as_str).collect::<Vec<_>>(), m, l)
    }
    fn capture_checked(&self, a: &[&str], t: Duration) -> Result<String, QueryError> {
        let a = self.argv(a);
        SystemRunner.capture_checked(&a.iter().map(String::as_str).collect::<Vec<_>>(), t)
    }
}
fn mount_directory(source: &Path, target: &str) {
    fs::create_dir_all(source).unwrap();
    fs::create_dir_all(target).unwrap();
    checked(&["mount", "--bind", source.to_str().unwrap(), target]);
}
fn certificate_action() -> Action {
    Action::new(
        "certificate.trusttunnel",
        "certificates",
        "proxy-control:certificate:trusttunnel",
        vec![
            "service=trusttunnel".into(),
            "certificate=gate.example.org".into(),
            "email=lab@example.org".into(),
            "name=gate.example.org".into(),
            "webroot=/var/www/gate.example.org".into(),
        ],
        vec!["private issuer available".into()],
        vec!["real issued lineage valid".into()],
        vec!["preserve valid lineage".into()],
        false,
    )
    .unwrap()
}
fn route_action(upgrade: bool) -> Action {
    let mut m = vec![
        format!("mode={}", if upgrade { "coexist" } else { "fresh" }),
        "stream_context=present".into(),
        format!("target=/etc/nginx/stream.d/{}", if upgrade { "existing.conf" } else { "proxy-control.conf" }),
        format!("variable=${}", if upgrade { "existing_backend" } else { "proxy_control_backend" }),
        format!("path_kind={}", if upgrade { "file" } else { "missing" }),
        format!("resolved_path=/etc/nginx/stream.d/{}", if upgrade { "existing.conf" } else { "proxy-control.conf" }),
        "symlink_target=-".into(),
        "route=gate.example.org 127.0.0.1:4453".into(),
        "route=panel.example.org 127.0.0.1:8443".into(),
    ];
    if !upgrade {
        m.extend(["client_ip=proxy".into(), "panel_tls_backend=127.0.0.1:8443".into()]);
    }
    Action::new(
        "nginx.routes",
        "nginx",
        "proxy-control:nginx",
        m,
        vec!["private Nginx namespace".into()],
        vec!["real SNI TLS route".into()],
        vec!["restore original router".into()],
        false,
    )
    .unwrap()
}
fn tls(root: &Path, hostname: &str) -> Output {
    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            "127.0.0.1:443",
            "-servername",
            hostname,
            "-verify_hostname",
            hostname,
            "-verify_return_error",
            "-CAfile",
            root.join("ca/ca.pem").to_str().unwrap(),
            "-showcerts",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // s_client with EOF terminates after the real TLS handshake; timeout protects a
    // broken SNI route instead of waiting indefinitely for a server application response.
    let start = std::time::Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > Duration::from_secs(15) {
            child.kill().unwrap();
            panic!("SNI TLS handshake deadline expired");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
#[test]
#[ignore = "ams-test only: private mount namespace and anchor-container network namespace; see PC_TT_SMOKE_ANCHOR"]
fn native_trusttunnel_fresh_upgrade_private_ca_san_and_sni() {
    namespace("net");
    namespace("mnt");
    let anchor = std::env::var("PC_TT_SMOKE_ANCHOR").expect("PC_TT_SMOKE_ANCHOR");
    let pid = checked(&["docker", "inspect", "--format", "{{.State.Pid}}", &anchor]);
    assert_eq!(
        fs::read_link("/proc/self/ns/net").unwrap(),
        fs::read_link(format!("/proc/{}/ns/net", String::from_utf8(pid.stdout).unwrap().trim())).unwrap()
    );
    checked(&["ip", "link", "set", "lo", "up"]);
    for upgrade in [false, true] {
        let temp = Temp::new();
        let root = &temp.0;
        let project = format!("pc-tt-proof-{}-{}", std::process::id(), if upgrade { "upgrade" } else { "fresh" });
        let container = format!("{project}-manager");
        let cleanup = Cleanup { container: container.clone() };
        for (source, target) in
            [("etc/nginx", "/etc/nginx"), ("etc/letsencrypt", "/etc/letsencrypt"), ("var/www", "/var/www")]
        {
            mount_directory(&root.join(source), target);
        }
        fs::create_dir_all(root.join("etc/nginx/conf.d")).unwrap();
        fs::create_dir_all(root.join("etc/nginx/stream.d")).unwrap();
        fs::create_dir_all(root.join("ca/trust")).unwrap();
        checked(&[
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=Proxy Control native TT lab private CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
            root.join("ca/ca.key").to_str().unwrap(),
            "-out",
            root.join("ca/ca.pem").to_str().unwrap(),
        ]);
        fs::copy(root.join("ca/ca.pem"), root.join("ca/trust/ca.pem")).unwrap();
        checked(&["openssl", "rehash", root.join("ca/trust").to_str().unwrap()]);
        fs::write(root.join("etc/nginx/nginx.conf"), format!("load_module /usr/lib/nginx/modules/ngx_stream_module.so;\npid {}/nginx.pid;\nerror_log {}/nginx-error.log;\nevents {{}}\nhttp {{ access_log off; include /etc/nginx/conf.d/*.conf; }}\nstream {{ include /etc/nginx/stream.d/*.conf; }}\n", root.display(), root.display())).unwrap();
        let original = "map $ssl_preread_server_name $existing_backend {\n default 127.0.0.1:8443;\n neighbor.example.org 127.0.0.1:9443;\n}\nserver { listen 443; ssl_preread on; proxy_pass $existing_backend; }\n";
        if upgrade {
            fs::write(root.join("etc/nginx/stream.d/existing.conf"), original).unwrap();
        }
        checked(&["nginx"]);
        let runner = Arc::new(PrivateIssuer {
            root: root.clone(),
            project: project.clone(),
            container: container.clone(),
            issued: AtomicUsize::new(0),
            renewed: AtomicUsize::new(0),
        });
        // An upgrade starts with a previously issued, trusted exact-SAN lineage. The
        // fresh run exercises native CertificatePlan issuance through the local issuer.
        if upgrade {
            fs::create_dir_all(root.join("var/www/gate.example.org/.well-known/acme-challenge")).unwrap();
            let cert =
                CertificatePlan::new(&AdapterContext { root: root.clone(), tree: repo(), runner: runner.clone() });
            let a = certificate_action();
            let cp = cert.prepare(&a).unwrap();
            let cp = cert.apply(&a, cp).unwrap();
            assert!(cert.verify(&a).unwrap().success);
            cert.rollback(&a, cp, false, installer::journal::RollbackTarget::Uninstalled).unwrap();
        }
        let issued_before = runner.issued.load(Ordering::SeqCst);
        let cert_before = fs::read(root.join("etc/letsencrypt/live/gate.example.org/cert.pem")).ok();
        let path = root.join("opt/mtproxy-shared443");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join(".env"), "").unwrap();
        fs::write(path.join("compose.yaml"), format!("name: {project}\nservices: {{}}\n")).unwrap();
        fs::write(path.join("compose.trusttunnel.yaml"), format!("services:\n  trusttunnel-manager:\n    image: proxy_panel_by_dubr1k-trusttunnel-manager:latest\n    container_name: {container}\n    network_mode: container:{anchor}\n    cap_drop: [ALL]\n    tmpfs: [/tmp, /run/trusttunnel-manager]\n    volumes:\n      - {}/var/lib/trusttunnel-manager:/var/lib/trusttunnel-manager\n      - {}/secrets/trusttunnel-manager-token:/run/secrets/trusttunnel-manager-token:ro\n      - {}/etc/letsencrypt:/etc/letsencrypt:ro\n    environment:\n      TT_MANAGER_TOKEN_FILE: /run/secrets/trusttunnel-manager-token\n      TT_MANAGER_SOCKET: /run/trusttunnel-manager/manager.sock\n      TT_STATE_DIR: /var/lib/trusttunnel-manager\n      TT_HOSTNAME: gate.example.org\n      TT_LISTEN: 127.0.0.1:4453\n      TT_METRICS: 127.0.0.1:1987\n      TT_CERT: /etc/letsencrypt/live/gate.example.org/fullchain.pem\n      TT_KEY: /etc/letsencrypt/live/gate.example.org/privkey.pem\n      TT_BINARY: /usr/local/bin/trusttunnel_endpoint\n    healthcheck:\n      test: [CMD, /usr/local/bin/trusttunnel-manager, healthcheck]\n      interval: 1s\n      timeout: 3s\n      retries: 20\n      start_period: 2s\n", root.display(), path.display(), root.display())).unwrap();
        let context = AdapterContext { root: root.clone(), tree: repo(), runner: runner.clone() };
        let tt = Arc::new(TrustTunnelAdapter::new(&context));
        let config = installer_core::config::load_config(
            &repo().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"),
        )
        .unwrap();
        let mut action = tt.plan(&config, &AuditFacts::default()).unwrap().remove(0);
        for value in &mut action.mutations {
            if value.starts_with("hostname=") {
                *value = "hostname=gate.example.org".into();
            }
            if value.starts_with("listen=") {
                *value = "listen=127.0.0.1:4453".into();
            }
        }
        let cert_action = certificate_action();
        let cert = Arc::new(CertificatePlan::new(&context));
        assert_eq!(cert.prepare(&cert_action).unwrap()["lineage_preexisting"], json!(upgrade));
        let p = plan(vec![route_action(upgrade), cert_action, action]);
        let engine = TransactionEngine::new(TransactionStore::new(root).unwrap())
            .with_adapter(Arc::new(NginxAdapter::new(&context)))
            .with_adapter(cert)
            .with_adapter(tt);
        engine.apply(&p, &p.digest()).unwrap();
        assert_eq!(runner.issued.load(Ordering::SeqCst) - issued_before, usize::from(!upgrade));
        if let Some(before) = cert_before {
            assert_eq!(
                fs::read(root.join("etc/letsencrypt/live/gate.example.org/cert.pem")).unwrap(),
                before,
                "upgrade must retain the existing certificate"
            );
        }
        let pem = root.join("etc/letsencrypt/live/gate.example.org/cert.pem");
        let san = checked(&["openssl", "x509", "-in", pem.to_str().unwrap(), "-noout", "-ext", "subjectAltName"]);
        assert_eq!(
            String::from_utf8(san.stdout).unwrap().lines().skip(1).map(str::trim).collect::<Vec<_>>(),
            ["DNS:gate.example.org"]
        );
        let expected = checked(&["openssl", "x509", "-in", pem.to_str().unwrap(), "-noout", "-fingerprint", "-sha256"]);
        for phase in ["installed", "repaired"] {
            if phase == "repaired" {
                engine.repair().unwrap();
            }
            let connection = tls(root, "gate.example.org");
            assert!(connection.status.success(), "real routed TLS handshake must validate the private CA and hostname");
            let mut child = Command::new("openssl")
                .args(["x509", "-noout", "-fingerprint", "-sha256"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            use std::io::Write;
            child.stdin.take().unwrap().write_all(&connection.stdout).unwrap();
            let served = child.wait_with_output().unwrap();
            assert!(served.status.success());
            assert_eq!(served.stdout, expected.stdout, "443 must serve the actual native-issued TT leaf");
        }
        assert!(!tls(root, "unrouted.example.org").status.success(), "unselected SNI must not reach TT");
        assert!(runner.renewed.load(Ordering::SeqCst) > 0);
        engine.uninstall(true).unwrap();
        assert!(pem.is_file(), "uninstall preserves the valid issued lineage");
        if upgrade {
            assert_eq!(fs::read_to_string(root.join("etc/nginx/stream.d/existing.conf")).unwrap(), original);
        }
        assert!(!root.join("var/lib/trusttunnel-manager").exists());
        println!("NATIVE_TT_CERT_SNI {}: real OpenSSL private CA (not public ACME), HTTP-01, exact PEM SAN, native durable engine install/repair/uninstall, real endpoint TLS through {} SNI router, leaf fingerprint matched", if upgrade { "upgrade" } else { "fresh" }, if upgrade { "coexist" } else { "fresh PROXY/raw relay" });
        drop(cleanup);
        for target in ["/var/www", "/etc/letsencrypt", "/etc/nginx"] {
            checked(&["umount", target]);
        }
    }
}

#[test]
#[ignore = "ams-test only: disposable Ubuntu systemd container, explicit PC_WARP_SMOKE_DISPOSABLE=1"]
fn native_warp_shipped_pin_download_install_and_egress() {
    assert_eq!(std::env::var("PC_WARP_SMOKE_DISPOSABLE").as_deref(), Ok("1"));
    assert!(Path::new("/.dockerenv").is_file(), "disposable container required");
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap().to_string_lossy(),
        std::env::var("PC_WARP_SMOKE_HOST_NETNS")
            .expect("PC_WARP_SMOKE_HOST_NETNS must name the outer host network namespace"),
        "WARP proof must not share host networking"
    );
    let context = AdapterContext { root: PathBuf::from("/"), tree: repo(), runner: Arc::new(SystemRunner) };
    let adapter = Arc::new(WarpAdapter::new(&context));
    let mut config = installer_core::config::load_config(&repo().join("examples/installer/core.toml")).unwrap();
    config.egress = Some(installer_core::model::EgressConfig { warp: true, warp_port: 40173, ..Default::default() });
    let p = plan(adapter.plan(&config, &AuditFacts::default()).unwrap());
    let engine = TransactionEngine::new(TransactionStore::new(Path::new("/")).unwrap()).with_adapter(adapter);
    engine.apply(&p, &p.digest()).unwrap();
    assert_eq!(
        String::from_utf8(checked(&["dpkg-query", "-W", "-f=${Version}", "cloudflare-warp"]).stdout).unwrap(),
        installer::adapters::warp::VERSION
    );
    engine.repair().unwrap();
    engine.uninstall(true).unwrap();
    println!("NATIVE_WARP_PIN: adapter acquired official shipped {}, validated pinned key/package digests, real apt install, real systemd service/registration, distinct tunneled egress, repair and purge", installer::adapters::warp::VERSION);
}
