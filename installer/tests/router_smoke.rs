//! Real archive extraction, durable engine apply/uninstall and real loopback API/TLS fixture.
//! Run the managed fixture in a private network namespace, never against installed services.
use installer::adapter::Adapter;
use installer::adapters::{three_xui::ThreeXuiAdapter, xray_router::XrayRouterAdapter, AdapterContext};
use installer::engine::TransactionEngine;
use installer::store::TransactionStore;
use installer_core::planner::{Action, AuditFacts, InstallPlan, ReleaseIdentity, PLAN_SCHEMA};
use pc_host::runner::{RecordingRunner, Reply};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("pc-router-smoke-{}", pc_host::fs::token_hex::<8>()));
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
fn plan(actions: Vec<Action>) -> InstallPlan {
    let names = actions
        .iter()
        .map(|action| action.adapter.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    InstallPlan::new(
        json!({"smoke":true}),
        AuditFacts::default(),
        ReleaseIdentity::new("v4.0.0", &"a".repeat(40), &"b".repeat(64), BTreeMap::new(), BTreeMap::new()).unwrap(),
        names.clone(),
        names.into_iter().map(|name| (name, vec![])).collect(),
        actions,
        PLAN_SCHEMA,
    )
    .unwrap()
}
fn pin_tree(temp: &Temp) -> PathBuf {
    let tree = temp.0.join("release-tree");
    fs::create_dir_all(tree.join("release")).unwrap();
    fs::copy(repo().join("release/external-artifacts.json"), tree.join("release/external-artifacts.json")).unwrap();
    fs::create_dir_all(tree.join("scripts")).unwrap();
    for name in ["prepare-xray-router-state.sh", "rotate-xray-router-ingress.sh"] {
        fs::copy(repo().join("scripts").join(name), tree.join("scripts").join(name)).unwrap();
    }
    tree
}
fn update_pin(tree: &Path, name: &str, digest: &str, members: Option<Value>) {
    let path = tree.join("release/external-artifacts.json");
    let mut document: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let pin = document["artifacts"].as_array_mut().unwrap().iter_mut().find(|value| value["name"] == name).unwrap();
    pin["platforms"]["amd64"]["sha256"] = json!(digest);
    if let Some(members) = members {
        pin["platforms"]["amd64"]["members"] = members;
    }
    fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
}
fn zip_fixture(root: &Path, tree: &Path, tamper: bool) {
    let archive = root.join("var/lib/proxy-control/Xray-linux-64.zip");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    let mut zip = zip::ZipWriter::new(fs::File::create(&archive).unwrap());
    let mut members = serde_json::Map::new();
    for name in ["xray", "geoip.dat", "geosite.dat"] {
        let bytes = format!("reviewed-{name}");
        let mode = if name == "xray" { 0o755 } else { 0o644 };
        zip.start_file(name, zip::write::SimpleFileOptions::default().unix_permissions(mode)).unwrap();
        zip.write_all(bytes.as_bytes()).unwrap();
        members.insert(name.into(),json!({"sha256":if tamper&&name=="geoip.dat"{"0".repeat(64)}else{pc_host::fs::sha256_hex(bytes.as_bytes())},"size":bytes.len(),"mode":if name=="xray"{"0755"}else{"0644"}}));
    }
    zip.finish().unwrap();
    update_pin(tree, "xray", &pc_host::fs::sha256_file(&archive).unwrap(), Some(Value::Object(members)));
}
fn router_context(temp: &Temp, tamper: bool) -> AdapterContext {
    let root = temp.0.join("root");
    fs::create_dir_all(&root).unwrap();
    let tree = pin_tree(temp);
    zip_fixture(&root, &tree, tamper);
    let runner = Arc::new(RecordingRunner::new());
    runner.reply(&["docker","exec","proxy-control-xray-router","/usr/local/bin/xray-router-manager","healthcheck","--status"],Reply::ok("{\"artifacts\":{\"xray\":{\"verified\":true},\"geoip\":{\"verified\":true},\"geosite\":{\"verified\":true}},\"running\":{\"generation\":1},\"phase\":\"idle\"}"));
    for port in [45101, 45102, 45104] {
        runner.reply(
            &["ss", "-H", "-lnt", &format!("sport = :{port}")],
            Reply::ok(&format!("LISTEN 0 4096 127.0.0.1:{port} 0.0.0.0:*\n")),
        );
    }
    runner.reply(&["curl"], Reply::ok("ip=203.0.113.10\n"));
    runner.reply(&["docker", "exec", "proxy-control-xray-router-ingress"], Reply::ok("bridge-ok\n"));
    AdapterContext { root, tree, runner }
}
#[test]
fn real_zip_engine_apply_and_purge_rollback() {
    let temp = Temp::new();
    let context = router_context(&temp, false);
    let mut config =
        installer_core::config::load_config(&repo().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"))
            .unwrap();
    config.egress.as_mut().unwrap().relay_port = 0;
    let adapter = Arc::new(XrayRouterAdapter::new(&context));
    let actions = adapter.plan(&config, &AuditFacts::default()).unwrap();
    let plan = plan(actions);
    let engine = TransactionEngine::new(TransactionStore::new(&context.root).unwrap()).with_adapter(adapter);
    engine.apply(&plan, &plan.digest()).unwrap();
    for member in ["xray", "geoip.dat", "geosite.dat"] {
        assert!(context.root.join(format!("usr/local/lib/proxy-control/xray-router/{member}")).is_file());
    }
    let token = context.root.join("opt/mtproxy-shared443/secrets/xray-router-manager-token");
    assert!(token.is_file());
    engine.uninstall(true).unwrap();
    assert!(!token.exists());
    assert!(!context.root.join("usr/local/lib/proxy-control/xray-router/xray").exists());
    assert!(fs::read_to_string(context.root.join("etc/proxy-control/version-agent.env"))
        .unwrap()
        .contains("PROXY_CONTROL_XRAY_ROUTER=off"));
}
#[test]
fn bad_pinned_zip_member_prevents_commands_and_install() {
    let temp = Temp::new();
    let context = router_context(&temp, true);
    let mut config =
        installer_core::config::load_config(&repo().join("tests/fixtures/host-golden/plans/kitchen-sink/config.toml"))
            .unwrap();
    config.egress.as_mut().unwrap().relay_port = 0;
    let adapter = XrayRouterAdapter::new(&context);
    let action = adapter.plan(&config, &AuditFacts::default()).unwrap().remove(0);
    let checkpoint = adapter.prepare(&action).unwrap();
    assert!(adapter.apply(&action, checkpoint).is_err());
    assert!(!context.root.join("opt/mtproxy-shared443/.env.xray-router").exists());
    assert!(!context.root.join("usr/local/lib/proxy-control/xray-router/xray").exists());
}
fn tar_fixture(root: &Path, tree: &Path) {
    let mut entries = Vec::new();
    let mut raw = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut raw);
        for (name, bytes, mode) in [
            ("x-ui/x-ui", b"fixture-x-ui".as_slice(), 0o755),
            ("x-ui/x-ui.service.debian", b"[Service]\nExecStart=/usr/local/x-ui/x-ui run\n", 0o644),
            ("x-ui/bin/xray-linux-amd64", b"fixture-xray", 0o755),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(mode);
            header.set_cksum();
            tar.append_data(&mut header, name, bytes).unwrap();
            entries.push(json!({"path":name,"kind":"file","mode":mode,"sha256":pc_host::fs::sha256_hex(bytes)}));
        }
        tar.finish().unwrap();
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&raw).unwrap();
    let archive = encoder.finish().unwrap();
    let digest = pc_host::fs::sha256_hex(&archive);
    let path = root.join(format!("var/cache/proxy-control/three-xui-{digest}.tar.gz"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, archive).unwrap();
    fs::write(
        tree.join("release/three-xui-layout-amd64.json"),
        serde_json::to_vec(&json!({"entries":entries})).unwrap(),
    )
    .unwrap();
    update_pin(tree, "three_xui", &digest, None);
}
fn tls_config(root: &Path) -> Arc<rustls::ServerConfig> {
    let directory = root.join("etc/letsencrypt/live/xui.example.com");
    fs::create_dir_all(&directory).unwrap();
    let cert = directory.join("fullchain.pem");
    let key = directory.join("privkey.pem");
    assert!(std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=xui.example.com",
            "-days",
            "1",
            "-keyout"
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .unwrap()
        .status
        .success());
    let der = directory.join("key.der");
    assert!(std::process::Command::new("openssl")
        .args(["pkcs8", "-topk8", "-nocrypt", "-in"])
        .arg(key)
        .args(["-outform", "DER", "-out"])
        .arg(&der)
        .output()
        .unwrap()
        .status
        .success());
    use base64::Engine;
    let pem = fs::read_to_string(cert).unwrap();
    let leaf = pem
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)
        .unwrap()
        .split("-----END CERTIFICATE-----")
        .next()
        .unwrap()
        .split_whitespace()
        .collect::<String>();
    let cert = base64::engine::general_purpose::STANDARD.decode(leaf).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.into()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(fs::read(der).unwrap()).into(),
            )
            .unwrap(),
    )
}
#[derive(Default)]
struct FixtureState {
    rows: Vec<Value>,
    settings: Value,
    rotated: bool,
    calls: Vec<String>,
}
fn serve(stream: &mut dyn Io, state: &Arc<Mutex<FixtureState>>) {
    let mut head = Vec::new();
    let mut one = [0];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut one).is_err() {
            return;
        }
        head.push(one[0]);
        assert!(head.len() < 65536);
    }
    let head = String::from_utf8(head).unwrap();
    let path = head.lines().next().unwrap().split_whitespace().nth(1).unwrap();
    let length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    let mut state = state.lock().unwrap();
    state.calls.push(path.into());
    let mut cookies = "";
    let response = if path.ends_with("/login") {
        assert!(head.to_ascii_lowercase().contains("x-csrf-token: abcdefghijklmnop"));
        if state.rotated && String::from_utf8_lossy(&body).contains("password=admin") {
            json!({"success":false})
        } else {
            cookies = "Set-Cookie: session=fixture; HttpOnly\r\n";
            json!({"success":true})
        }
    } else if path.ends_with("/updateUser") {
        state.rotated = true;
        json!({"success":true})
    } else if path.ends_with("/setting/all") {
        json!({"success":true,"obj":state.settings})
    } else if path.ends_with("/setting/update") {
        let fields = String::from_utf8(body).unwrap();
        state.settings = json!({"wholeForm":fields});
        json!({"success":true})
    } else if path.ends_with("/inbounds/add") {
        let mut inbound: Value = serde_json::from_slice(&body).unwrap();
        inbound["id"] = json!(state.rows.len() + 1);
        state.rows.push(inbound.clone());
        json!({"success":true,"obj":inbound})
    } else if path.contains("/clients/del/") {
        let email = path.rsplit('/').next().unwrap();
        for row in &mut state.rows {
            let mut settings: Value = serde_json::from_str(row["settings"].as_str().unwrap()).unwrap();
            settings["clients"].as_array_mut().unwrap().retain(|client| client["email"] != email);
            row["settings"] = json!(settings.to_string());
        }
        json!({"success":true})
    } else if path.ends_with("/inbounds/list") {
        json!({"success":true,"obj":state.rows})
    } else {
        let body = "<meta name='csrf-token' content='abcdefghijklmnop'>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSet-Cookie: pre=fixture\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
        return;
    };
    let body = response.to_string();
    let response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{cookies}Connection: close\r\n\r\n{body}", body.len());
    stream.write_all(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}
trait Io: Read + Write {}
impl<T: Read + Write> Io for T {}
#[test]
#[ignore = "requires private network namespace: unshare --net; ip link set lo up"]
fn managed_three_xui_real_tls_engine_apply_and_rollback() {
    let temp = Temp::new();
    let root = temp.0.join("root");
    fs::create_dir_all(&root).unwrap();
    let tree = pin_tree(&temp);
    tar_fixture(&root, &tree);
    let tls = tls_config(&root);
    let listener = TcpListener::bind("127.0.0.1:8451").unwrap();
    listener.set_nonblocking(true).unwrap();
    let state = Arc::new(Mutex::new(FixtureState {
        settings: json!({"webPort":2053,"keep":"unchanged","hasPassword":true}),
        ..Default::default()
    }));
    let captured = state.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let server = std::thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((socket, _)) => {
                    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                    let connection = rustls::ServerConnection::new(tls.clone()).unwrap();
                    let mut stream = rustls::StreamOwned::new(connection, socket);
                    serve(&mut stream, &captured);
                    stream.conn.send_close_notify();
                    let _ = stream.flush();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("{error}"),
            }
        }
    });
    let runner = Arc::new(RecordingRunner::new());
    runner.reply(&["systemctl", "is-active"], Reply::ok("inactive\n"));
    runner.reply(&["ss","-lntH"],Reply::ok("LISTEN 0 128 127.0.0.1:8451 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:8449 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:8450 0.0.0.0:*\n"));
    runner.reply(&["ss", "-lnuH"], Reply::ok("UNCONN 0 0 0.0.0.0:443 0.0.0.0:*\n"));
    runner.reply(
        &["/usr/local/x-ui/bin/xray-linux-amd64", "x25519"],
        Reply::ok(&format!("PrivateKey: {}\nPublicKey: {}\n", "a".repeat(43), "b".repeat(43))),
    );
    runner.reply(&["/usr/local/x-ui/x-ui", "-v"], Reply::ok("3.10.2\n"));
    let staged_runner = runner.clone();
    let original = runner;
    let runner = Arc::new(RecordingRunner::with_responder(move |call| {
        if call.argv.last().is_some_and(|arg| arg == "-v") {
            Some(Reply::ok("3.10.2\n"))
        } else {
            let argv = call.argv.iter().map(String::as_str).collect::<Vec<_>>();
            use pc_host::runner::HostRunner;
            match call.kind {
                pc_host::runner::CallKind::Capture => {
                    Some(Reply::ok(&staged_runner.capture(&argv, 65536, pc_host::runner::Capture::VERSION_AGENT)))
                }
                pc_host::runner::CallKind::CaptureChecked => {
                    Some(match staged_runner.capture_checked(&argv, Duration::from_secs(30)) {
                        Ok(text) => Reply::ok(&text),
                        Err(_) => Reply::exit(1, "", ""),
                    })
                }
                _ => Some(Reply::ok("")),
            }
        }
    }));
    let context = AdapterContext { root: root.clone(), tree, runner };
    let mut config =
        installer_core::config::load_config(&repo().join("examples/installer/managed-three-xui.toml")).unwrap();
    config.three_xui.panel_domain = Some("xui.example.com".into());
    config.three_xui.subscription_domain = None;
    config.three_xui.warp = false;
    let values = installer_core::credentials::OperatorCredentials::new(
        None,
        None,
        Some("owner"),
        Some("fixture-password-not-in-journal"),
    )
    .unwrap();
    installer_core::credentials::stage_operator_credentials(&root, Some(&values)).unwrap();
    let adapter = Arc::new(ThreeXuiAdapter::new(&context));
    let actions = adapter.plan(&config, &AuditFacts::default()).unwrap();
    let plan = plan(actions);
    let engine = TransactionEngine::new(TransactionStore::new(&root).unwrap()).with_adapter(adapter);
    let result = engine.apply(&plan, &plan.digest());
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    result.unwrap();
    assert_eq!(state.lock().unwrap().rows.len(), 3);
    assert!(state.lock().unwrap().rows.iter().all(|row| !row["settings"].as_str().unwrap().contains("acceptance-")));
    let journal = fs::read_to_string(root.join("var/lib/proxy-control/installer/state.json")).unwrap();
    assert!(!journal.contains("fixture-password-not-in-journal"));
    assert!(fs::read_to_string(root.join("var/lib/proxy-control/three-xui/panel-access"))
        .unwrap()
        .contains("fixture-password-not-in-journal"));
    engine.uninstall(true).unwrap();
    assert!(!root.join("usr/local/x-ui").exists());
    assert!(!root.join("etc/systemd/system/x-ui.service").exists());
    assert!(original.argvs().iter().any(|argv| argv == &["systemctl", "is-active", "x-ui"]));
}
#[test]
fn real_hidden_bootstrap_cli_rotates_and_rejects_default_credential() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = Arc::new(Mutex::new(FixtureState {
        settings: json!({"webPort":2053,"keep":"retained"}),
        ..Default::default()
    }));
    let capture = state.clone();
    let server = std::thread::spawn(move || {
        for _ in 0..11 {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            serve(&mut socket, &capture);
        }
    });
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_proxy-control-installer"))
        .arg("three-xui-bootstrap")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let payload = json!({"port":port,"panel_port":8451,"initial_username":"admin","initial_password":"admin","username":"owner","password":"CLI-SECRET","web_path":"/private/","certificate":"/cert.pem","private_key":"/key.pem"});
    child.stdin.take().unwrap().write_all(payload.to_string().as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("CLI-SECRET"));
    assert!(state.lock().unwrap().rotated);
    assert!(state.lock().unwrap().settings["wholeForm"].as_str().unwrap().contains("webPort=8451"));
}
