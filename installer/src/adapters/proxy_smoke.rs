//! Opt-in ams-test smoke. Real Caddy/mita/client processes and production mutation methods;
//! only Docker/Compose/systemd supervision is translated into private processes. The panel
//! session acceptance is separately tested by protocol conformance tests, not faked here.
use super::proxy_common::*;
use super::{mieru::MieruAdapter, naive::NaiveAdapter, AdapterContext};
use crate::journal::{CheckpointData, RollbackTarget};
use crate::planner::{Action, AuditFacts, Evidence};
use crate::testkit::{engine_for, plan_with};
use crate::{Adapter, Error, Status};
use pc_host::fs::atomic_write;
use pc_host::runner::{CallKind, RecordingRunner, Reply};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Processes {
    caddy: Option<Child>,
    mita: Option<Child>,
}
fn stop(process: &mut Option<Child>) {
    if let Some(mut child) = process.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}
impl Drop for Processes {
    fn drop(&mut self) {
        stop(&mut self.caddy);
        stop(&mut self.mita);
    }
}
fn execute(argv: &[String]) -> Reply {
    let output = Command::new(&argv[0]).args(&argv[1..]).output().unwrap();
    Reply::exit(
        output.status.code().unwrap_or(-1),
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    )
}
fn identity() -> (u32, u32) {
    let output = Command::new("getent").args(["passwd", "mita"]).output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    let fields: Vec<_> = text.trim().split(':').collect();
    (fields[2].parse().unwrap(), fields[3].parse().unwrap())
}
fn start_mita(processes: &mut Processes) {
    stop(&mut processes.mita);
    let (uid, gid) = identity();
    let child = Command::new("/usr/bin/mita")
        .arg("run")
        .env("MITA_CONFIG_JSON_FILE", "/var/lib/mita/server_config.json")
        .env("MITA_UDS_PATH", "/run/mita/mita.sock")
        .uid(uid)
        .gid(gid)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    processes.mita = Some(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output =
            Command::new("/usr/bin/mita").arg("status").env("MITA_UDS_PATH", "/run/mita/mita.sock").output().unwrap();
        if output.status.success() {
            break;
        }
        assert!(Instant::now() < deadline, "private mita did not answer");
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn start_caddy(processes: &mut Processes) {
    stop(&mut processes.caddy);
    let source = fs::read_to_string("/var/lib/naive-manager/Caddyfile").unwrap();
    // Only the smoke's private origin is allowed; the shipped template remains unchanged.
    let source = source.replace(
        "            probe_resistance\n",
        "            probe_resistance\n            acl {\n                allow 127.0.0.1\n            }\n",
    );
    let source=format!("{source}\nhttps://origin.example.com:18443 {{\n    bind 127.0.0.1\n    tls /var/lib/naive-caddy/tls/fullchain.pem /var/lib/naive-caddy/tls/privkey.pem\n    respond \"isolated-native-inner-tls-payload\" 200\n}}\n");
    atomic_write(Path::new("/run/proxy-smoke/runtime.caddy"), source.as_bytes(), 0o600, None).unwrap();
    let output = Command::new("/usr/local/bin/caddy")
        .args(["adapt", "--adapter", "caddyfile", "--config", "/run/proxy-smoke/runtime.caddy"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Caddy rejected private smoke render: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut config: Value = serde_json::from_slice(&output.stdout).unwrap();
    fn private_port(value: &mut Value) {
        match value {
            Value::String(text) if text == ":443" || text == "127.0.0.1:443" => *text = "127.0.0.1:4443".into(),
            Value::Array(values) => values.iter_mut().for_each(private_port),
            Value::Object(map) => map.values_mut().for_each(private_port),
            _ => (),
        }
    }
    private_port(&mut config);
    atomic_write(
        Path::new("/run/proxy-smoke/runtime.json"),
        &serde_json::to_vec(&config).unwrap(),
        0o640,
        Some((10003, 10004)),
    )
    .unwrap();
    fs::create_dir_all("/var/lib/naive-caddy/runtime").unwrap();
    let dir = std::ffi::CString::new("/var/lib/naive-caddy/runtime").unwrap();
    assert_eq!(unsafe { libc::chown(dir.as_ptr(), 10003, 10004) }, 0);
    let child = Command::new("/usr/local/bin/caddy")
        .args(["run", "--config", "/run/proxy-smoke/runtime.json"])
        .env("XDG_DATA_HOME", "/var/lib/naive-caddy/runtime")
        .env("XDG_CONFIG_HOME", "/var/lib/naive-caddy/runtime")
        .uid(10003)
        .gid(10004)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    processes.caddy = Some(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect("127.0.0.1:4443").is_err() {
        assert!(Instant::now() < deadline, "private Caddy did not listen");
        std::thread::sleep(Duration::from_millis(100));
    }
}
struct RuntimeAdapter {
    inner: Arc<dyn Adapter + Send + Sync>,
    name: &'static str,
    bootstrap: Arc<Mutex<Value>>,
    client: PathBuf,
}
impl RuntimeAdapter {
    fn probe_naive(&self) -> Result<Value, Error> {
        let source = fs::read_to_string("/var/lib/naive-manager/Caddyfile")?;
        let auth = source.lines().find(|line| line.trim_start().starts_with("basic_auth ")).expect("bootstrap auth");
        let fields: Vec<_> = auth.split_whitespace().collect();
        let body=format!("proxy = \"https://edge.example.com:4443\"\nproxy-user = \"{}:{}\"\nproxy-http2\nproxytunnel\nnoproxy = \"\"\nproxy-cacert = \"/var/lib/naive-caddy/tls/fullchain.pem\"\ncacert = \"/var/lib/naive-caddy/tls/fullchain.pem\"\nurl = \"https://origin.example.com:18443/\"\noutput = \"/run/proxy-smoke/payload\"\nwrite-out = \"%{{http_code}} %{{size_download}}\"\nmax-time = 10\n",fields[1],fields[2]);
        atomic_write(Path::new("/run/proxy-smoke/curl.conf"), body.as_bytes(), 0o600, None)?;
        let output = Command::new("curl")
            .args(["--silent", "--show-error", "--config", "/run/proxy-smoke/curl.conf"])
            .output()?;
        if !output.status.success() {
            return Err(Error::other("AcceptanceError", "private Caddy HTTP/2 CONNECT failed"));
        }
        let output = String::from_utf8_lossy(&output.stdout);
        let fields: Vec<_> = output.split_whitespace().collect();
        if fields.len() != 2 || fields[0] != "200" || fields[1].parse::<u64>().unwrap_or(0) == 0 {
            return Err(Error::other("AcceptanceError", "private Caddy inner TLS response failed"));
        }
        if fs::read("/run/proxy-smoke/payload")? != b"isolated-native-inner-tls-payload" {
            return Err(Error::other("AcceptanceError", "private Caddy tunnel payload differs"));
        }
        Ok(json!({"native_http2_connect":true,"inner_tls_payload_bytes":fields[1].parse::<u64>().unwrap()}))
    }
    fn probe_mieru(&self) -> Result<Value, Error> {
        let bootstrap = self.bootstrap.lock().unwrap().clone();
        let user = bootstrap["users"][0].clone();
        let bindings = bootstrap["portBindings"].as_array().unwrap();
        let mut verified = 0;
        for binding in bindings {
            let listener = std::net::TcpListener::bind("127.0.0.1:18081")?;
            let origin = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = [0; 4096];
                let _ = stream.read(&mut bytes);
                stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").unwrap();
            });
            let native = json!({"profiles":[{"profileName":"smoke","user":user,"servers":[{"ipAddress":"127.0.0.1","portBindings":[binding]}],"mtu":1400}],"activeProfile":"smoke","rpcPort":18082,"socks5Port":18080,"socks5ListenLAN":false,"loggingLevel":"ERROR"});
            atomic_write(
                Path::new("/run/proxy-smoke/client.json"),
                &serde_json::to_vec(&native).unwrap(),
                0o600,
                None,
            )?;
            let mut client = Command::new(&self.client)
                .arg("run")
                .env("MIERU_CONFIG_JSON_FILE", "/run/proxy-smoke/client.json")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(10);
            while std::net::TcpStream::connect("127.0.0.1:18080").is_err() {
                if Instant::now() >= deadline {
                    let _ = client.kill();
                    let _ = client.wait();
                    return Err(Error::other("AcceptanceError", "private official client did not listen"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let output = Command::new("curl")
                .args([
                    "--silent",
                    "--show-error",
                    "--noproxy",
                    "",
                    "--socks5-hostname",
                    "127.0.0.1:18080",
                    "--max-time",
                    "10",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                    "http://127.0.0.1:18081/",
                ])
                .output()?;
            let _ = client.kill();
            let _ = client.wait();
            if !output.status.success() || output.stdout != b"204" {
                return Err(Error::other("AcceptanceError", "private official client tunnel failed"));
            }
            origin.join().expect("local origin");
            verified += 1;
        }
        Ok(json!({"native_official_client_transports":verified,"mita_running":true}))
    }
}
impl Adapter for RuntimeAdapter {
    fn name(&self) -> &str {
        self.name
    }
    fn plan(&self, config: &crate::model::InstallerConfig, facts: &AuditFacts) -> Result<Vec<Action>, Error> {
        self.inner.plan(config, facts)
    }
    fn prepare(&self, a: &Action) -> Result<CheckpointData, Error> {
        self.inner.prepare(a)
    }
    fn apply(&self, a: &Action, d: CheckpointData) -> Result<CheckpointData, Error> {
        self.inner.apply(a, d)
    }
    fn reconcile_apply(&self, a: &Action, d: CheckpointData) -> Result<CheckpointData, Error> {
        self.inner.reconcile_apply(a, d)
    }
    fn verify(&self, a: &Action) -> Result<Evidence, Error> {
        let value = if self.name == "naive" { self.probe_naive()? } else { self.probe_mieru()? };
        Ok(evidence(a, &["real private protocol tunnel and payload verified"], value))
    }
    fn repair(&self, a: &Action, d: CheckpointData) -> Result<CheckpointData, Error> {
        self.inner.repair(a, d)
    }
    fn rollback(&self, a: &Action, d: CheckpointData, p: bool, t: RollbackTarget) -> Result<Evidence, Error> {
        self.inner.rollback(a, d, p, t)
    }
    fn reconcile_rollback(&self, a: &Action, d: CheckpointData, p: bool, t: RollbackTarget) -> Result<Evidence, Error> {
        self.inner.reconcile_rollback(a, d, p, t)
    }
}
#[test]
#[ignore = "ams-test only: private mount+network namespace and tmpfs host paths; staged pinned native binaries required"]
fn real_proxy_engine_install_repair_and_rollback() {
    for namespace in ["net", "mnt"] {
        assert_ne!(
            fs::read_link(format!("/proc/self/ns/{namespace}")).unwrap(),
            fs::read_link(format!("/proc/1/ns/{namespace}")).unwrap(),
            "private namespace required"
        );
    }
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    for path in [
        "/etc",
        "/var/lib",
        "/var/log",
        "/var/www",
        "/opt",
        "/run",
        "/usr/bin",
        "/usr/local/bin",
        "/usr/local/libexec",
        "/usr/share/doc",
    ] {
        assert!(
            mounts.lines().any(|line| line.contains(&format!(" {path} ")) && line.contains(" - tmpfs ")),
            "tmpfs boundary missing: {path}"
        );
    }
    fs::create_dir_all("/run/proxy-smoke").unwrap();
    let tree = PathBuf::from(std::env::var_os("PC_PROXY_SMOKE_TREE").expect("release source tree"));
    let native = PathBuf::from(std::env::var_os("PC_PROXY_SMOKE_NATIVE").expect("staged native artifacts"));
    let installer = PathBuf::from(std::env::var_os("PC_PROXY_SMOKE_INSTALLER").expect("built installer binary"));
    fs::write(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
    )
    .unwrap();
    fs::write("/etc/group", "root:x:0:\nnogroup:x:65534:\n").unwrap();
    fs::write("/etc/shadow", "root:*:0:0:99999:7:::\nnobody:*:0:0:99999:7:::\n").unwrap();
    fs::write("/etc/gshadow", "root:*::\nnogroup:*::\n").unwrap();
    fs::write(
        "/etc/hosts",
        "127.0.0.1 localhost edge.example.com origin.example.com panel.example.com mieru.example.com\n",
    )
    .unwrap();
    fs::create_dir_all("/opt/mtproxy-shared443/installer/bin/linux-amd64").unwrap();
    fs::copy(installer, "/opt/mtproxy-shared443/installer/bin/linux-amd64/proxy-control-installer").unwrap();
    fs::create_dir_all("/etc/letsencrypt/live/edge.example.com").unwrap();
    let output = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "/etc/letsencrypt/live/edge.example.com/privkey.pem",
            "-out",
            "/etc/letsencrypt/live/edge.example.com/fullchain.pem",
            "-days",
            "1",
            "-subj",
            "/CN=edge.example.com",
            "-addext",
            "subjectAltName=DNS:edge.example.com,DNS:origin.example.com",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    for name in ["mita_3.38.1_amd64.deb", "mieru_3.38.1_amd64.deb"] {
        fs::create_dir_all("/var/lib/proxy-control").unwrap();
        fs::copy(native.join(name), Path::new("/var/lib/proxy-control").join(name)).unwrap();
    }
    let bootstrap = Arc::new(Mutex::new(Value::Null));
    let shared_bootstrap = bootstrap.clone();
    let processes = Arc::new(Mutex::new(Processes::default()));
    let supervised = processes.clone();
    let caddy = native.join("caddy");
    let runner = Arc::new(RecordingRunner::with_responder(move |call| {
        let a = &call.argv;
        if a.first().is_some_and(|s| s == "docker") {
            if a.get(1).is_some_and(|s| s == "create") {
                return Some(Reply::ok(&"a".repeat(64)));
            }
            if a.get(1).is_some_and(|s| s == "cp") {
                fs::copy(&caddy, &a[3]).unwrap();
            }
            return Some(Reply::ok(""));
        }
        if a.first().is_some_and(|s| s == "systemctl") {
            let mut owned = supervised.lock().unwrap();
            let unit = a.last().unwrap();
            if unit == "caddy-naive" {
                if a.iter().any(|s| s == "disable") {
                    stop(&mut owned.caddy);
                } else if a.iter().any(|s| s == "enable" || s == "restart" || s == "reload") {
                    start_caddy(&mut owned);
                }
            } else if unit == "mita" {
                if a.iter().any(|s| s == "disable") {
                    stop(&mut owned.mita);
                } else if a.iter().any(|s| s == "enable" || s == "restart") {
                    start_mita(&mut owned);
                }
            } else if unit == "mita-bootstrap.service" && a.get(1).is_some_and(|s| s == "stop") {
                stop(&mut owned.mita);
            }
            return Some(Reply::ok(""));
        }
        if a.first().is_some_and(|s| s == "systemd-run") {
            start_mita(&mut supervised.lock().unwrap());
            return Some(Reply::ok(""));
        }
        if a.starts_with(&strings(&["sudo", "-u", "mita", "env"])) {
            let args = &a[6..];
            if args.first().is_some_and(|s| s == "apply") {
                *shared_bootstrap.lock().unwrap() =
                    serde_json::from_slice(&fs::read(args.last().unwrap()).unwrap()).unwrap();
            }
            let (uid, gid) = identity();
            let output = Command::new("/usr/bin/mita")
                .args(args)
                .env("MITA_UDS_PATH", "/run/mita/mita.sock")
                .uid(uid)
                .gid(gid)
                .output()
                .unwrap();
            return Some(Reply::exit(
                output.status.code().unwrap_or(-1),
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr),
            ));
        }
        if call.kind == CallKind::Run || call.kind == CallKind::Capture || call.kind == CallKind::CaptureChecked {
            return Some(execute(a));
        }
        panic!("unexpected smoke command {a:?}");
    }));
    let context = AdapterContext { root: PathBuf::from("/"), tree: tree.clone(), runner };
    let mut config = installer_core::config::load_config(&tree.join("examples/installer/full-three-xui.toml")).unwrap();
    config.domains.naive = Some("edge.example.com".into());
    config.domains.panel = "panel.example.com".into();
    config.domains.mieru = Some("mieru.example.com".into());
    config.initial_user = "owner".into();
    config.three_xui.mode = crate::model::ThreeXuiMode::None;
    config.mieru.as_mut().unwrap().tcp_ports = vec![46001];
    config.mieru.as_mut().unwrap().udp_ports = vec![46001];
    for name in ["naive", "mieru"] {
        let inner: Arc<dyn Adapter + Send + Sync> =
            if name == "naive" { Arc::new(NaiveAdapter::new(&context)) } else { Arc::new(MieruAdapter::new(&context)) };
        let action = inner.plan(&config, &AuditFacts::default()).unwrap().remove(0);
        let adapter: Arc<dyn Adapter> = Arc::new(RuntimeAdapter {
            inner,
            name,
            bootstrap: bootstrap.clone(),
            client: native.join("client/usr/bin/mieru"),
        });
        let plan = plan_with(vec![action], serde_json::Map::new());
        let engine = engine_for(Path::new("/"), vec![adapter]);
        assert_eq!(engine.apply(&plan, &plan.digest()).unwrap().status, Status::Active);
        assert_eq!(engine.repair().unwrap().status, Status::Active);
        assert_eq!(engine.uninstall(true).unwrap().status, Status::Uninstalled);
    }
    assert!(processes.lock().unwrap().caddy.is_none());
    assert!(processes.lock().unwrap().mita.is_none());
}
