//! Destructive, explicit ams-test acceptance; every adapter command uses SystemRunner.
//! Build the current xray_router_manager/Dockerfile first, then run with
//! PC_XRAY_ROUTER_LIVE=ams-test PC_XRAY_ROUTER_IMAGE=<native-image>
//! PC_VERSION_AGENT_BIN=<native-agent> cargo test --locked --test xray_router_live --
//! --ignored --exact real_unstaged_xray_router_native_lifecycle --nocapture --test-threads=1.
//! The test re-execs in private mount/network/PID namespaces and starts its own Docker daemon.
use installer::adapter::Adapter;
use installer::adapters::{version_agent::VersionAgentAdapter, xray_router::XrayRouterAdapter, AdapterContext};
use installer::engine::TransactionEngine;
use installer::store::TransactionStore;
use installer::Status;
use installer_core::planner::{AuditFacts, InstallPlan, ReleaseIdentity, PLAN_SCHEMA};
use pc_host::archive::{ArtifactPin, ReleaseManifest};
use pc_host::runner::SystemRunner;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TEST: &str = "real_unstaged_xray_router_native_lifecycle";
const PROJECT: &str = "/opt/mtproxy-shared443";
const BIN: &str = "/usr/local/lib/proxy-control/xray-router";
const ARCHIVE: &str = "/var/lib/proxy-control/Xray-linux-64.zip";
const STATE: &str = "/var/lib/xray-router";
const ROUTER: &str = "proxy-control-xray-router";

fn checked(command: &mut Command) -> Output {
    let output = command.output().expect("execute native command");
    assert!(
        output.status.success(),
        "native {} exited {}: {}",
        command.get_program().to_string_lossy(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn docker(args: &[&str]) -> Output {
    checked(Command::new("docker").args(args))
}
fn text(output: Output) -> String {
    String::from_utf8(output.stdout).unwrap().trim().into()
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Lab {
    directory: PathBuf,
    keeper: String,
}
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "--force", &self.keeper]).output();
        if std::thread::panicking() {
            eprintln!("NATIVE_XRAY_FAILURE_ARTIFACTS={}", self.directory.display());
        } else {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}
fn wait_until(mut condition: impl FnMut() -> bool, seconds: u64, description: &str) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out: {description}");
        std::thread::sleep(Duration::from_millis(200));
    }
}
fn outer(tree: &Path) {
    assert!(tree.starts_with("/root/dev/prove-native-xray"), "use the dedicated ams-test checkout");
    assert!(std::env::var_os("DOCKER_HOST").is_none(), "outer Docker must be the stand daemon");
    let image = std::env::var("PC_XRAY_ROUTER_IMAGE").expect("current native manager image required");
    docker(&["image", "inspect", &image]);
    let directory = tree.join(format!(".native-xray-{}", pc_host::fs::token_hex::<8>()));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let lab = Lab { directory, keeper: format!("pc-native-xray-{}", pc_host::fs::token_hex::<8>()) };
    // Import the real built image, not an Xray archive: acquisition must remain unstaged.
    docker(&["image", "save", "--output", lab.directory.join("manager.tar").to_str().unwrap(), &image]);
    for name in ["resolv.conf", "hosts", "nsswitch.conf", "login.defs", "passwd", "group", "shadow", "gshadow"] {
        fs::copy(Path::new("/etc").join(name), lab.directory.join(name)).unwrap();
    }
    fs::copy("/etc/ssl/certs/ca-certificates.crt", lab.directory.join("ca-certificates.crt")).unwrap();
    docker(&[
        "run",
        "--detach",
        "--name",
        &lab.keeper,
        "--network",
        "bridge",
        "--entrypoint",
        "/bin/sh",
        &image,
        "-c",
        "exec sleep infinity",
    ]);
    // Host systemd-resolved's 127.0.0.53 is outside this network namespace.
    docker(&["cp", &format!("{}:/etc/resolv.conf", lab.keeper), lab.directory.join("resolv.conf").to_str().unwrap()]);
    let pid = text(docker(&["inspect", "--format", "{{.State.Pid}}", &lab.keeper]));
    let status = Command::new("nsenter")
        .arg(format!("--net=/proc/{pid}/ns/net"))
        .args(["unshare", "--mount", "--pid", "--fork", "--mount-proc", "--propagation", "private"])
        .arg(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", TEST, "--nocapture", "--test-threads=1"])
        .env("PC_XRAY_ROUTER_INNER", &lab.directory)
        .env("PC_XRAY_ROUTER_OUTER_NET", fs::read_link("/proc/self/ns/net").unwrap())
        .env("PC_XRAY_ROUTER_OUTER_MNT", fs::read_link("/proc/self/ns/mnt").unwrap())
        .status()
        .unwrap();
    assert!(status.success(), "isolated native Xray acceptance failed");
}
fn isolated_host(directory: &Path) {
    for (namespace, key) in [("net", "PC_XRAY_ROUTER_OUTER_NET"), ("mnt", "PC_XRAY_ROUTER_OUTER_MNT")] {
        assert_ne!(
            fs::read_link(format!("/proc/self/ns/{namespace}")).unwrap(),
            PathBuf::from(std::env::var_os(key).unwrap())
        );
    }
    for path in ["/etc", "/var/lib", "/var/log", "/opt", "/run", "/usr/local"] {
        checked(Command::new("mount").args(["-t", "tmpfs", "-o", "mode=0755", "tmpfs", path]));
    }
    fs::create_dir_all("/run/native-xray-tmp").unwrap();
    std::env::set_var("TMPDIR", "/run/native-xray-tmp");
    std::env::set_var("XDG_RUNTIME_DIR", "/run/native-xray-tmp");
    for name in ["resolv.conf", "hosts", "nsswitch.conf", "login.defs", "passwd", "group", "shadow", "gshadow"] {
        fs::copy(directory.join(name), Path::new("/etc").join(name)).unwrap();
    }
    // The stand may already have the real service identity. Fresh installation must
    // create it in our private /etc, never adopt the stand's account by accident.
    for name in ["passwd", "group", "shadow", "gshadow"] {
        let path = Path::new("/etc").join(name);
        let source = fs::read_to_string(&path).unwrap();
        let private = source.lines().filter(|line| !line.starts_with("xray-router:")).collect::<Vec<_>>().join("\n");
        fs::write(path, format!("{private}\n")).unwrap();
    }
    fs::create_dir_all("/etc/ssl/certs").unwrap();
    fs::copy(directory.join("ca-certificates.crt"), "/etc/ssl/certs/ca-certificates.crt").unwrap();
    fs::create_dir_all("/usr/local/libexec").unwrap();
    fs::write(directory.join("daemon.json"), b"{}\n").unwrap();
}
fn private_daemon(directory: &Path) -> Process {
    let log = fs::File::create(directory.join("dockerd.log")).unwrap();
    let process = Process(
        Command::new("dockerd")
            .arg(format!("--config-file={}", directory.join("daemon.json").display()))
            .arg(format!("--data-root={}", directory.join("docker").display()))
            .args([
                "--exec-root=/run/native-xray-docker",
                "--pidfile=/run/native-xray-docker.pid",
                "--host=unix:///run/native-xray-docker.sock",
                "--bridge=none",
                "--iptables=false",
                "--ip-forward=false",
                "--ip-masq=false",
                "--userland-proxy=false",
                "--default-address-pool=base=10.239.0.0/16,size=24",
            ])
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    std::env::set_var("DOCKER_HOST", "unix:///run/native-xray-docker.sock");
    std::env::set_var("DOCKER_CONFIG", directory.join("docker-config"));
    wait_until(
        || Command::new("docker").arg("info").output().is_ok_and(|output| output.status.success()),
        30,
        "private Docker daemon",
    );
    docker(&["load", "--input", directory.join("manager.tar").to_str().unwrap()]);
    process
}
fn stage_compose(tree: &Path, image: &str) {
    fs::create_dir_all(format!("{PROJECT}/version-overrides")).unwrap();
    fs::write(format!("{PROJECT}/.env"), b"").unwrap();
    fs::write(
        format!("{PROJECT}/compose.yaml"),
        format!("name: proxy_panel_by_dubr1k\nservices:\n  panel:\n    image: {image}\n    profiles: [not-started]\n"),
    )
    .unwrap();
    fs::copy(tree.join("compose.xray-router.yaml"), format!("{PROJECT}/compose.xray-router.yaml")).unwrap();
    // Use the normal override boundary. The production overlay is unmodified and
    // real Compose creates both real services in our independent daemon.
    fs::write(format!("{PROJECT}/version-overrides/compose.versions.yaml"), format!("services:\n  xray-router:\n    build: !reset null\n    image: {image}\n  xray-router-ingress:\n    build: !reset null\n    image: {image}\n")).unwrap();
}
fn engine(context: &AdapterContext) -> TransactionEngine {
    TransactionEngine::new(TransactionStore::new(Path::new("/")).unwrap())
        .with_adapter(Arc::new(XrayRouterAdapter::new(context)))
}
fn manager_status() -> Value {
    serde_json::from_slice(
        &docker(&["exec", ROUTER, "/usr/local/bin/xray-router-manager", "healthcheck", "--status"]).stdout,
    )
    .unwrap()
}
fn assert_runtime() -> u64 {
    let status = manager_status();
    assert_eq!(status["phase"], "idle");
    for member in ["xray", "geoip", "geosite"] {
        assert_eq!(status["artifacts"][member]["verified"], true);
    }
    let generation = status["running"]["generation"].as_u64().unwrap();
    assert!(generation > 0);
    for port in [45101, 45102, 45104] {
        let output = checked(Command::new("ss").args(["-H", "-lnt", &format!("sport = :{port}")]));
        let addresses = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| line.split_whitespace().nth(3).unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(addresses, [format!("127.0.0.1:{port}")]);
    }
    generation
}
fn socks(port: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    stream
}
fn authenticate(stream: &mut TcpStream, credential: &str) -> bool {
    stream.write_all(&[5, 1, 2]).unwrap();
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 2]);
    let (user, password) = credential.trim().split_once(':').unwrap();
    let mut request = vec![1, user.len() as u8];
    request.extend_from_slice(user.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password.as_bytes());
    stream.write_all(&request).unwrap();
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply[0], 1);
    reply[1] == 0
}
fn credential_and_connect_proof() {
    for (port, name) in [(45101, "naive"), (45102, "mieru")] {
        let mut stream = socks(port);
        stream.write_all(&[5, 1, 0]).unwrap();
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [5, 255], "unauthenticated SOCKS must be rejected");
        assert!(!authenticate(&mut socks(port), "invalid:invalid-password-0123456789"));
        let credential = fs::read_to_string(format!("{PROJECT}/secrets/xray-router-ingress-{name}")).unwrap();
        let probe = format!("/run/native-xray-tmp/{name}-connect.conf");
        pc_host::fs::atomic_write(
            Path::new(&probe),
            format!("proxy-user = \"{}\"\n", credential.trim()).as_bytes(),
            0o600,
            None,
        )
        .unwrap();
        // The router deliberately blocks private destinations. Use a real TLS
        // Internet origin; never change that security policy to admit a fixture.
        let output = checked(Command::new("curl").args([
            "--config",
            &probe,
            "--fail",
            "--silent",
            "--show-error",
            "--noproxy",
            "",
            "--socks5-hostname",
            &format!("127.0.0.1:{port}"),
            "--max-time",
            "20",
            "https://www.cloudflare.com/cdn-cgi/trace",
        ]));
        fs::remove_file(probe).unwrap();
        let response = String::from_utf8(output.stdout).unwrap();
        assert!(response.lines().any(|line| line.starts_with("ip=")));
        assert!(response.lines().any(|line| line == "h=www.cloudflare.com"));
    }
}
fn version_agent_initialstate(
    tree: &Path,
    directory: &Path,
    config: &installer_core::model::InstallerConfig,
    pin: &ArtifactPin,
) {
    let source = directory.join("agent-source");
    for name in [
        "deploy/version-agent.env.example",
        "deploy/version-agent.service",
        "deploy/proxy-control-version-agent.tmpfiles.conf",
        "compose.yaml",
        "release/external-artifacts.json",
    ] {
        let target = source.join(name);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(tree.join(name), target).unwrap();
    }
    let binary = source.join("version_agent/bin/linux-amd64/proxy-control-version-agent");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    fs::copy(std::env::var_os("PC_VERSION_AGENT_BIN").expect("native version-agent binary"), &binary).unwrap();
    let context = AdapterContext { root: "/".into(), tree: source, runner: Arc::new(SystemRunner) };
    let adapter = VersionAgentAdapter::new(&context);
    let action = adapter.plan(config, &AuditFacts::default()).unwrap().remove(0);
    assert!(!Path::new("/run/systemd/private").exists());
    // This is the native initialstate boundary, not a pretend systemd installation:
    // the actual state write precedes the actual unsupported supervision command.
    let error = adapter.apply(&action, adapter.prepare(&action).unwrap()).unwrap_err();
    assert!(error.to_string().contains("systemctl"), "unexpected initialstate failure: {error}");
    let state: Value =
        serde_json::from_slice(&fs::read("/var/lib/proxy-control/version-agent/state.json").unwrap()).unwrap();
    let xray = &state["components"]["xray"];
    assert_eq!(xray["version"], pin.version);
    assert_eq!(xray["sha256"], pin.sha256);
    for name in ["xray", "geoip.dat", "geosite.dat"] {
        assert_eq!(xray["members"][name], pin.member(name).unwrap().sha256);
    }
    let environment = pc_host::envfile::read(Path::new("/etc/proxy-control/version-agent.env")).unwrap();
    let log = fs::File::create(directory.join("version-agent.log")).unwrap();
    let _agent = Process(
        Command::new("/opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent")
            .envs(environment)
            .env("PROXY_CONTROL_UPSTREAM_CHECK_INTERVAL", "0")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    wait_until(|| Path::new("/run/proxy-control/version-agent.sock").exists(), 10, "native version-agent socket");
    let get = |endpoint: &str| -> Value {
        serde_json::from_slice(
            &checked(Command::new("curl").args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "30",
                "--unix-socket",
                "/run/proxy-control/version-agent.sock",
                &format!("http://version-agent{endpoint}"),
            ]))
            .stdout,
        )
        .unwrap()
    };
    assert_eq!(get("/v1/health")["status"], "ok");
    let versions = get("/v1/versions");
    assert_eq!(versions["components"]["xray"]["current"], pin.version);
    assert_eq!(versions["components"]["xray"]["status"], "ready");
    let status = manager_status();
    assert_eq!(status["xray_version"].as_str().unwrap().split_whitespace().nth(1), Some(pin.version.as_str()));
    println!(
        "XRAY_NATIVE_AGENT_INITIALSTATE_OK version={} archive_sha256={} real_members=true native_health=true",
        pin.version, pin.sha256
    );
}

#[test]
#[ignore = "destructive native ams-test proof; explicit PC_XRAY_ROUTER_LIVE=ams-test required"]
fn real_unstaged_xray_router_native_lifecycle() {
    assert_eq!(std::env::var("PC_XRAY_ROUTER_LIVE").as_deref(), Ok("ams-test"));
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(std::env::consts::ARCH, "x86_64");
    let tree = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let Some(directory) = std::env::var_os("PC_XRAY_ROUTER_INNER") else {
        return outer(tree);
    };
    let directory = PathBuf::from(directory);
    isolated_host(&directory);
    let _daemon = private_daemon(&directory);
    let image = std::env::var("PC_XRAY_ROUTER_IMAGE").unwrap();
    stage_compose(tree, &image);
    docker(&[
        "run",
        "--detach",
        "--name",
        "native-xray-foreign",
        "--network",
        "none",
        "--entrypoint",
        "/bin/sh",
        &image,
        "-c",
        "exec sleep infinity",
    ]);
    docker(&["run", "--rm", "--network", "none", "--entrypoint", "/bin/sh", &image, "-ec", "! command -v python && ! command -v python3 && test -x /usr/local/bin/xray-router-manager && test -x /usr/local/bin/mtproxy-bridge"]);
    let manifest =
        ReleaseManifest::from_bytes(&fs::read(tree.join("release/external-artifacts.json")).unwrap()).unwrap();
    let pin = manifest.external_artifact("xray", "amd64").unwrap();
    let mut config =
        installer_core::config::load_config(&tree.join("examples/installer/core-trusttunnel.toml")).unwrap();
    config.egress = Some(installer_core::model::EgressConfig { router: true, ..Default::default() });
    let context = AdapterContext { root: "/".into(), tree: tree.into(), runner: Arc::new(SystemRunner) };
    let adapter = XrayRouterAdapter::new(&context);
    let actions = adapter.plan(&config, &AuditFacts::default()).unwrap();
    assert_eq!(actions.len(), 1, "the acceptance profile must select the real router");
    let plan = InstallPlan::new(
        json!({"native_xray_live":true}),
        AuditFacts::default(),
        ReleaseIdentity::new("v4.0.0", &"a".repeat(40), &"b".repeat(64), BTreeMap::new(), BTreeMap::new()).unwrap(),
        vec!["xray_router".into()],
        BTreeMap::from([("xray_router".into(), vec![])]),
        actions,
        PLAN_SCHEMA,
    )
    .unwrap();
    assert!(!Path::new(ARCHIVE).exists(), "positive acquisition must not use a staged archive");
    assert!(!Path::new(STATE).exists());
    assert_eq!(engine(&context).apply(&plan, &plan.digest()).unwrap().status, Status::Active);
    assert_eq!(pc_host::fs::sha256_file(Path::new(ARCHIVE)).unwrap(), pin.sha256);
    for name in ["xray", "geoip.dat", "geosite.dat"] {
        let path = Path::new(BIN).join(name);
        let member = pin.member(name).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(pc_host::fs::sha256_file(&path).unwrap(), member.sha256);
        assert_eq!(metadata.len(), member.size);
        assert_eq!(metadata.mode() & 0o777, member.mode);
    }
    assert!(text(docker(&["exec", ROUTER, "/opt/xray/xray", "version"])).contains(&pin.version));
    assert_eq!(engine(&context).resume().unwrap().status, Status::Active);
    let generation = assert_runtime();
    credential_and_connect_proof();
    println!("XRAY_NATIVE_UNSTAGED_FETCH_OK url={} archive_sha256={} members=3 durable_active=true generation={generation} loopback=3 unauth_rejected=2 bad_password_rejected=2 authenticated_connect=2 internet_connect=true", pin.url, pin.sha256);
    version_agent_initialstate(tree, &directory, &config, pin);
    let token_path = format!("{PROJECT}/secrets/xray-router-manager-token");
    let token = fs::read(&token_path).unwrap();
    let state = fs::metadata(STATE).unwrap();
    assert_eq!((state.uid(), state.gid(), state.mode() & 0o777), (10006, 10006, 0o700));
    let secret = fs::metadata(&token_path).unwrap();
    assert_eq!((secret.uid(), secret.gid(), secret.mode() & 0o777), (0, 10006, 0o440));
    fs::write(format!("{PROJECT}/.env.xray-router"), b"drifted-managed-overlay\n").unwrap();
    docker(&["stop", ROUTER]);
    assert_eq!(engine(&context).repair().unwrap().status, Status::Active);
    assert_eq!(fs::read(&token_path).unwrap(), token);
    assert_runtime();
    credential_and_connect_proof();
    println!("XRAY_NATIVE_REPAIR_OK stopped_service=true managed_overlay_drift=true credentials_preserved=true authenticated_connect=2");
    fs::write(&token_path, b"foreign-drift\n").unwrap();
    assert!(engine(&context).uninstall(true).unwrap_err().to_string().contains("owned file drifted"));
    // A changed manager-token file correctly stops the healthcheck client from
    // authenticating; prove refusal left the real processes/data plane untouched.
    assert_eq!(text(docker(&["inspect", "--format", "{{.State.Running}}", ROUTER])), "true");
    credential_and_connect_proof();
    fs::write(&token_path, &token).unwrap();
    fs::write(Path::new(BIN).join("foreign"), b"do-not-remove").unwrap();
    assert_eq!(engine(&context).uninstall(true).unwrap().status, Status::Uninstalled);
    assert!(!Path::new(STATE).exists());
    assert!(!Path::new(&token_path).exists());
    assert!(!Path::new(BIN).join("xray").exists());
    assert_eq!(fs::read(Path::new(BIN).join("foreign")).unwrap(), b"do-not-remove");
    assert_eq!(text(docker(&["container", "ls", "--all", "--format", "{{.Names}}"])), "native-xray-foreign");
    assert!(!Command::new("getent").args(["passwd", "xray-router"]).status().unwrap().success());
    assert!(!Command::new("getent").args(["group", "xray-router"]).status().unwrap().success());
    println!("XRAY_NATIVE_OWNERSHIP_PURGE_OK drift_refused=true foreign_file_preserved=true foreign_container_preserved=true owned_identity_removed=true");
    let trusted_archive = Path::new(ARCHIVE).with_extension("trusted");
    fs::rename(ARCHIVE, &trusted_archive).unwrap();
    fs::write(ARCHIVE, b"corrupt-archive").unwrap();
    assert!(engine(&context)
        .apply(&plan, &plan.digest())
        .unwrap_err()
        .to_string()
        .contains("artifact digest mismatch"));
    assert_eq!(engine(&context).store().read_state().unwrap().status, Status::RolledBack);
    assert!(!Path::new(BIN).join("xray").exists());
    fs::remove_file(ARCHIVE).unwrap();
    fs::rename(trusted_archive, ARCHIVE).unwrap();
    println!("XRAY_NATIVE_ARCHIVE_REJECTION_OK corrupt_archive_refused=true no_members_installed=true");
    // Real manager startup failure, not an injected successful command or a staged fixture.
    let occupied = TcpListener::bind("127.0.0.1:45101").unwrap();
    assert!(engine(&context).apply(&plan, &plan.digest()).is_err());
    assert_eq!(engine(&context).store().read_state().unwrap().status, Status::RolledBack);
    assert!(Path::new(STATE).is_dir(), "failed-install rollback must preserve manager state");
    assert!(Path::new(&token_path).is_file(), "failed-install rollback must preserve credentials");
    assert!(!Path::new(BIN).join("xray").exists());
    assert!(!Path::new(&format!("{PROJECT}/.env.xray-router")).exists());
    assert_eq!(text(docker(&["container", "ls", "--all", "--format", "{{.Names}}"])), "native-xray-foreign");
    drop(occupied);
    println!("XRAY_NATIVE_FAILURE_ROLLBACK_OK real_port_conflict=true durable_rolled_back=true runtime_removed=true data_preserved=true foreign_untouched=true");
    assert_eq!(engine(&context).apply(&plan, &plan.digest()).unwrap().status, Status::Active);
    assert_runtime();
    credential_and_connect_proof();
    assert_eq!(engine(&context).uninstall(true).unwrap().status, Status::Uninstalled);
    assert!(!Path::new(STATE).exists());
    assert!(!Path::new(&token_path).exists());
    println!("XRAY_NATIVE_REINSTALL_AFTER_ROLLBACK_OK authenticated_connect=2 purge=true");
    docker(&["rm", "--force", "native-xray-foreign"]);
}
