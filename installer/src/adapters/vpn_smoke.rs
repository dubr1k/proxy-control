//! Explicit ams-test-only smoke: real engine, Docker Compose and manager images, isolated
//! container networks/state and a caller-owned network namespace for reversible sysctl writes.
use super::vpn_tests::{action, tree};
use crate::{
    adapter::Adapter,
    adapters::{amneziawg::AmneziaWgAdapter, trusttunnel::TrustTunnelAdapter, AdapterContext},
    testkit::{engine_for, plan_with, TempDir},
};
use pc_host::runner::{
    Bounded, BoundedError, BoundedOutput, Capture, HostRunner, QueryError, RunError, RunOptions, RunOutput,
    SystemRunner,
};
use std::{fs, path::PathBuf, sync::Arc, time::Duration};
struct IsolatedRunner {
    root: PathBuf,
    project: String,
    container: String,
}
impl IsolatedRunner {
    fn argv(&self, args: &[&str]) -> Vec<String> {
        args.iter()
            .map(|s| {
                if s.starts_with("/opt/mtproxy-shared443") || s.starts_with("/etc/sysctl.d/") {
                    return self.root.join(s.trim_start_matches('/')).to_string_lossy().into_owned();
                }
                if s.starts_with("proxy-control-") && s.ends_with("-manager") {
                    return self.container.clone();
                }
                if s.starts_with("label=com.docker.compose.project=") {
                    return format!("label=com.docker.compose.project={}", self.project);
                }
                s.to_string()
            })
            .collect()
    }
    fn refs(args: &[String]) -> Vec<&str> {
        args.iter().map(String::as_str).collect()
    }
}
impl HostRunner for IsolatedRunner {
    fn bounded(&self, a: &[&str], l: Bounded) -> Result<BoundedOutput, BoundedError> {
        let a = self.argv(a);
        SystemRunner.bounded(&Self::refs(&a), l)
    }
    fn run(&self, a: &[&str], o: &RunOptions<'_>) -> Result<RunOutput, RunError> {
        let a = self.argv(a);
        SystemRunner.run(&Self::refs(&a), o)
    }
    fn capture(&self, a: &[&str], max: usize, l: Capture) -> String {
        if a.first() == Some(&"ss") {
            let pid = SystemRunner
                .capture_checked(
                    &["docker", "inspect", "--format", "{{.State.Pid}}", &self.container],
                    Duration::from_secs(10),
                )
                .expect("isolated container pid");
            let mut args = vec!["nsenter", "-t", pid.trim(), "-n", "ss"];
            args.extend_from_slice(&a[1..]);
            return SystemRunner.capture(&args, max, l);
        }
        let a = self.argv(a);
        SystemRunner.capture(&Self::refs(&a), max, l)
    }
    fn capture_checked(&self, a: &[&str], t: Duration) -> Result<String, QueryError> {
        let a = self.argv(a);
        SystemRunner.capture_checked(&Self::refs(&a), t)
    }
}
struct Cleanup(String);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}
#[test]
#[ignore = "ams-test only: invoke under unshare --net; uses isolated existing manager images"]
fn real_isolated_engine_install_repair_rollback() {
    assert_eq!(
        std::env::var("PC_VPN_SMOKE_NETNS").as_deref(),
        Ok("1"),
        "run under unshare --net with PC_VPN_SMOKE_NETNS=1"
    );
    // Refuse any invocation sharing the host's network namespace.
    assert_ne!(fs::read_link("/proc/self/ns/net").unwrap(), fs::read_link("/proc/1/ns/net").unwrap());
    for awg in [false, true] {
        let root = TempDir::new("vpn-real");
        let project = format!("pc-vpn-smoke-{}-{}", std::process::id(), if awg { "awg" } else { "tt" });
        let container = format!("{project}-manager");
        let _cleanup = Cleanup(container.clone());
        let service = if awg { "awg-manager" } else { "trusttunnel-manager" };
        let name = if awg { "amneziawg" } else { "trusttunnel" };
        let path = root.path().join("opt/mtproxy-shared443");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join(".env"), "").unwrap();
        fs::write(path.join("compose.yaml"), format!("name: {project}\nservices: {{}}\n")).unwrap();
        fs::create_dir_all(root.path().join("dev/net")).unwrap();
        fs::write(root.path().join("dev/net/tun"), "").unwrap();
        let state = root.path().join(format!("var/lib/{service}"));
        let token = path.join(format!("secrets/{service}-token"));
        let mut compose=format!("services:\n  {service}:\n    image: proxy_panel_by_dubr1k-{service}:latest\n    container_name: {container}\n    network_mode: none\n    cap_drop: [ALL]\n    tmpfs:\n      - /tmp\n      - /run/{service}\n    volumes:\n      - {}:/var/lib/{service}\n      - {}:/run/secrets/{service}-token:ro\n    environment:\n",state.display(),token.display());
        if awg {
            compose.push_str("      AWG_MANAGER_TOKEN_FILE: /run/secrets/awg-manager-token\n      AWG_MANAGER_SOCKET: /run/awg-manager/manager.sock\n      AWG_STATE_DIR: /var/lib/awg-manager\n      AWG_VERSIONS: 1.5,2.0,3.1\n      AWG_PORTS: 1.5=25076,2.0=11892,3.1=13013\n      AWG_SUBNETS: 1.5=10.66.15.0/24,2.0=10.66.20.0/24,3.1=10.66.31.0/24\n      AWG_MTU: '1280'\n      AWG_DNS: 1.1.1.1,1.0.0.1\n      AWG_NAT: 'false'\n    cap_add: [NET_ADMIN, NET_RAW]\n    devices: [/dev/net/tun:/dev/net/tun]\n    sysctls:\n      net.ipv4.ip_forward: '1'\n    tmpfs:\n      - /tmp\n      - /run/awg-manager\n      - /run/amneziawg\n");
            // Replace the shared tmpfs entry rather than duplicate a YAML key.
            compose = compose.replacen("    tmpfs:\n      - /tmp\n      - /run/awg-manager\n", "", 1);
        } else {
            let lineage = root.path().join("etc/letsencrypt/live/gate.example.org");
            fs::create_dir_all(&lineage).unwrap();
            assert!(std::process::Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=gate.example.org",
                    "-keyout"
                ])
                .arg(lineage.join("privkey.pem"))
                .arg("-out")
                .arg(lineage.join("fullchain.pem"))
                .output()
                .unwrap()
                .status
                .success());
            compose.push_str("      TT_MANAGER_TOKEN_FILE: /run/secrets/trusttunnel-manager-token\n      TT_MANAGER_SOCKET: /run/trusttunnel-manager/manager.sock\n      TT_STATE_DIR: /var/lib/trusttunnel-manager\n      TT_HOSTNAME: gate.example.org\n      TT_LISTEN: 127.0.0.1:4453\n      TT_METRICS: 127.0.0.1:1987\n      TT_CERT: /cert/fullchain.pem\n      TT_KEY: /cert/privkey.pem\n      TT_BINARY: /usr/local/bin/trusttunnel_endpoint\n");
            compose = compose
                .replace("    environment:\n", &format!("      - {}:/cert:ro\n    environment:\n", lineage.display()));
        }
        compose.push_str(&format!("    healthcheck:\n      test: [CMD, /usr/local/bin/{service}, healthcheck]\n      interval: 1s\n      timeout: 3s\n      retries: 20\n      start_period: 2s\n"));
        fs::write(path.join(format!("compose.{name}.yaml")), compose).unwrap();
        let runner = Arc::new(IsolatedRunner { root: root.path().into(), project, container });
        let context = AdapterContext { root: root.path().into(), tree: tree(), runner: runner.clone() };
        let adapter: Arc<dyn Adapter> =
            if awg { Arc::new(AmneziaWgAdapter::new(&context)) } else { Arc::new(TrustTunnelAdapter::new(&context)) };
        let plan = plan_with(vec![action(name)], Default::default());
        let engine = engine_for(root.path(), vec![adapter]);
        let before =
            SystemRunner.capture_checked(&["sysctl", "-n", "net.ipv4.ip_forward"], Duration::from_secs(5)).unwrap();
        engine.apply(&plan, &plan.digest()).unwrap();
        engine.repair().unwrap();
        engine.uninstall(true).unwrap();
        assert!(!path.join(format!(".env.{name}")).exists());
        assert!(!state.exists());
        assert!(!token.exists());
        let after =
            SystemRunner.capture_checked(&["sysctl", "-n", "net.ipv4.ip_forward"], Duration::from_secs(5)).unwrap();
        assert_eq!(before, after);
        println!("REAL_VPN_ENGINE_SMOKE {name}: install, real manager health/listeners, repair, purge rollback, forwarding restored");
    }
}
