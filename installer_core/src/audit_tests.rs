//! Ported `tests/test_installer_audit.py` (names without `test_`), plus the C-locale and parser
//! cases of the Rust port. Real processes run through `/bin/sh` instead of `sys.executable`.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

use super::*;
use crate::model::{DomainConfig, FirewallConfig, MieruConfig, Profile, ThreeXuiConfig, ThreeXuiMode};

const HOST_V4: &str = "203.0.113.10";
const HOST_V6: &str = "2001:db8::10";
const FOREIGN_V6: &str = "2001:db8::99";

fn config_with(host_mode: HostMode, profile: Profile, mode: ThreeXuiMode) -> InstallerConfig {
    let mut domains = DomainConfig::new("panel.example.com", "relay.example.com");
    if profile.includes_naive() {
        domains.naive = Some("naive.example.com".into());
    }
    if profile.includes_mieru() {
        domains.mieru = Some("mieru.example.com".into());
    }
    let mut three_xui = ThreeXuiConfig::new(mode);
    if mode != ThreeXuiMode::None {
        three_xui.panel_domain = Some("xui.example.com".into());
        three_xui.vless_tcp_domain = Some("reality.example.com".into());
    }
    InstallerConfig {
        schema: 1,
        host_mode,
        profile,
        acme_email: "admin@example.com".into(),
        initial_user: "owner".into(),
        domains,
        mieru: profile.includes_mieru().then(|| MieruConfig {
            tcp_ports: vec![4567],
            udp_ports: vec![4567],
            lane_slots: 0,
        }),
        three_xui,
        firewall: FirewallConfig { manage_ufw: host_mode == HostMode::Fresh },
        egress: None,
        ingress: None,
        amneziawg: None,
        trusttunnel: None,
    }
}

fn config() -> InstallerConfig {
    config_with(HostMode::Fresh, Profile::Full, ThreeXuiMode::Existing)
}

fn core_config() -> InstallerConfig {
    config_with(HostMode::Fresh, Profile::Core, ThreeXuiMode::None)
}

type Responses = BTreeMap<Vec<String>, (i32, String, String)>;

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| part.to_string()).collect()
}

/// `ScriptedExecutor`: answers from a table (unknown: exit 127), records every call.
#[derive(Default)]
struct Scripted {
    responses: Responses,
    missing: Vec<&'static str>,
    calls: Mutex<Vec<(Vec<String>, bool)>>,
}

impl Scripted {
    fn new(responses: Responses) -> Scripted {
        Scripted { responses, ..Default::default() }
    }

    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().iter().map(|(argv, _)| argv.clone()).collect()
    }
}

impl AuditExecutor for Scripted {
    fn execute(
        &self,
        argv: &[&str],
        _limits: Bounded,
        c_locale: bool,
    ) -> std::result::Result<BoundedOutput, BoundedError> {
        let command: Vec<String> = argv.iter().map(|part| part.to_string()).collect();
        if self.missing.contains(&argv[0]) {
            return Err(BoundedError::Unavailable);
        }
        self.calls.lock().unwrap().push((command.clone(), c_locale));
        let (returncode, stdout, stderr) =
            self.responses.get(&command).cloned().unwrap_or((127, String::new(), "missing".into()));
        Ok(BoundedOutput { returncode, stdout, stderr })
    }
}

/// `resolver(records)`: A and AAAA answers per name (absolute names, trailing dot dropped).
struct Records(BTreeMap<String, (Vec<String>, Vec<String>)>);

impl Resolver for Records {
    fn getaddrinfo(&self, absolute_name: &str) -> ResolveResult {
        let (a, aaaa) = self.0.get(absolute_name.trim_end_matches('.')).cloned().unwrap_or_default();
        Ok(a.into_iter()
            .map(|address| (Family::Inet, address))
            .chain(aaaa.into_iter().map(|address| (Family::Inet6, address)))
            .collect())
    }
}

fn records(domains: &[String], a: &[&str], aaaa: &[&str]) -> Records {
    Records(
        domains
            .iter()
            .map(|domain| {
                (
                    domain.clone(),
                    (a.iter().map(|s| s.to_string()).collect(), aaaa.iter().map(|s| s.to_string()).collect()),
                )
            })
            .collect(),
    )
}

fn ok(stdout: &str) -> (i32, String, String) {
    (0, stdout.into(), String::new())
}

fn host_responses(domains: &[String], caa: &str, xray: Option<&Value>) -> Responses {
    let mut responses = Responses::new();
    responses.insert(argv(&["uname", "-m"]), ok("x86_64\n"));
    responses.insert(
        argv(&["df", "-Pk"]),
        ok("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 100000 25000 75000 25% /\n"),
    );
    responses.insert(
        argv(&["free", "-b"]),
        ok("              total used free shared buff/cache available\nMem:     8589934592 1 2 3 4 6442450944\n"),
    );
    responses.insert(
        argv(&["ip", "-j", "address"]),
        ok(&json!([{"ifname": "eth0", "addr_info": [
            {"family": "inet", "local": HOST_V4, "scope": "global"},
            {"family": "inet6", "local": HOST_V6, "scope": "global"}]}])
        .to_string()),
    );
    responses.insert(
        argv(&["ss", "-H", "-lntup"]),
        ok("tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=4,fd=3))\n\
            tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=5,fd=4))\n\
            udp UNCONN 0 0 0.0.0.0:4567 0.0.0.0:* users:((\"mieru\",pid=6,fd=5))\n"),
    );
    responses.insert(
        argv(&["nginx", "-T"]),
        ok("# configuration file /etc/nginx/nginx.conf:\n\
            events {}\nstream { map $ssl_preread_server_name $upstream {\n\
            old.example.com 127.0.0.1:10443;\ndefault 127.0.0.1:8443;\n} }\n\
            server { server_name old-panel.example.com; }\n"),
    );
    responses.insert(argv(&["docker", "--version"]), ok("Docker version 28.0.0, build abc\n"));
    responses.insert(argv(&["docker", "compose", "version", "--short"]), ok("2.35.0\n"));
    responses.insert(
        argv(&["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"]),
        ok("nginx.service enabled\nssh.service enabled\nx-ui.service enabled\n"),
    );
    responses.insert(
        argv(&["systemctl", "show", "ssh.socket", "--property=Listen", "--value", "--no-pager"]),
        ok("[::]:22 (Stream)\n"),
    );
    responses.insert(argv(&UFW_IPV6_CONFIG_COMMAND), ok("IPV6=yes\n"));
    responses.insert(argv(&["ufw", "status", "verbose"]), ok("Status: active\n22/tcp ALLOW IN Anywhere\n"));
    for domain in domains {
        responses.insert(argv(&["dig", "+short", "CAA", domain]), ok(caa));
        let path = format!("/etc/letsencrypt/live/{domain}/fullchain.pem");
        responses.insert(
            argv(&["openssl", "x509", "-in", &path, "-noout", "-dates", "-ext", "subjectAltName"]),
            (1, String::new(), "not found".into()),
        );
    }
    match xray {
        None => {
            responses
                .insert(argv(&["test", "-f", "/usr/local/x-ui/bin/config.json"]), (1, String::new(), String::new()));
        }
        Some(xray) => {
            responses.insert(argv(&["test", "-f", "/usr/local/x-ui/bin/config.json"]), ok(""));
            responses.insert(argv(&["cat", "/usr/local/x-ui/bin/config.json"]), ok(&xray.to_string()));
        }
    }
    responses.insert(argv(&["test", "-f", "/var/lib/proxy-control/ownership.json"]), (1, String::new(), String::new()));
    responses
}

const LETSENCRYPT: &str = "0 issue \"letsencrypt.org\"\n";

fn run_audit(config: &InstallerConfig, executor: &Scripted, resolver: &dyn Resolver) -> Result<Audit> {
    let runner = CommandRunner::new(executor, resolver).with_environment(&[]);
    audit_host(config, &runner)
}

fn scripted_audit(config: &InstallerConfig, caa: &str, aaaa: &[&str], xray: Option<&Value>) -> (Audit, Scripted) {
    let domains = config.required_domains();
    let executor = Scripted::new(host_responses(&domains, caa, xray));
    let audit = run_audit(config, &executor, &records(&domains, &[HOST_V4], aaaa)).unwrap();
    (audit, executor)
}

fn expect_error(result: Result<Audit>) -> String {
    match result {
        Err(AuditError::Failed(message)) => message,
        other => panic!("expected an audit error, got {other:?}"),
    }
}

fn sh(script: &str, args: &[&str]) -> Vec<String> {
    let mut command = vec!["/bin/sh".to_string(), "-c".into(), script.into(), "sh".into()];
    command.extend(args.iter().map(|arg| arg.to_string()));
    command
}

fn system_runner(timeout: Duration, max_output: usize) -> CommandRunner<'static> {
    static EXECUTOR: SystemExecutor = SystemExecutor;
    static RESOLVER: SystemResolver = SystemResolver;
    CommandRunner::new(&EXECUTOR, &RESOLVER).with_limits(timeout, max_output).unwrap().with_environment(&[])
}

fn strs(command: &[String]) -> Vec<&str> {
    command.iter().map(String::as_str).collect()
}

#[test]
fn command_runner_uses_argv_without_shell_and_parses_json() {
    let runner = system_runner(Duration::from_secs(1), 1024);
    let literal = runner.capture(&strs(&sh("printf '%s\\n' \"$1\"", &["$(echo injected)"]))).unwrap();
    let parsed = runner.json(&strs(&sh("echo '{\"value\": 7}'", &[]))).unwrap();
    assert_eq!(literal, "$(echo injected)\n");
    assert_eq!(parsed, json!({"value": 7}));
}

#[test]
fn command_runner_redacts_failed_output_and_argv() {
    let runner = system_runner(Duration::from_secs(1), 1024);
    let secret = "Authorization: Bearer header-secret password=hunter2";
    let err = runner.capture(&strs(&sh("echo \"$1\" >&2; exit 9", &[secret]))).unwrap_err().message();
    for forbidden in ["header-secret", "hunter2", "Authorization"] {
        assert!(!err.contains(forbidden), "{err}");
    }
    assert!(err.contains("exit status 9"));
}

#[test]
fn command_runner_bounds_output_timeout_and_malformed_json() {
    let bounded = system_runner(Duration::from_secs(1), 64);
    let oversized = bounded
        .capture(&strs(&sh("i=0; while [ $i -lt 1000 ]; do printf sensitive-value-; i=$((i+1)); done", &[])))
        .unwrap_err()
        .message();
    assert!(oversized.contains("output limit") && !oversized.contains("sensitive-value"));
    let timed = system_runner(Duration::from_millis(20), 1024);
    assert!(timed.run(&strs(&sh("sleep 2", &[]))).unwrap_err().message().contains("timed out"));
    let malformed = bounded.json(&strs(&sh("echo '{password: hunter2}'", &[]))).unwrap_err().message();
    assert!(malformed.contains("malformed JSON") && !malformed.contains("hunter2"));
}

/// Python injected a runner raising a `RuntimeError` with these texts; the Rust audit cannot
/// receive a foreign exception, so the sanitizer is exercised directly.
#[test]
fn audit_error_redacts_headers_passwords_tokens_uuid_keys_and_panel_paths() {
    let environment_secret = "environment-secret-specimen";
    let redactor = Redactor::new(&[("AUDIT_API_TOKEN".into(), environment_secret.into())]);
    let text = format!(
        "Authorization: Bearer abc Cookie: sid=cookie-secret password=hunter2 token=tok-value \
         id=deadbeef-dead-beef-dead-beefdeadbeef privateKey=priv-key shortId=short-secret \
         panelPath=/hidden-panel {environment_secret}"
    );
    let message = redactor.safe_audit_error(&text);
    for secret in [
        "abc",
        "cookie-secret",
        "hunter2",
        "tok-value",
        "deadbeef",
        "priv-key",
        "/hidden-panel",
        "short-secret",
        environment_secret,
    ] {
        assert!(!message.contains(secret), "{message}");
    }
    assert!(message.starts_with("audit observation failed"));
    assert!(message.matches("[REDACTED]").count() >= 6, "{message}");
}

#[test]
fn audit_facts_cover_all_categories_and_are_deterministic() {
    let selected = config();
    let (first, _) = scripted_audit(&selected, LETSENCRYPT, &[HOST_V6], None);
    let (second, _) = scripted_audit(&selected, LETSENCRYPT, &[HOST_V6], None);
    assert_eq!(first.facts.stable_dict(), second.facts.stable_dict());
    let keys = |map: &Map<String, Value>| map.keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(&first.facts.platform), ["addresses", "architecture", "disks", "memory", "os"]);
    assert_eq!(keys(&first.facts.listeners), ["owners", "ports", "ssh_socket_tcp", "tcp", "udp"]);
    assert_eq!(first.facts.listeners["ssh_socket_tcp"], json!([22]));
    assert_eq!(keys(&first.facts.topology), ["certificates", "dns", "nginx", "three_xui"]);
    assert_eq!(
        keys(&first.facts.ownership),
        ["compose", "docker", "identities", "installer", "systemd", "three_xui", "ufw"]
    );
    assert_eq!(first.facts.ownership["identities"], json!({"gid": {}, "uid": {}}));
    assert_eq!(first.facts.ownership["ufw"]["ipv6_enabled"], json!(true));
    assert_eq!(first.operator_prerequisites.len(), 1);
    assert_eq!(first.operator_prerequisites[0].code, "cloud_firewall.reachability");
    assert_eq!(first.operator_prerequisites[0].status, "operator_required");
}

#[test]
fn audit_uses_authoritative_ufw_ipv6_mode_not_observed_rules() {
    for (response, expected) in [
        (ok("IPV6=no\n"), json!(false)),
        (ok("IPV6=maybe\n"), Value::Null),
        ((1, String::new(), "permission denied".into()), Value::Null),
    ] {
        let selected = config();
        let domains = selected.required_domains();
        let mut responses = host_responses(&domains, LETSENCRYPT, None);
        responses.insert(argv(&UFW_IPV6_CONFIG_COMMAND), response);
        responses
            .insert(argv(&["ufw", "status", "verbose"]), ok("Status: active\n22/tcp (v6) ALLOW IN Anywhere (v6)\n"));
        let executor = Scripted::new(responses);
        let audit = run_audit(&selected, &executor, &records(&domains, &[HOST_V4], &[HOST_V6])).unwrap();
        assert_eq!(audit.facts.ownership["ufw"]["ipv6_enabled"], expected);
    }
}

#[test]
fn injected_dns_a_aaaa_and_caa_accept_local_addresses() {
    let selected = core_config();
    let (audit, _) = scripted_audit(&selected, LETSENCRYPT, &[HOST_V6], None);
    assert!(audit.hard_stops.is_empty());
    let expected: Map<String, Value> = selected
        .required_domains()
        .into_iter()
        .map(|domain| {
            let fact = json!({
                "a": [HOST_V4], "aaaa": [HOST_V6], "a_matches_local": true, "aaaa_handled": true,
                "caa": [{"flags": 0, "issuer": "letsencrypt.org", "tag": "issue"}],
                "caa_compatible": true, "caa_source": domain,
            });
            (domain, fact)
        })
        .collect();
    assert_eq!(audit.facts.topology["dns"], Value::Object(expected));
}

#[test]
fn unhandled_aaaa_and_incompatible_caa_are_exact_hard_stops() {
    let selected = core_config();
    let (audit, _) = scripted_audit(&selected, "0 issue \"sectigo.com\"\n", &[FOREIGN_V6], None);
    let codes: Vec<&str> = audit.hard_stops.iter().map(|stop| stop.code.as_str()).collect();
    assert_eq!(codes, ["dns.caa_mismatch", "dns.unhandled_aaaa"]);
    // The facts keep the order the audit found them in.
    let listed: Vec<&str> = audit.facts.prerequisites["hard_stops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|stop| stop["code"].as_str().unwrap())
        .collect();
    assert_eq!(listed, ["dns.unhandled_aaaa", "dns.caa_mismatch"]);
    assert_eq!(hard_stops(&audit.facts), audit.hard_stops);
    assert_eq!(audit.hard_stops[1].message, "AAAA records point outside addresses handled by this host");
}

#[test]
fn three_xui_facts_whitelist_only_non_secret_inbound_fields() {
    let xray = json!({
        "inbounds": [{
            "tag": "vless-in", "protocol": "vless", "listen": "127.0.0.1", "port": 10443,
            "settings": {"clients": [{"id": "deadbeef-dead-beef-dead-beefdeadbeef", "password": "hunter2"}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "serverNames": ["reality.example.com"], "privateKey": "private-material",
                "shortIds": ["0123456789abcdef"]}},
        }],
        "api": {"tag": "api", "services": ["HandlerService"]},
        "webBasePath": "/hidden-panel-path",
        "authorization": "Bearer panel-token",
        "cookies": ["session=cookie-secret"],
    });
    let (audit, _) = scripted_audit(&config(), LETSENCRYPT, &[HOST_V6], Some(&xray));
    let encoded = audit.facts.stable_dict().to_string();
    assert_eq!(
        audit.facts.topology["three_xui"]["inbounds"],
        json!([{"listen": "127.0.0.1", "port": 10443, "protocol": "vless",
                "reality_server_names": ["reality.example.com"], "tag": "vless-in", "transport_security": "reality"}])
    );
    for forbidden in [
        "deadbeef",
        "hunter2",
        "private-material",
        "0123456789abcdef",
        "hidden-panel-path",
        "panel-token",
        "cookie-secret",
        "clients",
        "shortIds",
    ] {
        assert!(!encoded.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn malformed_and_unbounded_three_xui_json_fail_closed_without_content() {
    let selected = config_with(HostMode::Fresh, Profile::Core, ThreeXuiMode::Existing);
    let domains = selected.required_domains();
    let dns = records(&domains, &[HOST_V4], &[HOST_V6]);
    let mut malformed = host_responses(&domains, LETSENCRYPT, None);
    malformed.insert(argv(&["test", "-f", "/usr/local/x-ui/bin/config.json"]), ok(""));
    malformed.insert(argv(&["cat", "/usr/local/x-ui/bin/config.json"]), ok("{\"password\":\"hunter2\""));
    let message = expect_error(run_audit(&selected, &Scripted::new(malformed), &dns));
    assert!(message.contains("malformed JSON") && !message.contains("hunter2"));

    let mut huge = host_responses(&domains, LETSENCRYPT, None);
    huge.insert(argv(&["test", "-f", "/usr/local/x-ui/bin/config.json"]), ok(""));
    huge.insert(
        argv(&["cat", "/usr/local/x-ui/bin/config.json"]),
        ok(&json!({"clients": ["secret-value".repeat(200)]}).to_string()),
    );
    let executor = Scripted::new(huge);
    let runner = CommandRunner::new(&executor, &dns).with_limits(DEFAULT_TIMEOUT, 256).unwrap().with_environment(&[]);
    let message = expect_error(audit_host(&selected, &runner));
    assert!(message.contains("output limit") && !message.contains("secret-value"));
}

#[test]
fn audit_uses_only_read_only_commands_and_coexist_never_inspects_firewall_mutably() {
    let selected = config_with(HostMode::Coexist, Profile::Core, ThreeXuiMode::None);
    let (audit, executor) = scripted_audit(&selected, LETSENCRYPT, &[HOST_V6], None);
    assert_eq!(audit.facts.ownership["ufw"]["mode"], json!("read_only"));
    let forbidden = [
        "add", "allow", "apply", "create", "delete", "disable", "enable", "install", "reload", "remove", "restart",
        "set", "start", "stop", "write",
    ];
    for command in executor.calls() {
        assert!(!command.iter().any(|part| forbidden.contains(&lower(part).as_str())), "{command:?}");
    }
}

#[test]
fn missing_optional_tools_are_explicit_facts_not_audit_failures() {
    let selected = core_config();
    let domains = selected.required_domains();
    let executor = Scripted {
        responses: host_responses(&domains, LETSENCRYPT, None),
        missing: vec!["docker", "nginx", "systemctl", "ufw"],
        ..Default::default()
    };
    let audit = run_audit(&selected, &executor, &records(&domains, &[HOST_V4], &[HOST_V6])).unwrap();
    assert_eq!(
        audit.facts.topology["nginx"],
        json!({"available": false, "http_domains": [], "observation": "unavailable", "route_target": null,
               "sni_map_count": 0, "sni_map_files": {}, "sni_routes": {}, "stream_enabled": false,
               "duplicate_sni_domains": [], "topology_error": null})
    );
    assert_eq!(audit.facts.ownership["docker"], json!({"available": false, "observation": "unavailable"}));
    assert_eq!(audit.facts.ownership["compose"], json!({"available": false, "observation": "unavailable"}));
    assert_eq!(
        audit.facts.ownership["systemd"],
        json!({"available": false, "observation": "unavailable", "services": []})
    );
    assert_eq!(audit.facts.ownership["ufw"]["observation"], json!("unavailable"));
}

#[test]
fn required_base_tool_absence_fails_closed_distinctly() {
    let selected = core_config();
    let domains = selected.required_domains();
    let executor =
        Scripted { responses: host_responses(&domains, LETSENCRYPT, None), missing: vec!["ip"], ..Default::default() };
    let message = expect_error(run_audit(&selected, &executor, &records(&domains, &[HOST_V4], &[HOST_V6])));
    assert_eq!(message, "required audit command is unavailable");
}

#[test]
fn failed_optional_observations_are_explicitly_unknown() {
    let selected = core_config();
    let domains = selected.required_domains();
    let mut responses = host_responses(&domains, LETSENCRYPT, None);
    for command in [
        argv(&["nginx", "-T"]),
        argv(&["docker", "--version"]),
        argv(&["docker", "compose", "version", "--short"]),
        argv(&["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"]),
        argv(&["ufw", "status", "verbose"]),
    ] {
        responses.insert(command, (1, String::new(), "failed".into()));
    }
    let audit = run_audit(&selected, &Scripted::new(responses), &records(&domains, &[HOST_V4], &[HOST_V6])).unwrap();
    assert_eq!(audit.facts.topology["nginx"]["observation"], json!("unknown"));
    for key in ["docker", "compose", "systemd", "ufw"] {
        assert_eq!(audit.facts.ownership[key]["observation"], json!("unknown"), "{key}");
    }
}

struct Failing;

impl Resolver for Failing {
    fn getaddrinfo(&self, _name: &str) -> ResolveResult {
        Err(ResolveError)
    }
}

struct Stalled;

impl Resolver for Stalled {
    fn getaddrinfo(&self, _name: &str) -> ResolveResult {
        std::thread::sleep(Duration::from_secs(2));
        Ok(Vec::new())
    }
}

#[test]
fn dns_resolution_transient_failure_and_timeout_fail_closed() {
    let selected = core_config();
    let responses = host_responses(&selected.required_domains(), LETSENCRYPT, None);
    let message = expect_error(run_audit(&selected, &Scripted::new(responses.clone()), &Failing));
    assert_eq!(message, "DNS resolution failed");
    let executor = Scripted::new(responses);
    let runner = CommandRunner::new(&executor, &Stalled)
        .with_limits(Duration::from_millis(30), DEFAULT_MAX_OUTPUT)
        .unwrap()
        .with_environment(&[]);
    let started = std::time::Instant::now();
    assert_eq!(expect_error(audit_host(&selected, &runner)), "DNS resolution timed out");
    assert!(started.elapsed() < Duration::from_secs(2));
}

fn leak_script(overflow: bool) -> String {
    let write = if overflow { "head -c 4096 /dev/zero | tr '\\0' x; " } else { "" };
    format!("( {write}sleep 0.3; echo leaked > \"$1\" ) & exit 0")
}

#[test]
fn command_runner_kills_descendants_after_leader_exit() {
    let directory = std::env::temp_dir().join(format!("audit-leak-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    for overflow in [false, true] {
        for c_locale in [false, true] {
            let marker = directory.join(format!("leak-{overflow}-{c_locale}"));
            let timeout = if overflow { Duration::from_secs(5) } else { Duration::from_millis(30) };
            let limits = Bounded::new(timeout, 64).unwrap();
            let command = sh(&leak_script(overflow), &[marker.to_str().unwrap()]);
            let result = SystemExecutor.execute(&strs(&command), limits, c_locale);
            let expected = if overflow { BoundedError::OutputLimit } else { BoundedError::TimedOut };
            assert_eq!(result.unwrap_err(), expected);
            std::thread::sleep(Duration::from_millis(400));
            assert!(!marker.exists(), "{marker:?}");
        }
    }
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn c_locale_commands_run_with_lc_all_c_and_without_language() {
    let command = sh("printf '%s|%s' \"$LC_ALL\" \"${LANGUAGE-unset}\"", &[]);
    let output = SystemExecutor.execute(&strs(&command), Bounded::AUDIT, true).unwrap();
    assert_eq!(output.stdout, "C|unset");
    assert_eq!(c_locale_bounded(&["/nonexistent/binary"], Bounded::AUDIT).unwrap_err(), BoundedError::Unavailable);
    // Only `free -b` and `ufw status verbose` ask for it.
    let (_, executor) = scripted_audit(&core_config(), LETSENCRYPT, &[HOST_V6], None);
    let located: Vec<Vec<String>> =
        executor.calls.lock().unwrap().iter().filter(|(_, c)| *c).map(|(argv, _)| argv.clone()).collect();
    assert_eq!(located, [argv(&["free", "-b"]), argv(&["ufw", "status", "verbose"])]);
}

struct Absolute;

impl Resolver for Absolute {
    fn getaddrinfo(&self, name: &str) -> ResolveResult {
        assert_eq!(name, "panel.example.com.");
        Ok(vec![(Family::Inet, HOST_V4.into())])
    }
}

struct Oversized;

impl Resolver for Oversized {
    fn getaddrinfo(&self, name: &str) -> ResolveResult {
        assert!(name.ends_with('.'));
        let mut answers = vec![(Family::Inet6, HOST_V6.to_string()); 256];
        answers.push((Family::Inet6, FOREIGN_V6.into()));
        Ok(answers)
    }
}

#[test]
fn dns_resolution_uses_absolute_name_and_rejects_oversized_results() {
    let executor = Scripted::default();
    let runner = CommandRunner::new(&executor, &Absolute);
    assert_eq!(runner.resolve("panel.example.com").unwrap(), (vec![HOST_V4.to_string()], vec![]));
    let runner = CommandRunner::new(&executor, &Oversized);
    assert_eq!(
        runner.resolve("panel.example.com").unwrap_err(),
        AuditError::Failed("DNS resolution result limit exceeded".into())
    );
}

#[test]
fn failed_caa_query_is_not_treated_as_empty_rrset() {
    let selected = core_config();
    let domains = selected.required_domains();
    let mut responses = host_responses(&domains, LETSENCRYPT, None);
    responses.insert(argv(&["dig", "+short", "CAA", &domains[0]]), (9, String::new(), "query failed".into()));
    let message =
        expect_error(run_audit(&selected, &Scripted::new(responses), &records(&domains, &[HOST_V4], &[HOST_V6])));
    assert_eq!(message, "CAA query failed");
}

fn dig_calls(executor: &Scripted) -> usize {
    executor.calls().iter().filter(|call| call.len() > 2 && call[..3] == argv(&["dig", "+short", "CAA"])[..]).count()
}

#[test]
fn successful_empty_caa_rrsets_remain_distinct_from_query_failure() {
    let selected = core_config();
    let domains = selected.required_domains();
    let mut responses = host_responses(&domains, "", None);
    responses.insert(argv(&["dig", "+short", "CAA", "example.com"]), ok(""));
    responses.insert(argv(&["dig", "+short", "CAA", "com"]), ok(""));
    let executor = Scripted::new(responses);
    let audit = run_audit(&selected, &executor, &records(&domains, &[HOST_V4], &[HOST_V6])).unwrap();
    assert!(audit.hard_stops.is_empty());
    for domain in &domains {
        assert_eq!(audit.facts.topology["dns"][domain]["caa"], json!([]));
        assert_eq!(audit.facts.topology["dns"][domain]["caa_source"], Value::Null);
    }
    assert!(dig_calls(&executor) <= domains.len() + 2);
}

#[test]
fn caa_policy_is_inherited_from_first_parent_rrset() {
    for (parent, expected) in [
        ("0 issue \"sectigo.com\"\n", vec!["dns.caa_mismatch"]),
        (LETSENCRYPT, vec![]),
        ("0 issue \";\"\n", vec!["dns.caa_mismatch"]),
    ] {
        let selected = core_config();
        let domains = selected.required_domains();
        let mut responses = host_responses(&domains, "", None);
        responses.insert(argv(&["dig", "+short", "CAA", "example.com"]), ok(parent));
        let executor = Scripted::new(responses);
        let audit = run_audit(&selected, &executor, &records(&domains, &[HOST_V4], &[HOST_V6])).unwrap();
        let codes: Vec<&str> = audit.hard_stops.iter().map(|stop| stop.code.as_str()).collect();
        assert_eq!(codes, expected);
        for domain in &domains {
            assert_eq!(audit.facts.topology["dns"][domain]["caa_source"], json!("example.com"));
        }
        assert!(dig_calls(&executor) <= domains.len() + 1);
    }
}

#[test]
fn caa_alias_result_is_followed_within_the_query_bound() {
    let selected = core_config();
    let domains = selected.required_domains();
    let mut responses = host_responses(&domains, LETSENCRYPT, None);
    responses.insert(argv(&["dig", "+short", "CAA", &domains[0]]), ok("caa-policy.example.net.\n"));
    responses.insert(argv(&["dig", "+short", "CAA", "caa-policy.example.net"]), ok(LETSENCRYPT));
    let audit = run_audit(&selected, &Scripted::new(responses), &records(&domains, &[HOST_V4], &[HOST_V6])).unwrap();
    assert_eq!(audit.facts.topology["dns"][&domains[0]]["caa_source"], json!("caa-policy.example.net"));
    assert!(audit.hard_stops.is_empty());
}

#[test]
fn caa_issuer_restrictions_are_strictly_evaluated() {
    for (caa, mismatch) in [
        ("0 issue \"letsencrypt.org; validationmethods=dns-01\"\n", true),
        ("0 issue \"letsencrypt.org; validationmethods=http-01\"\n", false),
        ("0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/12345\"\n", true),
    ] {
        let (audit, _) = scripted_audit(&core_config(), caa, &[HOST_V6], None);
        assert_eq!(audit.hard_stops.iter().any(|stop| stop.code == "dns.caa_mismatch"), mismatch, "{caa}");
        assert!(!audit.facts.stable_dict().to_string().contains("acme/acct/12345"));
    }
}

#[test]
fn unsafe_or_malformed_caa_issuer_policy_fails_closed() {
    for caa in [
        "0 issue \"letsencrypt.org; unknown=value\"\n",
        "0 issue \"letsencrypt.org; validationmethods=http-01; validationmethods=dns-01\"\n",
        "0 issue \"letsencrypt.org; validationmethods\"\n",
        "0 issue \"letsencrypt.org; validationmethods=http-01,0123456789abcdef\"\n",
        "0 issue \"deadbeef-dead-beef-dead-beefdeadbeef\"\n",
        "0 issue \"0123456789abcdef\"\n",
    ] {
        let selected = core_config();
        let domains = selected.required_domains();
        let executor = Scripted::new(host_responses(&domains, caa, None));
        let message = expect_error(run_audit(&selected, &executor, &records(&domains, &[HOST_V4], &[HOST_V6])));
        assert!(message.contains("CAA issuer"), "{caa}: {message}");
    }
}

#[test]
fn caa_facts_never_serialize_raw_iodef_values() {
    let caa = "0 issue \"letsencrypt.org\"\n0 iodef \"https://report.example/?token=caa-secret\"\n";
    let (audit, _) = scripted_audit(&core_config(), caa, &[HOST_V6], None);
    let encoded = audit.facts.stable_dict().to_string();
    assert!(!encoded.contains("caa-secret") && !encoded.contains("https://report.example"));
    for domain in core_config().required_domains() {
        let tags: Vec<&str> = audit.facts.topology["dns"][&domain]["caa"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["tag"].as_str().unwrap())
            .collect();
        assert_eq!(tags, ["iodef", "issue"]);
    }
}

#[test]
fn certificate_wildcard_san_covers_exactly_one_label() {
    for (domain, covered) in [("panel.example.com", true), ("a.b.example.com", false)] {
        let mut selected = core_config();
        selected.domains.panel = domain.into();
        let domains = selected.required_domains();
        let mut responses = host_responses(&domains, LETSENCRYPT, None);
        let path = format!("/etc/letsencrypt/live/{domain}/fullchain.pem");
        responses.insert(
            argv(&["openssl", "x509", "-in", &path, "-noout", "-dates", "-ext", "subjectAltName"]),
            ok("X509v3 Subject Alternative Name:\n    DNS:*.example.com\n"),
        );
        let audit =
            run_audit(&selected, &Scripted::new(responses), &records(&domains, &[HOST_V4], &[HOST_V6])).unwrap();
        assert_eq!(audit.facts.topology["certificates"][domain]["covers_domain"], json!(covered));
    }
}

#[test]
fn audit_names_a_foreign_holder_of_every_reserved_identity() {
    let mut responses = Responses::new();
    responses.insert(
        argv(&["getent", "passwd", "10003"]),
        ok("foreign-service:x:10003:10003::/nonexistent:/usr/sbin/nologin\n"),
    );
    responses.insert(
        argv(&["getent", "group", "10004"]),
        ok("foreign-accounting:x:10004:10004::/nonexistent:/usr/sbin/nologin\n"),
    );
    let executor = Scripted::new(responses);
    let runner = CommandRunner::new(&executor, &Failing).with_environment(&[]);
    // Unknown identities answer 127 here (Python's fake answered 2): both are "no holder".
    let facts = identity_facts(&runner).unwrap();
    assert_eq!(facts, json!({"gid": {"10004": "foreign-accounting"}, "uid": {"10003": "foreign-service"}}));
}

#[test]
fn free_space_and_free_memory_never_change_the_plan_digest() {
    let selected = config();
    let domains = selected.required_domains();
    let responses = host_responses(&domains, LETSENCRYPT, None);
    let mut later = responses.clone();
    later.insert(
        argv(&["df", "-Pk"]),
        ok("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 100000 25064 74936 26% /\n"),
    );
    later.insert(
        argv(&["free", "-b"]),
        ok("              total used free shared buff/cache available\nMem:     8589934592 1 2 3 4 6442449920\n"),
    );
    let dns = records(&domains, &[HOST_V4], &[]);
    let first = run_audit(&selected, &Scripted::new(responses), &dns).unwrap();
    let second = run_audit(&selected, &Scripted::new(later), &dns).unwrap();
    assert_eq!(first.facts.stable_dict(), second.facts.stable_dict());
    assert_ne!(first.facts.transient, second.facts.transient);
    for disk in first.facts.platform["disks"].as_array().unwrap() {
        assert_eq!(disk.as_object().unwrap().keys().collect::<Vec<_>>(), ["filesystem", "mount", "total_kib"]);
    }
    assert_eq!(first.facts.platform["memory"], json!({"total_bytes": 8589934592u64}));
    assert_ne!(
        first.facts.transient["capacity"]["disks"][0]["available_kib"],
        second.facts.transient["capacity"]["disks"][0]["available_kib"]
    );
}

#[test]
fn a_non_x86_host_is_refused_by_name() {
    let names: Vec<&str> = SAFE_ARCHITECTURES.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, ["amd64", "x86_64"]);
    assert!(SAFE_ARCHITECTURES.iter().all(|(_, value)| *value == "amd64"));
    let selected = core_config();
    let domains = selected.required_domains();
    let mut responses = host_responses(&domains, LETSENCRYPT, None);
    responses.insert(argv(&["uname", "-m"]), ok("aarch64\n"));
    let audit = run_audit(&selected, &Scripted::new(responses), &records(&domains, &[HOST_V4], &[HOST_V6])).unwrap();
    assert_eq!(audit.facts.platform["architecture"], json!("unknown"));
}

// -- parsers of the Rust port ------------------------------------------------------------------

#[test]
fn version_facts_follow_the_python_regexes() {
    let output = |text: &str| BoundedOutput { returncode: 0, stdout: text.into(), stderr: String::new() };
    let version = |text: &str, bare: bool| version_fact(Some(&output(text)), "observed", bare).get("version").cloned();
    assert_eq!(version("Docker version 26.1.3, build x\n", false), Some(json!("26.1.3")));
    assert_eq!(version("VERSION 1.2.3.4.5\n", false), Some(json!("1.2.3.4")));
    assert_eq!(version("myversion 1.2\n", false), None);
    assert_eq!(version("version 1.2a version 3.4\n", false), Some(json!("3.4")));
    assert_eq!(version("2.35.0\n", true), Some(json!("2.35.0")));
    assert_eq!(version("  2.35\n\n", true), Some(json!("2.35")));
    assert_eq!(version("2.24.6+ds1-0ubuntu1~24.04.1\n", true), None);
    assert_eq!(version("7\n", true), None);
}

#[test]
fn listener_and_socket_parsers() {
    let parsed = parse_listener_lines(
        "tcp LISTEN 0 4096 [::]:22 [::]:* users:((\"sshd\",pid=1,fd=3),(\"sshd\",pid=2,fd=3))\n\
         udp UNCONN 0 0 *:51820 *:*\nraw x 0.0.0.0:7\ntcp LISTEN 0 1 0.0.0.0:99999 x\n",
    );
    assert_eq!(listeners_value(&parsed)["ports"], json!([22, 51820]));
    assert_eq!(listeners_value(&parsed)["owners"], json!({"22": ["sshd"]}));
    assert_eq!(parse_ssh_socket_ports("0.0.0.0:2222 (Stream)\n/run/x.sock (Stream)\n22 (Stream)\n"), vec![22, 2222]);
    assert_eq!(parse_ssh_socket_ports("[::]:22 (Datagram)\n"), Vec::<u32>::new());
    assert_eq!(parse_ssh_socket_ports("0.0.0.0:0 (Stream)\n"), Vec::<u32>::new());
    assert_eq!(parse_ufw_ipv6_config("\n  IPV6=yes \n"), Some(true));
    assert_eq!(parse_ufw_ipv6_config("IPV6=yes\nIPV6=no\n"), None);
    assert!(ufw_active("Status: active\n"));
    assert!(ufw_active("x\nstatus:\n  ACTIVE  \n"));
    assert!(!ufw_active("Status: inactive\n"));
    assert!(!ufw_active("Status: active now\n"));
}

#[test]
fn nginx_observation_reports_routes_http_names_and_errors() {
    let redactor = Redactor::default();
    let text = "# configuration file /etc/nginx/nginx.conf:\n\
        stream { map $ssl_preread_server_name $up { A.example.com 127.0.0.1:1; a.example.com 127.0.0.1:2; \
        bad_name 127.0.0.1:3; } server { listen 443; ssl_preread on; proxy_pass $up; } }\n\
        http { server {\n  server_name  Web.Example.com. www.example.com bad_name; } }\n";
    let fact = parse_nginx_observation(text, &redactor).unwrap();
    assert_eq!(fact["sni_routes"], json!({"a.example.com": "127.0.0.1:1"}));
    assert_eq!(fact["duplicate_sni_domains"], json!(["a.example.com"]));
    assert_eq!(fact["http_domains"], json!(["web.example.com", "www.example.com"]));
    assert_eq!(fact["sni_map_files"], json!({"/etc/nginx/nginx.conf": 1}));
    assert_eq!(fact["topology_error"], Value::Null);
    let malformed = parse_nginx_observation("stream {", &redactor).unwrap_err();
    assert_eq!(malformed.message(), "Nginx observation is malformed");
    let unrouted = parse_nginx_observation("events {}\n", &redactor).unwrap();
    assert_eq!(unrouted["topology_error"], json!("no effective stream listener on port 443"));
    assert_eq!(unrouted["route_target"], Value::Null);
}

#[test]
fn http_domain_scan_follows_the_multiline_regex() {
    assert_eq!(parse_http_domains("server_name a.example.com;").into_iter().collect::<Vec<_>>(), ["a.example.com"]);
    assert!(parse_http_domains("  server_names a.example.com;").is_empty());
    assert!(parse_http_domains("x server_name a.example.com;").is_empty());
    assert_eq!(
        parse_http_domains("\n\n  server_name\n a.example.com\n b.example.com ;\nserver_name c.example.com;")
            .into_iter()
            .collect::<Vec<_>>(),
        ["a.example.com", "b.example.com", "c.example.com"]
    );
    assert!(parse_http_domains("server_name a.example.com").is_empty());
}

#[test]
fn redaction_counts_every_category() {
    let redactor = Redactor::new(&[("MY_SESSION".into(), "abcd".into()), ("PATH".into(), "/usr/bin".into())]);
    assert_eq!(redactor.sanitize_error("plain"), "audit observation failed");
    assert_eq!(
        redactor.sanitize_error("-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY----- abcd"),
        "audit observation failed [REDACTED] [REDACTED]"
    );
    assert_eq!(
        redactor.sanitize_error("sessionid = \"a b\" token:'x'"),
        "audit observation failed [REDACTED] [REDACTED]"
    );
    assert_eq!(redactor.safe_audit_error("command failed with exit status -9"), "command failed with exit status -9");
    assert_eq!(redactor.safe_audit_error("DNS resolution failed"), "DNS resolution failed");
    assert!(!redactor.safe_text("x-abcd-y", 64));
    assert!(redactor.safe_text("/usr/bin", 64));
    assert!(!redactor.safe_text("", 64));
    assert!(sensitive_key("Database-URL") && sensitive_key("x_auth") && !sensitive_key("PATH"));
}

#[test]
fn splitlines_matches_python() {
    assert_eq!(splitlines("a\r\nb\rc\u{b}d\n", false), ["a", "b", "c", "d"]);
    assert_eq!(splitlines("a\r\nb", true), ["a\r\n", "b"]);
    assert_eq!(splitlines("", false), Vec::<&str>::new());
}
