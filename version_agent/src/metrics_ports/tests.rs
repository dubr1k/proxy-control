//! Ported from `tests/test_version_agent_metrics_ports.py`, plus the golden port maps.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value};

use super::*;
use crate::testutil::TempDir;

fn files(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| name.to_string()).collect()
}

fn sources(dir: &Path, names: &[&str]) -> Sources {
    Sources {
        compose_dir: dir.to_path_buf(),
        compose_files: files(names),
        override_path: dir.join("override.json"),
        mita_config: dir.join("server_config.json"),
    }
}

fn discover_in(dir: &Path, names: &[&str]) -> PortMap {
    discover(&sources(dir, names)).unwrap()
}

#[test]
fn core_only_has_mtproxy_default() {
    let dir = TempDir::new("ports-core");
    assert_eq!(to_json(&discover_in(dir.path(), &["compose.yaml"])), json!({"mtproxy": {"tcp": [8445], "udp": []}}));
}

#[test]
fn mtproxy_backend_port_from_env() {
    let dir = TempDir::new("ports-env");
    dir.write(".env", "MTPROXY_BACKEND_PORT=18445\n");
    assert_eq!(discover_in(dir.path(), &["compose.yaml"])["mtproxy"].tcp, [18445]);
}

#[test]
fn naive_and_trusttunnel_only_with_their_overlay() {
    let dir = TempDir::new("ports-overlays");
    dir.write(".env.trusttunnel", "TT_LISTEN=127.0.0.1:4460\n");
    let both = discover_in(dir.path(), &["compose.yaml", "compose.naive.yaml", "compose.trusttunnel.yaml"]);
    assert_eq!(both["naive"], Ports::tcp(&[4443]));
    assert_eq!(both["trusttunnel"], Ports::tcp(&[4460]));
    let plain = discover_in(dir.path(), &["compose.yaml"]);
    assert!(!plain.contains_key("naive") && !plain.contains_key("trusttunnel"));
}

#[test]
fn trusttunnel_default_port_without_env() {
    let dir = TempDir::new("ports-tt");
    assert_eq!(discover_in(dir.path(), &["compose.trusttunnel.yaml"])["trusttunnel"].tcp, [4453]);
}

#[test]
fn mieru_ports_from_mita_config_and_lane_slots() {
    let dir = TempDir::new("ports-mieru");
    dir.write(
        "server_config.json",
        &json!({"portBindings": [{"port": 8443, "protocol": "TCP"}, {"portRange": "9000-9002", "protocol": "UDP"},
                                  {"port": 8443, "protocol": "TCP"}]})
        .to_string(),
    );
    dir.write(".env.mieru", "MIERU_LANE_SLOTS=1:46101:/s:/t,2:46102:/s:/t\n");
    let mieru = &discover_in(dir.path(), &["compose.yaml", "compose.mieru.yaml"])["mieru"];
    assert_eq!(mieru, &Ports { tcp: vec![8443, 46101, 46102], udp: vec![9000, 9001, 9002] });
}

#[test]
fn mieru_without_readable_config_is_omitted() {
    let dir = TempDir::new("ports-mieru-none");
    assert!(!discover_in(dir.path(), &["compose.mieru.yaml"]).contains_key("mieru"));
}

#[test]
fn override_replaces_and_adds() {
    let dir = TempDir::new("ports-override");
    dir.write("override.json", r#"{"naive":{"tcp":[4444]},"mieru":{"udp":[5000]}}"#);
    let found = discover_in(dir.path(), &["compose.yaml", "compose.naive.yaml"]);
    assert_eq!(found["naive"], Ports::tcp(&[4444]));
    assert_eq!(found["mieru"], Ports { tcp: vec![], udp: vec![5000] });
}

#[test]
fn malformed_override_is_ignored_with_one_log_line() {
    let dir = TempDir::new("ports-bad-override");
    for payload in [
        "not json",
        "[]",
        r#"{"nope":{"tcp":[1]}}"#,
        r#"{"naive":{"tcp":[0]}}"#,
        r#"{"naive":{"tcp":[70000]}}"#,
        r#"{"naive":{"sctp":[1]}}"#,
        r#"{"naive":{"tcp":["80"]}}"#,
        r#"{"naive":{"tcp":[true]}}"#,
        r#"{"naive":[]}"#,
    ] {
        assert!(parse_override(payload).is_err(), "{payload}");
        dir.write("override.json", payload);
        assert!(load_override(&dir.path().join("override.json")).is_empty(), "{payload}");
        assert!(load_override(&dir.path().join("override.json")).is_empty(), "{payload}");
    }
    assert_eq!(parse_override(r#"{"nope":{"tcp":[1]}}"#).unwrap_err(), "unknown protocol 'nope'");
    assert_eq!(parse_override(r#"{"naive":{"sctp":[1]}}"#).unwrap_err(), "naive: bad transport 'sctp'");
    // The warning is written once per process (`_warn_once`).
    assert!(WARNED.lock().unwrap().contains("override-invalid"));
}

#[test]
fn missing_override_is_silent() {
    let dir = TempDir::new("ports-no-override");
    assert!(load_override(&dir.path().join("none.json")).is_empty());
}

#[test]
fn port_budget_per_protocol() {
    let dir = TempDir::new("ports-budget");
    dir.write(
        "server_config.json",
        &json!({"portBindings": [{"portRange": "1000-5000", "protocol": "TCP"}]}).to_string(),
    );
    assert_eq!(discover_in(dir.path(), &["compose.mieru.yaml"])["mieru"].tcp.len(), MAX_PORTS_PER_PROTOCOL);
}

#[test]
fn read_env_file_strips_quotes_and_comments() {
    let dir = TempDir::new("ports-envfile");
    dir.write(".env", "# c\nA=1\nB='two'\nC=\"3\"\nbroken\n");
    let expected: BTreeMap<String, String> =
        [("A", "1"), ("B", "two"), ("C", "3")].into_iter().map(|(k, v)| (k.into(), v.into())).collect();
    assert_eq!(read_env_file(&dir.path().join(".env")).unwrap(), expected);
    assert!(read_env_file(&dir.path().join("missing")).unwrap().is_empty());
}

#[test]
fn env_reader_is_injectable() {
    let dir = TempDir::new("ports-reader");
    let reader = |path: &Path| -> Result<BTreeMap<String, String>, String> {
        Ok(if path.file_name().and_then(|n| n.to_str()) == Some(".env.trusttunnel") {
            BTreeMap::from([("TT_LISTEN".to_string(), "[::1]:4999".to_string())])
        } else {
            BTreeMap::new()
        })
    };
    let found = discover_ports(&sources(dir.path(), &["compose.trusttunnel.yaml"]), &reader).unwrap();
    assert_eq!(found["trusttunnel"].tcp, [4999]);
}

#[test]
fn listen_ports_parse_like_the_python_regex() {
    assert_eq!(port_from_listen(Some("4453"), 1), 4453);
    assert_eq!(port_from_listen(Some(" [::1]:4999 "), 1), 4999);
    assert_eq!(port_from_listen(Some("a:b:80"), 1), 80);
    assert_eq!(port_from_listen(Some("host:123456"), 1), 1);
    assert_eq!(port_from_listen(Some("host:0"), 1), 1);
    assert_eq!(port_from_listen(Some("a\nb:80"), 1), 1);
    assert_eq!(port_from_listen(Some(""), 7), 7);
    assert_eq!(port_from_listen(None, 7), 7);
}

#[test]
fn golden_port_maps_are_reproduced() {
    let inputs: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/host-golden/metrics/inputs.json")).unwrap();
    let golden: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/host-golden/metrics/port-maps.json")).unwrap();
    let dir = TempDir::new("ports-golden");
    dir.write(".env", inputs["env"].as_str().unwrap());
    dir.write(".env.mieru", inputs["env.mieru"].as_str().unwrap());
    dir.write(".env.trusttunnel", inputs["env.trusttunnel"].as_str().unwrap());
    dir.write("server_config.json", &inputs["mita_server_config"].to_string());
    let compose: Vec<&str> = inputs["compose_files"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();
    assert_eq!(to_json(&discover_in(dir.path(), &compose)), golden["no-override"]);
    for (case, document) in inputs["overrides"].as_object().unwrap() {
        dir.write("override.json", &document.to_string());
        assert_eq!(to_json(&discover_in(dir.path(), &compose)), golden[format!("override-{case}")], "{case}");
    }
    std::fs::remove_file(dir.path().join("override.json")).unwrap();
    assert_eq!(to_json(&discover_in(dir.path(), &["compose.yaml"])), golden["core-only"]);
}
