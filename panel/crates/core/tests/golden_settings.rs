//! `Settings` against what `panel.settings.Settings()` made of the same environments
//! (`fixtures/settings.json`, made by `fixtures/generators/gen_settings.py` in the panel image).

#![recursion_limit = "256"]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use panel_core::pyjson;
use panel_core::settings::{Settings, SettingsError, DEFAULT_VERSION_FILE};
use serde_json::{json, Value};

/// Token files are recreated under a private directory; the paths in the environments are
/// rewritten to it.
fn token_dir(files: &serde_json::Map<String, Value>) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("panel-core-settings-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (path, content) in files {
        let name = Path::new(path).file_name().unwrap();
        std::fs::write(dir.join(name), content.as_str().unwrap()).unwrap();
    }
    dir
}

fn as_python(settings: &Settings) -> Value {
    let path = |path: &Path| Value::String(path.to_string_lossy().into_owned());
    json!({
        "database_path": path(&settings.database_path),
        "telemt_url": settings.telemt_url,
        "telemt_token": settings.telemt_token,
        "naive_socket": settings.naive_socket,
        "naive_token": settings.naive_token,
        "naive_public_host": settings.naive_public_host,
        "mtproxy_public_host": settings.mtproxy_public_host,
        "naive_enabled": settings.naive_enabled,
        "mieru_socket": settings.mieru_socket,
        "mieru_token": settings.mieru_token,
        "mieru_enabled": settings.mieru_enabled,
        "amneziawg_socket": settings.amneziawg_socket,
        "amneziawg_token": settings.amneziawg_token,
        "amneziawg_enabled": settings.amneziawg_enabled,
        "amneziawg_public_host": settings.amneziawg_public_host,
        "trusttunnel_socket": settings.trusttunnel_socket,
        "trusttunnel_token": settings.trusttunnel_token,
        "trusttunnel_enabled": settings.trusttunnel_enabled,
        "trusttunnel_public_host": settings.trusttunnel_public_host,
        "xray_router_enabled": settings.xray_router_enabled,
        "xray_router_socket": settings.xray_router_socket,
        "xray_router_token": settings.xray_router_token,
        "subscription_url": settings.subscription_url,
        "subscription_host": settings.subscription_host,
        "singbox_fork_clients": settings.singbox_fork_clients,
        "version_agent_socket": settings.version_agent_socket,
        "panel_version_file": path(&settings.panel_version_file),
        "master_key_file": settings.master_key_file.as_deref().map(path),
        "session_cookie_secure": settings.session_cookie_secure,
        "allowed_hosts": settings.allowed_hosts,
        "session_ttl_seconds": settings.session_ttl_seconds,
        "login_attempts": settings.login_attempts,
        "login_window_seconds": settings.login_window_seconds,
        "reveal_ttl_seconds": settings.reveal_ttl_seconds,
        "body_limit_bytes": settings.body_limit_bytes,
        "login_verify_concurrency": settings.login_verify_concurrency,
        "api_key_rate_per_minute": settings.api_key_rate_per_minute,
        "fleet_heartbeat_seconds": settings.fleet_heartbeat_seconds,
        "metrics_enabled": settings.metrics_enabled,
        "metrics_interval_seconds": pyjson::float_repr(settings.metrics_interval_seconds),
        "metrics_ring_points": settings.metrics_ring_points,
        "mtproxy_host": settings.mtproxy_host(),
        "validate": settings.validate().err().map(|error| error.to_string()),
    })
}

#[test]
fn every_python_environment_gives_the_same_settings() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/settings.json")).unwrap();
    let fixture: Value = serde_json::from_str(&text).unwrap();
    let dir = token_dir(fixture["files"].as_object().unwrap());
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 60);
    for case in cases {
        let env: BTreeMap<String, String> = case["env"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| {
                let value = value.as_str().unwrap().replace("/tmp/pc-settings", dir.to_str().unwrap());
                (name.clone(), value)
            })
            .collect();
        let result = Settings::from_lookup(|name| Ok(env.get(name).cloned()));
        let expected = &case["result"];
        match (expected.get("error"), result) {
            (Some(kind), Err(error)) => {
                if kind == "FileNotFoundError" {
                    assert!(matches!(error, SettingsError::TokenFile { .. }), "{env:?}: {error}");
                } else {
                    assert_eq!(kind, "ValueError");
                    assert_eq!(error.to_string(), expected["message"].as_str().unwrap(), "{env:?}");
                }
            }
            (Some(_), Ok(settings)) => panic!("{env:?}: Python refused, Rust gave {settings:?}"),
            (None, Err(error)) => panic!("{env:?}: Rust refused: {error}"),
            (None, Ok(settings)) => {
                let mut expected = expected.clone();
                if !env.contains_key("PANEL_VERSION_FILE") {
                    // Python derives the default from its source path; the image's is /app/VERSION.
                    expected["panel_version_file"] = json!(DEFAULT_VERSION_FILE);
                }
                expected.as_object_mut().unwrap().remove("vnext_writer");
                assert_eq!(as_python(&settings), expected, "{env:?}");
            }
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn metrics_interval_is_clamped_like_python_max() {
    let with = |value: &str| {
        let value = value.to_string();
        Settings::from_lookup(move |name| Ok((name == "PANEL_METRICS_INTERVAL_SECONDS").then(|| value.clone())))
            .unwrap()
            .metrics_interval()
    };
    assert_eq!(with("0.1"), 0.5);
    assert_eq!(with("3"), 3.0);
    assert_eq!(with("nan"), 0.5);
    assert_eq!(with("inf"), f64::INFINITY);
}

#[test]
fn the_telemt_journal_sits_next_to_the_database() {
    let settings =
        Settings::from_lookup(|name| Ok((name == "PANEL_DATABASE").then(|| "/data/panel.sqlite3".into()))).unwrap();
    assert_eq!(settings.telemt_egress_journal(), PathBuf::from("/data/telemt-egress.json"));
}
