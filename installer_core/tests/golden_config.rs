//! The configuration goldens recorded from Python (`tests/fixtures/host-golden/config/`):
//! every error text exactly, every valid canonical dict and `render_config` output, the CLI's
//! `BLOCKED:` lines, and the example round trips.

use std::path::{Path, PathBuf};

use installer_core::cli::blocked_line;
use installer_core::config::{load_config, parse_config, render_config};
use serde_json::Value;

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden")
}

fn read_json(relative: &str) -> Value {
    serde_json::from_slice(&std::fs::read(golden().join(relative)).unwrap()).unwrap()
}

/// Cases whose outcome changes on purpose (DIFFERENCES.md, host WP3).
fn deliberate(name: &str) -> Option<&'static str> {
    match name {
        // `panel.example.c0m`: the last label must be letters or an `xn--` A-label.
        "domain-value-6" => Some("invalid domain: domains.panel"),
        // `fe80::1%eth0`: a DNS server address with an interface scope is refused.
        "awg-dns-scope-id" => Some("amneziawg.dns contains an invalid address"),
        _ => None,
    }
}

#[test]
fn every_config_case_matches_python() {
    let cases = read_json("config/errors.json");
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 145);
    let mut checked = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let input = case["input"].as_str().unwrap();
        let result = parse_config(input);
        if let Some(message) = deliberate(name) {
            assert_eq!(result.unwrap_err().0, message, "{name}");
            checked += 1;
            continue;
        }
        match case["result"].as_str().unwrap() {
            "error" => {
                assert_eq!(case["exception"], "ConfigError", "{name}");
                let err = result.expect_err(name);
                assert_eq!(err.0, case["message"].as_str().unwrap(), "{name}");
            }
            _ => {
                let config = result.unwrap_or_else(|err| panic!("{name}: {err}"));
                assert_eq!(config.canonical_dict(), case["canonical"], "{name}");
                let rendered = render_config(&config);
                assert_eq!(rendered, case["rendered"].as_str().unwrap(), "{name}");
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 145);
}

#[test]
fn valid_renders_round_trip_except_a_raw_del() {
    for case in read_json("config/errors.json").as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if case["result"] != "ok" || deliberate(name).is_some() {
            continue;
        }
        let config = parse_config(case["input"].as_str().unwrap()).unwrap();
        let again = parse_config(&render_config(&config));
        if name == "acme-email-with-del-accepted" {
            // Python renders DEL raw (json.dumps) and tomllib refuses it on the way back.
            assert!(again.unwrap_err().0.starts_with("invalid TOML: Illegal character"), "{name}");
        } else {
            assert_eq!(again.unwrap(), config, "{name}");
        }
    }
}

#[test]
fn cli_blocked_lines_match_python() {
    let cases = read_json("config/cli-blocked.json");
    let corpus = read_json("config/errors.json");
    let directory = std::env::temp_dir().join(format!("installer-core-blocked-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let shown = directory.to_string_lossy().to_string();
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let path = directory.join(format!("{name}.toml"));
        match name {
            "missing-file" => {}
            "invalid-utf8" => std::fs::write(&path, b"schema = 1\nacme_email = \"\xff\"\n").unwrap(),
            _ => {
                let input =
                    corpus.as_array().unwrap().iter().find(|c| c["name"] == name).unwrap()["input"].as_str().unwrap();
                std::fs::write(&path, input).unwrap();
            }
        }
        let err = load_config(&path).expect_err(name);
        let stderr = blocked_line(&err.0).replace(&shown, "<dir>");
        assert_eq!(case["exit"], 2);
        assert_eq!(case["stdout"], "");
        assert_eq!(stderr, case["stderr"].as_str().unwrap(), "{name}");
    }
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn example_renders_match_python() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/installer");
    let round_trip = read_json("config/render/round-trip.json");
    for (name, outcome) in round_trip.as_object().unwrap() {
        let config = load_config(&examples.join(name)).unwrap();
        let rendered = render_config(&config);
        let expected = std::fs::read_to_string(golden().join("config/render").join(name)).unwrap();
        assert_eq!(rendered, expected, "{name}");
        assert_eq!(outcome["round_trip_equal"], true);
        assert_eq!(parse_config(&rendered).unwrap(), config, "{name}");
    }
}
