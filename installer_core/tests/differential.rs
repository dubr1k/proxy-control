//! Differential check against a large Python-generated corpus (not committed: mutated TOML
//! configurations and random command lines with Python's outcomes). Run on ams-test with
//! `INSTALLER_CORE_DIFF=<corpus.json> cargo test --test differential -- --ignored --nocapture`.

use installer_core::argparse::Arg;
use installer_core::config::{parse_config, render_config};
use serde_json::{Map, Value};

fn corpus() -> Option<Value> {
    let path = std::env::var("INSTALLER_CORE_DIFF").ok()?;
    Some(serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
}

/// Outcomes that differ on purpose (DIFFERENCES.md, host WP3): a scoped IPv6 DNS address, and a
/// name whose top-level label holds a digit or a hyphen (Python's regex took it, so Python may fail later
/// with another message or not at all).
fn deliberate(input: &str, python: &Value, rust_error: Option<&str>) -> bool {
    match rust_error {
        Some("amneziawg.dns contains an invalid address") => {
            input.contains("::") && input.contains('%')
                || python.get("canonical").is_some_and(|c| c.to_string().contains('%'))
        }
        Some(message)
            if message.starts_with("invalid domain") || message.ends_with("a DNS name or an IPv4 address") =>
        {
            input.split('"').any(|item| {
                let name = item.trim().trim_end_matches('.').to_lowercase();
                name.contains('.')
                    && name.rsplit('.').next().is_some_and(|tld| {
                        tld.chars().any(|c| c.is_ascii_digit() || c == '-')
                            && !tld.starts_with("xn--")
                            && tld.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                    })
            })
        }
        _ => false,
    }
}

#[test]
#[ignore]
fn configs_match_python() {
    let Some(corpus) = corpus() else { return };
    let mut mismatches = Vec::new();
    let cases = corpus["configs"].as_array().unwrap();
    for case in cases {
        if case.get("crash").is_some() {
            continue;
        }
        let input = case["input"].as_str().unwrap();
        let ours = parse_config(input);
        let same = match (&ours, case.get("error")) {
            (Err(err), Some(message)) => err.0 == message.as_str().unwrap(),
            (Ok(config), None) => {
                config.canonical_dict() == case["canonical"]
                    && render_config(config) == case["rendered"].as_str().unwrap()
            }
            _ => false,
        };
        if !same && !deliberate(input, case, ours.as_ref().err().map(|e| e.0.as_str())) {
            mismatches.push(format!(
                "{input:?}\n  python: {:?}\n  rust:   {:?}",
                case.get("error"),
                ours.map(|_| "ok")
            ));
        }
    }
    let crashes = cases.iter().filter(|c| c.get("crash").is_some()).count();
    eprintln!("{} configs, {} Python crashes skipped, {} mismatches", cases.len(), crashes, mismatches.len());
    for mismatch in mismatches.iter().take(20) {
        eprintln!("{mismatch}");
    }
    assert!(mismatches.is_empty());
}

#[test]
#[ignore]
fn command_lines_match_python() {
    let Some(corpus) = corpus() else { return };
    let parser = installer_core::cli::python_parser();
    let mut mismatches = 0;
    let records = corpus["argv"].as_array().unwrap();
    for record in records {
        let argv: Vec<String> =
            record["argv"].as_array().unwrap().iter().map(|a| a.as_str().unwrap().to_string()).collect();
        let width = record["columns"].as_u64().unwrap() as usize - 2;
        let same = match parser.parse_args(&argv, width) {
            Ok(namespace) => {
                let ours: Map<String, Value> = namespace
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            match v {
                                Arg::None => Value::Null,
                                Arg::Bool(b) => Value::Bool(b),
                                Arg::Str(s) => Value::String(s),
                            },
                        )
                    })
                    .collect();
                record["exit"].is_null() && Value::Object(ours) == record["namespace"]
            }
            Err(exit) => {
                Some(i64::from(exit.status)) == record["exit"].as_i64()
                    && exit.stdout == record["stdout"].as_str().unwrap()
                    && exit.stderr == record["stderr"].as_str().unwrap()
            }
        };
        if !same {
            mismatches += 1;
            if mismatches <= 20 {
                eprintln!("{argv:?} at {}: python {record}", record["columns"]);
                eprintln!("  rust {:?}", parser.parse_args(&argv, width));
            }
        }
    }
    eprintln!("{} command lines, {mismatches} mismatches", records.len());
    assert_eq!(mismatches, 0);
}
