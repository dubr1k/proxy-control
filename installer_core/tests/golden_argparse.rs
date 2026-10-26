//! The installer's and verify.py's argparse surfaces against Python 3.12
//! (`tests/data/argparse-python.json`, recorded by `scripts/dev/record-argparse-goldens.py`):
//! namespaces, help texts at several widths, usage errors and exit codes, byte for byte.

use std::path::Path;

use installer_core::argparse::{Arg, Parser};
use serde_json::{Map, Value};

fn corpus() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/argparse-python.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn check(parser: &Parser, records: &[Value]) -> usize {
    let mut checked = 0;
    for record in records {
        let argv: Vec<String> =
            record["argv"].as_array().unwrap().iter().map(|a| a.as_str().unwrap().to_string()).collect();
        let width = record["columns"].as_u64().unwrap() as usize - 2;
        let label = format!("{argv:?} at {}", record["columns"]);
        match parser.parse_args(&argv, width) {
            Ok(namespace) => {
                assert_eq!(record["exit"], Value::Null, "{label}: Python exited, Rust parsed {namespace:?}");
                let ours: Map<String, Value> = namespace
                    .into_iter()
                    .map(|(key, value)| {
                        let value = match value {
                            Arg::None => Value::Null,
                            Arg::Bool(flag) => Value::Bool(flag),
                            Arg::Str(text) => Value::String(text),
                        };
                        (key, value)
                    })
                    .collect();
                assert_eq!(Value::Object(ours), record["namespace"], "{label}");
                assert_eq!(record["stdout"], "", "{label}");
                assert_eq!(record["stderr"], "", "{label}");
            }
            Err(exit) => {
                assert_eq!(Some(i64::from(exit.status)), record["exit"].as_i64(), "{label}: {exit:?}");
                assert_eq!(exit.stdout, record["stdout"].as_str().unwrap(), "{label}");
                assert_eq!(exit.stderr, record["stderr"].as_str().unwrap(), "{label}");
            }
        }
        checked += 1;
    }
    checked
}

#[test]
fn installer_command_lines_match_python() {
    let corpus = corpus();
    let checked = check(&installer_core::cli::python_parser(), corpus["installer"].as_array().unwrap());
    assert!(checked > 80, "{checked}");
}

#[test]
fn verify_release_command_lines_match_verify_py() {
    let corpus = corpus();
    let parser = installer_core::verify_release::parser("proxy-control-installer verify-release");
    let checked = check(&parser, corpus["verify"].as_array().unwrap());
    assert!(checked > 10, "{checked}");
}
